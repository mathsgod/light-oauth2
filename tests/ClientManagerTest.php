<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;
use PHPUnit\Framework\TestCase;
use Light\OAuth2\Contract\PermissionProvider;
use Light\OAuth2\Input\OAuthClientInput;
use Light\OAuth2\Management\ClientManager;

final class ClientManagerTest extends TestCase
{
    private MemoryStore $store;
    private ClientManager $manager;

    protected function setUp(): void
    {
        $this->store = new MemoryStore();
        $permissions = new class implements PermissionProvider {
            public function scopes(): array { return ['client.list']; }
            public function can(string $userId, string $permission): bool { return false; }
        };
        $this->manager = new ClientManager($this->store, $permissions, $this->store->registry('https://api.example.com/', $permissions->scopes()));
    }

    private function input(): OAuthClientInput
    {
        $input = new OAuthClientInput();
        $input->id = 'nuxt-test';
        $input->name = 'Test application';
        $input->redirectUris = ['http://127.0.0.1:5555/callback'];
        $input->scopes = ['client.list'];
        $input->confidential = true;
        $input->enabled = true;
        return $input;
    }

    public function testSecretLifecycleAndSafeList(): void
    {
        $input = $this->input();
        $result = $this->manager->save($input, true);
        self::assertTrue(password_verify($result->secret, $this->store->client($input->id)['secret_hash']));
        self::assertArrayNotHasKey('secret_hash', get_object_vars($this->manager->clients()[0]));
        $input->enabled = false;
        $updated = $this->manager->save($input, false);
        self::assertNull($updated->secret);
        self::assertFalse($updated->client->enabled);
        $newSecret = $this->manager->resetSecret($input->id);
        self::assertTrue(password_verify($newSecret, $this->store->client($input->id)['secret_hash']));
        self::assertFalse(password_verify($result->secret, $this->store->client($input->id)['secret_hash']));
        $input->confidential = false;
        self::assertNull($this->manager->save($input, false)->secret);
        self::assertArrayNotHasKey('secret_hash', $this->store->client($input->id));
    }

    public function testDuplicateCreateDoesNotOverwriteClient(): void
    {
        $input = $this->input();
        $this->manager->save($input, true);
        $input->name = 'Overwrite';
        try {
            $this->manager->save($input, true);
            self::fail('Duplicate ID accepted');
        } catch (\InvalidArgumentException) {
            self::assertSame('Test application', $this->store->client($input->id)['name']);
        }
    }

    public function testUnexposedScopeCannotBeGranted(): void
    {
        $input = $this->input();
        $input->scopes = ['oauth_client.update'];
        $this->expectException(\InvalidArgumentException::class);
        $this->manager->save($input, true);
    }

    public function testInvalidRedirectIsRejected(): void
    {
        $input = $this->input();
        $input->redirectUris = ['http://example.com/callback'];
        $this->expectException(\InvalidArgumentException::class);
        $this->manager->save($input, true);
    }

    public function testGraphQLManagementAndPermissions(): void
    {
        if (!interface_exists(\Light\GraphQL\ExplicitController::class)) self::markTestSkipped('Set LIGHT_SOURCE_PATH to Light with explicit controller registration');
        $container = new \League\Container\Container();
        $controller = new \Light\OAuth2\Controller\OAuthClientController($this->manager);
        $container->add($controller::class, $controller);
        $cache = new \Symfony\Component\Cache\Psr16Cache(new \Symfony\Component\Cache\Adapter\ArrayAdapter());
        $factory = new \TheCodingMachine\GraphQLite\SchemaFactory($cache, $container);
        $factory->setFinder(\Light\GraphQL\ControllerDiscovery::finder($container));
        $factory->addNamespace('Light\\OAuth2\\Controller');
        $factory->addNamespace('Light\\OAuth2\\Type');
        $factory->addNamespace('Light\\OAuth2\\Input');
        $security = new class implements \TheCodingMachine\GraphQLite\Security\AuthenticationServiceInterface, \TheCodingMachine\GraphQLite\Security\AuthorizationServiceInterface {
            public bool $logged = true;
            public array $rights = ['oauth_client.list', 'oauth_client.add', 'oauth_client.update'];
            public function isLogged(): bool { return $this->logged; }
            public function getUser(): ?object { return $this->logged ? new \stdClass() : null; }
            public function isAllowed(string $right, mixed $subject = null): bool { return in_array($right, $this->rights, true); }
        };
        $factory->setAuthenticationService($security)->setAuthorizationService($security);
        $schema = $factory->createSchema();
        $query = 'mutation { createOAuthClient(input: {id: "graphql-test", name: "GraphQL", redirectUris: ["https://example.com/callback"], scopes: ["client.list"], confidential: true, enabled: true}) {client {id redirectUris confidential enabled scopes} secret} }';
        $result = \GraphQL\GraphQL::executeQuery($schema, $query)->toArray();
        self::assertArrayNotHasKey('errors', $result, json_encode($result));
        self::assertSame('graphql-test', $result['data']['createOAuthClient']['client']['id']);
        self::assertNotEmpty($result['data']['createOAuthClient']['secret']);
        self::assertArrayNotHasKey('secret_hash', $schema->getType('OAuthClient')->getFields());
        $security->rights = ['oauth_client.list'];
        $denied = \GraphQL\GraphQL::executeQuery($schema, 'mutation { resetOAuthClientSecret(id: "graphql-test") }')->toArray();
        self::assertArrayHasKey('errors', $denied);
        self::assertArrayHasKey('errors', \GraphQL\GraphQL::executeQuery($schema, 'mutation { deleteOAuthClient(id: "graphql-test") }')->toArray());
        $listed = \GraphQL\GraphQL::executeQuery($schema, '{oauthClients {id name} oauthClientScopes}')->toArray();
        self::assertArrayNotHasKey('errors', $listed, json_encode($listed));
        self::assertCount(1, $listed['data']['oauthClients']);
        $security->rights[] = 'oauth_client.delete';
        $deleted = \GraphQL\GraphQL::executeQuery($schema, 'mutation { deleteOAuthClient(id: "graphql-test") }')->toArray();
        self::assertArrayNotHasKey('errors', $deleted, json_encode($deleted));
        self::assertTrue($deleted['data']['deleteOAuthClient']);
        self::assertNull($this->store->client('graphql-test'));
        $security->logged = false;
        self::assertArrayHasKey('errors', \GraphQL\GraphQL::executeQuery($schema, '{oauthClients {id}}')->toArray());
    }

    public function testOptionalControllerIsNotDiscoveredBeforeProviderRegistration(): void
    {
        if (!interface_exists(\Light\GraphQL\ExplicitController::class)) self::markTestSkipped('Set LIGHT_SOURCE_PATH to Light with explicit controller registration');
        $controller = \Light\OAuth2\Controller\OAuthClientController::class;
        $container = new \League\Container\Container();
        $container->delegate(new \League\Container\ReflectionContainer());
        // Reflection autowiring alone must not expose an optional controller.
        self::assertTrue($container->has($controller));
        $finder = \Light\GraphQL\ControllerDiscovery::finder($container)->inNamespace('Light');
        $classes = iterator_to_array($finder);
        self::assertArrayNotHasKey($controller, $classes);
        self::assertArrayHasKey(\Light\App::class, $classes);
        $container->add($controller, new $controller($this->manager));
        $finder = \Light\GraphQL\ControllerDiscovery::finder($container)->inNamespace('Light');
        self::assertArrayHasKey($controller, iterator_to_array($finder));
    }
}
