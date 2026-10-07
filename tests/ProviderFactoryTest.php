<?php
declare(strict_types=1);

namespace Light\OAuth2\Tests;

use GraphQL\GraphQL;
use Light\App;
use Light\OAuth2\ProviderFactory;
use TheCodingMachine\GraphQLite\Security\AuthenticationServiceInterface;
use TheCodingMachine\GraphQLite\Security\AuthorizationServiceInterface;

final class ProviderFactoryTest extends ApplicationTestCase
{
    public function testConfiguredProviderExposesTheManagementQuery(): void
    {
        if (!filter_var($_ENV['OAUTH_ENABLED'] ?? false, FILTER_VALIDATE_BOOLEAN)) self::markTestSkipped('Configure OAuth in .env to test the application bootstrap');
        $app = new App();
        self::assertNotNull(ProviderFactory::registerFromEnvironment($app));
        $security = new class implements AuthenticationServiceInterface, AuthorizationServiceInterface {
            public function isLogged(): bool { return true; }
            public function getUser(): ?object { return new \stdClass(); }
            public function isAllowed(string $right, mixed $subject = null): bool { return true; }
        };
        $factory = $app->getSchemaFactory();
        $factory->setAuthenticationService($security)->setAuthorizationService($security);
        $result = GraphQL::executeQuery($factory->createSchema(),
            'query { oauthClients { id name redirectUris scopes confidential enabled } oauthClientScopes }')->toArray();
        self::assertArrayNotHasKey('errors', $result, json_encode($result));
        self::assertIsArray($result['data']['oauthClients']);
        self::assertIsArray($result['data']['oauthClientScopes']);
        self::assertFalse((bool) ProviderFactory::connection()->getAttribute(\PDO::ATTR_PERSISTENT));
    }

    public function testDisabledProviderNeedsNoOAuthConfiguration(): void
    {
        $enabled = $_ENV['OAUTH_ENABLED'] ?? null;
        try {
            $_ENV['OAUTH_ENABLED'] = 'false';
            self::assertNull(ProviderFactory::registerFromEnvironment(new App()));
        } finally {
            if ($enabled === null) unset($_ENV['OAUTH_ENABLED']);
            else $_ENV['OAUTH_ENABLED'] = $enabled;
        }
    }

    public function testApplicationCanSupplyItsOwnAuthorizationFlow(): void
    {
        if (!filter_var($_ENV['OAUTH_ENABLED'] ?? false, FILTER_VALIDATE_BOOLEAN)) self::markTestSkipped('Configure OAuth in the Light application');
        $flow = new class implements \Light\OAuth2\Contract\AuthorizationFlow {
            public function resolve(\Psr\Http\Message\ServerRequestInterface $request, \League\OAuth2\Server\RequestTypes\AuthorizationRequest $authorization): \Light\OAuth2\Contract\AuthorizationDecision|\Psr\Http\Message\ResponseInterface
            {
                return new \Laminas\Diactoros\Response\HtmlResponse('Custom authorization page');
            }
        };
        $provider = ProviderFactory::registerFromEnvironment(new App(), $flow);
        $store = new \Light\OAuth2\Storage\PdoStore(ProviderFactory::connection());
        $id = 'custom-flow-test-' . bin2hex(random_bytes(6));
        $store->createClient(['id' => $id, 'name' => 'Temporary test', 'redirect_uris' => ['https://example.com/callback'], 'confidential' => false, 'enabled' => true, 'scopes' => []]);
        try {
            $request = (new \Laminas\Diactoros\ServerRequest())->withQueryParams([
                'response_type' => 'code', 'client_id' => $id, 'redirect_uri' => 'https://example.com/callback',
                'state' => 'test-state', 'code_challenge' => str_repeat('a', 43), 'code_challenge_method' => 'S256',
            ]);
            $response = $provider->authorize($request);
            self::assertSame(200, $response->getStatusCode());
            self::assertSame('Custom authorization page', (string) $response->getBody());
        } finally {
            $store->deleteClient($id);
        }
    }
}
