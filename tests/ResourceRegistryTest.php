<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;
use PHPUnit\Framework\TestCase;
use Light\OAuth2\{Config, OAuthProvider, ResourceRegistry, TokenExchangePolicy};
use Light\OAuth2\Auth\TokenValidator;
use Light\OAuth2\Contract\{PermissionProvider, AuthorizationFlow, AuthorizationDecision};
use Light\OAuth2\Management\{ResourceManager, ClientManager};
use Light\OAuth2\Input\{OAuthResourceInput, OAuthClientInput};
use Light\OAuth2\ClientMetadata\{ClientResolver, MetadataFetcher};
use Light\OAuth2\Grant\TokenExchangeGrant;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Laminas\Diactoros\{ServerRequest, Stream};
use Psr\Http\Message\{ServerRequestInterface, ResponseInterface};
final class ResourceRegistryTest extends TestCase
{
    private const MCP = 'https://mcp.example.com/mcp';
    private const API = 'https://api.example.com/';
    private const OTHER = 'https://third.example.com/api';
    private static string $privateKey = '';
    private static string $publicKey;
    private MemoryStore $store;
    private Config $config;
    private PermissionProvider $permissions;
    private OAuthProvider $provider;
    private ResourceRegistry $registry;
    private string $verifier;
    public static function setUpBeforeClass(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, self::$privateKey);
        self::$publicKey = openssl_pkey_get_details($key)['key'];
    }
    protected function setUp(): void
    {
        $this->store = new MemoryStore();
        $this->config = new Config('https://auth.example.com', self::MCP, self::$privateKey, self::$publicKey, str_repeat('x', 32), apiResource: self::API, autoSelectScopes: true, dcrEnabled: true);
        $this->permissions = new class implements PermissionProvider {
            public function scopes(): array { return ['client.list', 'invoice.list', 'client.edit']; }
            public function can(string $userId, string $permission): bool { return $userId === '27' && $permission !== 'client.edit'; }
        };
        foreach ([self::MCP => ['client.list'], self::API => ['client.list', 'invoice.list'], self::OTHER => ['invoice.list']] as $id => $scopes) {
            $this->store->createResource(['id' => $id, 'name' => $id, 'scopes' => $scopes, 'enabled' => true]);
        }
        $this->store->saveClient(['id' => 'client', 'name' => 'Client', 'redirect_uris' => ['http://127.0.0.1/callback'], 'scopes' => $this->permissions->scopes(), 'confidential' => false, 'enabled' => true, 'resources' => [self::MCP, self::API, self::OTHER]]);
        $flow = new class implements AuthorizationFlow {
            public function resolve(ServerRequestInterface $request, AuthorizationRequest $authorization): AuthorizationDecision|ResponseInterface {
                $automatic = $request->getAttribute(\Light\OAuth2\AutomaticScopes::class);
                if ($automatic !== null) $automatic->select($authorization, '27');
                return new AuthorizationDecision('27', true, true);
            }
        };
        $this->registry = new ResourceRegistry($this->config, $this->store);
        $this->provider = new OAuthProvider($this->config, $this->store, $this->permissions, $flow, new TokenExchangePolicy(['exchange' => ['source' => self::MCP, 'targets' => [self::API => ['client.list']]]]));
        $this->verifier = str_repeat('v', 64);
    }
    private function authorize(string $resource, ?string $scope = null): ResponseInterface
    {
        $params = ['resource' => $resource, 'response_type' => 'code', 'client_id' => 'client', 'redirect_uri' => 'http://127.0.0.1/callback', 'state' => 'test', 'code_challenge_method' => 'S256', 'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $this->verifier, true)), '+/', '-_'), '=')];
        if ($scope !== null) $params['scope'] = $scope;
        return $this->provider->authorize((new ServerRequest())->withQueryParams($params));
    }
    private function exchange(array $params): ResponseInterface { return $this->provider->token((new ServerRequest())->withParsedBody($params)); }
    private function tokens(string $resource, ?string $scope = null): array
    {
        $response = $this->authorize($resource, $scope);
        self::assertSame(302, $response->getStatusCode(), (string) $response->getBody());
        parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $response = $this->exchange(['grant_type' => 'authorization_code', 'code' => $query['code'], 'client_id' => 'client', 'redirect_uri' => 'http://127.0.0.1/callback', 'code_verifier' => $this->verifier]);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        return json_decode((string) $response->getBody(), true);
    }
    private function context(array $tokens, string $resource): \Light\OAuth2\Auth\TokenContext
    {
        return (new TokenValidator($this->config->forResource($resource), $this->store, registry: $this->registry))->validate((new ServerRequest())->withHeader('Authorization', 'Bearer ' . $tokens['access_token']));
    }
    public function testDatabaseOnlyResourcesAndAutomaticScopesWorkWithoutEnvironmentAllowlist(): void
    {
        self::assertNotSame(self::OTHER, $this->config->resource);
        self::assertNotSame(self::OTHER, $this->config->apiResource);
        self::assertArrayNotHasKey('resourceRegistryEnabled', get_object_vars($this->config));
        $tokens = $this->tokens(self::OTHER);
        self::assertSame(['invoice.list'], $this->context($tokens, self::OTHER)->scopes);
        $denied = $this->authorize(self::OTHER, 'client.list');
        parse_str(parse_url($denied->getHeaderLine('Location'), PHP_URL_QUERY), $error);
        self::assertSame('invalid_scope', $error['error']);
        self::assertArrayNotHasKey('code', $error);
        self::assertSame(400, $this->authorize('https://unknown.example.com/')->getStatusCode());
        $this->store->deleteResource(self::API);
        // Being configured as the local API audience does not bypass DB policy.
        self::assertSame(400, $this->authorize(self::API)->getStatusCode());
    }
    public function testClientAssignmentsApplyToAuthorizationAndRefresh(): void
    {
        $tokens = $this->tokens(self::API);
        $client = $this->store->client('client');
        $client['resources'] = [self::MCP]; $this->store->saveClient($client);
        self::assertSame(400, $this->authorize(self::API)->getStatusCode());
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'client', 'refresh_token' => $tokens['refresh_token']])->getStatusCode());
        $this->expectException(OAuthServerException::class);
        $this->context($tokens, self::API);
    }
    public function testResourceDisableAndScopeRemovalAffectExistingTokens(): void
    {
        $tokens = $this->tokens(self::API);
        self::assertSame(['client.list', 'invoice.list'], $this->context($tokens, self::API)->scopes);
        $record = $this->store->resource(self::API); $record['scopes'] = ['client.list']; $this->store->saveResource($record);
        self::assertSame(['client.list'], $this->context($tokens, self::API)->scopes);
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'client', 'refresh_token' => $tokens['refresh_token']])->getStatusCode());
        $response = $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'client', 'refresh_token' => $tokens['refresh_token'], 'scope' => 'client.list']);
        self::assertSame(200, $response->getStatusCode());
        $record['enabled'] = false; $this->store->saveResource($record);
        self::assertSame(400, $this->authorize(self::API)->getStatusCode());
        $this->expectException(OAuthServerException::class);
        $this->context(json_decode((string) $response->getBody(), true), self::API);
    }
    public function testCodeRedemptionRechecksResourceAndClientPolicy(): void
    {
        $response = $this->authorize(self::API, 'client.list');
        parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $params = ['grant_type' => 'authorization_code', 'code' => $query['code'], 'client_id' => 'client', 'redirect_uri' => 'http://127.0.0.1/callback', 'code_verifier' => $this->verifier];
        $resource = $this->store->resource(self::API); $resource['enabled'] = false; $this->store->saveResource($resource);
        self::assertSame(400, $this->exchange($params)->getStatusCode());
        $resource['enabled'] = true; $this->store->saveResource($resource);
        $client = $this->store->client('client'); $client['resources'] = [self::MCP]; $this->store->saveClient($client);
        self::assertSame(400, $this->exchange($params)->getStatusCode());
        $client['resources'][] = self::API; $this->store->saveClient($client);
        self::assertSame(200, $this->exchange($params)->getStatusCode());
    }
    public function testAutomaticScopesIntersectResourceClientAndCurrentUserPermissions(): void
    {
        $resource = $this->store->resource(self::API); $resource['scopes'][] = 'client.edit'; $this->store->saveResource($resource);
        $client = $this->store->client('client'); $client['scopes'] = ['client.list', 'client.edit']; $this->store->saveClient($client);
        self::assertSame(['client.list'], $this->context($this->tokens(self::API), self::API)->scopes);
    }
    public function testLegacyClientGetsOnlyDefaultResource(): void
    {
        $client = $this->store->client('client'); unset($client['resources']); $this->store->saveClient($client);
        self::assertSame(302, $this->authorize(self::MCP)->getStatusCode());
        self::assertSame(400, $this->authorize(self::API)->getStatusCode());
    }
    public function testResourceAndClientManagementEnforceScopeAndResourcePolicy(): void
    {
        $manager = new ResourceManager($this->store, $this->permissions);
        $input = new OAuthResourceInput(); $input->id = 'https://new.example.com/'; $input->name = 'New'; $input->enabled = true; $input->scopes = ['client.list'];
        self::assertSame($input->id, $manager->save($input, true)->id);
        $input->enabled = false; self::assertFalse($manager->save($input, false)->enabled);
        self::assertCount(4, $manager->resources());
        self::assertTrue($manager->delete($input->id));
        $client = new OAuthClientInput(); $client->id = 'managed'; $client->name = 'Managed'; $client->redirectUris = ['https://client.example.com/callback']; $client->confidential = false; $client->enabled = true; $client->scopes = ['invoice.list']; $client->resources = [self::API];
        $clients = new ClientManager($this->store, $this->permissions, $this->registry);
        self::assertSame([self::API], $clients->save($client, true)->client->resources);
        // An older management UI omitting resources must preserve the assignment.
        $client->resources = null; self::assertSame([self::API], $clients->save($client, false)->client->resources);
        $client->resources = [self::MCP];
        $this->expectException(\InvalidArgumentException::class);
        $clients->save($client, false);
    }
    public function testManagementRejectsUnknownScopesAndInvalidResourceUrls(): void
    {
        $manager = new ResourceManager($this->store, $this->permissions);
        foreach (['http://untrusted.example.com/', 'https://api.example.com/#fragment', 'https://user:pass@api.example.com/'] as $id) {
            $input = new OAuthResourceInput(); $input->id = $id; $input->name = 'Bad'; $input->enabled = true; $input->scopes = ['client.list'];
            try { $manager->save($input, true); self::fail('Invalid URL accepted'); } catch (\InvalidArgumentException) { self::assertNull($this->store->resource($id)); }
        }
        $input->id = 'https://new.example.com/'; $input->scopes = ['unknown.scope'];
        $this->expectException(\InvalidArgumentException::class); $manager->save($input, true);
    }
    public function testGraphQLResourceManagementAndClientAssociationsRequirePermissions(): void
    {
        $container = new \League\Container\Container();
        $resources = new \Light\OAuth2\Controller\OAuthResourceController(new ResourceManager($this->store, $this->permissions));
        $clients = new \Light\OAuth2\Controller\OAuthClientController(new ClientManager($this->store, $this->permissions, $this->registry));
        $container->add($resources::class, $resources); $container->add($clients::class, $clients);
        $cache = new \Symfony\Component\Cache\Psr16Cache(new \Symfony\Component\Cache\Adapter\ArrayAdapter());
        $factory = new \TheCodingMachine\GraphQLite\SchemaFactory($cache, $container);
        $factory->setFinder(\Light\GraphQL\ControllerDiscovery::finder($container));
        foreach (['Controller', 'Type', 'Input'] as $part) $factory->addNamespace('Light\\OAuth2\\' . $part);
        $security = new class implements \TheCodingMachine\GraphQLite\Security\AuthenticationServiceInterface, \TheCodingMachine\GraphQLite\Security\AuthorizationServiceInterface {
            public bool $logged = true;
            public bool $allowed = true;
            public function isLogged(): bool { return $this->logged; }
            public function getUser(): ?object { return $this->logged ? new \stdClass() : null; }
            public function isAllowed(string $right, mixed $subject = null): bool { return $this->allowed; }
        };
        $factory->setAuthenticationService($security)->setAuthorizationService($security); $schema = $factory->createSchema();
        $mutation = 'mutation { createOAuthResource(input: {id: "https://graphql.example.com/", name: "GraphQL", scopes: ["client.list"], enabled: true}) {id scopes enabled} }';
        $result = \GraphQL\GraphQL::executeQuery($schema, $mutation)->toArray();
        self::assertArrayNotHasKey('errors', $result, json_encode($result));
        self::assertSame(['client.list'], $result['data']['createOAuthResource']['scopes']);
        $result = \GraphQL\GraphQL::executeQuery($schema, 'mutation { createOAuthClient(input: {id: "graphql", name: "Client", redirectUris: ["https://client.example.com/callback"], resources: ["https://graphql.example.com/"], scopes: ["client.list"], confidential: false, enabled: true}) {client {resources}} }')->toArray();
        self::assertArrayNotHasKey('errors', $result, json_encode($result));
        self::assertSame(['https://graphql.example.com/'], $result['data']['createOAuthClient']['client']['resources']);
        $result = \GraphQL\GraphQL::executeQuery($schema, '{oauthResources {id name scopes enabled} oauthResourceScopes oauthClientResourcePolicy {defaultResource resources {id scopes enabled}}}')->toArray();
        self::assertArrayNotHasKey('errors', $result, json_encode($result)); self::assertCount(4, $result['data']['oauthResources']);
        self::assertSame(self::MCP, $result['data']['oauthClientResourcePolicy']['defaultResource']);
        self::assertCount(4, $result['data']['oauthClientResourcePolicy']['resources']);
        $security->allowed = false;
        self::assertArrayHasKey('errors', \GraphQL\GraphQL::executeQuery($schema, $mutation)->toArray());
        self::assertArrayHasKey('errors', \GraphQL\GraphQL::executeQuery($schema, '{oauthResources {id}}')->toArray());
        $security->allowed = true; $security->logged = false;
        self::assertArrayHasKey('errors', \GraphQL\GraphQL::executeQuery($schema, '{oauthResources {id}}')->toArray());
    }
    private function register(array $extra): ResponseInterface
    {
        $body = new Stream('php://temp', 'r+');
        $body->write(json_encode($extra + ['redirect_uris' => ['https://client.example.com/callback'], 'token_endpoint_auth_method' => 'none'])); $body->rewind();
        return $this->provider->registerClient((new ServerRequest())->withMethod('POST')->withHeader('Content-Type', 'application/json')->withBody($body));
    }
    public function testDcrRegistersKnownResourcesWithoutCreatingUntrustedResources(): void
    {
        $response = $this->register(['resources' => [self::OTHER]]);
        self::assertSame(201, $response->getStatusCode(), (string) $response->getBody());
        $result = json_decode((string) $response->getBody(), true);
        self::assertSame([self::OTHER], $result['resources']); self::assertSame('invoice.list', $result['scope']);
        self::assertSame([self::OTHER], $this->store->client($result['client_id'])['resources']);
        foreach ([['resources' => ['https://unknown.example.com/']], ['resources' => [self::MCP], 'scope' => 'invoice.list'], ['resources' => null], ['resources' => []]] as $extra) {
            self::assertSame(400, $this->register($extra)->getStatusCode());
        }
        self::assertCount(3, $this->store->resources()); self::assertCount(2, $this->store->clients());
        $response = $this->register([]); $result = json_decode((string) $response->getBody(), true);
        self::assertSame([self::MCP], $result['resources']); self::assertSame('client.list', $result['scope']);
    }
    public function testCimdUsesKnownResourcesAndNeverPersistsRemoteClient(): void
    {
        $id = 'https://client.example.com/metadata.json';
        $fetcher = new class($id) implements MetadataFetcher {
            public array $resources = ['https://third.example.com/api'];
            public function __construct(private string $id) {}
            public function fetch(string $url): array { return ['client_id' => $this->id, 'redirect_uris' => ['https://client.example.com/callback'], 'resources' => $this->resources]; }
        };
        $resolver = new ClientResolver($this->store, $this->permissions->scopes(), $fetcher, $this->registry);
        $record = $resolver->client($id);
        self::assertSame([self::OTHER], $record['resources']); self::assertSame(['invoice.list'], $record['scopes']); self::assertNull($this->store->client($id));
        $fetcher->resources = ['https://untrusted.example.com/'];
        self::assertNull((new ClientResolver($this->store, $this->permissions->scopes(), $fetcher, $this->registry))->client($id));
    }
    public function testExchangeStillWorksButChecksTargetResourceAndScopes(): void
    {
        $tokens = $this->tokens(self::MCP);
        $this->store->saveClient(['id' => 'exchange', 'name' => 'Exchange', 'redirect_uris' => ['https://client.example.com/callback'], 'scopes' => ['client.list'], 'confidential' => true, 'secret_hash' => password_hash('secret', PASSWORD_DEFAULT), 'enabled' => true, 'resources' => [self::API]]);
        $params = ['grant_type' => TokenExchangeGrant::IDENTIFIER, 'client_id' => 'exchange', 'client_secret' => 'secret', 'subject_token' => $tokens['access_token'], 'subject_token_type' => TokenExchangeGrant::ACCESS_TOKEN_TYPE, 'resource' => self::API];
        $response = $this->exchange($params); self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame(['client.list'], $this->context(json_decode((string) $response->getBody(), true), self::API)->scopes);
        $record = $this->store->resource(self::API); $record['enabled'] = false; $this->store->saveResource($record);
        self::assertSame(400, $this->exchange($params)->getStatusCode());
    }
}
