<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;
use PHPUnit\Framework\TestCase;
use Light\OAuth2\{Config, OAuthProvider};
use Light\OAuth2\Contract\{PermissionProvider, AuthorizationFlow, AuthorizationDecision};
use Light\OAuth2\Auth\TokenValidator;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use Laminas\Diactoros\ServerRequest;
use Psr\Http\Message\{ServerRequestInterface, ResponseInterface};
final class OAuthTest extends TestCase
{
    private static string $privateKey = "";
    private static string $publicKey;
    private MemoryStore $store;
    private PermissionProvider $permissions;
    private AuthorizationFlow $flow;
    private Config $config;
    private OAuthProvider $provider;
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
        $this->store->saveClient(['id' => 'codex', 'name' => 'Codex', 'redirect_uris' => ['http://127.0.0.1:5555/callback'], 'confidential' => false, 'enabled' => true, 'scopes' => ['client.list']]);
        $this->permissions = new class implements PermissionProvider {
            public bool $allowed = true;
            public function scopes(): array { return ['client.list', 'client.edit']; }
            public function can(string $userId, string $permission): bool { return $this->allowed && $userId === '27' && $permission === 'client.list'; }
        };
        $this->flow = new class implements AuthorizationFlow {
            public bool $complete = true;
            public bool $approve = true;
            public function resolve(ServerRequestInterface $request, AuthorizationRequest $authorization): AuthorizationDecision|ResponseInterface
            { return new AuthorizationDecision('27', $this->approve, $this->complete); }
        };
        $this->config = new Config('https://auth.example.com', 'https://api.example.com/', self::$privateKey, self::$publicKey, str_repeat('x', 32));
        $this->provider = new OAuthProvider($this->config, $this->store, $this->permissions, $this->flow);
        $this->verifier = str_repeat('a', 64);
    }
    private function authorization(array $changes = []): ResponseInterface
    {
        $params = array_replace(['response_type' => 'code', 'client_id' => 'codex', 'redirect_uri' => 'http://127.0.0.1:5555/callback', 'scope' => 'client.list', 'state' => 'random-test-state', 'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $this->verifier, true)), '+/', '-_'), '='), 'code_challenge_method' => 'S256', 'resource' => $this->config->resource], $changes);
        return $this->provider->authorize((new ServerRequest())->withQueryParams($params));
    }
    private function code(): string
    {
        $response = $this->authorization();
        self::assertSame(302, $response->getStatusCode(), (string) $response->getBody());
        parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        self::assertSame('random-test-state', $query['state']);
        return $query['code'];
    }
    private function exchange(array $params): ResponseInterface
    {
        return $this->provider->token((new ServerRequest())->withMethod('POST')->withParsedBody($params));
    }
    private function tokens(): array
    {
        $response = $this->exchange(['grant_type' => 'authorization_code', 'client_id' => 'codex', 'redirect_uri' => 'http://127.0.0.1:5555/callback', 'code' => $this->code(), 'code_verifier' => $this->verifier]);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        return json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
    }
    private function request(string $token): ServerRequestInterface { return (new ServerRequest())->withHeader('Authorization', 'Bearer ' . $token); }
    public function testPkceExchangeResourceValidationAndLivePermission(): void
    {
        $tokens = $this->tokens();
        $context = $this->provider->validator()->validate($this->request($tokens['access_token']));
        self::assertSame('27', $context->userId);
        self::assertSame('codex', $context->clientId);
        self::assertTrue($context->can('client.list', $this->permissions));
        self::assertFalse($context->can('client.edit', $this->permissions));
        $this->permissions->allowed = false;
        self::assertFalse($context->can('client.list', $this->permissions));
        $wrong = new Config('https://auth.example.com', 'https://other.example.com/', self::$privateKey, self::$publicKey, str_repeat('x', 32));
        $this->expectException(OAuthServerException::class);
        (new TokenValidator($wrong, $this->store))->validate($this->request($tokens['access_token']));
    }
    public function testCodeCannotBeReplayedAndWrongVerifierDoesNotConsumeIt(): void
    {
        $params = ['grant_type' => 'authorization_code', 'client_id' => 'codex', 'redirect_uri' => 'http://127.0.0.1:5555/callback', 'code' => $this->code(), 'code_verifier' => str_repeat('b', 64)];
        self::assertSame(400, $this->exchange($params)->getStatusCode());
        $params['code_verifier'] = $this->verifier;
        self::assertSame(200, $this->exchange($params)->getStatusCode());
        self::assertSame(400, $this->exchange($params)->getStatusCode());
    }
    public function testRefreshRotationAndRevocation(): void
    {
        $tokens = $this->tokens();
        $params = ['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $tokens['refresh_token']];
        $response = $this->exchange($params);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame(400, $this->exchange($params)->getStatusCode());
        $new = json_decode((string) $response->getBody(), true);
        self::assertSame('27', $this->provider->validator()->validate($this->request($new['access_token']))->userId);
        $this->expectException(OAuthServerException::class);
        $this->provider->validator()->validate($this->request($tokens['access_token']));
    }
    public function testRefreshCannotExpandScopeAndChecksCurrentPermissions(): void
    {
        $tokens = $this->tokens();
        $params = ['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $tokens['refresh_token'], 'scope' => 'client.edit'];
        self::assertSame(400, $this->exchange($params)->getStatusCode());
        unset($params['scope']); $this->permissions->allowed = false;
        self::assertSame(400, $this->exchange($params)->getStatusCode());
    }
    public function testSecondFactorAndInvalidAuthorizationAreRejected(): void
    {
        $this->flow->complete = false;
        self::assertSame(401, $this->authorization()->getStatusCode());
        $this->flow->complete = true;
        foreach ([['code_challenge_method' => 'plain'], ['state' => ''], ['resource' => 'https://evil.example.com'], ['scope' => 'client.edit'], ['scope' => 'unknown'], ['redirect_uri' => 'https://evil.example.com']] as $changes) {
            $response = $this->authorization($changes);
            self::assertContains($response->getStatusCode(), [400, 401, 302]);
            if ($response->getStatusCode() === 302) self::assertStringContainsString('error=', $response->getHeaderLine('Location')); 
        }
        self::assertEmpty($this->store->records);
    }
    public function testDeniedConsentReturnsErrorWithoutIssuingCode(): void
    {
        $this->flow->approve = false;
        $response = $this->authorization();
        self::assertStringContainsString('error=access_denied', $response->getHeaderLine('Location'));
        self::assertEmpty($this->store->records);
    }
    public function testMetadataAndDisabledClient(): void
    {
        $metadata = json_decode((string) $this->provider->metadata(new ServerRequest())->getBody(), true);
        self::assertSame(['S256'], $metadata['code_challenge_methods_supported']);
        self::assertSame('https://auth.example.com/oauth/token', $metadata['token_endpoint']);
        $tokens = $this->tokens();
        $this->store->clients['codex']['enabled'] = false;
        $this->expectException(OAuthServerException::class);
        $this->provider->validator()->validate($this->request($tokens['access_token']));
    }
    public function testRevocationEndpointRejectsReuseAndUnknownTokensAreSuccessful(): void
    {
        $tokens = $this->tokens();
        $request = (new ServerRequest())->withParsedBody(['client_id' => 'codex', 'token' => $tokens['refresh_token']]);
        self::assertSame(200, $this->provider->revoke($request)->getStatusCode());
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $tokens['refresh_token']])->getStatusCode());
        self::assertSame(200, $this->provider->revoke($request->withParsedBody(['client_id' => 'codex', 'token' => 'unknown']))->getStatusCode());
        $this->expectException(OAuthServerException::class);
        $this->provider->validator()->validate($this->request($tokens['access_token']));
    }
    public function testConfidentialClientRequiresSecretAndWrongClientCannotRedeemCode(): void
    {
        $client = $this->store->clients['codex'];
        $client['id'] = 'private'; $client['confidential'] = true; $client['secret_hash'] = password_hash('secret', PASSWORD_DEFAULT);
        $this->store->saveClient($client);
        $params = ['grant_type' => 'authorization_code', 'client_id' => 'private', 'redirect_uri' => 'http://127.0.0.1:5555/callback', 'code' => $this->code(), 'code_verifier' => $this->verifier];
        self::assertSame(400, $this->exchange($params)->getStatusCode());
        $params['client_secret'] = 'secret';
        self::assertSame(400, $this->exchange($params)->getStatusCode());
    }

    public function testProviderRegistersRoutesAndAuthenticatesThroughLightFactory(): void
    {
        if (!method_exists(\Light\App::class, 'setAuthServiceFactory')) self::markTestSkipped('Set LIGHT_SOURCE_PATH to patched Light checkout');
        $app = (new \ReflectionClass(\Light\App::class))->newInstanceWithoutConstructor();
        $router = new \League\Route\Router();
        $server = $this->createStub(\Light\Server::class);
        $server->method('getRouter')->willReturn($router);
        (new \ReflectionProperty(\Light\App::class, 'server'))->setValue($app, $server);
        (new \ReflectionProperty(\Light\App::class, 'cache'))->setValue($app, new \Symfony\Component\Cache\Psr16Cache(new \Symfony\Component\Cache\Adapter\ArrayAdapter()));
        $user = (new \ReflectionClass(\Light\Model\User::class))->newInstanceWithoutConstructor();
        $this->provider->register($app, fn() => $user);
        $request = (new ServerRequest())->withMethod('GET')->withUri(new \Laminas\Diactoros\Uri('https://auth.example.com/.well-known/oauth-authorization-server'));
        self::assertSame(200, $router->dispatch($request)->getStatusCode());
        $request = $request->withMethod('POST')->withUri(new \Laminas\Diactoros\Uri('https://auth.example.com/oauth/token'))->withParsedBody(['grant_type' => 'bad']);
        self::assertSame(400, $router->dispatch($request)->getStatusCode());
        $token = $this->tokens()['access_token'];
        $request = $this->request($token)->withUri(new \Laminas\Diactoros\Uri('https://api.example.com/'));
        $service = $app->createAuthService($request);
        self::assertTrue($service->isLogged());
        self::assertTrue($service->isAllowed('client.list'));
        self::assertFalse($service->isAllowed('client.edit'));
        $id = $this->provider->validator()->validate($request)->tokenId;
        $this->store->revoke('access_token', $id);
        self::assertFalse($app->createAuthService($request)->isLogged());
    }

}
