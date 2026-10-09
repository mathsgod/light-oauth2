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
            {
                $automatic = $request->getAttribute(\Light\OAuth2\AutomaticScopes::class);
                if ($automatic && $this->complete) $automatic->select($authorization, '27');
                return new AuthorizationDecision('27', $this->approve, $this->complete);
            }
        };
        $this->config = new Config('https://auth.example.com', 'https://api.example.com/', self::$privateKey, self::$publicKey, str_repeat('x', 32));
        $this->provider = new OAuthProvider($this->config, $this->store, $this->permissions, $this->flow);
        $this->verifier = str_repeat('a', 64);
    }
    private function enableMultipleResources(): void
    {
        $this->config = new Config('https://auth.example.com', 'https://mcp.example.com/mcp', self::$privateKey, self::$publicKey, str_repeat('x', 32), apiResource: 'https://api.example.com/', additionalResources: ['https://other.example.com/api']);
        $this->provider = new OAuthProvider($this->config, $this->store, $this->permissions, $this->flow);
    }
    private function codeForResource(?string $resource): array
    {
        $response = $this->authorization(['resource' => $resource]);
        self::assertSame(302, $response->getStatusCode(), (string) $response->getBody());
        parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        return ['grant_type' => 'authorization_code', 'client_id' => 'codex', 'redirect_uri' => 'http://127.0.0.1:5555/callback', 'code' => $query['code'], 'code_verifier' => $this->verifier];
    }
    public function testDirectResourceTokensAndRefreshKeepTheirAudience(): void
    {
        $this->enableMultipleResources();
        foreach ($this->config->resources() as $resource) {
            $params = $this->codeForResource($resource);
            // Token request may omit resource: use the server-stored authorization.
            $response = $this->exchange($params);
            self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
            $tokens = json_decode((string) $response->getBody(), true);
            $validator = new TokenValidator($this->config->forResource($resource), $this->store);
            self::assertSame(['client.list'], $validator->validate($this->request($tokens['access_token']))->scopes);
            $wrong = $resource === $this->config->resource ? $this->config->apiResource : $this->config->resource;
            try {
                (new TokenValidator($this->config->forResource($wrong), $this->store))->validate($this->request($tokens['access_token']));
                self::fail('Token must not work at another resource');
            } catch (OAuthServerException $error) { self::assertStringContainsString('resource', $error->getHint()); }
            $refresh = ['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $tokens['refresh_token']];
            self::assertSame(400, $this->exchange($refresh + ['resource' => $wrong])->getStatusCode());
            $response = $this->exchange($refresh);
            self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
            $tokens = json_decode((string) $response->getBody(), true);
            self::assertSame(['client.list'], $validator->validate($this->request($tokens['access_token']))->scopes);
            // Revocation must support direct non-default audience tokens too.
            $response = $this->provider->revoke((new ServerRequest())->withParsedBody(['client_id' => 'codex', 'token' => $tokens['access_token']]));
            self::assertSame(200, $response->getStatusCode());
            $this->expectRevoked($validator, $tokens['access_token']);
        }
    }
    private function expectRevoked(TokenValidator $validator, string $token): void
    {
        try { $validator->validate($this->request($token)); self::fail('Token must be revoked'); }
        catch (OAuthServerException) { self::assertTrue(true); }
    }
    public function testAuthorizationCodeCannotChangeResourceAndFailedExchangeDoesNotConsumeCode(): void
    {
        $this->enableMultipleResources();
        $params = $this->codeForResource($this->config->apiResource);
        self::assertSame(400, $this->exchange($params + ['resource' => $this->config->resource])->getStatusCode());
        $response = $this->exchange($params + ['resource' => $this->config->apiResource]);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $tokens = json_decode((string) $response->getBody(), true);
        (new TokenValidator($this->config->forResource($this->config->apiResource), $this->store))->validate($this->request($tokens['access_token']));
    }
    public function testUntrustedMalformedAndTrailingSlashResourcesAreRejected(): void
    {
        $this->enableMultipleResources();
        foreach (['https://evil.example.com/', ['https://api.example.com/'], '', 'https://api.example.com', false] as $resource) {
            self::assertSame(400, $this->authorization(['resource' => $resource])->getStatusCode());
            self::assertSame(400, $this->exchange(['grant_type' => 'authorization_code', 'resource' => $resource])->getStatusCode());
        }
    }
    public function testResourceSelectionDoesNotLeakBetweenRequests(): void
    {
        $this->enableMultipleResources();
        $api = $this->codeForResource($this->config->apiResource);
        $mcp = $this->codeForResource($this->config->resource);
        foreach ([$api, $mcp, $this->codeForResource($this->config->resource)] as $index => $params) {
            $response = $this->exchange($params);
            self::assertSame(200, $response->getStatusCode());
            $tokens = json_decode((string) $response->getBody(), true);
            $resource = $index === 0 ? $this->config->apiResource : $this->config->resource;
            (new TokenValidator($this->config->forResource($resource), $this->store))->validate($this->request($tokens['access_token']));
        }
    }
    public function testOmittedAndLegacyResourceKeepDefaultAudience(): void
    {
        $this->enableMultipleResources();
        $response = $this->authorization();
        parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        // Model a code issued before the resource field existed.
        foreach ($this->store->records['auth_code'] as &$record) unset($record['resource']);
        unset($record);
        $params = ['grant_type' => 'authorization_code', 'client_id' => 'codex', 'redirect_uri' => 'http://127.0.0.1:5555/callback', 'code' => $query['code'], 'code_verifier' => $this->verifier];
        self::assertSame(400, $this->exchange($params + ['resource' => $this->config->apiResource])->getStatusCode());
        $response = $this->exchange($params);
        self::assertSame(200, $response->getStatusCode());
        $tokens = json_decode((string) $response->getBody(), true);
        $this->provider->validator()->validate($this->request($tokens['access_token']));
        foreach ($this->store->records['refresh_token'] as &$record) unset($record['resource']);
        unset($record);
        $response = $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $tokens['refresh_token'], 'resource' => $this->config->resource]);
        self::assertSame(200, $response->getStatusCode());
        $tokens = json_decode((string) $response->getBody(), true);
        $this->provider->validator()->validate($this->request($tokens['access_token']));
        $selection = new \Light\OAuth2\ResourceSelection($this->config);
        $selection->begin([]);
        self::assertSame($this->config->resource, $selection->resource());
    }
    public function testRepeatedResourcesAreRejectedInQueryAndFormBody(): void
    {
        $this->enableMultipleResources();
        $raw = 'resource=' . urlencode($this->config->resource) . '&resource=' . urlencode($this->config->apiResource);
        $request = (new ServerRequest())->withUri(new \Laminas\Diactoros\Uri('https://auth.example.com/oauth/authorize?' . $raw))->withQueryParams(['resource' => $this->config->apiResource]);
        self::assertSame(400, $this->provider->authorize($request)->getStatusCode());
        $request = (new ServerRequest())->withParsedBody(['grant_type' => 'authorization_code', 'resource' => $this->config->apiResource]);
        $body = new \Laminas\Diactoros\Stream('php://temp', 'r+');
        $body->write($raw);
        $request = $request->withBody($body);
        self::assertSame(400, $this->provider->token($request)->getStatusCode());
    }
    private function authorization(array $changes = []): ResponseInterface
    {
        $params = array_replace(['response_type' => 'code', 'client_id' => 'codex', 'redirect_uri' => 'http://127.0.0.1:5555/callback', 'scope' => 'client.list', 'state' => 'random-test-state', 'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $this->verifier, true)), '+/', '-_'), '='), 'code_challenge_method' => 'S256', 'resource' => $this->config->resource], $changes);
        if (array_key_exists('scope', $changes) && $changes['scope'] === null) unset($params['scope']);
        return $this->provider->authorize((new ServerRequest())->withQueryParams($params));
    }
    private function enableAutomaticScopes(): void
    {
        $this->config = new Config($this->config->issuer, $this->config->resource, self::$privateKey, self::$publicKey, str_repeat('x', 32), autoSelectScopes: true);
        $this->provider = new OAuthProvider($this->config, $this->store, $this->permissions, $this->flow);
    }
    public function testOmittedScopesSelectIntersectionAndIssueUsableToken(): void
    {
        $this->store->saveClient(['id' => 'codex', 'name' => 'Codex', 'redirect_uris' => ['http://127.0.0.1:5555/callback'], 'confidential' => false, 'enabled' => true, 'scopes' => ['client.list', 'client.edit', 'unknown']]);
        $this->enableAutomaticScopes();
        self::assertTrue($this->config->forResource('https://other.example.com')->autoSelectScopes);
        $response = $this->authorization(['scope' => null]);
        self::assertSame(302, $response->getStatusCode(), (string) $response->getBody());
        parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $response = $this->exchange(['grant_type' => 'authorization_code', 'client_id' => 'codex', 'redirect_uri' => 'http://127.0.0.1:5555/callback', 'code' => $query['code'], 'code_verifier' => $this->verifier]);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $tokens = json_decode((string) $response->getBody(), true);
        self::assertSame(['client.list'], $this->provider->validator()->validate($this->request($tokens['access_token']))->scopes);
    }
    public function testAutomaticScopesRejectEmptyIntersection(): void
    {
        $this->enableAutomaticScopes();
        $this->permissions->allowed = false;
        $response = $this->authorization(['scope' => null]);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_scope', json_decode((string) $response->getBody(), true)['error']);
    }
    public function testExplicitScopesRemainStrictWithAutomaticSelection(): void
    {
        $this->enableAutomaticScopes();
        self::assertSame(400, $this->authorization(['scope' => 'client.edit'])->getStatusCode());
        self::assertSame(302, $this->authorization(['scope' => ''])->getStatusCode());
    }
    public function testAutomaticScopeFlowCannotApproveWithoutSelectingScopes(): void
    {
        $this->enableAutomaticScopes();
        $flow = new class implements AuthorizationFlow {
            public function resolve(ServerRequestInterface $request, AuthorizationRequest $authorization): AuthorizationDecision|ResponseInterface
            { return new AuthorizationDecision('27', true, true); }
        };
        $this->provider = new OAuthProvider($this->config, $this->store, $this->permissions, $flow);
        self::assertSame(401, $this->authorization(['scope' => null])->getStatusCode());
    }
    public function testOmittedScopesRemainEmptyByDefault(): void
    {
        $response = $this->authorization(['scope' => null]);
        self::assertSame(302, $response->getStatusCode());
        parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $response = $this->exchange(['grant_type' => 'authorization_code', 'client_id' => 'codex', 'redirect_uri' => 'http://127.0.0.1:5555/callback', 'code' => $query['code'], 'code_verifier' => $this->verifier]);
        self::assertSame(200, $response->getStatusCode());
        $tokens = json_decode((string) $response->getBody(), true);
        self::assertSame([], $this->provider->validator()->validate($this->request($tokens['access_token']))->scopes);
    }
    public function testAutomaticSelectionUsesResolvedCimdClientScopes(): void
    {
        $id = 'https://client.example.com/automatic.json';
        $config = new Config($this->config->issuer, $this->config->resource, self::$privateKey, self::$publicKey, str_repeat('x', 32), cimdEnabled: true, autoSelectScopes: true);
        $fetcher = new class implements \Light\OAuth2\ClientMetadata\MetadataFetcher {
            public function fetch(string $url): array {
                return ['client_id' => $url, 'client_name' => 'Automatic client', 'redirect_uris' => ['http://127.0.0.1/callback'], 'token_endpoint_auth_method' => 'none', 'scope' => 'client.list client.edit'];
            }
        };
        $this->provider = new OAuthProvider($config, $this->store, $this->permissions, $this->flow, metadataFetcher: $fetcher);
        $response = $this->authorization(['client_id' => $id, 'scope' => null]);
        self::assertSame(302, $response->getStatusCode(), (string) $response->getBody());
        parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $response = $this->exchange(['grant_type' => 'authorization_code', 'client_id' => $id, 'redirect_uri' => 'http://127.0.0.1:5555/callback', 'code' => $query['code'], 'code_verifier' => $this->verifier]);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $tokens = json_decode((string) $response->getBody(), true);
        self::assertSame(['client.list'], $this->provider->validator()->validate($this->request($tokens['access_token']))->scopes);
    }
    public function testConsentSubsetIsPreservedInTokensAndRefresh(): void
    {
        foreach ([false, true] as $automatic) {
            $this->store->saveClient(['id' => 'codex', 'name' => 'Codex', 'redirect_uris' => ['http://127.0.0.1:5555/callback'], 'confidential' => false, 'enabled' => true, 'scopes' => ['client.list', 'client.edit']]);
            $permissions = new class implements PermissionProvider {
                public function scopes(): array { return ['client.list', 'client.edit']; }
                public function can(string $userId, string $permission): bool { return $userId === '27' && in_array($permission, $this->scopes(), true); }
            };
            $flow = new class implements AuthorizationFlow {
                public function resolve(ServerRequestInterface $request, AuthorizationRequest $authorization): AuthorizationDecision|ResponseInterface {
                    $selector = $request->getAttribute(\Light\OAuth2\AutomaticScopes::class);
                    if ($selector) $selector->select($authorization, '27');
                    \Light\OAuth2\ConsentScopes::apply($authorization, ['client.list']);
                    return new AuthorizationDecision('27', true, true);
                }
            };
            $config = new Config($this->config->issuer, $this->config->resource, self::$privateKey, self::$publicKey, str_repeat('x', 32), autoSelectScopes: $automatic);
            $this->provider = new OAuthProvider($config, $this->store, $permissions, $flow);
            $response = $this->authorization(['scope' => $automatic ? null : 'client.list client.edit']);
            self::assertSame(302, $response->getStatusCode(), (string) $response->getBody());
            parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
            $response = $this->exchange(['grant_type' => 'authorization_code', 'client_id' => 'codex', 'redirect_uri' => 'http://127.0.0.1:5555/callback', 'code' => $query['code'], 'code_verifier' => $this->verifier]);
            self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
            $tokens = json_decode((string) $response->getBody(), true);
            self::assertSame(['client.list'], $this->provider->validator()->validate($this->request($tokens['access_token']))->scopes);
            self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $tokens['refresh_token'], 'scope' => 'client.edit'])->getStatusCode());
            $response = $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $tokens['refresh_token']]);
            self::assertSame(200, $response->getStatusCode());
            $refreshed = json_decode((string) $response->getBody(), true);
            self::assertSame(['client.list'], $this->provider->validator()->validate($this->request($refreshed['access_token']))->scopes);
        }
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
    public function testCimdAuthorizationTokenRefreshValidationAndRevocation(): void
    {
        $id = 'https://client.example.com/codex/client.json';
        $config = new Config($this->config->issuer, $this->config->resource, self::$privateKey, self::$publicKey, str_repeat('x', 32), cimdEnabled: true);
        $fetcher = new class implements \Light\OAuth2\ClientMetadata\MetadataFetcher {
            public function fetch(string $url): array {
                return ['client_id' => $url, 'client_name' => 'Codex', 'redirect_uris' => ['http://127.0.0.1/callback', 'http://localhost/callback'], 'token_endpoint_auth_method' => 'none', 'scope' => 'client.list'];
            }
        };
        $this->provider = new OAuthProvider($config, $this->store, $this->permissions, $this->flow, metadataFetcher: $fetcher);
        $metadata = json_decode((string) $this->provider->metadata(new ServerRequest())->getBody(), true);
        self::assertTrue($metadata['client_id_metadata_document_supported']);
        $response = $this->authorization(['client_id' => $id]);
        self::assertSame(302, $response->getStatusCode(), (string) $response->getBody());
        parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $response = $this->exchange(['grant_type' => 'authorization_code', 'client_id' => $id, 'redirect_uri' => 'http://127.0.0.1:5555/callback', 'code' => $query['code'], 'code_verifier' => $this->verifier]);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $tokens = json_decode((string) $response->getBody(), true);
        self::assertSame($id, $this->provider->validator()->validate($this->request($tokens['access_token']))->clientId);
        $response = $this->exchange(['grant_type' => 'refresh_token', 'client_id' => $id, 'refresh_token' => $tokens['refresh_token']]);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $tokens = json_decode((string) $response->getBody(), true);
        $response = $this->provider->revoke((new ServerRequest())->withMethod('POST')->withParsedBody(['client_id' => $id, 'token' => $tokens['access_token']]));
        self::assertSame(200, $response->getStatusCode());
        self::assertNull($this->store->client($id));
        $this->expectException(OAuthServerException::class);
        $this->provider->validator()->validate($this->request($tokens['access_token']));
    }

    public function testCimdCannotRedirectToUnlistedCallback(): void
    {
        $id = 'https://client.example.com/codex/client.json';
        $config = new Config($this->config->issuer, $this->config->resource, self::$privateKey, self::$publicKey, str_repeat('x', 32), cimdEnabled: true);
        $fetcher = new class implements \Light\OAuth2\ClientMetadata\MetadataFetcher {
            public function fetch(string $url): array { return ['client_id' => $url, 'redirect_uris' => ['http://127.0.0.1/callback/expected']]; }
        };
        $this->provider = new OAuthProvider($config, $this->store, $this->permissions, $this->flow, metadataFetcher: $fetcher);
        self::assertSame(401, $this->authorization(['client_id' => $id])->getStatusCode());
    }

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
        $new = json_decode((string) $response->getBody(), true);
        self::assertSame('27', $this->provider->validator()->validate($this->request($new['access_token']))->userId);
        self::assertSame(400, $this->exchange($params)->getStatusCode());
        self::assertSame(400, $this->exchange([...$params, 'refresh_token' => $new['refresh_token']])->getStatusCode());
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
    private function refresh(array $tokens): array
    {
        $response = $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $tokens['refresh_token']]);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        return json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
    }
    public function testReplayRevokesDescendantsButNotIndependentAuthorization(): void
    {
        $a = $this->tokens();
        $b = $this->refresh($a);
        $c = $this->refresh($b);
        $independent = $this->tokens();
        $response = $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $a['refresh_token']]);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_grant', json_decode((string) $response->getBody(), true)['error']);
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        foreach ([$a, $b, $c] as $tokens) {
            try { $this->provider->validator()->validate($this->request($tokens['access_token'])); self::fail('Family access token survived replay'); }
            catch (OAuthServerException) {}
        }
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $c['refresh_token']])->getStatusCode());
        self::assertSame('27', $this->provider->validator()->validate($this->request($independent['access_token']))->userId);
        $this->refresh($independent);
    }
    public function testInvalidOrExpiredRefreshDoesNotRevokeFamily(): void
    {
        $a = $this->tokens();
        $b = $this->refresh($a);
        $other = $this->store->client('codex'); $other['id'] = 'other'; $this->store->saveClient($other);
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'other', 'refresh_token' => $a['refresh_token']])->getStatusCode());
        $payload = json_decode(\Defuse\Crypto\Crypto::decryptWithPassword($a['refresh_token'], $this->config->encryptionKey), true);
        $payload['expire_time'] = time() - 1;
        $expired = \Defuse\Crypto\Crypto::encryptWithPassword(json_encode($payload), $this->config->encryptionKey);
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $expired])->getStatusCode());
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => 'invalid'])->getStatusCode());
        $this->refresh($b);
    }
    public function testReplayDoesNotAffectAnotherUsersFamily(): void
    {
        $a = $this->tokens();
        $b = $this->refresh($a);
        $this->store->insert('access_token', 'foreign-access', ['client_id' => 'codex', 'user_id' => '28', 'scopes' => ['client.list'], 'expires_at' => time() + 300, 'revoked' => false]);
        $this->store->insert('refresh_token', 'foreign-refresh', ['access_token_id' => 'foreign-access', 'family_id' => 'foreign-family', 'used_at' => null, 'expires_at' => time() + 3600, 'revoked' => false]);
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $a['refresh_token']])->getStatusCode());
        self::assertFalse($this->store->record('access_token', 'foreign-access')['revoked']);
        self::assertFalse($this->store->record('refresh_token', 'foreign-refresh')['revoked']);
    }
    public function testWrongConfidentialSecretCannotTriggerReplayRevocation(): void
    {
        $a = $this->tokens(); $b = $this->refresh($a);
        $client = $this->store->client('codex');
        $client['confidential'] = true; $client['secret_hash'] = password_hash('correct-secret', PASSWORD_DEFAULT);
        $this->store->saveClient($client);
        $params = ['grant_type' => 'refresh_token', 'client_id' => 'codex', 'client_secret' => 'wrong', 'refresh_token' => $a['refresh_token']];
        self::assertSame(401, $this->exchange($params)->getStatusCode());
        self::assertSame(200, $this->exchange([...$params, 'client_secret' => 'correct-secret', 'refresh_token' => $b['refresh_token']])->getStatusCode());
    }
    public function testManuallyRevokedUnusedTokenDoesNotTriggerFamilyRevocation(): void
    {
        $a = $this->tokens();
        $payload = json_decode(\Defuse\Crypto\Crypto::decryptWithPassword($a['refresh_token'], $this->config->encryptionKey), true);
        $record = $this->store->record('refresh_token', $payload['refresh_token_id']);
        $this->store->insert('refresh_token', 'family-probe', [...$record, 'access_token_id' => 'probe-access']);
        $this->store->revoke('refresh_token', $payload['refresh_token_id']);
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $a['refresh_token']])->getStatusCode());
        self::assertFalse($this->store->record('refresh_token', 'family-probe')['revoked']);
    }
    public function testFailureAfterConsumptionRollsBackAndResetsRepositoryContext(): void
    {
        $a = $this->tokens(); $before = $this->store->records;
        $inner = $this->store;
        $fault = $this->createStub(\Light\OAuth2\Contract\RefreshTokenStore::class);
        foreach (['client', 'saveClient', 'record', 'revoke', 'consumeRefreshToken', 'revokeRefreshTokenFamily', 'transaction'] as $method) {
            $fault->method($method)->willReturnCallback(fn(...$args) => $inner->$method(...$args));
        }
        $failOnce = true;
        $fault->method('insert')->willReturnCallback(function ($type, $id, $record) use ($inner, &$failOnce) {
            if ($type === 'refresh_token' && $failOnce) { $failOnce = false; throw new \RuntimeException('Simulated persistence failure'); }
            $inner->insert($type, $id, $record);
        });
        $this->provider = new OAuthProvider($this->config, $fault, $this->permissions, $this->flow);
        try { $this->refresh($a); self::fail('Persistence failure not propagated'); }
        catch (\RuntimeException $error) { self::assertSame('Simulated persistence failure', $error->getMessage()); }
        self::assertSame($before, $inner->records);
        $this->refresh($a);
        $this->tokens();
        self::assertCount(2, array_unique(array_column($inner->records['refresh_token'], 'family_id')));
    }
    public function testFailedExchangeDoesNotConsumeRefreshAndLegacyTokenGetsFamily(): void
    {
        $a = $this->tokens();
        foreach ($this->store->records['refresh_token'] as &$record) unset($record['family_id'], $record['used_at']);
        unset($record);
        $this->permissions->allowed = false;
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $a['refresh_token']])->getStatusCode());
        $this->permissions->allowed = true;
        $b = $this->refresh($a);
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $a['refresh_token']])->getStatusCode());
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $b['refresh_token']])->getStatusCode());
    }
    public function testMysqlReplayRevocationCommitsDespiteInvalidGrant(): void
    {
        if (!getenv('OAUTH_TEST_DSN')) self::markTestSkipped('MySQL test connection required');
        $pdo = new \PDO(getenv('OAUTH_TEST_DSN'), getenv('OAUTH_TEST_USER') ?: '', getenv('OAUTH_TEST_PASSWORD') ?: '');
        $sql = preg_replace('/^--.*$/m', '', file_get_contents(dirname(__DIR__) . '/migrations/001_oauth.sql'));
        foreach (explode(';', str_replace('CREATE TABLE IF NOT EXISTS', 'CREATE TEMPORARY TABLE', $sql)) as $statement) {
            if (trim($statement) !== '') $pdo->exec($statement);
        }
        $store = new \Light\OAuth2\Storage\PdoStore($pdo);
        $store->saveClient($this->store->client('codex'));
        $this->provider = new OAuthProvider($this->config, $store, $this->permissions, $this->flow);
        $this->testReplayRevokesDescendantsButNotIndependentAuthorization();
        self::assertFalse($pdo->inTransaction());
        self::assertSame(3, (int) $pdo->query("SELECT COUNT(*) FROM oauth_credentials WHERE type = 'refresh_token' AND JSON_UNQUOTE(JSON_EXTRACT(record, '$.used_at')) REGEXP '^[0-9]+$'")->fetchColumn());
    }
    public function testMysqlConcurrentRefreshRevokesTheWinningDescendant(): void
    {
        if (!getenv('OAUTH_TEST_DSN') || !function_exists('proc_open')) self::markTestSkipped('MySQL and process spawning required');
        $connect = fn() => new \PDO(getenv('OAUTH_TEST_DSN'), getenv('OAUTH_TEST_USER') ?: '', getenv('OAUTH_TEST_PASSWORD') ?: '');
        $pdo = $connect();
        $store = new \Light\OAuth2\Storage\PdoStore($pdo);
        $client = $this->store->client('codex');
        $client['id'] = 'refresh-race-' . bin2hex(random_bytes(12));
        $store->createClient($client);
        $workers = [];
        $blocker = null;
        try {
            $this->provider = new OAuthProvider($this->config, $store, $this->permissions, $this->flow);
            $authorization = $this->authorization(['client_id' => $client['id']]);
            self::assertSame(302, $authorization->getStatusCode());
            parse_str(parse_url($authorization->getHeaderLine('Location'), PHP_URL_QUERY), $query);
            $response = $this->exchange(['grant_type' => 'authorization_code', 'client_id' => $client['id'], 'redirect_uri' => $client['redirect_uris'][0], 'code' => $query['code'], 'code_verifier' => $this->verifier]);
            self::assertSame(200, $response->getStatusCode());
            $tokens = json_decode((string) $response->getBody(), true);
            $input = json_encode(['config' => get_object_vars($this->config), 'params' => ['grant_type' => 'refresh_token', 'client_id' => $client['id'], 'refresh_token' => $tokens['refresh_token']]], JSON_THROW_ON_ERROR);
            // Hold the shared client lock until both workers are ready to exchange.
            $blocker = $connect();
            $blocker->beginTransaction();
            $statement = $blocker->prepare('SELECT id FROM oauth_clients WHERE id = ? FOR UPDATE');
            $statement->execute([$client['id']]);
            for ($i = 0; $i < 2; $i++) {
                $process = proc_open([PHP_BINARY, __DIR__ . '/refresh-worker.php'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
                if (!is_resource($process)) throw new \RuntimeException('Cannot start refresh worker');
                $workers[] = [$process, $pipes];
                stream_set_timeout($pipes[1], 20);
                fwrite($pipes[0], $input); fclose($pipes[0]);
                self::assertSame("ready\n", fgets($pipes[1]));
            }
            $blocker->commit();
            $results = [];
            foreach ($workers as [$process, $pipes]) {
                $results[] = json_decode(stream_get_contents($pipes[1]), true, 512, JSON_THROW_ON_ERROR);
                self::assertSame('', stream_get_contents($pipes[2]));
            }
            $statuses = array_column($results, 'status'); sort($statuses);
            self::assertSame([200, 400], $statuses);
            $winner = array_values(array_filter($results, fn($r) => $r['status'] === 200))[0]['body'];
            $failed = array_values(array_filter($results, fn($r) => $r['status'] === 400))[0]['body'];
            self::assertSame('invalid_grant', $failed['error']);
            self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => $client['id'], 'refresh_token' => $winner['refresh_token']])->getStatusCode());
            try { $this->provider->validator()->validate($this->request($winner['access_token'])); self::fail('Race winner access token survived replay'); }
            catch (OAuthServerException) {}
        } finally {
            if ($blocker?->inTransaction()) $blocker->rollBack();
            foreach ($workers as [$process, $pipes]) {
                if (proc_get_status($process)['running']) proc_terminate($process);
                foreach ($pipes as $pipe) if (is_resource($pipe)) fclose($pipe);
                proc_close($process);
            }
            // Remove only credentials belonging to the unique test client.
            $statement = $pdo->prepare("SELECT id FROM oauth_credentials WHERE type = 'access_token' AND JSON_UNQUOTE(JSON_EXTRACT(record, '$.client_id')) = ?");
            $statement->execute([$client['id']]);
            $refresh = $pdo->prepare("DELETE FROM oauth_credentials WHERE type = 'refresh_token' AND JSON_UNQUOTE(JSON_EXTRACT(record, '$.access_token_id')) = ?");
            foreach ($statement->fetchAll(\PDO::FETCH_COLUMN) as $accessId) $refresh->execute([$accessId]);
            $statement = $pdo->prepare("DELETE FROM oauth_credentials WHERE JSON_UNQUOTE(JSON_EXTRACT(record, '$.client_id')) = ?");
            $statement->execute([$client['id']]);
            $statement = $pdo->prepare('DELETE FROM oauth_clients WHERE id = ?'); $statement->execute([$client['id']]);
        }
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

    public function testDeletingClientPermanentlyInvalidatesItsTokens(): void
    {
        $tokens = $this->tokens();
        $client = $this->store->client('codex');
        self::assertTrue($this->store->deleteClient('codex'));
        foreach ($this->store->records as $records) {
            foreach ($records as $record) self::assertTrue($record['revoked']);
        }
        // Reusing the ID cannot bring a deleted client's old credentials back.
        $this->store->createClient($client);
        self::assertSame(400, $this->exchange(['grant_type' => 'refresh_token', 'client_id' => 'codex', 'refresh_token' => $tokens['refresh_token']])->getStatusCode());
        $this->expectException(OAuthServerException::class);
        $this->provider->validator()->validate($this->request($tokens['access_token']));
    }

    public function testProviderRegistersRoutesAndAuthenticatesThroughLightFactory(): void
    {
        if (!method_exists(\Light\App::class, 'setAuthServiceFactory')) self::markTestSkipped('Set LIGHT_SOURCE_PATH to patched Light checkout');
        if (!interface_exists(\Light\GraphQL\ExplicitController::class)) self::markTestSkipped('Set LIGHT_SOURCE_PATH to Light with explicit controller registration');
        $app = (new \ReflectionClass(\Light\App::class))->newInstanceWithoutConstructor();
        $router = new \League\Route\Router();
        $server = $this->createStub(\Light\Server::class);
        $server->method('getRouter')->willReturn($router);
        (new \ReflectionProperty(\Light\App::class, 'server'))->setValue($app, $server);
        (new \ReflectionProperty(\Light\App::class, 'cache'))->setValue($app, new \Symfony\Component\Cache\Psr16Cache(new \Symfony\Component\Cache\Adapter\ArrayAdapter()));
        $container = new \League\Container\Container();
        (new \ReflectionProperty(\Light\App::class, 'container'))->setValue($app, $container);
        $factory = new \TheCodingMachine\GraphQLite\SchemaFactory($app->getCache(), $container);
        $factory->setFinder(\Light\GraphQL\ControllerDiscovery::finder($container));
        (new \ReflectionProperty(\Light\App::class, 'factory'))->setValue($app, $factory);
        $user = (new \ReflectionClass(\Light\Model\User::class))->newInstanceWithoutConstructor();
        $this->provider->register($app, fn() => $user);
        self::assertTrue($container->has(\Light\OAuth2\Controller\OAuthClientController::class));
        if (method_exists($app, 'addPermissions')) {
            self::assertSame(['oauth_client.list', 'oauth_client.add', 'oauth_client.update', 'oauth_client.delete'], (new \ReflectionProperty(\Light\App::class, 'extensionPermissions'))->getValue($app));
        }
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
