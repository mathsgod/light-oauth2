<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Light\OAuth2\{Config, OAuthProvider, TokenExchangePolicy};
use Light\OAuth2\Auth\TokenValidator;
use Light\OAuth2\Contract\{PermissionProvider, AuthorizationFlow, AuthorizationDecision};
use Light\OAuth2\Grant\TokenExchangeGrant;
use Light\OAuth2\Repository\AccessTokenRepository;
use Light\OAuth2\Entity\{Client, Scope};
use League\OAuth2\Server\{CryptKey, Exception\OAuthServerException, RequestTypes\AuthorizationRequest};
use Laminas\Diactoros\ServerRequest;
use Psr\Http\Message\{ServerRequestInterface, ResponseInterface};

final class TokenExchangeTest extends TestCase
{
    private static string $privateKey = '';
    private static string $publicKey;
    private const MCP = 'https://mcp.example.com';
    private const API = 'https://api.example.com/graphql';
    private MemoryStore $store;
    private Config $config;
    private PermissionProvider $permissions;
    private AuthorizationFlow $flow;
    private OAuthProvider $provider;
    private string $subject;
    private string $subjectId;

    public static function setUpBeforeClass(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, self::$privateKey);
        self::$publicKey = openssl_pkey_get_details($key)['key'];
    }

    protected function setUp(): void
    {
        $this->store = new MemoryStore();
        foreach (['codex' => false, 'mcp' => true, 'other' => true] as $id => $confidential) {
            $this->store->saveClient(['id' => $id, 'name' => $id, 'redirect_uris' => ['http://127.0.0.1/callback'], 'confidential' => $confidential, 'secret_hash' => $confidential ? password_hash('secret', PASSWORD_DEFAULT) : null, 'enabled' => true, 'scopes' => ['client.list', 'client.edit']]);
        }
        $this->config = new Config('https://auth.example.com', self::MCP, self::$privateKey, self::$publicKey, str_repeat('x', 32));
        $this->permissions = new class implements PermissionProvider {
            public bool $allowed = true;
            public function scopes(): array { return ['client.list', 'client.edit']; }
            public function can(string $userId, string $permission): bool { return $this->allowed && $userId === '27'; }
        };
        $this->flow = new class implements AuthorizationFlow {
            public function resolve(ServerRequestInterface $request, AuthorizationRequest $authorization): AuthorizationDecision|ResponseInterface { return new AuthorizationDecision('27', true, true); }
        };
        $this->provider = new OAuthProvider($this->config, $this->store, $this->permissions, $this->flow, $this->policy());
        $this->subject = $this->mint($this->config);
        $this->subjectId = $this->provider->validator()->validate($this->bearer($this->subject))->tokenId;
    }

    private function policy(): TokenExchangePolicy
    {
        return new TokenExchangePolicy(['mcp' => ['source' => self::MCP, 'targets' => [self::API => ['client.list']]]]);
    }

    /** Mint a real signed, persisted source token without browser interaction. */
    private function mint(Config $config, ?\DateTimeImmutable $expiry = null): string
    {
        $repo = new AccessTokenRepository($this->store, $config);
        $token = $repo->getNewToken(new Client($this->store->client('codex')), [new Scope('client.list')], '27');
        $token->setIdentifier(bin2hex(random_bytes(20)));
        $token->setExpiryDateTime($expiry ?? new \DateTimeImmutable('+1 hour'));
        $token->setPrivateKey(new CryptKey($config->privateKey));
        $repo->persistNewAccessToken($token);
        return $token->toString();
    }

    private function bearer(string $token): ServerRequestInterface { return (new ServerRequest())->withHeader('Authorization', 'Bearer ' . $token); }
    private function params(array $changes = []): array
    {
        return array_replace(['grant_type' => TokenExchangeGrant::IDENTIFIER, 'client_id' => 'mcp', 'client_secret' => 'secret', 'subject_token' => $this->subject, 'subject_token_type' => TokenExchangeGrant::ACCESS_TOKEN_TYPE, 'resource' => self::API, 'scope' => 'client.list'], $changes);
    }
    private function exchange(array $changes = []): ResponseInterface
    {
        return $this->provider->token((new ServerRequest())->withMethod('POST')->withParsedBody($this->params($changes)));
    }
    private function body(ResponseInterface $response): array { return json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR); }
    private function assertRejected(ResponseInterface $response, string $error): void
    {
        self::assertGreaterThanOrEqual(400, $response->getStatusCode());
        self::assertSame($error, $this->body($response)['error']);
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public function testExchangePreservesUserAndBindsTokenToApi(): void
    {
        $response = $this->exchange();
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $data = $this->body($response);
        self::assertSame(TokenExchangeGrant::ACCESS_TOKEN_TYPE, $data['issued_token_type']);
        self::assertSame('Bearer', $data['token_type']);
        self::assertSame('client.list', $data['scope']);
        self::assertGreaterThan(0, $data['expires_in']);
        self::assertLessThanOrEqual(300, $data['expires_in']);
        self::assertArrayNotHasKey('refresh_token', $data);
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $api = new TokenValidator($this->config->forResource(self::API), $this->store);
        $context = $api->validate($this->bearer($data['access_token']));
        self::assertSame('27', $context->userId);
        self::assertSame('mcp', $context->clientId);
        self::assertSame(['client.list'], $context->scopes);
        self::assertTrue($context->can('client.list', $this->permissions));
        self::assertFalse($context->can('client.edit', $this->permissions));
        self::assertFalse($this->store->record('access_token', $this->subjectId)['revoked']);
        $this->expectException(OAuthServerException::class);
        $this->provider->validator()->validate($this->bearer($data['access_token']));
    }

    public function testApiRejectsOriginalMcpToken(): void
    {
        $this->expectException(OAuthServerException::class);
        (new TokenValidator($this->config->forResource(self::API), $this->store))->validate($this->bearer($this->subject));
    }

    public function testBasicAuthenticationAndDefaultTargetAndScopes(): void
    {
        $params = $this->params();
        unset($params['client_id'], $params['client_secret'], $params['resource'], $params['scope']);
        $request = (new ServerRequest())->withParsedBody($params)->withHeader('Authorization', 'Basic ' . base64_encode('mcp:secret'));
        $response = $this->provider->token($request);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('client.list', $this->body($response)['scope']);
    }

    public function testAudienceCanSelectTarget(): void
    {
        $params = $this->params(['audience' => self::API]);
        unset($params['resource']);
        $response = $this->provider->token((new ServerRequest())->withParsedBody($params));
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
    }

    public static function invalidRequests(): iterable
    {
        yield 'wrong secret' => [['client_secret' => 'wrong'], 'invalid_client'];
        yield 'unknown client' => [['client_id' => 'missing'], 'invalid_client'];
        yield 'public client' => [['client_id' => 'codex'], 'invalid_client'];
        yield 'untrusted confidential client' => [['client_id' => 'other'], 'unauthorized_client'];
        yield 'target not allowed' => [['resource' => 'https://evil.example.com'], 'invalid_target'];
        yield 'conflicting audience' => [['audience' => self::MCP], 'invalid_target'];
        yield 'malformed subject' => [['subject_token' => 'not-a-jwt'], 'invalid_request'];
        yield 'header injection in subject' => [['subject_token' => "bad\r\nInjected: value"], 'invalid_request'];
        yield 'empty subject' => [['subject_token' => ''], 'invalid_request'];
        yield 'missing subject type' => [['subject_token_type' => null], 'invalid_request'];
        yield 'unsupported subject type' => [['subject_token_type' => 'urn:ietf:params:oauth:token-type:refresh_token'], 'invalid_request'];
        yield 'unsupported requested type' => [['requested_token_type' => 'urn:ietf:params:oauth:token-type:id_token'], 'invalid_request'];
        yield 'actor unsupported' => [['actor_token' => 'actor', 'actor_token_type' => TokenExchangeGrant::ACCESS_TOKEN_TYPE], 'invalid_request'];
        yield 'actor type alone' => [['actor_token_type' => TokenExchangeGrant::ACCESS_TOKEN_TYPE], 'invalid_request'];
        yield 'scope escalation' => [['scope' => 'client.edit'], 'invalid_scope'];
        yield 'unknown scope' => [['scope' => 'admin'], 'invalid_scope'];
        yield 'whitespace scope' => [['scope' => '   '], 'invalid_scope'];
        yield 'array resource' => [['resource' => [self::API]], 'invalid_request'];
        yield 'array scope' => [['scope' => ['client.list']], 'invalid_request'];
    }

    #[DataProvider('invalidRequests')]
    public function testInvalidRequestsAreRejected(array $changes, string $error): void { $this->assertRejected($this->exchange($changes), $error); }

    public function testMissingRequiredSubjectParameters(): void
    {
        foreach (['subject_token', 'subject_token_type'] as $name) {
            $params = $this->params();
            unset($params[$name]);
            $this->assertRejected($this->provider->token((new ServerRequest())->withParsedBody($params)), 'invalid_request');
        }
    }

    public function testRepeatedWireParametersAreRejected(): void
    {
        foreach (['resource' => 'invalid_target', 'audience' => 'invalid_target', 'subject_token' => 'invalid_request'] as $name => $error) {
            $params = $this->params(['audience' => self::API]);
            $request = (new ServerRequest())->withParsedBody($params)->withBody(new \Laminas\Diactoros\Stream('php://temp', 'w+b'));
            $request->getBody()->write(http_build_query($params) . '&' . urlencode($name) . '=' . urlencode($params[$name]));
            $this->assertRejected($this->provider->token($request), $error);
        }
    }

    public function testRevokedAndExpiredSubjectTokensAreRejected(): void
    {
        $this->store->revoke('access_token', $this->subjectId);
        $this->assertRejected($this->exchange(), 'invalid_request');
        $this->subject = $this->mint($this->config, new \DateTimeImmutable('-1 minute'));
        $this->assertRejected($this->exchange(), 'invalid_request');
    }

    public function testWrongIssuerAudienceAndSignatureAreRejected(): void
    {
        $this->subject = $this->mint($this->config->forResource(self::API));
        $this->assertRejected($this->exchange(), 'invalid_request');
        $other = new Config('https://other.example.com', self::MCP, self::$privateKey, self::$publicKey, str_repeat('x', 32));
        $this->subject = $this->mint($other);
        $this->assertRejected($this->exchange(), 'invalid_request');
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $private);
        $this->subject = $this->mint(new Config($this->config->issuer, self::MCP, $private, openssl_pkey_get_details($key)['key'], str_repeat('x', 32)));
        $this->assertRejected($this->exchange(), 'invalid_request');
    }

    public function testCurrentUserAndBothClientsPermissionsAreRequired(): void
    {
        $this->permissions->allowed = false;
        $this->assertRejected($this->exchange(), 'invalid_scope');
        $this->permissions->allowed = true;
        foreach (['mcp', 'codex'] as $id) {
            $client = $this->store->client($id);
            $original = $client;
            $client['scopes'] = [];
            $this->store->saveClient($client);
            $this->assertRejected($this->exchange(), 'invalid_scope');
            $this->store->saveClient($original);
        }
    }

    public function testDisabledSourceAndCallerAreRejected(): void
    {
        foreach (['codex' => 'invalid_request', 'mcp' => 'invalid_client'] as $id => $error) {
            $client = $this->store->client($id);
            $client['enabled'] = false;
            $this->store->saveClient($client);
            $this->assertRejected($this->exchange(), $error);
            $client['enabled'] = true;
            $this->store->saveClient($client);
        }
    }

    public function testExpiryIsCappedAtSubjectJwtExpiry(): void
    {
        $this->subject = $this->mint($this->config, new \DateTimeImmutable('+60 seconds'));
        $response = $this->exchange();
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertLessThanOrEqual(60, $this->body($response)['expires_in']);
    }

    public function testSourceRevocationInvalidatesExchangedToken(): void
    {
        $data = $this->body($this->exchange());
        $this->store->revoke('access_token', $this->subjectId);
        $this->expectException(OAuthServerException::class);
        (new TokenValidator($this->config->forResource(self::API), $this->store))->validate($this->bearer($data['access_token']));
    }

    public function testExchangingClientCanRevokeApiTokenWithoutRevokingSource(): void
    {
        $data = $this->body($this->exchange());
        $api = new TokenValidator($this->config->forResource(self::API), $this->store);
        $context = $api->validate($this->bearer($data['access_token']));
        $params = ['client_id' => 'other', 'client_secret' => 'secret', 'token' => $data['access_token']];
        self::assertSame(200, $this->provider->revoke((new ServerRequest())->withParsedBody($params))->getStatusCode());
        self::assertFalse($this->store->record('access_token', $context->tokenId)['revoked']);
        $params['client_id'] = 'mcp';
        self::assertSame(200, $this->provider->revoke((new ServerRequest())->withParsedBody($params))->getStatusCode());
        self::assertTrue($this->store->record('access_token', $context->tokenId)['revoked']);
        self::assertFalse($this->store->record('access_token', $this->subjectId)['revoked']);
        $this->expectException(OAuthServerException::class);
        $api->validate($this->bearer($data['access_token']));
    }

    public function testDisabledSourceClientInvalidatesExistingApiToken(): void
    {
        $data = $this->body($this->exchange());
        $client = $this->store->client('codex');
        $client['enabled'] = false;
        $this->store->saveClient($client);
        $this->expectException(OAuthServerException::class);
        (new TokenValidator($this->config->forResource(self::API), $this->store))->validate($this->bearer($data['access_token']));
    }

    public function testUnknownSignedSubjectAndChainingAreRejected(): void
    {
        $record = $this->store->records['access_token'][$this->subjectId];
        unset($this->store->records['access_token'][$this->subjectId]);
        $this->assertRejected($this->exchange(), 'invalid_request');
        $record['exchange_subject'] = $this->provider->validator()->validate($this->bearer($this->mint($this->config)))->tokenId;
        $this->store->records['access_token'][$this->subjectId] = $record;
        $this->assertRejected($this->exchange(), 'invalid_request');
    }

    public function testSourceClientScopeRemovalAffectsExistingExchangedToken(): void
    {
        $data = $this->body($this->exchange());
        $client = $this->store->client('codex');
        $client['scopes'] = [];
        $this->store->saveClient($client);
        $context = (new TokenValidator($this->config->forResource(self::API), $this->store))->validate($this->bearer($data['access_token']));
        self::assertFalse($context->can('client.list', $this->permissions));
    }

    public function testDefaultProviderDoesNotEnableOrAdvertiseExchange(): void
    {
        $provider = new OAuthProvider($this->config, $this->store, $this->permissions, $this->flow);
        self::assertNotContains(TokenExchangeGrant::IDENTIFIER, $this->body($provider->metadata(new ServerRequest()))['grant_types_supported']);
        $params = $this->params();
        unset($params['resource']);
        $this->assertRejected($provider->token((new ServerRequest())->withParsedBody($params)), 'unsupported_grant_type');
        self::assertContains(TokenExchangeGrant::IDENTIFIER, $this->body($this->provider->metadata(new ServerRequest()))['grant_types_supported']);
    }

    public function testNoDefaultWhenMultipleTargetsAreConfigured(): void
    {
        $policy = new TokenExchangePolicy(['mcp' => ['source' => self::MCP, 'targets' => [self::API => ['client.list'], 'https://other.example.com' => ['client.list']]]]);
        $provider = new OAuthProvider($this->config, $this->store, $this->permissions, $this->flow, $policy);
        $params = $this->params();
        unset($params['resource']);
        $this->assertRejected($provider->token((new ServerRequest())->withParsedBody($params)), 'invalid_target');
    }

    public function testMultipleExchangesDoNotConsumeSourceOrLeakTargetState(): void
    {
        $secondTarget = 'https://other.example.com/graphql';
        $policy = new TokenExchangePolicy(['mcp' => ['source' => self::MCP, 'targets' => [self::API => ['client.list'], $secondTarget => ['client.list']]]]);
        $provider = new OAuthProvider($this->config, $this->store, $this->permissions, $this->flow, $policy);
        foreach ([self::API, $secondTarget, self::API] as $target) {
            $response = $provider->token((new ServerRequest())->withParsedBody($this->params(['resource' => $target])));
            self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
            $context = (new TokenValidator($this->config->forResource($target), $this->store))->validate($this->bearer($this->body($response)['access_token']));
            self::assertSame($target, $this->store->record('access_token', $context->tokenId)['resource']);
        }
        self::assertFalse($this->store->record('access_token', $this->subjectId)['revoked']);
    }

    public function testInvalidExchangeDoesNotPersistAnyCredential(): void
    {
        $before = $this->store->records;
        $this->assertRejected($this->exchange(['scope' => 'client.edit']), 'invalid_scope');
        self::assertSame($before, $this->store->records);
    }

    public function testPolicyCannotExchangeTokensFromAnotherSourceResource(): void
    {
        $policy = new TokenExchangePolicy(['mcp' => ['source' => 'https://another-mcp.example.com', 'targets' => [self::API => ['client.list']]]]);
        $provider = new OAuthProvider($this->config, $this->store, $this->permissions, $this->flow, $policy);
        $this->assertRejected($provider->token((new ServerRequest())->withParsedBody($this->params())), 'unauthorized_client');
    }

    public static function invalidPolicies(): iterable
    {
        yield 'source target identical' => [['mcp' => ['source' => self::MCP, 'targets' => [self::MCP => ['client.list']]]]];
        yield 'fragment target' => [['mcp' => ['source' => self::MCP, 'targets' => [self::API . '#fragment' => ['client.list']]]]];
        yield 'non-loopback HTTP target' => [['mcp' => ['source' => self::MCP, 'targets' => ['http://api.example.com' => ['client.list']]]]];
        yield 'missing source' => [['mcp' => ['targets' => [self::API => ['client.list']]]]];
        yield 'no targets' => [['mcp' => ['source' => self::MCP, 'targets' => []]]];
        yield 'no scopes' => [['mcp' => ['source' => self::MCP, 'targets' => [self::API => []]]]];
        yield 'scope with whitespace' => [['mcp' => ['source' => self::MCP, 'targets' => [self::API => ['client list']]]]];
    }

    #[DataProvider('invalidPolicies')]
    public function testInvalidPolicyIsRejectedAtConfigurationTime(array $rules): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TokenExchangePolicy($rules);
    }
}
