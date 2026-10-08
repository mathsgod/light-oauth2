<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;

use PHPUnit\Framework\TestCase;
use Laminas\Diactoros\{ServerRequest, Stream};
use Light\OAuth2\{DynamicClientRegistrationEndpoint, Config, OAuthProvider};
use Light\OAuth2\Contract\{PermissionProvider, AuthorizationFlow, AuthorizationDecision};
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Light\OAuth2\Repository\ClientRepository;
use Psr\Http\Message\{ServerRequestInterface, ResponseInterface};

final class DynamicClientRegistrationTest extends TestCase
{
    private MemoryStore $store;
    private PermissionProvider $permissions;
    private DynamicClientRegistrationEndpoint $endpoint;
    protected function setUp(): void
    {
        $this->store = new MemoryStore();
        $this->permissions = new class implements PermissionProvider {
            public function scopes(): array { return ['client.list', 'invoice.list']; }
            public function can(string $userId, string $permission): bool { return $userId === '27' && $permission === 'client.list'; }
        };
        $this->endpoint = new DynamicClientRegistrationEndpoint($this->store, $this->permissions);
    }
    private function request(string $json, string $type = 'application/json'): ServerRequestInterface
    {
        $body = new Stream('php://temp', 'r+'); $body->write($json); $body->rewind();
        return (new ServerRequest())->withMethod('POST')->withHeader('Content-Type', $type)->withBody($body);
    }
    private function input(array $changes = []): array
    {
        return array_replace(['client_name' => 'Codex', 'redirect_uris' => ['http://127.0.0.1/callback/id'], 'token_endpoint_auth_method' => 'none', 'grant_types' => ['authorization_code', 'refresh_token'], 'response_types' => ['code'], 'scope' => 'client.list'], $changes);
    }
    private function register(array $changes = []): ResponseInterface
    {
        return $this->endpoint->handle($this->request(json_encode($this->input($changes), JSON_THROW_ON_ERROR)));
    }
    private function body(ResponseInterface $response): array { return json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR); }

    public function testRegistrationCreatesUniquePublicClientAndCannotChooseIdOrPrivilege(): void
    {
        $response = $this->register(['client_id' => 'administrator', 'confidential' => true, 'enabled' => false, 'secret_hash' => 'chosen']);
        self::assertSame(201, $response->getStatusCode());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame('no-cache', $response->getHeaderLine('Pragma'));
        $result = $this->body($response);
        self::assertStringStartsWith('dcr_', $result['client_id']);
        self::assertSame('none', $result['token_endpoint_auth_method']);
        self::assertSame('client.list', $result['scope']);
        self::assertIsInt($result['client_id_issued_at']);
        self::assertArrayNotHasKey('client_secret', $result);
        $record = $this->store->client($result['client_id']);
        self::assertFalse($record['confidential']); self::assertTrue($record['enabled']);
        self::assertArrayNotHasKey('secret_hash', $record);
        self::assertNull($this->store->client('administrator'));
        self::assertNotSame($result['client_id'], $this->body($this->register())['client_id']);
        self::assertTrue((new ClientRepository($this->store))->validateClient($result['client_id'], null, 'authorization_code'));
    }
    public function testDefaultsAndRefreshGrantRestriction(): void
    {
        $input = ['redirect_uris' => ['https://app.example/callback'], 'token_endpoint_auth_method' => 'none'];
        $response = $this->endpoint->handle($this->request(json_encode($input)));
        self::assertSame(201, $response->getStatusCode());
        $body = $this->body($response);
        self::assertSame(['authorization_code'], $body['grant_types']);
        self::assertSame('client.list invoice.list', $body['scope']);
        self::assertFalse((new ClientRepository($this->store))->validateClient($body['client_id'], null, 'refresh_token'));
        unset($input['token_endpoint_auth_method']);
        self::assertSame(400, $this->endpoint->handle($this->request(json_encode($input)))->getStatusCode());
    }
    public function testMalformedAndOversizedBodiesNeverWriteClients(): void
    {
        foreach (['{', '[]', 'null', '"string"', '{"nested":' . str_repeat('[', 20) . '0' . str_repeat(']', 20) . '}'] as $json) {
            self::assertSame(400, $this->endpoint->handle($this->request($json))->getStatusCode());
        }
        self::assertSame(413, $this->endpoint->handle($this->request(str_repeat(' ', 16385)))->getStatusCode());
        self::assertSame(415, $this->endpoint->handle($this->request('{}', 'application/x-www-form-urlencoded'))->getStatusCode());
        $method = $this->endpoint->handle($this->request('{}')->withMethod('GET'));
        self::assertSame(405, $method->getStatusCode());
        self::assertSame('POST', $method->getHeaderLine('Allow'));
        self::assertSame([], $this->store->clients);
    }
    public function testUnsafeRedirectsAndUnsupportedMetadataFailWithoutWriting(): void
    {
        foreach ([[], ['http://app.example/cb'], ['http://localhost/callback'], ['https://app.example/cb#fragment'], ['https://u:p@app.example/cb'], ['https://*.example/cb'], ['https://app.example/\\cb'], ['javascript:alert(1)'], [12], ['https://app.example/cb newline'], array_fill(0, 21, 'https://app.example/cb')] as $redirects) {
            $response = $this->register(['redirect_uris' => $redirects]);
            self::assertSame(400, $response->getStatusCode(), json_encode($redirects));
            self::assertSame('invalid_redirect_uri', $this->body($response)['error']);
        }
        foreach ([['token_endpoint_auth_method' => 'client_secret_basic'], ['grant_types' => ['client_credentials']], ['grant_types' => ['refresh_token']], ['grant_types' => [[]]], ['grant_types' => null], ['response_types' => ['token']], ['client_name' => null], ['scope' => 'administrator'], ['scope' => ['client.list']], ['scope' => 'client.list  invoice.list']] as $changes) {
            self::assertSame('invalid_client_metadata', $this->body($this->register($changes))['error']);
        }
        self::assertSame('unapproved_software_statement', $this->body($this->register(['software_statement' => 'jwt']))['error']);
        self::assertSame([], $this->store->clients);
    }
    public function testRegistrationDiscoveryAndCompletePkceFlow(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048]); openssl_pkey_export($key, $private);
        $public = openssl_pkey_get_details($key)['key'];
        $config = new Config('https://auth.example/tenant', 'https://mcp.example/mcp', $private, $public, str_repeat('x', 32), dcrEnabled: true);
        $flow = new class implements AuthorizationFlow {
            public function resolve(ServerRequestInterface $request, AuthorizationRequest $authorization): AuthorizationDecision|ResponseInterface { return new AuthorizationDecision('27', true, true); }
        };
        $provider = new OAuthProvider($config, $this->store, $this->permissions, $flow);
        $metadata = $this->body($provider->metadata(new ServerRequest()));
        self::assertSame('https://auth.example/tenant/oauth/register', $metadata['registration_endpoint']);
        self::assertTrue($config->forResource('https://api.example')->dcrEnabled);
        $registered = $provider->registerClient($this->request(json_encode($this->input())));
        self::assertSame(201, $registered->getStatusCode());
        $id = $this->body($registered)['client_id'];
        $verifier = str_repeat('a', 64);
        $params = ['response_type' => 'code', 'client_id' => $id, 'redirect_uri' => 'http://127.0.0.1:52109/callback/id', 'scope' => 'client.list', 'state' => 'test', 'code_challenge_method' => 'S256', 'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=')];
        $response = $provider->authorize((new ServerRequest())->withQueryParams($params));
        self::assertSame(302, $response->getStatusCode(), (string) $response->getBody());
        parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $callback);
        $response = $provider->token((new ServerRequest())->withMethod('POST')->withParsedBody(['grant_type' => 'authorization_code', 'client_id' => $id, 'redirect_uri' => $params['redirect_uri'], 'code' => $callback['code'], 'code_verifier' => $verifier]));
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $token = $this->body($response);
        self::assertSame($id, $provider->validator()->validate((new ServerRequest())->withHeader('Authorization', 'Bearer ' . $token['access_token']))->clientId);
        $refresh = $provider->token((new ServerRequest())->withMethod('POST')->withParsedBody(['grant_type' => 'refresh_token', 'client_id' => $id, 'refresh_token' => $token['refresh_token']]));
        self::assertSame(200, $refresh->getStatusCode());
        $disabled = new OAuthProvider(new Config($config->issuer, $config->resource, $private, $public, str_repeat('x', 32)), $this->store, $this->permissions, $flow);
        self::assertArrayNotHasKey('registration_endpoint', $this->body($disabled->metadata(new ServerRequest())));
        self::assertSame(404, $disabled->registerClient($this->request(json_encode($this->input())))->getStatusCode());
    }
}
