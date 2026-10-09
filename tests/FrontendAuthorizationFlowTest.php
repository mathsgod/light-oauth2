<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;

use Laminas\Diactoros\{ServerRequest, Uri};
use Light\{App};
use Light\Auth\Service;
use Light\Model\User;
use Light\OAuth2\{BrowserAuthorizationFlow, Config, FrontendAuthorizationFlow, OAuthProvider};
use Light\OAuth2\Contract\PermissionProvider;
use PHPUnit\Framework\Attributes\{PreserveGlobalState, RunInSeparateProcess};

final class FrontendAuthorizationFlowTest extends ApplicationTestCase
{
    #[RunInSeparateProcess, PreserveGlobalState(false)]
    public function testFrontendLoginConsentSubsetCodeExchangeAndReplayProtection(): void
    {
        $app = new App();
        $user = User::Create(['user_id' => 123, 'username' => 'frontend-user', 'status' => 0]);
        $auth = $this->createStub(Service::class);
        $auth->method('getUser')->willReturn($user);
        $auth->method('isViewAsMode')->willReturn(false);
        $auth->method('getSessionId')->willReturn('native-session');
        (new \ReflectionProperty(App::class, 'auth_service'))->setValue($app, $auth);
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $privateKey);
        $config = new Config('https://api.example.com', 'https://mcp.example.com/mcp', $privateKey, openssl_pkey_get_details($key)['key'], str_repeat('k', 32), autoSelectScopes: true, authorizationUiUrl: 'https://app.example.com/oauth/authorize');
        $store = new MemoryStore();
        $store->saveClient(['id' => 'test', 'name' => 'Frontend client', 'redirect_uris' => ['http://127.0.0.1:5556/callback'], 'scopes' => ['client.list', 'quotation.list'], 'confidential' => false, 'enabled' => true]);
        $permissions = new class implements PermissionProvider {
            public function scopes(): array { return ['client.list', 'quotation.list']; }
            public function can(string $userId, string $permission): bool { return $userId === '123' && in_array($permission, $this->scopes(), true); }
        };
        $flow = new FrontendAuthorizationFlow(new BrowserAuthorizationFlow($app), $config);
        $provider = new OAuthProvider($config, $store, $permissions, $flow);
        $verifier = str_repeat('v', 64);
        $params = ['response_type' => 'code', 'client_id' => 'test', 'redirect_uri' => 'http://127.0.0.1:5556/callback', 'state' => 'client-state', 'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='), 'code_challenge_method' => 'S256'];
        $start = (new ServerRequest())->withUri(new Uri('https://api.example.com/oauth/authorize'))->withQueryParams($params);
        $response = $provider->authorize($start);
        self::assertSame(303, $response->getStatusCode());
        self::assertStringStartsWith($config->authorizationUiUrl . '?request_id=', $response->getHeaderLine('Location'));
        self::assertStringNotContainsString('client-state', $response->getHeaderLine('Location'));
        parse_str(parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $request = (new ServerRequest())->withUri(new Uri('https://api.example.com/oauth/interaction'))->withQueryParams($query)->withHeader('Origin', 'https://app.example.com');
        $call = fn($req) => $flow->interaction($req, [$provider, 'authorize']);
        $login = $call($request);
        self::assertSame('https://app.example.com', $login->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('true', $login->getHeaderLine('Access-Control-Allow-Credentials'));
        self::assertSame('no-store', $login->getHeaderLine('Cache-Control'));
        $data = json_decode((string) $login->getBody(), true);
        self::assertSame('login', $data['stage']);
        self::assertSame('Frontend client', $data['client_name']);
        // The native login endpoint normally establishes this after password + 2FA.
        session_start();
        $pending = array_key_first($_SESSION['oauth_pending']);
        $_SESSION['oauth_pending'][$pending]['user_id'] = '123';
        session_write_close();
        $consent = json_decode((string) $call($request)->getBody(), true);
        self::assertSame('consent', $consent['stage']);
        self::assertSame(['client.list', 'quotation.list'], $consent['scopes']);
        $post = $request->withMethod('POST')->withParsedBody(['csrf' => $consent['csrf'], 'action' => 'approve', 'scopes' => ['quotation.list']]);
        self::assertSame(403, $call($post->withHeader('Origin', 'https://evil.example.com'))->getStatusCode());
        self::assertSame(403, $call($post->withoutHeader('Origin'))->getStatusCode());
        self::assertSame(403, $call($post->withParsedBody(['csrf' => 'wrong', 'action' => 'approve', 'scopes' => ['quotation.list']]))->getStatusCode());
        self::assertSame(400, $call($post->withParsedBody(['csrf' => $consent['csrf'], 'action' => 'approve', 'scopes' => ['unknown']]))->getStatusCode());
        $result = json_decode((string) $call($post->withQueryParams($query + ['client_id' => 'forged', 'scope' => 'unknown']))->getBody(), true);
        parse_str(parse_url($result['redirect_uri'], PHP_URL_QUERY), $callback);
        self::assertSame('client-state', $callback['state']);
        $tokens = $provider->token((new ServerRequest())->withMethod('POST')->withParsedBody(['grant_type' => 'authorization_code', 'client_id' => 'test', 'redirect_uri' => $params['redirect_uri'], 'code' => $callback['code'], 'code_verifier' => $verifier]));
        self::assertSame(200, $tokens->getStatusCode(), (string) $tokens->getBody());
        $token = json_decode((string) $tokens->getBody(), true)['access_token'];
        self::assertSame(['quotation.list'], $provider->validator()->validate((new ServerRequest())->withHeader('Authorization', 'Bearer ' . $token))->scopes);
        self::assertSame(403, $call($post)->getStatusCode());
        self::assertSame(403, $call($request->withQueryParams(['request_id' => str_repeat('0', 64)]))->getStatusCode());
        session_start(); session_destroy();
    }
}
