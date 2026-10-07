<?php
declare(strict_types=1);

namespace Light\OAuth2\Tests;

use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Light\App;
use Light\Auth\Service;
use Light\Model\User;
use Light\OAuth2\BrowserAuthorizationFlow;
use Light\OAuth2\Contract\AuthorizationDecision;
use Light\OAuth2\Entity\{Client, Scope};
use PHPUnit\Framework\Attributes\{PreserveGlobalState, RunInSeparateProcess};

final class BrowserAuthorizationFlowTest extends ApplicationTestCase
{
    #[RunInSeparateProcess, PreserveGlobalState(false)]
    public function testConsentRequiresTheOriginalCsrfRequestAndSession(): void
    {
        $app = new App();
        $user = User::Create(['user_id' => 123, 'username' => 'oauth-test', 'status' => 0]);
        $sessionId = 'browser-session';
        $auth = $this->createStub(Service::class);
        $auth->method('getUser')->willReturn($user);
        $auth->method('isViewAsMode')->willReturn(false);
        $auth->method('getSessionId')->willReturnCallback(static function () use (&$sessionId): string { return $sessionId; });
        (new \ReflectionProperty(App::class, 'auth_service'))->setValue($app, $auth);
        $flow = new BrowserAuthorizationFlow($app);
        $authorization = new AuthorizationRequest();
        $authorization->setClient(new Client(['id' => 'test', 'name' => 'Test client', 'redirect_uris' => ['https://example.com/callback'], 'confidential' => false, 'enabled' => true, 'scopes' => ['user.list']]));
        $authorization->setScopes([new Scope('user.list')]);
        $authorization->setRedirectUri('http://127.0.0.1:5555/callback');
        $params = ['client_id' => 'test', 'state' => 'original', 'code_challenge' => 'challenge'];
        $request = (new ServerRequest())->withUri(new Uri('https://auth.example.com/oauth/authorize?client_id=test&state=original&code_challenge=challenge'))->withQueryParams($params)->withMethod('GET');
        $login = $flow->resolve($request, $authorization);
        self::assertStringContainsString('Sign in to authorize', (string) $login->getBody());
        self::assertStringContainsString("form-action 'self';", $login->getHeaderLine('Content-Security-Policy'));
        // Simulate successful native password/2FA login, preserving the session.
        session_start();
        $key = array_key_first($_SESSION['oauth_pending']);
        $_SESSION['oauth_pending'][$key]['user_id'] = '123';
        session_write_close();
        $consent = $flow->resolve($request, $authorization);
        self::assertStringContainsString('Allow access', (string) $consent->getBody());
        self::assertStringContainsString("form-action 'self' http://127.0.0.1:5555;", $consent->getHeaderLine('Content-Security-Policy'));
        $csrf = $_SESSION['oauth_pending'][$key]['csrf'];
        $post = $request->withMethod('POST')->withParsedBody(['csrf' => $csrf, 'action' => 'approve']);
        self::assertSame(403, $flow->resolve($post->withParsedBody(['csrf' => 'wrong', 'action' => 'approve']), $authorization)->getStatusCode());
        self::assertSame(403, $flow->resolve($post->withQueryParams([...$params, 'state' => 'changed']), $authorization)->getStatusCode());
        $sessionId = 'different-session';
        self::assertSame(403, $flow->resolve($post, $authorization)->getStatusCode());
        $sessionId = 'browser-session';
        $decision = $flow->resolve($post, $authorization);
        self::assertInstanceOf(AuthorizationDecision::class, $decision);
        self::assertTrue($decision->approved);
        self::assertTrue($decision->authenticationComplete);
        self::assertSame('123', $decision->userId);
        self::assertSame(403, $flow->resolve($post, $authorization)->getStatusCode());
        session_start();
        session_destroy();
    }
}
