<?php
declare(strict_types=1);

namespace Light\OAuth2;

use GraphQL\Error\Error;
use Laminas\Diactoros\Response\HtmlResponse;
use Laminas\Diactoros\Response\RedirectResponse;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Light\App;
use Light\Controller\AuthController;
use Light\Model\User;
use Light\OAuth2\Contract\AuthorizationDecision;
use Light\OAuth2\Contract\AuthorizationFlow;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/** Reuses Light password/2FA checks and binds explicit consent to the browser. */
final class BrowserAuthorizationFlow implements AuthorizationFlow
{
    public function __construct(private App $app) {}

    public function resolve(ServerRequestInterface $request, AuthorizationRequest $authorization): AuthorizationDecision|ResponseInterface
    {
        session_name('LIGHT_OAUTH_SESSION');
        if (!session_start([
            'use_strict_mode' => 1,
            'use_only_cookies' => 1,
            'cookie_httponly' => true,
            'cookie_secure' => $request->getUri()->getScheme() === 'https',
            'cookie_samesite' => 'Lax',
            'cookie_path' => dirname($request->getUri()->getPath()),
        ])) throw new \RuntimeException('Unable to start OAuth browser session');

        try {
            // Bind the full validated request (client, URI, PKCE, scopes and state).
            $params = $request->getQueryParams();
            ksort($params);
            $key = hash('sha256', json_encode($params, JSON_THROW_ON_ERROR));
            $pending = &$_SESSION['oauth_pending'];
            $pending ??= [];
            foreach ($pending as $id => $entry) {
                if ($entry['expires'] < time()) unset($pending[$id]);
            }
            $body = $request->getParsedBody();
            $body = is_array($body) ? $body : [];
            if ($request->getMethod() === 'POST') {
                if (!isset($pending[$key]) || !is_string($body['csrf'] ?? null)
                    || !hash_equals($pending[$key]['csrf'], $body['csrf'])) {
                    return $this->page('Authorization expired', '<p>Please restart authorization.</p>', 403);
                }
            } elseif (!isset($pending[$key])) {
                if (count($pending) >= 10) array_shift($pending);
                $pending[$key] = ['csrf' => bin2hex(random_bytes(32)), 'expires' => time() + 600];
            }

            $entry = &$pending[$key];
            if ($request->getMethod() === 'POST' && ($body['action'] ?? '') === 'login') {
                try {
                    $username = is_string($body['username'] ?? null) ? $body['username'] : '';
                    $password = is_string($body['password'] ?? null) ? $body['password'] : '';
                    $code = is_string($body['code'] ?? null) && $body['code'] !== '' ? $body['code'] : null;
                    $this->app->getContainer()->get(AuthController::class)->login($this->app, $username, $password, $code);
                    $entry['user_id'] = (string) User::Get(['username' => $username])->user_id;
                    $entry['csrf'] = bin2hex(random_bytes(32));
                    session_regenerate_id(true);
                    return new RedirectResponse($this->action($request), 303);
                } catch (Error $error) {
                    return $this->loginPage($request, $authorization, $entry['csrf'], $error->getMessage());
                }
            }

            $auth = $this->app->getAuthService();
            $user = $auth->getUser();
            if (!$user || (int) $user->status !== 0 || $auth->isViewAsMode() || !$auth->getSessionId()
                || ($entry['user_id'] ?? null) !== (string) $user->user_id) {
                return $this->loginPage($request, $authorization, $entry['csrf']);
            }

            $automatic = $request->getAttribute(AutomaticScopes::class);
            if ($automatic instanceof AutomaticScopes) $automatic->select($authorization, (string) $user->user_id);
            $scopeIds = array_map(fn($scope) => $scope->getIdentifier(), $authorization->getScopes());

            if ($request->getMethod() === 'POST') {
                if ($automatic instanceof AutomaticScopes && ($entry['consent_scopes'] ?? null) !== $scopeIds) {
                    return new RedirectResponse($this->action($request), 303);
                }
                if (!in_array($body['action'] ?? '', ['approve', 'deny'], true)
                    || ($entry['session_id'] ?? null) !== $auth->getSessionId()) {
                    return $this->page('Authorization expired', '<p>Please restart authorization.</p>', 403);
                }
                unset($pending[$key]);
                return new AuthorizationDecision((string) $user->user_id, $body['action'] === 'approve', true);
            }

            $entry['session_id'] = $auth->getSessionId();
            $entry['consent_scopes'] = $scopeIds;
            $redirectUri = $authorization->getRedirectUri() ?? $authorization->getClient()->getRedirectUri();
            if (is_array($redirectUri)) $redirectUri = $redirectUri[0] ?? null;
            $scopes = implode('', array_map(fn($scope) => '<li>' . self::escape($scope->getIdentifier()) . '</li>', $authorization->getScopes()));
            return $this->page('Authorize application',
                '<p><strong>' . self::escape($authorization->getClient()->getName()) . '</strong> requests access as '
                . self::escape($user->username) . '.</p><ul>' . $scopes . '</ul>'
                . '<form method="post" action="' . self::escape($this->action($request)) . '">'
                . '<input type="hidden" name="csrf" value="' . self::escape($entry['csrf']) . '">'
                . '<button name="action" value="approve">Allow access</button> '
                . '<button name="action" value="deny">Deny</button></form>', 200, $redirectUri);
        } finally {
            session_write_close();
        }
    }

    private function action(ServerRequestInterface $request): string
    {
        return $request->getUri()->getPath() . '?' . $request->getUri()->getQuery();
    }

    private function loginPage(ServerRequestInterface $request, AuthorizationRequest $authorization, string $csrf, string $error = ''): ResponseInterface
    {
        return $this->page('Sign in to authorize',
            '<p>Sign in to authorize <strong>' . self::escape($authorization->getClient()->getName()) . '</strong>.</p>'
            . ($error !== '' ? '<p role="alert">' . self::escape($error) . '</p>' : '')
            . '<form method="post" action="' . self::escape($this->action($request)) . '">'
            . '<input type="hidden" name="csrf" value="' . self::escape($csrf) . '">'
            . '<input type="hidden" name="action" value="login">'
            . '<label>Username<input name="username" required autocomplete="username"></label>'
            . '<label>Password<input type="password" name="password" required autocomplete="current-password"></label>'
            . '<label>Two-factor code (if enabled)<input name="code" autocomplete="one-time-code" inputmode="numeric"></label>'
            . '<button>Sign in</button></form>', $error !== '' ? 400 : 200);
    }

    private function page(string $title, string $body, int $status = 200, ?string $redirectUri = null): ResponseInterface
    {
        $formAction = "'self'";
        if ($redirectUri !== null) {
            // Browsers can apply form-action to the POST's redirect as well.
            // Only add the origin of the redirect already validated by League.
            $parts = parse_url($redirectUri);
            if (!$parts || !in_array($parts['scheme'] ?? '', ['http', 'https'], true)
                || !preg_match('/\A(?:[a-z0-9.-]+|\[[0-9a-f:]+\])\z/i', $parts['host'] ?? '')) {
                throw new \InvalidArgumentException('Invalid OAuth callback origin');
            }
            $formAction .= ' ' . $parts['scheme'] . '://' . $parts['host']
                . (isset($parts['port']) ? ':' . $parts['port'] : '');
        }
        return new HtmlResponse('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<title>' . self::escape($title) . '</title>'
            . '<style>body{font:16px system-ui;background:#f5f6f8;margin:0;padding:24px}main{max-width:440px;margin:8vh auto;background:white;padding:28px;border-radius:12px}label{display:block;margin:16px 0}input:not([type=hidden]){display:block;box-sizing:border-box;width:100%;padding:10px;margin-top:6px}button{padding:10px 16px;cursor:pointer}[role=alert]{color:#b00020}</style>'
            . '</head><body><main><h1>' . self::escape($title) . '</h1>' . $body . '</main></body></html>',
            $status, ['Content-Security-Policy' => "default-src 'none'; style-src 'unsafe-inline'; form-action {$formAction}; frame-ancestors 'none'; base-uri 'none'", 'X-Content-Type-Options' => 'nosniff', 'Referrer-Policy' => 'no-referrer']);
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
