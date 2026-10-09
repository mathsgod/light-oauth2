<?php
declare(strict_types=1);
namespace Light\OAuth2;

use Laminas\Diactoros\Response\{JsonResponse, RedirectResponse};
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Light\OAuth2\Contract\{AuthorizationDecision, AuthorizationFlow};
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

/** Keeps OAuth state on the API while a configured frontend renders the UI. */
final class FrontendAuthorizationFlow implements AuthorizationFlow
{
    public const INTERACTION = 'light.oauth.frontend.interaction';

    public function __construct(private BrowserAuthorizationFlow $browser, private Config $config)
    {
        if ($config->authorizationUiUrl === null) throw new \InvalidArgumentException('Configure an authorization UI URL');
    }

    public function resolve(ServerRequestInterface $request, AuthorizationRequest $authorization): AuthorizationDecision|ResponseInterface
    {
        if ($request->getAttribute(self::INTERACTION) === true) {
            return $this->browser->resolve($request, $authorization);
        }
        $this->session($request);
        try {
            $pending = &$_SESSION['oauth_frontend_requests'];
            $pending ??= [];
            foreach ($pending as $id => $entry) if ($entry['expires'] < time()) unset($pending[$id]);
            if (count($pending) >= 10) array_shift($pending);
            $id = bin2hex(random_bytes(32));
            $pending[$id] = ['params' => $request->getQueryParams(), 'expires' => time() + 600];
            return new RedirectResponse($this->config->authorizationUiUrl . '?request_id=' . $id, 303);
        } finally { session_write_close(); }
    }

    /** Resume only server-stored parameters from the same API browser session. */
    public function interaction(ServerRequestInterface $request, callable $authorize): ResponseInterface
    {
        $origin = $request->getHeaderLine('Origin');
        $parts = parse_url($this->config->authorizationUiUrl);
        $allowedOrigin = $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
        $headers = ['Cache-Control' => 'no-store', 'Vary' => 'Origin', 'X-Content-Type-Options' => 'nosniff'];
        if (($origin !== '' && $origin !== $allowedOrigin) || ($request->getMethod() === 'POST' && $origin !== $allowedOrigin)) {
            return new JsonResponse(['stage' => 'error', 'message' => 'Origin not allowed'], 403, $headers);
        }
        if ($origin === $allowedOrigin) {
            $headers += ['Access-Control-Allow-Origin' => $allowedOrigin, 'Access-Control-Allow-Credentials' => 'true'];
        }
        if ($request->getMethod() === 'OPTIONS') {
            return new JsonResponse(null, 204, $headers + ['Access-Control-Allow-Methods' => 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers' => 'Content-Type']);
        }
        $id = $request->getQueryParams()['request_id'] ?? null;
        $this->session($request);
        try {
            $entry = is_string($id) && preg_match('/\A[a-f0-9]{64}\z/', $id) ? ($_SESSION['oauth_frontend_requests'][$id] ?? null) : null;
            if (!$entry || $entry['expires'] < time()) {
                return new JsonResponse(['stage' => 'error', 'message' => 'Authorization expired. Restart login from your application.'], 403, $headers);
            }
        } finally { session_write_close(); }
        $uri = new \Laminas\Diactoros\Uri($this->config->endpoint('authorize') . '?' . http_build_query($entry['params']));
        $resume = $request->withUri($uri)->withQueryParams($entry['params'])->withAttribute(self::INTERACTION, true);
        $response = $authorize($resume);
        $location = $response->getHeaderLine('Location');
        if ($location !== '') {
            $reload = $location === $uri->getPath() . '?' . $uri->getQuery();
            if (!$reload) {
                $this->session($request);
                try { unset($_SESSION['oauth_frontend_requests'][$id]); }
                finally { session_write_close(); }
            }
            $response = new JsonResponse($reload ? ['reload' => true] : ['redirect_uri' => $location]);
        } elseif (!str_contains($response->getHeaderLine('Content-Type'), 'application/json')) {
            $response = new JsonResponse(['stage' => 'error', 'message' => 'Unable to continue authorization. Restart login.'], 400);
        }
        foreach ($headers as $name => $value) $response = $response->withHeader($name, $value);
        return $response;
    }

    private function session(ServerRequestInterface $request): void
    {
        session_name('LIGHT_OAUTH_SESSION');
        if (!session_start([
            'use_strict_mode' => 1, 'use_only_cookies' => 1, 'cookie_httponly' => true,
            'cookie_secure' => $request->getUri()->getScheme() === 'https', 'cookie_samesite' => 'Lax',
            'cookie_path' => dirname($request->getUri()->getPath()),
        ])) throw new \RuntimeException('Unable to start OAuth browser session');
    }
}
