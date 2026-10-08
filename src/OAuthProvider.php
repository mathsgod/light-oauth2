<?php
declare(strict_types=1);
namespace Light\OAuth2;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\{AuthCodeGrant, RefreshTokenGrant};
use League\OAuth2\Server\Exception\OAuthServerException;
use Light\OAuth2\Contract\{Store, PermissionProvider, AuthorizationFlow};
use Light\OAuth2\Repository\{ClientRepository, ScopeRepository, AccessTokenRepository, AuthCodeRepository, RefreshTokenRepository};
use Light\OAuth2\Entity\User;
use Light\OAuth2\Auth\TokenValidator;
use Laminas\Diactoros\Response\{JsonResponse};
use Psr\Http\Message\{ServerRequestInterface, ResponseInterface};
final class OAuthProvider
{
    private AuthorizationServer $server;
    private ScopeRepository $scopes;
    private RevocationEndpoint $revocation;
    private TokenValidator $validator;
    private TokenValidator $apiValidator;
    private RefreshTokenRepository $refresh;
    private ClientMetadata\ClientResolver $clients;
    public function __construct(private Config $config, private Store $store, private PermissionProvider $permissions, private AuthorizationFlow $flow, private ?TokenExchangePolicy $exchangePolicy = null, ?ClientMetadata\MetadataFetcher $metadataFetcher = null)
    {
        if ($config->cimdEnabled && $metadataFetcher === null && !extension_loaded('curl')) {
            throw new \LogicException('CIMD requires ext-curl');
        }
        $clients = $this->clients = new ClientMetadata\ClientResolver($store, $permissions->scopes(),
            $config->cimdEnabled ? ($metadataFetcher ?? new ClientMetadata\HttpsMetadataFetcher()) : null);
        $this->scopes = new ScopeRepository($permissions);
        $this->server = new AuthorizationServer(new ClientRepository($store, $clients), new AccessTokenRepository($store, $config, $clients), $this->scopes, $config->privateKey, $config->encryptionKey, new Response\TokenResponse());
        if (!$store instanceof Contract\RefreshTokenStore) throw new \LogicException('OAuth stores must implement RefreshTokenStore for refresh replay protection');
        $refresh = $this->refresh = new RefreshTokenRepository($store);
        $grant = new AuthCodeGrant(new AuthCodeRepository($store), $refresh, new \DateInterval($config->codeTtl));
        $grant->setRefreshTokenTTL(new \DateInterval($config->refreshTokenTtl));
        $this->server->enableGrantType($grant, new \DateInterval($config->accessTokenTtl));
        $grant = new RefreshTokenGrant($refresh);
        $grant->setRefreshTokenTTL(new \DateInterval($config->refreshTokenTtl));
        $this->server->enableGrantType($grant, new \DateInterval($config->accessTokenTtl));
        $this->validator = new TokenValidator($config, $store, $clients);
        $this->apiValidator = $config->apiResource === null ? $this->validator : new TokenValidator($config->forResource($config->apiResource), $store, $clients);
        if ($exchangePolicy !== null) {
            $this->server->enableGrantType(new Grant\TokenExchangeGrant($config, $store, $this->validator, $exchangePolicy), new \DateInterval($exchangePolicy->ttl));
        }
        $this->revocation = new RevocationEndpoint($config, $store, $this->validator, $clients);
    }
    public function revoke(ServerRequestInterface $request): ResponseInterface { return $this->revocation->handle($request); }
    public function validator(): TokenValidator { return $this->validator; }
    public function authorize(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $params = $request->getQueryParams();
            $this->validateResource($params);
            // Require PKCE S256 for every client, including confidential clients.
            if (($params['code_challenge_method'] ?? null) !== 'S256' || !is_string($params['code_challenge'] ?? null)) throw OAuthServerException::invalidRequest('code_challenge_method', 'S256 PKCE required');
            if (!is_string($params['state'] ?? null) || $params['state'] === '') throw OAuthServerException::invalidRequest('state');
            $authorization = $this->server->validateAuthorizationRequest($request);
            $decision = $this->flow->resolve($request, $authorization);
            if ($decision instanceof ResponseInterface) return $this->noStore($decision);
            if (!$decision->authenticationComplete) throw OAuthServerException::accessDenied('Complete login and required second factor first');
            if ($decision->approved) $this->scopes->finalizeScopes($authorization->getScopes(), 'authorization_code', $authorization->getClient(), $decision->userId);
            $authorization->setUser(new User($decision->userId));
            $authorization->setAuthorizationApproved($decision->approved);
            return $this->noStore($this->server->completeAuthorizationRequest($authorization, new \Laminas\Diactoros\Response()));
        } catch (OAuthServerException $error) { return $this->noStore($error->generateHttpResponse(new \Laminas\Diactoros\Response())); }
    }
    public function token(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $params = $request->getParsedBody();
            if (!is_array($params)) throw OAuthServerException::invalidRequest('grant_type');
            if (($params['grant_type'] ?? null) !== Grant\TokenExchangeGrant::IDENTIFIER || $this->exchangePolicy === null) $this->validateResource($params);
            $this->refresh->reset();
            $response = $this->store->transaction(function () use ($request) {
                try { return $this->server->respondToAccessTokenRequest($request, new \Laminas\Diactoros\Response()); }
                catch (Exception\RefreshTokenReuse $reuse) { return $reuse; }
            });
            // Returning the signal commits family revocation; ordinary failures
            // still throw inside the transaction and roll back token consumption.
            if ($response instanceof Exception\RefreshTokenReuse) throw OAuthServerException::invalidRefreshToken('Refresh token reuse detected');
            return $this->noStore($response);
        } catch (OAuthServerException $error) { return $this->noStore($error->generateHttpResponse(new \Laminas\Diactoros\Response())); }
        finally { $this->refresh->reset(); }
    }
    private function validateResource(array $params): void
    {
        if (isset($params['resource']) && $params['resource'] !== $this->config->resource) throw OAuthServerException::invalidRequest('resource', 'Unsupported resource');
    }
    private function noStore(ResponseInterface $response): ResponseInterface
    {
        return $response->withHeader('Cache-Control', 'no-store')->withHeader('Pragma', 'no-cache');
    }
    public function metadata(ServerRequestInterface $request): ResponseInterface
    {
        return new JsonResponse([
            'issuer' => $this->config->issuer,
            'client_id_metadata_document_supported' => $this->config->cimdEnabled,
            'authorization_endpoint' => $this->config->endpoint('authorize'),
            'token_endpoint' => $this->config->endpoint('token'),
            'revocation_endpoint' => $this->config->endpoint('revoke'),
            'response_types_supported' => ['code'],
            'grant_types_supported' => $this->exchangePolicy === null ? ['authorization_code', 'refresh_token'] : ['authorization_code', 'refresh_token', Grant\TokenExchangeGrant::IDENTIFIER],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['none', 'client_secret_basic', 'client_secret_post'],
            'scopes_supported' => $this->permissions->scopes(),
        ]);
    }
    public function protectedResourceMetadata(ServerRequestInterface $request): ResponseInterface
    {
        return new JsonResponse(['resource' => $this->config->resource, 'authorization_servers' => [$this->config->issuer], 'bearer_methods_supported' => ['header'], 'scopes_supported' => $this->permissions->scopes()]);
    }
    /** Requires Light's new getRouter() and setAuthServiceFactory() extension points. */
    public function register(\Light\App $app, callable $loadUser): void
    {
        if (!method_exists($app, 'getRouter') || !method_exists($app, 'setAuthServiceFactory')) throw new \LogicException('Use a Light version with OAuth extension points: getRouter(), setAuthServiceFactory() and createAuthService()');
        if ($this->store instanceof Contract\ClientStore) {
            if (!interface_exists(\Light\GraphQL\ExplicitController::class)) {
                throw new \LogicException('OAuth client management requires Light explicit controller registration support');
            }
            $manager = new Management\ClientManager($this->store, $this->permissions);
            $app->getContainer()->add(\Light\OAuth2\Controller\OAuthClientController::class, new \Light\OAuth2\Controller\OAuthClientController($manager));
            $app->getSchemaFactory()->addNamespace('Light\\OAuth2\\Controller');
            $app->getSchemaFactory()->addNamespace('Light\\OAuth2\\Type');
            $app->getSchemaFactory()->addNamespace('Light\\OAuth2\\Input');
            if (method_exists($app, 'addPermissions')) {
                $app->addPermissions(['oauth_client.list', 'oauth_client.add', 'oauth_client.update', 'oauth_client.delete']);
            }
            $app->addMenus([[
                'label' => 'OAuth Clients', 'to' => '/OAuthClient',
                'icon' => 'sym_o_key', 'permission' => 'oauth_client.list',
            ]]);
        }
        if ($this->store instanceof Contract\AuthorizationStore) {
            $manager = new Management\AuthorizationManager($this->store, $this->clients);
            $app->getContainer()->add(Controller\OAuthAuthorizationController::class, new Controller\OAuthAuthorizationController($manager));
            $app->getSchemaFactory()->addNamespace('Light\\OAuth2\\Controller');
            $app->getSchemaFactory()->addNamespace('Light\\OAuth2\\Type');
        }
        $router = $app->getRouter();
        $issuerPath = rtrim(parse_url($this->config->issuer, PHP_URL_PATH) ?? '', '/');
        $routePrefix = $issuerPath . $this->config->routePrefix;
        $router->map('GET', $routePrefix . '/authorize', [$this, 'authorize']);
        $router->map('POST', $routePrefix . '/authorize', [$this, 'authorize']);
        $router->map('POST', $routePrefix . '/token', [$this, 'token']);
        $router->map('POST', $routePrefix . '/revoke', [$this, 'revoke']);
        $router->map('GET', '/.well-known/oauth-authorization-server' . $issuerPath, [$this, 'metadata']);
        $app->setAuthServiceFactory(function (ServerRequestInterface $request) use ($loadUser, $routePrefix, $issuerPath) {
            $path = $request->getUri()->getPath();
            $anonymousRequest = $request->withoutHeader('Authorization')->withCookieParams([]);
            if (in_array($path, [$routePrefix . '/token', $routePrefix . '/revoke', '/.well-known/oauth-authorization-server' . $issuerPath], true)) {
                return new \Light\Auth\Service($anonymousRequest);
            }
            if ($path === $routePrefix . '/authorize') {
                $native = new \Light\Auth\Service($request);
                try { $native->getUser(); return $native; }
                catch (\Light\TokenExpiredException) { return new \Light\Auth\Service($anonymousRequest); }
            }
            // Distinguish stored OAuth credentials without trusting unverified JWT claims.
            // Unknown tokens go through existing Light validation; invalid known OAuth
            // credentials stay rejected rather than falling back to a browser cookie.
            $header = $request->getHeaderLine('Authorization');
            if (!preg_match('/^Bearer ([^.]+)\.([^.]+)\.([^.]+)$/i', $header, $matches)) return new \Light\Auth\Service($request);
            $payload = json_decode(base64_decode(strtr($matches[2], '-_', '+/')), true);
            $id = is_array($payload) ? ($payload['jti'] ?? null) : null;
            if (!is_string($id) || !$this->store->record('access_token', $id)) return new \Light\Auth\Service($request);
            try { $context = $this->apiValidator->validate($request); }
            catch (OAuthServerException) { return new Auth\OAuthService($request, null, $this->permissions, $loadUser); }
            return new Auth\OAuthService($request, $context, $this->permissions, $loadUser);
        });
    }
}
