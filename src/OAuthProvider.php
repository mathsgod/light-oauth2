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
    private ResourceSelection $resources;
    private ResourceRegistry $registry;
    private ScopeRepository $scopes;
    private RevocationEndpoint $revocation;
    private TokenValidator $validator;
    private TokenValidator $apiValidator;
    private RefreshTokenRepository $refresh;
    private ClientMetadata\ClientResolver $clients;
    private ?DynamicClientRegistrationEndpoint $registration = null;
    public function __construct(private Config $config, private Store $store, private PermissionProvider $permissions, private AuthorizationFlow $flow, ?ClientMetadata\MetadataFetcher $metadataFetcher = null)
    {
        $this->registry = new ResourceRegistry($config, $store);
        if ($config->cimdEnabled && $metadataFetcher === null && !extension_loaded('curl')) {
            throw new \LogicException('CIMD requires ext-curl');
        }
        if ($config->dcrEnabled) {
            if (!$store instanceof Contract\ClientStore) throw new \LogicException('DCR requires a ClientStore with insert-only createClient support');
            $this->registration = new DynamicClientRegistrationEndpoint($store, $permissions, $this->registry);
        }
        $clients = $this->clients = new ClientMetadata\ClientResolver($store, $permissions->scopes(),
            $config->cimdEnabled ? ($metadataFetcher ?? new ClientMetadata\HttpsMetadataFetcher()) : null, $this->registry);
        $this->resources = new ResourceSelection($config, $this->registry);
        $this->scopes = new ScopeRepository($permissions, $this->registry, $this->resources);
        $this->server = new AuthorizationServer(new ClientRepository($store, $clients), new AccessTokenRepository($store, $config, $clients, $this->resources, $this->registry), $this->scopes, $config->privateKey, $config->encryptionKey, new Response\TokenResponse());
        if (!$store instanceof Contract\RefreshTokenStore) throw new \LogicException('OAuth stores must implement RefreshTokenStore for refresh replay protection');
        $refresh = $this->refresh = new RefreshTokenRepository($store, $this->resources);
        $grant = new AuthCodeGrant(new AuthCodeRepository($store, $this->resources), $refresh, new \DateInterval($config->codeTtl));
        $grant->setRefreshTokenTTL(new \DateInterval($config->refreshTokenTtl));
        $this->server->enableGrantType($grant, new \DateInterval($config->accessTokenTtl));
        $grant = new RefreshTokenGrant($refresh);
        $grant->setRefreshTokenTTL(new \DateInterval($config->refreshTokenTtl));
        $this->server->enableGrantType($grant, new \DateInterval($config->accessTokenTtl));
        $this->validator = new TokenValidator($config, $store, $clients, $this->registry);
        $this->apiValidator = $config->apiResource === null ? $this->validator : new TokenValidator($config->forResource($config->apiResource), $store, $clients, $this->registry);
        $this->server->enableGrantType(new Grant\TokenExchangeGrant($config, $store, $this->validator, $this->registry, $this->resources), new \DateInterval($config->exchangeTokenTtl));
        $this->revocation = new RevocationEndpoint($config, $store, $this->validator, $clients, $this->registry);
    }
    public function registerClient(ServerRequestInterface $request): ResponseInterface
    {
        return $this->registration?->handle($request) ?? new JsonResponse(['error' => 'not_found'], 404, ['Cache-Control' => 'no-store']);
    }
    public function revoke(ServerRequestInterface $request): ResponseInterface { return $this->revocation->handle($request); }
    public function validator(): TokenValidator { return $this->validator; }
    public function authorize(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $params = $request->getQueryParams();
            $this->resources->begin($params, $request->getUri()->getQuery());
            // Require PKCE S256 for every client, including confidential clients.
            if (($params['code_challenge_method'] ?? null) !== 'S256' || !is_string($params['code_challenge'] ?? null)) throw OAuthServerException::invalidRequest('code_challenge_method', 'S256 PKCE required');
            if (!is_string($params['state'] ?? null) || $params['state'] === '') throw OAuthServerException::invalidRequest('state');
            $this->registry->assertResource($this->resources->resource());
            $authorization = $this->server->validateAuthorizationRequest($request);
            $client = $authorization->getClient();
            if (!$client instanceof Entity\Client) throw OAuthServerException::invalidClient($request);
            $this->registry->assertClient($client->record, $this->resources->resource());
            $automatic = $this->config->autoSelectScopes && !array_key_exists('scope', $params)
                ? new AutomaticScopes($this->permissions, $this->registry->scopes($this->resources->resource(), $this->permissions->scopes())) : null;
            if ($automatic !== null) $request = $request->withAttribute(AutomaticScopes::class, $automatic);
            $request = $request->withAttribute(ScopeRepository::class, $this->scopes);
            $offeredScopeIds = array_map(fn($scope): string => $scope->getIdentifier(), $authorization->getScopes());
            $decision = $this->flow->resolve($request, $authorization);
            if ($decision instanceof ResponseInterface) return $this->noStore($decision);
            if (!$decision->authenticationComplete) throw OAuthServerException::accessDenied('Complete login and required second factor first');
            $approvedScopeIds = array_map(fn($scope): string => $scope->getIdentifier(), $authorization->getScopes());
            if ($decision->approved && $automatic === null && array_diff($approvedScopeIds, $offeredScopeIds) !== []) {
                throw OAuthServerException::invalidScope('');
            }
            if ($decision->approved && $automatic !== null) $automatic->assertSelected($authorization, $decision->userId);
            if ($decision->approved) $this->scopes->finalizeScopes($authorization->getScopes(), 'authorization_code', $authorization->getClient(), $decision->userId);
            $authorization->setUser(new User($decision->userId));
            $authorization->setAuthorizationApproved($decision->approved);
            return $this->noStore($this->server->completeAuthorizationRequest($authorization, new \Laminas\Diactoros\Response()));
        } catch (OAuthServerException $error) { return $this->noStore($error->generateHttpResponse(new \Laminas\Diactoros\Response())); }
        finally { $this->resources->reset(); }
    }
    public function token(ServerRequestInterface $request): ResponseInterface
    {
        $this->resources->reset();
        try {
            $params = $request->getParsedBody();
            if (!is_array($params)) throw OAuthServerException::invalidRequest('grant_type');
            if (($params['grant_type'] ?? null) !== Grant\TokenExchangeGrant::IDENTIFIER) $this->resources->begin($params, (string) $request->getBody());
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
        finally { $this->refresh->reset(); $this->resources->reset(); }
    }
    private function noStore(ResponseInterface $response): ResponseInterface
    {
        return $response->withHeader('Cache-Control', 'no-store')->withHeader('Pragma', 'no-cache');
    }
    public function metadata(ServerRequestInterface $request): ResponseInterface
    {
        return new JsonResponse([
            ...($this->config->dcrEnabled ? ['registration_endpoint' => $this->config->endpoint('register')] : []),
            'issuer' => $this->config->issuer,
            'client_id_metadata_document_supported' => $this->config->cimdEnabled,
            'authorization_endpoint' => $this->config->endpoint('authorize'),
            'token_endpoint' => $this->config->endpoint('token'),
            'revocation_endpoint' => $this->config->endpoint('revoke'),
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token', Grant\TokenExchangeGrant::IDENTIFIER],
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
        $manager = new Management\ResourceManager($this->store, $this->permissions);
        $app->getContainer()->add(Controller\OAuthResourceController::class, new Controller\OAuthResourceController($manager));
        $app->getSchemaFactory()->addNamespace('Light\\OAuth2\\Controller');
        $app->getSchemaFactory()->addNamespace('Light\\OAuth2\\Type');
        $app->getSchemaFactory()->addNamespace('Light\\OAuth2\\Input');
        if (method_exists($app, 'addPermissions')) $app->addPermissions(['oauth_resource.list', 'oauth_resource.add', 'oauth_resource.update', 'oauth_resource.delete']);
        $app->addMenus([['label' => 'OAuth Resources', 'to' => '/OAuthResource', 'icon' => 'sym_o_dns', 'permission' => 'oauth_resource.list']]);
    
        if ($this->store instanceof Contract\ClientStore) {
            if (!interface_exists(\Light\GraphQL\ExplicitController::class)) {
                throw new \LogicException('OAuth client management requires Light explicit controller registration support');
            }
            $manager = new Management\ClientManager($this->store, $this->permissions, $this->registry);
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
        if ($this->flow instanceof FrontendAuthorizationFlow) {
            foreach (['GET', 'POST', 'OPTIONS'] as $method) {
                $router->map($method, $routePrefix . '/interaction', fn(ServerRequestInterface $request): ResponseInterface => $this->flow->interaction($request, [$this, 'authorize']));
            }
        }
        $router->map('POST', $routePrefix . '/token', [$this, 'token']);
        $router->map('POST', $routePrefix . '/revoke', [$this, 'revoke']);
        if ($this->registration !== null) $router->map('POST', $routePrefix . '/register', [$this, 'registerClient']);
        $router->map('GET', '/.well-known/oauth-authorization-server' . $issuerPath, [$this, 'metadata']);
        $app->setAuthServiceFactory(function (ServerRequestInterface $request) use ($loadUser, $routePrefix, $issuerPath) {
            $path = $request->getUri()->getPath();
            $anonymousRequest = $request->withoutHeader('Authorization')->withCookieParams([]);
            if (in_array($path, [$routePrefix . '/token', $routePrefix . '/revoke', ...($this->registration !== null ? [$routePrefix . '/register'] : []), '/.well-known/oauth-authorization-server' . $issuerPath], true)) {
                return new \Light\Auth\Service($anonymousRequest);
            }
            if (in_array($path, [$routePrefix . '/authorize', $routePrefix . '/interaction'], true)) {
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
