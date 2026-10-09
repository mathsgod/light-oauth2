<?php
declare(strict_types=1);
namespace Light\OAuth2\Grant;

use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Exception\{OAuthServerException, UniqueTokenIdentifierConstraintViolationException};
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use League\OAuth2\Server\{RequestAccessTokenEvent, RequestEvent};
use Light\OAuth2\{Config, TokenExchangePolicy};
use Light\OAuth2\Auth\TokenValidator;
use Light\OAuth2\Contract\Store;
use Light\OAuth2\Entity\AccessToken;
use Psr\Http\Message\ServerRequestInterface;

/** RFC 8693 profile: local access tokens, confidential callers, one target, no actor token. */
final class TokenExchangeGrant extends AbstractGrant
{
    public const IDENTIFIER = 'urn:ietf:params:oauth:grant-type:token-exchange';
    public const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

    public function __construct(private Config $config, private Store $store, private TokenValidator $validator, private TokenExchangePolicy $policy, private ?\Light\OAuth2\ResourceSelection $resources = null) {}
    public function getIdentifier(): string { return self::IDENTIFIER; }

    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseTypeInterface $responseType, \DateInterval $accessTokenTTL): ResponseTypeInterface
    {
        $this->validateParameters($request);
        $client = $this->validateClient($request);
        if (!$client->isConfidential()) throw OAuthServerException::invalidClient($request);
        $params = $request->getParsedBody();
        $target = $this->policy->target($client->getIdentifier(), $this->config->resource, $params['resource'] ?? null, $params['audience'] ?? null);
        if (($params['subject_token_type'] ?? null) !== self::ACCESS_TOKEN_TYPE) throw OAuthServerException::invalidRequest('subject_token_type', 'Only local access tokens are supported');
        if (($params['requested_token_type'] ?? self::ACCESS_TOKEN_TYPE) !== self::ACCESS_TOKEN_TYPE) throw OAuthServerException::invalidRequest('requested_token_type', 'Only access tokens can be issued');
        if (isset($params['actor_token']) || isset($params['actor_token_type'])) throw OAuthServerException::invalidRequest('actor_token', 'Actor tokens are not supported by this profile');
        if (!isset($params['subject_token']) || $params['subject_token'] === '') throw OAuthServerException::invalidRequest('subject_token');
        if (!preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/D', $params['subject_token'])) throw OAuthServerException::invalidRequest('subject_token', 'Expected a local access-token JWT');
        try {
            // Client Basic authentication must not leak into subject-token validation.
            $subject = $this->validator->validate($request->withHeader('Authorization', 'Bearer ' . $params['subject_token']));
        } catch (OAuthServerException) {
            throw OAuthServerException::invalidRequest('subject_token', 'Invalid subject token');
        }
        $record = $this->store->record('access_token', $subject->tokenId);
        if (!$record || isset($record['exchange_subject'])) throw OAuthServerException::invalidRequest('subject_token', 'Exchange chaining is not supported');
        $this->resources?->begin(['resource' => $target['resource']]);
        $requested = $params['scope'] ?? implode(' ', array_intersect($subject->scopes, $target['scopes']));
        if (trim($requested) === '') throw OAuthServerException::invalidScope('');
        $scopes = $this->validateScopes($requested);
        foreach ($scopes as $scope) {
            $id = $scope->getIdentifier();
            if (!in_array($id, $subject->scopes, true) || !in_array($id, $target['scopes'], true)) throw OAuthServerException::invalidScope($id);
        }
        // Also checks current user permissions and the exchanging client's allowed scopes.
        $scopes = $this->scopeRepository->finalizeScopes($scopes, self::IDENTIFIER, $client, $subject->userId);
        $token = $this->accessTokenRepository->getNewToken($client, $scopes, $subject->userId);
        if (!$token instanceof AccessToken) throw new \LogicException('Token exchange requires Light AccessToken entities');
        $token->setExchangeTarget($target['resource'], $subject->tokenId);
        $expires = min((new \DateTimeImmutable())->add($accessTokenTTL)->getTimestamp(), $record['expires_at'], $subject->expiresAt);
        if ($expires <= time()) throw OAuthServerException::invalidRequest('subject_token', 'Subject token expired');
        $token->setExpiryDateTime((new \DateTimeImmutable())->setTimestamp($expires));
        $token->setPrivateKey($this->privateKey);
        for ($attempt = 0; $attempt < self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS; $attempt++) {
            $token->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->accessTokenRepository->persistNewAccessToken($token);
                $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $token));
                $responseType->setAccessToken($token);
                return $responseType;
            } catch (UniqueTokenIdentifierConstraintViolationException $error) {
                if ($attempt === self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS - 1) throw $error;
            }
        }
        throw new \LogicException('Unable to issue exchange token');
    }

    private function validateParameters(ServerRequestInterface $request): void
    {
        $params = $request->getParsedBody();
        foreach (['subject_token', 'subject_token_type', 'requested_token_type', 'actor_token', 'actor_token_type', 'resource', 'audience', 'scope', 'client_id', 'client_secret'] as $name) {
            if (array_key_exists($name, $params) && (!is_string($params[$name]) || $params[$name] === '')) throw OAuthServerException::invalidRequest($name);
        }
        // PHP's parsed form body drops repeated scalar parameters. Inspect the wire
        // form too, so multi-target requests cannot silently become single-target ones.
        $counts = [];
        foreach (explode('&', (string) $request->getBody()) as $pair) {
            $name = urldecode(explode('=', $pair, 2)[0]);
            if (!in_array($name, ['resource', 'audience', 'subject_token', 'subject_token_type', 'requested_token_type', 'actor_token', 'actor_token_type', 'scope', 'client_id', 'client_secret', 'grant_type'], true)) continue;
            $counts[$name] = ($counts[$name] ?? 0) + 1;
            if ($counts[$name] > 1) {
                if (in_array($name, ['resource', 'audience'], true)) throw TokenExchangePolicy::invalidTarget();
                throw OAuthServerException::invalidRequest($name, 'Repeated parameter');
            }
        }
    }
}
