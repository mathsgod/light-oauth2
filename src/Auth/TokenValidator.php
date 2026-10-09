<?php
declare(strict_types=1);
namespace Light\OAuth2\Auth;
use Light\OAuth2\{Config, Repository\AccessTokenRepository};
use Light\OAuth2\Contract\Store;
use League\OAuth2\Server\{ResourceServer, CryptKey};
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\{IssuedBy, PermittedFor};
final class TokenValidator
{
    private ResourceServer $server;
    private CryptKey $key;
    public function __construct(private Config $config, private Store $store, private ?\Light\OAuth2\ClientMetadata\ClientResolver $clients = null, private ?\Light\OAuth2\ResourceRegistry $registry = null)
    {
        $this->registry ??= new \Light\OAuth2\ResourceRegistry($config, $store);
        $this->key = new CryptKey($config->publicKey);
        $this->server = new ResourceServer(new AccessTokenRepository($store, $config, $clients), $this->key);
    }
    private function client(string $id): ?array
    {
        return $this->clients ? $this->clients->client($id) : $this->store->client($id);
    }
    private function resourceScopes(array $client, string $resource, array $scopes): array
    {
        try {
            $this->registry->assertClient($client, $resource);
            return $this->registry->scopes($resource, $scopes);
        } catch (OAuthServerException) {
            throw OAuthServerException::accessDenied('Resource is disabled, missing or no longer allowed for this client');
        }
    }
    /** Select the source audience from a verified, persisted local token, never from caller input. */
    public function validateForExchange(ServerRequestInterface $request): TokenContext
    {
        $validated = $this->server->validateAuthenticatedRequest($request);
        $record = $this->store->record('access_token', $validated->getAttribute('oauth_access_token_id'));
        if (!$record || isset($record['exchange_subject'])) throw OAuthServerException::accessDenied('Invalid exchange source');
        $resource = $record['resource'] ?? $this->config->resource;
        return (new self($this->config->forResource($resource), $this->store, $this->clients, $this->registry))->validate($request);
    }
    public function validate(ServerRequestInterface $request): TokenContext
    {
        $validated = $this->server->validateAuthenticatedRequest($request);
        $id = $validated->getAttribute('oauth_access_token_id');
        $record = $this->store->record('access_token', $id);
        if (!$record || empty($record['user_id'])) throw OAuthServerException::accessDenied('Invalid user token');
        $raw = preg_replace('/^Bearer\s+/i', '', $request->getHeaderLine('Authorization'));
        $jwt = Configuration::forAsymmetricSigner(new Sha256(), InMemory::plainText('unused'), InMemory::plainText($this->key->getKeyContents()));
        $token = $jwt->parser()->parse($raw);
        if (!$jwt->validator()->validate($token, new IssuedBy($this->config->issuer), new PermittedFor($this->config->resource))) {
            throw OAuthServerException::accessDenied('Invalid issuer or resource audience');
        }
        $client = $this->client($record['client_id']);
        if (!$client || !$client['enabled']) throw OAuthServerException::accessDenied('Client disabled');
        if (isset($record['resource']) && $record['resource'] !== $this->config->resource) throw OAuthServerException::accessDenied('Invalid stored resource');
        $scopes = $this->resourceScopes($client, $this->config->resource, array_intersect($record['scopes'], $client['scopes']));
        if (isset($record['exchange_subject'])) {
            $subject = $this->store->record('access_token', $record['exchange_subject']);
            $sourceClient = $subject ? $this->client($subject['client_id']) : null;
            if (!$subject || !$sourceClient || empty($sourceClient['enabled'])) throw OAuthServerException::accessDenied('Invalid exchange source');
            $scopes = array_intersect($scopes, $subject['scopes'], $sourceClient['scopes']);
            $sourceResource = $subject['resource'] ?? $this->registry->clientPolicy()->defaultResource;
            $scopes = $this->resourceScopes($sourceClient, $sourceResource, $scopes);
            $scopes = $this->resourceScopes($client, $sourceResource, $scopes);
        }
        return new TokenContext((string) $record['user_id'], $record['client_id'], $id, array_values($scopes), $token->claims()->get('exp')->getTimestamp());
    }
}
