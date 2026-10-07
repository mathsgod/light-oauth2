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
    public function __construct(private Config $config, private Store $store)
    {
        $this->key = new CryptKey($config->publicKey);
        $this->server = new ResourceServer(new AccessTokenRepository($store, $config), $this->key);
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
        $client = $this->store->client($record['client_id']);
        if (!$client || !$client['enabled']) throw OAuthServerException::accessDenied('Client disabled');
        if (isset($record['resource']) && $record['resource'] !== $this->config->resource) throw OAuthServerException::accessDenied('Invalid stored resource');
        $scopes = array_intersect($record['scopes'], $client['scopes']);
        if (isset($record['exchange_subject'])) {
            $subject = $this->store->record('access_token', $record['exchange_subject']);
            $sourceClient = $subject ? $this->store->client($subject['client_id']) : null;
            if (!$subject || !$sourceClient || empty($sourceClient['enabled'])) throw OAuthServerException::accessDenied('Invalid exchange source');
            $scopes = array_intersect($scopes, $subject['scopes'], $sourceClient['scopes']);
        }
        return new TokenContext((string) $record['user_id'], $record['client_id'], $id, array_values($scopes), $token->claims()->get('exp')->getTimestamp());
    }
}
