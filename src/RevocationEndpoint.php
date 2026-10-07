<?php
declare(strict_types=1);
namespace Light\OAuth2;
use Light\OAuth2\Contract\Store;
use Light\OAuth2\Repository\ClientRepository;
use Light\OAuth2\Auth\TokenValidator;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\{ServerRequestInterface, ResponseInterface};
use Laminas\Diactoros\Response;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
final class RevocationEndpoint
{
    public function __construct(private Config $config, private Store $store, private TokenValidator $validator) {}
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $params = $request->getParsedBody();
            if (!is_array($params) || !is_string($params['token'] ?? null)) throw OAuthServerException::invalidRequest('token');
            $clientId = $params['client_id'] ?? null;
            $secret = $params['client_secret'] ?? null;
            if (preg_match('/^Basic (.+)$/i', $request->getHeaderLine('Authorization'), $matches)) {
                $decoded = base64_decode($matches[1], true);
                if ($decoded !== false && str_contains($decoded, ':')) {
                    [$clientId, $secret] = array_map('urldecode', explode(':', $decoded, 2));
                }
            }
            if (!is_string($clientId) || ($secret !== null && !is_string($secret)) || !(new ClientRepository($this->store))->validateClient($clientId, $secret, 'authorization_code')) throw OAuthServerException::invalidClient($request);
            $token = $params['token'];
            // Unknown, expired and already revoked tokens still return HTTP 200.
            if (substr_count($token, '.') === 2) {
                try {
                    $context = $this->validatorFor($token)->validate($request->withHeader('Authorization', 'Bearer ' . $token));
                    if ($context->clientId === $clientId) $this->store->revoke('access_token', $context->tokenId);
                } catch (OAuthServerException) {}
            } else {
                try {
                    $payload = json_decode(Crypto::decryptWithPassword($token, $this->config->encryptionKey), true);
                    if (is_array($payload) && ($payload['client_id'] ?? null) === $clientId && is_string($payload['refresh_token_id'] ?? null)) {
                        $this->store->transaction(function () use ($payload) {
                            $record = $this->store->record('refresh_token', $payload['refresh_token_id']);
                            if (!$record) return;
                            $this->store->revoke('refresh_token', $payload['refresh_token_id']);
                            $this->store->revoke('access_token', $record['access_token_id']);
                        });
                    }
                } catch (WrongKeyOrModifiedCiphertextException|\InvalidArgumentException) {}
            }
            return (new Response())->withHeader('Cache-Control', 'no-store');
        } catch (OAuthServerException $error) { return $error->generateHttpResponse(new Response())->withHeader('Cache-Control', 'no-store'); }
    }
    private function validatorFor(string $token): TokenValidator
    {
        // Unverified jti is only a lookup hint. Audience comes from our stored
        // issuance record; signature, expiry and caller ownership are still checked.
        $payload = json_decode(base64_decode(strtr(explode('.', $token)[1], '-_', '+/')), true);
        $id = is_array($payload) ? ($payload['jti'] ?? null) : null;
        $record = is_string($id) ? $this->store->record('access_token', $id) : null;
        if ($record && isset($record['exchange_subject'], $record['resource'])) {
            return new TokenValidator($this->config->forResource($record['resource']), $this->store);
        }
        return $this->validator;
    }
}
