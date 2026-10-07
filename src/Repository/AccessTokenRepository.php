<?php
declare(strict_types=1);
namespace Light\OAuth2\Repository;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Entities\{AccessTokenEntityInterface, ClientEntityInterface};
use Light\OAuth2\Contract\Store;
use Light\OAuth2\Config;
use Light\OAuth2\Entity\AccessToken;
final class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function __construct(private Store $store, private Config $config) {}
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, ?string $userIdentifier = null): AccessTokenEntityInterface
    {
        $token = new AccessToken($this->config); $token->setClient($clientEntity);
        if ($userIdentifier !== null) $token->setUserIdentifier($userIdentifier);
        foreach ($scopes as $scope) $token->addScope($scope);
        return $token;
    }
    public function persistNewAccessToken(AccessTokenEntityInterface $token): void
    {
        $record = ['expires_at' => $token->getExpiryDateTime()->getTimestamp(), 'revoked' => false, 'user_id' => $token->getUserIdentifier(), 'client_id' => $token->getClient()->getIdentifier(), 'scopes' => array_map(fn($s) => $s->getIdentifier(), $token->getScopes())];
        if ($token instanceof AccessToken) {
            $record['resource'] = $token->resource();
            if ($token->exchangeSubject() !== null) $record['exchange_subject'] = $token->exchangeSubject();
        }
        $this->store->insert('access_token', $token->getIdentifier(), $record);
    }
    public function revokeAccessToken(string $tokenId): void { $this->store->revoke('access_token', $tokenId); }
    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $record = $this->store->record('access_token', $tokenId);
        if (!$record || $record['revoked'] || $record['expires_at'] <= time()) return true;
        if (isset($record['exchange_subject'])) {
            $subject = $this->store->record('access_token', $record['exchange_subject']);
            if (!$subject || $subject['revoked'] || $subject['expires_at'] <= time() || isset($subject['exchange_subject']) ||
                (string) $subject['user_id'] !== (string) $record['user_id']) return true;
            $client = $this->store->client($subject['client_id']);
            if (!$client || empty($client['enabled'])) return true;
        }
        return false;
    }
}
