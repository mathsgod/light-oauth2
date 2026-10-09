<?php
declare(strict_types=1);
namespace Light\OAuth2\Repository;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Entities\{AuthCodeEntityInterface, ClientEntityInterface};
use Light\OAuth2\Contract\Store;
use Light\OAuth2\Config;
use Light\OAuth2\Entity\AuthCode;
final class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function __construct(private Store $store, private ?\Light\OAuth2\ResourceSelection $resources = null) {}
    public function getNewAuthCode(): AuthCodeEntityInterface { return new AuthCode(); }
    public function persistNewAuthCode(AuthCodeEntityInterface $token): void
    {
        $this->store->insert('auth_code', $token->getIdentifier(), ['resource' => $this->resources?->resource(), 'expires_at' => $token->getExpiryDateTime()->getTimestamp(), 'revoked' => false, 'user_id' => $token->getUserIdentifier(), 'client_id' => $token->getClient()->getIdentifier(), 'scopes' => array_map(fn($s) => $s->getIdentifier(), $token->getScopes())]);
    }
    public function revokeAuthCode(string $tokenId): void { $this->store->revoke('auth_code', $tokenId); }
    public function isAuthCodeRevoked(string $tokenId): bool
    {
        $record = $this->store->record('auth_code', $tokenId);
        if (!$record || $record['revoked'] || $record['expires_at'] <= time()) return true;
        $this->resources?->bind($record['resource'] ?? null);
        return false;
    }
}
