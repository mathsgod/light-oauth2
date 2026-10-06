<?php
declare(strict_types=1);
namespace Light\OAuth2\Repository;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Entities\{RefreshTokenEntityInterface, ClientEntityInterface};
use Light\OAuth2\Contract\Store;
use Light\OAuth2\Config;
use Light\OAuth2\Entity\RefreshToken;
final class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function __construct(private Store $store) {}
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface { return new RefreshToken(); }
    public function persistNewRefreshToken(RefreshTokenEntityInterface $token): void
    {
        $this->store->insert('refresh_token', $token->getIdentifier(), ['expires_at' => $token->getExpiryDateTime()->getTimestamp(), 'revoked' => false, 'access_token_id' => $token->getAccessToken()->getIdentifier()]);
    }
    public function revokeRefreshToken(string $tokenId): void { $this->store->revoke('refresh_token', $tokenId); }
    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $record = $this->store->record('refresh_token', $tokenId);
        return !$record || $record['revoked'] || $record['expires_at'] <= time();
    }
}
