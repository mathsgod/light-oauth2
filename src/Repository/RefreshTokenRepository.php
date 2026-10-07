<?php
declare(strict_types=1);
namespace Light\OAuth2\Repository;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Entities\{RefreshTokenEntityInterface, ClientEntityInterface};
use Light\OAuth2\Contract\RefreshTokenStore;
use Light\OAuth2\Exception\RefreshTokenReuse;
use Light\OAuth2\Config;
use Light\OAuth2\Entity\RefreshToken;
final class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    private ?string $familyId = null;
    public function __construct(private RefreshTokenStore $store) {}
    public function reset(): void { $this->familyId = null; }
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface { return new RefreshToken(); }
    public function persistNewRefreshToken(RefreshTokenEntityInterface $token): void
    {
        $this->store->insert('refresh_token', $token->getIdentifier(), ['expires_at' => $token->getExpiryDateTime()->getTimestamp(), 'revoked' => false, 'access_token_id' => $token->getAccessToken()->getIdentifier(), 'family_id' => $this->familyId ?? $token->getIdentifier(), 'used_at' => null]);
    }
    public function revokeRefreshToken(string $tokenId): void
    {
        $record = $this->store->record('refresh_token', $tokenId);
        if (!$record) throw new \LogicException('Refresh token disappeared during exchange');
        $this->familyId = $record['family_id'] ?? $tokenId;
        $this->store->consumeRefreshToken($tokenId, $this->familyId);
    }
    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $record = $this->store->record('refresh_token', $tokenId);
        // League has already authenticated the client, decrypted the token,
        // checked client binding and rejected expiry before reaching here.
        if ($record && $record['expires_at'] > time() && ($record['used_at'] ?? null) !== null) {
            $this->store->revokeRefreshTokenFamily($record['family_id'] ?? $tokenId);
            throw new RefreshTokenReuse('Refresh token was already used');
        }
        return !$record || $record['revoked'] || $record['expires_at'] <= time();
    }
}
