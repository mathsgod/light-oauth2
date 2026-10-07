<?php
declare(strict_types=1);
namespace Light\OAuth2\Contract;

interface RefreshTokenStore extends Store
{
    /** Called inside the exchange transaction, after locking the token. */
    public function consumeRefreshToken(string $id, string $familyId): void;
    /** Revoke every refresh token and its associated access token in this family. */
    public function revokeRefreshTokenFamily(string $familyId): void;
}
