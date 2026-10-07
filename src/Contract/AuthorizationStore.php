<?php
declare(strict_types=1);
namespace Light\OAuth2\Contract;

interface AuthorizationStore extends Store
{
    /** @return list<array{type: string, id: string, record: array}> */
    public function userCredentials(string $userId): array;
    public function revokeUserAuthorization(string $userId, string $clientId): bool;
}
