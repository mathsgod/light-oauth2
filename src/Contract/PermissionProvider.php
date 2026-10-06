<?php
declare(strict_types=1);
namespace Light\OAuth2\Contract;
interface PermissionProvider
{
    /** Permissions explicitly exposed for OAuth delegation. @return list<string> */
    public function scopes(): array;
    public function can(string $userId, string $permission): bool;
}
