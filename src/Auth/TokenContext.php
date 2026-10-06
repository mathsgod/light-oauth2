<?php
declare(strict_types=1);
namespace Light\OAuth2\Auth;
use Light\OAuth2\Contract\PermissionProvider;
final readonly class TokenContext
{
    public function __construct(public string $userId, public string $clientId, public string $tokenId, public array $scopes) {}
    public function can(string $permission, PermissionProvider $permissions): bool
    {
        return in_array($permission, $this->scopes, true) && in_array($permission, $permissions->scopes(), true) && $permissions->can($this->userId, $permission);
    }
}
