<?php
declare(strict_types=1);
namespace Light\OAuth2\Auth;
use Light\OAuth2\Contract\PermissionProvider;
final class LightPermissionProvider implements PermissionProvider
{
    /** @param list<string> $delegatablePermissions */
    public function __construct(private \Light\App $app, private array $delegatablePermissions) {}
    public function scopes(): array { return $this->delegatablePermissions; }
    public function can(string $userId, string $permission): bool
    {
        if (!ctype_digit($userId) || !in_array($permission, $this->delegatablePermissions, true)) return false;
        $user = \Light\Model\User::Get((int) $userId);
        if (!$user || (int) $user->status !== 0) return false;
        return $this->app->getRbac()->getUser((int) $userId)?->can($permission) ?? false;
    }
}
