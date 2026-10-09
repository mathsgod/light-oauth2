<?php
declare(strict_types=1);
namespace Light\OAuth2\Auth;
use Light\OAuth2\Contract\PermissionProvider;
final class LightPermissionProvider implements PermissionProvider
{
    /** @param list<string>|null $delegatablePermissions Optional restriction on registered permissions. */
    public function __construct(private \Light\App $app, private ?array $delegatablePermissions = null) {}
    public function scopes(): array
    {
        $registered = array_values(array_unique(array_filter(
            $this->app->getPermissions(),
            static fn(string $permission): bool => $permission !== '' && !str_contains($permission, '*') && preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/D', $permission) === 1,
        )));
        $scopes = $this->delegatablePermissions === null ? $registered : array_values(array_intersect($registered, $this->delegatablePermissions));
        sort($scopes);
        return $scopes;
    }
    public function can(string $userId, string $permission): bool
    {
        if (!ctype_digit($userId) || !in_array($permission, $this->scopes(), true)) return false;
        $user = \Light\Model\User::Get((int) $userId);
        if (!$user || (int) $user->status !== 0) return false;
        return $this->app->getRbac()->getUser($userId)?->can($permission) ?? false;
    }
}
