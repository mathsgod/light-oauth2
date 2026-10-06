<?php
declare(strict_types=1);
namespace Light\OAuth2\Auth;
use Light\OAuth2\Contract\PermissionProvider;
use Psr\Http\Message\ServerRequestInterface;
use Light\Model\User;
final class OAuthService extends \Light\Auth\Service
{
    public function __construct(ServerRequestInterface $request, private ?TokenContext $context, private PermissionProvider $permissions, callable $loadUser)
    {
        // OAuth credentials are verified by League, not Light's native TokenManager.
        $this->app = $request->getAttribute(\Light\App::class);
        $this->user = $context ? $loadUser($context->userId) : null;
        if ($this->user !== null && !$this->user instanceof User) throw new \UnexpectedValueException('User loader must return Light\\Model\\User or null');
        $this->is_logged = $this->user !== null;
        $this->jti = $context?->tokenId;
    }
    public function isAllowed(string $right, mixed $subject = null): bool
    {
        return $this->is_logged && ($this->context?->can($right, $this->permissions) ?? false);
    }
}
