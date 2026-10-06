<?php
declare(strict_types=1);
namespace Light\OAuth2\Contract;
final readonly class AuthorizationDecision
{
    public function __construct(public string $userId, public bool $approved, public bool $authenticationComplete)
    {
        if ($userId === '') throw new \InvalidArgumentException('User identifier required');
    }
}
