<?php
declare(strict_types=1);
namespace Light\OAuth2\Controller;
use Light\Model\User;
use Light\OAuth2\Management\AuthorizationManager;
use Light\OAuth2\Type\OAuthAuthorization;
use TheCodingMachine\GraphQLite\Annotations\{Query, Mutation, Logged, InjectUser};

final class OAuthAuthorizationController implements \Light\GraphQL\ExplicitController
{
    public function __construct(private AuthorizationManager $manager) {}

    /** @return OAuthAuthorization[] */
    #[Query, Logged]
    public function myOAuthAuthorizations(#[InjectUser] User $user): array
    {
        return $this->manager->authorizations((string) $user->user_id);
    }

    #[Mutation, Logged]
    public function revokeMyOAuthAuthorization(string $clientId, #[InjectUser] User $user): bool
    {
        return $this->manager->revoke((string) $user->user_id, $clientId);
    }
}
