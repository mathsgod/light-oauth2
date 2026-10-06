<?php
declare(strict_types=1);
namespace Light\OAuth2\Repository;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Entities\{ScopeEntityInterface, ClientEntityInterface};
use League\OAuth2\Server\Exception\OAuthServerException;
use Light\OAuth2\Contract\PermissionProvider;
use Light\OAuth2\Entity\{Scope, Client};
final class ScopeRepository implements ScopeRepositoryInterface
{
    public function __construct(private PermissionProvider $permissions) {}
    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return in_array($identifier, $this->permissions->scopes(), true) ? new Scope($identifier) : null;
    }
    public function finalizeScopes(array $scopes, string $grantType, ClientEntityInterface $clientEntity, ?string $userIdentifier = null, ?string $authCodeId = null): array
    {
        foreach ($scopes as $scope) {
            $id = $scope->getIdentifier();
            if (!$clientEntity instanceof Client || !in_array($id, $clientEntity->record['scopes'], true) ||
                !in_array($id, $this->permissions->scopes(), true) || $userIdentifier === null || !$this->permissions->can($userIdentifier, $id)) {
                throw OAuthServerException::invalidScope($id);
            }
        }
        return $scopes;
    }
}
