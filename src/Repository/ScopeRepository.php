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
    public function __construct(private PermissionProvider $permissions, private ?\Light\OAuth2\ResourceRegistry $registry = null, private ?\Light\OAuth2\ResourceSelection $resources = null) {}
    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return in_array($identifier, $this->allowedScopes(), true) ? new Scope($identifier) : null;
    }
    private function allowedScopes(): array
    {
        return $this->registry !== null && $this->resources !== null && $this->registry->enabled()
            ? $this->registry->scopes($this->resources->resource(), $this->permissions->scopes()) : $this->permissions->scopes();
    }
    public function finalizeScopes(array $scopes, string $grantType, ClientEntityInterface $clientEntity, ?string $userIdentifier = null, ?string $authCodeId = null): array
    {
        if ($this->registry !== null && $this->resources !== null && $this->registry->enabled() && $clientEntity instanceof Client) {
            $this->registry->assertClient($clientEntity->record, $this->resources->resource());
        }
        foreach ($scopes as $scope) {
            $id = $scope->getIdentifier();
            if (!$clientEntity instanceof Client || !in_array($id, $clientEntity->record['scopes'], true) ||
                !in_array($id, $this->allowedScopes(), true) || $userIdentifier === null || !$this->permissions->can($userIdentifier, $id)) {
                throw OAuthServerException::invalidScope($id);
            }
        }
        return $scopes;
    }
}
