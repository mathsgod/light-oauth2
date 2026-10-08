<?php
declare(strict_types=1);
namespace Light\OAuth2;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Light\OAuth2\Contract\PermissionProvider;
use Light\OAuth2\Entity\{Client, Scope};

/** Request-local helper for flows that select scopes after authentication. */
final class AutomaticScopes
{
    private ?string $userId = null;
    private array $selected = [];

    public function __construct(private PermissionProvider $permissions) {}

    public function select(AuthorizationRequest $authorization, string $userId): void
    {
        $client = $authorization->getClient();
        $ids = $client instanceof Client ? array_values(array_filter(
            array_intersect($this->permissions->scopes(), $client->record['scopes']),
            fn(string $scope): bool => $this->permissions->can($userId, $scope),
        )) : [];
        if ($ids === []) throw OAuthServerException::invalidScope('');
        $authorization->setScopes(array_map(fn(string $id): Scope => new Scope($id), $ids));
        $this->selected = $ids;
        $this->userId = $userId;
    }

    public function assertSelected(AuthorizationRequest $authorization, string $userId): void
    {
        $ids = array_map(fn($scope): string => $scope->getIdentifier(), $authorization->getScopes());
        if ($this->userId !== $userId || $ids !== $this->selected || $ids === []) {
            throw OAuthServerException::accessDenied('The authorization flow must select automatic scopes before consent');
        }
    }
}
