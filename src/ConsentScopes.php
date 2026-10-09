<?php
declare(strict_types=1);
namespace Light\OAuth2;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

/** Restrict an authorization to the user's selection from the offered scopes. */
final class ConsentScopes
{
    public static function apply(AuthorizationRequest $authorization, mixed $selected): void
    {
        if (!is_array($selected) || !array_is_list($selected)) throw OAuthServerException::invalidScope('');
        $offered = $authorization->getScopes();
        $ids = array_map(fn($scope): string => $scope->getIdentifier(), $offered);
        foreach ($selected as $id) {
            if (!is_string($id) || !in_array($id, $ids, true)) throw OAuthServerException::invalidScope(is_string($id) ? $id : '');
        }
        if ($ids !== [] && $selected === []) throw OAuthServerException::invalidScope('');
        $authorization->setScopes(array_values(array_filter($offered, fn($scope): bool => in_array($scope->getIdentifier(), $selected, true))));
    }
}
