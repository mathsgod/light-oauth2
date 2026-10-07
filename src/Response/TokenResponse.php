<?php
declare(strict_types=1);
namespace Light\OAuth2\Response;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use Light\OAuth2\Entity\AccessToken;
use Light\OAuth2\Grant\TokenExchangeGrant;

final class TokenResponse extends BearerTokenResponse
{
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        if (!$accessToken instanceof AccessToken || $accessToken->exchangeSubject() === null) return [];
        return [
            'issued_token_type' => TokenExchangeGrant::ACCESS_TOKEN_TYPE,
            'scope' => implode(' ', array_map(static fn($scope): string => $scope->getIdentifier(), $accessToken->getScopes())),
        ];
    }
}
