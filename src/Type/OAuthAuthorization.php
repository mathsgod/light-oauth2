<?php
declare(strict_types=1);
namespace Light\OAuth2\Type;
use TheCodingMachine\GraphQLite\Annotations\{Type, Field};

#[Type]
final class OAuthAuthorization
{
    #[Field]
    public string $clientId;
    #[Field]
    public string $clientName;
    /** @var string[] */
    #[Field]
    public array $scopes = [];
    #[Field]
    public bool $enabled;
    #[Field]
    public int $accessTokens = 0;
    #[Field]
    public int $refreshTokens = 0;
    #[Field]
    public int $authorizationCodes = 0;
    #[Field]
    public int $expiresAt = 0;

    public function __construct(string $clientId, ?array $client)
    {
        $this->clientId = $clientId;
        $this->clientName = $client['name'] ?? $clientId;
        $this->enabled = $client['enabled'] ?? false;
    }
}
