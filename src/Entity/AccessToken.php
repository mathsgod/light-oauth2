<?php
declare(strict_types=1);
namespace Light\OAuth2\Entity;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\{EntityTrait, TokenEntityTrait, AccessTokenTrait};
use Light\OAuth2\Config;
use Lcobucci\JWT\Token;
final class AccessToken implements AccessTokenEntityInterface
{
    use EntityTrait, TokenEntityTrait, AccessTokenTrait;
    public function __construct(private readonly Config $config) {}
    private function convertToJWT(): Token
    {
        $this->initJwtConfiguration();
        $now = new \DateTimeImmutable();
        return $this->jwtConfiguration->builder()
            ->issuedBy($this->config->issuer)->permittedFor($this->config->resource)
            ->identifiedBy($this->getIdentifier())->issuedAt($now)->canOnlyBeUsedAfter($now)
            ->expiresAt($this->getExpiryDateTime())->relatedTo($this->getUserIdentifier() ?? $this->getClient()->getIdentifier())
            ->withClaim('client_id', $this->getClient()->getIdentifier())
            ->withClaim('scopes', $this->getScopes())
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());
    }
}
