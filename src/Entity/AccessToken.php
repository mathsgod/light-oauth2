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
    private ?string $targetResource = null;
    private ?string $subjectTokenId = null;
    public function __construct(private readonly Config $config) {}
    public function setExchangeTarget(string $resource, string $subjectTokenId): void
    {
        $this->targetResource = $resource;
        $this->subjectTokenId = $subjectTokenId;
    }
    public function resource(): string { return $this->targetResource ?? $this->config->resource; }
    public function exchangeSubject(): ?string { return $this->subjectTokenId; }
    private function convertToJWT(): Token
    {
        $this->initJwtConfiguration();
        $now = new \DateTimeImmutable();
        return $this->jwtConfiguration->builder()
            ->issuedBy($this->config->issuer)->permittedFor($this->resource())
            ->identifiedBy($this->getIdentifier())->issuedAt($now)->canOnlyBeUsedAfter($now)
            ->expiresAt($this->getExpiryDateTime())->relatedTo($this->getUserIdentifier() ?? $this->getClient()->getIdentifier())
            ->withClaim('client_id', $this->getClient()->getIdentifier())
            ->withClaim('scopes', $this->getScopes())
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());
    }
}
