<?php
declare(strict_types=1);
namespace Light\OAuth2;
final readonly class Config
{
    public function __construct(
        public string $issuer,
        public string $resource,
        public string $privateKey,
        public string $publicKey,
        public string $encryptionKey,
        public string $routePrefix = '/oauth',
        public string $accessTokenTtl = 'PT1H',
        public string $refreshTokenTtl = 'P30D',
        public string $codeTtl = 'PT5M',
        public ?string $apiResource = null,
        public bool $cimdEnabled = false,
        public bool $dcrEnabled = false,
        public bool $autoSelectScopes = false,
    ) {
        foreach ($apiResource === null ? [$issuer, $resource] : [$issuer, $resource, $apiResource] as $url) {
            $parts = parse_url($url);
            if (!$parts || empty($parts['host']) || isset($parts['fragment']) || isset($parts['query']) || isset($parts['user']) ||
                (($parts['scheme'] ?? '') !== 'https' && !(($parts['scheme'] ?? '') === 'http' && in_array($parts['host'], ['localhost', '127.0.0.1', '[::1]'], true)))) {
                throw new \InvalidArgumentException('Issuer and resources must be HTTPS URLs (HTTP loopback allowed)');
            }
        }
        if (strlen($encryptionKey) < 32) throw new \InvalidArgumentException('Encryption key must be at least 32 characters');
        if (!preg_match('~^/[a-zA-Z0-9/_-]+$~', $routePrefix)) throw new \InvalidArgumentException('Invalid OAuth route prefix');
        foreach ([$accessTokenTtl, $refreshTokenTtl, $codeTtl] as $ttl) {
            $interval = new \DateInterval($ttl);
            if ($interval->invert || (new \DateTimeImmutable())->add($interval) <= new \DateTimeImmutable()) throw new \InvalidArgumentException('TTL must be positive');
        }
    }
    public function endpoint(string $name): string { return rtrim($this->issuer, '/') . $this->routePrefix . '/' . $name; }
    /** Keep issuer/keys/settings while selecting the audience validated by a resource server. */
    public function forResource(string $resource): self
    {
        return new self($this->issuer, $resource, $this->privateKey, $this->publicKey, $this->encryptionKey, $this->routePrefix, $this->accessTokenTtl, $this->refreshTokenTtl, $this->codeTtl, $this->apiResource, $this->cimdEnabled, $this->dcrEnabled, $this->autoSelectScopes);
    }
}
