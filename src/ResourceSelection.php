<?php
declare(strict_types=1);
namespace Light\OAuth2;
use League\OAuth2\Server\Exception\OAuthServerException;

/** Request-local audience shared by the grant repositories. Never inferred from unverified JWTs. */
final class ResourceSelection
{
    private ?string $requested = null;
    private ?string $selected = null;
    public function __construct(private readonly Config $config, private ?ResourceRegistry $registry = null) {}
    public function reset(): void { $this->requested = $this->selected = null; }
    public function begin(array $params, string $encoded = ''): void
    {
        $this->reset();
        $count = 0;
        foreach (explode('&', $encoded) as $pair) {
            if (urldecode(explode('=', $pair, 2)[0]) === 'resource' && ++$count > 1) {
                throw OAuthServerException::invalidRequest('resource', 'Select exactly one resource per authorization');
            }
        }
        if (!array_key_exists('resource', $params)) return;
        if (!is_string($params['resource']) || !$this->supported($params['resource'])) {
            throw OAuthServerException::invalidRequest('resource', 'Unsupported resource');
        }
        $this->requested = $params['resource'];
    }
    private function supported(string $resource): bool
    {
        if ($this->registry === null) return in_array($resource, $this->config->resources(), true);
        $this->registry->assertResource($resource);
        return true;
    }
    public function resource(): string { return $this->selected ?? $this->requested ?? $this->config->resource; }
    public function bind(?string $resource): void
    {
        // Records issued before audience binding used the original default resource.
        $resource ??= $this->config->resource;
        if (!$this->supported($resource) || ($this->requested !== null && $this->requested !== $resource)) {
            throw OAuthServerException::invalidRequest('resource', 'Resource differs from the original authorization');
        }
        $this->selected = $resource;
    }
}
