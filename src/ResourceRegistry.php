<?php
declare(strict_types=1);
namespace Light\OAuth2;
use Light\OAuth2\Contract\{Store, ResourceStore};
use League\OAuth2\Server\Exception\OAuthServerException;

/** Trusted resource policy. DB mode never falls back to the environment allowlist. */
final class ResourceRegistry
{
    public function __construct(private Config $config, private Store $store)
    {
        if ($config->resourceRegistryEnabled && !$store instanceof ResourceStore) {
            throw new \LogicException('Resource registry requires a ResourceStore');
        }
    }
    public function clientPolicy(): Type\OAuthClientResourcePolicy
    {
        return new Type\OAuthClientResourcePolicy($this->enabled(), $this->config->resource, $this->enabled() ? $this->store->resources() : []);
    }
    public function enabled(): bool { return $this->config->resourceRegistryEnabled; }
    public function record(string $id): ?array
    {
        if (!$this->enabled()) return in_array($id, $this->config->resources(), true) ? ['id' => $id, 'enabled' => true] : null;
        return $this->store->resource($id);
    }
    public function assertResource(string $id): void
    {
        $record = $this->record($id);
        if (!$record || empty($record['enabled'])) throw OAuthServerException::invalidRequest('resource', 'Unknown or disabled resource');
    }
    public function scopes(string $id, array $providerScopes): array
    {
        $record = $this->record($id);
        if (!$record || empty($record['enabled'])) throw OAuthServerException::invalidRequest('resource', 'Unknown or disabled resource');
        if (!$this->enabled()) return $providerScopes;
        return array_values(array_intersect($providerScopes, $record['scopes']));
    }
    /** Validate a client-declared association; omission grants only the default resource. */
    public function clientResources(mixed $resources): array
    {
        $resources ??= [$this->config->resource];
        if (!is_array($resources) || !array_is_list($resources) || !$resources || count($resources) > 20) {
            throw new \InvalidArgumentException('Provide between 1 and 20 registered resources');
        }
        foreach ($resources as $id) {
            if (!is_string($id)) throw new \InvalidArgumentException('Resource IDs must be strings');
            try { $this->assertResource($id); }
            catch (OAuthServerException $error) { throw new \InvalidArgumentException('Unknown or disabled resource', 0, $error); }
        }
        return array_values(array_unique($resources));
    }
    public function assertClient(array $client, string $resource): void
    {
        $this->assertResource($resource);
        if ($this->enabled() && !in_array($resource, $client['resources'] ?? [$this->config->resource], true)) {
            throw OAuthServerException::invalidRequest('resource', 'Resource is not registered for this client');
        }
    }
    public function registrationScopes(array $resources, array $providerScopes): array
    {
        $allowed = [];
        foreach ($resources as $id) $allowed = [...$allowed, ...$this->scopes($id, $providerScopes)];
        return array_values(array_unique($allowed));
    }
}
