<?php
declare(strict_types=1);
namespace Light\OAuth2;
use Light\OAuth2\Contract\{Store, ResourceStore};
use League\OAuth2\Server\Exception\OAuthServerException;

/** Trusted resource and scope policy, managed exclusively in the database. */
final class ResourceRegistry
{
    public function __construct(private Config $config, private Store $store)
    {
        if (!$store instanceof ResourceStore) {
            throw new \LogicException('Resource registry requires a ResourceStore');
        }
    }
    public function clientPolicy(): Type\OAuthClientResourcePolicy
    {
        return new Type\OAuthClientResourcePolicy($this->config->resource, $this->store->resources());
    }
    public function record(string $id): ?array
    {
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
        if (!in_array($resource, $client['resources'] ?? [$this->config->resource], true)) {
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
