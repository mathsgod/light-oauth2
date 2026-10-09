<?php
declare(strict_types=1);
namespace Light\OAuth2\Management;
use Light\OAuth2\Contract\{ResourceStore, PermissionProvider};
use Light\OAuth2\Input\OAuthResourceInput;
use Light\OAuth2\Type\OAuthResource;
use Light\OAuth2\Storage\ResourceRegistration;
final class ResourceManager
{
    public function __construct(private ResourceStore $store, private PermissionProvider $permissions) {}
    /** @return OAuthResource[] */
    public function resources(): array { return array_map(fn(array $record) => new OAuthResource($record), $this->store->resources()); }
    /** @return string[] */
    public function scopes(): array { return $this->permissions->scopes(); }
    public function save(OAuthResourceInput $input, bool $create): OAuthResource
    {
        $record = ['id' => $input->id, 'name' => $input->name, 'scopes' => array_values(array_unique($input->scopes)), 'enabled' => $input->enabled];
        ResourceRegistration::validate($record);
        if (array_diff($record['scopes'], $this->scopes())) throw new \InvalidArgumentException('Scope is not exposed by this OAuth provider');
        return $this->store->transaction(function () use ($record, $create): OAuthResource {
            $existing = $this->store->resource($record['id']);
            if ($create && $existing !== null) throw new \InvalidArgumentException('Resource already exists');
            if (!$create && $existing === null) throw new \InvalidArgumentException('Resource not found; resource URLs cannot be renamed');
            if ($create) $this->store->createResource($record);
            else $this->store->saveResource($record);
            return new OAuthResource($record);
        });
    }
    public function delete(string $id): bool { return $this->store->deleteResource($id); }
}
