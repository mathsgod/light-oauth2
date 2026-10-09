<?php
declare(strict_types=1);
namespace Light\OAuth2\Management;
use Light\OAuth2\Contract\{ClientStore, PermissionProvider};
use Light\OAuth2\Input\OAuthClientInput;
use Light\OAuth2\Type\{OAuthClient, OAuthClientSaved};

final class ClientManager
{
    public function __construct(private ClientStore $store, private PermissionProvider $permissions, private ?\Light\OAuth2\ResourceRegistry $registry = null) {}

    /** @return OAuthClient[] */
    public function clients(): array
    {
        return array_map(fn(array $record) => new OAuthClient($record), $this->store->clients());
    }

    /** @return string[] */
    public function scopes(): array { return $this->permissions->scopes(); }

    public function save(OAuthClientInput $input, bool $create): OAuthClientSaved
    {
        $existing = $this->store->client($input->id);
        if ($create && $existing !== null) throw new \InvalidArgumentException('Client ID already exists');
        if (!$create && $existing === null) throw new \InvalidArgumentException('OAuth client not found');
        if (array_diff($input->scopes, $this->scopes())) throw new \InvalidArgumentException('Scope is not exposed by this OAuth provider');
        $secret = $input->confidential && !($existing['confidential'] ?? false) ? bin2hex(random_bytes(32)) : null;
        $record = [
            'id' => $input->id, 'name' => $input->name,
            'redirect_uris' => array_values(array_unique($input->redirectUris)),
            'scopes' => array_values(array_unique($input->scopes)),
            'confidential' => $input->confidential, 'enabled' => $input->enabled,
        ];
        $resources = $input->resources ?? $existing['resources'] ?? null;
        if ($this->registry?->enabled()) {
            $record['resources'] = $this->registry->clientResources($resources);
            if (array_diff($record['scopes'], $this->registry->registrationScopes($record['resources'], $this->scopes()))) throw new \InvalidArgumentException('Scope is not allowed by the selected resources');
        } elseif ($resources !== null) {
            $record['resources'] = $resources;
        }
        if ($input->confidential) $record['secret_hash'] = $secret !== null ? password_hash($secret, PASSWORD_DEFAULT) : $existing['secret_hash'];
        if ($create) $this->store->createClient($record);
        else $this->store->saveClient($record);
        return new OAuthClientSaved(new OAuthClient($record), $secret);
    }

    public function resetSecret(string $id): string
    {
        $record = $this->store->client($id);
        if (!$record || !$record['confidential']) throw new \InvalidArgumentException('Secret reset requires a confidential client');
        $secret = bin2hex(random_bytes(32));
        $record['secret_hash'] = password_hash($secret, PASSWORD_DEFAULT);
        $this->store->saveClient($record);
        return $secret;
    }

    public function delete(string $id): bool { return $this->store->deleteClient($id); }
}
