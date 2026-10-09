<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;
use Light\OAuth2\Storage\ClientRegistration;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
final class MemoryStore implements \Light\OAuth2\Contract\ResourceStore, \Light\OAuth2\Contract\ClientStore, \Light\OAuth2\Contract\AuthorizationStore, \Light\OAuth2\Contract\RefreshTokenStore
{
    public array $clients = [];
    public array $resourceRecords = [];
    public function resources(): array { return array_values($this->resourceRecords); }
    public function resource(string $id): ?array { return $this->resourceRecords[$id] ?? null; }
    public function createResource(array $resource): void
    {
        if (isset($this->resourceRecords[$resource['id']])) throw new \InvalidArgumentException('Resource already exists');
        $this->saveResource($resource);
    }
    public function saveResource(array $resource): void
    {
        \Light\OAuth2\Storage\ResourceRegistration::validate($resource);
        $this->resourceRecords[$resource['id']] = $resource;
    }
    public function deleteResource(string $id): bool
    {
        $exists = isset($this->resourceRecords[$id]);
        unset($this->resourceRecords[$id]);
        return $exists;
    }
    public array $records = [];
    public function clients(): array { return array_values($this->clients); }
    public function createClient(array $client): void
    {
        if (isset($this->clients[$client['id']])) throw new \InvalidArgumentException('Client ID already exists');
        $this->saveClient($client);
    }
    public function client(string $id): ?array { return $this->clients[$id] ?? null; }
    public function deleteClient(string $id): bool
    {
        if (!isset($this->clients[$id])) return false;
        $accessIds = [];
        foreach ($this->records['access_token'] ?? [] as $tokenId => $record) {
            if (($record['client_id'] ?? null) === $id) $accessIds[] = $tokenId;
        }
        foreach ($this->records as $type => $records) {
            foreach ($records as $tokenId => $record) {
                if (($record['client_id'] ?? null) === $id || ($type === 'refresh_token' && in_array($record['access_token_id'] ?? null, $accessIds, true))) $this->revoke($type, $tokenId);
            }
        }
        unset($this->clients[$id]);
        return true;
    }
    public function saveClient(array $client): void { ClientRegistration::validate($client); $this->clients[$client['id']] = $client; }
    public function insert(string $type, string $id, array $record): void
    {
        if (isset($this->records[$type][$id])) throw UniqueTokenIdentifierConstraintViolationException::create();
        $this->records[$type][$id] = $record;
    }
    public function record(string $type, string $id): ?array { return $this->records[$type][$id] ?? null; }
    public function userCredentials(string $userId): array
    {
        $result = [];
        $accessIds = [];
        foreach (['access_token', 'auth_code'] as $type) {
            foreach ($this->records[$type] ?? [] as $id => $record) {
                if ((string) ($record['user_id'] ?? '') !== $userId) continue;
                $result[] = ['type' => $type, 'id' => $id, 'record' => $record];
                if ($type === 'access_token') $accessIds[] = $id;
            }
        }
        foreach ($this->records['refresh_token'] ?? [] as $id => $record) {
            if (in_array($record['access_token_id'], $accessIds, true)) $result[] = ['type' => 'refresh_token', 'id' => $id, 'record' => $record];
        }
        return $result;
    }
    public function revokeUserAuthorization(string $userId, string $clientId): bool
    {
        $credentials = $this->userCredentials($userId);
        $access = [];
        foreach ($credentials as $credential) {
            if ($credential['type'] === 'access_token') $access[$credential['id']] = $credential['record'];
        }
        $found = false;
        foreach ($credentials as $credential) {
            $record = $credential['record'];
            $source = $credential['type'] === 'refresh_token' ? $access[$record['access_token_id']] : $record;
            if (($source['client_id'] ?? null) !== $clientId) continue;
            $this->revoke($credential['type'], $credential['id']);
            $found = true;
        }
        return $found;
    }
    public function revoke(string $type, string $id): void { if (isset($this->records[$type][$id])) $this->records[$type][$id]['revoked'] = true; }
    public function consumeRefreshToken(string $id, string $familyId): void
    {
        $this->records['refresh_token'][$id]['family_id'] = $familyId;
        $this->records['refresh_token'][$id]['used_at'] = time();
        $this->revoke('refresh_token', $id);
    }
    public function revokeRefreshTokenFamily(string $familyId): void
    {
        foreach ($this->records['refresh_token'] ?? [] as $id => $record) {
            if (($record['family_id'] ?? null) !== $familyId) continue;
            $this->revoke('refresh_token', $id);
            $this->revoke('access_token', $record['access_token_id']);
        }
    }
    public function transaction(callable $operation): mixed
    {
        $snapshot = [$this->records, $this->clients, $this->resourceRecords];
        try { return $operation(); } catch (\Throwable $error) { [$this->records, $this->clients, $this->resourceRecords] = $snapshot; throw $error; }
    }
}
