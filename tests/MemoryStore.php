<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;
use Light\OAuth2\Storage\ClientRegistration;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
final class MemoryStore implements \Light\OAuth2\Contract\ClientStore
{
    public array $clients = [];
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
    public function revoke(string $type, string $id): void { if (isset($this->records[$type][$id])) $this->records[$type][$id]['revoked'] = true; }
    public function transaction(callable $operation): mixed
    {
        $snapshot = $this->records;
        try { return $operation(); } catch (\Throwable $error) { $this->records = $snapshot; throw $error; }
    }
}
