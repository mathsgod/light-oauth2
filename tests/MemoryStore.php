<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;
use Light\OAuth2\Contract\Store;
use Light\OAuth2\Storage\ClientRegistration;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
final class MemoryStore implements Store
{
    public array $clients = [];
    public array $records = [];
    public function client(string $id): ?array { return $this->clients[$id] ?? null; }
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
