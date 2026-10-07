<?php
declare(strict_types=1);
namespace Light\OAuth2\Storage;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use PDO;
final class PdoStore implements \Light\OAuth2\Contract\ClientStore, \Light\OAuth2\Contract\AuthorizationStore
{
    public function __construct(private PDO $pdo)
    {
        if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) !== 'mysql') throw new \InvalidArgumentException('PdoStore requires MySQL/MariaDB');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    }
    public function clients(): array
    {
        $rows = $this->pdo->query('SELECT record FROM oauth_clients ORDER BY id')->fetchAll(PDO::FETCH_COLUMN);
        return array_map(fn(string $record): array => json_decode($record, true, 512, JSON_THROW_ON_ERROR), $rows);
    }
    public function createClient(array $client): void
    {
        ClientRegistration::validate($client);
        try {
            $statement = $this->pdo->prepare('INSERT INTO oauth_clients (id, record) VALUES (?, ?)');
            $statement->execute([$client['id'], json_encode($client, JSON_THROW_ON_ERROR)]);
        } catch (\PDOException $error) {
            if (($error->errorInfo[1] ?? null) === 1062) throw new \InvalidArgumentException('Client ID already exists');
            throw $error;
        }
    }
    public function client(string $id): ?array
    {
        $lock = $this->pdo->inTransaction() ? ' FOR UPDATE' : '';
        $statement = $this->pdo->prepare('SELECT record FROM oauth_clients WHERE id = ?' . $lock);
        $statement->execute([$id]);
        $value = $statement->fetchColumn();
        return $value === false ? null : json_decode($value, true, 512, JSON_THROW_ON_ERROR);
    }
    public function saveClient(array $client): void
    {
        ClientRegistration::validate($client);
        $statement = $this->pdo->prepare('INSERT INTO oauth_clients (id, record) VALUES (?, ?) ON DUPLICATE KEY UPDATE record = VALUES(record)');
        $statement->execute([$client['id'], json_encode($client, JSON_THROW_ON_ERROR)]);
    }
    public function deleteClient(string $id): bool
    {
        return $this->transaction(function () use ($id): bool {
            if ($this->client($id) === null) return false;
            // Refresh records reference access-token IDs rather than client IDs.
            $access = $this->pdo->prepare("SELECT id FROM oauth_credentials WHERE type = 'access_token' AND JSON_UNQUOTE(JSON_EXTRACT(record, '$.client_id')) = ? FOR UPDATE");
            $access->execute([$id]);
            $refresh = $this->pdo->prepare("UPDATE oauth_credentials SET revoked = 1 WHERE type = 'refresh_token' AND JSON_UNQUOTE(JSON_EXTRACT(record, '$.access_token_id')) = ?");
            foreach ($access->fetchAll(PDO::FETCH_COLUMN) as $tokenId) $refresh->execute([$tokenId]);
            $credentials = $this->pdo->prepare("UPDATE oauth_credentials SET revoked = 1 WHERE JSON_UNQUOTE(JSON_EXTRACT(record, '$.client_id')) = ?");
            $credentials->execute([$id]);
            $client = $this->pdo->prepare('DELETE FROM oauth_clients WHERE id = ?');
            $client->execute([$id]);
            return true;
        });
    }
    public function insert(string $type, string $id, array $record): void
    {
        try {
            $statement = $this->pdo->prepare('INSERT INTO oauth_credentials (type, id, record, revoked, expires_at) VALUES (?, ?, ?, 0, ?)');
            $statement->execute([$type, $id, json_encode($record, JSON_THROW_ON_ERROR), $record['expires_at']]);
        } catch (\PDOException $error) {
            if (($error->errorInfo[1] ?? null) === 1062) throw UniqueTokenIdentifierConstraintViolationException::create();
            throw $error;
        }
    }
    public function userCredentials(string $userId): array
    {
        return $this->credentialsForUser($userId);
    }
    private function credentialsForUser(string $userId, ?string $clientId = null): array
    {
        $lock = $this->pdo->inTransaction() ? ' FOR UPDATE' : '';
        $sql = "SELECT type, id, record, revoked FROM oauth_credentials WHERE type IN ('access_token', 'auth_code') AND JSON_UNQUOTE(JSON_EXTRACT(record, '$.user_id')) = ?";
        $args = [$userId];
        if ($clientId !== null) {
            $sql .= " AND JSON_UNQUOTE(JSON_EXTRACT(record, '$.client_id')) = ?";
            $args[] = $clientId;
        }
        $statement = $this->pdo->prepare($sql . $lock);
        $statement->execute($args);
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        $accessIds = array_column(array_filter($rows, fn(array $row): bool => $row['type'] === 'access_token'), 'id');
        foreach (array_chunk($accessIds, 500) as $chunk) {
            $placeholders = implode(',', array_fill(0, count($chunk), '?'));
            $statement = $this->pdo->prepare("SELECT type, id, record, revoked FROM oauth_credentials WHERE type = 'refresh_token' AND JSON_UNQUOTE(JSON_EXTRACT(record, '$.access_token_id')) IN ({$placeholders})" . $lock);
            $statement->execute($chunk);
            $rows = [...$rows, ...$statement->fetchAll(PDO::FETCH_ASSOC)];
        }
        return array_map(static function (array $row): array {
            $record = json_decode($row['record'], true, 512, JSON_THROW_ON_ERROR);
            $record['revoked'] = (bool) $row['revoked'];
            return ['type' => $row['type'], 'id' => $row['id'], 'record' => $record];
        }, $rows);
    }
    public function revokeUserAuthorization(string $userId, string $clientId): bool
    {
        return $this->transaction(function () use ($userId, $clientId): bool {
            // Serialize with exchanges for this client before locking credentials.
            $this->client($clientId);
            $credentials = $this->credentialsForUser($userId, $clientId);
            foreach ($credentials as $credential) $this->revoke($credential['type'], $credential['id']);
            return $credentials !== [];
        });
    }
    public function record(string $type, string $id): ?array
    {
        $lock = $this->pdo->inTransaction() ? ' FOR UPDATE' : '';
        $statement = $this->pdo->prepare('SELECT record, revoked FROM oauth_credentials WHERE type = ? AND id = ?' . $lock);
        $statement->execute([$type, $id]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!$row) return null;
        $record = json_decode($row['record'], true, 512, JSON_THROW_ON_ERROR);
        $record['revoked'] = (bool) $row['revoked'];
        return $record;
    }
    public function revoke(string $type, string $id): void
    {
        $statement = $this->pdo->prepare('UPDATE oauth_credentials SET revoked = 1 WHERE type = ? AND id = ?');
        $statement->execute([$type, $id]);
    }
    public function transaction(callable $operation): mixed
    {
        if ($this->pdo->inTransaction()) throw new \LogicException('Use a dedicated PDO connection for OAuth exchanges');
        $this->pdo->beginTransaction();
        try { $result = $operation(); $this->pdo->commit(); return $result; }
        catch (\Throwable $error) { $this->pdo->rollBack(); throw $error; }
    }
}
