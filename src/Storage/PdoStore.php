<?php
declare(strict_types=1);
namespace Light\OAuth2\Storage;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use PDO;
final class PdoStore implements \Light\OAuth2\Contract\ClientStore
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
