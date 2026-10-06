<?php
declare(strict_types=1);
namespace Light\OAuth2\Storage;
use Light\OAuth2\Contract\Store;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use PDO;
final class PdoStore implements Store
{
    public function __construct(private PDO $pdo)
    {
        if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) !== 'mysql') throw new \InvalidArgumentException('PdoStore requires MySQL/MariaDB');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    }
    public function client(string $id): ?array
    {
        $statement = $this->pdo->prepare('SELECT record FROM oauth_clients WHERE id = ?');
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
