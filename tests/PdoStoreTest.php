<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;
use PHPUnit\Framework\TestCase;
use Light\OAuth2\Storage\PdoStore;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
final class PdoStoreTest extends TestCase
{
    public function testMysqlPersistenceRevocationRollbackAndDuplicate(): void
    {
        if (!getenv('OAUTH_TEST_DSN')) self::markTestSkipped('Set OAUTH_TEST_DSN, OAUTH_TEST_USER, OAUTH_TEST_PASSWORD for MySQL');
        $pdo = new \PDO(getenv('OAUTH_TEST_DSN'), getenv('OAUTH_TEST_USER') ?: '', getenv('OAUTH_TEST_PASSWORD') ?: '');
        // Connection-local temporary tables shadow persistent names. No application tables are modified.
        $sql = file_get_contents(dirname(__DIR__) . '/migrations/001_oauth.sql');
        $sql = preg_replace('/^--.*$/m', '', $sql);
        foreach (explode(';', str_replace('CREATE TABLE IF NOT EXISTS', 'CREATE TEMPORARY TABLE', $sql)) as $statement) {
            if (trim($statement) !== '') $pdo->exec($statement);
        }
        $store = new PdoStore($pdo);
        $client = ['id' => 'test', 'name' => 'Test', 'redirect_uris' => ['https://example.com/callback'], 'confidential' => false, 'enabled' => true, 'scopes' => ['client.list']];
        $store->saveClient($client);
        self::assertSame($client, $store->client('test'));
        $client['enabled'] = false; $store->saveClient($client);
        self::assertFalse($store->client('test')['enabled']);
        $record = ['expires_at' => time() + 60, 'revoked' => false];
        $store->transaction(fn() => $store->insert('auth_code', 'one', $record));
        self::assertSame($record, $store->record('auth_code', 'one'));
        try {
            $store->transaction(function () use ($store) { $store->revoke('auth_code', 'one'); throw new \RuntimeException('rollback'); });
        } catch (\RuntimeException) {}
        self::assertFalse($store->record('auth_code', 'one')['revoked']);
        $store->transaction(function () use ($store) { self::assertFalse($store->record('auth_code', 'one')['revoked']); $store->revoke('auth_code', 'one'); });
        self::assertTrue($store->record('auth_code', 'one')['revoked']);
        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);
        $store->insert('auth_code', 'one', $record);
    }
}
