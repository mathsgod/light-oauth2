<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;
use PHPUnit\Framework\TestCase;
use Light\OAuth2\Storage\PdoStore;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
final class PdoStoreTest extends TestCase
{
    public function testMysqlResourceRegistryPersistenceAndRollback(): void
    {
        if (!getenv('OAUTH_TEST_DSN')) self::markTestSkipped('Set OAUTH_TEST_DSN for MySQL');
        $pdo = new \PDO(getenv('OAUTH_TEST_DSN'), getenv('OAUTH_TEST_USER') ?: '', getenv('OAUTH_TEST_PASSWORD') ?: '');
        $sql = preg_replace('/^--.*$/m', '', file_get_contents(dirname(__DIR__) . '/migrations/002_oauth_resources.sql'));
        $pdo->exec(str_replace('CREATE TABLE IF NOT EXISTS', 'CREATE TEMPORARY TABLE', $sql));
        $store = new PdoStore($pdo);
        $record = ['id' => 'https://api.example.com/' . str_repeat('x', 1000), 'name' => 'API', 'scopes' => ['client.list'], 'enabled' => true];
        $store->createResource($record); self::assertSame($record, $store->resource($record['id'])); self::assertSame([$record], $store->resources());
        self::assertNull($store->resource($record['id'] . '/'));
        try { $store->createResource($record); self::fail('Duplicate accepted'); } catch (\InvalidArgumentException) { self::assertCount(1, $store->resources()); }
        try { $store->transaction(function () use ($store, $record) { $record['enabled'] = false; $store->saveResource($record); throw new \RuntimeException('rollback'); }); } catch (\RuntimeException) {}
        self::assertTrue($store->resource($record['id'])['enabled']);
        $record['enabled'] = false; $store->saveResource($record); self::assertFalse($store->resource($record['id'])['enabled']);
        self::assertTrue($store->deleteResource($record['id'])); self::assertNull($store->resource($record['id'])); self::assertFalse($store->deleteResource($record['id']));
    }
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
        self::assertSame([$client], $store->clients());
        try {
            $store->createClient($client);
            self::fail('Duplicate OAuth client accepted');
        } catch (\InvalidArgumentException) {
            self::assertSame($client, $store->client('test'));
        }
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
        $credential = ['expires_at' => time() + 60, 'revoked' => false, 'client_id' => 'test'];
        $store->insert('auth_code', 'owned-code', $credential);
        $store->insert('access_token', 'owned-access', $credential);
        $store->insert('refresh_token', 'owned-refresh', ['expires_at' => time() + 60, 'access_token_id' => 'owned-access']);
        $store->insert('access_token', 'other-access', [...$credential, 'client_id' => 'other']);
        $store->insert('refresh_token', 'other-refresh', ['expires_at' => time() + 60, 'access_token_id' => 'other-access']);
        self::assertTrue($store->deleteClient('test'));
        self::assertNull($store->client('test'));
        self::assertFalse($store->deleteClient('test'));
        foreach (['auth_code' => 'owned-code', 'access_token' => 'owned-access', 'refresh_token' => 'owned-refresh'] as $type => $id) self::assertTrue($store->record($type, $id)['revoked']);
        self::assertFalse($store->record('access_token', 'other-access')['revoked']);
        self::assertFalse($store->record('refresh_token', 'other-refresh')['revoked']);
        $personal = [...$credential, 'user_id' => '27', 'scopes' => ['client.list']];
        $store->insert('access_token', 'personal-expired', [...$personal, 'expires_at' => time() - 60]);
        $store->insert('refresh_token', 'personal-refresh', ['expires_at' => time() + 3600, 'revoked' => false, 'access_token_id' => 'personal-expired']);
        $store->insert('auth_code', 'personal-code', $personal);
        $store->insert('access_token', 'foreign-user', [...$personal, 'user_id' => '28']);
        $store->insert('refresh_token', 'foreign-refresh', ['expires_at' => time() + 3600, 'access_token_id' => 'foreign-user']);
        $store->insert('access_token', 'personal-other-client', [...$personal, 'client_id' => 'other']);
        $manager = new \Light\OAuth2\Management\AuthorizationManager($store);
        $grants = $manager->authorizations('27');
        $testGrant = array_values(array_filter($grants, fn($grant) => $grant->clientId === 'test'))[0];
        self::assertSame(0, $testGrant->accessTokens);
        self::assertSame(1, $testGrant->refreshTokens);
        self::assertSame(1, $testGrant->authorizationCodes);
        self::assertSame(['client.list'], $testGrant->scopes);
        self::assertFalse($manager->revoke('29', 'test'));
        self::assertTrue($manager->revoke('27', 'test'));
        self::assertTrue($store->record('access_token', 'personal-expired')['revoked']);
        self::assertTrue($store->record('refresh_token', 'personal-refresh')['revoked']);
        self::assertTrue($store->record('auth_code', 'personal-code')['revoked']);
        self::assertFalse($store->record('access_token', 'foreign-user')['revoked']);
        self::assertFalse($store->record('refresh_token', 'foreign-refresh')['revoked']);
        self::assertFalse($store->record('access_token', 'personal-other-client')['revoked']);
        self::assertCount(1, $manager->authorizations('27'));
        $store->createClient($client);
        self::assertTrue($store->record('refresh_token', 'owned-refresh')['revoked']);
        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);
        $store->insert('auth_code', 'one', $record);
    }
}
