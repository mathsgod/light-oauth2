<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;

use Light\Db\Adapter;
use Light\Model;
use PHPUnit\Framework\TestCase;

/** Optional integration tests against a configured Light application checkout. */
abstract class ApplicationTestCase extends TestCase
{
    private ?string $originalDirectory = null;
    private array $originalEnvironment = [];
    private array $originalServer = [];
    private bool $transactionStarted = false;

    protected function setUp(): void
    {
        parent::setUp();
        $path = getenv('LIGHT_SOURCE_PATH');
        if (!$path || !is_dir($path)) self::markTestSkipped('Set LIGHT_SOURCE_PATH to a configured Light application checkout');
        $this->originalDirectory = getcwd();
        $this->originalEnvironment = $_ENV;
        $this->originalServer = $_SERVER;
        chdir($path);
        \Dotenv\Dotenv::createImmutable($path)->safeLoad();
        if (empty($_ENV['DATABASE_HOSTNAME'])) self::markTestSkipped('Configure the Light application database');
        Adapter::Create()->beginTransaction();
        $this->transactionStarted = true;
    }

    protected function tearDown(): void
    {
        try {
            if ($this->transactionStarted) Adapter::Create()->rollback();
            Model::SetContainer(null);
        } finally {
            if ($this->originalDirectory !== null) {
                chdir($this->originalDirectory);
                $_ENV = $this->originalEnvironment;
                $_SERVER = $this->originalServer;
            }
            parent::tearDown();
        }
    }
}
