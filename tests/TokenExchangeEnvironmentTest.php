<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;

use Light\OAuth2\TokenExchangePolicy;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

final class TokenExchangeEnvironmentTest extends TestCase
{
    public function testEnvironmentSettingsProduceExplicitExchangePolicy(): void
    {
        $source = 'https://mcp.example.com';
        $target = 'https://api.example.com/graphql';
        $clients = ['hostlink-mcp' => ['source' => $source, 'targets' => [$target => ['client.list']]]];
        $policy = TokenExchangePolicy::fromEnvironment(['OAUTH_TOKEN_EXCHANGE_POLICY' => json_encode($clients, JSON_THROW_ON_ERROR), 'OAUTH_TOKEN_EXCHANGE_TTL' => 'PT2M']);
        self::assertSame('PT2M', $policy->ttl);
        self::assertSame(['resource' => $target, 'scopes' => ['client.list']], $policy->target('hostlink-mcp', $source, $target, null));
        self::assertSame('PT5M', TokenExchangePolicy::fromEnvironment(['OAUTH_TOKEN_EXCHANGE_POLICY' => json_encode($clients, JSON_THROW_ON_ERROR)])->ttl);
    }

    public function testMissingOrEmptyPolicyDoesNotEnableExchange(): void
    {
        self::assertNull(TokenExchangePolicy::fromEnvironment([]));
        self::assertNull(TokenExchangePolicy::fromEnvironment(['OAUTH_TOKEN_EXCHANGE_POLICY' => '']));
        self::assertNull(TokenExchangePolicy::fromEnvironment(['OAUTH_TOKEN_EXCHANGE_TTL' => 'PT2M']));
    }

    public static function invalidSettings(): iterable
    {
        yield 'malformed JSON' => [['OAUTH_TOKEN_EXCHANGE_POLICY' => '{']];
        yield 'JSON list' => [['OAUTH_TOKEN_EXCHANGE_POLICY' => '[]']];
        yield 'JSON null' => [['OAUTH_TOKEN_EXCHANGE_POLICY' => 'null']];
        yield 'scalar value' => [['OAUTH_TOKEN_EXCHANGE_POLICY' => true]];
        yield 'invalid rule' => [['OAUTH_TOKEN_EXCHANGE_POLICY' => '{"mcp":{}}']];
        yield 'wrong TTL type' => [['OAUTH_TOKEN_EXCHANGE_POLICY' => '{}', 'OAUTH_TOKEN_EXCHANGE_TTL' => 12]];
        yield 'zero TTL' => [['OAUTH_TOKEN_EXCHANGE_POLICY' => '{}', 'OAUTH_TOKEN_EXCHANGE_TTL' => 'PT0S']];
    }

    #[DataProvider('invalidSettings')]
    public function testMalformedSettingsFailClosed(array $environment): void
    {
        $this->expectException(\InvalidArgumentException::class);
        TokenExchangePolicy::fromEnvironment($environment);
    }
}
