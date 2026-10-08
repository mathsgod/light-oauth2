<?php
declare(strict_types=1);
namespace Light\OAuth2\Tests;

use PHPUnit\Framework\TestCase;
use Light\OAuth2\ClientMetadata\{ClientResolver, HttpsMetadataFetcher, MetadataFetcher};
use Light\OAuth2\Repository\ClientRepository;

final class ClientMetadataTest extends TestCase
{
    private const ID = 'https://client.example.com/codex/client.json';
    private function fetcher(array $changes = []): MetadataFetcher
    {
        return new class($changes) implements MetadataFetcher {
            public int $calls = 0;
            public function __construct(public array $changes) {}
            public function fetch(string $url): array
            {
                $this->calls++;
                return array_replace(['client_id' => $url, 'client_name' => 'Codex', 'redirect_uris' => ['http://127.0.0.1/callback/id'], 'token_endpoint_auth_method' => 'none'], $this->changes);
            }
        };
    }
    public function testPublicClientResolutionAndMemoizationWithoutDatabaseRegistration(): void
    {
        $store = new MemoryStore();
        $fetcher = $this->fetcher();
        $resolver = new ClientResolver($store, ['client.list'], $fetcher);
        $repo = new ClientRepository($store, $resolver);
        self::assertSame(self::ID, $repo->getClientEntity(self::ID)->getIdentifier());
        self::assertTrue($repo->validateClient(self::ID, null, 'authorization_code'));
        self::assertFalse($repo->validateClient(self::ID, null, \Light\OAuth2\Grant\TokenExchangeGrant::IDENTIFIER));
        self::assertSame(1, $fetcher->calls);
        self::assertSame([], $store->clients);
    }
    public function testCodexDocumentWithLocalhostAlternativeResolves(): void
    {
        $redirects = ['http://127.0.0.1/callback/wSHsHZ6KgDv5', 'http://localhost/callback/wSHsHZ6KgDv5'];
        $resolver = new ClientResolver(new MemoryStore(), ['client.list'], $this->fetcher(['redirect_uris' => $redirects]));
        $record = $resolver->client(self::ID);
        self::assertNotNull($record);
        self::assertSame($redirects, $record['redirect_uris']);
        $validator = new \League\OAuth2\Server\RedirectUriValidators\RedirectUriValidator($record['redirect_uris']);
        self::assertTrue($validator->validateRedirectUri('http://127.0.0.1:21486/callback/wSHsHZ6KgDv5'));
        self::assertFalse($validator->validateRedirectUri('http://127.0.0.1:21486/callback/other'));
        self::assertFalse($validator->validateRedirectUri('http://localhost:21486/callback/wSHsHZ6KgDv5'));
        foreach (['localhost.evil.example', 'evil.localhost', '192.168.1.1'] as $host) {
            $bad = new ClientResolver(new MemoryStore(), ['client.list'], $this->fetcher(['redirect_uris' => ['http://' . $host . '/callback']]));
            self::assertNull($bad->client(self::ID));
        }
    }

    public function testDisabledFeatureAndDatabaseOverride(): void
    {
        $store = new MemoryStore();
        self::assertNull((new ClientResolver($store, ['client.list']))->client(self::ID));
        $store->saveClient(['id' => self::ID, 'name' => 'Blocked', 'redirect_uris' => ['https://client.example.com/callback'], 'scopes' => [], 'enabled' => false, 'confidential' => false]);
        $fetcher = $this->fetcher();
        $repo = new ClientRepository($store, new ClientResolver($store, ['client.list'], $fetcher));
        self::assertNull($repo->getClientEntity(self::ID));
        self::assertSame(0, $fetcher->calls);
    }
    public function testInvalidDocumentsAreRejectedAndNeverCached(): void
    {
        foreach ([['client_id' => 'https://other.example/id'], ['token_endpoint_auth_method' => 'client_secret_basic'], ['client_secret' => 'secret'], ['jwks_uri' => 'https://keys.example/jwks'], ['redirect_uris' => ['http://evil.example/callback']], ['redirect_uris' => []], ['redirect_uris' => ['https://app.example/cb#fragment']], ['redirect_uris' => ['https://user:pass@app.example/cb']], ['client_name' => []], ['scope' => []], ['grant_types' => ['client_credentials']], ['response_types' => ['token']], ['grant_types' => [[]]]] as $changes) {
            $fetcher = $this->fetcher($changes);
            $resolver = new ClientResolver(new MemoryStore(), ['client.list'], $fetcher);
            self::assertNull($resolver->client(self::ID), json_encode($changes));
            self::assertNull($resolver->client(self::ID));
            self::assertSame(2, $fetcher->calls);
        }
    }
    public function testUnavailableDocumentFailsClosedWithoutCaching(): void
    {
        $fetcher = new class implements MetadataFetcher {
            public int $calls = 0;
            public function fetch(string $url): array { $this->calls++; throw new \RuntimeException('network unavailable'); }
        };
        $resolver = new ClientResolver(new MemoryStore(), ['client.list'], $fetcher);
        self::assertNull($resolver->client(self::ID));
        self::assertNull($resolver->client(self::ID));
        self::assertSame(2, $fetcher->calls);
    }
    public function testFetcherRefusesPrivateLiteralBeforeConnecting(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('public IP');
        (new HttpsMetadataFetcher())->fetch('https://127.0.0.1/client.json');
    }

    public function testScopeCannotExpandServerPermissions(): void
    {
        $resolver = new ClientResolver(new MemoryStore(), ['client.list'], $this->fetcher(['scope' => 'client.list administrator']));
        self::assertSame(['client.list'], $resolver->client(self::ID)['scopes']);
    }
    public function testMixedDnsAnswersOnlySelectPublicDestination(): void
    {
        self::assertSame('104.207.155.211', HttpsMetadataFetcher::selectPublicAddress(['::', '127.0.0.1', '104.207.155.211']));
        self::assertSame('8.8.8.8', HttpsMetadataFetcher::selectPublicAddress(['8.8.8.8', '10.0.0.1']));
        $this->expectException(\RuntimeException::class);
        HttpsMetadataFetcher::selectPublicAddress(['::', '10.0.0.1']);
    }

    public function testUrlAndSsrfPolicy(): void
    {
        foreach (['http://client.example/id', 'https://client.example', 'https://user:pass@client.example/id', 'https://client.example/id#fragment', 'https://client.example/a/../id', 'https://client.example/%2e%2e/id', "https://client.example/a\nb", 'https://client.example/a\\b'] as $url) {
            try { HttpsMetadataFetcher::validateUrl($url); self::fail($url); }
            catch (\InvalidArgumentException) {}
        }
        foreach (['127.0.0.1', '10.1.2.3', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1', '2002:7f00:1::', '2001:0::1', '64:ff9b::7f00:1'] as $ip) self::assertFalse(HttpsMetadataFetcher::isPublicAddress($ip), $ip);
        self::assertTrue(HttpsMetadataFetcher::isPublicAddress('8.8.8.8'));
        self::assertTrue(HttpsMetadataFetcher::isPublicAddress('2606:4700:4700::1111'));
    }
}
