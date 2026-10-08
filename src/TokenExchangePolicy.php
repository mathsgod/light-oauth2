<?php
declare(strict_types=1);
namespace Light\OAuth2;

use League\OAuth2\Server\Exception\OAuthServerException;

/** Explicit allowlist for local access-token impersonation exchanges. */
final readonly class TokenExchangePolicy
{
    /**
     * @param array<string, array{source: string, targets: array<string, list<string>>}> $clients
     * Targets are exact resource URLs; audience uses the same URLs, not aliases.
     */
    public function __construct(public array $clients, public string $ttl = 'PT5M')
    {
        $now = new \DateTimeImmutable();
        $interval = new \DateInterval($ttl);
        if ($interval->invert || $now->add($interval) <= $now) throw new \InvalidArgumentException('Exchange TTL must be positive');
        foreach ($clients as $id => $rule) {
            if ((!is_string($id) && !is_int($id)) || (string) $id === '' || !is_array($rule) || !is_string($rule['source'] ?? null) ||
                !is_array($rule['targets'] ?? null) || $rule['targets'] === []) {
                throw new \InvalidArgumentException('Invalid token exchange client policy');
            }
            self::validateResource($rule['source']);
            foreach ($rule['targets'] as $target => $scopes) {
                if (!is_string($target)) throw new \InvalidArgumentException('Exchange targets must be resource URLs');
                self::validateResource($target);
                if ($target === $rule['source'] || !is_array($scopes) || !array_is_list($scopes) || $scopes === []) {
                    throw new \InvalidArgumentException('Exchange requires a different target and nonempty scope allowlist');
                }
                foreach ($scopes as $scope) {
                    if (!is_string($scope) || !preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/D', $scope)) {
                        throw new \InvalidArgumentException('Invalid exchange scope');
                    }
                }
            }
        }
    }

    /** Read trusted application settings; callers may still supply a policy object explicitly. */
    public static function fromEnvironment(array $environment): ?self
    {
        $json = $environment['OAUTH_TOKEN_EXCHANGE_POLICY'] ?? null;
        if ($json === null || $json === '') return null;
        if (!is_string($json)) throw new \InvalidArgumentException('OAUTH_TOKEN_EXCHANGE_POLICY must be a JSON object');
        try {
            $clients = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new \InvalidArgumentException('Invalid OAUTH_TOKEN_EXCHANGE_POLICY JSON', 0, $error);
        }
        if (!str_starts_with(ltrim($json), '{') || !is_array($clients)) throw new \InvalidArgumentException('OAUTH_TOKEN_EXCHANGE_POLICY must be a JSON object');
        $ttl = $environment['OAUTH_TOKEN_EXCHANGE_TTL'] ?? 'PT5M';
        if (!is_string($ttl)) throw new \InvalidArgumentException('OAUTH_TOKEN_EXCHANGE_TTL must be an ISO 8601 duration');
        return new self($clients, $ttl);
    }

    /** @return array{resource: string, scopes: list<string>} */
    public function target(string $clientId, string $source, ?string $resource, ?string $audience): array
    {
        $rule = $this->clients[$clientId] ?? null;
        if (!$rule || $rule['source'] !== $source) throw OAuthServerException::unauthorizedClient();
        if ($resource !== null && $audience !== null && $resource !== $audience) throw self::invalidTarget();
        $target = $resource ?? $audience;
        if ($target === null && count($rule['targets']) === 1) $target = array_key_first($rule['targets']);
        if ($target === null || !isset($rule['targets'][$target])) throw self::invalidTarget();
        return ['resource' => $target, 'scopes' => $rule['targets'][$target]];
    }

    public static function invalidTarget(): OAuthServerException
    {
        return new OAuthServerException('Unsupported token exchange target', 0, 'invalid_target', 400);
    }

    private static function validateResource(string $resource): void
    {
        $parts = parse_url($resource);
        if (!$parts || empty($parts['host']) || isset($parts['fragment']) || isset($parts['query']) || isset($parts['user']) ||
            (($parts['scheme'] ?? '') !== 'https' && !(($parts['scheme'] ?? '') === 'http' && in_array($parts['host'], ['localhost', '127.0.0.1', '[::1]'], true)))) {
            throw new \InvalidArgumentException('Exchange resources must be HTTPS URLs (HTTP loopback allowed), without query or fragment');
        }
    }
}
