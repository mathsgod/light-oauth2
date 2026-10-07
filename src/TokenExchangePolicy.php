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
