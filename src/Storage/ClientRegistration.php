<?php
declare(strict_types=1);
namespace Light\OAuth2\Storage;
final class ClientRegistration
{
    public static function validate(array $client): void
    {
        if (!is_string($client['id'] ?? null) || $client['id'] === '' || strlen($client['id']) > 191 || !preg_match('/^[\x21-\x7E]+$/D', $client['id']) ||
            !is_string($client['name'] ?? null) || !is_bool($client['confidential'] ?? null) || !is_bool($client['enabled'] ?? null) ||
            !is_array($client['redirect_uris'] ?? null) || !$client['redirect_uris'] || !is_array($client['scopes'] ?? null)) {
            throw new \InvalidArgumentException('Invalid OAuth client record');
        }
        if ($client['confidential'] && empty($client['secret_hash'])) throw new \InvalidArgumentException('Confidential client requires a hashed secret');
        foreach ($client['redirect_uris'] as $uri) {
            if (!is_string($uri)) throw new \InvalidArgumentException('Invalid redirect URI');
            $parts = parse_url($uri);
            if (!$parts || empty($parts['host']) || isset($parts['fragment']) || isset($parts['user']) ||
                (($parts['scheme'] ?? '') !== 'https' && !(($parts['scheme'] ?? '') === 'http' && in_array($parts['host'], ['127.0.0.1', '[::1]'], true)))) {
                throw new \InvalidArgumentException('Redirect URI requires HTTPS or a loopback IP');
            }
        }
        foreach ($client['scopes'] as $scope) {
            if (!is_string($scope) || !preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/D', $scope)) throw new \InvalidArgumentException('Invalid scope name');
        }
    }
}
