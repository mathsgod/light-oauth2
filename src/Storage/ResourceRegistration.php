<?php
declare(strict_types=1);
namespace Light\OAuth2\Storage;
final class ResourceRegistration
{
    public static function validate(array $record): void
    {
        $id = $record['id'] ?? null;
        if (!is_string($id) || $id === '' || strlen($id) > 2048 || preg_match('/[^\x21-\x7E]/', $id) || str_contains($id, '\\')) {
            throw new \InvalidArgumentException('Invalid resource URL');
        }
        $parts = parse_url($id);
        if (!$parts || empty($parts['host']) || isset($parts['fragment']) || isset($parts['query']) || isset($parts['user']) || isset($parts['pass']) ||
            (($parts['scheme'] ?? '') !== 'https' && !(($parts['scheme'] ?? '') === 'http' && in_array($parts['host'], ['localhost', '127.0.0.1', '[::1]'], true)))) {
            throw new \InvalidArgumentException('Resource requires HTTPS or HTTP loopback, without query, fragment or credentials');
        }
        if (!is_string($record['name'] ?? null) || $record['name'] === '' || strlen($record['name']) > 200 || !is_bool($record['enabled'] ?? null) ||
            !is_array($record['scopes'] ?? null) || !array_is_list($record['scopes']) || count($record['scopes']) > 1000) {
            throw new \InvalidArgumentException('Invalid resource record');
        }
        foreach ($record['scopes'] as $scope) {
            if (!is_string($scope) || !preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/D', $scope)) throw new \InvalidArgumentException('Invalid resource scope');
        }
    }
}
