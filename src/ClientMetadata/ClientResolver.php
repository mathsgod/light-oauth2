<?php
declare(strict_types=1);
namespace Light\OAuth2\ClientMetadata;

use Light\OAuth2\Contract\Store;
use Light\OAuth2\Storage\ClientRegistration;

/** Database registrations take precedence; remote documents never become trusted DB clients. */
final class ClientResolver
{
    private array $resolved = [];
    public function __construct(private Store $store, private array $scopes, private ?MetadataFetcher $fetcher, private \Light\OAuth2\ResourceRegistry $registry) {}

    public function client(string $id): ?array
    {
        if ($record = $this->store->client($id)) return $record;
        if ($this->fetcher === null || !str_starts_with($id, 'https://')) return null;
        if (isset($this->resolved[$id]) && $this->resolved[$id]['expires'] > time()) return $this->resolved[$id]['record'];
        try {
            HttpsMetadataFetcher::validateUrl($id);
            $document = $this->fetcher->fetch($id);
            if (($document['client_id'] ?? null) !== $id || ($document['token_endpoint_auth_method'] ?? 'none') !== 'none'
                || isset($document['client_secret']) || isset($document['client_secret_expires_at']) || isset($document['jwks']) || isset($document['jwks_uri'])) {
                return null;
            }
            foreach (['grant_types' => ['authorization_code', 'refresh_token'], 'response_types' => ['code']] as $field => $allowed) {
                if (isset($document[$field])) {
                    if (!is_array($document[$field]) || !array_is_list($document[$field])) return null;
                    foreach ($document[$field] as $value) {
                        if (!is_string($value) || !in_array($value, $allowed, true)) return null;
                    }
                }
            }
            $scope = $document['scope'] ?? null;
            if ($scope !== null && !is_string($scope)) return null;
            $resources = null;
            $allowedScopes = $this->scopes;
            if (array_key_exists('resources', $document) && $document['resources'] === null) return null;
            $resources = $this->registry->clientResources($document['resources'] ?? null);
            $allowedScopes = $this->registry->registrationScopes($resources, $allowedScopes);
        
            $allowedScopes = $scope === null ? $allowedScopes : array_values(array_intersect($allowedScopes, explode(' ', $scope)));
            $redirects = $document['redirect_uris'] ?? null;
            if (!is_array($redirects) || !array_is_list($redirects) || !$redirects || count($redirects) > 20) return null;
            // Validate the same record shape without the database ID length limit.
            $record = ['id' => 'cimd', 'name' => $document['client_name'] ?? $id,
                'redirect_uris' => $redirects, 'scopes' => $allowedScopes, 'confidential' => false, 'enabled' => true];
            // Codex publishes localhost alongside its loopback IP callback.
            // These are browser redirects, never metadata fetch destinations.
            if ($resources !== null) $record['resources'] = $resources;
            ClientRegistration::validate($record, allowLocalhost: true);
            foreach ($redirects as $uri) {
                if (strlen($uri) > 2048 || preg_match('/[^\x21-\x7E]/', $uri) || str_contains($uri, '\\')) return null;
            }
            $record['id'] = $id;
            // Short in-process memoization only; never persist or cache failures.
            if (count($this->resolved) >= 100) array_shift($this->resolved);
            $this->resolved[$id] = ['record' => $record, 'expires' => time() + 60];
            return $record;
        } catch (\RuntimeException|\InvalidArgumentException|\JsonException $error) {
            return null;
        }
    }
}
