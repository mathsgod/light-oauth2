<?php
declare(strict_types=1);
namespace Light\OAuth2\Management;
use Light\OAuth2\Contract\AuthorizationStore;
use Light\OAuth2\Type\OAuthAuthorization;

final class AuthorizationManager
{
    public function __construct(private AuthorizationStore $store, private ?\Light\OAuth2\ClientMetadata\ClientResolver $clients = null) {}

    /** @return OAuthAuthorization[] */
    public function authorizations(string $userId): array
    {
        $credentials = $this->store->userCredentials($userId);
        $access = [];
        foreach ($credentials as $credential) {
            if ($credential['type'] === 'access_token') $access[$credential['id']] = $credential['record'];
        }
        $groups = [];
        foreach ($credentials as $credential) {
            $record = $credential['record'];
            if ($record['revoked'] || $record['expires_at'] <= time()) continue;
            $source = $credential['type'] === 'refresh_token' ? ($access[$record['access_token_id']] ?? null) : $record;
            if (!$source || !is_string($source['client_id'] ?? null)) continue;
            $id = $source['client_id'];
            if (!isset($groups[$id])) $groups[$id] = new OAuthAuthorization($id, $this->clients ? $this->clients->client($id) : $this->store->client($id));
            $group = $groups[$id];
            $field = ['access_token' => 'accessTokens', 'refresh_token' => 'refreshTokens', 'auth_code' => 'authorizationCodes'][$credential['type']];
            $group->$field++;
            $group->expiresAt = max($group->expiresAt, $record['expires_at']);
            $group->scopes = array_values(array_unique([...$group->scopes, ...($source['scopes'] ?? [])]));
        }
        return array_values($groups);
    }

    public function revoke(string $userId, string $clientId): bool
    {
        return $this->store->revokeUserAuthorization($userId, $clientId);
    }
}
