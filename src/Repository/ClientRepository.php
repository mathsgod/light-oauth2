<?php
declare(strict_types=1);
namespace Light\OAuth2\Repository;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use Light\OAuth2\Contract\Store;
use Light\OAuth2\Entity\Client;
final class ClientRepository implements ClientRepositoryInterface
{
    public function __construct(private Store $store, private ?\Light\OAuth2\ClientMetadata\ClientResolver $clients = null) {}
    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $record = $this->clients ? $this->clients->client($clientIdentifier) : $this->store->client($clientIdentifier);
        return $record && !empty($record['enabled']) ? new Client($record) : null;
    }
    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        $client = $this->getClientEntity($clientIdentifier);
        if (!$client || !in_array($grantType, ['authorization_code', 'refresh_token', \Light\OAuth2\Grant\TokenExchangeGrant::IDENTIFIER], true)) return false;
        if ($grantType === \Light\OAuth2\Grant\TokenExchangeGrant::IDENTIFIER && !$client->isConfidential()) return false;
        return !$client->isConfidential() || ($clientSecret !== null && password_verify($clientSecret, $client->record['secret_hash'] ?? ''));
    }
}
