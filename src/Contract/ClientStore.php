<?php
declare(strict_types=1);
namespace Light\OAuth2\Contract;

/** Optional management support for OAuth stores. */
interface ClientStore extends Store
{
    /** @return list<array> */
    public function clients(): array;
    /** Insert only; an existing ID must never be overwritten. */
    public function createClient(array $client): void;
    /** Delete the client and permanently revoke all of its credentials. */
    public function deleteClient(string $id): bool;
}
