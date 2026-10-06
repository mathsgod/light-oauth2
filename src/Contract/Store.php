<?php
declare(strict_types=1);
namespace Light\OAuth2\Contract;
interface Store
{
    public function client(string $id): ?array;
    public function saveClient(array $client): void;
    public function insert(string $type, string $id, array $record): void;
    /** Lock credential rows when called inside a token-exchange transaction. */
    public function record(string $type, string $id): ?array;
    public function revoke(string $type, string $id): void;
    public function transaction(callable $operation): mixed;
}
