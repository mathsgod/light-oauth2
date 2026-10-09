<?php
declare(strict_types=1);
namespace Light\OAuth2\Contract;

/** Required resource policy storage. Apply migration 002 before using the provider. */
interface ResourceStore extends Store
{
    public function resources(): array;
    public function resource(string $id): ?array;
    /** Insert only. Resource URLs are immutable identities. */
    public function createResource(array $resource): void;
    public function saveResource(array $resource): void;
    public function deleteResource(string $id): bool;
}
