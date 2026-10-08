<?php
declare(strict_types=1);
namespace Light\OAuth2\ClientMetadata;

interface MetadataFetcher
{
    /** Return a decoded document. Implementations must enforce HTTPS and SSRF protections. */
    public function fetch(string $url): array;
}
