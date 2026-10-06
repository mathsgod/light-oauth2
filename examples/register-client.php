<?php
declare(strict_types=1);
use Light\OAuth2\Contract\Store;

/** Register once from application administration, not during every API request. */
function registerPublicClient(Store $store, string $redirectUri): void
{
    $store->saveClient([
        'id' => 'codex',
        'name' => 'Codex',
        'redirect_uris' => [$redirectUri],
        'confidential' => false,
        'enabled' => true,
        'scopes' => ['client.list'],
    ]);
}
