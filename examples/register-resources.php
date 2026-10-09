<?php
declare(strict_types=1);
use Light\OAuth2\Contract\{ResourceStore, PermissionProvider};
use Light\OAuth2\Input\OAuthResourceInput;
use Light\OAuth2\Management\ResourceManager;

/** Run explicitly from application administration after migration 002. */
function registerOAuthResource(ResourceStore $store, PermissionProvider $permissions, string $url, string $name, array $scopes): void
{
    $input = new OAuthResourceInput();
    $input->id = $url;
    $input->name = $name;
    $input->scopes = $scopes;
    $input->enabled = true;
    (new ResourceManager($store, $permissions))->save($input, true);
}
