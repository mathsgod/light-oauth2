# Access-token exchange

The RFC 8693 token-exchange grant is available whenever OAuth is enabled. A confidential service such as an MCP server can exchange a user's local OAuth access token for a token addressed to another registered resource. The user does not need a second browser authorization flow.

## Configure the MCP service

Register the MCP server as a **separate confidential OAuth client** with a hashed secret, enabled status and allowed scopes. Assign **both the source MCP resource and the target API resource** to this client. Both resources must be registered and enabled, with their allowed scopes configured. The user-facing DCR or CIMD client remains a separate public client; its token is the `subject_token`, and it cannot perform exchange itself.

Manage service resources/scopes through `/OAuthResource` and confidential-client assignments through `/OAuthClient`. The OAuth client secret authenticates the MCP server; it does not let that server grant itself additional permissions. Client registration still requires a redirect URI, although exchange does not use it.

No environment exchange policy or PHP policy object is needed. The provider validates sources against their persisted token resource and accepts requested targets according to the authenticated client's resource assignments. `OAUTH_RESOURCE` remains the default audience for legacy records and requests that omit it during ordinary authorization; it does not restrict exchange to one source resource.

```dotenv
OAUTH_ENABLED=true
OAUTH_RESOURCE=https://mcp.example.com
OAUTH_API_RESOURCE=https://api.example.com/graphql
OAUTH_TOKEN_EXCHANGE_TTL=PT5M
```

Keep the normal issuer, key-path, encryption-key and database settings. Apply migrations 001/002 and register resources before enabling OAuth. `OAUTH_API_RESOURCE` is the audience accepted by the Light application's GraphQL/filesystem authentication, not an exchange allowlist. Native Light credentials retain their existing authentication path.

```php
$app = new Light\App();
Light\OAuth2\ProviderFactory::registerFromEnvironment($app);
$app->run();
```

Manual integrations can set `Config::exchangeTokenTtl` (default `PT5M`). All providers register exchange automatically and advertise it in authorization-server discovery.

## Exchange from the MCP server

Send a form-encoded POST to `/oauth/token`. Authenticate the MCP server using HTTP Basic, or `client_id` / `client_secret` in the body. Put the user's token in `subject_token`, not in the Authorization header.

```text
POST /oauth/token
Authorization: Basic <base64 of hostlink-mcp:its-secret>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<user's MCP access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
resource=https://api.example.com/graphql
scope=client.list
```

These lines illustrate fields; send them as one URL-encoded form body. A target must be supplied explicitly. `audience` may be used instead of `resource`, but it must be the exact resource URL; if both appear they must match. Multiple targets, repeated parameters and a target identical to the source are rejected. Unknown, disabled or unassigned source/target resources are rejected.

The requested scopes must be present in the user's source token, allowed by both clients, allowed by both resources, exposed by the permission provider and currently permitted to the user. Explicit scopes outside these limits are rejected. Omitting `scope` selects the intersection of the source token's effective scopes, the exchanging client's scopes and the target resource's scopes, then applies the provider and current-user permission checks. An empty scope set is rejected. Scope names retain the same meaning across resources; there is no scope remapping.

A successful response contains:

```json
{
  "access_token": "<new API JWT>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "client.list"
}
```

The new token's `sub` remains the user ID, `client_id` identifies the exchanging MCP service and `aud` is the requested target resource. The source token remains usable. No refresh token is issued; exchange again using a valid source token after the derived token expires.

## Validate at the API

For a Light application, configure `OAUTH_API_RESOURCE` and let the provider install the scope-aware `OAuthService`. Existing `#[Right('client.list')]` checks enforce token scopes and current user permissions. Merely validating a JWT does not authorize every operation. The MCP server must implement the outgoing exchange and API requests itself.

Manual integrations should share the authorization server's resource registry, client resolver and issuance/revocation store:

```php
$registry = new Light\OAuth2\ResourceRegistry($config, $store);
$clients = new Light\OAuth2\ClientMetadata\ClientResolver(
    $store, $permissions->scopes(), registry: $registry,
);
$api = new Light\OAuth2\Auth\TokenValidator(
    $config->forResource('https://api.example.com/graphql'),
    $store, $clients, $registry,
);
$context = $api->validate($request);
if (!$context->can('client.list', $permissions)) {
    // Reject insufficient permission.
}
```

The normal API validator stays bound to its own audience. Dynamic source validation is used only for exchange; it does not make the API accept tokens addressed to arbitrary resources. Do not mount two providers on the same token routes or replace the installed auth factory with one that only understands native tokens.

## Lifetime, revocation and supported profile

- Only this provider's signed, persisted OAuth access tokens are accepted. Foreign issuers, external opaque tokens, refresh tokens, ID tokens and SAML are unsupported.
- Only confidential clients authenticated with their secret can exchange. Public DCR/CIMD clients can supply subject tokens but cannot act as the exchanging service.
- Exchange preserves user identity. `actor_token` and `actor_token_type` are rejected; no `act` claim or delegation chain is emitted.
- The derived token expires at the earliest of the configured exchange TTL, source JWT expiry and stored source expiry.
- Revoking/expiring the source or disabling its client invalidates derived tokens. Removing either client's source assignment or disabling/deleting a source/target resource also prevents derived token use. Scope removals narrow effective rights. Current user permissions are enforced by `TokenContext::can()` / `OAuthService`.
- Exchanged tokens cannot be exchanged again. The exchanging service can revoke its own derived token without revoking the original user token.
- Unsupported targets return `invalid_target`, invalid subjects/types return `invalid_request`, and client authentication failures return `invalid_client`. Responses use `Cache-Control: no-store`.

## Storage

The existing credential JSON stores `resource` and, for derived credentials, `exchange_subject`; no additional exchange migration is required beyond the resource registry tables. Custom stores must preserve these fields and transactional guarantees. Retain source issuance records for the lifetime of derived credentials; deleting a source record invalidates its derivatives.
