# Access-token exchange

This package implements an opt-in profile of [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html). It lets a confidential service such as an MCP server exchange a user's token for a token addressed to a downstream API. The MCP server performs the exchange; Codex or another MCP client does not need to perform another upstream authorization flow.

## Enable explicitly

Keep the provider's `Config::resource` set to the public MCP resource. Register the MCP service as a **separate confidential OAuth client** with a hashed secret, enabled status and an allowed scope list. The original MCP client (for example Codex) remains its own client. The confidential client's registration must satisfy the existing `ClientRegistration` requirements, including a redirect URI, although token exchange does not use that URI.

```php
use Light\OAuth2\{OAuthProvider, TokenExchangePolicy};

$policy = new TokenExchangePolicy([
    'hostlink-mcp' => [
        'source' => 'https://mcp.example.com',
        'targets' => [
            'https://api.example.com/graphql' => ['client.list'],
        ],
    ],
], ttl: 'PT5M');

$provider = new OAuthProvider($config, $store, $permissions, $loginFlow, $policy);
$provider->register($app, $loadActiveUser);
```

The rule's `source` must exactly match this provider's configured resource. No policy is enabled by default. An authenticated confidential client without a matching rule receives `unauthorized_client`. The normal authorization-code and refresh-token flows retain their existing audience and behavior.

For a Light GraphQL application, set `Config::apiResource` to the API audience. The provider's built-in `register()` then validates application OAuth credentials against that audience and installs `OAuthService` with the existing per-operation permission checks. Its `validator()` remains bound to `Config::resource` for MCP validation. You do not need an application-specific auth factory override.

The environment factory supports the complete setup from trusted environment settings:

```dotenv
OAUTH_ENABLED=true
OAUTH_RESOURCE=https://mcp.example.com
OAUTH_API_RESOURCE=https://api.example.com/graphql
OAUTH_SCOPES=client.list
OAUTH_TOKEN_EXCHANGE_POLICY='{"hostlink-mcp":{"source":"https://mcp.example.com","targets":{"https://api.example.com/graphql":["client.list"]}}}'
OAUTH_TOKEN_EXCHANGE_TTL=PT5M
```

Keep the existing issuer, key-path, encryption-key and database settings too. Load `.env` into `$_ENV` before constructing the application. The entry point can then use only:

```php
$app = new Light\App();
Light\OAuth2\ProviderFactory::registerFromEnvironment($app);
$app->run();
```

Malformed policy JSON fails configuration instead of enabling unrestricted exchange. With no policy setting, exchange stays disabled. An explicitly supplied policy object takes precedence over the environment policy:

```php
Light\OAuth2\ProviderFactory::registerFromEnvironment($app, exchangePolicy: $policy);
```

Existing `OAUTH_ENABLED`, key-path and database configuration is still required. No client credentials or policies are discovered from an incoming token, and the factory does not enable exchange merely because OAuth is enabled.

## Exchange from the MCP service

Send a form-encoded POST to the existing token endpoint. Authenticate the MCP service using HTTP Basic or `client_id` / `client_secret` in the body. Do not put the user's bearer token in the Authorization header of this request; it belongs in `subject_token`.

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

The lines above illustrate parameters; encode them as a single form body, not literal newline-separated text. `requested_token_type`, if supplied, must be `urn:ietf:params:oauth:token-type:access_token`.

A successful response includes:

```json
{
  "access_token": "<new API JWT>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "client.list"
}
```

The issued token's `sub` remains the user's identifier; `client_id` identifies the exchanging MCP service, and `aud` is the target API resource. The source token remains usable. No refresh token is issued. The MCP service can reuse the API token while it is valid, then perform another exchange using a valid source token.

## Validate at the downstream API

```php
use Light\OAuth2\Auth\TokenValidator;

$apiValidator = new TokenValidator(
    $config->forResource('https://api.example.com/graphql'),
    $store,
);
$context = $apiValidator->validate($request);
if (!$context->can('client.list', $permissions)) {
    // Reject the operation with insufficient permission.
}
// Load the active user identified by $context->userId and invoke the existing
// business operation with that user's normal data restrictions.
```

The API needs the same trusted issuer/public key and access to the issuance/revocation store; this profile is not validation of arbitrary third-party JWTs. The validator returns an identity and scopes, not an automatic authorization to every GraphQL field. In a Light application, configure `apiResource` / `OAUTH_API_RESOURCE` and let the provider install `OAuthService`; existing resolver attributes such as `#[Right('client.list')]` enforce scopes and current user rights. The manual validator example above is for other integrations.

Do not call `register()` twice to install two providers on the same application's token routes, and do not subsequently replace its auth factory with an application-specific factory that only understands native tokens. When `apiResource` is omitted, the provider retains its previous behavior of accepting its primary resource's OAuth tokens for application authentication. Native Light credentials retain their existing authentication path.

With distinct MCP and API resources configured, the MCP validator rejects API-audience tokens and the application's API validator rejects the original MCP-audience token. The MCP service still needs to perform token exchange before it calls GraphQL; configuring API authentication does not implement those outgoing MCP requests.

## Supported profile and policy

- Subject and requested token types: this package's persisted OAuth access tokens only, even though their representation is JWT. Foreign issuers, opaque external tokens, refresh tokens, ID tokens and SAML are not supported.
- This is an impersonation profile. `actor_token` / `actor_token_type` are rejected with `invalid_request`; no `act` claim is emitted. The authenticated client's identity is recorded as `client_id`, not treated as an actor-token delegation chain.
- One target per request. `resource` selects an exact allowlisted URL. `audience` can select the same URL, with no logical-name aliases; if both are supplied they must identify the same target. Repeated target parameters are rejected with `invalid_target` instead of silently selecting the last value. URLs must meet the existing Config URL policy (HTTPS, or HTTP loopback; no query or fragment).
- If no target is specified, a rule with exactly one target provides the default. Otherwise the request fails with `invalid_target`.
- If scope is omitted, the default is the intersection of source-token scopes and target-policy scopes. All resulting scopes must also be exposed by the permission provider, allowed to both clients and currently permitted to the user. An explicit disallowed scope fails with `invalid_scope`; an empty effective scope set also fails. Scope names keep the same meaning across source and target; no scope remapping is performed.
- The issued token expires no later than the source JWT, its stored expiration, or the exchange TTL, whichever comes first. API validation checks source revocation/expiration and the source client's enabled status; scope removals at either client reduce effective rights. Current user permissions are checked via `TokenContext::can()` / `OAuthService`.
- Exchanged tokens cannot be exchanged again. This avoids delegation chains and cycles in this initial profile.
- The exchanging client can revoke its API token through the existing revocation endpoint. Revoking an API token does not revoke the original MCP token. Revoking the source token invalidates derived API tokens when they are validated.
- Invalid subject credentials and unsupported token types return `invalid_request`, unsupported targets return `invalid_target`, and normal client-authentication errors retain OAuth's standard errors. Responses use `Cache-Control: no-store`.

This deliberately bounded profile does not implement every token format or optional delegation feature described in RFC 8693. Exchange policies are trusted application configuration. Removing a policy stops future exchanges; it does not by itself revoke already issued API tokens. Revoke credentials or disable the client when immediate withdrawal is required.

## Storage

No SQL migration is needed for `PdoStore`: the existing credential JSON stores `resource` and, for exchanged credentials, `exchange_subject`. Legacy credentials without these fields retain their existing validation behavior. Custom stores must preserve the additional record fields and provide the existing transactional/locking guarantees. Retain source issuance records for at least the lifetime of derived credentials; deleting a source record invalidates its derivatives.
