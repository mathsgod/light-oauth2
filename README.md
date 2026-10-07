# mathsgod/light-oauth2

OAuth 2.0 Authorization Code + S256 PKCE integration for Light, powered by League OAuth2 Server. PHP 8.3+; PHPUnit 12 development tests require PHP 8.3+.

## Implemented

- Authorization Code with mandatory S256 PKCE and state; exact registered redirect URI validation through League.
- Public and confidential pre-registered clients, hashed confidential-client secrets.
- Access tokens, rotating refresh tokens, single-use codes and token revocation.
- MySQL/MariaDB storage with transactional token exchange and row locks to serialize credential reuse.
- Authorization-server and protected-resource metadata responses.
- Resource-specific JWT audience, issuer validation, expiry/signature/revocation validation.
- Light authentication adapter and permission scopes. Effective rights require token scope, client-allowed scope, OAuth-exposed scope and the user's current permission.
- Default Light login/2FA and consent pages, with customizable `AuthorizationFlow`.
- Opt-in RFC 8693 access-token exchange with confidential-client authentication, explicit source/target allowlists and scope narrowing.

This package does not supply dynamic client registration, CIMD, OpenID Connect, or a complete Codex-to-MCP-to-GraphQL deployment. Those application integrations remain separate. Each provider authorizes one configured resource; optional token exchange can issue tokens for explicitly allowed downstream resources. Consent must be collected on each authorization, or explicitly remembered and checked by the application flow.

### Refresh token replay protection

Each initial authorization starts an independent refresh-token family. Successful refresh
marks the old token as used and issues a replacement in the same family. Reusing a used,
unexpired token with valid client authentication revokes every refresh token and associated
access token in that family and returns `invalid_grant`. This security revocation commits
even though the exchange is rejected. Other authorizations (including another authorization
by the same user to the same client) remain valid. Expired, malformed, wrong-client and
manually revoked unused tokens do not trigger family revocation.

Clients must serialize refresh requests and save the replacement refresh token. Retrying
a successfully consumed token, including after losing the response, revokes its family and
requires new authorization; there is no retry grace period. Each replacement still expires
30 days after issuance by default; there is no absolute family lifetime.

Custom stores must implement `RefreshTokenStore`, including transactional consumption,
family revocation and locking that serializes exchanges for a family. `PdoStore` implements
this using the client row lock and existing credential JSON (`family_id`, `used_at`), so no
SQL migration is required. Active legacy refresh tokens acquire a family on their first
successful rotation after upgrading. Previously revoked legacy tokens have no consumption
history and cannot retroactively be linked to replacements. Retain used records while their
token can still be presented unexpired, and retain refresh-to-access links needed for revocation.

## Light integration

Light 1.46+ is required. It provides `App::getRouter()`, `App::setAuthServiceFactory()`, `App::createAuthService()` and explicit GraphQL controller registration. During local development, use the sibling `../light` checkout as a Composer path repository.

The application calls `$provider->register($app, $loadActiveUser)` before `$app->run()`. See `examples/register.php`. The factory retains existing Light authentication for native tokens and uses League validation for stored OAuth credentials. Both GraphQL and the built-in filesystem routes use the patched Light auth factory. OAuth tokens use separate keys/issuer from native Light credentials. OAuth users retain `#[Right('client.list')]` checks through the scope-aware adapter.

The user loader must return an active `Light\Model\User` or null. `LightPermissionProvider` rejects missing/disabled users (`status != 0`) and checks current RBAC rights. Projects with extra account restrictions should implement `PermissionProvider` accordingly. Light's RBAC cache policy still determines how quickly permission changes become visible.

## Setup

For service-to-service access on behalf of a user (including MCP to GraphQL), see [access-token exchange](docs/TOKEN_EXCHANGE.md).

1. `composer install`.
2. Apply `migrations/001_oauth.sql` through the application's migration runner.
3. Create separate OAuth RSA keys outside the web root, and a random encryption key of at least 32 characters. Keep all keys out of source control. Use HTTPS outside loopback development.
4. Construct `Config`, `PdoStore`, a permission provider and an application `AuthorizationFlow`.
5. Register each OAuth client once; see `examples/register-client.php`. Store only `password_hash()` output for confidential-client secrets.
6. Register the provider before running Light.

Do not share the OAuth PDO connection with an already-open application transaction. The package does not apply migrations or provision clients automatically.

## Routes

| Method | Route | Purpose |
| --- | --- | --- |
| GET / POST | `/oauth/authorize` | Validate OAuth parameters and delegate login/2FA/consent to the application |
| POST | `/oauth/token` | Form-encoded authorization-code or refresh-token exchange |
| POST | `/oauth/revoke` | Revoke a client-owned access or refresh token |
| GET | `/.well-known/oauth-authorization-server` | Authorization server discovery |

Issuer paths are appended to the authorization-server well-known route. The configurable route prefix is `/oauth` by default. `metadata()` and `protectedResourceMetadata()` also return PSR-7 responses for integrations that mount routes independently. Register OAuth routes once; do not also define conflicting `pages/oauth/*.php` routes.

Revoking a refresh token also revokes its associated access token. Revoking an access token alone does not revoke all related refresh tokens. Use the repository/store revocation methods for administrative revocation by identifier.

## Login, 2FA and consent

Implement `AuthorizationFlow::resolve()`:

- Return a PSR-7 response to show or redirect to login, 2FA or consent.
- Return `AuthorizationDecision($userId, $approved, $authenticationComplete)` only after checking the user's session and required second factor.
- Bind the pending authorization request to the browser session. Preserve validated OAuth parameters across redirects; do not trust hidden form fields or browser-supplied user IDs/2FA flags.
- Validate a separate CSRF token for consent POSTs. OAuth `state` is the client's correlation value and does not replace server-side consent CSRF protection.
- After login/2FA, resume authorization using the original validated query parameters. Only an approved decision with completed authentication issues a code.

The package trusts this application contract; the decision boolean is not itself proof of 2FA. OAuth code generation rechecks client/user scopes, and token exchange/refresh rechecks them again. Login failure, incomplete 2FA and denied consent do not create codes.

## Resource authentication and MCP

Use `$provider->validator()->validate($request)` to obtain a `TokenContext`; use `$context->can($right, $permissions)` before exposing protected data. A successful JWT validation alone does not authorize an operation.

`Config::resource` defines token audience, not the OAuth client ID. `client_id` is recorded separately. The token endpoint accepts only this configured resource. If the MCP server and GraphQL are distinct OAuth resources, obtain downstream credentials through an explicitly designed delegation/token-exchange mechanism; do not forward a token addressed only to MCP into GraphQL.

An MCP service must host its own protected-resource metadata and return the appropriate `WWW-Authenticate` resource metadata challenge. This PHP package does not update the Node MCP server. Codex can use the pre-registered client ID; use the exact callback URL shown by your Codex version. Loopback ports are matched exactly in this release; configure a fixed Codex callback port and register that URI. No wildcard redirect URIs are accepted.

## Application bootstrap and authorization page

Both `Light\OAuth2\ProviderFactory` and `Light\OAuth2\BrowserAuthorizationFlow`
are provided by this package. The application's entry point only needs to call
the factory before `run()`:

```php
$app = new \Light\App();
\Light\OAuth2\ProviderFactory::registerFromEnvironment($app);
$app->run();
```

The factory is enabled by `OAUTH_ENABLED=true`. It reads `OAUTH_ISSUER`,
`OAUTH_RESOURCE`, `OAUTH_PRIVATE_KEY_PATH`, `OAUTH_PUBLIC_KEY_PATH`,
`OAUTH_ENCRYPTION_KEY` and comma-separated `OAUTH_SCOPES`, and uses the Light
`DATABASE_*` settings with a dedicated PDO connection. The default browser flow
reuses Light password and required 2FA checks, with explicit consent, one-time
CSRF protection and CSP allowing the validated callback origin.

An application may supply its own `AuthorizationFlow` as the optional second
argument to `registerFromEnvironment($app, $flow)` to customize the login and
consent pages. The default page implementation lives entirely in this package.

## OAuth client management

When `OAuthProvider::register()` is used with `PdoStore` (or another `ClientStore`),
it registers the client management GraphQL API and adds an **OAuth Clients** menu
entry at `/OAuthClient` for `nuxt-light`. Update both packages to use this page.
No additional database migration is needed beyond `migrations/001_oauth.sql`.
Use a Light checkout with `Light\GraphQL\ExplicitController` and
`ControllerDiscovery` support. The management controller uses
`Light\OAuth2\Controller`; it is discovered only after the provider explicitly
registers it in the container, so installing the package alone does not activate
management queries or require a client store during schema generation.

- Queries: `oauthClients`, `oauthClientScopes` (`oauth_client.list`).
- Mutations: `createOAuthClient(input)` (`oauth_client.add`),
  `updateOAuthClient(input)` and `resetOAuthClientSecret(id)` (`oauth_client.update`).
  `deleteOAuthClient(id)` requires `oauth_client.delete` and removes the client,
  permanently revoking its authorization codes, access tokens and linked refresh
  tokens in one transaction. Recreating the ID does not restore those credentials.
- Input fields: `id`, `name`, `redirectUris`, `scopes`, `confidential`, `enabled`.
  The ID cannot be changed on edit. Scopes must be exposed by the provider.
- Create/update return `{ client, secret }`. A new confidential client, or a
  public client converted to confidential, receives a secret shown once.
  Reset returns a new secret and invalidates the previous secret. Only hashes
  are stored; lists never expose secrets or hashes.
- Disabling a client prevents OAuth token use and exchange while disabled.
  Re-enabling restores access to credentials that remain valid; disabling does
  not permanently revoke them. Secret reset does not revoke access tokens.

Grant these permissions through Light RBAC for delegated administrators.
Light's `addPermissions()` extension hook makes these rights discoverable in
the permissions page; upgrade the local Light checkout to include this hook.
The existing `Administrators` wildcard already grants access. Stores that only
implement `RefreshTokenStore` continue to work without the management API.
Clear Light's schema cache when upgrading an existing deployment.

## Personal authorizations

Stores implementing `AuthorizationStore` (including `PdoStore`) expose
`myOAuthAuthorizations { clientId clientName scopes enabled accessTokens refreshTokens authorizationCodes expiresAt }`
and `revokeMyOAuthAuthorization(clientId: String!): Boolean!`.
Both require login and derive ownership from the authenticated user; they accept no user ID.
The Nuxt Light user settings page `/User/setting/oauth` lists active authorizations per application.
Revocation disables all of that user's access tokens, linked refresh tokens and authorization codes
for the selected client, including refresh tokens whose access token has expired.
The application must obtain a new authorization. Other users' grants and the OAuth client remain intact.
The response contains no token values or client secrets. No administrator permission is required.

## Tests

```bash
composer test
# Include local Light application/bootstrap integration:
LIGHT_SOURCE_PATH=/path/to/light composer test
# Include MySQL storage checks:
OAUTH_TEST_DSN='mysql:host=127.0.0.1;dbname=test' \
OAUTH_TEST_USER=... OAUTH_TEST_PASSWORD=... \
LIGHT_SOURCE_PATH=/path/to/light composer test
```

MySQL persistence and replay tests use connection-local temporary tables. The two-process
refresh race test uses one uniquely named client in the configured test database, removes
its credentials and client afterwards, and verifies one exchange succeeds while the second
detects reuse and revokes the winning descendant. Use a dedicated test database. Optional
application bootstrap and browser-flow tests use the Light checkout's `.env` and database
when `LIGHT_SOURCE_PATH` is set, rolling back ORM transactions and removing temporary clients.
Tests also cover PKCE, code replay, refresh-family isolation, failed-exchange rollback,
legacy token rotation, expiry versus reuse, scope escalation, revocation, client binding,
resource audience, permissions, 2FA, consent, metadata and Light integration. Load testing
has not been run.
