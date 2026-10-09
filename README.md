# mathsgod/light-oauth2

OAuth 2.0 Authorization Code + S256 PKCE integration for Light, powered by League OAuth2 Server. PHP 8.3+; PHPUnit 12 development tests require PHP 8.3+.

## Implemented

- Authorization Code with mandatory S256 PKCE and state; exact registered redirect URI validation through League.
- Public and confidential pre-registered clients, hashed confidential-client secrets.
- Opt-in Client ID Metadata Documents (CIMD) for URL-based public clients without manual registration.
- Opt-in RFC 7591 Dynamic Client Registration (DCR) for public PKCE clients at `/oauth/register`.
- Access tokens, rotating refresh tokens, single-use codes and token revocation.
- MySQL/MariaDB storage with transactional token exchange and row locks to serialize credential reuse.
- Authorization-server and protected-resource metadata responses.
- Resource-specific JWT audience, issuer validation, expiry/signature/revocation validation.
- Database resource registry with per-resource scopes, client assignments and permission-protected GraphQL management.
- Light authentication adapter and permission scopes. Effective rights require token scope, client-allowed scope, OAuth-exposed scope and the user's current permission.
- Default Light login/2FA and consent pages, with customizable `AuthorizationFlow`.
- RFC 8693 access-token exchange with confidential-client authentication, registered source/target resource assignments and scope narrowing.

This package does not supply confidential-client DCR, RFC 7592 registration management, OpenID Connect, or a complete Codex-to-MCP-to-GraphQL deployment. Those application integrations remain separate. Each authorization selects one configured resource. See [direct API authorization and resource binding](docs/RESOURCES.md). Token exchange uses confidential-client resource assignments and scopes; no separate exchange policy is needed.

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

For direct client access to GraphQL, see [resource selection](docs/RESOURCES.md).

For service-to-service access on behalf of a user (including MCP to GraphQL), see [access-token exchange](docs/TOKEN_EXCHANGE.md).

Light GraphQL applications can set `OAUTH_API_RESOURCE` for the API token audience. Token exchange accepts explicitly requested targets assigned to the authenticated confidential client. `ProviderFactory::registerFromEnvironment($app)` installs the built-in token validation and scope-aware authentication; no application auth factory override is needed.

1. `composer install`.
2. Apply `migrations/001_oauth.sql` through the application's migration runner. Also apply `migrations/002_oauth_resources.sql`, register trusted resources and assign clients before enabling OAuth; see [resource setup](docs/RESOURCES.md).
3. Create separate OAuth RSA keys outside the web root, and a random encryption key of at least 32 characters. Keep all keys out of source control. Use HTTPS outside loopback development.
4. Configure the environment and use `ProviderFactory::registerFromEnvironment($app)` with the built-in login/consent flow, or construct `Config`, `PdoStore`, a permission provider and an `AuthorizationFlow` manually.
5. Register database clients once; see `examples/register-client.php`. Store only `password_hash()` output for confidential-client secrets. Public clients can instead use opt-in [DCR](docs/DCR.md) for automatic registration, or [CIMD](docs/CIMD.md) without a database client record.
6. Register the provider before running Light.

Do not share the OAuth PDO connection with an already-open application transaction. The package does not apply migrations or provision database clients/resources automatically. Resource policy is always enabled; custom stores must implement `Contract\ResourceStore`.

## Routes

| Method | Route | Purpose |
| --- | --- | --- |
| GET / POST | `/oauth/authorize` | Validate OAuth parameters and delegate login/2FA/consent to the application |
| POST | `/oauth/token` | Form-encoded authorization-code, refresh-token or RFC 8693 token exchange |
| POST | `/oauth/register` | Opt-in public client registration (DCR); accepts JSON |
| POST | `/oauth/revoke` | Revoke a client-owned access or refresh token |
| GET | `/.well-known/oauth-authorization-server` | Authorization server discovery |

Issuer paths are appended to the authorization-server well-known route. The configurable route prefix is `/oauth` by default. `metadata()` and `protectedResourceMetadata()` also return PSR-7 responses for integrations that mount routes independently. Register OAuth routes once; do not also define conflicting `pages/oauth/*.php` routes.

Revoking a refresh token also revokes its associated access token. Revoking an access token alone does not revoke all related refresh tokens. Use the repository/store revocation methods for administrative revocation by identifier.

## Login, 2FA and consent

The default `BrowserAuthorizationFlow` provides password/2FA login followed by a consent page with checked scope checkboxes. Users may uncheck permissions before allowing access, or deny the request. At least one scope must remain selected when scopes are offered. To customize this flow, implement `AuthorizationFlow::resolve()`:

- Return a PSR-7 response to show or redirect to login, 2FA or consent.
- Return `AuthorizationDecision($userId, $approved, $authenticationComplete)` only after checking the user's session and required second factor.
- Bind the pending authorization request to the browser session. Preserve validated OAuth parameters across redirects; do not trust hidden form fields or browser-supplied user IDs/2FA flags.
- Validate a separate CSRF token for consent POSTs. OAuth `state` is the client's correlation value and does not replace server-side consent CSRF protection.
- After login/2FA, resume authorization using the original validated query parameters. Only an approved decision with completed authentication issues a code.

The package trusts this application contract; the decision boolean is not itself proof of 2FA. OAuth code generation rechecks client/user scopes, and token exchange/refresh rechecks them again. Login failure, incomplete 2FA and denied consent do not create codes.

### Automatically select scopes when omitted (1.0.4)

Enable this behavior in the application's environment:

```dotenv
OAUTH_AUTO_SELECT_SCOPES=true
OAUTH_SCOPES=client.list,quotation.list
```

`ProviderFactory` reads the setting automatically. For manual setup, pass `autoSelectScopes: true` to `Config`. The default is `false` for compatibility. Scopes default to Light’s registered, concrete permissions (wildcards are excluded). Set `OAUTH_SCOPES` to optionally restrict that catalog; unregistered permissions are never exposed. Scopes do not grant permissions to users or clients.

Only an authorization request **without a `scope` parameter** selects scopes automatically. Clients can omit `scope` from `/oauth/authorize`; they must still supply the usual client, redirect URI, state, and S256 PKCE parameters. After authentication, the server selects the intersection of the provider's registered permission catalog (optionally restricted by `OAUTH_SCOPES`), the resolved client's allowed scopes (including CIMD/DCR clients), and the user's current permissions. An empty intersection returns `invalid_scope`. Explicit scopes keep the existing strict validation; an explicitly empty `scope` does not enable automatic selection.

The built-in browser flow displays eligible scopes as checked checkboxes. Users may grant any nonempty subset. The offered scope list is bound to the pending browser session; if eligibility changes before approval, the flow requires a new consent page. Malformed selections and scopes outside the offered list are rejected. Authorization codes, access tokens, and refresh tokens retain only the approved subset. Token issuance, refresh, and exchange still perform their normal permission checks.

Custom `AuthorizationFlow` implementations must support this opt-in before enabling it. Once the user has completed authentication and required second factors, select scopes before displaying consent:

```php
$automatic = $request->getAttribute(\Light\OAuth2\AutomaticScopes::class);
if ($automatic instanceof \Light\OAuth2\AutomaticScopes) {
    $automatic->select($authorization, $userId);
}
// Render $authorization->getScopes() and bind their identifiers to consent.
```

Repeat selection on the consent POST, validate CSRF and the authenticated session, and redisplay consent if the selected scope identifiers differ from those shown. To support individual scope selection, call `ConsentScopes::apply($authorization, $submittedScopes)` after checking consent. It validates the selection against the scopes currently on the authorization and replaces them with the selected subset; reject empty selections when scopes were offered. Return an approved `AuthorizationDecision` only after these checks. The provider rejects automatic-scope approval if the flow has not selected scopes for that user. This request-local helper is supplied only when automatic selection is enabled and `scope` was omitted.

## Resource authentication and MCP

Use `$provider->validator()->validate($request)` to obtain a `TokenContext`; use `$context->can($right, $permissions)` before exposing protected data. A successful JWT validation alone does not authorize an operation.

`Config::resource` defines token audience, not the OAuth client ID. `client_id` is recorded separately. Authorization-code and refresh-token requests accept only this configured resource. With RFC 8693 enabled, token-exchange requests can select an explicitly allowed downstream resource. If the MCP server and GraphQL are distinct OAuth resources, use [token exchange](docs/TOKEN_EXCHANGE.md); do not forward a token addressed only to MCP into GraphQL.

An MCP service must host its own protected-resource metadata and return the appropriate `WWW-Authenticate` resource metadata challenge. This PHP package does not update the Node MCP server. Codex can use a pre-registered client ID or, when enabled, [DCR](docs/DCR.md) or [CIMD](docs/CIMD.md). For pre-registered clients, register the complete callback URL shown by Codex, including its path. League permits variable ports for HTTP loopback IP callbacks under RFC 8252; the host, path and query must still match. Other callbacks require exact matching. No wildcard redirect URIs are accepted.

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
`OAUTH_ENCRYPTION_KEY` and optional comma-separated `OAUTH_SCOPES`, and uses the Light
`DATABASE_*` settings with a dedicated PDO connection. Optional settings are
`OAUTH_CIMD_ENABLED`, `OAUTH_DCR_ENABLED`, `OAUTH_API_RESOURCE` and
`OAUTH_TOKEN_EXCHANGE_TTL`; see [.env.example](.env.example). The default browser flow
reuses Light password and required 2FA checks, with explicit consent, one-time
CSRF protection and CSP allowing the validated callback origin.

An application may supply its own `AuthorizationFlow` as the optional second
argument to `registerFromEnvironment($app, $flow)` to customize the login and
consent pages. The default page implementation lives entirely in this package.

## URL-based public clients (CIMD)

Enable CIMD with `OAUTH_CIMD_ENABLED=true` when using `ProviderFactory`, or add
`cimdEnabled: true` when constructing `Config` manually. It is disabled by default.
The built-in fetcher requires `ext-curl` and direct public HTTPS egress.

A CIMD client uses its metadata document's HTTPS URL as `client_id`. The provider
fetches and validates that document to obtain the client name, callbacks and scopes;
no manually created `oauth_clients` record is required. Existing database records
retain priority, including disabled records. Only public clients with `none` token
endpoint authentication are supported; PKCE, user permissions and consent remain required.

Discovery advertises `client_id_metadata_document_supported` when enabled. Fetching
includes public-IP checks, DNS pinning, TLS verification, time/size limits and no
redirect following. Valid metadata is memoized in process for up to 60 seconds;
errors are not cached. CIMD does not add a DCR registration endpoint.

For Codex, remove the pre-registered `client_id` override to allow CIMD selection.
See [CIMD setup, metadata format, security and Codex login](docs/CIMD.md).

## Dynamic Client Registration (DCR)

Enable `OAUTH_DCR_ENABLED=true` through `ProviderFactory`, or `dcrEnabled: true` on
`Config`, to expose `POST /oauth/register` and advertise `registration_endpoint`.
DCR is off by default and requires a `ClientStore` such as `PdoStore`. It accepts JSON
registration for public clients with explicit `token_endpoint_auth_method: none`,
authorization-code/optional refresh grants, validated callbacks and exposed scopes.
The server creates the database record and returns a random client ID with HTTP 201.
PKCE and user login/consent remain mandatory. Apply application/proxy rate limits;
the package does not automatically expire registrations. See [DCR setup and limits](docs/DCR.md).

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
resource audience, permissions, 2FA, consent, metadata and Light integration. CIMD tests
cover document validation, SSRF address restrictions, database overrides, callback matching,
code/refresh flows, token revocation and exchange-source validation. Load testing
has not been run.

### Nuxt authorization UI

Keep the authorization endpoint on the API and let `@hostlink/nuxt-light` render login, the two-factor code field, scope checkboxes, and Allow/Deny. Opt in through `ProviderFactory`:

```dotenv
OAUTH_AUTHORIZATION_UI_URL=https://app.example.com/oauth/authorize
OAUTH_AUTO_SELECT_SCOPES=true
```

The API still validates `/oauth/authorize` before redirecting to the configured UI with a random, ten-minute `request_id`. Original OAuth parameters remain in the API's PHP browser session. The frontend uses `GET`/`POST /oauth/interaction?request_id=...` with cookies to obtain view data and submit login or consent. The API verifies the native login/2FA session, CSRF, current permissions, and selected scopes, then returns the validated client callback for top-level navigation. Completed interaction IDs cannot be replayed. The discovery `authorization_endpoint` does not change.

Configure the frontend's `light.oauth.apiBase` to the public API issuer URL. Use same-site frontend/API hosts (for example `app.example.com` and `api.example.com`), or the same loopback hostname on different ports for local development. Do not mix `localhost` and `127.0.0.1`. PHP sessions and Light's native authentication cookies must be usable on the API; retain the existing Light cookie/domain/TLS settings. The interaction endpoint allows credentialed CORS only from the configured UI origin and requires that origin on POST. Reverse proxies must forward the OAuth routes and cookies. Multi-instance APIs need their normal shared PHP session storage.

Manual setup can use `new FrontendAuthorizationFlow(new BrowserAuthorizationFlow($app), $config)` with `authorizationUiUrl` set on `Config`. `OAuthProvider::register()` mounts the interaction routes for this flow. With no UI URL, the existing PHP-rendered browser flow remains the default. Custom flows passed to the factory retain precedence.
