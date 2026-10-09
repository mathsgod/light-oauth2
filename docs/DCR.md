# Dynamic Client Registration (DCR)

This package implements an opt-in open public-client profile of
[RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html). It coexists with CIMD and
administrator-provisioned clients. It does not implement confidential-client registration,
software statement validation, initial access tokens, or RFC 7592 registration management.

## Enable

With `ProviderFactory::registerFromEnvironment($app)`:

```dotenv
OAUTH_ENABLED=true
OAUTH_DCR_ENABLED=true
OAUTH_SCOPES=client.list,invoice.list
```

For manual construction, pass `dcrEnabled: true` to `Config`. The store must implement
`ClientStore` with insert-only `createClient()`; otherwise provider construction fails.
`PdoStore` already supports this using the existing `oauth_clients` table. No migration
is needed. DCR is disabled by default, with no registration route or discovery field.

When enabled, discovery includes `registration_endpoint`, and the provider registers
`POST /oauth/register`. Issuer paths and custom `routePrefix` values are respected.
The registration endpoint is anonymous: it ignores native login cookies and Bearer
credentials. Applications must not replace the provider's auth factory with one that
requires user login on this route.

## Request

Use `Content-Type: application/json` and a JSON object:

```http
POST /oauth/register HTTP/1.1
Host: auth.example.com
Content-Type: application/json

{
  "client_name": "Codex",
  "redirect_uris": ["http://127.0.0.1/callback/example"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "client.list"
}
```

`token_endpoint_auth_method` must explicitly be `none`. RFC 7591 defaults omitted auth
methods to `client_secret_basic`, which this public-only registration profile rejects.
Omitted `grant_types` defaults to `authorization_code`; include `refresh_token` to enable
refresh. Omitted `response_types` defaults to `code`. Authorization code is required;
implicit, client credentials and token exchange cannot be registered here.

`redirect_uris` must contain 1–20 absolute HTTPS or HTTP loopback IP URLs. Fragments,
credentials, wildcards, whitespace and backslashes are rejected. Each URI is limited to
2048 bytes. HTTP `localhost` is not accepted for DCR database clients; use `127.0.0.1` or
`[::1]`. League allows varying ports for HTTP loopback IPs under RFC 8252, while preserving
host, path and query matching. Other callbacks require exact matching.

`scope` is a space-separated string, limited to scopes exposed by the provider. Omission
uses the exposed scopes. Actual token access still requires user permissions, requested
token scopes, mandatory S256 PKCE and browser consent. Client names are optional, at most
200 bytes, and default to `OAuth application`. Submitted client IDs, enabled/confidential
flags, hashes and unknown extensions cannot control the stored record and are ignored.
Software statements return `unapproved_software_statement`.

## Response and storage

Successful registration returns HTTP **201 Created**, JSON and `Cache-Control: no-store`
plus `Pragma: no-cache`. It includes the server-generated `client_id`, integer
`client_id_issued_at`, registered callbacks, client name, scopes, grant/response types and
`token_endpoint_auth_method: none`. No client secret or registration management token
is issued. The client uses this new ID for subsequent authorization/token requests.

The server creates an enabled public client using a random 192-bit identifier prefixed
with `dcr_`. Inserts never overwrite an existing record. Registered grants are enforced
during token authentication. Administrators can disable/delete clients through the existing
management API. Deleting a client revokes its credentials through the store's existing behavior.

Invalid metadata or callbacks return HTTP 400 with `invalid_client_metadata` or
`invalid_redirect_uri`. Unsupported content types return 415; bodies exceeding 16 KiB
return 413. All responses are JSON and marked no-store. Malformed requests never create
client records. The body is decoded and validated independently of browser/session input.

## Operations and clients

This is open registration, not proof that a client is trusted. Enable it only where
anonymous registration is intended. Apply rate limits at the application or reverse proxy
and monitor database growth. Every successful request creates a new record; this package
has no built-in rate limiter, quota, automatic expiry or cleanup job. The persisted
`registration_source: dcr` and `client_id_issued_at` fields can identify records for an
application-managed retention policy. Client names remain self-asserted.

For a Codex version supporting registration selection, remove any fixed OAuth client ID
from its server configuration, then use:

```bash
codex mcp login hostlink --scopes client.list --oauth-client-registration dcr
```

When both DCR and CIMD are enabled, the client selects its supported registration method;
there is no need to manually create its DCR client record.

## Resource registry

The custom `resources` metadata list selects administrator-registered, enabled resources. Omission grants only the default resource; metadata never creates new resource records. See [resource policy and registration examples](RESOURCES.md).
