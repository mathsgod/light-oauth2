# Client ID Metadata Documents (CIMD)

CIMD is an opt-in public-client profile of the evolving
[OAuth Client ID Metadata Document specification](https://drafts.oauth.net/draft-ietf-oauth-client-id-metadata-document/draft-ietf-oauth-client-id-metadata-document.html).
It does not implement Dynamic Client Registration or asymmetric client authentication.

## Enable

With `ProviderFactory::registerFromEnvironment()`:

```dotenv
OAUTH_ENABLED=true
OAUTH_CIMD_ENABLED=true
OAUTH_SCOPES=client.list
```

With manual construction, set `cimdEnabled: true` on `Config` and continue registering
`OAuthProvider` as usual. The factory setting has no effect on manually constructed configs.
The default fetcher requires `ext-curl`, DNS resolution and direct public HTTPS egress.
It does not use environment HTTP proxies: DNS is validated and pinned to the connection.
A missing cURL extension fails provider startup when CIMD is enabled.

Discovery advertises `client_id_metadata_document_supported: true` only when enabled.
No schema migration or manually created `oauth_clients` row is required for URL clients.
Existing database clients retain priority, including disabled records; a remote document
cannot override a stored client. Credentials are still persisted in `oauth_credentials`.

## Client document

Serve the following at the exact HTTPS URL used as `client_id`:

```json
{
  "client_id": "https://client.example.com/oauth/client.json",
  "client_name": "Example application",
  "redirect_uris": ["http://127.0.0.1/callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "client.list"
}
```

The `client_id` must match exactly. Only public clients (`none`, also the default when
omitted), authorization-code/refresh grants and code responses are supported. Secrets
and key-based authentication metadata are rejected. Scope is intersected with server
permissions; when omitted it uses the server's configured scopes. User permission checks,
PKCE S256 and explicit browser consent remain required.

Callbacks must be HTTPS or HTTP loopback IPs; CIMD also accepts the exact `localhost`
hostname because Codex publishes it alongside its loopback IP callback. HTTP `localhost`
callbacks still require exact port matching; variable-port matching applies only to
loopback IPs. Metadata fetching continues to reject localhost and private addresses. League validates the exact callback except
for the variable port allowance for native loopback callbacks (RFC 8252); host, path and
query must still match. Wildcard callbacks are not supported.

The default fetcher allows only HTTPS URLs with a path and no credentials, fragment or
dot path segments. It rejects private/reserved IP addresses and DNS responses containing
any non-public address, pins DNS for the TLS connection, and disables redirects. Requests
have a 3-second connect timeout, a 5-second total timeout and a 64 KiB body limit. HTTP 200
and a JSON content type are required. No logos, key URLs or other document links are fetched.
Invalid or unavailable documents fail closed without returning their contents to the caller.

Valid normalized metadata is memoized in the provider's resolver for at most 60 seconds,
with a 100-entry bound. Errors are never cached. There is no persistent/shared HTTP cache
or conditional revalidation; short bounded memoization uses a local TTL rather than HTTP
cache headers. Use the provider's `validator()` when validating its tokens so it shares the
same CIMD resolver. Token validation, refresh, revocation and exchange-source checks resolve
the URL client too; metadata outages after memoization expires deny those operations.
A database override can disable a URL client locally. User authorization revocation also
continues to work without a client record.

The optional final `OAuthProvider` constructor argument `metadataFetcher` accepts a
`ClientMetadata\MetadataFetcher` for controlled environments and testing. Custom fetchers
must enforce equivalent transport/SSRF protections. Document validation remains in the
resolver. Remote metadata is self-asserted, not proof of a trusted publisher: names are
escaped and applications still need user consent. Operators should apply normal endpoint
rate limits, particularly on public authorization and token endpoints.

## Codex

Use a Codex version supporting CIMD, remove the manually configured
`mcp_servers.hostlink.oauth.client_id`, and any callback URL saved for that pre-registered
client. Keep the MCP URL/resource settings and, if desired, `callback_port`.

```bash
codex mcp login hostlink --scopes client.list --oauth-client-registration cimd
```

Codex can then use its hosted metadata document as the client ID. The callback-specific
CIMD form works without issuer-bound authorization responses; this package does not
advertise `authorization_response_iss_parameter_supported` as part of CIMD support.

## Resource registry

The custom `resources` metadata list selects administrator-registered, enabled resources. Omission grants only the default resource; metadata never creates new resource records. See [resource policy and registration examples](RESOURCES.md).
