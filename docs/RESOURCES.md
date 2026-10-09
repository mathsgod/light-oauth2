# Resource registry and direct API authorization

The authorization server can issue tokens directly for GraphQL APIs, MCP services or other registered services. Each grant selects one resource; token exchange is optional.

## Database resource policy

1. Apply `migrations/001_oauth.sql` if this is a new installation, then `migrations/002_oauth_resources.sql` using the application's migration runner.
2. Register the trusted resources and their scopes with `ResourceStore::createResource()`. See `examples/register-resources.php`. Resource scopes must be drawn from the provider's exposed permission scopes.
3. Set each existing client's `resources` array in its `oauth_clients.record` JSON. A client without this field is restricted to the default `OAUTH_RESOURCE`; no client implicitly gains every registered resource. Preserve the rest of each client record, including its secret hash.
4. Configure the issuer and default/API resource identities:

```dotenv
OAUTH_ISSUER=https://isapi.hostlink.com.hk
# Default audience for requests/legacy credentials that omit resource:
OAUTH_RESOURCE=https://mcp.hostlink.com.hk/mcp
# Identity of the GraphQL resource server, not an authorization allowlist:
OAUTH_API_RESOURCE=https://isapi.hostlink.com.hk/
OAUTH_SCOPES=client.list,quotation.list,invoice.list
```

Only enabled database resources are accepted. Environment resource URLs do not bypass database policy. Additional services can be registered in the DB without changing environment settings. Resource identities are exact URLs: `https://isapi.hostlink.com.hk/` and `https://isapi.hostlink.com.hk` are different identifiers. Resource URLs are immutable; create a new record and update clients to move to a different identity.

`oauth_resources` uses a SHA-256 primary key and keeps the exact URL (`id`), display name, scope list and enabled state in its JSON record. Client associations are a `resources` URL list in the existing client JSON, so no separate join table is needed. Custom stores must implement `Contract\ResourceStore`.

Resource management and database policy are always available when OAuth is enabled. Existing installations must apply migration 002 and register trusted resources before upgrading. Environment URLs identify audiences; they do not create resource records or bypass database policy.

## Management GraphQL

OAuth registers these operations (a frontend management page is outside this package):

| Operation | Required permission |
| --- | --- |
| `oauthResources`, `oauthResourceScopes` | `oauth_resource.list` |
| `createOAuthResource(input: OAuthResourceInput!)` | `oauth_resource.add` |
| `updateOAuthResource(input: OAuthResourceInput!)` | `oauth_resource.update` |
| `deleteOAuthResource(id: String!)` | `oauth_resource.delete` |

The `oauthClientResourcePolicy` query (requiring `oauth_client.list`) returns `enabled`, `defaultResource` and the resource catalog for client resource selectors. It does not grant resource-management rights. The provider adds an `/OAuthResource` menu entry when OAuth is enabled; the frontend page is supplied by `nuxt-light`.

All require login. Resource permissions are registered with Light but are not granted automatically. The resource input and output fields are `id`, `name`, `scopes`, `enabled`.

```graphql
mutation {
  createOAuthResource(input: {
    id: "https://isapi.hostlink.com.hk/"
    name: "Hostlink GraphQL API"
    scopes: ["client.list", "quotation.list", "invoice.list"]
    enabled: true
  }) { id name scopes enabled }
}
```

`OAuthClientInput.resources` assigns a list of registered, enabled resources; `OAuthClient.resources` exposes explicit assignments. Omission on update preserves an existing assignment. Omission on creation assigns only the default resource. For legacy client records the output list is empty until explicitly assigned, but the effective policy is default-only. Manual client scopes must be allowed by at least one selected resource; an individual grant is constrained by its chosen resource.

## DCR and CIMD

This package's custom `resources` metadata extension is a list of resource URLs, accepted in both DCR registration JSON and CIMD metadata documents. It is not a standard RFC 7591 metadata field and third-party clients are not required to send it.

```json
{
  "redirect_uris": ["http://127.0.0.1:8888/callback"],
  "token_endpoint_auth_method": "none",
  "resources": ["https://isapi.hostlink.com.hk/"],
  "scope": "client.list"
}
```

For CIMD, also provide the exact metadata-document URL as `client_id`. Unknown, disabled, empty or malformed resource lists are rejected. Omission selects the default resource. DCR saves the validated association in the new client record and returns it in the registration response. CIMD resolves the association in memory and never converts a remote document into a trusted DB registration. Neither creates resources automatically. The actual `/oauth/authorize` request must select a resource permitted by the client metadata.

An omitted registration scope defaults to the intersection of the selected resources' scopes and provider scopes. DCR rejects explicit scopes outside that set; CIMD narrows metadata scopes to that set. The eventual grant also requires the user's current permissions and consent.

## Direct GraphQL access

1. Open `/oauth/authorize` with the registered client ID and redirect URI, `response_type=code`, `scope=client.list`, `resource=https://isapi.hostlink.com.hk/`, a random state and an S256 PKCE challenge.
2. After login and consent, validate state and exchange the code at `/oauth/token` with `grant_type=authorization_code`, client authentication as applicable, the same redirect URI and the PKCE verifier. Omit resource or send the same resource as the authorization.
3. Send the access token to the API GraphQL endpoint in `Authorization: Bearer <access_token>`.
4. Refresh with `grant_type=refresh_token`, client authentication as applicable and the refresh token. Omit resource or send the original resource.

The effective scopes are the intersection of resource scopes, client scopes, provider-exposed scopes, current user permissions and the consent selection. Code and refresh redemption recheck current resource policy and client assignments. Audience selection is bound to the code and refresh records; a request cannot switch resource during redemption or refresh.

An API must validate its own audience, not accept every audience in the resource table. The built-in GraphQL authentication uses `OAUTH_API_RESOURCE`, falling back to `OAUTH_RESOURCE`. Other services should construct `TokenValidator` with their own audience and a shared registry policy. For custom server code, pass the registry constructed with the original authorization-server config into `TokenValidator` so legacy default-only client assignments retain the same meaning across services.

## Policy changes and token exchange

Disabled/deleted resources and removed client associations make existing tokens unusable, not just new requests. Removing a resource scope narrows the scopes of existing tokens immediately at validation. Refreshing with removed scopes fails; clients may request the remaining subset or reauthorize. Resource deletion does not physically erase credentials; recreating the same resource can restore still-valid tokens. Use credential revocation when permanent invalidation is required.

MCP-to-API exchange requires enabled source and target resources, a confidential client authenticated with its secret and assigned to both resources, and scope narrowing. No separate exchange policy is needed. See [token exchange](TOKEN_EXCHANGE.md). Direct API access remains available without an exchange request.

## Legacy credentials

Keep `OAUTH_RESOURCE` unchanged during rollout while legacy credentials remain active. Legacy codes without a resource field stay bound to that default. Legacy refresh tokens recover their resource from the associated access-token record, falling back to the default for older records without resource metadata. Existing refresh replay protection continues to apply.

This implements multiple registered resources with one selected audience per grant, rather than a single grant covering several resources. Repeated resource parameters and array values in authorization/token requests are rejected. See [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html).
