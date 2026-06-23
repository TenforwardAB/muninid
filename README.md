# MuninID

Go-based starting point for the MuninID Identity Provider. It is built to mirror the existing Node IDP as closely as practical while keeping the code small, explicit, and easy to continue from.

The current implementation uses:

- `chi` for HTTP routing and middleware.
- PostgreSQL through `pgx`.
- Goose SQL migrations through a separate migration command.
- The existing MuninID database tables where possible.
- `github.com/tenforwardab/wildduck-gosdk` from its tagged Go module release.
- The same `enc:v1` AES-256-GCM secret format as the Node IDP.
- RS256 JWT access/id tokens and JWKS.
- A Fosite dependency is included for the OAuth/OIDC migration path, but this first base keeps the endpoint behavior explicit instead of hiding it behind a large storage adapter.

## Status

Implemented:

- `/.well-known/openid-configuration`
- `/oauth/jwks.json`
- `/oauth/authorize`
- `/interaction/{uid}`
- `/interaction/{uid}/login`
- `/oauth/token`
- `/oauth/introspect`
- `/oauth/revoke`
- `/oauth/logout`
- `/userinfo`
- `/gui`
- `/gui/api/clients`
- `/gui/api/policies`
- `/gui/api/sps`
- `/api/global/admin/clients`
- `/api/global/admin/policies`
- `/api/global/admin/sps`
- `/api/admin/clients`
- WildDuck username/password authentication
- PKCE `S256` authorization code flow
- Refresh token flow
- Client credentials flow
- RFC 8693 access-token exchange with database policy checks and event logging
- Tenant-scoped client administration based on token claims
- Global SAML service provider admin CRUD
- Global identity policy admin CRUD
- Existing `oidc_clients`, `jwt_rsa256_keys`, `oidc_adapter_store`, and `login_attempts` tables

Scaffolded/not yet exact:

- SAML service provider records are persisted through admin CRUD, but no SAML runtime flow consumes them yet.
- Identity policy records are persisted through admin CRUD, but login/token policy enforcement is not wired yet.
- Token exchange is implemented for access-token to access-token exchanges; other token types are intentionally rejected.
- The Node `oidc-provider` interaction cookies are not binary-compatible. The Go service uses its own signed `idp.sid`.
- The current OAuth engine is explicit Go code; wiring Fosite as the token engine is the next hardening step if you want full RFC edge-case coverage.

## Run

```bash
cp .env.example .env
set -a
. ./.env
set +a

go run ./cmd/muninid
```

## Database Migrations

This repo includes Goose SQL migrations translated from the Sequelize migrations in:

```text
/home/andrek/dev/gits/muninid/src/migrations
```

Run migrations with:

```bash
DATABASE_URL=postgres://postgres:postgres@localhost:5432/muninid?sslmode=disable \
go run ./cmd/muninid-migrate up
```

Other Goose commands are passed through:

```bash
go run ./cmd/muninid-migrate status
go run ./cmd/muninid-migrate down
go run ./cmd/muninid-migrate redo
go run ./cmd/muninid-migrate version
```

You can also pass flags explicitly:

```bash
go run ./cmd/muninid-migrate \
  -database-url "$DATABASE_URL" \
  -dir ./migrations \
  up
```

The migration command uses Goose with Go's `database/sql` and the `pgx` stdlib driver. Runtime application queries still use plain `pgxpool` in `internal/store`.

The migrations create/maintain:

- `jwt_rsa256_keys`
- `oidc_adapter_store`
- `oidc_clients`
- `login_attempts`
- `saml_service_providers`
- `identity_policies`
- `token_exchange_policies`
- `token_exchange_events`
- `admin_audit_events`

The SQL uses the same timestamp-based versions as the Sequelize migrations and preserves the same mixed-case quoted column names expected by the current Go store and Node IDP. It also uses `IF NOT EXISTS`/guarded DDL where practical so a partially migrated development database is easier to recover.

If the Node IDP has already migrated a database, do not blindly run Goose `up` against production before reconciling `goose_db_version`. For a fresh Go-managed database, run Goose before starting the server.

## Configuration

Required environment variables:

- `DATABASE_URL`
- `WILDDUCK_API_URL`
- `WILDDUCK_API_TOKEN`
- `OIDC_COOKIE_KEYS`
- `IDP_SECRET_ENCRYPTION_KEY`

Useful optional variables:

- `HOST`, default `0.0.0.0`
- `PORT`, default `8080`
- `OIDC_ISSUER`, default `http://localhost:${PORT}`
- `CORS_ORIGINS`, comma-separated
- `OIDC_TRUSTED_CONSENT_DOMAINS`, comma-separated domains that auto-grant consent for first-party clients, default `muninid.local,mailtrix.eu`
- `ADMIN_API_KEY`, required for `/api/global/admin/*`
- `ENABLE_GUI`, set to `true` to enable the simple admin UI at `/gui`
- `MASTER_USER`, default `idp_admin`, used for `/gui` Basic Auth
- `MASTER_PASSWORD`, required when `ENABLE_GUI=true`

`IDP_SECRET_ENCRYPTION_KEY` must match the existing Node IDP value if you want this Go service to read existing encrypted client secrets and signing keys.

## Admin GUI

The old simple Node admin UI is available at:

```text
http://localhost:8080/gui
```

Enable it with:

```bash
ENABLE_GUI=true
MASTER_USER=idp_admin
MASTER_PASSWORD=change-me
```

The page and its backing `/gui/api/*` routes are protected with HTTP Basic Auth using `MASTER_USER` and `MASTER_PASSWORD`. The UI exposes the same resources as the Node view:

- `clients`
- `policies`
- `sps`

Client CRUD is wired to the Go admin store and returns newly generated client secrets on create or rotation. `policies` and `sps` are also wired to persistent admin CRUD for parity with the current Node IDP admin surface. They are intentionally records-only for now: policy enforcement and SAML runtime behavior are future integration work.

## Admin API

Global admin routes use `X-Admin-Api-Key`.

```bash
curl -H "X-Admin-Api-Key: $ADMIN_API_KEY" \
  http://localhost:8080/api/global/admin/clients
```

Create a client:

```bash
curl -X POST http://localhost:8080/api/global/admin/clients \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MuninID UI",
    "redirect_uris": ["http://localhost:5173/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "email", "account", "offline_access"]
  }'
```

Tenant admin routes use a bearer token with `roles` containing `idp_admin`, `admin`, or `superadmin`, and scope clients by `customer_id`.

Create an identity policy record:

```bash
curl -X POST http://localhost:8080/api/global/admin/policies \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "require-2fa",
    "target_type": "client",
    "policy": {"rule": "allow"}
  }'
```

Create a SAML service provider record:

```bash
curl -X POST http://localhost:8080/api/global/admin/sps \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "urn:example:sp",
    "acs": ["https://app.example.com/saml/acs"],
    "binding": "post",
    "attr_mapping": {"email": "mail"}
  }'
```

## Authorization Code Flow

The authorize endpoint requires PKCE `S256`, matching the stricter Node configuration:

```text
GET /oauth/authorize?
  response_type=code&
  client_id=...&
  redirect_uri=...&
  scope=openid profile email account offline_access&
  code_challenge=...&
  code_challenge_method=S256&
  state=...
```

If no `idp.sid` session exists, the user is redirected to:

```text
/interaction/{uid}
```

The login form authenticates with WildDuck, stores a signed session, issues an authorization code, and redirects back to the registered redirect URI.

## Token Endpoint

Supported grant types:

- `authorization_code`
- `refresh_token`
- `client_credentials`
- `urn:ietf:params:oauth:grant-type:token-exchange`

Client authentication supports:

- `client_secret_basic`
- `client_secret_post`

Refresh tokens are only issued for user authorization-code flows when both are true:

- the client has `refresh_token` in `grant_types`
- the requested/approved scope contains `offline_access`

The refresh grant is rejected for clients that do not have `refresh_token` in `grant_types`. Refresh tokens are rotated on use: a successful refresh deletes the old opaque refresh token and, when `offline_access` is still present, returns a new one.

Requested scopes are validated against the registered client scopes for authorization-code, refresh-token, and client-credentials flows. `client_credentials` requests default to all registered client scopes when no `scope` parameter is supplied.

Revocation supports both JWT access tokens and opaque refresh tokens. Introspection returns JWT access-token claims when active and can also report active refresh tokens for the authenticated owning client.

## Token Exchange

Token exchange is deliberately conservative. It only supports exchanging an access token for a new access token, and the authenticated client must:

- include `urn:ietf:params:oauth:grant-type:token-exchange` in its `grant_types`
- present a valid `subject_token` issued to the same client
- request exactly one `audience` or `resource`
- match an enabled row in `token_exchange_policies`
- request scopes that are already present on the subject token and allowed by the policy

Every successful or failed exchange attempt is written to `token_exchange_events`.

Example policy:

```sql
INSERT INTO token_exchange_policies (
  "clientId",
  priority,
  subject,
  "subjectTokenTypes",
  audiences,
  scopes,
  "actorTokenRequired",
  enabled,
  description
) VALUES (
  'your-client-id',
  100,
  '*',
  '["urn:ietf:params:oauth:token-type:access_token"]'::jsonb,
  '["https://api.example.com"]'::jsonb,
  '["openid", "profile", "email", "account"]'::jsonb,
  false,
  true,
  'Allow this client to exchange user access tokens for the API audience'
);
```

Example request:

```bash
curl -X POST http://localhost:8080/oauth/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$ACCESS_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=https://api.example.com" \
  -d "scope=openid profile email"
```

## Project Layout

```text
cmd/muninid/      executable entrypoint
internal/app/            router and middleware wiring
internal/config/         environment configuration
internal/handlers/       interaction and admin handlers
internal/idp/            OAuth/OIDC behavior, JWT/JWKS, WildDuck claims
internal/secret/         Node-compatible enc:v1 secret encryption
internal/store/          PostgreSQL access for existing IDP tables
migrations/              Goose SQL migrations matching Node Sequelize migrations
```

## Verification

```bash
GOCACHE=/tmp/muninid-gocache \
GOTMPDIR=/tmp/muninid-gotmp \
go test ./...
```

Current result:

```text
ok/build: all packages compile
```

## Licenses

MuninID is licensed under EUPL-1.2. Direct third-party dependency license texts are collected in `LICENSES/`

## Recommended Next Steps

1. Replace the explicit OAuth code path with a full Fosite storage implementation if strict RFC conformance is required.
2. Wire identity policy enforcement into login/token decisions.
3. Wire SAML service provider records into a real SAML runtime flow.
4. Add integration tests against a migrated MuninID database and a test WildDuck instance.
5. Add audit logging to `admin_audit_events`.
