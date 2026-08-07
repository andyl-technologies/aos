# Use the AOS Hub API

AOS Hub exposes unary, Connect-compatible JSON routes over HTTP. Requests use
JSON bodies and responses use JSON; clients do not need a gRPC runtime.

## Endpoint shape

Methods are mounted at:

```text
POST /aos.hub.v1.<Service>/<Method>
```

For example:

```sh
curl -fsS \
  -H 'Content-Type: application/json' \
  -d '{"slug":"acme/cdn"}' \
  https://hub.example.com/aos.hub.v1.RegistryService/GetRegistry
```

An empty request may be sent as `{}`. API errors use a JSON envelope with a
machine-readable `code` and a human-readable `message`.

The service families cover registries, organizations, projects, storage,
packages, channels, audits, instance settings, identity and access, webhooks,
publishing, Git surfaces, and binary caches. The complete request and response
schema is in
[`hub.proto`](../../../crates/aos-proto/src/proto/aos/hub/v1/hub.proto).

## Authentication

Public registry reads do not require authentication. Private reads and changes
require a bearer access token with the necessary permission:

```text
Authorization: Bearer <access-token>
```

The simple `/<flat-slug>/-/api/...` routes documented in the web guide are
always public-only: they do not use a browser session or bearer token, and the
current router accepts only single-segment slugs. Use the unary service routes
for canonical organization/registry paths and authenticated visibility.

Interactive clients start an RFC 8628 device grant with
`POST /oauth2/device_authorization`, show the returned verification URL and
user code, and poll `POST /oauth2/token` at the advertised interval. A
successful poll returns a one-hour access token and a rotating refresh
credential. `aos hub login` implements this flow:

```sh
aos hub login --hub https://hub.example.com
```

The device request uses `client_id=aos-cli`, an optional canonical stable
resource `scope`, and an optional space-separated `permission` value. Polling
uses grant type `urn:ietf:params:oauth:grant-type:device_code`. Refresh uses
grant type `refresh_token`; every successful refresh returns a replacement
refresh credential. Reusing a consumed credential revokes the complete family.
`POST /oauth2/revoke` accepts the refresh credential,
`client_id=aos-cli`, and `token_type_hint=refresh_token`.

Publishing automation may instead start with a provisioning token whose secret
begins with `aos_`. The Hub stores only its hash. Exchange it with the explicit
grant type `urn:aos:params:oauth:grant-type:provisioning-token` and the secret
as an `Authorization: Bearer` credential. A native operator can mint scoped
provisioning tokens with `aos-hub token mint`.

All OAuth credential responses carry `Cache-Control: no-store`. Native and
Cloudflare Worker deployments mount the same handlers and return the same
structured pending, slow-down, denial, expiry, and invalid-grant errors.

The current CLI and console do not provide an initial instance-admin bearer
token. Bootstrap administration through the local `aos-hub` command on native
deployments or the web console on either runtime. Treat administrative API
methods as integration points for clients that already have a suitably scoped
credential.

Browser authentication uses an opaque session cookie and is intentionally
separate from API bearer tokens.

Inspect a bearer without exposing its secret through
`IdentityService/WhoAmI`:

```sh
curl -fsS \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <access-token>' \
  -d '{}' \
  https://hub.example.com/aos.hub.v1.IdentityService/WhoAmI
```

The response identifies the live user or service account, lists current role
grants, and separately reports this token's scope, permissions, and expiry.

## Scripting

The remote client covers common calls and provides stable JSON output:

```sh
aos --json hub registry list --hub https://hub.example.com
aos --json hub registry get acme/cdn --hub https://hub.example.com
```

Pass `--token '<access-token>'` to commands that require authentication. Use
the schema when building a client or integration.
