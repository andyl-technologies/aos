# Use the AOS Hub API

AOS Hub exposes unary, Connect-compatible JSON routes over HTTP. Requests use
JSON bodies and responses use JSON; clients do not need a gRPC runtime.

## Endpoint shape

Methods are mounted at:

```text
POST /aos.registry.v1.<Service>/<Method>
```

For example:

```sh
curl -fsS \
  -H 'Content-Type: application/json' \
  -d '{"slug":"acme/cdn"}' \
  https://hub.example.com/aos.registry.v1.RegistryService/GetRegistry
```

An empty request may be sent as `{}`. API errors use a JSON envelope with a
machine-readable `code` and a human-readable `message`.

The service families cover registries, organizations, projects, storage,
packages, channels, audits, instance settings, identity and access, webhooks,
publishing, Git surfaces, and binary caches. The complete request and response
schema is in
[`registry.proto`](../../../crates/aos-proto/src/proto/aos/registry/v1/registry.proto).

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

Publishing automation starts with a provisioning token whose secret begins with `aos_`.
The Hub stores only its hash. Exchange it at `POST /oauth2/token` to obtain a
one-hour access token, or let `aos hub login` perform the exchange:

```sh
aos hub login \
  --hub https://hub.example.com \
  --provisioning-token '<aos_...>'
```

Keep the provisioning token in a secret store and exchange it again when the
short-lived access token expires. A native operator can mint read/publish
provisioning tokens with `aos-hub token mint`; the web console can mint the same
scoped tokens on either runtime.

The current CLI and console do not provide an initial instance-admin bearer
token. Bootstrap administration through the local `aos-hub` command on native
deployments or the web console on either runtime. Treat administrative API
methods as integration points for clients that already have a suitably scoped
credential.

Browser authentication uses an opaque session cookie and is intentionally
separate from API bearer tokens.

## Scripting

The remote client covers common calls and provides stable JSON output:

```sh
aos --json hub registry list --hub https://hub.example.com
aos --json hub registry get acme/cdn --hub https://hub.example.com
```

Pass `--token '<access-token>'` to commands that require authentication. Use
the schema when building a client or integration.
