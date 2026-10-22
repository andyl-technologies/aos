# AOS Hub

Hub hosts package registries and binary caches, manages access and credentials,
and coordinates artifact publication and delivery. It runs as a native service
or a Cloudflare Worker. Both deployments use the same application code and
database schema; the browser console calls the Hub API.

## Crates

| Crate | Responsibility |
| --- | --- |
| [`aos-hub-model`](aos-hub-model/) | Domain types for tenancy, access control, credentials, delivery policy, webhook events, and cache metadata |
| [`aos-hub-db`](aos-hub-db/) | Schema migrations, typed database queries, and native SQLx backends |
| [`aos-hub-service`](aos-hub-service/) | Authorization, publication and indexing, authentication flows, API handlers, and server-rendered pages |
| [`aos-hub-api`](aos-hub-api/) | Generated messages, ProtoJSON codecs, and Connect descriptors from the canonical [`api/proto`](../../api/proto/) schemas |
| [`aos-hub-client`](aos-hub-client/) | Native API client and OAuth login, device authorization, and token refresh |
| [`aos-hub-ui`](aos-hub-ui/) | Navigation, routes, and presentation types shared by the console and service |
| [`aos-hub-native`](aos-hub-native/) | The `aos-hub` executable and native database, network, and filesystem adapters |
| [`aos-hub-worker`](aos-hub-worker/) | Cloudflare Worker deployment, Durable Object database bridge, and platform adapters |
| [`aos-hub-console`](aos-hub-console/) | WebAssembly browser console |

## How the pieces fit together

The model defines domain values without a database or HTTP server. The database
crate implements persistence using those values. The service coordinates
application operations through database and runtime interfaces. Native and
Worker adapters supply the platform-specific implementations.

The database does not depend on the service. The service does not depend on the
client. Native database drivers compile only for native targets, keeping the
model and shared application code available to the Worker deployment.

Database queries and service operations are organized by capability. Their tests
live with the crate that owns the behavior. Database fault-injection helpers
require the `test-fixtures` feature; production code uses typed mutations.

## Development

From the repository root, use the Cargo development shell for native tests:

```sh
nix develop --file cargo-shell.nix -c aos-dev cargo test \
  --manifest-path crates/Cargo.toml \
  -p aos-hub-model -p aos-hub-db -p aos-hub-service
```

The [Worker README](aos-hub-worker/README.md) describes its platform adapters and
deployment setup. The user guides cover [native deployment](../../docs/users/aos-hub/native.md)
and [Cloudflare deployment](../../docs/users/aos-hub/cloudflare.md).
