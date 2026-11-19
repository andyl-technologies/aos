# AOS Hub

AOS Hub hosts AOS package registries and Nix binary caches for many
organizations. It indexes signed registry surfaces fail-closed, serves their
git, Nix-cache, OCI, and image bytes through configurable routes, manages
identities, credentials, storage, and delivery topology, and coordinates
authenticated publication. It runs as a native server or as a Cloudflare
Worker from the same application code and database schema. The Hub is a
transport and index: it never becomes a trust root for registries whose keys
maintainers hold.

Operator guides are in [Operate AOS Hub](../../users/aos-hub/README.md); the
registry protocol the Hub indexes and serves is described in
[`../registry/`](../registry/README.md).

## Pages

| Page | What it covers |
|---|---|
| [runtime.md](runtime.md) | The shared application core, runtime ports, the database backend, and how the native server and the Worker execute requests. |
| [tenancy-and-auth.md](tenancy-and-auth.md) | Organizations, projects, principals, the role ladder and scope grammar, authentication methods, and audit. |
| [configuration.md](configuration.md) | SQL configuration change-sets and revert, git-backed change requests, and webhooks. |
| [topology.md](topology.md) | Goals, terminology, and invariants of the surface topology: surfaces, bindings, placements, routes, and their separation of effects. |
| [domain-model.md](domain-model.md) | The topology records and their identities. |
| [delivery.md](delivery.md) | Route matching, delivery modes, authorization, network-policy gates, direct and proxied serving, and replicated publication. |
| [registry-cache-relations.md](registry-cache-relations.md) | Consumer cache stacks, retention subscriptions, and population targets between registries and caches. |
| [retention-and-gc.md](retention-and-gc.md) | Release artifact snapshots, retention roots, and fail-closed cache garbage collection. |
| [control-plane.md](control-plane.md) | The API, CLI, and web console parity contract, the plan/apply mutation protocol, and the checked manifests. |
| [topology-cutover.md](topology-cutover.md) | The one-shot migration of an older deployment and its signed evidence bundle. |

## Crates

| Crate | Responsibility |
|---|---|
| `crates/hub/aos-hub-model` | IO-free, wasm-clean domain types: tenancy and the authorization kernel, credentials, delivery paths and HTTP semantics, endpoints, retention selectors, webhook events, and cache metadata. |
| `crates/hub/aos-hub-db` | Schema migrations, typed queries organized by capability, the async `Backend` trait, and native SQLx drivers. |
| `crates/hub/aos-hub-service` | Runtime-neutral application services: authorization, indexing, storage coordination, authentication flows, Connect handlers, and server-rendered pages. |
| `crates/hub/aos-hub-api` | Generated messages, ProtoJSON codecs, and Connect descriptors from `api/proto/aos/hub/v1/hub.proto`, plus the checked API and capability manifests in `contracts/`. |
| `crates/hub/aos-hub-client` | Native API client and OAuth login, device authorization, and token refresh, used by `aos hub`. |
| `crates/hub/aos-hub-ui` | Navigation, canonical settings routes, and presentation types shared by the console and service. |
| `crates/hub/aos-hub-console` | The WebAssembly browser console. |
| `crates/hub/aos-hub-native` | The `aos-hub` executable and native database, network, and filesystem adapters. |
| `crates/hub/aos-hub-worker` | The Cloudflare Worker deployment, Durable Object database bridge, and platform adapters. |

The model has no database or HTTP dependency; the database crate implements
persistence over model values; the service coordinates operations through
database and runtime ports; native and Worker adapters supply the platform
implementations. The database does not depend on the service, and native
database drivers compile only for native targets, so the model and the shared
service code also build for `wasm32-unknown-unknown`.

## One router, three surfaces

Both runtimes mount the same `axum` router from `aos-hub-service`
(`connect::router`, the web browse handlers, and the console router). It
serves:

- the `aos.hub.v1` API as Connect-JSON: `POST /aos.hub.v1.{Service}/{Method}`
  with a JSON request body (`crates/hub/aos-hub-service/src/connect.rs`);
- machine delivery for registries and caches at their configured endpoints and
  routes, through the shared streaming serve paths
  ([delivery.md](delivery.md)); and
- the no-JS browse pages and JSON read API under `/{slug}/-/...`, the
  authentication ceremonies, and the console shell for management deep links
  ([control-plane.md](control-plane.md)).

Because the same code serves every surface on both runtimes, the native server
and the Worker cannot drift in application semantics; only their storage,
coordination, and scheduling adapters differ ([runtime.md](runtime.md)).

## Indexing

The indexer reads each registry's committed surface with
`aos-registry-format`, the same wasm-clean reader `apm` uses, verifies signed
tags and the trust roster fail-closed with anti-rollback floors, and replaces
the registry's derived SQL index only after verification succeeds. A failed
index preserves the previous successful state. The native server re-indexes on
its own schedule; the Worker's Cron and queue handlers schedule the same
indexer (`crates/hub/aos-hub-service/src/indexer/`).
