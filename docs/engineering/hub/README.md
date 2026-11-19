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

Read the pages in the order of this table: each one uses terms that an
earlier one defines. Terms used across pages are collected in the
[Glossary](#glossary).

| Page | What it covers |
|---|---|
| [runtime.md](runtime.md) | The shared application core, runtime ports, the database backend, and how the native server and the Worker execute requests. |
| [tenancy-and-auth.md](tenancy-and-auth.md) | Organizations, projects, principals, the role ladder and scope grammar, credentials and authentication methods, and audit. |
| [topology.md](topology.md) | Goals, terminology, and invariants of the surface topology: surfaces, bindings, placements, routes, and their separation of effects. |
| [domain-model.md](domain-model.md) | The topology records and their identities. |
| [delivery.md](delivery.md) | Route matching, delivery modes, authorization, network-policy gates, direct and proxied serving, placement failover, webhook delivery, and replicated publication. |
| [registry-cache-relations.md](registry-cache-relations.md) | Consumer cache stacks, retention subscriptions, and population targets between registries and caches. |
| [retention-and-gc.md](retention-and-gc.md) | Release artifact snapshots, retention roots, and fail-closed cache garbage collection. |
| [configuration.md](configuration.md) | SQL configuration change-sets and revert, git-backed change requests, and webhook events. |
| [control-plane.md](control-plane.md) | The API, CLI, and web console parity contract, the plan/apply mutation protocol, CLI and browser authentication flows, and the checked manifests. |
| [topology-cutover.md](topology-cutover.md) | The signed evidence bundle for moving a deployment onto the topology model, the commands that generate and verify it, and the operator procedure it attests. |

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

## One router, three request classes

Both runtimes mount the same `axum` router from `aos-hub-service`
(`connect::router`, the web browse handlers, and the console router). It
serves three classes of request:

- the `aos.hub.v1` API as Connect-JSON: `POST /aos.hub.v1.{Service}/{Method}`
  with a JSON request body (`crates/hub/aos-hub-service/src/connect.rs`);
- machine delivery for registries and caches at their configured endpoints and
  routes, through the shared streaming serve paths
  ([delivery.md](delivery.md)); and
- the no-JS browse pages and JSON read API under `/{slug}/-/...`, the
  authentication ceremonies, and the console shell for management deep links
  ([control-plane.md](control-plane.md)).

Because the same code serves every request class on both runtimes, the native
server and the Worker cannot drift in application semantics; only their
storage, coordination, and scheduling adapters differ
([runtime.md](runtime.md)).

## Indexing

The indexer reads each registry's committed surface with
`aos-registry-format`, the same wasm-clean reader `apm` uses, verifies signed
tags and the trust roster fail-closed with anti-rollback floors, and replaces
the registry's derived SQL index only after verification succeeds. A failed
index preserves the previous successful state. The native server re-indexes on
its own schedule; the Worker's Cron and queue handlers schedule the same
indexer (`crates/hub/aos-hub-service/src/indexer/`).

## Glossary

The topology nouns (surface, binding, placement, write authority, domain,
network policy, endpoint, route, gateway, consumer cache stack, retention
subscription, population target, root reason) are defined in the
[terminology table](topology.md#terminology). The other terms the Hub pages
share are:

| Term | Meaning |
|---|---|
| Access token, access JWT, refresh credential | The three bearer credentials; defined in [tenancy-and-auth.md](tenancy-and-auth.md#credentials). |
| CAS | Compare-and-swap: a write that applies only if the row still has the version the writer read. In these pages CAS never means content-addressed storage. |
| Checked batch | One atomic database transaction that rolls back when a guarded statement affects an unexpected number of rows ([runtime.md](runtime.md#database-backend)). |
| Connect-JSON | The API transport: `POST /aos.hub.v1.{Service}/{Method}` with a JSON body. |
| CSRF | Cross-site request forgery; the browser session carries a CSRF token that the session-to-API exchange requires. |
| Durable Object | The Cloudflare Workers stateful object. The Worker's database is the `HubDb` Durable Object with colocated SQLite ([runtime.md](runtime.md#cloudflare-worker)). |
| Epoch (cache GC epoch) | A per-cache monotonic counter advanced by every mutation that can invalidate a collection; racing mutations from one epoch have one winner ([retention-and-gc.md](retention-and-gc.md#portable-cache-epoch)). |
| Fail closed | On missing, stale, or uncertain state, refuse the operation instead of proceeding. |
| Fence, fencing token | A fence makes writes from a superseded or unfinished owner fail. A fencing token is the value a lease holder must present to commit, so a holder whose lease was taken over cannot. |
| GC | Garbage collection of binary-cache objects, or of OCI blobs where a page says OCI GC. |
| Generation, revision | An immutable numbered version of a record. Other records pin an exact generation instead of following a mutable pointer. |
| JCS | JSON Canonicalization Scheme (RFC 8785), the canonical form the cutover bundle signs. |
| NAR, narinfo | A NAR is a Nix archive, the serialized contents of one store path. A narinfo is the small metadata file that names a store path's NAR, hash, and references. |
| OCI | Open Container Initiative. OCI routes serve the Distribution protocol for container images under `/v2`. |
| PHC string | The self-describing password-hash string format used for stored Argon2id hashes. |
| Plan/apply | The two-step mutation protocol: a plan returns a reviewed diff and confirmation hash, and apply executes exactly that plan ([control-plane.md](control-plane.md#one-api-three-clients)). |
| Seal, seal-gated | The deployment seal is a Worker secret. A seal-gated endpoint accepts only calls that carry it, which keeps the Worker's internal SQL endpoint unreachable from public requests ([runtime.md](runtime.md#shared-core-and-ports)). |
| SSRF | Server-side request forgery; the reason outbound URLs and storage origins are validated before the Hub connects to them. |
| Tombstone | The retained logical record of a collected cache object, kept until its physical deletions are confirmed or abandoned. |
