# Hub runtime

The native server and the Cloudflare Worker run one application core,
`aos-hub-service`, over a small set of runtime ports. This page describes those
ports, the database backend, and how each runtime executes requests and
deferred work.

## Shared core and ports

`aos-hub-service` contains authorization, indexing, storage coordination,
authentication flows, Connect handlers, and server-rendered pages. It reaches
the platform only through ports, each implemented once per runtime:

| Port | Contract | Native | Worker |
|---|---|---|---|
| `Backend` (`aos-hub-db/src/backend/mod.rs`) | Async SQL execution with atomic batches | `sqlx` pools (SQLite; PostgreSQL and MySQL behind features) | `HubDb` Durable Object colocated SQLite (`sqldobackend.rs`), reached from execution shards over seal-gated remote SQL (`remotebackend.rs`) |
| Surface fetch and write (`fetch.rs`, `surface_write.rs`) | Read, list, and atomically write surface objects | Local filesystem or S3-compatible bindings | R2 and configured bindings |
| `KvStore` (`kv.rs`) | Hot, point-key, read-mostly state | Optional | Workers KV (`workerkv.rs`) |
| `Coordinator` (`coordinator.rs`) | Strictly serializable counters, leases, and floors | In-process `InMemoryCoordinator` | Coordinator Durable Object (`coordinatorobj.rs`) |
| `RateLimiter` (`ratelimit.rs`) | Per-class request budgets | In-memory limiter | Edge-local Rate Limiting bindings (`edgeratelimit.rs`) |
| `Queue` (`jobs.rs`) | Deferred post-write jobs | In-process runner | Cloudflare Queues (`workerqueue.rs`) |
| HTTP client and egress | Outbound OIDC, webhook, and provider calls | `reqwest` with DNS pre-check and validating resolver | Workers `fetch` or the optional authenticated egress gateway |

The authorization kernel, delivery-path grammar, credential validation, and
retention selectors are pure functions in `aos-hub-model`, so both runtimes make
identical decisions without sharing state.

## Database backend

`Backend` is the narrow waist between the typed `Database` methods and the SQL
engines. Every driver applies the dialect translation before executing SQL, so
one `Database` implementation serves SQLite, PostgreSQL, MySQL, and the Durable
Object:

```text
execute(sql, params).await        -> rows affected
execute_insert(sql, params).await -> last auto-increment id
query(sql, params).await          -> Vec<Row>
query_opt(sql, params).await      -> Option<Row>
execute_batch(ddl).await          -> ()   (migration scripts)
batch(&[Statement]).await         -> ()   (one atomic transaction)
checked_batch(&[CheckedStatement])-> ()   (atomic row-count assertions)
```

`checked_batch` rolls the whole transaction back when a guarded statement
affects an unexpected number of rows; multi-row mutations use it so a concurrent
change fails closed instead of partially applying. Migrations live in
`crates/hub/aos-hub-db/src/db/schema.sql` and run on first use. A `Backend`
decorator can record per-statement timing when the timing feature is enabled
(`backend/timing.rs`).

## Hot state off the relational path

Request hot paths avoid a relational round-trip where they can:

- **KV read-through cache.** Sessions, API-token resolutions, instance
  settings, the host-to-registry routing table, and trust rosters are cached in
  a `KvStore` with a short TTL and invalidated on write (`cache.rs`). When no KV
  binding is attached the service reads the database directly. The eventual
  consistency is bounded by `HOT_TTL_SECS`.
- **Coordinator.** Rate-limit windows, the per-registry publish lease, and
  channel anti-rollback floors need strict serializability, which KV cannot
  provide. They use the `Coordinator` port: a single Durable Object instance on
  the Worker, an in-process map on a single native process.
- **Edge rate limiting.** On the Worker, request budgets use Cloudflare's
  edge-local Rate Limiting bindings (`limit({key})`), which add no network hop
  to reads; the coordinator Durable Object backs only the publish lease, whose
  hop is paid on publish, never on read.

## Deferred work

A write commits its durable state and defers expensive propagation —
regenerating a machine surface, rebuilding the global directory projection,
delivering webhooks, and re-indexing — to the `Queue` port. A `Job` is a
wire-free JSON value, so both runtimes produce the same jobs and consume them
with the same handlers. The anonymous instance home is served from the
directory projection that a `RebuildDirectory` job maintains in KV, avoiding a
per-registry fan-out on every visit.

## Native server

`aos-hub` (`crates/hub/aos-hub-native`) is an `axum` and `tokio` binary. A
single process, a SQLite database, and local or S3-compatible bindings form a
complete Hub; local-first operation, including `aos-hub serve --dev`, needs no
external service. Native-only capabilities include direct database
administration through `aos-hub`, NAR listing for the browse UI (`narlist.rs`),
and Prometheus metrics at `/metrics`.

## Cloudflare Worker

`aos-hub-worker` compiles to `wasm32-unknown-unknown` with `workers-rs`. Its
outer `fetch` handler assigns each public request to a deterministic execution
Durable Object (`requestshard.rs`): a control singleton for instance-wide work,
or a tenant, registry, or cache shard. A shard bridges the request to the shared
router (`bridge.rs`) and makes only short, seal-gated SQL calls to `HubDb`,
the single transactional system of record; it never copies relational state.
This keeps cross-resource constraints atomic while request parsing, response
construction, and provider I/O no longer serialize behind unrelated resources.
SQL and administrative endpoints remain pinned to `HubDb`, and Cron and queue
handlers keep provider and network I/O outside its serialized request turn.

Because the `connectrpc` server runtime cannot target wasm, the API transport is
Connect-JSON over ordinary `axum` handlers on both runtimes, and the Worker
drives the router through a hand-written Workers-to-`axum` bridge. Bindings are
declared in `crates/hub/aos-hub-worker/wrangler.toml` and named in
`handlers::bindings`. Deployment is described in
[Deploy to Cloudflare](../../users/aos-hub/cloudflare.md) and
[AOS Hub deployment](../../maintainers/aos-hub-deployment.md).
