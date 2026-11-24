# Hub runtime

The native server and the Cloudflare Worker run one application core,
`aos-hub-service`, over a small set of runtime ports. This page describes those
ports, the database backend, and how each runtime executes requests and
deferred work.

## Shared core and ports

`aos-hub-service` contains authorization, indexing, storage coordination,
authentication flows, Connect handlers, and server-rendered pages. It reaches
the platform only through ports, each implemented once per runtime. In the
Worker column, *seal-gated* means that the internal SQL endpoint accepts a
call only when it carries the deployment seal, a deployment secret
(`HUB_SEAL_KEY`), so no public request can reach it.

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
change fails closed instead of partially applying.

The schema is the ordered `MIGRATIONS` list in
`crates/hub/aos-hub-db/src/db/mod.rs`. Its first script, `schema.sql`, is the
baseline; each later script is one further schema version. On first use the
database applies every script beyond the recorded `schema_version` and refuses
a database whose version is newer than the build supports. Pending scripts and
the version marker commit in one transaction, which on the Worker is one
Durable Object transaction. MySQL DDL implicitly commits, so there the
database applies replay-safe statements one at a time, checks indexes through
the catalog, and advances a keyed singleton ledger after each complete
migration.

A `Backend` decorator can record per-statement timing when the timing feature
is enabled (`backend/timing.rs`).

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
(Seal-gated is defined under [Shared core and ports](#shared-core-and-ports).)
This keeps cross-resource constraints atomic while request parsing, response
construction, and provider I/O do not serialize behind unrelated resources.
SQL and administrative endpoints remain pinned to `HubDb`, and Cron and queue
handlers keep provider and network I/O outside its serialized request turn.

Because the `connectrpc` server runtime cannot target wasm, the API transport is
Connect-JSON over ordinary `axum` handlers on both runtimes, and the Worker
drives the router through a hand-written Workers-to-`axum` bridge. Bindings are
declared in `crates/hub/aos-hub-worker/wrangler.toml` and named in
`handlers::bindings`. Deployment is described in
[Deploy to Cloudflare](../../users/aos-hub/cloudflare.md) and
[AOS Hub deployment](../../maintainers/aos-hub-deployment.md).

### Worker outbound boundary

Code: the gateway's request and response envelopes are in
`crates/hub/aos-hub-service/src/egress_protocol.rs`; the gateway is the
`aos-hub-egress` binary in `crates/hub/aos-hub-native`.

Cloudflare Worker deployments use the platform Fetch API directly by default.
This is a complete Worker-only deployment: registry and cache placements,
OIDC, domain probes, mail relay, webhooks, and Cloudflare control-plane
observation require no VM or metal component. Cloudflare mediates outbound
connections; AOS additionally requires HTTPS and rejects URL credentials,
fragments, and literal non-global addresses before Fetch, constructs requests
from a closed method and header set, bounds redirects, forbids mutating
redirects, and forbids authenticated cross-origin redirects. Individual
consumers retain their request and response size limits.

Worker Fetch does not expose the connected peer address or allow AOS to pin a
validated DNS answer to a connection. An installation that requires those
stronger guarantees may configure the repository-owned `aos-hub-egress` router
with `HUB_EGRESS_GATEWAY_URL` and `HUB_EGRESS_GATEWAY_KEY`. The pair is
optional but atomic: neither may be configured alone. Selecting it routes all
outbound HTTP through that transport rather than creating inconsistent
per-feature paths. The runtime ignores a key that has been pre-staged without a
URL so the installer can use direct Fetch as a safe transition state; desired
configuration and generated Wrangler configuration never contain only half of
the pair. The staged-key state is used only during a first-install bootstrap;
router updates keep the existing router selected throughout rotation.

The repository packages the gateway as `aos-hub-egress`. It disables
environment proxies and automatic redirects, resolves all addresses at connect
time, rejects the whole DNS answer set if any address is non-global, and gives
reqwest only that validated set while preserving hostname SNI. Redirects are
bounded and revalidated per hop; mutating requests cannot redirect, and a
request carrying authorization cannot redirect across origins. Request,
response, redirect, connect, and total-request limits are closed constants.

The gateway rebuilds the response header set rather than forwarding it. It
signs the request nonce, final URL, connected peer IP, upstream status, and
timestamp. The Worker accepts bytes only when that signed response record is
fresh, nonce-bound, status-consistent, and names a global peer. Missing
configuration, an unavailable gateway, a stale record, an unknown peer, or a
signature failure fails closed. Gateway failures and logs never include target
URLs, presigned queries, authorization values, or bodies.

The gateway accepts each request nonce once:

- After authenticating the envelope and checking its timestamp, it atomically
  inserts the nonce into a durable strongly-consistent database before
  starting the upstream request.
- Every replica uses that same database, so the nonce primary key accepts each
  nonce once across replicas and process restarts.
- Replicated deployments use PostgreSQL; file-backed SQLite is valid only for
  a singleton gateway process.
- Expired rows may be reclaimed, but a live conflict always fails before an
  upstream side effect.

The deployment interface takes optional `--egress-gateway-url` and an
operator-provisioned `HUB_EGRESS_GATEWAY_KEY` encoded as one atomic
`KEY_ID:KEY` value. It never mints that key, and it installs the scoped
provider token separately. Whenever the optional transport is selected, the
installer first completes a fresh, mutually authenticated `/v1/challenge`.
The key and router are then installed in an order that never leaves half of
the pair selected:

- **Rotation.** Every router replica accepts the bounded current/next key-id
  overlap before the installer challenges the new router.
- **Existing deployment.** The installer stages the challenged overlap key
  while the existing router remains selected and publishes the new router URL
  only after every secret mutation succeeds.
- **First install.** The installer may publish a direct-Fetch bootstrap
  version, install the first complete secret set, and then select the router.
- **Retirement.** The old router id is removed only after the Worker has
  switched.

There is one egress abstraction and one selected transport.
