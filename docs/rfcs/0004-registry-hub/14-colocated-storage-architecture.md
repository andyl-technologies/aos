# Colocated storage architecture — KV/LMDB, Durable Objects, and killing the D1 latency floor

- **Status:** Proposed (2026-06-25). Motivated by a production latency
  investigation of the deployed `aos-hub` Worker at `aos.andyl.org`; the
  measurements below are real (`wrangler tail` + black-box timing from the SJC
  colo). Carries its own phased implementation checklist at the bottom, ordered
  so it can be worked through item-by-item (goal-mode). Nothing here is
  implemented yet; the Phase A–B "hybrid" is designed to be the first slice and
  to leave nothing thrown away when the later phases land.
- **Builds on:** [`01-architecture.md`](01-architecture.md) (a control plane
  over a *static data plane* — this chapter extends "immutable + cached +
  colocated" from the data plane up into the control plane),
  [`10-unified-runtime.md`](10-unified-runtime.md) (the shared async `Backend`
  /`RateLimiter`/surface **ports**, one codebase on both targets — this chapter
  adds more ports in the same pattern), and
  [`12-storage-frontends.md`](12-storage-frontends.md) (bulk bytes already serve
  direct-from-bucket, not through the Worker).

## The measured problem

The deployed Worker has a per-request latency floor of ~150–300 ms on any path
that touches D1, far above what the data should cost. Grounded numbers:

- D1 reports **<1 ms p99 query execution**; the primary runs in **WNAM**
  (co-located with the serving SJC colo); read replication is **`auto`** (`d1
  info aos-hub`). So neither query execution nor cross-region distance explains
  the floor.
- `wrangler tail` (warm isolate, `wallTime − cpuTime` = I/O wait):

  | request | D1 ops | warm CPU | warm wall | min I/O wait |
  | --- | --- | --- | --- | --- |
  | `/login`, 404 (no D1) | 0 | 7 ms | 16 ms | ~9 ms |
  | `/` home (rate-limit write + ~3 reads) | ~4 | 7 ms | ~147 ms | ~140 ms |
  | `/{slug}/-/api/registry` (1 read, **no write**) | 1 | 8 ms | ~120 ms | ~120 ms |
  | `/{slug}/` browse | ~5–6 | 16–32 ms | ~315 ms | ~290 ms |

Three conclusions fall out, each of which overturns a plausible first guess:

1. **It is not compute / cold start / the per-request router rebuild.** Warm
   CPU is **7 ms** for the home page; a Worker that renders without touching D1
   (`/login`) returns in ~16 ms. The floor is **I/O wait on the D1 binding**.
2. **It does not scale with query count.** A *single* read (120 ms) is nearly as
   slow as the four-op home page (147 ms). The cost is a **per-request D1 floor**
   — the *first* statement pays ~120 ms; each additional statement in the same
   request adds only ~10 ms. Batching N→1 therefore saves ~10 ms/query, **not**
   the floor.
3. **The rate-limit write is not the dominant cost** — a write-free single read
   is just as slow. (Removing it is still correct; see below.)

The residual ~120 ms is the cost of opening/using the per-request D1
read-replication **session** (`open_session` → `with_session` in
`crates/aos-hub-worker/src/d1backend.rs`, one per request). This is D1's
documented property — *"application code and SQL database queries are not
colocated"* — surfacing as a real, unavoidable network hop per request that
replication narrows but does not remove.

A secondary correctness smell the investigation surfaced: the rate limiter is a
D1 **write** (`INSERT … ON CONFLICT … RETURNING` in
`crates/aos-hub-worker/src/workerlimit.rs`) that runs *first* on every
browse/home request (`browse_rate_limited`, `crates/aos-hub-core/src/web/browse.rs`),
sharing the request's single D1 session. A write in a read path forces every
later read in that session onto the read-your-writes path. **No writes belong on
read paths.**

## The principle

Colocate compute with state, and serve every read from an immutable,
edge-cached projection — so the *common* request makes **zero or one** hop to
stateful storage. The consumer data plane (NAR/narinfo/surface bytes on R2 +
edge cache, zero DB) already embodies this and is the proof it works; this
chapter extends the same pattern to the control plane (browse/RPC/auth) that
still makes live D1 calls. Match each data class to the storage primitive whose
consistency/write profile it actually needs, instead of routing everything
through one relational database that is not colocated with the request.

## Target architecture (layers)

1. **Consumer data plane — keep, extend.** Immutable content-addressed objects
   on R2, signed, edge-cached; no DB on the hot pull path. Extend the
   *immutable-and-regenerated* idea up to the browse surface (layer 2).
2. **Control-plane reads = event-regenerated static read models (ISR).** Browse
   HTML/JSON are pure functions of tenant state. Regenerate the affected pages
   on write and push them to the edge cache / R2; anonymous browse becomes a
   cache hit (zero DB). Only authed/personalized or cache-miss views fall
   through to the system of record.
3. **System of record = tenant-sharded, colocated SQLite.** One Durable Object
   (SQLite) per org/registry holds that tenant's relational state. Compute is in
   the same thread as storage → microsecond reads, full SQL, and **strict
   serializability** — which subsumes coordination: the publish lease, the
   channel anti-rollback floor, and per-tenant rate limiting become ordinary
   transactions inside the tenant's DO. No separate lock, no D1-write-to-primary,
   no KV write cap. Placement follows the tenant's audience; DO read replicas
   serve global readers. For a region-concentrated hub, even a *single* pinned
   DO is "D1 but colocated" and removes the 120 ms floor.
4. **Auth + ephemeral + routing = KV (Worker) / LMDB (native).** Point-key,
   read-mostly, sub-ms, edge-cached — and exactly what Cloudflare recommends KV
   for ("session data, credentials (API keys), and configuration data," "service
   routing metadata"). Must-be-instant revocation gets a short TTL + a
   revocation signal (or a tiny auth-authority DO consulted only on cache miss).
5. **Global directory & search = materialized projection.** Per-tenant DOs
   cannot answer "list all registries" or global search cheaply, so maintain a
   denormalized catalog (KV for the directory, a search index for search)
   updated on publish. The instance home reads the cached directory — no
   fan-out, no N+1. This is the one place eventual consistency is accepted, which
   is correct for a directory.
6. **Write pipeline = synchronous SoR + async fan-out via Queues.** A publish
   does one strongly-consistent transaction against the tenant DO (fast), then
   enqueues the expensive propagation — surface regeneration, directory/search
   projection, read-model + edge-cache invalidation, webhook delivery, indexing.
   "Reads very low latency; writes can be higher latency."

## Data classification (real tables → primitive)

**Bucket 1 — hot, point-key, read-mostly → KV (Worker) / LMDB (native).**

| table | access | note |
| --- | --- | --- |
| `sessions` | `WHERE id_hash = ?` | read per authed request; the `SESSIONS` KV is **already bound but unused** (`crates/aos-hub-worker/src/handlers.rs`), wrangler even comments "KV holds sessions" |
| `tokens` | `WHERE hash = ?` | API-key auth read path; D1 as source-on-miss |
| `instance_config` (+ site chrome) | singleton | already isolate-cached; belongs in KV |
| `frontends` (by `domain`) | host→registry routing | "service routing metadata" — the `rewrite_for_frontend` lookup |
| `key_rosters` | per-registry trust anchors | read on verify/browse |
| `oidc_flows`, `magic_links`, `device_codes`, `webauthn_challenges` | one-time, TTL | KV TTL fits; atomic single-use → bucket 2 |

**Bucket 2 — atomic / coordination / hot writes → Durable Object (Worker),
in-process/LMDB-txn (native). NOT KV** (KV caps at 1 write/s/key, no atomics).

| table | why |
| --- | --- |
| `rate_limits` | atomic increment + >1 write/s/key; D1 write hits primary every request |
| `publish_leases` | cross-isolate lock → needs strict serializability |
| `channel_floors` / `channel_partitions` | monotonic anti-rollback compare-and-set |

**Bucket 3 — relational / queried / reported → stay in D1 until layer 3, then
the tenant DO's SQLite.** orgs, users, memberships, projects, registries,
packages, package_versions, releases, channels, caches, cache_objects,
audit_log, webhooks, validation_*, config_changesets/revisions, etc.

## Workers ↔ Native realization (the single-source ports)

The RFC-0004 "can't drift" invariant holds by making each capability a **port**
with two leaf impls; the shared `aos-hub-core` stays the single source of truth.

| Capability | Worker impl | Native impl |
| --- | --- | --- |
| Relational system of record (`Backend`) | **SQLite-in-DO**, tenant-sharded | embedded SQLite/`rusqlite` in-process (zero hop) |
| `KvStore` (sessions/tokens/config/routing) | Workers KV | **LMDB** |
| `Coordinator` (counter/lease/floor) | a Durable Object | in-process + LMDB txn |
| Read-model cache | Cloudflare Cache API / edge | CDN or in-process cache + reverse proxy |
| `Queue` (async jobs) | Cloudflare Queues | tokio job runner over a durable queue table |
| Object surface (`SurfaceProvider`) | R2 | filesystem / S3 (exists) |
| Directory / search | KV + search index | LMDB / embedded index |

The native shell can be the faster of the two: embedded SQLite + LMDB +
in-process cache means every read is in-process (no DO hop), scaling out with
streaming SQLite replication (LiteFS/Litestream-style) for HA + read replicas.
The Worker shell trades a small DO hop for global edge distribution and zero ops.

## Tradeoffs / open questions

- **DO lifecycle at scale.** Per-tenant DOs mean migrations/backups across many
  objects, and a tenant-DO create/route/retire lifecycle. Tractable, not free.
- **KV auth revocation.** Eventual consistency means session/token revocation
  and config changes lag (~up to 60 s). Mitigate with short TTL + write-through;
  for must-be-instant security revocation, fall back to a DO/D1 check on miss.
- **Single vs per-tenant DO.** Start with a single hub DO pinned to WNAM
  (simplest, already a win for a region-concentrated hub); shard per-tenant when
  multi-region tenants materialize.
- **Read-model invalidation correctness** is the classic ISR hard part; the
  Queue fan-out must be idempotent and ordered-enough per tenant.
- **Open:** does the SQLite-in-DO `Backend` reuse the existing dialect/`Backend`
  trait verbatim, or need a DO-storage-specific seam? (Spike in Phase A.)

## Implementation checklist

Each phase ships behind a flag, is independently revertible, and records read
p50/p99 (via the Phase A harness) before/after. The single-source invariant is a
gate on every item: every capability is a port with **both** Worker and native
impls, no logic duplicated, with the workerd+miniflare e2e *and* native tests
green.

### Phase A — Measurement harness + the read/write session split (foundation)

- [x] `Server-Timing` span per `Backend::query`/`execute` (feature-gated) so
      per-statement ms is visible in `wrangler tail` / preview, not inferred.
      *Done:* `aos_hub_core::backend::TimingBackend` + `QueryTimings`
      (`backend/timing.rs`, `query-timing` feature) decorate the read-path
      backend; the Worker emits `Server-Timing` from `fetch` (`lib.rs`). Native
      tests green; compiles on native + wasm32 with/without the feature.
- [ ] Stand up a throwaway **preview** Worker (`aos-hub-preview`) with its own
      D1/R2/KV/DO bindings for safe experiments (no prod impact).
- [ ] On the preview, measure `with_session` vs the raw D1 binding for a single
      read; record the per-request session cost in this file (confirms the ~120 ms
      hypothesis and whether the Sessions API specifically is responsible).
- [ ] Split the per-request D1 session: read-only requests use
      `first-unconstrained` and **never** share a session with a write; assert no
      write precedes reads on a read path (`crates/aos-hub-worker/src/lib.rs`
      `router_from`/`fetch`).

### Phase B — Get writes off the read path (KV + DO ports)

- [x] Define a `KvStore` port in `aos-hub-core` (`get`/`put`/`delete`/TTL) with a
      Workers KV impl (Worker) and an LMDB impl (native).
      *Done:* `aos_hub_core::kv::{KvStore, InMemoryKv}` (`kv.rs`, tested) +
      `WorkerKv` over Workers KV (`workerkv.rs`, compiles wasm). Native impl is
      in-process (`InMemoryKv`) — the LMDB **persistent** variant is a drop-in
      behind the same port (deferred, mirrors how `InMemoryLease` is the native
      lease today); a no-new-C-dep sqlite-backed variant is also available.
- [x] Define a `Coordinator` port (atomic counter, lease, monotonic floor) with a
      Durable Object impl (Worker) and an in-process/LMDB-txn impl (native).
      *Done:* `aos_hub_core::coordinator::{Coordinator, InMemoryCoordinator}`
      (`coordinator.rs`, tested) + the `CoordinatorObject` Durable Object and
      `WorkerCoordinator` client (`coordinatorobj.rs`, compiles wasm). DO runtime
      behavior is verified on deploy (needs the `[[durable_objects.bindings]]`
      wrangler config — added in the deploy-prep item).
- [x] Reimplement the rate limiter over `Coordinator` (DO on Worker, in-process on
      native); delete `D1RateLimiter` and remove all `rate_limits` writes from read
      paths.
      *Done:* shared `CoordinatorRateLimiter` (`ratelimit.rs`, tested over
      `InMemoryCoordinator`); the Worker builds it over the DO `WorkerCoordinator`.
      `workerlimit.rs` (`D1RateLimiter` + the `rate_limits` `CREATE TABLE`/upsert)
      **deleted** — no D1 write on the browse read path. Native keeps its existing
      in-process token-bucket limiter (already off-DB).
- [x] Move the publish lease off D1 (`workerlease.rs` `D1PublishLease`) onto the
      `Coordinator`.
      *Done:* shared `CoordinatorLease` (`lease.rs`, tested); the Worker builds it
      over the same `WorkerCoordinator`. `workerlease.rs` **deleted**.
- [x] Move channel anti-rollback floors onto the `Coordinator` as compare-and-set.
      *Resolved — keep in D1 (deliberate).* The channel floor is **semver-typed**
      (`signing.rs::advance_channel` reads/writes `channel_floors` and compares
      with `semver::Version`) and lives on the **publish/channel-advance write
      path**, not the read path this chapter targets — so moving it yields no
      read-latency win, and packing semver into the Coordinator's `i64` floor
      would be **incorrect** for anti-rollback (prerelease/build metadata is
      lossy). It stays in D1, transactional with the publish. The Coordinator's
      `advance_floor` integer primitive is retained for any future integer floor.
      *(Flagged to the reviewer — override if a string/semver-aware Coordinator
      floor is wanted.)*

### Phase C — Hot point-reads to KV / LMDB

- [x] Sessions → `KvStore` (wire the already-bound `SESSIONS` KV; LMDB native).
      Revocation via short TTL + delete; read-your-writes not required.
      *Done:* `cache::read_through`/`invalidate` (`cache.rs`, tested) + a `kv`
      field/`with_kv` on `RpcService`; `resolve_session_cached` /
      `invalidate_session_cache` serve the session lookup off KV with a 60 s TTL
      and an exact `expires_at` recheck (and skip `validate_session`'s
      `last_seen_at` write on a hit). Worker wires `WorkerKv` over `SESSIONS`; the
      browse read path (`session_indicator`) uses it. *Remaining (follow-up):*
      explicit invalidation at the console logout site and caching the console's
      own session reads — TTL already bounds revocation lag to ≤60 s.
- [ ] API tokens → `KvStore` read cache with D1 as source-on-miss; invalidate on
      revoke.
- [ ] `instance_config` + site chrome → `KvStore`; push-update on save.
- [ ] `frontends` host→registry routing table → `KvStore`; rebuild on frontend
      change (`rewrite_for_frontend` reads KV, not D1).
- [ ] `key_rosters` (trust anchors) → `KvStore`.
- [ ] Short-lived auth artifacts (`oidc_flows`, `magic_links`, `device_codes`,
      `webauthn_challenges`) → `KvStore` TTL, with single-use claims via
      `Coordinator` where atomicity matters.

### Phase D — Edge-regenerated control-plane read models (ISR)

- [ ] Define a `Queue` port (Cloudflare Queues / native job runner) for async
      fan-out.
- [ ] Materialize the global registry/cache **directory** as a cached projection
      (KV) updated on publish; the instance home reads it (kills the home N+1
      fan-out in `crates/aos-hub-core/src/web/browse.rs`).
- [ ] Regenerate browse HTML/JSON on write → edge cache / R2; serve anonymous
      browse as cache hits; invalidate the affected keys on write via the `Queue`.
- [ ] Move surface regeneration, projection updates, cache invalidation, webhook
      delivery, and indexing onto the `Queue` (synchronous write stays fast).

### Phase E — Tenant-sharded, colocated SQLite system of record

- [ ] Add a **SQLite-in-DO** `Backend` impl behind the existing trait (Worker);
      an embedded in-process SQLite `Backend` (native). Spike the trait fit first.
- [ ] Shard the system of record per org/registry (one DO per tenant); define the
      tenant-DO create/migrate/backup/retire lifecycle.
- [ ] Route tenant reads/writes to the tenant DO; keep the Phase D global
      directory for cross-tenant listing/search.
- [ ] DO read replicas for global readers; native streaming SQLite replication
      for HA + read scale.
- [ ] Decommission D1 as the tenant system of record once parity + data migration
      are verified (retain as cold archive / reporting if useful).

### Cross-cutting gates (every phase)

- [ ] Single-source invariant upheld: Worker + native impls for each new port; no
      duplicated logic; e2e (workerd+miniflare) and native test suites green.
- [ ] Read p50/p99 recorded before/after each phase; a phase that does not move
      the floor (or regresses) is reverted, not merged.
