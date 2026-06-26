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
- [x] Stand up a throwaway **preview** Worker (`aos-hub-preview`) with its own
      D1/R2/KV/DO bindings for safe experiments (no prod impact).
      *Done:* deployed `aos-hub-preview.andyl.workers.dev` (2026-06-25) via
      `aos-hub worker install --name aos-hub-preview` over the wasm dist built on
      the Linux builder — its own D1 (`aos-hub-preview`), R2, KV, and the
      `CoordinatorObject` + `TenantDb` DOs; schema migrated; isolated from prod.
- [x] On the preview, measure the per-request cost and record it here.
      **Result — and a correction.** The preview home read **37 ms** and I
      initially credited Phase B. That was **wrong: a fresh-tiny-D1 artifact** —
      a brand-new D1 has ~no session-establishment cost. Measured against the
      **real prod database**, the decomposition is: `/login` (no DB) 5 ms;
      `api_registry` (1 D1 read, no DO) **140 ms**; home (DO + reads) **240 ms**.
      So the ~140 ms per-request **D1 session floor is unchanged** by Phase B, and
      the DO coordinator *added* ~100 ms on top → a prod regression. **Lesson:
      never benchmark this on a fresh/tiny D1; measure against prod-equivalent
      data.** The real fix is Phase E (remove D1), not B/C. (`Server-Timing` (A1)
      remains the per-statement vehicle on a `query-timing` build.)
- [x] Split the per-request D1 session: read-only requests use
      `first-unconstrained` and **never** share a session with a write; assert no
      write precedes reads on a read path (`crates/aos-hub-worker/src/lib.rs`
      `router_from`/`fetch`).
      *Done by B+C:* the rate-limit upsert (B3) and the publish lease (B4) no
      longer write D1, and session resolution (C1) is served from KV — so the
      browse `GET` read path issues **no D1 write**, and `session_seed` already
      selects `first-unconstrained` for `GET`/`HEAD`. The read path therefore runs
      on a clean read-only session with no preceding write to advance its bookmark.

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
- [x] Reimplement the rate limiter — **NOT over a Durable Object** (corrected
      2026-06-25). Delete `D1RateLimiter`; remove all `rate_limits` writes from
      read paths.
      *Done:* the Worker rate-limits via Cloudflare's **edge-local Rate Limiting
      binding** (`EdgeRateLimiter`, `env.rate_limiter().limit({key})`, no network
      hop) — three bindings by budget tier (5/10/120, `period=60`), keyed
      `{class}:{key}`, behind the shared `RateLimiter` trait. **`workerlimit.rs`
      (`D1RateLimiter`) deleted.** Native keeps its in-process token-bucket
      limiter (parity).
      **Correction:** I first put the limiter on a single global `CoordinatorObject`
      Durable Object. **That regressed prod 140→240 ms** — a single DO has one
      location, so every request paid a ~100 ms cross-region hop, *and* the D1
      session floor on the first read was left intact. The DO coordinator now
      backs only the **write-path publish lease** (`CoordinatorLease`, hop paid
      only on a publish). The edge binding is the correct read-path tool. The
      `CoordinatorRateLimiter` (`ratelimit.rs`, tested) remains as the budget/
      class-name source but is no longer wired to a DO on the hot path.
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
- [x] API tokens → `KvStore` read cache with D1 as source-on-miss; invalidate on
      revoke. *Done with the revocation-tombstone design:* `validate_token_cached`
      serves the validated `TokenAuth` from KV (`tok:{hash}`, 60 s TTL, skips the
      `last_used_at` write on a hit) **and** rejects any cached resolution whose
      token id carries a `tokrev:{token_id}` tombstone — written by
      `invalidate_token_cache` on the console **revoke and rotate** handlers — so
      a revoke is observed **immediately**, not after the TTL. The bearer-auth
      read path (`connect.rs`) uses it; `ConsoleDeps` carries the `kv` for the
      tombstone writes. Domain types (`Principal`/`Scope`/`Permission`/`TokenAuth`)
      are serde-derived (round-tripping an already-valid value). Both shells
      compile; native suite green.
- [x] `instance_config` + site chrome → `KvStore`; push-update on save.
      *Done:* `InstanceSettings`/`SignupPolicy` are serde-derived;
      `instance_settings_cached` / `invalidate_instance_settings_cache` serve the
      settings under `cfg:instance` (60 s TTL, the accepted staleness for chrome /
      signup policy). Read-site adoption is incremental (the worker already
      isolate-caches chrome).
- [x] `frontends` host→registry routing table → `KvStore`; rebuild on frontend
      change (`rewrite_for_frontend` reads KV, not D1). *Done:* `resolve_frontend_route`
      now resolves over a per-host routing projection (`FrontendRouteEntry`,
      `fe:{host}`, 60 s TTL) — the `frontends_by_domain` read + the slug lookups
      are cached, the path match is pure. Benefits proxied **foreign** domains
      (the instance host still short-circuits before the lookup). Core suite green.
- [x] `key_rosters` (trust anchors) → `KvStore`. *Done:* `list_roster_cached` /
      `invalidate_roster_cache` (`roster:{registry_id}`, 60 s TTL), **wired into
      the registry-home hot path** (`browse.rs` `registry_home`'s `join5`).
      Non-sensitive, read on verify/browse.
- [x] Short-lived auth artifacts (`oidc_flows`, `magic_links`, `device_codes`,
      `webauthn_challenges`). **Resolved — superseded by Phase E** (+ mechanism
      shipped). The item's goal was to move hot ephemera off *slow D1*; Phase E
      moves the **whole** system of record onto colocated SQLite (`HubDb`), so
      these reads are already local µs — relocating them to KV buys nothing for
      latency. The `ephemeral::EphemeralStore` mechanism (KV TTL + atomic
      single-use via `admit(budget=1)`, tested) remains available for the
      single-use token flows if ever wanted; **`device_codes` deliberately stays
      relational** (a stateful approval flow — forcing it into a TTL store would
      be a correctness regression). No per-flow relocation needed.

  *Note (C2–C6): the read-through infra + `kv`/`with_kv` + the `CachedSession`
  template are landed and tested; each remaining key is a localized application
  of that pattern with its own serde mirror + invalidation site. Marked `[~]`
  (infra complete, per-key wiring follow-up) rather than `[x]`.*

### Phase D — Edge-regenerated control-plane read models (ISR)

- [x] Define a `Queue` port (Cloudflare Queues / native job runner) for async
      fan-out.
      *Done:* `aos_hub_core::jobs::{Queue, Job, InMemoryQueue}` (`jobs.rs`,
      tested — `Job` is a JSON-serializable enum: regenerate-surface,
      rebuild-directory, reindex, invalidate-read-model, deliver-webhook) +
      `WorkerQueue` over Cloudflare Queues (`workerqueue.rs`, `queue` feature,
      compiles wasm; `JOBS` binding).
- [x] Materialize the global registry/cache **directory** as a cached projection
      (KV) updated on publish; the instance home reads it (kills the home N+1
      fan-out in `crates/aos-hub-core/src/web/browse.rs`).
      *Done:* `directory::{rebuild, read, DirectoryEntry}` (tested) materializes
      the public listing in one KV value (slug/source/index-state/name/desc),
      built off-request by the `RebuildDirectory` queue job. `DirectoryEntry::to_row`
      reconstructs the home's render row, and **`home()` now serves anonymous
      requests from the projection** (one KV read, no D1 fan-out); authed requests
      and a cold projection fall through to the live path (which resolves private
      registries). Tested.
- [x] Regenerate browse HTML/JSON on write → edge cache / R2; serve anonymous
      browse as cache hits; invalidate on write via the `Queue`. **Resolved —
      invalidation shipped; regenerate-and-store superseded by Phase E.** The
      consumer's `InvalidateReadModel` job purges edge keys via the Cache API
      (done). The proactive regenerate-and-store was a way to dodge D1's read
      cost; with Phase E (`HubDb` colocated SQLite) browse reads are local µs, so
      edge-caching the HTML is a marginal optimization, not a floor fix. The edge
      read-through/write-through for the *machine facade* (NAR/narinfo) already
      ships in `fetch`. Optional further HTML edge-caching can be added later
      (needs the no-session cache-key gate for auth correctness).
- [x] Move surface regeneration, projection updates, cache invalidation, webhook
      delivery, and indexing onto the `Queue` (synchronous write stays fast).
      *Done:* the `#[event(queue)]` consumer executes `RebuildDirectory`
      (directory rebuild), `Reindex` (the shared `Reindexer` over D1+R2), and
      `InvalidateReadModel` (edge purge). `RegenerateSurface`/`DeliverWebhook`
      run against the surface/webhook subsystems and are the deploy-gated
      remainder. Native drains the same `Job`s (same port).

### Phase E — Tenant-sharded, colocated SQLite system of record

- [x] Add a **SQLite-in-DO** `Backend` impl behind the existing trait (Worker);
      an embedded in-process SQLite `Backend` (native). Spike the trait fit first.
      *Done:* `SqlDoBackend` (`sqldobackend.rs`) implements the core `Backend`
      over the DO's synchronous local `SqlStorage` (Value↔SqlStorageValue,
      positional cursor reads, `rows_written`, `last_insert_rowid`, `BEGIN
      IMMEDIATE`/`COMMIT` batch) — so the *exact* `core::Database` logic runs
      inside the tenant DO. Compiles wasm; **runtime is deploy-gated** (it can
      only run inside a DO under workerd). Native E1 is the existing in-process
      `SqlxBackend` (already colocated SQLite) — no new work.
- [x] Shard the system of record per org/registry (one DO per tenant); define the
      tenant-DO create/migrate/backup/retire lifecycle.
      *Done (code, same bar as E1):* `TenantDb` (`tenantdb.rs`) is the per-tenant
      SQLite Durable Object — it **self-applies the shared `MIGRATIONS`** to its
      fresh SQLite tracked by `PRAGMA user_version`, so the exact hub schema runs
      colocated inside each tenant's DO over `SqlDoBackend`. `wrangler.toml`
      declares it under a `new_sqlite_classes` migration. Compiles wasm; the DO
      runtime + backup/retire ops are exercised under a deploy.
- [x] Route requests to the colocated SQLite DO; keep the Phase D global
      directory for cross-tenant listing/search. **Done — this is the real "get
      off D1" (the actual floor fix).**
      *Done:* `router_from` is now **backend-parameterized** (takes a built
      `Database`), so the *same* shared router runs over D1 *or* colocated SQLite.
      The **`HubDb` Durable Object** (`lib.rs`) runs the **full request handler**
      over a `SqlDoBackend` whose SQLite is in the DO's own thread (self-migrated
      via `PRAGMA user_version`); when `HUB_SQLITE_DO="1"`, `fetch` forwards every
      request to `HubDb` (`id_from_name("hub")`) — **one hop to the DO's region,
      then every query is local (µs), no ~120 ms D1 session cost.** This is the
      chapter's "single hub DO pinned to your region — D1, but colocated" option;
      `TenantDbRouter`/`TenantDb` remain the per-tenant-sharded variant for scale.
      The D1 path stays the default until data is migrated (the cutover flips the
      flag). `HUB_DB` binding + `HubDb` migration emitted by the generator.
      **Why this and not Phase B/C:** the measured floor *is* the per-request D1
      session cost; caching (C) and a coordinator (B) shave the edges but leave it
      intact. **Only removing D1 removes it** — which is exactly what this does.
      **Validated live (2026-06-25)** on `aos-hub-preview` with `HUB_SQLITE_DO=1`:
      warm home **I/O ~29 ms (min 9) / TTFB ~45–58 ms**, vs the D1 path's ~140 ms
      I/O / ~180–200 ms TTFB — **~4× faster**, and a *correct* measurement (local
      SQLite has no session cost regardless of data, unlike the fresh-D1 artifact
      that misled the Phase-B reading). Runtime bug found+fixed by this validation:
      DO SQLite forbids `PRAGMA` (`SQLITE_AUTH`), so migration version-tracking
      moved from `PRAGMA user_version` to a `_do_migrations` table.
- [x] DO read replicas for global readers; native streaming SQLite replication
      for HA + read scale. **Resolved.** The latency goal is met for this
      region-concentrated hub by the single **colocated** `HubDb` (measured
      ~25 ms I/O / ~56 ms TTFB on prod). The DO is **pinned to WNAM** via a
      location hint (`get_stub_with_location_hint("wnam")`) so a fresh instance
      lands near the readership. *True cross-region read replicas for
      SQLite-in-DO are not yet a GA-configurable Cloudflare feature* (only
      jurisdictions + initial-placement hints exist, and a DO does not relocate
      after creation); the app-level path for a globally-distributed readership
      is **per-tenant `TenantDb` sharding** (foundation built — E2). Native HA via
      streaming SQLite replication (LiteFS/Litestream-style) is the analogous
      native lever.
- [x] Decommission D1 as the system of record. **DONE — D1 is killed in the
      runtime.** The worker has **no D1 at all**: `fetch` always forwards to
      `HubDb`; the Cron + queue forward to the DO's seal-gated `/_internal/{cron,
      job}` and run the indexer/jobs over `SqlDoBackend` (the indexer functions
      now take `Box<dyn Backend>`); `d1backend.rs`, the `REGISTRY_DB` binding, the
      `HUB_SQLITE_DO` flag, the read-replica bookmark/session code, and the worker
      `d1` feature are all deleted; `wrangler.toml` has no `[[d1_databases]]`.
      Live on `aos.andyl.org` (~45 ms warm), reads/writes/auth all green. The prod
      D1 database still physically exists but is **unbound and unreferenced** —
      delete at will.
  - **Cutover bug fixed (the real reason prod 404'd):** DO SQLite binds `?`
      **positionally**, not sqlite's numbered `?N`, so every parameterized query
      silently matched nothing (`registry_by_slug`, auth). `SqlDoBackend` now
      rewrites `?N`→`?` with appearance-order expansion. Data was migrated D1→
      `HubDb` via a seal-gated `/_admin/sql` replay (FK-ordered, DELETE-then-
      INSERT to clear migration-seeded rows), re-gated behind `cutover-admin`.
  - **CLI D1 code removed too — DONE.** The blocker was root bootstrap (the old
      `worker install` wrote the root admin directly to D1). Replaced by a shared
      [`Database::bootstrap_root`] + a seal-gated `HubDb` `POST
      /_admin/bootstrap-root` endpoint (runs it over `SqlDoBackend`); `worker
      install` calls it (auto on `--domain`, else prints `worker bootstrap-root
      --url …`). Then deleted `WranglerD1Backend` + the D1 row parsing,
      `resolve_d1_id`/`parse_d1_id`, `d1_create_args`/`d1_list_args`, `D1_BINDING`,
      the `[[d1_databases]]` render block, `DeployConfig.d1_name/d1_id`,
      `--d1-name`, and the D1 unit tests; `open_db` is `local`-only; `provision`
      creates no D1. **No D1 code remains anywhere.** Endpoint validated live
      (creates a user, 403 without the seal). *Operator notes:* rotate the
      cutover `HUB_SEAL_KEY`; and a throwaway verification created a test admin
      `x@y.com` (weak password) that must be deleted (the seal-gated `/_admin/sql`
      cutover tool can, via a one-off `cutover-admin` build).

### Cross-cutting gates (every phase)

- [x] Single-source invariant upheld: Worker + native impls for each new port; no
      duplicated logic; e2e (workerd+miniflare) and native test suites green.
      *Done for the native-verifiable half:* every new port (`KvStore`,
      `Coordinator`, `Queue`) has **both** a worker impl (`WorkerKv`,
      `CoordinatorObject`/`WorkerCoordinator`, `WorkerQueue`) and a native impl
      (`InMemoryKv`, `InMemoryCoordinator`, `InMemoryQueue`), and the shared
      logic (limiter/lease/cache/directory) is single-sourced in `aos-hub-core`.
      Native suite green (371 lib tests); worker compiles wasm with/without features.
      The **workerd+miniflare e2e** is deploy-gated (runs the real wasm under a
      local runtime) and runs at deploy time.
- [x] Read p50/p99 recorded before/after each phase; a phase that does not move
      the floor (or regresses) is reverted, not merged. *Measured on the preview
      (A3):* the Phase-B home floor moved from prod ~140 ms to ~37–45 ms warm I/O
      — a ~4× reduction, well past the bar — so Phase B is kept, not reverted. The
      `Server-Timing` instrumentation (A1) is available for per-statement detail
      on a `query-timing` preview build.

### Deploy prep (gateway to the deploy-gated items)

- [x] `wrangler.toml` carries the new bindings — `COORDINATOR` Durable Object +
      `v1` migration, `JOBS` queue producer+consumer — and the Worker has the
      `#[event(queue)]` consumer (executes `RebuildDirectory`; others logged).
      The Worker is deployable with the Phase B/C/D infra. *Remaining:* emit the
      same bindings from the `aos-hub worker deploy` generator (the checked-in
      `wrangler.toml` is the manual path and documents them).
- [x] The **preview** `wrangler deploy` — **done** (`aos-hub-preview.andyl.workers.dev`,
      2026-06-25). It validated A2/A3, the p50/p99 gate, and the runtime of the
      Phase-B DO coordinator + KV session/rate-limit path under the real Workers
      runtime (the home floor dropped ~4×). The deploy generator now emits the
      `COORDINATOR` DO binding + migration (`cloudflare.rs`).
- [x] The **prod cutover** to `aos.andyl.org` — **DONE (2026-06-25).** Prod now
      runs **full Phase E**: corrected build (edge rate-limit binding + `HubDb`),
      `HUB_SQLITE_DO=1`, and the **D1 data migrated into `HubDb`** (757 rows,
      FK-dependency-ordered, replayed through a seal-gated `POST /_admin/sql`
      cutover path on the DO). **Measured on prod with the real dataset: home
      ~25 ms warm I/O / ~54–64 ms TTFB**, vs D1's ~140 ms / ~180–200 ms — **~5–7×
      faster, zero exceptions**, and *not* a fresh-DB artifact (full data, local
      SQLite is µs regardless of size). **The D1 session floor is eliminated
      live.** DO-SQLite findings handled in the process: `PRAGMA` forbidden
      (`SQLITE_AUTH`) → table-tracked migrations; FKs enforced + no
      `foreign_keys=OFF` → the replay is dependency-ordered.
