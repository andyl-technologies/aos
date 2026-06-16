# Phase 5: one async runtime, full Cloudflare/native parity

- **Status:** In progress (2026-06-16). **Data layer landed** (PR #99): the
  async `Backend` trait, the shared `aos-registry-core::Database` (reads *and*
  writes), and the worker's `D1Backend` all ship; the worker folds its read
  path + Cron indexer onto `core::Database`. **Remaining work — the handler
  unification** (this is where parity is won): move the facade, browse UI, JSON
  API, RPC, auth, and producer console into one shared `axum` router in
  `core`, served natively via `axum::serve` and on Workers via
  `axum-cloudflare-adapter`. The worker's hand-written read-only fetch router
  (`handlers.rs`/`reads.rs`/`facade.rs`) is then deleted. The wasm-feasibility
  spike that gated the handler shape is **done** — results in
  "[Spike results](#spike-results-2026-06-16-what-actually-compiles-to-wasm)"
  below; it forced one amendment to the RPC transport (the `connectrpc`
  *server* runtime cannot target wasm). Still gated on the D1 transaction
  audit for the write sites.
- **Audience:** `crates/aos-registry-hub/`, `crates/aos-registry-worker/`,
  `crates/aos-proto/`, the `aos` CLI (`crates/aos/`, `crates/aos-remote/`).

> Code links reflect the tree at the time of writing and are illustrative
> of the proposal; this is a design record, not a description of shipped
> behavior.

## Problem: the read path is built twice

Phases 1–4 shipped the hub as a native binary. The Cloudflare deployment
was then spiked as a **separate, read-only** Worker
(`crates/aos-registry-worker`). The two share only
`aos-registry-surface` (~500 LOC: the pure Ed25519/SSHSIG verifier).
Everything else on the read path is implemented twice:

| Read-path concern | Worker | Native hub | Status |
| --- | --- | --- | --- |
| Signature verification | `aos-registry-surface` | `aos-registry-surface` | **shared** |
| Machine-path facade (git/nix-cache) | `src/facade.rs` + `src/keymap.rs` | `src/compat.rs` | duplicated (~900 LOC) |
| Indexer orchestration | `src/indexer.rs` + `src/indexlogic.rs` | `src/indexer.rs` | duplicated |
| Browse UI HTML | `src/render.rs` | `src/ui/render.rs` + `src/ui/pages.rs` | duplicated |
| JSON read API | inline in `src/handlers.rs` | `src/rpc.rs` (ConnectRPC) | duplicated |
| Schema DDL | `src/sql.rs` | `src/db/mod.rs` migrations | duplicated, byte-identical (enforced by a test) |

`src/keymap.rs` documents itself as "faithful copies" of `compat.rs` with
equivalence tests; the schema is kept identical by
`sql::tests::migration_file_matches_schema`. This is *managed* duplication,
but it is a permanent maintenance tax: two indexers, two renderers, and two
JSON shapes that must agree forever, plus a read-only edge that can never
reach feature parity with the hub.

### Why the split was originally forced

Three hard constraints, not arbitrary choices:

1. **Sync vs async DB.** The native `Backend` trait
   (`crates/aos-registry-hub/src/db/backend.rs`) is deliberately
   **synchronous** (`Mutex<Connection>`); its doc comment notes "an async
   trait would cascade through the whole crate for no benefit." Cloudflare
   D1 is async-only (`prepare(…).first(None).await`). A sync trait cannot
   wrap D1, so the Worker reimplemented every query in `src/d1.rs`.
2. **rusqlite will not target wasm.** The hub bundles `libsqlite3` (C),
   which does not link for `wasm32-unknown-unknown`.
3. **tokio/axum/connectrpc** assume a multi-threaded runtime that does not
   run on the Workers single-threaded JS event loop.

Two of these have since dissolved: `rusqlite` can target wasm via the
`ffi-sqlite-wasm-rs` feature, and `axum` (types-only, `default-features =
false`) runs on Workers through `axum-cloudflare-adapter` — both **verified by
the spike below**. The third splits: `tokio`/`axum` are fine, but the
`connectrpc` *server runtime* specifically is **not** wasm-portable (it drags
in `hyper`/`hyper-util`/`tokio`+`mio`/`zstd-sys`), so RPC keeps a thin
per-target transport adapter over shared logic. The sync-vs-async constraint —
the thing that forced the *whole read path* to be rebuilt — is removed by going
**async everywhere**.

## Goal

One codebase. The bulk of the logic written once, with traits capturing the
differences between deployment targets:

- **Async everywhere** — no sync `Backend`, no duplicate read path.
- **Full feature parity on Cloudflare** — the read/write/console/auth path
  all run on Workers. "Read-only deployment" ceases to exist as a separate
  code path; it is at most a configuration toggle.
- **Different frontends behind one router** — `axum` served natively via
  `axum::serve`, and on Workers via `axum-cloudflare-adapter`.
- **Different backends behind one trait** — `sqlx` natively (sqlite,
  postgres, mysql), Cloudflare D1 on Workers.
- **CLI over the API** — the CLI stops touching the database directly and
  becomes a client of the hub's API, folded into `aos hub …`.

## The unifying realization

The hub already has the right bones. `crates/aos-registry-hub/src/db/mod.rs`
builds *all* ~5,000 lines of domain queries (registries, packages, indexer
writes, `instance_config`, IAM) generically on top of a tiny `Backend`
trait (`execute` / `query` / `with_tx`) plus a `Dialect` enum that rewrites
SQL text per engine. The Worker only reimplemented `registry_by_slug` et al.
in `src/d1.rs` *because that trait is synchronous and D1 is async*.

So the entire move is: **make `Backend` async, and the duplication has
nowhere left to live.** The Worker's `d1.rs` collapses from "reimplement
every query" to "implement a handful of async primitives." Everything above
the trait is written once.

## Crate topology

```text
crates/
  aos-registry-core/      # NEW: the one crate. compiles to BOTH native + wasm32.
    db/                   #   async Backend trait + Dialect + ALL repo methods
    handlers/             #   the shared axum Router: facade, browse UI, JSON API, RPC, auth
    indexer/              #   surface -> store logic over Backend + Blobs (one copy)
    render/               #   HTML (one copy; was render.rs x2)
    ports/                #   the seam traits: Backend, Blobs, HttpClient, Clock, Tasks
    # deps: axum (default-features=false), aos-registry-surface, serde, sha2, ...
    # NO tokio server, NO hyper, NO worker, NO sqlx -- runtime-agnostic core

  aos-registry-hub/       # native binary. shell only.
    # SqlxBackend (Any: sqlite/pg/mysql), FsBlobs, reqwest HttpClient,
    # axum::serve over tokio, install-time root bootstrap

  aos-registry-worker/    # cdylib wasm. shell only.
    # D1Backend, R2Blobs, worker::Fetch HttpClient,
    # #[event(fetch)] via axum-cloudflare-adapter, #[event(scheduled)] -> indexer

  aos-registry-surface/   # unchanged -- already the shared verifier
```

The discipline that makes this work: **heavy runtime dependencies live in
the shells, never in core.** `sqlx`/`tokio`/`hyper` exist only in the native
crate; `worker`/`wasm-bindgen` only in the Worker crate. Core depends on
`axum`'s *types* (router, extractors, responses) with
`default-features = false` so it does not drag in the hyper server — which is
exactly what `axum-cloudflare-adapter` requires. Crate boundaries (not
`#[cfg]`) enforce the dependency isolation per target.

## The seams

### `Backend` — async, batch-oriented transactions

The only thing each store implements. The critical change from phase 1–4 is
the transaction primitive: a **batch of statements** committed atomically,
*not* an interactive closure handed a live `Tx` (see the audit below for
why).

```rust,ignore
#[async_trait::async_trait(?Send)]   // ?Send: wasm futures are not Send
pub trait Backend {
    fn dialect(&self) -> Dialect;    // the existing Dialect enum, reused verbatim
    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64>;
    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>>;
    async fn query_opt(&self, sql: &str, params: &[Value]) -> Result<Option<Row>>;

    /// Submit a fixed list of statements, committed atomically.
    /// sqlx runs them inside a real transaction; D1 runs them as `batch()`.
    async fn batch(&self, stmts: &[Statement]) -> Result<Vec<BatchResult>>;
}
```

Every existing repo method gains `async`/`.await` and stays single-source —
e.g. `instance_config_set`, `registry_by_slug`, the indexer writers — written
once in `aos-registry-core::db`, used by both deployments.

### `Blobs` — surface object storage

Abstracts R2 (Worker) vs filesystem/S3 (native); replaces the storage half
of the duplicated `facade.rs`/`compat.rs`.

```rust,ignore
#[async_trait::async_trait(?Send)]
pub trait Blobs {
    async fn get(&self, key: &str) -> Result<Option<Bytes>>;
    async fn put(&self, key: &str, body: Bytes) -> Result<()>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}
```

### `HttpClient`, `Clock`, `Tasks` — the remaining runtime differences

- `HttpClient` — outbound HTTP for OIDC token exchange and JWKS fetch:
  `reqwest` natively, `worker::Fetch` on Workers.
- `Clock` — `SystemTime` is unavailable on wasm; time comes through a port.
- `Tasks` — background work: a `tokio` interval natively, the Cron
  `scheduled` event on Workers (with Cloudflare Queues / a Durable Object
  for anything longer-running than the indexer).

### Seams the producer console / write path still need

The audit of `aos-registry-hub` surfaced four more native-only couplings that
the write/console/auth path depends on. Three are *already* trait-shaped in
`core`; one is not. All resolve the same way — a port with a native and a
worker impl, the logic above it written once:

- `SecretSealer` (**exists** in `core::auth::seal`) — seals OIDC client
  secrets and hosted-key seeds at rest (AES-256-GCM). Native builds it from a
  file-backed instance key; the worker builds the *same* `AesGcmSealer` from a
  Wrangler secret binding. No new trait — just a different constructor.
- `Mailer` (**exists** in `core::auth::magic`) — sends magic-link / invite
  email. Native impl is the SMTP/dev-echo seam; the worker needs a
  `worker::Fetch`-backed impl posting to an email API (or the dev-echo path).
- **Publish lease** (**not yet a trait**) — `facade.rs` guards concurrent
  pointer-flips with an in-memory `std::sync::Mutex<LeaseMap>`, which is
  per-isolate and meaningless across Worker invocations. Becomes a `Lease`
  port backed by a conditional D1 `UPDATE … WHERE expires_at < ?` (or a
  Durable Object) — atomic across the edge.
- **Rate limiter** (**not yet a trait**) — `ratelimit.rs` is an in-memory
  token bucket; same per-isolate problem. Becomes a `RateLimiter` port over
  D1/KV (or a Durable Object) on the worker; the in-memory bucket stays native.

## Backend choice: `sqlx` native, D1 on Workers

`sqlx` is the native backend and **collapses the three current backends**
(`db/backend/sqlite.rs`, `postgres.rs`, `mysql.rs`) into **one** `sqlx::Any`
pool, with the existing `Dialect` still doing SQL-text rewriting (sqlx
handles the wire protocol/pooling/async; it does not translate dialects).

Two constraints to respect:

- **`sqlx` is the *native* impl only.** It has no D1 driver (D1 is reachable
  only through the Workers binding), and neither its runtime nor its bundled
  SQLite link for `wasm32`. The Worker's `D1Backend` remains a distinct impl
  of the same async `Backend` trait — that is the point of the seam.
- **Use the runtime query API, not the `query!` macros.** Compile-time query
  checking needs a live DB or a committed offline cache at build time, which
  is hostile to the hermetic Nix sandbox and unusable across three dialects.
  `query_with(…).fetch_all(pool)` over `Dialect`-rewritten SQL is what we
  want. `ffi-sqlite-wasm-rs` is reserved for running the shared `db` layer's
  tests under wasm; D1 remains the Worker's durable store.

## Spike results (2026-06-16): what actually compiles to wasm

Before committing the handler-unification to the shared-router shape, a
throwaway probe crate (`axum` + `axum-cloudflare-adapter` + `worker` 0.4.2 +
`connectrpc`) was compiled against `wasm32-unknown-unknown`. Findings, all
empirical:

| Dependency | `wasm32-unknown-unknown` | Notes |
| --- | --- | --- |
| `axum` 0.8 (`default-features = false`) | ✅ compiles | types/router only; no hyper server |
| `axum-cloudflare-adapter` 0.14 + `worker` 0.4.2 | ✅ compiles | confirms `#[event(fetch)]` can serve the shared router |
| plain `axum` handlers (write/console/auth/facade) | ✅ | ordinary handlers — parity is just "move them into `core`" |
| **`connectrpc` 0.3 server runtime** | ❌ **hard blocker** | unconditional `hyper` + `hyper-util` + `tokio`(+`mio`) + `tower`; `default` pulls `zstd-sys` (C + amd64 `.S`). Not portable even with `default-features = false, features = ["server","axum"]`. |
| `prost` message types (in isolation) | ✅ (pure Rust) | wasm-clean as a standalone codec; **today's `aos-proto` crate is not** — it depends on `connectrpc`, hence the split below |

**Consequence — the one amendment to "shared router incl. RPC":** the
`connectrpc` server cannot be mounted into the worker's router. RPC therefore
keeps its method bodies as transport-free functions in `core` (a shared
`RpcService` trait), with a thin per-target *transport adapter*:

- **Native:** the existing `connectrpc` server (`#[connectrpc]` trait impls in
  `aos-registry-hub::rpc`) becomes a thin delegate to `RpcService` — unchanged
  wire behavior, mature runtime.
- **Worker:** a small hand-rolled **Connect-unary** `axum` handler decodes the
  request (proto or JSON per `Content-Type`), calls the same `RpcService`, and
  encodes the Connect response — all over the wasm-clean `prost` messages.

This requires a wasm-clean home for the **message types without the
`connectrpc` runtime**. `connectrpc-build` 0.3 can't provide it: it generates
`buffa`-based types through its own `buffa_codegen` (not `prost-build`) and
exposes no `extern_path`/message-reuse knob, so its output can't be imported
piecemeal. The split is therefore:

- **`aos-proto-types`** (new, wasm-clean) — the request/response structs
  generated **independently with `prost-build`** (`prost` + `serde`, no
  `buffa`, no `connectrpc`). This is the lingua franca of the shared
  `RpcService`.
- **`aos-proto`** (native, unchanged generator) — keeps its `connectrpc`/`buffa`
  client+server codegen for the native transport.

The native RPC adapter converts the `buffa` view it receives into the
`aos-proto-types` struct (it already reads buffa views field-by-field in
`rpc.rs` — this just lands the fields in a struct), calls `RpcService`, and
converts the struct back to a `buffa` response. The worker adapter does the
same struct ↔ bytes mapping with `prost` (binary) / `serde_json` (JSON) per
`Content-Type`. Every *other* route — facade, browse, JSON read API, auth,
console — is the byte-identical shared `axum` handler on both targets; only RPC
carries a second (thin) transport adapter, and **no service logic is written
twice** (only mechanical, per-message field mapping at each transport edge).

`RpcService` carries the same **target-conditional `Send` bound** the shipped
`Backend` trait already uses — `#[cfg_attr(not(target_arch = "wasm32"),
async_trait)]` (Send) natively, `async_trait(?Send)` on wasm — so the native
`connectrpc`/hyper server gets the `Send + 'static` futures it requires while
the worker's single-threaded handler stays `?Send`. The `?Send` shown in the
illustrative trait sketches above is the wasm arm of that same `cfg_attr`, not
an unconditional bound; the method bodies remain single-source.

> Reality note: the shipped data layer holds the backend as `Box<dyn Backend>`
> on `Database` (not the generic `Router<State<B: Backend>>` this file
> originally sketched under "Dispatch"). The boxed form is what compiles
> cleanly through `axum-cloudflare-adapter` and keeps `core` free of a backend
> type parameter; the "prefer generics" note below is superseded.

## Frontends: one router, two servers

```rust,ignore
// native shell (aos-registry-hub)
let app: axum::Router = aos_registry_core::handlers::router(state);
axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;

// worker shell (aos-registry-worker)
#[event(fetch)]
async fn fetch(req: worker::Request, env: Env, _: Context) -> worker::Result<worker::Response> {
    let app = aos_registry_core::handlers::router(state_from(env)?);  // identical router
    Ok(axum_cloudflare_adapter::to_worker_response(
        app.oneshot(axum_cloudflare_adapter::to_axum_request(req).await?).await?).await?)
}

#[event(scheduled)]
async fn scheduled(_e: ScheduledEvent, env: Env, _: ScheduleContext) {
    aos_registry_core::indexer::index_all(&backend(env)?, &blobs(env)?).await.ok();
}
```

`facade.rs`, `keymap.rs`, `render.rs`, the inline JSON API, and the query
methods in `d1.rs` all **delete** — they become the shared
`handlers`/`render` over `D1Backend`. The lone exception is RPC: the spike
showed the `connectrpc` server cannot mount on wasm, so the `/aos.registry.v1/*`
routes are *not* the identical handler across targets — the worker adds the
Connect-unary transport adapter (spike amendment above) over the same
`RpcService`. Every other route in the sketch is byte-identical on both.

### Dispatch

> **Superseded by the shipped data layer** (see the Reality note under the
> spike results): `Database` holds `Box<dyn Backend>`, not a generic
> `Router<State<B: Backend>>`. The boxed form is what passes cleanly through
> `axum-cloudflare-adapter` and keeps `core` free of a backend type
> parameter; the dynamic-dispatch cost is negligible against D1/network
> latency. The original generics recommendation below is retained only as
> design history.

Each shell has exactly one backend, so `Router<State<B: Backend>>` with
generics monomorphizes cleanly and avoids `#[async_trait]` boxing. The
current `Box<dyn Backend>` would need boxing. Prefer generics — one
instantiation per binary, no runtime dispatch cost.

## Bootstrap: install-time root, then API-only

API-only mutation has a chicken-and-egg: how is the first admin created
before any credential exists? **The root credential is created at
installation time via native, in-process DB calls** (the binary is both
server and installer; this reuses the existing
`Database::find_or_create_user` + `password::hash_password` path, scoped to
install rather than exposed as a general CLI capability). Everything
thereafter goes through the WebUI or the API. This is the *only* sanctioned
bypass of the API.

## CLI over the API, folded into `aos hub …`

The CLI stops opening the database and becomes a ConnectRPC client of the
hub's existing `aos.registry.v1` services (`RegistryService`, `OrgService`,
`ConfigService`, …), reusing the `aos-remote` connectrpc client pattern
already used by `aos build --remote` / `aos gc --remote`. The standalone
`aos-registry-hub` subcommands move under `aos hub …`:

```text
aos hub serve                                  # run the native hub
aos hub registry create <org>/<proj>/<name> …  # RPC call, --hub <url> --token <…>
aos hub instance set-signup-policy invite_only # RPC call
```

Once handler unification lands (step 4), the Worker serves the *same* router
for every non-RPC route and answers the RPC surface through its Connect-unary
transport adapter (the spike amendment above), so `aos hub … --hub
https://…workers.dev` will configure a Cloudflare deployment identically to a
native one — no raw D1 SQL, no `wrangler` seeding beyond the one-time
`migrations apply`. Same code path yields the same config path. *Today the
worker serves only the read path; the admin/RPC routes answer on the native
hub.*

## The D1 transaction audit (the gate)

D1 has **no interactive transactions** — only `batch()`, a fixed list of
statements submitted together and committed atomically, with no ability to
read a row mid-transaction and branch on its value before writing. The
shipped `Tx` trait (`crates/aos-registry-hub/src/db/backend.rs`) is fully
interactive — `query`, `query_opt`, and `execute_insert` (returning the
last-insert id) — and 16 call sites in `db/mod.rs` use it. Audit result:

- **2 batchable as-is:** `transfer_org_ownership` (5894), `apply_changeset`
  (7338).
- **14 read-then-write** as literally written.

Two corrections shrink the apparent problem materially:

1. **Runtime-variable statement lists are fine on D1.** `batch()` takes a
   `Vec` assembled in Rust before submission — loops emitting *N* statements
   are not a blocker. The only true incompatibilities are (a) **last-insert
   id used mid-transaction** and (b) **reading a value mid-transaction to
   decide the next write**.
2. **D1 supports `RETURNING`** (it is SQLite). Several read-then-write sites
   are explicitly the **MySQL dialect branch** — the SQLite/Postgres path
   very likely already collapses to a single `… RETURNING`, making them
   D1-clean today.

### Disposition

| Class | Sites (`db/mod.rs` line) | Fix | Effort |
| --- | --- | --- | --- |
| Batchable now | `transfer_org_ownership` 5894, `apply_changeset` 7338 | none | — |
| Claim/consume | `approve_device` 6085, `consume_magic_link` 6256, `take_oidc_flow` 6589, `take_webauthn_challenge` 6677 | use the existing `… RETURNING` SQLite path; collapse read+write into one statement | low (likely already done on the SQLite branch) |
| Insert-id chains | `apply_snapshot` 2242, `update_channels` 2429, `record_validation_run_with_findings` 2559 | **client-side UUIDs** instead of autoincrement + last-insert id (as `rotate_token` already does) → the whole tree becomes a fixed batch | low–medium, mechanical |
| Guarded single-stmt | `reserve_org_usage` 4944, `revoke_membership_owner_safe` 4133, `set_membership_role_owner_safe` 4193, `add_org_domain` 6407 | re-express the invariant as one conditional `UPDATE … WHERE …` / `RETURNING` checking rows-affected | medium, per-site SQL design |
| Read-before-batch | `rotate_token` 5655 | read the old token *before* the batch (outside the tx), then batch the writes | low |
| Genuinely gnarly | `delete_user` 5938 | nested loop reading owner-scopes to block last-owner deletion — needs real restructuring | high (1 site) |

### Verdict

D1's batch-only model is **not a wall** — it is roughly a week of focused,
per-site SQL work, concentrated in IAM/auth plus the two indexer writers.
Only `delete_user` is genuinely hard. The keystone insight is about the
*seam*, not the sites: the interactive `with_tx(|tx| …)` primitive is itself
what does not port. Redefining the transaction primitive as a
**batch-of-statements** (above) is what makes all sites portable —
client-side ids, `RETURNING` claims, and guarded conditionals produce
statement lists that sqlx runs in a real transaction and D1 runs as
`batch()`. That work is identical whether the target is D1 or simply a
cleaner backend abstraction.

## Cloudflare platform sharp edges (parity cost)

Designable seams, not blockers — but real work, surfaced now:

- **D1 transactions** — addressed above (the batch seam).
- **D1 scale ceilings** — per-database size and per-query limits; fine for
  many registries, but the wall exists.
- **Argon2 on Workers** — compiles to wasm but is CPU-heavy against the
  per-request CPU budget; cost parameters may need tuning.
- **OIDC outbound HTTP** — via the `HttpClient` port (`worker::Fetch`).
- **Background / long jobs** — Cron `scheduled` for the indexer; Cloudflare
  Queues or a Durable Object for anything longer-running than repair-class
  work.

## Sequencing

Steps 1–4a (the data layer) **landed in PR #99**. Steps 4b onward (the handler
unification) are the remaining work that wins parity.

1. ✅ **Redefine the transaction seam** as an async batch-of-statements
   primitive on `Backend` (the keystone). *Done.*
2. ✅ **Restructure the read-then-write sites** (client-side ids / `RETURNING`
   / guarded conditionals) so writes are batchable on D1. *Done.*
3. ✅ **Flip `Backend` to async** and ship the native `sqlx` backend +
   `core::Database` (reads and writes) + the worker `D1Backend`. *Done.*
4. **Handler unification** (in progress — the parity work):
   - a. ✅ Worker read path + Cron indexer fold onto `core::Database`. *Done.*
   - b. **Add `aos-proto-types`** — message structs generated independently
     with `prost-build` (`prost` + `serde`, wasm-clean), the lingua franca of
     `RpcService`. `aos-proto` keeps its `connectrpc`/`buffa` generator for the
     native transport (it has no `extern_path` to share types).
   - c. **Lift the handlers into `core`** as one shared `axum` router: facade,
     browse UI, JSON API, auth, producer console — plain `axum` handlers
     written once. Add the `Blobs` port and the `Lease`/`RateLimiter` ports;
     wire `SecretSealer`/`Mailer` worker impls.
   - d. **RPC transport adapter**: extract RPC method bodies into a
     transport-free `RpcService` in `core`; native delegates from the
     `connectrpc` server, the worker mounts a hand-rolled Connect-unary `axum`
     handler over `aos-proto-types` (see the spike amendment above).
   - e. **Fold the worker** onto the shared router via `axum-cloudflare-adapter`
     and **delete** `handlers.rs`/`reads.rs`/`facade.rs`/`render.rs`/`keymap.rs`
     (the duplicated read-only edge).
5. **Move the CLI to the API** under `aos hub …` (largely shipped in PR #99 as
   the `aos hub` ConnectRPC client against the native hub; the worker answers
   the same calls only once step 4d lands).
6. **Install-time root bootstrap** as the sole non-API mutation path.

## Open questions

- Does the SQLite/Postgres branch of the four claim/consume sites already
  use a single `RETURNING` statement (making them D1-clean without change)?
  Confirm before estimating step 2.
- `sqlx::Any` vs per-driver pools: does `Any` carry acceptable overhead and
  type fidelity across sqlite/pg/mysql, or do we want feature-gated concrete
  pools behind the same `Backend` impl?
- Whether the Cloudflare deployment *exposes* the write/console/auth surface
  by default or gates it behind configuration (parity in code; policy in
  config).
- ~~Can the shared `axum` router (incl. RPC) run on wasm?~~ **Resolved by the
  spike:** the router yes, the `connectrpc` *server* no — hence the RPC
  transport adapter (above).
- **`axum-cloudflare-adapter` ↔ `worker` version skew.** The adapter's latest
  (0.14) tracks `worker` 0.5.x, while the worker crate currently pins
  `worker` 0.4.2. The adapter's `to_axum_request` / `to_worker_response` take
  the `worker` crate's `Request`/`Response` types, so the adapter version must
  match the `worker` version the `#[event(fetch)]` shell uses. Resolve by
  bumping the worker crate to 0.5.x (and re-validating D1/R2 binding behavior
  under the pinned workerd) or pinning an adapter release built against 0.4.x.
- **Argon2 cost under the Worker CPU budget** (carried from sharp edges): the
  password-auth path runs in-request on the worker; confirm the cost
  parameters fit the per-request CPU limit or move password verification to a
  Durable Object.
