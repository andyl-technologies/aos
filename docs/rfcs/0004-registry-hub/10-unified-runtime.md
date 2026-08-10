# Phase 5: one async runtime, full Cloudflare/native parity

- **Status:** Complete (2026-06-17). **Data layer + handler unification landed**
  (PR #99): the async `Backend` trait, the shared `aos-registry-core::Database`
  (reads *and* writes), and the worker's `D1Backend` all ship. The handler
  unification — where parity is won — is **done**: the facade, browse UI, JSON
  API, RPC, auth, and producer console all live in one shared `axum` router in
  `core`, served natively via `axum::serve` and on Workers via a hand-rolled
  `worker`⇄`axum` bridge (the published `axum-cloudflare-adapter`s don't support
  the worker 0.4.x pin — see Open questions). The worker's hand-written
  read-only fetch router is deleted; no application logic is duplicated. The
  wasm-feasibility spike is in
  "[Spike results](#spike-results-2026-06-16-what-actually-compiles-to-wasm)"
  below; it forced the RPC transport decision (the `connectrpc` *server*
  runtime cannot target wasm, so the hub serves a single **Connect-JSON**
  transport over shared `axum` handlers — see below). The D1 transaction audit
  for the write sites is resolved (synchronous anti-rollback floor-raise on
  channel advance). The async `Mailer` Worker impl, install-time root bootstrap,
  unified `core::indexer`, and `SurfaceWrite`/`PublishLease` (D1) ports ship.
  The deployed wasm artifact is verified end-to-end under workerd + miniflare by
  `pkgs.aos-registry-worker-e2e` (`just test-worker-e2e`).
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
in `hyper`/`hyper-util`/`tokio`+`mio`/`zstd-sys`), so the registry hub leaves
the connectrpc runtime and serves a single **Connect-JSON** transport as plain
`axum` handlers on both targets. The sync-vs-async constraint —
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

The audit of `aos-registry-hub` surfaced more native-only couplings that the
write/console/auth path depends on. **All are now resolved** — each is a port
with a native and a worker impl, the logic above it written once. The surface
*write* path that backs all of them is `core::surface_write::SurfaceWrite`
(native filesystem with safe-join + symlink containment + atomic temp-rename;
worker R2 `put`/`delete`), and it backs the three write consumers now shared on
both shells: the facade artifact-upload `PUT`, the git-backed config/change
flow, and retained signing operations (`core::signing`). The couplings:

- `SecretSealer` (**exists** in `core::auth::seal`) — seals OIDC client
  secrets and the isolated draft-signing seed at rest (AES-256-GCM). Native builds it from a
  file-backed instance key; the worker builds the *same* `AesGcmSealer` from a
  Wrangler secret binding. No new trait — just a different constructor.
- `Mailer` (**now an async trait** in `core::auth::magic`) — sends magic-link /
  invite email. Made `async` so a deployment can deliver over the network: the
  worker's `WorkerMailer` `POST`s the link to an `HUB_EMAIL_API_URL` relay over
  the Fetch API (optional `HUB_EMAIL_API_TOKEN` bearer), falling back to
  `console_log!` when unset; the native hub keeps `LogMailer` by default and can
  inject any async sender.
- **Publish lease** (**now a trait** — `core::lease::PublishLease`) — the
  native hub keeps its in-memory `Mutex<LeaseMap>` (`InMemoryLease`) behind the
  port; the worker's `D1PublishLease` is a conditional upsert (take iff no row /
  `deadline <= now` / holder is mine; release iff mine) over the
  `publish_leases` D1 table — atomic across the edge. Wired into the facade
  `PUT` for mutable-pointer flips.
- **Rate limiter** (**now a trait** — `core::ratelimit::RateLimiter`) — the
  native hub keeps its in-memory token bucket behind the port; the worker's
  `D1RateLimiter` meters over a D1 counter table, so the per-isolate problem is
  gone. Pre-auth handlers key it on a runtime-neutral `ClientIp` (the hub
  resolves it from the socket peer / trusted-proxy `X-Forwarded-For`, the worker
  from `CF-Connecting-IP`).

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

**Consequence — RPC drops the `connectrpc` runtime on *both* sides, and the hub
serves one transport: Connect-JSON over plain `axum` (decision 2026-06-16).**
The `connectrpc` server is hyper/tokio and cannot mount on the worker. Running
two different RPC transports (connectrpc natively, something hand-rolled on the
worker) would defeat "a single hub," so the registry hub serves **one**
transport on both targets: **Connect-JSON**.

Connect-JSON is the Connect protocol's JSON encoding — `POST
/aos.registry.v1.{Service}/{Method}` with a JSON request body, a JSON response
body, and a JSON error envelope `{ "code": …, "message": … }`. It is ordinary
JSON-over-HTTP that compiles and runs anywhere `axum` does: no `buffa`, no
proto-binary framing, no `connectrpc` runtime, callable from browsers with
`fetch`. Because it is just `axum` handlers, the registry RPC surface is the
**same shared handlers** as every other route — *there is no per-target RPC
adapter*. The native hub moves off the connectrpc *server* too; method bodies
live once in a transport-free `RpcService` in `core` that the shared handlers
call.

The schema stays in `.proto` (the contract, consistent with the rest of AOS);
only the runtime path changes:

- **`aos-proto-types`** (new, wasm-clean) — the request/response structs
  generated from the `.proto` with `prost-build` + `serde` derives (no `buffa`,
  no `connectrpc`). `connectrpc-build` 0.3 can't supply these (it emits
  `buffa`-based types via its own `buffa_codegen`, with no `extern_path`/reuse
  knob), so they are generated separately. These serde structs are the lingua
  franca of `RpcService`, the shared handlers, and the client; JSON is the only
  wire encoding, so the structs' serde shape is the contract both ends agree on.
- **`aos-proto`** keeps its `connectrpc`/`buffa` codegen for the *other* AOS
  services (cache/build/gc/auth), which are unaffected — the registry hub simply
  stops using the connectrpc runtime.
- **`aos-remote`** — `RegistryHubClient` becomes a small Connect-JSON client
  (`reqwest` natively) over `aos-proto-types`, replacing the connectrpc client.
  The `aos hub …` CLI is unchanged above that client.

Every route — facade, browse, JSON read API, auth, console, **and RPC** — is
the byte-identical shared `axum` handler on both targets. **No transport or
service logic is written twice.**

`RpcService` carries the same **target-conditional `Send` bound** the shipped
`Backend` trait already uses — `#[cfg_attr(not(target_arch = "wasm32"),
async_trait)]` (Send) natively, `async_trait(?Send)` on wasm — so the native
tokio server gets the `Send + 'static` futures it requires while the worker's
single-threaded handler stays `?Send`. The `?Send` in the illustrative trait
sketches above is the wasm arm of that same `cfg_attr`, not an unconditional
bound; the method bodies remain single-source.

> Reality note: the shipped data layer holds the backend as `Box<dyn Backend>`
> on `Database` (not the generic `Router<State<B: Backend>>` this file
> originally sketched under "Dispatch"). The boxed form keeps `core` free of a
> backend type parameter and mounts cleanly through the hand-rolled worker
> bridge; the "prefer generics" note below is superseded.

## Frontends: one router, two servers

```rust,ignore
// native shell (aos-registry-hub)
let app: axum::Router = aos_registry_core::connect::router(service);
axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;

// worker shell (aos-registry-worker) — hand-rolled bridge (no adapter dep; see
// the version-skew resolution in Open questions), over worker 0.4.2's API.
#[event(fetch)]
async fn fetch(req: worker::Request, env: Env, _: Context) -> worker::Result<worker::Response> {
    let app = aos_registry_core::connect::router(service_from(env)?);  // identical router
    let axum_req = worker_request_to_http(req).await?;     // method/uri/headers/body
    let axum_resp = app.oneshot(axum_req).await?;          // SendWrapper bridges Send
    http_response_to_worker(axum_resp).await               // status/headers/body
}

#[event(scheduled)]
async fn scheduled(_e: ScheduledEvent, env: Env, _: ScheduleContext) {
    aos_registry_core::indexer::index_all(&backend(env)?, &blobs(env)?).await.ok();
}
```

`facade.rs`, `keymap.rs`, `render.rs`, the inline JSON API, and the query
methods in `d1.rs` all **delete** — they become the shared `handlers`/`render`
over `D1Backend`. RPC joins them: with the Connect-JSON decision above, the
`/aos.registry.v1.{Service}/{Method}` routes are *also* plain shared `axum`
handlers (calling `RpcService`), byte-identical on both targets — the
`connectrpc` server runtime is dropped, not adapted. Natively this replaces the
`#[connectrpc]` trait impls in `aos-registry-hub::rpc` with the same shared
handlers; `aos-registry-hub::rpc.rs` deletes too. Every route in the sketch is
byte-identical on both.

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

The CLI stops opening the database and becomes a **Connect-JSON** client of the
hub's `aos.registry.v1` services (`RegistryService`, `OrgService`,
`ConfigService`, …) — a small `reqwest` client over `aos-proto-types`, posting
JSON to `/aos.registry.v1.{Service}/{Method}`. (The other AOS surfaces —
`aos build --remote` / `aos gc --remote` — keep their `aos-remote` connectrpc
clients; only the registry hub leaves the connectrpc runtime.) The standalone
`aos-registry-hub` subcommands move under `aos hub …`:

```text
aos hub serve                                  # run the native hub
aos hub registry create <org>/<proj>/<name> …  # RPC call, --hub <url> --token <…>
aos hub instance set-signup-policy invite_only # RPC call
```

Once handler unification lands (step 4), the Worker serves the *same* router for
every route — RPC included, as shared Connect-JSON handlers (the decision
above) — so `aos hub … --hub https://…workers.dev` will configure a Cloudflare
deployment identically to a native one — no raw D1 SQL, no `wrangler` seeding
beyond the one-time `migrations apply`. Same code path yields the same config
path. *Handler unification has landed: the worker now serves the **entire**
shared router — RPC, the facade read **and write** (`PUT`), browse, the full
producer console (login/OIDC/activate/passkey/IAM/config/changes), and
retained signing operations — so `aos hub … --hub https://…workers.dev`
administers a Cloudflare deployment identically to a native one. Schema
migration and root bootstrap are CLI-driven over D1 (`aos-registry-hub init
--target d1:<name>`) — the Worker has no public init endpoint.*

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
4. **Handler unification** (the parity work — RPC, facade, browse, and most of
   the producer console now shared):
   - a. ✅ Worker read path + Cron indexer fold onto `core::Database`. *Done.*
   - b. ✅ **`aos-proto-types`** — wasm-clean `prost`+`serde` message structs,
     the lingua franca of `RpcService`/the shared handlers/the client. *Done.*
   - c. ✅ **Lift the handlers into `core`** — the shared Connect-JSON `axum`
     router (`core::connect`), the `RpcService` (all 26 `aos.registry.v1`
     methods), the R2/fs **facade** (`RpcService::facade_fetch`), the **browse
     UI** (`core::web::browse`/`render`), and **39 of the producer console's
     routes** (`core::web::console`) all run on one code path; the ports —
     `RateLimiter` (`core::ratelimit`), `SurfaceFetch`/`SurfaceProvider`
     (`core::fetch`), `Mailer`/`SecretSealer` (`core::auth`), plus the console's
     `HttpClient` and `ChannelAdvancer` — abstract the rest. The worker's
     `facade.rs`/`reads.rs`/`render.rs` are deleted; the hub's `console.rs`
     shrank from 5277 to ~2100 lines. *Done.* **Remaining:** the 9 console
     routes that need a host-only capability — the pre-auth rate-limited
     login/activation paths (a `ClientIp` abstraction, *in progress*), the OIDC
     flow (route its outbound calls through the `HttpClient` port), and the
     git-backed config/change-request flows (an R2 surface-write port).
   - d. ✅ **RPC as shared Connect-JSON handlers** — `RpcService` + `core::connect`
     serve all 26 methods (`POST /aos.registry.v1.{Service}/{Method}`, JSON
     in/out, `{code,message}` errors) on both targets. *Done.*
   - e. ✅ **Fold the worker** — the Worker serves the **full** shared router
     (RPC, facade, browse, and the shared console) via the hand-rolled
     `worker`⇄`axum` bridge + the `SendWrapper` Send bridge; its D1/R2/D1-limiter
     back the `RpcService`, and its `consoleports` (logging `Mailer`, Fetch-API
     `HttpClient`, AES-GCM sealer) back the `ConsoleDeps`. *Done.*
   - f. ✅ **Port `aos-remote::RegistryHubClient`** to a Connect-JSON `reqwest`
     client over `aos-proto-types`. *Done.*
   - g. ✅ **Rewire the native hub** to mount `core::connect::rpc_router()` and
     `core::web::console::console_router()` (the CLI speaks Connect-JSON); the
     connectrpc `rpc.rs` services are retired. *Done.*
5. ✅ **Move the CLI to the API** under `aos hub …` — the client speaks
   Connect-JSON and answers identically from the native hub or the worker.
   *Done.*
6. ✅ **Schema migration + root bootstrap are CLI-driven** (provider-neutral over
   `--target`), not a public endpoint. *Done* — `aos-registry-hub init --target
   <local|d1:name>` runs the shared `MIGRATIONS` then `find_or_create_user` +
   `hash_password` + `set_user_password`, against the local sqlite file or live
   D1 (the `WranglerD1Backend`). The Worker has no `/_init` endpoint.

The indexer is also unified: `core::indexer` is the single canonical
fetch→verify→load→index orchestration over the `SurfaceFetch` port — the native
hub reindexes inline over it and the Worker's Cron runs the same code over R2,
so the index (packages, channels, anti-rollback floors) cannot drift between the
two shells. (One intentional change: the Worker Cron now skips public registries
of soft-deleted orgs, matching the native hub's `list_registries` filter.)

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
  spike:** the router yes, the `connectrpc` *server* no — hence the single
  Connect-JSON transport over shared `axum` handlers (above).
- **Connect-JSON body shape — RESOLVED: camelCase field names + native JSON
  scalars.** `aos-proto-types` derives `serde` with `#[serde(rename_all =
  "camelCase")]`, so fields are canonical proto3-JSON names (`orgSlug`,
  `nextPageToken`, `expiresAt`) — this is what the old connectrpc server emitted
  and what the hub tests assert. It is *not* fully canonical proto3-JSON: int64
  is a JSON **number**, not the proto3-canonical string, and there's no
  base64-bytes/enum-as-string handling. That's fine because all consumers
  (the hub handlers, the Worker, the `aos-remote` client, `apr`/`apm`) share the
  same `aos-proto-types` structs, so both ends agree. (Lesson learned: the
  field-name half *was* contract-load-bearing — plain snake_case 404'd
  `{"orgSlug":…}` requests; the int64-as-string half was not, and only one test
  assumed it.) Upgrade path if a *stock* Buf/Connect client ever needs byte-exact
  canonical proto3-JSON: swap the serde derives for `pbjson-build` — no handler
  or service change.
- **`axum-cloudflare-adapter` ↔ `worker` version skew — RESOLVED: hand-roll the
  bridge, drop the adapter.** No adapter release supports the AOS pin: 0.12
  needs `worker` 0.2 + `axum` 0.7, and 0.14 jumps to `worker` 0.5 + `axum` 0.8 —
  there is no build for `worker` 0.4.x with `axum` 0.8 (confirmed against the
  published crate manifests). Using the adapter would force a `worker`
  0.4.2 → 0.5 bump (changed D1/R2 APIs, re-validation against the pinned
  workerd's D1 quirks) for no real gain, since the adapter only converts
  `worker::Request`⇄`http::Request` and runs `router.oneshot`. The Worker shell
  therefore **hand-rolls** that ~40-line bridge over `worker` 0.4.2's
  `Request`/`Response` API and calls `connect::router(...).oneshot(req)`
  directly — keeping the pin, dropping the external dependency, and still
  serving the *same* shared `axum` router. (The Send bridge above —
  `SendWrapper` — is what makes that router mountable on wasm in the first
  place.)
- **Argon2 cost under the Worker CPU budget** (carried from sharp edges): the
  password-auth path runs in-request on the worker; confirm the cost
  parameters fit the per-request CPU limit or move password verification to a
  Durable Object.
