# RFC-0004: `aos-registry-hub` — a multi-tenant registry management WebUI

- **Status:** Implemented (phases 1–4) — `crates/aos-registry-hub`.
  Phase 1: surface reader, fail-closed indexer (anti-rollback floors,
  presence+integrity validation), machine-path facade, no-JS browse UI,
  cache-freshness probes, `aos.registry.v1` read path, local-first
  `serve --dev`. Phase 2: tenancy/IAM, tokens/JWT/device-flow/sessions/
  magic-links, storage bindings + nested URLs + visibility, authenticated
  upload facade. Phase 3: audit + SQL config change-sets, no-JS producer
  console, cache stacks + `apm` miss-fallthrough, per-org OIDC SSO.
  Phase 4: hosted signing keys + web channel advance (AES-256-GCM secret
  sealer), webhooks + `/metrics`, AOS package + NixOS module, and
  postgres + mysql `Database` backends behind a dialect trait (validated
  against live servers). Plus the phase-major `apr` upload fix and
  `apr web generate`. ~865 tests across the hub and `aos-package`.

  **Phase 5 (RPC unification SHIPPED; read-path relocation + tests remain,
  2026-06-16):** a single async runtime shared by the native hub and the
  Cloudflare Workers deployment, at **full feature parity** — see
  [`10-unified-runtime.md`](10-unified-runtime.md). This **supersedes** the
  read-only Workers edge in `crates/aos-registry-worker`.

  **Shipped:** the async `Backend` + shared `aos-registry-core::Database` (reads
  *and* writes; sqlx native / D1 Workers); a wasm-clean `aos-proto-types`
  message crate; the transport-free `RpcService` holding **all 26
  `aos.registry.v1` methods** (registry/package/channel/release reads, org/
  project/storage/IAM, config change-sets + revert, webhooks, publish, git),
  with the `RateLimiter` and surface-read (`SurfaceFetch`/`SurfaceProvider`)
  ports; and **one shared Connect-JSON `axum` router** (`core::connect`) that
  compiles and serves on **both** targets — the `connectrpc` *server* runtime
  can't target wasm (verified by a spike), so the transport is Connect-JSON
  (`POST /aos.registry.v1.{Service}/{Method}`) over plain `axum`, with a
  `SendWrapper` Send-bridge on the single-threaded Worker. The **Worker** mounts
  that router via a hand-rolled `worker`⇄`axum` bridge (no adapter dep — none
  supports the worker 0.4.x pin) over its D1/R2/D1-limiter; the **native hub**
  mounts the same router and its connectrpc `rpc.rs` is deleted (connectrpc gone
  from the registry path); and `aos-remote`/`aos hub` speak Connect-JSON,
  working identically against either deployment. No application logic is
  duplicated across the two.

  **Phase 5 complete:** the read-path **facade + browse UI + producer console**
  now live in the shared router (the Worker's read handlers and the hub's
  console/facade are one codebase); the async `Mailer` Worker impl (HTTP relay),
  install-time root bootstrap, the unified `core::indexer`, and the
  `SurfaceWrite`/`PublishLease` (D1) write ports all ship. The deployed Worker
  is exercised end-to-end by `pkgs.aos-registry-worker-e2e` (`just
  test-worker-e2e`), booting the real wasm artifact under workerd + miniflare —
  the gap `cargo test` (native-only) can't cover.

  The unification extends to **deployment + maintenance**: the native
  `aos-registry-hub` binary doubles as the installer. Provider-specific work is
  `aos-registry-hub worker deploy --provider cloudflare` (provision + deploy +
  secrets, packaged with `wrangler` + the Worker wasm as
  `pkgs.aos-registry-hub-cloudflare`); everything else is provider-neutral over
  `--target`: `init` (migrate + bootstrap root), `reset-root`, and every admin
  command run the *same* `core::Database` code over the local sqlite file or live
  D1 (the `WranglerD1Backend`, via `wrangler d1 execute`). Schema migration is
  CLI-driven — there is **no public init endpoint** on the Worker. See
  `crates/aos-registry-worker/deploy/DEPLOY.md`.

  **Proposed continuation (2026-06-17):** hosting managed Nix binary
  **caches** as a first-class sibling of registries — turning the hub from a
  cache *observer* into a cache *host* (GC, size limits, expiring manual pins,
  full-text search, closure-graph visualization, GC roots pinned to published
  packages, reclamation when versions are removed, no-JS browse, NAR explorer)
  — and the consequent `aos-registry-* → aos-hub` rename. Design + full
  implementation checklist in [`11-caches.md`](11-caches.md); not yet
  implemented.

  Still deferred to RFC-future: the Leptos-CSR WASM SPA web surface (the
  no-JS static tier ships); passkeys/WebAuthn beyond phase 2; mirroring
  (full/derived/pull-through); validation deep depth and HTTP-cache repair;
  git-backed change requests; quotas/backup/offboarding.
- **Date:** 2026-06-12 (Phase 5 addendum: 2026-06-15; wasm spike + Connect-JSON transport decision: 2026-06-16)
- **PR:** [#99](https://github.com/andyl-technologies/aos/pull/99)
- **Audience:** anyone working on `crates/aos-package/` (the `apr`/`apm`
  registry surface), `crates/aos-server/`, `crates/aos-proto/`,
  `crates/aos-registry-hub/`, `crates/aos-registry-worker/`, or the
  registry docs under `docs/registry/`.

This RFC is a multi-file directory: this `README.md` carries the status
header and indexes the topic files. The body below the status header is
history — only the status header is maintained as the design ships. Phase 5
is a live proposal and its own file carries its working status.

## Topic files

| File | Contents |
| --- | --- |
| [00-problem-and-goal.md](00-problem-and-goal.md) | The problem (no server to *manage* a static registry) and the goal |
| [01-architecture.md](01-architecture.md) | Stance — a control plane over a static data plane — and architecture / runtime targets |
| [02-tenancy-iam-auth.md](02-tenancy-iam-auth.md) | Tenancy and IAM, authentication (sessions/tokens/SSO), the access matrix |
| [03-api-storage-frontends.md](03-api-storage-frontends.md) | `aos.registry.v1` over ConnectRPC, `StorageBinding` + shared buckets, direct/proxied frontends |
| [04-caching-and-mirroring.md](04-caching-and-mirroring.md) | Cache stores, stacks, consistency validation; mirroring other registries |
| [05-url-cli-and-config.md](05-url-cli-and-config.md) | URL design (one URL, three audiences), CLI convergence, configuration management |
| [06-web-surface.md](06-web-surface.md) | UI surface map, the static SPA on the registry's own CDN, sitemap / page flows / visual design |
| [07-data-ops-and-testing.md](07-data-ops-and-testing.md) | Database schema sketch, operations (migrations/backup/quotas/observability), testing, changes outside the hub crate |
| [08-sequencing.md](08-sequencing.md) | Implementation sequencing of the shipped phases |
| [09-alternatives-and-open-questions.md](09-alternatives-and-open-questions.md) | Alternatives considered and open questions |
| [10-unified-runtime.md](10-unified-runtime.md) | **Phase 5 (Complete):** one async codebase, full Cloudflare/native parity, sqlx + D1 backends, `aos hub` CLI-over-API, the wasm-feasibility spike + Connect-JSON transport decision, the D1 transaction audit, the workerd+miniflare e2e |
| [11-caches.md](11-caches.md) | **Proposed:** hosting managed Nix binary **caches** (GC, size limits, expiring pins, search, closure-graph viz, GC roots pinned to packages, NAR explorer, web browse) as a first-class sibling of registries — the org/registry/cache topology, schema (v22+), GC subsystem, and the `aos-registry-* → aos-hub` rename. Carries its own implementation checklist. |
| [12-storage-frontends.md](12-storage-frontends.md) | **Proposed:** **storage-binding frontends** — a public bucket owns its CDN frontend, and registries/caches stored in it inherit a direct-from-bucket frontend (path inferred from their `prefix`), with a per-consumer advertise toggle; promotes the instance default storage to a real, editable binding so it shares the same frontend form. Serves bulk `nar/**`/git bytes straight from R2's CDN instead of streaming through the Worker. Carries its own implementation checklist. |
| [13-streaming-multipart-uploads.md](13-streaming-multipart-uploads.md) | Streaming multipart uploads through the facade. |
| [14-colocated-storage-architecture.md](14-colocated-storage-architecture.md) | **Proposed:** the target storage architecture, motivated by a production investigation of the deployed Worker's ~150–300 ms per-request D1 latency floor (measured: per-request D1 *session* cost, not query execution / distance / cold start). Maps each data class to the right primitive — **KV (Worker) / LMDB (native)** for hot point-reads (sessions/tokens/config/routing), **Durable Objects** for coordination (rate-limit/lease/anti-rollback), edge-regenerated read models for browse, and **tenant-sharded SQLite-in-DO** as the colocated system of record — all behind single-source ports. Carries a phased (A–E), goal-mode implementation checklist. |
