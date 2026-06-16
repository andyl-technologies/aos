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

  **Phase 5 (In progress, 2026-06-16):** a single async runtime shared by the
  native hub and the Cloudflare Workers deployment, at **full feature
  parity** — see [`10-unified-runtime.md`](10-unified-runtime.md). This
  **supersedes** the read-only Workers edge in `crates/aos-registry-worker`.
  The **data layer landed** (PR #99): the async `Backend` trait, the shared
  `aos-registry-core::Database` (reads *and* writes), and the worker's
  `D1Backend` (sqlx for native pg/mysql/sqlite, D1 for Workers). The
  **remaining work** is the handler unification: the read/write/console/auth
  path becomes one shared `axum` router served natively via `axum::serve` and
  on Workers via `axum-cloudflare-adapter`, deleting the worker's hand-written
  read-only fetch router. A wasm-feasibility spike (2026-06-16) confirmed the
  shared router compiles to wasm but the `connectrpc` *server* runtime does
  not, so the registry hub serves a single **Connect-JSON** transport (plain
  JSON over HTTP — `POST /aos.registry.v1.{Service}/{Method}`) as shared `axum`
  handlers on both targets, dropping the `connectrpc` runtime from the registry
  path entirely (a new wasm-clean `aos-proto-types` crate holds the message
  structs; `aos-remote`'s hub client becomes a Connect-JSON client). Phase 5
  folds the standalone hub CLI into `aos hub …` (API-driven, no direct DB
  access); once the unification lands the worker answers the same
  `aos.registry.v1` calls. Gated on the D1 batch-only transaction audit
  recorded in that file.

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
| [10-unified-runtime.md](10-unified-runtime.md) | **Phase 5 (In progress):** one async codebase, full Cloudflare/native parity, sqlx + D1 backends, `aos hub` CLI-over-API, the wasm-feasibility spike + Connect-JSON transport decision, the D1 transaction audit |
