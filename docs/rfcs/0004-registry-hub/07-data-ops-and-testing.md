### Database schema (sketch)

System-of-record tables: `orgs`, `projects` (materialized-path
hierarchy), `users`, `user_identities` (`(iss, sub)`-keyed),
`service_accounts`, `memberships(principal, scope, role)`,
`tokens(id, hash, owner, scope, permissions, expires_at, revoked_at,
last_used_at)`, `sessions`, `invitations`, `org_idp_configs`
(encrypted client secrets), `org_domains` (TXT-verified),
**`registries`** (identity, slug, visibility, `storage_binding_id`,
prefix — facts that exist nowhere on the surface and do *not* survive a
re-index), `storage_bindings`, `frontends`, `cache_stores`,
`mirror_sources`, signing-key identities/generations/usages, `publish_jobs` (leases,
staged releases, pipeline state), `config_changesets`,
`config_revisions`, `audit_log`, `webhooks` (phase 4; event taxonomy
and delivery model in a follow-up RFC). The `cache_stores` sketched here
is superseded by the managed-cache `caches` table and its companions
(`cache_registry_links`, `cache_gc_policy`, `cache_gc_roots`) in
[11-caches.md](11-caches.md).

Rebuildable index tables (derived from the surface, droppable and
re-indexable at any time): `registry_index` (per-registry
`last_indexed_commit`, frontier, index state, health), `packages`,
`package_versions`, `version_platforms`, `channels`,
`channel_partitions(channel, bucket, release, sig_key_id)`,
`channel_floor_events` (derived from indexed tag/partition history),
`releases(semver, tag_hash, signer, pack_presence)`, `key_rosters`,
`validation_runs`, `validation_findings(cache, store_hash, depth,
status)`, `frontend_probes`, plus the per-dialect full-text index.
Reverse-dependencies are derived from `closures/` during indexing, not
stored as a separate source of truth.

### Operations: migrations, backup, quotas, observability, offboarding

The index half of the database is disposable; the system-of-record half
is not, and a multi-tenant service needs the unglamorous chapters
written down:

- **Migrations.** Ordered SQL migration files per dialect, applied by
  an embedded runner: at startup under an advisory lock natively; at
  deploy time (wrangler migrations) or behind a first-request gate on
  D1. A `schema_version` table is the source of truth; the runner
  refuses to serve ahead of or behind its known range. Moving an
  instance between backends is an app-level export/import (below), not
  a SQL-dump translation.
- **Backup.** The SoR tables must be backed up: D1 Time Travel /
  export on Cloudflare; `sqlite3 .backup` / `pg_dump` / `mysqldump`
  natively; plus an app-level encrypted export covering the same data
  for backend moves. Signing-key private material remains in explicit external
  custody; exports retain public generations, exact usage pins, and immutable
  provider-version references but never private key bytes.
- **Quotas and limits.** Per-org quotas on hub-managed storage (bytes
  and object count — enforced at the upload facade with
  `507 Insufficient Storage`, the same contract as `aos-server`'s
  `max_paths`), registries, members, and active tokens. Per-endpoint
  rate limits by class: anonymous browse/search (per-IP),
  device-authorization and magic-link issuance (per-target *and*
  per-IP — the email-bombing surface), token exchange, and the upload
  facade (per-token). Instance signup policy is `open` or
  `invite-only` on both the hosted instance and self-hosted ones —
  free hub-managed storage behind an open signup is an abuse magnet
  and the default hosted posture is invite-gated org creation with
  open membership-by-invitation.
- **Observability of the hub itself.** The hub monitors registries;
  this monitors the hub. Natively: a Prometheus `/metrics` endpoint,
  structured JSON logs, optional OTLP traces. On Workers: Workers
  Analytics Engine counters and Logpush with the *same* structured-log
  schema and metric names, so dashboards are portable. A `/healthz`
  endpoint covers DB reachability, binding reachability, and indexer
  lag; the AOS module wires it to systemd watchdog/readiness.
- **Offboarding and export.** Org deletion is soft, gated (owner +
  sudo + typed path), with a 30-day grace window during which an
  export job can run. Export is genuinely easy here and worth
  advertising: a registry *is* a portable git surface + bucket prefix
  — the export job copies the prefix to any S3-compatible target the
  org supplies, and the SQL SoR (members, tokens-metadata, audit
  slice) exports as JSON. At hard-delete, hub-managed objects are
  removed, signing-key usages are detached while public generations remain
  available for verification, and the audit log is retained per instance policy
  (default one year) with the org tombstoned. User deletion requires
  transferring sole ownerships first; their sessions and owned tokens
  deaden immediately.

### Testing

The pyramid exploits the local-first property: the hermetic local hub
*is* the harness, and the no-JS design language makes most of the UI
assertable with plain HTTP.

1. **Parser-divergence fixtures.** Golden fixture surfaces —
   committed registry trees, packs/thin-deltas, channel partitions,
   static caches — generated *by `apr`* in a build step. Both `apm`'s
   reader and the hub's `surface/` reader run against every fixture;
   any disagreement (parse result, signature verdict, channel
   resolution) is a test failure. This pins the bug class named in
   Architecture, and the same fixtures feed the in-browser verifier's
   wasm tests.
2. **Database contract tests.** One contract suite for the `Database`
   trait, run against every driver: sqlite always (in-process);
   postgres and mysql as hermetic services built as AOS packages and
   started inside the sandbox (their packaging is its own work, owed
   anyway under the repo's no-host-tools principle); the D1 *dialect*
   is sqlite and is covered by the sqlite runs, while the D1 *driver
   shim* is exercised by tier 4. Dialect SQL runs on real engines,
   never mocks.
3. **The end-to-end CLI loop — the test that matters.** Start the
   native hub on sqlite + a `LocalFs` binding; run the real `apr`
   against it (`apr login` via device flow, `apr create --remote`,
   `apr release --upload-url http://127.0.0.1:…`), then the real
   `apm` consumes through the facade (update → install → channel
   advance via prepared op → upgrade), asserting the entire magic
   contract — unchanged-CLI publish, leases, the validation gate's
   202 semantics, indexing, facade consumption — in one hermetic test.
   The same scenario scales up into the existing fleet harness as a
   hub-in-the-middle variant of `tests/fleet/apm-registry-upgrade.nix`
   (hub running as the AOS module in one VM, hosts upgrading through
   it).
4. **Workers runtime, three tiers.** (a) Day one: the Workers drivers
   (D1/R2/KV shims) are tested against in-tree fakes implementing the
   same traits over sqlite/filesystem — fast, hermetic, runs
   everywhere. (b) When a hermetic `workerd` AOS package lands (it
   builds with Bazel, which the repo already builds from source — but
   it drags in V8; see open question 11), a check runs the actual
   worker cdylib under workerd with D1/R2 emulation. (c) Non-hermetic
   staging deploys against real Cloudflare (deploy → smoke → destroy)
   run as CI cron *outside* `nix-build` — the only tier that touches
   the real platform, and deliberately not load-bearing for merges.
5. **UI tests.** The tier-3 no-JS pages and all SSR pages are asserted
   with plain HTTP + HTML checks — curl-testable by design, which is
   the design language paying rent in CI. Leptos component tests
   render SSR natively. Full headless-browser/WASM e2e is optional and
   non-hermetic initially.
6. **Policy lints.** The asset-policy CI walk (no third-party URLs in
   dist or rendered pages) and the CSP header check run on every
   build.

### Changes outside the hub crate

The hub is one crate, but several small changes land in existing code,
each independently valuable:

| Where | Change | When |
| --- | --- | --- |
| `apr` (`static_upload.rs`) | Phase-major multi-destination ordering (immutables to all mirrors, then mutables to all); `content_type()` entries for `.wasm/.html/.js/.css/.json`; collect `index.html` + `web/` + `browse/` | phase 1, in parallel |
| `apr` | New `apr web generate` / `apr web config`; `apr release` web-dir awareness | phase 1, in parallel |
| `apr` | `apr channel advance --from-hub <id>` (execute a prepared advance); `apr release --wait` (poll a gated flip) | hub phase 3 |
| `apr` | `apr change merge <id>` (fetch, review, sign, push a hub change request) | hub phase 3 |
| `apm` (`download.rs`) | Cache miss-fallthrough (try next `[[caches]]` entry on 404) — today only the highest-priority cache is consulted | hub phase 3 |
| `registry.toml` | **None required** for mirrors/shared caches. Additive later: `[cache_stack]` expression; `[[origins]]` git-origin mirror list; `[registry.upstream]` inheritance | deferred |
| `apm` | Optional client-side `urls = [..]` git-origin fallback | deferred |
| `aos-proto` | `aos.registry.v1` package incl. `MintUploadCredentials` | phase 2 |
| `pkgs/` (rust) | `wasm32-unknown-unknown` std target in the from-source Rust chain (hermetic hub/SPA builds need it) | phase 1 |
| `pkgs/` | postgres + mysql packages (DB contract tests, and owed under package completeness anyway) | phase 2–3 |

On **registry inheritance**: layering already works consumer-side —
`apm`'s registry `priority` selects the package source across
configured registries, orthogonally to cache priority — so base +
overlay registries compose today. True committed inheritance
(`[registry.upstream]`, a child transparently re-exporting a parent's
packages) is backwards-compatible to add (the parser ignores unknown
fields; old clients simply don't see inherited packages) and is
deliberately deferred.
