## Design

### Stance: a control plane over a static data plane

The single load-bearing decision: **the hub never becomes a dependency
for consumption.** The git-over-CDN surface on S3/R2 stays the source
of truth; `apm` and plain Nix keep working if the hub is down, deleted,
or never deployed. The hub is three things layered on top:

1. **A read index** — it parses the same surface `apm` parses
   (including full signature verification) and renders it for humans.
2. **A write orchestrator** — it hosts the tenancy/IAM layer, mints
   upload credentials, tracks the publish pipeline, and (optionally)
   flips mutable pointers itself.
3. **A compatible facade** — every registry URL it serves *is
   simultaneously* a dumb-HTTP git origin and a Nix binary cache, by
   redirect or zero-egress proxy to the object store.

Consequence: the SQL database is **a rebuildable cache plus the
tenancy/IAM system of record**. Registry content (packages, versions,
channels, rosters) is always derivable by re-indexing the git surface;
only tenancy (orgs, projects, users), registry identity and topology
(visibility, binding, frontends — facts that exist nowhere on
the surface), tokens, and audit live solely in SQL. This keeps the
sqlite→postgres→mysql story trivial and makes "import an existing
registry" a first-class operation rather than a migration.

Corollary: the hub displays *verified* state, never trusted state. The
indexer performs the same checks an `apm` client performs — tag
signature verification, name-binding, roster walks, anti-rollback
floors (`crates/aos-package/src/registry/verify.rs`,
`channel.rs`) — and surfaces verification failures as first-class
health states rather than hiding them.

### Architecture and runtime targets

One new crate, **`crates/aos-registry-hub`**, plus proto additions to
the existing `aos-proto` crate (a new `aos.registry.v1` package,
buf-managed alongside `aos.{cache,build,gc,auth}.v1`).

The crate is a Leptos application (SSR + hydration) with build profiles
selected by features, the standard Leptos pattern:

```text
crates/aos-registry-hub/
  src/
    domain/      # orgs, projects, IAM, authz — pure, wasm-clean
    surface/     # registry-surface reader: loose objects, packs, tag
                 # objects + Ed25519 verify, package TOML, narinfo,
                 # channel partition resolution — pure Rust, no git CLI
    db/          # Database trait + dialect SQL; drivers below
    rpc/         # ConnectRPC service impls (aos.registry.v1)
    compat/      # nix-cache + dumb-HTTP facade (redirect/proxy to
                 # object store, auth on private registries)
    ui/          # Leptos components/pages
  bin: aos-registry-hub   (native: axum + tokio + sqlx + aos-net S3)
  cdylib: worker          (Cloudflare Workers via workers-rs:
                           D1, R2 bindings, Queues/Cron, KV sessions)
```

- **Native target** — what a self-hosting operator runs: axum server,
  sqlx with the driver selected at runtime by database URL
  (`sqlite://`, `postgres://`, `mysql://`), S3 via the existing
  `aos-net` SigV4 engine. Packaged as an AOS package + module
  (`aos.registry-hub.enable = true`) so operators deploy the hub *with*
  AOS.
- **Local-first operation is a hard requirement, not a degraded
  mode.** The native binary + a sqlite file + `LocalFs` storage
  bindings is a *complete* hub: `file://` paths are valid registry
  backends exactly as they already are for `apr` and `aos-cache`'s
  `FsBackend`, and every feature — the dumb-HTTP/nix-cache facade,
  browse UI, indexing and verification, consistency validation,
  publish leases and the upload facade, the web surface — works
  offline against the local filesystem. `aos-registry-hub serve --dev`
  boots zero-config: an ephemeral sqlite database and a bindings
  directory under `--root`, listening on localhost, so
  `apr release --upload-url http://127.0.0.1:8420/...` and
  `apm` consumption against the same URL form a complete loop on one
  machine with no cloud account, no network, and no containers. This
  one binary is simultaneously the self-host story, the development
  environment, and the integration-test harness — local is a
  deployment target, not a simulator of one.
- **Cloudflare target** — `wasm32-unknown-unknown` via `workers-rs`.
  D1 is the sqlite backend (same dialect, different driver); R2 via
  native bindings gives a zero-egress facade, which is why R2 is the
  flagship deployment; Cron Triggers/Queues drive the indexer,
  validator, and mirror jobs; KV holds sessions.
- **Database abstraction** — sqlx does not compile to
  `wasm32-unknown-unknown`, so `db/` defines a small async `Database`
  trait (execute / query / transaction) with two drivers — sqlx
  (native) and D1 (workers) — and per-dialect SQL kept to the common
  subset. Deliberately hand-rolled, not an ORM: three dialects × two
  drivers is exactly where ORMs leak. The one intentional divergence is
  full-text search (FTS5 on sqlite/D1, `tsvector` on postgres,
  `FULLTEXT` on mysql), isolated behind a single search query.
- **The `surface/` reader is the linchpin** — a pure-Rust,
  no-IO-assumptions parser for the registry wire surface: zlib-inflate
  loose objects under `/objects/<xx>/<62-hex>`, pack/idx walks, tag
  object parsing with SSH-format Ed25519 verification (`ed25519-dalek`
  is wasm-clean), package TOML, narinfo, and channel partition
  resolution with name-binding checks. It reimplements the *read half*
  of `crates/aos-package/src/registry/` without the git CLI (which
  `apm` shells out to and which does not exist on Workers). The pure
  parsing types (`types.rs`, `registry/parse.rs`) should be shared with
  `aos-package` — day one by direct reuse if they prove wasm-clean,
  otherwise by factoring them into a shared no-IO module. Divergence
  between the hub's parser and `apm`'s is a correctness bug class to
  design against: the e2e test suite must run both against the same
  fixture surfaces. The same crate compiles for a **third runtime —
  the visitor's browser** (see "The registry web surface"), so one
  parser serves server, Worker, and client.
- **Indexer robustness.** Indexing is checkpointed and incremental,
  keyed on `last_indexed_commit` — a re-walk fetches only the delta
  (packs/thin deltas, the same access pattern as `apm`). Index state is
  explicit and user-visible: `fresh`, `indexing`, `stale` (upstream
  unreachable; shown with last-success age and retry/backoff state),
  `failed` (verification error — a first-class health alarm, never
  silently hidden), `partial` (crash mid-index; resumes from the
  checkpoint). On Workers, large registries are indexed in
  Queue-batched slices to respect CPU/duration limits. All list APIs
  (`PackageService`, search, audit) are paginated from day one.

