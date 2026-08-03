# aos-hub-worker

The **Cloudflare Workers read-path target** for the AOS registry hub
(RFC-0004). The native hub (`aos-hub`) is a sync axum + tokio +
rusqlite binary that cannot compile to `wasm32-unknown-unknown`, and
`workers-rs` uses its own async router and async D1/R2/KV bindings — so this is
a **separate Worker crate** implementing RFC-0004's phase-1 Cloudflare
deployment (read index + facade), reusing the pure, shared crates rather than
porting the whole hub.

## What this Worker does (the read path)

- **R2 machine-path facade (zero-egress).** Serves a registry's machine surface
  — `HEAD`, `info/refs`, `objects/**`, `channels/**`, `releases/**`,
  `nix-cache-info`, `*.narinfo`, `nar/**`, and the `web/`/`browse/` files —
  directly from an R2 bucket binding, keyed `{registry-prefix}/{path}`. Each
  response carries the same immutable/60-second `Cache-Control` split and
  `Content-Type` the native facade and `apr origin upload` use, so the surface
  is byte-and-header faithful for `apm`, stock git, and Nix. A miss is a `404`.
  (`src/facade.rs`, `src/keymap.rs`.)
- **No-JS browse UI from D1.** The registry home, package index + detail,
  channel 256-partition grid, and releases pages, rendered server-side from D1
  (`src/render.rs`, `src/handlers.rs`). D1 *is* sqlite, so the read queries are
  the native hub's sqlite SQL strings unchanged (`src/sql.rs`).
- **A JSON read API** at `/{slug}/-/api/{registry,packages,channels,releases}`
  and `/-/api/packages/{name}` — the same data as the `aos.hub.v1` read
  services, served as plain `application/json`. See "What is NOT ported" for why
  this is a simple JSON shape, not full Connect framing.
- **A Cron-trigger indexer.** The `scheduled` handler re-walks every public
  registry's R2 surface into D1 (`src/indexer.rs`), reusing
  `aos-registry-surface` — the *exact* verifier the native hub indexer and `apm`
  run — to verify the HEAD commit signature, every release tag (signature + name
  binding + commit target), and every channel partition. A partition must point
  at a *known* release *tag object*: a partition targeting a non-tag object or
  an unknown/forged tag oid fails the whole index (the same hard checks the
  native `resolve_channels` makes — never a silent skip). Channels are also
  guarded by a monotonic anti-rollback floor (the `channel_floors` table,
  matching the native hub's "system of record"): a channel whose frontier fell
  below its recorded floor is rejected before any row is written, and a clean
  index raises the floor (only ever upward). The per-decision verification logic
  is factored into `src/indexlogic.rs` so it is unit-tested natively against the
  same rules. Fail-closed: an unverifiable or rolled-back surface is recorded
  `failed`, never `fresh`.

The Worker serves **public registries anonymously**; the D1 read queries filter
on `visibility = 'public'`.

## URL grammar

```text
/                              hub home — list public registries
/{slug}/-/                     registry home (HTML)
/{slug}/-/packages             package index (HTML)
/{slug}/-/packages/{name}      package detail (HTML)
/{slug}/-/channels/{name}      channel 256-partition grid (HTML)
/{slug}/-/releases             releases (HTML)
/{slug}/-/api/...              the JSON read API
/{slug}/{machine-path}         the R2 facade
```

The schema is migrated by the operator CLI over D1 (`aos-hub init
--target d1:<name>`), not by any HTTP endpoint — there is no `/_init`.

Human pages live under the reserved `/-/` segment (the GitLab convention) so
they cannot shadow the machine surface that owns the registry root.

> **Phase 5 update (shipped):** the lists below predate the Phase 5 runtime
> unification. The write/publish path, the producer console, authentication
> (sessions, tokens, device-code, magic links, OIDC SSO), and the
> `aos.hub.v1` surface are **no longer native-only** — they now live in the
> shared `aos-hub-core` router and the Worker serves them over its D1/R2/KV
> bindings (the transport is Connect-JSON over `axum`, since the `connectrpc`
> *server* runtime can't target wasm). The Worker serves only the request
> surface — schema migration is CLI-driven over D1, with no init endpoint. The
> genuinely still-deferred items are below.

## What is NOT ported (native-only for now)

- **Private/internal registry access control** — anonymous reads still resolve
  only `public` registries (the authed private-read path is RFC-future).
- **Package-table population from the committed tree.** The Cron indexer
  verifies and populates `releases`, `channels`, and `channel_partitions` (the
  cryptographically verified, surface-derivable core), but parsing
  `registry.toml` / the package TOMLs into `packages`/`version_platforms`
  depends on `aos-package`'s committed-file parsers, which are not part of the
  wasm-clean `aos-registry-surface` core. The browse UI renders whatever
  packages are present in D1 (e.g. populated by the native hub against the same
  D1 database, or a later wasm-clean tree walk). In-band roster rotation from
  the committed `keys.toml` is deferred with this step; the indexer verifies
  against the registry's pinned trust anchors only.

## Build

```sh
# Compile check (no account needed — this is what CI runs):
cargo build -p aos-hub-worker --target wasm32-unknown-unknown

# Native unit tests for the pure modules (sql, keymap, render, model):
cargo test -p aos-hub-worker
```

The crate is a workspace member, but only its pure modules
(`sql`, `keymap`, `render`, `model`) build for the native target; the Worker
glue (`d1`, `facade`, `handlers`, `indexer`, the event handlers) is gated behind
`#[cfg(target_arch = "wasm32")]`, exactly like the sibling `aos-registry-spa`
crate, so `cargo build --workspace` on native skips the Worker code and is never
broken by this crate.

## Deploy (requires a Cloudflare account)

The native `aos-hub` binary is also the **installer** — see
[`deploy/DEPLOY.md`](deploy/DEPLOY.md) for the full walkthrough. The short
version, using the `aos-hub-cloudflare` Nix package (which bundles
`wrangler` + `node` + the prebuilt Worker wasm):

```sh
HUB=$(nix-build -A pkgs.aos-hub-cloudflare --no-out-link)/bin/aos-hub
export CLOUDFLARE_API_TOKEN=…                # or `wrangler login`
# 1. Provider: provision D1/R2/KV, deploy the wasm, set secrets.
"$HUB" worker deploy --provider cloudflare --external-url https://reg.example.com
# 2. Database: migrate + bootstrap root over D1 (no public init endpoint).
"$HUB" init --target d1:aos-hub \
  --root-email ops@example.com --root-password-stdin <<<"$ROOT_PASSWORD"
```

`worker deploy` provisions D1/R2/KV, deploys the bundled wasm, and sets the
runtime secrets (`HUB_JWT_SECRET`/`HUB_SEAL_KEY` minted if omitted). `init
--target d1:<name>` then migrates the schema and bootstraps root over D1 via the
bundled `wrangler d1 execute` — the same `Database` code the native hub runs. A
one-shot `worker install` composes both. Reset the root password with
`reset-root --target d1:…`; `deploy/cf-seed.sh` seeds a registry + its signed R2
surface, which the `*/15` Cron then indexes into `releases`/`channels`.

The schema is applied by the operator's CLI over D1, never an HTTP endpoint —
`aos-hub schema dump` prints the canonical `MIGRATIONS` (the single
source of truth). A manual `wrangler deploy` path (without the installer) is in
`deploy/DEPLOY.md`.

## Validation gap (be explicit)

**This Worker cannot be validated in this environment.** What *is* verified here:

- `cargo build -p aos-hub-worker --target wasm32-unknown-unknown` compiles
  the full crate (facade, D1 layer, handlers, indexer, event handlers) — the
  `worker` 0.4 dependency tree resolves and builds for wasm32.
- The native unit tests run the D1 schema and read queries through a real sqlite
  engine (D1 *is* sqlite), and exercise the R2 key mapping, facade
  classification, and HTML rendering.

What **cannot** be exercised without a Cloudflare account and the Workers
runtime: the live D1/R2/KV bindings, the Cron trigger firing the `scheduled`
handler, `wrangler dev` / miniflare, and `wrangler deploy`. There is no
`wrangler` or miniflare runtime in this sandbox, so the end-to-end request and
indexing behavior is validated only by the pure-logic unit tests plus the
wasm32 compile, not by running the isolate.
