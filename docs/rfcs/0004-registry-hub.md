# RFC-0004: `aos-registry-hub` — a multi-tenant registry management WebUI

- **Status:** Proposed
- **Date:** 2026-06-12
- **PR:** _(pending)_
- **Audience:** anyone working on `crates/aos-package/` (the `apr`/`apm`
  registry surface), `crates/aos-server/`, `crates/aos-proto/`, or the
  registry docs under `docs/registry/`.

## Problem

An AOS registry is a SHA-256 git repository served as static files over
dumb-HTTP from an S3/R2 bucket behind a CDN
(`docs/registry/architecture.md`). The committed tree carries
`registry.toml`, `packages/<x>/<name>.toml`, `closures/`, and the
signing roster `keys.toml`; beside the git surface live release packs
and thin deltas (`releases/<M>/<m>/<P>/pack/`), 256-partition channel
pointers (`channels/<name>/00..ff`, each a signed tag object), and a
standard Nix binary cache (`nix-cache-info`, `*.narinfo`,
`nar/*.nar.zst`). Trust is entirely client-side: SSH-format Ed25519
signatures on tags and commits, in-band roster rotation, anti-rollback
floors, and staleness windows
(`crates/aos-package/src/registry/verify.rs`,
`docs/registry/signing-and-trust.md`).

This design deliberately requires no server to consume — and today it
offers no server to *manage*, either. Every interaction with a registry
goes through the CLIs:

- **Producers** (registry maintainers) drive the whole publish pipeline
  with `apr`: `publish`, `tag`, `channel advance`, `keys
  add`/`retire`, `cache generate`, `origin upload`, or the `apr
  release` orchestrator (`crates/aos-package/src/registry_ops.rs`).
- **Consumers** (AOS host operators) configure and sync with `apm`:
  `registries.d/<name>.toml`, `apm update`, `apm install`/`upgrade`
  (`crates/aos-package/src/types.rs`).

What is missing:

- **No human-readable view of a registry.** A consumer deciding whether
  to trust `https://cdn.aos.andyl.org/` sees raw object-store listings
  at best. Debian's plain APT directory indexes set a *floor* here; we
  currently sit below it — there is no way to browse packages,
  versions, channels, rollout state, or trust anchors without cloning
  the repo.
- **No multi-tenancy or identity anywhere.** The registry model has a
  single key roster per registry and no notion of organizations,
  projects, users, roles, or per-registry access control. Multiple
  maintainers share a roster; multiple teams must run disjoint
  registries with hand-managed credentials.
- **No managed write path.** Producers need direct S3 credentials (or
  an `aos-server` provisioning token) plus local signing keys; there is
  no way to grant a teammate "may publish to this registry" without
  handing over bucket access.
- **No operational visibility.** Channel rollout state (which of the
  256 partitions point where), freshness of the frontier, signature
  health, and pack/delta availability are observable only by running
  `apr channel status` against a local clone.

Meanwhile the building blocks for a server-side surface already exist:
`aos-server` speaks ConnectRPC (`aos.{cache,build,gc,auth}.v1` in
`crates/aos-proto/`), has a proven two-tier token model (long-lived
hashed provisioning tokens exchanged at `/oauth2/token` for short-lived
JWTs — `crates/aos-server/src/tokens.rs`, `auth.rs`), and
`aos-cache`'s HTTP backend already knows how to authenticate and batch
uploads against that surface (`crates/aos-cache/src/backend/http.rs`).

## Goal

Ship an open-source registry management WebUI as a new crate,
**`aos-registry-hub`** ("the hub"), that:

1. is written in Rust targeting WASM, runs on Cloudflare Workers
   (D1 + R2) and as a native binary (axum) for self-hosting — operators
   or users of AOS can run their own instance easily;
2. exposes the full registry feature set to both audiences — anonymous
   consumers get a verified, rich, no-JS-required browse surface (the
   Debian directory listing, done right); authenticated producers get
   publish, channel rollout, key roster, and token management;
3. is **multi-tenant** (organizations), **multi-project** (hierarchical
   teams), **multi-user** (full IAM), and **multi-registry**;
4. speaks buf-compliant protobuf over ConnectRPC, sharing one schema
   between browser, CLIs, and third parties;
5. remains **backwards-compatible as a plain Nix binary cache** and as
   a dumb-HTTP git origin — every registry URL the hub serves is
   simultaneously a substituter URL and an `apm` origin;
6. uses sqlite as the primary database, with postgres and mysql also
   supported;
7. integrates with `aos`/`apr`/`apm` "like magic": existing CLI
   pipelines work against the hub unchanged, and the hub never asks a
   human to do something the CLI already automates.

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
only orgs/users/tokens/audit live solely in SQL. This keeps the
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
- **Cloudflare target** — `wasm32-unknown-unknown` via `workers-rs`.
  D1 is the sqlite backend (same dialect, different driver); R2 via
  native bindings gives a zero-egress facade, which is why R2 is the
  flagship deployment; Cron Triggers/Queues drive the indexer; KV holds
  sessions.
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
  fixture surfaces.

### Tenancy and IAM

```text
Organization   (tenant boundary; SSO/audit scope)
 └─ Project    (hierarchical, arbitrary depth — teams, environments)
     └─ Registry   (one git surface + one cache surface, backed by an
                    object-store prefix: s3://bucket/{org}/{proj…}/{reg}/)
```

- **Principals**: users (humans; passkey + email auth, per-org OIDC SSO
  later), service accounts, and tokens.
- **Roles**, grantable at org, project, or registry scope and inherited
  downward:

  | Role | Grants |
  | --- | --- |
  | `owner` | everything incl. delete and IAM |
  | `admin` | members, tokens, registries, hosted keys |
  | `maintainer` | publish, tag, advance channels, manage rosters |
  | `developer` | read private registries, self-service tokens |
  | `viewer` | read-only |

- **Visibility** per registry: `public` (anonymous read — the Debian
  case), `internal` (any org member), `private` (explicit grants).
- Every mutating action lands in an append-only `audit_log` carrying
  the actor, scope, and — where applicable — the resulting git
  commit/tag hash, so the audit log cross-references the cryptographic
  history rather than replacing it.

The registry's own trust model is unchanged and remains beneath the
hub: signatures verify against the roster regardless of what the hub's
IAM says. Hub IAM controls *who may use the hub's write paths*; the
roster controls *what consumers accept*.

### API: `aos.registry.v1` over ConnectRPC

Buf-compliant protos in `crates/aos-proto`, served via Connect
(JSON + binary, HTTP/1.1 and h2) so the browser, the CLIs, and
third-party tooling share one schema:

| Service | Responsibility |
| --- | --- |
| `OrgService` | orgs, membership, invitations |
| `ProjectService` | project tree CRUD, role grants |
| `RegistryService` | create/import/configure registries, visibility, trust-anchor display, freshness/health |
| `PackageService` | search, package/version/platform metadata, closures, narinfo lookups, reverse-deps |
| `ChannelService` | channel list, 256-partition state, advance/init, floor history |
| `PublishService` | the write path: stage release, mint upload credentials, finalize, status stream (mirrors `apr release` phases) |
| `KeyService` | roster mirror, hosted-key operations, rotation workflows |
| `TokenService` | provisioning-token CRUD — same semantics as `aos token` |
| `AuditService` | audit log queries |
| `GitService` | log/diff/branch/refs read API for the UI and remote `apr` |

Auth reuses the proven `aos-server` two-tier pattern
(`crates/aos-server/src/auth.rs`): provisioning tokens — now scoped to
`{org}/{project}/{registry}` rather than views, hashed at rest, same
`aos_` prefix family — exchanged at `/oauth2/token` for short-lived
JWTs. Humans get cookie sessions; CLIs get the OAuth device-code flow
(RFC 8628): `apr login https://hub.example.com` prints a code, the user
approves in the browser, and the token lands in
`[registry.upload_auth]`.

### URL design — one URL, three audiences

```text
https://hub.example.com/
  {org}/                          org page
  {org}/{project…}/               project pages (nested)
  {org}/{project…}/{registry}/    ← THE registry URL
```

The registry URL is simultaneously:

1. **HTML** for browsers (negotiated on `Accept` / known machine
   paths): the registry home — packages, channels, trust keys,
   freshness, copy-paste setup snippets.
2. **A git dumb-HTTP origin**: `…/{registry}/info/refs`, `/HEAD`,
   `/objects/…`, `/channels/…`, `/releases/…` — served by 302-redirect
   (native) or zero-egress R2 proxy (Workers), preserving the
   immutable/60-second cache-header split the upload pipeline already
   defines (`crates/aos-package/src/registry/static_upload.rs`). So
   `url = "https://hub.example.com/acme/infra/prod/"` in
   `registries.d/<name>.toml` just works — signature verification,
   channel resolution, delta fetch, all of it.
3. **A Nix binary cache**: `…/{registry}/nix-cache-info`,
   `/{hash}.narinfo`, `/nar/…` — same facade. Any Nix installation can
   point a substituter at it. The backwards-compatibility requirement
   is satisfied structurally, not as a feature.

Private registries enforce bearer-token auth on the machine paths —
which `apm` and `aos-cache` already know how to send.

### CLI convergence — the "like magic" contract

The magic is protocol reuse, not new glue:

- **`apr origin upload` and `apr cache generate --upload-url` work
  against the hub unchanged.** The hub implements the existing AOS-mode
  upload surface (`/oauth2/token`, `/query-missing`,
  `PUT /store/{hash}`, `/upload-pack` — the endpoints in
  `crates/aos-server/src/routes.rs` that
  `crates/aos-cache/src/backend/http.rs` already targets), scoped per
  registry. A maintainer's existing
  `apr release --upload-url https://hub.example.com/acme/infra/prod
  --token aos_…` pipeline needs zero new flags.
- **Publish-completion hook**: when the mutable pointers land
  (`info/refs`, `channels/**`, `nix-cache-info`), the hub indexes the
  new state inline — no S3-event plumbing in the managed path. For
  registries uploaded out-of-band (direct to R2), a scheduled indexer
  re-walks the surface exactly as an `apm` client would.
- **`apr create --remote https://hub.example.com/acme/infra/prod`**
  provisions the registry via `RegistryService` and writes local
  `registries.d` config plus upload auth in one step.
- **Setup snippets everywhere**: every registry page shows the exact
  `apr add` command, the `aos.apm.registries.<name>` module stanza with
  trust keys filled in (`modules/base/apm-registries.nix`), and the
  plain-Nix `substituters` + `trusted-public-keys` lines.
- **Signing stays client-side by default.** Maintainers' Ed25519 keys
  sign locally; the hub orchestrates but is not in the TCB. Optionally,
  an org enrolls a **hosted signing key** (encrypted at rest, every use
  audited) so the hub itself can advance channels and re-sign tags —
  required for the channel-rollout console to be more than a
  record-keeper. Both modes are explicit in the UI ("signed by alice@
  locally" vs "signed by hosted key acme-release").

### UI surface map

**Consumer-facing** (anonymous, server-rendered, works with JS
disabled — the Debian ethos):

- Registry home: name, description, trust anchors with fingerprints,
  channels and their current versions, freshness ("frontier observed
  4m ago"), setup snippets.
- Package index and search; package page: versions × platforms table,
  NAR/closure sizes, store paths, license/homepage/maintainer,
  dependency closure browser, sysroot image downloads (qcow2/raw),
  narinfo permalinks.
- Channel page: the **256-partition grid** — which buckets point at
  which release, rollout percentage, floor history, staleness; a
  "which version will *my* host get?" calculator (paste your bucket
  from `[registry.state]`).
- Releases page: signed tags, signature status, pack/thin-delta
  availability, commit history.
- Raw directory-listing fallback for every machine path (literal
  Debian-style autoindex over the object store).

**Producer-facing** (authenticated):

- Org/project dashboards: registries, members, roles, tokens, audit
  feed.
- Publish pipeline view: live phase status for in-flight releases,
  mirroring `apr release` phases (commit → tag → packs →
  upload-immutable → flip-pointers), resumable/idempotent like
  `--resume`.
- Channel rollout console: advance N partitions with preview ("this
  moves `stable` from 12% → 50% on 1.4.2"), hold/roll-forward, floor
  guard warnings.
- Key roster management: active/revoked keys, a rotation wizard
  mirroring `apr keys add` → overlap → `apr keys retire --vouched-by`,
  hosted-key enrollment.
- Token management: create/scope/rotate/revoke, last-used — exactly
  mirroring `aos token` semantics.
- Git view: branches, commit log, TOML diffs ("what changed in curl
  between 8.4 and 8.5"); later, **change requests** — propose package
  changes on a branch, review the diff, merge with a signed commit.
  The registry's git-native design makes this nearly free and gives
  teams a dev flow without leaving the hub.

### Database schema (sketch)

System-of-record tables: `orgs`, `projects` (materialized-path
hierarchy — portable across all three dialects), `users`,
`service_accounts`, `memberships(principal, scope, role)`,
`tokens(id, hash, scope, permissions, expires_at, revoked_at,
last_used_at)`, `sessions`, `invitations`, `hosted_keys` (encrypted),
`audit_log`, `webhooks`.

Rebuildable index tables (derived from the surface, droppable and
re-indexable at any time): `registries` (with `last_indexed_commit`,
frontier, health), `packages`, `package_versions`, `version_platforms`,
`channels`, `channel_partitions(channel, bucket, release, sig_key_id)`,
`releases(semver, tag_hash, signer, pack_presence)`, `key_rosters`,
plus the per-dialect full-text index.

### Sequencing

1. **Read-only hub** (highest value, lowest risk): `surface/` reader +
   indexer, public browse UI, nix-cache/dumb-HTTP facade. Deploy on
   Cloudflare against the existing `cdn.aos.andyl.org` bucket. No auth,
   no DB writes beyond the index. This alone replaces "Debian directory
   listing" with something dramatically better and proves the
   WASM/D1/R2 stack end to end.
2. **Tenancy + tokens + upload facade**: orgs/projects/IAM, device-flow
   login, the AOS-mode upload endpoints so `apr release` targets the
   hub; private registries.
3. **Producer console**: publish pipeline view, channel console, key
   rotation wizard, audit.
4. **Hosted keys, change requests, webhooks/notifications**;
   postgres/mysql drivers hardened; AOS package + module for
   self-hosting.

## Alternatives considered

- **Extend `aos-server` instead of a new crate.** `aos-server` is a
  build + ephemeral-cache server (views, TTLs, `nix-store --realise`)
  with a tokio/axum/process-spawning core that cannot target Workers.
  The hub's job — tenancy, indexing, static-surface facade — is
  disjoint; what they share (token model, upload endpoints, protos) is
  shared through `aos-proto` and protocol compatibility, not code
  colocation.
- **A JS/TS frontend with a Rust API.** Rejected by requirement (the
  WebUI is Rust→WASM) and by preference: one language across
  `surface/`, `domain/`, and `ui/` lets the browser reuse the exact
  verification and parsing code the server uses, and Leptos SSR gives
  the no-JS baseline a JS framework cannot.
- **The hub as the registry's source of truth** (database-first, à la
  crates.io). Rejected: it would break the property that consumption
  needs no server, put the hub in the trust path, and turn the SQL
  database into a single point of failure. The git surface already *is*
  a database with signatures; the hub indexes it.
- **An ORM / sea-orm for the three-dialect story.** Rejected: the
  schema is small, the D1 driver would still need hand-writing, and
  dialect divergence is better handled by keeping the SQL in sight.
- **gRPC-web or REST-only instead of ConnectRPC.** The repo already
  standardized on ConnectRPC (`aos-proto`, `aos-remote`); Connect's
  JSON mapping doubles as the pragmatic REST surface for third parties.

## Open questions

1. **Hosted signing keys in v1?** Without them the channel console is
   read-only (the CLI does the signing); with them the hub enters the
   TCB. Current position: ship BYO-key first; hosted keys are an
   explicit org-level opt-in in phase 4, encrypted at rest, every use
   audited.
2. **How much of `aos-package`'s registry code is wasm-clean today?**
   `types.rs` and `registry/parse.rs` look pure; `registry/git.rs`
   shells out to git. The factoring (direct reuse vs a shared no-IO
   module) needs a spike before phase 1.
3. **Leptos vs Dioxus.** Leptos is the working assumption for its
   SSR-first story (the no-JS Debian ethos); Dioxus is the fallback if
   Leptos-on-Workers friction is worse than expected. Decide during the
   phase-1 spike.
4. **Range requests through the Workers facade.** `aos-server`
   materializes compressed NARs in memory for range requests; a Worker
   cannot. R2 supports native ranged GETs, so the facade should always
   redirect/proxy ranges to R2 rather than reimplementing slicing —
   verify this covers `apm`'s delta-fetch access patterns.
5. **Identity for v1 humans.** Passkeys + email magic links are the
   working assumption; per-org OIDC SSO is deferred. Does the first
   real deployment (Andyl) need SSO sooner?
6. **"Full IPAM."** This RFC reads the requirement as full **IAM**
   (identity and access management). If IP/host management for fleet
   operators (host inventory, per-host partition buckets) is also
   intended, that is a separate consumer-side design.
