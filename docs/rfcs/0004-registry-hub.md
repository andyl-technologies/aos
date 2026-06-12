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
  health, pack/delta availability, and **binary-cache completeness**
  (does every published package actually resolve in every advertised
  cache?) are observable only by running `apr channel status` /
  `apr validate` against a local clone.

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
   publish, channel rollout, key roster, token, and configuration
   management;
3. is **multi-tenant** (organizations), **multi-project** (hierarchical
   teams), **multi-user** (full IAM), and **multi-registry** — with
   first-class models for storage buckets, CDN frontends, cache
   mirrors/stacks, and registry mirroring;
4. speaks buf-compliant protobuf over ConnectRPC, sharing one schema
   between browser, CLIs, and third parties;
5. remains **backwards-compatible as a plain Nix binary cache** and as
   a dumb-HTTP git origin — every registry URL the hub serves is
   simultaneously a substituter URL and an `apm` origin;
6. uses sqlite as the primary database, with postgres and mysql also
   supported;
7. integrates with `aos`/`apr`/`apm` "like magic": existing CLI
   pipelines work against the hub unchanged, and the hub never asks a
   human to do something the CLI already automates;
8. is **polished and self-contained**: every byte of every page —
   fonts, JS, CSS, WASM — is served from the page's own origin. No
   third-party font/script/style CDNs, no analytics beacons, ever.

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

### Tenancy and IAM

```text
Organization   (tenant boundary; SSO/audit scope)
 └─ Project    (hierarchical, arbitrary depth — teams, environments)
     └─ Registry   (one git surface + one cache surface, backed by a
                    StorageBinding + prefix — see "Storage")
```

- **Principals**: users (humans), service accounts, and tokens.
- **Roles**, grantable at org, project, or registry scope and inherited
  downward, expanding to permission verbs (`read`, `publish`,
  `channel.advance`, `keys.manage`, `tokens.self`, `tokens.manage`,
  `members.manage`, `registry.configure`, `audit.read`, `iam.admin`):

  | Role | Grants |
  | --- | --- |
  | `owner` | everything incl. delete, ownership transfer, IAM |
  | `admin` | members, tokens, registries, frontends, hosted keys |
  | `maintainer` | publish, tag, advance channels, manage rosters |
  | `developer` | read private registries, self-service tokens |
  | `viewer` | read-only |

- **Visibility** per registry: `public` (anonymous read — the Debian
  case), `internal` (any org member), `private` (explicit grants).
- Every mutating action lands in an append-only `audit_log` carrying
  the actor, scope, a `change_id` (see "Configuration management"),
  and — where applicable — the resulting git commit/tag hash, so the
  audit log cross-references the cryptographic history rather than
  replacing it.

The registry's own trust model is unchanged and remains beneath the
hub: signatures verify against the roster regardless of what the hub's
IAM says. Hub IAM controls *who may use the hub's write paths*; the
roster controls *what consumers accept*.

### Authentication: sessions, tokens, SSO

Two principal planes that never cross:

- **Humans** get cookie sessions (`__Host-aos_session`, opaque 256-bit
  random, `Secure; HttpOnly; SameSite=Lax`; only the SHA-256 of the
  session id is stored — the same high-entropy-secret rationale as
  `aos-server`'s token store). Native: a `sessions` table. Workers: KV
  with native TTL plus a D1 row for enumeration and "revoke all
  sessions"; KV is eventually consistent, so revocation tombstones D1
  and destructive operations re-check it. Sessions carry an
  `auth_level` enabling **sudo mode**: destructive operations require
  re-authentication within the last 10 minutes. Human authorization is
  computed from `memberships` per request — role changes take effect
  immediately, no static scopes.
- **Machines** keep the existing `aos-server` pattern
  (`crates/aos-server/src/auth.rs`, `tokens.rs`): `aos_`-prefixed
  provisioning tokens, hashed at rest, exchanged at `/oauth2/token` for
  short-TTL JWTs — with scope generalized from `views` to
  `{path_prefix, permissions[]}` (e.g. `acme/infra/prod` +
  `["read","publish"]`). One strengthening: **tokens are owned by a
  principal, and effective permissions = token grants ∩ the owner's
  *current* grants** — removing a member instantly deadens every token
  they minted; no revocation sweep needed. Cookies are never accepted
  on machine paths; bearer tokens never establish a human session. The
  rotation-grace bug noted in `tokens.rs`'s own docs (grace window
  recorded but not honored) is fixed in the hub's implementation.

**Human auth methods** (verified against both runtimes):

- **Email magic links** — v1 baseline and the recovery path. SMTP via
  `lettre` natively; an HTTP mail API behind a `Mailer` trait on
  Workers (no raw TCP).
- **Passkeys/WebAuthn** — v1. `webauthn-rs` cannot ship on the Workers
  target today (OpenSSL backend; server-side WASM is an open upstream
  issue), so the plan is a small in-house RP verifier with a hard
  `attestation: "none"` policy — which deletes the hard 80% of WebAuthn
  (the attestation-format zoo) and leaves clientDataJSON checks,
  authenticatorData parsing, COSE key decode, and ES256/Ed25519/RS256
  signature verification on already-wasm-proven RustCrypto crates.
  `webauthn-rs` remains the native-only fallback if the spike fails.
- **Passwords — never.** No credential-stuffing surface, no
  memory-hard-KDF-vs-Workers-CPU-budget problem, no reset flows beyond
  the magic link that must exist anyway.
- **Per-org OIDC SSO** — phase 3. The `openidconnect` crate is
  wasm-clean by construction (pure-RustCrypto JWS verification,
  pluggable `AsyncHttpClient` — implemented over `worker::Fetch` on
  Workers and `aos-net`/hyper natively). Authorization-code + PKCE
  always; per-org IdP config with encrypted client secrets;
  **domain capture** (email-first login: `user@acme.com` routes to
  acme's IdP when `acme.com` is DNS-TXT-verified, forced if the org
  sets `enforce_sso`); JIT provisioning keyed on `(iss, sub)` — never
  bare email — with auto-linking only for IdP-verified emails on
  captured domains; `groups_claim` → role mapping re-evaluated on every
  SSO login. SCIM deprovisioning is explicitly later; `enforce_sso`
  orgs mitigate with short absolute session lifetimes.
- **SAML — permanently out of scope.** No credible Rust/wasm story;
  orgs bridge through an OIDC-capable IdP or proxy (Dex, Okta/Entra
  OIDC apps).

**CLI login** is the OAuth device-code flow (RFC 8628):
`apr login https://hub.example.com` → anonymous, rate-limited
`POST /oauth2/device_authorization` → the user approves at
`/activate` in any authenticated session → the approval mints a
provisioning token **owned by the approving user**, scope clamped to
≤ that user's grants, delivered through the standard polling exchange
and written to `[registry.upload_auth]`.

**CSRF** for Connect-JSON endpoints, layered: cookie-authenticated
Connect calls require the `Connect-Protocol-Version` header (forms
can't send it; cross-origin XHR with it triggers a preflight rejected
by strict same-origin CORS), plus `Origin`/`Sec-Fetch-Site` validation;
the no-JS SSR form pages carry a per-session synchronizer token; bearer
requests need no CSRF defense (no ambient credential).

### Access matrix

Anonymous vs authenticated follows **registry visibility, not page
type** — on a `public` registry every read-only surface is anonymous,
including machine paths:

| Surface | `public` | `internal` | `private` |
| --- | --- | --- | --- |
| Browse pages (home, packages, channels, releases, git log/diff), raw autoindex | anonymous | org member (viewer+) | explicit grant |
| Machine paths: nix-cache + dumb-HTTP git | anonymous | bearer token with `read` at scope | same |
| Cross-registry search | public results only | + internal for members | + grants |

Always authenticated: org/project dashboards and member lists
(viewer+), audit feed (admin+), publish console and upload-credential
minting (maintainer+), channel advance (maintainer+), roster mutations
(maintainer+; the roster itself is *readable* per visibility — it is
public data on a public registry), hosted-key enrollment (admin+),
own-token management (developer+), others' tokens (admin+),
registry/frontend/storage configuration (admin+ at parent), org
delete/ownership transfer (owner; last-owner removal is hard-blocked).
ConnectRPC services map method-by-method onto the same matrix.

### API: `aos.registry.v1` over ConnectRPC

Buf-compliant protos in `crates/aos-proto`, served via Connect
(JSON + binary, HTTP/1.1 and h2) so the browser, the CLIs, and
third-party tooling share one schema:

| Service | Responsibility |
| --- | --- |
| `OrgService` | orgs, membership, invitations |
| `ProjectService` | project tree CRUD, role grants |
| `RegistryService` | create/import/configure registries, visibility, trust-anchor display, freshness/health, mirror sources |
| `StorageService` | storage bindings, bucket provisioning, frontend domains |
| `PackageService` | search, package/version/platform metadata, closures, narinfo lookups, reverse-deps |
| `ChannelService` | channel list, 256-partition state, advance/init, floor history |
| `PublishService` | the write path: stage release, mint upload credentials (`MintUploadCredentials`), finalize, status stream |
| `ValidationService` | consistency-validation runs, per-cache coverage reports, repair jobs |
| `KeyService` | roster mirror, hosted-key operations, rotation workflows |
| `TokenService` | provisioning-token CRUD — same semantics as `aos token` |
| `AuditService` | audit log queries |
| `GitService` | log/diff/branch/refs read API for the UI and remote `apr` |
| `ConfigService` | change-sets: draft, review-diff, apply, revert |

### Storage: `StorageBinding` and shared buckets

A registry never owns a bucket directly; it references a
**StorageBinding** plus a sub-prefix:

```text
StorageBinding {
  id, org_id,
  kind:        HubManagedR2 | ExternalS3 | ExternalR2 | LocalFs,
  endpoint, region, bucket, root_prefix,
  credentials: CredentialRef { purpose: write | admin | mint },
  worker_binding: Option<String>,   # static R2 binding name when this
                                    # is a hub-owned bucket (Workers)
  capabilities: { mint_scoped_creds, conditional_put,
                  public_base_url: Option<Url> },
  health
}
Registry { …, storage_binding_id, prefix: "{org}/{proj…}/{reg}/" }
```

Credential purposes are kept distinct because their blast radii
differ: `write` lets the hub's upload facade write under the binding;
`admin` is bucket lifecycle (create, custom domains, CORS) and exists
only on hub-managed bindings; `mint` is a parent credential for
deriving short-lived prefix-scoped credentials for direct producer
upload.

**Provisioning modes:**

1. **Hub-managed (default; R2 flagship).** A Workers-hosted hub *can*
   create R2 buckets — the Cloudflare REST API is plain HTTPS, callable
   from a Worker with an account-scoped API token held as a Worker
   secret. However, Workers **R2 bindings are static at deploy time**,
   so the default shape is *one (or a few) hub-owned shared buckets
   bound at deploy time, with registries as prefixes* — keeping the
   zero-egress fast path. Dedicated bucket-per-registry is an opt-in
   (large tenants, clean export/exit), accessed via R2's S3-compatible
   endpoint with SigV4 (the same `aos-net` engine; SigV4-over-fetch on
   Workers) — latency cost only, R2 has no egress fees.
2. **BYO bucket**, in three tiers by what the operator hands over:
   `write` credentials (hub hosts the upload facade and pointer
   flips), `mint` (hub brokers direct uploads), or **nothing** —
   registration-only: the hub indexes the registry through its public
   URL exactly like an `apm` client. Registration-only is phase 1's
   mode for `cdn.aos.andyl.org`.
3. **BYO prefix** on a hub bucket — mode 1 with a tenant-supplied
   prefix.

**Shared buckets work cleanly** because everything that matters is
per-object: `Cache-Control`/`Content-Type` are set per uploaded file
(`crates/aos-package/src/registry/static_upload.rs`), and consumption
is pure GETs — `apm`, stock git, and Nix never call a listing API.
Credential scoping per prefix: STS session policies on AWS S3; on R2,
**permanent API tokens are bucket-scoped only, but the temporary-
credentials API mints short-lived SigV4 credentials scoped to bucket +
prefixes** — exactly the `mint` purpose. Default write path on shared
buckets is the hub facade (the producer's token is hub-scoped; the hub
enforces the prefix structurally on any backend); direct-to-bucket
scoped credentials are an optimization via
`PublishService.MintUploadCredentials`. Bucket-wide permanent keys are
never handed out for shared buckets. One constraint surfaced as a
`Frontend` validation rule rather than a footgun: a *direct* custom
domain serving a shared-bucket prefix at its domain root needs an
origin-path rewrite (native on CloudFront; a one-line rule in front of
R2).

### Frontends: direct and proxied domains

A **Frontend** is a domain serving some subset of a registry's
surfaces, in a mode — **mode is a property of the frontend, not the
registry**, and a registry can have many frontends:

```text
Frontend {
  id, registry_id, domain, base_path,
  mode:     Direct | Proxied,
  surfaces: { git, cache, web },
  direct:   { cdn_kind: R2CustomDomain | CloudFront | GenericCdn
              | PlainS3, origin_path },
  proxied:  { visibility_enforced, render_html },
  consumer_priority,                  # → [[caches]] priority
  advertised: { in_caches, primary_origin },   # exactly one primary
  health: { last_probe_at, status, observed_frontier, lag_releases }
}
```

`Direct` = hub not in the serving path (CNAME → R2 custom domain,
CloudFront → S3); the hub only probes it. `Proxied` = the hub's facade
(redirect, or zero-egress R2 proxy on Workers) — which is what enables
bearer-token enforcement on private registries and HTML at the same
URL. A typical registry: proxied
`hub.example.com/acme/infra/prod` (primary origin + HTML) plus direct
`cdn.acme.com` (high-priority cache mirror) plus a low-priority S3
backup.

**Mapping to consumer configuration requires zero schema change for
the cache surface**: the committed `registry.toml` already carries
`[[caches]]` entries with `url` + `priority`, and the client merges
them with client-side entries and sorts by priority descending
(`crates/aos-package/src/registry_ops.rs:916-924`,
`types.rs:1247-1259`). Each frontend with
`surfaces.cache && advertised.in_caches` becomes one `[[caches]]` row.
Because `registry.toml` is signed tree content, the hub cannot silently
edit the mirror list — updating it is a normal signed publish
(maintainer-signed change request, or hosted key). That is correct and
desirable: *the mirror list is part of what consumers verify*. When a
probe finds a mirror stale or dead, the hub alerts and offers a
one-click "demote mirror" change request.

The **git origin** is the one genuinely singular thing today
(`RegistryConfig.url` is a single string, `types.rs:638-639`). A stale
git origin is *safe* by construction (signed tags + anti-rollback floor
→ old-but-valid state); it is an availability gap only. Deferred
follow-ons: a client-side `urls = [..]` ordered fallback list in
`registries.d`, and later a committed `[[origins]]` table mirroring the
`[[caches]]` shape.

**Mirror replication and ordering.** `apr origin upload` already
accepts multiple `--upload-url` destinations with independent
per-destination failure — but the current loop is *destination-major*
(one mirror receives everything including mutable pointers before the
next starts), so cross-mirror pointer/payload skew is possible. A
small `apr` change is specified regardless of the hub: restructure to
**phase-major** order — all `Immutable` files to *all* destinations,
then all `Mutable` pointers to all destinations; a mirror that fails
phase 1 skips phase 2 and stays stale-but-consistent. New invariant:
*any pointer visible on any mirror only references objects present on
every mirror that completed phase 1.* The hub's `MirrorJob` (replicate
primary → secondary bindings server-side, immutable-first, idempotent
because content-addressed) follows the same rule, and per-frontend
`MirrorProbe` jobs record observed frontier + lag, rendered as a
freshness table on the registry page.

### Cache stores, stacks, and consistency validation

**Shared NAR storage (no duplication).** Verified against the code:
narinfo and NAR files contain nothing registry-specific — no registry
id, content-hash-named files, signatures over content
(`crates/aos-core/src/nar/info.rs`) — so multiple registries pointing
`[[caches]]` at the same cache URL is already fully supported with
natural deduplication. The hub models this as a shareable
**CacheStore** (a binding + prefix that several registries advertise):
an org with twenty team registries stores each NAR once. No
`registry.toml` change required.

**Cache stacks.** Today the `[[caches]]` list is a *preference* list,
not a failover chain: `apm` resolves the highest-priority cache and
uses only it (`crates/aos-package/src/download.rs:147-156` takes
`mirrors.first()`). The stack model generalizes this into a small,
nestable expression:

```text
StackNode =
  | endpoint(url)            # one cache endpoint
  | try [node, node, …]      # ordered fall-through: hit each member
                             # top-to-bottom, first hit wins
                             # (availability = UNION of members)
  | mirror [node, node, …]   # declared replicas: every member is
                             # expected to hold the full set
                             # (validation invariant: INTERSECTION
                             # must equal union; client may use any
                             # member — first, or latency-based)
```

`try` is the user-visible "stack": top-to-bottom fall-through, union
semantics. `mirror` is a replication contract: it doesn't change what
a client may fetch, it changes what the validator *enforces* (every
member individually complete) and what the hub's replication jobs
maintain. Nodes nest — e.g. `try [ mirror [r2-eu, r2-us],
upstream-cdn, s3-backup ]` — internal fast replicas first, falling
through to the upstream public cache, then cold backup.

Encoding, in two backwards-compatible layers:

1. **Flattened `[[caches]]`** — every stack flattens to today's
   priority list (depth-first order → descending priorities), so
   existing clients keep working with no schema change. The parser
   ignores unknown fields (`RegistryRootConfig` has no
   `deny_unknown_fields`), making layer 2 additive-safe.
2. **A committed `[cache_stack]` expression** in `registry.toml` for
   stack-aware clients, carrying the full nested structure.

Required `apm` enhancement (small, and valuable independent of stacks):
**miss-fallthrough** — on narinfo/NAR 404 from the selected cache, fall
to the next entry instead of failing. Phase one of the stack feature is
exactly this (making the flattened list behave as a `try` stack);
nested semantics ride on the `[cache_stack]` expression afterward.

**Consistency validation.** The hub continuously proves that *every
package the registry lists actually resolves in the caches it
advertises* — the server-side, always-on generalization of
`apr validate`:

- **What is checked**: for each package version × platform in the
  verified index, the full closure set (store path + transitive
  references, walked via `closures/` and narinfo `References`) against
  each advertised cache endpoint.
- **Depths**: `presence` (HEAD each `.narinfo`), `integrity` (HEAD the
  NAR; `FileSize`/`Compression` consistency), `deep` (sampled download
  + `FileHash` verification). Presence runs on every index refresh and
  after every managed publish; integrity on schedule; deep on a sampled
  rotation.
- **Coverage requirements derive from stack semantics**: for a `try`
  node, the *union* of members must cover the closure set (and the hub
  reports which member serves what fraction — a top member at 60%
  coverage means 40% of fetches fall through); for a `mirror` node,
  *each member individually* must cover it — any shortfall is a
  replication failure, with a one-click repair job that copies the
  missing objects from a member that has them (content-addressed, so
  always safe).
- **Surfacing**: a per-registry health page with a cache × coverage
  matrix, missing-path drill-down, and history; failures are
  first-class health states on the registry home (consumers deserve to
  see "mirror X is missing 3 NARs" before pointing a fleet at it).
- **Gating**: on hub-managed publishes, the pointer flip can optionally
  be gated on `presence` validation of required caches — a release is
  not announced until its closures are fetchable. (CLI `apr release`
  retains its own ordering guarantees; the gate is facade-side and
  opt-in.)

### Mirroring other registries

Headline property, worth stating prominently: **a mirror cannot alter
content without breaking verification.** Releases are signed tag
objects, partitions are signed name-bound tags, objects are sha256
content-addressed, narinfos are Ed25519-signed — a mirror is a byte
courier, not a trust party. The only attacks left are staleness/freeze
and withholding, both already bounded by the consumer's
`max_staleness_seconds` and monotonic anti-rollback floor.

Three named modes, to prevent concept confusion:

1. **Full mirror** — the "internal mirror of the public andyl
   registry" case. A registry of `kind: mirror` with a `MirrorSource
   { upstream_url, schedule, verify: true }`: a scheduled job fetches
   the upstream surface exactly as `apm` would (the same `surface/`
   reader), **verifies tags against the upstream roster before
   accepting anything**, writes byte-identical files into the local
   binding immutable-first, and refuses to flip local pointers on
   verification failure — a poisoned upstream never propagates.
   Consumers keep **upstream trust anchors**; only the URL in their
   `registries.d` changes. The UI labels it "mirror of
   https://cdn.aos.andyl.org — trust anchors are upstream's" and shows
   sync lag.
2. **Derived registry** — re-signed under the org's own roster;
   may subset, extend, or re-publish. Different commit hashes,
   different trust anchors — genuinely a different registry. This is a
   publish-pipeline feature (an eventual `apr import-from`), named here
   to keep it distinct, deferred past v1.
3. **Pull-through cache** — a *proxied* frontend that fetches from
   upstream on miss, verifies, persists to the local binding, and
   serves. Content-addressed payloads (objects, packs, NARs) are
   verified by hash and trivially safe to persist; pointers
   (`info/refs`, partition tags) are self-verifying but are persisted
   with upstream-equivalent low TTL and re-fetched on expiry — never
   frozen. The proxy falls through to upstream on any local miss, so
   ordering hazards don't exist: fall-through *is* the completeness
   guarantee. A natural fit for the Workers target with R2 as the
   persistent cache; the same logic runs over the local binding
   natively. (A pull-through frontend composes with cache stacks: it
   is an `endpoint` whose backing happens to be lazy.)

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
   freshness, setup snippets.
2. **A git dumb-HTTP origin**: `…/{registry}/info/refs`, `/HEAD`,
   `/objects/…`, `/channels/…`, `/releases/…` — served by 302-redirect
   (native) or zero-egress R2 proxy (Workers), preserving the
   immutable/60-second cache-header split the upload pipeline already
   defines. So `url = "https://hub.example.com/acme/infra/prod/"` in
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
  new state inline and triggers presence validation — no S3-event
  plumbing in the managed path. Out-of-band uploads (direct to R2) are
  picked up by the scheduled indexer re-walking the surface exactly as
  an `apm` client would.
- **`apr login https://hub.example.com`** — device-code flow, token
  lands in `[registry.upload_auth]`.
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
  audited) so the hub itself can advance channels, re-sign tags, and
  apply web-edited config directly. Both modes are explicit in the UI
  ("signed by alice@ locally" vs "signed by hosted key acme-release").

### Configuration management

Half the configuration is already a git repo, so the unifying model is:
**every change is a reviewed change-set with a stable `change_id`
(ULID), a renderable diff, and a revert path** — implemented per store:

**Git-backed config** (`registry.toml`, `keys.toml`, `packages/`): the
change *is* a commit, but consumers only trust roster-signed state, so
web edits have exactly two honest paths, mapping onto the hosted-key
stance above:

1. **Default (BYO-key orgs): web edits are change requests.** The hub
   commits the edit to `refs/hub/changes/<change_id>`, signed by a
   per-instance hub key that is *not* in the roster — consumption-
   invisible by construction, since clients follow only signed
   tags/partitions, never branches. Promotion happens when a maintainer
   reviews and signs locally: `apr change merge <change_id>` fetches
   the draft, shows the diff, signs with a roster key, pushes. The web
   UI is a full authoring/review surface; roster keys never leave
   maintainers' machines.
2. **Hosted-key orgs**: the hub applies and signs directly; every use
   audited.

Consequence: without hosted keys, web editing of registry config is
change-request-only — which is why a *minimal* change-request feature
(single-commit change, no threaded review) is promoted into phase 3
rather than "later".

**SQL-backed config** (orgs, projects, members, roles, tokens,
visibility, frontends, bindings): an append-only revision log —

```sql
config_changesets(change_id PK, actor, scope, status,   -- draft|applied|reverted
                  created_at, applied_at, reverted_by_change_id)
config_revisions(id PK, change_id, object_type, object_id,
                 op,                  -- create|update|delete
                 old_json, new_json,  -- full object snapshots
                 seq)
```

Rows are never updated; diffs render from the snapshots (semantic
field-level, not raw JSON). **Revert is a snapshot-targeted *forward*
change**, not a literal restore: reverting change-set C drafts a new
change-set targeting each object's `old_json`, which re-enters the same
validation/authz/review pipeline — surfacing a conflict if the object
changed since C, and respecting invariants (uniqueness, last-owner
rule). Security objects are revert-exempt by type: a token revocation
never reverts into a live credential (renders as "issue a replacement
token"); member removal reverts to a fresh *invitation*; secrets are
never carried in revision rows.

**Editing UX** — terraform-plan shaped, uniform across both stores:
form edits accumulate into a persistent, shareable **draft**
change-set; one **review** screen renders git parts as real TOML diffs
(via `GitService` against the draft branch) and SQL parts as field
diffs, with a plain-language impact summary ("3 hosts currently resolve
`stable` through this registry will lose anonymous read"); **apply** is
atomic per store (one transaction / one commit) and the diff screen
becomes the permanent revision page. Drafts/review/apply work as plain
forms + redirects — the producer console keeps the no-JS ethos, JS only
enhances. Confirmation gates beyond review: visibility flips (type the
registry name + sudo re-auth), member removal (shows minted-token
count — "also deadens 3 tokens"), token revocation (shows
`last_used_at`), key retirement (wizard-only, enforces the
overlap/`--vouched-by` sequence), channel advance (preview + floor
hard-block), deletes (type full path, soft-delete grace window, owner +
sudo).

**Cross-referencing** — one join key everywhere: hub-authored commits
embed an `AOS-Change-Id: <ulid>` trailer; audit rows carry `change_id`
plus resulting commit/tag hashes; the indexer matches trailers while
re-walking the surface and synthesizes an `external` audit entry
(actor = signing-key fingerprint, resolved to a roster identity where
possible, visually distinct: "observed on surface" vs "performed via
hub") for commits without one — the audit feed is complete over managed
*and* out-of-band changes without pretending the hub mediated the
latter.

### UI surface map

**Consumer-facing** (anonymous, server-rendered, works with JS
disabled — the Debian ethos):

- Registry home: name, description, trust anchors with fingerprints,
  channels and their current versions, freshness ("frontier observed
  4m ago"), mirror-freshness table, cache-coverage health, setup
  snippets.
- Package index and search; package page: versions × platforms table,
  NAR/closure sizes, store paths, license/homepage/maintainer,
  dependency closure browser, sysroot image downloads (qcow2/raw),
  narinfo permalinks, per-cache availability.
- Channel page: the **256-partition grid** — which buckets point at
  which release, rollout percentage, floor history, staleness; a
  "which version will *my* host get?" calculator.
- Releases page: signed tags, signature status, pack/thin-delta
  availability, commit history.
- Registry health page: cache × coverage matrix, validation history,
  missing-path drill-down.
- Raw directory-listing fallback for every machine path.

**Producer-facing** (authenticated):

- Org/project dashboards: registries, members, roles, tokens, storage
  bindings, frontends, audit feed.
- Publish pipeline view: live phase status mirroring `apr release`
  (commit → tag → packs → upload-immutable → flip-pointers),
  resumable/idempotent like `--resume`, with the optional
  validation gate before the flip.
- Channel rollout console: advance N partitions with preview, hold,
  floor guard warnings.
- Key roster management: rotation wizard, hosted-key enrollment.
- Token management mirroring `aos token` semantics.
- Configuration: draft → diff review → apply, revision history, revert.
- Git view: branches, commit log, TOML diffs; change requests
  (phase 3 minimal, fuller review flows later).

**Asset policy — strictly first-party.** Every page the hub renders and
every artifact it ships serves *all* of its assets from its own
origin: no third-party font CDNs (system-font stack by default;
any custom face is a self-hosted, subsetted, hash-named woff2), no
external JS or CSS, no analytics beacons, no third-party embeds. This
is enforced, not aspired to: a `Content-Security-Policy` of
`default-src 'self'` (plus the minimum for inline Leptos hydration
bootstrapping, nonce'd) ships in every response on both runtimes, and a
CI check walks the built dist + rendered pages and fails on any
absolute third-party URL. The same policy applies to the on-CDN web
surface below — which is also a privacy property: browsing a registry
leaks nothing to anyone but the registry's own origin (and the hub,
only when explicitly configured).

### The registry web surface: a static SPA on the registry's own CDN

Every registry gets a **`web` surface**: a static, client-side-rendered
WASM app uploaded to the registry's own bucket and served by plain
S3/HTTP file serving — a polished UI with **zero hub in the serving
path**, optionally connecting to a hub for dynamic features.

**Artifact shape** — a handful of static files, not literally one
(base64-inlining the WASM adds ~33% and forfeits streaming
instantiation; there is no upload-side benefit since the pipeline
handles arbitrary file sets):

```text
/index.html               mutable    (low TTL — the pointer; see below)
/web/app-<hash>_bg.wasm   immutable  (hash-named)
/web/app-<hash>.js        immutable  (wasm-bindgen glue)
/web/style-<hash>.css     immutable
/web/config.json          mutable    (branding/theme/hub URL)
/web/index.json           mutable    (pre-rendered registry snapshot)
/web/packages/<name>.json mutable    (per-package snapshots)
/browse/<name>.html       mutable    (static no-JS package pages)
```

This maps exactly onto the existing immutable/mutable upload classes in
`static_upload.rs` — SPA upgrades are atomic by the same
immutable-first pointer-flip discipline as everything else. All assets
are first-party by construction (the asset policy above). `index.html`
and `web/`/`browse/` are origin-only files like the nix-cache surface,
never part of the committed git tree.

**Data sources:**

- **Same-origin static snapshots (primary).** Publish-time pre-rendered
  JSON (`index.json`: registry meta, channels + partition summary,
  package list; `packages/<name>.json`: versions × platforms, sizes,
  narinfo links), generated from the committed tree. Same-origin
  relative fetches → **zero CORS configuration**.
- **In-browser verification — the honest badge.** The `surface/` crate
  compiles for the browser, so the SPA lazily fetches the channel
  partition and roster same-origin and runs *real* Ed25519
  verification client-side, rendering "verified in your browser:
  partition → 1.4.2 → commit ab12…" and cross-checking the JSON
  snapshot against the verified commit. One parser — server, Worker,
  browser — which also kills the parser-divergence bug class.
- **Hub ConnectRPC (optional enhancement).** `config.json` may carry
  `hub_url`; present, the SPA lights up search (server FTS), auth,
  publish status, cross-registry navigation. The hub's CORS allowlist
  is derived from its own `Frontend` table — exact domains, not `*`.
  Absent, search degrades to client-side substring over `index.json`.

**No-JS ethos preserved, three tiers**: (1) proxied frontends — full
Leptos SSR + hydration; (2) direct frontends with JS — the CSR SPA;
(3) direct frontends without JS — `index.html` is generated as a
*real, content-bearing* Debian-style static page (trust-anchor
fingerprints, channel table, package list linking to
`/browse/<pkg>.html` static pages) that the SPA progressively takes
over. One URL, no loader shell; curl and lynx see actual content. Tier
3 is the floor and it is already strictly better than Debian's
autoindex.

**Production**: a new **`apr web generate`** subcommand, exactly
parallel to `apr cache generate` — the SPA dist is embedded in the
`apr` binary (hermetically built; the AOS build already builds
Rust→wasm toolchains from source) and the command emits the dist +
static pages + JSON snapshots + `config.json` defaults;
`apr origin upload`/`apr release` grow awareness of the web dir the
same way they handle the cache dir. The no-hub story stays complete:
an operator with only `apr` and a bucket gets the full web surface.
The hub regenerates snapshots on managed publishes; both producers emit
the identical layout, and `index.json` carries `generator` +
`surface_commit` so staleness is detectable. `config.json` is
presentation-only and never trust-relevant (it is origin-only, not
signed tree content).

### Database schema (sketch)

System-of-record tables: `orgs`, `projects` (materialized-path
hierarchy), `users`, `user_identities` (`(iss, sub)`-keyed),
`service_accounts`, `memberships(principal, scope, role)`,
`tokens(id, hash, owner, scope, permissions, expires_at, revoked_at,
last_used_at)`, `sessions`, `invitations`, `org_idp_configs`
(encrypted client secrets), `org_domains` (TXT-verified),
`storage_bindings`, `frontends`, `cache_stores`, `mirror_sources`,
`hosted_keys` (encrypted), `config_changesets`, `config_revisions`,
`audit_log`, `webhooks`.

Rebuildable index tables (derived from the surface, droppable and
re-indexable at any time): `registries` (with `last_indexed_commit`,
frontier, health), `packages`, `package_versions`, `version_platforms`,
`channels`, `channel_partitions(channel, bucket, release, sig_key_id)`,
`releases(semver, tag_hash, signer, pack_presence)`, `key_rosters`,
`validation_runs`, `validation_findings(cache, store_hash, depth,
status)`, `frontend_probes`, plus the per-dialect full-text index.

### Changes outside the hub crate

The hub is one crate, but several small changes land in existing code,
each independently valuable:

| Where | Change | When |
| --- | --- | --- |
| `apr` (`static_upload.rs`) | Phase-major multi-destination ordering (immutables to all mirrors, then mutables to all); `content_type()` entries for `.wasm/.html/.js/.css/.json`; collect `index.html` + `web/` + `browse/` | with hub phase 1–2 |
| `apr` | New `apr web generate` / `apr web config`; `apr release` web-dir awareness | hub phase 1–2 |
| `apr` | `apr change merge <id>` (fetch, review, sign, push a hub change request) | hub phase 3 |
| `apm` (`download.rs`) | Cache miss-fallthrough (try next `[[caches]]` entry on 404) — today only the highest-priority cache is consulted | hub phase 3 |
| `registry.toml` | **None required** for mirrors/shared caches. Additive later: `[cache_stack]` expression; `[[origins]]` git-origin mirror list; `[registry.upstream]` inheritance | deferred |
| `apm` | Optional client-side `urls = [..]` git-origin fallback | deferred |
| `aos-proto` | `aos.registry.v1` package incl. `MintUploadCredentials` | phase 2 |

On **registry inheritance**: layering already works consumer-side —
`apm`'s registry `priority` selects the package source across
configured registries, orthogonally to cache priority — so base +
overlay registries compose today. True committed inheritance
(`[registry.upstream]`, a child transparently re-exporting a parent's
packages) is backwards-compatible to add (the parser ignores unknown
fields; old clients simply don't see inherited packages) and is
deliberately deferred.

### Sequencing

1. **Read-only hub** (highest value, lowest risk): `surface/` reader +
   indexer, public browse UI, nix-cache/dumb-HTTP facade,
   **consistency validation** (read-only by nature) and frontend
   freshness probes. Deploy on Cloudflare against the existing
   `cdn.aos.andyl.org` bucket in registration-only mode. In parallel:
   `apr web generate` and the phase-major upload fix.
2. **Tenancy + tokens + upload facade**: orgs/projects/IAM, magic
   links + the passkey verifier spike, device-flow login, storage
   bindings + registry creation (hub-managed R2 + BYO), the AOS-mode
   upload endpoints so `apr release` targets the hub; private
   registries.
3. **Producer console**: publish pipeline view, channel console, key
   rotation wizard, configuration change-sets + minimal change
   requests, per-org OIDC SSO, hub-driven mirror jobs + pull-through
   frontends, cache stacks (with the `apm` miss-fallthrough change),
   audit.
4. **Hosted keys, derived registries, fuller change-request review,
   webhooks/notifications**; postgres/mysql drivers hardened; AOS
   package + module for self-hosting; `[registry.upstream]` and
   `[[origins]]` if demand materializes.

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
- **Password authentication.** Rejected outright: a credential-stuffing
  surface, an awkward memory-hard-KDF story under Workers CPU limits,
  and reset flows that duplicate the magic-link path which must exist
  anyway for recovery.
- **SAML SSO.** No credible Rust/wasm implementation path
  (XML-DSIG); orgs bridge via OIDC. Permanently out of scope.
- **Single-file SPA (base64-inlined WASM in `index.html`).** Rejected:
  ~33% payload inflation, loses streaming instantiation, and saves
  nothing — the static-upload pipeline already handles file sets, and
  the hash-named multi-file layout is what makes SPA upgrades atomic.
- **Dedicated bucket per registry by default.** Rejected on the
  Workers target: R2 bindings are deploy-time static, so dynamic
  buckets forgo the zero-egress path; prefix sharing is sound because
  the data plane never lists. Dedicated buckets remain an opt-in.
- **An ORM / sea-orm for the three-dialect story.** Rejected: the
  schema is small, the D1 driver would still need hand-writing, and
  dialect divergence is better handled by keeping the SQL in sight.
- **gRPC-web or REST-only instead of ConnectRPC.** The repo already
  standardized on ConnectRPC (`aos-proto`, `aos-remote`); Connect's
  JSON mapping doubles as the pragmatic REST surface for third parties.

## Open questions

1. **Hosted signing keys in v1?** Without them the channel console is
   read-only and web config editing is change-request-only; with them
   the hub enters the TCB. Current position: BYO-key first, minimal
   change requests promoted to phase 3 as the mitigation, hosted keys
   an explicit org-level opt-in in phase 4.
2. **How much of `aos-package`'s registry code is wasm-clean today?**
   `types.rs` and `registry/parse.rs` look pure; `registry/git.rs`
   shells out to git. The factoring (direct reuse vs a shared no-IO
   module) needs a spike before phase 1.
3. **Leptos vs Dioxus, and CSR bundle size.** Leptos is the working
   assumption (SSR-first for the no-JS ethos); the phase-1 spike must
   also validate the CSR build for the on-CDN web surface — target
   well under ~500 KB compressed wasm — and the ergonomics of one
   codebase with SSR + CSR profiles.
4. **Range requests through the Workers facade.** R2 supports native
   ranged GETs; the facade should always redirect/proxy ranges to R2
   rather than slicing — verify this covers `apm`'s delta-fetch access
   patterns.
5. **JWT minting on Workers.** `jsonwebtoken` historically depends on
   ring; confirm a RustCrypto path or hand-roll HS256 (`hmac` + `sha2`)
   / EdDSA via `ed25519-dalek`. Also: `getrandom` needs its js feature
   on `wasm32-unknown-unknown`.
6. **The in-house passkey verifier spike.** Attestation-`none` RP
   verification is ~500–800 lines on RustCrypto crates with W3C test
   vectors; if it overruns, magic links carry phase 2 alone and
   passkeys slip a phase (or `webauthn-rs` lands its OpenSSL removal
   and slots in behind the same trait).
7. **Exact `[cache_stack]` schema and rollout.** The flattened
   `[[caches]]` compatibility layer is settled; the committed
   expression encoding (inline TOML tables vs a parallel section) and
   the `apm` stack-resolution semantics need a short design pass with
   the `apm` miss-fallthrough change.
8. **R2 dynamic bindings.** Workers R2 bindings are deploy-time static
   today, which shapes the shared-bucket default — re-verify (dispatch
   namespaces et al.) before phase 2 locks the provisioning model.
9. **SSO timing for the first deployment.** Magic links + passkeys are
   sufficient for the bootstrap team; if Andyl needs org SSO sooner
   than phase 3, OIDC moves up.
10. **"Full IPAM."** This RFC reads the requirement as full **IAM**
    (identity and access management). If IP/host management for fleet
    operators (host inventory, per-host partition buckets) is also
    intended, that is a separate consumer-side design.
