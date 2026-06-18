# Managed caches — hosting Nix binary caches in `aos-hub`

- **Status:** Proposed (2026-06-17). Not yet implemented; this file carries
  its own working status and the implementation checklist at the bottom.
- **Supersedes naming:** the hub becomes **`aos-hub`** — it manages two
  first-class surface kinds, *registries* (git wire surfaces) and *caches*
  (Nix binary caches), so the `aos-registry-*` crate/binary names are renamed
  (§ "The `aos-hub` rename").

A **cache** here means exactly a Nix binary cache: a `nix-cache-info` plus a
set of content-addressed NARs and their Ed25519-signed `.narinfo` pointers —
the substituter half of the world, the counterpart to a registry's mutable
git surface. The hub already *observes* caches (the advertised-endpoint list +
freshness probes in [04](04-caching-and-mirroring.md)); this file makes the hub
**host and manage** them: garbage collection, size limits, full-text search,
closure-graph visualization, GC roots pinned to published AOS packages,
reclamation when package versions are removed, no-JS web browsing, and a NAR
file explorer + downloader.

The guiding constraint, unchanged from the rest of RFC-0004: **one async
codebase in `aos-hub-core`** serves both the native hub (sqlite/pg/mysql +
local-fs/S3) and the Cloudflare Worker (D1 + R2), at parity. A cache is just a
new object type over the same `Backend`, `Blobs`/`SurfaceProvider`, and
Connect-JSON router — no Worker-only capability is introduced.

## Topology: organizations / registries / caches

A cache is a **sibling of a registry**, not a child of one. Both are
org-scoped surfaces backed by a `storage_bindings` row, optionally signed by a
`hosted_keys` row, and exposed through one or more `frontends`. They differ
only in payload: a registry's surface is a git wire surface (refs, signed
tags, releases, channels); a cache's surface is a NAR + narinfo object store.

```text
org  (acme)                         ── or no org: an instance-level standalone cache (org_id NULL)
 ├── projects ─────────────> registries        git surface: releases, channels, packages
 │                               │ cache_stack   (advertised substituter URLs)
 ├── storage_bindings ──────────┼──> buckets / prefixes      "hosted in different buckets"
 ├── hosted_keys ───────────────┤                            signs registries AND caches
 ├── frontends ─────────────────┴──> domains / CDN URLs      serves_git | serves_cache | serves_web
 │                                                           "served with different URLs / CDNs"
 └── caches ─────────────────────> NAR + narinfo store       nix-cache-info, Ed25519-signed narinfo
        ▲          ▲
        │          └── cache_registry_links  (0..N ⇄ 0..N)
        └── a cache with no links is a fully usable standalone binary cache
```

The four independence properties you asked for all fall out of reusing
existing primitives — **no new storage or frontend concept is invented**:

| Requirement | Mechanism |
| --- | --- |
| Caches need not be linked to any registry | a `caches` row with **no** `cache_registry_links` — a bare, standalone Nix cache |
| Linked to **one or more** registries | `cache_registry_links(cache_id, registry_id, …)` is a join — many-to-many in both directions |
| Hosted in **different buckets** | `caches.storage_binding_id` → `storage_bindings` (local-fs / R2 today; S3 later) + a per-cache `prefix` |
| Served with **different URLs / CDNs** | one or more `frontends` rows with `serves_cache = 1`, each its own domain / base path |

A managed cache, once served through a frontend, produces a substituter URL;
that URL can be **advertised** into a linked registry's cache stack
(`advertised = 1` on the link), so consumers of the registry automatically
learn the cache. Conversely a registry can **pin** a cache's GC roots
(`roots_packages = 1` on the link, below) so the cache retains exactly the
store paths that registry's published packages need. The two directions are
independent flags on the same join row.

### Naming reconciliation with the current spec

The shipped schema already has a *rebuildable, derived* table named `caches`
(`(registry_id, url, priority)` — the flattened advertised cache-stack, with
`cache_probes` for observability). To give the managed object the clean name
the model deserves, the migration **renames that derived table to
`advertised_caches`** (it is rebuilt from each registry's committed
`[cache_stack]` on every index, so the rename is a drop+recreate with no
system-of-record data at risk; `cache_probes`/validation reference a
`cache_url` string, not a foreign key, so they are unaffected beyond the column
they read). The freed name `caches` becomes the managed-cache
system-of-record table. The [04](04-caching-and-mirroring.md) "CacheStore"
concept (a shareable binding+prefix several registries advertise) is realized
*by* a managed cache — that's what a `caches` row is.

## Storage layout

A cache's surface lives at `{storage_binding.root}/{cache.prefix}` — the same
binding+prefix addressing a registry surface uses — laid out as a standard Nix
binary cache so stock Nix, `apm`, and the hub's own facade all read it
unchanged:

```text
{root}/{prefix}/
  nix-cache-info                     StoreDir, WantMassQuery, Priority
  <store-hash>.narinfo               StorePath, URL, Compression, FileHash,
                                     FileSize, NarHash, NarSize, References,
                                     Deriver, Sig=<keyname>:<ed25519-sig>, CA
  nar/<file-hash>.nar.zst            content-addressed NAR (zstd|xz|none)
```

**NAR files are content-addressed and shared.** As [04](04-caching-and-mirroring.md)
already establishes for registry surfaces, narinfo/NAR files carry nothing
cache-specific, so two caches pointing at the same binding+prefix deduplicate
naturally; a NAR is reference-counted by the set of `.narinfo` files (across
every cache on that binding+prefix) that name its `file-hash`, and is removed
only when that count reaches zero (§ GC sweep).

**Streaming everywhere — reads, writes, and the Worker bridge (a cross-cutting
change).** Today *every* object and body is fully buffered into memory, in five
places, and there is **no** `Range` support anywhere:

| Site | Today | Why it's wrong for NARs |
| --- | --- | --- |
| read port | `SurfaceFetch::fetch(path) -> Option<Vec<u8>>` (`fetch.rs`) | whole object in RAM |
| read facade | `facade_fetch -> FacadeObject { bytes: Vec<u8> }` (`service.rs`) | ships a whole `Vec<u8>` |
| write port | `SurfaceWrite::write(path, bytes: &[u8])` (`surface_write.rs`) | whole upload in RAM |
| write facade | `put_machine_path(body: &[u8])`, cap `MAX_UPLOAD_BYTES` (`service.rs`) | buffers then measures |
| Worker bridge | `req.bytes().await` + `to_bytes(body, usize::MAX)` → `Response::from_bytes` (`bridge.rs`) | re-buffers **both** directions |

The only metadata-cheap path is `size()`/`head_machine_path` (filesystem `stat`
/ R2 `head`). Full buffering is fine for the small registry-surface objects, but
unacceptable for NARs: a multi-hundred-MB NAR OOMs a Worker isolate (~128 MB),
and the NAR explorer must read interior members without pulling the whole
archive. **The principle: anywhere the hub reads a file or a body, it
streams** — buffering is reserved for objects with a known-small bound (git
loose objects, narinfo, JSON RPC bodies). Concretely the cache work:

- **Read** — extends the port with a ranged, streaming read
  (`fetch_range(path, offset, len)` → byte stream) over R2 ranged GET / local
  seek, and the cache facade **honors client `Range:`** with `206 Partial
  Content` + `Accept-Ranges: bytes`, streaming the body. `apm`/Nix substituter
  range fetches and the NAR explorer ride this.
- **Write** — extends the write port to accept a body **stream** (R2 streaming /
  multipart put; local streamed file write), and the upload facade enforces the
  size cap + quota from the `Content-Length` and a streaming byte counter
  instead of buffering then measuring.
- **Worker bridge** — streams request and response bodies through the
  `worker`⇄`axum` boundary (`worker::Body`/`ByteStream` ⇄ `axum::body::Body`)
  instead of `req.bytes()` / `to_bytes(usize::MAX)` — without this the facade's
  streaming is moot on the Worker, which re-buffers everything at the edge.

Registry-surface reads/writes keep the buffered `fetch()`/`write()` (small,
bounded); the streaming variants are what NARs and any future large body use.

**Signing.** A cache with a `hosted_key_id` signs every `.narinfo` with that
Ed25519 key at publish time, using the same sealed-key machinery the registries
use (`hosted_keys.secret_enc`, the AES-256-GCM sealer). The cache's public key
is surfaced in the canonical `<name>:<base64>` substituter form on the cache's
browse page and at a stable endpoint, so a consumer can drop it into
`nix.conf` `trusted-public-keys`. An unsigned cache is permitted (a private,
trusted-network cache) but flagged in the UI.

## Schema (migrations v22+)

System-of-record tables (not derivable from the bucket; backed up):

```sql
-- The managed cache identity. Mirrors `registries` deliberately.
caches(
  id, org_id NULL→orgs,            -- NULL = instance-level standalone cache
  slug UNIQUE, name,
  storage_binding_id→storage_bindings, prefix,
  hosted_key_id NULL→hosted_keys,  -- narinfo signing key; NULL = unsigned
  visibility,                      -- public | internal | private
  priority,                        -- nix-cache-info Priority (substituter order)
  compression DEFAULT 'zstd', want_mass_query DEFAULT 1,
  created_at, deleted_at NULL, purge_after NULL)   -- soft-delete, like orgs

-- 0..N ⇄ 0..N registry⇄cache association; both flags independent.
cache_registry_links(
  cache_id→caches, registry_id→registries,
  roots_packages BOOL,             -- this registry's live store paths pin GC roots
  advertised     BOOL,             -- inject this cache's URL into the registry's stack
  created_at, PRIMARY KEY(cache_id, registry_id))

-- Retention policy per cache. NULL = unlimited / disabled.
cache_gc_policy(
  cache_id PK→caches,
  max_bytes NULL, max_objects NULL,
  ttl_unreferenced_secs NULL,      -- grace before an unreachable object is swept
  keep_release_versions NULL,      -- per linked registry: keep N most-recent releases' closures
  keep_channel_frontier DEFAULT 1, -- always retain live channel-frontier closures
  schedule_secs NULL, updated_at)

-- GC roots. Manual rows are SoR; 'derived' rows are recomputed each run.
cache_gc_roots(
  id, cache_id→caches, store_hash,
  root_kind,                       -- manual | release | channel | package_version | derived
  root_ref,                        -- e.g. 'registry:42:channel:stable' or '' for manual
  expires_at NULL,                 -- manual pins only: deadline; NULL = unlimited (default).
                                   -- renewable in place (no re-upload); past it, stops pinning.
  created_at, UNIQUE(cache_id, store_hash, root_kind, root_ref))
```

Existing `frontends` gains a nullable `cache_id→caches`; a frontend now serves
**either** a registry (`registry_id` set) **or** a cache (`cache_id` set),
disambiguated by which is non-NULL, and `serves_cache` gates the cache facade.
It also gains the proxy/access columns the current thin schema lacks (see
"CDN frontends, proxy modes & access control" below):

```sql
-- frontends: additive columns (apply to registry AND cache frontends).
frontends(… ,
  proxy JSON,            -- proxied-mode settings: connect/read/overall timeouts,
                         -- stream (always on), max_body, retries, failover,
                         -- range_passthrough, cache_control/etag passthrough
  access_log_source NULL, -- direct-mode CDN log ingestion for LRU backfill
  primary BOOL)          -- the one advertised primary origin

-- storage_bindings: additive columns — the missing "can this be served
-- directly / must the hub authenticate to origin?" facts.
storage_bindings(… ,
  access,                -- public | private
  public_base_url NULL,  -- set iff access=public; enables a Direct frontend
  credential_ref NULL)   -- sealed SigV4 credential for proxying a private origin
```

Rebuildable / derived tables (a full bucket re-scan reconstructs them;
droppable like `packages`/`version_platforms`):

```sql
-- The narinfo index — THE searchable / browsable / graph-able surface.
cache_objects(
  cache_id→caches, store_hash, store_name,
  nar_url, nar_hash, nar_size, file_hash, file_size, compression,
  deriver, refs JSON,              -- closure edges = store hashes this path references
  sig, ca, uploaded_at, last_accessed_at,
  PRIMARY KEY(cache_id, store_hash))

cache_usage(cache_id PK→caches, used_bytes, object_count, updated_at)

cache_gc_runs(
  id, cache_id→caches, started_at, finished_at, status, error,
  scanned, retained, deleted_objects, freed_bytes)   -- run history, like validation_runs
```

Plus the per-dialect full-text index over `cache_objects(store_name, deriver)`.
`last_accessed_at` is access telemetry (drives LRU eviction); a re-scan resets
it to scan time — acceptable, it only relaxes eviction.

## CDN frontends, proxy modes & access control

CDN URLs for registries **and** caches are managed by the one `frontends`
table — there is no separate cache-CDN concept. "Managing CDN URLs" *is*
"rows in `frontends`," each a `(domain, base_path, mode, surfaces)` over one
object; a registry or cache may have many (a proxied primary + direct CDN
mirrors + a cold backup). This generalizes the [03](03-api-storage-frontends.md)
`Frontend` design to caches and fills the gaps below; it supersedes the thin
shipped schema (`mode`/`serves_*`/`consumer_priority`/`advertised` only).

**Direct vs proxied — a property of the frontend, not the object.**

- **Direct** — the hub is not in the request path (CNAME → R2 custom domain,
  CloudFront → S3). Lowest latency/cost; the hub only *probes* it
  (`frontend_probes`) and **sees no request traffic** (matters for LRU, below).
- **Proxied** — the hub facade is in the path, either streaming the bytes
  through or `302`-redirecting to a presigned URL. This is what enables auth
  enforcement, HTML at the same URL, `Range`/`206`, and per-request
  observability.

**Rule: a private or internal object can only be served proxied.** A Direct
frontend on a private/internal registry or cache is a validation error — it
would serve bytes with no auth check. Public objects may be either mode.

**Proxy settings (new — none exist today).** A proxied frontend carries a
`proxy` settings block: `connect_timeout` / `read_timeout` / `overall_deadline`;
`stream` (always on — the streaming work above, never buffer); `max_body`;
`retries` + `failover` (advance to the next frontend/binding on 5xx/timeout —
composes with cache stacks); `range_passthrough`; and `cache_control`/`etag`
passthrough so a downstream CDN still caches the proxied response. Conservative
defaults (≈5s connect, 30s read, stream on, range on, one retry with failover).

**Backend access mode (new).** Each `storage_bindings` row is marked
`access = public | private` with an optional `public_base_url`. This is the
fact that makes mapping decidable: a `public` binding (with a `public_base_url`)
can back a **Direct** frontend and the hub can hand out plain GET URLs; a
`private` binding can only back a **Proxied** frontend and the hub must reach
the origin **with credentials**. You cannot build a Direct frontend over a
private bucket.

**The hub proxying authenticated R2/S3 (yes).** A proxied frontend over a
`private` binding authenticates to origin: on Workers, native R2-binding access
(zero-egress, no credentials in flight); for external private S3/R2, **SigV4**
with the binding's sealed `credential_ref`, streamed through. For private
*reads* the hub may instead **mint a short-lived presigned GET URL and `302`**
the client to it — offloading bytes to the bucket/CDN while keeping the auth
decision at the hub. So **signed URLs run both ways**: hub→client (presigned
GET via 302, presigned PUT via the `mint` purpose / `MintUploadCredentials`) and
hub→origin (SigV4 to an authenticated bucket for a proxied private binding).

**LRU under direct mode (the subtlety you flagged).** `last_accessed_at` drives
LRU eviction, but a **Direct** frontend never touches the hub, so request
traffic can't update it. Resolution, in order:

1. **Proxied** frontends tap every GET → exact `last_accessed_at`.
2. **Direct** frontends may set `access_log_source` to ingest CDN access logs
   (Cloudflare Logpush / R2 access events / CloudFront logs) on a schedule and
   backfill access times.
3. **Absent both,** LRU is unavailable for that cache: size-cap eviction falls
   back to **upload-age + root-reachability only** (TTL + GC roots), and the UI
   states plainly that eviction is age-based, not usage-based. Root-pinned
   closures are never evicted regardless, so correctness holds — only the
   eviction *order* degrades.

**Cross-visibility pointing.** A registry points to a cache by **advertising**
its URL (`advertised = 1` → the cache's frontend URL lands in the registry's
`cache_stack`); a cache points to registries only via `gc_root_source` linkage,
which is internal and never exposed to consumers. The decidable rules:

| Link | Constraint |
| --- | --- |
| registry **advertises** cache | the cache must be visible to everyone who can see the registry — a **public** registry may advertise only a **public** cache; **internal** may advertise internal/public; **private** may advertise any. Otherwise consumers hit 401/403 on substitution. **Enforced at link time.** |
| registry is a **gc_root_source** for cache | unconstrained for function (it only pins store paths), but **warned** when a private/internal registry roots a **public** cache: the rooted NARs become publicly fetchable by hash — fine for open build outputs, a leak for secret artifacts. |
| cache served **Direct** | only if its binding is `public` **and** its visibility is `public`. |

So a **public registry → private cache is rejected** (broken for consumers); a
**private registry → public cache is allowed but flagged** (content-exposure
warning). Both are decidable from `visibility` + binding `access` alone. The
same matrix governs registry frontends — caches and registries share one
access-control model.

## Garbage collection

Classic mark/sweep over the `cache_objects.refs` closure graph, with roots
derived from the published-package graph:

1. **Refresh derived roots.** For each linked registry with
   `roots_packages = 1`: every `version_platforms.store_path` belonging to a
   release that is *live* — reachable from a current channel frontier
   (always, when `keep_channel_frontier`) or within the
   `keep_release_versions` most-recent releases — becomes a
   `cache_gc_roots(root_kind='derived')` row, its `store_hash` the hash
   component of the store path. Stale derived rows are deleted. **This is GC
   roots pinned to AOS packages.**
2. **Mark.** Transitive closure over `cache_objects.refs` from every *live*
   root `store_hash` present in this cache — a manual pin whose `expires_at`
   has passed is skipped (it no longer roots anything) and reaped.
3. **Sweep.** A `cache_objects` row not in the marked set and older than
   `ttl_unreferenced_secs` is deleted: its `.narinfo` is removed, and its NAR
   `file-hash` is removed only when no remaining narinfo on the binding+prefix
   references it (the content-addressed refcount above). Recorded in
   `cache_gc_runs`; `cache_usage` is updated.
4. **Size limits.** After the sweep, if `used_bytes > max_bytes` (or
   `object_count > max_objects`), evict **unrooted** objects by ascending
   `last_accessed_at` (LRU) until under the cap. Rooted closures are never
   evicted — breaking a published package's closure is worse than overrunning
   a soft cap; an over-cap-while-fully-rooted cache raises a quota-breach
   health state + audit event instead of corrupting a closure.

**Expiring manual pins.** A manual pin defaults to unlimited (`expires_at`
NULL), but may carry a deadline (`cache pin --ttl 14d`) — ideal for build
intermediates and other paths you want kept *for a while* without keeping them
forever. The deadline is renewed in place (`cache pin --ttl …` again, or
`cache renew`) **without re-uploading** the NAR — it only rewrites
`cache_gc_roots.expires_at`. Once it lapses, the path is no longer a root and
is swept under the normal TTL grace like any other unreachable object.

**Reclamation when package versions are removed** needs no special path: drop
a release, or advance a channel frontier past it, and step 1 stops emitting
its derived roots; the next sweep reclaims the now-unreachable NARs. A
standalone cache (no links) has only `manual` roots, so it keeps pinned
closures and reclaims everything else under TTL/size.

GC runs on demand (`aos-hub cache gc`) and on a schedule: natively on a timer,
on the Worker by **extending the existing Cron trigger** that already runs the
indexer with a cache-GC pass (no new Worker plumbing).

## Search, dependency graph, NAR explorer, web browse

- **Full-text search.** `cache_objects` is indexed by `store_hash`,
  `store_name`, and `deriver`, with a dialect FTS index over name/deriver; a
  `SearchCache` RPC backs both the hub search box (gaining a cache scope) and
  `aos-hub cache search`.
- **Dependency-graph visualization.** `refs` *is* the closure DAG. A
  `CacheClosure(store_hash)` RPC returns nodes + edges (sizes, signer,
  presence); the no-JS page renders the immediate edge table, and the
  `aos-registry-spa` SPA renders the interactive closure graph — reusing
  RFC-0005's store/ realisation-graph model so there is one closure renderer.
- **NAR file explorer + downloader.** A `ListNarContents(store_hash)` RPC
  lists a NAR's internal file tree (parsed via the existing `aos-core/src/nar`
  reader, which already runs on wasm); the browse page renders the tree with
  per-file and whole-NAR download links, all served through the existing
  `facade_fetch` / `head_machine_path` machinery — a new content shape, not a
  new transport.
- **Web browsing.** Caches get browse pages alongside registries in
  `core::web`: `/<cache-slug>/` (summary: `nix-cache-info`, object count,
  `cache_usage`, GC policy + last run, the `trusted-public-keys` line), a
  searchable object list, a per-object narinfo + closure view, and the NAR
  explorer. Cache pages honor `visibility` and the same auth as registries.

## CLI surface — `aos-hub cache …`

A new `cache` command group parallel to `registry`, backend-agnostic via the
existing global `--target` (`local` | `d1:<name>`), so every operation runs the
same `core::Database` code against the local sqlite file or live D1:

```text
aos-hub cache create <slug> --binding <b> [--org <o>] [--key <hosted-key>]
                            [--prefix <p>] [--visibility <v>] [--priority <n>]
aos-hub cache list | show <slug> | update <slug> … | rm <slug>
aos-hub cache link   <cache> <registry> [--advertise] [--roots-packages]
aos-hub cache unlink <cache> <registry>
aos-hub cache frontend <cache> --domain <d> [--base-path <p>]   # serves_cache=1
aos-hub cache push <cache> <store-path…>     # upload NAR+narinfo, sign if keyed
aos-hub cache pull <cache> <store-hash>      # download a NAR
aos-hub cache gc <cache> [--dry-run]         # mark/sweep; prints freed bytes
aos-hub cache gc-policy <cache> --max-bytes … --ttl … --keep-versions …
aos-hub cache pin   <cache> <store-hash> [--ttl <dur>]   # default unlimited
aos-hub cache renew <cache> <store-hash> --ttl <dur>     # extend, no re-upload
aos-hub cache unpin <cache> <store-hash>
aos-hub cache roots <cache>                  # list roots (manual + derived, with expiry)
aos-hub cache search <cache> <query>
aos-hub cache info <cache> [<store-hash>]    # nix-cache-info / a narinfo
```

## RPC surface (`aos.registry.v1`, additive)

New methods extend the shared `RpcService` (today's 26): `CreateCache`,
`GetCache`, `ListCaches`, `UpdateCache`, `DeleteCache`; `LinkCache`,
`UnlinkCache`; `SetCacheGcPolicy`, `GetCacheGcPolicy`; `PinCachePath`
(optional `expires_at`, upsert so it doubles as renew), `UnpinCachePath`,
`ListCacheRoots`; `SearchCache`, `GetCacheObject`,
`CacheClosure`, `ListNarContents`; `RunCacheGc`, `ListCacheGcRuns`;
`MintCacheUploadCredentials` (the cache analog of `MintUploadCredentials` —
short-lived credential for `PutNar`/narinfo writes through the facade). Reads
honor `visibility`; writes/GC/policy require the cache's org scope at the
appropriate role.

## Native / Worker parity

Everything lives in `aos-hub-core`, so it is identical on both shells. NAR and
narinfo are R2 objects under the cache `prefix` (native: local-fs/S3); the
index is `cache_objects` rows in D1 (native: sqlite/pg/mysql); the read facade
is the existing `facade_fetch` pointed at a cache's binding+prefix; upload is
`MintCacheUploadCredentials` + facade PUT (the same lease-free, content-
addressed write the registry surface uses); and GC piggybacks the Worker's
existing Cron. No capability the registry path doesn't already exercise is
added — the workerd+miniflare e2e gains cache assertions rather than new
infrastructure.

## The `aos-hub` rename

The binary is already a multi-tenant control plane; registries are merely its
first object type and caches are its second, so the `registry`-specific names
are misleading. Mechanical, lands as its own PR before the cache work:

| Old | New |
| --- | --- |
| `aos-registry-hub` (binary crate + bin name) | `aos-hub` |
| `aos-registry-core` | `aos-hub-core` |
| `aos-registry-worker` | `aos-hub-worker` |
| `pkgs.aos-registry-hub-cloudflare` | `pkgs.aos-hub-cloudflare` |
| `pkgs.aos-registry-worker-e2e` | `pkgs.aos-hub-worker-e2e` |

`aos-registry-surface` and `aos-registry-spa` **keep** their names — they read
the registry *git wire surface* specifically (the SPA merely *gains* cache
closure/NAR views). The runtime env vars are already `HUB_*`
(`HUB_EXTERNAL_URL`, `HUB_JWT_SECRET`, `HUB_SEAL_KEY`, …), so **no deployed
Worker secret/var churn** — the rename is crate, bin, Nix-package, justfile,
and doc naming only. `aos hub …` remains the umbrella subcommand.

## Testing

The same pyramid [07](07-data-ops-and-testing.md) draws: `Database` contract
tests gain the cache tables on every driver; an end-to-end hermetic test
pushes store paths into a `local` cache, links it to a registry, advances a
channel, runs GC, and asserts the right NARs survive and the reclaimed ones
are gone (closure-correctness is the test that matters); the workerd+miniflare
e2e (`aos-hub-worker-e2e`) gains `nix-cache-info`/narinfo/NAR-fetch + a Cron GC
pass over D1+R2; and the no-JS cache browse pages + NAR explorer are asserted
over plain HTTP, the SPA closure graph in a Leptos render test.

---

## Implementation checklist

Tracks the rename, every cache feature and structure above, and each change to
the current spec. Phases are orderable; A lands first, E last.

### Phase A — the `aos-hub` rename (mechanical, standalone PR)

- [ ] Rename crate `aos-registry-hub` → `aos-hub` (dir, `Cargo.toml` `name`,
      bin name, workspace members) and update all path/dep references.
- [ ] Rename `aos-registry-core` → `aos-hub-core`; update every `use`/dep.
- [ ] Rename `aos-registry-worker` → `aos-hub-worker`; update wasm build refs.
- [ ] Rename Nix packages `aos-registry-hub-cloudflare` → `aos-hub-cloudflare`
      and `aos-registry-worker-e2e` → `aos-hub-worker-e2e`
      (`pkgs/tools/**`, `discoverPackages` filenames).
- [ ] Update `justfile` recipes, `crates/*/deploy/DEPLOY.md`, READMEs,
      `flake.nix`/`pkgs` outputs, NixOS module names, and AGENTS.md/CLAUDE.md
      mentions; confirm `HUB_*` env vars and `aos hub …` subcommand are
      unchanged (no deployed-Worker churn).
- [ ] Confirm `aos-registry-surface` / `aos-registry-spa` are intentionally
      *not* renamed; build green on host + `pkgs.aos` workspace tests.

### Phase B — cache core: object, storage, publish, serve

- [x] Migration (v22): rename derived `caches` → `advertised_caches`; repoint the
      indexer/validation readers (`cache_probes` keys on a `cache_url` string, so
      it is unaffected) and the `list_advertised_caches` method.
- [x] Migration (v22): `caches`, `cache_registry_links`, `cache_gc_policy`,
      `cache_gc_roots` (with `expires_at`) SoR tables; `cache_objects`,
      `cache_usage`, `cache_gc_runs` derived tables; indexed `LIKE` search over
      `cache_objects(store_name)` (FTS5 ranking deferred to D-web for D1 safety).
- [ ] Migration: add nullable `frontends.cache_id`; enforce exactly one of
      `registry_id`/`cache_id`; gate the cache facade on `serves_cache`.
- [x] `aos-hub-core` cache domain types + `Database` methods: create/get/list/
      update/soft-delete/delete cache, link/unlink/list links, set/get GC policy,
      pin/renew/unpin/list roots, cache-object upsert/get/list/search/delete,
      `nar_refcount`, usage, GC-run lifecycle — all on the async `Backend`
      (sqlite + D1 clean), with contract tests.
- [ ] Cache storage layout writer/reader: `nix-cache-info`, `<hash>.narinfo`
      (Ed25519-signed via `hosted_keys` sealer when keyed), content-addressed
      `nar/<file-hash>.nar.<ext>` with cross-cache refcount on the
      binding+prefix.
- [ ] **Streaming reads:** extend the surface-read port with a ranged,
      streaming read (`fetch_range(path, offset, len)` → byte stream) over R2
      ranged GET and local-file seek; keep buffered `fetch()` for small surface
      objects.
- [ ] **Streaming writes:** extend the surface-write port to accept a body
      **stream** (R2 streaming/multipart put; local streamed file write);
      `MintCacheUploadCredentials` + facade PUT becomes streaming and
      content-addressed, enforcing the size cap + org quota from
      `Content-Length` + a streaming byte counter (no buffer-then-measure);
      reject over-quota with `507`.
- [ ] **Streaming Worker bridge:** stream request and response bodies through
      the `worker`⇄`axum` boundary (`worker::Body`/`ByteStream` ⇄
      `axum::body::Body`), replacing `req.bytes()` / `to_bytes(usize::MAX)` /
      `Response::from_bytes` in `bridge.rs` — the enabler without which facade
      streaming is re-buffered at the edge (verify `Range`/`206` passthrough end
      to end under workerd).
- [ ] Serve the read facade for caches via `facade_fetch`/`head_machine_path`
      pointed at the cache binding+prefix; **honor client `Range:` →
      `206 Partial Content` + `Accept-Ranges: bytes`, streaming NAR bodies (no
      whole-NAR buffering, Worker-isolate-safe)**; surface the
      `trusted-public-keys` line + public-key endpoint.
- [ ] **Backend access mode:** `storage_bindings.access` (public|private) +
      `public_base_url` + sealed `credential_ref`; reject a Direct frontend over
      a private binding.
- [ ] **Frontend model for caches + proxy settings:** the `proxy` block
      (timeouts, stream, max_body, retries+failover, range/cache-control
      passthrough) and `primary` flag on `frontends`; proxied facade honors them
      and streams; conservative defaults.
- [ ] **Proxy to authenticated origin:** SigV4 to private external S3/R2 (and
      native R2-binding on Workers) for proxied private bindings, streamed
      through; **presigned GET → `302`** for private direct-style reads;
      presigned PUT via the `mint` purpose.
- [ ] **Visibility enforcement:** private/internal objects served proxied only;
      `require_read` enforced on the cache facade; Direct-on-private rejected.
- [x] `aos-hub cache create/list/show/update/rm/link/unlink/links/gc-policy/
      pin/renew/unpin/roots/search/info/gc-runs` CLI over global `--target`
      (calls the `Database` layer directly). `frontend --mode direct|proxied` +
      proxy-settings/binding-`access` flags land with the frontend slice (#21);
      `push`/`pull` with the storage slice (#20).
- [ ] RPC: `CreateCache`/`GetCache`/`ListCaches`/`UpdateCache`/`DeleteCache`,
      `LinkCache`/`UnlinkCache`, `GetCacheObject`,
      `MintCacheUploadCredentials`; `visibility` + role enforcement.

### Phase C — garbage collection & retention

- [ ] Derived-root refresh from linked registries (`roots_packages`): live
      channel-frontier + `keep_release_versions` closures → `cache_gc_roots`.
- [ ] Mark/sweep over `cache_objects.refs`; narinfo delete + content-addressed
      NAR delete at zero refcount; `ttl_unreferenced_secs` grace.
- [ ] Manual-pin expiry: `cache_gc_roots.expires_at` (NULL = unlimited
      default); expired pins skipped at mark and reaped; `cache pin --ttl` /
      `cache renew` upsert the deadline with no re-upload (`PinCachePath`
      carries `expires_at`).
- [ ] Size-limit LRU eviction of **unrooted** objects; quota-breach health +
      audit event when fully-rooted and over cap (never evict a rooted path).
- [ ] **LRU access signal:** `last_accessed_at` tapped by the proxied facade;
      optional `access_log_source` CDN-log ingestion for direct frontends;
      documented age-based fallback when neither is present (correctness via
      roots is unaffected).
- [ ] **Cross-visibility enforcement:** reject a registry advertising a cache
      less visible than itself; warn on a private/internal registry rooting a
      public cache (content-exposure).
- [ ] Reclamation-on-removal verified: dropping a release / advancing a
      channel reclaims its now-unreachable NARs on the next sweep.
- [ ] `cache_gc_runs` history + `cache_usage` maintenance; `RunCacheGc` /
      `ListCacheGcRuns` RPCs; `aos-hub cache gc [--dry-run]` /
      `cache gc-policy` / `cache pin|renew|unpin|roots` CLI.
- [ ] Worker GC: extend the existing Cron trigger with a cache-GC pass over
      D1+R2 (no new Worker plumbing).

### Phase D — discovery, graph, NAR explorer, web

- [ ] `SearchCache` over the FTS index; hub search box gains a cache scope;
      `aos-hub cache search` CLI.
- [ ] `CacheClosure(store_hash)` RPC (nodes+edges); no-JS edge table + SPA
      interactive closure graph sharing the RFC-0005 graph model.
- [ ] `ListNarContents(store_hash)` RPC over the `aos-core/src/nar` reader,
      reading interior members via the ranged port (no whole-NAR buffering);
      NAR file-tree browse page with per-file + whole-NAR download streamed
      through the range-aware facade.
- [ ] Cache browse pages in `core::web`: `/<cache-slug>/` summary
      (`nix-cache-info`, usage, GC policy + last run, public key), searchable
      object list, per-object narinfo + closure view; `visibility`/auth honored
      and identical on native hub + Worker.

### Phase E — parity, ops, tests, docs

- [ ] `Database` contract tests cover the cache tables on every driver.
- [ ] Hermetic end-to-end: push → link → advance channel → GC → assert closure
      survives and reclaimed NARs are gone (the closure-correctness test).
- [ ] `aos-hub-worker-e2e` gains `nix-cache-info`/narinfo/NAR-fetch + a Cron GC
      pass over D1+R2 under workerd+miniflare, including a **large-NAR
      streaming** case (ranged GET → `206`, and a streamed upload) that asserts
      the isolate does not buffer the whole body — the memory-safety regression
      guard for the streaming path.
- [ ] No-JS cache browse + NAR explorer asserted over plain HTTP; SPA closure
      graph in a Leptos render test.
- [ ] Per-org quota accounting includes cache bytes/objects (`org_usage`);
      `/metrics` + structured logs gain cache + GC counters; soft-delete /
      purge / export cover caches.
- [ ] DEPLOY.md + the [04](04-caching-and-mirroring.md)/[07](07-data-ops-and-testing.md)
      reconciliation documented; `aos-hub cache` `--help` reviewed as
      user-facing porcelain.

### Changes to the current spec (cross-file)

- [ ] [04](04-caching-and-mirroring.md): note that "CacheStore" is realized by
      a managed `caches` row, and that the advertised-endpoint table is renamed
      `advertised_caches` (added below).
- [ ] [07](07-data-ops-and-testing.md): schema sketch points the managed-cache
      tables here; `cache_stores` in the sketch is superseded by `caches`.
- [ ] [README](README.md): index this file; status header notes the cache
      addition + `aos-hub` rename as a proposed continuation.
