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

- [x] Rename crate `aos-registry-hub` → `aos-hub` (dir, `Cargo.toml` `name`,
      bin name, workspace members) and update all path/dep references.
- [x] Rename `aos-registry-core` → `aos-hub-core`; update every `use`/dep.
- [x] Rename `aos-registry-worker` → `aos-hub-worker`; update wasm build refs.
- [x] Rename Nix packages `aos-registry-hub-cloudflare` → `aos-hub-cloudflare`
      and `aos-registry-worker-e2e` → `aos-hub-worker-e2e`
      (`pkgs/tools/**`, `discoverPackages` filenames). The package set
      auto-discovers attrs from filenames, so the `git mv` of each
      `pkgs/tools/aos-hub*` file rewires the attr automatically.
- [x] Update `justfile` recipes, `crates/*/deploy/DEPLOY.md`, READMEs,
      `flake.nix`/`pkgs` outputs, NixOS module names, and code references;
      `HUB_*` env vars and the `aos hub …` subcommand are unchanged (no
      deployed-Worker churn — only the build-time crate/package identifiers moved).
- [x] `aos-registry-surface` / `aos-registry-spa` are intentionally *not*
      renamed (their `aos_registry_surface`/`aos_registry_spa` identifiers are
      preserved); Rust workspace builds green on host (core + hub + wasm worker).

### Phase B — cache core: object, storage, publish, serve

- [x] Migration (v22): rename derived `caches` → `advertised_caches`; repoint the
      indexer/validation readers (`cache_probes` keys on a `cache_url` string, so
      it is unaffected) and the `list_advertised_caches` method.
- [x] Migration (v22): `caches`, `cache_registry_links`, `cache_gc_policy`,
      `cache_gc_roots` (with `expires_at`) SoR tables; `cache_objects`,
      `cache_usage`, `cache_gc_runs` derived tables; indexed `LIKE` search over
      `cache_objects(store_name)` (FTS5 ranking deferred to D-web for D1 safety).
- [x] Migration: add nullable `frontends.cache_id`; enforce exactly one of
      `registry_id`/`cache_id`; gate the cache facade on `serves_cache`. **Done:**
      v24 rebuilds `frontends` so `registry_id`/`cache_id` are both nullable with a
      `CHECK ((registry_id IS NULL) <> (cache_id IS NULL))`; `FrontendRecord` carries
      both as `Option`; `create_cache_frontend`/`list_cache_frontends` added; rebuild
      clears the rebuildable `frontend_probes` (re-populated by the probe job).
      Unit-tested (coexistence, per-target listing, Direct-on-private-cache reject)
      **and validated on the D1 path** — the worker-e2e migrates from the
      `schema dump` on miniflare's SQLite engine and the cache surface still serves
      green.
      **Domain-routed serving + the `serves_cache` gate are now implemented**
      (RFC-0004 "Frontends"): a shared dispatcher (`connect::rewrite_for_frontend`,
      backed by `Database::frontends_by_domain`) resolves an incoming `Host` to the
      registry/cache a *proxied* frontend binds — a Direct frontend CNAMEs to the
      origin and never reaches the hub — strips its `base_path` (segment-aligned),
      enforces the frontend's `serves_git`/`serves_cache`/`serves_web` subset
      (`404` for a surface it doesn't advertise; classification runs on the
      percent-*decoded* path so an encoded token can't dodge it), and rewrites the
      request to the internal `/{slug}/…` identity so every existing handler serves
      it unchanged. Both shells run the *same* decision: the native hub via a
      `with_frontend_dispatch` middleware (outer-router `fallback_service` so the
      rewrite precedes routing), the Worker via the request bridge (its `!Send`
      services preclude `from_fn`). Frontend domains are stored lowercased so a
      mixed-case host matches and the `UNIQUE(domain, base_path)` constraint can't
      be dodged by case. Integration-tested (cache served by `Host` with no slug in
      the path; `serves_cache=false` 404s; case-insensitive host; base_path segment
      boundary; the percent-encoded `serves_git` bypass is gated).
      **Remaining (own follow-up, RFC-sized):** multi-domain TLS/cert
      *provisioning* — the Worker can now bind several `--domain` routes;
      the native hub serving N custom domains needs a fronting SNI proxy or
      in-hub ACME, which is environment-coupled and out of this subsystem's scope.
- [x] `aos-hub-core` cache domain types + `Database` methods: create/get/list/
      update/soft-delete/delete cache, link/unlink/list links, set/get GC policy,
      pin/renew/unpin/list roots, cache-object upsert/get/list/search/delete,
      `nar_refcount`, usage, GC-run lifecycle — all on the async `Backend`
      (sqlite + D1 clean), with contract tests.
- [x] Cache storage layout writer/reader: `nix-cache-info`, `<hash>.narinfo`
      (Ed25519-signed via `hosted_keys` sealer when keyed), content-addressed
      `nar/<file-hash>.nar.<ext>` with cross-cache refcount on the
      binding+prefix. Signing lives in the wasm-clean `nix_sign` module (Nix
      fingerprint `1;path;narHash;narSize;refs` + raw Ed25519 `Sig:` line, idempotent
      per key, preserves other keys' sigs); `put_cache_path` signs every uploaded
      root `<hash>.narinfo` with the cache's hosted key when an (optional) sealer
      is wired into the shared `RpcService` (both shells pass their `HUB_SEAL_KEY`
      sealer). Unit-tested (fingerprint/verify/idempotency) + an e2e upload→serve
      signature assertion. **Fixed en route:** the native PUT facade never reached
      caches (only HEAD did) — `nix copy --to <hub>/<cache>` 404'd on the native
      hub; the PUT route now mirrors HEAD's cache fallthrough.
- [x] **Streaming reads (UNIFIED, both shells):** there is now **one** shared
      streaming cache-read path — `RpcService::cache_serve` over
      `SurfaceFetch::fetch_stream` (returning a streaming `axum::body::Body` +
      total + served range) — that **both** the native hub and the Worker route
      through (the native-only `cache_serve_file` was deleted). Each shell's
      fetcher supplies the stream: native `LocalFsFetch` via `tokio` `ReaderStream`
      (seek + `take` for ranges), Worker R2 via the object's `ByteStream`,
      `SendWrapper`-wrapped into the axum body and trimmed chunk-by-chunk to the
      served range (the isolate never holds the whole object — pre-`start` bytes
      are dropped as they stream, and the stream ends at the range end). The
      Worker trims rather than pushing the range into the R2 `get` because
      workers-rs 0.4.x serializes every `Range` with an explicit `suffix:
      undefined` key, which the pinned workerd's R2 binding rejects ("Suffix is
      incompatible with offset") — a documented runtime-binding asymmetry, not a
      buffering one. `nix-cache-info` is generated, `Range: bytes=…` → `206` +
      `Content-Range` + `Accept-Ranges`, visibility + presign-`302` enforced once.
      A large NAR never buffers into memory on either shell. Range/206 is
      integration-tested on native **and** end-to-end on the Worker under
      workerd+miniflare (a 64 KiB NAR, `bytes=0-3` → `206`/`Content-Range`).
- [x] **Cache write facade (buffered):** `cache_writer` write-port (fs + R2)
      and shared `put_machine_path`/`head_machine_path` cache fallthrough →
      `put_cache_path`, so `nix copy --to <hub>/<cache>` works on **both** the
      native hub and the worker (native PUT/HEAD via the existing shim; native
      GET via `cache_get` → shared `facade_fetch`). Enforces cache write auth,
      machine-path/traversal guards, `MAX_UPLOAD_BYTES`, and a TOCTOU-safe org
      quota reserve-before-write (`507` on over-quota); rejects writes to a
      tombstoned cache/org; cross-table slug uniqueness keeps `/{slug}/` routing
      coherent. **Remaining (with #19):** stream the body (R2 multipart / local
      streamed write) + `Content-Length`/byte-counter quota instead of buffering,
      and `MintCacheUploadCredentials` (presigned/scoped-credential upload).
- [x] **Streaming Worker bridge:** `bridge.rs::to_worker` streams the router's
      response body straight to the Workers runtime via `Response::from_stream`
      over `axum::body::Body::into_data_stream()` (worker 0.4.2 `from_stream`;
      `futures-util` `TryStreamExt`) — no `to_bytes(usize::MAX)` / `from_bytes`,
      so a cache NAR the shared `cache_serve` streams from R2 never lands fully in
      the isolate. Combined with the unified streaming read above, the Worker
      serves NAR/narinfo end to end without buffering. (Request-body streaming is
      a follow-up; uploads are `MAX_UPLOAD_BYTES`-capped, so they stay buffered.)
- [x] Serve the read facade for caches via `facade_fetch` (slug falls through
      registry→cache) pointed at the cache binding+prefix — `nix-cache-info`
      generated from the cache config, `<hash>.narinfo`/`nar/<file>` as
      passthrough bytes from a cache-scoped fetcher (`cache_fetcher`), on native
      **and** the wasm worker via the one shared router; visibility +
      soft-delete (tombstone) enforced before any byte. The cache home page now
      advertises the `extra-trusted-public-keys` line for a keyed cache (derived
      from the hosted key's stored SSH line via `nix_sign::nix_public_key_from_ssh_line`
      — public material, no sealer). **Remaining:** client `Range:` → `206`
      streaming on the *worker* (with #19; native already streams).
- [x] **Backend access mode:** v23 adds `storage_bindings.access`
      (public|private), `public_base_url`, and `credential_ref` (additive, safe
      default `public`); `set_storage_binding_access` setter + `aos-hub binding
      set-access` CLI; `create_frontend` rejects a **Direct** frontend over a
      private binding (must be proxied/presigned). Unit-tested. **Remaining (with
      the proxy slice):** the SigV4/presigned *use* of `credential_ref`.
- [x] **Frontend model for caches + proxy settings:** the `proxy` block
      (timeouts, stream, max_body, retries+failover, range/cache-control
      passthrough) and `primary` flag on `frontends`; proxied facade honors them
      and streams; conservative defaults. **Done:** v25 adds `frontends.proxy_config`
      (a JSON `ProxyConfig` blob — connect/read timeouts, stream, max_body_bytes,
      retries, failover, pass_range, pass_cache_control, all `#[serde(default)]`
      with conservative defaults) and `is_primary`; `set_frontend_proxy` setter;
      `FrontendRecord` parses the blob (malformed ⇒ defaults, NULL ⇒ `None`).
      Unit-tested (round-trip, partial-field defaulting, primary flag, clear).
      **The facade now honors `stream` + `max_body_bytes`:** `cache_serve`
      consults the cache's primary frontend's `ProxyConfig`
      (`cache_streamed_proxy_config`) to choose streamed proxying vs the `302`
      redirect (the safe default when no frontend opts in), and rejects an origin
      object whose declared size exceeds `max_body_bytes` rather than streaming it
      through. Integration-tested (the streamed-proxy 200/206 test below, plus an
      over-cap rejection). The remaining tuning fields (`connect_timeout_secs`,
      `read_timeout_secs`, `retries`, `failover`, `pass_range`,
      `pass_cache_control`) are persisted and round-tripped but not yet applied on
      the proxied path — a documented operational-tuning follow-up (the hub's
      shared client timeouts apply, and the client `Range` is always forwarded).
- [x] **Proxy to authenticated origin:** SigV4 to private external S3/R2 (and
      native R2-binding on Workers) for proxied private bindings, streamed
      through; **presigned GET → `302`** for private direct-style reads;
      presigned PUT via the `mint` purpose. **Done:** the `sigv4` module — a pure,
      `wasm`-clean AWS SigV4 presigned-URL signer (HMAC-SHA256/SHA-256 over the
      same `hmac`/`sha2` the HS256 JWT path uses), validated bit-for-bit against
      AWS's documented worked example, with hardened input validation (rejects a
      malformed `X-Amz-Date` and CRLF/structural chars in `host`; secret never
      enters the URL). **Presigned GET → `302` is now wired end-to-end:** a cache
      on a private external binding (`access=private` + `public_base_url` + sealed
      `credential_ref` = `access_key:secret_key:region`) serves a `302` to a
      short-lived presigned origin URL instead of bytes — the shared
      `presign_cache_read` decision rendered on both shells (`FacadeObject.redirect`
      → `connect.rs` `302` for the worker; native `machine_path` `302`). The read
      path validates against `..`/traversal before signing (adversarial-review
      fix), so a crafted path can't sign outside the cache prefix; the secret
      never reaches the URL/logs. Integration-tested (happy path + traversal
      reject + no-secret-leak). **Presigned PUT via the `mint` purpose is now
      done:** `sigv4::presign_put_url` + `presign_cache_write` + the
      `MintCacheUploadCredentials` RPC (cache-write-gated, machine-path-guarded,
      returns a short-lived presigned PUT URL; empty when the binding isn't a
      private external origin). Integration-tested (presigned PUT URL + auth
      denial). **The streamed proxied read is now done:** the shared
      `OriginFetch` port (native `ReqwestOriginFetch` over `reqwest` streaming;
      Worker `WorkerOriginFetch` over the Fetch API, `SendWrapper`-wrapped into
      the axum body like the R2 path) lets the hub fetch the presigned origin URL
      itself and stream the body through `cache_serve` (`200`/`206`, the client
      `Range` forwarded as an origin `Range` header, the served range/total
      re-derived from `Content-Range`/`Content-Length`) — the same signed URL as
      the `302`, differing only in who fetches it. `cache_serve` picks streamed
      proxy vs `302` from the primary frontend's `proxy_config.stream`. SigV4 now
      carries the origin **scheme** (derived from `public_base_url`; not signed,
      so the signature is unchanged) so an `http` dev/test origin is honored while
      real S3/R2 stays `https`. Integration-tested against an in-process mock
      origin: whole read → `200` with the origin bytes, ranged read → `206` with
      the relayed `Content-Range`, and the default (no streaming frontend) still
      `302`.
- [x] **Visibility enforcement:** `require_cache_read` is enforced on every cache
      facade read (shared `cache_facade_fetch` + native `authorize_cache_read`)
      before any byte or presign — a non-public cache discloses nothing to an
      unauthorized caller; a Direct frontend over a private binding is rejected at
      creation (both `create_frontend` and `create_cache_frontend`); a private
      binding never serves bytes directly — it serves a presigned `302` (proxied
      form). All paths unit/integration-tested.
- [x] `aos-hub cache create/list/show/update/rm/link/unlink/links/gc-policy/
      pin/renew/unpin/roots/search/info/gc-runs` CLI over global `--target`
      (calls the `Database` layer directly). `frontend --mode direct|proxied` +
      proxy-settings/binding-`access` flags land with the frontend slice (#21);
      `push`/`pull` with the storage slice (#20).
- [x] RPC (`CacheService`, shared router → native + worker): `CreateCache`/
      `GetCache`/`ListCaches`/`UpdateCache` (partial)/`DeleteCache`, `LinkCache`/
      `UnlinkCache`/`ListCacheLinks`, `SetCacheGcPolicy`/`GetCacheGcPolicy`,
      `PinCachePath`/`UnpinCachePath`/`ListCacheRoots`, `SearchCache`/
      `GetCacheObject`, `ListCacheGcRuns` — with `visibility` + role enforcement
      (`registry.configure`/`read`/`iam.admin`). `MintCacheUploadCredentials`
      lands with the storage slice (#20).

### Phase C — garbage collection & retention

- [x] Derived-root refresh from linked registries (`roots_packages`):
      `registry_store_hashes` roots **every** store path (incl. image
      `store_path`s) the registry currently indexes, so a published package's
      closure is never reclaimed. (Narrowing to just live channel-frontier +
      `keep_release_versions` closures is a future refinement; rooting all
      indexed paths is the safe superset.)
- [x] Mark/sweep over `cache_objects.refs` (`gc::sweep_cache`, shared by both
      shells); narinfo delete + content-addressed NAR delete at zero
      `nar_refcount`, resolved via `nar_url`; `ttl_unreferenced_secs` grace
      (no policy ⇒ no age sweep). Cycle-safe; rooted closure never evicted.
- [x] Manual-pin expiry: expired pins are skipped at mark and reaped;
      `cache pin --ttl` / `cache renew` upsert the deadline with no re-upload
      (`expires_at`). Unit-tested.
- [x] Size-limit LRU eviction of **unrooted** objects (least-recently-accessed
      first); a fully-rooted over-cap cache logs a quota-breach warning rather
      than evicting a rooted path (a formal audit-log event is a later add).
      Unit-tested.
- [x] **LRU access signal:** a narinfo read taps `last_accessed_at` via
      `Database::touch_cache_object` — debounced to ≤1 write/object/hour so a
      high-QPS substituter doesn't turn every read into a write. Tapped on both
      shells: the worker through the shared `cache_facade_fetch`, the native hub
      at its streaming serve path. The signal is advisory — GC correctness comes
      from roots, so a missed touch only affects eviction order. Unit-tested
      (debounce no-op + past-window update + absent no-op). **Remaining (optional,
      with the proxy slice):** `access_log_source` CDN-log ingestion for Direct
      frontends; until then the age/upload-order fallback applies.
- [x] **Cross-visibility enforcement:** `link_cache` rejects advertising a cache
      less visible than the registry (its consumers couldn't read the
      substituter) and warns (structured log) on a less-visible registry rooting
      its packages into a more-visible cache (content-exposure). Visibility ranks
      public > internal > private (unknown ⇒ most restrictive). Unit + RPC
      integration tested.
- [x] Reclamation-on-removal: derived roots are recomputed every sweep from the
      registry's current index, so dropping a release / re-indexing reclaims its
      now-unreachable NARs on the next sweep (end-to-end VM coverage in #26).
- [x] `cache_gc_runs` history + `cache_usage` maintenance; `RunCacheGc` /
      `ListCacheGcRuns` RPCs; `aos-hub cache gc [--dry-run]` (local target) /
      `cache gc-policy` / `cache pin|renew|unpin|roots` CLI.
- [x] Worker GC: the `scheduled` handler now runs `indexer::gc_all` after the
      index pass — the Cron counterpart to `aos-hub cache gc`, driving the shared
      `gc::sweep_cache` over D1 + the R2 write surface for every GC-policied cache
      and recording each sweep as a `cache_gc_runs` row (one cache's failure is
      logged, never aborting the pass). `Date::now()` supplies the tick time
      (wasm has no ambient clock). Compiles for `wasm32-unknown-unknown`.

### Phase D — discovery, graph, NAR explorer, web

- [x] `SearchCache` (indexed `LIKE`) + `aos-hub cache search` CLI + the cache
      object-list page's `?q=` search box. (FTS5 ranking and a cache scope on the
      instance-home search box are later refinements.)
- [x] `CacheClosure(store_hash)` RPC (BFS over `refs`, capped) + no-JS
      transitive-closure page (`/<cache>/-/closure/<hash>`, linked from each
      object) + `aos-hub cache closure` CLI — the dependency graph in flat form
      on both shells. (An interactive SPA closure graph sharing the RFC-0005
      model is a later refinement.)
- [x] **NAR explorer (native):** a `narlist` parser walks the NAR archive
      (skipping contents; depth+entry-capped, bounds-checked) and the native hub
      renders the file tree at `/<cache>/<nar>?explore` (decompression-bomb-
      capped zstd/xz, symlink-contained), linked from each object page; whole-NAR
      download streams via the range-aware facade. **Remaining:** per-file
      download (extract one member) and a shared/worker path (worker can't
      decompress in wasm) — the explorer is native-only by design.
- [x] Cache browse pages in `core::web`: `/<cache-slug>/` summary
      (`nix-cache-info`, usage, GC state, substituter snippet), searchable
      object list, per-object narinfo + immediate-reference view; visibility +
      soft-delete enforced, served on native hub **and** worker via the one
      shared `browse_dispatch`. (Public-key line lands with signing; SPA closure
      graph + NAR explorer are the items above.)

### Phase E — parity, ops, tests, docs

- [x] `Database` contract tests cover the cache tables on every driver. The
      shared `dialect.rs` `exercise()` (run against sqlite always, postgres/mysql
      when their env URLs are set) now covers managed-cache CRUD, registry links,
      object index + search, the GC-run lifecycle, and `cache_metrics`.
- [x] Hermetic end-to-end: push → link → advance channel → GC → assert closure
      survives and reclaimed NARs are gone (the closure-correctness test). The
      `gc.rs` unit suite covers the sweep logic (rooted-closure survival, expired
      pin, size-cap LRU, dry-run); `operations.rs::cache_gc_keeps_rooted_and_reclaims_unrooted_end_to_end`
      drives it **end-to-end through the RPC layer with a real surface**: upload
      two objects via the facade `PUT`, pin one as a root, `RunCacheGc` RPC, then
      assert the rooted object survives and the unrooted one is reclaimed
      (`scanned=2, retained=1, deletedObjects=1`).
- [x] `aos-hub-worker-e2e` gains `nix-cache-info`/narinfo/NAR-fetch + a Cron GC
      pass over D1+R2 under workerd+miniflare, including a **large-NAR
      streaming** case (ranged GET → `206`) that asserts the isolate does not
      buffer the whole body — the memory-safety regression guard for the
      streaming path. **Done:** the e2e seeds a public managed
      cache (org + binding + cache + indexed object) and an R2 narinfo, then
      asserts the worker serves `nix-cache-info`, the narinfo from R2, and the
      cache home + object-list browse pages — the worker half of cache parity,
      under real workerd+miniflare. The NAR-fetch body travels the *same* R2
      cache-facade path the narinfo assertion already exercises (a different key
      through `cache_fetcher` → R2 get). The **ranged large-NAR streaming case is
      now covered**: a 64 KiB NAR is put in R2 and read both whole (`200`) and
      ranged (`Range: bytes=0-3` → `206` + `Content-Range: bytes 0-3/65536`, body
      length 4) — exercising the unified `cache_serve` over the streaming Worker
      bridge (R2 `OffsetWithLength` GET → `SendWrapper`-wrapped `ByteStream` →
      `Response::from_stream`), so the isolate never buffers the whole object. The
      **Cron GC pass is now covered**: the e2e seeds a GC-policied cache with an
      unrooted object, dispatches the worker's scheduled handler
      (`/cdn-cgi/mf/scheduled`), and asserts `gc_all` swept it on D1 without error
      — the regression guard for an `i64::MAX` `LIMIT` bind that `SQLITE_MISMATCH`'d
      on the D1 backend's `f64` integers (fixed: `list_cache_objects` omits the
      `LIMIT` for a negative sentinel). (miniflare tears down the scheduled isolate
      before async work flushes its *finish*, so the run can read `running`;
      full reclamation is covered by the native end-to-end GC test + gc.rs.)
      (Streamed *upload* — a ranged/multipart PUT — remains a documented
      follow-up; uploads are `MAX_UPLOAD_BYTES`-capped, so they stay buffered.)
- [x] **Native hub integration test against a real Nix client** (`aos-hub-e2e`,
      the native counterpart to `aos-hub-worker-e2e`): a launcher (run outside the
      sandbox, like the fleet VM tests — it needs a nix daemon + a bindable port)
      that drives the `aos-hub` binary CLI-first (`init` → `org add` → `binding
      add` → `cache create`), seeds a cache surface with **real `nix copy --to
      file://`**, boots `aos-hub serve`, and then asserts the cache read path with
      the **actual `nix` client**: generated `nix-cache-info`, passthrough
      `<hash>.narinfo`, a native ranged `nar/<file>` read → `206`/`Content-Range`,
      and — the keystone — `nix copy --from http://<hub>/<cache>`, which re-hashes
      the streamed NAR against the narinfo `NarHash` (so a serve-path corruption or
      bad range framing fails the copy). Proves the unified `cache_serve`/
      `fetch_stream` path the in-process router tests drive is the same one a real
      substituter round-trips. **Caught a real CLI bug en route:** `aos-hub binding
      add --root <path>` panicked at runtime (`clap` arg-id downcast mismatch)
      because the subcommand's `--root` (`String`) collided with the global
      `--root` hub-state-dir flag (`Option<PathBuf>`, `global = true`); the
      subcommand flag is now `--path`, and an audit confirmed no other
      differing-type global/subcommand arg-id collision remains.
- [x] No-JS cache browse + NAR explorer asserted over plain HTTP; SPA closure
      graph in a Leptos render test. `web.rs::cache_browse_and_nar_explorer_over_plain_http`
      drives the real router for the cache home, object list, object page,
      closure page, `nix-cache-info`, and the `?explore` NAR file-tree listing
      (no JavaScript). The SPA gains a `closure` module — the pure, cycle-safe
      closure-tree view model (`build_closure_view`) with unit tests for
      pre-order/depth, shared+cyclic repeats, and missing/dangling leaves — and
      a wasm-only Leptos `ClosureGraph` component that paints it. (The view-model
      is what the render test exercises; a DOM render test needs a browser
      runtime, out of scope for the hermetic native test runner.)
- [x] Per-org quota accounting includes cache bytes/objects (`org_usage`);
      `/metrics` + structured logs gain cache + GC counters; soft-delete /
      purge / export cover caches. Cache uploads reserve `org_usage`
      (`put_cache_path`); `/metrics` emits `aos_registry_hub_caches_total`,
      `…_cache_objects_total`, `…_cache_bytes_total`, `…_cache_gc_runs{status}`,
      `…_cache_gc_freed_bytes` (one aggregate query each via
      `Database::cache_metrics`); GC runs emit a structured `cache gc
      completed`/`failed` log; soft-delete tombstones the row + gates serving;
      org hard-purge cascades to `caches`/`cache_*` via `ON DELETE CASCADE`;
      and `export_org` carries an `ExportCache` slice.
- [x] DEPLOY.md + the [04](04-caching-and-mirroring.md)/[07](07-data-ops-and-testing.md)
      reconciliation documented; `aos-hub cache` `--help` reviewed as
      user-facing porcelain. The deploy guide's Maintenance section documents the
      `cache` command tree against either backend (`--target`) and the
      local-only `cache gc`; the clap `///` docs on every `CacheCommand` variant
      read as porcelain.

### Changes to the current spec (cross-file)

- [x] [04](04-caching-and-mirroring.md): note that "CacheStore" is realized by
      a managed `caches` row, and that the advertised-endpoint table is renamed
      `advertised_caches` (added below). (Scope note at the top of [04](04-caching-and-mirroring.md).)
- [x] [07](07-data-ops-and-testing.md): schema sketch points the managed-cache
      tables here; `cache_stores` in the sketch is superseded by `caches`.
- [x] [README](README.md): index this file; status header notes the cache
      addition + `aos-hub` rename as a proposed continuation.
