# `apr release` — all-or-nothing publishing with internal caching

> **Specification.** `apr release` MUST publish a registry release as a single
> transactional unit: either it produces a complete, self-consistent set of
> artifacts — signed tag, packs, binary cache (narinfos + NARs), `[[caches]]`
> advertisement, channel update, and uploads — or it produces none and fails
> loudly. The static binary cache is an internal implementation detail: the
> caller never names a `--cache-output` directory, and `apr` stages, reuses,
> and garbage-collects cache files itself under a platform cache directory.
> Incoherent flag combinations are rejected before any work begins.
>
> **Audience:** `apr`/`apm` implementers (`crates/aos-package/`, `crates/aos-cache/`).
>
> **Scope:** the producer release pipeline — `apr release`, `apr cache
> generate`, and the static-cache/origin upload path. It does **not** change
> the consumer substitution path, the registry transport, pack/delta
> generation, or signing of tags and narinfos beyond the wiring described here.
>
> **Grounding.** All `path:line` citations describe the tree at commit
> `ec9c2989` (`crates/`). Treat them as a map to the code as it stands, not as
> a live API. Line numbers will drift; the function and type names will not.

---

## 1. Problem

`apr release` is meant to be the one command a producer runs to cut a release.
In its current form the binary-cache portion of that pipeline is assembled from
**three independently-gated steps** keyed on three separate flags, so most flag
combinations yield a *partially published* release that looks successful.

### 1.1 The three independent toggles

In `release_registry_tree` (`registry_ops.rs:7510`) the cache work is three
disjoint blocks:

| Step | Gate | Location |
|---|---|---|
| Commit `[[caches]]` pointer | `Some(cache_url)` | `registry_ops.rs:7537` |
| Generate narinfos + NARs | `Some(cache_output)` | `registry_ops.rs:7563` |
| Upload (origin + cache files) | `!upload_urls.is_empty()` | `registry_ops.rs:7611` |

Because the gates are independent, the eight combinations of
(`--cache-url`, `--cache-output`, `--upload-url`) are all reachable, and most
are incoherent.

### 1.2 Failure modes

1. **Advertise-without-publish (the trap).** `--cache-url` with no
   `--cache-output` upserts and commits a `[[caches]]` pointer
   (`registry_ops.rs:7537`–`7547`) while generation is skipped
   (`registry_ops.rs:7563`). Consumers sync, discover the cache, and `404` on
   every substitution. The only guard that exists is
   `--cache-key requires --cache-output` (`validate_release_options`,
   `registry_ops.rs:7668`); there is **no** `--cache-url requires …` guard.

2. **Silent no-cache.** Without `--cache-output`, generation is skipped, and
   the upload passes `cache_dir = None` so `collect_static_origin_files` omits
   `nix-cache-info`, narinfos, and `nar/` entirely
   (`static_upload.rs:106`). A release with `--upload-url` therefore uploads
   packs and refs but zero substitutable bytes — without any error.

3. **Generate-without-upload.** `--cache-output` with no `--upload-url`
   generates and (if `--cache-url` is set) advertises, but the upload block is
   skipped (`registry_ops.rs:7611`), so nothing is pushed anywhere — same empty
   result, reached differently.

4. **Advertise ≠ upload.** `--cache-url` and `--upload-url` are unrelated
   strings. A producer can advertise read URL `A` while writing to destination
   `B`, with nothing checking the relationship.

### 1.3 Redundant regeneration and re-upload

Even when used correctly, the pipeline does no existence checking:

- Generation re-creates the **entire current closure** every release. The only
  work it avoids is when a compressed NAR still happens to sit in the local
  output directory (`let skip = nar_dir.join(&nar_name).exists()`,
  `nixcache.rs:158`).
- Upload re-`PUT`s **every** file in the output directory each release with no
  remote existence check (`upload_static_cache`, `nixcache.rs:415`–`453`;
  `upload_static_origin`, `static_upload.rs:187`–`219`).

The remote cache is content-addressed and immutable
(`Cache-Control: …, immutable`, `static_upload.rs:31`), so re-uploading a path
that is already present is pure waste. It is also the only reason
retention-by-reachability would matter: a later release re-expands the whole
closure (which still lists older, still-referenced versions) and re-dumps any
member absent from the local output — and **fails** if that store path was
garbage-collected from the local Nix store in the meantime
(`gather_all_path_info` validity check inside `generate_static_cache`,
`nixcache.rs:109`).

### 1.4 `--cache-output` is a build artifact, not configuration

The output directory is written by `generate_static_cache` and read back by the
uploader within the same command. Nothing downstream needs the path; the
generator already performs content-addressed reuse (`nixcache.rs:158`). It is a
staging area, surfaced to users only because the pipeline was assembled from
the lower-level `apr cache generate` primitive (`run_cache`,
`registry_ops.rs:4774`), whose `--output` is mandatory.

---

## 2. Current behavior (reference)

### 2.1 Entry points

- CLI variant `RegistryCommand::Release` — `lib.rs:854`; cache flags at
  `cache_output` `lib.rs:920`, `cache_key` `lib.rs:923`, `cache_url`
  `lib.rs:926`, `cache_priority` `lib.rs:929`, `upload_urls` `lib.rs:933`.
- Dispatch — `RegistryCommand::Release { … }` arm at `lib.rs:2145`, calling
  `registry_ops::release(…)` at `lib.rs:2178`.
- `release(…)` — `registry_ops.rs:7383`: resolves the registry directory and
  signing key, optionally `publish`es `--store-path`, builds
  `ReleaseTreeOptions`, and calls `release_registry_tree`.
- `release_registry_tree(…)` — `registry_ops.rs:7510`: the transactional body
  under `ReleaseLock` (`registry_ops.rs:7336`).
- `ReleaseTreeOptions` — `registry_ops.rs:7281`; `ReleaseReport` —
  `registry_ops.rs:7316`.

### 2.2 Static-cache primitives

- `generate_static_cache(registry_dir, output_dir, key_path, priority, jobs,
  printer)` — `nixcache.rs:109`. Bails on an empty registry
  (`nixcache.rs:119`). `collect_store_paths` expands every root to its full
  closure (`nixcache.rs:596`); `common_store_dir` requires one store directory
  per cache (`nixcache.rs:615`).
- `upsert_registry_cache(registry_dir, cache_url, priority)` —
  `nixcache.rs:548`.
- `upload_static_cache` / `upload_static_cache_to_all` — `nixcache.rs:415` /
  `nixcache.rs:512`.
- `collect_static_origin_files(registry_dir, cache_dir)` — `static_upload.rs:84`;
  the cache portion is conditional on `Some(cache_dir)` at
  `static_upload.rs:106`. `upload_static_origin_to_all` — `static_upload.rs:138`.

### 2.3 Backend and scope

- Cache backend trait `CacheBackend` — `crates/aos-cache/src/backend/mod.rs:36`,
  with `put_narinfo` (`:61`), `put_nar` (`:78`), `put_cache_info` (`:104`),
  `put_static_file` (`:117`); constructor `from_url` (`:327`); `AuthOptions`
  (`:173`). Implemented in `backend/{fs,http,s3,sftp}.rs`. There is **no**
  existence/`HEAD` method today; `validate_cache_entry` reaches for a raw HTTP
  client instead (`registry_ops.rs:3979`).
- Scope path helpers — `ProfileScope` (`types.rs:1003`): `nar_cache_path`
  (`types.rs:1058` → `~/.cache/apm` user / `/var/lib/apm/cache` system),
  `registries_path` (`types.rs:1118`), `writable_config_dir` (`types.rs:1110`).
  `ApmConfig` wrappers at `config.rs:320`/`config.rs:325`.

---

## 3. Goals and non-goals

### 3.1 Goals

1. **Transactional unit.** Generate → upload → advertise become one all-or-nothing
   step. A release never advertises a cache it did not publish, never publishes
   narinfos it did not upload, and never leaves a destination missing a
   referenced NAR.
2. **Internal caching.** The caller never passes `--cache-output`. `apr` stages
   cache files under a scope-aware platform cache directory, reuses them across
   releases, and garbage-collects them by age.
3. **Reject incoherence.** Every contradictory flag combination is rejected with
   an actionable message before any mutation or network call.
4. **Do the minimum work.** Existence is checked against the remote as early as
   possible — before dumping or compressing a NAR — so already-published paths
   cost nothing. The remote is the source of truth; **no local manifest of
   published paths is kept.**

### 3.2 Non-goals

- No binary-cache *index* protocol (e.g. RFC 0195 HLSSI). Existence checks are
  per-path `HEAD`s in this work, behind an abstraction that a future index
  implementation can replace (§14).
- No change to the consumer substitution path, `apr validate`
  (`registry_ops.rs`), pack/delta generation, channel partition math, or tag
  signing semantics.
- No change to where registry clones, NAR download caches, or profiles live.

---

## 4. Design principles

### 4.1 Publishing is the trigger

The honest signal for "this release ships substitutable artifacts" is **the
presence of resolved upload destinations** — `--upload-url` flags or the
`upload_urls` persisted by `apr origin config`, as already resolved by
`resolve_upload_urls` (`registry_ops.rs`, used at `release` build-up). Define:

- **publishing** ⇔ the resolved upload-destination list is non-empty.

When publishing, the cache is generated, uploaded, and advertised as one unit.
When not publishing, the release is a local tag + packs operation only, and all
cache flags are rejected (§5.3). This replaces three independent gates with one.

### 4.2 The remote is the source of truth

Whether a path is already published is answered by querying the destinations,
not by consulting local state. This keeps `apr` stateless with respect to
publication history and makes correctness robust to a wiped staging directory,
a fresh checkout, or a second producer machine.

### 4.3 The staging directory is disposable

Because the remote is authoritative, the local staging directory is a pure
performance cache: deleting any entry can only cost a re-compression, never
correctness or availability. This is what makes age-based GC sufficient and
makes reachability/store-presence GC unnecessary (§6.4).

---

## 5. The cache decision model

### 5.1 Inputs

- `has_store_paths` — the registry references ≥1 store path
  (`collect_store_paths` non-empty, `nixcache.rs:596`).
- `publishing` — resolved upload destinations non-empty (§4.1).
- `cache_url` — explicit public read URL (`--cache-url`).
- `cache_key` — explicit narinfo signing key (`--cache-key`).

### 5.2 Decision table

| `has_store_paths` | `publishing` | Action |
|---|---|---|
| yes | yes | Generate (with skip), upload cache + origin, advertise `[[caches]]`. The full transactional unit. |
| no  | yes | Upload origin only (packs/refs/channels). No narinfos, no `[[caches]]` pointer. `--cache-url`/`--cache-key` ⇒ **reject** (§5.3.4). |
| any | no  | Local tag + packs only. Any of `--cache-url`/`--cache-key`/`--cache-priority` ⇒ **reject** (§5.3.1–§5.3.3). |

"Generate (with skip)" never re-creates or re-uploads a path already present on
all destinations (§7). The `[[caches]]` pointer is committed **iff** at least
one narinfo is present on the destinations after the upload step completes
(freshly uploaded or pre-existing).

### 5.3 Rejected invocations

Validation runs in `validate_release_options` (`registry_ops.rs:7643`) **before**
the release lock is taken and before any mutation. The existing
`--cache-key requires --cache-output` check (`registry_ops.rs:7668`) is removed
(the flag it referenced no longer exists) and replaced by:

1. **`--cache-url` without publishing.**
   > `--cache-url advertises a published cache; it requires an upload destination (--upload-url, or a default persisted by 'apr origin config')`

2. **`--cache-key` without publishing.**
   > `--cache-key signs published narinfos; it requires an upload destination`

3. **`--cache-priority` set without publishing.** Same shape as (1). (Detected
   only when explicitly provided; the value defaults to `40` at `lib.rs:929`,
   so use a `0`/`Option` sentinel or clap's `value_source` to distinguish an
   explicit `--cache-priority` from the default.)

4. **Publishing with store paths but no derivable public URL.** When publishing
   and `cache_url` is absent, `apr` derives the public read URL from the upload
   destinations (§5.4). If it cannot, reject:
   > `cannot derive a public cache URL from upload destination '<dest>'; pass --cache-url <https://…> to advertise where consumers fetch NARs`

5. **Channel selectors without a channel.** Unchanged from today:
   `--init-channel`, `--count`, `--partitions` without `--channel`
   (`registry_ops.rs:7644`–`7665`). Retain verbatim.

`--no-skip` (§7.6) is always valid.

### 5.4 Deriving the advertised cache URL

When publishing and `--cache-url` is omitted, the `[[caches]]` URL is derived
from the upload destinations:

- Exactly one destination, and its scheme is `http`/`https` → advertise that
  URL.
- Otherwise (a write-only scheme such as `s3://` or `sftp://`, or more than one
  destination) → no automatic derivation; `--cache-url` is required (§5.3.4).

This keeps the common single-HTTP-origin case zero-config while making the
"write to S3, read through a CDN" case explicit rather than silently wrong.

---

## 6. Internal cache staging directory

### 6.1 Location

Add a scope-aware helper beside the existing cache paths:

- `ProfileScope::registry_cache_path(&self, registry: &str) -> PathBuf`
  immediately after `registries_path` (`types.rs:1118`), returning
  `self.nar_cache_path().join("registry-static").join(registry)`.
  - **User scope:** `~/.cache/apm/registry-static/<registry>` (XDG via
    `xdg_cache_home`, `types.rs:1060`).
  - **System scope:** `/var/lib/apm/cache/registry-static/<registry>`
    (`apm_state_dir`, `types.rs:1061`).
- `ApmConfig::registry_cache_path(&self, registry)` wrapper beside
  `config.rs:325`.

**Load-bearing choices.** The directory is rooted at `nar_cache_path` because
that is already the scope's "regenerable bytes" location (the consumer NAR
download cache lives there too), is XDG-respecting for user scope, and is on the
persisted `/var/lib/apm` tree for system scope. The `registry-static/`
infix keeps producer staging clearly separate from the consumer NAR cache that
shares the parent. The per-registry leaf preserves the one-`StoreDir`-per-cache
invariant (`common_store_dir`, `nixcache.rs:615`) and prevents cross-registry
collisions.

### 6.2 Lifecycle

- The directory persists across releases. Content-addressed reuse
  (`nixcache.rs:158`) makes a warm directory cheap to re-run and lets an
  interrupted release resume without recompressing (`--resume`).
- It is never required for correctness: the authoritative copies live at the
  upload destinations (§4.2). It may be deleted at any time; the next release
  regenerates only what the remote is missing.

### 6.3 Garbage collection

- **Trigger.** After a successful `release` and after a successful `apr cache
  generate`, run GC over the registry's staging directory. GC failure is
  non-fatal: it warns and does not fail the release.
- **Policy.** Remove each staged `<hash>.narinfo` / `nar/<name>` pair whose
  modification time is older than a retention window (default **30 days**).
  Every staged entry that participates in the current release — freshly written
  **or** reused/skipped — has its mtime bumped, so the window measures "time
  since last referenced by a release" (an LRU-by-last-use eviction).
- **Explicit command.** Add `CacheCommand::Gc` beside `CacheCommand::Generate`
  (`lib.rs:1022`): `apr cache gc [--registry <name>] [--max-age <days>]
  [--dry-run]`. Default `--max-age` from `[registry.cache] max_age_days` when
  present, else 30.

### 6.4 Why age, and not reachability or store presence

With the remote authoritative and existence checked before work (§7), the
staging directory never gates re-publication: anything evicted is either already
on the remote (so it is skipped, never regenerated) or trivially recompressed if
genuinely new. Therefore:

- **Reachability GC is unnecessary** — keeping a still-referenced path locally
  buys nothing once it is on the remote.
- **Store-presence is the wrong key** — a path absent from `/nix/store` may
  still be the current advertisement (keep it), and a path present in
  `/nix/store` may be wholly unreferenced (no reason to keep it). Store presence
  is at most a diagnostic ("can this still be regenerated locally?") and never
  drives deletion. This work adds no command for it.

Age alone bounds disk while never costing correctness.

---

## 7. Existence checks and early skip

### 7.1 The narinfo key is free

A store path `…/<hash>-<name>` maps to the narinfo object `<hash>.narinfo`
purely by string — no store access — exactly as
`collect_cache_validation_entries` already derives it
(`registry_ops.rs:3703`) and `validate_cache_entry` already probes it
(`registry_ops.rs:3979`). Existence can therefore be checked before any
`nix path-info` or `nix-store --dump`.

### 7.2 Backend `exists` op

Add to `CacheBackend` (`crates/aos-cache/src/backend/mod.rs:36`), beside the
`put_*` methods:

```text
async fn exists(&self, key: &str) -> Result<bool>;
```

`key` is an object path relative to the cache root (e.g. `"<hash>.narinfo"` or
`"nar/<name>"`). Implement per backend alongside the existing `put_*` impls:

- `http.rs` (`put_*` from `:207`): HTTP `HEAD`; `200`→true, `404`→false, other
  status→error.
- `s3.rs` (`:67`): `HEAD`-object; `NotFound`→false.
- `sftp.rs` (`:79`): `stat`; absent→false.
- `fs.rs` (`:67`): `Path::try_exists`.

### 7.3 The membership abstraction

Introduce a small trait so the call sites never bake in "one HEAD per path":

```text
enum Membership { Present, Absent }
trait CacheMembership { async fn narinfo(&self, store_hash: &str) -> Result<Membership>; }
```

v1 implementation `HeadMembership` wraps the resolved destination backends and
answers `Present` **iff** the `<hash>.narinfo` object exists on **every**
destination (an absence on any one destination means that destination still
needs the upload). Checks run concurrently through the existing connection pool.
§14 replaces this implementation without touching callers.

### 7.4 Root-level early-out (no store access)

Generation is restructured so the closure is expanded lazily:

1. Collect roots from `packages/*.toml` only (split the root-gathering half of
   `collect_store_paths`, `nixcache.rs:596`, into `collect_store_roots`).
2. For each root, `membership.narinfo(root_hash)`. A `Present` root ⇒ its whole
   closure was published by a prior release (guaranteed by the ordering
   invariant, §8) ⇒ **skip the entire subtree**: no `nix-store -qR`, no store
   access, no dump, no upload. This is what lets a release re-ship versions
   whose store paths were since GC'd from `/nix/store`.
3. Expand closures only for `Absent` roots.

### 7.5 Per-member skip

For the closures of `Absent` roots, check each member's narinfo before the
dump/compress in Phase B (`nixcache.rs:192`). `Present` members are skipped
(not dumped, not compressed, not uploaded); `Absent` members are generated and
uploaded. Shared dependencies a prior release already pushed cost one `HEAD`
each, not a re-compression.

### 7.6 `--no-skip`

`apr release --no-skip` (and `apr cache generate --no-skip`) bypasses
§7.4–§7.5 entirely: every closure path is regenerated and re-uploaded. This is
the repair/reseed path for a destination whose contents predate the ordering
invariant or are otherwise suspect. `generate_static_cache` receives the
membership checker as `Option<&dyn CacheMembership>`; `--no-skip` (and the
not-publishing case) passes `None`.

---

## 8. Required write-ordering invariant

The root-level early-out (§7.4) is correct **iff** a present root narinfo
implies its full closure is present on that destination. The pipeline MUST
establish this on the write side:

- **Per destination, per release:** upload all NARs, then all member narinfos,
  with the root narinfo(s) last. Only after every NAR and member narinfo is
  acknowledged may a root narinfo be `PUT`.

Today the dedicated cache upload already does NARs-before-narinfos
(`upload_static_cache`, `nixcache.rs:428`–`444`), but the release path uploads
through `collect_static_origin_files`, which classes narinfos and NARs together
as `Immutable` and orders them by path string (`static_upload.rs:106`–`124`,
`StaticOriginClass` at `static_upload.rs:40`). The release upload MUST be
changed so that, within a destination, NAR payloads precede member narinfos and
root narinfos are written last, preserving the producer-safe
immutable-before-mutable guarantee already documented for that module
(`static_upload.rs:1`–`13`).

Because every release upload obeys this ordering, a root narinfo can only be
present if its closure was fully uploaded, making §7.4 sound for any cache this
pipeline has ever written.

---

## 9. Transactional release execution

`release_registry_tree` (`registry_ops.rs:7510`) is restructured so the cache
steps are one unit gated by `publishing` (§4.1). The ordered body, under the
existing `ReleaseLock` (`registry_ops.rs:7336`):

1. `validate_release_options` (§5.3) — reject incoherent flags. **Before the
   lock**, as today.
2. Acquire lock; assert sha256 object format; ensure clean worktree
   (unchanged, `registry_ops.rs:7532`–`7534`).
3. Create the signed release tag (or reuse under `--resume`);
   refresh the object store (unchanged, `registry_ops.rs:7555`–`7556`).
4. Write release pack artifacts; refresh the object store (unchanged,
   `registry_ops.rs:7558`–`7560`).
5. **If `publishing` and `has_store_paths`** (the new unit):
   1. Build `HeadMembership` over the resolved destinations (§7.3).
   2. `generate_static_cache` into the internal staging dir (§6.1) with the
      membership checker (§7.4–§7.5), unless `--no-skip`.
   3. Upload the static origin **and** the staged cache files to every
      destination in the §8 order. Per-destination, skip `PUT`s for objects the
      destination already has (using `exists`, §7.2).
   4. Resolve the advertised cache URL (§5.4); `upsert_registry_cache`
      (`nixcache.rs:548`) and commit the pointer **only now**, after uploads
      succeeded and only if ≥1 narinfo is present on the destinations.
6. **Else if `publishing`** (no store paths): upload the origin only; no
   narinfos, no pointer.
7. Channel init/advance, if `--channel` (unchanged,
   `registry_ops.rs:7587`–`7609`).
8. Run staging GC (§6.3); warn on failure.
9. Emit the report / JSON (extended per §11.4).

The key inversion versus today: the `[[caches]]` pointer commit
(`registry_ops.rs:7537`) moves from the **top** of the body (before tag and
generation) to **after** a successful upload, so the registry can never
advertise a cache that was not published.

---

## 10. CLI surface changes

### 10.1 `apr release` (`lib.rs:854`)

- **Remove** `--cache-output` (`lib.rs:920`). Staging is internal (§6.1).
- **Keep** `--cache-key` (`lib.rs:923`) — narinfo signing key for the internal
  generation. Valid only when publishing (§5.3.2).
- **Keep** `--cache-url` (`lib.rs:926`) — redefined as the **public read URL**
  advertised in `[[caches]]`; derived when omitted (§5.4); valid only when
  publishing (§5.3.1).
- **Keep** `--cache-priority` (`lib.rs:929`); valid only when publishing
  (§5.3.3).
- **Add** `--no-skip` (§7.6).
- **Keep** `--upload-url`, `--jobs`, `--resume`, `--dry-run`, channel flags,
  `--store-path` and its metadata flags.

### 10.2 `apr cache generate` (`lib.rs:1022`)

- Make `--output` **optional** (`lib.rs:126`), defaulting to the internal
  staging dir (§6.1). An explicit `--output` remains honored for ad-hoc local
  generation.
- **Add** `--no-skip` and, when `--upload-url` is supplied, the same membership
  skip and per-destination upload skip (§7).
- Behavior is otherwise unchanged: this remains the low-level primitive; only
  `release` ties caching to publishing.

### 10.3 `apr cache gc` (new)

`apr cache gc [--registry <name>] [--max-age <days>] [--dry-run]` (§6.3).

### 10.4 Help-text rule

Per the workspace clap convention, the edited field doc comments are
user-facing CLI text. Keep them short and imperative; do not add container docs
to the `Release`/`CacheCommand` enums.

---

## 11. Implementation map

### 11.1 `crates/aos-cache`

- `backend/mod.rs:36` — add `exists` to `CacheBackend` (§7.2).
- `backend/{http,s3,sftp,fs}.rs` — implement `exists` beside each `put_*`.

### 11.2 `crates/aos-package` — generation

- `nixcache.rs:596` — split `collect_store_paths` into `collect_store_roots`
  (TOML only) + closure expansion, so roots can be checked before expansion
  (§7.4).
- `nixcache.rs:109` — `generate_static_cache` gains
  `membership: Option<&dyn CacheMembership>`; applies root-level (§7.4) and
  per-member (§7.5) skipping; bumps mtime on reused entries (§6.3). The empty
  bail (`nixcache.rs:119`) is retained for the standalone command but the
  release path checks `has_store_paths` first (§5.2) so it never reaches it.
- New `CacheMembership` trait + `HeadMembership` impl (§7.3), in a new
  `crates/aos-package/src/registry/membership.rs`.

### 11.3 `crates/aos-package` — upload

- `static_upload.rs:84`/`:187` — enforce the §8 ordering (NARs → member
  narinfos → root narinfos) and add per-destination `exists`-based `PUT`
  skipping.
- `nixcache.rs:415` — `upload_static_cache` gains per-destination `PUT`
  skipping (it already orders NARs first).

### 11.4 `crates/aos-package` — release orchestration

- `registry_ops.rs:7281` — `ReleaseTreeOptions`: replace
  `cache_output: Option<PathBuf>` with `cache_dir: PathBuf` (always the internal
  staging dir, computed by `release` from
  `config.scope.registry_cache_path(&registry_name)`); add `no_skip: bool`. The
  publishing gate is `!upload_urls.is_empty()`.
- `registry_ops.rs:7383` — `release(…)`: drop the `cache_output` parameter;
  compute `cache_dir`; pass `no_skip`.
- `registry_ops.rs:7510` — `release_registry_tree`: restructure per §9; move the
  pointer commit after upload.
- `registry_ops.rs:7643` — `validate_release_options`: remove the
  `--cache-key requires --cache-output` check (`:7668`); add §5.3 rules.
- `registry_ops.rs:7673`/`:7726`/`:7751` — update `release_result_json`,
  `release_plan_steps_json`, and `print_release_plan` so the plan reflects the
  single unit (no independent `commit_cache_pointer` step ahead of the tag;
  `generate_static_cache` + `upload` + `advertise` shown together and only when
  publishing).
- `registry_ops.rs:4774` — `run_cache`: default `output` to the staging dir;
  thread `no_skip` and membership; add the `Gc` arm.

### 11.5 `crates/aos-package` — scope & config

- `types.rs:1118` — add `ProfileScope::registry_cache_path`.
- `config.rs:325` — add the `ApmConfig` wrapper.
- Optional `[registry.cache] max_age_days` config field for §6.3 default.

---

## 12. Behavioral invariants (acceptance criteria)

A correct implementation guarantees, for every `apr release` run:

1. The registry's `[[caches]]` advertises a URL **only if** that release left
   ≥1 narinfo present on the advertised destination.
2. After a successful publishing release, every store path the registry
   references has its `<hash>.narinfo` and NAR present on **every** upload
   destination.
3. No store path already present on all destinations is dumped, compressed, or
   re-uploaded (absent `--no-skip`).
4. A version whose store paths were GC'd from `/nix/store` can still be
   re-shipped, provided it was published before (via §7.4).
5. The caller never names a cache directory; no cache files are written outside
   the scope's `registry-static/<registry>/` staging tree.
6. Every incoherent flag combination in §5.3 fails before the release lock is
   taken, with no partial mutation.
7. The staging directory can be deleted between releases with no effect on
   published output beyond recompression cost.

---

## 13. Testing

- **Unit.** `validate_release_options` rejects each §5.3 case; URL derivation
  (§5.4) for single-HTTP, S3, SFTP, and multi-destination inputs; mtime-based
  GC selection (§6.3); `HeadMembership` all-present vs any-absent.
- **Backend.** `exists` against `fs`/`http`/`s3`/`sftp` for present and absent
  objects (mirror the existing `upload_static_cache_to_all` filesystem tests,
  `nixcache.rs` test module).
- **Integration.** Extend the end-to-end suite `crates/aos/tests/apr_cache_cli.rs`:
  1. publishing release → narinfos + NARs at the destination, pointer committed,
     consumer-visible;
  2. second release of an overlapping closure → only new paths transferred
     (assert skip counts in the report);
  3. `--cache-url` without `--upload-url` → rejected;
  4. publishing release with the destination's NARs pre-deleted but root present
     → §7.4 skips, then `--no-skip` repairs;
  5. non-publishing release → tag + packs only, no pointer, cache flags
     rejected.

All test tooling uses AOS-built binaries per the repo build principles; no host
or nixpkgs tools.

---

## 14. Out of scope: cache-index acceleration

The per-path `HEAD` model (§7) is deliberately confined behind the
`CacheMembership` trait (§7.3) so it can be replaced wholesale by a downloaded
membership index — e.g. the sharded exact-membership index plus append-only
journal proposed in nixpkgs RFC 0195 (HLSSI). Under that model, `narinfo(hash)`
is answered from one bulk index fetched once and queried locally, collapsing N
round-trips into a few cacheable requests, with per-prefix partial download for
a single closure. Two properties of this design make it forward-compatible:

- The producer already serializes publishers per registry via `ReleaseLock`
  (`registry_ops.rs:7336`), which is exactly the single-writer point such an
  index's journal requires.
- The §8 write-ordering invariant is the producer-side discipline (“record
  membership only after the artifacts are durable”) that an index would build
  on.

Adopting an index is future work and changes only the `CacheMembership`
implementation; the orchestration, CLI, staging, and GC in this specification do
not change.
