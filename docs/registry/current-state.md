# AOS Registry — Current State (As-Is)

> **Status:** Reference / as-built. This document describes the registry
> **exactly as the code implements it today**, grounded in source with
> `path:line` citations. Where the implementation diverges from the
> [design brief](../plans/registry/design-brief.md), the **code wins** and the
> divergence is recorded explicitly (see [Discrepancies](#11-discrepancies-vs-the-design-brief)).
>
> For the **target** design (a git-native registry served over dumb HTTP —
> channels-as-branches, 256-partition rollouts, signed tag objects, thin delta
> packs, Nix-cache superset), see [`architecture.md`](architecture.md),
> [`http-layout.md`](http-layout.md),
> [`versioning-and-channels.md`](versioning-and-channels.md), and
> [`packs-and-deltas.md`](packs-and-deltas.md). For *what must change* to get
> there, see [`gap-analysis.md`](../plans/registry/gap-analysis.md) and the
> workstreams.
>
> **Audience:** users, implementers, architects, engineers.

All paths are relative to the repo root. Source crate is
`crates/aos-package/` unless noted. Citations point at the code as it exists at
the time of writing; line numbers may drift as the tree changes.

---

## 1. What the registry is, today

An AOS registry is a **git repository of TOML metadata** — *not* a blob store.
It carries per-package metadata (`packages/…`) and precomputed dependency
closures (`closures/…`). It is distributed over **dumb HTTP** as **git bundles**
(packed git objects) and consumed by the `apm` client, which unbundles them into
a local bare-git cache and extracts the TOMLs.

The actual build artifacts — **NARs** (zstd-compressed serialized store paths) —
live on a **separate cache/mirror**, addressed by content hash. The registry
metadata records each NAR's hashes and sizes; the client downloads NARs from the
mirror and verifies them by **SHA-256 content hash**.

```
            ┌───────────────────────────────────────────────────────┐
            │  REGISTRY ORIGIN (dumb HTTP)                            │
            │  {base}/bundles/{name}/bundle-list.toml   ← manifest    │
            │  {base}/bundles/{name}/<uri>.bundle       ← git bundles │
            └───────────────────────────────────────────────────────┘
                         │  apm update: fetch manifest → pick bundles →
                         │  download → SHA-256 + `git bundle verify` →
                         │  `git bundle unbundle` → extract TOMLs
                         ▼
            ┌───────────────────────────────────────────────────────┐
            │  CONSUMER (apm)                                         │
            │  remote cache  (extracted TOMLs)                       │
            │  registries/   (bare git repo)                         │
            │  [registry.state] persisted in registries.d/{name}.toml│
            └───────────────────────────────────────────────────────┘
                         │  resolve closures → build NAR download list
                         ▼
            ┌───────────────────────────────────────────────────────┐
            │  NAR MIRROR (separate origin; `[[caches]]` or {url}/nar)│
            │  {mirror}/<sha256:hex>.nar.zst   ← content-addressed   │
            └───────────────────────────────────────────────────────┘
```

The **consumer side is rich** (parse manifest, semver selection, incremental
delta selection, downgrade defense, signature verification). The **producer side
is a thin wrapper over `git` + `git bundle create`** with significant gaps — see
[§9 Producer-side gaps](#9-producer-side-gaps-the-asymmetry).

> **CURRENT vs TARGET.** Today the registry is distributed as **git bundles** +
> a `bundle-list.toml` manifest, and there is **no** producer-side
> (`apr`) manifest writer. The narinfo **format + sign + FileHash logic**
> (`NarInfo`, `format_narinfo`, `NarInfoSigner`, `compute_file_hash_size`) already
> exists — but it lives *outside* `aos-package`, in `aos-server` / `aos-core`, as
> part of a **live, store-DB-backed cache server** (`aos-server`, a nix-serve-style
> host serving its *own* Nix store). The **consumer** side is already narinfo-driven
> (`aos-package`'s NAR downloader). What does **not** exist yet is the **producer**:
> ahead-of-time generation of static `nix-cache-info` / `*.narinfo` / `nar/` files
> for the registry's own store paths. The target registry **runs no server** — it
> *reuses* that format/sign logic as a library to emit dumb static CDN files (see
> [§6.1, *The Nix-cache / narinfo logic exists as a reusable library*](#61-the-nix-cache--narinfo-logic-exists-as-a-reusable-library-current)).
> The root file
> `registry.toml` that *does* exist is a small repo-local config (`[registry]`,
> `[[caches]]`, `[signing]`) — see [§3.1](#31-the-repo-local-registrytoml). The
> **target** drops bundles and `bundle-list.toml` in favor of a bare git repo
> served over dumb HTTP, with channel/releases pointers carried by signed git
> tag objects — pure signed pointers with no structured payload (see
> [`architecture.md`](architecture.md), TARGET). The git-repo-root
> `registry.toml` is **kept** (it is a committed tree file, authenticated
> transitively by the signed tag), but its `[signing].public_key` is **removed**
> and a new committed `keys.toml` trust roster is added — see
> [§3.1](#31-the-repo-local-registrytoml) and
> [`repo-layout.md`](repo-layout.md), TARGET.

---

## 2. CLI dispatch (`aos` / `apm` / `apr`)

One binary, three entry points selected by `argv[0]`:

- `crates/aos/Cargo.toml` declares two `[[bin]]` targets, `aos` and `apr`, both
  `path = "src/main.rs"` (`crates/aos/Cargo.toml:6-12`). The `apm` name is an
  install-time alias of the same binary.
- `main.rs` inspects `argv[0]`'s file name, tolerating a leading `.` and a
  trailing `-unwrapped` suffix (so wrapper scripts that
  `exec .apm-unwrapped` still resolve correctly), then rewrites the argument
  vector (`crates/aos/src/main.rs:37-68`):
  - `apr` ⇒ insert `package registry` before the user's args.
  - `apm` ⇒ insert `package` before the user's args.
  - anything else ⇒ parse argv as-is.

| Invocation | Effective command |
|---|---|
| `apr tag v2026.02` | `aos package registry tag v2026.02` |
| `apm update`       | `aos package update` |
| `aos package …`    | (literal) |

All **registry producer logic** lives in
`crates/aos-package/src/registry_ops.rs` — module doc line 1:
*"Registry management operations (`apr` / `apm registry`)."*

---

## 3. Storage layout (local)

Resolved from `types.rs` `ProfileScope` (`types.rs:442-514`) and
`registry_ops.rs` `registry_dir` (`registry_ops.rs:26-29`).

| Concern | User scope | System scope |
|---|---|---|
| Producer git repo (`apr` writes) — `registries_path()` | `~/.local/share/apm/registries/{name}/` | `/var/lib/apm/registries/{name}/` |
| Consumer extracted-TOML cache (`apm update` writes) — `cache_path()` | `~/.local/share/apm/remote/` | `/var/lib/apm/remote/` |
| NAR download cache — `nar_cache_path()` | `~/.cache/apm/` | `/var/lib/apm/cache/` |
| Registry config files — `config_dir()` | `~/.config/apm/` | `/etc/apm/` |
| Trusted keys — `trusted_keys_dirs()` | `~/.config/apm/trusted-keys.d/`, then `/etc/apm/trusted-keys.d/` | `/etc/apm/trusted-keys.d/`, then `/var/lib/apm/trusted-keys.d/` |

Notes:

- **Producer and consumer git repos are distinct trees.** `registries_path()`
  is used both as the `apr` working repo and as the `apm update` bare-git cache
  destination, but for HTTP-bundle registries the bare cache is keyed per
  registry under `registries/{name}/`. The extracted TOMLs land separately under
  `remote/`.
- Per-registry config: `registries.d/{name}.toml` under `config_dir()`.
- `resolve_home()` (`types.rs:24-36`) reads `$HOME`, warning and falling back to
  `/tmp` if unset.

### 3.1 The repo-local `registry.toml`

This file lives **inside** the registry git repo — it is a **committed tree
file**, parsed by `RegistryRootConfig` (`types.rs:564-568`). It is *not* the
removed intermediate signed-HTTP-root `registry.toml` (a mutable origin file
carrying `[latest]`/`[channels]`/`[components]`/`[capabilities]`/`[[bundles]]`/
`[signature]`); that intermediate file never existed in the code and is gone
from the target. The committed file now carries `[registry]` + `[[caches]]`:

```toml
[registry]
name = "aos-core"
description = "AOS core packages"

# Optional NAR mirrors, highest priority first (see §6).
[[caches]]
url = "https://cache.aos.dev/nar"
priority = 100
```

- `[[caches]]` each carry `url` + `priority` (`CacheEntry`, default priority
  `100`, `types.rs:582-586`).
- The previous in-tree signing pubkey field was removed from
  `RegistryRootConfig`; trust bootstrap is client-side TOFU, and committed
  `keys.toml` carries the target rotation/revocation roster.

> The `[[caches]]` NAR-cache pointers **stay in this committed `registry.toml`**
> (authenticated via the tag), *not* in the signed tags (which carry **no**
> structured payload — no `[meta]`, no `[[caches]]`) and *not* solely
> client-side; the consumer's `registries.d/<name>.toml` is an optional
> override/supplement (higher priority wins). An authenticated-but-wrong cache
> pointer still can't serve bad bytes — NARs are content-addressed and SHA-256
> verified (§6), so the trust that matters is the tag/commit chain governed by
> `keys.toml`. The committed **tree** is `registry.toml` + `keys.toml` +
> `packages/<x>/<name>.toml` + `closures/<hash>` + `.gitattributes`, distinct
> from the served object store — see [`repo-layout.md`](repo-layout.md), TARGET,
> for the full tree and the Nix binary-cache superset
> ([`nix-cache-compatibility.md`](nix-cache-compatibility.md), TARGET).

---

## 4. Registry git repo contents

### 4.1 `packages/<…>/<name>.toml` — per-package, per-platform metadata

The **on-disk** package TOML is a **nested** document:

```toml
[package]                                  # PackageHeader
name = "hello"
description = "GNU Hello"
# homepage = "https://…"                   # optional
license = "GPL-3.0-or-later"
maintainer = "aos-core"
# sysroot = true                           # system toplevel marker (default false)

[[versions]]                               # VersionEntry (one per version)
version = "2.12.1"
# previous = "2.12"                        # optional; previous version in the chain (sysroot)

[versions.platforms.x86_64-linux]          # PlatformEntry (one per platform)
store_path = "/nix/store/…-hello-2.12.1"
nar_hash = "sha256:…"
nar_size = 226880
download_hash = "sha256:…"
download_size = 71204
closure_size = 31250000
source_drv = "/nix/store/…-hello-2.12.1.drv"
source_nar_hash = "sha256:…"
references = ["…", "…"]
# images = [ … ]                           # sysroot only
```

This nested `[package]` / `[[versions]]` / `[versions.platforms.<platform>]`
shape is what the code deserializes (`PackageToml` / `PackageHeader` /
`VersionEntry` / `PlatformEntry`, `registry/parse.rs:14-66`) and what the
producer **writes** (`build_package_toml`, `registry_ops.rs:595-769`). It
matches the nested sketch in the design brief §2.3 — there is **no**
flat-vs-nested divergence.

`PackageMeta` (`types.rs:44-74`) is **not** the on-disk type. It is the
**flattened, in-memory projection** of one (package, platform) pair, produced by
`parse_package_toml` (`registry/parse.rs:129-170`), which walks the nested TOML,
selects the first (latest) version carrying the requested platform, and hoists
the header/version/platform fields into a single flat record. The table below
lists **`PackageMeta`'s flattened fields**:

| Field (`PackageMeta`) | Type | Meaning |
|---|---|---|
| `name` | string | package name |
| `version` | string | version |
| `description` | string | |
| `homepage` | string? | optional |
| `license` | string | |
| `maintainer` | string | |
| `platform` | string | e.g. `x86_64-linux` |
| `store_path` | string | the Nix store path |
| `nar_hash` | string `"sha256:…"` | hash of the **uncompressed** NAR |
| `nar_size` | u64 | uncompressed size |
| `download_hash` | string `"sha256:…"` | hash of the **compressed** `.nar.zst` |
| `download_size` | u64 | compressed size |
| `references` | list of strings | direct runtime references (store-path **hashes**) |
| `source_drv` | string | source derivation store path |
| `source_nar_hash` | string | hash of the source-derivation NAR |
| `closure_size` | u64 | total NAR size of the full closure |
| `sysroot` | bool (default false) | system toplevel marker |
| `previous` | string? | previous version in the chain (sysroot) |
| `images` | list of `SysrootImageEntry` | pre-compiled images (sysroot only) |

`SysrootImageEntry` (`types.rs:604-609`) carries `format`, `store_path`,
`nar_hash`, `nar_size`.

> **TARGET note.** The redesign keeps this nested package-TOML **tree content**
> unchanged — the package metadata *is* the git tree, consumed by both `apm` and
> stock `git clone`. What changes is everything *around* it (distribution,
> rollout, signing surface). The earlier `[components]`/component-grouping idea is
> **removed** from the target (see
> [`architecture.md`](architecture.md), TARGET).

### 4.2 `closures/<hash>` — adjacency-list closures

Parsed by `ClosureMeta::parse` (`types.rs:109-132`). The file is an adjacency
list, one line per store path, first token = node, remaining tokens = its direct
dependency hashes; the first line is the root. Blank lines and `#` comments are
skipped.

```text
h7j3k8l2m9n4 r4q1m2kp8v3x xr5is7by89v3q   ← root + its direct deps
r4q1m2kp8v3x                              ← leaf (no deps)
xr5is7by89v3q q8mn2pv73w0x
q8mn2pv73w0x
```

`ClosureMeta` exposes `serialize()`, `direct_deps()`, `contains()`, and a
`members` list (self-inclusive, file order). This precomputed, **explicit
closure** model is what AOS uses instead of an APT-style `Depends` solver (see
[`apt-comparison.md`](apt-comparison.md)).

---

## 5. Bundle distribution over HTTP (consumer side)

Implemented in `crates/aos-package/src/registry/bundle.rs`.

### 5.1 Bundle and manifest types

- `BundleType { Snapshot, SequentialDelta, SkipDelta }` (`bundle.rs:22-31`).
- `BundleEntry { uri, creation_token, sha256, size, bundle_type, base_tag,
  target_tag }` (`bundle.rs:33-45`).
- `BundleManifest { registry, version, entries }` (`bundle.rs:47-53`).

The manifest is parsed from **`bundle-list.toml`**. The serde shapes
(`ManifestToml`, `ManifestHeader`, `BundleEntryToml`, `bundle.rs:59-92`) are
**`Deserialize`-only** — *there is no serializer*, which is the root of the
producer asymmetry (see [§9](#9-producer-side-gaps-the-asymmetry)).

`bundle-list.toml` wire shape (from the in-repo test fixture, `bundle.rs:431-497`):

```toml
[manifest]
registry = "aos-core"
version = 1
generated = "2026-02-15T12:00:00Z"   # optional, ignored on read

[[bundles]]                          # snapshot
tag = "v2026.02"
type = "snapshot"
uri = "aos-core-v2026.02.bundle"
creation_token = 2026020000
size = 153600
sha256 = "abc123"

[[bundles]]                          # delta (sequential or skip — see §5.4)
from_tag = "v2026.02"
to_tag = "v2026.02.1"
type = "delta"
uri = "aos-core-v2026.02..v2026.02.1.delta.bundle"
creation_token = 2026020001
size = 8192
sha256 = "def456"
```

On parse (`bundle.rs:124-178`): snapshots require `tag`; deltas require both
`from_tag` and `to_tag`; an unknown `type` is rejected; entries are sorted by
`creation_token` ascending.

### 5.2 HTTP transport

- `BundleManifest::fetch` (`bundle.rs:100-121`) builds the URL
  **`{base_url}/bundles/{registry_name}/bundle-list.toml`** and parses the body.
- `download_bundle` (`bundle.rs:251-300`) fetches
  **`{base_url}/bundles/{registry_name}/{entry.uri}`** with inline SHA-256
  verification via the transfer engine.
- `verify_bundle` (`bundle.rs:305-346`) performs **SHA-256 match** *and*
  `git bundle verify` (pack integrity + prerequisite presence). On failure it
  advises re-running `apm update` or `apm update --force`.
- `ensure_git_repo` (`bundle.rs:349-371`) `git init --bare`s the cache repo.
- `unbundle` (`bundle.rs:376-404`) runs `git bundle unbundle` into the cache.
- `resolve_tag` (`bundle.rs:407-421`) `git rev-parse refs/tags/<tag>`.

### 5.3 Manifest query helpers

`bundle.rs:180-224`:

| Helper | Behavior |
|---|---|
| `entries_since(token)` | entries with `creation_token > token` |
| `latest_snapshot()` | highest-token entry of type `Snapshot` |
| `skip_delta_from(base_tag)` | highest-token `SkipDelta` whose `base_tag` matches |
| `sequential_deltas_between(from, to)` | `SequentialDelta`s with `from < token <= to` |

### 5.4 Delta classification (read-time)

`classify_delta(from, _to)` (`bundle.rs:238-243`) inspects only the `from` tag:
strip a leading `v`, split on `.`; if `from` has **≤ 2** dotted segments
(a minor base like `v2026.02`) the delta is a **SkipDelta**, otherwise a
**SequentialDelta**. The `to` tag is unused in the decision.

---

## 6. NAR download (separate from the registry)

Implemented in `crates/aos-package/src/download.rs`.

- NAR/narinfo URLs are built by `join_cache_url(base, path)`
  (`download.rs:65-71`, trims a trailing `/` on base and a leading `/` on path)
  and `narinfo_url(mirror_url, store_path)` →
  **`{mirror_url}/{storeHash}.narinfo`** (`download.rs:74-77`). The NAR itself is
  fetched at `join_cache_url(mirror_url, narinfo.url)` — i.e. the relative path
  from the narinfo's `URL:` field (`download.rs:184`), not a colon-bearing
  `{nar_hash}.nar.zst` literal.
- `resolve_mirror` (`download.rs:85-97`) reads `[[caches]]` from the **local
  registry clone** via `registry_ops::resolve_mirrors` and returns the
  **first** entry; with no caches it falls back to **`{registry.url}`**.
- `resolve_mirrors` (`registry_ops.rs:405-414`) sorts the caches **descending by
  priority** (highest priority first), so "first" = highest priority. *(The
  brief §2.8 says "sorted by priority" without specifying direction; the code is
  descending — see [§11](#11-discrepancies-vs-the-design-brief).)*
- Downloads verify the **compressed** file against the narinfo `FileHash`
  (falling back to `NarHash` for uncompressed NARs) via
  `TransferRequest::with_hash(Sha256, …)` in `download_one`
  (`download.rs:191-204`); the local cache filename replaces the colon with a
  dash: `sha256-<hex>.nar.zst` (`nar_cache_filename`, `download.rs:314-317`).
- `download_nars` (`download.rs:246-307`) runs downloads in parallel under a
  semaphore (default 4, `parallel_downloads`), failing fast on first error.

**NARs are authenticated only by their SHA-256 content hash, not by a
signature.** Their integrity roots transitively in the signed git commit → TOML
→ recorded `download_hash`/`nar_hash` (see [§8](#8-signing--trust) and
[`signing-and-trust.md`](signing-and-trust.md)).

### 6.1 The Nix-cache / narinfo logic exists as a reusable library (CURRENT)

> **CURRENT.** The narinfo **format + sign + FileHash/FileSize logic** already
> exists in the tree (`NarInfo`, `format_narinfo`, `NarInfoSigner`,
> `compute_file_hash_size`). It is **not** greenfield. But it is important to be
> precise about *what* exists and what does not:
>
> - It exists today only as the engine of a **live cache server** — `aos-server`
>   is a **nix-serve-style host that dynamically serves its own Nix store**, one
>   request at a time, from the local store DB (`DbPathInfo` via
>   `state.store.path_info`). **The registry never runs this server.** The target
>   registry is dumb static files on a CDN (§13 of the
>   [design brief](../plans/registry/design-brief.md)) with **no process at
>   serve-time**.
> - The **consumer** is done: `aos-package`'s NAR downloader is already
>   narinfo-driven and consumes a *dumb static* narinfo cache as-is.
> - The **producer** does not exist yet: nothing in the tree generates the static
>   `nix-cache-info` / `*.narinfo` / `nar/<…>.nar.zst` files **for the registry's
>   own store paths** ahead-of-time and uploads them to a CDN. That is the real
>   remaining work (WS-06, §9.2) — and it **reuses** the format/sign logic below
>   *as a library*, rather than running `aos-server`.

**The shared narinfo type** — `aos_core::nar::info::NarInfo`
(`crates/aos-core/src/nar/info.rs:5-16`) carries
`{store_path, url, compression, file_hash, file_size, nar_hash, nar_size,
references, deriver, signatures}`, with `parse()` (`info.rs:19`),
`format()` (`info.rs:81`), and `store_hash()` / `basename()` helpers
(`info.rs:147-155`). This one type is shared by the cache server and the apm
consumer, and is the type a future producer would emit.

**The reusable formatting / signing logic** (today wired into `aos-server`'s live
cache, reusable by a static producer):

- `format_narinfo(&DbPathInfo, store_dir, &CompressionConfig, Option<&NarInfoSigner>)`
  (`crates/aos-server/src/narinfo.rs:27`) renders one path's metadata to narinfo
  text. The NAR URL is `nar/{store_hash}-{nar_hash with ':' → '-'}.{ext}`
  (`narinfo.rs:37`).
- **`FileHash`/`FileSize` are always emitted.** For `Compression: none` they
  equal `NarHash`/`NarSize`; for zstd/xz they are computed by
  `compute_file_hash_size` (`crates/aos-server/src/compress.rs:143`) over the
  actual compressed stream (`narinfo.rs:45-59`). The apm consumer requires both
  present (§6, `download.rs:191-198`), so the logic populates them
  unconditionally. A static producer can call `compute_file_hash_size` the same
  way, or capture the FileHash/FileSize at build time.
- **Ed25519 signing** — `NarInfoSigner` (`crates/aos-server/src/sign.rs`) with
  `load(key_file)` (`sign.rs:14`), `sign(fingerprint) → "name:base64"`
  (`sign.rs:44`), and `fingerprint(store_path, nar_hash, nar_size, refs)`
  (`sign.rs:57`) — emits the exact Nix narinfo fingerprint
  (`1;{store_path};{nar_hash};{nar_size};{refs}`) and `Sig:` line, reusing one
  Ed25519 key. `narinfo.rs:87-93` appends the `Sig`.
- **HTTP routes — these belong to the live server only.** The handlers at
  `crates/aos-server/src/routes.rs:80-89` — `/{view}/nix-cache-info`
  (`cache_info_handler`, `routes.rs:123`, advertising `Priority: 30` at
  `routes.rs:145`), `/{view}/{hash}.narinfo` (`narinfo_handler`,
  `routes.rs:157`, which reads from `state.store.path_info`), `/{view}/nar/{filename}`
  (`nar_handler`, `routes.rs:223`), plus `query-missing`, `store` upload,
  `build`, and `gc` — are the **live host-store server** (a different use case).
  **The registry does not run these handlers.** The producer reuses the
  `format_narinfo` / `NarInfoSigner` / `compute_file_hash_size` functions above
  (not the routes) to emit static files.

**The cache backends** — `aos-cache` carries `has_narinfo`/`get_narinfo`/
`put_narinfo` on every backend (`crates/aos-cache/src/backend/mod.rs:16-23`)
with S3, SFTP, HTTP, and FS implementations
(`crates/aos-cache/src/backend/{s3,sftp,http,fs}.rs`); backend-served
`nix-cache-info` advertises `Priority: 40` (`s3.rs:133`, `sftp.rs:143`).

**The consumer is already narinfo-driven** — `aos-package/src/download.rs`
(commit `7149acf6`) is built around `aos_core::nar::info`. `fetch_narinfos`
fetches the narinfo and `download_nars` consumes it; `DownloadRequest` carries
nothing but the store path + cache base, and `FileHash`/`NarHash`/`References`/
`Deriver` all come **from the fetched narinfo** (`download.rs:24-55`,
`191-233`). The narinfo URL is built by `narinfo_url(mirror_url, store_path)`
(`download.rs:74`); the NAR is then fetched from the narinfo's own `URL:` field.
This consumer works against **any** dumb static narinfo cache — it does not care
whether a server or a producer produced the files.

> **TARGET.** The registry's Nix binary cache is **dumb static files on the HTTP
> CDN, generated ahead-of-time at publish — no server at serve-time** (design
> brief §13). The producer (WS-06) **reuses** `format_narinfo` / `NarInfo` /
> `NarInfoSigner` / `compute_file_hash_size` as a **library** to generate, for each
> registry store path, a static `<storehash>.narinfo` (with `FileHash`/`FileSize`
> and an Ed25519 `Sig`), a `nar/<…>.nar.zst`, and a `nix-cache-info`, then
> **uploads** them to the CDN. The committed `registry.toml` `[[caches]]` points
> consumers at that static cache base (client-side `registries.d` is an optional
> override). The result is a **strict superset** of the Nix binary-cache protocol
> consumable by stock `nix` — without running `aos-server`. See
> [`nix-cache-compatibility.md`](nix-cache-compatibility.md), TARGET.

---

## 7. Versioning, tracking modes, and bundle selection (consumer)

### 7.1 Tracking modes

`TrackingMode { Commit, Branch, Tag, Version(semver::VersionReq), Default }`
(`types.rs:279-290`). `RegistryConfig::tracking_mode()` (`types.rs:349-397`)
validates that **at most one** of `commit`/`branch`/`tag`/`version` is set
(the legacy `pin` field merges into `tag`, `types.rs:227-229`, `351`), erroring
otherwise; with none set it returns `Default` (default-branch HEAD).

Transport is derived from the URL scheme (`RegistryConfig::transport`,
`types.rs:312-321`): `git://`, `git+https://`, `git+ssh://` ⇒ `Git`; everything
else (incl. `http(s)://`) ⇒ `HttpBundle`.

### 7.2 calendar-version ↔ creation_token

`crates/aos-package/src/registry/state.rs`:

- `version_to_token(tag)` (`state.rs:131-166`):
  `year*1_000_000 + month*10_000 + patch`. Rejects anything but
  `vYYYY.MM[.P]`, requires month `1..=12`, patch `≤ 9999`. Examples:
  `v2026.02` → `2026020000`, `v2026.02.3` → `2026020003`.
- `token_to_version(token)` (`state.rs:173-184`): inverse; patch `0` renders as a
  2-part base tag (`v2026.02`).
- `check_monotonic(old, new)` (`state.rs:104-117`): rejects `new <= old`
  (downgrade / stale-mirror defense). **Gap:** its only call site
  (`update.rs:291-292`) is gated by `if latest_token > old_token`, so a genuine
  downgrade (`latest <= old`) silently **skips** the guard entirely — the check
  only fires on the strictly-increasing path it would already accept (see
  [`versioning-and-channels.md`](versioning-and-channels.md) §8.4, TARGET).

### 7.3 Semver parsing of tags

`crates/aos-package/src/update.rs`:

- `parse_tag_as_semver(tag)` (`update.rs:456-477`): strip leading `v`, strip
  leading zeros per component, pad 2-component tags to `.0`.
  `v2026.02` → `2026.2.0`; `v2026.02.3` → `2026.2.3`. Non-semver tags → `None`.
- `find_best_version_tag_in_manifest(manifest, req)` (`update.rs:427-451`):
  filter manifest target tags by the `VersionReq`, return the **highest**
  matching; unparseable tags are silently skipped.
- `extract_minor_base(tag)` (`update.rs:483-491`): `v2026.02.3` → `v2026.02`.

### 7.4 `pick_bundles` — the incremental selection algorithm

`pick_bundles(manifest, reg_state, tracking_mode)` (`update.rs:319-418`):

```
1. Tag(tag)      → snapshot with target_tag == tag, else any entry targeting tag,
                   else error "tag not found".
2. Commit(_)     → bundle transport can't resolve arbitrary commits; falls
                   through to the incremental logic below.
3. Version(req)  → find_best_version_tag_in_manifest; then snapshot to it, else
                   the latest delta targeting it; error if no match.
4. Branch/Default→ incremental logic:
   4a. No prior creation_token in state → latest_snapshot() (error if none).
   4b. entries_since(current) empty     → [] (already up to date).
   4c. SkipDelta from extract_minor_base(current) with token > current → [skip].
   4d. else sequential_deltas_between(current, latest) if non-empty → chain.
   4e. else latest_snapshot() fallback (error if none).
```

### 7.5 Persisted state

`RegistryState { last_commit, last_creation_token, last_update }`
(`types.rs:251-259`), serialized under `[registry.state]` in the per-registry
config file. `load_state`/`save_state` (`state.rs:21-95`) preserve user-edited
fields and only replace/append the `[registry.state]` section. A successful sync
updates all three fields.

---

## 8. Signing & trust

Implemented in `crates/aos-package/src/security.rs`.

### 8.1 Commit-signature verification (SSH-format Ed25519)

`verify_commit_signature(repo, commit, expected_key)` (`security.rs:199-233`):
parses the expected key, writes a temporary `allowed_signers` file
(`registry ssh-ed25519 <pubkey>`), and runs
`git -c gpg.ssh.allowedSignersFile=… verify-commit <commit>`. Signatures are
**SSH-format Ed25519** git commit signatures.

### 8.2 Key format

`parse_signing_key(key_str)` (`security.rs:306-331`): the published key string is
`registry:algorithm:base64key`; the function **rejects any algorithm but
`Ed25519`** (`security.rs:324-328`). Example:
`aos-core:Ed25519:<base64>`. `key_fingerprint` (`security.rs:338+`) returns the
first 8 hex chars of the SHA-256 over the decoded key bytes.

### 8.3 TOFU and trust roots

A key is either **admin-provisioned** in
`…/trusted-keys.d/{registry}.pub` or **accepted on first use** (TOFU) from the
registry's advertised `signing.public_key`, then pinned; a later mismatch is a
`KeyMismatch` (`security.rs` `…:180-186`). Trust roots in the **signed git
commit**: git's Merkle DAG authenticates the whole tree → every TOML → every
recorded NAR hash. There is **no per-NAR signature** today and the AOS client
does not need one.

### 8.4 Downgrade / divergence detection

`check_downgrade(current, new, repo)` (`security.rs:256-296`) uses
`git merge-base --is-ancestor` to classify a transition as
`FastForward`, `SameCommit`, `Downgrade`, or `Diverged`
(`DowngradeStatus`, `security.rs:240-250`).

See [`signing-and-trust.md`](signing-and-trust.md) for the full trust model and
the TARGET two-encoding key story (SSH-commit form + Nix `trusted-public-keys`
form).

---

## 9. Producer-side gaps (the asymmetry)

The producer (`apr`) is a thin wrapper over `git` and `git bundle create`. The
consumer can do far more than the producer can produce.

### 9.1 `apr` commands as implemented

| Command | Implementation | Notes |
|---|---|---|
| `apr create` | `git init` + `packages/` + writes repo-local `registry.toml` (`registry_ops.rs:421+`) | |
| `apr publish` | builds package metadata + commits (`registry_ops.rs:476+`) | |
| `apr tag NAME [-m MSG] [--key]` | `git tag [-a -m]` (`registry_ops.rs:1684-1702`) | **`--key` is ignored** (`_key`) |
| `apr push [BRANCH] [-u] [--force]` | `git push [-u origin] [branch] [--force]` (`registry_ops.rs:1398-1430`) | FF-only by default (git's own rule) |
| `apr pull [--rebase]` | `git pull [--rebase]` (`registry_ops.rs:1433+`) | |
| `apr bundle [-o DIR] [--tag] [--delta-from] [--update-manifest]` | `git bundle create` into a local dir (`registry_ops.rs:1706-1744`) | `_update_manifest` is **unused dead code**; filenames `{name}-{tag}.bundle` / `{name}-{from}..{tag}.bundle` |
| `apr sign [COMMIT] [--key]` | `git commit --amend --no-edit -S` (`registry_ops.rs:1747-1762`) | **`--key` ignored**; **`COMMIT` ignored** — only HEAD is (re)signed via amend |

### 9.2 What's absent

- **No `bundle-list.toml` writer** anywhere — the manifest types are
  `Deserialize`-only (`bundle.rs:59-92`).
- **`apr bundle` cannot maintain the manifest** — its `_update_manifest`
  parameter is unused (`registry_ops.rs:1711`).
- **No producer-side `creation_token` computation** — `version_to_token` exists
  (`state.rs:131-166`) but is called consumer-side only.
- **No automatic delta-type classification on the producer** — `--tag` and
  `--delta-from` are passed manually; `classify_delta` runs only at read time.
- **No bundle/NAR upload to a mirror/CDN/S3 from the producer** — the only
  upload code in the tree is in `aos-cache`, and that is for NARs, not bundles.
- **No static `nix-cache-info` / narinfo / `nar` *producer*** — nothing in the
  tree generates the static binary-cache files (`nix-cache-info`,
  `<storehash>.narinfo`, `nar/<…>.nar.zst`) for the registry's own store paths
  ahead-of-time and uploads them to a CDN. The narinfo **format + sign +
  FileHash logic** *does* exist (`format_narinfo`, `NarInfoSigner`,
  `compute_file_hash_size`) — but it lives inside `aos-server`'s **live,
  store-DB-backed cache server** (a nix-serve-style host serving its *own* store),
  which **the registry never runs** (see
  [§6.1](#61-the-nix-cache--narinfo-logic-exists-as-a-reusable-library-current)).
  The TARGET producer (WS-06) **reuses that logic as a library** to emit the
  static files at publish — genuine ahead-of-time generation + upload work, not
  "just integration" and not a running server (see
  [`nix-cache-compatibility.md`](nix-cache-compatibility.md), TARGET).
- **No locks/atomicity** beyond git's own FF-rejection on push.
- **No explicit "latest" pointer** — "latest" is *derived* by scanning the
  manifest for the max `creation_token`/latest snapshot.

### 9.3 Capability matrix

| Capability | Consumer | Producer |
|---|---|---|
| Parse `bundle-list.toml` | ✅ (`bundle.rs:124`) | — |
| **Write** `bundle-list.toml` | n/a | ❌ |
| `creation_token` encode/decode | ✅ (`state.rs`) | ❌ (encode exists, unused) |
| Classify snapshot/sequential/skip | ✅ read-time (`bundle.rs:238`) | ❌ |
| Select minimal bundle set | ✅ (`update.rs:319`) | n/a |
| `git bundle create` | n/a | ✅ (`registry_ops.rs:1706`) |
| Upload bundles | — | ❌ |
| narinfo / `nix-cache-info` | ✅ consumer is narinfo-driven (`download.rs`, commit `7149acf6`) | ❌ no static-file producer; format/sign **logic** reusable from `aos-server` (`narinfo.rs`, `sign.rs`) — but that's a live host-store server the registry never runs (§6.1) |
| Persist `[registry.state]` | ✅ (`state.rs:37`) | n/a |

> The complete producer/consumer gap mapping to remediation workstreams is in
> [`gap-analysis.md`](../plans/registry/gap-analysis.md) and
> [`workstream-01`](../plans/registry/workstream-01-object-store.md) /
> [`workstream-02`](../plans/registry/workstream-02-pack-delta-pipeline.md).

---

## 10. Git transport (alternative to HTTP bundles)

For `git://`, `git+https://`, `git+ssh://` URLs, the consumer uses
`crates/aos-package/src/registry/git.rs` instead of the bundle path: `git fetch`,
fast-forward enforcement, optional commit-signature verification, then TOML
extraction into the cache. The transport is chosen purely by URL scheme
(`types.rs:312-321`). The HTTP-bundle path (§5) is the dumb-HTTP
lowest-common-denominator; the git path is the richer alternative when a real git
endpoint is available.

---

## 11. Discrepancies vs. the design brief

The [design brief](../plans/registry/design-brief.md) declares: *"the code wins
for current state."* The following points where the **code** differs from the
brief's as-is claims are recorded here and surfaced as open questions.

1. **Package TOML shape (no discrepancy).** Brief §2.3 sketches a nested
   `[package]` / `[[versions]]` / `[versions.platforms.<platform>]` layout, and
   the code **agrees**: the on-disk format is that nested shape, deserialized by
   `PackageToml` et al. (`registry/parse.rs:14-66`) and written by
   `build_package_toml` (`registry_ops.rs:595-769`). The flat `PackageMeta`
   (`types.rs:44-74`) is **not** the on-disk type — it is the in-memory
   per-(package, platform) projection produced by `parse_package_toml`
   (`registry/parse.rs:129-170`) (see [§4.1](#41-packagesnametoml--per-package-per-platform-metadata)).
   The earlier brief-vs-code contradiction recorded here was spurious; the
   [gap-analysis](../plans/registry/gap-analysis.md) grounds the shape in
   `build_package_toml`.

2. **Mirror sort direction.** Brief §2.8 says caches are "sorted by priority."
   The code (`registry_ops.rs:405-414`) sorts **descending** (highest priority
   first), so `resolve_mirror` returning the *first* entry returns the
   *highest-priority* cache. Direction was unspecified in the brief.

3. **`apr sign` semantics.** Brief §2.10 cites `git commit --amend --no-edit -S`.
   Confirmed (`registry_ops.rs:1758`), but note two behaviors not called out:
   the `--key` argument is **ignored** (`_key`, line 1750) and the `COMMIT`
   positional is **ignored** — `--amend` only ever (re)signs **HEAD**, never an
   arbitrary commit.

4. **`apr tag --key` ignored.** The `--key` argument to `apr tag` is accepted but
   unused (`_key`, `registry_ops.rs:1688`).

These do not contradict the brief's *intent* (target design), only its
*as-is* description; the target docs are unaffected.

---

## 12. Cross-references

- [`README.md`](README.md) — registry doc index and glossary.
- [`architecture.md`](architecture.md) — git-repo-over-dumb-HTTP; superset of git **and** Nix; the three ref layers (TARGET).
- [`http-layout.md`](http-layout.md) — HTTP/object layout, CDN TTLs, relative `info/alternates`, stock dumb-HTTP compatibility (TARGET).
- [`repo-layout.md`](repo-layout.md) — the committed git **tree** (`registry.toml` `[[caches]]`, `keys.toml`, `packages/`, `closures/`, `.gitattributes`) and the tree ↔ HTTP mapping; distinct from the served object store (TARGET).
- [`versioning-and-channels.md`](versioning-and-channels.md) — semver, channels-as-branches, the 256-partition rollout, bucket selection, anti-rollback (TARGET).
- [`packs-and-deltas.md`](packs-and-deltas.md) — pack-objects, thin vs full packs, the delta scheme graph, zstd (TARGET).
- [`nix-cache-compatibility.md`](nix-cache-compatibility.md) — the Nix binary-cache superset as **dumb static CDN files generated ahead-of-time at publish** (no server at serve-time), located via the committed `registry.toml` `[[caches]]`, client-side `registries.d` as optional override (TARGET).
- [`signing-and-trust.md`](signing-and-trust.md) — signed tag objects, name-binding, `tag→tag→commit`, TOFU (TARGET).
- [`publishing.md`](publishing.md) — producer pipeline & concurrency (TARGET).
- [`apt-comparison.md`](apt-comparison.md) — APT format comparison and adopted improvements.
- Plan set: [`gap-analysis.md`](../plans/registry/gap-analysis.md),
  [`workstream-01`](../plans/registry/workstream-01-object-store.md),
  [`workstream-02`](../plans/registry/workstream-02-pack-delta-pipeline.md),
  [`workstream-03`](../plans/registry/workstream-03-channels-rollouts.md),
  [`workstream-04`](../plans/registry/workstream-04-signing-trust.md),
  [`workstream-05`](../plans/registry/workstream-05-consumer.md),
  [`open-questions.md`](../plans/registry/open-questions.md).
