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
> a `bundle-list.toml` manifest, there is **no** `nix-cache-info`/narinfo
> emission, and **no** producer-side manifest writer. The root file
> `registry.toml` that *does* exist is a small repo-local config (`[registry]`,
> `[[caches]]`, `[signing]`) — see [§3.1](#31-the-repo-local-registrytoml). The
> **target** drops bundles, `bundle-list.toml`, *and* this `registry.toml`
> config entirely in favor of a bare git repo served over dumb HTTP, with
> channel/release metadata carried by signed git tag objects (see
> [`architecture.md`](architecture.md) and
> [`tag-metadata.md`](tag-metadata.md), TARGET).

---

## 2. CLI dispatch (`aos` / `apm` / `apr`)

One binary, three entry points selected by `argv[0]`:

- `crates/aos/Cargo.toml` declares two `[[bin]]` targets, `aos` and `apr`, both
  `path = "src/main.rs"` (`crates/aos/Cargo.toml:6-11`). The `apm` name is an
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

Resolved from `types.rs` `ProfileScope` (`types.rs:443-517`) and
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

This file lives **inside** the registry git repo and is parsed by
`RegistryRootConfig` (`types.rs:566-599`):

```toml
[registry]
name = "aos-core"
description = "AOS core packages"

# Optional NAR mirrors, highest priority first (see §6).
[[caches]]
url = "https://cache.aos.dev/nar"
priority = 100

# Optional signing pubkey advertised to clients (TOFU; see §8).
[signing]
public_key = "aos-core:Ed25519:base64keyhere"
```

- `[[caches]]` each carry `url` + `priority` (`CacheEntry`, default priority
  `100`, `types.rs:583-593`).
- `[signing].public_key` carries the registry's Ed25519 key string.

> This `registry.toml` is a repo-local config file, **not** part of the target
> wire format. The target has **no** `registry.toml` at all: channel/release
> metadata moves into the **TOML message of signed git tag objects**, which
> carries only `[meta]` (with `schema` + `valid_until`) and `[[caches]]` (see
> [`tag-metadata.md`](tag-metadata.md), TARGET). The `[[caches]]` advertisement
> survives the redesign — relocated from this file into the tag message and now
> permitted to be a **relative** URL on the same origin (see
> [`nix-cache-compatibility.md`](nix-cache-compatibility.md), TARGET).

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
`VersionEntry` / `PlatformEntry`, `registry/parse.rs:14-70`) and what the
producer **writes** (`build_package_toml`, `registry_ops.rs:595-781`). It
matches the nested sketch in the design brief §2.3 — there is **no**
flat-vs-nested divergence.

`PackageMeta` (`types.rs:43-77`) is **not** the on-disk type. It is the
**flattened, in-memory projection** of one (package, platform) pair, produced by
`parse_package_toml` (`registry/parse.rs:133-178`), which walks the nested TOML,
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

`SysrootImageEntry` (`types.rs:606-614`) carries `format`, `store_path`,
`nar_hash`, `nar_size`, `download_hash`, `download_size`.

> **TARGET note.** The redesign keeps this nested package-TOML **tree content**
> unchanged — the package metadata *is* the git tree, consumed by both `apm` and
> stock `git clone`. What changes is everything *around* it (distribution,
> rollout, signing surface). The earlier `[components]`/component-grouping idea is
> **removed** from the target (see
> [`architecture.md`](architecture.md), TARGET).

### 4.2 `closures/<hash>` — adjacency-list closures

Parsed by `ClosureMeta::parse` (`types.rs:107-135`). The file is an adjacency
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

- `nar_url(mirror_url, nar_hash)` →
  **`{mirror_url}/{nar_hash}.nar.zst`** (`download.rs:57-60`), where `nar_hash`
  is the **full `sha256:<hex>` string** — the URL filename literally contains a
  colon (`download.rs:281-294`, e.g.
  `https://cache.aos.dev/nar/sha256:abc123.nar.zst`).
- `resolve_mirror` (`download.rs:67-82`) reads `[[caches]]` from the **local
  registry clone** via `registry_ops::resolve_mirrors` and returns the
  **first** entry; with no caches it falls back to **`{registry.url}/nar`**.
- `resolve_mirrors` (`registry_ops.rs:405-414`) sorts the caches **descending by
  priority** (highest priority first), so "first" = highest priority. *(The
  brief §2.8 says "sorted by priority" without specifying direction; the code is
  descending — see [§11](#11-discrepancies-vs-the-design-brief).)*
- Downloads verify the **compressed** file against `download_hash`
  (`download.rs:102-111`); the local cache filename replaces the colon with a
  dash: `sha256-<hex>.nar.zst` (`download.rs:232-236`).
- `download_nars` (`download.rs:158-222`) runs downloads in parallel under a
  semaphore (default 4, `parallel_downloads`), failing fast on first error.

**NARs are authenticated only by their SHA-256 content hash, not by a
signature.** Their integrity roots transitively in the signed git commit → TOML
→ recorded `download_hash`/`nar_hash` (see [§8](#8-signing--trust) and
[`signing-and-trust.md`](signing-and-trust.md)).

---

## 7. Versioning, tracking modes, and bundle selection (consumer)

### 7.1 Tracking modes

`TrackingMode { Commit, Branch, Tag, Version(semver::VersionReq), Default }`
(`types.rs:281-293`). `RegistryConfig::tracking_mode()` (`types.rs:347-400`)
validates that **at most one** of `commit`/`branch`/`tag`/`version` is set
(the legacy `pin` field merges into `tag`, `types.rs:230-232`, `354`), erroring
otherwise; with none set it returns `Default` (default-branch HEAD).

Transport is derived from the URL scheme (`RegistryConfig::transport`,
`types.rs:315-323`): `git://`, `git+https://`, `git+ssh://` ⇒ `Git`; everything
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
  (`update.rs:262-264`) is gated by `if latest_token > old_token`, so a genuine
  downgrade (`latest <= old`) silently **skips** the guard entirely — the check
  only fires on the strictly-increasing path it would already accept (see
  [`versioning-and-channels.md`](versioning-and-channels.md) §8.4, TARGET).

### 7.3 Semver parsing of tags

`crates/aos-package/src/update.rs`:

- `parse_tag_as_semver(tag)` (`update.rs:429-450`): strip leading `v`, strip
  leading zeros per component, pad 2-component tags to `.0`.
  `v2026.02` → `2026.2.0`; `v2026.02.3` → `2026.2.3`. Non-semver tags → `None`.
- `find_best_version_tag_in_manifest(manifest, req)` (`update.rs:400-424`):
  filter manifest target tags by the `VersionReq`, return the **highest**
  matching; unparseable tags are silently skipped.
- `extract_minor_base(tag)` (`update.rs:456-464`): `v2026.02.3` → `v2026.02`.

### 7.4 `pick_bundles` — the incremental selection algorithm

`pick_bundles(manifest, reg_state, tracking_mode)` (`update.rs:291-391`):

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
(`types.rs:253-262`), serialized under `[registry.state]` in the per-registry
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
| `apr create` | `git init` + `packages/` + writes repo-local `registry.toml` (`registry_ops.rs:420+`) | |
| `apr publish` | builds package metadata + commits (`registry_ops.rs:476+`) | |
| `apr tag NAME [-m MSG] [--key]` | `git tag [-a -m]` (`registry_ops.rs:1696-1714`) | **`--key` is ignored** (`_key`) |
| `apr push [BRANCH] [-u] [--force]` | `git push [-u origin] [branch] [--force]` (`registry_ops.rs:1410-1442`) | FF-only by default (git's own rule) |
| `apr pull [--rebase]` | `git pull [--rebase]` (`registry_ops.rs:1445+`) | |
| `apr bundle [-o DIR] [--tag] [--delta-from] [--update-manifest]` | `git bundle create` into a local dir (`registry_ops.rs:1718-1756`) | `_update_manifest` is **unused dead code**; filenames `{name}-{tag}.bundle` / `{name}-{from}..{tag}.bundle` |
| `apr sign [COMMIT] [--key]` | `git commit --amend --no-edit -S` (`registry_ops.rs:1759-1774`) | **`--key` ignored**; **`COMMIT` ignored** — only HEAD is (re)signed via amend |

### 9.2 What's absent

- **No `bundle-list.toml` writer** anywhere — the manifest types are
  `Deserialize`-only (`bundle.rs:59-92`).
- **`apr bundle` cannot maintain the manifest** — its `_update_manifest`
  parameter is unused (`registry_ops.rs:1723`).
- **No producer-side `creation_token` computation** — `version_to_token` exists
  (`state.rs:131-166`) but is called consumer-side only.
- **No automatic delta-type classification on the producer** — `--tag` and
  `--delta-from` are passed manually; `classify_delta` runs only at read time.
- **No bundle/NAR upload to a mirror/CDN/S3 from the producer** — the only
  upload code in the tree is in `aos-cache`, and that is for NARs, not bundles.
- **No `nix-cache-info` / narinfo emission** — the registry is not a Nix binary
  cache today (see [`nix-cache-compatibility.md`](nix-cache-compatibility.md),
  TARGET).
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
| Select minimal bundle set | ✅ (`update.rs:291`) | n/a |
| `git bundle create` | n/a | ✅ (`registry_ops.rs:1718`) |
| Upload bundles | — | ❌ |
| narinfo / `nix-cache-info` | n/a | ❌ |
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
(`types.rs:315-323`). The HTTP-bundle path (§5) is the dumb-HTTP
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
   `PackageToml` et al. (`registry/parse.rs:14-70`) and written by
   `build_package_toml` (`registry_ops.rs:595-781`). The flat `PackageMeta`
   (`types.rs:43-77`) is **not** the on-disk type — it is the in-memory
   per-(package, platform) projection produced by `parse_package_toml`
   (`registry/parse.rs:133-178`) (see [§4.1](#41-packagesnametoml--per-package-per-platform-metadata)).
   The earlier brief-vs-code contradiction recorded here was spurious; the
   [gap-analysis](../plans/registry/gap-analysis.md) grounds the shape in
   `build_package_toml`.

2. **Mirror sort direction.** Brief §2.8 says caches are "sorted by priority."
   The code (`registry_ops.rs:405-414`) sorts **descending** (highest priority
   first), so `resolve_mirror` returning the *first* entry returns the
   *highest-priority* cache. Direction was unspecified in the brief.

3. **`apr sign` semantics.** Brief §2.10 cites `git commit --amend --no-edit -S`.
   Confirmed (`registry_ops.rs:1770`), but note two behaviors not called out:
   the `--key` argument is **ignored** (`_key`, line 1762) and the `COMMIT`
   positional is **ignored** — `--amend` only ever (re)signs **HEAD**, never an
   arbitrary commit.

4. **`apr tag --key` ignored.** The `--key` argument to `apr tag` is accepted but
   unused (`_key`, `registry_ops.rs:1700`).

These do not contradict the brief's *intent* (target design), only its
*as-is* description; the target docs are unaffected.

---

## 12. Cross-references

- [`README.md`](README.md) — registry doc index and glossary.
- [`architecture.md`](architecture.md) — git-repo-over-dumb-HTTP; superset of git **and** Nix; the three ref layers (TARGET).
- [`http-layout.md`](http-layout.md) — HTTP/object layout, CDN TTLs, `http-alternates`, stock dumb-HTTP compatibility (TARGET).
- [`versioning-and-channels.md`](versioning-and-channels.md) — semver, channels-as-branches, the 256-partition rollout, bucket selection, anti-rollback (TARGET).
- [`packs-and-deltas.md`](packs-and-deltas.md) — pack-objects, thin vs full packs, the delta scheme graph, zstd (TARGET).
- [`tag-metadata.md`](tag-metadata.md) — the channel/release tag-message TOML schema (TARGET).
- [`nix-cache-compatibility.md`](nix-cache-compatibility.md) — the Nix binary-cache superset via relative `[[caches]]` (TARGET).
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
