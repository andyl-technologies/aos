# Workstream 06 — Nix binary-cache / narinfo emitter

> **Status:** Implementation plan / **TARGET** design. As-is code behaviour is
> labelled **CURRENT** and cited as `path:line`; the publish-time goal is labelled
> **TARGET**. Where the code contradicts the brief, the code wins for *current
> state* and the brief wins for *target intent*; discrepancies are logged in
> [open-questions.md](./open-questions.md).
>
> **Audience:** implementers building the `nix-cache-info` / narinfo emitter,
> architects reasoning about the NAR-cache layer vs the git-metadata layer, and
> engineers wiring the one-key signing model into the publish pipeline.
>
> **Grounding:** [design-brief.md](./design-brief.md) **§13** (Nix binary-cache
> superset) and **§11** (signing & trust — the one shared key), reconciled with
> the reference doc
> [`nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md) and the
> actual code (`crates/aos-package/src/types.rs:43-77`,
> `crates/aos-package/src/download.rs`, `crates/aos-package/src/registry/parse.rs`,
> `crates/aos-core/src/nar/info.rs`, `crates/aos-server/src/sign.rs`). The brief
> and the reference doc are authoritative for intent; this doc translates that
> intent into a concrete change set on the **producer / publish** side.

This is the **producer-side** counterpart to
[workstream-05-consumer.md](./workstream-05-consumer.md) §8 (which only *resolves*
and *reads* a substituter) and to
[workstream-04-signing-trust.md](./workstream-04-signing-trust.md) (the one-key
model). WS-06 builds the **emitter** that projects the registry git tree's
`PackageMeta` into the three stock-Nix static files — `nix-cache-info`,
`<storehash>.narinfo`, `nar/<key>.nar.zst` — so a non-AOS host running stock
`nix` can use an AOS origin as an ordinary substituter, with signatures intact and
`require-sigs` left on.

The NAR-cache layer is a **strict superset** of the standard Nix binary cache and
is **orthogonal** to the git-object trust chain that `apm` walks: it is not part
of `apm`'s trust root, and its location is named **in-tree** (the committed
`registry.toml` `[[caches]]`), never in a signed tag (see
[`nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md) §1, §3).

---

## 1. Where this sits in the plan

```
 WS-01 object store ─┐
 WS-02 pack/delta   ─┤  emit the git-metadata layer (packages/ TOMLs = narinfo SOURCE)
 WS-03 channels     ─┤
 WS-04 signing      ─┘  the ONE Ed25519 key (also signs narinfos here)
        │
        ▼
 WS-06 NIX-CACHE EMITTER  ◄── THIS doc: project PackageMeta → nix-cache-info + *.narinfo,
        │                      sign each narinfo with the one key, place NAR blobs
        ▼
 WS-05 CONSUMER §8 ──► resolves the cache from committed [[caches]], reads these files
 stock `nix` host  ──► points extra-substituters at the cache URL, verifies Sig:
```

WS-06 adds **no new git surface** — it reads the same `packages/<l>/<name>.toml`
tree WS-01/02/03 already emit, and writes flat static files into the NAR-cache
layer. The git layer is the **source of truth**; the narinfo is "just a
reprojection of metadata AOS already holds in its git tree"
([`nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md) §2).

> **CURRENT.** A nix-cache *server* already exists:
> [`aos-server/src/routes.rs`](../../../crates/aos-server/src/routes.rs) serves
> `/{view}/nix-cache-info`, `/{view}/{hash}.narinfo`, and `/{view}/nar/{filename}`
> off its runtime SQLite. WS-06 is **not greenfield** — it reuses that surface's
> output format and signer, and **extends** it with publish-time narinfo + `Sig:`
> emission keyed off the committed `packages/*.toml` tree (see §2.2).

---

## 2. CURRENT state (as-is, grounded in code)

> **CURRENT.** Two halves of this surface already exist but on the **wrong side**
> of the split: the *consumer* fully parses/downloads NAR blobs, and the
> *cache-server* (`aos-server`) already emits narinfo + `nix-cache-info` — but
> **from its runtime SQLite `DbPathInfo`**, not from the registry git tree's
> `PackageMeta`. There is **no publish-time emitter** that projects a
> `packages/*.toml` registry tree into static `*.narinfo` / `nix-cache-info`
> files. That static-file projection is exactly what WS-06 builds.

### 2.1 The NAR **blob** layer already carries over (consumer side)

The content-addressed, zstd-compressed blob layer is done and reusable verbatim:

- `nar_url`-style key: the consumer downloads from
  `{mirror_url}/{nar.url}` where the cache-supplied `URL:` is `nar/<key>.nar.zst`;
  `join_cache_url` trims slashes
  ([`download.rs:65-77`](../../../crates/aos-package/src/download.rs)).
- Compressed-stream verification is by **SHA-256 of the `.nar.zst` bytes** against
  the narinfo `FileHash`, **not** by signature
  ([`download.rs:191-204`](../../../crates/aos-package/src/download.rs)) — the
  `(Some(h),_) | (None,"none") | (None,comp)=>bail!` match.
- On-disk colon→dash rewrite for filesystem safety: `nar_cache_filename`
  ([`download.rs:314-317`](../../../crates/aos-package/src/download.rs)) →
  `sha256-<hex>.nar.zst`; the **wire** key keeps the colon.
- `resolve_mirror` ([`download.rs:85-97`](../../../crates/aos-package/src/download.rs))
  picks the highest-priority `[[caches]]` entry via `resolve_mirrors`, else falls
  back to `{registry.url}` as the base.

### 2.2 The narinfo data model + emitter already exist (but DB-fed)

- `NarInfo` struct + `parse` / `format` / `from_path_info` / `store_hash` /
  `basename` live in
  [`crates/aos-core/src/nar/info.rs`](../../../crates/aos-core/src/nar/info.rs).
  `format(&NarInfo) -> String` already emits the canonical line-oriented
  `Key: value` text (StorePath/URL/Compression/FileHash/FileSize/NarHash/NarSize/
  References/Deriver/Sig). **WS-06 reuses this formatter verbatim** — it only needs
  to *build* a `NarInfo` from `PackageMeta` instead of from `PathInfoParams`.
- `aos-server` already serves the live cache surface from its DB:
  `narinfo::format_narinfo(&DbPathInfo, ...)`
  ([`aos-server/src/narinfo.rs:27`](../../../crates/aos-server/src/narinfo.rs)),
  the `cache_info_handler`
  ([`aos-server/src/routes.rs:123-148`](../../../crates/aos-server/src/routes.rs))
  emitting `StoreDir: … \nWantMassQuery: 1\nPriority: 30\n…` (`Priority: 30` at
  [`routes.rs:145`](../../../crates/aos-server/src/routes.rs)),
  and the Nix fingerprint signer (see §6.1).

> **The CURRENT-vs-TARGET crux.** `aos-server`'s emitter is a *runtime daemon*
> keyed off SQLite `DbPathInfo`; WS-06 is a *publish-time* emitter keyed off the
> committed `packages/*.toml` registry tree (`PackageMeta`). Same output format
> (`nar::info::format`), same fingerprint (`NarInfoSigner::fingerprint`),
> **different source struct and different lifecycle** (static files written once
> at publish, not served per-request). The two share `aos-core::nar::info`.

### 2.3 The narinfo **source data** is already on `PackageMeta`

Every narinfo field except `Sig:` already exists on the flattened in-memory
`PackageMeta` ([`types.rs:43-77`](../../../crates/aos-package/src/types.rs)), the
projection of the nested on-disk `PackageToml` (`PlatformEntry`,
[`registry/parse.rs:44-57`](../../../crates/aos-package/src/registry/parse.rs)).
See the field table in §5.

### 2.4 What is missing today

| Missing piece | Why WS-06 |
|---|---|
| Publish-time `nix-cache-info` emitter from registry config | §4 |
| Publish-time `*.narinfo` emitter projecting `PackageMeta` (not `DbPathInfo`) | §5 |
| Sysroot-image narinfos (each `SysrootImageEntry` is its own store path) | §5.4 |
| References **bare-hash → `<hash>-<name>` basename** expansion | §5.3 |
| Per-narinfo `Sig:` from the **one** registry key (fingerprint reuse) | §6 |
| Two pubkey encodings: `aos-core:Ed25519:<b64>` (apm) vs `<name>:<b64>` (nix) | §6.3 |
| NAR blob `URL:` key scheme (colon-retained + colon-free fallback) | §7 |
| Stock-`nix` consumer docs (`extra-substituters`, `require-sigs`) | §8 |

---

## 3. TARGET — the publish-time emitter pipeline

### 3.1 End-to-end flow

```
apr publish  (after the git tree + NAR blobs are placed)
│
├─ 1. load RegistryRootConfig (registry.toml)  → StoreDir/Priority policy   (§4)
│
├─ 2. parse_registry(tree) → HashMap<name, PackageMeta>  (reuse parse.rs)   (§5.1)
│        + build hash_index (bare-hash → store_path basename)               (§5.3)
│
├─ 3. for each PackageMeta:
│        build NarInfo via package_meta_to_narinfo(meta, &index, cfg)        (§5.2)
│        ├─ References: expand bare hashes → <hash>-<name>                   (§5.3)
│        ├─ Sig: sign fingerprint(StorePath,NarHash,NarSize,References)      (§6)
│        └─ for each SysrootImageEntry: its OWN narinfo                      (§5.4)
│
├─ 4. write  <cache-root>/<storehash>.narinfo   (nar::info::format)          (§5.5)
│
├─ 5. write  <cache-root>/nix-cache-info        (once per cache)             (§4)
│
└─ 6. ensure NAR blobs reachable at the URL: key the narinfo points at       (§7)
```

Step 6 is mostly a placement check — the blob layer (§2.1) already lays out
`nar/<key>.nar.zst`; WS-06 only guarantees the emitted `URL:` matches the served
key (colon caveat, §7).

### 3.2 New module

```
crates/aos-package/src/registry/nix_cache.rs        ← NEW (the emitter)
```

It depends on the existing `aos-core::nar::info` (formatter), `registry/parse.rs`
(`PackageMeta`, `build_hash_index`, `store_path_hash`), `types.rs`
(`RegistryRootConfig`, `CacheEntry`, `SysrootImageEntry`), and a new signer (§6)
that reuses the **one** registry Ed25519 key (WS-04).

---

## 4. The `nix-cache-info` stub (TARGET)

Nix hardcodes the filename `nix-cache-info` at the **root of the cache URL** and
fetches it once per cache. WS-06 writes it once at publish time from registry
policy — **not** from any per-path metadata.

```
StoreDir: /nix/store
WantMassQuery: 1
Priority: 30
```

| Key | Source | Notes |
|---|---|---|
| `StoreDir` | publish-pipeline input (the AOS store dir the NARs were built against) | **Not** derivable from any `types.rs` field — supplied by the publisher; commonly `/nix/store`. Must match the consuming host's store. |
| `WantMassQuery` | constant `1` | The origin is a plain object store; mass query is cheap. |
| `Priority` | operator policy knob (default `30`, matching the live server) | Lower = preferred. The live `cache_info_handler` emits `30` ([`routes.rs:145`](../../../crates/aos-server/src/routes.rs)); the `aos-cache` backends emit `40` ([`fs.rs:126`](../../../crates/aos-cache/src/backend/fs.rs), [`sftp.rs:143`](../../../crates/aos-cache/src/backend/sftp.rs)). Stock `cache.nixos.org` is `40`; `30` is therefore consulted **before** upstream. **Distinct** from the AOS `[[caches]]` `priority` (§4 of the ref doc). |

> Note the `nix-cache-info` `Priority` (Nix-cache preference, ordered by stock
> `nix`) is a different knob from the AOS `CacheEntry.priority`
> ([`types.rs:585-593`](../../../crates/aos-package/src/types.rs),
> `default_cache_priority()==100`) that `apm`'s `resolve_mirrors` sorts. **Two
> independent priority knobs** (F362).

### 4.1 Emitter signature

```rust
/// Policy inputs for the nix-cache-info stub (publisher-supplied; NOT from
/// PackageMeta).
pub struct CacheInfoConfig {
    /// The AOS store dir the NARs were built against (e.g. "/nix/store").
    pub store_dir: String,
    /// Nix-cache preference (lower = preferred; distinct from CacheEntry.priority).
    pub priority: u32,
}

/// Emit the fixed-name `nix-cache-info` capability stub.
pub fn emit_nix_cache_info(cfg: &CacheInfoConfig) -> String {
    format!(
        "StoreDir: {}\nWantMassQuery: 1\nPriority: {}\n",
        cfg.store_dir, cfg.priority,
    )
}
```

This mirrors the live handler `cache_info_handler` at
[`aos-server/src/routes.rs:123-148`](../../../crates/aos-server/src/routes.rs)
(minus the AOS-only `Capabilities:` line, which stock `nix` ignores and which the
static cache surface does not advertise).

**Tests** (`#[test]`):
- `nix_cache_info_default_store_dir` — `store_dir="/nix/store"`, `priority=30`
  ⇒ exact three-line body.
- `nix_cache_info_custom_priority` — a custom `priority` renders verbatim.
- `nix_cache_info_omits_capabilities` — the AOS `Capabilities:` line is **absent**
  from the static surface.

---

## 5. narinfo generator (TARGET)

A narinfo is line-oriented `Key: value` text. WS-06 builds a `NarInfo`
(`aos-core::nar::info::NarInfo`) from each `PackageMeta`, then renders it with the
existing `nar::info::format`.

### 5.1 Field mapping (the authoritative join)

| narinfo field | Source (`PackageMeta`) | Code ref | Transform |
|---|---|---|---|
| `StorePath` | `store_path` | [`types.rs:53`](../../../crates/aos-package/src/types.rs) | verbatim, e.g. `/nix/store/<hash>-<name>` |
| `URL` | derived `nar/<key>.nar.zst` | [`download.rs:65-77`](../../../crates/aos-package/src/download.rs) | key from `nar_hash` (§7) |
| `Compression` | constant `zstd` | n/a | AOS NARs are always `.nar.zst` |
| `FileHash` | **emit-time compute** — SHA-256 of the `.nar.zst` bytes | — | narinfo-driven; **not** on `PackageMeta` — see §5.2.1 |
| `FileSize` | **emit-time compute** — byte length of the `.nar.zst` | — | narinfo-driven; **not** on `PackageMeta` — see §5.2.1 |
| `NarHash` | `nar_hash` (`sha256:<hex>`) | [`types.rs:54-55`](../../../crates/aos-package/src/types.rs) | verbatim |
| `NarSize` | `nar_size` | [`types.rs:56`](../../../crates/aos-package/src/types.rs) | verbatim |
| `References` | `references` (**bare hashes**) | [`types.rs:57-58`](../../../crates/aos-package/src/types.rs) | ⚠️ expand `<hash>` → `<hash>-<name>` (§5.3) |
| `Deriver` | `source_drv` basename | [`types.rs:59-60`](../../../crates/aos-package/src/types.rs) | basename of the `.drv` store path |
| `Sig` | — generated | n/a | Ed25519 over the fingerprint (§6) |

Carried by AOS but **not** narinfo fields (dropped): `closure_size`
([`types.rs:63-64`](../../../crates/aos-package/src/types.rs) — Nix recomputes
closures from `References`), `source_nar_hash`
([`types.rs:61-62`](../../../crates/aos-package/src/types.rs)), `homepage` /
`license` / `maintainer` / `description`. `System` (`platform`,
[`types.rs:52`](../../../crates/aos-package/src/types.rs)) is **optional** and
omittable; `CA` is omitted (AOS paths are input-addressed).

#### 5.2.1 `FileHash` / `FileSize` are computed at emit time (narinfo-driven)

`download_hash` / `download_size` **were removed from the registry schema** in
commit `7149acf6` ("apm: narinfo-driven NAR downloads"): `apm` no longer reads
the compressed-NAR hash/size from the package TOML — it fetches the narinfo first
and reads `FileHash` / `FileSize` from there. The current `PackageMeta`
([`types.rs:44-74`](../../../crates/aos-package/src/types.rs)) and the on-disk
`PlatformEntry` ([`registry/parse.rs:45-51`](../../../crates/aos-package/src/registry/parse.rs))
therefore have **no** `download_hash` / `download_size` fields — the narinfo is
their single source of truth.

The narinfo is exactly where these values live, so **WS-06 computes them at emit
time** from the compressed blob: the emitter reads each `nar/<key>.nar.zst`,
SHA-256s the bytes (`FileHash`), and takes its byte length (`FileSize`). No schema
change is needed — this matches the narinfo-driven contract the consumer already
relies on (§2.1, [`download.rs:191-204`](../../../crates/aos-package/src/download.rs)
verifies the `.nar.zst` against the narinfo `FileHash`). The builder below takes
`file_hash` / `file_size` as **computed inputs**, not as `PackageMeta` fields.

### 5.2 Builder signature

```rust
use aos_core::nar::info::{NarInfo, format as format_narinfo};
use crate::types::PackageMeta;
use crate::registry::parse::store_path_hash;

/// SHA-256 / byte-length of the compressed `.nar.zst`, computed at emit time
/// from the blob (§5.2.1). Not carried on `PackageMeta` — narinfo-driven.
pub struct CompressedNar {
    pub file_hash: String,   // "sha256:<hex>" of the .nar.zst bytes
    pub file_size: u64,      // byte length of the .nar.zst
}

/// Project a registry `PackageMeta` into a Nix `NarInfo`.
///
/// `refs_index` maps a bare store-path hash → that path's full store-path
/// basename, used to expand `References` into `<hash>-<name>` (§5.3). `nar`
/// carries the emit-time-computed `.nar.zst` hash/size (§5.2.1).
pub fn package_meta_to_narinfo(
    meta: &PackageMeta,
    nar: &CompressedNar,
    refs_index: &ReferenceIndex,
    signer: &NarInfoSigner,
) -> anyhow::Result<NarInfo> {
    let references = expand_references(&meta.references, refs_index)?;   // §5.3
    let nar_key = nar_url_key(&meta.nar_hash);                            // §7
    let mut info = NarInfo {
        store_path: meta.store_path.clone(),
        url: format!("nar/{nar_key}.nar.zst"),
        compression: "zstd".to_string(),
        file_hash: Some(nar.file_hash.clone()),   // §5.2.1 (emit-time compute)
        file_size: Some(nar.file_size),           // §5.2.1 (emit-time compute)
        nar_hash: meta.nar_hash.clone(),
        nar_size: meta.nar_size,
        references,
        deriver: Some(basename(&meta.source_drv).to_string()),
        signatures: Vec::new(),
    };
    let sig = signer.sign_narinfo(&info)?;             // §6
    info.signatures.push(sig);
    Ok(info)
}
```

### 5.3 References basename expansion (the one non-mechanical transform)

AOS stores `references` as **bare store-path hashes**
([`types.rs:57-58`](../../../crates/aos-package/src/types.rs); the
`closures/<hash>` adjacency files use the same bare-hash format,
[`types.rs:93-101`](../../../crates/aos-package/src/types.rs)). Nix narinfo
`References` requires **store-path basenames** `<hash>-<name>`. If left bare,
stock `nix` **rejects** the narinfo (it validates references as basenames against
`StoreDir`).

```
AOS references:     [ "r4q1m2kp8v3x…", "xr5is7by89v3q…" ]
                              │                  │
              resolve bare hash → referenced package's store_path basename
                              │                  │
narinfo References:  r4q1m2kp8v3x…-glibc-2.39   xr5is7by89v3q…-zlib-1.3.1
```

The name suffix is recoverable from the *referenced* package's own `store_path`
([`types.rs:53`](../../../crates/aos-package/src/types.rs)). `build_hash_index`
([`registry/parse.rs:176-196`](../../../crates/aos-package/src/registry/parse.rs))
already maps a bare hash → package name; WS-06 adds a parallel
hash → **store-path basename** map so the join yields the exact `<hash>-<name>`
(name + version, not just name):

```rust
/// Bare store-path hash → full store-path basename (`<hash>-<name>-<ver>`).
/// Built alongside `build_hash_index`, from every PackageMeta + every
/// SysrootImageEntry in the registry.
pub struct ReferenceIndex {
    by_hash: std::collections::HashMap<String, String>, // hash → basename
}

impl ReferenceIndex {
    pub fn build(packages: &std::collections::HashMap<String, PackageMeta>) -> Self { /* … */ }
    pub fn basename(&self, bare_hash: &str) -> Option<&str> { /* … */ }
}

fn expand_references(
    bare: &[String],
    index: &ReferenceIndex,
) -> anyhow::Result<Vec<String>> {
    bare.iter()
        .map(|h| index.basename(h)
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("unresolved reference hash {h}")))
        .collect()
}
```

> A reference hash that resolves to **no** package in the registry is a hard error
> (fail-closed) — a narinfo with a dangling `<hash>` would be unverifiable by the
> consumer. This is the producer-side dual of the consumer's closure resolution.

**Tests:**
- `expand_references_curl` — using `CURL_TOML` + `ZLIB_TOML`
  ([`parse.rs:209-259`](../../../crates/aos-package/src/registry/parse.rs)
  fixtures), curl's `references` (zlib's bare hash `r4q1m2kp8v3x`) expands to
  `r4q1m2kp8v3x-zlib-1.3.1`.
- `expand_references_empty` — zlib (leaf, `references == []`) ⇒ empty vector ⇒
  `format` omits the `References:` line.
- `expand_references_dangling_errors` — an unknown bare hash returns
  `Err(... "unresolved reference hash ...")`.

### 5.4 Sysroot images are their own store paths (TARGET)

Each `SysrootImageEntry`
([`types.rs:603-609`](../../../crates/aos-package/src/types.rs); carried in
`PackageMeta.images`, [`types.rs:71-73`](../../../crates/aos-package/src/types.rs);
parsed from `[[versions.platforms.*.images]]`,
[`registry/parse.rs:59-66`](../../../crates/aos-package/src/registry/parse.rs)) is
a **distinct store path** with its own `store_path` / `nar_hash` / `nar_size`. Each
image therefore gets its **own** `<storehash>.narinfo`, keyed by the image's
store-path hash, with an identical field mapping (§5.1):

```rust
/// Build a narinfo for a sysroot image (its own store path).
/// `SysrootImageEntry` has no `references` field, so References is empty
/// (image NARs are self-contained system images).
pub fn image_to_narinfo(
    img: &SysrootImageEntry,
    signer: &NarInfoSigner,
) -> anyhow::Result<NarInfo> { /* maps store_path/nar_hash/nar_size; refs = [] */ }
```

**Tests:**
- `image_narinfo_keyed_by_image_hash` — a `SysrootImageEntry`'s narinfo file name
  uses `store_path_hash(img.store_path)`, not the parent sysroot's hash.
- `image_narinfo_empty_references` — image narinfo has no `References:` line.

### 5.5 Writing the files

```rust
/// Emit all narinfo files for a parsed registry into <cache_root>.
/// File name = `<store_path_hash>.narinfo` (the 32-char base32 store-hash,
/// matching `narinfo::store_hash` / `narinfo_url` on the consumer side,
/// download.rs:74-77).
pub fn emit_narinfos(
    packages: &HashMap<String, PackageMeta>,
    cache_root: &Path,
    signer: &NarInfoSigner,
    cfg: &CacheInfoConfig,
) -> anyhow::Result<EmitReport> { /* writes <hash>.narinfo + nix-cache-info */ }
```

The file name uses `store_path_hash(&meta.store_path)`
([`registry/parse.rs:201-205`](../../../crates/aos-package/src/registry/parse.rs))
so it round-trips with the consumer's `narinfo_url`
([`download.rs:74-77`](../../../crates/aos-package/src/download.rs)), which derives
the same `<storehash>.narinfo` name via `narinfo::store_hash`.

**Tests:**
- `emit_narinfos_round_trips_through_parse` — emit a narinfo for curl, then
  `aos_core::nar::info::parse` it back and assert `store_path` / `nar_hash` /
  `references` / `deriver` survive (uses `format`↔`parse` symmetry already proven
  by `round_trip` in [`info.rs:161`](../../../crates/aos-core/src/nar/info.rs)).
- `emit_narinfos_filename_is_store_hash` — the written file for curl is
  `<curl-store-hash>.narinfo`.
- `emit_narinfos_includes_images` — a sysroot `PackageMeta` with two images emits
  3 narinfo files (the sysroot + 2 images).

---

## 6. Signing: one key, two signature forms (TARGET)

The `Sig:` line is the **only** narinfo field with no source in AOS metadata — it
must be generated. The design reuses the **same single Ed25519 keypair** that
signs git tags (brief §11): one secret to manage, two *signed messages*, two
*published pubkey encodings*.

### 6.1 Reuse the existing fingerprint + signer

`aos-server` **already** implements the Nix fingerprint and the Ed25519 sign over
it ([`aos-server/src/sign.rs`](../../../crates/aos-server/src/sign.rs)):

```rust
// aos-server/src/sign.rs:57-60  (REUSE this fingerprint composition verbatim)
pub fn fingerprint(store_path: &str, nar_hash: &str, nar_size: i64, refs: &[String]) -> String {
    let refs_str = refs.join(",");
    format!("1;{store_path};{nar_hash};{nar_size};{refs_str}")
}
// aos-server/src/sign.rs:44-54  sign() → "name:base64_sig", 32-byte ed25519 seed
```

The fingerprint is exactly the Nix message over **`(StorePath, NarHash, NarSize,
References)`** (the `1;…;…;…;…` form). **`refs` here must be the EXPANDED
`<hash>-<name>` basenames** (§5.3), not the bare AOS hashes — the signed message
must match what stock `nix` recomputes from the emitted `References:` line.

WS-06 lifts this composition into a shared place so producer and daemon agree.
Proposed home: a `Fingerprint` helper in `aos-core::nar::info` (next to `format`),
re-exported by both `aos-server::sign` and the new `registry/nix_cache.rs`.

```rust
/// Producer-side narinfo signer reusing the ONE registry Ed25519 key (WS-04).
pub struct NarInfoSigner {
    name: String,        // the cache/key name, e.g. "aos-core"
    secret: [u8; 32],    // ed25519 seed (first 32 bytes of the Nix 64-byte key)
}

impl NarInfoSigner {
    /// Sign a fully-built NarInfo. Composes the fingerprint over the EXPANDED
    /// references already on `info`, signs it, returns the `name:base64sig`
    /// value for the `Sig:` line.
    pub fn sign_narinfo(&self, info: &NarInfo) -> anyhow::Result<String> {
        let fp = nar_fingerprint(
            &info.store_path,
            &info.nar_hash,
            info.nar_size,
            &info.references,         // EXPANDED basenames (§5.3)
        );
        Ok(self.sign(&fp))            // "name:base64sig"  (sign.rs:44-54)
    }
}
```

```
apm trust:   signed tag chain ──► TOML ──► NAR sha256   (transitive; no Sig needed)
nix trust:   narinfo Sig (Ed25519) ──► fingerprint(StorePath,NarHash,NarSize,Refs)
                 ▲
                 └── SAME key, DIFFERENT signed message than the git tag
```

### 6.2 Why a per-narinfo `Sig` exists at all

`apm` trust is rooted in the **signed git tag chain**: tag → tag → commit
authenticates the whole tree → every package TOML → every NAR SHA-256
(brief §5, §11). So `apm` needs **no** per-NAR signature; NARs are authenticated
transitively and verified by content hash
([`download.rs:191-204`](../../../crates/aos-package/src/download.rs)). The
per-narinfo `Sig:` exists **only** to satisfy a stock `nix` substituter without
forcing `require-sigs = false` — a compatibility affordance, orthogonal to the
AOS trust chain (ref doc §8.1, closes **F387**).

### 6.3 Two published pubkey encodings (one key)

| Form | Consumer | Encoding | Source |
|---|---|---|---|
| **apm** | `apm` TOFU / `trusted-keys.d` | `aos-core:Ed25519:<base64>` | `SigningConfig.public_key` ([`types.rs:246-247`](../../../crates/aos-package/src/types.rs)), parsed by `parse_signing_key` ([`security.rs:306`](../../../crates/aos-package/src/security.rs)) as `<name>:Ed25519:<base64>` |
| **nix** | stock `nix` `trusted-public-keys` | `<name>:<base64>` | the **same** key bytes, Nix-flavored projection (drops the `:Ed25519:` algo segment) |

The publisher emits **both** projections from the one key. The nix form is what a
stock host puts in `extra-trusted-public-keys` (§8). This is **F386** (two
encodings) and **F392** (nix-form value). The projection is mechanical:

```rust
/// nix `<name>:<base64>` from the apm `<name>:Ed25519:<base64>` form.
pub fn nix_pubkey_from_apm(apm_key: &str) -> anyhow::Result<String> {
    let (name, _algo, b64) = crate::security::parse_signing_key(apm_key)?;  // security.rs:306
    Ok(format!("{name}:{b64}"))
}
```

**Tests:**
- `sig_value_is_name_colon_base64` — `sign_narinfo` returns a `name:…` value whose
  prefix matches the signer name.
- `fingerprint_uses_expanded_refs` — the signed fingerprint contains
  `<hash>-<name>` basenames, not bare hashes (guards the §5.3↔§6 coupling).
- `fingerprint_matches_server_form` — `nar_fingerprint(...)` is byte-identical to
  `aos_server::sign::NarInfoSigner::fingerprint(...)` for the same inputs
  (prevents producer/daemon drift).
- `nix_pubkey_from_apm_drops_algo` —
  `nix_pubkey_from_apm("aos-core:Ed25519:Xk9m2Qp4=") == "aos-core:Xk9m2Qp4="`.
- `nix_pubkey_from_apm_rejects_rsa` — a non-Ed25519 algo errors (rides
  `parse_signing_key`, [`security.rs:324-329`](../../../crates/aos-package/src/security.rs)).

---

## 7. NAR blob `URL:` key scheme (TARGET)

The narinfo `URL:` is a path relative to the cache base (§4 of ref doc). Two facts
constrain it:

1. **CURRENT wire key.** The blob is served at `{cache}/nar/<nar_hash>.nar.zst`
   with the **full `sha256:<hex>` retained** — the literal colon is kept in the
   wire filename ([`download.rs:65-77`](../../../crates/aos-package/src/download.rs),
   via the cache-supplied `URL:`). On disk the consumer rewrites colon→dash
   ([`download.rs:314-317`](../../../crates/aos-package/src/download.rs)), but the
   **wire** key keeps the colon.
2. **Cache placement.** The cache may be co-located with the git repo (relative
   `[[caches]]` url `./nar`) or a separate host (absolute url); `URL:` is resolved
   relative to whichever base `apm` selects (§3 of ref doc, WS-05 §8.2).

```
<cache-url>/nar/sha256:<hex>.nar.zst        ← AOS wire key (colon retained, default)
        └── narinfo  URL: nar/sha256:<hex>.nar.zst
```

```rust
/// Default wire key: colon retained (matches CURRENT download.rs path).
/// `nar_hash` is the full "sha256:<hex>".
pub fn nar_url_key(nar_hash: &str) -> String {
    nar_hash.to_string()           // colon retained
}

/// Colon-free fallback (the `sha256-<hex>` form the consumer already writes on
/// disk, download.rs:314-317) for edges that mangle the colon.
pub fn nar_url_key_colon_free(nar_hash: &str) -> String {
    nar_hash.replace(':', "-")     // sha256-<hex>
}
```

> **Colon-in-filename caveat (F388/F389).** S3 allows a literal `:` in object
> keys, but some CDN/edge layers percent-encode or reject it. If the chosen edge
> mangles the colon, the emitter switches to `nar_url_key_colon_free` **and** sets
> `URL:` to match — the blob is then served under `sha256-<hex>.nar.zst`. This is
> a **deployment decision** (a `colon_safe: bool` on the emitter config); see
> [open-questions.md](./open-questions.md).

**Tests:**
- `nar_url_key_retains_colon` — `nar_url_key("sha256:abc") == "sha256:abc"`.
- `nar_url_key_colon_free` — `nar_url_key_colon_free("sha256:abc") == "sha256-abc"`
  (mirrors the existing `nar_cache_filename_replaces_colon` test,
  [`download.rs:410-415`](../../../crates/aos-package/src/download.rs)).
- `url_field_is_relative_nar_path` — emitted `URL:` is `nar/<key>.nar.zst`, no
  leading slash, so `join_cache_url`
  ([`download.rs:65-71`](../../../crates/aos-package/src/download.rs)) resolves it
  against any cache base.

---

## 8. Stock-`nix` consumer wiring (TARGET, docs)

Once a cache emits `nix-cache-info` + `*.narinfo` (§4, §5), a non-AOS host running
stock `nix` consumes it as an ordinary binary cache. WS-06 owns the **docs** for
this path (the plumbing itself is stock Nix); the AOS-host resolution path is
WS-05 §8.

### 8.1 `nix.conf` (F390)

```ini
# /etc/nix/nix.conf  (or ~/.config/nix/nix.conf)
extra-substituters         = https://registry.aos.dev/core/nar
extra-trusted-public-keys  = aos-core:base64publickeyhere==
```

- Use the `extra-` prefix (**appends** to defaults) so `cache.nixos.org` is
  retained.
- The key value is the **`<name>:<base64>`** nix encoding — same key bytes as the
  apm `aos-core:Ed25519:<base64>` form (§6.3, **F392**).
- **Do not** set `require-sigs = false` (**F393**). Emitting `Sig:` (§6) is
  precisely what lets signature verification stay on.

### 8.2 Flake `nixConfig` acceptance caveat (F394)

```nix
nixConfig = {
  extra-substituters        = [ "https://registry.aos.dev/core/nar" ];
  extra-trusted-public-keys = [ "aos-core:base64publickeyhere==" ];
};
```

Flake-level `nixConfig` substituters/keys are only used after the user accepts
them (or the flake is already trusted). For unattended/CI hosts prefer the
`nix.conf` form, or pass `--accept-flake-config`.

### 8.3 The substitution request/verify flow (F395)

```
host nix                          AOS cache (URL from registry.toml [[caches]] / override)
   │  GET /nix-cache-info          │   StoreDir/WantMassQuery/Priority   (§4)
   │ ─────────────────────────────►│
   │  GET /<storehash>.narinfo      │   field-mapped from PackageMeta     (§5)
   │ ─────────────────────────────►│
   │      verify Sig: against       │
   │      trusted-public-keys (§6)  │
   │  GET /nar/<key>.nar.zst        │   content-addressed blob            (§7)
   │ ─────────────────────────────►│
   │      verify NarHash, decompress│
```

`apm`, by contrast, fetches the narinfo and verifies the `.nar.zst` against its
`FileHash` ([`download.rs:191-204`](../../../crates/aos-package/src/download.rs)),
**never** the narinfo `Sig:` — its trust is rooted in the signed git tag chain
(§6.2). The two clients share the same blobs and narinfo bytes but trust them via
independent layers (ref doc §1, §10.4).

---

## 9. Feature coverage

Features from the validation report
([validation-report.md](./validation-report.md) §81-114, recommendation P0 #1)
that WS-06 closes:

| Feature(s) | What | This WS |
|---|---|---|
| **F362** | Distinct AOS-`priority` vs `nix-cache-info` `Priority` | §4 (two knobs) |
| **F363–F366** | `nix-cache-info` emitter (StoreDir / WantMassQuery / Priority) | §4 |
| **F367–F376, F378–F383** | narinfo generator + every narinfo field mapping | §5.1, §5.2 |
| **F377** | narinfo `Sig` generated | §6.1 |
| **F385** | Nix fingerprint signed message `(StorePath, NarHash, NarSize, References)` | §6.1 |
| **F386** | Two published pubkey encodings (apm + nix form) | §6.3 |
| **F387** | per-narinfo `Sig` satisfies `require-sigs` (rationale) | §6.2 |
| **F388 / F389** | NAR blob URL key — colon retained / colon-free fallback | §7 |
| **F390** | Stock-`nix` host substituter wiring (`extra-substituters`) | §8.1 |
| **F392** | Nix-form `trusted-public-keys` value `<name>:<base64>` | §6.3, §8.1 |
| **F393** | Do **not** disable `require-sigs` | §8.1 |
| **F394** | Flake `nixConfig` acceptance caveat | §8.2 |
| **F395** | Substitution request/verify flow | §8.3 |
| **F94** | Package metadata = narinfo source | §2.3, §5.1 |
| **F354** (with WS-05) | Strict-superset cache origin (3 endpoints) | §3, §4, §5, §7 |
| **F361** (with WS-05) | Standard relative endpoint paths (producer commitment) | §3.1, §5.5 |

> Cross-WS: **F386 / F392** also touch WS-04 (the key lives in `keys.toml`); WS-06
> owns the *nix-form projection* of it. **F388/F389** ride the CURRENT
> `download.rs` colon handling. `FileHash` / `FileSize` are computed at emit time
> from the `.nar.zst` (§5.2.1) — narinfo-driven since commit `7149acf6`, no schema
> change required.

---

## 10. CURRENT → TARGET mapping

| CURRENT (`path:line`) | TARGET (WS-06) | Notes |
|---|---|---|
| `aos-server::narinfo::format_narinfo(&DbPathInfo,…)` ([`narinfo.rs:27`](../../../crates/aos-server/src/narinfo.rs)) | publish-time `emit_narinfos(&HashMap<_,PackageMeta>,…)` (§5.5) | DB-fed runtime daemon → static file from git tree |
| `cache_info_handler` ([`routes.rs:123-148`](../../../crates/aos-server/src/routes.rs), `Priority: 30` at `:145`) | `emit_nix_cache_info(&CacheInfoConfig)` (§4) | per-request handler → static file written once |
| `aos-server::sign::NarInfoSigner::fingerprint` ([`sign.rs:57-60`](../../../crates/aos-server/src/sign.rs)) | shared `nar_fingerprint` in `aos-core::nar::info` (§6.1) | lift composition so producer + daemon agree |
| `nar::info::format` ([`info.rs:81`](../../../crates/aos-core/src/nar/info.rs)) | **reused verbatim** | only the *builder* (PackageMeta→NarInfo) is new |
| `build_hash_index` ([`parse.rs:176-196`](../../../crates/aos-package/src/registry/parse.rs)) | add parallel `ReferenceIndex` (hash → basename) (§5.3) | name index → basename index for `References` |
| `PlatformEntry` / `PackageMeta` (no `download_hash`/`download_size`, removed in `7149acf6`) ([`parse.rs:45-51`](../../../crates/aos-package/src/registry/parse.rs), [`types.rs:44-74`](../../../crates/aos-package/src/types.rs)) | compute `FileHash`/`FileSize` at emit time from the `.nar.zst` (§5.2.1) | narinfo-driven — no schema change |
| `nar_cache_filename` ([`download.rs:314-317`](../../../crates/aos-package/src/download.rs)) | `nar_url_key_colon_free` (§7) | same colon→dash transform, reused for the colon-free `URL:` |
| `SigningConfig.public_key` apm form ([`types.rs:246-247`](../../../crates/aos-package/src/types.rs)) | `nix_pubkey_from_apm` projection (§6.3) | one key → nix `<name>:<base64>` |

---

## 11. Task checklist

**Compressed-NAR hash/size (emit-time, no schema change):**

- [ ] Compute `FileHash` (SHA-256 of the `.nar.zst` bytes) + `FileSize` (byte
      length) at emit time from each `nar/<key>.nar.zst` blob (§5.2.1) — these were
      removed from the schema in `7149acf6` and are narinfo-driven. Surface them via
      a `CompressedNar { file_hash, file_size }` input to the builder. Apply the same
      compute to each `SysrootImageEntry`'s image blob.

**`nix-cache-info` (§4):**

- [ ] `CacheInfoConfig { store_dir, priority }` + `emit_nix_cache_info` (StoreDir
      from publisher, not metadata; `priority` defaults to `30`).
- [ ] Tests: `nix_cache_info_default_store_dir`, `nix_cache_info_custom_priority`,
      `nix_cache_info_omits_capabilities`.

**narinfo generator (§5):**

- [ ] New module `crates/aos-package/src/registry/nix_cache.rs`.
- [ ] `package_meta_to_narinfo` building `aos_core::nar::info::NarInfo` from
      `PackageMeta`; render via `nar::info::format`.
- [ ] `ReferenceIndex` (hash → `<hash>-<name>` basename) + `expand_references`;
      fail-closed on dangling hash (§5.3).
- [ ] `image_to_narinfo` for each `SysrootImageEntry` (its own store path) (§5.4).
- [ ] `emit_narinfos` writing `<store_path_hash>.narinfo` + `nix-cache-info`.
- [ ] Tests: `expand_references_curl`, `expand_references_empty`,
      `expand_references_dangling_errors`, `image_narinfo_keyed_by_image_hash`,
      `image_narinfo_empty_references`, `emit_narinfos_round_trips_through_parse`,
      `emit_narinfos_filename_is_store_hash`, `emit_narinfos_includes_images`.

**Signing (§6):**

- [ ] Lift `fingerprint` into `aos-core::nar::info` as `nar_fingerprint`; re-export
      from `aos-server::sign` to kill drift.
- [ ] Producer `NarInfoSigner::sign_narinfo` over the **expanded** references,
      reusing the **one** registry Ed25519 key (WS-04).
- [ ] `nix_pubkey_from_apm` projection (apm `<name>:Ed25519:<b64>` → nix
      `<name>:<b64>`) via `parse_signing_key`.
- [ ] Tests: `sig_value_is_name_colon_base64`, `fingerprint_uses_expanded_refs`,
      `fingerprint_matches_server_form`, `nix_pubkey_from_apm_drops_algo`,
      `nix_pubkey_from_apm_rejects_rsa`.

**NAR URL key (§7):**

- [ ] `nar_url_key` (colon retained) + `nar_url_key_colon_free`; a `colon_safe`
      emitter switch.
- [ ] Tests: `nar_url_key_retains_colon`, `nar_url_key_colon_free`,
      `url_field_is_relative_nar_path`.

**Docs (§8):**

- [ ] Stock-`nix` `nix.conf` / flake `nixConfig` / verify-flow guidance (already
      drafted in [`nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md)
      §10; WS-06 owns it as a deliverable).

---

## 12. Cross-references

### Reference set (`docs/registry/`)

- [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) — **the
  target this WS implements**: the strict-superset idea (§2), where the cache
  location comes from (§3), the `nix-cache-info` stub (§5), the narinfo field
  mapping (§6), references basename expansion (§7), the one-key/two-form signing
  (§8), the NAR blob URL key (§9), and dev-shell wiring (§10).
- [repo-layout.md](../../registry/repo-layout.md) — the committed git tree this WS
  reads: `registry.toml` `[[caches]]` (§2, where the cache list lives),
  `keys.toml` trust roster (§3, the one key), `packages/*.toml` (§4, the narinfo
  source), `closures/<hash>` (§5, the bare-hash adjacency format).
- [README.md](../../registry/README.md) — purpose, glossary, doc index.
- [architecture.md](../../registry/architecture.md) — where the NAR cache sits
  relative to the git-over-dumb-HTTP layer.
- [http-layout.md](../../registry/http-layout.md) — full HTTP/object layout and
  CDN TTLs (the `nar/` surface).
- [signing-and-trust.md](../../registry/signing-and-trust.md) — the one-key model,
  name-binding, `tag → tag → commit`.
- [current-state.md](../../registry/current-state.md) — the as-is
  bundle/`creation_token` implementation.

### Plan set (`docs/plans/registry/`)

- [design-brief.md](./design-brief.md) — §13 (Nix binary-cache superset), §11
  (one-key signing) — authoritative intent.
- [validation-report.md](./validation-report.md) — §81-114 + P0 recommendation #1
  (the F362–F395 cluster this WS closes).
- [workstream-05-consumer.md](./workstream-05-consumer.md) — §8, the consumer side
  that *resolves* and *reads* the cache this WS emits.
- [workstream-04-signing-trust.md](./workstream-04-signing-trust.md) — the one-key
  model and `keys.toml` whose pubkey this WS projects into the nix `<name>:<b64>`
  form.
- [workstream-01-object-store.md](./workstream-01-object-store.md),
  [workstream-02-pack-delta-pipeline.md](./workstream-02-pack-delta-pipeline.md) —
  emit the `packages/*.toml` tree + `.nar.zst` blobs this WS projects/points at.
- [open-questions.md](./open-questions.md) — the colon-in-NAR-key edge decision
  (§7).
