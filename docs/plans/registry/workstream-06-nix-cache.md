# Workstream 06 — Nix binary-cache / narinfo (AOT static generation)

> **Status:** **Producer-side work, reusing existing logic.** The registry's Nix
> binary cache is **dumb static files on the HTTP CDN**, pre-generated
> **ahead-of-time (AOT) at publish** and uploaded — there is **no server at
> serve-time**. The narinfo *format + sign + FileHash* logic **already exists** as
> a library (in `aos-core` and `aos-server`) and is labelled **CURRENT(reusable)**.
> WS-06's job is the **TARGET(build)** work: an AOT generator that, for each
> registry store path, emits `<storehash>.narinfo` (signed), `nar/<…>.nar.zst`, and
> `nix-cache-info`, then **uploads them as static CDN files** — **reusing** that
> existing format/sign code (likely extracted into a library so the producer can
> call it without standing up the server). Plus the committed `registry.toml`
> `[[caches]]` pointer. Discrepancies are logged in
> [open-questions.md](./open-questions.md).
>
> **This is neither "client-side only / already done" nor "the running `aos-server`
> cache serves it".** The `aos-server` cache (`routes.rs`
> `cache_info_handler`/`narinfo_handler`/`nar_handler`) is a **live host serving its
> own Nix store** (nix-serve-style) — a **different use case**. The registry
> **never runs that server**; it reuses the *formatting and signing logic* to
> produce static files ahead of time.
>
> **Audience:** implementers building the AOT generator + CDN upload, and architects
> reasoning about the static NAR-cache layer vs the git-metadata layer.
>
> **Grounding:** [design-brief.md](./design-brief.md) **§13** (Nix binary-cache
> superset — AOT static on the CDN) and **§11** / **§14** (the one shared key;
> cache base in the committed `registry.toml` `[[caches]]`), reconciled with the
> reference doc [`nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md)
> and the actual code: `aos-core/src/nar/info.rs`, `aos-server/src/{narinfo.rs,
> compress.rs,sign.rs,routes.rs}`, `aos-package/src/download.rs`,
> `aos-package/src/types.rs`, `aos-package/src/registry/parse.rs`. The code wins for
> *current state*; the design brief is authoritative for *target intent* (AOT static
> generation, not a running server).
>
> **As-built status note:** this workstream is now archival planning context. The
> static cache producer and release upload plumbing have landed locally. Use
> [`../../registry/current-state.md`](../../registry/current-state.md) and
> [`TODO.md`](./TODO.md) for current facts; stock-Nix and service-backed S3/SFTP
> validation is deferred to the follow-up PR tracked in
> [`validation-runbook.md`](./validation-runbook.md).

This is the **producer-side** counterpart to
[workstream-05-consumer.md](./workstream-05-consumer.md) §8 (which *resolves* and
*reads* a static substituter) and to
[workstream-04-signing-trust.md](./workstream-04-signing-trust.md) (the one-key
model). The three stock-Nix files — `nix-cache-info`, `<storehash>.narinfo`,
`nar/<key>.nar.zst` — are **generated AOT at publish and uploaded as static CDN
files**, then **already consumed** by `apm` (the consumer side is done — §2.5). A
non-AOS host running stock `nix` can point `extra-substituters` at the static CDN
base and use it as an ordinary binary cache, signatures intact and `require-sigs`
left on. WS-06's job is to **generate and upload** that static surface (reusing the
format/sign code), make the **registry's** committed `[[caches]]` point at it, and
guarantee every registry-listed store path has its static narinfo/NAR present.

The NAR-cache layer is a **strict superset** of the standard Nix binary cache and
is **orthogonal** to the git-object trust chain that `apm` walks: it is not part
of `apm`'s trust root, and its location is named **in-tree** (the committed
`registry.toml` `[[caches]]`), never in a signed tag (see
[design-brief.md](./design-brief.md) §13, §14, and
[`nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md) §1, §3).

---

## 1. Where this sits in the plan

```
 WS-01 object store ─┐
 WS-02 pack/delta   ─┤  emit the git-metadata layer (packages/ TOMLs)
 WS-03 channels     ─┤
 WS-04 signing      ─┘  the ONE Ed25519 key (also signs narinfos)
        │
        ▼
 WS-06 AOT GENERATE ◄── THIS doc: at publish, for each registry store path,
   + UPLOAD (static)     GENERATE nix-cache-info + <storehash>.narinfo (signed)
        │                + nar/<…>.nar.zst, REUSING the format/sign logic,
        │                then UPLOAD as static CDN files. Commit [[caches]].
        ▼
 CDN (dumb static)  ◄── {cache-base}/nix-cache-info, /<storehash>.narinfo,
        │                /nar/<…>.nar.zst — NO running process at serve-time
        ▼
 WS-05 CONSUMER §8 ──► resolves the cache from committed [[caches]] (DONE),
 stock `nix` host  ──► points extra-substituters at the static base, verifies Sig:
```

The cache surface is **dumb static files generated ahead of time**, not a running
process. WS-06 adds **no new git surface** (the git layer remains the metadata
source of truth), but it does add a **real producer**: the AOT generator + the CDN
upload + the reuse glue. The narinfo is **not** re-derived from `packages/*.toml`;
it is generated from each store path's `PathInfo` (NarHash/NarSize/References/
Deriver from the Nix store) and keyed by store hash. The git registry's TOMLs are
the *metadata* layer; the *bytes* are the static cache files.

> **CURRENT(reusable), NOT a server.** A full nix-serve-style cache server exists
> in [`aos-server/src/routes.rs`](../../../crates/aos-server/src/routes.rs)
> (`cache_info_handler` [`routes.rs:123`](../../../crates/aos-server/src/routes.rs),
> `narinfo_handler` [`routes.rs:157`](../../../crates/aos-server/src/routes.rs),
> `nar_handler` [`routes.rs:223`](../../../crates/aos-server/src/routes.rs)) — but
> that is a **live host serving its own store**, a **different use case the registry
> never runs**. What WS-06 reuses is the **library logic** those handlers call:
> `narinfo::format_narinfo` ([`narinfo.rs:27`](../../../crates/aos-server/src/narinfo.rs)),
> built on `aos-core::nar::info`, plus `sign.rs` and `compress.rs`. WS-06 calls that
> logic **offline** to write static files.

---

## 2. CURRENT — what to REUSE (grounded in code)

> **CURRENT(reusable).** The narinfo **format**, the Ed25519 **fingerprint+Sig**,
> and the **FileHash/FileSize** compute all exist as logic today. They are exercised
> by the live `aos-server` cache handlers, but the logic itself is independent of the
> server runtime — it takes a path-info struct and returns narinfo text. WS-06
> **reuses this logic as a library** to generate the static AOT files; it does **not**
> run the server. The consumer (§2.5) is genuinely **done**.

### 2.1 The narinfo format + the `format_narinfo` builder — REUSE as a library

- `NarInfo` struct + `parse` / `format` / `from_path_info` / `store_hash` /
  `basename` live in
  [`aos-core/src/nar/info.rs`](../../../crates/aos-core/src/nar/info.rs).
  `format(&NarInfo) -> String` ([`info.rs:81`](../../../crates/aos-core/src/nar/info.rs))
  emits the canonical line-oriented `Key: value` text
  (StorePath/URL/Compression/FileHash/FileSize/NarHash/NarSize/References/Deriver/
  Sig). `from_path_info(&PathInfoParams)` ([`info.rs:129`](../../../crates/aos-core/src/nar/info.rs))
  builds a `NarInfo` from path metadata + compressed-NAR metadata. **This is the
  shared type the AOT generator emits and the consumer parses** — no new format.
- `narinfo::format_narinfo(&DbPathInfo, store_dir, &CompressionConfig, Option<&NarInfoSigner>)`
  ([`aos-server/src/narinfo.rs:27`](../../../crates/aos-server/src/narinfo.rs))
  builds and renders the narinfo, populating **every** field including the NAR
  `URL:` ([`narinfo.rs:37`](../../../crates/aos-server/src/narinfo.rs)), References
  basename-expansion ([`narinfo.rs:71-74`](../../../crates/aos-server/src/narinfo.rs)),
  and the `Sig:` ([`narinfo.rs:87-93`](../../../crates/aos-server/src/narinfo.rs)).
  **REUSE this rendering logic.** Note it currently takes `&DbPathInfo`
  ([`narinfo.rs:5`](../../../crates/aos-server/src/narinfo.rs)) and lives in the
  server crate — see §3 for extracting it so the producer can call it without the
  server runtime.

> The narinfo is keyed by **store hash** off the path's `PathInfo`
> (NarHash/NarSize/References/Deriver), **not** off the git tree's `PackageMeta`.
> That is correct: the narinfo/NAR bytes belong to the cache layer, decoupled from
> the git metadata layer. There is no plan to re-emit narinfos from `packages/*.toml`.

### 2.2 FileHash / FileSize compute — REUSE `compute_file_hash_size`

`format_narinfo` computes `FileHash` / `FileSize` for the **compressed** stream the
client downloads. For `Compression::None` they equal `NarHash` / `NarSize`; for
`zstd` / `xz` it calls
`compute_file_hash_size(&info.path, compression)`
([`narinfo.rs:45-59`](../../../crates/aos-server/src/narinfo.rs)), which dumps and
compresses the path once and SHA-256s the compressed bytes
([`compress.rs:143`](../../../crates/aos-server/src/compress.rs)). Both fields are
**always emitted** so the consumer can verify the compressed stream.

For AOT generation the producer must produce the **same** `nar/<…>.nar.zst` bytes it
hashes. **REUSE `compute_file_hash_size`** (or, better for AOT, capture the hash/size
**while writing** the `.nar.zst` file in one pass, so the producer doesn't compress
twice — the current path buffers the whole compressed stream in memory
([`compress.rs:142`](../../../crates/aos-server/src/compress.rs)), which a streaming
AOT writer should avoid for large closures).

This is exactly the narinfo-driven contract `apm` relies on: `download_hash` /
`download_size` were removed from the registry schema in commit `7149acf6` ("apm:
narinfo-driven NAR downloads"). The package TOML no longer carries the
compressed-NAR hash/size — the static narinfo is their single source of truth.

### 2.3 The Ed25519 `Sig:` (Nix fingerprint) — REUSE `NarInfoSigner`

[`aos-server/src/sign.rs`](../../../crates/aos-server/src/sign.rs) implements the
exact Nix narinfo fingerprint and Ed25519 signature reusing a single key:

```rust
// aos-server/src/sign.rs:57-60  — the Nix narinfo fingerprint
pub fn fingerprint(store_path: &str, nar_hash: &str, nar_size: i64, refs: &[String]) -> String {
    let refs_str = refs.join(",");
    format!("1;{store_path};{nar_hash};{nar_size};{refs_str}")
}
// sign.rs:14-31  load(key_file) parses a `name:base64` key file
// sign.rs:44-54  sign() → "name:base64_sig"; first 32 bytes of the Nix key = ed25519 seed
```

`format_narinfo` calls `NarInfoSigner::fingerprint(...)` then `signer.sign(...)` and
appends the `Sig:` line ([`narinfo.rs:87-93`](../../../crates/aos-server/src/narinfo.rs)).
The fingerprint's `refs` are the **expanded basenames** already produced for the
`References:` line (§2.4) — so the signed message matches what stock `nix`
recomputes. **REUSE this signer** in the AOT generator, loading the **one Ed25519
key** (the same key git signing uses, §11 of the design brief). The static narinfo
is signed **at generation time**, then served as a dumb file — verification happens
entirely client-side.

### 2.4 References basename-expansion — REUSE the same mapping

`format_narinfo` emits `References:` as space-separated **basenames**, mapping each
stored reference through `basename(r)`
([`narinfo.rs:71-74`](../../../crates/aos-server/src/narinfo.rs)). The producer must
expand refs the same way so the signed fingerprint matches what stock `nix`
recomputes. REUSING `format_narinfo` gets this for free.

### 2.5 The narinfo-driven consumer — DONE (no work)

`apm`'s downloader is narinfo-first (commit `7149acf6`,
[`aos-package/src/download.rs`](../../../crates/aos-package/src/download.rs)) and
consumes a **dumb static** narinfo cache as-is:

- `fetch_narinfos` GETs `<mirror_url>/<storeHash>.narinfo` and parses it via
  `aos_core::nar::info` ([`download.rs:107`](../../../crates/aos-package/src/download.rs)),
  with `narinfo_url(mirror_url, store_path)` deriving the file name from
  `narinfo::store_hash` ([`download.rs:74`](../../../crates/aos-package/src/download.rs)).
- the NAR URL is taken **from the narinfo's `URL:` field** —
  `join_cache_url(&resolved.req.mirror_url, &resolved.narinfo.url)`
  ([`download.rs:184`](../../../crates/aos-package/src/download.rs)) — the consumer
  never constructs a NAR key itself, so a static `nar/<…>.nar.zst` named by the
  generator works as long as the narinfo `URL:` points at it.
- `FileHash` / `NarHash` / `References` / `Deriver` all come **from the narinfo**;
  the compressed stream is verified by SHA-256 against the narinfo `FileHash`
  ([`download.rs:187`](../../../crates/aos-package/src/download.rs)).
- `resolve_mirror` ([`download.rs:85-97`](../../../crates/aos-package/src/download.rs))
  picks the highest-priority `[[caches]]` entry via `resolve_mirrors`
  ([`registry_ops.rs:404-410`](../../../crates/aos-package/src/registry_ops.rs)),
  falling back to `{registry.url}`.

This is a **static-cache consumer** — it issues plain GETs and needs **no running
server**, only the static files WS-06 generates. **No consumer work in WS-06.**

---

## 3. TARGET — the AOT static generator + upload (the real WS-06 work)

The producer pipeline, run **at publish**, for every store path the registry lists:

```
publish:
│
├─ 0. (reuse glue) extract format_narinfo + NarInfoSigner + compute_file_hash_size
│        into a library callable WITHOUT the server runtime               (§3.1)
│
├─ for each registry store path (packages/*.toml store_path + SysrootImageEntry):
│   ├─ 1. read PathInfo (NarHash/NarSize/References/Deriver) from the Nix store (§3.2)
│   ├─ 2. compress once while computing FileHash/FileSize                    (§3.2)
│   ├─ 3. name nar/<storehash>-<filehash>.nar.zst from captured FileHash    (§3.2)
│   ├─ 4. render <storehash>.narinfo via format_narinfo, signed w/ the key   (§3.2)
│   └─ 5. UPLOAD <storehash>.narinfo + nar/<…>.nar.zst as static CDN files    (§3.3)
│
├─ 6. emit + upload {cache-base}/nix-cache-info (StoreDir/WantMassQuery/Priority) (§3.2,§3.3)
│
└─ 7. commit registry.toml [[caches]] pointing at {cache-base}              (§4)
```

**There IS new code to write** — but it is *reuse glue + AOT orchestration + upload*,
not a greenfield emitter or a new narinfo format.

### 3.1 Extract the narinfo logic so the producer can call it without the server

`format_narinfo` currently lives in the `aos-server` crate and takes `&DbPathInfo`
([`narinfo.rs:5,27`](../../../crates/aos-server/src/narinfo.rs)); `NarInfoSigner` and
`compute_file_hash_size` likewise live under `aos-server`
([`sign.rs`](../../../crates/aos-server/src/sign.rs),
[`compress.rs:143`](../../../crates/aos-server/src/compress.rs)). The AOT generator
must call them **without** standing up an HTTP server.

- Extract the format/sign/FileHash logic into a library reachable by the producer —
  either into `aos-core` (next to `nar::info`) or a small `aos-cache`/dedicated
  crate that both `aos-server` and the publisher depend on. `aos-server`'s handlers
  then call the same library, so there is **one** narinfo formatter, not two.
- Generalize the input from `&DbPathInfo` to a path-info value the producer can fill
  from a non-running-daemon source (the Nix store directly). The simplest shape is
  to render via `aos_core::nar::info::from_path_info(&PathInfoParams)`
  ([`info.rs:129`](../../../crates/aos-core/src/nar/info.rs)) — which already takes
  plain fields — and move the **`URL:` construction, FileHash/FileSize compute, and
  `Sig:` signing** that `format_narinfo` does today onto that path so they are shared.

**Signature (proposed), in the extracted library:**

```rust
/// Inputs the AOT generator gathers per store path (from the Nix store, not a daemon).
pub struct CacheEntryInput<'a> {
    pub store_path: &'a str,          // /nix/store/<hash>-<name>
    pub nar_hash: &'a str,            // "sha256:<base16>" (uncompressed NAR)
    pub nar_size: u64,
    pub references: &'a [String],     // full store paths; basename-expanded on emit
    pub deriver: Option<&'a str>,
}

/// Render one signed static narinfo + decide the nar/ filename, REUSING the
/// existing format + fingerprint + Sig logic. `file_hash`/`file_size` describe
/// the compressed bytes the generator just wrote (captured in one pass).
pub fn render_static_narinfo(
    input: &CacheEntryInput<'_>,
    store_dir: &str,
    compression: &CompressionConfig,
    file_hash: &str,
    file_size: u64,
    signer: Option<&NarInfoSigner>,
) -> String;   // body of <storehash>.narinfo

/// nix-cache-info body (StoreDir / WantMassQuery: 1 / Priority).
pub fn nix_cache_info(store_dir: &str, priority: u32) -> String;
```

> This is a **refactor of CURRENT code into a library**, keeping the exact byte
> output. Today the server's `cache_info_handler` builds `nix-cache-info` inline
> ([`routes.rs:123-145`](../../../crates/aos-server/src/routes.rs), `Priority: 30`)
> and `narinfo_handler` builds the body via `format_narinfo`
> ([`routes.rs:211`](../../../crates/aos-server/src/routes.rs)); both should call the
> extracted functions so the static files are byte-identical to what the server would
> serve. The `aos-cache` backends already write `nix-cache-info` (`Priority: 40`) to
> remote stores — that mirror path is a related precedent, not the AOT generator.

### 3.2 Generate the static files (per store path + the cache-info)

For each registry store path, the generator:

1. Reads the path's `PathInfo` from the Nix store (`nix-store --query` /
   `nix path-info`) to fill `CacheEntryInput` (NarHash/NarSize/References/Deriver).
2. Runs `nix-store --dump | zstd` into a temporary file and captures the SHA-256
   and byte length of the compressed output **in the same pass** to get
   `FileHash`/`FileSize` — equivalent to
   `compute_file_hash_size` ([`compress.rs:143`](../../../crates/aos-server/src/compress.rs))
   but streaming, so large closures don't buffer the whole compressed NAR in memory
   ([`compress.rs:142`](../../../crates/aos-server/src/compress.rs)).
3. Renames that file to `nar/<storehash>-<filehash>.nar.zst`, so the exact
   transferred bytes determine the immutable URL.
4. Renders `<storehash>.narinfo` via `render_static_narinfo` (§3.1), passing the
   captured `file_hash`/`file_size` and the `NarInfoSigner` loaded with the one
   Ed25519 key — producing a **signed** static narinfo.
5. Emits one `nix-cache-info` for the whole cache base (`StoreDir: /nix/store`,
   `WantMassQuery: 1`, `Priority:`).

### 3.3 Upload the static files to the CDN

The static files are uploaded under `{cache-base}`:
`{cache-base}/nix-cache-info`, `{cache-base}/<storehash>.narinfo`,
`{cache-base}/nar/<storehash>-<filehash>.nar.zst`. Upload is part of the publish
pipeline (alongside the git objects/packs upload — see
[publishing.md](../../registry/publishing.md) / WS-01/02). The
[`aos-cache`](../../../crates/aos-cache/src/backend/mod.rs) backend traits
(`put`/`put_narinfo` over S3/SFTP/HTTP/FS) are a candidate transport for the upload
step, but the **content is generated AOT by §3.2**, not served live. CDN TTL: the
narinfo/`nar` are immutable per store hash and **MAY** have very high TTL
(design-brief §4); `nix-cache-info` is small and stable.

---

## 4. Wire the committed `registry.toml` `[[caches]]`

`apm`'s `resolve_mirror` reads `registry.toml` `[[caches]]` (sorted by
`CacheEntry.priority`) and falls back to `{registry.url}` when the list is empty
([`download.rs:85-97`](../../../crates/aos-package/src/download.rs),
[`registry_ops.rs:404-410`](../../../crates/aos-package/src/registry_ops.rs)). Commit
a `[[caches]]` entry pointing at `{cache-base}` (the static CDN prefix the generator
uploaded to), so the consumer selects the AOS cache instead of falling back:

```toml
# registry.toml at the git-repo root (committed tree file, authenticated by the
# signed tag — design-brief §14; NOT advertised inside the tag).
[[caches]]
url = "https://registry.aos.dev/core"   # the base apm appends <storeHash>.narinfo to
priority = 100
```

`apm` then GETs `<url>/<storeHash>.narinfo` (a **static file**) and follows the
narinfo's own `URL:` to the static `nar/<…>.nar.zst`
([`download.rs:184`](../../../crates/aos-package/src/download.rs)). The narinfo's
`URL:` field is authoritative and the consumer follows it verbatim — so the
generator's `nar/` filename (§3.2) and the narinfo `URL:` must agree.

> Two **independent priority knobs** (F362): the `nix-cache-info` `Priority:` line
> (stock-`nix` cache ordering) is distinct from the AOS `CacheEntry.priority`
> ([`types.rs:580-593`](../../../crates/aos-package/src/types.rs)) that `apm`'s
> `resolve_mirrors` sorts. The generator sets the former; `registry.toml` sets the
> latter.

---

## 5. Presence/completeness check at publish

The AOT generator **is** the presence guarantee: it walks every registry-listed
store path (`packages/*.toml` `store_path`, plus each `SysrootImageEntry`) and emits
a static narinfo + NAR for each. The publish step should **fail closed** if any
listed store path is missing from the local Nix store (no NAR to dump) — otherwise
`apm` would later 404 on a narinfo for a path with no bytes. This is a producer-side
completeness assertion over the registry's listed paths, not a runtime query against
a server.

---

## 6. Stock-`nix` consumer wiring (docs)

The CDN base **already** holds `nix-cache-info` + `*.narinfo` + `nar/` with a signed
`Sig:` once §3 runs. A non-AOS host running stock `nix` consumes it as an ordinary
**static** binary cache; WS-06 owns the **docs** for this path (the plumbing is stock
Nix). The AOS-host resolution path is WS-05 §8.

### 6.1 `nix.conf` (F390)

```ini
# /etc/nix/nix.conf  (or ~/.config/nix/nix.conf)
extra-substituters         = https://registry.aos.dev/core
extra-trusted-public-keys  = aos-core:base64publickeyhere==
```

- Use the `extra-` prefix (**appends** to defaults) so `cache.nixos.org` is
  retained.
- The key value is the **`<name>:<base64>`** nix encoding — the same key bytes the
  generator signs with (`NarInfoSigner::load` parses a `name:base64` key,
  [`sign.rs:14-31`](../../../crates/aos-server/src/sign.rs)) and emits in the `Sig:`
  line (F392).
- **Do not** set `require-sigs = false` (**F393**). The generator emits `Sig:` at
  publish (§2.3, §3.2), which is precisely what lets signature verification stay on
  against a dumb static cache.

### 6.2 Flake `nixConfig` acceptance caveat (F394)

```nix
nixConfig = {
  extra-substituters        = [ "https://registry.aos.dev/core" ];
  extra-trusted-public-keys = [ "aos-core:base64publickeyhere==" ];
};
```

Flake-level `nixConfig` substituters/keys are only used after the user accepts them
(or the flake is already trusted). For unattended/CI hosts prefer the `nix.conf`
form, or pass `--accept-flake-config`.

### 6.3 The substitution request/verify flow (F395)

```
host nix                          AOS static cache (CDN base from registry.toml [[caches]])
   │  GET /nix-cache-info          │   static file: StoreDir/WantMassQuery/Priority  (§3.2)
   │ ─────────────────────────────►│
   │  GET /<storehash>.narinfo      │   static file rendered AOT by §3.2
   │ ─────────────────────────────►│
   │      verify Sig: against       │
   │      trusted-public-keys (§2.3)│
   │  GET /nar/<key>.nar.zst        │   static content-addressed blob (§3.2)
   │ ─────────────────────────────►│
   │      verify NarHash, decompress│
```

There is **no process on the right** — every GET hits a pre-generated static file.
`apm`, by contrast, fetches the static narinfo and verifies the `.nar.zst` against
its `FileHash` ([`download.rs:187`](../../../crates/aos-package/src/download.rs)),
**never** the narinfo `Sig:` — its trust is rooted in the signed git tag chain. Both
clients share the same static blobs and narinfo bytes but trust them via independent
layers (design-brief §11, §13).

---

## 7. Feature coverage

Features from the validation report
([validation-report.md](./validation-report.md) §81-114, recommendation P0 #1). The
table marks each as **CURRENT(reusable)** (logic exists, reuse it), **TARGET(build)**
(the AOT generator/upload/glue WS-06 builds), or **DONE** (consumer, no work).

| Feature(s) | What | Status |
|---|---|---|
| **F362** | Distinct AOS-`priority` vs `nix-cache-info` `Priority` | CURRENT(reusable) — server `Priority: 30` ([`routes.rs:145`](../../../crates/aos-server/src/routes.rs)) / backend `40` vs `CacheEntry.priority` ([`types.rs:580-593`](../../../crates/aos-package/src/types.rs)); generator sets the cache-info `Priority` (§3.2) |
| **F363–F366** | `nix-cache-info` (StoreDir / WantMassQuery / Priority) | TARGET(build) — generate + upload it AOT (§3.2, §3.3), reusing the inline body in `cache_info_handler` ([`routes.rs:123`](../../../crates/aos-server/src/routes.rs)) |
| **F367–F376, F378–F383** | narinfo generator + every narinfo field | CURRENT(reusable) — `format_narinfo` ([`narinfo.rs:27`](../../../crates/aos-server/src/narinfo.rs)) + `nar::info::format` ([`info.rs:81`](../../../crates/aos-core/src/nar/info.rs)); TARGET: call it AOT per store path (§3.2) |
| **F377** | narinfo `Sig` generated | CURRENT(reusable) — `format_narinfo` signs ([`narinfo.rs:87-93`](../../../crates/aos-server/src/narinfo.rs)); TARGET: sign at publish (§3.2) |
| **F385** | Nix fingerprint `(StorePath, NarHash, NarSize, References)` | CURRENT(reusable) — `NarInfoSigner::fingerprint` ([`sign.rs:57-60`](../../../crates/aos-server/src/sign.rs)) |
| **F386** | Two published pubkey encodings (apm + nix form) | TARGET(build) — publish the nix `<name>:<base64>` form alongside the apm key (§6.1) |
| **F387** | per-narinfo `Sig` satisfies `require-sigs` | CURRENT(reusable) — sign logic exists ([`narinfo.rs:87-93`](../../../crates/aos-server/src/narinfo.rs)); TARGET: emit signed static narinfo (§3.2) |
| **F388 / F389** | NAR blob URL key (colon-in-filename handling) | CURRENT(reusable) — URL `nar/{hash}-{narhash}.{ext}` (colon→dash) ([`narinfo.rs:37`](../../../crates/aos-server/src/narinfo.rs)); consumer follows narinfo `URL:` verbatim ([`download.rs:184`](../../../crates/aos-package/src/download.rs)); TARGET: write the `nar/` file under that name (§3.2) |
| **F390** | Stock-`nix` host substituter wiring | TARGET (docs) — §6.1 |
| **F392** | Nix-form `trusted-public-keys` value `<name>:<base64>` | CURRENT(reusable) — signer loads a `name:base64` key ([`sign.rs:14-31,44-54`](../../../crates/aos-server/src/sign.rs)); TARGET: surface that pubkey in docs/registry (§6.1) |
| **F393** | Do **not** disable `require-sigs` | CURRENT(reusable) — `Sig:` always emitted by the logic (§2.3) |
| **F394** | Flake `nixConfig` acceptance caveat | TARGET (docs) — §6.2 |
| **F395** | Substitution request/verify flow | TARGET(build) — generate all three static files (§3.2, §3.3); docs §6.3 |
| **F94** | Package metadata vs narinfo source | CURRENT — narinfo from each path's `PathInfo`, git TOMLs are the *metadata* layer (§1, §2.1) |
| **F354** (with WS-05) | Strict-superset cache origin (3 static files) | TARGET(build) — generate `nix-cache-info` + `*.narinfo` + `nar/` AOT (§3) |
| **F361** (with WS-05) | Standard relative endpoint paths | DONE (consumer) — follows relative narinfo `URL:` via `join_cache_url` ([`download.rs:65-71,184`](../../../crates/aos-package/src/download.rs)); TARGET: generator emits relative `URL:` (§3.2) |

> **Producer is the work.** WS-06 builds the AOT generator + CDN upload + the
> reuse-glue extraction (§3), surfaces the cache URL in the committed `[[caches]]`
> (§4), surfaces the nix-form pubkey for stock hosts (§6.1, F386/F392), and writes
> the stock-`nix` docs (§6). The **consumer** (`apm` narinfo-driven since `7149acf6`)
> is **done** (§2.5) — no schema change required.

---

## 8. CURRENT(reusable) → TARGET(build) map

| CURRENT(reusable) logic (`path:line`) | TARGET (WS-06 produces) | Notes |
|---|---|---|
| `format_narinfo(&DbPathInfo,…)` renderer ([`narinfo.rs:27`](../../../crates/aos-server/src/narinfo.rs)) | extract to a library taking a plain path-info; render static narinfo per registry store path (§3.1, §3.2) | one formatter shared by server + producer; do **not** re-emit from the git tree |
| `nix-cache-info` body in `cache_info_handler` ([`routes.rs:123-145`](../../../crates/aos-server/src/routes.rs)) | extract `nix_cache_info(...)`; generate + upload one static `nix-cache-info` (§3.1–§3.3) | byte-identical to what the server serves |
| FileHash/FileSize compute ([`narinfo.rs:45-59`](../../../crates/aos-server/src/narinfo.rs), [`compress.rs:143`](../../../crates/aos-server/src/compress.rs)) | reuse, or capture hash/size while writing `nar/<…>.nar.zst` in one streaming pass (§3.2) | avoid double compression / in-memory buffering for large closures |
| Ed25519 fingerprint + `Sig:` ([`sign.rs:14-60`](../../../crates/aos-server/src/sign.rs), [`narinfo.rs:87-93`](../../../crates/aos-server/src/narinfo.rs)) | sign each static narinfo at publish with the one key; publish the nix-form pubkey (§3.2, §6.1) | sign logic reused; signing moves to generation time |
| References basename-expansion ([`narinfo.rs:71-74`](../../../crates/aos-server/src/narinfo.rs)) | reused via `format_narinfo` so the signed fingerprint matches stock `nix` (§2.4) | producer must expand refs identically |
| NAR URL scheme ([`narinfo.rs:37`](../../../crates/aos-server/src/narinfo.rs)); consumer follows it ([`download.rs:184`](../../../crates/aos-package/src/download.rs)) | write `nar/<storehash>-<filehash>.nar.zst` under that exact name (§3.2) | narinfo `URL:` and the static file name must agree; the transferred bytes determine the immutable URL |
| `resolve_mirror` / `resolve_mirrors` over `[[caches]]` ([`download.rs:85-97`](../../../crates/aos-package/src/download.rs), [`registry_ops.rs:404-410`](../../../crates/aos-package/src/registry_ops.rs)) | **commit a `[[caches]]`** entry pointing at `{cache-base}` (§4) | resolution exists (DONE); the registry needs the committed entry |
| narinfo-driven consumer ([`download.rs`](../../../crates/aos-package/src/download.rs), `7149acf6`) | — (DONE) | consumes the static cache as-is; no WS-06 work |

---

## 9. Task checklist (producer-side)

**Reuse glue — extract the narinfo logic into a callable library (§3.1):**

- [ ] Move `format_narinfo` + `nix-cache-info` body + `NarInfoSigner` +
      `compute_file_hash_size` into a library both `aos-server` and the publisher
      depend on (e.g. `aos-core` next to `nar::info`), keeping byte-identical output.
- [ ] Generalize the input from `&DbPathInfo` to a plain `CacheEntryInput`
      (store_path/nar_hash/nar_size/references/deriver) the producer fills from the
      Nix store, not a running daemon.

**AOT generate the static files (§3.2):**

- [ ] For each registry store path (`packages/*.toml` `store_path` + each
      `SysrootImageEntry`): read `PathInfo`, write
      `nar/<storehash>-<filehash>.nar.zst`, capture FileHash/FileSize in one pass.
- [ ] Render `<storehash>.narinfo` via the extracted renderer, **signed** with the
      one Ed25519 key.
- [ ] Generate one `nix-cache-info` (`StoreDir` / `WantMassQuery: 1` / `Priority`).
- [ ] Fail closed at publish if any registry-listed store path is missing locally (§5).

**Upload as static CDN files (§3.3):**

- [ ] Upload `nix-cache-info` + `<storehash>.narinfo` + `nar/<…>.nar.zst` under
      `{cache-base}` (immutable per store hash → high CDN TTL).

**Wire + verify (§4):**

- [ ] Commit a `registry.toml` `[[caches]]` entry pointing at `{cache-base}` so
      `resolve_mirror` selects it instead of falling back to `{registry.url}`
      ([`download.rs:85-97`](../../../crates/aos-package/src/download.rs)).
- [ ] End-to-end smoke: `apm` GETs `<url>/<storeHash>.narinfo` (static) and follows
      the narinfo `URL:` to the static `nar/…`; stock `nix` substitutes from the same
      base with `require-sigs` on.

**Stock-`nix` docs + nix-form pubkey (§6, F386/F390/F392/F394):**

- [ ] Surface the signer's pubkey in the nix `<name>:<base64>` form for stock hosts
      (the signer loads a `name:base64` key, [`sign.rs:14-31`](../../../crates/aos-server/src/sign.rs)).
- [ ] Stock-`nix` `nix.conf` / flake `nixConfig` / verify-flow guidance (§6;
      drafted in [`nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md)).

### Tests

- [ ] **Unit (extracted library):** `render_static_narinfo` output round-trips
      through `aos_core::nar::info::parse` ([`info.rs:19`](../../../crates/aos-core/src/nar/info.rs))
      and is byte-identical to the server's `format_narinfo`
      ([`narinfo.rs:27`](../../../crates/aos-server/src/narinfo.rs)) for the same
      `PathInfo` + `CompressionConfig` + signer (golden test guarding the refactor).
- [ ] **Unit (fingerprint/Sig):** a static narinfo's `Sig:` verifies against the
      pubkey using the Nix fingerprint `1;{store_path};{nar_hash};{nar_size};{refs}`
      ([`sign.rs:57-60`](../../../crates/aos-server/src/sign.rs)), with refs as the
      basename-expanded `References:` (§2.4).
- [ ] **Unit (FileHash/FileSize):** the captured-in-one-pass hash/size of
      `nar/<…>.nar.zst` equals `compute_file_hash_size`
      ([`compress.rs:143`](../../../crates/aos-server/src/compress.rs)) for the same
      path + compression (guards the streaming optimization).
- [ ] **Integration (generate→serve-static→consume):** run the generator over a
      fixture store path, serve the output directory as **dumb static files** (no
      `aos-server`), and assert `apm` (`fetch_narinfos` + `download_one`,
      [`download.rs:107,184`](../../../crates/aos-package/src/download.rs)) installs
      and verifies `FileHash` ([`download.rs:187`](../../../crates/aos-package/src/download.rs)).
- [ ] **Integration (stock `nix`):** point `extra-substituters` at the static output
      dir with `require-sigs` on and `extra-trusted-public-keys` set; assert a stock
      `nix` substitution succeeds (Sig verifies).
- [ ] **Completeness:** the generator fails closed when a registry-listed
      `store_path` is absent from the local Nix store (§5).

---

## 10. Cross-references

### Reference set (`docs/registry/`)

- [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) — the
  strict-superset intent the AOT static surface satisfies: the superset idea (§2),
  where the cache location comes from (§3), the `nix-cache-info` stub (§5), the
  narinfo field mapping (§6), references basename expansion (§7), the one-key signing
  (§8), the NAR blob URL key (§9), and dev-shell wiring (§10).
- [repo-layout.md](../../registry/repo-layout.md) — the committed git tree:
  `registry.toml` `[[caches]]` (the cache list WS-06 commits an entry into),
  `keys.toml` trust roster (the one key), `packages/*.toml` (the metadata layer),
  `closures/<hash>`.
- [http-layout.md](../../registry/http-layout.md) — the full HTTP/object layout and
  CDN TTLs (the static `nar/` + narinfo surface).
- [publishing.md](../../registry/publishing.md) — the producer pipeline this AOT
  generation + upload step plugs into.
- [signing-and-trust.md](../../registry/signing-and-trust.md) — the one-key model
  the narinfo `Sig:` reuses.

### Plan set (`docs/plans/registry/`)

- [design-brief.md](./design-brief.md) — **§13** (Nix binary-cache superset — AOT
  static on the CDN, reuse-don't-run), **§11** (one-key signing), **§14** (cache base
  in the committed `registry.toml` `[[caches]]`) — authoritative intent.
- [validation-report.md](./validation-report.md) — §81-114 + P0 recommendation #1
  (the F362–F395 cluster).
- [workstream-05-consumer.md](./workstream-05-consumer.md) — §8, the consumer side
  that *resolves* and *reads* the static cache (the consumer is DONE — §2.5).
- [workstream-04-signing-trust.md](./workstream-04-signing-trust.md) — the one-key
  model and `keys.toml` whose pubkey is surfaced in the nix `<name>:<b64>` form.
- [workstream-01-object-store.md](./workstream-01-object-store.md),
  [workstream-02-pack-delta-pipeline.md](./workstream-02-pack-delta-pipeline.md) —
  emit the `packages/*.toml` metadata tree and the git objects/packs this WS uploads
  the static cache alongside.
- [open-questions.md](./open-questions.md) — deployment edge decisions (upload
  backends; whether the NAR cache superset ships in the same milestone).
</content>
</invoke>
