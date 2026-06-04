# Workstream 06 — Nix binary-cache / narinfo (MOSTLY DONE — integration only)

> **Status:** **Mostly implemented.** The Nix binary-cache surface
> (`nix-cache-info` + `*.narinfo` + `nar/` + Ed25519 `Sig:`) **already exists**,
> is served by `aos-server`, mirrored by the `aos-cache` backends, and consumed
> end-to-end by `aos-package` (`apm`). As-is code is labelled **ALREADY
> IMPLEMENTED** and cited as `path:line`. The only remaining **TARGET** work is
> *integration*: wiring the committed `registry.toml` `[[caches]]` to point the
> consumer at the existing cache, optionally co-serving that cache from the git
> origin, and a thin registry-specific presence/queryability check. Discrepancies
> are logged in [open-questions.md](./open-questions.md).
>
> **Audience:** implementers wiring `[[caches]]` into the publish/consume path,
> and architects reasoning about the NAR-cache layer vs the git-metadata layer.
> There is **no emitter to build** — `aos-server::narinfo::format_narinfo` and
> `aos-core::nar::info::format` already emit the exact stock-Nix surface.
>
> **Grounding:** [design-brief.md](./design-brief.md) **§13** (Nix binary-cache
> superset) and **§11** (signing & trust — the one shared key), reconciled with
> the reference doc
> [`nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md) and the
> actual code: `aos-core/src/nar/info.rs`, `aos-server/src/{narinfo.rs,
> compress.rs,sign.rs,routes.rs}`, `aos-cache/src/backend/*`,
> `aos-package/src/download.rs`, `aos-package/src/types.rs`,
> `aos-package/src/registry/parse.rs`. The code wins for *current state*; the
> reference doc remains authoritative for *target intent* of the remaining glue.

This is the **integration** counterpart to
[workstream-05-consumer.md](./workstream-05-consumer.md) §8 (which *resolves* and
*reads* a substituter) and to
[workstream-04-signing-trust.md](./workstream-04-signing-trust.md) (the one-key
model). The three stock-Nix files — `nix-cache-info`, `<storehash>.narinfo`,
`nar/<key>.nar.zst` — are **already produced** by `aos-server` (and writable to
S3/SFTP/HTTP/FS by `aos-cache`) and **already consumed** by `apm`. A non-AOS host
running stock `nix` can already use such an origin as an ordinary substituter,
with signatures intact and `require-sigs` left on. WS-06's remaining job is to
make the **registry's** committed `[[caches]]` point at that surface and to
guarantee the registry-listed store paths are present/queryable there.

The NAR-cache layer is a **strict superset** of the standard Nix binary cache and
is **orthogonal** to the git-object trust chain that `apm` walks: it is not part
of `apm`'s trust root, and its location is named **in-tree** (the committed
`registry.toml` `[[caches]]`), never in a signed tag (see
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
 NIX-CACHE SURFACE  ◄── ALREADY IMPLEMENTED: aos-server emits nix-cache-info +
   (aos-server +         *.narinfo + nar/, signs each narinfo with the key;
    aos-cache)           aos-cache mirrors to S3/SFTP/HTTP/FS
        │
        ▼
 WS-06 INTEGRATION  ◄── THIS doc: point committed [[caches]] at that surface,
        │                  optionally co-serve from the git origin, ensure the
        ▼                  registry-listed store paths are present/queryable
 WS-05 CONSUMER §8 ──► resolves the cache from committed [[caches]] (ALREADY
 stock `nix` host  ──► points extra-substituters at the cache URL, verifies Sig:
```

The nix-cache surface is **already produced and consumed**; WS-06 adds **no new
emitter and no new git surface**. The git layer remains the metadata source of
truth, but the narinfo/NAR live in the **cache** (store-DB-backed,
`DbPathInfo`-keyed), served independently and already read by `apm`. The narinfo
is not re-derived from `packages/*.toml` — it is emitted from the store DB and
keyed by store hash. The git registry's TOMLs (`store_path`/`nar_hash`/
`references`/`closure`) are the *metadata* layer; the *bytes* are in the cache.

> **ALREADY IMPLEMENTED.** A full nix-serve-style cache server exists:
> [`aos-server/src/routes.rs`](../../../crates/aos-server/src/routes.rs) serves
> `/{view}/nix-cache-info` (`cache_info_handler`, [`routes.rs:123`](../../../crates/aos-server/src/routes.rs)),
> `/{view}/{hash}.narinfo` (`narinfo_handler`, [`routes.rs:157`](../../../crates/aos-server/src/routes.rs)),
> and `/{view}/nar/{filename}` (`nar_handler`, [`routes.rs:223`](../../../crates/aos-server/src/routes.rs))
> off its runtime store. The narinfo body comes from
> `narinfo::format_narinfo(&DbPathInfo, store_dir, &CompressionConfig, Some(&signer))`
> ([`narinfo.rs:27`](../../../crates/aos-server/src/narinfo.rs)), built on the
> shared `aos-core::nar::info` types. WS-06 is **not greenfield and not an
> emitter** — it is integration only (see §2.5, §3).

---

## 2. ALREADY IMPLEMENTED (grounded in code)

> **ALREADY IMPLEMENTED.** The full nix-cache surface exists *and is wired
> end-to-end*: `aos-server` emits `nix-cache-info` + `*.narinfo` + serves `nar/`,
> signs each narinfo with an Ed25519 key; `aos-cache` mirrors that surface to
> S3/SFTP/HTTP/FS; and `aos-package` (`apm`) consumes it narinfo-first. There is
> **nothing to build** for the emitter, the signer, the field mapping, the NAR
> URL scheme, or the consumer. The surface is a strict superset of the Nix
> binary-cache protocol *today*. What is missing is **integration** (§2.5).

### 2.1 The narinfo data model + emitter ALREADY EXIST

- `NarInfo` struct + `parse` / `format` / `from_path_info` / `store_hash` /
  `basename` live in
  [`aos-core/src/nar/info.rs`](../../../crates/aos-core/src/nar/info.rs).
  `format(&NarInfo) -> String` ([`info.rs:81`](../../../crates/aos-core/src/nar/info.rs))
  emits the canonical line-oriented `Key: value` text
  (StorePath/URL/Compression/FileHash/FileSize/NarHash/NarSize/References/Deriver/
  Sig). This is the shared narinfo type used by both server and consumer.
- `aos-server` already serves the live cache surface from its store DB:
  `narinfo::format_narinfo(&DbPathInfo, store_dir, &CompressionConfig, Option<&NarInfoSigner>)`
  ([`aos-server/src/narinfo.rs:27`](../../../crates/aos-server/src/narinfo.rs))
  builds and renders the narinfo, populating **every** field including References
  basename-expansion and the live `Sig:`.
- `aos-cache` backends mirror the same surface to remote stores: each backend
  exposes `get_narinfo` / `put_narinfo` / `has` / `get` / `put`
  ([`aos-cache/src/backend/mod.rs:20-23`](../../../crates/aos-cache/src/backend/mod.rs);
  [`s3.rs`](../../../crates/aos-cache/src/backend/s3.rs),
  [`sftp.rs`](../../../crates/aos-cache/src/backend/sftp.rs),
  [`http.rs`](../../../crates/aos-cache/src/backend/http.rs),
  [`fs.rs`](../../../crates/aos-cache/src/backend/fs.rs)) and write `nix-cache-info`
  with `Priority: 40` ([`fs.rs:126`](../../../crates/aos-cache/src/backend/fs.rs),
  [`sftp.rs:143`](../../../crates/aos-cache/src/backend/sftp.rs),
  [`s3.rs:133`](../../../crates/aos-cache/src/backend/s3.rs)).

> The emitter is keyed off the runtime store DB (`DbPathInfo`), **not** the git
> tree's `PackageMeta` — and that is correct: the narinfo/NAR bytes belong to the
> cache layer, keyed by store hash, decoupled from the git metadata layer. There
> is no need (and no plan) to re-emit narinfos from `packages/*.toml`.

### 2.2 `nix-cache-info`, narinfo, and `nar/` endpoints ALREADY served

[`aos-server/src/routes.rs`](../../../crates/aos-server/src/routes.rs) registers
all three stock-Nix endpoints ([`routes.rs:80-89`](../../../crates/aos-server/src/routes.rs)):

| Endpoint | Handler | Code ref |
|---|---|---|
| `/{view}/nix-cache-info` | `cache_info_handler` — `StoreDir`/`WantMassQuery: 1`/`Priority: 30`/`Capabilities:` | [`routes.rs:123`](../../../crates/aos-server/src/routes.rs), `Priority: 30` at [`:145`](../../../crates/aos-server/src/routes.rs) |
| `/{view}/{hash}.narinfo` | `narinfo_handler` → `format_narinfo(&info, store_dir, compression, Some(&signer))` | [`routes.rs:157`](../../../crates/aos-server/src/routes.rs), body at [`:211`](../../../crates/aos-server/src/routes.rs) |
| `/{view}/nar/{filename}` | `nar_handler` — streams the compressed NAR | [`routes.rs:223`](../../../crates/aos-server/src/routes.rs) |

This is a complete nix-serve-style cache server (plus query-missing, upload,
build, gc, and ConnectRPC services on the same port).

### 2.3 FileHash / FileSize emit-time compute ALREADY EXISTS

`format_narinfo` already computes `FileHash` / `FileSize` at emit time. For
`Compression::None` they equal `NarHash` / `NarSize`; for `zstd` / `xz` it runs
`compute_file_hash_size(&info.path, ...)`
([`narinfo.rs:45-59`](../../../crates/aos-server/src/narinfo.rs)) which dumps and
compresses the path once and SHA-256s the compressed bytes
([`compress.rs:143`](../../../crates/aos-server/src/compress.rs)). Both fields are
**always emitted** so the consumer can verify the compressed stream.

This is exactly the narinfo-driven contract `apm` relies on: `download_hash` /
`download_size` were removed from the registry schema in commit `7149acf6` ("apm:
narinfo-driven NAR downloads"). The package TOML no longer carries the
compressed-NAR hash/size — the narinfo is their single source of truth, and the
server already supplies them.

### 2.4 The Ed25519 `Sig:` (Nix fingerprint) ALREADY EXISTS

[`aos-server/src/sign.rs`](../../../crates/aos-server/src/sign.rs) implements the
exact Nix narinfo fingerprint and Ed25519 signature reusing a single key:

```rust
// aos-server/src/sign.rs:57-60  — the Nix narinfo fingerprint
pub fn fingerprint(store_path: &str, nar_hash: &str, nar_size: i64, refs: &[String]) -> String {
    let refs_str = refs.join(",");
    format!("1;{store_path};{nar_hash};{nar_size};{refs_str}")
}
// sign.rs:44-54  sign() → "name:base64_sig"; first 32 bytes of the Nix key = ed25519 seed
// sign.rs:14     load(key_file) parses a `name:base64` key file
```

`format_narinfo` calls `fingerprint(...)` then `signer.sign(...)` and appends the
`Sig:` line ([`narinfo.rs:87-93`](../../../crates/aos-server/src/narinfo.rs)). The
fingerprint's `refs` are the **expanded basenames** already produced for the
`References:` line (§2.6) — so the signed message matches what stock `nix`
recomputes. This is the "fingerprint Sig reusing one key" — done.

### 2.5 The narinfo-driven consumer ALREADY EXISTS

`apm`'s downloader is narinfo-first (commit `7149acf6`,
[`aos-package/src/download.rs`](../../../crates/aos-package/src/download.rs)):

- `fetch_narinfos` GETs `<mirror_url>/<storeHash>.narinfo` and parses it via
  `aos_core::nar::info` ([`download.rs:107`](../../../crates/aos-package/src/download.rs)),
  with `narinfo_url(mirror_url, store_path)` deriving the file name from
  `narinfo::store_hash` ([`download.rs:74`](../../../crates/aos-package/src/download.rs)).
- `download_nars` consumes the parsed narinfo: the NAR URL is taken **from the
  narinfo's `URL:` field** —
  `join_cache_url(&resolved.req.mirror_url, &resolved.narinfo.url)`
  ([`download.rs:184`](../../../crates/aos-package/src/download.rs)) — the consumer
  never constructs a NAR key itself.
- `FileHash` / `NarHash` / `References` / `Deriver` all come **from the narinfo**
  ([`download.rs:191-233`](../../../crates/aos-package/src/download.rs)); the
  compressed stream is verified by SHA-256 against the narinfo `FileHash`
  ([`download.rs:191-204`](../../../crates/aos-package/src/download.rs)).
- `resolve_mirror` ([`download.rs:85-97`](../../../crates/aos-package/src/download.rs))
  already picks the highest-priority `[[caches]]` entry via `resolve_mirrors`
  ([`registry_ops.rs:405-410`](../../../crates/aos-package/src/registry_ops.rs)),
  falling back to `{registry.url}`.

### 2.6 References basename-expansion ALREADY HAPPENS server-side

The server emits `References:` as space-separated **basenames**, mapping each
stored reference through `basename(r)`
([`narinfo.rs:71-74`](../../../crates/aos-server/src/narinfo.rs)). The DB stores
full store paths, so the basename is `<hash>-<name>` directly — stock `nix`
accepts it. No bare-hash→basename projection from the git tree is required,
because the cache narinfos are not built from the git tree.

### 2.7 The actual remaining gap (INTEGRATION only)

| Remaining piece | Why WS-06 | Section |
|---|---|---|
| Point the committed `registry.toml` `[[caches]]` at the existing cache surface | so `apm`'s `resolve_mirror` selects the AOS cache instead of falling back to `{registry.url}` | §3, §4 |
| (Optional) co-serve the cache from the git origin | one host can serve both dumb-HTTP git objects and the `nar/`+narinfo surface | §3, §5 |
| Registry-specific presence/queryability check | ensure every store path the registry lists is actually present/queryable in the cache before publish | §3, §6 |
| Stock-`nix` consumer docs (`extra-substituters`, `require-sigs`) | document pointing a non-AOS host at the (already-emitting) cache | §7 |

Note the two **independent priority knobs** (F362): the `nix-cache-info`
`Priority:` line (Nix-cache preference, stock-`nix`-ordered; `30` from
`cache_info_handler` at [`routes.rs:145`](../../../crates/aos-server/src/routes.rs),
`40` from the `aos-cache` backends) is distinct from the AOS `CacheEntry.priority`
([`types.rs:580-593`](../../../crates/aos-package/src/types.rs)) that `apm`'s
`resolve_mirrors` sorts.

---

## 3. TARGET — the integration steps

The surface already exists; integration is wiring, not building.

```
publish / serve  (the narinfo + nar/ surface is ALREADY produced by
│                 aos-server / mirrored by aos-cache)
│
├─ 1. commit registry.toml [[caches]] pointing at the existing cache URL   (§4)
│        → apm's resolve_mirror / resolve_mirrors selects it (download.rs:85)
│
├─ 2. (optional) co-serve nar/ + *.narinfo + nix-cache-info from the git
│        origin host so one base URL covers both layers                    (§5)
│
└─ 3. presence/queryability check: every store path the registry lists is
         present in the cache (query-missing / backend.has) before publish (§6)
```

There is **no new emitter module**. The relevant code already lives in
`aos-server` (live daemon surface), `aos-cache` (remote backends), `aos-core`
(shared narinfo type), and `aos-package` (consumer + `[[caches]]` resolution).

---

## 4. Wire the committed `registry.toml` `[[caches]]`

`apm`'s `resolve_mirror` already reads `registry.toml` `[[caches]]` (sorted by
`CacheEntry.priority`) and falls back to `{registry.url}` when the list is empty
([`download.rs:85-97`](../../../crates/aos-package/src/download.rs),
[`registry_ops.rs:404-410`](../../../crates/aos-package/src/registry_ops.rs)). The
integration step is to **commit** a `[[caches]]` entry pointing at the cache the
`aos-server`/`aos-cache` surface already serves, so the consumer stops falling
back.

```toml
# registry.toml at the git-repo root
[[caches]]
url = "https://registry.aos.dev/core"   # the base apm appends <storeHash>.narinfo to
priority = 100
```

`apm` then GETs `<url>/<storeHash>.narinfo` (already served by `narinfo_handler`)
and follows the narinfo's own `URL:` to the NAR (already served by `nar_handler`).
No producer change is needed — the narinfo's `URL:` field
([`narinfo.rs:37`](../../../crates/aos-server/src/narinfo.rs)) is authoritative and
the consumer follows it verbatim ([`download.rs:184`](../../../crates/aos-package/src/download.rs)).

> The `nix-cache-info` `Priority:` (`30` from the server) is **unchanged** — it is
> the stock-`nix` ordering knob, distinct from the `[[caches]]` `priority` here
> (§2.7, F362).

---

## 5. (Optional) co-serve the cache from the git origin

If the deployment wants a single base URL for both layers, the git origin host can
also serve the (already-produced) `nix-cache-info` + `*.narinfo` + `nar/` surface —
either by fronting `aos-server` or by syncing an `aos-cache` FS/HTTP backend next
to the dumb-HTTP git tree. The relative-path narinfo `URL:` resolves against
whatever base `apm` selects ([`join_cache_url`](../../../crates/aos-package/src/download.rs)),
so co-serving is purely a placement/deployment choice, not a code change.

---

## 6. Registry-specific presence/queryability check

The one registry-specific guarantee worth adding at publish time: every store path
the committed registry lists (`packages/*.toml` `store_path`, plus each
`SysrootImageEntry`) must be **present/queryable** in the cache the `[[caches]]`
entry points at — otherwise `apm` would fetch a narinfo (or 404) for a path with
no NAR. The pieces to do this already exist:

- `query-missing` on the server
  ([`routes.rs:83`](../../../crates/aos-server/src/routes.rs)) reports which store
  hashes the cache lacks.
- `aos-cache` backends expose `has(...)`
  ([`backend/mod.rs`](../../../crates/aos-cache/src/backend/mod.rs)) for the same
  check against a remote store.

So the remaining work is a thin pre-publish validation that walks the registry's
listed store paths and asserts each is present in the configured cache (failing
closed on a missing path), reusing those existing primitives. This is the only
registry-specific glue; it builds no narinfo and no NAR.

---

## 7. Stock-`nix` consumer wiring (docs)

The cache **already** emits `nix-cache-info` + `*.narinfo` + `nar/` with signed
`Sig:` (§2). A non-AOS host running stock `nix` can consume it as an ordinary
binary cache today; WS-06 owns only the **docs** for this path (the plumbing is
stock Nix). The AOS-host resolution path is WS-05 §8.

### 7.1 `nix.conf` (F390)

```ini
# /etc/nix/nix.conf  (or ~/.config/nix/nix.conf)
extra-substituters         = https://registry.aos.dev/core
extra-trusted-public-keys  = aos-core:base64publickeyhere==
```

- Use the `extra-` prefix (**appends** to defaults) so `cache.nixos.org` is
  retained.
- The key value is the **`<name>:<base64>`** nix encoding — the same key bytes the
  server signs with (`sign.rs` loads a `name:base64` key, [`sign.rs:14-31`](../../../crates/aos-server/src/sign.rs))
  and emits in the `Sig:` line (F392).
- **Do not** set `require-sigs = false` (**F393**). The server already emits `Sig:`
  (§2.4), which is precisely what lets signature verification stay on.

### 7.2 Flake `nixConfig` acceptance caveat (F394)

```nix
nixConfig = {
  extra-substituters        = [ "https://registry.aos.dev/core" ];
  extra-trusted-public-keys = [ "aos-core:base64publickeyhere==" ];
};
```

Flake-level `nixConfig` substituters/keys are only used after the user accepts
them (or the flake is already trusted). For unattended/CI hosts prefer the
`nix.conf` form, or pass `--accept-flake-config`.

### 7.3 The substitution request/verify flow (F395)

```
host nix                          AOS cache (URL from registry.toml [[caches]] / override)
   │  GET /nix-cache-info          │   StoreDir/WantMassQuery/Priority   (§2.2)
   │ ─────────────────────────────►│
   │  GET /<storehash>.narinfo      │   format_narinfo(&DbPathInfo,…)     (§2.1)
   │ ─────────────────────────────►│
   │      verify Sig: against       │
   │      trusted-public-keys (§2.4)│
   │  GET /nar/<key>.nar.zst        │   content-addressed blob            (§2.2)
   │ ─────────────────────────────►│
   │      verify NarHash, decompress│
```

`apm`, by contrast, fetches the narinfo and verifies the `.nar.zst` against its
`FileHash` ([`download.rs:191-204`](../../../crates/aos-package/src/download.rs)),
**never** the narinfo `Sig:` — its trust is rooted in the signed git tag chain.
The two clients share the same blobs and narinfo bytes but trust them via
independent layers (ref doc §1, §10.4).

---

## 8. Feature coverage

Features from the validation report
([validation-report.md](./validation-report.md) §81-114, recommendation P0 #1).
**Most are ALREADY IMPLEMENTED** — the table marks each as DONE (with the code
that satisfies it) or as the remaining INTEGRATION work.

| Feature(s) | What | Status |
|---|---|---|
| **F362** | Distinct AOS-`priority` vs `nix-cache-info` `Priority` | DONE — server `Priority: 30` ([`routes.rs:145`](../../../crates/aos-server/src/routes.rs)) / backend `40` vs `CacheEntry.priority` ([`types.rs:580-593`](../../../crates/aos-package/src/types.rs)) |
| **F363–F366** | `nix-cache-info` (StoreDir / WantMassQuery / Priority) | DONE — `cache_info_handler` ([`routes.rs:123`](../../../crates/aos-server/src/routes.rs)), backends ([`fs.rs:126`](../../../crates/aos-cache/src/backend/fs.rs)) |
| **F367–F376, F378–F383** | narinfo generator + every narinfo field | DONE — `format_narinfo` ([`narinfo.rs:27`](../../../crates/aos-server/src/narinfo.rs)) + `nar::info::format` ([`info.rs:81`](../../../crates/aos-core/src/nar/info.rs)) |
| **F377** | narinfo `Sig` generated | DONE — `format_narinfo` signs ([`narinfo.rs:87-93`](../../../crates/aos-server/src/narinfo.rs)) |
| **F385** | Nix fingerprint `(StorePath, NarHash, NarSize, References)` | DONE — `NarInfoSigner::fingerprint` ([`sign.rs:57-60`](../../../crates/aos-server/src/sign.rs)) |
| **F386** | Two published pubkey encodings (apm + nix form) | INTEGRATION — publish the nix `<name>:<base64>` form alongside the apm key (§7.1) |
| **F387** | per-narinfo `Sig` satisfies `require-sigs` | DONE — server emits `Sig:` ([`narinfo.rs:87-93`](../../../crates/aos-server/src/narinfo.rs)) |
| **F388 / F389** | NAR blob URL key (colon-in-filename handling) | DONE — server URL `nar/{hash}-{narhash}.{ext}` (colon→dash) ([`narinfo.rs:37`](../../../crates/aos-server/src/narinfo.rs)); consumer follows narinfo `URL:` verbatim ([`download.rs:184`](../../../crates/aos-package/src/download.rs)) |
| **F390** | Stock-`nix` host substituter wiring | INTEGRATION (docs) — §7.1 |
| **F392** | Nix-form `trusted-public-keys` value `<name>:<base64>` | DONE — server signs with a `name:base64` key ([`sign.rs:14-31,44-54`](../../../crates/aos-server/src/sign.rs)); INTEGRATION: surface that pubkey in docs/registry (§7.1) |
| **F393** | Do **not** disable `require-sigs` | DONE — `Sig:` always emitted (§2.4) |
| **F394** | Flake `nixConfig` acceptance caveat | INTEGRATION (docs) — §7.2 |
| **F395** | Substitution request/verify flow | DONE (server side) — all three endpoints served (§2.2); docs §7.3 |
| **F94** | Package metadata vs narinfo source | DONE — narinfo from store DB (`DbPathInfo`), git TOMLs are the *metadata* layer (§1, §2.1) |
| **F354** (with WS-05) | Strict-superset cache origin (3 endpoints) | DONE — `routes.rs:80-89` (§2.2) |
| **F361** (with WS-05) | Standard relative endpoint paths | DONE — consumer follows relative narinfo `URL:` via `join_cache_url` ([`download.rs:65-71,184`](../../../crates/aos-package/src/download.rs)) |

> The **only** open items are INTEGRATION: surface the cache URL in the committed
> `[[caches]]` (§4), surface the nix-form pubkey for stock hosts (§7.1, F386/F392),
> and the stock-`nix` docs (§7). `FileHash` / `FileSize` are already computed at
> emit time by the server ([`narinfo.rs:45-59`](../../../crates/aos-server/src/narinfo.rs),
> [`compress.rs:143`](../../../crates/aos-server/src/compress.rs)) — narinfo-driven
> since commit `7149acf6`, no schema change required.

---

## 9. CURRENT (implemented) → remaining integration

| ALREADY IMPLEMENTED (`path:line`) | Remaining (WS-06 integration) | Notes |
|---|---|---|
| `format_narinfo(&DbPathInfo,…)` emitter ([`narinfo.rs:27`](../../../crates/aos-server/src/narinfo.rs)) | — (none) | DB-fed narinfo emitter is correct; do **not** re-emit from the git tree |
| `cache_info_handler` `nix-cache-info` ([`routes.rs:123`](../../../crates/aos-server/src/routes.rs)) | — (none) | served; backends also write it ([`fs.rs:126`](../../../crates/aos-cache/src/backend/fs.rs)) |
| FileHash/FileSize emit-time compute ([`narinfo.rs:45-59`](../../../crates/aos-server/src/narinfo.rs), [`compress.rs:143`](../../../crates/aos-server/src/compress.rs)) | — (none) | already narinfo-driven (`7149acf6`) |
| Ed25519 fingerprint + `Sig:` ([`sign.rs:14-60`](../../../crates/aos-server/src/sign.rs), [`narinfo.rs:87-93`](../../../crates/aos-server/src/narinfo.rs)) | publish the nix-form pubkey for stock hosts (§7.1) | sign path done; only the pubkey-surfacing is integration |
| References basename-expansion ([`narinfo.rs:71-74`](../../../crates/aos-server/src/narinfo.rs)) | — (none) | server maps refs through `basename` already |
| NAR URL scheme + consumer following it ([`narinfo.rs:37`](../../../crates/aos-server/src/narinfo.rs), [`download.rs:184`](../../../crates/aos-package/src/download.rs)) | — (none) | consumer follows narinfo `URL:` verbatim |
| `resolve_mirror` / `resolve_mirrors` over `[[caches]]` ([`download.rs:85-97`](../../../crates/aos-package/src/download.rs), [`registry_ops.rs:404-410`](../../../crates/aos-package/src/registry_ops.rs)) | **commit a `[[caches]]` entry** pointing at the cache (§4) | resolution exists; the registry just needs the entry |
| `query-missing` + backend `has` ([`routes.rs:83`](../../../crates/aos-server/src/routes.rs), [`backend/mod.rs`](../../../crates/aos-cache/src/backend/mod.rs)) | thin pre-publish presence check over registry-listed paths (§6) | reuse existing primitives |

---

## 10. Task checklist (integration only)

**Wire the cache into the registry (§4):**

- [ ] Commit a `registry.toml` `[[caches]]` entry pointing at the existing
      `aos-server` / `aos-cache` surface so `resolve_mirror` selects it instead of
      falling back to `{registry.url}` ([`download.rs:85-97`](../../../crates/aos-package/src/download.rs)).
- [ ] Verify `apm` GETs `<url>/<storeHash>.narinfo` and follows the narinfo `URL:`
      to the NAR (end-to-end smoke test against a live cache).

**(Optional) co-serve from the git origin (§5):**

- [ ] Front `aos-server` or sync an `aos-cache` FS/HTTP backend next to the
      dumb-HTTP git tree so one base URL serves both layers.

**Presence/queryability check (§6):**

- [ ] Thin pre-publish validation: every registry-listed `store_path` (and each
      `SysrootImageEntry`) is present in the configured cache, reusing
      `query-missing` / backend `has`; fail closed on a missing path.

**Stock-`nix` docs + nix-form pubkey (§7, F386/F390/F392/F394):**

- [ ] Surface the signer's pubkey in the nix `<name>:<base64>` form for stock hosts
      (the server already signs with a `name:base64` key, [`sign.rs:14-31`](../../../crates/aos-server/src/sign.rs)).
- [ ] Stock-`nix` `nix.conf` / flake `nixConfig` / verify-flow guidance (already
      drafted in [`nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md)
      §10; WS-06 owns it as a deliverable).

> **No emitter, signer, field-mapping, NAR-scheme, or consumer code to write** —
> those are done (§2). The checklist above is integration and documentation only.

---

## 11. Cross-references

### Reference set (`docs/registry/`)

- [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) — the
  strict-superset intent the *already-built* surface satisfies: the superset idea
  (§2), where the cache location comes from (§3), the `nix-cache-info` stub (§5),
  the narinfo field mapping (§6), references basename expansion (§7), the one-key
  signing (§8), the NAR blob URL key (§9), and dev-shell wiring (§10).
- [repo-layout.md](../../registry/repo-layout.md) — the committed git tree:
  `registry.toml` `[[caches]]` (§2, the cache list WS-06 commits an entry into),
  `keys.toml` trust roster (§3, the one key), `packages/*.toml` (§4, the metadata
  layer), `closures/<hash>` (§5, the bare-hash adjacency format).
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
  (the F362–F395 cluster, most ALREADY satisfied by existing code).
- [workstream-05-consumer.md](./workstream-05-consumer.md) — §8, the consumer side
  that *resolves* and *reads* the (already-emitting) cache.
- [workstream-04-signing-trust.md](./workstream-04-signing-trust.md) — the one-key
  model and `keys.toml` whose pubkey is surfaced in the nix `<name>:<b64>` form.
- [workstream-01-object-store.md](./workstream-01-object-store.md),
  [workstream-02-pack-delta-pipeline.md](./workstream-02-pack-delta-pipeline.md) —
  emit the `packages/*.toml` metadata tree this WS points the cache alongside.
- [open-questions.md](./open-questions.md) — deployment edge decisions
  (co-serve vs separate cache host; colon-in-NAR-key handling).
