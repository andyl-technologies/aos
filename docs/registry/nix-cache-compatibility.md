# Nix Binary-Cache Compatibility

> **Audience:** users running non-AOS dev shells against an AOS registry,
> implementers building the **producer** that pre-generates the static
> Nix-cache files at publish, and architects reasoning about the git-metadata
> layer versus the NAR-cache layer.
>
> **Status legend:** **CURRENT** = behavior present in the code today (cited as
> `path:line`). **TARGET** = the protocol/design contract from the
> [design brief](../plans/registry/design-brief.md) §13 (and §14 for the committed
> `registry.toml` `[[caches]]`, §11 for signing).
>
> **Up front — the registry runs no server.** The registry's Nix binary cache is
> **dumb static files on the HTTP CDN, generated ahead-of-time (AOT) at publish**
> (`{cache-base}/nix-cache-info`, `{cache-base}/<storehash>.narinfo`,
> `{cache-base}/nar/<…>.nar.zst`). There is **no process** answering requests at
> serve-time — a stock `nix` / `apm` reads these files as an ordinary static
> binary cache (the strict superset). What is **not** greenfield is the narinfo
> **format / sign / FileHash logic**: it already exists as reusable code —
> `aos-core/nar/info.rs` (the shared `NarInfo` type) and
> `aos-core/nar/cache.rs` (`render_static_narinfo`, `NarInfoSigner`,
> `nix_cache_info`, and `nar_url`). The **producer reuses these as a library** to
> *generate* the static files. The live `aos-server` cache
> (a host serving its **own** Nix store, nix-serve-style) is a **separate use
> case the registry never runs**. The consumer (`aos-package/download.rs`) is
> already narinfo-driven and works against a dumb static cache. The producer path
> is implemented as `apr cache generate`: it AOT-generates those static files,
> can upload them through `aos-cache`, and can update the committed
> `registry.toml` `[[caches]]` pointer.

This document explains how an AOS registry's Nix binary cache is, by design, a
**strict superset** of the standard Nix binary-cache (substituter) protocol,
**delivered as pre-generated static files on the CDN** — not by a running
server. The NAR-cache surface is **orthogonal** to the git-object metadata
layer: it is not part of the trust chain that `apm` walks. Its location is
**not** advertised in signed tags — signed tags are pure signed pointers and
carry no structured payload. The substituter location lives in the **committed
git-repo-root `registry.toml`** `[[caches]]` table (a tree file authenticated
transitively by the signed tag — see
[`repo-layout.md`](repo-layout.md)), with the consumer's client-side
`registries.d/<name>.toml` as an **optional override/supplement**. The static
cache files MAY be co-located with the git metadata on the same origin or live
on a separate CDN host.

See also:
[README.md](README.md) ·
[architecture.md](architecture.md) ·
[http-layout.md](http-layout.md) ·
[current-state.md](current-state.md) ·
[versioning-and-channels.md](versioning-and-channels.md) ·
[packs-and-deltas.md](packs-and-deltas.md) ·
[signing-and-trust.md](signing-and-trust.md) ·
[publishing.md](publishing.md) ·
[apt-comparison.md](apt-comparison.md) ·
[repo-layout.md](repo-layout.md)

---

## 1. Two orthogonal layers

An AOS registry origin serves **two layers that do not depend on each other**:

1. **The git metadata layer** — a bare, sha256 git repository served over dumb
   HTTP. Channels are branches, releases are signed tags, and the package
   metadata *is* the git tree content. This is the trust root: a signed
   `tag → tag → commit` chain authenticates the whole Merkle DAG (see
   [signing-and-trust.md](signing-and-trust.md)). A signed tag is a **pure
   signed pointer** — standard git tag fields plus the Ed25519 signature and an
   optional freeform message — and carries no structured payload. `apm`
   consumes this layer.

2. **The NAR-cache layer** — the stock Nix `nix-cache-info` / `<storehash>.narinfo`
   / `nar/` surface, **delivered as pre-generated static files on the CDN**
   (AOT-generated at publish; no running process). A stock `nix` substituter
   consumes this layer for dev-shell substitution. It is a **strict superset** of
   the standard Nix binary cache.

The link between them is deliberately thin. The **signed tag** carries no cache
advertisement — but the git layer does name the cache, in the **committed
git-repo-root `registry.toml`** `[[caches]]` table inside the tree the signed tag
authenticates (tag → commit → tree → file; see
[`repo-layout.md`](repo-layout.md)). The NAR cache may physically live anywhere —
co-located with the git repo on the same origin (a relative `[[caches]]` url like
`./nar`) or on a separate host (an absolute url). A consumer's client-side
`registries.d/<name>.toml` may **override or supplement** that committed list.
Neither layer's correctness depends on the other:

```
            ┌──────────────────────────────────────────┐
  apm   ──► │  git metadata layer  (bare sha256 repo)   │  ← trust root
            │  channels=branches · releases=signed tags │     (signed tags)
            │  signed tag = pure signed pointer         │     (no cache payload)
            │  tree: registry.toml [[caches]] ──────────┼──┐  (authenticated via tag)
            └──────────────────────────────────────────┘  │
                                                           ▼ committed [[caches]]
            ┌──────────────────────────────────────────┐    (+ client-side override)
  nix   ──► │  NAR-cache layer (static CDN files, AOT)  │  ← NOT in apm trust chain
            │  nix-cache-info · <storehash>.narinfo     │     (per-narinfo Sig:)
            │  nar/<key>.nar.zst   (no running server)  │
            └──────────────────────────────────────────┘
```

The cache is **named in-tree, not in the tag**: its location comes from the
committed `registry.toml` `[[caches]]` (authenticated via the tag), which the
consumer's client-side `registries.d/<name>.toml` may override. The metadata
layer is authoritative; the NAR cache is a content-addressed, swappable
substituter whose pointer the tag chain governs.

---

## 2. The strict-superset idea

A standard Nix binary cache is a dumb HTTP origin that answers three kinds of
request, all relative to a **cache base URL** — and it can be served entirely
from **static files**, no application logic required:

1. `GET {cache}/nix-cache-info` — a fixed-name capability/identity stub.
2. `GET {cache}/<storehash>.narinfo` — per-store-path text metadata, keyed by the
   32-character base32 store-path hash.
3. `GET {cache}/nar/<…>.nar[.zst|.xz]` — the content-addressed NAR blob the
   narinfo points at.

The AOS registry pre-generates exactly these three kinds of file and uploads
them to the CDN, so any host that knows nothing about AOS can point a stock
`nix` at the cache URL and use it as an ordinary substituter. AOS adds nothing
the Nix protocol cannot ignore — that is the **strict superset**.

**What is implemented today.** The narinfo **format / sign / FileHash logic**
has been extracted into reusable code:

- `crates/aos-core/src/nar/info.rs` defines the shared `NarInfo` type and its
  `parse` / `format` helpers.
- `crates/aos-core/src/nar/cache.rs` defines `render_static_narinfo`,
  `nix_cache_info`, `nar_url`, and `NarInfoSigner`.
- `crates/aos-package/src/registry/nixcache.rs` implements `apr cache generate`:
  it walks registry store paths, dumps/compresses NARs, computes `FileHash` /
  `FileSize`, writes signed `.narinfo` files and `nix-cache-info`, optionally
  uploads them to one or more repeatable `--upload-url` destinations, and can
  commit the root `registry.toml` `[[caches]]` pointer.

The **registry producer uses this library** to *emit static files* at publish
time — it does **not** run `aos-server`'s request handlers
(`routes.rs` `cache_info_handler` / `narinfo_handler` / `nar_handler`), which
serve a live host's own store dynamically and are a **different use case the
registry never runs**. The `aos-cache` backends
(`crates/aos-cache/src/backend/{s3,sftp,http,fs}.rs`,
`has_narinfo` / `get_narinfo` / `put_narinfo`, `backend/mod.rs:16-23`) are a
related building block — object-store I/O that reads/writes the same static
surface. A stock `nix` consumes the resulting static files unchanged; so can
`apm` (§4).

Production validation for the stock-Nix/static-cache surface is covered by the
Nix VM test-suite check:

```sh
nix-build -A checks.vm.apm.registry-validation-stock-nix-backend-array
```

That VM creates a tiny fixed-output store path, generates signed static cache
files with `apr cache generate`, serves them to stock Nix with
`require-sigs = true`, and uploads the same cache to a mixed `file://`, `s3://`,
and `sftp://` destination array. It passed on a remote KVM builder on
2026-06-08 with output
`/nix/store/bwp2ayp8r199n32s2csndcv43qmi38xr-aos-vm-test-apm-registry-validation-stock-nix-backend-array-0`;
the output `serial.log` records the expected one-destination failure for the
invalid `not-a-url` probe and
`registry stock Nix + backend array validation passed`. The Rust and CLI cache
e2e tests remain available as lower-level host-store-mutating checks behind
`AOS_PACKAGE_TEST_REAL_NIX_CACHE=1`; ordinary Rust test runs skip them.

> **Why the projection lines up so cleanly:** Nix's two-level naming — a
> store-hash narinfo that *indirects* to a content-addressed NAR — is exactly how
> AOS already names blobs. AOS records a `store_path` (carrying the store-hash)
> and a `nar_hash` (content address of the blob) per package version. The static
> narinfo the producer emits is just a reprojection of metadata AOS already holds
> in its git tree. (design brief §13)

---

## 3. Where the cache location comes from (TARGET)

The cache is **not** advertised in any signed tag. Signed tags are pure signed
pointers and carry no structured payload — there is no tag-message TOML, no
`[meta]`, no `[[caches]]` *in the tag*. Instead the cache list lives in the
**committed git-repo-root `registry.toml`** `[[caches]]` table — a tree file
authenticated transitively by the signed tag (tag → commit → tree → file), the
existing `RegistryRootConfig` (`crates/aos-package/src/types.rs:564-570`). See
[`repo-layout.md`](repo-layout.md) §2 for the full tree shape.

The substituter location therefore comes from:

1. **Committed `registry.toml` `[[caches]]` (the authoritative source).** Each
   entry is `CacheEntry { url, priority }`. The `url` may be **absolute** (a
   separate cache host) or **relative** (e.g. `./nar`, the same origin that serves
   the git metadata). Because the file is in the tree the signed tag covers, the
   cache pointer is **authenticated** — though, as §1 and §8.1 note, an
   authenticated-but-wrong pointer still cannot serve bad bytes (NARs are
   content-addressed).
2. **Client-side `registries.d/<name>.toml` (optional override/supplement).** The
   consumer may add or override caches locally, exactly as a stock `nix` host lists
   `extra-substituters` in `nix.conf` (§10). Where the client-side list and the
   committed list both name a cache, the **higher priority wins** (entries are
   sorted descending — §4).

Whichever base URL is selected, the standard Nix relative paths give the three
superset endpoints:

```
<cache-url>/nix-cache-info             Nix: capability stub   (§5)
<cache-url>/<storehash>.narinfo        Nix: per-path metadata (§6)
<cache-url>/nar/<key>.nar.zst          Nix: NAR blob          (§9)
```

- A consumer may end up with multiple substituter URLs (committed + client-side);
  ordering across them follows the AOS `priority` field (descending, higher wins —
  §4), while a stock `nix` host orders *its own* substituters by each cache's
  `nix-cache-info` `Priority` (§5). These are distinct knobs.
- Because the cache list is **in-tree (signed-by-extension) plus an optional
  client-side override** — rather than embedded in a signed tag — there is no
  unsigned *in-band* side-channel served by the origin to reconcile.

---

## 4. What exists today (CURRENT) vs. what the producer generates (TARGET)

Two things **exist today** as code: (a) the narinfo **format / sign / FileHash
logic** (currently the body of `aos-server`'s live cache, reusable as a library),
and (b) a **narinfo-driven consumer** (`aos-package`). What does **not** exist is
the registry **producer** that, at publish, *reuses* (a) to AOT-generate the
static `nix-cache-info` / `<storehash>.narinfo` / `nar/` files and uploads them
to the CDN — see §11. The registry runs **no server**; nothing dynamically serves
these files.

**Shared narinfo type (CURRENT — reusable).** `crates/aos-core/src/nar/info.rs`
defines the `NarInfo` struct (`info.rs:5`) — `{ store_path, url, compression,
file_hash, file_size, nar_hash, nar_size, references, deriver, signatures }` —
plus `parse()` (`info.rs:19`), `format()` (`info.rs:81`), `from_path_info()`
(`info.rs:129`), and the `store_hash()` / `basename()` helpers
(`info.rs:147`, `info.rs:153`). Both the format logic and the consumer use this
one type; the producer reuses `format()` to emit each static `.narinfo`.

**narinfo format / FileHash / NAR logic (CURRENT).** The static producer calls
`render_static_narinfo` (`aos-core/src/nar/cache.rs`) after it has dumped and
zstd-compressed each NAR. The producer computes `FileHash` / `FileSize` from the
compressed bytes it writes to `nar/`, so the narinfo and NAR file are generated
from the same byte stream.

**Per-narinfo Ed25519 `Sig:` (CURRENT).** `NarInfoSigner::load(key_file)`
(`aos-core/src/nar/cache.rs`) loads a `name:base64` Ed25519 secret;
`sign(fingerprint)` returns `name:base64sig`; and
`fingerprint(store_path, nar_hash, nar_size, refs)` produces the exact Nix
narinfo fingerprint `1;{store_path};{nar_hash};{nar_size};{refs}`.
`render_static_narinfo` appends the resulting `Sig:` line when a signer is
configured, baking the signature into each static narinfo at publish.

**Object-store I/O (CURRENT — reusable upload path, `aos-cache`).** The backend
trait declares `has_narinfo` / `get_narinfo` / `put_narinfo` /
`put_cache_info` (`crates/aos-cache/src/backend/mod.rs`), implemented for `s3`,
`sftp`, `http`, and `fs` (`crates/aos-cache/src/backend/`). The
push-to-object-store backends can upload the producer-generated
`nix-cache-info` body exactly, preserving the generator's `Priority` value; the
pull-side `http` backend GETs narinfo + NAR from any standard static cache. The
producer reuses this `put_*` path to **upload the generated static files** to
the CDN.

**Cache parsing & resolution (CURRENT).** The consumer already reads a
`[[caches]]` array from a **repo-root `registry.toml`** (parsed by
`RegistryRootConfig`, living *inside* the registry git repo — see
[current-state.md](current-state.md) §3.1), not a signed tag. The git-native
target **keeps this committed `registry.toml` `[[caches]]`** as the authoritative
cache list (authenticated via the signed tag), and **adds** an optional
consumer-side `registries.d/<name>.toml` override. The in-repo signing pubkey has
already left `registry.toml`; trust rotation/revocation lives in `keys.toml` (see
[`repo-layout.md`](repo-layout.md) §3, §7). The parsing/sorting/selection logic
below is reusable as-is.

- `CacheEntry { url, priority }` with `default_cache_priority() == 100`
  (`crates/aos-package/src/types.rs:582-590`), nested under `RegistryRootConfig`
  (`types.rs:564-570`).
- `resolve_mirrors` reads the caches and sorts them **descending by priority**
  (higher first), returning `Vec<CacheEntry>`
  (`crates/aos-package/src/registry_ops.rs:405-414`).
- `resolve_mirror` picks the first (highest-priority) cache, else falls back to
  the registry URL itself (`crates/aos-package/src/download.rs:85-97`).

**Consumer is narinfo-driven and DONE (CURRENT, `aos-package/src/download.rs`).**
This is the half that is genuinely complete and consumes a **dumb static narinfo
cache as-is** — no server required on the origin. Since
commit `7149acf6`, `apm` resolves NARs **from the narinfo**, not from package
TOML fields. It imports `aos_core::nar::info` (`download.rs:10`); a
`DownloadRequest` carries only the store-path identity plus the cache base URL
(`download.rs:24-30`); `narinfo_url(mirror_url, store_path)` (`download.rs:74`)
builds `<base>/<storeHash>.narinfo`; `fetch_narinfos` GETs and parses each
narinfo (`download.rs:107`, parsing at `download.rs:169`); the resulting
`ResolvedDownload { req, narinfo }` is consumed by the downloader. `FileHash`,
`NarHash`, `References`, and `Deriver` all come **from the narinfo**
(`DownloadResult`, `download.rs:42-55`):

- The NAR blob URL is `join_cache_url(mirror_url, narinfo.url)` — the cache base
  joined with the narinfo-supplied `URL:` path (`download.rs:65-71`, applied at
  `download.rs:184`).
- The compressed file is verified by SHA-256 of its bytes against the narinfo
  `FileHash` (falling back to `NarHash` when uncompressed; a missing `FileHash`
  on a compressed NAR is treated as a server bug and errors loudly) — wired into
  the transfer request via `.with_hash(...)` (`download.rs:191-204`), **not** by
  a signature.

**Conclusion:** the narinfo **format / sign / FileHash logic**, the
**narinfo-driven consumer**, and the **static producer** exist today. The cache
pointer remains the committed `registry.toml` `[[caches]]` (authenticated via
the tag), plus an optional client-side `registries.d/<name>.toml` override — so
no migration into a tag is needed.

---

## 5. The `nix-cache-info` stub

Nix hardcodes the name `nix-cache-info` and fetches it once per cache to learn
the store directory and query behavior. The registry publishes it as a **static
file at the cache root** (`{cache-base}/nix-cache-info`). The stub text the
producer writes is a small fixed body, e.g.:

```
StoreDir: <store_dir>
WantMassQuery: 1
Priority: 40
```

The producer writes this static file locally, then uploads that exact body
through `aos-cache` so backend upload does not rewrite the chosen `Priority`.
For reference, the **live**
`aos-server` cache returns its own variant dynamically — with `Priority: 30` and
a `Capabilities: pack-upload query-missing sse-logs zstd xz content-range` line
(`cache_info_handler`, `routes.rs:123,145`) — but that is the **separate
nix-serve-style host use case the registry does not run**, and its
`Capabilities` advertise an `aos-server`-specific dynamic extension surface that
has no meaning for a static CDN cache.

| Key | Meaning | Registry static value |
|---|---|---|
| `StoreDir` | Store prefix the NARs were built against. Must match the consuming host's store. | The configured store dir baked into the static file. Commonly `/nix/store`. |
| `WantMassQuery` | `1` lets `nix` batch-query this cache when computing substitutions. | `1` — the origin is a plain static object store; mass query is cheap. |
| `Priority` | Lower = preferred. Stock `cache.nixos.org` is `40`. | The `apr cache generate --priority` value preserved in the uploaded `nix-cache-info`. Operator policy knob — raise above `40` to defer to the upstream cache for shared paths. (The live `aos-server` host uses `30`; not relevant to the registry's static cache.) |
| `Capabilities` | `aos-server` dynamic extension advertisement (not stock Nix). | **Omitted** on the registry's static cache — there is no running server to advertise extensions. (The live `aos-server` host emits `pack-upload query-missing sse-logs zstd xz content-range`; stock `nix` ignores such an unknown line, so the strict-superset property holds either way.) |

> Note: the `nix-cache-info` `Priority` is the **Nix-cache** preference knob,
> consumed by stock `nix` to order substituters. It is distinct from the AOS
> `priority` field in the committed `registry.toml` `[[caches]]` (and any
> client-side `registries.d` override), which orders the caches `apm` has
> resolved (§3, §4).

---

## 6. narinfo field mapping

A narinfo is line-oriented `Key: value` text. The table below **describes the
fields the producer writes into each static `.narinfo`**, using
`render_static_narinfo` in `crates/aos-core/src/nar/cache.rs`. That function
projects plain `StaticNarInfoInput` into the shared `NarInfo` shape in
`crates/aos-core/src/nar/info.rs`. The consumer parses the same static text back
into `NarInfo` and reads exactly these fields (`crates/aos-package/src/download.rs`).

| narinfo field | Source in `render_static_narinfo` / `registry::nixcache` | Notes |
|---|---|---|
| `StorePath` | `<store_dir>/<basename(store_path)>` | Full store path; `basename` comes from `aos-core::nar::info`. |
| `URL` | `nar_url(store_path, nar_hash, compression)` | Relative to the cache URL; `nar/{store_hash}-{nar_hash with ':' -> '-'}.{ext}`. The consumer joins it via `join_cache_url`. |
| `Compression` | `NarCompression::{None,Zstd,Xz}.name()` | `zstd`, `xz`, or `none`. |
| `FileHash` | compressed-bytes SHA-256 computed by `registry::nixcache` | Always emitted. Consumer verifies the wire bytes against it (integrity precheck). |
| `FileSize` | compressed-byte length computed by `registry::nixcache` | Always emitted. |
| `NarHash` | `nix path-info --json` `narHash` | Hash of the **uncompressed** NAR, straight from the local Nix store. |
| `NarSize` | `nix path-info --json` `narSize` | Size in bytes of the uncompressed NAR. |
| `References` | full refs mapped through `basename` | Written as `<hash>-<name>` basenames, matching the Nix fingerprint. |
| `Deriver` | `basename(deriver)` | Optional `.drv` basename. |
| `Sig` | existing sigs + `NarInfoSigner` signature | Freshly computed Ed25519 `Sig:` when a signer is configured. |

Stock-Nix fields AOS does **not** emit:

- `System` — omitted; Nix tolerates its absence.
- `CA` — omitted; AOS store paths are input-addressed.

The `NarInfo` struct itself carries no `System` / `CA` fields
(`info.rs:5-16`), and `parse()` ignores any unknown keys (`info.rs:61`), so the
round trip is lossless for the fields AOS uses.

> **Trust note (RFC-0005):** for the AOS consumer, narinfos are **advisory
> transport metadata** - they supply the NAR URL, compression, and sizes for
> planning, plus the `FileHash` integrity precheck. The *trust decision* for
> the decompressed bytes is the registry's signed `store/` realisation graph
> ([`repo-layout.md`](repo-layout.md) §5): every downloaded NAR's
> uncompressed SHA-256 and size must match a blessed entry, and a narinfo
> `NarHash` disagreeing with `store/` always resolves in favor of `store/`. Only
> registries that publish no graph at all fall back to trusting `NarHash`
> (with a warning). Stock-Nix consumers, which cannot read `ca/`, keep the
> narinfo `Sig:` Ed25519 signature (§8) as their substitution defence.

### 6.1 Example static narinfo

Shape of the static file the producer emits via `render_static_narinfo`:

```
StorePath: /nix/store/abc123def456abc123def456abc123de-curl-8.5.0
URL: nar/abc123def456abc123def456abc123de-sha256-1f2e3d….nar.zst
Compression: zstd
FileHash: sha256:1f2e3d4c5b6a79880011223344556677889900aabbccddeeff00112233445566
FileSize: 1894572
NarHash: sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
NarSize: 6553600
References: r4q1m2kp8v3x…-glibc-2.39 xr5is7by89v3q…-zlib-1.3.1
Deriver: q8mn2pv73w0x…-curl-8.5.0.drv
Sig: aos-core:base64signature==
```

Note the `URL:` form: `nar/{store_hash}-{nar_hash}.{ext}` with the `nar_hash`'s
colon rewritten to a dash.

### 6.2 Sysroot images are their own store paths

For sysroot packages, each pre-compiled image (`SysrootImageEntry`, carried in
`PackageMeta.images`, `types.rs:71-73` and defined at `types.rs:604-609`) is
itself a distinct store path with its own `store_path` / `nar_hash` /
`download_hash`. Because narinfos are keyed by store-path hash, the producer
emits a **separate static `<storehash>.narinfo`** for each such image, via the
same `render_static_narinfo` logic (§6) — no per-image special case. The field
mapping is identical; the image is just another store path.

---

## 7. References basename expansion

Nix narinfo `References` requires **store-path basenames** of the form
`<hash>-<name>`, not bare hashes. The reusable format logic **writes them in this
form**: `render_static_narinfo` maps every full store-path reference through
`basename` before joining them space-separated. Since `registry::nixcache` reads
full references from `nix path-info --json`, the basename call yields the
`<hash>-<name>` form stock `nix` expects in each static narinfo.

```
DbPathInfo.refs:      [ "/nix/store/r4q1m2kp8v3x…-glibc-2.39", … ]
                                │
                       basename(r)
                                │
narinfo References:    r4q1m2kp8v3x…-glibc-2.39  xr5is7by89v3q…-zlib-1.3.1
```

> **Note for the git-metadata layer:** the *git registry* stores
> dependency edges as **bare store-path hashes** in the `store/` realisation
> graph (`ia:sha256:<store-hash>` lines, RFC-0005;
> `crates/aos-package/src/registry/store.rs`). That bare-hash form lives in the
> git tree and is consumed by `apm`'s closure walk; it is **independent** of the
> narinfo-layer `References`, which the producer writes as basenames from the
> store DB into the static narinfo. The two layers are decoupled (§1) — no
> expansion step crosses between them.

> **Why basenames matter:** if `References` were emitted as bare hashes, stock
> `nix` would reject the narinfo (it parses references as store-path basenames
> and validates them against `StoreDir`).

---

## 8. Signing: one key, two signature forms

The narinfo-signing logic is implemented by `NarInfoSigner` in
`crates/aos-core/src/nar/cache.rs`. `fingerprint(store_path, nar_hash, nar_size,
refs)` produces the standard Nix narinfo fingerprint
`1;{store_path};{nar_hash};{nar_size};{refs}`; `sign(fingerprint)` signs it with
the Ed25519 secret and returns `name:base64sig`; and
`render_static_narinfo` appends the `Sig:` line. The producer bakes the `Sig:`
into each static narinfo at publish. The key model is the same single Ed25519
keypair that signs the git tags (design brief §11):

- **One secret key** signs (a) git tag objects via an SSH-format signature and
  (b) narinfos via the Nix fingerprint
  `(StorePath, NarHash, NarSize, References)` — the latter **already
  implemented** by `NarInfoSigner`. The *signed messages
  differ*, so the *signatures differ*, but there is **one secret to manage**.
- **Two published public-key encodings** from that one key:
  - `aos-core:Ed25519:<base64>` — the apm form for `trusted-keys.d` anchoring and
    the `keys.toml` roster (the `SigningConfig.public_key` format,
    `crates/aos-package/src/types.rs:346`,
    parsed as `<name>:Ed25519:<base64>` by `parse_signing_key` in `security.rs:575`;
    the base64 payload is the SSH `ssh-ed25519` public-key blob used by git
    `allowed_signers`).
  - `<name>:<base64>` — the nix form for Nix `trusted-public-keys`.
    Its base64 payload is the raw Ed25519 verifying key bytes. It is a different
    wire encoding of the same public key, not the same literal base64 string.

### 8.1 Why a per-narinfo `Sig` exists at all

`apm`'s trust is rooted in the **signed git tag chain**: the Ed25519-signed
`tag → tag → commit` authenticates the whole git tree (a Merkle DAG) → every
package TOML → every NAR SHA-256 recorded in those TOMLs (design brief §5, §11).
So `apm` needs **no** per-NAR signature; NARs are authenticated transitively and
verified by content hash (`download.rs:191-204`).

The per-narinfo `Sig:` exists **only** to satisfy a stock `nix` substituter
without forcing the operator to set `require-sigs = false`. It is a compatibility
affordance for the Nix protocol — orthogonal to the AOS trust chain, exactly as
the NAR-cache layer itself is (§1).

```
apm trust:   signed tag chain ──► TOML ──► NAR sha256   (transitive, no Sig needed)
nix trust:   narinfo Sig (Ed25519) ──► NarHash          (per-path, satisfies require-sigs)
                 ▲
                 └── same key, different signed message
```

See [signing-and-trust.md](signing-and-trust.md) for the full key model,
name-binding, and the `tag → tag → commit` chain.

---

## 9. NAR blob layout and the `URL:` field

The narinfo `URL:` is a relative path under the configured cache URL (§3),
pointing at a **static `.nar.zst` file the producer uploaded**. The format logic
and consumer already agree on it:

1. **`URL:` written into the static narinfo.** `nar_url` writes
   `nar/{store_hash}-{file_hash with ':' -> '-'}.{ext}`. The colon in the
   compressed file's `sha256:<hex>` hash is rewritten to a dash, so the key is colon-free
   (e.g. `nar/<storehash>-sha256-<hex>.nar.zst`). The producer uploads the
   compressed NAR to exactly this static `.nar.zst` / `.nar.xz` / `.nar` path.
   Because `FileHash` identifies the transferred bytes, changing compression
   output produces a new immutable URL even when the uncompressed `NarHash`
   remains unchanged.
2. **Consumer resolution (CURRENT).** `apm` downloads from the cache base joined
   with the narinfo-supplied `URL:` — `join_cache_url(mirror_url, narinfo.url)`
   (`crates/aos-package/src/download.rs:65-71`, applied at `download.rs:184`). It
   does not synthesize the key; it trusts the `URL:` the narinfo carries.
3. **Cache placement (committed `[[caches]]`, optionally overridden).** The cache
   may be co-located with the git repo on one origin (a relative `[[caches]]` url
   like `./nar`) or on a separate host (an absolute url); the pointer lives in the
   committed `registry.toml` `[[caches]]`, which a client-side `registries.d`
   override may supersede (§3). The narinfo `URL:` is resolved relative to whichever
   cache base `apm` ends up selecting (§3, §10).

```
<cache-url>/nar/<storehash>-sha256-<hex>.nar.zst   <-- emitted key (colon → dash)
        └── narinfo URL: nar/<storehash>-sha256-<hex>.nar.zst
```

> **Colon-in-filename:** because the format logic rewrites the file-hash colon to
> a dash in the `URL:`, the static object key is colon-free, so
> CDN/edge layers that mangle a literal `:` are not a concern for the
> generated static files. (The `aos-cache` backend keys —
> `<storehash>.narinfo` / `nar/<filename>` — are likewise colon-free.) See
> [open-questions.md](../plans/registry/open-questions.md) for any
> alternate-keying deployment notes.

---

## 10. Using the AOS cache as a dev-shell substituter

Once the producer has published the static `nix-cache-info` + `*.narinfo` +
`nar/` files with per-narinfo `Sig:` (§4, §5, §6, §8), a non-AOS host running
stock `nix` consumes them as an ordinary binary cache — **dumb static files, no
server** — exactly like any other static substituter. A **stock `nix` host has
no AOS git layer**, so it simply names the substituter URL directly in
`nix.conf` (§10.1). An **AOS host**, by contrast, resolves the cache from the
committed `registry.toml` `[[caches]]` (authenticated via the tag), optionally
overridden by its client-side `registries.d/<name>.toml` (§3). Either way there
is no tag to decode — the cache pointer is a tree file or local config, not a tag
payload.

### 10.1 `nix.conf`

```ini
# /etc/nix/nix.conf  (or ~/.config/nix/nix.conf for per-user)

# Append the resolved AOS cache URL. Order does not imply priority — that comes
# from each cache's nix-cache-info `Priority` (§5).
extra-substituters = https://registry.aos.dev/core/nar

# Trust the registry's Ed25519 key in Nix's <name>:<base64> form (§8).
extra-trusted-public-keys = aos-core:base64publickeyhere==
```

- Use `extra-substituters` / `extra-trusted-public-keys` (the `extra-` prefix
  **appends** to the defaults) so `cache.nixos.org` is retained.
- The key value is the **`<name>:<base64>`** encoding — the same underlying
  Ed25519 key as the `aos-core:Ed25519:<base64>` apm form, just the Nix-flavored
  projection (§8).
- Do **not** set `require-sigs = false`. Emitting `Sig:` (§8) is what lets
  signature verification stay on.

### 10.2 Flake config (`nixConfig`)

```nix
{
  nixConfig = {
    extra-substituters = [ "https://registry.aos.dev/core/nar" ];
    extra-trusted-public-keys = [ "aos-core:base64publickeyhere==" ];
  };

  outputs = { self, nixpkgs }: {
    # … dev shell, packages, etc.
  };
}
```

> Flake-level `nixConfig` substituters/keys are only used after the user accepts
> them (or the flake is already trusted). For unattended/CI hosts, prefer the
> `nix.conf` form (§10.1) or pass `--accept-flake-config`.

### 10.3 One-off / CLI form

```sh
nix build .#devShell \
  --extra-substituters    https://registry.aos.dev/core/nar \
  --extra-trusted-public-keys 'aos-core:base64publickeyhere=='
```

### 10.4 What a substitution looks like

```
host nix              AOS static CDN cache (URL from registry.toml [[caches]] / override)
   │                                   │   (dumb static files, no server)
   │  GET /nix-cache-info               │   static stub: StoreDir/Priority/WantMassQuery (§5)
   │ ─────────────────────────────────►│
   │  GET /<storehash>.narinfo          │   static file (pre-gen via render_static_narinfo) (§6)
   │ ─────────────────────────────────►│
   │      verify Sig: against           │
   │      trusted-public-keys  (§8)     │
   │  GET /nar/<key>.nar.zst            │   static content-addressed blob                (§9)
   │ ─────────────────────────────────►│
   │      verify NarHash, decompress    │
```

`apm` on an AOS host, meanwhile, walks the git metadata layer (channel partition
tag → semver tag → commit → package TOML) and fetches NARs by content hash from
the cache named in the committed `registry.toml` `[[caches]]` (or a client-side
override) — verifying the content hash (`download.rs:191-204`), never the narinfo
`Sig:`. The two clients share the blobs but trust them via independent layers (§1).

---

## 11. Summary: implemented static producer

The narinfo **format / sign / FileHash logic**, the **narinfo-driven consumer**,
and the **static producer** exist today. The registry runs **no server**: its Nix
cache is dumb static files on the CDN, generated AOT by `apr cache generate` and
optionally uploaded through `aos-cache` to one or more destinations.

**Reusable logic and producer surface.** These are libraries and commands the
producer calls; none of them is a server the registry runs.

| Capability | Where it lives | Cite |
|---|---|---|
| Shared `NarInfo` type + `parse`/`format` | `aos-core` | `nar/info.rs:5,19,81` |
| Static narinfo rendering, URL construction, cache-info body, and Nix `Sig:` | `aos-core` | `nar/cache.rs` |
| Static cache generation, local completeness checks, compressed NAR writing, upload, and `[[caches]]` update | `aos-package` | `registry/nixcache.rs`; `registry_ops.rs run_cache` |
| Static object upload backends (`put_*`, `put_cache_info`) | `aos-cache` | `backend/mod.rs`; backend implementations |
| Consumer (`apm`) reads a dumb static narinfo cache | `aos-package` | `download.rs` |

`apr cache generate` walks every package and sysroot-image store path listed by
the registry, fails if any path is absent from the local Nix store, emits signed
narinfos and `nar/*.nar.zst`, writes `nix-cache-info`, optionally uploads the
files to repeatable `--upload-url` destinations without rewriting the generated
cache-info body, and optionally commits the root `registry.toml` cache pointer.
Upload destinations and auth can come from `[registry.upload_auth]` in the
selected `registries.d/<name>.toml` (persisted by `apr origin config`) and are
then overridden by env/CLI values on `apr cache generate`.
Stock-Nix host wiring remains ordinary
`nix.conf` / flake `nixConfig` setup (§10).
The production validation VM check for this surface is
`checks.vm.apm.registry-validation-stock-nix-backend-array`.

These map to plan
[workstream-06-nix-cache.md](../plans/registry/workstream-06-nix-cache.md) (the
implemented producer that AOT-generates + uploads the static cache),
[workstream-05-consumer.md](../plans/registry/workstream-05-consumer.md) (the
consumer-side Nix substituter superset — **already narinfo-driven and done** in
`download.rs`), and
[workstream-04-signing-trust.md](../plans/registry/workstream-04-signing-trust.md)
(the one-key signing model).

---

## See also

- [architecture.md](architecture.md) — the git-over-dumb-HTTP layer and where the
  NAR cache sits relative to it.
- [repo-layout.md](repo-layout.md) — the committed git tree, including
  `registry.toml` `[[caches]]` (where the cache list lives) and `keys.toml`.
- [http-layout.md](http-layout.md) — full HTTP/object layout and CDN TTLs.
- [signing-and-trust.md](signing-and-trust.md) — the one-key model, name-binding,
  `tag → tag → commit`.
- [current-state.md](current-state.md) — current git-native implementation
  status.
- Plan: [workstream-06-nix-cache.md](../plans/registry/workstream-06-nix-cache.md),
  [workstream-05-consumer.md](../plans/registry/workstream-05-consumer.md),
  [workstream-04-signing-trust.md](../plans/registry/workstream-04-signing-trust.md),
  [open-questions.md](../plans/registry/open-questions.md),
  [design-brief.md](../plans/registry/design-brief.md) §13, §11.
