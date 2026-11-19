# Registry Nix binary cache

> **Audience:** users running non-AOS dev shells against an AOS registry,
> implementers building the **producer** that pre-generates the static
> Nix-cache files at publish, and architects reasoning about the git-metadata
> layer versus the NAR-cache layer.
>
> **The registry runs no cache server.** In short:
>
> - The Nix binary cache is static files on the content delivery network
>   (CDN), generated ahead of time (AOT) at publish:
>   `{cache-base}/nix-cache-info`, `{cache-base}/<storehash>.narinfo`, and
>   `{cache-base}/nar/<…>.nar.zst`. A NAR is a Nix archive, the serialized
>   form of one store path.
> - No process answers requests at serve time. Stock `nix` and `apm` read the
>   files as an ordinary static binary cache.
> - `apr cache generate` is the producer. It writes the files, can upload
>   them through `aos-nix-cache`, and can update the committed
>   `registry.toml` `[caches]` pointer.
> - The narinfo format, signing, and `FileHash` logic is shared library code
>   in `aos-nar` (`src/info.rs`, `src/cache.rs`), which the producer calls to
>   generate the files.
> - The consumer (`aos-package-manager/src/download.rs`) is narinfo-driven and
>   needs nothing beyond those static files.
> - The live `aos-build-server` cache, a host serving its own Nix store, is a
>   separate use case that the registry never runs.

An AOS registry's Nix binary cache is a **strict superset** of the standard
Nix binary-cache (substituter) protocol, delivered as pre-generated static
files rather than by a running server. The cache is orthogonal to the
git-object metadata layer: it is not part of the trust chain that `apm` walks.

Its location is not advertised in signed tags, which are pure signed pointers
with no structured payload. The cache location lives in the committed
repo-root `registry.toml` `[caches]` stack (a tree file authenticated
transitively by the signed tag — see
[`repository-layout.md`](repository-layout.md)), with the consumer's
client-side `registries.d/<name>.toml` as an optional supplement. The static
cache files may share an origin with the git metadata or live on a separate
CDN host.

See also:
[README.md](README.md) ·
[architecture.md](architecture.md) ·
[http-layout.md](http-layout.md) ·
[implementation.md](implementation.md) ·
[versioning-and-channels.md](versioning-and-channels.md) ·
[packs-and-deltas.md](packs-and-deltas.md) ·
[signing-and-trust.md](signing-and-trust.md) ·
[publishing.md](publishing.md) ·
[apt-comparison.md](apt-comparison.md) ·
[repository-layout.md](repository-layout.md)

---

## 1. Two orthogonal layers

An AOS registry origin serves two layers that do not depend on each other:

1. **The git metadata layer** — a bare, sha256 git repository served over dumb
   HTTP. Channels are branches, releases are signed tags, and the package
   metadata *is* the git tree content. This is the trust root: a signed
   `tag → tag → commit` chain authenticates the whole Merkle DAG (see
   [signing-and-trust.md](signing-and-trust.md)). A signed tag is a **pure
   signed pointer** — standard git tag fields plus the Ed25519 signature and an
   optional freeform message — and carries no structured payload. `apm`
   consumes this layer.

2. **The NAR-cache layer** — the stock Nix `nix-cache-info` / `<storehash>.narinfo`
   / `nar/` files, delivered as pre-generated static files on the CDN
   (AOT-generated at publish; no running process). A stock `nix` substituter
   consumes this layer for dev-shell substitution. It is a **strict superset** of
   the standard Nix binary cache.

The link between them is deliberately thin. The signed tag carries no cache
advertisement, but the git layer does name the cache: the committed repo-root
`registry.toml` `[caches]` stack sits inside the tree the signed tag
authenticates (tag → commit → tree → file; see
[`repository-layout.md`](repository-layout.md)). The NAR cache may live on any
host the stack names. A consumer's client-side `registries.d/<name>.toml` may
add caches to that committed list. When neither names a cache, `apm` uses the
registry URL itself as the cache base, which is how a co-located cache is
found. Neither layer's correctness depends on the other:

```
            ┌──────────────────────────────────────────┐
  apm   ──► │  git metadata layer  (bare sha256 repo)   │  ← trust root
            │  channels=branches · releases=signed tags │     (signed tags)
            │  signed tag = pure signed pointer         │     (no cache payload)
            │  tree: registry.toml [caches] ────────────┼──┐  (authenticated via tag)
            └──────────────────────────────────────────┘  │
                                                           ▼ committed [caches]
            ┌──────────────────────────────────────────┐    (+ client-side override)
  nix   ──► │  NAR-cache layer (static CDN files, AOT)  │  ← NOT in apm trust chain
            │  nix-cache-info · <storehash>.narinfo     │     (per-narinfo Sig:)
            │  nar/<key>.nar.zst   (no running server)  │
            └──────────────────────────────────────────┘
```

The cache is named in-tree, not in the tag. The metadata layer is
authoritative; the NAR cache is a swappable substituter whose pointer the tag
chain governs.

---

## 2. The strict-superset idea

A standard Nix binary cache is a dumb HTTP origin that answers three kinds of
request, all relative to a **cache base URL** — and it can be served entirely
from static files, no application logic required:

1. `GET {cache}/nix-cache-info` — a fixed-name capability/identity stub.
2. `GET {cache}/<storehash>.narinfo` — per-store-path text metadata, keyed by the
   32-character base32 store-path hash.
3. `GET {cache}/nar/<…>.nar[.zst|.xz]` — the content-addressed NAR blob the
   narinfo points at.

The AOS registry pre-generates exactly these three kinds of file and uploads
them to the CDN, so any host that knows nothing about AOS can point a stock
`nix` at the cache URL and use it as an ordinary substituter. AOS adds nothing
the Nix protocol cannot ignore — that is the **strict superset**.

**Shared code.** The narinfo format, signing, and `FileHash` logic is reusable
library code:

- `crates/artifacts/aos-nar/src/info.rs` defines the shared `NarInfo` type and its
  `parse` / `format` helpers.
- `crates/artifacts/aos-nar/src/cache.rs` defines `render_static_narinfo`,
  `nix_cache_info`, `nar_url`, and `NarInfoSigner`.
- `crates/registry/aos-registry-authoring/src/registry/nixcache.rs` implements `apr cache generate`:
  it walks registry store paths, dumps/compresses NARs, computes `FileHash` /
  `FileSize`, writes signed `.narinfo` files and `nix-cache-info`, optionally
  uploads them to one or more repeatable `--upload-url` destinations, and can
  commit the root `registry.toml` `[caches]` pointer.

The registry producer uses this library to emit static files at publish time.
It does not run `aos-build-server`'s request handlers (`routes.rs`
`cache_info_handler` / `narinfo_handler` / `nar_handler`), which serve a live
host's own store dynamically. The `aos-nix-cache` backends
(`crates/packages/aos-nix-cache/src/backend/{s3,sftp,http,fs}.rs`,
`has_narinfo` / `get_narinfo` / `put_narinfo`, `backend/mod.rs`) are a
related building block: object-store I/O that reads and writes the same static
files. A stock `nix` consumes the resulting files unchanged; so can `apm` (§4).

The stock-Nix path through the static cache is covered by a Nix VM check:

```sh
nix-build -A checks.vm.apm.registry-validation-stock-nix-backend-array
```

That VM creates a tiny fixed-output store path, generates signed static cache
files with `apr cache generate`, serves them to stock Nix with
`require-sigs = true`, and uploads the same cache to a mixed `file://`, `s3://`,
and `sftp://` destination array, including an expected one-destination failure
for an invalid URL. The Rust and CLI cache
e2e tests remain available as lower-level host-store-mutating checks behind
`AOS_PACKAGE_TEST_REAL_NIX_CACHE=1`; ordinary Rust test runs skip them.

> **Why the projection lines up:** Nix names a cache entry in two levels: a
> narinfo keyed by the store-path hash, which points at a NAR file. Package
> TOML already records each output's `store_path`, so the narinfo key is
> derived from committed metadata, and the `store/` realisation graph records
> the NAR hash the downloaded bytes must match
> ([`store-realisation-graph.md`](store-realisation-graph.md)).

---

## 3. Where the cache location comes from

The cache is **not** advertised in any signed tag. Signed tags are pure signed
pointers and carry no structured payload: there is no tag-message TOML and no
cache list *in the tag*. Instead the cache list lives in the committed
repo-root `registry.toml` `[caches]` table — a tree file authenticated
transitively by the signed tag (tag → commit → tree → file), parsed as
`RegistryRootConfig` (`crates/registry/aos-registry-format/src/manifest.rs`). See
[`repository-layout.md`](repository-layout.md) §2 for the full tree shape.

The cache location therefore comes from:

1. **Committed `registry.toml` `[caches]` (the authoritative source).** The
   table is one stack expression: an endpoint, an ordered `try` group, or a
   `mirror` group of replicas, and groups may nest
   (`crates/registry/aos-registry-format/src/stack.rs`):

   ```toml
   [caches]
   kind = "try"
   members = [
     { endpoint = "https://cache.aos.dev" },
     { endpoint = "https://cache-backup.aos.dev" },
   ]
   ```

   Only this table form is accepted; an array-shaped `[[caches]]` list is a
   schema error. Because the file is in the tree the signed tag covers, the
   cache pointer is **authenticated** — though, as §8.1 notes, an
   authenticated-but-wrong pointer still cannot serve bad bytes.
2. **Client-side `registries.d/<name>.toml` (optional supplement).** The
   consumer may add caches locally as `[[registry.caches]]` entries, each a
   `url` plus an optional `priority` (default `100`), much as a stock `nix`
   host lists `extra-substituters` in `nix.conf` (§10). The two lists are
   merged and tried in descending priority (§4), so a client-side entry with a
   higher priority is tried before the committed ones.
3. **The registry URL (fallback).** When neither source names a cache, `apm`
   uses the registry URL itself as the cache base.

Whichever base URL is selected, the standard Nix relative paths give the three
superset endpoints:

```
<cache-url>/nix-cache-info             Nix: capability stub   (§5)
<cache-url>/<storehash>.narinfo        Nix: per-path metadata (§6)
<cache-url>/nar/<key>.nar.zst          Nix: NAR blob          (§9)
```

- A consumer may end up with multiple cache URLs (committed + client-side);
  ordering across them follows the AOS priority (descending, higher first —
  §4), while a stock `nix` host orders *its own* substituters by each cache's
  `nix-cache-info` `Priority` (§5). These are distinct knobs.
- Because the cache list is in-tree (signed by extension) plus an optional
  client-side supplement, the origin serves no unsigned in-band cache pointer.

---

## 4. Cache resolution in the consumer

The committed `registry.toml` cache list is parsed by `RegistryRootConfig`
(`crates/registry/aos-registry-format/src/manifest.rs`). The `[caches]`
value is a small try/mirror stack expression
(`crates/registry/aos-registry-format/src/stack.rs`).
`RegistryRootConfig::cache_entries` flattens it depth-first into
`CacheEntry { url, priority }` values: the first endpoint gets priority `100`
and each later one gets one less, so committed order is the preference order.
`resolve_mirrors_for_registry`
(`crates/registry/aos-registry-client/src/registry/mirrors.rs`) merges that
list with any client-side `registries.d/<name>.toml` caches and sorts the
result descending by priority.

`apm` then works purely from narinfo
(`crates/packages/aos-package-manager/src/download.rs`):

- `resolve_mirror_chain` returns every cache base URL in priority order, or the
  registry URL itself when no cache is configured; the first entry is the
  primary mirror and the rest are miss-fallthrough mirrors.
- `narinfo_url` builds `<base>/<storeHash>.narinfo`, and `fetch_narinfos` GETs
  and parses each narinfo with the shared `aos_nar::info::NarInfo` type. A 404
  falls through to the next mirror.
- The NAR URL is `join_cache_url(base, narinfo.url)`; `FileHash`, `NarHash`,
  `References`, and `Deriver` all come from the narinfo, and the downloaded file
  is checked against `FileHash` (or `NarHash` for an uncompressed NAR) before
  the signed `store/` graph makes the final trust decision (§6).

The producer side reuses the same library code: `aos_nar::cache` provides
`render_static_narinfo`, `nar_url`, `nix_cache_info`, and `NarInfoSigner`, and
`aos-nix-cache` provides the `put_narinfo` / `put_cache_info` upload backends
(`fs`, `http`, `s3`, `sftp`).

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
through `aos-nix-cache` so backend upload does not rewrite the chosen `Priority`.
For reference, the live
`aos-build-server` cache returns its own variant dynamically — with `Priority: 30` and
a `Capabilities: pack-upload query-missing sse-logs zstd xz content-range` line
(`cache_info_handler`, `routes.rs`). That is the separate host use case the
registry does not run, and its `Capabilities` advertise `aos-build-server`
extensions that have no meaning for a static CDN cache.

| Key | Meaning | Registry static value |
|---|---|---|
| `StoreDir` | Store prefix the NARs were built against. Must match the consuming host's store. | The configured store dir baked into the static file. Commonly `/nix/store`. |
| `WantMassQuery` | `1` lets `nix` batch-query this cache when computing substitutions. | `1` — the origin is a plain static object store; mass query is cheap. |
| `Priority` | Lower = preferred. Stock `cache.nixos.org` is `40`. | The `apr cache generate --priority` value preserved in the uploaded `nix-cache-info`. Operator policy knob — raise above `40` to defer to the upstream cache for shared paths. (The live `aos-build-server` host uses `30`; not relevant to the registry's static cache.) |
| `Capabilities` | `aos-build-server` dynamic extension advertisement (not stock Nix). | **Omitted** on the registry's static cache — there is no running server to advertise extensions. (The live `aos-build-server` host emits `pack-upload query-missing sse-logs zstd xz content-range`; stock `nix` ignores such an unknown line, so the strict-superset property holds either way.) |

> Note: the `nix-cache-info` `Priority` is the **Nix-cache** preference knob,
> consumed by stock `nix` to order substituters. It is distinct from the AOS
> priority derived from the committed `registry.toml` `[caches]` order (and set
> explicitly on client-side `registries.d` entries), which orders the caches
> `apm` has resolved (§3, §4).

---

## 6. narinfo field mapping

A narinfo is line-oriented `Key: value` text. The table below describes the
fields the producer writes into each static `.narinfo`, using
`render_static_narinfo` in `crates/artifacts/aos-nar/src/cache.rs`. That function
projects plain `StaticNarInfoInput` into the shared `NarInfo` shape in
`crates/artifacts/aos-nar/src/info.rs`. The consumer parses the same static text back
into `NarInfo` and reads exactly these fields (`crates/packages/aos-package-manager/src/download.rs`).

| narinfo field | Source in `render_static_narinfo` / `registry::nixcache` | Notes |
|---|---|---|
| `StorePath` | `<store_dir>/<basename(store_path)>` | Full store path; `basename` comes from `aos_nar::info`. |
| `URL` | `nar_url(store_path, file_hash, compression)` | Relative to the cache URL; `nar/{store_hash}-sha256-{file_hash as lowercase hex}.{ext}`, built from the compressed file's hash (§9). The consumer joins it via `join_cache_url`. |
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
(`info.rs`), and `parse()` ignores any unknown keys (`info.rs`), so the
round trip is lossless for the fields AOS uses.

> **Trust note:** for the AOS consumer, narinfos are **advisory
> transport metadata** - they supply the NAR URL, compression, and sizes for
> planning, plus the `FileHash` integrity precheck. The *trust decision* for
> the decompressed bytes is the registry's signed `store/` realisation graph
> ([`repository-layout.md`](repository-layout.md) §5): every downloaded NAR's
> uncompressed SHA-256 and size must match a blessed entry, and a narinfo
> `NarHash` disagreeing with `store/` always resolves in favor of `store/`. Only
> registries that publish no graph at all fall back to trusting `NarHash`
> (with a warning). Stock-Nix consumers, which cannot read `store/`, keep the
> narinfo `Sig:` Ed25519 signature (§8) as their substitution defence.

### 6.1 Example static narinfo

Shape of the static file the producer emits via `render_static_narinfo`:

```
StorePath: /nix/store/abc123def456abc123def456abc123de-curl-8.5.0
URL: nar/abc123def456abc123def456abc123de-sha256-1f2e3d4c….nar.zst
Compression: zstd
FileHash: sha256:1f2e3d4c5b6a79880011223344556677889900aabbccddeeff00112233445566
FileSize: 1894572
NarHash: sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
NarSize: 6553600
References: r4q1m2kp8v3x…-glibc-2.39 xr5is7by89v3q…-zlib-1.3.1
Deriver: q8mn2pv73w0x…-curl-8.5.0.drv
Sig: aos-core:base64signature==
```

Note the `URL:` form: `nar/{store_hash}-sha256-{hex}.{ext}`, where the hex
digest is the `FileHash` of the compressed file, not the `NarHash` (§9).

### 6.2 Sysroot images are their own store paths

For sysroot packages, each pre-compiled image (`SysrootImageEntry`, defined in
`crates/registry/aos-registry-format/src/manifest.rs` and carried in
`PackageMeta.images`, `consumer.rs`) is
itself a distinct store path with its own `store_path` / `nar_hash` /
`download_hash`. Because narinfos are keyed by store-path hash, the producer
emits a separate static `<storehash>.narinfo` for each such image, via the
same `render_static_narinfo` logic (§6) — no per-image special case. The field
mapping is identical; the image is just another store path.

---

## 7. References basename expansion

Nix narinfo `References` requires **store-path basenames** of the form
`<hash>-<name>`, not bare hashes. The reusable format logic writes them in this
form: `render_static_narinfo` maps every full store-path reference through
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
> graph (`ia:sha256:<store-hash>` lines;
> `crates/registry/aos-registry-client/src/registry/store.rs`). That bare-hash form lives in the
> git tree and is consumed by `apm`'s closure walk; it is **independent** of the
> narinfo-layer `References`, which the producer writes as basenames from the
> store DB into the static narinfo. The two layers are decoupled (§1) — no
> expansion step crosses between them.

> **Why basenames matter:** if `References` were emitted as bare hashes, stock
> `nix` would reject the narinfo (it parses references as store-path basenames
> and validates them against `StoreDir`).

---

## 8. Signing: a separate cache role

The narinfo-signing logic is implemented by `NarInfoSigner` in
`crates/artifacts/aos-nar/src/cache.rs`. `fingerprint(store_path, nar_hash, nar_size,
refs)` produces the standard Nix narinfo fingerprint
`1;{store_path};{nar_hash};{nar_size};{refs}`; `sign(fingerprint)` signs it with
the Ed25519 secret and returns `name:base64sig`; and
`render_static_narinfo` appends the `Sig:` line. The producer bakes the `Sig:`
into each static narinfo at publish. Production deployments use a dedicated
cache-signing Ed25519 keypair instead of the registry tag-signing key:

- The registry key signs git tag objects via an SSH-format signature and is trusted
  through the AOS anchor and `keys.toml` roster.
- The cache key signs the Nix fingerprint
  `(StorePath, NarHash, NarSize, References)` and is distributed as
  `<name>:<base64>` through the Nix `trusted-public-keys` configuration.

Both paths use Ed25519, but they are different roles and different key material.
This keeps a cache-publishing compromise from granting release authority and lets
operators rotate cache trust without rotating the registry root.

### 8.1 Why a per-narinfo `Sig` exists at all

`apm`'s trust is rooted in the **signed git tag chain**: the Ed25519-signed
`tag → tag → commit` authenticates the whole git tree (a Merkle DAG), which
includes every package TOML and the `store/` realisation graph recording each
blessed NAR's SHA-256 and size.
So `apm` needs **no** per-NAR signature; NARs are authenticated transitively and
verified against `store/` after download (`verify_downloads`,
`crates/packages/aos-package-manager/src/verify.rs`).

The per-narinfo `Sig:` exists **only** to satisfy a stock `nix` substituter
without forcing the operator to set `require-sigs = false`. It is a compatibility
affordance for the Nix protocol — orthogonal to the AOS trust chain, exactly as
the NAR-cache layer itself is (§1).

```
apm trust:   signed tag chain ──► store/ ──► NAR sha256 (transitive, no Sig needed)
nix trust:   cache-role narinfo Sig ──► NarHash         (per-path, satisfies require-sigs)
```

See [signing-and-trust.md](signing-and-trust.md) for the full key model,
name-binding, and the `tag → tag → commit` chain.

---

## 9. NAR blob layout and the `URL:` field

The narinfo `URL:` is a relative path under the configured cache URL (§3),
pointing at a static `.nar.zst` file the producer uploaded. The format logic
and consumer already agree on it:

1. **`URL:` written into the static narinfo.** `nar_url` writes
   `nar/{store_hash}-sha256-{hex}.{ext}`. The compressed file's hash is
   canonicalized to lowercase hex, so the key is colon-free
   (e.g. `nar/<storehash>-sha256-<hex>.nar.zst`). The producer uploads the
   compressed NAR to exactly this static `.nar.zst` / `.nar.xz` / `.nar` path.
   Because `FileHash` identifies the transferred bytes, changing compression
   output produces a new immutable URL even when the uncompressed `NarHash`
   remains unchanged.
2. **Consumer resolution.** `apm` downloads from the cache base joined
   with the narinfo-supplied `URL:` — `join_cache_url(mirror_url, narinfo.url)`
   (`crates/packages/aos-package-manager/src/download.rs`). It
   does not synthesize the key; it uses the `URL:` the narinfo carries.
3. **Cache placement.** The cache base comes from the committed
   `registry.toml` `[caches]` stack, any client-side `registries.d` entries,
   or the registry URL itself (§3). The narinfo `URL:` is resolved relative to
   whichever cache base `apm` ends up selecting.

```
<cache-url>/nar/<storehash>-sha256-<hex>.nar.zst   <-- emitted key (colon-free)
        └── narinfo URL: nar/<storehash>-sha256-<hex>.nar.zst
```

> **Colon-in-filename:** because the format logic writes the file hash as
> `sha256-<hex>` in the `URL:`, the static object key is colon-free, so
> CDN/edge layers that mangle a literal `:` are not a concern for the
> generated static files. (The `aos-nix-cache` backend keys —
> `<storehash>.narinfo` / `nar/<filename>` — are likewise colon-free.)

---

## 10. Using the AOS cache as a dev-shell substituter

Once the producer has published the static `nix-cache-info` + `*.narinfo` +
`nar/` files with per-narinfo `Sig:` (§4, §5, §6, §8), a non-AOS host running
stock `nix` consumes them as an ordinary binary cache — static files, no
server — exactly like any other static substituter. A stock `nix` host has
no AOS git layer, so it simply names the substituter URL directly in
`nix.conf` (§10.1). An AOS host, by contrast, resolves the cache from the
committed `registry.toml` `[caches]` stack (authenticated via the tag),
optionally supplemented by its client-side `registries.d/<name>.toml` (§3).
Either way there is no tag to decode — the cache pointer is a tree file or
local config, not a tag payload.

### 10.1 `nix.conf`

```ini
# /etc/nix/nix.conf  (or ~/.config/nix/nix.conf for per-user)

# Append the resolved AOS cache URL. Order does not imply priority — that comes
# from each cache's nix-cache-info `Priority` (§5).
extra-substituters = https://registry.aos.dev/core/nar

# Trust the cache-signing Ed25519 key in Nix's <name>:<base64> form (§8).
extra-trusted-public-keys = aos-core:base64publickeyhere==
```

- Use `extra-substituters` / `extra-trusted-public-keys` (the `extra-` prefix
  **appends** to the defaults) so `cache.nixos.org` is retained.
- The key value is the cache-signing public key in Nix's `<name>:<base64>`
  encoding. It is a different key from the registry's
  `aos-core:Ed25519:<base64>` tag-signing key (§8).
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
host nix              AOS static CDN cache (the URL named in nix.conf)
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
tag → semver tag → commit → package TOML and `store/`) and fetches NARs from
the cache named in the committed `registry.toml` `[caches]` stack (or a
client-side entry) — verifying the bytes against `store/` (`verify.rs`), never
the narinfo `Sig:`. The two clients share the blobs but trust them via
independent layers (§1).

---

## 11. Implementation map

The shared narinfo logic, the narinfo-driven consumer, and the static producer
are summarized here. These are libraries and commands; none of them is a
server the registry runs.

| Capability | Where it lives | Cite |
|---|---|---|
| Shared `NarInfo` type + `parse`/`format` | `aos-nar` | `src/info.rs` |
| Static narinfo rendering, URL construction, cache-info body, and Nix `Sig:` | `aos-nar` | `src/cache.rs` |
| Static cache generation, local completeness checks, compressed NAR writing, upload, and `[caches]` update | `aos-registry-authoring` | `registry/nixcache.rs`; `run_cache` in `registry_ops/distribution.rs` |
| Static object upload backends (`put_*`, `put_cache_info`) | `aos-nix-cache` | `backend/mod.rs`; backend implementations |
| Consumer (`apm`) reads a dumb static narinfo cache | `aos-package-manager` | `download.rs` |

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
The VM check that validates this path is
`checks.vm.apm.registry-validation-stock-nix-backend-array`.


---

## See also

- [architecture.md](architecture.md) — the git-over-dumb-HTTP layer and where the
  NAR cache sits relative to it.
- [repository-layout.md](repository-layout.md) — the committed git tree, including
  `registry.toml` `[caches]` (where the cache list lives) and `keys.toml`.
- [http-layout.md](http-layout.md) — full HTTP/object layout and CDN TTLs.
- [signing-and-trust.md](signing-and-trust.md) — role separation, name-binding,
  `tag → tag → commit`.
- [implementation.md](implementation.md) — crate and module map.
