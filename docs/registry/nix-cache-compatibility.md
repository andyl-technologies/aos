# Nix Binary-Cache Compatibility

> **Audience:** users running non-AOS dev shells against an AOS registry,
> implementers building the `nix-cache-info` / narinfo emitter, and architects
> reasoning about the git-metadata layer versus the NAR-cache layer.
>
> **Status legend:** **CURRENT** = behavior present in the code today (cited as
> `path:line`). **TARGET** = the design decided in the
> [design brief](../plans/registry/design-brief.md) §13 (and §11 for signing),
> not yet fully built.

This document explains how an AOS registry origin is, by design, a **strict
superset** of the standard Nix binary-cache (substituter) protocol. The
NAR-cache surface is **orthogonal** to the git-object metadata layer: it is not
part of the trust chain that `apm` walks. Its location is **not** advertised in
signed tags — signed tags are pure signed pointers and carry no structured
payload. The substituter location is the **consumer's client-side
configuration** (its local registry config) or the **origin itself**, which may
serve the stock-Nix surface (`nix-cache-info` / `<storehash>.narinfo` / `nar/`)
alongside the git metadata.

See also:
[README.md](README.md) ·
[architecture.md](architecture.md) ·
[http-layout.md](http-layout.md) ·
[current-state.md](current-state.md) ·
[versioning-and-channels.md](versioning-and-channels.md) ·
[packs-and-deltas.md](packs-and-deltas.md) ·
[signing-and-trust.md](signing-and-trust.md) ·
[publishing.md](publishing.md) ·
[apt-comparison.md](apt-comparison.md)

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
   / `nar/` surface. A stock `nix` substituter consumes this layer for dev-shell
   substitution. It is a **strict superset** of the standard Nix binary cache.

The link between them is deliberately thin. The git layer does **not** point at
the NAR-cache layer at all — signed tags carry no cache advertisement. The
substituter location is the **consumer's client-side configuration** or the
**origin itself**; the NAR cache may physically live anywhere — co-located with
the git repo on the same origin or on a separate host. Neither layer's
correctness depends on the other:

```
            ┌──────────────────────────────────────────┐
  apm   ──► │  git metadata layer  (bare sha256 repo)   │  ← trust root
            │  channels=branches · releases=signed tags │     (signed tags)
            │  signed tag = pure signed pointer         │     (no cache payload)
            └──────────────────────────────────────────┘
                                                           ▼ client-side config
            ┌──────────────────────────────────────────┐    (or the origin itself)
  nix   ──► │  NAR-cache layer                          │  ← NOT in apm trust chain
            │  nix-cache-info · <storehash>.narinfo     │     (per-narinfo Sig:)
            │  nar/<key>.nar.zst                        │
            └──────────────────────────────────────────┘
```

> **Why "orthogonal" and not "disjoint namespaces":** an earlier capture framed
> the two as two URL prefixes on one mandatory origin, and a later one advertised
> the cache through a tag-embedded `[[caches]]` table. In the git-native target,
> the cache is neither pinned to the same origin nor advertised in-band: its
> location is the consumer's client-side registry config, or simply the origin
> serving the stock-Nix surface itself. The metadata layer is authoritative; the
> NAR cache is a client-configured, swappable substituter.

---

## 2. The strict-superset idea

A standard Nix binary cache is a dumb HTTP origin that answers three kinds of
request, all relative to a **cache base URL**:

1. `GET {cache}/nix-cache-info` — a fixed-name capability/identity stub.
2. `GET {cache}/<storehash>.narinfo` — per-store-path text metadata, keyed by the
   32-character base32 store-path hash.
3. `GET {cache}/nar/<…>.nar[.zst|.xz]` — the content-addressed NAR blob the
   narinfo points at.

An AOS origin that serves a cache answers exactly these three, so any host that
knows nothing about AOS can point a stock `nix` at the cache URL and use it as an
ordinary substituter. AOS adds nothing the Nix protocol cannot ignore — that is
the **strict superset**.

> **Why the projection lines up so cleanly:** Nix's two-level naming — a
> store-hash narinfo that *indirects* to a content-addressed NAR — is exactly how
> AOS already names blobs. AOS records a `store_path` (carrying the store-hash)
> and a `nar_hash` (content address of the blob) per package version. The narinfo
> is just a reprojection of metadata AOS already holds in its git tree.
> (design brief §13)

---

## 3. Where the cache location comes from (TARGET)

The cache is **not** advertised in any signed tag. Signed tags are pure signed
pointers and carry no structured payload — there is no tag-message TOML, no
`[meta]`, no `[[caches]]`. The substituter location instead comes from one of two
places:

1. **Client-side configuration.** The consumer's own local registry config names
   the substituter(s) it trusts, exactly as a stock `nix` host lists
   `extra-substituters` in `nix.conf` (§10). This is the authoritative source of
   "which cache do I use".
2. **The origin itself.** The origin that serves the git metadata **may** also
   serve the stock-Nix surface (`nix-cache-info` / `<storehash>.narinfo` / `nar/`)
   under its own URL. A consumer that simply points at the origin gets both
   layers from one host with no separate advertisement step.

Whichever base URL the consumer selects, the standard Nix relative paths give the
three superset endpoints:

```
<cache-url>/nix-cache-info             Nix: capability stub   (§5)
<cache-url>/<storehash>.narinfo        Nix: per-path metadata (§6)
<cache-url>/nar/<key>.nar.zst          Nix: NAR blob          (§9)
```

- A consumer may configure multiple substituter URLs; ordering/preference is a
  stock-Nix concern, driven by each cache's `nix-cache-info` `Priority` (§5), not
  by any in-band AOS field.
- Because the cache list is client-side (the consumer's own `registry.toml`, §4)
  or simply the origin itself — rather than embedded in a signed tag — there is no
  unsigned *in-band* side-channel served by the origin to reconcile.
  (`bundle-list.toml`, `[latest]`, `[components]`, and `[capabilities]` are
  **removed** from the target — design brief §15.)

---

## 4. What exists today (CURRENT)

The NAR **blob layer** already exists and carries straight over; the git-native
metadata and the narinfo emitter do not yet exist.

**Cache parsing & resolution (CURRENT).** The code already reads a `[[caches]]`
array from a standalone **`registry.toml`** inside the registry clone — a
**client-side** config file, not a signed tag. The target keeps cache selection
client-side (§3); it is **not** moved into any signed tag. The
parsing/sorting/selection logic below is reusable as-is.

- `CacheEntry { url, priority }` with `default_cache_priority() == 100`
  (`crates/aos-package/src/types.rs:585-593`), nested under `RegistryRootConfig`
  (`types.rs:566-573`).
- `resolve_mirrors` reads the caches and sorts them **descending by priority**
  (higher first), returning `Vec<CacheEntry>`
  (`crates/aos-package/src/registry_ops.rs:405-414`).
- `resolve_mirror` picks the first (highest-priority) cache, else falls back to
  `{registry.url}/nar` (`crates/aos-package/src/download.rs:67-82`).

**Blob download (CURRENT).** Content-addressed and zstd-compressed:

- `nar_url(mirror_url, nar_hash)` builds `{mirror_url}/{nar_hash}.nar.zst`, using
  the **full** `sha256:<hex>` string — the literal colon is kept in the wire
  filename (`crates/aos-package/src/download.rs:57-60`).
- The compressed file is verified by SHA-256 of its bytes against
  `download_hash` (`crates/aos-package/src/download.rs:102-115`), **not** by a
  signature.
- On disk the consumer rewrites the colon to a dash for filesystem safety:
  `nar_cache_filename` → `sha256-<hex>.nar.zst`
  (`crates/aos-package/src/download.rs:232-235`).

**narinfo source data (CURRENT).** The fields a narinfo needs already exist in
the flattened in-memory `PackageMeta`
(`crates/aos-package/src/types.rs:43-77`), which is the projection of the nested
on-disk `PackageToml` (deserialized in
`crates/aos-package/src/registry/parse.rs`). Every narinfo field except the
signature maps to a field already on that struct (§6).

What is **missing** today: there is no `nix-cache-info` emitter and no
`*.narinfo` emitter anywhere in the tree. The cache list stays where it is —
read from the client-side `registry.toml` (or pointed straight at the origin) —
so no migration into a signed tag is needed.

---

## 5. The `nix-cache-info` stub (TARGET)

Nix hardcodes the name `nix-cache-info` and fetches it once per cache to learn
the store directory and query behavior. It is a tiny static file served at the
**root of the cache URL**, written once at publish time:

```
StoreDir: /nix/store
WantMassQuery: 1
Priority: 41
```

| Key | Meaning | AOS value |
|---|---|---|
| `StoreDir` | Store prefix the NARs were built against. Must match the consuming host's store. | The AOS store dir the packages were built with (commonly `/nix/store`). Supplied by the publish pipeline — **not** derivable from any `types.rs` field. |
| `WantMassQuery` | `1` lets `nix` batch-query this cache when computing substitutions. | `1` — the origin is a plain object store; mass query is cheap. |
| `Priority` | Lower = preferred. Stock `cache.nixos.org` is `40`. | Operator policy knob. Use `> 40` to be consulted **after** the upstream cache for shared paths, or `< 40` to prefer AOS. |

> Note: the `nix-cache-info` `Priority` is the **Nix-cache** preference knob,
> consumed by stock `nix` to order substituters. It is distinct from the
> client-side `priority` field AOS's `registry.toml` uses to order the caches a
> consumer has configured (§3, §4).

---

## 6. narinfo field mapping (TARGET)

A narinfo is line-oriented `Key: value` text. The table maps each narinfo field
to the corresponding field on the flattened `PackageMeta`
(`crates/aos-package/src/types.rs:43-77`). This is the authoritative mapping from
design brief §13, reconciled with the actual struct.

| narinfo field | Source (`PackageMeta` field / derivation) | Code reference | Notes |
|---|---|---|---|
| `StorePath` | `store_path` | `types.rs:53` | Full store path, e.g. `/nix/store/<hash>-<name>`. |
| `URL` | derived: `nar/<key>.nar.zst` (relative to cache) | n/a (`download.rs:57`) | Relative path to the blob under the configured cache URL. See §9 for the exact key. |
| `Compression` | constant `zstd` | n/a | AOS NARs are always zstd-compressed (`.nar.zst`). |
| `FileHash` | `download_hash` (`sha256:<hex>`) | `types.rs:57-58` | Hash of the **compressed** `.nar.zst` file. |
| `FileSize` | `download_size` | `types.rs:59` | Size in bytes of the compressed file. |
| `NarHash` | `nar_hash` (`sha256:<hex>`) | `types.rs:54` | Hash of the **uncompressed** NAR. |
| `NarSize` | `nar_size` | `types.rs:56` | Size in bytes of the uncompressed NAR. |
| `References` | `references` (**bare hashes**) | `types.rs:60-61` | ⚠️ Must be expanded `<hash>` → `<hash>-<name>` basenames; see §7. |
| `Deriver` | `source_drv` | `types.rs:64` | Optional. The `.drv` basename, e.g. `<hash>-<name>.drv`. |
| `Sig` | — (must be generated) | n/a | **Not present in any TOML.** Ed25519 narinfo signature; see §8. |
| `System` | `platform` (optional, omittable) | `types.rs:52` | Nix tolerates absence; not required. |
| `CA` | — (omit) | n/a | AOS paths are input-addressed; `CA` omitted. |

Fields AOS carries but a narinfo does not need:

- `closure_size` (`types.rs:66-67`) — AOS-side total closure size; Nix recomputes
  closures from `References`.
- `source_nar_hash` (`types.rs:65`) — provenance of the source derivation; not a
  narinfo field.
- `sysroot` / `previous` / `images` (`types.rs:69-76`) — AOS sysroot semantics;
  irrelevant to the narinfo *fields*. But the `images` entries are themselves
  store paths and each gets its own narinfo — see §6.2.

### 6.1 Example emitted narinfo (TARGET)

```
StorePath: /nix/store/abc123def456abc123def456abc123de-curl-8.5.0
URL: nar/sha256:1f2e3d…nar.zst
Compression: zstd
FileHash: sha256:1f2e3d4c5b6a79880011223344556677889900aabbccddeeff00112233445566
FileSize: 1894572
NarHash: sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
NarSize: 6553600
References: r4q1m2kp8v3x…-glibc-2.39 xr5is7by89v3q…-zlib-1.3.1
Deriver: q8mn2pv73w0x…-curl-8.5.0.drv
Sig: aos-core:base64signature==
```

### 6.2 Sysroot images are their own store paths (TARGET)

For sysroot packages, each pre-compiled image (`SysrootImageEntry`, carried in
`PackageMeta.images`, `types.rs:74-76` and defined at `types.rs:607-614`) is
itself a distinct store path with its own `store_path` / `nar_hash` /
`download_hash`. Each such image therefore gets its **own**
`<storehash>.narinfo`, emitted exactly like a regular package narinfo (§6) —
keyed by the image's store-path hash, pointing at the image's NAR blob. The
field mapping is identical; only the source struct differs (`SysrootImageEntry`
rather than the top-level `PackageMeta`).

---

## 7. References basename expansion (TARGET)

This is the **one non-mechanical transform** in the mapping. AOS stores the
`references` field as a list of **bare store-path hashes** — "Store path hashes
of direct runtime references" (`crates/aos-package/src/types.rs:60-61`). The
closure files (`closures/<hash>`) use the same bare-hash adjacency-list format
(`types.rs:90-95`).

Nix narinfo `References`, by contrast, requires **store-path basenames** of the
form `<hash>-<name>`. The emitter must resolve each bare hash to its full
basename:

```
AOS references:        [ "r4q1m2kp8v3x…", "xr5is7by89v3q…" ]
                                │                  │
                  resolve hash → store_path basename
                                │                  │
narinfo References:    r4q1m2kp8v3x…-glibc-2.39  xr5is7by89v3q…-zlib-1.3.1
```

The name suffix for each hash is recoverable from the referenced package's own
`store_path` (`types.rs:53`) — the emitter looks up the dependency's package
metadata and takes the basename of its `StorePath`. The registry already records
every dependency's `store_path`, so this is purely a join over metadata the
registry holds.

> **Why it matters:** if `References` is left as bare hashes, stock `nix` rejects
> the narinfo (it parses references as store-path basenames and validates them
> against `StoreDir`).

---

## 8. Signing: one key, two signature forms (TARGET)

The `Sig:` line is the only narinfo field with no source in the AOS metadata — it
must be **generated**. The design reuses the **same single Ed25519 keypair** that
signs the git tags (design brief §11):

- **One secret key** signs (a) git tag objects via an SSH-format signature and
  (b) narinfos via the Nix fingerprint
  `(StorePath, NarHash, NarSize, References)`. The *signed messages differ*, so
  the *signatures differ*, but there is **one secret to manage**.
- **Two published public-key encodings** from that one key:
  - `aos-core:Ed25519:<base64>` — the apm form for TOFU / `trusted-keys.d` (the
    `SigningConfig.public_key` format, `crates/aos-package/src/types.rs:249-250`,
    parsed as `<name>:Ed25519:<base64>` by `parse_signing_key` in `security.rs`).
  - `<name>:<base64>` — the nix form for Nix `trusted-public-keys`.

### 8.1 Why a per-narinfo `Sig` exists at all

`apm`'s trust is rooted in the **signed git tag chain**: the Ed25519-signed
`tag → tag → commit` authenticates the whole git tree (a Merkle DAG) → every
package TOML → every NAR SHA-256 recorded in those TOMLs (design brief §5, §11).
So `apm` needs **no** per-NAR signature; NARs are authenticated transitively and
verified by content hash (`download.rs:102-115`).

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

## 9. NAR blob layout and the `URL:` field (TARGET)

The narinfo `URL:` is a relative path the cache must serve, under the configured
cache URL (§3). Two facts constrain it:

1. **CURRENT blob key.** The consumer downloads from
   `{mirror_url}/{nar_hash}.nar.zst` with the full `sha256:<hex>` retained
   (`crates/aos-package/src/download.rs:57-60`). On disk it rewrites the colon to
   a dash (`download.rs:232-235`), but the **wire** filename keeps the colon.
2. **Cache placement (client-side).** The cache may be co-located with the git
   repo on one origin or on a separate host; which one a consumer uses is its
   client-side config (§3). The narinfo `URL:` is resolved relative to whichever
   cache base the client selected (§3, §10).

```
<cache-url>/nar/sha256:<hex>.nar.zst   <-- AOS wire key (colon retained)
        └── narinfo URL: nar/sha256:<hex>.nar.zst
```

> **Colon-in-filename caveat:** S3 allows a literal `:` in object keys, but some
> CDN/edge layers percent-encode or reject it. If the chosen edge mangles the
> colon, the emitter must serve the blob under a colon-free key (e.g. the
> `sha256-<hex>` form the consumer already uses on disk, `download.rs:232-235`)
> and set `URL:` to match. This is a deployment decision; see
> [open-questions.md](../plans/registry/open-questions.md).

---

## 10. Using the AOS cache as a dev-shell substituter (TARGET)

Once a cache emits `nix-cache-info` + `*.narinfo` (§5, §6), a non-AOS host
running stock `nix` consumes it as an ordinary binary cache. The substituter URL
is whatever the consumer **configures client-side** (§3) — typically the origin
itself if the origin also serves the stock-Nix surface, or a separate cache host.
There is no tag to resolve: the URL is named directly in `nix.conf` or the AOS
client's `registry.toml`.

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
host nix                         AOS cache (client-configured URL)
   │                                   │
   │  GET /nix-cache-info               │   StoreDir/Priority/WantMassQuery  (§5)
   │ ─────────────────────────────────►│
   │  GET /<storehash>.narinfo          │   field-mapped from PackageMeta    (§6)
   │ ─────────────────────────────────►│
   │      verify Sig: against           │
   │      trusted-public-keys  (§8)     │
   │  GET /nar/<key>.nar.zst            │   content-addressed blob           (§9)
   │ ─────────────────────────────────►│
   │      verify NarHash, decompress    │
```

`apm` on an AOS host, meanwhile, walks the git metadata layer (channel partition
tag → semver tag → commit → package TOML) and fetches NARs by content hash from
its client-configured cache (or the origin itself) — verifying `download_hash`
(`download.rs:102-115`), never the narinfo `Sig:`. The two clients share the
blobs but trust them via independent layers (§1).

---

## 11. Summary: what must be built

From design brief §13, the delta to reach the target (the blob layer in §4 is
already done in `download.rs`; the work is the metadata projection and signing on
the **producer** side):

1. **Client-side cache selection stays put** — the existing `CacheEntry` shape
   (`types.rs:585-593`) keeps living in the consumer's `registry.toml` (or the
   consumer points straight at the origin). Nothing is embedded in a signed tag
   (§3); no migration is required here.
2. A **`nix-cache-info` stub** emitter (§5) — `StoreDir` supplied by the publish
   pipeline.
3. A **narinfo generator** keyed by store-path hash, projecting `PackageMeta`
   (§6), including **sysroot-image narinfos** (§6.2).
4. **References basename expansion** — bare hash → `<hash>-<name>` (§7).
5. **Per-narinfo Ed25519 `Sig:`** using the one shared key (§8).
6. **Reachable NAR blobs** under a `URL:` the chosen cache serves without mangling
   the key (§9).
7. **Dev-shell wiring docs** (§10) — already captured here; the substituter and
   key plumbing is stock Nix.

These map to plan
[workstream-05-consumer.md](../plans/registry/workstream-05-consumer.md) (the
consumer-side Nix substituter superset) and
[workstream-04-signing-trust.md](../plans/registry/workstream-04-signing-trust.md)
(the one-key signing model).

---

## See also

- [architecture.md](architecture.md) — the git-over-dumb-HTTP layer and where the
  NAR cache sits relative to it.
- [http-layout.md](http-layout.md) — full HTTP/object layout and CDN TTLs.
- [signing-and-trust.md](signing-and-trust.md) — the one-key model, name-binding,
  `tag → tag → commit`.
- [current-state.md](current-state.md) — the as-is bundle/`creation_token`
  implementation.
- Plan: [workstream-05-consumer.md](../plans/registry/workstream-05-consumer.md),
  [workstream-04-signing-trust.md](../plans/registry/workstream-04-signing-trust.md),
  [open-questions.md](../plans/registry/open-questions.md),
  [design-brief.md](../plans/registry/design-brief.md) §13, §11.
