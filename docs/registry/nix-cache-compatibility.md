# Nix Binary-Cache Compatibility

> **Audience:** users running non-AOS dev shells against an AOS registry,
> implementers building the narinfo/`nix-cache-info` emitter, and architects
> reasoning about the two-protocol origin.
>
> **Status legend:** **CURRENT** = behavior present in the code today (cited as
> `path:line`). **TARGET** = the design decided in the
> [design brief](../plans/registry/design-brief.md) §4.1–§4.2, not yet built.

This document explains how an AOS registry origin is, by design, a **strict
superset** of the standard Nix binary-cache (substituter) protocol: the same
HTTP origin can serve both the AOS-native metadata (consumed by `apm`) and the
Nix narinfo/NAR protocol (consumed by a stock `nix` substituter), because the
two protocols occupy **disjoint URL namespaces**.

See also:
[architecture.md](architecture.md) ·
[http-layout.md](http-layout.md) ·
[current-state.md](current-state.md) ·
[registry-toml.md](registry-toml.md) ·
[signing-and-trust.md](signing-and-trust.md) ·
[bundles-and-deltas.md](bundles-and-deltas.md) ·
[README.md](README.md)

---

## 1. The strict-superset idea

A standard Nix binary cache is a dumb HTTP origin that answers three kinds of
request:

1. `GET {base}/nix-cache-info` — a fixed-name capability/identity stub.
2. `GET {base}/<storehash>.narinfo` — per-store-path text metadata, keyed by the
   32-character base32 store-path hash.
3. `GET {base}/nar/<…>.nar[.zst|.xz]` — the content-addressed NAR blob the
   narinfo points at.

An AOS registry origin already serves the AOS-native protocol on a different set
of paths:

- `GET {base}/registry.toml` — the single signed root (**TARGET**; see
  [registry-toml.md](registry-toml.md)).
- `GET {base}/bundles/{name}/…` — git bundles of the TOML metadata
  (**CURRENT**; see [bundles-and-deltas.md](bundles-and-deltas.md)).

The two namespaces never collide:

```
{base}/                       <-- one HTTP origin
├── registry.toml             AOS: signed root              (TARGET)
├── bundles/<name>/…          AOS: git bundles              (CURRENT)
│
├── nix-cache-info            Nix: capability stub          (TARGET)
├── <storehash>.narinfo       Nix: per-path metadata        (TARGET)
└── nar/<…>.nar.zst           shared: content-addressed NAR (CURRENT blobs)
```

Because adding the Nix endpoints is purely **additive**, a host that knows
nothing about AOS can point a stock `nix` at the same URL and use it as an
ordinary substituter, while `apm` continues to use the registry endpoints. This
is the **strict superset**: every Nix-cache request is answerable, and AOS adds
more on top.

> **Why it lines up so cleanly:** Nix's two-level naming — a store-hash narinfo
> that *indirects* to a content-addressed NAR — is exactly how AOS already names
> blobs. AOS records a `store_path` (carrying the store-hash) and a `nar_hash`
> (content address of the blob) per package version. The narinfo is just a
> reprojection of metadata AOS already has. (design brief §4.1)

---

## 2. What exists today (CURRENT)

The AOS registry is **not yet** a Nix binary cache. A stock `nix` substituter
cannot consume it as-is, because:

- There is no `nix-cache-info` emitter and no `*.narinfo` emitter anywhere in
  the tree (design brief §2.11, §3.2). The producer is a thin wrapper over
  `git` + `git bundle create`.
- AOS distributes metadata as git bundles of TOML, not as narinfo text files.

What **does** exist today and carries straight over is the **NAR blob layer**.
The consumer-side NAR download path is already content-addressed and
zstd-compressed:

- `nar_url(mirror_url, nar_hash)` builds `{mirror_url}/{nar_hash}.nar.zst`,
  using the **full** `sha256:<hex>` string (the literal colon is in the
  filename) — `crates/aos-package/src/download.rs:57`.
- The compressed file is verified by SHA-256 of its bytes against
  `download_hash` (`crates/aos-package/src/download.rs:102-115`), **not** by a
  signature — design brief §2.8.
- The mirror is resolved from `[[caches]]` in the local registry clone (sorted
  by priority), falling back to `{registry.url}/nar` —
  `crates/aos-package/src/download.rs:67-82`.

> **Discrepancy note (URL grammar):** the *current* AOS blob filename uses the
> full `sha256:<hex>` (colon retained), e.g. `nar/sha256:<hex>.nar.zst`
> (`download.rs:57`). The *standard* Nix `URL:` field points at
> `nar/<filehash>.nar.<ext>` where the filename is typically the **compressed**
> file hash, often without the algorithm prefix. The narinfo `URL:` field is
> free-form relative text, so the emitter can point at whatever object key the
> origin actually serves — but implementers must pick one canonical key and
> ensure the blob is reachable under it. See §7 and the open questions.

The package metadata that the narinfo emitter will read from already exists. The
narinfo source data lives in the **nested on-disk package TOML** — `PackageToml`
(`[package]` header + `[[versions]]` + `[versions.platforms.<platform>]`),
deserialized in `crates/aos-package/src/registry/parse.rs:14-70`. At load time
`parse_package_toml` (`parse.rs:133-178`) **flattens** that nested shape into a
per-(package, platform) `PackageMeta` projection
(`crates/aos-package/src/types.rs:43-77`). Every narinfo field except the
signature maps to a field already present in that flattened struct (see §4).

---

## 3. The `nix-cache-info` stub (TARGET)

Nix hardcodes the name `nix-cache-info` and fetches it once per cache to learn
the store directory and query behavior. It is a tiny static file, regenerated
(or simply written once) at publish time:

```
StoreDir: /nix/store
WantMassQuery: 1
Priority: 41
```

| Key | Meaning | AOS value |
|---|---|---|
| `StoreDir` | Store prefix the NARs were built against. Must match the consuming host's store. | The AOS store dir the packages were built with (commonly `/nix/store`). |
| `WantMassQuery` | `1` lets `nix` batch-query this cache when computing substitutions. | `1` — the origin is a plain object store; mass query is cheap. |
| `Priority` | Lower = preferred. Stock `cache.nixos.org` is `40`. | Operator policy knob. Use `> 40` so it is consulted **after** the upstream cache for shared paths, or `< 40` to prefer AOS. |

> **On the `Priority` value:** `41` above is an *illustrative* static default; the
> dynamic server emits `30`. Either way it is an operator policy knob, not a
> protocol constant — set it relative to `cache.nixos.org`'s `40` per the
> consult-before/after intent above.

> **CURRENT vs TARGET:** `nix-cache-info` is listed as an explicit producer gap
> ("narinfo / nix-cache-info" → ❌) in design brief §2.11. It does not exist in
> the code today. The `StoreDir` value is a deployment decision tied to how AOS
> packages were built; it is **not** derivable from any field in
> `crates/aos-package/src/types.rs` and must be supplied by the publish
> pipeline.

---

## 4. narinfo field mapping

A narinfo is line-oriented `Key: value` text. The on-disk source is the nested
package TOML (`PackageToml`, `registry/parse.rs:14-70`); the table below maps
each narinfo field to the corresponding field on the **flattened** `PackageMeta`
/ `PlatformEntry` projection (`crates/aos-package/src/types.rs:43-77`) that
`parse_package_toml` produces. This is the authoritative mapping from design
brief §4.1, reconciled with the actual struct fields.

| narinfo field | Source (`PackageMeta` field / derivation) | Code reference | Notes |
|---|---|---|---|
| `StorePath` | `store_path` | `types.rs:53` | Full store path, e.g. `/nix/store/<hash>-<name>`. |
| `URL` | derived: `nar/<key>.nar.zst` (relative) | n/a (§2.8 / `download.rs:57`) | Relative path to the blob on this origin. See §7 for the exact key. |
| `Compression` | constant `zstd` | n/a | AOS NARs are always zstd-compressed (`.nar.zst`). |
| `FileHash` | `download_hash` (`sha256:<hex>`) | `types.rs:58` | Hash of the **compressed** `.nar.zst` file. |
| `FileSize` | `download_size` | `types.rs:59` | Size in bytes of the compressed file. |
| `NarHash` | `nar_hash` (`sha256:<hex>`) | `types.rs:54` | Hash of the **uncompressed** NAR. |
| `NarSize` | `nar_size` | `types.rs:56` | Size in bytes of the uncompressed NAR. |
| `References` | `references` (**bare hashes**) | `types.rs:61` | ⚠️ Must be expanded `<hash>` → `<hash>-<name>` basenames; see §5. |
| `Deriver` | `source_drv` | `types.rs:64` | Optional. The `.drv` basename, e.g. `<hash>-<name>.drv`. |
| `Sig` | — (must be generated) | n/a | **Not present in any TOML.** Ed25519 narinfo signature; see §6. |
| `System` | — (optional, omittable) | n/a | Nix tolerates absence; AOS `platform` (`types.rs:52`) could populate it but it is not required. |
| `CA` | — (omit) | n/a | AOS paths are input-addressed; the `CA` field is omitted. |

Notes on fields AOS carries but a narinfo does not need:

- `closure_size` (`types.rs:67`) — AOS-side total closure size; not a narinfo
  field. Nix recomputes closures from `References`.
- `source_nar_hash` (`types.rs:65`) — provenance of the source derivation; not a
  narinfo field.
- `sysroot` / `previous` / `images` (`types.rs:69-76`) — AOS sysroot semantics;
  irrelevant to the Nix-protocol *narinfo* fields. But note the `images` entries
  are themselves store paths and do get their own narinfos — see §4.2.

### 4.1 Example emitted narinfo (TARGET)

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

### 4.2 Sysroot images are their own store paths (TARGET)

For sysroot packages, each pre-compiled image (`SysrootImageEntry`, carried in
`PackageMeta.images`, `types.rs:74-76`) is itself a distinct store path with its
own `store_path` / `nar_hash` / `download_hash` (parsed from
`[[versions.platforms.<platform>.images]]` into `ImageEntry`,
`registry/parse.rs:61-70`). Each such image therefore gets its **own**
`<storehash>.narinfo`, emitted exactly like a regular package narinfo (§4) —
keyed by the image's store-path hash, pointing at the image's NAR blob. The
field mapping is identical; only the source struct differs
(`SysrootImageEntry` rather than the top-level `PlatformEntry`). See
[workstream-03-nix-cache.md](../plans/registry/workstream-03-nix-cache.md) §4.3
for the producer-side handling of sysroot-image narinfos.

---

## 5. References basename expansion (TARGET)

This is the **one non-mechanical transform** in the mapping. AOS stores the
`references` field as a list of **bare store-path hashes** — the design brief
calls them "dependency hashes" (§2.3) and the struct doc says "Store path hashes
of direct runtime references" (`crates/aos-package/src/types.rs:60-61`). The
closure files (`closures/<hash>`) use the same bare-hash adjacency-list format
(`types.rs:90-95`).

Nix narinfo `References`, by contrast, requires **store-path basenames** of the
form `<hash>-<name>`. The emitter must therefore resolve each bare hash to its
full basename:

```
AOS references:        [ "r4q1m2kp8v3x…", "xr5is7by89v3q…" ]
                                │                  │
                  resolve hash → store_path basename
                                │                  │
narinfo References:    r4q1m2kp8v3x…-glibc-2.39  xr5is7by89v3q…-zlib-1.3.1
```

The name suffix for each hash is recoverable from the referenced package's own
`store_path` (`types.rs:53`) — i.e. the emitter looks up the dependency's
package TOML / narinfo and takes the basename of its `StorePath`. The registry
already records every dependency's `store_path`, so no extra information is
needed; this is purely a join over the metadata the registry holds.

> **Why it matters:** if `References` is left as bare hashes, stock `nix` will
> reject the narinfo (it parses references as store-path basenames and validates
> them against `StoreDir`). This expansion is explicitly called out as one of
> the things "that must be built" in design brief §4.1.

---

## 6. Signing: one key, two signature forms (TARGET)

The `Sig:` line is the only narinfo field with no source in the AOS metadata —
it must be **generated**. The design (brief §4.2) reuses the **same Ed25519
keypair** that signs git commits:

- **Same secret key** signs (a) git commits via an SSH-format signature and
  (b) narinfos via the Nix fingerprint
  `(StorePath, NarHash, NarSize, References)`. The *signed messages differ*, so
  the *signatures differ*, but there is **one secret to manage**.
- **Two published public-key encodings** from that one key:
  - `aos-core:Ed25519:<base64>` — the apm form for `apm` TOFU / `trusted-keys.d`
    (the `SigningConfig.public_key` format, `crates/aos-package/src/types.rs:249-250`,
    parsed as `<name>:Ed25519:<base64>` by `parse_signing_key` in `security.rs`).
  - `<name>:<base64>` — the nix form for Nix `trusted-public-keys`, the standard
    `keyname:base64` form `nix` expects.

### 6.1 Why a per-narinfo `Sig` exists at all

`apm`'s trust is rooted in the **signed git commit**: the Ed25519-signed commit
authenticates the whole git tree (a Merkle DAG) → every package TOML → every NAR
SHA-256 recorded in those TOMLs (design brief §3, §4.2). So `apm` needs **no**
per-NAR signature; NARs are authenticated transitively and verified by content
hash (`download.rs:102-115`).

The per-narinfo `Sig:` exists **only** to satisfy a stock `nix` substituter
without forcing the operator to set `require-sigs = false`. It is a
compatibility affordance for the Nix protocol, not part of the AOS trust chain.

```
apm trust:   signed commit ──► TOML ──► NAR sha256   (transitive, no Sig needed)
nix trust:   narinfo Sig (Ed25519) ──► NarHash       (per-path, satisfies require-sigs)
                 ▲
                 └── same key, different signed message
```

See [signing-and-trust.md](signing-and-trust.md) for the full key model, TOFU,
and threat analysis.

---

## 7. NAR blob layout and the `URL:` field

The narinfo `URL:` is a relative path the origin must serve. Two facts constrain
it:

1. **CURRENT blob key.** The consumer downloads from
   `{mirror_url}/{nar_hash}.nar.zst` with the full `sha256:<hex>` retained
   (`crates/aos-package/src/download.rs:57`). On disk the consumer rewrites the
   colon to a dash for filesystem safety —
   `nar_cache_filename` → `sha256-<hex>.nar.zst`
   (`crates/aos-package/src/download.rs:232-235`) — but the **wire** filename
   keeps the colon.
2. **Deployment choice (open).** NARs may be served under `{base}/nar/` on the
   registry origin itself, or kept on a separate cache with the narinfo `URL:`
   pointing off-origin (design brief §7 Q2). Both work; the narinfo `URL:` is
   just a relative-or-absolute reference.

```
{base}/nar/sha256:<hex>.nar.zst      <-- current AOS wire key (colon retained)
        └── narinfo URL: nar/sha256:<hex>.nar.zst
```

> **Colon-in-filename caveat (open question, design brief §7 Q3):** S3 allows a
> literal `:` in object keys, but some CDN/edge layers percent-encode or reject
> it. If the chosen edge mangles the colon, the emitter must serve the blob
> under a colon-free key (e.g. the `sha256-<hex>` form the consumer already uses
> on disk) and set `URL:` to match. This is a deployment decision recorded as an
> open question, not yet resolved in code.

---

## 8. Using the AOS origin as a dev-shell substituter (TARGET)

Once the origin emits `nix-cache-info` + `*.narinfo` (§3, §4), a non-AOS host
running stock `nix` can consume it as an ordinary binary cache. Two pieces of
configuration are needed: register the **substituter URL** and the
**trusted public key**.

### 8.1 `nix.conf`

```ini
# /etc/nix/nix.conf  (or ~/.config/nix/nix.conf for per-user)

# Append the AOS origin to the substituter list. Order does not imply
# priority — that comes from each cache's nix-cache-info `Priority`.
extra-substituters = https://registry.aos.dev/core

# Trust the registry's Ed25519 key in Nix's <name>:<base64> form (§6).
extra-trusted-public-keys = aos-core:base64publickeyhere==
```

- Use `extra-substituters` / `extra-trusted-public-keys` (the `extra-` prefix
  **appends** to the defaults) so `cache.nixos.org` is retained.
- The key value is the **`<name>:<base64>`** encoding — the same underlying
  Ed25519 key as the `aos-core:Ed25519:<base64>` apm form `apm` uses, just the
  Nix-flavored projection (§6).
- Do **not** set `require-sigs = false`. The whole point of emitting `Sig:` is
  that the cache is properly signed, so signature verification stays on.

### 8.2 Flake config (`nixConfig`)

A flake can advertise the substituter so consumers are prompted to opt in:

```nix
{
  nixConfig = {
    extra-substituters = [ "https://registry.aos.dev/core" ];
    extra-trusted-public-keys = [ "aos-core:base64publickeyhere==" ];
  };

  outputs = { self, nixpkgs }: {
    # … dev shell, packages, etc.
  };
}
```

> Flake-level `nixConfig` substituters/keys are only used after the user accepts
> them (or the flake is already trusted), because they affect what binaries are
> trusted. For unattended/CI hosts, prefer the `nix.conf` approach in §8.1 or
> pass `--accept-flake-config`.

### 8.3 One-off / CLI form

```sh
nix build .#devShell \
  --extra-substituters    https://registry.aos.dev/core \
  --extra-trusted-public-keys 'aos-core:base64publickeyhere=='
```

### 8.4 What a substitution looks like

```
host nix                         AOS origin (strict superset)
   │                                   │
   │  GET /nix-cache-info               │   StoreDir/Priority/WantMassQuery  (§3)
   │ ─────────────────────────────────►│
   │  GET /<storehash>.narinfo          │   field-mapped from PackageMeta    (§4)
   │ ─────────────────────────────────►│
   │      verify Sig: against           │
   │      trusted-public-keys  (§6)     │
   │  GET /nar/<key>.nar.zst            │   content-addressed blob           (§7)
   │ ─────────────────────────────────►│
   │      verify NarHash, decompress    │
```

`apm` on an AOS host, meanwhile, ignores all of the above and fetches
`registry.toml` + `bundles/<name>/…` from the **same origin** — the disjoint
namespaces (§1) mean the two clients never interfere.

---

## 9. Summary: what must be built

From design brief §4.1, the delta to reach the target (none of which exists in
the code today — see §2 and the producer-gap table in design brief §2.11):

1. A **`nix-cache-info` stub** emitter (§3) — `StoreDir` supplied by the publish
   pipeline.
2. A **narinfo generator** keyed by store-path hash, projecting `PackageMeta`
   (§4).
3. **References basename expansion** — bare hash → `<hash>-<name>` (§5).
4. **Per-narinfo Ed25519 `Sig:`** using the shared key (§6).
5. **Co-located / reachable NAR blobs** with a `URL:` the chosen edge serves
   without mangling the key (§7).
6. **Dev-shell wiring docs** (§8) — already captured here; the substituter and
   key plumbing is stock Nix.

These map to plan
[workstream-03-nix-cache.md](../plans/registry/workstream-03-nix-cache.md). The
blob layer (NAR fetch, content-addressing, zstd) is already done
(`download.rs`); the work is the metadata projection and signing on the
**producer** side.

---

## See also

- [architecture.md](architecture.md) — the layered trust/metadata/blob model and
  where the two protocols sit.
- [http-layout.md](http-layout.md) — full wire/object layout, namespaces,
  by-hash, object-key grammar.
- [registry-toml.md](registry-toml.md) — the AOS-native signed root.
- [signing-and-trust.md](signing-and-trust.md) — the one-key model, TOFU, threat
  model.
- [current-state.md](current-state.md) — the as-is producer/consumer asymmetry.
- Plan: [workstream-03-nix-cache.md](../plans/registry/workstream-03-nix-cache.md),
  [open-questions.md](../plans/registry/open-questions.md),
  [design-brief.md](../plans/registry/design-brief.md) §4.1–§4.2.
