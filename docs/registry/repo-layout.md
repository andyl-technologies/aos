# Registry Repo Layout (committed git tree)

> **Audience:** implementers, architects, engineers.
> **Scope:** the **committed git tree** of a registry — the files a commit contains
> (what you'd see on `git checkout`). This is *distinct* from how the bare repo is
> **served** over dumb HTTP (`/objects`, `/channels`, `/releases`, `HEAD`,
> `info/refs`), which is covered in [`http-layout.md`](http-layout.md).

The registry's metadata **is** the git tree. A consumer resolves a channel bucket →
semver tag → **commit**, reconstructs that commit's **tree** from fetched git objects,
and reads the files below. The signed tag authenticates the whole tree transitively
(tag → commit → tree → file), so every file here is signed-by-extension **without**
anything being placed in the tag message (tags are pure pointers — see
[`signing-and-trust.md`](signing-and-trust.md) and design-brief §14).

---

## 1. Tree at a glance

```
<repo root>/                          ← a commit's tree (what `git checkout` yields)
├── registry.toml                     ← [registry] name/description + [[caches]]
├── keys.toml                         ← trust roster: active signing key(s) + revoked list   (TARGET)
├── .gitattributes                    ← "closures/** -diff"
├── packages/
│   ├── a/apache.toml
│   ├── c/curl.toml
│   └── <first-letter>/<name>.toml    ← per-package metadata, sharded by first letter
└── closures/
    └── <hash>                         ← dependency adjacency list
```

This is **almost unchanged** from today's code — the git-native redesign changed
*distribution* (refs, tags, objects, packs over dumb HTTP), not the tree's content.
The in-repo signing pubkey has moved out of `registry.toml`; the remaining target
tree work is to emit `keys.toml` as the committed trust roster during registry
creation/publish.

---

## 2. `registry.toml` — registry-level config (root of the tree)

The git-repo-**root** `registry.toml` is the existing `RegistryRootConfig`
(`crates/aos-package/src/types.rs:563-568`), read by `read_registry_toml`
(`registry_ops.rs:391-402`) and written with a default at `registry_ops.rs:443-450`.

> **Do not confuse this with the removed signed-HTTP-root `registry.toml`.** An
> intermediate design briefly proposed a *mutable file served at the origin root*
> carrying `[latest]`/`[channels]`/`[components]`/`[capabilities]`/`[[bundles]]`/
> `[signature]`. **That** was removed (design-brief §15). The file documented here is a
> **committed tree file**, like any package TOML, authenticated by the signed tag.

**TARGET:**

```toml
[registry]
name        = "aos-core"
description = "AOS core packages"

# Where NAR blobs (and, if served, the Nix-cache surface) live. Authenticated via the
# signed tag. The consumer's client-side registries.d/<name>.toml may override/supplement.
[[caches]]
url      = "https://cache.aos.dev"     # absolute, OR relative (e.g. "./nar") = same origin
priority = 1000                        # HIGHER is preferred (resolve_mirrors sorts descending)

[[caches]]
url      = "./nar"
priority = 100                         # fallback
```

- `[[caches]]` is `CacheEntry { url, priority }`, `default_cache_priority() == 100`
  (`types.rs:582-590`). `resolve_mirrors` sorts **descending** (higher first,
  `registry_ops.rs:405-414`); `resolve_mirror` takes the first
  (`download.rs:85-97`). See [`nix-cache-compatibility.md`](nix-cache-compatibility.md).
- **No signing key here.** The in-repo `RegistryRootConfig.signing` field was
  removed; a key inside a file authenticated *by* that key is circular for
  bootstrap. Key trust lives in `keys.toml` + client-side TOFU (§3).

---

## 3. `keys.toml` — the trust roster (TARGET)

A dedicated committed file holding the **active signing key(s)** and a **revoked
list**, authenticated via the signed tag like everything else. It does **not**
bootstrap trust — initial trust is **TOFU-pinned client-side** in
`trusted-keys.d/<registry>.pub` (`crates/aos-package/src/security.rs`,
`types.rs` `trusted_keys_dirs()`).

```toml
schema = 1

# Currently-valid signing keys (name:Ed25519:<base64>, the parse_signing_key format).
# The model is >=2 OVERLAPPING active keys (no role field, no "root" tier).
[[keys]]
id     = "aos-core-2026a"
key    = "aos-core:Ed25519:<base64>"
[[keys]]
id     = "aos-core-2026b"
key    = "aos-core:Ed25519:<base64>"

# Keys no longer trusted (planned retirement or rotated-out).
[[revoked]]
id     = "aos-core-2025"
reason = "rotated"
```

**Trust model (decided — design-brief §14, §16.8):** **≥2 overlapping active keys.**
There is **no** offline-root / operational two-tier and **no** TUF-style root role — the
**git lineage** (signed tag → commit → parent chain) provides the continuity, so a
separate root tier is unnecessary.

**Rotation (planned):** publish `keys.toml` listing both old and new keys (an overlap
window) in a tag signed by a currently-trusted key; a consumer that trusts the old key
verifies the tag, reads `keys.toml`, and pins the new key. Later, publish with only the
new key (the old key is dropped).

**Planned retirement:** list the key under `[[revoked]]`, **signed by one of the
*other* overlapping active keys.** Because there are always ≥2 active keys, a retiring
key never has to revoke itself.

**Compromise:** handled **out-of-band** — the consumer re-pins via `trusted-keys.d`
(`apr trust`). An in-repo key cannot credibly revoke itself, and compromise is rare
enough that the out-of-band re-pin is acceptable.

> **Defence-in-depth note:** even an authenticated-but-wrong cache pointer can't serve
> bad bytes — NARs are content-addressed and SHA-256-verified on download
> (`download_one`, `download.rs:191-204`). So the trust that matters is the *tag/commit* chain (which
> `keys.toml` governs), not the cache list.

---

## 4. `packages/<first-letter>/<name>.toml` — package metadata

Sharded one subdirectory per first letter of the package name (`first_letter`,
`registry_ops.rs:149`; layout documented at `parse.rs:74`, walked at `parse.rs:89-102`;
written by `build_package_toml`, `registry_ops.rs:527-528,784-785`). The on-disk shape
is the **nested** `PackageToml` (`registry/parse.rs:14-66`); the consumer flattens it
into `PackageMeta` (`types.rs:43-74`) in memory.

```toml
[package]
name        = "curl"
description = "command-line URL transfer tool"
homepage    = "https://curl.se"
license     = "curl"
maintainer  = "aos"
sysroot     = false

[[versions]]
version  = "8.5.0"
previous = "8.4.0"                      # version chain (sysroot packages)

[versions.platforms.x86_64-linux]
store_path    = "/nix/store/<hash>-curl-8.5.0"
nar_hash      = "sha256:<hex>"          # uncompressed NAR
nar_size      = 1048576
download_hash = "sha256:<hex>"          # compressed .nar.zst
download_size = 393216
closure_size  = 5242880
source_drv    = "/nix/store/<hash>-curl-8.5.0.drv"
source_nar_hash = "sha256:<hex>"
references    = ["<hash>", "<hash>"]    # direct runtime deps (store-path hashes)
# [[versions.platforms.x86_64-linux.images]]  ← pre-built images (sysroot packages only)
```

This is the data a narinfo emitter reads (see
[`nix-cache-compatibility.md`](nix-cache-compatibility.md) §6) and unchanged by the
git-native redesign.

---

## 5. `closures/<hash>` — dependency graph

One file per root store-path hash, an **adjacency list** (`write_closure_files`,
`registry_ops.rs:305-352`):

```
<root-hash> <dep-hash> <dep-hash> <dep-hash>
<dep-hash> <dep-hash>
<leaf-hash>
```

`.gitattributes` carries `closures/** -diff` (`registry_ops.rs:354-357`) so git does not
waste effort delta-diffing these (they pack/transfer better untouched).

---

## 6. Tree ↔ HTTP mapping

The files above are **never served as literal HTTP paths**. They are encoded inside git
objects; the consumer fetches the objects and reconstructs the tree:

```
/channels/stable/<bucket>     (signed partition tag — AOS rollout)
        │  → semver tag  refs/tags/<semver>  (+ /releases/<…>/ packs)   (signed)
        ▼
     commit ──► TREE  ┌─ registry.toml  → [[caches]]
                      ├─ keys.toml      → trust roster
                      ├─ packages/*     → package metadata + NAR hashes
                      └─ closures/*     → dependency graph
```

| This doc (git **tree**) | [`http-layout.md`](http-layout.md) (served **object store**) |
|---|---|
| `registry.toml`, `keys.toml`, `packages/`, `closures/` | encoded inside git objects under `/objects/` |
| a commit's working-tree content | `/objects/` (loose + packs), `refs` (`info/refs`), `HEAD` |
| read after assembling objects | `/releases/<…>/objects/pack/*` transfer those objects efficiently |
| authenticated by the signed tag (Merkle) | content-addressed; tags/commits verified by `keys.toml`-rostered keys |

So: **this doc = the producer's source content / what the consumer reads after
assembling objects**; **`http-layout.md` = the transport encoding of that content.**

---

## 7. CURRENT vs TARGET summary

| File | CURRENT (today's code) | TARGET |
|---|---|---|
| `registry.toml` | `[registry]` + `[[caches]]` | unchanged shape |
| `keys.toml` | parser/helpers exist; not emitted by create yet | committed trust roster (active keys + revoked) |
| `packages/<x>/<name>.toml` | nested `PackageToml` | unchanged |
| `closures/<hash>` | adjacency list | unchanged |
| `.gitattributes` | `closures/** -diff` | unchanged |
| bootstrap trust | TOFU `trusted-keys.d` (pin) | TOFU `trusted-keys.d` (pin) + `keys.toml` overlap rotation |

See also: [`signing-and-trust.md`](signing-and-trust.md) (keys, rotation/revocation),
[`http-layout.md`](http-layout.md) (served layout), `current-state.md` (the as-is
code), and the design brief §14.
