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
├── registry.toml                     ← [registry] metadata and the unified [caches] stack
├── keys.toml                         ← trust roster: active signing key(s) + revoked list
├── packages/
│   ├── a/apache.toml
│   ├── c/curl.toml
│   └── <first-letter>/<name>.toml    ← per-package metadata, sharded by first letter
└── store/
    ├── r4/r4q1m2kp8v3x               ← realisation graph: one file per IA store path,
    └── <2-char>/<ia-hash>              sharded git-style (RFC-0005)
```

This is **almost unchanged** from today's code — the git-native redesign changed
*distribution* (refs, tags, objects, packs over dumb HTTP), not the tree's content.
The in-repo signing pubkey has moved out of `registry.toml`; `apr create` now
emits `keys.toml` as the committed trust roster, and `apr keys list/add/retire`
maintains that roster through supported rotation/revocation workflows.

---

## 2. `registry.toml` — registry-level config (root of the tree)

The git-repo-**root** `registry.toml` is the existing `RegistryRootConfig`
(`crates/aos-package/src/types.rs:737`), read by `read_registry_toml`
(`registry_ops.rs`) and written with a default during `apr create`.

> **Do not confuse this with the removed signed-HTTP-root `registry.toml`.** An
> intermediate design briefly proposed a *mutable file served at the origin root*
> carrying release, channel, component, capability, artifact-list, and signature
> tables. **That** was removed (design-brief §15). The file documented here is a
> **committed tree file**, like any package TOML, authenticated by the signed tag.

**TARGET:**

```toml
[registry]
name        = "aos-core"
description = "AOS core packages"
require_signed_ukis = true
# Optional initial release shown by the public browser.
# Omitting it selects the highest verified non-prerelease semantic version.
default_release = "1.2.0"

# Optional release-train support promise, copied verbatim from the
# qualification contract's `support` export. Trains without an entry follow
# the rolling default; LTS trains must state their end date.
[support.default]
kind = "standard"
superseded_after_trains = 2

[[support.trains]]
train = "2026.9"
kind = "lts"
supported_until = "2028-09-30"

# Ordered cache endpoints, authenticated by the signed tag. Managed
# endpoints correspond to explicit Hub routes; external endpoints do
# not gain a managed identity merely because their URL happens to match.
[caches]
kind = "try"
members = [
  { endpoint = "https://cache.aos.dev" },
  { endpoint = "./nar" },
]
```

- `[caches]` is the unified `StackNode` expression. `try` is ordered
  fall-through and `mirror` declares equivalent replicas; nodes may nest.
  Consumers flatten the stack depth-first when they need a simple URL list. See
  [`nix-cache-compatibility.md`](nix-cache-compatibility.md).
- `require_signed_ukis` is an authenticated, opt-in release gate. When `true`,
  every directly delivered system image must contain signed UKIs verified
  against the active certificates in committed `sb-certs.toml`. Publishing,
  Hub indexing, and installation all fail closed on unsigned or merely
  unverified UKIs. It defaults to `false`; package-only releases are unaffected.
- **No signing key here.** The in-repo `RegistryRootConfig.signing` field was
  removed; a key inside a file authenticated *by* that key is circular for
  bootstrap. Key trust lives in the `keys.toml` roster (§3), anchored
  out-of-band by the image-baked `trusted-keys.d` or `apr trust pin`.

---

## 3. `keys.toml` — the trust roster

A dedicated committed file holding the **active signing key(s)** and a **revoked
list**, authenticated via the signed tag like everything else. Clients **consume
it during sync** (`pin_rotated_keys`, `crates/aos-package/src/registry/keys.rs`):
it is the **authoritative trusted-key set** once the consumer is anchored. It does
**not** bootstrap trust — initial trust is delivered **out-of-band**, either
baked into the image (`aos.apm.registries` → `trusted-keys.d/<registry>.pub`) or
pinned by an operator (`apr trust pin`). After that anchor, the roster *evolves*
trust in-band under continuity enforcement (signed fast-forward by an
already-trusted key); see [`signing-and-trust.md`](signing-and-trust.md) §2.5–§2.6.
`apr create` writes this file during the initial commit; pass
`--trust-key registry:Ed25519:<base64>` and optionally `--trust-key-id <id>`
(default `initial`) to seed the active-key list, or omit `--trust-key` to write an
empty schema-1 roster. Operators maintain the roster after creation with
`apr keys generate`, `apr keys add`, `apr keys retire`, and `apr keys list`;
roster-modifying commits are signed.

```toml
schema = 1

# Currently-valid git signing keys (name:Ed25519:<base64>, the parse_signing_key format).
# TUF role membership and thresholds live in tuf/root.json, not in keys.toml.
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

**Trust model:** the out-of-band anchor and signed git lineage still authenticate
the first accepted registry commit and the `keys.toml` roster. Moving-ref release
commits must carry `tuf/root.json`, `tuf/targets.json`, `tuf/snapshot.json`, and
`tuf/timestamp.json`; clients verify those role thresholds, metadata versions,
catalog hashes, and signed timestamp expiry before extracting package metadata.
Explicit commit/tag/version pins still verify the same signed metadata and hashes
when TUF exists without expiring old immutable release snapshots.

**Rotation:** use `apr keys add <new-id> <new-key>` to update `keys.toml` so it
lists both old and new keys (an overlap window), then publish the resulting
commit in a tag signed by a currently-trusted key. A consumer that trusts the old
key verifies the tag, reads `keys.toml`, and pins the new key. Later, publish
with only the new key (the old key is dropped).

**Planned retirement / revocation:** use `apr keys retire <id> [--vouched-by
<survivor-id>] [--reason ..]` to list the key under `[[revoked]]` in a commit
**signed by one of the *other* overlapping active keys** (the command refuses to
retire the last active key, so a retiring key never revokes itself). Because
signatures by a revoked key stop verifying, retirement also **re-signs** the
channel partition tags and the release tags they reference whose only valid signer
was the retired key, using the vouching key (`--no-resign` skips). The revocation
propagates to consumers **in-band** on their next sync, which pins the new active
set and masks the dropped key.

**Compromise — local recovery:** if a consumer must stop trusting a key that still
appears in a **read-only** baked anchor, the operator re-pins the writable store
with `apr trust pin --replace`; the `# revoked:` masking excludes the bad key
without touching the image-baked file.

> **Defence-in-depth note:** even an authenticated-but-wrong cache pointer can't serve
> bad bytes - every downloaded NAR's decompressed SHA-256 and size must match a
> blessed NAR in the signed `store/` graph (§5; `verify_downloads`,
> `crates/aos-package/src/verify.rs`). So the trust that matters is the
> *tag/commit* chain (which `keys.toml` governs), not the cache list.

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
closure_size  = 5242880
source_drv    = "/nix/store/<hash>-curl-8.5.0.drv"
source_nar_hash = "sha256:<hex>"
# [[versions.platforms.x86_64-linux.images]]  ← pre-built images (sysroot packages
#                                               only; image entries keep nar_hash/nar_size)
```

The output's **content binding (`nar_hash`/`nar_size`) and dependency edges
(`references`) are not here** - they live in the `store/` realisation graph
(§5), the single authority for blessed bytes and dependency shape (RFC-0005).
Pre-RFC-0005 registries still carry these fields per platform entry; the
parser treats them as optional legacy fields and consumers backfill the
in-memory metadata from `store/` when absent. `store_path` still anchors the
package to its IA hash (and thus its `store/` record); sources
(`source_nar_hash`) and sysroot images keep their hashes in the TOML - they
sit outside the runtime closure the graph covers.

---

## 5. `store/<2-char>/<ia-hash>` - the realisation graph (RFC-0005)

Input-addressed store-path hashes promise *how* a path was built, not *what
bits* it contains. The `store/` graph closes that gap: one file per IA store
path records, for every blessed build, its exact NAR bytes, its
content-addressed (CA) realisation, and the realisations of its direct
dependencies. The node is a Nix-style realisation, so the realisation graph
*is* the closure graph - content addresses on the nodes, dependency CA pins
on the edges - and consumers validate exact bytes against the signed tree
instead of trusting cache-served narinfos
(`crates/aos-package/src/registry/store.rs`; design record:
[RFC-0005](../rfcs/0005-ca-trust-map.md)).

One file per IA store path, named by the IA hash, sharded git-style
(`store/<first-2>/<ia-hash>`). Each file is a sequence of realisation
records - a `ca:`/`nar:` header line starts a record, `ia:` lines are its
dependency edges:

```
ca:sha256:<ca-hash> nar:sha256:<nar-hash>:<size>
  ia:sha256:<dep-ia>/ca:sha256:<dep-ca>
  ia:sha256:<dep-ia>/ca:sha256:<dep-ca>
```

An input-addressed-only path (or a pure-IA registry, `content_addressed =
false`) carries no `ca:` - the header is just the NAR and edges are bare IA
hashes. A path maps to **0..N** blessed NARs and **0..M** CA realisations;
the dedup is per realisation, so reproducible nodes are shared across
otherwise-divergent trees. The token prefix disambiguates header from edge;
blank lines and `#` comments are ignored.

- **Producer**: `apr publish` records every runtime-closure member (and,
  when `content_addressed`, its CA realisation + pins via `nix store
  make-content-addressed`), *refusing* on a content mismatch unless
  `--bless`; `apr store bless/revoke/verify/backfill` maintain the graph
  directly.
- **Consumer**: `apm` verifies each downloaded NAR's decompressed SHA-256
  and size against the record's blessed set (`verify_downloads`,
  `crates/aos-package/src/verify.rs`), and checks coverage over the **whole
  closure** before downloading (`enforce_totality`), so a stripped graph is
  caught even for members already in the local store. Enforcement is **per
  source registry**: when a path's registry publishes a graph, an unmapped
  member is a **hard failure**; a registry with no `store/` at all falls
  back to narinfo hashes with a warning, independent of other registries in
  the same transaction.
- **Semantics**: append-mostly; removal is revocation and carries the same
  review weight as a `keys.toml` retirement. Deliberately **no `store/**
  -diff`** gitattribute - content-address changes are the highest-value
  security-review surface and must show as readable diffs.

---

## 6. Tree ↔ HTTP mapping

The files above are **never served as literal HTTP paths**. They are encoded inside git
objects; the consumer fetches the objects and reconstructs the tree:

```
/channels/stable/<bucket>     (signed partition tag — AOS rollout)
        │  → semver tag  refs/tags/<semver>  (+ /releases/<…>/ packs)   (signed)
        ▼
     commit ──► TREE  ┌─ registry.toml  → [caches] stack
                      ├─ keys.toml      → trust roster
                      ├─ packages/*     → package metadata
                      └─ store/*        → realisation graph (bytes + deps + CAs)
```

| This doc (git **tree**) | [`http-layout.md`](http-layout.md) (served **object store**) |
|---|---|
| `registry.toml`, `keys.toml`, `packages/`, `store/` | encoded inside git objects under `/objects/` |
| a commit's working-tree content | `/objects/` (loose + packs), `refs` (`info/refs`), `HEAD` |
| read after assembling objects | `/releases/<…>/objects/pack/*` transfer those objects efficiently |
| authenticated by the signed tag (Merkle) | content-addressed; tags/commits verified by `keys.toml`-rostered keys |

So: **this doc = the producer's source content / what the consumer reads after
assembling objects**; **`http-layout.md` = the transport encoding of that content.**

---

## 7. Status summary

| File | Status (today's code) |
|---|---|
| `registry.toml` | `[registry]` + unified `[caches]` stack (no signing pubkey) |
| `keys.toml` | emitted by `apr create` as a schema-1 roster; maintained by `apr keys generate/list/add/retire` (signed roster commits, survivor-vouched + re-signed retirement); **consumed by clients** during sync (`pin_rotated_keys`) as the authoritative trusted-key set |
| `packages/<x>/<name>.toml` | nested `PackageToml` (`nar_hash`/`nar_size`/`references` legacy-optional, superseded by `store/`) |
| `store/<2-char>/<ia-hash>` | realisation graph: blessed NARs + dependency edges + CA realisations (RFC-0005); written by `apr publish`, maintained by `apr store`, enforced by `apm` |
| bootstrap trust | out-of-band anchor — image-baked `aos.apm.registries` → `trusted-keys.d`, or `apr trust pin`, or `[registry.signing] public_key` when the store is empty — then `keys.toml` overlap rotation in-band (no silent TOFU) |

See also: [`signing-and-trust.md`](signing-and-trust.md) (keys, rotation/revocation),
[`http-layout.md`](http-layout.md) (served layout), `current-state.md` (as-built
code status), and the design brief §14.

The public browser scopes Packages, Docs, Images, and Containers to a published
release. `[registry].default_release` is an optional semantic version used for
initial navigation; it does not change package-manager tracking or channel
assignments. Without it, the browser selects the highest verified non-prerelease
version across all published branches, then the highest verified prerelease.
A selected version remains in page URLs, filters, searches, and installation
instructions. An unavailable release does not fall back to another catalog.

`[support]` states how long each stable train (`major.minor`) receives updates.
It is the qualification contract's `support` export, committed so consumers and
Hubs read the reviewed promise from the signed registry. `default.kind` and
`default.superseded_after_trains` govern trains without an explicit entry: such
a train is supported until that many newer stable trains exist. Each
`[[support.trains]]` entry names a train, its `kind` (`standard` or `lts`), and
an optional `supported_until` ISO-8601 date; an `lts` train must state one.
Train keys have no leading zeros, and an invalid table is a schema error that
fails indexing rather than a warning. The public Releases page shows one tile
per supported train with its newest release, marks trains within ninety days of
their end date, and lists older trains as end of life. Without the table, the
browser applies the default rule alone.

Docs combines the release's configuration paths into one tree. Any path may be
opened as a subtree. Child lists, variant lists, and indexed search results use
50-item cursor pages. Expanding a branch fetches only its immediate children;
selecting an option loads its exact verified documentation object. Search covers
the entire release unless the reader chooses the current subtree. Typed path
segments preserve literal dots and dynamic attributes without confusing them
with hierarchy separators.
