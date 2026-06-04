# HTTP / Object-Store Layout

> **Audience:** users, implementers, architects, engineers.
> **Status:** Reference. Describes the **TARGET** on-the-wire layout for an AOS
> registry origin, contrasted against the **CURRENT** layout in code. Where both
> appear, each is explicitly labelled. Current-state claims cite code as
> `path:line`; intent is grounded in
> [`design-brief.md`](../plans/registry/design-brief.md) §4.1, §4.3, §2.8.

This document specifies what bytes live at what URLs on a registry HTTP origin:
the disjoint protocol namespaces, the dumb-HTTP lowest-common-denominator
contract versus the optional S3 listing fast-path, the by-hash discipline, the
object keys, and the bundle key grammar.

For the consuming clients and how the layers fit together, see
[`architecture.md`](./architecture.md). For the schema of the signed root file,
see [`registry-toml.md`](./registry-toml.md). For the bundle/delta model that the
keys below encode, see [`bundles-and-deltas.md`](./bundles-and-deltas.md). For
the Nix-protocol half, see
[`nix-cache-compatibility.md`](./nix-cache-compatibility.md).

---

## 1. The origin serves two disjoint protocols

A single registry origin (`{base}` — an `https://` URL, optionally backed by an
S3 bucket) serves **two** protocols that occupy **non-overlapping URL
namespaces**. Because the namespaces are disjoint, adding the Nix protocol is
**additive** — a *strict superset*, not a conflict (brief §4.1). Either protocol
can be removed without affecting the other; a mirror can host one, the other, or
both.

| Protocol | Consumer | Entry point | Namespace owned |
|---|---|---|---|
| **AOS registry** | `apm` (the AOS package CLI) | `{base}/registry.toml` (TARGET) / `{base}/bundles/{name}/bundle-list.toml` (CURRENT) | `registry.toml`, `bundles/` |
| **Nix binary cache** | stock `nix` (dev-shell substitution) | `{base}/nix-cache-info` | `nix-cache-info`, `<storehash>.narinfo`, `nar/` |

```
{base}/
├── registry.toml                  ── AOS root (TARGET; signed)  ──────────┐
├── bundles/                       ── AOS: git bundles of TOML metadata    │ AOS
│   └── <name>/                                                            │ namespace
│       ├── bundle-list.toml       ── CURRENT root (removed in TARGET)     │
│       └── <bundle-key>.bundle                                           ─┘
│
├── nix-cache-info                 ── Nix: fixed-name cache descriptor  ───┐
├── <storehash>.narinfo            ── Nix: per-store-path metadata         │ Nix
└── nar/                                                                   │ namespace
    └── <…>.nar.zst                ── content-addressed blobs (shared)    ─┘
```

The `nar/` blob tree is the one place the two protocols **share** objects: the
same content-addressed `.nar.zst` files are the build artifacts `apm` downloads
and the bodies that narinfo `URL:` fields point at. The metadata layers above
them are protocol-specific. See [§5](#5-the-nar-blob-namespace) for the blob
naming subtlety (the two protocols name the *same* blobs differently today).

---

## 2. CURRENT layout (as-is)

The registry origin today is **self-contained** and serves **only** the AOS
bundle protocol (brief §2.4, §3.1). It is *not* a Nix binary cache: there is no
`nix-cache-info`, no `*.narinfo`, and no narinfo signatures.

### 2.1 AOS bundle namespace (CURRENT)

The consumer fetches a per-registry manifest and then the bundles it names. Both
URLs are built in `registry/bundle.rs`:

| Object | URL | Built at |
|---|---|---|
| Bundle manifest | `{base}/bundles/{registry_name}/bundle-list.toml` | `bundle.rs:105` (`BundleManifest::fetch`) |
| Bundle file | `{base}/bundles/{registry_name}/{entry.uri}` | `bundle.rs:259` (`download_bundle`) |

Key facts:

- The manifest is `bundle-list.toml`, parsed by `ManifestToml` /
  `BundleEntryToml` which are **`Deserialize`-only** — there is no serializer
  anywhere in the tree (`bundle.rs:59`–`92`; brief §2.11). The producer has no
  manifest **writer**.
- `entry.uri` is a bundle filename **relative** to `{base}/bundles/{name}/`. The
  manifest carries the literal `uri` string; the consumer does not reconstruct
  it from tags.
- The manifest is **not signed** as a file. Trust is rooted transitively in the
  Ed25519-signed git commit inside the bundle, verified by `git bundle verify`
  plus the commit-signature check (`bundle.rs:305`, brief §2.10, §3.3).
- Bundles are verified by **SHA-256** from the manifest (`bundle.rs:277`,
  `with_hash(HashAlgorithm::Sha256, &entry.sha256)`) **and** `git bundle verify`
  (`bundle.rs:326`).

### 2.2 Bundle key grammar (CURRENT)

The producer command `apr bundle` constructs filenames in
`registry_ops.rs:1736` and `registry_ops.rs:1746`:

| Kind | Filename pattern | Example |
|---|---|---|
| Snapshot | `{reg_name}-{tag}.bundle` | `aos-core-v2026.02.bundle` |
| Delta | `{reg_name}-{from}..{tag}.bundle` | `aos-core-v2026.02..v2026.02.3.bundle` |

> **Known bug (delta suffix).** The producer (`registry_ops.rs:1736`) emits
> `{from}..{tag}.bundle`. The consumer's sample manifest in `bundle.rs`
> (e.g. `bundle.rs:457`) uses keys like
> `aos-core-v2026.02..v2026.02.1.delta.bundle` — with an extra `.delta`
> infix. The two do not agree on the literal filename. This is harmless **only**
> because the consumer reads `entry.uri` verbatim from the manifest and never
> reconstructs it; but a hand-written or future producer-generated manifest must
> use whatever string the producer actually wrote. This producer/consumer
> disagreement is tracked as a bug to fix in the authoritative grammar at
> [§4](#4-bundle-key-grammar-authoritative); the `..` separator and the `.bundle`
> suffix are the stable parts, and the `.delta` infix is not authoritative.

The `..` in a delta key is the git rev-range separator: `apr bundle` builds the
bundle from `git bundle create <dest> {from}..{tag}` (`registry_ops.rs:1738`).

### 2.3 The `[[caches]]` indirection and NAR blobs (CURRENT)

The registry repo's in-repo `registry.toml` (the **local** root, distinct from
the TARGET signed wire-root) carries `[[caches]]` entries that point NAR
downloads at a separate blob store. The schema is `RegistryRootConfig { registry,
caches: Vec<CacheEntry>, signing }` (`types.rs:566`), where each `CacheEntry`
carries `url` + `priority` (`types.rs:585`).

NAR download URLs are built independently of the registry origin in
`download.rs`:

- `resolve_mirror` (`download.rs:67`) reads `[[caches]]` from the local registry
  clone, sorted by priority, and returns the highest-priority `url`. With no
  caches configured it **falls back** to `{registry.url}/nar`
  (`download.rs:80`–`81`).
- `nar_url(mirror_url, nar_hash)` (`download.rs:57`) →
  `{mirror_url}/{nar_hash}.nar.zst`, where `nar_hash` is the **full
  `sha256:<hex>` string**, colon included (brief §2.8). Example:
  `https://cache.aos.dev/nar/sha256:abc123….nar.zst`.

So today the NAR blob namespace is keyed by the **NAR content hash** (the
uncompressed-archive hash), not by store-path hash, and lives under `nar/` on a
cache that may or may not be the registry origin.

---

## 3. TARGET layout (the decisions)

The TARGET (brief §4.1, §4.3) keeps the AOS namespace, collapses its root to a
single signed file, and **adds** the Nix namespace alongside it.

### 3.1 Full TARGET tree

```
{base}/
├── registry.toml          ── single inline-signed AOS root (§3.2)
│                              replaces bundle-list.toml; carries the
│                              by-hash bundle/delta index inline
│
├── bundles/
│   └── <name>/
│       └── <bundle-key>    ── immutable, content-addressed git bundles
│                              (§4); referenced by-hash from registry.toml
│
├── nix-cache-info          ── generated stub (StoreDir/Priority/WantMassQuery)
├── <storehash>.narinfo     ── one per store path, keyed by 32-char base32
│                              store-path hash; carries Ed25519 Sig:
└── nar/
    └── <…>.nar.zst         ── content-addressed blobs (shared with AOS)
```

### 3.2 The single signed root replaces the manifest

`bundle-list.toml` is **removed** (brief §4.3). Its bundle enumeration moves
**into** `registry.toml`, which becomes the one signed root the origin serves at
the fixed name `{base}/registry.toml`. The key target properties:

- **Inline-signed** (single object, like APT `InRelease`): root + signature are
  one file, fetched atomically with no signature/body race.
- **By-hash references** ([§6](#6-by-hash-discipline)): every bundle/delta the
  root names is identified by its SHA-256 so a client that read root@T resolves a
  consistent set even after the publisher flips to root@T+1.
- Carries the signed `[latest]` pointer (`tag`, `token`, `head` commit SHA), a
  `valid_until` freshness window, `[channels]`, optional `[components]`, and the
  pdiff-style bundle/delta tables (brief §4.3).

The full annotated schema lives in [`registry-toml.md`](./registry-toml.md).
`nix-cache-info` remains a *separate* file only because Nix hardcodes that name;
it is a generated stub, never a competing index (brief §4.3).

### 3.3 Object mutability classes

The publish ordering (brief §4.4) depends on a strict split between immutable
content-addressed objects and the one mutable pointer:

| Class | Objects | Mutability | Upload order |
|---|---|---|---|
| Immutable / content-addressed | `nar/*.nar.zst`, `*.narinfo`, `bundles/<name>/<key>` | Never rewritten; new content ⇒ new key | **First** (idempotent, any order) |
| Mutable pointer | `registry.toml` | Flipped on each publish | **Last**, atomically (conditional PUT) |
| Generated stub | `nix-cache-info` | Effectively static | With immutables |

Because every object the new root references already exists before the root
flips, readers see either the old root or the new root — never a torn set
([§6](#6-by-hash-discipline)).

---

## 4. Bundle key grammar (authoritative)

This section is the **authoritative home** of the bundle key grammar for the
whole registry doc set; other docs reference it rather than restating variants.
Bundle objects under `bundles/<name>/` are git bundles of registry TOML
metadata. There is exactly **one canonical key shape** per kind:

| Kind | Key grammar | Example |
|---|---|---|
| Snapshot | `{name}-{tag}.bundle` | `aos-core-v2026.05.3.bundle` |
| Delta | `{name}-{from}..{to}.bundle` | `aos-core-v2026.05.2..v2026.05.3.bundle` |

Grammar notes (the stable, load-bearing parts):

- The `..` separator is the git rev-range marker and distinguishes a delta from a
  snapshot. There is **one** delta key shape: sequential and skip deltas use the
  *same* `{name}-{from}..{to}.bundle` form — they are not different filename
  variants. The skip-vs-sequential distinction is **derived**, not encoded in the
  key: the consumer classifies a delta from the segment count of the `from` tag
  (`classify_delta`, `bundle.rs:238`), where a `from` with `≤ 2` dotted parts
  (a minor base `vYYYY.MM`) ⇒ skip, else sequential. See
  [`bundles-and-deltas.md`](./bundles-and-deltas.md).
- The tag form is `vYYYY.MM[.P]` calendar versioning.
- The literal filename is **convention only**. Authority is **by-hash**: under
  by-hash discipline the client fetches a bundle by the `uri`/key recorded in the
  root's `[[bundles]]` entry and validates its `sha256` against the same row. Do
  **not** embed the sha256 in the key — the key stays human/CDN-legible; the hash
  in the signed root is the contract.
- The `creation_token` that orders bundles is **not** in the filename; it is a
  field in the root's `[[bundles]]` entry (`year*1_000_000 + month*10_000 +
  patch`, brief §2.5). The key is for human/CDN legibility; the *index* is the
  root.

> **Known bug — the `.delta` infix disagreement.** The producer
> (`registry_ops.rs:1736`) writes delta keys as `{from}..{to}.bundle`, but the
> consumer's sample manifest in `bundle.rs` (e.g. `bundle.rs:457`) carries keys
> with an extra `.delta` infix — `{from}..{to}.delta.bundle`. The two do **not**
> agree on the literal filename. This is currently harmless only because the
> consumer reads `entry.uri` verbatim and never reconstructs it, and because
> authority is by-hash, not by-string. It is nonetheless a **bug to fix**: the
> canonical grammar above (`{name}-{from}..{to}.bundle`, no `.delta` infix) is the
> one both producer and consumer should converge on. See
> [§2.2](#22-bundle-key-grammar-current).

---

## 5. The NAR blob namespace

The `nar/` tree holds zstd-compressed Nix archives, content-addressed, shared by
both protocols. There is a **naming subtlety** between CURRENT and TARGET that
implementers must reconcile.

| | Keyed by | URL shape | Source |
|---|---|---|---|
| **CURRENT** (`apm`) | full NAR hash `sha256:<hex>` (uncompressed-archive hash) | `{mirror}/sha256:<hex>.nar.zst` | `download.rs:57`, `nar_url` |
| **TARGET** (`nix`) | narinfo `URL:` field, conventionally `nar/<download_hash>.nar.zst` (compressed-file hash) | `{base}/nar/<…>.nar.zst` (relative URL from narinfo) | brief §4.1 table |

Two things differ and must be made consistent per-deployment:

1. **Which hash names the blob.** `apm` today names by the *uncompressed* NAR
   hash (`nar_hash`); the brief's narinfo mapping derives `URL:` from the
   *compressed* `download_hash` (brief §4.1, `FileHash`/`FileSize` row). A blob
   store can host both names (one as a symlink/alias), or narinfo can point
   `URL:` at the `apm`-style name. This is recorded as an open question.
2. **Colon in the filename.** The CURRENT `apm` URL embeds a literal colon
   (`sha256:<hex>.nar.zst`). S3 permits colons in keys, but some CDN edges
   re-encode them; the local **cache filename** already sidesteps this by
   rewriting `:`→`-` (`download.rs:233`, `nar_cache_filename`). Whether the
   *wire* key keeps the colon is deployment-dependent (brief §7, open Q3).

NAR blobs are authenticated by **SHA-256 content hash**, not by signature, on the
`apm` path (brief §2.8). The per-narinfo Ed25519 `Sig:` exists **only** to
satisfy stock `nix` without `require-sigs = false` (brief §4.2); `apm` does not
need it because trust flows transitively from the signed commit.

---

## 6. By-hash discipline

The TARGET applies APT's `by-hash` consistency model (brief §4.3, §6 Tier-1 item
2). The mechanism is the split in [§3.3](#33-object-mutability-classes):

1. Every bundle and delta is an **immutable, content-addressed** object. Its key
   may be human-legible, but the root pins its **SHA-256**.
2. The **only** mutable object is `registry.toml`, flipped atomically last via a
   conditional PUT (S3 `If-Match` / `If-None-Match` ETag CAS — brief §4.4).
3. A reader fetches the root once, then resolves every referenced object **by the
   hash in that root**. Even if the publisher flips to a newer root mid-read, the
   reader's objects still exist (immutable) and still hash-match (by-hash), so it
   sees a **consistent snapshot** — never a torn mix of old index + new objects.

```
   publish ordering (brief §4.4):
   ┌──────────────────────────────────────────────────────────────┐
   │ 1. git push (FF-only CAS)          ── ref update serializes    │
   │ 2. generate artifacts from landed commit (bundles, narinfos)   │
   │ 3. PUT immutable objects FIRST     ── idempotent, any order     │
   │ 4. flip registry.toml LAST         ── conditional PUT (ETag CAS)│
   └──────────────────────────────────────────────────────────────┘
            readers see old-root OR new-root, never torn
```

This is what lets dumb-HTTP mirrors (no listing, no locks) stay correct under
concurrent publish: there is exactly one switch, and everything it points at is
already in place when it flips.

---

## 7. Dumb-HTTP LCD vs S3 listing fast-path

The layout is designed so **correctness never depends on directory listing**
(brief §4.3). Two access tiers:

| Tier | Mechanism | Required for correctness? | Who uses it |
|---|---|---|---|
| **Dumb-HTTP (LCD)** | Fetch the one fixed root file `{base}/registry.toml`, then follow by-hash references | **Yes** — this is the contract | Every `apm` client; every static mirror (S3, plain HTTP, CDN) |
| **S3 `ListObjects`** | Enumerate keys directly for richer/admin queries | **No** — optional fast-path only | Publishers / admins (e.g. reconciling, GC) |

Consequences of "the enumerated index lives **inside** the registry files"
(brief §4.3):

- A static file server with **no listing capability** is a fully correct mirror:
  every object a client needs is reachable from the signed root by a known key.
- The signed `[latest]` pointer is the freshness/anti-rollback anchor that a dumb
  listing could never provide — a listing can omit newer bundles silently; the
  signed `[latest].head` makes a client **fail closed** rather than use stale
  data (brief §4.5 *omission*).
- `valid_until` in the signed root defends against a mirror frozen on an old,
  validly-signed root (brief §4.5 *freeze*) — again, something a directory
  listing cannot express.

S3 listing is therefore a convenience for operators, never a dependency for
consumers. See [`publishing.md`](./publishing.md) for the publish pipeline and
[`signing-and-trust.md`](./signing-and-trust.md) for the freshness/threat model.

---

## 8. CURRENT vs TARGET at a glance

| Aspect | CURRENT | TARGET |
|---|---|---|
| AOS root file | `bundles/{name}/bundle-list.toml` (`bundle.rs:105`) | `registry.toml` at origin root (brief §4.3) |
| Root signed as a file? | No (transitive via signed commit) | Yes (inline-signed, like `InRelease`) |
| Bundle index | In `bundle-list.toml`, `Deserialize`-only (no writer) | Inline in `registry.toml`, by-hash |
| Bundle URL | `{base}/bundles/{name}/{entry.uri}` (`bundle.rs:259`) | `{base}/bundles/{name}/<key>`, fetched by-hash |
| Bundle integrity | SHA-256 (manifest) + `git bundle verify` (`bundle.rs:277`,`326`) | Same, plus by-hash discipline atop signed root |
| Nix namespace | Absent | `nix-cache-info` + `*.narinfo` + `nar/` |
| NAR URL | `{mirror}/{nar_hash}.nar.zst`, colon-keyed (`download.rs:57`) | `nar/<…>.nar.zst`, narinfo `URL:`; naming reconciled per deployment |
| NAR mirror selection | `[[caches]]` by priority, else `{url}/nar` (`download.rs:67`) | Same; mirror may be the registry origin |
| `[latest]` pointer | Derived (max `creation_token` scan) | Explicit signed field, flipped last |
| Freshness defense | None (sequence only) | `valid_until` + monotonic `[latest].token` |
| Concurrency guard | git FF-rejection on push | git FF CAS + conditional-PUT root flip |

---

## 9. Related documents

- [`README.md`](./README.md) — registry doc index and overview.
- [`architecture.md`](./architecture.md) — layered model; how `apm` and `nix`
  consume the namespaces above.
- [`current-state.md`](./current-state.md) — full as-is grounding (code-cited).
- [`registry-toml.md`](./registry-toml.md) — the signed root schema this layout
  serves.
- [`bundles-and-deltas.md`](./bundles-and-deltas.md) — `creation_token`, the
  snapshot/sequential/skip model, `pick_bundles` selection.
- [`nix-cache-compatibility.md`](./nix-cache-compatibility.md) — narinfo mapping,
  `nix-cache-info`, dev-shell substituter config.
- [`signing-and-trust.md`](./signing-and-trust.md) — one Ed25519 key, transitive
  authentication, threat model.
- [`publishing.md`](./publishing.md) — the §4.4 publish ordering and root flip.
- [`apt-comparison.md`](./apt-comparison.md) — `InRelease`/`by-hash`/`pool`
  parallels and adopted improvements.
- Plan: [`design-brief.md`](../plans/registry/design-brief.md) (§4.1, §4.3, §2.8),
  [`gap-analysis.md`](../plans/registry/gap-analysis.md),
  [`workstream-01-registry-root.md`](../plans/registry/workstream-01-registry-root.md),
  [`workstream-03-nix-cache.md`](../plans/registry/workstream-03-nix-cache.md),
  [`open-questions.md`](../plans/registry/open-questions.md).
