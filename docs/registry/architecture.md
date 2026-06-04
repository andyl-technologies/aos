# AOS Registry — Architecture

> **Audience:** users, implementers, architects, engineers.
> **Scope:** the layered model of the registry (trust root → metadata → blobs),
> how `apm` and stock `nix` both consume **one** HTTP origin, the
> dumb-HTTP-lowest-common-denominator philosophy, and the *strict-superset* idea
> that lets the registry serve two protocols without conflict.
>
> This document draws on the [design brief](../plans/registry/design-brief.md)
> §3, §4.1, and §4.3. Where it describes behavior that exists today it cites code
> as `path:line` and labels it **CURRENT**; where it describes the intended end
> state it labels it **TARGET**. When the two differ, this page documents what the
> code actually does and the difference is noted in
> [`current-state.md`](./current-state.md) and the plan's
> [`open-questions.md`](../plans/registry/open-questions.md).

---

## 1. One-paragraph mental model

An AOS registry is a **git repository of TOML metadata** — not a blob store, and
not (today) a Nix binary cache. It is published over **dumb HTTP** as a single
signed root plus a set of immutable, content-addressed objects. The Ed25519
signature on the git history transitively authenticates every package TOML, and
every TOML pins the SHA-256 of the build artifacts (NARs) it describes. Two
consumers read the *same* origin: `apm` (the AOS package manager) reads the
registry root and git bundles to install packages and their closures; stock
`nix` reads `nix-cache-info` and `.narinfo` files to use the same NARs as a
binary-cache substituter. Because the two protocols live in **disjoint URL
namespaces**, the Nix protocol is a **strict superset** added on top of the AOS
one — additive, never in conflict.

---

## 2. The three layers

The registry is best understood as three stacked layers. Each layer authenticates
the one below it, and each is fetched with progressively dumber transport
requirements.

```
┌──────────────────────────────────────────────────────────────────────┐
│  LAYER 1 — TRUST ROOT                                                   │
│  One inline-signed file: registry.toml  (TARGET)                       │
│  • Ed25519 public key  • [latest] signed pointer (tag/token/head)     │
│  • valid_until expiry   • [channels]  • bundle/delta index by-hash    │
│  Authenticates ───────────────────────────────────────────┐          │
└───────────────────────────────────────────────────────────┼──────────┘
                                                             │ signed commit
                                                             ▼  + by-hash
┌──────────────────────────────────────────────────────────────────────┐
│  LAYER 2 — METADATA  (the git repo, distributed as bundles)           │
│  packages/<x>/<name>.toml   — per-package, per-platform records        │
│  closures/<hash>            — dependency adjacency lists              │
│  Each TOML pins ──────────────────────────────────────────┐          │
└───────────────────────────────────────────────────────────┼──────────┘
                                                             │ nar_hash
                                                             ▼ (SHA-256)
┌──────────────────────────────────────────────────────────────────────┐
│  LAYER 3 — BLOBS  (content-addressed; may live on a separate mirror)  │
│  nar/<hash>.nar.zst         — zstd-compressed Nix archives            │
│  <storehash>.narinfo        — Nix narinfo (TARGET; for stock nix)     │
│  nix-cache-info             — Nix cache descriptor (TARGET)           │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.1 Layer 1 — the trust root

The root is the **only** mutable, named object a normal client must know how to
locate. Everything below it is content-addressed and immutable.

| | CURRENT | TARGET |
|---|---|---|
| Root file | `bundle-list.toml` per registry, fetched at `{base}/bundles/{name}/bundle-list.toml` (`registry/bundle.rs:105`) | one inline-signed `registry.toml` at `{base}/registry.toml` (brief §4.3) |
| Signing | the **git commit** is SSH-Ed25519 signed; the manifest itself is not signed | the root file is **inline-signed** (single object, like APT `InRelease`) |
| Freshness anchor | derived: scan manifest for max `creation_token` | explicit signed `[latest]` (`tag`, `token`, `head`) + `valid_until` expiry |
| Index references | bundle `uri` + `sha256` per entry (`BundleEntry`, `registry/bundle.rs:34`) | bundles referenced **by hash** (APT `by-hash` discipline) for torn-publish safety |

The move from `bundle-list.toml` to a single signed `registry.toml` is the
central root-layer decision in the brief (§4.3, §6 Tier 1). See
[`registry-toml.md`](./registry-toml.md) for the full target schema and
[`http-layout.md`](./http-layout.md) for the wire layout.

### 2.2 Layer 2 — the metadata git repo

The registry repository (`apr` writes it; `apm` clones/syncs it) contains:

- **`packages/<x>/<name>.toml`** — per-package metadata with one `[[versions]]`
  block per release and a `[versions.platforms.<platform>]` table per platform.
  Each platform record pins `store_path`, `nar_hash`, `nar_size`,
  `download_hash`, `download_size`, `closure_size`, `source_drv`, and a
  `references` list of dependency **hashes**. (Brief §2.3; exact field names are
  catalogued in [`current-state.md`](./current-state.md).)
- **`closures/<hash>`** — an adjacency list, one line per store path:
  `<root-hash> <dep-hash> <dep-hash> …`; leaves have no dependencies (brief
  §2.3).

The repo is **distributed as git bundles**, not as a live git server, so it
rides over the same dumb HTTP as everything else:

- `BundleType { Snapshot, SequentialDelta, SkipDelta }` (`registry/bundle.rs:22`).
- A `BundleManifest` enumerates the available bundles; the consumer's
  `pick_bundles` algorithm selects the minimal set to advance its state
  (brief §2.4–2.6). See [`bundles-and-deltas.md`](./bundles-and-deltas.md).
- `git+https://` / `git+ssh://` / `git://` URLs are an **alternative** transport
  that fetches the repo directly with FF enforcement (`registry/git.rs`; URL
  scheme selects transport, brief §2.9). Bundles are the dumb-HTTP path; git
  transport is the smart-HTTP/SSH path.

### 2.3 Layer 3 — the blobs

NARs are the actual build artifacts. They are **content-addressed** and
**separate from the registry metadata**:

- **CURRENT:** `nar_url(mirror_url, nar_hash)` →
  `{mirror_url}/{nar_hash}.nar.zst`, where `nar_hash` is the **full**
  `sha256:<hex>` string — the filename literally contains a colon
  (`download.rs:57–60`). The mirror is resolved from the local registry clone's
  `[[caches]]` (sorted by priority), falling back to `{registry.url}/nar`
  (`download.rs:67–82`).
- **CURRENT:** NARs are verified by **SHA-256 content hash**, never by a
  per-blob signature (brief §2.8, §3).
- **TARGET:** the registry origin *may also* serve `<storehash>.narinfo` and
  `nix-cache-info` so stock `nix` can consume the same blobs (brief §4.1). NAR
  co-location vs. a separate cache is a per-deployment choice (brief §7 Q2).

> **Why no per-NAR signature is needed (CURRENT).** Git is a Merkle DAG: the
> single Ed25519-signed commit authenticates the entire tree → every package
> TOML → every `nar_hash` recorded in those TOMLs → every NAR by content hash.
> Authentication is **transitive** down the layers (brief §3.3). The per-narinfo
> `Sig:` field in the TARGET design exists **only** to satisfy stock `nix`
> without `require-sigs = false` — not because `apm` needs it. See
> [`signing-and-trust.md`](./signing-and-trust.md).

---

## 3. Two consumers, one origin

The defining architectural property of the target design is that **one HTTP
origin** serves both `apm` and stock `nix`, because the two protocols occupy
**disjoint URL namespaces** (brief §4.1).

```
                    ┌───────────────────────────────────────┐
                    │        ONE HTTP ORIGIN  {base}/        │
                    │                                        │
   apm (AOS) ──────▶│  AOS namespace:                        │
   "package mgr"    │    registry.toml         (root)        │
                    │    bundles/{name}/…      (git bundles) │
                    │                                        │
   nix (stock) ────▶│  Nix namespace:                        │
   "substituter"    │    nix-cache-info        (descriptor)  │
                    │    <storehash>.narinfo   (per path)    │
                    │                                        │
   both ───────────▶│  Shared blobs:                         │
                    │    nar/<…>.nar.zst       (artifacts)   │
                    └───────────────────────────────────────┘
```

### 3.1 What each consumer fetches

| Step | `apm` (AOS package manager) | stock `nix` (dev-shell substituter) |
|---|---|---|
| Discover root | `GET {base}/registry.toml` (TARGET) / `bundle-list.toml` (CURRENT) | `GET {base}/nix-cache-info` (TARGET) |
| Resolve a package | read package TOMLs from the synced metadata repo | `GET {base}/<storehash>.narinfo` (TARGET) |
| Verify metadata | signed git commit → transitive (CURRENT) | per-narinfo `Sig:` Ed25519 (TARGET) |
| Fetch artifact | `GET {mirror}/{sha256:hex}.nar.zst` (CURRENT, `download.rs:57`) | `GET {base}/nar/<…>.nar.zst` (TARGET) |
| Verify artifact | SHA-256 content hash (CURRENT) | NarHash + `Sig:` (Nix native) |

The two consumers never collide because their entry points (`registry.toml` /
`bundles/…` vs. `nix-cache-info` / `*.narinfo`) are different paths. A static
mirror serving the union of both namespaces is correct for *both* clients with
no server-side logic. See [`nix-cache-compatibility.md`](./nix-cache-compatibility.md)
for the narinfo field mapping and an example substituter config.

### 3.2 Why the models align

Nix's narinfo indirection — a **store-hash** narinfo that points at a
**content-addressed** NAR — is *exactly* how AOS already names its blobs
(brief §4.1). The package TOMLs already carry nearly every narinfo field:

| narinfo field | AOS package TOML field | notes |
|---|---|---|
| `StorePath` | `store_path` | |
| `URL` | derived `nar/<download_hash>.nar.zst` | relative |
| `Compression` | constant `zstd` | |
| `FileHash` / `FileSize` | `download_hash` / `download_size` | compressed `.nar.zst` |
| `NarHash` / `NarSize` | `nar_hash` / `nar_size` | uncompressed |
| `References` | `references` | ⚠ must expand bare hashes → `<hash>-<name>` basenames |
| `Deriver` | `source_drv` | optional |
| `Sig` | — | **must be generated (Ed25519)** — the only net-new field |

So the work to become a strict superset is small: a narinfo generator keyed by
store-path hash, a `nix-cache-info` stub, references-basename expansion, and
per-narinfo Ed25519 signatures (brief §4.1). One Ed25519 key signs *both* the
git commits and the narinfos — same secret, two signed-message forms
(brief §4.2; [`signing-and-trust.md`](./signing-and-trust.md)).

---

## 4. The strict-superset principle

> **TARGET (brief §4.1).** The registry HTTP origin serves **both** the AOS
> protocol and the Nix binary-cache protocol. Because they occupy disjoint URL
> namespaces, adding Nix support is **additive** — a *strict superset* of the AOS
> protocol, never a competing or conflicting one.

Two invariants make this safe:

1. **Namespace disjointness.** No path is claimed by both protocols. `apm` owns
   `registry.toml` and `bundles/…`; `nix` owns `nix-cache-info` and
   `*.narinfo`; `nar/…` is shared but only *read* by both, identically.
2. **Stub-not-index.** `nix-cache-info` remains a *separate file only because Nix
   hardcodes its name* — it is a generated stub (`StoreDir`, `Priority`,
   `WantMassQuery`), **not** a second index competing with `registry.toml`
   (brief §4.3). The single source of truth for enumeration stays inside the AOS
   root.

A consequence: a deployment can start as an AOS-only registry today and *grow*
Nix-cache capability later by emitting the Nix-namespace files, with **zero**
change to the AOS-namespace objects or their clients.

---

## 5. Dumb HTTP as the lowest common denominator

> **TARGET (brief §4.3).** Dumb HTTP is the lowest common denominator. Normal
> clients fetch **one known root file** and never rely on directory listing.
> S3 `ListObjects` is an **optional admin fast-path**, never required for
> correctness. Therefore the enumerated index lives **inside the registry
> files**.

### 5.1 The rule

```
  Normal client:   GET {base}/registry.toml   →   everything else by hash
  Admin / tooling: S3 ListObjects             →   richer queries (optional)
```

A client must be able to operate against a **static file server** — S3 without
listing, a plain CDN bucket, an `nginx` `root`, even `python -m http.server`.
It learns *what exists* exclusively from the signed root, which enumerates the
bundle/delta index by hash. It never needs `LIST`, `PROPFIND`, or any dynamic
endpoint.

This is the same property that lets APT scale to thousands of mirrors from a
signed flat-file index (brief §5; [`apt-comparison.md`](./apt-comparison.md)).
The registry deliberately converges on that model.

### 5.2 Why the index is *inside* the files

If discovery depended on directory listing, three things break:

- **Portability** — many static hosts disable or rate-limit listing.
- **Authentication** — a listing is unsigned; the root's hash-pinned index is
  signed (transitively today, inline tomorrow).
- **Consistency under publish** — a listing read mid-publish can show a torn set;
  a hash-pinned index read from a single signed root cannot (the `by-hash`
  discipline, brief §4.3, §6 Tier 1). A client that read root@T resolves a
  consistent set even after root@T+1 lands, because the root flips **atomically
  and last** (brief §4.4).

### 5.3 S3 as an admin bonus, not a dependency

S3 `ListObjects` and conditional PUT (`If-Match`/`If-None-Match` ETag CAS) are
used **on the producer side** for the atomic root flip and for admin queries
(brief §4.4). They are never on the read path for a normal client. A registry
served from a non-S3 static host is fully correct for consumers; it only loses
the admin fast-path. See [`publishing.md`](./publishing.md) and
[`http-layout.md`](./http-layout.md).

---

## 6. How the pieces fit together (end to end)

### 6.1 Publish (producer) — TARGET ordering

The only safe publish order writes immutable objects first and flips the root
last (brief §4.4):

```
  1. apr publish → commit → apr sign (SSH-Ed25519) → git push
                                              └── git ref CAS = the lock
                                                  (FF-only; loser rebases + retries)
  2. winner generates artifacts FROM the landed commit:
        bundles, *.narinfo, nix-cache-info
  3. upload IMMUTABLE content-addressed objects first
        nar/…, *.narinfo, *.bundle           (idempotent, any order)
  4. flip the root LAST, atomically
        PUT registry.toml  (S3 If-Match / If-None-Match ETag CAS)
```

Readers therefore see either the old root or the new root, never a torn state,
because everything the new root references already exists before the flip
(brief §4.4). "Latest" is an **explicit signed `[latest]` field**, flipped in
that last step — not re-derived by scanning. See
[`publishing.md`](./publishing.md).

> **CURRENT.** The producer is a thin wrapper over `git` + `git bundle create`:
> `apr sign` = `git commit --amend --no-edit -S` (`registry_ops.rs:1770`);
> `apr push` = `git push` with FF enforcement (`registry_ops.rs:1410`);
> `apr bundle` only runs `git bundle create` into a local `bundles/` dir and its
> `_update_manifest` parameter is **dead code** (`registry_ops.rs:1718`). There
> is **no** `bundle-list.toml` writer, no producer-side `creation_token`
> computation, no bundle upload, and no narinfo emission (brief §2.11). The
> producer gaps are enumerated in [`current-state.md`](./current-state.md) and
> mapped to workstreams in
> [`gap-analysis.md`](../plans/registry/gap-analysis.md).

### 6.2 Consume (`apm`) — CURRENT path

```
  apm update:
    1. fetch manifest  GET {base}/bundles/{name}/bundle-list.toml   (bundle.rs:105)
    2. pick_bundles    select minimal snapshot/delta set            (update.rs)
    3. download bundle GET {base}/bundles/{name}/{entry.uri}        (bundle.rs:259)
    4. verify          SHA-256 + git bundle verify                  (bundle.rs:305)
    5. unbundle        git bundle unbundle → consumer cache repo    (bundle.rs:376)
    6. verify commit   SSH-Ed25519 signature (TOFU / trusted-keys)  (security.rs)
    7. persist state   [registry.state] last_commit/token/update    (types.rs)

  apm install / upgrade:
    8. read package TOMLs from the synced repo
    9. download NARs   GET {mirror}/{sha256:hex}.nar.zst            (download.rs:57)
   10. verify          SHA-256 content hash                         (download.rs)
```

Trust roots in the signed commit (step 6) and flows transitively to the NARs
(step 10), so no per-NAR signature is required (brief §3.3).

### 6.3 Consume (`nix`) — TARGET path

A non-AOS dev-shell host adds the origin as a substituter and trusts the
registry's Nix-form public key (`<name>:<base64>`). Stock `nix` then fetches
`nix-cache-info`, the relevant `*.narinfo` files, and the shared `nar/…` blobs,
verifying each via the narinfo `Sig:` it finds there (brief §4.1, §4.2). The
AOS-namespace objects are untouched and invisible to `nix`. See
[`nix-cache-compatibility.md`](./nix-cache-compatibility.md).

---

## 7. Threat model at the architectural level (TARGET)

The layered model has a matching defense at each layer (brief §4.5):

| Threat | Defense | Layer |
|---|---|---|
| Tamper / MITM | signed root + signed commit + content hashes pin every byte | all |
| Rollback | `check_monotonic` on `[latest].token` + `merge-base --is-ancestor` (no ancestor regression) | root + metadata |
| Freeze (mirror stuck on an old but validly-signed root) | APT-style `valid_until` expiry in the signed root; client rejects expired roots | root |
| Omission (a listing hides newer bundles) | signed `[latest].head`: client **fails closed** (can't reach the signed target) rather than silently using stale data — freeze degrades to DoS, not silent rollback | root |

The rollback primitives exist today: `check_monotonic` rejects
`new_token <= old_token` (`registry/state.rs`), and `check_downgrade` classifies
`FastForward / SameCommit / Downgrade / Diverged` via `merge-base`
(`security.rs`, brief §2.5, §2.10). `valid_until` and the signed `[latest]`
anchor are TARGET additions. Full detail in
[`signing-and-trust.md`](./signing-and-trust.md).

---

## 8. Cross-references

- [`README.md`](./README.md) — purpose, audience map, glossary, doc index.
- [`current-state.md`](./current-state.md) — the as-is, grounded in code,
  including the producer gaps.
- [`http-layout.md`](./http-layout.md) — wire/object layout, namespaces,
  dumb-HTTP vs. S3, by-hash, object-key grammar.
- [`registry-toml.md`](./registry-toml.md) — the signed root schema with a full
  annotated example.
- [`bundles-and-deltas.md`](./bundles-and-deltas.md) — bundle model,
  `creation_token`, snapshot/sequential/skip, `pick_bundles`.
- [`nix-cache-compatibility.md`](./nix-cache-compatibility.md) — the strict
  superset: narinfo mapping, `nix-cache-info`, substituter usage.
- [`signing-and-trust.md`](./signing-and-trust.md) — one Ed25519 key, transitive
  authentication, TOFU, threat model.
- [`publishing.md`](./publishing.md) — producer workflow, git CAS lock, atomic
  publish ordering, conditional-PUT root flip.
- [`versioning-and-channels.md`](./versioning-and-channels.md) — versioning,
  tracking modes, symbolic channels, phased rollouts, components.
- [`apt-comparison.md`](./apt-comparison.md) — why this design is
  well-precedented, and the APT improvements adopted.
- Plan set: [`design-brief.md`](../plans/registry/design-brief.md) (grounding
  intent), [`gap-analysis.md`](../plans/registry/gap-analysis.md),
  [`workstream-01-registry-root.md`](../plans/registry/workstream-01-registry-root.md),
  [`workstream-03-nix-cache.md`](../plans/registry/workstream-03-nix-cache.md),
  [`open-questions.md`](../plans/registry/open-questions.md).
