# AOS Registry vs. APT — Comparison & Inherited Lineage

> **Audience:** users, implementers, architects, engineers.
>
> **Scope:** This document maps the AOS registry design onto the Debian/Ubuntu
> **APT repository format**, explains the lineage AOS inherits, re-maps each APT
> mechanism onto the **git-native** model, and calls out where the git-native
> design is strictly better. It is the reference companion to the design brief's
> §3–§12 (the target architecture vs. APT's mechanisms).
>
> **Grounding:** [`docs/plans/registry/design-brief.md`](../plans/registry/design-brief.md)
> §3–§12 is the authoritative intent source for this document.

This page describes **TARGET** state unless a row or note is explicitly marked
**CURRENT**. The as-is behavior of the code is documented in
[`current-state.md`](./current-state.md); the implementation work required to
reach the target is enumerated in
[`docs/plans/registry/gap-analysis.md`](../plans/registry/gap-analysis.md).

> **Important — the design changed.** An earlier capture compared APT to a single
> inline-signed `registry.toml` root with git-*bundle* deltas. That model is
> **superseded**. The target is a **bare git repository (sha256 object format)
> served as static files over dumb HTTP**. Nothing here describes `registry.toml`,
> `bundle-list.toml`, git bundles, `[latest]`, `[components]`, `[capabilities]`,
> percentage rollouts, or `creation_token` ordering — those are removed (see
> design-brief §15). They may still appear in [`current-state.md`](./current-state.md)
> as a description of today's *code*.

---

## 1. Why compare to APT at all?

APT is the canonical proof that a **signed flat-file index served over dumb HTTP**
scales to thousands of independent, untrusted mirrors. It needs no smart server,
no database, no per-request computation on the origin: a client fetches one
known, inline-signed root file, validates the signature, and from there resolves
every index and package **by content hash**.

The AOS registry inherits that exact discipline — **signed static-file indices
over dumb HTTP, with content-addressed blob storage** — and then changes the
*substrate*. Instead of hand-rolled `Release` / `Packages` text files plus a
`pool/` of `.deb`s, AOS uses a **bare git repository in sha256 object format**,
published verbatim as static files. The package metadata *is* the git tree; the
content-addressed blob store *is* the git object store; the signed root *is* a
signed git tag object.

This keeps three pieces of APT's lineage that genuinely hold up:

1. **Signed static-file indices over dumb HTTP.** No smart server. A stock
   `git clone <url>` works because the repo is a valid dumb-HTTP bare repo
   (design-brief §12).
2. **A content-addressed `pool`.** APT's `pool/` is content-*organized*; git's
   loose object store under `/objects/<xx>/<62-hex>` is content-*addressed* (the
   path **is** the sha256), which is strictly stronger for dedup and integrity.
3. **Phased rollout heritage.** APT's `Phased-Update-Percentage` proved that
   fleet-wide canarying belongs in the index; AOS keeps the idea and replaces the
   percentage with **16 signed partitions** (design-brief §6).

Where the two diverge, AOS is generally **ahead**, because its substrate is a
**Merkle DAG** with **atomic ref updates** that is **dumb-HTTP-clonable**. Those
three structural facts give AOS signed history, torn-publish safety, and
zero-cost reproducible snapshots without bolting anything on.

See [`architecture.md`](./architecture.md) for the layered model and the
dumb-HTTP-lowest-common-denominator philosophy, and
[`http-layout.md`](./http-layout.md) for the concrete object layout the
comparison below references.

---

## 2. Structure of an APT repository (quick reference)

For readers unfamiliar with APT, the relevant pieces are:

```
dists/
  <suite>/                         e.g. stable, bookworm
    InRelease                      inline-signed root: index list + hashes + Valid-Until
    Release / Release.gpg          detached-signature variant of the above
    <component>/                   e.g. main, contrib, non-free
      binary-<arch>/
        Packages[.gz/.xz]          stanzas: Package, Filename->pool, Size, SHA256, Depends
        Packages.diff/Index        pdiff: incremental Packages updates
      Contents-<arch>.gz           file index: which package ships which path
    by-hash/SHA256/<hash>          content-addressed copies of the index files
pool/
  <component>/<l>/<src>/<pkg>.deb  the actual packages, content-organized
```

The **trust root** is `InRelease`: one file signed *inline* (signature and
payload fetched atomically) enumerating every index file with its size and
SHA-256. From a validated `InRelease`, every other file is pinned by hash.
`Valid-Until` bounds how long a signed root may be trusted, defending against a
mirror **freezing** clients on an old (but validly-signed) snapshot.

---

## 3. The structural re-mapping

The single most important shift: APT distributes **hand-generated text indices +
a separate pool**, while AOS distributes **a git object DAG**. Every APT concept
re-maps onto a git primitive.

```
            APT                                git-native AOS
   ┌──────────────────────┐          ┌────────────────────────────────────┐
   │ InRelease (signed)   │   ──→     │ signed tag object (Ed25519/SSH),    │
   │  enumerates indices  │           │  message = TOML [meta] + [[caches]] │
   │  + Valid-Until       │           │  + valid_until                      │
   ├──────────────────────┤          ├────────────────────────────────────┤
   │ Release/Release.gpg  │   ──→     │ info/refs + HEAD (update-server-info)│
   │  (ref/index surface) │           │  the dumb-HTTP ref shim             │
   ├──────────────────────┤          ├────────────────────────────────────┤
   │ Packages (flat text) │   ──→     │ git tree + blob objects             │
   │  Filename->pool      │           │  (the metadata IS the tree content) │
   ├──────────────────────┤          ├────────────────────────────────────┤
   │ pool/*.deb           │   ──→     │ /objects/<xx>/<62-hex> loose objects │
   │  (content-organized) │           │  (content-ADDRESSED) + full packs    │
   ├──────────────────────┤          ├────────────────────────────────────┤
   │ Packages.diff (pdiff)│   ──→     │ thin delta-<from-semver>.pack        │
   │                      │           │  (git pack-objects --thin)          │
   ├──────────────────────┤          ├────────────────────────────────────┤
   │ by-hash/SHA256/<h>   │   ──→     │ content-addressed git objects        │
   │                      │           │  (path == sha256, intrinsically)     │
   ├──────────────────────┤          ├────────────────────────────────────┤
   │ Phased-Update-%      │   ──→     │ 16 signed partition tags /channel/*  │
   ├──────────────────────┤          ├────────────────────────────────────┤
   │ suites / components  │   ──→     │ channels = branches refs/heads/*     │
   ├──────────────────────┤          ├────────────────────────────────────┤
   │ Valid-Until          │   ──→     │ tag-message valid_until             │
   └──────────────────────┘          └────────────────────────────────────┘
```

Two namespaces ride alongside the standard git surface without conflicting
(design-brief §3): the AOS `/channel/<name>/0..f` partition tags (signed,
bucketed rollout) and the thin `delta-*.pack`s (cheap incremental fetch). A stock
dumb `git clone` ignores both and still resolves a complete, correct tree from
loose objects + conventionally-named full packs.

---

## 4. Side-by-side comparison

The table pairs each APT mechanism with its AOS (target, git-native)
counterpart. The AOS column links to the reference doc that specifies it.

| APT mechanism | AOS registry (TARGET) | Reference |
|---|---|---|
| `InRelease` — inline-signed root: index list + hashes + `Valid-Until` | **Signed tag object** (annotated git tag, SSH-format Ed25519). Its message is **TOML** carrying only `[meta]` (`schema`, `valid_until`) + `[[caches]]`. Channel partition tags *and* release tags are signed. | [`tag-metadata.md`](./tag-metadata.md), [`signing-and-trust.md`](./signing-and-trust.md) |
| `Release` / `Release.gpg` (the ref/index surface) | `HEAD` + `info/refs` regenerated by `git update-server-info` on every publish; `objects/info/http-alternates` lists every per-release object dir (doubles as the full release index) | [`http-layout.md`](./http-layout.md) |
| OpenPGP / GPG signature | **Ed25519**, SSH signature format (reuses `apr sign` / `security.rs`); one key may also sign narinfos if NARs are served | [`signing-and-trust.md`](./signing-and-trust.md) |
| `Packages` stanzas (`Package`, `Filename`→pool, `Size`, `SHA256`, `Depends`) | The git **tree + blob objects** are the metadata — package TOMLs live in the tree, transitively authenticated by the signed tag. Dependencies are **explicit closures**, not a `Depends` solver field. | [`http-layout.md`](./http-layout.md), [`nix-cache-compatibility.md`](./nix-cache-compatibility.md) |
| `pool/…/<pkg>.deb` — content-organized package files | **Content-addressed git object store**: `/objects/<xx>/<62-hex>` loose objects (sha256 2/62 split) — *all* objects exist loose as the completeness fallback; full packs are an efficiency layer | [`http-layout.md`](./http-layout.md), [`packs-and-deltas.md`](./packs-and-deltas.md) |
| `Packages.diff/Index` — pdiff incremental index | **Thin delta packs** `delta-<from-semver>.pack`: `git pack-objects --revs --thin` reading `"<to>\n^<from>\n"`; client completes with `git index-pack --fix-thin`. A guaranteed, walkable delta graph at every release. | [`packs-and-deltas.md`](./packs-and-deltas.md) |
| `by-hash/SHA256/<h>` — consistency under concurrent publish | **Intrinsic** — git objects *are* content-addressed (the path is the sha256). Publish flips refs atomically; a client that resolved a ref reads a consistent immutable object closure regardless of later publishes. | [`http-layout.md`](./http-layout.md) |
| `dists/<suite>/…/binary-<arch>/` partitioning | **Channels are branches** (`refs/heads/<channel>`); `HEAD` = the default channel. (No `[components]` table in the target.) | [`versioning-and-channels.md`](./versioning-and-channels.md) |
| `Valid-Until` — time-based freshness bound | `valid_until` in the tag-message `[meta]`: **freshness** knob for channels (paired with low CDN TTL), **generous** signature-trust/key-rotation lifetime for releases | [`tag-metadata.md`](./tag-metadata.md), [`signing-and-trust.md`](./signing-and-trust.md) |
| dumb-HTTP, static-mirror-friendly | dumb-HTTP is the substrate — the repo is a valid bare dumb-HTTP repo; a stock `git clone` works (design-brief §12) | [`architecture.md`](./architecture.md), [`http-layout.md`](./http-layout.md) |
| `signed-by=` per-source key pinning | per-registry key pinning via TOFU + `trusted-keys.d/<registry>.pub` | [`signing-and-trust.md`](./signing-and-trust.md) |
| `snapshot.debian.org` reproducible archives | reproducible snapshots are intrinsic: a signed tag addresses an immutable commit; the whole object closure is content-addressed | [`versioning-and-channels.md`](./versioning-and-channels.md) |
| Phased updates (`Phased-Update-Percentage`) | **16 signed partition tags** `/channel/<name>/0..f`; the publisher points N partitions at a new release to roll it to N/16 of the fleet; clients self-select a deterministic bucket | [`versioning-and-channels.md`](./versioning-and-channels.md) |
| `Components` (`main` / `contrib` / `non-free`) | **Not adopted** — the target has no `[components]` table; a registry is one git repo, partitioned by channel branches | [`versioning-and-channels.md`](./versioning-and-channels.md) |
| `Contents-<arch>` — file → package index | not in scope for the registry layer; file-index discovery is a separate concern | — |

---

## 5. Detailed re-mappings

### 5.1 `InRelease` → signed tag object (TOML message)

APT's trust root is one text file: a signature wrapping a body that enumerates
every index with its hash and a `Valid-Until`. AOS replaces it with a **signed
git tag object** whose *message is TOML*. The signature is on the tag object
itself (SSH-format Ed25519), so it is fetched atomically with its payload exactly
like `InRelease`.

The tag-message TOML is deliberately tiny — the tag *object* carries the
signature, the ref namespace carries the pointers, and the object store carries
everything else. The canonical shape (design-brief §14) supports **only**:

```toml
[meta]
schema      = 1                      # integer schema version
valid_until = "2026-06-30T00:00:00Z" # channels: freshness; releases: generous

[[caches]]
url      = "./nar"                   # relative (same origin) OR absolute
priority = 100
```

No `[latest]`, `[components]`, `[capabilities]`, `[channels]`, `[[bundles]]`,
`[[deltas]]`, `pubkey`, or `[signature]` tables exist. The hash *enumeration*
that `InRelease` needs is unnecessary because git objects are self-naming by hash
and the tag's commit transitively authenticates the whole tree. See
[`tag-metadata.md`](./tag-metadata.md).

### 5.2 `pool/*.deb` → content-addressed git object store

APT's `pool/` is content-*organized* (`pool/main/l/libfoo/…`) but the filename is
still a human name; integrity comes from the `Packages` `SHA256` field. AOS's
store is content-*addressed*: an object at `/objects/ab/cdef…` **is** the object
whose sha256 is `abcdef…`. Two consequences:

- **Dedup is free and exact.** Identical content has one path. APT relies on the
  pool's human layout plus per-stanza hashes; git relies on the path itself.
- **Tamper-evidence is intrinsic.** A wrong byte changes the hash, so the path no
  longer resolves — there is no "trust the `SHA256` field" step distinct from
  "fetch the file."

**ALL objects exist loose** under `/objects/<xx>/<62-hex>` (design-brief §8) —
the guaranteed completeness fallback for any stock dumb client. Packs sit on top
as an efficiency layer. See [`http-layout.md`](./http-layout.md).

### 5.3 `Packages.diff` (pdiff) → thin delta packs

APT's pdiff ships line-level `ed`-script diffs of the `Packages` text so clients
patch their local index instead of re-downloading it. AOS generalizes this to
the whole object DAG with **thin git packs**.

**Producer** (design-brief §10), per `packs-and-deltas.md`:

```sh
# Thin delta: objects in <to> not in <from>; deltas MAY reference <from>'s objects
printf '%s\n^%s\n' "$to_commit" "$from_commit" \
  | git pack-objects --revs --thin \
      --no-reuse-object --no-reuse-delta \
      --window=350 --depth=50 --threads=0 \
      --stdout > delta-"$from_semver".pack
```

**Consumer** completes the thin pack against objects it already retains:

```sh
git index-pack --fix-thin delta-<from-semver>.pack
```

The delta *graph* is guaranteed and walkable so clients can plan (design-brief
§9): every `X.Y.0` ships a self-contained full pack; majors/minors ship deltas
from the previous major/minor and current major; patches ship deltas from the
last three patches and the current minor. This is strictly richer than pdiff,
which only diffs *consecutive* index snapshots. See
[`packs-and-deltas.md`](./packs-and-deltas.md).

> **pdiff parallel preserved:** the *reason* both exist is identical — never make
> a client re-download a full index/closure when a small diff suffices. AOS just
> diffs the object DAG instead of one text file, and degrades to a full pack, then
> to loose objects, when no usable delta exists.

### 5.4 `Phased-Update-Percentage` → 16 signed partitions

APT canaries a release to a percentage of machines; each client hashes its
`machine-id` (plus package identity) and updates only if the hash falls under the
current percentage. AOS keeps the heritage and discretizes it into **exactly 16
signed partition tags** per channel (design-brief §6):

```
/channel/stable/
  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f   ← 16 SIGNED tag objects
       each (tag name == "stable") → a semver release tag
```

- **Consumer bucket selection** is deterministic and *persisted*:
  `sha256(machine_id) mod 16`, written once so a host does not flap between
  buckets. (APT recomputes per-package; AOS pins a stable bucket per host.)
- **Publisher-controlled rollout:** to roll a new release to N/16 of the fleet,
  point N partitions at the new semver tag; the un-advanced partitions still name
  the prior release — which **explicitly answers "where does the rest of the
  fleet go"** (APT leaves the not-yet-phased cohort implicit). Advance partitions
  as confidence grows; completion = all 16 point at the new release.
- **There must always be 16.** If one is missing a client *may* probe-forward
  `(bucket+1) mod 16`.
- **Anti-rollback:** a consumer keeps a monotonic floor and never moves to an
  older release. Aborting a bad rollout is **fix-forward** (publish a newer
  release, point partitions at it) — never partition-decrement.

See [`versioning-and-channels.md`](./versioning-and-channels.md).

### 5.5 `Valid-Until` → tag `valid_until`

Same defense, same field name (lowercased). A mirror cannot pin clients on a
validly-signed-but-stale snapshot forever. The git-native twist is **dual
semantics by ref class** (design-brief §11):

- **Channel partition tags:** `valid_until` is a tight **freshness** bound,
  paired with the **low CDN TTL** mandated for `/channel/**`. Expired ⇒ refuse to
  treat the rollout pointer as current.
- **Release tags:** `valid_until` is a **generous** signature-trust /
  key-rotation lifetime — it must *not* fight the long CDN TTL on immutable
  `/release/**`.

See [`signing-and-trust.md`](./signing-and-trust.md).

### 5.6 `signed-by=` → TOFU + `trusted-keys.d`

Both pin a per-source key. AOS reuses the existing primitive: a registry's
Ed25519 public key in `name:Ed25519:<base64>` format (parsed by
`parse_signing_key`, `crates/aos-package/src/security.rs:306`), trust-on-first-use
plus `trusted-keys.d/<registry>.pub`. Verification today runs
`git verify-commit` against a temporary `allowed_signers`
(`crates/aos-package/src/security.rs:199`); the target moves this to
`git verify-tag` over the signed tag objects.

---

## 6. Where the git-native design is strictly better

These are not gaps to close — they are structural wins from choosing a git DAG
over hand-generated indices.

### 6.1 Merkle history (signed, walkable, fork-detecting)

APT's `Release` authenticates one snapshot; there is no native notion of "is
snapshot B a descendant of snapshot A." AOS's commit DAG gives **signed history
for free**: a signed tag authenticates a commit, which authenticates its whole
ancestry as a Merkle DAG. `git merge-base --is-ancestor` distinguishes
fast-forward, same-commit, downgrade, and divergence — APT has no equivalent
native check. The **frontier** (the channel branch head, design-brief §6) is just
the newest release any partition targets, and ancestry tells a client whether a
proposed move is forward or a rollback.

### 6.2 Dumb-HTTP-clonable (the index *is* the transport)

APT needs a client that understands `Release`/`Packages`/pdiff text formats. AOS
needs only **git** — and even then, only *dumb* HTTP. A stock `git clone <url>`
resolves channels (branches) and releases (tags) from loose objects +
conventionally-named full packs, with **zero AOS-specific tooling**
(design-brief §12). The AOS layer (`/channel` partitions, thin deltas) is purely
additive and invisible to stock git.

> Edge: sha256 over dumb HTTP requires a client git that supports sha256 (the
> dumb protocol has no capability negotiation). This is the one new compatibility
> constraint the substrate introduces (design-brief §12, §16).

### 6.3 Atomic refs (torn-publish safety without `by-hash` bookkeeping)

APT added `by-hash/SHA256/<h>` *specifically* so a client reading `Release@T`
still resolves a consistent index set if `Release@T+1` lands mid-fetch. In AOS
this is **intrinsic**: objects are immutable and content-addressed, and a publish
is an **atomic ref flip**. A client that resolved a partition/release tag reads
its complete immutable object closure no matter what later publishes do — no
parallel `by-hash` directory to maintain. The producer pays the cost (expensive
packing, design-brief §10) so every consumer reads a consistent, immutable view
cheaply. See [`publishing.md`](./publishing.md).

### 6.4 Reproducible snapshots without a snapshot service

`snapshot.debian.org` is a *separate archive* that periodically captures the
state of the main archive. In AOS, **every signed release tag already is** an
immutable, content-addressed snapshot; there is nothing extra to run or store.

### 6.5 The Nix binary-cache superset (orthogonal bonus)

APT's `pool` holds `.deb`s consumed only by APT. AOS's origin can *additionally*
advertise itself as a **Nix NAR binary cache** via a `[[caches]]` entry whose
`url` may be **relative** (same origin) — exposing
`nix-cache-info` / `<storehash>.narinfo` / `nar/` so stock `nix` dev-shell
substitution works as a strict superset. The same Ed25519 key signs narinfos
(separate signature object). See [`nix-cache-compatibility.md`](./nix-cache-compatibility.md)
and design-brief §13.

---

## 7. Where AOS keeps APT's lineage verbatim

| Capability | APT | AOS (git-native) equivalent | Verdict |
|---|---|---|---|
| Signed static-file index over dumb HTTP | `InRelease` + dumb HTTP | signed tag object + `info/refs`/`HEAD` over dumb HTTP | **parity (kept)** |
| Content-addressed pool | `pool/` (content-organized) + `Packages` `SHA256` | `/objects/<xx>/<62-hex>` (content-*addressed*) | **AOS ahead** |
| Incremental index updates | `Packages.diff` (pdiff) | thin `delta-*.pack` graph | **AOS ahead** (DAG, not one text file) |
| Concurrent-publish consistency | `by-hash/SHA256/<h>` | immutable objects + atomic ref flip | **AOS ahead** (intrinsic) |
| Time-based freshness | `Valid-Until` | tag `valid_until` (dual semantics) | **parity (kept)** |
| Per-source key pinning | `signed-by=` | TOFU + `trusted-keys.d/<registry>.pub` | **parity (kept)** |
| Reproducible snapshots | `snapshot.debian.org` | immutable signed tags | **AOS ahead** (no extra service) |
| Phased rollout | `Phased-Update-Percentage` | 16 signed partition tags | **AOS ahead** (explicit cohorts) |

---

## 8. Where AOS deliberately drops APT mechanisms

These are **not** re-added to the target (design-brief §15):

- **Regenerated flat `Packages` / `Release` text.** The git tree *is* the index;
  there is nothing to regenerate or to tear during an rsync.
- **OpenPGP/GPG.** One Ed25519 key (SSH signature form) serves git signing and,
  optionally, narinfo signing.
- **`Depends` SAT solver.** AOS records explicit, pre-computed dependency
  closures — exact, reproducible, already authenticated — so there is no
  install-time solver.
- **`Components` (`main`/`contrib`/`non-free`).** No `[components]` table; a
  registry is one git repo partitioned by channel branches.
- **`Contents-<arch>` file index.** Out of scope for the registry layer.
- **The superseded `registry.toml` / `bundle-list.toml` / git-bundle / `[latest]`
  / percentage-rollout / `creation_token` model** — see the banner at the top and
  [`current-state.md`](./current-state.md) for what today's *code* still does.

---

## 9. CURRENT vs TARGET

The **TARGET** is everything above. Today's **CURRENT** code is the bundle /
`creation_token` implementation:

- A registry is a git repo of nested package TOMLs (`PackageToml`,
  `crates/aos-package/src/registry/parse.rs:15`; written by `build_package_toml`,
  `crates/aos-package/src/registry_ops.rs:595`) plus `closures/<hash>` adjacency
  files; `PackageMeta` (`crates/aos-package/src/types.rs:44`) is the flattened
  in-memory projection.
- Distribution is via **git bundles** + a `bundle-list.toml` the *consumer*
  parses (`crates/aos-package/src/registry/bundle.rs`); the producer side is a
  stub. Bundle selection is `pick_bundles`
  (`crates/aos-package/src/update.rs:292`).
- Versions are **calendar tags** (`vYYYY.MM[.P]`) ordered by `version_to_token`
  (`crates/aos-package/src/registry/state.rs:131`); tracking modes are
  commit/branch/tag/version (`TrackingMode`,
  `crates/aos-package/src/types.rs:282`).
- Signing already uses **SSH-format Ed25519** git signatures, verified via
  `git verify-commit` + a temporary `allowed_signers`
  (`crates/aos-package/src/security.rs:199`), with TOFU +
  `trusted-keys.d/<registry>.pub`.

The target **keeps** the Ed25519/SSH signing primitive and the package-TOML tree
content, and replaces *everything about distribution, indexing, and rollout* with
the git-native model. See [`docs/plans/registry/gap-analysis.md`](../plans/registry/gap-analysis.md).

---

## 10. Summary

```
                 APT                          AOS registry (git-native target)
        ┌─────────────────────┐        ┌────────────────────────────────────┐
root    │ InRelease (signed)  │   ≈    │ signed tag object (TOML [meta])     │
        │  + Valid-Until      │        │  + valid_until                      │
refs    │ Release/Release.gpg │   ≈    │ info/refs + HEAD (server-info)      │
sign    │ OpenPGP             │   →    │ Ed25519 (one key; SSH + narinfo)    │
index   │ Packages (flat text)│   ↑    │ git tree/blob objects               │ AOS ahead
deltas  │ pdiff               │   ↑    │ thin delta-*.pack (DAG)             │ AOS ahead
pool    │ pool/*.deb (org'd)  │   ↑    │ /objects/<xx>/<hex> (addressed)     │ AOS ahead
deps    │ Depends (solver)    │   ↑    │ explicit closures                   │ AOS ahead
consist │ by-hash             │   ↑    │ immutable objects + atomic ref flip │ AOS ahead
chan    │ suites/components   │   →    │ channels = branches (no components) │
rollout │ Phased-Update-%     │   ↑    │ 16 signed partition tags            │ AOS ahead
trust   │ signed-by=          │   ≈    │ TOFU + trusted-keys.d/              │
fresh   │ snapshot.debian.org │   ↑    │ immutable signed tags               │ AOS ahead
clone   │ APT-specific client │   ↑    │ stock `git clone` (dumb HTTP)       │ AOS ahead
        └─────────────────────┘        └────────────────────────────────────┘
          ≈ parity (kept)   ↑ AOS structurally ahead   → re-mapped onto git
```

**Keep from APT:** signed static-file indices over dumb HTTP; a content-addressed
pool; the phased-rollout idea; `Valid-Until`; per-source key pinning.
**Re-map onto git:** `InRelease`→signed tag object; `Packages`→git tree;
`pool`→object store; pdiff→thin delta packs; `Phased-Update-%`→16 partitions;
`by-hash`→content-addressed objects; `Valid-Until`→tag `valid_until`.
**Drop:** regenerated flat `Packages`, OpenPGP, `Depends` solver, `Components`,
`Contents-<arch>`, rsync-mirror publish.

---

## See also

- [`README.md`](./README.md) — registry reference index and glossary.
- [`architecture.md`](./architecture.md) — git-repo-over-dumb-HTTP; superset of git and Nix.
- [`current-state.md`](./current-state.md) — the as-is bundle/`creation_token` implementation.
- [`http-layout.md`](./http-layout.md) — HTTP/object layout, object store, `http-alternates`, stock-git compat.
- [`versioning-and-channels.md`](./versioning-and-channels.md) — semver, channels-as-branches, 16-partition rollout.
- [`packs-and-deltas.md`](./packs-and-deltas.md) — pack-objects, thin/full packs, the delta scheme, zstd.
- [`tag-metadata.md`](./tag-metadata.md) — the channel/release tag-message TOML schema.
- [`signing-and-trust.md`](./signing-and-trust.md) — signed tag objects, name-binding, `tag→tag→commit`.
- [`publishing.md`](./publishing.md) — the producer pipeline and atomic publish ordering.
- [`nix-cache-compatibility.md`](./nix-cache-compatibility.md) — the Nix binary-cache superset.
- Plan: [`docs/plans/registry/design-brief.md`](../plans/registry/design-brief.md) §3–§12 (grounding),
  [`gap-analysis.md`](../plans/registry/gap-analysis.md),
  [`workstream-03-channels-rollouts.md`](../plans/registry/workstream-03-channels-rollouts.md).
