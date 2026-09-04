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

> Superseded concepts live only in [`current-state.md`](./current-state.md)
> (today's code) and design-brief §15.

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
   percentage with **256 signed partitions** (design-brief §6).

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
   │ InRelease (signed)   │   ──→     │ signed tag object (Ed25519/SSH):    │
   │  enumerates indices  │           │  a PURE signed pointer (object,     │
   │  + Valid-Until       │           │  type, name, tagger, signature)     │
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
   │ Packages.diff (pdiff)│   ──→     │ thin delta-<from-semver>.pack.zst    │
   │                      │           │  (Rust thinpack + zstd)              │
   ├──────────────────────┤          ├────────────────────────────────────┤
   │ by-hash/SHA256/<h>   │   ──→     │ content-addressed git objects        │
   │                      │           │  (path == sha256, intrinsically)     │
   ├──────────────────────┤          ├────────────────────────────────────┤
   │ Phased-Update-%      │   ──→     │ 256 signed partition tags /channels/* │
   ├──────────────────────┤          ├────────────────────────────────────┤
   │ suites / components  │   ──→     │ channels = branches refs/heads/*     │
   ├──────────────────────┤          ├────────────────────────────────────┤
   │ Valid-Until          │   ──→     │ AOS-TUF timestamp + channel policy │
   │                      │           │  (signed expiry over snapshot)      │
   └──────────────────────┘          └────────────────────────────────────┘
```

Two namespaces ride alongside the standard git surface without conflicting
(design-brief §3): the AOS `/channels/<name>/00..ff` partition tags (signed,
bucketed rollout) and the thin `delta-*.pack`s (cheap incremental fetch). A stock
dumb `git clone` ignores both and still resolves a complete, correct tree from
loose objects + conventionally-named full packs.

---

## 4. Side-by-side comparison

The table pairs each APT mechanism with its AOS (target, git-native)
counterpart. The AOS column links to the reference doc that specifies it.

| APT mechanism | AOS registry (TARGET) | Reference |
|---|---|---|
| `InRelease` — inline-signed root: index list + hashes + `Valid-Until` | **Signed tag object** (annotated git tag, SSH-format Ed25519): a **pure signed pointer** — standard git tag fields (`object`, `type`, the tag *name*, `tagger`) + the Ed25519 signature + an optional freeform human message. No structured payload. Channel partition tags *and* release tags are signed. | [`signing-and-trust.md`](./signing-and-trust.md) |
| `Release` / `Release.gpg` (the ref/index surface) | `HEAD` + `info/refs` regenerated by `git update-server-info` on every publish; `objects/info/alternates` lists every per-release pack dir as relative `../releases/…/objects/` paths (doubles as the release index) | [`http-layout.md`](./http-layout.md) |
| OpenPGP / GPG signature | **Ed25519**, SSH signature format for registry tags; a separate cache-role Ed25519 key signs narinfos when NARs are served | [`signing-and-trust.md`](./signing-and-trust.md) |
| `Packages` stanzas (`Package`, `Filename`→pool, `Size`, `SHA256`, `Depends`) | The git **tree + blob objects** are the metadata — package TOMLs live in the tree, transitively authenticated by the signed tag. Dependencies are **explicit closures**, not a `Depends` solver field. | [`http-layout.md`](./http-layout.md), [`nix-cache-compatibility.md`](./nix-cache-compatibility.md) |
| `pool/…/<pkg>.deb` — content-organized package files | **Content-addressed git object store**: *all* loose objects for every release live under the single root `/objects/<xx>/<62-hex>` (sha256 2/62 split) as the completeness fallback; per-release `/releases/*/objects/` dirs are **pack-only** (an efficiency layer) | [`http-layout.md`](./http-layout.md), [`packs-and-deltas.md`](./packs-and-deltas.md) |
| `Packages.diff/Index` — pdiff incremental index | **Thin delta packs** `delta-<from-semver>.pack.zst`: Rust thinpack over `to ^from`, zstd transport compression, and client-side local pack indexing. A guaranteed, walkable delta graph at every release. | [`packs-and-deltas.md`](./packs-and-deltas.md) |
| `by-hash/SHA256/<h>` — consistency under concurrent publish | **Intrinsic** — git objects *are* content-addressed (the path is the sha256). Publish flips refs atomically; a client that resolved a ref reads a consistent immutable object closure regardless of later publishes. | [`http-layout.md`](./http-layout.md) |
| `dists/<suite>/…/binary-<arch>/` partitioning | **Channels are branches** (`refs/heads/<channel>`); `HEAD` = the default channel. (No `[components]` table in the target.) | [`versioning-and-channels.md`](./versioning-and-channels.md) |
| `Valid-Until` — time-based freshness bound | AOS-TUF `timestamp.json` gives signed expiry over the selected snapshot; channel pointers additionally use low CDN TTL, consumer max-staleness, and the monotonic anti-rollback floor | [`signing-and-trust.md`](./signing-and-trust.md), [`versioning-and-channels.md`](./versioning-and-channels.md) |
| dumb-HTTP, static-mirror-friendly | dumb-HTTP is the substrate — the repo is a valid bare dumb-HTTP repo; a stock `git clone` works (design-brief §12) | [`architecture.md`](./architecture.md), [`http-layout.md`](./http-layout.md) |
| `signed-by=` per-source key pinning | per-registry out-of-band anchor in `trusted-keys.d/<registry>.pub` + in-band `keys.toml` roster | [`signing-and-trust.md`](./signing-and-trust.md) |
| `snapshot.debian.org` reproducible archives | reproducible snapshots are intrinsic: a signed tag addresses an immutable commit; the whole object closure is content-addressed | [`versioning-and-channels.md`](./versioning-and-channels.md) |
| Phased updates (`Phased-Update-Percentage`) | **256 signed partition tags** `/channels/<name>/00..ff`; the publisher points N partitions at a new release to roll it to N/256 of the fleet; clients self-select a deterministic bucket | [`versioning-and-channels.md`](./versioning-and-channels.md) |
| `Components` (`main` / `contrib` / `non-free`) | **Not adopted** — the target has no `[components]` table; a registry is one git repo, partitioned by channel branches | [`versioning-and-channels.md`](./versioning-and-channels.md) |
| `Contents-<arch>` — file → package index | not in scope for the registry layer; file-index discovery is a separate concern | — |

---

## 5. Detailed re-mappings

### 5.1 `InRelease` → signed tag object (pure signed pointer)

APT's trust root is one text file: a signature wrapping a body that enumerates
every index with its hash and a `Valid-Until`. AOS replaces it with a **signed
git tag object** that is a **pure signed pointer** — no structured payload. The
signature is on the tag object itself (SSH-format Ed25519), so it is fetched
atomically with its payload exactly like `InRelease`.

A signed tag carries only the standard git tag fields — `object` (the commit it
points at), `type`, the tag **name**, and `tagger` — plus the Ed25519 signature
and an **optional freeform human message**. There is no TOML, no `[meta]`, no
`schema`, no `valid_until`, and no `[[caches]]` table inside the tag object. The
tag *object* carries the signature, the ref namespace carries the pointers, and
the object store carries everything else.

The hash *enumeration* that `InRelease` needs is unnecessary because git objects
are self-naming by hash and the tag's commit transitively authenticates the whole
tree. See [`signing-and-trust.md`](./signing-and-trust.md).

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

**ALL loose objects are centralized at the single root** `/objects/<xx>/<62-hex>`
(design-brief §8) — every release writes its loose objects there, the guaranteed
completeness fallback for any stock dumb client. The per-release
`/releases/<M>/<m>/<patch…>/objects/` dirs are **pack-only**: they hold
`info/packs` + `pack/pack-<sha256>.pack(.idx)` + `pack/delta-<from>.pack.zst`, with no
loose `<xx>/<…>` objects and no per-release `info/alternates`. Packs sit on top
as an efficiency layer. See [`http-layout.md`](./http-layout.md).

### 5.3 `Packages.diff` (pdiff) → thin delta packs

APT's pdiff ships line-level `ed`-script diffs of the `Packages` text so clients
patch their local index instead of re-downloading it. AOS generalizes this to
the whole object DAG with **thin git packs**.

**Producer**, per `packs-and-deltas.md`: `registry::thinpack` writes a thin pack
equivalent to `git pack-objects --thin` over `to ^from`, then the producer serves
`delta-<from-semver>.pack.zst`.

**Consumer** decompresses the thin pack and completes it against objects it
already retains using local libgit2 pack indexing.

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

### 5.4 `Phased-Update-Percentage` → 256 signed partitions

APT canaries a release to a percentage of machines; each client hashes a stable
machine identity (plus package identity) and updates only if the hash falls under
the current percentage. AOS keeps the heritage and discretizes it into **exactly 256
signed partition tags** per channel (design-brief §6):

```
/channels/stable/
  00  01  02  ..  b7  ..  fd  fe  ff   ← 256 SIGNED tag objects
       each (tag name == "stable") → a semver release tag
```

- **Consumer bucket selection** is generated once per registry and *persisted*:
  first sync hashes `registry_name || "\0" || registry_local_salt` to choose
  `00..ff`, then writes that bucket so a host does not flap between buckets.
  (APT recomputes per-package; AOS pins a stable bucket per host and registry.)
- **Publisher-controlled rollout:** to roll a new release to N/256 of the fleet,
  point N partitions at the new semver tag; the un-advanced partitions still name
  the prior release — which **explicitly answers "where does the rest of the
  fleet go"** (APT leaves the not-yet-phased cohort implicit). Advance partitions
  as confidence grows; completion = all 256 point at the new release.
- **There must always be 256.** If one is missing a client *may* probe-forward
  `(bucket+1) mod 256`.
- **Anti-rollback:** a consumer keeps a monotonic floor and never moves to an
  older release. Aborting a bad rollout is **fix-forward** (publish a newer
  release, point partitions at it) — never partition-decrement.

See [`versioning-and-channels.md`](./versioning-and-channels.md).

### 5.5 `Valid-Until` → AOS-TUF timestamp + channel policy

APT's `Valid-Until` is an **in-band signed expiry**: the signed root names the
instant past which it must not be trusted, defending against a mirror that pins
clients on a validly-signed-but-stale snapshot. AOS moving-ref syncs require
release commits to carry `tuf/timestamp.json`, a short-lived signed pointer to
the accepted snapshot hash. Channel tracking still layers CDN TTL, consumer
max-staleness, and the monotonic anti-rollback floor around rollout pointers.

- **Low CDN TTL** on the mutable surfaces — `/channels` (the rollout pointers) and
  the dumb-HTTP ref shim (`info/refs`, `objects/info`) — so a frozen mirror falls
  behind quickly.
- **The consumer's own max-staleness policy** — its local registry config decides
  how old the last channel freshness observation may be before a failed refresh
  or unchanged-but-valid signed channel target is treated as stale. `apm`
  persists that observation in
  `[registry.state].last_update`, and `max_staleness_seconds` defaults to 14 days
  for channel sync.
- **The monotonic anti-rollback floor** — a consumer never moves to an older
  release than one it has already accepted.

Moving-ref consumers verify `tuf/timestamp.json` before accepting the package
catalog. Explicit commit/tag/version pins keep old immutable releases
reproducible: they verify TUF signatures, hashes, and metadata version floors
when TUF exists, but do not fail solely because TUF is absent on a pre-cutover
release or because the signed timestamp window has passed.

See [`signing-and-trust.md`](./signing-and-trust.md) and
[`versioning-and-channels.md`](./versioning-and-channels.md).

### 5.6 `signed-by=` → out-of-band anchor + `trusted-keys.d` roster

Both pin a per-source key. AOS pins a registry's Ed25519 public key in
`name:Ed25519:<base64>` format (parsed by `parse_signing_key`,
`crates/aos-package/src/security.rs:575`) into `trusted-keys.d/<registry>.pub`.
Where APT's `signed-by=` names a static keyring file, AOS goes further: the
anchor is delivered **out-of-band** (baked into the image by `aos.apm.registries`,
or `apr trust pin` — no silent trust-on-first-use), and from it the committed
`keys.toml` roster lets the trusted set rotate **in-band** across multiple
maintainer keys. Verification runs `git verify-tag` / `git verify-commit` against
a temporary `allowed_signers` built from the whole trusted set
(`crates/aos-package/src/security.rs:455`,`:490`).

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
(design-brief §12). The AOS layer (`/channels` partitions, thin deltas) is purely
additive and invisible to stock git.

> Edge: sha256 over dumb HTTP requires a client git that supports sha256 (the
> dumb protocol has no capability negotiation). This is the one new compatibility
> constraint the substrate introduces (design-brief §12, §16).

### 6.3 Atomic refs (torn-publish safety without `by-hash` bookkeeping)

APT added `by-hash/SHA256/<h>` *specifically* so a client reading `Release@T`
still resolves a consistent index set if `Release@T+1` lands mid-fetch. In AOS
this is **intrinsic**: objects are immutable and content-addressed, and a publish
is an **atomic ref flip**. A client that resolved a partition/releases tag reads
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
serve a **Nix NAR binary cache** — `nix-cache-info` / `<storehash>.narinfo` /
`nar/` — so stock `nix` dev-shell substitution works as a strict superset. The
substituter location is **not** advertised in signed tags; it lives in the
committed repo-root `registry.toml` `[[caches]]` (a tree file authenticated
transitively by the signed tag), with the consumer's client-side `registries.d`
as an optional override (or the origin itself).
A separate cache-role Ed25519 key signs narinfos in production. See
[`nix-cache-compatibility.md`](./nix-cache-compatibility.md) and design-brief §13.

---

## 7. Where AOS keeps APT's lineage verbatim

| Capability | APT | AOS (git-native) equivalent | Verdict |
|---|---|---|---|
| Signed static-file index over dumb HTTP | `InRelease` + dumb HTTP | signed tag object + `info/refs`/`HEAD` over dumb HTTP | **parity (kept)** |
| Content-addressed pool | `pool/` (content-organized) + `Packages` `SHA256` | `/objects/<xx>/<62-hex>` (content-*addressed*) | **AOS ahead** |
| Incremental index updates | `Packages.diff` (pdiff) | thin `delta-*.pack` graph | **AOS ahead** (DAG, not one text file) |
| Concurrent-publish consistency | `by-hash/SHA256/<h>` | immutable objects + atomic ref flip | **AOS ahead** (intrinsic) |
| Time-based freshness | `Valid-Until` (in-band signed expiry) | AOS-TUF `timestamp.json` plus channel max-staleness and anti-rollback floor | **parity for release metadata; extra channel policy for rollout pointers** |
| Per-source key pinning | `signed-by=` | out-of-band anchor in `trusted-keys.d/<registry>.pub` + `keys.toml` roster | **AOS ahead** (in-band rotation) |
| Reproducible snapshots | `snapshot.debian.org` | immutable signed tags | **AOS ahead** (no extra service) |
| Phased rollout | `Phased-Update-Percentage` | 256 signed partition tags | **AOS ahead** (explicit cohorts) |

---

## 8. Where AOS deliberately drops APT mechanisms

These are **not** re-added to the target (design-brief §15):

- **Regenerated flat `Packages` / `Release` text.** The git tree *is* the index;
  there is nothing to regenerate or to tear during an rsync.
- **OpenPGP/GPG.** Ed25519 role keys replace it: registry and channel roles use
  SSH signature form, while a separate cache role signs narinfo.
- **`Depends` SAT solver.** AOS records explicit, pre-computed dependency
  closures — exact, reproducible, already authenticated — so there is no
  install-time solver.
- **`Components` (`main`/`contrib`/`non-free`).** No `[components]` table; a
  registry is one git repo partitioned by channel branches.
- **`Contents-<arch>` file index.** Out of scope for the registry layer.

---

## 9. CURRENT vs TARGET

The **TARGET** is everything above. Today's **CURRENT** code has moved onto the
git-native registry path:

- A registry is a git repo of nested package TOMLs (`PackageToml`,
  `crates/aos-package/src/registry/parse.rs:15`; written by `build_package_toml`,
  `crates/aos-package/src/registry_ops.rs:595`) plus the `store/` realisation graph
  files; `PackageMeta` (`crates/aos-package/src/types.rs:44`) is the flattened
  in-memory projection.
- HTTP and native git origins are synchronized by `registry::git::sync_git`;
  HTTP origins are treated as dumb-HTTP git repositories.
- Versions are semver tags for release/channel verification. Tracking modes are
  commit/branch/channel/tag/version (`TrackingMode`,
  `crates/aos-package/src/types.rs`).
- Channel rollout uses 256 signed partition tag objects, a persisted semver
  floor/bucket state, and `registry::fetch` delta/full/fallback object
  resolution.
- Signing uses SSH-format Ed25519 tag signatures, an out-of-band `trusted-keys.d`
  anchor (image-baked or pinned), and the committed `keys.toml` roster that
  clients pin in-band for rotation/revocation.
- `apr release` now orchestrates the producer-safe path: signed semver tag,
  full packs and compressed thin deltas, static index refresh, optional static
  cache generation, channel partition updates, and immutable-first static-origin
  upload.
- `apr cache generate` produces and optionally uploads the static Nix-cache
  surface (`nix-cache-info`, `<storehash>.narinfo`, and `nar/*.nar.zst`) and can
  commit the root `registry.toml` `[[caches]]` pointer.

---

## 10. Summary

```
                 APT                          AOS registry (git-native target)
        ┌─────────────────────┐        ┌────────────────────────────────────┐
root    │ InRelease (signed)  │   ≈    │ signed tag object (pure pointer)    │
        │  + Valid-Until      │        │  (no structured payload)            │
refs    │ Release/Release.gpg │   ≈    │ info/refs + HEAD (server-info)      │
sign    │ OpenPGP             │   →    │ Ed25519 (registry + cache roles)    │
index   │ Packages (flat text)│   ↑    │ git tree/blob objects               │ AOS ahead
deltas  │ pdiff               │   ↑    │ thin delta-*.pack (DAG)             │ AOS ahead
pool    │ pool/*.deb (org'd)  │   ↑    │ /objects/<xx>/<hex> (addressed)     │ AOS ahead
deps    │ Depends (solver)    │   ↑    │ explicit closures                   │ AOS ahead
consist │ by-hash             │   ↑    │ immutable objects + atomic ref flip │ AOS ahead
chan    │ suites/components   │   →    │ channels = branches (no components) │
rollout │ Phased-Update-%     │   ↑    │ 256 signed partition tags           │ AOS ahead
trust   │ signed-by=          │   ↑    │ anchor + trusted-keys.d/ roster     │
fresh   │ snapshot.debian.org │   ↑    │ immutable signed tags               │ AOS ahead
freshTTL│ Valid-Until         │   ↓    │ CDN TTL + consumer policy           │ APT ahead (in-band)
clone   │ APT-specific client │   ↑    │ stock `git clone` (dumb HTTP)       │ AOS ahead
        └─────────────────────┘        └────────────────────────────────────┘
   ≈ parity (kept)  ↑ AOS ahead  ↓ APT ahead  → re-mapped onto git
```

**Keep from APT:** signed static-file indices over dumb HTTP; a content-addressed
pool; the phased-rollout idea; per-source key pinning.
**Re-map onto git:** `InRelease`→signed tag object (a pure signed pointer);
`Packages`→git tree; `pool`→object store; pdiff→thin delta packs;
`Phased-Update-%`→256 partitions; `by-hash`→content-addressed objects.
**Drop:** regenerated flat `Packages`, OpenPGP, `Depends` solver, `Components`,
`Contents-<arch>`, rsync-mirror publish; APT's exact `Valid-Until` field is
replaced by AOS-TUF timestamp metadata plus channel freshness policy.

---

## See also

- [`README.md`](./README.md) — registry reference index and glossary.
- [`architecture.md`](./architecture.md) — git-repo-over-dumb-HTTP; superset of git and Nix.
- [`current-state.md`](./current-state.md) — the current git-native implementation status.
- [`http-layout.md`](./http-layout.md) — HTTP/object layout, object store, `info/alternates`, stock-git compat.
- [`versioning-and-channels.md`](./versioning-and-channels.md) — semver, channels-as-branches, 256-partition rollout.
- [`packs-and-deltas.md`](./packs-and-deltas.md) — libgit2 full packs, Rust thin packs, the delta scheme, zstd.
- [`signing-and-trust.md`](./signing-and-trust.md) — signed tag objects, name-binding, `tag→tag→commit`.
- [`publishing.md`](./publishing.md) — the producer pipeline and atomic publish ordering.
- [`nix-cache-compatibility.md`](./nix-cache-compatibility.md) — the Nix binary-cache superset.
- Plan: [`docs/plans/registry/design-brief.md`](../plans/registry/design-brief.md) §3–§12 (grounding),
  [`gap-analysis.md`](../plans/registry/gap-analysis.md),
  [`workstream-03-channels-rollouts.md`](../plans/registry/workstream-03-channels-rollouts.md).
