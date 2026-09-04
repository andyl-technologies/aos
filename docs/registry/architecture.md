# AOS Registry — Architecture

> **Audience:** implementers, architects, engineers.
> **Scope:** the **git-native** registry — a bare sha256 git repository published
> as static files over **dumb HTTP**, which is simultaneously a *superset of git
> dumb HTTP* and a *superset of the Nix binary cache*. This page covers the three
> ref layers (`HEAD` / channels-as-branches / semver tags), how both `apm` and a
> stock `git clone` consume the same origin, and the asymmetric-cost
> (expensive-producer) philosophy that ties the design together.
>
> This document draws on the [design brief](../plans/registry/design-brief.md)
> §3–§5. Behavior that exists today is cited as `path:line` and labeled
> **CURRENT**; the intended end state is labeled **TARGET**. The full as-is
> implementation lives in [`current-state.md`](./current-state.md); the migration
> path is in [`gap-analysis.md`](../plans/registry/gap-analysis.md).

---

## 1. One-paragraph mental model

**TARGET.** An AOS registry is a **bare git repository in sha256 object format,
published as plain static files over dumb HTTP**. The package metadata *is* the
git tree content; there is no separate index file and no smart git server. Because
it is laid out as a valid dumb-HTTP bare repo, a stock `git clone <url>` works
unmodified — **channels are branches**, **releases are signed semver tags**, and
`HEAD` symlinks the default channel. On top of that same byte surface, the origin
*may also* advertise itself as a **Nix binary cache** (`nix-cache-info` /
`*.narinfo` / `nar/`) so a stock `nix` substituter can pull the same artifacts.
The AOS client (`apm`) layers two extra, *additive* surfaces that ride alongside
without conflict: signed **`/channels/<name>/00..ff`** partition tags for bucketed
rollout, and **thin `delta-*.pack`s** for cheap incremental fetch. The current
tools accept active registry Ed25519 keys for release and channel tags;
canonical production assigns those authorities separate role- and
channel-scoped keys. The governing design principle is **asymmetric cost: make
publishing as expensive as possible so that consumption is as cheap as
possible** — the producer pays once, every consumer benefits forever.

> **CURRENT.** The registry now uses sha256 git repositories, dumb-HTTP index
> refreshes, signed release/channel tag objects, channel partition commands, and
> git-native consumer sync. The package-TOML tree content remains the metadata
> layer. The consumer includes AOS delta/full/fallback object resolution, and
> `apr cache generate` produces the static Nix-cache layer. See
> [`current-state.md`](./current-state.md).

---

## 2. What "git-native, served as static files" means

The registry is produced as a **bare sha256 git repository** and uploaded as-is to
any static host. No CGI, no `git-upload-pack`, no `git-http-backend` — git's
**dumb HTTP** transport is pure `GET` against a known directory tree.

```
  git init --object-format=sha256 --bare
  …populate refs, objects, packs…
  git update-server-info            ← regenerates info/refs + objects/info/packs
  upload the tree to S3 / CDN / nginx root / `python -m http.server`
```

A client (stock git or AOS) needs only:

| File | Role |
|---|---|
| `HEAD` | symref naming the default channel branch |
| `info/refs` | the flat ref advertisement (branches + tags), from `update-server-info` |
| `objects/info/packs` | the list of self-contained packs to consider |
| `objects/info/alternates` | relative chain of per-release **pack** stores to follow (one `../` per entry) |
| `objects/<xx>/<62-hex>` | loose objects, sha256 `2/62` split — centralized at the **root** `/objects/`, the completeness fallback |

Because **all objects also exist loose**, a dumb client can always reconstruct any
ref by walking loose objects alone; packs and deltas are an efficiency layer *on
top of* a guaranteed-correct baseline. The full wire layout and CDN TTL policy live
in [`http-layout.md`](./http-layout.md).

### 2.1 Two supersets over one byte surface

```
                      ┌──────────────────────────────────────────────┐
                      │   ONE STATIC ORIGIN  /  (bare sha256 git repo)│
                      │                                              │
  git clone ─────────▶│  GIT DUMB-HTTP SURFACE  (lowest common       │
  (stock, unmodified) │    HEAD · info/refs · objects/…             │  ◀── superset #1
                      │    refs/heads/<channel> · refs/tags/<semver> │
                      │                                              │
  nix substituter ───▶│  NIX BINARY-CACHE SURFACE  (optional, ⊇)     │  ◀── superset #2
  (stock)             │    nix-cache-info · <storehash>.narinfo      │
                      │    nar/<…>  (registry.toml [[caches]])       │
                      │                                              │
  apm (AOS) ─────────▶│  AOS-ONLY ADDITIONS  (additive, ⊇)           │  ◀── apm's extra reach
                      │    channels/<name>/00..ff (signed partitions) │
                      │    releases/…/delta-<semver>.pack  (thin)     │
                      └──────────────────────────────────────────────┘
```

The registry is a **strict superset** of git dumb HTTP (superset #1) and *may also*
be a strict superset of the Nix binary cache (superset #2). Neither superset claims
a path the other needs; the AOS-only additions ride in disjoint namespaces
(`/channels/**`, `delta-*.pack`) that stock clients simply never request. See
[`nix-cache-compatibility.md`](./nix-cache-compatibility.md) for the Nix surface.

---

## 3. The three ref layers

The defining structure of the target is a **three-layer ref model**. Every release
and every rollout decision is expressed as a git ref or a signed git tag object —
there is no out-of-band index. (Brief §5.)

```
  ┌─ LAYER A · HEAD ───────────────────────────────────────────────────────────┐
  │  HEAD  →  ref: refs/heads/<default-channel>        (e.g. stable)            │
  │  unsigned symref; what a bare `git clone` checks out                        │
  └────────────────────────────────────┬───────────────────────────────────────┘
                                        │
  ┌─ LAYER B · CHANNELS AS BRANCHES ────▼───────────────────────────────────────┐
  │  refs/heads/<channel>  →  commit of the FRONTIER release                     │
  │  unsigned convenience pointer; head = newest release ANY partition targets   │
  └────────────────────────────────────┬───────────────────────────────────────┘
                                        │
  ┌─ LAYER C · SIGNED SEMVER TAGS ──────▼───────────────────────────────────────┐
  │  refs/tags/<semver>  →  (signed annotated tag)  →  release commit            │
  │  Ed25519-signed; stock git can `git verify-tag <semver>`                     │
  └────────────────────────────────────▲───────────────────────────────────────┘
                                        │  AOS rollout overlay (outside ref ns)
  ┌─ /channels/<name>/00..ff ────────────┴───────────────────────────────────────┐
  │  256 SIGNED partition tag objects (tag name == channel) → a semver tag       │
  │  AOS-only; the bucketed-rollout selector                                     │
  └─────────────────────────────────────────────────────────────────────────────┘
```

| Path / ref | What | Signed? | Consumed by |
|---|---|---|---|
| `HEAD` | symref → `refs/heads/<default-channel>` | no | stock git + AOS |
| `refs/heads/<channel>` | channels-as-branches; head = **frontier** (newest release any partition targets) | no (ref pointer) | stock git convenience |
| `refs/tags/<semver>` | release: signed tag → commit | **yes** | stock (`verify-tag`) + AOS |
| `/channels/<name>/<00..ff>` | 256 signed partition tag objects (name == channel) → semver tag | **yes** | AOS rollout only |

### 3.1 Layer A — `HEAD`

`HEAD` is a plain symref, `ref: refs/heads/<default-channel>` (e.g. `stable`). It
is what an unadorned `git clone <url>` checks out and the default a consumer
follows when no channel is named. Low CDN TTL (it moves when the default channel
changes). Unsigned — it is a pointer, not a trust anchor.

### 3.2 Layer B — channels as branches (the frontier)

A **channel** is a named release line modeled as a git branch
`refs/heads/<channel>`. Its head always points at the **frontier**: the commit of
the *newest release any of the channel's 256 partitions currently targets* — the
rollout target, not necessarily what every host runs.

The implication is deliberate: a stock `git pull <channel>` always gets the
frontier with **no rollout protection**, which is acceptable because *rollout is an
AOS-fleet concept, not a git-clone concept*. Branch refs are **unsigned convenience
pointers** and are never part of the trust chain. Channel branches and the
`/channels/**` partition tags are low TTL so rollout changes propagate fast. See
[`versioning-and-channels.md`](./versioning-and-channels.md).

### 3.3 Layer C — signed semver tags

A **release** is a standard semver (no `v` prefix: `1.1.2`, `1.1.0-alpha.1`,
`1.0.0-beta+exp.sha.5114f85`) published as a signed annotated tag
`refs/tags/<semver>` → commit. A signed tag is a **pure signed pointer**: the
standard git tag fields (object, type, the tag name, tagger) plus an SSH-format
**Ed25519** signature and an *optional* freeform human message — no structured
TOML payload, no embedded cache or freshness metadata. Releases are **immutable**
once published (long CDN TTL). A stock-git user can authenticate any release with
`git verify-tag <semver>` against the registry's public key — the signed release
tags *are* the trust anchor for stock clients. See
[`signing-and-trust.md`](./signing-and-trust.md).

**Registry-level config lives in the committed tree, not in the tag.** Because the
tag is a pure pointer, anything a consumer needs *about* the registry —
the NAR cache pointers (`registry.toml` `[[caches]]`) and the signing-key trust
roster (`keys.toml`: active key(s) + revoked list) — lives as **committed files in
the git tree** and is authenticated *transitively* by the signed tag: the chain
runs **tag → commit → tree → file** (extending the verification hops below). A key
inside a file authenticated by that key would be circular for bootstrap, so the
signing pubkey is *not* in `registry.toml`; bootstrap trust is an **out-of-band
anchor** — baked into the AOS image by `aos.apm.registries`
(`trusted-keys.d/<registry>.pub`) or pinned with `apr trust pin`, never a silent
trust-on-first-use. From that anchor the committed `keys.toml` roster is the
authoritative trusted-key set that clients pin on sync, with rotation and
revocation published as new signed `keys.toml` versions and reaching machines
in-band. The committed
tree is therefore `registry.toml` + `keys.toml` + `packages/<x>/<name>.toml` +
`store/` realisation graph, distinct from the served object store. See
[`repo-layout.md`](./repo-layout.md) for the full tree and the tree ↔ HTTP mapping.

### 3.4 The rollout overlay — `/channels/<name>/00..ff`

Outside the ref namespace, each channel exposes exactly **256** files
`/channels/<name>/00..ff`, each an independently-signed tag object whose **tag name ==
the channel name**, pointing at a semver tag. These are the **rollout partitions**:
a consumer self-selects one bucket on first channel sync from a registry-local
random salt, persists that bucket index once so it never flaps, and the publisher
advances buckets independently to control fleet exposure. They live outside
`refs/` precisely so a stock git client never sees them. Detailed in
[`versioning-and-channels.md`](./versioning-and-channels.md).

### 3.5 The trust chain and name-binding

AOS verification walks **signed partition tag → signed semver tag → commit**,
checking at each hop both that the SSH-Ed25519 signature is valid **and** that the
tag object's embedded **tag-name field equals the name expected for its serving
path**:

- under `/channels/<name>/<n>`, the partition tag's name must be `<name>`;
- under `/releases/.../` the semver tag's name must be that semver.

This **name-binding** check binds a tag object to the path it is served from and
prevents a cross-serving attack (replaying a validly-signed tag at the wrong URL).
Once the chain reaches the **commit**, every file in its **tree** — including the
registry-level config (`registry.toml` `[[caches]]`) and the `keys.toml` trust
roster — is authenticated by extension (**tag → commit → tree → file**), so no
config or cache pointer ever needs to ride *in* the tag. Branch refs carry no
signature and are never trusted; their only job is stock-git convenience. Full
detail and the threat model are in [`signing-and-trust.md`](./signing-and-trust.md);
the committed tree layout is in [`repo-layout.md`](./repo-layout.md).

---

## 4. How both consumers read one origin

### 4.1 Stock `git clone` (superset #1)

```
  git clone <url>                       # checks out HEAD's channel = frontier
  git clone --branch testing <url>      # checks out a specific channel branch
  git clone --branch 1.2.0 <url>        # checks out a specific release tag
  git verify-tag 1.2.0                   # authenticates the release (Ed25519)
```

The dumb fetcher reads `info/refs` and `HEAD`, then resolves objects via
`objects/info/packs` and `objects/info/alternates` — a host-independent file of
**relative** `../releases/<M>/<m>/<patch…>/objects/` entries (one `../` per entry,
which strips the `objects` segment to reach the repo root), newest→oldest. The dumb
walker reads `http-alternates` then falls back to `alternates`, so the one relative
file serves HTTP and local-FS alike. Because all loose objects are centralized at the
root `/objects/`, alternates now serve **pack discovery + the release index**, not
object completeness. Conventionally-named **full packs** (`pack-<sha256>.pack` +
`.idx`, listed in `info/packs`) restore speed; **loose objects** guarantee
correctness even if no pack helps. AOS clients regenerate pack indexes locally
rather than trusting server `.idx` files. A stock client never touches
`/channels/**` or any `delta-*.pack.zst` (thin deltas are deliberately *not*
listed in `info/packs`, since a dumb client cannot apply a thin pack). sha256 +
dumb HTTP requires a git client that supports the sha256 object format (the dumb
protocol has no capability
negotiation). See [`http-layout.md`](./http-layout.md) §"stock git compatibility".

### 4.2 `apm` (the AOS package manager)

`apm` consumes the *same* origin but uses the rollout overlay and thin deltas for
efficiency. End to end (TARGET):

```
  apm update / upgrade:
    1. bucket    b = persisted bucket, or first-sync registry-local salt hash
    2. channel   GET /channels/<channel>/<b>               → signed partition tag
                 verify sig + name-binding (name == <channel>)
    3. semver    follow partition tag → refs/tags/<semver> (signed)
                 verify sig + name-binding (name == <semver>)
    4. anti-rollback: reject if <semver> below the monotonic floor
    5. resolve   walk delta graph C→T (current→target):
                   prefer delta-<B>.pack.zst whose base B is retained;
                   else walk releases back to a usable delta / full pack;
                   else full pack; else loose objects over dumb HTTP
    6. fetch     GET .../pack/delta-<…>.pack.zst (or full pack / loose)
                 zstd -d, then local libgit2 pack indexing
    7. checkout  read package TOMLs from the materialized tree
```

The delta scheme, client retention, and zstd handling are specified in
[`packs-and-deltas.md`](./packs-and-deltas.md); rollout, bucket selection, and
anti-rollback in [`versioning-and-channels.md`](./versioning-and-channels.md).

### 4.3 Stock `nix` (superset #2, optional)

Orthogonal to the git-object layer, the NAR binary-cache location lives in the
committed repo-root `registry.toml` `[[caches]]` (a tree file authenticated
transitively by the signed tag), with the consumer's client-side `registries.d`
as an optional override (or the origin itself) — it is *not* advertised in any
signed tag. The origin **may** serve the
`nix-cache-info` / `<storehash>.narinfo` / `nar/` surface, a strict superset for
stock `nix` dev-shell substitution; a separate cache-role Ed25519 key signs
narinfo in production. The AOS-namespace and git-object surfaces are untouched and
invisible to `nix`. See [`nix-cache-compatibility.md`](./nix-cache-compatibility.md).

---

## 5. The asymmetric-cost (expensive-producer) philosophy

> **Make publishing as expensive as possible so that consumption is as cheap as
> possible.** The producer pays a large, one-time cost per release; every consumer,
> forever, reaps a cheap fetch. (Brief §3.)

This single principle explains most of the non-obvious design choices:

| Producer pays (once) | Consumer saves (forever) |
|---|---|
| libgit2 full-pack generation plus `.idx` emission | stock dumb Git gets conventional pack acceleration |
| Rust thinpack generation with bounded delta-base search | smaller incremental packs → less bytes transferred |
| Stored-entry thin packs then `zstd --ultra -22 --long=27` | far smaller thin-delta transport while the decompressed pack stays git-valid |
| Emitting a **guaranteed, walkable delta graph** (full pack at every `X.Y.0`; deltas to last major/minor/patches) | consumers can *plan* a minimal fetch without probing |
| Materializing **all objects loose** + conventionally-named full packs | any client (even stock dumb git) is always correct |
| Trying multiple delta bases and shipping the smallest | best-case incremental size with no consumer effort |

Two design knobs remain *explicitly asymmetric*: the producer can spend more CPU
searching for better thin-pack encodings, but it should not create deep chains
that shift reconstruction cost onto *every consumer*. The zstd trick follows the
same logic for thin deltas: the producer emits a stored-entry, delta-encoded pack
and lets zstd do entropy coding over the whole stream. All of this is detailed in
[`packs-and-deltas.md`](./packs-and-deltas.md) and [`publishing.md`](./publishing.md).

---

## 6. How the pieces fit together (end to end)

### 6.1 Publish (producer) — TARGET ordering

The safe publish order writes immutable objects first and flips refs last, so a
reader never sees a torn state:

```
  1. commit       apr stages package TOMLs/closures → release commit
  2. tag/sign     refs/tags/<semver>  (annotated, Ed25519, pure signed pointer)
  3. objects      write loose objects to the ROOT /objects/<xx>/<62hex>
  4. pack/delta   per-release pack-only /releases/*/objects/pack/: full pack + .idx at X.Y.0;
                  thin delta-<from>.pack.zst per the delta scheme
                  stored-entry thin pack  →  zstd --ultra -22 --long=27
  5. index        git update-server-info  (regenerate info/refs, objects/info/packs)
                  write objects/info/alternates (relative ../releases/*/objects, new→old)
  6. partitions   advance N of /channels/<name>/00..ff to the new semver tag (signed)
  7. upload       immutable /releases/** first;  /channels/** + info/** flipped last
```

Releases under `/releases/**` are immutable (long TTL) and uploaded before any ref
or partition that references them; `/channels/**` and the `info/**` shims are low TTL
and flipped last. Full producer workflow, atomicity, and concurrency are in
[`publishing.md`](./publishing.md).

> **CURRENT.** `apr release` now sequences the producer-safe order above. It can
> publish a real store path first or release an already committed registry tree,
> signs the semver tag, generates full packs and compressed thin deltas, refreshes
> dumb-HTTP indexes, optionally generates static Nix-cache files, advances channel
> partitions, and uploads immutable files before low-TTL mutable refs/channels.
> The focused `apr publish`, `apr tag`, `apr channel`, `apr cache`, and
> `apr origin` subcommands remain available for repair and unusual workflows.

### 6.2 Rollout (publisher-controlled, fix-forward)

To roll a new release to *N*/256 of the fleet, point *N* partitions at the new
semver tag and leave the rest on the prior release; this answers "where does the
rest of the fleet go" explicitly — the un-advanced partitions still name the prior
release. Advance partitions as confidence grows; completion = all 256 point at the
new release. Aborting a bad rollout is **fix-forward** (publish a newer release and
point partitions at it), never partition-decrement — the consumer's monotonic floor
would block a decrement anyway. See
[`versioning-and-channels.md`](./versioning-and-channels.md).

### 6.3 Anti-rollback at the architectural level

| Threat | Defense |
|---|---|
| Tamper / MITM | signed semver + partition tags pin every object by sha256; loose-object Merkle DAG |
| Cross-serving a valid tag at the wrong path | **name-binding**: embedded tag name must equal the serving path's expected name |
| Rollback to an older release | consumer **monotonic floor** (never moves below current release) |
| Stale / frozen mirror | AOS-TUF `timestamp.json` gives signed expiry over release metadata; **low CDN TTL** on `/channels` (and `info/refs`, `objects/info`) + consumer **max-staleness** + the monotonic anti-rollback floor bound rollout pointers |

Full threat model in [`signing-and-trust.md`](./signing-and-trust.md).

---

## 7. Cross-references

- [`README.md`](./README.md) — purpose, audience, glossary, doc index.
- [`current-state.md`](./current-state.md) — current git-native implementation
  status and external validation gaps.
- [`http-layout.md`](./http-layout.md) — full HTTP/object layout, CDN TTLs,
  `info/refs` / `HEAD` / relative `info/alternates`, root-centralized loose
  `/objects/`, stock-git dumb-HTTP compatibility.
- [`repo-layout.md`](./repo-layout.md) — the committed git **tree** content
  (`registry.toml` `[[caches]]`, `keys.toml` trust roster, `packages/`, the
  `store/` realisation graph), authenticated via the signed tag (tag → commit → tree → file),
  and the tree ↔ HTTP mapping.
- [`versioning-and-channels.md`](./versioning-and-channels.md) — semver,
  channels-as-branches, frontier head, the 256-partition rollout, bucket selection,
  anti-rollback.
- [`packs-and-deltas.md`](./packs-and-deltas.md) — libgit2 full packs, Rust
  thin packs, the delta graph, client resolution + retention, zstd.
- [`signing-and-trust.md`](./signing-and-trust.md) — signed tag objects as pure
  signed pointers, name-binding, `tag→tag→commit`, sha256, unsigned branch refs.
- [`publishing.md`](./publishing.md) — the producer pipeline end to end.
- [`nix-cache-compatibility.md`](./nix-cache-compatibility.md) — the Nix
  binary-cache superset located via the committed `registry.toml` `[[caches]]`
  (client-side `registries.d` as optional override).
- [`apt-comparison.md`](./apt-comparison.md) — git-native + dumb-HTTP vs. APT's
  signed-flat-file / `pool` / phased-rollout lineage.
- Plan set: [`design-brief.md`](../plans/registry/design-brief.md) (grounding
  intent), [`gap-analysis.md`](../plans/registry/gap-analysis.md),
  [`workstream-01-object-store.md`](../plans/registry/workstream-01-object-store.md),
  [`workstream-02-pack-delta-pipeline.md`](../plans/registry/workstream-02-pack-delta-pipeline.md),
  [`workstream-03-channels-rollouts.md`](../plans/registry/workstream-03-channels-rollouts.md),
  [`workstream-04-signing-trust.md`](../plans/registry/workstream-04-signing-trust.md),
  [`workstream-05-consumer.md`](../plans/registry/workstream-05-consumer.md),
  [`open-questions.md`](../plans/registry/open-questions.md).
