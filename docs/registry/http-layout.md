# HTTP / Object-Store Layout

> **Audience:** users, implementers, architects, engineers, doc-authoring agents.
> **Status:** Reference. Describes the **TARGET** on-the-wire layout for an AOS
> registry origin — a bare git repository (sha256) published as static files over
> dumb HTTP — and contrasts it against the **CURRENT** bundle-based layout in code.
>
> The authoritative grounding for this document is the design brief
> ([`docs/plans/registry/design-brief.md`](../plans/registry/design-brief.md)),
> sections §4 (HTTP / object layout & CDN cache policy), §8 (object store &
> dumb-HTTP details), and §12 (stock git dumb-HTTP compatibility).

---

## 1. Scope & sibling documents

This document is the canonical description of *what bytes live at what URLs* on an
AOS registry origin, and *how a CDN must cache each path*. It deliberately does
**not** re-derive the ref/trust model, the rollout semantics, or the pack/delta
generation pipeline — those live in siblings:

| Concern | Document |
|---|---|
| Big-picture architecture, three ref layers, asymmetric cost | [`architecture.md`](architecture.md) |
| As-is code (bundles, `creation_token`, `bundle-list.toml`) | [`current-state.md`](current-state.md) |
| **HTTP/object layout, CDN TTLs, dumb-HTTP shim (this doc)** | `http-layout.md` |
| Semver, channels-as-branches, 256-partition rollout, frontier | [`versioning-and-channels.md`](versioning-and-channels.md) |
| Pack-objects, thin vs full packs, delta graph, zstd | [`packs-and-deltas.md`](packs-and-deltas.md) |
| Signed tag objects, name-binding, `tag→tag→commit`, trust | [`signing-and-trust.md`](signing-and-trust.md) |
| The producer publish pipeline end-to-end | [`publishing.md`](publishing.md) |
| Nix binary-cache superset (client-side cache config, narinfo, `nar/`) | [`nix-cache-compatibility.md`](nix-cache-compatibility.md) |
| Comparison to APT/dpkg flat-file repositories | [`apt-comparison.md`](apt-comparison.md) |

Plan-side: [`docs/plans/registry/README.md`](../plans/registry/README.md),
[`design-brief.md`](../plans/registry/design-brief.md),
[`gap-analysis.md`](../plans/registry/gap-analysis.md),
[`workstream-01-object-store.md`](../plans/registry/workstream-01-object-store.md),
[`workstream-02-pack-delta-pipeline.md`](../plans/registry/workstream-02-pack-delta-pipeline.md),
[`workstream-03-channels-rollouts.md`](../plans/registry/workstream-03-channels-rollouts.md),
[`workstream-04-signing-trust.md`](../plans/registry/workstream-04-signing-trust.md),
[`workstream-05-consumer.md`](../plans/registry/workstream-05-consumer.md),
[`open-questions.md`](../plans/registry/open-questions.md).

---

## 2. CURRENT layout (as-is, code-grounded)

Today an AOS registry is *not* served as a bare git repo. Distribution is a set of
git **bundle** files plus a TOML manifest that the **consumer** parses. The on-the-
wire surface is:

```
{base_url}/
  bundles/
    {registry_name}/
      bundle-list.toml                         ← manifest the consumer fetches & parses
      {registry}-vYYYY.MM.bundle               ← snapshot bundles
      {registry}-vA..vB.delta.bundle           ← delta bundles (sequential & skip)
```

- The manifest URL is constructed as
  `{base_url}/bundles/{registry_name}/bundle-list.toml`
  (`crates/aos-package/src/registry/bundle.rs:105-109`).
- Each bundle is downloaded from
  `{base_url}/bundles/{registry}/{entry.uri}` and SHA-256-verified against the
  manifest entry (`bundle.rs:259-264`, `bundle.rs:276-277`), then validated with
  `git bundle verify` (`bundle.rs:326-331`) and applied with `git bundle unbundle`
  (`bundle.rs:376-392`).
- The manifest header carries `registry`, `version`, and an optional `generated`
  timestamp (`bundle.rs:66-73`); each `[[bundles]]` entry carries `tag`/`from_tag`/
  `to_tag`, `type` (`snapshot`/`delta`), `uri`, `creation_token`, `size`, `sha256`
  (`bundle.rs:75-92`).
- Ordering and selection are driven by an integer **`creation_token`** monotonic
  ordinal (`bundle.rs:170-171` sorts entries ascending; `entries_since`,
  `latest_snapshot`, `skip_delta_from`, `sequential_deltas_between` at
  `bundle.rs:181-224` are all `creation_token`-keyed).
- Delta classification is by counting dot-segments of a `vYYYY.MM[.P]` calendar tag:
  a 2-segment base → patch is a **skip** delta, patch → patch is **sequential**
  (`classify_delta` at `bundle.rs:238-243`).

Everything in this section is **removed** from the target (design-brief §15): no
`bundle-list.toml`, no git bundles, no `creation_token`, no calendar tags. See
[`current-state.md`](current-state.md) for the full as-is picture.

---

## 3. TARGET layout — the bare git repo over dumb HTTP

The registry origin is the working tree of a **bare git repository initialised with
`git init --object-format=sha256`**, served as plain static files. Stock git's
"dumb HTTP" transport reads exactly these paths; the AOS client reads the same
paths plus an additive `/channel` and per-release object layer.

```
/                                  ← bare git repo root (dumb HTTP)
  HEAD                             ← "ref: refs/heads/<default-channel>" (e.g. stable)   [low TTL]
  info/refs                        ← update-server-info: refs/heads/<channels> + refs/tags/<semvers> [low TTL]
  objects/
    info/packs                     ← lists self-contained pack-<sha>.pack ONLY           [low TTL]
    info/alternates                ← RELATIVE "../release/*/objects/" dirs, newest→oldest [low TTL]
                                       (pack discovery + the full release index)
    <xx>/<62-hex>                  ← ALL loose objects, sha256 2/62 split (dumb HTTP)     [immutable, high TTL]
  channel/
    <name>/                                                                              [low TTL]
      00 .. ff                     ← 256 SIGNED tag objects (tag name == <name>),
                                       each → a semver tag (rollout partitions)
  release/
    <major>/<minor>/<patch[-prerelease][+build]>/                                        [long TTL, immutable]
      objects/                               ← PACK-ONLY (no loose objects, no info/alternates)
        info/packs                           ← lists this release's full pack(s)
        pack/pack-<sha256>.pack (+ .idx)     ← self-contained "full" pack at X.Y.0 anchors
        pack/delta-<from-semver>.pack         ← THIN deltas; AOS-only; NOT listed in info/packs
```

Three properties hold by construction:

1. **It is a superset of git dumb HTTP.** A stock `git clone <url>` works: channels
   are branches, releases are tags, fetched from loose objects + conventionally-named
   full packs. See §7.
2. **It is a superset of the Nix binary cache.** The origin MAY additionally serve a
   `nix-cache-info` / `*.narinfo` / `nar/` surface (the superset for stock nix);
   narinfo signing reuses the one Ed25519 key. The substituter location is the
   *consumer's* client-side registry config (or the origin itself) — it is **not**
   advertised in signed tags. That surface is documented in
   [`nix-cache-compatibility.md`](nix-cache-compatibility.md); it is orthogonal to
   the git-object layout here.
3. **The AOS layer is additive.** `/channel/<name>/00..ff` and the thin
   `delta-*.pack`s ride alongside the standard git surface without conflicting (they
   are not git refs and are not listed in `info/packs`).

---

## 4. The object store

### 4.1 sha256, loose objects, and the 2/62 split

All git operations use the **sha256** object format
(`git init --object-format=sha256`, design-brief §8). A git object id is therefore a
64-hex-character string, and the loose-object path is the first **2** hex characters
as a directory and the remaining **62** as the filename:

```
objects/<xx>/<62-hex>
        └┬┘ └──┬───┘
         │     └─ remaining 62 hex chars of the sha256
         └─────── first 2 hex chars (fan-out directory)
```

Example: object `3a7f…` (64 chars) → `objects/3a/7f…` (the trailing 62 chars).

> **Contrast with the default sha1 format** (used by stock repos): sha1 ids are 40
> hex chars, split 2/38. AOS uses sha256 throughout, so every fan-out file name is
> 62 hex chars. A client git that does not understand sha256 cannot clone — see §7.5.

### 4.2 Completeness guarantee: every object exists loose

**Every object that any release needs exists as a loose object** under the single
root store `objects/<xx>/<…>`. All loose objects for every release are centralized
here; the per-release `release/<…>/objects/` dirs are **pack-only** and hold no loose
objects. This is the guaranteed-correctness fallback: a client that cannot or will not
use packs can always reconstruct any commit by walking the root loose store over plain
HTTP GETs. Packs (§4.4) are a pure efficiency layer *on top of* the loose store, never
a replacement for it.

### 4.3 Distributed pack store: per-release pack dirs + `info/alternates`

The **packs** are **split across one directory per release** so that an immutable
release's pack can be cached forever while the root store's index stays small and
churny. (All *loose* objects already live centralized at the root — §4.2; the
per-release dirs are pack-only.) The root store stitches the per-release pack stores
together into one logical store via a git **alternates** mechanism:

- `objects/info/alternates` lists **every** `release/<…>/objects/` directory, newest
  release first (design-brief §8). One **relative** path per line, each ending in
  `/objects/`. Git's fetcher (HTTP and local-FS) follows each entry as an additional
  object store, so pack discovery falls through to the per-release stores.
- This file **doubles as the full release index**: because it lists every release's
  object dir newest→oldest, reading it tells a client (or a human) the complete,
  ordered set of published releases without parsing refs.

The entries are **relative paths**, e.g. `../release/1/2/0/objects/`. Git resolves a
relative alternate against the repo's own `objects/` URL, and each `../` strips one
path segment — so `../` strips the `objects` segment to land at the repo root,
meaning the correct depth is **one** `../`. Because the entries bake in no hostname,
the file is **host-independent**: byte-identical across CDN, mirror, and localhost.

The dumb-HTTP walker reads `info/http-alternates` first and falls back to
`info/alternates`; because the relative form is valid for both HTTP and local-FS, a
single `info/alternates` serves every transport — no separate `http-alternates` file
is needed.

Because all loose objects are centralized at the root (§4.2), `info/alternates` now
serves **pack discovery and the release index**, *not* object completeness.

```
# objects/info/alternates  (newest release first, relative paths)
../release/1/2/0/objects/
../release/1/1/3/objects/
../release/1/1/2/objects/
../release/1/1/0/objects/
../release/1/0/0/objects/
```

Each per-release `objects/` directory has its own `info/packs` so that a release
subtree describes its own pack(s). Per-release dirs carry **no** `info/alternates`
(they are pack-only leaves; delta-base discovery is driven by the root index, not by
chained per-release alternates).

### 4.4 Packs: full vs thin

Two kinds of pack files live under each release's `objects/pack/`:

| Pack | Filename | Self-contained? | In `info/packs`? | Audience |
|---|---|---|---|---|
| **Full pack** | `pack-<sha256>.pack` (+ `.idx`) | yes | **yes** | stock git + AOS |
| **Thin delta pack** | `delta-<from-semver>.pack` (+ `.zst`) | no (references base) | **no** | AOS only |

- A **full pack** is emitted at every `X.Y.0` (major/minor) anchor release. It is
  self-contained, conventionally named `pack-<sha256>.pack` so stock dumb git
  recognises it, ships with an `.idx`, and **is** listed in `info/packs`.
- A **thin delta pack** carries only the objects introduced between two release
  commits and may reference the base release's objects. It is named
  `delta-<from-semver>.pack`, ships **without** an `.idx` (the client rebuilds it
  with `git index-pack --fix-thin`), and is **never** listed in `info/packs`
  (a stock dumb client cannot apply a thin pack). AOS clients discover delta packs
  by the `delta-<semver>` naming convention, not via `info/packs`.

The delta graph the producer guarantees, the `pack-objects`/zstd command details,
and client resolution/retention all live in
[`packs-and-deltas.md`](packs-and-deltas.md). The only layout fact that matters here:
**`info/packs` lists full packs only.**

### 4.5 `info/refs` and `HEAD`

`info/refs` and `HEAD` make the repo a valid dumb-HTTP bare repo (design-brief §8):

- `HEAD` is a symref text file: `ref: refs/heads/<default-channel>` (e.g.
  `ref: refs/heads/stable`). It selects what a bare `git clone` checks out and what
  branch a stock pull tracks.
- `info/refs` is the advertised ref list, regenerated by `git update-server-info`
  on **every publish**. It contains the channel branches (`refs/heads/<channel>`)
  and the release tags (`refs/tags/<semver>`). The 256 partition tag objects are
  **not** refs and do **not** appear here — they live at `/channel/*` (§5) outside
  the ref namespace.

```
# info/refs (sha256 ids; one ref per line, TAB-separated)
<commit-sha256>\trefs/heads/stable
<commit-sha256>\trefs/heads/testing
<tag-sha256>\trefs/tags/1.0.0
<tag-sha256>\trefs/tags/1.1.0
<tag-sha256>\trefs/tags/1.1.0^{}      ← peeled tag → commit
<tag-sha256>\trefs/tags/1.2.0
```

Because regenerating `info/refs`, `info/packs`, `info/alternates`, and `HEAD`
is exactly what `git update-server-info` (plus the AOS pack/alternates writers) does,
those paths are the *only* mutable-on-publish parts of the root tree and must be
low-TTL (§6).

---

## 5. The `/channel` partition layer (AOS-only)

`/channel/<name>/00` … `/channel/<name>/ff` are **256 signed git tag objects** served
as static files, *outside* the git ref namespace. Each file is a single annotated,
SSH-Ed25519-signed git tag object whose **tag-name field equals the channel name**
(`<name>`), pointing at a semver tag (which in turn points at a commit) — the
`tag → tag → commit` chain.

- There must always be exactly **256** files (`00`–`ff`); a consumer self-selects one
  bucket deterministically. The publisher advances buckets independently to control
  rollout. The full rollout/frontier/anti-rollback semantics live in
  [`versioning-and-channels.md`](versioning-and-channels.md); the trust chain and
  the name-binding check (signature valid **and** embedded tag-name == `<name>`) live
  in [`signing-and-trust.md`](signing-and-trust.md).
- These files are **layout, not refs**: they are not in `info/refs`, so a stock
  `git clone` never sees them. That is intentional — rollout is an AOS-fleet concept.
- They change frequently (every rollout advance), so `/channel/**` is **low TTL**
  (§6). Freshness comes from that low CDN TTL combined with the consumer's own
  max-staleness policy and the monotonic anti-rollback floor — there is **no in-band
  `valid_until`** in the tag (§6). The trade-off: this is weaker than an in-band
  signed expiry against a frozen-but-validly-signed mirror.

A single partition file is just the raw bytes of a git tag object; a client fetches
`/channel/stable/<bucket>`, verifies the signature and the name binding, follows the
embedded target semver, and resolves the release subtree under `/release/<…>/`.

---

## 6. CDN cache policy

The single most important operational property of this layout is that **what changes
on publish is small and segregated from what is immutable**. CDN TTLs follow directly
(design-brief §4):

| Path glob | TTL class | Rationale |
|---|---|---|
| `/channel/**` | **low (MUST)** | Rollout advances must propagate fast; partition tags repoint frequently. |
| `/HEAD`, `/info/refs` | **low (MUST)** | Rewritten by `update-server-info` on every publish. |
| `/objects/info/**` (`packs`, `alternates`) | **low (MUST)** | The pack list and release index change on every publish. |
| per-release `release/**/objects/info/packs` | **low (MUST)** | Same reason, scoped to a release subtree. |
| `/objects/<xx>/<…>` (root loose objects) | **immutable, high (MAY)** | A given object id is content-addressed and never changes. |
| `/release/**` everything else (loose objects, `pack/`) | **long, immutable (MAY)** | Releases are immutable once published. |

Two rules summarise it:

1. **Mutable-on-publish ⇒ low TTL.** The root index paths (`HEAD`, `info/refs`,
   `objects/info/packs`, `objects/info/alternates`) plus each release's
   `objects/info/packs` and the whole `/channel/**` tree.
2. **Content-addressed or immutable-by-contract ⇒ high TTL.** All loose objects (the
   id *is* the content hash) and everything under a published `/release/<…>/` subtree
   (releases never mutate).

This is the asymmetric-cost philosophy realised at the cache edge: publishing rewrites
a handful of low-TTL index files; the bulk of bytes (objects and packs) is immutable
and served from cache near-permanently.

The low CDN TTL on `/channel` (and `info/refs`, `objects/info`) is also the
**freshness mechanism**: there is no in-band signed `valid_until` (C). Freshness is
the low TTL plus the consumer's own max-staleness policy plus the monotonic
anti-rollback floor; the trade-off is that this is weaker than an in-band signed
expiry against a frozen-but-validly-signed mirror.

```
                 publish event
                      │
        ┌─────────────┴──────────────┐
        ▼                            ▼
  LOW TTL (rewritten)         HIGH TTL (immutable)
  HEAD                        objects/<xx>/<…>
  info/refs                   release/<…>/objects/pack/*
  objects/info/packs
  objects/info/alternates
  release/<…>/objects/info/packs
  channel/<name>/00..ff
```

---

## 7. Stock git dumb-HTTP compatibility

The repo is a **valid bare dumb-HTTP git repository**; the AOS layer is purely
additive. A stock `git clone <url>` and `git fetch` work with no AOS tooling
(design-brief §12).

### 7.1 The dumb-HTTP shim

To be transparently clonable, the origin serves the standard dumb-HTTP triad,
regenerated on every publish:

- **`HEAD`** — symref to the default channel branch (e.g.
  `ref: refs/heads/stable`). Determines the default checkout for `git clone`.
- **`info/refs`** — the advertised ref list from `git update-server-info`: channel
  branches and release tags (peeled).
- **`objects/info/alternates`** — the distributed pack store as relative paths, so
  git's fetcher (HTTP via `http-alternates` fallback, or local-FS) resolves
  per-release object dirs as one logical store (§4.3).

A stock client reads `HEAD` + `info/refs` to learn the refs, then fetches objects
from the root loose store and the full packs listed in `info/packs`, following
`info/alternates` into the per-release pack stores as needed.

### 7.2 Pack naming: `pack-<sha256>.pack`, no `full.pack`

The self-contained full pack is named **`pack-<sha256>.pack`** (+ `.idx`) and listed
in that **release's** `objects/info/packs`, discovered by the client following the
root `objects/info/alternates` into the per-release pack store — precisely what stock
dumb git expects. There is **no** separate semantic `full.pack` name — that alias is
dropped entirely so there is no duplicate file and no special-casing (design-brief §12).

### 7.3 Thin delta packs are invisible to stock git

Thin `delta-*.pack`s are **not** listed in `info/packs`. A stock dumb client cannot
apply a thin pack (it references objects it may not have indexed), so it must never
be told one exists. AOS clients find them by the `delta-<from-semver>` naming
convention and complete them with `git index-pack --fix-thin`. Result: thin packs
help AOS and are completely transparent to stock git.

### 7.4 Channels-as-branches, releases-as-tags, graceful degradation

- **Channels are branches** (`refs/heads/<channel>`); their head is the rollout
  **frontier** (the newest release any partition targets). A stock `git pull
  <channel>` therefore always gets the frontier — there is **no rollout protection
  for stock clients**, which is acceptable because rollout is an AOS-fleet concept
  (see [`versioning-and-channels.md`](versioning-and-channels.md)).
- **Releases are tags** (`refs/tags/<semver>`), each a signed annotated tag, so a
  stock user can `git verify-tag <semver>` even without AOS tooling — the release
  tags are the signed objects in the trust chain
  ([`signing-and-trust.md`](signing-and-trust.md)).
- **`HEAD` = the default channel** (e.g. `stable`); the 256 partition tag objects
  live outside the ref namespace at `/channel/*` and are AOS-only (§5).
- **Graceful degradation for patch releases:** a stock dumb clone of a *patch*
  release (which ships no full pack) pulls the minor-base full pack via
  `info/alternates` plus the patch's loose new objects from the root store — **no
  thin packs needed**.
- **Loose objects guarantee correctness** for any stock client; the
  conventionally-named full packs restore speed. Worst case, a client degrades to
  fetching loose objects one GET at a time, which is always correct (§4.2).

### 7.5 sha256 caveat

Dumb HTTP has **no capability negotiation** — there is no handshake in which the
server can advertise that it speaks sha256. Therefore a stock client *must* be a git
build that supports the sha256 object format, or the clone fails. This is a hard
requirement of the dumb protocol, not a choice; it is tracked as an open question to
validate against target git client versions (design-brief §16.1). There is no sha1
fallback served from the same origin.

---

## 8. Worked example: one origin, two releases, mid-rollout

A registry `aos-core` with releases `1.0.0` and `1.1.0` published, the `stable`
channel rolling `1.1.0` out to 4/256 of the fleet (buckets `00`–`03` advanced,
`04`–`ff` still on `1.0.0`):

```
/
  HEAD                                   "ref: refs/heads/stable"            [low]
  info/refs                              stable, testing, 1.0.0, 1.1.0       [low]
  objects/
    info/packs                           (root packs, if any)               [low]
    info/alternates                      ../release/1/1/0/objects/          [low]
                                         ../release/1/0/0/objects/
    a3/7f…                               (ALL loose objects, both releases) [high]
  channel/
    stable/
      00 → tag(name=stable) → 1.1.0       (advanced)                        [low]
      01 → tag(name=stable) → 1.1.0       (advanced)                        [low]
      02 → tag(name=stable) → 1.1.0       (advanced)                        [low]
      03 → tag(name=stable) → 1.1.0       (advanced)                        [low]
      04 → tag(name=stable) → 1.0.0       (held back)                       [low]
      …                                                                     [low]
      ff → tag(name=stable) → 1.0.0       (held back)                       [low]
  release/                               (PACK-ONLY — no loose, no alternates)
    1/0/0/objects/
      info/packs                         pack-<sha>.pack                    [low]
      pack/pack-<sha256>.pack (+ .idx)   self-contained full pack          [immutable]
    1/1/0/objects/
      info/packs                         pack-<sha>.pack                    [low]
      pack/pack-<sha256>.pack (+ .idx)   full pack at the 1.1.0 minor      [immutable]
      pack/delta-1.0.0.pack (+ .zst)     thin delta from 1.0.0 (AOS-only)  [immutable]
```

Reading the example:

- **Stock `git clone <url>`** checks out `stable` (= `1.1.0`, the frontier), pulls
  the `1.1.0` full pack from `release/1/1/0/objects/pack/`, ignores
  `delta-1.0.0.pack` (not in `info/packs`), and can `git verify-tag 1.1.0`.
- **An AOS host in bucket `b7`** fetches `/channel/stable/b7`, verifies it, sees it
  targets `1.0.0`, and stays on `1.0.0` — held back from the rollout.
- **An AOS host in bucket `01` already on `1.0.0`** fetches `/channel/stable/01`, sees
  `1.1.0`, and fetches the thin `delta-1.0.0.pack` (small) instead of a full pack,
  completing it with `git index-pack --fix-thin`.

A worked split of a prerelease/build version into its `/release/<…>/` path:
`1.0.0-beta+exp.sha.5114f85` → `/release/1/0/0-beta+exp.sha.5114f85/` (the third path
segment is everything after `major.minor`; design-brief §7).

---

## 9. Quick reference: paths, mutability, TTL

| Path | Contents | Mutable on publish? | TTL |
|---|---|---|---|
| `/HEAD` | symref → default channel branch | yes | low |
| `/info/refs` | channel branches + release tags | yes | low |
| `/objects/info/packs` | full packs only | yes | low |
| `/objects/info/alternates` | relative per-release object dirs, newest→oldest; pack discovery + release index | yes | low |
| `/objects/<xx>/<62-hex>` | ALL loose objects, every release (sha256) | no (content-addressed) | high |
| `/channel/<name>/00..ff` | 256 signed partition tag objects | yes | low |
| `/release/<M>/<m>/<patch…>/objects/info/packs` | per-release pack index | yes | low |
| `/release/<M>/<m>/<patch…>/objects/pack/pack-<sha>.pack(.idx)` | self-contained full pack (X.Y.0 anchors) | no | high |
| `/release/<M>/<m>/<patch…>/objects/pack/delta-<from>.pack(.zst)` | thin AOS-only delta | no | high |

---

## 10. CURRENT → TARGET summary

| Aspect | CURRENT (`bundle.rs`) | TARGET (this doc) |
|---|---|---|
| Transport unit | git **bundles** (`*.bundle`) | bare git repo, dumb HTTP static files |
| Manifest | `bundle-list.toml` parsed by consumer (`bundle.rs:124`) | none — refs + `info/alternates` + `/channel` |
| Object format | sha1 (git default in bundles) | **sha256** (`git init --object-format=sha256`) |
| Object store | opaque inside bundles | all loose `objects/<xx>/<62-hex>` at root + per-release pack dirs |
| Release index | `[[bundles]]` snapshot entries | `objects/info/alternates` (doubles as index) |
| Versioning | calendar `vYYYY.MM[.P]` + `creation_token` (`bundle.rs:238-243`) | semver, no `v` prefix |
| Deltas | `*.delta.bundle`, classified by segment count | thin `delta-<from-semver>.pack`, not in `info/packs` |
| Full snapshot | snapshot bundle | `pack-<sha256>.pack` at X.Y.0 anchors |
| Rollout | (none in layout) | 256 signed `/channel/<name>/00..ff` partition tags |
| Stock-git clone | not possible | `git clone <url>` works (sha256-capable client) |

The target removes (design-brief §15): `bundle-list.toml`, git bundles,
`creation_token` ordering, calendar versioning, and the by-hash `[[bundles]]`/
`[[deltas]]` index — replaced by the git object store + `info/alternates`.
