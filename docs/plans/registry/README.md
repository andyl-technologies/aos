# AOS Registry — Implementation Plan

> **Status:** Plan overview. This is the entry point for the registry
> implementation effort. It summarizes the **target state** (a **git-native
> registry served over dumb HTTP**), maps the **pre-cutover gaps** between the
> original code and that target, and sequences the work into five workstreams. It
> does **not**
> restate design rationale — that lives in the
> [design brief](./design-brief.md), which is the authoritative source of intent
> for every doc in this set.
>
> **Audience:** users, implementers, architects, and engineers.
>
> **Reading order:** start here, read the [design brief](./design-brief.md) in
> full, skim the [gap analysis](./gap-analysis.md), then dive into the
> workstream you own.

> **As-built status note:** the local implementation work described by this plan
> has landed. Treat the workstream documents and old `path:line` citations below
> as archival planning context, not as the live source of current code facts. For
> the implemented registry surface, start with
> [`../../registry/current-state.md`](../../registry/current-state.md) and
> [`TODO.md`](./TODO.md). External infra, fleet, and target-host validation is
> tracked for the follow-up PR in
> [`validation-runbook.md`](./validation-runbook.md).
>
> **Superseding security policy:** references in this archival plan to reusing
> one Ed25519 key for registry tags and narinfo predate RFC-0017. Production
> publication uses separate registry and cache signing roles; current policy is
> documented in
> [`../../maintainers/trust-model.md`](../../maintainers/trust-model.md).

---

## 1. What this plan is

The AOS package registry already has a **rich consumer** (`apm update` /
`apm upgrade`: semver tracking, signature verification, incremental fetch) and a
**thin producer** (`apr` is little more than `git` plus `git bundle create`).
This plan closes that asymmetry and lifts the registry to the **target design**
captured in the [design brief §3](./design-brief.md).

The target is a **bare git repository (sha256 object format) published as static
files over dumb HTTP**. The package metadata *is* the git tree content. That one
artifact is simultaneously:

- a **superset of git dumb HTTP** — a stock `git clone <url>` works (channels are
  branches, releases are tags), using loose objects plus conventionally-named
  full packs; and
- a **superset of the Nix binary cache** — the origin **MAY** serve
  `nix-cache-info` + `<storehash>.narinfo` + `nar/`, so the same origin doubles as
  a NAR substituter. The substituter location lives in the committed repo-root
  `registry.toml` `[[caches]]` (a tree file authenticated transitively by the
  signed tag), with the consumer's client-side `registries.d` as an optional
  override/supplement — it is **not** advertised in the signed tag itself.

On top of that standard surface the AOS client uses two AOS-only conventions that
ride *alongside* git without conflicting: the `/channels/<name>/00..ff` **signed
partition tags** (bucketed rollout) and the thin `delta-<from-semver>.pack`s
(cheap incremental fetch).

Design philosophy: **make publishing as expensive as possible so consumption is
as cheap as possible** — asymmetric cost. The producer pays once (large delta
windows, multi-base trials, `zstd --ultra`); every consumer benefits.

> **Historical CURRENT vs TARGET labeling.** In the original plan, *as-is* code
> behavior was labeled **CURRENT** and cited as `path:line`; the design goal was
> labeled **TARGET**. Those CURRENT citations describe the pre-cutover tree at the
> time the plan was written. Use the code, `docs/registry/current-state.md`, and
> this plan's `TODO.md` for present-day status.

---

## 2. Target-state summary

One bare git repo (sha256) is served as static files from a dumb-HTTP origin.
Two consumers read disjoint slices of it; one signing key authenticates the
whole thing.

```
                        ┌─────────────────────────────────────────────┐
                        │           Registry HTTP origin              │
                        │  bare git repo, sha256, served as static    │
                        │  files (dumb HTTP) — superset of git AND Nix│
                        └─────────────────────────────────────────────┘
                                          │
        ┌─────────────────────────────────┼─────────────────────────────────┐
        │                                 │                                 │
  stock `git clone`               AOS client (`apm`)               stock `nix` substituter
        │                                 │                                 │
  HEAD → refs/heads/<default>      /channels/<name>/00..ff           registry.toml [[caches]]
  refs/heads/<channel>  (branch)     256 signed partition tags        nix-cache-info
  refs/tags/<semver>    (tag)      bucket → channel tag → semver      <storehash>.narinfo (Sig:)
  loose objects + full packs         tag → commit (name-bound)        nar/<…> (content-addressed)
                                   thin delta-<from>.pack[.zst]
        └─────────────────────────────────┼─────────────────────────────────┘
                                          │
        ┌─────────────────────────────────┴─────────────────────────────────┐
        │  Trust root: ONE Ed25519 key (SSH-format git signatures)           │
        │   • signs release tags (refs/tags/<semver> → commit)               │
        │   • signs the 256 channel partition tags (/channels/<name>/00..ff) │
        │   • may reuse for narinfo Sig: if the origin also serves NARs       │
        └─────────────────────────────────────────────────────────────────────┘
```

### The three ref layers

From [design brief §5](./design-brief.md):

| Path / ref | What | Signed? | Consumer |
|---|---|---|---|
| `HEAD` | symref → `refs/heads/<default-channel>` (e.g. `stable`) | no | stock + AOS |
| `refs/heads/<channel>` | **channels are branches**; head = **frontier** (newest release any partition targets) | no (ref pointer) | stock git convenience |
| `refs/tags/<semver>` | release: signed tag → commit | **yes** | stock (`verify-tag`) + AOS |
| `/channels/<name>/<00..ff>` | **256 signed partition tag objects** (tag name == channel) → semver tag | **yes** | AOS rollout only |

**Trust chain (name-bound):** AOS verifies `signed partition tag → signed semver
tag → commit`, checking both the signature **and** the embedded tag-name field
against the expected path name (channel name under `/channels/*`, semver under
`/releases/*`). This binds a tag object to its serving path and prevents
cross-serving. Branch refs are **unsigned convenience pointers**, never part of
the trust chain.

### Key target properties

| Property | Mechanism | Brief |
|---|---|---|
| sha256 object format | `git init --object-format=sha256`; 2/62 loose-object split | §8 |
| Superset of git | dumb-HTTP shim: `HEAD`, `info/refs` (`update-server-info`), `objects/info/alternates` (one relative `../`) | §12 |
| Superset of Nix | committed `registry.toml` `[[caches]]` (client-side `registries.d` override; or the origin); `nix-cache-info` + narinfo + `nar/` | §13 |
| Channels = branches | `refs/heads/<channel>` head = rollout **frontier** | §6 |
| 256-partition rollout | `/channels/<name>/00..ff`, N/256 advanced to control blast radius | §6 |
| Bucketed consumers | deterministic, persisted: the low byte of `sha256(machine_id)` (i.e. `mod 256`) | §6 |
| Guaranteed delta graph | full pack at every `X.Y.0`; thin `delta-*.pack`s on a fixed schedule | §9 |
| zstd-over-stored packs | `pack-objects --compression=0` then `zstd --ultra -22 --long=27` | §10 |
| Signed tag objects | SSH-format Ed25519, name-binding, `tag→tag→commit` | §11 |
| Anti-rollback | monotonic floor; aborts are **fix-forward**, never partition-decrement | §6 |

### The properties that change the product

The git-native model buys four things the old bundle/`creation_token` design
could not:

1. **Stock-git clonability** — any sha256-capable `git clone <url>` works; loose
   objects guarantee correctness, full packs restore speed.
2. **Publisher-controlled 256-partition rollout** — advance N/256 partitions to put
   a release in front of exactly N/256 of the fleet; the un-advanced partitions
   still name the prior release, answering "where does the rest of the fleet go".
3. **Cheap incremental fetch** — a guaranteed, walkable thin-delta graph + the
   zstd-over-stored-pack trick beat zlib-9 while staying git-valid.
4. **Free Nix-cache superset** — the same origin can serve `nix-cache-info` +
   narinfo + `nar/`, turning it into a substituter for stock `nix` dev shells;
   the location lives in the committed `registry.toml` `[[caches]]` (client-side
   `registries.d` as an optional override).

---

## 3. Where we are today (CURRENT, in brief)

The full as-is picture, grounded in code with `path:line` citations, lives in
[gap-analysis.md](./gap-analysis.md) and (reference form) in
[../../registry/current-state.md](../../registry/current-state.md). The headline
asymmetry:

| Capability | Consumer | Producer |
|---|---|---|
| Parse package TOML tree (`PackageToml`) | present (`crates/aos-package/src/registry/parse.rs:15`) | writes via `build_package_toml` (`registry_ops.rs:595`) |
| Verify commit signature (`git verify-commit`) | present (`security.rs:199`, `registry/git.rs:384`) | signs via `apr sign` (`git commit -S`) |
| TOFU + `trusted-keys.d/<registry>.pub` | present (`types.rs:507`, `security.rs:22`) | n/a |
| Calendar `creation_token` ordering | present (`registry/state.rs:131` `version_to_token`) | **TARGET drops this** (→ semver + git ancestry) |
| Git **bundles** + `bundle-list.toml` | parse present (`registry/bundle.rs`) | stub (`apr bundle` = `git bundle create`); **TARGET drops bundles** |
| **sha256 object format** | absent (sha1 today) | absent |
| **256 signed partition tags** / channel branches | absent | absent |
| **Thin/full pack + delta scheme** | absent | absent |
| **zstd-over-stored packs** | absent | absent |
| **`info/alternates` pack/release-index discovery** | absent | absent |
| **Nix-cache superset (narinfo/nar from origin)** | absent | absent |

In short: the **signing primitive (Ed25519 / SSH-format git signatures) and the
package-TOML tree content are reusable as-is**; nearly **everything about
distribution, rollout, packing, and Nix-cache emission is new**. The target
keeps the trust primitive and the tree content and replaces the whole transport.

---

## 4. Milestone roadmap

The work is staged so each milestone is independently shippable and leaves the
registry in a consistent, deployable state.

| Milestone | Theme | Delivers | Primary workstreams |
|---|---|---|---|
| **M0** | Grounding | Confirmed schemas, gap map, reference docs | [gap-analysis](./gap-analysis.md), `docs/registry/*` |
| **M1** | Object store | sha256 bare repo, dumb-HTTP layout, `info/refs`/`HEAD`/`info/alternates`/`update-server-info`, centralized root `/objects/` + per-release pack-only dirs | [WS-01](./workstream-01-object-store.md) |
| **M2** | Pack & delta pipeline | `pack-objects` thin/full, the delta-scheme graph, zstd-over-stored, expensive-producer tuning | [WS-02](./workstream-02-pack-delta-pipeline.md) |
| **M3** | Signing & trust | signed tag objects (pure signed pointers), name-binding, `tag→tag→commit`, anti-rollback/fix-forward | [WS-04](./workstream-04-signing-trust.md) |
| **M4** | Channels & rollouts | 256 signed partition tags, channels-as-branches/frontier, bucket selection, publisher rollout control | [WS-03](./workstream-03-channels-rollouts.md) |
| **M5** | Consumer cutover | bucket → channel tag → semver tag → commit, delta walk + retention, name-bound verification, client-side Nix-cache superset | [WS-05](./workstream-05-consumer.md) |
| **M6** | Nix-cache emitter | `nix-cache-info` + `<storehash>.narinfo` + `nar/`, References basename expansion, per-narinfo Ed25519 `Sig:`, origin-as-substituter | [WS-06](./workstream-06-nix-cache.md) |

```
 M0 ──► M1 ──► M2 ──────────────┐
        │                       │
        └──► M3 (signing) ──► M4 (channels/rollouts)
                                │
                                ▼
                               M5  (consumer reads the new surface)
                                │
                                ▼
                               M6  (origin emits the Nix-cache superset)
```

Notes on the dependency edges:

- **M1 → M2.** Packs and deltas are produced over the centralized root
  `/objects/` and the per-release pack-only `objects/` dirs that WS-01
  establishes; there is nothing to pack until the sha256 bare repo and
  `info/alternates` layout exist.
- **M1 → M3.** Name-binding verification checks tag objects against their serving
  path under `/channels/*` and `/releases/*`; the signing/trust work (WS-04) builds
  on the layout WS-01 lays down.
- **M3 → M4.** A channel partition is a **signed** tag object pointing at a
  **signed** semver tag; channels and rollout (WS-03) require the signed-tag
  primitive and name-binding from WS-04 first.
- **M2/M4 → M5.** The consumer cutover (WS-05) resolves bucket → channel tag →
  semver tag → commit and then walks the delta graph; it lands last, after a
  producer can publish both the rollout surface (WS-03) and the pack/delta graph
  (WS-02).
- **M2 is parallelizable with M3.** The pack/delta pipeline (objects only) and
  the signing/trust primitive (tags only) touch disjoint surfaces and can proceed
  concurrently once the object store exists.
- **M3 → M6.** The Nix-cache emitter (WS-06) reuses the one Ed25519 key from
  WS-04 for the per-narinfo `Sig:`, so the signing/trust primitive must exist
  first. The narinfo/`nar/` surface is otherwise orthogonal to the git trust
  chain (NARs are content-addressed), so M6 can land after M3 independently of
  the consumer cutover (M5).

---

## 5. Workstreams

Each workstream is a self-contained design + task doc. They map onto the
authoring specs in [design brief §17](./design-brief.md). Note the file numbering
follows the on-disk specs; the **milestone order** above sequences signing
(WS-04) before channels/rollouts (WS-03).

| # | Workstream | Scope | Brief refs |
|---|---|---|---|
| 01 | [Object store](./workstream-01-object-store.md) | sha256 bare repo, dumb-HTTP layout, `info/refs`/`HEAD`/`info/alternates`/`update-server-info`, centralized root `/objects/` + per-release pack-only dirs | §4, §8 |
| 02 | [Pack & delta pipeline](./workstream-02-pack-delta-pipeline.md) | `pack-objects` thin/full, the delta scheme graph, client resolution + retention, zstd-over-stored, expensive-producer tuning | §9, §10 |
| 03 | [Channels & rollouts](./workstream-03-channels-rollouts.md) | 256 signed partition tags, channels-as-branches/frontier, deterministic bucket selection, publisher rollout control | §5, §6, §7 |
| 04 | [Signing & trust](./workstream-04-signing-trust.md) | signed tag objects (pure signed pointers), name-binding, `tag→tag→commit`, sha256, anti-rollback/fix-forward | §5, §11 |
| 05 | [Consumer](./workstream-05-consumer.md) | bucket → channel tag → semver tag → commit resolution, delta walk, retention, name-bound verification, client-side Nix-cache superset | §6, §9, §13 |
| 06 | [Nix cache](./workstream-06-nix-cache.md) | origin-side `nix-cache-info`/`<storehash>.narinfo`/`nar/` emitter, References basename expansion, per-narinfo Ed25519 `Sig:`, origin-as-substituter | §13, §11 |

### Workstream sequencing rationale

WS-01 is the keystone: a **sha256 bare repo with the dumb-HTTP shim and the
distributed per-release object store** is the substrate every other workstream
builds on — there is nothing to pack, sign, roll out, or consume until the object
layout exists. WS-02 (packs/deltas) and WS-04 (signing/trust) then proceed in
parallel over disjoint surfaces (objects vs tags). WS-03 layers the 256-partition
rollout and channel branches on top of WS-04's signed-tag primitive. WS-05 flips
the consumer to resolve buckets, walk the delta graph, verify name-binding, and
read the client-side Nix-cache superset — only after a producer can publish all
of it, so it lands last. WS-06 adds the **origin-side** Nix-cache emitter
(`nix-cache-info`/narinfo/`nar/`); it reuses WS-04's signing key for the
per-narinfo `Sig:` but is otherwise orthogonal to the git trust chain (NARs are
content-addressed), so it can follow WS-04 independently of WS-05.

---

## 6. Canonical shapes (quick reference)

These are reproduced verbatim from the brief so a workstream owner can sanity-
check an implementation without leaving this page. The brief is authoritative.

### HTTP / object layout (§4)

```
/                                  ← bare git repo root (dumb HTTP)
  HEAD                             ← "ref: refs/heads/<default-channel>"        [low TTL]
  info/refs                        ← refs/heads/<channels> + refs/tags/<semvers> [low TTL]
  objects/
    info/packs                     ← lists self-contained pack-<sha>.pack only   [low TTL]
    info/alternates                ← RELATIVE "../releases/*/objects/", newest→old [low TTL]
    <xx>/<62-hex>                  ← ALL loose objects (every release), 2/62 split [immutable]
  channels/
    <name>/00 .. ff               ← 256 SIGNED tag objects (tag == <name>)       [low TTL]
  releases/
    <major>/<minor>/<patch[-prerelease][+build]>/                                [long TTL]
      objects/                              ← PACK-ONLY (no loose, no alternates)
        info/packs
        pack/pack-<sha256>.pack (+ .idx)   ← full pack at X.Y.0 anchors
        pack/delta-<from-semver>.pack       ← THIN deltas; AOS-only; NOT in info/packs
```

All loose objects are **centralized** at the root `/objects/<xx>/<62-hex>`; the
per-release `objects/` dirs hold **packs only** (no loose objects, no per-release
`info/alternates`). The root `objects/info/alternates` lists each release's
pack dir as a **relative** path with a single `../` (e.g. `../releases/1/1/0/objects/`),
making the file **host-independent** (byte-identical across CDN/mirror/localhost).
Because loose objects are centralized, alternates serve **pack discovery + the
release index**, not object completeness.

CDN policy: `/channels/**` and all `objects/info/**` **MUST** be low TTL;
`/releases/**` and immutable `/objects/**` **MAY** be very high TTL.

### Delta scheme (§9)

- **Every `X.Y.0`** ships a self-contained full pack `pack-<sha256>.pack` (+ `.idx`).
- **Every major `X.0.0`** also ships `delta-<(X-1).0.0>.pack`.
- **Every minor `X.Y.0` (Y>0)** also ships `delta-<X.(Y-1).0>.pack` and `delta-<X.0.0>.pack`.
- **Every patch `X.Y.Z` (Z>0)** ships `delta-<X.Y.(Z-1)>.pack`, `delta-<X.Y.(Z-2)>.pack`,
  `delta-<X.Y.(Z-3)>.pack` (where they exist) and `delta-<X.Y.0>.pack`. Patches have **no** full pack.

Client retention: a client on `X.Y.Z` keeps object trees for at least `X.0.0`,
`X.Y.0`, and `X.Y.Z`, so a delta base is always present. Resolution falls back to
full packs and finally loose objects (always correct).

### Pack generation (§10)

```sh
# Thin delta from <from> to <to>:
printf '%s\n^%s\n' "$to" "$from" \
  | git pack-objects --revs --thin --stdout \
      --no-reuse-object --no-reuse-delta \
      --window=350 --depth=50 --threads=0 --compression=0 \
  > delta-$from.pack
zstd --ultra -22 --long=27 delta-$from.pack          # serve delta-$from.pack.zst

# Full pack at an X.Y.0 anchor (non-thin):
git pack-objects --revs <release-commit> \
      --no-reuse-object --no-reuse-delta \
      --window=350 --depth=50 --threads=0 --compression=0 \
  ...                                                # → pack-<sha256>.pack (+ .idx)
```

Window is the free lever; cap **depth** (deep chains cost the *consumer* CPU).
`--compression=0` keeps git's delta encoding but skips zlib entropy coding so
`zstd --ultra` can do the entropy coding over the delta-encoded stream. Client:
`zstd -d | git index-pack --fix-thin`. Ship `.idx` only for full packs; thin
deltas are `.pack[.zst]` only.

### 256-partition rollout (§6)

```
/channels/stable/   00 01 02 .. fd fe ff                 (256 signed tag objects)
   roll N/256 to new release  →  point N partitions at new semver tag
   the other (256-N) partitions still name the prior release
   completion  →  all 256 point at the new release
```

Consumer bucket: deterministic + persisted (the low byte of `sha256(machine_id)`,
i.e. `mod 256`), probe-forward `(bucket+1) mod 256` if a partition is missing. Branch head
`refs/heads/<channel>` = the **frontier** (newest release any partition targets).

### Signed tags carry no payload (§14)

A signed tag is a **pure signed pointer**: the standard git tag fields (`object`,
`type`, the tag **name**, `tagger`) + the Ed25519 (SSH-format) signature + an
**optional freeform human message**. There is **no** structured TOML payload — no
`[meta]`, no `schema`, no `valid_until`, no `[[caches]]` inside tag objects.

- **Cache config lives in the committed `registry.toml`.** The NAR substituter
  location lives in the committed repo-root `registry.toml` `[[caches]]` (a tree
  file authenticated transitively by the signed tag), with the consumer's
  client-side `registries.d` as an optional override (or the origin itself), never
  advertised in the signed tag itself. The origin **MAY** serve `nix-cache-info`/`<storehash>.narinfo`/`nar`;
  narinfo signing reuses the one Ed25519 key.
- **Freshness has no in-band `valid_until`.** Freshness = low CDN TTL on `/channels`
  (and `info/refs`, `objects/info`) + the consumer's own max-staleness policy + the
  monotonic anti-rollback floor. Trade-off: this is **weaker** than an in-band
  signed expiry against a frozen-but-validly-signed mirror.

The tag *object* carries the signature, the ref namespace carries pointers, the
object store carries everything else.

---

## 7. Cross-references

### Plan set (`docs/plans/registry/`)

- [design-brief.md](./design-brief.md) — the captured design and decision log.
  **Authoritative for intent.** Read in full before implementing.
- [gap-analysis.md](./gap-analysis.md) — current vs target, enumerated
  producer/consumer gaps, mapped to workstreams.
- [open-questions.md](./open-questions.md) — unresolved decisions (sha256
  dumb-HTTP client support, window/depth/zstd defaults, `machine_id` source,
  `apr release`/`apr publish` shape, max-staleness policy, migration strategy).
- Workstreams [01 Object store](./workstream-01-object-store.md) ·
  [02 Pack & delta pipeline](./workstream-02-pack-delta-pipeline.md) ·
  [03 Channels & rollouts](./workstream-03-channels-rollouts.md) ·
  [04 Signing & trust](./workstream-04-signing-trust.md) ·
  [05 Consumer](./workstream-05-consumer.md) ·
  [06 Nix cache](./workstream-06-nix-cache.md).

### Reference set (`docs/registry/`, describes the **TARGET** state)

- [README](../../registry/README.md) — reference-set entry point, glossary, doc index.
- [architecture.md](../../registry/architecture.md) — git-repo-over-dumb-HTTP, the
  superset-of-git-and-Nix model, the three ref layers, asymmetric-cost philosophy.
- [current-state.md](../../registry/current-state.md) — the as-is code (bundle /
  `creation_token` implementation), grounded in `path:line`.
- [repo-layout.md](../../registry/repo-layout.md) — the **committed git tree** (what a
  commit contains, distinct from the served object store): the target trust files
  `registry.toml` (`[registry]` name/description + `[[caches]]`, **signing pubkey
  removed**) and the new `keys.toml` roster (active signing key(s) + revoked list,
  bootstrap trust TOFU-pinned client-side), plus `packages/<x>/<name>.toml`,
  `closures/<hash>`, and `.gitattributes`.
- [http-layout.md](../../registry/http-layout.md) — full HTTP/object layout, CDN
  TTLs, `info/refs`/`HEAD`/`info/alternates`, stock-git dumb-HTTP compatibility.
- [versioning-and-channels.md](../../registry/versioning-and-channels.md) — semver
  (no `v`), channels-as-branches, frontier head, the 256-partition rollout, bucket
  selection, anti-rollback.
- [packs-and-deltas.md](../../registry/packs-and-deltas.md) — pack-objects, thin vs
  full packs, the delta-scheme graph, client resolution + retention, zstd.
- [signing-and-trust.md](../../registry/signing-and-trust.md) — signed tag objects
  as pure signed pointers, name-binding, `tag→tag→commit`, sha256, unsigned branch
  refs.
- [publishing.md](../../registry/publishing.md) — the producer pipeline end-to-end
  (commit → sign → pack/delta/zstd → update-server-info → advance partitions → upload).
- [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) — the Nix
  binary-cache superset located via the committed `registry.toml` `[[caches]]`
  (client-side `registries.d` override; or the origin) + narinfo/nar.
- [apt-comparison.md](../../registry/apt-comparison.md) — the APT comparison: signed
  flat-file lineage, bundles/pdiff → git packs/thin deltas, percentage → 256 partitions.

---

## 8. Glossary (quick reference)

Full definitions live in [design brief §1](./design-brief.md). The terms you need
to read this plan:

- **`apm` / `apr`** — independent package-consumer and registry-authoring CLIs
  with disjoint parsers and shared implementation libraries.
- **Registry (target)** — a bare git repo, **sha256** object format, served as
  static files over **dumb HTTP**. The package metadata *is* the git tree content.
- **Channel** — a named release line (`stable`, `testing`); a git **branch**
  (`refs/heads/<channel>`, head = frontier) plus **256 signed partition tags**
  (`/channels/<name>/00..ff`).
- **Partition / bucket** — one of exactly **256** channel partitions (`00`–`ff`); a
  consumer deterministically self-selects one bucket.
- **Release** — an immutable **semver** version (no `v` prefix); a signed git tag
  `refs/tags/<semver>` → commit, with objects under `/releases/<major>/<minor>/<patch…>/`.
- **Full pack** — a self-contained `pack-<sha256>.pack` (+ `.idx`) at every `X.Y.0`.
- **Delta pack** — a **thin** `delta-<from-semver>.pack`, completed on the client
  with `git index-pack --fix-thin`.
- **Frontier** — the newest release any channel partition targets; the value of
  the channel branch head.
- **Dumb HTTP** — git's static-file transport (`HEAD`, `info/refs`, loose objects,
  `objects/info/packs`, `objects/info/alternates`).
