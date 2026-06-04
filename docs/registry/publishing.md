# Publishing — the Producer Pipeline

> **Audience:** registry maintainers (producers), implementers of the `apr`
> tooling, and architects reasoning about the registry's atomicity and
> concurrency properties.
>
> **Scope:** the **TARGET** producer pipeline end to end — how a new release goes
> from a build commit to a fully published, signed, fetchable git-native
> registry over dumb HTTP, including pack/delta generation, `update-server-info`,
> partition (rollout) advancement, and upload with correct CDN TTLs. The
> consumer counterpart is [packs-and-deltas.md](./packs-and-deltas.md) (delta
> walk + retention) and [versioning-and-channels.md](./versioning-and-channels.md)
> (bucket selection).

Every claim is labelled **CURRENT** (verified against the code, cited as
`path:line`) or **TARGET** (the design intent from the
[design brief](../plans/registry/design-brief.md), authoritative §10, §4, §6).
The gap between them is the subject of
[workstream-02-pack-delta-pipeline.md](../plans/registry/workstream-02-pack-delta-pipeline.md)
and
[workstream-03-channels-rollouts.md](../plans/registry/workstream-03-channels-rollouts.md).

---

## 1. Mental model

**TARGET.** A registry is a **bare git repository in sha256 object format,
published as static files over dumb HTTP**
(see [architecture.md](./architecture.md) and
[http-layout.md](./http-layout.md)). Publishing is the asymmetric-cost half of
the design: *make publishing as expensive as possible so consumption is as cheap
as possible* (design brief §3). The producer pays once — building large-window
packs, thin deltas, and zstd-compressing — and every consumer benefits.

A publish has two strictly-ordered halves that must never be confused:

1. **Materialize immutable release objects.** Build the release commit, create
   and sign the semver tag, generate the full/delta packs, write loose objects,
   and regenerate the per-release `objects/info/*`. Everything here is
   **content-addressed and immutable** — once a sha256 object exists it never
   changes meaning.
2. **Flip the mutable pointers.** Regenerate the repo-root `info/refs` / `HEAD` /
   `objects/info/http-alternates`, bump `refs/heads/<channel>` to the frontier,
   and advance the signed `/channel/<name>/<0..f>` partition tags. These are the
   *only* mutable surfaces, and they are published **last**, after every object
   they can possibly reference already exists at the origin.

```
                      PRODUCER (TARGET)                          CONSUMER
   ┌────────────────────────────────────────────────┐
   │ 1  build release commit                          │
   │ 2  create + sign semver tag  (refs/tags/<semver>)│
   │ 3  pack-objects → full + thin deltas → zstd      │   immutable, content-addressed
   │ 4  write loose objects under /release/X/Y/P/     │──────────────────────────┐
   │ 5  per-release update-server-info                │                          │
   ├──────────────────────────────────────────────────┤   pointers, flipped LAST │
   │ 6  root update-server-info (info/refs, HEAD)      │                          ▼
   │ 7  regen objects/info/http-alternates            │                  ┌────────────────┐
   │ 8  bump refs/heads/<channel> → frontier          │                  │  HTTP / CDN     │
   │ 9  advance /channel/<name>/0..f partition tags    │─────────────────▶│  origin (dumb   │
   │ 10 upload with per-path CDN TTLs                  │                  │  git static)    │
   └────────────────────────────────────────────────┘                  └────────────────┘
                                                                                 │
                                                            apm bucket → channel tag → semver
                                                            tag → commit → delta walk / fetch
```

**Invariant (TARGET).** Immutable release objects (steps 1–5) are uploaded and
visible **before** any pointer that can name them flips (steps 6–9). A reader
mid-publish therefore sees **either** the old frontier/partition state **or** the
new one — never a partition tag pointing at a commit whose objects are missing.

---

## 2. CURRENT state — the `apr` stub

**CURRENT.** `apr` is the same binary as `aos`/`apm`, dispatched on `argv[0]`;
`apr …` expands to `package registry …`. All producer logic lives in
[`crates/aos-package/src/registry_ops.rs`](../../crates/aos-package/src/registry_ops.rs).
Today's tool operates on a *nested-TOML* registry (`packages/<x>/<name>.toml` +
`closures/<hash>`) and distributes via **git bundles**. None of the TARGET
git-native pipeline (sha256 object store, signed semver/partition tags, packs,
deltas, `update-server-info`, `http-alternates`, upload) exists yet.

The commands relevant to a release, in workflow order:

| Command | Function | What it actually does (CURRENT) |
|---|---|---|
| `apr create <name> [--remote URL]` | `create` (`registry_ops.rs:421`) | `git init`, make `packages/`, write a default `registry.toml`, initial commit, optional `git remote add origin`. |
| `apr publish <store-path> […]` | `publish` (`registry_ops.rs:476`) | Introspect the path, write `packages/<x>/<name>.toml`, compute + write `closures/<hash>`, then (unless `--no-commit`) `git add -A && git commit` (`commit_registry`, `registry_ops.rs:385`). |
| `apr tag <name> [--message] [--key]` | `tag` (`registry_ops.rs:1696`) | `git tag [-a -m …]`. **`--key` is accepted but ignored** (`_key`, `registry_ops.rs:1700`). |
| `apr sign [commit] [--key]` | `sign` (`registry_ops.rs:1759`) | `git commit --amend --no-edit -S` (`registry_ops.rs:1770`) — SSH-Ed25519 sign HEAD. **`--key` ignored** (`_key`, `registry_ops.rs:1762`). |
| `apr bundle [--output] [--tag] [--delta-from] [--update-manifest]` | `bundle` (`registry_ops.rs:1718`) | `git bundle create` into a local dir. See §2.1. |
| `apr push [--branch] [--set-upstream] [--force]` | `push` (`registry_ops.rs:1410`) | `git push [-u origin] [branch] [--force]`. |

There is **no** `apr release`, no pack/delta generation, no `update-server-info`,
no partition-tag advancement, and no upload command in the tree today.

### 2.1 CURRENT: `apr bundle` = `git bundle create` only

The producer's entire transport step today is `apr bundle` (`registry_ops.rs:1718`),
which runs `git bundle create` into a local output directory (default `bundles/`):

- **Snapshot:** `git bundle create <dir>/<reg>-<tag>.bundle <tag>`
  (`registry_ops.rs:1750`).
- **Delta:** with `--delta-from <from>`,
  `git bundle create <dir>/<reg>-<from>..<tag>.bundle <from>..<tag>`
  (`registry_ops.rs:1741`).

What it does **not** do: it does not write any manifest (`--update-manifest` is
dead code — `_update_manifest`, `registry_ops.rs:1723`), does not generate packs
or thin deltas independent of the bundle envelope, does not run
`update-server-info`, does not touch any channel/partition pointer, and **does
not upload anything**. The operator must hand-copy the resulting `.bundle` files
to a mirror.

> **TARGET shift.** The TARGET drops git **bundles** entirely (a bundle carries
> refs and prerequisites; refs are replaced by signed tag objects, and the object
> store is served loose + as conventionally-named packs). Producing the dumb-HTTP
> object store with `pack-objects` + `update-server-info` + `http-alternates`
> replaces `apr bundle` wholesale (design brief §10, §15). The rest of this
> document is TARGET.

---

## 3. Inputs and outputs of one release

**TARGET.** A single release publish is parameterized by:

| Input | Meaning |
|---|---|
| `<semver>` | Standard semver, **no `v` prefix** (`1.2.0`, `1.0.0-beta+exp.sha.5114f85`). |
| release commit | The commit the semver tag points at (the new registry tree content). |
| `<channel>` | The release line being advanced (e.g. `stable`, `testing`). |
| partition plan | How many of the 16 partitions `0..f` advance to `<semver>` this publish (rollout fraction). |
| signing key | One SSH-format Ed25519 key (reused from `apr sign` / `security.rs`). |

It produces, under [the HTTP/object layout](./http-layout.md):

```
/release/<major>/<minor>/<patch[-prerelease][+build]>/
  objects/
    info/packs                       ← lists this release's self-contained pack(s)
    info/http-alternates             ← this release's view of the alternates chain
    pack/pack-<sha256>.pack (+ .idx)  ← full pack (only at X.Y.0 anchors)
    pack/delta-<from-semver>.pack[.zst] ← THIN deltas (AOS-only; NOT in info/packs)
    <xx>/<62-hex>                     ← this release's new loose objects
refs/tags/<semver>                    ← signed tag → release commit          [via info/refs]
/channel/<name>/<0..f>                ← signed partition tags advanced per the rollout plan
refs/heads/<channel>                  ← branch head bumped to the frontier
/objects/info/{packs,http-alternates} ← repo-root indices regenerated
/info/refs, /HEAD                     ← regenerated via update-server-info
```

The third `/release` path segment is **everything after `major.minor`** — e.g.
`1.0.0-beta+exp.sha.5114f85` → `/release/1/0/0-beta+exp.sha.5114f85/`.

---

## 4. Step 1–2 — build commit, create + sign the semver tag

**TARGET.**

1. **Build the release commit.** The registry tree content (the package TOML
   tree, the same content model the current code already writes) is committed in
   the bare sha256 repo. All git operations use sha256
   (`git init --object-format=sha256`; design brief §8). The release commit is
   what `refs/tags/<semver>` will point at and what every pack is computed over.

2. **Create the annotated, signed semver tag.** An **annotated git tag** carrying
   an SSH-format Ed25519 signature, whose message is the TOML described in
   [tag-metadata.md](./tag-metadata.md):

   ```toml
   [meta]
   schema      = 1
   valid_until = "2027-06-30T00:00:00Z"   # releases: generous (must not fight long release TTL)

   [[caches]]
   url      = "https://cache.example.com"   # absolute external mirror
   priority = 1000                          # HIGHER priority = preferred (tried first)

   [[caches]]
   url      = "./nar"                        # relative (same origin) fallback
   priority = 100                           # lower priority = later fallback
   ```

   The tag **name** is the bare semver (`1.2.0`), the signature lives on the tag
   *object*, and the embedded tag-name field is bound to the serving path during
   verification (see §10 and [signing-and-trust.md](./signing-and-trust.md)).
   The signing primitive is the existing SSH-format Ed25519 git signature reused
   from `apr sign` (`git`-resolved `user.signingkey` + `gpg.format = ssh`;
   `security.rs` `parse_signing_key` `name:Ed25519:<base64>`).

Release `valid_until` is the **generous** signature-trust / key-rotation lifetime
(design brief §11); it is intentionally long because releases are immutable and
carry a long CDN TTL — a tight expiry here would defeat that. Contrast the
**channel** partition tags' `valid_until`, which is the *freshness* knob paired
with the low `/channel/**` TTL.

---

## 5. Step 3 — pack generation (`pack-objects` + zstd)

**TARGET.** Packs are an efficiency layer over the always-present loose object
store. The producer commits to the [guaranteed delta graph](./packs-and-deltas.md)
so consumers can plan their walk:

- **Every `X.Y.0` (major or minor)** ships a self-contained **full pack**.
- **Every patch `X.Y.Z` (Z>0)** ships thin deltas only (no full pack).
- The full set of guaranteed deltas per release class is specified in
  [packs-and-deltas.md](./packs-and-deltas.md).

### 5.1 Full pack (self-contained)

```sh
printf '%s\n' <release-commit-sha> \
  | git pack-objects --revs \
      --no-reuse-object --no-reuse-delta \
      --window=350 --depth=50 --threads=0 \
      --compression=0 \
      --stdout > pack-<sha256>.pack
# → emits pack-<sha256>.pack (+ pack-<sha256>.idx via git index-pack)
```

- `--revs` over the release commit (non-thin); git names the output
  `pack-<sha256>.pack` (+ `.idx`).
- The **expensive-producer flags** make the producer pay: `--no-reuse-object
  --no-reuse-delta` force a from-scratch recompute, `--window=350` is the free
  lever (more candidate bases = smaller pack), and `--depth=50` **caps** delta
  chain length because deep chains cost the *consumer* CPU to reconstruct
  (design brief §10). The producer may try multiple delta bases and ship the
  smallest.
- Ship the `.idx` **only** for full packs — they are self-contained and listed in
  `objects/info/packs`.

### 5.2 Thin delta pack

```sh
printf '%s\n^%s\n' <to-semver-commit> <from-semver-commit> \
  | git pack-objects --revs --thin \
      --no-reuse-object --no-reuse-delta \
      --window=350 --depth=50 --threads=0 \
      --compression=0 \
      --stdout > delta-<from-semver>.pack
# → emits delta-<from-semver>.pack (NO .idx — the client's --fix-thin builds it)
```

- `--revs --thin` reading `"<to>\n^<from>\n"` packs objects in `<to>` not
  `<from>`, and deltas may reference `<from>`'s objects (the "thin" part). The
  consumer completes it with `git index-pack --fix-thin` against the retained
  base (design brief §10; [packs-and-deltas.md](./packs-and-deltas.md)).
- Thin deltas are **`.pack[.zst]` only** — no `.idx`, and they are **NOT** listed
  in `objects/info/packs` (a stock dumb client cannot apply a thin pack; AOS
  clients discover them by the `delta-<semver>` filename convention).

### 5.3 zstd (the working trick)

git's pack format hard-codes **zlib per object**, so zstd-ing a
`--compression=9` pack is near-useless (already DEFLATEd). Instead:

```sh
# 1. emit at compression level 0: "stored" zlib framing, valid git pack,
#    NO entropy coding — BUT git's delta encoding is still applied.
git pack-objects … --compression=0 … <args>     # (as in §5.1 / §5.2)

# 2. zstd the whole .pack: zstd does the entropy coding over the delta-encoded stream.
zstd --ultra -22 --long=27 pack-<sha256>.pack -o pack-<sha256>.pack.zst
zstd --ultra -22 --long=27 delta-<from>.pack  -o delta-<from>.pack.zst
```

zstd's entropy coding over the delta-encoded (but un-DEFLATEd) stream beats
zlib-9, and the underlying `.pack` stays git-valid. The consumer fetches
`.pack.zst`, runs `zstd -d`, then `git index-pack --fix-thin`. A zstd **trained
dictionary** across a release line's small delta packs is an optional further win
(design brief §10, open question §16.2).

> **Serve both forms.** Keep the plain `.pack`/`.idx` for full packs (stock dumb
> git can use them) and additionally serve `.pack.zst`; AOS clients prefer the
> zstd form. See [http-layout.md](./http-layout.md).

---

## 6. Step 4–5 — loose objects + per-release `update-server-info`

**TARGET.**

- **Write loose objects.** **ALL** objects exist loose under
  `/objects/<xx>/<62-hex>` (the sha256 2/62 split) — this is the guaranteed
  completeness fallback; packs are an optimization on top (design brief §8). A
  release's *new* loose objects live under its own
  `/release/<major>/<minor>/<patch>/objects/<xx>/<…>`, so the per-release object
  dir is self-describing.

- **Per-release `update-server-info`.** Regenerate `objects/info/packs` (listing
  this release's self-contained full pack only — never the thin deltas) for the
  release's object dir. This makes the per-release directory a valid dumb-HTTP
  object store that the root `http-alternates` chain can stitch together.

Because release objects are content-addressed sha256, **writing the same object
twice is idempotent** — a re-run or a concurrent publisher writing the same bytes
is a no-op. This is what makes step 3/4 safe to retry freely (§11).

---

## 7. Step 6–7 — root `update-server-info` + `http-alternates`

**TARGET.** With every immutable object in place, regenerate the *repo-root*
mutable indices that make the whole thing a valid dumb-HTTP bare repo:

1. **`git update-server-info`** regenerates `/info/refs` (the full
   `refs/heads/<channels>` + `refs/tags/<semvers>` listing) and the root
   `/objects/info/packs`. A stock `git clone <url>` works off these
   (design brief §8, §12).

2. **`/HEAD`** is written as `ref: refs/heads/<default-channel>` (e.g.
   `ref: refs/heads/stable`) so a default clone lands on the default channel
   branch.

3. **`/objects/info/http-alternates`** is regenerated to list **every**
   `/release/*/objects/` directory, **newest → oldest**. Git's dumb fetcher
   follows it, resolving the distributed per-release object stores as one logical
   store; this file also doubles as the **full release index** (design brief §8).
   Use `http-alternates` (URL-reachable), not `alternates`; an `info/alternates`
   readable mirror is optional (open question §16.6).

```
# /objects/info/http-alternates  (newest → oldest)
../../release/1/2/0/objects/
../../release/1/1/3/objects/
../../release/1/1/0/objects/
../../release/1/0/0/objects/
…
```

These four files (`info/refs`, `HEAD`, `objects/info/packs`,
`objects/info/http-alternates`) are **mutable** and therefore **low TTL** (§9).

---

## 8. Step 8–9 — frontier branch head + partition rollout

**TARGET.** The ref/rollout model has three layers
(see [versioning-and-channels.md](./versioning-and-channels.md) and
[signing-and-trust.md](./signing-and-trust.md)):

| Path / ref | What | Signed? |
|---|---|---|
| `refs/heads/<channel>` | **channels are branches**; head = **frontier** (newest release any partition targets) | no (unsigned convenience pointer) |
| `refs/tags/<semver>` | release: signed tag → commit | **yes** |
| `/channel/<name>/<0..f>` | 16 signed partition tag objects (tag name == channel) → semver tag | **yes** |

### 8.1 Bump the frontier branch head

`refs/heads/<channel>` is set to the commit of the **newest release any partition
targets** — the rollout *target* (frontier). Implication: a stock `git pull
<channel>` always gets the frontier (no rollout protection), which is acceptable
because rollout is an AOS-fleet concept, not a git-clone concept (design brief
§6). The branch ref is an **unsigned** pointer and is never part of the trust
chain.

### 8.2 Advance the 16 partition tags (publisher-controlled rollout)

A channel exposes **exactly 16** partition files `/channel/<name>/0..f`, each an
**independently-signed** annotated tag object whose **tag name == the channel
name**, pointing at a semver tag. There must always be 16 present.

**To roll a new release to N/16 of the fleet:** point N partitions at the new
semver tag and **leave the rest on the prior release**. This is the explicit
answer to "where does the rest of the fleet go" — the un-advanced partitions
still name the prior release. Advance partitions as confidence grows; completion
= all 16 point at the new release (design brief §6).

```
  rollout fraction      /channel/stable/0..f  →  semver tag
  ────────────────      ────────────────────────────────────
  0/16  (none yet)      0 1 2 3 4 5 6 7 8 9 a b c d e f → 1.1.3
  4/16  (early ring)    0 1 2 3                         → 1.2.0   (new)
                                4 5 6 7 8 9 a b c d e f → 1.1.3   (prior)
  16/16 (complete)      0 1 2 3 4 5 6 7 8 9 a b c d e f → 1.2.0
```

Each advanced partition is a **fresh signed tag object** (`tag → tag → commit`:
channel partition tag → semver tag → release commit). The signature and the
embedded tag-name field (`== <channel>`) bind it to its `/channel/<name>/<bucket>`
serving path. See [signing-and-trust.md](./signing-and-trust.md).

**Aborting a bad rollout is fix-forward** (publish a newer release and point
partitions at it), never partition-decrement: the consumer's monotonic floor
(anti-rollback) would block a decrement anyway (design brief §6).

> Consumers self-select a bucket deterministically (e.g.
> `sha256(machine_id) mod 16`, persisted) and probe-forward `(bucket+1) mod 16`
> if their partition is missing — see
> [versioning-and-channels.md](./versioning-and-channels.md). The producer never
> chooses *which* hosts get a bucket; it only chooses *which buckets advance*.

---

## 9. Step 10 — upload with correct CDN TTLs

**TARGET.** Upload to the HTTP/CDN origin honoring the per-path cache policy
(design brief §4; [http-layout.md](./http-layout.md)). The ordering within the
upload (immutable first, pointers last) is the atomicity discipline of §11.

| Path | Mutability | CDN TTL |
|---|---|---|
| `/objects/<xx>/<…>` (loose), `/release/**/pack/*` | immutable (content-addressed) | **very high** (`MAY`) |
| `/release/**` (the whole subtree) | immutable after publish | **long** (`MAY`) |
| `/objects/info/**` (`packs`, `http-alternates`), per-release `objects/info/**` | mutable on publish | **low** (`MUST`) |
| `/info/refs`, `/HEAD` | mutable on publish | **low** (`MUST`) |
| `/channel/**` | mutable on rollout | **low** (`MUST`) — fast rollout updates |

The asymmetry is intentional: `/channel/**` and the `info/*` indices must turn
over quickly so a rollout or a new frontier is visible promptly, while the bulk
bytes (`/release/**`, loose objects, packs) are immutable and may be cached
aggressively forever. If the CDN supports cache invalidation, invalidate the
low-TTL paths on publish; otherwise the short TTL bounds staleness.

---

## 10. Verification the producer must satisfy (name-binding)

**TARGET.** The producer signs so that the consumer's trust chain holds. AOS
verification is **`signed partition tag → signed semver tag → commit`**, checking
**both** the signature **and** the embedded tag-name field against the expected
name:

- under `/channel/<name>/*` the embedded tag name **must** equal `<name>` (the
  channel);
- under `/release/*` (i.e. `refs/tags/<semver>`) the embedded tag name **must**
  equal the semver.

This **name-binding** is what binds a tag object to its serving path and prevents
cross-serving a tag from one path at another (design brief §5, §11). Concretely
the producer must ensure each partition tag it writes (a) is SSH-Ed25519 signed,
(b) names the channel in its tag-name field, and (c) points at a semver tag that
itself is signed and names that semver. Branch refs are **unsigned** and never
part of this chain — a stock-git user can still `git verify-tag <semver>` because
the release tags are the signed objects. Full detail lives in
[signing-and-trust.md](./signing-and-trust.md).

---

## 11. Concurrency & atomicity

**TARGET.** The HTTP origin is not git and has no native compare-and-swap, so the
safety property is imposed by **ordering** plus the **immutability** of release
objects.

### 11.1 The ordering invariant

```
  STEP   SURFACE                              MUTABILITY        SAFETY
  ────   ───────                              ──────────        ──────
  1–4    release commit, semver tag,          immutable (CA)    idempotent;
         packs, deltas, loose objects                           retry freely, any order
  5      per-release objects/info/*           low-TTL index     regenerated from immutable set
  6–7    info/refs, HEAD,                      MUTABLE pointer   flipped only AFTER 1–5 exist
         objects/info/http-alternates
  8      refs/heads/<channel> (frontier)       MUTABLE pointer   flipped after release objects
  9      /channel/<name>/0..f partition tags   MUTABLE pointer   flipped LAST (rollout gate)
```

**Invariant:** every object a pointer can reference (commits, packs, deltas,
loose objects, the semver tag) is published in steps 1–5 **before** any pointer
flips in steps 6–9. Therefore a reader who fetches a partition tag, then resolves
`partition → semver → commit → objects`, can **always** complete the resolution —
the objects it names were already at the origin when the partition advanced.

A reader caught mid-publish sees **one** of two consistent states:

- **old state:** old partition tags + old frontier (the prior release, fully
  fetchable); or
- **new state:** new partition tags + new frontier (the new release, whose
  objects were uploaded first).

There is no torn state in which a partition points at a release whose objects are
absent.

### 11.2 Why immutability removes the need for a lock

Because release objects are **content-addressed sha256**, two producers
materializing the same release write byte-identical objects — uploading them is
idempotent and needs no coordination (design brief §8, §10). Coordination is only
required for the **mutable pointers** (steps 6–9). Two publishers advancing the
*same* channel must serialize their pointer flips (e.g. via the upstream git
remote's ref CAS on `refs/heads/<channel>` and `refs/tags/*`, or a
conditional-PUT / `If-Match` on the `/channel/**` objects at the origin); the
loser re-derives the frontier and re-applies its partition plan. The mechanism
for serializing the pointer flip is an open implementation question
([open-questions.md](../plans/registry/open-questions.md), design brief §16.4),
but the *correctness* of a partially-applied publish never depends on it: the
worst case is a stale-but-consistent pointer, never a dangling one.

### 11.3 Anti-rollback is the consumer's backstop

Even if a pointer flip races or a mirror is stale, the consumer keeps a
**monotonic floor** and never moves to a release older than its current one
(design brief §6). Aborting a bad rollout is therefore always **fix-forward**:
publish a newer release and advance partitions to it; never decrement a
partition. See [versioning-and-channels.md](./versioning-and-channels.md) and
[signing-and-trust.md](./signing-and-trust.md).

---

## 12. End-to-end walkthrough

### 12.1 CURRENT (what works today)

```sh
# One-time
apr create acme --remote git@github.com:acme/registry.git

# Per release — nested-TOML model
apr publish /nix/store/<hash>-curl-8.5.0 \
    --description "URL transfer tool" --license MIT --maintainer acme
# → writes packages/c/curl.toml + closures/<hash>, then commits   (registry_ops.rs:476)

apr tag 2026.06.0 --message "June release"   # plain git tag; --key ignored  (registry_ops.rs:1696)
apr sign                                     # git commit --amend -S on HEAD (registry_ops.rs:1770)
apr push --set-upstream --branch main        # plain git push                (registry_ops.rs:1410)

# Local-only transport — git bundles, no manifest, no upload:
apr bundle --tag 2026.06.0                            # snapshot bundle (registry_ops.rs:1750)
apr bundle --delta-from 2026.05.0 --tag 2026.06.0     # delta bundle    (registry_ops.rs:1741)
# → files land in ./bundles/ ; publishing them to a mirror is out of scope
```

Everything after `apr push` is incomplete: the operator hand-copies bundles to a
mirror; there is no pack/delta/zstd, no `update-server-info`, no `http-alternates`,
no channel/partition tags, and no upload.

### 12.2 TARGET (the §10/§4/§6 pipeline, e.g. a future `apr release`)

```
build release commit  →  create + sign semver tag (refs/tags/<semver>, TOML message)
        │
        ▼  (immutable, content-addressed — idempotent, any order)
pack-objects:  full pack at X.Y.0  +  thin delta-<from>.pack(s)   [--no-reuse-* --window=350 --depth=50 --compression=0]
        →  zstd --ultra -22 --long=27 each .pack
        →  write loose objects under /release/X/Y/P/objects/
        →  per-release git update-server-info  (objects/info/packs: full pack only)
        │
        ▼  (mutable pointers — flipped LAST, after every object exists)
root git update-server-info  (info/refs, objects/info/packs)
write HEAD = ref: refs/heads/<default-channel>
regen /objects/info/http-alternates  (all /release/*/objects, newest→oldest)
bump refs/heads/<channel> → frontier
advance /channel/<name>/0..f  (N partitions → new semver tag; rest stay on prior)  [signed; name-bound]
        │
        ▼
upload with CDN TTLs:  /release/**, loose, packs = long/immutable
                       /objects/info/**, info/refs, HEAD, /channel/** = low TTL
```

Whether `apr` grows a single `apr release` / `apr publish` orchestrator that runs
this whole pipeline (commit → tag/sign → pack/delta/zstd → update-server-info →
advance partitions → upload), and whether upload backends are pluggable, is an
open question (design brief §16.4;
[open-questions.md](../plans/registry/open-questions.md)).

---

## 13. Cross-references

- [README.md](./README.md) — registry doc index and overview.
- [architecture.md](./architecture.md) — git-repo-over-dumb-HTTP; superset of git and Nix; asymmetric-cost philosophy.
- [current-state.md](./current-state.md) — full as-is grounding (the bundle/`creation_token` code).
- [http-layout.md](./http-layout.md) — the HTTP/object layout, CDN TTLs, `info/refs`/`HEAD`/`http-alternates`.
- [versioning-and-channels.md](./versioning-and-channels.md) — semver, channels-as-branches, frontier, the 16-partition rollout, bucket selection, anti-rollback.
- [packs-and-deltas.md](./packs-and-deltas.md) — the delta-scheme graph, client resolution + retention, `index-pack --fix-thin`, zstd.
- [tag-metadata.md](./tag-metadata.md) — the channel/release tag-message TOML schema (`[meta]` + `[[caches]]`).
- [signing-and-trust.md](./signing-and-trust.md) — signed tag objects, name-binding, `tag→tag→commit`, sha256, unsigned branch refs, `valid_until`.
- [nix-cache-compatibility.md](./nix-cache-compatibility.md) — the Nix binary-cache superset via relative `[[caches]]`.
- [apt-comparison.md](./apt-comparison.md) — git-native + dumb-HTTP vs APT signed-flat-file / `pool` / phased rollout.
- Plan: [design-brief.md](../plans/registry/design-brief.md) (§10, §4, §6 authoritative for this doc),
  [gap-analysis.md](../plans/registry/gap-analysis.md),
  [workstream-02-pack-delta-pipeline.md](../plans/registry/workstream-02-pack-delta-pipeline.md),
  [workstream-03-channels-rollouts.md](../plans/registry/workstream-03-channels-rollouts.md),
  [workstream-04-signing-trust.md](../plans/registry/workstream-04-signing-trust.md),
  [open-questions.md](../plans/registry/open-questions.md).
