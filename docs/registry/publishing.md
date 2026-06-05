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
   and sign the semver tag, generate the full/delta packs, write loose objects to
   the **root** `/objects/`, and regenerate the per-release pack indices. Everything
   here is **content-addressed and immutable** — once a sha256 object exists it never
   changes meaning.
2. **Flip the mutable pointers.** Regenerate the repo-root `info/refs` / `HEAD` /
   `objects/info/alternates`, bump `refs/heads/<channel>` to the frontier,
   and advance the signed `/channels/<name>/<00..ff>` partition tags. These are the
   *only* mutable surfaces, and they are published **last**, after every object
   they can possibly reference already exists at the origin.

```
                      PRODUCER (TARGET)                          CONSUMER
   ┌────────────────────────────────────────────────┐
   │ 1  build release commit                          │
   │ 2  create + sign semver tag  (refs/tags/<semver>)│
   │ 3  pack-objects → full + thin deltas → zstd      │   immutable, content-addressed
   │ 4  write loose objects under root /objects/      │──────────────────────────┐
   │ 5  per-release pack index (info/packs)           │                          │
   ├──────────────────────────────────────────────────┤   pointers, flipped LAST │
   │ 6  root update-server-info (info/refs, HEAD)      │                          ▼
   │ 7  regen objects/info/alternates                 │                  ┌────────────────┐
   │ 8  bump refs/heads/<channel> → frontier          │                  │  HTTP / CDN     │
   │ 9  advance /channels/<name>/00..ff partition tags  │─────────────────▶│  origin (dumb   │
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

## 2. CURRENT state — the `apr` producer surface

**CURRENT.** `apr` is the same binary as `aos`/`apm`, dispatched on `argv[0]`;
`apr …` expands to `package registry …`. All producer logic lives in
[`crates/aos-package/src/registry_ops.rs`](../../crates/aos-package/src/registry_ops.rs).
Today's tool operates on a *nested-TOML* registry (`packages/<x>/<name>.toml` +
`closures/<hash>`). The sha256 object-store scaffolding, signed release tags,
channel partition commands, `update-server-info`, and root
`objects/info/alternates` refresh hooks now exist. Pack/delta upload and static
Nix-cache generation are still pending.

The commands relevant to a release, in workflow order:

| Command | Function | What it actually does (CURRENT) |
|---|---|---|
| `apr create <name> [--remote URL]` | `create` (`registry_ops.rs:421`) | `git init --object-format=sha256`, set `HEAD` to `refs/heads/stable`, make `packages/`, write a default `registry.toml`, initial commit, then refresh dumb-HTTP object indexes; optional `git remote add origin`. |
| `apr publish <store-path> […]` | `publish` (`registry_ops.rs:476`) | Introspect the path, write `packages/<x>/<name>.toml`, compute + write `closures/<hash>`, then (unless `--no-commit`) `git add -A && git commit` and refresh `objects/info/alternates` + `update-server-info`. |
| `apr tag <name> [--message] --key <key>` | `tag` (`registry_ops.rs:1684`) | `git -c gpg.format=ssh -c user.signingkey=<key> tag -s <name> -m … HEAD`; `--key` is required; semver tags also prepare a release object dir during the object-store refresh. |
| `apr sign <tag> --key <key>` | `sign` (`registry_ops.rs:1747`) | Re-signs an existing release tag as a signed tag object with `git tag -s -f`, then refreshes dumb-HTTP object indexes; it no longer signs commits. |
| `apr channel init/advance/status` | `run_channel` (`registry_ops.rs`) | Initializes or advances raw signed partition tag files under `channels/<name>/00..ff`, updates `refs/heads/<channel>` to the frontier, and reports partition counts. |
| `apr push [--branch] [--set-upstream] [--force]` | `push` (`registry_ops.rs:1398`) | `git push [-u origin] [branch] [--force]`. |

There is **no** `apr release`, no pack/delta generation, and no upload command
in the tree today.

### 2.1 CURRENT: transport/index refresh

The producer now refreshes the git-native static index after create, publish,
unpublish, tag, sign, and channel operations. The refresh path updates
`objects/info/alternates` and `info/refs` so a dumb-HTTP origin can be served as
static files. Pack generation helpers exist in `registry::pack`, but the
single-command release pipeline that generates, uploads, and validates every
pack/Nix-cache artifact remains target work.

---

## 3. Inputs and outputs of one release

**TARGET.** A single release publish is parameterized by:

| Input | Meaning |
|---|---|
| `<semver>` | Standard semver, **no `v` prefix** (`1.2.0`, `1.0.0-beta+exp.sha.5114f85`). |
| release commit | The commit the semver tag points at (the new registry tree content). |
| `<channel>` | The release line being advanced (e.g. `stable`, `testing`). |
| partition plan | How many of the 256 partitions `00..ff` advance to `<semver>` this publish (rollout fraction). |
| signing key | One SSH-format Ed25519 key (reused from `apr sign` / `security.rs`). |

It produces, under [the HTTP/object layout](./http-layout.md):

```
/releases/<major>/<minor>/<patch[-prerelease][+build]>/
  objects/
    info/packs                       ← lists this release's self-contained pack(s)
    pack/pack-<sha256>.pack (+ .idx)  ← full pack (only at X.Y.0 anchors)
    pack/delta-<from-semver>.pack[.zst] ← THIN deltas (AOS-only; NOT in info/packs)
                                        (PACK-ONLY: no loose <xx>/<…>, no info/alternates)
/objects/<xx>/<62-hex>                ← ALL loose objects (every release), centralized at root
refs/tags/<semver>                    ← signed tag → release commit          [via info/refs]
/channels/<name>/<00..ff>              ← signed partition tags advanced per the rollout plan
refs/heads/<channel>                  ← branch head bumped to the frontier
/objects/info/{packs,alternates}     ← repo-root indices regenerated
/info/refs, /HEAD                     ← regenerated via update-server-info
```

The third `/releases` path segment is **everything after `major.minor`** — e.g.
`1.0.0-beta+exp.sha.5114f85` → `/releases/1/0/0-beta+exp.sha.5114f85/`.

---

## 4. Step 1–2 — build commit, create + sign the semver tag

**TARGET.**

1. **Build the release commit.** The registry tree content (the package TOML
   tree, the same content model the current code already writes) is committed in
   the bare sha256 repo. All git operations use sha256
   (`git init --object-format=sha256`; design brief §8). The release commit is
   what `refs/tags/<semver>` will point at and what every pack is computed over.

2. **Create the annotated, signed semver tag.** An **annotated git tag** that is a
   **pure signed pointer** — the standard git tag fields (`object`, `type`, the tag
   **name**, `tagger`) plus an SSH-format Ed25519 signature on the tag *object*, plus
   an **optional freeform human message**. The tag carries **no structured payload**
   and no in-band `valid_until`. Cache locations and
   freshness are **not** advertised in the tag (see §1 and §4 of [signing-and-trust.md](./signing-and-trust.md)).

   The tag **name** is the bare semver (`1.2.0`), the signature lives on the tag
   *object*, and the embedded tag-name field is bound to the serving path during
   verification (see §10 and [signing-and-trust.md](./signing-and-trust.md)).
   The signing primitive is the existing SSH-format Ed25519 git signature reused
   from `apr sign` (`git`-resolved `user.signingkey` + `gpg.format = ssh`;
   `security.rs` `parse_signing_key` `name:Ed25519:<base64>`).

Release tags carry no in-band expiry, which fits releases being
immutable and carrying a long CDN TTL. Freshness is enforced out of band — low CDN
TTL on `/channels` (and `info/refs`, `objects/info`), the consumer's own
max-staleness policy, and the monotonic anti-rollback floor — rather than a signed
`valid_until` inside the tag. The trade-off: this is weaker than an in-band signed
expiry against a frozen-but-validly-signed mirror.

The Nix binary-cache / NAR substituter location lives in the committed repo-root
`registry.toml` `[[caches]]` (a tree file authenticated transitively by the signed
tag), with the consumer's client-side `registries.d/<name>.toml` as an optional
override/supplement — never embedded in the signed tag itself. The origin **MAY**
serve `nix-cache-info` / `<storehash>.narinfo` / `nar`
as the stock-nix superset; narinfo signing reuses the one Ed25519 key.

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

## 6. Step 4–5 — loose objects + per-release pack index

**TARGET.**

- **Write loose objects to the root.** **ALL** objects (every release) exist loose
  under the single root `/objects/<xx>/<62-hex>` (the sha256 2/62 split) — this is
  the guaranteed completeness fallback; packs are an optimization on top
  (design brief §8). Loose objects are **centralized at the root only**; the
  per-release `/releases/<major>/<minor>/<patch>/objects/` dirs are **pack-only**
  (they hold `info/packs` + `pack/*` and contain **no** loose `<xx>/<…>` objects and
  **no** per-release `info/alternates`).

- **Per-release pack index.** Regenerate the per-release `objects/info/packs`
  (listing this release's self-contained full pack only — never the thin deltas) for
  the release's pack dir. This makes the per-release directory a valid dumb-HTTP
  **pack source** that the root `info/alternates` chain can stitch together for pack
  discovery — object completeness itself comes from the centralized root
  `/objects/`.

Because release objects are content-addressed sha256, **writing the same object
twice is idempotent** — a re-run or a concurrent publisher writing the same bytes
is a no-op. This is what makes step 3/4 safe to retry freely (§11).

---

## 7. Step 6–7 — root `update-server-info` + `info/alternates`

**TARGET.** With every immutable object in place, regenerate the *repo-root*
mutable indices that make the whole thing a valid dumb-HTTP bare repo:

1. **`git update-server-info`** regenerates `/info/refs` (the full
   `refs/heads/<channels>` + `refs/tags/<semvers>` listing) and the root
   `/objects/info/packs`. A stock `git clone <url>` works off these
   (design brief §8, §12).

2. **`/HEAD`** is written as `ref: refs/heads/<default-channel>` (e.g.
   `ref: refs/heads/stable`) so a default clone lands on the default channel
   branch.

3. **`/objects/info/alternates`** is regenerated to list **every**
   `/releases/*/objects/` directory, **newest → oldest**, as **relative** paths.
   Each entry is `../releases/<M>/<m>/<patch…>/objects/` — git resolves relative
   alternates against the repo's `objects/` URL, so the single `../` strips the
   `objects` segment to reach the repo root (therefore the correct depth is **one**
   `../`, not two). The file is **host-independent** — byte-identical across
   CDN / mirror / localhost, with no hostname baked in. The dumb-HTTP walker reads
   `http-alternates` then falls back to `alternates`, so this one relative
   `info/alternates` works for **HTTP and local-FS** alike. Because loose objects
   are centralized at the root `/objects/`, the alternates now serve **pack
   discovery + the release index**, not object completeness (design brief §8).

```
# /objects/info/alternates  (newest → oldest, relative, host-independent)
../releases/1/2/0/objects/
../releases/1/1/3/objects/
../releases/1/1/0/objects/
../releases/1/0/0/objects/
…
```

These four files (`info/refs`, `HEAD`, `objects/info/packs`,
`objects/info/alternates`) are **mutable** and therefore **low TTL** (§9).

---

## 8. Step 8–9 — frontier branch head + partition rollout

**TARGET.** The ref/rollout model has three layers
(see [versioning-and-channels.md](./versioning-and-channels.md) and
[signing-and-trust.md](./signing-and-trust.md)):

| Path / ref | What | Signed? |
|---|---|---|
| `refs/heads/<channel>` | **channels are branches**; head = **frontier** (newest release any partition targets) | no (unsigned convenience pointer) |
| `refs/tags/<semver>` | release: signed tag → commit | **yes** |
| `/channels/<name>/<00..ff>` | 256 signed partition tag objects (tag name == channel) → semver tag | **yes** |

### 8.1 Bump the frontier branch head

`refs/heads/<channel>` is set to the commit of the **newest release any partition
targets** — the rollout *target* (frontier). Implication: a stock `git pull
<channel>` always gets the frontier (no rollout protection), which is acceptable
because rollout is an AOS-fleet concept, not a git-clone concept (design brief
§6). The branch ref is an **unsigned** pointer and is never part of the trust
chain.

### 8.2 Advance the 256 partition tags (publisher-controlled rollout)

A channel exposes **exactly 256** partition files `/channels/<name>/00..ff`, each an
**independently-signed** annotated tag object whose **tag name == the channel
name**, pointing at a semver tag. There must always be 256 present.

**To roll a new release to N/256 of the fleet:** point N partitions at the new
semver tag and **leave the rest on the prior release**. This is the explicit
answer to "where does the rest of the fleet go" — the un-advanced partitions
still name the prior release. Advance partitions as confidence grows; completion
= all 256 point at the new release (design brief §6).

```
  rollout fraction      /channels/stable/00..ff  →  semver tag
  ────────────────      ────────────────────────────────────
  0/256  (none yet)     00 01 02 … fd fe ff → 1.1.3
  4/256  (early ring)   00 01 02 03         → 1.2.0   (new)
                        04 05 … fd fe ff    → 1.1.3   (prior)
  256/256 (complete)    00 01 02 … fd fe ff → 1.2.0
```

Each advanced partition is a **fresh signed tag object** (`tag → tag → commit`:
channel partition tag → semver tag → release commit). The signature and the
embedded tag-name field (`== <channel>`) bind it to its `/channels/<name>/<bucket>`
serving path. See [signing-and-trust.md](./signing-and-trust.md).

**Aborting a bad rollout is fix-forward** (publish a newer release and point
partitions at it), never partition-decrement: the consumer's monotonic floor
(anti-rollback) would block a decrement anyway (design brief §6).

> Consumers self-select a bucket deterministically (e.g.
> the low byte of `sha256(machine_id)` (i.e. mod 256), persisted) and probe-forward `(bucket+1) mod 256`
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
| `/objects/<xx>/<…>` (loose), `/releases/**/pack/*` | immutable (content-addressed) | **very high** (`MAY`) |
| `/releases/**` (the whole subtree) | immutable after publish | **long** (`MAY`) |
| `/objects/info/**` (`packs`, `alternates`), per-release `objects/info/**` | mutable on publish | **low** (`MUST`) |
| `/info/refs`, `/HEAD` | mutable on publish | **low** (`MUST`) |
| `/channels/**` | mutable on rollout | **low** (`MUST`) — fast rollout updates |

The asymmetry is intentional: `/channels/**` and the `info/*` indices must turn
over quickly so a rollout or a new frontier is visible promptly, while the bulk
bytes (`/releases/**`, loose objects, packs) are immutable and may be cached
aggressively forever. If the CDN supports cache invalidation, invalidate the
low-TTL paths on publish; otherwise the short TTL bounds staleness.

---

## 10. Verification the producer must satisfy (name-binding)

**TARGET.** The producer signs so that the consumer's trust chain holds. AOS
verification is **`signed partition tag → signed semver tag → commit`**, checking
**both** the signature **and** the embedded tag-name field against the expected
name:

- under `/channels/<name>/*` the embedded tag name **must** equal `<name>` (the
  channel);
- under `/releases/*` (i.e. `refs/tags/<semver>`) the embedded tag name **must**
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
  1–4    release commit, semver tag, packs,   immutable (CA)    idempotent;
         deltas, root /objects loose objects                    retry freely, any order
  5      per-release objects/info/packs       low-TTL index     regenerated from immutable set
  6–7    info/refs, HEAD,                      MUTABLE pointer   flipped only AFTER 1–5 exist
         objects/info/alternates
  8      refs/heads/<channel> (frontier)       MUTABLE pointer   flipped after release objects
  9      /channels/<name>/00..ff partition tags MUTABLE pointer   flipped LAST (rollout gate)
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
conditional-PUT / `If-Match` on the `/channels/**` objects at the origin); the
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

apr tag 2026.06.0 --message "June release" --key ./registry_signing_key
apr sign 2026.06.0 --key ./registry_signing_key
apr channel init stable --release 2026.06.0 --key ./registry_signing_key
apr channel advance stable --release 2026.06.0 --count 32 --key ./registry_signing_key
apr push --set-upstream --branch stable        # plain git push              (registry_ops.rs:1398)
```

Everything after `apr push` is still incomplete for CDN publication: there is no
single pack/delta/zstd upload pipeline and no static Nix-cache generator.

### 12.2 TARGET (the §10/§4/§6 pipeline, e.g. a future `apr release`)

```
build release commit  →  create + sign semver tag (refs/tags/<semver>, pure signed pointer + optional message)
        │
        ▼  (immutable, content-addressed — idempotent, any order)
pack-objects:  full pack at X.Y.0  +  thin delta-<from>.pack(s)   [--no-reuse-* --window=350 --depth=50 --compression=0]
        →  zstd --ultra -22 --long=27 each .pack
        →  packs under /releases/X/Y/P/objects/pack/  ;  loose objects under root /objects/
        →  per-release pack index  (objects/info/packs: full pack only)
        │
        ▼  (mutable pointers — flipped LAST, after every object exists)
root git update-server-info  (info/refs, objects/info/packs)
write HEAD = ref: refs/heads/<default-channel>
regen /objects/info/alternates  (all /releases/*/objects, newest→oldest, relative one-"../")
bump refs/heads/<channel> → frontier
advance /channels/<name>/00..ff  (N partitions → new semver tag; rest stay on prior)  [signed; name-bound]
        │
        ▼
upload with CDN TTLs:  /releases/**, loose, packs = long/immutable
                       /objects/info/**, info/refs, HEAD, /channels/** = low TTL
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
- [current-state.md](./current-state.md) — current git-native implementation status.
- [http-layout.md](./http-layout.md) — the HTTP/object layout, CDN TTLs, `info/refs`/`HEAD`/`info/alternates`.
- [versioning-and-channels.md](./versioning-and-channels.md) — semver, channels-as-branches, frontier, the 256-partition rollout, bucket selection, anti-rollback.
- [packs-and-deltas.md](./packs-and-deltas.md) — the delta-scheme graph, client resolution + retention, `index-pack --fix-thin`, zstd.
- [signing-and-trust.md](./signing-and-trust.md) — signed tag objects (pure signed pointers), name-binding, `tag→tag→commit`, sha256, unsigned branch refs.
- [nix-cache-compatibility.md](./nix-cache-compatibility.md) — the Nix binary-cache superset located via the committed `registry.toml` `[[caches]]` (client-side `registries.d` as optional override).
- [apt-comparison.md](./apt-comparison.md) — git-native + dumb-HTTP vs APT signed-flat-file / `pool` / phased rollout.
- Plan: [design-brief.md](../plans/registry/design-brief.md) (§10, §4, §6 authoritative for this doc),
  [gap-analysis.md](../plans/registry/gap-analysis.md),
  [workstream-02-pack-delta-pipeline.md](../plans/registry/workstream-02-pack-delta-pipeline.md),
  [workstream-03-channels-rollouts.md](../plans/registry/workstream-03-channels-rollouts.md),
  [workstream-04-signing-trust.md](../plans/registry/workstream-04-signing-trust.md),
  [open-questions.md](../plans/registry/open-questions.md).
