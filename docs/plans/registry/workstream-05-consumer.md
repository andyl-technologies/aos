# Workstream 05 — Consumer resolution & fetch

> **Status:** Implementation plan / **TARGET** design. As-is code behaviour is
> labelled **CURRENT** and cited as `path:line`; the git-native goal is labelled
> **TARGET**. Where the code contradicts the brief, the code wins for *current
> state* and the brief wins for *target intent*; discrepancies are logged in
> [open-questions.md](./open-questions.md).
>
> **Audience:** implementers, architects, engineers.
>
> **Grounding:** [design-brief.md](./design-brief.md) **§6** (channels &
> rollouts), **§9** (packs & the delta scheme — client resolution + retention),
> **§11** (signing & trust — name-binding), and **§13** (Nix `[[caches]]`
> superset). The brief is authoritative for intent; this doc translates that
> intent into a concrete change set on the `apm update` / `apm upgrade` path.

This is the `apm`-side counterpart to the producer workstreams
([01 object store](./workstream-01-object-store.md),
[02 pack/delta pipeline](./workstream-02-pack-delta-pipeline.md),
[03 channels & rollouts](./workstream-03-channels-rollouts.md),
[04 signing & trust](./workstream-04-signing-trust.md)). The consumer **only
reads static files over dumb HTTP** — there is no server-side cooperation, no
smart-protocol negotiation, and (per [§15 of the brief](./design-brief.md#15-removed-from-the-target-do-not-document-as-target))
**no `registry.toml`, no `bundle-list.toml`, no git bundles, and no
`creation_token`**. The consumer's job is six steps:

1. **Bucket selection** — deterministically self-select one of 256 partitions.
2. **Tag-chain resolution** — `/channel/<name>/<bucket>` signed tag → semver tag
   → commit.
3. **Chain verification** — verify both signatures *and* the name-binding of each
   tag object to its serving path (§11).
4. **Anti-rollback** — refuse a target older than the monotonic floor.
5. **Delta-walk fetch** — pick a thin `delta-*.pack` whose base is retained, walk
   backward otherwise, fall to full pack, fall to loose objects; complete with
   `git index-pack --fix-thin`; apply retention.
6. **Nix `[[caches]]` wiring** — read the tag-message TOML's `[[caches]]` (which
   may be relative) and register it for NAR substitution.

---

## 1. Where this sits in the plan

```
 WS-01 object store ─┐
 WS-02 pack/delta   ─┤  produce the static surface the consumer reads
 WS-03 channels     ─┤  (256 signed partition tags, frontier branch head)
 WS-04 signing      ─┘
        │
        ▼
 WS-05 CONSUMER  ◄── THIS doc: read-only resolution + fetch + verify + cache wiring
```

The consumer depends on the entire producer surface but adds **no new network
surface**: every byte it reads is a static file already specified by WS-01/02/03.
It re-uses the existing Ed25519/SSH verification primitives (WS-04,
`security.rs`) for the tag-chain check.

---

## 2. CURRENT state (as-is, grounded in code)

> **CURRENT.** Today's consumer fetches a `bundle-list.toml` manifest, selects
> git **bundles** by `creation_token`, unbundles them into a local repo, extracts
> package TOMLs, and persists a `creation_token` floor. None of bucket selection,
> the 256-partition tag chain, thin `delta-*.pack` walking, or `[[caches]]`-from-
> tag-message exist. This section maps the surfaces WS-05 replaces.

### 2.1 The sync entry point

`apm update` runs `update::run`
([`update.rs:37`](../../../crates/aos-package/src/update.rs)), which loops over
enabled registries and dispatches on `Transport`
([`update.rs:115`](../../../crates/aos-package/src/update.rs)):
`Transport::HttpBundle` → `sync_bundle`
([`update.rs:193`](../../../crates/aos-package/src/update.rs)), `Transport::Git`
→ `git::sync_git`. The bundle path is what the git-native model replaces.

### 2.2 Bundle selection — `pick_bundles`

`pick_bundles` ([`update.rs:292`](../../../crates/aos-package/src/update.rs)) is
the CURRENT analogue of the TARGET delta-walk. Its three-strategy logic —

```
1. skip delta from current minor base (update.rs:367-376)
2. sequential deltas current→latest (update.rs:378-384)
3. fall back to the latest snapshot (update.rs:386-390)
```

— is structurally the right shape (prefer a single big delta, else a chain, else
a self-contained pack), but it operates on `BundleEntry`s keyed by
`creation_token` and `target_tag`, not on git thin packs keyed by semver. The
TARGET replaces the *unit* (bundle → thin `delta-*.pack`), the *index* (manifest
→ git object store + `http-alternates`), and the *ordering key* (`creation_token`
→ semver + git ancestry), while keeping the prefer-delta-then-full-then-loose
shape.

### 2.3 Tracking modes — the resolution surface

`TrackingMode` ([`types.rs:282`](../../../crates/aos-package/src/types.rs)) has
five arms — `Commit`, `Branch`, `Tag`, `Version(VersionReq)`, `Default` —
resolved by `RegistryConfig::tracking_mode()`
([`types.rs:352`](../../../crates/aos-package/src/types.rs)). There is **no
`Channel` arm** and no notion of a 256-partition bucket. WS-05 adds channel
resolution; the existing `Tag` / `Version` arms remain valid stock-git-style
pins against `refs/tags/<semver>` and are reused once a channel collapses to a
concrete semver tag.

### 2.4 Anti-rollback — `check_monotonic`

`check_monotonic`
([`state.rs:104`](../../../crates/aos-package/src/registry/state.rs)) rejects
`new_token <= old_token`. It is the right *idea* (a monotonic floor) on the wrong
*key*: it compares calendar `creation_token`s via
`version_to_token`/`token_to_version`
([`state.rs:131`](../../../crates/aos-package/src/registry/state.rs),
[`state.rs:173`](../../../crates/aos-package/src/registry/state.rs)), which the
TARGET deletes (§15). Worse, the CURRENT call site is gated behind
`if latest_token > old_token`
([`update.rs:263`](../../../crates/aos-package/src/update.rs)) — so the check
only runs when the new token is *already greater*, i.e. exactly the case that is
**not** a downgrade. A genuine rollback (`latest_token <= old_token`) skips the
guard entirely. WS-05 reimplements the floor on **semver** and **fixes the
gating bug** (see §7).

### 2.5 Persisted state

`RegistryState { last_commit, last_creation_token, last_update }`
([`types.rs:255`](../../../crates/aos-package/src/types.rs)) is persisted under
`[registry.state]` and rewritten after each sync
([`update.rs:270`](../../../crates/aos-package/src/update.rs)) via
`state::save_state` ([`state.rs:37`](../../../crates/aos-package/src/registry/state.rs)).
WS-05 **retires `last_creation_token`** and adds a semver floor, a persisted
bucket, and a retained-release set (§3.5, §7).

---

## 3. TARGET — the consumer resolution pipeline

### 3.1 End-to-end flow

```
apm update / apm upgrade
│
├─ 1. bucket   = persisted_bucket  ||  the low byte of sha256(machine_id) (i.e. mod 256)      (§4)
│
├─ 2. fetch    /channel/<name>/<bucket>        (signed partition tag object)
│        │        └─ missing? probe-forward (bucket+1) mod 256          (§4.3)
│        ▼
│      partition_tag ──verify sig + name-binds "<name>"── (§6)
│        │  (tag → tag)
│        ▼
│      semver_tag    ──verify sig + name-binds "<semver>"── (§6)
│        │  (tag → commit)
│        ▼
│      target_commit
│
├─ 3. anti-rollback: semver(target) >= floor ?  ── no ─► REFUSE       (§7)
│
├─ 4. fetch objects for target_commit:                                 (§5)
│        prefer delta-<B>.pack with retained base B
│        else walk releases backward to a usable delta or full pack
│        else fetch full pack
│        else loose objects over dumb HTTP (always correct)
│      complete thin packs with `git index-pack --fix-thin`
│
├─ 5. checkout commit → extract packages/  (reuse git::extract today)
│
├─ 6. retention: keep object trees for X.0.0 / X.Y.0 / X.Y.Z          (§5.4)
│
├─ 7. parse target's tag-message TOML  →  register [[caches]]          (§8)
│
└─ 8. persist state: floor=semver, bucket, retained set                (§3.5)
```

Every fetch in step 4 is a static GET; the loose-object tier guarantees the whole
flow is **always completable** even if every pack is missing or corrupt.

### 3.2 What the consumer reads (recap of the static surface)

| URL | Purpose | Verify |
|---|---|---|
| `/channel/<name>/<bucket>` | signed partition tag → semver tag | sig + name == `<name>` |
| `refs/tags/<semver>` (via `info/refs`) | signed release tag → commit | sig + name == `<semver>` |
| `objects/info/http-alternates` | all `/release/*/objects` dirs, newest→oldest; doubles as release index | — |
| `/release/<M>/<m>/<p…>/objects/info/packs` | self-contained full packs only | idx self-check |
| `/release/<M>/<m>/<p…>/objects/pack/delta-<from>.pack[.zst]` | thin AOS deltas (NOT in `info/packs`) | `index-pack --fix-thin` |
| `/release/<M>/<m>/<p…>/objects/<xx>/<62hex>` | loose objects (sha256 2/62) | sha256 == path |

See [`http-layout.md`](../../registry/http-layout.md) and
[`packs-and-deltas.md`](../../registry/packs-and-deltas.md) for the full layout.

### 3.3 The tag chain — `tag → tag → commit`

```
/channel/stable/b7  ──►  signed partition tag object
   tag name: "stable"                      (name-binds the channel)
   target:   refs/tags/1.4.2  ─────────────┐
                                           ▼
refs/tags/1.4.2   ──►  signed release tag object
   tag name: "1.4.2"                        (name-binds the semver)
   target:   <commit sha256>  ─────────────┐
                                           ▼
                                       release commit
                                       (tree = packages/ + closures/)
```

Both tag objects are SSH-format Ed25519 annotated tags; only the commit carries
content. Branch refs (`refs/heads/<channel>` = the **frontier**) are **never**
read for the trust chain — a stock `git pull <channel>` gets the frontier, but
the AOS consumer's rollout-respecting target comes from the **partition tag**.

### 3.4 Why bucket, not branch head

`refs/heads/<channel>` points at the **frontier** (newest release any partition
targets, [§6](./design-brief.md#6-channels--rollouts)). Following it would defeat
rollout — every host would jump straight to the newest release. The AOS consumer
therefore resolves through `/channel/<name>/<bucket>`, which the publisher
advances **per-partition** to control blast radius. The branch head is a
stock-git convenience pointer only.

### 3.5 Persisted state changes

```toml
# registries.d/<name>.toml  →  [registry.state]   (TARGET)
[registry.state]
last_commit  = "…sha256…"        # KEEP
floor        = "1.4.2"           # NEW: monotonic semver anti-rollback floor (§7)
bucket       = 183               # NEW: persisted partition (0..255), written once (§4)
retained     = ["1.0.0", "1.4.0", "1.4.2"]  # NEW: object-tree retention set (§5.4)
last_update  = "2026-06-04T00:00:00Z"   # KEEP
# last_creation_token  →  REMOVED (calendar scheme deleted, §15)
```

`state::save_state` ([`state.rs:37`](../../../crates/aos-package/src/registry/state.rs))
already preserves user-edited fields and rewrites only the `[registry.state]`
block; WS-05 extends its serializer (it currently emits `last_commit`,
`last_creation_token`, `last_update` at
[`state.rs:43-51`](../../../crates/aos-package/src/registry/state.rs)) to swap
`last_creation_token` for `floor` and add `bucket` / `retained`.

---

## 4. Bucket selection (consumer self-partitioning)

> **TARGET.** Per [brief §6](./design-brief.md#6-channels--rollouts): a channel
> exposes exactly **256** partitions `/channel/<name>/00..ff`; the consumer
> deterministically self-selects **one** bucket and **persists** it so a host
> never flaps between buckets across updates.

### 4.1 Selection function

```text
bucket = the low byte of sha256(machine_id) (i.e. mod 256)            # 0..=255, rendered as one byte (two hex digits, 00–ff)
```

- **`machine_id`** source: `/etc/machine-id` (default). The exact input and any
  per-install override seed are [open question §16.3](./design-brief.md#16-open-questions--to-confirm-in-implementation).
- **Persist once.** On first resolution, compute and write `bucket` into
  `[registry.state]` (§3.5). On every subsequent update, read the persisted
  value. This is what makes a host *stick* — recomputing each time would be
  equivalent but persistence documents intent and survives a machine-id change.
- **Hex rendering.** Each bucket renders as one byte (two lowercase hex digits)
  for the partition file name — the channel directory is `00 01 02 … fe ff`.

### 4.2 Why deterministic self-selection

The publisher controls rollout by advancing *N of 256* partition tags to a new
semver and leaving the rest on the prior release (§6 of the brief). The consumer
controls *which* partition it reads, deterministically, so:

- a given host always lands on the same partition → no flapping;
- the fleet is evenly spread across 256 buckets (uniform hash);
- rollout fraction is `N/256` and is observable to the publisher.

### 4.3 Missing-partition probe-forward

There **must** always be 256 partition files. If one is missing (mid-publish, CDN
gap), the consumer **may** probe forward deterministically:

```text
b = bucket
for i in 0..256:
    try fetch /channel/<name>/((b + i) mod 256)
    if present and verifies: use it; stop
fail closed if none of 256 resolve
```

Probe-forward order is fixed (`(bucket+i) mod 256`) so the fallback is itself
deterministic and does not re-introduce flapping. The fallback order is
[open question §16.3](./design-brief.md#16-open-questions--to-confirm-in-implementation).

---

## 5. Delta-walk fetch & retention

> **TARGET.** Per [brief §9](./design-brief.md#9-packs--the-delta-scheme): a
> guaranteed, walkable delta graph the producer commits to, so the client can
> *plan* its fetch. The consumer always has a correct fallback (loose objects).

### 5.1 The guaranteed delta graph (what the consumer can rely on)

The producer ships exactly these per release (consumer planning assumptions):

| Release kind | Full pack? | Deltas shipped |
|---|---|---|
| `X.Y.0` (major or minor) | **yes** (`pack-<sha256>.pack` + `.idx`) | see major/minor rows |
| `X.0.0` (major) | yes | `delta-<(X-1).0.0>.pack` |
| `X.Y.0` (minor, Y>0) | yes | `delta-<X.(Y-1).0>.pack`, `delta-<X.0.0>.pack` |
| `X.Y.Z` (patch, Z>0) | **no** | `delta-<X.Y.(Z-1)>`, `delta-<X.Y.(Z-2)>`, `delta-<X.Y.(Z-3)>` (where they exist), `delta-<X.Y.0>` |

Patch releases have **no** full pack; they always have a delta back to the current
minor base, which the retention rule guarantees the client holds.

### 5.2 Client resolution algorithm (current C → target T)

```text
resolve_objects(from C, to T):
  # 1. prefer a delta at T whose base we retain
  for B in deltas_at(T) ordered nearest-base-first:
      if B in retained:
          fetch delta-<B>.pack[.zst]   →  index-pack --fix-thin   →  DONE

  # 2. walk releases backward looking for a usable delta or a full pack
  for R in releases_between(T, C) newest→oldest (via http-alternates):
      if R is X.Y.0 and full pack present:
          fetch pack-<sha256>.pack (+ .idx)
          then walk forward applying deltas R → … → T          →  DONE
      if some delta-<B>.pack at R has B in retained:
          fetch it, then continue toward T                      →  DONE

  # 3. no usable delta path: fetch the nearest full pack outright
  fetch the X.Y.0 full pack covering T's minor, then deltas to T →  DONE

  # 4. last resort: loose objects over dumb HTTP (ALWAYS correct)
  enumerate missing objects, GET /release/*/objects/<xx>/<62hex> →  DONE
```

- **Cross-major jumps** degrade to "minor-base full pack + walk": fetch the
  `X.Y.0` full pack of the target's minor, then apply the patch deltas up to `T`.
- **Loose-object fallback** is unconditional correctness: ALL objects exist loose
  under `/objects/<xx>/<…>` ([brief §8](./design-brief.md#8-object-store--dumb-http-details)),
  resolved across per-release stores via `objects/info/http-alternates`. A sha256
  loose object is self-verifying (content hash == path).

This is the TARGET shape of the CURRENT `pick_bundles` three-strategy logic
([`update.rs:367-390`](../../../crates/aos-package/src/update.rs)): prefer one
big delta (skip → "delta whose base we retain"), else a chain (sequential →
"walk backward"), else a self-contained artifact (snapshot → "full pack"), with a
new unconditional loose-object floor.

### 5.3 Thin-pack completion — `index-pack --fix-thin`

Thin `delta-*.pack`s reference objects in the base that are **not** in the pack.
The client materialises them:

```sh
# uncompressed thin delta
git index-pack --fix-thin --stdin < delta-1.4.1.pack
# zstd-wrapped thin delta (producer ships .pack.zst, brief §10)
zstd -d --long=27 -c delta-1.4.1.pack.zst | git index-pack --fix-thin --stdin
```

`--fix-thin` appends the referenced base objects (which the client already holds,
because they are *retained*, §5.4) and writes the completed `.pack` + `.idx`.
Thin deltas ship **without** an `.idx` ([brief §10](./design-brief.md#10-pack-generation-producer--zstd));
the client builds it. Full packs ship **with** an `.idx` and are applied with a
plain `git index-pack` (no `--fix-thin`).

### 5.4 Retention (co-designed with the delta scheme)

> **TARGET.** Per [brief §9](./design-brief.md#9-packs--the-delta-scheme): a
> client on `X.Y.Z` keeps object trees for at least **`X.0.0`** (current major),
> **`X.Y.0`** (current minor), and **`X.Y.Z`** (current patch).

```
on X.Y.Z, retained = { X.0.0, X.Y.0, X.Y.Z }
```

This is **co-designed** with §5.1: every delta the producer ships has a base in
exactly this set — patch deltas base on `X.Y.(Z-k)` and `X.Y.0`; minor deltas on
`X.(Y-1).0` and `X.0.0`; major deltas on `(X-1).0.0`. So `resolve_objects` step 1
("delta whose base we retain") almost always succeeds in one fetch. After a
successful update to `T = X.Y.Z`, recompute `retained`, prune object trees no
longer in the set, and persist the set (§3.5).

> **Note on the retained set size.** Three trees is the *minimum*; a client MAY
> keep more (e.g. the last few patches) to widen the single-fetch window, at a
> disk-space cost. The minimum guarantees a base is always present without
> requiring history beyond the current major/minor/patch.

### 5.5 Stock-git graceful degradation (for contrast)

A stock dumb `git clone` of a patch release cannot apply thin packs (they are not
in `info/packs`), so it pulls the **minor-base full pack** via `http-alternates`
plus the patch's **loose new objects** — no AOS logic, no thin packs, still
correct ([brief §9](./design-brief.md#9-packs--the-delta-scheme),
[§12](./design-brief.md#12-stock-git-dumb-http-compatibility)). The AOS consumer
is strictly faster (thin deltas) but degrades to exactly this path via the
loose-object floor.

---

## 6. Chain verification (name-binding)

> **TARGET.** Per [brief §5](./design-brief.md#5-ref-model--three-layers) and
> [§11](./design-brief.md#11-signing--trust): AOS verification is
> `signed partition tag → signed semver tag → commit`, checking the **signature**
> *and* the embedded **tag-name field** against the expected name. This binds a
> tag object to its serving path and prevents cross-serving.

### 6.1 The two checks, applied to each tag object

| Tag object | Signature check | Name-binding check |
|---|---|---|
| `/channel/<name>/<bucket>` | Ed25519/SSH valid against a trusted key | embedded tag name `== "<name>"` (the channel) |
| `refs/tags/<semver>` | Ed25519/SSH valid against a trusted key | embedded tag name `== "<semver>"` (the release) |

The **name-binding** is what stops a valid-but-misfiled tag from being honoured:
a partition tag signed for channel `testing` served under `/channel/stable/3f`
fails because its embedded name is `testing`, not `stable`. Likewise a release
tag whose embedded name is `1.4.1` cannot be served from the `1.4.2/` release
path. This closes cross-serving without any server-side enforcement — the
consumer rejects the mismatch.

### 6.2 Reusing existing signing primitives

WS-05 reuses the WS-04 / `security.rs` Ed25519 verification (`git verify-tag`
analogue + `allowed_signers` / `trusted-keys.d/<registry>.pub`, TOFU,
`parse_signing_key` `name:Ed25519:<base64>`). The CURRENT code already verifies
SSH-format Ed25519 git signatures (commits, via `git verify-commit`); the TARGET
applies the same primitive to **tag objects** (`git verify-tag`) and adds the
name-binding string comparison on the parsed tag header. The tag-message **TOML**
([`tag-metadata.md`](../../registry/tag-metadata.md)) is parsed *after* signature
verification, never before.

### 6.3 Verification ordering (fail-closed)

```text
1. fetch partition tag  → verify sig → check name == channel   (else REJECT)
2. follow to semver tag → verify sig → check name == semver     (else REJECT)
3. follow to commit     (commit content is hash-addressed; objects self-verify)
4. parse semver tag-message TOML  (valid_until freshness, [[caches]])  (§8, §7)
5. only now is the target commit trusted enough to fetch & check out
```

No body is parsed and no objects are checked out before the full chain verifies.
Branch refs are **never** consulted in this chain (they are unsigned, §5/§11 of
the brief).

---

## 7. Anti-rollback (monotonic semver floor)

> **TARGET.** Per [brief §6](./design-brief.md#6-channels--rollouts): a consumer
> keeps a **monotonic floor** and never moves to a release older than its current
> one. Aborting a bad rollout is **fix-forward** (publish a newer release, advance
> partitions), never partition-decrement — the floor would block a decrement
> anyway.

### 7.1 The floor on semver

```text
floor = persisted [registry.state].floor   (a semver, e.g. "1.4.2")

on resolving target T:
    if semver(T) <  floor:   REFUSE (anti-rollback; surface loudly, do not silently hold)
    if semver(T) >= floor:   proceed; after success, floor = max(floor, T)
```

Ordering follows **semver precedence**
([`packs-and-deltas.md`](../../registry/packs-and-deltas.md),
[`versioning-and-channels.md`](../../registry/versioning-and-channels.md)) — not
the deleted calendar `creation_token`. The `semver` crate is already a dependency
(used by `find_best_version_tag_in_manifest`
[`update.rs:400`](../../../crates/aos-package/src/update.rs) and the `Version`
tracking arm), so the comparison is `semver::Version` ordering.

### 7.2 Replacing `check_monotonic` and fixing the gating bug

The CURRENT `check_monotonic`
([`state.rs:104`](../../../crates/aos-package/src/registry/state.rs)) is reframed
onto semver, and the **gating bug** at
[`update.rs:263`](../../../crates/aos-package/src/update.rs) is fixed:

```rust
// CURRENT (buggy): guard only runs when the new token is ALREADY greater,
// i.e. never on an actual downgrade.
if let Some(old_token) = reg_state.last_creation_token {
    if latest_token > old_token {            // <-- bug: skips the real rollback case
        state::check_monotonic(old_token, latest_token)?;
    }
}

// TARGET: unconditional semver floor check, BEFORE fetching the target.
if semver(target) < floor {
    bail!("anti-rollback: target {target} is older than floor {floor}");
}
```

The check must run **unconditionally** (the whole point is to catch
`target < floor`) and **before** any object fetch, so a rollback never even
downloads. This reconciles the discrepancy flagged in
[open-questions.md](./open-questions.md).

### 7.3 Interaction with rollout & fix-forward

- A consumer that already advanced to `1.4.2` has `floor = 1.4.2`. If the
  publisher *decrements* its partition back to `1.4.1` (bad idea), the consumer
  **refuses** — the floor blocks it.
- The correct abort is **fix-forward**: publish `1.4.3` (the revert-as-new-
  release) and advance partitions to it; `1.4.3 >= floor`, so consumers adopt it.
- Rollout gates **adoption order**, the floor gates **direction**; the two are
  orthogonal and both fail-closed.

---

## 8. Nix `[[caches]]` superset wiring

> **TARGET.** Per [brief §13](./design-brief.md#13-nix-binary-cache-superset) and
> [§14](./design-brief.md#14-tag-message-toml-schema): the verified semver tag's
> message carries a `[[caches]]` entry whose `url` may be **relative** (same
> origin) or absolute. The consumer registers it for NAR substitution.

### 8.1 The tag-message TOML (only `[meta]` + `[[caches]]`)

```toml
[meta]
schema      = 1
valid_until = "2026-06-30T00:00:00Z"   # releases: generous signature-trust window

[[caches]]
url      = "./nar"                      # relative (same origin) OR absolute
priority = 100
```

**No other top-level tables exist** — not `[latest]`, `[components]`,
`[capabilities]`, `[[bundles]]`, `[[deltas]]`, `pubkey`, or `[signature]`
([brief §14](./design-brief.md#14-tag-message-toml-schema)). The tag *object*
carries the signature; the ref namespace carries pointers; the object store
carries everything else. See [`tag-metadata.md`](../../registry/tag-metadata.md).

### 8.2 Relative-URL resolution

A `[[caches]].url` is resolved relative to the **registry origin** (the base URL
the partition/release was fetched from):

```text
registry origin:  https://registry.aos.dev/core/
[[caches]].url:   "./nar"
resolved cache:   https://registry.aos.dev/core/nar/
                      ├─ nix-cache-info
                      ├─ <storehash>.narinfo
                      └─ nar/<...>.nar[.zst]
```

An absolute `url` (`https://cache.example/…`) is used verbatim. The resolved
cache exposes the standard Nix binary-cache surface (`nix-cache-info`,
`<storehash>.narinfo`, `nar/`) — a strict superset for stock `nix` dev-shell
substitution. narinfo `Sig:` (if served) reuses the one Ed25519 key
([brief §11](./design-brief.md#11-signing--trust),
[`nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md)).

### 8.3 Consumer responsibilities

| Step | Action |
|---|---|
| Parse | After chain verification (§6), parse the semver tag-message TOML; read `[meta].valid_until` and each `[[caches]]`. |
| Freshness | For releases, `valid_until` is a **generous** signature-trust / key-rotation lifetime (it must not fight the long release TTL). Treat an expired release `valid_until` per [`signing-and-trust.md`](../../registry/signing-and-trust.md); channels use it as the freshness knob (paired with low CDN TTL). |
| Resolve | Resolve each `[[caches]].url` against the origin (§8.2). |
| Register | Wire the resolved cache(s) into the substituter set, ordered by `priority`. |
| Substitute | NAR substitution then proceeds through the standard Nix path — orthogonal to the git-object metadata layer. |

The `[[caches]]` mechanism is **orthogonal** to git-object fetch: the git layer
delivers package metadata (the `packages/` tree); the `[[caches]]` layer delivers
build artifacts (NARs). A consumer that only needs metadata can ignore
`[[caches]]`; one doing substitution reads it.

---

## 9. Mapping CURRENT code → TARGET behaviour

| CURRENT (`path:line`) | TARGET replacement | Notes |
|---|---|---|
| `sync_bundle` ([`update.rs:193`](../../../crates/aos-package/src/update.rs)) | git-native resolve+fetch (§3) | drops bundle manifest fetch |
| `pick_bundles` ([`update.rs:292`](../../../crates/aos-package/src/update.rs)) | `resolve_objects` delta-walk (§5.2) | bundle → thin `delta-*.pack`; token → semver+ancestry |
| `BundleManifest::fetch` ([`update.rs:203`](../../../crates/aos-package/src/update.rs)) | `info/refs` + `http-alternates` reads (§3.2) | manifest → git object store |
| `bundle::unbundle` / `resolve_tag` ([`update.rs:240`,`:249`](../../../crates/aos-package/src/update.rs)) | `index-pack --fix-thin` + tag-chain resolve (§5.3, §6) | bundles → thin packs + signed tags |
| `check_monotonic` + gating ([`state.rs:104`](../../../crates/aos-package/src/registry/state.rs), [`update.rs:263`](../../../crates/aos-package/src/update.rs)) | unconditional semver floor (§7.2) | fixes gating bug; deletes token math |
| `version_to_token`/`token_to_version` ([`state.rs:131`,`:173`](../../../crates/aos-package/src/registry/state.rs)) | **deleted** (§15) | calendar scheme removed |
| `RegistryState.last_creation_token` ([`types.rs:259`](../../../crates/aos-package/src/types.rs)) | `floor` (semver) + `bucket` + `retained` (§3.5) | state schema change |
| `TrackingMode` (no `Channel`) ([`types.rs:282`](../../../crates/aos-package/src/types.rs)) | add `Channel(name)` → bucket → partition tag (§4, §3.3) | new resolution arm |
| `extract_packages_from_git` ([`update.rs:469`](../../../crates/aos-package/src/update.rs)) | **reused** | `git archive <commit> packages/` is unchanged |

---

## 10. Task checklist

**State & config:**

- [ ] Replace `RegistryState.last_creation_token`
      ([`types.rs:259`](../../../crates/aos-package/src/types.rs)) with `floor:
      Option<String>` (semver); add `bucket: Option<u8>` and `retained:
      Vec<String>`.
- [ ] Extend `state::save_state`
      ([`state.rs:43-51`](../../../crates/aos-package/src/registry/state.rs)) to
      serialize the new fields; drop `last_creation_token`.
- [ ] Delete `version_to_token`/`token_to_version`/`check_monotonic`
      ([`state.rs:104`,`:131`,`:173`](../../../crates/aos-package/src/registry/state.rs)),
      replace with a semver floor comparator.

**Resolution:**

- [ ] Bucket selection `the low byte of sha256(machine_id) (i.e. mod 256)`, persist once (§4); hex render
      each byte as two hex digits `00..ff`; probe-forward `(bucket+i) mod 256` (§4.3).
- [ ] Add `TrackingMode::Channel(String)`
      ([`types.rs:282`](../../../crates/aos-package/src/types.rs)) and a `channel`
      config field threaded into `tracking_mode()`
      ([`types.rs:352`](../../../crates/aos-package/src/types.rs)).
- [ ] Tag-chain resolver `/channel/<name>/<bucket>` → semver tag → commit (§3.3).

**Verification:**

- [ ] `git verify-tag`-style Ed25519 check on each tag object + name-binding
      string comparison (§6); reuse `security.rs` primitives.
- [ ] Fail-closed ordering: verify chain *before* fetching objects (§6.3).

**Fetch:**

- [ ] `resolve_objects` delta-walk: retained-base delta → backward walk → full
      pack → loose objects (§5.2).
- [ ] `git index-pack --fix-thin` for thin packs; `zstd -d --long=27` for
      `.pack.zst` (§5.3).
- [ ] Retention set `{X.0.0, X.Y.0, X.Y.Z}`; prune + persist (§5.4).

**Anti-rollback:**

- [ ] Unconditional semver floor check before fetch; fix the
      [`update.rs:263`](../../../crates/aos-package/src/update.rs) gating bug
      (§7.2).

**Nix cache:**

- [ ] Parse semver tag-message TOML (`[meta]` + `[[caches]]` only); resolve
      relative `url` against origin; register substituters by `priority` (§8).

---

## 11. Cross-references

### Reference set (`docs/registry/`, TARGET state)

- [README.md](../../registry/README.md) — purpose, glossary, doc index.
- [architecture.md](../../registry/architecture.md) — git-over-dumb-HTTP, the
  three ref layers, how `apm` and stock git both consume.
- [current-state.md](../../registry/current-state.md) — the as-is bundle /
  `creation_token` implementation this WS replaces.
- [http-layout.md](../../registry/http-layout.md) — the static surface the
  consumer reads (`/channel`, `/release`, `http-alternates`, loose objects).
- [versioning-and-channels.md](../../registry/versioning-and-channels.md) —
  semver, 256-partition rollout, bucket selection, anti-rollback.
- [packs-and-deltas.md](../../registry/packs-and-deltas.md) — the delta scheme
  graph, client resolution + retention, `index-pack --fix-thin`, zstd.
- [tag-metadata.md](../../registry/tag-metadata.md) — the `[meta]` + `[[caches]]`
  tag-message TOML schema.
- [signing-and-trust.md](../../registry/signing-and-trust.md) — signed tag
  objects, name-binding, `tag→tag→commit`, `valid_until`, anti-rollback.
- [publishing.md](../../registry/publishing.md) — the producer pipeline that
  emits the surface this consumer reads.
- [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) — the
  Nix binary-cache superset via relative `[[caches]]`.
- [apt-comparison.md](../../registry/apt-comparison.md) — phased-rollout /
  pdiff → 256-partition / thin-delta lineage.

### Plan set (`docs/plans/registry/`)

- [design-brief.md](./design-brief.md) — §6, §9, §11, §13 (authoritative intent).
- [README.md](./README.md) — milestone roadmap and sequencing.
- [gap-analysis.md](./gap-analysis.md) — current vs target gap map.
- [workstream-01-object-store.md](./workstream-01-object-store.md) — the object
  store + `http-alternates` the consumer fetches from.
- [workstream-02-pack-delta-pipeline.md](./workstream-02-pack-delta-pipeline.md)
  — the thin/full pack + zstd artifacts the consumer applies.
- [workstream-03-channels-rollouts.md](./workstream-03-channels-rollouts.md) —
  the 256 signed partition tags + frontier branch the consumer resolves.
- [workstream-04-signing-trust.md](./workstream-04-signing-trust.md) — the signed
  tag objects + name-binding the consumer verifies.
- [open-questions.md](./open-questions.md) — machine-id source / probe-forward
  order (§16.3), the `check_monotonic` gating bug, retained-set sizing.
