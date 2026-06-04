# Versioning & Channels

> **Audience:** users pinning a registry, implementers of the consumer
> (`apm update` / `apm upgrade`) and producer (`apr`), architects, and engineers
> operating a fleet.
>
> **Scope:** how AOS registries are *versioned* (**semver, no `v` prefix**), how a
> channel is modeled (**a git branch whose head is the rollout *frontier***), how
> rollout is driven (**256 signed partition tag objects per channel**), how a
> consumer self-selects one of those partitions (**deterministic, persisted bucket
> with probe-forward fallback**), and how downgrades are prevented
> (**monotonic anti-rollback floor + fix-forward abort**).
>
> **CURRENT vs TARGET.** This is one of the docs being **rewritten** onto the
> git-native registry architecture. Sections labeled **CURRENT** describe behavior
> that exists in the code today, cited as `path:line`. Sections labeled **TARGET**
> describe the design intent from the
> [design brief](../plans/registry/design-brief.md) (§5–§7). The current code still
> implements the *old* calendar-tag / `creation_token` / git-bundle scheme; that
> scheme is **superseded** and is documented here only as the migration baseline.

Related reference docs:
[README](./README.md) ·
[architecture](./architecture.md) ·
[current-state](./current-state.md) ·
[http-layout](./http-layout.md) ·
[packs-and-deltas](./packs-and-deltas.md) ·
[signing-and-trust](./signing-and-trust.md) ·
[publishing](./publishing.md) ·
[nix-cache-compatibility](./nix-cache-compatibility.md) ·
[apt-comparison](./apt-comparison.md)

Plan docs:
[plan README](../plans/registry/README.md) ·
[design brief](../plans/registry/design-brief.md) ·
[gap analysis](../plans/registry/gap-analysis.md) ·
[workstream-03 channels & rollouts](../plans/registry/workstream-03-channels-rollouts.md) ·
[workstream-04 signing & trust](../plans/registry/workstream-04-signing-trust.md) ·
[workstream-05 consumer](../plans/registry/workstream-05-consumer.md) ·
[open questions](../plans/registry/open-questions.md)

---

## 1. Overview

In the **TARGET** architecture the registry is a **bare git repository (sha256)
served as static files over dumb HTTP** (see [architecture](./architecture.md) and
[http-layout](./http-layout.md)). On top of that object store, three concepts give
us versioning and fleet rollout:

| Concept | Modeled as | Signed? | Consumed by |
|---|---|---|---|
| **Release** | semver git **tag** `refs/tags/<semver>` → commit | **yes** | stock git (`verify-tag`) + AOS |
| **Channel (branch)** | `refs/heads/<channel>`, head = **frontier** | no (ref pointer) | stock git convenience |
| **Channel (rollout)** | **256 signed partition tag objects** `/channel/<name>/00..ff` | **yes** | AOS rollout only |

The release tag is the **immutable, signed unit of distribution**. The channel
*branch* is an **unsigned convenience pointer** at the rollout *frontier* (the
newest release any partition targets). The channel *partitions* are the **signed,
bucketed rollout surface** the AOS client actually follows.

```
                       ┌─────────────────────────────────────────┐
   release tags        │  refs/tags/1.0.0   refs/tags/1.1.0  ...  │  (signed → commit)
                       └─────────────────────────────────────────┘
                                  ▲                   ▲
   channel branch head ───────────┼───────────────────┘   = FRONTIER
   refs/heads/stable ─────────────┘  (unsigned; newest release any partition targets)

   channel partitions (signed tag objects, name == "stable", → semver tag):
     /channel/stable/00 ─► 1.1.0    ─┐
     /channel/stable/01 ─► 1.1.0     │  publisher has advanced 4/256
     /channel/stable/02 ─► 1.1.0     │  partitions to 1.1.0 ...
     /channel/stable/03 ─► 1.1.0    ─┘
     /channel/stable/04 ─► 1.0.0    ─┐
     ...                             │  ... and left 252/256 on the prior
     /channel/stable/ff ─► 1.0.0    ─┘  release 1.0.0
```

> **Design philosophy.** Rollout is an **AOS-fleet** concept, not a `git clone`
> concept. A stock `git pull <channel>` always lands on the frontier (no rollout
> protection); only AOS clients honor the 256-partition bucketing. This is an
> accepted trade for staying a clean superset of stock dumb-HTTP git.

---

## 2. Semver versioning (TARGET)

### 2.1 Version grammar

Releases use **standard [semver](https://semver.org/), with no `v` prefix**:

```
1.1.2                          a normal patch release
1.1.0-alpha.1                  a pre-release of the 1.1.0 minor base
1.0.0-beta+exp.sha.5114f85     pre-release "beta" with build metadata
```

A release is a **signed git tag** `refs/tags/<semver>` pointing at a commit. There
is no calendar component, no `creation_token`, and no `v` prefix — those belong to
the superseded scheme in §6.

### 2.2 Precedence & ordering

Ordering follows semver precedence exactly. The relevant rules:

1. Compare `major`, then `minor`, then `patch` numerically.
2. A version **with** a pre-release has **lower** precedence than the associated
   normal version: `1.0.0-alpha < 1.0.0`.
3. Pre-release identifiers compare left-to-right: numeric identifiers compare
   numerically, alphanumeric identifiers compare in ASCII sort order, numeric < alphanumeric,
   and a larger set of identifiers (when all preceding are equal) has higher
   precedence.
4. **Build metadata** (`+…`) is **ignored** for precedence —
   `1.0.0+a` and `1.0.0+b` have equal precedence.

```
1.0.0-alpha  <  1.0.0-alpha.1  <  1.0.0-alpha.beta  <  1.0.0-beta
            <  1.0.0-beta.2   <  1.0.0-beta.11     <  1.0.0-rc.1
            <  1.0.0
```

Crucially, ordering is *not* re-derived from a synthetic token: it comes from
semver precedence **and** git ancestry (the commit a tag points at is a descendant
of the prior release's commit). The two agree because the publisher only ever tags
forward — see [packs-and-deltas](./packs-and-deltas.md) for how this co-designs with
the delta graph.

### 2.3 Path encoding of a release

A release's object store lives under
`/release/<major>/<minor>/<patch…>/`, where the **third segment is everything after
`major.minor`** — including any `-prerelease` and `+build` suffix:

| Semver | Release path |
|---|---|
| `1.1.2` | `/release/1/1/2/` |
| `1.1.0-alpha.1` | `/release/1/1/0-alpha.1/` |
| `1.0.0-beta+exp.sha.5114f85` | `/release/1/0/0-beta+exp.sha.5114f85/` |

Releases are **immutable** once published and may carry a long CDN TTL (see
[http-layout](./http-layout.md) §CDN policy).

---

## 3. Channels as branches; branch head = frontier (TARGET)

A **channel** is a named release line — e.g. `stable`, `testing`. It is modeled two
ways simultaneously:

### 3.1 The branch (unsigned convenience pointer)

`refs/heads/<channel>` is an ordinary git branch. Its head points at the commit of
the **frontier**: the newest release *any* of the channel's 256 partitions targets
(i.e. the current rollout target).

- `HEAD` is a symref to `refs/heads/<default-channel>` (e.g. `stable`), so a bare
  `git clone <url>` checks out the default channel's frontier.
- Branch refs are **never part of the trust chain** (see
  [signing-and-trust](./signing-and-trust.md)). They are an unsigned convenience so
  stock git users get a working clone. Those users can still
  `git verify-tag <semver>` because the **release tags** are the signed objects.

```
HEAD ──symref──► refs/heads/stable ──► commit(1.1.0)   ← frontier
                                            ▲
                 newest release any /channel/stable/<00..ff> targets
```

> **Implication.** `git pull stable` always advances to the frontier — there is no
> rollout gating for stock clients. Acceptable by design (§1): rollout is fleet
> policy enforced by AOS, not by the git ref graph.

### 3.2 The partitions (the rollout surface) — see §4.

The frontier is a *derived* value: when the publisher advances even one partition
to a newer release, the branch head moves to that newer release's commit. The
branch head is therefore "the most ambitious thing the channel is currently rolling
out," not "what the median host runs."

---

## 4. The 256 signed partition tag objects (TARGET)

Each channel exposes **exactly 256** partition files:

```
/channel/<name>/00
/channel/<name>/01
   ...
/channel/<name>/ff         (one byte (two hex digits, 00–ff) → 256 partitions)
```

Each file is an **independently signed annotated tag object** whose **tag name field
equals the channel name** (`<name>`), pointing at a **semver release tag**. A signed
partition tag is a **pure signed pointer**: standard git tag fields (object, type, the
tag name, tagger) + the Ed25519 signature + an optional freeform human message. It
carries **no structured payload** — no embedded cache list, no expiry. The full
trust chain is therefore:

```
signed partition tag  ──►  signed semver tag  ──►  commit
   (name == channel)          (name == semver)
   under /channel/<name>/      under /release/...
```

Verification checks **both** the Ed25519/SSH signature **and** the embedded
tag-name field against the expected name — the channel name under `/channel/*`, the
semver under `/release/*`. This **name-binding** binds a tag object to its serving
path and prevents cross-serving a tag from one path at another. See
[signing-and-trust](./signing-and-trust.md) for the signature format.

> **Invariant: there must always be 256.** A complete channel has all of `00..ff`
> present and signed. If a partition file is temporarily missing or fails
> verification, a client **MAY** fall back to another partition via deterministic
> **probe-forward** (§5.3) — it does **not** treat a single missing partition as a
> channel-wide failure.

These 256 tag objects live **outside** the git ref namespace (under `/channel/*`, not
`refs/`). They are **AOS-only**; stock dumb-HTTP git never sees them and is
unaffected.

---

## 5. Consumer bucket selection (TARGET)

### 5.1 Deterministic, persisted bucket

A consumer self-selects **one** of the 256 partitions, deterministically and
**persisted once**, so a host does not flap between buckets across `apm update`
runs:

```
bucket = the low byte of sha256(machine_id) (i.e. mod 256)   # 00..ff, computed once, then persisted
```

- `machine_id` is a stable per-host identifier; its exact source (e.g.
  `/etc/machine-id`) and the encoding fed into the hash are an
  [open question](../plans/registry/open-questions.md) (brief §16 item 3).
- The bucket is **written once** and reused thereafter, so the host's partition
  assignment is stable for the life of the machine. Re-deriving it every run (rather
  than persisting) would also be deterministic, but persistence makes the contract
  explicit and survives any future change to the hash construction.

### 5.2 Resolution path

On `apm update`, an AOS client resolves its target release like this:

```
1. bucket  ← persisted low byte of sha256(machine_id) (mod 256)  (§5.1)
2. fetch   /channel/<name>/<bucket>                          (signed partition tag)
3. verify  signature + tag-name field == <name>             (name-binding, §4)
4. follow  partition tag → semver tag; verify sig + name == <semver>
5. target  ← that semver release; resolve objects via packs/deltas/loose
            (see packs-and-deltas.md), subject to the anti-rollback floor (§7)
```

The bucket selects *which* release this host adopts *now*; the partition the
publisher has (or has not) advanced is what determines whether this host is in the
already-rolled-out cohort or still holding on the prior release.

### 5.3 Probe-forward fallback

If the host's assigned partition file is missing or fails verification, the client
probes forward deterministically:

```
b ← bucket
repeat up to 256 times:
    try /channel/<name>/<hex(b)>
    if present AND verifies → use it
    else b ← (b + 1) mod 256
if none usable → channel is unavailable → fail closed (do not invent a target)
```

Probe-forward is **deterministic** (same starting bucket → same probe order), so the
fallback choice is itself reproducible and does not reshuffle the host between runs.

---

## 6. Publisher-controlled rollout (TARGET)

Rollout is driven entirely by **how many of the 256 partitions point at the new
release**. To roll a new release to N/256 of the fleet:

```
point N partitions at the new semver tag;
leave (256 − N) partitions on the prior release.
```

A host adopts the new release iff its persisted bucket maps to a partition that has
been advanced. Because buckets are stable, **the same hosts adopt first** as the
publisher ramps `1/256 → 16/256 → 128/256 → 256/256`; the cohort is monotone, never
reshuffled.

```
 step 0   advance 1/256     /channel/stable/00 → 1.1.0       canary (one bucket, ~0.4%)
 step 1   advance 16/256    /channel/stable/00..0f → 1.1.0   widen if healthy (~6%)
 step 2   advance 128/256   /channel/stable/00..7f → 1.1.0   half the fleet (50%)
 step 3   advance 256/256   /channel/stable/00..ff → 1.1.0   complete (100%)
```

Key properties:

- **"Where does the rest of the fleet go?" is answered explicitly.** The
  un-advanced partitions still *name the prior release* — there is no separate
  `previous_tag`/baseline concept. A held host resolves its (un-advanced) partition
  and lands on the prior release, a no-op relative to where it already is.
- **Completion = all 256 point at the new release.** At that point every bucket maps
  to the new release and the rollout is done.
- **The branch head tracks the frontier** (§3.1): as soon as the first partition is
  advanced to `1.1.0`, `refs/heads/stable` points at `commit(1.1.0)`.
- **The granularity is ~0.39% (1/256).** This replaces the superseded percentage
  rollout (any `0..100` value) with a fixed 256-way partitioning — coarser, but it
  needs **no central host registry** and no per-host reporting: the deterministic
  bucket *is* the cohort assignment.

---

## 7. Anti-rollback: monotonic floor + fix-forward (TARGET)

### 7.1 Monotonic floor

A consumer keeps a **monotonic floor**: it **never moves to a release older than its
current one** (by semver precedence + git ancestry). If a resolved partition would
take the host *backward* — for example, because a partition was repointed at an
older release, or a mirror is stale — the client **rejects** the move and stays put.

```
target ← release the bucket resolves to
if precedence(target) < floor  OR  not is-ancestor(floor.commit, target.commit):
    reject (do not downgrade); keep running floor
else:
    adopt target; floor ← target
```

This is the conceptual successor to today's `check_monotonic`
(`crates/aos-package/src/registry/state.rs:104-117`), but the anchor moves from the
calendar `creation_token` to **semver precedence plus a git
`merge-base --is-ancestor` ancestry check** against the signed target commit. See
[signing-and-trust](./signing-and-trust.md) for how the signed tag chain feeds this.

### 7.2 Aborting a bad rollout is fix-forward

A publisher does **not** abort a bad rollout by **decrementing** partitions back to
the prior release. That would be a downgrade — and the consumers' monotonic floor
(§7.1) would block it anyway. Instead, abort is **fix-forward**:

```
1. publish a NEWER release that fixes (or reverts the content of) the regression;
2. point the affected partitions at that newer release.
```

Because the new release is *newer* by precedence and a descendant commit, it passes
the floor check and rolls out normally. The semantics: "roll back" means "roll
*forward* to a corrected build," never "move the fleet to an older tag."

| Action | Mechanism | Allowed? |
|---|---|---|
| Roll out N/256 | advance N partitions to a newer release | yes |
| Widen rollout | advance more partitions to the same newer release | yes |
| Abort / "rollback" | publish a newer fixed release, advance partitions to it | yes (fix-forward) |
| Decrement partitions to an older release | point partitions back at a prior semver | rejected by consumer floor |

---

## 8. Migration baseline — the superseded calendar scheme (CURRENT)

> **This entire section describes today's code, which is being replaced.** It is
> kept as the migration baseline, not as target design. The git-native model in
> §2–§7 supersedes all of it. Do not implement new behavior against this section.

### 8.1 Calendar tags & `creation_token` (CURRENT)

Today, releases are **calendar** git tags `vYYYY.MM[.P]`, parsed by
`version_to_token` (`crates/aos-package/src/registry/state.rs:131-166`) into a
monotonic 64-bit integer:

```
creation_token = year * 1_000_000 + month * 10_000 + patch
```

| Tag | `creation_token` |
|---|---|
| `v2026.02`    | `2026020000` |
| `v2026.02.3`  | `2026020003` |
| `v2026.12.99` | `2026120099` |

The inverse is `token_to_version` (`state.rs:173-184`), which renders patch `0` as
the 2-part base tag. The token is the *total order* and the anti-rollback anchor
today — it is **removed** in the target, replaced by semver precedence + git
ancestry (§2.2, §7.1).

### 8.2 Tag → semver projection (CURRENT)

Calendar tags are *also* projected to semver by `parse_tag_as_semver`
(`crates/aos-package/src/update.rs:429-450`) — strip the leading `v`, parse each
component as `u64` to drop leading zeros, pad a 2-component tag to `X.Y.0` — so a
host can write `version = "~2026.3"` and match `v2026.03`. Best-match selection is
`find_best_version_tag_in_manifest` (`update.rs:400-424`). In the **target**, this
projection is unnecessary: versions are *already* `MAJOR.MINOR.PATCH` semver with no
`v` and no calendar normalization.

### 8.3 Tracking modes (CURRENT)

A host subscribes via `~/.config/apm/registries.d/{name}.toml`; the resolved mode is
`TrackingMode` (`crates/aos-package/src/types.rs:281-293`):

```rust
// types.rs:281
pub enum TrackingMode {
    Commit(String),                  // frozen to an exact commit hash
    Branch(String),                  // track HEAD of a named branch
    Tag(String),                     // pinned to an exact tag
    Version(semver::VersionReq),     // semver constraint on tags
    Default,                         // no field set -> default branch HEAD
}
```

There is **no `Channel` variant** today; channel subscription is the target
addition (§3–§6). The natural mapping under the target model:

| Today's intent | Target mechanism |
|---|---|
| `branch = "stable"` (track a line) | `channel = "stable"` → bucketed partitions (§4–§6) |
| `tag = "1.1.0"` (pin a release) | unchanged — signed semver tag `refs/tags/1.1.0` (§2) |
| `commit = "<sha>"` (freeze) | unchanged — exact commit |
| `version = "~1.1"` (constraint) | unchanged — semver `VersionReq` over signed tags |

### 8.4 Monotonic check (CURRENT, conditional)

The current downgrade guard is `check_monotonic` (`state.rs:104-117`), called from
`update.rs:263-267`:

```rust
// update.rs:262
// Downgrade protection: check monotonic ordering.
if let Some(old_token) = reg_state.last_creation_token {
    if latest_token > old_token {
        state::check_monotonic(old_token, latest_token)?;
    }
}
```

Because the call sits **inside** `if latest_token > old_token`, the `<=` reject
branch of `check_monotonic` is effectively unreachable from this path — a stale or
equal token silently skips the guard. The **target** floor (§7.1) is evaluated
**unconditionally** against semver precedence + git ancestry, closing that gap.
Tracked in [open questions](../plans/registry/open-questions.md).

---

## 9. Worked examples

### 9.1 TARGET — a 4/256 rollout, two different hosts

Publisher advances 4 of 256 `stable` partitions to `1.1.0`; partitions `04..ff` still
name `1.0.0`. Two hosts, both on `channel = "stable"`, both currently at floor
`1.0.0`:

```
Host A:  bucket = low byte of sha256(machine_id_A) (mod 256) = 02
         /channel/stable/02 → 1.1.0  (advanced)  → adopt 1.1.0; floor ← 1.1.0
Host B:  bucket = low byte of sha256(machine_id_B) (mod 256) = 0xb7
         /channel/stable/b7 → 1.0.0  (held)       → no-op; stays at 1.0.0
```

When the publisher later advances to `8/256`, Host A is unaffected (already at
`1.1.0`); a host whose bucket is `05` flips from held to adopted. Host B (bucket
`b7`) keeps holding until partition `b7` is advanced.

### 9.2 TARGET — frontier vs. median

With the 4/256 rollout above:

```
refs/heads/stable  → commit(1.1.0)     ← frontier (newest release any partition targets)
git clone <url>    → checks out 1.1.0  ← stock git gets the frontier, no gating
AOS fleet median   → still 1.0.0       ← 252/256 buckets are held
```

### 9.3 TARGET — fix-forward abort

`1.1.0` (rolled to 8/256) is found bad. The publisher does **not** repoint partitions
back to `1.0.0` (consumers' floor would reject it). Instead:

```
1. publish 1.1.1 (signed tag → fixed commit, descendant of 1.1.0)
2. advance the affected partitions: /channel/stable/00..07 → 1.1.1
3. hosts at floor 1.1.0 see a NEWER release → adopt 1.1.1 (passes the floor)
   hosts at floor 1.0.0 (held buckets) see 1.0.0 still on their partition → unchanged
```

### 9.4 TARGET — probe-forward fallback

Host bucket = `7f`, but `/channel/stable/7f` 404s (CDN propagation gap):

```
try /channel/stable/7f  → 404
try /channel/stable/80  → present + verifies  → use it
```

The host transiently follows partition `80`'s release for this run; once partition
`7f` is restored, the host returns to its assigned bucket on the next update.

---

## 10. Cross-references

- **HTTP/object layout** of `/channel/*`, `/release/*`, `refs`, `HEAD`,
  `info/alternates`, and CDN TTLs: [http-layout](./http-layout.md).
- **The three ref layers, name-binding, and the `tag → tag → commit` trust chain:**
  [signing-and-trust](./signing-and-trust.md).
- **How a resolved release is fetched** (full packs, thin deltas, retention, loose
  fallback): [packs-and-deltas](./packs-and-deltas.md).
- **The producer pipeline** that tags/signs, packs, runs `update-server-info`, and
  **advances partitions**: [publishing](./publishing.md).
- **As-is grounding** for tracking modes, state, and the calendar/`creation_token`
  baseline: [current-state](./current-state.md).
- **The Nix binary-cache superset** (`nix-cache-info`/`.narinfo`/`nar`), configured
  client-side or served by the origin — never advertised in signed tags:
  [nix-cache-compatibility](./nix-cache-compatibility.md).
- **APT precedent** (signed flat-file lineage, `pool`, phased rollout → 256
  partitions): [apt-comparison](./apt-comparison.md).
- **Implementation plan:**
  [workstream-03](../plans/registry/workstream-03-channels-rollouts.md) (256 signed
  partition tags, channels-as-branches/frontier, bucket selection, publisher rollout
  control),
  [workstream-04](../plans/registry/workstream-04-signing-trust.md) (signed tag
  objects, name-binding, anti-rollback/fix-forward),
  [workstream-05](../plans/registry/workstream-05-consumer.md) (consumer resolution:
  bucket → channel tag → semver tag → commit), and
  [gap-analysis](../plans/registry/gap-analysis.md).
