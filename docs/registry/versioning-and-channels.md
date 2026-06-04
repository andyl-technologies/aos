# Versioning & Channels

> **Audience:** users pinning a registry, implementers of the consumer
> (`apm update`/`apm upgrade`) and producer (`apr`), architects, and engineers
> operating a fleet.
>
> **Scope:** how AOS registries are *versioned* (calendar tags ↔ semver ↔
> `creation_token`), how a host *tracks* a registry (commit / branch / tag /
> version), and the **target** machinery layered on top — symbolic **channels**
> (`stable`/`testing`) decoupled from tags, **phased rollouts**, and
> **components**.
>
> **CURRENT vs TARGET:** sections labeled **CURRENT** describe behavior that
> exists in the code today, cited as `path:line`. Sections labeled **TARGET**
> describe the design intent from the
> [design brief](../plans/registry/design-brief.md) (§2.5, §4.3, §6) that is
> **not yet implemented**. Where the two are interleaved, each subsection is
> labeled.

Related reference docs:
[README](./README.md) ·
[architecture](./architecture.md) ·
[current-state](./current-state.md) ·
[http-layout](./http-layout.md) ·
[registry-toml](./registry-toml.md) ·
[bundles-and-deltas](./bundles-and-deltas.md) ·
[nix-cache-compatibility](./nix-cache-compatibility.md) ·
[signing-and-trust](./signing-and-trust.md) ·
[publishing](./publishing.md) ·
[apt-comparison](./apt-comparison.md)

Plan docs:
[plan README](../plans/registry/README.md) ·
[design brief](../plans/registry/design-brief.md) ·
[gap analysis](../plans/registry/gap-analysis.md) ·
[workstream-04 channels & rollouts](../plans/registry/workstream-04-channels-rollouts.md) ·
[workstream-05 consumer](../plans/registry/workstream-05-consumer.md) ·
[open questions](../plans/registry/open-questions.md)

---

## 1. Overview

A registry is a **git repository of TOML metadata** distributed over HTTP. Its
*releases* are git **tags** following a **calendar versioning** scheme; a host
*subscribes* to a registry and chooses which release(s) it will track. The
mechanisms in play, from lowest to highest level:

| Layer | What it is | Status |
|---|---|---|
| **Calendar tag** | `vYYYY.MM[.P]` git tag naming a release | CURRENT |
| **`creation_token`** | monotonic integer `YYYYMMPPPP` derived from the tag — total order over releases | CURRENT (consumer-side) |
| **Semver projection** | tag parsed as `semver::Version` for `VersionReq` matching | CURRENT |
| **Tracking mode** | how a host selects a release: commit / branch / tag / version / default | CURRENT |
| **Channel** | symbolic alias (`stable`/`testing`) → concrete tag, decoupled from tag names | TARGET |
| **Rollout** | percentage gate on a channel target for canary/phased fleet updates | TARGET |
| **Component** | intra-registry partition (trust/license/stability) | TARGET |

The first four exist and are exercised by `apm update`. The last three are
APT-derived improvements adopted into the **target** signed `registry.toml`
root (design brief §4.3, §6 items 3/4/5) and are documented here as the design
that [workstream-04](../plans/registry/workstream-04-channels-rollouts.md) and
[workstream-05](../plans/registry/workstream-05-consumer.md) will implement.

---

## 2. Calendar versioning (CURRENT)

### 2.1 Tag grammar

Releases are git tags of the form:

```
vYYYY.MM        a "minor base" — a monthly release with no patch
vYYYY.MM.P      a patch release within that month
```

Examples: `v2026.02`, `v2026.02.3`, `v2026.12.99`.

Constraints enforced by `version_to_token`
(`crates/aos-package/src/registry/state.rs:131-166`):

- exactly **2 or 3** dot-separated components after stripping the optional
  leading `v`;
- `YYYY` and `MM` parse as integers; `MM` is **1–12** (`state.rs:149-151`);
- `P` (patch) defaults to `0` when absent and must be **≤ 9999**
  (`state.rs:161-163`).

A 2-component tag (`vYYYY.MM`) is the *minor base* of a month; its patch
component is implicitly `0`.

### 2.2 `creation_token` — the total order

Every tag maps to a monotonic 64-bit integer used to order releases and bundles:

```
creation_token = year * 1_000_000 + month * 10_000 + patch
```

Source: `version_to_token` (`state.rs:131-166`), inverse `token_to_version`
(`state.rs:168-184`).

| Tag | `creation_token` |
|---|---|
| `v2026.02`   | `2026020000` |
| `v2026.02.3` | `2026020003` |
| `v2026.12.99`| `2026120099` |

The inverse renders patch `0` as a **2-part base tag** (`token_to_version` at
`state.rs:179-183`): `2026020000 → "v2026.02"`, `2026020003 → "v2026.02.3"`.

```
 token = 2 0 2 6 0 2 0 0 0 3
          \__/  \_/  \____/
          year month patch (0000-9999)
```

This layout makes ordinary integer comparison a correct release ordering:
later year > earlier year; within a year, later month wins; within a month,
higher patch wins.

> **Note on capacity.** Because month occupies 4 decimal digits
> (`* 10_000`) but only uses 01–12, and patch occupies the low 4 digits, the
> token is *not* a dense encoding — there are unused integer ranges between
> months. This is intentional and harmless; the token is an ordering key, not a
> compact identifier.

### 2.3 Monotonicity & downgrade defense (CURRENT)

`creation_token` is the anchor for **anti-rollback**. `check_monotonic`
(`state.rs:104-117`) rejects any sync whose new token is **≤** the persisted
token:

```rust
// state.rs:104
pub fn check_monotonic(old_token: u64, new_token: u64) -> Result<()> {
    if new_token <= old_token { bail!("registry downgrade detected: ...") }
    Ok(())
}
```

The consumer calls this from `sync_bundle` *after* picking and applying bundles
but *before* committing new state
(`crates/aos-package/src/update.rs:263-267`). The error names both versions via
`token_to_version`, framing it as a possible downgrade attack or stale mirror.

> **CURRENT caveat (guard is conditional).** In `update.rs:263-267` the check
> only runs *inside* `if latest_token > old_token`, so the `<=` branch of
> `check_monotonic` is effectively unreachable from `sync_bundle`: a stale or
> equal token silently skips the guard rather than erroring. The standalone
> `check_monotonic` unit tests (`state.rs:254-274`) still exercise the reject
> path. See [open questions](../plans/registry/open-questions.md). The
> **TARGET** anti-rollback anchor moves to the signed `[latest].creation_token`
> field in `registry.toml` (§6.2), evaluated unconditionally.

---

## 3. Semver projection (CURRENT)

Calendar tags are *also* interpreted as semver so that a host can express a
flexible constraint (`~2026.3`, `^2026`, `>=2026.3, <2026.5`). AOS depends on
the standard `semver` crate (design brief §2.5).

### 3.1 Tag → semver normalization

`parse_tag_as_semver` (`crates/aos-package/src/update.rs:429-450`):

1. strip a leading `v`;
2. split on `.`, parse each component as `u64` to **strip leading zeros**
   (`02 → 2`), falling back to the literal on parse failure;
3. pad a **2-component** tag to `X.Y.0`; accept a **3-component** tag as-is;
   any other length → `None` (not semver).

| Tag | Parsed `semver::Version` |
|---|---|
| `v2026.02`   | `2026.2.0` |
| `v2026.02.3` | `2026.2.3` |
| `v1.2.3`     | `1.2.3` |
| `release-candidate` | — (`None`, skipped) |

This is *why* a `version` constraint written as `~2026.3` (not `~2026.03`)
matches a `v2026.03` tag — the leading zero is normalized away before matching
(`types.rs` tests at `crates/aos-package/src/types.rs:914-925`,
`update.rs` tests at `crates/aos-package/src/update.rs:754-761`).

### 3.2 Best-match selection

`find_best_version_tag_in_manifest` (`update.rs:400-424`) scans every bundle
entry's `target_tag`, projects it to semver, keeps those satisfying the
`VersionReq`, and returns the **highest** matching tag. Non-semver tags are
silently skipped (`update.rs:771-798` test). If nothing matches, the caller
errors (`update.rs:334-336`).

> **`creation_token` vs semver — two orderings, kept consistent.** The
> calendar→token map and the calendar→semver map agree on ordering for
> well-formed `vYYYY.MM[.P]` tags, so "highest semver match" and "highest token"
> coincide in practice. They diverge only for tags outside the calendar grammar
> (e.g. `v1.2.3`), which `version_to_token` rejects but `parse_tag_as_semver`
> accepts. Producers SHOULD use calendar tags exclusively; the version-matching
> path tolerates plain semver for flexibility.

---

## 4. Tracking modes (CURRENT)

A host subscribes to a registry via a config file at
`~/.config/apm/registries.d/{name}.toml` (or `/etc/apm/registries.d/…` for
system scope; see `ProfileScope::config_dir` at
`crates/aos-package/src/types.rs:483-489`). The `[registry]` table carries at
most one *tracking field*. The resolved mode is the
`TrackingMode` enum (`types.rs:281-293`):

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

### 4.1 Config fields → mode

`RegistryConfig::tracking_mode` (`types.rs:352-400`) maps fields to modes and
**validates that at most one** of `commit`/`branch`/`tag`/`version` is set
(legacy `pin` folds into `tag`); two or more set → error
(`types.rs:370-377`).

| `[registry]` field | `TrackingMode` | Selection behavior |
|---|---|---|
| `commit = "<sha>"` | `Commit` | Pin to an exact commit. **Bundle transport cannot resolve arbitrary commits** — falls through to default fetch (`update.rs:314-317`). Honored fully under git transport. |
| `branch = "<name>"` | `Branch` | Track the branch HEAD; behaves as Default for bundle selection (incremental to latest). |
| `tag = "<v…>"` | `Tag` | Pin to an exact tag; sync resolves the matching snapshot or a delta targeting it (`update.rs:299-313`). |
| `version = "<req>"` | `Version` | Best-match the highest tag satisfying the semver `VersionReq` (`update.rs:318-337`). |
| *(none)* | `Default` | Default branch HEAD; incremental sync to latest. |
| `pin = "<v…>"` *(legacy)* | `Tag` | Backward-compat alias for `tag` (`types.rs:354`, `230-232`). |

Example config files:

```toml
# Track the latest stable monthly line within 2026, auto-adopt patches.
[registry]
name = "aos-core"
url  = "https://registry.aos.dev/core"
version = "~2026.3"          # matches v2026.03, v2026.03.1, v2026.03.2, ...
```

```toml
# Freeze to an exact release for reproducibility.
[registry]
name = "aos-core"
url  = "https://registry.aos.dev/core"
tag  = "v2026.02.3"
```

```toml
# Frozen to an exact commit (only fully honored under git transport).
[registry]
name = "aos-core"
url  = "git+ssh://git@github.com/andyl/registry.git"
commit = "abc123def456abc123def456abc123def456abcd"
```

### 4.2 Mode-aware bundle selection

`pick_bundles` (`update.rs:291-391`) consumes the `TrackingMode` plus persisted
`RegistryState` to choose the minimal set of bundles. Summary (full algorithm
in [bundles-and-deltas](./bundles-and-deltas.md)):

```
TrackingMode::Tag      -> snapshot with target_tag == tag, else any delta to it,
                          else error                            (update.rs:299-313)
TrackingMode::Commit   -> bundle transport can't resolve; fall through  (update.rs:314-317)
TrackingMode::Version  -> find_best_version_tag_in_manifest, then snapshot/delta
                          to it, else error                     (update.rs:318-337)
TrackingMode::Branch
TrackingMode::Default  -> incremental:
                            no prior state          -> latest_snapshot()
                            entries_since(cur) empty-> []  (up to date)
                            skip delta available    -> skip delta
                            sequential chain        -> sequential deltas
                            otherwise               -> latest snapshot
```

> **Transport interaction.** The URL scheme selects transport
> (`RegistryConfig::transport`, `types.rs:315-324`): `http(s)://` ⇒ HTTP
> bundles, `git*://` ⇒ native git. Under git transport, `Commit` and `Branch`
> are resolved directly by `git fetch`; the bundle-transport limitation on
> `Commit` (above) does not apply. See `update.rs:115-128`.

### 4.3 State persistence

After a successful sync the consumer writes
`RegistryState { last_commit, last_creation_token, last_update }`
(`types.rs:254-262`) into the `[registry.state]` section of the same config
file (`save_state`, `state.rs:37-77`; called from `update.rs:131-145`).
User-edited fields (name, url, signing, tracking fields) are preserved — only
the state section is rewritten (`state.rs:53-71`).

---

## 5. Channels (TARGET)

> **Status: TARGET.** No channel field, parsing, or selection logic exists in
> the code today. `TrackingMode` has no `Channel` variant (`types.rs:281-293`),
> and the current root schema `RegistryRootConfig` (`types.rs:566-599`) carries
> only `registry`, `caches`, and `signing` — there is **no `[channels]`
> table**. This section is the design from brief §4.3 and §6 (item 3), to be
> implemented by
> [workstream-04](../plans/registry/workstream-04-channels-rollouts.md) and
> [workstream-05](../plans/registry/workstream-05-consumer.md).

### 5.1 Motivation: decouple subscription from tag names

Today a host that wants "the current stable release" must either pin an exact
`tag` (and manually bump it each month) or use a `version` constraint (which
couples the subscription to the *calendar shape* of tags). Neither lets the
**publisher** move the meaning of "stable" forward without every host editing
config.

A **channel** is a *symbolic alias* — a name like `stable` or `testing` — that
the publisher maps to a concrete tag inside the signed `registry.toml` root.
Promotion is **one atomic signed flip** of that mapping; subscribers that track
`channel = "stable"` follow it automatically with no local edit. This is the
APT `suite`/`Codename` idea (`stable`, `testing`, `unstable`), adapted.

```
                 registry.toml [channels]            git tags
   apm host  ───────────────────────────────────────────────────
   channel = "stable"  ──►  stable  = "v2026.02.3"  ──►  v2026.02.3
   channel = "testing" ──►  testing = "v2026.03"    ──►  v2026.03
```

The key property: `stable` and `testing` are **not** themselves git tags or
branches — they are *pointers* living in the signed root, independent of the
tag-naming convention. A publisher can repoint `stable` from `v2026.02.3` to
`v2026.03.1` without renaming anything.

### 5.2 Root schema (TARGET)

In the target signed root (`registry.toml`, see
[registry-toml](./registry-toml.md)), channels live in a `[channels]` table.
Brief §4.3 specifies: *"`[channels]` symbolic aliases (`stable`, `testing`) →
concrete tags, each optionally with a **rollout** percentage."*

```toml
# registry.toml (TARGET) — channel definitions in the signed root
# [channels.<name>] subtables (NOT inline tables, NOT [[array]]).

[channels.stable]
tag            = "v2026.02.3"
creation_token = 2026020003   # per-channel monotonic anti-rollback

[channels.testing]
tag            = "v2026.03"
creation_token = 2026030000
rollout        = 25           # percent; phased — only ~25% of the fleet adopts (see §6)
```

The simplest form (a channel that is just an alias) needs only `tag`;
`creation_token` SHOULD be present so the consumer can apply the same monotonic
ordering it uses for `[latest]` (per-channel anti-rollback). `rollout` is the
adoption percentage; omit it (or set `100`) for a fully rolled-out channel.

### 5.3 Consumer subscription (TARGET)

A host opts into channel tracking with a new `channel` tracking field, mutually
exclusive with the existing four (the same one-of validation in
`tracking_mode`, `types.rs:352-400`, extended for a fifth field):

```toml
# registries.d/aos-core.toml (TARGET)
[registry]
name    = "aos-core"
url     = "https://registry.aos.dev/core"
channel = "stable"          # follow whatever the publisher calls "stable"
```

Resolution (TARGET): `apm update` reads the signed root, looks up
`channel = "stable"` in `[channels]`, obtains the concrete `tag`/`creation_token`, then
runs the **existing** bundle-selection machinery as if the user had pinned that
tag — i.e. channels resolve to a tag *before* `pick_bundles` runs, reusing
§4.2. A `TrackingMode::Channel(String)` variant captures this.

This means channels add a *resolution step* on top of the current design; they
do not replace `creation_token`, semver, or bundle selection.

### 5.4 Relationship to the signed `[latest]` pointer (TARGET)

Brief §4.3 also defines a single signed `[latest]` pointer (`tag`,
`creation_token`, `head` — the authentic git commit SHA) as the *freshness /
anti-rollback anchor*. `[latest]` is the registry-wide "newest published
release"; channels are *named, possibly-lagging* views (`stable` typically
trails `[latest]`). Both are signed fields in the same root and flip atomically
on publish (brief §4.4). The consumer applies monotonic `creation_token` checks
against the *channel's* `creation_token` for channel subscribers, and against
`[latest].creation_token` for freshness.

---

## 6. Freshness, freeze, and anti-rollback for channels (TARGET)

Channels and the `[latest]` pointer inherit the threat model in
[signing-and-trust](./signing-and-trust.md) (brief §4.5). Three defenses apply
to *which release a channel resolves to*:

### 6.1 `valid_until` (freeze defense) — TARGET

A mirror stuck on a validly-signed-but-old root cannot be detected by sequence
numbers alone. The target root carries an APT-style `[meta].valid_until` expiry
(brief §4.3, §6 item 1); a client **rejects an expired root**, so a frozen
mirror degrades to a *visible* failure rather than silently serving a stale
channel. Re-signed each publish with `valid_until = publish_time + N`.

### 6.2 Monotonic `[latest].creation_token` — TARGET

The current `check_monotonic` on `RegistryState.last_creation_token`
(`state.rs:104-117`, §2.3) moves up to operate on the signed
`[latest].creation_token` in the root, plus a git `merge-base --is-ancestor`
ancestry check
(`security.rs` `check_downgrade`, brief §2.10/§4.5). A channel repointed
*backward* (lower token than the host's current state for that channel) is
rejected as a downgrade.

### 6.3 Fail-closed omission — TARGET

With the signed `[latest].head` (authentic commit SHA), a mirror that *omits*
newer bundles causes the client to **fail closed** — it cannot reach the signed
target commit and errors, rather than silently using stale data (brief §4.5).
Freeze degrades to DoS, not silent rollback.

| Threat | CURRENT defense | TARGET defense |
|---|---|---|
| Downgrade | `check_monotonic` on local `last_creation_token` (§2.3, conditional) | unconditional monotonic on signed `[latest].creation_token` + git ancestry |
| Freeze (stale valid root) | — (none) | `valid_until` signed expiry |
| Omission (hidden newer bundles) | — (silently stale) | fail-closed via signed `[latest].head` |
| Tamper / MITM | NAR SHA-256 + signed commit (transitive) | + inline-signed root, by-hash index |

---

## 7. Phased rollouts (TARGET)

> **Status: TARGET.** No rollout gating exists in the code. This is brief §6
> (item 4), the analogue of APT `Phased-Update-Percentage`.

### 7.1 Motivation

For a fleet, flipping a channel to a new tag exposes *every* host at once — a
bad release has maximum blast radius. A **rollout percentage** on a channel
target lets a publisher say "make `v2026.03` the `testing` target, but only
~25% of hosts should adopt it yet." This is a **canary** mechanism for
blast-radius control.

```toml
[channels.testing]
tag     = "v2026.03"
rollout = 25                # ~25% of the fleet adopts now; the rest hold
```

### 7.2 Deterministic gating (TARGET)

The gate MUST be **deterministic per host** so that a host's adopt/hold
decision is stable across `apm update` runs (no flapping) and so the cohort is
reproducible. The design (brief §6 item 4, open question §7.4) is a
deterministic hash bucket keyed on the **channel name** — explicitly **not** the
target tag, so cohorts stay stable across promotions:

```
bucket = sha256(machine_id : channel_name) mod 100      # 0..99, stable per host
adopt  = bucket < rollout
```

- A host with `bucket = 12` adopts at `rollout >= 13`; a host with `bucket = 80`
  waits until `rollout >= 81`.
- Because the bucket is a function of a stable `machine_id` and the channel
  name — and **not** the candidate tag — the *same* hosts adopt first as the
  publisher ramps `rollout` 25 → 50 → 100, and the cohort is unchanged across
  successive promotions (a host's bucket does not re-shuffle when the channel
  repoints to a new tag). Adoption is **monotone**, not re-shuffled each step.
- A host in the held (not-yet-rolled-out) cohort is a **no-op**: it stays at its
  current `last_creation_token` (its previously-resolved release), not at
  no-release. There is no `previous_tag` field — the held host simply does not
  advance.

> **Open question (brief §7.4):** the exact hash construction within
> `sha256(machine_id : channel_name)` (delimiter, encoding) and how a host
> reports/learns its bucket are not yet fixed; the inputs are settled as
> `machine_id` and `channel_name` (tag excluded). Tracked in
> [open questions](../plans/registry/open-questions.md) and to be specified by
> [workstream-04](../plans/registry/workstream-04-channels-rollouts.md).

### 7.3 Rollout lifecycle (TARGET)

```
 day 0   testing.tag = v2026.03   rollout =   5    canary cohort only
 day 2   testing.tag = v2026.03   rollout =  25    widen if metrics healthy
 day 5   testing.tag = v2026.03   rollout = 100    full; promote to stable next
 ...     stable.tag  = v2026.03.1 rollout = 100    promoted after soak
```

Each step is one atomic signed flip of the root (brief §4.4 publish ordering);
hosts re-evaluate their bucket against the new `rollout` on the next
`apm update`. A regression at any step is rolled back by repointing the channel
(subject to the §6.2 monotonic/ancestry checks — a rollback to an *older* tag
needs an explicit, signed, ancestry-valid move).

---

## 8. Components (TARGET)

> **Status: TARGET.** No component field or partitioning exists in the code.
> This is brief §4.3 and §6 (item 5), the analogue of APT
> `main`/`contrib`/`non-free`.

A **component** is an optional *intra-registry partition* by trust, license, or
stability — a single signed root can expose multiple component views without
splitting into separate registries. Brief §4.3: *"`[components]` optional
intra-registry partitions (trust/license/stability)."*

```toml
# registry.toml (TARGET) — component partitions in one signed root
[components.main]
description = "Fully-supported, hermetic-from-source packages."

[components.contrib]
description = "Community-contributed; built from source but lower support tier."
```

Mapping to APT and to the AOS layout (brief §5 comparison table):

| APT | AOS registry (TARGET) |
|---|---|
| `dists/<suite>/<component>/binary-<arch>/` | registry **name** + **component** + **platform** |
| `main` / `contrib` / `non-free` | `[components]` partitions in one signed root |

Components compose *orthogonally* with channels and platforms: a host could, in
principle, subscribe to the `stable` channel of the `main` component for its
platform. The exact consumer surface (a `component` field? a default of
`main`?) is part of
[workstream-04](../plans/registry/workstream-04-channels-rollouts.md) and is
left open here because no consumer code consumes it yet.

---

## 9. Worked examples

### 9.1 CURRENT — version constraint adopts patches automatically

```toml
# registries.d/aos-core.toml
[registry]
name = "aos-core"
url  = "https://registry.aos.dev/core"
version = "~2026.2"
```

Given a bundle manifest containing tags `v2026.02`, `v2026.02.1`, `v2026.02.2`
(the sample at `update.rs:586-625`):

1. `tracking_mode()` → `Version(~2026.2)` (`types.rs:388-396`).
2. `find_best_version_tag_in_manifest` projects each tag to semver
   (`2026.2.0`, `2026.2.1`, `2026.2.2`), all match `~2026.2`, picks the highest:
   `v2026.02.2` (`update.rs:400-424`, test `update.rs:754-761`).
3. `pick_bundles` resolves a snapshot or skip/sequential delta to `v2026.02.2`
   (`update.rs:318-337`; test `pick_bundles_version_mode` at
   `update.rs:714-726`).
4. On the next month, `v2026.03` appears; `~2026.2` does **not** match it, so
   the host stays on the `2026.02.x` line — patches yes, minor bump no.

### 9.2 TARGET — channel + phased rollout

```toml
# registries.d/aos-core.toml (TARGET)
[registry]
name    = "aos-core"
url     = "https://registry.aos.dev/core"
channel = "testing"
```

```toml
# registry.toml (TARGET, published)
[channels.testing]
tag            = "v2026.03"
creation_token = 2026030000
rollout        = 25
```

1. `apm update` fetches and verifies the signed root, checks `valid_until`
   (§6.1).
2. Resolve `channel = "testing"` → candidate `tag = v2026.03`,
   `creation_token = 2026030000`.
3. Compute `bucket = sha256(machine_id : "testing") mod 100` (§7.2). If
   `bucket < 25`, adopt `v2026.03`; else hold — a no-op that stays at the host's
   current `last_creation_token`.
4. If adopting, feed `v2026.03` into the **existing** `pick_bundles` path (§4.2)
   exactly as a `tag` pin would, apply the monotonic/ancestry checks against
   the channel `creation_token` (§6.2), download/verify/unbundle as today.

---

## 10. Cross-references

- **Tag → token → semver internals** and the full `pick_bundles` algorithm:
  [bundles-and-deltas](./bundles-and-deltas.md).
- **The signed `registry.toml` root** that will carry `[channels]`,
  `[latest]`, `[components]`, and `[meta].valid_until`:
  [registry-toml](./registry-toml.md) and [http-layout](./http-layout.md).
- **As-is grounding** for tracking modes, state, and the producer gaps:
  [current-state](./current-state.md).
- **Signatures, TOFU, and the threat model** behind §6:
  [signing-and-trust](./signing-and-trust.md).
- **Atomic publish ordering** that flips channels/`[latest]`:
  [publishing](./publishing.md).
- **APT precedent** for channels, phased updates, and components:
  [apt-comparison](./apt-comparison.md).
- **Implementation plan:**
  [workstream-04](../plans/registry/workstream-04-channels-rollouts.md)
  (channels, rollouts, components, freshness),
  [workstream-05](../plans/registry/workstream-05-consumer.md) (consumer:
  channel tracking, expiry/freeze checks, fail-closed omission), and
  [gap-analysis](../plans/registry/gap-analysis.md).
