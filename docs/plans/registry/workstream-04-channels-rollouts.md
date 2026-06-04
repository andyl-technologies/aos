# Workstream 04 — Channels, Rollouts, Components & Freshness

> **Status:** Implementation plan / **TARGET** design. As-is code behavior is
> labelled **CURRENT** and cited as `path:line`; the design goal is labelled
> **TARGET**. Where the code contradicts the brief's current-state narrative, the
> code wins and the discrepancy is recorded in
> [open-questions.md](./open-questions.md).
>
> **Audience:** users, implementers, architects, engineers.
>
> **Grounding:** [design brief](./design-brief.md) §4.3 (single signed root),
> §4.5 (trust / threat model), and §6 (APT improvements to adopt). The brief is
> authoritative for intent; this doc translates that intent into a concrete
> producer + consumer change set.

This workstream implements the **four operationally-visible features** that the
single signed `registry.toml` root unlocks once it exists (per
[WS-01](./workstream-01-registry-root.md)):

| Feature | Brief tier | Kind | What it buys |
|---|---|---|---|
| **`valid_until` / freshness** | §6 Tier 1 item 1 | correctness / security | Freeze-attack defense: a client rejects a validly-signed-but-stale root. |
| **Symbolic channels** | §6 Tier 1 item 3 | operational | Promotion UX: `stable`/`testing` decoupled from tags; promote = one atomic signed flip. |
| **Phased rollouts** | §6 Tier 1 item 4 | operational | Fleet blast-radius control: gate adoption on a deterministic machine-id hash. |
| **Components** | §6 Tier 2 item 5 | operational | Intra-registry partitions (trust / license / stability tiers) in one signed root. |
| **Capability flags** | §6 Tier 2 item 6 | forward-compat | Advertise optional features for graceful degradation and forward compatibility. |

These are *fields of the signed root* and a *client honoring* layer, not a new
network surface. The dependency is therefore **M1 → M4**: WS-04 extends the WS-01
schema rather than inventing a new file (see the
[plan README milestone roadmap](./README.md#4-milestone-roadmap)).

---

## 1. Where this sits in the plan

```
 M0 ──► M1 ──► M2 ──► M3
        │       │
        └──► M4 ─┘            ◄── THIS workstream (extends the WS-01 root schema)
                 │
                 ▼
                M5            ◄── consumer cutover honors these fields (WS-05)
```

- **Producer half (this doc, §3–§7).** Add `valid_until`, `[capabilities]`,
  `[channels]`, and `[components]` to the `registry.toml` writer (the serializer
  built in [WS-01](./workstream-01-registry-root.md)); add `apr` commands to set
  channels/components and re-sign with a fresh expiry; wire them into the
  `apr release` ordering from [WS-02](./workstream-02-publish-pipeline.md).
- **Consumer half (this doc, §8; full cutover in
  [WS-05](./workstream-05-consumer.md)).** Teach the client to track a `channel`,
  honor `rollout` via a deterministic gate, enforce `valid_until`, and parse
  `[capabilities]` for graceful degradation.

The reference-state description of these features for users lives in
[`versioning-and-channels.md`](../../registry/versioning-and-channels.md); the
signed-root schema that hosts them is
[`registry-toml.md`](../../registry/registry-toml.md); the threat model they serve
is [`signing-and-trust.md`](../../registry/signing-and-trust.md).

---

## 2. CURRENT state (as-is, grounded in code)

> **CURRENT.** None of channels, rollouts, components, `valid_until`, or
> capability flags exist in the code today. What exists is calendar-version
> tracking, four tracking modes, and a monotonic-token anti-rollback check. This
> section establishes the surfaces WS-04 extends.

### 2.1 Tracking modes — the closest existing surface

The consumer already resolves *which version of a registry to follow* through
`TrackingMode`
([`crates/aos-package/src/types.rs:281`](../../crates/aos-package/src/types.rs)):

```rust
pub enum TrackingMode {
    Commit(String),               // frozen to an exact commit hash
    Branch(String),               // HEAD of a named branch
    Tag(String),                  // pinned to an exact tag
    Version(semver::VersionReq),  // semver constraint over tags
    Default,                      // no field set -> default branch HEAD
}
```

`RegistryConfig::tracking_mode()`
([`types.rs:352`](../../crates/aos-package/src/types.rs)) validates that **at most
one** of `commit` / `branch` / `tag` / `version` is set (the legacy `pin` field
folds into `tag`). The per-registry config struct that carries these fields is
`RegistryConfig` ([`types.rs:210`](../../crates/aos-package/src/types.rs)) /
`RegistryFileInner` ([`types.rs:529`](../../crates/aos-package/src/types.rs)).

> **Gap.** There is **no `channel` field** on `RegistryConfig` /
> `RegistryFileInner`, and **no `Channel` variant** on `TrackingMode`. Channel
> tracking is entirely absent. WS-04 adds both (see §4 and §8).

### 2.2 Version / token machinery (reused by channels & rollouts)

- `parse_tag_as_semver`
  ([`update.rs:429`](../../crates/aos-package/src/update.rs)) — strips `v`, strips
  leading zeros, pads 2-component tags to `.0`: `v2026.02` → `2026.2.0`,
  `v2026.02.3` → `2026.2.3`.
- `find_best_version_tag_in_manifest`
  ([`update.rs:400`](../../crates/aos-package/src/update.rs)) — filters manifest
  tags by a `VersionReq`, picks the highest match.
- `version_to_token` / `token_to_version`
  ([`crates/aos-package/src/registry/state.rs:131`](../../crates/aos-package/src/registry/state.rs)
  and `:168`) — encode/decode `YYYYMMPPP` as `year*1_000_000 + month*10_000 +
  patch`; reject non-`vYYYY.MM[.P]`, month 1–12, patch ≤ 9999.
- `check_monotonic` (`registry/state.rs`) — rejects `new_token <= old_token`
  (downgrade / stale-mirror defense). **CURRENT** call site is gated behind
  `latest_token > old_token` ([`update.rs:263`](../../crates/aos-package/src/update.rs)),
  which makes the guard a no-op when the new token is *not* already greater — see
  §3.4 and the open question recorded below.

A channel's `tag` and a rollout's bucketing both reuse this `tag → token`
encoding, so WS-04 adds **no** new version math; it threads the existing
functions through a channel-resolution step.

### 2.3 State persistence (extended by rollouts)

The consumer persists `RegistryState { last_commit, last_creation_token,
last_update }` ([`types.rs:254`](../../crates/aos-package/src/types.rs)) under
`[registry.state]` in the per-registry config file; `update.rs` rewrites all
three after a successful sync
([`update.rs:270`](../../crates/aos-package/src/update.rs)). WS-04 adds **no**
required state fields, but §8.3 discusses an *optional* `rollout_seed` for
stable, non-machine-identifying bucketing.

### 2.4 The root schema today

The CURRENT `registry.toml` deserialized type is `RegistryRootConfig`
([`types.rs:566`](../../crates/aos-package/src/types.rs)) — only `[registry]`
(name, description), `[[caches]]`, and `[signing]`. It has **no** `[meta]`,
`valid_until`, `[capabilities]`, `[channels]`, `[components]`, `[latest]`, or
bundle index. WS-01 introduces those tables; WS-04 fills in the channel /
rollout / component / freshness subset.

> **CURRENT vs brief note.** Design brief §2.2 describes the root as
> `RegistryRootConfig { registry, caches, signing }` — the code agrees. The brief
> §4.3 *target* fields (`valid_until`, `[capabilities]`, `[channels]`,
> `[components]`, `[latest]`) are all unimplemented. No contradiction with the
> code; this whole workstream is net-new.

---

## 3. `valid_until` & freshness (Tier 1, correctness/security)

### 3.1 The threat it closes

From [design brief §4.5](./design-brief.md), the **Freeze** attack: a mirror (or
a MITM that can only withhold, not forge) serves a **validly-signed but old**
root forever. The signature verifies; the git history is authentic; yet the
client never learns that newer, security-relevant versions exist. Sequence-based
`[latest].token` alone cannot see this — the old root's token is genuinely the
newest token *the client has been shown*.

`valid_until` is the APT `Valid-Until` analogue (brief §5 table, §6 Tier 1 item
1): an absolute RFC 3339 timestamp inside the signed body. After it passes, the
client refuses the root. Freeze then degrades from a **silent rollback** to a
**loud DoS** — the client knows it cannot get fresh metadata and fails closed.

### 3.2 Producer responsibilities

| Step | Action |
|---|---|
| Compute | `valid_until = date + W`, where `date` is the publish/sign time and `W` is the freshness window (recommended default: ~30 days, pending [open question Q5](./open-questions.md); the 7-day span shown below is illustrative only). |
| Serialize | Emit `[meta].date` and `[meta].valid_until` as RFC 3339 in the root body (WS-01 serializer). |
| Sign | The inline `[signature]` covers `valid_until`, so a mirror cannot extend the window. |
| Re-sign cadence | Every publish re-stamps `date`/`valid_until`. A registry that publishes less often than `W` needs a **heartbeat re-sign** (re-sign the same `[latest]` with a fresh window) so quiet registries don't self-expire. |

```toml
[meta]
schema      = 1
name        = "aos-core"
date        = "2026-06-03T17:04:00Z"   # when this root was signed
valid_until = "2026-06-10T17:04:00Z"   # FREEZE DEFENSE: reject if now > this
                                       # (7d span shown is illustrative; default window ~30d)
```

`apr` gains the freshness window as a config knob plus an `apr resign` (or
`apr refresh`) verb that re-stamps and re-signs without changing `[latest]` — the
heartbeat. This re-sign reuses the [WS-02](./workstream-02-publish-pipeline.md)
atomic root-flip ordering (it is just a root flip with an unchanged body except
`date`/`valid_until`/`[signature]`).

### 3.3 Consumer responsibilities (honoring)

On reading the root, after signature verification:

```text
if now() > meta.valid_until:
    reject root  ->  AosError::RegistryError { message: "registry root expired …" }
    (do NOT fall back to a cached body silently; surface the staleness)
```

This is **fail-closed**: an expired root is treated as *no usable metadata*, not
as *the latest metadata*. The exact error surfacing and any grace/skew tolerance
(clock skew on appliances) is detailed in
[WS-05](./workstream-05-consumer.md) and flagged in
[open-questions.md](./open-questions.md).

### 3.4 Relationship to the existing monotonic guard

`valid_until` is **complementary** to `check_monotonic` on `[latest].token`, not
a replacement:

| Defense | Catches | Mechanism |
|---|---|---|
| `check_monotonic` (CURRENT, `registry/state.rs`) | Rollback / downgrade to an *older* token | Reject `new_token <= old_token`. |
| `valid_until` (TARGET, this WS) | Freeze on a *current-but-stale* token | Reject `now > valid_until`. |
| `[latest].head` (WS-01 / brief §4.5) | Omission (hiding newer bundles) | Fail closed when the signed head is unreachable. |

> **Discrepancy to record.** The CURRENT `check_monotonic` call site is gated
> behind `if latest_token > old_token` ([`update.rs:263`](../../crates/aos-package/src/update.rs)),
> so the downgrade check only runs when the new token is *already* greater than
> the old — i.e. exactly the case that is **not** a downgrade. A genuine rollback
> (`latest_token <= old_token`) skips the check entirely. WS-04's freshness work
> touches the same anti-rollback story, so this is logged in
> [open-questions.md](./open-questions.md) for WS-05 to address during the
> consumer cutover.

---

## 4. Symbolic channels (Tier 1, operational)

### 4.1 Model

A **channel** is a stable, human-named alias (`stable`, `testing`, `lts`) that
maps to a concrete calendar tag inside the signed root. Clients track the
*channel name*; the registry owner moves the channel's `tag` to **promote**. The
promotion is **one atomic signed flip** of one field in `registry.toml` (brief
§4.3, §4.4, §6 Tier 1 item 3) — no client config change, no new bundle.

```toml
[channels.stable]
tag            = "v2026.05.3"
creation_token = 2026050003   # per-channel monotonic anti-rollback token
rollout        = 100          # percent; omit or 100 = fully rolled out (see §5)

[channels.testing]
tag            = "v2026.06.0"
creation_token = 2026060000
rollout        = 25           # phased: only ~25% of the fleet adopts
```

This is the field shape established in
[`registry-toml.md` §3.3](../../registry/registry-toml.md): `[channels.<name>]`
is a subtable (not an inline table, not a `[[array]]`) carrying `tag`,
`creation_token` (per-channel monotonic anti-rollback), and an optional `rollout`
(omit or 100 = fully rolled out).

### 4.2 Why decouple from tags

The CURRENT consumer can already pin a `tag` or follow a `version` constraint
(§2.1), but both bind the *client config* to concrete versions:

| Approach | Promotion = | Client change on promote? |
|---|---|---|
| CURRENT `tag = "v2026.05.3"` | edit every client's config | **yes** — fleet-wide config push |
| CURRENT `version = "~2026.5"` | publish a new matching tag | no, but the constraint is hard-coded and inflexible |
| TARGET `channel = "stable"` | flip `[channels].stable.tag` in the signed root | **no** — one server-side signed flip |

Channels give the operator a server-side promotion lever with no client churn,
which is the whole point of the APT suite/channel model the brief converges on
(brief §5).

### 4.3 Producer responsibilities

1. **Schema (WS-01).** Add a `channels: BTreeMap<String, ChannelEntry>` field to
   the root config type, where:

   ```rust
   pub struct ChannelEntry {
       pub tag: String,
       pub creation_token: u64,                  // per-channel monotonic anti-rollback
       #[serde(default = "default_rollout")]   // 100
       pub rollout: u8,                          // 0..=100
   }
   ```

   Use `BTreeMap` (not `HashMap`) so the serialized output is **deterministic**,
   which matters because the body is signed (a non-deterministic map order would
   change the signed bytes between runs).

2. **`apr` verbs.** Add channel management that edits the root and re-signs:
   - `apr channel set <name> <tag> [--rollout N]` — point a channel at a tag.
   - `apr channel rm <name>` — remove a channel.
   - `apr channel ls` — list channels and their targets.
   - `apr promote <name> <tag>` — convenience alias for `channel set` framed as a
     release action; flips `[channels].<name>.tag` and re-signs.

   Each verb mutates the in-memory root, re-serializes (WS-01), and re-signs;
   publishing the new root uses the [WS-02](./workstream-02-publish-pipeline.md)
   atomic flip. **Validation:** `channel set` must reject a `tag` that is not
   present in the bundle/delta index of the same root (a channel may not point at
   a tag the client cannot resolve), and `0 <= rollout <= 100`.

3. **Capability flag.** Set `[capabilities].channels = true` (see §7) so older
   clients can detect the feature.

### 4.4 Consumer responsibilities (honoring)

Add a fifth tracking mode and a config field:

```rust
// types.rs — RegistryConfig / RegistryFileInner
#[serde(default)]
pub channel: Option<String>,   // mutually exclusive with commit/branch/tag/version

// types.rs — TrackingMode
Channel(String),               // resolve via [channels].<name>.tag at update time
```

`tracking_mode()` ([`types.rs:352`](../../crates/aos-package/src/types.rs)) gains
`channel` to its mutual-exclusion count and returns `TrackingMode::Channel(name)`
when set. Resolution at update time:

```text
1. read & verify registry.toml root
2. mode = Channel("stable")
3. let chan = root.channels["stable"]              # error if missing
4. if !rollout_admits(machine_id, "stable", chan): # §5
       hold at current version (channel not yet adopted on this machine)
   else:
       resolve chan.tag the same way Tag mode does today
       (pick_bundles snapshot/delta to chan.tag — update.rs:299)
```

Because a resolved channel collapses to a concrete `tag`, the existing
`pick_bundles` **Tag branch**
([`update.rs:299`](../../crates/aos-package/src/update.rs)) is reused verbatim
once the channel→tag resolution and rollout gate have run. No new bundle-selection
logic is required.

> The full consumer wiring (config parsing, mutual-exclusion update, the
> `Channel` arm in `pick_bundles`) is owned by
> [WS-05](./workstream-05-consumer.md); WS-04 specifies the *contract* those
> changes must satisfy.

---

## 5. Phased rollouts (Tier 1, operational)

### 5.1 Model

A channel target carries an optional `rollout = N` (0–100). When `N < 100`, only
~N% of the fleet adopts the channel's new `tag`; the rest **hold** at their
current version until `N` is raised. This is the AOS analogue of APT's
`Phased-Update-Percentage` (brief §6 Tier 1 item 4, §5 table). It gives
canary / blast-radius control: ship `v2026.06.0` to 5%, watch, then 25%, 100%.

The gate must be **deterministic per machine**: the same machine must always land
on the same side of a given percentage so that raising `N` is monotonic (a machine
that adopted at 25% must still be "in" at 50%) and a machine never flaps in and
out across updates.

### 5.2 The gating function (TARGET)

> **Open question.** The exact hash and inputs are
> [open question §7.4](./open-questions.md). This section specifies the
> *properties* the function must have and a concrete candidate; the candidate is
> not yet ratified.

**Properties the gate MUST satisfy:**

1. **Deterministic** — pure function of stable inputs (no RNG, no wall-clock).
2. **Per-(machine, channel)** — bucketing keyed on machine identity *and* the
   channel name, so a machine that's an early adopter on `testing` is not
   correlated into being an early adopter on every channel.
3. **Stable under target change** — keyed on the channel, **not** the target tag,
   so promoting `stable` from `v2026.05.2` → `v2026.05.3` does **not** re-roll the
   dice and shuffle which machines are "in". (APT keys its phasing on the *source
   package + version*; AOS keys on the *channel* because the channel is the stable
   identity and the tag is what moves.)
4. **Uniform** — a good hash so buckets are evenly spread; raising `N` only ever
   *adds* machines (monotone inclusion).

**Candidate function:**

```text
seed   = machine_id                     # /etc/machine-id, or a per-install rollout_seed (§8.3)
digest = sha256( seed || ":" || channel_name )
bucket = first_8_bytes_as_u64(digest) % 100     # 0..=99
admit  = bucket < rollout                        # rollout = N  ->  buckets 0..N-1 adopt
```

Monotonicity falls out: machine `m` adopts channel `c` at rollout `N` iff
`bucket(m,c) < N`; since `bucket` is fixed, raising `N` only flips more machines
from hold→adopt, never the reverse. `rollout = 100` admits every bucket
(`bucket < 100` always true); `rollout = 0` admits none.

```
rollout = 25
bucket:   0         24 25                              99
          ├───adopt──┤ ├──────────────hold─────────────┤
          └─ 25% of the fleet, deterministically chosen ┘

rollout raised to 50  ->  buckets 0..49 adopt (the original 0..24 stay in)
```

### 5.3 Producer responsibilities

- Serialize `rollout` on the channel entry (default 100 when omitted, per §4.3's
  `ChannelEntry`).
- `apr channel set --rollout N` and `apr promote --rollout N` set/raise the value;
  re-sign + atomic flip publishes it.
- **Recommended discipline (docs, not enforced):** promote the *tag* first at a low
  `rollout`, then ratchet `rollout` upward on the *same tag* in subsequent flips.
  Lowering `rollout` after machines have adopted does **not** roll them back (a
  consumer that already moved to the tag stays there); rollout gates *adoption*,
  not *retention*. This retention asymmetry is called out in
  [`versioning-and-channels.md`](../../registry/versioning-and-channels.md) and
  [open-questions.md](./open-questions.md).

### 5.4 Consumer responsibilities (honoring)

`rollout_admits(machine_id, channel_name, channel_entry)` implements §5.2 and
gates the channel resolution in §4.4. When the gate returns **hold**, the update
is a **no-op for that registry** (the client stays at its current
`last_creation_token`); this is not an error and must not abort syncing other
registries. The `[capabilities].rollouts` flag (§7) tells a client whether to
expect/honor the gate; a client that does not implement rollouts treats every
channel as `rollout = 100` (graceful degradation — it adopts immediately, which
is safe-but-less-cautious).

---

## 6. Components (Tier 2, operational)

### 6.1 Model

**Components** partition one registry into named tiers — the APT
`main` / `contrib` / `non-free` analogue (brief §6 Tier 2 item 5, §5 table). They
let one signed root express *trust / license / stability* partitions without
splitting into separate registries:

```toml
[components.main]
description = "Hermetic-from-source, fully supported"

[components.contrib]
description = "Community packages, supported best-effort"

[components.staging]
description = "Pre-release / unstable; opt-in"
```

A package's component membership is recorded on the package side (a `component`
field on the per-package metadata, defaulting to `main`); the root enumerates the
*set of components* and their human descriptions so a client can offer
`enabled_components` filtering.

### 6.2 Producer responsibilities

- Schema (WS-01): `components: BTreeMap<String, ComponentEntry>` on the root,
  `ComponentEntry { description: Option<String> }` (room to grow: a future
  `default_enabled: bool`, a per-component signing sub-key, etc.).
- `apr component add/rm/ls` to manage the set; re-sign + flip.
- Per-package `component` field plumbed through the publish path
  ([WS-02](./workstream-02-publish-pipeline.md)) and the package metadata type
  (`PackageMeta`, [`types.rs:44`](../../crates/aos-package/src/types.rs) — add
  `#[serde(default)] component: Option<String>` defaulting to `main`, keeping old
  TOMLs parseable).
- `[capabilities].components = true`.

### 6.3 Consumer responsibilities (honoring)

- Optional `enabled_components` on `RegistryConfig` (default: all). When set, the
  client filters candidate packages by their `component` during resolution.
- A client that doesn't understand components ignores the field and sees every
  package (graceful degradation) — which is why `main` is the safe default for
  un-tagged packages.

Components are **Tier 2**: lower urgency than channels/rollouts/`valid_until`.
They can land after M4's Tier-1 features without blocking them. The full consumer
filtering is part of [WS-05](./workstream-05-consumer.md).

---

## 7. Capability flags (Tier 2, forward-compat)

### 7.1 Model

`[capabilities]` is a table of booleans in the signed root advertising which
optional features this registry implements (brief §6 Tier 2 item 6 — the APT
`Acquire-By-Hash: yes` analogue). It enables **graceful degradation** (a client
skips a feature the registry doesn't advertise) and **forward compatibility** (a
new client can detect an old registry and a new registry can announce a feature
to clients that know to look).

```toml
[capabilities]
by_hash   = true    # index references are by-hash (WS-01)
channels  = true    # [channels] present and maintained (§4)
rollouts  = true    # rollout gating is honored / meaningful (§5)
components = true   # [components] partitioning present (§6)
nix_cache = true    # serves the Nix narinfo superset (WS-03)
```

This is the exact set already shown in
[`registry-toml.md` §4](../../registry/registry-toml.md). WS-04 owns the
`channels`, `rollouts`, and `components` flags; `by_hash` is owned by
[WS-01](./workstream-01-registry-root.md) and `nix_cache` by
[WS-03](./workstream-03-nix-cache.md).

### 7.2 Semantics & rules

| Rule | Rationale |
|---|---|
| **Unknown keys are ignored.** A client parses `[capabilities]` leniently (`#[serde(default)]`, no `deny_unknown_fields`). | A future registry advertising a future capability must not break an old client. |
| **A missing flag means "not advertised", treated as `false`.** | Absence ⇒ degrade. E.g. no `rollouts` flag ⇒ a client treats channels as un-phased (`rollout = 100`). |
| **Flags advertise intent, not permission.** A client still validates signatures/hashes regardless of flags. | Capabilities are a compatibility hint, **never** a security boundary; the brief's trust roots (signed root + signed commit + content hashes) are unconditional. |
| **The table is inside the signed body.** | A mirror cannot strip a capability to downgrade a client into skipping a defense. |

### 7.3 Producer & consumer responsibilities

- **Producer:** the WS-01 serializer emits `[capabilities]`; each feature
  workstream sets its own flag when it activates the feature. A `Capabilities`
  struct with `#[serde(default)]` bool fields keeps it forward-compatible.
- **Consumer:** parse leniently; branch behavior on the flags only for
  *degradation* decisions (skip rollout gating if `!rollouts`, skip component
  filtering if `!components`), never for trust decisions.

---

## 8. Consumer honoring — contract summary

WS-04 defines the **producer-side fields** and the **client-honoring contract**;
the mechanical consumer changes land in
[WS-05](./workstream-05-consumer.md). The contract the consumer must satisfy:

### 8.1 New config surface

```toml
# registries.d/<name>.toml  (TARGET additions)
[registry]
name    = "aos-core"
url     = "https://registry.aos.dev/core"
channel = "stable"                 # NEW: mutually exclusive with commit/branch/tag/version
# enabled_components = ["main", "contrib"]   # NEW (optional; default = all)
```

`channel` joins the mutual-exclusion set enforced by `tracking_mode()`
([`types.rs:352`](../../crates/aos-package/src/types.rs)); setting `channel`
alongside any of `commit`/`branch`/`tag`/`version` is an error, consistent with
the CURRENT one-of-N validation.

### 8.2 Resolution order at `apm update`

```text
fetch & verify registry.toml root  (signature + valid_until + [latest].head)
│
├─ valid_until passed?           ── no ─► reject root, fail closed (§3.3)
│
├─ mode == Channel(name)?
│     ├─ root.channels[name] missing?          ─► error
│     ├─ rollout_admits(machine, name, entry)? ── no ─► HOLD (no-op, not error) (§5.4)
│     └─ yes ─► tag = entry.tag ─► reuse Tag-mode pick_bundles (update.rs:299)
│
├─ mode == Tag/Version/Branch/Commit/Default ─► unchanged CURRENT behavior
│
└─ filter candidates by enabled_components (if set & capability advertised) (§6.3)
```

### 8.3 Optional `rollout_seed`

The default rollout seed is the host machine-id (`/etc/machine-id`). For
deployments that consider the machine-id sensitive, or for multi-tenant test
fleets that want reproducible bucketing without a real machine-id, a per-install
`rollout_seed` may be persisted (proposal: alongside `[registry.state]`, or in
`apm.conf`). This is **optional** and does **not** change the gate's math — it only
substitutes the `seed` input in §5.2. Exact placement is
[open question §7.4](./open-questions.md).

### 8.4 Graceful degradation matrix

| Client lacks… | Registry advertises… | Behavior |
|---|---|---|
| channel support | `channels = true` | Client can't track `channel`; user must pin a `tag`/`version` (older clients). |
| rollout support | `rollouts = true` | Channel treated as `rollout = 100` — adopts immediately (safe-but-eager). |
| component support | `components = true` | All packages visible (no filtering) — `main` default keeps this sane. |
| `valid_until` enforcement | always present | **Must not** be optional: expiry is a security defense; a conformant client enforces it. |

Note the asymmetry: channels/rollouts/components degrade *gracefully*, but
`valid_until` is a **security** field and is **not** subject to opt-out
degradation — see [`signing-and-trust.md`](../../registry/signing-and-trust.md).

---

## 9. Task checklist

> Producer tasks assume the WS-01 serializer and WS-02 atomic flip exist
> (M1/M2 land before M4 per the [roadmap](./README.md#4-milestone-roadmap)).

**Schema (extends WS-01 root types):**

- [ ] Add `[meta].date` / `[meta].valid_until` (RFC 3339) to the root config + writer.
- [ ] Add `channels: BTreeMap<String, ChannelEntry>` (`tag`, `creation_token`,
      `rollout` default 100).
- [ ] Add `components: BTreeMap<String, ComponentEntry>` (`description?`).
- [ ] Add `Capabilities` table (`by_hash`, `channels`, `rollouts`, `components`,
      `nix_cache`), all `#[serde(default)]`, lenient parse.
- [ ] Add `#[serde(default)] component: Option<String>` to `PackageMeta`
      ([`types.rs:44`](../../crates/aos-package/src/types.rs)), default `main`.

**Producer (`apr`):**

- [ ] `apr channel set/rm/ls`, `apr promote` — edit root, validate tag-in-index +
      `0..=100`, re-sign, atomic flip (WS-02).
- [ ] `apr component add/rm/ls`.
- [ ] `apr resign`/`apr refresh` heartbeat — re-stamp `date`/`valid_until`,
      re-sign, flip, unchanged `[latest]`.
- [ ] Freshness window `W` as an `apr` config knob (recommended default ~30d; 7d
      illustrative-only — [open question Q5](./open-questions.md)).
- [ ] Set capability flags when each feature is activated.

**Consumer (contract; built in [WS-05](./workstream-05-consumer.md)):**

- [ ] `channel` field on `RegistryConfig` / `RegistryFileInner`; add to
      `tracking_mode()` mutual exclusion; add `TrackingMode::Channel`.
- [ ] `Channel` arm in `pick_bundles` — resolve channel→tag, then reuse Tag branch
      ([`update.rs:299`](../../crates/aos-package/src/update.rs)).
- [ ] `rollout_admits()` deterministic gate (§5.2); HOLD = no-op, not error.
- [ ] Enforce `valid_until` (fail closed); reconcile the `check_monotonic` gating
      discrepancy (§3.4, [open-questions.md](./open-questions.md)).
- [ ] Parse `[capabilities]` leniently; degrade per §8.4.
- [ ] Optional `enabled_components` filtering; optional `rollout_seed`.

---

## 10. Cross-references

### Reference set (`docs/registry/`, TARGET state)

- [versioning-and-channels.md](../../registry/versioning-and-channels.md) —
  user-facing description of channels, rollouts, components, and the tracking modes.
- [registry-toml.md](../../registry/registry-toml.md) — the signed-root schema that
  hosts `[meta].valid_until`, `[capabilities]`, `[channels]`, `[components]`.
- [signing-and-trust.md](../../registry/signing-and-trust.md) — why `valid_until` is
  a security field, the threat model (freeze / rollback / omission), and the one key.
- [apt-comparison.md](../../registry/apt-comparison.md) — APT `Valid-Until`,
  suites/channels, `Phased-Update-Percentage`, components, `Acquire-By-Hash` lineage.
- [README.md](../../registry/README.md) · [architecture.md](../../registry/architecture.md)
  · [current-state.md](../../registry/current-state.md) ·
  [http-layout.md](../../registry/http-layout.md) ·
  [bundles-and-deltas.md](../../registry/bundles-and-deltas.md) ·
  [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) ·
  [publishing.md](../../registry/publishing.md).

### Plan set (`docs/plans/registry/`)

- [design-brief.md](./design-brief.md) — §4.3, §4.5, §6 (authoritative intent).
- [README.md](./README.md) — milestone roadmap (M1 → M4 dependency).
- [gap-analysis.md](./gap-analysis.md) — current vs target gap map.
- [open-questions.md](./open-questions.md) — rollout gating function (§7.4),
  `valid_until` window/cadence (§7.5), the `check_monotonic` gating discrepancy.
- [workstream-01-registry-root.md](./workstream-01-registry-root.md) — the root
  schema + serializer + inline signing this workstream extends.
- [workstream-02-publish-pipeline.md](./workstream-02-publish-pipeline.md) — the
  `apr release` ordering and atomic root flip that publishes channel/component edits.
- [workstream-03-nix-cache.md](./workstream-03-nix-cache.md) — owns the `nix_cache`
  capability flag.
- [workstream-05-consumer.md](./workstream-05-consumer.md) — the consumer-side
  cutover that implements the honoring contract in §8.
