# Workstream 03 — Channels & Rollouts

> **Plan doc.** Implementation plan for channels-as-branches, the **256 signed
> partition tag objects**, publisher partition-advancement rollout control,
> `refs/heads/<channel>` frontier maintenance, consumer deterministic bucket
> selection (the low byte of `sha256(machine_id)` (i.e. mod 256)) + probe-forward, and the anti-rollback
> floor / fix-forward discipline.
>
> Grounds out [`design-brief.md`](./design-brief.md) §5 (ref model), §6 (channels
> & rollouts), and §7 (releases & versioning). For the reference description of
> the finished design see
> [`../../registry/versioning-and-channels.md`](../../registry/versioning-and-channels.md).

---

## 0. Scope & relationship to sibling workstreams

This workstream owns the **rollout control plane**: the channel ref namespace,
the 256-partition fan-out, the publisher's advancement logic, and the consumer's
bucket selection + anti-rollback floor. It deliberately does **not** own:

| Concern | Owner |
|---|---|
| sha256 bare repo, `info/refs`/`HEAD`/`info/alternates`, per-release pack dirs | [`workstream-01-object-store.md`](./workstream-01-object-store.md) |
| `git pack-objects` thin/full packs, the delta scheme, zstd | [`workstream-02-pack-delta-pipeline.md`](./workstream-02-pack-delta-pipeline.md) |
| Signed-tag-object primitive (pure signed pointer), name-binding verification, `tag→tag→commit` chain | [`workstream-04-signing-trust.md`](./workstream-04-signing-trust.md) |
| Consumer resolution path (bucket → channel tag → semver tag → commit), delta walk, retention | [`workstream-05-consumer.md`](./workstream-05-consumer.md) |

The boundaries are intentionally tight: this doc decides **which release a given
host targets**; workstream-04 decides **whether to trust the tag that names it**;
workstream-05 decides **how to fetch the objects** once the target is known.

Cross-references: [`README.md`](./README.md) ·
[`gap-analysis.md`](./gap-analysis.md) ·
[`open-questions.md`](./open-questions.md).

---

## 1. Target model recap (the shape we are building)

### 1.1 Three ref layers (brief §5)

| Path / ref | What | Signed? | Consumer |
|---|---|---|---|
| `HEAD` | symref → `refs/heads/<default-channel>` (e.g. `stable`) | no | stock + AOS |
| `refs/heads/<channel>` | **channels are branches**; head = **frontier** | no (ref pointer) | stock git convenience |
| `refs/tags/<semver>` | release: signed tag → commit | **yes** | stock (`verify-tag`) + AOS |
| `/channels/<name>/<00..ff>` | 256 signed partition tag objects (tag name == channel) → semver tag | **yes** | AOS rollout only |

The partition tags live **outside** the git ref namespace, as static files under
`/channels/<name>/00..ff`. They are not `refs/*` and do not appear in `info/refs`;
they are an AOS-only overlay served over the same dumb-HTTP origin.

### 1.2 HTTP layout for this workstream (brief §4)

```
/channels/
  <name>/                                                       [low TTL — MUST]
    00 .. ff        ← 256 SIGNED tag objects (tag name == <name>),
                       each → a semver tag (rollout partitions)
/                                                               [low TTL — MUST]
  HEAD              ← "ref: refs/heads/<default-channel>"
  info/refs         ← refs/heads/<channels> + refs/tags/<semvers>
```

CDN policy this workstream depends on:

- `/channels/**` — **MUST** be low TTL so partition advancement propagates fast.
- `info/refs` + `HEAD` — **MUST** be low TTL (the frontier branch head moves on
  every rollout step).

---

## 2. CURRENT state (code-grounded as-is)

> The detailed as-is lives in
> [`../../registry/current-state.md`](../../registry/current-state.md). What
> follows is only the slice relevant to channels & rollouts, cited to code.

### 2.1 There are no channels and no partitions today

The current config model has **no channel concept**. A registry is tracked by a
single `TrackingMode` enum with four variants plus a default:

- `crates/aos-package/src/types.rs:279-290` — `TrackingMode { Commit, Branch,
  Tag, Version, Default }`. `Branch` tracks the **HEAD of a named git branch**
  (e.g. `main`/`stable`) — this is the *closest* current analogue to a channel,
  but it is a raw branch HEAD, not a 256-partition rollout surface.
- `crates/aos-package/src/types.rs:215-226` — config fields `commit` / `branch` /
  `tag` / `version` (mutually exclusive); `RegistryConfig::tracking_mode()`
  enforces "at most one set" at `types.rs:349-397`.

There is no `channel` field, no partition file, no bucket selection, and no
publisher rollout primitive anywhere in the config or update path.

### 2.2 Rollout today is calendar tokens + bundle deltas

Selection of "what to fetch next" is `pick_bundles` in
`crates/aos-package/src/update.rs:319-418`. It is built entirely around the
**calendar `creation_token`** scheme that the target removes:

- `update.rs:370-379` — first sync (no `last_creation_token`) grabs the latest
  snapshot bundle via `manifest.latest_snapshot()`.
- `update.rs:394-403` — "skip delta" from the current minor base, keyed by
  `creation_token` monotonicity.
- `update.rs:405-411` — sequential deltas between two `creation_token`s
  (`manifest.sequential_deltas_between`).
- `update.rs:413-417` — fall back to the latest snapshot.

The token machinery: `RegistryState.last_creation_token`
(`types.rs:251-259`), `state::token_to_version` (called at `update.rs:395`),
`extract_minor_base` (`update.rs:483-491`), and the calendar-tag normalizer
`parse_tag_as_semver` (`update.rs:456-477`, which strips a leading `v` and pads
`2026.02` → `2026.2.0`).

### 2.3 Downgrade protection today

A single monotonic guard exists at `update.rs:290-294`: if the new
`creation_token` exceeds the old one, `state::check_monotonic(old, new)`
(`registry/state.rs:104`) is called. This is the **only** anti-rollback present,
and it is keyed on calendar tokens, not semver — it must be re-pointed at a
semver/floor model (§7).

### 2.4 What survives into the target

`TrackingMode::Branch` survives in spirit: a "channel" is precisely a branch +
its 256 partition overlay. The current `creation_token` ordering, calendar-tag
versioning (`vYYYY.MM[.P]`), and the `v`-prefix machinery in `update.rs`
(`parse_tag_as_semver`, `extract_minor_base`) are dropped — see the removal tasks
in §9 (Phase D) and design-brief §15.

---

## 3. TARGET — channels as branches + 256 partition tags

### 3.1 Canonical shape

A channel `<name>` (e.g. `stable`, `testing`) consists of exactly two things:

1. A **branch** `refs/heads/<name>` whose head is the **frontier** — the commit
   of the newest release any of its 256 partitions targets (§5). Unsigned
   convenience pointer; not part of the trust chain.
2. **256 signed partition tag objects** at `/channels/<name>/00 .. /channels/<name>/ff`
   (one byte (two hex digits, 00–ff)). Each is an annotated, Ed25519-signed git tag whose
   **tag-name field == `<name>`** (the channel name, *not* the partition index)
   and which points at a **semver release tag** (`refs/tags/<semver>`). A
   partition tag is a **pure signed pointer**: the standard git tag fields
   (`object`, `type`, the tag *name*, `tagger`) + the Ed25519 signature + an
   optional freeform human message — no structured payload. The chain is
   `partition tag → semver tag → commit`.

```
/channels/stable/00  ── signed tag (name="stable") ──►  refs/tags/1.2.0 ──► commit C_120
/channels/stable/01  ── signed tag (name="stable") ──►  refs/tags/1.2.0 ──► commit C_120
        ...
/channels/stable/9f  ── signed tag (name="stable") ──►  refs/tags/1.2.0 ──► commit C_120
/channels/stable/a0  ── signed tag (name="stable") ──►  refs/tags/1.1.3 ──► commit C_113   (not yet advanced)
        ...
/channels/stable/ff  ── signed tag (name="stable") ──►  refs/tags/1.1.3 ──► commit C_113

refs/heads/stable  ──────────────────────────────►  commit C_120  (frontier = newest target = 1.2.0)
```

In this snapshot 160/256 partitions (`00`–`9f`) have advanced to `1.2.0`; `a0`–`ff`
remain on `1.1.3`. The fleet is at "160/256 rolled out". The branch head already
points at `1.2.0` (the frontier).

### 3.2 Why 256 (not percentages)

The target uses **exactly 256 fixed partitions** rather than a percentage knob
because:

- A consumer's bucket is a **pure function of its identity**
  (the low byte of `sha256(machine_id)` (i.e. mod 256)) — stable, no central coordination, no flapping.
- The publisher controls rollout by **which partitions name the new release**,
  answering "where does the rest of the fleet go?" explicitly: the un-advanced
  partitions still name the prior release (no ambiguity, no implicit "latest").
- Granularity is ~0.39% (1/256) steps — coarse but sufficient for staged rollout,
  and trivially auditable (256 static files you can `curl` and diff).

### 3.3 "There must always be 256"

The invariant is **256 partition files exist at all times** for every live
channel. A fresh channel is bootstrapped by pointing all 256 at the initial
release. If a client finds a partition missing (404 / stale / unsigned), it
**may** probe forward deterministically (`(bucket+1) mod 256`) rather than fail
(§6.3). The publisher MUST never leave a channel with fewer than 256 partitions in
a committed/published state.

---

## 4. Tags carry no structured payload (this workstream's slice)

Partition tags (and release tags) carry **no structured message** — no TOML, no
`[meta]`, no `schema` field, no `valid_until`, no `[[caches]]`. A signed tag is a
**pure signed pointer**: the standard git tag fields (`object`, `type`, the tag
*name*, `tagger`) + the Ed25519 signature + an *optional* freeform human message.
The tag *object* carries the signature and the name binding; the ref namespace
carries pointers; the object store carries everything else.

**Freshness** for partition tags is therefore **out-of-band**, not an in-band
`valid_until` (§6.3, §7.3): it is the low `/channels/**` CDN TTL + the consumer's
own max-staleness policy + the monotonic anti-rollback floor. Trade-off: this is
weaker than an in-band signed expiry against a frozen-but-validly-signed mirror —
a mirror can replay an old (still-correctly-signed) partition pointer, and only
the consumer's max-staleness policy and floor catch it.

**Cache config lives in the committed `registry.toml`**, never tag-embedded. The
Nix binary-cache / NAR substituter location lives in the committed repo-root
`registry.toml` `[[caches]]` (a tree file authenticated transitively by the signed
tag), with the consumer's client-side `registries.d` as an optional override — it
is **not** advertised in the signed tag itself. The origin MAY serve the stock
nix superset (`nix-cache-info`, `<storehash>.narinfo`, `nar/…`); narinfo signing
reuses the same one Ed25519 key.

A tag carries no `[latest]`, `[[bundles]]`, `[[deltas]]`, `valid_until`, or
`[[caches]]` — superseded concepts live only in current-state.md (today's code)
and design-brief §15.

---

## 5. TARGET — frontier branch head maintenance

**Rule:** `refs/heads/<channel>` always points at the commit of the **newest
release any partition targets** (the rollout target / frontier), per brief §6.

### 5.1 Maintenance procedure (producer, on every partition advance)

```
frontier(channel) = commit of max_semver( target(p) for p in 00..ff )
git update-ref refs/heads/<channel> <frontier-commit>
git update-server-info          # regenerate info/refs + objects/info/packs
```

The branch head is computed from the partition set, never the reverse. After the
*first* partition advances to a new release, the frontier already equals that new
release's commit (even though 255/256 partitions still name the old one). This is
intentional: the branch is the **rollout target**, not the **rollout state**.

### 5.2 Implication for stock git

`git pull <channel>` / `git clone -b <channel>` always lands on the frontier —
**no rollout protection**. This is acceptable and by design: rollout is an
AOS-fleet concept, not a git-clone concept. A stock clone is a developer/agent
pulling "the newest thing this line is moving toward". Fleet hosts go through the
AOS partition path and get staged rollout + anti-rollback.

### 5.3 Default channel & `HEAD`

`HEAD` is `ref: refs/heads/<default-channel>` (e.g. `stable`). Maintained by
workstream-01 on publish; this workstream only ensures the default channel's
branch exists and tracks its frontier.

---

## 6. TARGET — consumer bucket selection & probe-forward

### 6.1 Deterministic bucket selection

```
bucket = the low byte of sha256(machine_id) (i.e. mod 256)   →  one of 00..ff
```

- **Input:** `machine_id` (source TBD — `/etc/machine-id` is the leading
  candidate; see [`open-questions.md`](./open-questions.md) and brief §16.3).
- **Persisted once:** the chosen bucket is written to AOS state on first
  selection so a host **never flaps between buckets** even if the input source
  changes. Re-selection happens only on explicit operator action.
- **Determinism:** identical `machine_id` ⇒ identical bucket on every run; the
  fleet's hosts are uniformly spread across `00`–`ff` by sha256 avalanche.

Suggested persisted shape (AOS state, not the registry):

```toml
[rollout]
bucket      = 10              # 0..255 (decimal) == partition '0a'
machine_id  = "…"            # the input that produced it (for audit)
selected_at = "2026-06-04T12:00:00Z"
```

> **Schema note (code).** `RegistryState` (`types.rs:251-259`) currently holds
> `last_commit` / `last_creation_token` / `last_update`. The target replaces
> `last_creation_token` with a semver/floor + persisted-bucket model (§7). The
> bucket is host-scoped (one per machine), not per-registry, so it likely lives
> in a separate state file rather than per-`registries.d/*.toml`.

### 6.2 Selection flow (consumer)

```
machine_id ─► sha256 ─► mod 256 ─► bucket b (persisted)
                                     │
                                     ▼
                   GET /channels/<name>/<hex(b)>           [low TTL]
                                     │  signed partition tag (name=="<name>")
                                     ▼
                   verify: sig valid AND tag-name == <name>   (ws-04)
                                     │
                                     ▼
                   partition tag → semver tag  (e.g. 1.1.3)
                                     │  verify: sig valid AND tag-name == "1.1.3"
                                     ▼
                   semver tag → commit  ─► hand off to ws-05 (fetch/delta)
```

The two name-binding checks (channel name under `/channels/*`, semver under the
release tag) are the trust gate; they are specified in
[`workstream-04-signing-trust.md`](./workstream-04-signing-trust.md) and are a
hard precondition before this workstream's output is acted on.

### 6.3 Probe-forward fallback

If partition `b` is unusable — HTTP 404, signature invalid, name mismatch, or
stale past the consumer's max-staleness policy — the client **may**
deterministically probe the next partition:

```
for i in 0..256:
    p = (b + i) mod 256
    tag = GET /channels/<name>/<hex(p)>
    if usable(tag):   # fetched AND signature valid AND name=="<name>" AND fresh
        return tag
fail: channel has no usable partition  →  fall back to last-good / abort
```

Probe-forward is **forward-only and wrap-around** (`(b+1) mod 256`, …), so the
order is deterministic per host. It trades a tiny rollout-fairness skew (a probing
host advances slightly earlier than its assigned partition) for availability when
a partition file is briefly missing during publish. Anti-rollback (§7) still
applies to whatever release the probe lands on — probe-forward can never move a
host *backward*.

---

## 7. TARGET — publisher rollout control (partition advancement)

### 7.1 The primitive

To roll a new release `T` to **N/256** of the fleet: point **N partitions** at
`T`'s semver tag and leave the remaining `256-N` on the prior release `P`. The
un-advanced partitions still **explicitly name** `P` — there is no implicit
"latest" (brief §6).

```
advance(channel, T, partitions=[0,1,2]):
    for p in partitions:
        # create/replace the signed partition tag object for /channels/<name>/<p>
        write_signed_tag(name=<channel>, target=refs/tags/<T>) ─► /channels/<name>/<hex(p)>
    frontier(channel) = max_semver(all 256 targets)        # ← T once any partition names it
    git update-ref refs/heads/<channel> <commit-of-frontier>
    git update-server-info
    upload /channels/<name>/* + refs (see ws-01 / publishing for atomicity)
```

| Step | Partitions on T | Fleet on T | Notes |
|---|---|---|---|
| Canary | `00` | ~0.39% | Frontier head already moves to T |
| Early | `00`–`3f` | ~25% | Advance as confidence grows |
| Half | `00`–`7f` | ~50% | |
| Complete | `00`–`ff` | 100% | All 256 name T; rollout done |

**Completion** = all 256 partitions point at the new release. The producer SHOULD
advance in a documented, deterministic partition order (e.g. ascending `00→ff`) so
the canary cohort is predictable and `apr` can report "N/256 advanced".

### 7.2 Tooling sketch (`apr`)

The brief leaves the exact command surface open (§16.4). The minimal additions:

```sh
# advance K partitions of <channel> to <semver> (ascending fill by default)
apr channel advance <channel> <semver> --count 4
apr channel advance <channel> <semver> --partitions 0,1,2,3

# inspect rollout state: which partition → which release, + frontier
apr channel status <channel>
#   stable: frontier=1.2.0  (160/256 on 1.2.0, 96/256 on 1.1.3)
#   00..9f → 1.2.0   a0..ff → 1.1.3

# bootstrap a brand-new channel: all 256 at an initial release
apr channel init <channel> <semver>
```

Each `advance` writes signed tag objects (workstream-04 signing primitive),
recomputes the frontier (§5), regenerates server info, and uploads. Whether this
folds into a single `apr release` / `apr publish` pipeline is
[open question §16.4](./open-questions.md).

### 7.3 Anti-rollback: monotonic floor + fix-forward

Two independent guarantees:

1. **Consumer floor (monotonic).** Each host keeps a monotonic **floor** = the
   highest release it has ever successfully targeted. It will **never** move to a
   release older than its floor, regardless of what a partition names. This makes
   accidental or malicious partition-decrement a no-op on already-advanced hosts.

   ```
   target = resolve_partition(bucket)        # §6
   if semver(target) < floor:  reject (anti-rollback); keep current
   else:                       floor = max(floor, semver(target)); proceed
   ```

   > **Code (current vs target).** The only current downgrade guard is
   > `state::check_monotonic(old, new)` (`registry/state.rs:104`), called from
   > the sync path at `update.rs:290-294`, keyed on `creation_token`. The target
   > re-keys it on **semver precedence** (brief §7) and turns it into a persisted
   > floor in AOS state rather than a per-sync token comparison. The semver
   > machinery already exists (`TrackingMode::Version(semver::VersionReq)`,
   > `types.rs:287`; `find_best_version_tag_in_manifest` (`update.rs:427-451`) /
   > `parse_tag_as_semver` (`update.rs:456-477`) in `update.rs`), but those carry
   > the `v`-prefix / calendar normalization that the target drops (brief §15).

2. **Producer fix-forward (never decrement).** Aborting a bad rollout is done by
   **publishing a newer release and pointing partitions at it** — never by
   pointing partitions back at the old release. Partition-decrement is forbidden
   both by convention and because the consumer floor would block it anyway (a
   host already on the bad release won't go backward, so a decrement helps
   nobody). Fix-forward keeps the floor monotonic fleet-wide.

```
bad rollout of T detected
   │
   ├─ WRONG: advance partitions back to P            ← blocked by floor; do not do this
   │
   └─ RIGHT: publish T' (> T, the fix), advance partitions to T'   ← fix-forward
```

---

## 8. Worked rollout walkthrough

Starting state: channel `stable`, all 256 partitions on `1.1.3`, frontier =
`1.1.3`. Publish `1.2.0` and roll it out.

```
t0  init:      00..ff → 1.1.3                          frontier=1.1.3   fleet: 0/256 on 1.2.0
t1  publish 1.2.0 (tag+sign+pack/delta via ws-02/04; no partitions advanced yet)
t2  advance 00: 00 → 1.2.0   01..ff → 1.1.3            frontier=1.2.0   fleet: 1/256   (canary)
t3  advance 01..3f: 00..3f → 1.2.0   40..ff → 1.1.3    frontier=1.2.0   fleet: 64/256  (~25%)
t4  advance 40..7f: 00..7f → 1.2.0   80..ff → 1.1.3    frontier=1.2.0   fleet: 128/256 (~50%)
t5  advance 80..ff: 00..ff → 1.2.0                     frontier=1.2.0   fleet: 256/256 (done)
```

Consumer with bucket `5a`: still targets `1.1.3` at t2–t3 (partition 5a not yet
advanced — it falls in the `40..7f` cohort), moves to `1.2.0` at t4. Its floor
rises `1.1.3 → 1.2.0` and can never fall back.

If `1.2.0` proves bad after t3 (64/256): publisher does **not** revert; it publishes
`1.2.1` and advances partitions `00..3f` (the affected cohort) to `1.2.1`. Hosts on
buckets `00..3f` move `1.2.0 → 1.2.1` (forward); hosts on `40..ff` were never exposed
to `1.2.0`.

---

## 9. Implementation tasks

### Phase A — config & state model
- [ ] **A1.** Add a `channel` concept to registry config. Reuse the
  `TrackingMode::Branch` slot semantics (`types.rs:279-290`) so a channel name is
  the branch name, but add the partition overlay on top. Decide config field
  shape (`channel = "stable"`) and its interaction with existing `branch` / `tag`
  / `version` (likely: `channel` is the fleet path; `branch` / `tag` remain
  raw-git escape hatches).
- [ ] **A2.** Replace `RegistryState.last_creation_token: Option<u64>`
  (`types.rs:256`) with a semver **floor** field
  `pub last_floor: Option<semver::Version>` on `RegistryState`
  (`types.rs:251-259`); keep `last_commit` / `last_update`. `semver::Version`
  does not implement `Serialize`/`Deserialize` directly, so serialize it via a
  `#[serde(with = "...")]` string adapter (a `mod semver_string { fn serialize / fn deserialize }`
  in `types.rs`) or store as `Option<String>` and parse on read. This breaks the
  state serializer in `registry/state.rs`: `save_state` (`state.rs:37`) writes
  `last_creation_token = {token}` at `state.rs:46-47` and `load_state`
  (`state.rs:21`) reads it — both must switch to `last_floor`. The state
  round-trip tests `test_save_state_appends_to_file_without_state`
  (`state.rs:332`), `test_save_state_replaces_existing_state_section`
  (`state.rs:371`), and `test_load_state_from_registry_file` (`state.rs:277`)
  reference `last_creation_token` and must be rewritten to assert `last_floor`.
  Add `#[test] fn test_floor_round_trips_as_string()`.
- [ ] **A3.** Add host-scoped rollout state (`bucket: u8`, `machine_id: String`,
  `selected_at: String`) as a new `pub struct RolloutState` in a dedicated module
  `crates/aos-package/src/registry/rollout.rs` (new), persisted to a single host
  file (e.g. `/var/lib/aos/rollout.toml`) — **not** per-registry
  `registries.d/*.toml`. Signatures: `pub fn load_rollout(path: &Path) -> anyhow::Result<Option<RolloutState>>`
  and `pub fn save_rollout(path: &Path, state: &RolloutState) -> anyhow::Result<()>`,
  mirroring `state::load_state`/`save_state` (`state.rs:21`/`:37`). Named tests:
  `#[test] fn test_rollout_round_trip()`, `#[test] fn test_rollout_load_missing_is_none()`.

### Phase B — consumer bucket + resolution

All consumer-side code lands in a new module
`crates/aos-package/src/registry/channel.rs` (sibling to `state.rs`/`bundle.rs`,
registered in `registry/mod.rs` alongside the existing `pub mod state;`).

- [ ] **B1.** Implement bucket selection from the low byte of `sha256(machine_id)`
  (i.e. mod 256); persist on first run; never re-select implicitly (§6.1).
  Module `registry/channel.rs`:
  `pub fn select_bucket(machine_id: &str) -> u8` — `Sha256::digest(machine_id.as_bytes())[31]`
  (the `sha2` crate is already a workspace dep via `aos-core::nar`); and
  `pub fn resolve_bucket(rollout_path: &Path, machine_id: &str) -> anyhow::Result<u8>`
  which reads `RolloutState` (A3) and only calls `select_bucket` + `save_rollout`
  when no bucket is persisted. Named tests:
  `#[test] fn test_bucket_is_deterministic()` (same `machine_id` ⇒ same `u8`),
  `#[test] fn test_bucket_persists_across_machine_id_change()` (persisted bucket
  wins after the input changes), `#[test] fn test_bucket_distribution_uniform()`
  (10k synthetic ids spread over `00..ff`).
- [ ] **B2.** Implement partition fetch `GET /channels/<name>/<hex(b)>` and the
  `partition tag → semver tag → commit` resolution, gated on the ws-04
  name-binding verification (§6.2). Module `registry/channel.rs`:
  ```rust
  pub struct ResolvedPartition { pub channel: String, pub semver: semver::Version,
                                 pub commit: String }
  pub async fn fetch_partition(base_url: &str, channel: &str, bucket: u8)
      -> anyhow::Result<RawTag>;           // GET <base>/channels/<channel>/<02x bucket>
  pub fn resolve_partition(tag: &RawTag, channel: &str)
      -> anyhow::Result<ResolvedPartition>;  // verify name-binding (ws-04), walk tag→tag→commit
  ```
  Reuse the download engine that `download.rs` already uses (the `TransferEngine`
  in `download::download_one`, `download.rs:178`); name-binding/signature
  verification is the ws-04 primitive, called here, not reimplemented. Named test:
  `#[test] fn test_resolve_partition_walks_tag_to_commit()` and
  `#[test] fn test_resolve_partition_rejects_name_mismatch()`.
- [ ] **B3.** Implement probe-forward `(b+i) mod 256` with the
  fetched/valid/name-matched/fresh predicate (§6.3). Module `registry/channel.rs`:
  `pub async fn resolve_with_probe(base_url: &str, channel: &str, bucket: u8, max_staleness: Duration) -> anyhow::Result<ResolvedPartition>`
  — loops `for i in 0..256 { let p = bucket.wrapping_add(i) }`, returning the
  first `usable` partition. Named tests:
  `#[test] fn test_probe_forward_wraps_around()` (bucket `ff` probes `00` next),
  `#[test] fn test_probe_forward_deterministic_order()`,
  `#[test] fn test_probe_forward_all_missing_errors()`.
- [ ] **B4.** Implement the anti-rollback floor check (§7.3.1); re-key
  `check_monotonic` (`state.rs:104`, called from `update.rs:290-294`) from
  `creation_token` to semver precedence. Add
  `pub fn check_floor(floor: Option<&semver::Version>, target: &semver::Version) -> anyhow::Result<semver::Version>`
  in `registry/channel.rs` (returns `max(floor, target)` or `Err` on
  `target < floor`); the old `state::check_monotonic(old_token, new_token)`
  call site at `update.rs:290-294` is replaced by `check_floor`. Breaks the
  monotonic tests `test_check_monotonic_succeeds_when_newer` (`state.rs:255`),
  `test_check_monotonic_fails_when_equal` (`state.rs:261`), and
  `test_check_monotonic_fails_when_older` (`state.rs:269`) — these `u64`-token
  tests are replaced by `#[test] fn test_floor_rejects_downgrade()`,
  `#[test] fn test_floor_raises_on_newer()`, `#[test] fn test_floor_none_accepts_any()`.

### Phase C — producer rollout control

Producer-side code lands in `crates/aos-package/src/registry_ops.rs` (where the
existing `apr tag`/`apr bundle`/`apr sign` live at `registry_ops.rs:1684`/`:1706`/`:1747`)
plus a frontier helper. The shared git wrappers `git` (`registry_ops.rs:79`) and
the allow-fail `git_try` (`registry_ops.rs:96`, returns `(bool, String, String)`)
are the only git entry points; new partition/ref operations call these.

- [ ] **C1.** `apr channel init <channel> <semver>` — write all 256 signed
  partition tags (uses ws-04 signing primitive).
  `pub async fn channel_init(config: &ApmConfig, channel: &str, semver: &semver::Version, registry: Option<&str>, printer: &Printer) -> anyhow::Result<()>`.
- [ ] **C2.** `apr channel advance <channel> <semver> [--count N | --partitions …]`
  — write N signed partition tags, ascending-fill default (§7.1).
  `pub async fn channel_advance(config: &ApmConfig, channel: &str, semver: &semver::Version, partitions: &[u8], registry: Option<&str>, printer: &Printer) -> anyhow::Result<()>`;
  a helper `fn ascending_fill(count: usize, current: &PartitionMap) -> Vec<u8>`
  resolves `--count` to the next `N` un-advanced partition indices. Named tests:
  `#[test] fn test_advance_count_fills_ascending()`,
  `#[test] fn test_advance_explicit_partitions()`.
- [ ] **C3.** Frontier maintenance: recompute `max_semver(targets)`, `update-ref
  refs/heads/<channel>`, `update-server-info` after every advance (§5.1).
  `fn compute_frontier(targets: &PartitionMap) -> Option<semver::Version>`
  (max over the 256 targets) and
  `fn update_frontier(dir: &Path, channel: &str, frontier_commit: &str) -> anyhow::Result<()>`
  which runs `git(dir, &["update-ref", &format!("refs/heads/{channel}"), frontier_commit])`
  then `git(dir, &["update-server-info"])`. `PartitionMap` is a new
  `pub struct PartitionMap([Option<semver::Version>; 256])`. Named test:
  `#[test] fn test_frontier_is_max_semver_over_partitions()` (after one of 256
  advances to `1.2.0`, frontier == `1.2.0`).
- [ ] **C4.** `apr channel status <channel>` — report partition→release map,
  frontier, and N/256 progress (§7.2).
  `pub async fn channel_status(config: &ApmConfig, channel: &str, registry: Option<&str>, printer: &Printer) -> anyhow::Result<PartitionMap>`.
- [ ] **C5.** Enforce the "always 256" invariant on publish (refuse to upload a
  channel with <256 partitions). `fn assert_full_partition_set(map: &PartitionMap) -> anyhow::Result<()>`
  (errs if any of the 256 slots is `None`); call it from the publish/upload path.
  Named test: `#[test] fn test_publish_refuses_255_partitions()`.
- [ ] **C6 (F351).** Serialize concurrent publishers on the same channel.
  Two `apr channel advance`/`init` runs against one channel must not interleave
  and clobber each other's frontier ref or partition flip. Use compare-and-swap
  on both the git ref and the object-store object:
  - **Git ref CAS.** Advance `refs/heads/<channel>` only with an atomic
    expected-old-value swap, never a blind `update-ref`. Implement
    `fn cas_update_ref(dir: &Path, channel: &str, old_commit: &str, new_commit: &str) -> anyhow::Result<bool>`
    via `git update-ref refs/heads/<channel> <new> <old>` (git's two-arg form is
    an atomic CAS: it fails if the current value ≠ `<old>`), or
    `git push --force-with-lease=refs/heads/<channel>:<old>` when pushing to a
    remote origin. Run it through the existing allow-fail wrapper
    `git_try` (`registry_ops.rs:96`) so a lost race is observable as
    `success == false` rather than an early `bail!`. The partition flip and the
    frontier update advance together: read the current frontier commit as the CAS
    `old` before writing partitions, then CAS the ref to the recomputed frontier;
    if the CAS fails, **another publisher advanced first** — re-read the partition
    map and frontier, recompute, and retry (bounded retry, e.g. 5 attempts, then
    `bail!("channel <name>: lost the publish race after N retries")`).
  - **Object-store conditional PUT / If-Match.** Each `/channels/<name>/<hex>`
    flip and the `info/refs`/`HEAD` re-upload uses a conditional write: send
    `If-Match: <etag>` (or `If-None-Match: *` for the create case) so a
    concurrent overwrite is rejected with `412 Precondition Failed`. Signature
    `pub async fn put_if_match(engine: &TransferEngine, url: &str, body: &[u8], etag: Option<&str>) -> anyhow::Result<PutOutcome>`
    where `enum PutOutcome { Written(String /* new etag */), PreconditionFailed }`.
  - **Failure / retry.** On `PreconditionFailed` (object store) **or** `git_try`
    CAS `success == false` (ref), the publisher re-reads the channel's partition
    map + frontier, recomputes the target frontier, and retries the whole advance
    (idempotent: re-signing the same partition→semver mapping is a no-op write).
    The retry loop is bounded; on exhaustion it aborts without partial publish so
    the "always 256" invariant (C5) is never broken mid-flight. Named tests:
    `#[test] fn test_cas_update_ref_rejects_stale_old()`,
    `#[test] fn test_put_if_match_returns_precondition_failed_on_etag_mismatch()`,
    `#[test] fn test_advance_retries_then_succeeds_after_concurrent_winner()`,
    `#[test] fn test_advance_bails_after_retry_budget_exhausted()`.

### Phase D — removals (brief §15)
- [ ] **D1.** Delete the `creation_token` rollout path: `pick_bundles`
  token branches (`update.rs:370-417`), `token_to_version` (`state.rs:173`),
  `extract_minor_base` (`update.rs:483-491`), `parse_tag_as_semver`'s `v`-prefix /
  calendar normalization (`update.rs:456-477`). This also removes the
  `pick_bundles_*` and `extract_minor_base_*` tests in `update.rs` and the
  `version_to_token_*` / `token_to_version_*` / `token_version_round_trip` tests
  in `state.rs` (`state.rs:197-246`).
- [ ] **D2.** Strip any lingering `[channels.<name>.rollout]` percentage /
  `previous_tag` / baseline+candidate framing references from docs and config
  parsing.

---

## 10. Test plan

| Test | Asserts |
|---|---|
| Bucket determinism | same `machine_id` → same bucket across runs; persisted bucket survives a `machine_id` source change |
| Bucket distribution | 10k synthetic `machine_id`s spread roughly uniformly over `00..ff` (sha256 avalanche) |
| Partition resolve | `GET /channels/stable/a3` → signed tag (name=="stable") → `1.1.3` tag → commit; name-binding enforced |
| Probe-forward | partition `b7` missing/expired → lands on `(b+1) mod 256`; wrap-around; deterministic order |
| Frontier | after advancing 1/256 to `1.2.0`, `refs/heads/stable` head == `1.2.0` commit |
| Rollout staging | `advance --count 4` ⇒ exactly partitions `00..03` on T, `04..ff` on P; `status` reports 4/256 |
| Anti-rollback floor | host on `1.2.0` ignores a partition that decrements to `1.1.3`; floor unchanged |
| Fix-forward | publish `1.2.1`, advance affected cohort; floor rises; never decrements |
| "Always 256" | publishing a channel with 255 partitions is refused |
| Concurrent publishers (F351) | two `advance` runs on one channel: ref CAS rejects the stale `old`; `If-Match` PUT returns `412`; loser re-reads + retries; bounded budget then aborts without partial publish |
| Stock-git frontier | `git clone -b stable` lands on the frontier (no rollout protection), as designed |

---

## 11. Risks & open questions (this workstream)

- **`machine_id` source & stability** (brief §16.3,
  [`open-questions.md`](./open-questions.md)): `/etc/machine-id` vs hardware ID
  vs operator-assigned; behavior on cloned VMs (would collide buckets). Mitigated
  by persist-once, but VM-clone fan-out needs a re-selection policy.
- **Probe-forward fairness skew:** hosts whose assigned partition is briefly
  missing advance early. Acceptable, but a flapping partition could systematically
  skew a cohort — bound by the "always 256" publish invariant.
- **Partition freshness tuning** (brief §11, §16.5): freshness is out-of-band
  (low `/channels/**` CDN TTL + consumer max-staleness policy + the anti-rollback
  floor), not an in-band signed `valid_until`. Too aggressive a max-staleness ⇒
  spurious staleness + probe-forward storms; too lax ⇒ a frozen-but-validly-signed
  mirror can replay a stale partition pointer for longer (caught only by the floor).
  The consumer's max-staleness must be co-tuned with the low `/channels/**` CDN TTL.
- **Command surface** (brief §16.4): whether `apr channel advance` is standalone
  or folded into a single `apr release` / `apr publish` pipeline.
- **State location:** host-scoped bucket vs per-registry floor — confirm the
  split so multi-registry hosts share one bucket but track independent floors.

---

## 12. Cross-links

- Reference (target): [`../../registry/versioning-and-channels.md`](../../registry/versioning-and-channels.md) ·
  [`../../registry/signing-and-trust.md`](../../registry/signing-and-trust.md) ·
  [`../../registry/http-layout.md`](../../registry/http-layout.md) ·
  [`../../registry/publishing.md`](../../registry/publishing.md) ·
  [`../../registry/architecture.md`](../../registry/architecture.md) ·
  [`../../registry/README.md`](../../registry/README.md) ·
  [`../../registry/current-state.md`](../../registry/current-state.md) ·
  [`../../registry/packs-and-deltas.md`](../../registry/packs-and-deltas.md) ·
  [`../../registry/nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md) ·
  [`../../registry/apt-comparison.md`](../../registry/apt-comparison.md)
- Plan: [`README.md`](./README.md) · [`design-brief.md`](./design-brief.md) ·
  [`gap-analysis.md`](./gap-analysis.md) ·
  [`workstream-01-object-store.md`](./workstream-01-object-store.md) ·
  [`workstream-02-pack-delta-pipeline.md`](./workstream-02-pack-delta-pipeline.md) ·
  [`workstream-04-signing-trust.md`](./workstream-04-signing-trust.md) ·
  [`workstream-05-consumer.md`](./workstream-05-consumer.md) ·
  [`open-questions.md`](./open-questions.md)
