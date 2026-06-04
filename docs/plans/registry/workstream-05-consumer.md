# Workstream 05 — Consumer-side changes

> **Plan doc.** Part of the [AOS Registry implementation plan](./README.md).
> Grounding intent: [`design-brief.md`](./design-brief.md) §2.6, §4.3, §4.5.
> Sibling reference docs describe the **target** wire format
> ([`registry-toml.md`](../../registry/registry-toml.md),
> [`http-layout.md`](../../registry/http-layout.md),
> [`signing-and-trust.md`](../../registry/signing-and-trust.md),
> [`versioning-and-channels.md`](../../registry/versioning-and-channels.md)).
> This doc describes **what must change on the consumer** (`apm update` /
> `apm upgrade`) to reach that target.

This is the `apm`-side counterpart to the producer workstreams
([01](./workstream-01-registry-root.md), [02](./workstream-02-publish-pipeline.md),
[03](./workstream-03-nix-cache.md), [04](./workstream-04-channels-rollouts.md)).
It covers five changes:

1. Read the signed **`registry.toml` root** as the entry point (replacing the
   `bundle-list.toml` manifest fetch).
2. **Channel tracking** — a new `TrackingMode` that resolves `stable`/`testing`
   to a concrete tag via the root's `[channels]` table, with rollout gating.
3. **Expiry / freeze checks** — reject a signed-but-stale root via `valid_until`
   and the signed `[latest]` anchor.
4. **By-hash fetch** — resolve bundles through the root's hashed index so a sync
   reads a consistent set even across a concurrent publish.
5. **Fail-closed omission handling** — if the signed `[latest].head` cannot be
   reached after a sync, error out rather than silently accepting stale data.

---

## 1. Scope and entry points

All consumer code lives in `crates/aos-package/`. The relevant files:

| File | Role | Changes |
|---|---|---|
| `src/update.rs` | `apm update` driver, `sync_bundle`, `pick_bundles` | rewrite manifest fetch → root fetch; channel mode; fail-closed |
| `src/registry/bundle.rs` | manifest/bundle parse, download, verify, unbundle | parse bundles **from root**; by-hash keys |
| `src/registry/state.rs` | state persistence, `check_monotonic`, token codec | add `valid_until` / `[latest]` checks; persist channel |
| `src/types.rs` | `RegistryConfig`, `TrackingMode`, `RegistryState`, root structs | add `channel`, extend `TrackingMode`, extend root schema |
| `src/download.rs` | NAR mirror resolution | unchanged in behavior; reads root `[[caches]]` (already does) |

The flow today (`update.rs:115`) dispatches on `RegistryConfig::transport()`
(`types.rs:315`): `HttpBundle` → `sync_bundle`, `Git` → `git::sync_git`. **This
workstream changes the `HttpBundle` path only.** The git path
([`registry/git.rs`], §2.9 of the brief) already roots trust in the signed
commit and needs no consumer change beyond honoring the new `channel` tracking
mode.

---

## 2. CURRENT consumer behavior (grounded in code)

### 2.1 The fetch root is `bundle-list.toml`, not signed

`sync_bundle` fetches a manifest, not a signed root:

- `update.rs:203` → `bundle::BundleManifest::fetch(&engine, &config.url, &config.name)`.
- `bundle.rs:100-121` builds `"{base_url}/bundles/{registry_name}/bundle-list.toml"`
  and parses the body.
- `ManifestToml` / `ManifestHeader` / `BundleEntryToml` (`bundle.rs:59-92`) are
  `#[derive(Deserialize)]` **only** — there is no `valid_until`, no `[latest]`,
  no `[channels]`, no signature field, and no by-hash key. The manifest is plain
  unsigned TOML.

> **Trust note.** Today the manifest itself is unsigned; integrity comes
> downstream from `git bundle verify` over a bundle whose tag ultimately roots
> in a signed commit (brief §2.10, §3). The manifest can still be *tampered to
> omit or reorder* bundles without detection — which is exactly the **freeze /
> omission** gap §4.5 closes with a signed root.

### 2.2 Bundle selection (`pick_bundles`)

`pick_bundles` (`update.rs:292-391`) is the incremental selection algorithm
(brief §2.6). Given the manifest, `RegistryState`, and `TrackingMode`:

```
TrackingMode::Tag(t)      -> snapshot with target_tag==t, else any delta to t,   (update.rs:299)
                             else bail "tag not found"
TrackingMode::Commit(_)   -> falls through (bundle transport can't resolve        (update.rs:314)
                             arbitrary commits)
TrackingMode::Version(req)-> find_best_version_tag_in_manifest -> snapshot/delta   (update.rs:318)
TrackingMode::Branch|Default -> incremental logic below                            (update.rs:338)

no last_creation_token    -> latest_snapshot()                                     (update.rs:344)
entries_since(cur).empty  -> [] (up to date)                                       (update.rs:355)
skip_delta_from(base)     -> [skip] if newer                                       (update.rs:372)
sequential_deltas_between -> [chain] if non-empty                                  (update.rs:379)
else                      -> latest_snapshot() fallback                            (update.rs:387)
```

The selection helpers live on `BundleManifest`: `entries_since`
(`bundle.rs:181`), `latest_snapshot` (`bundle.rs:189`), `skip_delta_from`
(`bundle.rs:200`), `sequential_deltas_between` (`bundle.rs:211`).

### 2.3 Download / verify / apply

For each selected entry (`update.rs:233-246`):

1. `download_bundle` (`bundle.rs:251`) → `GET {base}/bundles/{name}/{entry.uri}`,
   verified by SHA-256 via `TransferRequest::with_hash` (`bundle.rs:276`).
2. `verify_bundle` (`bundle.rs:305`) → recompute SHA-256 **and** `git bundle
   verify` (pack integrity + prerequisites).
3. `unbundle` (`bundle.rs:376`) → `git bundle unbundle` into `repo.git`.
4. `resolve_tag` (`bundle.rs:407`) on the last `target_tag` → new commit SHA.
5. `extract_packages_from_git` (`update.rs:469`) → `git archive | tar -x` the
   `packages/` tree into the package cache.

### 2.4 Downgrade defense and state

After applying, `update.rs:256-267` computes `latest_token = max(creation_token)`
of the applied entries and calls `state::check_monotonic(old, new)`
(`state.rs:104`), which **bails on `new <= old`** (downgrade / stale-mirror
defense). State is then written (`update.rs:270-272`):

```rust
reg_state.last_commit          = Some(new_commit);
reg_state.last_creation_token  = Some(latest_token);
reg_state.last_update          = Some(now_iso8601());
```

`RegistryState` (`types.rs:253-262`) has exactly those three fields and is
serialized under `[registry.state]` by `state::save_state` (`state.rs:37`),
which surgically rewrites only that section, preserving user-edited fields.

### 2.5 Tracking modes available today

`TrackingMode` (`types.rs:282-293`): `Commit`, `Branch`, `Tag`, `Version`,
`Default`. `RegistryConfig::tracking_mode()` (`types.rs:352-399`) validates that
**at most one** of `commit`/`branch`/`tag`/`version` is set (`pin` is a legacy
alias for `tag`). **There is no `channel` field and no `Channel` variant.**

### 2.6 NAR resolution is already root-aware (no change needed)

`download::resolve_mirror` (`download.rs:67-82`) reads `[[caches]]` from the
local registry clone's in-repo `registry.toml` (sorted by priority), falling
back to `{registry.url}/nar`. `nar_url` (`download.rs:57`) →
`{mirror}/{sha256:hex}.nar.zst`. NARs are verified by content hash, not
signature (brief §2.8, §3). This stays as-is.

> ⚠️ **Two different files are both named `registry.toml`.** `types.rs:566-599`
> defines `RegistryRootConfig` — the **in-repo** file holding `[[caches]]` +
> `[signing].public_key`, consumed by `resolve_mirror`. The brief §4.3 **target**
> `registry.toml` is the **HTTP-served signed root** that subsumes
> `bundle-list.toml`. These are not the same object. The migration MUST keep them
> distinct (or consciously merge them); see [open questions](#10-open-questions).

---

## 3. TARGET consumer behavior

### 3.1 New top-of-sync flow

```
                       apm update (HttpBundle transport)
                                   |
                                   v
   GET {base}/registry.toml   (single signed root, inline signature)   [NEW]
                                   |
              +--------------------+--------------------+
              |                                         |
        verify inline signature                  reject if absent /
        (Ed25519, registry pubkey, TOFU)         unverifiable  --> FAIL CLOSED
              |
              v
   check [meta].valid_until > now            --> expired? FAIL CLOSED   [NEW]
   check [latest].token monotonic vs state   --> regressed? FAIL CLOSED
              |
              v
   resolve TrackingMode -> concrete target tag
       (Channel mode resolves via [channels] + rollout gate)           [NEW]
              |
              v
   pick_bundles( root.bundle_index, state, target )   (by-hash keys)    [CHANGED]
              |
              v
   for each bundle: download (by hash) -> verify SHA -> git verify -> unbundle
              |
              v
   resolve target tag -> commit; assert commit == [latest].head        [NEW]
       (when target IS latest) else FAIL CLOSED (omission defense)
              |
              v
   extract packages; persist state (+ channel, + valid_until snapshot)
```

The single change in transport selection: `BundleManifest::fetch` is replaced by
a `RegistryRoot::fetch` that pulls `{base}/registry.toml`, verifies the inline
signature, and exposes the bundle index plus `[meta]`, `[latest]`, `[channels]`.

### 3.2 New / changed types

```rust
// types.rs — extend TrackingMode (additive variant)
pub enum TrackingMode {
    Commit(String),
    Branch(String),
    Tag(String),
    Version(semver::VersionReq),
    Channel(String),   // NEW: "stable", "testing", ...
    Default,
}

// types.rs — RegistryConfig gains a channel field (mutually exclusive group)
pub struct RegistryConfig {
    // ...existing commit/branch/tag/version/pin...
    #[serde(default)]
    pub channel: Option<String>,   // NEW
}

// types.rs — RegistryState gains anti-freeze / channel bookkeeping
pub struct RegistryState {
    pub last_commit: Option<String>,
    pub last_creation_token: Option<u64>,
    pub last_update: Option<String>,
    pub last_channel: Option<String>,       // NEW: detect channel switch
    pub root_valid_until: Option<String>,   // NEW: last seen expiry (diagnostics)
}
```

`tracking_mode()` (`types.rs:352`) must add `channel` to the
mutually-exclusive set (currently commit/branch/tag/version) and return
`TrackingMode::Channel(name)` when set.

### 3.3 The signed root parser

A new `RegistryRoot` type (in `registry/root.rs` or extending `bundle.rs`)
deserializes the §4.3 schema and holds, at minimum:

| Field | Source (§4.3) | Consumer use |
|---|---|---|
| `[meta].name`, `.date`, `.valid_until` | signed root | expiry / freeze check |
| `[meta].schema` / `[capabilities]` | signed root | forward-compat / graceful degradation |
| `pubkey` (Ed25519) | signed root | TOFU pin, signature verify |
| `[latest] { tag, token, head }` | signed root | freshness anchor; omission defense |
| `[channels] { stable = {...}, testing = {...} }` | signed root | channel resolution + rollout |
| bundle index (by-hash: `uri`/key, `creation_token`, `type`, `from`/`to`, `sha256`, `size`) | signed root | replaces `BundleManifest.entries` |
| inline signature line(s) | signed root | verified before any field is trusted |

The existing `BundleEntry` (`bundle.rs:34-45`) and `BundleType`
(`bundle.rs:22-31`) carry the right shape already; `pick_bundles` should be
reusable against `root.bundle_index` with minimal change, because the entry
fields (`creation_token`, `sha256`, `size`, `bundle_type`, `base_tag`,
`target_tag`) are unchanged. The **key difference** is that the entry's fetch key
is now the content hash, not a producer-chosen `uri` (see §6).

---

## 4. Channel tracking (TARGET)

Channels decouple a moving alias (`stable`, `testing`) from concrete tags
(brief §4.3, §6 Tier-1 #3; [`versioning-and-channels.md`](../../registry/versioning-and-channels.md)).

### 4.1 Config

```toml
# registries.d/aos-core.toml
[registry]
name = "aos-core"
url  = "https://registry.aos.dev/core"
channel = "stable"          # NEW — mutually exclusive with commit/branch/tag/version
```

### 4.2 Resolution in `pick_bundles`

Add a `TrackingMode::Channel(name)` arm **before** the incremental fallthrough
(mirroring the `Tag` arm at `update.rs:299`):

```
Channel(name):
  let entry = root.channels.get(name)?           // else bail "unknown channel"
  let target_tag = entry.tag
  if let Some(pct) = entry.rollout {              // phased rollout (§4.3, §6 #4)
      if !in_rollout_bucket(machine_id, name, pct) {
          // not yet in the rollout window -> hold (no-op): the host STAYS AT
          // its current last_creation_token and selects no bundles this run.
          return Ok(vec![]);
      }
  }
  // resolve target_tag exactly like Tag mode: snapshot, else delta-to-tag
```

### 4.3 Rollout gating function

A deterministic bucket so a host either is or isn't in the rollout, stably
across runs (APT `Phased-Update-Percentage` analogue):

```
bucket   = u64::from_le_bytes( sha256(machine_id || ":" || channel_name)[..8] )
in_window = (bucket % 100) < rollout_pct
```

The hash is `sha256(machine_id : channel_name)` — keyed on the **channel name**
and explicitly **NOT** the target tag, so a host's cohort stays stable across
promotions (a host in the rollout for one tag stays in it for the next; it does
not re-bucket each promotion). Inputs: `machine_id` from `/etc/machine-id`
(system scope) or a per-user stable id (user scope). The function must be pure
and side-effect free for testability.

### 4.4 Channel-switch handling

If `state.last_channel != Some(config.channel)`, the client is switching
channels (e.g. `testing` → `stable`). This can legitimately move the
`creation_token` **backwards** (stable lags testing). The monotonic check
(`state.rs:104`) MUST be **scoped per channel** or bypassed on an explicit
channel switch — otherwise a `stable`→`testing`→`stable` user trips a false
"downgrade detected". Record `last_channel` so the switch is detectable; on a
detected switch, replace state rather than diffing tokens.

---

## 5. Expiry / freeze checks (TARGET)

Two independent anti-staleness signals from the signed root (brief §4.5):

### 5.1 `valid_until` expiry

After signature verification, before selecting bundles:

```
let now = now_iso8601();                         // update.rs:545 already exists
if root.meta.valid_until < now {                 // string compare ok for ISO-8601 Z
    bail!("registry root for '{name}' expired at {valid_until} (now {now}); \
           the mirror may be frozen. Refusing stale metadata.");
}
```

This catches a mirror serving a **validly-signed-but-old** root that
`check_monotonic` alone cannot see (the old root is internally consistent). The
producer re-signs each publish with `valid_until = publish + N`
([workstream-04](./workstream-04-channels-rollouts.md), brief §6 Tier-1 #1).

### 5.2 `[latest].token` monotonicity

Reuse `check_monotonic` (`state.rs:104`) but feed it **`root.latest.token`**, not
the max applied bundle token. The current code (`update.rs:263`) only checks the
*applied* tokens; that defends against applying an older bundle, but the signed
`[latest].token` lets the client also reject a root whose advertised head is
older than what it already synced — even before downloading any bundle.

```
if let Some(prev) = state.last_creation_token {
    state::check_monotonic(prev, root.latest.token)?;   // pre-flight, on the root
}
```

> Both checks are **clock-dependent vs clock-independent** in different ways:
> `valid_until` needs a roughly-correct local clock; `[latest].token`
> monotonicity needs persisted prior state. Run both; either firing is fatal.
> See [`signing-and-trust.md`](../../registry/signing-and-trust.md) for the full
> threat model.

---

## 6. By-hash fetch (TARGET)

### 6.1 Why

The root references each bundle **by its content hash** (APT `by-hash`
discipline, brief §4.3, §6 Tier-1 #2). A client that read `root@T` resolves a
consistent bundle set even if the origin flips to `root@T+1` mid-sync, because
the hashed objects `root@T` references are immutable and were uploaded before the
root flip ([workstream-02](./workstream-02-publish-pipeline.md), brief §4.4).

### 6.2 CURRENT vs TARGET URL grammar

| | URL | Integrity binding |
|---|---|---|
| CURRENT | `{base}/bundles/{name}/{entry.uri}` (`bundle.rs:259`) | SHA-256 from unsigned manifest |
| TARGET | `{base}/bundles/{name}/by-hash/sha256/{entry.sha256}` (or content-keyed object) | SHA-256 from **signed** root |

The SHA-256 verification machinery already exists end-to-end:
`TransferRequest::with_hash(HashAlgorithm::Sha256, &entry.sha256)`
(`bundle.rs:276`) and the recompute in `verify_bundle` (`bundle.rs:315`). The
change is (a) the URL is derived from the hash rather than a producer `uri`, and
(b) the expected hash now comes from a signed source, so a tampered mirror cannot
point the client at different bytes. See
[`http-layout.md`](../../registry/http-layout.md) for the canonical object-key
grammar.

### 6.3 Migration shim

To avoid a flag-day, the consumer can prefer the by-hash path and **fall back**
to the legacy `{base}/bundles/{name}/{uri}` path when the root advertises no
by-hash capability (`[capabilities]` flag, brief §6 Tier-2 #6). The SHA-256
check is identical in both cases, so the fallback is safe.

---

## 7. Fail-closed omission handling (TARGET)

### 7.1 The threat

A malicious or broken listing/mirror **hides** newer bundles so the client
silently stays on stale-but-valid data (brief §4.5 "Omission"). Today, if a
bundle is omitted from `bundle-list.toml`, `pick_bundles` simply selects fewer
entries and reports "Already up to date" (`update.rs:209`) — a **silent**
downgrade-to-stale.

### 7.2 The fix: the signed `[latest].head` is a reachability assertion

After applying the selected bundles and resolving the target commit:

```
let new_commit = bundle::resolve_tag(&repo_dir, &last_target_tag).await?;  // update.rs:249

// When the target IS [latest] (Default/Branch/Channel-to-latest), the
// resolved commit MUST equal the signed head. If it does not, a bundle was
// omitted or the listing lied.
if target_is_latest && new_commit != root.latest.head {
    bail!("omission detected: synced to {new_commit} but signed [latest].head is \
           {head}. A mirror may be hiding newer bundles. Refusing to report \
           success on stale metadata.");
}
```

Because `[latest].head` is an authentic git commit SHA inside the signed root, a
mirror cannot forge it. If the client **cannot reach** that head (no bundle path
to it), it **fails closed** — surfacing an error rather than reporting a
spuriously-successful update. Freeze thus degrades to a visible DoS, never a
silent rollback (brief §4.5).

### 7.3 Interaction with "up to date"

The `entries_since(current).is_empty()` early return (`update.rs:355`) is only
legitimate when `state.last_commit == root.latest.head` (the client already holds
the signed head). If the index claims "nothing newer" but the client's commit is
**not** the signed head, that is an omission — bail, don't return `Ok(vec![])`.

---

## 8. State persistence changes

`state::save_state` (`state.rs:37-77`) already rewrites only `[registry.state]`,
preserving user fields. The new optional fields slot in cleanly:

```toml
[registry.state]
last_commit          = "deadbeef…"
last_creation_token  = 2026020003
last_update          = "2026-02-16T12:00:00Z"
last_channel         = "stable"             # NEW
root_valid_until     = "2026-03-01T00:00:00Z"  # NEW (diagnostics / next-run hint)
```

`save_state` builds the section line-by-line (`state.rs:42-51`); add two
`if let Some(...)` blocks following the existing pattern. `load_state`
(`state.rs:21`) deserializes via `RegistryFile` and needs no change beyond the
struct fields being `#[serde(default)]` (already the convention,
`types.rs:256-261`). Round-trip is covered by the existing `state.rs` tests
(`save_state_*`, `load_state_*`) — extend them for the two new fields.

---

## 9. Implementation checklist

| # | Change | File(s) | Depends on |
|---|---|---|---|
| 1 | `RegistryRoot::fetch` + parser (inline-sig verify) | `registry/root.rs` (new), `bundle.rs` | [WS-01](./workstream-01-registry-root.md) |
| 2 | Swap `BundleManifest::fetch` → `RegistryRoot::fetch` in `sync_bundle` | `update.rs:203` | #1 |
| 3 | `TrackingMode::Channel` + `RegistryConfig.channel` + `tracking_mode()` validation | `types.rs:282`, `:307`, `:352` | — |
| 4 | `Channel` arm in `pick_bundles` + rollout gate | `update.rs:298` | #3, [WS-04](./workstream-04-channels-rollouts.md) |
| 5 | `valid_until` expiry pre-flight | `update.rs` (in `sync_bundle`), `state.rs` | #1 |
| 6 | `[latest].token` monotonic pre-flight (reuse `check_monotonic`) | `update.rs`, `state.rs:104` | #1 |
| 7 | By-hash URL grammar + capability fallback | `bundle.rs:259`, `:100` | [WS-01](./workstream-01-registry-root.md) |
| 8 | Fail-closed `[latest].head` assertion + "up to date" guard | `update.rs:249`, `:355` | #1 |
| 9 | `RegistryState.last_channel` / `root_valid_until` + per-channel monotonic scope | `types.rs:253`, `state.rs:37`, `:104` | #3 |
| 10 | Tests: channel resolution, rollout buckets, expiry, omission, by-hash | `update.rs` / `bundle.rs` / `state.rs` test mods | all |

### Test strategy

The existing test suites are the template:

- `pick_bundles_*` (`update.rs:627-751`) — add `pick_bundles_channel_mode`,
  `pick_bundles_channel_rollout_held`, `pick_bundles_omission_fails_closed`.
- `bundle.rs` parse tests (`:499-723`) — add signed-root parse, by-hash key
  parse, capability-flag parse.
- `state.rs` (`:196-443`) — add `valid_until` expiry, `[latest].token`
  monotonic, channel-switch bypass, new-field round-trip.

Rollout gating must be tested with a fixed `machine_id` for determinism (the
bucket function is pure by design).

---

## 10. Open questions

These are consumer-specific; see [`open-questions.md`](./open-questions.md) and
brief §7 for the full list.

1. **Two `registry.toml` files.** `types.rs:566-599` (`RegistryRootConfig`) is
   the **in-repo** caches/signing file read by `download::resolve_mirror`
   (`download.rs:67`); brief §4.3's `registry.toml` is the **HTTP-served signed
   root**. The plan must decide whether the served root *is* this struct extended
   (with `[latest]`/`[channels]`/`valid_until`/bundle index/signature) or a
   distinct file. This doc assumes a **superset of the in-repo struct**, but the
   code today treats them as different concerns. **(Discrepancy: brief implies a
   single root; code has two distinct `registry.toml` structs.)**
2. **Rollout hash inputs** (brief §7.4): exact bytes (`machine_id` source per
   scope, separator) and how a client learns/serves its bucket. The gating hash
   is `sha256(machine_id : channel_name) % 100` — keyed on the channel name and
   NOT the target tag, so cohorts stay stable across promotions. The remaining
   open detail is the `machine_id` source per scope, unconfirmed.
3. **Per-channel monotonic scope.** `check_monotonic` (`state.rs:104`) is global;
   channel switching can legitimately regress the token. The plan must choose
   between per-channel state, explicit channel-switch bypass, or rejecting
   regressions outright. This doc proposes bypass-on-switch via `last_channel`.
4. **`valid_until` clock dependence.** Expiry needs a roughly-correct local
   clock; hosts with skewed clocks may falsely reject. Decide whether to pair it
   with an NTP-freshness assumption or a grace window (brief §7.5).
5. **Migration / compat shim** (brief §7.7): does the consumer keep reading
   legacy unsigned `bundle-list.toml` mirrors during transition, gated on a
   schema-version / capability flag, or is this a clean break? This doc assumes a
   capability-gated fallback (§6.3).
6. **Commit-mode under bundle transport** stays unsupported (`update.rs:314`
   falls through). Channels do not change this; arbitrary-commit resolution
   remains a git-transport-only capability (brief §2.6 step 2).
