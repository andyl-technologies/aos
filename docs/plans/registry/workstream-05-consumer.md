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
> **§11** (signing & trust — name-binding), and **§13** (Nix binary-cache
> superset — client-side substituter config). The brief is authoritative for
> intent; this doc translates that intent into a concrete change set on the
> `apm update` / `apm upgrade` path.

This is the `apm`-side counterpart to the producer workstreams
([01 object store](./workstream-01-object-store.md),
[02 pack/delta pipeline](./workstream-02-pack-delta-pipeline.md),
[03 channels & rollouts](./workstream-03-channels-rollouts.md),
[04 signing & trust](./workstream-04-signing-trust.md)). The consumer **only
reads static files over dumb HTTP** — there is no server-side cooperation and no
smart-protocol negotiation. The consumer's job is six steps:

1. **Bucket selection** — deterministically self-select one of 256 partitions.
2. **Tag-chain resolution** — `/channels/<name>/<bucket>` signed tag → semver tag
   → commit.
3. **Chain verification** — verify both signatures *and* the name-binding of each
   tag object to its serving path (§11).
4. **Anti-rollback** — refuse a target older than the monotonic floor.
5. **Delta-walk fetch** — pick a thin `delta-*.pack` whose base is retained, walk
   backward otherwise, fall to full pack, fall to loose objects; complete with
   `git index-pack --fix-thin`; apply retention.
6. **Nix cache wiring** — resolve the NAR substituter from the **committed
   git-repo-root `registry.toml` `[[caches]]`** (authenticated via the tag), with
   the **client-side `registries.d`** as an optional override (or the origin
   itself) and register it for NAR substitution. The substituter location is
   **not** advertised in signed tags.

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
> the 256-partition tag chain, thin `delta-*.pack` walking, or client-side
> NAR-substituter wiring exist. This section maps the surfaces WS-05 replaces.

### 2.1 The sync entry point

`apm update` runs `update::run`
([`update.rs:37`](../../../crates/aos-package/src/update.rs)), which loops over
enabled registries and dispatches on `reg_config.transport()`
([`update.rs:116`](../../../crates/aos-package/src/update.rs)):
`Transport::HttpBundle` → `sync_bundle`
([`update.rs:209`](../../../crates/aos-package/src/update.rs)), `Transport::Git`
→ `git::sync_git` ([`git.rs:45`](../../../crates/aos-package/src/registry/git.rs)).
The bundle path is what the git-native model replaces.

### 2.2 Bundle selection — `pick_bundles`

`pick_bundles` ([`update.rs:319`](../../../crates/aos-package/src/update.rs),
signature `fn pick_bundles<'a>(manifest: &'a BundleManifest, reg_state:
&RegistryState, tracking_mode: &TrackingMode) -> Result<Vec<&'a BundleEntry>>`)
is the CURRENT analogue of the TARGET delta-walk. Its three-strategy logic —

```
1. skip delta from current minor base (update.rs:394-403, manifest.skip_delta_from)
2. sequential deltas current→latest   (update.rs:405-411, manifest.sequential_deltas_between)
3. fall back to the latest snapshot    (update.rs:413-417, manifest.latest_snapshot)
```

— is structurally the right shape (prefer a single big delta, else a chain, else
a self-contained pack), but it operates on `bundle::BundleEntry`s keyed by
`creation_token` and `target_tag`, not on git thin packs keyed by semver. The
TARGET replaces the *unit* (bundle → thin `delta-*.pack`), the *index* (manifest
→ git object store + `info/alternates`), and the *ordering key* (`creation_token`
→ semver + git ancestry), while keeping the prefer-delta-then-full-then-loose
shape.

### 2.3 Tracking modes — the resolution surface

`TrackingMode` ([`types.rs:279`](../../../crates/aos-package/src/types.rs)) has
five arms — `Commit(String)`, `Branch(String)`, `Tag(String)`,
`Version(semver::VersionReq)`, `Default` — resolved by
`RegistryConfig::tracking_mode()`
([`types.rs:349`](../../../crates/aos-package/src/types.rs)). There is **no
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
([`update.rs:290-291`](../../../crates/aos-package/src/update.rs)) — so the check
only runs when the new token is *already greater*, i.e. exactly the case that is
**not** a downgrade. A genuine rollback (`latest_token <= old_token`) skips the
guard entirely. WS-05 reimplements the floor on **semver** and **fixes the
gating bug** (see §7).

### 2.5 Persisted state

`RegistryState { last_commit, last_creation_token, last_update }`
([`types.rs:251`](../../../crates/aos-package/src/types.rs); `last_creation_token`
field at [`types.rs:256`](../../../crates/aos-package/src/types.rs)) is persisted
under `[registry.state]`. Its fields are reassigned in `sync_bundle`
([`update.rs:297-299`](../../../crates/aos-package/src/update.rs)) and the block is
rewritten by the caller `update::run`
([`update.rs:153`](../../../crates/aos-package/src/update.rs)) via
`state::save_state` ([`state.rs:37`](../../../crates/aos-package/src/registry/state.rs)).
WS-05 **retires `last_creation_token`** and adds a semver floor, a persisted
bucket, and a retained-release set (§3.5, §7) — i.e. the struct becomes
`RegistryState { last_commit: Option<String>, floor: Option<String>, bucket:
Option<u8>, retained: Vec<String>, last_update: Option<String> }`. This change
breaks every existing literal that names `last_creation_token` — the
`pick_bundles` tests (`pick_bundles_already_up_to_date`, `pick_bundles_uses_skip_delta`,
`pick_bundles_uses_sequential_when_no_skip` at
[`update.rs:670-716`](../../../crates/aos-package/src/update.rs)) and the
`state.rs` round-trip tests (`load_state_from_registry_file`,
`save_state_appends_to_file_without_state`,
`save_state_replaces_existing_state_section` at
[`state.rs:277-407`](../../../crates/aos-package/src/registry/state.rs)) — all of
which must be ported to the new fields.

---

## 3. TARGET — the consumer resolution pipeline

### 3.1 End-to-end flow

```
apm update / apm upgrade
│
├─ 1. bucket   = persisted_bucket  ||  the low byte of sha256(machine_id) (i.e. mod 256)      (§4)
│
├─ 2. fetch    /channels/<name>/<bucket>        (signed partition tag object)
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
├─ 7. wire NAR substituter from committed registry.toml [[caches]]    (§8)
│        (client-side registries.d override; else origin)
│
└─ 8. persist state: floor=semver, bucket, retained set                (§3.5)
```

Every fetch in step 4 is a static GET; the loose-object tier guarantees the whole
flow is **always completable** even if every pack is missing or corrupt.

### 3.2 What the consumer reads (recap of the static surface)

| URL | Purpose | Verify |
|---|---|---|
| `/channels/<name>/<bucket>` | signed partition tag → semver tag | sig + name == `<name>` |
| `refs/tags/<semver>` (via `info/refs`) | signed release tag → commit | sig + name == `<semver>` |
| `objects/info/alternates` | relative `../releases/*/objects/` entries, newest→oldest; pack discovery + release index | — |
| `/releases/<M>/<m>/<p…>/objects/info/packs` | self-contained full packs only | idx self-check |
| `/releases/<M>/<m>/<p…>/objects/pack/delta-<from>.pack[.zst]` | thin AOS deltas (NOT in `info/packs`) | `index-pack --fix-thin` |
| `/objects/<xx>/<62hex>` | loose objects (sha256 2/62), centralized at the root | sha256 == path |

The `objects/info/alternates` entries are **relative** paths, newest→oldest, e.g.
`../releases/1/1/0/objects/`. Git resolves relative alternates against the repo's
`objects/` URL, so each `../` strips the trailing `objects` segment to reach the
repo root — therefore the correct depth is **one** `../`, not two. The file is
**host-independent** (byte-identical across CDN, mirror, and `localhost` — no
hostname is baked in). The dumb-HTTP walker reads `http-alternates` first then
falls back to `alternates`, so a single relative `info/alternates` works for HTTP
**and** local-FS clones. Because loose objects are centralized at the root
`/objects/`, alternates serve **pack discovery + the release index**, not object
completeness.

See [`http-layout.md`](../../registry/http-layout.md) and
[`packs-and-deltas.md`](../../registry/packs-and-deltas.md) for the full layout.

### 3.3 The tag chain — `tag → tag → commit`

```
/channels/stable/b7  ──►  signed partition tag object
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
therefore resolves through `/channels/<name>/<bucket>`, which the publisher
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

`state::save_state(path: &Path, state: &RegistryState) -> Result<()>`
([`state.rs:37`](../../../crates/aos-package/src/registry/state.rs)) already
preserves user-edited fields and rewrites only the `[registry.state]` block via
`find_state_section` ([`state.rs:80`](../../../crates/aos-package/src/registry/state.rs)).
WS-05 extends its serializer (it currently emits `last_commit`,
`last_creation_token`, `last_update` at
[`state.rs:43-51`](../../../crates/aos-package/src/registry/state.rs)) to drop the
`if let Some(token) = state.last_creation_token` branch
([`state.rs:46-48`](../../../crates/aos-package/src/registry/state.rs)) and emit
instead `floor = "<semver>"`, `bucket = <u8>`, and `retained = ["…", …]` (a TOML
array). Loading is automatic once `RegistryState` gains the new `#[serde(default)]`
fields, since `load_state` ([`state.rs:21`](../../../crates/aos-package/src/registry/state.rs))
deserialises the whole struct from `RegistryFile`.

---

## 4. Bucket selection (consumer self-partitioning)

> **TARGET.** Per [brief §6](./design-brief.md#6-channels--rollouts): a channel
> exposes exactly **256** partitions `/channels/<name>/00..ff`; the consumer
> deterministically self-selects **one** bucket and **persists** it so a host
> never flaps between buckets across updates.

### 4.1 Selection function

```text
bucket = the low byte of sha256(machine_id) (i.e. mod 256)            # 0..=255, rendered as one byte (two hex digits, 00–ff)
```

This lands in a **new** module `crates/aos-package/src/registry/channel.rs`
(consumer-side channel resolution; sibling to `state.rs` and `git.rs`), with:

```rust
/// Compute the partition bucket for a host. `machine_id` defaults to the
/// trimmed contents of /etc/machine-id; sha256 is the digest already used
/// by aos_core::nar::info::store_hash.
pub fn select_bucket(machine_id: &str) -> u8;            // sha256(machine_id)[0]

/// Two-hex-digit lowercase rendering for the partition file name (00..ff).
pub fn bucket_hex(bucket: u8) -> String;                 // format!("{bucket:02x}")

/// Read the persisted bucket, or compute+return one to be persisted.
pub fn resolve_bucket(state: &RegistryState, machine_id: &str) -> u8;
```

`resolve_bucket` reads `state.bucket` (the new `Option<u8>` field, §3.5) and
falls back to `select_bucket`; `sync_bundle`'s git-native successor writes the
result back into `RegistryState.bucket` before `save_state`.

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
    try fetch /channels/<name>/((b + i) mod 256)
    if present and verifies: use it; stop
fail closed if none of 256 resolve
```

Probe-forward order is fixed (`(bucket+i) mod 256`) so the fallback is itself
deterministic and does not re-introduce flapping. The fallback order is
[open question §16.3](./design-brief.md#16-open-questions--to-confirm-in-implementation).

The probe sequence is generated by `fn probe_order(bucket: u8) -> impl
Iterator<Item = u8>` in `channel.rs`, yielding `(0..256).map(|i| bucket.wrapping_add(i))`.
Tests in `channel.rs`: `#[test] fn test_select_bucket_deterministic` (same
`machine_id` → same `u8`), `#[test] fn test_bucket_hex_two_digits` (`5` → `"05"`,
`255` → `"ff"`), `#[test] fn test_probe_order_wraps_and_covers_all_256` (every
bucket appears exactly once, starting at `bucket`), and `#[test] fn
test_resolve_bucket_prefers_persisted` (a `RegistryState` with `bucket =
Some(183)` returns `183` regardless of `machine_id`).

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

This is a **new** function in `crates/aos-package/src/registry/fetch.rs` (a new
module replacing the bundle-walk in `pick_bundles`), with the signature:

```rust
/// Plan and execute the object fetch from current `from` to target `to`,
/// completing thin packs with `git index-pack --fix-thin`. `retained` is the
/// release set the client currently holds (§5.4); `origin` is the registry
/// base URL; `repo_dir` is the local object store.
pub async fn resolve_objects(
    repo_dir: &Path,
    origin: &str,
    from: &semver::Version,
    to: &semver::Version,
    retained: &[semver::Version],
    engine: &aos_net::TransferEngine,
    printer: &Printer,
) -> anyhow::Result<()>;
```

with supporting helpers `fn deltas_at(to: &semver::Version) -> Vec<semver::Version>`
(the bases the producer ships per §5.1) and `async fn releases_between(origin:
&str, to: &Version, from: &Version) -> Result<Vec<Version>>` (newest→oldest, read
from `objects/info/alternates`). It replaces the three `pick_bundles` strategies
([`update.rs:394-417`](../../../crates/aos-package/src/update.rs)) and reuses
`aos_net::{TransferEngine, TransferRequest}` (already used by
`download::fetch_one_narinfo`, [`download.rs:154`](../../../crates/aos-package/src/download.rs))
for the static GETs.

```text
resolve_objects(from C, to T):
  # 1. prefer a delta at T whose base we retain
  for B in deltas_at(T) ordered nearest-base-first:
      if B in retained:
          fetch delta-<B>.pack[.zst]   →  index-pack --fix-thin   →  DONE

  # 2. walk releases backward looking for a usable delta or a full pack
  for R in releases_between(T, C) newest→oldest (via info/alternates):
      if R is X.Y.0 and full pack present:
          fetch pack-<sha256>.pack (+ .idx)
          then walk forward applying deltas R → … → T          →  DONE
      if some delta-<B>.pack at R has B in retained:
          fetch it, then continue toward T                      →  DONE

  # 3. no usable delta path: fetch the nearest full pack outright
  fetch the X.Y.0 full pack covering T's minor, then deltas to T →  DONE

  # 4. last resort: loose objects over dumb HTTP (ALWAYS correct)
  enumerate missing objects, GET /objects/<xx>/<62hex>            →  DONE
```

- **Cross-major jumps** degrade to "minor-base full pack + walk": fetch the
  `X.Y.0` full pack of the target's minor, then apply the patch deltas up to `T`.
- **Loose-object fallback** is unconditional correctness: ALL objects (every
  release) exist loose under the single root `/objects/<xx>/<…>`
  ([brief §8](./design-brief.md#8-object-store--dumb-http-details)) and are
  reachable directly — no alternates traversal is needed for object
  completeness. The relative `objects/info/alternates` instead serves **pack
  discovery + the release index** (the per-release pack-only stores). A sha256
  loose object is self-verifying (content hash == path).

This is the TARGET shape of the CURRENT `pick_bundles` three-strategy logic
([`update.rs:394-417`](../../../crates/aos-package/src/update.rs)): prefer one
big delta (skip → "delta whose base we retain"), else a chain (sequential →
"walk backward"), else a self-contained artifact (snapshot → "full pack"), with a
new unconditional loose-object floor.

Named tests in `fetch.rs`: `#[test] fn test_deltas_at_patch_bases`
(`X.Y.Z` → `[X.Y.(Z-1), X.Y.(Z-2), X.Y.(Z-3), X.Y.0]`, matching the §5.1 table),
`#[test] fn test_deltas_at_minor_bases` (`X.Y.0` → `[X.(Y-1).0, X.0.0]`),
`#[tokio::test] async fn test_resolve_objects_prefers_retained_delta` (one fetch
when the nearest base is retained), and `#[tokio::test] async fn
test_resolve_objects_falls_to_loose` (all packs 404 → loose-object floor
completes). These supersede the bundle-manifest tests
`pick_bundles_uses_skip_delta` / `pick_bundles_uses_sequential_when_no_skip`
([`update.rs:684-716`](../../../crates/aos-package/src/update.rs)), which are
deleted along with `pick_bundles`.

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

Retention is computed by `fn retained_set(target: &semver::Version) ->
Vec<semver::Version>` in `fetch.rs` (returns the deduplicated `{ X.0.0, X.Y.0,
X.Y.Z }`), serialized into `RegistryState.retained: Vec<String>` (§3.5), and
parsed back via `semver::Version::parse`. Pruning is `fn prune_releases(repo_dir:
&Path, keep: &[semver::Version]) -> Result<()>`, which removes per-release
pack-store directories under the `objects/info/alternates` entries not in `keep`
(the centralized root `/objects/` loose store is never pruned by this path —
losing it would break the §5.2 step-4 floor). Tests: `#[test] fn
test_retained_set_dedups_when_minor_is_zero` (`1.4.0` → `["1.0.0", "1.4.0"]`, not
three entries), `#[test] fn test_retained_set_three_distinct` (`1.4.2` →
`["1.0.0", "1.4.0", "1.4.2"]`).

> **Note on the retained set size.** Three trees is the *minimum*; a client MAY
> keep more (e.g. the last few patches) to widen the single-fetch window, at a
> disk-space cost. The minimum guarantees a base is always present without
> requiring history beyond the current major/minor/patch.

### 5.5 Stock-git graceful degradation (for contrast)

A stock dumb `git clone` of a patch release cannot apply thin packs (they are not
in `info/packs`), so it pulls the **minor-base full pack** via the relative
`info/alternates` plus the patch's **loose new objects** (from the root
`/objects/`) — no AOS logic, no thin packs, still
correct ([brief §9](./design-brief.md#9-packs--the-delta-scheme),
[§12](./design-brief.md#12-stock-git-dumb-http-compatibility)). The AOS consumer
is strictly faster (thin deltas) but degrades to exactly this path via the
loose-object floor.

---

## 6. Chain verification (name-binding)

> **TARGET.** Per [brief §5](./design-brief.md#5-ref-model--three-layers),
> [§11](./design-brief.md#11-signing--trust), and
> [§14](./design-brief.md#14-tag-payload-repo-tree-config--trust-files): AOS
> verification is `signed partition tag → signed semver tag → commit`, checking
> the **signature** *and* the embedded **tag-name field** against the expected
> name. This binds a tag object to its serving path and prevents cross-serving.
> The trusted-key set is the committed `keys.toml` trust roster (≥2 overlapping
> active keys, no root tier), bootstrapped by a client-side TOFU pin (§6.3).

### 6.1 The two checks, applied to each tag object

| Tag object | Signature check | Name-binding check |
|---|---|---|
| `/channels/<name>/<bucket>` | Ed25519/SSH valid against a trusted key | embedded tag name `== "<name>"` (the channel) |
| `refs/tags/<semver>` | Ed25519/SSH valid against a trusted key | embedded tag name `== "<semver>"` (the release) |

The **name-binding** is what stops a valid-but-misfiled tag from being honoured:
a partition tag signed for channel `testing` served under `/channels/stable/3f`
fails because its embedded name is `testing`, not `stable`. Likewise a release
tag whose embedded name is `1.4.1` cannot be served from the `1.4.2/` release
path. This closes cross-serving without any server-side enforcement — the
consumer rejects the mismatch.

### 6.2 Reusing existing signing primitives

WS-05 reuses the WS-04 / `security.rs` Ed25519 verification primitives:
`parse_signing_key` (`name:Ed25519:<base64>`,
[`security.rs:306`](../../../crates/aos-package/src/security.rs)), the `KeyStore`
TOFU machinery (`KeyStore::lookup` / `tofu_check`,
[`security.rs:52`,`:159`](../../../crates/aos-package/src/security.rs)) reading
`trusted-keys.d/<registry>.pub` (via `ProfileScope::trusted_keys_dirs`,
[`types.rs:499`](../../../crates/aos-package/src/types.rs)), and the
`allowed_signers`-file pattern from `verify_commit_signature`
([`security.rs:199`](../../../crates/aos-package/src/security.rs); a second copy
exists at [`git.rs:391`](../../../crates/aos-package/src/registry/git.rs) using
bare `git verify-commit`).

The CURRENT code verifies SSH-format Ed25519 git signatures only for **commits**
(`git verify-commit`). The TARGET adds a **new** `verify_tag` to
`channel.rs`, applying the same primitive to **tag objects**:

```rust
/// Verify a tag object's signature against the trusted key set and check the
/// embedded tag-name header equals `expected_name` (the name-binding, §6.1).
/// Returns the target object the tag points at on success.
pub async fn verify_tag(
    repo_dir: &Path,
    tag_ref: &str,
    expected_name: &str,
    keys: &KeyStore,
    registry: &str,
) -> anyhow::Result<String>;        // Ok(target object id) or Err(reject)
```

It shells out via the allow-fail helper `git_try`
([`registry_ops.rs:96`](../../../crates/aos-package/src/registry_ops.rs)) running
`git verify-tag <tag_ref>`, then reads the tag-name header from `git cat-file -p
<tag_ref>` (the `tag <name>` line) and string-compares it to `expected_name`. A
signed tag is a **pure signed pointer** — standard git tag fields (object, type,
tag name, tagger) + the Ed25519 signature + an optional freeform human message —
so the only thing parsed out of it is the tag-name header (for name-binding);
there is no structured tag payload to read. Tests in `channel.rs`: `#[tokio::test]
async fn test_verify_tag_rejects_name_mismatch` (a tag whose `tag` header is
`testing` served as `stable` is rejected) and `#[tokio::test] async fn
test_verify_tag_rejects_bad_signature` (untrusted key → reject).

### 6.3 Trust roster — `keys.toml` (rotation, retirement & compromise)

> **TARGET.** Per [brief §14](./design-brief.md#14-tag-payload-repo-tree-config--trust-files):
> the set of trusted signing keys lives in a **committed git-repo-root
> `keys.toml`** — the **trust roster** (active signing key(s) + a revoked list),
> authenticated via the signed tag like every other tree file. The signing pubkey
> is **not** in `registry.toml` (a key inside a file authenticated by that key is
> circular for bootstrap). See [`repo-layout.md`](../../registry/repo-layout.md)
> §3.
>
> **Trust model — decided: ≥2 overlapping active keys.** There is **no**
> offline-root / operational two-tier and **no** TUF-style root role. The **git
> lineage** (signed tag → commit → parent chain) provides continuity, so a
> separate root tier is unnecessary. `keys.toml` lists the active signing key(s)
> — `id` + `key`, **no role field**, **no `root` entry** — plus a `revoked` list.

- **Bootstrap trust is TOFU-pinned client-side**, **not** read from `keys.toml`:
  initial trust is the pinned key in `trusted-keys.d/<registry>.pub`
  (`security.rs`, `types.rs` `trusted_keys_dirs()`). `keys.toml` does **not**
  bootstrap trust. The consumer verifies the tag chain (§6.1) with the pinned
  key, *then* reads `keys.toml` from the resolved tree.
- **Rotation:** the publisher commits `keys.toml` listing **both** the old and
  new keys (an overlap window) in a tag signed by the **currently-trusted** key.
  A consumer that trusts the old key verifies the tag, reads `keys.toml`, and
  **pins the new key**. A later publish drops the old key.
- **Planned retirement:** list the key under `revoked`, in a `keys.toml` **signed
  by one of the *other* overlapping active keys**. With ≥2 overlapping active
  keys this needs no separate signing tier.
- **Compromise** is handled **out-of-band**: the consumer **re-pins** via
  `trusted-keys.d` (`apr trust`). An in-repo key cannot credibly revoke itself,
  and compromise is rare enough that the out-of-band re-pin is acceptable.

The consumer therefore follows `keys.toml` for active-key/retirement state on
**every** resolution after the TOFU bootstrap, with the client-side
`trusted-keys.d/<registry>.pub` pin as the only out-of-band trust input.

**Concretely.** `keys.toml` parses into the **WS-04-owned** roster types — the
consumer **does not redeclare them**. The canonical definitions live in
[workstream-04-signing-trust.md §7.5](./workstream-04-signing-trust.md#75-trust-roster-lives-in-keystoml-not-in-registrytoml-g9)
(`crates/aos-package/src/registry/keys.rs`, a **new** module):

```rust
// crates/aos-package/src/registry/keys.rs  (defined in WS-04 §7.5 — IMPORTED here)
pub struct KeysToml {
    pub schema: u32,                       // = 1
    pub keys: Vec<RosterKey>,              // active signing key(s)
    pub revoked: Vec<RevokedKey>,          // planned-retirement list
}
pub struct RosterKey { pub id: String, pub key: String }   // key: "name:Ed25519:<base64>"
pub struct RevokedKey { pub id: String, pub reason: Option<String> }  // reason: freeform
```

WS-05 **imports** these (`use crate::registry::keys::{KeysToml, RosterKey,
RevokedKey, read_keys_toml}`) rather than declaring a parallel type in `types.rs`
— a divergent `types.rs` copy would drift from the producer's serializer and the
`revoked` shape (WS-04's `revoked` is `Vec<RevokedKey { id, reason }>`, **not** a
second `Vec<RosterKey>`). The roster is read from the resolved tree by WS-04's
reader `keys::read_keys_toml(dir: &Path) -> Result<Option<KeysToml>>`
(WS-04 §7.5 / §8.1, sourcing the bytes with `git -C <repo> show <commit>:keys.toml`
into the reconstructed tree, then validating each `RosterKey.key` through
`parse_signing_key`, [`security.rs:306`](../../../crates/aos-package/src/security.rs)).
The parsed active keys feed the `KeyStore` used by `verify_tag` (§6.2).
Out-of-band re-pin (`apr trust`) is a
**new** producer/operator subcommand that writes
`trusted-keys.d/<registry>.pub` via `KeyStore::store`
([`security.rs:97`](../../../crates/aos-package/src/security.rs)); no `apr trust`
exists today. The roster parse/roundtrip tests are owned by WS-04 alongside the
type definitions (`keys_toml_roundtrip`, `keys_toml_rejects_bad_key_format`,
`keys_toml_absent_returns_none` in `registry/keys.rs`,
[WS-04 §7.5](./workstream-04-signing-trust.md#75-trust-roster-lives-in-keystoml-not-in-registrytoml-g9));
the no-root-tier decision (`keys.toml` carries no role field) is enforced there.
WS-05 adds only consumer-side coverage that `verify_tag` (§6.2) honours the active
keys read back from the imported roster.

### 6.4 Verification ordering (fail-closed)

```text
1. fetch partition tag  → verify sig → check name == channel   (else REJECT)
2. follow to semver tag → verify sig → check name == semver     (else REJECT)
3. follow to commit     (commit content is hash-addressed; objects self-verify)
4. anti-rollback: semver(target) >= floor ?  (else REFUSE)             (§7)
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
[`update.rs:427`](../../../crates/aos-package/src/update.rs) and the
`TrackingMode::Version(semver::VersionReq)` arm,
[`types.rs:287`](../../../crates/aos-package/src/types.rs)), so the comparison is
plain `semver::Version` ordering — `target >= floor` via the derived `Ord`. The
floor lives in a **new** `fn check_floor(target: &semver::Version, floor:
Option<&semver::Version>) -> Result<()>` in `state.rs`, replacing
`check_monotonic`.

### 7.2 Replacing `check_monotonic` and fixing the gating bug

The CURRENT `check_monotonic`
([`state.rs:104`](../../../crates/aos-package/src/registry/state.rs)) is reframed
onto semver (becoming `check_floor`, §7.1), and the **gating bug** at
[`update.rs:290-291`](../../../crates/aos-package/src/update.rs) is fixed:

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

The existing `check_monotonic` tests in `state.rs`
(`check_monotonic_succeeds_when_newer`, `check_monotonic_fails_when_equal`,
`check_monotonic_fails_when_older`,
[`state.rs:255-274`](../../../crates/aos-package/src/registry/state.rs)) are
replaced by semver equivalents on `check_floor`: `#[test] fn
test_check_floor_allows_equal_or_newer` (`1.4.2 >= 1.4.2`, `1.4.3 >= 1.4.2`),
`#[test] fn test_check_floor_rejects_older` (`1.4.1 < 1.4.2` → `Err`), and
`#[test] fn test_check_floor_allows_when_no_floor` (`None` floor → first sync
proceeds). The `token_*` round-trip tests
([`state.rs:196-252`](../../../crates/aos-package/src/registry/state.rs)) are
deleted with `version_to_token`/`token_to_version`.

### 7.3 Interaction with rollout & fix-forward

- A consumer that already advanced to `1.4.2` has `floor = 1.4.2`. If the
  publisher *decrements* its partition back to `1.4.1` (bad idea), the consumer
  **refuses** — the floor blocks it.
- The correct abort is **fix-forward**: publish `1.4.3` (the revert-as-new-
  release) and advance partitions to it; `1.4.3 >= floor`, so consumers adopt it.
- Rollout gates **adoption order**, the floor gates **direction**; the two are
  orthogonal and both fail-closed.

### 7.4 Freshness (no in-band `valid_until`)

There is **no** in-band signed `valid_until` expiry — signed tags carry no
structured payload (§6.2). Freshness is instead the combination of:

- a **low CDN TTL** on the mutable surface (`/channels`, `info/refs`,
  `objects/info`), so a host re-reads the publisher's current pointer quickly;
- the consumer's own **max-staleness policy** (how long it tolerates not having
  re-resolved); and
- the monotonic **anti-rollback floor** (§7.1), which prevents moving backward.

**Trade-off.** This is *weaker* than an in-band signed expiry against a
**frozen-but-validly-signed mirror**: a mirror that serves an old, correctly
signed `/channels` pointer cannot be detected by signature alone, since the tag
has no embedded expiry. The low CDN TTL + max-staleness policy bound the staleness
window operationally rather than cryptographically.

---

## 8. Nix binary-cache superset wiring (committed `[[caches]]` + client override)

> **TARGET.** Per [brief §13](./design-brief.md#13-nix-binary-cache-superset)
> and [§14](./design-brief.md#14-tag-payload-repo-tree-config--trust-files): the
> NAR substituter location lives in the **committed git-repo-root
> `registry.toml` `[[caches]]`** — a tree file authenticated transitively by the
> signed tag (tag → commit → tree → file), **not** advertised in the tag itself.
> Signed tags are pure signed pointers and carry no `[[caches]]` entry, no `url`,
> and no structured payload (§6.2). The consumer's client-side
> `registries.d/<name>.toml` is an **optional override/supplement** (higher
> priority wins). The consumer registers the resolved substituter(s) for NAR
> substitution.

### 8.1 Where the substituter location comes from

The substituter is **not** discovered from the verified tag — there is no
tag-embedded `[[caches]]`. It is read from the **committed `registry.toml`
`[[caches]]`** in the resolved tree, optionally overridden client-side:

```toml
# registry.toml  (git-repo-ROOT, a COMMITTED TREE FILE in the resolved commit;
#  authenticated via the signed tag — see repo-layout.md)
[registry]
name        = "aos-core"
description = "AOS core packages"

[[caches]]
url      = "https://cache.aos.dev"   # absolute, OR relative (e.g. "./nar") = same origin
priority = 1000                      # HIGHER wins (resolve_mirrors sorts descending)

[[caches]]
url      = "./nar"
priority = 100                       # fallback
```

```toml
# registries.d/<name>.toml  →  [registry]   (CLIENT-SIDE override/supplement; OPTIONAL)
[registry]
origin     = "https://registry.aos.dev/core/"
# optional explicit substituter(s) that override/supplement the committed [[caches]]:
cache_url  = "./nar"        # relative to origin, OR absolute
```

- **Committed `[[caches]]`** in the git-repo-root `registry.toml` (the existing
  `RegistryRootConfig.caches`,
  [`types.rs:563-570`](../../../crates/aos-package/src/types.rs); the `caches`
  field at [`types.rs:567`](../../../crates/aos-package/src/types.rs)) is the
  **primary** source — authenticated via the tag (tag → commit → tree → file), so
  it is signed-by-extension without anything being placed in the tag. The
  `[[caches]]` entries are `CacheEntry { url: String, priority: u32 }`
  ([`types.rs:581-590`](../../../crates/aos-package/src/types.rs)); `resolve_mirrors`
  ([`registry_ops.rs:405`](../../../crates/aos-package/src/registry_ops.rs)) sorts
  **descending** (higher `priority` preferred,
  [`registry_ops.rs:409`](../../../crates/aos-package/src/registry_ops.rs)) and is
  reused unchanged. See [`repo-layout.md`](../../registry/repo-layout.md) §2 for
  the committed-tree shape.
- **Client-side `registries.d/<name>.toml`** is an **optional override/
  supplement** — when present it takes precedence (higher priority wins), letting
  an operator pin a local mirror without re-publishing the tree.
- **The origin itself** — the origin MAY serve the standard Nix binary-cache
  surface (`nix-cache-info`, `<storehash>.narinfo`, `nar/`) as a superset for
  stock `nix`, so a relative `[[caches]]` `url`/`cache_url` (or an omitted one)
  resolves straight to the origin.

Tags are pure signed pointers (§6.2): the consumer reads no `[[caches]]` entry
or any other structured payload out of a tag object — the `[[caches]]` it honours
is the one **inside the committed tree**, not the tag.

> **NAR safety.** An authenticated-but-wrong cache pointer **cannot** serve bad
> bytes: NARs are content-addressed and SHA-256-verified on download. This is
> already enforced in `download::download_one`
> ([`download.rs:177-204`](../../../crates/aos-package/src/download.rs)), which
> derives the authoritative `file_hash`
> ([`download.rs:191-201`](../../../crates/aos-package/src/download.rs)) and
> pins it on the transfer via
> `TransferRequest::get(&url).with_hash(HashAlgorithm::Sha256, expected_hex)`
> ([`download.rs:203-204`](../../../crates/aos-package/src/download.rs)) — distinct
> from the plain narinfo GET in `fetch_one_narinfo`
> ([`download.rs:154`](../../../crates/aos-package/src/download.rs)), which does no
> content check. (See also [`repo-layout.md`](../../registry/repo-layout.md) §3.)
> The trust that matters is the **tag/commit chain** (governed by `keys.toml`,
> §6), not the cache list — so the `[[caches]]` pointer needs only
> integrity-by-extension, which the signed tree already gives it.

### 8.2 Relative-URL resolution

A relative cache `url` — whether from the committed `[[caches]]` or a client-side
`cache_url` — is resolved against the **registry origin** (the base URL the
partition/releases was fetched from):

```text
registry origin:  https://registry.aos.dev/core/
cache_url:        "./nar"
resolved cache:   https://registry.aos.dev/core/nar/
                      ├─ nix-cache-info
                      ├─ <storehash>.narinfo
                      └─ nar/<...>.nar[.zst]
```

An absolute `cache_url` (`https://cache.example/…`) is used verbatim. The
resolved cache (or the origin) exposes the standard Nix binary-cache surface
(`nix-cache-info`, `<storehash>.narinfo`, `nar/`) — a strict superset for stock
`nix` dev-shell substitution. narinfo `Sig:` (if served) reuses the **one**
Ed25519 key ([brief §11](./design-brief.md#11-signing--trust),
[`nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md)).

### 8.3 Consumer responsibilities

| Step | Action |
|---|---|
| Read config | Read `[[caches]]` from the **committed** git-repo-root `registry.toml` in the resolved tree (primary); merge any client-side `registries.d/<name>.toml` override/supplement; otherwise default to the origin as the cache. |
| Resolve | Resolve a relative cache `url` (committed or client-side) against the origin (§8.2). |
| Register | Wire the resolved cache(s) into the substituter set, ordered by `priority` (HIGHER wins; client-side override takes precedence). |
| Substitute | NAR substitution then proceeds through the standard Nix path — orthogonal to the git-object metadata layer; a wrong pointer can't serve bad bytes (NARs are SHA-256-verified). |

The cache mechanism is **orthogonal** to git-object fetch: the git layer delivers
package metadata (the `packages/` tree); the binary-cache layer delivers build
artifacts (NARs). A consumer that only needs metadata can ignore the cache; one
doing substitution reads the committed `registry.toml` `[[caches]]` (with any
client-side override). Even so, a wrong cache pointer is harmless — NARs are
content-addressed and SHA-256-verified (§8 NAR-safety note).

The existing `resolve_mirror(registry: &RegistryConfig) -> String`
([`download.rs:85`](../../../crates/aos-package/src/download.rs)) already reads the
locally-cloned `registry.toml` `[[caches]]` via `resolve_mirrors`
([`registry_ops.rs:405`](../../../crates/aos-package/src/registry_ops.rs)) and
falls back to `registry.url`; WS-05 extends it to (a) source the committed
`registry.toml` from the **resolved tree** rather than only the on-disk clone,
(b) merge a client-side `registries.d/<name>.toml` `cache_url` override at higher
priority, and (c) resolve a relative `url`/`cache_url` against the origin (§8.2)
via `join_cache_url` ([`download.rs:65`](../../../crates/aos-package/src/download.rs)).
The existing `resolve_mirror_strips_trailing_slash` test
([`download.rs:392`](../../../crates/aos-package/src/download.rs)) stays valid; add
`#[test] fn test_resolve_mirror_client_override_wins` and `#[test] fn
test_resolve_mirror_relative_url_against_origin`.

---

## 9. Mapping CURRENT code → TARGET behaviour

| CURRENT (`path:line`) | TARGET replacement | Notes |
|---|---|---|
| `sync_bundle` ([`update.rs:209`](../../../crates/aos-package/src/update.rs)) | git-native resolve+fetch (§3) | drops bundle manifest fetch |
| `pick_bundles` ([`update.rs:319`](../../../crates/aos-package/src/update.rs)) | `resolve_objects` delta-walk (§5.2) | bundle → thin `delta-*.pack`; token → semver+ancestry |
| `BundleManifest::fetch` ([`update.rs:220-221`](../../../crates/aos-package/src/update.rs)) | `info/refs` + `info/alternates` reads (§3.2) | manifest → git object store |
| `bundle::unbundle` / `bundle::resolve_tag` ([`update.rs:257`,`:266`](../../../crates/aos-package/src/update.rs)) | `index-pack --fix-thin` + tag-chain resolve (§5.3, §6) | bundles → thin packs + signed tags |
| `check_monotonic` + gating ([`state.rs:104`](../../../crates/aos-package/src/registry/state.rs), [`update.rs:290-291`](../../../crates/aos-package/src/update.rs)) | unconditional semver `check_floor` (§7.2) | fixes gating bug; deletes token math |
| `version_to_token`/`token_to_version` ([`state.rs:131`,`:173`](../../../crates/aos-package/src/registry/state.rs)) | **deleted** (§15) | calendar scheme removed |
| `RegistryState.last_creation_token` ([`types.rs:256`](../../../crates/aos-package/src/types.rs)) | `floor` (semver) + `bucket` + `retained` (§3.5) | state schema change |
| `TrackingMode` (no `Channel`) ([`types.rs:279`](../../../crates/aos-package/src/types.rs)) | add `Channel(String)` → bucket → partition tag (§4, §3.3) | new resolution arm |
| `extract_packages_from_git` ([`update.rs:496`](../../../crates/aos-package/src/update.rs)) | **reused** | `git archive <commit> packages/` is unchanged |

---

## 10. Task checklist

**State & config:**

- [ ] Replace `RegistryState.last_creation_token`
      ([`types.rs:256`](../../../crates/aos-package/src/types.rs)) with `floor:
      Option<String>` (semver); add `bucket: Option<u8>` and `retained:
      Vec<String>`.
- [ ] Extend `state::save_state`
      ([`state.rs:43-51`](../../../crates/aos-package/src/registry/state.rs)) to
      serialize the new fields; drop `last_creation_token`.
- [ ] Delete `version_to_token`/`token_to_version`/`check_monotonic`
      ([`state.rs:104`,`:131`,`:173`](../../../crates/aos-package/src/registry/state.rs)),
      replace with `check_floor` (semver `Version` comparator, §7.1).

**Resolution:**

- [ ] Bucket selection `the low byte of sha256(machine_id) (i.e. mod 256)`, persist once (§4); hex render
      each byte as two hex digits `00..ff`; probe-forward `(bucket+i) mod 256` (§4.3).
- [ ] Add `TrackingMode::Channel(String)`
      ([`types.rs:279`](../../../crates/aos-package/src/types.rs); also extend the
      `Display` impl at [`types.rs:292`](../../../crates/aos-package/src/types.rs))
      and a `channel` config field threaded into `tracking_mode()`
      ([`types.rs:349`](../../../crates/aos-package/src/types.rs)).
- [ ] Tag-chain resolver `/channels/<name>/<bucket>` → semver tag → commit (§3.3).

**Verification:**

- [ ] `git verify-tag`-style Ed25519 check on each tag object + name-binding
      string comparison (§6); reuse `security.rs` primitives.
- [ ] Read the committed `keys.toml` trust roster from the resolved tree; honour
      active keys (`id` + `key`, no role field) + `revoked`; bootstrap-trust via
      client-side TOFU `trusted-keys.d/<registry>.pub` pin; follow overlap
      rotation + planned retirement; handle compromise out-of-band (re-pin) (§6.3).
- [ ] Fail-closed ordering: verify chain *before* fetching objects (§6.4).

**Fetch:**

- [ ] `resolve_objects` delta-walk: retained-base delta → backward walk → full
      pack → loose objects (§5.2).
- [ ] `git index-pack --fix-thin` for thin packs; `zstd -d --long=27` for
      `.pack.zst` (§5.3).
- [ ] Retention set `{X.0.0, X.Y.0, X.Y.Z}`; prune + persist (§5.4).

**Anti-rollback:**

- [ ] Unconditional semver floor check before fetch; fix the
      [`update.rs:290-291`](../../../crates/aos-package/src/update.rs) gating bug
      (§7.2).

**Nix cache:**

- [ ] Read `[[caches]]` from the **committed** git-repo-root `registry.toml` in
      the resolved tree (primary); merge any **client-side** `registries.d` override
      (higher `priority` wins; default: the origin); resolve relative `url`s
      against origin; register substituters by `priority` (§8). No tag-embedded
      `[[caches]]` is parsed.

---

## 11. Cross-references

### Reference set (`docs/registry/`, TARGET state)

- [README.md](../../registry/README.md) — purpose, glossary, doc index.
- [architecture.md](../../registry/architecture.md) — git-over-dumb-HTTP, the
  three ref layers, how `apm` and stock git both consume.
- [current-state.md](../../registry/current-state.md) — the as-is bundle /
  `creation_token` implementation this WS replaces.
- [http-layout.md](../../registry/http-layout.md) — the static surface the
  consumer reads (`/channels`, `/releases`, relative `info/alternates`, root
  `/objects/` loose objects).
- [repo-layout.md](../../registry/repo-layout.md) — the committed git **tree**
  the consumer reconstructs after fetch: `registry.toml` `[[caches]]`,
  `keys.toml` trust roster, `packages/`, `closures/` (distinct from the served
  object store).
- [versioning-and-channels.md](../../registry/versioning-and-channels.md) —
  semver, 256-partition rollout, bucket selection, anti-rollback.
- [packs-and-deltas.md](../../registry/packs-and-deltas.md) — the delta scheme
  graph, client resolution + retention, `index-pack --fix-thin`, zstd.
- [signing-and-trust.md](../../registry/signing-and-trust.md) — signed tag
  objects (pure signed pointers), name-binding, `tag→tag→commit`, anti-rollback.
- [publishing.md](../../registry/publishing.md) — the producer pipeline that
  emits the surface this consumer reads.
- [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) — the
  Nix binary-cache superset via client-side substituter config / the origin.
- [apt-comparison.md](../../registry/apt-comparison.md) — phased-rollout /
  pdiff → 256-partition / thin-delta lineage.

### Plan set (`docs/plans/registry/`)

- [design-brief.md](./design-brief.md) — §6, §9, §11, §13 (authoritative intent).
- [README.md](./README.md) — milestone roadmap and sequencing.
- [gap-analysis.md](./gap-analysis.md) — current vs target gap map.
- [workstream-01-object-store.md](./workstream-01-object-store.md) — the root
  `/objects/` store + relative `info/alternates` the consumer fetches from.
- [workstream-02-pack-delta-pipeline.md](./workstream-02-pack-delta-pipeline.md)
  — the thin/full pack + zstd artifacts the consumer applies.
- [workstream-03-channels-rollouts.md](./workstream-03-channels-rollouts.md) —
  the 256 signed partition tags + frontier branch the consumer resolves.
- [workstream-04-signing-trust.md](./workstream-04-signing-trust.md) — the signed
  tag objects + name-binding the consumer verifies.
- [open-questions.md](./open-questions.md) — machine-id source / probe-forward
  order (§16.3), the `check_monotonic` gating bug, retained-set sizing.
