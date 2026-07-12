# RFC-0007 P2 — Demotion / size-pressure engine: executor brief

> Hand-off brief for the multi-location **demotion** engine (task #18 item 1, doc
> 29 §5.7). Recon + the confirmed victim-selection model + a tested selection
> algorithm are captured here so a fresh-context agent can implement the executor
> without re-deriving anything. **No demotion code is landed yet** — see §7 for
> why the "planning half" turned out to need new read-path machinery this brief
> specifies. Author: the front-end/speculation agent, after closing task #3.
>
> **Resolved (lead ruling 2026-07-12, §6 closed).** The demotion unit is the
> **root-instantiation record** (`PersistRootRecordKey`), not a blob-pack record.
> The multi-location tier machinery (`locations.rs`) moves *only* root records:
> `load_root_instantiation` probes primary→secondaries and `promote_root_instantiation`
> copies one UP; demotion is the exact mirror, copying one DOWN via
> `secondary.store_root_instantiation`. No blob-pack record is ever probed or moved
> across locations, and **unrooted blob-pack records are garbage for repack to
> reclaim — never demotion candidates** (demoting one to a secondary is strictly
> worse than deleting it: nothing roots it there, so it is never probed).
>
> The earlier "rooted records are NEVER demoted / only unrooted records move down"
> rule is **RETRACTED**: it conflated blob-reachability rootedness with the tiered
> root-record entity, and read literally it gives L2 demotion zero victims (root
> records are the only demotable population) and nullifies the doc 29 §5.4/§5.6
> feature. Confirmed semantics (doc 29 §5.4/§5.6): under size pressure, demote the
> **coldest** root records (`resident_bytes` DESC, recency ASC — largest+oldest
> first); demotion is a **move**, not a delete; a demoted root **re-promotes on its
> next hit** via `promote_root_instantiation`. The warm path degrades gracefully — a
> demoted root's next hit pays one slower-class probe (still a cache hit), then
> promotes back — rather than being lost, which is the concern the retracted rule
> was protecting.

## 1. Confirmed victim-selection model

Doc 29 §5.7 scores placement by **value density** = `est_recompute / entry_bytes`
(recompute cost bought per byte held), *not* recency — and there is no LRU in the
design or in the index. But the per-record static `est_recompute` is **not
persisted** today, so the §5.7-faithful policy cannot drive demotion yet.

**Ruled interim policy (implement this):** victim order =
1. **UNROOTED only** (rooted excluded upstream).
2. within unrooted, sort by `(resident_bytes DESC, mtime ASC)` — **largest-oldest
   first**. Size-greedy is the cheap approximation of §5.7's denominator (maximum
   pressure relief per record moved); mtime is the cold-record tiebreak.
3. select the minimal prefix whose cumulative `resident_bytes` reaches
   `bytes_to_free`.

**§5.7-faithful follow-up (record the intent, do not build yet):** persist the
`est_recompute` static cost per record (wire the ratchet-jit static cost estimator
into persist records) and demote *lowest value-density* first. Reference §5.7
explicitly in the code so the intent is not lost.

## 2. The selection algorithm (tested — transcribe verbatim)

This compiled and passed 5 unit tests during recon; it is pure and non-flock, so
land it in `maintenance_types.rs` as soon as a caller (planning, §7) consumes it.

```rust
/// One unrooted primary record eligible for demotion under size pressure.
pub struct PersistDemotionCandidate {
    key: PersistRootRecordKey,   // Copy + Ord (format::root_record_index)
    resident_bytes: u64,
    mtime_unix_secs: u64,
}
// new(key, resident_bytes, mtime_unix_secs) + key()/resident_bytes()/mtime_unix_secs()

/// Orders unrooted candidates largest-and-oldest first and returns the prefix
/// relieving `bytes_to_free`. Sorts in place; empty when bytes_to_free == 0.
pub fn select_demotion_victims(
    candidates: &mut [PersistDemotionCandidate],
    bytes_to_free: u64,
) -> &[PersistDemotionCandidate] {
    candidates.sort_unstable_by(|l, r| {
        r.resident_bytes.cmp(&l.resident_bytes)
            .then(l.mtime_unix_secs.cmp(&r.mtime_unix_secs))
            .then(l.key.cmp(&r.key))
    });
    if bytes_to_free == 0 { return &candidates[..0]; }
    let (mut freed, mut count) = (0u64, 0usize);
    for c in candidates.iter() {
        if freed >= bytes_to_free { break; }
        freed = freed.saturating_add(c.resident_bytes);
        count += 1;
    }
    &candidates[..count]
}
```

Policy additions (also tested):
`PersistStorageMaintenancePolicy::with_primary_size_pressure_bytes(u64)` (stores
`Option<u64>`, default `None` = demotion disabled), `primary_size_pressure_bytes()
-> Option<u64>`, and `demotion_bytes_to_free(primary_used_bytes) -> u64`
(= `primary_used_bytes.saturating_sub(bound)`, or 0 when disabled/within bound).

Test cases to keep (all passed): default disabled frees nothing; overshoot math
(600→0, 1000→0, 1500→500); largest-then-oldest ordering incl. the bytes-tie broken
by older mtime; zero target → no victims; target beyond available → all.

## 3. Runner seams (ratchet-oracle/src/cache/persist/cache.rs)

- `plan_storage_maintenance(policy) -> PersistStorageMaintenancePlan` (:508):
  builds the plan from blob-index + blob-pack sub-plans. **Where the demotion plan
  is computed.**
- `maintain_storage(policy) -> PersistStorageMaintenanceOutcome` (:553): matches
  `plan.action()` (Skip / RepairIndexes / RepackBlobs) and runs the op. **Where
  the demote action is dispatched** (report `Skipped { executor-pending }` in the
  planning-only stage; run the executor in the full stage).
- `compact_storage()` (:607), `repack_storage()` (:651): the existing removal /
  reclaim ops. Demotion **reuses** compaction's unrooted-record removal for the
  "remove from primary after copy-down" step — do not write a second removal.
- Promotion mirror to reverse: `locations.rs::promote_root_instantiation` (:270)
  copies a record UP via `primary.store_root_instantiation(...)`. Demotion copies
  DOWN via `secondary.store_root_instantiation(...)` — the same store API on the
  secondary `PersistCache`.

## 4. The missing enumeration (build this — read-only, single-location)

`select_demotion_victims` needs `(key, resident_bytes, mtime_unix_secs, rooted?)`
per primary root record. **No such API exists today** (compaction/repack operate
on blob packs, not root records). Data sources:
- keys/entries: `format/root_record_index.rs::latest_entries` (:326) iterates the
  root-record index; each `PersistRootRecordIndexEntry` points at the `files/`
  blob holding the encoded record payload.
- `resident_bytes`: size of that `files/` blob (+ its closure blobs' marginal
  contribution — decide whether to charge the record its exclusive bytes or the
  files-blob bytes; exclusive is truer to §5.7 but harder; files-blob size is the
  cheap proxy).
- `mtime_unix_secs`: fs mtime of the record's files blob (proxy for recency).
- `rooted?`: **OPEN QUESTION (§6)**.

Enumeration is **read-only on the primary location** — a single-location read
lock, NOT the two-location flock dance. Safe to do in the planning half.

## 5. The executor (the flock-sensitive core)

For each selected victim, in order:
1. **Copy down**: `demotion_target_secondary.store_root_instantiation(key,
   root_bytes, closure, inputs, run_id)` — mirrors `promote_root_instantiation`.
   Choose the demotion target = the next slower opened secondary class
   (nvme→ssd→hdd); if none opened, demotion is a no-op (log + skip).
2. **Verify the copy** landed (re-load from the secondary) before removing from
   the primary — never remove until the down-copy is durable, or a crash between
   the two loses the record (it is advisory, so a lost record is a miss not a
   corruption, but avoid it).
3. **Remove from primary**: reuse the compaction unrooted-record removal path.

### Flock ordering — the deadlock landmine

The campaign discipline is **files → artifacts → root-records** lock order. A
demotion touches **two locations**: it writes the secondary (its own
files→artifacts→root-records chain) and removes from the primary (same chain).
Interleavings that deadlock:
- Acquiring primary and secondary locks in inconsistent order across concurrent
  demotions / a demotion racing a promotion of the same record.
- Holding a primary lock while blocking on a secondary lock that another worker
  holds while blocking on the primary.

**Rule:** never hold a primary write lock across a secondary write acquisition.
Sequence it: (a) read-enumerate primary under a read lock, release; (b) copy-down
to the secondary under the secondary's own lock, release; (c) remove from primary
under the primary write lock, release. Each lock is held for one location's chain
only, released before the next location is touched. This makes the two-location
operation a sequence of single-location locked steps — no nested cross-location
holds, so no cross-location cycle.

## 6. RESOLVED — the victim entity is the root-instantiation record

> Closed 2026-07-12 (see the header amendment): the demotion unit is the
> root-instantiation record; unrooted blob-pack records are repack garbage, never
> demotion candidates. §4 enumerates the primary root-record index (not a new
> blob-pack walk); `resident_bytes` is the record blob + its closure blobs (cheap
> files-blob proxy); recency is the files-pack append offset (packed blobs carry no
> independent fs mtime). The original open-question text is retained below for
> history.

Is a **root-instantiation record** (`PersistRootRecordKey`, the root-cutoff warm
record) ever "unrooted"? The lead's rule says rooted records are never demoted and
back the warm path — and root-instantiation records ARE the warm-path roots. If
**all** root records are rooted, then root-record demotion has **no victims**, and
the demotable "unrooted records" must be a different entity (e.g. unrooted
blob-pack records — cold blobs not reachable from any current root — which the
existing reachability plan already classifies: `maintenance_types.rs`
`unrooted_records() -> &[PersistBlobPackRecord]`, :518). Resolve this with the
persist-campaign author before building §4: **demotion may operate on unrooted
blob-pack records, not root-instantiation records.** If so, the enumeration source
is the reachability plan (already exists), not a new root-record walk, and
`resident_bytes`/`mtime` come from `PersistBlobPackRecord`. This flips §4 from
"build new enumeration" to "reuse `unrooted_records()`" and is likely the intended
design — verify.

## 7. Why nothing is landed yet (the planning-half snag)

The lead's upgraded-(b) plan was: land the planning half (compute the demotion
plan via `select_demotion_victims`, report `Skipped{executor-pending}`) so nothing
is dead and nothing flock-risky lands. Recon found two blockers to a *clean*
planning landing:
1. **No primary-used-bytes signal exists.** The repack plan exposes only
   `reclaimable_bytes()`, not resident total. `demotion_bytes_to_free` needs
   `primary_used_bytes`, which requires a new read path (a directory-size stat of
   the primary root, or a pack-size API).
2. **The victim entity is unresolved (§6)** — building an enumeration before
   resolving root-record-vs-blob-pack-record risks targeting the wrong thing.

So the tested policy API + selection algorithm (§2) are captured here rather than
landed dead/half-wired. First executor step: resolve §6, add the read-only
`primary_used_bytes` measure + enumeration (§4), wire §2 into
`plan_storage_maintenance`, then the executor (§5).

## 8. Acceptance tests

- Unit: the §2 test cases (selection ordering + policy math) — already written.
- Unit: plan reports `demotion_bytes_to_free > 0` when primary exceeds the bound,
  0 when within it or disabled.
- Integration (two-location, the acceptance proof): open a primary + one secondary
  in tempdirs; store N unrooted records into the primary; set a size-pressure bound
  below the primary footprint; run maintenance; assert the largest-oldest unrooted
  victims now load from the secondary AND are gone from the primary, rooted records
  remain in the primary, and a subsequent probe still finds every record
  (promotion of a demoted record back up on hit still works). Inject size pressure
  by a low bound, not by writing gigabytes.
- Gate: cache crate tests + persist/memo suites; parity battery cache-enabled
  (demotion is advisory — `.drv` output must be byte-identical with demotion on
  and off); no new file-size offender.
