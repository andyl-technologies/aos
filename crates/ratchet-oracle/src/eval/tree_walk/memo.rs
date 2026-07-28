//! In-process content-keyed memoization tables (RFC-0007 MEMO-1, L0/L1).
//!
//! This module owns the *storage* for the two in-memory tiers of the tiered
//! content-keyed memoization architecture:
//!
//! - **L0** ([`MemoL0Table`]) — a plain per-worker map with no
//!   synchronization, cleared with the evaluator that owns it;
//! - **L1** ([`SharedMemoTable`]) — a sharded, mutex-guarded map shared by
//!   every worker of one parallel evaluation through the
//!   [`SharedEvalContext`](super::parallel_demand::SharedEvalContext), the
//!   parallel substrate's first shared writable map.
//!
//! Both tiers store the same [`MemoEntry`]: a self-contained replayable
//! payload (the force cache's [`CachedExpressionValue`] encoding — attr names
//! as bytes, no heap handles, no `Symbol` ids) plus the entry's canonicalized
//! impure-observation slice. Because payloads are plain data, entries cross
//! worker threads without any publication protocol beyond the shard mutex,
//! and the L0 table needs no GC-root registration.
//!
//! Keys are [`DemandCacheKey`]s derived per RFC-0007 doc 29 §3: the ordered,
//! length-prefixed combination of a [`CacheExprIdentity`] code component with
//! the captured free-variable [`ValueHash`]es (hot xxh3 probe plus blake3
//! confirmation). Key *derivation* and the force-path probe/record logic live
//! in `eval_core::memo`, which has access to the evaluator internals; this
//! module is deliberately evaluator-free so the table types stay `Send +
//! Sync` and unit-testable in isolation.
//!
//! [`CacheExprIdentity`]: crate::cache::CacheExprIdentity
//! [`ValueHash`]: crate::cache::ValueHash

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use std::sync::Arc;

use crate::cache::{
    CacheExprIdentity, CacheableInputFingerprint, CachedExpressionValue, DemandCacheKey,
};
use crate::eval::EvalNodeRef;

/// Shard count for the L1 shared table.
///
/// Sixteen shards keep worker contention negligible for the K <= 8 worker
/// pools the parallel scheduler currently spawns while bounding per-table
/// fixed cost; probes hash the key's hot component to pick a shard.
const SHARED_MEMO_SHARDS: usize = 16;

/// A per-def-site static admission decision for the content memo.
///
/// Computed once per `(module, node)` def-site and cached on the evaluator so
/// non-admitted def-sites pay exactly one map probe per force. Admission
/// requires a stable expression identity (the def-site subtree is
/// force-lookup safe) and a static recompute estimate at or above the
/// configured floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MemoDefSiteDecision {
    /// The def-site is never probed or recorded.
    Skipped,
    /// The def-site cleared the static cost floor; its expression identity
    /// (a full subtree safety walk plus a module content hash) is derived
    /// lazily on the first force whose environment hashes successfully, so
    /// def-sites whose environments never hash never pay identity
    /// derivation.
    CostAdmitted,
    /// The def-site participates in the memo under this stable identity.
    Admitted {
        /// The def-site's stable expression identity (code component).
        identity: CacheExprIdentity,
    },
}

/// Cached per-def-site memo state: the static decision plus the
/// consecutive-decline gate.
///
/// Environment-dependent key derivation (free-variable hashing) runs per
/// force at admitted def-sites and can fail every time when the captured
/// environment is structurally unhashable (closures, open thunks). Such a
/// site would otherwise pay the dependency walk on every force — exactly the
/// per-force tax the admission-flag design exists to avoid — so after enough
/// consecutive derivation declines with no intervening success the site is
/// permanently gated to [`MemoDefSiteDecision::Skipped`], mirroring the
/// tier-1 skipped-def-site precedent.
#[derive(Clone, Copy, Debug)]
pub(super) struct MemoDefSiteState {
    /// The current admission decision.
    pub(super) decision: MemoDefSiteDecision,
    /// Full static subtree cost when economics instrumentation is enabled;
    /// otherwise the admission floor for admitted sites and zero for skips.
    pub(super) static_cost_units: u32,
    /// Consecutive per-force derivation declines since the last success.
    pub(super) consecutive_declines: u32,
}

impl MemoDefSiteState {
    /// Creates the initial state for a freshly decided def-site.
    pub(super) const fn new(decision: MemoDefSiteDecision, static_cost_units: u32) -> Self {
        Self {
            decision,
            static_cost_units,
            consecutive_declines: 0,
        }
    }
}

/// Module-indexed sparse storage for content-memo admission decisions.
///
/// The claimed-force path consults this table for every node thunk while the
/// memo is active. Indexing the module directly and hashing only its `u32` node
/// id avoids hashing [`EvalNodeRef`] millions of times while keeping state
/// sparse for modules whose forced node ids span a large arena range.
#[derive(Debug, Default)]
pub(super) struct MemoDefSiteTable {
    modules: Vec<Option<MemoDefSiteModuleTable>>,
}

impl MemoDefSiteTable {
    /// Returns the state for `def_site`, when the site has been decided.
    pub(super) fn get(&self, def_site: EvalNodeRef) -> Option<&MemoDefSiteState> {
        let module = self.modules.get(def_site.module().index())?.as_ref()?;
        module.get(&def_site.id().as_u32())
    }

    /// Returns mutable state for `def_site`, when the site has been decided.
    pub(super) fn get_mut(&mut self, def_site: EvalNodeRef) -> Option<&mut MemoDefSiteState> {
        let module = self
            .modules
            .get_mut(def_site.module().index())?
            .as_mut()?;
        module.get_mut(&def_site.id().as_u32())
    }

    /// Installs or replaces the decision for `def_site`.
    pub(super) fn insert(&mut self, def_site: EvalNodeRef, state: MemoDefSiteState) -> bool {
        let module_index = def_site.module().index();
        if self.modules.len() <= module_index {
            self.modules.resize_with(module_index + 1, || None);
        }
        let module = self.modules[module_index].get_or_insert_with(MemoDefSiteModuleTable::default);
        module.insert(def_site.id().as_u32(), state);
        true
    }
}

/// One module's admission decisions keyed by its local IR node id.
type MemoDefSiteModuleTable =
    HashMap<u32, MemoDefSiteState, BuildHasherDefault<MemoNodeIdHasher>>;

/// Fast integer mixer for module-local IR node ids.
///
/// The table's key type is exactly `u32`, so the specialized `write_u32` path
/// handles every production lookup. `write` remains a complete fallback for
/// the [`Hasher`] contract and for diagnostic tooling.
#[derive(Debug, Default)]
struct MemoNodeIdHasher(u64);

impl Hasher for MemoNodeIdHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.0 = hash;
    }

    fn write_u32(&mut self, value: u32) {
        let mixed = u64::from(value).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.0 = mixed ^ (mixed >> 32);
    }
}

/// One memoized forced-subtree record shared by the L0 and L1 tiers.
///
/// The payload is the force cache's self-contained replayable encoding; the
/// slice is the entry's canonicalized per-subtree impure-observation trace
/// (empty for pure subtrees). A hit must revalidate every slice entry against
/// the current world before the payload may be replayed.
#[derive(Clone, Debug)]
pub(super) struct MemoEntry {
    /// Replayable canonical payload for the memoized forced value.
    pub(super) payload: Arc<CachedExpressionValue>,
    /// Canonicalized impure-observation slice attributed to the subtree.
    pub(super) slice: Arc<[CacheableInputFingerprint]>,
}

impl MemoEntry {
    /// Returns the serialized-size estimate used for byte budgeting.
    fn payload_bytes_estimate(&self) -> u64 {
        let len = self.payload.persistent_payload_len();
        if len > u128::from(u64::MAX) {
            u64::MAX
        } else {
            len as u64
        }
    }
}

/// One admitted-key observation returned by the potential-hit census.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MemoPotentialObservation {
    /// Whether this is the key's first occurrence.
    pub(super) unique_key: bool,
    /// Whether this occurrence makes the key repeated for the first time.
    pub(super) first_hit_for_key: bool,
    /// Whether an already-built table could have answered this occurrence.
    pub(super) potential_hit: bool,
}

/// Shared admitted-key census used only by `AOS_NIX_MEMO_STATS`.
///
/// The table exists independently of L0/L1, so a stats-only run measures the
/// duplicate `(code, environment)` opportunity before building replay tables.
/// One mutex makes the census global across parallel workers; it is acceptable
/// only because the explicit stats knob already opts into instrumentation tax.
#[derive(Debug, Default)]
pub(super) struct MemoEconomicsCensus {
    occurrences: Mutex<HashMap<DemandCacheKey, u64>>,
}

impl MemoEconomicsCensus {
    /// Records one successfully derived admitted key.
    pub(super) fn observe(&self, key: DemandCacheKey) -> MemoPotentialObservation {
        let mut occurrences = match self.occurrences.lock() {
            Ok(occurrences) => occurrences,
            Err(poisoned) => poisoned.into_inner(),
        };
        let seen = occurrences.entry(key).or_insert(0);
        let observation = MemoPotentialObservation {
            unique_key: *seen == 0,
            first_hit_for_key: *seen == 1,
            potential_hit: *seen > 0,
        };
        *seen = seen.saturating_add(1);
        observation
    }
}

/// The per-worker in-thread memo tier (L0).
///
/// A plain hash map probed by the key's hot xxh3 component and confirmed by
/// its blake3 confirmation digest (both inside [`DemandCacheKey`] equality).
/// Bounded by entry count: at capacity, new admissions are declined rather
/// than evicted, which keeps insertion O(1) and makes the cap observable in
/// the decline counters.
#[derive(Debug)]
pub(super) struct MemoL0Table {
    entries: HashMap<DemandCacheKey, MemoEntry>,
    capacity: usize,
}

impl MemoL0Table {
    /// Creates an empty table admitting at most `capacity` entries.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
        }
    }

    /// Returns the entry recorded under `key`, if any.
    pub(super) fn get(&self, key: &DemandCacheKey) -> Option<&MemoEntry> {
        self.entries.get(key)
    }

    /// Removes an entry whose slice failed revalidation.
    pub(super) fn remove(&mut self, key: &DemandCacheKey) {
        self.entries.remove(key);
    }

    /// Inserts `entry` under `key`, returning whether it was admitted.
    ///
    /// Returns `false` (and leaves the table unchanged) when the table is at
    /// capacity and `key` is not already present.
    pub(super) fn insert(&mut self, key: DemandCacheKey, entry: MemoEntry) -> bool {
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&key) {
            return false;
        }
        self.entries.insert(key, entry);
        true
    }

    /// Returns the number of resident entries.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns every resident key, for tests.
    #[cfg(test)]
    pub(super) fn keys(&self) -> Vec<DemandCacheKey> {
        self.entries.keys().copied().collect()
    }
}

/// One L1 shard entry: the record plus its per-eval hit count.
#[derive(Debug)]
struct SharedMemoSlot {
    entry: MemoEntry,
    hits: u32,
}

/// The in-process shared memo tier (L1) for one parallel evaluation.
///
/// A sharded, mutex-guarded map: probes lock exactly one shard (never a
/// global lock on the force path), and publication is first-write-wins so
/// duplicate concurrent recording of one key is benign. Payloads are
/// self-contained plain data, so a worker may replay an entry another worker
/// recorded with no cross-shard heap publication protocol; the shard mutex's
/// release/acquire edge orders the entry bytes themselves.
///
/// Bounded by a retained-bytes budget over the payload-size estimates; at
/// budget, new publications are declined rather than evicted.
#[derive(Debug)]
pub(super) struct SharedMemoTable {
    shards: Vec<Mutex<HashMap<DemandCacheKey, SharedMemoSlot>>>,
    retained_bytes: AtomicU64,
    byte_budget: u64,
}

impl SharedMemoTable {
    /// Creates an empty shared table with the given retained-bytes budget.
    pub(super) fn new(byte_budget: u64) -> Self {
        let mut shards = Vec::with_capacity(SHARED_MEMO_SHARDS);
        for _ in 0..SHARED_MEMO_SHARDS {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self {
            shards,
            retained_bytes: AtomicU64::new(0),
            byte_budget,
        }
    }

    fn shard(&self, key: &DemandCacheKey) -> &Mutex<HashMap<DemandCacheKey, SharedMemoSlot>> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        let index = (hasher.finish() as usize) % self.shards.len();
        // Index is always in range by construction of the modulo above.
        &self.shards[index]
    }

    /// Returns the entry recorded under `key` plus its post-probe hit count.
    ///
    /// The hit count feeds the promote-to-L0 policy; it counts probes that
    /// found the entry, not probes whose slice later revalidated.
    pub(super) fn get_and_count_hit(&self, key: &DemandCacheKey) -> Option<(MemoEntry, u32)> {
        let mut shard = match self.shard(key).lock() {
            Ok(shard) => shard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let slot = shard.get_mut(key)?;
        slot.hits = slot.hits.saturating_add(1);
        Some((slot.entry.clone(), slot.hits))
    }

    /// Removes an entry whose slice failed revalidation.
    pub(super) fn remove(&self, key: &DemandCacheKey) {
        let mut shard = match self.shard(key).lock() {
            Ok(shard) => shard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(slot) = shard.remove(key) {
            let bytes = slot.entry.payload_bytes_estimate();
            self.retained_bytes.fetch_sub(bytes, Ordering::Relaxed);
        }
    }

    /// Publishes `entry` under `key`, returning whether it was admitted.
    ///
    /// First-write-wins: an existing entry is kept (the bytes are idempotent
    /// content, so which worker's copy survives is unobservable). Returns
    /// `false` when the retained-bytes budget is exhausted or the key was
    /// already published.
    pub(super) fn publish(&self, key: DemandCacheKey, entry: MemoEntry) -> bool {
        let bytes = entry.payload_bytes_estimate();
        if self
            .retained_bytes
            .load(Ordering::Relaxed)
            .saturating_add(bytes)
            > self.byte_budget
        {
            return false;
        }
        let mut shard = match self.shard(&key).lock() {
            Ok(shard) => shard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if shard.contains_key(&key) {
            return false;
        }
        shard.insert(key, SharedMemoSlot { entry, hits: 0 });
        self.retained_bytes.fetch_add(bytes, Ordering::Relaxed);
        true
    }
}

// The L1 table crosses worker threads through `SharedEvalContext`; assert the
// bound here so a payload-representation change that breaks `Send + Sync`
// fails at this line instead of at the distant context field.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SharedMemoTable>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{DurableBlake3Hash, ValueHash};

    fn key(seed: u8) -> DemandCacheKey {
        let identity = CacheExprIdentity::new(
            crate::cache::hashing::CacheExprSourceHash::from_persisted_hash(
                DurableBlake3Hash::for_bytes(&[seed]),
            ),
            crate::compile::IrId::new(0),
        );
        DemandCacheKey::for_free_vars(
            identity,
            [ValueHash::from_canonical_value_hash(
                DurableBlake3Hash::for_bytes(&[seed, 1]),
            )],
        )
        .expect("key builds")
    }

    fn entry() -> MemoEntry {
        MemoEntry {
            payload: Arc::new(CachedExpressionValue::context_free_string(b"x".to_vec())),
            slice: Arc::from(Vec::new()),
        }
    }

    #[test]
    fn def_site_table_indexes_sparse_modules_and_replaces_states() {
        let mut table = MemoDefSiteTable::default();
        let first = EvalNodeRef::new(
            crate::eval::EvalModuleId::new(3),
            crate::compile::IrId::new(17),
        );
        let second = EvalNodeRef::new(
            crate::eval::EvalModuleId::new(9),
            crate::compile::IrId::new(2),
        );

        assert!(table.get(first).is_none());
        assert!(table.insert(
            first,
            MemoDefSiteState::new(MemoDefSiteDecision::Skipped, 0)
        ));
        assert!(table.insert(
            second,
            MemoDefSiteState::new(MemoDefSiteDecision::CostAdmitted, 64)
        ));
        assert_eq!(
            table.get(first).map(|state| state.decision),
            Some(MemoDefSiteDecision::Skipped)
        );
        assert_eq!(
            table.get(second).map(|state| state.static_cost_units),
            Some(64)
        );

        assert!(table.insert(
            first,
            MemoDefSiteState::new(MemoDefSiteDecision::CostAdmitted, 16)
        ));
        assert_eq!(
            table.get(first).map(|state| state.decision),
            Some(MemoDefSiteDecision::CostAdmitted)
        );
        assert_eq!(table.get(first).map(|state| state.static_cost_units), Some(16));
    }

    #[test]
    fn l0_capacity_declines_new_keys_but_replaces_existing() {
        let mut table = MemoL0Table::new(1);
        assert!(table.insert(key(1), entry()));
        assert!(!table.insert(key(2), entry()), "table is at capacity");
        assert!(table.insert(key(1), entry()), "existing keys replace");
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn shared_table_publish_is_first_write_wins_and_counts_hits() {
        let table = SharedMemoTable::new(u64::MAX);
        assert!(table.publish(key(1), entry()));
        assert!(!table.publish(key(1), entry()), "second publish declines");
        let (_, hits) = table.get_and_count_hit(&key(1)).expect("entry exists");
        assert_eq!(hits, 1);
        let (_, hits) = table.get_and_count_hit(&key(1)).expect("entry exists");
        assert_eq!(hits, 2);
        assert!(table.get_and_count_hit(&key(2)).is_none());
    }

    #[test]
    fn shared_table_byte_budget_declines_publication() {
        let table = SharedMemoTable::new(0);
        assert!(!table.publish(key(1), entry()));
        table.remove(&key(1));
    }

    #[test]
    fn economics_census_distinguishes_unique_keys_and_repeat_mass() {
        let census = MemoEconomicsCensus::default();

        assert_eq!(
            census.observe(key(1)),
            MemoPotentialObservation {
                unique_key: true,
                first_hit_for_key: false,
                potential_hit: false,
            }
        );
        assert_eq!(
            census.observe(key(1)),
            MemoPotentialObservation {
                unique_key: false,
                first_hit_for_key: true,
                potential_hit: true,
            }
        );
        assert!(census.observe(key(1)).potential_hit);
        assert!(census.observe(key(2)).unique_key);
    }
}
