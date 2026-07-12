//! Per-worker identity-keyed cache of force-cache payloads for heap aggregates.
//!
//! When the persistent force-cache is active every forced value is *observed*:
//! [`TreeWalk::force_cache_payload_for_value`](super::TreeWalk) walks the value,
//! builds a [`CachedExpressionValue`] payload, and BLAKE3-hashes it. On a
//! nixpkgs-shaped evaluation the same heap aggregate — a shared `stdenv`
//! attrset, a `lib` sub-tree — is reachable from many observed roots, so the
//! recursive encode re-walks and re-hashes identical substructure on every
//! reach. This memo caches the finished payload keyed by the aggregate's heap
//! address, turning the second and later encodes of one address into a clone of
//! the cached payload (skipping the heap walk, symbol resolution, and BLAKE3).
//!
//! # Soundness — heap-address keying under Tier-A
//!
//! The key is [`Value::address_identity_bits`], the aggregate's raw heap
//! address. This is only sound because, under the default Tier-A one-shot
//! arena, a `List`/`Attrs`/`String`/`Path` value routes to
//! `HeapGeneration::Permanent` and is **never reclaimed or moved within an
//! evaluation** (the permanent lanes grow monotonically; only the poppable
//! worker-closure lane is ever rewound, and lists/attrs never live there).
//! Two forces that see the same address therefore see byte-identical heap
//! contents, so the memoized payload equals a fresh encode.
//!
//! This memo caches **only** `List` and `Attrs` values — the recursive,
//! re-walked aggregates. Scalars (`Int`/`Bool`/`String`/`Path`) are cheap to
//! re-encode and thunks are excluded because their identity is force-state
//! dependent.
//!
//! ## B2 relocation hazard (post-S4)
//!
//! [`Value::address_identity_bits`] explicitly forbids retaining its result
//! across a moving-collector safepoint. The future Tier-B B2 copying collector
//! (gated, post-S4) is the only thing that ever moves these aggregates; if it
//! lands, this memo **must** be invalidated on every moving safepoint or keyed
//! on a relocation-stable identity instead. The run-boundary [`Self::clear`]
//! bounds staleness to one evaluation run; the debug re-encode-compare guard in
//! `force_cache_payload_for_value_with_depth` catches any address aliasing that
//! slips past that assumption during tests.

use super::*;

/// Default retained-bytes budget for the observe payload memo (64 MiB).
///
/// Overridable through the `AOS_NIX_OBSERVE_MEMO_BYTES` environment variable.
/// A value of `0` disables the memo entirely.
const DEFAULT_OBSERVE_MEMO_BUDGET_BYTES: u64 = 64 * 1024 * 1024;

/// Returns whether the memo is opted in through `AOS_NIX_OBSERVE_MEMO`.
///
/// **Default off.** The A/B (RFC-0007 persist-write-batching-plan §9) measured
/// the memo at roughly noise level (~2-4% of cold cache-population), because the
/// dominant cache-on cost is the synchronous persist write-through, not the
/// observe encode this memo dedups. It stays off until §3.2 write-behind removes
/// the write floor and re-measurement shows a decisive win, mirroring the
/// simplifier passes' default-off discipline.
fn observe_memo_enabled() -> bool {
    matches!(
        std::env::var("AOS_NIX_OBSERVE_MEMO").ok().as_deref(),
        Some("1") | Some("true") | Some("on") | Some("yes")
    )
}

/// Reads the configured retained-bytes budget from the environment once.
fn configured_budget_bytes() -> u64 {
    match std::env::var("AOS_NIX_OBSERVE_MEMO_BYTES") {
        Ok(raw) => raw.trim().parse().unwrap_or(DEFAULT_OBSERVE_MEMO_BUDGET_BYTES),
        Err(_) => DEFAULT_OBSERVE_MEMO_BUDGET_BYTES,
    }
}

/// Identity-keyed cache of finished force-cache payloads for heap aggregates.
///
/// Lives behind a [`RefCell`](std::cell::RefCell) on each worker's
/// [`TreeWalk`](super::TreeWalk) — it is per-worker and never shared across
/// threads, so the payload force path takes no lock. Bounded by a
/// retained-bytes budget: once [`Self::retained_bytes`] would exceed
/// [`Self::budget_bytes`] the memo stops admitting new entries (it never
/// evicts, since a stale entry within one run is still a valid encode).
#[derive(Debug)]
pub(in crate::eval::tree_walk) struct ForcePayloadMemo {
    /// Finished payloads keyed by [`Value::address_identity_bits`].
    entries: std::collections::HashMap<u64, CachedExpressionValue>,
    /// Live payload bytes retained by [`Self::entries`], by
    /// [`CachedExpressionValue::persistent_payload_len`].
    retained_bytes: u64,
    /// Admission ceiling for [`Self::retained_bytes`]; `0` disables the memo.
    budget_bytes: u64,
    /// Whether the enclosing evaluator observes forced values at all.
    ///
    /// Mirrors `TreeWalk::force_cache_active`: when the evaluator performs no
    /// observations the memo is dead weight, so consult/populate short-circuit.
    active: bool,
    /// Suppresses consult/populate while a debug re-encode-compare guard runs.
    ///
    /// The guard re-encodes a hit value through the ordinary force path to
    /// assert equality with the served payload; that recompute must bypass the
    /// memo it is checking, so it toggles this flag around the call.
    bypass: bool,
    /// Cumulative served hits, for the campaign hit-rate report.
    hits: u64,
    /// Cumulative misses (distinct aggregate encodes), for the report.
    misses: u64,
    /// Cumulative admitted payload bytes (monotonic), for the report.
    inserted_bytes: u64,
}

impl ForcePayloadMemo {
    /// Creates an empty memo.
    ///
    /// Active only when the evaluator observes forces
    /// (`force_cache_active`), the memo is opted in through
    /// `AOS_NIX_OBSERVE_MEMO`, and the retained-bytes budget is positive.
    pub(in crate::eval::tree_walk) fn new(force_cache_active: bool) -> Self {
        let budget_bytes = configured_budget_bytes();
        Self {
            entries: std::collections::HashMap::new(),
            retained_bytes: 0,
            budget_bytes,
            active: force_cache_active && observe_memo_enabled() && budget_bytes > 0,
            bypass: false,
            hits: 0,
            misses: 0,
            inserted_bytes: 0,
        }
    }

    /// Returns whether the memo will consult and populate for eligible values.
    ///
    /// False while a debug guard has [bypassed](Self::set_bypass) the memo.
    pub(in crate::eval::tree_walk) fn is_active(&self) -> bool {
        self.active && !self.bypass
    }

    /// Toggles the debug re-encode-compare bypass; see [`Self::bypass`].
    pub(in crate::eval::tree_walk) fn set_bypass(&mut self, on: bool) {
        self.bypass = on;
    }

    /// Returns a clone of the cached payload for `key`, counting the outcome.
    ///
    /// A `Some` result is a hit (the caller skips the recursive encode); `None`
    /// is a miss and the caller must build and then [`Self::insert`] the
    /// payload.
    pub(in crate::eval::tree_walk) fn get(&mut self, key: u64) -> Option<CachedExpressionValue> {
        if !self.active {
            return None;
        }
        match self.entries.get(&key) {
            Some(payload) => {
                self.hits = self.hits.saturating_add(1);
                Some(payload.clone())
            }
            None => {
                self.misses = self.misses.saturating_add(1);
                None
            }
        }
    }

    /// Admits `payload` for `key` if it fits within the retained-bytes budget.
    ///
    /// Silently declines when the entry already exists (a concurrent recursive
    /// reach populated it first) or when admitting it would exceed the budget.
    pub(in crate::eval::tree_walk) fn insert(&mut self, key: u64, payload: &CachedExpressionValue) {
        if !self.active || self.entries.contains_key(&key) {
            return;
        }
        let size = u64::try_from(payload.persistent_payload_len()).unwrap_or(u64::MAX);
        if self.retained_bytes.saturating_add(size) > self.budget_bytes {
            return;
        }
        self.retained_bytes = self.retained_bytes.saturating_add(size);
        self.inserted_bytes = self.inserted_bytes.saturating_add(size);
        self.entries.insert(key, payload.clone());
    }

    /// Drops all entries at an evaluation run boundary, bounding key staleness.
    ///
    /// Cumulative hit/miss/byte counters are preserved for the run-boundary
    /// report; only the live entry table and its [`Self::retained_bytes`] gauge
    /// reset.
    pub(in crate::eval::tree_walk) fn clear(&mut self) {
        self.entries.clear();
        self.retained_bytes = 0;
    }

    /// Live payload bytes retained by the memo, for byte attribution.
    ///
    /// The wiring hook for fv5's memory-campaign retained-bytes counter: once
    /// that counter lands, the snapshot assembly reads this into it so the
    /// memo's footprint shows up in the memory scoreboard.
    #[allow(dead_code)]
    pub(in crate::eval::tree_walk) fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    /// Cumulative served hits, for engagement assertions.
    #[cfg(test)]
    pub(in crate::eval::tree_walk) fn hits(&self) -> u64 {
        self.hits
    }

    /// Force-activates the memo, bypassing the `AOS_NIX_OBSERVE_MEMO` opt-in.
    ///
    /// Tests exercise the default-off memo without mutating process-global
    /// environment, which would race with concurrently running tests.
    #[cfg(test)]
    pub(in crate::eval::tree_walk) fn set_active_for_test(&mut self) {
        self.active = true;
    }

    /// Emits the cumulative hit/miss/byte report as a tracing event.
    ///
    /// A no-op unless the campaign counters recorded any activity, so a
    /// cache-less evaluation stays silent.
    pub(in crate::eval::tree_walk) fn log_report(&self) {
        if self.hits == 0 && self.misses == 0 {
            return;
        }
        tracing::info!(
            target: "aos_nix::cache",
            hits = self.hits,
            misses = self.misses,
            retained_bytes = self.retained_bytes,
            inserted_bytes = self.inserted_bytes,
            budget_bytes = self.budget_bytes,
            "observe payload memo report"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small payload with a strictly positive persistent length.
    fn sample_payload() -> CachedExpressionValue {
        CachedExpressionValue::context_free_string(b"payload".to_vec())
    }

    /// An active memo, independent of the `AOS_NIX_OBSERVE_MEMO` opt-in.
    fn active_memo() -> ForcePayloadMemo {
        let mut memo = ForcePayloadMemo::new(true);
        memo.set_active_for_test();
        memo
    }

    #[test]
    fn inactive_memo_never_serves() {
        let mut memo = ForcePayloadMemo::new(false);
        assert!(!memo.is_active());
        memo.insert(1, &sample_payload());
        assert!(memo.get(1).is_none());
    }

    #[test]
    fn hit_after_insert_then_clear_resets() {
        let mut memo = active_memo();
        assert!(memo.is_active());
        assert!(memo.get(7).is_none(), "first lookup is a miss");
        memo.insert(7, &sample_payload());
        assert!(memo.get(7).is_some(), "second lookup is a hit");
        assert!(memo.retained_bytes() > 0);
        memo.clear();
        assert_eq!(memo.retained_bytes(), 0);
        assert!(memo.get(7).is_none(), "clear drops the entry");
    }

    #[test]
    fn duplicate_insert_does_not_double_count() {
        let mut memo = active_memo();
        let payload = sample_payload();
        memo.insert(3, &payload);
        let retained = memo.retained_bytes();
        memo.insert(3, &payload);
        assert_eq!(memo.retained_bytes(), retained);
    }

    #[test]
    fn budget_declines_admission_that_would_overflow() {
        let payload = sample_payload();
        let size = u64::try_from(payload.persistent_payload_len()).unwrap_or(u64::MAX);
        assert!(size > 0);
        let mut memo = active_memo();
        memo.budget_bytes = size - 1;
        memo.insert(1, &payload);
        assert!(memo.get(1).is_none(), "over-budget admission is declined");
        assert_eq!(memo.retained_bytes(), 0);
    }

    #[test]
    fn bypass_suspends_service_without_dropping_entries() {
        let mut memo = active_memo();
        memo.insert(5, &sample_payload());
        memo.set_bypass(true);
        assert!(!memo.is_active());
        memo.set_bypass(false);
        assert!(memo.is_active());
        assert!(memo.get(5).is_some(), "bypass does not evict");
    }
}
