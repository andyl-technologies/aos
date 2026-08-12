//! Demand-node key-finalize probe (RFC-0007 §P4 cache-tax attribution).
//!
//! The cache-tax campaign found the cache-on cold toplevel spends ~67% of its
//! cycles in BLAKE3, of which ~35.8% is small-key finalizes over the *same*
//! demand-node preimage (source hash + node id + free-var value hashes), keyed
//! at up to three sites per node: the in-memory
//! [`DemandCacheKey`](super::key::DemandCacheKey) free-var confirmation, the
//! durable
//! [`PersistNodeMetadataKey`](super::persist::format::node_metadata::PersistNodeMetadataKey)
//! expression key, and observe-path re-derivations. This probe counts those two
//! finalize classes so a reduction in the *number* of keys hashed per eval can
//! be attributed and measured.
//!
//! The counters are process-wide cumulative relaxed atomics (matching the env
//! apply-probe and [`capture_stats`](crate::eval::env) convention). Each
//! increment is a single relaxed add, dwarfed by the BLAKE3 finalize it
//! accompanies, so recording is left always-on; the totals are read and emitted
//! as one greppable JSON line to stderr only on the `AOS_NIX_EVAL_STATS` dump
//! path (not the tracing target):
//!
//! ```text
//! aos_nix_demand_key_hashes {"persist_expr":1234567,"demand_confirm":890123}
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

/// Durable `PersistNodeMetadataKey::for_expression` finalizes observed.
static PERSIST_EXPR_FINALIZES: AtomicU64 = AtomicU64::new(0);
/// In-memory `DemandCacheKey` free-var confirmation finalizes observed.
static DEMAND_CONFIRM_FINALIZES: AtomicU64 = AtomicU64::new(0);

/// Records one durable expression-key finalize.
#[inline]
pub(crate) fn note_persist_expression_key_finalize() {
    PERSIST_EXPR_FINALIZES.fetch_add(1, Ordering::Relaxed);
}

/// Records one in-memory demand-key free-var confirmation finalize.
#[inline]
pub(crate) fn note_demand_confirmation_finalize() {
    DEMAND_CONFIRM_FINALIZES.fetch_add(1, Ordering::Relaxed);
}

/// A point-in-time count of demand-node key finalizes.
///
/// Both fields are process-wide cumulative totals across every evaluation in
/// the process; the last line a run prints holds the full picture.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DemandKeyHashCounts {
    /// Durable `PersistNodeMetadataKey::for_expression` finalizes.
    pub persist_expr: u64,
    /// In-memory `DemandCacheKey` free-var confirmation finalizes.
    pub demand_confirm: u64,
}

/// Returns the current finalize counts, or `None` when nothing was recorded.
pub(crate) fn demand_key_hash_counts() -> Option<DemandKeyHashCounts> {
    let persist_expr = PERSIST_EXPR_FINALIZES.load(Ordering::Relaxed);
    let demand_confirm = DEMAND_CONFIRM_FINALIZES.load(Ordering::Relaxed);
    if persist_expr == 0 && demand_confirm == 0 {
        return None;
    }
    Some(DemandKeyHashCounts {
        persist_expr,
        demand_confirm,
    })
}

/// Emits the demand-node key-finalize totals to stderr as one greppable JSON
/// line, or nothing when no finalize was recorded this process.
///
/// Called on the `AOS_NIX_EVAL_STATS` dump path so it lands on the evaluator's
/// stderr rather than the `aos_nix::eval::stats` trace subscriber.
pub(crate) fn emit_demand_key_hash_report() {
    let Some(counts) = demand_key_hash_counts() else {
        return;
    };
    eprintln!(
        "aos_nix_demand_key_hashes {{\"persist_expr\":{},\"demand_confirm\":{}}}",
        counts.persist_expr, counts.demand_confirm
    );
}
