//! Captured-environment apply-count probe (RFC-0007 §P1 env-flatten lever).
//!
//! A diagnostic that answers one load-bearing question about the shelved
//! shared-flattened-base optimization: **how many times is each captured
//! lexical environment installed?** A flatten memo can only pay off for
//! environments installed two or more times; if evaluation is dominated by
//! once-installed environments the whole env-flatten direction is a dead lever.
//!
//! Every lambda apply and thunk force routes through
//! [`TreeWalk::clone_env_frames`](crate::eval::tree_walk), which installs a
//! captured environment. This module counts those installs per distinct
//! captured environment — keyed by the innermost captured frame `Arc`, a stable
//! identity for one lexical environment — and buckets the distribution.
//!
//! Collection is opt-in: [`note_env_install`] is called only when the evaluator
//! has `AOS_NIX_EVAL_STATS` stats collection enabled, so a normal or production
//! evaluation pays nothing. The distribution is emitted as one greppable JSON
//! line to stderr by [`emit_env_apply_histogram_report`], on the same
//! `AOS_NIX_EVAL_STATS` dump path as the evaluator's other stderr diagnostics
//! (not the tracing stats target):
//!
//! ```text
//! aos_nix_env_apply_histogram {"installs":1234,"empty_installs":56,"distinct":900,
//!   "applied_once":810,"applied_two":60,"applied_three_four":20,
//!   "applied_five_eight":8,"applied_nine_plus":2}
//! ```
//!
//! Counts are process-wide and cumulative across every evaluation in the
//! process (matching the [`capture_stats`](super::capture_stats) atomics
//! convention); the last line printed by a run holds the full picture.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use super::EvalFrame;
use std::sync::Arc;

/// Total captured-environment installs observed (`clone_env_frames` calls).
static INSTALLS: AtomicU64 = AtomicU64::new(0);
/// Installs of environments with no shared frames (nothing to flatten).
static EMPTY_INSTALLS: AtomicU64 = AtomicU64::new(0);
/// Per-environment install counts, keyed by innermost-frame identity.
///
/// `None` until the first recorded install. Retaining each key's `Arc` keeps
/// the frame alive so its address cannot be reused by a later allocation, which
/// would otherwise alias two distinct environments onto one key.
static COUNTS: Mutex<Option<HashMap<HeadKey, u64>>> = Mutex::new(None);

/// Pointer-identity key over an innermost captured frame `Arc`.
struct HeadKey(Arc<EvalFrame>);

impl PartialEq for HeadKey {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for HeadKey {}

impl Hash for HeadKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (Arc::as_ptr(&self.0) as usize).hash(state);
    }
}

/// Records one captured-environment install against its identity.
///
/// `head` is the innermost captured frame — the stable identity of one lexical
/// environment — or `None` for an environment with no shared frames. Call this
/// only when stats collection is active; see `TreeWalk::clone_env_frames`.
///
/// A poisoned probe lock is treated as a lost sample and silently skipped: this
/// is diagnostic instrumentation and must never perturb evaluation.
pub(crate) fn note_env_install(head: Option<&Arc<EvalFrame>>) {
    INSTALLS.fetch_add(1, Ordering::Relaxed);
    let Some(head) = head else {
        EMPTY_INSTALLS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if let Ok(mut guard) = COUNTS.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        *map.entry(HeadKey(Arc::clone(head))).or_insert(0) += 1;
    }
}

/// A point-in-time apply-count distribution over captured environments.
///
/// Fields are process-wide cumulative totals. `installs` counts every install
/// (including empty ones); the non-empty installs equal `installs -
/// empty_installs` and are also the sum of the `applied_*` bucket weights.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EnvApplyHistogram {
    /// Total captured-environment installs (`clone_env_frames` calls).
    pub installs: u64,
    /// Installs of environments with no shared frames (nothing to flatten).
    pub empty_installs: u64,
    /// Distinct non-empty captured environments installed at least once.
    pub distinct: u64,
    /// Distinct environments installed exactly once.
    pub applied_once: u64,
    /// Distinct environments installed exactly twice.
    pub applied_two: u64,
    /// Distinct environments installed 3-4 times.
    pub applied_three_four: u64,
    /// Distinct environments installed 5-8 times.
    pub applied_five_eight: u64,
    /// Distinct environments installed 9 or more times.
    pub applied_nine_plus: u64,
}

/// Returns the current apply-count distribution, or `None` when the probe has
/// recorded nothing (stats collection was never active this process).
pub(crate) fn env_apply_histogram() -> Option<EnvApplyHistogram> {
    let installs = INSTALLS.load(Ordering::Relaxed);
    let empty_installs = EMPTY_INSTALLS.load(Ordering::Relaxed);
    if installs == 0 {
        return None;
    }
    let mut histogram = EnvApplyHistogram {
        installs,
        empty_installs,
        ..EnvApplyHistogram::default()
    };
    if let Ok(guard) = COUNTS.lock() {
        if let Some(map) = guard.as_ref() {
            histogram.distinct = map.len() as u64;
            for &count in map.values() {
                match count {
                    0 => {}
                    1 => histogram.applied_once += 1,
                    2 => histogram.applied_two += 1,
                    3..=4 => histogram.applied_three_four += 1,
                    5..=8 => histogram.applied_five_eight += 1,
                    _ => histogram.applied_nine_plus += 1,
                }
            }
        }
    }
    Some(histogram)
}

/// Prints the apply-count distribution as one JSON line to stderr, or does
/// nothing when the probe holds no data.
///
/// Emitted on the `AOS_NIX_EVAL_STATS` diagnostic dump path so it lands on the
/// same stderr stream a benchmark run already captures. The line is prefixed
/// with `aos_nix_env_apply_histogram` for grepping.
pub(crate) fn emit_env_apply_histogram_report() {
    let Some(h) = env_apply_histogram() else {
        return;
    };
    eprintln!(
        "aos_nix_env_apply_histogram {{\"installs\":{},\"empty_installs\":{},\"distinct\":{},\"applied_once\":{},\"applied_two\":{},\"applied_three_four\":{},\"applied_five_eight\":{},\"applied_nine_plus\":{}}}",
        h.installs,
        h.empty_installs,
        h.distinct,
        h.applied_once,
        h.applied_two,
        h.applied_three_four,
        h.applied_five_eight,
        h.applied_nine_plus,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> Arc<EvalFrame> {
        EvalFrame::new(1).expect("frame allocation")
    }

    /// Two installs of the same environment identity bucket as one distinct
    /// twice-applied environment, while a second identity applied once buckets
    /// separately.
    #[test]
    fn buckets_distinct_environments_by_install_count() {
        // The probe is a private, per-test-binary global; exercise the pure
        // bucketing logic directly against a fresh map rather than the shared
        // statics, which other tests in the process also touch.
        let f_multi = frame();
        let f_once = frame();
        let mut map: HashMap<HeadKey, u64> = HashMap::new();
        *map.entry(HeadKey(Arc::clone(&f_multi))).or_insert(0) += 1;
        *map.entry(HeadKey(Arc::clone(&f_multi))).or_insert(0) += 1;
        *map.entry(HeadKey(Arc::clone(&f_once))).or_insert(0) += 1;

        assert_eq!(map.len(), 2, "same identity collapses to one key");
        assert_eq!(map.get(&HeadKey(Arc::clone(&f_multi))).copied(), Some(2));
        assert_eq!(map.get(&HeadKey(Arc::clone(&f_once))).copied(), Some(1));

        let mut once = 0u64;
        let mut two = 0u64;
        for &count in map.values() {
            match count {
                1 => once += 1,
                2 => two += 1,
                _ => {}
            }
        }
        assert_eq!(once, 1);
        assert_eq!(two, 1);
    }

    /// Distinct frame `Arc`s are distinct keys even though both wrap one slot.
    #[test]
    fn distinct_arcs_are_distinct_keys() {
        let a = frame();
        let b = frame();
        assert_ne!(Arc::as_ptr(&a) as usize, Arc::as_ptr(&b) as usize);
        assert!(HeadKey(Arc::clone(&a)) != HeadKey(b));
        assert!(HeadKey(Arc::clone(&a)) == HeadKey(a));
    }
}
