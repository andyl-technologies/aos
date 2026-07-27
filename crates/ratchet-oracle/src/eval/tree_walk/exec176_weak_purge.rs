//! Execution-176 purge-only lifetime falsifier.
//!
//! The experiment removes exact unreachable checkpoint candidates from weak
//! interning and evaluator advisory caches before the ordinary nonmoving
//! quarantine starts. It never retires or reuses an object. Representation-
//! semantic thunk side tables are a fail-closed preflight because clearing
//! those tables could change lazy identity or native-entry behavior.

use std::ptr::NonNull;

use super::*;

const EXEC176_WEAK_PURGE_ENV: &str = "AOS_NIX_EXEC176_WEAK_PURGE";

impl TreeWalk {
    /// Runs the exact execution-176 weak-handle purge when explicitly enabled.
    pub(super) fn run_exec176_weak_purge(&mut self, candidates: &[LifetimeCohortCandidate]) {
        if !std::env::var(EXEC176_WEAK_PURGE_ENV).is_ok_and(|value| value == "1") {
            return;
        }
        let mut addresses = Vec::new();
        if addresses.try_reserve_exact(candidates.len()).is_err() {
            emit_refusal("candidate address membership allocation failed", 0, 0, 0);
            return;
        }
        addresses.extend(candidates.iter().map(|candidate| candidate.address));
        addresses.sort_unstable();
        addresses.dedup();

        let semantic = match self.exec176_semantic_identity_hits(candidates) {
            Ok(semantic) => semantic,
            Err(reason) => {
                emit_refusal(reason, 0, 0, 0);
                return;
            }
        };
        if semantic.lazy_identity != 0
            || semantic.lazy_foldl_initial != 0
            || semantic.tier1_publish != 0
        {
            emit_refusal(
                "candidate intersects representation-semantic thunk side tables",
                semantic.lazy_identity,
                semantic.lazy_foldl_initial,
                semantic.tier1_publish,
            );
            return;
        }
        if self.force_payload_memo.borrow().is_active() {
            emit_refusal("force payload memo is active", 0, 0, 0);
            return;
        }

        debug_assert!(
            self.memo_l0.is_none(),
            "admitted purge mode disables MEMO-1 L0"
        );
        let genlist_recipes_cleared = self.genlist_elem_at_add_one_plans.len();
        let memo_unhashable_cleared = self.memo_unhashable_values.len();
        let force_payload_entries_cleared = self.force_payload_memo.borrow().entry_count();
        debug_assert_eq!(
            memo_unhashable_cleared, 0,
            "memo-off admitted mode must leave no advisory memo declines"
        );
        debug_assert_eq!(
            force_payload_entries_cleared, 0,
            "force-cache-off admitted mode must leave no payload memo entries"
        );
        self.genlist_elem_at_add_one_plans.clear();
        self.memo_unhashable_values.clear();
        self.force_payload_memo.borrow_mut().clear();

        let report = self.heap.purge_weak_hash_cons_candidates(&addresses);
        emit_report(
            candidates.len(),
            addresses.len(),
            genlist_recipes_cleared,
            memo_unhashable_cleared,
            force_payload_entries_cleared,
            report,
        );
    }

    /// Counts candidate thunk identities retained by semantic side tables.
    fn exec176_semantic_identity_hits(
        &self,
        candidates: &[LifetimeCohortCandidate],
    ) -> Result<SemanticIdentityHits, &'static str> {
        let mut hits = SemanticIdentityHits::default();
        for candidate in candidates {
            if !candidate_is_thunk(*candidate) {
                continue;
            }
            let pointer = NonNull::new(candidate.address as *mut HeapObject)
                .ok_or("candidate thunk has a null address")?;
            let value = Value::thunk(pointer)
                .map_err(|_| "candidate thunk identity reconstruction failed")?;
            let identity = value.relocation_sensitive_identity_bits();
            hits.lazy_identity = hits
                .lazy_identity
                .saturating_add(self.lazy_identity_thunks.contains(&identity) as usize);
            hits.lazy_foldl_initial = hits
                .lazy_foldl_initial
                .saturating_add(self.lazy_foldl_initial_thunks.contains(&identity) as usize);
            hits.tier1_publish = hits
                .tier1_publish
                .saturating_add(self.tier1_publish_slots.contains_key(&identity) as usize);
        }
        Ok(hits)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SemanticIdentityHits {
    lazy_identity: usize,
    lazy_foldl_initial: usize,
    tier1_publish: usize,
}

/// Returns whether a captured object can be represented by a thunk identity key.
fn candidate_is_thunk(candidate: LifetimeCohortCandidate) -> bool {
    matches!(
        candidate.kind,
        LifetimeCohortCandidateKind::Record(ValueTag::Thunk)
            | LifetimeCohortCandidateKind::Closure(FlatObjectKind::Thunk)
            | LifetimeCohortCandidateKind::TypedThunk
    )
}

fn emit_refusal(
    reason: &'static str,
    lazy_identity: usize,
    lazy_foldl_initial: usize,
    tier1_publish: usize,
) {
    eprintln!(
        "aos_nix_exec176_weak_purge_refused \
         {{\"version\":1,\"execution\":176,\"reason\":{reason:?},\
         \"lazy_identity_hits\":{lazy_identity},\
         \"lazy_foldl_initial_hits\":{lazy_foldl_initial},\
         \"tier1_publish_hits\":{tier1_publish}}}"
    );
}

fn emit_report(
    candidate_objects: usize,
    candidate_addresses: usize,
    genlist_recipes_cleared: usize,
    memo_unhashable_cleared: usize,
    force_payload_entries_cleared: usize,
    report: WeakHashConsPurgeReport,
) {
    eprintln!(
        "aos_nix_exec176_weak_purge \
         {{\"version\":1,\"execution\":176,\
         \"candidate_objects\":{candidate_objects},\
         \"candidate_addresses\":{candidate_addresses},\
         \"genlist_recipes_cleared\":{genlist_recipes_cleared},\
         \"memo_unhashable_cleared\":{memo_unhashable_cleared},\
         \"force_payload_entries_cleared\":{force_payload_entries_cleared},\
         \"string\":{},\"path\":{},\"list\":{},\"attrs\":{}}}",
        table_json(report.string),
        table_json(report.path),
        table_json(report.list),
        table_json(report.attrs),
    );
}

fn table_json(report: WeakHashConsTablePurgeReport) -> String {
    format!(
        "{{\"before\":[{},{},{},{}],\"after\":[{},{},{},{}],\
         \"candidates_removed\":{},\
         \"buckets_removed\":{},\"candidate_capacity_released\":{},\
         \"bucket_capacity_released\":{}}}",
        report.before.0,
        report.before.1,
        report.before.2,
        report.before.3,
        report.after.0,
        report.after.1,
        report.after.2,
        report.after.3,
        report.retained.candidates_removed,
        report.retained.buckets_removed,
        report.retained.candidate_capacity_released,
        report.retained.bucket_capacity_released,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::resolve as resolve_ast;
    use crate::syntax::parse_str;

    fn lower(source: &str) -> Ir {
        nix_lower(resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("source lowers")
    }

    #[test]
    fn candidate_kind_filter_includes_every_thunk_storage_form() {
        let candidate = |kind| LifetimeCohortCandidate {
            address: 0x1000,
            kind,
            inline_bytes: 8,
            external_bytes: 0,
            initial_touch_epoch: Some(1),
        };
        assert!(candidate_is_thunk(candidate(
            LifetimeCohortCandidateKind::Record(ValueTag::Thunk)
        )));
        assert!(candidate_is_thunk(candidate(
            LifetimeCohortCandidateKind::Closure(FlatObjectKind::Thunk)
        )));
        assert!(candidate_is_thunk(candidate(
            LifetimeCohortCandidateKind::TypedThunk
        )));
        assert!(!candidate_is_thunk(candidate(
            LifetimeCohortCandidateKind::String
        )));
    }

    #[test]
    fn semantic_preflight_detects_exact_candidate_thunk_keys() {
        let ir = lower("null");
        let mut evaluator = TreeWalk::new(&ir);
        let candidate_value = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(IrId::new(1)))
            .expect("candidate thunk allocates");
        let other_value = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(IrId::new(2)))
            .expect("other thunk allocates");
        evaluator
            .lazy_identity_thunks
            .insert(candidate_value.relocation_sensitive_identity_bits());
        evaluator
            .lazy_foldl_initial_thunks
            .insert(other_value.relocation_sensitive_identity_bits());
        let candidate = LifetimeCohortCandidate {
            address: candidate_value
                .as_heap_ptr()
                .expect("candidate thunk has a pointer")
                .as_ptr() as usize,
            kind: LifetimeCohortCandidateKind::Closure(FlatObjectKind::Thunk),
            inline_bytes: 8,
            external_bytes: 0,
            initial_touch_epoch: Some(1),
        };

        let hits = evaluator
            .exec176_semantic_identity_hits(&[candidate])
            .expect("candidate identity reconstructs");

        assert_eq!(hits.lazy_identity, 1);
        assert_eq!(hits.lazy_foldl_initial, 0);
        assert_eq!(hits.tier1_publish, 0);
    }
}
