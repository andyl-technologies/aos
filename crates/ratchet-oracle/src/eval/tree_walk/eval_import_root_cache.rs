//! Persistent force-cache boundary for pure imported module roots.

use super::*;

impl TreeWalk {
    fn lookup_pure_import_root_cache(
        &mut self,
        subject: Option<ForceCacheSubject>,
    ) -> Option<Value> {
        // `force_cache_misses` is the established forced-thunk miss surface.
        // Imported roots are speculative non-thunk boundaries: count their hits,
        // but do not turn an unsupported root payload into a perpetual miss.
        let force_cache_misses = self.stats.force_cache_misses;
        let value = self.lookup_forced_inline_expression_result(subject);
        if value.is_none() {
            self.stats.force_cache_misses = force_cache_misses;
        }
        value
    }

    fn pure_import_root_cache_subject(&self, body: EvalNodeRef) -> Option<ForceCacheSubject> {
        let module = self.modules.get(body.module().index())?;
        if !module.ir.arena.node(body.id())?.effect.is_speculable() {
            return None;
        }
        let identity = Self::cache_expression_identity_for_node(module, body.id())?;
        Some(ForceCacheSubject {
            lookup_identity: Some(identity),
            pure_observation_identity: Some(identity),
            impure_observation_identity: None,
            metadata_identity: Some(identity),
            persistent_clear_identity: Some(identity),
            free_var_value_hashes: Vec::new(),
            replay_position_module: Some(body.module()),
            replay_allocation_node: Some(body),
            memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
        })
    }

    pub(super) fn eval_import_root_with_cache(
        &mut self,
        root: IrId,
    ) -> Result<Value, TreeWalkError> {
        if !self.force_cache_active {
            return self.eval_node(root);
        }

        let body = EvalNodeRef::new(self.current_module, root);
        let subject = self.pure_import_root_cache_subject(body);
        let memoization_decision = subject
            .as_ref()
            .map(|subject| self.record_force_cache_memoization_demand(subject))
            .unwrap_or(MemoizationDecision::Admit);
        let admitted = subject.is_some() && memoization_decision == MemoizationDecision::Admit;
        if admitted && let Some(value) = self.lookup_pure_import_root_cache(subject.clone()) {
            return Ok(value);
        }

        let thunks_forced_before = self.stats.thunks_forced;
        let trace_cursor = admitted.then(|| self.impure_input_trace_cursor());
        let value = self.eval_node(root)?;
        if let Some(subject) = &subject {
            self.record_forced_expression_demand(subject);
        }
        if let Some(trace_cursor) = trace_cursor {
            let trace = self.force_cache_impure_input_trace_segment(trace_cursor);
            let scale_eval_work_by_payload = !trace.trace.is_empty();
            let eval_work_units = self
                .stats
                .thunks_forced
                .saturating_sub(thunks_forced_before);
            let observed = self.observe_forced_inline_expression_result_with_eval_work_units(
                subject,
                value,
                trace,
                Some(eval_work_units),
                scale_eval_work_by_payload,
            );
            if let Some(observed) = observed {
                self.record_enclosing_memo_read(observed);
            }
        }
        Ok(value)
    }
}
