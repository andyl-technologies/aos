//! Persistent force-cache observation, demand tracking, and payload replay.

use super::*;

mod persist_hit;
mod trace_record;
mod value_payload_replay;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ForcePayloadPersistenceAction {
    Skip,
    Clear,
    Materialize {
        node: DemandNodeId,
        early_cutoff: bool,
    },
    MaterializeWithTrace {
        node: DemandNodeId,
        early_cutoff: bool,
    },
}

impl TreeWalk {
    #[cfg(test)]
    pub(in crate::eval::tree_walk) fn observe_forced_inline_expression_result(
        &mut self,
        subject: Option<ForceCacheSubject>,
        value: Value,
        trace: ImpureInputTraceSegment,
    ) {
        self.observe_forced_inline_expression_result_with_eval_work_units(
            subject, value, trace, None, false,
        );
    }

    pub(in crate::eval::tree_walk) fn observe_forced_inline_expression_result_with_eval_work_units(
        &mut self,
        subject: Option<ForceCacheSubject>,
        value: Value,
        trace: ImpureInputTraceSegment,
        eval_work_units: Option<u64>,
        scale_eval_work_by_payload: bool,
    ) -> Option<DemandNodeId> {
        let Some(subject) = subject else {
            return None;
        };
        let Some(payload) = self.force_cache_payload_for_value(value) else {
            self.invalidate_cached_forced_expression_payload(&subject);
            self.clear_persist_forced_expression_payload(&subject);
            return None;
        };
        let trace_is_empty_complete = trace.is_empty_complete();
        // Generally effectful primops can still produce an empty trace for
        // immutable text-store inputs; use their trace-backed identity when no
        // pure identity is available.
        let use_impure_observation =
            !trace_is_empty_complete || subject.pure_observation_identity.is_none();
        let identity = if use_impure_observation {
            subject.impure_observation_identity
        } else {
            subject.pure_observation_identity
        };
        let Some(identity) = identity else {
            return None;
        };
        let Some(payload) = self.prepare_observable_payload_for_subject(payload, &subject) else {
            self.invalidate_cached_forced_expression_payload(&subject);
            self.clear_persist_forced_expression_payload(&subject);
            return None;
        };
        let materialization_cost_observation = self.materialization_cost_observation_for_payload(
            &payload,
            eval_work_units,
            scale_eval_work_by_payload,
        );

        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping forced expression observation"
            );
            return None;
        };
        let cache_enabled = cache.is_enabled();
        let persistence_action = if !use_impure_observation {
            match cache.observe_inline_expression_payload(
                identity,
                subject.free_var_value_hashes.iter().copied(),
                payload.clone(),
            ) {
                Ok(Some(reconsideration)) => Ok(ForcePayloadPersistenceAction::Materialize {
                    node: reconsideration.node(),
                    early_cutoff: reconsideration.decision() == CutoffDecision::CutOff,
                }),
                Ok(None) if cache_enabled => Ok(ForcePayloadPersistenceAction::Clear),
                Ok(None) => Ok(ForcePayloadPersistenceAction::Skip),
                Err(error) => Err(error),
            }
        } else {
            match cache.observe_inline_expression_payload_with_impure_inputs(
                identity,
                subject.free_var_value_hashes.iter().copied(),
                payload.clone(),
                &trace,
            ) {
                Ok(Some(observation)) => {
                    if let Some(node) = observation.node() {
                        Ok(ForcePayloadPersistenceAction::MaterializeWithTrace {
                            node,
                            early_cutoff: observation
                                .payload_reconsideration()
                                .map(|reconsideration| {
                                    reconsideration.decision() == CutoffDecision::CutOff
                                })
                                .unwrap_or(false),
                        })
                    } else {
                        Ok(ForcePayloadPersistenceAction::Clear)
                    }
                }
                Ok(None) => Ok(ForcePayloadPersistenceAction::Skip),
                Err(error) => Err(error),
            }
        };
        drop(cache);
        match persistence_action {
            Ok(ForcePayloadPersistenceAction::Materialize { node, early_cutoff }) => {
                if early_cutoff {
                    self.increment_early_cutoffs();
                }
                if let Some(value_hash) = self.materialize_persist_forced_expression_payload(
                    &subject,
                    &payload,
                    materialization_cost_observation,
                ) && !self
                    .record_persist_forced_expression_pure_trace(&subject, node, value_hash)
                {
                    self.clear_persist_forced_expression_payload(&subject);
                }
                Some(node)
            }
            Ok(ForcePayloadPersistenceAction::MaterializeWithTrace { node, early_cutoff }) => {
                if early_cutoff {
                    self.increment_early_cutoffs();
                }
                if let Some(value_hash) = self.materialize_persist_forced_expression_payload(
                    &subject,
                    &payload,
                    materialization_cost_observation,
                ) && !self
                    .record_persist_forced_expression_trace(&subject, node, value_hash, &trace)
                {
                    self.clear_persist_forced_expression_payload(&subject);
                }
                Some(node)
            }
            Ok(ForcePayloadPersistenceAction::Clear) => {
                self.clear_persist_forced_expression_payload(&subject);
                None
            }
            Ok(ForcePayloadPersistenceAction::Skip) => None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator forced expression observation failed"
                );
                None
            }
        }
    }

    fn invalidate_cached_forced_expression_payload(&mut self, subject: &ForceCacheSubject) -> bool {
        let Some(identity) = subject
            .lookup_identity
            .or(subject.persistent_clear_identity)
            .or(subject.impure_observation_identity)
        else {
            return false;
        };
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping forced expression invalidation"
            );
            return false;
        };
        match cache.invalidate_inline_expression_payload(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        ) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator forced expression invalidation failed"
                );
                false
            }
        }
    }

    fn materialize_persist_forced_expression_payload(
        &mut self,
        subject: &ForceCacheSubject,
        payload: &CachedExpressionValue,
        cost_observation: MaterializationCostObservation,
    ) -> Option<ValueHash> {
        if !self.options.eval_cache_enabled() {
            return None;
        }
        if self
            .payload_position_remap_for_subject(payload, subject)
            .is_none()
        {
            self.clear_persist_forced_expression_payload(subject);
            return None;
        }
        let identity = subject.metadata_identity?;
        self.open_persist_eval_cache();
        let key = PersistNodeMetadataKey::for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        );
        let costs = cost_observation.costs(self.options.force_cache_materialization_costs());
        let signals = {
            let Some(persist_cache) = &self.persist_cache else {
                return None;
            };
            match persist_cache.node_materialization_signals(key, costs) {
                Ok(signals) => signals,
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator persistent force materialization signals failed"
                    );
                    return None;
                }
            }
        };
        let decision = signals.decide();
        self.increment_force_cache_materialization_decision(decision);
        if decision == MaterializationDecision::KeepInMemory {
            return None;
        }
        let Some(persist_cache) = &self.persist_cache else {
            return None;
        };
        let value_hash = match payload.value_hash() {
            Ok(value_hash) => value_hash,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force payload hashing failed"
                );
                return None;
            }
        };
        match persist_cache.materialize_cached_expression_node_value_indexed(key, payload, decision)
        {
            Ok(PersistMaterialization::Materialized(_)) => Some(value_hash),
            Ok(PersistMaterialization::Skipped) => None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force payload materialization failed"
                );
                None
            }
        }
    }

    /// Materializes cold permanent hash-consed values into the indexed value pack.
    ///
    /// This scans the evaluator heap with [`EvalHeap::cold_hash_consed_values`],
    /// captures replayable candidates through the existing force-cache payload
    /// encoder, and ensures those payloads are addressable in the persistent
    /// cache's indexed `values/` pack under their [`ValueHash`] content address.
    /// Payload capture uses ordinary heap reads and can refresh selected
    /// records' access epochs after the cold snapshot has been taken. The
    /// operation is advisory: failures are logged and counted in the returned
    /// report rather than propagated to evaluation.
    ///
    /// This method does not evict resident heap records, install content-hash
    /// handles, reclaim mapped bytes, or wire on-demand rematerialization into
    /// value access. Callers must configure a persistent cache root on
    /// [`TreeWalkOptions`] for materialization to occur.
    pub fn materialize_cold_hash_consed_values_indexed(
        &mut self,
        min_idle_epochs: u64,
    ) -> ColdHashConsedValueMaterializationReport {
        let mut report = ColdHashConsedValueMaterializationReport::default();
        let values = match self.heap.cold_hash_consed_values(min_idle_epochs) {
            Ok(values) => values,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator cold hash-consed value snapshot failed"
                );
                report.errors = report.errors.saturating_add(1);
                return report;
            }
        };
        report.record_candidates(&values);
        if values.is_empty() {
            return report;
        }

        self.open_persist_eval_cache();
        if self.persist_cache.is_none() {
            report.cache_unavailable = report.candidates;
            return report;
        }

        for cold_value in values {
            let Some(payload) = self.force_cache_payload_for_value(cold_value.value()) else {
                report.uncapturable = report.uncapturable.saturating_add(1);
                continue;
            };
            report.record_captured(&payload);
            let value_hash = match payload.value_hash() {
                Ok(value_hash) => value_hash,
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator cold hash-consed value hashing failed"
                    );
                    report.errors = report.errors.saturating_add(1);
                    continue;
                }
            };
            let Some(persist_cache) = &self.persist_cache else {
                report.cache_unavailable = report.cache_unavailable.saturating_add(1);
                continue;
            };
            match persist_cache.materialize_cached_expression_value_indexed(
                &payload,
                MaterializationDecision::Materialize,
            ) {
                Ok(PersistMaterialization::Materialized(_)) => {
                    report.record_materialized(value_hash);
                }
                Ok(PersistMaterialization::Skipped) => {
                    report.skipped = report.skipped.saturating_add(1);
                }
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator cold hash-consed value materialization failed"
                    );
                    report.errors = report.errors.saturating_add(1);
                }
            }
        }
        report
    }

    fn materialization_cost_observation_for_payload(
        &self,
        payload: &CachedExpressionValue,
        eval_work_units: Option<u64>,
        scale_eval_work_by_payload: bool,
    ) -> MaterializationCostObservation {
        let payload_len = payload.persistent_payload_len();
        let persistent_payload_bytes = if payload_len > u64::MAX as u128 {
            u64::MAX
        } else {
            payload_len as u64
        };
        let observation = MaterializationCostObservation::new(
            eval_work_units.unwrap_or(1),
            persistent_payload_bytes,
        );
        if scale_eval_work_by_payload {
            MaterializationCostObservation::new(
                observation
                    .eval_work_units()
                    .max(observation.persistent_payload_cost_units()),
                observation.persistent_payload_bytes(),
            )
        } else {
            observation
        }
    }

    pub(in crate::eval::tree_walk) fn record_force_cache_memoization_demand(
        &mut self,
        subject: &ForceCacheSubject,
    ) -> MemoizationDecision {
        let Some(identity) = subject.lookup_identity else {
            return MemoizationDecision::Admit;
        };
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping forced expression memoization demand"
            );
            return MemoizationDecision::Admit;
        };
        let observed_decision = match cache.record_memoization_demand(
            identity,
            subject.free_var_value_hashes.iter().copied(),
            MemoizationSubject::Thunk,
            true,
        ) {
            Ok(Some(observation)) => Some(observation.decision()),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator forced expression memoization demand failed"
                );
                None
            }
        };
        drop(cache);
        let mut decision = observed_decision.unwrap_or(MemoizationDecision::Admit);
        if subject.memoization_admission.admits_on_first_demand()
            || (decision == MemoizationDecision::Bypass
                && self.force_cache_has_prior_persistent_demand(subject))
        {
            decision = MemoizationDecision::Admit;
        }
        if observed_decision.is_some() {
            self.increment_force_cache_memoization_decision(decision);
        }
        decision
    }

    pub(in crate::eval::tree_walk) fn active_force_cache_node_for_subject(
        &mut self,
        subject: Option<&ForceCacheSubject>,
    ) -> Option<DemandNodeId> {
        let subject = subject?;
        let identity = subject
            .lookup_identity
            .or(subject.impure_observation_identity)?;
        self.active_memo_read_node_for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        )
    }

    pub(in crate::eval::tree_walk) fn active_memo_read_node_for_expression<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Option<DemandNodeId>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping active memo-read node"
            );
            return None;
        };
        match cache.get_or_insert_expression_node(identity, free_var_value_hashes, None) {
            Ok(Some(node)) => Some(node),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator active memo-read node allocation failed"
                );
                None
            }
        }
    }

    fn record_active_memo_read(
        &mut self,
        dependent: Option<DemandNodeId>,
        dependency: DemandNodeId,
    ) {
        let Some(dependent) = dependent else {
            return;
        };
        if dependent == dependency {
            return;
        }
        let Some(active) = self.active_memo_read_nodes.last_mut() else {
            return;
        };
        if active.node() != dependent {
            tracing::warn!(
                target: "aos_nix::cache",
                dependent = dependent.as_u32(),
                active = active.node().as_u32(),
                "tree-walk evaluator active memo-read edge did not match the current node"
            );
            return;
        }
        active.memo_reads.insert(dependency);
    }

    pub(in crate::eval::tree_walk) fn record_enclosing_memo_read(
        &mut self,
        dependency: DemandNodeId,
    ) {
        let dependent = self
            .active_memo_read_nodes
            .last()
            .map(ActiveMemoReadNode::node);
        self.record_active_memo_read(dependent, dependency);
    }

    pub(in crate::eval::tree_walk) fn replace_active_memo_reads(
        &mut self,
        active: ActiveMemoReadNode,
    ) -> bool {
        let (dependent, memo_reads) = active.into_parts();
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping memo-read edge replacement"
            );
            return false;
        };
        match cache.replace_memo_read_dependencies(dependent, memo_reads) {
            Ok(Some(has_dirty_dependency)) => has_dirty_dependency,
            Ok(None) => false,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator memo-read edge replacement failed"
                );
                false
            }
        }
    }

    pub(in crate::eval::tree_walk) fn force_cache_has_prior_persistent_demand(
        &mut self,
        subject: &ForceCacheSubject,
    ) -> bool {
        if !self.options.eval_cache_enabled() {
            return false;
        }
        let Some(identity) = subject.metadata_identity else {
            return false;
        };
        self.open_persist_eval_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return false;
        };
        let key = PersistNodeMetadataKey::for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        );
        match persist_cache.lookup_node_materialization_reuse(key) {
            Ok(Some(reuse)) => reuse.likely_redemanded_across_runs(),
            Ok(None) => false,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force memoization demand lookup failed"
                );
                false
            }
        }
    }

    pub(in crate::eval::tree_walk) fn record_forced_expression_demand(
        &mut self,
        subject: &ForceCacheSubject,
    ) {
        if !self.options.eval_cache_enabled() {
            return;
        }
        let Some(identity) = subject.metadata_identity else {
            return;
        };
        self.open_persist_eval_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
        let key = PersistNodeMetadataKey::for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        );
        // Coalesce the demand observation in memory; it is flushed to the sidecar
        // once at the run boundary rather than appending a record per hit.
        persist_cache.buffer_node_current_demand(key);
    }

    pub(in crate::eval::tree_walk) fn advance_persist_eval_cache_run_boundary(&mut self) {
        // Drop the identity-keyed observe payload memo unconditionally: a new run
        // may recycle the heap addresses its entries are keyed on, so bounding
        // their staleness to one run is a correctness requirement, not an
        // optimization. Emitted first so the campaign report survives a config
        // that skips the persist bookkeeping below.
        {
            let memo = self.force_payload_memo.borrow();
            memo.log_report();
        }
        self.force_payload_memo.borrow_mut().clear();
        if !self.options.eval_cache_enabled() {
            return;
        }
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
        // Flush the write-behind buffers (RFC-0007 §3.2(b)) at the run boundary,
        // strictly before the synchronous root-cutoff record (native/mod.rs), and
        // log their memory-scoreboard counters. See
        // `PersistCache::flush_write_behind_at_run_boundary`.
        persist_cache.flush_write_behind_at_run_boundary();
        // Flush coalesced current-run demand before advancing runs, which carries
        // current-run demand into the cross-run history.
        if let Err(error) = persist_cache.flush_buffered_node_demands() {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent force demand buffer flush failed"
            );
        }
        // A new run re-verifies every node against freshly observed impure
        // inputs, so discard the run-scoped verified-node memo.
        persist_cache.clear_verified_node_trace_memo();
        if let Err(error) = persist_cache.advance_all_node_materialization_reuse_runs() {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent force demand run-boundary advancement failed"
            );
        }
        if let Err(error) = persist_cache.compact_node_traces_if_bloated() {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent force trace run-boundary compaction failed"
            );
        }
    }

    pub(in crate::eval::tree_walk) fn open_persist_eval_cache(&mut self) {
        if self.persist_cache.is_none() && !self.persist_cache_open_attempted {
            self.persist_cache_open_attempted = true;
            if let Some(root) = self.options.persist_cache_root().map(Path::to_path_buf) {
                let verify = self.options.persist_cache_verify();
                self.persist_cache = PersistCache::open(root)
                    .ok()
                    .map(|cache| cache.with_value_decode_verification(verify));
                // Secondary L2 locations (MEMO-2): opened best-effort in probe
                // order; consulted by import-time parse-artifact loads after a
                // primary miss. An unopenable location is silently skipped.
                let secondaries = crate::cache::persist::open_secondary_caches(
                    self.options.memo_disk_locations(),
                    verify,
                );
                self.persist_secondary_caches = secondaries;
            }
        }
    }
}
