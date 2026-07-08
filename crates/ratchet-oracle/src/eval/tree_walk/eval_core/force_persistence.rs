//! Persistent force-cache observation, demand tracking, and payload replay.

use super::*;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistRuntimeHitObservation {
    Accepted {
        node: DemandNodeId,
        early_cutoff: bool,
    },
    Rejected,
    Skipped,
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

    fn record_persist_forced_expression_pure_trace(
        &mut self,
        subject: &ForceCacheSubject,
        node: DemandNodeId,
        value_hash: ValueHash,
    ) -> bool {
        let payload = match PersistNodeTracePayload::from_impure_trace(std::iter::empty::<
            &ImpureInputFingerprint,
        >()) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator pure force trace could not be encoded for persistence"
                );
                return false;
            }
        };
        let Some(payload) = self.persistent_trace_payload_with_memo_reads(node, payload) else {
            return false;
        };
        self.record_persist_forced_expression_trace_payload(subject, value_hash, &payload)
    }

    fn record_persist_forced_expression_trace(
        &mut self,
        subject: &ForceCacheSubject,
        node: DemandNodeId,
        value_hash: ValueHash,
        trace: &ImpureInputTraceSegment,
    ) -> bool {
        let payload = match PersistNodeTracePayload::from_impure_trace(trace.impure_input_trace()) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator accepted force trace could not be encoded for persistence"
                );
                return false;
            }
        };
        let Some(payload) = self.persistent_trace_payload_with_memo_reads(node, payload) else {
            return false;
        };
        self.record_persist_forced_expression_trace_payload(subject, value_hash, &payload)
    }

    fn persistent_trace_payload_with_memo_reads(
        &mut self,
        node: DemandNodeId,
        payload: PersistNodeTracePayload,
    ) -> Option<PersistNodeTracePayload> {
        let Ok(cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping persistent force trace dependencies"
            );
            return None;
        };
        let dependencies = match cache.memo_read_dependency_persist_keys(node, payload.inputs()) {
            Ok(Some(dependencies)) => dependencies,
            Ok(None) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = node.as_u32(),
                    "tree-walk evaluator persistent force trace has memo-read dependencies without durable keys"
                );
                return None;
            }
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force trace dependency lookup failed"
                );
                return None;
            }
        };
        drop(cache);
        let dependencies = self.persistently_traceable_memo_read_dependencies(dependencies)?;
        match payload.with_memo_read_dependency_records(dependencies) {
            Ok(payload) => Some(payload),
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force trace dependencies could not be encoded"
                );
                None
            }
        }
    }

    fn persistently_traceable_memo_read_dependencies(
        &mut self,
        dependencies: Vec<(PersistNodeMetadataKey, bool)>,
    ) -> Option<Vec<(PersistNodeMetadataKey, ValueHash)>> {
        if dependencies.is_empty() {
            return Some(Vec::new());
        }
        let Some(persist_cache) = &self.persist_cache else {
            return None;
        };
        let mut traceable = Vec::new();
        for (dependency, covered_by_parent_trace) in dependencies {
            let value_hash = match persist_cache.lookup_node_materialized_value_hash(dependency) {
                Ok(Some(value_hash)) => value_hash,
                Ok(None) if covered_by_parent_trace => continue,
                Ok(None) => return None,
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator persistent force trace dependency metadata lookup failed"
                    );
                    return None;
                }
            };
            let trace = match persist_cache.lookup_node_trace(dependency) {
                Ok(Some(trace)) => trace,
                Ok(None) if covered_by_parent_trace => continue,
                Ok(None) => return None,
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator persistent force trace dependency trace lookup failed"
                    );
                    return None;
                }
            };
            if trace.value_hash() != value_hash || trace.payload().is_tombstone() {
                if covered_by_parent_trace {
                    continue;
                }
                return None;
            }
            traceable.push((dependency, value_hash));
        }
        Some(traceable)
    }

    fn record_persist_forced_expression_trace_payload(
        &mut self,
        subject: &ForceCacheSubject,
        value_hash: ValueHash,
        payload: &PersistNodeTracePayload,
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
        match persist_cache.record_node_trace(key, value_hash, payload) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force trace writeback failed"
                );
                false
            }
        }
    }

    fn clear_persist_forced_expression_payload(&mut self, subject: &ForceCacheSubject) {
        if !self.options.eval_cache_enabled() {
            return;
        }
        let Some(identity) = subject
            .metadata_identity
            .or(subject.persistent_clear_identity)
        else {
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
        let cleared_materialized_value = match persist_cache.clear_node_materialized_value_hash(key)
        {
            Ok(cleared) => cleared,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force payload clear failed"
                );
                false
            }
        };
        let has_live_trace = match persist_cache.lookup_node_trace(key) {
            Ok(Some(trace)) => !trace.payload().is_tombstone(),
            Ok(None) => false,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force trace lookup before tombstone failed"
                );
                false
            }
        };
        if !cleared_materialized_value && !has_live_trace {
            return;
        }
        if let Err(error) = persist_cache.record_node_trace_tombstone(key) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent force trace tombstone write failed"
            );
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

    fn force_cache_has_prior_persistent_demand(&mut self, subject: &ForceCacheSubject) -> bool {
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

    pub(in crate::eval::tree_walk) fn lookup_forced_inline_expression_result(
        &mut self,
        subject: Option<ForceCacheSubject>,
    ) -> Option<Value> {
        let subject = subject?;
        let identity = subject.lookup_identity?;
        let mut revalidator = TreeWalkImpureInputRevalidator::new(&self.options);
        let active_force_cache_node = self
            .active_memo_read_nodes
            .last()
            .map(ActiveMemoReadNode::node);

        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping forced expression lookup"
            );
            return None;
        };
        if !cache.is_enabled() {
            return None;
        }
        match cache.lookup_inline_expression_payload_hit_with_impure_inputs(
            identity,
            subject.free_var_value_hashes.iter().copied(),
            &mut revalidator,
        ) {
            Ok(Some(hit)) => {
                let dependency = hit.node();
                let early_cutoff = hit.reconsideration().is_some_and(|reconsideration| {
                    reconsideration.decision() == CutoffDecision::CutOff
                });
                let payload = hit.into_value();
                if self
                    .payload_position_remap_for_subject(&payload, &subject)
                    .is_none()
                {
                    if let Err(error) = cache.invalidate_inline_expression_payload(
                        identity,
                        subject.free_var_value_hashes.iter().copied(),
                    ) {
                        tracing::warn!(
                            target: "aos_nix::cache",
                            error = %error,
                            "tree-walk evaluator incompatible positioned payload invalidation failed"
                        );
                    }
                    drop(revalidator);
                    drop(cache);
                    self.clear_persist_forced_expression_payload(&subject);
                    self.increment_eval_cache_miss();
                    return None;
                }
                let trace = revalidator.into_revalidated_trace();
                drop(cache);
                let Some(value) =
                    self.value_for_cached_expression_payload_for_subject(payload, &subject)
                else {
                    self.increment_eval_cache_miss();
                    return None;
                };
                self.record_active_memo_read(active_force_cache_node, dependency);
                for fingerprint in trace {
                    self.record_impure_input(fingerprint);
                }
                if early_cutoff {
                    self.increment_early_cutoffs();
                }
                self.record_forced_expression_demand(&subject);
                self.increment_eval_cache_hit();
                Some(value)
            }
            Ok(None) => {
                drop(revalidator);
                drop(cache);
                if let Some(value) = self.lookup_persist_forced_expression_result(&subject) {
                    return Some(value);
                }
                self.increment_eval_cache_miss();
                None
            }
            Err(error) => {
                drop(revalidator);
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator forced expression lookup failed"
                );
                None
            }
        }
    }

    fn lookup_persist_forced_expression_result(
        &mut self,
        subject: &ForceCacheSubject,
    ) -> Option<Value> {
        if !self.options.eval_cache_enabled() {
            return None;
        }
        let identity = subject.metadata_identity?;
        let active_force_cache_node = self
            .active_memo_read_nodes
            .last()
            .map(ActiveMemoReadNode::node);
        self.open_persist_eval_cache();
        let persist_cache = self.persist_cache.as_ref()?;
        let key = PersistNodeMetadataKey::for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        );
        let mut revalidator = TreeWalkImpureInputRevalidator::new(&self.options);
        let hit = match persist_cache
            .load_cached_expression_node_value_trace_hit_with_revalidation(key, &mut revalidator)
        {
            Ok(Some(hit)) => hit,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent forced expression lookup failed"
                );
                return None;
            }
        };
        let memo_read_dependencies = hit.memo_read_dependencies().to_vec();
        let payload = hit.into_value();
        if self
            .payload_position_remap_for_subject(&payload, subject)
            .is_none()
        {
            self.clear_persist_forced_expression_payload(subject);
            return None;
        }
        let trace = revalidator.into_revalidated_trace();
        let value =
            self.value_for_cached_expression_payload_for_subject(payload.clone(), subject)?;
        match self.observe_persist_forced_expression_runtime_hit(
            subject,
            payload,
            &trace,
            &memo_read_dependencies,
        ) {
            PersistRuntimeHitObservation::Accepted {
                node: dependency,
                early_cutoff,
            } => {
                self.record_active_memo_read(active_force_cache_node, dependency);
                if early_cutoff {
                    self.increment_early_cutoffs();
                }
            }
            PersistRuntimeHitObservation::Rejected => {
                self.clear_persist_forced_expression_payload(subject);
                return None;
            }
            PersistRuntimeHitObservation::Skipped => {}
        }
        for fingerprint in trace {
            self.record_impure_input(fingerprint);
        }
        self.record_forced_expression_demand(subject);
        self.increment_eval_cache_hit();
        self.persist_force_cache_hit_keys.push(key);
        Some(value)
    }

    fn observe_persist_forced_expression_runtime_hit(
        &mut self,
        subject: &ForceCacheSubject,
        payload: CachedExpressionValue,
        trace: &[ImpureInputFingerprint],
        memo_read_dependencies: &[PersistNodeMetadataKey],
    ) -> PersistRuntimeHitObservation {
        let Some(identity) = subject.lookup_identity else {
            return PersistRuntimeHitObservation::Skipped;
        };
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping persistent forced expression runtime observation"
            );
            return PersistRuntimeHitObservation::Skipped;
        };
        if !cache.is_enabled() {
            return PersistRuntimeHitObservation::Skipped;
        }
        let observation = if trace.is_empty() {
            cache
                .observe_inline_expression_payload(
                    identity,
                    subject.free_var_value_hashes.iter().copied(),
                    payload,
                )
                .map(|observation| {
                    observation.map(|reconsideration| {
                        (
                            reconsideration.node(),
                            reconsideration.decision() == CutoffDecision::CutOff,
                        )
                    })
                })
        } else {
            let mut runtime_trace = Vec::new();
            if runtime_trace.try_reserve_exact(trace.len()).is_err() {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator persistent forced expression runtime trace allocation failed"
                );
                return PersistRuntimeHitObservation::Skipped;
            }
            runtime_trace.extend_from_slice(trace);
            let source = ImpureInputTraceSegment {
                trace: runtime_trace,
                complete: true,
            };
            cache
                .observe_inline_expression_payload_with_impure_inputs(
                    identity,
                    subject.free_var_value_hashes.iter().copied(),
                    payload,
                    &source,
                )
                .map(|observation| {
                    observation.and_then(|observation| {
                        let node = observation.node()?;
                        let early_cutoff =
                            observation
                                .payload_reconsideration()
                                .is_some_and(|reconsideration| {
                                    reconsideration.decision() == CutoffDecision::CutOff
                                });
                        Some((node, early_cutoff))
                    })
                })
        };
        match observation {
            Ok(Some((node, early_cutoff))) => match cache
                .replace_memo_read_dependencies_by_persist_keys(node, memo_read_dependencies)
            {
                Ok(Some(true)) => PersistRuntimeHitObservation::Rejected,
                Ok(Some(false)) => PersistRuntimeHitObservation::Accepted { node, early_cutoff },
                Ok(None) => PersistRuntimeHitObservation::Accepted { node, early_cutoff },
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator persistent forced expression memo-read rehydration failed"
                    );
                    PersistRuntimeHitObservation::Rejected
                }
            },
            Ok(None) => PersistRuntimeHitObservation::Rejected,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent forced expression runtime observation failed"
                );
                PersistRuntimeHitObservation::Rejected
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
        if !self.options.eval_cache_enabled() {
            return;
        }
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
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
