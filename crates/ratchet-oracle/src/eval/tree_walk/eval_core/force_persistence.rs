//! Persistent force-cache observation, demand tracking, and payload replay.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ForcePayloadPersistenceAction {
    Skip,
    Clear,
    Materialize { early_cutoff: bool },
    MaterializeWithTrace { early_cutoff: bool },
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
    ) {
        let Some(subject) = subject else {
            return;
        };
        let Some(payload) = self.force_cache_payload_for_value(value) else {
            if self.invalidate_cached_forced_expression_payload(&subject) {
                self.clear_persist_forced_expression_payload(&subject);
            }
            return;
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
            return;
        };
        let Some(payload) = self.prepare_observable_payload_for_subject(payload, &subject) else {
            self.invalidate_cached_forced_expression_payload(&subject);
            self.clear_persist_forced_expression_payload(&subject);
            return;
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
            return;
        };
        let persistence_action = if !use_impure_observation {
            match cache.observe_inline_expression_payload(
                identity,
                subject.free_var_value_hashes.iter().copied(),
                payload.clone(),
            ) {
                Ok(Some(reconsideration)) => Ok(ForcePayloadPersistenceAction::Materialize {
                    early_cutoff: reconsideration.decision() == CutoffDecision::CutOff,
                }),
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
                Ok(Some(observation)) if observation.node().is_some() => {
                    Ok(ForcePayloadPersistenceAction::MaterializeWithTrace {
                        early_cutoff: observation
                            .payload_reconsideration()
                            .map(|reconsideration| {
                                reconsideration.decision() == CutoffDecision::CutOff
                            })
                            .unwrap_or(false),
                    })
                }
                Ok(Some(_)) => Ok(ForcePayloadPersistenceAction::Clear),
                Ok(None) => Ok(ForcePayloadPersistenceAction::Skip),
                Err(error) => Err(error),
            }
        };
        drop(cache);
        match persistence_action {
            Ok(ForcePayloadPersistenceAction::Materialize { early_cutoff }) => {
                if early_cutoff {
                    self.increment_early_cutoffs();
                }
                if let Some(value_hash) = self.materialize_persist_forced_expression_payload(
                    &subject,
                    &payload,
                    materialization_cost_observation,
                ) && !self.record_persist_forced_expression_pure_trace(&subject, value_hash)
                {
                    self.clear_persist_forced_expression_payload(&subject);
                }
            }
            Ok(ForcePayloadPersistenceAction::MaterializeWithTrace { early_cutoff }) => {
                if early_cutoff {
                    self.increment_early_cutoffs();
                }
                if let Some(value_hash) = self.materialize_persist_forced_expression_payload(
                    &subject,
                    &payload,
                    materialization_cost_observation,
                ) && !self.record_persist_forced_expression_trace(&subject, value_hash, &trace)
                {
                    self.clear_persist_forced_expression_payload(&subject);
                }
            }
            Ok(ForcePayloadPersistenceAction::Clear) => {
                self.clear_persist_forced_expression_payload(&subject);
            }
            Ok(ForcePayloadPersistenceAction::Skip) => {}
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator forced expression observation failed"
                );
            }
        }
    }

    fn invalidate_cached_forced_expression_payload(&mut self, subject: &ForceCacheSubject) -> bool {
        let Some(identity) = subject.lookup_identity else {
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
        let Some(persist_cache) = &self.persist_cache else {
            return None;
        };
        let key = PersistNodeMetadataKey::for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        );
        let costs = cost_observation.costs(self.options.force_cache_materialization_costs());
        let signals = match persist_cache.node_materialization_signals(key, costs) {
            Ok(signals) => signals,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force materialization signals failed"
                );
                return None;
            }
        };
        if signals.decide() == MaterializationDecision::KeepInMemory {
            return None;
        }
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
        match persist_cache
            .materialize_cached_expression_node_value_indexed_with_signals(key, payload, signals)
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
        self.record_persist_forced_expression_trace_payload(subject, value_hash, &payload)
    }

    fn record_persist_forced_expression_trace(
        &mut self,
        subject: &ForceCacheSubject,
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
        self.record_persist_forced_expression_trace_payload(subject, value_hash, &payload)
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
        let identity = subject.lookup_identity?;
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping active force-cache node"
            );
            return None;
        };
        match cache.get_or_insert_expression_node(
            identity,
            subject.free_var_value_hashes.iter().copied(),
            None,
        ) {
            Ok(Some(node)) => Some(node),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator active force-cache node allocation failed"
                );
                None
            }
        }
    }

    fn record_active_force_cache_memo_read(
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
        let Some(active) = self.active_force_cache_nodes.last_mut() else {
            return;
        };
        if active.node() != dependent {
            tracing::warn!(
                target: "aos_nix::cache",
                dependent = dependent.as_u32(),
                active = active.node().as_u32(),
                "tree-walk evaluator active memo-read edge did not match the current force-cache node"
            );
            return;
        }
        active.memo_reads.insert(dependency);
    }

    pub(in crate::eval::tree_walk) fn record_enclosing_force_cache_memo_read(
        &mut self,
        dependency: DemandNodeId,
    ) {
        let dependent = self
            .active_force_cache_nodes
            .last()
            .map(ActiveForceCacheNode::node);
        self.record_active_force_cache_memo_read(dependent, dependency);
    }

    pub(in crate::eval::tree_walk) fn replace_active_force_cache_memo_reads(
        &mut self,
        active: ActiveForceCacheNode,
    ) {
        let (dependent, memo_reads) = active.into_parts();
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping memo-read edge replacement"
            );
            return;
        };
        if let Err(error) = cache.replace_memo_read_dependencies(dependent, memo_reads) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator memo-read edge replacement failed"
            );
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
            .active_force_cache_nodes
            .last()
            .map(ActiveForceCacheNode::node);

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
                self.record_active_force_cache_memo_read(active_force_cache_node, dependency);
                for fingerprint in trace {
                    self.record_impure_input(fingerprint);
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
            .active_force_cache_nodes
            .last()
            .map(ActiveForceCacheNode::node);
        self.open_persist_eval_cache();
        let persist_cache = self.persist_cache.as_ref()?;
        let key = PersistNodeMetadataKey::for_expression(
            identity,
            subject.free_var_value_hashes.iter().copied(),
        );
        let mut revalidator = TreeWalkImpureInputRevalidator::new(&self.options);
        let payload = match persist_cache
            .load_cached_expression_node_value_with_trace_revalidation(key, &mut revalidator)
        {
            Ok(Some(payload)) => payload,
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
        let dependency =
            self.observe_persist_forced_expression_runtime_hit(subject, payload, &trace);
        if let Some(dependency) = dependency {
            self.record_active_force_cache_memo_read(active_force_cache_node, dependency);
        }
        for fingerprint in trace {
            self.record_impure_input(fingerprint);
        }
        self.record_forced_expression_demand(subject);
        self.increment_eval_cache_hit();
        #[cfg(test)]
        self.persist_force_cache_hit_keys.push(key);
        Some(value)
    }

    fn observe_persist_forced_expression_runtime_hit(
        &mut self,
        subject: &ForceCacheSubject,
        payload: CachedExpressionValue,
        trace: &[ImpureInputFingerprint],
    ) -> Option<DemandNodeId> {
        let Some(identity) = subject.lookup_identity else {
            return None;
        };
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping persistent forced expression runtime observation"
            );
            return None;
        };
        if !cache.is_enabled() {
            return None;
        }
        let observation = if trace.is_empty() {
            cache
                .observe_inline_expression_payload(
                    identity,
                    subject.free_var_value_hashes.iter().copied(),
                    payload,
                )
                .map(|observation| observation.map(|reconsideration| reconsideration.node()))
        } else {
            let mut runtime_trace = Vec::new();
            if runtime_trace.try_reserve_exact(trace.len()).is_err() {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator persistent forced expression runtime trace allocation failed"
                );
                return None;
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
                .map(|observation| observation.and_then(|observation| observation.node()))
        };
        match observation {
            Ok(node) => node,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent forced expression runtime observation failed"
                );
                None
            }
        }
    }

    fn value_for_cached_expression_payload_for_subject(
        &mut self,
        payload: CachedExpressionValue,
        subject: &ForceCacheSubject,
    ) -> Option<Value> {
        let position_remap = self.payload_position_remap_for_subject(&payload, subject)?;
        self.value_for_cached_expression_payload_with_depth(payload, 0, position_remap)
    }

    fn prepare_observable_payload_for_subject(
        &self,
        payload: CachedExpressionValue,
        subject: &ForceCacheSubject,
    ) -> Option<CachedExpressionValue> {
        if !payload.retains_attr_positions() {
            return Some(payload);
        }
        let module = subject.replay_position_module?;
        if !payload.attr_positions_all_in_module(module.as_u32()) {
            return None;
        }
        let source_hash = self.cache_module_identity_hash_for_id(module)?;
        Some(payload.with_attr_position_source_hash(source_hash))
    }

    fn payload_position_remap_for_subject(
        &self,
        payload: &CachedExpressionValue,
        subject: &ForceCacheSubject,
    ) -> Option<Option<(u32, u32)>> {
        if !payload.retains_attr_positions() {
            return Some(None);
        }
        let target_module = subject.replay_position_module?;
        let source_hash = self.cache_module_identity_hash_for_id(target_module)?;
        if payload.attr_position_source_hash()? != source_hash {
            return None;
        }
        let target = target_module.as_u32();
        let mut modules = BTreeSet::new();
        payload.collect_attr_position_modules(&mut modules);
        let mut modules = modules.into_iter();
        let source = modules.next()?;
        if modules.next().is_some() {
            return None;
        }
        Some(Some((source, target)))
    }

    fn cache_module_identity_hash_for_id(&self, module: EvalModuleId) -> Option<DurableBlake3Hash> {
        Self::cache_module_identity_hash(self.modules.get(module.index())?)
    }

    fn remap_cached_attr_position(
        position: AttrPosition,
        position_remap: Option<(u32, u32)>,
    ) -> Option<AttrPosition> {
        let Some((source, target)) = position_remap else {
            return Some(position);
        };
        if position.module != source {
            return None;
        }
        Some(AttrPosition::new(target, position.span))
    }

    fn value_for_cached_expression_payload_with_depth(
        &mut self,
        payload: CachedExpressionValue,
        depth: usize,
        position_remap: Option<(u32, u32)>,
    ) -> Option<Value> {
        if depth > FORCE_CACHE_PAYLOAD_MAX_DEPTH {
            return None;
        }
        if let Some(value) = payload.immediate_value() {
            return Some(value);
        }
        if let Some(bytes) = payload.context_free_string_bytes() {
            let bytes = try_clone_bytes(bytes).ok()?;
            return self.heap.alloc_string(NixString::from_bytes(bytes)).ok();
        }
        if let Some((bytes, context)) = payload.context_string_parts() {
            let bytes = try_clone_bytes(bytes).ok()?;
            let context = context.try_clone_context().ok()?;
            return self.heap.alloc_string(NixString::new(bytes, context)).ok();
        }
        if let Some((bytes, context)) = payload.context_path_parts() {
            let bytes = try_clone_bytes(bytes).ok()?;
            let context = context.try_clone_context().ok()?;
            return self.heap.alloc_path(NixString::new(bytes, context)).ok();
        }
        if payload.is_empty_list() {
            return self.heap.alloc_list(NixList::empty()).ok();
        }
        if let Some(element_payloads) = payload.list_element_payloads() {
            let mut elements = Vec::new();
            elements.try_reserve_exact(element_payloads.len()).ok()?;
            for element in element_payloads {
                elements.push(self.value_for_cached_expression_payload_with_depth(
                    element,
                    depth.saturating_add(1),
                    position_remap,
                )?);
            }
            return self.heap.alloc_list(NixList::new(elements)).ok();
        }
        if payload.is_empty_attrs() {
            return self.heap.alloc_attrs(0, FlatAttrs::empty()).ok();
        }
        if let Some(attr_payloads) = payload.attrs_entries_with_positions() {
            let mut entries = Vec::new();
            entries.try_reserve_exact(attr_payloads.len()).ok()?;
            for (name, position, value_payload) in attr_payloads {
                let symbol = self.symbols.intern(&name).ok()?;
                let value = self.value_for_cached_expression_payload_with_depth(
                    value_payload,
                    depth.saturating_add(1),
                    position_remap,
                )?;
                let entry = match position {
                    Some(position) => {
                        let position = Self::remap_cached_attr_position(position, position_remap)?;
                        AttrEntry::with_position(symbol, value, position)
                    }
                    None => AttrEntry::new(symbol, value),
                };
                entries.push(entry);
            }
            let attrs = FlatAttrs::new(entries, &self.symbols).ok()?;
            return self.heap.alloc_attrs(0, attrs).ok();
        }
        let bytes = try_clone_bytes(payload.path_bytes()?).ok()?;
        self.heap.alloc_path(NixString::from_bytes(bytes)).ok()
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
        if let Err(error) = persist_cache.record_node_current_demand(key) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent force demand observation failed"
            );
        }
    }

    pub(in crate::eval::tree_walk) fn advance_persist_eval_cache_run_boundary(&mut self) {
        if !self.options.eval_cache_enabled() {
            return;
        }
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
        if let Err(error) = persist_cache.advance_all_node_materialization_reuse_runs() {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent force demand run-boundary advancement failed"
            );
        }
    }

    pub(in crate::eval::tree_walk) fn open_persist_eval_cache(&mut self) {
        if self.persist_cache.is_none() && !self.persist_cache_open_attempted {
            self.persist_cache_open_attempted = true;
            if let Some(root) = self.options.persist_cache_root().map(Path::to_path_buf) {
                self.persist_cache = PersistCache::open(root).ok();
            }
        }
    }
}
