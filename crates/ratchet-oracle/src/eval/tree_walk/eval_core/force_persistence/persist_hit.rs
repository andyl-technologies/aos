//! Force-cache lookups and persistent-tier hit replay.
//!
//! Owns the in-memory force-cache lookup choke point
//! ([`TreeWalk::lookup_forced_inline_expression_result`]) and the
//! persistent-tier fallback it delegates to on a miss: loading a node's
//! materialized value and trace, revalidating impure inputs, replaying the
//! payload into the live heap, and re-observing the hit into the in-memory
//! cache so cutoff reconsideration and memo-read edges stay wired.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistRuntimeHitObservation {
    Accepted {
        node: DemandNodeId,
        early_cutoff: bool,
    },
    DurableOnly,
    Rejected,
    Skipped,
}

impl TreeWalk {
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
            PersistRuntimeHitObservation::DurableOnly => {
                self.increment_early_cutoffs();
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
        match cache.memo_read_dependencies_resolved_by_persist_keys(memo_read_dependencies) {
            Ok(Some(true)) => {}
            Ok(Some(false)) | Ok(None) => {
                // The persistent lookup recursively revalidated every durable
                // supplier and pinned value hash before reaching this point.
                // Replaying that value is safe, but installing it in the fresh
                // runtime graph without supplier nodes would leave no edge to
                // invalidate later. Keep this as a durable-only hit until the
                // suppliers have been instantiated in memory.
                return PersistRuntimeHitObservation::DurableOnly;
            }
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent force dependency resolution failed"
                );
                return PersistRuntimeHitObservation::Rejected;
            }
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
}
