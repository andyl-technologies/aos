//! Persistent force-trace recording and payload clearing.
//!
//! Encodes accepted (or pure) impure-input traces together with their
//! memo-read dependency records into [`PersistNodeTracePayload`] writebacks,
//! and owns the tombstoning clear path that keeps the sidecar consistent
//! when a payload is invalidated.

use super::*;

impl TreeWalk {
    pub(super) fn record_persist_forced_expression_pure_trace(
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

    pub(super) fn record_persist_forced_expression_trace(
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

    pub(super) fn clear_persist_forced_expression_payload(&mut self, subject: &ForceCacheSubject) {
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
}
