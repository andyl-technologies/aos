//! Derivation ATerm path cache helpers.

use super::*;
use crate::cache::{CachedDerivationAtermPath, PersistBlobKey};

impl TreeWalk {
    pub(super) fn active_derivation_aterm_memo_read_node_for_current_node(
        &mut self,
        id: IrId,
    ) -> Option<DemandNodeId> {
        let (identity, free_var_value_hashes) =
            self.derivation_aterm_cache_subject_for_current_node(id)?;
        self.active_memo_read_node_for_expression(identity, free_var_value_hashes.iter().copied())
    }

    pub(super) fn calculate_derivation_path_with_aterm_cache(
        &mut self,
        id: IrId,
        span: Span,
        name: &str,
        derivation: &nix_compat::derivation::Derivation,
        output_resolution: DerivationOutputResolution,
    ) -> Result<nix_compat::store_path::StorePath<String>, TreeWalkError> {
        let aterm = match output_resolution {
            DerivationOutputResolution::StaticPaths => self.derivation_aterm_bytes(derivation),
            DerivationOutputResolution::FloatingCa(floating_ca_output) => {
                self.floating_ca_derivation_aterm_bytes(derivation, floating_ca_output, None)
            }
            DerivationOutputResolution::Impure(impure_output) => {
                self.impure_derivation_aterm_bytes(derivation, impure_output, None)
            }
            DerivationOutputResolution::DeferredPlaceholders => {
                return self.calculate_derivation_path(id, span, name, derivation);
            }
        };
        if let Some(path) = self.lookup_derivation_aterm_path_for_current_node(id, name, &aterm) {
            return Ok(path);
        }
        self.calculate_derivation_path_from_aterm(id, span, name, derivation, &aterm)
    }

    fn lookup_derivation_aterm_path_for_current_node(
        &mut self,
        id: IrId,
        name: &str,
        aterm: &[u8],
    ) -> Option<nix_compat::store_path::StorePath<String>> {
        if !self.eval_cache_runtime_enabled() {
            return None;
        }
        let (identity, free_var_value_hashes) =
            self.derivation_aterm_cache_subject_for_current_node(id)?;
        let (path_bytes, mut dependency, persistent_hit) = if let Some((path_bytes, dependency)) = {
            let Ok(cache) = self.eval_cache.lock() else {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator cache lock was poisoned; skipping derivation ATerm path lookup"
                );
                return None;
            };
            match cache.lookup_derivation_aterm_path_hit(
                identity,
                free_var_value_hashes.iter().copied(),
                aterm,
            ) {
                Ok(Some(hit)) => {
                    let dependency = hit.node();
                    Some((hit.into_path_bytes(), dependency))
                }
                Ok(None) => None,
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator derivation ATerm path lookup failed"
                    );
                    None
                }
            }
        } {
            (path_bytes, Some(dependency), false)
        } else {
            let path_bytes =
                self.lookup_persist_derivation_aterm_path(identity, &free_var_value_hashes, aterm)?;
            (path_bytes, None, true)
        };
        let Some(path_in_store) = self.strip_configured_store_dir(&path_bytes) else {
            tracing::warn!(
                target: "aos_nix::cache",
                node = ?id,
                path = %String::from_utf8_lossy(&path_bytes),
                "tree-walk evaluator derivation ATerm cached path was outside the configured store dir"
            );
            return None;
        };
        let path = match nix_compat::store_path::StorePath::<String>::from_bytes(path_in_store) {
            Ok(path) => path,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = ?id,
                    path = %String::from_utf8_lossy(&path_bytes),
                    error = %error,
                    "tree-walk evaluator derivation ATerm cached path was invalid"
                );
                return None;
            }
        };
        let expected_name = format!("{name}.drv");
        if path.name().as_str() != expected_name.as_str() {
            tracing::warn!(
                target: "aos_nix::cache",
                node = ?id,
                expected = %expected_name,
                actual = %path.name().as_str(),
                "tree-walk evaluator derivation ATerm cached path had the wrong derivation name"
            );
            return None;
        }
        if persistent_hit {
            dependency = self.observe_persist_derivation_aterm_path_runtime_hit(
                identity,
                &free_var_value_hashes,
                aterm,
                &path_bytes,
            );
        }
        if let Some(dependency) = dependency {
            self.record_enclosing_memo_read(dependency);
        }
        self.increment_derivation_aterm_path_reuses();
        Some(path)
    }

    fn lookup_persist_derivation_aterm_path(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[DurableBlake3Hash],
        aterm: &[u8],
    ) -> Option<Vec<u8>> {
        if !self.options.eval_cache_enabled() {
            return None;
        }
        self.open_persist_eval_cache();
        let persist_cache = self.persist_cache.as_ref()?;
        let key =
            PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
        let value_hash = match persist_cache.lookup_node_materialized_value_hash(key) {
            Ok(Some(value_hash)) => value_hash,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path metadata lookup failed"
                );
                return None;
            }
        };
        let payload_bytes = match persist_cache
            .read_blob_indexed(PersistBlobKey::for_value(value_hash.as_durable_hash()))
        {
            Ok(Some(payload_bytes)) => payload_bytes,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path payload read failed"
                );
                return None;
            }
        };
        let payload = match CachedDerivationAtermPath::decode_persistent_payload(&payload_bytes) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path payload decode failed"
                );
                return None;
            }
        };
        let actual = payload.value_hash();
        if actual != value_hash {
            tracing::warn!(
                target: "aos_nix::cache",
                expected = ?value_hash,
                actual = ?actual,
                "tree-walk evaluator persistent derivation ATerm path payload hash mismatch"
            );
            return None;
        }
        if payload.aterm_bytes() != aterm {
            return None;
        }
        try_clone_bytes(payload.path_bytes()).ok()
    }

    fn observe_persist_derivation_aterm_path_runtime_hit(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[DurableBlake3Hash],
        aterm: &[u8],
        path: &[u8],
    ) -> Option<DemandNodeId> {
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping persistent derivation ATerm path runtime observation"
            );
            return None;
        };
        match cache.observe_derivation_aterm_expression_path(
            identity,
            free_var_value_hashes.iter().copied(),
            aterm,
            path,
        ) {
            Ok(Some(reconsideration)) => Some(reconsideration.node()),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path runtime observation failed"
                );
                None
            }
        }
    }

    pub(super) fn observe_derivation_aterm_expression(
        &mut self,
        id: IrId,
        span: Span,
        drv_path: &nix_compat::store_path::StorePath<String>,
        derivation: &nix_compat::derivation::Derivation,
        output_resolution: DerivationOutputResolution,
    ) {
        if !self.eval_cache_runtime_enabled() {
            return;
        }
        let Some((identity, free_var_value_hashes)) =
            self.derivation_aterm_cache_subject_for_current_node(id)
        else {
            return;
        };
        let aterm = match self.derivation_aterm_bytes_for_observation(
            id,
            span,
            drv_path,
            derivation,
            output_resolution,
        ) {
            Ok(aterm) => aterm,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator derivation ATerm cache observation failed to serialize"
                );
                return;
            }
        };
        let drv_path_bytes = self.store_path_absolute_bytes(drv_path);
        let (observed, early_cutoff) = {
            let Ok(mut cache) = self.eval_cache.lock() else {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator cache lock was poisoned; skipping derivation ATerm observation"
                );
                return;
            };
            match cache.observe_derivation_aterm_expression_path(
                identity,
                free_var_value_hashes.iter().copied(),
                &aterm,
                &drv_path_bytes,
            ) {
                Ok(Some(reconsideration)) => {
                    (true, reconsideration.decision() == CutoffDecision::CutOff)
                }
                Ok(None) => (true, false),
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator derivation ATerm cache observation failed"
                    );
                    (false, false)
                }
            }
        };
        if observed {
            self.materialize_persist_derivation_aterm_path(
                identity,
                &free_var_value_hashes,
                &aterm,
                &drv_path_bytes,
            );
        }
        if early_cutoff {
            self.increment_early_cutoffs();
        }
    }

    fn materialize_persist_derivation_aterm_path(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[DurableBlake3Hash],
        aterm: &[u8],
        drv_path: &[u8],
    ) {
        if !self.options.eval_cache_enabled() {
            return;
        }
        self.open_persist_eval_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
        let aterm = match try_clone_bytes(aterm) {
            Ok(aterm) => aterm,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path payload allocation failed"
                );
                return;
            }
        };
        let drv_path = match try_clone_bytes(drv_path) {
            Ok(drv_path) => drv_path,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path payload allocation failed"
                );
                return;
            }
        };
        let payload = CachedDerivationAtermPath::new(aterm, drv_path);
        let value_hash = payload.value_hash();
        let payload_bytes = match payload.encode_persistent_payload() {
            Ok(payload_bytes) => payload_bytes,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path payload encode failed"
                );
                return;
            }
        };
        if let Err(error) = persist_cache.materialize_blob_indexed(
            PersistBlobKey::for_value(value_hash.as_durable_hash()),
            &payload_bytes,
            MaterializationDecision::Materialize,
        ) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent derivation ATerm path payload write failed"
            );
            return;
        }
        let key =
            PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
        if let Err(error) = persist_cache.record_node_materialized_value_hash(key, value_hash) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent derivation ATerm path metadata write failed"
            );
        }
    }

    fn derivation_aterm_bytes_for_observation(
        &self,
        id: IrId,
        span: Span,
        drv_path: &nix_compat::store_path::StorePath<String>,
        derivation: &nix_compat::derivation::Derivation,
        output_resolution: DerivationOutputResolution,
    ) -> Result<Vec<u8>, TreeWalkError> {
        match output_resolution {
            DerivationOutputResolution::StaticPaths => Ok(self.derivation_aterm_bytes(derivation)),
            DerivationOutputResolution::FloatingCa(floating_ca_output) => {
                Ok(self.floating_ca_derivation_aterm_bytes(derivation, floating_ca_output, None))
            }
            DerivationOutputResolution::Impure(impure_output) => {
                Ok(self.impure_derivation_aterm_bytes(derivation, impure_output, None))
            }
            DerivationOutputResolution::DeferredPlaceholders => {
                self.deferred_placeholder_derivation_aterm_bytes(id, span, drv_path, derivation)
            }
        }
    }
}
