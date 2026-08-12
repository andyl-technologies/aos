//! Derivation ATerm path cache helpers.

use super::*;
use crate::cache::{CachedDerivationAtermPath, PersistBlobKey};

pub(super) struct DerivationAtermPathCacheResult {
    pub(super) path: nix_compat::store_path::StorePath<String>,
    pub(super) hash_derivation_modulo: Option<DerivationHashModulo>,
    pub(super) aterm_bytes: Option<Vec<u8>>,
}

impl TreeWalk {
    pub(super) fn active_derivation_aterm_memo_read_node_for_current_node(
        &mut self,
        id: IrId,
    ) -> Option<DemandNodeId> {
        let (identity, free_var_value_hashes) =
            self.derivation_aterm_cache_subject_for_current_node(id)?;
        self.active_memo_read_node_for_expression(identity, free_var_value_hashes.iter().copied())
    }

    pub(super) fn calculate_derivation_path_with_aterm_cache_result(
        &mut self,
        id: IrId,
        span: Span,
        name: &str,
        derivation: &nix_compat::derivation::Derivation,
        output_resolution: DerivationOutputResolution,
    ) -> Result<DerivationAtermPathCacheResult, TreeWalkError> {
        let aterm = match output_resolution {
            DerivationOutputResolution::StaticPaths => self.derivation_aterm_bytes(derivation),
            DerivationOutputResolution::FloatingCa(floating_ca_output) => {
                self.floating_ca_derivation_aterm_bytes(derivation, floating_ca_output, None)
            }
            DerivationOutputResolution::Impure(impure_output) => {
                self.impure_derivation_aterm_bytes(derivation, impure_output, None)
            }
            DerivationOutputResolution::DeferredPlaceholders => {
                return self
                    .calculate_derivation_path(id, span, name, derivation)
                    .map(|path| DerivationAtermPathCacheResult {
                        path,
                        hash_derivation_modulo: None,
                        aterm_bytes: None,
                    });
            }
        };
        if let Some(mut result) =
            self.lookup_derivation_aterm_path_for_current_node(id, name, &aterm)
        {
            result.aterm_bytes = Some(aterm);
            return Ok(result);
        }
        let path = self.calculate_derivation_path_from_aterm(id, span, name, derivation, &aterm)?;
        Ok(DerivationAtermPathCacheResult {
            path,
            hash_derivation_modulo: None,
            aterm_bytes: Some(aterm),
        })
    }

    fn lookup_derivation_aterm_path_for_current_node(
        &mut self,
        id: IrId,
        name: &str,
        aterm: &[u8],
    ) -> Option<DerivationAtermPathCacheResult> {
        if !self.eval_cache_runtime_enabled() {
            return None;
        }
        let (identity, free_var_value_hashes) =
            self.derivation_aterm_cache_subject_for_current_node(id)?;
        let (path_bytes, hash_derivation_modulo, mut dependency, persistent_hit) = if let Some((
            path_bytes,
            hash_derivation_modulo,
            dependency,
        )) = {
            let Ok(mut cache) = self.eval_cache.lock() else {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator cache lock was poisoned; skipping derivation ATerm path lookup"
                );
                return None;
            };
            match cache.lookup_derivation_aterm_path_hit_revalidating(
                identity,
                free_var_value_hashes.iter().copied(),
                aterm,
            ) {
                Ok(Some(hit)) => {
                    let dependency = hit.node();
                    let hash_derivation_modulo = hit.hash_derivation_modulo();
                    Some((hit.into_path_bytes(), hash_derivation_modulo, dependency))
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
            (path_bytes, hash_derivation_modulo, Some(dependency), false)
        } else {
            let payload =
                self.lookup_persist_derivation_aterm_path(identity, &free_var_value_hashes, aterm)?;
            let path_bytes = try_clone_bytes(payload.path_bytes()).ok()?;
            (path_bytes, payload.hash_derivation_modulo(), None, true)
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
            match self.observe_persist_derivation_aterm_path_runtime_hit(
                identity,
                &free_var_value_hashes,
                aterm,
                &path_bytes,
                hash_derivation_modulo,
            ) {
                PersistSideRecordRuntimeObservation::Accepted(observed) => {
                    dependency = Some(observed);
                }
                PersistSideRecordRuntimeObservation::Rejected => {
                    self.clear_persist_derivation_aterm_path(identity, &free_var_value_hashes);
                    return None;
                }
                PersistSideRecordRuntimeObservation::Skipped => {}
            }
        }
        if let Some(dependency) = dependency {
            self.record_enclosing_memo_read(dependency);
        }
        self.increment_derivation_aterm_path_reuses();
        Some(DerivationAtermPathCacheResult {
            path,
            hash_derivation_modulo: hash_derivation_modulo
                .map(DerivationHashModulo::from_nix_sha256_digest),
            aterm_bytes: None,
        })
    }

    fn lookup_persist_derivation_aterm_path(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[ValueHash],
        aterm: &[u8],
    ) -> Option<CachedDerivationAtermPath> {
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
        let payload_bytes =
            match persist_cache.read_blob_indexed(PersistBlobKey::for_value(value_hash)) {
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
        Some(payload)
    }

    fn observe_persist_derivation_aterm_path_runtime_hit(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[ValueHash],
        aterm: &[u8],
        path: &[u8],
        hash_derivation_modulo: Option<NixSha256Digest>,
    ) -> PersistSideRecordRuntimeObservation {
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping persistent derivation ATerm path runtime observation"
            );
            return PersistSideRecordRuntimeObservation::Skipped;
        };
        match cache.observe_derivation_aterm_expression_path_with_hash(
            identity,
            free_var_value_hashes.iter().copied(),
            aterm,
            path,
            hash_derivation_modulo,
        ) {
            Ok(Some(reconsideration)) => {
                PersistSideRecordRuntimeObservation::Accepted(reconsideration.node())
            }
            Ok(None) => PersistSideRecordRuntimeObservation::Rejected,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path runtime observation failed"
                );
                PersistSideRecordRuntimeObservation::Rejected
            }
        }
    }

    pub(super) fn observe_derivation_aterm_expression(
        &mut self,
        id: IrId,
        span: Span,
        drv_path: &nix_compat::store_path::StorePath<String>,
        derivation: &nix_compat::derivation::Derivation,
        known_hash: DerivationHashModulo,
        output_resolution: DerivationOutputResolution,
        precomputed_aterm: Option<&[u8]>,
    ) {
        if !self.eval_cache_runtime_enabled() {
            return;
        }
        let Some((identity, free_var_value_hashes)) =
            self.derivation_aterm_cache_subject_for_current_node(id)
        else {
            return;
        };
        let computed_aterm;
        let aterm = if let Some(aterm) = precomputed_aterm {
            aterm
        } else {
            computed_aterm = match self.derivation_aterm_bytes_for_observation(
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
            computed_aterm.as_slice()
        };
        let drv_path_bytes = self.store_path_absolute_bytes(drv_path);
        let mut rejected = false;
        let (observed, early_cutoff) = {
            let Ok(mut cache) = self.eval_cache.lock() else {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator cache lock was poisoned; skipping derivation ATerm observation"
                );
                return;
            };
            match cache.observe_derivation_aterm_expression_path_with_hash(
                identity,
                free_var_value_hashes.iter().copied(),
                &aterm,
                &drv_path_bytes,
                Some(known_hash.nix_sha256_digest()),
            ) {
                Ok(Some(reconsideration)) => {
                    (true, reconsideration.decision() == CutoffDecision::CutOff)
                }
                Ok(None) => {
                    rejected = cache.is_enabled();
                    (false, false)
                }
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
        let persistable = self.active_derivation_side_record_trace_is_persistable();
        if observed && persistable {
            self.materialize_persist_derivation_aterm_path(
                identity,
                &free_var_value_hashes,
                &aterm,
                &drv_path_bytes,
                Some(known_hash.nix_sha256_digest()),
            );
        } else if rejected || !persistable {
            self.clear_persist_derivation_aterm_path(identity, &free_var_value_hashes);
        }
        if early_cutoff {
            self.increment_early_cutoffs();
        }
    }

    fn materialize_persist_derivation_aterm_path(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[ValueHash],
        aterm: &[u8],
        drv_path: &[u8],
        hash_derivation_modulo: Option<NixSha256Digest>,
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
        let payload = if let Some(hash_derivation_modulo) = hash_derivation_modulo {
            CachedDerivationAtermPath::with_hash_derivation_modulo(
                aterm,
                drv_path,
                hash_derivation_modulo,
            )
        } else {
            CachedDerivationAtermPath::new(aterm, drv_path)
        };
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
            PersistBlobKey::for_value(value_hash),
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

    pub(super) fn clear_persist_derivation_aterm_path(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[ValueHash],
    ) {
        if !self.options.eval_cache_enabled() {
            return;
        }
        self.open_persist_eval_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
        let key =
            PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
        if let Err(error) = persist_cache.clear_node_materialized_value_hash(key) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent derivation ATerm path metadata clear failed"
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
