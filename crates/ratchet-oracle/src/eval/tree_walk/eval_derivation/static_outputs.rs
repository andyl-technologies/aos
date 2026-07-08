//! Static derivation output path cache helpers.

use super::*;
use crate::cache::{CachedStaticDerivationOutputPathsPayload, PersistBlobKey};

impl TreeWalk {
    pub(super) fn resolve_static_derivation_outputs_with_cache(
        &mut self,
        id: IrId,
        span: Span,
        name: &str,
        derivation: &mut nix_compat::derivation::Derivation,
        input_hashes: &KnownDerivationInputHashes,
    ) -> Result<DerivationHashModulo, TreeWalkError> {
        // The pre-output ATerm serialization only feeds cache keys; skip the
        // full serialization pass entirely when the eval cache runtime is
        // disabled (both the lookup and the observation below no-op then).
        let pre_output_aterm = self.eval_cache_runtime_enabled().then(|| {
            self.derivation_aterm_bytes_with_input_hashes(derivation, &input_hashes.hashes)
        });
        if let Some(pre_output_aterm) = pre_output_aterm.as_deref()
            && let Some((
                cached,
                _persistent_hit,
                _identity,
                _free_var_value_hashes,
                dependency,
                early_cutoff,
            )) = self.lookup_static_derivation_output_paths_for_current_node(id, pre_output_aterm)
            && let Some(known_hash) =
                self.apply_static_derivation_output_paths_from_cache(id, name, derivation, &cached)
        {
            if let Some(dependency) = dependency {
                self.record_enclosing_memo_read(dependency);
            }
            if early_cutoff {
                self.increment_early_cutoffs();
            }
            return Ok(known_hash);
        }

        let hash =
            self.hash_derivation_modulo_with_inputs(id, span, derivation, &input_hashes.hashes)?;
        self.calculate_output_paths(id, span, name, derivation, &hash)?;
        let known_hash =
            self.hash_derivation_modulo_with_inputs(id, span, derivation, &input_hashes.hashes)?;
        if let Some(pre_output_aterm) = pre_output_aterm.as_deref() {
            self.observe_static_derivation_output_paths(
                id,
                pre_output_aterm,
                derivation,
                known_hash,
            );
        }
        Ok(known_hash)
    }

    fn lookup_static_derivation_output_paths_for_current_node(
        &mut self,
        id: IrId,
        pre_output_aterm: &[u8],
    ) -> Option<(
        CachedDerivationOutputPaths,
        bool,
        CacheExprIdentity,
        Vec<ValueHash>,
        Option<DemandNodeId>,
        bool,
    )> {
        if !self.eval_cache_runtime_enabled() {
            return None;
        }
        let (identity, free_var_value_hashes) =
            self.static_derivation_outputs_cache_subject_for_current_node(id)?;
        if let Some((paths, dependency, early_cutoff)) = {
            let Ok(mut cache) = self.eval_cache.lock() else {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator cache lock was poisoned; skipping static derivation output path lookup"
                );
                return None;
            };
            match cache.lookup_static_derivation_output_paths_hit_revalidating(
                identity,
                free_var_value_hashes.iter().copied(),
                pre_output_aterm,
            ) {
                Ok(Some(hit)) => {
                    let early_cutoff = hit
                        .reconsideration()
                        .map(|reconsideration| reconsideration.decision() == CutoffDecision::CutOff)
                        .unwrap_or(false);
                    let dependency = hit.node();
                    Some((hit.into_output_paths(), dependency, early_cutoff))
                }
                Ok(None) => None,
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator static derivation output path lookup failed"
                    );
                    None
                }
            }
        } {
            return Some((
                paths,
                false,
                identity,
                free_var_value_hashes,
                Some(dependency),
                early_cutoff,
            ));
        }
        let paths = self.lookup_persist_static_derivation_output_paths(
            identity,
            &free_var_value_hashes,
            pre_output_aterm,
        )?;
        let observation = self.observe_persist_static_derivation_output_paths_runtime_hit(
            identity,
            &free_var_value_hashes,
            pre_output_aterm,
            paths.clone(),
        );
        match observation {
            PersistSideRecordRuntimeObservation::Accepted(dependency) => Some((
                paths,
                true,
                identity,
                free_var_value_hashes,
                Some(dependency),
                false,
            )),
            PersistSideRecordRuntimeObservation::Rejected => {
                self.clear_persist_static_derivation_output_paths(identity, &free_var_value_hashes);
                None
            }
            PersistSideRecordRuntimeObservation::Skipped => {
                Some((paths, true, identity, free_var_value_hashes, None, false))
            }
        }
    }

    fn lookup_persist_static_derivation_output_paths(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[ValueHash],
        pre_output_aterm: &[u8],
    ) -> Option<CachedDerivationOutputPaths> {
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
                    "tree-walk evaluator persistent static derivation output metadata lookup failed"
                );
                return None;
            }
        };
        let payload_bytes = match persist_cache
            .read_blob_indexed(PersistBlobKey::for_value(value_hash))
        {
            Ok(Some(payload_bytes)) => payload_bytes,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent static derivation output payload read failed"
                );
                return None;
            }
        };
        let payload = match CachedStaticDerivationOutputPathsPayload::decode_persistent_payload(
            &payload_bytes,
        ) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent static derivation output payload decode failed"
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
                "tree-walk evaluator persistent static derivation output payload hash mismatch"
            );
            return None;
        }
        if payload.pre_output_aterm_bytes() != pre_output_aterm {
            return None;
        }
        Some(payload.into_output_paths())
    }

    fn observe_persist_static_derivation_output_paths_runtime_hit(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[ValueHash],
        pre_output_aterm: &[u8],
        output_paths: CachedDerivationOutputPaths,
    ) -> PersistSideRecordRuntimeObservation {
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping persistent static derivation output runtime observation"
            );
            return PersistSideRecordRuntimeObservation::Skipped;
        };
        match cache.observe_static_derivation_output_paths(
            identity,
            free_var_value_hashes.iter().copied(),
            pre_output_aterm,
            output_paths,
        ) {
            Ok(Some(reconsideration)) => {
                PersistSideRecordRuntimeObservation::Accepted(reconsideration.node())
            }
            Ok(None) => PersistSideRecordRuntimeObservation::Rejected,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent static derivation output runtime observation failed"
                );
                PersistSideRecordRuntimeObservation::Rejected
            }
        }
    }

    fn apply_static_derivation_output_paths_from_cache(
        &mut self,
        id: IrId,
        name: &str,
        derivation: &mut nix_compat::derivation::Derivation,
        cached: &CachedDerivationOutputPaths,
    ) -> Option<DerivationHashModulo> {
        let mut output_paths = BTreeMap::new();
        for cached_path in cached.output_paths() {
            let output_name = match std::str::from_utf8(cached_path.name()) {
                Ok(output_name) => output_name.to_owned(),
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        node = ?id,
                        error = %error,
                        "tree-walk evaluator cached static derivation output name was not UTF-8"
                    );
                    return None;
                }
            };
            if !derivation.outputs.contains_key(&output_name) {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = ?id,
                    output = %output_name,
                    "tree-walk evaluator cached static derivation output path had an unknown output"
                );
                return None;
            }
            let Some(path_in_store) = self.strip_configured_store_dir(cached_path.path()) else {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = ?id,
                    output = %output_name,
                    path = %String::from_utf8_lossy(cached_path.path()),
                    "tree-walk evaluator cached static derivation output path was outside the configured store dir"
                );
                return None;
            };
            let path = match nix_compat::store_path::StorePath::<String>::from_bytes(path_in_store)
            {
                Ok(path) => path,
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        node = ?id,
                        output = %output_name,
                        path = %String::from_utf8_lossy(cached_path.path()),
                        error = %error,
                        "tree-walk evaluator cached static derivation output path was invalid"
                    );
                    return None;
                }
            };
            let expected_name = Self::output_path_name(name, &output_name);
            if path.name().as_str() != expected_name.as_str() {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = ?id,
                    output = %output_name,
                    expected = %expected_name,
                    actual = %path.name().as_str(),
                    "tree-walk evaluator cached static derivation output path had the wrong output name"
                );
                return None;
            }
            if output_paths.insert(output_name, path).is_some() {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = ?id,
                    "tree-walk evaluator cached static derivation output path repeated an output"
                );
                return None;
            }
        }
        if output_paths.len() != derivation.outputs.len() {
            tracing::warn!(
                target: "aos_nix::cache",
                node = ?id,
                expected = derivation.outputs.len(),
                actual = output_paths.len(),
                "tree-walk evaluator cached static derivation output paths had the wrong output count"
            );
            return None;
        }

        for (output_name, path) in output_paths {
            let env_value = self.store_path_absolute_bytes(&path).into();
            let output = derivation.outputs.get_mut(&output_name)?;
            if output.path.is_some() {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = ?id,
                    output = %output_name,
                    "tree-walk evaluator cached static derivation output path targeted an already resolved output"
                );
                return None;
            }
            output.path = Some(path);
            derivation.environment.insert(output_name, env_value);
        }
        self.increment_static_derivation_output_path_reuses();
        Some(DerivationHashModulo::from_nix_sha256_digest(
            cached.hash_derivation_modulo(),
        ))
    }

    fn observe_static_derivation_output_paths(
        &mut self,
        id: IrId,
        pre_output_aterm: &[u8],
        derivation: &nix_compat::derivation::Derivation,
        known_hash: DerivationHashModulo,
    ) {
        if !self.eval_cache_runtime_enabled() {
            return;
        }
        let Some((identity, free_var_value_hashes)) =
            self.static_derivation_outputs_cache_subject_for_current_node(id)
        else {
            return;
        };
        let Some(output_paths) =
            self.static_derivation_output_paths_payload(derivation, known_hash)
        else {
            return;
        };
        let mut rejected = false;
        let observed = {
            let Ok(mut cache) = self.eval_cache.lock() else {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator cache lock was poisoned; skipping static derivation output path observation"
                );
                return;
            };
            match cache.observe_static_derivation_output_paths(
                identity,
                free_var_value_hashes.iter().copied(),
                pre_output_aterm,
                output_paths.clone(),
            ) {
                Ok(Some(_)) => true,
                Ok(None) => {
                    rejected = cache.is_enabled();
                    false
                }
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator static derivation output path observation failed"
                    );
                    false
                }
            }
        };
        let persistable = self.active_derivation_side_record_trace_is_persistable();
        if observed && persistable {
            self.materialize_persist_static_derivation_output_paths(
                identity,
                &free_var_value_hashes,
                pre_output_aterm,
                output_paths,
            );
        } else if rejected || !persistable {
            self.clear_persist_static_derivation_output_paths(identity, &free_var_value_hashes);
        }
    }

    fn materialize_persist_static_derivation_output_paths(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[ValueHash],
        pre_output_aterm: &[u8],
        output_paths: CachedDerivationOutputPaths,
    ) {
        if !self.options.eval_cache_enabled() {
            return;
        }
        self.open_persist_eval_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
        let pre_output_aterm = match try_clone_bytes(pre_output_aterm) {
            Ok(pre_output_aterm) => pre_output_aterm,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent static derivation output payload allocation failed"
                );
                return;
            }
        };
        let payload = CachedStaticDerivationOutputPathsPayload::new(pre_output_aterm, output_paths);
        let value_hash = payload.value_hash();
        let payload_bytes = match payload.encode_persistent_payload() {
            Ok(payload_bytes) => payload_bytes,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent static derivation output payload encode failed"
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
                "tree-walk evaluator persistent static derivation output payload write failed"
            );
            return;
        }
        let key =
            PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
        if let Err(error) = persist_cache.record_node_materialized_value_hash(key, value_hash) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent static derivation output metadata write failed"
            );
        }
    }

    pub(super) fn clear_persist_static_derivation_output_paths(
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
                "tree-walk evaluator persistent static derivation output metadata clear failed"
            );
        }
    }

    fn static_derivation_output_paths_payload(
        &self,
        derivation: &nix_compat::derivation::Derivation,
        known_hash: DerivationHashModulo,
    ) -> Option<CachedDerivationOutputPaths> {
        let mut output_paths = Vec::new();
        output_paths
            .try_reserve_exact(derivation.outputs.len())
            .ok()?;
        for (output_name, output) in &derivation.outputs {
            let path = output.path.as_ref()?;
            output_paths.push(CachedDerivationOutputPath::new(
                output_name.as_bytes().to_vec(),
                self.store_path_absolute_bytes(path),
            ));
        }
        Some(CachedDerivationOutputPaths::new(
            known_hash.nix_sha256_digest(),
            output_paths,
        ))
    }
}
