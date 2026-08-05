//! Enabled/disabled evaluator cache runtime facade.

use super::*;

/// Optional evaluator cache runtime state.
#[derive(Clone, Debug, Default)]
pub enum EvalCacheRuntime {
    /// Cache observation is disabled and all operations are no-ops.
    #[default]
    Disabled,
    /// Cache observation is enabled against an in-memory [`EvalCache`].
    Enabled(EvalCache),
}

impl EvalCacheRuntime {
    /// Creates a disabled cache runtime.
    pub fn disabled() -> Self {
        Self::Disabled
    }

    /// Creates an enabled cache runtime with an empty cache.
    pub fn enabled() -> Self {
        Self::Enabled(EvalCache::new())
    }

    /// Creates a cache runtime from an enable switch.
    pub fn from_enabled(enabled: bool) -> Self {
        if enabled {
            Self::enabled()
        } else {
            Self::disabled()
        }
    }

    /// Returns whether cache observation is enabled.
    pub const fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled(_))
    }

    /// Returns the enabled cache, if observation is enabled.
    pub const fn cache(&self) -> Option<&EvalCache> {
        match self {
            Self::Disabled => None,
            Self::Enabled(cache) => Some(cache),
        }
    }

    /// Returns the enabled cache mutably, if observation is enabled.
    pub fn cache_mut(&mut self) -> Option<&mut EvalCache> {
        match self {
            Self::Disabled => None,
            Self::Enabled(cache) => Some(cache),
        }
    }

    fn clean_reconsideration(
        cache: &EvalCache,
        reconsideration: Reconsideration,
    ) -> Result<Option<Reconsideration>, DemandGraphError> {
        let node = cache.graph().node(reconsideration.node())?;
        if node.freshness() == NodeFreshness::Dirty {
            return Ok(None);
        }
        Ok(Some(reconsideration))
    }

    fn clean_trace_observation(
        cache: &EvalCache,
        observation: ExpressionTraceObservation,
    ) -> Result<ExpressionTraceObservation, DemandGraphError> {
        let Some(node) = observation.node() else {
            return Ok(observation);
        };
        if cache.graph().node(node)?.freshness() != NodeFreshness::Dirty {
            return Ok(observation);
        }
        let (_, trace) = observation.into_parts();
        Ok(ExpressionTraceObservation::new(None, trace))
    }

    #[cfg(test)]
    pub(crate) fn test_mark_dirty_node(
        &mut self,
        node: DemandNodeId,
    ) -> Result<Option<()>, DemandGraphError> {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.test_mark_dirty_node(node).map(Some)
    }

    /// Returns a dirty-frontier snapshot when cache observation is enabled.
    ///
    /// Disabled runtimes return `None`; enabled runtimes delegate to
    /// [`EvalCache::dirty_frontier`]. This method is read-only and does not
    /// validate or recompute graph nodes.
    pub fn dirty_frontier(&self) -> Option<DirtyFrontier> {
        self.cache().map(EvalCache::dirty_frontier)
    }

    /// Recomputes ready dirty graph nodes when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without invoking `recompute`.
    /// Enabled runtimes delegate to [`EvalCache::recompute_ready_dirty_nodes`].
    /// The caller still owns evaluator recomputation, value hashing, dynamic
    /// dependency capture, and persistence.
    ///
    /// # Errors
    ///
    /// Returns graph scheduling/reconsideration errors converted through `E`
    /// from the enabled cache, or any caller error returned by `recompute`. If
    /// `recompute` fails after earlier nodes in the same call were reconsidered,
    /// those graph mutations are retained and the partial
    /// [`RecomputeReadyDirty`] result is not returned.
    pub fn recompute_ready_dirty_nodes<E, F>(
        &mut self,
        recompute: F,
    ) -> Result<Option<RecomputeReadyDirty>, E>
    where
        E: From<DemandGraphError>,
        F: FnMut(DemandNodeId) -> Result<ValueHash, E>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.recompute_ready_dirty_nodes(recompute).map(Some)
    }

    /// Observes evaluator impure-input traces when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without examining `source` or
    /// allocating demand-graph nodes. Enabled runtimes delegate to
    /// [`EvalCache::observe_impure_inputs`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to observe the trace.
    pub fn observe_impure_inputs<S>(
        &mut self,
        source: &S,
    ) -> Result<Option<ImpureTraceObservation>, DemandGraphError>
    where
        S: ImpureInputTraceSource + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.observe_impure_inputs(source).map(Some)
    }

    /// Observes evaluator impure-input traces and wires them to a node when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating `dependent`.
    /// Enabled runtimes delegate to [`EvalCache::observe_impure_inputs_for_node`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to observe or wire the trace.
    pub fn observe_impure_inputs_for_node<S>(
        &mut self,
        dependent: DemandNodeId,
        source: &S,
    ) -> Result<Option<ImpureTraceObservation>, DemandGraphError>
    where
        S: ImpureInputTraceSource + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_impure_inputs_for_node(dependent, source)
            .map(Some)
    }

    /// Observes one expression evaluation trace when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without examining `source` or
    /// allocating demand-graph nodes. Enabled runtimes delegate to
    /// [`EvalCache::observe_expression_impure_inputs`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to observe, allocate, or wire the expression trace.
    pub fn observe_expression_impure_inputs<I, S>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value_hash: Option<ValueHash>,
        source: &S,
    ) -> Result<Option<ExpressionTraceObservation>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
        S: ImpureInputTraceSource + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_expression_impure_inputs(identity, free_var_value_hashes, value_hash, source)
            .map(Some)
    }

    /// Records same-run memoization demand when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity. Enabled runtimes delegate to
    /// [`EvalCache::record_memoization_demand`]. This records telemetry and
    /// evaluates the caller-selected subject policy; it does not probe, insert,
    /// or invalidate memoized value payloads.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key.
    pub fn record_memoization_demand<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        subject: MemoizationSubject,
        cheap_value_hash: bool,
    ) -> Result<Option<MemoizationObservation>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .record_memoization_demand(identity, free_var_value_hashes, subject, cheap_value_hash)
            .map(Some)
    }

    /// Returns same-run memoization demand when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity. Enabled runtimes delegate to [`EvalCache::memoization_demand`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key.
    pub fn memoization_demand<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<MemoizationDemand>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache() else {
            return Ok(None);
        };
        cache.memoization_demand(identity, free_var_value_hashes)
    }

    /// Looks up a clean inline expression result when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity. Enabled runtimes delegate to
    /// [`EvalCache::lookup_inline_expression_result`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key or invalidate a blocked side
    /// payload.
    pub fn lookup_inline_expression_result<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<Value>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.lookup_inline_expression_result(identity, free_var_value_hashes)
    }

    /// Looks up a clean expression payload when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity. Enabled runtimes delegate to
    /// [`EvalCache::lookup_inline_expression_payload`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key or invalidate a blocked side
    /// payload.
    pub fn lookup_inline_expression_payload<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<CachedExpressionValue>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.lookup_inline_expression_payload(identity, free_var_value_hashes)
    }

    /// Looks up a clean inline result with impure-input revalidation when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or calling `revalidator`. Enabled runtimes delegate to
    /// [`EvalCache::lookup_inline_expression_result_with_impure_inputs`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key, observe a fresh input, or
    /// invalidate an unusable payload.
    pub fn lookup_inline_expression_result_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<Value>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.lookup_inline_expression_result_with_impure_inputs(
            identity,
            free_var_value_hashes,
            revalidator,
        )
    }

    /// Looks up a cached derivation `.drv` path for matching ATerm bytes when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or ATerm bytes. Enabled runtimes delegate to
    /// [`EvalCache::lookup_derivation_aterm_path`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key or invalidate a blocked side
    /// payload.
    pub(crate) fn lookup_derivation_aterm_path<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Option<Vec<u8>>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.lookup_derivation_aterm_path(identity, free_var_value_hashes, aterm)
    }

    pub(crate) fn lookup_derivation_aterm_path_hit_revalidating<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Option<CachedDerivationAtermPathHit>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.lookup_derivation_aterm_path_hit_revalidating(identity, free_var_value_hashes, aterm)
    }

    /// Looks up cached static derivation output paths for matching ATerm bytes when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or pre-output ATerm bytes. Enabled runtimes delegate to
    /// [`EvalCache::lookup_static_derivation_output_paths`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key or invalidate a blocked side
    /// payload.
    pub(crate) fn lookup_static_derivation_output_paths<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
    ) -> Result<Option<CachedDerivationOutputPaths>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.lookup_static_derivation_output_paths(
            identity,
            free_var_value_hashes,
            pre_output_aterm,
        )
    }

    pub(crate) fn lookup_static_derivation_output_paths_hit_revalidating<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
    ) -> Result<Option<CachedStaticDerivationOutputPathsHit>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.lookup_static_derivation_output_paths_hit_revalidating(
            identity,
            free_var_value_hashes,
            pre_output_aterm,
        )
    }

    /// Looks up a revalidatable expression payload when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or calling `revalidator`. Enabled runtimes delegate to
    /// [`EvalCache::lookup_inline_expression_payload_with_impure_inputs`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key, observe a fresh input, or
    /// invalidate an unusable payload.
    pub fn lookup_inline_expression_payload_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<CachedExpressionValue>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.lookup_inline_expression_payload_with_impure_inputs(
            identity,
            free_var_value_hashes,
            revalidator,
        )
    }

    pub(crate) fn lookup_inline_expression_payload_hit_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<CachedExpressionPayloadHit>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.lookup_inline_expression_payload_hit_with_impure_inputs(
            identity,
            free_var_value_hashes,
            revalidator,
        )
    }

    pub(crate) fn get_or_insert_expression_node<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value_hash: Option<ValueHash>,
    ) -> Result<Option<DemandNodeId>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .get_or_insert_expression_node(identity, free_var_value_hashes, value_hash)
            .map(Some)
    }

    pub(crate) fn replace_memo_read_dependencies<I>(
        &mut self,
        dependent: DemandNodeId,
        dependencies: I,
    ) -> Result<Option<bool>, DemandGraphError>
    where
        I: IntoIterator<Item = DemandNodeId>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .replace_memo_read_dependencies(dependent, dependencies)
            .map(Some)
    }

    pub(crate) fn memo_read_dependency_persist_keys(
        &self,
        node: DemandNodeId,
        trace_inputs: &[CacheableInputFingerprint],
    ) -> Result<Option<Vec<(PersistNodeMetadataKey, bool)>>, DemandGraphError> {
        let Some(cache) = self.cache() else {
            return Ok(None);
        };
        cache.memo_read_dependency_persist_keys(node, trace_inputs)
    }

    pub(crate) fn replace_memo_read_dependencies_by_persist_keys(
        &mut self,
        dependent: DemandNodeId,
        dependency_keys: &[PersistNodeMetadataKey],
    ) -> Result<Option<bool>, DemandGraphError> {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .replace_memo_read_dependencies_by_persist_keys(dependent, dependency_keys)
            .map(Some)
    }

    /// Returns whether every durable memo-read key names a live runtime node.
    ///
    /// Disabled runtimes return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`DemandGraphError`] if a mapped runtime node is invalid.
    pub(crate) fn memo_read_dependencies_resolved_by_persist_keys(
        &self,
        dependency_keys: &[PersistNodeMetadataKey],
    ) -> Result<Option<bool>, DemandGraphError> {
        let Some(cache) = self.cache() else {
            return Ok(None);
        };
        cache
            .memo_read_dependencies_resolved_by_persist_keys(dependency_keys)
            .map(Some)
    }

    /// Observes one inline expression result when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or value. Enabled runtimes delegate to
    /// [`EvalCache::observe_inline_expression_result`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to insert/reconsider the expression node or hash the inline value.
    pub fn observe_inline_expression_result<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: Value,
    ) -> Result<Option<Reconsideration>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_inline_expression_result(identity, free_var_value_hashes, value)
            .and_then(|reconsideration| Self::clean_reconsideration(cache, reconsideration))
    }

    /// Observes one expression payload when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or value. Enabled runtimes delegate to
    /// [`EvalCache::observe_inline_expression_payload`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to insert/reconsider the expression node or hash the payload.
    pub fn observe_inline_expression_payload<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: CachedExpressionValue,
    ) -> Result<Option<Reconsideration>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_inline_expression_payload(identity, free_var_value_hashes, value)
            .and_then(|reconsideration| Self::clean_reconsideration(cache, reconsideration))
    }

    /// Observes one derivation ATerm expression when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or ATerm bytes. Enabled runtimes delegate to
    /// [`EvalCache::observe_derivation_aterm_expression`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to insert/reconsider the expression node.
    pub fn observe_derivation_aterm_expression<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Option<Reconsideration>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_derivation_aterm_expression(identity, free_var_value_hashes, aterm)
            .map(Some)
    }

    /// Observes one derivation ATerm expression and `.drv` path when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity, ATerm bytes, or path bytes. Enabled runtimes delegate to
    /// [`EvalCache::observe_derivation_aterm_expression_path`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to insert/reconsider the expression node.
    pub(crate) fn observe_derivation_aterm_expression_path<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
        drv_path: &[u8],
    ) -> Result<Option<Reconsideration>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        self.observe_derivation_aterm_expression_path_with_hash(
            identity,
            free_var_value_hashes,
            aterm,
            drv_path,
            None,
        )
    }

    pub(crate) fn observe_derivation_aterm_expression_path_with_hash<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
        drv_path: &[u8],
        hash_derivation_modulo: Option<NixSha256Digest>,
    ) -> Result<Option<Reconsideration>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_derivation_aterm_expression_path_with_hash(
                identity,
                free_var_value_hashes,
                aterm,
                drv_path,
                hash_derivation_modulo,
            )
            .and_then(|reconsideration| Self::clean_reconsideration(cache, reconsideration))
    }

    /// Observes resolved static derivation output paths when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity, pre-output ATerm bytes, or output path payload. Enabled
    /// runtimes delegate to [`EvalCache::observe_static_derivation_output_paths`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to insert/reconsider the expression node.
    pub(crate) fn observe_static_derivation_output_paths<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
        output_paths: CachedDerivationOutputPaths,
    ) -> Result<Option<Reconsideration>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_static_derivation_output_paths(
                identity,
                free_var_value_hashes,
                pre_output_aterm,
                output_paths,
            )
            .and_then(|reconsideration| Self::clean_reconsideration(cache, reconsideration))
    }

    /// Invalidates one inline expression payload when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity. Enabled runtimes delegate to
    /// [`EvalCache::invalidate_inline_expression_payload`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression key or mark an existing node dirty.
    pub fn invalidate_inline_expression_payload<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<bool>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .invalidate_inline_expression_payload(identity, free_var_value_hashes)
            .map(Some)
    }

    /// Observes one inline expression result and its impure inputs when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity, value, or trace. Enabled runtimes delegate to
    /// [`EvalCache::observe_inline_expression_result_with_impure_inputs`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to observe or wire the expression trace, hash the inline value, or
    /// insert/reconsider the expression node.
    pub fn observe_inline_expression_result_with_impure_inputs<I, S>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: Value,
        source: &S,
    ) -> Result<Option<ExpressionTraceObservation>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
        S: ImpureInputTraceSource + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                free_var_value_hashes,
                value,
                source,
            )
            .and_then(|observation| Self::clean_trace_observation(cache, observation).map(Some))
    }

    /// Observes one expression payload and its impure inputs when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity, value, or trace. Enabled runtimes delegate to
    /// [`EvalCache::observe_inline_expression_payload_with_impure_inputs`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to observe or wire the expression trace, hash the payload, or
    /// insert/reconsider the expression node.
    pub fn observe_inline_expression_payload_with_impure_inputs<I, S>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: CachedExpressionValue,
        source: &S,
    ) -> Result<Option<ExpressionTraceObservation>, DemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
        S: ImpureInputTraceSource + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_inline_expression_payload_with_impure_inputs(
                identity,
                free_var_value_hashes,
                value,
                source,
            )
            .and_then(|observation| Self::clean_trace_observation(cache, observation).map(Some))
    }
}
