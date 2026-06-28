//! Caller-owned evaluator cache state and observation methods.

use super::*;

/// Explicit evaluator cache state owned by the caller.
#[derive(Clone, Debug, Default)]
pub struct EvalCache {
    pub(super) graph: DemandGraph,
    pub(super) inline_values: BTreeMap<DemandNodeId, InlineValueRecord>,
    pub(super) derivation_aterm_paths: BTreeMap<DemandNodeId, DerivationAtermPathRecord>,
    pub(super) static_derivation_output_paths:
        BTreeMap<DemandNodeId, StaticDerivationOutputPathRecord>,
    pub(super) memoization_demands: HashMap<DemandCacheKey, MemoizationDemand>,
}

impl EvalCache {
    /// Creates an empty evaluator cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an evaluator cache from an existing demand graph.
    pub fn from_graph(graph: DemandGraph) -> Self {
        Self {
            graph,
            inline_values: BTreeMap::new(),
            derivation_aterm_paths: BTreeMap::new(),
            static_derivation_output_paths: BTreeMap::new(),
            memoization_demands: HashMap::new(),
        }
    }

    /// Returns the number of nodes in the underlying demand graph.
    pub fn len(&self) -> usize {
        self.graph.len()
    }

    /// Returns whether the underlying demand graph has no nodes.
    pub fn is_empty(&self) -> bool {
        self.graph.is_empty()
    }

    /// Returns the underlying demand graph.
    pub const fn graph(&self) -> &DemandGraph {
        &self.graph
    }

    #[cfg(test)]
    pub(crate) fn derivation_aterm_path_record_count(&self) -> usize {
        self.derivation_aterm_paths.len()
    }

    #[cfg(test)]
    pub(crate) fn static_derivation_output_path_record_count(&self) -> usize {
        self.static_derivation_output_paths.len()
    }

    #[cfg(test)]
    pub(crate) fn test_mark_dirty_node(
        &mut self,
        node: DemandNodeId,
    ) -> Result<(), DemandGraphError> {
        self.graph.mark_dirty(node)
    }

    /// Consumes this cache into its demand graph.
    pub fn into_graph(self) -> DemandGraph {
        self.graph
    }

    /// Returns a deterministic scheduling snapshot for dirty graph nodes.
    ///
    /// This is a read-only adapter over [`DemandGraph::dirty_frontier`]. It
    /// does not recompute nodes, mutate freshness, or schedule evaluator work.
    pub fn dirty_frontier(&self) -> DirtyFrontier {
        self.graph.dirty_frontier()
    }

    /// Records same-run memoization demand and evaluates the subject policy.
    ///
    /// This API stores admission signals beside the demand graph without
    /// allocating graph nodes or probing/persisting value payloads. Callers
    /// supply the computation subject and whether the value hash is cheap or
    /// already available; the cache records one current-run demand for the
    /// expression key and returns the default policy decision for the updated
    /// demand.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails.
    pub fn record_memoization_demand<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        subject: MemoizationSubject,
        cheap_value_hash: bool,
    ) -> Result<MemoizationObservation, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let demand = self
            .memoization_demands
            .entry(key)
            .or_default()
            .record_current_demand();
        self.memoization_demands.insert(key, demand);
        let decision = subject
            .default_class()
            .decide(demand.signals(cheap_value_hash));
        Ok(MemoizationObservation::new(demand, decision))
    }

    /// Returns same-run memoization demand for an expression key.
    ///
    /// This read path is telemetry-only: it does not allocate demand-graph
    /// nodes, mutate demand counters, or evaluate admission policy.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails.
    pub fn memoization_demand<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<MemoizationDemand>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        Ok(self.memoization_demands.get(&key).copied())
    }

    /// Recomputes ready dirty graph nodes through a caller-supplied callback.
    ///
    /// This is an explicit adapter over
    /// [`DemandGraph::recompute_ready_dirty_nodes`]. It schedules ready dirty
    /// demand nodes and applies graph early cutoff, but the caller still owns
    /// evaluator recomputation, value hashing, dynamic dependency capture, and
    /// persistence.
    ///
    /// # Errors
    ///
    /// Returns graph scheduling/reconsideration errors converted through `E`, or
    /// any caller error returned by `recompute`. If `recompute` fails after
    /// earlier nodes in the same call were reconsidered, those graph mutations
    /// are retained and the partial [`RecomputeReadyDirty`] result is not
    /// returned.
    pub fn recompute_ready_dirty_nodes<E, F>(
        &mut self,
        recompute: F,
    ) -> Result<RecomputeReadyDirty, E>
    where
        E: From<DemandGraphError>,
        F: FnMut(DemandNodeId) -> Result<ValueHash, E>,
    {
        self.graph.recompute_ready_dirty_nodes(recompute)
    }

    /// Looks up a clean memoized expression payload.
    ///
    /// This is a precursor memo path for force-time cache hits. It returns a
    /// payload only when the expression key already exists, its demand node is
    /// clean, the side payload record is reusable without input revalidation,
    /// and that payload still matches the node's value hash. Unknown, dirty,
    /// missing-payload, trace-backed, and stale-payload nodes are cache misses.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails.
    pub fn lookup_inline_expression_payload<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<CachedExpressionValue>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        Ok(self
            .lookup_inline_expression_payload_hit(identity, free_var_value_hashes)?
            .map(CachedExpressionPayloadHit::into_value))
    }

    pub(crate) fn lookup_inline_expression_payload_hit<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<CachedExpressionPayloadHit>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        let Some(record) = self.inline_values.get(&node).cloned() else {
            return Ok(None);
        };
        if !record.is_reusable_without_revalidation() {
            return Ok(None);
        }
        if graph_node.value_hash() != Some(record.value_hash) {
            return Ok(None);
        }
        Ok(Some(CachedExpressionPayloadHit::new(node, record.value())))
    }

    /// Looks up a clean memoized immediate expression result.
    ///
    /// This compatibility path returns only immediate scalar values. Heap-backed
    /// payloads are misses for callers that cannot rehydrate them into their own
    /// heap.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails.
    pub fn lookup_inline_expression_result<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<Value>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        Ok(self
            .lookup_inline_expression_payload(identity, free_var_value_hashes)?
            .and_then(|value| value.immediate_value()))
    }

    /// Looks up a clean cached derivation `.drv` path for matching ATerm bytes.
    ///
    /// This is a path-lookup precursor for future derivationStrict SHA-256
    /// short-circuiting. It returns stored `.drv` path bytes only when the
    /// caller-supplied expression key exists, the demand node is clean, a
    /// derivation path side record exists, the side record's ATerm hash matches
    /// `aterm`, and the graph node's value hash still matches the full side
    /// payload hash. Unknown, dirty, missing, and stale records are misses.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails.
    pub(crate) fn lookup_derivation_aterm_path<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Option<Vec<u8>>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        Ok(self
            .lookup_derivation_aterm_path_hit(identity, free_var_value_hashes, aterm)?
            .map(CachedDerivationAtermPathHit::into_path_bytes))
    }

    pub(crate) fn lookup_derivation_aterm_path_hit<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Option<CachedDerivationAtermPathHit>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        let Some(record) = self.derivation_aterm_paths.get(&node) else {
            return Ok(None);
        };
        let aterm_value_hash = ValueHash::from_derivation_aterm_bytes(aterm);
        if record.aterm_value_hash != aterm_value_hash
            || graph_node.value_hash() != Some(record.payload_value_hash)
        {
            return Ok(None);
        }
        Ok(Some(CachedDerivationAtermPathHit::new(
            node,
            record.path_bytes(),
        )))
    }

    pub(crate) fn lookup_derivation_aterm_path_hit_revalidating<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Option<CachedDerivationAtermPathHit>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        let Some(record) = self.derivation_aterm_paths.get(&node).cloned() else {
            return Ok(None);
        };
        let aterm_value_hash = ValueHash::from_derivation_aterm_bytes(aterm);
        if record.aterm_value_hash != aterm_value_hash
            || graph_node.value_hash() != Some(record.payload_value_hash)
        {
            return Ok(None);
        }
        if graph_node.freshness() == NodeFreshness::Clean {
            return Ok(Some(CachedDerivationAtermPathHit::new(
                node,
                record.path_bytes(),
            )));
        }
        let reconsideration = self
            .graph
            .reconsider_node(node, record.payload_value_hash)?;
        Ok(Some(CachedDerivationAtermPathHit::with_reconsideration(
            node,
            record.path_bytes(),
            reconsideration,
        )))
    }

    /// Looks up clean cached static derivation output paths for matching ATerm bytes.
    ///
    /// This is a pre-output-path precursor for future `derivationStrict`
    /// SHA-256 short-circuiting. It returns stored output paths and the final
    /// derivation hash modulo only when the caller-supplied expression key
    /// exists, the demand node is clean, a static-output side record exists,
    /// the side record's pre-output hash matches `pre_output_aterm`, and the
    /// graph node's value hash still matches the full side payload hash.
    /// Unknown, dirty, missing, and stale records are misses.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails.
    pub(crate) fn lookup_static_derivation_output_paths<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
    ) -> Result<Option<CachedDerivationOutputPaths>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        Ok(self
            .lookup_static_derivation_output_paths_hit(
                identity,
                free_var_value_hashes,
                pre_output_aterm,
            )?
            .map(CachedStaticDerivationOutputPathsHit::into_output_paths))
    }

    pub(crate) fn lookup_static_derivation_output_paths_hit<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
    ) -> Result<Option<CachedStaticDerivationOutputPathsHit>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        let Some(record) = self.static_derivation_output_paths.get(&node) else {
            return Ok(None);
        };
        let pre_output_value_hash = ValueHash::from_derivation_aterm_bytes(pre_output_aterm);
        if record.pre_output_value_hash != pre_output_value_hash
            || graph_node.value_hash() != Some(record.payload_value_hash)
        {
            return Ok(None);
        }
        Ok(Some(CachedStaticDerivationOutputPathsHit::new(
            node,
            record.output_paths(),
        )))
    }

    pub(crate) fn lookup_static_derivation_output_paths_hit_revalidating<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
    ) -> Result<Option<CachedStaticDerivationOutputPathsHit>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        let Some(record) = self.static_derivation_output_paths.get(&node).cloned() else {
            return Ok(None);
        };
        let pre_output_value_hash = ValueHash::from_derivation_aterm_bytes(pre_output_aterm);
        if record.pre_output_value_hash != pre_output_value_hash
            || graph_node.value_hash() != Some(record.payload_value_hash)
        {
            return Ok(None);
        }
        if graph_node.freshness() == NodeFreshness::Clean {
            return Ok(Some(CachedStaticDerivationOutputPathsHit::new(
                node,
                record.output_paths(),
            )));
        }
        let reconsideration = self
            .graph
            .reconsider_node(node, record.payload_value_hash)?;
        Ok(Some(
            CachedStaticDerivationOutputPathsHit::with_reconsideration(
                node,
                record.output_paths(),
                reconsideration,
            ),
        ))
    }

    /// Looks up a clean expression payload after impure-input revalidation.
    ///
    /// Pure payload records are handled identically to
    /// [`EvalCache::lookup_inline_expression_payload`]. Trace-backed payload
    /// records are returned only if every stored cacheable input identity can be
    /// revalidated, the fresh identity still matches the stored identity, the
    /// fresh observation hash still matches the stored observation hash, and the
    /// expression node remains clean with the recorded value hash. Revalidation
    /// observes fresh input leaves through the demand graph so changed inputs
    /// dirty dependents through the ordinary cutoff path.
    ///
    /// Inputs that cannot be revalidated, revalidate to an uncacheable
    /// fingerprint, or revalidate to a different identity invalidate the
    /// expression payload and return a miss.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, graph
    /// node lookup fails, fresh input observation fails, or dirty marking
    /// fails.
    pub fn lookup_inline_expression_payload_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<CachedExpressionValue>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        Ok(self
            .lookup_inline_expression_payload_hit_with_impure_inputs(
                identity,
                free_var_value_hashes,
                revalidator,
            )?
            .map(CachedExpressionPayloadHit::into_value))
    }

    pub(crate) fn lookup_inline_expression_payload_hit_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<CachedExpressionPayloadHit>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        let Some(record) = self.inline_values.get(&node).cloned() else {
            return Ok(None);
        };
        if graph_node.value_hash() != Some(record.value_hash) {
            return Ok(None);
        }
        if record.is_reusable_without_revalidation() {
            return Ok(Some(CachedExpressionPayloadHit::new(node, record.value())));
        }
        if !self.revalidate_inline_record_inputs(node, &record, revalidator)? {
            return Ok(None);
        }
        let graph_node = self.graph.node(node)?;
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        if graph_node.value_hash() != Some(record.value_hash) {
            return Ok(None);
        }
        Ok(Some(CachedExpressionPayloadHit::new(node, record.value())))
    }

    /// Looks up a clean immediate result after impure-input revalidation.
    ///
    /// This compatibility path returns only immediate scalar values. Heap-backed
    /// payloads are misses for callers that cannot rehydrate them into their own
    /// heap.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, graph
    /// node lookup fails, fresh input observation fails, or dirty marking
    /// fails.
    pub fn lookup_inline_expression_result_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<Value>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        Ok(self
            .lookup_inline_expression_payload_with_impure_inputs(
                identity,
                free_var_value_hashes,
                revalidator,
            )?
            .and_then(|value| value.immediate_value()))
    }

    /// Gets or inserts an expression node in the underlying demand graph.
    ///
    /// This is an explicit graph-allocation helper. Callers still supply the
    /// expression identity, ordered free-variable value hashes, and optional
    /// current value hash.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails or if the
    /// underlying graph cannot reserve node/key storage.
    pub fn get_or_insert_expression_node<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value_hash: Option<ValueHash>,
    ) -> Result<DemandNodeId, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        self.graph
            .get_or_insert_expression_node(identity, free_var_value_hashes, value_hash)
    }

    pub(crate) fn record_memo_read_dependency(
        &mut self,
        dependent: DemandNodeId,
        dependency: DemandNodeId,
    ) -> Result<(), DemandGraphError> {
        self.graph
            .add_dependency_to_group(dependent, DemandDependencyGroup::MemoRead, dependency)
    }

    pub(crate) fn replace_memo_read_dependencies<I>(
        &mut self,
        dependent: DemandNodeId,
        dependencies: I,
    ) -> Result<(), DemandGraphError>
    where
        I: IntoIterator<Item = DemandNodeId>,
    {
        self.graph.replace_dependency_group(
            dependent,
            DemandDependencyGroup::MemoRead,
            dependencies,
        )
    }

    /// Observes impure inputs from one completed evaluator trace source.
    ///
    /// This delegates to [`DemandGraph::observe_impure_trace`]. It records only
    /// cacheable input leaves and cacheability status; it does not create
    /// evaluating-node demand edges or memoized value records.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if the underlying graph cannot reserve
    /// storage or cannot insert/reconsider a cacheable input leaf.
    pub fn observe_impure_inputs<T>(
        &mut self,
        source: &T,
    ) -> Result<ImpureTraceObservation, DemandGraphError>
    where
        T: ImpureInputTraceSource + ?Sized,
    {
        self.graph.observe_impure_trace(
            source.impure_input_trace(),
            source.impure_input_trace_complete(),
        )
    }

    /// Observes impure inputs and wires cacheable leaves to an existing node.
    ///
    /// `dependent` must be a caller-supplied node in this cache's demand graph.
    /// This delegates trace edge wiring to
    /// [`DemandGraph::observe_impure_trace_for_node`]. Incomplete or
    /// uncacheable traces also remove side payload records for `dependent` and
    /// its transitive memo-read dependents. This does not create evaluating
    /// nodes or memoized value records.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if the dependent node is unknown, if
    /// trace observation fails, or if dependency edge insertion fails.
    pub fn observe_impure_inputs_for_node<T>(
        &mut self,
        dependent: DemandNodeId,
        source: &T,
    ) -> Result<ImpureTraceObservation, DemandGraphError>
    where
        T: ImpureInputTraceSource + ?Sized,
    {
        let observation = self.graph.observe_impure_trace_for_node(
            dependent,
            source.impure_input_trace(),
            source.impure_input_trace_complete(),
        )?;
        if observation.status() != ImpureTraceStatus::Cacheable {
            let affected_dependents = self.graph.invalidate_node(dependent)?;
            self.remove_side_payloads(dependent);
            for dependent in affected_dependents {
                self.remove_side_payloads(dependent);
            }
        }
        Ok(observation)
    }

    /// Observes an expression evaluation trace and wires cacheable leaves to its node.
    ///
    /// This first computes the expression key and observes the trace.
    /// Incomplete or uncacheable traces return their status without creating a
    /// new expression node; if the expression key already exists, any side
    /// inline payload is invalidated, its transitive memo-read dependents are
    /// dirtied, and its stale input dependencies are cleared.
    /// Complete cacheable traces get or insert the caller-supplied expression
    /// node, invalidate any prior side inline payload, and then replace that
    /// node's impure-input dependency group with the observed input leaves.
    ///
    /// This is still an explicit adapter: callers supply expression identity,
    /// ordered free-variable value hashes, and the optional current value hash.
    /// It does not compute evaluator identities, perform memo lookup, or own
    /// dynamic evaluator node lifecycle.
    ///
    /// Successful leaf observations are not rolled back if expression-node
    /// allocation or edge replacement later fails.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if trace observation fails, expression
    /// cache-key construction or insertion fails, an existing payload cannot be
    /// invalidated, or dependency edge replacement fails.
    pub fn observe_expression_impure_inputs<I, T>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value_hash: Option<ValueHash>,
        source: &T,
    ) -> Result<ExpressionTraceObservation, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        T: ImpureInputTraceSource + ?Sized,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let existing_node = self.graph.node_id_for_key(key);
        let trace = self.observe_impure_inputs(source)?;
        if trace.status() != ImpureTraceStatus::Cacheable {
            if let Some(node) = existing_node {
                self.invalidate_existing_inline_payload(Some(node))?;
                self.graph.replace_dependency_group(
                    node,
                    DemandDependencyGroup::ImpureInput,
                    std::iter::empty::<DemandNodeId>(),
                )?;
            }
            return Ok(ExpressionTraceObservation::new(None, trace));
        }

        self.invalidate_existing_inline_payload_if_present(existing_node)?;
        let node = self.graph.get_or_insert_node(key, value_hash)?;
        self.graph.replace_dependency_group(
            node,
            DemandDependencyGroup::ImpureInput,
            trace.leaves().iter().map(|leaf| leaf.node()),
        )?;
        Ok(ExpressionTraceObservation::new(Some(node), trace))
    }

    /// Observes one recomputed expression payload.
    ///
    /// This is the first force-path integration point for the demand graph:
    /// callers still provide the expression identity and ordered free-variable
    /// hashes, and the cache only records/reconsiders the payload value hash.
    /// It does not perform memo lookup, compute free-variable hashes, or
    /// serialize general heap-backed values.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, or the node cannot be reconsidered.
    pub fn observe_inline_expression_payload<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: CachedExpressionValue,
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let record = InlineValueRecord::reusable_without_revalidation(value)
            .map_err(|source| DemandGraphError::ValueHash { source })?;
        let node = self.get_or_insert_expression_node(identity, free_var_value_hashes, None)?;
        let reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
        self.inline_values.insert(node, record);
        Ok(reconsideration)
    }

    /// Observes one recomputed derivation ATerm expression.
    ///
    /// Callers still provide the expression identity and ordered free-variable
    /// hashes. The cache hashes the recorded `.drv` ATerm bytes as a comparison
    /// key and reconsiders the expression node, but it does not memoize a value
    /// payload or compute Nix-observed SHA-256 `.drv` hashes or store paths.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, or the node cannot be reconsidered.
    pub fn observe_derivation_aterm_expression<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let node = self.get_or_insert_expression_node(identity, free_var_value_hashes, None)?;
        self.graph.reconsider_derivation_aterm_node(node, aterm)
    }

    /// Observes one recomputed derivation ATerm expression and `.drv` path.
    ///
    /// This extends [`Self::observe_derivation_aterm_expression`] with a side
    /// record containing caller-supplied `.drv` path bytes. The path record is
    /// usable only through [`Self::lookup_derivation_aterm_path`] when the graph
    /// node remains clean, the same ATerm hash still matches, and the graph
    /// node still carries the full ATerm/path payload hash. This API does not
    /// compute Nix-observed SHA-256 `.drv` hashes or store paths.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, or the node cannot be reconsidered.
    pub(crate) fn observe_derivation_aterm_expression_path<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
        drv_path: &[u8],
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let node = self.get_or_insert_expression_node(identity, free_var_value_hashes, None)?;
        let record = DerivationAtermPathRecord::new(aterm, drv_path);
        let reconsideration = self
            .graph
            .reconsider_node(node, record.payload_value_hash)?;
        self.derivation_aterm_paths.insert(node, record);
        Ok(reconsideration)
    }

    /// Observes resolved static derivation output paths for pre-output ATerm bytes.
    ///
    /// This records a side payload containing caller-supplied output paths and
    /// the final derivation hash modulo. The payload is usable only through
    /// [`Self::lookup_static_derivation_output_paths`] while the graph node
    /// remains clean, the same pre-output ATerm hash still matches, and the
    /// graph node still carries the full side payload hash. This API does not
    /// compute Nix-observed SHA-256 output paths itself.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, or the node cannot be reconsidered.
    pub(crate) fn observe_static_derivation_output_paths<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
        output_paths: CachedDerivationOutputPaths,
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let node = self.get_or_insert_expression_node(identity, free_var_value_hashes, None)?;
        let record = StaticDerivationOutputPathRecord::new(pre_output_aterm, output_paths);
        let reconsideration = self
            .graph
            .reconsider_node(node, record.payload_value_hash)?;
        self.static_derivation_output_paths.insert(node, record);
        Ok(reconsideration)
    }

    /// Invalidates an existing inline expression payload.
    ///
    /// If the expression key already exists, the node and its transitive
    /// memo-read dependents are marked dirty and their side payloads are
    /// removed. Missing keys return `Ok(false)`.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails or the
    /// existing node cannot be marked dirty.
    pub fn invalidate_inline_expression_payload<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<bool, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(false);
        };
        self.invalidate_existing_inline_payload(Some(node))?;
        Ok(true)
    }

    /// Observes one recomputed immediate expression result.
    ///
    /// This compatibility path accepts only immediate scalar values.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, the node cannot be reconsidered, or the value is not an
    /// inline scalar supported by [`ValueHash::from_inline_value`].
    pub fn observe_inline_expression_result<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: Value,
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let value = CachedExpressionValue::immediate(value)
            .map_err(|source| DemandGraphError::ValueHash { source })?;
        self.observe_inline_expression_payload(identity, free_var_value_hashes, value)
    }

    /// Observes one recomputed expression payload with its impure inputs.
    ///
    /// Cacheable traces get or insert the expression node, replace its
    /// dependencies with the observed input leaves, reconsider the node from
    /// the payload value hash, and store the side payload plus the cacheable
    /// input fingerprints
    /// required by
    /// [`EvalCache::lookup_inline_expression_payload_with_impure_inputs`].
    /// Incomplete or uncacheable traces return their status without creating a
    /// new expression node or payload; if the expression key already exists,
    /// its prior inline payload and stale dependencies are removed and the node
    /// is marked dirty.
    ///
    /// Successful leaf observations are not rolled back if expression-node
    /// allocation, edge replacement, or value reconsideration later fails.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if trace observation fails, expression
    /// cache-key construction or insertion fails, dependency edge replacement
    /// fails, dirty marking fails, or node reconsideration fails.
    pub fn observe_inline_expression_payload_with_impure_inputs<I, T>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: CachedExpressionValue,
        source: &T,
    ) -> Result<ExpressionTraceObservation, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        T: ImpureInputTraceSource + ?Sized,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        self.observe_inline_expression_payload_for_key_with_impure_inputs(key, value, source)
    }

    fn observe_inline_expression_payload_for_key_with_impure_inputs<T>(
        &mut self,
        key: DemandCacheKey,
        value: CachedExpressionValue,
        source: &T,
    ) -> Result<ExpressionTraceObservation, DemandGraphError>
    where
        T: ImpureInputTraceSource + ?Sized,
    {
        let existing_node = self.graph.node_id_for_key(key);
        let trace = self.observe_impure_inputs(source)?;
        if trace.status() != ImpureTraceStatus::Cacheable {
            self.invalidate_existing_inline_payload(existing_node)?;
            if let Some(node) = existing_node {
                self.graph.replace_dependency_group(
                    node,
                    DemandDependencyGroup::ImpureInput,
                    std::iter::empty::<DemandNodeId>(),
                )?;
            }
            return Ok(ExpressionTraceObservation::new(None, trace));
        }

        let record = match InlineValueRecord::requires_revalidation(value, source) {
            Ok(record) => record,
            Err(error) => {
                self.invalidate_existing_inline_payload(existing_node)?;
                if let Some(node) = existing_node {
                    self.graph.replace_dependency_group(
                        node,
                        DemandDependencyGroup::ImpureInput,
                        std::iter::empty::<DemandNodeId>(),
                    )?;
                }
                return Err(error);
            }
        };
        let node = self.graph.get_or_insert_node(key, None)?;
        self.graph.replace_dependency_group(
            node,
            DemandDependencyGroup::ImpureInput,
            trace.leaves().iter().map(|leaf| leaf.node()),
        )?;
        let payload_reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
        self.inline_values.insert(node, record);
        Ok(ExpressionTraceObservation::with_payload_reconsideration(
            node,
            trace,
            payload_reconsideration,
        ))
    }

    /// Observes one recomputed immediate expression result with its impure inputs.
    ///
    /// This compatibility path accepts only immediate scalar values.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if inline value hashing fails, trace
    /// observation fails, expression cache-key construction or insertion fails,
    /// dependency edge insertion fails, dirty marking fails, or node
    /// reconsideration fails.
    pub fn observe_inline_expression_result_with_impure_inputs<I, T>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: Value,
        source: &T,
    ) -> Result<ExpressionTraceObservation, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        T: ImpureInputTraceSource + ?Sized,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let value = match CachedExpressionValue::immediate(value) {
            Ok(value) => value,
            Err(source) => {
                let existing_node = self.graph.node_id_for_key(key);
                self.invalidate_existing_inline_payload(existing_node)?;
                return Err(DemandGraphError::ValueHash { source });
            }
        };
        self.observe_inline_expression_payload_for_key_with_impure_inputs(key, value, source)
    }

    /// Reconsiders one node from a recomputed inline scalar value.
    ///
    /// This delegates to [`DemandGraph::reconsider_inline_value_node`]. It does
    /// not implement heap-backed canonical value hashing or memo lookup.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if inline value hashing fails or if the
    /// node is unknown.
    pub fn reconsider_inline_value_node(
        &mut self,
        id: DemandNodeId,
        value: Value,
    ) -> Result<Reconsideration, DemandGraphError> {
        self.graph.reconsider_inline_value_node(id, value)
    }

    /// Reconsiders one node from recomputed derivation ATerm bytes.
    ///
    /// This delegates to [`DemandGraph::reconsider_derivation_aterm_node`]. It
    /// does not compute Nix-observed SHA-256 `.drv` hashes or store paths.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if the node is unknown.
    pub fn reconsider_derivation_aterm_node(
        &mut self,
        id: DemandNodeId,
        aterm: &[u8],
    ) -> Result<Reconsideration, DemandGraphError> {
        self.graph.reconsider_derivation_aterm_node(id, aterm)
    }

    fn invalidate_existing_inline_payload(
        &mut self,
        node: Option<DemandNodeId>,
    ) -> Result<(), DemandGraphError> {
        if let Some(node) = node {
            let affected_dependents = self.graph.invalidate_node(node)?;
            self.remove_side_payloads(node);
            for dependent in affected_dependents {
                self.remove_side_payloads(dependent);
            }
        }
        Ok(())
    }

    fn remove_side_payloads(&mut self, node: DemandNodeId) {
        self.inline_values.remove(&node);
        self.derivation_aterm_paths.remove(&node);
        self.static_derivation_output_paths.remove(&node);
    }

    fn invalidate_existing_inline_payload_if_present(
        &mut self,
        node: Option<DemandNodeId>,
    ) -> Result<(), DemandGraphError> {
        if let Some(node) = node
            && self.inline_values.contains_key(&node)
        {
            self.invalidate_existing_inline_payload(Some(node))?;
        }
        Ok(())
    }

    fn revalidate_inline_record_inputs<R>(
        &mut self,
        node: DemandNodeId,
        record: &InlineValueRecord,
        revalidator: &mut R,
    ) -> Result<bool, DemandGraphError>
    where
        R: ImpureInputRevalidator + ?Sized,
    {
        let Some(inputs) = record.revalidation_inputs() else {
            return Ok(false);
        };
        for expected in inputs {
            let Some(fresh) = revalidator.revalidate_impure_input(expected.identity()) else {
                self.invalidate_existing_inline_payload(Some(node))?;
                return Ok(false);
            };
            let ImpureInputFingerprint::Cacheable(fresh) = fresh else {
                self.invalidate_existing_inline_payload(Some(node))?;
                return Ok(false);
            };
            if fresh.identity() != expected.identity() {
                self.invalidate_existing_inline_payload(Some(node))?;
                return Ok(false);
            }
            self.graph.observe_impure_input(&fresh)?;
            if fresh.observation_hash() != expected.observation_hash() {
                self.invalidate_existing_inline_payload(Some(node))?;
                return Ok(false);
            }
        }
        Ok(true)
    }
}
