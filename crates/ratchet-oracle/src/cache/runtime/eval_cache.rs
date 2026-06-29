//! Caller-owned evaluator cache state and observation methods.

use super::*;

mod derivation_side_payloads;

/// Explicit evaluator cache state owned by the caller.
#[derive(Clone, Debug, Default)]
pub struct EvalCache {
    pub(super) graph: DemandGraph,
    pub(super) inline_values: BTreeMap<DemandNodeId, InlineValueRecord>,
    pub(super) derivation_aterm_paths: BTreeMap<DemandNodeId, DerivationAtermPathRecord>,
    pub(super) static_derivation_output_paths:
        BTreeMap<DemandNodeId, StaticDerivationOutputPathRecord>,
    pub(super) memoization_demands: HashMap<DemandCacheKey, MemoizationDemand>,
    persist_node_keys: BTreeMap<DemandNodeId, PersistNodeMetadataKey>,
    nodes_by_persist_key: BTreeMap<PersistNodeMetadataKey, DemandNodeId>,
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
            persist_node_keys: BTreeMap::new(),
            nodes_by_persist_key: BTreeMap::new(),
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
    pub(crate) fn inline_payload_record_count(&self) -> usize {
        self.inline_values.len()
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

    /// Looks up a memoized expression payload.
    ///
    /// This is a precursor memo path for force-time cache hits. It returns a
    /// payload when the expression key already exists, the side payload record
    /// is reusable without input revalidation, and that payload still matches
    /// the node's value hash. Clean nodes hit directly. Dependency-free dirty
    /// nodes may cut off locally by reconsidering the stored payload hash,
    /// mirroring trace-backed revalidation for pure records. Unknown,
    /// missing-payload, trace-backed, stale-payload, dirty nodes with
    /// dependencies, and dirty memo-read supplier nodes are cache misses. Dirty
    /// memo-read suppliers also purge the node's side payload records.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction or dirty-node
    /// invalidation fails.
    pub fn lookup_inline_expression_payload<I>(
        &mut self,
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
        &mut self,
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
        let graph_value_hash = graph_node.value_hash();
        let graph_freshness = graph_node.freshness();
        let graph_has_dependencies = !graph_node.dependencies().is_empty();
        let Some(record) = self.inline_values.get(&node).cloned() else {
            return Ok(None);
        };
        if !record.is_reusable_without_revalidation() {
            return Ok(None);
        }
        if graph_value_hash != Some(record.value_hash) {
            return Ok(None);
        }
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(None);
        }
        if graph_freshness == NodeFreshness::Dirty {
            if graph_has_dependencies {
                return Ok(None);
            }
            let reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
            return Ok(Some(CachedExpressionPayloadHit::with_reconsideration(
                node,
                record.value(),
                reconsideration,
            )));
        }
        if graph_freshness != NodeFreshness::Clean {
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
    /// Returns a [`DemandGraphError`] if cache-key construction or dirty-node
    /// invalidation fails.
    pub fn lookup_inline_expression_result<I>(
        &mut self,
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

    /// Looks up an expression payload after impure-input revalidation.
    ///
    /// Pure payload records are handled identically to
    /// [`EvalCache::lookup_inline_expression_payload`]. Trace-backed payload
    /// records are returned only if every stored cacheable input identity can be
    /// revalidated, the fresh identity still matches the stored identity, the
    /// fresh observation hash still matches the stored observation hash, and the
    /// expression node is clean or can be cleaned with the recorded value hash.
    /// Revalidation observes fresh input leaves through the demand graph so
    /// changed inputs dirty dependents through the ordinary cutoff path. Dirty
    /// trace-backed payload nodes whose inputs and payload hash still match and
    /// that have no memo-read dependencies are reconsidered and can cut off
    /// locally.
    ///
    /// Inputs that cannot be revalidated, revalidate to an uncacheable
    /// fingerprint, revalidate to a different identity, or depend on a dirty
    /// memo-read supplier invalidate the expression payload and return a miss.
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
        let graph_value_hash = graph_node.value_hash();
        let graph_freshness = graph_node.freshness();
        let graph_has_dependencies = !graph_node.dependencies().is_empty();
        let Some(record) = self.inline_values.get(&node).cloned() else {
            return Ok(None);
        };
        if graph_value_hash != Some(record.value_hash) {
            return Ok(None);
        }
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(None);
        }
        if record.is_reusable_without_revalidation() {
            if graph_freshness == NodeFreshness::Dirty {
                if graph_has_dependencies {
                    return Ok(None);
                }
                let reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
                return Ok(Some(CachedExpressionPayloadHit::with_reconsideration(
                    node,
                    record.value(),
                    reconsideration,
                )));
            }
            if graph_freshness != NodeFreshness::Clean {
                return Ok(None);
            }
            return Ok(Some(CachedExpressionPayloadHit::new(node, record.value())));
        }
        if !self.revalidate_inline_record_inputs(node, &record, revalidator)? {
            return Ok(None);
        }
        let graph_node = self.graph.node(node)?;
        if graph_node.value_hash() != Some(record.value_hash) {
            return Ok(None);
        }
        if graph_node.freshness() == NodeFreshness::Dirty {
            if graph_node
                .dependencies_in_group(DemandDependencyGroup::MemoRead)
                .is_some_and(|dependencies| !dependencies.is_empty())
            {
                return Ok(None);
            }
            if self.has_dirty_memo_read_dependency(node)? {
                self.invalidate_existing_inline_payload(Some(node))?;
                return Ok(None);
            }
            let reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
            return Ok(Some(CachedExpressionPayloadHit::with_reconsideration(
                node,
                record.value(),
                reconsideration,
            )));
        }
        if graph_node.freshness() != NodeFreshness::Clean {
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
        let (key, persist_key) = expression_cache_keys(identity, free_var_value_hashes)?;
        let node = self.graph.get_or_insert_node(key, value_hash)?;
        self.remember_persist_node_key(node, persist_key)?;
        Ok(node)
    }

    pub(crate) fn record_memo_read_dependency(
        &mut self,
        dependent: DemandNodeId,
        dependency: DemandNodeId,
    ) -> Result<(), DemandGraphError> {
        self.graph
            .add_dependency_to_group(dependent, DemandDependencyGroup::MemoRead, dependency)
    }

    /// Replaces memo-read dependencies and taints the dependent on dirty reads.
    pub(crate) fn replace_memo_read_dependencies<I>(
        &mut self,
        dependent: DemandNodeId,
        dependencies: I,
    ) -> Result<bool, DemandGraphError>
    where
        I: IntoIterator<Item = DemandNodeId>,
    {
        let dependencies = dependencies.into_iter().collect::<Vec<_>>();
        self.graph.replace_dependency_group(
            dependent,
            DemandDependencyGroup::MemoRead,
            dependencies.iter().copied(),
        )?;
        let has_dirty_dependency = self.has_dirty_memo_read_dependency(dependent)?;
        if has_dirty_dependency {
            self.invalidate_existing_inline_payload(Some(dependent))?;
        }
        Ok(has_dirty_dependency)
    }

    pub(crate) fn memo_read_dependency_persist_keys(
        &self,
        node: DemandNodeId,
        trace_inputs: &[CacheableInputFingerprint],
    ) -> Result<Option<Vec<(PersistNodeMetadataKey, bool)>>, DemandGraphError> {
        let Some(dependencies) = self
            .graph
            .node(node)?
            .dependencies_in_group(DemandDependencyGroup::MemoRead)
        else {
            return Ok(Some(Vec::new()));
        };
        let trace_leaves = self.trace_leaf_nodes_for_inputs(trace_inputs);
        let mut keys = Vec::new();
        for dependency in dependencies {
            let Some(key) = self.persist_node_keys.get(dependency).copied() else {
                return Ok(None);
            };
            let covered_by_trace =
                self.memo_read_dependency_is_covered_by_trace(*dependency, &trace_leaves)?;
            keys.push((key, covered_by_trace));
        }
        Ok(Some(keys))
    }

    pub(crate) fn replace_memo_read_dependencies_by_persist_keys(
        &mut self,
        dependent: DemandNodeId,
        dependency_keys: &[PersistNodeMetadataKey],
    ) -> Result<bool, DemandGraphError> {
        self.graph.node(dependent)?;
        let mut resolved = Vec::new();
        for key in dependency_keys {
            match self.nodes_by_persist_key.get(key).copied() {
                Some(node) if node == dependent => {
                    self.invalidate_existing_inline_payload(Some(dependent))?;
                    return Ok(true);
                }
                Some(node) => resolved.push(node),
                None => {
                    self.invalidate_existing_inline_payload(Some(dependent))?;
                    return Ok(true);
                }
            }
        }
        self.graph.replace_dependency_group(
            dependent,
            DemandDependencyGroup::MemoRead,
            resolved.iter().copied(),
        )?;
        let has_dirty_dependency = self.has_dirty_memo_read_dependency(dependent)?;
        if has_dirty_dependency {
            self.invalidate_existing_inline_payload(Some(dependent))?;
        }
        Ok(has_dirty_dependency)
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
        let (key, persist_key) = expression_cache_keys(identity, free_var_value_hashes)?;
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
        self.remember_persist_node_key(node, persist_key)?;
        self.graph.replace_dependency_group(
            node,
            DemandDependencyGroup::ImpureInput,
            trace.leaves().iter().map(|leaf| leaf.node()),
        )?;
        Ok(ExpressionTraceObservation::new(Some(node), trace))
    }

    /// Observes one recomputed pure expression payload.
    ///
    /// This is the first force-path integration point for the demand graph:
    /// callers still provide the expression identity and ordered free-variable
    /// hashes, and the cache only records/reconsiders the payload value hash.
    /// It does not perform memo lookup, compute free-variable hashes, or
    /// serialize general heap-backed values. Pure observations own no
    /// impure-input edges, so replacing a prior trace-backed payload clears only
    /// the node's impure-input dependency group while preserving memo-read
    /// dependencies.
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
        self.graph.replace_dependency_group(
            node,
            DemandDependencyGroup::ImpureInput,
            std::iter::empty::<DemandNodeId>(),
        )?;
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(reconsideration);
        }
        self.inline_values.insert(node, record);
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
        let (key, persist_key) = expression_cache_keys(identity, free_var_value_hashes)?;
        self.observe_inline_expression_payload_for_key_with_impure_inputs(
            key,
            persist_key,
            value,
            source,
        )
    }

    fn observe_inline_expression_payload_for_key_with_impure_inputs<T>(
        &mut self,
        key: DemandCacheKey,
        persist_key: PersistNodeMetadataKey,
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
        self.remember_persist_node_key(node, persist_key)?;
        self.graph.replace_dependency_group(
            node,
            DemandDependencyGroup::ImpureInput,
            trace.leaves().iter().map(|leaf| leaf.node()),
        )?;
        let payload_reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
        if self.invalidate_if_dirty_memo_read_dependency(node)? {
            return Ok(ExpressionTraceObservation::with_payload_reconsideration(
                node,
                trace,
                payload_reconsideration,
            ));
        }
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
        let (key, persist_key) = expression_cache_keys(identity, free_var_value_hashes)?;
        let value = match CachedExpressionValue::immediate(value) {
            Ok(value) => value,
            Err(source) => {
                let existing_node = self.graph.node_id_for_key(key);
                self.invalidate_existing_inline_payload(existing_node)?;
                if let Some(node) = existing_node {
                    self.graph.replace_dependency_group(
                        node,
                        DemandDependencyGroup::ImpureInput,
                        std::iter::empty::<DemandNodeId>(),
                    )?;
                }
                return Err(DemandGraphError::ValueHash { source });
            }
        };
        self.observe_inline_expression_payload_for_key_with_impure_inputs(
            key,
            persist_key,
            value,
            source,
        )
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

    fn remember_persist_node_key(
        &mut self,
        node: DemandNodeId,
        key: PersistNodeMetadataKey,
    ) -> Result<(), DemandGraphError> {
        self.persist_node_keys.insert(node, key);
        self.nodes_by_persist_key.insert(key, node);
        Ok(())
    }

    fn trace_leaf_nodes_for_inputs(
        &self,
        trace_inputs: &[CacheableInputFingerprint],
    ) -> BTreeSet<DemandNodeId> {
        let mut leaves = BTreeSet::new();
        for input in trace_inputs {
            let key = DemandCacheKey::for_impure_input(input.identity().hash());
            let Some(node) = self.graph.node_id_for_key(key) else {
                continue;
            };
            let Ok(graph_node) = self.graph.node(node) else {
                continue;
            };
            let observed = ValueHash::from_impure_input_observation_hash(input.observation_hash());
            if graph_node.value_hash() == Some(observed) {
                leaves.insert(node);
            }
        }
        leaves
    }

    fn memo_read_dependency_is_covered_by_trace(
        &self,
        dependency: DemandNodeId,
        trace_leaves: &BTreeSet<DemandNodeId>,
    ) -> Result<bool, DemandGraphError> {
        let node = self.graph.node(dependency)?;
        if node.freshness() != NodeFreshness::Clean {
            return Ok(false);
        }
        if !self.inline_values.contains_key(&dependency) {
            return Ok(false);
        }
        if node
            .dependencies_in_group(DemandDependencyGroup::MemoRead)
            .is_some_and(|dependencies| !dependencies.is_empty())
        {
            return Ok(false);
        }
        let Some(impure_inputs) = node.dependencies_in_group(DemandDependencyGroup::ImpureInput)
        else {
            return Ok(true);
        };
        Ok(impure_inputs
            .iter()
            .all(|dependency| trace_leaves.contains(dependency)))
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

    fn invalidate_if_dirty_memo_read_dependency(
        &mut self,
        node: DemandNodeId,
    ) -> Result<bool, DemandGraphError> {
        // Side records are only reusable when every memo-read supplier reachable
        // from the node is clean. Observations that race with dirty supplier
        // wiring keep the freshly computed value hash but leave the node dirty
        // and uncacheable.
        if !self.has_dirty_memo_read_dependency(node)? {
            return Ok(false);
        }
        self.invalidate_existing_inline_payload(Some(node))?;
        Ok(true)
    }

    fn has_dirty_memo_read_dependency(&self, node: DemandNodeId) -> Result<bool, DemandGraphError> {
        let mut stack = self
            .graph
            .node(node)?
            .dependencies_in_group(DemandDependencyGroup::MemoRead)
            .map(|dependencies| dependencies.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        let mut visited = BTreeSet::new();
        while let Some(dependency) = stack.pop() {
            if !visited.insert(dependency) {
                continue;
            }
            let dependency_node = self.graph.node(dependency)?;
            if dependency_node.freshness() == NodeFreshness::Dirty {
                return Ok(true);
            }
            if let Some(dependencies) =
                dependency_node.dependencies_in_group(DemandDependencyGroup::MemoRead)
            {
                stack.extend(dependencies.iter().copied());
            }
        }
        Ok(false)
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

fn expression_cache_keys<I>(
    identity: CacheExprIdentity,
    free_var_value_hashes: I,
) -> Result<(DemandCacheKey, PersistNodeMetadataKey), DemandGraphError>
where
    I: IntoIterator<Item = DurableBlake3Hash>,
{
    let free_var_value_hashes = free_var_value_hashes.into_iter().collect::<Vec<_>>();
    let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes.iter().copied())
        .map_err(|source| DemandGraphError::CacheKey { source })?;
    let persist_key =
        PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
    Ok((key, persist_key))
}
