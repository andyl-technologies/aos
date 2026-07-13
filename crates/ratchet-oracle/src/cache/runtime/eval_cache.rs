//! Caller-owned evaluator cache state and observation methods.

use super::*;

mod derivation_side_payloads;
mod lookup;
mod observe;

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
        I: IntoIterator<Item = ValueHash>,
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
        I: IntoIterator<Item = ValueHash>,
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
    I: IntoIterator<Item = ValueHash>,
{
    let free_var_value_hashes = free_var_value_hashes.into_iter().collect::<Vec<_>>();
    let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes.iter().copied())
        .map_err(|source| DemandGraphError::CacheKey { source })?;
    let persist_key =
        PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
    Ok((key, persist_key))
}
