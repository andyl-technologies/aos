//! Demand-graph bookkeeping: node interning, edges, dirty marking, and reconsideration.

use super::*;

impl DemandGraph {
    /// Creates an empty demand graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of nodes in this graph.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns whether this graph has no nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns a node by id.
    ///
    /// # Errors
    ///
    /// Returns [`DemandGraphError::UnknownNode`] if `id` does not belong to
    /// this graph.
    pub fn node(&self, id: DemandNodeId) -> Result<&DemandNode, DemandGraphError> {
        self.nodes
            .get(id.index())
            .ok_or(DemandGraphError::UnknownNode { id })
    }

    /// Returns the id for `key`, if a node with that key already exists.
    pub fn node_id_for_key(&self, key: DemandCacheKey) -> Option<DemandNodeId> {
        self.by_key.get(&key).copied()
    }

    /// Gets or inserts a node keyed by `key`.
    ///
    /// Existing nodes keep their current value hash; callers update hashes by
    /// reconsidering the node.
    ///
    /// # Errors
    ///
    /// Returns [`DemandGraphError::TooManyNodes`] if the graph cannot address
    /// another node. Returns an allocation error if node or key storage cannot
    /// reserve capacity.
    pub fn get_or_insert_node(
        &mut self,
        key: DemandCacheKey,
        value_hash: Option<ValueHash>,
    ) -> Result<DemandNodeId, DemandGraphError> {
        if let Some(id) = self.by_key.get(&key) {
            return Ok(*id);
        }

        let raw = u32::try_from(self.nodes.len()).map_err(|_| DemandGraphError::TooManyNodes)?;
        let id = DemandNodeId::new(raw);
        let nodes = self
            .nodes
            .len()
            .checked_add(1)
            .ok_or(DemandGraphError::TooManyNodes)?;
        self.nodes
            .try_reserve_exact(1)
            .map_err(|_| DemandGraphError::NodeAllocationFailed { nodes })?;
        self.by_key
            .try_reserve(1)
            .map_err(|_| DemandGraphError::KeyAllocationFailed {
                keys: self.by_key.len().saturating_add(1),
            })?;

        self.nodes.push(DemandNode::new(key, value_hash));
        self.by_key.insert(key, id);
        Ok(id)
    }

    /// Gets or inserts a node keyed by an expression identity and free variables.
    ///
    /// Existing nodes keep their current value hash; callers update hashes by
    /// reconsidering the node. This helper only centralizes demand-cache key
    /// construction and graph interning. It does not compute free-variable
    /// order, evaluate the expression, or perform memo lookup.
    ///
    /// # Errors
    ///
    /// Returns [`DemandGraphError::CacheKey`] if the expression/free-variable
    /// key cannot be built. Returns [`DemandGraphError::TooManyNodes`] if the
    /// graph cannot address another node. Returns an allocation error if node
    /// or key storage cannot reserve capacity.
    pub fn get_or_insert_expression_node<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value_hash: Option<ValueHash>,
    ) -> Result<DemandNodeId, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        self.get_or_insert_node(key, value_hash)
    }

    /// Observes one cacheable impure input as a demand-graph leaf.
    ///
    /// New input identities insert a clean leaf with the observed-result hash.
    /// Existing leaves are reconsidered through the ordinary early-cutoff path,
    /// so changed observations dirty direct dependents while unchanged
    /// observations cut off.
    ///
    /// # Errors
    ///
    /// Returns [`DemandGraphError::TooManyNodes`] if the graph cannot address
    /// another node. Returns an allocation error if node or key storage cannot
    /// reserve capacity.
    pub fn observe_impure_input(
        &mut self,
        fingerprint: &CacheableInputFingerprint,
    ) -> Result<ImpureInputObservation, DemandGraphError> {
        let key = DemandCacheKey::for_impure_input(fingerprint.identity().hash());
        let observed =
            ValueHash::from_impure_input_observation_hash(fingerprint.observation_hash());

        if let Some(id) = self.node_id_for_key(key) {
            return self
                .reconsider_node(id, observed)
                .map(ImpureInputObservation::Reconsidered);
        }

        let node = self.get_or_insert_node(key, Some(observed))?;
        Ok(ImpureInputObservation::Inserted { node })
    }

    /// Ingests an evaluator impure-input observation trace.
    ///
    /// This method only turns trace entries into cache-side input leaves. It
    /// does not create edges from an evaluating node to those leaves. Incomplete
    /// or uncacheable traces are reported without mutating graph state.
    /// Cacheable traces are applied incrementally after the pre-scan; errors
    /// from leaf observation are not rolled back.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if leaf observation storage cannot be
    /// reserved or if inserting/reconsidering a cacheable leaf fails.
    pub fn observe_impure_trace(
        &mut self,
        trace: &[ImpureInputFingerprint],
        complete: bool,
    ) -> Result<ImpureTraceObservation, DemandGraphError> {
        if !complete {
            return Ok(ImpureTraceObservation::incomplete());
        }
        if let Some(input) = trace.iter().find_map(|fingerprint| match fingerprint {
            ImpureInputFingerprint::Uncacheable(input) => Some(*input),
            ImpureInputFingerprint::Cacheable(_) => None,
        }) {
            return Ok(ImpureTraceObservation::uncacheable(input));
        }

        let mut leaves = Vec::new();
        leaves.try_reserve_exact(trace.len()).map_err(|_| {
            DemandGraphError::TraceObservationAllocationFailed {
                observations: trace.len(),
            }
        })?;
        for fingerprint in trace {
            let ImpureInputFingerprint::Cacheable(fingerprint) = fingerprint else {
                unreachable!("uncacheable inputs were pre-scanned");
            };
            leaves.push(self.observe_impure_input(fingerprint)?);
        }

        Ok(ImpureTraceObservation::cacheable(leaves))
    }

    /// Observes an impure-input trace and wires cacheable leaves to a node.
    ///
    /// `dependent` must be an existing caller-supplied evaluating node. This
    /// method does not create demand nodes for evaluator computations. Complete
    /// cacheable traces replace `dependent`'s dependencies with the observed
    /// input leaves, so later changed input observations dirty `dependent` only
    /// for the latest trace.
    /// Incomplete and uncacheable traces return their cacheability status and
    /// clear any existing dependencies from `dependent`.
    ///
    /// The graph does not type dependency edges. Callers must use this method
    /// only when the impure trace represents the full dependency set that should
    /// remain on `dependent`.
    ///
    /// Successful leaf observations are not rolled back if later edge
    /// replacement fails.
    ///
    /// # Errors
    ///
    /// Returns [`DemandGraphError::UnknownNode`] if `dependent` does not belong
    /// to this graph. Returns [`DemandGraphError::SelfDependency`] if
    /// `dependent` is itself one of the observed input leaves. Returns other
    /// [`DemandGraphError`] values from trace observation or edge replacement.
    pub fn observe_impure_trace_for_node(
        &mut self,
        dependent: DemandNodeId,
        trace: &[ImpureInputFingerprint],
        complete: bool,
    ) -> Result<ImpureTraceObservation, DemandGraphError> {
        self.node(dependent)?;
        let observation = self.observe_impure_trace(trace, complete)?;
        if observation.status() != ImpureTraceStatus::Cacheable {
            self.replace_dependencies(dependent, std::iter::empty::<DemandNodeId>())?;
            return Ok(observation);
        }

        if observation
            .leaves()
            .iter()
            .any(|leaf| leaf.node() == dependent)
        {
            return Err(DemandGraphError::SelfDependency { id: dependent });
        }

        self.replace_dependencies(
            dependent,
            observation.leaves().iter().map(|leaf| leaf.node()),
        )?;
        Ok(observation)
    }

    /// Records that `dependent` reads `dependency`.
    ///
    /// # Errors
    ///
    /// Returns [`DemandGraphError::UnknownNode`] if either id does not belong
    /// to this graph, or [`DemandGraphError::SelfDependency`] when both ids are
    /// equal.
    pub fn add_dependency(
        &mut self,
        dependent: DemandNodeId,
        dependency: DemandNodeId,
    ) -> Result<(), DemandGraphError> {
        self.node(dependent)?;
        self.node(dependency)?;
        if dependent == dependency {
            return Err(DemandGraphError::SelfDependency { id: dependent });
        }

        self.nodes[dependent.index()]
            .dependencies
            .insert(dependency);
        self.nodes[dependency.index()].dependents.insert(dependent);
        Ok(())
    }

    /// Replaces all dependencies read by `dependent`.
    ///
    /// Existing reverse edges from dependencies that are no longer present are
    /// removed, and new reverse edges are inserted for every replacement
    /// dependency. Duplicate replacement ids are collapsed by the graph's
    /// deterministic node-id ordering.
    ///
    /// Dependency edges are untyped, so replacement covers the node's whole
    /// dependency set. Callers that need to preserve separate dependency groups
    /// must merge those groups before calling this method.
    ///
    /// # Errors
    ///
    /// Returns [`DemandGraphError::UnknownNode`] if any id does not belong to
    /// this graph, or [`DemandGraphError::SelfDependency`] if `dependent`
    /// appears in the replacement dependency set. On error, graph edges are left
    /// unchanged.
    pub fn replace_dependencies<I>(
        &mut self,
        dependent: DemandNodeId,
        dependencies: I,
    ) -> Result<(), DemandGraphError>
    where
        I: IntoIterator<Item = DemandNodeId>,
    {
        self.node(dependent)?;
        let mut replacement = BTreeSet::new();
        for dependency in dependencies {
            self.node(dependency)?;
            if dependent == dependency {
                return Err(DemandGraphError::SelfDependency { id: dependent });
            }
            replacement.insert(dependency);
        }

        let previous = self.nodes[dependent.index()].dependencies.clone();
        for removed in previous.difference(&replacement) {
            self.nodes[removed.index()].dependents.remove(&dependent);
        }
        for added in replacement.difference(&previous) {
            self.nodes[added.index()].dependents.insert(dependent);
        }
        self.nodes[dependent.index()].dependencies = replacement;
        Ok(())
    }

    /// Marks one node dirty.
    ///
    /// # Errors
    ///
    /// Returns [`DemandGraphError::UnknownNode`] if `id` does not belong to
    /// this graph.
    pub fn mark_dirty(&mut self, id: DemandNodeId) -> Result<(), DemandGraphError> {
        let node = self.node_mut(id)?;
        node.freshness = NodeFreshness::Dirty;
        Ok(())
    }

    /// Returns dirty nodes in deterministic node order.
    ///
    /// This is a scheduling view only. It does not recompute nodes or mutate
    /// freshness.
    pub fn dirty_nodes(&self) -> impl Iterator<Item = DemandNodeId> + '_ {
        self.nodes.iter().enumerate().filter_map(|(index, node)| {
            if node.freshness != NodeFreshness::Dirty {
                return None;
            }
            u32::try_from(index).ok().map(DemandNodeId::new)
        })
    }

    /// Returns dirty nodes whose upstream dependencies are currently clean.
    ///
    /// Evaluator schedulers can repeatedly recompute this frontier, call
    /// [`Self::reconsider_node`] for each returned node, and let early cutoff
    /// decide whether downstream dependents become dirty. Dirty nodes with any
    /// dirty transitive dependency are withheld so a scheduler does not bypass
    /// cutoff by recomputing consumers before their inputs have settled.
    pub fn ready_dirty_nodes(&self) -> impl Iterator<Item = DemandNodeId> + '_ {
        self.nodes.iter().enumerate().filter_map(|(index, node)| {
            if node.freshness != NodeFreshness::Dirty {
                return None;
            }
            let id = u32::try_from(index).ok().map(DemandNodeId::new)?;
            if !self.dirty_upstream_blockers(id).is_empty() {
                return None;
            }
            Some(id)
        })
    }

    /// Returns a deterministic scheduling snapshot for dirty nodes.
    ///
    /// The returned frontier separates ready dirty nodes from dirty nodes
    /// blocked by dirty upstream nodes, including themselves when a dependency
    /// cycle makes a node reachable from itself. This is a diagnostic and
    /// scheduling view only; it does not recompute nodes or mutate freshness.
    pub fn dirty_frontier(&self) -> DirtyFrontier {
        let mut ready = Vec::new();
        let mut blocked = Vec::new();
        for node in self.dirty_nodes() {
            let blockers = self.dirty_upstream_blockers(node);
            if blockers.is_empty() {
                ready.push(node);
            } else {
                blocked.push(BlockedDirtyNode::new(node, blockers));
            }
        }
        DirtyFrontier::new(ready, blocked)
    }

    /// Recomputes ready dirty nodes until the dirty frontier is empty or blocked.
    ///
    /// The loop snapshots [`Self::dirty_frontier`], recomputes ready dirty nodes
    /// in deterministic node-id order through `recompute`, and applies
    /// [`Self::reconsider_node`] to each returned value hash. Reconsideration
    /// handles early cutoff: unchanged hashes clean the node without dirtying
    /// dependents, while changed hashes dirty direct dependents for a later pass.
    ///
    /// The returned [`RecomputeReadyDirty`] contains every reconsideration in
    /// loop order plus the final frontier. A non-empty final frontier has no ready
    /// nodes, which means dirty nodes are blocked by dirty upstream dependencies
    /// such as a dirty cycle.
    ///
    /// This is a graph-level scheduling primitive only. It does not know how to
    /// evaluate expressions, derive canonical value hashes, record dynamic
    /// dependencies, or integrate persistence.
    ///
    /// # Errors
    ///
    /// Returns [`DemandGraphError::RecomputeLoopAllocationFailed`] if the loop
    /// cannot reserve ready-node or reconsideration storage. Returns any error
    /// from `recompute`, or [`DemandGraphError::UnknownNode`] if graph
    /// bookkeeping observes an invalid node while reconsidering. If `recompute`
    /// returns an error after earlier nodes in the same call were reconsidered,
    /// those graph mutations are retained and the partial reconsideration list is
    /// not returned.
    pub fn recompute_ready_dirty_nodes<E, F>(
        &mut self,
        mut recompute: F,
    ) -> Result<RecomputeReadyDirty, E>
    where
        E: From<DemandGraphError>,
        F: FnMut(DemandNodeId) -> Result<ValueHash, E>,
    {
        let mut reconsiderations = Vec::new();
        loop {
            let frontier = self.dirty_frontier();
            if frontier.ready_nodes().is_empty() {
                return Ok(RecomputeReadyDirty::new(reconsiderations, frontier));
            }
            let ready_nodes = frontier.ready_nodes();
            let mut ready = Vec::new();
            ready.try_reserve_exact(ready_nodes.len()).map_err(|_| {
                DemandGraphError::RecomputeLoopAllocationFailed {
                    entries: ready_nodes.len(),
                }
            })?;
            ready.extend_from_slice(ready_nodes);
            reconsiderations.try_reserve(ready.len()).map_err(|_| {
                DemandGraphError::RecomputeLoopAllocationFailed {
                    entries: reconsiderations.len().saturating_add(ready.len()),
                }
            })?;
            for node in ready {
                let recomputed = recompute(node)?;
                let reconsideration = self.reconsider_node(node, recomputed)?;
                reconsiderations.push(reconsideration);
            }
        }
    }

    fn dirty_upstream_blockers(&self, id: DemandNodeId) -> Vec<DemandNodeId> {
        let Some(node) = self.nodes.get(id.index()) else {
            return Vec::new();
        };
        let mut blockers = BTreeSet::new();
        let mut stack: Vec<_> = node.dependencies.iter().copied().collect();
        let mut visited = BTreeSet::new();
        while let Some(dependency) = stack.pop() {
            if !visited.insert(dependency) {
                continue;
            }
            let Some(node) = self.nodes.get(dependency.index()) else {
                continue;
            };
            if node.freshness == NodeFreshness::Dirty {
                blockers.insert(dependency);
            }
            stack.extend(node.dependencies.iter().copied());
        }
        blockers.into_iter().collect()
    }

    /// Reconsiders one node with a recomputed value hash.
    ///
    /// The node is marked clean and updated to `recomputed`. If the recomputed
    /// value hash differs from the prior hash, direct dependents are marked
    /// dirty and newly dirtied dependents are returned. Transitive scheduling
    /// remains the caller's job.
    ///
    /// # Errors
    ///
    /// Returns [`DemandGraphError::UnknownNode`] if `id` does not belong to
    /// this graph.
    pub fn reconsider_node(
        &mut self,
        id: DemandNodeId,
        recomputed: ValueHash,
    ) -> Result<Reconsideration, DemandGraphError> {
        let node = self.node(id)?;
        let decision = EarlyCutoff::decide(node.value_hash, recomputed);
        let dependents: Vec<_> = node.dependents.iter().copied().collect();

        let node = self.node_mut(id)?;
        node.value_hash = Some(recomputed);
        node.freshness = NodeFreshness::Clean;

        let mut dirtied_dependents = Vec::new();
        if decision.should_propagate() {
            for dependent in &dependents {
                let node = &mut self.nodes[dependent.index()];
                if node.freshness != NodeFreshness::Dirty {
                    node.freshness = NodeFreshness::Dirty;
                    dirtied_dependents.push(*dependent);
                }
            }
        }

        Ok(Reconsideration::new(id, decision, dirtied_dependents))
    }

    /// Reconsiders one node with a recomputed inline scalar value.
    ///
    /// This hashes the inline value before mutating graph state, then delegates
    /// to [`Self::reconsider_node`]. It is an inline-value adapter only and does
    /// not implement heap-backed canonical value hashing.
    ///
    /// # Errors
    ///
    /// Returns [`DemandGraphError::ValueHash`] if `value` is not supported by
    /// [`ValueHash::from_inline_value`]. Returns
    /// [`DemandGraphError::UnknownNode`] if `id` does not belong to this graph.
    pub fn reconsider_inline_value_node(
        &mut self,
        id: DemandNodeId,
        value: Value,
    ) -> Result<Reconsideration, DemandGraphError> {
        let recomputed = ValueHash::from_inline_value(value)
            .map_err(|source| DemandGraphError::ValueHash { source })?;
        self.reconsider_node(id, recomputed)
    }

    fn node_mut(&mut self, id: DemandNodeId) -> Result<&mut DemandNode, DemandGraphError> {
        self.nodes
            .get_mut(id.index())
            .ok_or(DemandGraphError::UnknownNode { id })
    }
}
