//! Temporal graph storage, replay, checkpointing, and time-travel core.

use super::*;

/// A baked genesis checkpoint handle.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GenesisCheckpoint {
    /// The checkpoint content address.
    pub checkpoint: Checkpoint,
}

/// A world handle used by the `bake` signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct World {
    /// The world content address.
    pub id: ContentHash,
    pub(in crate::model) topology_nodes: Vec<WorldNodeDef>,
    pub(in crate::model) links: Vec<LinkDef>,
    pub(in crate::model) fault_topology: WorldFaultTopology,
    pub(in crate::model) fault_topology_id: ContentHash,
    pub(in crate::model) fault_topology_wire: Vec<u8>,
}

/// Borrowed VM-only view over a world's canonical heterogeneous topology.
#[derive(Clone, Copy)]
pub struct WorldVmNodes<'a> {
    nodes: &'a [WorldNodeDef],
}

impl<'a> WorldVmNodes<'a> {
    pub(in crate::model) const fn new(nodes: &'a [WorldNodeDef]) -> Self {
        Self { nodes }
    }

    /// Returns the number of VM nodes in the world.
    #[must_use]
    pub fn len(self) -> usize {
        self.iter().count()
    }

    /// Reports whether the world contains no VM nodes.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.first().is_none()
    }

    /// Returns the first VM node, if one exists.
    #[must_use]
    pub fn first(self) -> Option<&'a WorldNode> {
        self.iter().next()
    }

    /// Returns the VM node at `index`, if one exists.
    #[must_use]
    pub fn get(self, index: usize) -> Option<&'a WorldNode> {
        self.iter().nth(index)
    }

    /// Iterates the VM nodes in canonical topology order.
    pub fn iter(self) -> impl DoubleEndedIterator<Item = &'a WorldNode> + Clone {
        self.nodes.iter().filter_map(|node| match node {
            WorldNodeDef::Vm(node) => Some(node),
            WorldNodeDef::Io(_) => None,
        })
    }

    /// Copies the VM nodes into an owned collection.
    #[must_use]
    pub fn to_vec(self) -> Vec<WorldNode> {
        self.iter().cloned().collect()
    }
}

impl std::fmt::Debug for WorldVmNodes<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

impl PartialEq for WorldVmNodes<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for WorldVmNodes<'_> {}

impl<'a> IntoIterator for WorldVmNodes<'a> {
    type Item = &'a WorldNode;
    type IntoIter = std::iter::FilterMap<
        std::slice::Iter<'a, WorldNodeDef>,
        fn(&'a WorldNodeDef) -> Option<&'a WorldNode>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        fn vm_node(node: &WorldNodeDef) -> Option<&WorldNode> {
            match node {
                WorldNodeDef::Vm(node) => Some(node),
                WorldNodeDef::Io(_) => None,
            }
        }

        self.nodes.iter().filter_map(vm_node)
    }
}

/// A workload config-tree export declared by one world node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorldWorkloadConfigTree {
    /// The VM node that consumes this config tree.
    pub node: NodeId,
    /// The immutable content-addressed config tree and delivery channel.
    pub config: GuestWorkloadConfigTreeRef,
}

/// Static topology products derived from a [`World`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorldStaticTopology {
    /// The VM participants declared by the world.
    pub participants: Vec<NodeId>,
    /// Every VM, block/9p node, and logical link projected to a deterministic
    /// scheduler graph identity.
    pub scheduling_nodes: Vec<SchedulerNodeId>,
    /// The per-entity decision-RNG streams declared by the world.
    pub rng_streams: Vec<RngStreamId>,
    /// The directed scheduler-lookahead edges declared by the world.
    pub lookahead_graph: Vec<WorldLookaheadEdge>,
    /// The VM-only node set that `bake` must boot to a ready point.
    ///
    /// I/O nodes bind immutable artifacts directly and therefore participate in
    /// scheduling without a VM genesis-boot step.
    pub bake_nodes: Vec<NodeId>,
}

/// One directed edge in the scheduler lookahead graph derived from a [`World`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorldLookaheadEdge {
    /// The peer that can send a future network event.
    pub from: NodeId,
    /// The peer that can receive that future network event.
    pub to: NodeId,
    /// The minimum one-way latency that bounds conservative lookahead.
    pub minimum_latency: SimDuration,
}

/// An abstract reduced state handle.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct State {
    /// The reduced state's content address.
    pub id: ContentHash,
}

/// A temporal graph handle used by the `instantiate` signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraph {
    /// The temporal graph content address.
    pub id: ContentHash,
    pub(in crate::model) recorded_configurations: BTreeMap<ContentHash, Configuration>,
    pub(in crate::model) checkpoint_nodes: BTreeMap<ContentHash, Checkpoint>,
    pub(in crate::model) cached_snapshots: BTreeMap<ContentHash, Checkpoint>,
    pub(in crate::model) baked_genesis: BTreeMap<ContentHash, GenesisCheckpoint>,
    pub(in crate::model) non_canonical_debug_branches:
        BTreeMap<ContentHash, DebugNonCanonicalBranch>,
}

impl TemporalGraph {
    /// Builds an empty temporal graph cache with `id`.
    #[must_use]
    pub fn new(id: ContentHash) -> Self {
        Self {
            id,
            recorded_configurations: BTreeMap::new(),
            checkpoint_nodes: BTreeMap::new(),
            cached_snapshots: BTreeMap::new(),
            baked_genesis: BTreeMap::new(),
            non_canonical_debug_branches: BTreeMap::new(),
        }
    }

    /// Builds an empty temporal graph cache with the default test identity.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(ContentHash::default())
    }

    /// Resumes `tip` by instantiating it through the temporal graph.
    ///
    /// The graph records the thin checkpoint closure before calling
    /// [`instantiate`], so resume uses the same exact-snapshot, cached-ancestor,
    /// or baked-genesis path as every other operation.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when no baked root can
    /// realize the configuration, or another [`EngineError`] if checkpoint
    /// metadata is invalid.
    pub fn resume(&mut self, tip: &Configuration) -> Result<TemporalGraphRuntime, EngineError> {
        self.record_checkpoint_closure(tip)?;
        let runtime = instantiate(self, tip)?;
        Ok(TemporalGraphRuntime {
            configuration: tip.id(),
            checkpoint: tip.id(),
            runtime,
        })
    }

    /// Forks from `base` by instantiating it and appending `decisions`.
    ///
    /// The returned branch is recorded as a thin checkpoint in the same DAG.
    /// Forking therefore creates no state representation outside the temporal
    /// graph; later save or search operations may materialize the branch through
    /// the usual replay-oracle-checked path.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when `base` cannot be instantiated or the branch
    /// cannot be recorded as a valid checkpoint edge.
    pub fn fork<I>(
        &mut self,
        base: &Configuration,
        decisions: I,
    ) -> Result<TemporalGraphFork, EngineError>
    where
        I: IntoIterator<Item = Decision>,
    {
        let base_runtime = self.resume(base)?;
        let mut branch = base.clone();
        for decision in decisions {
            branch = try_step(&branch, decision)?;
        }
        let branch_checkpoint = self.record_thin_checkpoint(&branch)?;
        Ok(TemporalGraphFork {
            base: base_runtime,
            branch,
            branch_checkpoint,
        })
    }

    /// Replays the stored fat checkpoint for `configuration` on demand.
    ///
    /// The operation checks the exact cached snapshot, or baked genesis for the
    /// genesis configuration, against the independent thin replay path.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointNotRecorded`] when no stored fat
    /// checkpoint exists for `configuration`. Returns replay-oracle validation
    /// errors from [`Self::replay_checkpoint`] when the fat and thin paths do
    /// not match.
    pub fn replay(&self, configuration: &Configuration) -> Result<ReplayOracleCheck, EngineError> {
        let checkpoint = if configuration.is_genesis() {
            self.genesis_snapshot(&configuration.def)
                .map(|genesis| genesis.checkpoint.clone())
        } else {
            self.cached_snapshot(configuration).cloned()
        }
        .ok_or(EngineError::CheckpointNotRecorded {
            checkpoint: configuration.id(),
        })?;
        self.replay_checkpoint(configuration, &checkpoint)
    }

    /// Validates any advanced operation through the single temporal graph path.
    ///
    /// This is the unifying-view check for fork/save/resume/replay/search/fuzz/
    /// reproduction/minimization outputs: typed operation evidence is first
    /// checked for an internally consistent operation output and reduced to one
    /// configuration, then that configuration is recorded in the graph,
    /// realized once with [`instantiate`], compared to the pure reducer,
    /// converted into a checkpoint, and checked by the replay oracle against
    /// the same thin graph derivation used by ordinary resume and save paths.
    /// The model-side single-VM fingerprint is the realized runtime state
    /// identity, matching `gate:single-vm-fingerprint`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when `operation` evidence is internally
    /// inconsistent or does not match the recomputed unified report,
    /// [`EngineError::MissingBakedGenesis`] when the graph cannot realize its
    /// configuration, [`EngineError::ReplayTargetMismatch`] when the realized
    /// runtime does not match the reduced configuration state, or another
    /// [`EngineError`] from checkpoint materialization or replay-oracle
    /// validation.
    pub fn validate_unified_operation(
        &mut self,
        operation: &UnifiedGraphOperationEvidence,
    ) -> Result<UnifiedGraphOperationReport, EngineError> {
        let operation_kind = operation.kind();
        let configuration = operation.configuration()?;
        let report = self.validate_unified_configuration(operation_kind, &configuration)?;
        operation.validate_report(self, &configuration, &report)?;
        Ok(report)
    }

    pub(in crate::model) fn validate_unified_configuration(
        &mut self,
        operation: UnifiedGraphOperationKind,
        configuration: &Configuration,
    ) -> Result<UnifiedGraphOperationReport, EngineError> {
        self.record_checkpoint_closure(configuration)?;
        let runtime = instantiate(self, configuration)?;
        let reduced = reduce(&configuration.def, &configuration.schedule)?;
        if runtime.id != reduced.id {
            return Err(EngineError::ReplayTargetMismatch {
                expected: reduced.id,
                actual: runtime.id,
            });
        }
        let checkpoint = materialized_checkpoint_for_runtime(configuration, runtime.clone())?;
        let replay_oracle = self.replay_checkpoint(configuration, &checkpoint)?;
        Ok(UnifiedGraphOperationReport {
            operation,
            graph: self.id,
            configuration: configuration.id(),
            schedule: configuration.schedule.content_hash(),
            checkpoint: checkpoint.id,
            reduced_state: reduced.id,
            runtime_state: runtime.id,
            single_vm_fingerprint: ExecutionFingerprint { hash: runtime.id },
            replay_oracle,
        })
    }

    /// Searches one frontier by realizing, reducing, deduplicating, and materializing children.
    ///
    /// The frontier is first realized through [`Self::resume`], so expansion uses
    /// the same [`instantiate`] path as user-facing resume and fork operations.
    /// Search then enumerates runtime-derived frontier decisions from the closed
    /// search taxonomy and passes them to [`Self::enumerate_frontier_reduced`].
    /// Every explored child is passed through [`Self::materialize_hot_checkpoint`]
    /// with the supplied materialization policy and trigger; covered children
    /// are reported but never materialized.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the frontier cannot be realized or recorded,
    /// a child checkpoint cannot be represented, or a requested hot
    /// materialization cannot be replay-oracle validated.
    pub fn search(
        &mut self,
        frontier: &Configuration,
        reduction_policy: FrontierReductionPolicy,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
    ) -> Result<TemporalGraphSearch, EngineError> {
        self.search_inner(
            frontier,
            reduction_policy,
            materialization_policy,
            trigger,
            None,
            0,
        )
    }

    /// Selects one pending frontier with the advanced search strategy ordering.
    ///
    /// This read-only boundary lets a concrete backend driver retain ownership
    /// of runtime realization while using exactly the same breadth-first,
    /// depth-first, priority, and coverage-guided ordering as graph search.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use crucible::{Configuration, SearchStrategy, TemporalGraph};
    /// # fn select(graph: &TemporalGraph, pending: &[Configuration]) {
    /// let selected =
    ///     graph.select_strategy_frontier(pending, SearchStrategy::BreadthFirst, None);
    /// # let _ = selected;
    /// # }
    /// ```
    #[must_use]
    pub fn select_strategy_frontier(
        &self,
        pending: &[Configuration],
        strategy: SearchStrategy,
        max_depth: Option<u64>,
    ) -> Option<usize> {
        let candidates = pending
            .iter()
            .cloned()
            .map(SearchFrontierCandidate::new)
            .collect::<Vec<_>>();
        select_search_frontier_candidate(self, &candidates, strategy, max_depth, None)
    }

    /// Branches one frontier over bounded preemption decisions.
    ///
    /// Generated children are ordinary content-addressed temporal-graph nodes.
    /// Explored children are materialized through the replay-oracle-checked fat
    /// checkpoint path, while `reduction_policy` can cover commuting preemption
    /// branches before materialization.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the frontier or an explored child cannot be
    /// recorded or materialized.
    pub fn branch_preemptions(
        &mut self,
        frontier: &Configuration,
        config: &PreemptionBranchConfig,
        reduction_policy: FrontierReductionPolicy,
    ) -> Result<PreemptionBranchRun, EngineError> {
        let (discovery, choices) = preemption_branch_choices(frontier, config)?;
        let decisions = choices
            .iter()
            .map(|choice| choice.decision().clone())
            .collect::<Vec<_>>();
        let report =
            self.enumerate_frontier_choices_reduced(frontier, choices, reduction_policy)?;
        let materialized = self.materialize_preemption_branches(&report)?;
        Ok(PreemptionBranchRun {
            discovery,
            decisions,
            report,
            materialized,
        })
    }

    /// Searches a graph by repeatedly expanding frontiers selected by `strategy`.
    ///
    /// Strategy selection is deterministic: breadth-first and depth-first use
    /// schedule depth, priority uses a seeded score, coverage-guided uses
    /// checkpoint coverage feedback, and every tie is broken by configuration
    /// content address. The underlying single-frontier expansion remains
    /// [`Self::search`], so strategies order the work-list without changing the
    /// graph semantics. Graph-level symmetry and partial-order reductions are
    /// deliberately not applied by this T-ADV-8 driver; T-ADV-9 owns reduction
    /// soundness for multi-frontier search.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the root or any selected frontier cannot be
    /// realized, reduced, recorded, or materialized by the single-frontier search
    /// operation.
    pub fn search_with_strategy(
        &mut self,
        root: &Configuration,
        strategy: SearchStrategy,
        budget: SearchBudget,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
    ) -> Result<TemporalGraphSearchRun, EngineError> {
        let failure_oracle = SearchFailureOracle::none();
        self.search_with_strategy_inner(
            root,
            strategy,
            budget,
            FrontierReductionPolicy::none(),
            materialization_policy,
            trigger,
            None,
            &failure_oracle,
            None,
            None,
            None,
            None,
        )
    }

    /// Searches with an explicit deterministic failure oracle.
    ///
    /// The oracle is read-only steering/reporting input: it can mark reached
    /// configurations as discovered failures, but it cannot change which graph
    /// nodes are explored. `scenario` pins the concrete serialized scenario form
    /// used to attach self-contained reproduction artifacts to every discovered
    /// failure. This keeps failure reporting reproducible while the assertion and
    /// triage layers own the semantics of what counts as a failure. Graph-level
    /// symmetry and partial-order reductions are not applied here; T-ADV-9 owns
    /// reduction soundness for multi-frontier search.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not describe `root`. Returns other [`EngineError`] values when the
    /// root or any selected frontier cannot be realized, reduced, recorded, or
    /// materialized by the single-frontier search operation, or when a discovered
    /// failure reproduction artifact cannot be captured.
    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    pub fn search_with_strategy_and_failure_oracle(
        &mut self,
        scenario: &ScenarioDefForm,
        root: &Configuration,
        strategy: SearchStrategy,
        budget: SearchBudget,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        failure_oracle: &SearchFailureOracle,
    ) -> Result<TemporalGraphSearchRun, EngineError> {
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != root.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: root.def.id,
                actual: scenario_def.id,
            });
        }
        self.search_with_strategy_inner(
            root,
            strategy,
            budget,
            FrontierReductionPolicy::none(),
            materialization_policy,
            trigger,
            Some(scenario),
            failure_oracle,
            None,
            None,
            None,
            None,
        )
    }

    /// Searches with a deterministic failure oracle and decision-depth bound.
    ///
    /// `max_depth` limits which pending frontier checkpoints may be expanded by
    /// their recorded-decision depth. Candidates at or beyond the bound remain
    /// pending, so [`TemporalGraphSearchRun::exhausted`] is false when a depth
    /// bound, rather than graph exhaustion, stops the run.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::search_with_strategy_and_failure_oracle`].
    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    pub fn search_with_strategy_and_failure_oracle_bounded_depth(
        &mut self,
        scenario: &ScenarioDefForm,
        root: &Configuration,
        strategy: SearchStrategy,
        budget: SearchBudget,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        failure_oracle: &SearchFailureOracle,
        max_depth: Option<u64>,
    ) -> Result<TemporalGraphSearchRun, EngineError> {
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != root.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: root.def.id,
                actual: scenario_def.id,
            });
        }
        self.search_with_strategy_inner(
            root,
            strategy,
            budget,
            FrontierReductionPolicy::none(),
            materialization_policy,
            trigger,
            Some(scenario),
            failure_oracle,
            max_depth,
            None,
            None,
            None,
        )
    }

    /// Searches with a failure oracle, depth bound, and replay-oracle sampling.
    ///
    /// This is the strategy-search analogue of
    /// [`Self::search_with_replay_oracle_sampling`]: every explored child
    /// materialized as a fat checkpoint by the supplied policy is considered by
    /// `sampling_config`, and sampled checkpoints are immediately replayed
    /// through the thin oracle path.
    ///
    /// # Errors
    ///
    /// Returns the same errors as
    /// [`Self::search_with_strategy_and_failure_oracle_bounded_depth`], plus
    /// [`EngineError::SearchReplayOracleMismatch`] when a sampled fat checkpoint
    /// differs from its thin reconstruction.
    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    pub fn search_with_strategy_and_failure_oracle_bounded_depth_sampled(
        &mut self,
        scenario: &ScenarioDefForm,
        root: &Configuration,
        strategy: SearchStrategy,
        budget: SearchBudget,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        failure_oracle: &SearchFailureOracle,
        max_depth: Option<u64>,
        sampling_config: &SearchReplayOracleSamplingConfig,
    ) -> Result<TemporalGraphSampledSearchRun, EngineError> {
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != root.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: root.def.id,
                actual: scenario_def.id,
            });
        }
        let mut replay_oracle_sampling = SearchReplayOracleSamplingReport::default();
        let run = self.search_with_strategy_inner(
            root,
            strategy,
            budget,
            FrontierReductionPolicy::none(),
            materialization_policy,
            trigger,
            Some(scenario),
            failure_oracle,
            max_depth,
            None,
            Some(sampling_config),
            Some(&mut replay_oracle_sampling),
        )?;
        Ok(TemporalGraphSampledSearchRun {
            run,
            replay_oracle_sampling,
        })
    }

    /// Searches with a deterministic shared-worklist fleet model.
    ///
    /// The fleet model uses one shared content-addressed frontier, deterministic
    /// host claim ordering, and the same single-frontier expansion path as
    /// [`Self::search_with_strategy_and_failure_oracle`]. Host identities are
    /// recorded only as claim/order metadata in the returned report; they do not
    /// enter configurations, discovered findings, or reproduction artifacts.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not describe `root`. Returns other [`EngineError`] values when
    /// expanding a frontier or capturing a discovered finding artifact fails.
    pub fn search_with_work_stealing_fleet(
        &mut self,
        scenario: &ScenarioDefForm,
        root: &Configuration,
        config: FleetWorkStealingConfig,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        failure_oracle: &SearchFailureOracle,
    ) -> Result<FleetWorkStealingSearchRun, EngineError> {
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != root.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: root.def.id,
                actual: scenario_def.id,
            });
        }

        let host_count = config.host_count();
        let mut worklist = vec![SearchFrontierCandidate::new(root.clone())];
        let mut scheduled = BTreeSet::from([root.id()]);
        let mut expanded = BTreeSet::new();
        let mut explored_graph = BTreeSet::from([root.id()]);
        let mut claims = Vec::new();
        let mut discovered_failures = Vec::new();
        let mut discovered_failure_configurations = BTreeSet::new();
        record_search_discovered_failure(
            root,
            Some(scenario),
            failure_oracle,
            &mut discovered_failure_configurations,
            &mut discovered_failures,
        )?;

        while (claims.len() as u64) < config.total_budget.max_expansions {
            let sequence = claims.len() as u64;
            let Some(index) =
                select_fleet_work_stealing_candidate(&worklist, host_count, config.seed, sequence)
            else {
                break;
            };
            let host_index = fleet_claim_host_index(host_count, config.seed, sequence);
            let candidate = worklist.remove(index);
            if !expanded.insert(candidate.id()) {
                continue;
            }

            let search = self.search(
                &candidate.configuration,
                FrontierReductionPolicy::none(),
                materialization_policy,
                trigger,
            )?;
            for child in &search.frontier_report.explored {
                let child_id = child.configuration.id();
                explored_graph.insert(child_id);
                record_search_discovered_failure(
                    &child.configuration,
                    Some(scenario),
                    failure_oracle,
                    &mut discovered_failure_configurations,
                    &mut discovered_failures,
                )?;
                if scheduled.insert(child_id) {
                    worklist.push(SearchFrontierCandidate::new(child.configuration.clone()));
                }
            }
            for covered in &search.frontier_report.covered {
                if let Some(representative) = self
                    .recorded_configurations
                    .get(&covered.representative)
                    .cloned()
                {
                    let representative_id = representative.id();
                    explored_graph.insert(representative_id);
                    record_search_discovered_failure(
                        &representative,
                        Some(scenario),
                        failure_oracle,
                        &mut discovered_failure_configurations,
                        &mut discovered_failures,
                    )?;
                    if scheduled.insert(representative_id) {
                        worklist.push(SearchFrontierCandidate::new(representative));
                    }
                }
            }

            claims.push(FleetWorkClaim {
                sequence,
                host_index,
                frontier: candidate.id(),
                depth: candidate.depth,
                search,
            });
        }

        Ok(FleetWorkStealingSearchRun {
            root: root.id(),
            config,
            explored_graph,
            claims,
            discovered_failures,
            exhausted: worklist.is_empty(),
        })
    }
}
#[path = "core/checkpoint_cache.rs"]
mod checkpoint_cache;
#[path = "core/debug_navigation.rs"]
mod debug_navigation;
#[path = "core/reduced_search.rs"]
mod reduced_search;
