//! Temporal-graph search, frontier storage, and artifact persistence.

use super::*;

impl TemporalGraph {
    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::model) fn search_with_strategy_inner(
        &mut self,
        root: &Configuration,
        strategy: SearchStrategy,
        budget: SearchBudget,
        reduction_policy: FrontierReductionPolicy,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        scenario: Option<&ScenarioDefForm>,
        failure_oracle: &SearchFailureOracle,
        max_depth: Option<u64>,
        sampling_config: Option<&SearchReplayOracleSamplingConfig>,
        mut sampling_report: Option<&mut SearchReplayOracleSamplingReport>,
    ) -> Result<TemporalGraphSearchRun, EngineError> {
        let mut worklist = vec![SearchFrontierCandidate::new(root.clone())];
        let mut scheduled = BTreeSet::from([root.id()]);
        let mut expanded = BTreeSet::new();
        let mut explored_graph = BTreeSet::from([root.id()]);
        let mut expansions = Vec::new();
        let mut discovered_failures = Vec::new();
        let mut discovered_failure_configurations = BTreeSet::new();
        let mut sampling_sequence_offset = 0;
        record_search_discovered_failure(
            root,
            scenario,
            failure_oracle,
            &mut discovered_failure_configurations,
            &mut discovered_failures,
        )?;

        while (expansions.len() as u64) < budget.max_expansions {
            let Some(index) =
                select_search_frontier_candidate(self, &worklist, strategy, max_depth)
            else {
                break;
            };
            let candidate = worklist.remove(index);
            if !expanded.insert(candidate.id()) {
                continue;
            }

            let search = match sampling_config {
                Some(config) => self.search_with_replay_oracle_sampling_offset(
                    &candidate.configuration,
                    reduction_policy.clone(),
                    materialization_policy,
                    trigger,
                    config,
                    sampling_sequence_offset,
                )?,
                None => self.search(
                    &candidate.configuration,
                    reduction_policy.clone(),
                    materialization_policy,
                    trigger,
                )?,
            };
            if let (Some(total), Some(frontier_report)) = (
                sampling_report.as_deref_mut(),
                search.replay_oracle_sampling.as_ref(),
            ) {
                merge_search_replay_oracle_sampling_report(total, frontier_report);
            }
            if sampling_config.is_some() {
                sampling_sequence_offset =
                    sampling_sequence_offset.saturating_add(search.materialized.len() as u64);
            }
            for child in &search.frontier_report.explored {
                let child_id = child.configuration.id();
                explored_graph.insert(child_id);
                record_search_discovered_failure(
                    &child.configuration,
                    scenario,
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
                        scenario,
                        failure_oracle,
                        &mut discovered_failure_configurations,
                        &mut discovered_failures,
                    )?;
                    if scheduled.insert(representative_id) {
                        worklist.push(SearchFrontierCandidate::new(representative));
                    }
                }
            }

            expansions.push(SearchExpansion {
                sequence: expansions.len() as u64,
                frontier: candidate.id(),
                depth: candidate.depth,
                search,
            });
        }

        Ok(TemporalGraphSearchRun {
            root: root.id(),
            strategy,
            budget,
            explored_graph,
            expansions,
            discovered_failures,
            exhausted: worklist.is_empty(),
        })
    }

    /// Searches one frontier while sampling fat checkpoints through the replay oracle.
    ///
    /// Each explored child is materialized according to `materialization_policy`.
    /// Every returned fat checkpoint is considered for deterministic sampling;
    /// sampled fat checkpoints are immediately reconstructed through thin replay
    /// and compared before search returns.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::SearchReplayOracleMismatch`] when a sampled fat
    /// checkpoint differs from its thin reconstruction. Other graph,
    /// materialization, or replay-oracle validation errors are returned as
    /// [`EngineError`].
    pub fn search_with_replay_oracle_sampling(
        &mut self,
        frontier: &Configuration,
        reduction_policy: FrontierReductionPolicy,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        sampling_config: &SearchReplayOracleSamplingConfig,
    ) -> Result<TemporalGraphSearch, EngineError> {
        self.search_inner(
            frontier,
            reduction_policy,
            materialization_policy,
            trigger,
            Some(sampling_config),
            0,
        )
    }

    pub(in crate::model) fn search_with_replay_oracle_sampling_offset(
        &mut self,
        frontier: &Configuration,
        reduction_policy: FrontierReductionPolicy,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        sampling_config: &SearchReplayOracleSamplingConfig,
        sampling_sequence_offset: u64,
    ) -> Result<TemporalGraphSearch, EngineError> {
        self.search_inner(
            frontier,
            reduction_policy,
            materialization_policy,
            trigger,
            Some(sampling_config),
            sampling_sequence_offset,
        )
    }

    pub(in crate::model) fn search_inner(
        &mut self,
        frontier: &Configuration,
        reduction_policy: FrontierReductionPolicy,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        sampling_config: Option<&SearchReplayOracleSamplingConfig>,
        sampling_sequence_offset: u64,
    ) -> Result<TemporalGraphSearch, EngineError> {
        let frontier_runtime = self.resume(frontier)?;
        let frontier_id = frontier_runtime.configuration;
        let choices = search_frontier_choices(&frontier_runtime.runtime);
        let frontier_report =
            self.enumerate_frontier_choices_reduced(frontier, choices, reduction_policy)?;
        let mut materialized = Vec::new();
        let mut replay_oracle_sampling =
            sampling_config.map(|_| SearchReplayOracleSamplingReport::default());
        for (sequence, child) in frontier_report.explored.iter().enumerate() {
            let sequence = sampling_sequence_offset + sequence as u64;
            let checkpoint = match self.materialize_hot_checkpoint(
                &child.configuration,
                materialization_policy,
                trigger,
            ) {
                Ok(checkpoint) => checkpoint,
                Err(error) => {
                    return Err(match sampling_config {
                        Some(config) => sampled_search_replay_oracle_error(sequence, config, error),
                        None => error,
                    });
                }
            };

            if let (Some(config), Some(report)) = (sampling_config, replay_oracle_sampling.as_mut())
            {
                sample_search_replay_oracle_checkpoint(
                    self,
                    &child.configuration,
                    &checkpoint,
                    sequence,
                    config,
                    report,
                )?;
            }

            materialized.push(checkpoint);
        }

        Ok(TemporalGraphSearch {
            frontier: frontier_id,
            frontier_runtime,
            frontier_report,
            materialized,
            replay_oracle_sampling,
        })
    }

    /// Admits an exact cached snapshot only if it matches thin replay.
    ///
    /// Cached ancestors are admitted from genesis outward before the target is
    /// checked, so a corrupt ancestor cannot make a corrupt descendant appear
    /// valid. The exact target snapshot is never used to validate itself. On a
    /// replay mismatch or incomplete materialized state, the fat cache entry is
    /// evicted back to its thin checkpoint before the error is returned.
    ///
    /// # Errors
    ///
    /// Returns replay-oracle validation errors from [`Self::replay_checkpoint`].
    /// Returns eviction errors if a corrupt cache entry cannot be converted
    /// back to a thin checkpoint.
    pub fn replay_oracle_admit_cached_snapshot(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Option<ReplayOracleCheck>, EngineError> {
        let Some(checkpoint) = self.cached_snapshot(configuration).cloned() else {
            return Ok(None);
        };
        if let Err(error) = self.replay_oracle_admit_cached_ancestors(configuration) {
            if replay_oracle_failure_rejects_cache(&error) {
                self.evict_fat_checkpoint_to_thin(configuration)?;
            }
            return Err(error);
        }

        match self.replay_checkpoint(configuration, &checkpoint) {
            Ok(check) => Ok(Some(check)),
            Err(error) => {
                if replay_oracle_failure_rejects_cache(&error) {
                    self.evict_fat_checkpoint_to_thin(configuration)?;
                }
                Err(error)
            }
        }
    }

    /// Validates every cached fat snapshot as a replay-oracle invariant.
    ///
    /// Cached checkpoints are admitted from shortest schedule to longest so a
    /// corrupt ancestor is rejected before descendants can use it. The first
    /// mismatch is surfaced and no later cache entry is silently repaired.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when a cached checkpoint has
    /// no independent thin replay path. Returns replay-oracle validation errors
    /// from [`Self::replay_oracle_admit_cached_snapshot`].
    pub fn validate_cached_snapshots_with_replay_oracle(
        &mut self,
    ) -> Result<Vec<ReplayOracleCheck>, EngineError> {
        let mut configurations = self.cached_snapshot_configurations()?;
        configurations
            .sort_by_key(|configuration| (configuration.schedule.len(), configuration.id()));

        let mut checks = Vec::new();
        for configuration in configurations {
            if let Some(check) = self.replay_oracle_admit_cached_snapshot(&configuration)? {
                checks.push(check);
            }
        }
        Ok(checks)
    }

    /// Checks a stored fat checkpoint against its thin replay derivation.
    ///
    /// This is the on-demand replay operation: the supplied fat checkpoint is
    /// validated, the same configuration is reconstructed from an ancestor or
    /// baked genesis without using the target exact snapshot, and both
    /// checkpoint identities are compared.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] or
    /// [`EngineError::CheckpointNotLoadable`] when the fat checkpoint metadata
    /// is invalid. Returns [`EngineError::ReplayOracleMismatch`] when the thin
    /// derivation does not reproduce the fat checkpoint identity.
    pub fn replay_checkpoint(
        &self,
        configuration: &Configuration,
        checkpoint: &Checkpoint,
    ) -> Result<ReplayOracleCheck, EngineError> {
        validate_loadable_checkpoint(checkpoint, configuration)?;
        let thin_runtime = instantiate_thin_replay(self, configuration)?;
        let thin_checkpoint = if configuration.is_genesis() {
            self.genesis_snapshot(&configuration.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                })?
                .checkpoint
                .clone()
        } else {
            materialized_checkpoint_for_runtime(configuration, thin_runtime)?
        };
        validate_loadable_checkpoint(&thin_checkpoint, configuration)?;
        let fat_state = checkpoint.state.as_ref().ok_or(
            EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: checkpoint.id,
                reason: "missing-state",
            },
        )?;
        let thin_state = thin_checkpoint.state.as_ref().ok_or(
            EngineError::CheckpointMaterializedStateIncomplete {
                checkpoint: thin_checkpoint.id,
                reason: "missing-state",
            },
        )?;
        if checkpoint.id != thin_checkpoint.id
            || checkpoint.node_blobs != thin_checkpoint.node_blobs
            || checkpoint.node_icounts != thin_checkpoint.node_icounts
            || fat_state.event_log != thin_state.event_log
            || fat_state.id != thin_state.id
        {
            return Err(EngineError::ReplayOracleMismatch {
                checkpoint: checkpoint.id,
                expected: thin_state.id,
                actual: fat_state.id,
            });
        }

        Ok(ReplayOracleCheck {
            configuration: configuration.id(),
            fat_checkpoint: checkpoint.id,
            thin_checkpoint: thin_checkpoint.id,
        })
    }

    /// Enumerates frontier checkpoint children by applying decisions with `step`.
    ///
    /// The temporal graph records the frontier and each unique child in the
    /// baked-genesis-rooted checkpoint DAG. Duplicate child configurations are
    /// returned once, in stable content-address order, and previously recorded
    /// children are marked so a search driver can avoid re-materializing them.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the scenario has no
    /// baked root. Returns other [`EngineError`] variants if the frontier or a
    /// child cannot be represented as a valid checkpoint edge.
    pub fn enumerate_frontier<I>(
        &mut self,
        frontier: &Configuration,
        decisions: I,
    ) -> Result<Vec<FrontierChild>, EngineError>
    where
        I: IntoIterator<Item = Decision>,
    {
        self.record_checkpoint_closure(frontier)?;
        let mut children = BTreeMap::new();
        for decision in decisions {
            let configuration = try_step(frontier, decision.clone())?;
            children.entry(configuration.id()).or_insert(FrontierChild {
                decision,
                configuration,
                already_recorded: false,
            });
        }

        let mut result = Vec::new();
        for mut child in children.into_values() {
            child.already_recorded = !self.record_checkpoint_closure(&child.configuration)?;
            result.push(child);
        }
        Ok(result)
    }

    /// Enumerates frontier children while applying graph-level reductions.
    ///
    /// Partial-order reduction is applied before recording a child only when an
    /// explicit independence proof covers adjacent schedule decisions and the
    /// candidate appears in non-canonical order; the canonical representative is
    /// recorded on demand before the candidate is marked covered. Symmetry
    /// reduction uses explicit interchangeable-node classes plus a loadable
    /// checkpoint's canonicalized materialized state; candidates without such
    /// proof material are explored.
    ///
    /// The reductions never rewrite a child configuration. Explored children
    /// remain ordinary content-addressed DAG nodes, and covered children carry
    /// the representative configuration id that justified skipping expansion.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the scenario has no
    /// baked root. Returns other [`EngineError`] variants if the frontier or an
    /// explored child cannot be represented as a valid checkpoint edge.
    pub fn enumerate_frontier_reduced<I>(
        &mut self,
        frontier: &Configuration,
        decisions: I,
        policy: FrontierReductionPolicy,
    ) -> Result<FrontierReductionReport, EngineError>
    where
        I: IntoIterator<Item = Decision>,
    {
        self.record_checkpoint_closure(frontier)?;
        let mut children = BTreeMap::new();
        let mut covered = Vec::new();
        for decision in decisions {
            let configuration = try_step(frontier, decision.clone())?;
            if let Some(cover) =
                partial_order_cover(self, decision.clone(), configuration.clone(), &policy)?
            {
                covered.push(cover);
                continue;
            }
            children.entry(configuration.id()).or_insert(FrontierChild {
                decision,
                configuration,
                already_recorded: false,
            });
        }

        let mut explored = Vec::new();
        let mut symmetry_representatives = BTreeMap::new();
        let candidate_ids = children.keys().copied().collect::<BTreeSet<_>>();
        for mut child in children.into_values() {
            if let Some(key) =
                self.symmetry_reduction_key(&child.configuration, &policy.symmetry_classes)
            {
                if let Some(representative) = self.symmetry_representative_for_key_excluding(
                    key,
                    &candidate_ids,
                    &policy.symmetry_classes,
                ) {
                    covered.push(FrontierCoveredChild {
                        decision: child.decision,
                        configuration: child.configuration,
                        representative,
                        reason: FrontierReductionReason::Symmetry,
                        reduction_key: key.fingerprint,
                    });
                    continue;
                }
                match symmetry_representatives.entry(key) {
                    Entry::Vacant(entry) => {
                        entry.insert(child.configuration.id());
                    }
                    Entry::Occupied(entry) => {
                        covered.push(FrontierCoveredChild {
                            decision: child.decision,
                            configuration: child.configuration,
                            representative: *entry.get(),
                            reason: FrontierReductionReason::Symmetry,
                            reduction_key: key.fingerprint,
                        });
                        continue;
                    }
                }
            }
            child.already_recorded = !self.record_checkpoint_closure(&child.configuration)?;
            explored.push(child);
        }

        Ok(FrontierReductionReport { explored, covered })
    }

    pub(in crate::model) fn enumerate_frontier_choices_reduced<I>(
        &mut self,
        frontier: &Configuration,
        choices: I,
        policy: FrontierReductionPolicy,
    ) -> Result<FrontierReductionReport, EngineError>
    where
        I: IntoIterator<Item = SearchFrontierChoice>,
    {
        self.record_checkpoint_closure(frontier)?;
        let mut children = BTreeMap::new();
        let mut covered = Vec::new();
        for choice in choices {
            let mut configuration = frontier.clone();
            for decision in choice.decisions() {
                configuration = try_step(&configuration, decision.clone())?;
            }
            let decision = choice.decision().clone();
            if let Some(cover) =
                partial_order_cover(self, decision.clone(), configuration.clone(), &policy)?
            {
                covered.push(cover);
                continue;
            }
            children.entry(configuration.id()).or_insert(FrontierChild {
                decision,
                configuration,
                already_recorded: false,
            });
        }

        let mut explored = Vec::new();
        let mut symmetry_representatives = BTreeMap::new();
        let candidate_ids = children.keys().copied().collect::<BTreeSet<_>>();
        for mut child in children.into_values() {
            if let Some(key) =
                self.symmetry_reduction_key(&child.configuration, &policy.symmetry_classes)
            {
                if let Some(representative) = self.symmetry_representative_for_key_excluding(
                    key,
                    &candidate_ids,
                    &policy.symmetry_classes,
                ) {
                    covered.push(FrontierCoveredChild {
                        decision: child.decision,
                        configuration: child.configuration,
                        representative,
                        reason: FrontierReductionReason::Symmetry,
                        reduction_key: key.fingerprint,
                    });
                    continue;
                }
                match symmetry_representatives.entry(key) {
                    Entry::Vacant(entry) => {
                        entry.insert(child.configuration.id());
                    }
                    Entry::Occupied(entry) => {
                        covered.push(FrontierCoveredChild {
                            decision: child.decision,
                            configuration: child.configuration,
                            representative: *entry.get(),
                            reason: FrontierReductionReason::Symmetry,
                            reduction_key: key.fingerprint,
                        });
                        continue;
                    }
                }
            }
            child.already_recorded = !self.record_checkpoint_closure(&child.configuration)?;
            explored.push(child);
        }

        Ok(FrontierReductionReport { explored, covered })
    }

    /// Records one `step` edge in the checkpoint DAG.
    ///
    /// The graph must already contain the baked genesis checkpoint for the
    /// scenario. The returned checkpoint is a thin recorded child unless an
    /// identical configuration was already present, in which case the existing
    /// checkpoint node is returned.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the scenario has no
    /// baked root. Returns other [`EngineError`] variants if the parent/delta
    /// edge cannot be represented as a valid checkpoint.
    pub fn record_step(
        &mut self,
        parent: &Configuration,
        decision: Decision,
    ) -> Result<Checkpoint, EngineError> {
        self.record_checkpoint_closure(parent)?;
        let child = try_step(parent, decision)?;
        self.record_checkpoint_closure(&child)?;
        self.checkpoint_node(child.id())
            .cloned()
            .ok_or(EngineError::CheckpointNotRecorded {
                checkpoint: child.id(),
            })
    }

    /// Returns a recorded checkpoint DAG node by id.
    #[must_use]
    pub fn checkpoint_node(&self, checkpoint: ContentHash) -> Option<&Checkpoint> {
        self.checkpoint_nodes.get(&checkpoint)
    }

    /// Returns a recorded checkpoint DAG node or exact cached snapshot by id.
    #[must_use]
    pub fn checkpoint_record(&self, checkpoint: ContentHash) -> Option<&Checkpoint> {
        self.checkpoint_nodes
            .get(&checkpoint)
            .or_else(|| self.cached_snapshots.get(&checkpoint))
    }

    /// Returns the recorded configuration denoted by a checkpoint id.
    #[must_use]
    pub fn checkpoint_configuration(&self, checkpoint: ContentHash) -> Option<&Configuration> {
        self.checkpoint_record(checkpoint)
            .and_then(|node| self.recorded_configurations.get(&node.configuration))
    }

    /// Resumes the recorded configuration denoted by `checkpoint`.
    ///
    /// This is the checkpoint-addressed form of [`Self::resume`]. It resolves the
    /// checkpoint back to its recorded configuration, then realizes that
    /// configuration through the same graph-backed [`instantiate`] path. A recorded
    /// thin checkpoint delegates to [`Self::resume`]; a standalone exact cached
    /// snapshot can instantiate directly because it has no thin closure to record.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointNotRecorded`] when `checkpoint` or its
    /// configuration is absent from the graph. Returns other [`EngineError`]
    /// variants from [`Self::resume`] when realization fails.
    pub fn resume_checkpoint(
        &mut self,
        checkpoint: ContentHash,
    ) -> Result<TemporalGraphRuntime, EngineError> {
        let configuration = self
            .checkpoint_configuration(checkpoint)
            .cloned()
            .ok_or(EngineError::CheckpointNotRecorded { checkpoint })?;
        if self.checkpoint_node(checkpoint).is_some() {
            self.resume(&configuration)
        } else {
            let runtime = instantiate(self, &configuration)?;
            Ok(TemporalGraphRuntime {
                configuration: configuration.id(),
                checkpoint,
                runtime,
            })
        }
    }

    /// Returns the symmetry-reduction key for a recorded configuration.
    ///
    /// Exact cached snapshots are preferred because they carry the richest
    /// per-node material. If neither a cached snapshot nor a checkpoint node has
    /// explicit coverage, a loadable materialized state, and an unambiguous
    /// class-based canonical relabeling, `None` is returned and search must
    /// explore the candidate.
    #[must_use]
    pub fn symmetry_reduction_key(
        &self,
        configuration: &Configuration,
        classes: &SymmetryReductionClasses,
    ) -> Option<SymmetryReductionKey> {
        self.cached_snapshots
            .get(&configuration.id())
            .or_else(|| self.checkpoint_nodes.get(&configuration.id()))
            .and_then(|checkpoint| checkpoint.symmetry_reduction_key(classes))
    }

    pub(in crate::model) fn symmetry_representative_for_key_excluding(
        &self,
        key: SymmetryReductionKey,
        excluded: &BTreeSet<ContentHash>,
        classes: &SymmetryReductionClasses,
    ) -> Option<ContentHash> {
        let mut representatives = BTreeSet::new();
        for checkpoint in self
            .checkpoint_nodes
            .values()
            .chain(self.cached_snapshots.values())
        {
            if excluded.contains(&checkpoint.configuration) {
                continue;
            }
            if checkpoint.symmetry_reduction_key(classes) == Some(key) {
                representatives.insert(checkpoint.configuration);
            }
        }
        representatives.into_iter().next()
    }

    /// Returns the number of deduplicated checkpoint DAG nodes.
    #[must_use]
    pub fn checkpoint_node_count(&self) -> usize {
        self.checkpoint_nodes.len()
    }

    /// Returns the root-to-target parent chain for `checkpoint`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointNotRecorded`] when the target or one of
    /// its parents is absent from the graph.
    pub fn checkpoint_parent_chain(
        &self,
        checkpoint: ContentHash,
    ) -> Result<Vec<Checkpoint>, EngineError> {
        let mut current = checkpoint;
        let mut reversed = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(current) {
                return Err(EngineError::CheckpointTopologyMismatch {
                    checkpoint: current,
                    reason: "parent-cycle",
                });
            }
            let node = self
                .checkpoint_node(current)
                .ok_or(EngineError::CheckpointNotRecorded {
                    checkpoint: current,
                })?;
            reversed.push(node.clone());
            let Some(parent) = node.parent else {
                break;
            };
            current = parent;
        }
        reversed.reverse();
        Ok(reversed)
    }

    /// Persists the root-to-frontier checkpoint closure into `store`.
    ///
    /// The returned keys include checkpoint-node descriptors, typed CoW delta
    /// descriptors, and a reproduction artifact whose scenario, genesis, and
    /// schedule-delta fields are all portable [`DagStore`] keys. VM/device/log
    /// byte streams are owned by lower layers; the pure model persists their
    /// typed content references here so the graph records the same closure shape
    /// that those layers populate with raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TemporalGraphStoreError::Engine`] when the graph cannot derive a
    /// valid baked-genesis-rooted checkpoint closure. Returns
    /// [`TemporalGraphStoreError::Store`] when `store` cannot persist an object.
    pub fn persist_checkpoint_closure<S>(
        &mut self,
        store: &S,
        frontier: &Configuration,
    ) -> Result<TemporalGraphStoreKeys, TemporalGraphStoreError>
    where
        S: DagStore + ?Sized,
    {
        self.record_checkpoint_closure(frontier).map_err(|source| {
            TemporalGraphStoreError::Engine {
                operation: "record-checkpoint-closure",
                source: Box::new(source),
            }
        })?;
        let chain = self
            .checkpoint_parent_chain(frontier.id())
            .map_err(|source| TemporalGraphStoreError::Engine {
                operation: "checkpoint-parent-chain",
                source: Box::new(source),
            })?;
        let genesis = self.genesis_snapshot(&frontier.def).ok_or_else(|| {
            TemporalGraphStoreError::Engine {
                operation: "load-genesis-snapshot",
                source: Box::new(EngineError::MissingBakedGenesis {
                    scenario: frontier.def.id,
                }),
            }
        })?;

        let scenario_def = store
            .put(&scenario_def_store_bytes(&frontier.def))
            .map_err(|source| TemporalGraphStoreError::Store {
                operation: "put-scenario-def",
                source,
            })?;
        let genesis_snapshot = store
            .put(&checkpoint_store_bytes(&genesis.checkpoint))
            .map_err(|source| TemporalGraphStoreError::Store {
                operation: "put-genesis-snapshot",
                source,
            })?;

        let mut checkpoint_nodes = BTreeMap::new();
        let mut cached_snapshots = BTreeMap::new();
        let mut cow_deltas = BTreeMap::new();
        let mut schedule_deltas = Vec::new();
        let mut event_log_segments = Vec::new();
        for checkpoint in &chain {
            let checkpoint_key =
                store
                    .put(&checkpoint_store_bytes(checkpoint))
                    .map_err(|source| TemporalGraphStoreError::Store {
                        operation: "put-checkpoint-node",
                        source,
                    })?;
            checkpoint_nodes.insert(checkpoint.id, checkpoint_key);

            persist_checkpoint_cow_deltas(
                store,
                checkpoint,
                &mut cow_deltas,
                &mut schedule_deltas,
                &mut event_log_segments,
            )?;

            if let Some(snapshot) = self.cached_snapshots.get(&checkpoint.id) {
                let snapshot_key =
                    store
                        .put(&checkpoint_store_bytes(snapshot))
                        .map_err(|source| TemporalGraphStoreError::Store {
                            operation: "put-cached-snapshot",
                            source,
                        })?;
                cached_snapshots.insert(snapshot.id, snapshot_key);
                persist_checkpoint_cow_deltas(
                    store,
                    snapshot,
                    &mut cow_deltas,
                    &mut schedule_deltas,
                    &mut event_log_segments,
                )?;
            }
        }

        Ok(TemporalGraphStoreKeys {
            checkpoint_nodes,
            cached_snapshots,
            cow_deltas,
            reproduction_artifact: DagStoreReproductionArtifact::new(
                scenario_def,
                genesis_snapshot,
                schedule_deltas,
            )
            .with_event_log_segment_keys(event_log_segments),
        })
    }

    /// Computes reference counts for objects reachable from `roots`.
    ///
    /// Baked genesis checkpoints are implicit roots. A live or pinned checkpoint
    /// roots its parent chain, cached snapshot when present, and all typed CoW
    /// deltas referenced by the retained checkpoint/cache closure.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointNotRecorded`] when a live or pinned root
    /// is absent from the checkpoint DAG. Returns
    /// [`EngineError::CheckpointTopologyMismatch`] when a parent chain is
    /// malformed.
    pub fn reference_counts(
        &self,
        roots: &TemporalGraphGcRoots,
    ) -> Result<TemporalGraphReferenceCounts, EngineError> {
        let live_checkpoints = self.mark_live_checkpoints(roots)?;
        Ok(self.reference_counts_for_live_checkpoints(roots, &live_checkpoints))
    }

    /// Runs mark-and-sweep garbage collection over the temporal graph.
    ///
    /// The sweep is rooted at live session tips, pinned checkpoints, and every
    /// baked genesis checkpoint. Unreachable thin checkpoint nodes and exact
    /// cached snapshots are removed; reachable fat cache entries stay cache
    /// entries because they are still referenced by a live identity. Use
    /// [`Self::collect_cached_snapshot`] to explicitly collect a reachable fat
    /// cache entry without deleting its checkpoint identity.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointNotRecorded`] when a live or pinned root
    /// is absent from the checkpoint DAG. Returns
    /// [`EngineError::CheckpointTopologyMismatch`] when a parent chain is
    /// malformed.
    pub fn garbage_collect(
        &mut self,
        roots: &TemporalGraphGcRoots,
    ) -> Result<TemporalGraphGcReport, EngineError> {
        let before_checkpoints = self
            .checkpoint_nodes
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let before_cached_snapshots = self
            .cached_snapshots
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let before_configurations = self
            .recorded_configurations
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let before_cow_deltas = self.cow_delta_ref_set();
        let before_store_keys = self.store_keys_for_checkpoint_ids(&self.store_checkpoint_ids());
        let live_checkpoints = self.mark_live_checkpoints(roots)?;
        let live_reference_counts =
            self.reference_counts_for_live_checkpoints(roots, &live_checkpoints);
        let live_store_keys = self.store_keys_for_checkpoint_ids(&live_checkpoints);

        self.checkpoint_nodes
            .retain(|checkpoint, _| live_checkpoints.contains(checkpoint));
        self.cached_snapshots
            .retain(|checkpoint, _| live_checkpoints.contains(checkpoint));
        self.recorded_configurations
            .retain(|configuration, _| live_checkpoints.contains(configuration));

        let retained_checkpoints = self
            .checkpoint_nodes
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let retained_cached_snapshots = self
            .cached_snapshots
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let retained_configurations = self
            .recorded_configurations
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let retained_cow_deltas = live_reference_counts
            .cow_deltas
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();

        Ok(TemporalGraphGcReport {
            roots: roots.clone(),
            live_checkpoints,
            live_reference_counts,
            collected_checkpoints: before_checkpoints
                .difference(&retained_checkpoints)
                .copied()
                .collect(),
            collected_cached_snapshots: before_cached_snapshots
                .difference(&retained_cached_snapshots)
                .copied()
                .collect(),
            collected_configurations: before_configurations
                .difference(&retained_configurations)
                .copied()
                .collect(),
            collectible_cow_deltas: before_cow_deltas
                .difference(&retained_cow_deltas)
                .copied()
                .collect(),
            live_store_keys: live_store_keys.clone(),
            collectible_store_keys: before_store_keys
                .difference(&live_store_keys)
                .copied()
                .collect(),
            deleted_store_keys: BTreeSet::new(),
            missing_store_keys: BTreeSet::new(),
        })
    }

    /// Runs mark-and-sweep GC and deletes swept objects from `store`.
    ///
    /// The graph first computes the pre-sweep and retained content-addressed
    /// store-key closures. After unreachable graph/cache/configuration entries
    /// are removed, every store key unique to the swept closure is deleted from
    /// `store`.
    ///
    /// # Errors
    ///
    /// Returns [`TemporalGraphStoreError::Engine`] when root reachability cannot
    /// be computed. Returns [`TemporalGraphStoreError::Store`] when `store`
    /// rejects a delete operation. A store error may occur after the graph maps
    /// have been swept.
    pub fn garbage_collect_store<S>(
        &mut self,
        store: &S,
        roots: &TemporalGraphGcRoots,
    ) -> Result<TemporalGraphGcReport, TemporalGraphStoreError>
    where
        S: DagStore + ?Sized,
    {
        let mut report =
            self.garbage_collect(roots)
                .map_err(|source| TemporalGraphStoreError::Engine {
                    operation: "garbage-collect",
                    source: Box::new(source),
                })?;
        delete_collectible_store_keys(store, &mut report)?;
        Ok(report)
    }

    /// Collects a reachable fat cache entry without deleting its checkpoint.
    ///
    /// This is the cache-not-identity GC rule: the exact snapshot is removed,
    /// and the checkpoint remains as a thin DAG node that can be replayed from
    /// its retained ancestor chain.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the graph cannot record
    /// the thin source node for `configuration`. Returns
    /// [`EngineError::CheckpointNotRecorded`] if the thin node is absent after
    /// closure recording.
    pub fn collect_cached_snapshot(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Option<Checkpoint>, EngineError> {
        if self.cached_snapshot(configuration).is_none() {
            return Ok(None);
        }
        self.evict_fat_checkpoint_to_thin(configuration).map(Some)
    }

    /// Collects a reachable fat cache entry and deletes its now-unreferenced store keys.
    ///
    /// This is the store-backed form of [`Self::collect_cached_snapshot`]. The
    /// thin checkpoint identity remains in the graph, while the persisted
    /// cached-snapshot descriptor and any cache-only CoW descriptor keys are
    /// removed from `store`.
    ///
    /// # Errors
    ///
    /// Returns [`TemporalGraphStoreError::Engine`] when the graph cannot evict
    /// the fat cache entry to its thin source node. Returns
    /// [`TemporalGraphStoreError::Store`] when `store` rejects a delete
    /// operation.
    pub fn collect_cached_snapshot_store<S>(
        &mut self,
        store: &S,
        configuration: &Configuration,
    ) -> Result<Option<TemporalGraphGcReport>, TemporalGraphStoreError>
    where
        S: DagStore + ?Sized,
    {
        if self.cached_snapshot(configuration).is_none() {
            return Ok(None);
        }

        let before_store_keys = self.store_keys_for_checkpoint_ids(&self.store_checkpoint_ids());
        let before_cow_deltas = self.cow_delta_ref_set();
        self.collect_cached_snapshot(configuration)
            .map_err(|source| TemporalGraphStoreError::Engine {
                operation: "collect-cached-snapshot",
                source: Box::new(source),
            })?;
        let live_checkpoints = self
            .checkpoint_nodes
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let live_store_keys = self.store_keys_for_checkpoint_ids(&self.store_checkpoint_ids());
        let retained_cow_deltas = self.cow_delta_ref_set();
        let mut report = TemporalGraphGcReport {
            roots: TemporalGraphGcRoots::new(),
            live_checkpoints,
            live_reference_counts: TemporalGraphReferenceCounts::default(),
            collected_checkpoints: BTreeSet::new(),
            collected_cached_snapshots: BTreeSet::from([configuration.id()]),
            collected_configurations: BTreeSet::new(),
            collectible_cow_deltas: before_cow_deltas
                .difference(&retained_cow_deltas)
                .copied()
                .collect(),
            live_store_keys: live_store_keys.clone(),
            collectible_store_keys: before_store_keys
                .difference(&live_store_keys)
                .copied()
                .collect(),
            deleted_store_keys: BTreeSet::new(),
            missing_store_keys: BTreeSet::new(),
        };
        delete_collectible_store_keys(store, &mut report)?;
        Ok(Some(report))
    }

    /// Returns whether `configuration` is recorded in the temporal graph.
    #[must_use]
    pub fn contains_configuration(&self, configuration: &Configuration) -> bool {
        self.recorded_configurations
            .contains_key(&configuration.id())
    }

    /// Returns the number of deduplicated configurations recorded by the graph.
    #[must_use]
    pub fn recorded_configuration_count(&self) -> usize {
        self.recorded_configurations.len()
    }

    /// Returns the number of saved non-genesis fat checkpoints in the graph.
    #[must_use]
    pub fn cached_snapshot_count(&self) -> usize {
        self.cached_snapshots.len()
    }

    /// Returns CoW sharing stats for recorded DAG nodes and exact-snapshot cache entries.
    #[must_use]
    pub fn cow_sharing_stats(&self) -> CowSharingStats {
        CowSharingStats::from_refs(self.cow_delta_refs())
    }

    /// Returns how many new CoW objects `checkpoint` would add to this graph.
    ///
    /// Existing objects are matched by typed content hash, so a sibling fork
    /// that dirties the same VM page, device overlay page, or event-log segment
    /// pays no additional storage for that already-present delta object.
    #[must_use]
    pub fn marginal_fork_cow_delta_objects(&self, checkpoint: &Checkpoint) -> usize {
        let existing = self.cow_delta_ref_set();
        checkpoint
            .cow_delta_refs()
            .into_iter()
            .filter(|cow_ref| !existing.contains(cow_ref))
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub(in crate::model) fn record_configuration(&mut self, configuration: Configuration) -> bool {
        let id = configuration.id();
        match self.recorded_configurations.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(configuration);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    pub(in crate::model) fn cow_delta_refs(&self) -> Vec<CowDeltaRef> {
        let mut refs = Vec::new();
        for checkpoint in self.checkpoint_nodes.values() {
            refs.extend(checkpoint.cow_delta_refs());
        }
        for checkpoint in self.cached_snapshots.values() {
            refs.extend(checkpoint.cow_delta_refs());
        }
        refs
    }

    pub(in crate::model) fn cow_delta_ref_set(&self) -> BTreeSet<CowDeltaRef> {
        self.cow_delta_refs().into_iter().collect()
    }

    pub(in crate::model) fn mark_live_checkpoints(
        &self,
        roots: &TemporalGraphGcRoots,
    ) -> Result<BTreeSet<ContentHash>, EngineError> {
        let mut live = BTreeSet::new();
        for root in self.gc_root_checkpoint_ids(roots) {
            let chain = self.checkpoint_parent_chain(root)?;
            live.extend(chain.into_iter().map(|checkpoint| checkpoint.id));
        }
        Ok(live)
    }

    pub(in crate::model) fn gc_root_checkpoint_ids(
        &self,
        roots: &TemporalGraphGcRoots,
    ) -> BTreeSet<ContentHash> {
        let mut root_ids = BTreeSet::new();
        root_ids.extend(
            roots
                .live_tips
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(checkpoint, _)| *checkpoint),
        );
        root_ids.extend(
            roots
                .pinned_checkpoints
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(checkpoint, _)| *checkpoint),
        );
        root_ids.extend(
            self.baked_genesis
                .values()
                .map(|genesis| genesis.checkpoint.id),
        );
        root_ids
    }

    pub(in crate::model) fn reference_counts_for_live_checkpoints(
        &self,
        roots: &TemporalGraphGcRoots,
        live_checkpoints: &BTreeSet<ContentHash>,
    ) -> TemporalGraphReferenceCounts {
        let mut counts = TemporalGraphReferenceCounts::default();
        for (root, refcount) in self.gc_root_refcounts(roots) {
            if live_checkpoints.contains(&root) {
                for _ in 0..refcount {
                    counts.increment_checkpoint(root);
                }
            }
        }
        for checkpoint_id in live_checkpoints {
            let Some(checkpoint) = self.checkpoint_nodes.get(checkpoint_id) else {
                continue;
            };
            if let Some(parent) = checkpoint.parent
                && live_checkpoints.contains(&parent)
            {
                counts.increment_checkpoint(parent);
            }
            for cow_ref in checkpoint.cow_delta_refs() {
                counts.increment_cow_delta(cow_ref);
            }
            if let Some(snapshot) = self.cached_snapshots.get(checkpoint_id) {
                counts.increment_cached_snapshot(*checkpoint_id);
                for cow_ref in snapshot.cow_delta_refs() {
                    counts.increment_cow_delta(cow_ref);
                }
            }
        }
        counts
    }

    pub(in crate::model) fn gc_root_refcounts(
        &self,
        roots: &TemporalGraphGcRoots,
    ) -> BTreeMap<ContentHash, usize> {
        let mut refcounts = BTreeMap::new();
        for (checkpoint, count) in &roots.live_tips {
            if *count == 0 {
                continue;
            }
            *refcounts.entry(*checkpoint).or_insert(0) += *count;
        }
        for (checkpoint, count) in &roots.pinned_checkpoints {
            if *count == 0 {
                continue;
            }
            *refcounts.entry(*checkpoint).or_insert(0) += *count;
        }
        for genesis in self.baked_genesis.values() {
            *refcounts.entry(genesis.checkpoint.id).or_insert(0) += 1;
        }
        refcounts
    }

    pub(in crate::model) fn store_checkpoint_ids(&self) -> BTreeSet<ContentHash> {
        let mut checkpoints = self
            .checkpoint_nodes
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        checkpoints.extend(self.cached_snapshots.keys().copied());
        checkpoints
    }

    pub(in crate::model) fn store_keys_for_checkpoint_ids(
        &self,
        checkpoints: &BTreeSet<ContentHash>,
    ) -> BTreeSet<ContentHash> {
        let mut keys = BTreeSet::new();
        for configuration in self.recorded_configurations.values() {
            if checkpoints.contains(&configuration.id()) {
                keys.insert(ContentHash::from_bytes(&scenario_def_store_bytes(
                    &configuration.def,
                )));
                if let Some(genesis) = self.genesis_snapshot(&configuration.def) {
                    keys.insert(ContentHash::from_bytes(&checkpoint_store_bytes(
                        &genesis.checkpoint,
                    )));
                }
            }
        }
        for checkpoint_id in checkpoints {
            if let Some(checkpoint) = self.checkpoint_nodes.get(checkpoint_id) {
                insert_checkpoint_store_keys(checkpoint, &mut keys);
            }
            if let Some(snapshot) = self.cached_snapshots.get(checkpoint_id) {
                insert_checkpoint_store_keys(snapshot, &mut keys);
            }
        }
        keys
    }

    pub(in crate::model) fn has_replay_oracle_path(
        &self,
        configuration: &Configuration,
    ) -> Result<bool, EngineError> {
        if configuration.is_genesis() {
            return Ok(self.genesis_snapshot(&configuration.def).is_some());
        }
        Ok(self.genesis_snapshot(&configuration.def).is_some())
    }

    pub(in crate::model) fn replay_oracle_admit_cached_ancestors(
        &mut self,
        configuration: &Configuration,
    ) -> Result<(), EngineError> {
        let ancestors = self.cached_ancestor_configurations(configuration)?;
        for ancestor in ancestors {
            self.replay_oracle_admit_cached_snapshot(&ancestor)?;
        }
        Ok(())
    }

    pub(in crate::model) fn cached_ancestor_configurations(
        &self,
        configuration: &Configuration,
    ) -> Result<Vec<Configuration>, EngineError> {
        let mut ancestors = Vec::new();
        for prefix_len in 0..configuration.schedule.len() {
            let schedule = configuration
                .schedule
                .prefix(prefix_len)
                .map_err(EngineError::SchedulePrefix)?;
            let ancestor = Configuration {
                def: configuration.def.clone(),
                schedule,
            };
            if self.cached_snapshot(&ancestor).is_some() {
                ancestors.push(ancestor);
            }
        }
        Ok(ancestors)
    }

    pub(in crate::model) fn cached_snapshot_configurations(
        &self,
    ) -> Result<Vec<Configuration>, EngineError> {
        let mut configurations = Vec::new();
        for checkpoint in self.cached_snapshots.keys() {
            let configuration = self.recorded_configurations.get(checkpoint).ok_or(
                EngineError::CheckpointNotRecorded {
                    checkpoint: *checkpoint,
                },
            )?;
            configurations.push(configuration.clone());
        }
        Ok(configurations)
    }

    pub(in crate::model) fn record_checkpoint_closure(
        &mut self,
        configuration: &Configuration,
    ) -> Result<bool, EngineError> {
        if self.checkpoint_nodes.contains_key(&configuration.id()) {
            self.record_configuration(configuration.clone());
            return Ok(false);
        }
        if configuration.is_genesis() {
            let checkpoint = self
                .genesis_snapshot(&configuration.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                })?
                .checkpoint
                .clone();
            self.record_configuration(configuration.clone());
            self.checkpoint_nodes.insert(configuration.id(), checkpoint);
            return Ok(true);
        }

        let parent = immediate_parent_configuration(configuration)?.ok_or(
            EngineError::CheckpointTopologyMismatch {
                checkpoint: configuration.id(),
                reason: "descendant-missing-parent",
            },
        )?;
        self.record_checkpoint_closure(&parent)?;
        let mut checkpoint = Checkpoint::from_recorded_configuration(
            configuration,
            Some(&parent),
            configuration_virtual_time(configuration),
            self.thin_checkpoint_node_icounts(configuration)?,
            CheckpointKind::Thin,
            BTreeMap::new(),
        )?;
        if let Some(snapshot) = self.cached_snapshots.get(&configuration.id()) {
            checkpoint.coverage_fingerprint = snapshot.coverage_fingerprint;
            checkpoint.assertion_proximity_fingerprint = snapshot.assertion_proximity_fingerprint;
        }
        self.record_configuration(configuration.clone());
        self.checkpoint_nodes.insert(configuration.id(), checkpoint);
        Ok(true)
    }

    /// Returns the exact loadable snapshot for `configuration`, if one exists.
    #[must_use]
    pub fn cached_snapshot(&self, configuration: &Configuration) -> Option<&Checkpoint> {
        self.cached_snapshots.get(&configuration.id())
    }

    /// Returns the baked genesis snapshot for `def`, if one exists.
    #[must_use]
    pub fn genesis_snapshot(&self, def: &ScenarioDef) -> Option<&GenesisCheckpoint> {
        self.baked_genesis.get(&def.id)
    }

    /// Returns the nearest cached ancestor of `configuration`, excluding itself.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if a schedule prefix cannot be constructed.
    pub fn nearest_cached_ancestor(
        &self,
        configuration: &Configuration,
    ) -> Result<Option<Configuration>, EngineError> {
        for prefix_len in (0..configuration.schedule.len()).rev() {
            let schedule = configuration
                .schedule
                .prefix(prefix_len)
                .map_err(EngineError::SchedulePrefix)?;
            let ancestor = Configuration {
                def: configuration.def.clone(),
                schedule,
            };
            if self.cached_snapshot(&ancestor).is_some() {
                return Ok(Some(ancestor));
            }
        }

        Ok(None)
    }

    pub(in crate::model) fn debug_restore_configuration(
        &self,
        target: &Configuration,
    ) -> Result<Configuration, EngineError> {
        if target.is_genesis() || self.cached_snapshot(target).is_some() {
            return Ok(target.clone());
        }
        if let Some(ancestor) = self.nearest_cached_ancestor(target)? {
            return Ok(ancestor);
        }
        Ok(Configuration::genesis(target.def.clone()))
    }

    pub(in crate::model) fn thin_checkpoint_node_icounts(
        &self,
        configuration: &Configuration,
    ) -> Result<BTreeMap<NodeId, Icount>, EngineError> {
        let genesis =
            self.genesis_snapshot(&configuration.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                })?;
        Ok(replayed_node_icounts(
            &genesis.checkpoint.node_icounts,
            &configuration.schedule,
        ))
    }

    pub(in crate::model) fn debug_resolve_coordinate(
        &self,
        current: &Configuration,
        coordinate: &DebugCoordinate,
        event_coordinates: &BTreeMap<u64, Configuration>,
    ) -> Result<Configuration, EngineError> {
        match coordinate {
            DebugCoordinate::Configuration(configuration) => Ok(configuration.clone()),
            DebugCoordinate::Checkpoint(checkpoint) => {
                self.recorded_configurations.get(checkpoint).cloned().ok_or(
                    EngineError::CheckpointNotRecorded {
                        checkpoint: *checkpoint,
                    },
                )
            }
            DebugCoordinate::EventSequence(sequence) => event_coordinates
                .get(sequence)
                .cloned()
                .ok_or(EngineError::DebugTimeTravelMissingEventCoordinate {
                    sequence: *sequence,
                }),
            DebugCoordinate::VirtualTime(time) => self
                .debug_latest_checkpoint_at_or_before_time(current, *time)
                .ok_or_else(|| EngineError::DebugTimeTravelCoordinateNotFound {
                    coordinate: coordinate.clone(),
                }),
            DebugCoordinate::NodeIcount { node, icount } => self
                .debug_latest_checkpoint_at_or_before_icount(current, node, *icount)
                .ok_or_else(|| EngineError::DebugTimeTravelCoordinateNotFound {
                    coordinate: coordinate.clone(),
                }),
        }
    }

    pub(in crate::model) fn debug_resolve_scoped_node_icount(
        &self,
        current: &Configuration,
        node: &NodeId,
        target: Icount,
    ) -> Option<Configuration> {
        self.debug_scoped_node_coordinate_candidates(current)
            .into_iter()
            .filter_map(|candidate| {
                let icount = candidate.node_icounts.get(node).copied()?;
                if icount == target {
                    Some((candidate, icount))
                } else {
                    None
                }
            })
            .max_by_key(|(candidate, icount)| {
                (
                    *icount,
                    candidate.virtual_time,
                    candidate.configuration.schedule.len(),
                    candidate.configuration.id(),
                )
            })
            .map(|(candidate, _)| candidate.configuration)
    }

    pub(in crate::model) fn debug_scoped_node_material(
        &mut self,
        current: &Configuration,
        target: &Configuration,
        node: NodeId,
        requested_icount: Icount,
    ) -> Result<DebugScopedNodeMaterial, EngineError> {
        debug_validate_same_scenario(current, target)?;
        self.record_checkpoint_closure(target)?;
        let restore = Configuration::genesis(target.def.clone());
        let restore_checkpoint = self
            .genesis_snapshot(&target.def)
            .ok_or(EngineError::MissingBakedGenesis {
                scenario: target.def.id,
            })?
            .checkpoint
            .clone();
        let (restore_icount, restore_blob) =
            debug_checkpoint_node_material(&restore_checkpoint, &node, restore.id())?;
        let replay_suffix = target
            .schedule
            .suffix_from(restore.schedule.len())
            .map_err(EngineError::SchedulePrefix)?;
        let (node_icount, node_blob) = if replay_suffix.is_empty() {
            (restore_icount, restore_blob)
        } else {
            let replayed_icounts = replayed_node_icounts(
                &BTreeMap::from([(node.clone(), restore_icount)]),
                &replay_suffix,
            );
            let replayed_blobs = replayed_node_blobs(
                &BTreeMap::from([(node.clone(), restore_blob)]),
                &restore,
                &replay_suffix,
                target,
            );
            (
                replayed_icounts.get(&node).copied().ok_or_else(|| {
                    EngineError::DebugTimeTravelUnknownNode {
                        node: node.clone(),
                        configuration: target.id(),
                    }
                })?,
                replayed_blobs.get(&node).cloned().ok_or_else(|| {
                    EngineError::DebugTimeTravelUnknownNode {
                        node: node.clone(),
                        configuration: target.id(),
                    }
                })?,
            )
        };
        if node_icount != requested_icount {
            return Err(EngineError::DebugTimeTravelCoordinateNotFound {
                coordinate: DebugCoordinate::node_icount(node, requested_icount),
            });
        }
        let mut materialized_nodes = BTreeSet::new();
        materialized_nodes.insert(node.clone());

        Ok(DebugScopedNodeMaterial {
            target_configuration: target.id(),
            node_icount,
            node_blob,
            goto: DebugPerNodeGotoReport {
                current_configuration: current.id(),
                target_coordinate: DebugCoordinate::node_icount(node, requested_icount),
                target_configuration: target.id(),
                restore_configuration: restore.id(),
                restore_checkpoint: restore_checkpoint.id,
                replay_suffix_decisions: replay_suffix.len(),
                replay_oracle: None,
                materialized_nodes,
            },
        })
    }

    pub(in crate::model) fn debug_latest_checkpoint_at_or_before_time(
        &self,
        current: &Configuration,
        target: VirtualTime,
    ) -> Option<Configuration> {
        self.debug_checkpoint_coordinate_candidates(current)
            .into_iter()
            .filter(|candidate| candidate.virtual_time <= target)
            .max_by_key(|candidate| {
                (
                    candidate.virtual_time,
                    candidate.configuration.schedule.len(),
                    candidate.configuration.id(),
                )
            })
            .map(|candidate| candidate.configuration)
    }

    pub(in crate::model) fn debug_latest_checkpoint_at_or_before_icount(
        &self,
        current: &Configuration,
        node: &NodeId,
        target: Icount,
    ) -> Option<Configuration> {
        self.debug_checkpoint_coordinate_candidates(current)
            .into_iter()
            .filter_map(|candidate| {
                let icount = candidate.node_icounts.get(node).copied()?;
                if icount <= target {
                    Some((candidate, icount))
                } else {
                    None
                }
            })
            .max_by_key(|(candidate, icount)| {
                (
                    *icount,
                    candidate.virtual_time,
                    candidate.configuration.schedule.len(),
                    candidate.configuration.id(),
                )
            })
            .map(|(candidate, _)| candidate.configuration)
    }

    pub(in crate::model) fn debug_checkpoint_coordinate_candidates(
        &self,
        current: &Configuration,
    ) -> Vec<DebugCheckpointCoordinateCandidate> {
        self.debug_checkpoint_coordinate_candidates_where(current, |configuration| {
            debug_configuration_is_ancestor_or_self(configuration, current)
        })
    }

    pub(in crate::model) fn debug_scoped_node_coordinate_candidates(
        &self,
        current: &Configuration,
    ) -> Vec<DebugCheckpointCoordinateCandidate> {
        self.debug_checkpoint_coordinate_candidates_where(current, |configuration| {
            debug_configurations_are_linearly_related(configuration, current)
        })
    }

    pub(in crate::model) fn debug_checkpoint_coordinate_candidates_where<F>(
        &self,
        current: &Configuration,
        include: F,
    ) -> Vec<DebugCheckpointCoordinateCandidate>
    where
        F: Fn(&Configuration) -> bool,
    {
        let mut candidates = BTreeMap::<ContentHash, DebugCheckpointCoordinateCandidate>::new();
        for checkpoint in self
            .checkpoint_nodes
            .values()
            .chain(self.cached_snapshots.values())
        {
            if checkpoint.scenario_ref != current.def.id {
                continue;
            }
            let Some(configuration) = self.recorded_configurations.get(&checkpoint.configuration)
            else {
                continue;
            };
            if !include(configuration) {
                continue;
            }
            candidates
                .entry(checkpoint.configuration)
                .and_modify(|candidate| {
                    if candidate.node_icounts.is_empty() && !checkpoint.node_icounts.is_empty() {
                        candidate.node_icounts = checkpoint.node_icounts.clone();
                    }
                    if checkpoint.virtual_time > candidate.virtual_time {
                        candidate.virtual_time = checkpoint.virtual_time;
                    }
                })
                .or_insert_with(|| DebugCheckpointCoordinateCandidate {
                    configuration: configuration.clone(),
                    virtual_time: checkpoint.virtual_time,
                    node_icounts: checkpoint.node_icounts.clone(),
                });
        }
        candidates.into_values().collect()
    }

    pub(in crate::model) fn debug_goto_error(
        &self,
        current: &Configuration,
        target: &Configuration,
        restore: &Configuration,
        error: EngineError,
    ) -> EngineError {
        match error {
            EngineError::ReplayOracleMismatch {
                checkpoint,
                expected,
                actual,
            } => EngineError::DebugGotoReplayOracleMismatch {
                bisection: Box::new(self.debug_replay_oracle_bisection(current, target, restore)),
                checkpoint,
                expected,
                actual,
            },
            other => other,
        }
    }

    pub(in crate::model) fn debug_replay_oracle_bisection(
        &self,
        current: &Configuration,
        target: &Configuration,
        restore: &Configuration,
    ) -> DebugReplayOracleBisectionRequest {
        let mut low = 0_usize;
        let mut high = target.schedule.len();
        while low < high {
            let mid = low + (high - low) / 2;
            let prefix = debug_configuration_prefix(target, mid).unwrap_or_else(|_| target.clone());
            match debug_cached_prefix_matches_replay_oracle(self, &prefix) {
                Ok(true) => low = mid.saturating_add(1),
                Ok(false) | Err(_) => high = mid,
            }
        }
        let restore_checkpoint = self
            .checkpoint_node(restore.id())
            .or_else(|| self.cached_snapshot(restore))
            .map(|checkpoint| checkpoint.id)
            .unwrap_or_else(|| restore.id());
        DebugReplayOracleBisectionRequest {
            current_configuration: current.id(),
            target_configuration: target.id(),
            restore_configuration: restore.id(),
            restore_checkpoint,
            last_matching_schedule_prefix_len: low.checked_sub(1),
            first_different_schedule_prefix_len: low,
        }
    }
}
