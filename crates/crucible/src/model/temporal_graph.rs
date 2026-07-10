// Temporal graph storage, replay, checkpointing, and time-travel core.

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
    topology_nodes: Vec<WorldNodeDef>,
    /// Derived VM-only projection retained for the legacy VM authoring/runtime API.
    /// It is rebuilt from `topology_nodes` by every constructor and is not a
    /// separate logical topology collection.
    nodes: Vec<WorldNode>,
    links: Vec<LinkDef>,
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
    recorded_configurations: BTreeMap<ContentHash, Configuration>,
    checkpoint_nodes: BTreeMap<ContentHash, Checkpoint>,
    cached_snapshots: BTreeMap<ContentHash, Checkpoint>,
    baked_genesis: BTreeMap<ContentHash, GenesisCheckpoint>,
    non_canonical_debug_branches: BTreeMap<ContentHash, DebugNonCanonicalBranch>,
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

    /// Returns a graph with a loadable snapshot registered for `configuration`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when the
    /// checkpoint does not name `configuration`, or
    /// [`EngineError::CheckpointNotLoadable`] when `checkpoint` is not fat.
    /// Returns [`EngineError::GenesisSnapshotMustBeBaked`] when
    /// `configuration` is the scenario genesis.
    pub fn with_cached_snapshot(
        mut self,
        configuration: &Configuration,
        checkpoint: Checkpoint,
    ) -> Result<Self, EngineError> {
        self.cache_snapshot(configuration, checkpoint)?;
        Ok(self)
    }

    /// Registers a loadable snapshot for `configuration`.
    ///
    /// When the graph has the scenario's baked genesis, this also records the
    /// thin checkpoint closure for `configuration` and keeps that thin node as
    /// the source of truth. The supplied fat checkpoint is stored only as the
    /// loadable cache entry.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when the
    /// checkpoint does not name `configuration`, or
    /// [`EngineError::CheckpointNotLoadable`] when `checkpoint` is not fat.
    /// Returns [`EngineError::GenesisSnapshotMustBeBaked`] when
    /// `configuration` is the scenario genesis.
    pub fn cache_snapshot(
        &mut self,
        configuration: &Configuration,
        checkpoint: Checkpoint,
    ) -> Result<(), EngineError> {
        if configuration.is_genesis() {
            return Err(EngineError::GenesisSnapshotMustBeBaked {
                configuration: configuration.id(),
            });
        }
        validate_loadable_checkpoint(&checkpoint, configuration)?;
        if self.genesis_snapshot(&configuration.def).is_some() {
            self.record_checkpoint_closure(configuration)?;
        }
        self.record_configuration(configuration.clone());
        self.cached_snapshots.insert(configuration.id(), checkpoint);
        Ok(())
    }

    /// Registers a loadable snapshot with coverage feedback derived from event-log entries.
    ///
    /// Search and fuzzing consumers read the resulting
    /// [`Checkpoint::coverage_fingerprint`] through the normal checkpoint/cache
    /// path. This method is the boundary for callers that have retained unified
    /// event-log entries: the graph stores only the deterministic projection
    /// digest, not a second coverage record.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::cache_snapshot`].
    pub fn cache_snapshot_with_event_log_coverage(
        &mut self,
        configuration: &Configuration,
        checkpoint: Checkpoint,
        entries: &[crate::scheduler::SchedulerEventLogEntry],
    ) -> Result<(), EngineError> {
        let fingerprint = crate::scheduler::coverage_fingerprint_from_event_log(entries);
        self.cache_snapshot(
            configuration,
            checkpoint.with_coverage_fingerprint(fingerprint),
        )?;
        if let Some(checkpoint) = self.checkpoint_nodes.get_mut(&configuration.id()) {
            checkpoint.coverage_fingerprint = fingerprint;
        }
        Ok(())
    }

    /// Registers a loadable snapshot with assertion-proximity feedback from event-log entries.
    ///
    /// Guided search consumers read the resulting
    /// [`Checkpoint::assertion_proximity_fingerprint`] through the normal
    /// checkpoint/cache path. The graph stores the deterministic projection digest
    /// only; the source distances stay in the unified event log.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::cache_snapshot`].
    pub fn cache_snapshot_with_event_log_assertion_proximity(
        &mut self,
        configuration: &Configuration,
        checkpoint: Checkpoint,
        entries: &[crate::scheduler::SchedulerEventLogEntry],
    ) -> Result<(), EngineError> {
        let fingerprint = crate::scheduler::assertion_proximity_fingerprint_from_event_log(entries);
        self.cache_snapshot(
            configuration,
            checkpoint.with_assertion_proximity_from_event_log(entries),
        )?;
        if let Some(checkpoint) = self.checkpoint_nodes.get_mut(&configuration.id()) {
            checkpoint.assertion_proximity_fingerprint = fingerprint;
        }
        Ok(())
    }

    /// Registers `checkpoint` only when the savevm hedge allows fat caching.
    ///
    /// If the hedge marks the snapshot unreliable, the graph records and
    /// returns the thin source-of-truth checkpoint instead of inserting the fat
    /// cache entry.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] or related
    /// checkpoint-validation errors when the supplied fat checkpoint metadata is
    /// invalid. Returns [`EngineError::MissingBakedGenesis`] when the hedge
    /// rejects the fat checkpoint but no baked root exists to support thin
    /// replay.
    pub fn cache_snapshot_with_savevm_hedge(
        &mut self,
        configuration: &Configuration,
        checkpoint: Checkpoint,
        hedge: &SavevmCompletenessHedge,
    ) -> Result<Checkpoint, EngineError> {
        validate_loadable_checkpoint(&checkpoint, configuration)?;
        if hedge.allows_checkpoint(&checkpoint) {
            self.cache_snapshot(configuration, checkpoint.clone())?;
            Ok(checkpoint)
        } else {
            self.evict_fat_checkpoint_to_thin(configuration)
        }
    }

    /// Returns a graph with the baked genesis checkpoint registered for `def`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when the baked
    /// checkpoint does not name the genesis configuration for `def`, or
    /// [`EngineError::CheckpointNotLoadable`] when the baked checkpoint is not
    /// fat.
    pub fn with_baked_genesis(
        mut self,
        def: &ScenarioDef,
        genesis: GenesisCheckpoint,
    ) -> Result<Self, EngineError> {
        self.cache_baked_genesis(def, genesis)?;
        Ok(self)
    }

    /// Registers the baked genesis checkpoint for `def`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when the baked
    /// checkpoint does not name the genesis configuration for `def`, or
    /// [`EngineError::CheckpointNotLoadable`] when the baked checkpoint is not
    /// fat.
    pub fn cache_baked_genesis(
        &mut self,
        def: &ScenarioDef,
        genesis: GenesisCheckpoint,
    ) -> Result<(), EngineError> {
        let genesis_config = Configuration::genesis(def.clone());
        validate_loadable_checkpoint(&genesis.checkpoint, &genesis_config)?;
        self.record_configuration(genesis_config);
        self.checkpoint_nodes
            .insert(genesis.checkpoint.id, genesis.checkpoint.clone());
        self.baked_genesis.insert(def.id, genesis);
        Ok(())
    }

    /// Records `configuration` as a thin checkpoint source-of-truth node.
    ///
    /// Descendants are recorded with `state = None`; the baked genesis remains
    /// the materialized root because there is no cold-boot checkpoint in the
    /// temporal graph.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the graph has no baked
    /// root for the scenario. Returns other [`EngineError`] variants if the
    /// parent/delta edge cannot be represented as a valid checkpoint.
    pub fn record_thin_checkpoint(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Checkpoint, EngineError> {
        self.record_checkpoint_closure(configuration)?;
        self.checkpoint_node(configuration.id()).cloned().ok_or(
            EngineError::CheckpointNotRecorded {
                checkpoint: configuration.id(),
            },
        )
    }

    /// Materializes `configuration` as a fat checkpoint cache entry.
    ///
    /// The thin checkpoint remains the canonical DAG node whenever the graph
    /// has a baked genesis root. The returned fat checkpoint is validated by
    /// replaying the same configuration through the thin ancestor path before
    /// it is inserted into the exact-snapshot cache.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when no exact or ancestor
    /// cache can realize the configuration. Returns other [`EngineError`]
    /// variants when replay validation or checkpoint metadata validation fails.
    pub fn materialize_checkpoint(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Checkpoint, EngineError> {
        self.record_configuration(configuration.clone());
        if configuration.is_genesis() {
            let genesis = self.genesis_snapshot(&configuration.def).ok_or(
                EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                },
            )?;
            return Ok(genesis.checkpoint.clone());
        }
        if self.genesis_snapshot(&configuration.def).is_some() {
            self.record_thin_checkpoint(configuration)?;
        }
        if self.cached_snapshot(configuration).is_some() {
            if self.has_replay_oracle_path(configuration)? {
                self.replay_oracle_admit_cached_snapshot(configuration)?;
            }
            if let Some(checkpoint) = self.cached_snapshot(configuration) {
                return Ok(checkpoint.clone());
            }
        }
        if self.has_replay_oracle_path(configuration)? {
            self.replay_oracle_admit_cached_ancestors(configuration)?;
        }

        let runtime = instantiate(self, configuration)?;
        let checkpoint = materialized_checkpoint_for_runtime(configuration, runtime)?;
        self.replay_checkpoint(configuration, &checkpoint)?;
        self.cache_snapshot(configuration, checkpoint.clone())?;
        Ok(checkpoint)
    }

    /// Materializes `configuration` only when the savevm hedge permits it.
    ///
    /// The thin checkpoint is returned when fat snapshots are disabled or when
    /// the materialized state touches a device whose snapshot is unreliable.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the graph cannot
    /// record or replay the thin source-of-truth path. Returns other
    /// [`EngineError`] variants from checkpoint validation or replay-oracle
    /// validation.
    pub fn materialize_checkpoint_with_savevm_hedge(
        &mut self,
        configuration: &Configuration,
        hedge: &SavevmCompletenessHedge,
    ) -> Result<Checkpoint, EngineError> {
        self.record_configuration(configuration.clone());
        if configuration.is_genesis() {
            let genesis = self.genesis_snapshot(&configuration.def).ok_or(
                EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                },
            )?;
            return Ok(genesis.checkpoint.clone());
        }
        if self.genesis_snapshot(&configuration.def).is_some() {
            self.record_thin_checkpoint(configuration)?;
        }
        if let Some(checkpoint) = self.cached_snapshot(configuration).cloned() {
            if !hedge.allows_checkpoint(&checkpoint) {
                return self.evict_fat_checkpoint_to_thin(configuration);
            }
            if self.has_replay_oracle_path(configuration)? {
                self.replay_oracle_admit_cached_snapshot(configuration)?;
            }
            if let Some(checkpoint) = self.cached_snapshot(configuration).cloned() {
                return Ok(checkpoint);
            }
        }
        if !hedge.fat_snapshot_default() {
            return self.record_thin_checkpoint(configuration);
        }
        if self.has_replay_oracle_path(configuration)? {
            self.replay_oracle_admit_cached_ancestors(configuration)?;
        }

        let runtime = instantiate(self, configuration)?;
        let checkpoint = materialized_checkpoint_for_runtime(configuration, runtime)?;
        self.replay_checkpoint(configuration, &checkpoint)?;
        if hedge.allows_checkpoint(&checkpoint) {
            self.cache_snapshot(configuration, checkpoint.clone())?;
            Ok(checkpoint)
        } else {
            self.record_thin_checkpoint(configuration)
        }
    }

    /// Applies the hot-node materialization policy to `configuration`.
    ///
    /// Hot nodes within budget are materialized through
    /// [`Self::materialize_checkpoint`]. Cold or over-budget nodes are kept as
    /// thin DAG checkpoints and returned in that form.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when a thin checkpoint
    /// cannot be recorded or a requested materialization cannot be realized.
    /// Returns other [`EngineError`] variants from checkpoint validation.
    pub fn materialize_hot_checkpoint(
        &mut self,
        configuration: &Configuration,
        policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
    ) -> Result<Checkpoint, EngineError> {
        if self.cached_snapshot(configuration).is_some() {
            if self.has_replay_oracle_path(configuration)? {
                self.replay_oracle_admit_cached_snapshot(configuration)?;
            }
            if let Some(checkpoint) = self.cached_snapshot(configuration) {
                return Ok(checkpoint.clone());
            }
        }
        if policy.should_materialize(self.cached_snapshot_count(), trigger) {
            self.materialize_checkpoint(configuration)
        } else {
            self.record_thin_checkpoint(configuration)
        }
    }

    /// Applies both hot-node policy and the savevm-completeness hedge.
    ///
    /// Even hot nodes remain thin when fat snapshots are globally disabled or
    /// their materialized state contains an unreliable device snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the graph cannot
    /// record or replay the thin source-of-truth path. Returns other
    /// [`EngineError`] variants from checkpoint validation.
    pub fn materialize_hot_checkpoint_with_savevm_hedge(
        &mut self,
        configuration: &Configuration,
        policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        hedge: &SavevmCompletenessHedge,
    ) -> Result<Checkpoint, EngineError> {
        if self.cached_snapshot(configuration).is_some()
            && self.has_replay_oracle_path(configuration)?
        {
            self.replay_oracle_admit_cached_snapshot(configuration)?;
        }
        if let Some(checkpoint) = self.cached_snapshot(configuration).cloned() {
            if hedge.allows_checkpoint(&checkpoint) {
                return Ok(checkpoint);
            }
            return self.evict_fat_checkpoint_to_thin(configuration);
        }
        if policy.should_materialize(self.cached_snapshot_count(), trigger) {
            self.materialize_checkpoint_with_savevm_hedge(configuration, hedge)
        } else {
            self.record_thin_checkpoint(configuration)
        }
    }

    /// Evicts an ordinary fat checkpoint cache entry back to its thin node.
    ///
    /// The checkpoint identity and denoted configuration are unchanged. The
    /// exact-snapshot cache entry is dropped, and future realization must use
    /// ancestor replay until the node is materialized again. Baked genesis is
    /// not an ordinary cache entry and remains the graph root.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the thin source node
    /// cannot be recorded. Returns [`EngineError::CheckpointNotRecorded`] if
    /// the thin node is still absent after closure recording.
    pub fn evict_fat_checkpoint_to_thin(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Checkpoint, EngineError> {
        if configuration.is_genesis() {
            return self
                .genesis_snapshot(&configuration.def)
                .map(|genesis| genesis.checkpoint.clone())
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                });
        }
        if self.checkpoint_node(configuration.id()).is_none() {
            self.record_checkpoint_closure(configuration)?;
        }
        self.cached_snapshots.remove(&configuration.id());
        self.checkpoint_node(configuration.id()).cloned().ok_or(
            EngineError::CheckpointNotRecorded {
                checkpoint: configuration.id(),
            },
        )
    }

    /// Saves `configuration` as a fat checkpoint in the temporal graph.
    ///
    /// The checkpoint cache key is the configuration's content address. Saving
    /// the same configuration repeatedly is idempotent and returns the existing
    /// checkpoint instead of re-materializing a duplicate node.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when materialization reaches
    /// genesis without a baked genesis checkpoint. Returns other
    /// [`EngineError`] variants when cached checkpoint metadata is invalid.
    pub fn save_checkpoint(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Checkpoint, EngineError> {
        self.materialize_checkpoint(configuration)
    }

    /// Saves `configuration` as a graph checkpoint and persists its DAG-store closure.
    ///
    /// This is the user-facing save operation expressed on the temporal graph:
    /// it realizes the configuration via [`instantiate`], validates the fat
    /// checkpoint against thin replay, keeps the thin checkpoint as the DAG
    /// source of truth, and writes the content-addressed closure through
    /// `store`.
    ///
    /// # Errors
    ///
    /// Returns [`TemporalGraphStoreError::Engine`] when materialization or
    /// replay-oracle validation fails. Returns [`TemporalGraphStoreError::Store`]
    /// when `store` cannot persist an object.
    pub fn save<S>(
        &mut self,
        store: &S,
        configuration: &Configuration,
    ) -> Result<TemporalGraphSave, TemporalGraphStoreError>
    where
        S: DagStore + ?Sized,
    {
        let checkpoint = self.save_checkpoint(configuration).map_err(|source| {
            TemporalGraphStoreError::Engine {
                operation: "save-checkpoint",
                source: Box::new(source),
            }
        })?;
        let store_keys = self.persist_checkpoint_closure(store, configuration)?;
        Ok(TemporalGraphSave {
            configuration: configuration.id(),
            checkpoint: checkpoint.id,
            checkpoint_kind: checkpoint.kind,
            store_keys,
        })
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

    /// Attaches a debug session by realizing the requested checkpoint configuration.
    ///
    /// Debug attach is intentionally just [`Self::resume`] plus metadata for the
    /// fourth out-of-band gdbstub channel. It records no scheduler decision,
    /// carries no per-quantum/frame data, and introduces no debug-specific
    /// realization path.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::resume`] when the checkpoint
    /// configuration cannot be instantiated. Returns
    /// [`EngineError::DebugAttachUnknownNode`] when the realized runtime does not
    /// contain the requested node.
    pub fn debug_attach(
        &mut self,
        request: &DebugAttachRequest,
    ) -> Result<DebugAttachReport, EngineError> {
        let runtime = self.resume(&request.configuration)?;
        let node = request.node.clone();
        if !runtime.runtime.node_blobs.contains_key(&node)
            || !runtime.runtime.node_icounts.contains_key(&node)
        {
            return Err(EngineError::DebugAttachUnknownNode {
                node,
                configuration: request.configuration.id(),
            });
        }
        let reduced = reduce(&request.configuration.def, &request.configuration.schedule)?;
        if runtime.runtime.id != reduced.id {
            return Err(EngineError::ReplayTargetMismatch {
                expected: reduced.id,
                actual: runtime.runtime.id,
            });
        }

        Ok(DebugAttachReport {
            configuration: request.configuration.id(),
            checkpoint: runtime.checkpoint,
            runtime,
            reduced_state: reduced.id,
            channel_set: DebugAttachChannelSet::four_channel_debug_session(),
            gdbstub: DebugGdbstubChannel {
                node: request.node.clone(),
                qemu_endpoint: request.qemu_gdbstub.clone(),
                operator_listen: request.gdb_listen.clone(),
                mediated_by_crucible: true,
                out_of_band: true,
                carries_per_quantum_timing: false,
                carries_frame_data: false,
            },
        })
    }

    /// Records read-only debugger observations without mutating the temporal graph.
    ///
    /// The immutable receiver is part of the contract: inspection cannot record
    /// graph state, append decisions, or advance virtual time through this API.
    /// The report captures graph/checkpoint/runtime footprints before and after
    /// building the debugger event-log view, then compares canonical causal
    /// projections of the supplied no-debug log and the debug-observed log.
    #[must_use]
    pub fn read_only_debug_inspection(
        &self,
        attach: &DebugAttachReport,
        request: &DebugReadOnlyInspectionRequest,
        event_log: &[SchedulerEventLogEntry],
    ) -> DebugReadOnlyInspectionReport {
        let footprint_before =
            DebugReadOnlyInspectionFootprint::capture(self, attach, request.virtual_time);
        let observation_time = footprint_before.virtual_time;
        let causal_event_log_before = event_log_causal_projection(event_log);
        let mut event_log_with_observations = event_log.to_vec();
        let mut observational_entries = Vec::with_capacity(request.inspections.len() + 2);
        let mut sequence = u64::try_from(event_log.len()).unwrap_or(u64::MAX);

        observational_entries.push(debug_read_only_observation_entry(
            sequence,
            observation_time,
            DebugReadOnlyInspectionEvent::Attach,
            attach,
        ));
        sequence = sequence.saturating_add(1);
        for inspection in &request.inspections {
            observational_entries.push(debug_read_only_observation_entry(
                sequence,
                observation_time,
                DebugReadOnlyInspectionEvent::Inspect(*inspection),
                attach,
            ));
            sequence = sequence.saturating_add(1);
        }
        observational_entries.push(debug_read_only_observation_entry(
            sequence,
            observation_time,
            DebugReadOnlyInspectionEvent::Detach,
            attach,
        ));

        event_log_with_observations.extend(observational_entries.iter().cloned());
        let causal_event_log_after = event_log_causal_projection(&event_log_with_observations);
        let footprint_after =
            DebugReadOnlyInspectionFootprint::capture(self, attach, request.virtual_time);

        DebugReadOnlyInspectionReport {
            footprint_before,
            footprint_after,
            requested_virtual_time: request.virtual_time,
            causal_event_log_before,
            causal_event_log_after,
            observational_entries,
            event_log_with_observations,
        }
    }

    /// Resolves a canonical debugger breakpoint without guest-memory mutation.
    ///
    /// Software breakpoint requests are translated to an out-of-band mechanism
    /// when one is available. If the request would require patching a trap into
    /// guest memory, the operation returns a typed `--allow-mutate` error rather
    /// than modifying the canonical run.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DebugAttachUnknownNode`] when the request names a
    /// node outside the attached runtime. Returns
    /// [`EngineError::DebugBreakpointRequiresAllowMutate`] when no canonical
    /// out-of-band mechanism can satisfy the request.
    pub fn canonical_debug_breakpoint(
        &self,
        attach: &DebugAttachReport,
        request: &DebugBreakpointRequest,
    ) -> Result<DebugBreakpointReport, EngineError> {
        if request.node != attach.gdbstub.node
            || !attach
                .runtime
                .runtime
                .node_blobs
                .contains_key(&request.node)
            || !attach
                .runtime
                .runtime
                .node_icounts
                .contains_key(&request.node)
        {
            return Err(EngineError::DebugAttachUnknownNode {
                node: request.node.clone(),
                configuration: attach.configuration,
            });
        }
        let mechanism = request.canonical_mechanism().ok_or_else(|| {
            EngineError::DebugBreakpointRequiresAllowMutate {
                node: request.node.clone(),
                target: request.target.clone(),
                requested_client_kind: request.client_kind,
            }
        })?;

        Ok(DebugBreakpointReport {
            configuration: attach.configuration,
            checkpoint: attach.checkpoint,
            node: request.node.clone(),
            requested_client_kind: request.client_kind,
            target: request.target.clone(),
            mechanism,
            canonical: true,
            mutates_guest_memory: false,
            memory_patch_used: false,
            requires_allow_mutate: false,
        })
    }

    /// Forks an attached debugger into a marked non-canonical debug branch.
    ///
    /// The branch is recorded as debug metadata rather than as a
    /// [`Configuration`]. Decision-expressible edits and control-log operations
    /// are retained separately from the debug-edit script for arbitrary
    /// guest-state changes. The canonical graph/checkpoint/runtime footprint and
    /// causal event-log projection are preserved.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DebugGotoAttachMismatch`] when `attach` does not
    /// realize `request.current`. Returns
    /// [`EngineError::DebugNonCanonicalBranchMissingTriggerEvidence`] when the
    /// request trigger is not backed by a corresponding operator action.
    pub fn debug_non_canonical_branch(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugNonCanonicalBranchRequest,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<DebugNonCanonicalBranchReport, EngineError> {
        if attach.configuration != request.current.id() {
            return Err(EngineError::DebugGotoAttachMismatch {
                attached: attach.configuration,
                requested_current: request.current.id(),
            });
        }
        if !request.trigger_has_evidence() {
            return Err(EngineError::DebugNonCanonicalBranchMissingTriggerEvidence {
                trigger: request.trigger,
                configuration: request.current.id(),
            });
        }

        let footprint_before = DebugReadOnlyInspectionFootprint::capture(self, attach, request.at);
        let causal_event_log_before =
            canonical_run_event_log_projection_without_debug_branches(event_log);
        let marker_sequence = next_event_log_sequence(event_log);
        let branch = DebugNonCanonicalBranch::from_request(attach, request, marker_sequence);
        let mut event_log_with_fork_marker = event_log.to_vec();
        event_log_with_fork_marker.push(branch.fork_marker.entry.clone());
        let causal_event_log_after =
            canonical_run_event_log_projection_without_debug_branches(&event_log_with_fork_marker);
        self.non_canonical_debug_branches
            .insert(branch.id, branch.clone());
        let footprint_after = DebugReadOnlyInspectionFootprint::capture(self, attach, request.at);

        Ok(DebugNonCanonicalBranchReport {
            branch,
            canonical_footprint_before: footprint_before,
            canonical_footprint_after: footprint_after,
            causal_event_log_before,
            causal_event_log_after,
            event_log_with_fork_marker,
        })
    }

    /// Returns a recorded non-canonical debug branch by id.
    #[must_use]
    pub fn debug_non_canonical_branch_view(
        &self,
        branch: ContentHash,
    ) -> Option<&DebugNonCanonicalBranch> {
        self.non_canonical_debug_branches.get(&branch)
    }

    /// Returns the number of non-canonical debug branches recorded as graph metadata.
    #[must_use]
    pub fn debug_non_canonical_branch_count(&self) -> usize {
        self.non_canonical_debug_branches.len()
    }

    /// Resolves an operator-facing debug target into a `goto` request.
    ///
    /// The resolver accepts the public coordinate forms used by the debug CLI:
    /// direct `--at` coordinates, event-log sequence coordinates, the first
    /// assertion failure in the event log, checkpoint content addresses, and
    /// divergence-bisection coordinates. The returned request delegates actual
    /// movement to [`Self::debug_goto`], keeping target resolution separate from
    /// restore-plus-replay execution.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the selector has no matching event-log or
    /// checkpoint coordinate, when `--at-failure` sees no assertion violation,
    /// or when the resolved target belongs to another scenario.
    pub fn debug_resolve_target(
        &self,
        request: &DebugTargetResolverRequest,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<DebugTargetResolverReport, EngineError> {
        let mut failure_event_sequence = None;
        let mut divergence = None;
        let mut exact_target = None;
        let resolved_coordinate = match &request.selector {
            DebugTargetSelector::At(coordinate) => coordinate.clone(),
            DebugTargetSelector::AtEvent(sequence) => {
                if !debug_event_log_contains_sequence(event_log, *sequence) {
                    return Err(EngineError::DebugTimeTravelMissingEventCoordinate {
                        sequence: *sequence,
                    });
                }
                DebugCoordinate::event_sequence(*sequence)
            }
            DebugTargetSelector::AtFailure => {
                let sequence = debug_first_assertion_violation_sequence(event_log).ok_or(
                    EngineError::DebugTargetResolverFailureNotFound {
                        configuration: request.current.id(),
                    },
                )?;
                failure_event_sequence = Some(sequence);
                DebugCoordinate::event_sequence(sequence)
            }
            DebugTargetSelector::AtCheckpoint(checkpoint) => {
                DebugCoordinate::checkpoint(*checkpoint)
            }
            DebugTargetSelector::Divergence(coordinate) => {
                divergence = Some(coordinate.clone());
                let target =
                    self.debug_resolve_exact_divergence_coordinate(&request.current, coordinate)?;
                exact_target = Some(target.clone());
                DebugCoordinate::configuration(target)
            }
        };
        let target = if let Some(target) = exact_target {
            target
        } else {
            self.debug_resolve_coordinate(
                &request.current,
                &resolved_coordinate,
                &request.event_coordinates,
            )?
        };
        debug_validate_same_scenario(&request.current, &target)?;
        let goto_request = DebugGotoRequest {
            current: request.current.clone(),
            target: resolved_coordinate.clone(),
            event_coordinates: request.event_coordinates.clone(),
        };
        let failure_footer = request
            .failure_footer_artifact
            .as_ref()
            .map(|artifact| DebugFailureFooterCommand::new(artifact.clone()));

        Ok(DebugTargetResolverReport {
            selector: request.selector.clone(),
            resolved_coordinate,
            target_configuration: target.id(),
            goto_request,
            failure_event_sequence,
            divergence,
            failure_footer,
        })
    }

    fn debug_resolve_exact_divergence_coordinate(
        &self,
        current: &Configuration,
        coordinate: &DebugDivergenceCoordinate,
    ) -> Result<Configuration, EngineError> {
        self.debug_resolve_scoped_node_icount(current, &coordinate.node, coordinate.icount)
            .ok_or_else(|| EngineError::DebugTimeTravelCoordinateNotFound {
                coordinate: DebugCoordinate::node_icount(
                    coordinate.node.clone(),
                    coordinate.icount,
                ),
            })
    }

    /// Moves an attached debug session to `request.target` using restore-plus-replay.
    ///
    /// The selected restore point is the exact target snapshot when one exists,
    /// otherwise the nearest cached ancestor, otherwise baked genesis. The target
    /// runtime is then materialized through [`instantiate`] and checked against
    /// the replay oracle, so a corrupt exact snapshot or cached ancestor cannot
    /// be accepted as a debugger-only shortcut.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the attached configuration does not match
    /// `request.current`, when the target belongs to another scenario, when the
    /// target cannot be instantiated, or when the replay oracle rejects the
    /// restored path.
    pub fn debug_goto(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugGotoRequest,
    ) -> Result<DebugGotoReport, EngineError> {
        if attach.configuration != request.current.id() {
            return Err(EngineError::DebugGotoAttachMismatch {
                attached: attach.configuration,
                requested_current: request.current.id(),
            });
        }
        let target = self.debug_resolve_coordinate(
            &request.current,
            &request.target,
            &request.event_coordinates,
        )?;
        debug_validate_same_scenario(&request.current, &target)?;
        self.record_checkpoint_closure(&target)?;
        let restore = self.debug_restore_configuration(&target)?;
        let restore_checkpoint = self
            .checkpoint_node(restore.id())
            .or_else(|| self.cached_snapshot(&restore))
            .map(|checkpoint| checkpoint.id)
            .ok_or(EngineError::CheckpointNotRecorded {
                checkpoint: restore.id(),
            })?;
        let replay_suffix = target
            .schedule
            .suffix_from(restore.schedule.len())
            .map_err(EngineError::SchedulePrefix)?;

        let runtime = self
            .resume(&target)
            .map_err(|error| self.debug_goto_error(&request.current, &target, &restore, error))?;
        let target_checkpoint =
            materialized_checkpoint_for_runtime(&target, runtime.runtime.clone()).map_err(
                |error| self.debug_goto_error(&request.current, &target, &restore, error),
            )?;
        let replay_oracle = self
            .replay_checkpoint(&target, &target_checkpoint)
            .map_err(|error| self.debug_goto_error(&request.current, &target, &restore, error))?;

        Ok(DebugGotoReport {
            current_configuration: request.current.id(),
            target_coordinate: request.target.clone(),
            target_configuration: target.id(),
            restore_configuration: restore.id(),
            restore_checkpoint,
            replay_suffix_decisions: replay_suffix.len(),
            runtime,
            target_checkpoint: target_checkpoint.id,
            replay_oracle,
        })
    }

    /// Resolves and executes one reverse-step operation.
    ///
    /// Reverse stepping only resolves an earlier coordinate and delegates the
    /// actual movement to [`Self::debug_goto`]. This keeps reverse motion in the
    /// same restore-plus-replay path as forward instantiation.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when no earlier coordinate exists for the
    /// requested grain, when an event-log coordinate lacks a configuration
    /// mapping, or when the delegated `goto` fails.
    pub fn debug_reverse_step(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugReverseStepRequest,
    ) -> Result<DebugReverseStepReport, EngineError> {
        let target = debug_reverse_step_target(request)?;
        let goto = self.debug_goto(
            attach,
            &DebugGotoRequest::at_configuration(
                request.current.clone(),
                target.configuration.clone(),
            ),
        )?;
        Ok(DebugReverseStepReport {
            grain: request.grain,
            target_event_sequence: target.event_sequence,
            target_configuration: target.configuration.id(),
            goto,
        })
    }

    /// Scans backward to the latest event-log coordinate where `condition` holds.
    ///
    /// Named and guest-marker leaves are false by default; callers that need a
    /// host-side leaf resolver should use
    /// [`Self::debug_reverse_continue_with_leaf_oracle`].
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when a checked condition prefix cannot be built,
    /// a matching event-log coordinate lacks a configuration mapping, or the
    /// delegated `goto` fails.
    pub fn debug_reverse_continue(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugReverseContinueRequest,
    ) -> Result<DebugReverseContinueReport, EngineError> {
        self.debug_reverse_continue_with_leaf_oracle(attach, request, |_entry, _leaf| false)
    }

    /// Scans backward with a caller-supplied host-side leaf resolver.
    ///
    /// The scan evaluates each candidate through [`ConditionEvaluationPass`]
    /// over a checked event-log prefix, picks the latest matching coordinate at
    /// or before the current event limit, and realizes it through
    /// [`Self::debug_goto`].
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when a checked condition prefix cannot be built,
    /// a matching event-log coordinate lacks a configuration mapping, or the
    /// delegated `goto` fails.
    pub fn debug_reverse_continue_with_leaf_oracle<F>(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugReverseContinueRequest,
        mut leaf_oracle: F,
    ) -> Result<DebugReverseContinueReport, EngineError>
    where
        F: for<'leaf> FnMut(&SchedulerEventLogEntry, ConditionLeaf<'leaf>) -> bool,
    {
        for index in (0..request.event_log.len()).rev() {
            let entry = &request.event_log[index];
            if entry.sequence() > request.current_event_sequence_limit() {
                continue;
            }
            let prefix_entries = request.event_log[..=index].to_vec();
            let prefix = crate::trigger::ConditionEventLogPrefix::from_scheduler_event_log_entries(
                prefix_entries,
            )
            .map_err(|error| EngineError::DebugReverseContinueInvalidPrefix {
                sequence: entry.sequence(),
                reason: format!("{error:?}"),
            })?;
            let oracle = DebugReverseContinueLeafOracle {
                entry,
                leaf_oracle: &mut leaf_oracle,
            };
            let mut pass = ConditionEvaluationPass::from_log_prefix(prefix, oracle);
            if pass.evaluate_assertion_condition(&request.condition) {
                let target = request
                    .event_coordinates
                    .get(&entry.sequence())
                    .cloned()
                    .ok_or_else(|| EngineError::DebugTimeTravelMissingEventCoordinate {
                        sequence: entry.sequence(),
                    })?;
                let goto = self.debug_goto(
                    attach,
                    &DebugGotoRequest::at_configuration(request.current.clone(), target.clone()),
                )?;
                return Ok(DebugReverseContinueReport {
                    condition: request.condition.clone(),
                    searched_entries: request.searched_entries_before(index),
                    matched: Some(DebugReverseContinueMatch {
                        event_sequence: entry.sequence(),
                        target_configuration: target.id(),
                        goto,
                    }),
                });
            }
        }

        Ok(DebugReverseContinueReport {
            condition: request.condition.clone(),
            searched_entries: request.event_log.len(),
            matched: None,
        })
    }

    /// Moves one debugged node to an exact node-icount coordinate.
    ///
    /// The target is resolved from checkpoint metadata on the same linear
    /// schedule family as the attached configuration. Only the requested node's
    /// material is derived from the baked source-of-truth restore and target
    /// replay suffix; all other nodes keep the attached runtime material in the
    /// returned debugger projection.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the attached configuration does not match
    /// `request.current`, the node cannot be found in the attached runtime, the
    /// target coordinate cannot be resolved exactly, the target node material
    /// cannot be derived, or the graph lacks baked genesis for the scenario.
    pub fn debug_per_node_time_travel(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugPerNodeTimeTravelRequest,
    ) -> Result<DebugPerNodeTimeTravelReport, EngineError> {
        if attach.configuration != request.current.id() {
            return Err(EngineError::DebugGotoAttachMismatch {
                attached: attach.configuration,
                requested_current: request.current.id(),
            });
        }
        let (current_node_icount, current_node_blob) = debug_runtime_node_material(
            &attach.runtime.runtime,
            &request.node,
            request.current.id(),
        )?;
        let target = self
            .debug_resolve_scoped_node_icount(&request.current, &request.node, request.icount)
            .ok_or_else(|| EngineError::DebugTimeTravelCoordinateNotFound {
                coordinate: DebugCoordinate::node_icount(request.node.clone(), request.icount),
            })?;
        let scoped = self.debug_scoped_node_material(
            &request.current,
            &target,
            request.node.clone(),
            request.icount,
        )?;
        let mut final_node_icounts = attach.runtime.runtime.node_icounts.clone();
        final_node_icounts.insert(request.node.clone(), scoped.node_icount);
        let mut final_node_blobs = attach.runtime.runtime.node_blobs.clone();
        final_node_blobs.insert(request.node.clone(), scoped.node_blob.clone());

        Ok(DebugPerNodeTimeTravelReport {
            current_configuration: request.current.id(),
            node: request.node.clone(),
            requested_icount: request.icount,
            target_configuration: scoped.target_configuration,
            current_node_icount,
            landed_node_icount: scoped.node_icount,
            current_node_blob,
            landed_node_blob: scoped.node_blob,
            current_node_icounts: attach.runtime.runtime.node_icounts.clone(),
            final_node_icounts,
            current_node_blobs: attach.runtime.runtime.node_blobs.clone(),
            final_node_blobs,
            node_goto: scoped.goto,
        })
    }

    /// Moves the whole debugged world to a prefix coordinate.
    ///
    /// Whole-world time travel is the same operation as a fork before it
    /// diverges: resolve a prefix configuration, instantiate it through
    /// [`Self::debug_goto`], and stop without appending any decisions.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the target coordinate cannot be resolved to
    /// an ancestor/prefix of `request.current`, when the delegated `goto` fails,
    /// or when the landed runtime lacks node material.
    pub fn debug_whole_world_time_travel(
        &mut self,
        attach: &DebugAttachReport,
        request: &DebugWholeWorldTimeTravelRequest,
    ) -> Result<DebugWholeWorldTimeTravelReport, EngineError> {
        let goto_request = request.goto_request(self)?;
        let target_configuration = match &goto_request.target {
            DebugCoordinate::Configuration(configuration) => configuration.clone(),
            coordinate => self.debug_resolve_coordinate(
                &goto_request.current,
                coordinate,
                &goto_request.event_coordinates,
            )?,
        };
        if !debug_configuration_is_ancestor_or_self(&target_configuration, &request.current) {
            return Err(EngineError::DebugTimeTravelCoordinateNotFound {
                coordinate: DebugCoordinate::configuration(target_configuration),
            });
        }
        let goto = self.debug_goto(attach, &goto_request)?;

        Ok(DebugWholeWorldTimeTravelReport {
            current_configuration: request.current.id(),
            target: request.target.clone(),
            target_configuration: goto.target_configuration,
            landed_node_icounts: goto.runtime.runtime.node_icounts.clone(),
            landed_node_blobs: goto.runtime.runtime.node_blobs.clone(),
            goto,
        })
    }

    /// Applies an opportunistic debug checkpoint cadence along a schedule prefix.
    ///
    /// Cadence materialization is routed through
    /// [`Self::materialize_checkpoint_with_savevm_hedge`], so the default
    /// S3-conservative hedge records thin checkpoints and the verified hedge may
    /// cache fat checkpoints. The denoted configuration identities do not change.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when any cadence prefix cannot be constructed,
    /// recorded, materialized, or replay-oracle checked.
    pub fn debug_apply_checkpoint_cadence(
        &mut self,
        request: &DebugCheckpointCadenceRequest,
    ) -> Result<DebugCheckpointCadenceReport, EngineError> {
        let cached_snapshots_before = self.cached_snapshot_count();
        let mut candidate_configurations = Vec::new();
        let mut fat_checkpoints = Vec::new();
        let mut thin_checkpoints = Vec::new();

        for prefix_len in 1..=request.current.schedule.len() {
            if !request.stride.includes_prefix(prefix_len) {
                continue;
            }
            let candidate = debug_configuration_prefix(&request.current, prefix_len)?;
            let checkpoint =
                self.materialize_checkpoint_with_savevm_hedge(&candidate, &request.hedge)?;
            candidate_configurations.push(candidate.id());
            match checkpoint.kind {
                CheckpointKind::Fat => fat_checkpoints.push(checkpoint.id),
                CheckpointKind::Thin => thin_checkpoints.push(checkpoint.id),
            }
        }

        Ok(DebugCheckpointCadenceReport {
            current_configuration: request.current.id(),
            stride: request.stride,
            hedge: request.hedge.clone(),
            candidate_configurations,
            fat_checkpoints,
            thin_checkpoints,
            cached_snapshots_before,
            cached_snapshots_after: self.cached_snapshot_count(),
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

    fn validate_unified_configuration(
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
        let decisions = preemption_branch_decisions(config);
        let report =
            self.enumerate_frontier_reduced(frontier, decisions.clone(), reduction_policy)?;
        let mut materialized = Vec::new();
        for child in &report.explored {
            materialized.push(self.materialize_checkpoint(&child.configuration)?);
        }
        Ok(PreemptionBranchRun {
            decisions,
            report,
            materialized,
        })
    }

    /// Branches one frontier over deterministic app-random served values.
    ///
    /// Each branch appends one [`Decision::AppRandom`] value sampled from an
    /// observed draw site in `config`. A scenario with no observed draw sites,
    /// or with `samples == 0`, generates no children and therefore leaves the
    /// explored graph unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::AppRandomDrawCapExceeded`] when a sampled branch
    /// would exceed the scenario's per-run draw cap, or another [`EngineError`]
    /// if the child cannot be recorded.
    pub fn branch_app_random(
        &mut self,
        frontier: &Configuration,
        config: &AppRandomBranchConfig,
    ) -> Result<AppRandomBranchRun, EngineError> {
        let decisions = app_random_branch_decisions(config);
        let report = self.enumerate_frontier_reduced(
            frontier,
            decisions.clone(),
            FrontierReductionPolicy::none(),
        )?;
        Ok(AppRandomBranchRun { decisions, report })
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

    /// Searches with graph-level symmetry and partial-order reductions enabled.
    ///
    /// Reductions are applied by the same single-frontier expansion path as
    /// [`Self::search`]. Covered partial-order candidates schedule their
    /// canonical representative instead, making the reduced graph independent of
    /// which frontier strategy reaches the non-canonical ordering first.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the root, a selected frontier, or an admitted
    /// reduction representative cannot be recorded, realized, reduced, or
    /// materialized.
    pub fn search_with_strategy_reduced(
        &mut self,
        root: &Configuration,
        strategy: SearchStrategy,
        budget: SearchBudget,
        reduction_policy: FrontierReductionPolicy,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
    ) -> Result<TemporalGraphSearchRun, EngineError> {
        let failure_oracle = SearchFailureOracle::none();
        self.search_with_strategy_inner(
            root,
            strategy,
            budget,
            reduction_policy,
            materialization_policy,
            trigger,
            None,
            &failure_oracle,
            None,
            None,
            None,
        )
    }
    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    fn search_with_strategy_inner(
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

    fn search_with_replay_oracle_sampling_offset(
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

    fn search_inner(
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

    fn enumerate_frontier_choices_reduced<I>(
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

    fn symmetry_representative_for_key_excluding(
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

    fn record_configuration(&mut self, configuration: Configuration) -> bool {
        let id = configuration.id();
        match self.recorded_configurations.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(configuration);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    fn cow_delta_refs(&self) -> Vec<CowDeltaRef> {
        let mut refs = Vec::new();
        for checkpoint in self.checkpoint_nodes.values() {
            refs.extend(checkpoint.cow_delta_refs());
        }
        for checkpoint in self.cached_snapshots.values() {
            refs.extend(checkpoint.cow_delta_refs());
        }
        refs
    }

    fn cow_delta_ref_set(&self) -> BTreeSet<CowDeltaRef> {
        self.cow_delta_refs().into_iter().collect()
    }

    fn mark_live_checkpoints(
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

    fn gc_root_checkpoint_ids(&self, roots: &TemporalGraphGcRoots) -> BTreeSet<ContentHash> {
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

    fn reference_counts_for_live_checkpoints(
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

    fn gc_root_refcounts(&self, roots: &TemporalGraphGcRoots) -> BTreeMap<ContentHash, usize> {
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

    fn store_checkpoint_ids(&self) -> BTreeSet<ContentHash> {
        let mut checkpoints = self
            .checkpoint_nodes
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        checkpoints.extend(self.cached_snapshots.keys().copied());
        checkpoints
    }

    fn store_keys_for_checkpoint_ids(
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

    fn has_replay_oracle_path(&self, configuration: &Configuration) -> Result<bool, EngineError> {
        if configuration.is_genesis() {
            return Ok(self.genesis_snapshot(&configuration.def).is_some());
        }
        Ok(self.genesis_snapshot(&configuration.def).is_some())
    }

    fn replay_oracle_admit_cached_ancestors(
        &mut self,
        configuration: &Configuration,
    ) -> Result<(), EngineError> {
        let ancestors = self.cached_ancestor_configurations(configuration)?;
        for ancestor in ancestors {
            self.replay_oracle_admit_cached_snapshot(&ancestor)?;
        }
        Ok(())
    }

    fn cached_ancestor_configurations(
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

    fn cached_snapshot_configurations(&self) -> Result<Vec<Configuration>, EngineError> {
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

    fn record_checkpoint_closure(
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

    fn debug_restore_configuration(
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

    fn thin_checkpoint_node_icounts(
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

    fn debug_resolve_coordinate(
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

    fn debug_resolve_scoped_node_icount(
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

    fn debug_scoped_node_material(
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

    fn debug_latest_checkpoint_at_or_before_time(
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

    fn debug_latest_checkpoint_at_or_before_icount(
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

    fn debug_checkpoint_coordinate_candidates(
        &self,
        current: &Configuration,
    ) -> Vec<DebugCheckpointCoordinateCandidate> {
        self.debug_checkpoint_coordinate_candidates_where(current, |configuration| {
            debug_configuration_is_ancestor_or_self(configuration, current)
        })
    }

    fn debug_scoped_node_coordinate_candidates(
        &self,
        current: &Configuration,
    ) -> Vec<DebugCheckpointCoordinateCandidate> {
        self.debug_checkpoint_coordinate_candidates_where(current, |configuration| {
            debug_configurations_are_linearly_related(configuration, current)
        })
    }

    fn debug_checkpoint_coordinate_candidates_where<F>(
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

    fn debug_goto_error(
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

    fn debug_replay_oracle_bisection(
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct DebugResolvedReverseStepTarget {
    configuration: Configuration,
    event_sequence: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DebugCheckpointCoordinateCandidate {
    configuration: Configuration,
    virtual_time: VirtualTime,
    node_icounts: BTreeMap<NodeId, Icount>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DebugScopedNodeMaterial {
    target_configuration: ContentHash,
    node_icount: Icount,
    node_blob: NodeBlobRef,
    goto: DebugPerNodeGotoReport,
}

struct DebugReverseContinueLeafOracle<'a, F> {
    entry: &'a SchedulerEventLogEntry,
    leaf_oracle: &'a mut F,
}

impl<F> ConditionLeafOracle for DebugReverseContinueLeafOracle<'_, F>
where
    F: for<'leaf> FnMut(&SchedulerEventLogEntry, ConditionLeaf<'leaf>) -> bool,
{
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        (self.leaf_oracle)(self.entry, leaf)
    }
}

fn debug_validate_same_scenario(
    current: &Configuration,
    target: &Configuration,
) -> Result<(), EngineError> {
    if current.def.id == target.def.id {
        Ok(())
    } else {
        Err(EngineError::DebugGotoScenarioMismatch {
            current: current.id(),
            target: target.id(),
        })
    }
}

fn debug_configuration_is_ancestor_or_self(
    candidate: &Configuration,
    current: &Configuration,
) -> bool {
    candidate.def.id == current.def.id
        && candidate.schedule.len() <= current.schedule.len()
        && current
            .schedule
            .decisions()
            .starts_with(candidate.schedule.decisions())
}

fn debug_configurations_are_linearly_related(
    candidate: &Configuration,
    current: &Configuration,
) -> bool {
    candidate.def.id == current.def.id
        && (current
            .schedule
            .decisions()
            .starts_with(candidate.schedule.decisions())
            || candidate
                .schedule
                .decisions()
                .starts_with(current.schedule.decisions()))
}

fn debug_runtime_node_material(
    runtime: &RuntimeState,
    node: &NodeId,
    configuration: ContentHash,
) -> Result<(Icount, NodeBlobRef), EngineError> {
    let icount = runtime.node_icounts.get(node).copied().ok_or_else(|| {
        EngineError::DebugTimeTravelUnknownNode {
            node: node.clone(),
            configuration,
        }
    })?;
    let blob = runtime.node_blobs.get(node).cloned().ok_or_else(|| {
        EngineError::DebugTimeTravelUnknownNode {
            node: node.clone(),
            configuration,
        }
    })?;
    Ok((icount, blob))
}

fn debug_checkpoint_node_material(
    checkpoint: &Checkpoint,
    node: &NodeId,
    configuration: ContentHash,
) -> Result<(Icount, NodeBlobRef), EngineError> {
    let icount = checkpoint.node_icounts.get(node).copied().ok_or_else(|| {
        EngineError::DebugTimeTravelUnknownNode {
            node: node.clone(),
            configuration,
        }
    })?;
    let blob = checkpoint.node_blobs.get(node).cloned().ok_or_else(|| {
        EngineError::DebugTimeTravelUnknownNode {
            node: node.clone(),
            configuration,
        }
    })?;
    Ok((icount, blob))
}

fn maps_equal_except_key<T: PartialEq>(
    left: &BTreeMap<NodeId, T>,
    right: &BTreeMap<NodeId, T>,
    excluded: &NodeId,
) -> bool {
    left.iter()
        .filter(|(node, _)| *node != excluded)
        .all(|(node, value)| right.get(node) == Some(value))
        && right
            .iter()
            .filter(|(node, _)| *node != excluded)
            .all(|(node, value)| left.get(node) == Some(value))
}

fn debug_configuration_prefix(
    configuration: &Configuration,
    len: usize,
) -> Result<Configuration, EngineError> {
    Ok(Configuration {
        def: configuration.def.clone(),
        schedule: configuration
            .schedule
            .prefix(len)
            .map_err(EngineError::SchedulePrefix)?,
    })
}

fn debug_cached_prefix_matches_replay_oracle(
    graph: &TemporalGraph,
    configuration: &Configuration,
) -> Result<bool, EngineError> {
    let checkpoint = if configuration.is_genesis() {
        graph
            .genesis_snapshot(&configuration.def)
            .map(|genesis| genesis.checkpoint.clone())
    } else {
        graph.cached_snapshot(configuration).cloned()
    };
    let Some(checkpoint) = checkpoint else {
        return Ok(true);
    };
    match graph.replay_checkpoint(configuration, &checkpoint) {
        Ok(_) => Ok(true),
        Err(EngineError::ReplayOracleMismatch { .. }) => Ok(false),
        Err(error) => Err(error),
    }
}

fn debug_reverse_step_target(
    request: &DebugReverseStepRequest,
) -> Result<DebugResolvedReverseStepTarget, EngineError> {
    if request.grain == DebugReverseStepGrain::Instruction {
        if request.current.schedule.is_empty() {
            return Err(EngineError::DebugTimeTravelNoEarlierCoordinate {
                grain: request.grain,
                current: request.current.id(),
            });
        }
        let target = debug_configuration_prefix(
            &request.current,
            request.current.schedule.len().saturating_sub(1),
        )?;
        return Ok(DebugResolvedReverseStepTarget {
            configuration: target,
            event_sequence: None,
        });
    }

    let Some(entry) = request.event_log.iter().rev().find(|entry| {
        entry.sequence() < request.current_event_sequence_limit()
            && debug_entry_matches_reverse_grain(entry, request.grain)
    }) else {
        return Err(EngineError::DebugTimeTravelNoEarlierCoordinate {
            grain: request.grain,
            current: request.current.id(),
        });
    };
    let configuration = request
        .event_coordinates
        .get(&entry.sequence())
        .cloned()
        .ok_or_else(|| EngineError::DebugTimeTravelMissingEventCoordinate {
            sequence: entry.sequence(),
        })?;
    Ok(DebugResolvedReverseStepTarget {
        configuration,
        event_sequence: Some(entry.sequence()),
    })
}

fn debug_entry_matches_reverse_grain(
    entry: &SchedulerEventLogEntry,
    grain: DebugReverseStepGrain,
) -> bool {
    match (grain, entry.payload()) {
        (
            DebugReverseStepGrain::Quantum,
            SchedulerEventLogPayload::EvaluationBoundary(
                crate::scheduler::SchedulerEvaluationBoundaryKind::Quantum,
            ),
        ) => true,
        (DebugReverseStepGrain::Event, payload) => debug_payload_is_event_grain(payload),
        (DebugReverseStepGrain::Assertion, payload) => debug_payload_is_assertion_grain(payload),
        (DebugReverseStepGrain::Timer, payload) => debug_payload_is_timer_grain(payload),
        (DebugReverseStepGrain::Instruction, _) => false,
        _ => false,
    }
}

fn debug_payload_is_event_grain(payload: &SchedulerEventLogPayload) -> bool {
    matches!(
        payload,
        SchedulerEventLogPayload::ResolvedHappening(_)
            | SchedulerEventLogPayload::Observable(_)
            | SchedulerEventLogPayload::TriggerFired(_)
            | SchedulerEventLogPayload::TriggerActionApplied(_)
    )
}

fn debug_payload_is_assertion_grain(payload: &SchedulerEventLogPayload) -> bool {
    match payload {
        SchedulerEventLogPayload::Observable(observable) => {
            matches!(
                observable,
                ObservableEventPayload::AssertionEvaluated { .. }
                    | ObservableEventPayload::GuestAssertionMarker { .. }
            )
        }
        SchedulerEventLogPayload::TriggerFired(_)
        | SchedulerEventLogPayload::TriggerActionApplied(_) => true,
        _ => false,
    }
}

fn debug_payload_is_timer_grain(payload: &SchedulerEventLogPayload) -> bool {
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            matches!(
                event.payload,
                ScheduledEventPayload::IoCompletion(_)
                    | ScheduledEventPayload::FaultActivation(_)
                    | ScheduledEventPayload::ProbabilisticFault(_)
            )
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            matches!(
                application.action,
                Action::ArmTimer { .. } | Action::CancelTimer { .. }
            )
        }
        _ => false,
    }
}
