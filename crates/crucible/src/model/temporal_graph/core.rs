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
    /// Derived VM-only projection retained for the legacy VM authoring/runtime API.
    /// It is rebuilt from `topology_nodes` by every constructor and is not a
    /// separate logical topology collection.
    pub(in crate::model) nodes: Vec<WorldNode>,
    pub(in crate::model) links: Vec<LinkDef>,
    pub(in crate::model) fault_topology: WorldFaultTopology,
    pub(in crate::model) fault_topology_id: ContentHash,
    pub(in crate::model) fault_topology_wire: Vec<u8>,
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

    pub(in crate::model) fn debug_resolve_exact_divergence_coordinate(
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
        let decisions = preemption_branch_decisions(config);
        let report =
            self.enumerate_frontier_reduced(frontier, decisions.clone(), reduction_policy)?;
        let materialized = self.materialize_preemption_branches(&report)?;
        Ok(PreemptionBranchRun {
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
#[path = "core/reduced_search.rs"]
mod reduced_search;
