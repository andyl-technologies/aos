//! Checkpoint caching and save operations.

use super::*;

impl TemporalGraph {
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
        let coverage_fingerprint = checkpoint.coverage_fingerprint;
        let assertion_proximity_fingerprint = checkpoint.assertion_proximity_fingerprint;
        self.record_configuration(configuration.clone());
        self.cached_snapshots.insert(configuration.id(), checkpoint);
        if let Some(checkpoint) = self.checkpoint_nodes.get_mut(&configuration.id()) {
            checkpoint.coverage_fingerprint = coverage_fingerprint;
            checkpoint.assertion_proximity_fingerprint = assertion_proximity_fingerprint;
        }
        Ok(())
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
}
