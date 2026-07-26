//! Session-owned replay and validation DAG adapters.
//!
//! The CLI and API layers need a small amount of local-double validation for
//! save, resume, fork, and search workflows. This module keeps those operations
//! behind the session boundary instead of exposing the underlying temporal graph
//! as a binary-owned implementation detail.

use crate::{CheckpointRef, Engine, SessionCommand, SessionError, SessionFork, SessionResume};
use std::collections::BTreeMap;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentAddressedBlobRef, ContentHash, DagStore,
    Decision, EngineError, GenesisCheckpoint, MaterializationPolicy, MaterializationTrigger,
    QuantumLoop, ReplayOracleCheck, ScenarioDef, ScenarioDefForm, ScheduleError, SearchBudget,
    SearchFailureOracle, SearchReplayOracleSamplingConfig, SearchStrategy, TemporalGraph,
    TemporalGraphSampledSearchRun, TemporalGraphSearchRun, TemporalGraphStoreError,
    TemporalGraphStoreKeys, UnifiedGraphOperationEvidence, UnifiedGraphOperationReport,
    VirtualTime, reduce,
};
use thiserror::Error;

/// Opaque validation DAG handle owned by the session boundary.
pub struct ValidationDag {
    graph: TemporalGraph,
}

/// Error emitted while persisting or replaying a validation DAG.
pub type ValidationDagStoreError = TemporalGraphStoreError;

/// Errors returned while deriving a resume realization proof.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ResumeRealizationError {
    /// The source checkpoint does not belong to the source configuration.
    #[error(
        "resume source checkpoint {checkpoint:?} belongs to {actual_configuration:?}, not {expected_configuration:?}"
    )]
    SourceCheckpointMismatch {
        /// Source checkpoint content address.
        checkpoint: ContentHash,
        /// Configuration recorded in the checkpoint.
        actual_configuration: ContentHash,
        /// Expected source configuration.
        expected_configuration: ContentHash,
    },
    /// The source schedule is longer than the target schedule.
    #[error("resume source schedule length {source_len} exceeds target length {target_len}")]
    SourceAfterTarget {
        /// Number of source decisions.
        source_len: usize,
        /// Number of target decisions.
        target_len: usize,
    },
    /// The target schedule prefix could not be checked.
    #[error("resume target schedule prefix check failed: {message}")]
    SchedulePrefix {
        /// Deterministic failure detail.
        message: String,
    },
    /// The source configuration is not an ancestor of the target.
    #[error(
        "resume source configuration {source_configuration:?} is not an ancestor of target {target:?}"
    )]
    SourceNotAncestor {
        /// Source configuration identity.
        source_configuration: ContentHash,
        /// Target configuration identity.
        target: ContentHash,
    },
    /// The target runtime state could not be reduced from the target schedule.
    #[error("resume target runtime reduction failed: {message}")]
    RuntimeReduction {
        /// Deterministic failure detail.
        message: String,
    },
}

/// Errors returned while materializing session-owned checkpoint state.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RecordedCheckpointError {
    /// The configuration's parent schedule prefix could not be derived.
    #[error("checkpoint parent schedule prefix failed: {0}")]
    SchedulePrefix(#[from] ScheduleError),
    /// The checkpoint material did not satisfy the engine contract.
    #[error("checkpoint materialization failed: {0}")]
    Engine(#[from] EngineError),
}

/// Stable proof fields emitted for local resume realization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeRealizationProof {
    operation: &'static str,
    branch: &'static str,
    configuration: ContentHash,
    runtime_state: ContentHash,
    ancestor_configuration: Option<ContentHash>,
    checkpoint: Option<ContentHash>,
    replayed_decisions: usize,
}

impl ResumeRealizationProof {
    /// Returns the machine-readable summary fields for stdout and canonical logs.
    #[must_use]
    pub fn field_summary(&self) -> String {
        format!(
            "operation={} branch={} configuration={} runtime={} ancestor_configuration={} checkpoint={} replayed_decisions={}",
            self.operation,
            self.branch,
            format_content_hash_ref(self.configuration),
            format_content_hash_ref(self.runtime_state),
            format_optional_content_hash_ref(self.ancestor_configuration),
            format_optional_content_hash_ref(self.checkpoint),
            self.replayed_decisions
        )
    }
}

/// Derives a resume realization proof from a source savepoint and target.
///
/// # Errors
///
/// Returns [`ResumeRealizationError`] when the source checkpoint does not match
/// the source configuration, the source schedule is not a target prefix, or the
/// target runtime state cannot be reduced.
pub fn realize_resume_from_savepoint(
    source_configuration: &Configuration,
    source_checkpoint: &Checkpoint,
    target: &Configuration,
) -> Result<ResumeRealizationProof, ResumeRealizationError> {
    let source_id = source_configuration.id();
    if source_checkpoint.configuration != source_id {
        return Err(ResumeRealizationError::SourceCheckpointMismatch {
            checkpoint: source_checkpoint.id,
            actual_configuration: source_checkpoint.configuration,
            expected_configuration: source_id,
        });
    }

    let source_len = source_configuration.schedule.len();
    let target_len = target.schedule.len();
    if source_len > target_len {
        return Err(ResumeRealizationError::SourceAfterTarget {
            source_len,
            target_len,
        });
    }
    let prefix = target.schedule.prefix(source_len).map_err(|error| {
        ResumeRealizationError::SchedulePrefix {
            message: error.to_string(),
        }
    })?;
    if source_configuration.def != target.def || prefix != source_configuration.schedule {
        return Err(ResumeRealizationError::SourceNotAncestor {
            source_configuration: source_id,
            target: target.id(),
        });
    }

    let state = reduce(&target.def, &target.schedule).map_err(|error| {
        ResumeRealizationError::RuntimeReduction {
            message: error.to_string(),
        }
    })?;
    let replayed_decisions = target_len - source_len;
    let (branch, ancestor_configuration, checkpoint) = if replayed_decisions == 0 {
        ("exact-savepoint", None, Some(source_checkpoint.id))
    } else {
        ("ancestor-replay", Some(source_id), None)
    };

    Ok(ResumeRealizationProof {
        operation: "resume",
        branch,
        configuration: target.id(),
        runtime_state: state.id,
        ancestor_configuration,
        checkpoint,
        replayed_decisions,
    })
}

impl ValidationDag {
    /// Creates an empty validation DAG.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            graph: TemporalGraph::empty(),
        }
    }

    /// Returns a validation DAG with a baked genesis checkpoint registered.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the baked genesis checkpoint does not match
    /// the scenario or cannot be loaded.
    pub fn with_baked_genesis(
        mut self,
        scenario: &ScenarioDef,
        genesis: GenesisCheckpoint,
    ) -> Result<Self, EngineError> {
        self.graph = self.graph.with_baked_genesis(scenario, genesis)?;
        Ok(self)
    }

    /// Registers a loadable snapshot for a configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the checkpoint is not a valid loadable fat
    /// snapshot for `configuration`.
    pub fn cache_snapshot(
        &mut self,
        configuration: &Configuration,
        checkpoint: Checkpoint,
    ) -> Result<(), EngineError> {
        self.graph.cache_snapshot(configuration, checkpoint)
    }

    /// Returns the nearest cached ancestor of `configuration`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when a schedule prefix cannot be constructed.
    pub fn nearest_cached_ancestor(
        &self,
        configuration: &Configuration,
    ) -> Result<Option<Configuration>, EngineError> {
        self.graph.nearest_cached_ancestor(configuration)
    }

    /// Checks that a fat checkpoint matches its thin replay reconstruction.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the supplied checkpoint is invalid or thin
    /// replay does not reproduce the same checkpoint identity.
    pub fn replay_checkpoint(
        &self,
        configuration: &Configuration,
        checkpoint: &Checkpoint,
    ) -> Result<ReplayOracleCheck, EngineError> {
        self.graph.replay_checkpoint(configuration, checkpoint)
    }

    /// Validates a unified temporal-graph operation.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the operation evidence is inconsistent or
    /// replay validation fails.
    pub fn validate_unified_operation(
        &mut self,
        operation: &UnifiedGraphOperationEvidence,
    ) -> Result<UnifiedGraphOperationReport, EngineError> {
        self.graph.validate_unified_operation(operation)
    }

    /// Persists the checkpoint closure rooted at `frontier` into `store`.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationDagStoreError`] when the graph cannot derive a valid
    /// closure or the store rejects an object write.
    pub fn persist_checkpoint_closure<S>(
        &mut self,
        store: &S,
        frontier: &Configuration,
    ) -> Result<TemporalGraphStoreKeys, ValidationDagStoreError>
    where
        S: DagStore + ?Sized,
    {
        self.graph.persist_checkpoint_closure(store, frontier)
    }

    /// Searches with a deterministic failure oracle and decision-depth bound.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when graph expansion, materialization, or failure
    /// oracle evaluation fails.
    // crucible-lint: allow rust-allow -- wrapper mirrors the engine search surface.
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
        self.graph
            .search_with_strategy_and_failure_oracle_bounded_depth(
                scenario,
                root,
                strategy,
                budget,
                materialization_policy,
                trigger,
                failure_oracle,
                max_depth,
            )
    }

    /// Searches with a failure oracle, depth bound, and replay-oracle sampling.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when graph expansion, materialization, failure
    /// oracle evaluation, or replay-oracle sampling fails.
    // crucible-lint: allow rust-allow -- wrapper mirrors the engine search surface.
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
        self.graph
            .search_with_strategy_and_failure_oracle_bounded_depth_sampled(
                scenario,
                root,
                strategy,
                budget,
                materialization_policy,
                trigger,
                failure_oracle,
                max_depth,
                sampling_config,
            )
    }
}

fn format_content_hash_ref(hash: ContentHash) -> String {
    ContentAddressedBlobRef::from_hash(hash).to_uri()
}

fn format_optional_content_hash_ref(hash: Option<ContentHash>) -> String {
    hash.map(format_content_hash_ref)
        .unwrap_or_else(|| String::from("none"))
}

/// Creates an empty validation DAG.
#[must_use]
pub fn empty_validation_dag() -> ValidationDag {
    ValidationDag::empty()
}

/// Materializes a fat checkpoint for a recorded configuration.
///
/// The session boundary derives the parent prefix and checkpoint material so
/// CLI and API callers never construct canonical checkpoint state themselves.
///
/// # Errors
///
/// Returns [`RecordedCheckpointError`] when the schedule prefix cannot be
/// derived or the checkpoint material is inconsistent with `configuration`.
pub fn recorded_checkpoint_for_configuration(
    configuration: &Configuration,
    frontier: VirtualTime,
) -> Result<Checkpoint, RecordedCheckpointError> {
    let parent = if configuration.schedule.is_empty() {
        None
    } else {
        let prefix = configuration
            .schedule
            .prefix(configuration.schedule.len().saturating_sub(1))?;
        Some(Configuration {
            def: configuration.def.clone(),
            schedule: prefix,
        })
    };
    Ok(Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        frontier,
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )?)
}

/// Creates a validation DAG with a session-owned baked genesis checkpoint.
///
/// # Errors
///
/// Returns [`RecordedCheckpointError`] when genesis checkpoint construction or
/// temporal graph registration fails.
pub fn validation_dag_with_baked_genesis(
    scenario: &ScenarioDef,
) -> Result<ValidationDag, RecordedCheckpointError> {
    let genesis = Configuration::genesis(scenario.clone());
    let checkpoint = recorded_checkpoint_for_configuration(&genesis, VirtualTime::default())?;
    Ok(empty_validation_dag().with_baked_genesis(scenario, GenesisCheckpoint { checkpoint })?)
}

fn engine_from_validation_dag<L>(
    configuration: Configuration,
    graph: ValidationDag,
    quantum_loop: L,
) -> Engine<L> {
    Engine::new(configuration, graph.graph, quantum_loop)
}

fn started_engine_from_validation_dag<L>(
    configuration: Configuration,
    graph: ValidationDag,
    quantum_loop: L,
) -> Result<Engine<L>, SessionError>
where
    L: QuantumLoop,
{
    let mut engine = engine_from_validation_dag(configuration, graph, quantum_loop);
    engine.apply_command(SessionCommand::Start).map(|_| engine)
}

/// Resumes a session actor from a checkpoint in a validation DAG.
///
/// # Errors
///
/// Returns [`SessionError`] when checkpoint resolution or runtime realization
/// fails.
pub fn resume_session_from_validation_dag<P, C>(
    configuration: Configuration,
    graph: ValidationDag,
    parent_loop: P,
    checkpoint: ContentHash,
    session_loop: C,
) -> Result<SessionResume<C>, SessionError> {
    let mut engine = engine_from_validation_dag(configuration, graph, parent_loop);
    engine.resume_session_from_checkpoint(checkpoint, session_loop)
}

/// Forks a child session actor from a checkpoint in a validation DAG.
///
/// # Errors
///
/// Returns [`SessionError`] when the parent cannot start, the checkpoint cannot
/// be resolved, or branch runtime realization fails.
pub fn fork_session_from_validation_checkpoint<P, C>(
    configuration: Configuration,
    graph: ValidationDag,
    parent_loop: P,
    checkpoint: CheckpointRef,
    child_loop: C,
) -> Result<SessionFork<C>, SessionError>
where
    P: QuantumLoop,
{
    let mut engine = started_engine_from_validation_dag(configuration, graph, parent_loop)?;
    engine.fork_child_from_checkpoint(checkpoint, child_loop)
}

/// Forks a child session actor from a configuration in a validation DAG.
///
/// # Errors
///
/// Returns [`SessionError`] when the parent cannot start, the branch cannot be
/// recorded, or branch runtime realization fails.
pub fn fork_session_from_validation_base<P, C, I>(
    configuration: Configuration,
    graph: ValidationDag,
    parent_loop: P,
    base: &Configuration,
    decisions: I,
    child_loop: C,
) -> Result<SessionFork<C>, SessionError>
where
    P: QuantumLoop,
    I: IntoIterator<Item = Decision>,
{
    let mut engine = started_engine_from_validation_dag(configuration, graph, parent_loop)?;
    engine.fork_child(base, decisions, child_loop)
}
