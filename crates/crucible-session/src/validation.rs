//! Session-owned replay and validation DAG adapters.
//!
//! The CLI and API layers need a small amount of local-double validation for
//! save, resume, fork, and search workflows. This module keeps those operations
//! behind the session boundary instead of exposing the underlying temporal graph
//! as a binary-owned implementation detail.

use crate::{CheckpointRef, Engine, SessionCommand, SessionError, SessionFork, SessionResume};
use crucible::{
    Checkpoint, Configuration, ContentHash, DagStore, Decision, EngineError, GenesisCheckpoint,
    MaterializationPolicy, MaterializationTrigger, QuantumLoop, ReplayOracleCheck, ScenarioDef,
    ScenarioDefForm, SearchBudget, SearchFailureOracle, SearchReplayOracleSamplingConfig,
    SearchStrategy, TemporalGraph, TemporalGraphSampledSearchRun, TemporalGraphSearchRun,
    TemporalGraphStoreError, TemporalGraphStoreKeys, UnifiedGraphOperationEvidence,
    UnifiedGraphOperationReport,
};

/// Opaque validation DAG handle owned by the session boundary.
pub struct ValidationDag {
    graph: TemporalGraph,
}

/// Error emitted while persisting or replaying a validation DAG.
pub type ValidationDagStoreError = TemporalGraphStoreError;

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

/// Creates an empty validation DAG.
#[must_use]
pub fn empty_validation_dag() -> ValidationDag {
    ValidationDag::empty()
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
