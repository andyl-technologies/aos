//! Interactive replay actor construction, terminal evidence, and shutdown ownership.
//!
//! Callers supply authenticated replay inputs and an admitted quantum loop. This
//! module owns the session engine and actor; callers only read evidence and request
//! terminal shutdown, so application frontends do not construct scheduler state.

use std::collections::BTreeMap;

use crucible_engine::{
    Checkpoint, CheckpointKind, Configuration, EngineError, FingerprintSample, GenesisCheckpoint,
    NodeId, QuantumLoop, TemporalGraph, VirtualTime,
};
use crucible_session::{
    AdmittedSessionReproductionSnapshot, CommandReply, Engine, SessionActor, SessionCommand,
    SessionControlReplayArtifact, SessionError, SessionEventLog,
};
use thiserror::Error;
use tokio::sync::mpsc;

/// Failure constructing, replaying, or terminating an interactive actor.
#[derive(Debug, Error)]
pub enum InteractiveReplayError {
    /// The original metadata authority refused replay storage.
    #[error("admit interactive replay metadata: {0}")]
    Metadata(#[from] crucible_engine::owned_decode::DecodeAdmissionError),
    /// The actor could not retain its original account through asynchronous polls.
    #[error("start admitted replay actor: {0}")]
    ActorSpawn(#[source] crucible_control_api::LifecycleApiError),
    /// The recorded initial configuration could not produce its genesis checkpoint.
    #[error("build interactive replay genesis: {0}")]
    Genesis(#[source] EngineError),
    /// The genesis graph rejected its checkpoint or configuration.
    #[error("build interactive replay graph: {0}")]
    Graph(#[source] EngineError),
    /// Reproduction failed or its original terminal nodes could not be sampled.
    #[error("replay interactive control artifact: {0}")]
    Replay(#[source] SessionError),
    /// The actor closed before accepting terminal shutdown.
    #[error("replay actor closed before terminal shutdown")]
    CommandClosed,
    /// The shutdown acknowledgement was abandoned.
    #[error("replay shutdown reply channel closed")]
    ReplyClosed(#[source] tokio::sync::oneshot::error::RecvError),
    /// The actor rejected terminal shutdown.
    #[error("shutdown replay actor: {0}")]
    Shutdown(#[source] SessionError),
    /// The actor task panicked or was canceled.
    #[error("join replay actor: {0}")]
    Join(#[source] tokio::task::JoinError),
    /// The actor returned an execution failure.
    #[error("replay actor failed: {0}")]
    Actor(#[source] SessionError),
}

/// Retains an interactive replay actor and its sampled original terminal nodes.
pub struct PreparedInteractiveReplay<L: QuantumLoop> {
    actor: SessionActor<L>,
    sender: mpsc::Sender<SessionCommand>,
    execution_fingerprints: Vec<FingerprintSample>,
    decoding: crucible_engine::owned_decode::DecodeBudget,
}

impl<L: QuantumLoop> PreparedInteractiveReplay<L> {
    /// Returns the canonical event-log observation handle.
    #[must_use]
    pub fn event_log(&self) -> SessionEventLog {
        self.actor.event_log()
    }

    /// Copies reproduction commands while retaining their original allocation custody.
    ///
    /// # Errors
    /// Refuses expired or exhausted original metadata authority or failed copying.
    pub fn reproduction_commands(
        &self,
    ) -> Result<AdmittedSessionReproductionSnapshot, EngineError> {
        let _scope = self.decoding.enter();
        self.actor.reproduction_log().snapshot_admitted()
    }

    /// Returns fingerprints sampled before original terminal nodes were retired.
    #[must_use]
    pub fn execution_fingerprints(&self) -> &[FingerprintSample] {
        &self.execution_fingerprints
    }
}

impl<L: QuantumLoop + Send + 'static> PreparedInteractiveReplay<L> {
    /// Starts the terminal actor, requests acknowledged shutdown, and joins it.
    ///
    /// # Errors
    ///
    /// Returns a channel, shutdown, join, or actor failure when terminal cleanup
    /// does not complete. The original actor's failure remains typed.
    ///
    /// # Panics
    ///
    /// Panics when polled outside a Tokio runtime.
    pub async fn shutdown(self) -> Result<(), InteractiveReplayError> {
        let actor = self.actor;
        let task = crucible_control_server::spawn_admitted_session_actor(actor, self.decoding)
            .map_err(InteractiveReplayError::ActorSpawn)?;
        let (reply, receiver) = CommandReply::channel();

        self.sender
            .send(SessionCommand::acknowledged(SessionCommand::Stop, reply))
            .await
            .map_err(|_| InteractiveReplayError::CommandClosed)?;
        receiver
            .await
            .map_err(InteractiveReplayError::ReplyClosed)?
            .map_err(InteractiveReplayError::Shutdown)?;
        task.await
            .map_err(InteractiveReplayError::Join)?
            .map_err(InteractiveReplayError::Actor)?;

        Ok(())
    }
}

/// Constructs the genesis engine and replays an admitted interactive artifact.
///
/// # Errors
///
/// Returns [`InteractiveReplayError`] when genesis construction, graph admission,
/// replay, or terminal fingerprint sampling fails.
pub fn prepare_interactive_replay<L: QuantumLoop>(
    initial_configuration: Configuration,
    quantum_loop: L,
    artifact: &SessionControlReplayArtifact,
    nodes: &[NodeId],
) -> Result<PreparedInteractiveReplay<L>, InteractiveReplayError> {
    let decoding = crucible_engine::owned_decode::require_current_child_budget()?;
    let _scope = decoding.enter();
    let checkpoint = Checkpoint::from_recorded_configuration(
        &initial_configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .map_err(InteractiveReplayError::Genesis)?;
    let graph = TemporalGraph::empty()
        .with_baked_genesis(&initial_configuration.def, GenesisCheckpoint { checkpoint })
        .map_err(InteractiveReplayError::Graph)?;
    let engine = Engine::new(initial_configuration, graph, quantum_loop);
    let (sender, receiver) = mpsc::channel(64);
    let (actor, execution_fingerprints) =
        replay_interactive_terminal_actor(engine, receiver, artifact, nodes)?;

    Ok(PreparedInteractiveReplay {
        actor,
        sender,
        execution_fingerprints,
        decoding,
    })
}

/// Replays an existing engine and samples its original terminal nodes.
///
/// # Errors
///
/// Returns a replay error when control reproduction, original-node sampling, or
/// original-node retirement fails.
pub fn replay_interactive_terminal_actor<L: QuantumLoop>(
    engine: Engine<L>,
    receiver: mpsc::Receiver<SessionCommand>,
    artifact: &SessionControlReplayArtifact,
    nodes: &[NodeId],
) -> Result<(SessionActor<L>, Vec<FingerprintSample>), InteractiveReplayError> {
    SessionActor::new(engine, receiver)
        .with_control_replay_artifact_and_terminal_fingerprints(artifact, nodes)
        .map_err(InteractiveReplayError::Replay)
}
