//! Discovery and lifecycle unary control-plane API.
//!
//! This module owns the RFC-0010 T-API-3 boundary. It provides typed unary
//! methods for `Hello`, `ListScenarios`, `CreateSession`, `ListSessions`, and
//! `DestroySession`, backed by the same `crucible-session` actor and lock-free
//! live mirror used by the lower session layer.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, EngineError, GenesisCheckpoint, QuantumLoop,
    ScenarioDef, Seed, TemporalGraph, VirtualTime,
};
use crucible_session::{
    Engine, LiveSnapshot, LiveStateKind, SessionActor, SessionCommand, SessionError,
    SessionRunReport,
};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::{
    ControlClient, ControlClientError, ControlClientFuture, ControlTransportKind, ControlWireModel,
    HelloRequest, HelloResponse, RPC_OPEN_SET_PAYLOAD_KINDS, RpcAbiError, negotiate_rpc_protocol,
};

/// Default actor mailbox capacity for lifecycle-created sessions.
pub const LIFECYCLE_SESSION_MAILBOX_CAPACITY: usize = 16;

/// Default actor-yield budget for lifecycle startup commands.
pub const LIFECYCLE_SESSION_STARTUP_MAX_ACTOR_YIELDS: u64 = 128;

/// Stable API-level session identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId {
    /// Monotone control-plane-local identifier.
    pub value: u64,
}

impl SessionId {
    /// Builds a session identifier from a monotone numeric value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self { value }
    }
}

/// Epoch-guarded reference to a live or recently-absent session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionRef {
    /// Stable session identifier.
    pub id: SessionId,
    /// Monotone epoch used to detect recycled identifiers.
    pub epoch: u64,
    /// Seed recorded for the session creation request.
    pub seed: Seed,
}

impl SessionRef {
    /// Builds an epoch-guarded session reference.
    #[must_use]
    pub const fn new(id: SessionId, epoch: u64, seed: Seed) -> Self {
        Self { id, epoch, seed }
    }
}

/// Scenario entry advertised by `ListScenarios`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioCatalogEntry {
    /// Human-readable registry name used by scenario-reference creation.
    pub name: String,
    /// Human-readable description returned by discovery.
    pub description: String,
    /// Stable source identifier for the scenario definition.
    pub source_id: String,
    /// Executable scenario source.
    pub source: ScenarioCatalogSource,
}

/// Scenario source stored in the server-side catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScenarioCatalogSource {
    /// A fixed scenario definition that accepts only its embedded seed.
    Fixed {
        /// Executable scenario definition.
        scenario: ScenarioDef,
    },
    /// Canonical material that can be re-materialized with the request seed.
    CanonicalMaterial {
        /// Canonical domain passed to [`ScenarioDef::from_canonical_material_with_seed`].
        domain: String,
        /// Seed-independent canonical scenario material.
        material: String,
    },
}

impl ScenarioCatalogEntry {
    /// Builds a scenario catalog entry.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        source_id: impl Into<String>,
        scenario: ScenarioDef,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            source_id: source_id.into(),
            source: ScenarioCatalogSource::Fixed { scenario },
        }
    }

    /// Builds a seed-parameterized scenario entry from canonical material.
    #[must_use]
    pub fn from_canonical_material(
        name: impl Into<String>,
        description: impl Into<String>,
        source_id: impl Into<String>,
        domain: impl Into<String>,
        material: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            source_id: source_id.into(),
            source: ScenarioCatalogSource::CanonicalMaterial {
                domain: domain.into(),
                material: material.into(),
            },
        }
    }

    /// Returns the public discovery view for this scenario.
    #[must_use]
    pub fn summary(&self) -> ScenarioSummary {
        ScenarioSummary {
            name: self.name.clone(),
            description: self.description.clone(),
            source_id: self.source_id.clone(),
        }
    }

    fn scenario_for_seed(&self, seed: Seed) -> Result<ScenarioDef, LifecycleApiError> {
        match &self.source {
            ScenarioCatalogSource::Fixed { scenario } => {
                if scenario.seed() != seed {
                    return Err(LifecycleApiError::ScenarioSeedMismatch {
                        scenario_seed: scenario.seed(),
                        request_seed: seed,
                    });
                }
                Ok(scenario.clone())
            }
            ScenarioCatalogSource::CanonicalMaterial { domain, material } => Ok(
                ScenarioDef::from_canonical_material_with_seed(domain, material, seed),
            ),
        }
    }
}

/// Scenario metadata returned by `ListScenarios`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioSummary {
    /// Human-readable registry name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Stable source identifier.
    pub source_id: String,
}

/// Response returned by `ListScenarios`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListScenariosResponse {
    /// Scenario entries known by the server.
    pub scenarios: Vec<ScenarioSummary>,
}

/// Scenario input accepted by `CreateSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateSessionSource {
    /// Resolve a named scenario from the server registry.
    ScenarioRef {
        /// Registry name to resolve.
        name: String,
    },
    /// Use a self-contained scenario definition.
    Inline {
        /// Inline scenario definition.
        scenario: ScenarioDef,
    },
}

/// Request accepted by `CreateSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSessionRequest {
    /// Scenario source, either by reference or inline.
    pub source: CreateSessionSource,
    /// Seed recorded in the returned [`SessionRef`].
    pub seed: Seed,
    /// Whether the session should remain paused immediately after `Start`.
    pub start_paused: bool,
}

impl CreateSessionRequest {
    /// Builds a request from a scenario registry name.
    #[must_use]
    pub fn scenario_ref(name: impl Into<String>, seed: Seed) -> Self {
        Self {
            source: CreateSessionSource::ScenarioRef { name: name.into() },
            seed,
            start_paused: true,
        }
    }

    /// Builds a request from an inline scenario definition.
    #[must_use]
    pub fn inline(scenario: ScenarioDef, seed: Seed) -> Self {
        Self {
            source: CreateSessionSource::Inline { scenario },
            seed,
            start_paused: true,
        }
    }

    /// Sets whether the created session should stay paused after `Start`.
    #[must_use]
    pub fn with_start_paused(mut self, start_paused: bool) -> Self {
        self.start_paused = start_paused;
        self
    }
}

/// Response returned by `CreateSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSessionResponse {
    /// Epoch-guarded session reference.
    pub session: SessionRef,
    /// State observed from the lock-free mirror after startup.
    pub state: LiveStateKind,
}

/// Summary returned by `ListSessions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    /// Epoch-guarded session reference.
    pub session: SessionRef,
    /// State read from the lock-free live mirror.
    pub state: LiveStateKind,
    /// Event-log length read from the lock-free live mirror.
    pub event_log_len: u64,
}

/// Response returned by `ListSessions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListSessionsResponse {
    /// Live session summaries.
    pub sessions: Vec<SessionSummary>,
}

/// Request accepted by `DestroySession`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DestroySessionRequest {
    /// Session reference to stop and drop.
    pub session: SessionRef,
}

impl DestroySessionRequest {
    /// Builds a destroy request for `session`.
    #[must_use]
    pub const fn new(session: SessionRef) -> Self {
        Self { session }
    }
}

/// Response returned by `DestroySession`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DestroySessionResponse {
    /// Session reference supplied by the caller.
    pub session: SessionRef,
    /// Whether the session id was already absent.
    pub already_absent: bool,
    /// Whether a live actor was stopped by this request.
    pub stopped: bool,
}

/// Error returned by lifecycle unary API methods.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LifecycleApiError {
    /// Protocol negotiation failed.
    #[error("lifecycle API RPC ABI negotiation failed: {source}")]
    RpcAbi {
        /// Underlying RPC ABI error.
        #[from]
        source: RpcAbiError,
    },
    /// A named scenario was not present in the registry.
    #[error("scenario `{name}` was not found")]
    ScenarioNotFound {
        /// Missing scenario name.
        name: String,
    },
    /// A fixed or inline scenario carried a different seed than the request.
    #[error("scenario seed mismatch: scenario={scenario_seed:?} request={request_seed:?}")]
    ScenarioSeedMismatch {
        /// Seed embedded in the scenario definition.
        scenario_seed: Seed,
        /// Seed supplied by the request.
        request_seed: Seed,
    },
    /// The genesis temporal graph could not be created.
    #[error("failed to create genesis temporal graph: {message}")]
    GenesisGraph {
        /// Deterministic graph construction error.
        message: String,
    },
    /// A command could not be sent to a session actor.
    #[error("session command channel closed for session {session_id:?}")]
    CommandChannelClosed {
        /// Session whose actor mailbox closed.
        session_id: SessionId,
    },
    /// The session did not reach the expected state in the bounded yield budget.
    #[error("session {session_id:?} did not reach state {expected:?}")]
    StateDidNotAdvance {
        /// Session that did not advance.
        session_id: SessionId,
        /// Expected state.
        expected: LiveStateKind,
    },
    /// The supplied epoch did not match the live session epoch.
    #[error("session {session_id:?} epoch mismatch: expected {expected}, actual {actual}")]
    EpochMismatch {
        /// Session whose epoch was checked.
        session_id: SessionId,
        /// Live session epoch.
        expected: u64,
        /// Caller-supplied epoch.
        actual: u64,
    },
    /// The actor task could not be joined.
    #[error("session actor join failed: {message}")]
    ActorJoin {
        /// Join error text.
        message: String,
    },
    /// The actor returned a session error.
    #[error("session actor failed: {message}")]
    ActorFailed {
        /// Session error text.
        message: String,
    },
}

/// In-process lifecycle control plane for unary API methods.
pub struct LifecycleControlPlane<L, F> {
    server_name: String,
    scenarios: BTreeMap<String, ScenarioCatalogEntry>,
    sessions: BTreeMap<SessionId, SessionRuntime>,
    next_session_id: u64,
    next_epoch: u64,
    loop_factory: F,
    mailbox_capacity: usize,
    startup_max_actor_yields: u64,
    _loop: PhantomData<fn() -> L>,
}

impl<L, F> LifecycleControlPlane<L, F>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Seed) -> L,
{
    /// Builds a lifecycle control plane from a scenario catalog and loop factory.
    #[must_use]
    pub fn new(
        server_name: impl Into<String>,
        scenarios: Vec<ScenarioCatalogEntry>,
        loop_factory: F,
    ) -> Self {
        let scenarios = scenarios
            .into_iter()
            .map(|entry| (entry.name.clone(), entry))
            .collect();
        Self {
            server_name: server_name.into(),
            scenarios,
            sessions: BTreeMap::new(),
            next_session_id: 1,
            next_epoch: 1,
            loop_factory,
            mailbox_capacity: LIFECYCLE_SESSION_MAILBOX_CAPACITY,
            startup_max_actor_yields: LIFECYCLE_SESSION_STARTUP_MAX_ACTOR_YIELDS,
            _loop: PhantomData,
        }
    }

    /// Overrides the session actor mailbox capacity for subsequently-created sessions.
    #[must_use]
    pub fn with_mailbox_capacity(mut self, mailbox_capacity: usize) -> Self {
        self.mailbox_capacity = mailbox_capacity;
        self
    }

    /// Overrides the startup actor-yield budget.
    #[must_use]
    pub fn with_startup_max_actor_yields(mut self, startup_max_actor_yields: u64) -> Self {
        self.startup_max_actor_yields = startup_max_actor_yields;
        self
    }

    /// Returns the number of live sessions in the registry.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns the lifecycle API `Hello` response.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::RpcAbi`] when the client offers an
    /// incompatible protocol major version.
    pub fn hello(&self, request: HelloRequest) -> Result<HelloResponse, LifecycleApiError> {
        let version = negotiate_rpc_protocol(request.version)?;
        Ok(HelloResponse::new(
            self.server_name.clone(),
            version,
            RPC_OPEN_SET_PAYLOAD_KINDS,
            ControlTransportKind::InProcess,
        ))
    }

    /// Lists registered scenario metadata without touching session actors.
    #[must_use]
    pub fn list_scenarios(&self) -> ListScenariosResponse {
        ListScenariosResponse {
            scenarios: self
                .scenarios
                .values()
                .map(ScenarioCatalogEntry::summary)
                .collect(),
        }
    }

    /// Creates a session actor and issues the session `Start` command.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::ScenarioNotFound`] when a named scenario is
    /// unknown, [`LifecycleApiError::GenesisGraph`] when the genesis temporal
    /// graph cannot be built, [`LifecycleApiError::CommandChannelClosed`] when
    /// the actor mailbox closes before startup, or
    /// [`LifecycleApiError::StateDidNotAdvance`] when the actor does not publish
    /// the expected startup state within the bounded yield budget.
    pub async fn create_session(
        &mut self,
        request: CreateSessionRequest,
    ) -> Result<CreateSessionResponse, LifecycleApiError> {
        let scenario = self.resolve_scenario(&request)?;
        let configuration = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario)?;
        let loop_instance = (self.loop_factory)(&scenario, request.seed);
        let engine = Engine::new(configuration, graph, loop_instance);
        let (sender, receiver) = mpsc::channel(self.mailbox_capacity);
        let actor = SessionActor::new(engine, receiver);
        let live = actor.live_snapshot();
        let actor_task = tokio::spawn(async move { actor.run().await });

        let session_ref = self.next_session_ref(request.seed);
        let runtime = SessionRuntime {
            session: session_ref,
            sender,
            live,
            actor_task,
        };

        if let Err(error) = start_runtime(
            &runtime,
            request.start_paused,
            self.startup_max_actor_yields,
        )
        .await
        {
            cleanup_runtime(runtime).await;
            return Err(error);
        }

        let state = runtime.live.read().state_kind;
        self.sessions.insert(session_ref.id, runtime);
        Ok(CreateSessionResponse {
            session: session_ref,
            state,
        })
    }

    /// Lists live sessions from the registry and lock-free mirrors.
    #[must_use]
    pub fn list_sessions(&self) -> ListSessionsResponse {
        ListSessionsResponse {
            sessions: self
                .sessions
                .values()
                .map(SessionRuntime::summary)
                .collect(),
        }
    }

    /// Stops and drops a session actor.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::EpochMismatch`] when the supplied epoch does
    /// not match the live session, [`LifecycleApiError::CommandChannelClosed`]
    /// when the actor mailbox closes before `Stop`, [`LifecycleApiError::ActorJoin`]
    /// when the actor task cannot be joined, or
    /// [`LifecycleApiError::ActorFailed`] when the actor returns a session error.
    pub async fn destroy_session(
        &mut self,
        request: DestroySessionRequest,
    ) -> Result<DestroySessionResponse, LifecycleApiError> {
        let Some(runtime) = self.sessions.get(&request.session.id) else {
            return Ok(DestroySessionResponse {
                session: request.session,
                already_absent: true,
                stopped: false,
            });
        };

        if runtime.session.epoch != request.session.epoch {
            return Err(LifecycleApiError::EpochMismatch {
                session_id: request.session.id,
                expected: runtime.session.epoch,
                actual: request.session.epoch,
            });
        }

        let runtime = self.sessions.remove(&request.session.id).ok_or(
            LifecycleApiError::CommandChannelClosed {
                session_id: request.session.id,
            },
        )?;
        if runtime.sender.send(SessionCommand::Stop).await.is_err() {
            join_actor(runtime.actor_task).await?;
            return Err(LifecycleApiError::CommandChannelClosed {
                session_id: request.session.id,
            });
        }
        join_actor(runtime.actor_task).await?;
        Ok(DestroySessionResponse {
            session: request.session,
            already_absent: false,
            stopped: true,
        })
    }

    fn resolve_scenario(
        &self,
        request: &CreateSessionRequest,
    ) -> Result<ScenarioDef, LifecycleApiError> {
        match &request.source {
            CreateSessionSource::ScenarioRef { name } => self
                .scenarios
                .get(name)
                .ok_or_else(|| LifecycleApiError::ScenarioNotFound { name: name.clone() })?
                .scenario_for_seed(request.seed),
            CreateSessionSource::Inline { scenario } => {
                if scenario.seed() != request.seed {
                    return Err(LifecycleApiError::ScenarioSeedMismatch {
                        scenario_seed: scenario.seed(),
                        request_seed: request.seed,
                    });
                }
                Ok(scenario.clone())
            }
        }
    }

    fn next_session_ref(&mut self, seed: Seed) -> SessionRef {
        let id = SessionId::new(self.next_session_id);
        self.next_session_id = self.next_session_id.saturating_add(1);
        let epoch = self.next_epoch;
        self.next_epoch = self.next_epoch.saturating_add(1);
        SessionRef::new(id, epoch, seed)
    }
}

/// In-process [`ControlClient`] implementation for unary lifecycle methods.
pub struct InProcessLifecycleClient<L, F> {
    control_plane: tokio::sync::Mutex<LifecycleControlPlane<L, F>>,
    wire_model: ControlWireModel,
}

impl<L, F> InProcessLifecycleClient<L, F> {
    /// Builds an in-process lifecycle client from a lifecycle control plane.
    #[must_use]
    pub fn new(control_plane: LifecycleControlPlane<L, F>) -> Self {
        Self {
            control_plane: tokio::sync::Mutex::new(control_plane),
            wire_model: ControlWireModel::current(),
        }
    }
}

impl<L, F> InProcessLifecycleClient<L, F>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Seed) -> L + Send + Sync + 'static,
{
    /// Returns the number of live sessions in the wrapped control plane.
    pub async fn session_count(&self) -> usize {
        self.control_plane.lock().await.session_count()
    }
}

impl<L, F> ControlClient for InProcessLifecycleClient<L, F>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Seed) -> L + Send + Sync + 'static,
{
    fn transport(&self) -> ControlTransportKind {
        ControlTransportKind::InProcess
    }

    fn wire_model(&self) -> ControlWireModel {
        self.wire_model
    }

    fn hello(&self, request: HelloRequest) -> ControlClientFuture<'_, HelloResponse> {
        Box::pin(async move {
            self.control_plane
                .lock()
                .await
                .hello(request)
                .map_err(ControlClientError::from)
        })
    }

    fn list_scenarios(&self) -> ControlClientFuture<'_, ListScenariosResponse> {
        Box::pin(async move { Ok(self.control_plane.lock().await.list_scenarios()) })
    }

    fn create_session(
        &self,
        request: CreateSessionRequest,
    ) -> ControlClientFuture<'_, CreateSessionResponse> {
        Box::pin(async move {
            self.control_plane
                .lock()
                .await
                .create_session(request)
                .await
                .map_err(ControlClientError::from)
        })
    }

    fn list_sessions(&self) -> ControlClientFuture<'_, ListSessionsResponse> {
        Box::pin(async move { Ok(self.control_plane.lock().await.list_sessions()) })
    }

    fn destroy_session(
        &self,
        request: DestroySessionRequest,
    ) -> ControlClientFuture<'_, DestroySessionResponse> {
        Box::pin(async move {
            self.control_plane
                .lock()
                .await
                .destroy_session(request)
                .await
                .map_err(ControlClientError::from)
        })
    }
}

struct SessionRuntime {
    session: SessionRef,
    sender: mpsc::Sender<SessionCommand>,
    live: Arc<LiveSnapshot>,
    actor_task: JoinHandle<Result<SessionRunReport, SessionError>>,
}

impl SessionRuntime {
    fn summary(&self) -> SessionSummary {
        let status = self.live.read();
        SessionSummary {
            session: self.session,
            state: status.state_kind,
            event_log_len: status.event_log_len,
        }
    }
}

async fn start_runtime(
    runtime: &SessionRuntime,
    start_paused: bool,
    max_actor_yields: u64,
) -> Result<(), LifecycleApiError> {
    send_runtime_command(runtime, SessionCommand::Start).await?;
    wait_for_live_state(runtime, LiveStateKind::Paused, max_actor_yields).await?;
    if !start_paused {
        send_runtime_command(runtime, SessionCommand::Continue).await?;
        wait_for_live_state(runtime, LiveStateKind::Running, max_actor_yields).await?;
    }
    Ok(())
}

async fn send_runtime_command(
    runtime: &SessionRuntime,
    command: SessionCommand,
) -> Result<(), LifecycleApiError> {
    runtime
        .sender
        .send(command)
        .await
        .map_err(|_| LifecycleApiError::CommandChannelClosed {
            session_id: runtime.session.id,
        })
}

async fn wait_for_live_state(
    runtime: &SessionRuntime,
    expected: LiveStateKind,
    max_actor_yields: u64,
) -> Result<(), LifecycleApiError> {
    for _ in 0..max_actor_yields {
        if runtime.live.read().state_kind == expected {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
    Err(LifecycleApiError::StateDidNotAdvance {
        session_id: runtime.session.id,
        expected,
    })
}

async fn cleanup_runtime(runtime: SessionRuntime) {
    let _ = runtime.sender.send(SessionCommand::Stop).await;
    if runtime.actor_task.is_finished() {
        let _ = runtime.actor_task.await;
        return;
    }
    for _ in 0..LIFECYCLE_SESSION_STARTUP_MAX_ACTOR_YIELDS {
        if runtime.actor_task.is_finished() {
            let _ = runtime.actor_task.await;
            return;
        }
        tokio::task::yield_now().await;
    }
    runtime.actor_task.abort();
    let _ = runtime.actor_task.await;
}

async fn join_actor(
    actor_task: JoinHandle<Result<SessionRunReport, SessionError>>,
) -> Result<SessionRunReport, LifecycleApiError> {
    match actor_task.await {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(error)) => Err(LifecycleApiError::ActorFailed {
            message: error.to_string(),
        }),
        Err(error) => Err(LifecycleApiError::ActorJoin {
            message: error.to_string(),
        }),
    }
}

fn graph_with_baked_genesis(scenario: &ScenarioDef) -> Result<TemporalGraph, LifecycleApiError> {
    let genesis = Configuration::genesis(scenario.clone());
    TemporalGraph::empty()
        .with_baked_genesis(scenario, genesis_checkpoint(&genesis)?)
        .map_err(engine_error)
}

fn genesis_checkpoint(
    configuration: &Configuration,
) -> Result<GenesisCheckpoint, LifecycleApiError> {
    let checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .map_err(engine_error)?;
    Ok(GenesisCheckpoint { checkpoint })
}

fn engine_error(error: EngineError) -> LifecycleApiError {
    LifecycleApiError::GenesisGraph {
        message: error.to_string(),
    }
}
