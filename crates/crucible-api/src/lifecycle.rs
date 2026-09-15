//! Discovery and lifecycle unary control-plane API.
//!
//! This module owns the RFC-0010 T-API-3 boundary. It provides typed unary
//! methods for `Hello`, `ListScenarios`, `CreateSession`, `ResumeSession`,
//! `ListSessions`, and `DestroySession`, backed by the same
//! `crucible-session` actor and lock-free live mirror used by the lower
//! session layer.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crucible::{
    Action, Checkpoint, CheckpointKind, Configuration, ContentHash, ControlOperationKind,
    DebugAttachReport, DebugGdbEndpoint, Decision, DeliveryOrderDecision, EngineError,
    EventAttributeValue, EventDiagnosticPayload, EventLevel, EventLogOffset, ExecutionFingerprint,
    FingerprintSample, GdbListen, GenesisCheckpoint, LogLevel, NodeId, QuantumLoop, QuantumOutcome,
    QuantumRequest, ScenarioDef, ScenarioDefForm, Schedule, SchedulerError, SchedulerEventLogEntry,
    SchedulerOperationalFailureClass, SchedulerQuiescence, Seed, TemporalGraph, VirtualTime,
    WhiteBoxPolicy, bake,
};
use crucible_session::{
    BreakpointDisposition, BreakpointPolicy, CheckpointRef, CommandReply, DebugCapability,
    DebugClientId, DebugControllerLease, DebugCoordinator, DebugCoordinatorError, DebugRole,
    Engine, LiveSnapshot, LiveStateKind, OutcomeKind, QueryKind, QueryResult, SessionActor,
    SessionCommand, SessionCommandKind, SessionControlLogEntry, SessionControlPayload,
    SessionControlResult, SessionError, SessionReproductionLog, SessionRunReport,
    SessionStateTransitionBus,
};
use thiserror::Error;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::debug_relay::DebugRelayAccess;
use crate::{
    AttachRequest, ClientControlStream, ClientWatchStream, CommandResultStatus, ControlClient,
    ControlClientError, ControlClientFuture, ControlPlaneEventLog, ControlTransportKind,
    ControlWireModel, HelloRequest, HelloResponse, InProcessLifecycleControlStream,
    InProcessStreamingSession, RPC_OPEN_SET_PAYLOAD_KINDS, RpcAbiError, SendRequest, SendResponse,
    StreamingApiError, negotiate_rpc_protocol,
};

#[path = "lifecycle/hex.rs"]
mod hex;
use hex::{hex_string, optional_hex_string};
#[path = "lifecycle/resource_limit.rs"]
mod resource_limit;
pub use resource_limit::LifecycleResourceLimit;

/// Default actor mailbox capacity for lifecycle-created sessions.
pub const LIFECYCLE_SESSION_MAILBOX_CAPACITY: usize = 16;

/// Default actor-yield budget for lifecycle startup commands.
pub const LIFECYCLE_SESSION_STARTUP_MAX_ACTOR_YIELDS: u64 = 128;

/// Maximum canonical campaign replay-closure bytes accepted by one resume request.
pub const RESUME_REPLAY_CLOSURE_MAX_BYTES: usize = 128 * 1024 * 1024;

/// Maximum combined canonical observation proof and raw evidence bytes accepted by resume.
pub const RESUME_OBSERVATION_SOURCE_MAX_BYTES: usize = 128 * 1024 * 1024;

/// Default wall-clock deadline for campaign-owned observation source preparation.
pub const RESUME_OBSERVATION_PREPARATION_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Default number of expensive portable observation preparations admitted concurrently.
pub const RESUME_OBSERVATION_PREPARATION_CAPACITY: usize = 1;

/// Opaque authority retained for the complete lifetime of one admitted session.
///
/// Owner-side session composition uses this guard to keep immutable source and
/// retention capabilities alive until the session is destroyed.
pub struct SessionLifetimeRetention {
    _capability: Box<dyn Send + Sync>,
}

impl SessionLifetimeRetention {
    /// Wraps one owner-bound capability for session-lifetime retention.
    #[must_use]
    pub fn new(capability: impl Send + Sync + 'static) -> Self {
        Self {
            _capability: Box::new(capability),
        }
    }
}

impl fmt::Debug for SessionLifetimeRetention {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SessionLifetimeRetention").finish()
    }
}

#[path = "lifecycle/debug_dispatch.rs"]
mod debug_dispatch;

/// Operator-visible evidence for the exact live runtime boundary selected by a debugger reposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugLandedRuntimeCoordinate {
    /// Coordinate selector resolved by the session actor.
    pub requested_coordinate: String,
    /// Content address of the landed configuration.
    pub configuration: String,
    /// Content address of the production-bound runtime state.
    pub runtime_state: String,
    /// Scheduler virtual time at the landed boundary.
    pub virtual_time_ticks: u64,
    /// Number of schedule decisions in the landed prefix.
    pub schedule_prefix_len: usize,
    /// Content address of the landed event-log prefix.
    pub event_log_prefix: String,
    /// Byte offset of the landed event-log cursor.
    pub event_log_bytes: u64,
    /// Event count of the landed event-log cursor.
    pub event_log_events: u64,
    /// Per-node retired instruction counters at the landed boundary.
    pub node_icounts: BTreeMap<String, u64>,
    /// Gateway generation committed for the selected production backend.
    pub gateway_generation: u64,
    /// Stable description of the retired world's observed cleanup state.
    pub retired_world_cleanup: String,
}

/// Result returned to a remote debugger after a live reposition operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugRepositionResult {
    /// Exact production-bound runtime coordinate reached by the operation.
    pub landed: DebugLandedRuntimeCoordinate,
    /// Matched event sequence for reverse operations, when applicable.
    pub target_event_sequence: Option<u64>,
}

/// Authorized actor dispatch handle captured without retaining the global registry lock.
#[derive(Clone)]
pub struct GuestIntrospectionDispatch {
    sender: mpsc::Sender<SessionCommand>,
    session_id: SessionId,
}

/// Authorized actor dispatch handle for debugger time-travel operations.
#[derive(Clone)]
pub struct DebugRepositionDispatch {
    sender: mpsc::Sender<SessionCommand>,
    session_id: SessionId,
}

/// Minimal delegated quantum loop used by the in-process CLI double.
///
/// The loop owns the scheduler boundary below the CLI/API layer. It advances a
/// deterministic virtual-time counter, emits no scheduler event-log entries, and
/// reports terminal quiescence after each quantum so lifecycle-created sessions
/// can exercise the real `Start`/`Continue`/streaming/terminal-state path
/// without a QEMU backend.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QuiescentLifecycleLoop {
    quanta: u64,
    event_log_events: u64,
}

impl QuiescentLifecycleLoop {
    /// Builds a quiescent lifecycle loop with a zero virtual-time frontier.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            quanta: 0,
            event_log_events: 0,
        }
    }

    /// Returns the number of driven quanta.
    #[must_use]
    pub const fn quanta(&self) -> u64 {
        self.quanta
    }
}

impl QuantumLoop for QuiescentLifecycleLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let frontier = VirtualTime { ticks: self.quanta };
        let event_log_entries = vec![self.diagnostic_entry(frontier)];
        self.event_log_events = self
            .event_log_events
            .saturating_add(event_log_entries.len() as u64);
        let decision = Decision::DeliveryOrder(DeliveryOrderDecision {
            at: frontier,
            order: Vec::new(),
        });
        let configuration =
            crucible::try_step(&request.configuration, decision.clone()).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "quiescent lifecycle loop could not record virtual-time decision: {error}"
                    ),
                }
            })?;
        Ok(QuantumOutcome {
            configuration,
            frontier,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            discovered_choices: Vec::new(),
            event_log_entries,
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: EventLogOffset::new(Default::default(), 0, self.event_log_events),
            scheduler_quiescence: Some(SchedulerQuiescence::default()),
        })
    }

    fn sample_fingerprint(
        &mut self,
        node: crucible::NodeId,
    ) -> Result<FingerprintSample, SchedulerError> {
        let material = format!(
            "node={}\nquanta={}\nevent-log-events={}\n",
            node.name, self.quanta, self.event_log_events
        );
        Ok(FingerprintSample {
            node,
            at: VirtualTime { ticks: self.quanta },
            fingerprint: ExecutionFingerprint {
                hash: ContentHash::from_canonical_material(
                    "crucible.lifecycle.quiescent-fingerprint.v1",
                    &material,
                ),
            },
        })
    }
}

impl QuiescentLifecycleLoop {
    fn diagnostic_entry(&self, frontier: VirtualTime) -> SchedulerEventLogEntry {
        let mut details = BTreeMap::new();
        details.insert(
            String::from("quantum"),
            EventAttributeValue::U64(self.quanta),
        );
        SchedulerEventLogEntry::diagnostic(
            self.event_log_events,
            frontier,
            EventDiagnosticPayload::new("crucible.lifecycle.quiescent", EventLevel::Info, details),
        )
    }
}

mod session_contract;

pub use session_contract::*;
use session_contract::{
    inline_scenario_form, resume_observation_source_identity, resume_replay_closure_identity,
    scenario_form_white_box_policies,
};

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
    /// A resume checkpoint closure was malformed or internally inconsistent.
    #[error("resume checkpoint closure is invalid: {message}")]
    ResumeCheckpoint {
        /// Deterministic resume-checkpoint validation error.
        message: String,
    },
    /// Campaign replay evidence was missing, unsupported, or failed authentication.
    #[error("resume campaign replay closure is invalid: {message}")]
    ResumeReplayClosure {
        /// Deterministic replay-closure validation error.
        message: String,
    },
    /// A portable observation source was missing, unsupported, or failed authentication.
    #[error("resume campaign observation source is invalid: {message}")]
    ResumeObservationSource {
        /// Deterministic observation-source validation error.
        message: String,
    },
    /// A command could not be sent to a session actor.
    #[error("session command channel closed for session {session_id:?}")]
    CommandChannelClosed {
        /// Session whose actor mailbox closed.
        session_id: SessionId,
    },
    /// The requested session is not present in the lifecycle registry.
    #[error("session {session:?} was not found")]
    SessionNotFound {
        /// Requested session reference.
        session: SessionRef,
    },
    /// The live session cap has been reached.
    #[error("live session limit reached: limit={limit}")]
    SessionLimitReached {
        /// Maximum number of live sessions.
        limit: usize,
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
    /// A live actor rejected an otherwise well-formed debugger operation.
    #[error("session command rejected: {message}")]
    SessionCommandRejected {
        /// Stable actor rejection detail.
        message: String,
    },
    /// A mutation was attempted against an owner-enforced read-only session.
    #[error("session {session:?} is an exclusive read-only debug session")]
    ReadOnlySession {
        /// Session that rejected mutation.
        session: SessionRef,
    },
    /// A debugger identity, capability, or controller lease was rejected.
    #[error("debug access rejected: {source}")]
    DebugAccess {
        /// Session-owned debugger authorization failure.
        #[from]
        source: DebugCoordinatorError,
    },
    /// The session has no active stable GDB endpoint to relay.
    #[error("session debugger is not attached")]
    DebugEndpointUnavailable,
    /// A production resource reservation exceeded its authored or compiled bound.
    #[error(transparent)]
    ResourceLimit(#[from] LifecycleResourceLimit),
    /// The delegated execution backend could not be constructed.
    #[error("session execution backend construction failed: {message}")]
    LoopFactory {
        /// Deterministic backend-construction failure detail.
        message: String,
    },
    /// Attempt-scoped resource enforcement stopped lifecycle progress.
    #[error("attempt operational boundary failed: {message}")]
    AttemptOperational {
        /// Stable supervisor disposition, independent of diagnostic wording.
        class: SchedulerOperationalFailureClass,
        /// Deterministic operational diagnostic text.
        message: String,
    },
}

/// Source-aware loop factory used by the lifecycle control plane.
pub type LifecycleLoopFactory<L> = Box<
    dyn Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync,
>;

/// Reports a replay-closure rejection at the lifecycle component boundary.
///
/// The API boundary owns the stable diagnostic carried by this error. Validators
/// convert model-specific errors when crossing the boundary so those error types
/// remain outside this crate's public contract. Callers identify the rejection by
/// this type and do not need to parse its diagnostic text.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{message}")]
pub struct ResumeReplayClosureValidationError {
    message: String,
}

impl ResumeReplayClosureValidationError {
    /// Creates a replay-closure rejection with stable diagnostic text.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the stable replay-closure validation diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Callback that authenticates campaign replay evidence for one exact resume source.
pub type ResumeReplayClosureValidator = Box<
    dyn Fn(
            &ScenarioDefForm,
            &Configuration,
            &Checkpoint,
            &ResumeReplayClosure,
        ) -> Result<(), ResumeReplayClosureValidationError>
        + Send
        + Sync,
>;

#[path = "lifecycle/observation_resume.rs"]
mod observation_resume;
pub(crate) use observation_resume::{
    PendingObservationResume, PreparedObservationResume, ResumeObservationCancellationGuard,
    ResumeObservationPreparationPermit,
};
pub use observation_resume::{
    ResumeObservationCancellation, ResumeObservationCancellationRegistration,
    ResumeObservationLoopFactory, ResumeObservationPreparationContext,
};

/// In-process lifecycle control plane for unary API methods.
pub struct LifecycleControlPlane<L, F> {
    server_name: String,
    scenarios: BTreeMap<String, ScenarioCatalogEntry>,
    sessions: BTreeMap<SessionId, SessionRuntime>,
    next_session_id: u64,
    next_epoch: u64,
    loop_factory: F,
    resume_replay_closure_validator: Option<ResumeReplayClosureValidator>,
    resume_observation_loop_factory: Option<ResumeObservationLoopFactory<L>>,
    resume_observation_preparation_timeout: Duration,
    resume_observation_preparation_capacity: usize,
    active_resume_observation_preparations: Arc<AtomicU64>,
    mailbox_capacity: usize,
    startup_max_actor_yields: u64,
    max_sessions: Option<usize>,
    retain_stopped_sessions: bool,
    _loop: PhantomData<fn() -> L>,
}

mod constructors;

impl<L, F> LifecycleControlPlane<L, F>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>,
{
    /// Installs the authority that authenticates campaign choice evidence on resume.
    ///
    /// The validator receives the scenario, exact recorded configuration, and
    /// checkpoint only after their ordinary identity checks pass. It runs before
    /// backend construction or session allocation.
    #[must_use]
    pub fn with_resume_replay_closure_validator(
        mut self,
        validator: impl Fn(
            &ScenarioDefForm,
            &Configuration,
            &Checkpoint,
            &ResumeReplayClosure,
        ) -> Result<(), ResumeReplayClosureValidationError>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.resume_replay_closure_validator = Some(Box::new(validator));
        self
    }

    /// Installs campaign-owned authentication and restore for portable observation resumes.
    ///
    /// Requests carrying an observation source fail closed when this factory is
    /// absent. The factory completes before the actor or session reference is
    /// created and must return a loop restored at the claimed source boundary.
    #[must_use]
    pub fn with_resume_observation_loop_factory(
        mut self,
        factory: impl Fn(
            &ResumeSessionRequest,
            &Configuration,
            &ResumeObservationPreparationContext,
        ) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.resume_observation_loop_factory = Some(Arc::new(factory));
        self
    }

    /// Sets the maximum number of expensive observation preparations in flight.
    #[must_use]
    pub const fn with_resume_observation_preparation_capacity(mut self, capacity: usize) -> Self {
        self.resume_observation_preparation_capacity = capacity;
        self
    }

    /// Overrides the session actor mailbox capacity for subsequently-created sessions.
    #[must_use]
    pub fn with_mailbox_capacity(mut self, mailbox_capacity: usize) -> Self {
        self.mailbox_capacity = mailbox_capacity;
        self
    }

    /// Overrides the maximum number of live sessions accepted by `CreateSession`.
    #[must_use]
    pub const fn with_max_sessions(mut self, max_sessions: usize) -> Self {
        self.max_sessions = Some(max_sessions);
        self
    }

    /// Keeps stopped session actors registered for terminal queries and reproduction reads.
    #[must_use]
    pub const fn with_terminal_session_retention(mut self, enabled: bool) -> Self {
        self.retain_stopped_sessions = enabled;
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
    /// a protocol version other than the sole version admitted by this build.
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
    /// Returns [`LifecycleApiError::SessionLimitReached`] when the live-session
    /// cap has been reached, [`LifecycleApiError::ScenarioNotFound`] when a
    /// named scenario is unknown, [`LifecycleApiError::GenesisGraph`] when the
    /// genesis temporal graph cannot be built,
    /// [`LifecycleApiError::CommandChannelClosed`] when the actor mailbox closes
    /// before startup, or [`LifecycleApiError::StateDidNotAdvance`] when the
    /// actor does not publish the expected startup state within the bounded
    /// yield budget.
    pub async fn create_session(
        &mut self,
        request: CreateSessionRequest,
    ) -> Result<CreateSessionResponse, LifecycleApiError> {
        if let Some(limit) = self.max_sessions
            && self.sessions.len() >= limit
        {
            return Err(LifecycleApiError::SessionLimitReached { limit });
        }
        let scenario = self.resolve_scenario(&request)?;
        let scenario_form = inline_scenario_form(&request);
        let configuration = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario)?;
        let debug_genesis = scenario_form
            .map(|source| debug_genesis_checkpoint(&configuration, source))
            .transpose()?;
        let loop_instance = (self.loop_factory)(&scenario, scenario_form, request.seed)?;
        let white_box_policies = self.white_box_policies_for_source(scenario_form);
        let engine = Engine::new(configuration, graph, loop_instance)
            .with_white_box_policies(white_box_policies);
        let (sender, receiver) = mpsc::channel(self.mailbox_capacity);
        let actor = SessionActor::new(engine, receiver)
            .with_terminal_command_keepalive(self.retain_stopped_sessions);
        let live = actor.live_snapshot();
        let event_log = ControlPlaneEventLog::new(actor.event_log());
        let reproduction_log = actor.reproduction_log();
        let state_transitions = actor.state_transition_bus();
        let actor_task = tokio::spawn(async move { actor.run().await });

        let session_ref = self.next_session_ref(request.seed);
        let runtime = SessionRuntime {
            session: session_ref,
            sender,
            live,
            event_log,
            reproduction_log,
            state_transitions,
            debug_access: DebugCoordinator::new(),
            debug_operation_gate: Arc::new(Mutex::new(())),
            debug_genesis,
            access: SessionAccess::ReadWrite,
            _lifetime_retention: None,
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

    pub(crate) fn prepare_observation_resume(
        &self,
        request: ResumeSessionRequest,
    ) -> Result<PendingObservationResume<L>, LifecycleApiError> {
        self.validate_resume_capacity_and_seed(&request)?;
        let permit = self.acquire_resume_observation_preparation()?;
        let configuration = self.validate_direct_resume_request(&request)?;
        let factory = self
            .resume_observation_loop_factory
            .clone()
            .ok_or_else(|| LifecycleApiError::ResumeObservationSource {
                message: String::from(
                    "daemon has no campaign-owned portable observation resume factory",
                ),
            })?;
        Ok(PendingObservationResume {
            request,
            configuration,
            factory,
            context: ResumeObservationPreparationContext::new(
                self.resume_observation_preparation_timeout,
            ),
            permit,
        })
    }

    pub(crate) async fn commit_observation_resume(
        &mut self,
        prepared: PreparedObservationResume<L>,
    ) -> Result<ResumeSessionResponse, LifecycleApiError> {
        if prepared.context.cancellation.is_canceled() {
            return Err(LifecycleApiError::ResumeObservationSource {
                message: String::from("portable observation source preparation was canceled"),
            });
        }
        if prepared.context.is_expired() {
            return Err(LifecycleApiError::ResumeObservationSource {
                message: String::from("portable observation preparation deadline elapsed"),
            });
        }
        self.validate_resume_capacity_and_seed(&prepared.request)?;
        self.finish_direct_resume(
            prepared.request,
            prepared.configuration,
            prepared.loop_instance,
        )
        .await
    }

    fn validate_resume_capacity_and_seed(
        &self,
        request: &ResumeSessionRequest,
    ) -> Result<(), LifecycleApiError> {
        if let Some(limit) = self.max_sessions
            && self.sessions.len() >= limit
        {
            return Err(LifecycleApiError::SessionLimitReached { limit });
        }
        if request.scenario.seed() != request.seed {
            return Err(LifecycleApiError::ScenarioSeedMismatch {
                scenario_seed: request.scenario.seed(),
                request_seed: request.seed,
            });
        }
        Ok(())
    }

    fn acquire_resume_observation_preparation(
        &self,
    ) -> Result<ResumeObservationPreparationPermit, LifecycleApiError> {
        let active_u64 = self
            .active_resume_observation_preparations
            .load(Ordering::Acquire);
        let active = usize::try_from(active_u64).unwrap_or(usize::MAX);
        if active >= self.resume_observation_preparation_capacity {
            return Err(LifecycleApiError::ResumeObservationSource {
                message: format!(
                    "portable observation preparation capacity {} is exhausted",
                    self.resume_observation_preparation_capacity,
                ),
            });
        }
        if let Some(limit) = self.max_sessions
            && self.sessions.len().saturating_add(active) >= limit
        {
            return Err(LifecycleApiError::SessionLimitReached { limit });
        }
        self.active_resume_observation_preparations
            .fetch_add(1, Ordering::AcqRel);
        Ok(ResumeObservationPreparationPermit {
            active: Arc::clone(&self.active_resume_observation_preparations),
        })
    }

    fn validate_direct_resume_request(
        &self,
        request: &ResumeSessionRequest,
    ) -> Result<Configuration, LifecycleApiError> {
        let scenario = request.scenario.scenario_def();
        let configuration = Configuration {
            def: scenario,
            schedule: request.schedule.clone(),
        };
        validate_resume_checkpoint_closure(&configuration, &request.checkpoint)?;
        validate_resume_replay_closure_presence(
            &request.schedule,
            request.replay_closure.as_ref(),
            self.resume_replay_closure_validator.is_some()
                || self.resume_observation_loop_factory.is_some(),
        )?;
        validate_resume_replay_closure_binding(request)?;
        validate_resume_observation_source_binding(request)?;
        if let (Some(closure), Some(validator)) = (
            request.replay_closure.as_ref(),
            self.resume_replay_closure_validator.as_deref(),
        ) {
            validator(
                &request.scenario,
                &configuration,
                &request.checkpoint,
                closure,
            )
            .map_err(|error| LifecycleApiError::ResumeReplayClosure {
                message: error.message,
            })?;
        }
        Ok(configuration)
    }

    async fn finish_direct_resume(
        &mut self,
        request: ResumeSessionRequest,
        configuration: Configuration,
        resumed_loop: L,
    ) -> Result<ResumeSessionResponse, LifecycleApiError> {
        let scenario = configuration.def.clone();

        let mut graph = graph_with_baked_genesis(&scenario)?;
        if !configuration.is_genesis() {
            graph
                .cache_snapshot(&configuration, request.checkpoint.clone())
                .map_err(resume_checkpoint_error)?;
        }

        let white_box_policies = self.white_box_policies_for_source(Some(&request.scenario));
        let engine = Engine::from_recorded_checkpoint(graph, resumed_loop, request.checkpoint.id)
            .map_err(|error| LifecycleApiError::ResumeCheckpoint {
                message: error.to_string(),
            })?
            .with_white_box_policies(white_box_policies);

        let checkpoint = request.checkpoint.id;
        let configuration = configuration.id();
        let (sender, receiver) = mpsc::channel(self.mailbox_capacity);
        let actor = SessionActor::new(engine, receiver)
            .with_terminal_command_keepalive(self.retain_stopped_sessions);
        let live = actor.live_snapshot();
        let event_log = ControlPlaneEventLog::new(actor.event_log());
        let reproduction_log = actor.reproduction_log();
        let state_transitions = actor.state_transition_bus();
        let debug_genesis = Some(debug_genesis_checkpoint(
            &Configuration::genesis(scenario.clone()),
            &request.scenario,
        )?);
        let actor_task = tokio::spawn(async move { actor.run().await });

        let session_ref = self.next_session_ref(request.seed);
        let runtime = SessionRuntime {
            session: session_ref,
            sender,
            live,
            event_log,
            reproduction_log,
            state_transitions,
            debug_access: DebugCoordinator::new(),
            debug_operation_gate: Arc::new(Mutex::new(())),
            debug_genesis,
            access: SessionAccess::ReadWrite,
            _lifetime_retention: None,
            actor_task,
        };
        let state = runtime.live.read().state_kind;
        self.sessions.insert(session_ref.id, runtime);
        Ok(ResumeSessionResponse {
            session: session_ref,
            state,
            checkpoint,
            configuration,
        })
    }

    /// Admits an owner-authenticated exact restore as an exclusive read-only session.
    ///
    /// The caller supplies a checkpoint whose immutable production closure has
    /// already been authenticated by its storage owner. Capacity and every
    /// modeled identity are validated before `build_loop` acquires runtime
    /// resources. The actor is registered paused and rejects all canonical
    /// mutation for its complete lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when capacity is exhausted, source,
    /// configuration, checkpoint, or seed identities disagree, the temporal
    /// graph cannot admit the checkpoint, or `build_loop` rejects restoration.
    pub fn admit_authenticated_read_only_session<E>(
        &mut self,
        source: ScenarioDefForm,
        configuration: Configuration,
        checkpoint: Checkpoint,
        seed: Seed,
        retention: SessionLifetimeRetention,
        build_loop: impl FnOnce() -> Result<L, E>,
    ) -> Result<ResumeSessionResponse, LifecycleApiError>
    where
        E: fmt::Display,
    {
        if let Some(limit) = self.max_sessions
            && self.sessions.len() >= limit
        {
            return Err(LifecycleApiError::SessionLimitReached { limit });
        }
        let scenario = source.scenario_def();
        if scenario.seed() != seed {
            return Err(LifecycleApiError::ScenarioSeedMismatch {
                scenario_seed: scenario.seed(),
                request_seed: seed,
            });
        }
        if configuration.def != scenario
            || checkpoint.configuration != configuration.id()
            || checkpoint.scenario_ref != scenario.id()
            || checkpoint.id != configuration.id()
        {
            return Err(LifecycleApiError::ResumeCheckpoint {
                message: String::from(
                    "owner-authenticated debug checkpoint has inconsistent modeled identities",
                ),
            });
        }

        let mut graph = graph_with_baked_genesis(&scenario)?;
        if !configuration.is_genesis() {
            graph
                .cache_snapshot(&configuration, checkpoint.clone())
                .map_err(resume_checkpoint_error)?;
        }
        let resumed_loop = build_loop().map_err(|error| LifecycleApiError::LoopFactory {
            message: error.to_string(),
        })?;
        let engine = Engine::from_recorded_checkpoint(graph, resumed_loop, checkpoint.id)
            .map_err(|error| LifecycleApiError::ResumeCheckpoint {
                message: error.to_string(),
            })?
            .with_white_box_policies(self.white_box_policies_for_source(Some(&source)));
        let (sender, receiver) = mpsc::channel(self.mailbox_capacity);
        let actor = SessionActor::new(engine, receiver)
            .with_terminal_command_keepalive(self.retain_stopped_sessions);
        let live = actor.live_snapshot();
        let event_log = ControlPlaneEventLog::new(actor.event_log());
        let reproduction_log = actor.reproduction_log();
        let state_transitions = actor.state_transition_bus();
        let debug_genesis = Some(debug_genesis_checkpoint(
            &Configuration::genesis(scenario.clone()),
            &source,
        )?);
        let actor_task = tokio::spawn(async move { actor.run().await });
        let session = self.next_session_ref(seed);
        let runtime = SessionRuntime {
            session,
            sender,
            live,
            event_log,
            reproduction_log,
            state_transitions,
            debug_access: DebugCoordinator::new(),
            debug_operation_gate: Arc::new(Mutex::new(())),
            debug_genesis,
            access: SessionAccess::ReadOnlyDebug,
            _lifetime_retention: Some(retention),
            actor_task,
        };
        let state = runtime.live.read().state_kind;
        self.sessions.insert(session.id, runtime);
        Ok(ResumeSessionResponse {
            session,
            state,
            checkpoint: checkpoint.id,
            configuration: configuration.id(),
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
        if let Some(expected_epoch) = request.expected_epoch
            && runtime.session.epoch != expected_epoch
        {
            return Err(LifecycleApiError::EpochMismatch {
                session_id: request.session.id,
                expected: runtime.session.epoch,
                actual: expected_epoch,
            });
        }

        let runtime = self.sessions.remove(&request.session.id).ok_or(
            LifecycleApiError::CommandChannelClosed {
                session_id: request.session.id,
            },
        )?;
        if runtime.live.read().state_kind == LiveStateKind::Stopped {
            let _ = runtime.sender.send(actor_shutdown_command()).await;
            join_actor(runtime.actor_task).await?;
            return Ok(DestroySessionResponse {
                session: request.session,
                already_absent: false,
                stopped: true,
            });
        }
        let (reply, receiver) = CommandReply::channel();
        let shutdown = SessionCommand::Acknowledge {
            command: Box::new(SessionCommand::Stop),
            reply,
        };
        if runtime.sender.send(shutdown).await.is_err() {
            join_actor(runtime.actor_task).await?;
            return Err(LifecycleApiError::CommandChannelClosed {
                session_id: request.session.id,
            });
        }
        match receiver.await {
            Ok(Ok(())) => {
                // The first Stop terminalizes a running session and deliberately
                // leaves its actor observable. A second terminal Stop releases
                // that keepalive so Destroy can join the owner deterministically.
                let _ = runtime.sender.send(actor_shutdown_command()).await;
            }
            Ok(Err(error)) => {
                runtime.actor_task.abort();
                let _ = runtime.actor_task.await;
                return Err(LifecycleApiError::ActorFailed {
                    message: format!("session shutdown was rejected: {error}"),
                });
            }
            Err(_) => {
                join_actor(runtime.actor_task).await?;
                return Err(LifecycleApiError::CommandChannelClosed {
                    session_id: request.session.id,
                });
            }
        }
        join_actor(runtime.actor_task).await?;
        Ok(DestroySessionResponse {
            session: request.session,
            already_absent: false,
            stopped: true,
        })
    }

    /// Returns the deterministic reproduction context for a live session.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::SessionNotFound`] when the session is absent
    /// or [`LifecycleApiError::EpochMismatch`] when the supplied session epoch
    /// or expected epoch is stale.
    pub fn get_reproduction(
        &self,
        request: GetReproductionRequest,
    ) -> Result<GetReproductionResponse, LifecycleApiError> {
        let runtime = self.checked_runtime(request.session, request.expected_epoch)?;
        Ok(GetReproductionResponse {
            session: runtime.session,
            commands: runtime
                .reproduction_log
                .snapshot()
                .into_iter()
                .map(ReproductionCommandRecord::from)
                .collect(),
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
                let scenario = scenario.scenario_def();
                if scenario.seed() != request.seed {
                    return Err(LifecycleApiError::ScenarioSeedMismatch {
                        scenario_seed: scenario.seed(),
                        request_seed: request.seed,
                    });
                }
                Ok(scenario)
            }
        }
    }

    fn white_box_policies_for_source(
        &self,
        scenario_form: Option<&ScenarioDefForm>,
    ) -> BTreeMap<NodeId, WhiteBoxPolicy> {
        scenario_form
            .map(scenario_form_white_box_policies)
            .unwrap_or_default()
    }

    fn next_session_ref(&mut self, seed: Seed) -> SessionRef {
        let id = SessionId::new(self.next_session_id);
        self.next_session_id = self.next_session_id.saturating_add(1);
        let epoch = self.next_epoch;
        self.next_epoch = self.next_epoch.saturating_add(1);
        SessionRef::new(id, epoch, seed)
    }

    fn checked_runtime(
        &self,
        requested: SessionRef,
        expected_epoch: Option<u64>,
    ) -> Result<&SessionRuntime, LifecycleApiError> {
        let runtime = self
            .sessions
            .get(&requested.id)
            .ok_or(LifecycleApiError::SessionNotFound { session: requested })?;
        if runtime.session.epoch != requested.epoch {
            return Err(LifecycleApiError::EpochMismatch {
                session_id: requested.id,
                expected: runtime.session.epoch,
                actual: requested.epoch,
            });
        }
        if runtime.session != requested {
            return Err(LifecycleApiError::SessionNotFound { session: requested });
        }
        if let Some(expected_epoch) = expected_epoch
            && runtime.session.epoch != expected_epoch
        {
            return Err(LifecycleApiError::EpochMismatch {
                session_id: requested.id,
                expected: runtime.session.epoch,
                actual: expected_epoch,
            });
        }
        Ok(runtime)
    }

    fn checked_runtime_mut(
        &mut self,
        requested: SessionRef,
    ) -> Result<&mut SessionRuntime, LifecycleApiError> {
        let runtime = self
            .sessions
            .get_mut(&requested.id)
            .ok_or(LifecycleApiError::SessionNotFound { session: requested })?;
        if runtime.session.epoch != requested.epoch {
            return Err(LifecycleApiError::EpochMismatch {
                session_id: requested.id,
                expected: runtime.session.epoch,
                actual: requested.epoch,
            });
        }
        if runtime.session != requested {
            return Err(LifecycleApiError::SessionNotFound { session: requested });
        }
        Ok(runtime)
    }

    /// Acquires the session's exclusive debugger controller lease.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the session reference is stale, the
    /// role lacks control capability, or another client owns the lease.
    pub fn acquire_debug_controller(
        &mut self,
        session: SessionRef,
        client: DebugClientId,
        role: &DebugRole,
    ) -> Result<DebugControllerLease, LifecycleApiError> {
        Ok(self
            .checked_runtime_mut(session)?
            .debug_access
            .acquire_controller(client, role)?)
    }

    /// Releases the session's debugger controller lease.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the session reference or lease is
    /// stale.
    pub fn release_debug_controller(
        &mut self,
        session: SessionRef,
        lease: &DebugControllerLease,
    ) -> Result<(), LifecycleApiError> {
        self.checked_runtime_mut(session)?
            .debug_access
            .release_controller(lease)?;
        Ok(())
    }

    /// Authorizes an operation against the current controller lease.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the session reference or lease is
    /// stale or the supplied role lacks the requested capability.
    pub fn authorize_debug_controller_operation(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
        role: &DebugRole,
        capability: DebugCapability,
    ) -> Result<(), LifecycleApiError> {
        let runtime = self.checked_runtime(session, None)?;
        if runtime.access == SessionAccess::ReadOnlyDebug
            && matches!(
                capability,
                DebugCapability::Mutate | DebugCapability::Shell | DebugCapability::Admin
            )
        {
            return Err(LifecycleApiError::ReadOnlySession { session });
        }
        runtime
            .debug_access
            .authorize_controller_operation(lease, role, capability)?;
        Ok(())
    }

    /// Returns the attached node and stable operator-facing GDB endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the session reference is stale, its
    /// actor is unavailable, the query fails, or no debugger is attached.
    pub async fn debug_operator_target(
        &self,
        session: SessionRef,
    ) -> Result<(NodeId, DebugGdbEndpoint), LifecycleApiError> {
        let runtime = self.checked_runtime(session, None)?;
        let sender = runtime.sender.clone();
        let session_id = runtime.session.id;
        let (reply, receiver) = CommandReply::channel();
        sender
            .send(SessionCommand::Query {
                kind: QueryKind::DebugOperatorEndpoint,
                reply,
            })
            .await
            .map_err(|_| LifecycleApiError::CommandChannelClosed { session_id })?;
        let result = receiver
            .await
            .map_err(|error| LifecycleApiError::ActorFailed {
                message: format!("debug endpoint query reply closed: {error}"),
            })?
            .map_err(|error| LifecycleApiError::ActorFailed {
                message: error.to_string(),
            })?;
        match result {
            QueryResult::DebugOperatorEndpoint(Some(endpoint)) => Ok(endpoint),
            QueryResult::DebugOperatorEndpoint(None) => {
                Err(LifecycleApiError::DebugEndpointUnavailable)
            }
            _ => Err(LifecycleApiError::ActorFailed {
                message: String::from("debug endpoint query returned an unexpected result"),
            }),
        }
    }

    /// Attaches the session debugger to one node through a daemon-local gateway.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the session reference is stale, its
    /// actor mailbox closes, or the backend rejects debugger attachment.
    pub async fn attach_debugger(
        &self,
        session: SessionRef,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<DebugAttachReport, LifecycleApiError> {
        let runtime = self.checked_runtime(session, None)?;
        let sender = runtime.sender.clone();
        let session_id = runtime.session.id;
        let debug_genesis = runtime.debug_genesis.clone();
        let (reply, receiver) = CommandReply::channel();
        sender
            .send(SessionCommand::AttachGdb {
                node,
                listen,
                debug_genesis: debug_genesis.map(Box::new),
                reply,
            })
            .await
            .map_err(|_| LifecycleApiError::CommandChannelClosed { session_id })?;
        receiver
            .await
            .map_err(|error| LifecycleApiError::ActorFailed {
                message: format!("debug attach reply closed: {error}"),
            })?
            .map_err(|error| LifecycleApiError::ActorFailed {
                message: error.to_string(),
            })
    }

    /// Captures a guest-introspection actor dispatch handle.
    ///
    /// The returned handle owns the mailbox sender needed for later asynchronous
    /// exchange, so callers can release the lifecycle registry lock first.
    /// Authorization must be completed before capturing this handle.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the session reference is stale.
    pub fn guest_introspection_dispatch(
        &self,
        session: SessionRef,
    ) -> Result<GuestIntrospectionDispatch, LifecycleApiError> {
        let runtime = self.checked_runtime(session, None)?;
        if runtime.access == SessionAccess::ReadOnlyDebug {
            return Err(LifecycleApiError::ReadOnlySession { session });
        }
        Ok(GuestIntrospectionDispatch {
            sender: runtime.sender.clone(),
            session_id: runtime.session.id,
        })
    }

    /// Captures a debugger-reposition actor dispatch handle.
    ///
    /// The caller must authorize the controller lease before requesting this
    /// handle. The returned sender permits the registry lock to be released
    /// before restore, replay, and live-runtime replacement are awaited.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the session reference is stale.
    pub(crate) fn debug_reposition_dispatch(
        &self,
        session: SessionRef,
    ) -> Result<DebugRepositionDispatch, LifecycleApiError> {
        let runtime = self.checked_runtime(session, None)?;
        if runtime.access == SessionAccess::ReadOnlyDebug {
            return Err(LifecycleApiError::ReadOnlySession { session });
        }
        Ok(DebugRepositionDispatch {
            sender: runtime.sender.clone(),
            session_id: runtime.session.id,
        })
    }

    pub(crate) fn debug_relay_access(
        &self,
        session: SessionRef,
    ) -> Result<DebugRelayAccess, LifecycleApiError> {
        let runtime = self.checked_runtime(session, None)?;
        Ok(match runtime.access {
            SessionAccess::ReadWrite => DebugRelayAccess::ReadWrite,
            SessionAccess::ReadOnlyDebug => DebugRelayAccess::ReadOnly,
        })
    }

    /// Captures the session-owned serialization gate for debugger operations.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the session reference is absent or stale.
    pub(crate) fn debug_operation_gate(
        &self,
        session: SessionRef,
    ) -> Result<Arc<Mutex<()>>, LifecycleApiError> {
        Ok(Arc::clone(
            &self.checked_runtime(session, None)?.debug_operation_gate,
        ))
    }

    /// Builds an in-process streaming handle for a live session.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingApiError::SessionNotFound`] when the session id is not
    /// live, [`StreamingApiError::EpochMismatch`] when the supplied epoch is
    /// stale, or [`StreamingApiError::SessionMismatch`] when the full session
    /// reference does not match the live registry entry.
    pub fn streaming_session(
        &self,
        requested: SessionRef,
    ) -> Result<InProcessStreamingSession, StreamingApiError> {
        let Some(runtime) = self.sessions.get(&requested.id) else {
            return Err(StreamingApiError::SessionNotFound { session: requested });
        };
        if runtime.session.epoch != requested.epoch {
            return Err(StreamingApiError::EpochMismatch {
                expected: requested.epoch,
                actual: runtime.session.epoch,
            });
        }
        if runtime.session != requested {
            return Err(StreamingApiError::SessionMismatch {
                requested,
                actual: runtime.session,
            });
        }
        let streaming = InProcessStreamingSession::new(
            runtime.session,
            runtime.sender.clone(),
            Arc::clone(&runtime.live),
            runtime.event_log.clone(),
            runtime.reproduction_log.clone(),
            runtime.state_transitions.clone(),
        );
        Ok(match runtime.access {
            SessionAccess::ReadWrite => streaming,
            SessionAccess::ReadOnlyDebug => streaming.with_read_only_debug_policy(),
        })
    }

    /// Dispatches one streaming command against a lifecycle-owned session.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] if the streaming request is rejected, the
    /// actor mailbox closes, or an accepted `Stop` cannot be joined cleanly.
    pub async fn send_streaming_command(
        &mut self,
        request: SendRequest,
    ) -> Result<SendResponse, ControlClientError> {
        let session = request.session;
        let command_id = request.command_id;
        let command_kind = SessionCommandKind::from(&request.command);
        if self.checked_runtime(session, None)?.access == SessionAccess::ReadOnlyDebug
            && !matches!(
                command_kind,
                SessionCommandKind::Query | SessionCommandKind::Stop
            )
        {
            return Err(LifecycleApiError::ReadOnlySession { session }.into());
        }
        let streaming_session = self.streaming_session(session)?;
        let mut response = match streaming_session.send(request).await {
            Ok(response) => response,
            Err(error @ StreamingApiError::CommandChannelClosed { .. }) => {
                if let Some(runtime) = self.sessions.remove(&session.id)
                    && let Err(actor_error) = join_actor(runtime.actor_task).await
                {
                    return Err(actor_error.into());
                }
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };

        if command_kind == SessionCommandKind::Stop
            && response.result.status == CommandResultStatus::Accepted
        {
            if self.retain_stopped_sessions {
                let snapshot = streaming_session
                    .send(SendRequest::new(
                        session,
                        command_id,
                        SessionCommand::Query {
                            kind: QueryKind::Snapshot,
                            reply: CommandReply::discard(),
                        },
                    ))
                    .await?;
                response.query_result = match snapshot.query_result {
                    Some(result @ QueryResult::Snapshot(_)) => Some(result),
                    _ => {
                        return Err(StreamingApiError::CommandResponseMissing {
                            command: SessionCommandKind::Query,
                        }
                        .into());
                    }
                };
            } else {
                let report = self.cleanup_accepted_streaming_stop(session).await?;
                response.query_result =
                    Some(QueryResult::Snapshot(Box::new(report.final_snapshot)));
            }
        }

        Ok(response)
    }

    async fn cleanup_accepted_streaming_stop(
        &mut self,
        session: SessionRef,
    ) -> Result<SessionRunReport, ControlClientError> {
        let Some(runtime) = self.sessions.remove(&session.id) else {
            return Err(StreamingApiError::SessionNotFound { session }.into());
        };
        join_actor(runtime.actor_task).await.map_err(Into::into)
    }
}

fn validate_resume_replay_closure_binding(
    request: &ResumeSessionRequest,
) -> Result<(), LifecycleApiError> {
    let Some(closure) = request.replay_closure.as_ref() else {
        return Ok(());
    };
    let expected = resume_replay_closure_identity(
        &request.scenario,
        &request.schedule,
        &request.checkpoint,
        closure.schema_version(),
        closure.payload(),
    );
    if closure.identity() != expected {
        return Err(LifecycleApiError::ResumeReplayClosure {
            message: String::from(
                "campaign replay closure identity does not bind the exact resume source",
            ),
        });
    }
    Ok(())
}

fn validate_resume_observation_source_binding(
    request: &ResumeSessionRequest,
) -> Result<(), LifecycleApiError> {
    let source = &request.observation_source;
    let expected = resume_observation_source_identity(
        &request.scenario,
        &request.schedule,
        &request.checkpoint,
        source.schema_version(),
        source.proof(),
        source.evidence(),
    );
    if source.identity() != expected {
        return Err(LifecycleApiError::ResumeObservationSource {
            message: String::from(
                "portable observation source identity does not bind the exact resume source",
            ),
        });
    }
    Ok(())
}

fn validate_resume_replay_closure_presence(
    schedule: &Schedule,
    closure: Option<&ResumeReplayClosure>,
    has_validator: bool,
) -> Result<(), LifecycleApiError> {
    let requires_closure = has_validator
        || schedule
            .decisions()
            .iter()
            .any(|decision| matches!(decision, Decision::Selection(_)));
    let Some(closure) = closure else {
        return if requires_closure {
            Err(LifecycleApiError::ResumeReplayClosure {
                message: String::from(
                    "campaign-owned or typed-selection resume requires authenticated replay evidence",
                ),
            })
        } else {
            Ok(())
        };
    };
    if closure.payload_len() > RESUME_REPLAY_CLOSURE_MAX_BYTES {
        return Err(LifecycleApiError::ResumeReplayClosure {
            message: format!(
                "campaign replay closure has {} bytes, maximum is {RESUME_REPLAY_CLOSURE_MAX_BYTES}",
                closure.payload_len()
            ),
        });
    }
    if !has_validator {
        return Err(LifecycleApiError::ResumeReplayClosure {
            message: String::from(
                "this session owner cannot authenticate campaign replay evidence",
            ),
        });
    }
    Ok(())
}

/// In-process [`ControlClient`] implementation for unary lifecycle methods.
pub struct InProcessLifecycleClient<L, F> {
    control_plane: Arc<tokio::sync::Mutex<LifecycleControlPlane<L, F>>>,
    wire_model: ControlWireModel,
}

impl<L, F> Clone for InProcessLifecycleClient<L, F> {
    fn clone(&self) -> Self {
        Self {
            control_plane: Arc::clone(&self.control_plane),
            wire_model: self.wire_model,
        }
    }
}

impl<L, F> InProcessLifecycleClient<L, F> {
    /// Builds an in-process lifecycle client from a lifecycle control plane.
    #[must_use]
    pub fn new(control_plane: LifecycleControlPlane<L, F>) -> Self {
        Self::from_shared_control_plane(Arc::new(tokio::sync::Mutex::new(control_plane)))
    }

    /// Builds an in-process client over an already shared lifecycle control plane.
    #[must_use]
    pub fn from_shared_control_plane(
        control_plane: Arc<tokio::sync::Mutex<LifecycleControlPlane<L, F>>>,
    ) -> Self {
        Self {
            control_plane,
            wire_model: ControlWireModel::current(),
        }
    }
}

impl<L, F> InProcessLifecycleClient<L, F>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    /// Returns the number of live sessions in the wrapped control plane.
    pub async fn session_count(&self) -> usize {
        self.control_plane.lock().await.session_count()
    }

    /// Admits one owner-authenticated exact restore into this client's control plane.
    ///
    /// This is the in-process ownership boundary used by daemon services that
    /// already authenticated immutable storage. It shares the same session
    /// capacity and mutation enforcement as every HTTP lifecycle request.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when owner authentication disagrees with
    /// modeled identities, capacity is exhausted, or runtime construction fails.
    pub async fn admit_authenticated_read_only_session<E>(
        &self,
        source: ScenarioDefForm,
        configuration: Configuration,
        checkpoint: Checkpoint,
        seed: Seed,
        retention: SessionLifetimeRetention,
        build_loop: impl FnOnce() -> Result<L, E>,
    ) -> Result<ResumeSessionResponse, LifecycleApiError>
    where
        E: fmt::Display,
    {
        self.control_plane
            .lock()
            .await
            .admit_authenticated_read_only_session(
                source,
                configuration,
                checkpoint,
                seed,
                retention,
                build_loop,
            )
    }
}

impl<L, F> ControlClient for InProcessLifecycleClient<L, F>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
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

    fn resume_session(
        &self,
        request: ResumeSessionRequest,
    ) -> ControlClientFuture<'_, ResumeSessionResponse> {
        Box::pin(async move {
            let pending = self
                .control_plane
                .lock()
                .await
                .prepare_observation_resume(request)
                .map_err(ControlClientError::from)?;
            let deadline = pending.context().deadline();
            let cancellation = pending.context().cancellation().clone();
            let mut cancellation_guard = ResumeObservationCancellationGuard::new(cancellation);
            let preparation = tokio::task::spawn_blocking(move || pending.authenticate());
            let prepared = match tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                preparation,
            )
            .await
            {
                Ok(Ok(Ok(prepared))) => prepared,
                Ok(Ok(Err(error))) => return Err(ControlClientError::from(error)),
                Ok(Err(error)) => {
                    return Err(ControlClientError::from(
                        LifecycleApiError::ResumeObservationSource {
                            message: format!(
                                "portable observation preparation task failed: {error}"
                            ),
                        },
                    ));
                }
                Err(_) => {
                    cancellation_guard.cancel();
                    return Err(ControlClientError::from(
                        LifecycleApiError::ResumeObservationSource {
                            message: String::from(
                                "portable observation preparation deadline elapsed",
                            ),
                        },
                    ));
                }
            };
            let commit_deadline = prepared.context().deadline();
            let mut control_plane = match tokio::time::timeout_at(
                tokio::time::Instant::from_std(commit_deadline),
                self.control_plane.lock(),
            )
            .await
            {
                Ok(control_plane) => control_plane,
                Err(_) => {
                    cancellation_guard.cancel();
                    return Err(ControlClientError::from(
                        LifecycleApiError::ResumeObservationSource {
                            message: String::from(
                                "portable observation preparation deadline elapsed before publication",
                            ),
                        },
                    ));
                }
            };
            let response = control_plane
                .commit_observation_resume(prepared)
                .await
                .map_err(ControlClientError::from)?;
            cancellation_guard.disarm();
            Ok(response)
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

    fn get_reproduction(
        &self,
        request: GetReproductionRequest,
    ) -> ControlClientFuture<'_, GetReproductionResponse> {
        Box::pin(async move {
            self.control_plane
                .lock()
                .await
                .get_reproduction(request)
                .map_err(ControlClientError::from)
        })
    }

    fn control_attach(
        &self,
        request: AttachRequest,
    ) -> ControlClientFuture<'_, ClientControlStream> {
        Box::pin(async move {
            let control_plane = Arc::clone(&self.control_plane);
            let streaming_session = control_plane
                .lock()
                .await
                .streaming_session(request.session)?;
            let stream = streaming_session.control(request)?;
            let command_control_plane = Arc::clone(&control_plane);
            Ok(ClientControlStream::InProcessLifecycle(
                InProcessLifecycleControlStream::new(stream, move |request| {
                    let command_control_plane = Arc::clone(&command_control_plane);
                    async move {
                        command_control_plane
                            .lock()
                            .await
                            .send_streaming_command(request)
                            .await
                    }
                }),
            ))
        })
    }

    fn control_send(&self, request: SendRequest) -> ControlClientFuture<'_, SendResponse> {
        Box::pin(async move {
            self.control_plane
                .lock()
                .await
                .send_streaming_command(request)
                .await
        })
    }

    fn watch_attach(&self, request: AttachRequest) -> ControlClientFuture<'_, ClientWatchStream> {
        Box::pin(async move {
            let streaming_session = self
                .control_plane
                .lock()
                .await
                .streaming_session(request.session)?;
            Ok(ClientWatchStream::InProcess(
                streaming_session.watch(request)?,
            ))
        })
    }

    fn send_command(&self, request: SendRequest) -> ControlClientFuture<'_, SendResponse> {
        Box::pin(async move {
            self.control_plane
                .lock()
                .await
                .send_streaming_command(request)
                .await
        })
    }
}

struct SessionRuntime {
    session: SessionRef,
    sender: mpsc::Sender<SessionCommand>,
    live: Arc<LiveSnapshot>,
    event_log: ControlPlaneEventLog,
    reproduction_log: SessionReproductionLog,
    state_transitions: SessionStateTransitionBus,
    debug_access: DebugCoordinator,
    debug_operation_gate: Arc<Mutex<()>>,
    debug_genesis: Option<GenesisCheckpoint>,
    access: SessionAccess,
    // Dropping the runtime releases the owner-provided immutable source guard.
    _lifetime_retention: Option<SessionLifetimeRetention>,
    actor_task: JoinHandle<Result<SessionRunReport, SessionError>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionAccess {
    ReadWrite,
    ReadOnlyDebug,
}

impl SessionRuntime {
    fn summary(&self) -> SessionSummary {
        let status = self.live.read();
        SessionSummary {
            session: self.session,
            state: status.state_kind,
            outcome: status.outcome,
            terminal_savepoint: status.terminal_savepoint,
            frontier: status.virtual_time,
            event_log_len: status.event_log_len,
            quanta_stepped: status.quanta_stepped,
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
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Err(LifecycleApiError::StateDidNotAdvance {
        session_id: runtime.session.id,
        expected,
    })
}

async fn cleanup_runtime(runtime: SessionRuntime) {
    let _ = runtime.sender.send(actor_shutdown_command()).await;
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

fn actor_shutdown_command() -> SessionCommand {
    SessionCommand::Acknowledge {
        command: Box::new(SessionCommand::Stop),
        reply: CommandReply::discard(),
    }
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

fn validate_resume_checkpoint_closure(
    configuration: &Configuration,
    checkpoint: &Checkpoint,
) -> Result<(), LifecycleApiError> {
    let configuration_id = configuration.id();
    if checkpoint.id != configuration_id {
        return Err(LifecycleApiError::ResumeCheckpoint {
            message: format!(
                "checkpoint id {} did not match configuration {}",
                checkpoint.id.to_hex(),
                configuration_id.to_hex()
            ),
        });
    }
    if checkpoint.configuration != configuration_id {
        return Err(LifecycleApiError::ResumeCheckpoint {
            message: format!(
                "checkpoint configuration {} did not match reconstructed configuration {}",
                checkpoint.configuration.to_hex(),
                configuration_id.to_hex()
            ),
        });
    }
    if checkpoint.scenario_ref != configuration.def.id() {
        return Err(LifecycleApiError::ResumeCheckpoint {
            message: format!(
                "checkpoint scenario {} did not match supplied scenario {}",
                checkpoint.scenario_ref.to_hex(),
                configuration.def.id().to_hex()
            ),
        });
    }
    if checkpoint.kind != CheckpointKind::Fat {
        return Err(LifecycleApiError::ResumeCheckpoint {
            message: String::from("resume checkpoint must contain fat materialized state"),
        });
    }
    if configuration.is_genesis() {
        let baked = Checkpoint::from_recorded_configuration(
            configuration,
            None,
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .map_err(resume_checkpoint_error)?;
        // A restored graph has one checkpoint slot per configuration id, so
        // replacing its baked root with runtime-only material would erase the
        // true zero-time genesis.
        let requires_baked_genesis = checkpoint.execution_closure.is_none()
            && checkpoint.virtual_time == VirtualTime::default();
        if requires_baked_genesis && checkpoint != &baked {
            return Err(LifecycleApiError::ResumeCheckpoint {
                message: String::from(
                    "genesis checkpoint material did not match the baked genesis checkpoint",
                ),
            });
        }
    }

    let parent = if configuration.schedule.is_empty() {
        None
    } else {
        let prefix = configuration
            .schedule
            .prefix(configuration.schedule.len().saturating_sub(1))
            .map_err(|error| LifecycleApiError::ResumeCheckpoint {
                message: error.to_string(),
            })?;
        Some(Configuration {
            def: configuration.def.clone(),
            schedule: prefix,
        })
    };
    let expected = Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        checkpoint.virtual_time,
        checkpoint.node_icounts.clone(),
        checkpoint.kind,
        checkpoint.node_blobs.clone(),
    )
    .map_err(resume_checkpoint_error)?;
    if checkpoint.parent != expected.parent {
        return Err(LifecycleApiError::ResumeCheckpoint {
            message: format!(
                "checkpoint parent {:?} did not match expected {:?}",
                checkpoint.parent, expected.parent
            ),
        });
    }
    if checkpoint.schedule_delta != expected.schedule_delta {
        return Err(LifecycleApiError::ResumeCheckpoint {
            message: String::from("checkpoint schedule delta did not match supplied schedule"),
        });
    }
    Ok(())
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

fn debug_genesis_checkpoint(
    configuration: &Configuration,
    source: &ScenarioDefForm,
) -> Result<GenesisCheckpoint, LifecycleApiError> {
    let baked = bake(source.world()).map_err(engine_error)?;
    let checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        None,
        VirtualTime::default(),
        baked.checkpoint.node_icounts,
        CheckpointKind::Fat,
        baked.checkpoint.node_blobs,
    )
    .map_err(engine_error)?;
    Ok(GenesisCheckpoint { checkpoint })
}

fn engine_error(error: EngineError) -> LifecycleApiError {
    LifecycleApiError::GenesisGraph {
        message: error.to_string(),
    }
}

fn resume_checkpoint_error(error: EngineError) -> LifecycleApiError {
    LifecycleApiError::ResumeCheckpoint {
        message: error.to_string(),
    }
}

#[cfg(test)]
#[path = "lifecycle/tests.rs"]
mod tests;
