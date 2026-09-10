//! Discovery and lifecycle unary control-plane API.
//!
//! This module owns the RFC-0010 T-API-3 boundary. It provides typed unary
//! methods for `Hello`, `ListScenarios`, `CreateSession`, `ResumeSession`,
//! `ListSessions`, and `DestroySession`, backed by the same
//! `crucible-session` actor and lock-free live mirror used by the lower
//! session layer.

use std::collections::BTreeMap;
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
    SessionStateTransitionBus, StepMode,
};
use thiserror::Error;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::large_enum_variant)]
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
        /// Optional full scenario source transferred with the request.
        scenario_form: Option<ScenarioDefForm>,
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
            source: CreateSessionSource::Inline {
                scenario,
                scenario_form: None,
            },
            seed,
            start_paused: true,
        }
    }

    /// Builds a request from an inline scenario source form.
    #[must_use]
    pub fn inline_form(scenario_form: ScenarioDefForm, seed: Seed) -> Self {
        let scenario = scenario_form.scenario_def();
        Self {
            source: CreateSessionSource::Inline {
                scenario,
                scenario_form: Some(scenario_form),
            },
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

fn inline_scenario_form(request: &CreateSessionRequest) -> Option<&ScenarioDefForm> {
    let CreateSessionSource::Inline {
        scenario_form: Some(scenario_form),
        ..
    } = &request.source
    else {
        return None;
    };
    Some(scenario_form)
}

fn scenario_form_white_box_policies(
    scenario_form: &ScenarioDefForm,
) -> BTreeMap<NodeId, WhiteBoxPolicy> {
    scenario_form
        .world()
        .vm_nodes()
        .iter()
        .map(|node| (node.id.clone(), node.white_box))
        .collect()
}

/// Response returned by `CreateSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSessionResponse {
    /// Epoch-guarded session reference.
    pub session: SessionRef,
    /// State observed from the lock-free mirror after startup.
    pub state: LiveStateKind,
}

/// Request accepted by `ResumeSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeSessionRequest {
    /// Serialized scenario form owning the checkpoint.
    pub scenario: ScenarioDefForm,
    /// Recorded schedule for the checkpoint configuration.
    pub schedule: Schedule,
    /// Fat checkpoint that materializes the recorded configuration.
    pub checkpoint: Checkpoint,
    /// Seed recorded in the returned [`SessionRef`].
    pub seed: Seed,
    /// Authenticated campaign choice records required by a typed selection schedule.
    pub replay_closure: Option<ResumeReplayClosure>,
    /// Pending portable observation claim that the daemon must reproduce before resume.
    pub observation_source: Option<ResumeObservationSource>,
}

impl ResumeSessionRequest {
    /// Builds a request from a self-contained checkpoint closure.
    #[must_use]
    pub fn new(
        scenario: ScenarioDefForm,
        schedule: Schedule,
        checkpoint: Checkpoint,
        seed: Seed,
    ) -> Self {
        Self {
            scenario,
            schedule,
            checkpoint,
            seed,
            replay_closure: None,
            observation_source: None,
        }
    }

    /// Returns this request with a versioned campaign replay closure.
    #[must_use]
    pub fn with_replay_closure(mut self, replay_closure: ResumeReplayClosure) -> Self {
        self.replay_closure = Some(replay_closure);
        self
    }

    /// Returns this request with a content-bound portable observation source claim.
    #[must_use]
    pub fn with_observation_source(mut self, observation_source: ResumeObservationSource) -> Self {
        self.observation_source = Some(observation_source);
        self
    }
}

/// Versioned portable observation claim supplied to `ResumeSession`.
///
/// This envelope provides transport integrity only. A configured campaign
/// owner must replay the source from genesis and compare newly produced proof
/// and evidence before the lifecycle control plane can allocate a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeObservationSource {
    schema_version: u32,
    identity: ContentHash,
    proof: Vec<u8>,
    evidence: Vec<u8>,
}

impl ResumeObservationSource {
    /// Binds canonical proof and evidence bytes to one exact resume source.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::ResumeObservationSource`] when their
    /// combined length exceeds [`RESUME_OBSERVATION_SOURCE_MAX_BYTES`].
    pub fn new(
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
        checkpoint: &Checkpoint,
        schema_version: u32,
        proof: Vec<u8>,
        evidence: Vec<u8>,
    ) -> Result<Self, LifecycleApiError> {
        let total = proof.len().checked_add(evidence.len()).ok_or_else(|| {
            LifecycleApiError::ResumeObservationSource {
                message: String::from("portable observation source size overflowed"),
            }
        })?;
        if total > RESUME_OBSERVATION_SOURCE_MAX_BYTES {
            return Err(LifecycleApiError::ResumeObservationSource {
                message: format!(
                    "portable observation source has {total} bytes, maximum is {RESUME_OBSERVATION_SOURCE_MAX_BYTES}"
                ),
            });
        }
        let identity = resume_observation_source_identity(
            scenario,
            schedule,
            checkpoint,
            schema_version,
            &proof,
            &evidence,
        );
        Ok(Self {
            schema_version,
            identity,
            proof,
            evidence,
        })
    }

    /// Returns the transport-envelope schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the identity binding both payloads to the exact resume source.
    #[must_use]
    pub const fn identity(&self) -> ContentHash {
        self.identity
    }

    /// Returns the canonical campaign observation-stop proof.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Returns the canonical raw measurement replay evidence.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }

    /// Returns the combined bounded payload length.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.proof.len().saturating_add(self.evidence.len())
    }
}

fn resume_observation_source_identity(
    scenario: &ScenarioDefForm,
    schedule: &Schedule,
    checkpoint: &Checkpoint,
    schema_version: u32,
    proof: &[u8],
    evidence: &[u8],
) -> ContentHash {
    const DOMAIN: &[u8] = b"crucible.resume-observation-source.v1\0";

    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule: schedule.clone(),
    };
    let checkpoint_material = ContentHash::from_bytes(&checkpoint.to_compact_binary());
    let proof_len = u64::try_from(proof.len()).unwrap_or(u64::MAX);
    let evidence_len = u64::try_from(evidence.len()).unwrap_or(u64::MAX);
    let mut material = Vec::with_capacity(
        DOMAIN
            .len()
            .saturating_add(32 * 3)
            .saturating_add(4 + 8 + proof.len() + 8 + evidence.len()),
    );
    material.extend_from_slice(DOMAIN);
    material.extend_from_slice(&scenario.id().bytes);
    material.extend_from_slice(&configuration.id().bytes);
    material.extend_from_slice(&checkpoint_material.bytes);
    material.extend_from_slice(&schema_version.to_be_bytes());
    material.extend_from_slice(&proof_len.to_be_bytes());
    material.extend_from_slice(proof);
    material.extend_from_slice(&evidence_len.to_be_bytes());
    material.extend_from_slice(evidence);
    ContentHash::from_bytes(&material)
}

/// Versioned, content-bound campaign choice evidence supplied to `ResumeSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeReplayClosure {
    schema_version: u32,
    identity: ContentHash,
    payload: Vec<u8>,
}

impl ResumeReplayClosure {
    /// Binds a schema version and exact payload to one resume source.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::ResumeReplayClosure`] before hashing when
    /// `payload` exceeds [`RESUME_REPLAY_CLOSURE_MAX_BYTES`].
    pub fn new(
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
        checkpoint: &Checkpoint,
        schema_version: u32,
        payload: Vec<u8>,
    ) -> Result<Self, LifecycleApiError> {
        if payload.len() > RESUME_REPLAY_CLOSURE_MAX_BYTES {
            return Err(LifecycleApiError::ResumeReplayClosure {
                message: format!(
                    "campaign replay closure has {} bytes, maximum is {RESUME_REPLAY_CLOSURE_MAX_BYTES}",
                    payload.len()
                ),
            });
        }
        let identity = resume_replay_closure_identity(
            scenario,
            schedule,
            checkpoint,
            schema_version,
            &payload,
        );
        Ok(Self {
            schema_version,
            identity,
            payload,
        })
    }

    /// Returns the replay-closure schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the identity binding the resume source, schema, length, and payload.
    #[must_use]
    pub const fn identity(&self) -> ContentHash {
        self.identity
    }

    /// Returns the exact canonical replay-closure payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the bound payload length.
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

fn resume_replay_closure_identity(
    scenario: &ScenarioDefForm,
    schedule: &Schedule,
    checkpoint: &Checkpoint,
    schema_version: u32,
    payload: &[u8],
) -> ContentHash {
    const DOMAIN: &[u8] = b"crucible.resume-replay-closure.v1\0";

    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule: schedule.clone(),
    };
    let checkpoint_material = ContentHash::from_bytes(&checkpoint.to_compact_binary());
    let payload_len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    let mut material = Vec::with_capacity(
        DOMAIN
            .len()
            .saturating_add(32 * 3)
            .saturating_add(4 + 8)
            .saturating_add(payload.len()),
    );
    material.extend_from_slice(DOMAIN);
    material.extend_from_slice(&scenario.id().bytes);
    material.extend_from_slice(&configuration.id().bytes);
    material.extend_from_slice(&checkpoint_material.bytes);
    material.extend_from_slice(&schema_version.to_be_bytes());
    material.extend_from_slice(&payload_len.to_be_bytes());
    material.extend_from_slice(payload);
    ContentHash::from_bytes(&material)
}

/// Response returned by `ResumeSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeSessionResponse {
    /// Epoch-guarded session reference.
    pub session: SessionRef,
    /// State observed from the lock-free mirror after resume.
    pub state: LiveStateKind,
    /// Checkpoint accepted as the resume source.
    pub checkpoint: ContentHash,
    /// Configuration realized by the resumed session.
    pub configuration: ContentHash,
}

/// Summary returned by `ListSessions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    /// Epoch-guarded session reference.
    pub session: SessionRef,
    /// State read from the lock-free live mirror.
    pub state: LiveStateKind,
    /// Terminal outcome read from the live mirror, when the session stopped.
    pub outcome: Option<OutcomeKind>,
    /// Terminal savepoint checkpoint id materialized for the outcome.
    pub terminal_savepoint: Option<ContentHash>,
    /// Latest scheduler virtual-time frontier read from the live mirror.
    pub frontier: VirtualTime,
    /// Event-log length read from the lock-free live mirror.
    pub event_log_len: u64,
    /// Number of scheduler quanta completed by the session actor.
    pub quanta_stepped: u64,
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
    /// Optional epoch guard supplied by the client.
    pub expected_epoch: Option<u64>,
}

impl DestroySessionRequest {
    /// Builds a destroy request for `session`.
    #[must_use]
    pub const fn new(session: SessionRef) -> Self {
        Self {
            session,
            expected_epoch: None,
        }
    }

    /// Sets the optional expected epoch guard.
    #[must_use]
    pub const fn with_expected_epoch(mut self, expected_epoch: u64) -> Self {
        self.expected_epoch = Some(expected_epoch);
        self
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

/// Request accepted by `GetReproduction`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GetReproductionRequest {
    /// Session whose reproduction context should be read.
    pub session: SessionRef,
    /// Optional epoch guard supplied by the client.
    pub expected_epoch: Option<u64>,
}

impl GetReproductionRequest {
    /// Builds a reproduction request for `session`.
    #[must_use]
    pub const fn new(session: SessionRef) -> Self {
        Self {
            session,
            expected_epoch: None,
        }
    }

    /// Sets the optional expected epoch guard.
    #[must_use]
    pub const fn with_expected_epoch(mut self, expected_epoch: u64) -> Self {
        self.expected_epoch = Some(expected_epoch);
        self
    }
}

/// Response returned by `GetReproduction`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetReproductionResponse {
    /// Epoch-guarded session reference whose context was read.
    pub session: SessionRef,
    /// Recorded operator command stream in deterministic replay order.
    pub commands: Vec<ReproductionCommandRecord>,
}

/// Payload recorded for one command in the reproduction context.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReproductionCommandPayload {
    /// Payload-free command kind admitted at the boundary.
    pub command: SessionCommandKind,
    /// Stable reply-free command payload material admitted at the boundary.
    pub command_payload: String,
    /// Scheduler-control batch identifier, or zero when no scheduler payload was applied.
    pub scheduler_batch: u64,
    /// Stable scheduler-owned control payload material admitted by this command, when any.
    pub scheduler_control: Option<String>,
}

/// Result recorded for one command in the reproduction context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReproductionCommandResult {
    /// The command was accepted and is part of the deterministic replay stream.
    Accepted,
}

impl From<SessionControlResult> for ReproductionCommandResult {
    fn from(value: SessionControlResult) -> Self {
        match value {
            SessionControlResult::Accepted => Self::Accepted,
        }
    }
}

/// One recorded command in the API reproduction context.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReproductionCommandRecord {
    /// Monotone session-local reproduction sequence.
    pub sequence: u64,
    /// Command payload admitted at the boundary.
    pub payload: ReproductionCommandPayload,
    /// Virtual-time boundary where the command took effect.
    pub virtual_time: VirtualTime,
    /// Number of scheduler quanta completed before the command took effect.
    pub quanta: u64,
    /// Event-log sequence immediately before the command took effect.
    pub at_sequence: u64,
    /// Terminal result returned for this recorded command.
    pub result: ReproductionCommandResult,
    /// Observational ordering aid for same-boundary commands; not a replay input.
    pub observational_order: u64,
}

impl From<SessionControlLogEntry> for ReproductionCommandRecord {
    fn from(value: SessionControlLogEntry) -> Self {
        Self {
            sequence: value.sequence,
            payload: ReproductionCommandPayload {
                command: value.command,
                command_payload: session_control_payload_material(&value.payload),
                scheduler_batch: value.scheduler_batch,
                scheduler_control: value
                    .scheduler_control
                    .as_ref()
                    .map(control_operation_material),
            },
            virtual_time: value.frontier,
            quanta: value.quanta,
            at_sequence: value.event_log_sequence_before,
            result: value.result.into(),
            observational_order: value.sequence,
        }
    }
}

fn session_control_payload_material(payload: &SessionControlPayload) -> String {
    match payload {
        SessionControlPayload::CommandKind { command } => {
            format!("payload=command-kind\ncommand={command:?}\n")
        }
        SessionControlPayload::Fork { from } => {
            format!("payload=fork\nfrom={}\n", checkpoint_ref_material(*from))
        }
        SessionControlPayload::SetBreakpoint { spec } => format!(
            "payload=set-breakpoint\npredicate={}\ndisposition={}\npolicy={}\n",
            hex_string(&spec.predicate.canonical_summary()),
            breakpoint_disposition_material(&spec.disposition),
            breakpoint_policy_material(spec.policy),
        ),
        SessionControlPayload::RemoveBreakpoint { id } => {
            format!("payload=remove-breakpoint\nid={id}\n")
        }
        SessionControlPayload::CreateSavepoint { label } => {
            format!("payload=create-savepoint\nlabel={}\n", hex_string(label))
        }
    }
}

fn control_operation_material(control: &ControlOperationKind) -> String {
    match control {
        ControlOperationKind::Pause => String::from("control=pause\n"),
        ControlOperationKind::Resume => String::from("control=resume\n"),
        ControlOperationKind::Step => String::from("control=step\n"),
        ControlOperationKind::Snapshot => String::from("control=snapshot\n"),
        ControlOperationKind::Fork => String::from("control=fork\n"),
        ControlOperationKind::Query => String::from("control=query\n"),
    }
}

fn checkpoint_ref_material(from: CheckpointRef) -> String {
    match from {
        CheckpointRef::Current => String::from("current"),
        CheckpointRef::Checkpoint(hash) => format!("checkpoint:{}", hash.to_hex()),
    }
}

fn breakpoint_disposition_material(disposition: &BreakpointDisposition) -> String {
    match disposition {
        BreakpointDisposition::Suspend => String::from("suspend"),
        BreakpointDisposition::Trace => String::from("trace"),
        BreakpointDisposition::Action(action) => {
            format!("action:{}", hex_string(&action_material(action)))
        }
    }
}

fn action_material(action: &Action) -> String {
    match action {
        Action::ArmTimer { name, after } => format!(
            "action=arm-timer\nname={}\nafter-nanos={}\n",
            hex_string(&name.name),
            after.nanos,
        ),
        Action::CancelTimer { name } => {
            format!("action=cancel-timer\nname={}\n", hex_string(&name.name))
        }
        Action::StartNode { node } => {
            format!("action=start-node\nnode={}\n", hex_string(&node.name))
        }
        Action::StopNode { node } => {
            format!("action=stop-node\nnode={}\n", hex_string(&node.name))
        }
        Action::CreateSavepoint { label } => format!(
            "action=create-savepoint\nlabel={}\n",
            optional_hex_string(label.as_deref()),
        ),
        Action::Fork { label } => format!(
            "action=fork\nlabel={}\n",
            optional_hex_string(label.as_deref()),
        ),
        Action::Pass => String::from("action=pass\n"),
        Action::Fail { reason } => format!("action=fail\nreason={}\n", hex_string(reason)),
        Action::Log { level, message } => format!(
            "action=log\nlevel={}\nmessage={}\n",
            log_level_material(*level),
            hex_string(message),
        ),
        Action::Group(actions) => {
            let mut output = format!("action=group\ncount={}\n", actions.len());
            for (index, action) in actions.iter().enumerate() {
                output.push_str(&format!(
                    "member.{index}={}\n",
                    hex_string(&action_material(action)),
                ));
            }
            output
        }
    }
}

fn log_level_material(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

fn breakpoint_policy_material(policy: BreakpointPolicy) -> &'static str {
    match policy {
        BreakpointPolicy::OneShot => "one-shot",
        BreakpointPolicy::Repeatable => "repeatable",
    }
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
    /// An inline scenario source did not match its advertised identity.
    #[error("inline scenario payload identity mismatch: expected={expected:?} actual={actual:?}")]
    InlineScenarioIdentityMismatch {
        /// Advertised scenario definition handle.
        expected: Box<ScenarioDef>,
        /// Scenario definition handle reconstructed from the inline payload.
        actual: Box<ScenarioDef>,
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

/// Factory that realizes one concrete backend from a validated fat checkpoint.
pub type LifecycleResumeLoopFactory<L> = Box<
    dyn Fn(&ScenarioDef, &ScenarioDefForm, Seed, &Checkpoint) -> Result<L, LifecycleApiError>
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

/// Callback type used to derive node white-box policies for a scenario.
pub type WhiteBoxPolicyProvider =
    Box<dyn Fn(&ScenarioDef) -> BTreeMap<NodeId, WhiteBoxPolicy> + Send + Sync>;

/// In-process lifecycle control plane for unary API methods.
pub struct LifecycleControlPlane<L, F> {
    server_name: String,
    scenarios: BTreeMap<String, ScenarioCatalogEntry>,
    sessions: BTreeMap<SessionId, SessionRuntime>,
    next_session_id: u64,
    next_epoch: u64,
    loop_factory: F,
    resume_loop_factory: Option<LifecycleResumeLoopFactory<L>>,
    resume_replay_closure_validator: Option<ResumeReplayClosureValidator>,
    resume_observation_loop_factory: Option<ResumeObservationLoopFactory<L>>,
    resume_observation_preparation_timeout: Duration,
    resume_observation_preparation_capacity: usize,
    active_resume_observation_preparations: Arc<AtomicU64>,
    white_box_policy_provider: WhiteBoxPolicyProvider,
    mailbox_capacity: usize,
    startup_max_actor_yields: u64,
    max_sessions: Option<usize>,
    resume_via_thin_replay: bool,
    _loop: PhantomData<fn() -> L>,
}

mod constructors;

impl<L, F> LifecycleControlPlane<L, F>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>,
{
    /// Installs a trusted guest-marker white-box policy provider for new sessions.
    ///
    /// The lifecycle plane calls this provider inside the same process as the
    /// session actor. It must derive policies from authoritative scenario
    /// material, not from client-supplied breakpoint requests.
    #[must_use]
    pub fn with_white_box_policy_provider(
        mut self,
        provider: impl Fn(&ScenarioDef) -> BTreeMap<NodeId, WhiteBoxPolicy> + Send + Sync + 'static,
    ) -> Self {
        self.white_box_policy_provider = Box::new(provider);
        self
    }

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

    /// Sets the wall-clock deadline for portable observation preparation.
    #[must_use]
    pub const fn with_resume_observation_preparation_timeout(mut self, timeout: Duration) -> Self {
        self.resume_observation_preparation_timeout = timeout;
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

    /// Overrides the startup actor-yield budget.
    #[must_use]
    pub fn with_startup_max_actor_yields(mut self, startup_max_actor_yields: u64) -> Self {
        self.startup_max_actor_yields = startup_max_actor_yields;
        self
    }

    /// Overrides the maximum number of live sessions accepted by `CreateSession`.
    #[must_use]
    pub const fn with_max_sessions(mut self, max_sessions: usize) -> Self {
        self.max_sessions = Some(max_sessions);
        self
    }

    /// Realizes resumed sessions by deterministic replay from genesis.
    ///
    /// Production QEMU uses this mode when the persisted session has no exact
    /// snapshot. The control plane verifies the replayed configuration and
    /// virtual-time boundary before publishing the resumed session.
    #[must_use]
    pub const fn with_thin_replay_resume(mut self) -> Self {
        self.resume_via_thin_replay = true;
        self
    }

    /// Installs direct production realization for validated fat checkpoints.
    ///
    /// The factory must restore the complete concrete continuation named by
    /// `checkpoint`. Once installed, resume never falls back to genesis replay.
    #[must_use]
    pub fn with_fat_checkpoint_resume_factory(
        mut self,
        factory: impl Fn(
            &ScenarioDef,
            &ScenarioDefForm,
            Seed,
            &Checkpoint,
        ) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.resume_loop_factory = Some(Box::new(factory));
        self.resume_via_thin_replay = false;
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
        let white_box_policies = self.white_box_policies_for_source(scenario_form, &scenario);
        let engine = Engine::new(configuration, graph, loop_instance)
            .with_white_box_policies(white_box_policies);
        let (sender, receiver) = mpsc::channel(self.mailbox_capacity);
        let actor = SessionActor::new(engine, receiver).with_terminal_command_keepalive(true);
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

    /// Resumes a session actor from a self-contained checkpoint closure.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::SessionLimitReached`] when the live-session
    /// cap has been reached, [`LifecycleApiError::ScenarioSeedMismatch`] when
    /// the scenario seed differs from the request seed,
    /// [`LifecycleApiError::GenesisGraph`] when the genesis temporal graph
    /// cannot be built, or [`LifecycleApiError::ResumeCheckpoint`] when the
    /// supplied scenario, schedule, and checkpoint do not describe one loadable
    /// recorded configuration, or [`LifecycleApiError::ResumeReplayClosure`]
    /// when typed campaign replay evidence is missing or invalid. Portable
    /// observation sources must enter through [`ControlClient::resume_session`]
    /// so authentication can run off the async runtime and outside the
    /// lifecycle registry lock; direct calls reject them before invoking a
    /// backend factory.
    pub async fn resume_session(
        &mut self,
        request: ResumeSessionRequest,
    ) -> Result<ResumeSessionResponse, LifecycleApiError> {
        self.validate_resume_capacity_and_seed(&request)?;
        if self.resume_via_thin_replay && request.observation_source.is_none() {
            validate_resume_replay_closure_presence(
                &request.schedule,
                request.replay_closure.as_ref(),
                false,
            )?;
            return self.resume_session_via_thin_replay(request).await;
        }

        if request.observation_source.is_some() {
            return Err(LifecycleApiError::ResumeObservationSource {
                message: String::from(
                    "portable observation resume requires an async ControlClient transport",
                ),
            });
        }

        let configuration = self.validate_direct_resume_request(&request)?;
        let scenario = configuration.def.clone();
        let resumed_loop = match &self.resume_loop_factory {
            Some(factory) => factory(
                &scenario,
                &request.scenario,
                request.seed,
                &request.checkpoint,
            )?,
            None => (self.loop_factory)(&scenario, Some(&request.scenario), request.seed)?,
        };
        self.finish_direct_resume(request, configuration, resumed_loop)
            .await
    }

    pub(crate) fn prepare_observation_resume(
        &self,
        request: ResumeSessionRequest,
    ) -> Result<PendingObservationResume<L>, LifecycleApiError> {
        self.validate_resume_capacity_and_seed(&request)?;
        if request.observation_source.is_none() {
            return Err(LifecycleApiError::ResumeObservationSource {
                message: String::from("portable observation source envelope is missing"),
            });
        }
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
        validate_resume_checkpoint_closure(
            &configuration,
            &request.checkpoint,
            ResumeCheckpointValidation::DirectLoad,
        )?;
        validate_resume_replay_closure_presence(
            &request.schedule,
            request.replay_closure.as_ref(),
            self.resume_replay_closure_validator.is_some()
                || (request.observation_source.is_some()
                    && self.resume_observation_loop_factory.is_some()),
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

        let white_box_policies =
            self.white_box_policies_for_source(Some(&request.scenario), &scenario);
        let engine = Engine::from_recorded_checkpoint(graph, resumed_loop, request.checkpoint.id)
            .map_err(|error| LifecycleApiError::ResumeCheckpoint {
                message: error.to_string(),
            })?
            .with_white_box_policies(white_box_policies);

        let checkpoint = request.checkpoint.id;
        let configuration = configuration.id();
        let (sender, receiver) = mpsc::channel(self.mailbox_capacity);
        let actor = SessionActor::new(engine, receiver).with_terminal_command_keepalive(true);
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
            Ok(Ok(())) => {}
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
            CreateSessionSource::Inline {
                scenario,
                scenario_form,
            } => {
                if let Some(scenario_form) = scenario_form {
                    let source_scenario = scenario_form.scenario_def();
                    if source_scenario != *scenario {
                        return Err(LifecycleApiError::InlineScenarioIdentityMismatch {
                            expected: Box::new(scenario.clone()),
                            actual: Box::new(source_scenario),
                        });
                    }
                }
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

    fn white_box_policies_for_source(
        &self,
        scenario_form: Option<&ScenarioDefForm>,
        scenario: &ScenarioDef,
    ) -> BTreeMap<NodeId, WhiteBoxPolicy> {
        let mut policies = scenario_form
            .map(scenario_form_white_box_policies)
            .unwrap_or_default();
        policies.extend((self.white_box_policy_provider)(scenario));
        policies
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

    /// Registers an authenticated read-only debugger observer for a session.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the session reference is stale or the
    /// supplied role lacks [`DebugCapability::Observe`].
    pub fn add_debug_observer(
        &mut self,
        session: SessionRef,
        client: DebugClientId,
        role: &DebugRole,
    ) -> Result<(), LifecycleApiError> {
        self.checked_runtime_mut(session)?
            .debug_access
            .add_observer(client, role)?;
        Ok(())
    }

    /// Removes a debugger observer connection from a session.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the session reference is stale.
    pub fn remove_debug_observer(
        &mut self,
        session: SessionRef,
        client: &DebugClientId,
    ) -> Result<(), LifecycleApiError> {
        self.checked_runtime_mut(session)?
            .debug_access
            .remove_observer(client);
        Ok(())
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
        self.checked_runtime(session, None)?
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
    pub fn debug_reposition_dispatch(
        &self,
        session: SessionRef,
    ) -> Result<DebugRepositionDispatch, LifecycleApiError> {
        let runtime = self.checked_runtime(session, None)?;
        Ok(DebugRepositionDispatch {
            sender: runtime.sender.clone(),
            session_id: runtime.session.id,
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
        Ok(InProcessStreamingSession::new(
            runtime.session,
            runtime.sender.clone(),
            Arc::clone(&runtime.live),
            runtime.event_log.clone(),
            runtime.reproduction_log.clone(),
            runtime.state_transitions.clone(),
        ))
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
        let command_kind = SessionCommandKind::from(&request.command);
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
            let report = self.cleanup_accepted_streaming_stop(session).await?;
            response.query_result = Some(QueryResult::Snapshot(Box::new(report.final_snapshot)));
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
        let _ = runtime.sender.send(actor_shutdown_command()).await;
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
    let Some(source) = request.observation_source.as_ref() else {
        return Ok(());
    };
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
    let requires_closure = schedule
        .decisions()
        .iter()
        .any(|decision| matches!(decision, Decision::Selection(_)));
    let Some(closure) = closure else {
        return if requires_closure {
            Err(LifecycleApiError::ResumeReplayClosure {
                message: String::from(
                    "typed selection resume requires authenticated campaign replay evidence",
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
            if request.observation_source.is_none() {
                return self
                    .control_plane
                    .lock()
                    .await
                    .resume_session(request)
                    .await
                    .map_err(ControlClientError::from);
            }
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
    actor_task: JoinHandle<Result<SessionRunReport, SessionError>>,
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
    validation: ResumeCheckpointValidation,
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
    if validation == ResumeCheckpointValidation::DirectLoad
        && checkpoint.kind != CheckpointKind::Fat
    {
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
        // A direct-load graph has one checkpoint slot per configuration id, so
        // replacing its baked root with a later runtime-only snapshot would
        // erase the true zero-time genesis. Thin replay never registers the
        // supplied material: it may use a nonzero frontier to reconstruct a
        // deterministic runtime whose causal schedule is still empty.
        let requires_baked_genesis = checkpoint.execution_closure.is_none()
            && (validation == ResumeCheckpointValidation::DirectLoad
                || checkpoint.virtual_time == VirtualTime::default());
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResumeCheckpointValidation {
    DirectLoad,
    ThinReplay,
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
mod thin_replay;
