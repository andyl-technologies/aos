//! Lifecycle request, response, bounded payload, and error contracts.
//!
//! The RPC wire format is owned by [`crate::rpc_abi`]; these values are shared
//! by remote clients and server dispatch without owning sessions or VM processes.

use std::collections::BTreeMap;
use std::time::Duration;

use crucible_engine::{
    Action, Checkpoint, Configuration, ContentHash, ControlOperationKind, LogLevel, NodeId,
    ScenarioDef, ScenarioDefForm, Schedule, SchedulerOperationalFailureClass, Seed, VirtualTime,
    WhiteBoxPolicy,
};
use crucible_session::{
    BreakpointDisposition, BreakpointPolicy, CheckpointRef, DebugCoordinatorError, LiveStateKind,
    OutcomeKind, SessionCommandKind, SessionControlLogEntry, SessionControlPayload,
    SessionControlResult,
};
use thiserror::Error;

use crate::rpc_abi::RpcAbiError;

mod hex;
use hex::{hex_string, optional_hex_string};
mod resource_limit;
pub use resource_limit::LifecycleResourceLimit;
mod session_contract;
pub use session_contract::*;

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

/// Failure reported while removing durable session-retention state.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{message}")]
pub struct SessionRetentionUpdateError {
    message: String,
}

impl SessionRetentionUpdateError {
    /// Creates a retention update failure with stable owner-supplied detail.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the stable retention update diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

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
    /// Durable session-retention state could not be updated.
    #[error("session retention update failed: {source}")]
    SessionRetention {
        /// Owner-supplied retention update failure.
        #[source]
        source: SessionRetentionUpdateError,
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
