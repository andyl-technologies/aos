//! Thin API-to-session mapping contract.
//!
//! RFC-0010 T-API-2 requires the programmatic API to add no control semantics of
//! its own. This module makes that boundary explicit: every declared API method
//! is classified as a server read, lock-free mirror read, control-log read, or a
//! one-command dispatch into the `crucible-session` command set.

use crucible_session::{LiveQueryKind, SessionCommandKind};
use thiserror::Error;

/// Programmatic service method exposed by the control API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ApiMethod {
    /// Version and capability discovery.
    Hello,
    /// Scenario-registry discovery.
    ListScenarios,
    /// Session actor creation from a scenario.
    CreateSession,
    /// Live-session registry observation.
    ListSessions,
    /// Epoch-guarded session teardown.
    DestroySession,
    /// Reproduction-log retrieval.
    GetReproduction,
    /// Bidirectional attach and command stream.
    Control,
    /// Read-only attach and event stream.
    Watch,
    /// Unary command dispatch against an attached session.
    Send,
}

impl ApiMethod {
    /// Closed set of control API service methods.
    pub const ALL: [Self; 9] = [
        Self::Hello,
        Self::ListScenarios,
        Self::CreateSession,
        Self::ListSessions,
        Self::DestroySession,
        Self::GetReproduction,
        Self::Control,
        Self::Watch,
        Self::Send,
    ];

    /// Returns the canonical service method name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hello => "Hello",
            Self::ListScenarios => "ListScenarios",
            Self::CreateSession => "CreateSession",
            Self::ListSessions => "ListSessions",
            Self::DestroySession => "DestroySession",
            Self::GetReproduction => "GetReproduction",
            Self::Control => "Control",
            Self::Watch => "Watch",
            Self::Send => "Send",
        }
    }
}

/// Request-shape class accepted by the API boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ApiRequestShape {
    /// Typed programmatic client request, independent of browser transports.
    TypedProgrammatic,
}

impl ApiRequestShape {
    /// Returns whether this shape exists only to accommodate browser transports.
    #[must_use]
    pub const fn is_browser_shaped(self) -> bool {
        match self {
            Self::TypedProgrammatic => false,
        }
    }
}

/// Cardinality for API envelopes that carry session commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommandDispatchCardinality {
    /// Each request envelope dispatches exactly one session command.
    OneSessionCommandPerEnvelope,
}

/// Thin dispatch class for one API method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ApiDispatch {
    /// Read server-owned data without touching any session actor.
    ServerObservation,
    /// Create a new session actor and issue the startup command.
    SessionCreate {
        /// First command sent to the newly-created actor.
        startup: SessionCommandKind,
    },
    /// Read the lock-free mirror of one or more live sessions.
    LiveMirrorRead {
        /// Mirror query used by the API method.
        query: LiveQueryKind,
    },
    /// Dispatch one concrete command to an existing session actor.
    SessionCommand {
        /// Session command kind dispatched by the method.
        command: SessionCommandKind,
    },
    /// Read the actor-owned reproduction command log.
    ReproductionLogRead,
    /// Attach to a session and process one command per incoming stream envelope.
    ControlStream {
        /// Command dispatch cardinality per stream envelope.
        cardinality: CommandDispatchCardinality,
    },
    /// Attach read-only and observe the mirror snapshot plus event-log tail.
    WatchStream {
        /// Mirror query used for the attach snapshot.
        attach_query: LiveQueryKind,
    },
    /// Dispatch one command from a unary request envelope.
    SendEnvelope {
        /// Command dispatch cardinality for the unary envelope.
        cardinality: CommandDispatchCardinality,
    },
}

impl ApiDispatch {
    /// Returns whether this dispatch adds no control semantics beyond session.
    #[must_use]
    pub const fn is_thin_wrapper(self) -> bool {
        match self {
            Self::ServerObservation | Self::ReproductionLogRead => true,
            Self::SessionCreate { startup } => matches!(startup, SessionCommandKind::Start),
            Self::LiveMirrorRead { .. } | Self::WatchStream { .. } => true,
            Self::SessionCommand { command } => matches!(command, SessionCommandKind::Stop),
            Self::ControlStream { cardinality } | Self::SendEnvelope { cardinality } => {
                matches!(
                    cardinality,
                    CommandDispatchCardinality::OneSessionCommandPerEnvelope
                )
            }
        }
    }

    /// Returns the fixed session command kind, if this method has one.
    #[must_use]
    pub const fn fixed_session_command(self) -> Option<SessionCommandKind> {
        match self {
            Self::SessionCreate { startup } => Some(startup),
            Self::SessionCommand { command } => Some(command),
            Self::ServerObservation
            | Self::LiveMirrorRead { .. }
            | Self::ReproductionLogRead
            | Self::ControlStream { .. }
            | Self::WatchStream { .. }
            | Self::SendEnvelope { .. } => None,
        }
    }

    /// Returns the lock-free mirror query, if this method is mirror-backed.
    #[must_use]
    pub const fn mirror_query(self) -> Option<LiveQueryKind> {
        match self {
            Self::LiveMirrorRead { query } => Some(query),
            Self::WatchStream { attach_query } => Some(attach_query),
            Self::ServerObservation
            | Self::SessionCreate { .. }
            | Self::SessionCommand { .. }
            | Self::ReproductionLogRead
            | Self::ControlStream { .. }
            | Self::SendEnvelope { .. } => None,
        }
    }

    /// Returns the command-envelope cardinality, if this method carries commands.
    #[must_use]
    pub const fn command_cardinality(self) -> Option<CommandDispatchCardinality> {
        match self {
            Self::ControlStream { cardinality } | Self::SendEnvelope { cardinality } => {
                Some(cardinality)
            }
            Self::ServerObservation
            | Self::SessionCreate { .. }
            | Self::LiveMirrorRead { .. }
            | Self::SessionCommand { .. }
            | Self::ReproductionLogRead
            | Self::WatchStream { .. } => None,
        }
    }
}

/// Mapping from an API method to its thin session operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ApiMethodMapping {
    /// API method being classified.
    pub method: ApiMethod,
    /// Session-backed dispatch route for the method.
    pub dispatch: ApiDispatch,
    /// Request shape accepted by the method.
    pub request_shape: ApiRequestShape,
}

/// Mapping from an API command name to the existing session command set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ApiCommandMapping {
    /// Programmatic command name accepted by the API.
    pub command_name: &'static str,
    /// Existing session command kind reached by that name.
    pub command_kind: SessionCommandKind,
}

/// Thin method mapping table for the current service surface.
pub const API_METHOD_MAPPINGS: [ApiMethodMapping; 9] = [
    ApiMethodMapping {
        method: ApiMethod::Hello,
        dispatch: ApiDispatch::ServerObservation,
        request_shape: ApiRequestShape::TypedProgrammatic,
    },
    ApiMethodMapping {
        method: ApiMethod::ListScenarios,
        dispatch: ApiDispatch::ServerObservation,
        request_shape: ApiRequestShape::TypedProgrammatic,
    },
    ApiMethodMapping {
        method: ApiMethod::CreateSession,
        dispatch: ApiDispatch::SessionCreate {
            startup: SessionCommandKind::Start,
        },
        request_shape: ApiRequestShape::TypedProgrammatic,
    },
    ApiMethodMapping {
        method: ApiMethod::ListSessions,
        dispatch: ApiDispatch::LiveMirrorRead {
            query: LiveQueryKind::Status,
        },
        request_shape: ApiRequestShape::TypedProgrammatic,
    },
    ApiMethodMapping {
        method: ApiMethod::DestroySession,
        dispatch: ApiDispatch::SessionCommand {
            command: SessionCommandKind::Stop,
        },
        request_shape: ApiRequestShape::TypedProgrammatic,
    },
    ApiMethodMapping {
        method: ApiMethod::GetReproduction,
        dispatch: ApiDispatch::ReproductionLogRead,
        request_shape: ApiRequestShape::TypedProgrammatic,
    },
    ApiMethodMapping {
        method: ApiMethod::Control,
        dispatch: ApiDispatch::ControlStream {
            cardinality: CommandDispatchCardinality::OneSessionCommandPerEnvelope,
        },
        request_shape: ApiRequestShape::TypedProgrammatic,
    },
    ApiMethodMapping {
        method: ApiMethod::Watch,
        dispatch: ApiDispatch::WatchStream {
            attach_query: LiveQueryKind::Status,
        },
        request_shape: ApiRequestShape::TypedProgrammatic,
    },
    ApiMethodMapping {
        method: ApiMethod::Send,
        dispatch: ApiDispatch::SendEnvelope {
            cardinality: CommandDispatchCardinality::OneSessionCommandPerEnvelope,
        },
        request_shape: ApiRequestShape::TypedProgrammatic,
    },
];

/// API command mapping table covering the complete session command vocabulary.
pub const API_COMMAND_MAPPINGS: [ApiCommandMapping; 22] = [
    ApiCommandMapping {
        command_name: "start",
        command_kind: SessionCommandKind::Start,
    },
    ApiCommandMapping {
        command_name: "continue",
        command_kind: SessionCommandKind::Continue,
    },
    ApiCommandMapping {
        command_name: "pause",
        command_kind: SessionCommandKind::Pause,
    },
    ApiCommandMapping {
        command_name: "step-quantum",
        command_kind: SessionCommandKind::StepQuantum,
    },
    ApiCommandMapping {
        command_name: "step-event",
        command_kind: SessionCommandKind::StepEvent,
    },
    ApiCommandMapping {
        command_name: "step-assertion",
        command_kind: SessionCommandKind::StepAssertion,
    },
    ApiCommandMapping {
        command_name: "step-timer",
        command_kind: SessionCommandKind::StepTimer,
    },
    ApiCommandMapping {
        command_name: "step-duration",
        command_kind: SessionCommandKind::StepDuration,
    },
    ApiCommandMapping {
        command_name: "stop",
        command_kind: SessionCommandKind::Stop,
    },
    ApiCommandMapping {
        command_name: "exhaust-budget",
        command_kind: SessionCommandKind::ExhaustBudget,
    },
    ApiCommandMapping {
        command_name: "set-breakpoint",
        command_kind: SessionCommandKind::SetBreakpoint,
    },
    ApiCommandMapping {
        command_name: "remove-breakpoint",
        command_kind: SessionCommandKind::RemoveBreakpoint,
    },
    ApiCommandMapping {
        command_name: "create-savepoint",
        command_kind: SessionCommandKind::CreateSavepoint,
    },
    ApiCommandMapping {
        command_name: "fork",
        command_kind: SessionCommandKind::Fork,
    },
    ApiCommandMapping {
        command_name: "query",
        command_kind: SessionCommandKind::Query,
    },
    ApiCommandMapping {
        command_name: "snapshot",
        command_kind: SessionCommandKind::Snapshot,
    },
    ApiCommandMapping {
        command_name: "attach-gdb",
        command_kind: SessionCommandKind::AttachGdb,
    },
    ApiCommandMapping {
        command_name: "debug-goto",
        command_kind: SessionCommandKind::DebugGoto,
    },
    ApiCommandMapping {
        command_name: "debug-reverse-step",
        command_kind: SessionCommandKind::DebugReverseStep,
    },
    ApiCommandMapping {
        command_name: "debug-reverse-continue",
        command_kind: SessionCommandKind::DebugReverseContinue,
    },
    ApiCommandMapping {
        command_name: "debug-fork-non-canonical",
        command_kind: SessionCommandKind::DebugForkNonCanonical,
    },
    ApiCommandMapping {
        command_name: "guest-introspection",
        command_kind: SessionCommandKind::GuestIntrospection,
    },
];

/// Error returned when the API mapping violates the thin-wrapper contract.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ApiMappingError {
    /// A service method has no mapping table entry.
    #[error("API method {method:?} is missing from the mapping table")]
    MissingMethod {
        /// Missing method.
        method: ApiMethod,
    },
    /// A service method appears more than once.
    #[error("API method {method:?} appears more than once in the mapping table")]
    DuplicateMethod {
        /// Duplicated method.
        method: ApiMethod,
    },
    /// A method uses a browser-shaped request boundary.
    #[error("API method {method:?} uses browser-shaped request {request_shape:?}")]
    BrowserShapedRequest {
        /// Method with the invalid request shape.
        method: ApiMethod,
        /// Invalid request shape.
        request_shape: ApiRequestShape,
    },
    /// A method dispatch route adds control semantics outside the session set.
    #[error("API method {method:?} is not a thin session wrapper")]
    NonThinMethod {
        /// Method with the invalid dispatch route.
        method: ApiMethod,
    },
    /// A session command kind has no API command mapping.
    #[error("session command {command:?} is missing from the API command mapping")]
    MissingCommand {
        /// Missing session command kind.
        command: SessionCommandKind,
    },
    /// A session command kind appears more than once.
    #[error("session command {command:?} appears more than once in the API command mapping")]
    DuplicateCommand {
        /// Duplicated session command kind.
        command: SessionCommandKind,
    },
}

/// Returns the mapping for one API method.
#[must_use]
pub fn method_mapping(method: ApiMethod) -> Option<&'static ApiMethodMapping> {
    API_METHOD_MAPPINGS
        .iter()
        .find(|mapping| mapping.method == method)
}

/// Returns the session command kind for a programmatic API command name.
#[must_use]
pub fn session_command_for_api_command(command_name: &str) -> Option<SessionCommandKind> {
    API_COMMAND_MAPPINGS
        .iter()
        .find(|mapping| mapping.command_name == command_name)
        .map(|mapping| mapping.command_kind)
}

/// Returns the API command mapping for one session command kind.
#[must_use]
pub fn api_command_for_session_command(
    command: SessionCommandKind,
) -> Option<&'static ApiCommandMapping> {
    API_COMMAND_MAPPINGS
        .iter()
        .find(|mapping| mapping.command_kind == command)
}

/// Validates the API mapping against the T-API-2 thin-wrapper contract.
///
/// # Errors
///
/// Returns [`ApiMappingError`] when a method is missing, duplicated, browser
/// shaped, or not session-thin, or when the API command table does not cover
/// every [`SessionCommandKind`] exactly once.
pub fn validate_thin_api_mapping() -> Result<(), ApiMappingError> {
    for method in ApiMethod::ALL {
        let count = API_METHOD_MAPPINGS
            .iter()
            .filter(|mapping| mapping.method == method)
            .count();
        if count == 0 {
            return Err(ApiMappingError::MissingMethod { method });
        }
        if count > 1 {
            return Err(ApiMappingError::DuplicateMethod { method });
        }
    }

    for mapping in API_METHOD_MAPPINGS {
        if mapping.request_shape.is_browser_shaped() {
            return Err(ApiMappingError::BrowserShapedRequest {
                method: mapping.method,
                request_shape: mapping.request_shape,
            });
        }
        if !mapping.dispatch.is_thin_wrapper() {
            return Err(ApiMappingError::NonThinMethod {
                method: mapping.method,
            });
        }
    }

    for command in SessionCommandKind::ALL {
        let count = API_COMMAND_MAPPINGS
            .iter()
            .filter(|mapping| mapping.command_kind == command)
            .count();
        if count == 0 {
            return Err(ApiMappingError::MissingCommand { command });
        }
        if count > 1 {
            return Err(ApiMappingError::DuplicateCommand { command });
        }
    }

    Ok(())
}
