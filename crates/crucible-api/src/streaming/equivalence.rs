//! Shared command-capability model for streaming control transports.

use super::*;

/// One command kind advertised by a streaming command path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamingCommandCapability {
    /// Programmatic command name accepted by the API.
    pub command_name: &'static str,
    /// Existing session command kind reached by that name.
    pub command_kind: SessionCommandKind,
}
/// Command capabilities advertised by one streaming command path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamingCapabilitySet {
    /// Command kinds accepted by the path.
    pub commands: Vec<StreamingCommandCapability>,
    /// Whether `Attached` carries a log-derived snapshot summary.
    pub snapshot_on_attach: bool,
}

impl StreamingCapabilitySet {
    /// Builds the current command capability set from the thin mapping table.
    #[must_use]
    pub fn current() -> Self {
        Self {
            commands: API_COMMAND_MAPPINGS
                .iter()
                .map(|mapping| StreamingCommandCapability {
                    command_name: mapping.command_name,
                    command_kind: mapping.command_kind,
                })
                .collect(),
            snapshot_on_attach: true,
        }
    }

    /// Returns whether `command` is advertised by this capability set.
    #[must_use]
    pub fn contains(&self, command: SessionCommandKind) -> bool {
        self.commands
            .iter()
            .any(|capability| capability.command_kind == command)
    }
}

/// Successful evidence that `Control` and `Watch`+`Send` expose the same command set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamingEquivalenceReport {
    /// Number of command kinds exposed by each command path.
    pub command_count: usize,
    /// Capabilities advertised by the bidirectional `Control` stream.
    pub control_capabilities: StreamingCapabilitySet,
    /// Capabilities advertised by unary `Send`.
    pub send_capabilities: StreamingCapabilitySet,
}

/// Error returned when `Control` and `Watch`+`Send` are not equivalent.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StreamingEquivalenceError {
    /// A required API method is not present in the thin mapping table.
    #[error("streaming method {method:?} is missing from the API mapping table")]
    MissingMethod {
        /// Missing method.
        method: ApiMethod,
    },
    /// A required API method has the wrong dispatch class.
    #[error("streaming method {method:?} has an unexpected dispatch mapping")]
    UnexpectedDispatch {
        /// Misconfigured method.
        method: ApiMethod,
    },
    /// A session command kind is not advertised by both command paths.
    #[error("streaming command capability {command:?} is missing")]
    MissingCommandCapability {
        /// Missing command kind.
        command: SessionCommandKind,
    },
    /// The bidirectional and unary command capability sets differ.
    #[error("Control and Send command capability sets differ")]
    CapabilityMismatch,
}
