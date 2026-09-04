//! Root-only fixed-function mount broker for AOS sandbox attachments.
//!
//! The crate orders hostile-input validation, assignment fencing, durable
//! intent, one-shot mount effects, and durable replay receipts. Kernel mount
//! operations are abstracted behind [`worker::MountWorker`], allowing the
//! privileged namespace helper to remain a separate executable and process.
//!
//! - [`broker`] implements crash-safe request ordering and replay;
//! - [`state`] encodes the broker's bounded journal records;
//! - [`worker`] defines the closed effect interface.

pub mod broker;
mod state;
pub mod worker;

/// Errors returned by the fixed mount broker.
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    /// Hostile or unauthorized local input was rejected.
    #[error("mount protocol rejected request: {0}")]
    Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
    /// Durable journal state is corrupt, unavailable, or exhausted.
    #[error("mount durable state failure: {0}")]
    State(String),
    /// The request is stale or contradicts durable state.
    #[error("mount request fence conflict: {0}")]
    Fence(&'static str),
    /// The fixed worker could not apply or verify the effect.
    #[error("mount worker failure: {0}")]
    Worker(String),
}

impl From<aos_sandbox::journal::JournalError> for MountError {
    fn from(error: aos_sandbox::journal::JournalError) -> Self {
        Self::State(error.to_string())
    }
}

/// Convenience result type for mount broker operations.
pub type Result<T> = std::result::Result<T, MountError>;
