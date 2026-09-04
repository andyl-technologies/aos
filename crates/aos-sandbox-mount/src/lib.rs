//! Root-only fixed-function mount broker for AOS sandbox attachments.
//!
//! The crate orders hostile-input validation, assignment fencing, durable
//! intent, one-shot mount effects, and durable replay receipts. Kernel mount
//! operations are abstracted behind [`worker::MountWorker`], allowing the
//! privileged namespace helper to remain a separate executable and process.
//!
//! - [`broker`] implements crash-safe request ordering and replay;
//! - [`catalog`] resolves exact assignment-bound descriptor pins;
//! - [`plan`] defines the sealed, fixed helper handoff;
//! - [`spawn`] performs the sole audited `posix_spawn` descriptor mapping;
//! - [`helper`] executes one namespace-local syscall plan and exits;
//! - [`transport`] and [`peer`] authenticate bounded local requests;
//! - [`service`] owns the synchronous broker loop.
//! - [`state`] encodes the broker's bounded journal records;
//! - [`worker`] defines the closed effect interface.

pub mod broker;
pub mod catalog;
pub mod helper;
pub mod peer;
pub mod plan;
pub mod service;
pub mod spawn;
mod state;
pub mod transport;
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
