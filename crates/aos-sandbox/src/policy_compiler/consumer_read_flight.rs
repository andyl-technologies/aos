//! Retains one nonauthorizing, Policy-state-first original Root connection.
//!
//! The actual Controller resource, selected process inputs and existing Policy
//! writer stay held. STATE transmits Policy metadata, not backing content or
//! permission. CONTINUE is unconditionally denied before any per-flight Root
//! writer, signer or capacity acquisition. This is not a Ready/kernel-request
//! producer or a positive read coordinator; later owning ambiguity obligations
//! cannot be represented by this PRE-ROOT callback contract.

mod client;
mod server;
mod transport;
mod wire;

pub use client::{ConsumerReadPolicyStateV1, with_consumer_read_policy_state_v1};
pub use server::serve_consumer_read_policy_state_v1;
pub use wire::CONSUMER_READ_BOOTSTRAP_MAGIC_V1;

pub(crate) use transport::{Deadline, RetainedCarrier, TransportFault};

/// Reports failure of this original nonauthorizing flight.
#[derive(Debug, thiserror::Error)]
pub enum ConsumerReadFlightErrorV1 {
    /// Original endpoint I/O failed; it must not be replaced or replayed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Strict ancillary evidence or original transport custody failed.
    #[error(transparent)]
    Subject(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
    /// A kernel observation was unavailable.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// Genuine selected startup or original peer comparisons failed.
    #[error(transparent)]
    Startup(#[from] crate::normal_root::NormalRootStartupErrorV1),
    /// Actual retained Controller resources or preparation changed.
    #[error(transparent)]
    Resource(#[from] crate::attachment_effect_owner::ConsumerResourceErrorV1),
    /// Actual named Policy state or canonical projection failed.
    #[error(transparent)]
    Policy(#[from] super::PolicyCompilerJournalErrorV1),
    /// Frame, phase, selector or accepted Policy comparison differs.
    #[error("consumer-read PRE-ROOT protocol differs")]
    Protocol,
    /// Original exclusive deadline or kernel incarnation expired/changed.
    #[error("consumer-read PRE-ROOT deadline expired or changed")]
    Deadline,
}
