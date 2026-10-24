//! Retains introspection transport refusals without formatting owned strings.

use crucible_qemu_protocol::guest_introspection::GuestIntrospectionError;
use crucible_qemu_protocol::guest_introspection_doorbell::{
    GuestIntrospectionDoorbellError, GuestIntrospectionDoorbellKind,
};
use crucible_qemu_shmem::{GuestIntrospectionEntryError, SpscRingError};
use thiserror::Error;

/// Retains a typed failure from the live guest-introspection transport.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GuestIntrospectionTransportError {
    /// The response ring requires the guest to retry publication.
    #[error("guest introspection response ring is full")]
    Full,
    /// A shared-memory operation rejected the exchange.
    #[error("guest introspection transport failed: {source}")]
    Ring {
        /// Original ring refusal, including its concrete coordinates.
        #[from]
        source: SpscRingError,
    },
    /// A response or request entry failed fixed-layout validation.
    #[error("guest introspection transport failed: {source}")]
    Entry {
        /// Original entry validation failure.
        #[from]
        source: GuestIntrospectionEntryError,
    },
    /// A record failed protocol or direction validation.
    #[error("guest introspection transport failed: {source}")]
    Record {
        /// Original protocol validation failure.
        #[from]
        source: GuestIntrospectionError,
    },
    /// A reply could not represent its encoded record.
    #[error("guest introspection transport failed: {source}")]
    Reply {
        /// Original exchange construction failure.
        #[from]
        source: GuestIntrospectionDoorbellError,
    },
    /// An internal validated exchange or modeled backend broke an invariant.
    #[error("guest introspection transport failed: {message}")]
    Invariant {
        /// Static explanation retained without allocating a diagnostic.
        message: &'static str,
    },
    /// Publishing another response would wrap its sequence.
    #[error("guest introspection transport failed: response sequence overflow")]
    ResponseSequenceOverflow,
    /// Committing a delivered request would wrap its sequence.
    #[error("guest introspection transport failed: request sequence overflow")]
    RequestSequenceOverflow,
    /// The guest supplied a kind reserved for replies from the plugin.
    #[error("guest introspection transport failed: guest supplied a plugin-to-guest exchange kind")]
    GuestReplyKind {
        /// Rejected exchange kind.
        kind: GuestIntrospectionDoorbellKind,
    },
    /// A queued request did not have the next required sequence.
    #[error(
        "guest introspection transport failed: request sequence mismatch: expected {expected}, actual {actual}"
    )]
    RequestSequenceMismatch {
        /// Next sequence required by the plugin.
        expected: u64,
        /// Sequence retained in the shared entry.
        actual: u64,
    },
}
