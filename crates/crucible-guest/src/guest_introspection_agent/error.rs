//! Failure taxonomy for the in-guest introspection service.

use thiserror::Error;

use crate::GuestEmitterError;

/// Failure while configuring or running the in-guest service.
#[derive(Debug, Error)]
pub enum GuestIntrospectionAgentError {
    /// Static service configuration is invalid.
    #[error("invalid guest introspection configuration: {message}")]
    Configuration {
        /// Stable diagnostic.
        message: String,
    },
    /// The public exchange or record protocol was violated.
    #[error("guest introspection protocol failed: {message}")]
    Protocol {
        /// Stable diagnostic.
        message: String,
    },
    /// The architecture-specific doorbell failed.
    #[error("guest introspection doorbell failed: {0}")]
    Doorbell(GuestEmitterError),
    /// An in-guest process or PTY operation failed.
    #[error("guest introspection process failed: {message}")]
    Process {
        /// Operating-system diagnostic.
        message: String,
    },
    /// A requested optional guest-agent capability is unavailable.
    #[error("guest introspection feature is unavailable: {message}")]
    Unsupported {
        /// Stable capability diagnostic.
        message: String,
    },
    /// A request reused an active channel identifier.
    #[error("guest introspection channel {channel_id} is already active")]
    DuplicateChannel {
        /// Conflicting channel identifier.
        channel_id: u64,
    },
    /// A request targeted no active channel.
    #[error("guest introspection channel {channel_id} is not active")]
    UnknownChannel {
        /// Missing channel identifier.
        channel_id: u64,
    },
    /// A request exceeded the advertised channel capacity.
    #[error("guest introspection channel limit {maximum} is exhausted")]
    ChannelLimit {
        /// Advertised maximum.
        maximum: u16,
    },
    /// Input arrived after a channel's stdin was closed.
    #[error("guest introspection channel {channel_id} input is closed")]
    ClosedChannel {
        /// Closed channel identifier.
        channel_id: u64,
    },
    /// Resize targeted a non-PTY channel.
    #[error("guest introspection channel {channel_id} is not a PTY")]
    NotPty {
        /// Non-PTY channel identifier.
        channel_id: u64,
    },
    /// A channel output reader panicked.
    #[error("guest introspection channel {channel_id} output reader panicked")]
    ReaderPanic {
        /// Affected channel identifier.
        channel_id: u64,
    },
}
