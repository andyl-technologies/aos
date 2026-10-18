//! Debugger byte-relay identifiers, chunks, errors, and bounds.

use thiserror::Error;

/// Maximum GDB bytes read or written by one relay RPC.
pub const DEBUG_RELAY_CHUNK_MAX_BYTES: usize = 64 * 1024;

/// Opaque daemon-local identifier for one GDB relay connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DebugRelayId(
    /// Monotonic process-local numeric identity.
    pub u64,
);

/// One nonblocking read from a debug relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugRelayChunk {
    /// Bytes currently available from the gateway.
    pub bytes: Vec<u8>,
    /// Whether the gateway side closed the stream.
    pub eof: bool,
}

/// Errors returned by the daemon's stable GDB byte relay.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DebugRelayError {
    /// The actor returned an endpoint outside a private Unix socket.
    #[error("debug gateway operator endpoint is not a private Unix socket")]
    InvalidGatewayEndpoint,
    /// The daemon could not connect to the stable local gateway.
    #[error("cannot connect to debug gateway: {message}")]
    Connect {
        /// Stable I/O diagnostic.
        message: String,
    },
    /// The daemon-local relay identifier space was exhausted.
    #[error("debug relay identifier space exhausted")]
    IdentifierExhausted,
    /// The session already owns its one permitted GDB relay.
    #[error("session already owns a debug relay connection")]
    CapacityExhausted,
    /// Connecting to the local gateway exceeded the bounded timeout.
    #[error("debug relay gateway connection timed out")]
    ConnectTimeout,
    /// The relay does not exist or has already closed.
    #[error("debug relay was not found")]
    NotFound,
    /// The request used another client's or an expired controller lease.
    #[error("debug relay controller lease is stale or foreign")]
    StaleOrForeignLease,
    /// One write exceeded the bounded relay chunk size.
    #[error("debug relay chunk length {length} exceeds the limit")]
    ChunkTooLarge {
        /// Rejected byte length.
        length: usize,
    },
    /// One read requested an invalid bounded size.
    #[error("debug relay read maximum {maximum} is invalid")]
    InvalidReadMaximum {
        /// Rejected maximum.
        maximum: usize,
    },
    /// The connected gateway stream failed.
    #[error("debug relay I/O failed: {message}")]
    Io {
        /// Stable I/O diagnostic.
        message: String,
    },
    /// A relay I/O operation exceeded the bounded timeout.
    #[error("debug relay I/O timed out")]
    IoTimeout,
    /// Another operation currently owns the relay stream.
    #[error("debug relay is busy")]
    Busy,
    /// A read-only relay received malformed GDB remote-protocol bytes.
    #[error("read-only debug relay received an invalid GDB packet")]
    InvalidReadOnlyPacket,
    /// A read-only relay received a command that can change target state.
    #[error("read-only debug relay rejected a state-changing GDB command")]
    ReadOnlyCommand,
}
