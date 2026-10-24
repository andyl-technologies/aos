//! Retains concrete private-codec refusals without manufacturing model errors.

use crate::source_birth::literal_value::{ReadFailure, StreamError};
use std::{collections::TryReserveError, fmt, io};

/// Identifies a closed malformed-worker-protocol condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolFault {
    /// A magic, version, discriminant or reserved field differs.
    Edition,
    /// An installed correlation operand differs from the request.
    Identity,
    /// A declared or actual extent exceeds its independent operational bound.
    Limit,
    /// A length cannot be represented on this platform.
    Overflow,
    /// Text is not UTF-8 or a portable identifier is malformed.
    Text,
    /// A map contains duplicate or non-increasing keys.
    MapOrder,
    /// Actual bytes do not match the announced commitment.
    Digest,
    /// The one-job stream contains trailing data.
    Trailing,
}

/// Owns the actual I/O, allocation, literal or closed framing refusal.
#[derive(Debug)]
pub enum CodecError {
    /// Retains the original stream failure.
    Io(io::Error),
    /// Retains a requested workspace allocation refusal.
    Allocation(TryReserveError),
    /// Retains an ordinary literal writer refusal.
    Literal(StreamError),
    /// Retains the literal reader's failed partial construction owner.
    LiteralRead(ReadFailure),
    /// Retains a Value-free leaf enum's actual decoding error.
    Json(serde_json::Error),
    /// Identifies a closed private protocol refusal.
    Protocol(ProtocolFault),
    /// Retains a closed shared result-envelope refusal.
    ResultWire(super::super::result_wire::WireError),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "worker I/O: {e}"),
            Self::Allocation(e) => write!(f, "worker allocation: {e}"),
            Self::Literal(e) => write!(f, "worker literal: {e}"),
            Self::LiteralRead(e) => write!(f, "worker literal: {}", e.error()),
            Self::Json(e) => write!(f, "worker leaf: {e}"),
            Self::ResultWire(e) => write!(f, "worker result: {e}"),
            Self::Protocol(e) => write!(f, "worker protocol: {e:?}"),
        }
    }
}

impl std::error::Error for CodecError {}

impl From<io::Error> for CodecError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<TryReserveError> for CodecError {
    fn from(e: TryReserveError) -> Self {
        Self::Allocation(e)
    }
}

impl From<StreamError> for CodecError {
    fn from(e: StreamError) -> Self {
        Self::Literal(e)
    }
}

impl From<serde_json::Error> for CodecError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<ProtocolFault> for CodecError {
    fn from(e: ProtocolFault) -> Self {
        Self::Protocol(e)
    }
}

impl From<super::super::result_wire::WireError> for CodecError {
    fn from(error: super::super::result_wire::WireError) -> Self {
        Self::ResultWire(error)
    }
}

/// Owns only causes reachable from borrowed parent request export.
///
/// No child literal-reader partial graph or result-decoder state can occur in
/// this type. The concrete installed sink must separately retain its original
/// rich failure and prefix; its `io::Error` adapter is not assumed inline here.
#[derive(Debug)]
pub enum ExportError {
    /// Retains the original sink refusal.
    Io(io::Error),
    /// Retains the original literal traversal refusal.
    Literal(StreamError),
    /// Retains the Value-free leaf serializer's actual refusal.
    Json(serde_json::Error),
    /// Identifies a closed operational framing refusal.
    Protocol(ProtocolFault),
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "request export I/O: {e}"),
            Self::Literal(e) => write!(f, "request export literal: {e}"),
            Self::Json(e) => write!(f, "request export leaf: {e}"),
            Self::Protocol(e) => write!(f, "request export protocol: {e:?}"),
        }
    }
}

impl std::error::Error for ExportError {}

impl From<io::Error> for ExportError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<StreamError> for ExportError {
    fn from(e: StreamError) -> Self {
        Self::Literal(e)
    }
}

impl From<serde_json::Error> for ExportError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<ProtocolFault> for ExportError {
    fn from(e: ProtocolFault) -> Self {
        Self::Protocol(e)
    }
}
