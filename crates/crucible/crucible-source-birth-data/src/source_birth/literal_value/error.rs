//! Defines closed literal-stream diagnostics while retaining actual I/O/allocation errors.
//!
//! These enums describe ordinary codec failures. They have no wire discriminant,
//! accepted-bank meaning or Source/native authority. Display text remains the
//! original diagnostic text; callers can match the closed reason types directly.

use std::{collections::TryReserveError, fmt, io};

/// Names a closed logical operation-limit refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamLimitReason {
    /// A checked codec size calculation overflowed.
    SizeOverflow,
    /// A size cannot be represented by the wire integer.
    WireIntegerOverflow,
    /// The borrowed traversal exhausted its workspace or node bound.
    TraversalWorkspaceOrValues,
    /// The complete frame exceeds the wire-byte bound.
    WireBytes,
    /// The frame exceeds the Value-node bound.
    ValueCount,
    /// The iterative retirement workspace size overflowed.
    RetirementSizeOverflow,
}

impl fmt::Display for StreamLimitReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SizeOverflow => "size overflow",
            Self::WireIntegerOverflow => "wire integer overflow",
            Self::TraversalWorkspaceOrValues => "traversal workspace or values",
            Self::WireBytes => "wire bytes",
            Self::ValueCount => "values",
            Self::RetirementSizeOverflow => "retirement size overflow",
        };
        formatter.write_str(message)
    }
}

/// Names a closed framing, chronology or representation refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamFormatReason {
    /// A wire integer cannot be represented by the target size type.
    IntegerExceedsTargetSize,
    /// The shared walker cannot represent the source Number.
    UnsupportedNumericRepresentation,
    /// Primitive reconstruction would change the source Number.
    NumberCannotRoundTripExactly,
    /// The borrowed traversal reported an unmatched container end.
    UnbalancedTraversal,
    /// The completed owner has no root Value.
    MissingCompletedRoot,
    /// The frame magic or version differs.
    MagicOrVersion,
    /// The declared node count is zero or exceeds the payload length.
    ImpossibleValueCount,
    /// The declared container depth exceeds its node count.
    ImpossibleDepth,
    /// Payload bytes remain after the root Value completes.
    TrailingPayload,
    /// The tokens exceed the declared node count.
    ValueCountExceeded,
    /// A signed token contains a nonnegative integer.
    SignedTokenNotNegative,
    /// A floating-point token contains nonfinite bits.
    NonFiniteFloat,
    /// The selected Value branch has an invalid tag.
    ValueTag,
    /// The payload contains an unknown token tag.
    UnknownToken,
    /// The payload ends with incomplete owning Value state.
    IncompleteValue,
    /// Actual node or depth counts differ from the header.
    HeaderCountsDiffer,
    /// A Value token has no permitted destination.
    ValueWithoutDestination,
    /// A container exceeds the declared depth.
    DepthExceeded,
    /// A close token mismatches its container or lacks an object value.
    MismatchedCloseOrMissingObjectValue,
    /// A close operation has no owning container.
    MissingContainer,
    /// A key token has no permitted object destination.
    KeyWithoutObjectDestination,
    /// The key operation has no owning object frame.
    MissingObject,
    /// The key operation has no retained key.
    MissingKey,
    /// An object key already exists.
    DuplicateKey,
    /// Attachment has no retained pending Value.
    MissingPendingValue,
    /// Attachment has no retained object key.
    MissingObjectKey,
    /// Attachment has no preinstalled object slot.
    MissingObjectSlot,
    /// Attachment found an occupied object slot.
    OccupiedObjectSlot,
    /// A token read would exceed the declared payload.
    TokenBeyondPayload,
    /// An integer read would exceed the declared payload.
    WordBeyondPayload,
    /// A text extent exceeds the declared remaining payload.
    TextBeyondPayload,
    /// A text token is not UTF8.
    InvalidUtf8,
    /// The input reader returned more bytes than its destination length.
    ReaderReturnedInvalidLength,
}

impl fmt::Display for StreamFormatReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::IntegerExceedsTargetSize => "integer exceeds target size",
            Self::UnsupportedNumericRepresentation => "unsupported numeric representation",
            Self::NumberCannotRoundTripExactly => "number cannot round-trip exactly",
            Self::UnbalancedTraversal => "unbalanced traversal",
            Self::MissingCompletedRoot => "missing completed root",
            Self::MagicOrVersion => "magic or version",
            Self::ImpossibleValueCount => "impossible value count",
            Self::ImpossibleDepth => "impossible depth",
            Self::TrailingPayload => "trailing payload",
            Self::ValueCountExceeded => "value count exceeded",
            Self::SignedTokenNotNegative => "signed token is not negative",
            Self::NonFiniteFloat => "nonfinite float",
            Self::ValueTag => "value tag",
            Self::UnknownToken => "unknown token",
            Self::IncompleteValue => "incomplete value",
            Self::HeaderCountsDiffer => "header counts differ",
            Self::ValueWithoutDestination => "value without destination",
            Self::DepthExceeded => "depth exceeded",
            Self::MismatchedCloseOrMissingObjectValue => "mismatched close or missing object value",
            Self::MissingContainer => "missing container",
            Self::KeyWithoutObjectDestination => "key without object destination",
            Self::MissingObject => "missing object",
            Self::MissingKey => "missing key",
            Self::DuplicateKey => "duplicate key",
            Self::MissingPendingValue => "missing pending value",
            Self::MissingObjectKey => "missing object key",
            Self::MissingObjectSlot => "missing object slot",
            Self::OccupiedObjectSlot => "occupied object slot",
            Self::TokenBeyondPayload => "token beyond payload",
            Self::WordBeyondPayload => "word beyond payload",
            Self::TextBeyondPayload => "text beyond payload",
            Self::InvalidUtf8 => "invalid UTF8",
            Self::ReaderReturnedInvalidLength => "reader returned invalid length",
        };
        formatter.write_str(message)
    }
}

/// Describes an ordinary stream, representation or operational limit refusal.
#[derive(Debug)]
pub enum StreamError {
    /// Retains the actual input or output error.
    Io(io::Error),
    /// Retains a fallible workspace or text reservation error.
    Allocation(TryReserveError),
    /// Identifies the logical operation bound that was exceeded.
    Limit(StreamLimitReason),
    /// Identifies malformed framing, token chronology or unsupported numbers.
    Format(StreamFormatReason),
}

impl fmt::Display for StreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "literal stream I/O: {error}"),
            Self::Allocation(error) => write!(formatter, "literal stream allocation: {error}"),
            Self::Limit(reason) => write!(formatter, "literal stream limit: {reason}"),
            Self::Format(reason) => write!(formatter, "literal stream format: {reason}"),
        }
    }
}

impl std::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Allocation(error) => Some(error),
            Self::Limit(_) | Self::Format(_) => None,
        }
    }
}

impl From<io::Error> for StreamError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<TryReserveError> for StreamError {
    fn from(error: TryReserveError) -> Self {
        Self::Allocation(error)
    }
}
