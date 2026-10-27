//! Streams literal JSON Values without invoking JSON or serde deserialization.
//!
//! The version-one wire format is deliberately private worker data:
//!
//! ```text
//! "CVLIT001" | payload_bytes:u64be | values:u64be | depth:u64be | tokens
//! tokens: 00 null; 01 false; 02 true; 03 unsigned:u64be;
//!         04 negative_i64_bits:u64be; 05 finite_f64_bits:u64be;
//!         06 string:length:u64be,utf8; 07 array_start; 08 array_end;
//!         09 object_start; 0a key:length:u64be,utf8; 0b object_end
//! ```
//!
//! Keys and strings are literal, including serde's reserved marker names. The
//! shared retained-token walker defines numeric selection: unsigned first,
//! negative signed integers next, otherwise finite floating-point bits.
//!
//! Readers retain completed and partial Values under iterative destruction.
//! Their immutable views do not make recursive cloning, equality or serde
//! conversion safe for arbitrary depth. No API extracts an owning or mutable
//! Value. The limits below bound logical work and wire bytes; allocator rounding,
//! runtime overhead and production OS containment remain separate obligations.

#[path = "literal_value/error.rs"]
mod error;
#[path = "literal_value/read.rs"]
mod read;
#[path = "literal_value/walk.rs"]
pub mod walk;
#[path = "literal_value/write.rs"]
mod write;

pub use error::{StreamError, StreamFormatReason, StreamLimitReason};
pub use read::{DecodedValue, ReadFailure, read_value};
pub use write::{LiteralWriteWorkspace, write_value, write_value_in};

#[cfg(test)]
#[path = "literal_value/tests.rs"]
mod tests;

const MAGIC: &[u8; 8] = b"CVLIT001";
const HEADER_BYTES: usize = 32;

/// Restricts one codec operation without issuing resource or Source authority.
#[derive(Clone, Copy, Debug)]
pub struct StreamLimits {
    /// Bounds the complete frame, including its fixed header.
    pub maximum_wire_bytes: usize,
    /// Bounds actual Value-producing tokens, including empty containers.
    pub maximum_values: usize,
}

/// Describes the actual successfully transferred literal frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamStatistics {
    /// Counts header and payload bytes.
    pub wire_bytes: usize,
    /// Counts actual Values, including containers.
    pub values: usize,
    /// Counts the largest simultaneous container nesting, without a grammar cap.
    pub depth: usize,
}

fn checked_add(left: usize, right: usize) -> Result<usize, StreamError> {
    left.checked_add(right)
        .ok_or(StreamError::Limit(StreamLimitReason::SizeOverflow))
}

fn wire_integer(value: usize) -> Result<u64, StreamError> {
    u64::try_from(value).map_err(|_| StreamError::Limit(StreamLimitReason::WireIntegerOverflow))
}

fn host_integer(value: u64) -> Result<usize, StreamError> {
    usize::try_from(value)
        .map_err(|_| StreamError::Format(StreamFormatReason::IntegerExceedsTargetSize))
}

fn traversal_error(error: crate::errors::RuntimeError) -> StreamError {
    match error {
        crate::errors::RuntimeError::ResourceLimit => {
            StreamError::Limit(StreamLimitReason::TraversalWorkspaceOrValues)
        }
        _ => StreamError::Format(StreamFormatReason::UnsupportedNumericRepresentation),
    }
}
