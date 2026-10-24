//! Names closed wire refusals without free-form constructor reasons.

use std::fmt;

/// Identifies an explicit one-byte tag field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagField {
    /// Names the result status.
    Status,
    /// Names the failed stage.
    Stage,
    /// Names the cause category.
    Cause,
    /// Names the explicit coordinate basis.
    CoordinateBasis,
    /// Names the original serde category.
    SerdeCategory,
}

/// Identifies a payload whose actual bytes disagree with its digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadKind {
    /// Names the SourceBirth payload.
    Source,
    /// Names the planned registration payload.
    Registration,
    /// Names the complete diagnostic payload.
    Diagnostic,
}

/// Reports a closed structural, commitment or explicit operational-limit refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The versioned magic differs.
    BadMagic,
    /// A reserved byte is nonzero.
    Reserved,
    /// A tag has no defined meaning in this version.
    UnknownTag(TagField, u8),
    /// Status-dependent fields are inconsistent.
    InvalidShape,
    /// A wire length cannot be represented or summed.
    LengthOverflow,
    /// The complete frame exceeds its explicit allowance.
    FrameLimit,
    /// The complete diagnostic exceeds its explicit allowance.
    DiagnosticLimit,
    /// The stream ends before the declared final byte.
    Truncated,
    /// A byte follows the declared final payload.
    Trailing,
    /// Task or complete-input identity differs from the original job.
    ForeignIdentity,
    /// Actual payload bytes differ from their declared identity.
    DigestMismatch(PayloadKind),
    /// A diagnostic is not valid UTF-8.
    InvalidUtf8,
    /// A streaming digest receives too many or too few bytes.
    HashLength,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "worker result wire: {self:?}")
    }
}

impl std::error::Error for WireError {}
