//! Typed failures returned by OCI parsing, validation, and serialization.

use thiserror::Error;

/// A failure to parse or validate an RFC-0015 OCI contract value.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// A JSON document exceeded its frozen admission bound.
    #[error("{document} is {actual} bytes; the limit is {limit} bytes")]
    JsonTooLarge {
        /// Human-readable document kind.
        document: &'static str,
        /// Frozen maximum byte count.
        limit: usize,
        /// Observed byte count.
        actual: usize,
    },

    /// Serde could not decode or encode a JSON document.
    #[error("invalid {document} JSON: {message}")]
    Json {
        /// Human-readable document kind.
        document: &'static str,
        /// Decoder or encoder diagnostic.
        message: String,
    },

    /// Canonical JSON encountered a floating-point number.
    #[error("canonical JSON does not permit floating-point numbers")]
    FloatingPointNotCanonical,

    /// A SHA-256 digest did not have the exact canonical spelling.
    #[error("invalid SHA-256 digest: {reason}")]
    InvalidDigest {
        /// Reason the digest was rejected.
        reason: &'static str,
    },

    /// Bytes did not match their declared digest.
    #[error("content digest mismatch: expected {expected}, observed {actual}")]
    DigestMismatch {
        /// Digest declared by the descriptor.
        expected: String,
        /// Digest computed from the bytes.
        actual: String,
    },

    /// Bytes did not match their declared size.
    #[error("content size mismatch: expected {expected}, observed {actual}")]
    SizeMismatch {
        /// Size declared by the descriptor.
        expected: u64,
        /// Observed byte count.
        actual: u64,
    },

    /// A repository name was not already in canonical RFC-0015 form.
    #[error("invalid OCI repository name: {reason}")]
    InvalidRepository {
        /// Reason the repository was rejected.
        reason: &'static str,
    },

    /// A tag was not already in canonical RFC-0015 form.
    #[error("invalid OCI tag: {reason}")]
    InvalidTag {
        /// Reason the tag was rejected.
        reason: &'static str,
    },

    /// A media type was outside the frozen first-release allowlist.
    #[error("unsupported OCI media type '{media_type}'")]
    UnsupportedMediaType {
        /// Exact rejected media type.
        media_type: String,
    },

    /// A Docker schema 1 media type was rejected explicitly.
    #[error("Docker schema 1 media type '{media_type}' is unsupported")]
    DockerSchema1Unsupported {
        /// Exact rejected schema 1 media type.
        media_type: String,
    },

    /// A duplicated annotation key appeared in one JSON object.
    #[error("annotation key '{key}' is duplicated")]
    DuplicateAnnotation {
        /// Exact repeated key.
        key: String,
    },

    /// Annotation data violated a key, value, or aggregate bound.
    #[error("invalid OCI annotations: {reason}")]
    InvalidAnnotations {
        /// Reason the annotations were rejected.
        reason: String,
    },

    /// A structural field violated its fixed item-count bound.
    #[error("{field} has {actual} items; the limit is {limit}")]
    TooManyItems {
        /// Name of the bounded field.
        field: &'static str,
        /// Frozen maximum item count.
        limit: usize,
        /// Observed item count.
        actual: usize,
    },

    /// An OCI model field was structurally invalid.
    #[error("invalid {field}: {reason}")]
    InvalidValue {
        /// Field or document being validated.
        field: &'static str,
        /// Reason the value was rejected.
        reason: String,
    },
}

impl Error {
    /// Creates a structured invalid-value error for an OCI field.
    #[must_use]
    pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidValue {
            field,
            reason: reason.into(),
        }
    }
}

/// Result type used by OCI contract operations.
pub type Result<T> = std::result::Result<T, Error>;
