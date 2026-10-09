//! Typed failures preserve transport and data-decoding sources.

/// Reports a bounded transport, semantic decoding, or negotiation failure.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// A transport failed before completing a frame.
    #[error("worker transport failed: {0}")]
    Io(#[from] std::io::Error),
    /// Protobuf could not decode the advertised message.
    #[error("invalid worker Protobuf: {0}")]
    Protobuf(#[from] prost::DecodeError),
    /// The frame exceeded limits or had an invalid length.
    #[error("invalid worker frame length {length}; limit is {limit}")]
    FrameLength {
        /// Observed or proposed encoded size.
        length: usize,
        /// Maximum accepted encoded size.
        limit: u32,
    },
    /// Protobuf would silently drop unknown fields or ambiguous repeated scalars.
    #[error("worker message is not the canonical known-field encoding")]
    NonCanonicalProtobuf,
    /// The envelope omitted an operation or contained an unknown enum alternative.
    #[error("invalid worker message: {0}")]
    InvalidMessage(String),
    /// An exact JSON document could not be decoded.
    #[error("invalid exact JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The portable assignment model failed structural or exact validation.
    #[error("invalid assignment model: {0}")]
    Model(#[from] dispatch_model::ModelError),
    /// JSON exceeded a configured size or construction bound.
    #[error("JSON exceeds its {0} bound")]
    JsonLimit(&'static str),
    /// Negotiation cannot faithfully implement the requested contract.
    #[error("unsupported worker contract: {0}")]
    Negotiation(String),
    /// A response was associated with a different worker or operation.
    #[error("worker correlation mismatch: {0}")]
    Correlation(String),
    /// The supplied semantic commitment did not bind the expected data.
    #[error("model or request commitment mismatch")]
    CommitmentMismatch,
    /// The published canonical mapping could not represent a value.
    #[error("invalid canonical value: {0}")]
    Canonical(String),
}
