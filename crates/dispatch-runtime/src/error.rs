//! Typed execution errors, distinct from assignment feasibility.

/// Reports a failed session operation or execution stage.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The session no longer admits operations.
    #[error("session is closed")]
    Closed,
    /// A configured accounting limit would be exceeded.
    #[error("session admission limit exceeded: {0}")]
    Overloaded(&'static str),
    /// Configuration or a required guarantee cannot be supported.
    #[error("unsupported configuration: {0}")]
    Unsupported(String),
    /// A handle belongs to an expired generation or released input.
    #[error("prepared input is stale or belongs to another session")]
    StaleHandle,
    /// A retained terminal result expired.
    #[error("terminal result retention expired")]
    Expired,
    /// A file or process operation failed.
    #[error("execution I/O failed")]
    Io(#[from] std::io::Error),
    /// Portable input or output decoding failed.
    #[error("execution JSON conversion failed")]
    Json(#[from] serde_json::Error),
    /// The language-neutral protocol rejected transport or exact interchange.
    #[error("worker wire protocol failed")]
    Wire(#[from] dispatch_protocol::ProtocolError),
    /// Portable model validation failed.
    #[error("invalid allocation model")]
    Model(#[from] dispatch_model::ModelError),
    /// Protocol communication or negotiation failed.
    #[error("worker protocol failed: {0}")]
    Protocol(String),
    /// An execution provider failed, retaining its concrete source.
    #[error("execution provider failed")]
    Provider(#[source] Box<dyn std::error::Error + Send + Sync>),
}
