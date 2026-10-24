//! Preserves the original owned transport and local-runtime failure vocabulary.

/// Reports transport, portable schema, or correlation failure.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The stream could not complete an I/O operation.
    #[error("provider stream I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Portable data failed its canonical representation or bounds.
    #[error("invalid provider data: {0}")]
    Contract(#[from] crucible_node_format::ContractError),
    /// A frame cannot be interpreted under the admitted transport.
    #[error("invalid provider frame: {0}")]
    Frame(&'static str),
    /// A message disagrees with retained connection or request custody.
    #[error("provider correlation failure: {0}")]
    Correlation(&'static str),
    /// A finite storage or sequence allowance is exhausted.
    #[error("provider resource exhausted: {0}")]
    ResourceExhausted(&'static str),
    /// A request identity is reused with different material.
    #[error("provider request conflict: {0}")]
    Conflict(&'static str),
}

/// Reports a local admission failure before provider effects begin.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    /// An admitted runtime or retained inventory ceiling would be exceeded.
    #[error("runtime resource ceiling exceeded")]
    ResourceLimit,
    /// Dispatch would violate the admitted native adapter's thread custody.
    #[error("native adapter thread affinity mismatch")]
    ThreadAffinity,
    /// The complete activated graph could not establish scheduling authority.
    #[error("scheduler admission failed: {0}")]
    SchedulerRefused(String),
    /// The requested public node was not admitted.
    #[error("unknown node")]
    UnknownNode,
    /// A route is missing owners or aliases an incompatible incarnation.
    #[error("invalid owner route")]
    InvalidRoute,
    /// An operation identity was already used in this world.
    #[error("operation identity already used")]
    DuplicateOperation,
    /// A shared owner has unresolved operation or publication custody.
    #[error("owner has retained operation custody")]
    OwnerBusy,
    /// An owner is contained or released and unavailable for ordinary work.
    #[error("owner is unavailable")]
    OwnerUnavailable,
    /// Complete world activation has not been durably established.
    #[error("world activation is not committed")]
    NotActivated,
    /// A token or activation record belongs to another local authority.
    #[error("foreign or stale authority")]
    ForeignAuthority,
    /// A required explicitly advertised facet is absent.
    #[error("unsupported facet")]
    UnsupportedFacet,
    /// A timing request has empty, inverted, or incompatible bounds.
    #[error("invalid timing request")]
    InvalidTiming,
    /// A provider result does not match the original admitted operation.
    #[error("invalid provider receipt; owner quarantined")]
    InvalidReceipt,
    /// Native terminal outcome or output acknowledgement is still outstanding.
    #[error("retained obligations remain")]
    OutstandingObligations,
    /// A durable publication failed or has uncertain status.
    #[error("activation publication failed or is uncertain")]
    PublicationFailed,
}
