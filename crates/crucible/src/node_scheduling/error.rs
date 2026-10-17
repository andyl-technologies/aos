//! Operational causal refusals, separate from application assertions.

/// Reports a causal admission refusal before grants or publication are widened.
#[derive(Debug, thiserror::Error)]
pub enum SchedulingError {
    /// Checked arithmetic or a closed contract value was invalid.
    #[error("invalid scheduling contract: {0}")]
    Contract(#[from] crucible_node_contract::ContractError),
    /// The scheduler does not belong to the committed runtime realization.
    #[error("foreign or stale world activation")]
    ForeignActivation,
    /// The requested node is absent from the complete graph.
    #[error("unknown scheduling node")]
    UnknownNode,
    /// The requested grant differs from the selected exact or quantized mode.
    #[error("unsupported scheduling mode or boundary representation")]
    UnsupportedMode,
    /// A native observation mechanism required by the policy is unimplemented.
    #[error("authenticated native scheduling or input evidence is unavailable")]
    MissingObservation,
    /// A producer bound is unknown, stale or does not close required input.
    #[error("input closure is blocked by producer {0}")]
    InputBlocked(crucible_node_contract::Id),
    /// No representable half-open limit permits further progress.
    #[error("no safe representable execution interval")]
    NoSafeProgress,
    /// An owner retains issued or dispatched grant custody.
    #[error("execution owner has an unresolved grant")]
    OwnerBusy,
    /// An original operation identity was already issued.
    #[error("operation identity already used")]
    DuplicateOperation,
    /// The receipt does not match the original immutable grant.
    #[error("invalid scheduling receipt; original reservation retained")]
    InvalidReceipt,
    /// ID-only output reports cannot establish causal publication coordinates.
    #[error("retained outputs lack authenticated causal coordinates")]
    MissingOutputCoordinates,
    /// Causal parent or public delivery precedes already committed progress.
    #[error("causal event regressed behind its parent or activated input cut")]
    CausalRegression,
    /// A publication does not use the declared public phase.
    #[error("invalid publication coordinate")]
    InvalidPublication,
    /// Same-time reaction requires a microstep beyond its finite admitted count.
    #[error("same-time closure did not converge within its admitted bound")]
    SameTimeNonconvergence,
    /// A producer already allocated the final representable public sequence.
    #[error("producer public sequence exhausted")]
    SequenceExhausted,
    /// A captured coordinator record is malformed or incomplete.
    #[error("invalid or incomplete scheduling snapshot")]
    InvalidSnapshot,
    /// Native original operation custody cannot yet be reconstructed.
    #[error("snapshot retains unresolved native operation custody")]
    UnresolvedCustody,
    /// The continuation would exceed its explicitly bounded record capacity.
    #[error("coordinator continuation capacity exhausted")]
    CapacityExceeded,
}
