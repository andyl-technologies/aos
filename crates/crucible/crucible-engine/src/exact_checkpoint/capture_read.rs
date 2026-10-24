//! Owned page-reader failures shared by capture producers and checkpoint storage.
//!
//! The contract moves the original IO, validation, or allocation cause without
//! introducing a shared owner or tying the scheduler to a capture adapter.

/// An owned failure while reading one already-admitted capture page.
///
/// Reading transfers the original cause to the caller. This error does not
/// clone, stringify, or allocate a second shared error body.
#[derive(Debug, thiserror::Error)]
pub enum CaptureReadError {
    /// The retained spool could not supply the requested bytes.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A record violates a capture ordering, version, or length invariant.
    #[error("invalid retained RAM capture: {0}")]
    Malformed(&'static str),
    /// A coordinate violates the admitted logical RAM geometry.
    #[error(transparent)]
    Validation(#[from] crucible_ram::RamError),
    /// Storage for the bounded page bytes could not be allocated.
    #[error(transparent)]
    Allocation(#[from] std::collections::TryReserveError),
}
