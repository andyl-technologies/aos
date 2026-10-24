//! Names distinct stages of one retained Runtime input batch.
//!
//! The phase identifies construction DATA and signed history. It supplies no
//! dispatch, acknowledgement or scheduler custody permission.

/// Distinguishes the two separately admitted phases of a Runtime input batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalRuntimeInputPhase {
    /// Stages the exact retained batch before any native acceptance.
    Stage,
    /// Commits the same staged batch after its actual acknowledgement.
    Commit,
}
