//! Preserves readonly mechanical and representation failures without Domain.
//!
//! The five locally constructed classes keep their original diagnostics. Other
//! canonical mechanical causes move intact, including owned IO errors. Replay
//! and role-specific failed originals remain on their genuine native owners.

use std::io;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;

/// Reports a fixed Root readonly or checked receiving failure.
#[derive(Debug, thiserror::Error)]
pub enum RootReadonlyErrorV1 {
    /// Preserves a canonical mechanical cause without cloning its payload.
    #[error(transparent)]
    Mechanical(CanonicalJournalMechanicalErrorV1),
    /// The captured journal exceeds its configured replay bound.
    #[error("journal exceeds the configured replay byte bound")]
    JournalTooLarge,
    /// A path, owner, file, mode or required native stage violates its boundary.
    #[error("protected journal storage boundary is invalid")]
    ProtectedBoundary,
    /// A selected readonly name stage refused; its native cause stays owned.
    #[error("selected readonly name observation {0} refused")]
    ReadOnlyNameReceivingFailure(u8),
    /// The retained authority cut is stale or belongs to another original.
    #[error("protected authority snapshot is stale or belongs to another journal")]
    StaleAuthoritySnapshot,
    /// An earlier durability failure requires reopening the native owner.
    #[error("journal handle is poisoned and must be reopened")]
    Poisoned,
    /// A checked representation or configured bound was exceeded.
    #[error("journal limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Preserves the exact checked ResourceVector arithmetic failure.
    #[error(transparent)]
    ReceivingAccounting(#[from] aos_sandbox_model::AccountingError),
}

impl From<CanonicalJournalMechanicalErrorV1> for RootReadonlyErrorV1 {
    fn from(cause: CanonicalJournalMechanicalErrorV1) -> Self {
        match cause {
            CanonicalJournalMechanicalErrorV1::JournalTooLarge => Self::JournalTooLarge,
            CanonicalJournalMechanicalErrorV1::ProtectedBoundary => Self::ProtectedBoundary,
            CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot => Self::StaleAuthoritySnapshot,
            CanonicalJournalMechanicalErrorV1::Poisoned => Self::Poisoned,
            CanonicalJournalMechanicalErrorV1::LimitExceeded(label) => Self::LimitExceeded(label),
            cause => Self::Mechanical(cause),
        }
    }
}

impl From<io::Error> for RootReadonlyErrorV1 {
    fn from(cause: io::Error) -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::Io(cause))
    }
}

impl aos_sandbox_journal::protected_storage::ProtectedFailure for RootReadonlyErrorV1 {
    const BOUNDARY: Self = Self::ProtectedBoundary;
    const UNSUPPORTED_OPEN: Self = Self::Mechanical(
        CanonicalJournalMechanicalErrorV1::UnsupportedProtectedOpen,
    );
    const STALE_NAME: Self = Self::StaleAuthoritySnapshot;
}
