//! Preserves Network's original journal and receiving causes.

use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1, NativeJournalDataErrorV1,
};
use aos_sandbox_model::AccountingError;
use aos_sandbox_journal::framing::FrameError;
use aos_sandbox_journal::protected_storage::ProtectedFailure;

/// Reports the actual Network journal or checked receiving failure.
#[derive(Debug, thiserror::Error)]
pub enum NetworkJournalErrorV1 {
    /// Preserves a direct ordinary file operation's original error.
    #[error("journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Refuses a prefix or representation that exceeds its actual bound.
    #[error("journal exceeds the configured replay byte bound")]
    JournalTooLarge,
    /// Refuses reuse after an ambiguous append or post.
    #[error("journal handle is poisoned and must be reopened")]
    Poisoned,
    /// Preserves actual checked accounting rather than replacing it with a marker.
    #[error(transparent)]
    ReceivingAccounting(#[from] AccountingError),
    /// Preserves a canonical native, record or historical semantic refusal.
    #[error(transparent)]
    Mechanical(#[from] CanonicalJournalMechanicalErrorV1),
    /// Retains the actual unfinished append DATA in its permanent shared sink.
    #[error(transparent)]
    CapturedAppendOriginal(
        aos_sandbox_broker::canonical_journal::coordinator::retained_data::RetainedAppendDataFailureV1,
    ),
    /// Retains the same body and independent native post after diagnostic Drop.
    #[error(transparent)]
    NativePostOriginal(super::JournalNativePostFailureOriginalV1),
}

impl From<FrameError> for NetworkJournalErrorV1 {
    fn from(cause: FrameError) -> Self {
        Self::Mechanical(cause.into())
    }
}

impl From<NativeJournalDataErrorV1> for NetworkJournalErrorV1 {
    fn from(cause: NativeJournalDataErrorV1) -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(
            cause,
        ))
    }
}

impl From<aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>
    for NetworkJournalErrorV1
{
    fn from(cause: aos_sandbox_protocol::domain_ledger::JournalTransactionDataError) -> Self {
        Self::Mechanical(cause.into())
    }
}

impl ProtectedFailure for NetworkJournalErrorV1 {
    const BOUNDARY: Self = Self::Mechanical(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
    const UNSUPPORTED_OPEN: Self =
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::UnsupportedProtectedOpen);
    const STALE_NAME: Self =
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot);
}

/// Preserves an actual held-writer or typed append-geometry refusal.
#[derive(Debug, thiserror::Error)]
pub enum NetworkJournalAppendReceivingDemandErrorV1 {
    /// Preserves this same actual journal's error.
    #[error(transparent)]
    Journal(#[from] NetworkJournalErrorV1),
    /// Preserves checked resource aggregation failure.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
}
