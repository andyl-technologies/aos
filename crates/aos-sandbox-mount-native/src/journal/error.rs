//! Retains Mount's actual mechanical, append and receiving causes.

use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1, NativeJournalDataErrorV1,
};
use aos_sandbox_journal::protected_storage::ProtectedFailure;

/// Reports the actual Mount journal refusal without extracting failed custody.
#[derive(Debug, thiserror::Error)]
pub enum MountJournalErrorV1 {
    /// Preserves the existing canonical mechanical cause unchanged.
    #[error(transparent)]
    Mechanical(#[from] CanonicalJournalMechanicalErrorV1),
    /// Preserves checked accounting at its actual receiving frontier.
    #[error(transparent)]
    ReceivingAccounting(#[from] aos_sandbox_core::AccountingError),
    /// Keeps the same failed captured DATA in its permanent original sink.
    #[error(transparent)]
    CapturedAppendOriginal(
        aos_sandbox_broker::canonical_journal::coordinator::retained_data::RetainedAppendDataFailureV1,
    ),
    /// Keeps the same failed body and independently owed native posts resident.
    #[error(transparent)]
    NativePostOriginal(super::MountAppendFailureOriginalV1),
}

impl From<std::io::Error> for MountJournalErrorV1 {
    fn from(cause: std::io::Error) -> Self {
        Self::Mechanical(cause.into())
    }
}

impl From<aos_sandbox_journal::framing::FrameError> for MountJournalErrorV1 {
    fn from(cause: aos_sandbox_journal::framing::FrameError) -> Self {
        Self::Mechanical(cause.into())
    }
}

impl From<NativeJournalDataErrorV1> for MountJournalErrorV1 {
    fn from(cause: NativeJournalDataErrorV1) -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(
            cause,
        ))
    }
}

impl From<aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>
    for MountJournalErrorV1
{
    fn from(cause: aos_sandbox_protocol::domain_ledger::JournalTransactionDataError) -> Self {
        Self::Mechanical(cause.into())
    }
}

impl From<aos_sandbox_protocol::domain_ledger::capacity_family::CapacityDataError>
    for MountJournalErrorV1
{
    fn from(
        cause: aos_sandbox_protocol::domain_ledger::capacity_family::CapacityDataError,
    ) -> Self {
        Self::Mechanical(cause.into())
    }
}

impl ProtectedFailure for MountJournalErrorV1 {
    const BOUNDARY: Self = Self::Mechanical(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
    const UNSUPPORTED_OPEN: Self =
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::UnsupportedProtectedOpen);
    const STALE_NAME: Self =
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot);
}
