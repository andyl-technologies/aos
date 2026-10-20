//! Classifies Source-owned geometry failures without importing Controller policy.

use aos_sandbox_core::AccountingError;

#[derive(Debug, thiserror::Error)]
pub(super) enum SourceReceivingGeometryErrorV1 {
    #[error("shared resource enrollment is unavailable")]
    EnrollmentUnavailable,
    #[error(transparent)]
    Accounting(#[from] AccountingError),
}
