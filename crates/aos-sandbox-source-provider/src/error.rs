//! Failure types for the protected SourceProvider ledger.

use aos_sandbox::JournalError;
use aos_sandbox_source_provider_protocol::{
    SourceProviderSignatureError, SourceProviderValidationError, SourceProviderVerificationError,
};
use aos_sandbox_source_provider_security::SourceProviderSecurityError;

/// Reports a fail-closed durable SourceProvider owner failure.
#[derive(Debug, thiserror::Error)]
pub enum ProviderLedgerError {
    /// The protected journal could not be read or durably updated.
    #[error("SourceProvider journal operation failed: {0}")]
    Journal(#[from] JournalError),
    /// A retained record violates the closed AOSSPL01 representation.
    #[error("SourceProvider ledger record is corrupt: {0}")]
    Corrupt(&'static str),
    /// A bounded ledger resource would exceed its configured ceiling.
    #[error("SourceProvider ledger limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// A legacy ledger requires separately authenticated migration provenance.
    #[error("SourceProvider ledger migration needs provenance: {0}")]
    MigrationNeedsProvenance(&'static str),
    /// Protected current configuration differs from the recovered durable head.
    #[error("SourceProvider protected configuration does not match durable state")]
    ConfigurationMismatch,
    /// A stable request, acquisition, lease, release, or catalog identity was reused differently.
    #[error("SourceProvider durable identity equivocation")]
    Equivocation,
    /// The requested transition is not valid from the recovered durable state.
    #[error("SourceProvider durable transition is invalid: {0}")]
    InvalidTransition(&'static str),
    /// The operation requires manual reconciliation after contradictory backend evidence.
    #[error("SourceProvider backend evidence conflicts with durable state")]
    BackendConflict,
    /// This runtime observed an authority conflict and refuses further work.
    #[error("SourceProvider runtime is poisoned pending manual reconciliation")]
    RuntimePoisoned,
    /// A required active acquisition could not be authoritatively reopened.
    #[error("SourceProvider active acquisition is unavailable")]
    Unavailable,
    /// Provider request authentication or graph verification failed.
    #[error("SourceProvider request verification failed: {0}")]
    Verification(#[from] SourceProviderVerificationError),
    /// A protocol model could not be constructed from owner-held facts.
    #[error("SourceProvider response construction failed: {0}")]
    Protocol(#[from] SourceProviderValidationError),
    /// Provider outcome signing failed.
    #[error("SourceProvider response signing failed: {0}")]
    Signing(#[from] SourceProviderSignatureError),
    /// Protected custody or current ingress revalidation failed.
    #[error("SourceProvider security custody failed: {0}")]
    Security(#[from] SourceProviderSecurityError),
}

impl From<crate::ledger::LedgerFormatErrorV1> for ProviderLedgerError {
    fn from(value: crate::ledger::LedgerFormatErrorV1) -> Self {
        match value {
            crate::ledger::LedgerFormatErrorV1::Corrupt(message) => Self::Corrupt(message),
            crate::ledger::LedgerFormatErrorV1::LimitExceeded(message) => {
                Self::LimitExceeded(message)
            }
            crate::ledger::LedgerFormatErrorV1::NeedsProvenance(message) => {
                Self::MigrationNeedsProvenance(message)
            }
        }
    }
}
