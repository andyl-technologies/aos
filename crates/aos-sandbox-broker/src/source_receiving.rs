//! Retains fixed Source native custody under the genuine pre-Bank C loan.
//!
//! The fixed opening selects its own path, limits and admitted writer UID.
//! Canonical acquisition, indexed replay and append stages remain the shared
//! mechanical engines. Completing these stages proves no Source semantics;
//! the actual private Source owner must run its complete historical schema.

mod opening;
mod recipe;
mod writer;
mod append;
mod facade;
mod replacement;
mod native_post;
mod provisioning;
pub use provisioning::{SourceCatalogMaintenanceCurrentnessOriginalV2, SourceProvisioningCurrentnessOriginalV1, SourceOperatorRecoverCurrentnessOriginalV1,
    SourceRecoveredEnrollmentCurrentnessOriginalV2};
pub(crate) mod delete_scope;
pub use delete_scope::{SourceDeleteAppendOriginalV1, SourceDeleteAppendDisposalV1,
    SourceExecutionEnvironmentAppendOriginalV1, SourceExecutionEnvironmentAppendDisposalV1};
pub use delete_scope::{SourceExecutionReadViewV1, SourceExecutionCompleteBorrowV1, SourceDeleteScopeV1, SourceDeleteScopeDisposalV1,
    SourceExecutionScopeV1, SourceExecutionScopeDisposalV1,
    SourceOperationScopeV1, SourceOperationScopeDisposalV1,
    DeleteSourcePurposeV1, ExecutionSourcePurposeV1};
mod semantic_receiving;
pub use semantic_receiving::SourceSemanticReceivingLoanV1;

pub use opening::SourceWriterOpeningOriginalsV1;
pub use writer::SourceCoordinatorWriterV1;
pub use native_post::SourceNativePostOriginalV1;
pub use replacement::{SourcePreparedReplacementV1, SourceReplacementFailureOriginalV1};
pub use append::{SourcePreparedAppendV1, SourceAppendFailureOriginalV1};
pub use recipe::{SOURCE_DOMAIN_DIRECTORY_V1, SOURCE_DOMAIN_JOURNAL_V1, source_journal_limits_v1};

/// Preserves native and same-original receiving failures without cloning causes.
#[derive(Debug, thiserror::Error)]
pub enum SourceNativeErrorV1 {
    /// Retains the original shared native failure.
    #[error(transparent)]
    Native(#[from] crate::canonical_journal::NativeJournalDataErrorV1),
    /// Retains the actual genuine Source construction/debit refusal.
    #[error(transparent)]
    Receiving(#[from] crate::controller_receiving::ControllerReceivingErrorV1),
    /// Preserves the actual common physical replacement failure.
    #[error(transparent)]
    Replacement(#[from] crate::canonical_journal::coordinator::replacement::CanonicalReplacementErrorV1),
    /// Preserves checked all-dimension receiving arithmetic.
    #[error(transparent)]
    Accounting(#[from] aos_sandbox_core::AccountingError),
    /// Preserves the original passive complete semantic geometry refusal.
    #[error(transparent)]
    SemanticGeometry(#[from] crate::canonical_journal::CanonicalJournalMechanicalErrorV1),
    /// Refuses a repeated, incomplete, foreign, or poisoned stage.
    #[error("fixed Source native custody is unavailable")]
    Closed,
}

#[cfg(test)]
mod tests {
    use super::SourceWriterOpeningOriginalsV1;

    #[test]
    fn an_empty_destination_cannot_supply_a_cursor_or_coordinator() {
        let mut originals = SourceWriterOpeningOriginalsV1::new();

        assert!(originals.begin_replay_once().is_err());
        assert!(originals.take_coordinator_after_semantic_replay_once(()).is_err());

        assert!(!originals.has_native_entry_v1());
    }
}
