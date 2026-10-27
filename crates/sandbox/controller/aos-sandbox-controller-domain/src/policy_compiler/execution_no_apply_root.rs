//! Retains the distinct Execution NoApply Root purpose's current-row models.
//!
//! The native C/Host Session/Source readers and real policy-pair interval stay
//! with their original owners. The model stage borrows those owners and shares
//! the sole Controller reducer. Planned rows are comparison DATA; they provide
//! no signed current Host lease, Root floor, native append or settlement grant.

mod current_models;
mod host_trust;
mod current_host_lease;
mod floor;
mod acknowledged;
pub(crate) mod transport;
mod acquisition;
pub(crate) use acquisition::{RootExecutionNoApplyAcquisitionOriginalV2,
    RootNoApplyAcquisitionSelectionDataV2};
pub(crate) use acknowledged::RootExecutionNoApplyAckOriginalV2;

pub(crate) use current_models::RootExecutionNoApplyModelsOriginalV2;
pub(crate) use host_trust::RootExecutionNoApplyHostTrustOriginalV2;
pub(crate) use current_host_lease::RootExecutionNoApplyHostLeaseOriginalV2;
pub(in crate::policy_compiler) use current_host_lease::host_history::HostHistoryOriginalV2;
pub(crate) use floor::{RootExecutionNoApplyFloorOriginalV2, RootExecutionNoApplyFloorAppendLoanV2};

/// Preserves the actual failure reached while receiving or planning C rows.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RootExecutionNoApplyModelsErrorV2 {
    #[error(transparent)]
    Journal(#[from] crate::journal::JournalError),
    #[error(transparent)]
    Reservation(#[from] crate::controller_resource_reservation::ResourceReservationErrorV1),
    #[error(transparent)]
    Reconciler(#[from] crate::reconciler::ReconcilerError),
}
