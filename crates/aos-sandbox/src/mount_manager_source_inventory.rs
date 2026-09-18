//! Compatibility surface for protected Mount-manager startup authority.
//!
//! The former environment-sized unsafe capture has been removed. The current
//! fixed-root owner safely consumes the sole opaque complete-table claim minted
//! by `aos-sandbox-linux`; environment bytes cannot authorize descriptor roles
//! and callers cannot substitute a protected journal.

pub use crate::mount_manager_startup::{
    CapturedMountManagerStartupV1, ManagerSourcePresenceV1, MountManagerActivationDescriptorKindV1,
    MountManagerActivationDescriptorV1, MountManagerActivationDescriptorsV1,
    MountManagerExecutionDeathKindV1, MountManagerSourceAbsenceProjectionV1,
    MountManagerSourceAbsenceV1, MountManagerSourceControlSessionV1,
    MountManagerSourceInventoryError, MountManagerStartupAuthorityV1,
    MountManagerStartupCaptureOutcomeV1, MountManagerStartupProtectedOpenReportV1,
    MountManagerStartupProtectedOwnerV1, ReleasingSourceAbsenceBatchV1,
};
