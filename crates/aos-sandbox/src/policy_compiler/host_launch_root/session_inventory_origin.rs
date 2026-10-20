//! Selects actual Start or Maintenance assignment owners for current Inventory.
//!
//! The shared authenticated Session/history/outcome decoder remains the sole
//! consumer. This finite borrower lends comparison fields only; a manifest,
//! cutoff, kind or caller-supplied callback cannot construct its native origin.

use aos_sandbox_core::{CanonicalAssignmentManifestV1, RawPairedClockSample};
use crate::journal::JournalError;
use super::{compiler::RootStartResourceCompilerOriginalV2,
    maintenance_assignment::RootMaintenanceAssignmentOriginalV2};

pub(super) enum CurrentInventoryOriginV2<'held> {
    Start(&'held RootStartResourceCompilerOriginalV2),
    MaintenanceStorage(&'held RootMaintenanceAssignmentOriginalV2),
}

impl CurrentInventoryOriginV2<'_> {
    pub(super) fn manifest_v2(&self) -> Result<&CanonicalAssignmentManifestV1, JournalError> {
        match self {
            Self::Start(compiler) => Ok(compiler.compiled_v2()?.manifest_v2()),
            Self::MaintenanceStorage(assignment) => assignment.manifest_v2(),
        }
    }

    pub(super) fn require_cutoff_v2(&self, sample: RawPairedClockSample, cutoff: u64)
        -> Result<(), JournalError> {
        if sample.boottime_nanoseconds() >= cutoff {
            return Err(JournalError::ProtectedBoundary);
        }
        match self {
            Self::Start(compiler) => {
                if cutoff > compiler.compiled_v2()?.source_v2().native_origin_data_v2().cutoff_v1() {
                    return Err(JournalError::ProtectedBoundary);
                }
                Ok(())
            }
            Self::MaintenanceStorage(assignment) => assignment.require_inventory_cutoff_data_v2(sample, cutoff),
        }
    }

    pub(super) fn permits_storage_inventory_v2(&self) -> bool {
        matches!(self, Self::MaintenanceStorage(_))
    }
}

#[derive(Clone, Copy)]
pub(super) enum FinalResourceOriginV3<'held> {
    Start {
        compiler: &'held RootStartResourceCompilerOriginalV2,
        historical: &'held super::history::RootHostHistoricalCreateOriginalV2,
    },
    MaintenanceStorage {
        assignment: &'held RootMaintenanceAssignmentOriginalV2,
        request: &'held super::maintenance_request::RootMaintenanceStorageRequestOriginalV2,
    },
}

impl FinalResourceOriginV3<'_> {
    pub(super) fn manifest_v3(&self) -> Result<&CanonicalAssignmentManifestV1, JournalError> {
        match self {
            Self::Start { compiler, .. } => Ok(compiler.compiled_v2()?.manifest_v2()),
            Self::MaintenanceStorage { assignment, request } => {
                assignment.require_compiled_v2()?;
                request.require_typed_v2()?;
                assignment.manifest_v2()
            }
        }
    }
}
