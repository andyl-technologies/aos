//! Lends only the actual Maintenance stage to the common Root opening engine.
//!
//! No accepted Start, historical Root receipt, replacement payer or new relative
//! window enters this distinct purpose.

use crate::journal::JournalError;
use crate::normal_root::RootMaintenanceStorageStageReceivingV2;
use crate::policy_compiler::continuation_policy::RootMaintenanceStoragePolicyOriginalV2;
use crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1;
use crate::policy_compiler::root_resource_opening::{
    OpeningQueryV2, OpeningReceivingV2, RootResourceOpeningOriginalV2,
};
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::provisioning_root::maintenance_storage::MaintenanceStorageQueryDataV2;

#[derive(Default)]
pub(crate) struct RootMaintenanceStorageOpeningOriginalV2 {
    original: RootResourceOpeningOriginalV2,
    tightening: Option<Result<(), Box<dyn std::error::Error>>>,
    repeated: bool,
}

impl RootMaintenanceStorageOpeningOriginalV2 {
    pub(super) fn admit_query_once_v2(&mut self,
        stage: &mut RootMaintenanceStorageStageReceivingV2<'_, '_>, server_bytes: usize,
    ) -> Result<(), JournalError> {
        let typed_errors = std::mem::size_of::<aos_sandbox_core::InvalidOwnershipLease>()
            .checked_add(std::mem::size_of::<JournalError>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Box<dyn std::error::Error>>()))
            .and_then(|bytes| bytes.checked_mul(3)).ok_or(JournalError::JournalTooLarge)?;
        let complete = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(typed_errors))
            .and_then(|bytes| bytes.checked_add(server_bytes)).ok_or(JournalError::JournalTooLarge)?;
        self.original.admit_query_once_v1(OpeningReceivingV2::MaintenanceStorage(stage), complete)
    }

    pub(super) fn observe_query_once_v2(&mut self, bytes: &[u8]) -> Result<(), JournalError> {
        self.original.observe_query_once_v1(bytes)
    }

    pub(super) fn admit_subject_once_v2(&mut self,
        stage: &mut RootMaintenanceStorageStageReceivingV2<'_, '_>, owner_bytes: usize,
    ) -> Result<(), JournalError> {
        self.original.admit_subject_once_v1(OpeningReceivingV2::MaintenanceStorage(stage), owner_bytes)
    }

    pub(super) fn query_v2(&self) -> Result<MaintenanceStorageQueryDataV2, JournalError> {
        match self.original.query_v1()? {
            OpeningQueryV2::MaintenanceStorage(query) => Ok(query),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(super) fn tighten_inputs_once_v2(&mut self,
        assignment: &super::maintenance_assignment::RootMaintenanceAssignmentOriginalV2,
        inputs: &super::inputs::RootResourceInputsOriginalV2,
        policy: &RootMaintenanceStoragePolicyOriginalV2,
    ) -> Result<(), JournalError> {
        if self.tightening.is_some() || self.repeated {
            self.repeated = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.tightening = Some((|| -> Result<(), Box<dyn std::error::Error>> {
            assignment.require_compiled_v2()?;
            let selected = assignment.selected_v2()?;
            let lease = inputs.maintenance_lease_v2()?;
            let manifest = selected.binding.manifest();
            let expected = aos_sandbox_core::LeaseAssignment::new(manifest.manifest().sandbox(),
                manifest.manifest().incarnation(), manifest.manifest().epoch(), manifest.digest())?;
            if expected != lease.assignment()
                || manifest.manifest().node() != lease.node()
                || selected.binding.lease_digest() != lease.digest()
                || selected.binding.lease_generation() != lease.generation() {
                return Err(JournalError::ProtectedBoundary.into());
            }
            self.original.tighten_maintenance_inputs_once_v2(policy, lease)?;
            Ok(())
        })());
        if matches!(self.tightening, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn require_paid_chunk_peak_v1(&self) -> Result<(), JournalError> {
        self.original.require_paid_chunk_peak_v1()
    }

    pub(crate) fn current_cutoff_v1(&self) -> Result<u64, JournalError> {
        self.original.current_cutoff_v1()
    }

    pub(crate) fn require_current_clock_v1(&self, sample: RawPairedClockSample) -> Result<(), JournalError> {
        self.original.require_current_clock_v1(sample)
    }

    pub(super) fn horizon_v2(&self) -> Result<RootContinuationHorizonDataV1, JournalError> {
        self.original.horizon_v1()
    }

    pub(super) fn root_sample_v2(&self) -> Result<RawPairedClockSample, JournalError> {
        self.original.root_sample_v1()
    }

    pub(super) fn root_nonce_v2(&self) -> Result<[u8; 16], JournalError> {
        self.original.root_nonce_v1()
    }

    pub(super) fn funding_failed_v2(&self) -> bool {
        self.original.funding_failed_v1()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
            .or_else(|| self.tightening.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.repeated.then_some(&JournalError::ProtectedBoundary as _))
    }
}
