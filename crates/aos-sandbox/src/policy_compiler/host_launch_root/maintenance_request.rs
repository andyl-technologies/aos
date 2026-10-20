//! Joins Maintenance's exact request to its actual current native Storage cut.
//!
//! The existing retained Session verifier supplies signed18. The current C
//! reader supplies the canonical reservation and complete roster; no historical
//! Start, caller manifest, workspace identifier or empty inventory is adopted.

use super::maintenance_assignment::RootMaintenanceAssignmentOriginalV2;
use super::inputs::RootResourceInputsOriginalV2;
use super::session::RootStartResourceFinalSessionOriginalV2;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootMaintenanceStorageStageReceivingV2};
use crate::policy_compiler::provisioning_current::finality_readonly::RootCreateFinalityReadonlyOriginalV1;
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::provisioning_root::maintenance_storage::{
    MaintenanceStorageQueryDataV2, MaintenanceStorageSubjectDataV2,
};
use aos_sandbox_protocol::semantics::storage_guest_root::CanonicalStorageGuestRootArgumentsV1;

type Cause = Box<dyn std::error::Error>;

pub(super) struct RootMaintenanceStorageRequestOriginalV2 {
    inventory_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    inventory_result: Option<Result<(), Cause>>,
    inventory: RootStartResourceFinalSessionOriginalV2,
    arguments: Option<CanonicalStorageGuestRootArgumentsV1>,
    reservation: Option<crate::guest_root_publication::GuestRootPublicationReservationV1>,
    request: Option<Vec<u8>>,
    request_id: Option<[u8; 16]>,
    result: Option<Result<(), Cause>>,
    repeated: bool,
}

impl RootMaintenanceStorageRequestOriginalV2 {
    pub(super) fn new() -> Self {
        Self { inventory_funding: None, inventory_result: None,
            inventory: RootStartResourceFinalSessionOriginalV2::new(),
            arguments: None, reservation: None, request: None, request_id: None,
            result: None, repeated: false }
    }

    // Inputs' same RequestTyped204 stage prepays this finite recipe together
    // with its actual public trust decoder. The current Inventory model's full
    // receiving was already admitted by the same native Session semantic stage5.
    pub(super) fn typed_receiving_demand_v2() -> Result<ResourceVector, JournalError> {
        let body = CanonicalStorageGuestRootArgumentsV1::deadline_free_request_receiving_bytes_v2()
            .ok_or(JournalError::JournalTooLarge)?;
        let fixed = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<CanonicalStorageGuestRootArgumentsV1>()))
            .and_then(|bytes| bytes.checked_add(body.checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, fixed))
    }

    pub(super) fn observe_inventory_once_v2(&mut self,
        stage: &mut RootMaintenanceStorageStageReceivingV2<'_, '_>,
        readonly: &RootCreateFinalityReadonlyOriginalV1,
        assignment: &RootMaintenanceAssignmentOriginalV2,
        inputs: &RootResourceInputsOriginalV2,
        subject: MaintenanceStorageSubjectDataV2<'_>,
        sample: RawPairedClockSample, cutoff: u64,
    ) -> Result<(), JournalError> {
        if self.inventory_funding.is_some() {
            self.repeated = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.inventory_funding = Some(stage.admit_maintenance_current_inventory_once_v2(
            RootContinuationDemandV1::from_demand_v1(ResourceVector::ZERO)));
        if !matches!(self.inventory_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.inventory_result = Some((|| -> Result<(), Cause> {
            readonly.maintenance_current_data_v2()?.require_initial_cut_data_v3()?;
            self.inventory.observe_maintenance_storage_inventory_once_v2(readonly.session_v1()?,
                inputs.storage_manifest_v2()?, assignment, sample, cutoff)?;
            self.inventory.require_current_storage_exchange_data_v2(
                subject.inventory_request, subject.inventory_outcome)?;
            Ok(())
        })());
        if matches!(self.inventory_result, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(super) fn observe_request_once_v2(&mut self,
        stage: &RootMaintenanceStorageStageReceivingV2<'_, '_>,
        readonly: &RootCreateFinalityReadonlyOriginalV1,
        assignment: &RootMaintenanceAssignmentOriginalV2,
        inputs: &RootResourceInputsOriginalV2,
        query: MaintenanceStorageQueryDataV2, subject: MaintenanceStorageSubjectDataV2<'_>,
        sample: RawPairedClockSample, cutoff: u64,
    ) -> Result<(), JournalError> {
        if self.result.is_some() {
            self.repeated = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some((|| {
            inputs.require_maintenance_request_admitted_v2()?;
            if !matches!(self.inventory_result, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            assignment.require_inventory_cutoff_data_v2(sample, cutoff)?;
            self.inventory.require_current_storage_exchange_data_v2(
                subject.inventory_request, subject.inventory_outcome)?;
            let inventory = self.inventory.current_storage_inventory_v2()?;
            let manifest = assignment.manifest_v2()?;
            let joined = readonly.maintenance_current_data_v2()?.reserved_workspace_data_v2(
                manifest, inventory, subject.reservation,
                aos_sandbox_core::NodeId::from_bytes(stage.enrolled_node_v1()?))?;
            self.arguments = Some(*joined.arguments_v2());
            self.reservation = Some(*joined.reservation_v2());
            // The new actual Controller Root-child nonce names this method
            // exchange. Stable effect identity remains in the C reservation.
            self.request_id = Some(query.controller_nonce);
            self.request = Some(joined.arguments_v2().deadline_free_request_body_v2(query.controller_nonce)?);
            if self.request.as_deref() != Some(subject.request_body) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Ok(())
        })());
        self.require_typed_v2()
    }

    pub(super) fn require_typed_v2(&self) -> Result<(), JournalError> {
        if self.repeated || !matches!(self.inventory_funding, Some(Ok(())))
            || !matches!(self.inventory_result, Some(Ok(())))
            || !matches!(self.result, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn request_body_v2(&self) -> Result<&[u8], JournalError> {
        self.require_typed_v2()?;
        self.request.as_deref().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn arguments_v2(&self) -> Result<&CanonicalStorageGuestRootArgumentsV1, JournalError> {
        self.require_typed_v2()?;
        self.arguments.as_ref().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn request_id_v2(&self) -> Result<[u8; 16], JournalError> {
        self.require_typed_v2()?;
        self.request_id.ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn require_response_data_v2(&self,
        response: &aos_sandbox_protocol::semantics::storage_guest_root::StorageGuestRootResponseDataV2,
    ) -> Result<(), Cause> {
        self.require_typed_v2()?;
        self.reservation.as_ref().ok_or(JournalError::ProtectedBoundary)?
            .verify_response_proof(response.proof_v1())?;
        Ok(())
    }

    pub(super) fn require_current_reservation_data_v3(&self,
        current: &crate::guest_root_publication::GuestRootPublicationReservationV1,
    ) -> Result<(), JournalError> {
        self.require_typed_v2()?;
        if self.reservation.as_ref() != Some(current) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inventory_funding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.inventory.failure())
            .or_else(|| self.inventory_result.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.repeated.then_some(&JournalError::ProtectedBoundary as _))
    }
}
