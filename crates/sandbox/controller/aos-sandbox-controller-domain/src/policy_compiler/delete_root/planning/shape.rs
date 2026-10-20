//! Derives planning receiving shapes from the same actual staged native owners.

use super::{
    Reader, RootDeletePlanningAdmissionPhaseV1, RootDeletePlanningDispatchOriginalV1,
    RootDeletePlanningReceivingV1, RootOwnershipProfileOriginalV1,
    TransferNamespaceNativeOriginalV1,
};
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::delete_root::planning::{
    DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3, DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2,
    DELETE_ROOT_PLANNING_OPEN_BYTES_V3,
};

impl RootDeletePlanningReceivingV1<'_, '_, '_> {
    pub(crate) fn fixed_receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        RootDeletePlanningDispatchOriginalV1::fixed_receiving_demand_v1()
    }
}

impl RootDeletePlanningDispatchOriginalV1 {
    pub(crate) fn opening_receiving_demand_v1(
        &self,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.entered
            || !matches!(self.peer, Some(Ok(())))
            || self.opening_permit.is_some()
            || self.remainder.is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // The same permanent listener has already paid its original112-byte
        // opening allowance; only this actual purpose's additional bytes enter.
        let bytes = DELETE_ROOT_PLANNING_OPEN_BYTES_V3
            .checked_sub(112)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        Ok(ResourceVector::ZERO.with(D::NetworkBytes, bytes))
    }

    pub(crate) fn fixed_receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let pair = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(pair.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(3 * DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3))
            .and_then(|bytes| bytes.checked_add(3 * DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let clock_files = RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1
            .checked_mul(2)
            .and_then(|files| u64::try_from(files).ok())
            .ok_or_else(invalid)?;
        let clock_names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(2))
            .and_then(|names| u64::try_from(names).ok())
            .ok_or_else(invalid)?;
        let wire = DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3
            .checked_add(DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let readers = Reader::controller_current_fixed_demand_v1()
            .and_then(|controller| {
                Reader::source_current_fixed_demand_v1().and_then(|source| {
                    controller
                        .checked_add(source)
                        .map_err(|_| crate::journal::JournalError::ProtectedBoundary)
                })
            })
            .map_err(|_| invalid())?;
        readers
            .checked_add(TransferNamespaceNativeOriginalV1::fixed_demand_v1()?)?
            .checked_add(RootOwnershipProfileOriginalV1::demand_v1()?)?
            .checked_add(RootDeleteChunkPostsV1::fixed_demand_v1()?)?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, memory)
                    .with(D::OpenFiles, clock_files)
                    .with(D::MetadataEntries, clock_names)
                    // One hostile EOF byte must also be paid before native read.
                    .with(D::NetworkBytes, wire.checked_add(1).ok_or_else(invalid)?)
                    .with(D::OutputBytes, wire),
            )
            .map_err(Into::into)
    }

    pub(crate) fn receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::Conflict;
        if !self.comparing || self.first.is_some() {
            return Err(invalid());
        }
        self.challenge.require_paid_chunk_peak_v1()?;
        let phase = self.phase.ok_or_else(invalid)?;
        if self.permits[phase.index()].is_some() {
            return Err(invalid());
        }
        let mut demand = Self::fixed_receiving_demand_v1()?;
        let reached = match phase {
            RootDeletePlanningAdmissionPhaseV1::ControllerNative => 1,
            RootDeletePlanningAdmissionPhaseV1::ControllerSemantic => 2,
            RootDeletePlanningAdmissionPhaseV1::SourceNative => 3,
            RootDeletePlanningAdmissionPhaseV1::SourceSemantic => 4,
            RootDeletePlanningAdmissionPhaseV1::BootstrapTrust => 4,
        };
        for index in 0..reached {
            let result = match index {
                0 => &self.native[0],
                1 => &self.semantic[0],
                2 => &self.native[1],
                _ => &self.semantic[1],
            };
            let shape = result
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or_else(invalid)?;
            demand = demand.checked_add(*shape)?;
        }
        if matches!(phase, RootDeletePlanningAdmissionPhaseV1::BootstrapTrust) {
            let bootstrap = self.bootstrap_demand.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or_else(invalid)?;
            demand = demand.checked_add(*bootstrap)?;
        }
        Ok(aos_sandbox_model::component_receiving::without_operation_traffic_v1(demand))
    }

    pub(crate) fn planning_funding_v3(
        &self,
    ) -> Result<
        &aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1,
        ResourceReservationErrorV1,
    > {
        if !self.entered
            || !matches!(self.peer, Some(Ok(())))
            || !matches!(self.prepared, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .map(|open| &open.funding)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }
}
