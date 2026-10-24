//! Shares finite NoApply native transport with the existing genuine IO engine.
//!
//! Five separate retained stages keep their original traffic and failures. The
//! concrete C/Source loan selects each finite command; generic Session fields
//! or canonical packets cannot select a payer, reset a stage or grant settlement.

use super::*;
use crate::controller_execution_operation::ControllerExecutionNoApplyClientLoanV2;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
};

#[derive(Default)]
pub(crate) struct ExecutionNoApplyIoOriginalV2 {
    stages: [StorageIoStagesV1; 5],
    archive: [Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>; 5],
    archive_funding: [Option<Result<(), ResourceReservationErrorV1>>; 5],
}

impl ExecutionNoApplyIoOriginalV2 {
    pub(crate) fn retained_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.stages
            .iter()
            .try_fold(ResourceVector::ZERO, |sum, stage| {
                sum.checked_add(stage.retained_demand_v1(0)?)
                    .map_err(Into::into)
            })
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        for index in 0..5 {
            if let Some(cause) = self.archive[index]
                .as_ref()
                .and_then(|value| value.as_ref().err())
            {
                return Some(cause);
            }
            if let Some(cause) = self.archive_funding[index]
                .as_ref()
                .and_then(|value| value.as_ref().err())
            {
                return Some(cause);
            }
            if let Some(cause) = self.stages[index].failure() {
                return Some(cause);
            }
        }
        None
    }
}

impl ControllerExecutionNoApplyClientLoanV2<'_, '_, '_> {
    pub(in crate::controller_resource_reservation) fn no_apply_io_stages_v2(
        &mut self,
    ) -> &mut StorageIoStagesV1 {
        let active = self.no_apply_phase_data_v2();
        let original = self.no_apply_io_original_v2();
        match active {
            0 => &mut original.stages[0],
            1 => &mut original.stages[1],
            2 => &mut original.stages[2],
            3 => &mut original.stages[3],
            _ => &mut original.stages[4],
        }
    }

    /// Admits the selected finite Host flight and actual two-row archive appends.
    ///
    /// # Errors
    /// Refuses unavailable phases, reentry, changed native Session, failed
    /// geometry or demand beyond the same genuine Source/C18 declaration.
    #[doc(hidden)]
    pub fn admit_no_apply_io_once_v2(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let active = self.no_apply_phase_data_v2();
        let bound = self
            .no_apply_request_bound_v2()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if active >= 5
            || shape.request_bytes > bound
            || self.no_apply_io_original_v2().archive[active].is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let cutoff = self.no_apply_cutoff_data_v2()?;
        NativeSessionIoMemberV2::ExecutionNoApply(self)
            .admit_io_v2(journal, socket, transcript, shape, false, cutoff)?;
        let extent = self
            .no_apply_io_stages_v2()
            .apply
            .extent
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let geometry = crate::journal::broker_session_receiving::host_execution_no_apply_append_encoded_bound_v2(extent, shape.request_bytes)
            .map(|bytes| ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::StorageBytes, bytes));
        self.no_apply_io_original_v2().archive[active] = Some(geometry);
        let demand = self.no_apply_io_original_v2().archive[active]
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let complete = self.complete_transport_base_v2(demand)?;
        let funding = self.require_transport_complete_v2(complete);
        self.no_apply_io_original_v2().archive_funding[active] = Some(funding);
        if !matches!(
            self.no_apply_io_original_v2().archive_funding[active],
            Some(Ok(()))
        ) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.no_apply_io_stages_v2().retain_paid_v1(0, demand)
    }

    /// Returns header DATA only for this genuine prepared native phase.
    ///
    /// # Errors
    /// Refuses changed originals, another Session, unavailable nonce or stage.
    #[doc(hidden)]
    pub fn no_apply_request_header_data_v2(&mut self, journal: &Journal,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2, ResourceReservationErrorV1>{
        self.require_transport_current_v2()?;
        self.require_transport_journal_v2(journal)?;
        let request_id = self.no_apply_request_id_data_v2()?;
        let cutoff = self.no_apply_cutoff_data_v2()?;
        let stage = self.no_apply_io_stages_v2().active_mut()?;
        if stage.phase != IoPhaseV1::Prepared
            || stage.failure().is_some()
            || stage.binding != transcript.session_binding()
            || transcript.protocol_version() != (1, 0)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2 {
            protocol_major: 1, protocol_minor: 0, audience: transcript.audience(),
            request_id, deadline_boottime_nanoseconds: cutoff,
            maximum_response_bytes: transcript.negotiated_maximum_response_bytes(),
        })
    }

    /// Binds the exact private finite command before the shared native send.
    ///
    /// # Errors
    /// Refuses foreign method/source/nonce/cutoff/body or changed native stage.
    #[doc(hidden)]
    pub fn bind_no_apply_request_once_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_no_apply_request_data_v2(request)?;
        NativeSessionIoMemberV2::ExecutionNoApply(self)
            .bind_request_data_once_v2(request.exact_body(), request)
    }

    /// Runs the same Session's independent post even after financial refusal.
    ///
    /// # Errors
    /// Retains the actual names, witness, endpoint or socket refusal.
    #[doc(hidden)]
    pub fn observe_no_apply_terminal_post_once_v2(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::ExecutionNoApply(self)
            .observe_terminal_post_once_v2(journal, socket, transcript)
    }

    /// Joins actual terminal/native ownership before decoding39/42/43 DATA.
    ///
    /// # Errors
    /// Refuses mismatched canonical request, actual protected head, failed
    /// native post, malformed response or changed immutable terminal/lease.
    #[doc(hidden)]
    pub fn finish_no_apply_terminal_once_v2(
        &mut self,
        journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_no_apply_request_data_v2(outcome.request())?;
        NativeSessionIoMemberV2::ExecutionNoApply(self).finish_terminal_data_once_v2(
            outcome.request().exact_body(),
            journal,
            outcome,
        )?;
        self.retain_no_apply_terminal_once_v2(outcome)
    }
}
