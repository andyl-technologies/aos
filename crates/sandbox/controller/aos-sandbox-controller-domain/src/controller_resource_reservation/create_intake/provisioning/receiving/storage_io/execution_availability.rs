//! Routes finite C18 availability turns through the existing Session IO engine.
//!
//! Host64 precedes Storage65. Both complete native stages remain resident in
//! their same C18 scope. Completion joins authenticated outcome bytes to the
//! actual protected terminal head; it does not create an admission capability.

use super::*;
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
    AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::execution_availability::{
    ExecutionAvailabilityPhaseV2, decode_execution_availability_response_v2,
};
use aos_sandbox_protocol::host_execution_availability::observation::HostExecutionAvailabilityObservationV2;
use aos_sandbox_protocol::storage_execution_availability::StorageExecutionAvailabilityObservationV2;
use crate::controller_execution_operation::ControllerExecutionAvailabilityClientLoanV2;

#[derive(Clone, Copy)]
enum EndpointObservationDataV2 {
    Host(HostExecutionAvailabilityObservationV2),
    Storage(StorageExecutionAvailabilityObservationV2),
}

#[derive(Default)]
pub(crate) struct ExecutionAvailabilityIoOriginalV2 {
    host: StorageIoStagesV1,
    storage: StorageIoStagesV1,
    host_bind: StorageIoStagesV1,
    storage_bind: StorageIoStagesV1,
    host_observation: Option<Result<EndpointObservationDataV2, aos_sandbox_protocol::ProtocolValidationError>>,
    storage_observation: Option<Result<EndpointObservationDataV2, aos_sandbox_protocol::ProtocolValidationError>>,
    host_bind_observation: Option<Result<EndpointObservationDataV2, aos_sandbox_protocol::ProtocolValidationError>>,
    storage_bind_observation: Option<Result<EndpointObservationDataV2, aos_sandbox_protocol::ProtocolValidationError>>,
}

impl ExecutionAvailabilityIoOriginalV2 {
    pub(crate) fn preaccept_cutoff_data_v2(&self, boot: [u8; 16])
        -> Result<u64, ResourceReservationErrorV1> {
        if self.failure_v2().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        for stages in [&self.host, &self.storage] {
            let stage = &stages.apply;
            if stages.active != Some(false) || stage.phase != IoPhaseV1::Complete
                || !matches!(stage.terminal_association, Some(Ok(())))
                || !matches!(stage.native_position, Some(Ok(_)))
                || !matches!(stage.terminal_native, Some(Ok(_)))
                || !matches!(stage.request_binding, Some(Ok(())))
                || stage.terminal_identity.is_none() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        let host = match self.host_observation.as_ref() {
            Some(Ok(EndpointObservationDataV2::Host(host)))
                if host.fields().boot == boot => host.fields().cutoff,
            _ => return Err(ResourceReservationErrorV1::Conflict),
        };
        let storage = match self.storage_observation.as_ref() {
            Some(Ok(EndpointObservationDataV2::Storage(storage)))
                if storage.fields().boot == boot => storage.fields().cutoff,
            _ => return Err(ResourceReservationErrorV1::Conflict),
        };
        Ok(host.min(storage))
    }

    pub(crate) fn require_observed_before_data_v2(&self, current: u64)
        -> Result<(), ResourceReservationErrorV1> {
        match (&self.host_observation, &self.storage_observation) {
            (Some(Ok(EndpointObservationDataV2::Host(host))),
                Some(Ok(EndpointObservationDataV2::Storage(storage))))
                if host.fields().observed_clock <= current
                    && storage.fields().observed_clock <= current => Ok(()),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.host.failure().or_else(|| self.storage.failure())
            .or_else(|| self.host_bind.failure()).or_else(|| self.storage_bind.failure())
            .or_else(|| self.host_observation.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.storage_observation.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.host_bind_observation.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.storage_bind_observation.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
    }

    pub(crate) fn retained_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let preaccept = self.host.retained_demand_v1(0)?
            .checked_add(self.storage.retained_demand_v1(0)?)?;
        let with_host = preaccept.checked_add(self.host_bind.retained_demand_v1(0)?)?;
        with_host.checked_add(self.storage_bind.retained_demand_v1(0)?).map_err(Into::into)
    }
}

impl ControllerExecutionAvailabilityClientLoanV2<'_> {
    pub(in crate::controller_resource_reservation) fn availability_io_stages_v2(&mut self) -> &mut StorageIoStagesV1 {
        let active = self.active_endpoint_data_v2();
        let original = self.io_original_v2();
        match active {
            0 => &mut original.host,
            1 => &mut original.storage,
            3 => &mut original.host_bind,
            _ => &mut original.storage_bind,
        }
    }

    pub(in crate::controller_resource_reservation) fn availability_protocol_data_v2(&self) -> BrokerSessionProtocolV1 {
        if matches!(self.active_endpoint_data_v2(), 0 | 3) { BrokerSessionProtocolV1::Host }
        else { BrokerSessionProtocolV1::Storage }
    }

    pub(in crate::controller_resource_reservation) fn availability_method_data_v2(&self) -> BrokerMethod {
        if matches!(self.active_endpoint_data_v2(), 0 | 3) { BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 }
        else { BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2 }
    }

    /// Admits the first Host64 representation on the original parked C18.
    ///
    /// # Errors
    /// Refuses a different finite turn, native Session, actual receive bound or
    /// full simultaneous requirement beyond the existing C18 declaration.
    #[doc(hidden)]
    pub fn admit_host_preaccept_io_once_v2(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.active_endpoint_data_v2() != 0 { return Err(ResourceReservationErrorV1::Conflict); }
        let cutoff = self.original_cutoff_data_v2()?;
        NativeSessionIoMemberV2::ExecutionAvailability(self).admit_io_v2(journal, socket, transcript, shape, false, cutoff)
    }

    /// Admits Storage65 while retaining the actual completed Host64 stage.
    ///
    /// # Errors
    /// Refuses missing Host completion, a changed actual Storage Session, a
    /// repeated turn or an unpayable complete simultaneous representation.
    #[doc(hidden)]
    pub fn admit_storage_preaccept_io_once_v2(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.active_endpoint_data_v2() != 1 { return Err(ResourceReservationErrorV1::Conflict); }
        let cutoff = self.original_cutoff_data_v2()?;
        NativeSessionIoMemberV2::ExecutionAvailability(self).admit_io_v2(journal, socket, transcript, shape, false, cutoff)
    }

    /// Pays Host64 accepted bind while retaining both original preaccept turns.
    ///
    /// # Errors
    /// Rejects another phase, failed original source or insufficient same-C18 capacity.
    #[doc(hidden)]
    pub fn admit_host_accepted_bind_io_once_v2(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.active_endpoint_data_v2() != 3 { return Err(ResourceReservationErrorV1::Conflict); }
        let cutoff = self.original_cutoff_data_v2()?;
        NativeSessionIoMemberV2::ExecutionAvailability(self).admit_io_v2(journal, socket, transcript, shape, false, cutoff)
    }

    /// Pays Storage65 accepted bind beside all three retained preceding turns.
    ///
    /// # Errors
    /// Rejects another phase, missing Host bind or changed actual native Session.
    #[doc(hidden)]
    pub fn admit_storage_accepted_bind_io_once_v2(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.active_endpoint_data_v2() != 4 { return Err(ResourceReservationErrorV1::Conflict); }
        let cutoff = self.original_cutoff_data_v2()?;
        NativeSessionIoMemberV2::ExecutionAvailability(self).admit_io_v2(journal, socket, transcript, shape, false, cutoff)
    }

    /// Lends fixed header DATA after this same native stage admitted preparation.
    ///
    /// Both preaccept Sessions use the same proposal nonce in distinct Session
    /// namespaces. Accepted bind requires a separate finite native transition.
    ///
    /// # Errors
    /// Refuses failed/unprepared IO, another transcript or unsupported bounds.
    #[doc(hidden)]
    pub fn availability_request_header_data_v2(&mut self, journal: &Journal,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2, ResourceReservationErrorV1> {
        self.require_transport_current_v2()?;
        self.require_transport_journal_v2(journal)?;
        let nonce = self.availability_request_id_data_v2()?;
        let cutoff = self.original_cutoff_data_v2()?;
        let stage = self.availability_io_stages_v2().active_mut()?;
        if stage.phase != IoPhaseV1::Prepared || stage.failure().is_some()
            || stage.binding != transcript.session_binding() || transcript.protocol_version() != (1, 0)
        { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2 {
            protocol_major: 1, protocol_minor: 0, audience: transcript.audience(),
            request_id: nonce, deadline_boottime_nanoseconds: cutoff,
            maximum_response_bytes: transcript.negotiated_maximum_response_bytes(),
        })
    }

    fn require_availability_request_data_v2(&mut self, request: &AuthenticatedBrokerMethodRequestV1)
        -> Result<(), ResourceReservationErrorV1> {
        let context = request.execution_availability_data_v2().ok_or(ResourceReservationErrorV1::Conflict)?;
        let proposal = self.proposal_data_v2()?;
        let phase = if matches!(self.active_endpoint_data_v2(), 0 | 1) {
            ExecutionAvailabilityPhaseV2::Preaccept
        } else { ExecutionAvailabilityPhaseV2::AcceptedBind };
        let accepted = self.availability_accepted_source_data_v2()?;
        let cutoff = self.original_cutoff_data_v2()?;
        if request.method() != self.availability_method_data_v2()
            || context.phase() != phase
            || context.canonical_proposal() != proposal.encode_canonical()
            || context.canonical_accepted_source() != accepted.as_ref().map(|bytes| bytes.as_slice()).unwrap_or(&[])
            || request.request_id() != self.availability_request_id_data_v2()?
            || request.deadline_boottime_nanoseconds() > cutoff
        { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(())
    }

    /// Joins the actual signed64/65 request to this retained compiled proposal.
    ///
    /// # Errors
    /// Refuses another phase/proposal/nonce/Session or an unprepared IO stage.
    #[doc(hidden)]
    pub fn bind_availability_request_once_v2(&mut self, request: &AuthenticatedBrokerMethodRequestV1)
        -> Result<(), ResourceReservationErrorV1> {
        self.require_availability_request_data_v2(request)?;
        NativeSessionIoMemberV2::ExecutionAvailability(self).bind_request_data_once_v2(request.exact_body(), request)
    }

    /// Runs the independently owed native terminal post on the same Session.
    ///
    /// # Errors
    /// Retains changed physical owner, cookie, names or witness even after an
    /// earlier financial, request, transport or response failure.
    #[doc(hidden)]
    pub fn observe_availability_terminal_post_once_v2(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::ExecutionAvailability(self).observe_terminal_post_once_v2(journal, socket, transcript)
    }

    /// Retains actual authenticated success and its exact protected terminal head.
    ///
    /// Remote observation DATA is decoded only after the shared native stage
    /// joined the actual same-writer terminal record and independent post.
    /// Completing both turns supplies no REQUESTED or floor capability.
    ///
    /// # Errors
    /// Refuses malformed or different authenticated context, native head,
    /// proposal or original deadline; no response can renew that interval.
    #[doc(hidden)]
    pub fn finish_availability_terminal_once_v2(&mut self, journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_availability_request_data_v2(outcome.request())?;
        let active = self.active_endpoint_data_v2();
        NativeSessionIoMemberV2::ExecutionAvailability(self).finish_terminal_data_once_v2(
            outcome.request().exact_body(), journal, outcome)?;
        let cutoff = self.original_cutoff_data_v2()?;
        let proposal = self.proposal_data_v2()?;
        let source = if matches!(active, 3 | 4) { Some(self.accepted_bind_source_data_v2()?) } else { None };
        let decoded = (|| {
            let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result()
                else { return Err(changed()); };
            let bytes = decode_execution_availability_response_v2(exact_body)?;
            let observation = if matches!(active, 0 | 3) {
                EndpointObservationDataV2::Host(HostExecutionAvailabilityObservationV2::decode_canonical(&bytes)?)
            } else {
                EndpointObservationDataV2::Storage(StorageExecutionAvailabilityObservationV2::decode_canonical(&bytes)?)
            };
            let (phase, digest, request, session, signed_request, observed_cutoff, bound_source) = match observation {
                EndpointObservationDataV2::Host(value) => { let f=value.fields();
                    (f.phase,f.proposal_digest,f.request,f.session,f.signed_request,f.cutoff,f.bound_source_digest) }
                EndpointObservationDataV2::Storage(value) => { let f=value.fields();
                    (f.phase,f.proposal_digest,f.request,f.session,f.signed_request,f.cutoff,f.bound_source_digest) }
            };
            let expected_phase = if source.is_some() { ExecutionAvailabilityPhaseV2::AcceptedBind }
                else { ExecutionAvailabilityPhaseV2::Preaccept };
            let expected_source = source.map(|source| *source.digest().as_bytes()).unwrap_or([0; 32]);
            if phase != expected_phase || digest != *proposal.digest().as_bytes()
                || request != outcome.request().request_id() || session != outcome.request().session_binding()
                || signed_request != outcome.request().signed_request_digest()
                || source.is_none() && observed_cutoff > cutoff
                || bound_source != expected_source
            { return Err(changed()); }
            if source.is_some() {
                self.io_original_v2().require_bind_observation_data_v2(observation,
                    outcome.request().deadline_boottime_nanoseconds())?;
            }
            Ok(observation)
        })();
        let original = self.io_original_v2();
        let slot = match active {
            0 => &mut original.host_observation,
            1 => &mut original.storage_observation,
            3 => &mut original.host_bind_observation,
            _ => &mut original.storage_bind_observation,
        };
        if slot.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        *slot = Some(decoded);
        if !matches!(slot, Some(Ok(_))) { return Err(ResourceReservationErrorV1::Conflict); }
        self.advance_endpoint_once_v2()
    }
}

impl ExecutionAvailabilityIoOriginalV2 {
    fn require_bind_observation_data_v2(&self, current: EndpointObservationDataV2, deadline: u64)
        -> Result<(), aos_sandbox_protocol::ProtocolValidationError> {
        match current {
            EndpointObservationDataV2::Host(current) => {
                let Some(Ok(EndpointObservationDataV2::Host(previous))) = self.host_observation else {
                    return Err(changed());
                };
                let (current, previous) = (current.fields(), previous.fields());
                if current.session != previous.session || current.proposal_digest != previous.proposal_digest
                    || current.boot != previous.boot || current.first_clock != previous.first_clock
                    || current.cutoff != previous.cutoff || current.runtime_handle != previous.runtime_handle
                    || current.execution_store != previous.execution_store || current.epoch < previous.epoch
                    || current.observed_clock < previous.observed_clock || current.observed_clock >= deadline {
                    return Err(changed());
                }
            }
            EndpointObservationDataV2::Storage(current) => {
                let Some(Ok(EndpointObservationDataV2::Storage(previous))) = self.storage_observation else {
                    return Err(changed());
                };
                let (current, previous) = (current.fields(), previous.fields());
                if current.session != previous.session || current.proposal_digest != previous.proposal_digest
                    || current.boot != previous.boot || current.first_clock != previous.first_clock
                    || current.cutoff != previous.cutoff || current.floor_scope != previous.floor_scope
                    || current.main_sequence < previous.main_sequence
                    || current.checkpoint_ordinal < previous.checkpoint_ordinal
                    || current.main_sequence == previous.main_sequence && current.main_head != previous.main_head
                    || current.checkpoint_ordinal == previous.checkpoint_ordinal && current.nv_value != previous.nv_value
                    || current.observed_clock < previous.observed_clock || current.observed_clock >= deadline {
                    return Err(changed());
                }
            }
        }
        Ok(())
    }

    pub(crate) fn require_completed_accepted_bind_data_v2(&self,
        source: aos_sandbox_protocol::host_execution_no_apply::BeforeArgumentNoApplySourceDataV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.failure_v2().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        for stages in [&self.host_bind, &self.storage_bind] {
            let stage = &stages.apply;
            if stages.active != Some(false) || stage.phase != IoPhaseV1::Complete
                || !matches!(stage.terminal_association, Some(Ok(())))
                || !matches!(stage.native_position, Some(Ok(_)))
                || !matches!(stage.terminal_native, Some(Ok(_)))
                || !matches!(stage.request_binding, Some(Ok(())))
                || stage.terminal_identity.is_none() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        let digest = *source.digest().as_bytes();
        match (&self.host_bind_observation, &self.storage_bind_observation) {
            (Some(Ok(EndpointObservationDataV2::Host(host))),
                Some(Ok(EndpointObservationDataV2::Storage(storage))))
                if host.fields().bound_source_digest == digest
                    && storage.fields().bound_source_digest == digest => Ok(()),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }
}

fn changed() -> aos_sandbox_protocol::ProtocolValidationError {
    aos_sandbox_protocol::ProtocolValidationError::InvalidField("original execution availability continuation")
}

#[cfg(test)]
mod execution_bind_data_tests {
    use super::*;
    use aos_sandbox_protocol::host_execution_availability::observation::HostExecutionAvailabilityObservationFieldsV2 as HostFields;
    use aos_sandbox_protocol::storage_execution_availability::StorageExecutionAvailabilityObservationFieldsV2 as StorageFields;

    fn host() -> HostFields {
        HostFields {
            phase: ExecutionAvailabilityPhaseV2::Preaccept,
            proposal_digest: [1; 32],
            request: [2; 16],
            session: [3; 32],
            signed_request: [4; 32],
            runtime_handle: [5; 32],
            execution_store: [6; 32],
            execution_cut: [7; 32],
            host_state_cut: [8; 32],
            boot: [9; 16],
            epoch: 1,
            first_clock: 10,
            cutoff: 1000,
            observed_clock: 20,
            bound_source_digest: [0; 32],
        }
    }

    #[test]
    fn bind_preserves_original_clock_and_cutoff_while_host_cuts_advance() {
        let mut io = ExecutionAvailabilityIoOriginalV2::default();
        io.host_observation = Some(Ok(EndpointObservationDataV2::Host(
            HostExecutionAvailabilityObservationV2::new(host()).unwrap(),
        )));
        let binding = HostFields {
            phase: ExecutionAvailabilityPhaseV2::AcceptedBind,
            request: [11; 16],
            signed_request: [12; 32],
            epoch: 2,
            execution_cut: [13; 32],
            host_state_cut: [14; 32],
            observed_clock: 30,
            bound_source_digest: [15; 32],
            ..host()
        };
        let observation = |fields| {
            EndpointObservationDataV2::Host(
                HostExecutionAvailabilityObservationV2::new(fields).unwrap(),
            )
        };

        assert!(
            io.require_bind_observation_data_v2(observation(binding), 100)
                .is_ok()
        );
        assert!(
            io.require_bind_observation_data_v2(
                observation(HostFields {
                    cutoff: 1001,
                    ..binding
                }),
                100
            )
            .is_err()
        );
        assert!(
            io.require_bind_observation_data_v2(
                observation(HostFields {
                    first_clock: 11,
                    ..binding
                }),
                100
            )
            .is_err()
        );
        assert!(
            io.require_bind_observation_data_v2(observation(binding), 30)
                .is_err()
        );
    }

    #[test]
    fn storage_nv_is_opaque_and_cannot_change_without_checkpoint_progress() {
        let mut io = ExecutionAvailabilityIoOriginalV2::default();
        let previous = StorageFields {
            phase: ExecutionAvailabilityPhaseV2::Preaccept,
            proposal_digest: [1; 32],
            request: [2; 16],
            session: [3; 32],
            signed_request: [4; 32],
            floor_scope: [5; 32],
            main_head: [6; 32],
            main_sequence: 1,
            checkpoint_ordinal: 1,
            nv_value: [200; 32],
            boot: [9; 16],
            first_clock: 10,
            cutoff: 1000,
            observed_clock: 20,
            bound_source_digest: [0; 32],
        };
        io.storage_observation = Some(Ok(EndpointObservationDataV2::Storage(
            StorageExecutionAvailabilityObservationV2::new(previous).unwrap(),
        )));
        let binding = StorageFields {
            phase: ExecutionAvailabilityPhaseV2::AcceptedBind,
            request: [11; 16],
            signed_request: [12; 32],
            observed_clock: 30,
            bound_source_digest: [13; 32],
            main_head: [14; 32],
            main_sequence: 2,
            checkpoint_ordinal: 2,
            nv_value: [1; 32],
            ..previous
        };
        let observation = |fields| {
            EndpointObservationDataV2::Storage(
                StorageExecutionAvailabilityObservationV2::new(fields).unwrap(),
            )
        };

        assert!(
            io.require_bind_observation_data_v2(observation(binding), 100)
                .is_ok()
        );
        assert!(
            io.require_bind_observation_data_v2(
                observation(StorageFields {
                    checkpoint_ordinal: 1,
                    ..binding
                }),
                100
            )
            .is_err()
        );
        assert!(
            io.require_bind_observation_data_v2(
                observation(StorageFields {
                    floor_scope: [15; 32],
                    ..binding
                }),
                100
            )
            .is_err()
        );
        // Canonical observations alone never satisfy the actual native stages.
        assert!(io.host.apply.terminal_identity.is_none());
        assert!(io.storage.apply.terminal_identity.is_none());
    }
}
