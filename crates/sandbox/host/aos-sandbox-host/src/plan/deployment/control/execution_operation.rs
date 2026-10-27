//! Lends only the same intrinsic Host original's once-consumed execution phase.
//!
//! This private borrower is created from the authenticated Session request
//! after the original enrollment latch. Both PID1 observations use the same
//! readonly manager, retained native destinations and permanently reserved
//! phase. A refused primary cannot suppress its independently prepaid post.

use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_model::ResourceVector;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};

use super::{HostComponentControlStartupV2, FirstCauseV2, MAXIMUM_ATTEMPTS,
    execution_receiving::{Phase, Request, AcceptedContinuationV2}};
use crate::{HostError, Result};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum HostExecutionLoanPurposeV4 {
    Initial,
    ResidentStop,
    StopContainment,
    ExecutionMonitor { ordinal: u64 },
    ExecutionQuery { sequence: u64 },
    Availability,
    RetainedAvailabilityAccept,
}

pub(crate) struct HostExecutionReceivingLoanV2<'original> {
    original: &'original mut HostComponentControlStartupV2,
    purpose: HostExecutionLoanPurposeV4,
    phase: Phase,
    request: Request,
    original_request: Request,
    continuation: Option<AcceptedContinuationV2>,
    manager_slot: usize,
    round_start: usize,
    before_entered: bool,
    after_entered: bool,
    settled: bool,
}

impl HostExecutionReceivingLoanV2<'_> {
    pub(crate) const fn observation_round_start_data_v2(&self) -> usize {
        self.round_start
    }
}

impl HostComponentControlStartupV2 {
    pub(crate) fn begin_accept_with_retained_availability_v2<'original>(
        &'original mut self, available: Request, preparation: Request,
        authenticated: &AuthenticatedBrokerMethodRequestV1, complete: ResourceVector,
    ) -> Result<HostExecutionReceivingLoanV2<'original>> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some()
            || authenticated.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || authenticated.method() != BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2
        { return Err(HostError::Fence("Host retained Accept purpose is unavailable")); }
        let request = Request { id: authenticated.request_id(), session: authenticated.session_binding(), signed: authenticated.signed_request_digest() };
        if self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(super::execution_receiving::Closed)
            .and_then(|owner| owner.begin_accept_with_retained_availability_v2(available, preparation, request, complete)).is_err()
        {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("Host Accept cannot retain its exact consumed Prepare19"));
        }
        Ok(HostExecutionReceivingLoanV2 { original: self, purpose: HostExecutionLoanPurposeV4::RetainedAvailabilityAccept,
            phase: Phase::Accept, original_request: request, request, continuation: None,
            manager_slot: Phase::Accept.index(), round_start: MAXIMUM_ATTEMPTS + Phase::Accept.index() * 2,
            before_entered: false, after_entered: false, settled: false })
    }

    pub(crate) fn require_argument_boot_v2(&self, protected_boot: [u8; 16]) -> Result<()> {
        self.require_admitted_original()?;
        if !self.original_boot.as_ref().and_then(|result| result.as_ref().ok())
            .is_some_and(|boot| boot.into_bytes() == protected_boot)
        {
            return Err(HostError::Fence("Host argument Session boot differs from its same original"));
        }
        Ok(())
    }

    pub(crate) fn argument_observation_demand_v2(&self,
        request: &AuthenticatedBrokerMethodRequestV1) -> Result<ResourceVector>
    {
        self.require_admitted_original()?;
        match request.method() {
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
                | BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
                | BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => (),
            _ => return Err(HostError::Fence("Host argument observation purpose is unavailable")),
        };
        let intervals = if request.method() == BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 { 3 } else { 1 };
        self.execution_observation_demand_v2(intervals)
    }

    pub(crate) fn retained_accept_observation_demand_v2(&self) -> Result<ResourceVector> {
        self.require_admitted_original()?;
        self.execution_observation_demand_for_maximum_v4(
            self.retained_accept_materialization_maximum_v2()?, 3)
    }

    fn retained_accept_materialization_maximum_v2(&self) -> Result<usize> {
        let schedule = self.manager_schedule.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host retained Accept has no original schedule"))?;
        self.manager_original.as_ref()
            .ok_or(HostError::Fence("Host retained Accept has no same manager"))?
            .materialization_extent_v2().1
            .checked_add(schedule.phase_materialized_bytes.checked_mul(3)
                .ok_or(HostError::ResourceExhausted)?)
            .ok_or(HostError::ResourceExhausted)
    }

    pub(crate) fn launch_observation_demand_v2(&self) -> Result<ResourceVector> {
        self.require_admitted_original()?;
        self.execution_observation_demand_v2(1)
    }

    fn execution_observation_demand_v2(&self, intervals: usize) -> Result<ResourceVector> {
        let schedule = self.manager_schedule.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host argument has no original readonly schedule"))?;
        let materialized = schedule.startup_materialized_bytes.checked_add(
            schedule.phase_materialized_bytes.checked_mul(intervals).ok_or(HostError::ResourceExhausted)?)
            .ok_or(HostError::ResourceExhausted)?;
        self.execution_observation_demand_for_maximum_v4(materialized, intervals)
    }

    pub(super) fn execution_observation_demand_for_maximum_v4(
        &self,
        materialized: usize,
        intervals: usize,
    ) -> Result<ResourceVector> {
        use aos_sandbox_model::ResourceDimension as D;
        use aos_sandbox_broker::receiving::OriginalEnrollmentPairAttemptV1;
        use aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1;

        let schedule = self.manager_schedule.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host observation has no original readonly schedule"))?;
        let native = schedule.initial;
        let phase_schedule = aos_systemd_client::ReadonlyPropertyReceiveScheduleV2::new(
            native.outgoing_messages(), native.incoming_messages(), native.maximum_message_bytes(),
            native.maximum_request_bytes(), materialized,
        ).map_err(|_| HostError::ResourceExhausted)?;
        let pair = OriginalEnrollmentPairAttemptV1::receiving_memory_bytes_v2()
            .ok_or(HostError::ResourceExhausted)?;
        let boot = RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()
            .ok_or(HostError::ResourceExhausted)?;
        let (subject_memory, subject_files, _) =
            aos_sandbox_linux::guest_confinement::CurrentThreadSubjectOriginalV1::receiving_demand_v1()
                .ok_or(HostError::ResourceExhausted)?;
        let (negative_memory, negative_files, _) =
            aos_sandbox_linux::pidfd::PidFdNegativeIdentityOriginalV1::receiving_demand_v1()
                .ok_or(HostError::ResourceExhausted)?;
        let memory = aos_systemd_client::ReadonlyPropertyManagerOriginalV2::receiving_memory_bytes_v2(phase_schedule)
            .and_then(|memory| memory.checked_add(2 * pair))
            .and_then(|memory| memory.checked_add(2 * boot))
            .and_then(|memory| memory.checked_add(2 * (65_536 + 4096)))
            .and_then(|memory| memory.checked_add(subject_memory.checked_mul(2)?))
            .and_then(|memory| memory.checked_add(negative_memory))
            .ok_or(HostError::ResourceExhausted)?;
        let network = schedule.phase_outgoing_messages.checked_mul(native.maximum_request_bytes())
            .and_then(|request_bytes| request_bytes.checked_add(schedule.phase_materialized_bytes))
            .ok_or(HostError::ResourceExhausted)?;
        let one = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| HostError::ResourceExhausted)?)
            .with(D::OpenFiles, u64::try_from(subject_files.checked_mul(2)
                .and_then(|files| files.checked_add(4))
                .and_then(|files| files.checked_add(negative_files)).ok_or(HostError::ResourceExhausted)?)
                .map_err(|_| HostError::ResourceExhausted)?)
            .with(D::MetadataEntries, 5)
            .with(D::NetworkBytes, u64::try_from(network).map_err(|_| HostError::ResourceExhausted)?);
        let mut complete = ResourceVector::ZERO;
        for _ in 0..intervals {
            complete = complete.checked_add(one).map_err(|_| HostError::ResourceExhausted)?;
        }
        if intervals == 3 {
            // Accept remains resident. Authorize's two complete samples dispose
            // at authenticated Sent+posts before this SAME original can admit
            // Observe. Failed/partial Authorize blocks Observe below. Only the
            // native descriptor peak is shared; bytes and traffic stay summed.
            let files = one.get(D::OpenFiles).checked_mul(2)
                .ok_or(HostError::ResourceExhausted)?;
            complete = complete.with(D::OpenFiles, files);
        }
        Ok(complete)
    }

    pub(crate) fn retire_authenticated_argument_v2(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() {
            return Err(HostError::Fence("Host execution original has unresolved post debt"));
        }
        let phase = match request.method() {
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 => Phase::Prepare,
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 => Phase::Prepare,
            BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => Phase::Accept,
            _ => return Err(HostError::Fence("Host execution disposal purpose differs")),
        };
        let request = Request { id: request.request_id(), session: request.session_binding(),
            signed: request.signed_request_digest() };
        if phase == Phase::Prepare && self.execution_receiving.as_ref()
            .and_then(|result| result.as_ref().ok()).is_some_and(|owner| owner.is_availability_original_v2(request))
        {
            return self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(HostError::Fence("Host availability original disappeared"))?
                .retain_authenticated_availability_v2(request)
                .map_err(|_| HostError::Fence("Host availability authenticated interval cannot retain"));
        }
        self.retire_execution_samples_v2(MAXIMUM_ATTEMPTS + phase.index() * 2,
            2, phase.index())?;
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("Host execution intrinsic original is absent"))?
            .retire_after_disposal(phase, request)
            .map_err(|_| HostError::Fence("Host execution authenticated interval cannot retire"))
    }

    pub(crate) fn prepare_authenticated_launch_disposal_v2<'original>(
        &'original mut self,
        authenticated: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<HostLaunchDisposalV2<'original>> {
        self.require_admitted_original()?;
        if authenticated.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || authenticated.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            || self.armed || self.first.is_some()
        {
            return Err(HostError::Fence("Host launch has unresolved authenticated post debt"));
        }
        let request = Request {
            id: authenticated.request_id(), session: authenticated.session_binding(),
            signed: authenticated.signed_request_digest(),
        };
        self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host launch intrinsic original is absent"))?
            .require_pending_launch_v2(request)
            .map_err(|_| HostError::Fence("Host launch response differs from its consumed original"))?;
        self.retire_execution_samples_v2(MAXIMUM_ATTEMPTS + 8, 2, 4)?;
        Ok(HostLaunchDisposalV2 { original: self, request, completed: false })
    }

    // Both callers select a fixed real schedule and have already disposed
    // their complete positive native capsule at authenticated Sent. The same
    // manager interval ends before either consumed operation is released.
    pub(super) fn retire_execution_samples_v2(&mut self, first: usize, count: usize,
        manager_slot: usize) -> Result<()> {
        for round in first .. first + count {
            if self.attempts[round].action.as_ref().is_none_or(|result| result.is_err()) {
                return Err(HostError::Fence("Host execution disposal lost its actual native posts"));
            }
        }
        // The enclosing Host caller has already disposed its whole positive
        // stage. Drop both actual samples before ending the consumed operation.
        for round in first .. first + count {
            drop(std::mem::replace(&mut self.attempts[round], super::OriginAttemptV2::new()));
        }
        let manager = self.manager_original.as_ref()
            .ok_or(HostError::Fence("Host execution same manager is absent"))?;
        let result = manager.retire_readonly_interval_v2();
        self.record_manager_growth_v4(manager_slot, result);
        if self.manager_growth_v4(manager_slot).is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(FirstCauseV2::ExecutionManager(manager_slot));
            return Err(HostError::Fence("Host execution raw interval cannot dispose"));
        }
        Ok(())
    }

    pub(crate) fn begin_argument_receiving_v2<'original>(&'original mut self,
        request: &AuthenticatedBrokerMethodRequestV1, complete: ResourceVector,
    ) -> Result<HostExecutionReceivingLoanV2<'original>> {
        self.require_admitted_original()?;
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || self.execution_origin.is_none() || self.armed
        {
            return Err(HostError::Fence("Host execution has no current original Session"));
        }
        let phase = match request.method() {
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 => Phase::Prepare,
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 => Phase::Prepare,
            BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => Phase::Accept,
            _ => return Err(HostError::Fence("Host execution receiving purpose is unavailable")),
        };
        let availability = request.method() == BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2;
        let request = Request { id: request.request_id(), session: request.session_binding(),
            signed: request.signed_request_digest() };
        let admitted = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(super::execution_receiving::Closed)
            .and_then(|owner| {
                owner.begin(phase, request)?;
                owner.require_complete(phase, request, complete)?;
                if availability { owner.mark_availability_original_v2(request)?; }
                Ok(())
            });
        if admitted.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("Host execution phase capacity is insufficient or spent"));
        }
        Ok(HostExecutionReceivingLoanV2 { original: self, purpose: HostExecutionLoanPurposeV4::Initial, phase, request,
            original_request: request, continuation: None, manager_slot: phase.index(),
            round_start: MAXIMUM_ATTEMPTS + phase.index() * 2,
            before_entered: false, after_entered: false, settled: false })
    }
    pub(crate) fn availability_interval_demand_v2(&self, original: Request)
        -> Result<(ResourceVector, usize)>
    {
        let (observation, maximum) = self.recurring_observation_demand_v4()?;
        let history = self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host availability original is absent"))?
            .availability_history_demand_v2(original)
            .map_err(|_| HostError::Fence("Host availability has unresolved authenticated custody"))?;
        Ok((observation.checked_add(history).map_err(|_| HostError::ResourceExhausted)?, maximum))
    }

    pub(crate) fn begin_availability_interval_v2(
        &mut self, original_request: Request, authenticated: &AuthenticatedBrokerMethodRequestV1,
        complete: ResourceVector, maximum: usize,
    ) -> Result<HostExecutionReceivingLoanV2<'_>> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some()
            || authenticated.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || !matches!(authenticated.method(),
                BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
                    | BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
                    | BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
                    | BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                    | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY
                    | BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
                    | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2)
        { return Err(HostError::Fence("Host availability continuation purpose is unavailable")); }
        let request = Request { id: authenticated.request_id(), session: authenticated.session_binding(), signed: authenticated.signed_request_digest() };
        let admitted = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("Host availability financial original is absent"))?
            .begin_availability_interval_v2(original_request, request, complete);
        if admitted.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("Host availability exceeds its same consumed Prepare19"));
        }
        let destinations = self.append_recurring_observation_destinations_v4(maximum)?;
        Ok(HostExecutionReceivingLoanV2 {
            original: self, purpose: HostExecutionLoanPurposeV4::Availability,
            phase: Phase::Prepare, original_request, request, continuation: None,
            manager_slot: destinations.manager_slot, round_start: destinations.round_start,
            before_entered: false, after_entered: false, settled: false,
        })
    }

    pub(crate) fn finish_authenticated_availability_interval_v2(
        &mut self, original: Request, authenticated: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() { return Err(HostError::Fence("Host availability retains native post debt")); }
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("Host availability original disappeared"))?
            .finish_availability_authenticated_v2(original, Request { id: authenticated.request_id(),
                session: authenticated.session_binding(), signed: authenticated.signed_request_digest() })
            .map_err(|_| HostError::Fence("Host availability authenticated continuation differs"))
    }

    pub(crate) fn retain_authenticated_availability_preparation_v2(
        &mut self, available: Request, authenticated: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some()
            || authenticated.method() != BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
        { return Err(HostError::Fence("Host availability preparation retains post debt")); }
        let preparation = Request { id: authenticated.request_id(), session: authenticated.session_binding(), signed: authenticated.signed_request_digest() };
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("Host availability preparation owner disappeared"))?
            .retain_authenticated_availability_preparation_v2(available, preparation)
            .map_err(|_| HostError::Fence("Host preparation differs from its original consumed19"))
    }

    pub(crate) fn begin_launch_receiving_v2<'original>(
        &'original mut self,
        authenticated: &AuthenticatedBrokerMethodRequestV1,
        validated: &aos_sandbox_protocol::ValidatedRuntimeRequest,
        admitted: &aos_sandbox_broker::VerifiedBrokerAdmission,
        complete: ResourceVector,
    ) -> Result<HostExecutionReceivingLoanV2<'original>> {
        use aos_sandbox_api::aos::sandbox::local::v1::RuntimeAction;
        use aos_sandbox_model::BrokerVerb;
        use sha2::{Digest as _, Sha256};

        self.require_admitted_original()?;
        if authenticated.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || authenticated.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            || validated.action() != RuntimeAction::RUNTIME_ACTION_LAUNCH
            || validated.header().request_id() != &authenticated.request_id()
            || admitted.intersection.verb() != BrokerVerb::HostLaunch
            || admitted.effect.request_id() != &authenticated.request_id()
            || admitted.effect.transport_request_digest().as_bytes()
                != &<[u8; 32]>::from(Sha256::digest(authenticated.exact_body()))
            || self.execution_origin.is_none() || self.armed
        {
            return Err(HostError::Fence("Host launch has no exact signed admission and original"));
        }
        let request = Request {
            id: authenticated.request_id(), session: authenticated.session_binding(),
            signed: authenticated.signed_request_digest(),
        };
        let admitted = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(super::execution_receiving::Closed)
            .and_then(|owner| {
                owner.begin(Phase::Launch, request)?;
                owner.require_complete(Phase::Launch, request, complete)
            });
        if admitted.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("Host launch capacity is insufficient or occupied"));
        }
        Ok(HostExecutionReceivingLoanV2 {
            original: self, purpose: HostExecutionLoanPurposeV4::Initial,
            phase: Phase::Launch, request, original_request: request,
            continuation: None, manager_slot: 4,
            round_start: MAXIMUM_ATTEMPTS + 8,
            before_entered: false, after_entered: false, settled: false,
        })
    }

    pub(crate) fn capture_stop_observation_demand_v4(&self) -> Result<(ResourceVector, usize)> {
        use aos_sandbox_model::ResourceDimension as D;

        // Pure shape calculation may run after the old execution has failed.
        // The genuine fresh Stop factory below still owns all admission.
        let (native, maximum) = self.recurring_observation_geometry_v4()?;
        let bytes = std::mem::size_of::<HostExecutionReceivingLoanV2<'_>>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::HostCaptureNegativeLoanV3>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<crate::broker::HostCaptureFailedStageV4>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                crate::storage_existing_output::capture::StorageCaptureStopParentV4<'_>>().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(HostError::ResourceExhausted)?;
        Ok((native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(|_| HostError::ResourceExhausted)?, maximum))
    }

    pub(crate) fn capture_stop_failure_v4(
        &self, request: ([u8; 16], [u8; 32], [u8; 32]), after: bool,
    ) -> Option<&dyn std::error::Error> {
        let request = Request { id: request.0, session: request.1, signed: request.2 };
        let receiving = self.execution_receiving.as_ref()?.as_ref().ok()?;
        if let Some(cause) = receiving.capture_stop_financial_failure_v4(request) { return Some(cause); }
        if receiving.capture_stop_allocation_refused_v4(request) {
            return self.attempts.allocation_failure_v4();
        }
        let (round, _) = receiving.capture_stop_destinations_v4(request)?;
        self.recurring_leaf_failure_v4(round + usize::from(after))
    }

    pub(crate) fn begin_capture_stop_receiving_v4<'original>(
        &'original mut self,
        failed: &crate::broker::HostCaptureFailedStageV4,
        negative: &super::HostCaptureNegativeLoanV3,
        held: &crate::storage_existing_output::capture::StorageCaptureStopParentV4<'_>,
        authenticated: &AuthenticatedBrokerMethodRequestV1,
        validated: &aos_sandbox_protocol::ValidatedRuntimeRequest,
        admitted: &aos_sandbox_broker::VerifiedBrokerAdmission,
        complete: ResourceVector,
        maximum_materialized_bytes: usize,
    ) -> Result<HostExecutionReceivingLoanV2<'original>> {
        use aos_sandbox_api::aos::sandbox::local::v1::RuntimeAction;
        use aos_sandbox_model::BrokerVerb;
        use sha2::{Digest as _, Sha256};

        failed.require_failed_resident_v4()?;
        let assignment = validated.fence().broker_assignment()
            .map_err(|_| HostError::Fence("Capture Stop assignment is invalid"))?;
        if !self.admitted || self.execution_origin.is_none()
            || authenticated.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || authenticated.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            || validated.action() != RuntimeAction::RUNTIME_ACTION_STOP
            || validated.header().request_id() != &authenticated.request_id()
            || admitted.intersection.verb() != BrokerVerb::HostStop
            || admitted.effect.request_id() != &authenticated.request_id()
            || admitted.effect.transport_request_digest().as_bytes()
                != &<[u8; 32]>::from(Sha256::digest(authenticated.exact_body()))
            || admitted.fence.assignment() != held.source_v4().original_source_v1().assignment()
            || assignment != admitted.fence.assignment()
            || negative.source_digest_v3() != held.source_v4().source_digest_v2()
            || negative.execution_v3() != failed.execution_v4()
            || negative.execution_v3() != held.source_v4().lifetime_v2().execution_v2()
            || failed.accept_v4() != negative.reservation_for_stop_v4().accept_for_stop_v4()
        {
            return Err(HostError::Fence("Capture containment lacks its exact fresh signed Stop and failed original"));
        }
        let (native, maximum) = self.capture_stop_observation_demand_v4()?;
        if maximum != maximum_materialized_bytes || !native.is_within(complete) {
            return Err(HostError::Fence("Capture Stop native supplier differs from its complete admission"));
        }
        let request = Request { id: authenticated.request_id(), session: authenticated.session_binding(),
            signed: authenticated.signed_request_digest() };
        let launch = negative.reservation_for_stop_v4().launch_for_stop_v4();
        let admitted = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(super::execution_receiving::Closed)
            .and_then(|owner| owner.begin_capture_stop_containment_v4(
                negative.reservation_for_stop_v4(), request, complete,
            ));
        if admitted.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("fresh Capture Stop exceeds its same consumed control capacity"));
        }
        let destinations = self.append_capture_stop_destinations_v4(launch, request, maximum)?;
        let round_start = destinations.round_start;
        let manager_slot = destinations.manager_slot;
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("Capture Stop intrinsic original disappeared"))?
            .park_capture_stop_destinations_v4(launch, request, destinations)
            .map_err(|_| HostError::Fence("Capture Stop lost its actual native destinations"))?;
        Ok(HostExecutionReceivingLoanV2 {
            original: self, purpose: HostExecutionLoanPurposeV4::StopContainment,
            phase: Phase::Launch, request, original_request: launch, continuation: None,
            manager_slot, round_start, before_entered: false, after_entered: false, settled: false,
        })
    }

    pub(crate) fn begin_resident_stop_receiving_v4<'original>(
        &'original mut self,
        launch: super::execution_receiving::Request,
        authenticated: &AuthenticatedBrokerMethodRequestV1,
        validated: &aos_sandbox_protocol::ValidatedRuntimeRequest,
        admitted: &aos_sandbox_broker::VerifiedBrokerAdmission,
        complete: ResourceVector,
        maximum_materialized_bytes: usize,
    ) -> Result<HostExecutionReceivingLoanV2<'original>> {
        use aos_sandbox_api::aos::sandbox::local::v1::RuntimeAction;
        use aos_sandbox_model::BrokerVerb;
        use sha2::{Digest as _, Sha256};

        self.require_admitted_original()?;
        if authenticated.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || authenticated.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            || validated.action() != RuntimeAction::RUNTIME_ACTION_STOP
            || validated.header().request_id() != &authenticated.request_id()
            || admitted.intersection.verb() != BrokerVerb::HostStop
            || admitted.effect.request_id() != &authenticated.request_id()
            || admitted.effect.transport_request_digest().as_bytes()
                != &<[u8; 32]>::from(Sha256::digest(authenticated.exact_body()))
            || self.execution_origin.is_none()
        {
            return Err(HostError::Fence("resident Stop lacks its exact fresh signed admission"));
        }
        let (native, maximum) = self.recurring_observation_demand_v4()?;
        if maximum != maximum_materialized_bytes || !native.is_within(complete) {
            return Err(HostError::Fence("resident Stop native supplier differs from its actual destination"));
        }
        let request = Request {
            id: authenticated.request_id(),
            session: authenticated.session_binding(),
            signed: authenticated.signed_request_digest(),
        };
        let admitted = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(super::execution_receiving::Closed)
            .and_then(|owner| owner.begin_resident_stop_v4(launch, request, complete));
        if admitted.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("resident Stop capacity is insufficient or occupied"));
        }
        // The actual upper supplier included this pair's complete new backing
        // and native peak before the same-flight comparison above.
        let destinations = self.append_recurring_observation_destinations_v4(maximum_materialized_bytes)?;
        let round_start = destinations.round_start;
        let manager_slot = destinations.manager_slot;
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("resident Stop intrinsic original disappeared"))?
            .park_resident_stop_destinations_v4(launch, request, destinations)
            .map_err(|_| HostError::Fence("resident Stop lost its actual native destinations"))?;
        Ok(HostExecutionReceivingLoanV2 {
            original: self,
            purpose: HostExecutionLoanPurposeV4::ResidentStop,
            phase: Phase::Launch,
            request,
            original_request: launch,
            continuation: None,
            manager_slot,
            round_start,
            before_entered: false,
            after_entered: false,
            settled: false,
        })
    }

    pub(crate) fn prepare_authenticated_resident_stop_disposal_identity_v4(
        &mut self,
        launch: Request,
        request: Request,
    ) -> Result<HostResidentStopDisposalV4<'_>> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() {
            return Err(HostError::Fence("Stop disposal has unresolved authenticated post debt"));
        }
        let owner = self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Stop disposal intrinsic owner is absent"))?;
        owner.require_resident_stop_owed_v4(launch, request)
            .map_err(|_| HostError::Fence("Stop disposal differs from its actual resident Launch"))?;
        let destinations = owner.resident_stop_destinations_v4(request)
            .map_err(|_| HostError::Fence("Stop disposal differs from its actual completed interval"))?;
        self.retire_execution_samples_v2(destinations.0, 2, destinations.1)?;
        Ok(HostResidentStopDisposalV4 { original: self, launch, request,
            kind: HostResidentStopDisposalKindV1::Authenticated, completed: false })
    }

    pub(crate) fn prepare_unsent_stop_disposal_v1(
        &mut self,
        launch: Request,
        proof: &crate::broker::HostResidentStopNativeCompletedV4,
    ) -> Result<HostResidentStopDisposalV4<'_>> {
        self.require_admitted_original()?;
        let owner = self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("unsent Stop disposal intrinsic owner is absent"))?;
        owner.require_unsent_native_stop_v1(launch, proof)
            .map_err(|_| HostError::Fence("unsent Stop disposal native original differs"))?;
        let request = proof.request_identity_v4();
        let request = Request { id: request.0, session: request.1, signed: request.2 };
        let destinations = owner.resident_stop_destinations_v4(request)
            .map_err(|_| HostError::Fence("unsent Stop disposal lacks its actual posts"))?;
        self.retire_execution_samples_v2(destinations.0, 2, destinations.1)?;
        Ok(HostResidentStopDisposalV4 { original: self, launch, request,
            kind: HostResidentStopDisposalKindV1::UnsentNativePositive, completed: false })
    }

    pub(crate) fn retain_authenticated_accept_v2(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some()
            || request.method() != BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2
        { return Err(HostError::Fence("Host accepted interval is incomplete")); }
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("Host accepted original is absent"))?
            .retain_authenticated_accept_v2(Request { id: request.request_id(),
                session: request.session_binding(), signed: request.signed_request_digest() })
            .map_err(|_| HostError::Fence("Host accepted original cannot transfer"))
    }

    pub(crate) fn begin_accepted_execution_v2(
        &mut self, stage: AcceptedContinuationV2,
        original_request: Request, request: &AuthenticatedBrokerMethodRequestV1,
        complete: ResourceVector,
    ) -> Result<HostExecutionReceivingLoanV2<'_>> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some()
            || request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
        { return Err(HostError::Fence("Host accepted execution scope is unavailable")); }
        if stage == AcceptedContinuationV2::Observe
            && !(MAXIMUM_ATTEMPTS + 4 .. MAXIMUM_ATTEMPTS + 6).all(|round| {
                self.attempts[round].positive_scratch_disposed
                    && matches!(self.attempts[round].action, Some(Ok(())))
            })
        {
            return Err(HostError::Fence("Host Observe still holds Authorize native scratch"));
        }
        let request = Request { id: request.request_id(), session: request.session_binding(),
            signed: request.signed_request_digest() };
        let entered = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(super::execution_receiving::Closed)
            .and_then(|owner| owner.begin_accepted_continuation_v2(stage, original_request, request, complete));
        if entered.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("Host accepted continuation exceeds its same original"));
        }
        Ok(HostExecutionReceivingLoanV2 { original: self, purpose: HostExecutionLoanPurposeV4::Initial, phase: Phase::Accept,
            original_request, request, continuation: Some(stage),
            manager_slot: 2 + stage.index(), round_start: MAXIMUM_ATTEMPTS + 4 + stage.index() * 2,
            before_entered: false, after_entered: false, settled: false })
    }

    pub(crate) fn require_accepted_terminal_v2(&self, original: Request) -> Result<()> {
        self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host accepted terminal original is absent"))?
            .require_owed_post(Phase::Accept, original)
            .map_err(|_| HostError::Fence("Host accepted terminal was not prepaid"))
    }

    pub(crate) fn require_authorize_samples_positive_v2(
        &self, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.require_accepted_samples_positive_v5(AcceptedContinuationV2::Authorize, request)
            .map(|_| ())
    }

    pub(crate) fn require_first_observe_samples_positive_v5(
        &self, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.require_accepted_samples_positive_v5(AcceptedContinuationV2::Observe, request)
            .map(|_| ())
    }

    fn require_accepted_samples_positive_v5(
        &self, stage: AcceptedContinuationV2, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<usize> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() {
            return Err(HostError::Fence("Host accepted continuation retains native debt"));
        }
        self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host accepted original is absent"))?
            .require_authenticated_continuation_v5(stage, Request { id: request.request_id(),
                session: request.session_binding(), signed: request.signed_request_digest() })
            .map_err(|_| HostError::Fence("Host accepted authenticated boundary differs"))?;
        let first = MAXIMUM_ATTEMPTS + 4 + stage.index() * 2;
        for round in first .. first + 2 {
            self.attempts[round].require_positive_leaf_v2()?;
        }
        Ok(first)
    }

    pub(crate) fn dispose_authorize_samples_positive_v2(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.dispose_accepted_samples_positive_v5(AcceptedContinuationV2::Authorize, request)
    }

    pub(crate) fn dispose_first_observe_samples_positive_v5(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.dispose_accepted_samples_positive_v5(AcceptedContinuationV2::Observe, request)
    }

    fn dispose_accepted_samples_positive_v5(
        &mut self, stage: AcceptedContinuationV2, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        let first = self.require_accepted_samples_positive_v5(stage, request)?;
        for round in first .. first + 2 {
            self.attempts[round].dispose_positive_leaf_v2()?;
        }
        // The same Accept readonly interval and consumed operation remain
        // occupied. Completed native leaves alone become non-reentrant tombstones.
        Ok(())
    }

    pub(crate) fn retain_capture_after_observe_v3(
        &mut self, launch: Request, accept: Request, observe: Request,
    ) -> Result<()> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() {
            return Err(HostError::Fence("Host Capture retains native post debt"));
        }
        self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host Capture intrinsic original is absent"))?
            .require_capture_after_observe_v3(launch, accept, observe)
            .map_err(|_| HostError::Fence("Host Capture consumed flight association differs"))
    }

    pub(crate) fn retire_accepted_after_disposal_v2(
        &mut self, original: Request,
    ) -> Result<()> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() { return Err(HostError::Fence("Host accepted post debt remains")); }
        self.retire_execution_samples_v2(MAXIMUM_ATTEMPTS + 2, 6, 1)?;
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("Host accepted original is absent"))?
            .retire_after_disposal(Phase::Accept, original)
            .map_err(|_| HostError::Fence("Host accepted original cannot retire before whole disposal"))
    }

    pub(crate) fn finish_authenticated_accepted_execution_v2(
        &mut self, stage: AcceptedContinuationV2,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() {
            return Err(HostError::Fence("Host accepted execution native posts are incomplete"));
        }
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("Host accepted original is absent"))?
            .finish_accepted_continuation_authenticated_v2(stage, Request {
                id: request.request_id(), session: request.session_binding(),
                signed: request.signed_request_digest(),
            }).map_err(|_| HostError::Fence("Host accepted authenticated continuation differs"))
    }

}

impl HostComponentControlStartupV2 {
    pub(crate) fn prepare_execution_monitor_receiving_v5(
        &mut self, launch: Request, accept: Request, observe: Request,
        source: aos_sandbox_model::ObjectDigest, execution: aos_sandbox_model::ExecutionId,
        complete: ResourceVector,
    ) -> Result<super::execution_receiving::monitor_interval::ExecutionMonitorReservationV5> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() {
            return Err(HostError::Fence("execution monitor retains original native post debt"));
        }
        let token_bytes = super::execution_receiving::monitor_interval::ExecutionMonitorReservationV5::receiving_bytes_v5()
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(HostError::ResourceExhausted)?;
        if complete.get(aos_sandbox_model::ResourceDimension::MemoryBytes) < token_bytes {
            return Err(HostError::ResourceExhausted);
        }
        let result = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("execution monitor intrinsic original is absent"))?
            .prepare_execution_monitor_v5(launch, accept, observe, source, execution, complete);
        if result.is_err() { self.first.get_or_insert(FirstCauseV2::ExecutionReceiving); }
        result.map_err(|_| HostError::Fence("same resident execution monitor capacity is unavailable"))
    }

    pub(crate) fn prepare_capture_terminal_receiving_v3(
        &mut self, launch: Request, accept: Request, observe: Request,
        source: aos_sandbox_model::ObjectDigest, execution: aos_sandbox_model::ExecutionId,
        complete: ResourceVector, terminal: aos_sandbox_model::ObjectDigest, ordinal: u64,
    ) -> Result<super::execution_receiving::monitor_interval::ExecutionMonitorReservationV5> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() {
            return Err(HostError::Fence("Capture terminal retains earlier native post debt"));
        }
        let bytes = super::execution_receiving::monitor_interval::ExecutionMonitorReservationV5::receiving_bytes_v5()
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(HostError::ResourceExhausted)?;
        if complete.get(aos_sandbox_model::ResourceDimension::MemoryBytes) < bytes {
            return Err(HostError::ResourceExhausted);
        }
        let result = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("Capture terminal financial original is absent"))?
            .prepare_capture_terminal_v3(launch, accept, observe, source, execution, complete, (terminal, ordinal));
        if result.is_err() { self.first.get_or_insert(FirstCauseV2::ExecutionReceiving); }
        result.map_err(|_| HostError::ResourceExhausted)
    }

    pub(crate) fn require_capture_terminal_receiving_identity_v3(
        &self, reservation: &super::execution_receiving::monitor_interval::ExecutionMonitorReservationV5,
        terminal: aos_sandbox_model::ObjectDigest, ordinal: u64,
    ) -> Result<()> {
        self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Capture terminal financial original is absent"))?
            .require_capture_terminal_identity_v3(reservation, terminal, ordinal)
            .map_err(|_| HostError::Fence("Capture terminal identity differs"))
    }

    pub(crate) fn extend_execution_monitor_receiving_v5(
        &mut self, reservation: &super::execution_receiving::monitor_interval::ExecutionMonitorReservationV5,
        complete: ResourceVector,
    ) -> Result<()> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() {
            return Err(HostError::Fence("execution monitor retains prior native debt"));
        }
        let result = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("execution monitor financial original is absent"))?
            .extend_execution_monitor_v5(reservation, complete);
        if result.is_err() { self.first.get_or_insert(FirstCauseV2::ExecutionReceiving); }
        result.map_err(|_| HostError::ResourceExhausted)
    }

    pub(crate) fn execution_monitor_native_demand_v5(&self) -> Result<(ResourceVector, usize)> {
        self.recurring_observation_demand_v4()
    }

    pub(crate) fn begin_execution_monitor_receiving_v5<'original>(
        &'original mut self,
        reservation: &super::execution_receiving::monitor_interval::ExecutionMonitorReservationV5,
        ordinal: u64,
        maximum: usize,
    ) -> Result<HostExecutionReceivingLoanV2<'original>> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() {
            return Err(HostError::Fence("execution monitor retains original native post debt"));
        }
        let (native, actual_maximum) = self.recurring_observation_demand_v4()?;
        if actual_maximum != maximum { return Err(HostError::ResourceExhausted); }
        let bound = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("execution monitor intrinsic original is absent"))?
            .bind_execution_monitor_sequence_v5(reservation, ordinal, native);
        if bound.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("execution monitor sequence or paid native extent differs"));
        }
        let destinations = self.append_recurring_observation_destinations_v4(maximum)?;
        let round_start = destinations.round_start;
        let manager_slot = destinations.manager_slot;
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("execution monitor financial original disappeared"))?
            .park_execution_monitor_destinations_v5(reservation, ordinal, destinations)
            .map_err(|_| HostError::Fence("execution monitor lost its same native destinations"))?;
        Ok(HostExecutionReceivingLoanV2 {
            original: self, purpose: HostExecutionLoanPurposeV4::ExecutionMonitor { ordinal },
            phase: Phase::Accept, request: reservation.accept_v5(),
            original_request: reservation.accept_v5(), continuation: None,
            manager_slot, round_start, before_entered: false, after_entered: false, settled: false,
        })
    }
}

impl HostComponentControlStartupV2 {
    pub(crate) fn prepare_execution_query_receiving_v3(&mut self,
        launch: Request, accept: Request, observe: Request,
        query: &AuthenticatedBrokerMethodRequestV1,
        source: aos_sandbox_model::ObjectDigest, execution: aos_sandbox_model::ExecutionId,
        complete: ResourceVector,
    ) -> Result<super::execution_receiving::query_interval::ExecutionQueryReservationV3> {
        self.require_admitted_original()?;
        if query.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || query.method() != BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
            || self.armed || self.first.is_some() { return Err(HostError::Fence("historical query has no original receiving entry")); }
        let minimum = super::execution_receiving::query_interval::ExecutionQueryReservationV3::receiving_bytes_v3()
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(HostError::ResourceExhausted)?;
        if complete.get(aos_sandbox_model::ResourceDimension::MemoryBytes) < minimum {
            return Err(HostError::ResourceExhausted);
        }
        let request = Request { id: query.request_id(), session: query.session_binding(), signed: query.signed_request_digest() };
        let result = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("historical query intrinsic payer is absent"))?
            .prepare_execution_query_v3(launch, accept, observe, request, query.client_sequence(),
                source, execution, complete);
        if result.is_err() { self.first.get_or_insert(FirstCauseV2::ExecutionReceiving); }
        result.map_err(|_| HostError::ResourceExhausted)
    }

    pub(crate) fn extend_execution_query_receiving_v3(&mut self,
        token: &super::execution_receiving::query_interval::ExecutionQueryReservationV3,
        complete: ResourceVector) -> Result<()> {
        self.require_admitted_original()?;
        let result = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("historical query intrinsic payer is absent"))?
            .extend_execution_query_v3(token, complete);
        if result.is_err() { self.first.get_or_insert(FirstCauseV2::ExecutionReceiving); }
        result.map_err(|_| HostError::ResourceExhausted)
    }

    pub(crate) fn begin_execution_query_receiving_v3(&mut self,
        token: &super::execution_receiving::query_interval::ExecutionQueryReservationV3,
        maximum: usize, selected_failure: &mut bool) -> Result<HostExecutionReceivingLoanV2<'_>> {
        *selected_failure = false;
        let preparation = (|| -> Result<(usize, usize)> {
            self.require_admitted_original()?;
            let (native, actual_maximum) = self.recurring_observation_demand_v4()?;
            if maximum != actual_maximum { return Err(HostError::ResourceExhausted); }
            self.extend_execution_query_receiving_v3(token, native)?;
            let destinations = self.append_recurring_observation_destinations_v4(maximum)?;
            let round_start = destinations.round_start;
            let manager_slot = destinations.manager_slot;
            let parked = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(HostError::Fence("historical query intrinsic payer disappeared"))?
                .park_execution_query_destinations_v3(token, destinations);
            if parked.is_err() { self.first.get_or_insert(FirstCauseV2::ExecutionReceiving); }
            parked.map_err(|_| HostError::Fence("historical query native destinations differ"))?;
            Ok((round_start, manager_slot))
        })();
        if preparation.is_err() {
            *selected_failure = self.execution_query_receiving_failure_v3().is_some();
        }
        let (round_start, manager_slot) = preparation?;
        Ok(HostExecutionReceivingLoanV2 { original: self,
            purpose: HostExecutionLoanPurposeV4::ExecutionQuery { sequence: token.sequence_v3() },
            phase: Phase::Accept, request: token.query_v3(), original_request: token.accept_v3(),
            continuation: None, manager_slot, round_start,
            before_entered: false, after_entered: false, settled: false })
    }

    pub(crate) fn execution_query_receiving_failure_v3(&self)
        -> Option<&(dyn std::error::Error + '_)> {
        matches!(self.first, Some(FirstCauseV2::ExecutionReceiving)).then(|| self.failure())
    }

    pub(crate) fn finish_execution_query_storage_disposal_v3(&mut self,
        disposed: &crate::broker::ExecutionQueryStorageDisposedV3) -> Result<()> {
        self.require_admitted_original()?;
        let (token, kept) = disposed.borrow_original_v3();
        let (round_start, _) = self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("historical query intrinsic payer is absent"))?
            .execution_query_disposal_destinations_v3(token)
            .map_err(|_| HostError::Fence("historical query lacks positive native posts"))?;
        for round in round_start .. round_start + 2 { self.attempts[round].require_positive_leaf_v2()?; }
        for round in round_start .. round_start + 2 { self.attempts[round].dispose_positive_leaf_v2()?; }
        // The same Accept readonly interval remains occupied; no manager reset.
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("historical query intrinsic payer disappeared"))?
            .finish_execution_query_storage_v3(token, kept)
            .map_err(|_| HostError::Fence("historical query disposal identity differs"))
    }
}

impl HostExecutionReceivingLoanV2<'_> {
    pub(super) fn require_capture_prearm_frontier_v3(&self) -> Result<()> {
        if self.phase != Phase::Accept || self.continuation != Some(AcceptedContinuationV2::Authorize)
            || !self.before_entered || self.after_entered || self.settled
            || self.original.armed || self.original.first.is_some()
        {
            return Err(HostError::Fence("Host Capture negative plan is outside its pre-issue frontier"));
        }
        Ok(())
    }

    pub(super) fn prearm_capture_reservation_v3(
        &mut self, launch: Request, source: aos_sandbox_model::ObjectDigest,
        execution: aos_sandbox_model::ExecutionId, requirement: ResourceVector,
    ) -> Result<super::execution_receiving::CaptureNegativeReservationV3> {
        self.require_capture_prearm_frontier_v3()?;
        self.original.prearm_capture_negative_v3(launch, self.original_request, source, execution, requirement)
    }

    pub(crate) fn require_capture_stop_request_v4(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        if self.purpose != HostExecutionLoanPurposeV4::StopContainment {
            return Err(HostError::Fence("Capture cleanup requires the actual Stop containment loan"));
        }
        self.require_launch_request_v2(request)
    }

    pub(crate) fn require_launch_current_v2(&self) -> Result<()> {
        self.require_launch_interval_v2()?;
        if self.purpose == HostExecutionLoanPurposeV4::StopContainment {
            self.original.attempts[self.round_start].require_positive_leaf_v2()?;
            self.original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(HostError::Fence("Capture Stop financial original is absent"))?
                .require_capture_stop_current_v4(self.original_request, self.request)
                .map_err(|_| HostError::Fence("Capture Stop primary financial interval is closed"))?;
        } else {
            self.original.require_admitted_original()?;
        }
        self.require_launch_consumed_flight_v2()
    }

    // Diagnostic only: callers latch this at the actual failed current gate,
    // before any independently owed later post can enter another first cause.
    pub(crate) fn component_report_original_failure_entered_v2(&self) -> bool {
        self.original.first.is_some()
    }

    /// Compares the same admitted component origin without relocking it.
    pub(crate) fn require_component_backend_origin_v2(
        &self,
        phase0: &super::super::component_phase0::HostComponentPhase0OriginalV2,
    ) -> Result<()> {
        self.require_launch_current_v2()?;
        phase0.require_same_startup_v2(self.original)
    }

    pub(crate) fn require_launch_request_v2(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.require_launch_current_v2()?;
        self.require_launch_request_identity_v2(request)
    }

    // Only the private Launch worker's already-prearmed read-only post recipe
    // calls this port. An earlier primary refusal cannot suppress its same-
    // flight bookend. It grants neither a new primary nor a mutating call.
    pub(crate) fn require_launch_readonly_post_request_v2(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.require_launch_interval_v2()?;
        self.require_launch_consumed_flight_v2()?;
        self.require_launch_request_identity_v2(request)
    }

    /// Rejoins only the same consumed Launch's successfully prepaid suffix.
    ///
    /// # Errors
    /// Refuses another purpose/request, missing original native-before leaf,
    /// completed interval or liabilities exceeding its earlier paid prearm.
    pub(crate) fn require_launch_compensation_phase_v1(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        phase: &crate::worker::launch::HostLaunchWorkerPhaseV4,
    ) -> Result<()> {
        self.require_launch_interval_v2()?;
        self.require_launch_request_identity_v2(request)?;
        if self.purpose != HostExecutionLoanPurposeV4::Initial
            || !self.original.admitted || self.original.armed
        {
            return Err(HostError::Fence("negative cleanup lacks its original Launch component"));
        }
        // This is the actual earlier positive native leaf, not a healthy flag
        // reconstructed after poison. The same consumed flight remains held.
        self.original.attempts[self.round_start].require_positive_leaf_v2()?;
        self.original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("negative cleanup lost its consumed Launch"))?
            .require_launch_compensation_phase_v1(self.request, phase)
            .map_err(|_| HostError::Fence("negative cleanup has no successful earlier prearm"))
    }

    fn require_launch_interval_v2(&self) -> Result<()> {
        if self.phase != Phase::Launch || self.continuation.is_some()
            || !self.before_entered || self.after_entered || self.settled
        {
            return Err(HostError::Fence("Host launch native purpose is not current"));
        }
        Ok(())
    }

    fn require_launch_consumed_flight_v2(&self) -> Result<()> {
        if self.purpose == HostExecutionLoanPurposeV4::StopContainment {
            return self.original.execution_receiving.as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(HostError::Fence("fresh Stop control original is absent"))?
                .require_capture_stop_owed_v4(self.original_request, self.request)
                .map_err(|_| HostError::Fence("fresh Stop has no exact consumed control interval"));
        }
        self.original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host launch original is absent"))?
            .require_owed_post(Phase::Launch, self.original_request)
            .and_then(|()| match self.purpose {
                HostExecutionLoanPurposeV4::Initial => Ok(()),
                HostExecutionLoanPurposeV4::StopContainment => self.original.execution_receiving.as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(super::execution_receiving::Closed)?
                    .require_capture_stop_owed_v4(self.original_request, self.request),
                HostExecutionLoanPurposeV4::ResidentStop => self.original.execution_receiving.as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(super::execution_receiving::Closed)?
                    .require_resident_stop_owed_v4(self.original_request, self.request),
                HostExecutionLoanPurposeV4::Availability | HostExecutionLoanPurposeV4::RetainedAvailabilityAccept
                    | HostExecutionLoanPurposeV4::ExecutionMonitor { .. }
                    | HostExecutionLoanPurposeV4::ExecutionQuery { .. } => Err(super::execution_receiving::Closed),
            })
            .map_err(|_| HostError::Fence("Host launch has no consumed financial flight"))
    }

    fn require_launch_request_identity_v2(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        let actual = Request {
            id: request.request_id(),
            session: request.session_binding(),
            signed: request.signed_request_digest(),
        };
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            || actual != self.request
        {
            return Err(HostError::Fence("Host launch catalog request differs from its original"));
        }
        Ok(())
    }

    pub(crate) fn remaining_launch_capacity_v2(
        &self,
        complete: ResourceVector,
    ) -> Result<ResourceVector> {
        self.require_launch_current_v2()?;
        self.original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host launch original is absent"))?
            .remaining_capacity_for_stop_or_launch_v4(self.purpose, self.original_request, self.request, complete)
            .map_err(|_| HostError::Fence("Host launch capacity view is unavailable"))
    }

    /// Associates completed local disposal with the same consumed Launch.
    ///
    /// # Errors
    /// Refuses an unhealthy or mismatched original and retains its first cause.
    pub(crate) fn retain_compilation_disposal_v2(
        &mut self,
        disposed: &crate::plan::HostLaunchCompilationDisposedV2,
    ) -> Result<()> {
        self.require_launch_current_v2()?;
        if self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(super::execution_receiving::Closed)
            .and_then(|owner| owner.retain_compilation_disposal_v2(self.request, disposed)).is_err()
        {
            self.original.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("Host compiler disposal differs from its original Launch"));
        }
        Ok(())
    }

    /// Checks the actual worker's next native phase on this same Launch.
    ///
    /// # Errors
    /// Refuses unhealthy, mismatched, or unaffordable entry before native work.
    pub(crate) fn enter_launch_worker_phase_v4(
        &mut self,
        phase: &crate::worker::launch::HostLaunchWorkerPhaseV4,
    ) -> Result<()> {
        self.require_launch_current_v2()?;
        if self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(super::execution_receiving::Closed)
            .and_then(|owner| match self.purpose {
                HostExecutionLoanPurposeV4::Initial => owner.enter_launch_worker_phase_v4(self.request, phase),
                HostExecutionLoanPurposeV4::StopContainment =>
                    owner.enter_capture_stop_worker_phase_v4(self.original_request, self.request, phase),
                HostExecutionLoanPurposeV4::ResidentStop =>
                    owner.enter_resident_stop_worker_phase_v4(self.original_request, self.request, phase),
                HostExecutionLoanPurposeV4::Availability | HostExecutionLoanPurposeV4::RetainedAvailabilityAccept
                    | HostExecutionLoanPurposeV4::ExecutionMonitor { .. }
                    | HostExecutionLoanPurposeV4::ExecutionQuery { .. } => Err(super::execution_receiving::Closed),
            }).is_err()
        {
            self.original.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("Host launch worker phase exceeds its original receiving capacity"));
        }
        Ok(())
    }

    pub(crate) fn require_complete_v2(&mut self, complete: ResourceVector) -> Result<()> {
        if self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(super::execution_receiving::Closed)
            .and_then(|owner| match self.continuation {
                Some(stage) => owner.require_accepted_continuation_v2(stage, self.request, complete),
                None => match self.purpose {
                    HostExecutionLoanPurposeV4::Initial | HostExecutionLoanPurposeV4::RetainedAvailabilityAccept => owner.require_complete(self.phase, self.request, complete),
                    HostExecutionLoanPurposeV4::Availability => owner.require_availability_interval_v2(
                        self.original_request, self.request, complete,
                    ),
                    HostExecutionLoanPurposeV4::StopContainment => owner.require_capture_stop_complete_v4(
                        self.original_request, self.request, complete,
                    ),
                    HostExecutionLoanPurposeV4::ResidentStop => owner.require_resident_stop_complete_v4(
                        self.original_request, self.request, complete,
                    ),
                    HostExecutionLoanPurposeV4::ExecutionMonitor { ordinal } =>
                        owner.require_execution_monitor_complete_v5(self.original_request, ordinal, complete),
                    HostExecutionLoanPurposeV4::ExecutionQuery { sequence } =>
                        owner.require_execution_query_complete_v3(self.original_request, self.request, sequence, complete),
                },
            }).is_err()
        {
            self.original.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("Host execution native representation exceeds its phase"));
        }
        Ok(())
    }

    pub(crate) fn prepay_ssh_birth_once_v1(
        &mut self,
        complete: ResourceVector,
        guest: &mut crate::live_agent::execution_original::AgentExecutionOriginalV2,
    ) -> Result<ResourceVector> {
        if self.phase != Phase::Accept
            || self.continuation != Some(AcceptedContinuationV2::Authorize)
            || guest.has_entered_v2() || guest.ssh_quote.is_some()
        {
            return Err(HostError::Fence("SSH source requires its original Authorize continuation"));
        }
        let available = self.original.execution_receiving.as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(HostError::ResourceExhausted)?
            .remaining_accepted_capacity_v1(self.original_request, self.request, complete)
            .map_err(|_| HostError::ResourceExhausted)?;
        let quote = crate::live_agent::execution_original::GuestSshSourceQuoteDataV1::derive(available)
            .ok_or(HostError::ResourceExhausted)?;
        let complete = complete.checked_add(quote.demand)
            .map_err(|_| HostError::ResourceExhausted)?;

        // Extend the SAME consumed Accept before any credential/native issue.
        // On failure its original operation and previous debt remain retained.
        self.require_complete_v2(complete)?;
        guest.ssh_quote = Some(quote);
        Ok(complete)
    }

    pub(crate) async fn observe_before_v2(&mut self) -> Result<()> {
        if self.before_entered { return Err(HostError::Fence("Host execution before was already entered")); }
        self.before_entered = true;
        let containment = self.purpose == HostExecutionLoanPurposeV4::StopContainment;
        if containment {
            self.original.prepare_owed_process_once_v2(self.round_start + 1)
                .map_err(|_| HostError::Fence("fresh Stop independent process post could not be prearmed"))?;
        }
        let phase = self.manager_slot;
        let intervals = if self.phase == Phase::Accept { 3 } else { 1 };
        let mut maximum = match self.original.recurring_materialized_maximum_v4(phase) {
            Some(maximum) => maximum,
            None => self.original.manager_schedule.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|schedule| schedule.startup_materialized_bytes.checked_add(
                    schedule.phase_materialized_bytes.checked_mul(intervals)?))
                .ok_or(HostError::ResourceExhausted)?,
        };
        if self.purpose == HostExecutionLoanPurposeV4::RetainedAvailabilityAccept {
            // Accept20 paid these three additional intervals before transfer;
            // the same manager still retains the whole consumed19 window.
            maximum = self.original.retained_accept_materialization_maximum_v2()?;
        } else if self.continuation.is_some()
            && self.original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(HostError::Fence("Host retained continuation lost its financial original"))?
                .retained_prepare_for_accept_v2(self.original_request)
                .map_err(|_| HostError::Fence("Host retained continuation lost its exact19"))?.is_some()
        {
            maximum = self.original.manager_original.as_ref()
                .ok_or(HostError::Fence("Host retained continuation lost its same manager"))?
                .materialization_extent_v2().1;
        }
        let growth = match self.original.manager_original.as_ref() {
            Some(original) => original.raise_materialization_limit_v2(maximum)
                .and_then(|()| if self.continuation.is_some()
                    || matches!(self.purpose, HostExecutionLoanPurposeV4::ExecutionMonitor { .. }
                        | HostExecutionLoanPurposeV4::ExecutionQuery { .. }
                        | HostExecutionLoanPurposeV4::Availability
                        | HostExecutionLoanPurposeV4::RetainedAvailabilityAccept
                        | HostExecutionLoanPurposeV4::StopContainment) { Ok(()) }
                    else { original.begin_readonly_interval_v2() }),
            None => return Err(HostError::Fence("Host execution lost its same readonly manager")),
        };
        self.original.record_manager_growth_v4(phase, growth);
        if self.original.manager_growth_v4(phase).is_some_and(|result| result.is_err()) {
            self.original.record_origin_failure_v4(self.round_start, FirstCauseV2::ExecutionManager(phase));
            return Err(HostError::Fence("Host execution same-manager extension failed"));
        }
        let after_round = self.round_start + 1;
        if !containment && self.original.prepare_owed_process_once_v2(after_round).is_err() {
            return Err(HostError::Fence("Host execution independent process post could not be prearmed"));
        }
        self.observe_slot_v2(false).await
    }

    pub(crate) async fn observe_after_v2(&mut self) -> Result<()> {
        if !self.before_entered || self.after_entered {
            return Err(HostError::Fence("Host execution has no outstanding independent post"));
        }
        if self.purpose == HostExecutionLoanPurposeV4::StopContainment {
            self.require_launch_consumed_flight_v2()?;
            self.after_entered = true;
            return self.observe_slot_v2(true).await;
        }
        self.original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host execution consumed phase is absent"))?
            .require_owed_post(self.phase, self.original_request)
            .and_then(|()| match self.purpose {
                HostExecutionLoanPurposeV4::Initial | HostExecutionLoanPurposeV4::RetainedAvailabilityAccept => Ok(()),
                HostExecutionLoanPurposeV4::Availability => self.original.execution_receiving.as_ref()
                    .and_then(|result| result.as_ref().ok()).ok_or(super::execution_receiving::Closed)?
                    .require_availability_owed_v2(self.original_request, self.request),
                HostExecutionLoanPurposeV4::StopContainment => self.original.execution_receiving.as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(super::execution_receiving::Closed)?
                    .require_capture_stop_owed_v4(self.original_request, self.request),
                HostExecutionLoanPurposeV4::ResidentStop => self.original.execution_receiving.as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(super::execution_receiving::Closed)?
                    .require_resident_stop_owed_v4(self.original_request, self.request),
                HostExecutionLoanPurposeV4::ExecutionMonitor { ordinal } =>
                    self.original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
                        .ok_or(super::execution_receiving::Closed)?
                        .require_execution_monitor_owed_v5(self.original_request, ordinal),
                HostExecutionLoanPurposeV4::ExecutionQuery { sequence } =>
                    self.original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
                        .ok_or(super::execution_receiving::Closed)?
                        .require_execution_query_owed_v3(self.original_request, self.request, sequence),
            })
            .map_err(|_| HostError::Fence("Host execution independent post was not prepaid"))?;
        self.after_entered = true;
        self.observe_slot_v2(true).await
    }

    async fn observe_slot_v2(&mut self, after: bool) -> Result<()> {
        let round = self.round_start + usize::from(after);
        match self.purpose {
            HostExecutionLoanPurposeV4::StopContainment => self.original.observe_capture_stop_slot_v4(round).await,
            _ => self.original.observe_execution_slot_v4(round).await,
        }
    }

    pub(crate) fn finish_native_v2(&mut self) -> Result<()> {
        if !self.before_entered || !self.after_entered {
            return Err(HostError::Fence("Host execution cannot complete before its real posts"));
        }
        if self.purpose == HostExecutionLoanPurposeV4::StopContainment {
            for round in self.round_start .. self.round_start + 2 {
                self.original.attempts[round].require_positive_leaf_v2()?;
            }
        } else if self.original.armed || self.original.first.is_some() {
            return Err(HostError::Fence("Host execution cannot complete before its real posts"));
        }
        let owner = self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("Host execution original is absent"))?;
        match self.continuation {
            Some(stage) => owner.finish_accepted_continuation_native_v2(stage, self.request),
            None => match self.purpose {
                HostExecutionLoanPurposeV4::Initial | HostExecutionLoanPurposeV4::RetainedAvailabilityAccept => owner.finish_native_positive(self.phase, self.request),
                HostExecutionLoanPurposeV4::Availability => owner.finish_availability_native_v2(
                    self.original_request, self.request,
                ),
                HostExecutionLoanPurposeV4::StopContainment =>
                    owner.finish_capture_stop_native_v4(self.original_request, self.request),
                HostExecutionLoanPurposeV4::ResidentStop =>
                    owner.finish_resident_stop_native_v4(self.original_request, self.request),
                HostExecutionLoanPurposeV4::ExecutionMonitor { ordinal } =>
                    owner.finish_execution_monitor_native_v5(self.original_request, ordinal),
                HostExecutionLoanPurposeV4::ExecutionQuery { sequence } =>
                    owner.finish_execution_query_native_v3(self.original_request, self.request, sequence),
            },
        }.map_err(|_| HostError::Fence("Host execution phase failed positive completion"))
    }

    pub(crate) fn require_monitor_posts_positive_v5(&self, ordinal: u64) -> Result<()> {
        if self.purpose != (HostExecutionLoanPurposeV4::ExecutionMonitor { ordinal })
            || !self.before_entered || !self.after_entered || self.settled
            || self.original.armed || self.original.first.is_some()
        {
            return Err(HostError::Fence("execution monitor native post owner is incomplete"));
        }
        self.original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("execution monitor financial original is absent"))?
            .require_execution_monitor_native_positive_v5(self.original_request, ordinal)
            .map_err(|_| HostError::Fence("execution monitor native interval is not positive"))?;
        for round in self.round_start .. self.round_start + 2 {
            self.original.attempts[round].require_positive_leaf_v2()?;
        }
        Ok(())
    }

    pub(crate) fn finish_monitor_storage_disposal_v5(
        mut self, disposed: &crate::broker::ExecutionMonitorStorageDisposedV5,
    ) -> Result<()> {
        let HostExecutionLoanPurposeV4::ExecutionMonitor { ordinal } = self.purpose
            else { return Err(HostError::Fence("monitor disposal has a different purpose")); };
        self.require_monitor_posts_positive_v5(ordinal)?;
        let (identity, kept) = disposed.require_ordinal_v5(ordinal)?;
        // This is the sole same-engine physical native leaf disposal. The
        // original Accept readonly manager interval remains occupied.
        for round in self.round_start .. self.round_start + 2 {
            self.original.attempts[round].dispose_positive_leaf_v2()?;
        }
        self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("monitor financial original disappeared"))?
            .finish_execution_monitor_storage_v5(identity, self.original_request, ordinal, kept)
            .map_err(|_| HostError::Fence("monitor positive storage frontier differs"))?;
        self.settled = true;
        Ok(())
    }

    // Ends only this temporary mutable borrow. The SAME consumed operation,
    // native samples and whole Host stage remain pending until authenticated
    // CAS/readback, exact response Sent and final currentness all succeed.
    pub(crate) fn retain_pending_authenticated_v2(mut self) -> Result<()> {
        if !self.before_entered || !self.after_entered {
            return Err(HostError::Fence("Host execution cannot retain an incomplete interval"));
        }
        if self.purpose == HostExecutionLoanPurposeV4::StopContainment {
            for round in self.round_start .. self.round_start + 2 {
                self.original.attempts[round].require_positive_leaf_v2()?;
            }
        } else if self.original.first.is_some() || self.original.armed {
            return Err(HostError::Fence("Host execution cannot retain an incomplete interval"));
        }
        self.settled = true;
        Ok(())
    }

}

impl Drop for HostExecutionReceivingLoanV2<'_> {
    fn drop(&mut self) {
        if !self.settled {
            // Cancellation or an early return keeps this SAME consumed phase
            // closed, with all resident originals and the earlier cause intact.
            self.original.armed = true;
            self.original.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            if let Some(owner) = self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok()) {
                owner.close();
            }
        }
    }
}

// The actual capsule remains held while this preparation checks the genuine
// original and retires its native interval. Only physical upper disposal and
// this infallible same-slot handoff may follow under the continuous borrow.
pub(crate) struct HostLaunchDisposalV2<'original> {
    original: &'original mut HostComponentControlStartupV2,
    request: Request,
    completed: bool,
}

impl HostLaunchDisposalV2<'_> {
    pub(crate) fn complete_after_disposal_v2(
        mut self,
        disposed: &crate::broker::HostLaunchResidentNativeV4,
    ) {
        let Some(Ok(owner)) = self.original.execution_receiving.as_mut() else {
            std::process::abort();
        };
        if owner.retain_authenticated_launch_native_v4(self.request, disposed).is_err() {
            // Preparation held the exclusive original continuously. No caller
            // could alter this already-checked financial phase during Drop.
            std::process::abort();
        }
        self.completed = true;
    }
}

impl Drop for HostLaunchDisposalV2<'_> {
    fn drop(&mut self) {
        if self.completed { return; }
        if let Some(Ok(owner)) = self.original.execution_receiving.as_mut() { owner.close(); }
        self.original.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
    }
}


#[derive(Clone, Copy)]
enum HostResidentStopDisposalKindV1 {
    Authenticated,
    UnsentNativePositive,
}

// This exclusive same-original token spans physical owner disposal. The closed
// unsent branch ends only a genuinely positive old native operation; it never
// manufactures authenticated Sent or permission for another effect.
pub(crate) struct HostResidentStopDisposalV4<'original> {
    original: &'original mut HostComponentControlStartupV2,
    launch: Request,
    request: Request,
    kind: HostResidentStopDisposalKindV1,
    completed: bool,
}

impl HostResidentStopDisposalV4<'_> {
    pub(crate) fn complete_after_disposal_v4(mut self) {
        let Some(Ok(owner)) = self.original.execution_receiving.as_mut() else {
            std::process::abort();
        };
        let completed = match self.kind {
            HostResidentStopDisposalKindV1::Authenticated => owner
                .retain_authenticated_resident_stop_v4(self.request)
                .and_then(|()| owner.complete_resident_stop_terminal_v4(self.launch, self.request)),
            HostResidentStopDisposalKindV1::UnsentNativePositive => owner
                .complete_unsent_stop_disposal_v1(self.launch, self.request),
        };
        if completed.is_err() {
            std::process::abort();
        }
        self.completed = true;
    }
}

impl Drop for HostResidentStopDisposalV4<'_> {
    fn drop(&mut self) {
        if self.completed { return; }
        self.original.armed = true;
        self.original.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
        if let Some(Ok(owner)) = self.original.execution_receiving.as_mut() { owner.close(); }
    }
}

// The genuine positive Host borrower remains live through preparation. The
// exclusive same-component token then spans physical Stage drop and the
// infallible completion of this exact already-consumed Accept operation.
pub(crate) struct HostTerminalStageDisposalV3<'original> {
    original: &'original mut HostComponentControlStartupV2,
    identity: HostTerminalDisposalIdentityV4,
    completed: bool,
}

#[derive(Clone, Copy)]
enum HostTerminalDisposalIdentityV4 {
    Execution { launch: Request, accept: Request, observe: Request, prepare: Option<Request> },
    NoApply { prepare: Request, ack: Request },
}

impl HostComponentControlStartupV2 {
    pub(crate) fn terminal_stage_disposal_receiving_bytes_v3() -> Option<usize> {
        std::mem::size_of::<HostTerminalStageDisposalV3<'_>>().checked_mul(2)?
            .checked_add(std::mem::size_of::<crate::broker::HostTerminalStagePositiveV3<'_>>().checked_mul(2)?)
    }

    pub(crate) fn prepare_terminal_stage_disposal_v3<'original>(
        &'original mut self,
        posts: &crate::broker::HostTerminalStagePositiveV3<'_>,
    ) -> Result<HostTerminalStageDisposalV3<'original>> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() {
            return Err(HostError::Fence("terminal Stage retains native receiving debt"));
        }
        let (launch, accept, observe) = posts.original_bindings_v3();
        let prepare = posts.retained_availability_binding_v2();
        self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("terminal Stage has no intrinsic original"))?
            .require_terminal_stage_disposal_v3(launch, accept, observe, prepare)
            .map_err(|_| HostError::Fence("terminal Stage financial association differs"))?;
        for start in posts.retained_availability_observation_rounds_v2() {
            for round in start .. start + 2 {
                if self.attempts[round].action.as_ref().is_none_or(|result| result.is_err()) {
                    return Err(HostError::Fence("terminal availability retains original post debt"));
                }
            }
        }
        for start in posts.retained_availability_observation_rounds_v2() {
            for round in start .. start + 2 {
                drop(std::mem::replace(&mut self.attempts[round], super::OriginAttemptV2::new()));
            }
        }
        self.retire_execution_samples_v2(MAXIMUM_ATTEMPTS + 2, 6, 1)?;
        Ok(HostTerminalStageDisposalV3 { original: self,
            identity: HostTerminalDisposalIdentityV4::Execution { launch, accept, observe, prepare },
            completed: false })
    }

    pub(crate) fn prepare_no_apply_terminal_disposal_v2<'original>(
        &'original mut self, posts: &crate::broker::HostNoApplyTerminalPositiveV2<'_>,
    ) -> Result<HostTerminalStageDisposalV3<'original>> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() {
            return Err(HostError::Fence("NoApply retains original Source post debt"));
        }
        let (prepare, ack) = posts.bindings_v2();
        self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("NoApply financial original is absent"))?
            .require_no_apply_terminal_disposal_v2(prepare, ack)
            .map_err(|_| HostError::Fence("NoApply financial association differs"))?;
        let first = posts.observation_rounds_v2().next()
            .ok_or(HostError::Fence("NoApply original observation schedule is absent"))?;
        for start in posts.observation_rounds_v2() {
            for round in start .. start + 2 {
                if self.attempts.get(round).and_then(|attempt| attempt.action.as_ref())
                    .is_none_or(|result| result.is_err())
                { return Err(HostError::Fence("NoApply original observation is incomplete")); }
            }
        }
        for start in posts.observation_rounds_v2().filter(|start| *start != first) {
            for round in start .. start + 2 {
                drop(std::mem::replace(&mut self.attempts[round], super::OriginAttemptV2::new()));
            }
        }
        self.retire_execution_samples_v2(first, 2, 0)?;
        Ok(HostTerminalStageDisposalV3 { original: self,
            identity: HostTerminalDisposalIdentityV4::NoApply { prepare, ack }, completed: false })
    }
}

impl HostTerminalStageDisposalV3<'_> {
    pub(crate) fn complete_after_disposal_v3(mut self) {
        let Some(Ok(owner)) = self.original.execution_receiving.as_mut() else { std::process::abort(); };
        let completed = match self.identity {
            HostTerminalDisposalIdentityV4::Execution { launch, accept, observe, prepare } =>
                owner.complete_terminal_stage_disposal_v3(launch, accept, observe, prepare),
            HostTerminalDisposalIdentityV4::NoApply { prepare, ack } =>
                owner.complete_no_apply_terminal_disposal_v2(prepare, ack),
        };
        if completed.is_err() {
            std::process::abort();
        }
        self.completed = true;
    }
}

impl Drop for HostTerminalStageDisposalV3<'_> {
    fn drop(&mut self) {
        if self.completed { return; }
        self.original.armed = true;
        self.original.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
        if let Some(Ok(owner)) = self.original.execution_receiving.as_mut() { owner.close(); }
    }
}
