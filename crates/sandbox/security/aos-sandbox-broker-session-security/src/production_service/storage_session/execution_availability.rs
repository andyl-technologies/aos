//! Retains remote Storage availability on the original service Session and F.
//!
//! This capsule is a field of the existing resident lifecycle Session. Its
//! short native loan borrows that actual Session and its original receiving
//! borrower together; no scalar response, cursor, account or reopened writer
//! constructs the loan. Positive request controls do not dispose the capsule.

use aos_sandbox_api::aos::sandbox::local::v1::{BrokerMethod, PrepareExecutionAvailabilityResponseV2};
use aos_sandbox_controller_domain::{StorageLifecycleSessionLoanV1, StorageReceivingClosedV1};
use aos_sandbox_broker::paired_clock::{PairedClockBaselineV1, PairedClockSamplesV1, ProtectedOwnershipClockError};
use aos_sandbox_model::{AccountingError, RawClockProvenance, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::execution_availability::{ExecutionAvailabilityPhaseV2, ValidatedExecutionAvailabilityRequestV2};
use aos_sandbox_protocol::host_execution_availability::HostExecutionAvailabilityProposalV2;
use aos_sandbox_protocol::host_execution_no_apply::BeforeArgumentNoApplySourceDataV2;
use aos_sandbox_protocol::storage_execution_availability::{
    StorageExecutionAvailabilityObservationFieldsV2, StorageExecutionAvailabilityObservationV2,
    decode_storage_execution_availability_request_v2,
};
use aos_sandbox_protocol::ProtocolValidationError;
use buffa::Message as _;
use std::error::Error;
use std::mem::size_of;

use crate::BrokerSessionSecurityError;
use crate::handshake::DormantAuthenticatedBrokerSessionV1;
use crate::tpm_nv_custody::{FloorCheckpointV1, FloorProfileV1};

type FloorObservation = Result<(FloorProfileV1, FloorCheckpointV1), BrokerSessionSecurityError>;
type ClockObservation = Result<RawPairedClockSample, ProtectedOwnershipClockError>;

/// Holds both finite phases with the actual resident Session's native interval.
pub(crate) struct ProductionStorageExecutionAvailabilityOriginalV2 {
    demand: [Option<Result<ResourceVector, AccountingError>>; 2],
    funding: [Option<Result<(), BrokerSessionSecurityError>>; 2],
    arm: [Option<Result<(), StorageReceivingClosedV1>>; 2],
    native_post: [Option<Result<(), StorageReceivingClosedV1>>; 2],
    decoded: [Option<Result<ValidatedExecutionAvailabilityRequestV2, ProtocolValidationError>>; 2],
    clocks: [Option<PairedClockSamplesV1>; 2],
    baseline: Option<PairedClockBaselineV1>,
    before_clock: [Option<ClockObservation>; 2],
    after_clock: [Option<ClockObservation>; 2],
    before_floor: [Option<FloorObservation>; 2],
    after_floor: [Option<FloorObservation>; 2],
    response: [Option<Vec<u8>>; 2],
    body: [Option<Result<(), BrokerSessionSecurityError>>; 2],
    returned: [Option<Result<(), BrokerSessionSecurityError>>; 2],
    proposal: Option<HostExecutionAvailabilityProposalV2>,
    accepted: Option<BeforeArgumentNoApplySourceDataV2>,
    session: Option<[u8; 32]>,
    first_clock: Option<RawPairedClockSample>,
    cutoff: Option<u64>,
    phase: Option<ExecutionAvailabilityPhaseV2>,
    lifetime: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    closed: Option<BrokerSessionSecurityError>,
}

impl ProductionStorageExecutionAvailabilityOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            demand: std::array::from_fn(|_| None), funding: std::array::from_fn(|_| None),
            arm: std::array::from_fn(|_| None), native_post: std::array::from_fn(|_| None),
            decoded: std::array::from_fn(|_| None), clocks: std::array::from_fn(|_| None), baseline: None,
            before_clock: std::array::from_fn(|_| None), after_clock: std::array::from_fn(|_| None),
            before_floor: std::array::from_fn(|_| None), after_floor: std::array::from_fn(|_| None),
            response: std::array::from_fn(|_| None), body: std::array::from_fn(|_| None),
            returned: std::array::from_fn(|_| None), proposal: None, accepted: None, session: None,
            first_clock: None, cutoff: None, phase: None, lifetime: None, closed: None,
        }
    }

    fn receiving_demand() -> Result<ResourceVector, AccountingError> {
        let overflow = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let framing = aos_sandbox_protocol::execution_availability::MAXIMUM_EXECUTION_AVAILABILITY_BODY_BYTES_V2;
        // Two finite decoder owners and each retained/returned response copy
        // coexist with the resident capsule. Neither phase refunds the first.
        let boot = aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(overflow)?;
        let phase_boot_inputs = boot.checked_mul(4).ok_or_else(overflow)?;
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(framing.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(framing.checked_mul(4)?))
            // One baseline and each phase's two before/after boot bookends.
            .and_then(|bytes| bytes.checked_add(boot))
            .and_then(|bytes| bytes.checked_add(phase_boot_inputs))
            .and_then(|bytes| bytes.checked_add(phase_boot_inputs))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(overflow)?;
        let clock = PairedClockSamplesV1::receiving_demand_v1().ok_or_else(overflow)?;
        // Each finite phase retains its two actual native observations. This
        // source-owned quote includes the baseline/native input geometry.
        ResourceVector::ZERO.with(D::MemoryBytes, bytes).checked_add(clock)?.checked_add(clock)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        for index in 0..2 {
            let cause = error(&self.arm[index]).or_else(|| error(&self.demand[index]))
                .or_else(|| error(&self.funding[index]))
                .or_else(|| self.baseline.as_ref()?.failure())
                .or_else(|| self.clocks[index].as_ref()?.observation_failure(0))
                .or_else(|| error(&self.before_clock[index]))
                .or_else(|| error(&self.decoded[index])).or_else(|| error(&self.before_floor[index]))
                .or_else(|| error(&self.body[index])).or_else(|| error(&self.native_post[index]))
                .or_else(|| error(&self.after_floor[index]))
                .or_else(|| self.clocks[index].as_ref()?.observation_failure(1))
                .or_else(|| error(&self.after_clock[index])).or_else(|| error(&self.returned[index]));
            if cause.is_some() { return cause; }
        }
        error(&self.lifetime).or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn require_retirement_v2(&self) -> Result<(), BrokerSessionSecurityError> {
        if self.phase.is_none() { return Ok(()); }
        if self.phase != Some(ExecutionAvailabilityPhaseV2::AcceptedBind)
            || self.accepted.is_none() || self.failure().is_some()
            || !matches!(self.returned[1], Some(Ok(())))
        { return Err(BrokerSessionSecurityError::Currentness); }
        Ok(())
    }

    pub(crate) fn require_method_v2(&mut self, method: BrokerMethod) -> Result<(), BrokerSessionSecurityError> {
        if self.failure().is_some() { return Err(BrokerSessionSecurityError::Currentness); }
        if self.phase == Some(ExecutionAvailabilityPhaseV2::Preaccept)
            && !matches!(method, BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2
                | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)
        { return Err(BrokerSessionSecurityError::Currentness); }
        if let Some(cutoff) = self.cutoff {
            self.lifetime = Some(crate::dormant_handshake::check_production_deadline(cutoff));
            if !matches!(self.lifetime, Some(Ok(()))) { return Err(BrokerSessionSecurityError::Currentness); }
        }
        Ok(())
    }

    /// Lends the same real native Session/F while completing one finite phase.
    ///
    /// The whole owning service retains both borrowers after this short Rust
    /// loan ends. It cannot retire before the same-Session accepted bind.
    pub(crate) fn observe_phase_v2(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>, request: &AuthenticatedBrokerMethodRequestV1,
        boot: [u8; 16], node: [u8; 16],
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        if self.failure().is_some() || self.phase == Some(ExecutionAvailabilityPhaseV2::AcceptedBind) {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let index = usize::from(self.phase.is_some());
        if self.returned[index].is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut loan = StorageExecutionAvailabilityNativeLoanV2 { original: self, session, receiving };
        loan.observe(index, request, boot, node)
    }
}

// Only the genuine service field and its actual same-Session receiving borrow
// can construct this loan. No observation or numeric amount is a constructor.
struct StorageExecutionAvailabilityNativeLoanV2<'phase, 'cut, 'original> {
    original: &'phase mut ProductionStorageExecutionAvailabilityOriginalV2,
    session: &'phase mut DormantAuthenticatedBrokerSessionV1,
    receiving: &'phase mut StorageLifecycleSessionLoanV1<'cut, 'original>,
}

impl StorageExecutionAvailabilityNativeLoanV2<'_, '_, '_> {
    fn sample(&mut self, index: usize) -> ClockObservation {
        self.original.clocks[index].as_mut().ok_or(ProtectedOwnershipClockError)?
            .sample(self.original.baseline.as_mut().ok_or(ProtectedOwnershipClockError)?)
    }

    fn observe(&mut self, index: usize, request: &AuthenticatedBrokerMethodRequestV1, boot: [u8; 16], node: [u8; 16])
        -> Result<Vec<u8>, BrokerSessionSecurityError>
    {
        let original = &mut *self.original;
        original.arm[index] = Some(self.session.arm_storage_operation_post_v1(self.receiving));
        let body = (|| {
            if !matches!(original.arm[index], Some(Ok(()))) { return Err(BrokerSessionSecurityError::Currentness); }
            original.demand[index] = Some(ProductionStorageExecutionAvailabilityOriginalV2::receiving_demand());
            let demand = original.demand[index].as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(BrokerSessionSecurityError::Currentness)?;
            original.funding[index] = Some(self.session.reserve_storage_execution_availability_v3(self.receiving, demand));
            if !matches!(original.funding[index], Some(Ok(()))) { return Err(BrokerSessionSecurityError::Currentness); }
            if original.baseline.is_none() {
                original.baseline = Some(PairedClockBaselineV1::capture(RawClockProvenance::new_untrusted(
                    aos_sandbox_broker::ownership_clock::CLOCK_PROVENANCE)));
            }
            original.clocks[index] = Some(PairedClockSamplesV1::new());
            Ok(())
        })();
        // End this short field borrow before sampling through the native loan.
        if body.is_ok() {
            let sample = self.sample(index);
            self.original.before_clock[index] = Some(sample);
        }
        let body = body.and_then(|()| self.observe_body(index, request, boot, node));
        self.original.body[index] = Some(body.clone());

        if matches!(self.original.arm[index], Some(Ok(()))) {
            self.original.native_post[index] = Some(self.session.finish_storage_operation_post_v1(self.receiving));
        }
        if matches!(self.original.funding[index], Some(Ok(()))) {
            self.original.after_floor[index] = Some(self.session.observe_storage_execution_availability_v3(self.receiving));
            let sample = self.sample(index);
            self.original.after_clock[index] = Some(sample);
        }
        let result = body.and_then(|()| {
            if !matches!(self.original.native_post[index], Some(Ok(())))
                || !matches!(self.original.after_floor[index], Some(Ok(_)))
            { return Err(BrokerSessionSecurityError::Currentness); }
            let current = self.original.after_clock[index].as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(BrokerSessionSecurityError::Currentness)?;
            self.require_clock(current, boot, request.deadline_boottime_nanoseconds())?;
            self.build_response(index, request, current)
        });
        self.original.returned[index] = Some(result.as_ref().map(|_| ()).map_err(Clone::clone));
        if result.is_ok() {
            self.original.phase = Some(if index == 0 { ExecutionAvailabilityPhaseV2::Preaccept }
                else { ExecutionAvailabilityPhaseV2::AcceptedBind });
        }
        result
    }

    fn observe_body(&mut self, index: usize, request: &AuthenticatedBrokerMethodRequestV1, boot: [u8; 16], node: [u8; 16])
        -> Result<(), BrokerSessionSecurityError>
    {
        let current = self.original.before_clock[index].as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(BrokerSessionSecurityError::Currentness)?;
        if index == 0 {
            self.original.first_clock = Some(current);
            self.original.cutoff = Some(request.deadline_boottime_nanoseconds());
            self.original.session = Some(request.session_binding());
        }
        self.require_clock(current, boot, request.deadline_boottime_nanoseconds())?;
        self.original.decoded[index] = Some(decode_storage_execution_availability_request_v2(
            request.exact_body(), request.peer(), request.peer_policy(), current.boottime_nanoseconds()));
        let decoded = self.original.decoded[index].as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let expected = if index == 0 { ExecutionAvailabilityPhaseV2::Preaccept }
            else { ExecutionAvailabilityPhaseV2::AcceptedBind };
        if decoded.phase() != expected || self.original.session != Some(request.session_binding()) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let proposal = HostExecutionAvailabilityProposalV2::decode_canonical(decoded.canonical_proposal())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if proposal.fields().node != node { return Err(BrokerSessionSecurityError::Currentness); }
        if index == 0 {
            self.original.proposal = Some(proposal);
        } else {
            if self.original.proposal != Some(proposal) { return Err(BrokerSessionSecurityError::Currentness); }
            let accepted = BeforeArgumentNoApplySourceDataV2::decode_canonical(decoded.canonical_accepted_source())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            proposal.require_accepted_source(accepted).map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if accepted.fields().host_boot != boot { return Err(BrokerSessionSecurityError::Currentness); }
            self.original.accepted = Some(accepted);
        }
        self.original.before_floor[index] = Some(self.session.observe_storage_execution_availability_v3(self.receiving));
        if !matches!(self.original.before_floor[index], Some(Ok(_))) { return Err(BrokerSessionSecurityError::Currentness); }
        Ok(())
    }

    fn require_clock(&self, current: RawPairedClockSample, boot: [u8; 16], request_cutoff: u64)
        -> Result<(), BrokerSessionSecurityError>
    {
        let first = self.original.first_clock.ok_or(BrokerSessionSecurityError::Currentness)?;
        let cutoff = self.original.cutoff.ok_or(BrokerSessionSecurityError::Currentness)?.min(request_cutoff);
        if current.host_boot_id() != boot || current.host_boot_id() != first.host_boot_id()
            || current.provenance() != first.provenance()
            || current.boottime_nanoseconds() < first.boottime_nanoseconds()
            || current.boottime_nanoseconds() >= cutoff
        { return Err(BrokerSessionSecurityError::Currentness); }
        Ok(())
    }

    fn build_response(&mut self, index: usize, request: &AuthenticatedBrokerMethodRequestV1, current: RawPairedClockSample)
        -> Result<Vec<u8>, BrokerSessionSecurityError>
    {
        let (profile, checkpoint) = self.original.after_floor[index].as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(BrokerSessionSecurityError::Currentness)?;
        let proposal = self.original.proposal.ok_or(BrokerSessionSecurityError::Currentness)?;
        let first = self.original.first_clock.ok_or(BrokerSessionSecurityError::Currentness)?;
        let phase = if index == 0 { ExecutionAvailabilityPhaseV2::Preaccept } else { ExecutionAvailabilityPhaseV2::AcceptedBind };
        let observed = StorageExecutionAvailabilityObservationV2::new(StorageExecutionAvailabilityObservationFieldsV2 {
            phase, proposal_digest: *proposal.digest().as_bytes(), request: request.request_id(),
            session: request.session_binding(), signed_request: request.signed_request_digest(),
            floor_scope: profile.scope(), main_head: checkpoint.cut().head(), main_sequence: checkpoint.cut().sequence(),
            checkpoint_ordinal: checkpoint.ordinal(), nv_value: checkpoint.nv_value(), boot: current.host_boot_id(),
            first_clock: first.boottime_nanoseconds(), cutoff: self.original.cutoff
                .ok_or(BrokerSessionSecurityError::Currentness)?,
            observed_clock: current.boottime_nanoseconds(), bound_source_digest: self.original.accepted
                .map(|source| *source.digest().as_bytes()).unwrap_or([0; 32]),
        }).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let response = PrepareExecutionAvailabilityResponseV2 {
            canonical_observation: observed.encode_canonical().to_vec(), ..Default::default()
        }.encode_to_vec();
        self.original.response[index] = Some(response);
        self.original.response[index].as_ref().cloned().ok_or(BrokerSessionSecurityError::Currentness)
    }
}
