//! Lends the same parked C18 to both actual preaccept client Sessions.
//!
//! Security continuously retains its Host and ControllerStorageClient owners.
//! Each finite native turn re-lends those exact Journal/socket/transcript parts;
//! this owner retains intrinsic Journal identities and native socket originals.
//! Construction precedes methods64/65 and supplies no availability or admission.

use aos_sandbox_broker::bounded_entropy::{EntropyError, RetainedKernelNonceOriginalV1};
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_protocol::host_execution_availability::{
    HostExecutionAvailabilityProposalFieldsV2, HostExecutionAvailabilityProposalV2,
};

use super::*;

pub(in crate::controller_execution_operation) mod native;
mod admission;
mod bind;
pub use bind::ControllerExecutionAvailabilityPositiveRetirementV2;
use native::ExecutionAvailabilitySessionNativeOriginalV2;
pub use native::ControllerExecutionAvailabilitySessionCurrentnessErrorV2;

pub(super) struct ExecutionAvailabilityClientOriginalV2 {
    fixed_geometry: Slot<ResourceVector, JournalError>,
    fixed_funding: Slot<(), ResourceReservationErrorV1>,
    funding_native_selected: bool,
    host: ExecutionAvailabilitySessionNativeOriginalV2,
    storage: ExecutionAvailabilitySessionNativeOriginalV2,
    nonce: RetainedKernelNonceOriginalV1,
    entropy: Slot<[u8; 16], EntropyError>,
    proposal: Slot<HostExecutionAvailabilityProposalV2, JournalError>,
    cutoff: Slot<u64, JournalError>,
    closed: bool,
    io: crate::controller_resource_reservation::ExecutionAvailabilityIoOriginalV2,
    base: ResourceVector,
    retirement_issued: bool,
    admission: admission::ExecutionAvailabilityAdmissionOriginalV2,
}

impl ExecutionAvailabilityClientOriginalV2 {
    fn new() -> Self {
        Self {
            fixed_geometry: None, fixed_funding: None, funding_native_selected: false,
            host: ExecutionAvailabilitySessionNativeOriginalV2::new(),
            storage: ExecutionAvailabilitySessionNativeOriginalV2::new(),
            nonce: RetainedKernelNonceOriginalV1::new(), entropy: None,
            proposal: None, cutoff: None, closed: false,
            io: Default::default(), base: ResourceVector::ZERO,
            retirement_issued: false,
            admission: admission::ExecutionAvailabilityAdmissionOriginalV2::new(),
        }
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.fixed_geometry).or_else(|| error(&self.fixed_funding))
            .or_else(|| self.host.failure_v2()).or_else(|| self.storage.failure_v2())
            .or_else(|| self.nonce.failure()).or_else(|| error(&self.entropy))
            .or_else(|| error(&self.cutoff)).or_else(|| error(&self.proposal))
            .or_else(|| self.io.failure_v2())
            .or_else(|| self.admission.failure_v2())
            .or_else(|| self.closed.then_some(&ResourceReservationErrorV1::Conflict as _))
    }

    pub(super) fn funding_native_selected_v2(&self) -> bool {
        self.funding_native_selected
    }
}

/// Borrows the real public scope and Controller through both client subturns.
///
/// Its private constructor pays and observes both actual lower Sessions. The
/// Security aggregate keeps those same owners continuously borrowed and passes
/// their original parts at each native crossing. No scalar observation creates
/// this loan, and its existence grants neither REQUESTED nor execution effects.
#[must_use = "retain the same C18 and both Security Session owners through all subturns"]
pub struct ControllerExecutionAvailabilityClientLoanV2<'turn> {
    scope: &'turn mut ExecutionPublicAdmissionScopeV2,
    controller: &'turn mut Journal,
    active: usize,
}

impl ExecutionPublicAdmissionScopeV2 {
    /// Borrows both concrete client Sessions before availability transport.
    ///
    /// Parameters come directly from the continuously held Security owners.
    /// Native currentness and entropy are paid by this same parked C18; every
    /// reached before observation runs its independent post even on refusal.
    /// The returned loan has no durable acceptance port until the complete
    /// authenticated remote and local provider continuation is joined.
    ///
    /// # Errors
    /// Refuses reentry, failed compilation, another Controller, invalid native
    /// Session association, native entropy or an exceeded original horizon.
    #[doc(hidden)]
    pub fn borrow_availability_client_once_v2<'turn>(
        &'turn mut self,
        controller: &'turn mut Journal,
        host_journal: &Journal,
        host_socket: &SeqpacketSocket,
        host_transcript: &VerifiedBrokerSessionTranscriptV1,
        storage_journal: &Journal,
        storage_socket: &SeqpacketSocket,
        storage_transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<ControllerExecutionAvailabilityClientLoanV2<'turn>, ResourceReservationErrorV1> {
        self.require_current_v2(controller).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if self.prefix.availability.is_some() || self.preaccept_source_data_v2().is_err() {
            self.prefix.first.get_or_insert(First::Availability);
            return Err(ResourceReservationErrorV1::Conflict);
        }

        self.prefix.availability = Some(ExecutionAvailabilityClientOriginalV2::new());
        let returned = self.prepare_availability_clients_inner_v2(controller,
            host_journal, host_socket, host_transcript,
            storage_journal, storage_socket, storage_transcript);
        if returned.is_err() {
            self.prefix.first.get_or_insert(First::Availability);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(ControllerExecutionAvailabilityClientLoanV2 { scope: self, controller, active: 0 })
    }

    fn prepare_availability_clients_inner_v2(&mut self, controller: &mut Journal,
        host_journal: &Journal, host_socket: &SeqpacketSocket,
        host_transcript: &VerifiedBrokerSessionTranscriptV1,
        storage_journal: &Journal, storage_socket: &SeqpacketSocket,
        storage_transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let original = self.prefix.availability.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        original.fixed_geometry = Some((|| {
            let host = ExecutionAvailabilitySessionNativeOriginalV2::fixed_demand_v2(true)?;
            let storage = ExecutionAvailabilitySessionNativeOriginalV2::fixed_demand_v2(false)?;
            let memory = RetainedKernelNonceOriginalV1::construction_bytes_v1()
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ControllerExecutionAvailabilityClientLoanV2<'_>>().checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            host.checked_add(storage).and_then(|demand| demand.checked_add(
                ResourceVector::ZERO.with(D::MemoryBytes, memory)))
                .map_err(JournalError::ReceivingAccounting)
        })());
        let demand = original.fixed_geometry.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
        original.fixed_funding = Some((|| {
            let bank = self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let mut loan = self.financial.resume_public_admission_v2(&bank, controller, self.profile.as_ref())?;
            let complete = loan.prefix_demand_v2().checked_add(demand)?;
            let returned = loan.require_complete_v2(&bank, controller, self.profile.as_ref(), Demand::from_demand_v1(complete));
            let parked = loan.park_public_admission_v2();
            returned.and(parked)
        })());
        if !matches!(original.fixed_funding, Some(Ok(()))) {
            original.funding_native_selected = self.financial.failure().is_some();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        original.base = self.financial.predurable_prefix.ok_or(ResourceReservationErrorV1::Conflict)?;

        original.host.capture_once_v2(host_journal, host_socket, host_transcript, true)?;
        original.storage.capture_once_v2(storage_journal, storage_socket, storage_transcript, false)?;
        original.entropy = Some(original.nonce.observe_once());
        if !matches!(original.entropy, Some(Ok(_))) { return Err(ResourceReservationErrorV1::Conflict); }

        let source = self.preaccept_source_data_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let clock = source.original_authorization_clock_v2();
        let cutoff = clock.conservative_expiry_deadline_data_v1(source.authorization_expires_v2())
            .and_then(|expiry| clock.boottime_nanoseconds()
                .checked_add(source.operation_timeout_nanoseconds_v2())
                .map(|operation| expiry.min(operation).min(source.original_peer_deadline_v2())))
            .filter(|cutoff| *cutoff > clock.boottime_nanoseconds())
            .ok_or(JournalError::ProtectedBoundary);
        let assignment = source.assignment_manifest_v2();
        let manifest = assignment.manifest();
        let fields = HostExecutionAvailabilityProposalFieldsV2 {
            sandbox: *manifest.sandbox().as_bytes(), incarnation: *manifest.incarnation().as_bytes(),
            node: *manifest.node().as_bytes(), assignment_epoch: manifest.epoch().get(),
            desired_generation: manifest.desired_generation().get(), public_request_digest: source.public_request_digest_v2(),
            assignment_digest: *assignment.digest().as_bytes(), nonce: [0; 16],
        };
        let original = self.prefix.availability.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        original.cutoff = Some(cutoff);
        let nonce = original.nonce.value().copied().ok_or(ResourceReservationErrorV1::Conflict)?;
        original.proposal = Some(HostExecutionAvailabilityProposalV2::new(
            HostExecutionAvailabilityProposalFieldsV2 { nonce, ..fields })
            .map_err(|_| JournalError::ProtectedBoundary));
        if original.failure_v2().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(())
    }
}

impl ControllerExecutionAvailabilityClientLoanV2<'_> {
    pub(crate) fn io_original_v2(&mut self) -> &mut crate::controller_resource_reservation::ExecutionAvailabilityIoOriginalV2 {
        match self.scope.prefix.availability.as_mut() {
            Some(original) => &mut original.io,
            None => std::process::abort(),
        }
    }

    pub(crate) fn active_endpoint_data_v2(&self) -> usize { self.active }

    pub(crate) fn advance_endpoint_once_v2(&mut self) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.active, 0 | 1 | 3 | 4) { return Err(ResourceReservationErrorV1::Conflict); }
        self.active += 1;
        Ok(())
    }

    pub(crate) fn require_transport_current_v2(&self) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.active, 0 | 1 | 3 | 4) { return Err(ResourceReservationErrorV1::Conflict); }
        self.original_v2().map(|_| ())
    }

    pub(crate) fn complete_transport_base_v2(&mut self, incoming: ResourceVector)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        let original = self.scope.prefix.availability.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        original.base.checked_add(original.io.retained_demand_v2()?)?
            .checked_add(original.admission.retained_demand_v2()?)?
            .checked_add(self.scope.accepted_bind_retained_demand_v2()?)?
            .checked_add(incoming).map_err(Into::into)
    }

    pub(crate) fn require_transport_complete_v2(&mut self, complete: ResourceVector)
        -> Result<(), ResourceReservationErrorV1> {
        let bank = self.scope.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let mut loan = self.scope.financial.resume_public_admission_v2(&bank, self.controller, self.scope.profile.as_ref())?;
        let returned = loan.require_complete_v2(&bank, self.controller, self.scope.profile.as_ref(), Demand::from_demand_v1(complete));
        let parked = loan.park_public_admission_v2();
        returned.and(parked)
    }

    pub(crate) fn require_transport_session_v2(&self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ControllerExecutionAvailabilitySessionCurrentnessErrorV2> {
        let original = self.scope.prefix.availability.as_ref();
        let native = match (original, self.active) {
            (Some(original), 0 | 3) => Some(&original.host),
            (Some(original), 1 | 4) => Some(&original.storage),
            _ => None,
        };
        ExecutionAvailabilitySessionNativeOriginalV2::observe_same_v2(native, journal, socket, transcript)
    }

    pub(crate) fn require_transport_journal_v2(&self, journal: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        let original = self.scope.prefix.availability.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        match self.active {
            0 | 3 => original.host.require_journal_v2(journal),
            1 | 4 => original.storage.require_journal_v2(journal),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    /// Borrows the actual original failure while all reached custody stays held.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.scope.failure_v2()
    }

    /// Borrows the exact compiled proposal with its same paid native nonce.
    ///
    /// # Errors
    /// Refuses failed or incomplete native preparation; DATA supplies no Ready.
    pub fn proposal_data_v2(&self) -> Result<HostExecutionAvailabilityProposalV2, ResourceReservationErrorV1> {
        let original = self.original_v2()?;
        original.proposal.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Returns the original authorization/operation/peer deadline minimum.
    ///
    /// Completed peers may only shorten this horizon by their actual original
    /// cutoffs. No query extends either retained PREACCEPT interval during bind.
    ///
    /// # Errors
    /// Refuses failed preparation or an absent original expiry calculation.
    pub fn original_cutoff_data_v2(&self) -> Result<u64, ResourceReservationErrorV1> {
        let original = self.original_v2()?;
        let local = original.cutoff.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if self.active >= 2 {
            let boot = self.scope.preaccept_source_data_v2()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?
                .original_authorization_clock_v2().host_boot_id();
            Ok(local.min(original.io.preaccept_cutoff_data_v2(boot)?))
        } else { Ok(local) }
    }

    fn original_v2(&self) -> Result<&ExecutionAvailabilityClientOriginalV2, ResourceReservationErrorV1> {
        self.scope.require_current_v2(self.controller).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let original = self.scope.prefix.availability.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if original.failure_v2().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(original)
    }
}
