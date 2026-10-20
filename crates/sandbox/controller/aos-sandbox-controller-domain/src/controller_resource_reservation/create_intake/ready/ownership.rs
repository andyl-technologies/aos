//! Acquires the exact planned assignment through the paid original J scope.
//!
//! The original owns fixed protected Controller credentials, every contacted
//! socket/record/native result and the cryptographically verified lease. Retry
//! queries the same immutable claim and retains earlier uncertain carriers;
//! it cannot change assignment, accepted operation, Node or original cutoff.

mod credentials;
mod pricing;
mod wire;
mod start;

pub(in crate::controller_resource_reservation::create_intake) use start::StartOwnershipOriginalV1;

pub(super) use wire::{RetainedOwnershipRecordDataV1, VerifiedOwnershipWireDataV1};

use std::error::Error;
use std::collections::TryReserveError;
use std::path::Path;
use crate::cache_residency::OriginalCreateStorageCacheLoanV1;
use aos_sandbox_model::{CanonicalAssignmentManifestV1, LeaseAssignment, RawPairedClockSample};
use aos_sandbox_linux::seqpacket::{LocalOwnershipSeqpacketEndAttemptV1,
    RetainedSeqpacketAdmissionErrorV1, SeqpacketSocket};
use aos_sandbox_ownership_protocol::{OwnershipClaimV1, OwnershipClaimError,
    OwnershipLeaseAcquisitionError, SignedOwnershipLease};
use aos_sandbox_ownership_protocol::authority_records::AuthorityRecordErrorV1;
use aos_sandbox_ownership_protocol::response_verification::OwnershipResponseVerifyCaptureV1;
use aos_sandbox_ownership_protocol::client_records::OwnershipClientRecordStateV1;
use aos_sandbox_ownership_protocol::carrier::{encode_client_hello_v1, MAXIMUM_OWNERSHIP_HELLO_BYTES};
use aos_sandbox_ownership_protocol::protocol::{OwnershipClientHelloV1, OwnershipRequestBodyV1,
    OwnershipRequestEnvelopeV1, OwnershipResponseEnvelopeV1, OwnershipResponseOutcomeV1,
    OwnershipTransactionReferenceV1, OwnershipTransactionStatusV1, OwnershipProtocolErrorCodeV1,
    OwnershipErrorRecoveryV1, OwnershipMethodV1, MAXIMUM_OWNERSHIP_RESPONSE_BYTES};
use aos_sandbox_broker::ownership_record_io::{OwnershipRecordIoV1, receive, send};
use crate::controller_resource_reservation::q04_intake::CreateContinuationCaptureOwnerV1 as Owner;
use super::cache_receiving::{CacheControlOriginalsV1, CacheCurrentnessOriginalV1, OriginalCacheAssociationV1};
use super::*;

const SOCKET: &str = "/run/aos/sandbox-ownership/control.sock";

/// Reports progress of the same retained Create Ownership claim.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateStorageOwnershipProgressV1 {
    /// The exact lease is cryptographically verified and every post completed.
    Verified,
    /// The authority still owns the same durable unsigned intent.
    Pending,
    /// Delivery is uncertain; a later call may only query this exact claim.
    Unavailable,
    /// The authority requires the named explicit recovery action.
    Rejected(OwnershipProtocolErrorCodeV1),
}

#[derive(Debug, thiserror::Error)]
enum OwnershipError {
    #[error(transparent)]
    Original(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Claim(#[from] OwnershipClaimError),
    #[error(transparent)]
    Assignment(#[from] aos_sandbox_model::InvalidOwnershipLease),
    #[error(transparent)]
    Clock(#[from] aos_sandbox_model::OwnershipLeaseVerificationError),
    #[error("the original Create Ownership client is closed")]
    Closed,
}

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct OriginalCreateStorageOwnershipV1 {
    credentials: credentials::ControllerOwnershipOriginalV1,
    credential_admission: Option<Result<(), ResourceReservationErrorV1>>,
    credential_result: Option<Result<(), OwnershipError>>,
    credential_position: Option<Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>>,
    credential_before: CacheCurrentnessOriginalV1,
    credential_before_result: Option<Result<(), ResourceReservationErrorV1>>,
    credential_after: CacheCurrentnessOriginalV1,
    credential_after_result: Option<Result<(), ResourceReservationErrorV1>>,
    claim: Option<Result<OwnershipClaimV1, OwnershipError>>,
    manifest: Option<[u8; 32]>,
    accepted: Option<CreateStorageAcceptedIdentityV1>,
    original_clock: Option<RawPairedClockSample>,
    cutoff: Option<u64>,
    attempts: Vec<OwnershipFlightV1>,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    growth: Option<Result<(), TryReserveError>>,
    verified: Option<usize>,
    progress: Option<Result<CreateStorageOwnershipProgressV1, OwnershipError>>,
    closed: bool,
}

#[derive(Default)]
struct OwnershipExchangeV1 {
    request: Option<Result<OwnershipRequestEnvelopeV1, AuthorityRecordErrorV1>>,
    io: OwnershipRecordIoV1,
    encoding: Option<Result<(), AuthorityRecordErrorV1>>,
    response: Option<Result<OwnershipResponseEnvelopeV1, AuthorityRecordErrorV1>>,
    advanced: Option<Result<(), AuthorityRecordErrorV1>>,
}

#[derive(Default)]
struct OwnershipFlightV1 {
    position: Option<Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>>,
    before: CacheCurrentnessOriginalV1,
    before_result: Option<Result<(), ResourceReservationErrorV1>>,
    connected: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    peer: Option<Result<(), OwnershipError>>,
    nonce: [u8; 32],
    entropy: Option<Result<usize, rustix::io::Errno>>,
    hello: Option<Result<OwnershipClientHelloV1, AuthorityRecordErrorV1>>,
    hello_io: OwnershipRecordIoV1,
    negotiation: Option<Result<OwnershipClientRecordStateV1, AuthorityRecordErrorV1>>,
    exchanges: [OwnershipExchangeV1; 3],
    clock: Option<aos_sandbox_broker::paired_clock::RetainedPairedClockV1>,
    clocks: [Option<Result<RawPairedClockSample, aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError>>; 2],
    clock_binding: [Option<Result<(), OwnershipError>>; 2],
    completed_response: Option<usize>,
    contact_result: Option<Result<CreateStorageOwnershipProgressV1, OwnershipError>>,
    signed: OwnershipResponseVerifyCaptureV1,
    signed_result: Option<Result<(), OwnershipLeaseAcquisitionError>>,
    assignment_binding: Option<Result<(), OwnershipError>>,
    primary: Option<Result<CreateStorageOwnershipProgressV1, OwnershipError>>,
    ending: Option<LocalOwnershipSeqpacketEndAttemptV1>,
    after: CacheCurrentnessOriginalV1,
    after_result: Option<Result<(), ResourceReservationErrorV1>>,
    result: Option<Result<CreateStorageOwnershipProgressV1, OwnershipError>>,
}

// The only constructor is the actual Ready method below. These are borrowed
// originals, not independently supplied identities, writer names or payers.
struct OriginalOwnershipInputsV1<'a, 'cache> {
    intake: &'a mut Q04OriginalIntakeAttemptV1,
    parent: &'a ProjectPreparationReservationAttemptV1,
    controller: &'a Journal,
    source: &'a ProtectedSourceDomainJournalOwnerV1,
    profile: &'a ProductionControllerNormalRootProfileV1,
    cache: &'a OriginalCreateStorageCacheLoanV1<'cache>,
    manifest: &'a CanonicalAssignmentManifestV1,
    accepted: CreateStorageAcceptedIdentityV1,
    expected: OriginalCacheAssociationV1,
    position: Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>,
}

impl<'original, 'cache> OriginalCreateStorageReadyV1<'original, 'cache> {
    /// Contacts the fixed local authority for this original planned assignment.
    ///
    /// Every uncertain attempt remains resident. A retry starts with Query for
    /// the unchanged claim; this method grants no Root U, Prepare or Apply.
    ///
    /// # Errors
    /// Refuses absent AssignmentPlanned/CacheHeld, changed original owners,
    /// financial/credential/currentness/integrity failure or the original cutoff.
    /// Whole native results and any remotely committed intent remain owned.
    pub fn progress_local_ownership_v1(&mut self)
        -> Result<CreateStorageOwnershipProgressV1, CreateStorageReadyClosedV1> {
        self.original.require_operation_currentness_peak_v1(&self.cache)
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let accepted = self.original.accepted().map_err(|_| CreateStorageReadyClosedV1)?;
        let expected = self.original.owner.cache_capture.currentness_association_v1()
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let position = self.original.current_controller_history_position_v1();
        // Genuine Cache remains borrowed throughout the call; the retained
        // pre-Root cut must exist before any credential/transport admission.
        self.cache.borrow_pre_root_cut_v1().map_err(|_| CreateStorageReadyClosedV1)?;
        let owner = &mut *self.original.owner;
        let manifest = owner.assignment.planned_manifest_v1().map_err(|_| CreateStorageReadyClosedV1)?;
        let inputs = OriginalOwnershipInputsV1 {
            intake: &mut owner.intake, parent: &owner.parent,
            controller: self.original.controller, source: self.original.source,
            profile: self.original.profile, cache: &self.cache, manifest,
            accepted, expected, position,
        };
        owner.ownership.drive_once(inputs).map_err(|_| CreateStorageReadyClosedV1)
    }
}

/// Borrows the verified result beside its genuine unchanged Ready/Cache scope.
///
/// This is not a fresh Root/current-time grant. Its private constructor checks
/// the actual retained original and same canonical assignment; later B/Root
/// validators must still reverify liveness at their own real effect boundary.
pub(super) struct VerifiedCreateStorageOwnershipV1<'held, 'cache> {
    original: &'held OriginalCreateStorageOwnershipV1,
    cache: &'held OriginalCreateStorageCacheLoanV1<'cache>,
    manifest: &'held CanonicalAssignmentManifestV1,
    claim: &'held OwnershipClaimV1,
    lease: &'held SignedOwnershipLease,
}

impl<'original, 'cache> OriginalCreateStorageReadyV1<'original, 'cache> {
    pub(super) fn verified_ownership_v1(&self)
        -> Result<VerifiedCreateStorageOwnershipV1<'_, 'cache>, ResourceReservationErrorV1> {
        self.original.require_operation_currentness_peak_v1(&self.cache)?;
        self.original.owner.ownership.verified_original_v1(
            &self.original.owner.assignment, &self.cache)
    }

    /// Borrows the current contacted attempt's actual cause with all custody held.
    #[must_use]
    #[doc(hidden)]
    pub fn local_ownership_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.original.owner.ownership.failure()
    }
}

impl<'held, 'cache> VerifiedCreateStorageOwnershipV1<'held, 'cache> {
    pub(super) fn manifest(&self) -> &'held CanonicalAssignmentManifestV1 { self.manifest }
    pub(super) fn claim(&self) -> &'held OwnershipClaimV1 { self.claim }
    pub(super) fn lease(&self) -> &'held SignedOwnershipLease { self.lease }

    pub(super) fn require_original(&self) -> Result<(), ResourceReservationErrorV1> {
        if self.original.closed || self.original.verified.is_none() || self.cache.failure().is_some()
            || self.original.manifest != Some(*self.manifest.digest().as_bytes()) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

impl OriginalCreateStorageOwnershipV1 {
    pub(super) fn verified_original_v1<'held, 'cache>(
        &'held self,
        assignment: &'held super::super::history::assignment::AssignmentPlannedOriginalV1,
        cache: &'held OriginalCreateStorageCacheLoanV1<'cache>,
    ) -> Result<VerifiedCreateStorageOwnershipV1<'held, 'cache>, ResourceReservationErrorV1> {
        let (manifest, claim, lease) = self.verified_material_v1(assignment)?;
        Ok(VerifiedCreateStorageOwnershipV1 { original: self, cache, manifest, claim, lease })
    }

    // The long signing loan holds mutable Cache and Root alongside these exact
    // immutable completed Ownership fields. Cache currentness stays on that
    // loan; this projection creates no independent lease or signing authority.
    pub(in crate::controller_resource_reservation::create_intake) fn verified_signing_material_v1<'held>(
        &'held self,
        assignment: &'held super::super::history::assignment::AssignmentPlannedOriginalV1,
    ) -> Result<(&'held SignedOwnershipLease, aos_sandbox_model::ObjectDigest), ResourceReservationErrorV1> {
        let (manifest, _, lease) = self.verified_material_v1(assignment)?;
        Ok((lease, manifest.manifest().policy().digest()))
    }

    pub(in crate::controller_resource_reservation::create_intake) fn verified_material_v1<'held>(
        &'held self,
        assignment: &'held super::super::history::assignment::AssignmentPlannedOriginalV1,
    ) -> Result<(&'held CanonicalAssignmentManifestV1, &'held OwnershipClaimV1, &'held SignedOwnershipLease), ResourceReservationErrorV1> {
        let original = self;
        if original.closed { return Err(ResourceReservationErrorV1::Conflict); }
        let manifest = assignment.planned_manifest_v1()?;
        let index = original.verified.ok_or(ResourceReservationErrorV1::Conflict)?;
        let flight = original.attempts.get(index).ok_or(ResourceReservationErrorV1::Conflict)?;
        if !matches!(flight.result, Some(Ok(CreateStorageOwnershipProgressV1::Verified)))
            || !matches!(flight.after_result, Some(Ok(())))
            || !flight.ending.as_ref().is_some_and(|ending| ending.is_complete())
            || original.manifest != Some(*manifest.digest().as_bytes()) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let claim = original.claim.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let lease = flight.signed.value()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok((manifest, claim, lease))
    }

}

impl OriginalCreateStorageOwnershipV1 {
    fn drive_once(&mut self, mut originals: OriginalOwnershipInputsV1<'_, '_>)
        -> Result<CreateStorageOwnershipProgressV1, OwnershipError> {
        if self.closed { return Err(OwnershipError::Closed); }
        if self.verified.is_some() { return Err(OwnershipError::Closed); }
        self.progress = Some(self.drive_entered_once(&mut originals));
        match retained(&self.progress) {
            Ok(progress) => Ok(*progress),
            Err(_) => {
                self.closed = true;
                Err(OwnershipError::Closed)
            }
        }
    }

    fn drive_entered_once(&mut self, originals: &mut OriginalOwnershipInputsV1<'_, '_>)
        -> Result<CreateStorageOwnershipProgressV1, OwnershipError> {
        self.require_claim_once(originals)?;
        let count = self.attempts.len().checked_add(1).ok_or(OwnershipError::Closed)?;
        let demand = pricing::complete_demand_v1(count, self.credentials.verifier()?)
            .ok_or(OwnershipError::Closed)?;
        self.admission = Some(originals.intake.reserve_create_capture_complete(Owner::Ownership, demand));
        if !matches!(self.admission, Some(Ok(()))) { self.closed = true; return Err(OwnershipError::Closed); }
        self.growth = Some(self.attempts.try_reserve_exact(1));
        if !matches!(self.growth, Some(Ok(()))) { self.closed = true; return Err(OwnershipError::Closed); }
        self.attempts.push(OwnershipFlightV1::default());
        let index = self.attempts.len() - 1;
        let flight = &mut self.attempts[index];
        flight.position = Some(std::mem::replace(&mut originals.position,
            Err(ResourceReservationErrorV1::Conflict)));
        flight.before_result = Some(observe(&mut flight.before, originals, &flight.position));
        let primary = if matches!(flight.before_result, Some(Ok(()))) {
            (|| flight.run(&self.credentials, retained(&self.claim)?, originals.manifest,
                self.original_clock.ok_or(OwnershipError::Closed)?, originals.accepted.original_cutoff))()
        } else { Err(OwnershipError::Closed) };
        flight.primary = Some(primary);
        flight.finish_local_once_v1();
        // This prepaid independent destination uses the captured actual
        // position/association even after primary or later J refusal.
        flight.after_result = Some(observe(&mut flight.after, originals, &flight.position));
        flight.result = Some((|| {
            let progress = *retained(&flight.primary)?;
            retained(&flight.after_result)?;
            if matches!(flight.connected, Some(Ok(_)))
                && !flight.ending.as_ref().is_some_and(|ending| ending.is_complete()) {
                return Ok(CreateStorageOwnershipProgressV1::Unavailable);
            }
            Ok(progress)
        })());
        let progress = match retained(&flight.result) {
            Ok(progress) => *progress,
            Err(_) => { self.closed = true; return Err(OwnershipError::Closed); }
        };
        if progress == CreateStorageOwnershipProgressV1::Verified { self.verified = Some(index); }
        if matches!(progress, CreateStorageOwnershipProgressV1::Rejected(_)) { self.closed = true; }
        Ok(progress)
    }

    fn require_claim_once(&mut self, originals: &mut OriginalOwnershipInputsV1<'_, '_>)
        -> Result<(), OwnershipError> {
        originals.parent.require_create_storage_association(originals.controller, originals.source, originals.profile)?;
        originals.intake.require_retained_capture()?;
        if self.claim.is_some() {
            let claim = retained(&self.claim)?;
            if self.manifest != Some(*originals.manifest.digest().as_bytes())
                || !self.accepted.is_some_and(|accepted| {
                    accepted.operation == originals.accepted.operation
                        && accepted.project == originals.accepted.project
                        && accepted.sandbox == originals.accepted.sandbox
                        && accepted.accepted_request == originals.accepted.accepted_request
                        && accepted.coissuance_binding == originals.accepted.coissuance_binding
                        && accepted.original_cutoff == originals.accepted.original_cutoff
                })
                || claim.node() != originals.manifest.manifest().node()
                || self.cutoff != Some(originals.accepted.original_cutoff) {
                self.closed = true;
                return Err(OwnershipError::Closed);
            }
            return Ok(());
        }
        if self.credential_admission.is_some() {
            self.closed = true;
            return Err(OwnershipError::Closed);
        }
        self.credential_admission = Some(originals.intake.reserve_create_capture_complete(
            Owner::Ownership, pricing::credential_demand_v1().ok_or(OwnershipError::Closed)?));
        retained(&self.credential_admission)?;
        self.credential_position = Some(std::mem::replace(&mut originals.position,
            Err(ResourceReservationErrorV1::Conflict)));
        self.credential_before_result = Some(observe(&mut self.credential_before, originals, &self.credential_position));
        self.credential_result = Some(if matches!(self.credential_before_result, Some(Ok(()))) {
            self.credentials.capture_once();
            self.credentials.require_complete()
        } else { Err(OwnershipError::Closed) });
        self.credential_after_result = Some(observe(&mut self.credential_after, originals, &self.credential_position));
        if !matches!(self.credential_result, Some(Ok(())))
            || !matches!(self.credential_after_result, Some(Ok(()))) {
            self.closed = true;
            return Err(OwnershipError::Closed);
        }
        originals.position = self.credential_position.as_ref()
            .and_then(|result| result.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict);
        self.original_clock = Some(originals.intake.create_storage_j_data_v1()?.clock);
        self.cutoff = Some(originals.accepted.original_cutoff);
        self.accepted = Some(originals.accepted);
        self.manifest = Some(*originals.manifest.digest().as_bytes());
        self.claim = Some((|| {
            let model = originals.manifest.manifest();
            if model.sandbox().into_bytes() != originals.accepted.sandbox
                || model.project().into_bytes() != originals.accepted.project
                || model.node() != originals.intake.create_storage_node_v1()? {
                return Err(OwnershipError::Closed);
            }
            let clock = self.original_clock.ok_or(OwnershipError::Closed)?;
            let seconds = originals.accepted.original_cutoff.checked_sub(clock.boottime_nanoseconds())
                .ok_or(OwnershipError::Closed)? / 1_000_000_000;
            let assignment = LeaseAssignment::new(model.sandbox(), model.incarnation(), model.epoch(), originals.manifest.digest())?;
            Ok(OwnershipClaimV1::acquire(originals.accepted.operation, assignment,
                model.desired_generation(), model.node(), seconds.min(aos_sandbox_ownership_protocol::MAXIMUM_REQUESTED_DURATION_SECONDS))?)
        })());
        retained(&self.claim).map(|_| ())
    }

    pub(in crate::controller_resource_reservation::create_intake) fn fatal_failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.closed { self.failure() } else { None }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.credential_admission).or_else(|| self.credential_before.failure())
            .or_else(|| error(&self.credential_before_result)).or_else(|| self.credentials.failure())
            .or_else(|| error(&self.credential_result)).or_else(|| self.credential_after.failure())
            .or_else(|| error(&self.credential_after_result)).or_else(|| error(&self.claim))
            .or_else(|| error(&self.admission)).or_else(|| error(&self.growth))
            .or_else(|| self.attempts.last().and_then(OwnershipFlightV1::failure))
            .or_else(|| error(&self.progress))
    }
}

impl OwnershipFlightV1 {
    fn run(&mut self, credentials: &credentials::ControllerOwnershipOriginalV1,
        claim: &OwnershipClaimV1, manifest: &CanonicalAssignmentManifestV1,
        original: RawPairedClockSample, cutoff: u64)
        -> Result<CreateStorageOwnershipProgressV1, OwnershipError> {
        self.run_engine(credentials, claim, manifest, original, cutoff, None)
    }

    fn run_engine(&mut self, credentials: &credentials::ControllerOwnershipOriginalV1,
        claim: &OwnershipClaimV1, manifest: &CanonicalAssignmentManifestV1,
        original: RawPairedClockSample, cutoff: u64,
        start_origin: Option<aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1>,
    ) -> Result<CreateStorageOwnershipProgressV1, OwnershipError> {
        self.clock = Some(aos_sandbox_broker::paired_clock::RetainedPairedClockV1::open_with_comparison(original));
        self.clocks[0] = self.clock.as_mut().map(|clock| clock.sample());
        self.clock_binding[0] = Some(validate_origin_clock(&self.clocks[0], original, cutoff, start_origin));
        self.contact_result = Some(if matches!(self.clock_binding[0], Some(Ok(()))) {
            self.contact(credentials, claim, cutoff)
        } else { Err(OwnershipError::Closed) });
        // Both clock observations are prepaid. A failed contact still retains
        // this independent after sample; it cannot extend the original cutoff.
        self.clocks[1] = self.clock.as_mut().map(|clock| clock.sample());
        self.clock_binding[1] = Some(validate_origin_clock(&self.clocks[1], original, cutoff, start_origin));
        let progress = *retained(&self.contact_result)?;
        retained(&self.clock_binding[1])?;
        if progress != CreateStorageOwnershipProgressV1::Verified { return Ok(progress); }
        let index = self.completed_response.ok_or(OwnershipError::Closed)?;
        let response = retained(&self.exchanges[index].response)?;
        let OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Completed(response)) = response.outcome() else {
            return Err(OwnershipError::Closed);
        };
        let sample = *self.clocks[1].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(OwnershipError::Closed)?;
        // The exact received canonical artifacts remain in their native
        // exchange. The verifier consumes only this separately priced copy.
        self.signed_result = Some(credentials.verifier()?.verify_response_retaining_v1(
            claim, (*response).clone(), &sample, &mut self.signed));
        self.assignment_binding = Some((|| {
            retained(&self.signed_result)?;
            let signed = self.signed.value().ok_or(OwnershipError::Closed)?;
            let model = manifest.manifest();
            let assignment = signed.assignment();
            if assignment.sandbox() != model.sandbox() || assignment.incarnation() != model.incarnation()
                || assignment.epoch() != model.epoch() || assignment.digest() != manifest.digest()
                || signed.node() != model.node() || signed.desired_generation() != model.desired_generation()
                || signed.assignment() != claim.assignment() {
                return Err(OwnershipError::Closed);
            }
            Ok(())
        })());
        retained(&self.assignment_binding)?;
        Ok(CreateStorageOwnershipProgressV1::Verified)
    }

    fn finish_local_once_v1(&mut self) {
        if let Some(Ok(socket)) = self.connected.as_mut() {
            self.ending = Some(socket.end_local_ownership_session_retaining_v1());
        }
    }

    fn contact(&mut self, credentials: &credentials::ControllerOwnershipOriginalV1,
        claim: &OwnershipClaimV1, cutoff: u64)
        -> Result<CreateStorageOwnershipProgressV1, OwnershipError> {
        self.hello_io.arm_deadline_once().map_err(|_| OwnershipError::Closed)?;
        self.hello_io.set_original_cutoff_once(cutoff).map_err(|_| OwnershipError::Closed)?;
        self.connected = Some(SeqpacketSocket::connect_retaining(Path::new(SOCKET)));
        let socket = match self.connected.as_mut() {
            Some(Ok(socket)) => socket,
            _ => return Ok(CreateStorageOwnershipProgressV1::Unavailable),
        };
        self.peer = Some(if socket.peer().credentials().uid() == 0 && socket.peer().credentials().gid() == 0 {
            Ok(())
        } else { Err(OwnershipError::Closed) });
        retained(&self.peer)?;
        self.entropy = Some(rustix::rand::getrandom(&mut self.nonce, rustix::rand::GetRandomFlags::empty()));
        if !matches!(self.entropy, Some(Ok(32))) || self.nonce == [0; 32] {
            return Err(OwnershipError::Closed);
        }
        self.hello = Some(OwnershipClientHelloV1::new(self.nonce, aos_sandbox_model::ProtocolVersion::new(1, 0),
            credentials.verifier()?.authority().clone(),
            aos_sandbox_ownership_protocol::authority_records::LOCAL_AUTHORITY_METHODS_V1.to_vec(),
            MAXIMUM_OWNERSHIP_RESPONSE_BYTES).map_err(AuthorityRecordErrorV1::from));
        let hello = retained(&self.hello)?;
        self.hello_io.outgoing = Some(encode_client_hello_v1(hello));
        if send(socket, &mut self.hello_io).is_err()
            || receive(socket, &mut self.hello_io, MAXIMUM_OWNERSHIP_HELLO_BYTES, 0, 0).is_err() {
            return Ok(CreateStorageOwnershipProgressV1::Unavailable);
        }
        let record = self.hello_io.received.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(OwnershipError::Closed)?;
        self.negotiation = Some(OwnershipClientRecordStateV1::negotiate(hello, record.payload(), credentials.secret()?));
        let records = self.negotiation.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(OwnershipError::Closed)?;
        let reference = OwnershipTransactionReferenceV1::from_claim(claim);
        let mut next = OwnershipRequestBodyV1::Query(reference);
        for (index, exchange) in self.exchanges.iter_mut().enumerate() {
            // One fixed whole-flight deadline survives all three semantic
            // steps. A fresh semantic record cannot renew the real operation.
            exchange.io.adopt_deadline_from(&self.hello_io).map_err(|_| OwnershipError::Closed)?;
            exchange.request = Some(records.session().request(next).map_err(AuthorityRecordErrorV1::from));
            let request = retained(&exchange.request)?;
            match records.encode_request(request) {
                Ok(bytes) => { exchange.io.outgoing = Some(bytes); exchange.encoding = Some(Ok(())); }
                Err(cause) => { exchange.encoding = Some(Err(cause)); return Err(OwnershipError::Closed); }
            }
            if send(socket, &mut exchange.io).is_err() || receive(socket, &mut exchange.io,
                records.session().maximum_response_bytes() as usize, 0, 0).is_err() {
                return Ok(CreateStorageOwnershipProgressV1::Unavailable);
            }
            let record = exchange.io.received.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(OwnershipError::Closed)?;
            exchange.response = Some(records.open_response(request, record.payload()));
            let response = retained(&exchange.response)?;
            exchange.advanced = Some(records.response_received());
            retained(&exchange.advanced)?;
            match response.outcome() {
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Completed(_)) => {
                    self.completed_response = Some(index);
                    return Ok(CreateStorageOwnershipProgressV1::Verified);
                }
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Absent) if index == 0 => {
                    next = OwnershipRequestBodyV1::Begin(Box::new(claim.clone()));
                }
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Pending) if request.method() != OwnershipMethodV1::CompleteOrResume => {
                    next = OwnershipRequestBodyV1::CompleteOrResume(reference);
                }
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Pending) => {
                    return Ok(CreateStorageOwnershipProgressV1::Pending);
                }
                OwnershipResponseOutcomeV1::Error(code) => {
                    if code.recovery() == OwnershipErrorRecoveryV1::QueryThenRetryExact {
                        return Ok(CreateStorageOwnershipProgressV1::Unavailable);
                    }
                    return Ok(CreateStorageOwnershipProgressV1::Rejected(*code));
                }
                _ => return Err(OwnershipError::Closed),
            }
        }
        Err(OwnershipError::Closed)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.position).or_else(|| self.before.failure()).or_else(|| error(&self.before_result))
            .or_else(||self.contacted_failure_v1())
            .or_else(|| self.after.failure()).or_else(|| error(&self.after_result))
            .or_else(|| error(&self.result))
    }

    fn contacted_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.clock.as_ref().and_then(|clock| clock.initial_failure())
            .or_else(|| self.clock.as_ref().and_then(|clock| clock.observation_failure(0)))
            .or_else(|| error(&self.clocks[0])).or_else(|| error(&self.clock_binding[0]))
            .or_else(|| error(&self.connected)).or_else(|| error(&self.peer)).or_else(|| error(&self.entropy))
            .or_else(|| error(&self.hello)).or_else(|| self.hello_io.send_failure())
            .or_else(|| self.hello_io.receive_failure()).or_else(|| error(&self.negotiation))
            .or_else(|| self.exchanges.iter().find_map(|exchange| error(&exchange.request)
                .or_else(|| error(&exchange.encoding)).or_else(|| exchange.io.send_failure())
                .or_else(|| exchange.io.receive_failure()).or_else(|| error(&exchange.response))
                .or_else(|| error(&exchange.advanced))))
            .or_else(|| error(&self.contact_result))
            .or_else(|| self.clock.as_ref().and_then(|clock| clock.observation_failure(1)))
            .or_else(|| error(&self.clocks[1])).or_else(|| error(&self.clock_binding[1]))
            .or_else(|| self.signed.cause()).or_else(|| error(&self.signed_result))
            .or_else(|| error(&self.assignment_binding))
            .or_else(|| error(&self.primary))
            .or_else(|| self.ending.as_ref().and_then(|ending| ending.failure()))

    }

}

fn validate_origin_clock(
    sample: &Option<Result<RawPairedClockSample, aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError>>,
    original: RawPairedClockSample, cutoff: u64,
    start_origin: Option<aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1>,
) -> Result<(), OwnershipError> {
    validate_clock(sample, original, cutoff)?;
    if let Some(origin) = start_origin {
        let sample = *sample.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(OwnershipError::Closed)?;
        if origin.first_native_clock_v1() != original || origin.cutoff_v1() != cutoff
            || origin.accepted_v1().cutoff_for_sample_data_v1(sample).is_none() {
            return Err(OwnershipError::Closed);
        }
    }
    Ok(())
}

fn validate_clock(sample: &Option<Result<RawPairedClockSample, aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError>>,
    original: RawPairedClockSample, cutoff: u64) -> Result<(), OwnershipError> {
    let sample = *sample.as_ref().and_then(|result| result.as_ref().ok()).ok_or(OwnershipError::Closed)?;
    original.validate_later_sample(sample)?;
    if sample.host_boot_id() != original.host_boot_id() || sample.boottime_nanoseconds() >= cutoff {
        return Err(OwnershipError::Closed);
    }
    Ok(())
}

fn observe(sample: &mut CacheCurrentnessOriginalV1, originals: &OriginalOwnershipInputsV1<'_, '_>,
    position: &Option<Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>>)
    -> Result<(), ResourceReservationErrorV1> {
    sample.observe_operation_once(CacheControlOriginalsV1 {
        parent: originals.parent, intake: originals.intake,
        controller: originals.controller, source: originals.source, profile: originals.profile,
    }, originals.cache, originals.expected, position.as_ref().and_then(|result| result.as_ref().ok()).copied()
        .ok_or(ResourceReservationErrorV1::Conflict))
}

fn retained<T, E>(result: &Option<Result<T, E>>) -> Result<&T, OwnershipError> {
    result.as_ref().and_then(|result| result.as_ref().ok()).ok_or(OwnershipError::Closed)
}

fn error<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod start_origin_tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;
    use aos_sandbox_protocol::domain_ledger::operation::{AcceptedStartOriginDataV1,StartNativeOriginDataV1};

    #[test]
    fn accepted_wall_expiry_refuses_ownership_contact_before_boottime_cutoff() {
        let first=RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1;16]).unwrap(),[2;16],100,10_000_000_000,
        ).unwrap();
        let accepted=AcceptedStartOriginDataV1::from_data_v1(first,90_000_000_000,
            120,140,60_000_000_000).unwrap();
        let cutoff=accepted.cutoff_for_sample_data_v1(first).unwrap();
        let origin=StartNativeOriginDataV1::from_data_v1(accepted,first,cutoff).unwrap();
        let later=Some(Ok(RawPairedClockSample::new_untrusted(first.provenance(),
            first.host_boot_id(),120,28_000_000_000).unwrap()));

        assert!(validate_clock(&later,first,cutoff).is_ok());
        assert!(validate_origin_clock(&later,first,cutoff,Some(origin)).is_err());
        assert!(validate_origin_clock(&Some(Ok(first)),first,cutoff,Some(origin)).is_ok());
    }
}
