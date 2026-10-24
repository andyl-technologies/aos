//! Holds the actual Root8, U and peer through one Controller signing attempt.
//!
//! Root's original frame remains on its resident stream owner. This loan has no
//! parsed-byte constructor or key. It admits the concrete signing carriers,
//! retains the final native clock, and owes a full Root/Source/Cache post after
//! every entered attempt, including a failed preparation or signature.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{ObjectDigest, RawPairedClockSample, ResourceDimension as D,
    ResourceVector};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::Journal;
use aos_sandbox_policy::storage_create_use_data::StorageCreateUseSecurityShapeDataV1;
use crate::journal::broker_session_receiving::{
    storage_create_use_signing_receiving_demand_v1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use super::*;
use super::super::use_reserved::OriginalCreateStorageUseReservedV1;

use super::CreateStorageRootExchangeClosedV1 as Closed;

#[derive(Clone, Copy)]
enum First { Geometry, Funding, Before, Predecessor, Clock, ClockCheck, After, Closed }

#[derive(Default)]
pub(super) struct CreateStorageSigningOriginalsV1 {
    entered: bool,
    demand: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    before_entered: bool,
    before: Option<Result<(), Closed>>,
    endpoint_association: Option<Result<(), super::super::client_session::ClientSessionAssociationErrorV1>>,
    predecessor_association: Option<Result<(), super::super::client_session::ClientSessionAssociationErrorV1>>,
    predecessor: super::super::outcome_receiving::OutcomeReplayReceivingOriginalsV1,
    predecessor_funding_failed: bool,
    clock: RetainedKernelPairedClockAttemptV1,
    clock_result: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    clock_check: Option<Result<(), ResourceReservationErrorV1>>,
    after_entered: bool,
    after: Option<Result<(), Closed>>,
    first: Option<First>,
    closed: Option<Closed>,
    finished: bool,
    complete: bool,
}

impl CreateStorageSigningOriginalsV1 {
    pub(super) fn started(&self) -> bool { self.entered }

    pub(super) fn funding_failed(&self) -> bool { matches!(self.first, Some(First::Funding))
        || (matches!(self.first, Some(First::Predecessor)) && self.predecessor_funding_failed) }

    pub(super) fn before_is_owed(&self) -> bool { self.before_entered && self.before.is_none() }

    pub(super) fn after_is_owed(&self) -> bool { self.after_entered && self.after.is_none() }

    pub(super) fn failure<'a>(&'a self,
        peer: &'a CreateStorageRootPeerReceivingOriginalsV1,
    ) -> Option<&'a (dyn Error + 'static)> {
        match self.first? {
            First::Geometry => cause(&self.demand),
            First::Funding => cause(&self.funding),
            First::Before => peer.failure().or_else(|| cause(&self.before)),
            First::Predecessor => cause(&self.endpoint_association)
                .or_else(|| cause(&self.predecessor_association))
                .or_else(|| self.predecessor.failure()),
            First::Clock => self.clock.failure().or_else(|| cause(&self.clock_result)),
            First::ClockCheck => cause(&self.clock_check),
            First::After => peer.failure().or_else(|| cause(&self.after)),
            First::Closed => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

pub(in crate::controller_resource_reservation) fn signing_originals_receiving_demand_v1()
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    let invalid = || ResourceReservationErrorV1::Conflict;
    let clock = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
        .and_then(|bytes| bytes.checked_sub(size_of::<RetainedKernelPairedClockAttemptV1>()))
        .ok_or_else(invalid)?;
    // Fixed clock results use bytes and the temporary procfs input uses its
    // descriptor permit. This phase creates no namespace map or pathname.
    let bytes = size_of::<CreateStorageSigningOriginalsV1>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(size_of::<OriginalCreateStorageUseSigningV1<'_, '_, '_>>().checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(clock)).ok_or_else(invalid)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
        .with(D::OpenFiles, u64::try_from(RetainedKernelPairedClockAttemptV1::
            MAXIMUM_RETAINED_FILES_V1).map_err(|_| invalid())?))
        .and_then(|fixed| fixed.checked_add(super::super::outcome_receiving::
            OutcomeReplayReceivingOriginalsV1::fixed_receiving_demand_v1()?)
            .map_err(ResourceReservationErrorV1::Accounting))
}

/// Borrows exact admitted signing inputs without a native signing grant.
///
/// The values remain borrowed from the actual completed Root8 and verified
/// Ownership original. A pure semantic check must still compare the protected
/// proposal and public signer; only the same long native loan can sample its
/// final clock and complete the independently owed original posts.
#[doc(hidden)]
pub struct CreateStorageUseSigningInputsDataV1<'held> {
    /// The exact original Root-admitted canonical unsigned plan.
    pub plan: &'held [u8],
    /// The exact original Root-admitted canonical signing statement.
    pub statement: &'held [u8],
    /// The actual verified lease retained by this operation's Ownership owner.
    pub lease: &'held SignedOwnershipLease,
    /// The policy digest in the same canonical AssignmentPlanned manifest.
    pub policy_digest: ObjectDigest,
    /// The completed before observation's actual native clock sample.
    pub clock: RawPairedClockSample,
    /// The minimum accepted operation and original RootHello deadline.
    pub cutoff: u64,
}

/// Holds one genuine completed Root8 and returned U through actual signing.
///
/// Its private constructor borrows the same Ready, Root peer, Source, Cache and
/// actual bank reservation. Parsed frames, scalar vectors, keys or caller IDs
/// cannot construct it. The actual caller keeps its raw signature and model
/// errors resident and invokes [`Self::finish_after_once`] on every entered path.
#[doc(hidden)]
#[must_use = "retain the actual U/Root loan through signing and its owed post"]
pub struct OriginalCreateStorageUseSigningV1<'turn, 'original, 'cache> {
    root: OriginalCreateStorageRootExchangeV1<'turn, 'original, 'cache>,
    peer: &'turn mut CreateStorageRootPeerReceivingOriginalsV1,
    reserved: OriginalCreateStorageUseReservedV1<'turn>,
    lease: &'turn SignedOwnershipLease,
    policy_digest: ObjectDigest,
    client: &'turn super::super::client_session::ClientSessionOriginalsV1,
}

impl<'original, 'cache> OriginalCreateStorageReadyV1<'original, 'cache> {
    /// Borrows and admits the actual completed Root8 for one signing attempt.
    ///
    /// The shape is concrete installed Security layout DATA. The same U pays
    /// the shared signing recipe before public-policy/model/key construction;
    /// all following Root observations debit its actual monotone ledger.
    ///
    /// # Errors
    /// Rejects earlier failure, reentry, incomplete Root8/U, changed original
    /// lease/Cache/controller position, insufficient U or failed before/post.
    #[doc(hidden)]
    pub fn borrow_original_storage_signing_once<'turn>(
        &'turn mut self, shape: StorageCreateUseSecurityShapeDataV1,
    ) -> Result<OriginalCreateStorageUseSigningV1<'turn, 'turn, 'cache>, Closed> {
        if self.failure().is_some() { return Err(Closed); }
        self.original.require_operation_currentness_peak_v1(&self.cache).map_err(|_| Closed)?;
        let owner = &mut *self.original.owner;
        let (lease, policy_digest) = owner.ownership.verified_signing_material_v1(&owner.assignment)
            .map_err(|_| Closed)?;
        let root = &mut owner.root_exchange;
        if root.turn.signing.entered || root.turn.samples.iter().any(Option::is_some)
            || root.peer.failure().is_some() {
            return Err(Closed);
        }
        let (reserved, receiving) = owner.storage_use.split_reserved_receiving_v1()
            .map_err(|_| Closed)?;
        root.borrow_use_admitted_v1(&reserved).map_err(|_| Closed)?;
        let root_loan = OriginalCreateStorageRootExchangeV1 {
            parent: &owner.parent, intake: &mut owner.intake,
            controller: self.original.controller, source: self.original.source,
            profile: self.original.profile, cache: &mut self.cache,
            state: &mut root.turn, use_receiving: Some(RootUseReceivingV1::Original(receiving)),
        };
        let mut loan = OriginalCreateStorageUseSigningV1 {
            root: root_loan, peer: &mut root.peer, reserved, lease, policy_digest,
            client: &owner.client_session,
        };
        if loan.enter_once(shape).is_err() {
            // A failed pure pre-entry traffic reservation owes no new IO. Once
            // entered, every actual refusal retains its independent full post.
            if loan.root.state.signing.entered { let _ = loan.finish_after_once(); }
            return Err(Closed);
        }
        Ok(loan)
    }

    /// Checks the actual signing original after its independently owed post.
    ///
    /// This is a read-only native phase check. It proves no signature, append,
    /// Prepare, release or Effect completion and constructs no new borrower.
    ///
    /// # Errors
    /// Rejects any incomplete, failed or abandoned signing native phase.
    #[doc(hidden)]
    pub fn require_original_storage_signing_complete_v1(&self) -> Result<(), Closed> {
        self.original.owner.root_exchange.require_completed_signing_v1()
            .map_err(|_| Closed)
    }

    /// Borrows the actual signing phase's chronological native cause.
    ///
    /// This performs no IO, admission or new loan construction. Upper callers
    /// keep an earlier semantic or signature cause ahead of this later post.
    #[doc(hidden)]
    #[must_use]
    pub fn original_storage_signing_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let root = &self.original.owner.root_exchange;
        if root.turn.signing.funding_failed() {
            self.original.owner.storage_use.failure()
                .or_else(|| root.turn.signing.failure(&root.peer))
        } else { root.turn.signing.failure(&root.peer) }
    }
}

impl OriginalCreateStorageUseSigningV1<'_, '_, '_> {
    fn enter_once(&mut self, shape: StorageCreateUseSecurityShapeDataV1) -> Result<(), Closed> {
        self.root.prepay_use_root_observations_once(3)?;
        self.root.state.signing.entered = true;
        self.root.state.signing.demand = Some((|| {
            let request = self.reserved.request_shape_bytes_v1()?;
            storage_create_use_signing_receiving_demand_v1(request, shape)
                .map_err(|_| ResourceReservationErrorV1::Conflict)
        })());
        if !matches!(self.root.state.signing.demand, Some(Ok(_))) {
            self.root.state.signing.first = Some(First::Geometry);
            return Err(Closed);
        }
        let demand = *self.root.state.signing.demand.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(Closed)?;
        self.root.state.signing.funding = Some(self.root.use_receiving.as_mut()
            .ok_or(Closed)?.reserve_once(demand));
        if !matches!(self.root.state.signing.funding, Some(Ok(()))) {
            self.root.state.signing.first = Some(First::Funding);
            return Err(Closed);
        }
        self.root.state.signing.before_entered = true;
        self.root.state.owed_post = Some(RootPostFrontierV1::UseSigningBefore);
        let before = self.peer.recheck_once(&mut self.root);
        self.root.state.signing.before = Some(before);
        if !matches!(self.root.state.signing.before, Some(Ok(()))) {
            self.root.state.signing.first = Some(First::Before);
            return Err(Closed);
        }
        self.root.borrow_use_admitted_v1(&self.reserved).map_err(|_| Closed)?;
        Ok(())
    }

    /// Borrows the original admitted plan, statement and verified lease.
    ///
    /// # Errors
    /// Refuses an incomplete or failed admission/before sample or changed
    /// native U/Root8 association. No allocation, clock or IO is performed.
    pub fn inputs_v1(&self) -> Result<CreateStorageUseSigningInputsDataV1<'_>, Closed> {
        if self.root.state.signing.first.is_some()
            || !matches!(self.root.state.signing.before, Some(Ok(()))) {
            return Err(Closed);
        }
        let admitted = self.root.borrow_use_admitted_v1(&self.reserved).map_err(|_| Closed)?;
        Ok(CreateStorageUseSigningInputsDataV1 {
            plan: admitted.plan_v1().map_err(|_| Closed)?,
            statement: admitted.statement_v1().map_err(|_| Closed)?,
            lease: self.lease, policy_digest: self.policy_digest,
            clock: self.root.state.last_native_clock.ok_or(Closed)?,
            cutoff: admitted.cutoff_v1(),
        })
    }

    /// Admits the complete same-Session predecessor before canonical replay.
    ///
    /// The same original Client verifies intrinsic Journal identity before the
    /// existing sampler captures actual held-file/materialized-map extent. U
    /// pays that complete existing replay/traffic/terminal supplier before any
    /// canonical decoder or method admission is entered.
    ///
    /// # Errors
    /// Retains a foreign Session, fixed metadata/extent/geometry error, reentry
    /// or actual U accounting refusal. The independent Root post remains owed.
    pub fn admit_original_session_predecessor_once(&mut self, journal: &Journal,
        endpoint: CreateStorageEndpointRevalidationShapeDataV1,
    )
        -> Result<(), Closed>
    {
        if self.root.state.signing.first.is_some()
            || self.root.state.signing.predecessor_association.is_some()
            || !matches!(self.root.state.signing.before, Some(Ok(()))) {
            return Err(Closed);
        }
        self.root.state.signing.endpoint_association = Some(
            self.client.require_completed_endpoint_shape_v1(endpoint));
        self.root.state.signing.predecessor_association = Some(
            self.client.require_completed_journal_v1(journal));
        let result = (|| {
            if !matches!(self.root.state.signing.endpoint_association, Some(Ok(())))
                || !matches!(self.root.state.signing.predecessor_association, Some(Ok(()))) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            self.root.state.signing.predecessor.capture_once(journal,
                super::super::outcome_receiving::OutcomeReplayRosterV1::CreateSigning)?;
            let demand = self.root.state.signing.predecessor.demand_v1()?;
            let admission = self.root.use_receiving.as_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?.reserve_once(demand);
            self.root.state.signing.predecessor_funding_failed = admission.is_err();
            self.root.state.signing.predecessor.retain_admission_once(admission)
        })();
        if result.is_err() {
            self.root.state.signing.first = Some(First::Predecessor);
            Err(Closed)
        } else { Ok(()) }
    }

    /// Requires this exact original's complete canonical comparison admission.
    ///
    /// # Errors
    /// Refuses absent or failed same-Journal admission without new native work.
    pub fn require_original_session_predecessor_prepaid_v1(&self) -> Result<(), Closed> {
        self.root.state.signing.predecessor.require_admitted_v1().map_err(|_| Closed)
    }

    /// Borrows the exact normalized request width in the actual U reservation.
    ///
    /// # Errors
    /// Refuses an incomplete or failed native reserve/UseReserved original.
    pub fn request_shape_bytes_v1(&self) -> Result<usize, Closed> {
        self.reserved.request_shape_bytes_v1().map_err(|_| Closed)
    }

    /// Samples and retains the final native clock immediately before signing.
    ///
    /// The actual caller first validates the prepared key-message loan, then
    /// calls this method and checks its prepared statement's wall interval
    /// before the unchanged Core raw signature operation. No key is exposed.
    ///
    /// # Errors
    /// Rejects repetition, incomplete before gates, changed boot/paired time,
    /// exhausted original cutoff or expired/not-yet-valid verified lease.
    pub fn final_clock_once(&mut self) -> Result<RawPairedClockSample, Closed> {
        if self.root.state.signing.first.is_some()
            || self.root.state.signing.clock_result.is_some()
            || !matches!(self.root.state.signing.before, Some(Ok(()))) {
            return Err(Closed);
        }
        self.require_original_session_predecessor_prepaid_v1()?;
        let cutoff = self.root.borrow_use_admitted_v1(&self.reserved)
            .map_err(|_| Closed)?.cutoff_v1();
        let original = self.root.intake.create_storage_j_data_v1().map_err(|_| Closed)?.clock;
        self.root.state.signing.clock_result = Some(
            self.root.state.signing.clock.observe_once(Some(original)));
        let sample = match self.root.state.signing.clock_result.as_ref() {
            Some(Ok(sample)) => *sample,
            _ => {
                self.root.state.signing.first = Some(First::Clock);
                return Err(Closed);
            }
        };
        self.root.state.signing.clock_check = Some(if sample.boottime_nanoseconds() < cutoff
            && sample.wall_seconds() >= self.lease.authority_issued_seconds()
            && sample.wall_seconds() < self.lease.authority_expires_seconds() {
            Ok(())
        } else { Err(ResourceReservationErrorV1::Conflict) });
        if !matches!(self.root.state.signing.clock_check, Some(Ok(()))) {
            self.root.state.signing.first = Some(First::ClockCheck);
            return Err(Closed);
        }
        Ok(sample)
    }

    /// Runs the independently owed full original post once after the attempt.
    ///
    /// This must run after semantic/key/signature failure as well as success.
    /// It finishes native currentness only; it does not assert a signature,
    /// append Signed, dispatch Prepare, commit U or report Create completion.
    ///
    /// # Errors
    /// Retains reentry, original peer/Source/Cache/controller/cutoff failure or
    /// an incomplete final clock. An earlier upper cause stays with its flight.
    pub fn finish_after_once(&mut self) -> Result<(), Closed> {
        if !self.root.state.signing.entered || self.root.state.signing.after_entered {
            return Err(Closed);
        }
        self.root.state.signing.after_entered = true;
        self.root.state.owed_post = Some(RootPostFrontierV1::UseSigningAfter);
        let after = self.peer.recheck_once(&mut self.root);
        self.root.state.signing.after = Some(after);
        let state = &mut self.root.state.signing;
        if !matches!(state.after, Some(Ok(()))) { state.first.get_or_insert(First::After); }
        state.finished = true;
        state.complete = state.first.is_none() && matches!(state.clock_check, Some(Ok(())));
        if state.complete { Ok(()) } else {
            state.first.get_or_insert(First::Closed);
            state.closed.get_or_insert(Closed);
            Err(Closed)
        }
    }
}

impl Drop for OriginalCreateStorageUseSigningV1<'_, '_, '_> {
    fn drop(&mut self) {
        let state = &mut self.root.state.signing;
        if state.entered && !state.finished {
            state.first.get_or_insert(First::Closed);
            state.closed.get_or_insert(Closed);
        }
    }
}


impl RootExchangeOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn require_completed_signing_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if self.turn.signing.complete && self.turn.signing.failure(&self.peer).is_none() {
            Ok(())
        } else { Err(ResourceReservationErrorV1::Conflict) }
    }
}
