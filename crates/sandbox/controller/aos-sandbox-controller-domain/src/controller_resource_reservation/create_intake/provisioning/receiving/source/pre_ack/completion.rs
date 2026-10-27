//! Owns the exact terminal destination paid before the final Root request.
//!
//! The association is minted only after genuine Completing/Applied pre-ACK
//! disposition and both actual native destinations are prearmed. Its private
//! shared identity survives a move across the async exchange; neither receipt
//! DATA nor a decoded ACK constructs it or authorizes another native turn.

mod terminal;
mod custody;
pub use custody::CreateStoppedTerminalCustodyV1;
pub(crate) use terminal::SourceCompletionAuthorizationV1;
pub use terminal::{CreateStoppedPostAckContextV1, CreateStoppedTerminalOriginalV1};

use super::*;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningCompletionDestinationV1;
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use aos_sandbox_model::RawPairedClockSample;

#[derive(Clone, Copy)]
enum FirstV1 { Entry, Geometry, Funding, SourceArm, ControllerArm, Association, Clock, Time, Native, SourceEntry, Body, SourceAfter, ControllerAfter, AfterClock, AfterTime, Position, Disposal, Reentry }

struct AssociationDataV1 {
    parent: aos_sandbox_model::OperationId,
    native_turn: u64,
    root_admission: [u8; 32],
    lane: [u8; 16],
    receipt: [u8; CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1],
    controller: crate::controller_resource_reservation::CreateStorageWriterPositionV1,
    source: crate::controller_resource_reservation::CreateStorageWriterPositionV1,
    origin: RawPairedClockSample,
    cutoff: u64,
    wall_expiry: i64,
    q04: Q04CutIdentityV1,
    inventory: aos_sandbox_model::ObjectDigest,
    creation_workspace: ([u8; 32], [u8; 16]),
}

/// Retains the private identity of one actually prepaid completion destination.
///
/// No public constructor or arbitrary native position adopter exists. Internal
/// clones share the same original identity and cannot authorize another turn.
#[doc(hidden)]
pub struct CreateStoppedCompletionAssociationV1 { actual: Arc<AssociationDataV1> }

impl CreateStoppedCompletionAssociationV1 {
    // The private constructor captures this tuple from the actual pre-ACK
    // selected workspace. It is historical comparison DATA, never a live grant.
    pub(crate) fn creation_workspace_selectors_v2(&self) -> ([u8; 32], [u8; 16]) {
        self.actual.creation_workspace
    }

    pub(crate) fn duplicate_v1(&self) -> Self { Self { actual: Arc::clone(&self.actual) } }
    pub(crate) fn same_original_v1(&self, other: &Self) -> bool { Arc::ptr_eq(&self.actual, &other.actual) }
    pub(crate) fn parent_operation_v1(&self) -> aos_sandbox_model::OperationId { self.actual.parent }
    pub(crate) fn native_turn_v1(&self) -> u64 { self.actual.native_turn }
    pub(crate) fn root_admission_v1(&self) -> [u8; 32] { self.actual.root_admission }
    pub(crate) fn lane_v1(&self) -> [u8; 16] { self.actual.lane }
    pub(crate) fn receipt_bytes_v1(&self) -> &[u8; CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1] { &self.actual.receipt }
    pub(crate) fn original_horizon_v1(&self) -> (RawPairedClockSample, u64) { (self.actual.origin, self.actual.cutoff) }
    pub(crate) fn wall_expiry_v1(&self) -> i64 { self.actual.wall_expiry }

    pub(crate) fn controller_native_v1(&self) -> [u8; 64] { encode_position(self.actual.controller) }
    pub(crate) fn source_native_v1(&self) -> [u8; 64] { encode_position(self.actual.source) }
}

fn encode_position(position: crate::controller_resource_reservation::CreateStorageWriterPositionV1) -> [u8; 64] {
    let mut bytes = [0; 64];
    bytes[..48].copy_from_slice(&position.names.to_bytes());
    bytes[48..56].copy_from_slice(&position.next.to_be_bytes());
    bytes[56..].copy_from_slice(&position.end.to_be_bytes());
    bytes
}

#[derive(Default)]
pub(super) struct CompletionDestinationV1 {
    entered: bool,
    journal_identity: Option<crate::journal::source_provisioning::CreateStoppedControllerIdentityV1>,
    fence: Option<Result<(),crate::JournalError>>,
    parent: Option<aos_sandbox_model::OperationId>,
    native_turn: u64,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    funding_original: bool,
    temporal: Option<(RawPairedClockSample, u64, i64)>,
    source: Option<Result<SourceProvisioningCurrentnessOriginalV1, ResourceReservationErrorV1>>,
    controller: Option<Result<ControllerCreateProvisioningCompletionDestinationV1, ResourceReservationErrorV1>>,
    association: Option<CreateStoppedCompletionAssociationV1>,
    base: Option<ResourceVector>,
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_time: Option<Result<(), ResourceReservationErrorV1>>,
    controller_clock: RetainedKernelPairedClockAttemptV1,
    controller_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    controller_time: Option<Result<(), ResourceReservationErrorV1>>,
    native_entry: Option<Result<(), ResourceReservationErrorV1>>,
    source_entry: Option<Result<(), ResourceReservationErrorV1>>,
    source_after: Option<Result<(), crate::JournalError>>,
    controller_after: Option<Result<(), ResourceReservationErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_time: Option<Result<(), ResourceReservationErrorV1>>,
    disposal: Option<Result<(), ResourceReservationErrorV1>>,
    native_disposition: Option<Result<(), ResourceReservationErrorV1>>,
    final_relation: Option<Result<(), SourceAdmissionErrorV1>>,
    payload_retirement: Option<Result<(), ResourceReservationErrorV1>>,
    terminal: SourceTurnOriginalsV1,
    source_body: Option<Result<(), ResourceReservationErrorV1>>,
    controller_terminal: Option<crate::journal::CreateStoppedControllerTerminalAppendOriginalV1>,
    controller_result: Option<Result<CommitResult, crate::JournalError>>,
    source_position: CreateStorageWriterPositionOriginalV1,
    controller_position: CreateStorageWriterPositionOriginalV1,
    first: Option<FirstV1>,
    reentry: Option<ResourceReservationErrorV1>,
}

impl CompletionDestinationV1 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            FirstV1::Entry => cause(&self.entry),
            FirstV1::Geometry => cause(&self.geometry),
            FirstV1::Funding => cause(&self.funding),
            FirstV1::SourceArm | FirstV1::SourceEntry => self.terminal.native.as_ref().or(self.source.as_ref()).and_then(|v| match v {
                Ok(native) => native.failure(), Err(cause) => Some(cause as _),
            }).or_else(|| cause(&self.source_entry)),
            FirstV1::ControllerArm | FirstV1::Native => self.controller.as_ref().and_then(|v| match v {
                Ok(native) => native.failure(), Err(cause) => Some(cause as _),
            }).or_else(|| cause(&self.native_entry)),
            FirstV1::Clock => self.before_clock.failure().or_else(|| cause(&self.before_sample))
                .or_else(|| self.controller_clock.failure()).or_else(|| cause(&self.controller_sample)),
            FirstV1::Time => cause(&self.before_time).or_else(|| cause(&self.controller_time)),
            FirstV1::SourceAfter => self.terminal.native.as_ref().or(self.source.as_ref()).and_then(|v|v.as_ref().ok()).and_then(|native|native.failure())
                .or_else(||cause(&self.source_after)),
            FirstV1::ControllerAfter => self.controller.as_ref().and_then(|v|v.as_ref().ok()).and_then(|native|native.failure())
                .or_else(||cause(&self.controller_after)),
            FirstV1::AfterClock => self.after_clock.failure().or_else(|| cause(&self.after_sample)),
            FirstV1::AfterTime => cause(&self.after_time),
            FirstV1::Position => self.source_position.failure().or_else(||self.controller_position.failure())
                .or_else(||cause(&self.native_disposition)),
            FirstV1::Disposal => cause(&self.native_disposition).or_else(||cause(&self.disposal))
                .or_else(||cause(&self.final_relation)).or_else(||cause(&self.payload_retirement)),
            FirstV1::Body => self.terminal.failure().or_else(|| cause(&self.source_body))
                .or_else(|| self.controller_terminal.as_ref().and_then(|owner| owner.failure()))
                .or_else(|| cause(&self.controller_result)),
            FirstV1::Association | FirstV1::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }
}

/// Borrows only the actual pending receipt and its already-paid destination.
///
/// It borrows neither the whole C23 receiver nor the Root client, allowing the
/// same short financial loan to drive the final RPC while custody stays held.
#[doc(hidden)]
pub struct CreateStoppedPreAckOriginalV1<'attempt> { attempt: &'attempt CreateStoppedCompletionAttemptV1 }

impl CreateStoppedPreAckOriginalV1<'_> {
    pub(crate) fn association_v1(&self) -> Result<CreateStoppedCompletionAssociationV1, ResourceReservationErrorV1> {
        self.attempt.completion.association.as_ref().map(CreateStoppedCompletionAssociationV1::duplicate_v1)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn require_current_v1(&self, loan: &OriginalCreateProvisioningRootLoanV1<'_, '_>,
        action: &OriginalPublicationActionV1, controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        loan.require_current_v1(controller)?;
        let state = &self.attempt.completion;
        let actual = state.association.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if state.first.is_some() || !state.entered || state.native_turn != loan.native_turn_v1()
            || state.parent != Some(loan.parent_operation_v1()) || state.controller.as_ref().is_none_or(|v|
                v.as_ref().is_err() || v.as_ref().is_ok_and(|n| n.failure().is_some()))
            || state.source.as_ref().is_none_or(|v| v.as_ref().is_err() || v.as_ref().is_ok_and(|n| n.failure().is_some()))
            || actual.actual.root_admission != action.root_admission_commitment_v1()
            || action.parent_operation_v1() != actual.actual.parent
            || self.attempt.pre_ack.first.is_some() || !matches!(self.attempt.pre_ack.disposal, Some(Ok(())))
            || controller.snapshot_sequence() != actual.actual.controller.next {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn receipt_v1(&self) -> Result<CreateStoppedLifecycleReceiptDataV1<'_>, ResourceReservationErrorV1> {
        let association = self.attempt.completion.association.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        match aos_sandbox_protocol::domain_ledger::effect_history::decode_lifecycle_effect_receipt_v1(
            &association.actual.receipt, association.actual.lane).map_err(|_| ResourceReservationErrorV1::Conflict)? {
            aos_sandbox_protocol::domain_ledger::effect_history::LifecycleEffectReceiptDataV1::CreateStopped(v) => Ok(v),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn terminal_destination_receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.attempt.completion.base.ok_or(ResourceReservationErrorV1::Conflict)
    }
}

impl OriginalCreateProvisioningRootLoanV1<'_, '_> {
    /// Prepays and retains the exact completion destination before any final wire.
    ///
    /// This fresh C23 turn follows positive pre-ACK disposition. No Root
    /// publication interval is opened: the final client's own before/post pair
    /// supplies the independent Root observations for this exact turn.
    ///
    /// # Errors
    /// Retains geometry, admission and native arm refusals in the same attempt.
    #[doc(hidden)]
    pub fn prearm_create_stopped_completion_once_v1<'attempt>(&mut self,
        attempt: &'attempt mut CreateStoppedCompletionAttemptV1,
        action: &OriginalPublicationActionV1, root: &RootStorageApplyClientOriginalV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<CreateStoppedPreAckOriginalV1<'attempt>, ResourceReservationErrorV1> {
        let state = &mut attempt.completion;
        if state.entered {
            state.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
            state.first.get_or_insert(FirstV1::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.entered = true;
        self.receiving.completion_entered = true;
        state.native_turn = self.receiving.native_turn;
        state.parent = Some(self.receiving.parent);
        state.entry = Some((|| {
            state.journal_identity=Some(controller.create_stopped_controller_identity_v1()?);
            let current=self.require_current_v1(controller);
            if current.is_err() && self.receiving.failure().is_some() {state.funding_original=true;}
            current?;
            if attempt.pre_ack.first.is_some() || !matches!(attempt.pre_ack.disposal, Some(Ok(())))
                || attempt.pre_ack.parent != Some(self.receiving.parent)
                || attempt.pre_ack.native_turn >= self.receiving.native_turn
                || action.parent_operation_v1() != self.receiving.parent {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let admission = root.borrow_admission_v1(self, controller).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            if admission.parent_operation_v1() != self.receiving.parent
                || admission.reply_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?.digest_v1()
                    .map_err(|_| ResourceReservationErrorV1::Conflict)? != action.root_admission_commitment_v1() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let temporal = aos_sandbox_protocol::domain_ledger::provisioning_root::storage_apply::StorageApplyAdmissionDataV1::decode_v1(
                admission.reply_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?.admission)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            state.temporal = Some((admission.original_horizon_v1().0,
                admission.cutoff_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?,
                temporal.policy_expires_seconds.min(temporal.lease_expires_seconds)
                    .min(action.storage_apply_plan_expires_seconds_v1()?)));
            let c = attempt.pre_ack.controller_position.position()?;
            let s = attempt.pre_ack.source_position.position()?;
            if c.next != controller.snapshot_sequence() || s.next != source.journal_ref_v1().snapshot_sequence() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        if !matches!(state.entry, Some(Ok(()))) {
            state.first = Some(FirstV1::Entry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.geometry = Some((|| {
            // The three clock backings stay resident. Their native files peak
            // at two destinations: a failed earlier clock suppresses Controller
            // entry, while the independent final after remains owed.
            let clocks = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
                .and_then(|n| n.checked_mul(3)).ok_or(ResourceReservationErrorV1::Conflict)?;
            let own = std::mem::size_of::<CreateStoppedCompletionAttemptV1>().checked_mul(2)
                .and_then(|n| n.checked_add(std::mem::size_of::<AssociationDataV1>().checked_add(2 * std::mem::size_of::<usize>())?.checked_mul(2)?))
                .and_then(|n| n.checked_add(clocks))
                .and_then(|n| n.checked_add(std::mem::size_of::<CompletionFailureViewV1<'static>>().checked_mul(2)?))
                .and_then(|n| u64::try_from(n).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let c = crate::journal::create_stopped_terminal_receiving_demand_v1(controller, self.receiving.parent)?;
            let source_models = crate::lifecycle::create_provisioning_committed_source_receiving_demand_v1(source.journal_ref_v1())?;
            let fixed = ControllerCreateProvisioningCompletionDestinationV1::receiving_demand_v1(self.receiving.profile.lower_original_v1())
                .map_err(ResourceReservationErrorV1::from)?;
            Ok(action.resident_receiving_demand_v1(controller)?
                .checked_add(root.resident_receiving_demand_v1()?)?
                .checked_add(c)?.checked_add(source_models)?
                .checked_add(crate::journal::create_storage_name_peak_demand_v1()?)?
                .checked_add(SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?)?
                .checked_add(fixed)?
                .checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, own)
                    .with(ResourceDimension::OpenFiles, 2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64))?)
        })());
        let Some(complete) = state.geometry.as_ref().and_then(|v| v.as_ref().ok()).copied() else {
            state.first = Some(FirstV1::Geometry);
            return Err(ResourceReservationErrorV1::Conflict);
        };
        state.base = Some(complete);
        state.funding = Some(self.receiving.require_complete_v1(controller, complete));
        if !matches!(state.funding, Some(Ok(()))) {
            state.funding_original = self.receiving.failure().is_some();
            state.first = Some(FirstV1::Funding);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.source = Some((|| {
            let bank = self.receiving.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            bank.prearm_provisioning_source_completion_v1(
                self.receiving.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?.original_mut_v1(),
                controller, source.journal(), self.receiving.profile.as_ref(), complete)
        })());
        if state.source.as_ref().is_none_or(|v| v.as_ref().is_err() || v.as_ref().is_ok_and(|n| n.failure().is_some())) {
            state.funding_original = self.receiving.failure().is_some();
            state.first = Some(FirstV1::SourceArm);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.controller = Some((|| {
            let bank = self.receiving.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            bank.prearm_provisioning_completion_native_v1(
                self.receiving.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?.original_mut_v1(),
                controller, self.receiving.profile.as_ref(), complete)
        })());
        if state.controller.as_ref().is_none_or(|v| v.as_ref().is_err() || v.as_ref().is_ok_and(|n| n.failure().is_some())) {
            state.funding_original = self.receiving.failure().is_some();
            state.first = Some(FirstV1::ControllerArm);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let association = (|| {
            let admission = root.borrow_admission_v1(self, controller).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let reply = admission.reply_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let temporal = aos_sandbox_protocol::domain_ledger::provisioning_root::storage_apply::StorageApplyAdmissionDataV1::decode_v1(reply.admission)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            Ok(CreateStoppedCompletionAssociationV1 { actual: Arc::new(AssociationDataV1 {
                parent: self.receiving.parent, native_turn: self.receiving.native_turn,
                root_admission: action.root_admission_commitment_v1(), lane: attempt.pre_ack.lane,
                receipt: *attempt.pre_ack.receipt.as_ref().and_then(|v| v.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?,
                controller: attempt.pre_ack.controller_position.position()?, source: attempt.pre_ack.source_position.position()?,
                origin: admission.original_horizon_v1().0, cutoff: admission.cutoff_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?,
                wall_expiry: temporal.policy_expires_seconds.min(temporal.lease_expires_seconds)
                    .min(action.storage_apply_plan_expires_seconds_v1()?),
                q04: self.completed.source_q04_identity_v1()?.clone(),
                inventory: attempt.pre_ack.inventory.ok_or(ResourceReservationErrorV1::Conflict)?,
                creation_workspace: attempt.pre_ack.creation_workspace
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
            }) })
        })();
        match association {
            Ok(association) => state.association = Some(association),
            Err(cause) => {
                state.reentry = Some(cause); state.first = Some(FirstV1::Association);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        Ok(CreateStoppedPreAckOriginalV1 { attempt })
    }
}

impl CreateStoppedCompletionAttemptV1 {
    /// Identifies an actual final-entry attempt for its inherited owed Root post.
    #[must_use]
    pub fn final_entry_started_v1(&self) -> bool { self.completion.entered }

    /// Borrows only the retained first final-entry/native cause.
    #[must_use]
    pub fn final_failure_with_original_v1<'cause>(&'cause self, original: &'cause CreateProvisioningOriginalsV1)
        -> Option<&'cause (dyn Error + 'static)> {
        if matches!(self.completion.first, Some(FirstV1::Entry | FirstV1::Funding | FirstV1::SourceArm | FirstV1::ControllerArm)) && self.completion.funding_original
            && self.completion.parent == Some(original.parent) {
            original.failure().or_else(|| self.completion.failure())
        } else { self.completion.failure() }
    }
}


fn require_sample(origin: RawPairedClockSample, cutoff: u64, expires: i64, sample: RawPairedClockSample)
    -> Result<(), ResourceReservationErrorV1> {
    origin.validate_later_sample(sample).map_err(|_| ResourceReservationErrorV1::Conflict)?;
    if sample.boottime_nanoseconds() >= cutoff || sample.wall_seconds() >= expires {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    Ok(())
}

impl CreateStoppedCompletionAttemptV1 {
    /// Returns only the actual entered final parent for its prepaid refusal post.
    #[must_use]
    pub fn final_parent_operation_v1(&self) -> Option<aos_sandbox_model::OperationId> {
        self.completion.entered.then_some(self.completion.parent).flatten()
    }

    /// Returns only the actual entered final native ordinal as comparison DATA.
    #[must_use]
    pub fn final_native_turn_v1(&self) -> Option<u64> {
        self.completion.entered.then_some(self.completion.native_turn)
    }

    /// Runs every reached prepaid terminal post, including failed ACK entry.
    ///
    /// This method requires no healthy financial entry or positive body. A
    /// missing/failed SourceTerminal or Controller CAS cannot suppress native
    /// disposal attempts. Ambiguity poisons the same public Controller Journal.
    ///
    /// # Errors
    /// Retains the earliest body/native/clock failure and refuses repeated posts.
    #[doc(hidden)]
    pub fn finish_create_stopped_completion_native_once_v1(&mut self,
        receiving: &CreateProvisioningOriginalsV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = &mut self.completion;
        if state.controller_after.is_some() || state.after_sample.is_some() || state.disposal.is_some() {
            state.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
            state.first.get_or_insert(FirstV1::Reentry);
            state.fence=Some(match state.journal_identity.as_ref() {Some(identity)=>controller.fence_create_stopped_completion_v1(identity),None=>Err(crate::JournalError::ProtectedBoundary)});
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if !state.entered { return Err(ResourceReservationErrorV1::Conflict); }
        if state.source_after.is_none() {
            let native = state.terminal.native.as_mut().or(state.source.as_mut());
            if let Some(Ok(native)) = native {
                state.source_after = Some(source.journal_ref_v1().finish_source_provisioning_native_v1(native));
                if !matches!(state.source_after, Some(Ok(()))) { state.first.get_or_insert(FirstV1::SourceAfter); }
            }
        }
        if let Some(Ok(destination)) = state.controller.as_mut() {
            state.controller_after = Some((|| {
                let bank = receiving.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
                bank.finish_provisioning_completion_native_v1(destination, controller, receiving.profile.as_ref())
            })());
            if !matches!(state.controller_after, Some(Ok(()))) { state.first.get_or_insert(FirstV1::ControllerAfter); }
        }
        state.native_disposition = Some((|| {
            if state.first.is_some() || state.native_turn != receiving.native_turn
                || state.parent != Some(receiving.parent)
                || !matches!(state.source_after, Some(Ok(())))
                || !matches!(state.controller_after, Some(Ok(())))
                || !state.controller_terminal.as_ref().is_some_and(|owner| owner.completed_v1().is_ok())
                || !matches!(state.terminal.committed, Some(Ok(_))) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let bank = receiving.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            bank.dispose_provisioning_source_completion_v1(
                state.terminal.native.as_mut().and_then(|v| v.as_mut().ok()).ok_or(ResourceReservationErrorV1::Conflict)?,
                state.controller.as_ref().and_then(|v| v.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?,
                receiving.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?.original_v1(),
                controller, source.journal(), receiving.profile.as_ref())?;
            state.source_position.capture_once(source.journal_ref_v1(), crate::controller_resource_reservation::HistoryRoleV1::Source);
            state.source_position.position()?;
            state.controller_position.capture_once(controller, crate::controller_resource_reservation::HistoryRoleV1::Controller);
            state.controller_position.position()?;
            Ok(())
        })());
        if !matches!(state.native_disposition,Some(Ok(()))) {
            state.first.get_or_insert(if state.source_position.failure().is_some() || state.controller_position.failure().is_some() {
                FirstV1::Position
            } else {FirstV1::Disposal});
        }
        if matches!(state.funding, Some(Ok(()))) {
            if let Some((origin, cutoff, expires)) = state.temporal {
                state.after_sample = Some(state.after_clock.observe_once(Some(origin)));
                match state.after_sample.as_ref() {
                    Some(Ok(sample)) => {
                        state.after_time = Some((|| {
                            if let Some(previous)=state.controller_sample.as_ref().or(state.before_sample.as_ref()).and_then(|v|v.as_ref().ok()) {
                                previous.validate_later_sample(*sample).map_err(|_|ResourceReservationErrorV1::Conflict)?;
                            }
                            require_sample(origin, cutoff, expires, *sample)
                        })());
                        if !matches!(state.after_time, Some(Ok(()))) { state.first.get_or_insert(FirstV1::AfterTime); }
                    }
                    _ => { state.first.get_or_insert(FirstV1::AfterClock); }
                }
            }
        }
        state.disposal=Some(if matches!(state.native_disposition,Some(Ok(())))
            && matches!(state.after_time,Some(Ok(()))) && state.first.is_none() { Ok(()) }
            else { Err(ResourceReservationErrorV1::Conflict) });
        if !matches!(state.disposal, Some(Ok(()))) {
            state.first.get_or_insert(FirstV1::Disposal);
            state.fence=Some(match state.journal_identity.as_ref() {Some(identity)=>controller.fence_create_stopped_completion_v1(identity),None=>Err(crate::JournalError::ProtectedBoundary)});
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}


#[cfg(test)]
mod time_tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;

    fn sample(wall:i64,boot:u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(RawClockProvenance::new_untrusted([1;16]).unwrap(),
            [2;16],wall,boot*1_000_000_000).unwrap()
    }

    #[test]
    fn prepaid_completion_never_renews_original_or_wall_deadline() {
        let original=sample(100,10);
        assert!(require_sample(original,30_000_000_000,120,sample(119,29)).is_ok());
        assert!(require_sample(original,30_000_000_000,120,sample(120,29)).is_err());
        assert!(require_sample(original,30_000_000_000,120,sample(119,30)).is_err());
        assert!(require_sample(original,30_000_000_000,120,sample(99,11)).is_err());
    }
}


struct CompletionFailureViewV1<'cause> {
    attempt: &'cause CreateStoppedCompletionAttemptV1,
    original: &'cause CreateProvisioningOriginalsV1,
}

impl std::fmt::Display for CompletionFailureViewV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = &self.attempt.completion;
        let original_selected = matches!(state.first, Some(
            FirstV1::Entry | FirstV1::Funding | FirstV1::SourceArm | FirstV1::ControllerArm,
        )) && state.funding_original && state.parent == Some(self.original.parent);
        if !original_selected && matches!(state.first, Some(
            FirstV1::ControllerArm | FirstV1::Native | FirstV1::ControllerAfter,
        )) {
            if let Some(Ok(destination)) = state.controller.as_ref() {
                if let Some(view) = destination.profile_failure_view_v1() {
                    return formatter.debug_struct("ControllerProfileFailureViewV1")
                        .field("phase", &view.phase())
                        .field("classification", &view.classification())
                        .field("cause", &view.cause())
                        .field("property", &view.property_failure())
                        .finish();
                }
            }
        }
        match self.attempt.final_failure_with_original_v1(self.original) {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("the actual Create completion has no retained failure"),
        }
    }
}

impl CreateStoppedCompletionAttemptV1 {
    /// Borrows the selected completion diagnostic without copying its archive.
    ///
    /// The actual e44 profile archive is guarded only while formatting at its
    /// selected native frontier. Earlier semantic or financial causes keep
    /// precedence and are rendered through their original borrowed errors.
    #[must_use]
    pub fn final_failure_view_with_original_v1<'cause>(
        &'cause self, original: &'cause CreateProvisioningOriginalsV1,
    ) -> Option<impl std::fmt::Display + 'cause> {
        self.final_failure_with_original_v1(original)?;
        Some(CompletionFailureViewV1 { attempt: self, original })
    }
}
