//! Drives the actual post-ACK Source successor and final public Controller CAS.
//!
//! Every body uses only the destination paid before748 and the matching native
//! Root completion loan. The Source observed attempt carries the actual ACK and
//! signed Inventory commitments. Public terminal is appended only afterward;
//! any independent late native/time failure fences the same Controller writer.

use super::*;
use crate::normal_root::RootStorageApplyCompletionOriginalV1;
use crate::journal::CreateStoppedControllerTerminalAppendOriginalV1;

/// Borrows the actual ACK-gated Source completion boundary for the sole planner.
pub(crate) struct SourceCompletionAuthorizationV1<'turn> {
    association: &'turn CreateStoppedCompletionAssociationV1,
    destination: &'turn ControllerCreateProvisioningCompletionDestinationV1,
    root: &'turn RootStorageApplyCompletionOriginalV1<'turn>,
    before: RawPairedClockSample,
}

impl SourceCompletionAuthorizationV1<'_> {
    pub(crate) fn require_current_v1(&self, original: &CreateProvisioningOriginalsV1, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        self.root.require_attempt_v1(self.association, original, controller)?;
        if self.association.native_turn_v1() != original.native_turn
            || self.association.parent_operation_v1() != original.parent {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let (origin, cutoff) = self.association.original_horizon_v1();
        require_sample(origin, cutoff.min(self.root.cutoff_v1()?), self.association.wall_expiry_v1(), self.before)?;
        original.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_provisioning_completion_native_v1(self.destination,
                original.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?.original_v1(),
                controller, original.profile.as_ref())
    }

    pub(crate) fn before_v1(&self) -> RawPairedClockSample { self.before }
    pub(crate) fn acknowledgement_v1(&self) -> Result<aos_sandbox_core::ObjectDigest, ResourceReservationErrorV1> {
        self.root.acknowledgement_commitment_v1()
    }
    pub(crate) fn inventory_v1(&self) -> aos_sandbox_core::ObjectDigest { self.association.actual.inventory }
}

/// Borrows the real SourceTerminal and prepaid Controller terminal destination.
///
/// It contains no Controller Journal borrow or generic payer. Its only append
/// route retains the complete canonical terminal owner in the same attempt.
#[doc(hidden)]
pub struct CreateStoppedPostAckContextV1<'turn> {
    original: &'turn CreateProvisioningOriginalsV1,
    state: &'turn mut CompletionDestinationV1,
    pre_ack: &'turn PreAckStateV1,
    action: &'turn OriginalPublicationActionV1,
    root: &'turn RootStorageApplyCompletionOriginalV1<'turn>,
}

impl CreateStoppedPostAckContextV1<'_> {
    /// Returns the actual accepted public parent.
    #[must_use]
    pub fn parent_operation_v1(&self) -> aos_sandbox_core::OperationId { self.original.parent }

    /// Returns the original Root6 lane for the canonical unchanged516 receipt.
    #[must_use]
    pub fn lane_v1(&self) -> [u8; 16] { self.pre_ack.lane }

    /// Returns the actual protected project from the issued resource relation.
    #[must_use]
    pub fn project_v1(&self) -> aos_sandbox_core::ProjectId { self.action.contract_v1().records_v1().fields_v1().project }

    /// Returns the actual sandbox from the issued resource relation.
    #[must_use]
    pub fn sandbox_v1(&self) -> aos_sandbox_core::SandboxId { self.action.contract_v1().records_v1().fields_v1().sandbox }

    /// Borrows the same historical Completing receipt, never a future ACK digest.
    ///
    /// # Errors
    /// Refuses absent or failed receipt construction.
    pub fn receipt_bytes_v1(&self) -> Result<&[u8], ResourceReservationErrorV1> {
        self.pre_ack.receipt.as_ref().and_then(|v| v.as_ref().ok()).map(|v|v.as_slice())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Decodes the unchanged actual receipt with its sole canonical decoder.
    ///
    /// # Errors
    /// Refuses malformed or another-method receipt DATA.
    pub fn lifecycle_receipt_v1(&self) -> Result<CreateStoppedLifecycleReceiptDataV1<'_>, ResourceReservationErrorV1> {
        match aos_sandbox_protocol::domain_ledger::effect_history::decode_lifecycle_effect_receipt_v1(
            self.receipt_bytes_v1()?, self.lane_v1()).map_err(|_| ResourceReservationErrorV1::Conflict)? {
            aos_sandbox_protocol::domain_ledger::effect_history::LifecycleEffectReceiptDataV1::CreateStopped(receipt) => Ok(receipt),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    /// Rejoins actual ACK, same native ordinal and positive Source terminal/post.
    ///
    /// # Errors
    /// Refuses an earlier failure, changed writer, already-entered append, missing
    /// native Source after or any substitution of the prepaid destination.
    pub fn require_current_v1(&self, controller: &Journal) -> Result<(), ResourceReservationErrorV1> {
        if self.state.first.is_some() || self.state.controller_after.is_some()
            || self.state.controller_terminal.is_some()
            || !matches!(self.state.terminal.committed, Some(Ok(_)))
            || !matches!(self.state.source_after, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.authorization_v1()?.require_current_v1(self.original, controller)
    }

    fn authorization_v1(&self) -> Result<SourceCompletionAuthorizationV1<'_>, ResourceReservationErrorV1> {
        Ok(SourceCompletionAuthorizationV1 {
            association: self.state.association.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?,
            destination: self.state.controller.as_ref().and_then(|v|v.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?,
            root: self.root,
            before: self.state.before_sample.as_ref().and_then(|v|v.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict)?,
        })
    }

    /// Returns the paid completion clock sampled after actual Root completion.
    ///
    /// # Errors
    /// Refuses missing/failed clock/time admission. The final independent after
    /// must still be observed under this same unchanged cutoff.
    pub fn actual_after_clock_v1(&self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        if !matches!(self.state.controller_time, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        self.state.controller_sample.as_ref().and_then(|v|v.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn require_controller_transition_v1(&self, controller: &Journal, transaction: &crate::JournalTransaction)
        -> Result<(), crate::JournalError> {
        self.require_current_v1(controller).map_err(|_|crate::JournalError::ProtectedBoundary)?;
        use aos_sandbox_protocol::domain_ledger::operation::effect_key;
        let records = transaction.records();
        if records.len() != 3 || records.iter().any(|r|r.value().is_none()) {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        let key = effect_key(self.original.parent, 0);
        let current = controller.get(crate::RecordNamespace::Effect, &key).ok_or(crate::JournalError::ProtectedBoundary)?;
        let mut effects = records.iter().filter(|r|r.namespace()==crate::RecordNamespace::Effect && r.key()==key.as_slice());
        if effects.next().is_none_or(|effect| effect.value()!=Some(current)) || effects.next().is_some()
            || records.iter().filter(|r|r.namespace()==crate::RecordNamespace::Operation && r.key()==self.original.parent.as_bytes()).count()!=1
            || records.iter().filter(|r|r.namespace()==crate::RecordNamespace::DesiredState).count()!=1 {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn final_crossing_v1(&self, controller: &Journal, transaction: &crate::JournalTransaction)
        -> Result<(), crate::JournalError> { self.require_controller_transition_v1(controller, transaction) }

    pub(crate) fn retain_controller_append_original_v1(&mut self, owner: CreateStoppedControllerTerminalAppendOriginalV1)
        -> Result<CommitResult, crate::JournalError> {
        if self.state.controller_terminal.is_some() {
            self.state.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
            self.state.first.get_or_insert(FirstV1::Reentry);
            return Err(crate::JournalError::ProtectedBoundary);
        }
        self.state.controller_terminal = Some(owner);
        let completed = self.state.controller_terminal.as_ref().ok_or(crate::JournalError::ProtectedBoundary)?.completed_v1();
        if completed.is_err() { self.state.first.get_or_insert(FirstV1::Body); }
        completed
    }
}

/// Borrows only an actual Source/C terminal whose native/time posts all passed.
#[doc(hidden)]
pub struct CreateStoppedTerminalOriginalV1<'attempt> { attempt: &'attempt CreateStoppedCompletionAttemptV1 }

impl CreateStoppedTerminalOriginalV1<'_> {
    pub(crate) fn association_v1(&self) -> Result<CreateStoppedCompletionAssociationV1, ResourceReservationErrorV1> {
        self.attempt.completion.association.as_ref().map(CreateStoppedCompletionAssociationV1::duplicate_v1)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn require_same_complete_v1(&self, expected: &CreateStoppedCompletionAssociationV1,
        original: &CreateProvisioningOriginalsV1, controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_association_v1(expected)?;
        controller.ensure_healthy()?;
        if original.parent!=expected.parent_operation_v1() || original.native_turn!=expected.native_turn_v1()
            || self.attempt.completion.controller_position.position()?.next!=controller.snapshot_sequence() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let destination=self.attempt.completion.controller.as_ref().and_then(|v|v.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        original.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_completed_provisioning_completion_native_v1(destination,
                original.native.as_ref().map_err(|_|ResourceReservationErrorV1::Conflict)?.original_v1(),
                controller,original.profile.as_ref())
    }

    pub(crate) fn require_historical_same_complete_v1(&self, expected:&CreateStoppedCompletionAssociationV1,
        original:&CreateProvisioningOriginalsV1,controller:&Journal,
    ) -> Result<(),ResourceReservationErrorV1> {
        self.require_association_v1(expected)?;
        controller.ensure_healthy()?;
        if original.parent!=expected.parent_operation_v1() || original.native_turn!=expected.native_turn_v1() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        original.require_completed_original_v1(controller)
    }

    pub(crate) fn parent_operation_v1(&self) -> Result<aos_sandbox_core::OperationId,ResourceReservationErrorV1> {
        self.attempt.completion.parent.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn q04_v1(&self) -> Result<&Q04CutIdentityV1,ResourceReservationErrorV1> {
        self.attempt.completion.association.as_ref().map(|v|&v.actual.q04).ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn fence_controller_on_refusal_v1(&self, controller: &mut Journal)
        -> Result<(),ResourceReservationErrorV1> {
        // This real terminal proof exists only after the actual same writer's
        // final append and posts. A late closure refusal must fence that writer.
        if self.attempt.completion.controller_position.position()?.next!=controller.snapshot_sequence() {
            let identity=self.attempt.completion.journal_identity.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            controller.fence_create_stopped_completion_v1(identity)?;
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let identity=self.attempt.completion.journal_identity.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        controller.fence_create_stopped_completion_v1(identity)?;
        Ok(())
    }

    pub(crate) fn require_association_v1(&self, expected: &CreateStoppedCompletionAssociationV1)
        -> Result<(), ResourceReservationErrorV1> {
        let state = &self.attempt.completion;
        if state.first.is_some() || !matches!(state.disposal, Some(Ok(())))
            || state.association.as_ref().is_none_or(|actual| !actual.same_original_v1(expected))
            || !state.controller_terminal.as_ref().is_some_and(|owner|owner.completed_v1().is_ok())
            || !matches!(state.terminal.committed, Some(Ok(_)))
            || !matches!(state.final_relation,Some(Ok(())))
            || !matches!(state.payload_retirement,Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

impl CreateStoppedCompletionAttemptV1 {
    /// Completes Source and public Controller state through the prearmed route.
    ///
    /// Every reached Source/native/time post runs independently after body
    /// failure. No new financial turn or after-ACK bound increase occurs.
    ///
    /// # Errors
    /// Retains semantic/readback/append/native/time refusal and poisons the
    /// same public Journal on ambiguous completion. The client stays resident.
    #[doc(hidden)]
    pub fn finish_create_stopped_after_root_once_v1<'attempt>(
        &'attempt mut self, action: &OriginalPublicationActionV1,
        root: &RootStorageApplyCompletionOriginalV1<'_>, original: &CreateProvisioningOriginalsV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<CreateStoppedTerminalOriginalV1<'attempt>, ResourceReservationErrorV1> {
        let body = (|| {
            let mut context = self.prepare_post_ack_context_once_v1(action, root, original, controller, source)?;
            context.state.controller_result = Some(controller.record_create_stopped_terminal_once_v1(&mut context));
            if !matches!(context.state.controller_result, Some(Ok(_))) {
                context.state.first.get_or_insert(FirstV1::Body);
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })();
        // No early return from Source planning, native binding, semantic append
        // or Controller CAS can suppress any already prepaid destination.
        let after = self.finish_create_stopped_completion_native_once_v1(original, controller, source);
        if body.is_err() || after.is_err() { return Err(ResourceReservationErrorV1::Conflict); }
        self.completion.final_relation=Some(self.require_final_rows_v1(original,controller,source));
        if !matches!(self.completion.final_relation,Some(Ok(()))) {
            self.completion.first.get_or_insert(FirstV1::Disposal);
            self.completion.fence=Some(match self.completion.journal_identity.as_ref() {Some(identity)=>controller.fence_create_stopped_completion_v1(identity),None=>Err(crate::JournalError::ProtectedBoundary)});
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.completion.payload_retirement = Some((|| {
            self.completion.controller_terminal.as_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .retire_completed_payloads_v1()?;
            if let Some(Ok(committed)) = self.completion.terminal.committed.as_mut() {
                committed.retire_completed_payloads_v1();
            }
            self.completion.terminal.prepared.take();
            self.completion.terminal.semantic.take();
            Ok(())
        })());
        if !matches!(self.completion.payload_retirement, Some(Ok(()))) {
            self.completion.first.get_or_insert(FirstV1::Disposal);
            self.completion.fence = Some(match self.completion.journal_identity.as_ref() {
                Some(identity) => controller.fence_create_stopped_completion_v1(identity),
                None => Err(crate::JournalError::ProtectedBoundary),
            });
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(CreateStoppedTerminalOriginalV1 { attempt: self })
    }

    fn prepare_post_ack_context_once_v1<'turn>(&'turn mut self,
        action: &'turn OriginalPublicationActionV1, root: &'turn RootStorageApplyCompletionOriginalV1<'turn>,
        original: &'turn CreateProvisioningOriginalsV1, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<CreateStoppedPostAckContextV1<'turn>, ResourceReservationErrorV1> {
        let state = &mut self.completion;
        if state.source_body.is_some() || state.before_sample.is_some() {
            state.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
            state.first.get_or_insert(FirstV1::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.source_body = Some((|| {
            let association = state.association.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            root.require_attempt_v1(association, original, controller)?;
            if state.first.is_some() || action.parent_operation_v1()!=original.parent
                || association.root_admission_v1()!=action.root_admission_commitment_v1()
                || state.native_turn!=original.native_turn {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let (origin, cutoff) = association.original_horizon_v1();
            state.temporal=Some((origin,cutoff.min(root.cutoff_v1()?),association.wall_expiry_v1()));
            state.before_sample = Some(state.before_clock.observe_once(Some(origin)));
            let before = state.before_sample.as_ref().and_then(|v|v.as_ref().ok()).copied();
            let Some(before) = before else { state.first=Some(FirstV1::Clock);return Err(ResourceReservationErrorV1::Conflict); };
            state.before_time = Some(root.actual_after_clock_v1().and_then(|root_after| {
                root_after.validate_later_sample(before).map_err(|_| ResourceReservationErrorV1::Conflict)?;
                require_sample(origin, cutoff.min(root.cutoff_v1()?), association.wall_expiry_v1(), before)
            }));
            if !matches!(state.before_time, Some(Ok(()))) { state.first=Some(FirstV1::Time);return Err(ResourceReservationErrorV1::Conflict); }
            let native = original.native.as_ref().map_err(|_|ResourceReservationErrorV1::Conflict)?.original_v1();
            {
                let bank = original.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?;
                state.native_entry = Some(bank.enter_provisioning_completion_native_v1(
                    state.controller.as_mut().and_then(|v|v.as_mut().ok()).ok_or(ResourceReservationErrorV1::Conflict)?,
                    native, controller, original.profile.as_ref()));
            }
            if !matches!(state.native_entry, Some(Ok(()))) { state.first=Some(FirstV1::Native);return Err(ResourceReservationErrorV1::Conflict); }
            state.terminal.native = state.source.take();
            state.terminal.entered = true;
            state.terminal.native_turn = original.native_turn;
            state.terminal.purpose = SourcePurposeV1::Completing;
            state.source_entry = Some(original.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                .enter_provisioning_source_completion_v1(
                    state.terminal.native.as_mut().and_then(|v|v.as_mut().ok()).ok_or(ResourceReservationErrorV1::Conflict)?,
                    state.controller.as_ref().and_then(|v|v.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?,
                    native, controller, source.journal(), original.profile.as_ref()));
            if !matches!(state.source_entry, Some(Ok(()))) {state.first=Some(FirstV1::SourceEntry);return Err(ResourceReservationErrorV1::Conflict);}
            state.terminal.identity = Some(source.journal_ref_v1().source_provisioning_identity_v1()?);
            state.terminal.expected = Some((|| {
                let owner = LifecycleProtectedJournalOwnerV1::claim(source)?;
                let (_, current) = owner.current_operation_by_id(original.parent)?.ok_or(SourceAdmissionErrorV1::Closed)?;
                let expected = self.pre_ack.source.as_ref().and_then(|v|v.as_ref().ok()).ok_or(SourceAdmissionErrorV1::Closed)?;
                if current.record()!=expected.record || current.operation()!=&expected.operation {
                    return Err(SourceAdmissionErrorV1::Closed);
                }
                state.terminal.predecessor=Some(current.record());
                Ok(current.operation().clone())
            })());
            if !matches!(state.terminal.expected, Some(Ok(_))) {state.terminal.first=Some(crate::controller_resource_reservation::create_intake::provisioning::receiving::source::FirstV1::Expected);return Err(ResourceReservationErrorV1::Conflict);}
            let authority = SourceCompletionAuthorizationV1 {association,
                destination: state.controller.as_ref().and_then(|v|v.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?, root,before};
            {
                let authorization = SourceAdmissionAuthorizationV1 { state: &state.terminal,
                    original, controller, action, root: None, completion: Some(&authority), q04: &association.actual.q04 };
                state.terminal.prepared = Some(LifecycleProtectedJournalOwnerV1::claim(source)
                    .and_then(|owner|owner.prepare_original_create_terminal_source_v1(&authorization)).map_err(SourceAdmissionErrorV1::Lifecycle));
            }
            if !matches!(state.terminal.prepared, Some(Ok(_))) {state.terminal.first=Some(crate::controller_resource_reservation::create_intake::provisioning::receiving::source::FirstV1::Preparation);return Err(ResourceReservationErrorV1::Conflict);}
            let prepared=state.terminal.prepared.as_ref().and_then(|v|v.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            if let Some(transaction)=prepared.transaction_v1() {
                state.terminal.binding=Some(original.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .bind_provisioning_source_completion_v1(
                        state.terminal.native.as_mut().and_then(|v|v.as_mut().ok()).ok_or(ResourceReservationErrorV1::Conflict)?,
                        state.controller.as_ref().and_then(|v|v.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?,
                        native,controller,source.journal(),original.profile.as_ref(),transaction));
                if !matches!(state.terminal.binding,Some(Ok(()))) {state.terminal.first=Some(crate::controller_resource_reservation::create_intake::provisioning::receiving::source::FirstV1::Binding);return Err(ResourceReservationErrorV1::Conflict);}
            }
            let authorization=SourceAdmissionAuthorizationV1 {state:&state.terminal,original,controller,action,root:None,completion:Some(&authority),q04:&association.actual.q04};
            state.terminal.committed=Some(LifecycleProtectedJournalOwnerV1::claim(source).map_err(SourceAdmissionErrorV1::Lifecycle)
                .and_then(|mut owner|owner.commit_original_create_source_admission_v1(prepared,&authorization).map_err(SourceAdmissionErrorV1::Commit)));
            if !matches!(state.terminal.committed,Some(Ok(_))) {state.terminal.first=Some(crate::controller_resource_reservation::create_intake::provisioning::receiving::source::FirstV1::Commit);return Err(ResourceReservationErrorV1::Conflict);}
            Ok(())
        })());
        if !matches!(state.source_body, Some(Ok(()))) { state.first.get_or_insert(FirstV1::Body); }
        // The independent Source post precedes public C finality on both paths.
        if let Some(Ok(native)) = state.terminal.native.as_mut().or(state.source.as_mut()) {
            state.source_after = Some(source.journal_ref_v1().finish_source_provisioning_native_v1(native));
            if !matches!(state.source_after,Some(Ok(()))) {state.first.get_or_insert(FirstV1::SourceAfter);}
        }
        if state.first.is_some() {return Err(ResourceReservationErrorV1::Conflict);}
        let association=state.association.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let (origin,cutoff)=association.original_horizon_v1();
        state.controller_sample=Some(state.controller_clock.observe_once(Some(origin)));
        match state.controller_sample.as_ref() {
            Some(Ok(sample)) => {
                state.controller_time=Some((|| {
                    let previous=state.before_sample.as_ref().and_then(|v|v.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
                    previous.validate_later_sample(*sample).map_err(|_|ResourceReservationErrorV1::Conflict)?;
                    require_sample(origin,cutoff.min(root.cutoff_v1()?),association.wall_expiry_v1(),*sample)
                })());
                if !matches!(state.controller_time,Some(Ok(()))) {state.first=Some(FirstV1::Time);}
            }
            _ => {state.first=Some(FirstV1::Clock);}
        }
        if state.first.is_some() {return Err(ResourceReservationErrorV1::Conflict);}
        Ok(CreateStoppedPostAckContextV1 {original,state,pre_ack:&self.pre_ack,action,root})
    }
}


impl CreateStoppedCompletionAttemptV1 {
    fn require_final_rows_v1(&self, original:&CreateProvisioningOriginalsV1,
        controller:&Journal, source:&mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(),SourceAdmissionErrorV1> {
        controller.ensure_healthy()?;
        source.journal_ref_v1().ensure_healthy()?;
        let association=self.completion.association.as_ref().ok_or(SourceAdmissionErrorV1::Closed)?;
        let expected=self.pre_ack.source.as_ref().and_then(|v|v.as_ref().ok()).ok_or(SourceAdmissionErrorV1::Closed)?;
        let fields=self.completion.terminal.expected.as_ref().and_then(|v|v.as_ref().ok())
            .ok_or(SourceAdmissionErrorV1::Closed)?;
        if fields!=&expected.operation || original.parent!=association.parent_operation_v1() {
            return Err(SourceAdmissionErrorV1::Closed);
        }
        let owner=LifecycleProtectedJournalOwnerV1::claim(source)?;
        let (_,terminal)=owner.current_operation_by_id(original.parent)?.ok_or(SourceAdmissionErrorV1::Closed)?;
        let key=self.final_completing_key_v1()?;
        let historical=owner.current_operation(&key)?.ok_or(SourceAdmissionErrorV1::Closed)?;
        self.require_final_rows_with_lifecycle_v1(original.parent, controller,
            historical.operation(), historical.record(), terminal.operation())
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn require_stored_terminal_association_v1(&self,
        association:&CreateStoppedCompletionAssociationV1,
    )->Result<(),ResourceReservationErrorV1> {
        CreateStoppedTerminalOriginalV1{attempt:self}.require_association_v1(association)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn final_completing_key_v1(&self)
        -> Result<crate::lifecycle::LifecycleProtectedJournalKeyV1, SourceAdmissionErrorV1> {
        let association=self.completion.association.as_ref().ok_or(SourceAdmissionErrorV1::Closed)?;
        let expected=self.pre_ack.source.as_ref().and_then(|v|v.as_ref().ok()).ok_or(SourceAdmissionErrorV1::Closed)?;
        Ok(crate::lifecycle::lifecycle_protected_key_v1(
            crate::lifecycle::LifecycleProtectedRecordKindV1::Effect,expected.operation.project(),
            aos_sandbox_core::ResourceId::from_bytes(association.actual.q04.sandbox().into_bytes()),
            association.parent_operation_v1())?)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn require_final_rows_with_lifecycle_v1(&self,
        parent: aos_sandbox_core::OperationId, controller: &Journal,
        historical: &crate::lifecycle::LifecycleOperationV1,
        historical_record: crate::lifecycle::LifecycleRecordDigestV1,
        terminal: &crate::lifecycle::LifecycleOperationV1,
    ) -> Result<(), SourceAdmissionErrorV1> {
        controller.ensure_healthy()?;
        let association=self.completion.association.as_ref().ok_or(SourceAdmissionErrorV1::Closed)?;
        let expected=self.pre_ack.source.as_ref().and_then(|v|v.as_ref().ok()).ok_or(SourceAdmissionErrorV1::Closed)?;
        let fields=self.completion.terminal.expected.as_ref().and_then(|v|v.as_ref().ok())
            .ok_or(SourceAdmissionErrorV1::Closed)?;
        if fields!=&expected.operation || parent!=association.parent_operation_v1() {
            return Err(SourceAdmissionErrorV1::Closed);
        }
        if historical_record!=expected.record || historical!=&expected.operation {
            return Err(SourceAdmissionErrorV1::Closed);
        }
        crate::cold_launch_publication::completion::require_create_terminal_source_v1(
            historical,historical_record,terminal,association.actual.inventory)?;
        let op=controller.get(crate::RecordNamespace::Operation,parent.as_bytes()).ok_or(SourceAdmissionErrorV1::Closed)?;
        let key=aos_sandbox_protocol::domain_ledger::operation::effect_key(parent,0);
        let effect=controller.get(crate::RecordNamespace::Effect,&key).ok_or(SourceAdmissionErrorV1::Closed)?;
        aos_sandbox_protocol::domain_ledger::effect_history::CreateStoppedTerminalTransactionDataV1::from_data_v1(
            parent,association.actual.q04.project(),association.actual.q04.sandbox(),op,effect)
            .map_err(|_|SourceAdmissionErrorV1::Closed)?;
        let (effect,_) = aos_sandbox_protocol::domain_ledger::effect_history::decode_effect_with_q04(effect)?;
        if !matches!(effect.state(),aos_sandbox_protocol::domain_ledger::effect_history::EffectState::Applied{receipt,..}
            if receipt.as_bytes()==association.receipt_bytes_v1().as_slice()) {return Err(SourceAdmissionErrorV1::Closed);}
        use aos_sandbox_protocol::public_api::projection::{PublicProjectionKindV1,PublicProjectionResourceV1};
        let projection=crate::controller_service::public_projection::PublicProjectionStoreV1::new(controller)
            .get(PublicProjectionKindV1::Sandbox,association.actual.q04.sandbox().into_bytes())
            .map_err(|_|SourceAdmissionErrorV1::Closed)?.ok_or(SourceAdmissionErrorV1::Closed)?;
        let PublicProjectionResourceV1::Sandbox(sandbox)=projection.resource() else {return Err(SourceAdmissionErrorV1::Closed);};
        if sandbox.sandbox_id.as_slice()!=association.actual.q04.sandbox().as_bytes()
            || sandbox.project_id.as_slice()!=association.actual.q04.project().as_bytes()
            || sandbox.observed.as_option().is_none_or(|observed| observed.phase.as_known()!=Some(aos_proto::aos::sandbox::v1::SandboxPhase::SANDBOX_PHASE_STOPPED)
                || !observed.incarnation_id.is_empty() || !observed.node_id.is_empty() || observed.assignment_epoch!=0) {
            return Err(SourceAdmissionErrorV1::Closed);
        }
        Ok(())
    }

    /// Borrows historical completed Create only after its original positive posts.
    ///
    /// This does not restart its expired admission window. A fresh Start must
    /// independently join the closed Root client and its own new native purpose.
    ///
    /// # Errors
    /// Refuses absent/failing final relation or changed actual Source/C rows.
    #[doc(hidden)]
    pub fn borrow_create_stopped_terminal_original_v1<'attempt>(&'attempt self,
        original:&CreateProvisioningOriginalsV1, controller:&Journal,
        source:&mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<CreateStoppedTerminalOriginalV1<'attempt>,ResourceReservationErrorV1> {
        if self.completion.first.is_some() || !matches!(self.completion.disposal,Some(Ok(())))
            || !matches!(self.completion.final_relation,Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        original.require_completed_original_v1(controller)?;
        self.require_final_rows_v1(original,controller,source).map_err(|_|ResourceReservationErrorV1::Conflict)?;
        Ok(CreateStoppedTerminalOriginalV1 {attempt:self})
    }
}


impl CreateStoppedCompletionAttemptV1 {
    // The new native purpose uses only this already completed live custody.
    // Its full historical semantic fold remains a separately funded frontier.
    pub(super) fn require_stored_terminal_custody_v1(
        &self, association: &CreateStoppedCompletionAssociationV1,
        original: &CreateProvisioningOriginalsV1, controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        CreateStoppedTerminalOriginalV1 { attempt: self }
            .require_historical_same_complete_v1(association, original, controller)
    }
}
