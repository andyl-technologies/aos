//! Retains the genuine Completing-to-Controller pre-ACK boundary.
//!
//! The receipt names the actual canonical Source Completing record, never a
//! prospective terminal or future Root acknowledgement. Failed native/model/
//! append prefixes remain in this external owner beside the same C23 original.

mod completion;
pub(crate) use completion::SourceCompletionAuthorizationV1;
pub use completion::{CreateStoppedCompletionAssociationV1, CreateStoppedPreAckOriginalV1,
    CreateStoppedPostAckContextV1, CreateStoppedTerminalOriginalV1, CreateStoppedTerminalCustodyV1};

use super::*;
use crate::journal::{CommitResult, CreateStoppedControllerPreAckAppendOriginalV1};
use crate::lifecycle::{LifecyclePhaseV1, LifecycleRecordDigestV1};
use aos_sandbox_protocol::domain_ledger::effect_history::{
    CreateStoppedLifecycleReceiptDataV1, CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1,
    lifecycle_child_effect_commitment_v1,
};
use crate::journal::CreateStorageWriterPositionOriginalV1;

#[derive(Clone, Copy)]
enum PreAckFirstV1 { Entry, Native, Models, Source, Receipt, Append, After, Position, Disposal, Reentry }

struct CompletingSourceV1 {
    operation: LifecycleOperationV1,
    record: LifecycleRecordDigestV1,
}

/// Retains actual Create pre-ACK custody without constructing completion rights.
///
/// The empty value admits no work. Only the actual same-intake Root loan may
/// enter it, derive its real receipt, or arm its separate post-ACK destination.
#[doc(hidden)]
#[derive(Default)]
pub struct CreateStoppedCompletionAttemptV1 {
    pre_ack: PreAckStateV1,
    completion: completion::CompletionDestinationV1,
}

#[derive(Default)]
struct PreAckStateV1 {
    entered: bool,
    native_turn: u64,
    parent: Option<aos_sandbox_model::OperationId>,
    lane: [u8; 16],
    base: Option<ResourceVector>,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    entry_selected_original: bool,
    entry_selected_root: bool,
    models_selected_original: bool,
    retirement: Option<Result<(), crate::JournalError>>,
    inventory: Option<aos_sandbox_model::ObjectDigest>,
    creation_workspace: Option<([u8; 32], [u8; 16])>,
    native: Option<Result<SourceProvisioningCurrentnessOriginalV1, ResourceReservationErrorV1>>,
    models: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    source: Option<Result<CompletingSourceV1, SourceAdmissionErrorV1>>,
    receipt: Option<Result<[u8; CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1], SourceAdmissionErrorV1>>,
    append: Option<CreateStoppedControllerPreAckAppendOriginalV1>,
    append_admission: Option<Result<(), ResourceReservationErrorV1>>,
    after: Option<Result<(), crate::JournalError>>,
    controller_position: CreateStorageWriterPositionOriginalV1,
    source_position: CreateStorageWriterPositionOriginalV1,
    disposal: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<PreAckFirstV1>,
    reentry: Option<ResourceReservationErrorV1>,
}

impl PreAckStateV1 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            PreAckFirstV1::Entry => cause(&self.entry),
            PreAckFirstV1::Native => self.native.as_ref().and_then(|result| match result {
                Ok(native) => native.failure(), Err(cause) => Some(cause as _),
            }),
            PreAckFirstV1::Models => cause(&self.models),
            PreAckFirstV1::Source => cause(&self.source),
            PreAckFirstV1::Receipt => cause(&self.receipt),
            PreAckFirstV1::Append => self.append.as_ref().and_then(|original| original.failure())
                .or_else(|| cause(&self.append_admission)),
            PreAckFirstV1::After => cause(&self.after),
            PreAckFirstV1::Position => self.source_position.failure()
                .or_else(|| self.controller_position.failure()),
            PreAckFirstV1::Disposal => cause(&self.disposal).or_else(|| cause(&self.retirement)),
            PreAckFirstV1::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }
}

/// Borrows the actual receipt-producing Source interval and same C23 original.
///
/// This opaque context holds no Controller Journal borrow. The one canonical
/// append owner can therefore reborrow that same writer and retain its complete
/// failed models without aliasing or extracting an account or generic payer.
#[doc(hidden)]
pub struct CreateStoppedPreAckContextV1<'turn> {
    original: &'turn mut CreateProvisioningOriginalsV1,
    state: &'turn mut PreAckStateV1,
    action: &'turn OriginalPublicationActionV1,
    root: &'turn RootStorageApplyCurrentTurnV1<'turn>,
}

impl CreateStoppedPreAckContextV1<'_> {
    /// Rejoins the genuine current Root, C23 and actual Source receipt stage.
    ///
    /// # Errors
    /// Refuses a failed, foreign, disposed or substituted original boundary.
    #[doc(hidden)]
    pub fn require_current_v1(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        self.root.require_action_v1(self.action, self.original, controller)?;
        if !self.state.entered || self.state.first.is_some() || self.state.after.is_some()
            || self.state.append.is_some()
            || self.state.native_turn != self.original.native_turn
            || self.state.parent != Some(self.original.parent)
            || !matches!(self.state.source, Some(Ok(_)))
            || !matches!(self.state.receipt, Some(Ok(_)))
            || !self.state.native.as_ref().is_some_and(|result|
                result.as_ref().is_ok_and(|native| native.failure().is_none())) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Returns the same original lane as comparison DATA.
    #[must_use]
    pub const fn lane_v1(&self) -> [u8; 16] { self.state.lane }

    /// Returns the actual accepted Create parent retained by this context.
    #[must_use]
    pub const fn parent_operation_v1(&self) -> aos_sandbox_model::OperationId { self.original.parent }

    /// Borrows only the canonical receipt produced from the actual Source row.
    ///
    /// # Errors
    /// Refuses an absent or failed receipt; parsed DATA cannot construct this context.
    #[doc(hidden)]
    pub fn lifecycle_receipt_v1(&self)
        -> Result<CreateStoppedLifecycleReceiptDataV1<'_>, ResourceReservationErrorV1> {
        let bytes = self.state.receipt.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        match aos_sandbox_protocol::domain_ledger::effect_history::decode_lifecycle_effect_receipt_v1(
            bytes, self.state.lane).map_err(|_| ResourceReservationErrorV1::Conflict)? {
            aos_sandbox_protocol::domain_ledger::effect_history::LifecycleEffectReceiptDataV1::CreateStopped(receipt) => Ok(receipt),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn original_v1(&self) -> &CreateProvisioningOriginalsV1 { self.original }

    /// Pays the exact reached Controller append models before their construction.
    ///
    /// This cost-only method grants no receipt or append authority. The actual
    /// closed append owner still verifies the sole parent/whole transaction.
    ///
    /// # Errors
    /// Retains failure of the same original's complete co-resident requirement.
    #[doc(hidden)]
    pub fn admit_controller_append_v1(&mut self, controller: &Journal, extra: ResourceVector)
        -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        self.state.append_admission = Some((|| {
            let complete = self.state.base.ok_or(ResourceReservationErrorV1::Conflict)?
                .checked_add(extra)?;
            self.original.require_complete_v1(controller, complete)
        })());
        if matches!(self.state.append_admission, Some(Ok(()))) { Ok(()) }
        else {
            self.state.first.get_or_insert(PreAckFirstV1::Append);
            Err(ResourceReservationErrorV1::Conflict)
        }
    }

    pub(crate) fn retain_controller_append_original_v1(&mut self,
        original: CreateStoppedControllerPreAckAppendOriginalV1,
    ) -> Result<CommitResult, crate::JournalError> {
        if self.state.append.is_some() {
            self.state.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
            self.state.first.get_or_insert(PreAckFirstV1::Reentry);
            return Err(crate::JournalError::ProtectedBoundary);
        }
        self.state.append = Some(original);
        let completed = self.state.append.as_ref()
            .ok_or(crate::JournalError::ProtectedBoundary)?.completed_v1();
        if completed.is_err() { self.state.first.get_or_insert(PreAckFirstV1::Append); }
        completed
    }
}

impl OriginalCreateProvisioningRootLoanV1<'_, '_> {
    /// Derives the genuine pre-ACK receipt from actual Completing and workspace.
    ///
    /// The external attempt retains every reached native and model result.
    /// Its Source after, C23 after and Root after remain mandatory even when
    /// this constructor refuses and no positive context can be borrowed.
    ///
    /// # Errors
    /// Refuses another stage, failed currentness, changed workspace/Source or
    /// unpayable representation without constructing pre-ACK completion rights.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_create_stopped_pre_ack_context_once_v1<'turn>(
        &'turn mut self, attempt: &'turn mut CreateStoppedCompletionAttemptV1,
        action: &'turn OriginalPublicationActionV1,
        root: &'turn RootStorageApplyCurrentTurnV1<'turn>,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        workspace: &crate::StorageProvisioningWorkspaceOriginalV1<'_>,
    ) -> Result<CreateStoppedPreAckContextV1<'turn>, ResourceReservationErrorV1> {
        let state = &mut attempt.pre_ack;
        if state.entered {
            state.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
            state.first.get_or_insert(PreAckFirstV1::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.entered = true;
        state.native_turn = self.receiving.native_turn;
        state.parent = Some(self.receiving.parent);
        state.entry = Some((|| {
            let current = root.require_action_v1(action, self.receiving, controller);
            state.entry_selected_root = current.is_err();
            current?;
            self.completed.require_current_v1()?;
            let completing = self.receiving.source.turn_v1(SourcePurposeV1::Completing);
            if !matches!(completing.disposal, Some(Ok(()))) || completing.failure().is_some() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let fixed = std::mem::size_of::<CreateStoppedCompletionAttemptV1>().checked_mul(2)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CreateStoppedPreAckContextV1<'static>>().checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            let complete = action.resident_receiving_demand_v1(controller)?
                .checked_add(root.receiving_demand_v1()?)?
                .checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, fixed))?
                .checked_add(CreateStoppedControllerPreAckAppendOriginalV1::fixed_receiving_demand_v1()?)?
                .checked_add(crate::journal::create_storage_name_peak_demand_v1()?)?;
            state.base = Some(complete);
            let admitted = self.receiving.require_complete_v1(controller, complete);
            state.entry_selected_original = admitted.is_err() && self.receiving.failure().is_some();
            admitted?;
            let native = self.receiving.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?.original_mut_v1();
            state.native = Some(self.receiving.bank.lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .begin_provisioning_source_native_v1(native, controller, source.journal(),
                    self.receiving.profile.as_ref(), complete));
            Ok(())
        })());
        if !matches!(state.entry, Some(Ok(()))) {
            state.first = Some(PreAckFirstV1::Entry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if !state.native.as_ref().is_some_and(|result| result.as_ref().is_ok_and(|native| native.failure().is_none())) {
            state.first = Some(PreAckFirstV1::Native);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.models = Some((|| {
            let complete = state.base.ok_or(ResourceReservationErrorV1::Conflict)?
                .checked_add(SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?)?
                .checked_add(crate::lifecycle::create_provisioning_committed_source_receiving_demand_v1(source.journal_ref_v1())?)?
                .checked_add(crate::cold_launch_publication::completion::create_stopped_controller_receiving_demand_v1(
                    controller.historical_read_view_v1().materialized_state_v1()).ok_or(ResourceReservationErrorV1::Conflict)?)?
                .checked_add(crate::cold_launch_publication::completion::create_workspace_comparison_receiving_demand_v1()
                    .ok_or(ResourceReservationErrorV1::Conflict)?)?;
            let admitted = self.receiving.require_complete_v1(controller, complete);
            state.models_selected_original = admitted.is_err() && self.receiving.failure().is_some();
            admitted?;
            Ok(complete)
        })());
        let Some(complete) = state.models.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            state.first = Some(PreAckFirstV1::Models);
            return Err(ResourceReservationErrorV1::Conflict);
        };
        state.base = Some(complete);
        state.source = Some((|| {
            self.require_storage_workspace_original_v1(workspace, controller)?;
            action.child_for_current_source_v1(self.receiving, root, controller)?;
            let context = PublicMutationEffectHistoryV1::decode(self.completed.accepted_context_v1()?)?
                .ok_or(SourceAdmissionErrorV1::Closed)?;
            let request = context.validated_request()?;
            let admission = lifecycle_public_mutation_admission_v1(controller, self.receiving.parent,
                context.project(), self.original_node_v1()?, &request)?;
            let expected = lifecycle_operation_from_public_mutation_v1(self.receiving.parent,
                context.caller(), context.project(), context.accepted_wall_seconds(),
                context.canonical_request(), &request, admission)?;
            let owner = LifecycleProtectedJournalOwnerV1::claim(source)?;
            let (_, current) = owner.current_operation_by_id(self.receiving.parent)?
                .ok_or(SourceAdmissionErrorV1::Closed)?;
            let operation = current.operation();
            crate::lifecycle::require_same_lifecycle_admission_v1(&expected, operation)?;
            if operation.phase() != LifecyclePhaseV1::Completing
                || operation.semantic_commit().is_none() || operation.terminal_result().is_some()
                || operation.finished_at().is_some() || operation.project() != action.contract_v1().records_v1().fields_v1().project
                || !matches!(operation.intent(), LifecycleIntentV1::Create { sandbox }
                    if *sandbox == action.contract_v1().records_v1().fields_v1().sandbox) {
                return Err(SourceAdmissionErrorV1::Closed);
            }
            let child = action.child_for_current_source_v1(self.receiving, root, controller)?;
            let records = child.records_v1();
            let fields = records.fields_v1();
            let (child_effect, gate) = aos_sandbox_protocol::domain_ledger::effect_history::
                decode_effect_with_q04(child.applied_effect_v1())?;
            if gate.is_some() { return Err(SourceAdmissionErrorV1::Closed); }
            let child_operation = aos_sandbox_protocol::domain_ledger::operation::decode_operation(
                controller.get(crate::RecordNamespace::Operation, fields.publication_operation.as_bytes())
                    .ok_or(SourceAdmissionErrorV1::Closed)?)?;
            let binding = crate::runtime_authority::RuntimeAuthorityStore::load(controller,
                crate::runtime_authority::RuntimeAuthorityLimits::default())?
                .current(fields.sandbox)?.ok_or(SourceAdmissionErrorV1::Closed)?;
            let publication = crate::publication::AuthorityPublicationStore::new(controller)
                .current(fields.sandbox)?.ok_or(SourceAdmissionErrorV1::Closed)?;
            crate::cold_launch_publication::completion::require_create_workspace_v1(
                crate::cold_launch_publication::completion::CreateWorkspaceSubjectsV1 {
                    resources: records, child_operation, child: &child_effect,
                    binding: &binding, publication: &publication,
                    apply: workspace.apply_outcome_v1(), apply_response: workspace.apply_result_v1(),
                    inventory_exchange: workspace.inventory_outcome_v1(), inventory: &workspace.inventory_model_v1().0,
                    admitted_plan: root.admitted_canonical_plan_v1(action, self.receiving, controller)?,
                })?;
            crate::cold_launch_publication::completion::require_create_source_semantic_v1(operation, records, &binding)?;
            // Retain only fixed selectors after the full original workspace
            // relation succeeded. A later Start cannot reenter the old C23.
            let selected = crate::cold_launch_publication::completion::
                selected_create_workspace_inventory_data_v2(records, &binding,
                    workspace.apply_result_v1(), &workspace.inventory_model_v1().0)?;
            state.creation_workspace = Some((*selected.workspace_handle(),
                *selected.creation_operation_id()));
            state.inventory = Some(aos_sandbox_model::ObjectDigest::from_bytes(
                workspace.inventory_model_v1().0.encoded_response_digest_v1()));
            Ok(CompletingSourceV1 { operation: operation.clone(), record: current.record() })
        })());
        if !matches!(state.source, Some(Ok(_))) {
            state.first = Some(PreAckFirstV1::Source);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.receipt = Some((|| {
            let child = action.child_for_current_source_v1(self.receiving, root, controller)?;
            let source = state.source.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(SourceAdmissionErrorV1::Closed)?;
            state.lane = self.completed.intake.intake.create_lane()?;
            let receipt = CreateStoppedLifecycleReceiptDataV1::from_data_v1(
                self.receiving.parent, source.record.digest(),
                lifecycle_child_effect_commitment_v1(child.applied_effect_v1()), child.records_v1(),
                self.completed.root_closed_receipt_v1()?, state.lane)?;
            Ok(receipt.encode_v1(state.lane)?)
        })());
        if !matches!(state.receipt, Some(Ok(_))) {
            state.first = Some(PreAckFirstV1::Receipt);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(CreateStoppedPreAckContextV1 { original: self.receiving, state, action, root })
    }
}

impl CreateStoppedCompletionAttemptV1 {
    /// Runs the already prepaid Source post independently of the append result.
    ///
    /// # Errors
    /// Retains an actual Source post/position failure or once-only refusal.
    /// Even a failed context constructor must pass this same owner here.
    #[doc(hidden)]
    pub fn finish_pre_ack_source_after_append_once_v1(&mut self,
        controller: &Journal, source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = &mut self.pre_ack;
        if state.after.is_some() {
            state.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
            state.first.get_or_insert(PreAckFirstV1::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if let Some(Ok(native)) = state.native.as_mut() {
            state.after = Some(source.journal_ref_v1().finish_source_provisioning_native_v1(native));
            if !matches!(state.after, Some(Ok(()))) {
                state.first.get_or_insert(PreAckFirstV1::After);
            }
        }
        if state.first.is_none() && state.append.as_ref().is_some_and(|owner| owner.completed_v1().is_ok()) {
            // The complete Source pair has already observed its independent
            // after. These additional positive cut captures produce only DATA;
            // no failed prefix is disposed or used to enter final Root work.
            state.source_position.capture_once(source.journal_ref_v1(), crate::controller_resource_reservation::HistoryRoleV1::Source);
            if state.source_position.failure().is_some() {
                state.first = Some(PreAckFirstV1::Position);
            } else {
                state.controller_position.capture_once(controller, crate::controller_resource_reservation::HistoryRoleV1::Controller);
                if state.controller_position.failure().is_some() {
                    state.first = Some(PreAckFirstV1::Position);
                }
            }
        }
        if state.first.is_none() && state.source_position.position().is_ok()
            && state.controller_position.position().is_ok() { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    /// Disposes only the actual pre-ACK native pair after C23 and Root posts.
    ///
    /// # Errors
    /// Refuses any earlier failure, changed Source/C native cut, another turn,
    /// missing independent post or repeated disposition. No terminal is minted.
    #[doc(hidden)]
    pub fn finish_pre_ack_after_original_posts_once_v1(&mut self,
        action: &OriginalPublicationActionV1,
        root: &RootStorageApplyClientOriginalV1,
        receiving: &CreateProvisioningOriginalsV1,
        controller: &Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = &mut self.pre_ack;
        if state.disposal.is_some() {
            state.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
            state.first.get_or_insert(PreAckFirstV1::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        state.disposal = Some((|| {
            if state.first.is_some() || state.native_turn != receiving.native_turn
                || state.parent != Some(receiving.parent) || !matches!(state.after, Some(Ok(())))
                || !state.append.as_ref().is_some_and(|owner| owner.completed_v1().is_ok()) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            root.require_completed_publication_turn_v1(action, receiving, controller)?;
            receiving.require_completed_original_v1(controller)?;
            receiving.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .dispose_provisioning_source_native_v1(
                    state.native.as_mut().and_then(|result| result.as_mut().ok())
                        .ok_or(ResourceReservationErrorV1::Conflict)?,
                    receiving.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?.original_v1(),
                    controller, source.journal(), receiving.profile.as_ref())
        })());
        if matches!(state.disposal, Some(Ok(()))) {
            state.retirement = Some(state.append.as_mut().ok_or(crate::JournalError::ProtectedBoundary)
                .and_then(|owner| owner.retire_completed_payloads_v1()));
            if !matches!(state.retirement, Some(Ok(()))) {
                state.first.get_or_insert(PreAckFirstV1::Disposal);
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        }
        else {
            state.first.get_or_insert(PreAckFirstV1::Disposal);
            Err(ResourceReservationErrorV1::Conflict)
        }
    }

    /// Identifies only the actually selected Root entry refusal for diagnostics.
    #[must_use]
    pub fn root_entry_failure_is_selected_v1(&self) -> bool {
        matches!(self.pre_ack.first, Some(PreAckFirstV1::Entry))
            && self.pre_ack.entry_selected_root
    }

    /// Borrows this same pre-ACK attempt's actual retained first cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> { self.pre_ack.failure() }
}

impl CreateStoppedCompletionAttemptV1 {
    /// Borrows the exact first source-bearing cause from this same actual C23.
    #[must_use]
    pub fn failure_with_original_v1<'a>(&'a self, original: &'a CreateProvisioningOriginalsV1)
        -> Option<&'a (dyn Error + 'static)> {
        if self.pre_ack.parent == Some(original.parent)
            && ((matches!(self.pre_ack.first, Some(PreAckFirstV1::Entry)) && self.pre_ack.entry_selected_original)
                || (matches!(self.pre_ack.first, Some(PreAckFirstV1::Models)) && self.pre_ack.models_selected_original)) {
            return original.failure().or_else(|| self.pre_ack.failure());
        }
        if self.pre_ack.parent == Some(original.parent)
            && matches!(self.pre_ack.first, Some(PreAckFirstV1::Append)) {
            return self.pre_ack.append.as_ref()
                .and_then(|owner| owner.failure_with_original_v1(original))
                .or_else(|| self.pre_ack.failure());
        }
        self.pre_ack.failure()
    }
}

impl CreateStoppedPreAckContextV1<'_> {
    /// Records the sole genuine parent Effect while public state stays pending.
    ///
    /// The existing canonical native append engine owns the exact one-row
    /// transaction. Its whole reached owner remains in this same attempt.
    ///
    /// # Errors
    /// Retains the actual model, financial, encoder or native append refusal.
    #[doc(hidden)]
    pub fn record_controller_pre_ack_once_v1(&mut self, controller: &mut Journal)
        -> Result<CommitResult, ResourceReservationErrorV1> {
        controller.record_create_stopped_pre_ack_once_v1(self).map_err(Into::into)
    }
}
