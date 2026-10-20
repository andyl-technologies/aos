//! Retains the actual first Source lifecycle admission through all owed posts.
//!
//! The accepted model is derived from the same completed intake. A real current
//! Root turn and C23 original select the canonical planner; no caller-supplied
//! lifecycle record or historical publication can mint this crossing.

use super::*;

mod pre_ack;
pub use pre_ack::{CreateStoppedCompletionAttemptV1, CreateStoppedPreAckContextV1,
    CreateStoppedCompletionAssociationV1, CreateStoppedPreAckOriginalV1,
    CreateStoppedPostAckContextV1, CreateStoppedTerminalOriginalV1, CreateStoppedTerminalCustodyV1};

mod workspace_context;
mod semantic;
pub use workspace_context::CreateProvisioningSourceWorkspaceContextV1;
use aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1;
use aos_sandbox_protocol::domain_ledger::effect_history::{PublicMutationEffectHistoryV1,
    effect_decoding_receiving_bytes_v1};
use crate::cold_launch_publication::OriginalPublicationActionV1;
use crate::journal::source_provisioning::SourceProvisioningIdentityV1;
use crate::lifecycle::{LifecycleIntentV1, LifecycleOperationV1,
    LifecycleProtectedJournalOwnerV1, lifecycle_public_mutation_admission_v1,
    lifecycle_operation_from_public_mutation_v1};
use crate::lifecycle::{PreparedSourceLifecycleAdmissionV1,
    SourceLifecycleAdmissionCommitV1};
use crate::normal_root::{RootStorageApplyClientOriginalV1, RootStorageApplyCurrentTurnV1};
use crate::policy_compiler::create_q04::Q04CutIdentityV1;

#[derive(Debug, thiserror::Error)]
pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) enum SourceAdmissionErrorV1 {
    #[error(transparent)]
    Resource(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Reconciler(#[from] crate::ReconcilerError),
    #[error(transparent)]
    Accounting(#[from] aos_sandbox_model::AccountingError),
    #[error(transparent)]
    Journal(#[from] crate::JournalError),
    #[error(transparent)]
    Context(#[from] aos_sandbox_protocol::domain_ledger::effect_history::EffectHistoryDataError),
    #[error(transparent)]
    Admission(#[from] crate::lifecycle::LifecyclePublicMutationAdmissionErrorV1),
    #[error(transparent)]
    Operation(#[from] crate::lifecycle::LifecyclePublicOperationErrorV1),
    #[error(transparent)]
    Lifecycle(#[from] crate::lifecycle::LifecycleProtectedJournalErrorV1),
    #[error(transparent)]
    Commit(#[from] crate::protected_domain_journal::ResidentDomainCommitFailureV1),
    #[error(transparent)]
    Model(#[from] aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError),
    #[error(transparent)]
    Runtime(#[from] crate::runtime_authority::RuntimeAuthorityError),
    #[error(transparent)]
    Publication(#[from] crate::publication::AuthorityPublicationError),
    #[error(transparent)]
    Workspace(#[from] crate::cold_launch_publication::completion::CreateStoppedCompletionMismatchV1),
    #[error(transparent)]
    PublicOperation(#[from] aos_sandbox_protocol::domain_ledger::public_operation::PublicOperationDataError),
    #[error("the original Source lifecycle admission is closed")]
    Closed,
}

#[derive(Clone, Copy)]
enum FirstV1 { Primary, Entry, Native, Models, Funding, Expected, Semantic, Preparation, Binding, Commit, After, Disposal, Reentry }

/// Selects only the next real canonical Create Source transition.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(crate) enum SourcePurposeV1 {
    #[default]
    Admission,
    BindPlan,
    InitialProgress,
    SemanticReadiness,
    SemanticCommit,
    Completing,
}

impl SourcePurposeV1 {
    fn progress_index_v1(self) -> Option<usize> {
        match self {
            Self::Admission => None,
            Self::BindPlan => Some(0),
            Self::InitialProgress => Some(1),
            Self::SemanticReadiness => Some(2),
            Self::SemanticCommit => Some(3),
            Self::Completing => Some(4),
        }
    }

    pub(crate) fn destination_phase_v1(self) -> crate::lifecycle::LifecyclePhaseV1 {
        use crate::lifecycle::LifecyclePhaseV1 as Phase;
        match self {
            Self::Admission | Self::BindPlan => Phase::Accepted,
            Self::InitialProgress => Phase::Prepared,
            Self::SemanticReadiness => Phase::ReadyToCommit,
            Self::SemanticCommit => Phase::Committed,
            Self::Completing => Phase::Completing,
        }
    }
}

#[derive(Default)]
pub(super) struct SourceProvisioningOriginalsV1 {
    admission: SourceTurnOriginalsV1,
    progress: [SourceTurnOriginalsV1; 5],
    reentry: Option<SourceAdmissionErrorV1>,
}

impl SourceProvisioningOriginalsV1 {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.admission.failure()
            .or_else(|| self.progress.iter().find_map(SourceTurnOriginalsV1::failure))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    pub(super) fn active(&self) -> bool {
        self.admission.active() || self.progress.iter().any(SourceTurnOriginalsV1::active)
    }

    fn turn_v1(&self, purpose: SourcePurposeV1) -> &SourceTurnOriginalsV1 {
        match purpose.progress_index_v1() {
            Some(index) => &self.progress[index],
            None => &self.admission,
        }
    }

    fn turn_mut_v1(&mut self, purpose: SourcePurposeV1) -> &mut SourceTurnOriginalsV1 {
        match purpose.progress_index_v1() {
            Some(index) => &mut self.progress[index],
            None => &mut self.admission,
        }
    }

    fn next_progress_v1(&mut self) -> Result<SourcePurposeV1, ResourceReservationErrorV1> {
        if self.failure().is_some() || !matches!(self.admission.disposal, Some(Ok(()))) {
            self.reentry.get_or_insert(SourceAdmissionErrorV1::Closed);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        for (index, purpose) in [SourcePurposeV1::BindPlan, SourcePurposeV1::InitialProgress,
            SourcePurposeV1::SemanticReadiness, SourcePurposeV1::SemanticCommit,
            SourcePurposeV1::Completing].into_iter().enumerate() {
            let turn = &self.progress[index];
            if !turn.entered {
                return Ok(purpose);
            }
            if !matches!(turn.disposal, Some(Ok(()))) {
                self.reentry.get_or_insert(SourceAdmissionErrorV1::Closed);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        self.reentry.get_or_insert(SourceAdmissionErrorV1::Closed);
        Err(ResourceReservationErrorV1::Conflict)
    }

    fn selected_original_failure_v1(&self) -> bool {
        std::iter::once(&self.admission).chain(self.progress.iter())
            .find(|turn| turn.failure().is_some())
            .is_some_and(|turn| turn.original_funding_selected)
    }
}

#[derive(Default)]
pub(super) struct SourceTurnOriginalsV1 {
    purpose: SourcePurposeV1,
    predecessor: Option<crate::lifecycle::LifecycleRecordDigestV1>,
    public_body: Option<crate::lifecycle::LifecycleStepBodyDigestV1>,
    entered: bool,
    native_turn: u64,
    identity: Option<SourceProvisioningIdentityV1>,
    primary: Option<Result<(), ResourceReservationErrorV1>>,
    entry: Option<Result<(), SourceAdmissionErrorV1>>,
    original_funding_selected: bool,
    base: Option<ResourceVector>,
    models: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    native: Option<Result<SourceProvisioningCurrentnessOriginalV1, ResourceReservationErrorV1>>,
    expected: Option<Result<LifecycleOperationV1, SourceAdmissionErrorV1>>,
    semantic: Option<Result<crate::lifecycle::LifecycleMethodSemanticCommitV1, SourceAdmissionErrorV1>>,
    prepared: Option<Result<PreparedSourceLifecycleAdmissionV1, SourceAdmissionErrorV1>>,
    binding: Option<Result<(), ResourceReservationErrorV1>>,
    committed: Option<Result<SourceLifecycleAdmissionCommitV1, SourceAdmissionErrorV1>>,
    after: Option<Result<(), crate::JournalError>>,
    disposal: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<FirstV1>,
    reentry: Option<SourceAdmissionErrorV1>,
}

impl SourceTurnOriginalsV1 {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let first = match self.first {
            Some(FirstV1::Primary) => cause(&self.primary),
            Some(FirstV1::Entry) => cause(&self.entry),
            Some(FirstV1::Native) => self.native.as_ref().and_then(|value| match value {
                Ok(value) => value.failure(), Err(cause) => Some(cause as _),
            }),
            Some(FirstV1::Models) => cause(&self.models),
            Some(FirstV1::Funding) => cause(&self.funding),
            Some(FirstV1::Expected) => cause(&self.expected),
            Some(FirstV1::Semantic) => cause(&self.semantic),
            Some(FirstV1::Preparation) => cause(&self.prepared),
            Some(FirstV1::Binding) => cause(&self.binding),
            Some(FirstV1::Commit) => cause(&self.committed),
            Some(FirstV1::After) => cause(&self.after),
            Some(FirstV1::Disposal) => cause(&self.disposal),
            Some(FirstV1::Reentry) => self.reentry.as_ref().map(|cause| cause as _),
            None => None,
        };
        first.or_else(|| self.native.as_ref().and_then(|value| value.as_ref().ok())
            .and_then(SourceProvisioningCurrentnessOriginalV1::failure))
            .or_else(|| cause(&self.after)).or_else(|| cause(&self.disposal))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    pub(super) fn active(&self) -> bool {
        self.entered && !matches!(self.disposal, Some(Ok(())))
    }

    fn fixed_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
    }
}

/// Borrows the genuine current Source admission, never caller-built records.
pub(crate) struct SourceAdmissionAuthorizationV1<'turn> {
    state: &'turn SourceTurnOriginalsV1,
    original: &'turn CreateProvisioningOriginalsV1,
    controller: &'turn Journal,
    action: &'turn OriginalPublicationActionV1,
    root: Option<&'turn RootStorageApplyCurrentTurnV1<'turn>>,
    completion: Option<&'turn pre_ack::SourceCompletionAuthorizationV1<'turn>>,
    q04: &'turn Q04CutIdentityV1,
}

impl SourceAdmissionAuthorizationV1<'_> {
    pub(crate) fn require_current_v1(&self) -> Result<(), crate::JournalError> {
        match (self.root, self.completion) {
            (Some(root), None) => root.require_action_v1(self.action, self.original, self.controller),
            (None, Some(completion)) => completion.require_current_v1(self.original, self.controller),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }.map_err(|_| crate::JournalError::ProtectedBoundary)?;
        if !self.state.entered || self.state.after.is_some()
            || self.state.identity.is_none() || !matches!(self.state.expected, Some(Ok(_)))
            || self.state.native_turn != self.original.native_turn
            || self.state.failure().is_some()
            || !self.state.native.as_ref().is_some_and(|value|
                value.as_ref().is_ok_and(|original| original.failure().is_none()))
            || self.q04.operation() != self.original.parent {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        let expected = self.expected_operation_v1();
        if expected.operation_id() != self.original.parent || expected.project() != self.q04.project()
            || !matches!(expected.intent(), LifecycleIntentV1::Create { sandbox }
                if *sandbox == self.q04.sandbox()) {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn expected_operation_v1(&self) -> &LifecycleOperationV1 {
        // The private constructor below checks this resident whole Result.
        match self.state.expected.as_ref().and_then(|value| value.as_ref().ok()) {
            Some(value) => value,
            None => std::process::abort(),
        }
    }

    pub(crate) fn expected_key_v1(&self)
        -> Result<crate::lifecycle::LifecycleProtectedJournalKeyV1, crate::JournalError> {
        crate::lifecycle::lifecycle_protected_key_v1(
            crate::lifecycle::provisioning_operation_record_kind_v1(if self.completion.is_some() {
                crate::lifecycle::LifecyclePhaseV1::Terminal
            } else { self.state.purpose.destination_phase_v1() }),
            self.q04.project(), aos_sandbox_model::ResourceId::from_bytes(self.q04.sandbox().into_bytes()),
            self.q04.operation(),
        ).map_err(|_| crate::JournalError::ProtectedBoundary)
    }

    pub(crate) fn purpose_v1(&self) -> SourcePurposeV1 { self.state.purpose }

    pub(crate) fn transaction_id_v1(&self) -> Result<[u8; 16], crate::JournalError> {
        use crate::lifecycle::{lifecycle_plan_binding_transaction_id_v1,
            lifecycle_initial_reservation_transaction_id_v1, lifecycle_progress_transaction_id_v1};
        if self.completion.is_some() {
            return Ok(lifecycle_progress_transaction_id_v1(self.parent_operation_v1(),
                self.state.predecessor.ok_or(crate::JournalError::ProtectedBoundary)?.digest(), b"observed-effect-progress"));
        }
        if self.state.purpose == SourcePurposeV1::Admission {
            return Ok(self.parent_operation_v1().into_bytes());
        }
        let record = self.state.predecessor.ok_or(crate::JournalError::ProtectedBoundary)?.digest();
        Ok(match self.state.purpose {
            SourcePurposeV1::Admission => return Err(crate::JournalError::ProtectedBoundary),
            SourcePurposeV1::BindPlan => lifecycle_plan_binding_transaction_id_v1(
                self.parent_operation_v1(), record),
            SourcePurposeV1::InitialProgress => lifecycle_initial_reservation_transaction_id_v1(
                self.parent_operation_v1(), record),
            SourcePurposeV1::SemanticReadiness => lifecycle_progress_transaction_id_v1(
                self.parent_operation_v1(), record, b"semantic-readiness"),
            SourcePurposeV1::SemanticCommit => lifecycle_progress_transaction_id_v1(
                self.parent_operation_v1(), record, b"semantic-commit"),
            SourcePurposeV1::Completing => lifecycle_progress_transaction_id_v1(
                self.parent_operation_v1(), record, b"postcommit-progress"),
        })
    }

    pub(crate) fn semantic_commit_v1(&self)
        -> Result<crate::lifecycle::LifecycleMethodSemanticCommitV1, crate::JournalError> {
        self.state.semantic.as_ref().and_then(|value| value.as_ref().ok()).cloned()
            .ok_or(crate::JournalError::ProtectedBoundary)
    }

    pub(crate) fn bound_step_v1(&self) -> Result<crate::lifecycle::LifecycleStepV1, crate::JournalError> {
        let [step] = self.expected_operation_v1().steps() else {
            return Err(crate::JournalError::ProtectedBoundary);
        };
        let context = self.action.contract_v1().records_v1().fields_v1();
        // The immutable Action constructor has already joined this template to
        // the actual same Root admission; the live token repeats its native gate.
        let mut templates = self.action.contract_v1().draft_v1().templates().iter().filter(|template|
            template.method() == aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_APPLY);
        let template = templates.next().ok_or(crate::JournalError::ProtectedBoundary)?;
        if templates.next().is_some() || context.parent != self.parent_operation_v1() {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        if step.index() != 0
            || step.class() != crate::lifecycle::LifecycleStepClassV1::PostCommitForward
            || step.domain() != crate::lifecycle::LifecycleStepDomainV1::Controller
            || !self.expected_operation_v1().plan_is_unbound() {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        let forward = crate::lifecycle::LifecyclePhase6EffectPlanV1::new(
            crate::lifecycle::LifecycleEffectDomainV1::Controller, 1, context.sandbox.into_bytes(),
            context.public_request, context.root_plan,
        ).map_err(|_| crate::JournalError::ProtectedBoundary)?;
        crate::lifecycle::lifecycle_phase6_bind_controller_anchor_v1(
            self.parent_operation_v1(), step, forward,
        ).map_err(|_| crate::JournalError::ProtectedBoundary)
    }

    pub(crate) fn actual_started_at_v1(&self) -> Result<crate::lifecycle::LifecycleTimeV1, crate::JournalError> {
        let clock = match (self.root, self.completion) {
            (Some(root), None) => root.actual_before_clock_v1(self.action, self.original, self.controller),
            (None, Some(completion)) => Ok(completion.before_v1()),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }.map_err(|_| crate::JournalError::ProtectedBoundary)?;
        let nanos = u64::try_from(clock.wall_seconds()).ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or(crate::JournalError::ProtectedBoundary)?;
        crate::lifecycle::LifecycleTimeV1::new(nanos).map_err(|_| crate::JournalError::ProtectedBoundary)
    }

    pub(crate) fn source_identity_v1(&self) -> &SourceProvisioningIdentityV1 {
        match self.state.identity.as_ref() { Some(value) => value, None => std::process::abort() }
    }

    pub(crate) fn resource_fields_v1(&self) -> aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceFieldsV1 {
        self.action.contract_v1().records_v1().fields_v1()
    }

    pub(crate) fn completion_readback_v1(&self) -> Result<(aos_sandbox_model::ObjectDigest, aos_sandbox_model::ObjectDigest), crate::JournalError> {
        self.require_current_v1()?;
        let completion = self.completion.ok_or(crate::JournalError::ProtectedBoundary)?;
        Ok((completion.acknowledgement_v1().map_err(|_| crate::JournalError::ProtectedBoundary)?, completion.inventory_v1()))
    }

    pub(crate) fn q04_v1(&self) -> &Q04CutIdentityV1 { self.q04 }
    pub(crate) fn parent_operation_v1(&self) -> aos_sandbox_model::OperationId { self.original.parent }
}

impl OriginalCreateProvisioningRootLoanV1<'_, '_> {
    /// Admits the actual accepted Create into the same retained Source writer.
    ///
    /// This enters only the canonical first lifecycle Intent. Internal Apply,
    /// workspace observations, STOPPED projection and public terminal remain
    /// separate stages. Every entered Source attempt runs its prepaid after.
    ///
    /// # Errors
    /// Retains the exact entry, native, model, planning, append or post cause.
    /// The caller must still finish C23 and the independent Root after.
    #[doc(hidden)]
    pub fn admit_original_create_lifecycle_source_once_v1(&mut self,
        action: &OriginalPublicationActionV1, root: &RootStorageApplyCurrentTurnV1<'_>,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.run_source_turn_once_v1(SourcePurposeV1::Admission, action, root, controller, source, None)
    }

    /// Advances one exact canonical Source stage before semantic commit.
    ///
    /// Each stage requires the preceding native/Root/C23 disposition. This
    /// method binds the real Controller anchor, prepares it, then reaches
    /// ReadyToCommit without minting workspace or terminal evidence.
    ///
    /// # Errors
    /// Retains the actual stage/model/planner/append/post refusal. Every entered
    /// Source stage still owes its independent prearmed Source after.
    #[doc(hidden)]
    pub fn advance_original_create_lifecycle_source_once_v1(&mut self,
        action: &OriginalPublicationActionV1, root: &RootStorageApplyCurrentTurnV1<'_>,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let purpose = self.receiving.source.next_progress_v1()?;
        if matches!(purpose, SourcePurposeV1::SemanticCommit | SourcePurposeV1::Completing) {
            self.receiving.source.reentry.get_or_insert(SourceAdmissionErrorV1::Closed);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.run_source_turn_once_v1(purpose, action, root, controller, source, None)
    }

    /// Commits the actual workspace facts, then reserves the real Completing step.
    ///
    /// Each call performs only the next existing canonical transition. Signed
    /// Apply and fresh Inventory models must rejoin their actual native owner;
    /// a parsed response or an activated publication alone cannot enter it.
    ///
    /// # Errors
    /// Retains actual native, model, semantic CAS, Source append or owed-post
    /// failures. The same C23 and independent Root posts remain mandatory.
    #[doc(hidden)]
    pub fn advance_original_create_workspace_source_once_v1(&mut self,
        action: &OriginalPublicationActionV1, root: &RootStorageApplyCurrentTurnV1<'_>,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        workspace: &crate::StorageProvisioningWorkspaceOriginalV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        let purpose = self.receiving.source.next_progress_v1()?;
        if !matches!(purpose, SourcePurposeV1::SemanticCommit | SourcePurposeV1::Completing) {
            self.receiving.source.reentry.get_or_insert(SourceAdmissionErrorV1::Closed);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.run_source_turn_once_v1(purpose, action, root, controller, source, Some(workspace))
    }

    fn run_source_turn_once_v1(&mut self, purpose: SourcePurposeV1,
        action: &OriginalPublicationActionV1, root: &RootStorageApplyCurrentTurnV1<'_>,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        workspace: Option<&crate::StorageProvisioningWorkspaceOriginalV1<'_>>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.receiving.source.turn_v1(purpose).entered {
            self.receiving.source.reentry.get_or_insert(SourceAdmissionErrorV1::Closed);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut state = std::mem::take(self.receiving.source.turn_mut_v1(purpose));
        state.purpose = purpose;
        state.entered = true;
        state.native_turn = self.receiving.native_turn;
        let mut debit_invoked = false;
        state.primary = Some((|| {
            state.entry = Some((|| {
                root.require_action_v1(action, self.receiving, controller)?;
                self.completed.require_current_v1()?;
                let context = self.completed.accepted_context_v1()?;
                let model_bytes = effect_decoding_receiving_bytes_v1(context.len())
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                let mut complete = action.resident_receiving_demand_v1(controller)?
                    .checked_add(root.receiving_demand_v1()?)?
                    .checked_add(SourceTurnOriginalsV1::fixed_demand_v1()?)?
                    .checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, model_bytes))?;
                if matches!(purpose, SourcePurposeV1::SemanticCommit | SourcePurposeV1::Completing) {
                    let state = controller.historical_read_view_v1().materialized_state_v1();
                    complete = complete.checked_add(crate::cold_launch_publication::completion::
                        create_stopped_controller_receiving_demand_v1(state)
                        .ok_or(ResourceReservationErrorV1::Conflict)?)?
                        .checked_add(crate::cold_launch_publication::completion::
                            create_workspace_comparison_receiving_demand_v1()
                            .ok_or(ResourceReservationErrorV1::Conflict)?)?;
                }
                state.base = Some(complete);
                debit_invoked = true;
                self.receiving.require_complete_v1(controller, complete)?;
                let native = self.receiving.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?
                    .original_mut_v1();
                state.native = Some(self.receiving.bank.lock()
                    .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .begin_provisioning_source_native_v1(native, controller, source.journal(),
                        self.receiving.profile.as_ref(), complete));
                Ok(())
            })());
            if state.entry.as_ref().is_some_and(Result::is_err) {
                state.first = Some(FirstV1::Entry);
                state.original_funding_selected = debit_invoked && self.receiving.failure().is_some();
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if !state.native.as_ref().is_some_and(|value|
                value.as_ref().is_ok_and(|original| original.failure().is_none())) {
                state.first = Some(FirstV1::Native);
                state.original_funding_selected = self.receiving.failure().is_some();
                return Err(ResourceReservationErrorV1::Conflict);
            }

            // The actual held-Source metadata forecast is inside its already
            // armed native pair. Model growth still follows the full C debit.
            state.models = Some((|| {
                let source_models = if purpose == SourcePurposeV1::Admission {
                    crate::lifecycle::create_provisioning_admission_receiving_demand_v1(source.journal_ref_v1())?
                } else if matches!(purpose, SourcePurposeV1::SemanticCommit | SourcePurposeV1::Completing) {
                    crate::lifecycle::create_provisioning_committed_source_receiving_demand_v1(source.journal_ref_v1())?
                } else {
                    crate::lifecycle::create_provisioning_uncommitted_source_receiving_demand_v1(source.journal_ref_v1())?
                };
                state.base.ok_or(ResourceReservationErrorV1::Conflict)?
                    .checked_add(SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?)?
                    .checked_add(source_models).map_err(Into::into)
            })());
            let complete = match state.models.as_ref().and_then(|value| value.as_ref().ok()) {
                Some(complete) => *complete,
                None => {
                    state.first = Some(FirstV1::Models);
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            };
            state.funding = Some(self.receiving.require_complete_v1(controller, complete));
            if state.funding.as_ref().is_some_and(Result::is_err) {
                state.first = Some(FirstV1::Funding);
                state.original_funding_selected = self.receiving.failure().is_some();
                return Err(ResourceReservationErrorV1::Conflict);
            }

            state.expected = Some((|| {
                state.identity = Some(source.journal_ref_v1().source_provisioning_identity_v1()?);
                let context = PublicMutationEffectHistoryV1::decode(self.completed.accepted_context_v1()?)
                    .map_err(SourceAdmissionErrorV1::Context)?
                    .ok_or(SourceAdmissionErrorV1::Closed)?;
                state.public_body = Some(crate::lifecycle::LifecycleStepBodyDigestV1::
                    commit(context.canonical_request()));
                let request = context.validated_request()
                    .map_err(SourceAdmissionErrorV1::Context)?;
                if !matches!(request, aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Create(_)) {
                    return Err(SourceAdmissionErrorV1::Closed);
                }
                let admission = lifecycle_public_mutation_admission_v1(controller, self.receiving.parent,
                    context.project(), self.original_node_v1()?, &request)
                    .map_err(SourceAdmissionErrorV1::Admission)?;
                lifecycle_operation_from_public_mutation_v1(self.receiving.parent,
                    context.caller(), context.project(), context.accepted_wall_seconds(),
                    context.canonical_request(), &request, admission)
                    .map_err(SourceAdmissionErrorV1::Operation)
            })());
            if state.expected.as_ref().is_some_and(Result::is_err) {
                state.first = Some(FirstV1::Expected);
                return Err(ResourceReservationErrorV1::Conflict);
            }

            if purpose != SourcePurposeV1::Admission {
                let selected = (|| {
                    let expected = state.expected.as_ref().and_then(|value| value.as_ref().ok())
                        .ok_or(SourceAdmissionErrorV1::Closed)?;
                    let owner = LifecycleProtectedJournalOwnerV1::claim(source)?;
                    let (_, current) = owner.current_operation_by_id(self.receiving.parent)?
                        .ok_or(SourceAdmissionErrorV1::Closed)?;
                    crate::lifecycle::require_same_lifecycle_admission_v1(
                        expected, current.operation())?;
                    state.predecessor = Some(current.record());
                    Ok(current.operation().clone())
                })();
                state.expected = Some(selected);
                if state.expected.as_ref().is_some_and(Result::is_err) {
                    state.first = Some(FirstV1::Expected);
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
            if matches!(purpose, SourcePurposeV1::SemanticCommit | SourcePurposeV1::Completing) {
                state.semantic = Some(self.prepare_workspace_semantic_commit_v1(
                    purpose, &mut state, action, root, controller, workspace));
                if state.semantic.as_ref().is_some_and(Result::is_err) {
                    state.first = Some(FirstV1::Semantic);
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
            let q04 = self.completed.source_q04_identity_v1()?;
            {
                let authorization = SourceAdmissionAuthorizationV1 { state: &state,
                    original: self.receiving, controller, action, root: Some(root), completion: None, q04 };
                state.prepared = Some(LifecycleProtectedJournalOwnerV1::claim(source)
                    .and_then(|owner| owner.prepare_original_create_source_turn_v1(&authorization))
                    .map_err(SourceAdmissionErrorV1::Lifecycle));
            }
            if state.prepared.as_ref().is_some_and(Result::is_err) {
                state.first = Some(FirstV1::Preparation);
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let prepared = state.prepared.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            if let Some(transaction) = prepared.transaction_v1() {
                state.binding = Some(self.receiving.bank.lock()
                    .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .bind_provisioning_source_native_v1(
                        state.native.as_mut().and_then(|value| value.as_mut().ok())
                            .ok_or(ResourceReservationErrorV1::Conflict)?,
                        self.receiving.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?.original_v1(),
                        controller, source.journal(), self.receiving.profile.as_ref(), transaction));
                if state.binding.as_ref().is_some_and(Result::is_err) {
                    state.first = Some(FirstV1::Binding);
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
            let authorization = SourceAdmissionAuthorizationV1 { state: &state,
                original: self.receiving, controller, action, root: Some(root), completion: None, q04 };
            let committed = LifecycleProtectedJournalOwnerV1::claim(source)
                .map_err(SourceAdmissionErrorV1::Lifecycle)
                .and_then(|mut owner| owner.commit_original_create_source_admission_v1(
                    prepared, &authorization).map_err(SourceAdmissionErrorV1::Commit));
            state.committed = Some(committed);
            if state.committed.as_ref().is_some_and(Result::is_err) {
                state.first = Some(FirstV1::Commit);
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        if state.primary.as_ref().is_some_and(Result::is_err) {
            state.first.get_or_insert(FirstV1::Primary);
        }
        // No early body return can suppress this already armed Source post.
        if let Some(Ok(original)) = state.native.as_mut() {
            state.after = Some(source.journal_ref_v1().finish_source_provisioning_native_v1(original));
            if state.after.as_ref().is_some_and(Result::is_err) {
                state.first.get_or_insert(FirstV1::After);
            }
        }
        let positive = state.first.is_none() && matches!(state.committed, Some(Ok(_)))
            && matches!(state.after, Some(Ok(())));
        *self.receiving.source.turn_mut_v1(purpose) = state;
        if positive { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }
}

impl CreateProvisioningOriginalsV1 {
    /// Disposes Source scratch only after the same actual C23 and Root posts.
    ///
    /// # Errors
    /// Refuses a failed body, another Action/ordinal, missing Root-after, changed
    /// Source or repeated disposition. Failure retains all original custody.
    #[doc(hidden)]
    pub fn finish_original_create_lifecycle_source_after_posts_once_v1(&mut self,
        action: &OriginalPublicationActionV1, root: &RootStorageApplyClientOriginalV1,
        controller: &Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.finish_source_turn_after_posts_once_v1(SourcePurposeV1::Admission,
            action, root, controller, source)
    }

    /// Disposes only the actual entered progress stage after its own posts.
    ///
    /// # Errors
    /// Refuses missing, failed, substituted or already disposed actual stages.
    #[doc(hidden)]
    pub fn finish_original_create_lifecycle_progress_after_posts_once_v1(&mut self,
        action: &OriginalPublicationActionV1, root: &RootStorageApplyClientOriginalV1,
        controller: &Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let purpose = [SourcePurposeV1::BindPlan, SourcePurposeV1::InitialProgress,
            SourcePurposeV1::SemanticReadiness, SourcePurposeV1::SemanticCommit,
            SourcePurposeV1::Completing].into_iter().find(|purpose| {
                let turn = self.source.turn_v1(*purpose);
                turn.entered && turn.disposal.is_none()
            }).ok_or(ResourceReservationErrorV1::Conflict)?;
        self.finish_source_turn_after_posts_once_v1(purpose, action, root, controller, source)
    }

    fn finish_source_turn_after_posts_once_v1(&mut self, purpose: SourcePurposeV1,
        action: &OriginalPublicationActionV1, root: &RootStorageApplyClientOriginalV1,
        controller: &Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let mut state = std::mem::take(self.source.turn_mut_v1(purpose));
        if state.disposal.is_some() {
            state.reentry.get_or_insert(SourceAdmissionErrorV1::Closed);
            state.first.get_or_insert(FirstV1::Reentry);
            *self.source.turn_mut_v1(purpose) = state;
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let result = (|| {
            if state.failure().is_some() || state.native_turn != self.native_turn
                || !matches!(state.committed, Some(Ok(_)))
                || !matches!(state.after, Some(Ok(()))) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            root.require_completed_publication_turn_v1(action, self, controller)?;
            self.require_completed_original_v1(controller)?;
            self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .dispose_provisioning_source_native_v1(
                    state.native.as_mut().and_then(|value| value.as_mut().ok())
                        .ok_or(ResourceReservationErrorV1::Conflict)?,
                    self.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?.original_v1(),
                    controller, source.journal(), self.profile.as_ref())
        })();
        state.disposal = Some(result);
        let returned = if matches!(state.disposal, Some(Ok(()))) {
            // Only complete pure planning scratch is retired. The actual
            // Applied result, native Source original, ordinal and once-only
            // markers stay resident; this is no retry or financial refund.
            if let Some(Ok(committed)) = state.committed.as_mut() {
                committed.retire_completed_payloads_v1();
            }
            state.expected.take();
            state.prepared.take();
            state.semantic.take();
            Ok(())
        } else {
            state.first.get_or_insert(FirstV1::Disposal);
            Err(ResourceReservationErrorV1::Conflict)
        };
        *self.source.turn_mut_v1(purpose) = state;
        returned
    }

    /// Borrows the selected Source cause before its later independently owed posts.
    #[must_use]
    #[doc(hidden)]
    pub fn create_lifecycle_source_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if self.source.selected_original_failure_v1() { self.failure().or_else(|| self.source.failure()) }
        else { self.source.failure().or_else(|| self.failure()) }
    }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_source_model_error_precedes_later_owed_post_and_reentry() {
        let mut state = SourceTurnOriginalsV1::default();
        state.entered = true;
        state.expected = Some(Err(SourceAdmissionErrorV1::Context(
            aos_sandbox_protocol::domain_ledger::effect_history::EffectHistoryDataError::InvalidPlan("source fixture"),
        )));
        state.first = Some(FirstV1::Expected);
        state.after = Some(Err(crate::JournalError::ProtectedBoundary));
        state.reentry = Some(SourceAdmissionErrorV1::Closed);

        let expected = state.expected.as_ref().unwrap()
            .as_ref().err().unwrap();

        // Concrete identity excludes duplicated trait-object vtable metadata.
        let actual = state.failure().unwrap().downcast_ref::<SourceAdmissionErrorV1>()
            .expect("the first retained model error keeps its concrete type");

        assert!(std::ptr::eq(actual, expected));
        assert!(matches!(actual, SourceAdmissionErrorV1::Context(
            aos_sandbox_protocol::domain_ledger::effect_history::EffectHistoryDataError::InvalidPlan("source fixture"),
        )));
        assert!(!std::ptr::eq(actual, state.reentry.as_ref().unwrap()));
        assert!(state.active());
    }

    #[test]
    fn failed_source_admission_cannot_look_disposed_after_other_posts() {
        let mut state = SourceTurnOriginalsV1::default();
        state.entered = true;
        state.entry = Some(Err(SourceAdmissionErrorV1::Closed));
        state.first = Some(FirstV1::Entry);
        state.after = Some(Ok(()));

        assert!(state.failure().is_some());
        assert!(state.active());
        assert!(state.disposal.is_none());
    }

    #[test]
    fn source_stage_router_preserves_an_earlier_original_over_later_stage_failure() {
        let mut state = SourceProvisioningOriginalsV1::default();
        state.admission.entered = true;
        state.admission.after = Some(Err(crate::JournalError::ProtectedBoundary));
        state.admission.first = Some(FirstV1::After);
        state.progress[0].entered = true;
        state.progress[0].entry = Some(Err(SourceAdmissionErrorV1::Closed));
        state.progress[0].first = Some(FirstV1::Entry);
        let expected = state.admission.failure().unwrap() as *const dyn Error;

        assert!(state.next_progress_v1().is_err());

        assert!(std::ptr::eq(state.failure().unwrap(), expected));
        assert!(state.active());
        assert!(state.progress[1].entry.is_none());
        assert!(state.progress[2].entry.is_none());
    }

    #[test]
    fn source_header_preserves_actual_installed_worker_send_requirement() {
        fn require_send<T: Send>() {}
        require_send::<CreateProvisioningOriginalsV1>();
    }
    #[test]
    fn semantic_witness_refusal_precedes_independently_owed_source_after() {
        let mut state = SourceTurnOriginalsV1::default();
        state.entered = true;
        state.purpose = SourcePurposeV1::SemanticCommit;
        state.semantic = Some(Err(SourceAdmissionErrorV1::Model(
            aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError::InvalidModel,
        )));
        state.first = Some(FirstV1::Semantic);
        state.after = Some(Err(crate::JournalError::ProtectedBoundary));

        let expected = state.semantic.as_ref().unwrap()
            .as_ref().err().unwrap();

        // Concrete identity still refuses a copied error or a later Source post.
        let actual = state.failure().unwrap().downcast_ref::<SourceAdmissionErrorV1>()
            .expect("the first retained semantic error keeps its concrete type");

        assert!(std::ptr::eq(actual, expected));
        assert!(matches!(actual, SourceAdmissionErrorV1::Model(
            aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError::InvalidModel,
        )));
        assert!(state.active());
        assert!(state.disposal.is_none());
    }

}


impl SourceProvisioningOriginalsV1 {
    // Successful scratch retirement leaves the real Applied snapshot on each
    // completed Source stage. Its private adapter allocation is measured by
    // that defining owner, while the native/result headers live inside C23.
    pub(super) fn completed_resident_backing_bytes_v1(&self)
        -> Result<usize, ResourceReservationErrorV1>
    {
        if self.failure().is_some() || self.active() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        std::iter::once(&self.admission).chain(self.progress.iter())
            .try_fold(0_usize, |bytes, turn| {
                if !matches!(turn.disposal, Some(Ok(())))
                    || turn.expected.is_some() || turn.prepared.is_some()
                    || turn.semantic.is_some()
                {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                let committed = turn.committed.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                bytes.checked_add(committed.completed_resident_backing_bytes_v1()
                    .ok_or(ResourceReservationErrorV1::Conflict)?)
                    .ok_or(ResourceReservationErrorV1::Conflict)
            })
    }
}
