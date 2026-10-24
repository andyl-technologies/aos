//! Issues the private Host publication child from the genuine paired Root turn.
//!
//! The public Start keeps its original single effect and accepted origin. This
//! owner retains the distinct internal ownership-gated child, immutable pair,
//! predecessor revision and catalog association before any Core mutation. The
//! existing Core admission and activation engines remain the only row writers.

mod catalog_io;
mod construction;
mod activation;
mod effect;

#[doc(hidden)]
pub use catalog_io::{StartHostCatalogIoLoanV2, StartHostCatalogNativeCompletionV2,
    StartHostCatalogCompletionRefusalV2};
pub(crate) use catalog_io::StartHostCatalogPostOriginalV2;

use super::*;
use crate::normal_root::{RootStartResourceConstructionTurnV2,
    RootStartResourcePrepareAdmissionOriginalV2, RootHostLaunchClientOriginalV1};
use crate::publication::{AuthorityPublicationDraftV1, PreparedAuthorityPublicationV1};
use crate::runtime_authority::{RuntimeAuthorityBindingV1, RuntimeAuthorityIntentV1,
    RuntimeAuthorityLimits, RuntimeAuthorityStore};
use aos_sandbox_model::{BrokerAudience, BrokerGrantTarget, BrokerVerb, ObjectDigest};
use aos_sandbox_protocol::authorization_artifact::{BrokerPlanPreparation, SignedBrokerPlan};
use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1;
use sha2::{Digest as _, Sha256};

use super::host_root::OriginalStartHostRootLoanV1;

type Cause = Box<dyn Error + Send + Sync>;

/// Refuses the private child while its actual construction originals remain held.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the original Start Host publication construction is incomplete or refused")]
pub struct StartHostPublicationClosedV2;

/// Shares immutable comparison inputs with the exact canonical Core loan.
///
/// Construction is private to the paired native issuer. No row, plan, budget,
/// namespace projection or catalog DTO can publicly create this contract.
pub(crate) struct StartHostPublicationContractV2 {
    pub(crate) identity: Arc<()>,
    pub(crate) parent: OperationId,
    pub(crate) origin: aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1,
    pub(crate) root_reply: [u8; 32],
    pub(crate) catalog_generation: u64,
    pub(crate) catalog_digest: [u8; 32],
    pub(crate) predecessor: RuntimeAuthorityBindingV1,
    pub(crate) predecessor_head_key: Vec<u8>,
    pub(crate) predecessor_head: Vec<u8>,
    pub(crate) pending_gate: Vec<u8>,
    pub(crate) plan: crate::OperationPlan,
    pub(crate) draft: AuthorityPublicationDraftV1,
    pub(crate) prepared: PreparedAuthorityPublicationV1,
    pub(crate) host: SignedBrokerPlan,
    pub(crate) guardian: SignedBrokerPlan,
}

/// Retains the actual private child's complete admission and activation results.
#[must_use = "retain this exact child through Host and public Start terminal posts"]
pub struct StartHostPublicationActionOriginalV2 {
    pub(crate) contract: Arc<StartHostPublicationContractV2>,
    admission_geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    admission_funding: Option<Result<(), ResourceReservationErrorV1>>,
    admission_native_selected: bool,
    admission_scope: Option<Result<(), ResourceReservationErrorV1>>,
    admission_turn: Option<u64>,
    pub(crate) admission: Option<Result<crate::AcceptOutcome, crate::ReconcilerError>>,
    pub(crate) admission_after: Option<Result<(), ResourceReservationErrorV1>>,
    pub(crate) activation_preparation: Option<Result<Option<crate::publication::AuthorityPublicationActivationV1>,
        crate::AuthorityPublicationError>>,
    activation_original: activation::StartHostActivationOriginalV2,
    effect_original: effect::StartHostEffectOriginalV2,
    pub(crate) activation: Option<Result<crate::OwnershipGateActivationOutcome, crate::ReconcilerError>>,
    pub(crate) activation_after: Option<Result<(), ResourceReservationErrorV1>>,
}

#[derive(Clone, Copy)]
enum First {
    Reentry,
    Funding,
    Clock,
    Current,
    HostSignature,
    GuardianSignature,
    Template,
    Draft,
    Prepared,
    Plan,
    ComparisonGeometry,
    ComparisonFunding,
    Comparison,
    CatalogAssociation,
    Posts,
}

/// Owns construction inside the actual prepaid Host signing interval.
///
/// Only pure models may be dropped on an error; the caller retains the real
/// Root/native turn, signed artifacts and source owner through independent
/// posts. Successful action handoff performs no late allocation or native IO.
pub(super) struct StartHostPublicationConstructionOriginalV2 {
    parent: Option<OperationId>,
    root_reply: Option<[u8; 32]>,
    construction_turn: Option<u64>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    clock: Option<Result<aos_sandbox_model::RawPairedClockSample, ResourceReservationErrorV1>>,
    current: Option<Result<RuntimeAuthorityBindingV1, Cause>>,
    host_signature: Option<Result<SignedBrokerPlan, Cause>>,
    guardian_signature: Option<Result<SignedBrokerPlan, Cause>>,
    template: Option<Result<crate::BrokerDispatchTemplateV1, Cause>>,
    draft: Option<Result<AuthorityPublicationDraftV1, Cause>>,
    prepared: Option<Result<PreparedAuthorityPublicationV1, Cause>>,
    plan: Option<Result<crate::OperationPlan, Cause>>,
    comparison_geometry: Option<Result<ResourceVector, Cause>>,
    comparison_funding: Option<Result<(), ResourceReservationErrorV1>>,
    comparison: Option<Result<(Vec<u8>, Vec<u8>, Vec<u8>), Cause>>,
    catalog_association: Option<Result<(u64, [u8; 32]), crate::StartHostCatalogProjectionClosedV2>>,
    action: Option<StartHostPublicationActionOriginalV2>,
    after: Option<Result<(), ResourceReservationErrorV1>>,
    original_selected: bool,
    first: Option<First>,
}


const CLOSED: StartHostPublicationClosedV2 = StartHostPublicationClosedV2;

impl StartHostPublicationActionOriginalV2 {
    /// Compares the real admitted pending child without native work or parsing.
    ///
    /// The exact canonical gate and predecessor head were constructed/captured
    /// while the genuine paired signing turn was current. Actual admission and
    /// its independently positive post are mandatory before this comparison.
    pub(crate) fn require_pending_catalog_v2(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        if self.activation_preparation.is_some() || self.activation.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_pending_rows_v2(controller)?;
        Ok(())
    }

    /// Compares the original admitted child and unchanged predecessor rows.
    fn require_pending_rows_v2(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        controller.ensure_protected_authority().map_err(ResourceReservationErrorV1::Journal)?;
        let operation = match self.admission.as_ref() {
            Some(Ok(crate::AcceptOutcome::Accepted(operation) | crate::AcceptOutcome::Replay(operation))) => *operation,
            _ => return Err(ResourceReservationErrorV1::Conflict),
        };
        if operation != self.contract.plan.operation_id()
            || !matches!(self.admission_after, Some(Ok(())))
            || controller.get(crate::RecordNamespace::OwnershipGate, operation.as_bytes())
                != Some(self.contract.pending_gate.as_slice())
            || controller.get(crate::RecordNamespace::RuntimeAuthority,
                &self.contract.predecessor_head_key) != Some(self.contract.predecessor_head.as_slice())
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

}

impl StartNativeStateV1 {
    /// Rejoins the sole private child held by this exact native owner.
    pub(crate) fn require_host_scope_contract_v2(&self, controller: &Journal,
        expected: &Arc<StartHostPublicationContractV2>,
        phase: crate::reconciler::start_admission::StartHostCoreScopePhaseV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        use crate::reconciler::start_admission::StartHostCoreScopePhaseV2 as Phase;
        self.require_current_v1(controller)?;
        let action = self.host_publication_action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if !Arc::ptr_eq(expected, &action.contract) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        match phase {
            Phase::Admission if action.admission.is_none() && action.activation.is_none()
                && matches!(action.admission_geometry, Some(Ok(_)))
                && matches!(action.admission_funding, Some(Ok(())))
                && action.admission_turn == Some(self.native_turn) => Ok(()),
            Phase::Catalog => action.require_pending_catalog_v2(controller),
            Phase::Activation => self.require_host_activation_scope_v2(controller, expected),
            Phase::Applying | Phase::Applied => self.require_host_effect_scope_v2(controller, expected, phase),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Transfers the same native state only from an entered genuine Host phase.
    pub(crate) fn take_host_publication_scope_state_v2(&mut self,
        controller: &Journal,
        phase: crate::reconciler::start_admission::StartHostCoreScopePhaseV2,
        root: &crate::normal_root::RootStartResourceCurrentTurnV2<'_>,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(StartNativeStateV1, Arc<()>, Arc<StartHostPublicationContractV2>, ResourceVector),
        ResourceReservationErrorV1> {
        use crate::normal_root::RootHostPublicationTurnKindV2 as RootPhase;
        use crate::reconciler::start_admission::StartHostCoreScopePhaseV2 as Phase;
        if self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let index = phase.stage_v2();
        let stage = &self.resource_entries.host;
        let native = self.native_state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let action = native.host_publication_action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let identity = self.identity.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if stage.active_turn != Some(index) || stage.turn_ordinal[index] != Some(native.native_turn)
            || !matches!(stage.turn_next[index], Some(Ok(())))
            || !matches!(stage.turn_before[index], Some(Ok(())))
            || stage.turn_after[index].is_some() || stage.turn_root_after[index].is_some()
            || !Arc::ptr_eq(identity, &action.contract.identity)
            || self.body.plan_v1()?.operation_id() != action.contract.parent
            || self.body.origin_v1()? != action.contract.origin
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.body.plan_v1()?.require_accepted_start_data_v1(controller)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.source_origin.require_completed_source_affinity_v1(source.journal_ref_v1())?;
        native.require_host_scope_contract_v2(controller, &action.contract, phase)?;
        let resident = match phase {
            Phase::Admission | Phase::Catalog | Phase::Activation => {
                let root_phase = match phase {
                    Phase::Admission => RootPhase::Admission,
                    Phase::Catalog => RootPhase::Catalog,
                    Phase::Activation => RootPhase::Activation,
                    _ => return Err(ResourceReservationErrorV1::Conflict),
                };
                root.require_host_publication_owner_v2(root_phase,
                    action.contract.parent, native.native_turn, native.profile.as_ref())?
            }
            Phase::Applying | Phase::Applied => root.require_host_io_owner_v2(
                action.contract.parent, native.native_turn, native.profile.as_ref())?,
        };
        let contract = Arc::clone(&action.contract);
        let identity = Arc::clone(identity);
        let native = self.native_state.take().ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok((native, identity, contract, resident))
    }
}

/// Reborrows the real catalog6 owner between canonical commits and Session IO.
///
/// Only the actual Entry issuer can create this wrapper after private child
/// admission and the genuine Root Catalog-before. Each append temporarily moves
/// the same native state into its restricted scope, then restores it even when
/// commit or admission refuses. No caller catalog or amount creates this loan.
#[doc(hidden)]
pub struct StartHostCatalogPublicationLoanV2<'catalog> {
    entry: &'catalog mut AcceptedStartEntryOriginalV1,
    intake: &'catalog crate::CreateContinuationIntakeAttemptV1,
    source: &'catalog crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    root: &'catalog crate::normal_root::RootStartResourceCurrentTurnV2<'catalog>,
    prepared: &'catalog super::network_preparation::PreparedStartResourceRequestOriginalV2,
    contract: Arc<StartHostPublicationContractV2>,
    original_selected: std::cell::Cell<bool>,
}

impl StartHostCatalogPublicationLoanV2<'_> {
    /// Rejoins the actual current Start, Source, private pending2 and Root6.
    ///
    /// # Errors
    /// Refuses changed owner, native ordinal, pending gate or active Root stage.
    pub(crate) fn require_current_v2(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        use crate::normal_root::RootHostPublicationTurnKindV2 as Phase;
        let native = self.entry.native_state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let current = native.require_current_v1(controller);
        self.original_selected.set(current.is_err() && native.native_failure_v1().is_some());
        current?;
        let action = native.host_publication_action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if !Arc::ptr_eq(&self.contract, &action.contract)
            || !Arc::ptr_eq(self.entry.scope_identity_v1()?, &self.contract.identity)
            || self.entry.resource_entries.host.active_turn != Some(6)
            || self.entry.resource_entries.host.turn_ordinal[6] != Some(native.native_turn)
            || !matches!(self.entry.resource_entries.host.turn_before[6], Some(Ok(())))
            || self.entry.resource_entries.host.turn_after[6].is_some()
            || self.entry.resource_entries.host.turn_root_after[6].is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.entry.body.plan_v1()?.require_accepted_start_data_v1(controller)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.entry.source_origin.require_completed_source_affinity_v1(self.source.journal_ref_v1())?;
        action.require_pending_catalog_v2(controller)?;
        self.root.require_host_publication_owner_v2(Phase::Catalog,
            self.contract.parent, native.native_turn, native.profile.as_ref())?;
        Ok(())
    }

    /// Enters canonical source preparation once on the actual catalog interval.
    ///
    /// A failed source owner remains resident. Constructing a different wrapper
    /// cannot reset this native-owned once state or acquire another window.
    pub(crate) fn enter_publication_source_once_v2(&mut self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2(controller)?;
        let native = self.entry.native_state.as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if native.resources.host_catalog_source_entered {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        native.resources.host_catalog_source_entered = true;
        Ok(())
    }

    /// Borrows the same genuine Root/Start owner without retaining a mutable alias.
    ///
    /// # Errors
    /// Refuses changed pending2, current native/Source/Root association or intake.
    #[doc(hidden)]
    pub fn borrow_host_root_v2<'short>(&'short mut self, controller: &Journal)
        -> Result<OriginalStartHostRootLoanV1<'short, '_>, ResourceReservationErrorV1> {
        self.require_current_v2(controller)?;
        self.entry.borrow_host_root_v1(self.intake, controller, self.source)
    }

    /// Compares the same retained paired owner without adopting another catalog.
    pub(crate) fn require_prepared_v2(&self, controller: &Journal,
        prepared: &super::network_preparation::PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2(controller)?;
        if !std::ptr::eq(self.prepared, prepared) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Selects only an actual native refusal at the current source/body boundary.
    #[must_use]
    pub(crate) fn original_failure_selected_v2(&self) -> bool {
        self.original_selected.get()
    }

    /// Records the genuine source's admitted survivor demand before its growth.
    ///
    /// The canonical owner supplies its own source-priced bound. This passive
    /// handoff creates no debit, traffic credit, FD or namespace entry.
    pub(crate) fn retain_source_resident_v2(&mut self,
        controller: &Journal,
        original: &crate::host_catalog_reconciliation::start_publication::StartHostCatalogPublicationOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2(controller)?;
        let demand = {
            let current = self.borrow_host_root_v2(controller)?;
            original.require_admitted_receiving_owner_v2(&current, controller)?
        };
        let native = self.entry.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        if native.resources.host_catalog_publication_resident != ResourceVector::ZERO {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        native.resources.host_catalog_publication_resident = demand;
        Ok(())
    }

    /// Runs the selected canonical write through the same native append engine.
    pub(crate) fn commit_catalog_recipe_v2(&mut self,
        controller: &mut Journal,
        transaction: &crate::JournalTransaction,
        recipe: &crate::host_catalog_reconciliation::publication_recipe::HostCatalogCommitRecipeV2<'_>,
    ) -> Result<crate::CommitResult, crate::JournalError> {
        use crate::reconciler::start_admission::{StartAdmissionScopeV1, StartHostCoreScopePhaseV2 as Phase};
        self.require_current_v2(controller).map_err(|_| crate::JournalError::ProtectedBoundary)?;
        if recipe.catalog_generation_v2() != self.contract.catalog_generation
            || recipe.catalog_digest_v2() != self.contract.catalog_digest
        {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        // The canonical transaction and source owner remain live while this
        // temporary Box holds the same native state and its distinct append.
        let receiving = StartAdmissionScopeV1::host_scope_receiving_demand_v2()?;
        {
            let mut original = self.borrow_host_root_v2(controller)
                .map_err(|_| crate::JournalError::ProtectedBoundary)?;
            let returned = original.require_complete_v1(controller,
                receiving);
            let selected = returned.is_err() && original.failure_v1().is_some();
            drop(original);
            self.original_selected.set(selected);
            returned.map_err(|_| crate::JournalError::ProtectedBoundary)?;
        }
        let scope = StartAdmissionScopeV1::from_host_entry_v2(self.entry, controller,
            Phase::Catalog, self.root, self.source).map_err(|_| crate::JournalError::ProtectedBoundary)?;
        match controller.install_start_admission_scope_v1(Box::new(scope)) {
            Ok(()) => {}
            Err(scope) => {
                self.entry.restore_native_state_v1(scope.into_native_v1());
                return Err(crate::JournalError::ProtectedBoundary);
            }
        }
        let returned = controller.commit_start_host_catalog_recipe_v2(transaction, recipe);
        let Some(scope) = controller.take_start_admission_scope_v1() else {
            std::process::abort();
        };
        self.entry.restore_native_state_v1(scope.into_native_v1());
        self.original_selected.set(returned.is_err() && self.entry.native_state.as_ref()
            .and_then(StartNativeStateV1::native_failure_v1).is_some());
        returned
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Lends catalog publication only from the real private pending child.
    ///
    /// # Errors
    /// Refuses incomplete paired construction/admission, another prepared owner,
    /// actual Root phase or source/native association. Source, opening and IO
    /// keep their own native-owned once state across these short reborrows.
    #[doc(hidden)]
    pub fn borrow_host_catalog_publication_once_v2<'catalog>(
        &'catalog mut self,
        intake: &'catalog crate::CreateContinuationIntakeAttemptV1,
        source: &'catalog crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        root: &'catalog crate::normal_root::RootStartResourceCurrentTurnV2<'catalog>,
        prepared: &'catalog super::network_preparation::PreparedStartResourceRequestOriginalV2,
        controller: &Journal,
    ) -> Result<StartHostCatalogPublicationLoanV2<'catalog>, ResourceReservationErrorV1> {
        use crate::normal_root::RootHostPublicationTurnKindV2 as Phase;
        {
            let original = self.borrow_host_root_v1(intake, controller, source)?;
            original.require_host_stage_v2(6, controller)?;
            prepared.host_catalog_projection_v2(&original, controller)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            root.require_host_publication_owner_v2(Phase::Catalog, original.parent_operation_v1(),
                original.native_turn_v1(), original.native.profile.as_ref())?;
        }
        let native = self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let action = native.host_publication_action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        action.require_pending_catalog_v2(controller)?;
        let (parent, reply, _, _) = prepared.completed_root_binding_v2()?;
        if action.contract.parent != parent || action.contract.root_reply != reply {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let contract = Arc::clone(&action.contract);
        native.resources.host_catalog_loan_entered = true;
        Ok(StartHostCatalogPublicationLoanV2 {
            entry: self,
            intake,
            source,
            root,
            prepared,
            contract,
            original_selected: std::cell::Cell::new(false),
        })
    }
}


impl AcceptedStartEntryOriginalV1 {
    /// Admits only the paired private child through the sole Core Journal kernel.
    ///
    /// Public Start stays unchanged. The actual Runtime must run the shared
    /// Host turn finisher after this result, including a refused body. No
    /// effect, activation or installed catalog follows from admission alone.
    ///
    /// # Errors
    /// Retains geometry, native funding, scope/current association, canonical
    /// admission, full schema validation, or actual append/durability refusal.
    #[doc(hidden)]
    pub fn admit_host_publication_once_v2(&mut self,
        intake: &crate::CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        root: &crate::normal_root::RootStartResourceCurrentTurnV2<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        use crate::cold_launch_publication::action::PublicationActionPhaseV1;
        use crate::normal_root::RootHostPublicationTurnKindV2;
        use crate::reconciler::start_admission::{StartAdmissionScopeV1, StartHostCoreScopePhaseV2};
        let contract = {
            let loan = self.borrow_host_root_v1(intake, controller, source)?;
            loan.require_host_stage_v2(4, controller)?;
            root.require_host_publication_owner_v2(RootHostPublicationTurnKindV2::Admission,
                loan.parent_operation_v1(), loan.native_turn_v1(), loan.native.profile.as_ref())?;
            let action = loan.native.host_publication_action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            if action.admission_geometry.is_some() || action.admission.is_some() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Arc::clone(&action.contract)
        };
        let geometry = contract.plan.start_host_publication_phase_receiving_demand_v2(
            controller, &contract.draft, &contract.prepared, PublicationActionPhaseV1::Admission,
        ).and_then(|models| {
            let scope = StartAdmissionScopeV1::host_scope_receiving_demand_v2()
                .map_err(ResourceReservationErrorV1::Journal)?;
            models.checked_add(scope).map_err(Into::into)
        });
        let native = self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let action = native.host_publication_action.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        action.admission_geometry = Some(geometry);
        let demand = *action.admission_geometry.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let funding = (|| -> Result<(), ResourceReservationErrorV1> {
            let mut loan = self.borrow_host_root_v1(intake, controller, source)?;
            let complete = loan.native.resources.host_publication_resident.checked_add(demand)?;
            let returned = loan.require_complete_v1(controller, demand);
            let selected = returned.is_err() && loan.native.native_failure_v1().is_some();
            if returned.is_ok() {
                loan.native.resources.host_publication_resident = complete;
            }
            let action = loan.native.host_publication_action.as_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            action.admission_native_selected = selected;
            returned
        })();
        let native = self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let action = native.host_publication_action.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        action.admission_turn = Some(native.native_turn);
        action.admission_funding = Some(funding);
        if !matches!(action.admission_funding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let scope = match StartAdmissionScopeV1::from_host_entry_v2(self, controller,
            StartHostCoreScopePhaseV2::Admission, root, source) {
            Ok(scope) => scope,
            Err(cause) => {
                let action = self.native_state.as_mut()
                    .and_then(|native| native.host_publication_action.as_mut())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                action.admission_scope = Some(Err(cause));
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        match controller.install_start_admission_scope_v1(Box::new(scope)) {
            Ok(()) => {}
            Err(scope) => {
                self.restore_native_state_v1(scope.into_native_v1());
                let action = self.native_state.as_mut()
                    .and_then(|native| native.host_publication_action.as_mut())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                action.admission_scope = Some(Err(ResourceReservationErrorV1::Conflict));
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        let returned = controller.admit_start_host_publication_v2();
        let Some(scope) = controller.take_start_admission_scope_v1() else {
            std::process::abort();
        };
        self.restore_native_state_v1(scope.into_native_v1());
        let native = self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let native_selected = returned.is_err() && native.native_failure_v1().is_some();
        let action = native.host_publication_action.as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        action.admission_scope = Some(Ok(()));
        action.admission_native_selected = native_selected;
        action.admission = Some(returned);
        if matches!(action.admission, Some(Ok(_))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    /// Rejoins admission only after the real Root4 and C posts both complete.
    ///
    /// # Errors
    /// Refuses an incomplete child, changed active ordinal or any actual post.
    #[doc(hidden)]
    pub fn finish_host_admission_after_posts_once_v2(&mut self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        let stage = &self.resource_entries.host;
        let native = self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let action = native.host_publication_action.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        if action.admission_after.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        action.admission_after = Some((|| {
            controller.ensure_protected_authority().map_err(ResourceReservationErrorV1::Journal)?;
            if stage.active_turn != Some(4) || action.admission_turn != Some(native.native_turn)
                || !matches!(action.admission, Some(Ok(_)))
                || !matches!(stage.turn_after[4], Some(Ok(())))
                || !matches!(stage.turn_root_after[4], Some(Ok(())))
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        if matches!(action.admission_after, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }
}

impl StartHostPublicationActionOriginalV2 {
    /// Selects the retained admission body before independently owed posts.
    pub(super) fn admission_body_failure_v2(&self)
        -> Option<(&(dyn Error + 'static), bool)> {
        if let Some(cause) = self.admission_geometry.as_ref()
            .and_then(|returned| returned.as_ref().err()) {
            return Some((cause, false));
        }
        if let Some(cause) = self.admission_funding.as_ref()
            .and_then(|returned| returned.as_ref().err()) {
            return Some((cause, self.admission_native_selected));
        }
        if let Some(cause) = self.admission_scope.as_ref()
            .and_then(|returned| returned.as_ref().err()) {
            return Some((cause, false));
        }
        self.admission.as_ref().and_then(|returned| returned.as_ref().err())
            .map(|cause| (cause as &(dyn Error + 'static), self.admission_native_selected))
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Reports a retained admission-body refusal before later independent posts.
    ///
    /// This diagnostic performs no IO and grants no phase or publication right.
    #[doc(hidden)]
    #[must_use]
    pub fn host_admission_body_failure_entered_v2(&self) -> bool {
        self.native_state.as_ref()
            .and_then(|native| native.host_publication_action.as_ref())
            .and_then(StartHostPublicationActionOriginalV2::admission_body_failure_v2)
            .is_some()
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Rejoins the actual completed catalog interval after both independent posts.
    ///
    /// This passive gate binds the same private pending child and Root6/C
    /// ordinal. The SDK additionally requires its actual completed method17
    /// native owner and authenticated Session before it retires operation aliases.
    pub(crate) fn require_completed_host_catalog_turn_v2(&self,
        root: &crate::normal_root::RootHostLaunchClientOriginalV1,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        let stage = &self.resource_entries.host;
        let native = self.native_state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let action = native.host_publication_action.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if stage.active_turn != Some(6) || stage.turn_ordinal[6] != Some(native.native_turn)
            || !matches!(stage.turn_before[6], Some(Ok(())))
            || !matches!(stage.turn_after[6], Some(Ok(())))
            || !matches!(stage.turn_root_after[6], Some(Ok(())))
            || !Arc::ptr_eq(self.scope_identity_v1()?, &action.contract.identity)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        action.require_pending_catalog_v2(controller)?;
        root.require_completed_host_publication_turn_v2(
            crate::normal_root::RootHostPublicationTurnKindV2::Catalog,
            self, controller, action.contract.parent, native.native_turn, native.profile.as_ref())
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Borrows the exact retained native catalog owner without sampling again.
    ///
    /// The SDK qualifier independently compares its private completed Session,
    /// generation and packet identities to this owner. This passive accessor
    /// cannot declare completion, create a qualifier or enter activation.
    #[doc(hidden)]
    #[must_use]
    pub fn host_catalog_native_completion_v2(&self)
        -> Option<&StartHostCatalogNativeCompletionV2> {
        self.native_state.as_ref()?.resources.host_catalog_completion.as_ref()
    }
}

/// Derives the private child's immutable comparison identity without authority.
///
/// Both Controller construction and Root's protected-row comparison use this
/// sole recipe. A derived ID cannot construct a child, gate or publication.
pub(crate) fn start_host_publication_operation_id_data_v2(
    parent: OperationId, root_reply: [u8; 32], prepared_publication: ObjectDigest,
) -> OperationId {
    let mut hash = Sha256::new();
    hash.update(b"aos.original-start.host-publication.v2\0");
    hash.update(parent.as_bytes());
    hash.update(root_reply);
    hash.update(prepared_publication.as_bytes());
    let digest: [u8; 32] = hash.finalize().into();
    let mut operation = [0; 16];
    operation.copy_from_slice(&digest[..16]);
    OperationId::from_bytes(operation)
}
