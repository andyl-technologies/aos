//! Runs an exact issued publication through the existing Core commit recipes.
//!
//! The scope retains the same original C receiver and immutable action contract.
//! Its private tags are constructed only at the three existing transaction
//! assembly sites. Ordinary Journal commits never receive a provisioning loan.

pub(crate) mod storage_io;
pub use storage_io::{
    CreateProvisioningStorageIoErrorV1, CreateProvisioningStorageIoLoanV1,
    CreateProvisioningStorageIoOriginalV1,
};

use std::sync::Arc;

use aos_sandbox_core::{ResourceDimension, ResourceVector};

use super::*;
use crate::cold_launch_publication::action::{
    OriginalPublicationActionClosedV1, OriginalPublicationActionV1,
    PublicationActionContractV1,
};
use crate::CreateProvisioningOriginalsV1;
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::publication::PreparedAuthorityPublicationV1;

/// Carries one private canonical Core assembly tag without public factories.
pub(crate) struct CoreCommitRecipeV1<'input> {
    kind: CoreCommitKindV1<'input>,
}

enum CoreCommitKindV1<'input> {
    Admission(&'input OperationPlan),
    Activation(OperationId, &'input PreparedAuthorityPublicationV1),
    ChildTransition,
}

impl<'input> CoreCommitRecipeV1<'input> {
    pub(crate) fn admission_plan_v1(&self) -> Option<&OperationPlan> {
        match self.kind { CoreCommitKindV1::Admission(plan) => Some(plan), _ => None }
    }

    pub(crate) fn require_start_host_admission_v2(&self,
        expected: &OperationPlan,
    ) -> Result<(), JournalError> {
        match self.kind {
            CoreCommitKindV1::Admission(actual) if actual == expected => Ok(()),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(crate) fn require_start_host_activation_v2(&self,
        operation: OperationId, expected: &PreparedAuthorityPublicationV1,
    ) -> Result<(), JournalError> {
        match self.kind {
            CoreCommitKindV1::Activation(actual, prepared)
                if actual == operation && prepared == expected => Ok(()),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(crate) fn require_start_host_child_kind_v2(&self) -> Result<(), JournalError> {
        if matches!(self.kind, CoreCommitKindV1::ChildTransition) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn require_start_host_child_v2(&self, plan: &OperationPlan,
        journal: &Journal, transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if !matches!(self.kind, CoreCommitKindV1::ChildTransition) {
            return Err(JournalError::ProtectedBoundary);
        }
        ProvisioningScopeV1::require_child_rows_v1(plan, journal, transaction)
    }

    pub(super) fn admission(plan: &'input OperationPlan) -> Self {
        Self { kind: CoreCommitKindV1::Admission(plan) }
    }

    pub(super) fn activation(operation: OperationId,
        prepared: &'input PreparedAuthorityPublicationV1,
    ) -> Self {
        Self { kind: CoreCommitKindV1::Activation(operation, prepared) }
    }

    pub(super) fn child_transition() -> Self {
        Self { kind: CoreCommitKindV1::ChildTransition }
    }
}

// The installed caller pays both the Box constructor and retained destination
// before the same original moves here. No failed native original is allocated.
pub(crate) struct ProvisioningScopeV1 {
    contract: Arc<PublicationActionContractV1>,
    original: Option<CreateProvisioningOriginalsV1>,
    complete: ResourceVector,
}

impl ProvisioningScopeV1 {
    pub(crate) fn into_original_v1(mut self) -> CreateProvisioningOriginalsV1 {
        match self.original.take() {
            Some(original) => original,
            None => std::process::abort(),
        }
    }

    fn original_v1(&self) -> Result<&CreateProvisioningOriginalsV1, ResourceReservationErrorV1> {
        self.original.as_ref().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn require_current_v1(&self, journal: &Journal)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.original_v1()?.require_current_v1(journal)
    }

    pub(crate) fn append_loan_v1<'loan>(&'loan mut self,
        transaction: &'loan JournalTransaction, recipe: CoreCommitRecipeV1<'loan>,
    ) -> ProvisioningAppendLoanV1<'loan> {
        ProvisioningAppendLoanV1 {
            backing: ProvisioningAppendBackingV1::Publication { scope: self, recipe },
            transaction,
        }
    }

    fn receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|n| n.checked_add(std::mem::size_of::<usize>().checked_mul(2)?))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
    }

    pub(crate) fn permits_operation_v1(&self, operation: OperationId) -> bool {
        self.contract.plan_v1().operation_id() == operation
    }

    pub(crate) fn require_recipe_v1(&self, journal: &Journal, transaction: &JournalTransaction,
        recipe: &CoreCommitRecipeV1<'_>,
    ) -> Result<(), JournalError> {
        self.original_v1().and_then(|original| original.require_current_v1(journal))
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let plan = self.contract.plan_v1();
        match &recipe.kind {
            // The tagged call remains after the sole original admission
            // validator and canonical ordered row assembly. Equality covers
            // the entire owned plan, including every typed companion.
            CoreCommitKindV1::Admission(actual) if *actual == plan => {
                let expected = self.contract.records_v1().records_v1();
                if plan.local_records.as_slice() != expected.as_slice() {
                    return Err(JournalError::ProtectedBoundary);
                }
                Ok(())
            }
            // The activation engine has already checked the same durable
            // pending gate, opaque activation and publication successor.
            CoreCommitKindV1::Activation(operation, prepared)
                if *operation == plan.operation_id()
                    && *prepared == self.contract.prepared_v1() => Ok(()),
            CoreCommitKindV1::ChildTransition => {
                Self::require_child_rows_v1(plan, journal, transaction)
            }
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(super) fn require_child_rows_v1(plan: &OperationPlan, journal: &Journal,
        transaction: &JournalTransaction)
        -> Result<(), JournalError>
    {
        if transaction.records().is_empty() {
            return Err(JournalError::ProtectedBoundary);
        }
        for record in transaction.records() {
            let value = record.value().ok_or(JournalError::ProtectedBoundary)?;
            match record.namespace() {
                RecordNamespace::Operation if record.key() == plan.operation_id().as_bytes() => {
                    let before = journal.get(RecordNamespace::Operation, record.key())
                        .ok_or(JournalError::ProtectedBoundary)?;
                    let before = decode_operation(before)
                        .map_err(|_| JournalError::ProtectedBoundary)?;
                    let after = decode_operation(value)
                        .map_err(|_| JournalError::ProtectedBoundary)?;
                    let expected = transition_operation(before, after.state(), None)
                        .map_err(|_| JournalError::ProtectedBoundary)?;
                    if expected != after {
                        return Err(JournalError::ProtectedBoundary);
                    }
                }
                RecordNamespace::Effect => {
                    let expected = plan.effects.iter().enumerate().find_map(|(step, effect)| {
                        let step = u32::try_from(step).ok()?;
                        (record.key() == effect_key(plan.operation_id(), step))
                            .then_some(effect)
                    }).ok_or(JournalError::ProtectedBoundary)?;
                    let (actual, q04) = decode_effect_with_q04(value)
                        .map_err(|_| JournalError::ProtectedBoundary)?;
                    if q04.is_some()
                        || actual.plan() != expected {
                        return Err(JournalError::ProtectedBoundary);
                    }
                }
                _ => return Err(JournalError::ProtectedBoundary),
            }
        }
        Ok(())
    }
}

/// Borrows only one exact transaction produced by a canonical Core stage.
pub(crate) struct ProvisioningAppendLoanV1<'loan> {
    backing: ProvisioningAppendBackingV1<'loan>,
    transaction: &'loan JournalTransaction,
}

enum ProvisioningAppendBackingV1<'loan> {
    ExecutionAdmission {
        scope: &'loan mut crate::controller_execution_operation::public_admission::ExecutionPublicAdmissionScopeV2,
        recipe: CoreCommitRecipeV1<'loan>,
    },
    ExecutionFloor {
        scope: &'loan mut crate::controller_execution_operation::public_admission::ExecutionPublicAdmissionScopeV2,
        recipe: &'loan crate::cli_model::authorization_adapter::PublicAuthorizationFloorRecipeV1<'loan>,
    },
    CatalogMaintenance(crate::controller_resource_reservation::CatalogMaintenanceAppendContextV2<'loan>),
    StopTerminal(crate::controller_lifecycle_stop::terminal::StopTerminalAppendContextV4<'loan>),
    StopCleanupController(crate::controller_lifecycle_stop::StopCleanupControllerAppendContextV1<'loan>),
    StartTerminal(crate::controller_resource_reservation::StartTerminalAppendContextV2<'loan>),
    Publication { scope: &'loan mut ProvisioningScopeV1, recipe: CoreCommitRecipeV1<'loan> },
    StartFloor {
        scope: &'loan mut super::start_admission::StartAdmissionScopeV1,
        recipe: &'loan crate::cli_model::authorization_adapter::PublicAuthorizationFloorRecipeV1<'loan>,
    },
    StartAdmission {
        scope: &'loan mut super::start_admission::StartAdmissionScopeV1,
        plan: &'loan OperationPlan,
    },
    StartHostCore {
        scope: &'loan mut super::start_admission::StartAdmissionScopeV1,
        recipe: CoreCommitRecipeV1<'loan>,
    },
    StartHostCatalog {
        scope: &'loan mut super::start_admission::StartAdmissionScopeV1,
        recipe: &'loan crate::host_catalog_reconciliation::publication_recipe::HostCatalogCommitRecipeV2<'loan>,
    },
}

impl<'loan> ProvisioningAppendLoanV1<'loan> {
    pub(crate) fn execution_admission_v2(
        scope: &'loan mut crate::controller_execution_operation::public_admission::ExecutionPublicAdmissionScopeV2,
        transaction: &'loan JournalTransaction,
        recipe: CoreCommitRecipeV1<'loan>,
    ) -> Self {
        Self { backing: ProvisioningAppendBackingV1::ExecutionAdmission { scope, recipe }, transaction }
    }

    pub(crate) fn execution_floor_v2(
        scope: &'loan mut crate::controller_execution_operation::public_admission::ExecutionPublicAdmissionScopeV2,
        transaction: &'loan JournalTransaction,
        recipe: &'loan crate::cli_model::authorization_adapter::PublicAuthorizationFloorRecipeV1<'loan>,
    ) -> Self {
        Self { backing: ProvisioningAppendBackingV1::ExecutionFloor { scope, recipe }, transaction }
    }

    pub(crate) fn catalog_maintenance_v2(
        context: crate::controller_resource_reservation::CatalogMaintenanceAppendContextV2<'loan>,
        transaction: &'loan JournalTransaction,
    ) -> Self {
        Self { backing: ProvisioningAppendBackingV1::CatalogMaintenance(context), transaction }
    }

    pub(crate) fn stop_terminal_v4(
        context: crate::controller_lifecycle_stop::terminal::StopTerminalAppendContextV4<'loan>,
        transaction: &'loan JournalTransaction,
    ) -> Self {
        Self { backing: ProvisioningAppendBackingV1::StopTerminal(context), transaction }
    }

    pub(crate) fn stop_cleanup_controller_v1(
        context: crate::controller_lifecycle_stop::StopCleanupControllerAppendContextV1<'loan>,
        transaction: &'loan JournalTransaction,
    ) -> Self {
        Self { backing: ProvisioningAppendBackingV1::StopCleanupController(context), transaction }
    }

    pub(crate) fn stop_cleanup_controller_original_v1(&self)
        -> Option<&crate::controller_lifecycle_stop::StopCleanupControllerAppendContextV1<'loan>> {
        match &self.backing {
            ProvisioningAppendBackingV1::StopCleanupController(context) => Some(context),
            _ => None,
        }
    }

    pub(crate) fn start_terminal_v2(
        context: crate::controller_resource_reservation::StartTerminalAppendContextV2<'loan>,
        transaction: &'loan JournalTransaction,
    ) -> Self {
        Self { backing: ProvisioningAppendBackingV1::StartTerminal(context), transaction }
    }

    pub(crate) fn start_floor_v1(
        scope: &'loan mut super::start_admission::StartAdmissionScopeV1,
        transaction: &'loan JournalTransaction,
        recipe: &'loan crate::cli_model::authorization_adapter::PublicAuthorizationFloorRecipeV1<'loan>,
    ) -> Result<Self, JournalError> {
        scope.prepare_floor_v1(transaction, recipe)?;
        Ok(Self { backing: ProvisioningAppendBackingV1::StartFloor { scope, recipe }, transaction })
    }

    pub(crate) fn start_admission_v1(
        scope: &'loan mut super::start_admission::StartAdmissionScopeV1,
        transaction: &'loan JournalTransaction, plan: &'loan OperationPlan,
    ) -> Result<Self, JournalError> {
        scope.prepare_admission_v1(plan)?;
        Ok(Self { backing: ProvisioningAppendBackingV1::StartAdmission { scope, plan }, transaction })
    }

    pub(crate) fn start_host_core_v2(
        scope: &'loan mut super::start_admission::StartAdmissionScopeV1,
        transaction: &'loan JournalTransaction,
        recipe: CoreCommitRecipeV1<'loan>,
    ) -> Result<Self, JournalError> {
        scope.prepare_host_core_recipe_v2(transaction, &recipe)?;
        Ok(Self { backing: ProvisioningAppendBackingV1::StartHostCore { scope, recipe }, transaction })
    }

    pub(crate) fn start_host_catalog_v2(
        scope: &'loan mut super::start_admission::StartAdmissionScopeV1,
        transaction: &'loan JournalTransaction,
        recipe: &'loan crate::host_catalog_reconciliation::publication_recipe::HostCatalogCommitRecipeV2<'loan>,
    ) -> Result<Self, JournalError> {
        scope.prepare_host_catalog_recipe_v2(transaction, recipe)?;
        Ok(Self { backing: ProvisioningAppendBackingV1::StartHostCatalog { scope, recipe }, transaction })
    }

    pub(crate) fn require_transition(&mut self, journal: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if transaction != self.transaction { return Err(JournalError::ProtectedBoundary); }
        match &mut self.backing {
            ProvisioningAppendBackingV1::ExecutionAdmission { scope, recipe } =>
                scope.require_admission_v2(journal, transaction, recipe),
            ProvisioningAppendBackingV1::ExecutionFloor { scope, recipe } => scope.require_floor_v2(journal, transaction, recipe),
            ProvisioningAppendBackingV1::CatalogMaintenance(context) => context.require_transition_v2(journal, transaction),
            ProvisioningAppendBackingV1::StopTerminal(context) => context.require_transition_v4(journal, transaction),
            ProvisioningAppendBackingV1::StopCleanupController(context) => context.require_transition_v1(journal, transaction),
            ProvisioningAppendBackingV1::StartTerminal(context) => context.require_transition_v2(journal, transaction),
            ProvisioningAppendBackingV1::Publication { scope, recipe } => scope.require_recipe_v1(journal, transaction, recipe),
            ProvisioningAppendBackingV1::StartFloor { scope, recipe } => scope.require_floor_v1(journal, transaction, recipe),
            ProvisioningAppendBackingV1::StartAdmission { scope, plan } => scope.require_admission_v1(journal, plan),
            ProvisioningAppendBackingV1::StartHostCore { scope, recipe } => scope.require_host_core_recipe_v2(journal, transaction, recipe),
            ProvisioningAppendBackingV1::StartHostCatalog { scope, recipe } => scope.require_host_catalog_recipe_v2(journal, transaction, recipe),
        }
    }

    pub(crate) fn matches_identity_v1(&self,
        identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
        state: &std::collections::BTreeMap<(aos_sandbox_core::RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> bool {
        match &self.backing {
            ProvisioningAppendBackingV1::ExecutionAdmission { scope, .. } => scope.matches_q04_v2(identity),
            ProvisioningAppendBackingV1::ExecutionFloor { scope, .. } => scope.matches_q04_v2(identity),
            ProvisioningAppendBackingV1::CatalogMaintenance(context) => context.matches_q04_v2(identity, state),
            // Ordinary Stop metadata never borrows a Create/Start Q04 cut.
            ProvisioningAppendBackingV1::StopTerminal(_) => false,
            ProvisioningAppendBackingV1::StopCleanupController(_) => false,
            ProvisioningAppendBackingV1::StartTerminal(context) => context.matches_q04_v2(identity),
            ProvisioningAppendBackingV1::Publication { scope, .. } => scope.original.as_ref()
                .is_some_and(|original| original.belongs_to_operation_v1(identity.operation())),
            ProvisioningAppendBackingV1::StartFloor { scope, .. }
                | ProvisioningAppendBackingV1::StartAdmission { scope, .. }
                | ProvisioningAppendBackingV1::StartHostCore { scope, .. }
                | ProvisioningAppendBackingV1::StartHostCatalog { scope, .. } => scope.matches_q04_v1(identity),
        }
    }

    pub(crate) fn final_crossing(&mut self, journal: &Journal) -> Result<(), JournalError> {
        match &mut self.backing {
            ProvisioningAppendBackingV1::ExecutionAdmission { scope, .. } => scope.require_availability_admission_crossing_once_v2(journal),
            ProvisioningAppendBackingV1::ExecutionFloor { scope, .. } => scope.require_current_v2(journal),
            ProvisioningAppendBackingV1::CatalogMaintenance(context) => context.final_crossing_v2(journal),
            ProvisioningAppendBackingV1::StopTerminal(context) => context.final_crossing_v4(journal),
            ProvisioningAppendBackingV1::StopCleanupController(context) => context.final_crossing_v1(journal),
            ProvisioningAppendBackingV1::StartTerminal(context) => context.final_crossing_v2(journal),
            ProvisioningAppendBackingV1::Publication { scope, .. } => scope.require_current_v1(journal)
                .map_err(|_| JournalError::ProtectedBoundary),
            ProvisioningAppendBackingV1::StartFloor { scope, .. }
                | ProvisioningAppendBackingV1::StartAdmission { scope, .. } => scope.require_current_v1(journal),
            ProvisioningAppendBackingV1::StartHostCore { scope, .. }
                | ProvisioningAppendBackingV1::StartHostCatalog { scope, .. } => scope.require_host_current_v2(journal),
        }
    }
}

impl<E: SingleNodeEffectExecutor> Reconciler<E> {
    /// Runs one exact child turn, returns its original, then always owes posts.
    ///
    /// The complete action recipe includes the original plan/publication graph
    /// and all future canonical rows. The same semantic provider covers the
    /// current map. Neither the fixed action header nor a Root reply substitutes
    /// for that reached representation bound.
    pub(crate) fn advance_original_publication_v1(&mut self,
        action: &mut OriginalPublicationActionV1,
        receiving: &mut Option<CreateProvisioningOriginalsV1>,
        root: &mut crate::normal_root::RootStorageApplyClientOriginalV1,
    ) -> Result<(), OriginalPublicationActionClosedV1> {
        // The opening's historical digest cannot authorize this phase. The
        // same client must own a live paid before and independently owed after.
        let root_entry = receiving.as_ref().ok_or(ResourceReservationErrorV1::Conflict)
            .and_then(|original| root.borrow_publication_turn_v1(action, original, &self.journal)
                .map(|_| ()));
        let root_entered = root_entry.is_ok();
        if let Err(cause) = root_entry {
            action.retain_core_entry_root_failure_v1(cause);
        }
        let mut original_debit_invoked = false;
        let entry = (|| {
            if !root_entered || self.journal.has_provisioning_scope_v1() || receiving.is_none() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if !receiving.as_ref().is_some_and(|original| {
                original.belongs_to_operation_v1(action.parent_operation_v1())
            }) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let complete = action.dynamic_complete_receiving_demand_v1(&self.journal)?
                .checked_add(root.active_turn_receiving_demand_v1()?)?
                .checked_add(ProvisioningScopeV1::receiving_demand_v1()?)?
                .checked_add(self.journal.create_storage_semantic_append_demand_v1()
                    .map_err(ResourceReservationErrorV1::Journal)?)?;
            original_debit_invoked = true;
            receiving.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
                .require_complete_v1(&self.journal, complete)?;
            Ok(complete)
        })();
        let body = match entry {
            Err(cause) => {
                if !root_entered {
                    // The retained Root-entry result above owns this earlier
                    // cause; do not replace it with this local coarse marker.
                } else if original_debit_invoked
                    && receiving.as_ref().is_some_and(|original| original.failure().is_some()) {
                    action.retain_core_entry_original_failure_v1(cause);
                } else {
                    action.retain_core_entry_failure_v1(cause);
                }
                Err(OriginalPublicationActionClosedV1)
            }
            Ok(complete) => {
                if let Some(original) = receiving.take() {
                    let scope = Box::new(ProvisioningScopeV1 {
                        contract: Arc::clone(action.contract_v1()), original: Some(original), complete,
                    });
                    match self.journal.install_provisioning_scope_v1(scope) {
                        Ok(()) => {
                            let next = if action.requires_next_native_turn_v1() {
                                // Admission and the live Root gate establish
                                // this actual next native interval together.
                                action.begin_next_after_native_posts_v1()
                            } else {
                                Ok(())
                            };
                            let returned = next.and_then(|()| action.advance_core_once_v1(self));
                            let Some(scope) = self.journal.take_provisioning_scope_v1() else {
                                std::process::abort();
                            };
                            *receiving = Some(scope.into_original_v1());
                            returned
                        }
                        Err(scope) => {
                            *receiving = Some(scope.into_original_v1());
                            action.retain_core_entry_failure_v1(ResourceReservationErrorV1::Conflict);
                            Err(OriginalPublicationActionClosedV1)
                        }
                    }
                } else {
                    action.retain_core_entry_failure_v1(ResourceReservationErrorV1::Conflict);
                    Err(OriginalPublicationActionClosedV1)
                }
            }
        };
        let after = receiving.as_mut().ok_or(ResourceReservationErrorV1::Conflict)
            .and_then(|original| original.finish_native_once_v1(&mut self.journal));
        let after_failed = after.is_err();
        if let Err(cause) = after {
            action.retain_core_native_after_failure_v1(cause);
        }
        // Root's independent post is never gated by failed Core/C23 work. The
        // actual returned original remains retained for chronological causes.
        let root_after = root.finish_publication_turn_once_v1(
            action, receiving.as_ref(), &self.journal,
        );
        let root_after_failed = root_after.is_err();
        if let Err(cause) = root_after {
            action.retain_core_root_after_failure_v1(cause);
        }
        if body.is_err() || after_failed || root_after_failed {
            return Err(OriginalPublicationActionClosedV1);
        }
        Ok(())
    }

    pub(super) fn continue_original_publication_parent_v1(&mut self,
        operation: OperationId, current: OperationRecord,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        use aos_sandbox_protocol::public_api::PublicOperationMethodV1;

        if current.state() != OperationState::Applying || current.effect_count() != 1
            || current.ownership_gated() || current.runtime_intent_digest().is_some()
            || current.public_operation().is_none_or(|public| {
                public.method() != PublicOperationMethodV1::CreateSandbox
            }) {
            return Ok(ReconcileOutcome::RetryPending);
        }
        let bytes = self.journal.get(RecordNamespace::Effect, &effect_key(operation, 0))
            .ok_or(ReconcilerError::CorruptLedger("original Create Effect is absent"))?;
        let (record, gate) = decode_effect_with_q04(bytes).map_err(ReconcilerError::from)?;
        if gate.is_none_or(|gate| gate.status() != 4)
            || !matches!(record.state(), EffectState::Applying { .. })
            || record.dispatch().is_some()
            || record.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateSandbox)
        {
            return Ok(ReconcileOutcome::RetryPending);
        }
        self.advance_original_publication_from_executor_v1(operation, record.plan())
    }

    pub(super) fn advance_original_publication_from_executor_v1(&mut self,
        operation: OperationId, plan: &EffectPlan,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        let turn = self.executor.prepare_original_publication_turn_v1(
            operation, plan, &mut self.journal,
        ).map_err(|_| ReconcilerError::InvalidExecutorOutput(
            "original provisioning issuance failed under retained custody",
        ))?;
        if let Some((mut action, original, mut root)) = turn {
            let mut receiving = Some(original);
            let returned = self.advance_original_publication_v1(&mut action, &mut receiving, &mut root);
            let succeeded = returned.is_ok();
            let Some(original) = receiving.take() else {
                std::process::abort();
            };
            self.executor.retain_original_publication_turn_v1(action, original, root, returned);
            if !succeeded {
                return Err(ReconcilerError::InvalidExecutorOutput(
                    "original provisioning turn failed under retained custody",
                ));
            }
            self.ledger_validated = false;
            self.ensure_ledger_validated()?;
        }
        Ok(ReconcileOutcome::RetryPending)
    }

    pub(super) fn commit_core_recipe_v1(&mut self, transaction: &JournalTransaction,
        recipe: CoreCommitRecipeV1<'_>,
    ) -> Result<crate::journal::CommitResult, JournalError> {
        self.journal.commit_core_provisioning_recipe_v1(transaction, recipe)
    }

    pub(super) fn has_original_provisioning_operation_v1(&self, operation: OperationId) -> bool {
        self.journal.has_original_provisioning_operation_v1(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_proto::aos::sandbox::local::v1::BrokerMethod;

    fn effect_record(plan: EffectPlan) -> Vec<u8> {
        encode_effect(&EffectLedgerRecord::from_parts((
            plan, EffectState::Planned, None, None,
        ))).unwrap()
    }

    #[test]
    fn child_recipe_accepts_only_its_original_planned_effect() {
        let (plan, _) = super::super::provisioning_plan_tests::plan_and_records();
        let directory = tempfile::tempdir().unwrap();
        let (journal, _) = Journal::open(directory.path().join("controller"),
            crate::JournalLimits::default()).unwrap();
        let key = effect_key(plan.operation_id(), 0).to_vec();
        let original = effect_record(plan.effects[0].clone());
        let transaction = JournalTransaction::new([81; 16], vec![JournalRecord::put(
            RecordNamespace::Effect, key.clone(), original.clone(),
        )]).unwrap();

        ProvisioningScopeV1::require_child_rows_v1(&plan, &journal, &transaction).unwrap();

        let foreign = JournalTransaction::new([82; 16], vec![JournalRecord::put(
            RecordNamespace::Effect, effect_key(OperationId::from_bytes([83; 16]), 0).to_vec(),
            original,
        )]).unwrap();
        assert!(ProvisioningScopeV1::require_child_rows_v1(&plan, &journal, &foreign).is_err());

        let substituted = EffectPlan::new(EffectDomain::Storage,
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES, b"other-request".to_vec()).unwrap();
        let substituted = JournalTransaction::new([84; 16], vec![JournalRecord::put(
            RecordNamespace::Effect, key, effect_record(substituted),
        )]).unwrap();
        assert!(ProvisioningScopeV1::require_child_rows_v1(&plan, &journal, &substituted).is_err());
    }

    #[test]
    fn child_recipe_cannot_change_a_companion_or_erase_a_record() {
        let (plan, _) = super::super::provisioning_plan_tests::plan_and_records();
        let directory = tempfile::tempdir().unwrap();
        let (journal, _) = Journal::open(directory.path().join("controller"),
            crate::JournalLimits::default()).unwrap();
        let companion = JournalTransaction::new([85; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, plan.desired_key.clone(), plan.desired_value.clone(),
        )]).unwrap();
        let deletion = JournalTransaction::new([86; 16], vec![JournalRecord::delete(
            RecordNamespace::Effect, effect_key(plan.operation_id(), 0).to_vec(),
        )]).unwrap();

        assert!(ProvisioningScopeV1::require_child_rows_v1(&plan, &journal, &companion).is_err());
        assert!(ProvisioningScopeV1::require_child_rows_v1(&plan, &journal, &deletion).is_err());
    }
}
