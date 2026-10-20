//! Shares Core admission and atomic activation over the actual borrowed Journal.
//!
//! Ordinary reconciliation keeps its original structural cache and executor
//! timing source. A closed Host scope starts with a fresh complete validation
//! and uses the boot of its genuine new native interval. No method accepts a
//! caller boot, row set, generic payer, or callback as publication authority.

use super::*;

mod admission;
mod activation;
mod effect_transition;
mod validation;
pub(super) mod readonly;

enum CoreValidationTimingV2<'executor> {
    Ordinary(&'executor mut dyn SingleNodeEffectExecutor),
    #[cfg(target_os = "linux")]
    StartHost { boot: [u8; 16] },
    #[cfg(target_os = "linux")]
    ExecutionPublic {
        scope: &'executor mut crate::controller_execution_operation::public_admission::ExecutionPublicAdmissionScopeV2,
        boot: [u8; 16],
    },
}

pub(super) struct CoreJournalMutationV2<'journal, 'executor> {
    journal: &'journal mut Journal,
    pub(super) ledger_validated: bool,
    timing: CoreValidationTimingV2<'executor>,
}

impl<'journal, 'executor> CoreJournalMutationV2<'journal, 'executor> {
    pub(super) fn ordinary_v2(journal: &'journal mut Journal,
        executor: &'executor mut dyn SingleNodeEffectExecutor, ledger_validated: bool,
    ) -> Self {
        Self { journal, ledger_validated, timing: CoreValidationTimingV2::Ordinary(executor) }
    }

    #[cfg(target_os = "linux")]
    fn scoped_host_v2(journal: &'journal mut Journal) -> Result<Self, ReconcilerError> {
        let boot = journal.start_host_scope_boot_v2()?;
        Ok(Self { journal, ledger_validated: false, timing: CoreValidationTimingV2::StartHost { boot } })
    }

    fn current_effect_boot_v2(&mut self, operation: OperationId, step: u32)
        -> Result<[u8; 16], ReconcilerError> {
        match &mut self.timing {
            CoreValidationTimingV2::Ordinary(executor) => Ok(executor
                .authority_effect_timing(operation, step)
                .ok_or(ReconcilerError::InvalidExecutorOutput(
                    "authority-bound effect execution is unsupported",
                ))?.clock().host_boot_id()),
            #[cfg(target_os = "linux")]
            CoreValidationTimingV2::StartHost { boot } => Ok(*boot),
            #[cfg(target_os = "linux")]
            CoreValidationTimingV2::ExecutionPublic { boot, .. } => Ok(*boot),
        }
    }

    #[cfg(target_os = "linux")]
    fn commit_core_recipe_v1(&mut self, transaction: &JournalTransaction,
        recipe: provisioning::CoreCommitRecipeV1<'_>,
    ) -> Result<crate::journal::CommitResult, JournalError> {
        match &mut self.timing {
            CoreValidationTimingV2::ExecutionPublic { scope, .. } => self.journal
                .commit_execution_admission_original_v2(scope, transaction, recipe),
            _ => self.journal.commit_core_provisioning_recipe_v1(transaction, recipe),
        }
    }
}

#[cfg(target_os = "linux")]
impl Journal {
    /// Uses the sole admission kernel under the same continuously held C18.
    pub(crate) fn admit_execution_publication_with_original_v2(
        &mut self,
        scope: &mut crate::controller_execution_operation::public_admission::ExecutionPublicAdmissionScopeV2,
        plan: &OperationPlan,
        maximum_pending_operations: usize,
    ) -> Result<AcceptOutcome, ReconcilerError> {
        if maximum_pending_operations == 0 {
            return Err(ReconcilerError::InvalidPlan("pending operation bound is zero"));
        }
        scope.require_current_v2(self)?;
        let boot = scope.preaccept_source_data_v2()?
            .original_authorization_clock_v2().host_boot_id();
        let mut kernel = CoreJournalMutationV2 {
            journal: self, ledger_validated: false,
            timing: CoreValidationTimingV2::ExecutionPublic { scope, boot },
        };
        kernel.accept_inner(plan, Some(maximum_pending_operations))
    }

    /// Admits only the private plan owned by the installed genuine Host scope.
    pub(crate) fn admit_start_host_publication_v2(&mut self) -> Result<AcceptOutcome, ReconcilerError> {
        let contract = self.start_host_admission_contract_v2()?;
        let mut kernel = CoreJournalMutationV2::scoped_host_v2(self)?;
        kernel.accept_inner(&contract.plan, None)
    }
}

#[cfg(target_os = "linux")]
impl Journal {
    pub(crate) fn activate_start_host_publication_v2(&mut self)
        -> Result<OwnershipGateActivationOutcome, ReconcilerError> {
        let (contract, activation) = self.take_start_host_activation_original_v2()?;
        let mut kernel = CoreJournalMutationV2::scoped_host_v2(self)?;
        kernel.activate_ownership_gate_inner(contract.plan.operation_id(), activation, None)
    }
}

#[cfg(target_os = "linux")]
impl Journal {
    pub(crate) fn advance_start_host_effect_v2(&mut self, complete: bool)
        -> Result<(), ReconcilerError> {
        let (contract, dispatch, receipt) = self.take_start_host_effect_inputs_v2(complete)?;
        let mut kernel = CoreJournalMutationV2::scoped_host_v2(self)?;
        kernel.ensure_ledger_validated()?;
        let operation_id = contract.plan.operation_id();
        let operation = kernel.load_operation(operation_id)?;
        if operation.effect_count() != 1 || !operation.ownership_gated()
            || operation.public_operation().is_some()
            || operation.state() != if complete { OperationState::Applying } else { OperationState::Accepted }
        {
            return Err(ReconcilerError::InvalidPlan("private Host operation changed before its original crossing"));
        }
        let before = decode_effect(kernel.journal.get(RecordNamespace::Effect, &effect_key(operation_id, 0))
            .ok_or(ReconcilerError::CorruptLedger("private Host effect is missing"))?)?;
        if before.plan() != contract.plan.start_host_effect_plan_v2()? || before.project_admission().is_some() {
            return Err(ReconcilerError::InvalidPlan("private Host effect changed before its original crossing"));
        }
        let (plan, state, prior_dispatch, metadata) = before.into_parts();
        let after = if complete {
            if !matches!(state, EffectState::Applying { attempt: 1, .. })
                || prior_dispatch.as_ref() != Some(dispatch.history()) {
                return Err(ReconcilerError::InvalidPlan("private Host completion lacks its original Applying"));
            }
            let receipt = receipt.ok_or(ReconcilerError::InvalidExecutorOutput("private Host native receipt is missing"))?
                .into_effect_receipt_for(&dispatch)?;
            effect::validate_durable_receipt_history(dispatch.history(), receipt.as_bytes())?;
            EffectLedgerRecord::from_parts((plan, EffectState::Applied { attempt: 1, receipt },
                Some(dispatch.into_history()), metadata))
        } else {
            if state != EffectState::Planned || prior_dispatch.is_some() || receipt.is_some() {
                return Err(ReconcilerError::InvalidPlan("private Host dispatch lacks its original Planned effect"));
            }
            EffectLedgerRecord::from_parts((plan,
                EffectState::Applying { attempt: 1, diagnostic: String::new() },
                Some(dispatch.into_history()), metadata))
        };
        // The closed Host completion commits its two canonical terminal rows
        // atomically. Ordinary callers retain their previous transaction order.
        kernel.store_effect(operation_id, 0, &after, Some(1), None, complete)
    }
}
