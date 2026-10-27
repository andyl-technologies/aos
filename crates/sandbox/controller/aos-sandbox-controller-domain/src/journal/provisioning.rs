//! Retains the same original C receiver during one exact Core semantic turn.
//!
//! A scope's presence does not permit ordinary Journal mutation. Only the
//! private Core assembly tags borrow its original into the existing append
//! engine. The installed caller takes back that same owner before owed posts.

use super::{CommitResult, Journal, JournalError, JournalTransaction};
use crate::reconciler::provisioning::{CoreCommitRecipeV1, ProvisioningScopeV1};
use aos_sandbox_model::OperationId;

impl Journal {
    pub(crate) fn has_provisioning_scope_v1(&self) -> bool {
        self.provisioning.is_some()
    }

    pub(crate) fn install_provisioning_scope_v1(&mut self,
        scope: Box<ProvisioningScopeV1>,
    ) -> Result<(), Box<ProvisioningScopeV1>> {
        if self.provisioning.is_some() || self.start_admission.is_some() || self.execution_admission.is_some() { return Err(scope); }
        self.provisioning = Some(scope);
        Ok(())
    }

    pub(crate) fn take_provisioning_scope_v1(&mut self) -> Option<Box<ProvisioningScopeV1>> {
        self.provisioning.take()
    }

    pub(crate) fn has_original_provisioning_operation_v1(&self, operation: OperationId) -> bool {
        self.provisioning.as_ref().is_some_and(|scope| {
            scope.permits_operation_v1(operation) && scope.require_current_v1(self).is_ok()
        })
    }

    pub(crate) fn commit_core_provisioning_recipe_v1(&mut self,
        transaction: &JournalTransaction, recipe: CoreCommitRecipeV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        if self.execution_admission.is_some() {
            return self.commit_execution_admission_recipe_v2(transaction, recipe);
        }
        let Some(mut scope) = self.provisioning.take() else {
            return self.commit_start_admission_recipe_v1(transaction, recipe);
        };
        let returned = {
            let mut loan = scope.append_loan_v1(transaction, recipe);
            self.commit_create_provisioning_v1(transaction, &mut loan)
        };
        // Error paths return the same native owner; its prepaid after is still
        // independent of the semantic/native append's returned result.
        self.provisioning = Some(scope);
        returned
    }
}

impl Journal {
    /// Borrows the same restored receiver's selected native Storage IO cause.
    ///
    /// This read-only view issues no loan, debit, retry or method authority.
    #[doc(hidden)]
    pub fn original_provisioning_storage_io_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)> {
        self.provisioning.as_ref().and_then(|scope| scope.storage_io_failure_v1())
    }
}

impl Journal {
    pub(crate) fn install_start_admission_scope_v1(&mut self,
        scope: Box<crate::reconciler::start_admission::StartAdmissionScopeV1>,
    ) -> Result<(), Box<crate::reconciler::start_admission::StartAdmissionScopeV1>> {
        if self.start_admission.is_some() || self.provisioning.is_some() || self.execution_admission.is_some() { return Err(scope); }
        self.start_admission = Some(scope);
        Ok(())
    }

    pub(crate) fn take_start_admission_scope_v1(&mut self)
        -> Option<Box<crate::reconciler::start_admission::StartAdmissionScopeV1>> {
        self.start_admission.take()
    }

    fn commit_start_admission_recipe_v1(&mut self, transaction: &JournalTransaction,
        recipe: CoreCommitRecipeV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        let Some(mut scope) = self.start_admission.take() else { return self.commit(transaction); };
        if scope.is_host_scope_v2() {
            let returned = scope.prepay_host_core_v2(self, transaction, &recipe).and_then(|()| {
                let mut loan = crate::reconciler::provisioning::ProvisioningAppendLoanV1::start_host_core_v2(
                    &mut scope, transaction, recipe)?;
                self.commit_create_provisioning_v1(transaction, &mut loan)
            });
            self.start_admission = Some(scope);
            return returned;
        }
        let returned = match recipe.admission_plan_v1() {
            Some(plan) => scope.prepay_append_v1(self, transaction, 1).and_then(|()| {
                let mut loan = crate::reconciler::provisioning::ProvisioningAppendLoanV1::start_admission_v1(
                    &mut scope, transaction, plan)?;
                self.commit_create_provisioning_v1(transaction, &mut loan)
            }),
            None => Err(JournalError::ProtectedBoundary),
        };
        self.start_admission = Some(scope);
        returned
    }

    pub(crate) fn commit_start_authorization_floor_v1(&mut self, transaction: &JournalTransaction,
        recipe: &crate::cli_model::authorization_adapter::PublicAuthorizationFloorRecipeV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        let Some(mut scope) = self.start_admission.take() else { return self.commit(transaction); };
        let returned = scope.prepay_append_v1(self, transaction, 0).and_then(|()| {
            let mut loan = crate::reconciler::provisioning::ProvisioningAppendLoanV1::start_floor_v1(
                &mut scope, transaction, recipe)?;
            self.commit_create_provisioning_v1(transaction, &mut loan)
        });
        // A debit/append error never loses the real new native original.
        self.start_admission = Some(scope);
        returned
    }
}

impl Journal {
    /// Commits a canonical catalog recipe only under the actual catalog6 scope.
    pub(crate) fn commit_start_host_catalog_recipe_v2(&mut self,
        transaction: &JournalTransaction,
        recipe: &crate::host_catalog_reconciliation::publication_recipe::HostCatalogCommitRecipeV2<'_>,
    ) -> Result<CommitResult, JournalError> {
        // This named entry deliberately has no ordinary-commit fallback.
        let Some(mut scope) = self.start_admission.take() else {
            return Err(JournalError::ProtectedBoundary);
        };
        let returned = scope.prepay_host_catalog_v2(self, transaction, recipe).and_then(|()| {
            let mut loan = crate::reconciler::provisioning::ProvisioningAppendLoanV1::start_host_catalog_v2(
                &mut scope, transaction, recipe)?;
            self.commit_create_provisioning_v1(transaction, &mut loan)
        });
        self.start_admission = Some(scope);
        returned
    }
}

impl Journal {
    /// Lends only the installed Host scope's actual native validation boot.
    pub(crate) fn start_host_scope_boot_v2(&self) -> Result<[u8; 16], JournalError> {
        let scope = self.start_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        scope.require_host_current_v2(self)?;
        scope.host_native_boot_v2()
    }

    /// Borrows the same private admitted plan while its native receiver is installed.
    pub(crate) fn start_host_admission_contract_v2(&self)
        -> Result<std::sync::Arc<crate::controller_resource_reservation::StartHostPublicationContractV2>, JournalError> {
        let scope = self.start_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        scope.require_host_current_v2(self)?;
        scope.host_admission_contract_v2()
    }
}

impl Journal {
    pub(crate) fn take_start_host_activation_original_v2(&mut self)
        -> Result<(std::sync::Arc<crate::controller_resource_reservation::StartHostPublicationContractV2>,
            crate::publication::AuthorityPublicationActivationV1), JournalError> {
        let mut scope = self.take_start_admission_scope_v1().ok_or(JournalError::ProtectedBoundary)?;
        let returned = (|| {
            scope.require_host_current_v2(self)?;
            scope.take_host_activation_original_v2()
        })();
        // The same native owner returns even if its guarded original refuses.
        // No append, native sampling or allocation occurs during this move.
        match self.install_start_admission_scope_v1(scope) {
            Ok(()) => returned,
            Err(_scope) => std::process::abort(),
        }
    }
}

impl Journal {
    pub(crate) fn take_start_host_effect_inputs_v2(&mut self, complete: bool)
        -> Result<(std::sync::Arc<crate::controller_resource_reservation::StartHostPublicationContractV2>,
            crate::PreparedAuthorityEffectV1, Option<crate::ValidatedAuthorityEffectReceiptV1>), JournalError> {
        let mut scope = self.take_start_admission_scope_v1().ok_or(JournalError::ProtectedBoundary)?;
        let returned = (|| {
            scope.require_host_current_v2(self)?;
            scope.host_effect_inputs_v2(complete)
        })();
        match self.install_start_admission_scope_v1(scope) {
            Ok(()) => returned,
            Err(_scope) => std::process::abort(),
        }
    }
}
