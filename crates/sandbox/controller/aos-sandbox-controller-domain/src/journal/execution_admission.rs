//! Routes the exact public authorization floor through its owning C18 scope.
//!
//! Taking the scope cannot drop its native or canonical prefix: every returned
//! body path restores the same whole owner before its caller runs owed posts.
//! Core admission uses its private exact-plan recipe. Host and Source effects
//! remain unavailable from this scope.

use super::{CommitResult, Journal, JournalError, JournalTransaction};
use crate::cli_model::authorization_adapter::PublicAuthorizationFloorRecipeV1;
use crate::controller_execution_operation::public_admission::ExecutionPublicAdmissionScopeV2;

impl Journal {
    pub(crate) fn prepare_execution_preaccept_assignment_once_v2(&mut self) -> Result<(), JournalError> {
        let Some(mut scope) = self.execution_admission.take() else {
            return Err(JournalError::ProtectedBoundary);
        };
        let returned = scope.prepare_assignment_once_v2(self);
        self.execution_admission = Some(scope);
        returned
    }

    pub(crate) fn prepare_execution_public_plan_once_v2(
        &mut self,
        compiler: &mut crate::production_operation_compiler::ProductionOperationCompilerV1,
        peer: &crate::public_api_session::PublicApiPeer,
        capability: aos_sandbox_model::CapabilityId,
        handle: &[u8],
        encoded: &[u8],
        digest: [u8; 32],
    ) -> Result<std::sync::Arc<crate::OperationPlan>, crate::OperationCompilationError> {
        let Some(mut scope) = self.execution_admission.take() else {
            return Err(crate::OperationCompilationError::Rejected);
        };
        let funded = scope.prepare_compiler_receiving_once_v2(self, peer, encoded);
        self.execution_admission = Some(scope);
        funded.map_err(|_| crate::OperationCompilationError::Rejected)?;

        // Only the mechanical compiler prefix moves. The SAME complete native
        // owner remains installed, including throughout authorization-floor IO.
        let Some(mut original) = self.execution_admission.as_mut()
            .and_then(|scope| scope.take_compiler_v2())
        else {
            return Err(crate::OperationCompilationError::Rejected);
        };
        let returned = original.prepare_once_v2(
            self, compiler, peer, capability, handle, encoded, digest,
        );
        let Some(scope) = self.execution_admission.as_mut() else {
            std::process::abort();
        };
        scope.restore_compiler_v2(original, returned.is_err());
        returned
    }

    pub(crate) fn bind_execution_admission_plan_v2(
        &mut self,
        plan: std::sync::Arc<crate::OperationPlan>,
    ) -> Result<(), JournalError> {
        let Some(mut original) = self.execution_admission.take() else {
            return Err(JournalError::ProtectedBoundary);
        };
        let returned = original.bind_plan_once_v2(self, plan);
        self.execution_admission = Some(original);
        returned
    }

    pub(crate) fn commit_execution_admission_recipe_v2(
        &mut self,
        transaction: &JournalTransaction,
        recipe: crate::reconciler::provisioning::CoreCommitRecipeV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        let Some(mut original) = self.execution_admission.take() else {
            return Err(JournalError::ProtectedBoundary);
        };
        let returned = self.commit_execution_admission_original_v2(&mut original, transaction, recipe);
        self.execution_admission = Some(original);
        returned
    }

    /// Shares the same original append body while both SDK Sessions stay borrowed.
    pub(crate) fn commit_execution_admission_original_v2(
        &mut self,
        original: &mut ExecutionPublicAdmissionScopeV2,
        transaction: &JournalTransaction,
        recipe: crate::reconciler::provisioning::CoreCommitRecipeV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        match original.prepare_admission_v2(self, transaction, &recipe) {
            Ok(()) => {
                let returned = {
                    let mut loan = crate::reconciler::provisioning::ProvisioningAppendLoanV1::execution_admission_v2(
                        original, transaction, recipe,
                    );
                    self.commit_create_provisioning_v1(transaction, &mut loan)
                };
                original.retain_admission_append_v2(returned)
            }
            Err(cause) => Err(cause),
        }
    }

    pub(crate) fn install_execution_admission_scope_v2(
        &mut self,
        original: Box<ExecutionPublicAdmissionScopeV2>,
    ) -> Result<(), Box<ExecutionPublicAdmissionScopeV2>> {
        if self.execution_admission.is_some() || self.start_admission.is_some()
            || self.provisioning.is_some() || self.operator_recovery.is_some()
        {
            return Err(original);
        }
        self.execution_admission = Some(original);
        Ok(())
    }

    pub(crate) fn take_execution_admission_scope_v2(&mut self) -> Option<Box<ExecutionPublicAdmissionScopeV2>> {
        self.execution_admission.take()
    }

    pub(crate) fn require_execution_admission_current_v2(&self) -> Result<(), JournalError> {
        self.execution_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?
            .require_current_v2(self)
    }

    pub(crate) fn commit_execution_authorization_floor_v2(
        &mut self,
        transaction: &JournalTransaction,
        recipe: &PublicAuthorizationFloorRecipeV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        let Some(mut original) = self.execution_admission.take() else {
            return Err(JournalError::ProtectedBoundary);
        };
        let returned = match original.prepare_floor_v2(self, transaction, recipe) {
            Ok(()) => {
                let returned = {
                    let mut loan = crate::reconciler::provisioning::ProvisioningAppendLoanV1::execution_floor_v2(
                        &mut original, transaction, recipe,
                    );
                    self.commit_create_provisioning_v1(transaction, &mut loan)
                };
                original.retain_floor_append_v2(returned)
            }
            Err(cause) => Err(cause),
        };
        self.execution_admission = Some(original);
        returned
    }
}
