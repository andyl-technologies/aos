//! Runs actual public Execution compilation under the Runtime's same C18.
//!
//! This prepared-only entry retains the complete canonical public prefix in
//! Runtime. It creates no REQUESTED result. Durable acceptance additionally
//! requires the actual retained Host and both Storage availability originals.

use super::*;

impl<E: SingleNodeEffectExecutor>
    NodeController<crate::production_operation_compiler::ProductionOperationCompilerV1, E>
{
    /// Admits actual public Execution through the continuously held provider pair.
    ///
    /// The same C18 enters before public authorization/Exec decoding, retains
    /// canonical compilation, then joins genuine64/65 before REQUESTED and both
    /// accepted binds. No result is exposed between those finite native turns.
    ///
    /// # Errors
    /// Rejects canonical preparation or any actual provider/native/financial
    /// refusal. Whole originals remain resident for exact recovery or NoApply.
    #[doc(hidden)]
    pub fn admit_public_original_execution_once_v2(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability: aos_sandbox_core::CapabilityId,
        handle: &[u8],
        canonical_request: &[u8],
    ) -> Result<AcceptOutcome, ControllerServiceError> {
        self.prepare_public_original_execution_once_v2(peer, capability, handle, canonical_request)?;
        self.reconciler.admit_original_execution_availability_once_v2(
            self.limits.maximum_pending_operations)
            .map_err(|_| OperationCompilationError::Rejected.into())
    }

    /// Prepares the canonical public Execution under the actual native C18.
    ///
    /// Success reports only retained compilation. It is neither acceptance nor
    /// provider availability. Every fallible body restores the same owning
    /// scope to Runtime, and refusals run its independently owed native posts.
    ///
    /// # Errors
    /// Refuses request bounds, unavailable original custody, native accounting,
    /// protected holder/authorization, production compilation or exact-plan
    /// binding. Actual causes remain resident in their original owners.
    fn prepare_public_original_execution_once_v2(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability: aos_sandbox_core::CapabilityId,
        handle: &[u8],
        canonical_request: &[u8],
    ) -> Result<(), ControllerServiceError> {
        if canonical_request.is_empty() {
            return Err(ControllerServiceError::EmptyRequest);
        }
        if canonical_request.len() > self.limits.maximum_request_bytes {
            return Err(ControllerServiceError::RequestTooLarge);
        }

        let (mut custody, bank, profile, fixed) = self.reconciler
            .take_original_execution_public_custody_once_v2()
            .map_err(|_| OperationCompilationError::Rejected)?
            .ok_or(OperationCompilationError::Rejected)?;
        let mut scope = match custody.take_public_scope_once_v2(bank, profile) {
            Ok(scope) => scope,
            Err(_) => {
                self.reconciler.retain_original_execution_public_custody_v2(custody);
                return Err(OperationCompilationError::Rejected.into());
            }
        };

        let digest = public_controller_request_digest(
            self.scope, peer.principal(), peer.project(), canonical_request,
        );
        let prepared = match scope.begin_once_v2(self.reconciler.journal_mut(), fixed) {
            Ok(()) => {
                match self.reconciler.journal_mut().install_execution_admission_scope_v2(scope) {
                    Ok(()) => {
                        let returned = (|| {
                            let plan = self.reconciler.journal_mut().prepare_execution_public_plan_once_v2(
                                &mut self.compiler, peer, capability, handle, canonical_request, digest,
                            )?;
                            if plan.request_digest() != digest {
                                return Err(ControllerServiceError::CompilerDigestMismatch);
                            }
                            self.reconciler.journal_mut().bind_execution_admission_plan_v2(plan)
                                .map_err(|_| OperationCompilationError::Rejected)?;
                            self.reconciler.journal_mut().prepare_execution_preaccept_assignment_once_v2()
                                .map_err(|_| OperationCompilationError::Rejected)?;
                            Ok(())
                        })();
                        scope = match self.reconciler.journal_mut().take_execution_admission_scope_v2() {
                            Some(scope) => scope,
                            None => std::process::abort(),
                        };
                        returned
                    }
                    Err(returned_scope) => {
                        scope = returned_scope;
                        Err(OperationCompilationError::Rejected.into())
                    }
                }
            }
            Err(_) => Err(OperationCompilationError::Rejected.into()),
        };

        let prepared = scope.retain_preparation_once_v2(prepared);
        if !prepared {
            scope.finish_refused_once_v2(self.reconciler.journal_mut());
        }
        custody.restore_public_scope_v2(scope);
        self.reconciler.retain_original_execution_public_custody_v2(custody);
        if prepared { Ok(()) } else { Err(OperationCompilationError::Rejected.into()) }
    }
}
