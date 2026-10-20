//! Admits genuine fresh Start under its own paid native authorization scope.
//!
//! The actual executor lends an owning entry only after completed Create
//! custody, new C native entry and fresh paid Source/C history. This method
//! runs the sole protected authorizer and production compiler, then the sole
//! Core admission validator/row encoder. The same native owner returns before
//! every independent post and before any admission Result reaches the caller.

use super::*;
use crate::reconciler::start_admission::StartAdmissionScopeV1;

impl<E: SingleNodeEffectExecutor> NodeController<crate::production_operation_compiler::ProductionOperationCompilerV1,E> {
    /// Admits a fresh public Start with the actual retained provisioning owner.
    ///
    /// # Errors
    /// Refuses unavailable completed custody, any current capability/policy,
    /// original deadline, paid history, canonical admission or native post.
    #[doc(hidden)]
    pub fn admit_public_original_start_v1(&mut self,
        peer:&crate::public_api_session::PublicApiPeer,capability:aos_sandbox_model::CapabilityId,
        handle:&[u8],canonical_request:&[u8],
    )->Result<AcceptOutcome,ControllerServiceError> {
        if canonical_request.is_empty() {return Err(ControllerServiceError::EmptyRequest);}
        if canonical_request.len()>self.limits.maximum_request_bytes {return Err(ControllerServiceError::RequestTooLarge);}
        let mut entry=self.reconciler.prepare_original_start_entry_v1(peer,canonical_request)
            .map_err(|_|OperationCompilationError::Rejected)?
            .ok_or(OperationCompilationError::Rejected)?;
        // This digest is inert. Its actual peer currentness checks belong to
        // the paid retained handle/authorization originals below.
        let digest=public_controller_request_digest(self.scope,peer.principal(),peer.project(),canonical_request);
        let admitted=(|| {
            let scope=StartAdmissionScopeV1::from_entry_v1(&mut entry,self.reconciler.journal_mut())
                .map_err(|_|OperationCompilationError::Rejected)?;
            let scope=Box::new(scope);
            if let Err(scope)=self.reconciler.journal_mut().install_start_admission_scope_v1(scope) {
                entry.restore_native_state_v1((*scope).into_native_v1());
                return Err(OperationCompilationError::Rejected.into());
            }
            // All actual fallible body paths below return through the same
            // scope extraction. No callback or await observes a placeholder.
            let returned=(|| {
                entry.prepare_actual_plan_once_v1(self.reconciler.journal_mut(),&mut self.compiler,
                    peer,capability,handle,canonical_request,digest)
                    .map_err(|_|OperationCompilationError::Rejected)?;
                let original=entry.actual_plan_v1().map_err(|_|OperationCompilationError::Rejected)?;
                self.reconciler.journal_mut().bind_start_admission_plan_v1(&original)
                    .map_err(|_|OperationCompilationError::Rejected)?;
                let plan=std::sync::Arc::clone(original.plan_v1().map_err(|_|OperationCompilationError::Rejected)?);
                drop(original);
                if plan.request_digest()!=digest {return Err(ControllerServiceError::CompilerDigestMismatch);}
                entry.mark_admission_invoked_v1();
                self.reconciler.accept_bounded(&plan,self.limits.maximum_pending_operations)
                    .map_err(ControllerServiceError::Reconciler)
            })();
            match self.reconciler.journal_mut().take_start_admission_scope_v1() {
                Some(scope)=>entry.restore_native_state_v1((*scope).into_native_v1()),
                None=>std::process::abort(),
            }
            returned
        })();
        entry.retain_acceptance_v1(admitted);
        // The executor owns the same held Source; it always returns this
        // entire entry after C native/paired after and Source disposition.
        self.reconciler.finish_original_start_entry_v1(&mut entry);
        if entry.failure().is_none() {
            self.reconciler.admit_original_start_source_origin_v1(&mut entry);
        }
        let returned=if entry.failure().is_none() && entry.start_source_origin_completed_v1() {entry.accepted_outcome_v1()}
            else if entry.admission_was_invoked_v1() {
                Err(ControllerServiceError::Reconciler(crate::ReconcilerError::InvalidExecutorOutput(
                    "the original Start owner retains an unresolved admission",
                )))
            } else {Err(OperationCompilationError::Rejected.into())};
        self.reconciler.retain_original_start_entry_v1(entry);
        returned
    }
}
