//! Issues the opaque context only after all four actual owners revalidate.
//!
//! The retained scope/proof is never sufficient alone. Every issuance and use
//! repeats the same runtime identity, installed member and actual native/Host
//! predicates. Old final-context routes and Source11 guards remain separate.

use super::*;
use crate::node_contract::{
    OriginalLineageNativeScope, OriginalLineageRestoration, OriginalLineageRuntimeRecord,
};
use crate::node_state::VerifiedStateContent;

impl CompleteOriginalRestorationWindow {
    pub(crate) fn authenticate_original_complete_member_data(
        &self,
        plan: &InstalledConformancePlan,
        scope: &OriginalLineageNativeScope,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let original = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        if !std::ptr::eq(scope, original)
            || !self
                .plan
                .upgrade()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .is_same_original_plan_data(plan)
            || self.stage.get() != WindowStage::TransactionAdmitted
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        for selected in 0..3 {
            let target = self.targets[selected]
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            target.authenticate_original_installed_member_data(
                &self.runtime,
                plan,
                &self.sources[selected],
                self.original_activation_slot,
                &scope.target.world_binding_hash,
            )?;
        }
        let member = OriginalRestorationMemberScope {
            plan,
            window: self,
            sources: &self.sources,
            publisher: None,
        };
        plan.0
            .authority
            .authenticate_original_restoration_construction_member(&plan.evidence(), &member)?;
        if self.stage.get() != WindowStage::TransactionAdmitted {
            return Err(RuntimeError::OutstandingObligations);
        }
        for selected in 0..3 {
            let target = self.targets[selected]
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            target.authenticate_original_installed_member_data(
                &self.runtime,
                plan,
                &self.sources[selected],
                self.original_activation_slot,
                &scope.target.world_binding_hash,
            )?;
        }
        self.authenticate_original_runtime_member_current_data(&scope.target.world_binding_hash)
    }

    pub(crate) fn validate_original_installed_context_current_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &NodeRuntime,
        source: &ContentRef,
        record: &OriginalLineageRuntimeRecord,
        scope: &OriginalLineageNativeScope,
        content: &VerifiedStateContent,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let original = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        if source != self.archive.runtime_object()
            || record != self.archive.original_runtime_record_data()?
            || scope != original
            || !std::ptr::eq(content, self.archive.content())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.runtime
            .authenticate_runtime_data(runtime, &original.target.world_binding_hash)?;
        self.authenticate_original_complete_member_data(plan, original)?;
        self.inspect_original_complete_native_fences_data(plan, runtime, original, 0)?;
        // The nested inspection invoked the final erased member while all three
        // SourceRead guards were armed. Only actual identity/live checks follow
        // their kernel/registrar completion; no callback can invalidate a peer
        // whose SourceRead guard has already completed.
        self.authenticate_original_complete_identity_data(plan, original)
    }

    pub(crate) fn original_installed_source_index_data(
        &self,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
    ) -> Result<usize, RuntimeError> {
        self.origin()?;
        self.sources
            .iter()
            .position(|actual| {
                std::ptr::addr_eq(
                    Rc::as_ptr(actual).cast::<()>(),
                    (source as *const dyn crate::node_adapters::cnp::CnpSemanticSource)
                        .cast::<()>(),
                )
            })
            .ok_or(RuntimeError::ForeignAuthority)
    }

    /// Issues one complete context from the original retained four-owner proof.
    ///
    /// All native effects already belong to their actual completed transactions.
    /// This constructor grants neither readiness nor activation, and a failed
    /// attempt cannot renew an old Source11 or installed context path.
    ///
    /// # Errors
    /// Refuses a pending whole observation, repeated attempt, missing owner,
    /// changed runtime/plan/source/journal, exhausted original future row or
    /// failed native, Host2, body or terminal currentness validation.
    pub fn prepare_original_complete_context<'a>(
        self: &'a Rc<Self>,
        plan: &'a InstalledConformancePlan,
        runtime: &ConformanceRuntime,
    ) -> Result<OriginalLineageRestoration<'a>, RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        self.authenticate_original_complete_declaration_data()?;
        if self.context_started.replace(true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.authenticate_original_complete_member_data(plan, scope)?;
        let context = runtime.prepare_original_installed_restoration_context_data(self, plan)?;
        self.whole_observation.authenticate_dispatch_data()?;
        self.authenticate_original_complete_identity_data(plan, scope)?;
        self.context_issued.set(true);
        Ok(context)
    }

    pub(crate) fn original_installed_context_inputs_data(
        &self,
    ) -> Result<
        (
            &CompleteOriginalRestorationSource,
            &OriginalLineageNativeScope,
        ),
        RuntimeError,
    > {
        self.origin()?;
        Ok((
            &self.archive,
            self.complete_scope
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .scope_data()?,
        ))
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn original_complete_scope_body_data(
        &self,
        reference: &ContentRef,
    ) -> Option<&[u8]> {
        self.complete_scope.get()?.proof_body_data(reference)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn authenticate_original_complete_identity_data(
        &self,
        plan: &InstalledConformancePlan,
        scope: &OriginalLineageNativeScope,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let original = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        if !std::ptr::eq(scope, original)
            || !self
                .plan
                .upgrade()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .is_same_original_plan_data(plan)
            || self.stage.get() != WindowStage::TransactionAdmitted
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        for selected in 0..3 {
            let target = self.targets[selected]
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            target.authenticate_original_installed_member_data(
                &self.runtime,
                plan,
                &self.sources[selected],
                self.original_activation_slot,
                &scope.target.world_binding_hash,
            )?;
        }
        self.authenticate_original_runtime_member_current_data(&scope.target.world_binding_hash)
    }

    fn inspect_original_complete_native_fences_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &NodeRuntime,
        scope: &OriginalLineageNativeScope,
        selected: usize,
    ) -> Result<(), RuntimeError> {
        if selected == 3 {
            runtime.inspect_original_host_restoration_continuation(
                super::host::OriginalRestorationHostContinuationInspection::for_original_installed_window(self, plan, scope))?;
            return self.authenticate_original_complete_member_data(plan, scope);
        }
        // The recursive depth is the closed physical roster, exactly three.
        // Each callback stays inside its SourceRead guard while the next actual
        // runtime-owned node and final Host2 validator authenticate their owners.
        let next = OriginalCompleteNativeFenceStep {
            window: self,
            plan,
            runtime,
            scope,
            selected: selected + 1,
        };
        runtime.inspect_original_restoration_node_continuation(
            super::continuation::OriginalRestorationNodeContinuationInspection::for_original_installed_window(
                self, plan, scope, selected, next))
    }
}

#[derive(Clone, Copy)]
pub(super) struct OriginalCompleteNativeFenceStep<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    plan: &'a InstalledConformancePlan,
    runtime: &'a NodeRuntime,
    scope: &'a OriginalLineageNativeScope,
    selected: usize,
}

impl OriginalCompleteNativeFenceStep<'_> {
    pub(super) fn inspect_next(self) -> Result<(), RuntimeError> {
        self.window.inspect_original_complete_native_fences_data(
            self.plan,
            self.runtime,
            self.scope,
            self.selected,
        )
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn with_original_installed_node_custody_data(
        &self,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &crucible_node_transport::client::CnpController,
        read_owner: *const (),
        inspect: impl FnOnce(
            &OriginalLineageRuntimeRecord,
            &OriginalLineageNativeScope,
            &VerifiedStateContent,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if !self.context_issued.get()
            || self.original_installed_source_index_data(source)? != selected
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let plan = self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        if self
            .observation_phases
            .get(selected)
            .is_some_and(|phase| phase.is_verified())
        {
            return self.with_original_observed_node_custody_data(
                selected, source, controller, read_owner, inspect,
            );
        }
        if let Some(phase) = self
            .activation_phases
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .verified_phase_data()?
        {
            return self.with_original_activated_node_custody_data(
                selected,
                source,
                controller,
                read_owner,
                phase,
                inspect,
                || self.authenticate_original_complete_member_data(&plan, scope),
            );
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let target = self
            .targets
            .get(selected)
            .and_then(OnceCell::get)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let node = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?;
        node.authenticate_original_owner_data(source, read_owner)?;
        let signer = node.signer.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let inspection = OriginalRestorationTransactionInspection {
            window: self,
            target,
            source,
            plan: &plan,
            activation: &scope.target,
            installed_scope: Some(scope),
        };
        let inputs = inspection.original_inputs_data()?;
        let uploaded = target.completed_upload_data()?;
        let uploaded = uploaded.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let evidence = source.original_verified_restore_transfer_commit_data(
            controller,
            uploaded,
            signer,
            &inspection,
        )?;
        let row = target
            .ticket_data()?
            .native_restoration_construction_data()?
            .original_archived_validation_construction_data()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let record = self.archive.original_runtime_record_data()?;
        let maximum_record = self
            .archive
            .original_archive_limits_data()?
            .state
            .maximum_record_bytes;
        evidence.authenticate_held_continuation_data(
            &inputs,
            signer,
            uploaded,
            |held, reference| {
                self.authenticate_original_activation_hold_data(selected, scope, held, reference)?;
                self.authenticate_original_import_boundary_data(
                    selected,
                    source,
                    held,
                    row,
                    maximum_record,
                    self.observed_other_retained
                        .get()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                )?;
                inspect(record, scope, self.archive.content())
            },
            || self.authenticate_original_complete_member_data(&plan, scope),
        )?;
        self.authenticate_original_complete_identity_data(&plan, scope)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(super) fn with_original_activated_node_custody_data(
        &self,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &crucible_node_transport::client::CnpController,
        read_owner: *const (),
        phase: super::super::activation::OriginalInstalledRestorationActivationPhase,
        inspect: impl FnOnce(
            &OriginalLineageRuntimeRecord,
            &OriginalLineageNativeScope,
            &VerifiedStateContent,
        ) -> Result<(), RuntimeError>,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.original_installed_source_index_data(source)? != selected {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let node = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?;
        node.authenticate_original_owner_data(source, read_owner)?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        let proof = self.original_complete_scope_proof_identity_data()?;
        let validation = self.targets[selected]
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .ticket_data()?
            .native_restoration_construction_data()?
            .original_archived_validation_construction_data()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let record = self.archive.original_runtime_record_data()?;
        let maximum_record = self
            .archive
            .original_archive_limits_data()?
            .state
            .maximum_record_bytes;
        self.with_original_activation_signing_inputs_data(
            selected,
            source.as_ref(),
            phase,
            proof,
            |inputs| {
                let evidence = source.original_verified_restoration_activation_data(
                    controller,
                    inputs,
                    inputs.source_construction,
                )?;
                let actual = evidence.authenticate_continuation_data(
                    inputs,
                    inputs.source_construction,
                    |held, reference| {
                        self.authenticate_original_activation_hold_data(
                            selected, scope, held, reference,
                        )?;
                        self.authenticate_original_import_boundary_data(
                            selected,
                            source,
                            held,
                            validation,
                            maximum_record,
                            self.observed_other_retained
                                .get()
                                .ok_or(RuntimeError::OwnerUnavailable)?,
                        )?;
                        inspect(record, scope, self.archive.content())
                    },
                    final_currency,
                )?;
                if actual != phase {
                    return Err(RuntimeError::InvalidReceipt);
                }
                Ok(())
            },
        )
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn original_complete_scope_value_data(
        &self,
        reference: &ContentRef,
    ) -> Result<&serde_json::Value, RuntimeError> {
        self.origin()?;
        self.complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .proof_value_data(reference)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn authenticate_original_installed_runtime_identity_data(
        &self,
        runtime: &NodeRuntime,
        archive: &CompleteOriginalRestorationSource,
        plan: &InstalledConformancePlan,
        target: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if !self.context_issued.get()
            || !Rc::ptr_eq(&self.archive.inner, &archive.inner)
            || !std::ptr::eq(self.original_activation_slot, target)
            || !matches!(
                self.stage.get(),
                WindowStage::TransactionAdmitted | WindowStage::TransactionChecking
            )
            || !self
                .plan
                .upgrade()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .is_same_original_plan_data(plan)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        if &scope.target != target {
            return Err(RuntimeError::ForeignAuthority);
        }
        for (selected, source) in self.sources.iter().enumerate() {
            self.targets[selected]
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .authenticate_original_installed_member_data(
                    &self.runtime,
                    plan,
                    source,
                    self.original_activation_slot,
                    &target.world_binding_hash,
                )?;
        }
        self.runtime
            .authenticate_runtime_data(runtime, &target.world_binding_hash)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn original_complete_scope_projection_data<'a>(
        &self,
        scope: &'a OriginalLineageNativeScope,
    ) -> Result<impl serde::Serialize + 'a, RuntimeError> {
        self.origin()?;
        let actual = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        if scope != actual {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(super::coordinator_projection::ActualScopeProjection(scope))
    }
}

impl CompleteOriginalRestorationWindow {
    // Only this new complete-context route requires mechanism 4. The shared
    // cold and transfer entry points retain their previous marker semantics.
    pub(super) fn authenticate_original_complete_declaration_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        for source in &self.sources {
            if !source.is_original_restoration_activation_declaration_data()? {
                return Err(RuntimeError::UnsupportedFacet);
            }
        }
        self.origin()
    }
}
