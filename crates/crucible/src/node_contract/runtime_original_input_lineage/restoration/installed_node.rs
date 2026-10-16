//! Retains one genuine installed-context association on its actual CNP node.
//!
//! Construction is private to the opaque context implementation. A weak Window
//! identity is never permission by itself: every use repeats actual same-Source
//! committed evidence, complete archived predicates and the final live member.
//! Old contexts and portable scope/ACK records cannot create this association.

use super::*;
use crate::node_adapters::cnp::{
    CnpSemanticSource, OriginalInstalledRestorationCustodyConstructionData,
};
use crate::node_admission::CompleteOriginalRestorationWindow;
use crucible_node_provider::client::CnpController;
use std::{mem::size_of, rc::Weak, thread::ThreadId};

/// Retains one same-node association issued by the genuine installed context.
///
/// This owner cannot be cloned, serialized or constructed from a native receipt,
/// public scope, DATA row or boolean. The original holder keeps the same Window
/// alive through cleanup; losing it refuses use without dropping node custody.
pub struct OriginalInstalledRestorationNodeAssociation {
    process: u32,
    thread: ThreadId,
    window: Weak<CompleteOriginalRestorationWindow>,
    selected: usize,
    proof_identity: [u8; 32],
    admitted: OriginalInstalledRestorationCustodyConstructionData,
}

impl OriginalLineageRestoration<'_> {
    /// Distinguishes the intrinsically issued installed context from old routes.
    ///
    /// This is classification DATA only. Every selected consumer must obtain
    /// and authenticate its actual nonconstructible node association.
    pub(crate) fn is_original_installed_restoration_data(&self) -> bool {
        matches!(self.ancestry, RestorationAncestry::Installed { .. })
    }

    pub(crate) fn retain_original_installed_node_association(
        &self,
        source: &dyn CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
    ) -> Result<OriginalInstalledRestorationNodeAssociation, RuntimeError> {
        let RestorationAncestry::Installed { window, plan: _ } = self.ancestry else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        let selected = window.original_installed_source_index_data(source)?;
        let admitted = *window.original_installed_node_custody_data(selected)?;
        window.with_original_installed_node_custody_data(
            selected,
            source,
            controller,
            read_owner,
            |_, _, _| Ok(()),
        )?;
        let proof_identity = window.original_complete_scope_proof_identity_data()?;
        Ok(OriginalInstalledRestorationNodeAssociation {
            process: std::process::id(),
            thread: std::thread::current().id(),
            window: Rc::downgrade(window),
            selected,
            proof_identity,
            admitted,
        })
    }
}

impl OriginalInstalledRestorationNodeAssociation {
    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Borrows the exact fixed node row retained at genuine Window admission.
    ///
    /// # Errors
    /// Refuses another creator or thread. This lends DATA, never a phase claim.
    pub fn admitted_node_custody_data(
        &self,
    ) -> Result<&OriginalInstalledRestorationCustodyConstructionData, RuntimeError> {
        self.origin()?;
        Ok(&self.admitted)
    }

    /// Inspects actual archived custody inside the same Source read fence.
    ///
    /// The callback must use the already admitted concrete fixed/copy window.
    /// It may retain partial selected node entries but cannot extract an owner,
    /// renew Query, issue a context or dispatch a new native operation.
    ///
    /// # Errors
    /// Refuses a missing/foreign actual Window, Source/controller/read owner,
    /// changed complete proof, archived/native journals or terminal live member.
    pub fn with_original_node_custody_data(
        &self,
        source: &dyn CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        inspect: impl FnOnce(
            &OriginalLineageRuntimeRecord,
            &OriginalLineageNativeScope,
            &VerifiedStateContent,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let window = self
            .window
            .upgrade()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if window.original_complete_scope_proof_identity_data()? != self.proof_identity
            || window.original_installed_source_index_data(source)? != self.selected
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        window.with_original_installed_node_custody_data(
            self.selected,
            source,
            controller,
            read_owner,
            inspect,
        )
    }

    /// Counts the actual Weak allocation view without renewing a revoked owner.
    ///
    /// Nested Window owners remain independently walked by its real holder; the
    /// shared allocation header/payload is conservatively repeated per weak view.
    ///
    /// # Errors
    /// Refuses a foreign creator or thread, arithmetic or the supplied bound.
    pub fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.origin()?;
        let Self {
            process: _,
            thread: _,
            window: _,
            selected: _,
            proof_identity: _,
            admitted: _,
        } = self;
        let bytes =
            NodeRuntime::capture_shared_allocation_storage::<CompleteOriginalRestorationWindow>();
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }

    /// Names exact fixed association and original weak/strong inspection views.
    pub fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<&OriginalLineageRestoration<'static>>()
            + size_of::<Result<&OriginalLineageRestoration<'static>, RuntimeError>>()
            + size_of::<Rc<CompleteOriginalRestorationWindow>>()
            + size_of::<Option<Rc<CompleteOriginalRestorationWindow>>>()
            + size_of::<Result<Rc<CompleteOriginalRestorationWindow>, RuntimeError>>()
            + size_of::<
                Result<&'static OriginalInstalledRestorationCustodyConstructionData, RuntimeError>,
            >()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<[u8; 32]>()
            + size_of::<
                crate::node_adapters::cnp::OriginalSourceRestorationActivationConstructionData,
            >()
            + size_of::<
                Result<
                    crate::node_adapters::cnp::OriginalSourceRestorationActivationConstructionData,
                    RuntimeError,
                >,
            >()
    }
}

impl NodeRuntime {
    pub(crate) fn prepare_original_installed_restoration_context_data<'a>(
        &self,
        window: &'a Rc<CompleteOriginalRestorationWindow>,
        plan: &'a crate::node_admission::InstalledConformancePlan,
    ) -> Result<OriginalLineageRestoration<'a>, RuntimeError> {
        let (archive, scope) = window.original_installed_context_inputs_data()?;
        let record = archive.original_runtime_record_data()?;
        let scheduling = &archive.original_host_record_data()?.scheduling;
        let content = archive.content();
        let source = archive.runtime_object();
        let limits = archive.original_installed_context_limits_data()?;
        if self.activated
            || !self.operations.is_empty()
            || !self.input_batches.is_empty()
            || self.terminal.is_some()
            || self.condition_stop.is_some()
            || self.barrier.record() != &scope.target
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        window.validate_original_installed_context_current_data(
            plan, self, source, record, scope, content,
        )?;
        record.validate_metadata(limits.lineage, limits.maximum_record_bytes)?;
        record.check_exact_original_bodies(|reference| content.get(reference))?;
        scope_validation::validate_source(self, record, scheduling, &scope.target)?;
        scope_validation::validate_native_scope(self, source, record, &scope.target, scope)?;
        let identity = scheduling
            .continuation_hash()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let original = OriginalLineageRestoration {
            authority: Rc::clone(&self.authority),
            source: source.clone(),
            scheduling: identity,
            record: record.clone(),
            scope: scope.clone(),
            content,
            limits,
            ancestry: RestorationAncestry::Installed { window, plan },
        };
        original.validate_current(self)?;
        Ok(original)
    }
}

impl OriginalLineageRestoration<'_> {
    pub(crate) fn authenticate_original_installed_host_ticket_data(
        &self,
        ticket: &crate::node_state::CompleteOriginalHostTicket,
    ) -> Result<(), RuntimeError> {
        let RestorationAncestry::Installed { window, plan } = self.ancestry else {
            return Err(RuntimeError::ForeignAuthority);
        };
        let (archive, scope) = window.original_installed_context_inputs_data()?;
        if !Rc::ptr_eq(&archive.inner, &ticket.source)
            || self.source != *archive.runtime_object()
            || &self.scope != scope
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        window.authenticate_original_complete_identity_data(plan, scope)
    }
}

impl OriginalInstalledRestorationNodeAssociation {
    pub(crate) fn begin_original_activation_claim_data(
        &self,
        source: &dyn CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        phase: crate::node_admission::OriginalInstalledRestorationActivationPhase,
        world: Option<&crate::node_contract::WorldActivation>,
    ) -> Result<crate::node_admission::OriginalInstalledRestorationActivationClaim, RuntimeError>
    {
        self.origin()?;
        let window = self
            .window
            .upgrade()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if window.original_complete_scope_proof_identity_data()? != self.proof_identity {
            return Err(RuntimeError::ForeignAuthority);
        }
        window.begin_original_installed_activation_claim_data(
            self.selected,
            source,
            controller,
            read_owner,
            phase,
            world,
        )
    }
}

impl OriginalInstalledRestorationNodeAssociation {
    pub(crate) fn authenticate_original_activation_evidence_data(
        &self,
        source: &dyn CnpSemanticSource,
        phase: crate::node_admission::OriginalInstalledRestorationActivationPhase,
        evidence: &crate::node_adapters::cnp::OriginalSourceRestorationActivationVerifiedPhase<'_>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let window = self
            .window
            .upgrade()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if window.original_complete_scope_proof_identity_data()? != self.proof_identity {
            return Err(RuntimeError::ForeignAuthority);
        }
        window.authenticate_original_activation_evidence_data(
            self.selected,
            source,
            phase,
            evidence,
        )
    }
}

impl OriginalLineageRestoration<'_> {
    pub(crate) fn original_installed_publication_projection_data(
        &self,
    ) -> Result<impl serde::Serialize + '_, RuntimeError> {
        let RestorationAncestry::Installed { window, plan } = self.ancestry else {
            return Err(RuntimeError::ForeignAuthority);
        };
        let (_, scope) = window.original_installed_context_inputs_data()?;
        window.authenticate_original_complete_identity_data(plan, scope)?;
        let proof = self
            .original_body(&scope.proof)
            .ok_or(RuntimeError::InvalidReceipt)?;
        // This borrows the same retained proof Value. No decode or arbitrary DTO
        // supplies context authority at publication.
        let value = window.original_complete_scope_value_data(&scope.proof)?;
        if proof.is_empty() {
            return Err(RuntimeError::InvalidReceipt);
        }
        let scope = window.original_complete_scope_projection_data(&self.scope)?;
        Ok((
            "crucible/original-lineage-restoration-context/1",
            &self.source,
            &self.scheduling,
            scope,
            value,
        ))
    }
}

impl OriginalLineageRestoration<'_> {
    pub(crate) fn authenticate_original_installed_window_data(
        &self,
        original: &CompleteOriginalRestorationWindow,
    ) -> Result<(), RuntimeError> {
        let RestorationAncestry::Installed { window, plan } = self.ancestry else {
            return Err(RuntimeError::ForeignAuthority);
        };
        if !std::ptr::eq(window.as_ref(), original) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let (_, scope) = window.original_installed_context_inputs_data()?;
        window.authenticate_original_complete_identity_data(plan, scope)
    }
}

impl OriginalInstalledRestorationNodeAssociation {
    /// Returns the exact fixed prospective Source row retained by this window.
    ///
    /// # Errors
    /// Refuses another creator, lost window or changed actual proof/member. This
    /// DATA copy cannot issue or renew the separate owned activation claim.
    pub fn admitted_source_activation_data(
        &self,
    ) -> Result<
        crate::node_adapters::cnp::OriginalSourceRestorationActivationConstructionData,
        RuntimeError,
    > {
        self.origin()?;
        let window = self
            .window
            .upgrade()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if window.original_complete_scope_proof_identity_data()? != self.proof_identity {
            return Err(RuntimeError::ForeignAuthority);
        }
        window.original_installed_source_activation_data(self.selected)
    }
}


impl OriginalInstalledRestorationNodeAssociation {
    /// Checks that an installation uses this association's exact issued context.
    ///
    /// The actual Source read fence and concrete custody callback remain caller
    /// requirements. This comparison neither issues a context nor renews a
    /// spent phase; equal portable scope or target data cannot replace the
    /// intrinsic installed ancestry's same retained Window.
    ///
    /// # Errors
    /// Refuses foreign creator/thread, expired original custody, another
    /// installed Window, a changed proof, or failed actual runtime currentness.
    pub fn authenticate_context_data(
        &self,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let window = self.window.upgrade().ok_or(RuntimeError::OwnerUnavailable)?;
        if window.original_complete_scope_proof_identity_data()? != self.proof_identity {
            return Err(RuntimeError::ForeignAuthority);
        }
        context.authenticate_original_installed_window_data(&window)?;
        if window.original_complete_scope_proof_identity_data()? != self.proof_identity {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.origin()
    }
}
