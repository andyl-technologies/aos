//! Binds one admitted transaction to its actual inactive target and query.
//!
//! This owner is not an OriginalLineageRestoration. It retains the original
//! ticket, query/mapping quote and planned IDs before any target callback. The
//! constructor is private to the installed restoration window; no external
//! scalar, decoder, context, Clone or caller-selected permission can create it.

use super::*;
use crate::node_admission::WeakInstalledConformancePlan;
use crate::node_contract::OriginalRuntimeStorageIdentity;
use crucible_node_transport::client::{
    CnpController, OriginalCanonicalBlobAckEmitter,
    OriginalCompleteRestoreInputUploadProspectiveStorageData,
    OriginalCompleteRestoreUploadBeforeMappingData, OriginalFreshRestoreQuery,
};
use crucible_node_transport::protocol_snapshot::PreparedArchivedProtocolMapping;
use std::{
    cell::{OnceCell, RefCell},
    thread::ThreadId,
};

/// Retains original inputs before the installed window attempts target binding.
///
/// This private input bank grants no authority. Its ticket and SDK DATA quote
/// already have their independent real issuers; all nested owners are charged
/// before the containing Option is moved into the admitted target slot.
pub(super) struct OriginalRestorationTargetInputs {
    pub(super) group: Rc<super::transaction_group::OriginalRestorationTransactionGroup>,
    pub(super) selected: usize,
    pub(super) before_mapping: OriginalCompleteRestoreUploadBeforeMappingData,
}

/// Borrows the actual protocol originals while their query frontier is unchanged.
pub(crate) struct OriginalRestorationTargetProtocol<'a> {
    pub(crate) controller: &'a CnpController,
    pub(crate) emitter: &'a OriginalCanonicalBlobAckEmitter,
    pub(crate) query: &'a OriginalFreshRestoreQuery,
    pub(crate) references: [&'a ContentRef; 5],
    pub(crate) mapping: &'a PreparedArchivedProtocolMapping,
}

/// Retains one spent pre-Commit target beneath its genuine installed window.
///
/// No public constructor, clone, serialization or conversion to a final context
/// exists. Final continuation, journal verification, readiness and activation
/// require their separate post-Commit mechanisms. A failed target keeps its
/// actual ticket, IDs and mapping association and cannot retry another owner.
#[must_use = "retain the spent target with every original transaction owner"]
pub struct CompleteOriginalRestorationTransactionTarget {
    process: u32,
    thread: ThreadId,
    plan: WeakInstalledConformancePlan,
    source: Weak<PacketCompleteSemanticSource>,
    runtime: Option<OriginalRuntimeStorageIdentity>,
    activation: *const ActivationRecord,
    inputs: OriginalRestorationTargetInputs,
    phase: phase::OriginalRestorationTargetPhaseGate,
    mapping_partial: RefCell<Option<PreparedArchivedProtocolMapping>>,
    mapping: OnceCell<PreparedArchivedProtocolMapping>,
    upload_partial: RefCell<Option<OriginalCompleteRestoreInputUploadProspectiveStorageData>>,
    upload: OnceCell<OriginalCompleteRestoreInputUploadProspectiveStorageData>,
    normalization_started: std::cell::Cell<bool>,
    normalization_value: RefCell<Option<serde_json::Value>>,
    normalization_partial: RefCell<Option<Vec<u8>>>,
    normalization: OnceCell<Vec<u8>>,
    responses: [RefCell<Option<crucible_node_transport::bodies::ResponseBody>>; 3],
    uploaded: RefCell<Option<crucible_node_transport::client::OriginalCompleteRestoreInputUpload>>,
    input_quote: RefCell<
        Option<crucible_node_transport::client::OriginalCompleteRestoreInputUploadStorageData>,
    >,
}

#[path = "target/phase.rs"]
mod phase;

impl CompleteOriginalRestorationTransactionTarget {
    /// Borrows the actual retained assigned Prepare identifier.
    pub fn prepare_id(&self) -> Result<&Id, RuntimeError> {
        self.inputs.group.prepare_id(self.inputs.selected)
    }

    /// Borrows the actual distinct retained assigned Commit identifier.
    pub fn commit_id(&self) -> Result<&Id, RuntimeError> {
        self.inputs.group.commit_id(self.inputs.selected)
    }

    pub(super) fn bind_original_into(
        window: &super::window::CompleteOriginalRestorationWindow,
        plan: &InstalledConformancePlan,
        source: &Rc<PacketCompleteSemanticSource>,
        runtime: &mut ConformanceRuntime,
        archive: &CompleteOriginalRestorationSource,
        activation: &ActivationRecord,
        pending: &mut Option<OriginalRestorationTargetInputs>,
        output: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        if output.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let inputs = pending.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        inputs.group.authenticate_archive(archive)?;
        if inputs.group.prepare_id(inputs.selected)? == inputs.group.commit_id(inputs.selected)? {
            return Err(RuntimeError::InvalidReceipt);
        }
        runtime.authenticate_original_restoration_target_data(archive, plan, activation)?;
        let ticket = inputs.group.ticket(inputs.selected)?;
        window.authenticate_original_target_data(
            plan, source, runtime, archive, ticket, activation,
        )?;
        ticket.authenticate_source(archive)?;
        source.authenticate_original_restoration_target_data(
            ticket, archive, runtime, plan, activation,
        )?;
        // The installed window obtains the nonconstructible SDK quote from
        // this runtime's actual node before this move. Runtime callbacks below
        // may change protocol currency. The same node must therefore recheck
        // the quote after its mutable loan begins and before any phase effect;
        // a changed frontier leaves this already-spent target retained.

        // No fallible step lies between moving the existing bank and retaining
        // its destination. Refusal/unwind below leaves every original here.
        let inputs = pending.take().ok_or(RuntimeError::OwnerUnavailable)?;
        *output = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            plan: plan.downgrade(),
            source: Rc::downgrade(source),
            runtime: None,
            activation: activation as *const _,
            inputs,
            phase: phase::OriginalRestorationTargetPhaseGate::new(),
            mapping_partial: RefCell::new(None),
            mapping: OnceCell::new(),
            upload_partial: RefCell::new(None),
            upload: OnceCell::new(),
            normalization_started: std::cell::Cell::new(false),
            normalization_value: RefCell::new(None),
            normalization_partial: RefCell::new(None),
            normalization: OnceCell::new(),
            responses: std::array::from_fn(|_| RefCell::new(None)),
            uploaded: RefCell::new(None),
            input_quote: RefCell::new(None),
        });
        let target = output.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        let identity = runtime.begin_original_restoration_transaction(
            archive,
            target.ticket_data()?,
            plan,
            activation,
        )?;
        target.runtime = Some(identity);
        target.authenticate_original_target_data(plan, source, runtime, archive, activation)?;
        target.origin()
    }

    pub(crate) fn authenticate_original_prepare_protocol_data(
        &self,
        protocol: OriginalRestorationTargetProtocol<'_>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.ticket_data()?
            .native_restoration_construction_data()?
            .authenticate_original_references_data(protocol.references)?;
        let upload = self.upload.get().ok_or(RuntimeError::OwnerUnavailable)?;
        let mapping = self.mapping.get().ok_or(RuntimeError::OwnerUnavailable)?;
        if !std::ptr::eq(mapping, protocol.mapping) {
            return Err(RuntimeError::ForeignAuthority);
        }
        upload
            .authenticate_original_inputs_data(
                protocol.controller,
                protocol.emitter,
                protocol.query,
                self.prepare_id()?,
                protocol.references,
                protocol.mapping,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.origin()
    }

    pub(crate) fn ticket_data(&self) -> Result<&CompleteOriginalNativeTicket, RuntimeError> {
        self.inputs.group.ticket(self.inputs.selected)
    }

    pub(crate) fn upload_data(
        &self,
    ) -> Result<&OriginalCompleteRestoreInputUploadProspectiveStorageData, RuntimeError> {
        self.upload.get().ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Spends the one mapping attempt before the Source touches its output slot.
    pub(super) fn begin_original_mapping_data(&self) -> Result<(), RuntimeError> {
        self.origin()?;
        self.phase.begin_mapping()
    }

    pub(super) fn mapping_output_data(
        &self,
    ) -> Result<std::cell::RefMut<'_, Option<PreparedArchivedProtocolMapping>>, RuntimeError> {
        self.origin()?;
        self.phase
            .authenticate_started(&OriginalRestorationTransactionPhase::Prepare)?;
        self.mapping_partial
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)
    }

    /// Retains the completed real mapping before its dependent upload requote.
    ///
    /// This move follows the Source's same-claim mapping method and its terminal
    /// SourceRead fence. No callback or allocation lies between taking the
    /// partial slot and installing the same original in the stable OnceCell.
    pub(super) fn retain_original_mapping_data(&self) -> Result<(), RuntimeError> {
        self.origin()?;
        self.phase.authenticate_mapping_started()?;
        if self.runtime.is_none() || self.mapping.get().is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut partial = self
            .mapping_partial
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = partial.take().ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(original) = self.mapping.set(original) {
            *partial = Some(original);
            return Err(RuntimeError::DuplicateOperation);
        }
        self.origin()
    }

    /// Retains the actual requote before refining all three prepaid upload axes.
    ///
    /// Stable mapping custody precedes this quote: its genuine SDK constructor
    /// must inspect that same mapping. This separate move avoids requiring the
    /// refined quote before its own construction. Refusal retains the actual
    /// quote in the partial slot and never reopens the mapping attempt.
    pub(super) fn retain_original_upload_quote_data(
        &self,
        quote: &mut Option<OriginalCompleteRestoreInputUploadProspectiveStorageData>,
        references: [&ContentRef; 5],
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.phase.authenticate_mapping_started()?;
        self.mapping_data()?;
        if self.upload.get().is_some() || quote.is_none() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.ticket_data()?
            .native_restoration_construction_data()?
            .authenticate_original_references_data(references)?;
        let mut partial = self
            .upload_partial
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if partial.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        *partial = quote.take();
        self.inputs
            .before_mapping
            .authenticate_actual_quote_data(
                partial.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                references,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let original = partial.take().ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(original) = self.upload.set(original) {
            *partial = Some(original);
            return Err(RuntimeError::DuplicateOperation);
        }
        self.origin()
    }

    pub(super) fn selected_data(&self) -> usize {
        self.inputs.selected
    }

    pub(super) fn group_data(
        &self,
    ) -> &Rc<super::transaction_group::OriginalRestorationTransactionGroup> {
        &self.inputs.group
    }

    pub(super) fn mapping_data(&self) -> Result<&PreparedArchivedProtocolMapping, RuntimeError> {
        self.origin()?;
        self.mapping.get().ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn normalization_data(&self) -> Result<&[u8], RuntimeError> {
        self.origin()?;
        self.normalization
            .get()
            .map(Vec::as_slice)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn begin_original_phase_data(
        &self,
        phase: &OriginalRestorationTransactionPhase,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.phase.begin(phase)
    }

    pub(super) fn authenticate_original_phase_data(
        &self,
        phase: &OriginalRestorationTransactionPhase,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.phase.authenticate_started(phase)
    }

    // The window calls this only after the opaque Source evidence returns its
    // exact phase from inside the terminal SourceRead/currentness fence.
    pub(super) fn finish_original_verified_phase_data(
        &self,
        phase: &OriginalRestorationTransactionPhase,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.phase.finish_verified(phase)
    }

    pub(super) fn authenticate_original_completed_data(&self) -> Result<(), RuntimeError> {
        self.origin()?;
        self.phase.authenticate_completed()
    }

    /// Checks the original pre-Prepare quote without renewing Query later.
    pub(super) fn authenticate_original_prepare_query_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
        references: [&ContentRef; 5],
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_phase_data(&OriginalRestorationTransactionPhase::Prepare)?;
        self.authenticate_original_prepare_protocol_data(OriginalRestorationTargetProtocol {
            controller,
            emitter,
            query,
            references,
            mapping: self.mapping_data()?,
        })
    }

    pub(super) fn authenticate_original_member_data(
        &self,
        window_runtime: &crate::node_contract::OriginalRestorationRuntimeMemberIdentity,
        plan: &InstalledConformancePlan,
        source: &Rc<PacketCompleteSemanticSource>,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.activation != activation as *const _
            || !self
                .plan
                .upgrade()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .is_same_original_plan_data(plan)
            || !self
                .source
                .upgrade()
                .is_some_and(|original| Rc::ptr_eq(&original, source))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        window_runtime.authenticate_original_transaction_member_data(
            self.ticket_data()?,
            self.runtime
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            &activation.world_binding_hash,
        )
    }

    pub(super) fn response_output_data(
        &self,
        phase: &OriginalRestorationTransactionPhase,
    ) -> Result<
        std::cell::RefMut<'_, Option<crucible_node_transport::bodies::ResponseBody>>,
        RuntimeError,
    > {
        self.authenticate_original_phase_data(phase)?;
        let index = match phase {
            OriginalRestorationTransactionPhase::Prepare => 0,
            OriginalRestorationTransactionPhase::Inputs => 1,
            OriginalRestorationTransactionPhase::Commit => 2,
        };
        self.responses[index]
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)
    }

    pub(super) fn input_quote_output_data(
        &self,
    ) -> Result<
        std::cell::RefMut<
            '_,
            Option<crucible_node_transport::client::OriginalCompleteRestoreInputUploadStorageData>,
        >,
        RuntimeError,
    > {
        self.authenticate_original_phase_data(&OriginalRestorationTransactionPhase::Inputs)?;
        self.input_quote
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)
    }

    pub(super) fn upload_output_data(
        &self,
    ) -> Result<
        std::cell::RefMut<
            '_,
            Option<crucible_node_transport::client::OriginalCompleteRestoreInputUpload>,
        >,
        RuntimeError,
    > {
        self.authenticate_original_phase_data(&OriginalRestorationTransactionPhase::Inputs)?;
        self.uploaded
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)
    }

    pub(super) fn completed_upload_data(
        &self,
    ) -> Result<
        std::cell::Ref<
            '_,
            Option<crucible_node_transport::client::OriginalCompleteRestoreInputUpload>,
        >,
        RuntimeError,
    > {
        self.origin()?;
        self.uploaded
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)
    }

    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn authenticate_original_target_data(
        &self,
        plan: &InstalledConformancePlan,
        source: &Rc<PacketCompleteSemanticSource>,
        runtime: &ConformanceRuntime,
        archive: &CompleteOriginalRestorationSource,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if !self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?
            .is_same_original_plan_data(plan)
            || !self
                .source
                .upgrade()
                .is_some_and(|original| Rc::ptr_eq(&original, source))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.authenticate_original_restoration_transaction_data(
            archive,
            self.ticket_data()?,
            plan,
            activation,
            self.runtime
                .as_ref()
                .ok_or(RuntimeError::ForeignAuthority)?,
        )?;
        source.authenticate_original_restoration_target_data(
            self.ticket_data()?,
            archive,
            runtime,
            plan,
            activation,
        )?;
        self.origin()
    }
}

#[path = "target/storage.rs"]
mod storage;

#[path = "target/normalization.rs"]
mod normalization;

impl CompleteOriginalRestorationTransactionTarget {
    pub(super) fn authenticate_original_installed_member_data(
        &self,
        window_runtime: &crate::node_contract::OriginalRestorationRuntimeMemberIdentity,
        plan: &InstalledConformancePlan,
        source: &Rc<PacketCompleteSemanticSource>,
        original_activation: *const ActivationRecord,
        world: &crucible_node_format::HashRef,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.authenticate_original_completed_data()?;
        if self.activation != original_activation
            || !self
                .plan
                .upgrade()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .is_same_original_plan_data(plan)
            || !self
                .source
                .upgrade()
                .is_some_and(|original| Rc::ptr_eq(&original, source))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        window_runtime.authenticate_original_transaction_member_data(
            self.ticket_data()?,
            self.runtime
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            world,
        )
    }
}

impl CompleteOriginalRestorationTransactionTarget {
    pub(super) fn authenticate_original_before_prepare_data(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.phase.authenticate_before_prepare_data()
    }
}
