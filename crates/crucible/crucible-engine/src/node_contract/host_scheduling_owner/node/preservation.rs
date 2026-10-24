//! Authenticates the separate host-two original closure before a single installation.
//!
//! The host has no independent native operation/input journal. Its actual state
//! is the original common allocation. Native peers authenticate their own state
//! separately; this adapter cannot validate or impersonate any native child.

use super::*;
use crate::node_contract::{
    HostSchedulingRuntimeRecord, OriginalLineageNativeScope, OriginalLineageRestoration,
    OriginalLineageRuntimeRecord, WorldActivation,
};
use crate::node_scheduling::RuntimeInputBatch;
use crucible_node_format::{ContentRef, HashRef};

pub(super) struct HostRestorationAdmission {
    pub(super) source: ContentRef,
    pub(super) scheduling: HashRef,
    pub(super) target: ActivationRecord,
}

impl PreparedHostSchedulingNode {
    pub(super) fn validate_original_host_restoration(
        &self,
        source_record: &ContentRef,
        record: &OriginalLineageRuntimeRecord,
        scope: &OriginalLineageNativeScope,
        content: &crate::node_state::VerifiedStateContent,
    ) -> Result<(), OperationFailure> {
        self.validate_original_host_restoration_fields(
            source_record,
            record,
            &scope.source_record,
            &scope.source_capture,
            &scope.target,
            scope.coordinator_schema,
            &scope.owners,
            &scope.journals,
            content,
        )
    }

    pub(super) fn validate_original_host_restoration_fields(
        &self,
        source_record: &ContentRef,
        record: &OriginalLineageRuntimeRecord,
        scope_source_record: &ContentRef,
        source_capture: &crate::node_contract::SavedRuntimeActivation,
        target: &ActivationRecord,
        coordinator_schema: u16,
        owners: &[crate::node_contract::OriginalLineageOwnerMapping],
        journals: &[crate::node_contract::OriginalLineageJournal],
        content: &crate::node_state::VerifiedStateContent,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        if !matches!(
            self.source.edition,
            super::super::preservation::Edition::OriginalLineage
                | super::super::preservation::Edition::CompleteOriginalLineage
        ) {
            return Err(failure("source-one host native restoration is unsupported"));
        }
        let original = self.source.original_restoration_record()?;
        let HostSchedulingRuntimeRecord::OriginalLineage(captured) = &original.runtime else {
            return Err(failure("original host legacy restoration is unsupported"));
        };
        if captured.as_ref() != record
            || scope_source_record != source_record
            || *source_capture != record.source_activation
            || *target != self.activation
            || record.source_activation.world_binding_hash != self.source.world
            || coordinator_schema != 7
            || record
                .operations
                .iter()
                .any(|operation| operation.route.node == self.route.node)
            || record
                .inputs
                .iter()
                .any(|input| input.node == self.route.node)
        {
            return Err(failure(
                "original host runtime, target or host journal differs",
            ));
        }
        let source_owner = OwnerIdentity {
            owner: original.source.owner.owner.id.clone(),
            incarnation: original.source.binding.authority.incarnation_id.clone(),
            generation: original.source.binding.authority.owner_generation,
        };
        let target_owner = self
            .route
            .owners
            .first()
            .ok_or_else(|| failure("fresh original host owner is absent"))?;
        let mapping = owners
            .iter()
            .find(|mapping| mapping.source == source_owner)
            .ok_or_else(|| failure("original host owner mapping is absent"))?;
        let journal = journals
            .iter()
            .find(|journal| journal.node == self.route.node)
            .ok_or_else(|| failure("original host journal is absent"))?;
        if &mapping.target != target_owner
            || !journal.operations.is_empty()
            || !journal.pending_operations.is_empty()
            || !journal.acknowledged_operations.is_empty()
            || !journal.input_stages.is_empty()
        {
            return Err(failure(
                "host restoration cannot adopt an independent native journal",
            ));
        }
        let bytes = content
            .get(source_record)
            .ok_or_else(|| failure("original complete runtime body is absent"))?;
        source_record.verify(bytes).map_err(failure)?;
        for object in &original.objects {
            if content.get(&object.reference) != Some(object.bytes.as_slice()) {
                return Err(failure("original host typed body changed"));
            }
        }
        self.current()
    }

    pub(super) fn admit_original_host_restoration(
        &mut self,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        self.source.authenticate_original_lineage_context(context)?;
        if self.restoration.is_some()
            || self.ready.is_some()
            || self.restoration_installed
            || context.target() != &self.activation
        {
            return Err(failure(
                "original host restoration admission changed or repeated",
            ));
        }
        self.source.authenticate_initial_attachment()?;
        let original = self.source.original_restoration_record()?;
        if let Some(ticket) = &self.source.archive_ticket {
            if context.is_original_installed_restoration_data() {
                context
                    .authenticate_original_installed_host_ticket_data(ticket)
                    .map_err(failure)?;
            } else {
                ticket.authenticate_context(context).map_err(failure)?;
            }
        }
        let HostSchedulingRuntimeRecord::OriginalLineage(record) = &original.runtime else {
            return Err(failure("original host legacy restoration is unsupported"));
        };
        if record.as_ref() != context.record() {
            return Err(failure("original host admitted another source record"));
        }
        context
            .validate_original_scheduler(&original.scheduling)
            .map_err(failure)?;
        self.restoration = Some(HostRestorationAdmission {
            source: context.source_record().clone(),
            scheduling: context.original_scheduler_identity().clone(),
            target: context.target().clone(),
        });
        self.current()
    }

    pub(super) fn install_original_host_restoration(
        &mut self,
        context: &OriginalLineageRestoration<'_>,
        activation: &WorldActivation,
        operations: &[OperationAdmission],
        inputs: &[Rc<RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        self.current()?;
        let admission = self
            .restoration
            .as_ref()
            .ok_or_else(|| failure("original host restoration admission is absent"))?;
        if self.restoration_installed
            || self.ready.is_none()
            || !operations.is_empty()
            || !inputs.is_empty()
            || &admission.source != context.source_record()
            || &admission.scheduling != context.original_scheduler_identity()
            || &admission.target != context.target()
            || activation.record() != &admission.target
        {
            return Err(failure(
                "original host installation changed or repeated its context",
            ));
        }
        // Matching portable labels and a normally initialized scheduler do not
        // suffice. The same original allocation carries the core-written seal.
        self.source
            .authenticate_original_lineage_installation(context)?;
        self.restoration_installed = true;
        self.current()
    }
}
