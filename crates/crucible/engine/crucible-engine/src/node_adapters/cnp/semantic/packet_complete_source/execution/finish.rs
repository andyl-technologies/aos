//! Seals original producer output in the same Core result slot before fences.
//!
//! The producer retains original SDK association owners independently of moved
//! body vectors. Born adjacency records identify exact original encodings;
//! complete cold validation remains mandatory before archive signing.

use super::born::{OriginalBornRole, semantic_external_content_dependencies};
use super::*;
use crucible_node_transport::reference_packet::service::confirmation::PacketNativeAfterConfirmationReceipt;

#[derive(serde::Serialize)]
struct SettledJournalView<'a> {
    schema: &'static str,
    owner: &'a Id,
    participants: &'a [Id],
    cut: Position,
    ordinal: U64,
    runtime: &'a ContentRef,
    backend_implementation: &'a ContentRef,
    semantic: &'a ContentRef,
    ancestry: &'a ContentRef,
    native_snapshot: &'a ContentRef,
    native_control: &'a ContentRef,
    native_anchor: &'a ContentRef,
    native_after_protocol: &'a ContentRef,
    host_protocol: &'a ContentRef,
    host_extension_registry: &'a ContentRef,
    confirmation_request: &'a Id,
    confirmation: &'a PacketNativeAfterConfirmationReceipt,
}

fn payload(slot: &Option<InputPayload>) -> Result<&InputPayload, OperationFailure> {
    slot.as_ref()
        .ok_or_else(|| refused("original complete output body is absent"))
}

impl PacketCompleteSemanticSource {
    #[expect(
        clippy::too_many_arguments,
        reason = "joins the original ticket, runtime, confirmation and preowned output without replacing their custody"
    )]
    pub(super) fn finish_original_complete_capture_into(
        &self,
        scope: &CnpSemanticCaptureScope<'_>,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        active: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeCaptureLimits,
        confirmation_id: &Id,
        completed: &mut Option<InstalledOriginalLineageCapture>,
    ) -> Result<(), OperationFailure> {
        let realized = scope.realization()?;
        self.authenticate_witness_scope(&realized)?;
        let lineages = self.original_reference_ancestry_lineages(&realized)?;
        let runtime = realized
            .native
            .runtime
            .as_ref()
            .ok_or_else(|| refused("original complete semantic custody is absent"))?;
        let mut banks_slot = self
            .capture_banks
            .try_borrow_mut()
            .map_err(|_| refused("original complete output banks are borrowed"))?;
        let banks = banks_slot
            .as_mut()
            .ok_or_else(|| refused("original complete output banks absent"))?;
        let mut execution_slot = self
            .capture_execution
            .try_borrow_mut()
            .map_err(|_| refused("original complete output custody is borrowed"))?;
        let execution = execution_slot
            .as_mut()
            .ok_or_else(|| refused("original complete output custody absent"))?;
        let mut registry_slot = self
            .registry_capture
            .try_borrow_mut()
            .map_err(|_| refused("original complete registry output is borrowed"))?;
        let registry = registry_slot
            .as_mut()
            .ok_or_else(|| refused("original complete registry output absent"))?;
        let registry_body = registry.completed_payload()?;
        let semantic = banks
            .semantic_snapshot
            .as_ref()
            .ok_or_else(|| refused("original complete semantic output absent"))?;
        semantic.authenticate_activation(active)?;
        let (_, confirmation) = banks
            .confirmation_response
            .as_ref()
            .ok_or_else(|| refused("original complete confirmation output absent"))?;
        if completed.is_some()
            || execution.failed
            || execution.transferred
            || banks.transferred
            || execution.owner.as_ref() != Some(&ticket.owner().owner)
            || execution.participants != ticket.participants()
            || payload(&banks.native_objects[0])?.reference
                != confirmation.capture.native_snapshot_ref
            || payload(&banks.native_objects[1])?.reference
                != confirmation.capture.native_control_ref
            || payload(&banks.native_objects[2])?.reference
                != confirmation.capture.native_anchor_ref
            || payload(&banks.native_after_object)?.reference != confirmation.native_after_ref
        {
            return Err(refused("original complete output association differs"));
        }
        if execution.host_protocol.is_none() {
            let (owner, bytes) = banks
                .protocol_payload
                .as_ref()
                .ok_or_else(|| refused("original encoded host owner is absent"))?;
            owner.validate_original_payload(bytes).map_err(unknown)?;
            let reference = canonical::content_ref(
                bytes,
                "application/vnd.source-owned.packet-host-protocol.v11+json",
            )
            .map_err(unknown)?;
            let (owner, bytes) = banks
                .protocol_payload
                .take()
                .ok_or_else(|| refused("original encoded host owner disappeared"))?;
            execution.retained_protocol_owner = Some(owner);
            execution.host_protocol = Some(InputPayload { reference, bytes });
            banks.protocol_detached = true;
        }
        let snapshot_class = self.selected_complete_native_snapshot_class()?;
        if snapshot_class.has_allocation() != execution.allocation_selected {
            return Err(refused(
                "original Report output class changed after reservation",
            ));
        }
        if execution.allocation_selected {
            let snapshot = payload(&banks.native_objects[0])?;
            let plan = snapshot_class
                .validate_snapshot(
                    &snapshot.bytes,
                    limits.maximum_record_bytes,
                    usize::try_from(
                        self.selected_capture_profile()?
                            .native_before_bytes(&self.selected_storage_selection()?.storage)
                            .get(),
                    )
                    .map_err(unknown)?,
                )
                .map_err(unknown)?;
            execution.retain_original_allocation_report(
                &plan,
                &realized,
                limits.maximum_total_record_bytes,
            )?;
        }
        let host = payload(&execution.host_protocol)?;
        let backend = payload(&execution.backend)?;
        let ancestry = payload(&banks.ancestry_record)?;
        let snapshot = payload(&banks.native_objects[0])?;
        let control = payload(&banks.native_objects[1])?;
        let anchor = payload(&banks.native_objects[2])?;
        let after = payload(&banks.native_after_object)?;
        let profile = self.selected_capture_profile()?;
        let before_capacity = usize::try_from(
            profile
                .native_before_bytes(&self.selected_storage_selection()?.storage)
                .get(),
        )
        .map_err(unknown)?;
        let native_plan = snapshot_class
            .validate_snapshot(
                &snapshot.bytes,
                limits.maximum_record_bytes,
                before_capacity,
            )
            .map_err(unknown)?;
        if native_plan.control_bytes() != control.bytes {
            return Err(refused(
                "original snapshot has another embedded Control body",
            ));
        }
        crate::node_adapters::cnp::semantic::semantic_snapshot::authenticate_canonical_reference_bytes(
            native_plan.control_reference_bytes(),
            &control.reference,
        )?;
        let view = SettledJournalView {
            schema: PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA,
            owner: &ticket.owner().owner,
            participants: ticket.participants(),
            cut: ticket.cut(),
            ordinal: ticket.ordinal(),
            runtime: &runtime_object.reference,
            backend_implementation: &backend.reference,
            semantic: &semantic.payload().reference,
            ancestry: &ancestry.reference,
            native_snapshot: &snapshot.reference,
            native_control: &control.reference,
            native_anchor: &anchor.reference,
            native_after_protocol: &after.reference,
            host_protocol: &host.reference,
            host_extension_registry: &registry_body.reference,
            confirmation_request: confirmation_id,
            confirmation,
        };
        // The same preallocated journal bank receives a borrowed complete view;
        // there is no independently cloned confirmation receipt or Value DOM.
        crate::node_adapters::cnp::semantic::semantic_snapshot::record_component(
            &mut banks.journal,
            &view,
        )?;
        banks.journal_record = Some(
            crate::node_adapters::cnp::semantic::semantic_snapshot::take_component(
                &mut banks.journal,
                "application/vnd.source-owned.packet-native-settled-journal.v12+json",
            )?,
        );

        let maximum = limits.maximum_total_record_bytes;
        let objects = limits.maximum_objects;
        OriginalCompleteCaptureExecution::record_born(
            &mut execution.born,
            OriginalBornRole::NativeSnapshot,
            snapshot,
            [&control.reference]
                .into_iter()
                .chain(execution.allocation.as_ref().map(|body| &body.reference)),
            objects,
            maximum,
        )?;
        // Report12 owns scalar/hash data and no ContentRef children. Register
        // this intrinsic leaf only from the actual authenticated SDK loan.
        if let Some(report) = &execution.allocation {
            OriginalCompleteCaptureExecution::record_born(
                &mut execution.born,
                OriginalBornRole::NativeAllocationReport,
                report,
                std::iter::empty(),
                objects,
                maximum,
            )?;
        }
        OriginalCompleteCaptureExecution::record_born(
            &mut execution.born,
            OriginalBornRole::NativeControl,
            control,
            [&backend.reference].into_iter(),
            objects,
            maximum,
        )?;
        OriginalCompleteCaptureExecution::record_born(
            &mut execution.born,
            OriginalBornRole::NativeAnchor,
            anchor,
            [&control.reference].into_iter(),
            objects,
            maximum,
        )?;
        OriginalCompleteCaptureExecution::record_born(
            &mut execution.born,
            OriginalBornRole::NativeAfter,
            after,
            std::iter::empty(),
            objects,
            maximum,
        )?;
        OriginalCompleteCaptureExecution::record_born(
            &mut execution.born,
            OriginalBornRole::HostProtocol,
            host,
            std::iter::empty(),
            objects,
            maximum,
        )?;
        OriginalCompleteCaptureExecution::record_born(
            &mut execution.born,
            OriginalBornRole::HostExtensionRegistry,
            registry_body,
            std::iter::empty(),
            objects,
            maximum,
        )?;
        OriginalCompleteCaptureExecution::record_born(
            &mut execution.born,
            OriginalBornRole::Semantic,
            semantic.payload(),
            [&runtime_object.reference, &host.reference]
                .into_iter()
                .chain(semantic_external_content_dependencies(runtime)),
            objects,
            maximum,
        )?;
        OriginalCompleteCaptureExecution::record_born(
            &mut execution.born,
            OriginalBornRole::Ancestry,
            ancestry,
            lineages
                .iter()
                .flat_map(|lineages| lineages.iter())
                .flat_map(super::born::ancestry_external_content_dependencies),
            objects,
            maximum,
        )?;
        OriginalCompleteCaptureExecution::record_born(
            &mut execution.born,
            OriginalBornRole::Backend,
            backend,
            self.installation()
                .binding
                .compatibility
                .implementation
                .artifacts
                .iter()
                .map(|artifact| &artifact.content)
                .chain(
                    self.installation()
                        .binding
                        .compatibility
                        .implementation
                        .formats
                        .iter()
                        .map(|schema| &schema.definition),
                )
                .chain(
                    self.installation()
                        .binding
                        .compatibility
                        .implementation
                        .model_definitions
                        .iter(),
                ),
            objects,
            maximum,
        )?;
        OriginalCompleteCaptureExecution::record_born(
            &mut execution.born,
            OriginalBornRole::Journal,
            payload(&banks.journal_record)?,
            [
                &runtime_object.reference,
                &backend.reference,
                &semantic.payload().reference,
                &ancestry.reference,
                &snapshot.reference,
                &control.reference,
                &anchor.reference,
                &after.reference,
                &host.reference,
                &registry_body.reference,
            ]
            .into_iter(),
            objects,
            maximum,
        )?;
        execution.authenticate_original_dependency_storage(
            &runtime_object.reference,
            objects,
            maximum,
        )?;
        execution.retained_storage(maximum)?;

        // All structural validation is complete while every object is borrowed.
        // The infallible move phase fills the preborrowed Core destination before
        // the enclosing callback performs any final Source or process fence.
        self.move_original_complete_output_into(execution, banks, registry, ticket, completed)?;
        let _ = record;
        Ok(())
    }
}
