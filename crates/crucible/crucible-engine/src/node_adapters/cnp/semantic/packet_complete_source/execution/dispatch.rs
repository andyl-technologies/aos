//! Dispatches one original administrative attempt through retained Source slots.
//!
//! The runtime ticket is issued only after the complete owning preflight. No
//! report, selected ceiling or local bank reservation substitutes for that
//! ticket. Each successful producer fills an original slot before later fences.

use super::*;
use crate::node_adapters::cnp::semantic::capture::CnpNativeAfterConfirmationCall;
use crucible_node_transport::{
    envelope::Nullable,
    reference_packet::service::confirmation::PacketNativeAfterConfirmationRequest,
};

impl PacketCompleteSemanticSource {
    #[expect(
        clippy::too_many_arguments,
        reason = "keeps the original capsule, opaque ticket, activation, runtime and result slot distinct"
    )]
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn dispatch_original_complete_capture_into(
        &self,
        mut scope: CnpSemanticCaptureScope<'_>,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        activation: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeCaptureLimits,
        completed: &mut Option<InstalledOriginalLineageCapture>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if completed.is_some() {
            return Err(refused("original complete Capture destination is occupied"));
        }
        let realized = scope.realization()?;
        self.authenticate_witness_scope(&realized)?;
        let active = realized
            .native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.active.as_ref())
            .ok_or_else(|| refused("original complete Capture activation is absent"))?;
        if !active.same_authority(activation) {
            return Err(refused("original complete Capture activation changed"));
        }
        ticket
            .authenticate_scope(
                active,
                record,
                runtime_object,
                scope.owner,
                &self.installation().owner.owner.participant_ids,
            )
            .map_err(unknown)?;
        self.authenticate_original_complete_capture_support()?;
        self.prepare_original_complete_capture_execution(
            &realized,
            runtime_object,
            limits.maximum_total_record_bytes,
        )?;
        self.begin_original_complete_capture_attempt(ticket, limits)?;

        // Every call below stores its result in the same preowned attempt. An
        // error or unwind cannot discard an already returned native payload.
        let result = (|| {
            {
                let mut slot = self
                    .capture_banks
                    .try_borrow_mut()
                    .map_err(|_| refused("original semantic Capture banks are borrowed"))?;
                let banks = slot
                    .as_mut()
                    .ok_or_else(|| refused("original Capture banks absent"))?;
                scope.take_original_semantic_snapshot_into(
                    &mut banks.semantic,
                    &mut banks.semantic_snapshot,
                )?;
            }
            self.record_original_ancestry(scope.realization()?)?;
            let request = self.original_complete_capture_request(ticket, activation)?;
            let capture_id = self.original_complete_capture_request_id(false)?;
            {
                let mut slot = self
                    .capture_execution
                    .try_borrow_mut()
                    .map_err(|_| refused("original Capture dispatch marker is borrowed"))?;
                let original = slot
                    .as_mut()
                    .ok_or_else(|| refused("original Capture attempt is absent"))?;
                original.wire_attempted = true;
            }
            {
                let mut slot = self
                    .capture_banks
                    .try_borrow_mut()
                    .map_err(|_| refused("original Capture reply slot is borrowed"))?;
                let banks = slot
                    .as_mut()
                    .ok_or_else(|| refused("original Capture banks absent"))?;
                scope.call_original_capture_into(
                    ticket,
                    record,
                    runtime_object,
                    capture_id.clone(),
                    request,
                    &mut banks.capture_response,
                )?;
            }
            self.record_original_native_capture_objects(
                &scope,
                ticket,
                record,
                runtime_object,
                &capture_id,
            )?;

            let confirmation_id = self.original_complete_capture_request_id(true)?;
            let context = self.original_complete_confirmation_context(&scope, &capture_id)?;
            {
                let mut slot = self
                    .capture_banks
                    .try_borrow_mut()
                    .map_err(|_| refused("original confirmation result slot is borrowed"))?;
                let banks = slot
                    .as_mut()
                    .ok_or_else(|| refused("original Capture banks absent"))?;
                scope.call_original_native_after_confirmation_into(
                    ticket,
                    record,
                    runtime_object,
                    CnpNativeAfterConfirmationCall {
                        request_id: confirmation_id.clone(),
                        context,
                    },
                    &mut banks.confirmation_response,
                )?;
            }
            // The receipt is not cloned or reinterpreted. Its original owning
            // slot remains borrowed while the independent fourth bank is filled.
            self.record_completed_original_native_after(
                &scope,
                ticket,
                record,
                runtime_object,
                &confirmation_id,
            )?;
            self.record_settled_original_protocol(&mut scope)?;
            self.retain_settled_original_protocol_payload(&scope)?;
            self.finish_original_complete_capture_into(
                &scope,
                ticket,
                activation,
                record,
                runtime_object,
                limits,
                &confirmation_id,
                completed,
            )?;
            self.authenticate_witness_scope(&scope.realization()?)
        })();
        if let Err(error) = result {
            // The destination, if already filled, remains Core-owned. The
            // Source keeps every other partial bank and original association.
            self.ensure_origin()?;
            let mut slot = self
                .capture_execution
                .try_borrow_mut()
                .map_err(|_| refused("failed original Capture attempt is borrowed"))?;
            let original = slot
                .as_mut()
                .ok_or_else(|| refused("failed original Capture attempt absent"))?;
            original.failed = true;
            return Err(if original.wire_attempted {
                crate::node_adapters::cnp::semantic::after_effect(error)
            } else {
                error
            });
        }
        Ok(())
    }

    fn begin_original_complete_capture_attempt(
        &self,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        limits: NativeCaptureLimits,
    ) -> Result<(), OperationFailure> {
        let mut slot = self
            .capture_execution
            .try_borrow_mut()
            .map_err(|_| refused("original Capture attempt is borrowed"))?;
        let original = slot
            .as_mut()
            .ok_or_else(|| refused("original Capture attempt is absent"))?;
        if original.failed
            || original.started
            || original.transferred
            || original.owner.is_none()
            || original.key.is_none()
            || original.backend.is_none()
            || original.allocation.is_some()
            || original.allocation_selected
                && original.allocation_bank.capacity() < allocation_report_capacity()
            || original
                .dependency_plan
                .as_ref()
                .is_none_or(|plan| &plan.runtime != ticket.runtime_object())
            || original.evidence.capacity() < original.evidence_roles()
            || original.born.capacity() < original.born_roles()
            || limits.maximum_objects < original.born_roles()
            || original.allocation_selected
                && limits.maximum_record_bytes < allocation_report_capacity()
        {
            return Err(refused(
                "original Capture preparation is incomplete or spent",
            ));
        }
        // A failure during preparation is sticky, including metadata allocation
        // failure before the first request. Retained fields are observed below.
        original.started = true;
        original.capture_request = Some(
            Id::new(format!("packet-source-capture-{}", ticket.operation_id())).map_err(unknown)?,
        );
        original.confirmation_request = Some(
            Id::new(format!("packet-source-after-{}", ticket.operation_id())).map_err(unknown)?,
        );
        original.retained_storage(limits.maximum_total_record_bytes)?;
        Ok(())
    }

    fn original_complete_capture_request_id(
        &self,
        confirmation: bool,
    ) -> Result<Id, OperationFailure> {
        let slot = self
            .capture_execution
            .try_borrow()
            .map_err(|_| refused("original Capture request identity is borrowed"))?;
        let original = slot
            .as_ref()
            .ok_or_else(|| refused("original Capture attempt is absent"))?;
        if confirmation {
            original.confirmation_request.as_ref()
        } else {
            original.capture_request.as_ref()
        }
        .cloned()
        .ok_or_else(|| refused("original Capture request identity is absent"))
    }

    fn original_complete_capture_request(
        &self,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        active: &WorldActivation,
    ) -> Result<BeginRequest, OperationFailure> {
        let installed = self.installation();
        let arguments = CaptureArguments {
            capture_id: ticket.capture_id().clone(), participant_ids: ticket.participants().to_vec(),
            cut_id: ticket.capture_id().clone(), cut: ticket.cut(), event_ordinal: ticket.ordinal(),
            ordering_profile: installed.binding.compatibility.operating_contract.ordering_profile.clone(),
            preservation_contract: Id::new(crucible_node_transport::reference_packet::continuation_contracts::PACKET_COMPLETE_LINEAGE_PROFILE).map_err(unknown)?,
        };
        let arguments = serde_json::to_value(arguments)
            .map_err(unknown)?
            .as_object()
            .cloned()
            .ok_or_else(|| refused("original Capture arguments are not an object"))?;
        let request = BeginRequest {
            kind: BeginKind::Capture,
            binding_hash: installed.owner.identity().map_err(unknown)?,
            owner_generation: installed.binding.authority.owner_generation,
            activation_id: Nullable(Some(active.record().activation_id.clone())),
            world_generation: active.record().generation,
            arguments,
            extensions: Extensions::new(),
        };
        request.validate().map_err(unknown)?;
        Ok(request)
    }

    fn original_complete_confirmation_context(
        &self,
        scope: &CnpSemanticCaptureScope<'_>,
        request_id: &Id,
    ) -> Result<PacketNativeAfterConfirmationRequest, OperationFailure> {
        let realized = scope.realization()?;
        let original = realized
            .controller
            .original(request_id)
            .ok_or_else(|| refused("original completed Capture is absent"))?;
        let terminal = original
            .response
            .as_ref()
            .ok_or_else(|| refused("original Capture terminal is absent"))?;
        original
            .request
            .matches_response(terminal)
            .map_err(unknown)?;
        let banks = self
            .capture_banks
            .try_borrow()
            .map_err(|_| refused("original native return bodies are borrowed"))?;
        let banks = banks
            .as_ref()
            .ok_or_else(|| refused("original Capture banks absent"))?;
        let object = |index: usize| {
            banks.native_objects[index]
                .as_ref()
                .map(|object| object.reference.clone())
                .ok_or_else(|| refused("original native return body is absent"))
        };
        let history = realized
            .controller
            .original_native5_frame_history()
            .map_err(unknown)?;
        let mut terminal_hash = None;
        for (index, frame) in history.frames().map_err(unknown)?.enumerate() {
            if frame.direction
                != crucible_node_transport::transport::original_frames::FrameDirection::Incoming
                || history
                    .authenticate_original_envelope(terminal, frame.direction, index)
                    .is_err()
            {
                continue;
            }
            if terminal_hash.is_some() {
                return Err(refused(
                    "original Capture terminal has repeated literal frames",
                ));
            }
            let body = frame
                .bytes
                .get(4..)
                .ok_or_else(|| refused("original Capture terminal header is absent"))?;
            terminal_hash = Some(
                canonical::hash("source-owned.packet-native-capture-terminal/5", body)
                    .map_err(unknown)?,
            );
        }
        let context = PacketNativeAfterConfirmationRequest {
            schema: "source-owned.packet-native-after-confirmation-request/5".to_owned(),
            capture_request_id: request_id.clone(),
            capture_request_hash: original.identity.clone(),
            capture_operation_id: original
                .request
                .operation_id
                .0
                .as_ref()
                .cloned()
                .ok_or_else(|| refused("original Capture operation is absent"))?,
            capture_terminal_hash: terminal_hash
                .ok_or_else(|| refused("original Capture terminal literal is absent"))?,
            capture_terminal_sequence: terminal.sequence,
            native_snapshot_ref: object(0)?,
            native_control_ref: object(1)?,
            native_anchor_ref: object(2)?,
        };
        context.validate_data().map_err(unknown)?;
        Ok(context)
    }

    fn record_completed_original_native_after(
        &self,
        scope: &CnpSemanticCaptureScope<'_>,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        confirmation_id: &Id,
    ) -> Result<(), OperationFailure> {
        let realized = scope.realization()?;
        self.authenticate_witness_scope(&realized)?;
        let mut slot = self
            .capture_banks
            .try_borrow_mut()
            .map_err(|_| refused("original native-after banks are borrowed"))?;
        let banks = slot
            .as_mut()
            .ok_or_else(|| refused("original native-after banks absent"))?;
        let (_, receipt) = banks
            .confirmation_response
            .as_ref()
            .ok_or_else(|| refused("original native-after receipt is absent"))?;
        self.authenticate_original_capture_settlement_transcript(
            scope,
            ticket,
            record,
            runtime_object,
            confirmation_id,
            receipt,
        )?;
        if banks.native_after_object.is_some() {
            return Err(refused("original native-after copy was already attempted"));
        }
        let bytes = realized
            .controller
            .content(&receipt.native_after_ref)
            .map_err(unknown)?;
        banks.native_after_object = Some(
            crate::node_adapters::cnp::semantic::semantic_snapshot::record_original_bytes(
                &mut banks.native_after_bank,
                &receipt.native_after_ref,
                bytes,
            )?,
        );
        self.authenticate_witness_scope(&realized)
    }
}
