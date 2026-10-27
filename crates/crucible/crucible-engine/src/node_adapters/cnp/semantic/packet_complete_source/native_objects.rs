//! Retains independent copies of three actually transferred Capture objects.
//!
//! These source-owned return banks coexist with the original controller content
//! cache. Recording them does not settle the complete local journal or issue an
//! installed capture. The original ticket, channel history and native closure
//! remain separate conjuncts.

use super::super::{CnpSemanticCaptureScope, semantic_snapshot::record_original_bytes};
use super::*;
use crucible_node_transport::envelope::Method;
use std::cell::Ref;

impl PacketCompleteSemanticSource {
    /// Retains exact native Capture objects in their original preallocated banks.
    ///
    /// The supplied ticket must match the independent active authority in the
    /// same owning capsule. Only its authentic completed original response selects
    /// the three objects; missing content is never reconstructed or preloaded.
    ///
    /// # Errors
    /// Refuses changed source/ticket custody, missing or unresolved Capture,
    /// different original arguments, unavailable complete objects or used banks.
    /// A refusal retains every already copied object and attempted bank.
    pub fn record_original_native_capture_objects(
        &self,
        scope: &CnpSemanticCaptureScope<'_>,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        runtime: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        request_id: &Id,
    ) -> Result<(), OperationFailure> {
        let realized = scope.realization()?;
        self.authenticate_witness_scope(&realized)?;
        let active = scope
            .native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.active.as_ref())
            .ok_or_else(|| refused("native object recording lacks original active authority"))?;
        ticket
            .authenticate_scope(
                active,
                runtime,
                runtime_object,
                scope.owner,
                &self.installation().owner.owner.participant_ids,
            )
            .map_err(|error| refused(error.to_string()))?;
        let original = realized
            .controller
            .original(request_id)
            .ok_or_else(|| refused("original Capture request is absent"))?;
        let request = &original.request;
        if request.method != Method::Begin
            || request.operation_id.0.as_ref() != Some(ticket.operation_id())
            || request.capture_owner_id.0.as_ref() != Some(&ticket.owner().owner)
        {
            return Err(refused(
                "native objects have another original Capture scope",
            ));
        }
        let request_body = decode_request(request.method, &request.body).map_err(unknown)?;
        let RequestBody::Begin(begin) = &request_body else {
            return Err(refused("original Capture has another request kind"));
        };
        let BeginArguments::Capture(arguments) = begin.decoded_arguments().map_err(unknown)? else {
            return Err(refused("original Capture has another action"));
        };
        if arguments.capture_id != *ticket.capture_id()
            || arguments.participant_ids != ticket.participants()
            || arguments.cut != ticket.cut()
            || arguments.event_ordinal != ticket.ordinal()
        {
            return Err(refused("original Capture arguments differ from the ticket"));
        }
        let response = original
            .response
            .as_ref()
            .ok_or_else(|| refused("original Capture remains unresolved"))?;
        request.matches_response(response).map_err(unknown)?;
        let decoded = decode_response(&request_body, &response.body).map_err(unknown)?;
        if !matches!(decoded.shape, ResponseShape::Completed { .. }) {
            return Err(refused("original Capture is not completed"));
        }
        let Some(MethodResult::Capture(result)) = decoded.result else {
            return Err(refused("original Capture has no complete native result"));
        };
        if result.owner_state_refs.len() != 1 {
            return Err(refused(
                "original Capture has another Control object population",
            ));
        }
        let references = [
            &result.capture_manifest,
            &result.owner_state_refs[0],
            &result.unchanged_cut_receipt,
        ];
        let mut banks = self
            .capture_banks
            .try_borrow_mut()
            .map_err(|_| refused("original native return banks are busy"))?;
        let banks = banks
            .as_mut()
            .ok_or_else(|| refused("original native return banks are absent"))?;
        if banks.native_objects.iter().any(Option::is_some) {
            return Err(refused("original native objects were already attempted"));
        }
        for (index, reference) in references.into_iter().enumerate() {
            let bytes = realized.controller.content(reference).map_err(unknown)?;
            let object = record_original_bytes(&mut banks.native_banks[index], reference, bytes)?;
            banks.native_objects[index] = Some(object);
        }
        self.authenticate_witness_scope(&realized)
    }

    /// Retains the fourth native body selected by its actual completed Poll.
    ///
    /// The original whole ticket, Capture/fourth-Poll transcript and canonical
    /// ACK windows must all match before the same preallocated bank is copied.
    /// The copy enters Source custody before the final currentness fence.
    ///
    /// # Errors
    /// Refuses another original transcript, an absent/incomplete body or used
    /// bank. Failure retains every partially attempted bank and completed copy.
    pub fn record_original_native_after_object(
        &self,
        scope: &CnpSemanticCaptureScope<'_>,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        runtime: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        confirmation_request: &Id,
        receipt: &crucible_node_transport::reference_packet::service::confirmation::PacketNativeAfterConfirmationReceipt,
    ) -> Result<(), OperationFailure> {
        self.authenticate_original_capture_settlement_transcript(
            scope,
            ticket,
            runtime,
            runtime_object,
            confirmation_request,
            receipt,
        )?;
        let realized = scope.realization()?;
        let bytes = realized
            .controller
            .content(&receipt.native_after_ref)
            .map_err(unknown)?;
        let mut banks = self
            .capture_banks
            .try_borrow_mut()
            .map_err(|_| refused("original native-after return bank is busy"))?;
        let banks = banks
            .as_mut()
            .ok_or_else(|| refused("original native-after return bank is absent"))?;
        if banks.native_after_object.is_some() {
            return Err(refused("original native-after return was already retained"));
        }
        let object = record_original_bytes(
            &mut banks.native_after_bank,
            &receipt.native_after_ref,
            bytes,
        )?;
        banks.native_after_object = Some(object);
        self.authenticate_witness_scope(&realized)
    }

    /// Borrows the original whole snapshot, Control object and unchanged-cut anchor.
    ///
    /// This data view is not a capture seal. All three copies must still match
    /// the same original controller content under current native/source custody.
    ///
    /// # Errors
    /// Refuses foreign custody, incomplete recording, busy banks or changed bytes.
    pub fn original_native_capture_objects(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<Ref<'_, [Option<InputPayload>; 3]>, OperationFailure> {
        self.authenticate_witness_scope(&scope)?;
        let banks = self
            .capture_banks
            .try_borrow()
            .map_err(|_| refused("original native return banks are busy"))?;
        let objects = Ref::filter_map(banks, |banks| Some(&banks.as_ref()?.native_objects))
            .map_err(|_| refused("original native return banks are absent"))?;
        for object in objects.iter() {
            let object = object
                .as_ref()
                .ok_or_else(|| refused("original native object recording is incomplete"))?;
            if scope
                .controller
                .content(&object.reference)
                .map_err(unknown)?
                != object.bytes
            {
                return Err(refused(
                    "original native return copy differs from controller custody",
                ));
            }
        }
        self.authenticate_witness_scope(&scope)?;
        Ok(objects)
    }
}
