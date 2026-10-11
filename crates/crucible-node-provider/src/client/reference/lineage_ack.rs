//! Borrows original public close and semantic consumption after native closure.

use super::*;
use crate::reference_service::PublicationConsumption;

/// Borrows exact cached public close and consumption controls for one original window.
///
/// This read grants no ACK, reclamation or source qualification authority. The
/// owning controller retains both original commands and complete receipt bytes.
pub struct OriginalLineageAcknowledgement<'a> {
    close: &'a ClientOriginal,
    retirement: &'a ClientOriginal,
    custody: ContentRef,
    committed: ObservationBatch,
}

impl OriginalLineageAcknowledgement<'_> {
    /// Returns the original public QuantumClose and its received terminal response.
    pub fn close(&self) -> &ClientOriginal {
        self.close
    }

    /// Returns the original semantic Retire and its received terminal response.
    pub fn retirement(&self) -> &ClientOriginal {
        self.retirement
    }

    /// Returns the unchanged original semantic custody receipt reference.
    pub fn custody_reference(&self) -> &ContentRef {
        &self.custody
    }

    /// Returns the original committed observation with unchanged publication events.
    pub fn committed_observation(&self) -> &ObservationBatch {
        &self.committed
    }
}

impl<'a> OriginalLineageWindow<'a> {
    /// Borrows the actual cached close and semantic consumption of this original window.
    ///
    /// The caller supplies lookup IDs, never replacement receipt bodies or an
    /// asserted native ACK. The source adopter still authenticates installed
    /// native implementation and its original owner scope independently.
    ///
    /// # Errors
    /// Refuses missing or uncertain originals, altered grants, events, stop
    /// scope, uncommitted publication, different consumption inventory, or
    /// absent original complete custody receipt bytes.
    pub fn acknowledged_publication(
        &self,
        close: &Id,
        retirement: &Id,
    ) -> Result<OriginalLineageAcknowledgement<'a>, ProviderError> {
        let source = self.controller;
        let (close_original, result) = completed(source, close, Method::QuantumClose)?;
        let Some(MethodResult::QuantumClose(closed)) = result.result else {
            return Err(invalid());
        };
        let RequestBody::QuantumClose(request) =
            decode_request(Method::QuantumClose, &close_original.request.body)?
        else {
            return Err(invalid());
        };
        if request.grant_id != self.native.grant.window_id
            || request.quantum_index != self.native.grant.quantum
            || request.observation_batch_hash != self.observation.identity()?
            || request.input_watermark != self.input.batch_sequence
            || request.cut != self.stop.reached.ok_or_else(invalid)?
            || closed.stop_receipt != self.stop_reference()?
            || closed.grant_id != request.grant_id
            || closed.quantum_index != request.quantum_index
            || closed.cut != request.cut
            || closed.owner_generation != self.stop.owner_generation
            || closed.activation_id != self.stop.activation_id
            || closed.world_generation != self.stop.world_generation
            || closed.input_epoch != self.input.input_epoch
        {
            return Err(invalid());
        }
        let committed: ObservationBatch = validated(source, &closed.committed_batch)?;
        let mut expected = self.observation.clone();
        expected.visibility = Visibility::Committed;
        if committed != expected {
            return Err(invalid());
        }

        let (retirement_original, result) = completed(source, retirement, Method::Retire)?;
        let Some(MethodResult::Retire(retired)) = result.result else {
            return Err(invalid());
        };
        let RequestBody::Retire(request) =
            decode_request(Method::Retire, &retirement_original.request.body)?
        else {
            return Err(invalid());
        };
        let begin = self.originals[2];
        let operation = begin.request.operation_id.0.as_ref().ok_or_else(invalid)?;
        let begin_id = begin.request.request_id.0.as_ref().ok_or_else(invalid)?;
        if request.disposition != RetirementDisposition::Consumed
            || request.operation_ids != [operation.clone()]
            || request.request_ids != [begin_id.clone()]
            || retired.retired_operation_ids != request.operation_ids
            || retired.retired_request_ids != request.request_ids
        {
            return Err(invalid());
        }
        let custody = request.custody_receipt.0.ok_or_else(invalid)?;
        let receipt: PublicationConsumption = validated(source, &custody)?;
        if receipt.session_id != source.bootstrap.authority.session_id
            || receipt.incarnation_id != source.bootstrap.authority.incarnation_id
            || receipt.operation_id != *operation
            || receipt.grant_id != self.native.grant.window_id
            || receipt.world_binding_hash != self.stop.world_binding_hash
            || receipt.observation_batch_hash != self.observation.identity()?
            || receipt.stop_receipt != self.stop_reference()?
            || receipt.publication != self.native.grant.publication
        {
            return Err(invalid());
        }
        Ok(OriginalLineageAcknowledgement {
            close: close_original,
            retirement: retirement_original,
            custody,
            committed,
        })
    }

    fn stop_reference(&self) -> Result<ContentRef, ProviderError> {
        let original = self.originals[2];
        let response = original.response.as_ref().ok_or_else(invalid)?;
        let result = decode_response(
            &decode_request(Method::Begin, &original.request.body)?,
            &response.body,
        )?;
        let Some(MethodResult::QuantumBegin(result)) = result.result else {
            return Err(invalid());
        };
        Ok(result.stop_receipt)
    }
}
