//! Complete provider-origin content custody and bidirectional transport replies.

use crucible_node_contract::{Bytes, ContentRef, Id, U64, Validate, canonical};
use serde_json::{Value, json};

use crate::ProviderError;
use crate::bodies::{self, RequestBody};
use crate::envelope::{Envelope, MessageKind, Method, RequestOrigin};

use super::{CheckResult, Runner};

impl Runner<'_> {
    pub(super) fn receive_blob(
        &mut self,
        expected: ContentRef,
        maximum_chunks: usize,
        reference_binding: &Id,
        bytes_binding: &Id,
        result: &mut CheckResult,
    ) -> Result<(), ProviderError> {
        expected.validate()?;
        if expected.length.get() > super::super::MAX_PLAN_BYTES as u64 {
            return Err(ProviderError::ResourceExhausted(
                "incoming probe content bytes",
            ));
        }
        let original = self.incoming_request()?;
        let RequestBody::BlobBegin(begin) =
            bodies::decode_request(original.method, &original.body)?
        else {
            return Err(ProviderError::Correlation(
                "expected original provider blob begin",
            ));
        };
        if begin.content != expected {
            return Err(ProviderError::Correlation(
                "provider changed promised content identity",
            ));
        }
        result.request_identity = Some(original.request_hash(RequestOrigin::Provider)?);
        self.complete_provider_request(
            &original,
            json!({
                "transfer_id":begin.transfer_id,"next_offset":"0",
                "maximum_chunk_bytes":self.limits.blob_chunk_bytes
            }),
        )?;

        let mut bytes = Vec::new();
        for _ in 0..maximum_chunks {
            if bytes.len() as u64 == expected.length.get() {
                break;
            }
            let request = self.incoming_request()?;
            check_transfer_scope(&original, &request)?;
            let RequestBody::BlobChunk(chunk) =
                bodies::decode_request(request.method, &request.body)?
            else {
                return Err(ProviderError::Correlation(
                    "provider blob chunk sequence interrupted",
                ));
            };
            let next = bytes
                .len()
                .checked_add(chunk.bytes.as_slice().len())
                .ok_or(ProviderError::ResourceExhausted(
                    "incoming content offset overflow",
                ))?;
            if chunk.transfer_id != begin.transfer_id
                || chunk.offset.get() != bytes.len() as u64
                || chunk.bytes.as_slice().len() as u64 > self.limits.blob_chunk_bytes.get()
                || next as u64 > expected.length.get()
            {
                return Err(ProviderError::Correlation(
                    "provider changed contiguous blob custody",
                ));
            }
            bytes.extend_from_slice(chunk.bytes.as_slice());
            self.complete_provider_request(
                &request,
                json!({
                    "transfer_id":begin.transfer_id,"next_offset":U64::new(next as u64)
                }),
            )?;
        }
        if bytes.len() as u64 != expected.length.get() {
            return Err(ProviderError::ResourceExhausted(
                "incoming probe chunk allowance",
            ));
        }

        let request = self.incoming_request()?;
        check_transfer_scope(&original, &request)?;
        let RequestBody::BlobFinish(finish) =
            bodies::decode_request(request.method, &request.body)?
        else {
            return Err(ProviderError::Correlation(
                "provider blob lacks original finish",
            ));
        };
        if finish.transfer_id != begin.transfer_id {
            return Err(ProviderError::Correlation(
                "provider changed original transfer identity",
            ));
        }
        expected.verify(&bytes)?;
        self.retain_binding(
            reference_binding.as_str(),
            serde_json::to_value(&expected).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        self.retain_binding(
            bytes_binding.as_str(),
            serde_json::to_value(Bytes::new(bytes))
                .map_err(crucible_node_contract::ContractError::from)?,
        )?;

        // Positive finish acknowledges complete probe content custody only. A
        // provider's native publication remains unresolved until its separate
        // authenticated consumption operation is actually accepted.
        let reply = self.complete_provider_request(
            &request,
            json!({
                "transfer_id":begin.transfer_id,"content":expected
            }),
        )?;
        result.response_identity = Some(canonical::json_hash("cnp.conformance-reply.v1", &reply)?);
        Ok(())
    }

    fn incoming_request(&mut self) -> Result<Envelope, ProviderError> {
        let limits = self.limits;
        let value = self
            .connected()?
            .receive(limits)?
            .ok_or(ProviderError::Correlation(
                "provider disconnected before content custody",
            ))?;
        let request = super::decode_envelope(&value)?;
        if request.message != MessageKind::Request
            || !matches!(
                request.method,
                Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
            )
        {
            return Err(ProviderError::Correlation(
                "unexpected provider-origin content frame",
            ));
        }
        self.guard
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "provider content preceded hello",
            ))?
            .receive(&request)?;
        Ok(request)
    }

    fn complete_provider_request(
        &mut self,
        original: &Envelope,
        result: Value,
    ) -> Result<Value, ProviderError> {
        let mut reply = original.clone();
        reply.message = MessageKind::Response;
        reply.sequence = U64::new(self.outgoing_sequence);
        reply.body = json!({
            "status":"completed","operation_state":"completed","result":result,"extensions":{}
        })
        .as_object()
        .cloned()
        .ok_or(ProviderError::Frame(
            "provider response construction failed",
        ))?;
        let request_body = bodies::decode_request(original.method, &original.body)?;
        bodies::decode_response(&request_body, &reply.body)?;
        self.guard
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "provider response preceded hello",
            ))?
            .register_outgoing(reply.clone())?;
        self.outgoing_sequence = self
            .outgoing_sequence
            .checked_add(1)
            .ok_or(ProviderError::ResourceExhausted("probe outgoing sequence"))?;
        let value =
            serde_json::to_value(&reply).map_err(crucible_node_contract::ContractError::from)?;
        let limits = self.limits;
        self.connected()?.send(&value, limits)?;
        self.guard
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "provider response lost original stream",
            ))?
            .confirm_response_sent(&reply)?;
        Ok(value)
    }
}

fn check_transfer_scope(original: &Envelope, next: &Envelope) -> Result<(), ProviderError> {
    if original.node_id != next.node_id
        || original.execution_owner_id != next.execution_owner_id
        || original.capture_owner_id != next.capture_owner_id
        || original.operation_id != next.operation_id
    {
        return Err(ProviderError::Correlation(
            "provider changed original blob scope",
        ));
    }
    Ok(())
}
