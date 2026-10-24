//! Borrows the actual sent query to restrict this receive before typed bodies.
//!
//! There is no retained Connection mode or new raw ceiling. Same literal-bank
//! error custody and supervision apply; the planned report fullref is checked
//! before any Blob DTO or content growth. Generic receive remains unchanged.

use super::*;
use crate::reference_packet::service::fresh_restore_allocation::{self as fresh, *};
use crucible_node_format::{ContentRef, U64};
use serde_json::Value;

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn preflight_original_fresh_query_data(&self) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller {
            return Err(refused());
        }
        self.native5_codec
            .as_ref()
            .ok_or_else(refused)?
            .fresh_restore_controller_selection_data(&self.authority)?;
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)
    }

    pub(crate) fn preflight_original_fresh_query_send(
        &self,
        query: &Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller {
            return Err(refused());
        }
        let selection = self
            .native5_codec
            .as_ref()
            .ok_or_else(refused)?
            .fresh_restore_controller_selection_data(&self.authority)?;
        super::authenticate_original_report_query_header_data(selection, crate::reference_packet::service::report_startup::PacketNativeReportStartupPurpose::FreshCompletedAdmit13, query)?;
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)
    }

    pub(crate) fn receive_original_fresh_query_response(
        &mut self,
        query: &Envelope,
    ) -> Result<ReceivedFrame, ProviderError> {
        self.receive_fresh_inner(query, None)
    }

    pub(crate) fn receive_original_fresh_report_frame(
        &mut self,
        query: &Envelope,
        reference: &ContentRef,
        transfer: Option<&Id>,
        offset: usize,
    ) -> Result<ReceivedFrame, ProviderError> {
        self.receive_fresh_inner(query, Some((reference, transfer, offset)))
    }

    fn receive_fresh_inner(
        &mut self,
        query: &Envelope,
        report: Option<(&ContentRef, Option<&Id>, usize)>,
    ) -> Result<ReceivedFrame, ProviderError> {
        self.authenticate_native5_source_codec()?;
        self.check_authority()?;
        if self.role != EndpointRole::Controller {
            return Err(refused());
        }
        self.native5_codec
            .as_ref()
            .ok_or_else(refused)?
            .fresh_restore_controller_selection_data(&self.authority)?;
        if report.is_none() {
            let mut pending = self.guard.pending_requests();
            if pending.next() != Some(query) || pending.next().is_some() {
                return Err(refused());
            }
        } else {
            self.guard
                .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)?;
        }
        let result = (|| {
            let value = self.reader.read()?.ok_or_else(refused)?;
            let envelope: Envelope =
                serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
            match report {
                None => {
                    query.matches_response(&envelope)?;
                    authenticate_response(&envelope)?;
                }
                Some((reference, transfer, offset)) => authenticate_proof(
                    query,
                    &envelope,
                    reference,
                    transfer,
                    offset,
                    self.authority.limits().blob_chunk_bytes,
                )?,
            }
            let body = self.validate_body(&envelope, true)?;
            self.retain_original_request_id(&envelope, self.reader.original_slot())?;
            self.authority.with_live(|| self.guard.receive(&envelope))?;
            self.authenticate_native5_source_codec()?;
            Ok(ReceivedFrame { envelope, body })
        })();
        if result.is_err() {
            self.contain(ConnectionFailure::Protocol);
        }
        result
    }
}

fn authenticate_response(envelope: &Envelope) -> Result<(), ProviderError> {
    let body = &envelope.body;
    if envelope.message != MessageKind::Response
        || envelope.method != Method::Observe
        || !envelope.extensions.is_empty()
        || body.len() != 4
        || body.get("status").and_then(Value::as_str) != Some("completed")
        || body.get("operation_state").and_then(Value::as_str) != Some("completed")
    {
        return Err(refused());
    }
    let result = body
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    let hash = result
        .get("inventory_hash")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    if result.len() != 4
        || result
            .get("observations")
            .and_then(Value::as_array)
            .is_none_or(|v| !v.is_empty())
        || decimal(result.get("next_sequence"))? != 0
        || result.get("complete").and_then(Value::as_bool) != Some(true)
        || hash.len() != 3
        || hash.get("algorithm").and_then(Value::as_str) != Some("blake3-256")
        || hash.get("domain").and_then(Value::as_str).is_none_or(|v| {
            ![
                "source-owned.packet-inventory.v1",
                "source-owned.packet-connected-inventory/4",
            ]
            .contains(&v)
        })
        || hash
            .get("digest")
            .and_then(Value::as_str)
            .is_none_or(|v| !hex(v))
    {
        return Err(refused());
    }
    let extensions = body
        .get("extensions")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    if extensions.len() != 1 {
        return Err(refused());
    }
    let receipt = extensions
        .get(PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT)
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    if receipt.len() != 2
        || receipt.get("schema").and_then(Value::as_str)
            != Some(PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT)
    {
        return Err(refused());
    }
    fresh::policy::validate_allocation_reference_value(
        receipt.get("allocation").ok_or_else(refused)?,
    )
}

fn authenticate_proof(
    query: &Envelope,
    envelope: &Envelope,
    reference: &ContentRef,
    transfer: Option<&Id>,
    offset: usize,
    maximum_chunk: U64,
) -> Result<(), ProviderError> {
    if envelope.protocol != query.protocol
        || envelope.session_id != query.session_id
        || envelope.incarnation_id != query.incarnation_id
        || envelope.message != MessageKind::Request
        || envelope.request_id.0.is_none()
        || envelope.node_id.0.is_some()
        || envelope.execution_owner_id.0.is_some()
        || envelope.capture_owner_id.0.is_some()
        || envelope.operation_id.0.is_some()
        || !envelope.extensions.is_empty()
        || envelope
            .body
            .get("extensions")
            .and_then(Value::as_object)
            .is_none_or(|v| !v.is_empty())
    {
        return Err(refused());
    }
    let body = &envelope.body;
    let id = body
        .get("transfer_id")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    if id.is_empty() || id.len() > 128 || transfer.is_some_and(|expected| expected.as_str() != id) {
        return Err(refused());
    }
    match (transfer, envelope.method) {
        (None, Method::BlobBegin) if offset == 0 && body.len() == 3 => {
            same_reference(body.get("content").ok_or_else(refused)?, reference)
        }
        (Some(_), Method::BlobChunk)
            if body.len() == 4
                && decimal(body.get("offset"))?
                    == u64::try_from(offset).map_err(|_| refused())? =>
        {
            let bytes = body
                .get("bytes")
                .and_then(Value::as_str)
                .ok_or_else(refused)?;
            let chunk = usize::try_from(maximum_chunk.get())
                .map_err(|_| refused())?
                .min(4096);
            let remaining = usize::try_from(reference.length.get())
                .map_err(|_| refused())?
                .checked_sub(offset)
                .ok_or_else(refused)?;
            let maximum = remaining.min(chunk);
            if maximum == 0
                || bytes.is_empty()
                || bytes.len() > maximum.div_ceil(3).checked_mul(4).ok_or_else(refused)?
                || !bytes
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(refused());
            }
            // Canonical Bytes decoding and exact resulting offset are checked
            // by the unchanged typed body/content receiver before growth.
            Ok(())
        }
        (Some(_), Method::BlobFinish)
            if body.len() == 2
                && u64::try_from(offset).map_err(|_| refused())? == reference.length.get() =>
        {
            Ok(())
        }
        _ => Err(refused()),
    }
}

fn same_reference(value: &Value, reference: &ContentRef) -> Result<(), ProviderError> {
    let object = value.as_object().ok_or_else(refused)?;
    let hash = object
        .get("hash")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    if object.len() != 3
        || hash.len() != 3
        || hash.get("algorithm").and_then(Value::as_str) != Some(reference.hash.algorithm.as_str())
        || hash.get("domain").and_then(Value::as_str) != Some(reference.hash.domain.as_str())
        || hash.get("digest").and_then(Value::as_str) != Some(reference.hash.digest.as_str())
        || decimal(object.get("length"))? != reference.length.get()
        || object.get("media_type").and_then(Value::as_str) != Some(reference.media_type.as_str())
    {
        return Err(refused());
    }
    Ok(())
}

fn decimal(value: Option<&Value>) -> Result<u64, ProviderError> {
    let value = value.and_then(Value::as_str).ok_or_else(refused)?;
    if value.is_empty() || value.len() > 20 || (value.len() > 1 && value.starts_with('0')) {
        return Err(refused());
    }
    value.bytes().try_fold(0u64, |n, b| {
        if !b.is_ascii_digit() {
            return Err(refused());
        }
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(b - b'0')))
            .ok_or_else(refused)
    })
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn refused() -> ProviderError {
    ProviderError::Correlation("fresh report original response or proof header differs")
}

#[cfg(test)]
mod tests {
    //! Exercises only the pretyped data predicates on actual contract bodies.
    // crucible-lint: panic-shortcut: fixture assertions stop on wrong grammar.
    use super::*;
    use crate::{bodies::*, envelope::Nullable};
    use crucible_node_format::{Extensions, canonical};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn object(
        value: impl serde::Serialize,
    ) -> Result<serde_json::Map<String, Value>, ProviderError> {
        let Value::Object(value) =
            serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?
        else {
            return Err(refused());
        };
        Ok(value)
    }

    fn query() -> Result<Envelope, ProviderError> {
        let (_, authority, selection, _) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        Ok(Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(authority.session_id().clone())),
            incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
            node_id: Nullable(Some(
                selection.realization.bindings[0]
                    .compatibility
                    .node_id
                    .clone(),
            )),
            execution_owner_id: Nullable(Some(
                selection.realization.owner_bindings[0].owner.id.clone(),
            )),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: Nullable(Some(Id::new("fresh-query-data-control")?)),
            sequence: U64::new(3),
            method: Method::Observe,
            body: object(ObserveRequest {
                binding_hash: selection.realization.owner_bindings[0].identity()?,
                owner_generation: selection.realization.bindings[0].authority.owner_generation,
                after_observation_sequence: U64::new(0),
                maximum_items: U64::new(1),
                extensions: Extensions::new(),
            })?,
            extensions: Extensions::new(),
        })
    }

    #[test]
    fn closed_response_refuses_request_kind_inventory_and_envelope_receipt() -> TestResult {
        let query = query()?;
        let reference = canonical::content_ref(
            b"inert grammar bytes",
            PACKET_FRESH_RESTORE_ALLOCATION_MEDIA,
        )?;
        let mut body_extensions = Extensions::new();
        body_extensions.insert(
            PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT.into(),
            serde_json::to_value(PacketNativeFreshRestoreAllocationReceipt {
                schema: PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT.into(),
                allocation: reference,
            })?,
        );
        let mut response = query.clone();
        response.message = MessageKind::Response;
        response.body = object(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: object(ObserveResult {
                observations: Vec::new(),
                next_sequence: U64::new(0),
                complete: true,
                inventory_hash: canonical::hash(
                    "source-owned.packet-inventory.v1",
                    b"inert grammar inventory",
                )?,
            })?,
            extensions: body_extensions.clone(),
        })?;
        query.matches_response(&response)?;
        authenticate_response(&response)?;

        let mut changed = response.clone();
        changed.message = MessageKind::Request;
        assert!(authenticate_response(&changed).is_err());
        changed = response.clone();
        changed
            .body
            .get_mut("result")
            .and_then(Value::as_object_mut)
            .ok_or_else(refused)?
            .insert("observations".into(), serde_json::json!([0]));
        assert!(authenticate_response(&changed).is_err());
        changed = response;
        changed.extensions = body_extensions;
        changed
            .body
            .insert("extensions".into(), serde_json::json!({}));
        assert!(authenticate_response(&changed).is_err());
        Ok(())
    }

    #[test]
    fn closed_report_proof_refuses_other_reference_offset_and_control_scope() -> TestResult {
        let query = query()?;
        let reference = canonical::content_ref(b"report", PACKET_FRESH_RESTORE_ALLOCATION_MEDIA)?;
        let transfer = Id::new("packet-transfer-4")?;
        let mut proof = query.clone();
        proof.node_id = Nullable(None);
        proof.execution_owner_id = Nullable(None);
        proof.request_id = Nullable(Some(Id::new("packet-proof-4")?));
        proof.method = Method::BlobBegin;
        proof.body = object(BlobBeginRequest {
            transfer_id: transfer.clone(),
            content: reference.clone(),
            extensions: Extensions::new(),
        })?;
        authenticate_proof(&query, &proof, &reference, None, 0, U64::new(4096))?;

        let other = canonical::content_ref(b"changed", PACKET_FRESH_RESTORE_ALLOCATION_MEDIA)?;
        assert!(authenticate_proof(&query, &proof, &other, None, 0, U64::new(4096)).is_err());
        proof.method = Method::BlobChunk;
        proof.body = object(BlobChunkRequest {
            transfer_id: transfer.clone(),
            offset: U64::new(1),
            bytes: crucible_node_format::Bytes::new(b"report".to_vec()),
            extensions: Extensions::new(),
        })?;
        assert!(
            authenticate_proof(
                &query,
                &proof,
                &reference,
                Some(&transfer),
                0,
                U64::new(4096)
            )
            .is_err()
        );
        proof
            .body
            .insert("offset".into(), serde_json::to_value(U64::new(0))?);
        authenticate_proof(
            &query,
            &proof,
            &reference,
            Some(&transfer),
            0,
            U64::new(4096),
        )?;
        proof.operation_id = Nullable(Some(Id::new("unrelated-control")?));
        assert!(
            authenticate_proof(
                &query,
                &proof,
                &reference,
                Some(&transfer),
                0,
                U64::new(4096)
            )
            .is_err()
        );
        Ok(())
    }
}
