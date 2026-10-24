//! Restricts the selected initial host replies before constructing method DTOs.
//!
//! Each receive borrows the same actual pending initial request. Literal framing,
//! negotiated raw limits, correlation, schema validation and containment remain
//! the ordinary Connection owners. These predicates grant no Source authority.

use super::*;
use crate::reference_packet::control::PacketControlSelection;
use crate::reference_packet::service::native_startup::data_equality;
use crucible_node_format::{ContentRef, U64};
use serde_json::{Map, Value};

pub(crate) const INITIAL_PROOF_BYTES: usize = 65_536;

// Keeps the current transfer position separate from the completed-object count.
type InitialProofPosition<'a> = (Option<&'a (Id, ContentRef, usize)>, usize);

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn original_host_initial_selection_data(
        &self,
    ) -> Result<&PacketControlSelection, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller {
            return Err(refused());
        }
        self.native5_codec
            .as_ref()
            .ok_or_else(refused)?
            .original_host_initial_selection_data(&self.authority)
    }

    pub(crate) fn receive_original_host_initial_into(
        &mut self,
        original: &Envelope,
        completed: &mut Option<ReceivedFrame>,
    ) -> Result<(), ProviderError> {
        self.receive_original_host_initial_inner(original, None, completed)
    }

    pub(crate) fn receive_original_host_initial_proof_into(
        &mut self,
        original: &Envelope,
        cursor: Option<&(Id, ContentRef, usize)>,
        objects: usize,
        completed: &mut Option<ReceivedFrame>,
    ) -> Result<(), ProviderError> {
        self.receive_original_host_initial_inner(original, Some((cursor, objects)), completed)
    }

    fn receive_original_host_initial_inner(
        &mut self,
        original: &Envelope,
        proof: Option<InitialProofPosition<'_>>,
        completed: &mut Option<ReceivedFrame>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() {
            return Err(refused());
        }
        self.check_authority()?;
        self.original_host_initial_selection_data()?;
        if !matches!(
            original.method,
            Method::Discover | Method::Realize | Method::Admit
        ) {
            return Err(refused());
        }
        if proof.is_some() {
            if original.method != Method::Realize {
                return Err(refused());
            }
            self.guard
                .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)?;
        } else {
            let mut pending = self.guard.pending_requests();
            if pending.next() != Some(original) || pending.next().is_some() {
                return Err(refused());
            }
        }
        let result = (|| {
            let value = self.reader.read()?.ok_or_else(refused)?;
            let envelope: Envelope =
                serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
            let selection = self.original_host_initial_selection_data()?;
            if let Some((cursor, objects)) = proof {
                authenticate_proof(
                    &envelope,
                    self.authority.limits().blob_chunk_bytes,
                    cursor,
                    objects,
                )?;
            } else {
                original.matches_response(&envelope)?;
                authenticate_response(selection, original, &envelope)?;
            }
            let body = self.validate_body(&envelope, true)?;
            // The complete typed owner precedes all post-decode state checks.
            // The caller retains this slot outside its fallible source boundary.
            *completed = Some(ReceivedFrame { envelope, body });
            let envelope = &completed.as_ref().ok_or_else(refused)?.envelope;
            self.retain_original_request_id(envelope, self.reader.original_slot())?;
            self.authority.with_live(|| self.guard.receive(envelope))?;
            self.original_host_initial_selection_data()?;
            Ok(())
        })();
        if result.is_err() {
            self.contain(ConnectionFailure::Protocol);
        }
        result
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn receive_original_host_initial_admit_into(
        &mut self,
        original: &Envelope,
        retained: &mut Option<Envelope>,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), ProviderError> {
        if retained.is_some() || completed.is_some() || original.method != Method::Admit {
            return Err(refused());
        }
        self.check_authority()?;
        self.original_host_initial_selection_data()?;
        let mut pending = self.guard.pending_requests();
        if pending.next() != Some(original) || pending.next().is_some() {
            return Err(refused());
        }
        drop(pending);
        let result = (|| {
            let value = self.reader.read()?.ok_or_else(refused)?;
            let envelope: Envelope =
                serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
            original.matches_response(&envelope)?;
            authenticate_response(
                self.original_host_initial_selection_data()?,
                original,
                &envelope,
            )?;
            let body = self.validate_body(&envelope, true)?;
            // The preceding exact Response header selects validate_body's
            // Response arm. No public callback can substitute another family.
            let ReceivedBody::Response(body) = body else {
                return Err(refused());
            };
            *retained = Some(envelope);
            *completed = Some(*body);
            // Both owning outputs now survive every check and containment.
            let envelope = retained.as_ref().ok_or_else(refused)?;
            self.retain_original_request_id(envelope, self.reader.original_slot())?;
            self.authority.with_live(|| self.guard.receive(envelope))?;
            self.original_host_initial_selection_data()?;
            Ok(())
        })();
        if result.is_err() {
            self.contain(ConnectionFailure::Protocol);
        }
        result
    }
}

fn authenticate_response(
    selection: &PacketControlSelection,
    original: &Envelope,
    envelope: &Envelope,
) -> Result<(), ProviderError> {
    if envelope.message != MessageKind::Response
        || envelope.method != original.method
        || !envelope.extensions.is_empty()
        || envelope.body.len() != 4
        || envelope.body.get("status").and_then(Value::as_str) != Some("completed")
        || envelope.body.get("operation_state").and_then(Value::as_str) != Some("completed")
        || !empty_object(envelope.body.get("extensions"))
    {
        return Err(refused());
    }
    let result = envelope
        .body
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    match original.method {
        Method::Discover => {
            exact_fields(
                result,
                &[
                    "provider_manifest",
                    "profiles",
                    "facet_schemas",
                    "complete",
                    "next_cursor",
                ],
            )?;
            if !data_equality::matches(
                result.get("provider_manifest").ok_or_else(refused)?,
                &selection.provider,
            ) || !data_equality::matches(
                result.get("profiles").ok_or_else(refused)?,
                &selection.provider.supported_profiles,
            ) || !data_equality::matches(
                result.get("facet_schemas").ok_or_else(refused)?,
                &selection.provider.implementation.formats,
            ) || result.get("complete").and_then(Value::as_bool) != Some(true)
                || !result.get("next_cursor").is_some_and(Value::is_null)
            {
                return Err(refused());
            }
        }
        Method::Realize => {
            exact_fields(
                result,
                &[
                    "realization_manifest",
                    "prepared_token",
                    "closed_gate_receipt",
                ],
            )?;
            if !data_equality::matches(
                result.get("realization_manifest").ok_or_else(refused)?,
                &selection.realization,
            ) || result.get("prepared_token").and_then(Value::as_str)
                != Some(selection.prepared_token.as_str())
            {
                return Err(refused());
            }
            reference(result.get("closed_gate_receipt").ok_or_else(refused)?)?;
        }
        Method::Admit => {
            exact_fields(result, &["accepted_binding_hashes", "admission_id"])?;
            if result.get("admission_id").and_then(Value::as_str)
                != Some(selection.admission.as_str())
            {
                return Err(refused());
            }
            let hashes = result
                .get("accepted_binding_hashes")
                .and_then(Value::as_array)
                .filter(|values| values.len() == 1)
                .ok_or_else(refused)?;
            hash(&hashes[0], "cnp.node-binding.v1")?;
            // The private Source still compares the complete actual binding
            // identity. Syntax and equal labels do not activate native Admit.
        }
        _ => return Err(refused()),
    }
    Ok(())
}

fn authenticate_proof(
    envelope: &Envelope,
    maximum_chunk: U64,
    cursor: Option<&(Id, ContentRef, usize)>,
    objects: usize,
) -> Result<(), ProviderError> {
    if envelope.message != MessageKind::Request
        || envelope.node_id.0.is_some()
        || envelope.execution_owner_id.0.is_some()
        || envelope.capture_owner_id.0.is_some()
        || envelope.operation_id.0.is_some()
        || !envelope.extensions.is_empty()
    {
        return Err(refused());
    }
    let body = &envelope.body;
    if !empty_object(body.get("extensions")) {
        return Err(refused());
    }
    let transfer = body
        .get("transfer_id")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    if transfer.is_empty() || transfer.len() > 128 {
        return Err(refused());
    }
    match envelope.method {
        Method::BlobBegin => {
            if cursor.is_some() || objects >= 2 {
                return Err(refused());
            }
            exact_fields(body, &["transfer_id", "content", "extensions"])?;
            reference(body.get("content").ok_or_else(refused)?)?;
        }
        Method::BlobChunk => {
            exact_fields(body, &["transfer_id", "offset", "bytes", "extensions"])?;
            let (expected_transfer, reference, offset) = cursor.ok_or_else(refused)?;
            let length = usize::try_from(reference.length.get()).map_err(|_| refused())?;
            if transfer != expected_transfer.as_str()
                || decimal(body.get("offset"))? != *offset
                || *offset >= length
            {
                return Err(refused());
            }
            let encoded = body
                .get("bytes")
                .and_then(Value::as_str)
                .ok_or_else(refused)?;
            let maximum = usize::try_from(maximum_chunk.get())
                .map_err(|_| refused())?
                .min(4096);
            let expected = maximum.min(length.checked_sub(*offset).ok_or_else(refused)?);
            let encoded_length = expected
                .checked_mul(4)
                .and_then(|n| n.checked_add(2))
                .ok_or_else(refused)?
                / 3;
            if expected == 0
                || encoded.len() != encoded_length
                || !encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(refused());
            }
        }
        Method::BlobFinish => {
            let (expected_transfer, reference, offset) = cursor.ok_or_else(refused)?;
            if transfer != expected_transfer.as_str()
                || u64::try_from(*offset).map_err(|_| refused())? != reference.length.get()
            {
                return Err(refused());
            }
            exact_fields(body, &["transfer_id", "extensions"])?;
        }
        _ => return Err(refused()),
    }
    Ok(())
}

fn reference(value: &Value) -> Result<(), ProviderError> {
    let object = value.as_object().ok_or_else(refused)?;
    exact_fields(object, &["hash", "length", "media_type"])?;
    hash(object.get("hash").ok_or_else(refused)?, "cnp.blob.v1")?;
    if decimal(object.get("length"))? > INITIAL_PROOF_BYTES
        || object.get("media_type").and_then(Value::as_str) != Some("application/json")
    {
        return Err(refused());
    }
    Ok(())
}

fn hash(value: &Value, domain: &str) -> Result<(), ProviderError> {
    let object = value.as_object().ok_or_else(refused)?;
    exact_fields(object, &["algorithm", "domain", "digest"])?;
    let digest = object
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    if object.get("algorithm").and_then(Value::as_str) != Some("blake3-256")
        || object.get("domain").and_then(Value::as_str) != Some(domain)
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refused());
    }
    Ok(())
}

fn decimal(value: Option<&Value>) -> Result<usize, ProviderError> {
    let text = value.and_then(Value::as_str).ok_or_else(refused)?;
    if text.is_empty()
        || text.len() > 20
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(refused());
    }
    text.parse().map_err(|_| refused())
}

fn exact_fields(object: &Map<String, Value>, fields: &[&str]) -> Result<(), ProviderError> {
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(refused());
    }
    Ok(())
}

fn empty_object(value: Option<&Value>) -> bool {
    value.and_then(Value::as_object).is_some_and(Map::is_empty)
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original initial host response or proof differs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bodies::BlobChunkRequest;
    use crate::envelope::Nullable;
    use crucible_node_format::Extensions;

    #[test]
    fn actual_typed_proof_chunk_matches_current_transfer_and_exact_remaining_extent() {
        let (_handshake, authority, _selection, _coordinator) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let transfer = Id::new("initial-proof-transfer").unwrap();
        let payload = vec![1_u8, 2, 3];
        let reference =
            crucible_node_format::canonical::content_ref(&payload, "application/json").unwrap();
        let request = BlobChunkRequest {
            transfer_id: transfer.clone(),
            offset: U64::new(0),
            bytes: crucible_node_format::Bytes::new(payload.clone()),
            extensions: Extensions::new(),
        };
        let mut envelope = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(authority.session_id().clone())),
            incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(Id::new("initial-proof-request").unwrap())),
            operation_id: Nullable(None),
            sequence: U64::new(2),
            method: Method::BlobChunk,
            body: serde_json::to_value(&request)
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
            extensions: Extensions::new(),
        };
        let cursor = (transfer.clone(), reference.clone(), 0);
        authenticate_proof(&envelope, U64::new(4096), Some(&cursor), 1).unwrap();

        let wrong = (Id::new("other-transfer").unwrap(), reference.clone(), 0);
        assert!(authenticate_proof(&envelope, U64::new(4096), Some(&wrong), 1).is_err());
        let short_remaining = (transfer, reference, 1);
        assert!(authenticate_proof(&envelope, U64::new(4096), Some(&short_remaining), 1).is_err());
        envelope
            .body
            .insert("bytes".into(), Value::String("AQIDBA".into()));
        assert!(authenticate_proof(&envelope, U64::new(4096), Some(&cursor), 1).is_err());
        assert!(authenticate_proof(&envelope, U64::new(4096), None, 0).is_err());
    }
}
