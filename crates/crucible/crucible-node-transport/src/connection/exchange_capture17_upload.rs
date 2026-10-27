//! Reconciles the closed zero-evidence Capture17 upload reply family.
//!
//! These checks bind transport correspondence only. The defining native scope
//! supplies the actual Source MAC, same Boot/index/Rc, once debit and real Blob
//! result. A selected header or successful row never grants an upload or model
//! effect. No output, evidence object or ACK receive is created by this family.

use super::*;
use crate::reference_packet::service::complete_restore::settled_recapture::authenticate_restored_settled_capture_selection_data;
use crate::reference_packet::service::restored_settled_capture::upload::RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE;

pub(super) fn authenticate_original_data<S: ProviderStream>(
    connection: &Connection<S>,
    original: &Envelope,
) -> Result<(), ProviderError> {
    connection.protocol_owner.ensure_current()?;
    connection.authenticate_native5_source_codec()?;
    let installed = connection.original_native_owned11_admission()?;
    let selection = installed
        .policy
        .original_restoration_activation_selection_data();
    authenticate_restored_settled_capture_selection_data(selection, &connection.authority)?;
    let [binding] = selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    if original.protocol != "CNP/1"
        || original.message != MessageKind::Request
        || !matches!(
            original.method,
            Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
        )
        || original.sequence.get() == 0
        || original.request_id.0.is_none()
        || original.operation_id.0.is_some()
        || original.execution_owner_id.0.is_some()
        || original.session_id.0.as_ref() != Some(&binding.authority.session_id)
        || original.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
        || original.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
        || original.capture_owner_id.0.as_ref() != Some(&binding.compatibility.capture_owner.id)
        || original.extensions.len() != 1
        || !original
            .extensions
            .contains_key(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE)
    {
        return Err(refused());
    }
    installed.authenticate_current(connection)
}

pub(super) fn authenticate_actual_inputs_data<S: ProviderStream>(
    connection: &Connection<S>,
    original: &Envelope,
    body: &Map<String, Value>,
    evidence: &[(ContentRef, Vec<u8>)],
) -> Result<(), ProviderError> {
    authenticate_original_data(connection, original)?;
    if !evidence.is_empty() {
        return Err(refused());
    }
    authenticate_response_data(
        original,
        body,
        connection
            .authority
            .limits()
            .blob_chunk_bytes
            .get()
            .min(4096),
    )?;
    authenticate_original_data(connection, original)
}

fn object<'a>(
    parent: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Map<String, Value>, ProviderError> {
    parent
        .get(name)
        .and_then(Value::as_object)
        .ok_or_else(refused)
}

fn text<'a>(parent: &'a Map<String, Value>, name: &str) -> Result<&'a str, ProviderError> {
    parent.get(name).and_then(Value::as_str).ok_or_else(refused)
}

fn closed(parent: &Map<String, Value>, fields: &[&str]) -> Result<(), ProviderError> {
    if parent.len() != fields.len() || fields.iter().any(|name| !parent.contains_key(*name)) {
        return Err(refused());
    }
    Ok(())
}

fn quantity(parent: &Map<String, Value>, name: &str) -> Result<u64, ProviderError> {
    let value = text(parent, name)?;
    if value.is_empty()
        || value.len() > 20
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(refused());
    }
    value.parse().map_err(|_| refused())
}

// Source's actual typed Chunk has already passed Bytes decoding. Rechecking its
// canonical spelling and decoded extent here avoids a second owned decode just
// to compare the completed offset with this exact retained original.
fn chunk_length_data(encoded: &str) -> Result<u64, ProviderError> {
    let sextet = |byte| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    };
    if encoded.is_empty() || encoded.bytes().any(|byte| sextet(byte).is_none()) {
        return Err(refused());
    }
    let last = encoded
        .as_bytes()
        .last()
        .copied()
        .and_then(sextet)
        .ok_or_else(refused)?;
    let tail = match encoded.len() % 4 {
        0 => 0,
        2 if last & 15 == 0 => 1,
        3 if last & 3 == 0 => 2,
        _ => return Err(refused()),
    };
    let length = (encoded.len() / 4)
        .checked_mul(3)
        .and_then(|length| length.checked_add(tail))
        .ok_or_else(credit)?;
    u64::try_from(length).map_err(|_| credit())
}

fn reference_data(value: &Map<String, Value>) -> Result<(), ProviderError> {
    closed(value, &["hash", "length", "media_type"])?;
    let hash = object(value, "hash")?;
    closed(hash, &["algorithm", "domain", "digest"])?;
    let digest = text(hash, "digest")?;
    let media = text(value, "media_type")?;
    if text(hash, "algorithm")? != "blake3-256"
        || text(hash, "domain")? != "cnp.blob.v1"
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || media.is_empty()
        || media.len() > 128
        || !media.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(refused());
    }
    quantity(value, "length")?;
    Ok(())
}

fn authenticate_response_data(
    original: &Envelope,
    body: &Map<String, Value>,
    maximum_chunk: u64,
) -> Result<(), ProviderError> {
    closed(body, &["status", "operation_state", "result", "extensions"])?;
    if text(body, "status")? != "completed"
        || text(body, "operation_state")? != "completed"
        || !object(body, "extensions")?.is_empty()
        || maximum_chunk == 0
    {
        return Err(refused());
    }
    let result = object(body, "result")?;
    let request = &original.body;
    if text(result, "transfer_id")? != text(request, "transfer_id")?
        || !object(request, "extensions")?.is_empty()
    {
        return Err(refused());
    }
    match original.method {
        Method::BlobBegin => {
            closed(request, &["transfer_id", "content", "extensions"])?;
            closed(
                result,
                &["transfer_id", "next_offset", "maximum_chunk_bytes"],
            )?;
            let content = object(request, "content")?;
            reference_data(content)?;
            if quantity(result, "next_offset")? > quantity(content, "length")?
                || quantity(result, "maximum_chunk_bytes")? != maximum_chunk
            {
                return Err(refused());
            }
        }
        Method::BlobChunk => {
            closed(request, &["transfer_id", "offset", "bytes", "extensions"])?;
            closed(result, &["transfer_id", "next_offset"])?;
            let length = chunk_length_data(text(request, "bytes")?)?;
            let end = quantity(request, "offset")?
                .checked_add(length)
                .ok_or_else(credit)?;
            // An exact primitive retry can report a later contiguous prefix.
            // The actual result owner independently checks the complete current
            // receiver state and its real native execution provenance.
            if length > maximum_chunk || quantity(result, "next_offset")? < end {
                return Err(refused());
            }
        }
        Method::BlobFinish => {
            closed(request, &["transfer_id", "extensions"])?;
            closed(result, &["transfer_id", "content"])?;
            reference_data(object(result, "content")?)?;
        }
        _ => return Err(refused()),
    }
    Ok(())
}

impl<S: ProviderStream> Connection<S> {
    /// Quotes one actual zero-evidence reply from the distinct Capture upload class.
    ///
    /// # Errors
    /// Refuses foreign selection/current ownership, changed reply correspondence,
    /// any evidence object, a wrong actual cut or an independent finite ceiling.
    pub(crate) fn quote_original_capture17_upload_prefix_storage_data(
        &self,
        first: u64,
        original: &Envelope,
        body: &Map<String, Value>,
        evidence: &[(ContentRef, Vec<u8>)],
        maximum: usize,
    ) -> Result<OriginalPacketPrefixStorageData, ProviderError> {
        authenticate_actual_inputs_data(self, original, body, evidence)?;
        let mut storage = self.quote_original_packet_prefix_accounting_data(
            first, original, body, evidence, maximum, false,
        )?;
        storage.declared_quote_scratch_bytes =
            add(storage.declared_quote_scratch_bytes, counter_scratch_data())?;
        if storage.frames != 1
            || storage.requests != 0
            || storage.one_open_ack_requested_bytes != 0
            || storage.requested_bytes()? > maximum
        {
            return Err(credit());
        }
        authenticate_original_data(self, original)?;
        Ok(storage)
    }

    /// Rechecks this exact selected reply before ordinary plan construction.
    ///
    /// # Errors
    /// Refuses changed same-owner fields, class or any independently priced term.
    pub(crate) fn authenticate_requoted_original_capture17_upload_prefix_storage_data(
        &self,
        first: u64,
        original: &Envelope,
        body: &Map<String, Value>,
        evidence: &[(ContentRef, Vec<u8>)],
        expected: &OriginalPacketPrefixStorageData,
    ) -> Result<(), ProviderError> {
        let actual = self.quote_original_capture17_upload_prefix_storage_data(
            first,
            original,
            body,
            evidence,
            expected.requested_bytes()?,
        )?;
        if actual != *expected {
            return Err(refused());
        }
        Ok(())
    }
}

impl<S: ProviderStream> Connection<S> {
    /// Checks completed upload-body correspondence without granting an effect.
    ///
    /// # Errors
    /// Refuses another selected header or malformed/mismatched normal reply.
    pub(crate) fn authenticate_capture17_upload_completed_body_data(
        &self,
        original: &Envelope,
        body: &Map<String, Value>,
    ) -> Result<(), ProviderError> {
        authenticate_original_data(self, original)?;
        authenticate_response_data(
            original,
            body,
            self.authority.limits().blob_chunk_bytes.get().min(4096),
        )?;
        authenticate_original_data(self, original)
    }

    /// Checks the actual installed receiver rather than matching scope labels.
    ///
    /// # Errors
    /// Refuses foreign/revoked Connection ownership, an absent original Blob
    /// root or another actual ledger. The defining receiver quote separately
    /// checks its private session/incarnation against the signed original key.
    pub(crate) fn authenticate_native_capture17_upload_receiver_data(
        &self,
        receiver: &crate::blob::BlobReceiver,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.original_native_owned11_admission()?
            .authenticate_current(self)?;
        if self.role != EndpointRole::Provider
            || self
                .native5_blobs
                .as_ref()
                .is_none_or(|owner| !receiver.same_protocol_owner(owner))
        {
            return Err(refused());
        }
        self.protocol_owner.ensure_current()
    }

    /// Derives the existing finite upload grid under this actual selected peer.
    ///
    /// Source proof, actual seed custody and native resource/once admission are
    /// independent. The fixed 256 is the unchanged format ceiling; the actual
    /// native reservation separately accounts every original without renewal.
    ///
    /// # Errors
    /// Refuses another live selected header, invalid full references/limits or
    /// a transfer pair that cannot fit the unchanged finite original ceiling.
    pub(crate) fn quote_current_capture17_upload_geometry_data(
        &self,
        original: &Envelope,
        history: &ContentRef,
        runtime: &ContentRef,
    ) -> Result<crate::reference_packet::service::native_startup::PacketRestoredSettledCaptureUploadGeometryData, ProviderError>{
        authenticate_original_data(self, original)?;
        let geometry = crate::reference_packet::service::native_startup::original_restored_settled_capture_auxiliary_geometry_for_limits_data(
            &self.authority.limits(), history, runtime, 256,
        )?;
        authenticate_original_data(self, original)?;
        Ok(geometry)
    }

    /// Names the actual selected-header and closed-reply correspondence checks.
    ///
    /// This fixed DATA is separately admitted before a predecessor/seed walk;
    /// it grants no Source, native effect or transport allocation permission.
    pub(crate) fn capture17_upload_correspondence_counter_scratch_data() -> usize {
        counter_scratch_data()
    }

    /// Names fixed defining quote/closed-validator/actual-original headers.
    ///
    /// This bound is checked before quotation; the resulting projection and
    /// complete phase row still require independent actual native admission.
    pub(crate) fn capture17_upload_prefix_counter_scratch_data() -> usize {
        Self::original_packet_prefix_quote_scratch_bytes_data()
            + counter_scratch_data()
            + crate::reference_packet::service::restored_input_reactive17::observation_geometry::prospective_counter_scratch_data()
            + size_of::<OriginalPacketPrefixProjectionStorageData<0>>()
            + size_of::<OriginalPacketPrefixProjectionInput<'static>>()
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<&Envelope>() + size_of::<&Map<String, Value>>()
        + size_of::<crate::handshake::Limits>()
        + size_of::<&[(ContentRef, Vec<u8>)]>()
        + size_of::<&[&str]>() + size_of::<std::slice::Iter<'static, &str>>()
        + size_of::<std::str::Bytes<'static>>() + size_of::<Option<u8>>()
        + size_of::<Option<&Value>>() + size_of::<Option<&Map<String, Value>>>()
        + size_of::<Option<&str>>() + size_of::<Result<u64, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<u64, std::num::ParseIntError>>()
        + size_of::<[u64; 4]>() + size_of::<[usize; 3]>()
        + crate::reference_packet::service::complete_restore::settled_recapture::restored_settled_capture_selection_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // These are response-correspondence DATA. A null extension cannot pass the
    // actual signed Source/native Scope or manufacture an upload effect owner.
    fn original(method: Method, body: Value) -> Envelope {
        let mut original = crate::envelope::tests::request();
        original.method = method;
        original.body = body.as_object().unwrap().clone();
        original.extensions.clear();
        original
            .extensions
            .insert(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE.into(), Value::Null);
        original
    }

    fn completed(result: Value) -> Map<String, Value> {
        json!({"status":"completed", "operation_state":"completed", "result":result, "extensions":{}})
            .as_object().unwrap().clone()
    }

    fn reference() -> Value {
        serde_json::to_value(canonical::content_ref(b"actual", "application/json").unwrap())
            .unwrap()
    }

    #[test]
    fn three_closed_reply_bodies_match_their_actual_original_phase() {
        let reference = reference();
        let begin = original(
            Method::BlobBegin,
            json!({"transfer_id":"transfer", "content":reference, "extensions":{}}),
        );
        let body = completed(
            json!({"transfer_id":"transfer", "next_offset":"0", "maximum_chunk_bytes":"64"}),
        );
        authenticate_response_data(&begin, &body, 64).unwrap();

        let chunk = original(
            Method::BlobChunk,
            json!({"transfer_id":"transfer", "offset":"0", "bytes":"YWJj", "extensions":{}}),
        );
        let body = completed(json!({"transfer_id":"transfer", "next_offset":"3"}));
        authenticate_response_data(&chunk, &body, 64).unwrap();
        let later_prefix = completed(json!({"transfer_id":"transfer", "next_offset":"6"}));
        authenticate_response_data(&chunk, &later_prefix, 64).unwrap();

        let finish = original(
            Method::BlobFinish,
            json!({"transfer_id":"transfer", "extensions":{}}),
        );
        let body = completed(json!({"transfer_id":"transfer", "content":reference}));
        authenticate_response_data(&finish, &body, 64).unwrap();
        assert!(authenticate_response_data(&begin, &body, 64).is_err());
    }

    #[test]
    fn changed_scope_ids_counts_result_or_decimal_fields_refuse_correspondence() {
        let original = original(
            Method::BlobChunk,
            json!({"transfer_id":"transfer", "offset":"5", "bytes":"YWJj", "extensions":{}}),
        );
        for result in [
            json!({"transfer_id":"wrong", "next_offset":"8"}),
            json!({"transfer_id":"transfer", "next_offset":"7"}),
            json!({"transfer_id":"transfer", "next_offset":"08"}),
            json!({"transfer_id":"transfer", "next_offset":8}),
            json!({"transfer_id":"transfer", "next_offset":"8", "extra":true}),
        ] {
            assert!(authenticate_response_data(&original, &completed(result), 64).is_err());
        }
        let mut changed = completed(json!({"transfer_id":"transfer", "next_offset":"8"}));
        changed.insert("extensions".into(), json!({"extra":true}));
        assert!(authenticate_response_data(&original, &changed, 64).is_err());
        let mut changed = original.clone();
        changed
            .body
            .insert("offset".into(), json!("18446744073709551615"));
        assert!(
            authenticate_response_data(
                &changed,
                &completed(json!({"transfer_id":"transfer", "next_offset":"8"})),
                64
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_chunk_extent_checks_all_tails_without_decoding_a_new_bank() {
        for bytes in [b"a".as_slice(), b"ab", b"abc", b"abcd", b"abcde", b"abcdef"] {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            assert_eq!(chunk_length_data(&encoded).unwrap(), bytes.len() as u64);
        }
        for invalid in ["", "a", "YQ=", "YQ==", "YR", "YWJ", "+w", "/w", "Y Q"] {
            assert!(chunk_length_data(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn begin_limits_and_finish_full_reference_grammar_remain_independent() {
        let reference = reference();
        let begin = original(
            Method::BlobBegin,
            json!({"transfer_id":"transfer", "content":reference, "extensions":{}}),
        );
        for (next, chunk) in [("7", "64"), ("0", "0"), ("0", "63")] {
            let body = completed(
                json!({"transfer_id":"transfer", "next_offset":next, "maximum_chunk_bytes":chunk}),
            );
            assert!(authenticate_response_data(&begin, &body, 64).is_err());
        }
        let finish = original(
            Method::BlobFinish,
            json!({"transfer_id":"transfer", "extensions":{}}),
        );
        let mut wrong = reference;
        wrong["hash"]["domain"] = json!("other");
        assert!(
            authenticate_response_data(
                &finish,
                &completed(json!({"transfer_id":"transfer", "content":wrong})),
                64
            )
            .is_err()
        );
    }
}
