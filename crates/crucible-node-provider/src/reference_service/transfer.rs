//! Opposite-direction verified content delivery with original retained request IDs.

use std::os::unix::net::UnixStream;

use crucible_node_contract::*;
use serde_json::{Map, Value};

use crate::ProviderError;
use crate::bodies::*;
use crate::connection::{Connection, ReceivedBody};
use crate::envelope::{Envelope, MessageKind, Method, Nullable, RequestOrigin};
use crate::handshake::ConnectionAuthority;
use crate::native_journal::*;

use super::object;
use super::resources::Resources;

pub(super) fn publish(
    connection: &mut Connection<UnixStream>,
    authority: &ConnectionAuthority,
    journal: &mut NativeJournal<Resources>,
    sequence: &mut U64,
) -> Result<(), ProviderError> {
    let Some(window) = &journal.resources().window else {
        return Ok(());
    };
    let mut content: Vec<ContentRef> = window
        .observation
        .events
        .iter()
        .map(|event| event.payload.clone())
        .collect();
    content.extend([
        window.measurement.clone(),
        window.pending.clone(),
        window.observation_ref.clone(),
        window.stop.clone(),
    ]);
    if let Some(committed) = &window.committed_ref {
        content.push(committed.clone());
    }
    for reference in content {
        if journal
            .resources()
            .transferred
            .borrow()
            .contains(&reference.hash.digest)
        {
            continue;
        }
        let bytes = journal.resources().content(&reference)?.to_vec();
        let transfer_id = Id::new(format!("output-{}", reference.hash.digest))?;
        let result = exchange(
            connection,
            authority,
            journal,
            sequence,
            Method::BlobBegin,
            Id::new(format!("output-begin-{}", reference.hash.digest))?,
            object(BlobBeginRequest {
                transfer_id: transfer_id.clone(),
                content: reference.clone(),
                extensions: Extensions::new(),
            })?,
        )?;
        let Some(MethodResult::BlobBegin(progress)) = result.result else {
            return Err(ProviderError::Correlation(
                "controller refused output reservation",
            ));
        };
        if progress.transfer_id != transfer_id
            || progress.next_offset.get() > reference.length.get()
        {
            return Err(ProviderError::Correlation(
                "output reservation changed original transfer",
            ));
        }
        let frame_room = authority
            .limits()
            .frame_bytes
            .get()
            .saturating_sub(2048)
            .saturating_mul(3)
            / 4;
        let maximum = progress
            .maximum_chunk_bytes
            .min(authority.limits().blob_chunk_bytes)
            .get()
            .min(frame_room);
        if maximum == 0 {
            return Err(ProviderError::ResourceExhausted(
                "output frame cannot contain a chunk",
            ));
        }
        // Original fixed chunk cuts do not depend on a receiver's reconnect
        // progress. Replaying the same cuts preserves request commitments.
        let maximum = usize::try_from(maximum)
            .map_err(|_| ProviderError::ResourceExhausted("output chunk platform limit"))?;
        let mut offset = 0usize;
        for chunk in bytes.chunks(maximum) {
            let offset_value = U64::new(offset as u64);
            let result = exchange(
                connection,
                authority,
                journal,
                sequence,
                Method::BlobChunk,
                Id::new(format!("output-chunk-{}-{offset}", reference.hash.digest))?,
                object(BlobChunkRequest {
                    transfer_id: transfer_id.clone(),
                    offset: offset_value,
                    bytes: Bytes::new(chunk.to_vec()),
                    extensions: Extensions::new(),
                })?,
            )?;
            offset = offset
                .checked_add(chunk.len())
                .ok_or(ProviderError::ResourceExhausted("output chunk offset"))?;
            if !matches!(result.result,Some(MethodResult::BlobChunk(ref result)) if result.transfer_id == transfer_id && result.next_offset == U64::new(offset as u64))
            {
                return Err(ProviderError::Correlation(
                    "controller changed original output chunk acknowledgment",
                ));
            }
        }
        let result = exchange(
            connection,
            authority,
            journal,
            sequence,
            Method::BlobFinish,
            Id::new(format!("output-finish-{}", reference.hash.digest))?,
            object(BlobFinishRequest {
                transfer_id: transfer_id.clone(),
                extensions: Extensions::new(),
            })?,
        )?;
        if !matches!(result.result,Some(MethodResult::BlobFinish(ref result)) if result.transfer_id == transfer_id && result.content == reference)
        {
            return Err(ProviderError::Correlation(
                "controller did not verify complete original output content",
            ));
        }
        // This marks authenticated byte custody only. Native publication remains
        // blocked until a separate exact host consumption receipt is verified.
        journal
            .resources()
            .transferred
            .borrow_mut()
            .insert(reference.hash.digest);
    }
    Ok(())
}

fn exchange(
    connection: &mut Connection<UnixStream>,
    authority: &ConnectionAuthority,
    journal: &mut NativeJournal<Resources>,
    sequence: &mut U64,
    method: Method,
    request_id: Id,
    body: Map<String, Value>,
) -> Result<ResponseBody, ProviderError> {
    let request = Envelope {
        protocol: "CNP/1".to_owned(),
        message: MessageKind::Request,
        session_id: Nullable(Some(authority.session_id().clone())),
        incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(request_id)),
        sequence: *sequence,
        method,
        body,
        extensions: Extensions::new(),
    };
    let registration = journal.register_request(authority, &request, RequestOrigin::Provider)?;
    if let NativeRequestRegistration::Original(ref original) = registration
        && let Some(bytes) = &original.outcome
    {
        let outcome = object(canonical::parse_json(bytes, 16 * 1024 * 1024)?)?;
        return decode_response(&decode_request(method, &request.body)?, &outcome);
    }
    connection.send(request.clone())?;
    *sequence = sequence.checked_add(U64::new(1))?;
    let frame = connection.receive()?.ok_or(ProviderError::Correlation(
        "output acknowledgment unavailable",
    ))?;
    request.matches_response(&frame.envelope)?;
    let ReceivedBody::Response(result) = frame.body else {
        return Err(ProviderError::Correlation(
            "controller output acknowledgment is not a response",
        ));
    };
    validate_ack(journal.resources(), &request, &result)?;
    let acknowledgement = Acknowledgement {
        original: request.clone(),
        outcome: frame.envelope.body.clone(),
    };
    match registration {
        NativeRequestRegistration::New(permit) => {
            journal.record_request_terminal(&permit, &frame.envelope.body)?
        }
        NativeRequestRegistration::Original(_) => journal.reconcile_request_terminal(
            authority,
            &request,
            RequestOrigin::Provider,
            &frame.envelope.body,
            &acknowledgement,
        )?,
    }
    Ok(*result)
}

// Constructed only from Connection's authenticated, original-correlated closed
// response above. It is not deserializable and cannot originate in wire claims.
struct Acknowledgement {
    original: Envelope,
    outcome: Map<String, Value>,
}

impl NativeRequestOutcomeVerifier<Resources> for Acknowledgement {
    fn verify_request_outcome(
        &self,
        resources: &Resources,
        original: &Envelope,
        response: &ResponseBody,
    ) -> Result<(), ProviderError> {
        if original.request_hash(RequestOrigin::Provider)?
            != self.original.request_hash(RequestOrigin::Provider)?
            || decode_response(
                &decode_request(original.method, &original.body)?,
                &self.outcome,
            )? != *response
        {
            return Err(ProviderError::Correlation(
                "recovered acknowledgment changed original request",
            ));
        }
        validate_ack(resources, original, response)?;
        Ok(())
    }
}

fn validate_ack(
    resources: &Resources,
    original: &Envelope,
    response: &ResponseBody,
) -> Result<(), ProviderError> {
    let Some(result) = &response.result else {
        return Ok(());
    };
    let request = decode_request(original.method, &original.body)?;
    let valid = match (request, result) {
        (RequestBody::BlobBegin(request), MethodResult::BlobBegin(result)) => {
            request.transfer_id == result.transfer_id
                && result.next_offset <= request.content.length
        }
        (RequestBody::BlobChunk(request), MethodResult::BlobChunk(result)) => {
            request.transfer_id == result.transfer_id
                && result.next_offset
                    == request
                        .offset
                        .checked_add(U64::new(request.bytes.as_slice().len() as u64))?
        }
        (RequestBody::BlobFinish(request), MethodResult::BlobFinish(result)) => {
            request.transfer_id == result.transfer_id
                && request
                    .transfer_id
                    .as_str()
                    .strip_prefix("output-")
                    .and_then(|digest| resources.contents.get(digest))
                    .is_some_and(|(reference, _)| reference == &result.content)
        }
        _ => false,
    };
    if !valid {
        return Err(ProviderError::Correlation(
            "output acknowledgment changed original native transfer",
        ));
    }
    Ok(())
}
