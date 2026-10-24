//! Prebuilds one exact held-proof Blob window without registering live requests.

use super::*;
use crate::envelope::Nullable;
use crucible_node_format::{Bytes, Extensions, U64};
use serde::Serialize;
use serde_json::{Map, Value};

pub(super) fn plan(
    authority: &ConnectionAuthority,
    commit: &Envelope,
    first: u64,
    reference: &ContentRef,
    bytes: &[u8],
) -> Result<(Vec<Envelope>, usize), ProviderError> {
    authority.ensure_live()?;
    reference.verify(bytes)?;
    let chunk = usize::try_from(authority.limits().blob_chunk_bytes.get())
        .map_err(|_| refused())?
        .min(4096);
    let maximum = usize::try_from(authority.limits().frame_bytes.get()).map_err(|_| refused())?;
    if bytes.is_empty() || chunk == 0 || maximum > 65_536 {
        return Err(refused());
    }
    let count = bytes
        .len()
        .div_ceil(chunk)
        .checked_add(2)
        .ok_or_else(refused)?;
    if u64::try_from(count).map_err(|_| refused())? > authority.limits().requests.get() {
        return Err(refused());
    }
    let mut originals = Vec::new();
    originals
        .try_reserve_exact(count)
        .map_err(|_| ProviderError::ResourceExhausted("native held proof frame slots"))?;
    let transfer = Id::new(format!("packet-restore-held-transfer-{first}"))?;
    let mut sequence = first;
    append(
        &mut originals,
        commit,
        &mut sequence,
        Method::BlobBegin,
        object(BlobBeginRequest {
            transfer_id: transfer.clone(),
            content: reference.clone(),
            extensions: Extensions::new(),
        })?,
    )?;
    for (index, bytes) in bytes.chunks(chunk).enumerate() {
        append(
            &mut originals,
            commit,
            &mut sequence,
            Method::BlobChunk,
            object(BlobChunkRequest {
                transfer_id: transfer.clone(),
                offset: U64::new(
                    u64::try_from(index.checked_mul(chunk).ok_or_else(refused)?)
                        .map_err(|_| refused())?,
                ),
                bytes: Bytes::new(bytes.to_vec()),
                extensions: Extensions::new(),
            })?,
        )?;
    }
    append(
        &mut originals,
        commit,
        &mut sequence,
        Method::BlobFinish,
        object(BlobFinishRequest {
            transfer_id: transfer,
            extensions: Extensions::new(),
        })?,
    )?;
    let outgoing = originals.iter().try_fold(0usize, |total, original| {
        total
            .checked_add(crate::connection::serialized_credit(original, maximum)?)
            .ok_or_else(refused)
    })?;
    // These are retained ordinary endpoint-prefix terms. The SDK additionally
    // checks the complete original B/F/ID suffix before its Prepare receipt.
    let charge = count
        .checked_mul(maximum.checked_add(4).ok_or_else(refused)?)
        .and_then(|incoming| incoming.checked_mul(2))
        .and_then(|incoming| {
            outgoing
                .checked_mul(3)
                .and_then(|outgoing| outgoing.checked_add(incoming))
        })
        .ok_or_else(refused)?;
    Ok((originals, charge))
}

fn append(
    originals: &mut Vec<Envelope>,
    commit: &Envelope,
    sequence: &mut u64,
    method: Method,
    body: Map<String, Value>,
) -> Result<(), ProviderError> {
    let mut original = commit.clone();
    original.message = MessageKind::Request;
    original.method = method;
    original.request_id = Nullable(Some(Id::new(format!(
        "packet-restore-held-proof-{sequence}"
    ))?));
    original.sequence = U64::new(*sequence);
    original.node_id = Nullable(None);
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(None);
    original.operation_id = Nullable(None);
    original.body = body;
    original.extensions = Extensions::new();
    *sequence = sequence.checked_add(1).ok_or_else(refused)?;
    originals.push(original);
    Ok(())
}

fn object(value: impl Serialize) -> Result<Map<String, Value>, ProviderError> {
    match serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)? {
        Value::Object(object) => Ok(object),
        _ => Err(refused()),
    }
}

pub(super) fn validate_ack(
    original: &Envelope,
    received: &ReceivedFrame,
) -> Result<(), ProviderError> {
    let ReceivedBody::Response(response) = &received.body else {
        return Err(refused());
    };
    if !matches!(&response.shape, ResponseShape::Completed { operation_state: OperationState::Completed, extensions, .. } if extensions.is_empty())
        || !received.envelope.extensions.is_empty()
    {
        return Err(refused());
    }
    original.matches_response(&received.envelope)?;
    match (
        decode_request(original.method, &original.body)?,
        &response.result,
    ) {
        (RequestBody::BlobBegin(request), Some(MethodResult::BlobBegin(result)))
            if request.transfer_id == result.transfer_id
                && result.next_offset.get() == 0
                && result.maximum_chunk_bytes.get() > 0 =>
        {
            Ok(())
        }
        (RequestBody::BlobChunk(request), Some(MethodResult::BlobChunk(result)))
            if request.transfer_id == result.transfer_id
                && request.offset.get().checked_add(
                    u64::try_from(request.bytes.as_slice().len()).map_err(|_| refused())?,
                ) == Some(result.next_offset.get()) =>
        {
            Ok(())
        }
        (RequestBody::BlobFinish(request), Some(MethodResult::BlobFinish(result)))
            if request.transfer_id == result.transfer_id =>
        {
            Ok(())
        }
        _ => Err(refused()),
    }
}
