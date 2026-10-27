//! Checks complete borrowed pairs, bounded canonical owners and ordered directions.

use super::*;
use crate::bodies::{MethodResult, OperationState, ResponseShape, decode_request, decode_response};
use crate::envelope::{MessageKind, Method, RequestOrigin};
use crucible_node_format::{Bytes, ContentRef, ContractError, canonical};
use serde::Serialize;

pub(super) fn canonical_bytes(
    value: &impl Serialize,
    maximum: usize,
) -> Result<Vec<u8>, ProviderError> {
    crate::connection::serialized_credit(value, maximum)?;
    let value = serde_json::to_value(value).map_err(ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > maximum {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(super) fn same_value(
    actual: &impl Serialize,
    expected: &impl Serialize,
    maximum: usize,
) -> Result<(), ProviderError> {
    if canonical_bytes(actual, maximum)? != canonical_bytes(expected, maximum)? {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn digest_matches(actual: &Bytes, expected: &[u8; 32]) -> Result<(), ProviderError> {
    if actual.as_slice() != expected {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn value_digest(
    actual: &Bytes,
    value: &impl Serialize,
    maximum: usize,
) -> Result<(), ProviderError> {
    digest_matches(
        actual,
        blake3::hash(&canonical_bytes(value, maximum)?).as_bytes(),
    )
}

pub(super) fn extension(
    original: &Envelope,
    name: &str,
    expected: &impl Serialize,
    maximum: usize,
) -> Result<(), ProviderError> {
    same_value(
        original.extensions.get(name).ok_or_else(invalid)?,
        expected,
        maximum,
    )
}

pub(super) fn completed_pair(
    pair: HistoricalCompletedPair17<'_>,
    method: Method,
    maximum_frame: usize,
) -> Result<ResponseBody, ProviderError> {
    for envelope in [pair.original, pair.terminal] {
        envelope.validate()?;
        crate::connection::serialized_credit(envelope, maximum_frame)?;
    }
    if pair.original.message != MessageKind::Request
        || pair.original.method != method
        || pair.original.sequence.get() == 0
        || pair.terminal.message != MessageKind::Response
        || pair.terminal.sequence.get() == 0
    {
        return Err(invalid());
    }
    pair.original.matches_response(pair.terminal)?;
    let request = decode_request(method, &pair.original.body)?;
    let response = decode_response(&request, &pair.terminal.body)?;
    if !matches!(&response.shape, ResponseShape::Completed {
        operation_state: OperationState::Completed, extensions, ..
    } if extensions.is_empty())
    {
        return Err(invalid());
    }
    Ok(response)
}

pub(super) fn follows(
    earlier: HistoricalCompletedPair17<'_>,
    later: HistoricalCompletedPair17<'_>,
) -> Result<(), ProviderError> {
    // Directions have independent sequences. Ordering request against response
    // would invent chronology that the actual protocol never records.
    if earlier.original.session_id != later.original.session_id
        || earlier.original.incarnation_id != later.original.incarnation_id
        || earlier.original.request_id == later.original.request_id
        || earlier.original.sequence >= later.original.sequence
        || earlier.terminal.sequence >= later.terminal.sequence
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn verify_reference(
    reference: &ContentRef,
    value: &impl Serialize,
    maximum: usize,
) -> Result<Vec<u8>, ProviderError> {
    if reference.media_type != "application/json" {
        return Err(invalid());
    }
    let bytes = canonical_bytes(value, maximum)?;
    reference.verify(&bytes)?;
    Ok(bytes)
}

pub(super) fn cached_pair(
    control: &CurrentControl17Data,
    pair: HistoricalCompletedPair17<'_>,
) -> Result<(), ProviderError> {
    let id = pair.original.request_id.0.as_ref().ok_or_else(invalid)?;
    let (identity, cached) = control.originals_data().get(id).ok_or_else(invalid)?;
    if pair.original.request_hash(RequestOrigin::Controller)? != *identity
        || cached.body != pair.terminal.body
    {
        return Err(invalid());
    }
    for (reference, bytes) in &cached.evidence {
        reference.verify(bytes)?;
        if control.content_data().get(reference) != Some(bytes) {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) fn hello_digest(
    literal: &[u8],
    maximum_frame: usize,
) -> Result<[u8; 32], ProviderError> {
    let header: [u8; 4] = literal
        .get(..4)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())?;
    let body = literal.get(4..).ok_or_else(invalid)?;
    if body.len() > maximum_frame
        || usize::try_from(u32::from_be_bytes(header)).map_err(|_| invalid())? != body.len()
    {
        return Err(invalid());
    }
    Ok(blake3::derive_key(
        "source-owned.cnp-original-hello-frame/5",
        literal,
    ))
}

pub(super) fn restored_underlying_bytes(
    underlying: &PacketNative5UnderlyingRecord,
    maximum: usize,
) -> Result<Vec<u8>, ProviderError> {
    match underlying {
        PacketNative5UnderlyingRecord::Producer(record) => {
            canonical_bytes(record.as_ref(), maximum)
        }
        PacketNative5UnderlyingRecord::Reactive(record) => {
            canonical_bytes(record.as_ref(), maximum)
        }
    }
}

pub(super) fn observe_result(
    response: &ResponseBody,
) -> Result<&crate::bodies::ObserveResult, ProviderError> {
    let Some(MethodResult::Observe(result)) = response.result.as_ref() else {
        return Err(invalid());
    };
    Ok(result)
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&Envelope>() * 4
        + size_of::<[&Envelope; 2]>()
        + size_of::<ResponseBody>()
        + size_of::<crate::bodies::RequestBody>()
        + size_of::<Value>()
        + size_of::<Vec<u8>>() * 2
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
        + size_of::<Result<crate::bodies::RequestBody, ProviderError>>()
        + size_of::<Result<ResponseBody, ProviderError>>()
        + size_of::<Result<crucible_node_format::HashRef, ProviderError>>()
        + size_of::<[u8; 4]>()
        + size_of::<u32>()
        + size_of::<usize>()
}
