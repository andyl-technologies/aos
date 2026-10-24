//! Explicit version8/body5 codec reusing the unchanged native field codec.

use super::{
    MAXIMUM_NATIVE_HELD_BODY_BYTES_V1, MAXIMUM_NATIVE_HELD_RECORD_BYTES_V1,
    SourceNativeHeldCompletionRecordV1, corrupt, schema_error,
};
use crate::ledger::{LedgerFormatErrorV1, format, model::RecordKind, native_completion};
use aos_sandbox_source_provider_protocol::native_held_completion::suffix::NativeHeldCompletionSuffixV1;

pub(super) const MAGIC: &[u8; 8] = b"AOSNCR05";
const CLOCKED_PREFIX_BYTES: usize = 544 + 32 + 56;

pub(super) fn encode(
    value: &SourceNativeHeldCompletionRecordV1,
) -> Result<Vec<u8>, LedgerFormatErrorV1> {
    super::evidence::validate_record(value)?;
    let mut body = native_completion::encode_body(&value.original);
    body[..8].copy_from_slice(MAGIC);
    body.extend_from_slice(&value.suffix.to_canonical_bytes().map_err(schema_error)?);
    if body.len() > MAXIMUM_NATIVE_HELD_BODY_BYTES_V1 {
        return Err(LedgerFormatErrorV1::LimitExceeded("held native body"));
    }
    Ok(format::encode_envelope_version(
        RecordKind::NativeCompletion,
        value.original.state as u8,
        value.original.revision,
        &native_completion::native_completion_key_v2(value.original.acquisition_id),
        &body,
        8,
    ))
}

pub(super) fn decode(
    key: &[u8],
    bytes: &[u8],
) -> Result<SourceNativeHeldCompletionRecordV1, LedgerFormatErrorV1> {
    if bytes.len() > MAXIMUM_NATIVE_HELD_RECORD_BYTES_V1 {
        return Err(LedgerFormatErrorV1::LimitExceeded("held native record"));
    }
    let envelope = format::decode_envelope_version(key, bytes, Some(8))?;
    if envelope.body.get(..8) != Some(MAGIC.as_slice()) {
        return Err(corrupt("held body version"));
    }
    let request_length = length_at(envelope.body, CLOCKED_PREFIX_BYTES)?;
    let reply_offset = CLOCKED_PREFIX_BYTES
        .checked_add(4)
        .and_then(|offset| offset.checked_add(request_length))
        .ok_or(corrupt("held request length overflow"))?;
    let reply_length = length_at(envelope.body, reply_offset)?;
    let suffix_offset = reply_offset
        .checked_add(4)
        .and_then(|offset| offset.checked_add(reply_length))
        .ok_or(corrupt("held reply length overflow"))?;
    let mut original_body = envelope
        .body
        .get(..suffix_offset)
        .ok_or(corrupt("held native artifacts truncated"))?
        .to_vec();
    original_body[..8].copy_from_slice(b"AOSNCR04");
    let original =
        native_completion::decode_body(key, &original_body, envelope.revision, envelope.state)?;
    let suffix = NativeHeldCompletionSuffixV1::from_canonical_bytes(
        envelope
            .body
            .get(suffix_offset..)
            .ok_or(corrupt("held suffix missing"))?,
    )
    .map_err(schema_error)?;
    let value = SourceNativeHeldCompletionRecordV1::new(original, suffix)?;
    if encode(&value)? != bytes {
        return Err(corrupt("held native canonical bytes"));
    }
    Ok(value)
}

fn length_at(bytes: &[u8], offset: usize) -> Result<usize, LedgerFormatErrorV1> {
    let end = offset
        .checked_add(4)
        .ok_or(corrupt("held length overflow"))?;
    let field = bytes
        .get(offset..end)
        .ok_or(corrupt("held length truncated"))?;
    Ok(u32::from_be_bytes(field.try_into().map_err(|_| corrupt("held length width"))?) as usize)
}
