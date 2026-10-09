//! Checked byte mechanics for the closed native held-completion formats.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{NativeHeldCompletionErrorV1, Result};

pub(super) fn invalid(reason: &'static str) -> NativeHeldCompletionErrorV1 {
    NativeHeldCompletionErrorV1::Invalid(reason)
}

pub(super) fn nonzero(value: ObjectDigest) -> bool {
    value.as_bytes() != &[0; 32]
}

pub(super) fn digest(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(domain)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

pub(super) fn put_length(bytes: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| invalid("length overflow"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

pub(super) type Reader<'a> =
    aos_sandbox_core::bounded_codec::BoundedReader<'a, NativeHeldCompletionErrorV1>;

pub(super) fn read_error(
    error: aos_sandbox_core::bounded_codec::ReadError,
) -> NativeHeldCompletionErrorV1 {
    use aos_sandbox_core::bounded_codec::ReadError;

    invalid(match error {
        ReadError::LengthOverflow => "length overflow",
        ReadError::Truncated => "truncated value",
        ReadError::NonzeroReserved => "reserved bytes",
        ReadError::TrailingBytes => "trailing bytes",
    })
}

pub(super) fn read_header(reader: &mut Reader<'_>, magic: &[u8; 8]) -> Result<()> {
    if reader.bytes(8)? != magic || reader.u16()? != 1 {
        return Err(invalid("magic or version"));
    }
    Ok(())
}
