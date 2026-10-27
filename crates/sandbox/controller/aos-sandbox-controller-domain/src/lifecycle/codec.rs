//! Lifecycle prefix adapters over Core's bounded byte mechanics.
//!
//! Callers retain their actual remaining slices and own all format, count-limit,
//! canonicality, digest and replay validation. Failed reads never advance them.

use aos_sandbox_model::bounded_codec::BoundedReader;
use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError;

/// Copies one fixed-width field and advances the original remaining slice.
///
/// # Errors
///
/// Returns corrupt encoding for a missing field, leaving the input position unchanged.
pub(super) fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], LifecycleModelError> {
    let mut reader = BoundedReader::new(*bytes, |_| LifecycleModelError::CorruptEncoding);
    let value = reader.array()?;
    *bytes = reader.remaining_bytes();
    Ok(value)
}

/// Borrows one exact prefix and advances the original remaining slice.
///
/// # Errors
///
/// Returns corrupt encoding for a missing range, leaving the input position unchanged.
pub(super) fn take_slice<'a>(
    bytes: &mut &'a [u8],
    length: usize,
) -> Result<&'a [u8], LifecycleModelError> {
    let mut reader = BoundedReader::new(*bytes, |_| LifecycleModelError::CorruptEncoding);
    let value = reader.bytes(length)?;
    *bytes = reader.remaining_bytes();
    Ok(value)
}

/// Converts an exact big-endian count field without selecting a semantic limit.
///
/// # Errors
///
/// Returns corrupt encoding for a non-four-byte field or an unrepresentable count.
pub(super) fn usize_from_u32(bytes: &[u8]) -> Result<usize, LifecycleModelError> {
    let raw: [u8; 4] = bytes
        .try_into()
        .map_err(|_| LifecycleModelError::CorruptEncoding)?;
    usize::try_from(u32::from_be_bytes(raw)).map_err(|_| LifecycleModelError::CorruptEncoding)
}

#[cfg(test)]
mod tests;
