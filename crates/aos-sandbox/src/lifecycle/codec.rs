use aos_sandbox_core::bounded_codec::BoundedReader;

use super::LifecycleModelError;

pub(super) fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], LifecycleModelError> {
    let mut reader = BoundedReader::new(*bytes, |_| LifecycleModelError::CorruptEncoding);
    let value = reader.array()?;
    *bytes = reader.remaining_bytes();
    Ok(value)
}

pub(super) fn take_slice<'a>(
    bytes: &mut &'a [u8],
    length: usize,
) -> Result<&'a [u8], LifecycleModelError> {
    let mut reader = BoundedReader::new(*bytes, |_| LifecycleModelError::CorruptEncoding);
    let value = reader.bytes(length)?;
    *bytes = reader.remaining_bytes();
    Ok(value)
}

pub(super) fn usize_from_u32(bytes: &[u8]) -> Result<usize, LifecycleModelError> {
    let raw: [u8; 4] = bytes
        .try_into()
        .map_err(|_| LifecycleModelError::CorruptEncoding)?;
    usize::try_from(u32::from_be_bytes(raw)).map_err(|_| LifecycleModelError::CorruptEncoding)
}

#[cfg(test)]
mod tests;
