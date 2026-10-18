//! Counts closed future JSON spellings without creating values or output banks.
//!
//! These are encoded-byte bounds, independent of retained layouts and permits.
//! Callers pair the field roster with its actual defining serializer.

use crate::ProviderError;

pub(crate) const DECIMAL: usize = 20;
pub(crate) const U64_STRING: usize = DECIMAL + 2;

pub(crate) fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

pub(crate) fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

pub(crate) fn literal(text: &str) -> Result<usize, ProviderError> {
    // All defining literals/keys are ASCII without escaping. Caller-produced
    // strings use string(), including printable media types containing quotes.
    if !text
        .bytes()
        .all(|byte| byte.is_ascii() && byte >= 0x20 && byte != b'"' && byte != b'\\')
    {
        return Err(exhausted());
    }
    add(text.len(), 2)
}

pub(crate) fn string(maximum_utf8_bytes: usize) -> Result<usize, ProviderError> {
    add(multiply(maximum_utf8_bytes, 6)?, 2)
}

pub(crate) fn object(fields: &[(&str, usize)]) -> Result<usize, ProviderError> {
    fields.iter().try_fold(2usize, |sum, (key, value)| {
        // Include a comma for every field; the absent final comma is harmless.
        add(sum, add(add(literal(key)?, 2)?, *value)?)
    })
}

pub(crate) fn array(count: usize, element: usize) -> Result<usize, ProviderError> {
    add(2, multiply(count, add(element, 1)?)?)
}

pub(crate) fn raw_bytes(count: usize) -> Result<usize, ProviderError> {
    // A u8 contributes at most three digits and its separating comma.
    add(multiply(count, 4)?, 2)
}

pub(crate) fn compact_bytes(count: usize) -> Result<usize, ProviderError> {
    // Exact BorrowedCompactBytes/7 chunk size and base64 expansion. Header
    // allowance includes schema, decimal decoded length, array/string framing.
    add(
        add(
            multiply(count.div_ceil(3), 4)?,
            multiply(count.div_ceil(3072), 3)?,
        )?,
        64,
    )
}

pub(crate) fn hash(domain: &str) -> Result<usize, ProviderError> {
    object(&[
        ("algorithm", literal("blake3-256")?),
        ("domain", literal(domain)?),
        ("digest", add(64, 2)?),
    ])
}

pub(crate) fn content_reference() -> Result<usize, ProviderError> {
    object(&[
        ("hash", hash("cnp.blob.v1")?),
        ("length", U64_STRING),
        ("media_type", string(128)?),
    ])
}

pub(crate) fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("SDK Capture17 future history encoding")
}

pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<&[(&str, usize)]>()
        + std::mem::size_of::<std::slice::Iter<'static, (&'static str, usize)>>()
        + std::mem::size_of::<Result<usize, ProviderError>>()
        + std::mem::size_of::<[usize; 8]>()
        + std::mem::size_of::<std::str::Bytes<'static>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;

    #[test]
    fn byte_spellings_cover_actual_compact_chunks_and_raw_u8_arrays()
    -> Result<(), Box<dyn std::error::Error>> {
        for length in [0, 1, 2, 3, 3071, 3072, 3073, 6143, 6144, 6145] {
            let bytes = vec![255u8; length];
            let compact = serde_json::to_vec(&BorrowedCompactBytes::new(&bytes))?;
            let raw = serde_json::to_vec(&bytes)?;
            assert!(compact.len() <= compact_bytes(length)?);
            assert!(raw.len() <= raw_bytes(length)?);
        }
        assert!(compact_bytes(usize::MAX).is_err());
        assert!(raw_bytes(usize::MAX).is_err());
        Ok(())
    }

    #[test]
    fn actual_full_reference_with_maximum_media_escaping_fits()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut reference = crucible_node_contract::canonical::content_ref(
            b"actual encoded reference",
            "application/json",
        )?;
        reference.length = crucible_node_contract::U64::new(u64::MAX);
        reference.media_type = "\"".repeat(128);
        crucible_node_contract::Validate::validate(&reference)?;
        assert!(serde_json::to_vec(&reference)?.len() <= content_reference()?);
        assert!(object(&[("raw", usize::MAX)]).is_err());
        Ok(())
    }
}
