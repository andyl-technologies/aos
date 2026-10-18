//! Reconstructs one admitted native byte bank without wire-base64 scratch.

use super::super::{
    state::next,
    typed::{Fields, Ledger, invalid, unsigned},
};
use crate::retained_metadata::records::MetadataRecordKind;
use crate::{ProviderError, protocol_snapshot::compact_bytes::ValidatedCompactBytes};

pub(super) fn bank(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    exact_length: Option<usize>,
) -> Result<Option<Vec<u8>>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let capacity = usize::try_from(unsigned(next(&mut fields)?)?).map_err(|_| invalid())?;
    if ledger.row(MetadataRecordKind::Vector, 1)? != capacity {
        return Err(invalid());
    }
    let plan = ValidatedCompactBytes::validate(
        next(&mut fields)?,
        ledger.limits.maximum_input_bytes,
        capacity,
    )?;
    fields.finish()?;
    if exact_length.is_some_and(|length| length != plan.decoded_length())
        || capacity > ledger.limits.maximum_owned_backing_bytes
    {
        return Err(invalid());
    }
    ledger.native17_target_vector_data::<u8>(capacity)?;
    if !build {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| ProviderError::ResourceExhausted("native historical byte bank"))?;
    if bytes.capacity() != capacity {
        return Err(invalid());
    }
    plan.fill_preowned(&mut bytes)?;
    Ok(Some(bytes))
}

/// Names actual fixed local and returned headers of this handwritten reader.
///
/// Empty maps and `Option` payloads remain real controls when `build` is false;
/// no tree entries, backing allocations or owning reconstruction are included.
pub(super) fn borrowed_validation_headers_data() -> usize {
    use std::mem::size_of;

    fn header<T>() -> usize {
        size_of::<Option<T>>() + size_of::<Result<Option<T>, ProviderError>>()
    }

    header::<Vec<u8>>()
}
