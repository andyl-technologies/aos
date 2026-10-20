//! Shares finite borrowed-field framing and fixed commitment-array grammar.
//!
//! ```text
//! fields = purpose-magic[8] | lengths[N * u32be] | original-fields[N]
//! commitments = purpose-magic[8] | nonzero-commitments[N * 32]
//! ```
//!
//! All maxima describe actual receiving bounds; they never admit an allocation.

use super::super::{HistoryErrorV1, nonzero, reader};

pub(in crate::domain_ledger) fn decode_fields<'bytes, const N: usize>(
    bytes: &'bytes [u8],
    magic: &[u8; 8],
    maxima: [usize; N],
) -> Result<[&'bytes [u8]; N], HistoryErrorV1> {
    let mut input = reader(bytes);
    if input.array::<8>()? != *magic {
        return Err(HistoryErrorV1::Malformed);
    }

    let lengths = read_field_lengths(&mut input, maxima)?;

    let mut fields = [b"".as_slice(); N];
    for (field, length) in fields.iter_mut().zip(lengths) {
        *field = input.bytes(length)?;
    }
    input.finish()?;
    Ok(fields)
}

// A receiver prices the announced complete width before growing its buffer.
// Complete decoding immediately uses the same length validation below.
pub(in crate::domain_ledger) fn declared_fields_bytes<const N: usize>(
    header: &[u8], magic: &[u8; 8], maxima: [usize; N],
) -> Result<usize, HistoryErrorV1> {
    let mut input = reader(header);
    if input.array::<8>()? != *magic {
        return Err(HistoryErrorV1::Malformed);
    }
    let lengths = read_field_lengths(&mut input, maxima)?;
    input.finish()?;
    lengths.into_iter().try_fold(header.len(), |sum, length| {
        sum.checked_add(length).ok_or(HistoryErrorV1::Extent)
    })
}

fn read_field_lengths<const N: usize>(
    input: &mut aos_sandbox_model::bounded_codec::BoundedReader<'_, HistoryErrorV1>,
    maxima: [usize; N],
) -> Result<[usize; N], HistoryErrorV1> {
    let mut lengths = [0; N];
    for (length, maximum) in lengths.iter_mut().zip(maxima) {
        *length = usize::try_from(input.u32()?).map_err(|_| HistoryErrorV1::Extent)?;
        if *length == 0 || *length > maximum {
            return Err(HistoryErrorV1::Extent);
        }
    }
    Ok(lengths)
}

pub(in crate::domain_ledger) fn fields_bytes<const N: usize>(
    fields: [&[u8]; N],
) -> Result<usize, HistoryErrorV1> {
    let prefix = N
        .checked_mul(4)
        .and_then(|value| value.checked_add(8))
        .ok_or(HistoryErrorV1::Extent)?;
    fields.into_iter().try_fold(prefix, |total, field| {
        if field.is_empty() {
            return Err(HistoryErrorV1::Extent);
        }
        u32::try_from(field.len()).map_err(|_| HistoryErrorV1::Extent)?;
        total.checked_add(field.len()).ok_or(HistoryErrorV1::Extent)
    })
}

pub(in crate::domain_ledger) fn encode_fields<const N: usize>(
    magic: &[u8; 8],
    fields: [&[u8]; N],
    output: &mut [u8],
) -> Result<(), HistoryErrorV1> {
    if output.len() != fields_bytes(fields)? {
        return Err(HistoryErrorV1::Extent);
    }
    encode_fields_range(magic, fields, 0, output)
}

// Both a complete encoder and a bounded transfer range use this same recipe.
// All length/extent validation precedes copying, so no partial invalid output
// can escape either adapter.
pub(in crate::domain_ledger) fn encode_fields_range<const N: usize>(
    magic: &[u8; 8],
    fields: [&[u8]; N],
    offset: usize,
    output: &mut [u8],
) -> Result<(), HistoryErrorV1> {
    let total = fields_bytes(fields)?;
    let end = offset.checked_add(output.len()).ok_or(HistoryErrorV1::Extent)?;
    if end > total {
        return Err(HistoryErrorV1::Extent);
    }

    copy_field_range(magic, 0, offset, end, output);
    let mut position = 8 + 4 * N;
    for (index, field) in fields.into_iter().enumerate() {
        copy_field_range(&(field.len() as u32).to_be_bytes(), 8 + index * 4, offset, end, output);
        copy_field_range(field, position, offset, end, output);
        position += field.len();
    }
    Ok(())
}

fn copy_field_range(field: &[u8], position: usize, offset: usize, end: usize, output: &mut [u8]) {
    let start = position.max(offset);
    let stop = (position + field.len()).min(end);
    if start < stop {
        output[start - offset..stop - offset].copy_from_slice(&field[start - position..stop - position]);
    }
}

pub(in crate::domain_ledger) fn decode_commitments<const N: usize>(
    bytes: &[u8],
    magic: &[u8; 8],
) -> Result<[[u8; 32]; N], HistoryErrorV1> {
    let mut input = reader(bytes);
    if input.array::<8>()? != *magic {
        return Err(HistoryErrorV1::Malformed);
    }
    let mut fields = [[0; 32]; N];
    for field in &mut fields {
        *field = input.array()?;
        nonzero(field)?;
    }
    input.finish()?;
    Ok(fields)
}

pub(in crate::domain_ledger) fn encode_commitments<const N: usize, const BYTES: usize>(
    magic: &[u8; 8],
    fields: [[u8; 32]; N],
) -> Result<[u8; BYTES], HistoryErrorV1> {
    if N.checked_mul(32).and_then(|bytes| bytes.checked_add(8)) != Some(BYTES) {
        return Err(HistoryErrorV1::Extent);
    }
    let mut output = [0; BYTES];
    output[..8].copy_from_slice(magic);
    for (index, field) in fields.into_iter().enumerate() {
        nonzero(&field)?;
        output[8 + index * 32..40 + index * 32].copy_from_slice(&field);
    }
    Ok(output)
}


const FIELD_HASH_SCRATCH_BYTES: usize = 4096;

pub(in crate::domain_ledger) fn hash_fields_receiving_bytes() -> Option<usize> {
    std::mem::size_of::<[u8; FIELD_HASH_SCRATCH_BYTES]>()
        .checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?)
}

// Uses the sole range encoder so streamed and whole-frame commitments agree.
pub(in crate::domain_ledger) fn hash_fields<const N: usize>(domain: &[u8], magic: &[u8; 8], fields: [&[u8]; N])
    -> Result<[u8; 32], HistoryErrorV1> {
    use sha2::{Digest as _, Sha256};
    let total = fields_bytes(fields)?;
    let mut hash = Sha256::new().chain_update(domain);
    let mut scratch = [0; FIELD_HASH_SCRATCH_BYTES];
    let mut offset = 0;
    while offset < total {
        let count = (total - offset).min(scratch.len());
        encode_fields_range(magic, fields, offset, &mut scratch[..count])?;
        hash.update(&scratch[..count]);
        offset += count;
    }
    Ok(hash.finalize().into())
}
