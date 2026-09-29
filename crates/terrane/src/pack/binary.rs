//! Encodes and validates fixed-width pack headers and index records.
//!
//! ```text
//! TRIX | count:u64le | (hash:32, offset:8, stored:4, plain:4,
//!                       codec:1, kind:1, dictionary:2, reserved:4)*
//! ```

use super::{
    Codec, EntryKind, HEADER_SIZE, INDEX_ENTRY_SIZE, IndexEntry, PackClass, PackError, PackHeader,
    PackId,
};

pub(super) const PREAMBLE_SIZE: usize = 12;

pub(super) fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], PackError> {
    bytes
        .get(offset..offset.checked_add(N).ok_or(PackError::Limit)?)
        .ok_or(PackError::Malformed)?
        .try_into()
        .map_err(|_| PackError::Malformed)
}

pub(super) fn encode_header(header: PackHeader) -> Vec<u8> {
    let mut output = Vec::with_capacity(HEADER_SIZE);
    output.extend_from_slice(b"TRPK");
    output.extend_from_slice(&1_u16.to_le_bytes());
    let flags = u16::from(header.compressed_default)
        | if header.class == PackClass::Meta {
            2
        } else {
            0
        };
    output.extend_from_slice(&flags.to_le_bytes());
    output.extend_from_slice(header.id.as_bytes());
    output
}

pub(super) fn decode_header(bytes: &[u8]) -> Result<PackHeader, PackError> {
    if array::<4>(bytes, 0)? != *b"TRPK" || u16::from_le_bytes(array(bytes, 4)?) != 1 {
        return Err(PackError::Version);
    }
    let flags = u16::from_le_bytes(array(bytes, 6)?);
    if flags & !3 != 0 {
        return Err(PackError::Reserved);
    }
    Ok(PackHeader {
        id: PackId(array(bytes, 8)?),
        class: if flags & 2 == 0 {
            PackClass::Data
        } else {
            PackClass::Meta
        },
        compressed_default: flags & 1 != 0,
    })
}

pub(super) fn encode_index(entries: &[IndexEntry]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(b"TRIX");
    output.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for entry in entries {
        output.extend_from_slice(&entry.hash);
        output.extend_from_slice(&entry.offset.to_le_bytes());
        output.extend_from_slice(&entry.body_len.to_le_bytes());
        output.extend_from_slice(&entry.plaintext_len.to_le_bytes());
        output.push(entry.codec as u8);
        output.push(entry.kind as u8);
        output.extend_from_slice(&entry.dictionary_id.to_le_bytes());
        output.extend_from_slice(&[0; 4]);
    }
    output
}

pub(super) fn index_count(bytes: &[u8], width: usize) -> Result<usize, PackError> {
    if array::<4>(bytes, 0)? != *b"TRIX" {
        return Err(PackError::Version);
    }
    let count =
        usize::try_from(u64::from_le_bytes(array(bytes, 4)?)).map_err(|_| PackError::Limit)?;
    let expected = count
        .checked_mul(width)
        .and_then(|size| size.checked_add(PREAMBLE_SIZE))
        .ok_or(PackError::Limit)?;
    if expected != bytes.len() {
        return Err(PackError::Index);
    }
    Ok(count)
}

pub(super) fn decode_index(bytes: &[u8], header: PackHeader) -> Result<Vec<IndexEntry>, PackError> {
    let count = index_count(bytes, INDEX_ENTRY_SIZE)?;
    let mut entries = Vec::with_capacity(count);
    for bytes in bytes[PREAMBLE_SIZE..].as_chunks::<INDEX_ENTRY_SIZE>().0 {
        if array::<4>(bytes, 52)? != [0; 4] {
            return Err(PackError::Reserved);
        }
        let entry = IndexEntry {
            hash: array(bytes, 0)?,
            offset: u64::from_le_bytes(array(bytes, 32)?),
            body_len: u32::from_le_bytes(array(bytes, 40)?),
            plaintext_len: u32::from_le_bytes(array(bytes, 44)?),
            codec: Codec::try_from(bytes[48])?,
            kind: EntryKind::try_from(bytes[49])?,
            dictionary_id: u16::from_le_bytes(array(bytes, 50)?),
        };
        validate_entry(&entry, header.class)?;
        if let Some(previous) = entries.last() {
            let previous: &IndexEntry = previous;
            if previous.hash >= entry.hash {
                return Err(if previous.hash == entry.hash {
                    PackError::Duplicate
                } else {
                    PackError::Index
                });
            }
        }
        entries.push(entry);
    }
    Ok(entries)
}

pub(super) fn validate_entry(entry: &IndexEntry, class: PackClass) -> Result<(), PackError> {
    if (entry.kind == EntryKind::Chunk) != (class == PackClass::Data) {
        return Err(PackError::Kind);
    }
    if entry.dictionary_id != 0 {
        return Err(PackError::Codec);
    }
    if class == PackClass::Meta && entry.codec != Codec::Raw {
        return Err(PackError::Codec);
    }
    if entry.codec == Codec::Raw {
        // CDDL chunk bodies include the codec byte; metadata stays canonical.
        let envelope = u32::from(entry.kind == EntryKind::Chunk);
        if entry.plaintext_len.checked_add(envelope) != Some(entry.body_len) {
            return Err(PackError::Index);
        }
    }
    if entry.offset < HEADER_SIZE as u64 || entry.body_len == 0 {
        return Err(PackError::Index);
    }
    Ok(())
}

/// Computes reflected CRC32C (Castagnoli), including initial and final inversion.
pub(super) fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
