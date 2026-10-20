//! Serializes hash-prefix merged shards without publication or adapter state.
//!
//! ```text
//! TRIX | count:u64le | (hash:32, pack:16, offset:8, stored:4, plain:4,
//!                       codec:1, kind:1, state:1, reserved:5)*
//! ```

use super::{Error, PREAMBLE_SIZE, Record, array, index_count, validate_record};
use alloc::vec::Vec;

/// A raw merged-shard record whose fields are validated during decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergedRecord {
    /// The identifier of the pack holding the body.
    pub pack: [u8; 16],
    /// The content location, kind, and codec.
    pub record: Record,
    /// The state: zero live, one GC tombstone, or two identity quarantine.
    pub state: u8,
}

/// Serializes exact shard records in the supplied order.
///
/// Callers use validated, hash-sorted records; decoding validates untrusted bytes.
pub fn encode_shard(records: &[MergedRecord]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"TRIX");
    bytes.extend_from_slice(&(records.len() as u64).to_le_bytes());
    for entry in records {
        bytes.extend_from_slice(&entry.record.hash);
        bytes.extend_from_slice(&entry.pack);
        bytes.extend_from_slice(&entry.record.offset.to_le_bytes());
        bytes.extend_from_slice(&entry.record.body_len.to_le_bytes());
        bytes.extend_from_slice(&entry.record.plaintext_len.to_le_bytes());
        bytes.push(entry.record.codec);
        bytes.push(entry.record.kind);
        bytes.push(entry.state);
        bytes.extend_from_slice(&[0; 5]);
    }
    bytes
}

/// Decodes a complete shard belonging to one first-byte hash prefix.
///
/// # Errors
/// Rejects malformed counts, unknown/reserved fields, invalid locations,
/// another hash prefix, nonascending hashes, or duplicate identities.
pub fn decode_shard(bytes: &[u8], shard: u8) -> Result<Vec<MergedRecord>, Error> {
    let count = index_count(bytes, 72)?;
    let mut records: Vec<MergedRecord> = Vec::with_capacity(count);
    for body in bytes[PREAMBLE_SIZE..].as_chunks::<72>().0 {
        if array::<5>(body, 67)? != [0; 5] || body[66] > 2 {
            return Err(Error::Reserved);
        }
        let record = Record {
            hash: array(body, 0)?,
            offset: u64::from_le_bytes(array(body, 48)?),
            body_len: u32::from_le_bytes(array(body, 56)?),
            plaintext_len: u32::from_le_bytes(array(body, 60)?),
            codec: body[64],
            kind: body[65],
            dictionary_id: 0,
        };
        validate_record(&record, record.kind != 0)?;
        if record.hash[0] != shard
            || records
                .last()
                .is_some_and(|previous| previous.record.hash >= record.hash)
        {
            return Err(Error::Index);
        }
        records.push(MergedRecord {
            pack: array(body, 32)?,
            record,
            state: body[66],
        });
    }
    Ok(records)
}
