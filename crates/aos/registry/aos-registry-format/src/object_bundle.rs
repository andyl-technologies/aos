//! Bounded shard bundles for accelerating loose Git object reads.
//!
//! A registry still publishes every reachable object at its canonical
//! `objects/<xx>/<oid-rest>` path. It may additionally publish one bundle per
//! leading OID byte at `objects/aos-index-v1/<xx>`. The bundle is only a
//! transport optimization: consumers decode and hash-check every selected
//! loose object against its Git OID, and fall back to the canonical path when
//! a bundle is absent.
//!
//! ```text
//! "AOSIDX1\n"
//! repeated {
//!   oid:        [u8; 32]
//!   byte_size:  u32, big endian
//!   loose_zlib: [u8; byte_size]
//! }
//! ```

use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};

use crate::object::{Oid, MAX_PUBLISHED_LOOSE_OBJECT_BYTES};

const MAGIC: &[u8] = b"AOSIDX1\n";
const ENTRY_HEADER_BYTES: usize = 36;

/// Relative directory containing replaceable bundle shards.
pub const DIRECTORY: &str = "objects/aos-index-v1";
/// Relative path of the optional aggregate bundle accelerator.
pub const AGGREGATE_PATH: &str = "objects/aos-index-v1/all";

/// Maximum encoded size of one bundle shard.
pub const MAX_BUNDLE_BYTES: usize = 2 * 1024 * 1024;

/// Maximum number of objects admitted in one bundle shard.
pub const MAX_BUNDLE_OBJECTS: usize = 4096;
/// Maximum encoded size of the optional aggregate bundle.
pub const MAX_AGGREGATE_BUNDLE_BYTES: usize = 32 * 1024 * 1024;
/// Maximum number of objects admitted in the optional aggregate bundle.
pub const MAX_AGGREGATE_BUNDLE_OBJECTS: usize = 65_536;

/// Returns the canonical bundle path for one lowercase hexadecimal shard.
///
/// # Errors
///
/// Returns an error unless `shard` is exactly two lowercase hexadecimal bytes.
pub fn shard_path(shard: &str) -> Result<String> {
    validate_shard(shard)?;
    Ok(format!("{DIRECTORY}/{shard}"))
}

/// Encodes one OID shard from canonical loose-object bytes.
///
/// Entries must belong to `shard`, be ordered by OID, and contain no duplicate.
///
/// # Errors
///
/// Returns an error for an invalid shard, unordered or duplicate OIDs, an
/// oversized loose object, or a shard exceeding the encoded size/object caps.
pub fn encode(shard: &str, entries: &[(Oid, Vec<u8>)]) -> Result<Vec<u8>> {
    validate_shard(shard)?;
    encode_inner(Some(shard), entries, MAX_BUNDLE_BYTES, MAX_BUNDLE_OBJECTS)
}

/// Encodes one aggregate accelerator from globally ordered loose objects.
///
/// # Errors
///
/// Returns an error for unordered or duplicate OIDs, an oversized loose
/// object, or an aggregate exceeding its encoded size/object caps.
pub fn encode_aggregate(entries: &[(Oid, Vec<u8>)]) -> Result<Vec<u8>> {
    encode_inner(
        None,
        entries,
        MAX_AGGREGATE_BUNDLE_BYTES,
        MAX_AGGREGATE_BUNDLE_OBJECTS,
    )
}

fn encode_inner(
    shard: Option<&str>,
    entries: &[(Oid, Vec<u8>)],
    max_bytes: usize,
    max_objects: usize,
) -> Result<Vec<u8>> {
    if entries.len() > max_objects {
        bail!("object bundle exceeds the {max_objects}-object cap");
    }

    let mut encoded = Vec::from(MAGIC);
    let mut previous = None;
    for (oid, loose) in entries {
        let oid_hex = oid.to_hex();
        if let Some(shard) = shard {
            if &oid_hex[..2] != shard {
                bail!("object {oid} does not belong to bundle shard '{shard}'");
            }
        }
        if previous.is_some_and(|previous| previous >= *oid) {
            bail!("object bundle entries must be strictly ordered by OID");
        }
        if loose.len() as u64 > MAX_PUBLISHED_LOOSE_OBJECT_BYTES {
            bail!("object {oid} exceeds the published loose-object size cap");
        }
        let byte_size = u32::try_from(loose.len()).context("loose object size exceeds u32")?;

        encoded.extend_from_slice(oid.as_bytes());
        encoded.extend_from_slice(&byte_size.to_be_bytes());
        encoded.extend_from_slice(loose);
        if encoded.len() > max_bytes {
            bail!("object bundle exceeds the {max_bytes}-byte cap");
        }
        previous = Some(*oid);
    }
    Ok(encoded)
}

/// Decodes one bounded OID shard into canonical loose-object bytes.
///
/// This validates only the bundle framing and OID partition. Consumers must
/// still decode and hash-check each loose object before using it.
///
/// # Errors
///
/// Returns an error for invalid framing, shard membership, ordering, lengths,
/// or size/object cap violations.
pub fn decode(shard: &str, bytes: &[u8]) -> Result<Vec<(Oid, Vec<u8>)>> {
    validate_shard(shard)?;
    decode_inner(Some(shard), bytes, MAX_BUNDLE_BYTES, MAX_BUNDLE_OBJECTS)
}

/// Decodes the optional aggregate accelerator into canonical loose bytes.
///
/// Consumers must still decode and hash-check every selected loose object.
///
/// # Errors
///
/// Returns an error for invalid framing, ordering, lengths, or aggregate
/// size/object cap violations.
pub fn decode_aggregate(bytes: &[u8]) -> Result<Vec<(Oid, Vec<u8>)>> {
    decode_inner(
        None,
        bytes,
        MAX_AGGREGATE_BUNDLE_BYTES,
        MAX_AGGREGATE_BUNDLE_OBJECTS,
    )
}

fn decode_inner(
    shard: Option<&str>,
    bytes: &[u8],
    max_bytes: usize,
    max_objects: usize,
) -> Result<Vec<(Oid, Vec<u8>)>> {
    if bytes.len() > max_bytes {
        bail!("object bundle exceeds the {max_bytes}-byte cap");
    }
    let Some(mut remaining) = bytes.strip_prefix(MAGIC) else {
        bail!("object bundle has an invalid magic header");
    };

    let mut entries = Vec::new();
    let mut observed = BTreeSet::new();
    while !remaining.is_empty() {
        if remaining.len() < ENTRY_HEADER_BYTES {
            bail!("object bundle ends inside an entry header");
        }
        let oid = Oid::from_bytes(&remaining[..32])?;
        let byte_size = u32::from_be_bytes(
            remaining[32..36]
                .try_into()
                .map_err(|_| anyhow::anyhow!("object bundle length header is invalid"))?,
        ) as usize;
        remaining = &remaining[ENTRY_HEADER_BYTES..];
        if byte_size as u64 > MAX_PUBLISHED_LOOSE_OBJECT_BYTES {
            bail!("object {oid} exceeds the published loose-object size cap");
        }
        if remaining.len() < byte_size {
            bail!("object bundle ends inside object {oid}");
        }
        let oid_hex = oid.to_hex();
        if let Some(shard) = shard {
            if &oid_hex[..2] != shard {
                bail!("object {oid} does not belong to bundle shard '{shard}'");
            }
        }
        if !observed.insert(oid) {
            bail!("object bundle repeats object {oid}");
        }
        if entries.last().is_some_and(|(previous, _)| *previous > oid) {
            bail!("object bundle entries are not ordered by OID");
        }

        entries.push((oid, remaining[..byte_size].to_vec()));
        if entries.len() > max_objects {
            bail!("object bundle exceeds the {max_objects}-object cap");
        }
        remaining = &remaining[byte_size..];
    }
    Ok(entries)
}

fn validate_shard(shard: &str) -> Result<()> {
    if shard.len() != 2
        || !shard
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("object bundle shard must be two lowercase hexadecimal bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{encode_loose, hash_object, ObjectKind};

    #[test]
    fn round_trip_preserves_ordered_loose_objects() {
        let mut entries = [b"alpha".as_slice(), b"beta".as_slice()]
            .into_iter()
            .map(|content| {
                let oid = hash_object(ObjectKind::Blob, content);
                let loose = encode_loose(ObjectKind::Blob, content).unwrap();
                (oid, loose)
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|(oid, _)| *oid);
        let shard = &entries[0].0.to_hex()[..2];
        entries.retain(|(oid, _)| &oid.to_hex()[..2] == shard);

        let encoded = encode(shard, &entries).unwrap();
        assert_eq!(decode(shard, &encoded).unwrap(), entries);
    }

    #[test]
    fn malformed_and_cross_shard_entries_fail_closed() {
        assert!(decode("zz", MAGIC).is_err());
        assert!(decode("00", b"wrong").is_err());

        let oid = hash_object(ObjectKind::Blob, b"value");
        let loose = encode_loose(ObjectKind::Blob, b"value").unwrap();
        let wrong = if oid.to_hex().starts_with("00") {
            "01"
        } else {
            "00"
        };
        assert!(encode(wrong, &[(oid, loose)]).is_err());
    }

    #[test]
    fn aggregate_round_trip_accepts_globally_ordered_cross_shard_objects() {
        let mut entries = (0..1_000)
            .map(|value| {
                let content = format!("aggregate object {value}");
                let oid = hash_object(ObjectKind::Blob, content.as_bytes());
                let loose = encode_loose(ObjectKind::Blob, content.as_bytes()).unwrap();
                (oid, loose)
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|(oid, _)| *oid);
        assert_ne!(
            entries.first().unwrap().0.to_hex()[..2],
            entries.last().unwrap().0.to_hex()[..2]
        );

        let encoded = encode_aggregate(&entries).unwrap();

        assert_eq!(decode_aggregate(&encoded).unwrap(), entries);
    }
}
