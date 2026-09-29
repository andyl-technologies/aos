//! Signed root/path receipts resolve introductions without self-referential hashes.
//!
//! Structural codec validation does not verify signatures or root/path witnesses;
//! those checks belong to provenance. Paths are opaque byte keys.
//! Receipts sort by root and path, while attribute keys sort by encoded CBOR.
//!
//! ```text
//! [root, path, 0]
//! [root, path, [source_commit, source_root, source_path], {name: 0}]
//! [root, path, 0, null, [source_commit, source_root, source_path]]
//! ```

use super::{RecordError, read_digest};
use crate::cbor::{self, Decoder};
use crate::identity::Digest;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A source witness identifying an entry in a verified commit and root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntrySource {
    /// Identity of the signed source commit.
    pub commit: Digest,
    /// Identity of the source tree root.
    pub root: Digest,
    /// Opaque source key, containing one through 4096 bytes.
    pub path: Vec<u8>,
}

/// The signed origin of an entry or attribute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntryOrigin {
    /// The containing commit, whose identity is calculated externally.
    Current,
    /// An entry witness in a verified source commit.
    Source(EntrySource),
}

/// A signed introduction receipt for one root and opaque entry key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryReceipt {
    /// Identity of the tree root containing the entry.
    pub root: Digest,
    /// Opaque entry key, containing one through 4096 bytes.
    pub path: Vec<u8>,
    /// Introduction origin of the entry content; metadata changes preserve it.
    pub origin: EntryOrigin,
    /// Optional attribute introductions, independent of the entry origin.
    pub attributes: Option<Vec<(String, EntryOrigin)>>,
    /// Original source explicitly reintroduced by the current commit.
    pub reintroduced_from: Option<EntrySource>,
}

fn validate_path(path: &[u8]) -> Result<(), RecordError> {
    if !(1..=4096).contains(&path.len()) {
        return Err(RecordError::Schema);
    }
    Ok(())
}

fn encode_source(source: &EntrySource, output: &mut Vec<u8>) -> Result<(), RecordError> {
    validate_path(&source.path)?;
    cbor::write_array(output, 3);
    cbor::write_bytes(output, &source.commit);
    cbor::write_bytes(output, &source.root);
    cbor::write_bytes(output, &source.path);
    Ok(())
}

fn encode_origin(origin: &EntryOrigin, output: &mut Vec<u8>) -> Result<(), RecordError> {
    match origin {
        EntryOrigin::Current => cbor::write_uint(output, 0),
        EntryOrigin::Source(source) => encode_source(source, output)?,
    }
    Ok(())
}

pub(super) fn encode_into(
    receipts: &[EntryReceipt],
    output: &mut Vec<u8>,
) -> Result<(), RecordError> {
    let mut ordered: Vec<_> = receipts.iter().collect();
    ordered
        .sort_unstable_by(|left, right| (&left.root, &left.path).cmp(&(&right.root, &right.path)));
    if ordered
        .windows(2)
        .any(|pair| pair[0].root == pair[1].root && pair[0].path == pair[1].path)
    {
        return Err(RecordError::Schema);
    }

    cbor::write_array(output, ordered.len());
    for receipt in ordered {
        validate_path(&receipt.path)?;
        if receipt.reintroduced_from.is_some() && receipt.origin != EntryOrigin::Current {
            return Err(RecordError::Schema);
        }
        let count = if receipt.reintroduced_from.is_some() {
            5
        } else if receipt.attributes.is_some() {
            4
        } else {
            3
        };
        cbor::write_array(output, count);
        cbor::write_bytes(output, &receipt.root);
        cbor::write_bytes(output, &receipt.path);
        encode_origin(&receipt.origin, output)?;

        if let Some(attributes) = &receipt.attributes {
            if attributes.len() > 256 {
                return Err(RecordError::Schema);
            }
            let mut ordered = Vec::with_capacity(attributes.len());
            for (name, origin) in attributes {
                if !(1..=255).contains(&name.len()) {
                    return Err(RecordError::Schema);
                }
                let mut key = Vec::new();
                cbor::write_text(&mut key, name);
                ordered.push((key, origin));
            }
            ordered.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            if ordered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(RecordError::Schema);
            }
            cbor::write_map(output, ordered.len());
            for (key, origin) in ordered {
                output.extend_from_slice(&key);
                encode_origin(origin, output)?;
            }
        } else if count == 5 {
            output.push(0xf6);
        }
        if let Some(source) = &receipt.reintroduced_from {
            encode_source(source, output)?;
        }
    }
    Ok(())
}

fn decode_path(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, RecordError> {
    let path = decoder.bytes(4096)?;
    validate_path(path)?;
    Ok(path.to_vec())
}

fn decode_source(decoder: &mut Decoder<'_>) -> Result<EntrySource, RecordError> {
    if decoder.array(3)? != 3 {
        return Err(RecordError::Schema);
    }
    Ok(EntrySource {
        commit: read_digest(decoder)?,
        root: read_digest(decoder)?,
        path: decode_path(decoder)?,
    })
}

fn decode_origin(decoder: &mut Decoder<'_>) -> Result<EntryOrigin, RecordError> {
    match decoder.peek_major()? {
        0 if decoder.uint()? == 0 => Ok(EntryOrigin::Current),
        4 => Ok(EntryOrigin::Source(decode_source(decoder)?)),
        _ => Err(RecordError::Schema),
    }
}

fn decode_attributes(decoder: &mut Decoder<'_>) -> Result<Vec<(String, EntryOrigin)>, RecordError> {
    let count = decoder.map(256)?;
    let mut attributes = Vec::with_capacity(count);
    let mut previous: Option<&[u8]> = None;
    for _ in 0..count {
        let start = decoder.position();
        let name = decoder.text(255)?;
        if name.is_empty() {
            return Err(RecordError::Schema);
        }
        let key = decoder.slice(start, decoder.position())?;
        if previous.is_some_and(|prior| prior >= key) {
            return Err(RecordError::Schema);
        }
        previous = Some(key);
        attributes.push((name.to_string(), decode_origin(decoder)?));
    }
    Ok(attributes)
}

pub(super) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Vec<EntryReceipt>, RecordError> {
    // A claimed count is bounded by encoded input before allocating storage.
    let count = decoder.array(decoder.remaining().len())?;
    let mut receipts: Vec<EntryReceipt> = Vec::with_capacity(count);
    for _ in 0..count {
        let fields = decoder.array(5)?;
        if !(3..=5).contains(&fields) {
            return Err(RecordError::Schema);
        }
        let root = read_digest(decoder)?;
        let path = decode_path(decoder)?;
        if receipts
            .last()
            .is_some_and(|previous| (&previous.root, &previous.path) >= (&root, &path))
        {
            return Err(RecordError::Schema);
        }
        let origin = decode_origin(decoder)?;
        let attributes = if fields >= 4 {
            if fields == 5 && decoder.peek_major()? == 7 {
                if decoder.simple()? != 0xf6 {
                    return Err(RecordError::Schema);
                }
                None
            } else {
                Some(decode_attributes(decoder)?)
            }
        } else {
            None
        };
        let reintroduced_from = if fields == 5 {
            if origin != EntryOrigin::Current {
                return Err(RecordError::Schema);
            }
            Some(decode_source(decoder)?)
        } else {
            None
        };
        receipts.push(EntryReceipt {
            root,
            path,
            origin,
            attributes,
            reintroduced_from,
        });
    }
    Ok(receipts)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::vec;

    fn receipt() -> EntryReceipt {
        EntryReceipt {
            root: [1; 32],
            path: vec![0xff, 0],
            origin: EntryOrigin::Current,
            attributes: None,
            reintroduced_from: None,
        }
    }

    fn source() -> EntrySource {
        EntrySource {
            commit: [2; 32],
            root: [3; 32],
            path: vec![0xfe],
        }
    }

    fn decode(bytes: &[u8]) -> Result<Vec<EntryReceipt>, RecordError> {
        let mut decoder = Decoder::new(bytes);
        let receipts = decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(receipts)
    }

    fn encode(receipts: &[EntryReceipt]) -> Vec<u8> {
        let mut bytes = Vec::new();
        encode_into(receipts, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn entry_receipts_roundtrip_all_shapes_and_opaque_paths() {
        let mut receipts = vec![receipt(); 5];
        for (index, receipt) in receipts.iter_mut().enumerate() {
            receipt.root = [index as u8; 32];
        }
        receipts[1].origin = EntryOrigin::Source(source());
        receipts[2].attributes = Some(vec![("attr".into(), EntryOrigin::Source(source()))]);
        receipts[3].reintroduced_from = Some(source());
        receipts[4].attributes = Some(Vec::new());
        receipts[4].reintroduced_from = Some(source());

        let bytes = encode(&receipts);
        assert_eq!(decode(&bytes).unwrap(), receipts);
        for length in 0..bytes.len() {
            assert!(decode(&bytes[..length]).is_err(), "length {length}");
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }

    #[test]
    fn entry_receipts_canonicalize_model_order_and_reject_duplicate_keys() {
        let mut first = receipt();
        first.attributes = Some(vec![
            ("aa".into(), EntryOrigin::Current),
            ("z".into(), EntryOrigin::Current),
        ]);
        let mut second = receipt();
        second.root = [2; 32];
        let bytes = encode(&[second.clone(), first.clone()]);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded[0].attributes.as_ref().unwrap()[0].0, "z");
        assert_eq!(decoded[1], second);
        assert!(encode_into(&[first.clone(), first.clone()], &mut Vec::new()).is_err());
        first.attributes = Some(vec![("z".into(), EntryOrigin::Current); 2]);
        assert!(encode_into(&[first], &mut Vec::new()).is_err());
    }

    #[test]
    fn entry_receipts_reject_wire_order_and_duplicate_receipts() {
        let first = receipt();
        let mut second = receipt();
        second.root = [2; 32];
        let first_bytes = encode(&[first]);
        let second_bytes = encode(&[second]);
        for tail in [&first_bytes[1..], &second_bytes[1..]] {
            let mut bytes = vec![0x82];
            bytes.extend_from_slice(&second_bytes[1..]);
            bytes.extend_from_slice(tail);
            assert!(decode(&bytes).is_err());
        }
    }

    #[test]
    fn entry_receipts_reject_four_element_null_and_source_reintroduction() {
        let bytes = encode(&[receipt()]);
        let mut four = bytes.clone();
        four[1] = 0x84;
        four.push(0xf6);
        assert!(decode(&four).is_err());

        let mut invalid = receipt();
        invalid.origin = EntryOrigin::Source(source());
        invalid.reintroduced_from = Some(source());
        assert!(encode_into(&[invalid.clone()], &mut Vec::new()).is_err());
        invalid.reintroduced_from = None;
        let mut five = encode(&[invalid]);
        five[1] = 0x85;
        five.push(0xf6);
        encode_source(&source(), &mut five).unwrap();
        assert!(decode(&five).is_err());
    }

    #[test]
    fn entry_receipts_reject_claimed_counts_and_deep_unsupported_origins() {
        assert!(decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
        let mut bytes = encode(&[receipt()]);
        bytes.pop();
        bytes.extend_from_slice(&vec![0x81; 100_000]);
        bytes.push(0);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn entry_receipts_reject_noncanonical_attribute_order_and_schema_limits() {
        let mut bytes = encode(&[receipt()]);
        bytes[1] = 0x84;
        bytes.push(0xa2);
        cbor::write_text(&mut bytes, "aa");
        cbor::write_uint(&mut bytes, 0);
        cbor::write_text(&mut bytes, "z");
        cbor::write_uint(&mut bytes, 0);
        assert!(decode(&bytes).is_err());

        for path in [Vec::new(), vec![0; 4097]] {
            let mut invalid = receipt();
            invalid.path = path;
            assert!(encode_into(&[invalid], &mut Vec::new()).is_err());
        }
        for name in [String::new(), "x".repeat(256)] {
            let mut invalid = receipt();
            invalid.attributes = Some(vec![(name, EntryOrigin::Current)]);
            assert!(encode_into(&[invalid], &mut Vec::new()).is_err());
        }
    }
}
