//! Complete encoded pairs at the semantic and transient decoded-byte limits.

use std::io::Write as _;

use flate2::{write::ZlibEncoder, Compression};
use sha2::{Digest as _, Sha256};

use super::projection::{ContentRange, PairReader, Selection};
use super::*;
use crate::object::{hash_object, ObjectKind, Oid};

struct PairFixture {
    path: String,
    pack: Vec<u8>,
    index: Vec<u8>,
    selected_oid: Oid,
}

impl PairFixture {
    fn reader(&self) -> PairReader {
        let mut reader = PairReader::new(&self.path).unwrap();
        for bytes in self.pack.chunks(projection::MAX_FEED_BYTES) {
            reader.feed_pack(bytes).unwrap();
        }
        for bytes in self.index.chunks(projection::MAX_FEED_BYTES) {
            reader.feed_index(bytes).unwrap();
        }
        reader
    }
}

fn append_entry(
    pack: &mut Vec<u8>,
    entries: &mut Vec<IndexEntry>,
    kind: u8,
    data: &[u8],
    oid: Oid,
    base_oid: Option<Oid>,
) {
    let offset = pack.len();
    let mut remaining = data.len() >> 4;
    pack.push((kind << 4) | (data.len() & 15) as u8 | if remaining > 0 { 0x80 } else { 0 });
    while remaining > 0 {
        let byte = (remaining & 127) as u8;
        remaining >>= 7;
        pack.push(byte | if remaining > 0 { 0x80 } else { 0 });
    }
    if let Some(base_oid) = base_oid {
        pack.extend_from_slice(base_oid.as_bytes());
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).unwrap();
    pack.extend_from_slice(&encoder.finish().unwrap());
    entries.push(IndexEntry {
        oid: *oid.as_bytes(),
        crc: crc32fast::hash(&pack[offset..]),
        offset: offset as u64,
    });
}

fn append_varint(bytes: &mut Vec<u8>, mut value: usize) {
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(byte | if value > 0 { 0x80 } else { 0 });
        if value == 0 {
            break;
        }
    }
}

fn reference_delta(full_input: bool) -> (Vec<u8>, Vec<u8>) {
    let mut delta = Vec::new();
    append_varint(&mut delta, MAX_PACK_OBJECT_BYTES);
    append_varint(&mut delta, MAX_PACK_OBJECT_BYTES);
    let mut output = Vec::new();
    if full_input {
        // Reserve the four-byte copy command, then fill the delta's exact
        // 4 MiB input with literal commands. The copied suffix closes the
        // result at 4 MiB despite the literal-command overhead.
        let mut available = MAX_PACK_OBJECT_BYTES - delta.len() - 4;
        while available > 0 {
            let encoded = if available == 129 {
                127
            } else {
                available.min(128)
            };
            assert!(encoded >= 2);
            let literal_bytes = encoded - 1;
            delta.push(literal_bytes as u8);
            delta.resize(delta.len() + literal_bytes, b'z');
            output.resize(output.len() + literal_bytes, b'z');
            available -= encoded;
        }
    } else {
        delta.extend_from_slice(&[1, b'z']);
        output.push(b'z');
    }
    let copied = MAX_PACK_OBJECT_BYTES - output.len();
    delta.push(0xf0); // Copy from offset zero, with all three size bytes present.
    delta.extend_from_slice(&(copied as u32).to_le_bytes()[..3]);
    output.resize(MAX_PACK_OBJECT_BYTES, b'a');
    assert_eq!(
        delta.len(),
        if full_input {
            MAX_PACK_OBJECT_BYTES
        } else {
            14
        }
    );
    (delta, output)
}

fn pair(delta: Option<bool>, extra_byte: bool) -> PairFixture {
    let mut pack = b"PACK".to_vec();
    pack.extend_from_slice(&2_u32.to_be_bytes());
    pack.extend_from_slice(&(8_u32 + u32::from(extra_byte)).to_be_bytes());
    let mut entries = Vec::new();
    let mut selected_oid = None;
    let mut base_oid = None;
    for position in 0..if delta.is_some() { 7 } else { 8 } {
        let data = vec![b'a' + position; MAX_PACK_OBJECT_BYTES];
        let oid = hash_object(ObjectKind::Blob, &data);
        append_entry(&mut pack, &mut entries, 3, &data, oid, None);
        if position == 0 {
            base_oid = Some(oid);
        }
        selected_oid = Some(oid);
    }
    if let Some(full_input) = delta {
        let (data, output) = reference_delta(full_input);
        let oid = hash_object(ObjectKind::Blob, &output);
        append_entry(&mut pack, &mut entries, 7, &data, oid, base_oid);
        selected_oid = Some(oid);
    }
    if extra_byte {
        let data = b"!";
        append_entry(
            &mut pack,
            &mut entries,
            3,
            data,
            hash_object(ObjectKind::Blob, data),
            None,
        );
    }

    let checksum: [u8; 32] = Sha256::digest(&pack).into();
    pack.extend_from_slice(&checksum);
    entries.sort_by_key(|entry| entry.oid);
    let mut index = MAGIC.to_vec();
    index.extend_from_slice(&2_u32.to_be_bytes());
    for byte in 0..256_u16 {
        let count = entries
            .iter()
            .filter(|entry| u16::from(entry.oid[0]) <= byte)
            .count();
        index.extend_from_slice(&(count as u32).to_be_bytes());
    }
    for entry in &entries {
        index.extend_from_slice(&entry.oid);
    }
    for entry in &entries {
        index.extend_from_slice(&entry.crc.to_be_bytes());
    }
    for entry in &entries {
        index.extend_from_slice(&(entry.offset as u32).to_be_bytes());
    }
    index.extend_from_slice(&checksum);
    let index_checksum = Sha256::digest(&index);
    index.extend_from_slice(&index_checksum);
    assert!(pack.len() as u64 <= MAX_PUBLISHED_PACK_BYTES);
    PairFixture {
        path: format!("objects/pack/pack-{}.idx", hex::encode(checksum)),
        pack,
        index,
        selected_oid: selected_oid.unwrap(),
    }
}

#[test]
fn semantic_limit_pair_returns_only_a_bounded_selection() {
    let fixture = pair(None, false);
    validate_against_pack(&fixture.path, &fixture.index, &fixture.pack).unwrap();
    let verified = fixture
        .reader()
        .finish(&[Selection {
            oid: fixture.selected_oid,
            range: Some(ContentRange { start: 0, end: 32 }),
        }])
        .unwrap();
    assert_eq!(verified.inflated_entry_bytes, MAX_DECODED_PACK_BYTES as u64);
    assert_eq!(
        verified.peak_decoded_graph_bytes,
        MAX_DECODED_PACK_BYTES as u64
    );
    assert_eq!(verified.objects[0].content, vec![b'h'; 32]);
    assert_eq!(
        verified.objects[0].object_size,
        MAX_PACK_OBJECT_BYTES as u64
    );
    assert!(fixture
        .reader()
        .finish(&[Selection {
            oid: fixture.selected_oid,
            range: None
        }])
        .is_err());
}

#[test]
fn delta_input_and_replacement_fit_the_distinct_live_limit() {
    let fixture = pair(Some(true), false);
    validate_against_pack(&fixture.path, &fixture.index, &fixture.pack).unwrap();
    let verified = fixture
        .reader()
        .finish(&[Selection {
            oid: fixture.selected_oid,
            range: Some(ContentRange { start: 0, end: 32 }),
        }])
        .unwrap();
    assert_eq!(verified.inflated_entry_bytes, MAX_DECODED_PACK_BYTES as u64);
    assert_eq!(
        verified.peak_decoded_graph_bytes,
        MAX_LIVE_DECODED_PACK_BYTES as u64
    );
    assert_eq!(verified.objects[0].content, vec![b'z'; 32]);
}

#[test]
fn delta_replacement_cannot_exceed_the_semantic_graph_limit() {
    let fixture = pair(Some(false), true);
    assert!(fixture
        .reader()
        .finish(&[])
        .unwrap_err()
        .to_string()
        .contains("remaining decoded-graph budget"));
    assert!(validate_against_pack(&fixture.path, &fixture.index, &fixture.pack).is_err());
}
