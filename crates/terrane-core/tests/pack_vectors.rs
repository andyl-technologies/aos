//! Checks published pack witnesses against separately constructed public models.
//!
//! Positive cases compare bytes, container identities, chunk identities and
//! decoded models. Negative wires use primitive field assembly rather than the
//! pack encoder, isolating CRC and reserved-field rejection without I/O.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use terrane_core::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_core::pack_format::{
    Error, Header, PackView, Record, decode_detached_index, encode_index, encode_pack,
};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md"
));

const PLAINTEXTS: [&[u8]; 2] = [b"hello\n", b"world\n"];

fn section(name: &str) -> &str {
    let marker = format!("### {name}\n");
    REFERENCE
        .split_once(&marker)
        .expect("published pack vector is required")
        .1
        .split("\n##")
        .next()
        .unwrap()
}

fn wire(name: &str) -> Vec<u8> {
    let hex = section(name)
        .split_once("```hex\n")
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0;
    let digits: String = hex.chars().filter(|ch| !ch.is_ascii_whitespace()).collect();
    assert_eq!(digits.len() % 2, 0);
    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

fn fixture() -> (Header, Vec<u8>, Vec<Record>) {
    let header = Header::new(core::array::from_fn(|index| index as u8), false, false);
    let mut bodies = Vec::new();
    let mut records = Vec::new();
    for plaintext in PLAINTEXTS {
        let offset = 24 + bodies.len() as u64;
        bodies.push(0);
        bodies.extend_from_slice(plaintext);

        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, plaintext)
            .unwrap();
        records.push(Record {
            hash: identity.digest().try_into().unwrap(),
            offset,
            body_len: 7,
            plaintext_len: 6,
            codec: 0,
            kind: 0,
            dictionary_id: 0,
        });
    }
    records.sort_by_key(|record| record.hash);
    (header, bodies, records)
}

fn assert_identity(name: &str, kind: IdentityKind, bytes: &[u8]) {
    let identity = TERRANE_V1.calculate(kind, bytes).unwrap();
    let expected = section(name)
        .lines()
        .find(|line| line.starts_with("blake3:"))
        .unwrap();
    let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, bytes).unwrap();
    assert_eq!(descriptor.to_string(), expected);
}

#[test]
fn published_pack_matches_independent_bytes_and_model() {
    let (header, bodies, records) = fixture();
    let published = wire("pack-two-entry");

    assert_eq!(encode_pack(header, &bodies, &records).unwrap(), published);
    assert_identity("pack-two-entry", IdentityKind::Pack, &published);
    let decoded = PackView::decode(&published).unwrap();

    assert_eq!(decoded.header(), header);
    assert_eq!(decoded.records(), records);
    assert_eq!(decoded.index_offset(), 38);
    assert_eq!(&published[24..38], bodies);
    assert_eq!(decoded.index_object(), wire("pack-detached-index"));
    for record in decoded.records() {
        let offset = usize::try_from(record.offset).unwrap();
        let length = usize::try_from(record.body_len).unwrap();
        let plaintext = &published[offset + 1..offset + length];
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, plaintext)
            .unwrap();
        assert_eq!(identity.digest(), record.hash);
        assert!(PLAINTEXTS.contains(&plaintext));
    }
}

#[test]
fn published_detached_index_matches_independent_bytes_and_model() {
    let (header, _, records) = fixture();
    let published = wire("pack-detached-index");
    let mut encoded = header.encode();
    encoded.extend_from_slice(&encode_index(&records));

    assert_eq!(encoded, published);
    assert_identity("pack-detached-index", IdentityKind::Index, &published);
    assert_eq!(
        decode_detached_index(&published).unwrap(),
        (header, records)
    );
}

fn independent_crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0x82f6_3b78
            };
        }
    }
    !crc
}

fn independent_wire(reserved: bool, flip_crc: bool) -> Vec<u8> {
    let (_, bodies, records) = fixture();
    let mut bytes = b"TRPK".to_vec();
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend(0_u8..16);
    bytes.extend_from_slice(&bodies);

    let mut index = b"TRIX".to_vec();
    index.extend_from_slice(&2_u64.to_le_bytes());
    for (position, record) in records.iter().enumerate() {
        index.extend_from_slice(&record.hash);
        index.extend_from_slice(&record.offset.to_le_bytes());
        index.extend_from_slice(&7_u32.to_le_bytes());
        index.extend_from_slice(&6_u32.to_le_bytes());
        index.extend_from_slice(&[0; 4]);
        index.extend_from_slice(&[u8::from(reserved && position == 0), 0, 0, 0]);
    }
    let crc = independent_crc32c(&index) ^ u32::from(flip_crc);
    bytes.extend_from_slice(&index);
    bytes.extend_from_slice(&38_u64.to_le_bytes());
    bytes.extend_from_slice(&crc.to_le_bytes());
    bytes.extend_from_slice(b"TRPE");
    bytes
}

#[test]
fn published_pack_rejects_corrupt_index_crc() {
    let published = wire("pack-bad-crc");
    assert_eq!(independent_wire(false, true), published);
    assert_eq!(PackView::decode(&published).unwrap_err(), Error::Crc);
}

#[test]
fn published_pack_rejects_reserved_index_bytes() {
    let published = wire("pack-reserved-index");
    assert_eq!(independent_wire(true, false), published);
    assert_eq!(PackView::decode(&published).unwrap_err(), Error::Reserved);
}
