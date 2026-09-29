//! Reproduces fixed pack bytes and checks portable structural and bundle codecs.

use super::*;
use crate::identity::{IdentityKind, TERRANE_V1};
use alloc::vec;
use alloc::vec::Vec;

fn fixture() -> Result<(Header, Record, Vec<u8>), Error> {
    let header = Header::new(core::array::from_fn(|index| index as u8), false, false);
    let hash = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"")?
        .terrane_v1_digest()?;
    let record = Record {
        hash,
        offset: 24,
        body_len: 1,
        plaintext_len: 0,
        codec: 0,
        kind: 0,
        dictionary_id: 0,
    };
    Ok((header, record, vec![0]))
}

fn unhex(text: &str) -> Result<Vec<u8>, Error> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16).ok_or(Error::Malformed)?;
            let low = char::from(pair[1]).to_digit(16).ok_or(Error::Malformed)?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}

#[test]
fn pack_bytes_are_reproducible_without_native_code_or_io() -> Result<(), Error> {
    let (header, record, bodies) = fixture()?;
    // Fixed fixture: codec-zero empty chunk, normative empty-chunk digest,
    // identifier bytes 00..0f, index offset 25, CRC32C 0x3efc3763.
    let expected = unhex(concat!(
        "5452504b01000000000102030405060708090a0b0c0d0e0f00",
        "545249580100000000000000",
        "b8c424f844a636a1baddbc5fbc1fe533739c7399de74eae490e9f6d50a120dc0",
        "180000000000000001000000000000000000000000000000",
        "19000000000000006337fc3e54525045"
    ))?;
    let bytes = encode_pack(header, &bodies, core::slice::from_ref(&record))?;
    assert_eq!(bytes, expected);
    let view = PackView::decode(&bytes)?;
    assert_eq!(view.header(), header);
    assert_eq!(view.records(), &[record]);
    assert_eq!(view.index_offset(), 25);
    assert_eq!(
        view.index_object(),
        [
            header.encode(),
            expected[25..expected.len() - FOOTER_SIZE].to_vec()
        ]
        .concat()
    );
    assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    Ok(())
}

#[test]
fn two_entry_pack_matches_independently_proposed_vector() -> Result<(), Error> {
    let (header, empty, mut bodies) = fixture()?;
    let plaintext = b"hello, terrane\n";
    bodies.push(0);
    bodies.extend_from_slice(plaintext);
    let hello = Record {
        hash: TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?.terrane_v1_digest()?,
        offset: 25,
        body_len: 16,
        plaintext_len: 15,
        codec: 0,
        kind: 0,
        dictionary_id: 0,
    };

    let bytes = encode_pack(header, &bodies, &[hello, empty])?;
    assert_eq!(bytes, unhex("5452504b01000000000102030405060708090a0b0c0d0e0f000068656c6c6f2c2074657272616e650a5452495802000000000000009479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba01900000000000000100000000f0000000000000000000000b8c424f844a636a1baddbc5fbc1fe533739c7399de74eae490e9f6d50a120dc01800000000000000010000000000000000000000000000002900000000000000a515c3ba54525045")?);
    let view = PackView::decode(&bytes)?;
    assert_eq!(view.index_object(), unhex("5452495802000000000000009479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba01900000000000000100000000f0000000000000000000000b8c424f844a636a1baddbc5fbc1fe533739c7399de74eae490e9f6d50a120dc0180000000000000001000000000000000000000000000000")?);
    assert_eq!(view.index_offset(), 41);
    assert_eq!(crc32c(&bytes[41..bytes.len() - FOOTER_SIZE]), 0xbac3_15a5);
    assert_eq!(bytes.len(), 181);
    Ok(())
}

#[test]
fn core_writer_rejects_overlaps_unknown_fields_and_unindexed_bodies() -> Result<(), Error> {
    let (header, record, bodies) = fixture()?;
    let mut bad = record.clone();
    bad.offset = 0;
    assert!(encode_pack(header, &bodies, &[bad]).is_err());
    let mut bad = record.clone();
    bad.dictionary_id = 1;
    assert_eq!(encode_pack(header, &bodies, &[bad]), Err(Error::Reserved));
    let mut bad = record.clone();
    bad.codec = 3;
    assert_eq!(encode_pack(header, &bodies, &[bad]), Err(Error::Codec));
    assert!(encode_pack(header, &[0, 0], core::slice::from_ref(&record)).is_err());
    assert_eq!(
        encode_pack(header, &bodies, &[record.clone(), record]),
        Err(Error::Duplicate)
    );
    Ok(())
}

#[test]
fn core_reader_rejects_crc_reserved_header_and_truncated_tail() -> Result<(), Error> {
    let (header, record, bodies) = fixture()?;
    let bytes = encode_pack(header, &bodies, &[record])?;
    let mut bad_crc = bytes.clone();
    let crc_position = bad_crc.len() - 8;
    bad_crc[crc_position] ^= 1;
    assert!(matches!(PackView::decode(&bad_crc), Err(Error::Crc)));
    let mut bad_header = bytes.clone();
    bad_header[6] |= 4;
    assert!(matches!(
        PackView::decode(&bad_header),
        Err(Error::Reserved)
    ));
    assert!(PackView::decode(&bytes[..bytes.len() - 1]).is_err());
    Ok(())
}

#[test]
fn pure_shard_and_bundle_codecs_verify_and_round_trip() -> Result<(), Error> {
    let (_, record, _) = fixture()?;
    let merged = MergedRecord {
        pack: [42; 16],
        record,
        state: 1,
    };
    let encoded_shard = encode_shard(core::slice::from_ref(&merged));
    assert_eq!(
        decode_shard(&encoded_shard, merged.record.hash[0])?,
        vec![merged]
    );
    let plaintext = b"bundle plaintext";
    let object = BundleRecord {
        kind: 0,
        hash: TERRANE_V1
            .calculate(IdentityKind::Chunk, plaintext)?
            .terrane_v1_digest()?,
        bytes: plaintext,
    };
    let encoded_bundle = encode_bundle(&[1; 32], &[object]);
    assert_eq!(bundle_size(&[object])?, encoded_bundle.len());
    let view = decode_bundle(&encoded_bundle)?;
    assert_eq!(*view.root_commit(), [1; 32]);
    assert_eq!(view.objects(), &[object]);
    let mut bad = encoded_bundle;
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(matches!(decode_bundle(&bad), Err(Error::Identity(_))));
    Ok(())
}

#[test]
fn metadata_canonical_validation_accepts_deep_input_without_a_guessed_schema_limit()
-> Result<(), Error> {
    let mut bytes = vec![0x81; 128];
    bytes.push(0);
    validate_metadata(3, &bytes)?;
    bytes.pop();
    assert!(validate_metadata(3, &bytes).is_err());
    Ok(())
}
