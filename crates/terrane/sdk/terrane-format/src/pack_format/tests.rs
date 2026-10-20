//! Reproduces fixed pack bytes and checks portable structural and bundle codecs.

use super::*;
use crate::cbor::{write_array, write_bytes, write_map, write_text, write_uint};
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
        hash: TERRANE_V1
            .calculate(IdentityKind::Chunk, plaintext)?
            .terrane_v1_digest()?,
        offset: 25,
        body_len: 16,
        plaintext_len: 15,
        codec: 0,
        kind: 0,
        dictionary_id: 0,
    };

    let bytes = encode_pack(header, &bodies, &[hello, empty])?;
    assert_eq!(
        bytes,
        unhex(
            "5452504b01000000000102030405060708090a0b0c0d0e0f000068656c6c6f2c2074657272616e650a5452495802000000000000009479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba01900000000000000100000000f0000000000000000000000b8c424f844a636a1baddbc5fbc1fe533739c7399de74eae490e9f6d50a120dc01800000000000000010000000000000000000000000000002900000000000000a515c3ba54525045"
        )?
    );
    let view = PackView::decode(&bytes)?;
    assert_eq!(
        &bytes[41..bytes.len() - FOOTER_SIZE],
        unhex(
            "5452495802000000000000009479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba01900000000000000100000000f0000000000000000000000b8c424f844a636a1baddbc5fbc1fe533739c7399de74eae490e9f6d50a120dc0180000000000000001000000000000000000000000000000"
        )?
    );
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
fn shard_states_preserve_legacy_bytes_and_register_identity_quarantine() -> Result<(), Error> {
    let (_, record, _) = fixture()?;
    // Independent fixed layout: empty-chunk digest, pack 2a..2a, offset 24,
    // one stored codec byte, zero plaintext bytes, and zero reserved bytes.
    let live_bytes = unhex(concat!(
        "545249580100000000000000",
        "b8c424f844a636a1baddbc5fbc1fe533739c7399de74eae490e9f6d50a120dc0",
        "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
        "1800000000000000",
        "01000000",
        "00000000",
        "0000000000000000"
    ))?;

    for state in 0..=2 {
        let merged = MergedRecord {
            pack: [42; 16],
            record: record.clone(),
            state,
        };
        let mut expected = live_bytes.clone();
        expected[PREAMBLE_SIZE + 66] = state;

        assert_eq!(encode_shard(core::slice::from_ref(&merged)), expected);
        assert_eq!(decode_shard(&expected, record.hash[0])?, vec![merged]);
    }
    Ok(())
}

#[test]
fn shard_states_reject_every_reserved_value() -> Result<(), Error> {
    let (_, record, _) = fixture()?;
    let mut bytes = encode_shard(&[MergedRecord {
        pack: [42; 16],
        record: record.clone(),
        state: 0,
    }]);

    for state in 3..=255 {
        bytes[PREAMBLE_SIZE + 66] = state;
        assert_eq!(decode_shard(&bytes, record.hash[0]), Err(Error::Reserved));
    }
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

fn metadata_objects() -> [(u8, IdentityKind, Vec<u8>); 3] {
    let mut attribute = Vec::new();
    write_map(&mut attribute, 5);
    write_uint(&mut attribute, 1);
    write_bytes(&mut attribute, &[1; 32]);
    write_uint(&mut attribute, 2);
    write_text(&mut attribute, "hash.sha256");
    write_uint(&mut attribute, 3);
    write_bytes(&mut attribute, &[2; 32]);
    write_uint(&mut attribute, 4);
    write_text(&mut attribute, "hash.sha256/1");
    write_uint(&mut attribute, 5);
    write_bytes(&mut attribute, &[3; 32]);

    let mut policy = Vec::new();
    write_map(&mut policy, 4);
    write_uint(&mut policy, 1);
    write_uint(&mut policy, 1);
    write_uint(&mut policy, 3);
    write_array(&mut policy, 0);
    write_uint(&mut policy, 4);
    write_map(&mut policy, 0);
    write_uint(&mut policy, 5);
    write_map(&mut policy, 0);

    let mut memo = Vec::new();
    write_map(&mut memo, 2);
    write_uint(&mut memo, 1);
    write_bytes(&mut memo, &[4; 32]);
    write_uint(&mut memo, 2);
    write_bytes(&mut memo, &[5; 32]);

    [
        (7, IdentityKind::Attribute, attribute),
        (8, IdentityKind::Policy, policy),
        (9, IdentityKind::Memo, memo),
    ]
}

#[test]
fn metadata_domains_roundtrip_portable_packs_indexes_and_shards() -> Result<(), Error> {
    for (kind, domain, bytes) in metadata_objects() {
        validate_metadata(kind, &bytes)?;
        let header = Header::new([29; 16], true, false);
        let record = Record {
            hash: TERRANE_V1.calculate(domain, &bytes)?.terrane_v1_digest()?,
            offset: HEADER_SIZE as u64,
            body_len: bytes.len() as u32,
            plaintext_len: bytes.len() as u32,
            codec: 0,
            kind,
            dictionary_id: 0,
        };
        let pack = encode_pack(header, &bytes, core::slice::from_ref(&record))?;
        let view = PackView::decode(&pack)?;
        assert_eq!(view.records(), core::slice::from_ref(&record));
        let (decoded_header, decoded_records) = decode_detached_index(&view.index_object())?;
        assert_eq!(decoded_header, header);
        assert_eq!(decoded_records.as_slice(), core::slice::from_ref(&record));

        let merged = MergedRecord {
            pack: [29; 16],
            record: record.clone(),
            state: 0,
        };
        assert_eq!(
            decode_shard(
                &encode_shard(core::slice::from_ref(&merged)),
                record.hash[0]
            )?,
            [merged]
        );
        assert_eq!(validate_record(&record, false), Err(Error::Kind));
        let mut compressed = record.clone();
        compressed.codec = 1;
        assert_eq!(validate_record(&compressed, true), Err(Error::Codec));

        for reserved in 10..=u8::MAX {
            let mut unknown = record.clone();
            unknown.kind = reserved;
            assert_eq!(validate_record(&unknown, true), Err(Error::Kind));
            assert_eq!(validate_metadata(reserved, &bytes), Err(Error::Kind));
        }
    }
    Ok(())
}

#[test]
fn metadata_bundle_triples_verify_each_new_identity_domain() -> Result<(), Error> {
    let commit_bytes = [0xa1, 1, 0];
    let root = TERRANE_V1
        .calculate(IdentityKind::Commit, &commit_bytes)?
        .terrane_v1_digest()?;
    let commit = BundleRecord {
        kind: 3,
        hash: root,
        bytes: &commit_bytes,
    };
    for (kind, domain, bytes) in metadata_objects() {
        let object = BundleRecord {
            kind,
            hash: TERRANE_V1.calculate(domain, &bytes)?.terrane_v1_digest()?,
            bytes: &bytes,
        };
        let encoded = encode_bundle(&root, &[commit, object]);
        assert_eq!(decode_bundle(&encoded)?.objects(), &[commit, object]);

        let wrong = BundleRecord {
            kind: if kind == 7 { 8 } else { 7 },
            ..object
        };
        assert!(matches!(
            decode_bundle(&encode_bundle(&root, &[commit, wrong])),
            Err(Error::Identity(_))
        ));
        let reserved = BundleRecord { kind: 10, ..object };
        assert!(matches!(
            decode_bundle(&encode_bundle(&root, &[commit, reserved])),
            Err(Error::Kind)
        ));
    }
    Ok(())
}
