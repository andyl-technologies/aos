//! Exercises canonical attribute formats, producer versions, and known digests.

use super::*;
use alloc::{string::ToString, vec, vec::Vec};

fn hex(bytes: &[u8]) -> alloc::string::String {
    bytes
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}

#[test]
fn hashes_known_vectors_include_git_header_and_stream_order() {
    let mut hashes = PlaintextHashes::new(3);
    hashes.update(b"a").expect("first segment");
    hashes.update(b"bc").expect("second segment");
    let values = hashes.finish().expect("complete object");
    assert_eq!(
        hex(&values.sha256),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&values.sha512),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_eq!(
        hex(&values.git_blob_sha1),
        "f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f"
    );
    assert_eq!(
        hex(&values.git_blob_sha256),
        "c1cf6e465077930e88dc5136641d402f72a229ddd996f627d60e9639eaba35a6"
    );
}

#[test]
fn hashes_length_is_checked_without_poisoning_state() {
    let mut hashes = PlaintextHashes::new(3);
    assert_eq!(hashes.update(b"abcd"), Err(Error::LengthMismatch));
    hashes.update(b"abc").expect("valid after rejected update");
    assert!(hashes.finish().is_ok());
    assert_eq!(PlaintextHashes::new(1).finish(), Err(Error::LengthMismatch));
    assert_eq!(
        hex(&PlaintextHashes::new(0)
            .finish()
            .expect("empty")
            .git_blob_sha1),
        "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    );
}

#[test]
fn record_canonical_fixture_and_separate_producer_identity() {
    let record = AttrRecord::new([0; 32], AttributeValue::Magic(Magic::Text), [1; 32]);
    let bytes = record.encode().expect("canonical record");
    let mut expected = vec![0xa5, 1, 0x58, 32];
    expected.extend_from_slice(&[0; 32]);
    expected.extend_from_slice(b"\x02\x6bclass.magic\x03\x64text\x04\x67magic/1\x05\x58\x20");
    expected.extend_from_slice(&[1; 32]);
    assert_eq!(bytes, expected);
    assert_eq!(AttrRecord::decode(&bytes), Ok(record.clone()));
    let other = AttrRecord {
        producer: [2; 32],
        ..record.clone()
    };
    assert_eq!(other.value, record.value);
    assert_eq!(other.function, record.function);
    assert_ne!(other.identity(), record.identity());
    assert_eq!(
        record.identity().expect("identity").kind(),
        crate::identity::IdentityKind::Attribute
    );
}

#[test]
fn optional_signature_codec_preserves_legacy_bytes_and_rejects_wrong_lengths() {
    let unsigned = AttrRecord::new([0; 32], AttributeValue::Magic(Magic::Text), [1; 32]);
    let legacy = unsigned.encode().expect("five-field encoding");
    let mut signed = unsigned.clone();
    signed.signature = Some([2; 64]);
    let bytes = signed.encode().expect("six-field encoding");
    let mut expected = legacy.clone();
    expected[0] = 0xa6;
    expected.extend_from_slice(&[6, 0x58, 64]);
    expected.extend_from_slice(&[2; 64]);
    assert_eq!(bytes, expected);
    assert_eq!(AttrRecord::decode(&bytes), Ok(signed));
    assert_eq!(AttrRecord::decode(&legacy), Ok(unsigned));

    let mut shortened = bytes.clone();
    shortened[legacy.len() + 2] = 63;
    shortened.pop();
    assert!(AttrRecord::decode(&shortened).is_err());
    let mut wrong_key = bytes.clone();
    wrong_key[legacy.len()] = 7;
    assert!(AttrRecord::decode(&wrong_key).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(AttrRecord::decode(&trailing).is_err());
}

#[test]
fn registered_values_roundtrip_with_numeric_map_fixtures() {
    let shebang = AttributeValue::Shebang(ShebangValue {
        interpreter: "/bin/bash".to_string(),
        argument: None,
    });
    assert_eq!(
        shebang.encode().expect("value"),
        b"\xa2\x01\x69/bin/bash\x02\xf6"
    );
    let elf = AttributeValue::Elf(ElfValue {
        class: 64,
        machine: 62,
        elf_type: 3,
        interpreter: None,
        needed: vec!["libc.so.6".to_string()],
    });
    assert_eq!(
        elf.encode().expect("value"),
        b"\xa5\x01\x18\x40\x02\x18\x3e\x03\x03\x04\xf6\x05\x81\x69libc.so.6"
    );
    for value in [
        AttributeValue::Sha256([3; 32]),
        AttributeValue::Sha512([4; 64]),
        AttributeValue::GitBlobSha1([5; 20]),
        AttributeValue::GitBlobSha256([6; 32]),
        shebang,
        elf,
    ] {
        let record = AttrRecord::new([9; 32], value, [8; 32]);
        assert_eq!(
            AttrRecord::decode(&record.encode().expect("encode")),
            Ok(record)
        );
    }
}

#[test]
fn dictionary_record_carries_chunk_digest_and_remains_supplied_metadata() {
    let value = AttributeValue::ZstdDictionary([3; 32]);
    let bytes = value.encode().expect("dictionary value");
    let mut expected = vec![0x58, 32];
    expected.extend_from_slice(&[3; 32]);
    assert_eq!(bytes, expected);
    assert_eq!(
        AttributeValue::decode(AttributeName::ZstdDictionary, &bytes),
        Ok(value.clone())
    );
    let record = AttrRecord::new([1; 32], value, [2; 32]);
    assert_eq!(record.value.name().as_str(), "zstd-dictionary");
    assert_eq!(
        AttrRecord::decode(&record.encode().expect("dictionary record")),
        Ok(record.clone())
    );
    assert_eq!(
        record.verify_value(&record.value),
        Err(Error::UnsupportedFunction)
    );
    assert!(AttributeValue::decode(AttributeName::ZstdDictionary, b"\x43abc").is_err());
    assert_ne!(
        record.identity().expect("attribute identity").digest(),
        &[3; 32]
    );
}

#[test]
fn unknown_function_versions_are_retained_but_never_verified() {
    let mut record = AttrRecord::new([1; 32], AttributeValue::Magic(Magic::Text), [2; 32]);
    record.function.version = "2".to_string();
    assert_eq!(
        AttrRecord::decode(&record.encode().expect("future version")),
        Ok(record.clone())
    );
    assert_eq!(
        record.verify_value(&record.value),
        Err(Error::UnsupportedFunction)
    );
    record.function = Function {
        name: "another-producer".to_string(),
        version: "1".to_string(),
    };
    assert_eq!(
        record.verify_value(&record.value),
        Err(Error::UnsupportedFunction)
    );
    record.function.version = "1/2".to_string();
    assert_eq!(record.encode(), Err(Error::InvalidFunction));
}

#[test]
fn strict_codec_rejects_schema_mismatch_noncanonical_keys_and_trailers() {
    let record = AttrRecord::new([1; 32], AttributeValue::Magic(Magic::Text), [2; 32]);
    let original = record.encode().expect("encode");
    for end in 0..original.len() {
        assert!(AttrRecord::decode(&original[..end]).is_err());
    }
    let mut duplicate = original.clone();
    // The second key follows the first key's two-byte bstr header and digest.
    duplicate[36] = 1;
    assert!(AttrRecord::decode(&duplicate).is_err());
    let mut nonminimal = original.clone();
    nonminimal.splice(1..2, [0x18, 1]);
    assert!(AttrRecord::decode(&nonminimal).is_err());
    let mut trailer = original;
    trailer.push(0);
    assert!(AttrRecord::decode(&trailer).is_err());
    assert!(AttributeValue::decode(AttributeName::Sha256, b"\x43abc").is_err());
    assert!(AttributeValue::decode(AttributeName::Magic, b"\x63zip").is_err());
    assert!(AttributeValue::decode(AttributeName::Shebang, b"\xa2\x01\x64bash\x02\xf6").is_err());
}

#[test]
fn inline_and_recomputation_require_exact_typed_agreement() {
    let record = AttrRecord::new([1; 32], AttributeValue::Magic(Magic::Text), [2; 32]);
    assert_eq!(record.agree_inline(b"\x64text"), Ok(()));
    assert_eq!(
        record.agree_inline(b"\x65other"),
        Err(Error::InlineDisagreement)
    );
    assert_eq!(
        record.verify_value(&AttributeValue::Magic(Magic::Other)),
        Err(Error::InvalidValue)
    );
}

#[test]
fn magic_signature_precedence_and_exact_prefix_bound() {
    for (bytes, result) in [
        (b"\x7fELF".as_slice(), Magic::Elf),
        (b"#!/bin/bash", Magic::Shebang),
        (b"!<arch>\n", Magic::Ar),
        (&[0x28, 0xb5, 0x2f, 0xfd], Magic::Zstd),
        (&[0x1f, 0x8b], Magic::Gzip),
        (b"hello\t\n", Magic::Text),
        (b"hi\0", Magic::Other),
    ] {
        assert_eq!(classify_magic(bytes), result);
    }
    let mut tar = vec![0; 512];
    tar[257..263].copy_from_slice(b"ustar\0");
    assert_eq!(classify_magic(&tar), Magic::Tar);
    let mut text = vec![b'a'; MAGIC_PREFIX_LIMIT];
    text.push(0);
    assert_eq!(classify_magic(&text), Magic::Text);
}

#[test]
fn shebang_first_line_is_bounded_and_preserves_unsplit_arguments() {
    assert_eq!(
        parse_shebang(b"#! \t/bin/env python3 -u \r\nignored", false),
        Ok(ShebangValue {
            interpreter: "/bin/env".to_string(),
            argument: Some("python3 -u".to_string())
        })
    );
    assert_eq!(
        parse_shebang(b"#!/bin/bash", true)
            .expect("EOF line")
            .argument,
        None
    );
    for bytes in [
        b"#!bash\n".as_slice(),
        b"#!\n",
        b"#!/bin/bash\0\n",
        b"#!/\xff\n",
    ] {
        assert_eq!(parse_shebang(bytes, true), Err(Error::MalformedExecutable));
    }
    assert_eq!(
        parse_shebang(b"#!/bin/bash", false),
        Err(Error::MalformedExecutable)
    );
    let mut long = vec![b'a'; MAGIC_PREFIX_LIMIT + 1];
    long[..3].copy_from_slice(b"#!/");
    assert_eq!(parse_shebang(&long, false), Err(Error::MalformedExecutable));
}

fn elf64(little: bool) -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[5] = if little { 1 } else { 2 };
    if little {
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    } else {
        bytes[16..18].copy_from_slice(&3u16.to_be_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_be_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_be_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_be_bytes());
    }
    bytes
}

#[test]
fn elf_header_accepts_both_orders_and_rejects_forged_ranges() {
    for little in [true, false] {
        let bytes = elf64(little);
        let header = parse_elf_header(&bytes, 64).expect("valid ELF64");
        assert_eq!(
            (
                header.value.class,
                header.value.machine,
                header.value.elf_type
            ),
            (64, 62, 3)
        );
    }
    let mut bytes = elf64(true);
    bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    assert!(parse_elf_header(&bytes, u64::MAX).is_err());
    for end in 0..64 {
        assert!(parse_elf_header(&bytes[..end], 64).is_err());
    }
}

#[test]
fn elf_program_and_dynamic_parsers_reject_partial_or_ambiguous_tables() {
    let header = parse_elf_header(&elf64(true), 64).expect("header");
    assert!(parse_elf_programs(&header, &[0; 55], 64).is_err());
    let mut program = vec![0; 56];
    program[..4].copy_from_slice(&1u32.to_le_bytes());
    program[32..40].copy_from_slice(&65u64.to_le_bytes());
    program[40..48].copy_from_slice(&65u64.to_le_bytes());
    assert!(parse_elf_programs(&header, &program, 64).is_err());
    let mut dynamic = Vec::new();
    for (tag, value) in [(1u64, 7u64), (1, 9), (5, 0x4000), (10, 32), (0, 0), (1, 20)] {
        dynamic.extend_from_slice(&tag.to_le_bytes());
        dynamic.extend_from_slice(&value.to_le_bytes());
    }
    let parsed = parse_elf_dynamic(&header, &dynamic).expect("dynamic");
    assert_eq!(parsed.needed, vec![7, 9]);
    assert_eq!(parsed.string_address, Some(0x4000));
    assert!(parsed.terminated);
    assert!(parse_elf_dynamic(&header, &dynamic[..15]).is_err());
    let duplicate = [&dynamic[32..48], &dynamic[32..48]].concat();
    assert!(parse_elf_dynamic(&header, &duplicate).is_err());
}
