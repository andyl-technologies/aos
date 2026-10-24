//! Checks common Memo schema routing without establishing recipe relationships.

#![allow(
    clippy::unwrap_used,
    reason = "fixtures assert structural validation outcomes"
)]

use super::*;
use std::error::Error;
use terrane_format::derivation::{Memo, MemoError};

fn frame(recipe: &[u8], root: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xa2, 1, 0x58, recipe.len() as u8];
    bytes.extend_from_slice(recipe);
    bytes.extend_from_slice(&[2, 0x58, root.len() as u8]);
    bytes.extend_from_slice(root);
    bytes
}

#[test]
fn memo_metadata_validator_accepts_exact_common_schema() {
    let validator = MetadataValidator::new(ChunkProfile::cdc_1m([42; 32]));
    let bytes = frame(&[0x11; 32], &[0x22; 32]);
    let upload = MetaUpload::new(IdentityKind::Memo, &bytes).unwrap();

    assert_eq!(bytes.len(), 71);
    let result = validator.validate_meta(&upload);
    assert!(result.is_ok(), "canonical Memo refused: {result:?}");
    assert!(validator.chunk_requirements(&upload).unwrap().is_empty());
}

fn refuses(validator: &MetadataValidator, bytes: &[u8]) {
    let expected = Memo::decode(bytes).unwrap_err();
    let upload = MetaUpload::new(IdentityKind::Memo, bytes).unwrap();
    let failure = validator.validate_meta(&upload).unwrap_err();

    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "DRV-21" })
    );
    let source = failure
        .source()
        .unwrap()
        .downcast_ref::<MemoError>()
        .unwrap();
    assert_eq!(*source, expected);
    if let MemoError::Encoding(cause) = expected {
        assert_eq!(
            source
                .source()
                .unwrap()
                .downcast_ref::<terrane_format::cbor::Error>(),
            Some(&cause)
        );
    }
}

#[test]
fn memo_metadata_validator_refuses_malformed_schema_and_recipe_bytes() {
    let validator = MetadataValidator::new(ChunkProfile::cdc_1m([42; 32]));
    let valid = frame(&[0x11; 32], &[0x22; 32]);
    for length in 0..valid.len() {
        refuses(&validator, &valid[..length]);
    }

    for (offset, byte) in [
        (0, 0xa1),
        (0, 0xa3),
        (0, 0x82),
        (0, 0xbf),
        (1, 0x02),
        (1, 0x61),
        (36, 0x01),
        (36, 0x03),
        (2, 0x78),
        (37, 0x78),
        (2, 0x5f),
        (37, 0x5f),
    ] {
        let mut bytes = valid.clone();
        bytes[offset] = byte;
        refuses(&validator, &bytes);
    }
    let mut reordered = valid.clone();
    reordered[1] = 2;
    reordered[36] = 1;
    refuses(&validator, &reordered);
    for bytes in [
        frame(&[0x11; 31], &[0x22; 32]),
        frame(&[0x11; 32], &[0x22; 31]),
        frame(&[0x11; 33], &[0x22; 32]),
        frame(&[0x11; 32], &[0x22; 33]),
    ] {
        refuses(&validator, &bytes);
    }
    for (offset, header, argument) in [(0, 0xb8, 2), (1, 0x18, 1), (2, 0x59, 0), (37, 0x59, 0)] {
        let mut bytes = valid.clone();
        bytes[offset] = header;
        bytes.insert(offset + 1, argument);
        bytes.pop();
        assert_eq!(
            Memo::decode(&bytes),
            Err(MemoError::Encoding(
                terrane_format::cbor::Error::NonCanonical
            ))
        );
        refuses(&validator, &bytes);
    }
    let mut trailing = valid;
    trailing.push(0);
    refuses(&validator, &trailing);
    // This is a canonical retained recipe, not the common two-digest record.
    refuses(&validator, b"\xa2\x01\x67overlay\x02\x80");
}

#[test]
fn memo_metadata_validator_preserves_existing_domain_dispatch() {
    let validator = MetadataValidator::new(ChunkProfile::cdc_1m([42; 32]));
    let empty_node = b"\xa2\x01\x00\x02\x80";
    let upload = MetaUpload::new(IdentityKind::Node, empty_node).unwrap();
    assert!(validator.validate_meta(&upload).is_ok());

    for (kind, rule_id) in [
        (IdentityKind::Manifest, "OBJ-15"),
        (IdentityKind::Node, "TREE-25"),
        (IdentityKind::Commit, "REF-9"),
        (IdentityKind::Attribute, "DRV-1"),
    ] {
        let upload = MetaUpload::new(kind, b"\xff").unwrap();
        let failure = validator.validate_meta(&upload).unwrap_err();
        assert_eq!(
            failure.kind(),
            &StoreErrorKind::Invalid(InvalidReason::Upload { rule_id })
        );
        assert!(failure.source().is_none());
    }
    for kind in [
        IdentityKind::Bundle,
        IdentityKind::Pack,
        IdentityKind::Index,
        IdentityKind::Filter,
        IdentityKind::Policy,
    ] {
        let upload = MetaUpload::new(kind, empty_node).unwrap();
        let failure = validator.validate_meta(&upload).unwrap_err();
        assert_eq!(failure.kind(), &StoreErrorKind::Unsupported);
        assert!(failure.source().is_none());
    }
}

#[test]
fn memo_metadata_validator_has_no_chunk_requirements() {
    let validator = MetadataValidator::new(ChunkProfile::cdc_1m([42; 32]));
    let bytes = frame(&[0x11; 32], &[0x22; 32]);
    for bytes in [bytes.as_slice(), b"\xff", b"\xa2\x01\x67overlay\x02\x80"] {
        let upload = MetaUpload::new(IdentityKind::Memo, bytes).unwrap();
        assert!(validator.chunk_requirements(&upload).unwrap().is_empty());
    }
}
