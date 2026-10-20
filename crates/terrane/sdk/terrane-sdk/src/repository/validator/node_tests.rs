//! Checks admission of registered physical Node schemas without tree context.
//!
//! Witnesses are assembled directly from canonical CBOR framing rather than
//! produced by the owning Node encoder. Admission establishes local schema
//! validity, not an owner binding, complete tree, or executable Index role.

#![allow(
    clippy::unwrap_used,
    reason = "fixtures assert independently assembled schema outcomes"
)]

use super::*;
use std::error::Error;
use terrane_format::tree_format::{EntryKind, MAX_KEY, MAX_NODE_ITEMS_BYTES, NodeItems};

const USES: [TreeUse; 3] = [TreeUse::Ordinary, TreeUse::OverlayLayer, TreeUse::Index];
const DIRECTORY: &[u8] = b"\xa2\x01\x02\x02\x00";
const WHITEOUT: &[u8] = b"\xa1\x01\x05";

fn validator() -> MetadataValidator {
    MetadataValidator::new(ChunkProfile::cdc_1m([42; 32]))
}

// These small framing helpers implement only CBOR's unsigned length headers;
// they do not normalize keys, fields, prefix compression, or Entry schemas.
fn head(major: u8, value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    match value {
        0..=23 => bytes.push(major | value as u8),
        24..=255 => bytes.extend_from_slice(&[major | 24, value as u8]),
        256..=65535 => {
            bytes.push(major | 25);
            bytes.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65536..=4294967295 => {
            bytes.push(major | 26);
            bytes.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            bytes.push(major | 27);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
    bytes
}

fn bstr(value: &[u8]) -> Vec<u8> {
    let mut bytes = head(0x40, value.len() as u64);
    bytes.extend_from_slice(value);
    bytes
}

fn text(value: &str) -> Vec<u8> {
    let mut bytes = head(0x60, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

fn index_entry(targets: &[&[u8]]) -> Vec<u8> {
    let mut bytes = vec![0xa2, 1, 7, 14];
    bytes.extend(head(0x80, targets.len() as u64));
    for target in targets {
        bytes.extend(bstr(target));
    }
    bytes
}

fn file_entry(size: u64, tag: u8) -> Vec<u8> {
    let mut bytes = vec![0xa4, 1, 1, 2, 0, 3];
    bytes.extend(head(0, size));
    bytes.extend([4, 0x82, tag]);
    bytes.extend(bstr(&[0x11; 32]));
    bytes
}

fn leaf_item(suffix: &[u8], shared: u64, entry: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x83];
    bytes.extend(bstr(suffix));
    bytes.extend(head(0, shared));
    bytes.extend(entry);
    bytes
}

fn child(last_key: &[u8], digest: &[u8], count: u64, weight: u64) -> Vec<u8> {
    let mut bytes = vec![0x84];
    bytes.extend(bstr(last_key));
    bytes.extend(bstr(digest));
    bytes.extend(head(0, count));
    bytes.extend(head(0, weight));
    bytes
}

fn node(level: u64, items: &[Vec<u8>], props: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = vec![if props.is_some() { 0xa3 } else { 0xa2 }, 1];
    bytes.extend(head(0, level));
    bytes.push(2);
    bytes.extend(head(0x80, items.len() as u64));
    for item in items {
        bytes.extend(item);
    }
    if let Some(props) = props {
        bytes.push(3);
        bytes.extend(props);
    }
    bytes
}

fn leaf(key: &[u8], entry: &[u8]) -> Vec<u8> {
    node(0, &[leaf_item(key, 0, entry)], None)
}

fn accepts(bytes: &[u8]) {
    let validator = validator();
    let upload = MetaUpload::new(IdentityKind::Node, bytes).unwrap();
    let result = validator.validate_meta(&upload);
    assert!(result.is_ok(), "registered Node refused: {result:?}");
    assert!(validator.chunk_requirements(&upload).unwrap().is_empty());
}

fn refuses(case: &str, bytes: &[u8]) {
    let validator = validator();
    let upload = MetaUpload::new(IdentityKind::Node, bytes).unwrap();
    let failure = validator.validate_meta(&upload).unwrap_err();

    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "TREE-25" }),
        "{case}"
    );
    assert!(failure.source().is_none(), "{case}");
    for usage in USES {
        for is_root in [true, false] {
            assert!(
                tree_format::decode_node_for(
                    bytes,
                    is_root,
                    validator.profile.minimum() as u64,
                    usage,
                )
                .is_err(),
                "{case}: unexpectedly valid for {usage:?}, root={is_root}"
            );
        }
    }
}

#[test]
fn node_metadata_validator_accepts_registered_node_schemas() {
    let minimum = validator().profile.minimum() as u64;
    for entry in [
        DIRECTORY.to_vec(),
        file_entry(minimum, 0),
        file_entry(minimum + 1, 1),
        b"\xa2\x01\x03\x05\x43../".to_vec(),
        [b"\xa2\x01\x04\x06".as_slice(), &bstr(&[0x22; 32])].concat(),
        b"\xa2\x01\x06\x0c\x82\xa1\x01\x05\xa2\x01\x02\x02\x00".to_vec(),
    ] {
        accepts(&leaf(b"ordinary", &entry));
    }

    let layer = node(
        0,
        &[
            leaf_item(b"dir", 0, DIRECTORY),
            leaf_item(b"gone", 0, WHITEOUT),
        ],
        None,
    );
    accepts(&layer);
    assert!(tree_format::decode_node_for(&layer, true, minimum, TreeUse::Ordinary).is_err());
    let mut whiteout_provenance = vec![0xa2, 1, 5, 11];
    whiteout_provenance.extend(bstr(&[0x33; 32]));
    accepts(&leaf(b"gone", &whiteout_provenance));

    let index = index_entry(&[&[0x11; 32], &[0x22; 32]]);
    for key in [b"\0/slash".as_slice(), b"../", b"a//b", b"/"] {
        let bytes = leaf(key, &index);
        accepts(&bytes);
        for usage in [TreeUse::Ordinary, TreeUse::OverlayLayer] {
            assert!(tree_format::decode_node_for(&bytes, true, minimum, usage).is_err());
        }
        // An ordinary Entry does not acquire opaque-key validity from bytes.
        refuses("ordinary entry with opaque key", &leaf(key, DIRECTORY));
    }
    accepts(&leaf(&[0xff], &index));
    accepts(&leaf(&[0xff], DIRECTORY));
    let mut ordinary_attribute = vec![0xa3, 1, 2, 2, 0, 9, 0xa1];
    ordinary_attribute.extend(text("index.occurrences"));
    ordinary_attribute.extend(bstr(&[0x44; 32]));
    let ordinary_bytes = leaf(b"a", &ordinary_attribute);
    accepts(&ordinary_bytes);
    assert!(tree_format::decode_node_for(&ordinary_bytes, true, minimum, TreeUse::Index).is_err());
    let mut empty_optional_maps = vec![0xa4, 1, 7, 9, 0xa0, 10, 0xa0, 14, 0x81];
    empty_optional_maps.extend(bstr(&[0x11; 32]));
    accepts(&leaf(b"retained", &empty_optional_maps));

    // Generic retained Index fields need not match DRV-30's executable rows.
    // An untyped index.occurrences value neither selects a role nor verifies it.
    let mut retained = vec![0xa5, 1, 7, 9, 0xa1];
    retained.extend(text("index.occurrences"));
    retained.extend(text("retained"));
    retained.extend([10, 0xa1]);
    retained.extend(bstr(b"user.note"));
    retained.extend(bstr(b"value"));
    retained.push(11);
    retained.extend(bstr(&[0x33; 32]));
    retained.extend([14, 0x82]);
    retained.extend(bstr(&[0x11; 32]));
    retained.extend(bstr(&[0x22; 32]));
    let bytes = leaf(b"\0/retained", &retained);
    accepts(&bytes);

    let decoded = tree_format::decode_node_for(&bytes, true, minimum, TreeUse::Index).unwrap();
    let NodeItems::Leaf(items) = &decoded.items else {
        panic!("expected independently framed leaf");
    };
    assert_eq!(items[0].entry.attrs[0].name, "index.occurrences");
    assert_eq!(items[0].entry.attrs[0].value, text("retained"));
    assert_eq!(items[0].entry.xattrs[0].name, b"user.note");
    assert_eq!(items[0].entry.xattrs[0].value, b"value");
    assert!(items[0].entry.attrs_present);
    assert!(items[0].entry.xattrs_present);
    assert!(items[0].entry.provenance.is_some());
    assert!(matches!(&items[0].entry.kind, EntryKind::Index { targets } if targets.len() == 2));
    assert_eq!(
        tree_format::encode_node_for(&decoded, true, minimum, TreeUse::Index).unwrap(),
        bytes
    );

    // The registered DRV-30 carriers are also physical Node schemas. These
    // bytes alone establish neither their contextual role nor a relationship
    // to the owner, named attribute, gap tree, or referenced occurrence route.
    let mut forwarding = vec![0xa3, 1, 7, 9, 0xa1];
    forwarding.extend(text("index.occurrences"));
    forwarding.extend(bstr(&[0x44; 32]));
    forwarding.extend([14, 0x81]);
    forwarding.extend(bstr(&[0x11; 32]));
    accepts(&leaf(b"graft", &forwarding));
    accepts(&leaf(b"nested/file", &index_entry(&[&[0x11; 32]])));

    let mut primary_key = bstr(&[0x22; 32]);
    primary_key.extend([0x11; 32]);
    let mut primary_props = vec![0xa1];
    primary_props.extend(text("index-gaps"));
    primary_props.push(0xa2);
    primary_props.extend(text("value"));
    primary_props.extend(text(&"55".repeat(32)));
    primary_props.extend(text("inherit"));
    primary_props.push(0xf4);
    accepts(&node(
        0,
        &[leaf_item(&primary_key, 0, &forwarding)],
        Some(&primary_props),
    ));

    let mut owner_props = vec![0xa1];
    owner_props.extend(text("index-roots"));
    owner_props.push(0xa2);
    owner_props.extend(text("value"));
    owner_props.push(0xa1);
    owner_props.extend(text("hash.sha256"));
    owner_props.extend(text(&"66".repeat(32)));
    owner_props.extend(text("inherit"));
    owner_props.push(0xf4);
    accepts(&node(
        0,
        &[leaf_item(b"file", 0, &file_entry(1, 0))],
        Some(&owner_props),
    ));

    let empty = b"\xa2\x01\x00\x02\x80";
    accepts(empty);
    for usage in USES {
        assert!(tree_format::decode_node_for(empty, true, minimum, usage).is_ok());
    }
    // The byte-identical empty physical Node has no inherent namespace or
    // Index role and establishes no complete occurrence or gap coverage.
}

#[test]
fn node_metadata_validator_preserves_root_and_internal_constraints() {
    let minimum = validator().profile.minimum() as u64;
    let index = index_entry(&[&[0x11; 32]]);
    for (usage, entry, key) in [
        (TreeUse::Ordinary, DIRECTORY, b"path".as_slice()),
        (TreeUse::OverlayLayer, WHITEOUT, b"path".as_slice()),
        (TreeUse::Index, index.as_slice(), b"\0/path".as_slice()),
    ] {
        let items = [leaf_item(key, 0, entry)];
        let internal = [child(key, &[0x44; 32], 1, 1)];
        for (level, items) in [(0, items.as_slice()), (15, internal.as_slice())] {
            let bytes = node(level, items, None);
            accepts(&bytes);
            for is_root in [true, false] {
                assert!(tree_format::decode_node_for(&bytes, is_root, minimum, usage).is_ok());
            }

            let with_props = node(level, items, Some(b"\xa1\x61p\xf4"));
            accepts(&with_props);
            assert!(tree_format::decode_node_for(&with_props, true, minimum, usage).is_ok());
            assert!(tree_format::decode_node_for(&with_props, false, minimum, usage).is_err());
        }
    }

    let empty = node(0, &[], Some(b"\xa0"));
    accepts(&empty);
    for usage in USES {
        assert!(tree_format::decode_node_for(&empty, false, minimum, usage).is_err());
    }
    for level in [1, 15] {
        refuses("empty internal node", &node(level, &[], None));
    }

    // MetaUpload has no contextual root status or fetched child closure. The
    // caller must check these conditions when assembling or traversing a tree.
    accepts(&leaf(b"missing/ancestor", DIRECTORY));
    accepts(&node(1, &[child(b"a", &[0x55; 32], 999, 1)], None));
    let compressed = node(
        0,
        &[leaf_item(b"a", 0, DIRECTORY), leaf_item(b"b", 1, DIRECTORY)],
        None,
    );
    accepts(&compressed);
}

#[test]
fn node_metadata_validator_refuses_malformed_or_mixed_schemas() {
    let index = index_entry(&[&[0x11; 32]]);
    for valid in [
        leaf(b"a", DIRECTORY),
        leaf(b"a", WHITEOUT),
        leaf(b"\0/a", &index),
    ] {
        for length in 0..valid.len() {
            refuses("truncated schema", &valid[..length]);
        }
        let mut trailing = valid;
        trailing.push(0);
        refuses("trailing byte", &trailing);
    }

    for (case, bytes) in [
        ("indefinite map", b"\xbf\x01\x00\x02\x80\xff".as_slice()),
        ("nonminimal map", b"\xb8\x02\x01\x00\x02\x80"),
        ("nonminimal level", b"\xa2\x01\x18\x00\x02\x80"),
        ("nonminimal array", b"\xa2\x01\x00\x02\x98\x00"),
        ("indefinite array", b"\xa2\x01\x00\x02\x9f\xff"),
        ("reordered fields", b"\xa2\x02\x80\x01\x00"),
        ("duplicate fields", b"\xa2\x01\x00\x01\x80"),
        ("unknown fields", b"\xa3\x01\x00\x02\x80\x04\xa0"),
        ("tagged node", b"\xc0\xa2\x01\x00\x02\x80"),
        ("excessive level", b"\xa2\x01\x10\x02\x80"),
        ("claimed array limit", b"\xa2\x01\x00\x02\x99\x40\x01"),
        ("null property", b"\xa3\x01\x00\x02\x80\x03\xa1\x61p\xf6"),
        (
            "floating property",
            b"\xa3\x01\x00\x02\x80\x03\xa1\x61p\xf9\x00\x00",
        ),
    ] {
        refuses(case, bytes);
    }

    for entry in [
        b"\xa1\x01\x07".to_vec(),
        index_entry(&[]),
        index_entry(&[&[0x11; 31]]),
        index_entry(&[&[0x11; 33]]),
        index_entry(&[&[0x11; 32], &[0x11; 32]]),
        index_entry(&[&[0x22; 32], &[0x11; 32]]),
        b"\xa2\x01\x05\x02\x00".to_vec(),
        b"\xa2\x01\x05\x09\xa0".to_vec(),
        b"\xa2\x01\x02\x02\x19\x10\x00".to_vec(),
        b"\xa3\x01\x02\x02\x00\x09\xb9\x01\x01".to_vec(),
        b"\xa2\x01\x18\x07\x0e\x81\x58\x20".to_vec(),
        b"\xa2\x01\x07\x0e\x98\x01\x58\x20".to_vec(),
        b"\xa1\x01\x18\x05".to_vec(),
        file_entry(validator().profile.minimum() as u64, 1),
        file_entry(validator().profile.minimum() as u64 + 1, 0),
    ] {
        refuses("malformed entry", &leaf(b"a", &entry));
    }
    for reserved in 8..=15 {
        refuses("reserved entry type", &leaf(b"a", &[0xa1, 1, reserved]));
    }
    for other in [DIRECTORY, WHITEOUT] {
        refuses(
            "mixed Index and namespace entries",
            &node(
                0,
                &[leaf_item(b"a", 0, &index), leaf_item(b"b", 0, other)],
                None,
            ),
        );
    }
    for key in [b"".as_slice(), b"a\0", b".", b"..", b"a//b", b"/a", b"a/"] {
        refuses("invalid namespace key", &leaf(key, DIRECTORY));
    }
    refuses("empty Index key", &leaf(b"", &index));
    accepts(&leaf(&vec![b'a'; 255], DIRECTORY));
    refuses("component limit", &leaf(&vec![b'a'; 256], DIRECTORY));
    accepts(&leaf(&vec![0; MAX_KEY], &index));
    refuses("Index key limit", &leaf(&vec![0; MAX_KEY + 1], &index));

    let mut large_items = Vec::new();
    for first_byte in 1..=15 {
        let mut key = vec![0; MAX_KEY];
        key[0] = first_byte;
        large_items.push(leaf_item(&key, 0, &index));
    }
    accepts(&node(0, &large_items, None));

    // Properties and items share the payload budget. Both witnesses remain
    // inside the outer framing allowance, isolating that shared constraint.
    let item_bytes: usize = large_items.iter().map(Vec::len).sum();
    let property_text_len = MAX_NODE_ITEMS_BYTES - item_bytes - 6;
    let mut props = vec![0xa1];
    props.extend(text("p"));
    props.extend(text(&"x".repeat(property_text_len)));
    accepts(&node(0, &large_items, Some(&props)));
    let mut excessive_props = vec![0xa1];
    excessive_props.extend(text("p"));
    excessive_props.extend(text(&"x".repeat(property_text_len + 1)));
    refuses(
        "shared item/property budget",
        &node(0, &large_items, Some(&excessive_props)),
    );

    let mut key = vec![0; MAX_KEY];
    key[0] = 16;
    large_items.push(leaf_item(&key, 0, &index));
    refuses("node byte limit", &node(0, &large_items, None));
    for items in [
        vec![leaf_item(b"a", 1, DIRECTORY)],
        vec![leaf_item(b"a", 0, DIRECTORY), leaf_item(b"a", 0, DIRECTORY)],
        vec![leaf_item(b"b", 0, DIRECTORY), leaf_item(b"a", 0, DIRECTORY)],
        vec![
            leaf_item(b"a", 0, DIRECTORY),
            leaf_item(b"ab", 0, DIRECTORY),
        ],
    ] {
        refuses("invalid prefix or order", &node(0, &items, None));
    }
    for (count, weight) in [(0, 1), (1, 0)] {
        refuses(
            "zero child advisory field",
            &node(1, &[child(b"a", &[0x11; 32], count, weight)], None),
        );
    }
    for digest in [&[0x11; 31][..], &[0x11; 33][..]] {
        refuses(
            "child digest length",
            &node(1, &[child(b"a", digest, 1, 1)], None),
        );
    }
    refuses(
        "duplicate internal key",
        &node(
            1,
            &[
                child(b"a", &[0x11; 32], 1, 1),
                child(b"a", &[0x22; 32], 1, 1),
            ],
            None,
        ),
    );
}

#[test]
fn node_metadata_validator_preserves_domain_dispatch_and_chunk_requirements() {
    let validator = validator();
    let node_bytes = leaf(b"\0/a", &index_entry(&[&[0x11; 32]]));
    for (kind, rule_id) in [
        (IdentityKind::Manifest, "OBJ-15"),
        (IdentityKind::Commit, "REF-9"),
        (IdentityKind::Attribute, "DRV-1"),
    ] {
        let upload = MetaUpload::new(kind, &node_bytes).unwrap();
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
        let upload = MetaUpload::new(kind, &node_bytes).unwrap();
        let failure = validator.validate_meta(&upload).unwrap_err();
        assert_eq!(failure.kind(), &StoreErrorKind::Unsupported);
        assert!(failure.source().is_none());
        assert!(validator.chunk_requirements(&upload).unwrap().is_empty());
    }
    for kind in [
        IdentityKind::Node,
        IdentityKind::Commit,
        IdentityKind::Attribute,
        IdentityKind::Memo,
    ] {
        for bytes in [node_bytes.as_slice(), b"\xff"] {
            let upload = MetaUpload::new(kind, bytes).unwrap();
            assert!(validator.chunk_requirements(&upload).unwrap().is_empty());
        }
    }
    let memo_upload = MetaUpload::new(IdentityKind::Memo, &node_bytes).unwrap();
    let memo_failure = validator.validate_meta(&memo_upload).unwrap_err();
    assert_eq!(
        memo_failure.kind(),
        &StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "DRV-21" })
    );
    assert_eq!(
        memo_failure
            .source()
            .unwrap()
            .downcast_ref::<terrane_format::derivation::MemoError>(),
        Some(&Memo::decode(&node_bytes).unwrap_err())
    );
    assert!(MetaUpload::new(IdentityKind::Chunk, &node_bytes).is_err());

    // Only Manifest dispatch emits chunk dependencies, with unchanged profile
    // lengths, digest domains, position labels, and missing-content rule.
    let minimum = validator.profile.minimum() as u64;
    let mut manifest = vec![0xa3, 1];
    manifest.extend(head(0, minimum + 1));
    manifest.extend([2, 0x82, 0x82]);
    manifest.extend(bstr(&[0x11; 32]));
    manifest.extend(head(0, minimum));
    manifest.push(0x82);
    manifest.extend(bstr(&[0x22; 32]));
    manifest.extend([1, 3, 0xa1]);
    manifest.extend(text("blake3"));
    manifest.extend(bstr(&[0x33; 32]));
    let upload = MetaUpload::new(IdentityKind::Manifest, &manifest).unwrap();
    assert!(validator.validate_meta(&upload).is_ok());
    let requirements = validator.chunk_requirements(&upload).unwrap();

    assert_eq!(requirements.len(), 2);
    for (requirement, digest, length, position) in [
        (
            &requirements[0],
            [0x11; 32],
            minimum as usize,
            ChunkPosition::NonFinal,
        ),
        (&requirements[1], [0x22; 32], 1, ChunkPosition::Final),
    ] {
        assert_eq!(
            requirement.identity,
            TERRANE_V1
                .from_digest(IdentityKind::Chunk, &digest)
                .unwrap()
        );
        assert_eq!(requirement.declared_plaintext_len, length);
        assert_eq!(requirement.position, position);
        assert_eq!(requirement.missing_rule_id, "OBJ-15");
    }
    let malformed = MetaUpload::new(IdentityKind::Manifest, b"\xff").unwrap();
    let failure = validator.chunk_requirements(&malformed).unwrap_err();
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "OBJ-15" })
    );
    assert!(failure.source().is_some());
}
