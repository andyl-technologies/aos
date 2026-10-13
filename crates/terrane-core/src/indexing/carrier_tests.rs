//! Tests contextual carrier shapes using independently assembled raw CBOR.

#![allow(clippy::unwrap_used)]

use super::carrier::{self, GapBinding, Role, SemanticContext};
use super::{IndexEvaluationRecipe, IndexKey, IndexRoots};
use crate::cbor;
use crate::properties::{self, Defaults, PropertyName, RootLayer};
use crate::tree_format::{self, Entry, EntryKind, LeafItem, Node, NodeItems, Property, TreeUse};
use alloc::{vec, vec::Vec};

fn context() -> SemanticContext {
    SemanticContext::new(3, 2, 1).unwrap()
}

// Primitive assembly deliberately bypasses specialized encoders.
fn raw_entry(targets: &[[u8; 32]], attrs: Option<&[u8]>, extra: Option<(u64, &[u8])>) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(
        &mut bytes,
        2 + usize::from(attrs.is_some()) + usize::from(extra.is_some()),
    );
    bytes.extend_from_slice(&[1, 7]);
    if let Some(attrs) = attrs {
        bytes.push(9);
        bytes.extend_from_slice(attrs);
    }
    if let Some((key, value)) = extra {
        cbor::write_uint(&mut bytes, key);
        bytes.extend_from_slice(value);
    }
    bytes.push(14);
    cbor::write_array(&mut bytes, targets.len());
    for target in targets {
        cbor::write_bytes(&mut bytes, target);
    }
    bytes
}

fn raw_attrs(name: &str, pointer: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, 1);
    cbor::write_text(&mut bytes, name);
    cbor::write_bytes(&mut bytes, pointer);
    bytes
}

fn entry(bytes: &[u8]) -> Entry<'_> {
    tree_format::decode_entry_bytes(bytes, 262144).unwrap()
}

fn raw_binding(hex: &str, inherit: bool) -> Vec<u8> {
    let mut bytes = vec![0xa2];
    cbor::write_text(&mut bytes, "value");
    cbor::write_text(&mut bytes, hex);
    cbor::write_text(&mut bytes, "inherit");
    bytes.push(if inherit { 0xf5 } else { 0xf4 });
    bytes
}

#[test]
fn contextual_carriers_preserve_object_targets_and_role_shapes() {
    let object = [0x13; 32];
    let pointer = [0x27; 32];
    let attrs = raw_attrs("index.occurrences", &pointer);
    let terminal_bytes = raw_entry(&[object], None, None);
    let forward_bytes = raw_entry(&[object], Some(&attrs), None);
    let terminal = entry(&terminal_bytes);
    let forward = entry(&forward_bytes);
    let key = IndexKey::new(&[0x18, 42], object).unwrap().encode();

    for role in [Role::Primary, Role::Gap] {
        let key = if role == Role::Primary {
            &key[..]
        } else {
            &object[..]
        };
        let row = carrier::validate_row(context(), role, key, &forward).unwrap();
        assert_eq!(row.object(), object);
        assert_eq!(row.route(), Some(pointer));
        assert!(carrier::validate_row(context(), role, key, &terminal).is_err());
        let wrong = raw_entry(&[[0x99; 32]], Some(&attrs), None);
        assert!(carrier::validate_row(context(), role, key, &entry(&wrong)).is_err());
    }
    for role in [Role::PresentRoute, Role::MissingRoute] {
        for value in [&terminal, &forward] {
            assert_eq!(
                carrier::validate_row(context(), role, b"a/b", value)
                    .unwrap()
                    .object(),
                object
            );
        }
        for invalid in [
            &b"/a"[..],
            b"a/",
            b"a//b",
            b"a/../b",
            b"a/./b",
            b"a\0b",
            b"",
        ] {
            assert!(
                carrier::validate_row(context(), role, invalid, &terminal).is_err(),
                "{invalid:?}"
            );
        }
        let maximum_component = vec![b'x'; 255];
        assert!(carrier::validate_row(context(), role, &maximum_component, &terminal).is_ok());
        assert!(carrier::validate_row(context(), role, &vec![b'x'; 256], &terminal).is_err());
        let mut maximum_path = vec![b'x'; 4096];
        for separator in (255..4096).step_by(256) {
            maximum_path[separator] = b'/';
        }
        // The last component must be nonempty at the total-size bound.
        maximum_path[4094] = b'/';
        maximum_path[4095] = b'x';
        assert!(carrier::validate_row(context(), role, &maximum_path, &terminal).is_ok());
        maximum_path.push(b'x');
        assert!(carrier::validate_row(context(), role, &maximum_path, &terminal).is_err());
    }

    let max_value = {
        let mut value = Vec::new();
        cbor::write_bytes(&mut value, &vec![0; 4061]);
        value
    };
    assert_eq!(max_value.len(), 4064);
    let maximum_key = IndexKey::new(&max_value, object).unwrap().encode();
    assert!(carrier::validate_row(context(), Role::Primary, &maximum_key, &forward).is_ok());
    let mut oversized = maximum_key.clone();
    oversized.push(0);
    assert!(carrier::validate_row(context(), Role::Primary, &oversized, &forward).is_err());
    for invalid in [vec![0x18, 0], vec![0, 0], vec![0xff]] {
        let mut key = invalid;
        key.extend_from_slice(&object);
        assert!(carrier::validate_row(context(), Role::Primary, &key, &forward).is_err());
    }

    let wrong_width = raw_attrs("index.occurrences", &[0; 31]);
    let other_name = raw_attrs("tag.pointer", &pointer);
    let cases = [
        raw_entry(&[object, pointer], None, None),
        raw_entry(&[object], Some(&[0xa0]), None),
        raw_entry(&[object], Some(&wrong_width), None),
        raw_entry(&[object], Some(&other_name), None),
        raw_entry(&[object], None, Some((10, &[0xa0]))),
        raw_entry(
            &[object],
            None,
            Some((11, &{
                let mut digest = Vec::new();
                cbor::write_bytes(&mut digest, &pointer);
                digest
            })),
        ),
    ];
    for bytes in cases {
        // Generic retained Index values keep their historical broad validity.
        let generic = entry(&bytes);
        assert!(
            carrier::classify_entry(context(), &generic).is_err(),
            "{bytes:?}"
        );
    }
    for bytes in [
        raw_entry(&[], None, None),
        raw_entry(&[object], None, Some((15, &[0]))),
    ] {
        assert!(tree_format::decode_entry_bytes(&bytes, 262144).is_err());
    }

    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![LeafItem {
            key: b"a/b".to_vec(),
            entry: terminal,
        }]),
        props: None,
    };
    let bytes = tree_format::encode_node_for(&node, true, 262144, TreeUse::Index).unwrap();
    let decoded = tree_format::decode_node_for(&bytes, true, 262144, TreeUse::Index).unwrap();
    assert_eq!(decoded, node);
    assert!(carrier::validate_node(context(), Role::PresentRoute, &decoded, true).is_ok());
    let directory = Entry {
        kind: EntryKind::Directory { mode: 0o755 },
        attrs: vec![],
        attrs_present: false,
        xattrs: vec![],
        xattrs_present: false,
        provenance: None,
    };
    assert!(carrier::validate_row(context(), Role::PresentRoute, b"a", &directory).is_err());
}

#[test]
fn structural_index_names_do_not_become_value_inputs() {
    let name = "index.occurrences";
    assert!(!properties::registered_attribute(name));
    assert!(crate::derived::AttributeName::parse(name).is_err());
    let function = crate::derived::Function {
        name: name.into(),
        version: "1".into(),
    };
    assert!(!function.supported(crate::derived::AttributeName::Sha256));
    let mut record = vec![0xa5, 1];
    cbor::write_bytes(&mut record, &[1; 32]);
    record.push(2);
    cbor::write_text(&mut record, name);
    record.push(3);
    cbor::write_bytes(&mut record, &[2; 32]);
    record.push(4);
    cbor::write_text(&mut record, "index.occurrences/1");
    record.push(5);
    cbor::write_bytes(&mut record, &[3; 32]);
    assert!(crate::derived::AttrRecord::decode(&record).is_err());
    for valid in [
        "uid",
        "gid",
        "tag.any",
        "nar.hash_sha256",
        "hash.sha256",
        "zstd-dictionary",
    ] {
        assert!(properties::registered_attribute(valid));
    }
    assert!(IndexEvaluationRecipe::new([1; 32], name).is_err());
    let mut index = vec![0x81];
    cbor::write_text(&mut index, name);
    assert!(
        properties::validate_property(&Property {
            name: "index",
            value: &index
        })
        .is_err()
    );
    let mut roots = vec![0xa1];
    cbor::write_text(&mut roots, name);
    cbor::write_text(&mut roots, &"0".repeat(64));
    assert!(IndexRoots::decode_value(&roots).is_err());
    let mut selector = vec![0x83];
    cbor::write_text(&mut selector, "attr-by");
    cbor::write_text(&mut selector, name);
    selector.push(0x82);
    cbor::write_text(&mut selector, "preset");
    cbor::write_text(&mut selector, "any");
    assert!(crate::provenance::Selector::decode(&selector).is_err());
    assert!(
        crate::algebra::TrustContext::verified(
            selector.clone(),
            "verifier/v1".into(),
            vec![0xf6],
            vec![]
        )
        .is_err()
    );
    assert!(
        properties::validate_property(&Property {
            name: "trust",
            value: &selector
        })
        .is_err()
    );

    let attrs = raw_attrs(name, &[2; 32]);
    let bytes = raw_entry(&[[1; 32]], Some(&attrs), None);
    let generic = entry(&bytes);
    assert!(carrier::validate_namespace_attributes(1, &generic).is_ok());
    assert!(carrier::validate_namespace_attributes(2, &generic).is_err());
    for revisions in [
        (1, 1, 1),
        (2, 1, 1),
        (2, 2, 1),
        (3, 1, 1),
        (3, 2, 2),
        (4, 2, 1),
    ] {
        assert!(SemanticContext::new(revisions.0, revisions.1, revisions.2).is_err());
    }
}

#[test]
fn gap_bindings_require_primary_root_placement_and_exact_wrapper() {
    let bytes = raw_binding(&"ab".repeat(32), false);
    let gap = GapBinding::decode_binding(&bytes).unwrap();
    assert_eq!(gap.node(), [0xab; 32]);
    assert_eq!(gap.encode_binding(), bytes);
    assert_eq!(GapBinding::new([0xab; 32]), gap);
    assert!(
        properties::validate_property(&Property {
            name: "index-gaps",
            value: &bytes
        })
        .is_ok()
    );
    assert_eq!(
        PropertyName::ALL
            .iter()
            .filter(|name| name.as_str() == "index-gaps")
            .count(),
        1
    );
    let property = Property {
        name: "index-gaps",
        value: &bytes,
    };
    assert!(properties::validate_map(&[property]).is_err());
    assert!(properties::validate_graft_overrides(&[property], &[]).is_err());
    let defaults = Defaults {
        store: "local",
        home: "local",
        private_domain: "private:test",
    };
    assert!(
        properties::resolve(
            &[RootLayer {
                properties: &[property],
                overrides: &[]
            }],
            defaults
        )
        .is_err()
    );
    assert!(
        properties::resolve(&[], defaults)
            .unwrap()
            .get(PropertyName::IndexGaps)
            .is_none()
    );

    let mut node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![]),
        props: Some(vec![property]),
    };
    assert_eq!(
        carrier::validate_node(context(), Role::Primary, &node, true).unwrap(),
        Some(gap)
    );
    assert!(carrier::validate_node(context(), Role::Primary, &node, false).is_err());
    for role in [Role::Gap, Role::PresentRoute, Role::MissingRoute] {
        assert!(carrier::validate_node(context(), role, &node, true).is_err());
    }
    node.props = Some(vec![]);
    assert!(carrier::validate_node(context(), Role::Primary, &node, true).is_err());
    node.props = None;
    assert_eq!(
        carrier::validate_node(context(), Role::Primary, &node, true).unwrap(),
        None
    );
    for hex in ["AB".repeat(32), "a".repeat(63), "g".repeat(64)] {
        assert!(GapBinding::decode_binding(&raw_binding(&hex, false)).is_err());
    }
    assert!(GapBinding::decode_binding(&raw_binding(&"a".repeat(64), true)).is_err());
    let mut bare = Vec::new();
    cbor::write_text(&mut bare, &"a".repeat(64));
    assert!(GapBinding::decode_binding(&bare).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(GapBinding::decode_binding(&trailing).is_err());
    let mut extra = bytes.clone();
    extra[0] = 0xa3;
    extra.extend_from_slice(&[0x61, b'z', 0]);
    assert!(GapBinding::decode_binding(&extra).is_err());
}
