//! Exercises D-104 carrier syntax under separately supplied roles and revisions.
//!
//! Independent fields define the expected bytes. These local schema checks do
//! not prove route nonemptiness, namespace relationships, coverage or authority.

use super::support::{Generator, cbor_properties, maximum_key};
use terrane_format::cbor;
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::indexing::carrier::{self, Role, SemanticContext};
use terrane_format::tree_format::{
    self, Attribute, ChildRef, Entry, EntryKind, LeafItem, Node, NodeItems, Property, TreeUse,
};

const MINIMUM: u64 = 262_144;

fn entry(object: [u8; 32], pointer: Option<&[u8]>) -> Entry<'_> {
    Entry {
        kind: EntryKind::Index {
            targets: vec![object],
        },
        attrs: pointer
            .map(|value| {
                vec![Attribute {
                    name: "index.occurrences",
                    value,
                }]
            })
            .unwrap_or_default(),
        attrs_present: pointer.is_some(),
        xattrs: vec![],
        xattrs_present: false,
        provenance: None,
    }
}

fn entry_wire(object: &[u8; 32], pointer: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_map(&mut bytes, 2 + usize::from(pointer.is_some()));
    cbor::write_uint(&mut bytes, 1);
    cbor::write_uint(&mut bytes, 7);
    if let Some(pointer) = pointer {
        cbor::write_uint(&mut bytes, 9);
        cbor::write_map(&mut bytes, 1);
        cbor::write_text(&mut bytes, "index.occurrences");
        bytes.extend_from_slice(pointer);
    }
    cbor::write_uint(&mut bytes, 14);
    cbor::write_array(&mut bytes, 1);
    cbor::write_bytes(&mut bytes, object);
    bytes
}

fn leaf_wire(key: &[u8], object: &[u8; 32], pointer: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = vec![0xa2, 1, 0, 2, 0x81, 0x83];
    cbor::write_bytes(&mut bytes, key);
    bytes.push(0);
    bytes.extend(entry_wire(object, pointer));
    bytes
}

fn check_node(model: &Node<'_>, expected: &[u8]) {
    assert_eq!(
        tree_format::encode_node_for(model, true, MINIMUM, TreeUse::Index).unwrap(),
        expected
    );
    assert_eq!(
        tree_format::decode_node_for(expected, true, MINIMUM, TreeUse::Index).unwrap(),
        *model
    );
    let mut preimage = b"terrane-node-v1\0".to_vec();
    preimage.extend_from_slice(expected);
    assert_eq!(
        TERRANE_V1
            .calculate(IdentityKind::Node, expected)
            .unwrap()
            .digest(),
        blake3::hash(&preimage).as_bytes()
    );
    cbor_properties("contextual Index Node", expected, |bytes| {
        let decoded = tree_format::decode_node_for(bytes, true, MINIMUM, TreeUse::Index)?;
        tree_format::encode_node_for(&decoded, true, MINIMUM, TreeUse::Index)
    });
}

#[test]
fn contextual_carrier_models_preserve_roles_shapes_and_property_placement() {
    let context = SemanticContext::new(3, 2, 1).unwrap();
    let mut generator = Generator::new(0x4f31_73a2_50bc_869d);
    for value in [0, 23, 24, 255, 256, u64::MAX] {
        for _ in 0..4 {
            let object = generator.bytes();
            let route = generator.bytes::<32>();
            let mut pointer = vec![];
            cbor::write_bytes(&mut pointer, &route);
            let mut primary_key = vec![];
            cbor::write_uint(&mut primary_key, value);
            primary_key.extend_from_slice(&object);

            for role in [
                Role::Primary,
                Role::Gap,
                Role::PresentRoute,
                Role::MissingRoute,
            ] {
                let key = match role {
                    Role::Primary => primary_key.clone(),
                    Role::Gap => object.to_vec(),
                    Role::PresentRoute | Role::MissingRoute => b"sub/file".to_vec(),
                };
                for forwarded in [false, true] {
                    let pointer = forwarded.then_some(pointer.as_slice());
                    let entry = entry(object, pointer);
                    let wire = entry_wire(&object, pointer);
                    assert_eq!(tree_format::encode_entry(&entry, MINIMUM).unwrap(), wire);
                    assert_eq!(
                        tree_format::decode_entry_bytes(&wire, MINIMUM).unwrap(),
                        entry
                    );
                    cbor_properties("closed carrier Entry", &wire, |bytes| {
                        tree_format::encode_entry(
                            &tree_format::decode_entry_bytes(bytes, MINIMUM)?,
                            MINIMUM,
                        )
                    });

                    let model = Node {
                        level: 0,
                        items: NodeItems::Leaf(vec![LeafItem {
                            key: key.clone(),
                            entry,
                        }]),
                        props: None,
                    };
                    check_node(&model, &leaf_wire(&key, &object, pointer));
                    let valid =
                        forwarded || matches!(role, Role::PresentRoute | Role::MissingRoute);
                    assert_eq!(
                        carrier::validate_node(context, role, &model, true).is_ok(),
                        valid
                    );
                    let NodeItems::Leaf(rows) = &model.items else {
                        unreachable!()
                    };
                    let classified = carrier::classify_entry(context, &rows[0].entry).unwrap();
                    assert_eq!(classified.object(), object);
                    assert_eq!(classified.route(), forwarded.then_some(route));
                    if forwarded {
                        association_controls(context, role, &key, &rows[0].entry);
                    }
                }
                internal(context, role, &key, generator.bytes());
            }
            shape_controls(context, object, &pointer);
            property_placement(context, object, &primary_key, &pointer, generator.bytes());
        }
    }
    route_key_limits(context);
}

fn association_controls(context: SemanticContext, role: Role, key: &[u8], entry: &Entry<'_>) {
    let mut wrong = entry.clone();
    let EntryKind::Index { targets } = &mut wrong.kind else {
        unreachable!()
    };
    targets[0][31] ^= 1;
    let bytes = tree_format::encode_entry(&wrong, MINIMUM).unwrap();
    assert_eq!(
        tree_format::decode_entry_bytes(&bytes, MINIMUM).unwrap(),
        wrong
    );
    // Generic validity survives a changed object. Only primary/gap suffix
    // associations reject it; route-to-source relationships need separate data.
    assert_eq!(
        carrier::validate_row(context, role, key, &wrong).is_ok(),
        matches!(role, Role::PresentRoute | Role::MissingRoute)
    );
    assert!(carrier::validate_row(context, role, &[], entry).is_err());
}

fn internal(context: SemanticContext, role: Role, key: &[u8], child: [u8; 32]) {
    let model = Node {
        level: 1,
        items: NodeItems::Internal(vec![ChildRef {
            last_key: key.to_vec(),
            child,
            count: u64::MAX,
            weight: u64::MAX,
        }]),
        props: None,
    };
    let mut bytes = vec![0xa2, 1, 1, 2, 0x81, 0x84];
    cbor::write_bytes(&mut bytes, key);
    cbor::write_bytes(&mut bytes, &child);
    cbor::write_uint(&mut bytes, u64::MAX);
    cbor::write_uint(&mut bytes, u64::MAX);
    check_node(&model, &bytes);
    assert_eq!(
        carrier::validate_node(context, role, &model, true).unwrap(),
        None
    );

    let mut wrong = model;
    let NodeItems::Internal(children) = &mut wrong.items else {
        unreachable!()
    };
    children[0].last_key = match role {
        Role::Primary => vec![0; 32],
        Role::Gap => vec![0; 31],
        Role::PresentRoute | Role::MissingRoute => b"sub/../file".to_vec(),
    };
    let bytes = tree_format::encode_node_for(&wrong, true, MINIMUM, TreeUse::Index).unwrap();
    assert_eq!(
        tree_format::decode_node_for(&bytes, true, MINIMUM, TreeUse::Index).unwrap(),
        wrong
    );
    assert!(carrier::validate_node(context, role, &wrong, true).is_err());
}

fn shape_controls(context: SemanticContext, object: [u8; 32], pointer: &[u8]) {
    let baseline = entry(object, Some(pointer));
    for change in 0..5 {
        let mut model = baseline.clone();
        match change {
            0 => {
                model.attrs.clear();
                model.attrs_present = true;
            }
            1 => model.xattrs_present = true,
            2 => model.provenance = Some(object),
            3 => model.attrs[0].name = "uid",
            4 => {
                let mut other = object;
                other[0] ^= 1;
                let mut targets = vec![object, other];
                targets.sort();
                model.kind = EntryKind::Index { targets };
            }
            _ => unreachable!(),
        }
        let bytes = tree_format::encode_entry(&model, MINIMUM).unwrap();
        assert_eq!(
            tree_format::decode_entry_bytes(&bytes, MINIMUM).unwrap(),
            model
        );
        assert!(carrier::classify_entry(context, &model).is_err());
    }

    // An empty target list is malformed even outside the active carrier
    // profile. Its raw input must bypass the rejecting generic encoder.
    let empty = Entry {
        kind: EntryKind::Index { targets: vec![] },
        ..entry(object, None)
    };
    let raw_empty = [0xa2, 1, 7, 14, 0x80];
    assert_eq!(
        tree_format::encode_entry(&empty, MINIMUM),
        Err(tree_format::Error::Entry)
    );
    assert_eq!(
        tree_format::decode_entry_bytes(&raw_empty, MINIMUM),
        Err(tree_format::Error::Entry)
    );
    assert!(carrier::classify_entry(context, &empty).is_err());

    for length in [0, 1, 31, 33, 64] {
        let mut pointer = vec![];
        cbor::write_bytes(&mut pointer, &vec![0; length]);
        let wire = entry_wire(&object, Some(&pointer));
        let decoded = tree_format::decode_entry_bytes(&wire, MINIMUM).unwrap();
        assert!(carrier::classify_entry(context, &decoded).is_err());
    }
    for value in [&[0][..], &[0xf6], &[0x60], &[0x80], &[0xa0]] {
        let wire = entry_wire(&object, Some(value));
        let decoded = tree_format::decode_entry_bytes(&wire, MINIMUM).unwrap();
        assert!(carrier::classify_entry(context, &decoded).is_err());
    }

    let namespace = Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: 1,
            content: tree_format::ContentRef::Inline(object),
            link_id: None,
        },
        ..baseline.clone()
    };
    let bytes = tree_format::encode_entry(&namespace, MINIMUM).unwrap();
    assert_eq!(
        tree_format::decode_entry_bytes(&bytes, MINIMUM).unwrap(),
        namespace
    );
    assert!(carrier::classify_entry(context, &namespace).is_err());
    assert!(carrier::validate_namespace_attributes(1, &namespace).is_ok());
    assert!(carrier::validate_namespace_attributes(2, &namespace).is_err());
    assert!(carrier::validate_namespace_attributes(1, &baseline).is_ok());
    assert!(carrier::validate_namespace_attributes(2, &baseline).is_err());
    assert!(carrier::validate_namespace_attributes(3, &baseline).is_err());
}

fn property_placement(
    context: SemanticContext,
    object: [u8; 32],
    key: &[u8],
    pointer: &[u8],
    gap: [u8; 32],
) {
    let mut binding = vec![0xa2];
    cbor::write_text(&mut binding, "value");
    let hex: String = gap.iter().map(|byte| format!("{byte:02x}")).collect();
    cbor::write_text(&mut binding, &hex);
    cbor::write_text(&mut binding, "inherit");
    binding.push(0xf4);
    let model = Node {
        level: 0,
        items: NodeItems::Leaf(vec![LeafItem {
            key: key.to_vec(),
            entry: entry(object, Some(pointer)),
        }]),
        props: Some(vec![Property {
            name: "index-gaps",
            value: &binding,
        }]),
    };
    let mut bytes = leaf_wire(key, &object, Some(pointer));
    bytes[0] = 0xa3;
    bytes.push(3);
    cbor::write_map(&mut bytes, 1);
    cbor::write_text(&mut bytes, "index-gaps");
    bytes.extend_from_slice(&binding);
    check_node(&model, &bytes);
    assert_eq!(
        carrier::validate_node(context, Role::Primary, &model, true)
            .unwrap()
            .unwrap()
            .node(),
        gap
    );
    for role in [
        Role::Primary,
        Role::Gap,
        Role::PresentRoute,
        Role::MissingRoute,
    ] {
        assert!(carrier::validate_node(context, role, &model, false).is_err());
        if role != Role::Primary {
            assert!(carrier::validate_node(context, role, &model, true).is_err());
        }
    }
    let mut empty = model;
    empty.props = Some(vec![]);
    assert!(tree_format::encode_node_for(&empty, true, MINIMUM, TreeUse::Index).is_ok());
    assert!(carrier::validate_node(context, Role::Primary, &empty, true).is_err());
}

fn route_key_limits(context: SemanticContext) {
    let terminal = entry([0; 32], None);
    let maximum = maximum_key();
    assert_eq!(maximum.len(), 4096);
    for role in [Role::PresentRoute, Role::MissingRoute] {
        carrier::validate_row(context, role, maximum.as_bytes(), &terminal).unwrap();
        for key in [
            vec![b'x'; 256],
            format!("{maximum}x").into_bytes(),
            b"/file".to_vec(),
            b"a//b".to_vec(),
            b"a/./b".to_vec(),
            b"a\0b".to_vec(),
        ] {
            assert!(carrier::validate_row(context, role, &key, &terminal).is_err());
        }
    }
    for revisions in [(2, 2, 1), (3, 1, 1), (3, 2, 2), (u64::MAX, 2, 1)] {
        assert!(SemanticContext::new(revisions.0, revisions.1, revisions.2).is_err());
    }
}
