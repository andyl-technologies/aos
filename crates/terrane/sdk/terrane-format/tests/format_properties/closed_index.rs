//! Checks public DRV-12/25/26 index data codecs independently of stored evidence.
//!
//! Binding and recipe acceptance establishes schema data only, never DRV-22
//! replay, producer trust, occurrence coverage or current publication authority.

use super::support::{Generator, byte_properties, cbor_properties};
use terrane_format::cbor;
use terrane_format::indexing::{IndexBinding, IndexEvaluationRecipe, IndexKey, IndexRoots};

fn binding(name: &str, digest: &[u8; 32], inherit: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, 2);
    cbor::write_text(&mut bytes, "value");
    cbor::write_map(&mut bytes, 1);
    cbor::write_text(&mut bytes, name);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    cbor::write_text(&mut bytes, &hex);
    cbor::write_text(&mut bytes, "inherit");
    bytes.push(if inherit { 0xf5 } else { 0xf4 });
    bytes
}

fn recipe(owner: &[u8], attribute: &str, profile: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, 3);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_text(&mut bytes, "index");
    cbor::write_uint(&mut bytes, 2);
    cbor::write_array(&mut bytes, 1);
    cbor::write_bytes(&mut bytes, owner);
    cbor::write_uint(&mut bytes, 3);
    cbor::write_map(&mut bytes, 2);
    cbor::write_text(&mut bytes, "profile");
    cbor::write_text(&mut bytes, profile);
    cbor::write_text(&mut bytes, "attribute");
    cbor::write_text(&mut bytes, attribute);
    bytes
}

#[test]
fn closed_index_bindings_and_recipes_match_independent_models() {
    let mut generator = Generator::new(0x2349_ba80_d921_770f);
    for attribute in ["uid", "gid", "hash.sha256", "class.elf"] {
        for _ in 0..16 {
            let owner = generator.bytes();
            let expected = binding(attribute, &owner, false);
            let mut expected_value = Vec::new();
            cbor::write_map(&mut expected_value, 1);
            cbor::write_text(&mut expected_value, attribute);
            let hex: String = owner.iter().map(|byte| format!("{byte:02x}")).collect();
            cbor::write_text(&mut expected_value, &hex);
            // The value constructor and independent public fields define the
            // model before the wrapper under test is decoded.
            let roots = IndexRoots::decode_value(&expected_value).unwrap();
            assert_eq!(
                roots.as_bindings(),
                &[IndexBinding {
                    attribute,
                    node: owner
                }]
            );
            assert_eq!(roots.get(attribute), Some(owner));
            assert_eq!(IndexRoots::decode_binding(&expected).unwrap(), roots);
            assert_eq!(roots.encode_binding().unwrap(), expected);
            assert_eq!(roots.encode_value(), expected_value);
            cbor_properties("index roots value", &expected_value, |bytes| {
                IndexRoots::decode_value(bytes).map(|decoded| decoded.encode_value())
            });
            assert_eq!(
                IndexRoots::decode_value(&roots.encode_value()).unwrap(),
                roots
            );
            cbor_properties("index roots binding", &expected, |bytes| {
                IndexRoots::decode_binding(bytes)?.encode_binding()
            });

            let expected = recipe(&owner, attribute, "terrane-index/v1");
            let model = IndexEvaluationRecipe::new(owner, attribute).unwrap();
            assert_eq!(model.encode(), expected);
            assert_eq!(IndexEvaluationRecipe::decode(&expected).unwrap(), model);
            assert_eq!(model.owner(), owner);
            assert_eq!(model.attribute(), attribute);
            assert_eq!(model.profile(), "terrane-index/v1");
            let mut preimage = b"terrane-memo-v1\0".to_vec();
            preimage.extend_from_slice(&expected);
            assert_eq!(
                model.identity().unwrap(),
                *blake3::hash(&preimage).as_bytes()
            );
            cbor_properties("closed index recipe", &expected, |bytes| {
                IndexEvaluationRecipe::decode(bytes).map(|decoded| decoded.encode())
            });
        }
    }
}

#[test]
fn opaque_index_keys_preserve_canonical_values_objects_and_inclusive_bounds() {
    let mut generator = Generator::new(0x312a_9c50_ff83_0461);
    // Composite canonical values remain opaque; only the complete value is parsed.
    for value in [
        vec![0xf4],
        vec![0xf6],
        vec![0x82, 0, 1],
        vec![0xa1, 0, 1],
        vec![0x42, 0, 255],
        vec![0x61, b'x'],
    ] {
        let object = generator.bytes();
        let mut expected = value.clone();
        expected.extend_from_slice(&object);
        let key = IndexKey::new(&value, object).unwrap();
        assert_eq!(key.encode(), expected);
        assert_eq!(IndexKey::decode(&expected).unwrap(), key);
        byte_properties("composite opaque index key", &expected, |bytes| {
            IndexKey::decode(bytes).map(|decoded| decoded.encode())
        });
        cbor_properties("composite opaque value", &value, |bytes| {
            IndexKey::new(bytes, object).map(|decoded| decoded.value().to_vec())
        });
    }

    for value in [0, 1, 23, 24, 255, 256, u64::MAX] {
        let mut encoded = Vec::new();
        cbor::write_uint(&mut encoded, value);
        let object = generator.bytes();
        let mut expected = encoded.clone();
        expected.extend_from_slice(&object);
        let key = IndexKey::new(&encoded, object).unwrap();
        assert_eq!(key.encode(), expected);
        assert_eq!(IndexKey::decode(&expected).unwrap(), key);
        assert_eq!(key.value(), encoded);
        assert_eq!(key.object(), object);
        let (lower, upper) = key.equality_bounds();
        assert_eq!(&lower[..encoded.len()], encoded);
        assert_eq!(&upper[..encoded.len()], encoded);
        assert_eq!(&lower[encoded.len()..], &[0; 32]);
        assert_eq!(&upper[encoded.len()..], &[255; 32]);
        assert!(lower <= expected && expected <= upper);
        byte_properties("opaque index key", &expected, |bytes| {
            IndexKey::decode(bytes).map(|decoded| decoded.encode())
        });
        cbor_properties("opaque value", &encoded, |bytes| {
            IndexKey::new(bytes, object).map(|decoded| decoded.value().to_vec())
        });
    }

    // A text header plus4061 bytes and the object digest reaches the exact cap.
    for length in [4061, 4062] {
        let mut value = Vec::new();
        cbor::write_text(&mut value, &"x".repeat(length));
        let result = IndexKey::new(&value, [0; 32]);
        assert_eq!(result.is_ok(), length == 4061);
        if let Ok(key) = result {
            assert_eq!(key.encode().len(), 4096);
            assert!(IndexKey::decode(&key.encode()).is_ok());
        }
    }
}

#[test]
fn closed_index_schemas_refuse_nonlocal_unknown_and_hostile_inputs() {
    assert!(IndexRoots::decode_binding(&binding("uid", &[0; 32], true)).is_err());
    assert!(IndexRoots::decode_binding(&binding("not-registered", &[0; 32], false)).is_err());
    assert!(IndexEvaluationRecipe::decode(&recipe(&[0; 32], "uid", "other")).is_err());
    assert!(
        IndexEvaluationRecipe::decode(&recipe(&[0; 32], "not-registered", "terrane-index/v1"))
            .is_err()
    );
    let mut uppercase = binding("uid", &[255; 32], false);
    for byte in &mut uppercase {
        if *byte == b'f' {
            *byte = b'F';
        }
    }
    assert!(IndexRoots::decode_binding(&uppercase).is_err());
    for length in [63, 65] {
        let mut bytes = Vec::new();
        cbor::write_map(&mut bytes, 1);
        cbor::write_text(&mut bytes, "uid");
        cbor::write_text(&mut bytes, &"0".repeat(length));
        assert!(IndexRoots::decode_value(&bytes).is_err());
    }
    for length in [0, 1, 31, 33, 64] {
        assert!(
            IndexEvaluationRecipe::decode(&recipe(&vec![0; length], "uid", "terrane-index/v1"))
                .is_err()
        );
    }
    for bytes in [
        vec![0xbf, 0xff],
        vec![0xbb, 255, 255, 255, 255, 255, 255, 255, 255],
        vec![
            0xa2, 0x65, b'v', b'a', b'l', b'u', b'e', 0xbb, 255, 255, 255, 255, 255, 255, 255, 255,
        ],
        vec![0; 65537],
    ] {
        assert!(IndexRoots::decode_binding(&bytes).is_err());
        assert!(IndexEvaluationRecipe::decode(&bytes).is_err());
    }
    for bytes in [
        vec![0x5b, 255, 255, 255, 255, 255, 255, 255, 255],
        vec![0x9f, 0xff],
        vec![0, 0],
        vec![0; 4065],
    ] {
        assert!(IndexKey::new(&bytes, [0; 32]).is_err());
    }
}

#[test]
fn empty_index_nodes_remain_generic_data_in_each_explicit_role() {
    use terrane_format::indexing::carrier::{Role, SemanticContext, validate_node};
    use terrane_format::tree_format::{self, TreeUse};

    // Physical identity alone cannot choose an occurrence or coverage role.
    let bytes = [0xa2, 1, 0, 2, 0x80];
    let context = SemanticContext::new(3, 2, 1).unwrap();
    for usage in [TreeUse::Ordinary, TreeUse::Index] {
        let node = tree_format::decode_node_for(&bytes, true, 262_144, usage).unwrap();
        assert_eq!(
            tree_format::encode_node_for(&node, true, 262_144, usage).unwrap(),
            bytes
        );
        for role in [
            Role::Primary,
            Role::Gap,
            Role::PresentRoute,
            Role::MissingRoute,
        ] {
            assert_eq!(validate_node(context, role, &node, true).unwrap(), None);
        }
    }
    assert!(SemanticContext::new(1, 1, 1).is_err());
}

fn gap_wire(value: &str, inherit: bool) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_map(&mut bytes, 2);
    cbor::write_text(&mut bytes, "value");
    cbor::write_text(&mut bytes, value);
    cbor::write_text(&mut bytes, "inherit");
    bytes.push(if inherit { 0xf5 } else { 0xf4 });
    bytes
}

#[test]
fn gap_binding_models_preserve_exact_local_wrapper_and_limits() {
    use terrane_format::indexing::carrier::GapBinding;
    let mut generator = Generator::new(0xf207_3556_b8d4_a999);
    for node in [[0; 32], [255; 32]]
        .into_iter()
        .chain((0..12).map(|_| generator.bytes()))
    {
        let hex: String = node.iter().map(|byte| format!("{byte:02x}")).collect();
        let expected = gap_wire(&hex, false);
        let model = GapBinding::new(node);
        assert_eq!(model.encode_binding(), expected);
        assert_eq!(GapBinding::decode_binding(&expected).unwrap(), model);
        assert_eq!(model.node(), node);
        cbor_properties("exact local gap wrapper", &expected, |bytes| {
            GapBinding::decode_binding(bytes).map(GapBinding::encode_binding)
        });
        assert!(GapBinding::decode_binding(&gap_wire(&hex, true)).is_err());
        let mut bare = vec![];
        cbor::write_text(&mut bare, &hex);
        assert!(GapBinding::decode_binding(&bare).is_err());
    }

    for value in [
        "0".repeat(63),
        "0".repeat(65),
        "F".repeat(64),
        "g".repeat(64),
    ] {
        assert!(GapBinding::decode_binding(&gap_wire(&value, false)).is_err());
    }
    let mut extra = gap_wire(&"0".repeat(64), false);
    extra[0] = 0xa3;
    cbor::write_text(&mut extra, "unknown");
    extra.push(0xf6);
    assert!(GapBinding::decode_binding(&extra).is_err());
    let mut missing = vec![];
    cbor::write_map(&mut missing, 1);
    cbor::write_text(&mut missing, "value");
    cbor::write_text(&mut missing, &"0".repeat(64));
    assert!(GapBinding::decode_binding(&missing).is_err());
}
