//! Uses independent literal CBOR assembly to exercise the public index formats.
//!
//! Wire witnesses are reviewed against the CDDL; these helpers intentionally
//! avoid the production CBOR writers so encoder mistakes cannot define the oracle.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use super::{IndexBinding, IndexEvaluationRecipe, IndexKey, IndexRoots, MAX_INDEX_KEY_BYTES};
use crate::identity::{IdentityKind, TERRANE_V1};
use crate::properties::{self, Defaults, PropertyName, RootLayer, Value};
use crate::refs::Commit;
use crate::tree_format::{Entry, EntryKind, Property};

type TestResult = Result<(), Box<dyn core::error::Error>>;

fn literal_string(major: u8, bytes: &[u8]) -> Vec<u8> {
    let mut encoded = match bytes.len() {
        0..=23 => vec![(major << 5) | bytes.len() as u8],
        24..=255 => vec![(major << 5) | 24, bytes.len() as u8],
        _ => {
            assert!(bytes.len() <= 65535);
            let length = (bytes.len() as u16).to_be_bytes();
            vec![(major << 5) | 25, length[0], length[1]]
        }
    };
    encoded.extend_from_slice(bytes);
    encoded
}

fn text(text: &str) -> Vec<u8> {
    literal_string(3, text.as_bytes())
}

fn binding_pairs(pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
    assert!(pairs.len() <= 23);
    let mut encoded = vec![0xa0 | pairs.len() as u8];
    for (name, value) in pairs {
        encoded.extend(text(name));
        encoded.extend(value);
    }
    encoded
}

fn owner_binding(value: &[u8], inherit: u8) -> Vec<u8> {
    let mut encoded = b"\xa2\x65value".to_vec();
    encoded.extend_from_slice(value);
    encoded.extend_from_slice(b"\x67inherit");
    encoded.push(inherit);
    encoded
}

fn roots_value(node: &str) -> Vec<u8> {
    binding_pairs(&[("uid", text(node))])
}

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "authority",
        private_domain: "private:root",
        home: "region-a",
    }
}

fn index_roots<'p, 'a>(policy: &'p properties::EffectiveProperties<'a>) -> &'p IndexRoots<'a> {
    let Some(Value::IndexRoots(roots)) = policy.get(PropertyName::IndexRoots) else {
        panic!("resolution must supply the registered owner-binding value");
    };
    roots
}

#[test]
fn owner_bindings_require_canonical_noninherited_root_values() -> TestResult {
    let node_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let node = [
        1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103,
        137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239,
    ];
    let value = roots_value(node_hex);
    let encoded = owner_binding(&value, 0xf4);
    let roots = IndexRoots::decode_binding(&encoded)?;

    assert_eq!(
        roots.as_bindings(),
        &[IndexBinding {
            attribute: "uid",
            node
        }]
    );
    assert_eq!(roots.get("uid"), Some(node));
    assert_eq!(roots.get("gid"), None);
    assert_eq!(roots.encode_value(), value);
    assert_eq!(roots.encode_binding()?, encoded);

    let property = Property {
        name: "index-roots",
        value: &encoded,
    };
    assert_eq!(
        properties::validate_property(&property)?,
        (PropertyName::IndexRoots, Value::IndexRoots(roots.clone())),
    );
    properties::validate_map(&[property])?;
    assert_eq!(
        PropertyName::parse("index-roots")?,
        PropertyName::IndexRoots
    );

    let empty = owner_binding(&[0xa0], 0xf4);
    let absent = properties::resolve(&[], defaults())?;
    assert!(index_roots(&absent).as_bindings().is_empty());
    assert_eq!(IndexRoots::default().encode_binding()?, empty);
    let explicit_empty = [Property {
        name: "index-roots",
        value: &empty,
    }];
    let empty_policy = properties::resolve(
        &[RootLayer {
            properties: &explicit_empty,
            overrides: &[],
        }],
        defaults(),
    )?;
    assert_eq!(index_roots(&empty_policy), &IndexRoots::default());

    let child_value = roots_value(&"ab".repeat(32));
    let child_binding = owner_binding(&child_value, 0xf4);
    let parent = [property];
    let child = [Property {
        name: "index-roots",
        value: &child_binding,
    }];
    let parent_policy = properties::resolve(
        &[RootLayer {
            properties: &parent,
            overrides: &[],
        }],
        defaults(),
    )?;
    let child_policy = properties::resolve(
        &[
            RootLayer {
                properties: &parent,
                overrides: &[],
            },
            RootLayer {
                properties: &child,
                overrides: &[],
            },
        ],
        defaults(),
    )?;
    let no_child_binding = properties::resolve(
        &[
            RootLayer {
                properties: &parent,
                overrides: &[],
            },
            RootLayer {
                properties: &[],
                overrides: &[],
            },
        ],
        defaults(),
    )?;
    assert_eq!(index_roots(&parent_policy).get("uid"), Some(node));
    assert_eq!(index_roots(&child_policy).get("uid"), Some([171; 32]));
    assert_eq!(index_roots(&no_child_binding).get("uid"), None);

    // The same current target keeps its own bindings under different inherited
    // requirements. Neither occurrence borrows an ancestor's index pointer.
    let uid_requirement = [Property {
        name: "index",
        value: b"\x81\x63uid",
    }];
    let gid_requirement = [Property {
        name: "index",
        value: b"\x81\x63gid",
    }];
    let extra_value = binding_pairs(&[("gid", text(node_hex)), ("uid", text(&"ab".repeat(32)))]);
    let extra_binding = owner_binding(&extra_value, 0xf4);
    let target = [Property {
        name: "index-roots",
        value: &extra_binding,
    }];
    let mut occurrence_bindings = Vec::new();
    for requirements in [&uid_requirement, &gid_requirement] {
        let policy = properties::resolve(
            &[
                RootLayer {
                    properties: requirements,
                    overrides: &[],
                },
                RootLayer {
                    properties: &target,
                    overrides: &[],
                },
            ],
            defaults(),
        )?;
        occurrence_bindings.push(index_roots(&policy).clone());
        let (_, expected_requirement) = properties::validate_property(&requirements[0])?;
        assert_eq!(policy.get(PropertyName::Index), Some(&expected_requirement));
    }
    assert_eq!(occurrence_bindings[0], occurrence_bindings[1]);
    assert_eq!(occurrence_bindings[0].get("uid"), Some([171; 32]));
    assert_eq!(occurrence_bindings[0].get("gid"), Some(node));

    for path in [
        vec![RootLayer {
            properties: &[],
            overrides: &parent,
        }],
        vec![
            RootLayer {
                properties: &parent,
                overrides: &parent,
            },
            RootLayer {
                properties: &[],
                overrides: &[],
            },
        ],
    ] {
        assert!(properties::resolve(&path, defaults()).is_err());
    }
    assert!(properties::validate_graft_overrides(&parent, &[]).is_err());
    assert!(properties::validate_graft_overrides(&parent, &["index-roots"]).is_err());

    let graft = Entry {
        kind: EntryKind::Tree {
            root: [9; 32],
            props: Some(parent.to_vec()),
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let change = properties::EntryChange {
        entry: &graft,
        properties: &parent_policy,
        reference_domains: &[],
        graft_properties: None,
    };
    assert_eq!(
        properties::validate_commit(&[change], &[]),
        Err(properties::Error::InvalidValue)
    );

    let mut trailing = encoded.clone();
    trailing.push(0);
    let duplicate = binding_pairs(&[("uid", text(node_hex)), ("uid", text(node_hex))]);
    let unsorted = binding_pairs(&[("uid", text(node_hex)), ("gid", text(node_hex))]);
    let mut nonminimal = value.clone();
    nonminimal.splice(0..1, [0xb8, 1]);
    let mut extra_wrapper = encoded.clone();
    extra_wrapper[0] = 0xa3;
    extra_wrapper.extend_from_slice(b"\x68unknown\x00");

    let invalid = [
        ("bare empty", vec![0xa0]),
        ("bare nonempty", value.clone()),
        ("inherited", owner_binding(&value, 0xf5)),
        ("null inheritance", owner_binding(&value, 0xf6)),
        (
            "uppercase hex",
            owner_binding(&roots_value(&"AB".repeat(32)), 0xf4),
        ),
        (
            "short hex",
            owner_binding(&roots_value(&"a".repeat(63)), 0xf4),
        ),
        (
            "long hex",
            owner_binding(&roots_value(&"a".repeat(65)), 0xf4),
        ),
        ("nonhex", owner_binding(&roots_value(&"g".repeat(64)), 0xf4)),
        (
            "unknown attribute",
            owner_binding(&binding_pairs(&[("unknown", text(node_hex))]), 0xf4),
        ),
        (
            "wrong digest type",
            owner_binding(
                &binding_pairs(&[("uid", literal_string(2, &[0; 32]))]),
                0xf4,
            ),
        ),
        ("wrong value type", owner_binding(&[0x80], 0xf4)),
        ("duplicate", owner_binding(&duplicate, 0xf4)),
        ("unsorted", owner_binding(&unsorted, 0xf4)),
        ("nonminimal map", owner_binding(&nonminimal, 0xf4)),
        (
            "claimed huge map",
            owner_binding(&[0xba, 255, 255, 255, 255], 0xf4),
        ),
        (
            "claimed huge text",
            owner_binding(&[0xa1, 0x7a, 255, 255, 255, 255], 0xf4),
        ),
        ("indefinite", owner_binding(&[0xbf, 0xff], 0xf4)),
        ("truncated", encoded[..encoded.len() - 1].to_vec()),
        ("trailing", trailing),
        ("unknown wrapper field", extra_wrapper),
        (
            "wrong wrapper order",
            [b"\xa2\x67inherit\xf4\x65value".as_slice(), &value].concat(),
        ),
        (
            "missing wrapper field",
            [b"\xa1\x65value".as_slice(), &value].concat(),
        ),
        ("oversized", vec![0; 65537]),
    ];
    for (name, bytes) in invalid {
        assert!(IndexRoots::decode_binding(&bytes).is_err(), "{name}");
        let property = Property {
            name: "index-roots",
            value: &bytes,
        };
        assert!(properties::validate_property(&property).is_err(), "{name}");
        assert!(properties::validate_map(&[property]).is_err(), "{name}");
    }
    Ok(())
}

fn literal_recipe(owners: &[[u8; 32]], arguments: Option<&[u8]>) -> Vec<u8> {
    assert!(owners.len() <= 23);
    let mut bytes = vec![if arguments.is_some() { 0xa3 } else { 0xa2 }, 1];
    bytes.extend_from_slice(b"\x65index\x02");
    bytes.push(0x80 | owners.len() as u8);
    for owner in owners {
        bytes.extend_from_slice(&[0x58, 0x20]);
        bytes.extend_from_slice(owner);
    }
    if let Some(arguments) = arguments {
        bytes.push(3);
        bytes.extend_from_slice(arguments);
    }
    bytes
}

fn literal_arguments(attribute: &str) -> Vec<u8> {
    binding_pairs(&[
        ("profile", text("terrane-index/v1")),
        ("attribute", text(attribute)),
    ])
}

fn unhex(encoded: &str) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
    assert_eq!(encoded.len() % 2, 0);
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(core::str::from_utf8(pair)?, 16)?))
        .collect()
}

#[test]
fn executable_index_recipes_are_closed_and_legacy_recipes_remain_data() -> TestResult {
    let owner = [1; 32];
    let arguments = literal_arguments("hash.sha256");
    let wire = literal_recipe(&[owner], Some(&arguments));
    let recipe = IndexEvaluationRecipe::decode(&wire)?;

    assert_eq!(recipe.owner(), owner);
    assert_eq!(recipe.attribute(), "hash.sha256");
    assert_eq!(recipe.profile(), "terrane-index/v1");
    assert_eq!(recipe.encode(), wire);
    assert_eq!(IndexEvaluationRecipe::new(owner, "hash.sha256")?, recipe);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"terrane-memo-v1\0");
    hasher.update(&wire);
    assert_eq!(recipe.identity()?, *hasher.finalize().as_bytes());

    let max_attribute = "tag.".to_owned() + &"a".repeat(251);
    let max_recipe = IndexEvaluationRecipe::new(owner, &max_attribute)?;
    let max_wire = max_recipe.encode();
    assert_eq!(IndexEvaluationRecipe::decode(&max_wire)?, max_recipe);
    assert!(IndexEvaluationRecipe::new(owner, "unknown").is_err());
    assert!(IndexEvaluationRecipe::new(owner, &(max_attribute + "a")).is_err());

    // This is the published two-operand/no-arguments Commit witness. Its
    // unchanged identity and full model round trip are independent of the new
    // specialization. A retained operation string supplies no executable input.
    let legacy_wire = unhex(concat!(
        "a601582001010101010101010101010101010101010101010101010101010101",
        "01010101028003a8016669737375657202500202020202020202020202020202",
        "020203677375626a6563740402066f666978747572652070726f636573730718",
        "1808070901041818056006a3010102666364632d316d03a20165696e64657802",
        "8258200101010101010101010101010101010101010101010101010101010101",
        "0101015820020202020202020202020202020202020202020202020202020202",
        "0202020202",
    ))?;
    let mut legacy = Commit::decode(&legacy_wire)?;
    assert_eq!(legacy.encode()?, legacy_wire);
    assert_eq!(Commit::decode(&legacy.encode()?)?, legacy);
    assert_eq!(
        legacy.identity()?.as_slice(),
        unhex("96fcfc6ca92638183319214b4694ab33d72b64a557fc150a8264f4c137febc78")?,
    );
    let legacy_recipe = literal_recipe(&[[1; 32], [2; 32]], None);
    assert_eq!(legacy.profile_pair.recipe.as_ref(), Some(&legacy_recipe));
    assert!(IndexEvaluationRecipe::decode(&legacy_recipe).is_err());

    let mut trailing = wire.clone();
    trailing.push(0);
    let mut nonminimal = wire.clone();
    nonminimal.splice(1..2, [0x18, 1]);
    let mut wrong_operation = wire.clone();
    wrong_operation[3] = b'x';
    let mut unknown_field = wire.clone();
    unknown_field[1] = 4;
    let invalid = [
        ("zero operands", literal_recipe(&[], Some(&arguments))),
        (
            "two operands",
            literal_recipe(&[[1; 32], [2; 32]], Some(&arguments)),
        ),
        ("absent arguments", literal_recipe(&[owner], None)),
        ("empty arguments", literal_recipe(&[owner], Some(&[0xa0]))),
        (
            "wrong profile",
            literal_recipe(
                &[owner],
                Some(&binding_pairs(&[
                    ("profile", text("other-index/v1")),
                    ("attribute", text("uid")),
                ])),
            ),
        ),
        (
            "unknown attribute",
            literal_recipe(&[owner], Some(&literal_arguments("unknown"))),
        ),
        (
            "missing attribute",
            literal_recipe(
                &[owner],
                Some(&binding_pairs(&[("profile", text("terrane-index/v1"))])),
            ),
        ),
        (
            "missing profile",
            literal_recipe(
                &[owner],
                Some(&binding_pairs(&[("attribute", text("uid"))])),
            ),
        ),
        (
            "unknown argument",
            literal_recipe(
                &[owner],
                Some(&binding_pairs(&[
                    ("other", vec![0]),
                    ("profile", text("terrane-index/v1")),
                    ("attribute", text("uid")),
                ])),
            ),
        ),
        (
            "duplicate argument",
            literal_recipe(
                &[owner],
                Some(&binding_pairs(&[
                    ("profile", text("terrane-index/v1")),
                    ("profile", text("terrane-index/v1")),
                ])),
            ),
        ),
        (
            "wrong argument order",
            literal_recipe(
                &[owner],
                Some(&binding_pairs(&[
                    ("attribute", text("uid")),
                    ("profile", text("terrane-index/v1")),
                ])),
            ),
        ),
        (
            "wrong attribute type",
            literal_recipe(
                &[owner],
                Some(&binding_pairs(&[
                    ("profile", text("terrane-index/v1")),
                    ("attribute", vec![0]),
                ])),
            ),
        ),
        ("nonminimal integer", nonminimal),
        ("unknown top field", unknown_field),
        ("wrong operation", wrong_operation),
        ("trailing", trailing),
        ("truncated", wire[..wire.len() - 1].to_vec()),
        (
            "claimed huge operands",
            b"\xa3\x01\x65index\x02\x9a\xff\xff\xff\xff".to_vec(),
        ),
        (
            "wrong owner size",
            b"\xa3\x01\x65index\x02\x81\x41\x00".to_vec(),
        ),
    ];
    for (name, bytes) in invalid {
        assert!(IndexEvaluationRecipe::decode(&bytes).is_err(), "{name}");
    }

    // Unknown generic arguments remain retained Commit data. The profile
    // parser alone decides whether a recipe has the closed executable shape.
    let retained = literal_recipe(&[owner], Some(&binding_pairs(&[("future", vec![0])])));
    legacy.profile_pair.recipe = Some(retained.clone());
    assert_eq!(Commit::decode(&legacy.encode()?)?, legacy);
    assert!(IndexEvaluationRecipe::decode(&retained).is_err());
    legacy.profile_pair.recipe = Some(wire);
    assert_eq!(Commit::decode(&legacy.encode()?)?, legacy);
    Ok(())
}

#[test]
fn index_keys_roundtrip_exact_canonical_values_and_object_targets() -> TestResult {
    let object = [0xab; 32];
    let values = [
        vec![0],
        vec![0x18, 24],
        vec![0x20],
        vec![0xf4],
        vec![0xf5],
        vec![0xf6],
        b"\x43\x00/\xff".to_vec(),
        b"\x65a\x00/bc".to_vec(),
        b"\x83\x00\x41/\xf6".to_vec(),
        b"\xa2\x01\x41\x00\x63uid\x00".to_vec(),
    ];
    for value in &values {
        let literal = [value.as_slice(), object.as_slice()].concat();
        let key = IndexKey::decode(&literal)?;

        assert_eq!(key.value(), value);
        assert_eq!(key.value().as_ptr(), literal.as_ptr());
        assert_eq!(key.object(), object);
        assert_eq!(key.encode(), literal);
        assert_eq!(IndexKey::new(value, object)?, key);
        let (lower, upper) = key.equality_bounds();
        assert_eq!(lower, [value.as_slice(), &[0; 32]].concat());
        assert_eq!(upper, [value.as_slice(), &[255; 32]].concat());
        for target in [[0; 32], [1; 32], object, [255; 32]] {
            let row = IndexKey::new(value, target)?.encode();
            assert!(lower <= row && row <= upper);
        }
    }

    let zero_object = IndexKey::new(&[0], object)?.encode();
    let true_object = IndexKey::new(&[0xf5], object)?.encode();
    let (lower, upper) = IndexKey::new(&[0xf4], object)?.equality_bounds();
    assert!(zero_object < lower);
    assert!(true_object > upper);

    let largest = literal_string(2, &vec![0; MAX_INDEX_KEY_BYTES - 35]);
    let largest_key = IndexKey::new(&largest, object)?.encode();
    assert_eq!(largest_key.len(), MAX_INDEX_KEY_BYTES);
    assert_eq!(IndexKey::decode(&largest_key)?.value(), largest);
    let too_large = literal_string(2, &vec![0; MAX_INDEX_KEY_BYTES - 34]);
    assert!(IndexKey::new(&too_large, object).is_err());
    assert!(IndexKey::decode(&[too_large.as_slice(), &object].concat()).is_err());

    let mut deep_value = vec![0x81; MAX_INDEX_KEY_BYTES - 33];
    deep_value.push(0);
    let deep_key = IndexKey::new(&deep_value, object)?.encode();
    assert_eq!(deep_key.len(), MAX_INDEX_KEY_BYTES);
    assert_eq!(IndexKey::decode(&deep_key)?.value(), deep_value);
    deep_value.pop();
    assert!(IndexKey::new(&deep_value, object).is_err());

    let invalid = [
        ("empty value", vec![]),
        ("nonminimal integer", vec![0x18, 0]),
        ("nonminimal length", vec![0x58, 1, 0]),
        ("duplicate keys", vec![0xa2, 1, 0, 1, 1]),
        ("unsorted keys", vec![0xa2, 2, 0, 1, 0]),
        ("trailing value", vec![0, 1]),
        ("indefinite array", vec![0x9f, 0xff]),
        ("tag", vec![0xc0, 0]),
        ("float", vec![0xf9, 0, 0]),
        ("unsupported simple", vec![0xf7]),
        ("invalid UTF8", vec![0x61, 0xff]),
        ("truncated value", vec![0x43, 0]),
        ("claimed huge bytes", vec![0x5a, 255, 255, 255, 255]),
        ("claimed huge array", vec![0x9a, 255, 255, 255, 255]),
        ("claimed huge map", vec![0xba, 255, 255, 255, 255]),
    ];
    for (name, bytes) in invalid {
        assert!(IndexKey::new(&bytes, object).is_err(), "{name}");
        let literal = [bytes.as_slice(), &object].concat();
        assert!(IndexKey::decode(&literal).is_err(), "{name}");
    }
    for digest_size in [0, 31, 33] {
        let literal = [&[0][..], &vec![0xab; digest_size]].concat();
        assert!(
            IndexKey::decode(&literal).is_err(),
            "digest size {digest_size}"
        );
    }

    let key = IndexKey::new(b"\x43\x00/\xff", object)?.encode();
    let index_entry = Entry {
        kind: EntryKind::Index {
            targets: vec![object],
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    assert_eq!(
        index_entry.kind,
        EntryKind::Index {
            targets: vec![IndexKey::decode(&key)?.object()]
        }
    );
    let literal_entry = [b"\xa2\x01\x07\x0e\x81\x58\x20".as_slice(), &object].concat();
    assert_eq!(
        crate::tree_format::decode_entry_bytes(&literal_entry, 4096)?,
        index_entry
    );
    assert_eq!(
        crate::tree_format::encode_entry(&index_entry, 4096)?,
        literal_entry
    );
    assert_ne!(
        TERRANE_V1
            .calculate(IdentityKind::Node, &key)?
            .terrane_v1_digest()?,
        object,
    );
    Ok(())
}
