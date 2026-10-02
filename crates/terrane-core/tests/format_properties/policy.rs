//! Tests every registered property vocabulary, inheritance bindings, and recipes.

use super::support::{Generator, cbor_properties};
use terrane_core::properties::PropertyName;
use terrane_core::tree_format::{Entry, EntryKind, Node, NodeItems, Property};
use terrane_core::{algebra, cbor, properties, tree_format};

fn text(value: &str) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_text(&mut bytes, value);
    bytes
}

fn names(values: &[&str]) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_array(&mut bytes, values.len());
    for value in values {
        cbor::write_text(&mut bytes, value);
    }
    bytes
}

fn quantity(value: u64) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_uint(&mut bytes, value);
    bytes
}

fn pair(label: &str, value: u64) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_array(&mut bytes, 2);
    cbor::write_text(&mut bytes, label);
    cbor::write_uint(&mut bytes, value);
    bytes
}

fn property_values(name: PropertyName, value: u64) -> Vec<Vec<u8>> {
    use PropertyName::*;
    let vocabulary: &[&str] = match name {
        Store | Home | Baseline => &["named", "generated-λ"],
        Chunk => &["cdc-1m"],
        Compression => &["raw", "zstd", "zstd:elf"],
        Encryption => &["none"],
        Retain => &["gc", "lease", "forever"],
        Domain => &[
            "public",
            "tenant:generated",
            "group:generated",
            "private:generated",
        ],
        Dedup => &["global", "domain", "none"],
        Redundancy => &["none", "replicated(3,ack=2)", "striped(4,parity=2)"],
        Degraded => &["allow", "refuse"],
        Durability => &["local", "zone", "region", "regions(3)"],
        Replicate => &["async", "none", "sync(3)"],
        Trust => &["any", "signed-baseline", "strict", "attested"],
        Writers => &["one", "many"],
        Prefetch => &["profile", "rules", "none"],
        Reassembly => &["never", "smart", "always"],
        Passthrough => &["auto", "force", "off"],
        Wipe => &["none", "zero", "discard", "volatile"],
        OnRelease => &["keep", "commit", "discard"],
        _ => &[],
    };
    let mut values: Vec<_> = vocabulary.iter().map(|value| text(value)).collect();
    match name {
        StrictAttrs => values.extend([vec![0xf4], vec![0xf5]]),
        CompactionThreshold | WholePackThreshold => {
            values.extend([quantity(0), quantity(10_000), quantity(value % 10_001)])
        }
        GapMergeBytes | SpanMaxBytes => {
            values.extend([quantity(0), quantity(value), quantity(u64::MAX)])
        }
        Warm => values.extend([names(&[]), names(&["region", "region", "zone"])]),
        Hashes => values.extend([
            names(&[]),
            names(&["sha256", "sha512", "git-blob-sha1", "git-blob-sha256"]),
        ]),
        Classify => values.extend([
            names(&[]),
            names(&[
                "elf", "shebang", "ar", "zstd", "gzip", "tar", "text", "other",
            ]),
        ]),
        Index => values.extend([names(&[]), names(&["sha256", "magic"])]),
        Merge => values.push(names(&[
            "prefer-ours",
            "prefer-theirs",
            "prefer-trusted",
            "prefer-newer",
            "keep-conflict",
            "error",
        ])),
        Acl => {
            values.push(names(&[]));
            let mut grants = vec![];
            cbor::write_array(&mut grants, 3);
            for mask in [0, 1, 31] {
                cbor::write_array(&mut grants, 2);
                cbor::write_text(&mut grants, "principal");
                cbor::write_uint(&mut grants, mask);
            }
            values.push(grants);
        }
        Quota => {
            let mut quota = vec![];
            cbor::write_map(&mut quota, 2);
            cbor::write_text(&mut quota, "bytes-per-root");
            cbor::write_uint(&mut quota, value);
            cbor::write_text(&mut quota, "bytes-per-principal-unreferenced");
            cbor::write_uint(&mut quota, u64::MAX);
            values.push(quota);
        }
        Retain => values.push(pair("ttl", value)),
        ReflogRetain => values.extend([quantity(value), pair("count", value)]),
        Trust => values.push(names(&["preset", "any"])),
        _ => {}
    }
    assert!(!values.is_empty(), "missing property model: {name:?}");
    values
}

#[test]
fn registered_properties_cover_closed_vocabularies_quantities_and_inheritance_binding() {
    let mut generator = Generator::new(0x77f2_e2d9_3468_129d);
    for name in PropertyName::ALL {
        for value in property_values(*name, generator.next()) {
            for inherit in [None, Some(false), Some(true)] {
                let bytes = if let Some(inherit) = inherit {
                    let mut binding = vec![];
                    cbor::write_map(&mut binding, 2);
                    cbor::write_text(&mut binding, "value");
                    binding.extend_from_slice(&value);
                    cbor::write_text(&mut binding, "inherit");
                    binding.push(if inherit { 0xf5 } else { 0xf4 });
                    binding
                } else {
                    value.clone()
                };
                let property = Property {
                    name: name.as_str(),
                    value: &bytes,
                };
                let model = properties::validate_property(&property).unwrap();
                assert_eq!(model.0, *name);
                cbor_properties(name.as_str(), &bytes, |input| {
                    properties::validate_property(&Property {
                        name: name.as_str(),
                        value: input,
                    })?;
                    Ok::<_, properties::Error>(input.to_vec())
                });
                let node = Node {
                    level: 0,
                    items: NodeItems::Leaf(vec![]),
                    props: Some(vec![property]),
                };
                let encoded = tree_format::encode_node(&node, true, 262144).unwrap();
                assert_eq!(
                    tree_format::decode_node(&encoded, true, 262144).unwrap(),
                    node
                );
            }
        }
    }
}

#[test]
fn property_and_tree_limits_reject_claimed_collection_lengths_and_out_of_range_values() {
    for name in [
        PropertyName::Warm,
        PropertyName::Hashes,
        PropertyName::Acl,
        PropertyName::Merge,
    ] {
        let mut claimed = vec![];
        cbor::write_argument(&mut claimed, 4, u64::MAX);
        assert!(
            properties::validate_property(&Property {
                name: name.as_str(),
                value: &claimed
            })
            .is_err()
        );
    }
    for name in [
        PropertyName::CompactionThreshold,
        PropertyName::WholePackThreshold,
    ] {
        assert!(
            properties::validate_property(&Property {
                name: name.as_str(),
                value: &quantity(10_001)
            })
            .is_err()
        );
    }
    let too_long = text(&"x".repeat(65536));
    assert!(
        properties::validate_property(&Property {
            name: "store",
            value: &too_long
        })
        .is_err()
    );
    for level in [16, 255, u64::MAX] {
        let mut bytes = vec![0xa2, 1];
        cbor::write_uint(&mut bytes, level);
        bytes.extend_from_slice(&[2, 0x80]);
        assert!(tree_format::decode_node(&bytes, true, 262144).is_err());
    }
    let mut claim = vec![0xa2, 1, 0, 2];
    cbor::write_argument(&mut claim, 4, u64::MAX);
    assert!(tree_format::decode_node(&claim, true, 262144).is_err());
}

#[test]
fn graft_merge_and_empty_overlay_recipe_models_roundtrip_without_trust_verification() {
    let mut generator = Generator::new(0xabe5_3551_4398_cf21);
    let trust = algebra::TrustContext::any();
    for case in 0..12 {
        let target = generator.bytes();
        let entry = Entry {
            kind: EntryKind::Tree {
                root: target,
                props: None,
            },
            attrs: vec![],
            attrs_present: false,
            xattrs: vec![],
            xattrs_present: false,
            provenance: None,
        };
        let entry_bytes = tree_format::encode_entry(&entry, 262144).unwrap();
        let policies = [
            algebra::MergePolicy::PreferOurs,
            algebra::MergePolicy::PreferTheirs,
            algebra::MergePolicy::PreferTrusted,
            algebra::MergePolicy::PreferNewer,
            algebra::MergePolicy::KeepConflict,
            algebra::MergePolicy::Error,
        ];
        let recipes = [
            algebra::Recipe::Overlay(&[]),
            algebra::Recipe::Graft {
                parent: generator.bytes(),
                target,
                at: b"subtree",
                entry: &entry_bytes,
                replace: case % 2 == 0,
                domains: None,
            },
            algebra::Recipe::Merge {
                base: generator.bytes(),
                ours: generator.bytes(),
                theirs: generator.bytes(),
                policies: &policies[..case % policies.len() + 1],
                trust: &trust,
                domains: None,
            },
        ];
        for recipe in recipes {
            let bytes = recipe.encode();
            assert_eq!(algebra::Recipe::decode(&bytes).unwrap().as_recipe(), recipe);
            cbor_properties("algebra recipe", &bytes, |input| {
                Ok::<_, algebra::RecipeError>(algebra::Recipe::decode(input)?.as_recipe().encode())
            });
        }
    }
}
