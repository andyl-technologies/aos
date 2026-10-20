//! Tests every registered property vocabulary, inheritance bindings, and recipes.

use super::support::{Generator, cbor_properties};
use terrane_format::properties::PropertyName;
use terrane_format::tree_format::{Entry, EntryKind, Node, NodeItems, Property};
use terrane_format::{algebra, cbor, properties, tree_format};

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
        Compression => &[
            "raw",
            "zstd",
            "zstd:elf",
            "zstd:shebang",
            "zstd:ar",
            "zstd:zstd",
            "zstd:gzip",
            "zstd:tar",
            "zstd:text",
            "zstd:other",
        ],
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
        IndexGaps => values.extend([text(&format!("{value:064x}")), text(&"f".repeat(64))]),
        IndexRoots => {
            values.push(vec![0xa0]);
            let mut roots = vec![];
            cbor::write_map(&mut roots, 2);
            // Canonical text keys are ordered by encoded length, then bytes.
            for (attribute, identity) in [("uid", value), ("hash.sha256", u64::MAX)] {
                cbor::write_text(&mut roots, attribute);
                cbor::write_text(&mut roots, &format!("{identity:064x}"));
            }
            values.push(roots);
        }
        Index => values.extend([names(&[]), names(&["hash.sha256", "class.magic"])]),
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
                if (*name == PropertyName::Acl && inherit == Some(false))
                    || (matches!(*name, PropertyName::IndexRoots | PropertyName::IndexGaps)
                        && inherit != Some(false))
                {
                    assert!(properties::validate_property(&property).is_err());
                    continue;
                }
                let model = properties::validate_property(&property)
                    .unwrap_or_else(|error| panic!("{name:?} {inherit:?} {bytes:?}: {error:?}"));
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

fn selector_atom(operator: &str, argument: &str) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_array(&mut bytes, 2);
    cbor::write_text(&mut bytes, operator);
    cbor::write_text(&mut bytes, argument);
    bytes
}

#[test]
fn selector_models_cover_every_atom_combinator_preset_and_deep_untrusted_ast() {
    use terrane_format::provenance::{Preset, Selector, SelectorError};
    let mut generator = Generator::new(0x809c_7142_aede_3259);
    let mut atoms = vec![];
    for (operator, arguments) in [
        ("issuer", &["issuer", "generated-λ"][..]),
        ("subject", &["principal", "workload-*"][..]),
        ("kind", &["human", "workload", "service"][..]),
        ("group", &["group", "generated-λ"][..]),
        (
            "source",
            &[
                "built", "uploaded", "imported", "merged", "derived", "migrated",
            ][..],
        ),
        (
            "preset",
            &["any", "signed-baseline", "strict", "attested"][..],
        ),
    ] {
        atoms.extend(
            arguments
                .iter()
                .map(|argument| selector_atom(operator, argument)),
        );
    }
    let signing_key: String = generator
        .bytes::<32>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    atoms.push(selector_atom("signed-by-key", &signing_key));
    for atom in &atoms {
        cbor_properties("selector atom", atom, |input| {
            Ok::<_, SelectorError>(Selector::decode(input)?.encode().to_vec())
        });
        for wrapper in ["not", "accepted-by"] {
            let mut bytes = vec![];
            cbor::write_array(&mut bytes, 2);
            cbor::write_text(&mut bytes, wrapper);
            bytes.extend_from_slice(atom);
            cbor_properties("selector unary", &bytes, |input| {
                Ok::<_, SelectorError>(Selector::decode(input)?.encode().to_vec())
            });
        }
    }
    for attribute in [
        "uid",
        "gid",
        "zstd-dictionary",
        "hash.sha256",
        "hash.sha512",
        "hash.git-blob-sha1",
        "hash.git-blob-sha256",
        "class.magic",
        "class.elf",
        "class.shebang",
        "provenance.reintroduced-from",
        "tag.generated",
        "nar.hash_sha256",
        "nar.size",
        "nar.references",
        "nar.deriver",
        "nar.signatures",
        "nar.ca",
        "nar.file_hash",
        "nar.file_size",
        "nar.compression",
        "nix-cache-info.store_dir",
        "nix-cache-info.priority",
        "nix-cache-info.want_mass_query",
        "reapi.size_bytes",
        "reapi.output_digests",
        "gha.key",
        "gha.version",
        "gha.scope",
        "gha.size",
        "gha.created_at",
        "oci.media_type",
        "oci.subject",
        "oci.annotations",
    ] {
        let mut bytes = vec![];
        cbor::write_array(&mut bytes, 3);
        cbor::write_text(&mut bytes, "attr-by");
        cbor::write_text(&mut bytes, attribute);
        bytes.extend_from_slice(&atoms[0]);
        cbor_properties("attribute selector", &bytes, |input| {
            Ok::<_, SelectorError>(Selector::decode(input)?.encode().to_vec())
        });
    }
    for operator in ["all", "any"] {
        let mut ordered = atoms.clone();
        generator.shuffle(&mut ordered);
        let mut bytes = vec![];
        cbor::write_array(&mut bytes, 2);
        cbor::write_text(&mut bytes, operator);
        cbor::write_array(&mut bytes, ordered.len());
        for atom in &ordered {
            bytes.extend_from_slice(atom);
        }
        cbor_properties("selector combinator", &bytes, |input| {
            Ok::<_, SelectorError>(Selector::decode(input)?.encode().to_vec())
        });
        let mut empty = vec![];
        cbor::write_array(&mut empty, 2);
        cbor::write_text(&mut empty, operator);
        cbor::write_array(&mut empty, 0);
        assert!(Selector::decode(&empty).is_err());
    }
    for (preset, name) in [
        (Preset::Any, "any"),
        (Preset::SignedBaseline, "signed-baseline"),
        (Preset::Strict, "strict"),
        (Preset::Attested, "attested"),
    ] {
        let model = Selector::preset(preset);
        assert_eq!(Selector::from_property(&text(name)).unwrap(), model);
        assert_eq!(Selector::decode(model.encode()).unwrap(), model);
    }
    for depth in [1, 64, 512] {
        let mut bytes = vec![];
        for _ in 0..depth {
            cbor::write_array(&mut bytes, 2);
            cbor::write_text(&mut bytes, "not");
        }
        bytes.extend_from_slice(&atoms[0]);
        assert_eq!(Selector::decode(&bytes).unwrap().encode(), bytes);
        assert!(Selector::decode(&bytes[..bytes.len() - 1]).is_err());
    }
    for (operator, argument) in [
        ("unknown", "x"),
        ("attested", "claim"),
        ("kind", "unknown"),
        ("source", "unknown"),
        ("preset", "unknown"),
        ("signed-by-key", "A"),
        ("signed-by-key", &"AA".repeat(32)),
    ] {
        assert!(Selector::decode(&selector_atom(operator, argument)).is_err());
    }
}

#[test]
fn recipe_domain_evidence_roundtrips_all_operations_without_authenticating_labels() {
    let mut generator = Generator::new(0xb75a_d1d8_9993_817f);
    for count in [0, 1, 4] {
        let roots: Vec<_> = (0..count)
            .map(|index| {
                let mut root = generator.bytes::<32>();
                root[0] = index as u8;
                root
            })
            .collect();
        let mut encoded = vec![];
        cbor::write_map(&mut encoded, 3);
        cbor::write_uint(&mut encoded, 1);
        cbor::write_text(&mut encoded, "overlay");
        cbor::write_uint(&mut encoded, 2);
        cbor::write_array(&mut encoded, roots.len());
        for root in &roots {
            cbor::write_bytes(&mut encoded, root);
        }
        cbor::write_uint(&mut encoded, 3);
        cbor::write_map(&mut encoded, 1);
        cbor::write_text(&mut encoded, "domains");
        cbor::write_array(&mut encoded, roots.len());
        for (index, root) in roots.iter().enumerate() {
            cbor::write_array(&mut encoded, 2);
            cbor::write_bytes(&mut encoded, root);
            cbor::write_text(
                &mut encoded,
                [
                    "public",
                    "tenant:generated",
                    "group:generated",
                    "private:generated",
                ][index],
            );
        }
        let owned = algebra::Recipe::decode(&encoded).unwrap();
        let algebra::Recipe::OverlayWithDomains { domains, .. } = owned.as_recipe() else {
            panic!("domain alternative");
        };
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
        let trust = algebra::TrustContext::any();
        let policies = [algebra::MergePolicy::KeepConflict];
        for recipe in [
            owned.as_recipe(),
            algebra::Recipe::Graft {
                parent: generator.bytes(),
                target,
                at: b"subtree",
                entry: &entry_bytes,
                replace: true,
                domains: Some(domains),
            },
            algebra::Recipe::Merge {
                base: generator.bytes(),
                ours: generator.bytes(),
                theirs: generator.bytes(),
                policies: &policies,
                trust: &trust,
                domains: Some(domains),
            },
        ] {
            let bytes = recipe.encode();
            assert_eq!(algebra::Recipe::decode(&bytes).unwrap().as_recipe(), recipe);
            cbor_properties("untrusted recipe domains", &bytes, |input| {
                Ok::<_, algebra::RecipeError>(algebra::Recipe::decode(input)?.as_recipe().encode())
            });
        }
    }
}

#[test]
fn merge_recipe_untrusted_receipt_and_timestamp_fields_reencode_canonically() {
    let mut generator = Generator::new(0x749b_218e_dbae_61cc);
    for count in [0, 1, 7] {
        for timestamps in [false, true] {
            if timestamps && count == 0 {
                continue;
            }
            let roots: Vec<_> = (0..3).map(|_| generator.bytes::<32>()).collect();
            let receipts: Vec<_> = (0..count)
                .map(|index| {
                    let mut value = generator.bytes::<32>();
                    value[0] = index as u8;
                    value
                })
                .collect();
            let mut bytes = vec![];
            cbor::write_map(&mut bytes, 3);
            cbor::write_uint(&mut bytes, 1);
            cbor::write_text(&mut bytes, "merge");
            cbor::write_uint(&mut bytes, 2);
            cbor::write_array(&mut bytes, 3);
            for root in &roots {
                cbor::write_bytes(&mut bytes, root);
            }
            cbor::write_uint(&mut bytes, 3);
            cbor::write_map(&mut bytes, 2);
            cbor::write_text(&mut bytes, "trust");
            cbor::write_map(&mut bytes, if timestamps { 5 } else { 4 });
            cbor::write_uint(&mut bytes, 1);
            bytes.extend(selector_atom("preset", "strict"));
            cbor::write_uint(&mut bytes, 2);
            cbor::write_text(&mut bytes, "opaque-evaluator/v2");
            cbor::write_uint(&mut bytes, 3);
            bytes.extend_from_slice(&[0xa1, 0, 0x82, 0xf4, 0xf6]);
            cbor::write_uint(&mut bytes, 4);
            cbor::write_array(&mut bytes, receipts.len());
            for receipt in &receipts {
                cbor::write_bytes(&mut bytes, receipt);
            }
            if timestamps {
                cbor::write_uint(&mut bytes, 5);
                cbor::write_array(&mut bytes, receipts.len());
                for receipt in &receipts {
                    cbor::write_array(&mut bytes, 2);
                    cbor::write_bytes(&mut bytes, receipt);
                    cbor::write_uint(&mut bytes, generator.next());
                }
            }
            cbor::write_text(&mut bytes, "policy");
            cbor::write_array(&mut bytes, 2);
            cbor::write_text(&mut bytes, "prefer-trusted");
            cbor::write_text(&mut bytes, "prefer-newer");
            cbor_properties("unverified merge receipt bytes", &bytes, |input| {
                Ok::<_, algebra::RecipeError>(algebra::Recipe::decode(input)?.as_recipe().encode())
            });
        }
    }
}

// Primitive framing bypasses the Entry encoder, including for present bodies
// above its registered standalone byte budget.
fn graft_entry_wire(target: &[u8], payload: usize) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_map(&mut bytes, 3);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_uint(&mut bytes, 4);
    cbor::write_uint(&mut bytes, 6);
    cbor::write_bytes(&mut bytes, target);
    cbor::write_uint(&mut bytes, 10);
    cbor::write_map(&mut bytes, 1);
    cbor::write_bytes(&mut bytes, b"x");
    cbor::write_bytes(&mut bytes, &vec![0; payload]);
    bytes
}

fn graft_wire(parent: &[u8], target: &[u8], entry: &[u8]) -> Vec<u8> {
    let mut bytes = vec![];
    cbor::write_map(&mut bytes, 3);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_text(&mut bytes, "graft");
    cbor::write_uint(&mut bytes, 2);
    cbor::write_array(&mut bytes, 2);
    cbor::write_bytes(&mut bytes, parent);
    cbor::write_bytes(&mut bytes, target);
    cbor::write_uint(&mut bytes, 3);
    cbor::write_map(&mut bytes, 3);
    cbor::write_text(&mut bytes, "at");
    cbor::write_bytes(&mut bytes, b"a");
    cbor::write_text(&mut bytes, "entry");
    cbor::write_bytes(&mut bytes, entry);
    cbor::write_text(&mut bytes, "replace");
    bytes.push(0xf4);
    bytes
}

#[test]
fn graft_embedded_entry_limits_precede_owned_recipe_fields() {
    let mut generator = Generator::new(0x2ade_7cc1_60d2_1559);
    for _ in 0..8 {
        let parent = generator.bytes();
        let target = generator.bytes();
        let entry = graft_entry_wire(&target, 3);
        let expected = graft_wire(&parent, &target, &entry);
        let model = algebra::Recipe::Graft {
            parent,
            target,
            at: b"a",
            entry: &entry,
            replace: false,
            domains: None,
        };
        assert_eq!(model.encode(), expected);
        assert_eq!(
            algebra::Recipe::decode(&expected).unwrap().as_recipe(),
            model
        );
        assert_eq!(
            algebra::Recipe::decode(&expected)
                .unwrap()
                .as_recipe()
                .identity(),
            model.identity()
        );
        cbor_properties("bounded graft Entry", &expected, |bytes| {
            Ok::<_, algebra::RecipeError>(algebra::Recipe::decode(bytes)?.as_recipe().encode())
        });
    }

    // A three-byte bstr header makes the complete Entry framing 45 bytes.
    let target = [7; 32];
    let maximum = tree_format::MAX_NODE_ITEMS_BYTES;
    for length in [maximum - 1, maximum, maximum + 1] {
        let entry = graft_entry_wire(&target, length - 45);
        assert_eq!(entry.len(), length);
        let wire = graft_wire(&[6; 32], &target, &entry);
        if length <= maximum {
            assert!(tree_format::decode_entry_bytes(&entry, 0).is_ok());
            assert_eq!(
                algebra::Recipe::decode(&wire).unwrap().as_recipe().encode(),
                wire
            );
        } else {
            assert_eq!(
                tree_format::decode_entry_bytes(&entry, 0),
                Err(tree_format::Error::Limit)
            );
            // This outer typed limit differs from the old nested Schema refusal.
            assert_eq!(
                algebra::Recipe::decode(&wire),
                Err(algebra::RecipeError::Encoding(cbor::Error::Limit))
            );
        }
    }
    let malformed = graft_entry_wire(&[7; 31], 0);
    assert_eq!(
        algebra::Recipe::decode(&graft_wire(&[6; 32], &target, &malformed)),
        Err(algebra::RecipeError::Schema)
    );
    let mismatched = graft_entry_wire(&[8; 32], 0);
    assert_eq!(
        algebra::Recipe::decode(&graft_wire(&[6; 32], &target, &mismatched)),
        Err(algebra::RecipeError::Schema)
    );
}
