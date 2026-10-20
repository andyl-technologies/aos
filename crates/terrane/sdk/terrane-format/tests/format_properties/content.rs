//! Tests content, tree, property, derived-data, selector, recipe, and token formats.

use super::support::{Generator, cbor_properties, check_record};
use std::collections::BTreeMap;
use terrane_format::derived::{AttrRecord, AttributeValue, ElfValue, Magic, ShebangValue};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_format::manifest::{ChunkRef, Manifest};
use terrane_format::provenance::Selector;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{
    self, Attribute, ContentRef, Entry, EntryKind, ExtendedAttribute, LeafItem, Node, NodeItems,
    Property, TreeUse,
};
use terrane_format::{algebra::Recipe, auth::Token, cbor, chunking::ChunkProfile, codec};

const MIN: u64 = 262_144;

fn entry(kind: EntryKind<'_>) -> Entry<'_> {
    Entry {
        kind,
        attrs: vec![],
        attrs_present: false,
        xattrs: vec![],
        xattrs_present: false,
        provenance: None,
    }
}

#[test]
fn identity_descriptors_validate_every_registered_domain_and_wire_boundary() {
    let mut generator = Generator::new(0x41bd_637a_2886_105f);
    for kind in [
        IdentityKind::Chunk,
        IdentityKind::Manifest,
        IdentityKind::Node,
        IdentityKind::Commit,
        IdentityKind::Bundle,
        IdentityKind::Pack,
        IdentityKind::Index,
        IdentityKind::Filter,
        IdentityKind::Attribute,
        IdentityKind::Policy,
        IdentityKind::Memo,
    ] {
        for size in [0, 1, 23, 24, 255, 256, 4096] {
            let plaintext: Vec<_> = (0..size).map(|_| generator.next() as u8).collect();
            let identity = TERRANE_V1.calculate(kind, &plaintext).unwrap();
            let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, &plaintext).unwrap();
            let bytes = descriptor.encode();
            assert_eq!(Descriptor::decode(&TERRANE_V1, &bytes).unwrap(), descriptor);
            cbor_properties("identity descriptor", &bytes, |input| {
                Ok::<_, terrane_format::identity::descriptor::Error>(
                    Descriptor::decode(&TERRANE_V1, input)?.encode(),
                )
            });
            let wire = Descriptor::from_wire(
                &TERRANE_V1,
                descriptor.algorithm(),
                descriptor.domain(),
                descriptor.digest(),
                descriptor.size(),
            )
            .unwrap();
            assert_eq!(wire, descriptor);
            assert_eq!(
                wire.verify_bytes(&TERRANE_V1, kind, &plaintext).unwrap(),
                identity
            );
            assert_eq!(wire.to_string(), descriptor.to_string());
            for wrong_size in [size as u64 + 1, u64::MAX] {
                let wrong = Descriptor::from_wire(
                    &TERRANE_V1,
                    descriptor.algorithm(),
                    descriptor.domain(),
                    descriptor.digest(),
                    wrong_size,
                )
                .unwrap();
                assert_eq!(
                    Descriptor::decode(&TERRANE_V1, &wrong.encode()).unwrap(),
                    wrong
                );
                assert!(wrong.verify_bytes(&TERRANE_V1, kind, &plaintext).is_err());
            }
            for length in [0, 1, 31, 33, 64] {
                assert!(
                    Descriptor::from_wire(
                        &TERRANE_V1,
                        "blake3",
                        descriptor.domain(),
                        &vec![0; length],
                        0
                    )
                    .is_err()
                );
            }
            assert!(
                Descriptor::from_wire(&TERRANE_V1, "unknown", descriptor.domain(), &[0; 32], 0)
                    .is_err()
            );
            assert!(Descriptor::from_wire(&TERRANE_V1, "blake3", "unknown", &[0; 32], 0).is_err());
        }
    }
}

#[test]
fn canonical_cbor_models_cover_integer_lengths_maps_and_preallocation_limits() {
    let mut generator = Generator::new(0x118e_2bd1_986a_4413);
    for value in [
        0,
        1,
        23,
        24,
        255,
        256,
        65535,
        65536,
        u32::MAX as u64,
        u32::MAX as u64 + 1,
        u64::MAX,
    ]
    .into_iter()
    .chain((0..32).map(|_| generator.next()))
    {
        let mut encoded = vec![];
        cbor::write_map(&mut encoded, 2);
        cbor::write_uint(&mut encoded, 0);
        cbor::write_uint(&mut encoded, value);
        cbor::write_uint(&mut encoded, 1);
        cbor::write_negative_argument(&mut encoded, value);
        cbor_properties("generic CBOR", &encoded, |input| {
            let mut decoder = cbor::Decoder::new(input);
            let raw = decoder.raw_value(input.len())?.to_vec();
            decoder.finish()?;
            Ok::<_, cbor::Error>(raw)
        });
    }
    for major in 2..=5 {
        let mut claimed = vec![];
        cbor::write_argument(&mut claimed, major, u64::MAX);
        let mut decoder = cbor::Decoder::new(&claimed);
        let error = match major {
            2 => decoder.bytes(65536).map(|_| ()),
            3 => decoder.text(4096).map(|_| ()),
            4 => decoder.array(256).map(|_| ()),
            _ => decoder.map(256).map(|_| ()),
        };
        assert_eq!(error, Err(cbor::Error::Limit));
        assert_eq!(decoder.position(), claimed.len());
    }
    for malformed in [
        &[0x9f, 0xff][..],
        &[0xc0, 0][..],
        &[0xf9, 0, 0][..],
        &[0x61, 0xff][..],
    ] {
        assert!(cbor::Decoder::new(malformed).skip_value(64).is_err());
    }
}

#[test]
fn manifests_preserve_order_optional_hashes_and_chunk_size_boundaries() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let mut generator = Generator::new(0x1375_5c99_67e0_33ad);
    for final_length in [0, 1, MIN - 1, MIN, MIN + 1, 4_194_304] {
        for count in [1, 2, 7] {
            if final_length == 0 && count > 1 {
                continue;
            }
            let mut chunks: Vec<_> = (0..count)
                .map(|_| ChunkRef {
                    digest: generator.bytes(),
                    length: MIN,
                })
                .collect();
            chunks.last_mut().unwrap().length = final_length;
            let mut model = Manifest {
                size: chunks.iter().map(|chunk| chunk.length).sum(),
                chunks,
                hashes: BTreeMap::from([
                    ("blake3".into(), generator.bytes::<32>().to_vec()),
                    ("sha256".into(), generator.bytes::<32>().to_vec()),
                ]),
                media_type: (count % 2 == 0).then(|| "application/x-generated".into()),
            };
            if model.size == 0 {
                model.chunks[0].digest = TERRANE_V1
                    .calculate(IdentityKind::Chunk, &[])
                    .unwrap()
                    .terrane_v1_digest()
                    .unwrap();
                model
                    .hashes
                    .insert("blake3".into(), blake3::hash(&[]).as_bytes().to_vec());
                model.hashes.insert("sha256".into(), vec![0; 32]);
            }
            let bytes = model.encode(&profile).unwrap();
            assert_eq!(Manifest::decode(&bytes, &profile).unwrap(), model);
            assert_eq!(
                model.identity(&profile).unwrap(),
                Manifest::decode(&bytes, &profile)
                    .unwrap()
                    .identity(&profile)
                    .unwrap()
            );
            cbor_properties("manifest", &bytes, |input| {
                Manifest::decode(input, &profile)?.encode(&profile)
            });
            let mut invalid = model.clone();
            invalid.size += 1;
            assert!(invalid.encode(&profile).is_err());
            let mut invalid = model;
            invalid.chunks[0].length = 4_194_305;
            assert!(invalid.encode(&profile).is_err());
        }
    }
    let oversized_count = [
        0xa3, 1, 0, 2, 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    assert!(Manifest::decode(&oversized_count, &profile).is_err());
}

#[test]
fn entries_nodes_and_properties_cover_all_kinds_and_optional_presence() {
    let mut generator = Generator::new(0x33f1_57de_2c55_e8a9);
    for case in 0..24 {
        let target: Vec<_> = (0..[0, 1, 255, 4096][case % 4])
            .map(|_| generator.next() as u8)
            .collect();
        let mut entries = vec![
            entry(EntryKind::File {
                mode: [0, 0o644, 0o7777][case % 3],
                size: if case % 2 == 0 { MIN } else { MIN + 1 },
                content: if case % 2 == 0 {
                    ContentRef::Inline(generator.bytes())
                } else {
                    ContentRef::Manifest(generator.bytes())
                },
                link_id: (case % 3 == 0).then_some(b"entry-00".as_slice()),
            }),
            entry(EntryKind::Directory { mode: 0o755 }),
            entry(EntryKind::Symlink { target: &target }),
            entry(EntryKind::Tree {
                root: generator.bytes(),
                props: match case % 3 {
                    0 => None,
                    1 => Some(vec![]),
                    _ => Some(vec![Property {
                        name: "domain",
                        value: b"\x66public",
                    }]),
                },
            }),
            entry(EntryKind::Whiteout),
            entry(EntryKind::Conflict {
                candidates: vec![
                    entry(EntryKind::Directory { mode: 0o755 }),
                    entry(EntryKind::Whiteout),
                ],
                base: match case % 3 {
                    0 => None,
                    1 => Some(None),
                    _ => Some(Some(Box::new(entry(EntryKind::Directory { mode: 0 })))),
                },
            }),
            entry(EntryKind::Index {
                targets: vec![[0; 32], [255; 32]],
            }),
        ];
        for model in &mut entries {
            model.attrs_present = case % 2 == 0;
            model.xattrs_present = case % 3 == 0;
            model.provenance = (case % 4 == 0).then(|| generator.bytes());
            if case % 5 == 0 {
                model.attrs_present = true;
                model.xattrs_present = true;
                model.attrs = vec![Attribute {
                    name: "test",
                    value: &[0x82, 0xf4, 0xf6],
                }];
                model.xattrs = vec![ExtendedAttribute {
                    name: b"user.test",
                    value: &target,
                }];
            }
            if matches!(model.kind, EntryKind::Whiteout) {
                model.attrs.clear();
                model.xattrs.clear();
                model.attrs_present = false;
                model.xattrs_present = false;
            }
            let bytes = tree_format::encode_entry(model, MIN).unwrap();
            assert_eq!(
                tree_format::decode_entry_bytes(&bytes, MIN).unwrap(),
                *model
            );
            cbor_properties("entry", &bytes, |input| {
                tree_format::encode_entry(&tree_format::decode_entry_bytes(input, MIN)?, MIN)
            });
        }
        let model = Node {
            level: 0,
            items: NodeItems::Leaf(
                entries
                    .into_iter()
                    .filter(|entry| {
                        !matches!(entry.kind, EntryKind::Index { .. } | EntryKind::Whiteout)
                    })
                    .enumerate()
                    .map(|(index, entry)| LeafItem {
                        key: format!("entry-{index:02}").into_bytes(),
                        entry,
                    })
                    .collect(),
            ),
            props: (case % 2 == 0).then(Vec::new),
        };
        let bytes = tree_format::encode_node(&model, true, MIN).unwrap();
        assert_eq!(tree_format::decode_node(&bytes, true, MIN).unwrap(), model);
        cbor_properties("leaf node", &bytes, |input| {
            tree_format::encode_node(&tree_format::decode_node(input, true, MIN)?, true, MIN)
        });
    }
    for value in [0, 1, 23, 24, 65536, u64::MAX] {
        let mut bytes = vec![];
        cbor::write_uint(&mut bytes, value);
        let property = Property {
            name: "gap_merge_bytes",
            value: &bytes,
        };
        terrane_format::properties::validate_property(&property).unwrap();
        cbor_properties("unsigned property", &bytes, |input| {
            terrane_format::properties::validate_property(&Property {
                name: property.name,
                value: input,
            })?;
            Ok::<_, terrane_format::properties::Error>(input.to_vec())
        });
    }
    let long_target = vec![0; 4097];
    assert!(
        tree_format::encode_entry(
            &entry(EntryKind::Symlink {
                target: &long_target
            }),
            MIN
        )
        .is_err()
    );
    let too_many = vec![
        Attribute {
            name: "test",
            value: &[0]
        };
        257
    ];
    let mut invalid = entry(EntryKind::Directory { mode: 0 });
    invalid.attrs = too_many;
    invalid.attrs_present = true;
    assert!(tree_format::encode_entry(&invalid, MIN).is_err());
}

#[test]
fn generated_tree_insertion_orders_match_sorted_model_and_internal_node_bytes() {
    let mut generator = Generator::new(0xc00a_d927_c531_efd3);
    for count in [0, 1, 64, 320] {
        let items: Vec<_> = (0..count)
            .map(|index| LeafItem {
                key: format!("{index:06}-{}", "p".repeat(180)).into_bytes(),
                entry: entry(EntryKind::Directory {
                    mode: (generator.next() & 0xfff) as u16,
                }),
            })
            .collect();
        let expected = Tree::build(items.clone(), None, MIN, TreeUse::Ordinary).unwrap();
        for _ in 0..3 {
            let mut order = items.clone();
            generator.shuffle(&mut order);
            let mut actual = Tree::build(vec![], None, MIN, TreeUse::Ordinary).unwrap();
            for item in order {
                actual = actual.insert(item).unwrap().tree;
            }
            assert_eq!(actual.iter().cloned().collect::<Vec<_>>(), items);
            assert_eq!(actual.root_identity(), expected.root_identity());
            assert_eq!(actual.root().encoded(), expected.root().encoded());
        }
        for node in expected.nodes() {
            let root = node.identity() == expected.root_identity();
            assert_eq!(
                tree_format::decode_node(node.encoded(), root, MIN).unwrap(),
                *node.node()
            );
            cbor_properties("generated tree node", node.encoded(), |input| {
                tree_format::encode_node(&tree_format::decode_node(input, root, MIN)?, root, MIN)
            });
        }
        if count == 320 {
            assert!(expected.root().level() > 0);
        }
    }
}

#[test]
fn derived_attribute_values_and_records_cover_every_registered_variant() {
    let mut generator = Generator::new(0x36cc_8149_7e2a_086d);
    for case in 0..12 {
        let values = [
            AttributeValue::Sha256(generator.bytes()),
            AttributeValue::Sha512(generator.bytes()),
            AttributeValue::GitBlobSha1(generator.bytes()),
            AttributeValue::GitBlobSha256(generator.bytes()),
            AttributeValue::ZstdDictionary(generator.bytes()),
            AttributeValue::Magic(
                Magic::parse(
                    [
                        "elf", "shebang", "ar", "zstd", "gzip", "tar", "text", "other",
                    ][case % 8],
                )
                .unwrap(),
            ),
            AttributeValue::Elf(ElfValue {
                class: if case % 2 == 0 { 32 } else { 64 },
                machine: generator.next() as u16,
                elf_type: generator.next() as u16,
                interpreter: (case % 2 == 0).then(|| "/interpreter".into()),
                needed: (0..case % 4)
                    .map(|index| format!("lib{index}.so"))
                    .collect(),
            }),
            AttributeValue::Shebang(ShebangValue {
                interpreter: "/interpreter".into(),
                argument: (case % 2 == 0).then(|| "--generated".into()),
            }),
        ];
        for value in values {
            let bytes = value.encode().unwrap();
            assert_eq!(AttributeValue::decode(value.name(), &bytes).unwrap(), value);
            cbor_properties("attribute value", &bytes, |input| {
                AttributeValue::decode(value.name(), input)?.encode()
            });
            let mut model = AttrRecord::new(generator.bytes(), value, generator.bytes());
            model.signature = (case % 2 == 0).then(|| generator.bytes());
            let mut unsigned = model.clone();
            unsigned.signature = None;
            assert_eq!(
                model.signature_preimage().unwrap(),
                [
                    b"terrane-attr-signature-v1\0".as_slice(),
                    &unsigned.encode().unwrap()
                ]
                .concat()
            );
            check_record!("attribute record", model, AttrRecord);
        }
    }
}

#[test]
fn selectors_recipes_and_unverified_token_envelopes_have_unique_canonical_bytes() {
    let mut generator = Generator::new(0xf23c_9971_1544_bb4d);
    for count in [1, 3, 16] {
        let mut selector = vec![];
        cbor::write_array(&mut selector, 2);
        cbor::write_text(&mut selector, "all");
        cbor::write_array(&mut selector, count);
        for index in 0..count {
            cbor::write_array(&mut selector, 2);
            cbor::write_text(&mut selector, "subject");
            cbor::write_text(&mut selector, &format!("principal-{index}"));
        }
        cbor_properties("selector", &selector, |input| {
            Ok::<_, terrane_format::provenance::SelectorError>(
                Selector::decode(input)?.encode().to_vec(),
            )
        });
        let roots: Vec<_> = (0..count).map(|_| generator.bytes()).collect();
        let recipe = Recipe::Overlay(&roots);
        let bytes = recipe.encode();
        assert_eq!(Recipe::decode(&bytes).unwrap().as_recipe(), recipe);
        cbor_properties("overlay recipe", &bytes, |input| {
            Ok::<_, terrane_format::algebra::RecipeError>(
                Recipe::decode(input)?.as_recipe().encode(),
            )
        });
    }
    // Structurally correct, deliberately unauthenticated signature bytes.
    // Token issuance and verification are outside this pure-envelope exercise.
    for grants in [1, 8, 256] {
        let mut bytes = vec![];
        cbor::write_array(&mut bytes, 1);
        cbor::write_map(&mut bytes, 10);
        for (key, text) in [(1, "issuer"), (2, "key"), (3, "subject")] {
            cbor::write_uint(&mut bytes, key);
            cbor::write_text(&mut bytes, text);
        }
        cbor::write_uint(&mut bytes, 4);
        cbor::write_uint(&mut bytes, 1);
        cbor::write_uint(&mut bytes, 5);
        cbor::write_array(&mut bytes, 0);
        cbor::write_uint(&mut bytes, 6);
        cbor::write_uint(&mut bytes, u64::MAX);
        cbor::write_uint(&mut bytes, 8);
        cbor::write_bytes(&mut bytes, &generator.bytes::<16>());
        cbor::write_uint(&mut bytes, 9);
        cbor::write_array(&mut bytes, grants);
        for index in 0..grants {
            cbor::write_array(&mut bytes, 2);
            cbor::write_text(&mut bytes, &format!("refs/heads/_/branch-{index}"));
            cbor::write_uint(&mut bytes, 1);
        }
        cbor::write_uint(&mut bytes, 11);
        cbor::write_bytes(&mut bytes, &generator.bytes::<32>());
        cbor::write_uint(&mut bytes, 12);
        cbor::write_bytes(&mut bytes, &generator.bytes::<64>());
        cbor_properties("unverified token", &bytes, |input| {
            Ok::<_, terrane_format::auth::Unauthorized>(Token::decode(input)?.encode())
        });
    }
    assert!(Token::decode(&[0x91]).is_err());
    assert!(Token::decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
}

#[test]
fn chunk_envelopes_roundtrip_opaque_bodies_and_bound_declared_lengths() {
    let mut generator = Generator::new(0x943e_cbb1_4325_111a);
    for length in [0, 1, 31, 32, 255, 4096] {
        let body: Vec<_> = (0..length).map(|_| generator.next() as u8).collect();
        for encoding in [
            codec::Codec::Raw,
            codec::Codec::Zstd,
            codec::Codec::ZstdDictionary(generator.bytes()),
        ] {
            let model = codec::EncodedChunk {
                codec: encoding,
                body: &body,
            };
            let bytes = codec::encode_envelope(model);
            assert_eq!(codec::parse_envelope(&bytes).unwrap(), model);
            for end in 0..bytes.len() {
                if let Ok(decoded) = codec::parse_envelope(&bytes[..end]) {
                    assert_eq!(codec::encode_envelope(decoded), bytes[..end]);
                }
            }
            assert!(codec::validate_envelope_size(model, usize::MAX, 4_194_304).is_err());
        }
    }
    for tag in 3..=255 {
        assert!(codec::parse_envelope(&[tag]).is_err());
    }
    for length in 0..32 {
        assert!(codec::parse_envelope(&[vec![2], vec![0; length]].concat()).is_err());
    }
}

#[test]
fn unverified_attenuation_envelopes_cover_all_caveats_and_chain_count_boundaries() {
    let mut generator = Generator::new(0x899a_257e_bb61_277e);
    for (grants, blocks) in [(1, 1), (2, 2), (1, 16), (256, 2)] {
        let bytes = super::support::token_bytes(grants, blocks, &mut generator);
        cbor_properties("token chain/caveats", &bytes, |input| {
            Ok::<_, terrane_format::auth::Unauthorized>(Token::decode(input)?.encode())
        });
    }
    for (grants, blocks) in [(0, 1), (257, 1), (1, 17)] {
        assert!(
            Token::decode(&super::support::token_bytes(grants, blocks, &mut generator)).is_err()
        );
    }
}

#[test]
fn index_overlay_and_internal_nodes_cover_context_and_summary_boundaries() {
    let mut generator = Generator::new(0x90bc_d88a_55f1_d04b);
    for usage in [TreeUse::Index, TreeUse::OverlayLayer] {
        let items = (0..8)
            .map(|index| LeafItem {
                key: if usage == TreeUse::Index {
                    vec![index, 0, b'/']
                } else {
                    format!("key-{index}").into_bytes()
                },
                entry: entry(if usage == TreeUse::Index {
                    EntryKind::Index {
                        targets: vec![[0; 32], [255; 32]],
                    }
                } else {
                    EntryKind::Whiteout
                }),
            })
            .collect();
        let model = Node {
            level: 0,
            items: NodeItems::Leaf(items),
            props: None,
        };
        let bytes = tree_format::encode_node_for(&model, true, MIN, usage).unwrap();
        assert_eq!(
            tree_format::decode_node_for(&bytes, true, MIN, usage).unwrap(),
            model
        );
        cbor_properties("context node", &bytes, |input| {
            tree_format::encode_node_for(
                &tree_format::decode_node_for(input, true, MIN, usage)?,
                true,
                MIN,
                usage,
            )
        });
        assert!(tree_format::decode_node(&bytes, true, MIN).is_err());
    }
    for level in [1, 15] {
        let model = Node {
            level,
            items: NodeItems::Internal(vec![tree_format::ChildRef {
                last_key: b"last".to_vec(),
                child: generator.bytes(),
                count: u64::MAX,
                weight: u64::MAX,
            }]),
            props: None,
        };
        let bytes = tree_format::encode_node(&model, true, MIN).unwrap();
        assert_eq!(tree_format::decode_node(&bytes, true, MIN).unwrap(), model);
        cbor_properties("internal summary node", &bytes, |input| {
            tree_format::encode_node(&tree_format::decode_node(input, true, MIN)?, true, MIN)
        });
    }
    let names: Vec<_> = (0..256)
        .map(|index| format!("attribute-{index:03}"))
        .collect();
    let mut model = entry(EntryKind::Directory { mode: 0 });
    model.attrs_present = true;
    model.attrs = names
        .iter()
        .map(|name| Attribute {
            name,
            value: &[0xf4],
        })
        .collect();
    let bytes = tree_format::encode_entry(&model, MIN).unwrap();
    assert_eq!(tree_format::decode_entry_bytes(&bytes, MIN).unwrap(), model);
    cbor_properties("max attribute count", &bytes, |input| {
        tree_format::encode_entry(&tree_format::decode_entry_bytes(input, MIN)?, MIN)
    });
    model.attrs.push(Attribute {
        name: "extra",
        value: &[0xf4],
    });
    assert!(tree_format::encode_entry(&model, MIN).is_err());
}

#[test]
fn token_field_models_cover_all_principal_kinds_verb_bits_and_absent_attenuation_fields() {
    let mut generator = Generator::new(0x371b_a3de_f17a_cc87);
    let source = super::support::token_bytes(1, 1, &mut generator);
    let mut decoder = cbor::Decoder::new(&source);
    assert_eq!(decoder.array(1).unwrap(), 1);
    let count = decoder.map(12).unwrap();
    let mut fields = BTreeMap::new();
    for _ in 0..count {
        let key = decoder.uint().unwrap();
        fields.insert(key, decoder.raw_value(source.len()).unwrap().to_vec());
    }
    for kind in 1..=3 {
        for optional in 0..4 {
            for mask in [1, 2, 4, 8, 16, 31] {
                let mut authority = fields.clone();
                authority.insert(4, vec![kind]);
                authority.insert(5, vec![0x80]);
                if optional & 1 == 0 {
                    authority.remove(&7);
                }
                if optional & 2 == 0 {
                    authority.remove(&10);
                }
                let mut grants = vec![];
                cbor::write_array(&mut grants, 1);
                cbor::write_array(&mut grants, 2);
                cbor::write_text(&mut grants, "refs/heads/_/main");
                cbor::write_uint(&mut grants, mask);
                authority.insert(9, grants);
                let mut bytes = vec![];
                cbor::write_array(&mut bytes, 2);
                cbor::write_map(&mut bytes, authority.len());
                for (key, value) in authority {
                    cbor::write_uint(&mut bytes, key);
                    bytes.extend(value);
                }
                // An empty attenuation body still carries the required opaque
                // next-key/signature envelope; no authority is verified.
                cbor::write_map(&mut bytes, 2);
                cbor::write_uint(&mut bytes, 5);
                cbor::write_bytes(&mut bytes, &generator.bytes::<32>());
                cbor::write_uint(&mut bytes, 6);
                cbor::write_bytes(&mut bytes, &generator.bytes::<64>());
                cbor_properties("token optional fields/kinds/verbs", &bytes, |input| {
                    Ok::<_, terrane_format::auth::Unauthorized>(Token::decode(input)?.encode())
                });
            }
        }
    }
}

#[test]
fn derived_function_metadata_and_text_values_preserve_unknown_versions_and_limits() {
    use terrane_format::derived::AttributeName;
    let mut generator = Generator::new(0x817e_223f_765a_dbba);
    for version in ["2".to_string(), "v".repeat(128)] {
        let mut record = AttrRecord::new(
            generator.bytes(),
            AttributeValue::Sha256(generator.bytes()),
            generator.bytes(),
        );
        record.function.version = version;
        assert!(!record.function.supported(AttributeName::Sha256));
        check_record!("preserved function version", record.clone(), AttrRecord);
        record.function.version.push('v');
        if record.function.version.len() > 128 {
            assert!(record.encode().is_err());
        }
    }
    let maximum = "a".repeat(65536);
    for value in [
        AttributeValue::Elf(ElfValue {
            class: 64,
            machine: u16::MAX,
            elf_type: u16::MAX,
            interpreter: Some(maximum.clone()),
            needed: vec![maximum.clone(), maximum.clone()],
        }),
        AttributeValue::Shebang(ShebangValue {
            interpreter: format!("/{}", "a".repeat(65535)),
            argument: Some(maximum.clone()),
        }),
    ] {
        let bytes = value.encode().unwrap();
        assert_eq!(AttributeValue::decode(value.name(), &bytes).unwrap(), value);
        for end in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert!(AttributeValue::decode(value.name(), &bytes[..end]).is_err());
        }
    }
    for text in ["a".repeat(65537), "contains\0NUL".into()] {
        let value = AttributeValue::Shebang(ShebangValue {
            interpreter: text,
            argument: None,
        });
        assert!(value.encode().is_err());
    }
}

#[test]
fn disclosure_target_bindings_normalize_only_typed_signatures_and_retain_metadata() {
    use terrane_format::{provenance::disclosure_target_binding, refs};
    let mut generator = Generator::new(0xf732_271d_abde_9371);
    for domain in [
        "public",
        "tenant:generated",
        "group:generated",
        "private:generated",
    ] {
        let mut model = super::records::commit(&mut generator, 0);
        model.signature = Some(generator.bytes());
        model.profile_pair.entry_receipts = Some(vec![refs::EntryReceipt {
            root: generator.bytes(),
            path: b"file".to_vec(),
            origin: refs::EntryOrigin::Current,
            attributes: None,
            reintroduced_from: Some(refs::EntrySource {
                commit: generator.bytes(),
                root: generator.bytes(),
                path: b"source".to_vec(),
            }),
            disclosure_proof: Some(refs::DisclosureProof {
                authority_key: "01".repeat(32),
                source_domain: domain.into(),
                observed_at: u64::MAX,
                signature: generator.bytes(),
            }),
        }]);
        check_record!("disclosure certificate domain", model.clone(), refs::Commit);
        let binding = disclosure_target_binding(&model).unwrap();
        let mut changed_signature = model.clone();
        changed_signature.signature = Some(generator.bytes());
        changed_signature
            .profile_pair
            .entry_receipts
            .as_mut()
            .unwrap()[0]
            .disclosure_proof
            .as_mut()
            .unwrap()
            .signature = generator.bytes();
        assert_eq!(
            disclosure_target_binding(&changed_signature).unwrap(),
            binding
        );
        let mut changed_metadata = model;
        changed_metadata.message.push_str("metadata matters");
        assert_ne!(
            disclosure_target_binding(&changed_metadata).unwrap(),
            binding
        );
    }
}
