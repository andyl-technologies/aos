//! Compares independent namespace witnesses with complete public format models.
//!
//! The prepared reference section supplies inert field data. Only whole nodes
//! receive identities; entries, provenance references and property selectors
//! establish neither immutable descriptors nor verified authority.
//!
//! ```text
//! node = {1: 0, 2: [[key_suffix, shared, entry]], ?3: properties}
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "independent format fixtures must match complete ordinary models"
)]

use terrane_format::cbor::{self, Decoder};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::properties::{
    PropertyName, validate_graft_overrides, validate_preserved_map, validate_property,
};
use terrane_format::tree_format::{
    Attribute, ContentRef, Entry, EntryKind, ExtendedAttribute, LeafItem, Node, NodeItems,
    Property, TreeUse, decode_entry_bytes, decode_node_for, encode_entry, encode_node_for,
    validate_tree_entries,
};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/terrane/namespace-reference.md"
));
const MIN_CHUNK: u64 = 262_144;
const CONTENT: [u8; 32] = [0x11; 32];
const ROOT: [u8; 32] = [0x22; 32];
const PROVENANCE: [u8; 32] = [0x33; 32];

fn reference_wire(name: &str, index: usize) -> Vec<u8> {
    let marker = format!("### {name}\n");
    assert_eq!(REFERENCE.matches(&marker).count(), 1, "{name}");
    let section = REFERENCE
        .split_once(&marker)
        .unwrap()
        .1
        .split("\n### ")
        .next()
        .unwrap();
    let block = section
        .split("```hex\n")
        .nth(index + 1)
        .unwrap()
        .split_once("```")
        .unwrap()
        .0;
    let digits: String = block.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    assert_eq!(digits.len() % 2, 0);
    assert!(digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

/// Represents primitive field values, independently of the rejecting codec.
#[derive(Clone)]
enum Field {
    Unsigned(u64),
    Bytes(Vec<u8>),
    Text(&'static str),
    Boolean(bool),
    Null,
    Array(Vec<Field>),
    Map(Vec<(Field, Field)>),
}

impl Field {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::Unsigned(value) => cbor::write_uint(&mut bytes, *value),
            Self::Bytes(value) => cbor::write_bytes(&mut bytes, value),
            Self::Text(value) => cbor::write_text(&mut bytes, value),
            Self::Boolean(value) => bytes.push(if *value { 0xf5 } else { 0xf4 }),
            Self::Null => bytes.push(0xf6),
            Self::Array(values) => {
                cbor::write_array(&mut bytes, values.len());
                for value in values {
                    bytes.extend(value.encode());
                }
            }
            Self::Map(fields) => {
                let mut encoded: Vec<_> = fields
                    .iter()
                    .map(|(key, value)| (key.encode(), value.encode()))
                    .collect();
                encoded.sort_by(|left, right| {
                    left.0.len().cmp(&right.0.len()).then(left.0.cmp(&right.0))
                });
                cbor::write_map(&mut bytes, encoded.len());
                for (key, value) in encoded {
                    bytes.extend(key);
                    bytes.extend(value);
                }
            }
        }
        bytes
    }
}

fn uint(value: u64) -> Field {
    Field::Unsigned(value)
}

fn bytes(value: &[u8]) -> Field {
    Field::Bytes(value.to_vec())
}

fn text(value: &'static str) -> Field {
    Field::Text(value)
}

fn array(values: Vec<Field>) -> Field {
    Field::Array(values)
}

fn fields(values: Vec<(u64, Field)>) -> Field {
    Field::Map(
        values
            .into_iter()
            .map(|(key, value)| (uint(key), value))
            .collect(),
    )
}

fn names(values: &[&'static str]) -> Field {
    array(values.iter().map(|value| text(value)).collect())
}

fn named(values: Vec<(&'static str, Field)>) -> Field {
    Field::Map(
        values
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
    )
}

fn binding(value: Field, inherit: bool) -> Field {
    named(vec![("value", value), ("inherit", Field::Boolean(inherit))])
}

fn quota(root: u64, principal: u64) -> Field {
    named(vec![
        ("bytes-per-root", uint(root)),
        ("bytes-per-principal-unreferenced", uint(principal)),
    ])
}

type NamedBytes = Vec<(&'static str, Vec<u8>)>;

fn property_bytes(values: Vec<(&'static str, Field)>) -> NamedBytes {
    let mut encoded: Vec<_> = values
        .into_iter()
        .map(|(name, value)| (name, value.encode()))
        .collect();
    encoded.sort_by(|left, right| left.0.len().cmp(&right.0.len()).then(left.0.cmp(right.0)));
    encoded
}

fn properties(values: &NamedBytes) -> Vec<Property<'_>> {
    values
        .iter()
        .map(|(name, value)| Property { name, value })
        .collect()
}

fn empty_entry(kind: EntryKind<'_>) -> Entry<'_> {
    Entry {
        kind,
        attrs: vec![],
        attrs_present: false,
        xattrs: vec![],
        xattrs_present: false,
        provenance: None,
    }
}

fn file(size: u64, manifest: bool, link_id: Option<&[u8]>) -> Entry<'_> {
    empty_entry(EntryKind::File {
        mode: 0o644,
        size,
        content: if manifest {
            ContentRef::Manifest(CONTENT)
        } else {
            ContentRef::Inline(CONTENT)
        },
        link_id,
    })
}

fn directory(mode: u16) -> Entry<'static> {
    empty_entry(EntryKind::Directory { mode })
}

fn conflict(base: Option<Option<Box<Entry<'_>>>>) -> Entry<'_> {
    empty_entry(EntryKind::Conflict {
        candidates: vec![
            directory(0o755),
            empty_entry(EntryKind::Symlink {
                target: b"../raw\xff",
            }),
        ],
        base,
    })
}

fn with_metadata<'a>(mut entry: Entry<'a>, empty: bool, attrs: &'a NamedBytes) -> Entry<'a> {
    entry.attrs_present = true;
    entry.xattrs_present = true;
    if !empty {
        entry.attrs = attrs
            .iter()
            .map(|(name, value)| Attribute { name, value })
            .collect();
        entry.xattrs = vec![
            ExtendedAttribute {
                name: b"\xff",
                value: b"",
            },
            ExtendedAttribute {
                name: b"user.fixture",
                value: b"\x00\xffvalue",
            },
        ];
        entry.provenance = Some(PROVENANCE);
    }
    entry
}

fn attribute_values() -> NamedBytes {
    property_bytes(vec![
        ("uid", uint(1000)),
        (
            "custom.fixture",
            array(vec![
                Field::Null,
                Field::Boolean(true),
                bytes(b"\x00\xff"),
                named(vec![("n", uint(24))]),
            ]),
        ),
    ])
}

fn graft_values() -> NamedBytes {
    property_bytes(vec![
        ("domain", binding(text("tenant:fixture"), false)),
        ("quota", quota(0, u64::MAX)),
    ])
}

fn entry_models<'a>(
    attrs: &'a NamedBytes,
    graft: &'a NamedBytes,
) -> Vec<(&'static str, Entry<'a>, TreeUse)> {
    let models = vec![
        ("entry-file-inline-absent", file(0, false, None)),
        (
            "entry-file-inline-empty",
            with_metadata(file(23, false, None), true, attrs),
        ),
        (
            "entry-file-inline-metadata",
            with_metadata(file(MIN_CHUNK, false, Some(b"a")), false, attrs),
        ),
        (
            "entry-file-manifest-metadata",
            with_metadata(file(u64::MAX, true, None), false, attrs),
        ),
        ("entry-directory-absent", directory(0)),
        (
            "entry-directory-empty",
            with_metadata(directory(4095), true, attrs),
        ),
        (
            "entry-directory-metadata",
            with_metadata(directory(0o755), false, attrs),
        ),
        (
            "entry-symlink-absent",
            empty_entry(EntryKind::Symlink { target: b"" }),
        ),
        (
            "entry-symlink-empty",
            with_metadata(
                empty_entry(EntryKind::Symlink { target: b"." }),
                true,
                attrs,
            ),
        ),
        (
            "entry-symlink-metadata",
            with_metadata(
                empty_entry(EntryKind::Symlink {
                    target: b"../raw\x00\xff",
                }),
                false,
                attrs,
            ),
        ),
        (
            "entry-tree-absent",
            empty_entry(EntryKind::Tree {
                root: ROOT,
                props: None,
            }),
        ),
        (
            "entry-tree-empty",
            with_metadata(
                empty_entry(EntryKind::Tree {
                    root: ROOT,
                    props: Some(vec![]),
                }),
                true,
                attrs,
            ),
        ),
        (
            "entry-tree-metadata",
            with_metadata(
                empty_entry(EntryKind::Tree {
                    root: ROOT,
                    props: Some(properties(graft)),
                }),
                false,
                attrs,
            ),
        ),
        ("entry-whiteout-absent", empty_entry(EntryKind::Whiteout)),
        (
            "entry-whiteout-provenance",
            Entry {
                provenance: Some(PROVENANCE),
                ..empty_entry(EntryKind::Whiteout)
            },
        ),
        ("entry-conflict-base-absent", conflict(None)),
        (
            "entry-conflict-base-null",
            with_metadata(conflict(Some(None)), true, attrs),
        ),
        (
            "entry-conflict-base-entry",
            with_metadata(
                conflict(Some(Some(Box::new(with_metadata(
                    file(24, false, None),
                    false,
                    attrs,
                ))))),
                false,
                attrs,
            ),
        ),
        (
            "entry-conflict-base-conflict",
            conflict(Some(Some(Box::new(conflict(Some(None)))))),
        ),
        (
            "entry-index-absent",
            empty_entry(EntryKind::Index {
                targets: vec![CONTENT],
            }),
        ),
        (
            "entry-index-empty",
            with_metadata(
                empty_entry(EntryKind::Index {
                    targets: vec![CONTENT, ROOT],
                }),
                true,
                attrs,
            ),
        ),
        (
            "entry-index-metadata",
            with_metadata(
                empty_entry(EntryKind::Index {
                    targets: vec![CONTENT, ROOT, PROVENANCE],
                }),
                false,
                attrs,
            ),
        ),
    ];
    models
        .into_iter()
        .map(|(name, entry)| {
            let usage = match entry.kind {
                EntryKind::Whiteout => TreeUse::OverlayLayer,
                EntryKind::Index { .. } => TreeUse::Index,
                _ => TreeUse::Ordinary,
            };
            (name, entry, usage)
        })
        .collect()
}

fn leaf<'a>(entry: Entry<'a>, props: Option<Vec<Property<'a>>>) -> Node<'a> {
    let key: &[u8] = if matches!(entry.kind, EntryKind::Index { .. }) {
        b"\x00/\xff"
    } else {
        b"a"
    };
    Node {
        level: 0,
        items: NodeItems::Leaf(vec![LeafItem {
            key: key.to_vec(),
            entry,
        }]),
        props,
    }
}

fn assert_node(name: &str, model: &Node<'_>, usage: TreeUse, wire_index: usize) {
    let expected = reference_wire(name, wire_index);
    let encoded = encode_node_for(model, true, MIN_CHUNK, usage).unwrap();
    assert_eq!(encoded, expected, "{name}: node wire");
    assert_eq!(
        decode_node_for(&expected, true, MIN_CHUNK, usage).unwrap(),
        *model,
        "{name}: complete node model"
    );
    let identity = TERRANE_V1.calculate(IdentityKind::Node, &encoded).unwrap();
    assert_eq!(
        identity.digest(),
        reference_wire(name, wire_index + 1),
        "{name}: node identity"
    );

    let decoded = decode_node_for(&expected, true, MIN_CHUNK, usage).unwrap();
    assert_eq!(
        encode_node_for(&decoded, true, MIN_CHUNK, usage).unwrap(),
        expected
    );
    for end in 0..expected.len() {
        assert!(
            decode_node_for(&expected[..end], true, MIN_CHUNK, usage).is_err(),
            "{name}: truncation {end}"
        );
    }
    let mut trailing = expected.clone();
    trailing.push(0);
    assert!(decode_node_for(&trailing, true, MIN_CHUNK, usage).is_err());
    let mut overlong = vec![0xb8, expected[0] & 0x1f];
    overlong.extend_from_slice(&expected[1..]);
    assert!(decode_node_for(&overlong, true, MIN_CHUNK, usage).is_err());
}

#[test]
fn reference_entry_models_preserve_optional_metadata_and_kind_fields() {
    let attrs = attribute_values();
    let graft = graft_values();
    let models = entry_models(&attrs, &graft);
    assert_eq!(models.len(), 22);

    for (name, entry, usage) in models {
        let expected = reference_wire(name, 0);
        assert_eq!(
            encode_entry(&entry, MIN_CHUNK).unwrap(),
            expected,
            "{name}: entry wire"
        );
        assert_eq!(
            decode_entry_bytes(&expected, MIN_CHUNK).unwrap(),
            entry,
            "{name}: complete entry model"
        );

        let mut reordered = entry.clone();
        reordered.attrs.reverse();
        reordered.xattrs.reverse();
        if let EntryKind::Tree {
            props: Some(values),
            ..
        } = &mut reordered.kind
        {
            values.reverse();
        }
        assert_eq!(
            encode_entry(&reordered, MIN_CHUNK).unwrap(),
            expected,
            "{name}: canonical map order"
        );
        for end in 0..expected.len() {
            assert!(
                decode_entry_bytes(&expected[..end], MIN_CHUNK).is_err(),
                "{name}: entry truncation {end}"
            );
        }
        assert_node(name, &leaf(entry, None), usage, 1);
    }

    let mut first = with_metadata(file(24, false, Some(b"a")), false, &attrs);
    let mut second = first.clone();
    second.provenance = Some([0x44; 32]);
    let namespace_models = vec![
        (
            "namespace-directory-descendant",
            vec![
                LeafItem {
                    key: b"a".to_vec(),
                    entry: directory(0o755),
                },
                LeafItem {
                    key: b"a/b".to_vec(),
                    entry: file(23, false, None),
                },
            ],
        ),
        (
            "namespace-conditional-descendant",
            vec![
                LeafItem {
                    key: b"a".to_vec(),
                    entry: conflict(None),
                },
                LeafItem {
                    key: b"a/b".to_vec(),
                    entry: file(23, false, None),
                },
            ],
        ),
        (
            "namespace-hardlink-pair",
            vec![
                LeafItem {
                    key: b"a".to_vec(),
                    entry: first.clone(),
                },
                LeafItem {
                    key: b"b".to_vec(),
                    entry: second,
                },
            ],
        ),
    ];
    assert_eq!(namespace_models.len(), 3);
    for (name, items) in namespace_models {
        validate_tree_entries(&items, TreeUse::Ordinary).unwrap();
        let node = Node {
            level: 0,
            items: NodeItems::Leaf(items.clone()),
            props: None,
        };
        assert_node(name, &node, TreeUse::Ordinary, 0);

        // Whole-tree checks consume complete decoded fields separately from
        // local node parsing; no tree operation or content lookup is needed.
        let mut malformed = items;
        if name == "namespace-hardlink-pair" {
            malformed[1].entry.attrs_present = false;
        } else {
            malformed.remove(0);
        }
        assert!(validate_tree_entries(&malformed, TreeUse::Ordinary).is_err());
    }
    if let EntryKind::File { link_id, .. } = &mut first.kind {
        *link_id = Some(b"b");
    }
    assert!(
        validate_tree_entries(
            &[LeafItem {
                key: b"a".to_vec(),
                entry: first
            }],
            TreeUse::Ordinary
        )
        .is_err()
    );
}

// PROP-30 fixes this historical vocabulary independently of compiled registrations.
const REVISION_ONE_NAMES: [&str; 33] = [
    "acl",
    "baseline",
    "chunk",
    "classify",
    "compaction_threshold",
    "compression",
    "dedup",
    "degraded",
    "domain",
    "durability",
    "encryption",
    "gap_merge_bytes",
    "hashes",
    "home",
    "index",
    "merge",
    "on-release",
    "passthrough",
    "prefetch",
    "quota",
    "reassembly",
    "redundancy",
    "reflog_retain",
    "replicate",
    "retain",
    "span_max_bytes",
    "store",
    "strict-attrs",
    "trust",
    "warm",
    "whole_pack_threshold",
    "wipe",
    "writers",
];

fn registered_values() -> NamedBytes {
    property_bytes(vec![
        ("store", text("local")),
        ("chunk", text("cdc-1m")),
        ("compression", text("zstd:text")),
        ("encryption", text("none")),
        ("retain", array(vec![text("ttl"), uint(u64::MAX)])),
        ("domain", text("group:fixture")),
        ("dedup", text("domain")),
        ("redundancy", text("replicated(3,ack=2)")),
        ("degraded", text("refuse")),
        ("durability", text("regions(2)")),
        ("replicate", text("sync(2)")),
        ("home", text("r1")),
        ("warm", names(&["r2", "r1", "r2"])),
        ("quota", quota(24, 65536)),
        ("compaction_threshold", uint(0)),
        ("whole_pack_threshold", uint(10000)),
        ("gap_merge_bytes", uint(0)),
        ("span_max_bytes", uint(u64::MAX)),
        ("trust", text("any")),
        ("baseline", text("fixture")),
        ("merge", names(&["prefer-ours", "keep-conflict", "error"])),
        ("writers", text("many")),
        ("reflog_retain", array(vec![text("count"), uint(24)])),
        ("prefetch", text("rules")),
        ("reassembly", text("smart")),
        ("passthrough", text("auto")),
        ("wipe", text("volatile")),
        ("on-release", text("commit")),
        (
            "acl",
            array(vec![
                array(vec![text("fixture:one"), uint(31)]),
                array(vec![text("fixture:two"), uint(0)]),
            ]),
        ),
        ("hashes", names(&["sha256", "git-blob-sha256"])),
        ("classify", names(&["text", "elf"])),
        ("index", names(&["uid", "hash.sha256"])),
        ("strict-attrs", Field::Boolean(true)),
    ])
}

#[test]
fn reference_root_property_models_preserve_nested_values_and_identity() {
    let registered = registered_values();
    let mut published_names: Vec<_> = registered.iter().map(|(name, _)| *name).collect();
    published_names.sort();
    assert_eq!(published_names, REVISION_ONE_NAMES);

    // The published original root is immutable; its new sibling has a separate model.
    let mut complete_names = published_names;
    complete_names.push("index-roots");
    complete_names.push("index-gaps");
    complete_names.sort();
    let mut compiled_names: Vec<_> = PropertyName::ALL.iter().map(|name| name.as_str()).collect();
    compiled_names.sort();
    assert_eq!(complete_names, compiled_names);
    let gap_wrapper = binding(
        text("2222222222222222222222222222222222222222222222222222222222222222"),
        false,
    )
    .encode();
    let gap_property = Property {
        name: "index-gaps",
        value: &gap_wrapper,
    };
    // Registered auxiliary syntax does not authorize namespace placement.
    validate_property(&gap_property).unwrap();
    assert!(terrane_format::properties::validate_map(&[gap_property]).is_err());
    assert!(validate_graft_overrides(&[gap_property], &[]).is_err());

    for value in [
        named(vec![]),
        named(vec![(
            "uid",
            text("2222222222222222222222222222222222222222222222222222222222222222"),
        )]),
    ] {
        let owner = property_bytes(vec![("index-roots", binding(value.clone(), false))]);
        let node = leaf(directory(0o755), Some(properties(&owner)));
        let encoded = encode_node_for(&node, true, MIN_CHUNK, TreeUse::Ordinary).unwrap();
        assert_eq!(
            decode_node_for(&encoded, true, MIN_CHUNK, TreeUse::Ordinary).unwrap(),
            node
        );
        for invalid in [value.clone(), binding(value, true)] {
            assert!(
                validate_property(&Property {
                    name: "index-roots",
                    value: &invalid.encode()
                })
                .is_err()
            );
        }
        let graft = empty_entry(EntryKind::Tree {
            root: ROOT,
            props: Some(properties(&owner)),
        });
        // Entry encoding preserves canonical data; owner placement is policy validation.
        let EntryKind::Tree {
            props: Some(overrides),
            ..
        } = &graft.kind
        else {
            panic!("graft model must retain its override map");
        };
        assert!(validate_graft_overrides(overrides, &[]).is_err());
    }
    let bindings = property_bytes(vec![
        ("store", binding(text("local"), false)),
        ("domain", binding(text("public"), true)),
        ("quota", binding(quota(0, u64::MAX), false)),
        (
            "acl",
            binding(array(vec![array(vec![text("fixture:one"), uint(7)])]), true),
        ),
        ("strict-attrs", binding(Field::Boolean(false), false)),
    ]);
    let selector = property_bytes(vec![(
        "trust",
        array(vec![
            text("all"),
            array(vec![
                names(&["preset", "any"]),
                array(vec![text("not"), names(&["kind", "human"])]),
                array(vec![
                    text("attr-by"),
                    text("hash.sha256"),
                    names(&["source", "derived"]),
                ]),
            ]),
        ]),
    )]);
    let nested_empty = property_bytes(vec![
        ("warm", array(vec![])),
        ("hashes", array(vec![])),
        ("index", array(vec![])),
        ("classify", array(vec![])),
        ("acl", array(vec![])),
    ]);
    let models = vec![
        (
            "root-properties-absent",
            Node {
                level: 0,
                items: NodeItems::Leaf(vec![]),
                props: None,
            },
        ),
        (
            "root-properties-empty",
            Node {
                level: 0,
                items: NodeItems::Leaf(vec![]),
                props: Some(vec![]),
            },
        ),
        (
            "root-properties-registered",
            leaf(directory(0o755), Some(properties(&registered))),
        ),
        (
            "root-properties-bindings",
            leaf(file(24, false, None), Some(properties(&bindings))),
        ),
        (
            "root-properties-selector",
            leaf(
                empty_entry(EntryKind::Symlink { target: b"raw" }),
                Some(properties(&selector)),
            ),
        ),
        (
            "root-properties-nested-empty",
            leaf(
                empty_entry(EntryKind::Tree {
                    root: ROOT,
                    props: Some(vec![]),
                }),
                Some(properties(&nested_empty)),
            ),
        ),
    ];
    assert_eq!(models.len(), 6);

    for (name, node) in models {
        if let Some(values) = &node.props {
            for property in values {
                validate_property(property).unwrap();
                let mut decoder = Decoder::new(property.value);
                decoder.raw_value(65536).unwrap();
                decoder.finish().unwrap();
            }
        }
        assert_node(name, &node, TreeUse::Ordinary, 0);
        let mut reordered = node.clone();
        if let Some(values) = &mut reordered.props {
            values.reverse();
        }
        assert_eq!(
            encode_node_for(&reordered, true, MIN_CHUNK, TreeUse::Ordinary).unwrap(),
            reference_wire(name, 0)
        );
    }

    // PROP-4 preservation uses an explicit local registry-extension fixture.
    // CONV-3 excludes this unregistered name from normative v1 witnesses.
    let later_registration = property_bytes(vec![(
        "future.fixture",
        named(vec![(
            "nested",
            array(vec![
                uint(0),
                Field::Boolean(true),
                named(vec![("label", text("opaque"))]),
            ]),
        )]),
    )]);
    let model = leaf(directory(0o755), Some(properties(&later_registration)));
    let encoded = encode_node_for(&model, true, MIN_CHUNK, TreeUse::Ordinary).unwrap();
    let decoded = decode_node_for(&encoded, true, MIN_CHUNK, TreeUse::Ordinary).unwrap();
    assert_eq!(decoded, model);
    assert_eq!(
        encode_node_for(&decoded, true, MIN_CHUNK, TreeUse::Ordinary).unwrap(),
        encoded
    );
    let preserved = decoded.props.as_ref().unwrap();
    assert_eq!(preserved[0].value, later_registration[0].1);
    assert!(validate_preserved_map(preserved, &[]).is_err());
    validate_preserved_map(preserved, &["future.fixture"]).unwrap();
}

fn file_fields(size: u64, tag: u64) -> Vec<(u64, Field)> {
    vec![
        (1, uint(1)),
        (2, uint(420)),
        (3, uint(size)),
        (4, array(vec![uint(tag), bytes(&CONTENT)])),
    ]
}

fn leaf_fields(entry: Field, index_key: bool) -> Field {
    fields(vec![
        (1, uint(0)),
        (
            2,
            array(vec![array(vec![
                bytes(if index_key { b"\x00/\xff" } else { b"a" }),
                uint(0),
                entry,
            ])]),
        ),
    ])
}

type NegativeEntry = (&'static str, Field, TreeUse);

fn negative_entries() -> Vec<NegativeEntry> {
    let mut models = vec![
        (
            "namespace-file-missing-mode",
            fields(vec![
                (1, uint(1)),
                (3, uint(0)),
                (4, array(vec![uint(0), bytes(&CONTENT)])),
            ]),
            TreeUse::Ordinary,
        ),
        (
            "namespace-file-reserved-content",
            fields(file_fields(0, 2)),
            TreeUse::Ordinary,
        ),
        (
            "namespace-file-inline-too-large",
            fields(file_fields(MIN_CHUNK + 1, 0)),
            TreeUse::Ordinary,
        ),
        (
            "namespace-file-manifest-too-small",
            fields(file_fields(MIN_CHUNK, 1)),
            TreeUse::Ordinary,
        ),
        (
            "namespace-file-mode-high",
            fields(vec![
                (1, uint(1)),
                (2, uint(4096)),
                (3, uint(0)),
                (4, array(vec![uint(0), bytes(&CONTENT)])),
            ]),
            TreeUse::Ordinary,
        ),
        (
            "namespace-file-short-digest",
            fields(vec![
                (1, uint(1)),
                (2, uint(420)),
                (3, uint(0)),
                (4, array(vec![uint(0), bytes(&CONTENT[..31])])),
            ]),
            TreeUse::Ordinary,
        ),
        (
            "namespace-file-empty-link",
            {
                let mut model = file_fields(0, 0);
                model.push((8, bytes(b"")));
                fields(model)
            },
            TreeUse::Ordinary,
        ),
        (
            "namespace-directory-content",
            fields(vec![
                (1, uint(2)),
                (2, uint(493)),
                (4, array(vec![uint(0), bytes(&CONTENT)])),
            ]),
            TreeUse::Ordinary,
        ),
        (
            "namespace-symlink-mode",
            fields(vec![(1, uint(3)), (2, uint(493)), (5, bytes(b"a"))]),
            TreeUse::Ordinary,
        ),
        (
            "namespace-tree-null-property",
            fields(vec![
                (1, uint(4)),
                (6, bytes(&ROOT)),
                (7, named(vec![("domain", Field::Null)])),
            ]),
            TreeUse::Ordinary,
        ),
        (
            "namespace-whiteout-empty-attrs",
            fields(vec![(1, uint(5)), (9, named(vec![]))]),
            TreeUse::OverlayLayer,
        ),
        (
            "namespace-whiteout-empty-xattrs",
            fields(vec![(1, uint(5)), (10, Field::Map(vec![]))]),
            TreeUse::OverlayLayer,
        ),
        (
            "namespace-conflict-one-candidate",
            fields(vec![
                (1, uint(6)),
                (12, array(vec![fields(vec![(1, uint(2)), (2, uint(493))])])),
            ]),
            TreeUse::Ordinary,
        ),
        (
            "namespace-conflict-nested-candidate",
            fields(vec![
                (1, uint(6)),
                (
                    12,
                    array(vec![
                        fields(vec![
                            (1, uint(6)),
                            (
                                12,
                                array(vec![fields(vec![(1, uint(5))]), fields(vec![(1, uint(5))])]),
                            ),
                        ]),
                        fields(vec![(1, uint(5))]),
                    ]),
                ),
            ]),
            TreeUse::Ordinary,
        ),
        (
            "namespace-conflict-bool-base",
            fields(vec![
                (1, uint(6)),
                (
                    12,
                    array(vec![fields(vec![(1, uint(5))]), fields(vec![(1, uint(5))])]),
                ),
                (13, Field::Boolean(false)),
            ]),
            TreeUse::Ordinary,
        ),
        (
            "namespace-index-empty",
            fields(vec![(1, uint(7)), (14, array(vec![]))]),
            TreeUse::Index,
        ),
        (
            "namespace-index-duplicate",
            fields(vec![
                (1, uint(7)),
                (14, array(vec![bytes(&CONTENT), bytes(&CONTENT)])),
            ]),
            TreeUse::Index,
        ),
        (
            "namespace-index-unsorted",
            fields(vec![
                (1, uint(7)),
                (14, array(vec![bytes(&ROOT), bytes(&CONTENT)])),
            ]),
            TreeUse::Index,
        ),
        (
            "namespace-empty-provenance",
            fields(vec![(1, uint(2)), (2, uint(493)), (11, bytes(b""))]),
            TreeUse::Ordinary,
        ),
        (
            "namespace-empty-attribute-name",
            fields(vec![
                (1, uint(2)),
                (2, uint(493)),
                (9, named(vec![("", uint(1))])),
            ]),
            TreeUse::Ordinary,
        ),
        (
            "namespace-empty-xattr-name",
            fields(vec![
                (1, uint(2)),
                (2, uint(493)),
                (10, Field::Map(vec![(bytes(b""), bytes(b"a"))])),
            ]),
            TreeUse::Ordinary,
        ),
    ];
    let reserved_names = [
        "namespace-reserved-kind-8",
        "namespace-reserved-kind-9",
        "namespace-reserved-kind-10",
        "namespace-reserved-kind-11",
        "namespace-reserved-kind-12",
        "namespace-reserved-kind-13",
        "namespace-reserved-kind-14",
        "namespace-reserved-kind-15",
    ];
    models.extend(
        reserved_names
            .into_iter()
            .zip(8..=15)
            .map(|(name, kind)| (name, fields(vec![(1, uint(kind))]), TreeUse::Ordinary)),
    );
    models
}

fn negative_nodes() -> Vec<(&'static str, Field, bool)> {
    let dir = || fields(vec![(1, uint(2)), (2, uint(493))]);
    let item = |suffix: &[u8], shared| array(vec![bytes(suffix), uint(shared), dir()]);
    let node = |items| fields(vec![(1, uint(0)), (2, array(items))]);
    vec![
        (
            "namespace-root-bytes-property",
            fields(vec![
                (1, uint(0)),
                (2, array(vec![item(b"a", 0)])),
                (3, named(vec![("domain", bytes(b"public"))])),
            ]),
            true,
        ),
        (
            "namespace-root-empty-property-name",
            fields(vec![
                (1, uint(0)),
                (2, array(vec![item(b"a", 0)])),
                (3, named(vec![("", Field::Boolean(true))])),
            ]),
            true,
        ),
        (
            "namespace-nonroot-properties",
            fields(vec![
                (1, uint(0)),
                (2, array(vec![item(b"a", 0)])),
                (3, named(vec![])),
            ]),
            false,
        ),
        ("namespace-first-prefix", node(vec![item(b"a", 1)]), true),
        (
            "namespace-nonmaximal-prefix",
            node(vec![item(b"aa", 0), item(b"ab", 0)]),
            true,
        ),
        (
            "namespace-duplicate-key",
            node(vec![item(b"a", 0), item(b"", 1)]),
            true,
        ),
        (
            "namespace-extra-item-field",
            node(vec![array(vec![bytes(b"a"), uint(0), dir(), uint(0)])]),
            true,
        ),
        (
            "namespace-whiteout-ordinary",
            leaf_fields(fields(vec![(1, uint(5))]), false),
            true,
        ),
        (
            "namespace-index-ordinary",
            leaf_fields(
                fields(vec![(1, uint(7)), (14, array(vec![bytes(&CONTENT)]))]),
                false,
            ),
            true,
        ),
    ]
}

#[test]
fn reference_negative_namespace_wires_require_structural_rejection() {
    let entries = negative_entries();
    let nodes = negative_nodes();
    assert_eq!(entries.len() + nodes.len(), 38);

    for (name, entry, usage) in entries {
        let encoded = entry.encode();
        assert_eq!(
            encoded,
            reference_wire(name, 0),
            "{name}: independently reproduced entry"
        );
        assert!(
            decode_entry_bytes(&encoded, MIN_CHUNK).is_err(),
            "{name}: entry rejection"
        );
        let node = leaf_fields(entry, usage == TreeUse::Index).encode();
        assert_eq!(
            node,
            reference_wire(name, 1),
            "{name}: independently reproduced node"
        );
        assert!(
            decode_node_for(&node, true, MIN_CHUNK, usage).is_err(),
            "{name}: node rejection"
        );
    }
    for (name, model, is_root) in nodes {
        let encoded = model.encode();
        assert_eq!(
            encoded,
            reference_wire(name, 0),
            "{name}: independently reproduced node"
        );
        assert!(
            decode_node_for(&encoded, is_root, MIN_CHUNK, TreeUse::Ordinary).is_err(),
            "{name}: node rejection"
        );
    }
}
