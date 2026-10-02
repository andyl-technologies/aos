//! Compares published descriptor/node bytes with separately constructed models.
//!
//! The independent reference generator supplies complete immutable payloads and
//! canonical tree models. Exact identities, fields, profile cuts and subtree
//! summaries are checked without granting deferred features or authority.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "independent fixtures must match separately constructed test models"
)]

use terrane_core::boundary::{BoundaryDecision, decide};
use terrane_core::identity::{Descriptor, Digest, IdentityKind, TERRANE_V1};
use terrane_core::tree_builder::Tree;
use terrane_core::tree_format::{
    ChildRef, ContentRef, Entry, EntryKind, ExtendedAttribute, LeafItem, Node, NodeItems, TreeUse,
    decode_node, encode_node,
};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md"
));
const MIN_CHUNK: u64 = 262_144;
const PADDING: [u8; 4096] = [0; 4096];

fn section(name: &str) -> &str {
    let marker = format!("### {name}\n");
    assert_eq!(REFERENCE.matches(&marker).count(), 1);
    REFERENCE
        .split_once(&marker)
        .unwrap()
        .1
        .split("\n## ")
        .next()
        .unwrap()
        .split("\n### ")
        .next()
        .unwrap()
}

fn hexadecimal(text: &str) -> Vec<u8> {
    let digits: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    assert!(digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(digits.len() % 2, 0);
    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

fn wire(name: &str, index: usize) -> Vec<u8> {
    let encoded = section(name)
        .split("```hex\n")
        .nth(index + 1)
        .unwrap()
        .split_once("```")
        .unwrap()
        .0;
    hexadecimal(encoded)
}

fn identity(bytes: &[u8]) -> Digest {
    TERRANE_V1
        .calculate(IdentityKind::Node, bytes)
        .unwrap()
        .digest()
        .try_into()
        .unwrap()
}

fn leaf(key: &[u8], padded: bool) -> LeafItem<'static> {
    let chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"hello, terrane\n")
        .unwrap();
    LeafItem {
        key: key.to_vec(),
        entry: Entry {
            kind: EntryKind::File {
                mode: 0o644,
                size: 15,
                content: ContentRef::Inline(chunk.digest().try_into().unwrap()),
                link_id: None,
            },
            attrs: vec![],
            attrs_present: false,
            xattrs: if padded {
                vec![ExtendedAttribute {
                    name: b"user.fixture",
                    value: &PADDING,
                }]
            } else {
                vec![]
            },
            xattrs_present: padded,
            provenance: None,
        },
    }
}

fn leaf_node(item: LeafItem<'static>) -> Node<'static> {
    Node {
        level: 0,
        items: NodeItems::Leaf(vec![item]),
        props: None,
    }
}

fn internal_node() -> Node<'static> {
    let mut children = vec![];
    for (key, padded) in [
        (b"boundary-003.txt".as_slice(), true),
        (b"world.txt", false),
    ] {
        let child = leaf_node(leaf(key, padded));
        let encoded = encode_node(&child, false, MIN_CHUNK).unwrap();
        children.push(ChildRef {
            last_key: key.to_vec(),
            child: identity(&encoded),
            count: 1,
            weight: u64::try_from(encoded.len()).unwrap(),
        });
    }
    Node {
        level: 1,
        items: NodeItems::Internal(children),
        props: None,
    }
}

#[test]
fn published_descriptors_match_all_registered_domains_and_payloads() {
    let kinds = [
        ("chunk", IdentityKind::Chunk),
        ("manifest", IdentityKind::Manifest),
        ("node", IdentityKind::Node),
        ("commit", IdentityKind::Commit),
        ("bundle", IdentityKind::Bundle),
        ("pack", IdentityKind::Pack),
        ("index", IdentityKind::Index),
        ("filter", IdentityKind::Filter),
        ("attr", IdentityKind::Attribute),
        ("policy", IdentityKind::Policy),
        ("memo", IdentityKind::Memo),
    ];
    assert_eq!(TERRANE_V1.domains().len(), kinds.len());
    for (label, kind) in kinds {
        let name = format!("descriptor-{label}");
        let encoded = wire(&name, 0);
        let payload = wire(&name, 1);
        let content = TERRANE_V1.calculate(kind, &payload).unwrap();
        let model = Descriptor::from_identity(&TERRANE_V1, &content, &payload).unwrap();

        assert_eq!(model.encode(), encoded, "{label}");
        assert_eq!(Descriptor::decode(&TERRANE_V1, &encoded).unwrap(), model);
        assert_eq!(
            model.verify_bytes(&TERRANE_V1, kind, &payload).unwrap(),
            content
        );
    }
}

#[test]
fn published_nodes_match_separately_constructed_fields_and_identities() {
    let models = [
        (
            "foundation-leaf-hello",
            leaf_node(leaf(b"hello.txt", false)),
        ),
        (
            "foundation-leaf-world",
            leaf_node(leaf(b"world.txt", false)),
        ),
        (
            "foundation-leaf-boundary",
            leaf_node(leaf(b"boundary-003.txt", true)),
        ),
        ("foundation-internal-node", internal_node()),
    ];
    for (name, model) in models {
        let encoded = wire(name, 0);
        let expected_digest = section(name)
            .split_once("Node identity:\n\n```text\n")
            .unwrap()
            .1
            .split_once("```")
            .unwrap()
            .0;

        assert_eq!(
            encode_node(&model, true, MIN_CHUNK).unwrap(),
            encoded,
            "{name}"
        );
        assert_eq!(decode_node(&encoded, true, MIN_CHUNK).unwrap(), model);
        assert_eq!(identity(&encoded).as_slice(), hexadecimal(expected_digest));
    }
}

#[test]
fn published_internal_tree_matches_actual_profile_boundary_and_child_summaries() {
    let first = leaf(b"boundary-003.txt", true);
    let second = leaf(b"world.txt", false);
    let child = wire("foundation-leaf-boundary", 0);
    // This one-item map has five framing bytes; the boundary hashes its item.
    let item = &child[5..];
    assert_eq!(
        decide(0, u64::try_from(item.len()).unwrap(), item).unwrap(),
        BoundaryDecision::CloseAfter
    );
    let tree = Tree::build(vec![first, second], None, MIN_CHUNK, TreeUse::Ordinary).unwrap();
    let encoded = wire("foundation-internal-node", 0);

    assert_eq!(tree.root().level(), 1);
    assert_eq!(tree.root().encoded(), encoded);
    assert_eq!(tree.root_identity(), identity(&encoded));
    assert_eq!(tree.root().count(), 2);
    assert_eq!(tree.root().node(), &internal_node());
    for (child, name) in tree
        .root()
        .children()
        .iter()
        .zip(["foundation-leaf-boundary", "foundation-leaf-world"])
    {
        let reference = wire(name, 0);
        assert_eq!(child.encoded(), reference);
        assert_eq!(child.count(), 1);
        assert_eq!(child.weight(), u64::try_from(reference.len()).unwrap());
    }
}
