//! Supplies raw active-role disagreements through otherwise generic-valid Nodes.

use super::*;
use crate::{
    identity::{IdentityKind, TERRANE_V1},
    tree_format::{NodeItems, decode_node_for, encode_node_for},
};
use core::error::Error as _;

fn changed(data: &IndexData, mutate: impl FnOnce(&mut crate::tree_format::Node<'_>)) -> IndexData {
    let mut node = decode_node_for(&data.nodes[&data.root], true, MINIMUM, TreeUse::Index).unwrap();
    mutate(&mut node);
    let bytes = encode_node_for(&node, true, MINIMUM, TreeUse::Index).unwrap();
    // The generic codec accepting this Node is part of the witness: contextual
    // maintenance preparation must still refuse it, rather than guessing roles.
    decode_node_for(&bytes, true, MINIMUM, TreeUse::Index).unwrap();
    let root = TERRANE_V1
        .calculate(IdentityKind::Node, &bytes)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    let mut changed = data.clone();
    changed.nodes.remove(&changed.root);
    changed.nodes.insert(root, bytes);
    changed.root = root;
    changed
}

/// Checks actual preparation refusal and typed error chains for malformed carriers.
///
/// # Panics
/// Panics if fixture construction or an asserted independent witness fails.
pub(super) fn assert_raw_relations_refuse() {
    let (graph, owner) = fixture(0, 3, 1);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let source = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
    let valid = oracle::Model::new(&graph, owner);
    let variants = [
        changed(&valid.data, |node| {
            let NodeItems::Leaf(rows) = &mut node.items else {
                unreachable!();
            };
            rows.remove(0);
        }),
        changed(&valid.data, |node| {
            let NodeItems::Leaf(rows) = &mut node.items else {
                unreachable!();
            };
            rows[0].entry.kind = EntryKind::Index {
                targets: alloc::vec![[0x77; 32]],
            };
        }),
        changed(&valid.data, |node| {
            let NodeItems::Leaf(rows) = &mut node.items else {
                unreachable!();
            };
            rows[0].entry.kind = EntryKind::Index {
                targets: alloc::vec![ONE, TWO],
            };
        }),
        changed(&valid.data, |node| {
            let NodeItems::Leaf(rows) = &mut node.items else {
                unreachable!();
            };
            rows[0].entry.attrs.clear();
            rows[0].entry.attrs_present = false;
        }),
        changed(&valid.data, |node| {
            let NodeItems::Leaf(rows) = &mut node.items else {
                unreachable!();
            };
            rows[0].entry.attrs[0].value = &[
                0x58, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ];
        }),
        changed(&valid.data, |node| {
            node.props = None;
        }),
    ];
    let arena = ByteArena::new(1024 * 1024).unwrap();
    for (case, data) in variants.iter().enumerate() {
        let error =
            prepare(&recipe, &source, &graph, data, &arena, MINIMUM, context()).unwrap_err();
        let evaluation = error
            .source()
            .unwrap()
            .downcast_ref::<evaluation::Error>()
            .unwrap();
        if matches!(case, 1..=3) {
            assert_eq!(
                evaluation,
                &evaluation::Error::Carrier(crate::indexing::Error::Schema),
                "generic-valid disagreement {case}"
            );
            let carrier = evaluation
                .source()
                .unwrap()
                .downcast_ref::<crate::indexing::Error>()
                .unwrap();
            assert_eq!(carrier, &crate::indexing::Error::Schema);
        } else {
            let expected = if case == 4 {
                evaluation::Error::MissingNode
            } else {
                evaluation::Error::Relationship
            };
            assert_eq!(evaluation, &expected);
            assert!(evaluation.source().is_none());
        }
    }
    // These freshly assembled bytes bypass the owning Node/Entry encoders.
    // Duplicate map keys, nonminimal integers and an empty Index target list
    // must fail through the real decoder/verifier path with fresh identities.
    for (bytes, expected) in [
        (
            alloc::vec![0xa3, 1, 0, 1, 0, 2, 0x80],
            crate::tree_format::Error::Node,
        ),
        (
            alloc::vec![0xa2, 1, 0x18, 0, 2, 0x80],
            crate::tree_format::Error::Cbor(crate::cbor::Error::NonCanonical),
        ),
        (
            alloc::vec![
                0xa2, 1, 0, 2, 0x81, 0x83, 0x41, b'a', 0, 0xa2, 1, 7, 14, 0x80
            ],
            crate::tree_format::Error::Entry,
        ),
    ] {
        let mut preimage = b"terrane-node-v1\0".to_vec();
        preimage.extend_from_slice(&bytes);
        let root = *blake3::hash(&preimage).as_bytes();
        let data = IndexData {
            root,
            nodes: BTreeMap::from([(root, bytes)]),
            work: Default::default(),
        };
        let error =
            prepare(&recipe, &source, &graph, &data, &arena, MINIMUM, context()).unwrap_err();
        let evaluation = error
            .source()
            .unwrap()
            .downcast_ref::<evaluation::Error>()
            .unwrap();
        assert_eq!(evaluation, &evaluation::Error::Tree(expected));
        let tree = evaluation
            .source()
            .unwrap()
            .downcast_ref::<crate::tree_format::Error>()
            .unwrap();
        assert_eq!(tree, &expected);
    }
    assert!(SemanticContext::new(2, 1, 1).is_err());
    assert!(SemanticContext::new(3, 1, 1).is_err());
    assert!(SemanticContext::new(3, 2, 2).is_err());
    assert!(PreparedSource::new(&recipe, &graph, MINIMUM + 1, context()).is_err());
    let empty_index = Tree::build(Vec::new(), None, MINIMUM, TreeUse::Index).unwrap();
    let empty_recipe = IndexEvaluationRecipe::new(empty_index.root_identity(), "uid").unwrap();
    let wrong_role = BTreeMap::from([(empty_index.root_identity(), empty_index)]);
    assert!(PreparedSource::new(&empty_recipe, &wrong_role, MINIMUM, context()).is_err());
}
