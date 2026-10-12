//! Independently attributes verifier operations and deduplicated retention.

use super::*;
use crate::{
    cbor,
    tree_format::{NodeItems, decode_node_for, encode_entry, encode_node_for},
};

fn item_length(item: &LeafItem<'_>, previous: &[u8]) -> usize {
    let shared = previous
        .iter()
        .zip(&item.key)
        .take_while(|(a, b)| a == b)
        .count();
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 3);
    cbor::write_bytes(&mut bytes, &item.key[shared..]);
    cbor::write_uint(&mut bytes, shared as u64);
    bytes.extend(encode_entry(&item.entry, MINIMUM).unwrap());
    bytes.len()
}

/// Checks contextual verifier work separately from deduplicated retention work.
///
/// # Panics
/// Panics if fixture construction or an asserted independent witness fails.
pub(super) fn prove_physical_accounting() {
    // Two predicates each revisit the same child through two distinct grafts.
    // Missing values also force a primary-root index-gaps property replacement.
    let mut graph = Graph::new();
    let child = add(
        &mut graph,
        alloc::vec![
            leaf(b"prefix-a", file(ONE, Some(VALUES[0]), false)),
            leaf(b"prefix-b", file(TWO, None, false)),
        ],
    );
    let owner = add(
        &mut graph,
        alloc::vec![leaf(b"g", graft(child)), leaf(b"h", graft(child))],
    );
    check(&graph, owner, true);

    let mut empty = Graph::new();
    let owner = add(&mut empty, Vec::new());
    check(&empty, owner, false);
}

fn check(graph: &Graph, owner: Digest, sharing: bool) {
    let model = oracle::Model::new(graph, owner);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let source = PreparedSource::new(&recipe, graph, MINIMUM, context()).unwrap();
    let arena = ByteArena::new(1024 * 1024).unwrap();
    let (_, report) = prepare(
        &recipe,
        &source,
        graph,
        &model.data,
        &arena,
        MINIMUM,
        context(),
    )
    .unwrap();

    // Logical pointers determine contextual physical checks independently of
    // the verifier report. Each forwarding row causes one physical-tree check.
    let mut visits = BTreeMap::<Digest, usize>::from([(model.data.root, 1)]);
    for value in model.logical.values() {
        if let RouteValue::Row {
            route: Some(root), ..
        } = value
        {
            *visits.entry(*root).or_default() += 1;
        }
    }
    let primary = decode_node_for(
        &model.data.nodes[&model.data.root],
        true,
        MINIMUM,
        TreeUse::Index,
    )
    .unwrap();
    if let Some(binding) = crate::indexing::carrier::validate_node(
        context(),
        crate::indexing::carrier::Role::Primary,
        &primary,
        true,
    )
    .unwrap()
    {
        *visits.entry(binding.node()).or_default() += 1;
    }
    let physical = &report.verification_physical;
    let checks: usize = visits.values().sum();
    let supplied_bytes: usize = visits
        .iter()
        .map(|(root, count)| model.data.nodes[root].len() * count)
        .sum();
    assert_eq!(physical.node_decodes, checks * 2);
    assert_eq!(physical.node_bytes_decoded, supplied_bytes * 2);
    assert_eq!(
        physical.node_bytes_hashed,
        supplied_bytes + checks * b"terrane-node-v1\0".len()
    );
    assert_eq!(physical.reconstructions.len(), checks);
    assert_eq!(report.decoded_nodes, visits.len());
    assert_eq!(
        report.decoded_bytes,
        visits
            .keys()
            .map(|root| model.data.nodes[root].len())
            .sum::<usize>()
    );
    assert_eq!(report.empty_trees, visits.len());
    assert_eq!(report.reconstruction.len(), visits.len() * 2);
    if sharing {
        assert_eq!(checks, 8);
        assert_eq!(visits.len(), 6);
        assert!(visits.values().filter(|count| **count == 2).count() == 2);
    } else {
        assert_eq!(physical.node_decodes, 2);
        assert_eq!(physical.node_bytes_decoded, 10);
        assert_eq!(physical.node_bytes_hashed, 21);
    }

    let mut remaining = visits;
    for reconstruction in &physical.reconstructions {
        *remaining.get_mut(&reconstruction.root).unwrap() -= 1;
        assert_eq!(
            reconstruction.initial,
            StreamWork {
                node_bytes_encoded: 5,
                node_bytes_hashed: 21,
                ..Default::default()
            }
        );
        let mut node = decode_node_for(
            &model.data.nodes[&reconstruction.root],
            true,
            MINIMUM,
            TreeUse::Index,
        )
        .unwrap();
        let NodeItems::Leaf(rows) = &node.items else {
            panic!("fixture must contain only single-leaf physical Trees")
        };
        let count = rows.len();
        let mut encoded = 0;
        let mut previous = &[][..];
        for row in rows {
            encoded += item_length(row, &[]) + item_length(row, previous);
            previous = &row.key;
        }
        assert!(encoded < 4096);
        let has_properties = node.props.is_some();
        node.props = None;
        let bare = encode_node_for(&node, true, MINIMUM, TreeUse::Index).unwrap();
        let expected = if count == 0 {
            StreamWork::default()
        } else {
            StreamWork {
                item_reads: count,
                comparisons: 1,
                frontier_checks: count + 3,
                item_bytes_encoded: encoded,
                item_bytes_hashed: 0,
                node_bytes_encoded: bare.len(),
                node_bytes_hashed: bare.len() + b"terrane-node-v1\0".len(),
            }
        };
        assert_eq!(reconstruction.entries.stream, expected);
        assert_eq!(
            reconstruction.entries.node_encodings,
            usize::from(count != 0)
        );
        assert_eq!(reconstruction.entries.item_encodings, count * 2);
        assert_eq!(reconstruction.entries.node_reads, usize::from(count != 0));
        assert_eq!(reconstruction.entries.preparation, StreamWork::default());
        assert_eq!(reconstruction.entries.adoption, StreamWork::default());
        assert!(reconstruction.entries.new_levels.is_empty());
        assert_eq!(
            reconstruction.entries.completion,
            StreamWork {
                frontier_checks: if count == 0 { 0 } else { 2 },
                ..Default::default()
            }
        );
        assert_eq!(
            reconstruction.entries.regions.len(),
            usize::from(count != 0)
        );
        if count != 0 {
            let mut region = expected;
            region.frontier_checks -= 2;
            assert_eq!(reconstruction.entries.regions[0].work, region);
        }
        if has_properties {
            let bytes = model.data.nodes[&reconstruction.root].len();
            let properties = StreamWork {
                node_bytes_encoded: bytes,
                node_bytes_hashed: bytes + b"terrane-node-v1\0".len(),
                ..Default::default()
            };
            assert_eq!(reconstruction.properties.stream, properties);
            assert_eq!(reconstruction.properties.root_properties, properties);
            assert_eq!(reconstruction.properties.node_encodings, 1);
        } else {
            assert_eq!(
                reconstruction.properties,
                crate::tree_builder::Work::default()
            );
        }
    }
    assert!(remaining.values().all(|count| *count == 0));
}
