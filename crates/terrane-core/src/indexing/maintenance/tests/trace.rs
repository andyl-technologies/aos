//! Derives complete multilevel encoding and hash traces without editor counters.

use super::*;
use crate::cbor;

#[derive(Clone)]
struct Node {
    identity: Digest,
    count: u64,
    weight: u64,
    first: Vec<u8>,
    last: Vec<u8>,
}

#[derive(Default)]
struct Trace {
    work: StreamWork,
    split_before: usize,
    reset_below_minimum: usize,
    below_minimum: usize,
    maximum: usize,
    hashes: usize,
    prefixes: usize,
    tail_closed: bool,
}

/// Assembles a prefix-compressed terminal Index row naming the fixture object.
pub(super) fn terminal(key: &[u8], previous: &[u8]) -> Vec<u8> {
    let shared = key.iter().zip(previous).take_while(|(a, b)| a == b).count();
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 3);
    cbor::write_bytes(&mut bytes, &key[shared..]);
    cbor::write_uint(&mut bytes, shared as u64);
    // Raw canonical Index entry: {1:7, 14:[O]}. No owning entry encoder.
    bytes.extend_from_slice(&[0xa2, 0x01, 0x07, 0x0e, 0x81, 0x58, 0x20]);
    bytes.extend_from_slice(&ONE);
    bytes
}

fn reference(node: &Node) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 4);
    cbor::write_bytes(&mut bytes, &node.last);
    cbor::write_bytes(&mut bytes, &node.identity);
    cbor::write_uint(&mut bytes, node.count);
    cbor::write_uint(&mut bytes, node.weight);
    bytes
}

fn emit(
    level: u8,
    items: &[Vec<u8>],
    children: &[Node],
    keys: &[Vec<u8>],
    trace: &mut Trace,
) -> Node {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, 2);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_uint(&mut bytes, u64::from(level));
    cbor::write_uint(&mut bytes, 2);
    cbor::write_array(&mut bytes, items.len());
    for item in items {
        bytes.extend_from_slice(item);
    }
    // The literal domain and the NUL are hashed, rather than inferred from a
    // production report or identity-profile helper.
    let mut preimage = b"terrane-node-v1\0".to_vec();
    preimage.extend_from_slice(&bytes);
    trace.work.node_bytes_encoded += bytes.len();
    trace.work.node_bytes_hashed += preimage.len();
    Node {
        identity: *blake3::hash(&preimage).as_bytes(),
        count: if level == 0 {
            keys.len() as u64
        } else {
            children.iter().map(|child| child.count).sum()
        },
        weight: bytes.len() as u64 + children.iter().map(|child| child.weight).sum::<u64>(),
        first: if level == 0 {
            keys[0].clone()
        } else {
            children[0].first.clone()
        },
        last: if level == 0 {
            keys.last().unwrap().clone()
        } else {
            children.last().unwrap().last.clone()
        },
    }
}

// Returns 0 for append, 1 for close-after, and 2 for split-before. Every actual
// short-circuit is represented independently; a capacity branch hashes zero.
fn decision(size: usize, stored: usize, full: &[u8], trace: &mut Trace) -> u8 {
    trace.work.frontier_checks += 1;
    let sum = size + stored;
    if sum > 65536 {
        trace.split_before += 1;
        return 2;
    }
    if sum == 65536 {
        trace.maximum += 1;
        return 1;
    }
    if sum < 4096 {
        trace.below_minimum += 1;
        return 0;
    }
    trace.hashes += 1;
    trace.work.item_bytes_hashed += full.len();
    let digest = blake3::hash(full);
    let hash = u32::from_le_bytes(digest.as_bytes()[..4].try_into().unwrap());
    let base = if sum >= 32768 {
        1_u64 << 24
    } else {
        (1_u64 << 20) + (sum as u64 - 4096) * ((1 << 24) - (1 << 20)) / 28672
    };
    u8::from(u64::from(hash) < (base * stored as u64 / 8).min(1 << 32))
}

fn level(keys: &[Vec<u8>], children: &[Node], depth: u8) -> (Vec<Node>, Trace) {
    let mut trace = Trace::default();
    let mut output = Vec::new();
    let mut stored_items = Vec::new();
    let mut chunk_keys = Vec::new();
    let mut chunk_children = Vec::new();
    let mut size = 0;
    for index in 0..if depth == 0 {
        keys.len()
    } else {
        children.len()
    } {
        let full = if depth == 0 {
            terminal(&keys[index], &[])
        } else {
            reference(&children[index])
        };
        let mut stored = if depth == 0 {
            terminal(&keys[index], chunk_keys.last().map_or(&[], Vec::as_slice))
        } else {
            full.clone()
        };
        trace.prefixes += usize::from(full != stored);
        trace.work.item_reads += 1;
        trace.work.item_bytes_encoded += full.len() + if depth == 0 { stored.len() } else { 0 };
        let mut cut = decision(size, stored.len(), &full, &mut trace);
        if cut == 2 {
            output.push(emit(
                depth,
                &stored_items,
                &chunk_children,
                &chunk_keys,
                &mut trace,
            ));
            stored_items.clear();
            chunk_keys.clear();
            chunk_children.clear();
            size = 0;
            stored = full.clone();
            trace.reset_below_minimum += usize::from(stored.len() < 4096);
            cut = decision(0, stored.len(), &full, &mut trace);
        }
        size += stored.len();
        stored_items.push(stored);
        if depth == 0 {
            chunk_keys.push(keys[index].clone());
        } else {
            chunk_children.push(children[index].clone());
        }
        if cut == 1 {
            output.push(emit(
                depth,
                &stored_items,
                &chunk_children,
                &chunk_keys,
                &mut trace,
            ));
            stored_items.clear();
            chunk_keys.clear();
            chunk_children.clear();
            size = 0;
        }
    }
    trace.tail_closed = stored_items.is_empty();
    if !stored_items.is_empty() {
        output.push(emit(
            depth,
            &stored_items,
            &chunk_children,
            &chunk_keys,
            &mut trace,
        ));
    }
    (output, trace)
}

fn fields(work: StreamWork) -> [usize; 7] {
    [
        work.item_reads,
        work.comparisons,
        work.frontier_checks,
        work.item_bytes_encoded,
        work.node_bytes_encoded,
        work.item_bytes_hashed,
        work.node_bytes_hashed,
    ]
}

/// Checks full multilevel encoding/hash traces against an independent literal model.
///
/// # Panics
/// Panics if fixture construction or an asserted independent witness fails.
pub(super) fn assert_literal_multilevel() {
    let mut graph = Graph::new();
    let owner = add(&mut graph, Vec::new());
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let source = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
    let previous = oracle::Model::new(&graph, owner);
    let arena = ByteArena::new(16 * 1024 * 1024).unwrap();
    let (state, _) = prepare(
        &recipe,
        &source,
        &graph,
        &previous.data,
        &arena,
        MINIMUM,
        context(),
    )
    .unwrap();
    let (new_graph, new_owner) = long_paths(80, false);
    let new_recipe = IndexEvaluationRecipe::new(new_owner, "uid").unwrap();
    let after = PreparedSource::new(&new_recipe, &new_graph, MINIMUM, context()).unwrap();
    let discovery = discover(&source, &after).unwrap();
    let (updated, work) = update(&state, &discovery).unwrap();
    let coordinate = Coordinate::Route {
        predicate: Predicate {
            object: ONE,
            value: Some(VALUES[0].to_vec()),
        },
        hops: Vec::new(),
    };
    let batch = work
        .batches
        .iter()
        .find(|batch| batch.coordinate == coordinate)
        .unwrap();
    let keys: Vec<_> = new_graph[&new_owner]
        .iter()
        .filter(|item| matches!(item.entry.kind, EntryKind::File { .. }))
        .map(|item| item.key.clone())
        .collect();
    let (mut nodes, mut leaf) = level(&keys, &[], 0);
    // An empty predecessor contributes one tail comparison and one pending
    // frontier; there are no old items, seeks, replacements or adoptions.
    leaf.work.comparisons = 1;
    leaf.work.frontier_checks += 1;
    assert_eq!(batch.work.regions.len(), 1);
    assert_eq!(fields(batch.work.regions[0].work), fields(leaf.work));
    let mut traces = alloc::vec![fields(leaf.work)];
    let mut depth = 0;
    while nodes.len() > 1 {
        depth += 1;
        let (next, trace) = level(&[], &nodes, depth);
        assert_eq!(
            fields(batch.work.new_levels[usize::from(depth - 1)].work),
            fields(trace.work)
        );
        traces.push(fields(trace.work));
        nodes = next;
    }
    assert_eq!(depth, 4);
    assert_eq!(batch.work.new_levels.len(), 4);
    assert_eq!(fields(batch.work.completion), [0, 0, 6, 0, 0, 0, 0]);
    assert_eq!(fields(batch.work.preparation), [0; 7]);
    assert_eq!(fields(batch.work.root_properties), [0; 7]);
    assert_eq!(fields(batch.work.adoption), [0; 7]);
    let mut scratch = MapWork::default();
    assert_eq!(
        updated
            .routes
            .get(&coordinate, &mut scratch)
            .unwrap()
            .root_identity(),
        nodes[0].identity
    );
    assert!(leaf.hashes > 0 && leaf.below_minimum == 0);
    // Kept as an explicit numeric trace after independent derivation, so a
    // counter omission cannot be hidden by changing both aggregate summations.
    assert_eq!(
        traces,
        alloc::vec![
            [80, 1, 81, 662240, 331270, 331120, 331750],
            [30, 0, 30, 124110, 124170, 124110, 124362],
            [12, 0, 12, 49644, 49664, 49644, 49728],
            [4, 0, 4, 16557, 16567, 16557, 16599],
            [2, 0, 2, 8279, 8284, 8279, 8300],
        ]
    );
}

/// Checks exact capacity splits and prolonged-tail invalidation against literal traces.
///
/// # Panics
/// Panics if fixture construction or an asserted independent witness fails.
pub(super) fn assert_capacity_and_prolonged_tail() {
    // Every stored noninitial row is at most 100 bytes. Selecting full-key
    // hashes above the largest possible threshold prevents all content cuts,
    // forcing capacity splits irrespective of accumulated-byte interpolation.
    let prefix = alloc::format!("{0}/{0}/{0}/{1}", "x".repeat(250), "x".repeat(100));
    let keys: Vec<_> = (0..10000)
        .map(|index| alloc::format!("{prefix}{index:08}").into_bytes())
        .filter(|key| {
            let digest = blake3::hash(&terminal(key, &[]));
            u32::from_le_bytes(digest.as_bytes()[..4].try_into().unwrap())
                >= ((1_u64 << 24) * 100 / 8) as u32
        })
        .take(6000)
        .collect();
    assert_eq!(keys.len(), 6000);
    let (old_nodes, trace) = level(&keys, &[], 0);
    assert!(trace.split_before >= 3);
    assert_eq!(trace.reset_below_minimum, trace.split_before);
    assert!(trace.below_minimum >= 3);
    assert!(trace.prefixes > 5900);
    let count = usize::try_from(old_nodes[0].count).unwrap() - 1;
    let mut cap_keys = keys[..count].to_vec();
    let mut size = 0;
    let mut prior = &[][..];
    for key in &cap_keys {
        size += terminal(key, prior).len();
        prior = key;
    }
    let exact = (0..140)
        .find_map(|padding| {
            let mut key = keys[count].clone();
            key.extend_from_slice(&alloc::vec![b'y'; padding]);
            (size + terminal(&key, prior).len() == 65536).then_some(key)
        })
        .unwrap();
    cap_keys.push(exact);
    let (cap_nodes, mut cap_trace) = level(&cap_keys, &[], 0);
    assert_eq!(cap_trace.maximum, 1);
    assert_eq!(cap_trace.split_before, 0);
    assert_eq!(cap_nodes.len(), 1);
    let edits: Vec<_> = cap_keys
        .iter()
        .map(|key| {
            (
                key.clone(),
                Some(Entry {
                    kind: EntryKind::Index {
                        targets: alloc::vec![ONE],
                    },
                    attrs: Vec::new(),
                    attrs_present: false,
                    xattrs: Vec::new(),
                    xattrs_present: false,
                    provenance: None,
                }),
            )
        })
        .collect();
    let empty = Tree::build(Vec::new(), None, MINIMUM, TreeUse::Index).unwrap();
    let exact_cap = empty.edit_entries(&edits).unwrap();
    cap_trace.work.comparisons = 1;
    cap_trace.work.frontier_checks += 1;
    assert_eq!(
        fields(exact_cap.work.regions[0].work),
        fields(cap_trace.work)
    );
    assert_eq!(exact_cap.tree.root_identity(), cap_nodes[0].identity);
    let mut rows: Vec<_> = keys
        .iter()
        .map(|key| leaf(key, file(ONE, Some(VALUES[0]), false)))
        .collect();
    // Namespace ancestry is independent of the auxiliary terminal stream.
    for (index, byte) in prefix.as_bytes().iter().enumerate() {
        if *byte == b'/' {
            rows.push(leaf(
                &prefix.as_bytes()[..index],
                Entry {
                    kind: EntryKind::Directory { mode: 0o755 },
                    attrs: Vec::new(),
                    attrs_present: false,
                    xattrs: Vec::new(),
                    xattrs_present: false,
                    provenance: None,
                },
            ));
        }
    }
    let mut graph = Graph::new();
    let owner = add(&mut graph, rows);
    let previous = oracle::Model::new(&graph, owner);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let source = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
    let arena = ByteArena::new(16 * 1024 * 1024).unwrap();
    let mut empty_graph = Graph::new();
    let empty_owner = add(&mut empty_graph, Vec::new());
    let empty_recipe = IndexEvaluationRecipe::new(empty_owner, "uid").unwrap();
    let empty_source =
        PreparedSource::new(&empty_recipe, &empty_graph, MINIMUM, context()).unwrap();
    let empty_model = oracle::Model::new(&empty_graph, empty_owner);
    let (empty_state, _) = prepare(
        &empty_recipe,
        &empty_source,
        &empty_graph,
        &empty_model.data,
        &arena,
        MINIMUM,
        context(),
    )
    .unwrap();
    let growth = discover(&empty_source, &source).unwrap();
    let (grown, growth_work) = update(&empty_state, &growth).unwrap();
    let growth_coordinate = Coordinate::Route {
        predicate: Predicate {
            object: ONE,
            value: Some(VALUES[0].to_vec()),
        },
        hops: Vec::new(),
    };
    let growth_batch = growth_work
        .batches
        .iter()
        .find(|batch| batch.coordinate == growth_coordinate)
        .unwrap();
    let mut growth_leaf = trace.work;
    growth_leaf.comparisons = 1;
    growth_leaf.frontier_checks += 1;
    assert_eq!(growth_batch.work.regions.len(), 1);
    assert_eq!(
        fields(growth_batch.work.regions[0].work),
        fields(growth_leaf)
    );
    let (old_parents, growth_parent) = level(&[], &old_nodes, 1);
    assert_eq!(old_parents.len(), 1);
    assert_eq!(growth_batch.work.new_levels.len(), 1);
    assert_eq!(
        fields(growth_batch.work.new_levels[0].work),
        fields(growth_parent.work)
    );
    assert_eq!(fields(growth_batch.work.completion), [0, 0, 3, 0, 0, 0, 0]);
    assert_eq!(fields(growth_batch.work.preparation), [0; 7]);
    assert_eq!(fields(growth_batch.work.root_properties), [0; 7]);
    assert_eq!(fields(growth_batch.work.adoption), [0; 7]);
    assert_eq!(growth_batch.work.node_reads, 1);
    assert_eq!(growth_batch.work.seek_comparisons, 0);
    assert_eq!(growth_batch.work.validation_reads, keys.len());
    assert_eq!(
        growth_batch.work.item_encodings,
        2 * keys.len() + old_nodes.len()
    );
    assert_eq!(growth_batch.work.node_encodings, old_nodes.len() + 1);
    let mut scratch = MapWork::default();
    assert_eq!(
        grown
            .routes
            .get(&growth_coordinate, &mut scratch)
            .unwrap()
            .root_identity(),
        old_parents[0].identity
    );
    check_phase_partition(&growth_work);
    oracle::assert_discovery(&empty_model, &previous, &growth);
    oracle::assert_routes(&empty_model, &previous, &growth_work);
    assert_result(&grown, &graph, owner, &previous);
    let state = grown;
    let coordinate = Coordinate::Route {
        predicate: Predicate {
            object: ONE,
            value: Some(VALUES[0].to_vec()),
        },
        hops: Vec::new(),
    };
    let mut scratch = MapWork::default();
    let tree = state.routes.get(&coordinate, &mut scratch).unwrap();
    let old_leaf_ids: Vec<_> = tree
        .nodes()
        .filter(|node| node.level() == 0)
        .map(|node| node.identity())
        .collect();
    assert_eq!(old_leaf_ids.len(), old_nodes.len());
    for node in &old_nodes {
        assert!(old_leaf_ids.contains(&node.identity));
    }
    let changed = graph[&owner]
        .edit_entries(&[(keys[1].clone(), Some(file(ONE, None, false)))])
        .unwrap()
        .tree;
    let new_owner = changed.root_identity();
    let mut new_graph = graph.clone();
    new_graph.insert(new_owner, changed);
    let new_recipe = IndexEvaluationRecipe::new(new_owner, "uid").unwrap();
    let after = PreparedSource::new(&new_recipe, &new_graph, MINIMUM, context()).unwrap();
    let discovery = discover(&source, &after).unwrap();
    let (updated, work) = update(&state, &discovery).unwrap();
    let batch = work
        .batches
        .iter()
        .find(|batch| batch.coordinate == coordinate)
        .unwrap();
    let region = batch
        .work
        .regions
        .iter()
        .find(|region| region.level == 0)
        .unwrap();
    assert_eq!(region.invalidated, old_nodes[0].last);
    assert_eq!(region.last, old_nodes.last().unwrap().last);
    assert_eq!(region.resynchronized, None);
    let mut remaining = keys.clone();
    remaining.remove(1);
    let (new_nodes, replacement_trace) = level(&remaining, &[], 0);
    assert!(replacement_trace.split_before >= 3);
    assert_eq!(
        replacement_trace.reset_below_minimum,
        replacement_trace.split_before
    );
    // The one deletion consumes exactly one old row without pushing it. The
    // preceding row tests the pending edit once; the deleted row tests it and
    // then tests equality. Every old leaf adds one tail comparison/frontier.
    let mut expected_leaf = replacement_trace.work;
    expected_leaf.item_reads += keys.len();
    expected_leaf.comparisons += old_nodes.len() + 3;
    expected_leaf.frontier_checks += old_nodes.len();
    assert_eq!(fields(region.work), fields(expected_leaf));

    let (new_parents, parent_trace) = level(&[], &new_nodes, 1);
    assert_eq!(new_parents.len(), 1);
    let parent_region = batch
        .work
        .regions
        .iter()
        .find(|region| region.level == 1)
        .unwrap();
    // One replacement span covers every old child: each old child makes one
    // pending-span and one coverage comparison. The root consumes the span
    // once, with a final empty-frontier comparison only for a closed tail.
    let mut expected_parent = parent_trace.work;
    expected_parent.item_reads += old_nodes.len();
    expected_parent.comparisons += 2 * old_nodes.len() + 1 + usize::from(parent_trace.tail_closed);
    expected_parent.frontier_checks += 1;
    assert_eq!(fields(parent_region.work), fields(expected_parent));
    assert_eq!(parent_region.invalidated, old_parents[0].last);
    assert_eq!(parent_region.last, old_parents[0].last);
    assert_eq!(parent_region.resynchronized, None);
    assert_eq!(batch.work.regions.len(), 2);
    assert!(batch.work.new_levels.is_empty());
    assert_eq!(fields(batch.work.completion), [0, 0, 2, 0, 0, 0, 0]);
    assert_eq!(fields(batch.work.preparation), [0; 7]);
    assert_eq!(fields(batch.work.root_properties), [0; 7]);
    assert_eq!(fields(batch.work.adoption), [0; 7]);
    // The first-leaf seek inspects one root; iteration reads every old leaf.
    // The ancestor seek is already at its target level and reads one root.
    assert_eq!(batch.work.node_reads, old_nodes.len() + 2);
    let mut length = old_nodes.len();
    let mut seek_comparisons = 1;
    while length > 1 {
        length -= length / 2;
        seek_comparisons += 1;
    }
    assert_eq!(batch.work.seek_comparisons, seek_comparisons);
    assert_eq!(batch.work.validation_reads, 2);
    assert_eq!(
        batch.work.item_encodings,
        2 * remaining.len() + new_nodes.len()
    );
    assert_eq!(batch.work.node_encodings, new_nodes.len() + 1);
    let mut scratch = MapWork::default();
    assert_eq!(
        updated
            .routes
            .get(&coordinate, &mut scratch)
            .unwrap()
            .root_identity(),
        new_parents[0].identity
    );
    check_phase_partition(&work);
    for old in old_nodes.iter().take(old_nodes.len() - 1) {
        assert!(
            !new_nodes.iter().any(|new| new.last == old.last),
            "capacity drift must invalidate every intermediate old cut"
        );
    }
    let replacement = oracle::Model::new(&new_graph, new_owner);
    oracle::assert_discovery(&previous, &replacement, &discovery);
    oracle::assert_routes(&previous, &replacement, &work);
    assert_result(&updated, &new_graph, new_owner, &replacement);
}
