//! Exercises complete independent data models and repeatable immutable updates.

#![allow(clippy::unwrap_used, reason = "test failures deliberately panic")]

mod boundary;
mod maps;
mod oracle;
mod preparation;
mod refusal;
mod selection;
mod trace;

use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};

use super::*;
use crate::{
    identity::Digest,
    indexing::{
        IndexEvaluationRecipe,
        carrier::SemanticContext,
        evaluation::{self, IndexData},
        incremental::{
            Address, DataChange, Discovery, FileState, Hop, InputChange, PopulationMode,
            PreparedSource, discover, discover_with_mode,
        },
    },
    tree_builder::{StreamWork, Tree},
    tree_format::{Attribute, ContentRef, Entry, EntryKind, LeafItem, TreeUse},
};

const MINIMUM: u64 = 262_144;
const ONE: Digest = [0x11; 32];
const TWO: Digest = [0x22; 32];
const VALUES: [&[u8]; 4] = [&[0x18, 24], &[0x18, 25], &[0x18, 26], &[0x18, 27]];
type Graph = BTreeMap<Digest, Tree<'static>>;

fn context() -> SemanticContext {
    SemanticContext::new(3, 2, 1).unwrap()
}

fn object(content: ContentRef) -> Digest {
    match content {
        ContentRef::Inline(root) | ContentRef::Manifest(root) => root,
    }
}

fn file(root: Digest, value: Option<&'static [u8]>, manifest: bool) -> Entry<'static> {
    Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: if manifest { MINIMUM + 1 } else { 1 },
            content: if manifest {
                ContentRef::Manifest(root)
            } else {
                ContentRef::Inline(root)
            },
            link_id: None,
        },
        attrs: value
            .map(|value| alloc::vec![Attribute { name: "uid", value }])
            .unwrap_or_default(),
        attrs_present: value.is_some(),
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn graft(root: Digest) -> Entry<'static> {
    Entry {
        kind: EntryKind::Tree { root, props: None },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn leaf(key: &[u8], entry: Entry<'static>) -> LeafItem<'static> {
    LeafItem {
        key: key.to_vec(),
        entry,
    }
}

fn add(graph: &mut Graph, mut rows: Vec<LeafItem<'static>>) -> Digest {
    rows.sort_by(|left, right| left.key.cmp(&right.key));
    let tree = Tree::build(rows, None, MINIMUM, TreeUse::Ordinary).unwrap();
    let root = tree.root_identity();
    graph.insert(root, tree);
    root
}

fn fixture(stage: usize, population: usize, depth: usize) -> (Graph, Digest) {
    let mut graph = Graph::new();
    let mut rows: Vec<_> = (0..population)
        .map(|index| {
            leaf(
                alloc::format!("item-{index:06}").as_bytes(),
                file(ONE, Some(VALUES[0]), false),
            )
        })
        .collect();
    let value = match stage % 4 {
        0 => Some(VALUES[0]),
        1 => Some(VALUES[1]),
        2 => None,
        _ => Some(VALUES[0]),
    };
    rows.push(leaf(
        b"changed",
        file(
            if stage % 7 == 6 { TWO } else { ONE },
            value,
            stage % 7 == 6,
        ),
    ));
    let mut child = add(&mut graph, rows);
    for level in 0..depth {
        child = add(
            &mut graph,
            alloc::vec![leaf(
                &alloc::vec![b'a' + u8::try_from(level % 20).unwrap(); 250],
                graft(child)
            )],
        );
    }
    let owner = add(
        &mut graph,
        alloc::vec![
            leaf(b"a", graft(child)),
            leaf(b"b", graft(child)),
            leaf(b"missing", file(ONE, None, false)),
            leaf(b"other", file(TWO, Some(VALUES[2]), true))
        ],
    );
    (graph, owner)
}

fn assert_result(
    state: &PreparedIndex<'_, '_>,
    graph: &Graph,
    owner: Digest,
    model: &oracle::Model,
) {
    let (data, export) = state.materialize().unwrap();
    assert_eq!(data.root, model.data.root);
    assert_eq!(data.nodes.len(), model.data.nodes.len());
    assert_eq!(data.nodes, model.data.nodes);
    assert_eq!(export.nodes, data.nodes.len());
    assert_eq!(
        export.bytes,
        data.nodes.values().map(Vec::len).sum::<usize>()
    );
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let constructed = evaluation::construct(&recipe, graph, MINIMUM, context()).unwrap();
    assert_eq!(data.root, constructed.root);
    assert_eq!(data.nodes, constructed.nodes);
    evaluation::verify(&recipe, graph, MINIMUM, context(), &data).unwrap();
    assert_eq!(
        crate::indexing::IndexRoots::decode_binding(&state.owner_binding())
            .unwrap()
            .get("uid"),
        Some(state.root())
    );
}

fn tree_handles<'a>(tree: &Tree<'a>) -> BTreeMap<Digest, Rc<crate::tree_builder::StoredNode<'a>>> {
    fn visit<'a>(
        node: Rc<crate::tree_builder::StoredNode<'a>>,
        nodes: &mut BTreeMap<Digest, Rc<crate::tree_builder::StoredNode<'a>>>,
    ) {
        for child in node.children() {
            visit(Rc::clone(child), nodes);
        }
        nodes.insert(node.identity(), node);
    }
    let mut nodes = BTreeMap::new();
    visit(tree.root_rc(), &mut nodes);
    nodes
}

#[test]
fn maintenance_matches_complete_independent_routes_and_logical_deltas() {
    for depth in [0, 2, 17] {
        let mut graphs: Vec<_> = (0..8).map(|stage| fixture(stage, 4, depth)).collect();
        // Real File-to-Tree and graft-population removals exercise mixed
        // terminal/continuation transitions at identical local row keys.
        let root = graphs[4].1;
        let child = add(
            &mut graphs[4].0,
            alloc::vec![leaf(b"nested", file(ONE, Some(VALUES[1]), false))],
        );
        let mut rows: Vec<_> = graphs[4].0[&root].iter().cloned().collect();
        rows.retain(|row| row.key != b"a" && row.key != b"missing");
        rows.push(leaf(b"missing", graft(child)));
        graphs[4].1 = add(&mut graphs[4].0, rows);
        for pair in graphs.windows(2) {
            let (old_graph, old_owner) = &pair[0];
            let (new_graph, new_owner) = &pair[1];
            let old_recipe = IndexEvaluationRecipe::new(*old_owner, "uid").unwrap();
            let new_recipe = IndexEvaluationRecipe::new(*new_owner, "uid").unwrap();
            let old_source =
                PreparedSource::new(&old_recipe, old_graph, MINIMUM, context()).unwrap();
            let new_source =
                PreparedSource::new(&new_recipe, new_graph, MINIMUM, context()).unwrap();
            let previous = oracle::Model::new(old_graph, *old_owner);
            let replacement = oracle::Model::new(new_graph, *new_owner);
            let arena = ByteArena::new(8 * 1024 * 1024).unwrap();
            let (state, _) = prepare(
                &old_recipe,
                &old_source,
                old_graph,
                &previous.data,
                &arena,
                MINIMUM,
                context(),
            )
            .unwrap();
            let discovery = discover(&old_source, &new_source).unwrap();
            oracle::assert_discovery(&previous, &replacement, &discovery);
            let (updated, work) = update(&state, &discovery).unwrap();
            oracle::assert_routes(&previous, &replacement, &work);
            assert_result(&updated, new_graph, *new_owner, &replacement);
            assert_result(&state, old_graph, *old_owner, &previous);
        }
    }

    let mut special = Vec::new();
    let mut graph = Graph::new();
    let owner = add(
        &mut graph,
        alloc::vec![leaf(b"file", file(ONE, None, false))],
    );
    special.push((graph, owner));
    let mut graph = Graph::new();
    let owner = add(
        &mut graph,
        alloc::vec![leaf(b"file", file(ONE, Some(VALUES[0]), false))],
    );
    special.push((graph.clone(), owner));
    let changed = graph[&owner]
        .edit_entries(&[(
            b"file".to_vec(),
            Some({
                let mut entry = file(ONE, Some(VALUES[0]), false);
                if let EntryKind::File { mode, .. } = &mut entry.kind {
                    *mode = 0o600;
                }
                entry
            }),
        )])
        .unwrap()
        .tree;
    let changed_owner = changed.root_identity();
    graph.insert(changed_owner, changed);
    special.push((graph.clone(), changed_owner));
    let tagged = graph[&changed_owner]
        .edit_entries(&[(b"file".to_vec(), Some(file(ONE, Some(VALUES[0]), true)))])
        .unwrap()
        .tree;
    let tagged_owner = tagged.root_identity();
    graph.insert(tagged_owner, tagged);
    special.push((graph.clone(), tagged_owner));
    let bound = graph[&changed_owner]
        .with_properties(Some(alloc::vec![crate::tree_format::Property {
            name: "index",
            value: &[0x81, 0x63, b'u', b'i', b'd']
        }]))
        .unwrap()
        .tree;
    let bound_owner = bound.root_identity();
    graph.insert(bound_owner, bound);
    special.push((graph, bound_owner));
    let (mut override_graph, override_owner) = fixture(0, 4, 2);
    let mut overridden = override_graph[&override_owner].get(b"a").unwrap().clone();
    if let EntryKind::Tree { props, .. } = &mut overridden.kind {
        *props = Some(alloc::vec![crate::tree_format::Property {
            name: "retain",
            value: &[0x67, b'f', b'o', b'r', b'e', b'v', b'e', b'r']
        }]);
    }
    special.push((override_graph.clone(), override_owner));
    let overridden = override_graph[&override_owner]
        .edit_entries(&[(b"a".to_vec(), Some(overridden))])
        .unwrap()
        .tree;
    let overridden_owner = overridden.root_identity();
    override_graph.insert(overridden_owner, overridden);
    special.push((override_graph, overridden_owner));
    let mut graph = Graph::new();
    let owner = add(&mut graph, Vec::new());
    special.push((graph, owner));
    for pair in special.windows(2) {
        let old_recipe = IndexEvaluationRecipe::new(pair[0].1, "uid").unwrap();
        let new_recipe = IndexEvaluationRecipe::new(pair[1].1, "uid").unwrap();
        let before = PreparedSource::new(&old_recipe, &pair[0].0, MINIMUM, context()).unwrap();
        let after = PreparedSource::new(&new_recipe, &pair[1].0, MINIMUM, context()).unwrap();
        let previous = oracle::Model::new(&pair[0].0, pair[0].1);
        let replacement = oracle::Model::new(&pair[1].0, pair[1].1);
        let arena = ByteArena::new(1024 * 1024).unwrap();
        let (state, _) = prepare(
            &old_recipe,
            &before,
            &pair[0].0,
            &previous.data,
            &arena,
            MINIMUM,
            context(),
        )
        .unwrap();
        let discovery = discover(&before, &after).unwrap();
        let (next, work) = update(&state, &discovery).unwrap();
        oracle::assert_discovery(&previous, &replacement, &discovery);
        oracle::assert_routes(&previous, &replacement, &work);
        if work.delta_data == 0 {
            assert_eq!(work.delta_route, 0);
            assert_eq!(state.root(), next.root());
        }
        assert_result(&next, &pair[1].0, pair[1].1, &replacement);
    }
}

#[test]
fn maintenance_repeated_updates_retain_stable_storage_and_bounded_maps() {
    selection::assert_unrelated_roots_do_not_enter_update();
    maps::assert_large_contextual_maps();
    for population in [64, 4096] {
        let graphs: Vec<_> = (0..34).map(|stage| fixture(stage, population, 1)).collect();
        let first = &graphs[0];
        let recipe = IndexEvaluationRecipe::new(first.1, "uid").unwrap();
        let source = PreparedSource::new(&recipe, &first.0, MINIMUM, context()).unwrap();
        let initial = oracle::Model::new(&first.0, first.1);
        let arena = ByteArena::new(8 * 1024 * 1024).unwrap();
        let (mut state, _) = prepare(
            &recipe,
            &source,
            &first.0,
            &initial.data,
            &arena,
            MINIMUM,
            context(),
        )
        .unwrap();
        let mut retained = Vec::new();
        let initial_nodes = state.node_count();
        for (index, pair) in graphs.windows(2).enumerate() {
            let before_recipe = IndexEvaluationRecipe::new(pair[0].1, "uid").unwrap();
            let after_recipe = IndexEvaluationRecipe::new(pair[1].1, "uid").unwrap();
            let before =
                PreparedSource::new(&before_recipe, &pair[0].0, MINIMUM, context()).unwrap();
            let after = PreparedSource::new(&after_recipe, &pair[1].0, MINIMUM, context()).unwrap();
            let discovery = discover(&before, &after).unwrap();
            let prior_nodes: BTreeMap<_, _> = {
                let mut nodes = BTreeMap::new();
                state.closure.visit(&mut |digest, record| {
                    nodes.insert(*digest, Rc::clone(&record.node));
                });
                nodes
            };
            let (next, work) = update(&state, &discovery).unwrap();
            next.routes.assert_balanced();
            next.closure.assert_balanced();
            let mut shared = 0;
            next.closure.visit(&mut |digest, record| {
                if let Some(previous) = prior_nodes.get(digest) {
                    assert!(Rc::ptr_eq(previous, &record.node));
                    shared += 1;
                }
            });
            let independent_old = oracle::Model::new(&pair[0].0, pair[0].1);
            let independent_new = oracle::Model::new(&pair[1].0, pair[1].1);
            let common: Vec<_> = independent_old
                .data
                .nodes
                .iter()
                .filter(|(digest, bytes)| independent_new.data.nodes.get(*digest) == Some(*bytes))
                .map(|(digest, _)| *digest)
                .collect();
            assert_eq!(shared, common.len());
            if population == 4096 {
                let unaffected: Vec<_> = common.iter().filter(|digest| {
                    let node = crate::tree_format::decode_node_for(&independent_old.data.nodes[*digest], true, MINIMUM, TreeUse::Index).unwrap();
                    matches!(node.items, crate::tree_format::NodeItems::Leaf(ref rows) if rows.first().is_some_and(|row| row.key.as_slice() >= b"item-002048" && row.key.starts_with(b"item-")))
                }).collect();
                assert!(
                    !unaffected.is_empty(),
                    "the independently equal untouched suffix must contain physical leaves"
                );
                for digest in unaffected {
                    let mut scratch = MapWork::default();
                    assert!(Rc::ptr_eq(
                        &prior_nodes[digest],
                        &next.closure.get(digest, &mut scratch).unwrap().node
                    ));
                }
                let coordinate = Coordinate::Route {
                    predicate: Predicate {
                        object: ONE,
                        value: Some(VALUES[0].to_vec()),
                    },
                    hops: alloc::vec![b"a".to_vec(), alloc::vec![b'a'; 250]],
                };
                let mut scratch = MapWork::default();
                let old_tree = state.routes.get(&coordinate, &mut scratch).unwrap();
                let new_tree = next.routes.get(&coordinate, &mut scratch).unwrap();
                let old_handles = tree_handles(old_tree);
                let new_handles = tree_handles(new_tree);
                let equal_inside: Vec<_> = old_handles
                    .keys()
                    .filter(|digest| new_handles.contains_key(*digest))
                    .collect();
                assert!(!equal_inside.is_empty());
                for digest in equal_inside {
                    assert!(Rc::ptr_eq(&old_handles[digest], &new_handles[digest]));
                }
            }
            let height = state.closure_map_shape().1.max(next.closure_map_shape().1);
            let operations = work.closure_edges
                + work.closure_added
                + work.closure_removed
                + work.routes.len()
                + 1;
            assert!(work.maps.allocations <= operations * (12 * height + 36));
            assert!(work.maps.probes <= operations * (8 * height + 24));
            assert!(next.node_count() <= initial_nodes + 24);
            assert!(arena.payload_bytes() >= work.arena_bytes);
            if index % 8 == 0 {
                retained.push(state.clone());
            }
            state = next;
        }
        assert_eq!(retained[0].root(), initial.data.root);
        assert_result(&retained[0], &first.0, first.1, &initial);
        let last = graphs.last().unwrap();
        assert_result(
            &state,
            &last.0,
            last.1,
            &oracle::Model::new(&last.0, last.1),
        );
    }
}

fn sum_stream(target: &mut StreamWork, source: StreamWork) {
    target.item_reads += source.item_reads;
    target.comparisons += source.comparisons;
    target.frontier_checks += source.frontier_checks;
    target.item_bytes_encoded += source.item_bytes_encoded;
    target.node_bytes_encoded += source.node_bytes_encoded;
    target.item_bytes_hashed += source.item_bytes_hashed;
    target.node_bytes_hashed += source.node_bytes_hashed;
}

fn long_paths(count: usize, changed: bool) -> (Graph, Digest) {
    let mut graph = Graph::new();
    let mut entries = Vec::new();
    let bytes: Vec<_> = (1u8..=128).filter(|byte| *byte != b'/').collect();
    for (index, byte) in bytes.into_iter().take(count).enumerate() {
        let mut key = Vec::new();
        for component in 0..16 {
            if component > 0 {
                key.push(b'/');
            }
            key.extend_from_slice(&alloc::vec![byte; 255]);
            let entry = if component == 15 {
                file(
                    ONE,
                    if changed && matches!(index, 2 | 3 | 4 | 40 | 78) {
                        None
                    } else {
                        Some(VALUES[0])
                    },
                    false,
                )
            } else {
                Entry {
                    kind: EntryKind::Directory { mode: 0o755 },
                    attrs: Vec::new(),
                    attrs_present: false,
                    xattrs: Vec::new(),
                    xattrs_present: false,
                    provenance: None,
                }
            };
            entries.push(leaf(&key, entry));
        }
    }
    let root = add(&mut graph, entries);
    (graph, root)
}

fn check_phase_partition(work: &UpdateWork) {
    let encoded_nodes: usize = work
        .batches
        .iter()
        .map(|batch| batch.work.node_encodings)
        .sum();
    let encoded_bytes: usize = work
        .batches
        .iter()
        .map(|batch| batch.work.stream.node_bytes_encoded)
        .sum();
    let reads: usize = work
        .batches
        .iter()
        .map(|batch| batch.work.stream.item_reads)
        .sum();
    assert_eq!(work.staging.nodes, encoded_nodes);
    assert!(work.staging.rows <= encoded_bytes);
    assert!(work.staging.edges <= encoded_bytes);
    assert!(work.closure_removed <= reads + work.batches.len());
    assert!(work.closure_edges <= work.staging.edges + reads + work.batches.len());
    assert_eq!(
        work.staging_maps.operations,
        work.staging.nodes + work.closure_added
    );
    assert!(work.staging_maps.comparisons <= 2827 * work.staging_maps.operations);
    if work.closure_maps.operations != 0 {
        assert_eq!(work.closure_maps.operations, 2 * (work.closure_edges + 2));
    }
    assert!(work.closure_maps.maximum_height <= 514);
    assert!(work.closure_maps.probes <= 1028 * work.closure_maps.operations);
    assert!(work.closure_maps.allocations <= 5140 * work.closure_maps.operations);
    for batch in &work.batches {
        let mut sum = StreamWork::default();
        for region in &batch.work.regions {
            sum_stream(&mut sum, region.work);
        }
        for level in &batch.work.new_levels {
            sum_stream(&mut sum, level.work);
        }
        sum_stream(&mut sum, batch.work.completion);
        sum_stream(&mut sum, batch.work.root_properties);
        sum_stream(&mut sum, batch.work.preparation);
        assert_eq!(sum, batch.work.stream);
    }
}

#[test]
fn maintenance_batches_all_levels_and_conserves_real_boundary_work() {
    trace::assert_literal_multilevel();
    trace::assert_capacity_and_prolonged_tail();
    boundary::assert_separated_recovery_and_middle();
    boundary::assert_internal_content_cut();
    let (old_graph, owner) = fixture(0, 16000, 0);
    let mut new_graph = old_graph.clone();
    let child = match old_graph[&owner].get(b"a").unwrap().kind {
        EntryKind::Tree { root, .. } => root,
        _ => unreachable!(),
    };
    let edits = [4, 5, 6, 7000, 15980].map(|index| {
        (
            alloc::format!("item-{index:06}").into_bytes(),
            Some(file(ONE, None, false)),
        )
    });
    let changed = new_graph[&child].edit_entries(&edits).unwrap().tree;
    let new_child = changed.root_identity();
    new_graph.insert(new_child, changed);
    let changed_owner = old_graph[&owner]
        .edit_entries(&[
            (b"a".to_vec(), Some(graft(new_child))),
            (b"b".to_vec(), Some(graft(new_child))),
        ])
        .unwrap()
        .tree;
    let new_owner = changed_owner.root_identity();
    new_graph.insert(new_owner, changed_owner);
    let old_recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let new_recipe = IndexEvaluationRecipe::new(new_owner, "uid").unwrap();
    let old_source = PreparedSource::new(&old_recipe, &old_graph, MINIMUM, context()).unwrap();
    let new_source = PreparedSource::new(&new_recipe, &new_graph, MINIMUM, context()).unwrap();
    let previous = oracle::Model::new(&old_graph, owner);
    let replacement = oracle::Model::new(&new_graph, new_owner);
    let arena = ByteArena::new(8 * 1024 * 1024).unwrap();
    let (state, _) = prepare(
        &old_recipe,
        &old_source,
        &old_graph,
        &previous.data,
        &arena,
        MINIMUM,
        context(),
    )
    .unwrap();
    let discovery = discover(&old_source, &new_source).unwrap();
    let (updated, work) = update(&state, &discovery).unwrap();
    oracle::assert_discovery(&previous, &replacement, &discovery);
    oracle::assert_routes(&previous, &replacement, &work);
    let mut entry_batches = BTreeMap::new();
    let mut region_cost = 0;
    let mut internal = false;
    for batch in &work.batches {
        if batch.edits > 0 {
            assert!(
                entry_batches
                    .insert(batch.coordinate.clone(), batch.edits)
                    .is_none()
            );
        }
        let mut sum = StreamWork::default();
        for region in &batch.work.regions {
            sum_stream(&mut sum, region.work);
            internal |= region.level > 0;
            for amount in [
                region.work.item_reads,
                region.work.comparisons,
                region.work.frontier_checks,
                region.work.item_bytes_encoded,
                region.work.node_bytes_encoded,
                region.work.item_bytes_hashed,
                region.work.node_bytes_hashed,
            ] {
                region_cost += amount;
            }
        }
        for level in &batch.work.new_levels {
            sum_stream(&mut sum, level.work);
        }
        sum_stream(&mut sum, batch.work.completion);
        sum_stream(&mut sum, batch.work.root_properties);
        sum_stream(&mut sum, batch.work.preparation);
        assert_eq!(sum, batch.work.stream);
        assert!(batch.work.stream.node_bytes_hashed >= batch.work.stream.node_bytes_encoded);
    }
    let source_cost: usize = work
        .streams
        .iter()
        .flat_map(|stream| &stream.events)
        .filter(|event| {
            event.boundary.is_some()
                && !matches!(
                    event.kind,
                    crate::indexing::incremental::PhysicalEventKind::NodeRead
                        | crate::indexing::incremental::PhysicalEventKind::SkippedSubtree
                )
        })
        .map(|event| event.amount)
        .sum();
    assert_eq!(work.boundary_cost().unwrap(), source_cost + region_cost);
    assert!(internal);
    assert!(region_cost > 0);
    assert_result(&updated, &new_graph, new_owner, &replacement);

    let mut empty_graph = Graph::new();
    let empty_owner = add(&mut empty_graph, Vec::new());
    let expanded = long_paths(80, false);
    let changed = long_paths(80, true);
    let graphs = [
        (empty_graph.clone(), empty_owner),
        expanded,
        changed,
        (empty_graph, empty_owner),
    ];
    let initial_model = oracle::Model::new(&graphs[0].0, graphs[0].1);
    let arena = ByteArena::new(16 * 1024 * 1024).unwrap();
    let recipe = IndexEvaluationRecipe::new(graphs[0].1, "uid").unwrap();
    let source = PreparedSource::new(&recipe, &graphs[0].0, MINIMUM, context()).unwrap();
    let (mut state, _) = prepare(
        &recipe,
        &source,
        &graphs[0].0,
        &initial_model.data,
        &arena,
        MINIMUM,
        context(),
    )
    .unwrap();
    let mut growth = false;
    let mut collapse = false;
    let mut middle_levels = BTreeMap::new();
    for (step, pair) in graphs.windows(2).enumerate() {
        let before_recipe = IndexEvaluationRecipe::new(pair[0].1, "uid").unwrap();
        let after_recipe = IndexEvaluationRecipe::new(pair[1].1, "uid").unwrap();
        let before = PreparedSource::new(&before_recipe, &pair[0].0, MINIMUM, context()).unwrap();
        let after = PreparedSource::new(&after_recipe, &pair[1].0, MINIMUM, context()).unwrap();
        let discovery = discover(&before, &after).unwrap();
        let previous = oracle::Model::new(&pair[0].0, pair[0].1);
        let replacement = oracle::Model::new(&pair[1].0, pair[1].1);
        let (next, work) = update(&state, &discovery).unwrap();
        check_phase_partition(&work);
        oracle::assert_discovery(&previous, &replacement, &discovery);
        oracle::assert_routes(&previous, &replacement, &work);
        for batch in &work.batches {
            growth |= batch.work.new_levels.iter().any(|level| level.level >= 2);
            collapse |= batch.work.completion.node_bytes_encoded > 0;
            if step == 1 {
                for region in &batch.work.regions {
                    middle_levels.insert(
                        region.level,
                        (region.invalidated.clone(), region.last.clone()),
                    );
                }
            }
        }
        assert_result(&next, &pair[1].0, pair[1].1, &replacement);
        state = next;
    }
    assert!(
        growth,
        "real long local keys must create more than one auxiliary ancestor level"
    );
    assert!(
        collapse,
        "removing the population must encode canonical empty completion"
    );
    assert!(middle_levels.contains_key(&0));
    assert!(middle_levels.contains_key(&1));
    assert!(middle_levels.contains_key(&2));
}

#[test]
fn maintenance_refuses_invalid_relations_and_mismatched_update_bindings() {
    selection::assert_removal_only_surviving_ancestor();
    refusal::assert_raw_relations_refuse();
    let (graph, owner) = fixture(0, 4, 1);
    let (new_graph, new_owner) = fixture(1, 4, 1);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let next_recipe = IndexEvaluationRecipe::new(new_owner, "uid").unwrap();
    let source = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
    let next_source = PreparedSource::new(&next_recipe, &new_graph, MINIMUM, context()).unwrap();
    let valid = oracle::Model::new(&graph, owner);
    let mut invalids = Vec::new();
    let mut omitted = valid.data.clone();
    omitted.nodes.remove(&omitted.root);
    invalids.push(omitted);
    let mut extra = valid.data.clone();
    extra
        .nodes
        .insert([0x99; 32], alloc::vec![0xa2, 1, 0, 2, 0x80]);
    invalids.push(extra);
    let mut wrong = valid.data.clone();
    wrong.root = [0x88; 32];
    invalids.push(wrong);
    let mut corrupt = valid.data.clone();
    corrupt.nodes.get_mut(&corrupt.root).unwrap()[0] = 0xff;
    invalids.push(corrupt);
    let arena = ByteArena::new(1024 * 1024).unwrap();
    for data in &invalids {
        assert!(prepare(&recipe, &source, &graph, data, &arena, MINIMUM, context()).is_err());
    }
    assert!(
        prepare(
            &recipe,
            &source,
            &graph,
            &valid.data,
            &arena,
            MINIMUM + 1,
            context()
        )
        .is_err()
    );
    let (state, _) = prepare(
        &recipe,
        &source,
        &graph,
        &valid.data,
        &arena,
        MINIMUM,
        context(),
    )
    .unwrap();
    let discovery = discover(&source, &next_source).unwrap();
    assert!(PreparedSource::new(&next_recipe, &graph, MINIMUM, context()).is_err());
    let reversed = discover(&next_source, &source).unwrap();
    assert_eq!(update(&state, &reversed).unwrap_err(), Error::Binding);
    let newly = discover_with_mode(&source, &next_source, PopulationMode::NewlyEnabled).unwrap();
    assert_eq!(update(&state, &newly).unwrap_err(), Error::Binding);
    let gid = IndexEvaluationRecipe::new(owner, "gid").unwrap();
    let gid_next = IndexEvaluationRecipe::new(new_owner, "gid").unwrap();
    let old_gid = PreparedSource::new(&gid, &graph, MINIMUM, context()).unwrap();
    let new_gid = PreparedSource::new(&gid_next, &new_graph, MINIMUM, context()).unwrap();
    assert_eq!(
        update(&state, &discover(&old_gid, &new_gid).unwrap()).unwrap_err(),
        Error::Binding
    );
    let small = ByteArena::new(0).unwrap();
    let (small_state, _) = prepare(
        &recipe,
        &source,
        &graph,
        &valid.data,
        &small,
        MINIMUM,
        context(),
    )
    .unwrap();
    assert_eq!(
        update(&small_state, &discovery).unwrap_err(),
        Error::Allocation
    );
    assert_result(&small_state, &graph, owner, &valid);
    assert_result(&state, &graph, owner, &valid);
}

#[test]
fn maintenance_separates_initial_rebuild_validation_and_export_work() {
    preparation::prove_physical_accounting();
    for stage in [0, 2] {
        let (graph, owner) = fixture(stage, 0, 2);
        let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
        let source = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
        let model = oracle::Model::new(&graph, owner);
        let arena = ByteArena::new(1024 * 1024).unwrap();
        let (initial, initial_work) =
            initialize(&recipe, &source, &arena, MINIMUM, context()).unwrap();
        assert_eq!(initial_work.kind, ConstructionKind::NewlyEnabled);
        assert_eq!(initial_work.work.boundary_cost(), Err(Error::Binding));
        assert_eq!(initial_work.work.delta_data, 4);
        assert!(initial_work.work.initialization.work.item_reads > 0);
        assert!(initial_work.work.empty_trees > 0);
        assert_result(&initial, &graph, owner, &model);
        let (rebuilt, rebuild_work) =
            rebuild(&recipe, &source, &arena, MINIMUM, context()).unwrap();
        assert_eq!(rebuild_work.kind, ConstructionKind::Rebuild);
        assert_eq!(rebuilt.root(), initial.root());
        let (prepared, preparation) = prepare(
            &recipe,
            &source,
            &graph,
            &model.data,
            &arena,
            MINIMUM,
            context(),
        )
        .unwrap();
        assert!(preparation.verification.source_entries > 0);
        assert!(preparation.decoded_nodes > 0);
        assert!(!preparation.reconstruction.is_empty());
        let discovery = discover(&source, &source).unwrap();
        let (same, work) = update(&prepared, &discovery).unwrap();
        assert_eq!(same.root(), prepared.root());
        assert!(Rc::ptr_eq(
            &same.primary.root_rc(),
            &prepared.primary.root_rc()
        ));
        assert_eq!(work.delta_route, 0);
        assert!(work.routes.is_empty());
        assert!(work.batches.is_empty());
        assert_eq!(work.closure_added, 0);
        assert_eq!(work.closure_removed, 0);
        assert_eq!(work.maps, MapWork::default());
        assert_eq!(work.arena_bytes, 0);
        assert_eq!(work.source_path_nodes, 0);
        assert_eq!(work.source_lookups.calls, 3);
        assert_eq!(work.source_roots_checked, 3);
        let (_, export) = same.materialize().unwrap();
        assert!(export.bytes > 0);
        assert_eq!(export.nodes, same.node_count());
    }
    let mut graph = Graph::new();
    let owner = add(&mut graph, Vec::new());
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let source = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
    let arena = ByteArena::new(0).unwrap();
    let (state, work) = initialize(&recipe, &source, &arena, MINIMUM, context()).unwrap();
    assert_eq!(work.work.delta_data, 0);
    assert_eq!(work.work.delta_route, 1);
    assert_eq!(work.work.routes[0].old, None);
    assert_eq!(
        work.work.routes[0].new,
        Some(RouteValue::Binding {
            bytes: state.owner_binding()
        })
    );
}
