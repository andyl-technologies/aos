//! Checks real discovery against independently enumerated local-hop models.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures assert supported immutable source construction"
)]

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::super::{IndexEvaluationRecipe, carrier::SemanticContext};
mod expected;
mod proofs;
mod witnesses;

use proofs::owner_binding_refusals;

use proofs::{
    conserve, contextual_refusals, fixed_delta_growth, independent_population_oracle,
    literal_transitions_and_stable_cuts, membership_and_growth, named_bindings_and_initialization,
    physical_cut_witness,
};

use super::*;
use crate::chunking::CDC_1M_MIN;
use crate::tree_builder::Tree;
use crate::tree_format::{Attribute, EntryKind, LeafItem, TreeUse};

const MIN: u64 = CDC_1M_MIN as u64;
const O: Digest = [0x11; 32];
const OTHER: Digest = [0x22; 32];

fn context() -> SemanticContext {
    SemanticContext::new(3, 2, 1).unwrap()
}

fn bare(kind: EntryKind<'static>) -> Entry<'static> {
    Entry {
        kind,
        attrs: vec![],
        attrs_present: false,
        xattrs: vec![],
        xattrs_present: false,
        provenance: None,
    }
}

fn file(object: Digest, value: Option<&'static [u8]>, manifest: bool) -> Entry<'static> {
    let mut entry = bare(EntryKind::File {
        mode: 0o644,
        size: if manifest { MIN + 1 } else { 1 },
        content: if manifest {
            ContentRef::Manifest(object)
        } else {
            ContentRef::Inline(object)
        },
        link_id: None,
    });
    entry.attrs = value
        .map(|value| vec![Attribute { name: "uid", value }])
        .unwrap_or_default();
    entry.attrs_present = value.is_some();
    entry
}

fn graft(root: Digest) -> Entry<'static> {
    bare(EntryKind::Tree { root, props: None })
}

fn item(key: &[u8], entry: Entry<'static>) -> LeafItem<'static> {
    LeafItem {
        key: key.to_vec(),
        entry,
    }
}

fn tree(entries: Vec<LeafItem<'static>>) -> Tree<'static> {
    Tree::build(entries, None, MIN, TreeUse::Ordinary).unwrap()
}

fn graph(trees: &[Tree<'static>]) -> BTreeMap<Digest, Tree<'static>> {
    trees
        .iter()
        .map(|tree| (tree.root_identity(), tree.clone()))
        .collect()
}

fn single(tree: &Tree<'static>) -> BTreeMap<Digest, Tree<'static>> {
    graph(core::slice::from_ref(tree))
}

fn compare<'graph>(
    old: Digest,
    old_graph: &'graph BTreeMap<Digest, Tree<'static>>,
    new: Digest,
    new_graph: &'graph BTreeMap<Digest, Tree<'static>>,
) -> Discovery<'graph, 'static> {
    let before = IndexEvaluationRecipe::new(old, "uid").unwrap();
    let after = IndexEvaluationRecipe::new(new, "uid").unwrap();
    let old = PreparedSource::new(&before, old_graph, MIN, context()).unwrap();
    let new = PreparedSource::new(&after, new_graph, MIN, context()).unwrap();
    let result = discover(&old, &new).unwrap();
    conserve(&result);
    expected::complete(&result, old.root(), old_graph, new.root(), new_graph);
    result
}

#[test]
fn source_discovery_preserves_local_hops_and_expands_changed_grafts() {
    let child_before = tree(vec![
        item(b"a", file(O, Some(&[1]), false)),
        item(b"b", file(O, None, true)),
    ]);
    let child_after = tree(vec![
        item(b"a", file(OTHER, Some(&[2]), false)),
        item(b"b", file(O, Some(&[3]), true)),
        item(b"c", file(O, None, false)),
    ]);
    let added = tree(vec![
        item(b"x", file(O, None, false)),
        item(b"y", file(OTHER, Some(&[1]), true)),
    ]);
    let removed = tree(vec![item(b"gone", file(OTHER, Some(&[2]), false))]);
    let old = tree(vec![
        item(b"g", graft(child_before.root_identity())),
        item(b"h", graft(child_before.root_identity())),
        item(b"r", graft(removed.root_identity())),
    ]);
    let new = tree(vec![
        item(b"g", graft(child_after.root_identity())),
        item(b"h", graft(child_after.root_identity())),
        item(b"n", graft(added.root_identity())),
    ]);
    let old_graph = graph(&[old.clone(), child_before.clone(), removed]);
    let new_graph = graph(&[new.clone(), child_after.clone(), added]);
    let result = compare(
        old.root_identity(),
        &old_graph,
        new.root_identity(),
        &new_graph,
    );
    // Literal changed local-hop population: g/{a,b,c}, h/{a,b,c}, n/{x,y}, r/gone.
    let mut paths: Vec<Vec<Vec<u8>>> = result
        .data
        .iter()
        .map(|change| {
            change
                .new_address
                .as_ref()
                .or(change.old_address.as_ref())
                .unwrap()
                .iter()
                .map(|hop| hop.key.clone())
                .collect()
        })
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            vec![b"g".to_vec(), b"a".to_vec()],
            vec![b"g".to_vec(), b"b".to_vec()],
            vec![b"g".to_vec(), b"c".to_vec()],
            vec![b"h".to_vec(), b"a".to_vec()],
            vec![b"h".to_vec(), b"b".to_vec()],
            vec![b"h".to_vec(), b"c".to_vec()],
            vec![b"n".to_vec(), b"x".to_vec()],
            vec![b"n".to_vec(), b"y".to_vec()],
            vec![b"r".to_vec(), b"gone".to_vec()]
        ]
    );
    assert_eq!(result.delta_data(), 9);
    assert_eq!(result.delta_input(), 13); // Nine expanded entries plus four changed graft descriptors.
    let a = &result.data[0];
    assert_eq!(a.old.as_ref().unwrap().object(), O);
    assert_eq!(a.new.as_ref().unwrap().object(), OTHER);
    assert_ne!(
        a.new.as_ref().unwrap().object(),
        child_after.root_identity()
    );
    assert_eq!(
        a.old_address.as_ref().unwrap()[1].source,
        child_before.root_identity()
    );
    assert_eq!(
        a.new_address.as_ref().unwrap()[1].source,
        child_after.root_identity()
    );
    long_hops();
    membership_and_growth();
    witnesses::nested_and_override_changes();
}

fn long_hops() {
    // Each local path is legal while the composed occurrence exceeds TREE-6.
    let component = vec![b'a'; 255];
    let mut before = tree(vec![item(b"f", file(O, None, false))]);
    let mut after = tree(vec![item(b"f", file(O, Some(&[1]), false))]);
    let mut old_graph = single(&before);
    let mut new_graph = single(&after);
    for _ in 0..18 {
        before = tree(vec![item(&component, graft(before.root_identity()))]);
        after = tree(vec![item(&component, graft(after.root_identity()))]);
        old_graph.insert(before.root_identity(), before.clone());
        new_graph.insert(after.root_identity(), after.clone());
    }
    let result = compare(
        before.root_identity(),
        &old_graph,
        after.root_identity(),
        &new_graph,
    );
    assert_eq!(result.delta_input(), 19);
    assert_eq!(result.delta_data(), 1);
    let hops = result.data[0].new_address.as_ref().unwrap();
    assert_eq!(hops.len(), 19);
    assert!(hops.iter().map(|hop| hop.key.len() + 1).sum::<usize>() > 4096);
    assert!(hops.iter().all(|hop| hop.key.len() <= 4096));
}

#[test]
fn source_discovery_skips_equal_frontiers_and_reports_logical_changes() {
    let old = tree(
        (0..2000)
            .map(|n| {
                item(
                    alloc::format!("f{n:05}").as_bytes(),
                    file(O, Some(&[1]), false),
                )
            })
            .collect(),
    );
    let old_graph = single(&old);
    let same = compare(
        old.root_identity(),
        &old_graph,
        old.root_identity(),
        &old_graph,
    );
    assert_eq!(same.delta_input(), 0);
    assert_eq!(same.delta_data(), 0);
    assert_eq!(
        same.work,
        DiscoveryWork {
            frontier_checks: 1,
            skipped_subtrees: 1,
            ..DiscoveryWork::default()
        }
    );
    let edited = old
        .insert(item(b"f01000", file(OTHER, None, false)))
        .unwrap()
        .tree;
    let new_graph = single(&edited);
    let result = compare(
        old.root_identity(),
        &old_graph,
        edited.root_identity(),
        &new_graph,
    );
    assert_eq!(result.delta_input(), 1);
    assert_eq!(result.delta_data(), 1);
    assert!(result.work.skipped_subtrees > 0);
    assert!(result.work.item_reads < 2000);
    assert!(
        old.nodes()
            .any(|node| edited.nodes().any(|new| node.identity() == new.identity()))
    );
    transitions_and_properties();
    independent_population_oracle();
    physical_cut_witness();
    named_bindings_and_initialization();
    literal_transitions_and_stable_cuts();
    fixed_delta_growth();
    witnesses::connected_cut_growth();
    witnesses::sparse_cut_recovery();
    witnesses::recovery_intervals();
    witnesses::multilevel_property_reuse();
}

fn transitions_and_properties() {
    let before = tree(vec![
        item(b"f", file(O, None, false)),
        item(b"s", bare(EntryKind::Symlink { target: b"old" })),
    ]);
    let after = tree(vec![
        item(b"f", file(O, Some(&[1]), false)),
        item(b"s", bare(EntryKind::Symlink { target: b"new" })),
    ]);
    let changed = after
        .with_properties(Some(vec![Property {
            name: "retain",
            value: b"\x62gc",
        }]))
        .unwrap()
        .tree;
    let result_old_graph = single(&before);
    let result_new_root = changed.root_identity();
    let result_new_graph = graph(&[changed]);
    let result = compare(
        before.root_identity(),
        &result_old_graph,
        result_new_root,
        &result_new_graph,
    );
    assert_eq!(result.delta_input(), 3);
    assert_eq!(result.delta_data(), 1);
    let manifest = tree(vec![
        item(b"f", file(O, None, true)),
        item(b"s", bare(EntryKind::Symlink { target: b"old" })),
    ]);
    let result_old_graph = single(&before);
    let result_new_root = manifest.root_identity();
    let result_new_graph = graph(&[manifest]);
    let result = compare(
        before.root_identity(),
        &result_old_graph,
        result_new_root,
        &result_new_graph,
    );
    assert_eq!(result.delta_data(), 1);
    assert_ne!(
        result.data[0].old.as_ref().unwrap().content,
        result.data[0].new.as_ref().unwrap().content
    );
}

#[test]
fn source_discovery_refuses_invalid_graphs_and_contexts() {
    assert!(SemanticContext::new(2, 2, 1).is_err());
    let good = tree(vec![item(b"f", file(O, Some(&[1]), false))]);
    let recipe = IndexEvaluationRecipe::new(good.root_identity(), "uid").unwrap();
    assert!(matches!(
        PreparedSource::new(&recipe, &BTreeMap::new(), MIN, context()),
        Err(Error::MissingSource)
    ));
    let wrong = single(&good);
    assert!(matches!(
        PreparedSource::new(&recipe, &wrong, MIN + 1, context()),
        Err(Error::Source)
    ));
    let invalid = tree(vec![item(b"f", file(O, Some(&[0xf6]), false))]);
    // uid is canonical ordinary writer data; derived hash.sha256 has a typed bytes schema.
    let bad = Entry {
        attrs: vec![Attribute {
            name: "hash.sha256",
            value: &[0xf6],
        }],
        attrs_present: true,
        ..file(O, None, false)
    };
    let bad_tree = tree(vec![item(b"f", bad)]);
    let bad_recipe = IndexEvaluationRecipe::new(bad_tree.root_identity(), "hash.sha256").unwrap();
    assert!(PreparedSource::new(&bad_recipe, &graph(&[bad_tree]), MIN, context()).is_err());
    let dangling = tree(vec![item(b"g", graft([0x55; 32]))]);
    let dangling_recipe = IndexEvaluationRecipe::new(dangling.root_identity(), "uid").unwrap();
    assert!(matches!(
        PreparedSource::new(&dangling_recipe, &graph(&[dangling]), MIN, context()),
        Err(Error::MissingSource)
    ));
    let index = Tree::build(vec![], None, MIN, TreeUse::Index).unwrap();
    let index_recipe = IndexEvaluationRecipe::new(index.root_identity(), "uid").unwrap();
    assert!(matches!(
        PreparedSource::new(&index_recipe, &graph(&[index]), MIN, context()),
        Err(Error::Source)
    ));
    let wrong_key = BTreeMap::from([(good.root_identity(), invalid)]);
    assert!(matches!(
        PreparedSource::new(&recipe, &wrong_key, MIN, context()),
        Err(Error::Source)
    ));
    depth_refusal();
    contextual_refusals();
    owner_binding_refusals();
    witnesses::fresh_refusals();
}

fn depth_refusal() {
    let mut child = tree(vec![item(b"f", file(O, None, false))]);
    let mut sources = single(&child);
    for depth in 1..=65 {
        child = tree(vec![item(b"g", graft(child.root_identity()))]);
        sources.insert(child.root_identity(), child.clone());
        if depth == 64 {
            let recipe = IndexEvaluationRecipe::new(child.root_identity(), "uid").unwrap();
            assert!(PreparedSource::new(&recipe, &sources, MIN, context()).is_ok());
        }
    }
    let recipe = IndexEvaluationRecipe::new(child.root_identity(), "uid").unwrap();
    assert!(matches!(
        PreparedSource::new(&recipe, &sources, MIN, context()),
        Err(Error::Limit)
    ));
}

#[test]
fn selected_source_lookups_ignore_growing_unrelated_graphs() {
    let old_child = tree(vec![item(b"file", file(O, Some(&[1]), false))]);
    let new_child = tree(vec![item(b"file", file(OTHER, Some(&[2]), false))]);
    let old_owner = tree(vec![
        item(b"left", graft(old_child.root_identity())),
        item(b"right", graft(old_child.root_identity())),
    ]);
    let new_owner = tree(vec![
        item(b"left", graft(new_child.root_identity())),
        item(b"right", graft(old_child.root_identity())),
    ]);
    let old_base = graph(&[old_owner.clone(), old_child.clone()]);
    let new_base = graph(&[new_owner.clone(), old_child.clone(), new_child.clone()]);
    let baseline_noop = compare(
        old_owner.root_identity(),
        &old_base,
        old_owner.root_identity(),
        &old_base,
    );
    let baseline_changed = compare(
        old_owner.root_identity(),
        &old_base,
        new_owner.root_identity(),
        &new_base,
    );
    assert_eq!(baseline_noop.source_lookup_work().calls, 2);
    assert_eq!(
        baseline_noop.source_lookup_work().probes,
        baseline_noop.source_lookup_work().comparisons
    );
    assert_eq!(baseline_noop.old_lookup().root_count(), 2);
    assert_eq!(baseline_changed.new_lookup().root_count(), 3);

    let mut old_graph = old_base.clone();
    let mut new_graph = new_base.clone();
    for number in 0..1024 {
        let key = alloc::format!("unrelated-{number:04}");
        let unrelated = tree(vec![item(key.as_bytes(), file(O, None, false))]);
        old_graph.insert(unrelated.root_identity(), unrelated.clone());
        new_graph.insert(unrelated.root_identity(), unrelated);
    }
    assert_eq!(old_graph.len(), 1026);
    assert_eq!(new_graph.len(), 1027);

    let noop = compare(
        old_owner.root_identity(),
        &old_graph,
        old_owner.root_identity(),
        &old_graph,
    );
    let changed = compare(
        old_owner.root_identity(),
        &old_graph,
        new_owner.root_identity(),
        &new_graph,
    );
    assert_eq!(noop, baseline_noop);
    assert_eq!(changed, baseline_changed);
    assert_eq!(changed.delta_data(), 1);
    assert_eq!(changed.old_lookup().root_count(), 2);
    assert_eq!(changed.new_lookup().root_count(), 3);
    let unrelated = old_graph
        .keys()
        .find(|root| !old_base.contains_key(*root))
        .copied()
        .unwrap();
    let mut rejected = SourceLookupWork::default();
    assert!(matches!(
        changed.old_lookup().tree(unrelated, &mut rejected),
        Err(Error::MissingSource)
    ));
    assert!(matches!(
        changed.new_lookup().tree(unrelated, &mut rejected),
        Err(Error::MissingSource)
    ));
    assert!(matches!(
        changed
            .old_lookup()
            .tree(new_child.root_identity(), &mut rejected),
        Err(Error::MissingSource)
    ));
    assert!(matches!(
        changed
            .new_lookup()
            .tree(old_owner.root_identity(), &mut rejected),
        Err(Error::MissingSource)
    ));
    assert_eq!(rejected.calls, 4);

    // Lookup work and exact borrowed handles stay fixed after the preparation
    // tokens have gone away, including roots retained only on the old side.
    for (lookup, baseline, roots) in [
        (
            changed.old_lookup(),
            baseline_changed.old_lookup(),
            vec![old_owner.root_identity(), old_child.root_identity()],
        ),
        (
            changed.new_lookup(),
            baseline_changed.new_lookup(),
            vec![
                new_owner.root_identity(),
                old_child.root_identity(),
                new_child.root_identity(),
            ],
        ),
    ] {
        let mut work = SourceLookupWork::default();
        let mut expected = SourceLookupWork::default();
        for root in roots {
            assert_eq!(lookup.tree(root, &mut work).unwrap().root_identity(), root);
            assert_eq!(
                baseline.tree(root, &mut expected).unwrap().root_identity(),
                root
            );
        }
        assert_eq!(work, expected);
        assert_eq!(work.probes, work.comparisons);
        assert!(matches!(
            lookup.tree([0; 32], &mut work),
            Err(Error::MissingSource)
        ));
    }
}

#[test]
fn selected_source_preparation_counts_reachable_storage_and_repeated_contexts() {
    let child = tree(vec![item(b"file", file(O, None, false))]);
    let owner = tree(vec![
        item(b"left", graft(child.root_identity())),
        item(b"right", graft(child.root_identity())),
    ]);
    let sources = graph(&[owner.clone(), child.clone()]);
    let recipe = IndexEvaluationRecipe::new(owner.root_identity(), "uid").unwrap();
    let prepared = PreparedSource::new(&recipe, &sources, MIN, context()).unwrap();
    let work = prepared.preparation_work();
    assert_eq!(work.roots, 3);
    assert_eq!(work.nodes, 3);
    assert_eq!(work.entries, 4);
    assert_eq!(work.supplied_map_lookups, 6);
    assert_eq!(work.cache_insertions, 3);
    assert_eq!(work.cached_roots, 2);
    assert_eq!(prepared.lookup().root_count(), 2);
    let discovery = discover_with_mode(&prepared, &prepared, PopulationMode::NewlyEnabled).unwrap();
    assert_eq!(discovery.delta_data(), 2);
    assert_ne!(
        discovery.data()[0].new_address,
        discovery.data()[1].new_address
    );
    assert_eq!(discovery.initialization().source_lookups.calls, 3);
    assert_eq!(discovery.source_lookup_work().calls, 2);
}

#[test]
fn selected_source_binding_refuses_other_geometry_and_semantic_revisions() {
    let entries = vec![item(b"file", file(O, Some(&[1]), false))];
    let ordinary = tree(entries.clone());
    let other_geometry = Tree::build(entries, None, MIN + 1, TreeUse::Ordinary).unwrap();
    assert_eq!(ordinary.root_identity(), other_geometry.root_identity());
    let original_graph = single(&ordinary);
    let other_graph = single(&other_geometry);
    let recipe = IndexEvaluationRecipe::new(ordinary.root_identity(), "uid").unwrap();
    let original = PreparedSource::new(&recipe, &original_graph, MIN, context()).unwrap();
    let result = discover(&original, &original).unwrap();
    assert_eq!(result.sources().minimum(), MIN);
    assert_eq!(result.sources().context(), context());
    assert!(matches!(
        PreparedSource::new(&recipe, &other_graph, MIN, context()),
        Err(Error::Source)
    ));
    assert!(matches!(
        PreparedSource::new(&recipe, &other_graph, MIN + 1, context()),
        Err(Error::Source)
    ));

    // Public carrier contexts form a singleton today; a different valid token
    // cannot be manufactured without weakening the protected constructor.
    for revisions in [(2, 2, 1), (3, 1, 1), (3, 2, 2), (4, 2, 1)] {
        assert_eq!(
            SemanticContext::new(revisions.0, revisions.1, revisions.2),
            Err(super::super::Error::Schema)
        );
    }
}
