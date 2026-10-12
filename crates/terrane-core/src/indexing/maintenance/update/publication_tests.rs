//! Checks emitted publication independently of full relationship verification.

#![allow(clippy::unwrap_used, reason = "test failures deliberately panic")]

use alloc::{collections::BTreeMap, vec::Vec};

use super::*;
use crate::indexing::{
    IndexEvaluationRecipe, carrier::SemanticContext, evaluation, incremental::PreparedSource,
};
use crate::tree_format::{Attribute, ContentRef, EntryKind, LeafItem};

const MINIMUM: u64 = 262_144;
const OBJECT: Digest = [0x11; 32];
const VALUE: &[u8] = &[0x18, 24];
type Graph = BTreeMap<Digest, Tree<'static>>;

fn context() -> SemanticContext {
    SemanticContext::new(3, 2, 1).unwrap()
}

fn file(value: Option<&'static [u8]>) -> Entry<'static> {
    Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: 1,
            content: ContentRef::Inline(OBJECT),
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

fn graph(population: usize, missing: bool) -> (Graph, Digest) {
    let rows = (0..population)
        .map(|index| LeafItem {
            key: alloc::format!("item-{index:06}").into_bytes(),
            entry: file((!missing || index != 17).then_some(VALUE)),
        })
        .collect();
    let tree = Tree::build(rows, None, MINIMUM, TreeUse::Ordinary).unwrap();
    let root = tree.root_identity();
    (BTreeMap::from([(root, tree)]), root)
}

#[test]
fn publication_contains_only_reachable_new_emissions_and_discards_intermediate_roots() {
    let (old_graph, old_owner) = graph(2048, false);
    let (new_graph, new_owner) = graph(2048, true);
    let old_recipe = IndexEvaluationRecipe::new(old_owner, "uid").unwrap();
    let new_recipe = IndexEvaluationRecipe::new(new_owner, "uid").unwrap();
    let old_source = PreparedSource::new(&old_recipe, &old_graph, MINIMUM, context()).unwrap();
    let new_source = PreparedSource::new(&new_recipe, &new_graph, MINIMUM, context()).unwrap();
    let old_data = evaluation::construct(&old_recipe, &old_graph, MINIMUM, context()).unwrap();
    let expected = evaluation::construct(&new_recipe, &new_graph, MINIMUM, context()).unwrap();
    let arena = super::super::ByteArena::new(4 * 1024 * 1024).unwrap();
    let (old, _) = super::super::prepare(
        &old_recipe,
        &old_source,
        &old_graph,
        &old_data,
        &arena,
        MINIMUM,
        context(),
    )
    .unwrap();
    let discovery = crate::indexing::incremental::discover(&old_source, &new_source).unwrap();

    let (updated, update_work, publication) = update_with_publication(&old, &discovery).unwrap();
    let (full, export) = updated.materialize().unwrap();

    assert_eq!(full.nodes, expected.nodes);
    assert_eq!(full.root, expected.root);
    evaluation::verify(&new_recipe, &new_graph, MINIMUM, context(), &full).unwrap();
    let required: BTreeMap<_, _> = expected
        .nodes
        .iter()
        .filter(|(identity, _)| !old_data.nodes.contains_key(*identity))
        .map(|(identity, bytes)| (*identity, bytes.clone()))
        .collect();
    assert_eq!(
        publication
            .nodes
            .iter()
            .cloned()
            .collect::<BTreeMap<_, _>>(),
        required
    );
    assert!(
        required.len() < expected.nodes.len(),
        "unchanged physical subtrees must remain reused"
    );
    assert!(
        publication.work.discarded > 0,
        "property-free intermediate primary must be excluded"
    );
    assert_eq!(publication.work.nodes, required.len());
    assert_eq!(
        publication.work.bytes,
        required.values().map(Vec::len).sum::<usize>()
    );
    assert!(publication.work.bytes < export.bytes);
    assert_eq!(
        publication.work.candidates,
        publication.work.nodes + publication.work.reused + publication.work.discarded
    );
    assert!(publication.work.candidates <= update_work.staging.nodes);
    assert_eq!(
        publication.work.maps.operations,
        2 * publication.work.candidates - publication.work.discarded
    );
    assert_eq!(publication.work.maps.allocations, 0);
    assert!(publication.work.maps.probes <= 1028 * publication.work.candidates);
    assert_eq!(
        publication.work.maps.probes,
        publication.work.maps.comparisons
    );
}

#[test]
fn unchanged_update_publishes_no_bytes_while_full_verification_remains_available() {
    let (graph, owner) = graph(128, false);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let source = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
    let arena = super::super::ByteArena::new(1024 * 1024).unwrap();
    let (old, _) = super::super::initialize(&recipe, &source, &arena, MINIMUM, context()).unwrap();
    let discovery = crate::indexing::incremental::discover(&source, &source).unwrap();

    let (updated, _, publication) = update_with_publication(&old, &discovery).unwrap();
    let (full, export) = updated.materialize().unwrap();

    assert!(publication.nodes.is_empty());
    assert_eq!(publication.work, super::super::PublicationWork::default());
    assert!(export.nodes > 0);
    assert!(export.bytes > 0);
    evaluation::verify(&recipe, &graph, MINIMUM, context(), &full).unwrap();
}

#[test]
fn initialization_exports_full_population_including_canonical_empty_root() {
    for population in [0, 128] {
        let (graph, owner) = graph(population, false);
        let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
        let source = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
        let arena = super::super::ByteArena::new(1024 * 1024).unwrap();

        let (initialized, _) =
            super::super::initialize(&recipe, &source, &arena, MINIMUM, context()).unwrap();
        let (full, export) = initialized.materialize().unwrap();

        assert!(full.nodes.contains_key(&full.root));
        assert_eq!(export.nodes, initialized.node_count());
        assert_eq!(
            export.bytes,
            full.nodes.values().map(Vec::len).sum::<usize>()
        );
        evaluation::verify(&recipe, &graph, MINIMUM, context(), &full).unwrap();
    }
}

#[test]
fn emitted_identity_reused_from_old_closure_is_excluded() {
    let (graph, owner) = graph(128, false);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let source = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
    let arena = super::super::ByteArena::new(1024 * 1024).unwrap();
    let (old, _) = super::super::initialize(&recipe, &source, &arena, MINIMUM, context()).unwrap();
    let mut staged = Staged::new();
    closure::stage(old.primary.root_rc(), context(), &mut staged).unwrap();

    let selected = publication(&old, &old, staged).unwrap();

    assert!(selected.nodes.is_empty());
    assert_eq!(selected.work.candidates, 1);
    assert_eq!(selected.work.reused, 1);
    assert_eq!(selected.work.maps.operations, 2);
    assert_eq!(selected.work.bytes, 0);
}

#[test]
fn installation_refuses_new_root_without_its_emitted_bytes() {
    let (old_graph, old_owner) = graph(128, false);
    let (new_graph, new_owner) = graph(128, true);
    let old_recipe = IndexEvaluationRecipe::new(old_owner, "uid").unwrap();
    let new_recipe = IndexEvaluationRecipe::new(new_owner, "uid").unwrap();
    let old_source = PreparedSource::new(&old_recipe, &old_graph, MINIMUM, context()).unwrap();
    let new_source = PreparedSource::new(&new_recipe, &new_graph, MINIMUM, context()).unwrap();
    let arena = super::super::ByteArena::new(1024 * 1024).unwrap();
    let (old, _) =
        super::super::initialize(&old_recipe, &old_source, &arena, MINIMUM, context()).unwrap();
    let discovery = crate::indexing::incremental::discover(&old_source, &new_source).unwrap();
    let (updated, _, mut staged) =
        apply_staged(&old, &discovery, PopulationMode::Existing).unwrap();
    staged.remove(&updated.root()).unwrap();
    let mut retained = old.closure.clone();

    let result = closure::add(
        updated.root(),
        &mut retained,
        &staged,
        &mut closure::Work::default(),
    );

    assert_eq!(result, Err(Error::Transition));
}

fn inline_change_work(new_value: Option<&'static [u8]>) -> UpdateWork {
    let (old_graph, old_owner) = graph(2, false);
    let new_tree = old_graph[&old_owner]
        .edit_entries(&[(b"item-000001".to_vec(), Some(file(new_value)))])
        .unwrap()
        .tree;
    let new_owner = new_tree.root_identity();
    let new_graph = BTreeMap::from([(new_owner, new_tree)]);
    let old_recipe = IndexEvaluationRecipe::new(old_owner, "uid").unwrap();
    let new_recipe = IndexEvaluationRecipe::new(new_owner, "uid").unwrap();
    let old_source = PreparedSource::new(&old_recipe, &old_graph, MINIMUM, context()).unwrap();
    let new_source = PreparedSource::new(&new_recipe, &new_graph, MINIMUM, context()).unwrap();
    let expected = evaluation::construct(&new_recipe, &new_graph, MINIMUM, context()).unwrap();
    let arena = super::super::ByteArena::new(1024 * 1024).unwrap();
    let (old, _) =
        super::super::initialize(&old_recipe, &old_source, &arena, MINIMUM, context()).unwrap();
    let discovery = crate::indexing::incremental::discover(&old_source, &new_source).unwrap();

    let (updated, work) = update(&old, &discovery).unwrap();
    let (full, _) = updated.materialize().unwrap();

    assert_eq!(full.root, expected.root);
    assert_eq!(full.nodes, expected.nodes);
    evaluation::verify(&new_recipe, &new_graph, MINIMUM, context(), &full).unwrap();
    assert_eq!(work.delta_input, 1);
    assert_eq!(work.delta_data, 1);

    work
}

#[test]
fn unchanged_gap_validates_changed_primary_once() {
    let work = inline_change_work(Some(&[0x18, 25]));

    // Each one-row route and the two-row primary are checked exactly once.
    assert_eq!(work.carrier_nodes, 3);
    assert_eq!(work.carrier_rows, 4);
    assert_eq!(work.batches.len(), 3);
    assert!(
        !work
            .routes
            .iter()
            .any(|change| change.key.as_slice() == b"index-gaps")
    );
}

#[test]
fn changed_gap_keeps_intermediate_and_final_primary_validation() {
    let work = inline_change_work(None);

    // The two routes, gap, intermediate primary and completed primary all differ.
    assert_eq!(work.carrier_nodes, 5);
    assert_eq!(work.carrier_rows, 5);
    assert_eq!(work.batches.len(), 5);
    assert!(
        work.routes
            .iter()
            .any(|change| change.key.as_slice() == b"index-gaps")
    );
}

#[test]
fn primary_batch_refuses_malformed_output_before_property_completion() {
    let (graph, owner) = graph(2, false);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let source = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
    let arena = super::super::ByteArena::new(1024 * 1024).unwrap();
    let (old, _) = super::super::initialize(&recipe, &source, &arena, MINIMUM, context()).unwrap();
    let key = IndexKey::new(&[0x18, 25], OBJECT).unwrap().encode();
    let mut edits = Edits::new();
    edits.insert(
        key,
        Edit {
            old: None,
            new: Some(RouteValue::Row {
                object: [0x22; 32],
                route: Some(old.root()),
            }),
        },
    );
    let mut staged = Staged::new();
    let mut work = UpdateWork::default();

    let result = batch(
        &Coordinate::Primary,
        &old.primary,
        edits,
        &old,
        &old.sources,
        &old.sources,
        owner,
        &mut staged,
        &mut work,
    );

    assert!(matches!(
        result,
        Err(Error::Evaluation(evaluation::Error::Carrier(
            crate::indexing::Error::Schema
        )))
    ));
    assert_eq!(work.carrier_nodes, 1);
    assert_eq!(work.carrier_rows, 2);
    assert!(work.batches.is_empty());
}
