//! Holds relevant immutable source inputs fixed while unrelated maps grow.

use super::*;

/// Checks that unrelated supplied roots do not change relevant update work.
///
/// # Panics
/// Panics if fixture construction or an asserted independent witness fails.
pub(super) fn assert_unrelated_roots_do_not_enter_update() {
    let (graph, owner) = fixture(0, 8, 2);
    let (next_graph, next_owner) = fixture(1, 8, 2);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let next_recipe = IndexEvaluationRecipe::new(next_owner, "uid").unwrap();
    let prepared = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
    let previous = oracle::Model::new(&graph, owner);
    let replacement = oracle::Model::new(&next_graph, next_owner);
    let arena = ByteArena::new(4 * 1024 * 1024).unwrap();
    let (state, _) = prepare(
        &recipe,
        &prepared,
        &graph,
        &previous.data,
        &arena,
        MINIMUM,
        context(),
    )
    .unwrap();
    let mut variants = Vec::new();
    for unrelated in [0, 128, 8192] {
        let mut old = graph.clone();
        let mut new = next_graph.clone();
        for index in 0..unrelated {
            let tree = Tree::build(
                alloc::vec![leaf(
                    alloc::format!("unrelated-{index:08}").as_bytes(),
                    file(TWO, None, false)
                )],
                None,
                MINIMUM,
                TreeUse::Ordinary,
            )
            .unwrap();
            new.insert(tree.root_identity(), tree.clone());
            old.insert(tree.root_identity(), tree);
        }
        assert_eq!(old.len(), graph.len() + unrelated);
        variants.push((old, new));
    }
    let mut sparse_work = None;
    let mut noop_work = None;
    for (old_graph, new_graph) in &variants {
        let old = PreparedSource::new(&recipe, old_graph, MINIMUM, context()).unwrap();
        let new = PreparedSource::new(&next_recipe, new_graph, MINIMUM, context()).unwrap();
        assert_eq!(old.lookup().root_count(), prepared.lookup().root_count());
        let changes = discover(&old, &new).unwrap();
        let (updated, work) = update(&state, &changes).unwrap();
        assert!(work.source_lookups.calls > 3);
        assert_eq!(work.source_roots_checked, work.source_lookups.calls);
        oracle::assert_discovery(&previous, &replacement, &changes);
        oracle::assert_routes(&previous, &replacement, &work);
        assert_result(&updated, new_graph, next_owner, &replacement);
        if let Some(expected) = &sparse_work {
            assert_eq!(&work, expected);
        } else {
            sparse_work = Some(work);
        }

        let changes = discover(&old, &old).unwrap();
        let (same, work) = update(&state, &changes).unwrap();
        assert_eq!(same.root(), state.root());
        assert_eq!(work.source_lookups.calls, 3);
        assert!(work.source_lookups.probes >= 3);
        assert_eq!(work.source_roots_checked, 3);
        assert_eq!(work.source_path_nodes, 0);
        assert_eq!(work.boundary_cost().unwrap(), 0);
        if let Some(expected) = &noop_work {
            assert_eq!(&work, expected);
        } else {
            noop_work = Some(work);
        }
    }
}

/// Checks removal-only transitions through a surviving changed graft ancestor.
///
/// # Panics
/// Panics if fixture construction or an asserted independent witness fails.
pub(super) fn assert_removal_only_surviving_ancestor() {
    let mut graph = Graph::new();
    let child = add(
        &mut graph,
        alloc::vec![
            leaf(b"x", file(ONE, Some(VALUES[0]), false)),
            leaf(b"y", file(ONE, Some(VALUES[0]), false))
        ],
    );
    let owner = add(&mut graph, alloc::vec![leaf(b"a", graft(child))]);
    let mut next = graph.clone();
    let next_child = add(
        &mut next,
        alloc::vec![leaf(b"y", file(ONE, Some(VALUES[0]), false))],
    );
    let next_owner = add(&mut next, alloc::vec![leaf(b"a", graft(next_child))]);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let next_recipe = IndexEvaluationRecipe::new(next_owner, "uid").unwrap();
    let old = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
    let new = PreparedSource::new(&next_recipe, &next, MINIMUM, context()).unwrap();
    let previous = oracle::Model::new(&graph, owner);
    let replacement = oracle::Model::new(&next, next_owner);
    let arena = ByteArena::new(1024 * 1024).unwrap();
    let (state, _) = prepare(
        &recipe,
        &old,
        &graph,
        &previous.data,
        &arena,
        MINIMUM,
        context(),
    )
    .unwrap();
    let changes = discover(&old, &new).unwrap();
    assert_eq!(changes.delta_data(), 1);
    assert!(changes.data().iter().all(|change| change.new.is_none()));
    let (updated, work) = update(&state, &changes).unwrap();
    let terminal = work
        .routes
        .iter()
        .find(|change| change.key == b"x")
        .unwrap();
    assert_eq!(terminal.old_source, Some(child));
    assert_eq!(terminal.new_source, Some(next_child));
    let continuation = work
        .routes
        .iter()
        .find(|change| change.key == b"a")
        .unwrap();
    assert!(continuation.old.is_some() && continuation.new.is_some());
    oracle::assert_discovery(&previous, &replacement, &changes);
    oracle::assert_routes(&previous, &replacement, &work);
    assert_result(&updated, &next, next_owner, &replacement);
    let mut missing = next.clone();
    missing.remove(&next_child);
    assert!(PreparedSource::new(&next_recipe, &missing, MINIMUM, context()).is_err());
}
