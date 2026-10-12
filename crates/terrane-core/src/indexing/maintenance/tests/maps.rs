//! Checks fixed sparse deltas at large contextual-map cardinalities.

use super::*;

fn graph(population: usize, stage: usize) -> (Graph, Digest) {
    let mut graph = Graph::new();
    let mut entries = Vec::new();
    for index in 0..population {
        let mut object = [0x44; 32];
        object[..8].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
        entries.push(leaf(
            alloc::format!("stable-{index:05}").as_bytes(),
            file(object, Some(VALUES[0]), false),
        ));
    }
    entries.push(leaf(
        b"changed",
        file(
            ONE,
            match stage % 3 {
                0 => Some(VALUES[0]),
                1 => None,
                _ => Some(VALUES[1]),
            },
            false,
        ),
    ));
    let child = add(&mut graph, entries);
    let owner = add(
        &mut graph,
        alloc::vec![leaf(b"a", graft(child)), leaf(b"b", graft(child))],
    );
    (graph, owner)
}

/// Checks balanced-map work for fixed sparse deltas across large repeated snapshots.
///
/// # Panics
/// Panics if fixture construction or an asserted independent witness fails.
pub(super) fn assert_large_contextual_maps() {
    for population in [32, 512] {
        let graphs: Vec<_> = (0..34).map(|stage| graph(population, stage)).collect();
        let recipe = IndexEvaluationRecipe::new(graphs[0].1, "uid").unwrap();
        let source = PreparedSource::new(&recipe, &graphs[0].0, MINIMUM, context()).unwrap();
        let initial = oracle::Model::new(&graphs[0].0, graphs[0].1);
        let arena = ByteArena::new(8 * 1024 * 1024).unwrap();
        let (mut state, _) = prepare(
            &recipe,
            &source,
            &graphs[0].0,
            &initial.data,
            &arena,
            MINIMUM,
            context(),
        )
        .unwrap();
        assert_eq!(state.route_map_shape().0, 3 * (population + 1));
        let saved = state.clone();
        for pair in graphs.windows(2) {
            let old_recipe = IndexEvaluationRecipe::new(pair[0].1, "uid").unwrap();
            let new_recipe = IndexEvaluationRecipe::new(pair[1].1, "uid").unwrap();
            let old = PreparedSource::new(&old_recipe, &pair[0].0, MINIMUM, context()).unwrap();
            let new = PreparedSource::new(&new_recipe, &pair[1].0, MINIMUM, context()).unwrap();
            let changes = discover(&old, &new).unwrap();
            assert_eq!(changes.delta_data(), 2);
            let (next, work) = update(&state, &changes).unwrap();
            next.routes.assert_balanced();
            next.closure.assert_balanced();
            let route_height = next.route_map_shape().1.max(state.route_map_shape().1);
            let closure_height = next.closure_map_shape().1.max(state.closure_map_shape().1);
            // Two independent graft paths remove and add two predicates:
            // six contextual Trees on each side, plus canonical closure edges.
            let route_operations = 24;
            let closure_operations = work.closure_edges + 2 + work.closure_removed;
            assert!(
                work.maps.probes
                    <= route_operations * (route_height + 1)
                        + 4 * closure_operations * (closure_height + 1)
            );
            assert!(
                work.maps.allocations
                    <= 4 * route_operations * (route_height + 1)
                        + 8 * closure_operations * (closure_height + 1)
            );
            assert_eq!(next.route_map_shape().0, 3 * (population + 1));
            state = next;
        }
        assert_result(&saved, &graphs[0].0, graphs[0].1, &initial);
        let last = graphs.last().unwrap();
        assert_result(
            &state,
            &last.0,
            last.1,
            &oracle::Model::new(&last.0, last.1),
        );
    }
}
