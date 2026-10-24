//! Models one internal P route, complete rich occurrences and every W counter.
//!
//! Literal source/route rows are independent of lookup and evaluation. The
//! reviewed Tree builder determines only canonical physical grouping. Offline
//! rank models derive comparison counts from that grouping and sorted caches.

use super::*;
use crate::tree_builder::StoredNode;
use crate::tree_format::ExtendedAttribute;

const POPULATION: usize = 2048;

fn rich_file(index: usize) -> Entry<'static> {
    let mut entry = file(ONE, Some(b"\x01"), "uid", !index.is_multiple_of(2));
    entry.attrs = alloc::vec![
        Attribute {
            name: "gid",
            value: b"\x07"
        },
        Attribute {
            name: "uid",
            value: b"\x01"
        },
        Attribute {
            name: "tag.note",
            value: b"\x61n"
        },
    ];
    entry.xattrs_present = true;
    entry.xattrs = alloc::vec![ExtendedAttribute {
        name: b"user.note",
        value: b"literal file metadata"
    }];
    entry
}

fn rich_graft(root: Digest, label: &'static [u8]) -> Entry<'static> {
    let mut entry = graft(root);
    entry.kind = EntryKind::Tree {
        root,
        props: Some(alloc::vec![Property {
            name: "compression",
            value: b"\xa2\x65value\x64none\x67inherit\xf5",
        }]),
    };
    entry.attrs_present = true;
    entry.attrs = alloc::vec![Attribute {
        name: "tag.note",
        value: label
    }];
    entry.xattrs_present = true;
    entry.xattrs = alloc::vec![ExtendedAttribute {
        name: b"user.graft",
        value: b"literal graft metadata"
    }];
    entry
}

// An exact-member search compares the balanced decision tree's ancestors and
// the matching position. This model operates on ranks, never production keys.
fn exact_cost(length: usize, rank: usize) -> usize {
    let middle = length / 2;
    match rank.cmp(&middle) {
        Ordering::Equal => 1,
        Ordering::Less => 1 + exact_cost(middle, rank),
        Ordering::Greater => 1 + exact_cost(length - middle - 1, rank - middle - 1),
    }
}

// A lower-bound partition reaches an empty interval, rather than stopping on
// equality. Rank counts separators strictly below the selected local key.
fn partition_cost(length: usize, rank: usize) -> usize {
    if length == 0 {
        return 0;
    }
    let middle = length / 2;
    if rank > middle {
        1 + partition_cost(length - middle - 1, rank - middle - 1)
    } else {
        1 + partition_cost(middle, rank)
    }
}

fn cache_cost(keys: &[Digest], wanted: Digest) -> usize {
    let rank = keys.iter().position(|key| *key == wanted).unwrap();
    exact_cost(keys.len(), rank)
}

fn source_cost(node: &StoredNode<'_>, key: &[u8]) -> (usize, usize) {
    match node.items() {
        NodeItems::Leaf(rows) => {
            let rank = rows.iter().position(|row| row.key == key).unwrap();
            (1, exact_cost(rows.len(), rank))
        }
        NodeItems::Internal(rows) => {
            let rank = rows
                .iter()
                .filter(|row| row.last_key.as_slice() < key)
                .count();
            let (visits, comparisons) = source_cost(&node.children()[rank], key);
            (1 + visits, partition_cost(rows.len(), rank) + comparisons)
        }
    }
}

fn physical_cost(node: &StoredNode<'_>, keys: &[Digest], depth: usize, first_only: bool) -> Work {
    let mut work = Work {
        route_nodes: 1,
        physical_cache_lookups: 1,
        physical_cache_comparisons: cache_cost(keys, node.identity()),
        route_cycle_comparisons: depth,
        ..Work::default()
    };
    if let NodeItems::Internal(children) = node.items() {
        let selected = if first_only { 1 } else { children.len() };
        for child in &node.children()[..selected] {
            work.route_edges += 1;
            let nested = physical_cost(child, keys, depth + 1, first_only);
            work.route_nodes += nested.route_nodes;
            work.route_edges += nested.route_edges;
            work.physical_cache_lookups += nested.physical_cache_lookups;
            work.physical_cache_comparisons += nested.physical_cache_comparisons;
            work.route_cycle_comparisons += nested.route_cycle_comparisons;
        }
    }
    work
}

fn assert_work(actual: Work, expected: Work) {
    assert_eq!(actual, expected, "complete immutable C/P/W model");
}

/// Checks rich repeated occurrences and exact lookup work across an internal route.
///
/// # Panics
/// Panics if fixture construction or an asserted lookup contract fails.
pub(super) fn check() {
    let keys: Vec<_> = (0..POPULATION)
        .map(|index| alloc::format!("file{index:05}").into_bytes())
        .collect();
    let entries: Vec<_> = (0..POPULATION).map(rich_file).collect();
    let source_rows = keys
        .iter()
        .zip(&entries)
        .map(|(key, entry)| leaf(key, entry.clone()))
        .collect();
    let child = tree(source_rows);
    let child_root = child.root_identity();
    let graft_g = rich_graft(child_root, b"\x61g");
    let graft_h = rich_graft(child_root, b"\x61h");
    let owner = tree(alloc::vec![
        leaf(b"g", graft_g.clone()),
        leaf(b"h", graft_h.clone())
    ]);
    let old = owner.root_identity();
    let mut graph = BTreeMap::from([(old, owner), (child_root, child)]);
    // Unrelated supplied roots enlarge the lookup cache, not namespace coverage.
    // Their cost is visible during preparation and every actual binary probe.
    for index in 0..129 {
        let unrelated = tree(alloc::vec![leaf(
            alloc::format!("unrelated{index:03}").as_bytes(),
            Entry {
                kind: EntryKind::Symlink {
                    target: b"literal unrelated root"
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            }
        )]);
        graph.insert(unrelated.root_identity(), unrelated);
    }

    let literal_routes: Vec<_> = keys
        .iter()
        .map(|key| {
            leaf(
                key,
                Entry {
                    kind: EntryKind::Index {
                        targets: alloc::vec![ONE],
                    },
                    attrs: Vec::new(),
                    attrs_present: false,
                    xattrs: Vec::new(),
                    xattrs_present: false,
                    provenance: None,
                },
            )
        })
        .collect();
    let route = Tree::build(literal_routes, None, MINIMUM, TreeUse::Index).unwrap();
    assert!(
        route.root().level() > 0,
        "canonical internal P, not many separate candidate routes"
    );
    let child_route = route.root_identity();
    let mut nodes: BTreeMap<_, _> = route
        .nodes()
        .map(|node| (node.identity(), node.encoded().to_vec()))
        .collect();
    let top_route = add(
        &mut nodes,
        &[
            forward(b"g", ONE, child_route),
            forward(b"h", ONE, child_route),
        ],
        None,
    );
    let primary = add(
        &mut nodes,
        &[forward(&value_key(b"\x01", ONE), ONE, top_route)],
        None,
    );
    let data = IndexData {
        root: primary,
        nodes,
        work: evaluation::Work::default(),
    };
    let bytes = binding("uid", primary);
    let (owner, graph) = bind(old, &graph, &bytes);
    let prepared = Prepared::prepare(
        IndexEvaluationRecipe::new(owner, "uid").unwrap(),
        &graph,
        MINIMUM,
        context(),
        &data,
    )
    .unwrap();
    assert_eq!(
        prepared.preparation().physical_cache_roots,
        data.nodes.len()
    );
    assert_eq!(prepared.preparation().source_cache_roots, graph.len());
    assert!(graph.len() > 128);
    let physical_keys: Vec<_> = data.nodes.keys().copied().collect();
    assert_eq!(prepared.preparation().cache_lookups, 2);
    assert_eq!(
        prepared.preparation().cache_comparisons,
        2 * cache_cost(&physical_keys, primary)
    );
    assert_eq!(prepared.preparation().loaded_nodes, data.nodes.len());
    assert_eq!(
        prepared.preparation().loaded_bytes,
        data.nodes.values().map(Vec::len).sum::<usize>()
    );
    assert_eq!(prepared.preparation().indexed_rows, 1);
    let preparation = prepared.preparation();

    let candidate = prepared.candidates(b"\x01").unwrap();
    assert_work(
        candidate.work,
        Work {
            comparisons: 2,
            candidates: 1,
            carrier_checks: 1,
            value_validations: 1,
            key_checks: 2,
            key_bytes_copied: 66,
            ..Work::default()
        },
    );
    assert_eq!(candidate.rows.len(), 1);
    assert_eq!(
        (candidate.rows[0].object(), candidate.rows[0].route()),
        (ONE, top_route)
    );
    let source_keys: Vec<_> = graph.keys().copied().collect();
    let full_physical = physical_cost(route.root(), &physical_keys, 0, false);
    let early_physical = physical_cost(route.root(), &physical_keys, 0, true);
    let all = candidate.rows[0].occurrences().unwrap();

    let mut expected_rows = Vec::new();
    for (graft_key, graft_entry) in [(b"g".as_slice(), &graft_g), (b"h".as_slice(), &graft_h)] {
        for (key, entry) in keys.iter().zip(&entries) {
            let EntryKind::File { content, size, .. } = entry.kind else {
                panic!("literal file")
            };
            expected_rows.push(Occurrence {
                hops: alloc::vec![Hop {
                    source_root: owner,
                    key: graft_key.to_vec(),
                    target: child_root,
                    route: child_route,
                    entry: graft_entry
                }],
                source_root: child_root,
                key: key.clone(),
                content,
                size,
                value: Some(b"\x01"),
                entry,
            });
        }
    }
    assert_eq!(
        all.rows, expected_rows,
        "all literal fields, including complete borrowed Entries"
    );
    let (owner_g_nodes, owner_g_compares) = source_cost(graph[&owner].root(), b"g");
    let (owner_h_nodes, owner_h_compares) = source_cost(graph[&owner].root(), b"h");
    let source_costs: Vec<_> = keys
        .iter()
        .map(|key| source_cost(graph[&child_root].root(), key))
        .collect();
    let total_nodes: usize = source_costs.iter().map(|cost| cost.0).sum();
    let total_comparisons: usize = source_costs.iter().map(|cost| cost.1).sum();
    let expected_work = Work {
        occurrences: 2 * POPULATION,
        route_nodes: 1 + 2 * full_physical.route_nodes,
        route_edges: 2 * full_physical.route_edges,
        route_rows: 2 + 2 * POPULATION,
        source_roots: 3,
        source_nodes: owner_g_nodes + owner_h_nodes + 2 * total_nodes,
        source_comparisons: owner_g_compares + owner_h_compares + 2 * total_comparisons,
        physical_cache_lookups: 1 + 2 * full_physical.physical_cache_lookups,
        physical_cache_comparisons: cache_cost(&physical_keys, top_route)
            + 2 * full_physical.physical_cache_comparisons,
        source_cache_lookups: 3,
        source_cache_comparisons: cache_cost(&source_keys, owner)
            + 2 * cache_cost(&source_keys, child_root),
        attribute_name_probes: 4 * POPULATION,
        terminal_value_checks: 2 * POPULATION,
        object_checks: 2 + 4 * POPULATION,
        carrier_checks: 2 + 2 * POPULATION,
        source_cycle_comparisons: 2,
        route_cycle_comparisons: 2 * full_physical.route_cycle_comparisons,
        key_bytes_copied: 2 + 2 * keys.iter().map(|key| key.len() + 1).sum::<usize>(),
        hop_records_copied: 2 + 2 * POPULATION,
        ..Work::default()
    };
    assert_work(all.work, expected_work);

    let first = candidate.rows[0].first_occurrence().unwrap();
    assert_eq!(first.occurrence.as_ref(), expected_rows.first());
    assert_work(
        first.work,
        Work {
            occurrences: 1,
            route_rows: 2,
            source_roots: 2,
            route_nodes: 1 + early_physical.route_nodes,
            route_edges: early_physical.route_edges,
            source_nodes: owner_g_nodes + source_costs[0].0,
            source_comparisons: owner_g_compares + source_costs[0].1,
            physical_cache_lookups: 1 + early_physical.physical_cache_lookups,
            physical_cache_comparisons: cache_cost(&physical_keys, top_route)
                + early_physical.physical_cache_comparisons,
            source_cache_lookups: 2,
            source_cache_comparisons: cache_cost(&source_keys, owner)
                + cache_cost(&source_keys, child_root),
            attribute_name_probes: 2,
            terminal_value_checks: 1,
            object_checks: 3,
            carrier_checks: 2,
            source_cycle_comparisons: 1,
            route_cycle_comparisons: early_physical.route_cycle_comparisons,
            key_bytes_copied: 2 + keys[0].len(),
            hop_records_copied: 2,
            ..Work::default()
        },
    );
    assert!(first.work.route_nodes < all.work.route_nodes);
    assert!(first.work.source_cache_comparisons < all.work.source_cache_comparisons);
    assert_eq!(prepared.preparation(), preparation);
}
