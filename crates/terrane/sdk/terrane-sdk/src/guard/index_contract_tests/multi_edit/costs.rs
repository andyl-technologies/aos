//! Checks complete local maintenance costs against algorithm-derived fixture bounds.
//!
//! B comes exclusively from the independent physical/source oracles. Binary
//! searches use independently decoded cardinalities and heights; fixed-digest
//! maps use the explicit AVL and BTree limits in maintenance/closure.rs and
//! maintenance/temporary.rs. No coefficient is selected from native timings.

use std::collections::BTreeMap;

use super::{
    CommitReport, Coordinate, ExpectedWork, REPEATS, TestResult, binding, invalid, physical,
};
use terrane_format::{
    indexing::{
        incremental::DiscoveryWork,
        maintenance::{MapWork, UpdateWork},
    },
    tree_builder::Work,
    tree_format::{MAX_NODE_ITEMS_BYTES, MAX_TREE_LEVEL},
};

const DIGEST_HEIGHT: usize = 514;
const STAGING_COMPARISONS: usize = 11 * 257;
// The node map has one header byte, at most three one-byte field keys and
// a one-byte level (the public height limit is 15). A leaf item occupies at least
// four bytes, so the 64 KiB item cap permits at most 16,384 items: its array
// header occupies three bytes. The property map itself belongs to payload.
const NODE_FRAMING: usize = 1 + 3 + 1 + 3;
const NODE_CAP: usize = MAX_NODE_ITEMS_BYTES + NODE_FRAMING;
const NODE_DOMAIN: usize = b"terrane-node-v1\0".len();

fn logarithm(n: usize) -> usize {
    (usize::BITS - n.max(2).saturating_sub(1).leading_zeros()) as usize
}

fn source_units(work: DiscoveryWork) -> usize {
    work.node_reads
        + work.item_reads
        + work.boundary_checks
        + work.property_reads
        + work.child_reads
        + work.comparisons
        + work.frontier_checks
        + work.skipped_subtrees
}

fn map_units(work: MapWork) -> usize {
    work.operations + work.probes + work.comparisons + work.allocations
}

fn tree_units(work: &Work) -> usize {
    // Phase descriptors are aliases of stream, not extra executed operations.
    work.node_reads
        + work.validation_reads
        + work.seek_comparisons
        + work.item_encodings
        + work.node_encodings
        + physical::sum(work.stream)
        + physical::sum(work.adoption)
}

fn update_units(work: &UpdateWork) -> usize {
    // closure_maps and staging_maps are subsets, so each is counted only once.
    source_units(work.discovery)
        + work.discovery_source_lookups.calls
        + work.discovery_source_lookups.probes
        + work.discovery_source_lookups.comparisons
        + work.source_lookups.calls
        + work.source_lookups.probes
        + work.source_lookups.comparisons
        + work.source_roots_checked
        + work.source_path_nodes
        + work.source_path_comparisons
        + work.auxiliary_path_nodes
        + work.auxiliary_path_comparisons
        + work.carrier_nodes
        + work.carrier_rows
        + map_units(work.maps)
        + work.closure_edges
        + work.closure_added
        + work.closure_removed
        + work.arena_bytes
        + work.empty_trees
        + work.empty_bytes_encoded
        + work.empty_bytes_hashed
        + work.staging.nodes
        + work.staging.rows
        + work.staging.edges
        + work.structural_bytes_encoded
        + work.temporary.operations
        + work.temporary.comparisons
        + work.temporary.scans
        + work
            .batches
            .iter()
            .map(|batch| tree_units(&batch.work))
            .sum::<usize>()
}

fn assert_tree(work: &Work, edits: usize, height: usize, log: usize) {
    physical::assert_partition(work);
    let seeks = 2 * (edits + work.regions.len() + 1) * height;
    assert!(work.node_reads <= seeks + height * work.stream.item_reads);
    assert!(work.seek_comparisons <= seeks * log);
    // These fixtures have no hard links or slash-containing auxiliary keys.
    // Sparse validation performs a bounded number of old/final keyed searches.
    assert!(work.validation_reads <= 4 * (edits + 1) * height);
    assert!(work.item_encodings <= work.stream.item_bytes_encoded);
    assert!(work.node_encodings <= work.stream.node_bytes_encoded);
    assert!(
        work.new_levels.is_empty(),
        "fixture creates no higher physical level"
    );
    assert!(physical::sum(work.preparation) <= 2 * seeks);
    // With unchanged height, completion has its two frontier checks; deleting
    // a singleton adds the canonical five-byte empty Node and its hash preimage.
    assert!(physical::sum(work.completion) <= 2 + 5 + 5 + NODE_DOMAIN);
}

fn assert_update(work: &UpdateWork, oracle: &ExpectedWork) {
    let log = logarithm(oracle.n);
    let source_height = usize::from(oracle.source_level) + 1;
    let auxiliary_height = usize::from(oracle.auxiliary_level) + 1;
    let coordinates = oracle
        .batches
        .keys()
        .filter(|coordinate| matches!(coordinate, Coordinate::Route { .. }))
        .count();
    let hops = oracle
        .batches
        .keys()
        .filter_map(|coordinate| match coordinate {
            Coordinate::Route { hops, .. } => Some(hops.len()),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(work.closure_added, oracle.closure.added.len());
    assert_eq!(work.closure_removed, oracle.closure.removed.len());
    assert_eq!(work.closure_edges, oracle.closure.edges);
    assert_eq!(work.closure_maps.operations, 2 * (oracle.closure.edges + 2));
    assert_eq!(
        work.maps.operations - work.closure_maps.operations,
        2 * coordinates
    );
    assert!(work.closure_maps.maximum_height <= DIGEST_HEIGHT);
    assert!(work.closure_maps.probes <= 2 * DIGEST_HEIGHT * work.closure_maps.operations);
    assert!(work.closure_maps.comparisons <= work.closure_maps.probes);
    assert!(work.closure_maps.allocations <= 5 * DIGEST_HEIGHT * work.closure_maps.operations);
    // A route coordinate exists for an actual value/object/local occurrence;
    // this two-level fixture has fewer than four coordinates per namespace row.
    let route_height = 2 * logarithm(4 * oracle.n + 1);
    assert!(work.maps.probes - work.closure_maps.probes <= 4 * route_height * coordinates);
    assert!(
        work.maps.comparisons - work.closure_maps.comparisons <= 4 * route_height * coordinates
    );
    assert!(
        work.maps.allocations - work.closure_maps.allocations <= 10 * route_height * coordinates
    );

    assert_eq!(work.discovery_source_lookups.calls, 2 * work.streams.len());
    assert_eq!(
        work.discovery_source_lookups.probes,
        work.discovery_source_lookups.comparisons
    );
    assert!(
        work.discovery_source_lookups.probes <= work.discovery_source_lookups.calls * logarithm(4)
    );
    assert_eq!(
        work.source_lookups.calls,
        3 + 2 * hops.iter().map(|depth| depth + 1).sum::<usize>()
    );
    assert_eq!(work.source_roots_checked, work.source_lookups.calls);
    assert_eq!(work.source_lookups.probes, work.source_lookups.comparisons);
    assert!(work.source_lookups.probes <= work.source_lookups.calls * logarithm(4));
    assert!(work.source_path_nodes <= 2 * hops.iter().sum::<usize>() * source_height);
    assert!(work.source_path_comparisons <= work.source_path_nodes * log);
    assert!(work.auxiliary_path_nodes <= (oracle.route - 1) * auxiliary_height);
    assert!(work.auxiliary_path_comparisons <= work.auxiliary_path_nodes * log);

    let encodings = work
        .batches
        .iter()
        .map(|batch| batch.work.node_encodings)
        .sum::<usize>();
    let items = work
        .batches
        .iter()
        .map(|batch| batch.work.stream.item_reads)
        .sum::<usize>();
    assert_eq!(
        work.staging.nodes, encodings,
        "each emitted Node is actually staged once"
    );
    assert_eq!(
        work.staging.nodes,
        oracle
            .batches
            .values()
            .map(|batch| batch.staging.nodes)
            .sum::<usize>()
    );
    assert_eq!(
        work.staging.rows,
        oracle
            .batches
            .values()
            .map(|batch| batch.staging.rows)
            .sum::<usize>()
    );
    assert_eq!(
        work.staging.edges,
        oracle
            .batches
            .values()
            .map(|batch| batch.staging.edges)
            .sum::<usize>()
    );
    assert!(work.staging.rows <= items);
    assert!(work.staging.edges <= items);
    assert!(work.carrier_nodes <= work.batches.len() + 1);
    assert!(work.carrier_rows <= 2 * work.staging.rows);
    assert!(work.closure_edges <= 2 * (items + encodings));

    let grouping_operations = work.temporary.operations - work.staging_maps.operations;
    assert!(grouping_operations <= 4 * oracle.data + 3 * coordinates);
    let grouping_comparisons = work.temporary.comparisons - work.staging_maps.comparisons;
    assert!(
        grouping_comparisons
            <= 11 * (1 + logarithm(4 * oracle.data + 3 * coordinates + 1)) * grouping_operations
    );
    assert!(work.temporary.scans <= 2 * (oracle.max_hops + 1) * coordinates);
    assert_eq!(
        work.staging_maps.operations,
        work.staging.nodes + work.closure_added
    );
    assert!(work.staging_maps.comparisons <= STAGING_COMPARISONS * work.staging_maps.operations);
    assert_eq!(work.staging_maps.scans, 0);
    assert!(work.empty_trees <= coordinates);
    assert_eq!(work.empty_bytes_encoded, 5 * work.empty_trees);
    assert_eq!(
        work.empty_bytes_hashed,
        (5 + NODE_DOMAIN) * work.empty_trees
    );
    // A continuation is a 34-byte CBOR digest, plus one old/new uid wrapper.
    assert!(work.arena_bytes <= 34 * oracle.route);
    assert!(work.structural_bytes_encoded <= 34 * oracle.route + 2 * binding([0; 32]).len());
    for batch in &work.batches {
        assert_tree(&batch.work, batch.edits, auxiliary_height, log);
        assert_eq!(
            batch.work.root_properties,
            Default::default(),
            "fixture has no gap/root mutation inside auxiliary edits"
        );
    }
}

/// Checks sparse emitted identities, separate validation and the whole local bound.
///
/// # Errors
/// Rejects a missing expected owner, propagation oracle or operation report.
/// # Panics
/// Panics for hidden enumeration, omitted costs, false reuse or a violated bound.
pub(super) fn assert_report(
    report: &CommitReport,
    expected: &BTreeMap<bool, ExpectedWork>,
    adversarial: bool,
) -> TestResult {
    let mut local = 0;
    let mut boundary = 0;
    let mut logical = 0;
    let mut publication_nodes = 0;
    let mut publication_bytes = 0;
    for operation in &report.index_work.operations {
        let root = operation.paths == [b"/".to_vec()];
        let oracle = expected.get(&root).ok_or_else(invalid)?;
        let work = operation.update.as_ref().ok_or_else(invalid)?;
        assert_update(work, oracle);
        let publication = operation.publication.ok_or_else(invalid)?;
        let candidates = oracle
            .batches
            .values()
            .flat_map(|batch| batch.candidates.iter().copied())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(publication.candidates, candidates.len());
        assert_eq!(
            publication.discarded,
            candidates.difference(&oracle.closure.new).count()
        );
        assert_eq!(
            publication.reused,
            candidates
                .intersection(&oracle.closure.new)
                .filter(|identity| oracle.closure.old.contains(*identity))
                .count()
        );
        assert_eq!(operation.publication_nodes, oracle.closure.added);
        assert_eq!(publication.nodes, oracle.closure.added.len());
        assert_eq!(publication.bytes, oracle.closure.bytes);
        assert_eq!(
            publication.candidates,
            publication.discarded + publication.reused + publication.nodes
        );
        assert!(publication.candidates <= work.staging.nodes);
        assert_eq!(
            publication.maps.operations,
            2 * publication.candidates - publication.discarded
        );
        assert_eq!(publication.maps.allocations, 0);
        assert_eq!(publication.maps.probes, publication.maps.comparisons);
        assert!(publication.maps.maximum_height <= DIGEST_HEIGHT);
        assert!(publication.maps.probes <= 2 * DIGEST_HEIGHT * publication.candidates);
        assert!(
            oracle.closure.added.len() < oracle.closure.new.len(),
            "real retained reachable Nodes survive sparse maintenance"
        );
        assert!(oracle.closure.removed.len() < oracle.closure.old.len());
        assert!(
            operation
                .publication_nodes
                .iter()
                .all(|identity| !oracle.reused.contains(identity)),
            "retained canonical Nodes are never republished"
        );
        if root {
            assert!(
                work.discovery.skipped_subtrees > 0,
                "actual equal physical frontiers avoid entry reads"
            );
        }
        // The complete closure copy remains an independently verified completion
        // input. Sparse publication above must never share that exemption.
        assert_eq!(operation.export.nodes, oracle.closure.new.len());
        assert_eq!(operation.export.bytes, oracle.closure.total_bytes);
        assert!(
            operation
                .old_source
                .as_ref()
                .is_some_and(|work| work.entries > 0)
        );
        assert!(operation.new_source.entries > 0);
        assert!(
            operation
                .old_index
                .as_ref()
                .is_some_and(|work| work.verification.source_entries > 0)
        );
        local += update_units(work) + publication.candidates + map_units(publication.maps);
        // One additional ordered identity collection visits/copies each digest.
        // Publication payload copies are included once in output_bytes_copied.
        local += operation.publication_nodes.len() * (1 + 32);
        publication_nodes += publication.nodes;
        publication_bytes += publication.bytes;
        let b = operation.boundary.ok_or_else(invalid)?;
        let a = (1 + oracle.input + oracle.data + oracle.route) * logarithm(oracle.n);
        boundary += b;
        logical += a;
        if !adversarial {
            // Ordinary recovery has bounded canonical node size at every level.
            // Eight byte passes cover full/prefix encodings, node encodings and
            // item/Node hash preimages on both sides of each changed frontier.
            assert!(b <= 8 * (NODE_CAP + NODE_DOMAIN) * (usize::from(MAX_TREE_LEVEL) + 1) * a);
        }
    }

    let work = &report.index_work;
    let capture = work.graft_validation.ok_or_else(invalid)?;
    let preparation = work.graft_preparation.ok_or_else(invalid)?;
    assert_eq!(capture.owners, 3);
    assert_eq!(
        capture.entry_visits,
        expected.get(&true).ok_or_else(invalid)?.n + 9
    );
    assert_eq!(capture.nested_entry_visits, capture.entry_visits);
    assert!(capture.node_visits >= capture.owners);
    assert_eq!(
        (capture.graft_slots, capture.addresses, capture.key_bytes),
        (REPEATS + 1, REPEATS + 1, 15)
    );
    assert_eq!((capture.depth_checks, capture.depth_edges), (6, 2));
    assert_eq!(
        (preparation.owners, preparation.owner_occurrences),
        (3, REPEATS + 2)
    );
    assert_eq!(
        (preparation.entry_visits, preparation.nested_entry_visits),
        (0, 0)
    );
    assert_eq!(
        (preparation.graft_slots, preparation.graft_occurrences),
        (REPEATS + 1, REPEATS + 1)
    );
    local += preparation.owners + preparation.owner_occurrences;
    let propagation = work.graft_propagation;
    assert_eq!(
        (propagation.changed_targets, propagation.target_lookups),
        (2, 2)
    );
    for amount in [
        propagation.address_links,
        propagation.affected_occurrences,
        propagation.selected_entries,
        propagation.entry_lookups,
        propagation.nested_entry_visits,
        propagation.replacement_lookups,
        propagation.replaced_graft_slots,
        propagation.edited_entries,
    ] {
        assert_eq!(amount, REPEATS);
        local += amount;
    }
    local += propagation.changed_targets + propagation.target_lookups;
    assert_eq!(work.propagation.len(), 1);
    let root = expected.get(&true).ok_or_else(invalid)?;
    let propagated = root.propagation.as_ref().ok_or_else(invalid)?;
    assert_eq!(
        work.propagation[0].regions, propagated.regions,
        "native graft edits follow the independent physical oracle"
    );
    assert_tree(
        &work.propagation[0],
        REPEATS,
        usize::from(root.source_level) + 1,
        logarithm(root.n),
    );
    local += tree_units(&work.propagation[0]);
    // Grafts are the final three root-local entries. At most that many capped
    // nodes per level can remain in their tail, rather than an n-entry scan.
    assert!(
        tree_units(&work.propagation[0])
            <= 8 * (NODE_CAP + NODE_DOMAIN) * (REPEATS + 1) * (usize::from(root.source_level) + 1)
    );
    assert_eq!(work.completion.len(), 2);
    for completion in &work.completion {
        assert_eq!(completion.checks.len(), 1);
        assert!(completion.checks[0].source.entries > 0);
        assert!(completion.graph_handles_copied > 0);
        // The graph handle copy exists solely for the separate full validator.
        // Every owner/binding/recipe/output operation remains local below.
        local += completion.binding_bytes_decoded
            + completion.binding_value_bytes_encoded
            + completion.binding_bytes_encoded
            + completion.arena_bytes_copied
            + completion.owner_handles_copied
            + completion.owner_bytes_emitted
            + completion.owner_bytes_hashed
            + completion.attribute_bytes_copied
            + completion.recipe_bytes_encoded
            + completion.recipe_bytes_hashed
            + completion.memo_bytes_encoded
            + completion.memo_bytes_hashed;
        assert!(completion.owner_bytes_emitted <= NODE_CAP);
    }
    assert_eq!(
        work.output_node_insertions,
        publication_nodes + work.propagation[0].node_encodings + work.completion.len()
    );
    assert_eq!(
        work.output_bytes,
        publication_bytes
            + work.propagation[0].stream.node_bytes_encoded
            + work
                .completion
                .iter()
                .map(|completion| completion.owner_bytes_emitted)
                .sum::<usize>()
    );
    assert_eq!(work.output_bytes_copied, work.output_bytes);
    local += work.output_node_insertions + work.output_bytes + work.output_bytes_copied;

    // Each changed closure edge performs two AVL operations, at most 2h probes
    // per operation and five copies per level. Staging uses at most 11*257
    // comparisons per operation; publication performs at most two h probes.
    // Edges/staged candidates are bounded above by actual stream items/bytes.
    let digest_units = 4 * (1 + 2 * DIGEST_HEIGHT + 2 * DIGEST_HEIGHT + 5 * DIGEST_HEIGHT)
        + 2 * (1 + STAGING_COMPARISONS)
        + 1
        + 4 * DIGEST_HEIGHT
        + 33;
    // Fixed capped root/tail work includes owner completion, native propagation,
    // binding wrappers and every output byte move/copy, outside normative B.
    let root_units =
        8 * (NODE_CAP + NODE_DOMAIN) * (REPEATS + 1) * (usize::from(MAX_TREE_LEVEL) + 1);
    let bound = (root_units + digest_units) * logical + digest_units * boundary;
    assert!(
        local <= bound,
        "all reported local work={local} exceeds derived DRV-29 bound={bound}, logical={logical}, B={boundary}"
    );
    eprintln!("multi-edit local_work={local} derived_bound={bound} logical={logical} B={boundary}");
    Ok(())
}
