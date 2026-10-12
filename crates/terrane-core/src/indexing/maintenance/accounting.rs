//! Keeps preparation, affected-path, canonical editing and export work distinct.

use alloc::vec::Vec;

use super::{Coordinate, Error, RouteChange};
use crate::indexing::evaluation;
use crate::indexing::incremental::{BoundaryRegion, DiscoveryWork, InitializationWork, StreamWork};
use crate::tree_builder;

/// Counts balanced-map work, including unsuccessful probes and rotation copies.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MapWork {
    /// Searches, insertions and removals requested, including empty searches.
    pub operations: usize,
    /// Greatest immutable map height at the start of an operation.
    pub maximum_height: usize,
    /// Immutable map nodes inspected.
    pub probes: usize,
    /// Ordered key comparisons performed.
    pub comparisons: usize,
    /// Immutable map nodes allocated, including rotation intermediates.
    pub allocations: usize,
    overflow: bool,
}

impl MapWork {
    /// Records an operation and starting height, deferring overflow to `checked`.
    pub(super) fn operation(&mut self, height: usize) {
        Self::charge(&mut self.operations, 1, &mut self.overflow);
        self.maximum_height = self.maximum_height.max(height);
    }

    fn charge(counter: &mut usize, amount: usize, overflow: &mut bool) {
        match counter.checked_add(amount) {
            Some(next) => *counter = next,
            None => *overflow = true,
        }
    }

    /// Records a node probe, deferring overflow to `checked`.
    pub(super) fn probe(&mut self) {
        Self::charge(&mut self.probes, 1, &mut self.overflow);
    }

    /// Records a key comparison, deferring overflow to `checked`.
    pub(super) fn compare(&mut self) {
        Self::charge(&mut self.comparisons, 1, &mut self.overflow);
    }

    /// Records a node allocation, deferring overflow to `checked`.
    pub(super) fn allocate(&mut self) {
        Self::charge(&mut self.allocations, 1, &mut self.overflow);
    }

    /// Combines counts, maximum heights and deferred overflow flags.
    pub(super) fn combine(&mut self, other: Self) {
        Self::charge(&mut self.operations, other.operations, &mut self.overflow);
        self.maximum_height = self.maximum_height.max(other.maximum_height);
        Self::charge(&mut self.probes, other.probes, &mut self.overflow);
        Self::charge(&mut self.comparisons, other.comparisons, &mut self.overflow);
        Self::charge(&mut self.allocations, other.allocations, &mut self.overflow);
        self.overflow |= other.overflow;
    }

    /// Checks whether any accumulated map count overflowed.
    ///
    /// # Errors
    /// Returns `Error::Limit` if charging or combining recorded an overflow.
    pub(super) fn checked(&self) -> Result<(), Error> {
        if self.overflow {
            Err(Error::Limit)
        } else {
            Ok(())
        }
    }
}

/// Adds an amount without changing the counter on overflow.
///
/// # Errors
/// Returns `Error::Limit` if the sum exceeds `usize`.
pub(super) fn add(counter: &mut usize, amount: usize) -> Result<(), Error> {
    *counter = counter.checked_add(amount).ok_or(Error::Limit)?;
    Ok(())
}

/// Counts transaction-local ordered-map operations and actual key comparisons.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TemporaryWork {
    /// Ordered map searches, entries, insertions and removals requested.
    pub operations: usize,
    /// Actual ordered key comparisons, including unsuccessful searches.
    pub comparisons: usize,
    /// Coordinate keys visited by bounded-depth grouping scans.
    pub scans: usize,
}

impl TemporaryWork {
    /// Adds temporary operation, comparison and scan counts in order.
    ///
    /// # Errors
    /// Rejects counter overflow; earlier successful additions remain applied.
    pub(super) fn combine(&mut self, other: Self) -> Result<(), Error> {
        add(&mut self.operations, other.operations)?;
        add(&mut self.comparisons, other.comparisons)?;
        add(&mut self.scans, other.scans)
    }
}

/// Counts actual emitted-node metadata inspection before reachability updates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StagingWork {
    /// Emitted immutable Nodes inspected, including temporary discarded roots.
    pub nodes: usize,
    /// Leaf rows inspected to extract logical continuation edges.
    pub rows: usize,
    /// Physical, continuation and gap references extracted.
    pub edges: usize,
}

impl StagingWork {
    /// Adds inspected-node, row and extracted-edge counts in order.
    ///
    /// # Errors
    /// Rejects counter overflow; earlier successful additions remain applied.
    pub(super) fn combine(&mut self, other: Self) -> Result<(), Error> {
        add(&mut self.nodes, other.nodes)?;
        add(&mut self.rows, other.rows)?;
        add(&mut self.edges, other.edges)
    }
}

/// Reports a full initial relationship check and canonical retention pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PreparationWork {
    /// Legacy selected independent-verifier traversal events.
    pub verification: evaluation::Work,
    /// Supplied-byte decoding, identity hashing and canonical reconstruction
    /// performed by the independent verifier, including repeated contextual
    /// checks. These operations are separate from retention below and exclude
    /// allocator costs and CPU instruction counts.
    pub verification_physical: evaluation::PhysicalWork,
    /// Physical Nodes decoded again to retain canonical Tree models.
    pub decoded_nodes: usize,
    /// Physical bytes read during retained-tree reconstruction.
    pub decoded_bytes: usize,
    /// Empty baseline Trees built before measured canonical population edits.
    pub empty_trees: usize,
    /// Bytes emitted by empty baseline creation.
    pub empty_bytes_encoded: usize,
    /// Node-domain preimage bytes hashed by empty baseline creation.
    pub empty_bytes_hashed: usize,
    /// Insertion and property replacement, two records per retained physical Tree.
    pub reconstruction: Vec<tree_builder::Work>,
    /// Persistent relationship and closure map construction work.
    pub maps: MapWork,
    /// Physical and logical references inspected during closure installation.
    pub edges: usize,
    /// Actual retained physical-node reference metadata extraction.
    pub staging: StagingWork,
    /// Ordered staging-map bookkeeping, outside retained reconstruction.
    pub temporary: TemporaryWork,
}

/// An affected auxiliary Tree's one sorted entry batch or root-property edit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchWork {
    /// Contextual route, primary or gap coordinate.
    pub coordinate: Coordinate,
    /// Number of genuinely changed logical entries in the sorted batch.
    pub edits: usize,
    /// Every measured canonical, seek, validation and adoption work field.
    pub work: tree_builder::Work,
}

/// Reports changed input/data/routes and all locally performed update phases.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateWork {
    /// Existing maintenance or explicitly enumerated full new-population work.
    pub mode: crate::indexing::incremental::PopulationMode,
    /// Changed logical source entries and individual source bindings.
    pub delta_input: usize,
    /// Changed participating tagged file states or occurrence memberships.
    pub delta_data: usize,
    /// Changed contextual route rows and gap/owner structural bindings.
    pub delta_route: usize,
    /// Complete logical route transitions, separate from canonical repartition.
    pub routes: Vec<RouteChange>,
    /// Actual source comparison operations, copied once from bound discovery.
    pub discovery: DiscoveryWork,
    /// Exact source divergence and recovery diagnostics.
    pub boundaries: Vec<BoundaryRegion>,
    /// Exclusive source event ownership by local stream and physical level.
    pub streams: Vec<StreamWork>,
    /// Explicit new-population enumeration, never maintenance boundary work.
    pub initialization: InitializationWork,
    /// Relevant-root lookup charges inherited once from bound discovery.
    pub discovery_source_lookups: crate::indexing::incremental::SourceLookupWork,
    /// Relevant-root lookup calls, probes and comparisons performed locally.
    pub source_lookups: crate::indexing::incremental::SourceLookupWork,
    /// Selected root handles checked for identity, geometry, use and conflicts.
    pub source_roots_checked: usize,
    /// Actual sorted auxiliary edits and property-only mutations.
    pub batches: Vec<BatchWork>,
    /// Map probes, comparisons and immutable path-copy allocations.
    pub maps: MapWork,
    /// Reachability-map subset of `maps`, including every incoming-edge call.
    pub closure_maps: MapWork,
    /// Namespace nodes examined while resolving affected local graft paths.
    pub source_path_nodes: usize,
    /// Key comparisons performed by affected local graft-path searches.
    pub source_path_comparisons: usize,
    /// Auxiliary path Nodes inspected while checking old logical row state.
    pub auxiliary_path_nodes: usize,
    /// Ordered key comparisons used to check old auxiliary row state.
    pub auxiliary_path_comparisons: usize,
    /// Physical root Nodes checked for contextual carrier shape.
    pub carrier_nodes: usize,
    /// Root leaf rows inspected by contextual carrier validation.
    pub carrier_rows: usize,
    /// Physical or logical edges examined while advancing reachable closure.
    pub closure_edges: usize,
    /// New immutable physical nodes installed in reachable closure.
    pub closure_added: usize,
    /// Immutable physical nodes retired after their last reference disappeared.
    pub closure_removed: usize,
    /// Generated canonical pointer/property payload bytes copied into the arena.
    pub arena_bytes: usize,
    /// Explicit empty baseline creation for previously absent route trees.
    pub empty_trees: usize,
    /// Empty baseline encoding output bytes.
    pub empty_bytes_encoded: usize,
    /// Empty baseline Node-domain hash preimage bytes.
    pub empty_bytes_hashed: usize,
    /// Actual emitted-node reference metadata extraction, outside boundary B.
    pub staging: StagingWork,
    /// Canonical pointer and property-wrapper output bytes encoded outside Tree edits.
    pub structural_bytes_encoded: usize,
    /// Actual transaction-local grouping, entry and staging map bookkeeping.
    pub temporary: TemporaryWork,
    /// Emitted-node staging subset of `temporary`, including closure lookups.
    pub staging_maps: TemporaryWork,
}

impl UpdateWork {
    /// Sums exclusively attributed divergence work in the normative cost units.
    ///
    /// Newly created levels, completion, root properties, preparation, seeks,
    /// map/path/closure work and source initialization remain separately visible.
    /// Source Node opens are reported but are not item/comparison/frontier units.
    ///
    /// # Errors
    /// Rejects full population construction and overflow while summing costs.
    pub fn boundary_cost(&self) -> Result<usize, Error> {
        if self.mode != crate::indexing::incremental::PopulationMode::Existing {
            return Err(Error::Binding);
        }
        let mut total = 0usize;
        for stream in &self.streams {
            for event in &stream.events {
                if event.boundary.is_some()
                    && !matches!(
                        event.kind,
                        crate::indexing::incremental::PhysicalEventKind::NodeRead
                            | crate::indexing::incremental::PhysicalEventKind::SkippedSubtree
                    )
                {
                    total = total.checked_add(event.amount).ok_or(Error::Limit)?;
                }
            }
        }
        for batch in &self.batches {
            for region in &batch.work.regions {
                let work = region.work;
                for count in [
                    work.item_reads,
                    work.comparisons,
                    work.frontier_checks,
                    work.item_bytes_encoded,
                    work.node_bytes_encoded,
                    work.item_bytes_hashed,
                    work.node_bytes_hashed,
                ] {
                    total = total.checked_add(count).ok_or(Error::Limit)?;
                }
            }
        }
        Ok(total)
    }
}

/// Reports a separate exhaustive closure materialization.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExportWork {
    /// Reachable immutable map records visited.
    pub nodes: usize,
    /// Canonical Node bytes copied into the owned export.
    pub bytes: usize,
}

/// Reports bounded selection and copying of transaction-local emitted Nodes.
///
/// Candidate visits are bounded by actual canonical outputs, including discarded
/// temporary roots. Neither the previous nor final complete closure is scanned.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PublicationWork {
    /// Distinct emitted identities examined in the transaction's staging map.
    pub candidates: usize,
    /// Emitted identities absent from the final reachable closure.
    pub discarded: usize,
    /// Reachable emitted identities already retained by the previous closure.
    pub reused: usize,
    /// Reachable newly emitted canonical Node payloads copied for publication.
    pub nodes: usize,
    /// Canonical Node bytes actually copied for those payloads.
    pub bytes: usize,
    /// All final/previous closure probes and comparisons, including misses.
    pub maps: MapWork,
}
