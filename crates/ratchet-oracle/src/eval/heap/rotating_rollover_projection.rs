//! Exact report-only accounting for rotating whole-domain rollover.
//!
//! The projection replays state causally. Each interval starts with the prior
//! projected compact destination, stable domain, and pinned domain; applies
//! explicit acquisitions and retirements; and then overlaps the complete
//! compactable source with a new destination. Independently measured non-heap
//! residency is exogenous and is never inferred from a residual.
//!
//! Every measured checkpoint and continuous high-water observation carries a
//! disjoint ownership partition. External payload lifecycle is reconciled
//! separately. Missing provenance or a non-reconciled partition fails closed.
//! This module performs no collection, mutation, purge, advice, or publication.

use std::fmt;

/// Required root-complete execution checkpoints for the rollover replay.
pub(crate) const ROTATING_ROLLOVER_ORDINALS: [u64; 9] =
    [160, 176, 192, 224, 256, 288, 320, 352, 357];

/// Optional stricter engineering ceiling, independent of the paired C++ proof.
pub(crate) const ROTATING_ROLLOVER_ENGINEERING_GATE_BYTES: u64 = 226_492_416;

const DEFAULT_LIVENESS_BYTES: u64 = 2 * 1024 * 1024;
const TABLE: &str = "rotating whole-domain rollover projection";

/// Evidence failures observed at one checkpoint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RotatingRolloverBlockers {
    /// Roots lacking exact writable-slot or pinned provenance.
    pub(crate) missing_writable_roots: u64,
    /// Edges lacking exact writable-owner or pinned provenance.
    pub(crate) missing_writable_edges: u64,
    /// Objects lacking an exact ownership and layout classification.
    pub(crate) unclassified_objects: u64,
    /// Edges lacking an exact ownership classification.
    pub(crate) unclassified_edges: u64,
    /// Semantic aliases not proven fresh or purgeable.
    pub(crate) stale_aliases: u64,
    /// Hash identities not proven rebuildable.
    pub(crate) hash_identity_blockers: u64,
    /// Tail identities not proven writable or pinned.
    pub(crate) tail_identity_blockers: u64,
    /// Other observable identities not proven writable or pinned.
    pub(crate) identity_blockers: u64,
    /// Object inventory or ownership-ledger mismatches.
    pub(crate) inventory_blockers: u64,
    /// Edge inventory mismatches.
    pub(crate) edge_inventory_blockers: u64,
    /// Missing exact compact-layout evidence.
    pub(crate) compact_layout_blockers: u64,
    /// Missing complete old-domain unmap evidence.
    pub(crate) old_domain_unmap_blockers: u64,
    /// Missing exact survivor-only weak-index rebuild evidence.
    pub(crate) weak_index_rebuild_blockers: u64,
}

impl RotatingRolloverBlockers {
    fn checked_total(self, ordinal: u64) -> Result<u64, RotatingRolloverProjectionError> {
        checked_sum(
            ordinal,
            &[
                self.missing_writable_roots,
                self.missing_writable_edges,
                self.unclassified_objects,
                self.unclassified_edges,
                self.stale_aliases,
                self.hash_identity_blockers,
                self.tail_identity_blockers,
                self.identity_blockers,
                self.inventory_blockers,
                self.edge_inventory_blockers,
                self.compact_layout_blockers,
                self.old_domain_unmap_blockers,
                self.weak_index_rebuild_blockers,
            ],
        )
    }
}

/// Completeness claims required in addition to zero observed blocker counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RotatingRolloverEvidence {
    /// Every root has exact writable-slot or pinned provenance.
    pub(crate) writable_root_provenance_complete: bool,
    /// Every edge has exact writable-owner or pinned provenance.
    pub(crate) writable_edge_provenance_complete: bool,
    /// Every semantic side table and alias has been audited.
    pub(crate) semantic_alias_audit_complete: bool,
    /// Every observable hash, tail, thunk, and handle identity has been audited.
    pub(crate) identity_audit_complete: bool,
    /// Iterable object and traversed edge inventories are complete.
    pub(crate) inventory_complete: bool,
    /// Compact immutable and typed-work layouts have exact size evidence.
    pub(crate) compact_layout_exact: bool,
    /// The complete old inline reservation can be unmapped.
    pub(crate) complete_old_inline_domain_unmap_proven: bool,
    /// Weak indexes can be rebuilt with survivor entries only.
    pub(crate) survivor_weak_index_rebuild_exact: bool,
}

impl RotatingRolloverEvidence {
    const fn complete(self) -> bool {
        self.writable_root_provenance_complete
            && self.writable_edge_provenance_complete
            && self.semantic_alias_audit_complete
            && self.identity_audit_complete
            && self.inventory_complete
            && self.compact_layout_exact
            && self.complete_old_inline_domain_unmap_proven
            && self.survivor_weak_index_rebuild_exact
    }
}

/// One disjoint byte/page ownership partition at a measured instant.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RotatingRolloverOwnershipLedger {
    /// Inline bytes owned by the uncollected compactable source generation.
    pub(crate) source_inline_bytes: u64,
    /// External bytes owned and retired with the source generation.
    pub(crate) source_external_bytes: u64,
    /// Bytes in the nonmoving stable-head domain.
    pub(crate) stable_head_bytes: u64,
    /// Inline bytes in other explicitly pinned domains.
    pub(crate) pinned_inline_bytes: u64,
    /// External bytes retained by explicitly pinned owners.
    pub(crate) pinned_external_bytes: u64,
    /// Measured bytes outside evaluator-owned rollover domains.
    pub(crate) exogenous_non_heap_bytes: u64,
    /// Sum of the six disjoint byte ownership classes.
    pub(crate) partition_total_bytes: u64,
    /// Allocation page size used by the page partition.
    pub(crate) page_bytes: u64,
    /// Pages owned by the compactable source, including its external payloads.
    pub(crate) source_pages: u64,
    /// Pages owned by the stable-head domain.
    pub(crate) stable_head_pages: u64,
    /// Pages owned by pinned inline and external storage.
    pub(crate) pinned_pages: u64,
    /// Pages owned by exogenous non-heap storage.
    pub(crate) exogenous_non_heap_pages: u64,
    /// Sum of the four disjoint page ownership classes.
    pub(crate) partition_total_pages: u64,
    /// Committed capacity of the inline compactable source reservation.
    pub(crate) source_inline_committed_capacity_bytes: u64,
    /// Committed capacity of separately allocated source external payloads.
    pub(crate) source_external_committed_capacity_bytes: u64,
    /// Independently measured union of uniquely owned allocation bytes.
    pub(crate) unique_allocation_union_bytes: u64,
    /// Independently measured resident-page union bytes.
    pub(crate) unique_resident_page_union_bytes: u64,
    /// Bytes claimed by more than one ownership domain.
    pub(crate) cross_domain_overlap_bytes: u64,
    /// Resident bytes on explicitly shared partial pages.
    pub(crate) partial_page_shared_bytes: u64,
    /// Pages owned by the old inline reservation and eligible for complete unmap.
    pub(crate) source_inline_pages: u64,
    /// Separately transferable external allocation pages.
    pub(crate) source_external_pages: u64,
    /// Whether independent allocation and page union enumeration is complete.
    pub(crate) unique_union_proven: bool,
}

impl RotatingRolloverOwnershipLedger {
    fn source_bytes(self, ordinal: u64) -> Result<u64, RotatingRolloverProjectionError> {
        checked_add(
            ordinal,
            self.source_inline_bytes,
            self.source_external_bytes,
        )
    }

    fn pinned_bytes(self, ordinal: u64) -> Result<u64, RotatingRolloverProjectionError> {
        checked_add(
            ordinal,
            self.pinned_inline_bytes,
            self.pinned_external_bytes,
        )
    }

    fn source_committed_capacity(
        self,
        ordinal: u64,
    ) -> Result<u64, RotatingRolloverProjectionError> {
        checked_add(
            ordinal,
            self.source_inline_committed_capacity_bytes,
            self.source_external_committed_capacity_bytes,
        )
    }

    fn reconciled(self, ordinal: u64) -> Result<bool, RotatingRolloverProjectionError> {
        if self.page_bytes == 0 {
            return Ok(false);
        }
        let byte_total = checked_sum(
            ordinal,
            &[
                self.source_inline_bytes,
                self.source_external_bytes,
                self.stable_head_bytes,
                self.pinned_inline_bytes,
                self.pinned_external_bytes,
                self.exogenous_non_heap_bytes,
            ],
        )?;
        let page_total = checked_sum(
            ordinal,
            &[
                self.source_pages,
                self.stable_head_pages,
                self.pinned_pages,
                self.exogenous_non_heap_pages,
            ],
        )?;
        let page_capacity = page_total.checked_mul(self.page_bytes).ok_or(
            RotatingRolloverProjectionError::ByteOverflow {
                ordinal,
                table: TABLE,
            },
        )?;
        let class_capacities_reconcile = [
            (self.source_bytes(ordinal)?, self.source_pages),
            (self.stable_head_bytes, self.stable_head_pages),
            (self.pinned_bytes(ordinal)?, self.pinned_pages),
            (self.exogenous_non_heap_bytes, self.exogenous_non_heap_pages),
        ]
        .into_iter()
        .all(|(bytes, pages)| {
            pages
                .checked_mul(self.page_bytes)
                .is_some_and(|capacity| bytes <= capacity)
        });
        let source_pages = checked_add(
            ordinal,
            self.source_inline_pages,
            self.source_external_pages,
        )?;
        let source_capacity = checked_add(
            ordinal,
            self.source_inline_committed_capacity_bytes,
            self.source_external_committed_capacity_bytes,
        )?;
        let classes_page_rounded = [
            self.source_inline_bytes,
            self.source_external_bytes,
            self.stable_head_bytes,
            self.pinned_inline_bytes,
            self.pinned_external_bytes,
            self.exogenous_non_heap_bytes,
        ]
        .into_iter()
        .all(|bytes| bytes % self.page_bytes == 0);
        Ok(byte_total == self.partition_total_bytes
            && page_total == self.partition_total_pages
            && self.partition_total_bytes <= page_capacity
            && class_capacities_reconcile
            && source_pages == self.source_pages
            && self.source_bytes(ordinal)? <= source_capacity
            && self.partition_total_bytes == self.unique_allocation_union_bytes
            && self.unique_resident_page_union_bytes == page_capacity
            && self.partition_total_bytes == self.unique_resident_page_union_bytes
            && self.cross_domain_overlap_bytes == 0
            && self.partial_page_shared_bytes == 0
            && classes_page_rounded
            && self.unique_union_proven)
    }
}

/// Checked identity and byte inventory for one external allocation cohort.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RotatingRolloverExternalCohort {
    /// Number of uniquely identified external allocations.
    pub(crate) allocations: u64,
    /// Logical payload bytes in those allocations.
    pub(crate) bytes: u64,
    /// Resident pages currently owned by those allocations.
    pub(crate) resident_pages: u64,
    /// Strictly increasing exact dense allocation identities.
    pub(crate) identities: Vec<u64>,
}

/// Exact ownership at one continuous interval high-water observation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RotatingRolloverWatermarkInput {
    /// Disjoint ownership at the high-water instant.
    pub(crate) ownership: RotatingRolloverOwnershipLedger,
    /// Source bytes acquired during this interval by that instant.
    pub(crate) source_acquired_at_watermark_bytes: u64,
    /// Source committed capacity acquired during this interval by that instant.
    pub(crate) source_committed_acquired_at_watermark_bytes: u64,
    /// Stable bytes acquired during this interval by that instant.
    pub(crate) stable_acquired_at_watermark_bytes: u64,
    /// Stable bytes retired during this interval by that instant.
    pub(crate) stable_retired_at_watermark_bytes: u64,
    /// Pinned bytes acquired during this interval by that instant.
    pub(crate) pinned_acquired_at_watermark_bytes: u64,
    /// Pinned bytes retired during this interval by that instant.
    pub(crate) pinned_retired_at_watermark_bytes: u64,
    /// Independently measured process high-water at the same instant.
    pub(crate) measured_process_bytes: u64,
    /// Committed source capacity at this observation.
    pub(crate) source_committed_capacity_bytes: u64,
    /// Interval sequence this observation belongs to.
    pub(crate) interval_sequence: u64,
    /// Globally monotonic observation sequence.
    pub(crate) observation_sequence: u64,
}

/// Causal domain changes and both continuous high-water observations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RotatingRolloverIntervalInput {
    /// Source bytes committed during the interval.
    pub(crate) source_committed_acquired_bytes: u64,
    /// Maximum source bytes acquired at any point during the interval.
    pub(crate) source_committed_acquisition_high_water_bytes: u64,
    /// Source resident bytes acquired by the interval endpoint.
    pub(crate) source_resident_acquired_bytes: u64,
    /// Maximum source resident bytes acquired during the interval.
    pub(crate) source_resident_acquisition_high_water_bytes: u64,
    /// Stable-head bytes acquired during the interval.
    pub(crate) stable_acquired_bytes: u64,
    /// Stable-head bytes retired during the interval.
    pub(crate) stable_retired_bytes: u64,
    /// Pinned bytes acquired during the interval.
    pub(crate) pinned_acquired_bytes: u64,
    /// Pinned bytes retired during the interval.
    pub(crate) pinned_retired_bytes: u64,
    /// Ownership at the continuous process high-water.
    pub(crate) process_high_water: RotatingRolloverWatermarkInput,
    /// Ownership at the continuous evaluator-allocator high-water.
    pub(crate) allocator_high_water: RotatingRolloverWatermarkInput,
    /// External allocations first created during this interval.
    pub(crate) external_acquired: RotatingRolloverExternalCohort,
    /// Exact zero-based interval sequence.
    pub(crate) interval_sequence: u64,
    /// First allocator/process event covered by continuous observation.
    pub(crate) coverage_start_event: u64,
    /// Exclusive last allocator/process event covered by continuous observation.
    pub(crate) coverage_end_event: u64,
    /// Whether process sampling was continuous for the complete interval.
    pub(crate) process_observation_complete: bool,
    /// Whether every allocator event was observed for the complete interval.
    pub(crate) allocator_observation_complete: bool,
    /// Whether newly acquired external identities are globally fresh.
    pub(crate) external_identity_uniqueness_proven: bool,
}

/// External payload lifecycle at one collection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RotatingRolloverExternalLifecycle {
    /// Live external source bytes copied without changing representation.
    pub(crate) copied_source_bytes: u64,
    /// Live external source bytes rebuilt into another exact representation.
    pub(crate) rebuilt_source_bytes: u64,
    /// Live external source bytes transferred to an explicit pinned owner.
    pub(crate) retained_pinned_source_bytes: u64,
    /// Dead external source bytes dropped with the old domain.
    pub(crate) dead_source_bytes: u64,
    /// Destination bytes produced by the copied lifecycle.
    pub(crate) copied_destination_bytes: u64,
    /// Destination bytes produced by the rebuilt lifecycle.
    pub(crate) rebuilt_destination_bytes: u64,
    /// Projected external cohorts entering this collection.
    pub(crate) projected_source: RotatingRolloverExternalCohort,
    /// Cohort copied without changing logical bytes or identity.
    pub(crate) copied_source: RotatingRolloverExternalCohort,
    /// Destination cohort for copied allocations.
    pub(crate) copied_destination: RotatingRolloverExternalCohort,
    /// Cohort rebuilt into another exact layout.
    pub(crate) rebuilt_source: RotatingRolloverExternalCohort,
    /// Destination cohort for rebuilt allocations.
    pub(crate) rebuilt_destination: RotatingRolloverExternalCohort,
    /// Cohort transferred to pinned ownership.
    pub(crate) retained_pinned: RotatingRolloverExternalCohort,
    /// Dead cohort dropped at this collection.
    pub(crate) dead: RotatingRolloverExternalCohort,
    /// Actual uncollected-control external cohort at this checkpoint.
    pub(crate) actual_control_source: RotatingRolloverExternalCohort,
    /// Whether lifecycle partitions have pairwise-disjoint identities.
    pub(crate) disjoint_identity_partition_proven: bool,
    /// Whether rebuilt source identities map to the stated destination layout.
    pub(crate) rebuilt_source_layout_proven: bool,
}

/// Exact persistent and temporary destination ownership.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RotatingRolloverDestinationInput {
    /// Compact immutable bytes in the new generation.
    pub(crate) compact_immutable_bytes: u64,
    /// Typed-work bytes in the new generation.
    pub(crate) typed_work_bytes: u64,
    /// Resident bytes occupied by copied external payloads in the new generation.
    pub(crate) external_copied_bytes: u64,
    /// Resident bytes occupied by rebuilt external payloads in the new generation.
    pub(crate) external_rebuilt_bytes: u64,
    /// Dense live-registry bytes in the new generation.
    pub(crate) dense_registry_bytes: u64,
    /// Survivor-only weak-index bytes in the new generation.
    pub(crate) survivor_weak_index_bytes: u64,
    /// Liveness table bytes in the new generation.
    pub(crate) liveness_bytes: u64,
    /// Allocator/page metadata and cache bytes owned by the new generation.
    pub(crate) allocator_page_metadata_cache_bytes: u64,
    /// Alias and stable-handle table bytes owned by the new generation.
    pub(crate) alias_handle_table_bytes: u64,
    /// Exact sum of all persistent same-generation fields above.
    pub(crate) same_generation_partition_bytes: u64,
    /// Temporary source-to-destination forwarding bytes.
    pub(crate) forwarding_bytes: u64,
    /// Temporary traversal and rebuild scratch bytes.
    pub(crate) scratch_bytes: u64,
    /// Temporary root-set, probe, and retained-report storage bytes.
    pub(crate) root_probe_report_bytes: u64,
    /// Temporary publication journal and writer-staging bytes.
    pub(crate) publication_journal_writer_bytes: u64,
    /// Exact sum of all temporary overlap fields above.
    pub(crate) overlap_partition_bytes: u64,
    /// Allocation rounding quantum for each independently allocated extent.
    pub(crate) allocator_quantum: u64,
    /// Committed capacity owned by the persistent destination.
    pub(crate) same_generation_committed_capacity_bytes: u64,
    /// Whether every committed destination page is resident at publication.
    pub(crate) all_committed_resident_proven: bool,
}

/// Exact accounting input captured at one root-complete checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RotatingRolloverCheckpointInput {
    /// Root-complete execution ordinal.
    pub(crate) ordinal: u64,
    /// Causal changes and continuous high-water observations since the prior checkpoint.
    pub(crate) interval: RotatingRolloverIntervalInput,
    /// Disjoint ownership at this checkpoint before projected collection.
    pub(crate) checkpoint_ownership: RotatingRolloverOwnershipLedger,
    /// External payload lifecycle for complete old-domain retirement.
    pub(crate) external_lifecycle: RotatingRolloverExternalLifecycle,
    /// Persistent destination and temporary overlap ownership.
    pub(crate) destination: RotatingRolloverDestinationInput,
    /// Complete iterable object inventory.
    pub(crate) inventory_objects: u64,
    /// Exactly classified object inventory.
    pub(crate) classified_objects: u64,
    /// Complete traversed edge inventory.
    pub(crate) inventory_edges: u64,
    /// Exactly classified edge inventory.
    pub(crate) classified_edges: u64,
    /// Observed evidence failures.
    pub(crate) blockers: RotatingRolloverBlockers,
    /// Completeness evidence required even with zero observed failures.
    pub(crate) evidence: RotatingRolloverEvidence,
}

/// Top-level paired benchmark and replay inputs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RotatingRolloverReplayInput<'a> {
    /// Peak resident bytes measured for stock C++ Nix on the paired run.
    pub(crate) paired_cpp_peak_bytes: u64,
    /// Whether to enforce the optional fixed engineering ceiling.
    pub(crate) enforce_engineering_gate: bool,
    /// All nine checkpoint inputs in exact execution order.
    pub(crate) checkpoints: &'a [RotatingRolloverCheckpointInput],
}

/// Projected local watermarks and conservation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RotatingRolloverCheckpoint {
    ordinal: u64,
    projected_process_interval_high_water_bytes: u64,
    projected_allocator_interval_high_water_bytes: u64,
    projected_pre_collection_bytes: u64,
    persistent_destination_bytes: u64,
    temporary_overlap_bytes: u64,
    collection_peak_bytes: u64,
    post_collection_bytes: u64,
    local_watermark_bytes: u64,
    actual_uncollected_source_bytes: u64,
    projected_source_bytes: u64,
    projected_stable_bytes: u64,
    projected_pinned_bytes: u64,
    projected_non_heap_bytes: u64,
    promoted_external_pinned_bytes: u64,
    ownership_reconciled: bool,
    external_lifecycle_reconciled: bool,
    interval_reconciled: bool,
    inventory_reconciled: bool,
    evidence_complete: bool,
    checkpoint_ownership: RotatingRolloverOwnershipLedger,
    external_lifecycle: RotatingRolloverExternalLifecycle,
    destination: RotatingRolloverDestinationInput,
    blockers: RotatingRolloverBlockers,
    blocker_total: u64,
    half_cpp_local_pass: bool,
    engineering_local_pass: bool,
    admitted: bool,
}

impl fmt::Display for RotatingRolloverCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{\"ordinal\":{},\"watermarks\":{{\"process_interval\":{},\
             \"allocator_interval\":{},\"pre_collection\":{},\
             \"collection_overlap\":{},\"post_collection\":{},\"local\":{}}},\
             \"domains\":{{\"actual_uncollected_source\":{},\
             \"projected_source\":{},\"projected_stable\":{},\
             \"projected_pinned\":{},\"exogenous_non_heap\":{},\
             \"persistent_destination\":{},\"temporary_overlap\":{},\
             \"promoted_external_pinned\":{}}},\
             \"reconciliation\":{{\"ownership\":{},\"external_lifecycle\":{},\
             \"interval\":{},\"inventory\":{},\"evidence_complete\":{}}},\
             \"ownership_ledger\":{{\"source_inline_bytes\":{},\
             \"source_external_bytes\":{},\"stable_head_bytes\":{},\
             \"pinned_inline_bytes\":{},\"pinned_external_bytes\":{},\
             \"exogenous_non_heap_bytes\":{},\"partition_total_bytes\":{},\
             \"page_bytes\":{},\"source_pages\":{},\"stable_head_pages\":{},\
             \"pinned_pages\":{},\"exogenous_non_heap_pages\":{},\
             \"partition_total_pages\":{}}},\
             \"external_lifecycle\":{{\"copied_source_bytes\":{},\
             \"rebuilt_source_bytes\":{},\"retained_pinned_source_bytes\":{},\
             \"dead_source_bytes\":{},\"copied_destination_bytes\":{},\
             \"rebuilt_destination_bytes\":{}}},\
             \"destination_partition\":{{\"compact_immutable_bytes\":{},\
             \"typed_work_bytes\":{},\"external_copied_bytes\":{},\
             \"external_rebuilt_bytes\":{},\"dense_registry_bytes\":{},\
             \"survivor_weak_index_bytes\":{},\"liveness_bytes\":{},\
             \"allocator_page_metadata_cache_bytes\":{},\
             \"alias_handle_table_bytes\":{},\
             \"same_generation_partition_bytes\":{},\"forwarding_bytes\":{},\
             \"scratch_bytes\":{},\"root_probe_report_bytes\":{},\
             \"publication_journal_writer_bytes\":{},\
             \"overlap_partition_bytes\":{},\"allocator_quantum\":{}}},\
             \"blockers\":{{\"missing_writable_roots\":{},\
             \"missing_writable_edges\":{},\"unclassified_objects\":{},\
             \"unclassified_edges\":{},\"stale_aliases\":{},\
             \"hash_identity\":{},\"tail_identity\":{},\"other_identity\":{},\
             \"inventory\":{},\"edge_inventory\":{},\"compact_layout\":{},\
             \"old_domain_unmap\":{},\"weak_index_rebuild\":{},\"total\":{}}},\
             \"half_cpp_local_pass\":{},\
             \"engineering_local_pass\":{},\"admitted\":{},\
             \"collection\":false,\"mutation\":false,\"purge\":false,\
             \"advice\":false,\"writer\":false}}",
            self.ordinal,
            self.projected_process_interval_high_water_bytes,
            self.projected_allocator_interval_high_water_bytes,
            self.projected_pre_collection_bytes,
            self.collection_peak_bytes,
            self.post_collection_bytes,
            self.local_watermark_bytes,
            self.actual_uncollected_source_bytes,
            self.projected_source_bytes,
            self.projected_stable_bytes,
            self.projected_pinned_bytes,
            self.projected_non_heap_bytes,
            self.persistent_destination_bytes,
            self.temporary_overlap_bytes,
            self.promoted_external_pinned_bytes,
            self.ownership_reconciled,
            self.external_lifecycle_reconciled,
            self.interval_reconciled,
            self.inventory_reconciled,
            self.evidence_complete,
            self.checkpoint_ownership.source_inline_bytes,
            self.checkpoint_ownership.source_external_bytes,
            self.checkpoint_ownership.stable_head_bytes,
            self.checkpoint_ownership.pinned_inline_bytes,
            self.checkpoint_ownership.pinned_external_bytes,
            self.checkpoint_ownership.exogenous_non_heap_bytes,
            self.checkpoint_ownership.partition_total_bytes,
            self.checkpoint_ownership.page_bytes,
            self.checkpoint_ownership.source_pages,
            self.checkpoint_ownership.stable_head_pages,
            self.checkpoint_ownership.pinned_pages,
            self.checkpoint_ownership.exogenous_non_heap_pages,
            self.checkpoint_ownership.partition_total_pages,
            self.external_lifecycle.copied_source_bytes,
            self.external_lifecycle.rebuilt_source_bytes,
            self.external_lifecycle.retained_pinned_source_bytes,
            self.external_lifecycle.dead_source_bytes,
            self.external_lifecycle.copied_destination_bytes,
            self.external_lifecycle.rebuilt_destination_bytes,
            self.destination.compact_immutable_bytes,
            self.destination.typed_work_bytes,
            self.destination.external_copied_bytes,
            self.destination.external_rebuilt_bytes,
            self.destination.dense_registry_bytes,
            self.destination.survivor_weak_index_bytes,
            self.destination.liveness_bytes,
            self.destination.allocator_page_metadata_cache_bytes,
            self.destination.alias_handle_table_bytes,
            self.destination.same_generation_partition_bytes,
            self.destination.forwarding_bytes,
            self.destination.scratch_bytes,
            self.destination.root_probe_report_bytes,
            self.destination.publication_journal_writer_bytes,
            self.destination.overlap_partition_bytes,
            self.destination.allocator_quantum,
            self.blockers.missing_writable_roots,
            self.blockers.missing_writable_edges,
            self.blockers.unclassified_objects,
            self.blockers.unclassified_edges,
            self.blockers.stale_aliases,
            self.blockers.hash_identity_blockers,
            self.blockers.tail_identity_blockers,
            self.blockers.identity_blockers,
            self.blockers.inventory_blockers,
            self.blockers.edge_inventory_blockers,
            self.blockers.compact_layout_blockers,
            self.blockers.old_domain_unmap_blockers,
            self.blockers.weak_index_rebuild_blockers,
            self.blocker_total,
            self.half_cpp_local_pass,
            self.engineering_local_pass,
            self.admitted,
        )
    }
}

/// Complete causal replay report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RotatingRolloverProjection {
    checkpoints: Vec<RotatingRolloverCheckpoint>,
    paired_cpp_peak_bytes: u64,
    strict_half_cpp_ceiling_bytes: u64,
    peak_replay_watermark_bytes: u64,
    savings_against_cpp_bytes: i128,
    engineering_gate_enforced: bool,
    strict_half_cpp_pass: bool,
    engineering_gate_pass: bool,
    total_blockers: u64,
    admitted: bool,
}

impl RotatingRolloverProjection {
    /// Returns checkpoint reports in execution order.
    pub(crate) fn checkpoints(&self) -> &[RotatingRolloverCheckpoint] {
        &self.checkpoints
    }

    /// Returns whether every local proof and both enabled global gates pass.
    pub(crate) const fn admitted(&self) -> bool {
        self.admitted
    }
}

impl fmt::Display for RotatingRolloverProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{\"mode\":\"causal_rotating_whole_domain_replay\",\
             \"independent_snapshot_subtraction\":false,\"checkpoints\":["
        )?;
        for (index, checkpoint) in self.checkpoints.iter().enumerate() {
            if index != 0 {
                f.write_str(",")?;
            }
            write!(f, "{checkpoint}")?;
        }
        write!(
            f,
            "],\"paired_cpp_peak_bytes\":{},\"strict_half_cpp_ceiling_bytes\":{},\
             \"peak_replay_watermark_bytes\":{},\"savings_against_cpp_bytes\":{},\
             \"strict_half_cpp_pass\":{},\"engineering_gate_enforced\":{},\
             \"engineering_gate_bytes\":{},\"engineering_gate_pass\":{},\
             \"total_blockers\":{},\"admitted\":{},\"collection\":false,\
             \"mutation\":false,\"purge\":false,\"advice\":false,\"writer\":false}}",
            self.paired_cpp_peak_bytes,
            self.strict_half_cpp_ceiling_bytes,
            self.peak_replay_watermark_bytes,
            self.savings_against_cpp_bytes,
            self.strict_half_cpp_pass,
            self.engineering_gate_enforced,
            ROTATING_ROLLOVER_ENGINEERING_GATE_BYTES,
            self.engineering_gate_pass,
            self.total_blockers,
            self.admitted,
        )
    }
}

/// Arithmetic or sequence error in a rollover projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RotatingRolloverProjectionError {
    /// The required checkpoint sequence is incomplete or unordered.
    CheckpointSequence,
    /// The paired C++ peak is zero.
    ZeroCppPeak,
    /// An allocator quantum was zero.
    ZeroAllocatorQuantum { ordinal: u64 },
    /// Checked byte arithmetic overflowed.
    ByteOverflow { ordinal: u64, table: &'static str },
    /// A causal retirement exceeded the owned domain.
    DomainUnderflow { ordinal: u64, domain: &'static str },
    /// Exact external cohort identities overlapped or were malformed.
    CohortIdentityOverlap { ordinal: u64 },
}

impl fmt::Display for RotatingRolloverProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CheckpointSequence => f.write_str("rollover checkpoint sequence is invalid"),
            Self::ZeroCppPeak => f.write_str("paired C++ peak is zero"),
            Self::ZeroAllocatorQuantum { ordinal } => {
                write!(f, "checkpoint {ordinal} has a zero allocator quantum")
            }
            Self::ByteOverflow { ordinal, table } => {
                write!(f, "checkpoint {ordinal} overflowed {table}")
            }
            Self::DomainUnderflow { ordinal, domain } => {
                write!(f, "checkpoint {ordinal} retires beyond the {domain} domain")
            }
            Self::CohortIdentityOverlap { ordinal } => {
                write!(
                    f,
                    "checkpoint {ordinal} has overlapping external cohort identities"
                )
            }
        }
    }
}

impl std::error::Error for RotatingRolloverProjectionError {}

/// Replays whole-domain rollover from exact interval and ownership evidence.
///
/// # Errors
///
/// Returns [`RotatingRolloverProjectionError`] for an invalid sequence, zero
/// paired C++ peak or allocator quantum, arithmetic overflow, or causal domain
/// underflow. Evidence and conservation mismatches remain visible in a
/// non-admitted report.
pub(crate) fn project_rotating_rollover(
    replay: RotatingRolloverReplayInput<'_>,
) -> Result<RotatingRolloverProjection, RotatingRolloverProjectionError> {
    if replay.paired_cpp_peak_bytes == 0 {
        return Err(RotatingRolloverProjectionError::ZeroCppPeak);
    }
    if replay.checkpoints.len() != ROTATING_ROLLOVER_ORDINALS.len()
        || replay
            .checkpoints
            .iter()
            .zip(ROTATING_ROLLOVER_ORDINALS)
            .any(|(input, ordinal)| input.ordinal != ordinal)
    {
        return Err(RotatingRolloverProjectionError::CheckpointSequence);
    }

    let strict_half_ceiling = replay.paired_cpp_peak_bytes.div_ceil(2);
    let mut reports = Vec::new();
    reports
        .try_reserve_exact(replay.checkpoints.len())
        .map_err(|_| RotatingRolloverProjectionError::ByteOverflow {
            ordinal: ROTATING_ROLLOVER_ORDINALS[0],
            table: TABLE,
        })?;

    let mut actual_source_resident = 0u64;
    let mut actual_source_committed = 0u64;
    let mut actual_stable = 0u64;
    let mut actual_pinned = 0u64;
    let mut projected_source_resident_base = 0u64;
    let mut projected_source_committed_base = 0u64;
    let mut projected_stable = 0u64;
    let mut projected_pinned = 0u64;
    let mut peak = 0u64;
    let mut total_blockers = 0u64;
    let mut all_local_admitted = true;
    let mut actual_external = RotatingRolloverExternalCohort::default();
    let mut projected_external = RotatingRolloverExternalCohort::default();
    let mut previous_coverage_end = 0u64;

    for (interval_index, input) in replay.checkpoints.iter().cloned().enumerate() {
        let ordinal = input.ordinal;
        if input.destination.allocator_quantum == 0 {
            return Err(RotatingRolloverProjectionError::ZeroAllocatorQuantum { ordinal });
        }

        let actual_source_resident_base = actual_source_resident;
        let actual_source_committed_base = actual_source_committed;
        let actual_stable_base = actual_stable;
        let actual_pinned_base = actual_pinned;
        let projected_stable_base = projected_stable;
        let projected_pinned_base = projected_pinned;
        actual_source_committed = checked_add(
            ordinal,
            actual_source_committed,
            input.interval.source_committed_acquired_bytes,
        )?;
        actual_source_resident = checked_add(
            ordinal,
            actual_source_resident,
            input.interval.source_resident_acquired_bytes,
        )?;
        actual_stable = apply_domain_delta(
            ordinal,
            actual_stable,
            input.interval.stable_acquired_bytes,
            input.interval.stable_retired_bytes,
            "stable",
        )?;
        actual_pinned = apply_domain_delta(
            ordinal,
            actual_pinned,
            input.interval.pinned_acquired_bytes,
            input.interval.pinned_retired_bytes,
            "pinned",
        )?;
        projected_stable = apply_domain_delta(
            ordinal,
            projected_stable,
            input.interval.stable_acquired_bytes,
            input.interval.stable_retired_bytes,
            "projected stable",
        )?;
        projected_pinned = apply_domain_delta(
            ordinal,
            projected_pinned,
            input.interval.pinned_acquired_bytes,
            input.interval.pinned_retired_bytes,
            "projected pinned",
        )?;
        let projected_source_resident = checked_add(
            ordinal,
            projected_source_resident_base,
            input.interval.source_resident_acquired_bytes,
        )?;
        let projected_source_committed = checked_add(
            ordinal,
            projected_source_committed_base,
            input.interval.source_committed_acquired_bytes,
        )?;
        actual_external =
            cohort_merge_strict(ordinal, &actual_external, &input.interval.external_acquired)?;
        let projected_external_source = cohort_merge_strict(
            ordinal,
            &projected_external,
            &input.interval.external_acquired,
        )?;

        let ledger = input.checkpoint_ownership;
        let ownership_reconciled = ledger.reconciled(ordinal)?
            && ledger.source_bytes(ordinal)? == actual_source_resident
            && ledger.source_committed_capacity(ordinal)? == actual_source_committed
            && projected_source_resident <= projected_source_committed
            && ledger.stable_head_bytes == actual_stable
            && ledger.pinned_bytes(ordinal)? == actual_pinned;
        let interval_reconciled = interval_reconciled(
            ordinal,
            &input.interval,
            interval_index as u64,
            previous_coverage_end,
            actual_source_resident_base,
            actual_source_committed_base,
            actual_stable_base,
            actual_pinned_base,
        )?;
        let external_lifecycle_reconciled = external_lifecycle_reconciled(
            ordinal,
            ledger,
            &input.external_lifecycle,
            input.destination,
            &actual_external,
            &projected_external_source,
        )?;
        let inventory_reconciled = input.inventory_objects == input.classified_objects
            && input.inventory_edges == input.classified_edges;
        let destination_reconciled = destination_reconciled(ordinal, input.destination)?;

        let persistent_destination = destination_persistent_bytes(ordinal, input.destination)?;
        let temporary_overlap = destination_overlap_bytes(ordinal, input.destination)?;
        let non_heap = ledger.exogenous_non_heap_bytes;
        let projected_pre_collection = checked_sum(
            ordinal,
            &[
                non_heap,
                projected_stable,
                projected_pinned,
                projected_source_resident,
            ],
        )?;
        let collection_peak = checked_sum(
            ordinal,
            &[
                projected_pre_collection,
                persistent_destination,
                temporary_overlap,
            ],
        )?;
        let promoted_pinned = checked_mul(
            ordinal,
            input.external_lifecycle.retained_pinned.resident_pages,
            ledger.page_bytes,
        )?;
        let post_pinned = checked_add(ordinal, projected_pinned, promoted_pinned)?;
        let post_collection = checked_sum(
            ordinal,
            &[
                non_heap,
                projected_stable,
                post_pinned,
                persistent_destination,
            ],
        )?;

        let process_interval = project_interval_watermark(
            ordinal,
            input.interval.process_high_water,
            projected_source_resident_base,
            projected_stable_base,
            projected_pinned_base,
        )?;
        let allocator_interval = project_interval_watermark(
            ordinal,
            input.interval.allocator_high_water,
            projected_source_resident_base,
            projected_stable_base,
            projected_pinned_base,
        )?;

        let local_watermark = process_interval
            .max(allocator_interval)
            .max(collection_peak)
            .max(post_collection);
        let half_cpp_local_pass = local_watermark < strict_half_ceiling;
        let engineering_local_pass = !replay.enforce_engineering_gate
            || local_watermark <= ROTATING_ROLLOVER_ENGINEERING_GATE_BYTES;

        let mut blockers = input.blockers;
        apply_evidence_blockers(ordinal, &mut blockers, input.evidence)?;
        if !ownership_reconciled
            || !external_lifecycle_reconciled
            || !interval_reconciled
            || !destination_reconciled
        {
            increment(ordinal, &mut blockers.inventory_blockers)?;
        }
        if !inventory_reconciled {
            increment(ordinal, &mut blockers.inventory_blockers)?;
            if input.inventory_edges != input.classified_edges {
                increment(ordinal, &mut blockers.edge_inventory_blockers)?;
            }
        }
        if input.destination.liveness_bytes != DEFAULT_LIVENESS_BYTES {
            increment(ordinal, &mut blockers.compact_layout_blockers)?;
        }
        let blocker_total = blockers.checked_total(ordinal)?;
        let evidence_complete = input.evidence.complete();
        let admitted = blocker_total == 0
            && ownership_reconciled
            && external_lifecycle_reconciled
            && interval_reconciled
            && inventory_reconciled
            && destination_reconciled
            && evidence_complete
            && half_cpp_local_pass
            && engineering_local_pass;
        all_local_admitted &= admitted;
        total_blockers = checked_add(ordinal, total_blockers, blocker_total)?;
        peak = peak.max(local_watermark);
        reports.push(RotatingRolloverCheckpoint {
            ordinal,
            projected_process_interval_high_water_bytes: process_interval,
            projected_allocator_interval_high_water_bytes: allocator_interval,
            projected_pre_collection_bytes: projected_pre_collection,
            persistent_destination_bytes: persistent_destination,
            temporary_overlap_bytes: temporary_overlap,
            collection_peak_bytes: collection_peak,
            post_collection_bytes: post_collection,
            local_watermark_bytes: local_watermark,
            actual_uncollected_source_bytes: actual_source_resident,
            projected_source_bytes: projected_source_resident,
            projected_stable_bytes: projected_stable,
            projected_pinned_bytes: projected_pinned,
            projected_non_heap_bytes: non_heap,
            promoted_external_pinned_bytes: promoted_pinned,
            ownership_reconciled,
            external_lifecycle_reconciled,
            interval_reconciled,
            inventory_reconciled,
            evidence_complete,
            checkpoint_ownership: ledger,
            external_lifecycle: input.external_lifecycle.clone(),
            destination: input.destination,
            blockers,
            blocker_total,
            half_cpp_local_pass,
            engineering_local_pass,
            admitted,
        });
        projected_source_resident_base = persistent_destination;
        projected_source_committed_base =
            input.destination.same_generation_committed_capacity_bytes;
        projected_external = cohort_merge_strict(
            ordinal,
            &input.external_lifecycle.copied_destination,
            &input.external_lifecycle.rebuilt_destination,
        )?;
        projected_pinned = post_pinned;
        previous_coverage_end = input.interval.coverage_end_event;
        let _ = projected_source_committed;
    }

    let strict_half_cpp_pass = peak < strict_half_ceiling;
    let engineering_gate_pass =
        !replay.enforce_engineering_gate || peak <= ROTATING_ROLLOVER_ENGINEERING_GATE_BYTES;
    let admitted =
        all_local_admitted && total_blockers == 0 && strict_half_cpp_pass && engineering_gate_pass;
    Ok(RotatingRolloverProjection {
        checkpoints: reports,
        paired_cpp_peak_bytes: replay.paired_cpp_peak_bytes,
        strict_half_cpp_ceiling_bytes: strict_half_ceiling,
        peak_replay_watermark_bytes: peak,
        savings_against_cpp_bytes: i128::from(replay.paired_cpp_peak_bytes) - i128::from(peak),
        engineering_gate_enforced: replay.enforce_engineering_gate,
        strict_half_cpp_pass,
        engineering_gate_pass,
        total_blockers,
        admitted,
    })
}

fn apply_domain_delta(
    ordinal: u64,
    current: u64,
    acquired: u64,
    retired: u64,
    domain: &'static str,
) -> Result<u64, RotatingRolloverProjectionError> {
    checked_add(ordinal, current, acquired)?
        .checked_sub(retired)
        .ok_or(RotatingRolloverProjectionError::DomainUnderflow { ordinal, domain })
}

fn interval_reconciled(
    ordinal: u64,
    interval: &RotatingRolloverIntervalInput,
    expected_interval_sequence: u64,
    previous_coverage_end: u64,
    actual_source_resident_base: u64,
    actual_source_committed_base: u64,
    actual_stable_base: u64,
    actual_pinned_base: u64,
) -> Result<bool, RotatingRolloverProjectionError> {
    if interval.source_committed_acquisition_high_water_bytes
        < interval.source_committed_acquired_bytes
        || interval.source_resident_acquisition_high_water_bytes
            < interval.source_resident_acquired_bytes
        || interval
            .allocator_high_water
            .source_committed_acquired_at_watermark_bytes
            != interval.source_committed_acquisition_high_water_bytes
        || interval
            .process_high_water
            .source_acquired_at_watermark_bytes
            > interval.source_resident_acquisition_high_water_bytes
        || interval
            .allocator_high_water
            .source_acquired_at_watermark_bytes
            != interval.source_resident_acquisition_high_water_bytes
        || interval.interval_sequence != expected_interval_sequence
        || interval.coverage_start_event != previous_coverage_end
        || interval.coverage_end_event <= interval.coverage_start_event
        || !interval.process_observation_complete
        || !interval.allocator_observation_complete
        || !interval.external_identity_uniqueness_proven
        || interval.process_high_water.interval_sequence != expected_interval_sequence
        || interval.allocator_high_water.interval_sequence != expected_interval_sequence
        || interval.process_high_water.observation_sequence
            == interval.allocator_high_water.observation_sequence
        || interval.process_high_water.observation_sequence < interval.coverage_start_event
        || interval.process_high_water.observation_sequence >= interval.coverage_end_event
        || interval.allocator_high_water.observation_sequence < interval.coverage_start_event
        || interval.allocator_high_water.observation_sequence >= interval.coverage_end_event
    {
        return Ok(false);
    }
    for watermark in [interval.process_high_water, interval.allocator_high_water] {
        if watermark.source_acquired_at_watermark_bytes
            > interval.source_resident_acquisition_high_water_bytes
            || watermark.source_committed_acquired_at_watermark_bytes
                > interval.source_committed_acquisition_high_water_bytes
            || watermark.stable_acquired_at_watermark_bytes > interval.stable_acquired_bytes
            || watermark.stable_retired_at_watermark_bytes > interval.stable_retired_bytes
            || watermark.pinned_acquired_at_watermark_bytes > interval.pinned_acquired_bytes
            || watermark.pinned_retired_at_watermark_bytes > interval.pinned_retired_bytes
        {
            return Ok(false);
        }
        let ownership = watermark.ownership;
        if !ownership.reconciled(ordinal)?
            || ownership.unique_resident_page_union_bytes != watermark.measured_process_bytes
            || ownership.source_bytes(ordinal)?
                != checked_add(
                    ordinal,
                    actual_source_resident_base,
                    watermark.source_acquired_at_watermark_bytes,
                )?
            || ownership.source_committed_capacity(ordinal)?
                != checked_add(
                    ordinal,
                    actual_source_committed_base,
                    watermark.source_committed_acquired_at_watermark_bytes,
                )?
            || ownership.source_committed_capacity(ordinal)?
                != watermark.source_committed_capacity_bytes
        {
            return Ok(false);
        }
        if ownership.stable_head_bytes
            != apply_domain_delta(
                ordinal,
                actual_stable_base,
                watermark.stable_acquired_at_watermark_bytes,
                watermark.stable_retired_at_watermark_bytes,
                "stable watermark",
            )?
            || ownership.pinned_bytes(ordinal)?
                != apply_domain_delta(
                    ordinal,
                    actual_pinned_base,
                    watermark.pinned_acquired_at_watermark_bytes,
                    watermark.pinned_retired_at_watermark_bytes,
                    "pinned watermark",
                )?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn project_interval_watermark(
    ordinal: u64,
    watermark: RotatingRolloverWatermarkInput,
    projected_source_base: u64,
    projected_stable_base: u64,
    projected_pinned_base: u64,
) -> Result<u64, RotatingRolloverProjectionError> {
    let ownership = watermark.ownership;
    let projected_stable_at_watermark = apply_domain_delta(
        ordinal,
        projected_stable_base,
        watermark.stable_acquired_at_watermark_bytes,
        watermark.stable_retired_at_watermark_bytes,
        "projected stable watermark",
    )?;
    let projected_pinned_at_watermark = apply_domain_delta(
        ordinal,
        projected_pinned_base,
        watermark.pinned_acquired_at_watermark_bytes,
        watermark.pinned_retired_at_watermark_bytes,
        "projected pinned watermark",
    )?;
    let projected_source_at_watermark = checked_add(
        ordinal,
        projected_source_base,
        watermark.source_acquired_at_watermark_bytes,
    )?;
    checked_sum(
        ordinal,
        &[
            ownership.exogenous_non_heap_bytes,
            projected_stable_at_watermark,
            projected_pinned_at_watermark,
            projected_source_at_watermark,
        ],
    )
}

fn external_lifecycle_reconciled(
    ordinal: u64,
    ownership: RotatingRolloverOwnershipLedger,
    lifecycle: &RotatingRolloverExternalLifecycle,
    destination: RotatingRolloverDestinationInput,
    expected_actual_control: &RotatingRolloverExternalCohort,
    expected_projected_source: &RotatingRolloverExternalCohort,
) -> Result<bool, RotatingRolloverProjectionError> {
    let Some(copied_and_rebuilt) =
        cohort_merge(ordinal, &lifecycle.copied_source, &lifecycle.rebuilt_source)?
    else {
        return Ok(false);
    };
    let Some(retained_and_dead) =
        cohort_merge(ordinal, &lifecycle.retained_pinned, &lifecycle.dead)?
    else {
        return Ok(false);
    };
    let Some(partition) = cohort_merge(ordinal, &copied_and_rebuilt, &retained_and_dead)? else {
        return Ok(false);
    };
    let actual_external_resident = checked_mul(
        ordinal,
        expected_actual_control.resident_pages,
        ownership.page_bytes,
    )?;
    let copied_destination_resident = checked_mul(
        ordinal,
        lifecycle.copied_destination.resident_pages,
        ownership.page_bytes,
    )?;
    let rebuilt_destination_resident = checked_mul(
        ordinal,
        lifecycle.rebuilt_destination.resident_pages,
        ownership.page_bytes,
    )?;
    Ok(&lifecycle.actual_control_source == expected_actual_control
        && &lifecycle.projected_source == expected_projected_source
        && ownership.source_external_bytes == actual_external_resident
        && ownership.source_external_pages == expected_actual_control.resident_pages
        && &partition == expected_projected_source
        && cohort_valid(&lifecycle.actual_control_source)
        && cohort_valid(&lifecycle.projected_source)
        && lifecycle.disjoint_identity_partition_proven
        && lifecycle.copied_source == lifecycle.copied_destination
        && lifecycle.copied_source_bytes == lifecycle.copied_source.bytes
        && lifecycle.copied_destination_bytes == lifecycle.copied_destination.bytes
        && lifecycle.copied_source_bytes == lifecycle.copied_destination_bytes
        && lifecycle.rebuilt_source_bytes == lifecycle.rebuilt_source.bytes
        && lifecycle.rebuilt_destination_bytes == lifecycle.rebuilt_destination.bytes
        && lifecycle.retained_pinned_source_bytes == lifecycle.retained_pinned.bytes
        && lifecycle.dead_source_bytes == lifecycle.dead.bytes
        && cohort_same_identity(&lifecycle.rebuilt_source, &lifecycle.rebuilt_destination)
        && lifecycle.rebuilt_source_layout_proven
        && copied_destination_resident == destination.external_copied_bytes
        && rebuilt_destination_resident == destination.external_rebuilt_bytes)
}

fn destination_reconciled(
    ordinal: u64,
    destination: RotatingRolloverDestinationInput,
) -> Result<bool, RotatingRolloverProjectionError> {
    let persistent = checked_sum(
        ordinal,
        &[
            destination.compact_immutable_bytes,
            destination.typed_work_bytes,
            destination.external_copied_bytes,
            destination.external_rebuilt_bytes,
            destination.dense_registry_bytes,
            destination.survivor_weak_index_bytes,
            destination.liveness_bytes,
            destination.allocator_page_metadata_cache_bytes,
            destination.alias_handle_table_bytes,
        ],
    )?;
    let overlap = checked_sum(
        ordinal,
        &[
            destination.forwarding_bytes,
            destination.scratch_bytes,
            destination.root_probe_report_bytes,
            destination.publication_journal_writer_bytes,
        ],
    )?;
    let rounded_persistent = destination_persistent_bytes(ordinal, destination)?;
    Ok(persistent == destination.same_generation_partition_bytes
        && overlap == destination.overlap_partition_bytes
        && rounded_persistent == destination.same_generation_committed_capacity_bytes
        && destination.all_committed_resident_proven)
}

fn cohort_merge(
    ordinal: u64,
    left: &RotatingRolloverExternalCohort,
    right: &RotatingRolloverExternalCohort,
) -> Result<Option<RotatingRolloverExternalCohort>, RotatingRolloverProjectionError> {
    if !cohort_valid(left) || !cohort_valid(right) {
        return Ok(None);
    }
    let reserve = left
        .identities
        .len()
        .checked_add(right.identities.len())
        .ok_or(RotatingRolloverProjectionError::ByteOverflow {
            ordinal,
            table: TABLE,
        })?;
    let mut identities = Vec::new();
    identities.try_reserve_exact(reserve).map_err(|_| {
        RotatingRolloverProjectionError::ByteOverflow {
            ordinal,
            table: TABLE,
        }
    })?;
    let (mut left_index, mut right_index) = (0usize, 0usize);
    while left_index < left.identities.len() || right_index < right.identities.len() {
        match (
            left.identities.get(left_index),
            right.identities.get(right_index),
        ) {
            (Some(left_id), Some(right_id)) if left_id < right_id => {
                identities.push(*left_id);
                left_index += 1;
            }
            (Some(left_id), Some(right_id)) if right_id < left_id => {
                identities.push(*right_id);
                right_index += 1;
            }
            (Some(_), Some(_)) => return Ok(None),
            (Some(left_id), None) => {
                identities.push(*left_id);
                left_index += 1;
            }
            (None, Some(right_id)) => {
                identities.push(*right_id);
                right_index += 1;
            }
            (None, None) => break,
        }
    }
    Ok(Some(RotatingRolloverExternalCohort {
        allocations: checked_add(ordinal, left.allocations, right.allocations)?,
        bytes: checked_add(ordinal, left.bytes, right.bytes)?,
        resident_pages: checked_add(ordinal, left.resident_pages, right.resident_pages)?,
        identities,
    }))
}

fn cohort_merge_strict(
    ordinal: u64,
    left: &RotatingRolloverExternalCohort,
    right: &RotatingRolloverExternalCohort,
) -> Result<RotatingRolloverExternalCohort, RotatingRolloverProjectionError> {
    cohort_merge(ordinal, left, right)?
        .ok_or(RotatingRolloverProjectionError::CohortIdentityOverlap { ordinal })
}

fn cohort_valid(cohort: &RotatingRolloverExternalCohort) -> bool {
    usize::try_from(cohort.allocations).ok() == Some(cohort.identities.len())
        && cohort.identities.windows(2).all(|pair| pair[0] < pair[1])
}

fn cohort_same_identity(
    left: &RotatingRolloverExternalCohort,
    right: &RotatingRolloverExternalCohort,
) -> bool {
    left.allocations == right.allocations && left.identities == right.identities
}

fn destination_persistent_bytes(
    ordinal: u64,
    destination: RotatingRolloverDestinationInput,
) -> Result<u64, RotatingRolloverProjectionError> {
    let quantum = destination.allocator_quantum;
    checked_sum(
        ordinal,
        &[
            round_extent(ordinal, destination.compact_immutable_bytes, quantum)?,
            round_extent(ordinal, destination.typed_work_bytes, quantum)?,
            round_extent(ordinal, destination.external_copied_bytes, quantum)?,
            round_extent(ordinal, destination.external_rebuilt_bytes, quantum)?,
            round_extent(ordinal, destination.dense_registry_bytes, quantum)?,
            round_extent(ordinal, destination.survivor_weak_index_bytes, quantum)?,
            round_extent(ordinal, destination.liveness_bytes, quantum)?,
            round_extent(
                ordinal,
                destination.allocator_page_metadata_cache_bytes,
                quantum,
            )?,
            round_extent(ordinal, destination.alias_handle_table_bytes, quantum)?,
        ],
    )
}

fn destination_overlap_bytes(
    ordinal: u64,
    destination: RotatingRolloverDestinationInput,
) -> Result<u64, RotatingRolloverProjectionError> {
    let quantum = destination.allocator_quantum;
    checked_sum(
        ordinal,
        &[
            round_extent(ordinal, destination.forwarding_bytes, quantum)?,
            round_extent(ordinal, destination.scratch_bytes, quantum)?,
            round_extent(ordinal, destination.root_probe_report_bytes, quantum)?,
            round_extent(
                ordinal,
                destination.publication_journal_writer_bytes,
                quantum,
            )?,
        ],
    )
}

fn apply_evidence_blockers(
    ordinal: u64,
    blockers: &mut RotatingRolloverBlockers,
    evidence: RotatingRolloverEvidence,
) -> Result<(), RotatingRolloverProjectionError> {
    if !evidence.writable_root_provenance_complete {
        increment(ordinal, &mut blockers.missing_writable_roots)?;
    }
    if !evidence.writable_edge_provenance_complete {
        increment(ordinal, &mut blockers.missing_writable_edges)?;
    }
    if !evidence.semantic_alias_audit_complete {
        increment(ordinal, &mut blockers.stale_aliases)?;
    }
    if !evidence.identity_audit_complete {
        increment(ordinal, &mut blockers.identity_blockers)?;
    }
    if !evidence.inventory_complete {
        increment(ordinal, &mut blockers.inventory_blockers)?;
    }
    if !evidence.compact_layout_exact {
        increment(ordinal, &mut blockers.compact_layout_blockers)?;
    }
    if !evidence.complete_old_inline_domain_unmap_proven {
        increment(ordinal, &mut blockers.old_domain_unmap_blockers)?;
    }
    if !evidence.survivor_weak_index_rebuild_exact {
        increment(ordinal, &mut blockers.weak_index_rebuild_blockers)?;
    }
    Ok(())
}

fn increment(ordinal: u64, value: &mut u64) -> Result<(), RotatingRolloverProjectionError> {
    *value = checked_add(ordinal, *value, 1)?;
    Ok(())
}

fn round_extent(
    ordinal: u64,
    bytes: u64,
    quantum: u64,
) -> Result<u64, RotatingRolloverProjectionError> {
    if bytes == 0 {
        return Ok(0);
    }
    let rounded = bytes
        .checked_add(
            quantum
                .checked_sub(1)
                .ok_or(RotatingRolloverProjectionError::ZeroAllocatorQuantum { ordinal })?,
        )
        .ok_or(RotatingRolloverProjectionError::ByteOverflow {
            ordinal,
            table: TABLE,
        })?;
    Ok(rounded / quantum * quantum)
}

fn checked_add(
    ordinal: u64,
    left: u64,
    right: u64,
) -> Result<u64, RotatingRolloverProjectionError> {
    left.checked_add(right)
        .ok_or(RotatingRolloverProjectionError::ByteOverflow {
            ordinal,
            table: TABLE,
        })
}

fn checked_mul(
    ordinal: u64,
    left: u64,
    right: u64,
) -> Result<u64, RotatingRolloverProjectionError> {
    left.checked_mul(right)
        .ok_or(RotatingRolloverProjectionError::ByteOverflow {
            ordinal,
            table: TABLE,
        })
}

fn checked_sum(ordinal: u64, values: &[u64]) -> Result<u64, RotatingRolloverProjectionError> {
    values
        .iter()
        .try_fold(0u64, |total, value| checked_add(ordinal, total, *value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> RotatingRolloverEvidence {
        RotatingRolloverEvidence {
            writable_root_provenance_complete: true,
            writable_edge_provenance_complete: true,
            semantic_alias_audit_complete: true,
            identity_audit_complete: true,
            inventory_complete: true,
            compact_layout_exact: true,
            complete_old_inline_domain_unmap_proven: true,
            survivor_weak_index_rebuild_exact: true,
        }
    }

    fn ledger(
        source: u64,
        stable: u64,
        pinned: u64,
        non_heap: u64,
    ) -> RotatingRolloverOwnershipLedger {
        RotatingRolloverOwnershipLedger {
            source_inline_bytes: source,
            source_external_bytes: 0,
            stable_head_bytes: stable,
            pinned_inline_bytes: pinned,
            pinned_external_bytes: 0,
            exogenous_non_heap_bytes: non_heap,
            partition_total_bytes: source + stable + pinned + non_heap,
            page_bytes: 4096,
            source_pages: source.div_ceil(4096),
            stable_head_pages: stable.div_ceil(4096),
            pinned_pages: pinned.div_ceil(4096),
            exogenous_non_heap_pages: non_heap.div_ceil(4096),
            partition_total_pages: source.div_ceil(4096)
                + stable.div_ceil(4096)
                + pinned.div_ceil(4096)
                + non_heap.div_ceil(4096),
            source_inline_committed_capacity_bytes: source,
            source_external_committed_capacity_bytes: 0,
            unique_allocation_union_bytes: source + stable + pinned + non_heap,
            unique_resident_page_union_bytes: source + stable + pinned + non_heap,
            cross_domain_overlap_bytes: 0,
            partial_page_shared_bytes: 0,
            source_inline_pages: source.div_ceil(4096),
            source_external_pages: 0,
            unique_union_proven: true,
        }
    }

    fn watermark(
        source: u64,
        stable: u64,
        pinned: u64,
        non_heap: u64,
        acquired: u64,
    ) -> RotatingRolloverWatermarkInput {
        RotatingRolloverWatermarkInput {
            ownership: ledger(source, stable, pinned, non_heap),
            source_acquired_at_watermark_bytes: acquired,
            source_committed_acquired_at_watermark_bytes: acquired,
            stable_acquired_at_watermark_bytes: 0,
            stable_retired_at_watermark_bytes: 0,
            pinned_acquired_at_watermark_bytes: 0,
            pinned_retired_at_watermark_bytes: 0,
            measured_process_bytes: source + stable + pinned + non_heap,
            source_committed_capacity_bytes: source,
            interval_sequence: 0,
            observation_sequence: 0,
        }
    }

    fn destination() -> RotatingRolloverDestinationInput {
        RotatingRolloverDestinationInput {
            compact_immutable_bytes: 8 * 1024 * 1024,
            typed_work_bytes: 2 * 1024 * 1024,
            external_copied_bytes: 0,
            external_rebuilt_bytes: 0,
            dense_registry_bytes: 1024 * 1024,
            survivor_weak_index_bytes: 1024 * 1024,
            liveness_bytes: DEFAULT_LIVENESS_BYTES,
            allocator_page_metadata_cache_bytes: 1024 * 1024,
            alias_handle_table_bytes: 1024 * 1024,
            same_generation_partition_bytes: 16 * 1024 * 1024,
            forwarding_bytes: 1024 * 1024,
            scratch_bytes: 1024 * 1024,
            root_probe_report_bytes: 1024 * 1024,
            publication_journal_writer_bytes: 1024 * 1024,
            overlap_partition_bytes: 4 * 1024 * 1024,
            allocator_quantum: 4096,
            same_generation_committed_capacity_bytes: 16 * 1024 * 1024,
            all_committed_resident_proven: true,
        }
    }

    fn cohort(identity: u64, bytes: u64) -> RotatingRolloverExternalCohort {
        RotatingRolloverExternalCohort {
            allocations: 1,
            bytes,
            resident_pages: 1,
            identities: vec![identity],
        }
    }

    fn external_ownership(
        cohort: RotatingRolloverExternalCohort,
    ) -> RotatingRolloverOwnershipLedger {
        let mut ownership = ledger(cohort.bytes, 0, 0, 0);
        ownership.source_inline_bytes = 0;
        ownership.source_external_bytes = cohort.resident_pages * ownership.page_bytes;
        ownership.source_inline_committed_capacity_bytes = 0;
        ownership.source_external_committed_capacity_bytes =
            cohort.resident_pages * ownership.page_bytes;
        ownership.source_pages = cohort.resident_pages;
        ownership.source_inline_pages = 0;
        ownership.source_external_pages = cohort.resident_pages;
        ownership.partition_total_bytes = ownership.source_external_bytes;
        ownership.unique_allocation_union_bytes = ownership.source_external_bytes;
        ownership.unique_resident_page_union_bytes = ownership.source_external_bytes;
        ownership
    }

    fn sequence() -> Vec<RotatingRolloverCheckpointInput> {
        let mut actual_source = 0u64;
        ROTATING_ROLLOVER_ORDINALS
            .into_iter()
            .enumerate()
            .map(|(interval_index, ordinal)| {
                let acquired = 8 * 1024 * 1024;
                let before = actual_source;
                actual_source += acquired;
                let stable = 2 * 1024 * 1024;
                let pinned = 2 * 1024 * 1024;
                let non_heap = 8 * 1024 * 1024;
                let stable_acquired = if ordinal == 160 { stable } else { 0 };
                let pinned_acquired = if ordinal == 160 { pinned } else { 0 };
                let mut process_high_water =
                    watermark(before + acquired, stable, pinned, non_heap, acquired);
                process_high_water.stable_acquired_at_watermark_bytes = stable_acquired;
                process_high_water.pinned_acquired_at_watermark_bytes = pinned_acquired;
                process_high_water.interval_sequence = interval_index as u64;
                process_high_water.observation_sequence = (interval_index * 2) as u64;
                let mut allocator_high_water = process_high_water;
                allocator_high_water.observation_sequence = (interval_index * 2 + 1) as u64;
                RotatingRolloverCheckpointInput {
                    ordinal,
                    interval: RotatingRolloverIntervalInput {
                        source_committed_acquired_bytes: acquired,
                        source_committed_acquisition_high_water_bytes: acquired,
                        source_resident_acquired_bytes: acquired,
                        source_resident_acquisition_high_water_bytes: acquired,
                        stable_acquired_bytes: stable_acquired,
                        stable_retired_bytes: 0,
                        pinned_acquired_bytes: pinned_acquired,
                        pinned_retired_bytes: 0,
                        process_high_water,
                        allocator_high_water,
                        external_acquired: RotatingRolloverExternalCohort::default(),
                        interval_sequence: interval_index as u64,
                        coverage_start_event: (interval_index * 2) as u64,
                        coverage_end_event: (interval_index * 2 + 2) as u64,
                        process_observation_complete: true,
                        allocator_observation_complete: true,
                        external_identity_uniqueness_proven: true,
                    },
                    checkpoint_ownership: ledger(actual_source, stable, pinned, non_heap),
                    external_lifecycle: RotatingRolloverExternalLifecycle::default(),
                    destination: destination(),
                    inventory_objects: 10,
                    classified_objects: 10,
                    inventory_edges: 20,
                    classified_edges: 20,
                    blockers: RotatingRolloverBlockers::default(),
                    evidence: evidence(),
                }
            })
            .collect()
    }

    fn replay<'a>(
        checkpoints: &'a [RotatingRolloverCheckpointInput],
    ) -> RotatingRolloverReplayInput<'a> {
        RotatingRolloverReplayInput {
            paired_cpp_peak_bytes: 512 * 1024 * 1024,
            enforce_engineering_gate: false,
            checkpoints,
        }
    }

    #[test]
    fn replays_source_stable_and_pinned_domains_causally() {
        let inputs = sequence();
        let report = project_rotating_rollover(replay(&inputs)).expect("bounded replay");
        assert_eq!(
            report.checkpoints()[0].projected_source_bytes,
            8 * 1024 * 1024
        );
        assert_eq!(
            report.checkpoints()[1].projected_source_bytes,
            24 * 1024 * 1024
        );
        assert_eq!(
            report.checkpoints()[1].projected_stable_bytes,
            2 * 1024 * 1024
        );
        assert_eq!(
            report.checkpoints()[1].projected_pinned_bytes,
            2 * 1024 * 1024
        );
    }

    #[test]
    fn includes_pre_first_and_interval_high_waters_in_global_peak() {
        let mut inputs = sequence();
        inputs[0]
            .interval
            .process_high_water
            .ownership
            .exogenous_non_heap_bytes = 180 * 1024 * 1024;
        inputs[0]
            .interval
            .process_high_water
            .ownership
            .partition_total_bytes = 192 * 1024 * 1024;
        inputs[0]
            .interval
            .process_high_water
            .ownership
            .unique_allocation_union_bytes = 192 * 1024 * 1024;
        inputs[0]
            .interval
            .process_high_water
            .ownership
            .unique_resident_page_union_bytes = 192 * 1024 * 1024;
        inputs[0]
            .interval
            .process_high_water
            .ownership
            .exogenous_non_heap_pages = (180 * 1024 * 1024u64).div_ceil(4096);
        inputs[0]
            .interval
            .process_high_water
            .ownership
            .partition_total_pages = inputs[0].interval.process_high_water.ownership.source_pages
            + inputs[0]
                .interval
                .process_high_water
                .ownership
                .stable_head_pages
            + inputs[0].interval.process_high_water.ownership.pinned_pages
            + inputs[0]
                .interval
                .process_high_water
                .ownership
                .exogenous_non_heap_pages;
        inputs[0].interval.process_high_water.measured_process_bytes = 192 * 1024 * 1024;
        let report = project_rotating_rollover(replay(&inputs)).expect("bounded replay");
        assert_eq!(
            report.checkpoints()[0].projected_process_interval_high_water_bytes,
            192 * 1024 * 1024
        );
    }

    #[test]
    fn ownership_external_and_destination_partitions_fail_closed() {
        let mut inputs = sequence();
        inputs[2].checkpoint_ownership.partition_total_bytes += 1;
        inputs[3].external_lifecycle.dead_source_bytes = 1;
        inputs[4].destination.same_generation_partition_bytes += 1;
        let report = project_rotating_rollover(replay(&inputs)).expect("mismatches report");
        assert!(!report.checkpoints()[2].ownership_reconciled);
        assert!(!report.checkpoints()[3].external_lifecycle_reconciled);
        assert!(!report.checkpoints()[4].admitted);
        assert!(!report.admitted());
    }

    #[test]
    fn copied_cohort_cannot_shrink_from_one_hundred_bytes_to_zero() {
        let source = cohort(7, 100);
        let destination_cohort = RotatingRolloverExternalCohort {
            bytes: 0,
            ..source.clone()
        };
        let lifecycle = RotatingRolloverExternalLifecycle {
            copied_source_bytes: 100,
            copied_destination_bytes: 0,
            projected_source: source.clone(),
            copied_source: source.clone(),
            copied_destination: destination_cohort,
            actual_control_source: source.clone(),
            disjoint_identity_partition_proven: true,
            rebuilt_source_layout_proven: true,
            ..RotatingRolloverExternalLifecycle::default()
        };
        let mut destination = destination();
        destination.external_copied_bytes = 0;

        assert!(
            !external_lifecycle_reconciled(
                160,
                external_ownership(source.clone()),
                &lifecycle,
                destination,
                &source,
                &source,
            )
            .expect("bounded cohort accounting")
        );
    }

    #[test]
    fn external_destination_charges_exact_resident_pages() {
        let source = RotatingRolloverExternalCohort {
            allocations: 2,
            bytes: 2,
            resident_pages: 2,
            identities: vec![1, 2],
        };
        let copied = RotatingRolloverExternalLifecycle {
            copied_source_bytes: 2,
            copied_destination_bytes: 2,
            projected_source: source.clone(),
            copied_source: source.clone(),
            copied_destination: source.clone(),
            actual_control_source: source.clone(),
            disjoint_identity_partition_proven: true,
            rebuilt_source_layout_proven: true,
            ..RotatingRolloverExternalLifecycle::default()
        };
        let mut undercharged = destination();
        undercharged.external_copied_bytes = 4096;
        assert!(
            !external_lifecycle_reconciled(
                160,
                external_ownership(source.clone()),
                &copied,
                undercharged,
                &source,
                &source,
            )
            .expect("bounded copied cohort accounting")
        );
        let mut exact = undercharged;
        exact.external_copied_bytes = 8192;
        assert!(
            external_lifecycle_reconciled(
                160,
                external_ownership(source.clone()),
                &copied,
                exact,
                &source,
                &source,
            )
            .expect("exact copied resident pages reconcile")
        );

        let rebuilt_destination = RotatingRolloverExternalCohort {
            resident_pages: 1000,
            ..source.clone()
        };
        let rebuilt = RotatingRolloverExternalLifecycle {
            rebuilt_source_bytes: 2,
            rebuilt_destination_bytes: 2,
            projected_source: source.clone(),
            rebuilt_source: source.clone(),
            rebuilt_destination,
            actual_control_source: source.clone(),
            disjoint_identity_partition_proven: true,
            rebuilt_source_layout_proven: true,
            ..RotatingRolloverExternalLifecycle::default()
        };
        let mut rebuilt_undercharged = destination();
        rebuilt_undercharged.external_rebuilt_bytes = 4096;
        assert!(
            !external_lifecycle_reconciled(
                160,
                external_ownership(source.clone()),
                &rebuilt,
                rebuilt_undercharged,
                &source,
                &source,
            )
            .expect("bounded rebuilt cohort accounting")
        );
        rebuilt_undercharged.external_rebuilt_bytes = 1000 * 4096;
        assert!(
            external_lifecycle_reconciled(
                160,
                external_ownership(source.clone()),
                &rebuilt,
                rebuilt_undercharged,
                &source,
                &source,
            )
            .expect("exact rebuilt resident pages reconcile")
        );
    }

    #[test]
    fn retained_cohort_cannot_be_promoted_again_next_checkpoint() {
        let source = cohort(11, 100);
        let lifecycle = RotatingRolloverExternalLifecycle {
            retained_pinned_source_bytes: 100,
            projected_source: source.clone(),
            retained_pinned: source.clone(),
            actual_control_source: source.clone(),
            disjoint_identity_partition_proven: true,
            rebuilt_source_layout_proven: true,
            ..RotatingRolloverExternalLifecycle::default()
        };
        let ownership = external_ownership(source.clone());
        assert!(
            external_lifecycle_reconciled(
                160,
                ownership,
                &lifecycle,
                destination(),
                &source,
                &source,
            )
            .expect("first promotion reconciles")
        );
        assert!(
            !external_lifecycle_reconciled(
                176,
                ownership,
                &lifecycle,
                destination(),
                &source,
                &RotatingRolloverExternalCohort::default(),
            )
            .expect("repeat promotion is a mismatch")
        );
    }

    #[test]
    fn colliding_sum_and_xor_identity_sets_are_not_equal() {
        let left = RotatingRolloverExternalCohort {
            allocations: 2,
            bytes: 200,
            resident_pages: 2,
            identities: vec![1, 6],
        };
        let right = RotatingRolloverExternalCohort {
            allocations: 2,
            bytes: 200,
            resident_pages: 2,
            identities: vec![2, 5],
        };
        assert_eq!(1u64 + 6, 2u64 + 5);
        assert_eq!(1u64 ^ 6, 2u64 ^ 5);
        assert!(!cohort_same_identity(&left, &right));
    }

    #[test]
    fn process_and_allocator_peak_observations_allow_either_order() {
        let mut inputs = sequence();
        inputs[0].interval.process_high_water.observation_sequence = 1;
        inputs[0].interval.allocator_high_water.observation_sequence = 0;
        let report = project_rotating_rollover(replay(&inputs)).expect("bounded replay");
        assert!(report.checkpoints()[0].interval_reconciled);
    }

    #[test]
    fn peak_observations_must_belong_to_their_interval() {
        let mut inputs = sequence();
        inputs[1].interval.process_high_water.observation_sequence =
            inputs[1].interval.coverage_end_event;
        inputs[1].interval.allocator_high_water.observation_sequence =
            inputs[1].interval.coverage_start_event - 1;
        let report = project_rotating_rollover(replay(&inputs)).expect("mismatch reports");
        assert!(!report.checkpoints()[1].interval_reconciled);
        assert!(!report.checkpoints()[1].admitted);
        assert!(!report.admitted());
    }

    #[test]
    fn resident_page_union_and_rounded_destination_capacity_are_exact() {
        let mut inputs = sequence();
        inputs[1]
            .checkpoint_ownership
            .unique_resident_page_union_bytes += 4096;
        inputs[2]
            .destination
            .same_generation_committed_capacity_bytes += 4096;
        let report = project_rotating_rollover(replay(&inputs)).expect("mismatches report");
        assert!(!report.checkpoints()[1].ownership_reconciled);
        assert!(!report.checkpoints()[2].admitted);
        assert!(!report.admitted());
    }

    #[test]
    fn local_watermark_and_strict_half_cpp_gate_control_admission() {
        let inputs = sequence();
        let mut paired = replay(&inputs);
        paired.paired_cpp_peak_bytes = 64 * 1024 * 1024;
        let report = project_rotating_rollover(paired).expect("bounded replay");
        assert!(!report.strict_half_cpp_pass);
        assert!(!report.admitted());
        assert!(report.savings_against_cpp_bytes > 0);
    }

    #[test]
    fn checked_arithmetic_rejects_max_and_domain_underflow() {
        assert_eq!(
            checked_add(160, u64::MAX, 1),
            Err(RotatingRolloverProjectionError::ByteOverflow {
                ordinal: 160,
                table: TABLE,
            })
        );
        assert_eq!(
            apply_domain_delta(160, 0, 0, 1, "stable"),
            Err(RotatingRolloverProjectionError::DomainUnderflow {
                ordinal: 160,
                domain: "stable",
            })
        );
        assert!(round_extent(160, u64::MAX, 4096).is_err());
    }

    #[test]
    fn sequence_and_cpp_pair_are_mandatory() {
        let mut inputs = sequence();
        inputs.pop();
        assert_eq!(
            project_rotating_rollover(replay(&inputs)),
            Err(RotatingRolloverProjectionError::CheckpointSequence)
        );
        let inputs = sequence();
        assert_eq!(
            project_rotating_rollover(RotatingRolloverReplayInput {
                paired_cpp_peak_bytes: 0,
                enforce_engineering_gate: false,
                checkpoints: &inputs,
            }),
            Err(RotatingRolloverProjectionError::ZeroCppPeak)
        );
    }
}
