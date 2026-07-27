//! Read-only planning for a same-layout moving evacuation.
//!
//! The planner starts from the ordinary weak-root reachable set, classifies
//! every reachable serial-heap object by its current storage lane, and assigns
//! deterministic dense offsets within each lane. It records forwarding
//! metadata only: no destination reservation is created, no forwarding slot is
//! installed, and no source heap field is changed.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};

use super::arena::any_value_heap_ptr;
use super::flat_values::evacuated_closures::plain_node_thunk_movable;
use super::flat_values::value_tag_for_flat_kind;
use super::snapshot::{CapturedFrameTable, RestoredFrameTable};
use super::*;
use crate::attrs::AttrsStorageKind;
use crate::eval::ThunkState;
use crate::eval::env::{
    EvalEnv, EvalFlatCapture, EvalFlatCaptureBuffer, EvalFrame, EvalScopedGlobalEnv, EvalWithEnv,
    EvalWithScope,
};
use crate::heap::{
    PeakResidentMemoryScope, ProcessResidentMemorySample, peak_resident_memory_bytes,
};
use crate::string::StringBytesStorageKind;

const PLAN_OBJECTS_TABLE: &str = "evacuation plan objects";
const PLAN_LAYOUT_TABLE: &str = "evacuation plan layout";
// Strictly half of the authoritative 466,904 KiB stock C++ Nix peak.
const ACCEPTANCE_RSS_BYTES: usize = 239_054_848;
const HARD_PIN_SEED_GRAPH_ENV: &str = "AOS_NIX_EVACUATION_HARD_PIN_SEED_GRAPH";
const HARD_PIN_SEED_GRAPH_MAX_SEEDS: usize = u64::BITS as usize;

/// One independently packed destination lane.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum EvacuationLane {
    /// Permanent strings, paths, lists, and attribute sets.
    PermanentFlat,
    /// Headerless stable thunk heads.
    TypedThunkHeads,
    /// Flat worker closures allocated from the rewindable lane.
    WorkerFlat,
    /// Compatibility worker records allocated from the worker bump arena.
    WorkerRecords,
}

impl EvacuationLane {
    const ALL: [Self; 4] = [
        Self::PermanentFlat,
        Self::TypedThunkHeads,
        Self::WorkerFlat,
        Self::WorkerRecords,
    ];

    const fn index(self) -> usize {
        match self {
            Self::PermanentFlat => 0,
            Self::TypedThunkHeads => 1,
            Self::WorkerFlat => 2,
            Self::WorkerRecords => 3,
        }
    }
}

/// Forwarding metadata for one reachable object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EvacuationForwarding {
    /// Source heap address.
    pub(crate) source_address: usize,
    /// Runtime value tag carried by references to the object.
    pub(crate) tag: ValueTag,
    /// Destination lane.
    pub(crate) lane: EvacuationLane,
    /// Dense byte offset within `lane`.
    pub(crate) destination_offset: usize,
    /// Exact current inline object extent.
    pub(crate) size_bytes: usize,
    /// Required destination alignment.
    pub(crate) align: usize,
}

/// Read-only accounting for a proposed evacuation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EvacuationPlanAccounting {
    /// Explicit roots supplied to the reachability traversal.
    pub(crate) roots: usize,
    /// Reachable objects assigned a destination.
    pub(crate) objects: usize,
    /// Precise outgoing heap edges across reachable objects.
    pub(crate) edges: usize,
    /// Sum of exact current inline object extents.
    pub(crate) source_inline_bytes: usize,
    /// Sum of known out-of-arena list-spine capacities.
    pub(crate) known_external_bytes: usize,
    /// Dense destination bytes including alignment padding.
    pub(crate) destination_inline_bytes: usize,
    /// Dense destination extent for each [`EvacuationLane`].
    lane_bytes: [usize; 4],
    /// Distinct reachable objects named directly by an explicit root.
    direct_root_objects: usize,
    /// Complete conservative V1 pin population.
    pinned_objects: usize,
    pinned_tail_owner_objects: usize,
    pinned_typed_head_objects: usize,
    pinned_blackhole_objects: usize,
    /// Source pages intersected by pinned objects or boxed scalar cells.
    pinned_pages: usize,
    pinned_scalar_pages: usize,
    /// Pin roots that can be healed by root or owner-relative-tail writeback.
    healable_pin_objects: usize,
    /// Truly nonmovable identity seeds and the graph island retained by them.
    hard_pin_seed_objects: usize,
    hard_pin_transitive_retained_objects: usize,
    hard_pin_retained_objects: usize,
    hard_pin_retained_inline_bytes: usize,
    hard_pin_unique_resident_source_pages: usize,
    /// Dense destination bytes needed when direct root targets stay in place.
    movable_destination_inline_bytes: usize,
    /// Reachable flat-thunk population by payload and force state.
    flat_thunks: EvacuationFlatThunkPopulation,
    /// Resident source reservation bytes at the sample.
    source_reservation_resident_bytes: usize,
    /// Page-rounded destination plus direct-root-pinned source pages.
    post_commit_reservation_bytes: usize,
    /// Current and live-sized flat registry structural bytes.
    registry_current_bytes: usize,
    registry_live_bytes: usize,
    /// Current and live-sized weak hash-index structural bytes.
    hash_current_bytes: usize,
    hash_live_bytes: usize,
    /// Compact mark/forwarding scratch carried during streaming evacuation.
    compact_scratch_bytes: usize,
    /// Conservative external-frame staging charged to the current writer.
    frame_staging_upper_bytes: usize,
    /// Conservative aggregate staging charged to the clone-all writer.
    current_writer_staging_upper_bytes: usize,
    /// Process RSS and watermark sampled before planner storage is allocated.
    preplan_current_rss_bytes: usize,
    preplan_peak_rss_bytes: usize,
    /// Newly covered reservation pages for an append-only full-copy destination.
    full_copy_new_page_bytes: usize,
    /// Conservative first-collection peak with the complete source retained.
    full_copy_peak_upper_bytes: usize,
    /// Remaining bytes below the acceptance ceiling, or the excess above it.
    full_copy_headroom_bytes: usize,
    full_copy_excess_bytes: usize,
    /// Dead-first, source-address-order page-streaming projection.
    page_stream_source_pages: usize,
    page_stream_resident_source_pages: usize,
    page_stream_dead_phase_released_pages: usize,
    page_stream_destination_pages: usize,
    page_stream_released_source_pages: usize,
    page_stream_peak_net_pages: usize,
    page_stream_peak_upper_bytes: usize,
    page_stream_headroom_bytes: usize,
    page_stream_excess_bytes: usize,
    /// First executable worker slice and two materially different orderings.
    first_slice: EvacuationFirstSliceAccounting,
    /// Captured lexical-frame ownership inside flat closures.
    reachable_frames: FramePopulation,
    total_frames: FramePopulation,
}

/// Shape census for reachable ordinary flat thunks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct EvacuationFlatThunkPopulation {
    inline: usize,
    shared: usize,
    suspended: usize,
    forced: usize,
    blackhole: usize,
    pinned_blackhole: usize,
    node: usize,
    synthetic: usize,
    released: usize,
    with_value_tail: usize,
    plain_node_movable: usize,
    plain_node_movable_inline_bytes: usize,
}

/// Exact, opt-in topology census for the bounded hard-pin seed population.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HardPinSeedGraphCensus {
    seeds: Vec<HardPinSeedCensus>,
    population: HardPinSeedPopulation,
    overlap_histogram: Vec<HardPinOverlapBucket>,
    contributing_seeds: usize,
    minimum_full_collapse_cut: usize,
    common_to_all_contributing_seeds: usize,
    greedy_cut: Vec<HardPinGreedyCutStep>,
}

/// Aggregate classification of the exact hard-seed population.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct HardPinSeedPopulation {
    inline: usize,
    shared: usize,
    typed_head: usize,
    node: usize,
    released: usize,
    synthetic: usize,
    with_value_tail: usize,
    physical_tail_free: usize,
}

/// One hard seed's exact classification and descendant reachability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HardPinSeedCensus {
    index: usize,
    storage: &'static str,
    work: &'static str,
    has_value_tail: bool,
    physical_tail_free: bool,
    outgoing_edges: usize,
    reachable_nonseed_objects: usize,
    exclusive_nonseed_objects: usize,
    retained_without_seed: usize,
}

/// Number of non-seed objects reached by exactly `multiplicity` hard seeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HardPinOverlapBucket {
    multiplicity: usize,
    objects: usize,
}

/// One deterministic maximum-immediate-release step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HardPinGreedyCutStep {
    cut_count: usize,
    seed_index: usize,
    newly_released_objects: usize,
    retained_nonseed_objects: usize,
}

/// Exact population and movement accounting for one bounded evacuation slice.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct EvacuationSlicePopulation {
    objects: usize,
    source_inline_bytes: usize,
    edges: usize,
    direct_root_objects: usize,
    pinned_objects: usize,
    movable_objects: usize,
    movable_inline_bytes: usize,
    movable_edges: usize,
    movable_destination_inline_bytes: usize,
}

impl fmt::Display for EvacuationSlicePopulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{\"objects\":{},\"source_inline_bytes\":{},\"edges\":{},\
             \"direct_root_objects\":{},\"pinned_objects\":{},\
             \"movable_objects\":{},\"movable_inline_bytes\":{},\
             \"movable_edges\":{},\"movable_destination_inline_bytes\":{}}}",
            self.objects,
            self.source_inline_bytes,
            self.edges,
            self.direct_root_objects,
            self.pinned_objects,
            self.movable_objects,
            self.movable_inline_bytes,
            self.movable_edges,
            self.movable_destination_inline_bytes,
        )
    }
}

impl EvacuationSlicePopulation {
    fn record(
        &mut self,
        entry: &EvacuationForwarding,
        edges: usize,
        direct_root: bool,
        pinned: bool,
    ) -> Result<(), EvalHeapError> {
        self.objects = self.objects.saturating_add(1);
        self.source_inline_bytes = self
            .source_inline_bytes
            .checked_add(entry.size_bytes)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PLAN_LAYOUT_TABLE,
            })?;
        self.edges =
            self.edges
                .checked_add(edges)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_OBJECTS_TABLE,
                })?;
        self.direct_root_objects = self
            .direct_root_objects
            .saturating_add(usize::from(direct_root));
        self.pinned_objects = self.pinned_objects.saturating_add(usize::from(pinned));
        if pinned {
            return Ok(());
        }
        self.movable_objects = self.movable_objects.saturating_add(1);
        self.movable_inline_bytes = self
            .movable_inline_bytes
            .checked_add(entry.size_bytes)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PLAN_LAYOUT_TABLE,
            })?;
        self.movable_edges =
            self.movable_edges
                .checked_add(edges)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_OBJECTS_TABLE,
                })?;
        self.movable_destination_inline_bytes =
            align_up(self.movable_destination_inline_bytes, entry.align)?
                .checked_add(entry.size_bytes)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_LAYOUT_TABLE,
                })?;
        Ok(())
    }
}

/// Source-page effect of one slice after the common unreachable-object prepass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct EvacuationSlicePageProjection {
    dead_phase_released_pages: usize,
    additional_released_pages: usize,
    destination_pages: usize,
    net_resident_page_delta: isize,
}

impl fmt::Display for EvacuationSlicePageProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{\"dead_phase_released_pages\":{},\"additional_released_pages\":{},\
             \"destination_pages\":{},\"net_resident_page_delta\":{}}}",
            self.dead_phase_released_pages,
            self.additional_released_pages,
            self.destination_pages,
            self.net_resident_page_delta,
        )
    }
}

/// The immediately executable slice plus alternative collection orderings.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct EvacuationFirstSliceAccounting {
    plain_primops: EvacuationSlicePopulation,
    plain_lambdas: EvacuationSlicePopulation,
    rejected_tail_free_lambdas: EvacuationSlicePopulation,
    primop_lambda: EvacuationSlicePopulation,
    primop_lambda_pages: EvacuationSlicePageProjection,
    alias_forwarded_primop_lambda: EvacuationSlicePopulation,
    alias_forwarded_primop_lambda_pages: EvacuationSlicePageProjection,
    permanent_strings: EvacuationSlicePopulation,
    permanent_string_pages: EvacuationSlicePageProjection,
    permanent_owned_strings: EvacuationSlicePopulation,
    permanent_owned_string_pages: EvacuationSlicePageProjection,
    permanent_inline_strings: EvacuationSlicePopulation,
    permanent_paths: EvacuationSlicePopulation,
    permanent_path_pages: EvacuationSlicePageProjection,
    permanent_owned_paths: EvacuationSlicePopulation,
    permanent_owned_path_pages: EvacuationSlicePageProjection,
    permanent_inline_paths: EvacuationSlicePopulation,
    permanent_owned_strings_paths: EvacuationSlicePopulation,
    permanent_owned_strings_paths_pages: EvacuationSlicePageProjection,
    permanent_lists: EvacuationSlicePopulation,
    permanent_list_pages: EvacuationSlicePageProjection,
    permanent_attrs: EvacuationSlicePopulation,
    permanent_attrs_pages: EvacuationSlicePageProjection,
    permanent_owned_attrs: EvacuationSlicePopulation,
    permanent_owned_attrs_pages: EvacuationSlicePageProjection,
    permanent_inline_attrs: EvacuationSlicePopulation,
    permanent_strings_paths: EvacuationSlicePopulation,
    permanent_strings_paths_pages: EvacuationSlicePageProjection,
    permanent_strings_paths_lists: EvacuationSlicePopulation,
    permanent_strings_paths_lists_pages: EvacuationSlicePageProjection,
    current_mover_permanent: EvacuationSlicePopulation,
    current_mover_permanent_pages: EvacuationSlicePageProjection,
    excluded_inline_permanent: EvacuationSlicePopulation,
    excluded_inline_permanent_pages: EvacuationSlicePageProjection,
    permanent_flat: EvacuationSlicePopulation,
    permanent_flat_pages: EvacuationSlicePageProjection,
    forced_tail_free_flat_thunks: EvacuationSlicePopulation,
    forced_tail_free_flat_thunk_pages: EvacuationSlicePageProjection,
}

impl EvacuationPlanAccounting {
    /// Returns the dense extent assigned to `lane`.
    pub(crate) const fn lane_bytes(self, lane: EvacuationLane) -> usize {
        self.lane_bytes[lane.index()]
    }
}

/// A deterministic, read-only same-layout evacuation plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvacuationPlan {
    forwarding: Vec<EvacuationForwarding>,
    accounting: EvacuationPlanAccounting,
    hard_pin_seed_graph: Option<HardPinSeedGraphCensus>,
}

impl EvacuationPlan {
    /// Returns forwarding records in deterministic lane/address order.
    pub(crate) fn forwarding(&self) -> &[EvacuationForwarding] {
        &self.forwarding
    }

    /// Returns the plan's exact inline and known-external accounting.
    pub(crate) const fn accounting(&self) -> EvacuationPlanAccounting {
        self.accounting
    }
}

impl fmt::Display for EvacuationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let accounting = self.accounting;
        write!(
            f,
            "{{\"roots\":{},\"objects\":{},\"edges\":{},\
             \"source_inline_bytes\":{},\"known_external_bytes\":{},\
             \"destination_inline_bytes\":{},\
             \"direct_root_objects\":{},\"pinned_objects\":{},\
             \"pinned_tail_owner_objects\":{},\"pinned_typed_head_objects\":{},\
             \"pinned_blackhole_objects\":{},\"pinned_pages\":{},\
             \"pinned_scalar_pages\":{},\
             \"hard_pinned_island\":{{\"healable_pin_objects\":{},\
             \"hard_seed_objects\":{},\"transitive_retained_objects\":{},\
             \"retained_objects\":{},\"retained_inline_bytes\":{},\
             \"unique_resident_source_pages\":{}}},\
             \"movable_destination_inline_bytes\":{},\
             \"flat_thunks\":{{\"inline\":{},\"shared\":{},\"suspended\":{},\
             \"forced\":{},\"blackhole\":{},\"node\":{},\"synthetic\":{},\
             \"pinned_blackhole\":{},\"released\":{},\"with_value_tail\":{},\
             \"plain_node_movable\":{},\
             \"plain_node_movable_inline_bytes\":{}}},\
             \"streaming_floor\":{{\"source_reservation_resident_bytes\":{},\
             \"post_commit_reservation_bytes\":{},\"registry_current_bytes\":{},\
             \"registry_live_bytes\":{},\"hash_current_bytes\":{},\
             \"hash_live_bytes\":{},\"compact_scratch_bytes\":{},\
             \"frame_staging_upper_bytes\":{},\
             \"current_writer_staging_upper_bytes\":{},\
             \"hash_savings_credited\":false,\
             \"preplan_current_rss_bytes\":{},\"preplan_peak_rss_bytes\":{},\
             \"full_copy_new_page_bytes\":{},\
             \"full_copy_peak_upper_bytes\":{},\
             \"full_copy_headroom_bytes\":{},\"full_copy_excess_bytes\":{},\
             \"acceptance_rss_bytes\":{},\
             \"page_stream\":{{\"strategy\":\"dead_first_source_address\",\
             \"source_pages\":{},\"resident_source_pages\":{},\
             \"dead_phase_released_pages\":{},\
             \"destination_pages\":{},\"released_source_pages\":{},\
             \"peak_net_pages\":{},\"peak_upper_bytes\":{},\
             \"headroom_bytes\":{},\"excess_bytes\":{}}}}},\
             \"first_slice\":{{\"plain_primops\":{},\"plain_lambdas\":{},\
             \"rejected_tail_free_lambdas\":{},\
             \"combined\":{},\"combined_pages\":{},\
             \"alias_forwarded_combined\":{},\"alias_forwarded_combined_pages\":{},\
             \"permanent_strings\":{},\"permanent_string_pages\":{},\
             \"permanent_owned_strings\":{},\"permanent_owned_string_pages\":{},\
             \"permanent_inline_strings\":{},\
             \"permanent_paths\":{},\"permanent_path_pages\":{},\
             \"permanent_owned_paths\":{},\"permanent_owned_path_pages\":{},\
             \"permanent_inline_paths\":{},\
             \"permanent_owned_strings_paths\":{},\
             \"permanent_owned_strings_paths_pages\":{},\
             \"permanent_lists\":{},\"permanent_list_pages\":{},\
             \"permanent_attrs\":{},\"permanent_attrs_pages\":{},\
             \"permanent_owned_attrs\":{},\"permanent_owned_attrs_pages\":{},\
             \"permanent_inline_attrs\":{},\
             \"permanent_strings_paths\":{},\"permanent_strings_paths_pages\":{},\
             \"permanent_strings_paths_lists\":{},\
             \"permanent_strings_paths_lists_pages\":{},\
             \"current_mover_permanent\":{},\
             \"current_mover_permanent_pages\":{},\
             \"excluded_inline_permanent\":{},\
             \"excluded_inline_permanent_pages\":{},\
             \"alternative_permanent_flat\":{},\
             \"alternative_permanent_flat_pages\":{},\
             \"alternative_forced_tail_free_flat_thunks\":{},\
             \"alternative_forced_tail_free_flat_thunk_pages\":{}}},\
             \"frames\":{{\"reachable\":{{\"references\":{},\"distinct\":{},\
             \"slots\":{},\"heap_backed\":{},\"heap_backed_slots\":{},\
             \"modeled_bytes\":{}}},\"total\":{{\"references\":{},\
             \"distinct\":{},\"slots\":{},\"heap_backed\":{},\
             \"heap_backed_slots\":{},\"modeled_bytes\":{}}}}},\
             \"lane_bytes\":{{\"permanent_flat\":{},\"typed_thunk_heads\":{},\
             \"worker_flat\":{},\"worker_records\":{}}}",
            accounting.roots,
            accounting.objects,
            accounting.edges,
            accounting.source_inline_bytes,
            accounting.known_external_bytes,
            accounting.destination_inline_bytes,
            accounting.direct_root_objects,
            accounting.pinned_objects,
            accounting.pinned_tail_owner_objects,
            accounting.pinned_typed_head_objects,
            accounting.pinned_blackhole_objects,
            accounting.pinned_pages,
            accounting.pinned_scalar_pages,
            accounting.healable_pin_objects,
            accounting.hard_pin_seed_objects,
            accounting.hard_pin_transitive_retained_objects,
            accounting.hard_pin_retained_objects,
            accounting.hard_pin_retained_inline_bytes,
            accounting.hard_pin_unique_resident_source_pages,
            accounting.movable_destination_inline_bytes,
            accounting.flat_thunks.inline,
            accounting.flat_thunks.shared,
            accounting.flat_thunks.suspended,
            accounting.flat_thunks.forced,
            accounting.flat_thunks.blackhole,
            accounting.flat_thunks.node,
            accounting.flat_thunks.synthetic,
            accounting.flat_thunks.pinned_blackhole,
            accounting.flat_thunks.released,
            accounting.flat_thunks.with_value_tail,
            accounting.flat_thunks.plain_node_movable,
            accounting.flat_thunks.plain_node_movable_inline_bytes,
            accounting.source_reservation_resident_bytes,
            accounting.post_commit_reservation_bytes,
            accounting.registry_current_bytes,
            accounting.registry_live_bytes,
            accounting.hash_current_bytes,
            accounting.hash_live_bytes,
            accounting.compact_scratch_bytes,
            accounting.frame_staging_upper_bytes,
            accounting.current_writer_staging_upper_bytes,
            accounting.preplan_current_rss_bytes,
            accounting.preplan_peak_rss_bytes,
            accounting.full_copy_new_page_bytes,
            accounting.full_copy_peak_upper_bytes,
            accounting.full_copy_headroom_bytes,
            accounting.full_copy_excess_bytes,
            ACCEPTANCE_RSS_BYTES,
            accounting.page_stream_source_pages,
            accounting.page_stream_resident_source_pages,
            accounting.page_stream_dead_phase_released_pages,
            accounting.page_stream_destination_pages,
            accounting.page_stream_released_source_pages,
            accounting.page_stream_peak_net_pages,
            accounting.page_stream_peak_upper_bytes,
            accounting.page_stream_headroom_bytes,
            accounting.page_stream_excess_bytes,
            accounting.first_slice.plain_primops,
            accounting.first_slice.plain_lambdas,
            accounting.first_slice.rejected_tail_free_lambdas,
            accounting.first_slice.primop_lambda,
            accounting.first_slice.primop_lambda_pages,
            accounting.first_slice.alias_forwarded_primop_lambda,
            accounting.first_slice.alias_forwarded_primop_lambda_pages,
            accounting.first_slice.permanent_strings,
            accounting.first_slice.permanent_string_pages,
            accounting.first_slice.permanent_owned_strings,
            accounting.first_slice.permanent_owned_string_pages,
            accounting.first_slice.permanent_inline_strings,
            accounting.first_slice.permanent_paths,
            accounting.first_slice.permanent_path_pages,
            accounting.first_slice.permanent_owned_paths,
            accounting.first_slice.permanent_owned_path_pages,
            accounting.first_slice.permanent_inline_paths,
            accounting.first_slice.permanent_owned_strings_paths,
            accounting.first_slice.permanent_owned_strings_paths_pages,
            accounting.first_slice.permanent_lists,
            accounting.first_slice.permanent_list_pages,
            accounting.first_slice.permanent_attrs,
            accounting.first_slice.permanent_attrs_pages,
            accounting.first_slice.permanent_owned_attrs,
            accounting.first_slice.permanent_owned_attrs_pages,
            accounting.first_slice.permanent_inline_attrs,
            accounting.first_slice.permanent_strings_paths,
            accounting.first_slice.permanent_strings_paths_pages,
            accounting.first_slice.permanent_strings_paths_lists,
            accounting.first_slice.permanent_strings_paths_lists_pages,
            accounting.first_slice.current_mover_permanent,
            accounting.first_slice.current_mover_permanent_pages,
            accounting.first_slice.excluded_inline_permanent,
            accounting.first_slice.excluded_inline_permanent_pages,
            accounting.first_slice.permanent_flat,
            accounting.first_slice.permanent_flat_pages,
            accounting.first_slice.forced_tail_free_flat_thunks,
            accounting.first_slice.forced_tail_free_flat_thunk_pages,
            accounting.reachable_frames.references,
            accounting.reachable_frames.distinct,
            accounting.reachable_frames.slots,
            accounting.reachable_frames.heap_backed,
            accounting.reachable_frames.heap_backed_slots,
            accounting.reachable_frames.modeled_bytes,
            accounting.total_frames.references,
            accounting.total_frames.distinct,
            accounting.total_frames.slots,
            accounting.total_frames.heap_backed,
            accounting.total_frames.heap_backed_slots,
            accounting.total_frames.modeled_bytes,
            accounting.lane_bytes(EvacuationLane::PermanentFlat),
            accounting.lane_bytes(EvacuationLane::TypedThunkHeads),
            accounting.lane_bytes(EvacuationLane::WorkerFlat),
            accounting.lane_bytes(EvacuationLane::WorkerRecords),
        )?;
        if let Some(census) = &self.hard_pin_seed_graph {
            write!(f, ",\"hard_pin_seed_graph\":{census}")?;
        } else {
            f.write_str(",\"hard_pin_seed_graph\":null")?;
        }
        f.write_str("}")
    }
}

impl fmt::Display for HardPinSeedGraphCensus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{\"bounded_max_seeds\":{},\"seed_count\":{},\
             \"contributing_seeds\":{},\"minimum_full_collapse_cut\":{},\
             \"common_to_all_contributing_seeds\":{},\
             \"population\":{{\"inline\":{},\"shared\":{},\"typed_head\":{},\
             \"node\":{},\"released\":{},\"synthetic\":{},\
             \"with_value_tail\":{},\"physical_tail_free\":{}}},\"seeds\":[",
            HARD_PIN_SEED_GRAPH_MAX_SEEDS,
            self.seeds.len(),
            self.contributing_seeds,
            self.minimum_full_collapse_cut,
            self.common_to_all_contributing_seeds,
            self.population.inline,
            self.population.shared,
            self.population.typed_head,
            self.population.node,
            self.population.released,
            self.population.synthetic,
            self.population.with_value_tail,
            self.population.physical_tail_free,
        )?;
        for (position, seed) in self.seeds.iter().enumerate() {
            if position != 0 {
                f.write_str(",")?;
            }
            write!(
                f,
                "{{\"index\":{},\"storage\":\"{}\",\"work\":\"{}\",\
                 \"has_value_tail\":{},\"physical_tail_free\":{},\
                 \"outgoing_edges\":{},\"reachable_nonseed_objects\":{},\
                 \"exclusive_nonseed_objects\":{},\"retained_without_seed\":{}}}",
                seed.index,
                seed.storage,
                seed.work,
                seed.has_value_tail,
                seed.physical_tail_free,
                seed.outgoing_edges,
                seed.reachable_nonseed_objects,
                seed.exclusive_nonseed_objects,
                seed.retained_without_seed,
            )?;
        }
        f.write_str("],\"overlap_histogram\":[")?;
        for (position, bucket) in self.overlap_histogram.iter().enumerate() {
            if position != 0 {
                f.write_str(",")?;
            }
            write!(
                f,
                "{{\"multiplicity\":{},\"objects\":{}}}",
                bucket.multiplicity, bucket.objects
            )?;
        }
        f.write_str("],\"greedy_cut\":[")?;
        for (position, step) in self.greedy_cut.iter().enumerate() {
            if position != 0 {
                f.write_str(",")?;
            }
            write!(
                f,
                "{{\"cut_count\":{},\"seed_index\":{},\
                 \"newly_released_objects\":{},\"retained_nonseed_objects\":{}}}",
                step.cut_count,
                step.seed_index,
                step.newly_released_objects,
                step.retained_nonseed_objects,
            )?;
        }
        f.write_str("]}")
    }
}

/// One source-to-destination mapping produced by a permanent-flat evacuation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EvacuationDestinationForwarding {
    /// Source heap address named by the plan.
    pub(crate) source_address: usize,
    /// Equivalent value allocated in the fresh destination heap.
    pub(crate) destination: Value,
}

/// A finalized fresh heap populated from permanent-flat evacuation objects.
///
/// The source heap and its values remain independent and usable until the
/// caller drops them. Values in `forwarding` belong exclusively to `heap`.
pub(crate) struct EvacuationDestination {
    heap: EvalHeap,
    forwarding: Vec<EvacuationDestinationForwarding>,
}

impl EvacuationDestination {
    /// Returns the fresh destination heap.
    pub(crate) const fn heap(&self) -> &EvalHeap {
        &self.heap
    }

    /// Returns source-address to destination-value mappings in plan order.
    pub(crate) fn forwarding(&self) -> &[EvacuationDestinationForwarding] {
        &self.forwarding
    }

    /// Separates the destination heap from its forwarding metadata.
    pub(crate) fn into_parts(self) -> (EvalHeap, Vec<EvacuationDestinationForwarding>) {
        (self.heap, self.forwarding)
    }
}

#[derive(Clone, Copy)]
struct SourceObject {
    tag: ValueTag,
    lane: EvacuationLane,
    size_bytes: usize,
    align: usize,
    known_external_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct PageStreamingProjection {
    source_pages: usize,
    resident_source_pages: usize,
    dead_phase_released_pages: usize,
    destination_pages: usize,
    released_source_pages: usize,
    peak_net_pages: usize,
    peak_upper_bytes: usize,
    headroom_bytes: usize,
    excess_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FramePopulation {
    references: usize,
    distinct: usize,
    slots: usize,
    heap_backed: usize,
    heap_backed_slots: usize,
    modeled_bytes: usize,
}

/// Bounds the external allocations made while the current evacuation writer
/// serializes and rebuilds reachable captured frames.
///
/// The charge deliberately exceeds the packed wire representation: it covers
/// each frame's payload vector and parent/count words, the capture pass's two
/// identity maps and two retained-`Arc` vectors, per-environment frame-id
/// vectors plus map entries, and the simultaneously rebuilt `Arc<EvalFrame>`
/// graph. A future in-place frame rewrite can remove this writer-specific
/// charge.
fn evacuation_frame_staging_upper_bytes(
    population: FramePopulation,
) -> Result<usize, EvalHeapError> {
    const PAYLOAD_RECORD_AND_HEADER_BYTES: usize = 40;
    const CAPTURE_IDENTITY_AND_ARC_BYTES: usize = 112;
    const ENVIRONMENT_FRAME_ID_AND_MAP_BYTES: usize = 36;

    population
        .distinct
        .checked_mul(PAYLOAD_RECORD_AND_HEADER_BYTES)
        .and_then(|bytes| {
            population
                .slots
                .checked_mul(std::mem::size_of::<u64>())
                .and_then(|slot_bytes| bytes.checked_add(slot_bytes))
        })
        .and_then(|bytes| {
            population
                .distinct
                .checked_mul(CAPTURE_IDENTITY_AND_ARC_BYTES)
                .and_then(|identity_bytes| bytes.checked_add(identity_bytes))
        })
        .and_then(|bytes| {
            population
                .references
                .checked_mul(ENVIRONMENT_FRAME_ID_AND_MAP_BYTES)
                .and_then(|id_bytes| bytes.checked_add(id_bytes))
        })
        .and_then(|bytes| bytes.checked_add(population.modeled_bytes))
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PLAN_LAYOUT_TABLE,
        })
}

/// Bounds clone-all metadata and external payload staging in the current
/// fresh-destination writer.
///
/// The writer retains its payload enum vector, source set, allocated map,
/// forwarding map, lambda-tail map, destination forwarding vector, compact
/// destination registries and weak indexes, copied external spines, and frame
/// capture/rebuild storage at overlapping phases. Hash-table buckets use the
/// next power-of-two population as a conservative load-factor allowance.
fn evacuation_current_writer_staging_upper_bytes(
    objects: usize,
    known_external_bytes: usize,
    registry_live_bytes: usize,
    hash_live_bytes: usize,
    frame_staging_upper_bytes: usize,
) -> Result<usize, EvalHeapError> {
    let buckets = objects.max(1).checked_next_power_of_two().ok_or(
        EvalHeapError::RootScanLengthOverflow {
            table: PLAN_LAYOUT_TABLE,
        },
    )?;
    let vector_bytes = objects
        .checked_mul(
            std::mem::size_of::<PermanentFlatPayload>()
                .saturating_add(std::mem::size_of::<EvacuationDestinationForwarding>()),
        )
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PLAN_LAYOUT_TABLE,
        })?;
    let hash_entry_bytes = (std::mem::size_of::<usize>() + 1).saturating_add(
        3usize.saturating_mul(
            std::mem::size_of::<usize>()
                .saturating_add(std::mem::size_of::<Value>())
                .saturating_add(1),
        ),
    );
    vector_bytes
        .checked_add(buckets.saturating_mul(hash_entry_bytes))
        .and_then(|bytes| bytes.checked_add(known_external_bytes))
        .and_then(|bytes| bytes.checked_add(registry_live_bytes))
        .and_then(|bytes| bytes.checked_add(hash_live_bytes))
        .and_then(|bytes| bytes.checked_add(frame_staging_upper_bytes))
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PLAN_LAYOUT_TABLE,
        })
}

enum PermanentFlatPayload {
    String(NixString),
    Path(NixString),
    List(NixList),
    Attrs(FlatAttrsPayload),
    Primop(EvalPrimOp),
    Lambda(EvacuationLambda),
    Thunk(EvacuationThunk),
    TypedThunk(EvacuationTypedThunk),
}

enum EvacuationTypedThunk {
    Suspended {
        work: EvalThunk,
        destination_handle: Option<TypedThunkWorkHandle>,
    },
    Forced(Value),
}

struct EvacuationLambda {
    lambda: EvalLambda,
    flat: Option<EvacuationFlatCapture>,
}

struct EvacuationThunk {
    thunk: EvalThunk,
    state: ThunkState,
    cached_value: Option<Value>,
    flat: Option<EvacuationFlatCapture>,
}

struct EvacuationFlatCapture {
    allocation_site: EvalNodeRef,
    frame_count: usize,
    values: Vec<Value>,
}

impl EvalHeap {
    fn hard_pin_seed_classification(
        &self,
        entry: &EvacuationForwarding,
    ) -> Result<(&'static str, &'static str, bool, bool), EvalHeapError> {
        if entry.lane == EvacuationLane::TypedThunkHeads {
            return Ok(("typed_head", "typed_unknown", false, false));
        }
        let ptr = NonNull::new(entry.source_address as *mut HeapObject).ok_or(
            EvalHeapError::UnknownPointer {
                tag: entry.tag,
                address: entry.source_address,
            },
        )?;
        let payload = self
            .flat_closure_payload_any(ptr)
            .ok_or(EvalHeapError::ShedRejected {
                address: entry.source_address,
                reason: "hard-pin flat seed has no closure payload",
            })?;
        let storage = match payload {
            FlatClosurePayload::Thunk(_) => "inline",
            FlatClosurePayload::SharedThunk(_) => "shared",
            FlatClosurePayload::Lambda(_)
            | FlatClosurePayload::Primop(_)
            | FlatClosurePayload::Retired(_) => {
                return Err(EvalHeapError::ShedRejected {
                    address: entry.source_address,
                    reason: "hard-pin thunk seed resolved to a non-thunk closure",
                });
            }
        };
        let thunk = payload.as_thunk().ok_or(EvalHeapError::ShedRejected {
            address: entry.source_address,
            reason: "hard-pin thunk seed lost its thunk payload",
        })?;
        let work = match thunk.kind() {
            EvalThunkKind::Node { .. } => "node",
            EvalThunkKind::Released => "released",
            EvalThunkKind::Apply { .. } => "synthetic_apply",
            EvalThunkKind::GenListElemAtAddOne { .. } => "synthetic_gen_list_elem_at_add_one",
            EvalThunkKind::Apply2(_) => "synthetic_apply2",
            EvalThunkKind::Select { .. } => "synthetic_select",
            EvalThunkKind::BuiltinAttr { .. } => "synthetic_builtin_attr",
        };
        let has_value_tail = self
            .flat_closures
            .value_tail(ptr, FlatObjectKind::Thunk)
            .map_err(|error| self.closure_resolution_error(ValueTag::Thunk, ptr, error))?
            .is_some();
        let physical_tail_free = self
            .flat_closures
            .is_plain_relocation_source(ptr, FlatObjectKind::Thunk)
            .map_err(|error| self.closure_resolution_error(ValueTag::Thunk, ptr, error))?;
        Ok((storage, work, has_value_tail, physical_tail_free))
    }

    fn hard_pin_seed_graph_census(
        &self,
        hard_pin_seeds: &HashSet<usize>,
        exact_graph: &HashMap<usize, (usize, Vec<usize>)>,
        forwarding: &[EvacuationForwarding],
    ) -> Result<HardPinSeedGraphCensus, EvalHeapError> {
        if hard_pin_seeds.len() > HARD_PIN_SEED_GRAPH_MAX_SEEDS {
            return Err(EvalHeapError::ShedRejected {
                address: hard_pin_seeds.len(),
                reason: "hard-pin seed graph exceeds the exact 64-seed census bound",
            });
        }

        let mut seed_addresses = hard_pin_seeds.iter().copied().collect::<Vec<_>>();
        seed_addresses.sort_unstable();
        let seed_set = hard_pin_seeds;
        let mut membership = HashMap::<usize, u64>::new();
        membership.try_reserve(exact_graph.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: exact_graph.len(),
            }
        })?;
        let mut reachable_counts = vec![0usize; seed_addresses.len()];
        let mut outgoing_counts = vec![0usize; seed_addresses.len()];

        for (seed_index, seed_address) in seed_addresses.iter().copied().enumerate() {
            let (_, seed_outgoing) =
                exact_graph
                    .get(&seed_address)
                    .ok_or(EvalHeapError::ShedRejected {
                        address: seed_address,
                        reason: "hard-pin seed census seed is absent from the exact graph",
                    })?;
            outgoing_counts[seed_index] = seed_outgoing.len();
            let bit = 1u64 << seed_index;
            let mut visited = HashSet::new();
            visited.try_reserve(exact_graph.len()).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: PLAN_OBJECTS_TABLE,
                    entries: exact_graph.len(),
                }
            })?;
            let mut worklist = seed_outgoing.clone();
            while let Some(address) = worklist.pop() {
                if !visited.insert(address) {
                    continue;
                }
                let (_, outgoing) =
                    exact_graph
                        .get(&address)
                        .ok_or(EvalHeapError::ShedRejected {
                            address,
                            reason: "hard-pin seed census reached an object absent from the graph",
                        })?;
                worklist.extend(outgoing.iter().copied());
                if !seed_set.contains(&address) {
                    let prior = membership.entry(address).or_default();
                    *prior |= bit;
                    reachable_counts[seed_index] = reachable_counts[seed_index].saturating_add(1);
                }
            }
        }

        let mut overlap_counts = vec![0usize; seed_addresses.len().saturating_add(1)];
        for mask in membership.values().copied() {
            let multiplicity = mask.count_ones() as usize;
            overlap_counts[multiplicity] = overlap_counts[multiplicity].saturating_add(1);
        }
        let overlap_histogram = overlap_counts
            .into_iter()
            .enumerate()
            .skip(1)
            .filter_map(|(multiplicity, objects)| {
                (objects != 0).then_some(HardPinOverlapBucket {
                    multiplicity,
                    objects,
                })
            })
            .collect::<Vec<_>>();

        let mut seeds = Vec::new();
        seeds.try_reserve_exact(seed_addresses.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: seed_addresses.len(),
            }
        })?;
        let total_retained_nonseed_objects = membership.len();
        let mut population = HardPinSeedPopulation::default();
        for (index, address) in seed_addresses.iter().copied().enumerate() {
            let entry = forwarding
                .iter()
                .find(|entry| entry.source_address == address)
                .ok_or(EvalHeapError::ShedRejected {
                    address,
                    reason: "hard-pin seed census has no forwarding record",
                })?;
            let (storage, work, has_value_tail, physical_tail_free) =
                self.hard_pin_seed_classification(entry)?;
            match storage {
                "inline" => population.inline = population.inline.saturating_add(1),
                "shared" => population.shared = population.shared.saturating_add(1),
                "typed_head" => {
                    population.typed_head = population.typed_head.saturating_add(1);
                }
                _ => {}
            }
            match work {
                "node" => population.node = population.node.saturating_add(1),
                "released" => population.released = population.released.saturating_add(1),
                work if work.starts_with("synthetic_") => {
                    population.synthetic = population.synthetic.saturating_add(1);
                }
                _ => {}
            }
            if has_value_tail {
                population.with_value_tail = population.with_value_tail.saturating_add(1);
            }
            if physical_tail_free {
                population.physical_tail_free = population.physical_tail_free.saturating_add(1);
            }
            let bit = 1u64 << index;
            let exclusive_nonseed_objects =
                membership.values().filter(|mask| **mask == bit).count();
            let retained_without_seed = membership
                .values()
                .filter(|mask| (**mask & !bit) != 0)
                .count();
            seeds.push(HardPinSeedCensus {
                index,
                storage,
                work,
                has_value_tail,
                physical_tail_free,
                outgoing_edges: outgoing_counts[index],
                reachable_nonseed_objects: reachable_counts[index],
                exclusive_nonseed_objects,
                retained_without_seed,
            });
        }

        let contributor_mask =
            reachable_counts
                .iter()
                .enumerate()
                .fold(0u64, |mask, (index, count)| {
                    if *count == 0 {
                        mask
                    } else {
                        mask | (1u64 << index)
                    }
                });
        let contributing_seeds = contributor_mask.count_ones() as usize;
        let common_to_all_contributing_seeds = if contributor_mask == 0 {
            0
        } else {
            membership
                .values()
                .filter(|mask| (**mask & contributor_mask) == contributor_mask)
                .count()
        };

        let mut greedy_cut = Vec::new();
        greedy_cut
            .try_reserve_exact(contributing_seeds)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: contributing_seeds,
            })?;
        let mut active_mask = contributor_mask;
        let mut retained = total_retained_nonseed_objects;
        while active_mask != 0 {
            let mut uniquely_owned = vec![0usize; seed_addresses.len()];
            for mask in membership.values().copied() {
                let active_owners = mask & active_mask;
                if active_owners.count_ones() == 1 {
                    let owner = active_owners.trailing_zeros() as usize;
                    uniquely_owned[owner] = uniquely_owned[owner].saturating_add(1);
                }
            }
            let next_seed = (0..seed_addresses.len())
                .filter(|index| active_mask & (1u64 << index) != 0)
                .max_by_key(|index| (uniquely_owned[*index], usize::MAX - *index))
                .ok_or(EvalHeapError::ShedRejected {
                    address: active_mask as usize,
                    reason: "hard-pin greedy cut lost its active seed",
                })?;
            let newly_released_objects = uniquely_owned[next_seed];
            retained = retained.saturating_sub(newly_released_objects);
            active_mask &= !(1u64 << next_seed);
            greedy_cut.push(HardPinGreedyCutStep {
                cut_count: greedy_cut.len().saturating_add(1),
                seed_index: next_seed,
                newly_released_objects,
                retained_nonseed_objects: retained,
            });
        }

        Ok(HardPinSeedGraphCensus {
            seeds,
            population,
            overlap_histogram,
            contributing_seeds,
            minimum_full_collapse_cut: contributing_seeds,
            common_to_all_contributing_seeds,
            greedy_cut,
        })
    }

    /// Plans a deterministic dense destination for the weak-root reachable graph.
    ///
    /// The serial source heap remains immutable. Hash-cons indexes are weak and
    /// therefore do not seed traversal.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when the heap is shared, precise reachability
    /// finds a stale or malformed edge, a reachable address is absent from the
    /// serial storage registries, planner storage cannot grow, or dense-layout
    /// arithmetic overflows.
    pub(crate) fn evacuation_plan(
        &self,
        roots: &EvalRootSet,
    ) -> Result<EvacuationPlan, EvalHeapError> {
        self.evacuation_plan_with_hard_pin_seed_graph(
            roots,
            std::env::var(HARD_PIN_SEED_GRAPH_ENV).is_ok_and(|value| value == "1"),
        )
    }

    fn evacuation_plan_with_hard_pin_seed_graph(
        &self,
        roots: &EvalRootSet,
        hard_pin_seed_graph_enabled: bool,
    ) -> Result<EvacuationPlan, EvalHeapError> {
        if self.shared.is_some() {
            return Err(EvalHeapError::ShedRejected {
                address: 0,
                reason: "evacuation planning requires the serial heap",
            });
        }

        let preplan_current_rss_bytes = ProcessResidentMemorySample::current()
            .ok()
            .flatten()
            .map_or(0, ProcessResidentMemorySample::resident_bytes);
        let preplan_peak_rss_bytes =
            peak_resident_memory_bytes(PeakResidentMemoryScope::SelfProcess)
                .ok()
                .flatten()
                .and_then(|bytes| usize::try_from(bytes).ok())
                .unwrap_or(preplan_current_rss_bytes);
        let reachable = self.weak_reachable_addresses(roots)?;
        let mut objects = self.evacuation_source_objects(Some(&reachable))?;
        objects.sort_unstable_by_key(|(address, _)| *address);
        if objects.len() != reachable.len() || objects.windows(2).any(|pair| pair[0].0 == pair[1].0)
        {
            return Err(EvalHeapError::RootScanLengthOverflow {
                table: PLAN_OBJECTS_TABLE,
            });
        }
        objects.sort_unstable_by_key(|(address, object)| (object.lane, *address));

        let mut forwarding = Vec::new();
        forwarding.try_reserve_exact(objects.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PLAN_LAYOUT_TABLE,
                entries: objects.len(),
            }
        })?;
        let mut lane_bytes = [0usize; 4];
        let mut source_inline_bytes = 0usize;
        let mut known_external_bytes = 0usize;
        for (address, object) in objects {
            let lane = object.lane.index();
            let offset = align_up(lane_bytes[lane], object.align)?;
            lane_bytes[lane] = offset.checked_add(object.size_bytes).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_LAYOUT_TABLE,
                },
            )?;
            source_inline_bytes = source_inline_bytes.checked_add(object.size_bytes).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_LAYOUT_TABLE,
                },
            )?;
            known_external_bytes = known_external_bytes
                .checked_add(object.known_external_bytes)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_LAYOUT_TABLE,
                })?;
            forwarding.push(EvacuationForwarding {
                source_address: address,
                tag: object.tag,
                lane: object.lane,
                destination_offset: offset,
                size_bytes: object.size_bytes,
                align: object.align,
            });
        }
        let destination_inline_bytes =
            lane_bytes.into_iter().try_fold(0usize, |total, bytes| {
                total
                    .checked_add(bytes)
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: PLAN_LAYOUT_TABLE,
                    })
            })?;
        let mut direct_roots = HashSet::new();
        direct_roots.try_reserve(roots.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: roots.len(),
            }
        })?;
        for root in roots.roots() {
            let ptr = root.value().as_heap_ptr().map_err(EvalHeapError::Value)?;
            direct_roots.insert(ptr.as_ptr() as usize);
        }
        let direct_root_objects = direct_roots.len();
        let mut healable_pins = direct_roots.clone();
        let mut hard_pin_seeds = HashSet::new();
        hard_pin_seeds.try_reserve(forwarding.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: forwarding.len(),
            }
        })?;
        let mut pinned = HashSet::new();
        pinned.try_reserve(direct_roots.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: direct_roots.len(),
            }
        })?;
        pinned.extend(direct_roots.iter().copied());
        let mut pinned_tail_owner_objects = 0usize;
        let mut pinned_typed_head_objects = 0usize;
        let mut pinned_blackhole_objects = 0usize;
        for entry in &forwarding {
            if entry.lane == EvacuationLane::TypedThunkHeads {
                pinned_typed_head_objects = pinned_typed_head_objects.saturating_add(1);
                pinned.insert(entry.source_address);
                hard_pin_seeds.insert(entry.source_address);
                continue;
            }
            let kind = match entry.tag {
                ValueTag::Thunk => Some(FlatObjectKind::Thunk),
                ValueTag::Lambda => Some(FlatObjectKind::Lambda),
                ValueTag::Primop => Some(FlatObjectKind::Primop),
                _ => None,
            };
            let Some(kind) = kind else {
                continue;
            };
            let ptr = NonNull::new(entry.source_address as *mut HeapObject).ok_or(
                EvalHeapError::UnknownPointer {
                    tag: entry.tag,
                    address: entry.source_address,
                },
            )?;
            if entry.tag == ValueTag::Thunk
                && self
                    .flat_closure_payload_any(ptr)
                    .and_then(FlatClosurePayload::as_thunk)
                    .is_some_and(|thunk| thunk.cell().state().ok() == Some(ThunkState::Blackhole))
            {
                pinned_blackhole_objects = pinned_blackhole_objects.saturating_add(1);
                pinned.insert(entry.source_address);
                hard_pin_seeds.insert(entry.source_address);
            }
            if self
                .flat_closures
                .value_tail(ptr, kind)
                .map_err(|error| self.closure_resolution_error(entry.tag, ptr, error))?
                .is_some()
            {
                pinned_tail_owner_objects = pinned_tail_owner_objects.saturating_add(1);
                pinned.insert(entry.source_address);
                healable_pins.insert(entry.source_address);
            }
        }
        healable_pins.retain(|address| !hard_pin_seeds.contains(address));
        let healable_pin_objects = healable_pins.len();
        let residency = self.flat_reservation_residency().and_then(Result::ok);
        let page_bytes = residency.as_ref().map_or(4096, |sample| sample.page_size);
        let mut pinned_pages = HashSet::new();
        pinned_pages.try_reserve(pinned.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: pinned.len(),
            }
        })?;
        let mut scalar_regions = Vec::new();
        self.compressed_scalars
            .append_cell_regions(0, &mut scalar_regions);
        let mut scalar_pages = HashSet::new();
        for &(address, bytes) in &scalar_regions {
            mark_source_pages(&mut scalar_pages, address, bytes, page_bytes);
        }
        pinned_pages.extend(scalar_pages.iter().copied());
        let mut movable_lane_bytes = [0usize; 4];
        for entry in &forwarding {
            if pinned.contains(&entry.source_address) {
                mark_source_pages(
                    &mut pinned_pages,
                    entry.source_address,
                    entry.size_bytes,
                    page_bytes,
                );
                continue;
            }
            let lane = entry.lane.index();
            let offset = align_up(movable_lane_bytes[lane], entry.align)?;
            movable_lane_bytes[lane] = offset.checked_add(entry.size_bytes).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_LAYOUT_TABLE,
                },
            )?;
        }
        let movable_destination_inline_bytes =
            movable_lane_bytes
                .into_iter()
                .try_fold(0usize, |total, bytes| {
                    total
                        .checked_add(bytes)
                        .ok_or(EvalHeapError::RootScanLengthOverflow {
                            table: PLAN_LAYOUT_TABLE,
                        })
                })?;
        let source_reservation_resident_bytes = residency.as_ref().map_or(0, |sample| {
            sample.total_resident_pages.saturating_mul(sample.page_size)
        });
        let movable_destination_page_bytes =
            movable_lane_bytes
                .into_iter()
                .try_fold(0usize, |total, bytes| {
                    let rounded = page_round_up(bytes, page_bytes)?;
                    total
                        .checked_add(rounded)
                        .ok_or(EvalHeapError::RootScanLengthOverflow {
                            table: PLAN_LAYOUT_TABLE,
                        })
                })?;
        let post_commit_reservation_bytes = pinned_pages
            .len()
            .checked_mul(page_bytes)
            .and_then(|bytes| bytes.checked_add(movable_destination_page_bytes))
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PLAN_LAYOUT_TABLE,
            })?;
        let registry_entry_bytes = std::mem::size_of::<usize>() * 2;
        let registry_current_bytes = [
            self.flat.registry_capacity(),
            self.flat_lists.registry_capacity(),
            self.flat_attrs.registry_capacity(),
            self.flat_closures.registry_capacity(),
        ]
        .into_iter()
        .try_fold(0usize, |total, capacity| {
            total
                .checked_add(capacity.saturating_mul(registry_entry_bytes))
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_LAYOUT_TABLE,
                })
        })?;
        let registry_live_entries = forwarding
            .iter()
            .filter(|entry| {
                matches!(
                    entry.lane,
                    EvacuationLane::PermanentFlat | EvacuationLane::WorkerFlat
                )
            })
            .count();
        let registry_live_bytes = registry_live_entries
            .checked_mul(registry_entry_bytes)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PLAN_LAYOUT_TABLE,
            })?;
        let (hash_current_bytes, hash_live_bytes) = evacuation_hash_storage(self, &reachable)?;
        let reachable_frames = self.evacuation_frame_population(Some(&reachable));
        let frame_staging_upper_bytes = evacuation_frame_staging_upper_bytes(reachable_frames)?;
        let current_writer_staging_upper_bytes = evacuation_current_writer_staging_upper_bytes(
            reachable.len(),
            known_external_bytes,
            registry_live_bytes,
            hash_live_bytes,
            frame_staging_upper_bytes,
        )?;
        let compact_scratch_bytes = reachable
            .len()
            .checked_mul(12)
            .and_then(|bytes| bytes.checked_add(reachable.len().div_ceil(8)))
            .and_then(|bytes| bytes.checked_add(pinned_pages.len().div_ceil(8)))
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PLAN_LAYOUT_TABLE,
            })?;
        let reservation_stats = self.flat_arena.reservation_stats();
        let full_copy_new_page_bytes = reservation_stats
            .map(|stats| {
                let low_destination_bytes = movable_lane_bytes
                    [EvacuationLane::PermanentFlat.index()]
                .saturating_add(movable_lane_bytes[EvacuationLane::TypedThunkHeads.index()]);
                let high_destination_bytes = movable_lane_bytes[EvacuationLane::WorkerFlat.index()];
                let old_low_pages = stats.low_used_bytes.div_ceil(page_bytes);
                let new_low_pages = stats
                    .low_used_bytes
                    .saturating_add(low_destination_bytes)
                    .div_ceil(page_bytes);
                let old_high_pages = stats.high_used_bytes.div_ceil(page_bytes);
                let new_high_pages = stats
                    .high_used_bytes
                    .saturating_add(high_destination_bytes)
                    .div_ceil(page_bytes);
                new_low_pages
                    .saturating_sub(old_low_pages)
                    .saturating_add(new_high_pages.saturating_sub(old_high_pages))
                    .saturating_mul(page_bytes)
            })
            .unwrap_or(movable_destination_page_bytes);
        let current_writer_scratch_committed_bytes = page_round_up(
            compact_scratch_bytes
                .checked_add(current_writer_staging_upper_bytes)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_LAYOUT_TABLE,
                })?,
            page_bytes,
        )?;
        let full_copy_peak_upper_bytes = preplan_current_rss_bytes
            .saturating_add(full_copy_new_page_bytes)
            .saturating_add(current_writer_scratch_committed_bytes)
            .max(preplan_peak_rss_bytes);
        let full_copy_headroom_bytes =
            ACCEPTANCE_RSS_BYTES.saturating_sub(full_copy_peak_upper_bytes);
        let full_copy_excess_bytes =
            full_copy_peak_upper_bytes.saturating_sub(ACCEPTANCE_RSS_BYTES);
        let mut edges = 0usize;
        let mut exact_graph = HashMap::new();
        exact_graph.try_reserve(forwarding.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: forwarding.len(),
            }
        })?;
        let mut flat_thunks = EvacuationFlatThunkPopulation::default();
        let mut first_slice = EvacuationFirstSliceAccounting::default();
        let mut primop_lambda_addresses = Vec::new();
        let mut alias_forwarded_primop_lambda_addresses = Vec::new();
        let mut permanent_string_addresses = Vec::new();
        let mut permanent_owned_string_addresses = Vec::new();
        let mut permanent_path_addresses = Vec::new();
        let mut permanent_owned_path_addresses = Vec::new();
        let mut permanent_owned_strings_paths_addresses = Vec::new();
        let mut permanent_list_addresses = Vec::new();
        let mut permanent_attrs_addresses = Vec::new();
        let mut permanent_owned_attrs_addresses = Vec::new();
        let mut permanent_strings_paths_addresses = Vec::new();
        let mut permanent_strings_paths_lists_addresses = Vec::new();
        let mut current_mover_permanent_addresses = Vec::new();
        let mut excluded_inline_permanent_addresses = Vec::new();
        let mut permanent_flat_addresses = Vec::new();
        let mut forced_tail_free_flat_thunk_addresses = Vec::new();
        for entry in &forwarding {
            let ptr = NonNull::new(entry.source_address as *mut HeapObject).ok_or(
                EvalHeapError::UnknownPointer {
                    tag: entry.tag,
                    address: entry.source_address,
                },
            )?;
            let mut is_plain_primop = false;
            let mut is_plain_lambda = false;
            let mut is_rejected_tail_free_lambda = false;
            let mut is_forced_tail_free_flat_thunk = false;
            let object_edges = if let Some(edges) = self.scan_typed_thunk_edges(ptr)? {
                if entry.tag != ValueTag::Thunk {
                    return Err(EvalHeapError::record_type_mismatch(
                        entry.tag,
                        ValueTag::Thunk,
                        ptr,
                    ));
                }
                edges
            } else if matches!(entry.tag, ValueTag::String | ValueTag::Path) {
                self.flat_verify(entry.tag, ptr)?;
                Vec::new()
            } else if entry.tag == ValueTag::List {
                self.scan_flat_list_edges(self.flat_list_payload(ptr)?)?
            } else if entry.tag == ValueTag::Attrs {
                self.scan_flat_attrs_edges(self.flat_attrs_payload(ptr)?)?
            } else if let Some(payload) = self.flat_closure_payload_any(ptr) {
                if payload.tag() != entry.tag {
                    return Err(EvalHeapError::record_type_mismatch(
                        entry.tag,
                        payload.tag(),
                        ptr,
                    ));
                }
                if entry.tag == ValueTag::Thunk {
                    match payload {
                        FlatClosurePayload::Thunk(_) => {
                            flat_thunks.inline = flat_thunks.inline.saturating_add(1)
                        }
                        FlatClosurePayload::SharedThunk(_) => {
                            flat_thunks.shared = flat_thunks.shared.saturating_add(1)
                        }
                        FlatClosurePayload::Lambda(_)
                        | FlatClosurePayload::Primop(_)
                        | FlatClosurePayload::Retired(_) => {}
                    }
                    let thunk = payload.as_thunk().ok_or(EvalHeapError::ShedRejected {
                        address: entry.source_address,
                        reason: "evacuation thunk population lost its thunk payload",
                    })?;
                    let state = thunk.cell().state().map_err(EvalHeapError::Thunk)?;
                    match state {
                        ThunkState::Suspended => {
                            flat_thunks.suspended = flat_thunks.suspended.saturating_add(1)
                        }
                        ThunkState::Forced => {
                            flat_thunks.forced = flat_thunks.forced.saturating_add(1)
                        }
                        ThunkState::Blackhole => {
                            flat_thunks.blackhole = flat_thunks.blackhole.saturating_add(1);
                            if pinned.contains(&entry.source_address) {
                                flat_thunks.pinned_blackhole =
                                    flat_thunks.pinned_blackhole.saturating_add(1);
                            }
                        }
                    }
                    match thunk.kind() {
                        EvalThunkKind::Node { .. } => {
                            flat_thunks.node = flat_thunks.node.saturating_add(1)
                        }
                        EvalThunkKind::Released => {
                            flat_thunks.released = flat_thunks.released.saturating_add(1)
                        }
                        EvalThunkKind::Apply { .. }
                        | EvalThunkKind::GenListElemAtAddOne { .. }
                        | EvalThunkKind::Apply2(_)
                        | EvalThunkKind::Select { .. }
                        | EvalThunkKind::BuiltinAttr { .. } => {
                            flat_thunks.synthetic = flat_thunks.synthetic.saturating_add(1)
                        }
                    }
                    let has_value_tail = self
                        .flat_closures
                        .value_tail(ptr, FlatObjectKind::Thunk)
                        .map_err(|error| {
                            self.closure_resolution_error(ValueTag::Thunk, ptr, error)
                        })?
                        .is_some();
                    if has_value_tail {
                        flat_thunks.with_value_tail = flat_thunks.with_value_tail.saturating_add(1);
                    }
                    let physical_tail_free = self
                        .flat_closures
                        .is_plain_relocation_source(ptr, FlatObjectKind::Thunk)
                        .map_err(|error| {
                            self.closure_resolution_error(ValueTag::Thunk, ptr, error)
                        })?;
                    if plain_node_thunk_movable(payload, physical_tail_free) {
                        flat_thunks.plain_node_movable =
                            flat_thunks.plain_node_movable.saturating_add(1);
                        flat_thunks.plain_node_movable_inline_bytes = flat_thunks
                            .plain_node_movable_inline_bytes
                            .checked_add(entry.size_bytes)
                            .ok_or(EvalHeapError::RootScanLengthOverflow {
                                table: PLAN_LAYOUT_TABLE,
                            })?;
                    }
                    is_forced_tail_free_flat_thunk = state == ThunkState::Forced && !has_value_tail;
                } else if entry.tag == ValueTag::Primop {
                    is_plain_primop = self
                        .flat_closures
                        .value_tail(ptr, FlatObjectKind::Primop)
                        .map_err(|error| {
                            self.closure_resolution_error(ValueTag::Primop, ptr, error)
                        })?
                        .is_none();
                } else if entry.tag == ValueTag::Lambda {
                    let is_tail_free = self
                        .flat_closures
                        .value_tail(ptr, FlatObjectKind::Lambda)
                        .map_err(|error| {
                            self.closure_resolution_error(ValueTag::Lambda, ptr, error)
                        })?
                        .is_none();
                    let has_plain_capture_shape = matches!(
                        payload,
                        FlatClosurePayload::Lambda(lambda)
                            if lambda.with_scope_env().is_empty()
                                && lambda.scoped_global_env().is_empty()
                                && lambda.env().flat_base().is_none()
                    );
                    is_plain_lambda = is_tail_free && has_plain_capture_shape;
                    is_rejected_tail_free_lambda = is_tail_free && !has_plain_capture_shape;
                }
                self.scan_flat_closure_edges(ptr, payload)?
            } else {
                let record = self.record_or_unknown(entry.tag, ptr)?;
                if record.object.tag() != entry.tag {
                    return Err(EvalHeapError::record_type_mismatch(
                        entry.tag,
                        record.object.tag(),
                        ptr,
                    ));
                }
                self.scan_record_edges(record)?
            };
            for edge in &object_edges {
                let address = edge
                    .value()
                    .as_heap_ptr()
                    .map_err(EvalHeapError::Value)?
                    .as_ptr() as usize;
                if !reachable.contains(&address) {
                    return Err(EvalHeapError::UnknownPointer {
                        tag: edge.value().tag(),
                        address,
                    });
                }
            }
            let mut outgoing = Vec::new();
            outgoing
                .try_reserve_exact(object_edges.len())
                .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                    table: PLAN_OBJECTS_TABLE,
                    entries: object_edges.len(),
                })?;
            for edge in &object_edges {
                outgoing.push(
                    edge.value()
                        .as_heap_ptr()
                        .map_err(EvalHeapError::Value)?
                        .as_ptr() as usize,
                );
            }
            if exact_graph
                .insert(entry.source_address, (entry.size_bytes, outgoing))
                .is_some()
            {
                return Err(EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_OBJECTS_TABLE,
                });
            }
            let object_edge_count = object_edges.len();
            let is_direct_root = direct_roots.contains(&entry.source_address);
            let is_pinned = pinned.contains(&entry.source_address);
            if is_plain_primop {
                first_slice.plain_primops.record(
                    entry,
                    object_edge_count,
                    is_direct_root,
                    is_pinned,
                )?;
                first_slice.primop_lambda.record(
                    entry,
                    object_edge_count,
                    is_direct_root,
                    is_pinned,
                )?;
                if !is_pinned {
                    primop_lambda_addresses.push(entry.source_address);
                }
                first_slice.alias_forwarded_primop_lambda.record(
                    entry,
                    object_edge_count,
                    is_direct_root,
                    false,
                )?;
                alias_forwarded_primop_lambda_addresses.push(entry.source_address);
            } else if is_plain_lambda {
                first_slice.plain_lambdas.record(
                    entry,
                    object_edge_count,
                    is_direct_root,
                    is_pinned,
                )?;
                first_slice.primop_lambda.record(
                    entry,
                    object_edge_count,
                    is_direct_root,
                    is_pinned,
                )?;
                if !is_pinned {
                    primop_lambda_addresses.push(entry.source_address);
                }
                first_slice.alias_forwarded_primop_lambda.record(
                    entry,
                    object_edge_count,
                    is_direct_root,
                    false,
                )?;
                alias_forwarded_primop_lambda_addresses.push(entry.source_address);
            } else if is_rejected_tail_free_lambda {
                first_slice.rejected_tail_free_lambdas.record(
                    entry,
                    object_edge_count,
                    is_direct_root,
                    is_pinned,
                )?;
            }
            if matches!(
                entry.tag,
                ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
            ) {
                let mut is_owned_string_or_path = false;
                let mut is_current_mover_permanent = false;
                let mut is_excluded_inline_permanent = false;
                match entry.tag {
                    ValueTag::String => {
                        let storage_kind = self
                            .flat
                            .resolve(ptr, FlatObjectKind::String)
                            .map_err(|error| {
                                self.flat_resolution_error(ValueTag::String, ptr, error)
                            })?
                            .payload()
                            .bytes_storage_kind();
                        if storage_kind == StringBytesStorageKind::Owned {
                            is_owned_string_or_path = true;
                            is_current_mover_permanent = true;
                            first_slice.permanent_owned_strings.record(
                                entry,
                                object_edge_count,
                                is_direct_root,
                                is_pinned,
                            )?;
                            first_slice.permanent_owned_strings_paths.record(
                                entry,
                                object_edge_count,
                                is_direct_root,
                                is_pinned,
                            )?;
                        } else {
                            is_excluded_inline_permanent = true;
                            first_slice.permanent_inline_strings.record(
                                entry,
                                object_edge_count,
                                is_direct_root,
                                is_pinned,
                            )?;
                        }
                        first_slice.permanent_strings.record(
                            entry,
                            object_edge_count,
                            is_direct_root,
                            is_pinned,
                        )?;
                        first_slice.permanent_strings_paths.record(
                            entry,
                            object_edge_count,
                            is_direct_root,
                            is_pinned,
                        )?;
                        first_slice.permanent_strings_paths_lists.record(
                            entry,
                            object_edge_count,
                            is_direct_root,
                            is_pinned,
                        )?;
                    }
                    ValueTag::Path => {
                        let storage_kind = self
                            .flat
                            .resolve(ptr, FlatObjectKind::Path)
                            .map_err(|error| {
                                self.flat_resolution_error(ValueTag::Path, ptr, error)
                            })?
                            .payload()
                            .bytes_storage_kind();
                        if storage_kind == StringBytesStorageKind::Owned {
                            is_owned_string_or_path = true;
                            is_current_mover_permanent = true;
                            first_slice.permanent_owned_paths.record(
                                entry,
                                object_edge_count,
                                is_direct_root,
                                is_pinned,
                            )?;
                            first_slice.permanent_owned_strings_paths.record(
                                entry,
                                object_edge_count,
                                is_direct_root,
                                is_pinned,
                            )?;
                        } else {
                            is_excluded_inline_permanent = true;
                            first_slice.permanent_inline_paths.record(
                                entry,
                                object_edge_count,
                                is_direct_root,
                                is_pinned,
                            )?;
                        }
                        first_slice.permanent_paths.record(
                            entry,
                            object_edge_count,
                            is_direct_root,
                            is_pinned,
                        )?;
                        first_slice.permanent_strings_paths.record(
                            entry,
                            object_edge_count,
                            is_direct_root,
                            is_pinned,
                        )?;
                        first_slice.permanent_strings_paths_lists.record(
                            entry,
                            object_edge_count,
                            is_direct_root,
                            is_pinned,
                        )?;
                    }
                    ValueTag::List => {
                        is_current_mover_permanent = true;
                        first_slice.permanent_lists.record(
                            entry,
                            object_edge_count,
                            is_direct_root,
                            is_pinned,
                        )?;
                        first_slice.permanent_strings_paths_lists.record(
                            entry,
                            object_edge_count,
                            is_direct_root,
                            is_pinned,
                        )?;
                    }
                    ValueTag::Attrs => {
                        let storage_kind = self
                            .flat_attrs
                            .resolve(ptr, FlatObjectKind::Attrs)
                            .map_err(|error| {
                                self.flat_resolution_error(ValueTag::Attrs, ptr, error)
                            })?
                            .payload()
                            .attrs
                            .storage_kind();
                        if storage_kind == AttrsStorageKind::Owned {
                            is_current_mover_permanent = true;
                            first_slice.permanent_owned_attrs.record(
                                entry,
                                object_edge_count,
                                is_direct_root,
                                is_pinned,
                            )?;
                        } else {
                            is_excluded_inline_permanent = true;
                            first_slice.permanent_inline_attrs.record(
                                entry,
                                object_edge_count,
                                is_direct_root,
                                is_pinned,
                            )?;
                        }
                        first_slice.permanent_attrs.record(
                            entry,
                            object_edge_count,
                            is_direct_root,
                            is_pinned,
                        )?;
                    }
                    _ => {}
                }
                if is_current_mover_permanent {
                    first_slice.current_mover_permanent.record(
                        entry,
                        object_edge_count,
                        is_direct_root,
                        is_pinned,
                    )?;
                }
                if is_excluded_inline_permanent {
                    first_slice.excluded_inline_permanent.record(
                        entry,
                        object_edge_count,
                        is_direct_root,
                        is_pinned,
                    )?;
                }
                first_slice.permanent_flat.record(
                    entry,
                    object_edge_count,
                    is_direct_root,
                    is_pinned,
                )?;
                if !is_pinned {
                    if is_current_mover_permanent {
                        current_mover_permanent_addresses.push(entry.source_address);
                    }
                    if is_excluded_inline_permanent {
                        excluded_inline_permanent_addresses.push(entry.source_address);
                    }
                    match entry.tag {
                        ValueTag::String => {
                            permanent_string_addresses.push(entry.source_address);
                            if is_owned_string_or_path {
                                permanent_owned_string_addresses.push(entry.source_address);
                                permanent_owned_strings_paths_addresses.push(entry.source_address);
                            }
                            permanent_strings_paths_addresses.push(entry.source_address);
                            permanent_strings_paths_lists_addresses.push(entry.source_address);
                        }
                        ValueTag::Path => {
                            permanent_path_addresses.push(entry.source_address);
                            if is_owned_string_or_path {
                                permanent_owned_path_addresses.push(entry.source_address);
                                permanent_owned_strings_paths_addresses.push(entry.source_address);
                            }
                            permanent_strings_paths_addresses.push(entry.source_address);
                            permanent_strings_paths_lists_addresses.push(entry.source_address);
                        }
                        ValueTag::List => {
                            permanent_list_addresses.push(entry.source_address);
                            permanent_strings_paths_lists_addresses.push(entry.source_address);
                        }
                        ValueTag::Attrs => {
                            permanent_attrs_addresses.push(entry.source_address);
                            if is_current_mover_permanent {
                                permanent_owned_attrs_addresses.push(entry.source_address);
                            }
                        }
                        _ => {}
                    }
                    permanent_flat_addresses.push(entry.source_address);
                }
            }
            if is_forced_tail_free_flat_thunk {
                first_slice.forced_tail_free_flat_thunks.record(
                    entry,
                    object_edge_count,
                    is_direct_root,
                    is_pinned,
                )?;
                if !is_pinned {
                    forced_tail_free_flat_thunk_addresses.push(entry.source_address);
                }
            }
            edges = edges.checked_add(object_edges.len()).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_OBJECTS_TABLE,
                },
            )?;
        }
        let mut hard_pin_retained = HashSet::new();
        hard_pin_retained
            .try_reserve(hard_pin_seeds.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: hard_pin_seeds.len(),
            })?;
        hard_pin_retained.extend(hard_pin_seeds.iter().copied());
        let mut hard_pin_worklist = Vec::new();
        hard_pin_worklist
            .try_reserve_exact(hard_pin_seeds.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: hard_pin_seeds.len(),
            })?;
        hard_pin_worklist.extend(hard_pin_seeds.iter().copied());
        while let Some(address) = hard_pin_worklist.pop() {
            let (_, outgoing) = exact_graph
                .get(&address)
                .ok_or(EvalHeapError::ShedRejected {
                    address,
                    reason: "hard-pin traversal seed is absent from the exact reachable graph",
                })?;
            for child in outgoing {
                if hard_pin_retained.insert(*child) {
                    hard_pin_worklist.push(*child);
                }
            }
        }
        let hard_pin_seed_objects = hard_pin_seeds.len();
        let hard_pin_retained_objects = hard_pin_retained.len();
        let hard_pin_transitive_retained_objects =
            hard_pin_retained_objects.saturating_sub(hard_pin_seed_objects);
        let hard_pin_seed_graph = if hard_pin_seed_graph_enabled {
            Some(self.hard_pin_seed_graph_census(&hard_pin_seeds, &exact_graph, &forwarding)?)
        } else {
            None
        };
        let mut hard_pin_retained_inline_bytes = 0usize;
        let mut hard_pin_source_pages = HashSet::new();
        hard_pin_source_pages
            .try_reserve(hard_pin_retained_objects)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: hard_pin_retained_objects,
            })?;
        for address in &hard_pin_retained {
            let (size_bytes, _) = exact_graph
                .get(address)
                .ok_or(EvalHeapError::ShedRejected {
                    address: *address,
                    reason: "hard-pin traversal reached an object absent from the exact graph",
                })?;
            hard_pin_retained_inline_bytes = hard_pin_retained_inline_bytes
                .checked_add(*size_bytes)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_OBJECTS_TABLE,
                })?;
            let ptr =
                NonNull::new(*address as *mut HeapObject).ok_or(EvalHeapError::UnknownPointer {
                    tag: ValueTag::Thunk,
                    address: *address,
                })?;
            match (residency.is_some(), self.flat_arena.index_for_pointer(ptr)) {
                (_, Some(index)) => hard_pin_source_pages.extend(page_interval(
                    index.raw() as usize,
                    *size_bytes,
                    page_bytes,
                )),
                (false, None) => {
                    hard_pin_source_pages.extend(page_interval(*address, *size_bytes, page_bytes));
                }
                (true, None) => {
                    return Err(EvalHeapError::ShedRejected {
                        address: *address,
                        reason: "hard-pin object is outside the sampled source reservation",
                    });
                }
            }
        }
        let hard_pin_unique_resident_source_pages = if residency.is_some() {
            let mut resident_pages = 0usize;
            for page in &hard_pin_source_pages {
                let offset = page
                    .checked_mul(page_bytes)
                    .and_then(|offset| u32::try_from(offset).ok())
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: PLAN_LAYOUT_TABLE,
                    })?;
                match self
                    .flat_arena
                    .page_is_resident_at_index(crate::heap::ArenaIndex::new(offset))
                {
                    Some(Ok(true)) => resident_pages = resident_pages.saturating_add(1),
                    Some(Ok(false)) => {}
                    Some(Err(_)) | None => {
                        return Err(EvalHeapError::ShedRejected {
                            address: 0,
                            reason: "hard-pin source-page residency query failed",
                        });
                    }
                }
            }
            resident_pages
        } else {
            hard_pin_source_pages.len()
        };
        primop_lambda_addresses.sort_unstable();
        alias_forwarded_primop_lambda_addresses.sort_unstable();
        permanent_string_addresses.sort_unstable();
        permanent_owned_string_addresses.sort_unstable();
        permanent_path_addresses.sort_unstable();
        permanent_owned_path_addresses.sort_unstable();
        permanent_owned_strings_paths_addresses.sort_unstable();
        permanent_list_addresses.sort_unstable();
        permanent_attrs_addresses.sort_unstable();
        permanent_owned_attrs_addresses.sort_unstable();
        permanent_strings_paths_addresses.sort_unstable();
        permanent_strings_paths_lists_addresses.sort_unstable();
        current_mover_permanent_addresses.sort_unstable();
        excluded_inline_permanent_addresses.sort_unstable();
        permanent_flat_addresses.sort_unstable();
        forced_tail_free_flat_thunk_addresses.sort_unstable();
        let slice_pages = self.evacuation_slice_page_projections(
            &reachable,
            [
                &primop_lambda_addresses,
                &alias_forwarded_primop_lambda_addresses,
                &permanent_string_addresses,
                &permanent_owned_string_addresses,
                &permanent_path_addresses,
                &permanent_owned_path_addresses,
                &permanent_owned_strings_paths_addresses,
                &permanent_list_addresses,
                &permanent_attrs_addresses,
                &permanent_owned_attrs_addresses,
                &permanent_strings_paths_addresses,
                &permanent_strings_paths_lists_addresses,
                &current_mover_permanent_addresses,
                &excluded_inline_permanent_addresses,
                &permanent_flat_addresses,
                &forced_tail_free_flat_thunk_addresses,
            ],
            [
                first_slice.primop_lambda.movable_destination_inline_bytes,
                first_slice
                    .alias_forwarded_primop_lambda
                    .movable_destination_inline_bytes,
                first_slice
                    .permanent_strings
                    .movable_destination_inline_bytes,
                first_slice
                    .permanent_owned_strings
                    .movable_destination_inline_bytes,
                first_slice.permanent_paths.movable_destination_inline_bytes,
                first_slice
                    .permanent_owned_paths
                    .movable_destination_inline_bytes,
                first_slice
                    .permanent_owned_strings_paths
                    .movable_destination_inline_bytes,
                first_slice.permanent_lists.movable_destination_inline_bytes,
                first_slice.permanent_attrs.movable_destination_inline_bytes,
                first_slice
                    .permanent_owned_attrs
                    .movable_destination_inline_bytes,
                first_slice
                    .permanent_strings_paths
                    .movable_destination_inline_bytes,
                first_slice
                    .permanent_strings_paths_lists
                    .movable_destination_inline_bytes,
                first_slice
                    .current_mover_permanent
                    .movable_destination_inline_bytes,
                first_slice
                    .excluded_inline_permanent
                    .movable_destination_inline_bytes,
                first_slice.permanent_flat.movable_destination_inline_bytes,
                first_slice
                    .forced_tail_free_flat_thunks
                    .movable_destination_inline_bytes,
            ],
            page_bytes,
        )?;
        first_slice.primop_lambda_pages = slice_pages[0];
        first_slice.alias_forwarded_primop_lambda_pages = slice_pages[1];
        first_slice.permanent_string_pages = slice_pages[2];
        first_slice.permanent_owned_string_pages = slice_pages[3];
        first_slice.permanent_path_pages = slice_pages[4];
        first_slice.permanent_owned_path_pages = slice_pages[5];
        first_slice.permanent_owned_strings_paths_pages = slice_pages[6];
        first_slice.permanent_list_pages = slice_pages[7];
        first_slice.permanent_attrs_pages = slice_pages[8];
        first_slice.permanent_owned_attrs_pages = slice_pages[9];
        first_slice.permanent_strings_paths_pages = slice_pages[10];
        first_slice.permanent_strings_paths_lists_pages = slice_pages[11];
        first_slice.current_mover_permanent_pages = slice_pages[12];
        first_slice.excluded_inline_permanent_pages = slice_pages[13];
        first_slice.permanent_flat_pages = slice_pages[14];
        first_slice.forced_tail_free_flat_thunk_pages = slice_pages[15];
        let page_stream = self.evacuation_page_streaming_projection(
            &reachable,
            &forwarding,
            &pinned,
            movable_lane_bytes,
            page_bytes,
            page_round_up(compact_scratch_bytes, page_bytes)?,
            preplan_current_rss_bytes,
            preplan_peak_rss_bytes,
        )?;
        let total_frames = self.evacuation_frame_population(None);

        Ok(EvacuationPlan {
            forwarding,
            accounting: EvacuationPlanAccounting {
                roots: roots.len(),
                objects: reachable.len(),
                edges,
                source_inline_bytes,
                known_external_bytes,
                destination_inline_bytes,
                lane_bytes,
                direct_root_objects,
                pinned_objects: pinned.len(),
                pinned_tail_owner_objects,
                pinned_typed_head_objects,
                pinned_blackhole_objects,
                pinned_pages: pinned_pages.len(),
                pinned_scalar_pages: scalar_pages.len(),
                healable_pin_objects,
                hard_pin_seed_objects,
                hard_pin_transitive_retained_objects,
                hard_pin_retained_objects,
                hard_pin_retained_inline_bytes,
                hard_pin_unique_resident_source_pages,
                movable_destination_inline_bytes,
                flat_thunks,
                source_reservation_resident_bytes,
                post_commit_reservation_bytes,
                registry_current_bytes,
                registry_live_bytes,
                hash_current_bytes,
                hash_live_bytes,
                compact_scratch_bytes,
                frame_staging_upper_bytes,
                current_writer_staging_upper_bytes,
                preplan_current_rss_bytes,
                preplan_peak_rss_bytes,
                full_copy_new_page_bytes,
                full_copy_peak_upper_bytes,
                full_copy_headroom_bytes,
                full_copy_excess_bytes,
                page_stream_source_pages: page_stream.source_pages,
                page_stream_resident_source_pages: page_stream.resident_source_pages,
                page_stream_dead_phase_released_pages: page_stream.dead_phase_released_pages,
                page_stream_destination_pages: page_stream.destination_pages,
                page_stream_released_source_pages: page_stream.released_source_pages,
                page_stream_peak_net_pages: page_stream.peak_net_pages,
                page_stream_peak_upper_bytes: page_stream.peak_upper_bytes,
                page_stream_headroom_bytes: page_stream.headroom_bytes,
                page_stream_excess_bytes: page_stream.excess_bytes,
                first_slice,
                reachable_frames,
                total_frames,
            },
            hard_pin_seed_graph,
        })
    }

    fn evacuation_frame_population(&self, reachable: Option<&HashSet<usize>>) -> FramePopulation {
        let mut population = FramePopulation::default();
        let mut seen = HashSet::<*const EvalFrame>::new();
        for object in self.flat_closures.iter() {
            let address = object.ptr().as_ptr() as usize;
            if reachable.is_some_and(|reachable| !reachable.contains(&address)) {
                continue;
            }
            let env = match object.object().payload() {
                FlatClosurePayload::Thunk(thunk) => thunk.env(),
                FlatClosurePayload::SharedThunk(thunk) => thunk.env(),
                FlatClosurePayload::Lambda(lambda) => Some(lambda.env()),
                FlatClosurePayload::Primop(_) | FlatClosurePayload::Retired(_) => None,
            };
            let Some(env) = env else {
                continue;
            };
            for frame in env.frames().iter() {
                population.references = population.references.saturating_add(1);
                if !seen.insert(Arc::as_ptr(frame)) {
                    continue;
                }
                population.distinct = population.distinct.saturating_add(1);
                let slots = frame.slot_count();
                population.slots = population.slots.saturating_add(slots);
                if slots > EvalFrame::inline_slot_capacity() {
                    population.heap_backed = population.heap_backed.saturating_add(1);
                    population.heap_backed_slots =
                        population.heap_backed_slots.saturating_add(slots);
                }
            }
        }
        population.modeled_bytes = population
            .distinct
            .saturating_mul(
                std::mem::size_of::<EvalFrame>().saturating_add(2 * std::mem::size_of::<usize>()),
            )
            .saturating_add(
                population
                    .heap_backed_slots
                    .saturating_mul(std::mem::size_of::<crate::eval::env::AtomicValueCell>()),
            );
        population
    }

    /// Projects page release for three bounded object selections after one
    /// shared unreachable-object prepass.
    fn evacuation_slice_page_projections<const N: usize>(
        &self,
        reachable: &HashSet<usize>,
        selections: [&[usize]; N],
        destination_inline_bytes: [usize; N],
        page_bytes: usize,
    ) -> Result<[EvacuationSlicePageProjection; N], EvalHeapError> {
        let mut all_objects = self.evacuation_source_objects(None)?;
        all_objects.sort_unstable_by_key(|(address, _)| *address);

        let mut remaining = HashMap::<usize, usize>::new();
        for (address, object) in &all_objects {
            let Some(index) = self.flat_arena.index_for_pointer(
                NonNull::new(*address as *mut HeapObject).ok_or(EvalHeapError::UnknownPointer {
                    tag: object.tag,
                    address: *address,
                })?,
            ) else {
                continue;
            };
            for page in page_interval(index.raw() as usize, object.size_bytes, page_bytes) {
                *remaining.entry(page).or_insert(0) += 1;
            }
        }
        let mut scalar_regions = Vec::new();
        self.compressed_scalars
            .append_cell_regions(0, &mut scalar_regions);
        for (address, bytes) in scalar_regions {
            let Some(index) =
                self.flat_arena
                    .index_for_pointer(NonNull::new(address as *mut HeapObject).ok_or(
                        EvalHeapError::UnknownPointer {
                            tag: ValueTag::Int,
                            address,
                        },
                    )?)
            else {
                continue;
            };
            for page in page_interval(index.raw() as usize, bytes, page_bytes) {
                *remaining.entry(page).or_insert(0) += 1;
            }
        }

        let mut resident_source_pages = HashSet::new();
        resident_source_pages
            .try_reserve(remaining.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: PLAN_LAYOUT_TABLE,
                entries: remaining.len(),
            })?;
        for page in remaining.keys().copied() {
            let offset = page
                .checked_mul(page_bytes)
                .and_then(|offset| u32::try_from(offset).ok())
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_LAYOUT_TABLE,
                })?;
            if self
                .flat_arena
                .page_is_resident_at_index(crate::heap::ArenaIndex::new(offset))
                .and_then(Result::ok)
                .unwrap_or(false)
            {
                resident_source_pages.insert(page);
            }
        }

        let mut dead_released = HashSet::new();
        dead_released
            .try_reserve(resident_source_pages.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: PLAN_LAYOUT_TABLE,
                entries: resident_source_pages.len(),
            })?;
        for (address, object) in &all_objects {
            if reachable.contains(address) {
                continue;
            }
            decrement_source_page_counts(
                &mut remaining,
                &resident_source_pages,
                &mut dead_released,
                self.flat_arena.index_for_pointer(
                    NonNull::new(*address as *mut HeapObject).ok_or(
                        EvalHeapError::UnknownPointer {
                            tag: object.tag,
                            address: *address,
                        },
                    )?,
                ),
                object.size_bytes,
                page_bytes,
            );
        }

        let mut projections = [EvacuationSlicePageProjection::default(); N];
        for selection_index in 0..selections.len() {
            let selection = selections[selection_index];
            let mut selected_remaining = remaining.clone();
            let mut selected_released = dead_released.clone();
            for (address, object) in &all_objects {
                if selection.binary_search(address).is_err() {
                    continue;
                }
                decrement_source_page_counts(
                    &mut selected_remaining,
                    &resident_source_pages,
                    &mut selected_released,
                    self.flat_arena.index_for_pointer(
                        NonNull::new(*address as *mut HeapObject).ok_or(
                            EvalHeapError::UnknownPointer {
                                tag: object.tag,
                                address: *address,
                            },
                        )?,
                    ),
                    object.size_bytes,
                    page_bytes,
                );
            }
            let additional_released_pages =
                selected_released.len().saturating_sub(dead_released.len());
            let destination_pages = destination_inline_bytes[selection_index].div_ceil(page_bytes);
            projections[selection_index] = EvacuationSlicePageProjection {
                dead_phase_released_pages: dead_released.len(),
                additional_released_pages,
                destination_pages,
                net_resident_page_delta: destination_pages as isize
                    - additional_released_pages as isize,
            };
        }
        Ok(projections)
    }

    #[allow(clippy::too_many_arguments)]
    fn evacuation_page_streaming_projection(
        &self,
        reachable: &HashSet<usize>,
        forwarding: &[EvacuationForwarding],
        pinned: &HashSet<usize>,
        movable_lane_bytes: [usize; 4],
        page_bytes: usize,
        scratch_committed_bytes: usize,
        preplan_current_rss_bytes: usize,
        preplan_peak_rss_bytes: usize,
    ) -> Result<PageStreamingProjection, EvalHeapError> {
        let Some(stats) = self.flat_arena.reservation_stats() else {
            return Ok(PageStreamingProjection::default());
        };
        let mut all_objects = self.evacuation_source_objects(None)?;
        all_objects.sort_unstable_by_key(|(address, _)| *address);

        let mut remaining = HashMap::<usize, usize>::new();
        for (address, object) in &all_objects {
            let Some(index) = self.flat_arena.index_for_pointer(
                NonNull::new(*address as *mut HeapObject).ok_or(EvalHeapError::UnknownPointer {
                    tag: object.tag,
                    address: *address,
                })?,
            ) else {
                continue;
            };
            for page in page_interval(index.raw() as usize, object.size_bytes, page_bytes) {
                *remaining.entry(page).or_insert(0) += 1;
            }
        }
        let mut scalar_regions = Vec::new();
        self.compressed_scalars
            .append_cell_regions(0, &mut scalar_regions);
        for (address, bytes) in scalar_regions {
            let Some(index) =
                self.flat_arena
                    .index_for_pointer(NonNull::new(address as *mut HeapObject).ok_or(
                        EvalHeapError::UnknownPointer {
                            tag: ValueTag::Int,
                            address,
                        },
                    )?)
            else {
                continue;
            };
            for page in page_interval(index.raw() as usize, bytes, page_bytes) {
                *remaining.entry(page).or_insert(0) += 1;
            }
        }

        let mut resident_source_pages = HashSet::new();
        resident_source_pages
            .try_reserve(remaining.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: PLAN_LAYOUT_TABLE,
                entries: remaining.len(),
            })?;
        for page in remaining.keys().copied() {
            let offset = page
                .checked_mul(page_bytes)
                .and_then(|offset| u32::try_from(offset).ok())
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: PLAN_LAYOUT_TABLE,
                })?;
            if self
                .flat_arena
                .page_is_resident_at_index(crate::heap::ArenaIndex::new(offset))
                .and_then(Result::ok)
                .unwrap_or(false)
            {
                resident_source_pages.insert(page);
            }
        }

        let mut released = HashSet::new();
        released
            .try_reserve(resident_source_pages.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: PLAN_LAYOUT_TABLE,
                entries: resident_source_pages.len(),
            })?;
        for (address, object) in &all_objects {
            if reachable.contains(address) {
                continue;
            }
            decrement_source_page_counts(
                &mut remaining,
                &resident_source_pages,
                &mut released,
                self.flat_arena.index_for_pointer(
                    NonNull::new(*address as *mut HeapObject).ok_or(
                        EvalHeapError::UnknownPointer {
                            tag: object.tag,
                            address: *address,
                        },
                    )?,
                ),
                object.size_bytes,
                page_bytes,
            );
        }
        let dead_phase_released_pages = released.len();

        let permanent_start = stats.low_used_bytes;
        let typed_start = permanent_start
            .checked_add(movable_lane_bytes[EvacuationLane::PermanentFlat.index()])
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PLAN_LAYOUT_TABLE,
            })?;
        let worker_start = stats
            .virtual_reserved_bytes
            .checked_sub(stats.high_used_bytes)
            .and_then(|cursor| {
                cursor.checked_sub(movable_lane_bytes[EvacuationLane::WorkerFlat.index()])
            })
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PLAN_LAYOUT_TABLE,
            })?;
        let lane_starts = [permanent_start, typed_start, worker_start, 0];
        let mut lane_offsets = [0usize; 4];
        let mut destination_pages = HashSet::new();
        destination_pages
            .try_reserve(movable_destination_page_capacity(
                movable_lane_bytes,
                page_bytes,
            ))
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: PLAN_LAYOUT_TABLE,
                entries: forwarding.len(),
            })?;
        let mut peak_net_pages = 0isize;

        for entry in forwarding {
            if pinned.contains(&entry.source_address) {
                continue;
            }
            let lane = entry.lane.index();
            if entry.lane != EvacuationLane::WorkerRecords {
                let offset = align_up(lane_offsets[lane], entry.align)?;
                lane_offsets[lane] = offset.checked_add(entry.size_bytes).ok_or(
                    EvalHeapError::RootScanLengthOverflow {
                        table: PLAN_LAYOUT_TABLE,
                    },
                )?;
                let destination = lane_starts[lane].checked_add(offset).ok_or(
                    EvalHeapError::RootScanLengthOverflow {
                        table: PLAN_LAYOUT_TABLE,
                    },
                )?;
                for page in page_interval(destination, entry.size_bytes, page_bytes) {
                    if !resident_source_pages.contains(&page) {
                        destination_pages.insert(page);
                    }
                }
            }
            decrement_source_page_counts(
                &mut remaining,
                &resident_source_pages,
                &mut released,
                self.flat_arena.index_for_pointer(
                    NonNull::new(entry.source_address as *mut HeapObject).ok_or(
                        EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        },
                    )?,
                ),
                entry.size_bytes,
                page_bytes,
            );
            let net = destination_pages.len() as isize - released.len() as isize;
            peak_net_pages = peak_net_pages.max(net);
        }

        let peak_net_pages = usize::try_from(peak_net_pages.max(0)).unwrap_or(usize::MAX);
        let peak_upper_bytes = preplan_current_rss_bytes
            .saturating_add(scratch_committed_bytes)
            .saturating_add(peak_net_pages.saturating_mul(page_bytes))
            .max(preplan_peak_rss_bytes);
        Ok(PageStreamingProjection {
            source_pages: remaining.len(),
            resident_source_pages: resident_source_pages.len(),
            dead_phase_released_pages,
            destination_pages: destination_pages.len(),
            released_source_pages: released.len(),
            peak_net_pages,
            peak_upper_bytes,
            headroom_bytes: ACCEPTANCE_RSS_BYTES.saturating_sub(peak_upper_bytes),
            excess_bytes: peak_upper_bytes.saturating_sub(ACCEPTANCE_RSS_BYTES),
        })
    }

    /// Advises complete reservation pages whose arena-owned live count is zero.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if complete Candidate-C allocation accounting
    /// is unavailable or the reservation rejects a zero-liveness page run.
    pub(crate) fn advise_tombstoned_reservation_pages(
        &self,
    ) -> Result<crate::heap::SharedReservationZeroPageAdviceReport, EvalHeapError> {
        self.flat_arena
            .advise_zero_liveness_pages()
            .ok_or(EvalHeapError::ShedRejected {
                address: 0,
                reason: "dead-page advice requires complete Candidate-C allocation accounting",
            })?
            .map_err(|_| EvalHeapError::ShedRejected {
                address: 0,
                reason: "arena-owned zero-liveness page advice was rejected",
            })
    }

    /// Copies a supported evacuation plan into a finalized fresh serial heap.
    ///
    /// Lists and attrsets are first allocated without hash-cons admission while
    /// the destination remains private. Once complete forwarding exists, their
    /// embedded values are rewritten and their structural hashes and complete
    /// hash-cons tables are rebuilt before the destination is returned.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the plan contains an unsupported worker,
    /// shared or blackholed flat thunk, blackholed typed head, node-shaped typed
    /// work, or boxed scalar edge; no longer describes the source heap;
    /// destination allocation fails; an allocation misses its planned offset;
    /// or final hash-cons publication cannot be completed.
    pub(crate) fn write_supported_evacuation_destination(
        &self,
        plan: &EvacuationPlan,
    ) -> Result<EvacuationDestination, EvalHeapError> {
        if self.shared.is_some() {
            return Err(EvalHeapError::ShedRejected {
                address: 0,
                reason: "permanent-flat evacuation requires the serial heap",
            });
        }

        let mut payloads = Vec::new();
        payloads
            .try_reserve_exact(plan.forwarding.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: plan.forwarding.len(),
            })?;
        let planned_sources: HashSet<_> = plan
            .forwarding
            .iter()
            .map(|entry| entry.source_address)
            .collect();
        for entry in &plan.forwarding {
            let supported_permanent = entry.lane == EvacuationLane::PermanentFlat
                && matches!(
                    entry.tag,
                    ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
                );
            let supported_worker = entry.lane == EvacuationLane::WorkerFlat
                && matches!(
                    entry.tag,
                    ValueTag::Primop | ValueTag::Lambda | ValueTag::Thunk
                );
            let supported_typed =
                entry.lane == EvacuationLane::TypedThunkHeads && entry.tag == ValueTag::Thunk;
            if !supported_permanent && !supported_worker && !supported_typed {
                return Err(EvalHeapError::ShedRejected {
                    address: entry.source_address,
                    reason: "evacuation supports permanent-flat values, ordinary flat Node thunks, flat primops/lambdas, and typed thunk heads only",
                });
            }
            let payload = match entry.tag {
                ValueTag::String | ValueTag::Path => {
                    let Some(object) = self
                        .flat
                        .iter()
                        .find(|object| object.ptr().as_ptr() as usize == entry.source_address)
                    else {
                        return Err(EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        });
                    };
                    let actual_tag = value_tag_for_flat_kind(object.object().kind());
                    if actual_tag != entry.tag {
                        return Err(EvalHeapError::RecordTypeMismatch {
                            expected: entry.tag,
                            actual: actual_tag,
                            address: entry.source_address,
                        });
                    }
                    validate_evacuation_extent(entry, object.size_bytes())?;
                    if entry.tag == ValueTag::String {
                        PermanentFlatPayload::String(object.object().payload().clone())
                    } else {
                        PermanentFlatPayload::Path(object.object().payload().clone())
                    }
                }
                ValueTag::List => {
                    let Some(object) = self
                        .flat_lists
                        .iter()
                        .find(|object| object.ptr().as_ptr() as usize == entry.source_address)
                    else {
                        return Err(EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        });
                    };
                    validate_evacuation_extent(entry, object.size_bytes())?;
                    for value in object.object().payload().iter() {
                        validate_permanent_flat_edge(*value, &planned_sources)?;
                    }
                    PermanentFlatPayload::List(object.object().payload().clone())
                }
                ValueTag::Attrs => {
                    let Some(object) = self
                        .flat_attrs
                        .iter()
                        .find(|object| object.ptr().as_ptr() as usize == entry.source_address)
                    else {
                        return Err(EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        });
                    };
                    validate_evacuation_extent(entry, object.size_bytes())?;
                    for attr in object.object().payload().attrs.entries_by_symbol() {
                        validate_permanent_flat_edge(attr.value, &planned_sources)?;
                    }
                    PermanentFlatPayload::Attrs(object.object().payload().clone())
                }
                ValueTag::Primop => {
                    let ptr = NonNull::new(entry.source_address as *mut HeapObject).ok_or(
                        EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        },
                    )?;
                    let Some(object) = self.flat_closures.iter().find(|object| object.ptr() == ptr)
                    else {
                        return Err(EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        });
                    };
                    validate_evacuation_extent(entry, object.size_bytes())?;
                    let FlatClosurePayload::Primop(primop) = object.object().payload() else {
                        return Err(EvalHeapError::ShedRejected {
                            address: entry.source_address,
                            reason: "evacuation rejects non-primop worker closures",
                        });
                    };
                    for arg in primop.args() {
                        validate_permanent_flat_edge(arg.value(), &planned_sources)?;
                    }
                    PermanentFlatPayload::Primop(primop.clone())
                }
                ValueTag::Lambda => {
                    let ptr = NonNull::new(entry.source_address as *mut HeapObject).ok_or(
                        EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        },
                    )?;
                    let Some(object) = self.flat_closures.iter().find(|object| object.ptr() == ptr)
                    else {
                        return Err(EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        });
                    };
                    validate_evacuation_extent(entry, object.size_bytes())?;
                    let FlatClosurePayload::Lambda(lambda) = object.object().payload() else {
                        return Err(EvalHeapError::ShedRejected {
                            address: entry.source_address,
                            reason: "evacuation rejects non-lambda worker closures",
                        });
                    };
                    for frame in lambda.env().frames().iter() {
                        for value in frame.slot_values()? {
                            validate_permanent_flat_edge(value, &planned_sources)?;
                        }
                    }
                    for scope in lambda.with_scope_env().scopes() {
                        validate_permanent_flat_edge(scope.value(), &planned_sources)?;
                    }
                    for value in lambda.scoped_global_env().scopes() {
                        validate_permanent_flat_edge(*value, &planned_sources)?;
                    }
                    let tail = self
                        .flat_closures
                        .value_tail(ptr, FlatObjectKind::Lambda)
                        .map_err(|error| {
                            self.closure_resolution_error(ValueTag::Lambda, ptr, error)
                        })?;
                    let flat = match (lambda.env().flat_base(), tail) {
                        (Some(flat), Some(values)) if flat.len() == values.len() => {
                            for value in values {
                                validate_permanent_flat_edge(*value, &planned_sources)?;
                            }
                            Some(EvacuationFlatCapture {
                                allocation_site: flat.allocation_site(),
                                frame_count: flat.frame_count(),
                                values: values.to_vec(),
                            })
                        }
                        (None, None) => None,
                        _ => {
                            return Err(EvalHeapError::ShedRejected {
                                address: entry.source_address,
                                reason: "lambda flat-capture metadata disagrees with its tail",
                            });
                        }
                    };
                    PermanentFlatPayload::Lambda(EvacuationLambda {
                        lambda: lambda.clone(),
                        flat,
                    })
                }
                ValueTag::Thunk if entry.lane == EvacuationLane::WorkerFlat => {
                    let ptr = NonNull::new(entry.source_address as *mut HeapObject).ok_or(
                        EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        },
                    )?;
                    let Some(object) = self.flat_closures.iter().find(|object| object.ptr() == ptr)
                    else {
                        return Err(EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        });
                    };
                    validate_evacuation_extent(entry, object.size_bytes())?;
                    let FlatClosurePayload::Thunk(thunk) = object.object().payload() else {
                        return Err(EvalHeapError::ShedRejected {
                            address: entry.source_address,
                            reason: "evacuation rejects shared or malformed flat thunks",
                        });
                    };
                    if !thunk.has_serial_only_force_storage() {
                        return Err(EvalHeapError::ShedRejected {
                            address: entry.source_address,
                            reason: "evacuation requires ordinary serial flat-thunk storage",
                        });
                    }
                    let state = thunk.cell().state().map_err(EvalHeapError::Thunk)?;
                    if state == ThunkState::Blackhole {
                        return Err(EvalHeapError::ShedRejected {
                            address: entry.source_address,
                            reason: "evacuation rejects blackholed flat thunks",
                        });
                    }
                    let cached_value = thunk.cell().cached_value().map_err(EvalHeapError::Thunk)?;
                    if let Some(value) = cached_value {
                        validate_permanent_flat_edge(value, &planned_sources)?;
                    }
                    let tail = self
                        .flat_closures
                        .value_tail(ptr, FlatObjectKind::Thunk)
                        .map_err(|error| {
                            self.closure_resolution_error(ValueTag::Thunk, ptr, error)
                        })?;
                    let (thunk, flat) = match thunk.kind() {
                        EvalThunkKind::Node { .. } => {
                            let env = thunk.env().ok_or(EvalHeapError::ShedRejected {
                                address: entry.source_address,
                                reason: "evacuation Node thunk lost its lexical environment",
                            })?;
                            for frame in env.frames().iter() {
                                for value in frame.slot_values()? {
                                    validate_permanent_flat_edge(value, &planned_sources)?;
                                }
                            }
                            for scope in thunk
                                .with_scope_env()
                                .ok_or(EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "evacuation Node thunk lost its dynamic scopes",
                                })?
                                .scopes()
                            {
                                validate_permanent_flat_edge(scope.value(), &planned_sources)?;
                            }
                            for value in thunk
                                .scoped_global_env()
                                .ok_or(EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "evacuation Node thunk lost its scoped globals",
                                })?
                                .scopes()
                            {
                                validate_permanent_flat_edge(*value, &planned_sources)?;
                            }
                            let flat = match (env.flat_base(), tail) {
                                (Some(flat), Some(values)) if flat.len() == values.len() => {
                                    for value in values {
                                        validate_permanent_flat_edge(*value, &planned_sources)?;
                                    }
                                    Some(EvacuationFlatCapture {
                                        allocation_site: flat.allocation_site(),
                                        frame_count: flat.frame_count(),
                                        values: values.to_vec(),
                                    })
                                }
                                (None, None) => None,
                                _ => {
                                    return Err(EvalHeapError::ShedRejected {
                                        address: entry.source_address,
                                        reason: "thunk flat-capture metadata disagrees with its tail",
                                    });
                                }
                            };
                            (thunk.clone(), flat)
                        }
                        EvalThunkKind::Apply { .. }
                        | EvalThunkKind::GenListElemAtAddOne { .. }
                        | EvalThunkKind::Apply2(_)
                        | EvalThunkKind::Select { .. }
                        | EvalThunkKind::BuiltinAttr { .. } => {
                            if tail.is_some() {
                                return Err(EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "synthetic flat thunk unexpectedly owns a capture tail",
                                });
                            }
                            let mut copied = thunk.clone();
                            copied.rewrite_flat_synthetic_evacuation_values(&|value| {
                                validate_permanent_flat_edge(value, &planned_sources)?;
                                Ok(value)
                            })?;
                            (copied, None)
                        }
                        EvalThunkKind::Released => {
                            let result = cached_value.ok_or(EvalHeapError::ShedRejected {
                                address: entry.source_address,
                                reason: "released evacuation thunk has no cached result",
                            })?;
                            if state != ThunkState::Forced {
                                return Err(EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "released evacuation thunk is not forced",
                                });
                            }
                            // Successful active-work detachment deliberately
                            // leaves the old inline capture extent physically
                            // beside the edge-free Released shell. Preserve
                            // that extent in this same-layout correctness
                            // destination so planned offsets stay exact, but
                            // fill it with non-heap words: Released scanning
                            // never treats the padding as semantic captures.
                            let padding = tail.map(|values| EvacuationFlatCapture {
                                allocation_site: EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(0)),
                                frame_count: 0,
                                values: vec![Value::null(); values.len()],
                            });
                            (EvalThunk::released_forced(result), padding)
                        }
                    };
                    PermanentFlatPayload::Thunk(EvacuationThunk {
                        thunk,
                        state,
                        cached_value,
                        flat,
                    })
                }
                ValueTag::Thunk if entry.lane == EvacuationLane::TypedThunkHeads => {
                    let ptr = NonNull::new(entry.source_address as *mut HeapObject).ok_or(
                        EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        },
                    )?;
                    let head = self
                        .typed_thunk_heads
                        .resolve(ptr)
                        .map_err(|_| EvalHeapError::unknown(ValueTag::Thunk, ptr))?;
                    validate_evacuation_extent(entry, std::mem::size_of::<StableThunkHead>())?;
                    match head.state() {
                        Some(ThunkState::Suspended) => {
                            let work = self.typed_thunk_work_ref(ptr)?.ok_or(
                                EvalHeapError::ReleasedThunkWork {
                                    address: entry.source_address,
                                },
                            )?;
                            if !work.is_plain_serial_typed_shape()
                                || matches!(
                                    work.kind(),
                                    EvalThunkKind::Node { .. } | EvalThunkKind::Released
                                )
                            {
                                return Err(EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "evacuation typed work requires a synthetic serial thunk",
                                });
                            }
                            for edge in self
                                .scan_typed_thunk_edges(ptr)?
                                .ok_or(EvalHeapError::unknown(ValueTag::Thunk, ptr))?
                            {
                                validate_permanent_flat_edge(edge.value(), &planned_sources)?;
                            }
                            PermanentFlatPayload::TypedThunk(EvacuationTypedThunk::Suspended {
                                work: work.clone(),
                                destination_handle: None,
                            })
                        }
                        Some(ThunkState::Forced) => {
                            let value = head
                                .published_value()
                                .map_err(EvalHeapError::Thunk)?
                                .ok_or(EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "forced typed head lost its published value",
                                })?;
                            validate_permanent_flat_edge(value, &planned_sources)?;
                            PermanentFlatPayload::TypedThunk(EvacuationTypedThunk::Forced(value))
                        }
                        Some(ThunkState::Blackhole) => {
                            return Err(EvalHeapError::ShedRejected {
                                address: entry.source_address,
                                reason: "evacuation rejects blackholed typed thunk heads",
                            });
                        }
                        None => {
                            return Err(EvalHeapError::unknown(ValueTag::Thunk, ptr));
                        }
                    }
                }
                _ => {
                    return Err(EvalHeapError::ShedRejected {
                        address: entry.source_address,
                        reason: "evacuation supports permanent-flat values, ordinary flat Node thunks, flat primops/lambdas, and typed thunk heads only",
                    });
                }
            };
            payloads.push(payload);
        }

        let captured_frames = CapturedFrameTable::capture_from_envs(payloads.iter().filter_map(
            |payload| match payload {
                PermanentFlatPayload::Lambda(lambda) => Some(lambda.lambda.env()),
                PermanentFlatPayload::Thunk(thunk) => thunk.thunk.env(),
                _ => None,
            },
        ))
        .map_err(|_| EvalHeapError::ShedRejected {
            address: 0,
            reason: "closure evacuation could not capture environment frames",
        })?;
        let mut closure_frame_ids = HashMap::new();
        for (entry, payload) in plan.forwarding.iter().zip(&payloads) {
            let env = match payload {
                PermanentFlatPayload::Lambda(lambda) => lambda.lambda.env(),
                PermanentFlatPayload::Thunk(thunk) => {
                    let Some(env) = thunk.thunk.env() else {
                        continue;
                    };
                    env
                }
                _ => continue,
            };
            let frames = env.frames();
            let mut ids = Vec::new();
            ids.try_reserve_exact(frames.len()).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: PLAN_OBJECTS_TABLE,
                    entries: frames.len(),
                }
            })?;
            for frame in frames.iter() {
                ids.push(
                    captured_frames
                        .frame_id(frame)
                        .ok_or(EvalHeapError::ShedRejected {
                            address: entry.source_address,
                            reason: "lambda frame was absent from captured frame table",
                        })?,
                );
            }
            closure_frame_ids.insert(entry.source_address, ids);
        }
        let captured_frame_payloads = captured_frames.into_payloads();

        let mut destination = EvalHeap::new();
        let mut allocated = HashMap::new();
        allocated.try_reserve(plan.forwarding.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PLAN_LAYOUT_TABLE,
                entries: plan.forwarding.len(),
            }
        })?;
        for (entry, payload) in plan.forwarding.iter().zip(&payloads) {
            if matches!(
                payload,
                PermanentFlatPayload::Primop(_)
                    | PermanentFlatPayload::Lambda(_)
                    | PermanentFlatPayload::Thunk(_)
                    | PermanentFlatPayload::TypedThunk(_)
            ) {
                continue;
            }
            let value = match payload {
                PermanentFlatPayload::String(string) => destination.alloc_string(string.clone())?,
                PermanentFlatPayload::Path(path) => destination.alloc_path(path.clone())?,
                PermanentFlatPayload::List(list) => {
                    destination.flat_alloc_evacuation_list(list.clone())?
                }
                PermanentFlatPayload::Attrs(payload) => destination
                    .flat_alloc_evacuation_attrs(payload.metadata, payload.attrs.clone())?,
                PermanentFlatPayload::Primop(_)
                | PermanentFlatPayload::Lambda(_)
                | PermanentFlatPayload::Thunk(_)
                | PermanentFlatPayload::TypedThunk(_) => continue,
            };
            let actual_offset = value
                .word()
                .arena_index()
                .map(|index| index.raw() as usize)
                .ok_or(EvalHeapError::ShedRejected {
                    address: entry.source_address,
                    reason: "permanent-flat destination did not produce an arena value",
                })?;
            if actual_offset != entry.destination_offset {
                return Err(EvalHeapError::ShedRejected {
                    address: entry.source_address,
                    reason: "permanent-flat destination did not match planned offset",
                });
            }
            let ptr = value.as_heap_ptr().map_err(EvalHeapError::Value)?;
            let actual_size = match entry.tag {
                ValueTag::String | ValueTag::Path => destination
                    .flat
                    .iter()
                    .find(|object| object.ptr() == ptr)
                    .map(|object| object.size_bytes()),
                ValueTag::List => destination
                    .flat_lists
                    .iter()
                    .find(|object| object.ptr() == ptr)
                    .map(|object| object.size_bytes()),
                ValueTag::Attrs => destination
                    .flat_attrs
                    .iter()
                    .find(|object| object.ptr() == ptr)
                    .map(|object| object.size_bytes()),
                _ => None,
            };
            if actual_size != Some(entry.size_bytes) {
                return Err(EvalHeapError::ShedRejected {
                    address: entry.source_address,
                    reason: "permanent-flat destination object extent changed",
                });
            }
            allocated.insert(entry.source_address, value);
        }

        for (entry, payload) in plan.forwarding.iter().zip(&mut payloads) {
            let PermanentFlatPayload::TypedThunk(typed) = payload else {
                continue;
            };
            let value = match typed {
                EvacuationTypedThunk::Suspended {
                    work,
                    destination_handle,
                } => {
                    let (value, handle) =
                        destination.alloc_evacuation_suspended_typed_thunk(work.clone())?;
                    *destination_handle = Some(handle);
                    value
                }
                EvacuationTypedThunk::Forced(value) => {
                    destination.alloc_evacuation_forced_typed_thunk(*value)?
                }
            };
            allocated.insert(entry.source_address, value);
        }
        let typed_base = plan
            .forwarding
            .iter()
            .filter(|entry| entry.lane == EvacuationLane::TypedThunkHeads)
            .filter_map(|entry| allocated.get(&entry.source_address))
            .map(|value| value.as_heap_ptr())
            .collect::<Result<Vec<_>, _>>()
            .map_err(EvalHeapError::Value)?
            .into_iter()
            .map(|ptr| ptr.as_ptr() as usize)
            .min();
        if let Some(typed_base) = typed_base {
            for entry in plan
                .forwarding
                .iter()
                .filter(|entry| entry.lane == EvacuationLane::TypedThunkHeads)
            {
                let value =
                    allocated
                        .get(&entry.source_address)
                        .ok_or(EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        })?;
                let address = value.as_heap_ptr().map_err(EvalHeapError::Value)?.as_ptr() as usize;
                if address.saturating_sub(typed_base) != entry.destination_offset {
                    return Err(EvalHeapError::ShedRejected {
                        address: entry.source_address,
                        reason: "typed-head destination did not match planned offset",
                    });
                }
            }
        }

        let mut closure_tails = HashMap::new();
        for (entry, payload) in plan.forwarding.iter().zip(&payloads).rev() {
            let (value, tail) = match payload {
                PermanentFlatPayload::Primop(primop) => {
                    (destination.flat_alloc_primop(primop.clone())?, None)
                }
                PermanentFlatPayload::Lambda(lambda) => {
                    let capture = match &lambda.flat {
                        Some(flat) => {
                            let mut capture =
                                EvalFlatCaptureBuffer::new(flat.allocation_site, flat.frame_count);
                            for value in &flat.values {
                                capture.push(*value)?;
                            }
                            Some(capture.finish())
                        }
                        None => None,
                    };
                    let (value, tail) =
                        destination.flat_alloc_lambda(lambda.lambda.clone(), capture)?;
                    (value, tail)
                }
                PermanentFlatPayload::Thunk(thunk) => {
                    let capture = match &thunk.flat {
                        Some(flat) => {
                            if matches!(thunk.thunk.kind(), EvalThunkKind::Released) {
                                Some(EvalFlatCaptureBuffer::pending(
                                    flat.allocation_site,
                                    flat.frame_count,
                                    flat.values.len(),
                                )?)
                            } else {
                                let mut capture = EvalFlatCaptureBuffer::new(
                                    flat.allocation_site,
                                    flat.frame_count,
                                );
                                for value in &flat.values {
                                    capture.push(*value)?;
                                }
                                Some(capture.finish())
                            }
                        }
                        None => None,
                    };
                    let allocation_thunk = if matches!(thunk.thunk.kind(), EvalThunkKind::Released)
                    {
                        let result = thunk.cached_value.ok_or(EvalHeapError::ShedRejected {
                            address: entry.source_address,
                            reason: "released evacuation thunk lost its cached result",
                        })?;
                        EvalThunk::released_forced(result)
                    } else {
                        thunk.thunk.clone()
                    };
                    destination.flat_alloc_thunk(allocation_thunk, capture)?
                }
                PermanentFlatPayload::TypedThunk(_) => continue,
                _ => continue,
            };
            let ptr = value.as_heap_ptr().map_err(EvalHeapError::Value)?;
            let actual_size = destination
                .flat_closures
                .iter()
                .find(|object| object.ptr() == ptr)
                .map(|object| object.size_bytes());
            if actual_size != Some(entry.size_bytes) {
                return Err(EvalHeapError::ShedRejected {
                    address: entry.source_address,
                    reason: "worker-flat destination object extent changed",
                });
            }
            if let Some(tail) = tail {
                closure_tails.insert(entry.source_address, tail);
            }
            allocated.insert(entry.source_address, value);
        }
        let worker_base = plan
            .forwarding
            .iter()
            .filter(|entry| entry.lane == EvacuationLane::WorkerFlat)
            .filter_map(|entry| allocated.get(&entry.source_address))
            .map(|value| value.as_heap_ptr())
            .collect::<Result<Vec<_>, _>>()
            .map_err(EvalHeapError::Value)?
            .into_iter()
            .map(|ptr| ptr.as_ptr() as usize)
            .min();
        if let Some(worker_base) = worker_base {
            for entry in plan
                .forwarding
                .iter()
                .filter(|entry| entry.lane == EvacuationLane::WorkerFlat)
            {
                let value =
                    allocated
                        .get(&entry.source_address)
                        .ok_or(EvalHeapError::UnknownPointer {
                            tag: entry.tag,
                            address: entry.source_address,
                        })?;
                let address = value.as_heap_ptr().map_err(EvalHeapError::Value)?.as_ptr() as usize;
                if address.saturating_sub(worker_base) != entry.destination_offset {
                    return Err(EvalHeapError::ShedRejected {
                        address: entry.source_address,
                        reason: "worker-flat destination did not match planned offset",
                    });
                }
            }
        }

        let mut forwarding = Vec::new();
        forwarding
            .try_reserve_exact(plan.forwarding.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: PLAN_LAYOUT_TABLE,
                entries: plan.forwarding.len(),
            })?;
        for entry in &plan.forwarding {
            let destination = allocated.get(&entry.source_address).copied().ok_or(
                EvalHeapError::UnknownPointer {
                    tag: entry.tag,
                    address: entry.source_address,
                },
            )?;
            forwarding.push(EvacuationDestinationForwarding {
                source_address: entry.source_address,
                destination,
            });
        }

        let forwarding_by_source: HashMap<_, _> = forwarding
            .iter()
            .map(|entry| (entry.source_address, entry.destination))
            .collect();
        let restored_frames =
            RestoredFrameTable::rebuild(&captured_frame_payloads).map_err(|_| {
                EvalHeapError::ShedRejected {
                    address: 0,
                    reason: "closure evacuation could not rebuild environment frames",
                }
            })?;
        for id in 0..restored_frames.len() {
            let frame = restored_frames
                .frame(id as u32)
                .ok_or(EvalHeapError::ShedRejected {
                    address: 0,
                    reason: "closure evacuation rebuilt a sparse frame table",
                })?;
            for (slot, value) in frame.slot_values()?.into_iter().enumerate() {
                frame.set(
                    slot as u32,
                    rewrite_permanent_flat_value(value, &forwarding_by_source)?,
                )?;
            }
        }
        let mut staged_lists = Vec::new();
        let mut staged_attrs = Vec::new();
        for (entry, payload) in plan.forwarding.iter().zip(payloads) {
            let destination_value = forwarding_by_source
                .get(&entry.source_address)
                .copied()
                .ok_or(EvalHeapError::UnknownPointer {
                    tag: entry.tag,
                    address: entry.source_address,
                })?;
            let destination_ptr = destination_value
                .as_heap_ptr()
                .map_err(EvalHeapError::Value)?;
            match payload {
                PermanentFlatPayload::List(list) => {
                    let mut elements = Vec::new();
                    elements.try_reserve_exact(list.len()).map_err(|_| {
                        EvalHeapError::RootScanAllocationFailed {
                            table: PLAN_OBJECTS_TABLE,
                            entries: list.len(),
                        }
                    })?;
                    for value in list.iter() {
                        elements.push(rewrite_permanent_flat_value(*value, &forwarding_by_source)?);
                    }
                    staged_lists.push((destination_ptr, NixList::new(elements)));
                }
                PermanentFlatPayload::Attrs(payload) => {
                    let mut attrs = payload.attrs;
                    attrs.rewrite_entry_values(&mut |value| {
                        let address = value.as_heap_ptr().ok()?.as_ptr() as usize;
                        forwarding_by_source.get(&address).copied()
                    });
                    staged_attrs.push((destination_ptr, attrs));
                }
                PermanentFlatPayload::Primop(primop) => {
                    let mut args = Vec::new();
                    args.try_reserve_exact(primop.args().len()).map_err(|_| {
                        EvalHeapError::RootScanAllocationFailed {
                            table: PLAN_OBJECTS_TABLE,
                            entries: primop.args().len(),
                        }
                    })?;
                    for arg in primop.args() {
                        args.push(EvalPrimOpArg::new_in_module(
                            arg.module(),
                            arg.id(),
                            arg.span(),
                            rewrite_permanent_flat_value(arg.value(), &forwarding_by_source)?,
                        ));
                    }
                    let primop = match primop.builtin() {
                        Some(builtin) => {
                            EvalPrimOp::registered_with_args(primop.symbol(), builtin, args)
                        }
                        None => EvalPrimOp::with_args(primop.symbol(), args),
                    };
                    destination.replace_evacuation_primop(destination_ptr, primop)?;
                }
                PermanentFlatPayload::Lambda(lambda) => {
                    let ids = closure_frame_ids.get(&entry.source_address).ok_or(
                        EvalHeapError::ShedRejected {
                            address: entry.source_address,
                            reason: "closure evacuation lost its frame-id list",
                        },
                    )?;
                    let mut frames: Vec<Arc<EvalFrame>> = Vec::new();
                    frames.try_reserve_exact(ids.len()).map_err(|_| {
                        EvalHeapError::RootScanAllocationFailed {
                            table: PLAN_OBJECTS_TABLE,
                            entries: ids.len(),
                        }
                    })?;
                    for id in ids {
                        frames.push(restored_frames.frame(*id).cloned().ok_or(
                            EvalHeapError::ShedRejected {
                                address: entry.source_address,
                                reason: "lambda evacuation referenced a missing frame",
                            },
                        )?);
                    }
                    let flat_base = match lambda.flat {
                        Some(flat) => {
                            let handle = closure_tails.get(&entry.source_address).copied().ok_or(
                                EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "lambda evacuation lost its flat tail handle",
                                },
                            )?;
                            let tail = destination
                                .flat_closures
                                .value_tail_mut(destination_ptr, FlatObjectKind::Lambda)
                                .map_err(|_| {
                                    EvalHeapError::unknown(ValueTag::Lambda, destination_ptr)
                                })?
                                .ok_or(EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "lambda evacuation lost its flat value tail",
                                })?;
                            if tail.len() != flat.values.len() {
                                return Err(EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "lambda evacuation flat tail length changed",
                                });
                            }
                            for value in tail {
                                *value =
                                    rewrite_permanent_flat_value(*value, &forwarding_by_source)?;
                            }
                            Some(EvalFlatCapture::inline(
                                flat.allocation_site,
                                flat.frame_count,
                                handle,
                            )?)
                        }
                        None => None,
                    };
                    let env = EvalEnv::restore_parts(&frames, flat_base)?;
                    let mut with_scopes = Vec::new();
                    with_scopes
                        .try_reserve_exact(lambda.lambda.with_scope_env().len())
                        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                            table: PLAN_OBJECTS_TABLE,
                            entries: lambda.lambda.with_scope_env().len(),
                        })?;
                    for scope in lambda.lambda.with_scope_env().scopes() {
                        with_scopes.push(EvalWithScope::new(
                            scope.module(),
                            scope.scope(),
                            rewrite_permanent_flat_value(scope.value(), &forwarding_by_source)?,
                        ));
                    }
                    let with_env = EvalWithEnv::capture(&with_scopes)?;
                    let mut scoped_globals = Vec::new();
                    scoped_globals
                        .try_reserve_exact(lambda.lambda.scoped_global_env().len())
                        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                            table: PLAN_OBJECTS_TABLE,
                            entries: lambda.lambda.scoped_global_env().len(),
                        })?;
                    for value in lambda.lambda.scoped_global_env().scopes() {
                        scoped_globals
                            .push(rewrite_permanent_flat_value(*value, &forwarding_by_source)?);
                    }
                    let lambda_payload = EvalLambda::with_captures(
                        lambda.lambda.module(),
                        lambda.lambda.pattern(),
                        lambda.lambda.body(),
                        lambda.lambda.frame(),
                        env,
                        with_env,
                        EvalScopedGlobalEnv::from(scoped_globals),
                    );
                    destination.replace_evacuation_lambda(destination_ptr, lambda_payload)?;
                }
                PermanentFlatPayload::Thunk(mut thunk) => {
                    if matches!(thunk.thunk.kind(), EvalThunkKind::Released) {
                        let result = match (thunk.state, thunk.cached_value) {
                            (ThunkState::Forced, Some(value)) => value,
                            _ => {
                                return Err(EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "released evacuation thunk state disagrees with its cached result",
                                });
                            }
                        };
                        destination.replace_evacuation_thunk(
                            destination_ptr,
                            EvalThunk::released_forced(rewrite_permanent_flat_value(
                                result,
                                &forwarding_by_source,
                            )?),
                        )?;
                        continue;
                    }
                    if !matches!(thunk.thunk.kind(), EvalThunkKind::Node { .. }) {
                        if thunk.flat.is_some() {
                            return Err(EvalHeapError::ShedRejected {
                                address: entry.source_address,
                                reason: "synthetic flat thunk unexpectedly owns a capture tail",
                            });
                        }
                        thunk
                            .thunk
                            .rewrite_flat_synthetic_evacuation_values(&|value| {
                                rewrite_permanent_flat_value(value, &forwarding_by_source)
                            })?;
                        destination.replace_evacuation_thunk(destination_ptr, thunk.thunk)?;
                        continue;
                    }
                    let ids = closure_frame_ids.get(&entry.source_address).ok_or(
                        EvalHeapError::ShedRejected {
                            address: entry.source_address,
                            reason: "closure evacuation lost its frame-id list",
                        },
                    )?;
                    let mut frames: Vec<Arc<EvalFrame>> = Vec::new();
                    frames.try_reserve_exact(ids.len()).map_err(|_| {
                        EvalHeapError::RootScanAllocationFailed {
                            table: PLAN_OBJECTS_TABLE,
                            entries: ids.len(),
                        }
                    })?;
                    for id in ids {
                        frames.push(restored_frames.frame(*id).cloned().ok_or(
                            EvalHeapError::ShedRejected {
                                address: entry.source_address,
                                reason: "thunk evacuation referenced a missing frame",
                            },
                        )?);
                    }
                    let flat_base = match thunk.flat {
                        Some(flat) => {
                            let handle = closure_tails.get(&entry.source_address).copied().ok_or(
                                EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "thunk evacuation lost its flat tail handle",
                                },
                            )?;
                            let tail = destination
                                .flat_closures
                                .value_tail_mut(destination_ptr, FlatObjectKind::Thunk)
                                .map_err(|_| {
                                    EvalHeapError::unknown(ValueTag::Thunk, destination_ptr)
                                })?
                                .ok_or(EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "thunk evacuation lost its flat value tail",
                                })?;
                            if tail.len() != flat.values.len() {
                                return Err(EvalHeapError::ShedRejected {
                                    address: entry.source_address,
                                    reason: "thunk evacuation flat tail length changed",
                                });
                            }
                            for value in tail {
                                *value =
                                    rewrite_permanent_flat_value(*value, &forwarding_by_source)?;
                            }
                            Some(EvalFlatCapture::inline(
                                flat.allocation_site,
                                flat.frame_count,
                                handle,
                            )?)
                        }
                        None => None,
                    };
                    let env = EvalEnv::restore_parts(&frames, flat_base)?;
                    let source_with_env =
                        thunk
                            .thunk
                            .with_scope_env()
                            .ok_or(EvalHeapError::ShedRejected {
                                address: entry.source_address,
                                reason: "evacuation Node thunk lost its dynamic scopes",
                            })?;
                    let mut with_scopes = Vec::new();
                    with_scopes
                        .try_reserve_exact(source_with_env.len())
                        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                            table: PLAN_OBJECTS_TABLE,
                            entries: source_with_env.len(),
                        })?;
                    for scope in source_with_env.scopes() {
                        with_scopes.push(EvalWithScope::new(
                            scope.module(),
                            scope.scope(),
                            rewrite_permanent_flat_value(scope.value(), &forwarding_by_source)?,
                        ));
                    }
                    let with_env = EvalWithEnv::capture(&with_scopes)?;
                    let source_globals =
                        thunk
                            .thunk
                            .scoped_global_env()
                            .ok_or(EvalHeapError::ShedRejected {
                                address: entry.source_address,
                                reason: "evacuation Node thunk lost its scoped globals",
                            })?;
                    let mut scoped_globals = Vec::new();
                    scoped_globals
                        .try_reserve_exact(source_globals.len())
                        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                            table: PLAN_OBJECTS_TABLE,
                            entries: source_globals.len(),
                        })?;
                    for value in source_globals.scopes() {
                        scoped_globals
                            .push(rewrite_permanent_flat_value(*value, &forwarding_by_source)?);
                    }
                    let body = thunk.thunk.body_ref().ok_or(EvalHeapError::ShedRejected {
                        address: entry.source_address,
                        reason: "evacuation Node thunk lost its body",
                    })?;
                    let suspended = EvalThunk::with_captures(
                        body.module(),
                        body.id(),
                        env,
                        with_env,
                        EvalScopedGlobalEnv::from(scoped_globals),
                    );
                    let thunk_payload = match (thunk.state, thunk.cached_value) {
                        (ThunkState::Suspended, None) => suspended,
                        (ThunkState::Forced, Some(value)) => {
                            EvalThunk::with_forced_cached_result_from(
                                &suspended,
                                rewrite_permanent_flat_value(value, &forwarding_by_source)?,
                            )
                        }
                        (ThunkState::Blackhole, _) => {
                            return Err(EvalHeapError::ShedRejected {
                                address: entry.source_address,
                                reason: "evacuation rejects blackholed flat thunks",
                            });
                        }
                        _ => {
                            return Err(EvalHeapError::ShedRejected {
                                address: entry.source_address,
                                reason: "evacuation thunk state disagrees with its cached result",
                            });
                        }
                    };
                    destination.replace_evacuation_thunk(destination_ptr, thunk_payload)?;
                }
                PermanentFlatPayload::TypedThunk(typed) => match typed {
                    EvacuationTypedThunk::Suspended {
                        mut work,
                        destination_handle,
                    } => {
                        work.rewrite_synthetic_evacuation_values(&|value| {
                            rewrite_permanent_flat_value(value, &forwarding_by_source)
                        })?;
                        let handle = destination_handle.ok_or(EvalHeapError::ShedRejected {
                            address: entry.source_address,
                            reason: "evacuation lost its typed-work destination handle",
                        })?;
                        destination.replace_evacuation_typed_work(handle, work)?;
                    }
                    EvacuationTypedThunk::Forced(value) => {
                        destination.replace_evacuation_typed_result(
                            destination_ptr,
                            rewrite_permanent_flat_value(value, &forwarding_by_source)?,
                        )?;
                    }
                },
                PermanentFlatPayload::String(_) | PermanentFlatPayload::Path(_) => {}
            }
        }

        for (ptr, list) in staged_lists {
            destination.flat_list_commit_writeback(ptr, list)?;
        }
        for (ptr, attrs) in staged_attrs {
            destination.flat_attrs_commit_writeback(ptr, attrs)?;
        }
        destination.finalize_permanent_flat_evacuation_indexes()?;

        Ok(EvacuationDestination {
            heap: destination,
            forwarding,
        })
    }

    fn finalize_permanent_flat_evacuation_indexes(&mut self) -> Result<(), EvalHeapError> {
        let list_count = self.flat_lists.iter().count();
        let mut lists = Vec::new();
        lists.try_reserve_exact(list_count).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: list_count,
            }
        })?;
        for object in self.flat_lists.iter() {
            let ptr = object.ptr();
            lists.push((
                ptr,
                crate::eval::heap::arena::list_structural_hash(object.object().payload()),
                self.value_for_flat_allocation(ValueTag::List, ptr)?,
            ));
        }
        let attrs_count = self.flat_attrs.iter().count();
        let mut attrs = Vec::new();
        attrs.try_reserve_exact(attrs_count).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: attrs_count,
            }
        })?;
        for object in self.flat_attrs.iter() {
            let ptr = object.ptr();
            let payload = object.object().payload();
            attrs.push((
                ptr,
                crate::eval::heap::arena::attrs_structural_hash(payload.metadata, &payload.attrs),
                self.value_for_flat_allocation(ValueTag::Attrs, ptr)?,
            ));
        }

        let mut list_cons = HashConsTable::new();
        for (_, hash, value) in &lists {
            let slot = list_cons.reserve_slot(*hash)?;
            if !list_cons.push_reserved(slot, *value) {
                return Err(EvalHeapError::ShedRejected {
                    address: 0,
                    reason: "evacuation list hash-cons publication lost its reservation",
                });
            }
        }
        let mut attrs_cons = HashConsTable::new();
        for (_, hash, value) in &attrs {
            let slot = attrs_cons.reserve_slot(*hash)?;
            if !attrs_cons.push_reserved(slot, *value) {
                return Err(EvalHeapError::ShedRejected {
                    address: 0,
                    reason: "evacuation attrs hash-cons publication lost its reservation",
                });
            }
        }
        for (ptr, hash, _) in lists {
            self.flat_lists
                .update_structural_hash(ptr, FlatObjectKind::List, hash.raw())
                .map_err(|_| EvalHeapError::unknown(ValueTag::List, ptr))?;
            self.flat_stale_hashes.remove(&(ptr.as_ptr() as usize));
        }
        for (ptr, hash, _) in attrs {
            self.flat_attrs
                .update_structural_hash(ptr, FlatObjectKind::Attrs, hash.raw())
                .map_err(|_| EvalHeapError::unknown(ValueTag::Attrs, ptr))?;
            self.flat_stale_hashes.remove(&(ptr.as_ptr() as usize));
        }
        self.list_cons = list_cons;
        self.attrs_cons = attrs_cons;
        Ok(())
    }

    fn evacuation_source_objects(
        &self,
        reachable: Option<&HashSet<usize>>,
    ) -> Result<Vec<(usize, SourceObject)>, EvalHeapError> {
        let mut objects = Vec::new();
        let expected = reachable.map_or_else(
            || {
                self.records
                    .len()
                    .saturating_add(self.flat.len())
                    .saturating_add(self.flat_lists.len())
                    .saturating_add(self.flat_attrs.len())
                    .saturating_add(self.flat_closures.len())
            },
            HashSet::len,
        );
        objects.try_reserve_exact(expected).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: PLAN_OBJECTS_TABLE,
                entries: expected,
            }
        })?;

        for record in self.records.iter() {
            let address = record.ptr.as_ptr() as usize;
            if record.is_retired()
                || reachable.is_some_and(|reachable| !reachable.contains(&address))
            {
                continue;
            }
            objects.push((
                address,
                SourceObject {
                    tag: record.object.tag(),
                    lane: EvacuationLane::WorkerRecords,
                    size_bytes: record.layout.size_bytes,
                    align: record.layout.align,
                    known_external_bytes: 0,
                },
            ));
        }
        for object in self.flat.iter() {
            let address = object.ptr().as_ptr() as usize;
            if reachable.is_some_and(|reachable| !reachable.contains(&address)) {
                continue;
            }
            let tag = match object.object().kind() {
                FlatObjectKind::String => ValueTag::String,
                FlatObjectKind::Path => ValueTag::Path,
                _ => {
                    return Err(EvalHeapError::UnknownPointer {
                        tag: ValueTag::String,
                        address,
                    });
                }
            };
            objects.push((
                address,
                SourceObject {
                    tag,
                    lane: EvacuationLane::PermanentFlat,
                    size_bytes: object.size_bytes(),
                    align: std::mem::align_of::<HeapObject>(),
                    known_external_bytes: 0,
                },
            ));
        }
        for object in self.flat_lists.iter() {
            let address = object.ptr().as_ptr() as usize;
            if reachable.is_some_and(|reachable| !reachable.contains(&address)) {
                continue;
            }
            let list = object.object().payload();
            objects.push((
                address,
                SourceObject {
                    tag: ValueTag::List,
                    lane: EvacuationLane::PermanentFlat,
                    size_bytes: object.size_bytes(),
                    align: std::mem::align_of::<HeapObject>(),
                    known_external_bytes: list
                        .capacity()
                        .saturating_mul(std::mem::size_of::<Value>()),
                },
            ));
        }
        for object in self.flat_attrs.iter() {
            let address = object.ptr().as_ptr() as usize;
            if reachable.is_some_and(|reachable| !reachable.contains(&address)) {
                continue;
            }
            objects.push((
                address,
                SourceObject {
                    tag: ValueTag::Attrs,
                    lane: EvacuationLane::PermanentFlat,
                    size_bytes: object.size_bytes(),
                    align: std::mem::align_of::<HeapObject>(),
                    known_external_bytes: 0,
                },
            ));
        }
        for object in self.flat_closures.iter() {
            let address = object.ptr().as_ptr() as usize;
            let payload = object.object().payload();
            if reachable
                .is_some_and(|reachable| payload.is_retired() || !reachable.contains(&address))
            {
                continue;
            }
            objects.push((
                address,
                SourceObject {
                    tag: if payload.is_retired() {
                        ValueTag::Thunk
                    } else {
                        payload.tag()
                    },
                    lane: EvacuationLane::WorkerFlat,
                    size_bytes: object.size_bytes(),
                    align: std::mem::align_of::<HeapObject>(),
                    known_external_bytes: 0,
                },
            ));
        }
        for (address, bytes) in self.typed_thunk_heads.initialized_regions() {
            if reachable.is_some_and(|reachable| !reachable.contains(&address)) {
                continue;
            }
            objects.push((
                address,
                SourceObject {
                    tag: ValueTag::Thunk,
                    lane: EvacuationLane::TypedThunkHeads,
                    size_bytes: bytes,
                    align: std::mem::align_of::<u64>(),
                    known_external_bytes: 0,
                },
            ));
        }
        Ok(objects)
    }
}

fn mark_source_pages(pages: &mut HashSet<usize>, address: usize, bytes: usize, page_bytes: usize) {
    if bytes == 0 {
        return;
    }
    let first = address / page_bytes;
    let last = address.saturating_add(bytes.saturating_sub(1)) / page_bytes;
    for page in first..=last {
        pages.insert(page);
    }
}

fn page_interval(
    byte_offset: usize,
    bytes: usize,
    page_bytes: usize,
) -> std::ops::RangeInclusive<usize> {
    let first = byte_offset / page_bytes;
    let last = byte_offset.saturating_add(bytes.saturating_sub(1)) / page_bytes;
    first..=last
}

fn movable_destination_page_capacity(lane_bytes: [usize; 4], page_bytes: usize) -> usize {
    lane_bytes.into_iter().fold(0usize, |pages, bytes| {
        pages.saturating_add(bytes.div_ceil(page_bytes))
    })
}

fn decrement_source_page_counts(
    remaining: &mut HashMap<usize, usize>,
    resident: &HashSet<usize>,
    released: &mut HashSet<usize>,
    index: Option<crate::heap::ArenaIndex>,
    bytes: usize,
    page_bytes: usize,
) {
    let Some(index) = index else {
        return;
    };
    for page in page_interval(index.raw() as usize, bytes, page_bytes) {
        let Some(count) = remaining.get_mut(&page) else {
            continue;
        };
        *count = count.saturating_sub(1);
        if *count == 0 && resident.contains(&page) {
            released.insert(page);
        }
    }
}

fn page_round_up(bytes: usize, page_bytes: usize) -> Result<usize, EvalHeapError> {
    if bytes == 0 {
        return Ok(0);
    }
    align_up(bytes, page_bytes)
}

fn evacuation_hash_storage(
    heap: &EvalHeap,
    reachable: &HashSet<usize>,
) -> Result<(usize, usize), EvalHeapError> {
    const BUCKET_BYTES: usize = std::mem::size_of::<HotXxh3Hash>()
        + std::mem::size_of::<Vec<Value>>()
        + std::mem::size_of::<usize>();
    let mut current = 0usize;
    let mut live = 0usize;
    for table in [
        &heap.string_cons,
        &heap.path_cons,
        &heap.list_cons,
        &heap.attrs_cons,
    ] {
        let (_buckets, bucket_capacity, _candidates, candidate_capacity) = table.storage_counts();
        current = current
            .checked_add(bucket_capacity.saturating_mul(BUCKET_BYTES))
            .and_then(|bytes| {
                bytes.checked_add(candidate_capacity.saturating_mul(std::mem::size_of::<Value>()))
            })
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PLAN_LAYOUT_TABLE,
            })?;
        let mut keys = HashSet::new();
        let mut candidates = 0usize;
        for (key, _index, value) in table.committed_entries() {
            let (_tag, ptr) = any_value_heap_ptr(*value)?;
            if reachable.contains(&(ptr.as_ptr() as usize)) {
                keys.insert(*key);
                candidates = candidates.saturating_add(1);
            }
        }
        live = live
            .checked_add(keys.len().saturating_mul(BUCKET_BYTES))
            .and_then(|bytes| {
                bytes.checked_add(candidates.saturating_mul(std::mem::size_of::<Value>()))
            })
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: PLAN_LAYOUT_TABLE,
            })?;
    }
    Ok((current, live))
}

fn align_up(value: usize, align: usize) -> Result<usize, EvalHeapError> {
    if align == 0 || !align.is_power_of_two() {
        return Err(EvalHeapError::RootScanLengthOverflow {
            table: PLAN_LAYOUT_TABLE,
        });
    }
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: PLAN_LAYOUT_TABLE,
        })
}

fn validate_evacuation_extent(
    entry: &EvacuationForwarding,
    actual_size: usize,
) -> Result<(), EvalHeapError> {
    if actual_size == entry.size_bytes {
        return Ok(());
    }
    Err(EvalHeapError::ShedRejected {
        address: entry.source_address,
        reason: "permanent-flat evacuation plan has stale object extent",
    })
}

fn validate_permanent_flat_edge(
    value: Value,
    planned_sources: &HashSet<usize>,
) -> Result<(), EvalHeapError> {
    if value.word().arena_index().is_none() {
        return Ok(());
    }
    if !value.tag().is_heap() {
        return Err(EvalHeapError::ShedRejected {
            address: 0,
            reason: "permanent-flat evacuation rejects boxed scalar edges",
        });
    }
    let ptr = value.as_heap_ptr().map_err(EvalHeapError::Value)?;
    let address = ptr.as_ptr() as usize;
    if planned_sources.contains(&address) {
        return Ok(());
    }
    Err(EvalHeapError::UnknownPointer {
        tag: value.tag(),
        address,
    })
}

fn rewrite_permanent_flat_value(
    value: Value,
    forwarding: &HashMap<usize, Value>,
) -> Result<Value, EvalHeapError> {
    if value.word().arena_index().is_none() {
        return Ok(value);
    }
    if !value.tag().is_heap() {
        return Err(EvalHeapError::ShedRejected {
            address: 0,
            reason: "permanent-flat evacuation rejects boxed scalar edges",
        });
    }
    let address = value.as_heap_ptr().map_err(EvalHeapError::Value)?.as_ptr() as usize;
    forwarding
        .get(&address)
        .copied()
        .ok_or(EvalHeapError::UnknownPointer {
            tag: value.tag(),
            address,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::AttrEntry;
    use crate::runtime::builtins::lookup_builtin;
    use crate::syntax::SymbolTable;

    fn fixture() -> (EvalHeap, EvalRootSet) {
        let mut heap = EvalHeap::new();
        heap.enable_typed_apply_thunk_heads();
        let leaf = heap
            .alloc_thunk(EvalThunk::new(IrId::new(7)))
            .expect("leaf thunk allocates");
        let list = heap
            .alloc_list(NixList::new(vec![leaf, Value::int(1)]))
            .expect("list allocates");
        let _garbage = heap
            .alloc_thunk(EvalThunk::new(IrId::new(9)))
            .expect("unreachable thunk allocates");
        let mut roots = EvalRootSet::new();
        roots.try_push_value_stack(0, list).expect("root appends");
        (heap, roots)
    }

    #[test]
    fn evacuation_plan_assigns_unique_dense_destinations() {
        let (heap, roots) = fixture();
        let plan = heap.evacuation_plan(&roots).expect("plan succeeds");
        let mut destinations = HashSet::new();
        for entry in plan.forwarding() {
            assert!(destinations.insert((entry.lane, entry.destination_offset)));
        }
        for lane in EvacuationLane::ALL {
            let entries: Vec<_> = plan
                .forwarding()
                .iter()
                .filter(|entry| entry.lane == lane)
                .collect();
            for pair in entries.windows(2) {
                assert!(
                    pair[0].destination_offset + pair[0].size_bytes <= pair[1].destination_offset
                );
            }
        }
    }

    #[test]
    fn evacuation_plan_pins_boxed_scalar_pages_outside_the_heap_graph() {
        let (mut heap, roots) = fixture();
        heap.candidate_c_encode_int(i64::MAX)
            .expect("wide integer allocates a boxed scalar");

        let plan = heap.evacuation_plan(&roots).expect("plan succeeds");

        assert!(plan.accounting().pinned_scalar_pages > 0);
        assert!(plan.accounting().pinned_pages >= plan.accounting().pinned_scalar_pages);
    }

    #[test]
    fn evacuation_plan_is_closed_over_precise_edges() {
        let (heap, roots) = fixture();
        let plan = heap.evacuation_plan(&roots).expect("plan succeeds");
        let sources: HashSet<_> = plan
            .forwarding()
            .iter()
            .map(|entry| entry.source_address)
            .collect();
        let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
        for edge in scan.objects().iter().flat_map(|object| object.edges()) {
            let address = edge
                .value()
                .as_heap_ptr()
                .expect("edge is heap backed")
                .as_ptr() as usize;
            assert!(sources.contains(&address));
        }
        assert_eq!(plan.accounting().edges, 1);
    }

    #[test]
    fn evacuation_plan_hard_pin_island_retains_only_blackhole_descendants() {
        let mut heap = EvalHeap::new();
        let child = heap
            .alloc_string(NixString::from_bytes(b"hard descendant".to_vec()))
            .expect("hard descendant allocates");
        let function = heap
            .alloc_list(NixList::new(vec![child]))
            .expect("hard function list allocates");
        let argument = heap
            .alloc_string(NixString::from_bytes(b"hard argument".to_vec()))
            .expect("hard argument allocates");
        let blackhole = heap
            .alloc_thunk(EvalThunk::apply(
                EvalModuleId::ROOT,
                IrId::new(31),
                Span::new(1, 2),
                function,
                EvalModuleId::ROOT,
                IrId::new(32),
                argument,
            ))
            .expect("blackhole thunk allocates");
        let unrelated = heap
            .alloc_string(NixString::from_bytes(b"healable direct root".to_vec()))
            .expect("unrelated root allocates");
        let blackhole_payload = heap.get_thunk(blackhole).expect("blackhole thunk resolves");
        let crate::eval::ForceClaim::Claimed(_guard) = blackhole_payload
            .cell()
            .begin_force()
            .expect("blackhole thunk claims")
        else {
            panic!("fresh thunk must claim");
        };
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, blackhole)
            .expect("blackhole root appends");
        roots
            .try_push_value_stack(1, unrelated)
            .expect("unrelated root appends");

        let plan = heap
            .evacuation_plan_with_hard_pin_seed_graph(&roots, true)
            .expect("plan succeeds");
        let accounting = plan.accounting();
        assert_eq!(accounting.hard_pin_seed_objects, 1);
        assert_eq!(accounting.hard_pin_transitive_retained_objects, 3);
        assert_eq!(accounting.hard_pin_retained_objects, 4);
        assert_eq!(accounting.healable_pin_objects, 1);
        assert!(accounting.hard_pin_unique_resident_source_pages > 0);

        let hard_addresses = [blackhole, function, child, argument]
            .into_iter()
            .map(|value| {
                value
                    .as_heap_ptr()
                    .expect("hard-island value is heap backed")
                    .as_ptr() as usize
            })
            .collect::<HashSet<_>>();
        let expected_inline_bytes = plan
            .forwarding()
            .iter()
            .filter(|entry| hard_addresses.contains(&entry.source_address))
            .map(|entry| entry.size_bytes)
            .sum::<usize>();
        assert_eq!(
            accounting.hard_pin_retained_inline_bytes,
            expected_inline_bytes
        );
        assert!(
            !hard_addresses.contains(
                &(unrelated
                    .as_heap_ptr()
                    .expect("unrelated value is heap backed")
                    .as_ptr() as usize)
            ),
            "an unrelated reachable direct root is not in the hard island"
        );
        let report = plan.to_string();
        assert!(report.contains("\"hard_seed_objects\":1"));
        assert!(report.contains("\"transitive_retained_objects\":3"));
        assert!(report.contains("\"retained_objects\":4"));
        let census = plan
            .hard_pin_seed_graph
            .as_ref()
            .expect("opt-in hard-pin seed census is present");
        assert_eq!(census.contributing_seeds, 1);
        assert_eq!(census.minimum_full_collapse_cut, 1);
        assert_eq!(census.common_to_all_contributing_seeds, 3);
        assert_eq!(
            census.population,
            HardPinSeedPopulation {
                inline: 1,
                synthetic: 1,
                physical_tail_free: 1,
                ..HardPinSeedPopulation::default()
            }
        );
        assert_eq!(
            census.seeds,
            vec![HardPinSeedCensus {
                index: 0,
                storage: "inline",
                work: "synthetic_apply",
                has_value_tail: false,
                physical_tail_free: true,
                outgoing_edges: 2,
                reachable_nonseed_objects: 3,
                exclusive_nonseed_objects: 3,
                retained_without_seed: 0,
            }]
        );
        assert_eq!(
            census.overlap_histogram,
            vec![HardPinOverlapBucket {
                multiplicity: 1,
                objects: 3,
            }]
        );
        assert_eq!(
            census.greedy_cut,
            vec![HardPinGreedyCutStep {
                cut_count: 1,
                seed_index: 0,
                newly_released_objects: 3,
                retained_nonseed_objects: 0,
            }]
        );
        assert!(report.contains("\"minimum_full_collapse_cut\":1"));
        assert!(report.contains("\"work\":\"synthetic_apply\""));
    }

    #[test]
    fn hard_pin_seed_census_measures_overlap_and_deterministic_cut_order() {
        let mut heap = EvalHeap::new();
        let common_leaf = heap
            .alloc_string(NixString::from_bytes(b"common".to_vec()))
            .expect("common leaf allocates");
        let common = heap
            .alloc_list(NixList::new(vec![common_leaf]))
            .expect("common list allocates");
        let first_argument = heap
            .alloc_string(NixString::from_bytes(b"first".to_vec()))
            .expect("first argument allocates");
        let second_argument = heap
            .alloc_string(NixString::from_bytes(b"second".to_vec()))
            .expect("second argument allocates");
        let first = heap
            .alloc_thunk(EvalThunk::apply(
                EvalModuleId::ROOT,
                IrId::new(41),
                Span::new(1, 2),
                common,
                EvalModuleId::ROOT,
                IrId::new(42),
                first_argument,
            ))
            .expect("first blackhole allocates");
        let second = heap
            .alloc_thunk(EvalThunk::apply(
                EvalModuleId::ROOT,
                IrId::new(43),
                Span::new(3, 4),
                common,
                EvalModuleId::ROOT,
                IrId::new(44),
                second_argument,
            ))
            .expect("second blackhole allocates");
        let first_payload = heap.get_thunk(first).expect("first blackhole resolves");
        let crate::eval::ForceClaim::Claimed(_first_guard) = first_payload
            .cell()
            .begin_force()
            .expect("first blackhole claims")
        else {
            panic!("fresh thunk must claim");
        };
        let second_payload = heap.get_thunk(second).expect("second blackhole resolves");
        let crate::eval::ForceClaim::Claimed(_second_guard) = second_payload
            .cell()
            .begin_force()
            .expect("second blackhole claims")
        else {
            panic!("fresh thunk must claim");
        };
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, first)
            .expect("first root appends");
        roots
            .try_push_value_stack(1, second)
            .expect("second root appends");

        let plan = heap
            .evacuation_plan_with_hard_pin_seed_graph(&roots, true)
            .expect("plan succeeds");
        let census = plan
            .hard_pin_seed_graph
            .as_ref()
            .expect("hard-pin seed census is present");

        assert_eq!(census.contributing_seeds, 2);
        assert_eq!(census.minimum_full_collapse_cut, 2);
        assert_eq!(census.common_to_all_contributing_seeds, 2);
        assert_eq!(
            census.population,
            HardPinSeedPopulation {
                inline: 2,
                synthetic: 2,
                physical_tail_free: 2,
                ..HardPinSeedPopulation::default()
            }
        );
        assert_eq!(
            census
                .seeds
                .iter()
                .map(|seed| (
                    seed.reachable_nonseed_objects,
                    seed.exclusive_nonseed_objects,
                    seed.retained_without_seed,
                ))
                .collect::<Vec<_>>(),
            vec![(3, 1, 3), (3, 1, 3)]
        );
        assert_eq!(
            census.overlap_histogram,
            vec![
                HardPinOverlapBucket {
                    multiplicity: 1,
                    objects: 2,
                },
                HardPinOverlapBucket {
                    multiplicity: 2,
                    objects: 2,
                },
            ]
        );
        assert_eq!(
            census.greedy_cut,
            vec![
                HardPinGreedyCutStep {
                    cut_count: 1,
                    seed_index: 0,
                    newly_released_objects: 1,
                    retained_nonseed_objects: 3,
                },
                HardPinGreedyCutStep {
                    cut_count: 2,
                    seed_index: 1,
                    newly_released_objects: 3,
                    retained_nonseed_objects: 0,
                },
            ]
        );
    }

    #[test]
    fn evacuation_plan_layout_is_deterministic() {
        let (heap, roots) = fixture();
        let first = heap.evacuation_plan(&roots).expect("first plan succeeds");
        let second = heap.evacuation_plan(&roots).expect("second plan succeeds");
        assert_eq!(first.forwarding(), second.forwarding());
        assert_eq!(
            first.accounting.destination_inline_bytes,
            second.accounting.destination_inline_bytes
        );
        assert_eq!(first.accounting.lane_bytes, second.accounting.lane_bytes);
    }

    #[test]
    fn evacuation_plan_does_not_mutate_the_heap() {
        let (heap, roots) = fixture();
        let worker_before = heap.arena_stats();
        let permanent_before = heap.permanent_arena_stats();
        let records_before = heap.record_count();
        let scan_before = heap.scan_precise_roots(&roots).expect("scan succeeds");

        let plan = heap.evacuation_plan(&roots).expect("plan succeeds");

        assert_eq!(heap.arena_stats(), worker_before);
        assert_eq!(heap.permanent_arena_stats(), permanent_before);
        assert_eq!(heap.record_count(), records_before);
        assert_eq!(
            heap.scan_precise_roots(&roots).expect("scan succeeds"),
            scan_before
        );
        assert_eq!(plan.accounting().objects, 2);
    }

    #[test]
    fn evacuation_plan_counts_exact_plain_node_thunk_mover_admission() {
        let mut heap = EvalHeap::new();
        let movable = heap
            .alloc_thunk(EvalThunk::new(IrId::new(11)))
            .expect("plain Node thunk allocates");

        let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
            EvalModuleId::ROOT,
            IrId::new(12),
            Value::int(13),
        )])
        .expect("dynamic scope captures");
        let dynamic = heap
            .alloc_thunk(EvalThunk::with_captures(
                EvalModuleId::ROOT,
                IrId::new(14),
                EvalEnv::default(),
                with_env,
                EvalScopedGlobalEnv::default(),
            ))
            .expect("dynamic Node thunk allocates");

        let site = EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(15));
        let mut capture = EvalFlatCaptureBuffer::new(site, 1);
        capture
            .push(Value::int(16))
            .expect("flat capture value fits");
        let tail_owner = heap
            .alloc_thunk_with_flat_capture(EvalThunk::new(IrId::new(17)), Some(capture.finish()))
            .expect("flat-tail Node thunk allocates")
            .0;

        let shared = heap
            .alloc_thunk(EvalThunk::new(IrId::new(18)))
            .expect("shared Node source allocates");
        let shared_ptr = shared.as_thunk_ptr().expect("shared source has a pointer");
        drop(
            heap.share_thunk_from_ptr(shared_ptr, shared)
                .expect("source thunk shares"),
        );

        let synthetic = heap
            .alloc_thunk(EvalThunk::apply(
                EvalModuleId::ROOT,
                IrId::new(19),
                Span::new(20, 21),
                Value::int(22),
                EvalModuleId::ROOT,
                IrId::new(23),
                Value::int(24),
            ))
            .expect("synthetic thunk allocates");
        let root = heap
            .alloc_list(NixList::new(vec![
                movable, dynamic, tail_owner, shared, synthetic,
            ]))
            .expect("root list allocates");
        let mut roots = EvalRootSet::new();
        roots.try_push_value_stack(0, root).expect("root appends");

        let plan = heap.evacuation_plan(&roots).expect("plan succeeds");
        let movable_inline_bytes = plan
            .forwarding()
            .iter()
            .find(|entry| {
                entry.source_address
                    == movable
                        .as_thunk_ptr()
                        .map_or(0, |ptr| ptr.as_ptr() as usize)
            })
            .map(|entry| entry.size_bytes)
            .expect("movable thunk participates in the plan");
        let population = plan.accounting().flat_thunks;

        assert_eq!(population.inline, 4);
        assert_eq!(population.shared, 1);
        assert_eq!(population.suspended, 5);
        assert_eq!(population.node, 4);
        assert_eq!(population.synthetic, 1);
        assert_eq!(population.with_value_tail, 1);
        assert_eq!(population.plain_node_movable, 1);
        assert_eq!(
            population.plain_node_movable_inline_bytes,
            movable_inline_bytes
        );
        assert!(
            plan.to_string().contains(&format!(
                "\"plain_node_movable\":1,\"plain_node_movable_inline_bytes\":{movable_inline_bytes}"
            )),
            "the exact mover-admitted population is present in the report"
        );
    }

    #[test]
    fn evacuation_plan_censuses_the_first_movable_closure_slice() {
        let mut symbols = SymbolTable::new();
        let symbol = symbols.intern(b"length").expect("symbol interns");
        let builtin = lookup_builtin(b"length").expect("length builtin exists");
        let mut heap = EvalHeap::new();
        let argument = heap
            .alloc_string(NixString::from_bytes(b"argument".to_vec()))
            .expect("argument allocates");
        let primop = heap
            .alloc_primop(EvalPrimOp::registered_with_args(
                symbol,
                builtin,
                vec![EvalPrimOpArg::new(
                    IrId::new(23),
                    Span::new(4, 12),
                    argument,
                )],
            ))
            .expect("primop allocates");
        let lambda = heap
            .alloc_lambda(EvalLambda::new(
                IrId::new(31),
                IrId::new(32),
                FrameId::new(33),
                EvalEnv::default(),
            ))
            .expect("lambda allocates");
        let root = heap
            .alloc_list(NixList::new(vec![primop, lambda]))
            .expect("root list allocates");
        let mut roots = EvalRootSet::new();
        roots.try_push_value_stack(0, root).expect("root appends");
        roots
            .try_push_value_stack(1, primop)
            .expect("direct primop root appends");

        let accounting = heap
            .evacuation_plan(&roots)
            .expect("plan succeeds")
            .accounting()
            .first_slice;

        assert_eq!(accounting.plain_primops.objects, 1);
        assert_eq!(accounting.plain_primops.edges, 1);
        assert_eq!(accounting.plain_primops.direct_root_objects, 1);
        assert_eq!(accounting.plain_primops.pinned_objects, 1);
        assert_eq!(accounting.plain_primops.movable_objects, 0);
        assert_eq!(accounting.plain_lambdas.objects, 1);
        assert_eq!(accounting.plain_lambdas.edges, 0);
        assert_eq!(accounting.plain_lambdas.direct_root_objects, 0);
        assert_eq!(accounting.plain_lambdas.pinned_objects, 0);
        assert_eq!(accounting.plain_lambdas.movable_objects, 1);
        assert_eq!(accounting.rejected_tail_free_lambdas.objects, 0);
        assert_eq!(accounting.primop_lambda.objects, 2);
        assert_eq!(accounting.primop_lambda.edges, 1);
        assert_eq!(accounting.primop_lambda.movable_objects, 1);
        assert_eq!(accounting.alias_forwarded_primop_lambda.movable_objects, 2);
        assert_eq!(
            accounting.alias_forwarded_primop_lambda.direct_root_objects,
            1
        );
        assert_eq!(accounting.alias_forwarded_primop_lambda.pinned_objects, 0);
        assert!(
            accounting.primop_lambda.movable_destination_inline_bytes
                >= accounting.primop_lambda.movable_inline_bytes
        );
        assert!(accounting.primop_lambda_pages.destination_pages > 0);
        assert!(
            accounting
                .alias_forwarded_primop_lambda_pages
                .destination_pages
                >= accounting.primop_lambda_pages.destination_pages
        );
        assert_eq!(accounting.permanent_strings.objects, 1);
        assert_eq!(accounting.permanent_strings.edges, 0);
        assert_eq!(accounting.permanent_strings.direct_root_objects, 0);
        assert_eq!(accounting.permanent_strings.movable_objects, 1);
        assert_eq!(accounting.permanent_owned_strings.objects, 0);
        assert_eq!(accounting.permanent_inline_strings.objects, 1);
        assert_eq!(accounting.permanent_inline_strings.movable_objects, 1);
        assert_eq!(
            accounting
                .permanent_owned_string_pages
                .additional_released_pages,
            0
        );
        assert_eq!(accounting.permanent_owned_string_pages.destination_pages, 0);
        assert_eq!(accounting.permanent_paths.objects, 0);
        assert_eq!(accounting.permanent_owned_paths.objects, 0);
        assert_eq!(accounting.permanent_inline_paths.objects, 0);
        assert_eq!(accounting.permanent_owned_strings_paths.objects, 0);
        assert_eq!(accounting.permanent_lists.objects, 1);
        assert_eq!(accounting.permanent_lists.edges, 2);
        assert_eq!(accounting.permanent_lists.direct_root_objects, 1);
        assert_eq!(accounting.permanent_lists.pinned_objects, 1);
        assert_eq!(accounting.permanent_attrs.objects, 0);
        assert_eq!(accounting.permanent_owned_attrs.objects, 0);
        assert_eq!(accounting.permanent_inline_attrs.objects, 0);
        assert_eq!(accounting.current_mover_permanent.objects, 1);
        assert_eq!(
            accounting.current_mover_permanent,
            accounting.permanent_lists
        );
        assert_eq!(accounting.excluded_inline_permanent.objects, 1);
        assert_eq!(
            accounting.excluded_inline_permanent,
            accounting.permanent_inline_strings
        );
        assert_eq!(
            accounting.permanent_strings_paths,
            accounting.permanent_strings
        );
        assert_eq!(accounting.permanent_strings_paths_lists.objects, 2);
        assert_eq!(
            accounting.permanent_strings_paths_lists,
            accounting.permanent_flat
        );
        assert_eq!(
            accounting.permanent_strings_paths_lists_pages,
            accounting.permanent_flat_pages
        );
    }

    #[test]
    fn edge_free_destination_coexists_in_an_isolated_domain() {
        let mut source = EvalHeap::new();
        let string = source
            .alloc_string(NixString::from_bytes(b"source string".to_vec()))
            .expect("string allocates");
        let path = source
            .alloc_path(NixString::from_bytes(b"/source/path".to_vec()))
            .expect("path allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, string)
            .expect("string root appends");
        roots
            .try_push_value_stack(1, path)
            .expect("path root appends");

        let plan = source.evacuation_plan(&roots).expect("plan succeeds");
        let destination = source
            .write_supported_evacuation_destination(&plan)
            .expect("destination writes");
        assert_eq!(destination.forwarding().len(), 2);

        for forwarding in destination.forwarding() {
            let source_value = if forwarding.source_address
                == string
                    .as_heap_ptr()
                    .expect("string is heap backed")
                    .as_ptr() as usize
            {
                string
            } else {
                path
            };
            assert_ne!(
                source_value.word().arena_domain(),
                forwarding.destination.word().arena_domain()
            );
            match source_value.tag() {
                ValueTag::String => {
                    assert_eq!(
                        source.get_string(source_value).expect("source resolves"),
                        destination
                            .heap()
                            .get_string(forwarding.destination)
                            .expect("destination resolves")
                    );
                    assert!(destination.heap().get_string(source_value).is_err());
                    assert!(source.get_string(forwarding.destination).is_err());
                }
                ValueTag::Path => {
                    assert_eq!(
                        source.get_path(source_value).expect("source resolves"),
                        destination
                            .heap()
                            .get_path(forwarding.destination)
                            .expect("destination resolves")
                    );
                    assert!(destination.heap().get_path(source_value).is_err());
                    assert!(source.get_path(forwarding.destination).is_err());
                }
                tag => panic!("unexpected edge-free source tag: {tag:?}"),
            }
        }
    }

    #[test]
    fn edge_free_destination_survives_source_drop_at_planned_offsets() {
        let (destination, forwarding, offsets) = {
            let mut source = EvalHeap::new();
            let string = source
                .alloc_string(NixString::from_bytes(b"kept string".to_vec()))
                .expect("string allocates");
            let path = source
                .alloc_path(NixString::from_bytes(b"/kept/path".to_vec()))
                .expect("path allocates");
            let mut roots = EvalRootSet::new();
            roots
                .try_push_value_stack(0, string)
                .expect("string root appends");
            roots
                .try_push_value_stack(1, path)
                .expect("path root appends");
            let plan = source.evacuation_plan(&roots).expect("plan succeeds");
            let offsets: Vec<_> = plan
                .forwarding()
                .iter()
                .map(|entry| (entry.source_address, entry.destination_offset))
                .collect();
            let written = source
                .write_supported_evacuation_destination(&plan)
                .expect("destination writes");
            let (destination, forwarding) = written.into_parts();
            (destination, forwarding, offsets)
        };

        for entry in forwarding {
            let planned_offset = offsets
                .iter()
                .find_map(|(source, offset)| (*source == entry.source_address).then_some(*offset))
                .expect("forwarding has planned offset");
            assert_eq!(
                entry
                    .destination
                    .word()
                    .arena_index()
                    .expect("destination has arena index")
                    .raw() as usize,
                planned_offset
            );
            match entry.destination.tag() {
                ValueTag::String => assert_eq!(
                    destination
                        .get_string(entry.destination)
                        .expect("destination string survives")
                        .bytes(),
                    b"kept string"
                ),
                ValueTag::Path => assert_eq!(
                    destination
                        .get_path(entry.destination)
                        .expect("destination path survives")
                        .bytes(),
                    b"/kept/path"
                ),
                tag => panic!("unexpected destination tag: {tag:?}"),
            }
        }
    }

    #[test]
    fn permanent_flat_destination_rewrites_aliases_and_rebuilds_interning() {
        let mut symbols = SymbolTable::new();
        let key = symbols.intern(b"items").expect("symbol interns");
        let (mut destination, forwarding) = {
            let mut source = EvalHeap::new();
            let string = source
                .alloc_string(NixString::from_bytes(b"shared child".to_vec()))
                .expect("string allocates");
            let list = source
                .alloc_list(NixList::new(vec![string, string]))
                .expect("list allocates");
            let attrs =
                FlatAttrs::new(vec![AttrEntry::new(key, list)], &symbols).expect("attrs construct");
            let attrs = source.alloc_attrs(17, attrs).expect("attrs allocate");
            let mut roots = EvalRootSet::new();
            roots
                .try_push_value_stack(0, attrs)
                .expect("attrs root appends");
            let plan = source.evacuation_plan(&roots).expect("plan succeeds");
            source
                .write_supported_evacuation_destination(&plan)
                .expect("destination writes")
                .into_parts()
        };

        let value_for_tag = |tag| {
            forwarding
                .iter()
                .find(|entry| entry.destination.tag() == tag)
                .map(|entry| entry.destination)
                .expect("forwarding contains tag")
        };
        let string = value_for_tag(ValueTag::String);
        let list = value_for_tag(ValueTag::List);
        let attrs = value_for_tag(ValueTag::Attrs);
        let relocated_list = destination.get_list(list).expect("list resolves");
        assert!(relocated_list.get(0).expect("first element").raw_eq(string));
        assert!(
            relocated_list
                .get(1)
                .expect("second element")
                .raw_eq(string)
        );
        let relocated_attrs = destination.get_attrs(attrs).expect("attrs resolve");
        assert!(relocated_attrs.entries_by_symbol()[0].value.raw_eq(list));
        assert_eq!(
            destination
                .get_attrs_metadata(attrs)
                .expect("metadata resolves")
                .shape(),
            17
        );

        let list_payload = relocated_list.clone();
        let attrs_payload = relocated_attrs.clone();
        let interned_list = destination
            .alloc_list(list_payload)
            .expect("identical list interns");
        let interned_attrs = destination
            .alloc_attrs(17, attrs_payload)
            .expect("identical attrs intern");
        assert!(interned_list.raw_eq(list));
        assert!(interned_attrs.raw_eq(attrs));
    }

    #[test]
    fn primop_destination_preserves_callable_state_and_bound_arguments() {
        let mut symbols = SymbolTable::new();
        let symbol = symbols.intern(b"length").expect("symbol interns");
        let builtin = lookup_builtin(b"length").expect("length builtin exists");
        let (destination, forwarding) = {
            let mut source = EvalHeap::new();
            let argument = source
                .alloc_string(NixString::from_bytes(b"argument".to_vec()))
                .expect("argument allocates");
            let partial = source
                .alloc_primop(EvalPrimOp::registered_with_args(
                    symbol,
                    builtin,
                    vec![EvalPrimOpArg::new(
                        IrId::new(23),
                        Span::new(4, 12),
                        argument,
                    )],
                ))
                .expect("partial primop allocates");
            let callable = source
                .alloc_primop(EvalPrimOp::registered(symbol, builtin))
                .expect("callable primop allocates");
            let roots_list = source
                .alloc_list(NixList::new(vec![partial, callable]))
                .expect("root list allocates");
            let mut roots = EvalRootSet::new();
            roots
                .try_push_value_stack(0, roots_list)
                .expect("list root appends");
            let plan = source.evacuation_plan(&roots).expect("plan succeeds");
            source
                .write_supported_evacuation_destination(&plan)
                .expect("destination writes")
                .into_parts()
        };

        let primops: Vec<_> = forwarding
            .iter()
            .filter(|entry| entry.destination.tag() == ValueTag::Primop)
            .map(|entry| entry.destination)
            .collect();
        assert_eq!(primops.len(), 2);
        let partial = primops
            .iter()
            .find(|value| {
                destination
                    .get_primop(**value)
                    .is_ok_and(|primop| !primop.args().is_empty())
            })
            .copied()
            .expect("partial primop forwards");
        let callable = primops
            .iter()
            .find(|value| {
                destination
                    .get_primop(**value)
                    .is_ok_and(|primop| primop.args().is_empty())
            })
            .copied()
            .expect("callable primop forwards");
        let partial_payload = destination.get_primop(partial).expect("partial resolves");
        let callable_payload = destination.get_primop(callable).expect("callable resolves");
        assert_eq!(partial_payload.builtin(), Some(builtin));
        assert_eq!(callable_payload.builtin(), Some(builtin));
        assert_eq!(partial_payload.symbol(), symbol);
        assert_eq!(callable_payload.symbol(), symbol);
        assert_eq!(partial_payload.args()[0].id(), IrId::new(23));
        assert_eq!(partial_payload.args()[0].span(), Span::new(4, 12));
        let argument = partial_payload.args()[0].value();
        assert_eq!(
            destination
                .get_string(argument)
                .expect("rewritten argument resolves")
                .bytes(),
            b"argument"
        );
    }

    #[test]
    fn lambda_destination_rebuilds_shared_captures_after_source_drop() {
        let (destination, forwarding, source_domain) = {
            let mut source = EvalHeap::new();
            let lexical = source
                .alloc_string(NixString::from_bytes(b"lexical".to_vec()))
                .expect("lexical value allocates");
            let with_value = source
                .alloc_string(NixString::from_bytes(b"with".to_vec()))
                .expect("with value allocates");
            let global = source
                .alloc_string(NixString::from_bytes(b"global".to_vec()))
                .expect("global value allocates");
            let frame = EvalFrame::new(1).expect("frame allocates");
            frame.set(0, lexical).expect("frame slot writes");
            let env = EvalEnv::capture(&[frame]).expect("environment captures");
            let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
                EvalModuleId::ROOT,
                IrId::new(31),
                with_value,
            )])
            .expect("with environment captures");
            let globals = EvalScopedGlobalEnv::capture(&[global]).expect("globals capture");
            let first = source
                .alloc_lambda(EvalLambda::with_captures(
                    EvalModuleId::ROOT,
                    IrId::new(11),
                    IrId::new(12),
                    FrameId::new(13),
                    env.clone(),
                    with_env.clone(),
                    globals.clone(),
                ))
                .expect("first lambda allocates");
            let second = source
                .alloc_lambda(EvalLambda::with_captures(
                    EvalModuleId::ROOT,
                    IrId::new(21),
                    IrId::new(22),
                    FrameId::new(23),
                    env,
                    with_env,
                    globals,
                ))
                .expect("second lambda allocates");
            let roots_list = source
                .alloc_list(NixList::new(vec![first, second]))
                .expect("root list allocates");
            let mut roots = EvalRootSet::new();
            roots
                .try_push_value_stack(0, roots_list)
                .expect("root appends");
            let plan = source.evacuation_plan(&roots).expect("plan succeeds");
            let source_domain = first.word().arena_domain();
            let (destination, forwarding) = source
                .write_supported_evacuation_destination(&plan)
                .expect("destination writes")
                .into_parts();
            (destination, forwarding, source_domain)
        };

        let lambdas: Vec<_> = forwarding
            .iter()
            .filter(|entry| entry.destination.tag() == ValueTag::Lambda)
            .map(|entry| entry.destination)
            .collect();
        assert_eq!(lambdas.len(), 2);
        assert_ne!(lambdas[0].word().arena_domain(), source_domain);
        let first = destination
            .get_lambda(lambdas[0])
            .expect("first lambda resolves");
        let second = destination
            .get_lambda(lambdas[1])
            .expect("second lambda resolves");
        assert!(
            (first.pattern(), first.body(), first.frame())
                == (IrId::new(11), IrId::new(12), FrameId::new(13))
                || (first.pattern(), first.body(), first.frame())
                    == (IrId::new(21), IrId::new(22), FrameId::new(23))
        );
        let first_frames = first.env().frames();
        let second_frames = second.env().frames();
        assert!(Arc::ptr_eq(&first_frames[0], &second_frames[0]));
        let lexical = first_frames[0].get(0).expect("lexical slot resolves");
        assert_eq!(
            destination
                .get_string(lexical)
                .expect("relocated lexical value resolves")
                .bytes(),
            b"lexical"
        );
        let with_value = first.with_scope_env().scopes()[0].value();
        assert_eq!(
            destination
                .get_string(with_value)
                .expect("relocated with value resolves")
                .bytes(),
            b"with"
        );
        let global = first.scoped_global_env().scopes()[0];
        assert_eq!(
            destination
                .get_string(global)
                .expect("relocated global resolves")
                .bytes(),
            b"global"
        );
    }

    #[test]
    fn ordinary_node_thunk_destination_rewrites_captures_and_preserves_force_state() {
        let (destination, forwarding, source_domain, source_values) = {
            let mut source = EvalHeap::new();
            let lexical = source
                .alloc_string(NixString::from_bytes(b"lexical".to_vec()))
                .expect("lexical value allocates");
            let flat = source
                .alloc_string(NixString::from_bytes(b"flat".to_vec()))
                .expect("flat value allocates");
            let with_value = source
                .alloc_string(NixString::from_bytes(b"with".to_vec()))
                .expect("with value allocates");
            let global = source
                .alloc_string(NixString::from_bytes(b"global".to_vec()))
                .expect("global value allocates");
            let result = source
                .alloc_string(NixString::from_bytes(b"result".to_vec()))
                .expect("result value allocates");

            let frame = EvalFrame::new(1).expect("frame allocates");
            frame.set(0, lexical).expect("frame slot writes");
            let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
                EvalModuleId::ROOT,
                IrId::new(41),
                with_value,
            )])
            .expect("with environment captures");
            let globals = EvalScopedGlobalEnv::capture(&[global]).expect("globals capture");
            let site = EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(42));
            let mut capture = EvalFlatCaptureBuffer::new(site, 1);
            capture.push(flat).expect("flat capture appends");
            let (suspended, tail) = source
                .alloc_thunk_with_flat_capture(
                    EvalThunk::with_captures(
                        EvalModuleId::ROOT,
                        IrId::new(43),
                        EvalEnv::default(),
                        with_env.clone(),
                        globals.clone(),
                    ),
                    Some(capture.finish()),
                )
                .expect("suspended flat-capture thunk allocates");
            let tail = tail.expect("flat-capture thunk owns a tail");
            let flat_base =
                EvalFlatCapture::inline(site, 1, tail).expect("flat capture handle is valid");
            let env = EvalEnv::capture_linked_with_flat_base(
                std::slice::from_ref(&frame),
                Some(flat_base),
            )
            .expect("combined environment captures");
            assert!(
                source
                    .replace_unique_flat_closure_env(suspended, env)
                    .expect("suspended thunk environment replaces")
            );

            let forced = source
                .alloc_thunk(EvalThunk::with_captures(
                    EvalModuleId::ROOT,
                    IrId::new(44),
                    EvalEnv::capture(std::slice::from_ref(&frame))
                        .expect("forced lexical environment captures"),
                    with_env,
                    globals,
                ))
                .expect("forced thunk allocates");
            let forced_thunk = source.get_thunk(forced).expect("forced thunk resolves");
            let crate::eval::ForceClaim::Claimed(guard) = forced_thunk
                .cell()
                .begin_force()
                .expect("forced thunk claims")
            else {
                panic!("fresh thunk must claim");
            };
            guard.finish(result).expect("forced result publishes");

            let roots_list = source
                .alloc_list(NixList::new(vec![suspended, forced]))
                .expect("thunk roots list allocates");
            let mut roots = EvalRootSet::new();
            roots
                .try_push_value_stack(0, roots_list)
                .expect("root appends");
            let plan = source.evacuation_plan(&roots).expect("plan succeeds");
            let source_domain = suspended.word().arena_domain();
            let source_values = [lexical, flat, with_value, global, result];
            let (destination, forwarding) = source
                .write_supported_evacuation_destination(&plan)
                .expect("destination writes")
                .into_parts();
            (destination, forwarding, source_domain, source_values)
        };

        let thunks: Vec<_> = forwarding
            .iter()
            .filter(|entry| entry.destination.tag() == ValueTag::Thunk)
            .map(|entry| entry.destination)
            .collect();
        assert_eq!(thunks.len(), 2);
        let suspended = thunks
            .iter()
            .copied()
            .find(|value| {
                destination
                    .get_thunk(*value)
                    .is_ok_and(|thunk| thunk.body() == Some(IrId::new(43)))
            })
            .expect("suspended Node thunk forwards");
        let forced = thunks
            .iter()
            .copied()
            .find(|value| {
                destination
                    .get_thunk(*value)
                    .is_ok_and(|thunk| thunk.body() == Some(IrId::new(44)))
            })
            .expect("forced Node thunk forwards");
        assert_ne!(suspended.word().arena_domain(), source_domain);

        let suspended_payload = destination
            .get_thunk(suspended)
            .expect("suspended destination resolves");
        assert_eq!(
            suspended_payload.cell().state().expect("state decodes"),
            ThunkState::Suspended
        );
        assert_eq!(
            suspended_payload.body_ref(),
            Some(EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(43)))
        );
        let lexical = suspended_payload
            .env()
            .expect("Node has an environment")
            .frames()[0]
            .get(0)
            .expect("lexical slot resolves");
        assert_eq!(
            destination
                .get_string(lexical)
                .expect("rewritten lexical value resolves")
                .bytes(),
            b"lexical"
        );
        let suspended_ptr = suspended
            .as_thunk_ptr()
            .expect("suspended destination is heap backed");
        let tail = destination
            .flat_closures
            .value_tail(suspended_ptr, FlatObjectKind::Thunk)
            .expect("destination tail resolves")
            .expect("destination tail is present");
        assert_eq!(tail.len(), 1);
        assert_eq!(
            destination
                .get_string(tail[0])
                .expect("rewritten flat capture resolves")
                .bytes(),
            b"flat"
        );
        assert_eq!(
            destination
                .get_string(
                    suspended_payload
                        .with_scope_env()
                        .expect("Node has dynamic scopes")
                        .scopes()[0]
                        .value()
                )
                .expect("rewritten dynamic scope resolves")
                .bytes(),
            b"with"
        );
        assert_eq!(
            destination
                .get_string(
                    suspended_payload
                        .scoped_global_env()
                        .expect("Node has scoped globals")
                        .scopes()[0]
                )
                .expect("rewritten scoped global resolves")
                .bytes(),
            b"global"
        );

        let forced_payload = destination
            .get_thunk(forced)
            .expect("forced destination resolves");
        assert_eq!(
            forced_payload.cell().state().expect("state decodes"),
            ThunkState::Forced
        );
        let cached = forced_payload
            .cell()
            .cached_value()
            .expect("cached result reads")
            .expect("forced thunk has a cached result");
        assert_eq!(
            destination
                .get_string(cached)
                .expect("rewritten cached result resolves")
                .bytes(),
            b"result"
        );

        for old_value in source_values {
            assert!(
                destination.get_string(old_value).is_err(),
                "no old-domain capture value resolves in the destination"
            );
        }
    }

    #[test]
    fn ordinary_node_thunk_destination_rejects_blackholes_and_shared_payloads() {
        let mut blackhole_heap = EvalHeap::new();
        let blackhole = blackhole_heap
            .alloc_thunk(EvalThunk::new(IrId::new(51)))
            .expect("blackhole thunk allocates");
        let blackhole_payload = blackhole_heap
            .get_thunk(blackhole)
            .expect("blackhole thunk resolves");
        let crate::eval::ForceClaim::Claimed(_guard) = blackhole_payload
            .cell()
            .begin_force()
            .expect("blackhole thunk claims")
        else {
            panic!("fresh thunk must claim");
        };
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, blackhole)
            .expect("blackhole root appends");
        let plan = blackhole_heap
            .evacuation_plan(&roots)
            .expect("blackhole plan builds");
        assert!(
            blackhole_heap
                .write_supported_evacuation_destination(&plan)
                .is_err(),
            "a blackholed thunk must fail closed"
        );

        let mut shared_heap = EvalHeap::new();
        let shared = shared_heap
            .alloc_thunk(EvalThunk::new(IrId::new(52)))
            .expect("shared thunk allocates");
        let shared_ptr = shared.as_thunk_ptr().expect("shared thunk has a pointer");
        let _shared_handle = shared_heap
            .share_thunk_from_ptr(shared_ptr, shared)
            .expect("thunk shares");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, shared)
            .expect("shared root appends");
        let plan = shared_heap
            .evacuation_plan(&roots)
            .expect("shared plan builds");
        assert!(
            shared_heap
                .write_supported_evacuation_destination(&plan)
                .is_err(),
            "a shared flat payload must fail closed"
        );
    }

    #[test]
    fn synthetic_flat_thunk_destination_preserves_every_shape_and_force_state() {
        let (destination, forwarding, source_values, symbol, builtin) = {
            let mut source = EvalHeap::new();
            let function = source
                .alloc_string(NixString::from_bytes(b"function".to_vec()))
                .expect("function value allocates");
            let argument = source
                .alloc_string(NixString::from_bytes(b"argument".to_vec()))
                .expect("argument value allocates");
            let first = source
                .alloc_string(NixString::from_bytes(b"first".to_vec()))
                .expect("first argument allocates");
            let second = source
                .alloc_string(NixString::from_bytes(b"second".to_vec()))
                .expect("second argument allocates");
            let receiver = source
                .alloc_string(NixString::from_bytes(b"receiver".to_vec()))
                .expect("receiver allocates");
            let result = source
                .alloc_string(NixString::from_bytes(b"result".to_vec()))
                .expect("result allocates");
            let mut symbols = SymbolTable::new();
            let symbol = symbols.intern(b"length").expect("symbol interns");
            let builtin = lookup_builtin(b"length").expect("length builtin exists");
            let shapes = [
                EvalThunk::apply(
                    EvalModuleId::ROOT,
                    IrId::new(61),
                    Span::new(1, 2),
                    function,
                    EvalModuleId::ROOT,
                    IrId::new(62),
                    argument,
                ),
                EvalThunk::genlist_elem_at_add_one(
                    EvalModuleId::ROOT,
                    IrId::new(63),
                    Span::new(3, 4),
                    function,
                    EvalModuleId::ROOT,
                    IrId::new(64),
                    argument,
                ),
                EvalThunk::apply2(
                    EvalModuleId::ROOT,
                    IrId::new(65),
                    Span::new(5, 6),
                    function,
                    EvalModuleId::ROOT,
                    IrId::new(66),
                    Span::new(7, 8),
                    first,
                    EvalModuleId::ROOT,
                    IrId::new(67),
                    Span::new(9, 10),
                    second,
                ),
                EvalThunk::select(
                    EvalModuleId::ROOT,
                    IrId::new(68),
                    receiver,
                    IrAttrPathId::new(2),
                ),
                EvalThunk::builtin_attr(symbol, builtin),
            ];
            let mut thunk_values = Vec::new();
            for shape in shapes {
                let suspended = source
                    .alloc_thunk(shape.clone())
                    .expect("suspended synthetic thunk allocates");
                let forced = source
                    .alloc_thunk(shape)
                    .expect("forced synthetic thunk allocates");
                let forced_payload = source.get_thunk(forced).expect("forced thunk resolves");
                let crate::eval::ForceClaim::Claimed(guard) = forced_payload
                    .cell()
                    .begin_force()
                    .expect("forced thunk claims")
                else {
                    panic!("fresh synthetic thunk must claim");
                };
                guard.finish(result).expect("forced result publishes");
                thunk_values.push(suspended);
                thunk_values.push(forced);
            }
            let roots_list = source
                .alloc_list(NixList::new(thunk_values))
                .expect("synthetic roots list allocates");
            let mut roots = EvalRootSet::new();
            roots
                .try_push_value_stack(0, roots_list)
                .expect("root appends");
            let plan = source.evacuation_plan(&roots).expect("plan succeeds");
            let source_values = [function, argument, first, second, receiver, result];
            let (destination, forwarding) = source
                .write_supported_evacuation_destination(&plan)
                .expect("destination writes")
                .into_parts();
            (destination, forwarding, source_values, symbol, builtin)
        };

        let thunks: Vec<_> = forwarding
            .iter()
            .filter(|entry| entry.destination.tag() == ValueTag::Thunk)
            .map(|entry| entry.destination)
            .collect();
        assert_eq!(thunks.len(), 10);
        let mut shape_states = [[0usize; 2]; 5];
        for value in thunks {
            let thunk = destination
                .get_thunk(value)
                .expect("synthetic destination resolves");
            let state = thunk.cell().state().expect("state decodes");
            let state_index = match state {
                ThunkState::Suspended => {
                    assert!(
                        thunk
                            .cell()
                            .cached_value()
                            .expect("cached value reads")
                            .is_none()
                    );
                    0
                }
                ThunkState::Forced => {
                    let cached = thunk
                        .cell()
                        .cached_value()
                        .expect("cached value reads")
                        .expect("forced thunk has a cached value");
                    assert_eq!(
                        destination
                            .get_string(cached)
                            .expect("rewritten forced result resolves")
                            .bytes(),
                        b"result"
                    );
                    1
                }
                ThunkState::Blackhole => panic!("destination cannot contain a blackhole"),
            };
            let (shape_index, embedded): (usize, Vec<Value>) = match thunk.kind() {
                EvalThunkKind::Apply {
                    function,
                    function_span,
                    function_value,
                    argument,
                    argument_value,
                } => {
                    assert_eq!(
                        *function,
                        EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(61))
                    );
                    assert_eq!(*function_span, Span::new(1, 2));
                    assert_eq!(
                        *argument,
                        EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(62))
                    );
                    (0, vec![*function_value, *argument_value])
                }
                EvalThunkKind::GenListElemAtAddOne {
                    function,
                    function_span,
                    function_value,
                    argument,
                    argument_value,
                } => {
                    assert_eq!(
                        *function,
                        EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(63))
                    );
                    assert_eq!(*function_span, Span::new(3, 4));
                    assert_eq!(
                        *argument,
                        EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(64))
                    );
                    (1, vec![*function_value, *argument_value])
                }
                EvalThunkKind::Apply2(apply) => {
                    assert_eq!(
                        apply.function,
                        EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(65))
                    );
                    assert_eq!(apply.function_span, Span::new(5, 6));
                    assert_eq!(
                        apply.first_argument,
                        EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(66))
                    );
                    assert_eq!(apply.first_argument_span, Span::new(7, 8));
                    assert_eq!(
                        apply.second_argument,
                        EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(67))
                    );
                    assert_eq!(apply.second_argument_span, Span::new(9, 10));
                    (
                        2,
                        vec![
                            apply.function_value,
                            apply.first_argument_value,
                            apply.second_argument_value,
                        ],
                    )
                }
                EvalThunkKind::Select {
                    select,
                    receiver,
                    path,
                } => {
                    assert_eq!(*select, EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(68)));
                    assert_eq!(*path, IrAttrPathId::new(2));
                    (3, vec![*receiver])
                }
                EvalThunkKind::BuiltinAttr {
                    symbol: actual_symbol,
                    builtin: actual_builtin,
                } => {
                    assert_eq!(*actual_symbol, symbol);
                    assert_eq!(*actual_builtin, builtin.kind());
                    (4, Vec::new())
                }
                EvalThunkKind::Node { .. } | EvalThunkKind::Released => {
                    panic!("synthetic destination changed thunk shape")
                }
            };
            shape_states[shape_index][state_index] += 1;
            for embedded_value in embedded {
                assert!(
                    destination.get_string(embedded_value).is_ok(),
                    "every embedded synthetic edge resolves in the destination"
                );
            }
        }
        assert_eq!(shape_states, [[1, 1]; 5]);
        for old_value in source_values {
            assert!(
                destination.get_string(old_value).is_err(),
                "no old-domain synthetic edge resolves in the destination"
            );
        }
    }

    #[test]
    fn synthetic_flat_thunk_destination_rejects_sidecars() {
        fn assert_rejected(thunk: EvalThunk) {
            let mut heap = EvalHeap::new();
            let value = heap.alloc_thunk(thunk).expect("test thunk allocates");
            let mut roots = EvalRootSet::new();
            roots
                .try_push_value_stack(0, value)
                .expect("test root appends");
            let plan = heap.evacuation_plan(&roots).expect("test plan builds");
            assert!(
                heap.write_supported_evacuation_destination(&plan).is_err(),
                "unsupported synthetic storage must fail closed"
            );
        }

        let apply = || {
            EvalThunk::apply(
                EvalModuleId::ROOT,
                IrId::new(71),
                Span::new(1, 2),
                Value::int(1),
                EvalModuleId::ROOT,
                IrId::new(72),
                Value::int(2),
            )
        };
        assert_rejected(apply().into_single_entry());
        assert_rejected(apply().with_parallel_payload_cell(
            crate::eval::TreeWalkError::new(
                crate::eval::TreeWalkErrorKind::DivisionByZero { id: IrId::new(73) },
                Span::new(3, 4),
            ),
            None,
        ));
    }

    #[test]
    fn released_flat_thunk_destination_preserves_result_and_physical_extent() {
        let mut source = EvalHeap::new();
        let site = EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(74));
        let capture = EvalFlatCaptureBuffer::pending(site, 0, 1).expect("padding capture reserves");
        let (released, _) = source
            .alloc_thunk_with_flat_capture(
                EvalThunk::released_forced(Value::int(76)),
                Some(capture),
            )
            .expect("released source allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, released)
            .expect("released root appends");
        let plan = source.evacuation_plan(&roots).expect("plan builds");
        let (destination, forwarding) = source
            .write_supported_evacuation_destination(&plan)
            .expect("released destination writes")
            .into_parts();
        let moved = forwarding
            .iter()
            .find(|entry| entry.source_address == released.as_heap_ptr().unwrap().as_ptr() as usize)
            .map(|entry| entry.destination)
            .expect("released forwarding exists");
        let thunk = destination
            .get_thunk(moved)
            .expect("released destination resolves");
        assert!(matches!(thunk.kind(), EvalThunkKind::Released));
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Forced));
        assert!(
            thunk
                .cell()
                .cached_value()
                .expect("released cached result reads")
                .is_some_and(|value| value.raw_eq(Value::int(76)))
        );
    }

    #[test]
    #[allow(unsafe_code)]
    fn typed_head_destination_preserves_suspended_and_forced_states_after_source_drop() {
        let (destination, forwarding, typed_offsets) = {
            let mut source = EvalHeap::new();
            source.enable_typed_apply_thunk_heads();
            let function = source
                .alloc_string(NixString::from_bytes(b"function".to_vec()))
                .expect("function value allocates");
            let argument = source
                .alloc_string(NixString::from_bytes(b"argument".to_vec()))
                .expect("argument value allocates");
            let result = source
                .alloc_string(NixString::from_bytes(b"result".to_vec()))
                .expect("result value allocates");
            let suspended = source
                .try_typed_alloc_thunk(EvalThunk::apply(
                    EvalModuleId::ROOT,
                    IrId::new(1),
                    Span::new(2, 3),
                    function,
                    EvalModuleId::ROOT,
                    IrId::new(4),
                    argument,
                ))
                .expect("typed allocation succeeds")
                .expect("synthetic thunk uses a typed head");
            let forced = source
                .try_typed_alloc_thunk(EvalThunk::apply(
                    EvalModuleId::ROOT,
                    IrId::new(5),
                    Span::new(6, 7),
                    function,
                    EvalModuleId::ROOT,
                    IrId::new(8),
                    argument,
                ))
                .expect("typed allocation succeeds")
                .expect("synthetic thunk uses a typed head");
            let forced_ptr = source.thunk_ptr(forced).expect("typed pointer resolves");
            let parts = source
                .typed_thunk_force_parts(forced_ptr)
                .expect("typed force parts resolve")
                .expect("value names a typed head");
            // SAFETY: `parts` belongs to `source`, which remains alive through
            // publication and work-slot release below.
            let TypedThunkForceClaim::Claimed(guard) =
                (unsafe { parts.begin_force() }).expect("suspended head claims")
            else {
                panic!("fresh typed head cannot already be forced");
            };
            let handle = guard.handle();
            let work = source
                .take_typed_thunk_work(forced_ptr, handle)
                .expect("typed work detaches");
            guard.finish(result).expect("typed result publishes");
            drop(work);
            source
                .release_taken_typed_thunk_work(forced_ptr, handle)
                .expect("typed work slot releases");

            let roots_list = source
                .alloc_list(NixList::new(vec![suspended, forced]))
                .expect("typed roots list allocates");
            let mut roots = EvalRootSet::new();
            roots
                .try_push_value_stack(0, roots_list)
                .expect("root appends");
            let plan = source.evacuation_plan(&roots).expect("plan succeeds");
            let typed_offsets: HashMap<_, _> = plan
                .forwarding()
                .iter()
                .filter(|entry| entry.lane == EvacuationLane::TypedThunkHeads)
                .map(|entry| (entry.source_address, entry.destination_offset))
                .collect();
            let (destination, forwarding) = source
                .write_supported_evacuation_destination(&plan)
                .expect("destination writes")
                .into_parts();
            (destination, forwarding, typed_offsets)
        };

        let typed: Vec<_> = forwarding
            .iter()
            .filter(|entry| entry.destination.tag() == ValueTag::Thunk)
            .collect();
        assert_eq!(typed.len(), 2);
        let typed_base = typed
            .iter()
            .map(|entry| {
                entry
                    .destination
                    .as_heap_ptr()
                    .expect("typed destination is heap backed")
                    .as_ptr() as usize
            })
            .min()
            .expect("typed destinations are non-empty");
        for entry in &typed {
            let address = entry
                .destination
                .as_heap_ptr()
                .expect("typed destination is heap backed")
                .as_ptr() as usize;
            assert_eq!(
                address - typed_base,
                typed_offsets[&entry.source_address],
                "typed lane preserves its exact Stage-A offset"
            );
        }

        let suspended = typed
            .iter()
            .find(|entry| {
                destination.typed_thunk_state_if_any(entry.destination)
                    == Some(ThunkState::Suspended)
            })
            .expect("suspended typed head forwards")
            .destination;
        let EvalThunkKind::Apply {
            function_value,
            argument_value,
            ..
        } = destination
            .get_thunk(suspended)
            .expect("suspended work resolves")
            .kind()
        else {
            panic!("suspended typed work keeps its Apply shape");
        };
        assert_eq!(
            destination
                .get_string(*function_value)
                .expect("relocated function resolves")
                .bytes(),
            b"function"
        );
        assert_eq!(
            destination
                .get_string(*argument_value)
                .expect("relocated argument resolves")
                .bytes(),
            b"argument"
        );

        let forced = typed
            .iter()
            .find(|entry| {
                destination.typed_thunk_state_if_any(entry.destination) == Some(ThunkState::Forced)
            })
            .expect("forced typed head forwards")
            .destination;
        let forced_ptr = destination
            .thunk_ptr(forced)
            .expect("forced typed pointer resolves");
        let parts = destination
            .typed_thunk_force_parts(forced_ptr)
            .expect("forced parts resolve")
            .expect("forced value names a typed head");
        // SAFETY: `parts` belongs to the live destination heap.
        match unsafe { parts.begin_force() }.expect("forced head replays") {
            TypedThunkForceClaim::AlreadyForced(value) => assert_eq!(
                destination
                    .get_string(value)
                    .expect("relocated result resolves")
                    .bytes(),
                b"result"
            ),
            TypedThunkForceClaim::Claimed(_) => panic!("forced typed head must not claim"),
        }
    }
}
