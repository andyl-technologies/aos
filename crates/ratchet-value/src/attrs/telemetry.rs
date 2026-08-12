//! In-process measurement helpers for attrset representation precursors.
//!
//! RFC-0007's hidden-class, inline-cache, and HAMT thresholds are meant to be
//! selected from measurements, not fixed by intuition. This module provides a
//! byte-neutral telemetry accumulator over the current precursor types: shape
//! instances, representation-dispatching slow-select outcomes, select-cache
//! terminal states and lookup outcomes, representation-policy decisions,
//! update-merge sizes and override-chain depths, and order-parity check
//! outcomes. It does not install shape/PIC/HAMT runtime hooks, mutate evaluator
//! values, serialize counters, or change observable Nix results.

use std::collections::HashMap;

use thiserror::Error;

use super::hamt::HamtMergeSummary;
use super::pic::{
    FlatSelectCacheState, HamtSelectCacheState, HamtSelectOutcome, HamtSelectSource,
    InlineCacheState, ShapedSelectCacheState, ShapedSelectOutcome, ShapedSelectSource,
};
use super::repr::{AttrSetConstruction, AttrSetReprDecision, AttrSetReprKind, AttrSetReprReason};
use super::select::{AttrSelectOutcome, AttrSelectRepr, AttrSelectSource};
use super::shape::{ShapeFingerprint, ShapeHandle, ShapeId};

/// Aggregates attrset measurement samples for one in-process evaluation.
#[derive(Clone, Debug, Default)]
pub struct AttrTelemetry {
    shapes: HashMap<ShapeId, ShapeCensusEntry>,
    inline_cache_states: InlineCacheStateCounts,
    flat_select_states: InlineCacheStateCounts,
    shaped_select_states: InlineCacheStateCounts,
    hamt_select_states: HamtSelectStateCounts,
    slow_select_lookups: SlowSelectLookupCounts,
    shaped_select_lookups: SelectLookupCounts,
    hamt_select_lookups: SelectLookupCounts,
    update_merges: UpdateMergeStats,
    order_parity: OrderParityStats,
}

impl AttrTelemetry {
    /// Creates an empty telemetry accumulator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one shaped attrset instance.
    ///
    /// Shape ids are meaningful only inside the [`super::shape::ShapeTable`]
    /// that produced `shape`. Feed one telemetry accumulator from one shape
    /// table, or remap ids before merging snapshots from multiple tables.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::AllocationFailed`] if a newly observed
    /// shape cannot reserve storage in the census table. Returns
    /// [`AttrTelemetryError::CounterOverflow`] if an existing shape's instance
    /// count cannot be incremented.
    pub fn record_shape_instance(&mut self, shape: &ShapeHandle) -> Result<(), AttrTelemetryError> {
        let id = shape.id();
        if let Some(entry) = self.shapes.get_mut(&id) {
            entry.instances =
                entry
                    .instances
                    .checked_add(1)
                    .ok_or(AttrTelemetryError::CounterOverflow {
                        counter: "shape instances",
                    })?;
            return Ok(());
        }

        self.shapes
            .try_reserve(1)
            .map_err(|_| AttrTelemetryError::AllocationFailed {
                entries: self.shapes.len().saturating_add(1),
            })?;
        self.shapes.insert(
            id,
            ShapeCensusEntry {
                id,
                key_count: shape.shape().len(),
                fingerprint: shape.shape().fingerprint(),
                instances: 1,
            },
        );
        Ok(())
    }

    /// Returns a deterministic shape-census snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::AllocationFailed`] if snapshot vectors
    /// cannot reserve storage. Returns
    /// [`AttrTelemetryError::CounterOverflow`] if total-instance or
    /// multiplicity counters cannot be represented.
    pub fn shape_census(&self) -> Result<ShapeCensusSnapshot, AttrTelemetryError> {
        let mut shapes = Vec::new();
        shapes.try_reserve_exact(self.shapes.len()).map_err(|_| {
            AttrTelemetryError::AllocationFailed {
                entries: self.shapes.len(),
            }
        })?;
        shapes.extend(self.shapes.values().copied());
        shapes.sort_unstable_by_key(|entry| entry.id.as_u32());

        let total_instances = shapes.iter().try_fold(0usize, |total, shape| {
            total
                .checked_add(shape.instances)
                .ok_or(AttrTelemetryError::CounterOverflow {
                    counter: "total shape instances",
                })
        })?;

        let multiplicity = multiplicity_distribution(&shapes)?;
        Ok(ShapeCensusSnapshot {
            total_instances,
            distinct_shapes: shapes.len(),
            shapes: shapes.into_boxed_slice(),
            multiplicity,
        })
    }

    /// Records the terminal state of one generic shape-id inline-cache site.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::CounterOverflow`] if a state counter
    /// cannot be incremented.
    pub fn record_inline_cache_site(
        &mut self,
        state: &InlineCacheState,
    ) -> Result<(), AttrTelemetryError> {
        self.inline_cache_states.record_inline_cache(state)
    }

    /// Records the terminal state of one flat select-cache site.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::CounterOverflow`] if a state counter
    /// cannot be incremented.
    pub fn record_flat_select_site(
        &mut self,
        state: &FlatSelectCacheState,
    ) -> Result<(), AttrTelemetryError> {
        self.flat_select_states.record_flat_select(state)
    }

    /// Records the terminal state of one shaped select-cache site.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::CounterOverflow`] if a state counter
    /// cannot be incremented.
    pub fn record_shaped_select_site(
        &mut self,
        state: &ShapedSelectCacheState,
    ) -> Result<(), AttrTelemetryError> {
        self.shaped_select_states.record_shaped_select(state)
    }

    /// Records the terminal state of one HAMT select-policy site.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::CounterOverflow`] if a state counter
    /// cannot be incremented.
    pub fn record_hamt_select_site(
        &mut self,
        state: HamtSelectCacheState,
    ) -> Result<(), AttrTelemetryError> {
        self.hamt_select_states.record(state)
    }

    /// Records one representation-dispatching slow-select outcome.
    ///
    /// This is a value-level measurement hook for the shared slow resolver. It
    /// does not distinguish active tree-walk callers from select-cache miss
    /// callers; callers that need that split should keep separate counters
    /// around this byte-neutral aggregate.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::CounterOverflow`] if a lookup counter
    /// cannot be incremented.
    pub fn record_slow_select_lookup(
        &mut self,
        outcome: &AttrSelectOutcome,
    ) -> Result<(), AttrTelemetryError> {
        let mut counts = self.slow_select_lookups;
        counts.record(outcome)?;
        self.slow_select_lookups = counts;
        Ok(())
    }

    /// Records one shaped select-cache lookup outcome.
    ///
    /// This method tracks lookup counts only. Call
    /// [`Self::record_shaped_select_site`] separately when recording terminal
    /// per-site histograms. Pass the cache state observed for this lookup; a
    /// later widened terminal state can no longer prove whether a cached hit
    /// was monomorphic at the time it happened.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::CounterOverflow`] if a lookup counter
    /// cannot be incremented.
    pub fn record_shaped_select_lookup(
        &mut self,
        state: &ShapedSelectCacheState,
        outcome: &ShapedSelectOutcome,
    ) -> Result<(), AttrTelemetryError> {
        let mut counts = self.shaped_select_lookups;
        match outcome {
            ShapedSelectOutcome::Hit { source, .. } => {
                counts.record_hit()?;
                match source {
                    ShapedSelectSource::Cached => {
                        counts.record_cached_hit()?;
                        if matches!(state, ShapedSelectCacheState::Monomorphic { .. }) {
                            counts.record_monomorphic_fast_hit()?;
                        }
                    }
                    ShapedSelectSource::Resolved { .. } => {
                        counts.record_resolved_hit()?;
                    }
                }
            }
            ShapedSelectOutcome::Missing => {
                counts.record_missing()?;
                counts.record_resolved_missing()?;
            }
        }
        self.shaped_select_lookups = counts;
        Ok(())
    }

    /// Records one HAMT select-policy lookup outcome.
    ///
    /// This method tracks lookup counts only. Call
    /// [`Self::record_hamt_select_site`] separately when recording terminal
    /// per-site histograms.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::CounterOverflow`] if a lookup counter
    /// cannot be incremented.
    pub fn record_hamt_select_lookup(
        &mut self,
        outcome: &HamtSelectOutcome,
    ) -> Result<(), AttrTelemetryError> {
        let mut counts = self.hamt_select_lookups;
        match outcome {
            HamtSelectOutcome::Hit { source, .. } => {
                counts.record_hit()?;
                match source {
                    HamtSelectSource::CachedDistinguishedHamt => {
                        counts.record_cached_hit()?;
                    }
                    HamtSelectSource::Resolved { .. } => {
                        counts.record_resolved_hit()?;
                    }
                }
            }
            HamtSelectOutcome::Missing { source } => {
                counts.record_missing()?;
                match source {
                    HamtSelectSource::CachedDistinguishedHamt => {
                        counts.record_cached_missing()?;
                    }
                    HamtSelectSource::Resolved { .. } => {
                        counts.record_resolved_missing()?;
                    }
                }
            }
        }
        self.hamt_select_lookups = counts;
        Ok(())
    }

    /// Records one representation-policy decision.
    ///
    /// Update-merge constructions contribute to the `//` size and chain-depth
    /// distributions. Static and dynamic construction decisions are counted by
    /// representation kind and reason but do not affect update-merge histograms.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::AllocationFailed`] if a histogram bucket
    /// cannot reserve storage. Returns
    /// [`AttrTelemetryError::CounterOverflow`] if a counter cannot be
    /// incremented.
    pub fn record_repr_decision(
        &mut self,
        construction: AttrSetConstruction,
        decision: AttrSetReprDecision,
    ) -> Result<(), AttrTelemetryError> {
        let mut next = self.update_merges.clone();
        next.record_decision(construction, decision)?;
        self.update_merges = next;
        Ok(())
    }

    /// Records one policy-dispatched update merge and optional HAMT summary.
    ///
    /// This records both the representation decision and the `//` merge-size
    /// sample. Use [`Self::record_repr_decision`] for construction decisions
    /// that do not have merge accounting.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::AllocationFailed`] if a histogram bucket
    /// cannot reserve storage. Returns
    /// [`AttrTelemetryError::CounterOverflow`] if a counter cannot be
    /// incremented. Returns
    /// [`AttrTelemetryError::UnexpectedHamtSummaryForFlatDecision`] if
    /// `hamt_summary` is present for a flat representation decision.
    pub fn record_update_merge(
        &mut self,
        left_len: usize,
        right_len: usize,
        override_chain_depth: usize,
        decision: AttrSetReprDecision,
        hamt_summary: Option<HamtMergeSummary>,
    ) -> Result<(), AttrTelemetryError> {
        let mut next = self.update_merges.clone();
        next.record_repr(decision)?;
        next.record_update_merge_sample(
            left_len,
            right_len,
            override_chain_depth,
            decision,
            hamt_summary,
        )?;
        self.update_merges = next;
        Ok(())
    }

    /// Records the result of one order-parity check.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::CounterOverflow`] if the outcome counter
    /// cannot be incremented.
    pub fn record_order_parity_check(&mut self, matched: bool) -> Result<(), AttrTelemetryError> {
        let mut next = self.order_parity;
        next.record(matched)?;
        self.order_parity = next;
        Ok(())
    }

    /// Returns the inline-cache terminal-state and lookup snapshot.
    pub const fn inline_cache_snapshot(&self) -> InlineCacheSnapshot {
        InlineCacheSnapshot {
            generic_sites: self.inline_cache_states,
            flat_select_sites: self.flat_select_states,
            shaped_select_sites: self.shaped_select_states,
            hamt_select_sites: self.hamt_select_states,
            shaped_select_lookups: self.shaped_select_lookups,
            hamt_select_lookups: self.hamt_select_lookups,
        }
    }

    /// Returns order-parity check counts.
    pub const fn order_parity_stats(&self) -> OrderParityStats {
        self.order_parity
    }

    /// Returns representation-dispatching slow-select lookup counts.
    pub const fn slow_select_snapshot(&self) -> SlowSelectLookupCounts {
        self.slow_select_lookups
    }

    /// Returns the update-merge measurement snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AttrTelemetryError::AllocationFailed`] if snapshot vectors
    /// cannot reserve storage.
    pub fn update_merge_snapshot(&self) -> Result<UpdateMergeSnapshot, AttrTelemetryError> {
        self.update_merges.snapshot()
    }
}

/// One shape census row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShapeCensusEntry {
    /// Process-local shape id from one shape table.
    pub id: ShapeId,
    /// Number of keys described by the shape.
    pub key_count: usize,
    /// In-process fingerprint of the shape key vector.
    pub fingerprint: ShapeFingerprint,
    /// Number of instances recorded for this shape.
    pub instances: usize,
}

/// A deterministic shape-census snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShapeCensusSnapshot {
    /// Total shaped instances recorded.
    pub total_instances: usize,
    /// Number of distinct shape ids observed.
    pub distinct_shapes: usize,
    /// Shape rows sorted by process-local shape id.
    pub shapes: Box<[ShapeCensusEntry]>,
    /// Distribution of how many shapes had a given instance count.
    pub multiplicity: Box<[ShapeMultiplicityBucket]>,
}

/// One bucket in the shape-multiplicity distribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShapeMultiplicityBucket {
    /// Number of instances attached to one shape.
    pub instances_per_shape: usize,
    /// Number of shapes with that instance count.
    pub shape_count: usize,
}

/// Terminal state counts for generic, flat, and shaped inline caches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct InlineCacheStateCounts {
    /// Sites that observed no shape.
    pub uninitialized: usize,
    /// Sites with one cached shape.
    pub monomorphic: usize,
    /// Sites with a bounded polymorphic entry list.
    pub polymorphic: usize,
    /// Sites that fell back to megamorphic dispatch.
    pub megamorphic: usize,
}

impl InlineCacheStateCounts {
    fn record_inline_cache(&mut self, state: &InlineCacheState) -> Result<(), AttrTelemetryError> {
        match state {
            InlineCacheState::Uninitialized => {
                increment(&mut self.uninitialized, "IC uninitialized")?
            }
            InlineCacheState::Monomorphic { .. } => {
                increment(&mut self.monomorphic, "IC monomorphic")?
            }
            InlineCacheState::Polymorphic { .. } => {
                increment(&mut self.polymorphic, "IC polymorphic")?
            }
            InlineCacheState::Megamorphic => increment(&mut self.megamorphic, "IC megamorphic")?,
        }
        Ok(())
    }

    fn record_shaped_select(
        &mut self,
        state: &ShapedSelectCacheState,
    ) -> Result<(), AttrTelemetryError> {
        match state {
            ShapedSelectCacheState::Uninitialized => {
                increment(&mut self.uninitialized, "shaped select uninitialized")?
            }
            ShapedSelectCacheState::Monomorphic { .. } => {
                increment(&mut self.monomorphic, "shaped select monomorphic")?
            }
            ShapedSelectCacheState::Polymorphic { .. } => {
                increment(&mut self.polymorphic, "shaped select polymorphic")?
            }
            ShapedSelectCacheState::Megamorphic => {
                increment(&mut self.megamorphic, "shaped select megamorphic")?
            }
        }
        Ok(())
    }

    fn record_flat_select(
        &mut self,
        state: &FlatSelectCacheState,
    ) -> Result<(), AttrTelemetryError> {
        match state {
            FlatSelectCacheState::Uninitialized => {
                increment(&mut self.uninitialized, "flat select uninitialized")?
            }
            FlatSelectCacheState::Monomorphic { .. } => {
                increment(&mut self.monomorphic, "flat select monomorphic")?
            }
            FlatSelectCacheState::Polymorphic { .. } => {
                increment(&mut self.polymorphic, "flat select polymorphic")?
            }
            FlatSelectCacheState::Megamorphic => {
                increment(&mut self.megamorphic, "flat select megamorphic")?
            }
        }
        Ok(())
    }
}

/// Terminal state counts for HAMT select-policy sites.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HamtSelectStateCounts {
    /// Sites that observed no HAMT value.
    pub uninitialized: usize,
    /// Sites with a distinguished HAMT entry.
    pub distinguished_hamt: usize,
    /// Sites that fell back to megamorphic dispatch.
    pub megamorphic: usize,
}

impl HamtSelectStateCounts {
    fn record(&mut self, state: HamtSelectCacheState) -> Result<(), AttrTelemetryError> {
        match state {
            HamtSelectCacheState::Uninitialized => {
                increment(&mut self.uninitialized, "HAMT select uninitialized")?
            }
            HamtSelectCacheState::DistinguishedHamt => {
                increment(&mut self.distinguished_hamt, "HAMT select distinguished")?
            }
            HamtSelectCacheState::Megamorphic => {
                increment(&mut self.megamorphic, "HAMT select megamorphic")?
            }
        }
        Ok(())
    }
}

/// Select-cache terminal-state and lookup measurements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct InlineCacheSnapshot {
    /// Generic shape-id PIC terminal states.
    pub generic_sites: InlineCacheStateCounts,
    /// Flat select-cache terminal states.
    pub flat_select_sites: InlineCacheStateCounts,
    /// Shaped select-cache terminal states.
    pub shaped_select_sites: InlineCacheStateCounts,
    /// HAMT select-policy terminal states.
    pub hamt_select_sites: HamtSelectStateCounts,
    /// Shaped select-cache lookup outcomes.
    pub shaped_select_lookups: SelectLookupCounts,
    /// HAMT select-policy lookup outcomes.
    pub hamt_select_lookups: SelectLookupCounts,
}

/// Lookup outcome counts for representation-dispatching slow selects.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SlowSelectLookupCounts {
    /// Successful flat attrset lookups.
    pub flat_hits: usize,
    /// Missing-key flat attrset lookups.
    pub flat_misses: usize,
    /// Successful HAMT attrset lookups.
    pub hamt_hits: usize,
    /// Missing-key HAMT attrset lookups.
    pub hamt_misses: usize,
    /// Successful shaped attrset lookups.
    pub shaped_hits: usize,
    /// Missing-key shaped attrset lookups.
    pub shaped_misses: usize,
}

impl SlowSelectLookupCounts {
    fn record(&mut self, outcome: &AttrSelectOutcome) -> Result<(), AttrTelemetryError> {
        match outcome {
            AttrSelectOutcome::Hit { source, .. } => self.record_hit(hit_source_repr(*source)),
            AttrSelectOutcome::Missing { repr } => self.record_missing(*repr),
        }
    }

    fn record_hit(&mut self, repr: AttrSelectRepr) -> Result<(), AttrTelemetryError> {
        match repr {
            AttrSelectRepr::Flat => increment(&mut self.flat_hits, "flat slow-select hits"),
            AttrSelectRepr::Hamt => increment(&mut self.hamt_hits, "HAMT slow-select hits"),
            AttrSelectRepr::Shaped => increment(&mut self.shaped_hits, "shaped slow-select hits"),
        }
    }

    fn record_missing(&mut self, repr: AttrSelectRepr) -> Result<(), AttrTelemetryError> {
        match repr {
            AttrSelectRepr::Flat => increment(&mut self.flat_misses, "flat slow-select misses"),
            AttrSelectRepr::Hamt => increment(&mut self.hamt_misses, "HAMT slow-select misses"),
            AttrSelectRepr::Shaped => {
                increment(&mut self.shaped_misses, "shaped slow-select misses")
            }
        }
    }
}

/// Lookup outcome counts for select-cache precursors.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SelectLookupCounts {
    /// Successful lookups.
    pub hits: usize,
    /// Missing-key lookups.
    pub misses: usize,
    /// Hits served by a cached path.
    pub cached_hits: usize,
    /// Hits served by a resolving path.
    pub resolved_hits: usize,
    /// Missing-key lookups served by a cached path.
    pub cached_misses: usize,
    /// Missing-key lookups served by a resolving path.
    pub resolved_misses: usize,
    /// Cached hits observed while the shaped select site was monomorphic.
    pub monomorphic_fast_hits: usize,
}

impl SelectLookupCounts {
    fn record_hit(&mut self) -> Result<(), AttrTelemetryError> {
        increment(&mut self.hits, "select hits")
    }

    fn record_missing(&mut self) -> Result<(), AttrTelemetryError> {
        increment(&mut self.misses, "select misses")
    }

    fn record_cached_hit(&mut self) -> Result<(), AttrTelemetryError> {
        increment(&mut self.cached_hits, "select cached hits")
    }

    fn record_resolved_hit(&mut self) -> Result<(), AttrTelemetryError> {
        increment(&mut self.resolved_hits, "select resolved hits")
    }

    fn record_cached_missing(&mut self) -> Result<(), AttrTelemetryError> {
        increment(&mut self.cached_misses, "select cached misses")
    }

    fn record_resolved_missing(&mut self) -> Result<(), AttrTelemetryError> {
        increment(&mut self.resolved_misses, "select resolved misses")
    }

    fn record_monomorphic_fast_hit(&mut self) -> Result<(), AttrTelemetryError> {
        increment(
            &mut self.monomorphic_fast_hits,
            "select monomorphic fast hits",
        )
    }
}

#[derive(Clone, Debug, Default)]
struct UpdateMergeStats {
    decisions: usize,
    flat_decisions: usize,
    hamt_decisions: usize,
    update_merges: usize,
    flat_update_merges: usize,
    hamt_update_merges: usize,
    hamt_inserted: usize,
    hamt_replaced: usize,
    reasons: ReprReasonCounts,
    left_len_distribution: HashMap<usize, usize>,
    right_len_distribution: HashMap<usize, usize>,
    result_len_upper_bound_distribution: HashMap<usize, usize>,
    override_chain_depth_distribution: HashMap<usize, usize>,
}

impl UpdateMergeStats {
    fn record_decision(
        &mut self,
        construction: AttrSetConstruction,
        decision: AttrSetReprDecision,
    ) -> Result<(), AttrTelemetryError> {
        self.record_repr(decision)?;
        if let AttrSetConstruction::UpdateMerge {
            left_len,
            right_len,
            override_chain_depth,
            ..
        } = construction
        {
            self.record_update_merge_sample(
                left_len,
                right_len,
                override_chain_depth,
                decision,
                None,
            )?;
        }
        Ok(())
    }

    fn record_update_merge_sample(
        &mut self,
        left_len: usize,
        right_len: usize,
        override_chain_depth: usize,
        decision: AttrSetReprDecision,
        hamt_summary: Option<HamtMergeSummary>,
    ) -> Result<(), AttrTelemetryError> {
        if matches!(decision.kind(), AttrSetReprKind::Flat) && hamt_summary.is_some() {
            return Err(AttrTelemetryError::UnexpectedHamtSummaryForFlatDecision);
        }

        increment(&mut self.update_merges, "update merges")?;
        match decision.kind() {
            AttrSetReprKind::Flat => increment(&mut self.flat_update_merges, "flat update merges")?,
            AttrSetReprKind::Hamt => increment(&mut self.hamt_update_merges, "HAMT update merges")?,
        }
        record_bucket(&mut self.left_len_distribution, left_len)?;
        record_bucket(&mut self.right_len_distribution, right_len)?;
        record_bucket(
            &mut self.result_len_upper_bound_distribution,
            decision.result_len_upper_bound(),
        )?;
        record_bucket(
            &mut self.override_chain_depth_distribution,
            override_chain_depth,
        )?;
        if let Some(summary) = hamt_summary {
            self.hamt_inserted = self.hamt_inserted.checked_add(summary.inserted()).ok_or(
                AttrTelemetryError::CounterOverflow {
                    counter: "HAMT inserted",
                },
            )?;
            self.hamt_replaced = self.hamt_replaced.checked_add(summary.replaced()).ok_or(
                AttrTelemetryError::CounterOverflow {
                    counter: "HAMT replaced",
                },
            )?;
        }
        Ok(())
    }

    fn record_repr(&mut self, decision: AttrSetReprDecision) -> Result<(), AttrTelemetryError> {
        increment(&mut self.decisions, "representation decisions")?;
        match decision.kind() {
            AttrSetReprKind::Flat => increment(&mut self.flat_decisions, "flat decisions")?,
            AttrSetReprKind::Hamt => increment(&mut self.hamt_decisions, "HAMT decisions")?,
        }
        self.reasons.record(decision.reason())?;
        Ok(())
    }

    fn snapshot(&self) -> Result<UpdateMergeSnapshot, AttrTelemetryError> {
        Ok(UpdateMergeSnapshot {
            decisions: self.decisions,
            flat_decisions: self.flat_decisions,
            hamt_decisions: self.hamt_decisions,
            update_merges: self.update_merges,
            flat_update_merges: self.flat_update_merges,
            hamt_update_merges: self.hamt_update_merges,
            hamt_inserted: self.hamt_inserted,
            hamt_replaced: self.hamt_replaced,
            reasons: self.reasons,
            left_len_distribution: sorted_buckets(&self.left_len_distribution)?,
            right_len_distribution: sorted_buckets(&self.right_len_distribution)?,
            result_len_upper_bound_distribution: sorted_buckets(
                &self.result_len_upper_bound_distribution,
            )?,
            override_chain_depth_distribution: sorted_buckets(
                &self.override_chain_depth_distribution,
            )?,
        })
    }
}

/// A deterministic update-merge telemetry snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateMergeSnapshot {
    /// Total representation decisions recorded.
    pub decisions: usize,
    /// Decisions that selected flat storage.
    pub flat_decisions: usize,
    /// Decisions that selected HAMT storage.
    pub hamt_decisions: usize,
    /// Number of `//` update merges recorded.
    pub update_merges: usize,
    /// Update merges that selected flat storage.
    pub flat_update_merges: usize,
    /// Update merges that selected HAMT storage.
    pub hamt_update_merges: usize,
    /// Total right-hand keys inserted by HAMT merge summaries.
    pub hamt_inserted: usize,
    /// Total right-hand keys replaced by HAMT merge summaries.
    pub hamt_replaced: usize,
    /// Decision counts by policy reason.
    pub reasons: ReprReasonCounts,
    /// Left operand size distribution for update merges.
    pub left_len_distribution: Box<[HistogramBucket]>,
    /// Right operand size distribution for update merges.
    pub right_len_distribution: Box<[HistogramBucket]>,
    /// Result length upper-bound distribution for update merges.
    pub result_len_upper_bound_distribution: Box<[HistogramBucket]>,
    /// Override-chain depth distribution for update merges.
    pub override_chain_depth_distribution: Box<[HistogramBucket]>,
}

/// Counts representation decisions by policy reason.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ReprReasonCounts {
    /// Static literals kept flat.
    pub static_literal: usize,
    /// Small shape-stable constructions kept flat.
    pub small_shape_stable: usize,
    /// Existing HAMT left operands kept HAMT-backed.
    pub left_already_hamt: usize,
    /// Large update merges promoted to HAMT.
    pub large_update_merge: usize,
    /// Deep override chains promoted to HAMT.
    pub deep_override_chain: usize,
    /// Large dynamic constructions promoted to HAMT.
    pub large_dynamic_construction: usize,
}

impl ReprReasonCounts {
    fn record(&mut self, reason: AttrSetReprReason) -> Result<(), AttrTelemetryError> {
        match reason {
            AttrSetReprReason::StaticLiteral => {
                increment(&mut self.static_literal, "static literal decisions")?
            }
            AttrSetReprReason::SmallShapeStable => {
                increment(&mut self.small_shape_stable, "small shape-stable decisions")?
            }
            AttrSetReprReason::LeftAlreadyHamt => {
                increment(&mut self.left_already_hamt, "left-already-HAMT decisions")?
            }
            AttrSetReprReason::LargeUpdateMerge => {
                increment(&mut self.large_update_merge, "large update-merge decisions")?
            }
            AttrSetReprReason::DeepOverrideChain => increment(
                &mut self.deep_override_chain,
                "deep override-chain decisions",
            )?,
            AttrSetReprReason::LargeDynamicConstruction => increment(
                &mut self.large_dynamic_construction,
                "large dynamic-construction decisions",
            )?,
        }
        Ok(())
    }
}

/// One exact-value histogram bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HistogramBucket {
    /// The sampled value.
    pub value: usize,
    /// Number of samples with this value.
    pub count: usize,
}

/// Counts order-parity check outcomes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct OrderParityStats {
    /// Checks where compared representations matched.
    pub matched: usize,
    /// Checks where compared representations diverged.
    pub mismatched: usize,
}

impl OrderParityStats {
    fn record(&mut self, matched: bool) -> Result<(), AttrTelemetryError> {
        if matched {
            increment(&mut self.matched, "order parity matches")?;
        } else {
            increment(&mut self.mismatched, "order parity mismatches")?;
        }
        Ok(())
    }
}

/// A failed attrset telemetry operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AttrTelemetryError {
    /// Telemetry storage could not be reserved.
    #[error("failed to reserve attr telemetry storage for {entries} entries")]
    AllocationFailed {
        /// The requested entry count.
        entries: usize,
    },
    /// A counter overflowed `usize`.
    #[error("attr telemetry counter overflowed: {counter}")]
    CounterOverflow {
        /// The counter that overflowed.
        counter: &'static str,
    },
    /// HAMT merge details were supplied for a flat representation decision.
    #[error("HAMT merge summary cannot be recorded for a flat update decision")]
    UnexpectedHamtSummaryForFlatDecision,
}

fn increment(counter: &mut usize, name: &'static str) -> Result<(), AttrTelemetryError> {
    *counter = (*counter)
        .checked_add(1)
        .ok_or(AttrTelemetryError::CounterOverflow { counter: name })?;
    Ok(())
}

const fn hit_source_repr(source: AttrSelectSource) -> AttrSelectRepr {
    match source {
        AttrSelectSource::Flat => AttrSelectRepr::Flat,
        AttrSelectSource::Hamt => AttrSelectRepr::Hamt,
        AttrSelectSource::Shaped { .. } => AttrSelectRepr::Shaped,
    }
}

fn multiplicity_distribution(
    shapes: &[ShapeCensusEntry],
) -> Result<Box<[ShapeMultiplicityBucket]>, AttrTelemetryError> {
    let mut instance_counts = Vec::new();
    instance_counts
        .try_reserve_exact(shapes.len())
        .map_err(|_| AttrTelemetryError::AllocationFailed {
            entries: shapes.len(),
        })?;
    instance_counts.extend(shapes.iter().map(|shape| shape.instances));
    instance_counts.sort_unstable();

    let mut buckets: Vec<ShapeMultiplicityBucket> = Vec::new();
    buckets
        .try_reserve_exact(instance_counts.len())
        .map_err(|_| AttrTelemetryError::AllocationFailed {
            entries: instance_counts.len(),
        })?;
    for instances in instance_counts {
        match buckets.last_mut() {
            Some(bucket) if bucket.instances_per_shape == instances => {
                bucket.shape_count = bucket.shape_count.checked_add(1).ok_or(
                    AttrTelemetryError::CounterOverflow {
                        counter: "shape multiplicity",
                    },
                )?;
            }
            _ => buckets.push(ShapeMultiplicityBucket {
                instances_per_shape: instances,
                shape_count: 1,
            }),
        }
    }
    Ok(buckets.into_boxed_slice())
}

fn record_bucket(
    buckets: &mut HashMap<usize, usize>,
    value: usize,
) -> Result<(), AttrTelemetryError> {
    if let Some(count) = buckets.get_mut(&value) {
        *count = count
            .checked_add(1)
            .ok_or(AttrTelemetryError::CounterOverflow {
                counter: "histogram bucket",
            })?;
        return Ok(());
    }

    buckets
        .try_reserve(1)
        .map_err(|_| AttrTelemetryError::AllocationFailed {
            entries: buckets.len().saturating_add(1),
        })?;
    buckets.insert(value, 1);
    Ok(())
}

fn sorted_buckets(
    buckets: &HashMap<usize, usize>,
) -> Result<Box<[HistogramBucket]>, AttrTelemetryError> {
    let mut sorted = Vec::new();
    sorted
        .try_reserve_exact(buckets.len())
        .map_err(|_| AttrTelemetryError::AllocationFailed {
            entries: buckets.len(),
        })?;
    sorted.extend(buckets.iter().map(|(value, count)| HistogramBucket {
        value: *value,
        count: *count,
    }));
    sorted.sort_unstable_by_key(|bucket| bucket.value);
    Ok(sorted.into_boxed_slice())
}

#[cfg(test)]
mod tests;
