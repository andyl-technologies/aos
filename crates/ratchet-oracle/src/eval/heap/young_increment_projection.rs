//! Read-only projection of chronologically sealed, typed heap increments.
//!
//! The projection assigns serial allocations to successful final-config
//! completion intervals using allocation fences. Within every interval, each
//! runtime kind receives its own fixed-size segment stream. A segment is
//! reclaimable only when the complete nonmoving root trace reaches none of its
//! objects.
//!
//! This is intentionally a same-layout upper bound, not a packed-layout
//! admission. It rounds the current inline allocation size into simulated
//! segments, conservatively keeps list spines and all other process-owned
//! storage in the observed RSS, and removes only the sampled resident
//! Candidate-C reservation before adding retained simulated segments.

use super::*;

/// Segment capacities exercised by the chronological projection.
pub(crate) const YOUNG_INCREMENT_SEGMENT_BYTES: [usize; 4] =
    [4 * 1024, 16 * 1024, 64 * 1024, 256 * 1024];

const STREAM_COUNT: usize = 9;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SegmentAccumulator {
    segment_bytes: usize,
    cohort: Option<usize>,
    used: usize,
    live: bool,
    total_segments: u64,
    live_segments: u64,
    initialized_bytes: u64,
}

impl SegmentAccumulator {
    const fn new(segment_bytes: usize) -> Self {
        Self {
            segment_bytes,
            cohort: None,
            used: 0,
            live: false,
            total_segments: 0,
            live_segments: 0,
            initialized_bytes: 0,
        }
    }

    fn add(&mut self, cohort: usize, bytes: usize, live: bool) {
        let bytes = bytes.max(1).saturating_add(7) & !7;
        self.initialized_bytes = self.initialized_bytes.saturating_add(bytes as u64);
        if self.cohort != Some(cohort) {
            self.finish_segment();
            self.cohort = Some(cohort);
        }
        if bytes > self.segment_bytes {
            self.finish_segment();
            let segments = bytes.div_ceil(self.segment_bytes) as u64;
            self.total_segments = self.total_segments.saturating_add(segments);
            if live {
                self.live_segments = self.live_segments.saturating_add(segments);
            }
            return;
        }
        if self.used != 0 && self.used.saturating_add(bytes) > self.segment_bytes {
            self.finish_segment();
        }
        self.used = self.used.saturating_add(bytes);
        self.live |= live;
    }

    fn finish_segment(&mut self) {
        if self.used == 0 {
            return;
        }
        self.total_segments = self.total_segments.saturating_add(1);
        self.live_segments = self.live_segments.saturating_add(u64::from(self.live));
        self.used = 0;
        self.live = false;
    }

    fn finish(mut self) -> Self {
        self.finish_segment();
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VariantBuilder {
    streams: [SegmentAccumulator; STREAM_COUNT],
}

impl VariantBuilder {
    fn new(segment_bytes: usize) -> Self {
        Self {
            streams: [SegmentAccumulator::new(segment_bytes); STREAM_COUNT],
        }
    }

    fn add(&mut self, stream: usize, cohort: usize, bytes: usize, live: bool) {
        if let Some(accumulator) = self.streams.get_mut(stream) {
            accumulator.add(cohort, bytes, live);
        }
    }

    fn finish(self) -> YoungIncrementSegmentProjection {
        let streams = self.streams.map(SegmentAccumulator::finish);
        let total_segments = streams.iter().fold(0_u64, |total, stream| {
            total.saturating_add(stream.total_segments)
        });
        let live_segments = streams.iter().fold(0_u64, |total, stream| {
            total.saturating_add(stream.live_segments)
        });
        let initialized_bytes = streams.iter().fold(0_u64, |total, stream| {
            total.saturating_add(stream.initialized_bytes)
        });
        let segment_bytes = streams
            .first()
            .map_or(0, |stream| stream.segment_bytes as u64);
        YoungIncrementSegmentProjection {
            segment_bytes,
            total_segments,
            live_segments,
            dead_segments: total_segments.saturating_sub(live_segments),
            initialized_bytes,
            retained_segment_bytes: live_segments.saturating_mul(segment_bytes),
            reclaimable_segment_bytes: total_segments
                .saturating_sub(live_segments)
                .saturating_mul(segment_bytes),
        }
    }
}

/// One simulated typed-increment geometry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct YoungIncrementSegmentProjection {
    /// Bytes in one independently disposable segment.
    pub(crate) segment_bytes: u64,
    /// Segments committed by all chronological typed streams.
    pub(crate) total_segments: u64,
    /// Segments containing at least one root-reachable object.
    pub(crate) live_segments: u64,
    /// Segments containing no root-reachable object.
    pub(crate) dead_segments: u64,
    /// Sum of current same-layout object extents assigned to segments.
    pub(crate) initialized_bytes: u64,
    /// Page-rounded segment bytes retained by live objects.
    pub(crate) retained_segment_bytes: u64,
    /// Page-rounded segment bytes disposable as whole increments.
    pub(crate) reclaimable_segment_bytes: u64,
}

/// Complete same-layout segregation projection for one root-complete milestone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct YoungIncrementProjection {
    /// Complete roots supplied to the weak scanner.
    pub(crate) roots: u64,
    /// Distinct addresses reached by the weak scanner.
    pub(crate) reachable: u64,
    /// Iterable objects assigned to a simulated stream.
    pub(crate) classified_objects: u64,
    /// Reached addresses reconciled to classified objects.
    pub(crate) classified_reachable: u64,
    /// Objects or reached addresses outside the simulated stream model.
    pub(crate) unclassified: u64,
    /// Number of chronological completion intervals represented by fences.
    pub(crate) cohort_intervals: u64,
    /// Whether fences are monotonic and end at the current store populations.
    pub(crate) fences_reconciled: bool,
    /// Four fixed segment-capacity projections.
    pub(crate) variants: [YoungIncrementSegmentProjection; 4],
}

impl EvalHeap {
    /// Projects typed chronological segments without moving or retiring values.
    ///
    /// Current inline object sizes are used deliberately. Records are reported
    /// as unclassified because production Candidate-C packed-at-birth mode must
    /// not retain its compatibility record table. Boxed scalar cells are
    /// classified as pinned/live because the weak edge scanner does not expose
    /// scalar-cell identities.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if weak traversal encounters a stale root,
    /// malformed edge, invalid thunk state, or cannot grow scanner storage.
    pub(crate) fn young_increment_projection(
        &self,
        roots: &EvalRootSet,
        fences: &[DemandRegionAllocationFence],
    ) -> Result<YoungIncrementProjection, EvalHeapError> {
        let reachable = self.weak_reachable_addresses(roots)?;
        let mut variants = YOUNG_INCREMENT_SEGMENT_BYTES.map(VariantBuilder::new);
        let mut classified_objects = 0_u64;
        let mut classified_reachable = 0_u64;

        let mut add = |stream: usize, cohort: usize, address: usize, bytes: usize| {
            let live = reachable.contains(&address);
            classified_objects = classified_objects.saturating_add(1);
            classified_reachable = classified_reachable.saturating_add(u64::from(live));
            for variant in &mut variants {
                variant.add(stream, cohort, bytes, live);
            }
        };

        for (index, object) in self.flat.iter().enumerate() {
            let stream = match object.object().kind() {
                FlatObjectKind::String => 0,
                FlatObjectKind::Path => 1,
                _ => STREAM_COUNT,
            };
            if stream < STREAM_COUNT {
                add(
                    stream,
                    birth_cohort(fences, index, |fence| fence.strings_and_paths),
                    object.ptr().as_ptr() as usize,
                    object.size_bytes(),
                );
            }
        }
        for (index, object) in self.flat_lists.iter().enumerate() {
            add(
                2,
                birth_cohort(fences, index, |fence| fence.lists),
                object.ptr().as_ptr() as usize,
                object.size_bytes(),
            );
        }
        for (index, object) in self.flat_attrs.iter().enumerate() {
            add(
                3,
                birth_cohort(fences, index, |fence| fence.attrs),
                object.ptr().as_ptr() as usize,
                object.size_bytes(),
            );
        }
        for (index, object) in self.flat_closures.iter().enumerate() {
            let payload = object.object().payload();
            let stream = match payload {
                FlatClosurePayload::Thunk(_) | FlatClosurePayload::SharedThunk(_) => 4,
                FlatClosurePayload::Lambda(_) => 5,
                FlatClosurePayload::Primop(_) => 6,
                FlatClosurePayload::Retired(_) => continue,
            };
            add(
                stream,
                birth_cohort(fences, index, |fence| fence.closures),
                object.ptr().as_ptr() as usize,
                object.size_bytes(),
            );
        }
        for (index, (address, bytes)) in self.typed_thunk_heads.initialized_regions().enumerate() {
            add(
                7,
                birth_cohort(fences, index, |fence| fence.typed_thunks),
                address,
                bytes,
            );
        }

        let mut scalar_regions = Vec::new();
        self.compressed_scalars
            .append_cell_regions(0, &mut scalar_regions);
        for (index, (_address, bytes)) in scalar_regions.iter().copied().enumerate() {
            let cohort = birth_cohort(fences, index, |fence| fence.boxed_scalars);
            classified_objects = classified_objects.saturating_add(1);
            for variant in &mut variants {
                variant.add(8, cohort, bytes, true);
            }
        }

        let (live_records, reachable_records) = self.records.iter().fold(
            (0_usize, 0_usize),
            |(live_records, reachable_records), record| {
                if record.is_retired() {
                    return (live_records, reachable_records);
                }
                (
                    live_records.saturating_add(1),
                    reachable_records.saturating_add(usize::from(
                        reachable.contains(&(record.ptr.as_ptr() as usize)),
                    )),
                )
            },
        );
        let reachable_outside_streams = reachable
            .len()
            .saturating_sub(classified_reachable as usize)
            .saturating_sub(reachable_records);
        let unclassified = live_records.saturating_add(reachable_outside_streams) as u64;
        let fences_reconciled = fences_reconcile(self, fences, scalar_regions.len());

        Ok(YoungIncrementProjection {
            roots: roots.len() as u64,
            reachable: reachable.len() as u64,
            classified_objects,
            classified_reachable,
            unclassified,
            cohort_intervals: fences.len().saturating_sub(1) as u64,
            fences_reconciled,
            variants: variants.map(VariantBuilder::finish),
        })
    }
}

fn birth_cohort(
    fences: &[DemandRegionAllocationFence],
    index: usize,
    count: impl Fn(&DemandRegionAllocationFence) -> usize,
) -> usize {
    fences.partition_point(|fence| count(fence) <= index)
}

fn fences_reconcile(
    heap: &EvalHeap,
    fences: &[DemandRegionAllocationFence],
    boxed_scalars: usize,
) -> bool {
    let Some(last) = fences.last() else {
        return false;
    };
    let monotonic = fences.windows(2).all(|pair| {
        pair[0].records <= pair[1].records
            && pair[0].strings_and_paths <= pair[1].strings_and_paths
            && pair[0].lists <= pair[1].lists
            && pair[0].attrs <= pair[1].attrs
            && pair[0].closures <= pair[1].closures
            && pair[0].typed_thunks <= pair[1].typed_thunks
            && pair[0].boxed_scalars <= pair[1].boxed_scalars
    });
    monotonic
        && last.records == heap.records.len()
        && last.strings_and_paths == heap.flat.len()
        && last.lists == heap.flat_lists.len()
        && last.attrs == heap.flat_attrs.len()
        && last.closures == heap.flat_closures.len()
        && last.typed_thunks == heap.typed_thunk_heads.len()
        && last.boxed_scalars == boxed_scalars
        && heap.flat.live_len() == heap.flat.len()
        && heap.flat_lists.live_len() == heap.flat_lists.len()
        && heap.flat_attrs.live_len() == heap.flat_attrs.len()
        && heap.flat_closures.live_len() == heap.flat_closures.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cohort_boundaries_seal_partial_segments() {
        let mut builder = VariantBuilder::new(4096);
        builder.add(0, 1, 64, false);
        builder.add(0, 2, 64, true);
        let projection = builder.finish();
        assert_eq!(projection.total_segments, 2);
        assert_eq!(projection.live_segments, 1);
        assert_eq!(projection.dead_segments, 1);
        assert_eq!(projection.reclaimable_segment_bytes, 4096);
    }

    #[test]
    fn oversized_objects_receive_dedicated_segments() {
        let mut accumulator = SegmentAccumulator::new(4096);
        accumulator.add(1, 9000, false);
        let accumulator = accumulator.finish();
        assert_eq!(accumulator.total_segments, 3);
        assert_eq!(accumulator.live_segments, 0);
    }
}
