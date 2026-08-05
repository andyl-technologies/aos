//! Compile-time-only fresh-allocation peak-RSS locator.
//!
//! The feature records successful serial heap publications at their
//! authoritative heap-side commit points. It deliberately does not infer
//! liveness or authorize collection.

use super::*;

const DEFAULT_SAMPLE_STRIDE: u64 = 4096;

/// One RSS sample captured immediately after a fresh serial heap publication.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PeakAllocationSample {
    /// Deduplicated fresh-allocation ordinal.
    pub(crate) ordinal: u64,
    /// Runtime kind published at this ordinal.
    pub(crate) kind: ValueTag,
    /// Current process resident bytes, when the platform exposes them.
    pub(crate) rss_bytes: Option<u64>,
    /// Worker-domain arena accounting at the publication.
    pub(crate) worker: ArenaStats,
    /// Permanent-domain arena accounting at the publication.
    pub(crate) permanent: ArenaStats,
}

/// Feature-only sampling state owned by one serial evaluator heap.
#[derive(Debug)]
pub(crate) struct PeakOrdinalProbe {
    stride: u64,
    serial_publications: u64,
    samples: u64,
    records: Vec<PeakAllocationSample>,
    pending_sample: Option<PeakAllocationSample>,
    max: Option<PeakAllocationSample>,
}

impl PeakOrdinalProbe {
    /// Creates a probe using `AOS_NIX_PEAK_ORDINAL_STRIDE`, or 4096.
    pub(crate) fn from_env() -> Self {
        let stride = std::env::var("AOS_NIX_PEAK_ORDINAL_STRIDE")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|stride| *stride != 0)
            .unwrap_or(DEFAULT_SAMPLE_STRIDE);
        Self {
            stride,
            serial_publications: 0,
            samples: 0,
            records: Vec::new(),
            pending_sample: None,
            max: None,
        }
    }

    fn record(&mut self, ordinal: u64, kind: ValueTag, worker: ArenaStats, permanent: ArenaStats) {
        self.serial_publications = self.serial_publications.saturating_add(1);
        if !ordinal.is_multiple_of(self.stride) {
            return;
        }
        let rss_bytes = crate::heap::ProcessResidentMemorySample::current()
            .ok()
            .flatten()
            .and_then(|sample| u64::try_from(sample.resident_bytes()).ok());
        let sample = PeakAllocationSample {
            ordinal,
            kind,
            rss_bytes,
            worker,
            permanent,
        };
        self.samples = self.samples.saturating_add(1);
        self.records.push(sample);
        self.pending_sample = Some(sample);
        if sample_is_higher(sample, self.max) {
            self.max = Some(sample);
        }
    }

    /// Takes a newly captured sample for evaluator-context attachment.
    pub(crate) fn take_pending_sample(&mut self) -> Option<PeakAllocationSample> {
        self.pending_sample.take()
    }

    /// Returns the configured sampling stride.
    pub(crate) const fn stride(&self) -> u64 {
        self.stride
    }

    /// Returns successful serial publications seen by the feature.
    pub(crate) const fn serial_publications(&self) -> u64 {
        self.serial_publications
    }

    /// Returns RSS samples attempted by the feature.
    pub(crate) const fn samples(&self) -> u64 {
        self.samples
    }

    /// Returns the heap-side maximum sample.
    pub(crate) const fn max(&self) -> Option<PeakAllocationSample> {
        self.max
    }

    /// Returns the earliest sample within `bytes` of the sampled maximum RSS.
    pub(crate) fn earliest_within_peak_bytes(&self, bytes: u64) -> Option<PeakAllocationSample> {
        earliest_sample_within_peak_bytes(&self.records, self.max?, bytes)
    }
}

impl EvalHeap {
    /// Records one already-committed fresh serial allocation.
    pub(in crate::eval) fn note_peak_ordinal_publication(&mut self, kind: ValueTag) {
        let ordinal = self.alloc_counters.values_allocated();
        let worker = self.arena_stats();
        let permanent = self.permanent_arena_stats();
        self.peak_ordinal_probe
            .record(ordinal, kind, worker, permanent);
    }

    /// Returns the feature-only peak locator.
    pub(in crate::eval) const fn peak_ordinal_probe(&self) -> &PeakOrdinalProbe {
        &self.peak_ordinal_probe
    }

    /// Returns the mutable feature-only peak locator.
    pub(in crate::eval) fn peak_ordinal_probe_mut(&mut self) -> &mut PeakOrdinalProbe {
        &mut self.peak_ordinal_probe
    }
}

fn sample_is_higher(sample: PeakAllocationSample, current: Option<PeakAllocationSample>) -> bool {
    match current {
        None => true,
        Some(current) => match (sample.rss_bytes, current.rss_bytes) {
            (Some(sample_rss), Some(current_rss)) => sample_rss > current_rss,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => sample.ordinal > current.ordinal,
        },
    }
}

fn earliest_sample_within_peak_bytes(
    records: &[PeakAllocationSample],
    max: PeakAllocationSample,
    bytes: u64,
) -> Option<PeakAllocationSample> {
    let threshold = max.rss_bytes?.saturating_sub(bytes);
    records
        .iter()
        .copied()
        .find(|sample| sample.rss_bytes.is_some_and(|rss| rss >= threshold))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_cons_hits_and_rejected_allocations_do_not_advance_the_ordinal() {
        let mut heap = EvalHeap::new();
        heap.peak_ordinal_probe.stride = 1;
        let bytes = NixString::from_bytes(b"same".to_vec());
        let first = heap
            .alloc_string(bytes.clone())
            .expect("first string allocates");
        let second = heap.alloc_string(bytes).expect("equal string reuses");
        assert!(first.raw_eq(second));
        assert_eq!(heap.peak_ordinal_probe.serial_publications(), 1);
        assert_eq!(heap.allocation_counters().values_allocated(), 1);

        heap.use_record_worker_closures_for_gc_scaffolding();
        let capture =
            EvalFlatCaptureBuffer::new(EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(1)), 0);
        assert!(matches!(
            heap.alloc_thunk_with_flat_capture(EvalThunk::new(IrId::new(2)), Some(capture),),
            Err(EvalHeapError::InlineCapturePlacementUnsupported)
        ));
        assert_eq!(heap.peak_ordinal_probe.serial_publications(), 1);
        assert_eq!(heap.allocation_counters().values_allocated(), 1);
    }

    #[test]
    fn unavailable_rss_falls_back_to_the_latest_ordinal() {
        let worker = ArenaStats::default();
        let first = PeakAllocationSample {
            ordinal: 1,
            kind: ValueTag::String,
            rss_bytes: None,
            worker,
            permanent: worker,
        };
        let second = PeakAllocationSample {
            ordinal: 2,
            ..first
        };
        assert!(sample_is_higher(first, None));
        assert!(sample_is_higher(second, Some(first)));
    }

    #[test]
    fn peak_band_selects_the_earliest_qualifying_sample() {
        let worker = ArenaStats::default();
        let records = [
            PeakAllocationSample {
                ordinal: 1,
                kind: ValueTag::Thunk,
                rss_bytes: Some(70),
                worker,
                permanent: worker,
            },
            PeakAllocationSample {
                ordinal: 2,
                kind: ValueTag::List,
                rss_bytes: Some(91),
                worker,
                permanent: worker,
            },
            PeakAllocationSample {
                ordinal: 3,
                kind: ValueTag::Attrs,
                rss_bytes: Some(100),
                worker,
                permanent: worker,
            },
        ];
        assert_eq!(
            earliest_sample_within_peak_bytes(&records, records[2], 10)
                .map(|sample| sample.ordinal),
            Some(2)
        );
        assert_eq!(
            earliest_sample_within_peak_bytes(&records, records[2], 5).map(|sample| sample.ordinal),
            Some(3)
        );
    }
}
