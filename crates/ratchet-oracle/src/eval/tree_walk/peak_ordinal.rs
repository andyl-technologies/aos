//! Evaluator context and final reporting for the allocation peak locator.

use super::*;
use crate::eval::heap::PeakAllocationSample;

/// Evaluator context attached to one heap-side RSS sample.
#[derive(Clone, Copy, Debug)]
pub(super) struct PeakOrdinalContext {
    sample: PeakAllocationSample,
    module: EvalModuleId,
    modules_loaded: usize,
    thunks_allocated: u64,
    thunks_forced: u64,
    function_calls: u64,
}

impl TreeWalk {
    /// Attaches current evaluator context to a newly observed heap-side sample.
    pub(super) fn capture_peak_ordinal_context(&mut self) {
        let Some(sample) = self.heap.peak_ordinal_probe_mut().take_pending_sample() else {
            return;
        };
        self.peak_ordinal_contexts.push(PeakOrdinalContext {
            sample,
            module: self.current_module,
            modules_loaded: self.modules.len(),
            thunks_allocated: self.stats.thunks_allocated(),
            thunks_forced: self.stats.thunks_forced(),
            function_calls: self.stats.function_calls(),
        });
    }

    /// Emits the locate-only peak sample and counter reconciliation.
    pub(super) fn emit_peak_ordinal_report(&mut self) {
        self.capture_peak_ordinal_context();
        let probe = self.heap.peak_ordinal_probe();
        let counters = self.heap.allocation_counters();
        let reconciled = probe.serial_publications() == counters.values_allocated();
        let heap_max = probe.max();
        let bands = [
            (16_u64, probe.earliest_within_peak_bytes(16 * 1024 * 1024)),
            (32_u64, probe.earliest_within_peak_bytes(32 * 1024 * 1024)),
            (64_u64, probe.earliest_within_peak_bytes(64 * 1024 * 1024)),
        ];
        let context = heap_max.and_then(|sample| self.context_for_peak_sample(sample));
        match (heap_max, context) {
            (Some(sample), Some(context)) if context.sample.ordinal == sample.ordinal => {
                let rss = sample
                    .rss_bytes
                    .map(|bytes| bytes.to_string())
                    .unwrap_or_else(|| "null".to_owned());
                eprintln!(
                    "aos_nix_peak_ordinal {{\"stride\":{},\"samples\":{},\
                     \"serial_publications\":{},\"values_allocated\":{},\
                     \"reconciled\":{},\"max\":{{\"ordinal\":{},\"kind\":\"{:?}\",\
                     \"module\":{},\"modules_loaded\":{},\"rss_bytes\":{},\
                     \"thunks_allocated\":{},\"thunks_forced\":{},\"function_calls\":{},\
                     \"worker_mapped_bytes\":{},\"worker_used_bytes\":{},\
                     \"permanent_mapped_bytes\":{},\"permanent_used_bytes\":{}}}}}",
                    probe.stride(),
                    probe.samples(),
                    probe.serial_publications(),
                    counters.values_allocated(),
                    reconciled,
                    sample.ordinal,
                    sample.kind,
                    context.module.as_u32(),
                    context.modules_loaded,
                    rss,
                    context.thunks_allocated,
                    context.thunks_forced,
                    context.function_calls,
                    sample.worker.mapped_bytes,
                    sample.worker.used_bytes,
                    sample.permanent.mapped_bytes,
                    sample.permanent.used_bytes,
                );
            }
            _ => eprintln!(
                "aos_nix_peak_ordinal {{\"stride\":{},\"samples\":{},\
                 \"serial_publications\":{},\"values_allocated\":{},\
                 \"reconciled\":{},\"max\":null}}",
                probe.stride(),
                probe.samples(),
                probe.serial_publications(),
                counters.values_allocated(),
                reconciled,
            ),
        }
        for (band_mib, sample) in bands {
            self.emit_peak_ordinal_band(band_mib, sample, heap_max);
        }
    }

    fn context_for_peak_sample(&self, sample: PeakAllocationSample) -> Option<PeakOrdinalContext> {
        self.peak_ordinal_contexts
            .iter()
            .copied()
            .find(|context| context.sample.ordinal == sample.ordinal)
    }

    fn emit_peak_ordinal_band(
        &self,
        band_mib: u64,
        sample: Option<PeakAllocationSample>,
        max: Option<PeakAllocationSample>,
    ) {
        let Some(sample) = sample else {
            eprintln!("aos_nix_peak_ordinal_band {{\"band_mib\":{band_mib},\"sample\":null}}");
            return;
        };
        let rss = sample
            .rss_bytes
            .map(|bytes| bytes.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let distance = max
            .and_then(|max| max.rss_bytes)
            .zip(sample.rss_bytes)
            .map(|(max, sample)| max.saturating_sub(sample).to_string())
            .unwrap_or_else(|| "null".to_owned());
        match self.context_for_peak_sample(sample) {
            Some(context) => eprintln!(
                "aos_nix_peak_ordinal_band {{\"band_mib\":{band_mib},\
                 \"sample\":{{\"ordinal\":{},\"kind\":\"{:?}\",\"rss_bytes\":{},\
                 \"distance_from_max_bytes\":{},\"worker_mapped_bytes\":{},\
                 \"worker_used_bytes\":{},\"permanent_mapped_bytes\":{},\
                 \"permanent_used_bytes\":{},\"module\":{},\"modules_loaded\":{},\
                 \"thunks_allocated\":{},\"thunks_forced\":{},\"function_calls\":{}}}}}",
                sample.ordinal,
                sample.kind,
                rss,
                distance,
                sample.worker.mapped_bytes,
                sample.worker.used_bytes,
                sample.permanent.mapped_bytes,
                sample.permanent.used_bytes,
                context.module.as_u32(),
                context.modules_loaded,
                context.thunks_allocated,
                context.thunks_forced,
                context.function_calls,
            ),
            None => eprintln!(
                "aos_nix_peak_ordinal_band {{\"band_mib\":{band_mib},\
                 \"sample\":{{\"ordinal\":{},\"kind\":\"{:?}\",\"rss_bytes\":{},\
                 \"distance_from_max_bytes\":{},\"worker_mapped_bytes\":{},\
                 \"worker_used_bytes\":{},\"permanent_mapped_bytes\":{},\
                 \"permanent_used_bytes\":{},\"context\":null}}}}",
                sample.ordinal,
                sample.kind,
                rss,
                distance,
                sample.worker.mapped_bytes,
                sample.worker.used_bytes,
                sample.permanent.mapped_bytes,
                sample.permanent.used_bytes,
            ),
        }
    }
}
