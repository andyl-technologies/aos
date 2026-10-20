//! Shares actual Source readonly native-clock brackets between closed purposes.
//!
//! Bounds are inert original-query DATA. The actual connection keeps its paid
//! fixed clock owners and all independent posts through response and shutdown.

use std::error::Error;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;
use crate::signer::clock::{SourceClockOriginalV1, SourceClockErrorV1};

pub(super) struct SourceReadonlyClockBoundsV1 {
    pub(super) boot: [u8; 16],
    pub(super) other_boot: [u8; 16],
    pub(super) started: u64,
    pub(super) cutoff: u64,
}

#[derive(Clone, Copy)]
pub(super) enum ClockFailureV1 { Native(usize), Binding(usize) }

pub(super) struct SourceReadonlyClockBracketV1 {
    clocks: [SourceClockOriginalV1; 5],
    pub(super) samples: [Option<Result<RawPairedClockSample, SourceClockErrorV1>>; 5],
    bindings: [Option<Result<(), HistoryErrorV1>>; 5],
    first: Option<ClockFailureV1>,
}

impl Default for SourceReadonlyClockBracketV1 {
    fn default() -> Self {
        Self { clocks: std::array::from_fn(|_| SourceClockOriginalV1::default()),
            samples: [None, None, None, None, None], bindings: [None, None, None, None, None], first: None }
    }
}

impl SourceReadonlyClockBracketV1 {
    pub(super) fn has_sample(&self, index: usize) -> bool { self.samples.get(index).is_none_or(Option::is_some) }

    pub(super) fn bound_is_positive(&self, index: usize) -> bool { matches!(self.bindings.get(index), Some(Some(Ok(())))) }

    pub(super) fn sample(&self, index: usize) -> Option<RawPairedClockSample> {
        self.samples.get(index)?.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn observe_once(&mut self, index: usize,
        bounds: Result<SourceReadonlyClockBoundsV1, HistoryErrorV1>,
    ) -> Result<(), ()> {
        if index >= 5 || self.samples[index].is_some() { return Err(()); }
        let original = self.sample(0);
        self.samples[index] = Some(self.clocks[index].observe_once(original));
        if !matches!(self.samples[index], Some(Ok(_))) {
            self.first.get_or_insert(ClockFailureV1::Native(index));
            return Err(());
        }
        self.bindings[index] = Some((|| {
            let bounds = bounds?;
            let sample = self.sample(index).ok_or(HistoryErrorV1::Correlation)?;
            if sample.host_boot_id() != bounds.boot || sample.host_boot_id() != bounds.other_boot
                || sample.boottime_nanoseconds() < bounds.started
                || sample.boottime_nanoseconds() >= bounds.cutoff { return Err(HistoryErrorV1::Correlation); }
            Ok(())
        })());
        if !matches!(self.bindings[index], Some(Ok(()))) {
            self.first.get_or_insert(ClockFailureV1::Binding(index));
            return Err(());
        }
        Ok(())
    }

    pub(super) fn selected(&self) -> Option<ClockFailureV1> { self.first }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            ClockFailureV1::Native(index) => self.clocks[index].failure().or_else(|| self.samples[index]
                .as_ref()?.as_ref().err().map(|cause| cause as _)),
            ClockFailureV1::Binding(index) => self.bindings[index].as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}
