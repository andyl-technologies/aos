//! Retains fixed native paired-clock samples under the original Capture horizon.
//!
//! The actual worker context supplies the signed first pre-spawn origin. Each
//! reached slot samples its own native provider once; the unchanged same-reader
//! law and persisted attempt horizon apply without an acquisition freshness TTL.

use aos_sandbox_broker::kernel_clock::{KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1};
use aos_sandbox_model::RawPairedClockSample;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureWorkerClockErrorV3 {
    #[error("original Capture worker clock or execution horizon changed")]
    Stale,
    #[error(transparent)]
    Native(aos_sandbox_linux::Error),
}

impl KernelPairedClockErrorV1 for CaptureWorkerClockErrorV3 {
    fn stale() -> Self { Self::Stale }
    fn kernel(cause: aos_sandbox_linux::Error) -> Self { Self::Native(cause) }
}

type Clock = RetainedKernelPairedClockAttemptV1<CaptureWorkerClockErrorV3>;

pub(crate) struct CaptureWorkerClockOriginalV3<const N: usize> {
    origin: RawPairedClockSample,
    boot: [u8; 16],
    cutoff: u64,
    source: aos_sandbox_model::ObjectDigest,
    effect_clock: aos_sandbox_broker::BrokerEffectClockComparisonV3,
    verified: [Option<Result<(), aos_sandbox_broker::BrokerAdmissionError>>; N],
    clocks: [Clock; N],
    pairs: [Option<Result<RawPairedClockSample, CaptureWorkerClockErrorV3>>; N],
    comparisons: [Option<Result<(), CaptureWorkerClockErrorV3>>; N],
    reentry: [Option<CaptureWorkerClockErrorV3>; N],
}

impl<const N: usize> CaptureWorkerClockOriginalV3<N> {
    pub(crate) fn maximum_retained_files_v3() -> Option<usize> {
        Clock::MAXIMUM_RETAINED_FILES_V1.checked_mul(N)
    }

    pub(crate) fn receiving_bytes_v3() -> Option<usize> {
        let dynamic = Clock::dominant_requested_bytes_v1()?.checked_sub(std::mem::size_of::<Clock>())?;
        std::mem::size_of::<Self>().checked_add(dynamic.checked_mul(N)?)
    }

    pub(crate) fn from_worker_v3(
        context: &crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>,
        boot: [u8; 16],
        cutoff: u64,
    ) -> Self {
        Self { origin: context.source_v3().lifetime_v2().first_pre_spawn_clock_v2(), boot, cutoff,
            source: context.source_v3().source_digest_v2(), effect_clock: context.clock_comparison_data_v3(), verified: std::array::from_fn(|_| None),
            clocks: std::array::from_fn(|_| Clock::default()),
            pairs: std::array::from_fn(|_| None), comparisons: std::array::from_fn(|_| None), reentry: std::array::from_fn(|_| None) }
    }

    pub(crate) fn from_verified_v3(verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3) -> Self {
        Self { origin: *verified.admitted_clock_v3(), boot: verified.admitted_clock_v3().host_boot_id(),
            cutoff: verified.ongoing_deadline_v3(), source: verified.source_v3().source_digest_v2(),
            effect_clock: aos_sandbox_broker::BrokerEffectClockComparisonV3::from_effect(&verified.admission_v3().effect),
            verified: std::array::from_fn(|_| None), clocks: std::array::from_fn(|_| Clock::default()),
            pairs: std::array::from_fn(|_| None), comparisons: std::array::from_fn(|_| None), reentry: std::array::from_fn(|_| None) }
    }

    pub(crate) fn observe_verified_once_v3(
        &mut self, index: usize, verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
    ) -> Result<(), ()> {
        if self.source != verified.source_v3().source_digest_v2()
            || self.cutoff != verified.ongoing_deadline_v3()
            || index >= N || self.verified[index].is_some()
        { return Err(()); }
        self.observe_once_v3(index)?;
        let Some(Ok(current)) = self.pairs[index].as_ref() else { return Err(()); };
        self.verified[index] = Some(verified.require_ongoing_clock_v3(current));
        if matches!(self.verified[index], Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    pub(crate) fn observe_once_v3(&mut self, index: usize) -> Result<(), ()> {
        if index >= N { return Err(()); }
        if self.pairs[index].is_some() || self.comparisons[index].is_some() {
            self.reentry[index].get_or_insert(CaptureWorkerClockErrorV3::Stale);
            return Err(());
        }
        // Supplying Some(origin) would impose the ordinary65s acquisition
        // freshness window. Ongoing Capture instead keeps its signed original
        // horizon and applies the same-reader clock progression law directly.
        self.pairs[index] = Some(self.clocks[index].observe_once(None));
        let Some(Ok(current)) = self.pairs[index].as_ref() else { return Err(()); };
        self.comparisons[index] = Some((|| {
            self.origin.validate_later_sample(*current)
                .map_err(|_| CaptureWorkerClockErrorV3::Stale)?;
            self.effect_clock.require_original_ongoing_clock_data_v4(current, self.cutoff)
                .map_err(|_| CaptureWorkerClockErrorV3::Stale)?;
            if self.cutoff == 0 || current.host_boot_id() != self.boot
                || current.boottime_nanoseconds() >= self.cutoff
            { return Err(CaptureWorkerClockErrorV3::Stale); }
            Ok(())
        })());
        if matches!(self.comparisons[index], Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    #[cfg(test)]
    pub(crate) fn expired_wall_fixture_v3() -> Result<Self, CaptureWorkerClockErrorV3> {
        let origin = aos_sandbox_broker::kernel_clock::ordinary_kernel_pair::<CaptureWorkerClockErrorV3>()?;
        let cutoff = origin.boottime_nanoseconds().checked_add(60_000_000_000)
            .ok_or(CaptureWorkerClockErrorV3::Stale)?;
        Ok(Self {
            origin, boot: origin.host_boot_id(), cutoff,
            source: aos_sandbox_model::ObjectDigest::from_bytes([1; 32]),
            effect_clock: aos_sandbox_broker::BrokerEffectClockComparisonV3::from_original_clock_fields_data_v4(
                origin, origin.wall_seconds(), origin.wall_seconds(),
            ),
            verified: std::array::from_fn(|_| None), clocks: std::array::from_fn(|_| Clock::default()),
            pairs: std::array::from_fn(|_| None), comparisons: std::array::from_fn(|_| None),
            reentry: std::array::from_fn(|_| None),
        })
    }

    #[cfg(test)]
    pub(crate) fn fresh_wall_fixture_v3() -> Result<Self, CaptureWorkerClockErrorV3> {
        let mut fixture = Self::expired_wall_fixture_v3()?;
        let expires = fixture.origin.wall_seconds().checked_add(60).ok_or(CaptureWorkerClockErrorV3::Stale)?;
        fixture.effect_clock = aos_sandbox_broker::BrokerEffectClockComparisonV3::from_original_clock_fields_data_v4(
            fixture.origin, expires, expires,
        );
        Ok(fixture)
    }

    pub(crate) fn boottime_at_v3(&self, index: usize) -> Option<u64> {
        if !matches!(self.comparisons.get(index), Some(Some(Ok(())))) { return None; }
        Some(self.pairs.get(index)?.as_ref()?.as_ref().ok()?.boottime_nanoseconds())
    }

    // Reuses only a fully positive native subphase. A failed/ambiguous sample
    // keeps every boot-reader/native/result prefix and cannot be overwritten.
    pub(crate) fn retire_positive_range_v3(&mut self, range: std::ops::Range<usize>) -> Result<(), ()> {
        if range.end > N || range.start > range.end { return Err(()); }
        for index in range.clone() {
            if self.pairs[index].is_some()
                && !matches!(self.comparisons[index], Some(Ok(()))) { return Err(()); }
            if matches!(self.verified[index], Some(Err(_))) || self.reentry[index].is_some() { return Err(()); }
        }
        for index in range {
            self.clocks[index] = Clock::default();
            self.pairs[index] = None;
            self.comparisons[index] = None;
            self.verified[index] = None;
        }
        Ok(())
    }

    pub(crate) fn failure_at_v3(&self, index: usize) -> Option<&(dyn std::error::Error + 'static)> {
        self.clocks.get(index)?.failure()
            .or_else(|| self.pairs.get(index)?.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.comparisons.get(index)?.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.verified.get(index)?.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.reentry.get(index)?.as_ref().map(|cause| cause as _))
    }
}
