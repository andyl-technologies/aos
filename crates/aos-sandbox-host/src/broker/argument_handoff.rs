//! Executes paid Host availability and argument phases on their original Session.
//!
//! Fixed native journals, retained clocks, State commits and independently owed
//! original posts belong to the same intrinsic Host financial original. This
//! module creates no account from request data and issues no execution Apply.

mod availability;
mod receiving;

use receiving::ArgumentNativeReceivingV2;

use std::time::{Duration, Instant};
use aos_sandbox_broker::paired_clock::{PairedClockBaselineV1, PairedClockSamplesV1, PairedClockIncrementalSamplesV3};
use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use crate::{HostError, Result};

// Each phase admits the existing sixteen-sample frontier/semantic envelope.
// Every reached sample retains its own bookends without wrap or reuse.
const FRONTIER_DEADLINES: usize = 11;
const CLOCK_SAMPLES_PER_STAGE: usize = FRONTIER_DEADLINES + 5;
// The positive programme is 64 (accepted bind), 35, 48, 58, 59. Its exclusive
// early branch is 64, 35?, 48?, 39, 42-preliminary, 43, 42-seal, 42-ACK.
// Both keep the same baseline and monotonically consumed destinations.
const MAXIMUM_CLOCK_SAMPLES: usize = 8 * CLOCK_SAMPLES_PER_STAGE;
const CLOCK_PAIRS: usize = MAXIMUM_CLOCK_SAMPLES.div_ceil(2);

pub(crate) struct ArgumentClockV2 {
    baseline: PairedClockBaselineV1,
    samples: [PairedClockSamplesV1; CLOCK_PAIRS],
    used: usize,
    stage: usize,
    stage_start: usize,
    protected_boot: [u8; 16],
    sample_refusal: Option<HostError>,
    launch_writes: Option<Box<LaunchWriteSamplesV2>>,
    effect_clock: Option<aos_sandbox_broker::BrokerEffectClockComparisonV3>,
    effect_clock_failure: Option<aos_sandbox_broker::BrokerAdmissionError>,
    sdk_writes: Option<Box<PairedClockIncrementalSamplesV3>>,
    handshake_writes: Option<Box<PairedClockIncrementalSamplesV3>>,
    handshake_write_refused: bool,
    component_report_writes: Option<Box<PairedClockIncrementalSamplesV3>>,
    effect_writes: Option<Box<PairedClockIncrementalSamplesV3>>,
}

// Two proof points, each with freeze and independently owed thaw. A freezer
// record is two bytes; the selected writer permits at most two native attempts
// per record, retaining refusal if interruption consumes that finite roster.
const LAUNCH_WRITE_SAMPLES: usize = 2 * 2 * 2;
const LAUNCH_WRITE_PAIRS: usize = LAUNCH_WRITE_SAMPLES.div_ceil(2);

struct LaunchWriteSamplesV2 {
    samples: [PairedClockSamplesV1; LAUNCH_WRITE_PAIRS],
    used: usize,
}

impl ArgumentClockV2 {
    // The genuine held Stage supplied this identity before its original
    // native clock capture. Borrowing it grants no new baseline or lifetime.
    pub(super) const fn protected_boot_data_v4(&self) -> [u8; 16] {
        self.protected_boot
    }

    // Called only after the actual complete phase consumption and before any
    // request-specific codec/State/nonce growth. These are the existing shared
    // kernel readers and shared paired-clock validator, not a recapture proof.
    pub(super) fn capture(protected_boot: [u8; 16]) -> Self {
        Self { baseline: PairedClockBaselineV1::capture(
            RawClockProvenance::new_untrusted(crate::KERNEL_CLOCK_PROVENANCE)),
            samples: std::array::from_fn(|_| PairedClockSamplesV1::new()),
            used: 0, stage: 0, stage_start: 0,
            protected_boot, sample_refusal: None, launch_writes: None,
            effect_clock: None, effect_clock_failure: None, sdk_writes: None,
            handshake_writes: None, handshake_write_refused: false, component_report_writes: None, effect_writes: None }
    }

    fn capture_cleanup_v2(protected_boot: [u8; 16]) -> Self {
        let mut clock = Self::capture(protected_boot);
        // A newly paid cleanup programme starts at its own42 preliminary.
        // The earlier39 is history, never an old clock/sample destination.
        clock.stage = 6;
        clock
    }

    // Host20 prepays this distinct two-attempt lane before59. It shares the
    // same baseline but spends no handshake, freezer, SDK or ordinary samples.
    pub(super) fn capture_effect_v4(protected_boot: [u8; 16]) -> Self {
        let mut clock = Self::capture(protected_boot);
        clock.effect_writes = Some(Box::new(PairedClockIncrementalSamplesV3::new(
            crate::live_agent::MAXIMUM_EFFECT_WRITE_ATTEMPTS_V4,
        )));
        clock
    }

    pub(super) fn effect_write_demand_v4() -> Option<aos_sandbox_core::ResourceVector> {
        // The same incremental sampler carries two observation planes; actual
        // failed native readers close no capacity and forbid another entry.
        Self::sdk_write_demand_v3()
    }

    pub(super) fn bind_effect_write_v4(
        &mut self, effect: &aos_sandbox_broker::BrokerEffectIntentV1,
    ) -> Result<()> {
        if self.failure().is_some() || self.effect_writes.is_none() || self.effect_clock.is_some() {
            return Err(HostError::Fence("Host effect clock cannot bind another effect"));
        }
        self.effect_clock = Some(aos_sandbox_broker::BrokerEffectClockComparisonV3::from_effect(effect));
        Ok(())
    }

    pub(super) fn sample_effect_write_v4(&mut self, original_cutoff: u64) -> Result<()> {
        if self.failure().is_some() || self.effect_clock.is_none() {
            return Err(HostError::Fence("Host effect write clock is closed"));
        }
        let sampled = (|| {
            let sample = self.effect_writes.as_mut()
                .ok_or(HostError::Fence("Host effect write clock lane is not prepaid"))?
                .sample(&mut self.baseline)
                .map_err(|_| HostError::Fence("Host effect native paired-clock sampling refused"))?;
            if sample.host_boot_id() != self.protected_boot
                || sample.boottime_nanoseconds() >= original_cutoff
            {
                return Err(HostError::Fence("Host effect original clock cutoff refused"));
            }
            self.require_effect_clock_v3(&sample)?;

            // The full actual effect/boot/deadline check finished. Only its
            // temporary native leaves retire; baseline and last sample remain.
            self.baseline.retire_positive_native_file_v2()
                .map_err(|_| HostError::Fence("Host effect clock baseline cannot retire"))?;
            self.effect_writes.as_mut()
                .ok_or(HostError::Fence("Host effect clock owner disappeared"))?
                .accept_positive_sample_v3(sample)
                .map_err(|_| HostError::Fence("Host effect clock sample cannot retire"))?;
            Ok(())
        })();
        if let Err(cause) = sampled {
            self.sample_refusal.get_or_insert(cause);
            return Err(HostError::Fence("Host effect write clock is unavailable"));
        }
        Ok(())
    }

    // Only genuine Launch uses this additional prepaid lane. It shares the
    // already captured baseline, boot identity and monotone clock validator.
    pub(super) fn capture_launch_v2(protected_boot: [u8; 16]) -> Self {
        let mut clock = Self::capture(protected_boot);
        clock.launch_writes = Some(Box::new(LaunchWriteSamplesV2 {
            samples: std::array::from_fn(|_| PairedClockSamplesV1::new()),
            used: 0,
        }));
        clock
    }

    // The comparison comes directly from the same admitted effect. It is
    // passive scalar DATA; no lease, clock baseline or live permission is made.
    pub(super) fn capture_launch_effect_v3(
        protected_boot: [u8; 16],
        effect: &aos_sandbox_broker::BrokerEffectIntentV1,
    ) -> Self {
        Self::capture_launch_effect_recipe_v4(protected_boot, effect, true)
    }

    pub(super) fn capture_stop_effect_v4(
        protected_boot: [u8; 16],
        effect: &aos_sandbox_broker::BrokerEffectIntentV1,
    ) -> Self {
        Self::capture_launch_effect_recipe_v4(protected_boot, effect, false)
    }

    pub(super) fn bind_retained_stop_effect_v4(
        &mut self,
        effect: &aos_sandbox_broker::BrokerEffectIntentV1,
    ) -> Result<()> {
        if self.failure().is_some() || self.effect_clock.is_some()
            || self.launch_writes.is_some() || self.sdk_writes.is_some()
            || self.handshake_writes.is_some() || self.effect_writes.is_some()
        {
            return Err(HostError::Fence("fresh Stop clock cannot replace an existing lane"));
        }
        self.launch_writes = Some(Box::new(LaunchWriteSamplesV2 {
            samples: std::array::from_fn(|_| PairedClockSamplesV1::new()), used: 0,
        }));
        self.effect_clock = Some(aos_sandbox_broker::BrokerEffectClockComparisonV3::from_effect(effect));
        self.sdk_writes = Some(Box::new(PairedClockIncrementalSamplesV3::new(
            crate::worker::launch::MAXIMUM_EFFECT_WRITE_ATTEMPTS_V3,
        )));
        Ok(())
    }

    // Both closed programs use the same original native baseline and effect
    // comparison. Stop constructs no Agent handshake sampler or setup owner.
    fn capture_launch_effect_recipe_v4(
        protected_boot: [u8; 16],
        effect: &aos_sandbox_broker::BrokerEffectIntentV1,
        handshake: bool,
    ) -> Self {
        let mut clock = Self::capture_launch_v2(protected_boot);
        clock.effect_clock = Some(aos_sandbox_broker::BrokerEffectClockComparisonV3::from_effect(effect));
        clock.sdk_writes = Some(Box::new(PairedClockIncrementalSamplesV3::new(
            crate::worker::launch::MAXIMUM_EFFECT_WRITE_ATTEMPTS_V3,
        )));
        if handshake {
            clock.handshake_writes = Some(Box::new(PairedClockIncrementalSamplesV3::new(
                crate::live_agent::MAXIMUM_HANDSHAKE_WRITE_ATTEMPTS_V3,
            )));
        }
        clock
    }

    // Shares the same baseline/native peak, but never spends SDK or freezer slots.
    pub(super) fn handshake_write_demand_v3() -> Option<aos_sandbox_core::ResourceVector> {
        Self::sdk_write_demand_v3()
    }

    pub(super) fn sample_handshake_write_v3(&mut self) -> Result<()> {
        if self.failure().is_some() || self.effect_clock.is_none() {
            self.handshake_write_refused = true;
            return Err(HostError::Fence("Host Launch handshake clock is closed"));
        }

        let sampled = (|| {
            let sample = self.handshake_writes.as_mut()
                .ok_or(HostError::Fence("Host Launch handshake clock lane is not prepaid"))?
                .sample(&mut self.baseline)
                .map_err(|_| HostError::Fence("Host Launch handshake paired-clock sampling refused"))?;
            if sample.host_boot_id() != self.protected_boot {
                return Err(HostError::Fence("Host Launch handshake boot changed"));
            }
            self.require_effect_clock_v3(&sample)?;

            self.baseline.retire_positive_native_file_v2()
                .map_err(|_| HostError::Fence("Host Launch clock baseline cannot retire"))?;
            self.handshake_writes.as_mut()
                .ok_or(HostError::Fence("Host Launch handshake clock owner disappeared"))?
                .accept_positive_sample_v3(sample)
                .map_err(|_| HostError::Fence("Host Launch handshake sample cannot retire"))?;
            Ok(())
        })();
        if let Err(cause) = sampled {
            self.handshake_write_refused = true;
            self.sample_refusal.get_or_insert(cause);
            return Err(HostError::Fence("Host Launch handshake clock is unavailable"));
        }
        Ok(())
    }

    pub(super) fn prepare_component_report_writes_v2(&mut self) -> Result<()> {
        if self.component_report_writes.is_some() || self.effect_clock.is_none() || self.failure().is_some() {
            return Err(HostError::Fence("component report clock is occupied or closed"));
        }
        self.component_report_writes = Some(Box::new(PairedClockIncrementalSamplesV3::new(3)));
        Ok(())
    }

    pub(crate) fn sample_component_report_write_v2(&mut self) -> Result<()> {
        if self.failure().is_some() || self.effect_clock.is_none() {
            self.handshake_write_refused = true;
            return Err(HostError::Fence("Host Launch handshake clock is closed"));
        }

        let sampled = (|| {
            let sample = self.component_report_writes.as_mut()
                .ok_or(HostError::Fence("Host Launch handshake clock lane is not prepaid"))?
                .sample(&mut self.baseline)
                .map_err(|_| HostError::Fence("Host Launch handshake paired-clock sampling refused"))?;
            if sample.host_boot_id() != self.protected_boot {
                return Err(HostError::Fence("Host Launch handshake boot changed"));
            }
            self.require_effect_clock_v3(&sample)?;

            self.baseline.retire_positive_native_file_v2()
                .map_err(|_| HostError::Fence("Host Launch clock baseline cannot retire"))?;
            self.component_report_writes.as_mut()
                .ok_or(HostError::Fence("Host Launch handshake clock owner disappeared"))?
                .accept_positive_sample_v3(sample)
                .map_err(|_| HostError::Fence("Host Launch handshake sample cannot retire"))?;
            Ok(())
        })();
        if let Err(cause) = sampled {
            self.handshake_write_refused = true;
            self.sample_refusal.get_or_insert(cause);
            return Err(HostError::Fence("Host Launch handshake clock is unavailable"));
        }
        Ok(())
    }

    pub(super) fn handshake_write_failure_v3(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.handshake_write_refused { self.failure() } else { None }
    }

    pub(super) fn sdk_write_demand_v3() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        // The same original three-file clock peak and actual proc name are
        // already included in receiving_demand_v2. Failed samples forbid any
        // next entry. Only two complete observation carriers coexist here.
        let bytes = PairedClockIncrementalSamplesV3::receiving_bytes_v3()?
            .checked_add(2 * std::mem::size_of::<Box<PairedClockIncrementalSamplesV3>>())?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    pub(super) fn has_effect_comparison_v3(&self) -> bool {
        self.effect_clock.is_some()
    }

    fn require_effect_clock_v3(&mut self, sample: &RawPairedClockSample) -> Result<()> {
        let comparison = self.effect_clock.as_ref()
            .ok_or(HostError::Fence("Host Launch durable clock comparison is absent"))?;
        if let Err(cause) = comparison.require_fresh(sample) {
            self.effect_clock_failure.get_or_insert(cause);
            return Err(HostError::Fence("Host Launch signed clock comparison refused"));
        }
        Ok(())
    }

    pub(super) fn sample_sdk_write_v3(&mut self) -> Result<RawPairedClockSample> {
        if self.failure().is_some() || self.effect_clock.is_none() {
            return Err(HostError::Fence("Host Launch SDK clock is closed"));
        }
        let sampled = (|| {
            let lane = self.sdk_writes.as_mut()
                .ok_or(HostError::Fence("Host Launch SDK clock lane is not prepaid"))?;
            let sample = lane.sample(&mut self.baseline)
                .map_err(|_| HostError::Fence("Host Launch SDK paired-clock sampling refused"))?;
            if sample.host_boot_id() != self.protected_boot {
                return Err(HostError::Fence("Host argument paired-clock boot changed"));
            }
            self.require_effect_clock_v3(&sample)?;

            // Every signed clock predicate succeeded. No later post consumes
            // these temporary boot readers; baseline and last sample survive.
            self.baseline.retire_positive_native_file_v2()
                .map_err(|_| HostError::Fence("Host Launch clock baseline cannot retire"))?;
            self.sdk_writes.as_mut()
                .ok_or(HostError::Fence("Host Launch SDK clock owner disappeared"))?
                .accept_positive_sample_v3(sample)
                .map_err(|_| HostError::Fence("Host Launch positive SDK sample cannot retire"))?;
            Ok(sample)
        })();
        match sampled {
            Ok(sample) => Ok(sample),
            Err(cause) => {
                self.sample_refusal.get_or_insert(cause);
                Err(HostError::Fence("Host Launch SDK clock is unavailable"))
            }
        }
    }

    pub(super) fn launch_write_demand_v2() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let boot = aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?;
        let bytes = LAUNCH_WRITE_PAIRS.checked_mul(PairedClockSamplesV1::representation_memory_bytes())?
            .checked_add(2 * std::mem::size_of::<LaunchWriteSamplesV2>())?
            .checked_add(LAUNCH_WRITE_SAMPLES.checked_mul(2)?.checked_mul(boot)?)?;
        // A failed clock prevents later native sampling. Completed canonical
        // Files close at the same shared frontier, so the original three-FD
        // peak and one actual proc name remain covered by receiving_demand.
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    pub(super) fn sample_launch_write_v2(&mut self) -> Result<RawPairedClockSample> {
        if self.failure().is_some() {
            return Err(HostError::Fence("Host Launch write clock has retained failure"));
        }
        let sampled = (|| {
            let lane = self.launch_writes.as_mut()
                .ok_or(HostError::Fence("Host Launch write clock is not prepaid"))?;
            if lane.used == LAUNCH_WRITE_SAMPLES {
                return Err(HostError::Fence("Host Launch write clock schedule is exhausted"));
            }
            let samples = lane.samples.get_mut(lane.used / 2)
                .ok_or(HostError::Fence("Host Launch write clock schedule is exhausted"))?;
            lane.used += 1;
            let sample = samples.sample(&mut self.baseline)
                .map_err(|_| HostError::Fence("Host argument native paired-clock failed"))?;
            if sample.host_boot_id() != self.protected_boot {
                return Err(HostError::Fence("Host argument paired-clock boot changed"));
            }
            // A full effect comparison is mandatory for genuine Launch writes.
            // The raw test-only lane remains usable as non-authorizing DATA.
            if let Some(comparison) = self.effect_clock.as_ref() {
                if let Err(cause) = comparison.require_fresh(&sample) {
                    self.effect_clock_failure.get_or_insert(cause);
                    return Err(HostError::Fence("Host Launch signed clock comparison refused"));
                }
            }
            self.baseline.retire_positive_native_file_v2()
                .and_then(|()| samples.retire_positive_native_files_v2())
                .map_err(|_| HostError::Fence("Host argument positive clock leaf cannot retire"))?;
            Ok(sample)
        })();
        match sampled {
            Ok(sample) => Ok(sample),
            Err(error) => {
                self.sample_refusal.get_or_insert(error);
                Err(HostError::Fence("Host Launch write clock is unavailable"))
            }
        }
    }

    pub(super) fn receiving_demand_v2() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceVector, ResourceDimension as D};
        let boot_readers = MAXIMUM_CLOCK_SAMPLES.checked_mul(2)?.checked_add(1)?;
        let boot_bytes = aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?;
        let bytes = CLOCK_PAIRS.checked_mul(PairedClockSamplesV1::representation_memory_bytes())?
            .checked_add(2 * std::mem::size_of::<Self>())?
            .checked_add(boot_readers.checked_mul(boot_bytes)?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            // Successful canonical EOF inputs close before the next sample.
            // A failed sample retains both bookends and blocks further entry.
            .with(D::OpenFiles, 3)
            // All baseline/bookend readers name the same actual proc entry.
            .with(D::MetadataEntries, 1))
    }

    pub(super) fn sample(&mut self) -> Result<RawPairedClockSample> {
        if self.failure().is_some() {
            return Err(HostError::Fence("Host argument clock has retained failure"));
        }
        let sampled = (|| {
            if self.used >= MAXIMUM_CLOCK_SAMPLES
                || self.used.checked_sub(self.stage_start).is_none_or(|used| used >= CLOCK_SAMPLES_PER_STAGE) {
                return Err(HostError::Fence("Host argument clock schedule is exhausted"));
            }
            let samples = self.samples.get_mut(self.used / 2)
                .ok_or(HostError::Fence("Host argument clock schedule is exhausted"))?;
            self.used += 1;
            sample_clock_lane_v2(&mut self.baseline, samples, self.protected_boot)
        })();
        match sampled {
            Ok(sample) => Ok(sample),
            Err(error) => {
                self.sample_refusal = Some(error);
                Err(HostError::Fence("Host argument clock is unavailable"))
            }
        }
    }

    // Only the real next paid Host phase advances this finite clock lane.
    // Each phase retains its original sixteen-sample envelope and old samples;
    // neither the first clock nor any source cutoff is recreated or extended.
    fn advance_argument_stage_v2(&mut self, method: BrokerMethod) -> Result<()> {
        let next = match method {
            BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY if self.stage <= 2 => 5,
            BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 => match self.stage {
                5 => 6,
                7 => 8,
                8 => 9,
                _ => return Err(HostError::Fence("Host held settlement clock phase differs")),
            },
            BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 if self.stage == 6 => 7,
            BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT => 1,
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT => 2,
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 => 3,
            BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => 4,
            _ => return Err(HostError::Fence("Host argument clock stage differs")),
        };
        if self.failure().is_some() || (next != 5 && next != self.stage + 1)
            || self.used.checked_sub(self.stage_start).is_none_or(|used| used > CLOCK_SAMPLES_PER_STAGE)
        { return Err(HostError::Fence("Host argument clock stage cannot advance")); }
        self.stage = next;
        self.stage_start = self.used;
        Ok(())
    }

    // A separate already-paid finite monitor destination borrows this SAME
    // baseline. Its owning permission must validate the returned sample before
    // accepting it; failure leaves all native inputs and the old clock intact.
    pub(super) fn sample_monitor_lane_v5(
        &mut self, lane: &mut PairedClockIncrementalSamplesV3,
    ) -> Result<RawPairedClockSample> {
        if self.failure().is_some() {
            return Err(HostError::Fence("execution monitor original clock is closed"));
        }
        let sample = lane.sample(&mut self.baseline)
            .map_err(|_| HostError::Fence("execution monitor native clock refused"))?;
        if sample.host_boot_id() != self.protected_boot {
            return Err(HostError::Fence("execution monitor original boot changed"));
        }
        Ok(sample)
    }

    // This separate, prepaid destination is an independently owed native
    // post. Earlier clock/permission refusal remains resident and cannot gate
    // either boot bookend. The same baseline still validates its DATA; a
    // successful native read cannot restore effect or read permission.
    pub(super) fn sample_monitor_owed_post_lane_v3(
        &mut self, lane: &mut PairedClockIncrementalSamplesV3,
    ) -> Result<RawPairedClockSample> {
        let sample = lane.sample(&mut self.baseline)
            .map_err(|_| HostError::Fence("execution owed post native clock refused"))?;
        if sample.host_boot_id() != self.protected_boot {
            return Err(HostError::Fence("execution owed post original boot changed"));
        }
        Ok(sample)
    }

    pub(super) fn retire_positive_monitor_sample_v5(
        &mut self, lane: &mut PairedClockIncrementalSamplesV3,
        sample: RawPairedClockSample,
    ) -> Result<()> {
        self.baseline.retire_positive_native_file_v2()
            .and_then(|()| lane.accept_positive_sample_v3(sample))
            .map_err(|_| HostError::Fence("execution monitor positive clock leaves cannot retire"))
    }

    pub(super) fn deadline(&mut self, boottime_deadline: u64) -> Result<Instant> {
        // Capture the local Instant before its native time sample. This may
        // shorten the remaining interval, never extend the original deadline.
        let instant = Instant::now();
        let now = self.sample()?;
        deadline_from_boottime_v2(instant, now.boottime_nanoseconds(), boottime_deadline)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.baseline.failure().or_else(|| self.samples.iter().find_map(|samples| {
            samples.observation_failure(0).or_else(|| samples.observation_failure(1))
        })).or_else(|| self.launch_writes.as_ref().and_then(|lane| {
            lane.samples.iter().find_map(|samples| {
                samples.observation_failure(0).or_else(|| samples.observation_failure(1))
            })
        })).or_else(|| self.sdk_writes.as_ref().and_then(|lane| lane.failure()))
            .or_else(|| self.component_report_writes.as_ref().and_then(|lane| lane.failure()))
            .or_else(|| self.handshake_writes.as_ref().and_then(|lane| lane.failure()))
            .or_else(|| self.effect_writes.as_ref().and_then(|lane| lane.failure()))
            .or_else(|| self.effect_clock_failure.as_ref().map(|cause| cause as _))
            .or_else(|| self.sample_refusal.as_ref().map(|cause| cause as _))
    }
}


fn sample_clock_lane_v2(
    baseline: &mut PairedClockBaselineV1,
    samples: &mut PairedClockSamplesV1,
    protected_boot: [u8; 16],
) -> Result<RawPairedClockSample> {
    let sample = samples.sample(baseline)
        .map_err(|_| HostError::Fence("Host argument native paired-clock failed"))?;
    if sample.host_boot_id() != protected_boot {
        return Err(HostError::Fence("Host argument paired-clock boot changed"));
    }
    // The exact completed canonical EOF Files may retire; their bytes, native
    // Results and one-shot latches remain on the same clock and baseline.
    baseline.retire_positive_native_file_v2()
        .and_then(|()| samples.retire_positive_native_files_v2())
        .map_err(|_| HostError::Fence("Host argument positive clock leaf cannot retire"))?;
    Ok(sample)
}

fn deadline_from_boottime_v2(instant: Instant, now: u64, absolute: u64) -> Result<Instant> {
    let remaining = absolute.checked_sub(now).filter(|remaining| *remaining > 0)
        .ok_or(HostError::Fence("Host argument original deadline has expired"))?;
    instant.checked_add(Duration::from_nanos(remaining))
        .ok_or(HostError::Fence("Host argument original deadline overflows"))
}

use std::sync::{Arc, Mutex, MutexGuard};
use aos_proto::aos::sandbox::local::v1::{BrokerMethod, AcceptHostExecutionArgumentResponseV2};
use aos_sandbox::runtime_execution::{DormantRuntimeExecutionOpeningV2,
    DormantRuntimeExecutionOwnerV1, DormantRuntimeExecutionOwnerErrorV1};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use buffa::Message as _;
use crate::live_agent::argument_attempt::{HostArgumentAttemptOpeningV2, HostArgumentAttemptErrorV1};
use crate::state::{HostState, HostStateStore, HostStateWriteAttemptV2};

#[derive(Debug, thiserror::Error)]
pub(in crate::broker) enum ArgumentStageErrorV2 {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error(transparent)]
    Owner(#[from] DormantRuntimeExecutionOwnerErrorV1),
    #[error(transparent)]
    Journal(#[from] aos_sandbox::JournalError),
    #[error(transparent)]
    Argument(#[from] HostArgumentAttemptErrorV1),
    #[error(transparent)]
    Transport(#[from] aos_sandbox_protocol::ProtocolValidationError),
    #[error(transparent)]
    Source(#[from] aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptErrorV1),
    #[error(transparent)]
    AcceptedSource(#[from] aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordErrorV1),
    #[error(transparent)]
    Output(#[from] crate::execution_effect::HostExecutionEffectErrorV1),
    #[error(transparent)]
    RootAttestation(#[from] aos_sandbox_protocol::host_execution_no_apply::root_attestation::RootNoApplyAttestationDataErrorV2),
    #[error(transparent)]
    RootRecoveryAcquisition(#[from] aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::RootNoApplyRecoveryAcquisitionDataErrorV2),
}

pub(super) struct ArgumentStateWritesV2 {
    slots: [HostStateWriteAttemptV2; 2],
    used: usize,
}

impl ArgumentStateWritesV2 {
    pub(super) fn new() -> Self {
        Self { slots: std::array::from_fn(|_| HostStateWriteAttemptV2::new()), used: 0 }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.slots.iter().find_map(HostStateWriteAttemptV2::failure)
    }

    pub(super) fn require_positive_disposal_v2(&self) -> Result<()> {
        if self.used > self.slots.len() || self.failure().is_some()
            || !self.slots[..self.used].iter().all(HostStateWriteAttemptV2::is_complete)
        {
            return Err(HostError::Fence("Host State scratch has incomplete native writes"));
        }
        Ok(())
    }

    pub(super) fn commit_once_v2(&mut self, store: &impl HostStateStore, state: &HostState) -> Result<()> {
        let slot = self.slots.get_mut(self.used)
            .ok_or(HostError::Fence("Host argument State write schedule is exhausted"))?;
        self.used += 1;
        store.commit_retaining_v2(state, slot)
    }
}

#[derive(Clone, Copy)]
enum ArgumentFirstV2 {
    Before,
    Clock,
    Opening,
    Fifth,
    Primary,
    After,
    NativeFinish,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RuntimeOpeningV2 { Fresh, Resident }

pub(super) struct ArgumentStageOriginalV2 {
    availability: Option<availability::HostAvailabilityOriginalV2>,
    opening: DormantRuntimeExecutionOpeningV2,
    pub(super) owner: Option<DormantRuntimeExecutionOwnerV1>,
    pub(super) argument: Option<HostArgumentAttemptOpeningV2>,
    writes: Arc<Mutex<ArgumentStateWritesV2>>,
    clock: Option<ArgumentClockV2>,
    pub(super) accepted: Option<super::accepted_execution::AcceptedExecutionOriginalV2>,
    pub(super) authenticated: bool,
    future_append: Option<std::result::Result<ResourceVector,
        aos_sandbox::journal::JournalAppendReceivingDemandErrorV1>>,
    source_cutoff: Option<std::result::Result<u64, ArgumentStageErrorV2>>,
    reservation: Option<super::HostExecutionGrantReservationV1>,
    before: Option<Result<()>>,
    primary: Option<std::result::Result<Vec<u8>, ArgumentStageErrorV2>>,
    after: Option<Result<()>>,
    native_finish: Option<Result<()>>,
    deadlines: [Option<Result<Instant>>; FRONTIER_DEADLINES],
    deadlines_used: usize,
    first: Option<ArgumentFirstV2>,
    frontier: ArgumentFirstV2,
    pub(super) complete_demand: ResourceVector,
    pub(super) request: (BrokerMethod, [u8; 16], [u8; 32], [u8; 32]),
}

/// Borrows the actual positive ACK stage before its last native owner drops.
pub(crate) struct HostNoApplyTerminalPositiveV2<'stage> {
    stage: &'stage ArgumentStageOriginalV2,
    prepare: crate::plan::HostExecutionRequestBindingV2,
    ack: crate::plan::HostExecutionRequestBindingV2,
}

impl HostNoApplyTerminalPositiveV2<'_> {
    pub(crate) fn bindings_v2(&self) -> (crate::plan::HostExecutionRequestBindingV2,
        crate::plan::HostExecutionRequestBindingV2) {
        (self.prepare, self.ack)
    }

    pub(crate) fn observation_rounds_v2(&self) -> impl Iterator<Item = usize> + '_ {
        self.stage.retained_availability_observation_rounds_v2()
    }

    pub(crate) fn require_cleanup_control_original_v1(
        &self,
        token: &crate::plan::HostControlCleanupTokenV1,
    ) -> Result<()> {
        self.stage.availability.as_ref().ok_or(HostError::Fence(
            "Host NoApply cleanup original is absent",
        ))?.require_cleanup_control_original_v1(token)
    }
}

impl ArgumentStageOriginalV2 {
    // Comparison DATA comes from this Stage's original retained clock.
    pub(in crate::broker) fn protected_boot_data_v4(&self) -> Option<[u8; 16]> {
        self.clock.as_ref().map(ArgumentClockV2::protected_boot_data_v4)
    }

    pub(in crate::broker) fn require_terminal_storage_disposal_v3(&self) -> Result<()> {
        self.require_retained_availability_terminal_v2()?;
        if !self.authenticated || self.first.is_some() || self.primary.is_some()
            || !matches!(self.before, Some(Ok(()))) || !matches!(self.after, Some(Ok(())))
            || !matches!(self.native_finish, Some(Ok(()))) || self.clock_error().is_some()
            || self.owner.is_none() || self.argument.is_none()
            || self.opening.failure().is_some()
            || self.argument.as_ref().is_some_and(|argument| argument.failure().is_some())
        {
            return Err(HostError::Fence("terminal Stage retains unresolved original custody"));
        }
        let writes = self.writes.lock().map_err(|_| HostError::Fence("terminal Stage State writer is poisoned"))?;
        writes.require_positive_disposal_v2()?;
        if Arc::strong_count(&self.writes) != 1
            || self.owner.as_ref().and_then(|owner| owner.execution_monitor_append_failure_v5()).is_some()
        {
            return Err(HostError::Fence("terminal Stage retains a writer alias or append failure"));
        }
        self.accepted.as_ref().ok_or(HostError::Fence("terminal Stage lacks actual execution"))?
            .require_terminal_storage_disposal_v3()
    }

    fn require_deadline_once_v2(&mut self, absolute: u64) -> Result<()> {
        self.frontier = ArgumentFirstV2::Clock;
        let slot = self.deadlines.get_mut(self.deadlines_used)
            .ok_or(HostError::Fence("Host argument deadline schedule is exhausted"))?;
        self.deadlines_used += 1;
        *slot = Some(self.clock.as_mut()
            .ok_or(HostError::Fence("Host argument retained clock is absent"))?
            .deadline(absolute));
        if !slot.as_ref().is_some_and(Result::is_ok) {
            return Err(HostError::Fence("Host argument absolute deadline is unavailable"));
        }
        Ok(())
    }

    fn primary_error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(cause) = self.availability.as_ref().and_then(availability::HostAvailabilityOriginalV2::failure) {
            return Some(cause);
        }
        if let Some(cause) = self.clock.as_ref().and_then(ArgumentClockV2::failure) {
            return Some(cause);
        }
        self.primary.as_ref()?.as_ref().err().map(|cause| cause as _)
    }

    fn clock_error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.clock.as_ref().and_then(ArgumentClockV2::failure)
            .or_else(|| self.source_cutoff.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.deadlines.iter().find_map(|result| result.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _)))
    }

    pub(in crate::broker) fn require_positive_opening_residency_v6(&self) -> Result<()> {
        if !self.authenticated || self.first.is_some() || self.owner.is_none()
            || !matches!(self.before, Some(Ok(()))) || !matches!(self.after, Some(Ok(())))
            || !matches!(self.native_finish, Some(Ok(()))) || self.primary.is_some()
        { return Err(HostError::Fence("Host accepted opening is not positively resident")); }
        self.opening.require_positive_residency_v6()
            .map_err(|_| HostError::Fence("Host runtime opening retains a native prefix"))?;
        self.argument.as_ref().ok_or(HostError::Fence("Host fifth opening is absent"))?
            .require_positive_residency_v6()
            .map_err(|_| HostError::Fence("Host fifth opening retains a native prefix"))
    }

    fn fixed_demand(request: &AuthenticatedBrokerMethodRequestV1) -> Option<ResourceVector> {
        Self::fixed_demand_for_runtime_v2(request, RuntimeOpeningV2::Fresh)
    }

    fn fixed_demand_for_runtime_v2(request: &AuthenticatedBrokerMethodRequestV1,
        opening: RuntimeOpeningV2) -> Option<ResourceVector> {
        let held_no_apply = request.host_held_no_apply_settlement_data_v2().is_some()
            || request.host_no_apply_current_lease_query_data_v2().is_some();
        let artifact_bytes = match request.authorization() {
            Some(artifacts) if !held_no_apply
                && request.method() != BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 =>
                [artifacts.broker_plan(), artifacts.broker_plan_signature(),
                    artifacts.ownership_lease(), artifacts.ownership_lease_signature()]
                    .into_iter().try_fold(0_usize, |sum, bytes| sum.checked_add(bytes.len()))?,
            None if held_no_apply
                || request.method() == BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 => 0,
            _ => return None,
        };
        // Original received inputs remain with the authenticated request. The
        // existing bounded canonical/typed/authority/seal recipes use dominant
        // byte planes, backed by the same real Host memory limit. This is no
        // allocation-exact model/crypto/allocator-fit claim or metadata-cell fee.
        let codec_bytes = artifact_bytes.checked_add(request.exact_body().len())?.checked_mul(8)?;
        let upper = (if opening == RuntimeOpeningV2::Fresh { 2 * std::mem::size_of::<Self>() } else { 0 })
            .checked_add(2 * std::mem::size_of::<ArgumentNativeReceivingV2<'static>>())?
            .checked_add(2 * std::mem::size_of::<ArgumentStateWritesV2>())?
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(codec_bytes)?;
        let runtime_opening = match opening {
            RuntimeOpeningV2::Fresh => DormantRuntimeExecutionOpeningV2::fixed_preparation_demand_v2()?,
            RuntimeOpeningV2::Resident => ResourceVector::ZERO,
        };
        let clock = match opening {
            RuntimeOpeningV2::Fresh => ArgumentClockV2::receiving_demand_v2()?,
            RuntimeOpeningV2::Resident => ResourceVector::ZERO,
        };
        let state_writes = if held_no_apply || matches!(request.method(),
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT) {
            ResourceVector::ZERO
        } else { HostStateWriteAttemptV2::argument_pair_demand_v2()? };
        let scratch_files = state_writes.get(D::OpenFiles)
            .checked_add(clock.get(D::OpenFiles))?;
        let mut file_peak = runtime_opening.get(D::OpenFiles);
        let mut demand = runtime_opening
            .checked_add(state_writes).ok()?
            .checked_add(clock).ok()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(upper).ok()?)
                .with(D::OutputBytes, u64::try_from(
                    aos_sandbox_protocol::host_execution_argument::receipt::MAXIMUM_HOST_ARGUMENT_FRESH_RECEIPT_BYTES_V1
                        .max(aos_sandbox_protocol::host_execution_argument::preparation::HOST_ARGUMENT_PREPARATION_BYTES_V2)
                        .checked_add(16)?).ok()?)
                .with(D::ConcurrentOperations, 1)).ok()?;
        if request.method() == BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 {
            let fifth = HostArgumentAttemptOpeningV2::fixed_preparation_demand_v2()?;
            let accepted = super::accepted_execution::AcceptedExecutionOriginalV2::fixed_demand_v2()?;
            let four_resident = match opening {
                RuntimeOpeningV2::Fresh => DormantRuntimeExecutionOpeningV2::positive_resident_files_v6(),
                RuntimeOpeningV2::Resident => 0,
            };
            let resident = four_resident.checked_add(HostArgumentAttemptOpeningV2::positive_resident_files_v6())?;
            file_peak = file_peak.max(four_resident.checked_add(fifth.get(D::OpenFiles))?)
                .max(resident.checked_add(accepted.get(D::OpenFiles))?);
            demand = demand.checked_add(fifth).ok()?
                .checked_add(ResourceVector::ZERO.with(D::NetworkBytes, 512 + 1024)).ok()?
                // The fixed finite20 continuation is admitted before59, not
                // reconstructed from its later signed response or spec DATA.
                .checked_add(accepted).ok()?;
        }
        // Memory, traffic, stored output and namespace invoices remain SUM.
        // The actual old clock/State files stay conservatively resident across
        // both phases; only proven-positive opening probe FDs share a peak.
        demand = demand.with(D::OpenFiles, scratch_files.checked_add(file_peak)?);
        if request.method() == BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 {
            demand = demand.checked_add(availability::HostAvailabilityOriginalV2::fixed_demand_v2()?).ok()?;
        }
        Some(demand)
    }

    fn new(request: &AuthenticatedBrokerMethodRequestV1, complete_demand: ResourceVector) -> Self {
        Self {
            availability: None,
            opening: DormantRuntimeExecutionOpeningV2::new(),
            owner: None,
            argument: (request.method() == BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2)
                .then(HostArgumentAttemptOpeningV2::new),
            writes: Arc::new(Mutex::new(ArgumentStateWritesV2::new())),
            clock: None,
            accepted: (request.method() == BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2)
                .then(super::accepted_execution::AcceptedExecutionOriginalV2::new),
            authenticated: false,
            future_append: None,
            source_cutoff: None,
            reservation: None,
            before: None,
            primary: None,
            after: None,
            native_finish: None,
            deadlines: std::array::from_fn(|_| None),
            deadlines_used: 0,
            first: None,
            frontier: ArgumentFirstV2::Primary,
            complete_demand,
            request: (request.method(), request.request_id(), request.session_binding(),
                request.signed_request_digest()),
        }
    }

    // Both argument and predurable availability enter this one paid native
    // recipe. The same captured extent is admitted before each replay; an
    // earlier positive journal never leaves its destination on later failure.
    fn open_runtime_once_v2(
        &mut self,
        receiving: &mut ArgumentNativeReceivingV2<'_>,
        cutoff: u64,
    ) -> std::result::Result<(), ArgumentStageErrorV2> {
        for journal in 0..4 {
            self.require_deadline_once_v2(cutoff)?;
            self.frontier = ArgumentFirstV2::Opening;
            if self.opening.prepare_next_once_v2()? != journal {
                return Err(HostError::Fence("Host argument fixed journal order changed").into());
            }
            let demand = self.opening.captured_extent_v2(journal)
                .ok_or(HostError::Fence("Host argument held prefix is absent"))?
                .dominant_native_receiving_demand_v1()?;
            self.complete_demand = self.complete_demand.checked_add(demand)
                .map_err(|_| HostError::ResourceExhausted)?;
            self.frontier = ArgumentFirstV2::Primary;
            receiving.require_complete_v2(self.complete_demand)?;
            self.require_deadline_once_v2(cutoff)?;
            self.frontier = ArgumentFirstV2::Opening;
            self.opening.replay_prepared_once_v2(journal)?;
        }
        self.frontier = ArgumentFirstV2::Opening;
        self.owner = Some(self.opening.take_owner_once_v2()?);
        Ok(())
    }

    fn prepare_argument_native_v2(
        &mut self,
        receiving: &mut ArgumentNativeReceivingV2<'_>,
        cutoff: u64,
        opening: RuntimeOpeningV2,
    ) -> std::result::Result<(), ArgumentStageErrorV2> {
        // The first prepare check also samples after the awaited
        // before observation. No source/header time was refreshed.
        if opening == RuntimeOpeningV2::Fresh {
            self.open_runtime_once_v2(receiving, cutoff)?;
        } else {
            self.clock
                .as_mut()
                .ok_or(HostError::Fence("Host retained clock is absent"))?
                .deadline(cutoff)?;
            let quote = self
                .owner
                .as_ref()
                .ok_or(HostError::Fence("Host retained runtime owner is absent"))?
                .execution_claim_receiving_demand_v2();
            let available = self.availability.as_mut().ok_or(HostError::Fence(
                "Host retained runtime association is absent",
            ))?;
            let quote = available
                .retain_claim_demand_v2(quote)
                .ok_or(HostError::Fence("Host retained claim quote failed"))?;
            self.complete_demand = self
                .complete_demand
                .checked_add(quote)
                .map_err(|_| HostError::ResourceExhausted)?;
            receiving.require_complete_v2(self.complete_demand)?;
        }
        if self.accepted.is_some() {
            self.future_append = Some(
                self.owner
                    .as_ref()
                    .ok_or(HostError::Fence("Host accepted native owner is absent"))?
                    .accepted_execution_append_demand_v2(),
            );
            let forecast = self
                .future_append
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .copied()
                .ok_or(HostError::Fence(
                    "Host accepted append forecast is unavailable",
                ))?;
            self.complete_demand = self
                .complete_demand
                .checked_add(forecast)
                .map_err(|_| HostError::ResourceExhausted)?;
            receiving.require_complete_v2(self.complete_demand)?;
        }
        if self.argument.is_some() {
            self.require_deadline_once_v2(cutoff)?;
            self.frontier = ArgumentFirstV2::Fifth;
            let argument = self
                .argument
                .as_mut()
                .ok_or(HostError::Fence("Host argument fifth owner is absent"))?;
            argument.prepare_once()?;
            let demand = argument
                .captured_extent()
                .ok_or(HostError::Fence(
                    "Host argument fifth held prefix is absent",
                ))?
                .dominant_native_receiving_demand_v1()?;
            self.complete_demand = self
                .complete_demand
                .checked_add(demand)
                .map_err(|_| HostError::ResourceExhausted)?;
            self.frontier = ArgumentFirstV2::Primary;
            receiving.require_complete_v2(self.complete_demand)?;
            self.require_deadline_once_v2(cutoff)?;
            self.frontier = ArgumentFirstV2::Fifth;
            self.argument
                .as_mut()
                .ok_or(HostError::Fence("Host argument fifth owner is absent"))?
                .replay_once()?;
            let forecast = self
                .argument
                .as_mut()
                .ok_or(HostError::Fence("Host argument fifth owner is absent"))?
                .future_append_demand_v2()?;
            self.complete_demand = self
                .complete_demand
                .checked_add(forecast)
                .map_err(|_| HostError::ResourceExhausted)?;
            self.frontier = ArgumentFirstV2::Primary;
            receiving.require_complete_v2(self.complete_demand)?;
        }
        Ok(())
    }

    // The same original observer owes this post after every primary result.
    // No failed prefix, first cause or consumed financial operation can leave
    // the stage while a response is transferred to its authenticated Session.
    async fn finish_native_response_v2(
        &mut self, receiving: &mut ArgumentNativeReceivingV2<'_>,
    ) -> Result<Vec<u8>> {
        self.after = Some(receiving.observe_after_v2().await);
        if self.after.as_ref().is_some_and(Result::is_err) { self.first.get_or_insert(ArgumentFirstV2::After); }
        if !self.before.as_ref().is_some_and(Result::is_ok)
            || !self.primary.as_ref().is_some_and(|result| result.is_ok())
            || !self.after.as_ref().is_some_and(Result::is_ok)
        {
            return Err(HostError::Fence("Host argument flight failed; original custody is retained"));
        }
        self.native_finish = Some(receiving.finish_native_v2());
        if !self.native_finish.as_ref().is_some_and(Result::is_ok) {
            self.first.get_or_insert(ArgumentFirstV2::NativeFinish);
            return Err(HostError::Fence("Host argument native completion failed; original custody is retained"));
        }
        match self.primary.take() {
            Some(Ok(response)) => Ok(response),
            retained => {
                self.primary = retained;
                Err(HostError::Fence("Host argument positive native response disappeared"))
            }
        }
    }
}

// Uses the existing canonical transport and source engines. This is a cutoff
// observation of already-held authenticated bytes, never a Host grant.
pub(in crate::broker) fn original_argument_source_v2(
    request: &AuthenticatedBrokerMethodRequestV1,
    now: u64,
) -> std::result::Result<
    aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1,
    ArgumentStageErrorV2,
> {
    use aos_sandbox_protocol::host_execution_argument::{
        decode_host_execution_argument_accept_request_v2,
        decode_host_execution_argument_prepare_request_v2,
    };
    let canonical = match request.method() {
        BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 =>
            *decode_host_execution_argument_prepare_request_v2(request.exact_body(),
                request.peer(), request.peer_policy(), now)?.canonical_attempt(),
        BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 =>
            *decode_host_execution_argument_accept_request_v2(request.exact_body(),
                request.peer(), request.peer_policy(), now)?.source().canonical_attempt(),
        _ => return Err(HostError::Fence("Host argument source purpose differs").into()),
    };
    Ok(aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1
        ::decode_canonical(&canonical)?)
}

fn require_original_cutoff_v2(source: u64, header: u64, now: u64) -> Result<u64> {
    let cutoff = source.min(header);
    if cutoff <= now {
        return Err(HostError::Fence("Host argument original deadline has expired"));
    }
    Ok(cutoff)
}

impl<C: crate::plan::HostCatalog, S: HostStateStore, W: crate::worker::HostWorker> super::HostBroker<C, S, W> {
    fn execute_argument_primary_v2(
        &mut self,
        capture: &mut ArgumentStageOriginalV2,
        request: &AuthenticatedBrokerMethodRequestV1,
        protected_boot: [u8; 16],
        agent: &mut crate::live_agent::HostAgentLiveSessionV1,
        deadline_boottime_nanoseconds: u64,
    ) -> std::result::Result<Vec<u8>, ArgumentStageErrorV2> {
        self.active_argument_writes = Some(Arc::clone(&capture.writes));
        let result = (|| {
            capture.frontier = ArgumentFirstV2::Primary;
            let ArgumentStageOriginalV2 {
                owner,
                clock,
                argument,
                reservation,
                ..
            } = capture;
            let mut claim = owner
                .as_mut()
                .ok_or(HostError::Fence("Host argument runtime owner is absent"))?
                .claim()?;
            if claim.host_verifier().boot_id() != protected_boot {
                return Err(HostError::Fence("Host argument runtime boot changed").into());
            }
            agent
                .validate_claim(&claim)
                .map_err(HostArgumentAttemptErrorV1::from)?;
            let clock = clock
                .as_mut()
                .ok_or(HostError::Fence("Host argument retained clock is absent"))?;
            if reservation.is_none() {
                *reservation = Some(self.reserve_host_execution(
                    &claim,
                    request,
                    None,
                    protected_boot,
                    || clock.sample(),
                )?);
            } else {
                // The same genuine reservation crossed only physical
                // terminal disposal; no transport-auth adoption or second
                // signature verification/State reservation occurs here.
                let prior = reservation
                    .as_ref()
                    .ok_or(HostError::Fence("Host transition reservation is absent"))?;
                if prior.session_binding != request.session_binding()
                    || prior.signed_request_digest != request.signed_request_digest()
                    || !prior.matches(
                        request.method(),
                        request.request_id(),
                        request.exact_body(),
                        &claim,
                    )
                {
                    return Err(HostError::Fence(
                        "Host transition reservation differs at new owner",
                    )
                    .into());
                }
                self.authority
                    .check_before_effect(&prior.effect, &mut || {
                        clock
                            .sample()
                            .map_err(|_| aos_sandbox_broker::BrokerAdmissionError::FenceRejected)
                    })
                    .map_err(HostError::Authority)?;
            }
            let reservation = reservation
                .as_ref()
                .ok_or(HostError::Fence("Host argument reservation is absent"))?;
            let response = if request.method()
                == BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
            {
                reservation
                    .prepare_argument_once_v2(&claim, agent, clock)?
                    .canonical_bytes()
                    .to_vec()
            } else {
                let deadline = clock.deadline(deadline_boottime_nanoseconds)?;
                let argument = argument.as_mut().ok_or(HostError::Fence(
                    "Host argument fifth native owner is absent",
                ))?;
                let receipt = reservation
                    .accept_prepared_argument_once_v2(&claim, agent, argument, clock, deadline)?;
                AcceptHostExecutionArgumentResponseV2 {
                    canonical_receipt: receipt.canonical_bytes(),
                    ..Default::default()
                }
                .encode_to_vec()
            };
            claim.revalidate()?;
            agent
                .validate_claim(&claim)
                .map_err(HostArgumentAttemptErrorV1::from)?;
            if !reservation.matches(
                request.method(),
                request.request_id(),
                request.exact_body(),
                &claim,
            ) {
                return Err(HostError::Fence(
                    "Host argument reservation changed before completion",
                )
                .into());
            }
            self.complete_host_execution_reservation(&reservation, &claim, &response)?;
            Ok(response)
        })();
        self.active_argument_writes = None;
        result
    }

    pub(crate) async fn execute_argument_flight_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        protected_boot: [u8; 16],
        agent: &mut crate::live_agent::HostAgentLiveSessionV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Vec<u8>> {
        if let Some(stage) = self.argument_stages[0].as_ref() {
            let retained = stage.lock()
                .map_err(|_| HostError::Fence("Host original argument stage is poisoned"))?
                .availability.is_some();
            if retained {
                return self.execute_retained_availability_argument_v2(request, protected_boot,
                    agent, deadline_boottime_nanoseconds).await;
            }
        }
        // A later method58 first obtains its genuine signed reservation using
        // the old paid held reader. Only the same positive terminal disposer
        // may then release those OFDs before the new four-journal opening.
        self.prepare_next_execution_transition_v5(request, protected_boot,
            deadline_boottime_nanoseconds).await?;
        let index = match request.method() {
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 => 0,
            BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => 1,
            _ => return Err(HostError::Fence("Host argument flight purpose is unavailable")),
        };
        if !self.state_healthy || self.argument_stages[index].is_some() || self.active_argument_writes.is_some() {
            return Err(HostError::Fence("Host argument original State or flight is unavailable"));
        }
        let original = self.component_control.as_ref().cloned()
            .ok_or(HostError::Fence("Host argument has no intrinsic financial original"))?;
        let mut original = original.lock()
            .map_err(|_| HostError::Fence("Host argument intrinsic original is poisoned"))?;
        original.require_argument_boot_v2(protected_boot)?;
        let complete = ArgumentStageOriginalV2::fixed_demand(request)
            .and_then(|fixed| fixed.checked_add(original.argument_observation_demand_v2(request).ok()?).ok())
            .ok_or(HostError::ResourceExhausted)?;
        // No new codec, Arc, State or native IO is entered on funding refusal.
        let mut receiving = ArgumentNativeReceivingV2::Active(
            original.begin_argument_receiving_v2(request, complete)?,
        );
        let stage = Arc::new(Mutex::new(ArgumentStageOriginalV2::new(request, complete)));
        self.argument_stages[index] = Some(Arc::clone(&stage));
        let mut capture = stage.lock()
            .map_err(|_| HostError::Fence("Host argument resident stage is poisoned"))?;
        if index == 0 {
            if let Some(launch) = self.launch_original.as_ref() {
                let mut launch = launch.lock().map_err(|_| HostError::Fence("Host transition Launch is poisoned"))?;
                capture.reservation = launch.take_next_execution_reservation_v5(request)?;
            }
        }
        capture.clock = Some(ArgumentClockV2::capture(protected_boot));
        // Header renewal cannot renew the original Controller source. The
        // complete fixed phase is already consumed, but no PID1 await, journal
        // preparation or replay may begin before this original-cutoff check.
        capture.source_cutoff = Some((|| -> std::result::Result<u64, ArgumentStageErrorV2> {
            let sample = capture.clock.as_mut()
                .ok_or(HostError::Fence("Host argument retained clock is absent"))?.sample()?;
            let source = original_argument_source_v2(request, sample.boottime_nanoseconds())?;
            require_original_cutoff_v2(source.deadline_boottime_nanoseconds(),
                deadline_boottime_nanoseconds, sample.boottime_nanoseconds()).map_err(Into::into)
        })());
        let original_cutoff = match capture.source_cutoff.as_ref() {
            Some(Ok(cutoff)) => Some(*cutoff),
            _ => {
                capture.first.get_or_insert(ArgumentFirstV2::Clock);
                None
            }
        };
        capture.before = Some(match original_cutoff {
            Some(_) => receiving.observe_before_v2().await,
            None => Err(HostError::Fence("Host argument original source cutoff is unavailable")),
        });
        if capture.before.as_ref().is_some_and(Result::is_err) {
            capture.first.get_or_insert(ArgumentFirstV2::Before);
        }
        if let Some(deadline_boottime_nanoseconds) = original_cutoff.filter(|_| {
            capture.before.as_ref().is_some_and(Result::is_ok)
        }) {
            // Every reached captured extent is admitted before the SAME native
            // replay. Earlier positive tuples stay parked if a later one fails.
            let prepare = capture.prepare_argument_native_v2(
                &mut receiving, deadline_boottime_nanoseconds, RuntimeOpeningV2::Fresh,
            );
            let primary = prepare.and_then(|()| self.execute_argument_primary_v2(
                &mut capture, request, protected_boot, agent, deadline_boottime_nanoseconds));
            if primary.is_err() {
                let frontier = capture.frontier;
                capture.first.get_or_insert(frontier);
            }
            capture.primary = Some(primary);
        }
        let response = capture.finish_native_response_v2(&mut receiving).await?;
        drop(capture);
        receiving.retain_pending_authenticated_v2()?;
        Ok(response)
    }

    // Called by the sealed production Session completion only after its real
    // protected outcome CAS/readback, Sent and final currentness. This releases
    // resource custody; it issues no request/effect permission or new original.
    pub(crate) fn retire_authenticated_argument_v2(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        if matches!(request.method(), BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
            | BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
            | BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2) {
            self.retain_authenticated_availability_response_v2(request)?;
            return self.dispose_acknowledged_no_apply_v2(request);
        }
        if request.method() == BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
            && self.argument_stages[0].as_ref().is_some_and(|stage|
                stage.lock().is_ok_and(|capture| capture.availability.is_some()))
        {
            return self.retain_authenticated_availability_preparation_v2(request);
        }
        if request.method() == BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
            && request.host_execution_query_data_v3().and_then(|query| query.monitor_v3()).is_some() {
            return self.retire_authenticated_execution_query_v3(request);
        }
        if request.method() == BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME {
            return self.retain_authenticated_launch_response_v2(request);
        }
        if request.method() == BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION {
            return self.retire_authenticated_accepted_execution_v2(request);
        }
        let index = match request.method() {
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 => 0,
            BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => 1,
            _ => return Err(HostError::Fence("Host argument completion purpose differs")),
        };
        let stage = self.argument_stages[index].as_ref()
            .ok_or(HostError::Fence("Host argument completed native stage is absent"))?;
        {
            let capture = stage.lock().map_err(|_| HostError::Fence("Host argument stage is poisoned"))?;
            if capture.request != (request.method(), request.request_id(), request.session_binding(),
                    request.signed_request_digest())
                || capture.before.as_ref().is_none_or(|result| result.is_err())
                || capture.after.as_ref().is_none_or(|result| result.is_err())
                || capture.primary.is_some()
            {
                return Err(HostError::Fence("Host argument completion differs from its native interval"));
            }
        }
        let original = self.component_control.as_ref().cloned()
            .ok_or(HostError::Fence("Host argument intrinsic original is absent"))?;
        let mut original = original.lock()
            .map_err(|_| HostError::Fence("Host argument intrinsic original is poisoned"))?;
        if index == 1 {
            let mut capture = stage.lock()
                .map_err(|_| HostError::Fence("Host accepted native stage is poisoned"))?;
            if capture.authenticated || capture.accepted.is_none()
                || capture.argument.as_ref().and_then(|opening|
                    opening.completed_original_cutoff_v2().ok()).is_none()
            {
                return Err(HostError::Fence("Host accepted live original is unavailable"));
            }
            original.retain_authenticated_accept_v2(request)?;
            // SAME native four-journal/fifth/Guest/clock/State capsule moves
            // into the still-consumed20 lifetime. No reopen or proof remint.
            capture.authenticated = true;
            return Ok(());
        }
        let stage = self.argument_stages[index].take()
            .ok_or(HostError::Fence("Host argument native stage disappeared"))?;
        let capsule = match Arc::try_unwrap(stage) {
            Ok(capsule) => capsule,
            Err(stage) => {
                self.argument_stages[index] = Some(stage);
                return Err(HostError::Fence("Host argument positive native custody remains aliased"));
            }
        };
        drop(capsule);
        original.retire_authenticated_argument_v2(request)?;
        if let Some(launch) = self.launch_original.as_ref() {
            let mut launch = launch.lock().map_err(|_| HostError::Fence("Host transition Launch is poisoned"))?;
            launch.retire_next_execution_preparation_v5(request)?;
        }
        Ok(())
    }
}

/// Holds the actual Host stage and intrinsic original while inspecting a cause.
///
/// This read-only view neither extracts native custody nor settles a flight.
/// The locks follow the production original-then-stage acquisition order.
pub struct HostArgumentFailureViewV2<'broker> {
    original: MutexGuard<'broker, crate::plan::HostComponentControlStartupV2>,
    stage: MutexGuard<'broker, ArgumentStageOriginalV2>,
}

enum ArgumentCauseBorrowV2<'view> {
    Direct(&'view (dyn std::error::Error + 'view)),
    StateWrite(MutexGuard<'view, ArgumentStateWritesV2>),
}

/// Keeps the actual selected native cause borrowed without cloning its error.
pub struct HostArgumentFailureCauseV2<'view> {
    inner: ArgumentCauseBorrowV2<'view>,
}

impl<'view> HostArgumentFailureCauseV2<'view> {
    fn direct(cause: &'view (dyn std::error::Error + 'view)) -> Self {
        Self { inner: ArgumentCauseBorrowV2::Direct(cause) }
    }

    /// Borrows the actual cause while all required owner locks remain held.
    #[must_use]
    pub fn failure(&self) -> Option<&dyn std::error::Error> {
        match &self.inner {
            ArgumentCauseBorrowV2::Direct(cause) => Some(*cause),
            ArgumentCauseBorrowV2::StateWrite(writes) => writes.slots.iter()
                .take(writes.used).find_map(HostStateWriteAttemptV2::failure),
        }
    }
}

impl HostArgumentFailureViewV2<'_> {
    /// Borrows the first actual failed frontier ahead of later owed posts.
    ///
    /// # Errors
    /// Returns an unavailable-diagnostics error if the retained write lock is
    /// poisoned. No error or native owner is cloned or extracted.
    pub fn cause(&self) -> Result<Option<HostArgumentFailureCauseV2<'_>>> {
        let stage = &*self.stage;
        if let Some(accepted) = stage.accepted.as_ref() {
            if accepted.failed_intrinsic_v2() {
                return Ok(Some(HostArgumentFailureCauseV2::direct(self.original.failure())));
            }
            if let Some(writes) = accepted.failed_writes_v2() {
                let writes = writes.lock()
                    .map_err(|_| HostError::Fence("Host accepted State diagnostics are poisoned"))?;
                if writes.failure().is_some() {
                    return Ok(Some(HostArgumentFailureCauseV2 {
                        inner: ArgumentCauseBorrowV2::StateWrite(writes),
                    }));
                }
            }
            if accepted.failed_primary_v2() {
                if let Some(cause) = stage.owner.as_ref().and_then(DormantRuntimeExecutionOwnerV1::accepted_execution_native_failure_v2) {
                    return Ok(Some(HostArgumentFailureCauseV2::direct(cause)));
                }
            }
            if let Some(cause) = accepted.failure() {
                return Ok(Some(HostArgumentFailureCauseV2::direct(cause)));
            }
        }
        let cause = match stage.first {
            Some(ArgumentFirstV2::Before | ArgumentFirstV2::After) => Some(self.original.failure()),
            Some(ArgumentFirstV2::Clock) => stage.clock_error().or_else(|| stage.primary_error()),
            Some(ArgumentFirstV2::Opening) => stage.opening.failure().or_else(|| stage.primary_error()),
            Some(ArgumentFirstV2::Fifth) => stage.argument.as_ref()
                .and_then(HostArgumentAttemptOpeningV2::failure).or_else(|| stage.primary_error()),
            Some(ArgumentFirstV2::Primary) => {
                // Body failures stop immediately. A failed clock, fifth IO or
                // State write cannot be followed by another primary operation;
                // their actual native cause precedes the returned projection.
                if let Some(cause) = stage.clock_error().or_else(|| stage.argument.as_ref()
                    .and_then(HostArgumentAttemptOpeningV2::failure))
                {
                    return Ok(Some(HostArgumentFailureCauseV2::direct(cause)));
                }
                let writes = stage.writes.lock()
                    .map_err(|_| HostError::Fence("Host argument retained State diagnostics are poisoned"))?;
                if writes.slots.iter().take(writes.used).any(|write| write.failure().is_some()) {
                    return Ok(Some(HostArgumentFailureCauseV2 {
                        inner: ArgumentCauseBorrowV2::StateWrite(writes),
                    }));
                }
                stage.owner.as_ref().and_then(DormantRuntimeExecutionOwnerV1::accepted_execution_native_failure_v2)
                    .or_else(|| stage.future_append.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn std::error::Error + 'static)))
                    .or_else(|| stage.primary_error())
            },
            Some(ArgumentFirstV2::NativeFinish) => stage.native_finish.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            None => None,
        };
        Ok(cause.map(HostArgumentFailureCauseV2::direct))
    }
}

impl<C: crate::plan::HostCatalog, S: HostStateStore, W: crate::worker::HostWorker> super::HostBroker<C, S, W> {
    /// Locks the resident stage for the exact Prepare or Accept purpose.
    ///
    /// The method is comparison DATA only. This port issues no authority,
    /// retry, positive completion, financial loan or owner extraction.
    ///
    /// # Errors
    /// Rejects other methods, missing intrinsic custody or poisoned owner locks.
    pub fn argument_failure_view_v2(&self, method: BrokerMethod)
        -> Result<Option<HostArgumentFailureViewV2<'_>>>
    {
        let index = match method {
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
                | BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
                | BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                | BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
                | BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 => 0,
            BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2
                | BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION => 1,
            _ => return Err(HostError::Fence("Host argument diagnostic purpose is unavailable")),
        };
        let Some(stage) = self.argument_stages[index].as_ref() else { return Ok(None); };
        let original = self.component_control.as_ref()
            .ok_or(HostError::Fence("Host argument intrinsic diagnostics are absent"))?
            .lock().map_err(|_| HostError::Fence("Host argument intrinsic diagnostics are poisoned"))?;
        let stage = stage.lock()
            .map_err(|_| HostError::Fence("Host argument stage diagnostics are poisoned"))?;
        Ok(Some(HostArgumentFailureViewV2 { original, stage }))
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;

    #[test]
    fn absolute_cutoff_never_becomes_a_fresh_relative_timeout() {
        let instant = Instant::now();
        let first = deadline_from_boottime_v2(instant, 10, 100).unwrap();
        let delayed = deadline_from_boottime_v2(instant, 99, 100).unwrap();

        assert_eq!(first.duration_since(instant), Duration::from_nanos(90));
        assert_eq!(delayed.duration_since(instant), Duration::from_nanos(1));
        assert!(deadline_from_boottime_v2(instant, 100, 100).is_err());
        assert!(deadline_from_boottime_v2(instant, 101, 100).is_err());
    }

    #[test]
    fn renewed_accept_header_cannot_extend_original_source_cutoff() {
        assert!(require_original_cutoff_v2(100, 200, 100).is_err());
        assert!(require_original_cutoff_v2(100, 200, 101).is_err());
        assert_eq!(require_original_cutoff_v2(100, 200, 99).unwrap(), 100);
        assert_eq!(require_original_cutoff_v2(200, 100, 99).unwrap(), 100);
    }

    #[test]
    fn finite_clock_schedule_owns_each_reached_frontier_and_semantic_sample() {
        // One original-source check before await; four prepare/replay pairs;
        // Accept's fifth prepare/replay pair; existing semantic/Guest maxfive.
        assert_eq!(FRONTIER_DEADLINES, 1 + 2 * 4 + 2);
        assert_eq!(CLOCK_SAMPLES_PER_STAGE, FRONTIER_DEADLINES + 5);
        assert_eq!(MAXIMUM_CLOCK_SAMPLES, 8 * CLOCK_SAMPLES_PER_STAGE);
        assert!(CLOCK_PAIRS * 2 >= MAXIMUM_CLOCK_SAMPLES);
    }
}

#[cfg(test)]
mod argument_clock_disposal_tests {
    use super::*;

    #[test]
    fn positive_clock_files_retire_with_full_schedule_and_no_sample_reuse() {
        let boot = aos_sandbox_linux::boot::KernelBootId::current().unwrap().into_bytes();
        let mut clock = ArgumentClockV2::capture(boot);
        let demand = ArgumentClockV2::receiving_demand_v2().unwrap();
        assert_eq!(demand.get(aos_sandbox_core::ResourceDimension::OpenFiles), 3);
        let mut last = 0;
        for next in [None,
            Some(BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT),
            Some(BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT),
            Some(BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2),
            Some(BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2)] {
            if let Some(next) = next { clock.advance_argument_stage_v2(next).unwrap(); }
            for _ in 0..CLOCK_SAMPLES_PER_STAGE {
                let sample = clock.sample().unwrap();
                assert!(sample.boottime_nanoseconds() >= last);
                last = sample.boottime_nanoseconds();
            }
        }
        assert!(clock.sample().is_err());
        assert_eq!(clock.used, 5 * CLOCK_SAMPLES_PER_STAGE);
        assert!(clock.failure().is_some());
        assert!(clock.sample().is_err());
        assert_eq!(clock.used, 5 * CLOCK_SAMPLES_PER_STAGE);
    }

    #[test]
    fn per_phase_clock_exhaustion_keeps_cause_and_cannot_reenter_or_advance() {
        let boot = aos_sandbox_linux::boot::KernelBootId::current().unwrap().into_bytes();
        let mut clock = ArgumentClockV2::capture(boot);
        assert!(clock.advance_argument_stage_v2(
            BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2).is_err());
        for _ in 0..CLOCK_SAMPLES_PER_STAGE { clock.sample().unwrap(); }

        assert!(clock.sample().is_err());
        let first = clock.failure().unwrap() as *const dyn std::error::Error;
        assert!(clock.advance_argument_stage_v2(
            BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT).is_err());
        assert!(clock.sample().is_err());

        assert_eq!(clock.used, CLOCK_SAMPLES_PER_STAGE);
        assert_eq!(clock.stage, 0);
        assert!(std::ptr::eq(first, clock.failure().unwrap()));
    }

    #[test]
    fn launch_write_samples_share_the_baseline_without_spending_ordinary_slots() {
        let boot = aos_sandbox_linux::boot::KernelBootId::current().unwrap().into_bytes();
        let mut clock = ArgumentClockV2::capture_launch_v2(boot);
        let mut last = clock.sample().unwrap().boottime_nanoseconds();

        for _ in 0..LAUNCH_WRITE_SAMPLES {
            let sample = clock.sample_launch_write_v2().unwrap();
            assert!(sample.boottime_nanoseconds() >= last);
            last = sample.boottime_nanoseconds();
        }

        assert_eq!(clock.used, 1);
        assert_eq!(clock.launch_writes.as_ref().unwrap().used, LAUNCH_WRITE_SAMPLES);
        assert!(clock.sample_launch_write_v2().is_err());
        let first = clock.failure().unwrap().downcast_ref::<HostError>().unwrap() as *const _;
        assert!(clock.sample_launch_write_v2().is_err());
        assert_eq!(clock.failure().unwrap().downcast_ref::<HostError>().unwrap() as *const _, first);
        assert_eq!(clock.used, 1);
        assert_eq!(clock.launch_writes.as_ref().unwrap().used, LAUNCH_WRITE_SAMPLES);
    }

    #[test]
    fn early_terminal_branch_spends_existing_slots_and_cannot_adopt_prepared_argument() {
        let boot = aos_sandbox_linux::boot::KernelBootId::current()
            .unwrap()
            .into_bytes();
        let mut clock = ArgumentClockV2::capture(boot);
        for method in [
            None,
            Some(BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT),
            Some(BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT),
        ] {
            if let Some(method) = method {
                clock.advance_argument_stage_v2(method).unwrap();
            }
            for _ in 0..CLOCK_SAMPLES_PER_STAGE {
                clock.sample().unwrap();
            }
        }
        clock
            .advance_argument_stage_v2(BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY)
            .unwrap();
        for _ in 0..CLOCK_SAMPLES_PER_STAGE {
            clock.sample().unwrap();
        }

        assert_eq!(clock.used, 4 * CLOCK_SAMPLES_PER_STAGE);
        assert!(clock.used < MAXIMUM_CLOCK_SAMPLES);
        assert!(
            clock
                .advance_argument_stage_v2(BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY)
                .is_err()
        );
        assert!(
            clock
                .advance_argument_stage_v2(
                    BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
                )
                .is_err()
        );
        assert!(clock.sample().is_err());

        let mut prepared = ArgumentClockV2::capture(boot);
        for method in [
            BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT,
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT,
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2,
        ] {
            prepared.advance_argument_stage_v2(method).unwrap();
        }
        assert!(
            prepared
                .advance_argument_stage_v2(BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY)
                .is_err()
        );
        assert_eq!(prepared.stage, 3);
    }

    #[test]
    fn mismatched_boot_retains_failure_and_blocks_new_native_samples() {
        let mut clock = ArgumentClockV2::capture([0; 16]);
        assert!(clock.sample().is_err());
        assert_eq!(clock.used, 1);
        let cause = clock.failure().unwrap() as *const dyn std::error::Error;
        assert!(clock.sample().is_err());
        assert_eq!(clock.used, 1);
        assert!(std::ptr::eq(cause, clock.failure().unwrap()));
    }

    #[test]
    fn held_cleanup_consumes_one_eight_phase_clock_and_cannot_reenter_after_ack() {
        let boot = aos_sandbox_linux::boot::KernelBootId::current().unwrap().into_bytes();
        let mut clock = ArgumentClockV2::capture(boot);
        let mut last = 0;
        let methods = [None,
            Some(BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT),
            Some(BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT),
            Some(BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY),
            Some(BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2),
            Some(BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2),
            Some(BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2),
            Some(BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2)];
        for method in methods {
            if let Some(method) = method { clock.advance_argument_stage_v2(method).unwrap(); }
            for _ in 0..CLOCK_SAMPLES_PER_STAGE {
                let sample = clock.sample().unwrap();
                assert!(sample.boottime_nanoseconds() >= last);
                last = sample.boottime_nanoseconds();
            }
        }

        assert_eq!(clock.used, MAXIMUM_CLOCK_SAMPLES);
        assert_eq!(clock.stage, 9);
        assert!(clock.advance_argument_stage_v2(BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2).is_err());
        assert!(clock.advance_argument_stage_v2(BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2).is_err());
        assert!(clock.sample().is_err());
        assert_eq!(clock.used, MAXIMUM_CLOCK_SAMPLES);
    }

    #[test]
    fn fresh_cleanup_has_only_four_new_phases_without_execution_frontiers() {
        let boot = aos_sandbox_linux::boot::KernelBootId::current()
            .unwrap()
            .into_bytes();
        let mut clock = ArgumentClockV2::capture_cleanup_v2(boot);

        for method in [
            BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT,
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT,
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2,
            BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2,
            BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
        ] {
            assert!(clock.advance_argument_stage_v2(method).is_err());
        }
        for method in [
            None,
            Some(BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2),
            Some(BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2),
            Some(BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2),
        ] {
            if let Some(method) = method {
                clock.advance_argument_stage_v2(method).unwrap();
            }
            for _ in 0..CLOCK_SAMPLES_PER_STAGE {
                clock.sample().unwrap();
            }
        }

        assert_eq!(clock.used, 4 * CLOCK_SAMPLES_PER_STAGE);
        assert_eq!(clock.stage, 9);
        assert!(
            clock
                .advance_argument_stage_v2(BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2)
                .is_err()
        );
        assert!(clock.sample().is_err());
    }
}
