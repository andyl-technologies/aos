//! Samples the existing boot-bookended kernel pair without role authority.
//!
//! Role owners retain their own error classes through the small diagnostic
//! adapter. The native observation and retirement order is implemented once;
//! it admits no work and owns no account, lease, key or signing permission.

use std::error::Error;

use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_linux::boot::{KernelBootId, RootOriginalKernelBootIdAttemptV1};
use rustix::time::{ClockId, Timespec, clock_gettime};

/// Projects only clock diagnostics into an existing role's error class.
///
/// Implementing this interface cannot supply a clock observation, financial
/// admission, original identity or positive disposition.
pub trait KernelPairedClockErrorV1: Error + 'static {
    /// Returns the role's established stale-clock diagnostic.
    fn stale() -> Self;

    /// Preserves the actual owning native error at an ordinary boundary.
    fn kernel(error: aos_sandbox_linux::Error) -> Self;
}

/// Samples BOOTTIME and realtime between two kernel boot observations.
///
/// # Errors
/// Preserves the actual kernel error or the role's stale-pair diagnostic.
pub fn ordinary_kernel_pair<E: KernelPairedClockErrorV1>() -> Result<RawPairedClockSample, E> {
    let before = KernelBootId::current().map_err(E::kernel)?.into_bytes();
    let boot = clock_gettime(ClockId::Boottime);
    let wall = clock_gettime(ClockId::Realtime).tv_sec;
    let after = KernelBootId::current().map_err(E::kernel)?.into_bytes();
    pair_from_observations::<E>(before, boot, wall, after)
}

/// Converts already-observed kernel values into untrusted clock DATA.
///
/// # Errors
/// Refuses changed boots, invalid time values or invalid raw-clock DATA.
pub fn pair_from_observations<E: KernelPairedClockErrorV1>(before: [u8; 16], boot: Timespec, wall: i64, after: [u8; 16])
    -> Result<RawPairedClockSample, E>
{
    if before != after {
        return Err(E::stale());
    }
    let boot = u64::try_from(boot.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(boot.tv_nsec)
                .ok()
                .and_then(|fraction| seconds.checked_add(fraction))
        })
        .ok_or(E::stale())?;
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"aos-kernel-clock")
            .map_err(|_| E::stale())?,
        before,
        wall,
        boot,
    )
    .map_err(|_| E::stale())
}

/// Compares an observed pair with the original strict 65-second interval.
///
/// # Errors
/// Refuses a changed boot, invalid wall/boot progression or expired interval.
pub fn require_original_clock<E: KernelPairedClockErrorV1>(original: Option<RawPairedClockSample>, current: RawPairedClockSample)
    -> Result<RawPairedClockSample, E>
{
    if let Some(original) = original {
        original.validate_later_sample(current)
            .map_err(|_| E::stale())?;
        let deadline = original.boottime_nanoseconds().checked_add(65_000_000_000)
            .ok_or(E::stale())?;
        if current.boottime_nanoseconds() >= deadline {
            return Err(E::stale());
        }
    }
    Ok(current)
}

/// Keeps one selected native pair and its complete first-cause destination.
pub struct RetainedKernelPairedClockAttemptV1<E> {
    before: RootOriginalKernelBootIdAttemptV1,
    after: RootOriginalKernelBootIdAttemptV1,
    before_value: Option<Result<[u8; 16], E>>,
    before_retired: Option<Result<(), E>>,
    boottime: Option<Timespec>,
    realtime: Option<Timespec>,
    after_value: Option<Result<[u8; 16], E>>,
    after_retired: Option<Result<(), E>>,
    result: Option<Result<RawPairedClockSample, E>>,
    reentry: Option<E>,
    entered: bool,
}

impl<E> Default for RetainedKernelPairedClockAttemptV1<E> {
    fn default() -> Self {
        Self {
            before: RootOriginalKernelBootIdAttemptV1::default(),
            after: RootOriginalKernelBootIdAttemptV1::default(),
            before_value: None, before_retired: None, boottime: None, realtime: None,
            after_value: None, after_retired: None, result: None, reentry: None,
            entered: false,
        }
    }
}

impl<E: KernelPairedClockErrorV1> RetainedKernelPairedClockAttemptV1<E> {
    // Includes both typed reservoirs; caller inline geometry may already count
    // them, but explicitly paying this fixed bound avoids hidden partial debt.
    /// Returns the fixed native reservoirs and bounded parser diagnostics.
    pub fn dominant_requested_bytes_v1() -> Option<usize> {
        let reader = RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?;
        let dynamic = reader.checked_sub(std::mem::size_of::<RootOriginalKernelBootIdAttemptV1>())?;
        std::mem::size_of::<Self>().checked_add(dynamic.checked_mul(2)?)
    }

    /// Reports both fixed boot readers' namespace bounds without control fields.
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        // Pair results and the once-only latch remain in measured byte storage.
        RootOriginalKernelBootIdAttemptV1::receiving_metadata_cells_v1()
            .checked_mul(2)
    }

    // At most one failed boot file survives: every positive primitive file is
    // closed before the next step, while a failed step stops this pair.
    /// Maximum failed boot descriptors retained by one once-only pair.
    pub const MAXIMUM_RETAINED_FILES_V1: usize =
        RootOriginalKernelBootIdAttemptV1::MAXIMUM_RETAINED_FILES_V1;

    /// Samples once without replacing an earlier native or partial result.
    ///
    /// # Errors
    /// Retains boot acquisition, retirement, conversion, age or reentry failure.
    /// The caller's already-paid independent post uses a distinct destination.
    pub fn observe_once(&mut self, original: Option<RawPairedClockSample>)
        -> Result<RawPairedClockSample, E>
    {
        if self.entered {
            self.reentry.get_or_insert(E::stale());
            return Err(E::stale());
        }
        self.entered = true;
        self.result = Some(self.observe_inner(original));
        match self.result.as_ref() {
            Some(Ok(sample)) => Ok(*sample),
            _ => Err(E::stale()),
        }
    }

    fn observe_inner(&mut self, original: Option<RawPairedClockSample>)
        -> Result<RawPairedClockSample, E>
    {
        self.before_value = Some(self.before.observe_once().map(|boot| boot.into_bytes())
            .map_err(|_| E::stale()));
        let before = *self.before_value.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(E::stale())?;
        self.before_retired = Some(self.before.retire_positive_file_once()
            .map_err(|_| E::stale()));
        if !matches!(self.before_retired, Some(Ok(()))) { return Err(E::stale()); }

        self.boottime = Some(clock_gettime(ClockId::Boottime));
        self.realtime = Some(clock_gettime(ClockId::Realtime));
        self.after_value = Some(self.after.observe_once().map(|boot| boot.into_bytes())
            .map_err(|_| E::stale()));
        let after = *self.after_value.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(E::stale())?;
        self.after_retired = Some(self.after.retire_positive_file_once()
            .map_err(|_| E::stale()));
        if !matches!(self.after_retired, Some(Ok(()))) { return Err(E::stale()); }

        let boot = self.boottime.ok_or(E::stale())?;
        let wall = self.realtime.ok_or(E::stale())?.tv_sec;
        require_original_clock::<E>(original, pair_from_observations::<E>(before, boot, wall, after)?)
    }

    /// Borrows the exact realtime observation already retained by this attempt.
    ///
    /// This passive DATA includes the original subsecond fraction needed to
    /// derive a conservative native wait from an admitted WALL deadline. It
    /// performs no observation, conversion, interval extension or admission.
    #[must_use]
    pub fn realtime_observation_data_v1(&self) -> Option<Timespec> {
        self.realtime
    }

    /// Borrows the earliest reached original cause without new IO.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before.failure().or_else(|| error(&self.before_value))
            .or_else(|| error(&self.before_retired)).or_else(|| self.after.failure())
            .or_else(|| error(&self.after_value)).or_else(|| error(&self.after_retired))
            .or_else(|| error(&self.result))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}
