//! Fixed kernel-clock mechanics for protected ownership observations.
//!
//! The sampler returns untrusted raw DATA. Each retained authority owner still
//! validates the sample against its own admitted effect and session custody.

use aos_sandbox::ownership_resume::OwnershipClockObservationError;
use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;

/// Names the unchanged raw ownership-clock observation provenance.
pub(crate) const CLOCK_PROVENANCE: [u8; 16] = *b"AOSOWNCTRLCLKV1!";

/// Samples paired host clocks without accepting clock facts from a caller.
///
/// # Errors
///
/// Returns an error if the boot identity cannot be read or changes across the
/// samples, elapsed time is unrepresentable, or raw sample validation fails.
pub(crate) fn sample_ownership_clock() -> Result<RawPairedClockSample, OwnershipClockObservationError> {
    let boot_before = KernelBootId::current()
        .map_err(|_| OwnershipClockObservationError)?
        .into_bytes();
    let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let boot_after = KernelBootId::current()
        .map_err(|_| OwnershipClockObservationError)?
        .into_bytes();

    if boot_before != boot_after {
        return Err(OwnershipClockObservationError);
    }

    let seconds = u64::try_from(boottime.tv_sec).map_err(|_| OwnershipClockObservationError)?;
    let nanoseconds =
        u64::try_from(boottime.tv_nsec).map_err(|_| OwnershipClockObservationError)?;
    let boottime_nanoseconds = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(OwnershipClockObservationError)?;

    let provenance = RawClockProvenance::new_untrusted(CLOCK_PROVENANCE)
        .map_err(|_| OwnershipClockObservationError)?;
    RawPairedClockSample::new_untrusted(
        provenance,
        boot_before,
        realtime.tv_sec,
        boottime_nanoseconds,
    )
    .map_err(|_| OwnershipClockObservationError)
}
