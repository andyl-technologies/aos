//! Kernel BOOTTIME sampling shared by Mount admission and helper effects.

use crate::{MountError, Result};

/// Reads nonnegative BOOTTIME nanoseconds with the Mount state error contract.
pub(crate) fn boottime_nanoseconds() -> Result<u64> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| MountError::State("CLOCK_BOOTTIME returned negative seconds".to_owned()))?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| {
        MountError::State("CLOCK_BOOTTIME returned negative nanoseconds".to_owned())
    })?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| MountError::State("CLOCK_BOOTTIME overflowed u64".to_owned()))
}
