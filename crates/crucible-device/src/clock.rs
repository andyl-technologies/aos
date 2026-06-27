//! The icount-derived virtual clock and the fixed-shift time conversions.
//!
//! An I/O sub-node has no host clock. Its only notion of time is an `icount`
//! advanced exclusively by the authoritative scheduler ([IO-1]). This module
//! owns [`VirtualClock`] — the monotonic, scheduler-driven icount cursor — and
//! the two halves of the fixed-shift virtual-time map:
//!
//! - icount to nanoseconds, reused from `crucible-shmem`
//!   ([`crucible_shmem::icount_to_virtual_ns`]);
//! - nanoseconds to icount, the [TIME-4] *ceil* map implemented here as
//!   [`ceil_ns_to_icount`]: the smallest icount whose virtual-nanosecond view is
//!   at or above the target.
//!
//! Both directions are pure functions of `(value, shift_bits)`; no host
//! wall-clock ever participates.
//!
//! ```text
//! virtual_ns(icount)      = icount << shift_bits
//! ceil_ns_to_icount(ns)   = smallest icount with (icount << shift_bits) >= ns
//!                         = (ns + (1 << shift_bits) - 1) >> shift_bits   (no overflow)
//! ```

use crucible_shmem::icount_to_virtual_ns;

use crate::error::DeviceError;

/// The fixed-shift virtual clock of an I/O sub-node.
///
/// The clock carries the sub-node's current `icount` and the `shift_bits` that
/// define the icount-to-nanosecond map for the whole simulation. It advances
/// only through [`VirtualClock::advance_to`], which the scheduler calls; the
/// sub-node never advances its own clock and never reads host time ([IO-1]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualClock {
    current_icount: u64,
    shift_bits: u8,
}

impl VirtualClock {
    /// Creates a clock at icount zero with the given fixed shift.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Clock`] when `shift_bits >= 64`, surfaced by the
    /// first virtual-time conversion the clock performs at construction.
    pub fn new(shift_bits: u8) -> Result<Self, DeviceError> {
        // Validate the shift eagerly so later conversions cannot surprise.
        // `icount_to_virtual_ns` rejects `shift_bits >= 64`, so this is the only
        // guard the constructor needs.
        let _ = icount_to_virtual_ns(0, shift_bits)?;
        Ok(Self {
            current_icount: 0,
            shift_bits,
        })
    }

    /// Returns the sub-node's current icount.
    #[must_use]
    pub fn current_icount(&self) -> u64 {
        self.current_icount
    }

    /// Returns the fixed virtual-time shift in bits.
    #[must_use]
    pub fn shift_bits(&self) -> u8 {
        self.shift_bits
    }

    /// Returns the current virtual time in nanoseconds.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Clock`] when the shifted nanosecond value
    /// overflows `u64`.
    pub fn current_ns(&self) -> Result<u64, DeviceError> {
        Ok(icount_to_virtual_ns(self.current_icount, self.shift_bits)?)
    }

    /// Returns the virtual nanoseconds of an arbitrary icount under this shift.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Clock`] when the shifted nanosecond value
    /// overflows `u64`.
    pub fn virtual_ns(&self, icount: u64) -> Result<u64, DeviceError> {
        Ok(icount_to_virtual_ns(icount, self.shift_bits)?)
    }

    /// Maps a nanosecond instant to an icount with [TIME-4] ceil semantics.
    ///
    /// Returns the smallest icount whose virtual nanoseconds are at or above
    /// `target_ns`, under this clock's shift.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::IcountOverflow`] when the ceil result would
    /// overflow `u64`. The [`DeviceError::Clock`] (`InvalidShift`) condition of
    /// the free [`ceil_ns_to_icount`] function is unreachable here because the
    /// clock's `shift_bits` was validated at construction.
    pub fn ceil_ns_to_icount(&self, target_ns: u64) -> Result<u64, DeviceError> {
        ceil_ns_to_icount(target_ns, self.shift_bits)
    }

    /// Advances the clock to `limit_icount`, which must not move backward.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ClockRegression`] when `limit_icount` is strictly
    /// below the current icount.
    pub fn advance_to(&mut self, limit_icount: u64) -> Result<(), DeviceError> {
        if limit_icount < self.current_icount {
            return Err(DeviceError::ClockRegression {
                current_icount: self.current_icount,
                limit_icount,
            });
        }
        self.current_icount = limit_icount;
        Ok(())
    }
}

/// Maps a nanosecond instant to the ceil icount under a fixed shift.
///
/// This is the standalone [TIME-4] ceil map: the smallest `icount` such that
/// `icount << shift_bits >= target_ns`. The division is computed as
/// `(target_ns + (1 << shift_bits) - 1) >> shift_bits` with each step guarded
/// against `u64` overflow.
///
/// # Errors
///
/// Returns [`DeviceError::Clock`] (via [`crucible_shmem::NodeSlotError::InvalidShift`])
/// when `shift_bits >= 64`, and [`DeviceError::IcountOverflow`] when the
/// rounding addition overflows `u64`.
pub fn ceil_ns_to_icount(target_ns: u64, shift_bits: u8) -> Result<u64, DeviceError> {
    if shift_bits >= 64 {
        return Err(DeviceError::Clock {
            source: crucible_shmem::NodeSlotError::InvalidShift { shift_bits },
        });
    }
    if shift_bits == 0 {
        // One nanosecond per icount: the icount is the nanosecond value itself.
        return Ok(target_ns);
    }
    let nanos_per_icount = 1_u64 << shift_bits;
    // ceil(target_ns / nanos_per_icount) without floating point. The bias is
    // `nanos_per_icount - 1`; the addition may overflow for ns near u64::MAX.
    let biased =
        target_ns
            .checked_add(nanos_per_icount - 1)
            .ok_or(DeviceError::IcountOverflow {
                target_ns,
                shift_bits,
            })?;
    Ok(biased >> shift_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unwraps a result in tests, panicking with the error on failure.
    fn ok<T>(result: Result<T, DeviceError>) -> T {
        result.unwrap_or_else(|error| panic!("expected Ok, got {error}"))
    }

    #[test]
    fn ceil_rounds_up_partial_icounts() {
        // shift 4 => 16 ns per icount.
        assert_eq!(ok(ceil_ns_to_icount(0, 4)), 0);
        assert_eq!(ok(ceil_ns_to_icount(1, 4)), 1);
        assert_eq!(ok(ceil_ns_to_icount(16, 4)), 1);
        assert_eq!(ok(ceil_ns_to_icount(17, 4)), 2);
        assert_eq!(ok(ceil_ns_to_icount(32, 4)), 2);
    }

    #[test]
    fn ceil_is_inverse_floor_of_icount_to_ns() {
        let shift = 8;
        for icount in [0_u64, 1, 7, 1000, 1 << 20] {
            let ns = ok(icount_to_virtual_ns(icount, shift).map_err(DeviceError::from));
            assert_eq!(ok(ceil_ns_to_icount(ns, shift)), icount);
            // One ns past the exact boundary rounds to the next icount.
            assert_eq!(ok(ceil_ns_to_icount(ns + 1, shift)), icount + 1);
        }
    }

    #[test]
    fn ceil_shift_zero_is_identity() {
        assert_eq!(ok(ceil_ns_to_icount(0, 0)), 0);
        assert_eq!(ok(ceil_ns_to_icount(12345, 0)), 12345);
        assert_eq!(ok(ceil_ns_to_icount(u64::MAX, 0)), u64::MAX);
    }

    #[test]
    fn ceil_overflow_is_an_error_not_a_panic() {
        assert!(matches!(
            ceil_ns_to_icount(u64::MAX, 4),
            Err(DeviceError::IcountOverflow { .. })
        ));
    }

    #[test]
    fn clock_advances_forward_only() {
        let mut clock = ok(VirtualClock::new(8));
        assert_eq!(clock.current_icount(), 0);
        ok(clock.advance_to(100));
        assert_eq!(clock.current_icount(), 100);
        ok(clock.advance_to(100));
        assert_eq!(clock.current_icount(), 100);
        assert!(matches!(
            clock.advance_to(99),
            Err(DeviceError::ClockRegression { .. })
        ));
    }

    #[test]
    fn invalid_shift_is_rejected() {
        assert!(matches!(
            VirtualClock::new(64),
            Err(DeviceError::Clock { .. })
        ));
        assert!(matches!(
            ceil_ns_to_icount(0, 64),
            Err(DeviceError::Clock { .. })
        ));
    }
}
