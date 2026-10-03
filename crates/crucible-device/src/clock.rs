//! Exact logical-tick clock for deterministic I/O sub-nodes.
//!
//! One nanosecond contains [`TICKS_PER_NS`] logical ticks. Integer-nanosecond
//! values are boundary or display values; device completion ordering uses the
//! exact tick that the scheduler supplies. An interval adds ticks to the exact
//! request coordinate, preserving its fractional phase.

use crucible_shmem::{TICKS_PER_NS, icount_to_virtual_ns};

use crate::error::DeviceError;

/// A scheduler-driven logical-tick cursor for an I/O sub-node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualClock {
    current_icount: u64,
}

impl VirtualClock {
    /// Creates a clock at the simulation epoch.
    #[must_use]
    pub const fn new() -> Self {
        Self { current_icount: 0 }
    }

    /// Returns the current exact logical tick.
    #[must_use]
    pub const fn current_icount(&self) -> u64 {
        self.current_icount
    }

    /// Returns the integer-nanosecond projection of the current tick.
    #[must_use]
    pub const fn current_ns(&self) -> u64 {
        icount_to_virtual_ns(self.current_icount)
    }

    /// Returns the integer-nanosecond projection of an exact tick.
    #[must_use]
    pub const fn virtual_ns(&self, icount: u64) -> u64 {
        icount_to_virtual_ns(icount)
    }

    /// Maps an absolute integer-nanosecond boundary to its exact tick.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::IcountOverflow`] when the boundary exceeds `u64`.
    pub fn ns_to_tick(&self, target_ns: u64) -> Result<u64, DeviceError> {
        ns_to_tick(target_ns)
    }

    /// Adds a nanosecond interval to an exact tick without discarding its phase.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::CompletionOverflow`] when the result exceeds `u64`.
    pub fn add_ns(&self, request_icount: u64, latency_ns: u64) -> Result<u64, DeviceError> {
        let latency_ticks =
            latency_ns
                .checked_mul(TICKS_PER_NS)
                .ok_or(DeviceError::CompletionOverflow {
                    request_icount,
                    latency_ns,
                })?;
        request_icount
            .checked_add(latency_ticks)
            .ok_or(DeviceError::CompletionOverflow {
                request_icount,
                latency_ns,
            })
    }

    /// Adds an exact tick interval without changing the clock phase.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::TickOverflow`] when the result exceeds `u64`.
    pub fn add_ticks(&self, base_tick: u64, delta_ticks: u64) -> Result<u64, DeviceError> {
        base_tick
            .checked_add(delta_ticks)
            .ok_or(DeviceError::TickOverflow {
                base_tick,
                delta_ticks,
            })
    }

    /// Advances the cursor to `limit_icount`, which must not move backward.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ClockRegression`] when the limit is behind the cursor.
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

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps an absolute integer-nanosecond boundary to its exact logical tick.
///
/// # Errors
///
/// Returns [`DeviceError::IcountOverflow`] when the scaled tick exceeds `u64`.
pub fn ns_to_tick(target_ns: u64) -> Result<u64, DeviceError> {
    target_ns
        .checked_mul(TICKS_PER_NS)
        .ok_or(DeviceError::IcountOverflow { target_ns })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nanosecond_projection_preserves_fractional_phase() {
        let clock = VirtualClock::new();
        assert_eq!(clock.virtual_ns(7), 0);
        assert_eq!(clock.virtual_ns(999), 0);
        assert_eq!(clock.virtual_ns(1_000), 1);
        assert_eq!(clock.virtual_ns(1_001), 1);
        assert_eq!(clock.ns_to_tick(2), Ok(2_000));
        assert_eq!(clock.add_ns(7, 1), Ok(1_007));
        assert_eq!(clock.add_ns(1_001, 1), Ok(2_001));
    }

    #[test]
    fn tick_arithmetic_rejects_overflow() {
        let clock = VirtualClock::new();
        assert!(matches!(
            ns_to_tick(u64::MAX),
            Err(DeviceError::IcountOverflow { .. })
        ));
        assert!(matches!(
            clock.add_ns(u64::MAX, 1),
            Err(DeviceError::CompletionOverflow { .. })
        ));
    }

    #[test]
    fn clock_advances_forward_only() {
        let mut clock = VirtualClock::new();
        assert_eq!(clock.advance_to(1_001), Ok(()));
        assert_eq!(clock.current_icount(), 1_001);
        assert_eq!(clock.current_ns(), 1);
        assert!(matches!(
            clock.advance_to(1_000),
            Err(DeviceError::ClockRegression { .. })
        ));
    }
}
