//! Exact virtual-clock deadline introspection.
//!
//! The raw QEMU plugin export returns a nanosecond deadline from
//! `QEMU_CLOCK_VIRTUAL`. This module models the fail-closed policy around that
//! export: the capability is required, realtime and host-clock sources are
//! rejected, and overshoot-and-correct is never an accepted fallback.

use thiserror::Error;

/// The required QEMU plugin extension symbol for exact timer deadlines.
pub const QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL: &str = "qemu_plugin_clock_deadline_ns";

/// The QEMU clock source used for a deadline query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClockDeadlineSource {
    /// The icount-derived virtual clock.
    QemuClockVirtual,
    /// QEMU realtime clock, which would reintroduce host timing.
    QemuClockRealtime,
    /// QEMU host clock, which would reintroduce host timing.
    QemuClockHost,
}

/// The fallback policy for an unavailable exact deadline capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeadlineFallbackPolicy {
    /// Fails the run loudly when the exact capability is unavailable.
    FailClosed,
    /// Guesses a wake point and corrects after observing whether the timer fired.
    OvershootAndCorrect,
}

/// A validated exact-deadline report from QEMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExactDeadlineReport {
    /// No virtual-clock guest timer is armed.
    NoArmedTimer,
    /// A virtual-clock guest timer is armed at this virtual nanosecond.
    Armed {
        /// The exact virtual nanosecond deadline from `QEMU_CLOCK_VIRTUAL`.
        deadline_ns: u64,
    },
}

/// A policy and capability check for exact deadline introspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExactDeadlineIntrospection {
    capability_available: bool,
    clock_source: ClockDeadlineSource,
    fallback_policy: DeadlineFallbackPolicy,
}

impl ExactDeadlineIntrospection {
    /// Builds an exact-deadline introspection policy.
    #[must_use]
    pub fn new(
        capability_available: bool,
        clock_source: ClockDeadlineSource,
        fallback_policy: DeadlineFallbackPolicy,
    ) -> Self {
        Self {
            capability_available,
            clock_source,
            fallback_policy,
        }
    }

    /// Returns the required fail-closed virtual-clock policy.
    #[must_use]
    pub fn required() -> Self {
        Self::new(
            true,
            ClockDeadlineSource::QemuClockVirtual,
            DeadlineFallbackPolicy::FailClosed,
        )
    }

    /// Validates that exact deadline introspection can be used.
    ///
    /// # Errors
    ///
    /// Returns [`ExactDeadlineError`] when the exact deadline capability is
    /// unavailable, the query would read a non-virtual QEMU clock, or the policy
    /// permits overshoot-and-correct.
    pub fn validate(self) -> Result<(), ExactDeadlineError> {
        if self.fallback_policy == DeadlineFallbackPolicy::OvershootAndCorrect {
            return Err(ExactDeadlineError::OvershootFallbackForbidden);
        }
        if !self.capability_available {
            return Err(ExactDeadlineError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL,
            });
        }
        if self.clock_source != ClockDeadlineSource::QemuClockVirtual {
            return Err(ExactDeadlineError::NonVirtualClockSource {
                clock_source: self.clock_source,
            });
        }
        Ok(())
    }

    /// Converts a raw QEMU deadline return value into a validated report.
    ///
    /// # Errors
    ///
    /// Returns [`ExactDeadlineError`] when [`Self::validate`] fails.
    pub fn report(self, raw_deadline_ns: i64) -> Result<ExactDeadlineReport, ExactDeadlineError> {
        self.validate()?;
        match u64::try_from(raw_deadline_ns) {
            Ok(deadline_ns) => Ok(ExactDeadlineReport::Armed { deadline_ns }),
            Err(_) => Ok(ExactDeadlineReport::NoArmedTimer),
        }
    }
}

/// An exact deadline introspection error.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ExactDeadlineError {
    /// The required QEMU plugin symbol is unavailable.
    #[error("required exact deadline capability `{symbol}` is unavailable")]
    CapabilityUnavailable {
        /// The missing QEMU plugin symbol.
        symbol: &'static str,
    },
    /// The deadline query would read a non-virtual QEMU clock.
    #[error("deadline query must use QEMU_CLOCK_VIRTUAL, got {clock_source:?}")]
    NonVirtualClockSource {
        /// The rejected clock source.
        clock_source: ClockDeadlineSource,
    },
    /// Overshoot-and-correct fallback was requested.
    #[error("overshoot-and-correct fallback is forbidden for exact deadlines")]
    OvershootFallbackForbidden,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_deadline_reports_virtual_timer_deadlines() {
        let introspection = ExactDeadlineIntrospection::required();

        assert_eq!(
            introspection.report(4096),
            Ok(ExactDeadlineReport::Armed { deadline_ns: 4096 })
        );
        assert_eq!(
            introspection.report(-1),
            Ok(ExactDeadlineReport::NoArmedTimer)
        );
    }

    #[test]
    fn exact_deadline_fails_when_capability_is_missing() {
        let introspection = ExactDeadlineIntrospection::new(
            false,
            ClockDeadlineSource::QemuClockVirtual,
            DeadlineFallbackPolicy::FailClosed,
        );

        assert_eq!(
            introspection.report(4096),
            Err(ExactDeadlineError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL,
            })
        );
    }

    #[test]
    fn exact_deadline_rejects_realtime_and_host_clock_sources() {
        for source in [
            ClockDeadlineSource::QemuClockRealtime,
            ClockDeadlineSource::QemuClockHost,
        ] {
            let introspection =
                ExactDeadlineIntrospection::new(true, source, DeadlineFallbackPolicy::FailClosed);

            assert_eq!(
                introspection.report(4096),
                Err(ExactDeadlineError::NonVirtualClockSource {
                    clock_source: source,
                })
            );
        }
    }

    #[test]
    fn exact_deadline_rejects_overshoot_and_correct_fallback() {
        let introspection = ExactDeadlineIntrospection::new(
            true,
            ClockDeadlineSource::QemuClockVirtual,
            DeadlineFallbackPolicy::OvershootAndCorrect,
        );

        assert_eq!(
            introspection.report(4096),
            Err(ExactDeadlineError::OvershootFallbackForbidden)
        );
    }
}
