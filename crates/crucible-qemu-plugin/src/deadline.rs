//! Exact virtual-clock deadline introspection.
//!
//! The raw QEMU plugin export returns a nanosecond deadline from
//! `QEMU_CLOCK_VIRTUAL`. This module models the fail-closed policy around that
//! export: the capability is required, realtime and host-clock sources are
//! rejected, and overshoot-and-correct is never an accepted fallback.

use thiserror::Error;

/// The required QEMU plugin extension symbol for exact timer deadlines.
pub const QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL: &str = "qemu_plugin_clock_deadline_ns";

/// QEMU's exact virtual-clock deadline function.
///
/// The patched QEMU plugin API exports this symbol as a no-argument function
/// returning either the absolute `QEMU_CLOCK_VIRTUAL` deadline in nanoseconds or
/// a negative sentinel when no virtual-clock timer is armed.
pub type QemuClockDeadlineFn = extern "C" fn() -> i64;

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

/// Required plugin-side handle for exact virtual-clock deadline introspection.
#[derive(Clone, Copy, Debug)]
pub struct ExactDeadlineReader {
    clock_deadline_ns: QemuClockDeadlineFn,
}

impl ExactDeadlineReader {
    /// Requires the patched QEMU deadline export and returns a reader for it.
    ///
    /// # Errors
    ///
    /// Returns [`ExactDeadlineError::CapabilityUnavailable`] when the
    /// `qemu_plugin_clock_deadline_ns` export was not resolved. This is the
    /// fail-closed registration path for [PLUG-15].
    pub fn require(
        clock_deadline_ns: Option<QemuClockDeadlineFn>,
    ) -> Result<Self, ExactDeadlineError> {
        let Some(clock_deadline_ns) = clock_deadline_ns else {
            return Err(ExactDeadlineError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL,
            });
        };

        ExactDeadlineIntrospection::required().validate()?;
        Ok(Self { clock_deadline_ns })
    }

    /// Reads the next exact virtual-clock deadline from QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`ExactDeadlineError`] if the required exact-deadline policy is
    /// invalid. The reader is constructed only by [`Self::require`], so this path
    /// cannot silently degrade to overshoot-and-correct.
    pub fn read_next_deadline(&self) -> Result<ExactDeadlineReport, ExactDeadlineError> {
        ExactDeadlineIntrospection::required().report((self.clock_deadline_ns)())
    }
}

/// One vCPU's plugin-internal exact-deadline observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PerVcpuDeadlineReport {
    vcpu_id: u64,
    report: ExactDeadlineReport,
}

impl PerVcpuDeadlineReport {
    /// Builds a deadline observation for one vCPU.
    #[must_use]
    pub fn new(vcpu_id: u64, report: ExactDeadlineReport) -> Self {
        Self { vcpu_id, report }
    }

    /// Returns the zero-based vCPU identifier for this observation.
    #[must_use]
    pub fn vcpu_id(&self) -> u64 {
        self.vcpu_id
    }

    /// Returns this vCPU's exact virtual-clock deadline report.
    #[must_use]
    pub fn report(&self) -> ExactDeadlineReport {
        self.report
    }
}

/// Reduces per-vCPU exact-deadline observations to the node deadline.
///
/// The returned value is the minimum armed `QEMU_CLOCK_VIRTUAL` deadline across
/// all `0..vcpu_count` vCPUs. `NoArmedTimer` observations are ignored unless
/// every vCPU is idle, in which case the node also reports
/// [`ExactDeadlineReport::NoArmedTimer`].
///
/// # Errors
///
/// Returns [`ExactDeadlineError`] when `vcpu_count` is zero, no vCPU reports are
/// supplied, a report names a vCPU outside `0..vcpu_count`, the same vCPU id
/// appears more than once, or any expected vCPU did not report.
pub fn aggregate_multi_vcpu_deadline(
    vcpu_count: u64,
    reports: &[PerVcpuDeadlineReport],
) -> Result<ExactDeadlineReport, ExactDeadlineError> {
    if vcpu_count == 0 {
        return Err(ExactDeadlineError::ZeroVcpuDeadlineCount);
    }
    if reports.is_empty() {
        return Err(ExactDeadlineError::EmptyVcpuDeadlineSet);
    }

    let mut min_deadline_ns: Option<u64> = None;
    for (index, report) in reports.iter().enumerate() {
        if report.vcpu_id >= vcpu_count {
            return Err(ExactDeadlineError::VcpuDeadlineOutOfRange {
                vcpu_id: report.vcpu_id,
                vcpu_count,
            });
        }
        if reports[..index]
            .iter()
            .any(|previous| previous.vcpu_id == report.vcpu_id)
        {
            return Err(ExactDeadlineError::DuplicateVcpuDeadline {
                vcpu_id: report.vcpu_id,
            });
        }

        if let ExactDeadlineReport::Armed { deadline_ns } = report.report {
            min_deadline_ns = Some(match min_deadline_ns {
                Some(current) => current.min(deadline_ns),
                None => deadline_ns,
            });
        }
    }

    for vcpu_id in 0..vcpu_count {
        if !reports.iter().any(|report| report.vcpu_id == vcpu_id) {
            return Err(ExactDeadlineError::MissingVcpuDeadline { vcpu_id });
        }
    }

    Ok(match min_deadline_ns {
        Some(deadline_ns) => ExactDeadlineReport::Armed { deadline_ns },
        None => ExactDeadlineReport::NoArmedTimer,
    })
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
    /// A multi-vCPU deadline aggregation was requested for zero vCPUs.
    #[error("multi-vCPU deadline aggregation requires a non-zero vCPU count")]
    ZeroVcpuDeadlineCount,
    /// No vCPU deadline observations were supplied for a multi-vCPU node.
    #[error("multi-vCPU deadline aggregation requires at least one vCPU report")]
    EmptyVcpuDeadlineSet,
    /// A multi-vCPU deadline report named a vCPU outside the configured range.
    #[error("multi-vCPU deadline report named vCPU {vcpu_id}, outside vCPU count {vcpu_count}")]
    VcpuDeadlineOutOfRange {
        /// The out-of-range vCPU id.
        vcpu_id: u64,
        /// The configured vCPU count.
        vcpu_count: u64,
    },
    /// A multi-vCPU deadline set contained two reports for the same vCPU.
    #[error("multi-vCPU deadline aggregation received duplicate report for vCPU {vcpu_id}")]
    DuplicateVcpuDeadline {
        /// The duplicated vCPU id.
        vcpu_id: u64,
    },
    /// A multi-vCPU deadline set did not include an expected vCPU.
    #[error("multi-vCPU deadline aggregation is missing report for vCPU {vcpu_id}")]
    MissingVcpuDeadline {
        /// The expected vCPU id with no report.
        vcpu_id: u64,
    },
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
    fn exact_deadline_reader_requires_qemu_clock_deadline_symbol() {
        let Err(error) = ExactDeadlineReader::require(None) else {
            panic!("missing deadline symbol should fail closed");
        };

        assert_eq!(
            error,
            ExactDeadlineError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL,
            }
        );
    }

    #[test]
    fn exact_deadline_reader_reads_virtual_deadline_without_fallback() {
        let reader = match ExactDeadlineReader::require(Some(test_armed_deadline)) {
            Ok(reader) => reader,
            Err(error) => panic!("deadline reader should require resolved symbol: {error}"),
        };
        assert_eq!(
            reader.read_next_deadline(),
            Ok(ExactDeadlineReport::Armed { deadline_ns: 2048 })
        );

        let no_timer_reader = match ExactDeadlineReader::require(Some(test_no_armed_deadline)) {
            Ok(reader) => reader,
            Err(error) => panic!("deadline reader should accept no-timer symbol: {error}"),
        };
        assert_eq!(
            no_timer_reader.read_next_deadline(),
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

    #[test]
    fn multi_vcpu_deadline_uses_minimum_armed_virtual_deadline() {
        let reports = [
            PerVcpuDeadlineReport::new(2, ExactDeadlineReport::Armed { deadline_ns: 90 }),
            PerVcpuDeadlineReport::new(0, ExactDeadlineReport::NoArmedTimer),
            PerVcpuDeadlineReport::new(1, ExactDeadlineReport::Armed { deadline_ns: 40 }),
            PerVcpuDeadlineReport::new(3, ExactDeadlineReport::Armed { deadline_ns: 70 }),
        ];

        assert_eq!(
            aggregate_multi_vcpu_deadline(4, &reports),
            Ok(ExactDeadlineReport::Armed { deadline_ns: 40 })
        );
    }

    #[test]
    fn multi_vcpu_deadline_returns_no_armed_timer_when_every_vcpu_is_idle() {
        let reports = [
            PerVcpuDeadlineReport::new(0, ExactDeadlineReport::NoArmedTimer),
            PerVcpuDeadlineReport::new(1, ExactDeadlineReport::NoArmedTimer),
        ];

        assert_eq!(
            aggregate_multi_vcpu_deadline(2, &reports),
            Ok(ExactDeadlineReport::NoArmedTimer)
        );
    }

    #[test]
    fn multi_vcpu_deadline_rejects_duplicate_vcpu_reports() {
        let reports = [
            PerVcpuDeadlineReport::new(0, ExactDeadlineReport::Armed { deadline_ns: 90 }),
            PerVcpuDeadlineReport::new(0, ExactDeadlineReport::Armed { deadline_ns: 40 }),
        ];

        assert_eq!(
            aggregate_multi_vcpu_deadline(2, &reports),
            Err(ExactDeadlineError::DuplicateVcpuDeadline { vcpu_id: 0 })
        );
    }

    #[test]
    fn multi_vcpu_deadline_rejects_empty_report_sets() {
        assert_eq!(
            aggregate_multi_vcpu_deadline(2, &[]),
            Err(ExactDeadlineError::EmptyVcpuDeadlineSet)
        );
    }

    #[test]
    fn multi_vcpu_deadline_rejects_zero_expected_vcpus() {
        let reports = [PerVcpuDeadlineReport::new(
            0,
            ExactDeadlineReport::Armed { deadline_ns: 40 },
        )];

        assert_eq!(
            aggregate_multi_vcpu_deadline(0, &reports),
            Err(ExactDeadlineError::ZeroVcpuDeadlineCount)
        );
    }

    #[test]
    fn multi_vcpu_deadline_rejects_out_of_range_vcpu_reports() {
        let reports = [
            PerVcpuDeadlineReport::new(0, ExactDeadlineReport::Armed { deadline_ns: 90 }),
            PerVcpuDeadlineReport::new(2, ExactDeadlineReport::Armed { deadline_ns: 40 }),
        ];

        assert_eq!(
            aggregate_multi_vcpu_deadline(2, &reports),
            Err(ExactDeadlineError::VcpuDeadlineOutOfRange {
                vcpu_id: 2,
                vcpu_count: 2,
            })
        );
    }

    #[test]
    fn multi_vcpu_deadline_rejects_incomplete_vcpu_report_sets() {
        let reports = [
            PerVcpuDeadlineReport::new(0, ExactDeadlineReport::Armed { deadline_ns: 90 }),
            PerVcpuDeadlineReport::new(1, ExactDeadlineReport::Armed { deadline_ns: 40 }),
            PerVcpuDeadlineReport::new(3, ExactDeadlineReport::Armed { deadline_ns: 70 }),
        ];

        assert_eq!(
            aggregate_multi_vcpu_deadline(4, &reports),
            Err(ExactDeadlineError::MissingVcpuDeadline { vcpu_id: 2 })
        );
    }

    extern "C" fn test_armed_deadline() -> i64 {
        2048
    }

    extern "C" fn test_no_armed_deadline() -> i64 {
        -1
    }
}
