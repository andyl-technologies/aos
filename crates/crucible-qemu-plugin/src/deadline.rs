//! Exact virtual-clock deadline introspection.
//!
//! The raw QEMU plugin export returns a picosecond deadline from
//! `QEMU_CLOCK_VIRTUAL`. This module models the fail-closed policy around that
//! export. The capability is required and every query reads the virtual clock;
//! there is no alternate clock or fallback policy.

use thiserror::Error;

/// The required QEMU plugin extension symbol for exact timer deadlines.
pub const QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL: &str = "qemu_plugin_clock_deadline_ps";

/// QEMU's exact virtual-clock deadline function.
///
/// The patched QEMU plugin API exports this symbol as a no-argument function
/// returning either the absolute `QEMU_CLOCK_VIRTUAL` deadline in picoseconds or
/// a negative sentinel when no virtual-clock timer is armed.
pub type QemuClockDeadlineFn = extern "C" fn() -> i64;

/// A validated exact-deadline report from QEMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExactDeadlineReport {
    /// No virtual-clock guest timer is armed.
    NoArmedTimer,
    /// A virtual-clock guest timer is armed at this virtual picosecond.
    Armed {
        /// The exact virtual picosecond deadline from `QEMU_CLOCK_VIRTUAL`.
        deadline_ps: u64,
    },
}

/// Required plugin-side handle for exact virtual-clock deadline introspection.
#[derive(Clone, Copy, Debug)]
pub struct ExactDeadlineReader {
    clock_deadline_ps: QemuClockDeadlineFn,
}

impl ExactDeadlineReader {
    /// Requires the patched QEMU deadline export and returns a reader for it.
    ///
    /// # Errors
    ///
    /// Returns [`ExactDeadlineError::CapabilityUnavailable`] when the
    /// `qemu_plugin_clock_deadline_ps` export was not resolved. This is the
    /// fail-closed registration path for [PLUG-15].
    pub fn require(
        clock_deadline_ps: Option<QemuClockDeadlineFn>,
    ) -> Result<Self, ExactDeadlineError> {
        let Some(clock_deadline_ps) = clock_deadline_ps else {
            return Err(ExactDeadlineError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL,
            });
        };

        Ok(Self { clock_deadline_ps })
    }

    /// Reads the next exact virtual-clock deadline from QEMU.
    ///
    /// # Errors
    ///
    /// This reader has no runtime error after [`Self::require`] admits the
    /// required QEMU export. The result type preserves the deadline-reading
    /// boundary used by the scheduler callbacks.
    pub fn read_next_deadline(&self) -> Result<ExactDeadlineReport, ExactDeadlineError> {
        match u64::try_from((self.clock_deadline_ps)()) {
            Ok(deadline_ps) => Ok(ExactDeadlineReport::Armed { deadline_ps }),
            Err(_) => Ok(ExactDeadlineReport::NoArmedTimer),
        }
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

    let mut min_deadline_ps: Option<u64> = None;
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

        if let ExactDeadlineReport::Armed { deadline_ps } = report.report {
            min_deadline_ps = Some(match min_deadline_ps {
                Some(current) => current.min(deadline_ps),
                None => deadline_ps,
            });
        }
    }

    for vcpu_id in 0..vcpu_count {
        if !reports.iter().any(|report| report.vcpu_id == vcpu_id) {
            return Err(ExactDeadlineError::MissingVcpuDeadline { vcpu_id });
        }
    }

    Ok(match min_deadline_ps {
        Some(deadline_ps) => ExactDeadlineReport::Armed { deadline_ps },
        None => ExactDeadlineReport::NoArmedTimer,
    })
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
            Ok(ExactDeadlineReport::Armed { deadline_ps: 2048 })
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
    fn multi_vcpu_deadline_uses_minimum_armed_virtual_deadline() {
        let reports = [
            PerVcpuDeadlineReport::new(2, ExactDeadlineReport::Armed { deadline_ps: 90 }),
            PerVcpuDeadlineReport::new(0, ExactDeadlineReport::NoArmedTimer),
            PerVcpuDeadlineReport::new(1, ExactDeadlineReport::Armed { deadline_ps: 40 }),
            PerVcpuDeadlineReport::new(3, ExactDeadlineReport::Armed { deadline_ps: 70 }),
        ];

        assert_eq!(
            aggregate_multi_vcpu_deadline(4, &reports),
            Ok(ExactDeadlineReport::Armed { deadline_ps: 40 })
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
            PerVcpuDeadlineReport::new(0, ExactDeadlineReport::Armed { deadline_ps: 90 }),
            PerVcpuDeadlineReport::new(0, ExactDeadlineReport::Armed { deadline_ps: 40 }),
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
            ExactDeadlineReport::Armed { deadline_ps: 40 },
        )];

        assert_eq!(
            aggregate_multi_vcpu_deadline(0, &reports),
            Err(ExactDeadlineError::ZeroVcpuDeadlineCount)
        );
    }

    #[test]
    fn multi_vcpu_deadline_rejects_out_of_range_vcpu_reports() {
        let reports = [
            PerVcpuDeadlineReport::new(0, ExactDeadlineReport::Armed { deadline_ps: 90 }),
            PerVcpuDeadlineReport::new(2, ExactDeadlineReport::Armed { deadline_ps: 40 }),
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
            PerVcpuDeadlineReport::new(0, ExactDeadlineReport::Armed { deadline_ps: 90 }),
            PerVcpuDeadlineReport::new(1, ExactDeadlineReport::Armed { deadline_ps: 40 }),
            PerVcpuDeadlineReport::new(3, ExactDeadlineReport::Armed { deadline_ps: 70 }),
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
