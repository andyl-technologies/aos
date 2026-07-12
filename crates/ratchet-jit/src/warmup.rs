//! Measurement gate for the deferred copy-and-patch baseline hedge.
//!
//! RFC-0007 keeps Cranelift as the initial tier-1 backend, while preserving
//! copy-and-patch as a measured fallback if tier-1 compile time itself becomes
//! the bottleneck. This module records that decision boundary as safe metadata:
//! callers provide compile-time and runtime observations, and the gate reports
//! whether the data says to keep Cranelift or investigate the stencil backend.

/// Compile-time share that must be met before revisiting tier-1 warmup.
///
/// The percentage is a starting measurement gate, not a claim about final AOS
/// workload behavior. A `25%` default means code-quality slowdowns alone do not
/// trigger the hedge; tier-1 compile time must consume a material share of the
/// observed tier-1 cost.
pub const DEFAULT_COPY_AND_PATCH_COMPILE_SHARE_THRESHOLD_PERCENT: u8 = 25;

/// Relative compile-time speedup required from copy-and-patch measurements.
///
/// Copy-and-patch adds a stencil library and fresh unsafe maintenance surface, so
/// a small compile-time win is not enough to justify switching the baseline.
pub const DEFAULT_COPY_AND_PATCH_SPEEDUP_THRESHOLD: f64 = 4.0;

/// A measured backend considered by the tier-1 warmup hedge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tier1WarmupBackend {
    /// The planned Cranelift baseline JIT.
    CraneliftBaseline,
    /// The deferred copy-and-patch stencil baseline.
    CopyAndPatchStencil,
}

/// Observed tier-1 warmup costs in caller-defined comparable time units.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Tier1WarmupObservation {
    compile_time: u64,
    execution_time: u64,
}

impl Tier1WarmupObservation {
    /// Creates a warmup observation from compile and execution costs.
    pub const fn new(compile_time: u64, execution_time: u64) -> Self {
        Self {
            compile_time,
            execution_time,
        }
    }

    /// Returns the observed tier-1 compile cost.
    pub const fn compile_time(self) -> u64 {
        self.compile_time
    }

    /// Returns the observed tier-1 execution cost.
    pub const fn execution_time(self) -> u64 {
        self.execution_time
    }

    /// Returns the total observed tier-1 cost, saturating on overflow.
    pub const fn total_time(self) -> u64 {
        self.compile_time.saturating_add(self.execution_time)
    }

    /// Returns the compile-time share as a percentage in the range `0..=100`.
    pub const fn compile_share_percent(self) -> u8 {
        let total = self.compile_time as u128 + self.execution_time as u128;
        if total == 0 {
            return 0;
        }

        (((self.compile_time as u128) * 100) / total) as u8
    }
}

/// Measured compile-time comparison between Cranelift and copy-and-patch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CopyAndPatchComparison {
    cranelift_compile_time: u64,
    copy_and_patch_compile_time: Option<u64>,
}

impl CopyAndPatchComparison {
    /// Creates a comparison with only Cranelift compile-time data.
    pub const fn cranelift_only(cranelift_compile_time: u64) -> Self {
        Self {
            cranelift_compile_time,
            copy_and_patch_compile_time: None,
        }
    }

    /// Creates a comparison with both Cranelift and copy-and-patch data.
    pub const fn with_copy_and_patch(
        cranelift_compile_time: u64,
        copy_and_patch_compile_time: u64,
    ) -> Self {
        Self {
            cranelift_compile_time,
            copy_and_patch_compile_time: Some(copy_and_patch_compile_time),
        }
    }

    /// Returns the measured Cranelift compile cost.
    pub const fn cranelift_compile_time(self) -> u64 {
        self.cranelift_compile_time
    }

    /// Returns the measured copy-and-patch compile cost when available.
    pub const fn copy_and_patch_compile_time(self) -> Option<u64> {
        self.copy_and_patch_compile_time
    }

    /// Returns the copy-and-patch compile speedup over Cranelift.
    ///
    /// A missing copy-and-patch measurement returns `None`. A zero copy-and-patch
    /// cost with non-zero Cranelift cost returns infinity, matching the usual
    /// benchmark convention for an unbounded relative speedup.
    pub fn copy_and_patch_speedup(self) -> Option<f64> {
        let copy_and_patch_compile_time = self.copy_and_patch_compile_time?;
        if copy_and_patch_compile_time == 0 {
            if self.cranelift_compile_time == 0 {
                return Some(1.0);
            }
            return Some(f64::INFINITY);
        }

        Some(self.cranelift_compile_time as f64 / copy_and_patch_compile_time as f64)
    }
}

/// The measurement-backed decision for the tier-1 warmup hedge.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CopyAndPatchHedgeDecision {
    /// Keep Cranelift as the tier-1 baseline.
    KeepCranelift {
        /// The observed Cranelift compile-time share.
        compile_share_percent: u8,
    },
    /// Collect copy-and-patch measurements because Cranelift compile time is high.
    MeasureCopyAndPatch {
        /// The observed Cranelift compile-time share.
        compile_share_percent: u8,
    },
    /// Consider replacing tier 1 with copy-and-patch based on measured speedup.
    ConsiderCopyAndPatch {
        /// The measured compile-time speedup over Cranelift.
        measured_speedup: f64,
    },
}

impl CopyAndPatchHedgeDecision {
    /// Returns the backend this decision currently favors.
    pub const fn favored_backend(self) -> Tier1WarmupBackend {
        match self {
            Self::ConsiderCopyAndPatch { .. } => Tier1WarmupBackend::CopyAndPatchStencil,
            Self::KeepCranelift { .. } | Self::MeasureCopyAndPatch { .. } => {
                Tier1WarmupBackend::CraneliftBaseline
            }
        }
    }

    /// Returns true when more copy-and-patch measurement is required.
    pub const fn needs_copy_and_patch_measurement(self) -> bool {
        matches!(self, Self::MeasureCopyAndPatch { .. })
    }
}

/// Measurement thresholds for the copy-and-patch hedge.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CopyAndPatchHedgeGate {
    compile_share_threshold_percent: u8,
    copy_and_patch_speedup_threshold: f64,
}

impl CopyAndPatchHedgeGate {
    /// Creates a hedge gate from explicit measurement thresholds.
    ///
    /// Thresholds less than or equal to `1.0`, `NaN`, or infinite thresholds fall back to
    /// [`DEFAULT_COPY_AND_PATCH_SPEEDUP_THRESHOLD`] so malformed configuration
    /// cannot accidentally select copy-and-patch without a real speedup.
    pub fn new(compile_share_threshold_percent: u8, copy_and_patch_speedup_threshold: f64) -> Self {
        let copy_and_patch_speedup_threshold = if copy_and_patch_speedup_threshold.is_finite()
            && copy_and_patch_speedup_threshold > 1.0
        {
            copy_and_patch_speedup_threshold
        } else {
            DEFAULT_COPY_AND_PATCH_SPEEDUP_THRESHOLD
        };

        Self {
            compile_share_threshold_percent,
            copy_and_patch_speedup_threshold,
        }
    }

    /// Returns the compile-time share that triggers copy-and-patch measurement.
    pub const fn compile_share_threshold_percent(self) -> u8 {
        self.compile_share_threshold_percent
    }

    /// Returns the speedup required before considering copy-and-patch replacement.
    pub const fn copy_and_patch_speedup_threshold(self) -> f64 {
        self.copy_and_patch_speedup_threshold
    }

    /// Classifies warmup observations against the copy-and-patch hedge.
    pub fn decide(
        self,
        observation: Tier1WarmupObservation,
        comparison: CopyAndPatchComparison,
    ) -> CopyAndPatchHedgeDecision {
        let compile_share_percent = observation.compile_share_percent();
        if compile_share_percent < self.compile_share_threshold_percent {
            return CopyAndPatchHedgeDecision::KeepCranelift {
                compile_share_percent,
            };
        }

        let Some(speedup) = comparison.copy_and_patch_speedup() else {
            return CopyAndPatchHedgeDecision::MeasureCopyAndPatch {
                compile_share_percent,
            };
        };

        if speedup >= self.copy_and_patch_speedup_threshold {
            CopyAndPatchHedgeDecision::ConsiderCopyAndPatch {
                measured_speedup: speedup,
            }
        } else {
            CopyAndPatchHedgeDecision::KeepCranelift {
                compile_share_percent,
            }
        }
    }
}

impl Default for CopyAndPatchHedgeGate {
    fn default() -> Self {
        Self::new(
            DEFAULT_COPY_AND_PATCH_COMPILE_SHARE_THRESHOLD_PERCENT,
            DEFAULT_COPY_AND_PATCH_SPEEDUP_THRESHOLD,
        )
    }
}

// JIT is off by construction under the Candidate-C variant; these tier-1 lowering/codegen tests re-enable at S4b (cutover plan section 6.1).
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use super::*;

    #[test]
    fn warmup_observation_reports_compile_share() {
        let observation = Tier1WarmupObservation::new(25, 75);

        assert_eq!(observation.compile_time(), 25);
        assert_eq!(observation.execution_time(), 75);
        assert_eq!(observation.total_time(), 100);
        assert_eq!(observation.compile_share_percent(), 25);
    }

    #[test]
    fn empty_warmup_observation_has_zero_compile_share() {
        let observation = Tier1WarmupObservation::default();

        assert_eq!(observation.total_time(), 0);
        assert_eq!(observation.compile_share_percent(), 0);
    }

    #[test]
    fn max_compile_time_observation_reports_full_compile_share() {
        let observation = Tier1WarmupObservation::new(u64::MAX, 0);

        assert_eq!(observation.total_time(), u64::MAX);
        assert_eq!(observation.compile_share_percent(), 100);
    }

    #[test]
    fn max_compile_and_execution_observation_reports_half_compile_share() {
        let observation = Tier1WarmupObservation::new(u64::MAX, u64::MAX);

        assert_eq!(observation.total_time(), u64::MAX);
        assert_eq!(observation.compile_share_percent(), 50);
    }

    #[test]
    fn low_compile_share_keeps_cranelift_without_copy_and_patch_data() {
        let gate = CopyAndPatchHedgeGate::default();
        let decision = gate.decide(
            Tier1WarmupObservation::new(10, 90),
            CopyAndPatchComparison::cranelift_only(10),
        );

        assert_eq!(
            decision,
            CopyAndPatchHedgeDecision::KeepCranelift {
                compile_share_percent: 10
            }
        );
        assert_eq!(
            decision.favored_backend(),
            Tier1WarmupBackend::CraneliftBaseline
        );
        assert!(!decision.needs_copy_and_patch_measurement());
    }

    #[test]
    fn high_compile_share_without_copy_and_patch_data_requests_measurement() {
        let gate = CopyAndPatchHedgeGate::default();
        let decision = gate.decide(
            Tier1WarmupObservation::new(30, 70),
            CopyAndPatchComparison::cranelift_only(30),
        );

        assert_eq!(
            decision,
            CopyAndPatchHedgeDecision::MeasureCopyAndPatch {
                compile_share_percent: 30
            }
        );
        assert_eq!(
            decision.favored_backend(),
            Tier1WarmupBackend::CraneliftBaseline
        );
        assert!(decision.needs_copy_and_patch_measurement());
    }

    #[test]
    fn high_compile_share_with_small_speedup_keeps_cranelift() {
        let gate = CopyAndPatchHedgeGate::default();
        let decision = gate.decide(
            Tier1WarmupObservation::new(30, 70),
            CopyAndPatchComparison::with_copy_and_patch(30, 10),
        );

        assert_eq!(
            decision,
            CopyAndPatchHedgeDecision::KeepCranelift {
                compile_share_percent: 30
            }
        );
    }

    #[test]
    fn high_compile_share_with_large_speedup_considers_copy_and_patch() {
        let gate = CopyAndPatchHedgeGate::default();
        let decision = gate.decide(
            Tier1WarmupObservation::new(30, 70),
            CopyAndPatchComparison::with_copy_and_patch(30, 5),
        );

        assert_eq!(
            decision,
            CopyAndPatchHedgeDecision::ConsiderCopyAndPatch {
                measured_speedup: 6.0
            }
        );
        assert_eq!(
            decision.favored_backend(),
            Tier1WarmupBackend::CopyAndPatchStencil
        );
    }

    #[test]
    fn zero_copy_and_patch_compile_time_reports_infinite_speedup() {
        let comparison = CopyAndPatchComparison::with_copy_and_patch(1, 0);

        assert_eq!(comparison.copy_and_patch_speedup(), Some(f64::INFINITY));
    }

    #[test]
    fn custom_gate_can_request_earlier_measurement() {
        let gate = CopyAndPatchHedgeGate::new(5, 2.0);
        let decision = gate.decide(
            Tier1WarmupObservation::new(5, 95),
            CopyAndPatchComparison::cranelift_only(5),
        );

        assert_eq!(gate.compile_share_threshold_percent(), 5);
        assert_eq!(gate.copy_and_patch_speedup_threshold(), 2.0);
        assert!(decision.needs_copy_and_patch_measurement());
    }

    #[test]
    fn invalid_or_non_speedup_threshold_falls_back_to_default() {
        for threshold in [1.0, 0.0, 0.5, -1.0, f64::NAN, f64::INFINITY] {
            let gate = CopyAndPatchHedgeGate::new(5, threshold);

            assert_eq!(
                gate.copy_and_patch_speedup_threshold(),
                DEFAULT_COPY_AND_PATCH_SPEEDUP_THRESHOLD
            );
        }
    }
}
