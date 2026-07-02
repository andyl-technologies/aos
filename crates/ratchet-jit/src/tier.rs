//! Safe tier-up policy metadata for future baseline compilation.
//!
//! This module names the counter-based promotion policy from RFC-0007 without
//! compiling code, installing function pointers, or mutating thunk state. Future
//! evaluator integration can feed invocation counters and accepted analysis or
//! profile hints into [`TierUpPolicy`] and route
//! [`TierUpDecision::PromoteToTier1`] to the Cranelift lowering pipeline once
//! that pipeline exists.

use ratchet_core::Cardinality;

/// Default invocation count that marks a thunk or lambda hot for tier 1.
///
/// The value is deliberately low because RFC-0007 treats the baseline Cranelift
/// tier as the cheap warmup tier. A policy threshold of `0` remains valid for
/// measurement modes that want to request tier-1 compilation immediately.
pub const DEFAULT_TIER1_INVOCATION_THRESHOLD: u64 = 2;

/// The execution tier selected by the safe tier-up policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum JitTier {
    /// The safe tree-walk evaluator remains the active implementation.
    #[default]
    Tier0Oracle,
    /// The baseline Cranelift tier should be used once compiled code exists.
    Tier1Baseline,
}

/// Saturating invocation counter for one thunk or lambda body.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TierUpCounter {
    invocations: u64,
}

impl TierUpCounter {
    /// Creates an invocation counter from an explicit count.
    pub const fn new(invocations: u64) -> Self {
        Self { invocations }
    }

    /// Returns the observed invocation count.
    pub const fn invocations(self) -> u64 {
        self.invocations
    }

    /// Returns a counter with one more invocation, saturating on overflow.
    pub const fn record_invocation(self) -> Self {
        Self {
            invocations: self.invocations.saturating_add(1),
        }
    }

    /// Returns a tier-up observation for the current counter value.
    pub const fn observation(self) -> TierUpObservation {
        TierUpObservation::new(self.invocations)
    }

    /// Returns a tier-up observation with accepted demand evidence.
    pub const fn observation_with_demand_hint(
        self,
        demand_hint: TierUpDemandHint,
    ) -> TierUpObservation {
        TierUpObservation::with_demand_hint(self.invocations, demand_hint)
    }
}

/// Demand evidence available to tier-1 promotion policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TierUpDemandHint {
    /// No accepted analysis or profile evidence says the site is multi-use.
    #[default]
    NoMultiUseEvidence,
    /// Profiling or cardinality analysis marks the site as multi-use.
    MultiUse,
}

impl TierUpDemandHint {
    /// Builds a demand hint from an accepted cardinality-analysis result.
    ///
    /// Conservative callers that have not accepted `Many` as a promotion hint
    /// should pass [`TierUpDemandHint::NoMultiUseEvidence`] directly.
    pub const fn from_cardinality(cardinality: Cardinality) -> Self {
        match cardinality {
            Cardinality::Many => Self::MultiUse,
            Cardinality::Absent | Cardinality::Once => Self::NoMultiUseEvidence,
        }
    }

    /// Returns whether the hint marks the site as multi-use.
    pub const fn is_multi_use(self) -> bool {
        matches!(self, Self::MultiUse)
    }
}

/// Hotness observations for one thunk or lambda body.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TierUpObservation {
    invocations: u64,
    demand_hint: TierUpDemandHint,
    current_tier: JitTier,
}

impl TierUpObservation {
    /// Creates a hotness observation from an invocation count.
    pub const fn new(invocations: u64) -> Self {
        Self {
            invocations,
            demand_hint: TierUpDemandHint::NoMultiUseEvidence,
            current_tier: JitTier::Tier0Oracle,
        }
    }

    /// Creates a hotness observation with explicit demand evidence.
    pub const fn with_demand_hint(invocations: u64, demand_hint: TierUpDemandHint) -> Self {
        Self {
            invocations,
            demand_hint,
            current_tier: JitTier::Tier0Oracle,
        }
    }

    /// Returns a copy of this observation with an explicit current tier.
    pub const fn with_current_tier(self, current_tier: JitTier) -> Self {
        Self {
            invocations: self.invocations,
            demand_hint: self.demand_hint,
            current_tier,
        }
    }

    /// Returns the observed invocation count.
    pub const fn invocations(self) -> u64 {
        self.invocations
    }

    /// Returns the accepted demand hint.
    pub const fn demand_hint(self) -> TierUpDemandHint {
        self.demand_hint
    }

    /// Returns the tier currently installed for the observed site.
    pub const fn current_tier(self) -> JitTier {
        self.current_tier
    }
}

/// Reasons a site qualifies for tier-1 promotion.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TierUpReasons {
    invocation_threshold: bool,
    multi_use_hint: bool,
}

impl TierUpReasons {
    /// Creates a reason set from explicit policy signals.
    pub const fn new(invocation_threshold: bool, multi_use_hint: bool) -> Self {
        Self {
            invocation_threshold,
            multi_use_hint,
        }
    }

    /// Returns whether the invocation counter crossed the tier-1 threshold.
    pub const fn invocation_threshold(self) -> bool {
        self.invocation_threshold
    }

    /// Returns whether accepted demand evidence marked the site as multi-use.
    pub const fn multi_use_hint(self) -> bool {
        self.multi_use_hint
    }

    /// Returns whether any promotion reason is present.
    pub const fn any(self) -> bool {
        self.invocation_threshold || self.multi_use_hint
    }
}

/// The tier selected by one policy decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TierUpDecision {
    /// Keep executing in the currently installed tier.
    StayInTier(JitTier),
    /// Request baseline tier-1 compilation for the observed site.
    PromoteToTier1(TierUpReasons),
}

impl TierUpDecision {
    /// Returns the target execution tier represented by this decision.
    pub const fn target_tier(self) -> JitTier {
        match self {
            Self::StayInTier(tier) => tier,
            Self::PromoteToTier1(_) => JitTier::Tier1Baseline,
        }
    }

    /// Returns true when this decision requests tier-1 promotion.
    pub const fn should_promote(self) -> bool {
        matches!(self, Self::PromoteToTier1(_))
    }

    /// Returns the promotion reasons when tier 1 was selected.
    pub const fn reasons(self) -> Option<TierUpReasons> {
        match self {
            Self::StayInTier(_) => None,
            Self::PromoteToTier1(reasons) => Some(reasons),
        }
    }
}

/// Counter-based tier-up policy for future baseline compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TierUpPolicy {
    tier1_invocation_threshold: u64,
    eager_multi_use: bool,
}

impl TierUpPolicy {
    /// Creates a tier-up policy from explicit tunables.
    pub const fn new(tier1_invocation_threshold: u64, eager_multi_use: bool) -> Self {
        Self {
            tier1_invocation_threshold,
            eager_multi_use,
        }
    }

    /// Returns the invocation count required for tier-1 promotion.
    pub const fn tier1_invocation_threshold(self) -> u64 {
        self.tier1_invocation_threshold
    }

    /// Returns whether accepted multi-use evidence can promote before the counter.
    pub const fn eager_multi_use(self) -> bool {
        self.eager_multi_use
    }

    /// Returns a copy of this policy with a different tier-1 threshold.
    pub const fn with_tier1_invocation_threshold(self, threshold: u64) -> Self {
        Self {
            tier1_invocation_threshold: threshold,
            eager_multi_use: self.eager_multi_use,
        }
    }

    /// Returns a copy of this policy with a different multi-use promotion mode.
    pub const fn with_eager_multi_use(self, eager_multi_use: bool) -> Self {
        Self {
            tier1_invocation_threshold: self.tier1_invocation_threshold,
            eager_multi_use,
        }
    }

    /// Classifies one hotness observation for tier-1 promotion.
    pub const fn decide(self, observation: TierUpObservation) -> TierUpDecision {
        if matches!(observation.current_tier(), JitTier::Tier1Baseline) {
            return TierUpDecision::StayInTier(JitTier::Tier1Baseline);
        }

        let reasons = TierUpReasons::new(
            observation.invocations() >= self.tier1_invocation_threshold,
            self.eager_multi_use && observation.demand_hint().is_multi_use(),
        );

        if reasons.any() {
            TierUpDecision::PromoteToTier1(reasons)
        } else {
            TierUpDecision::StayInTier(JitTier::Tier0Oracle)
        }
    }
}

impl Default for TierUpPolicy {
    fn default() -> Self {
        Self::new(DEFAULT_TIER1_INVOCATION_THRESHOLD, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_promotes_after_invocation_threshold() {
        let policy = TierUpPolicy::default();

        assert_eq!(
            policy.decide(TierUpObservation::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1
            )),
            TierUpDecision::StayInTier(JitTier::Tier0Oracle)
        );

        let decision = policy.decide(TierUpObservation::new(DEFAULT_TIER1_INVOCATION_THRESHOLD));
        assert_eq!(decision.target_tier(), JitTier::Tier1Baseline);
        assert!(decision.should_promote());
        assert_eq!(decision.reasons(), Some(TierUpReasons::new(true, false)));
    }

    #[test]
    fn default_policy_promotes_multi_use_sites_before_threshold() {
        let observation = TierUpObservation::with_demand_hint(
            0,
            TierUpDemandHint::from_cardinality(Cardinality::Many),
        );
        let decision = TierUpPolicy::default().decide(observation);

        assert_eq!(decision.target_tier(), JitTier::Tier1Baseline);
        assert_eq!(decision.reasons(), Some(TierUpReasons::new(false, true)));
    }

    #[test]
    fn absent_and_once_cardinality_do_not_promote_before_threshold() {
        for cardinality in [Cardinality::Absent, Cardinality::Once] {
            let observation = TierUpObservation::with_demand_hint(
                0,
                TierUpDemandHint::from_cardinality(cardinality),
            );

            assert_eq!(
                TierUpPolicy::default().decide(observation),
                TierUpDecision::StayInTier(JitTier::Tier0Oracle)
            );
        }
    }

    #[test]
    fn policy_can_disable_eager_multi_use_promotion() {
        let policy = TierUpPolicy::default().with_eager_multi_use(false);
        let observation = TierUpObservation::with_demand_hint(0, TierUpDemandHint::MultiUse);

        assert_eq!(
            policy.decide(observation),
            TierUpDecision::StayInTier(JitTier::Tier0Oracle)
        );
        assert!(!policy.eager_multi_use());
    }

    #[test]
    fn promotion_reasons_preserve_counter_and_multi_use_signals() {
        let observation = TierUpObservation::with_demand_hint(2, TierUpDemandHint::MultiUse);
        let decision = TierUpPolicy::default().decide(observation);

        assert_eq!(decision.reasons(), Some(TierUpReasons::new(true, true)));
    }

    #[test]
    fn zero_threshold_requests_immediate_tier_one_promotion() {
        let policy = TierUpPolicy::default().with_tier1_invocation_threshold(0);
        let decision = policy.decide(TierUpObservation::default());

        assert_eq!(policy.tier1_invocation_threshold(), 0);
        assert_eq!(decision.reasons(), Some(TierUpReasons::new(true, false)));
    }

    #[test]
    fn invocation_counter_saturates_at_u64_max() {
        let counter = TierUpCounter::new(u64::MAX).record_invocation();

        assert_eq!(counter.invocations(), u64::MAX);
        assert_eq!(counter.observation().invocations(), u64::MAX);
    }

    #[test]
    fn already_tier_one_sites_do_not_request_repeat_promotion() {
        let observation = TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD)
            .observation_with_demand_hint(TierUpDemandHint::MultiUse)
            .with_current_tier(JitTier::Tier1Baseline);
        let decision = TierUpPolicy::default().decide(observation);

        assert_eq!(decision, TierUpDecision::StayInTier(JitTier::Tier1Baseline));
        assert_eq!(decision.target_tier(), JitTier::Tier1Baseline);
        assert!(!decision.should_promote());
        assert_eq!(decision.reasons(), None);
    }
}
