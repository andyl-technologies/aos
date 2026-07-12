//! Safe tier-up policy and slot metadata for future baseline compilation.
//!
//! This module names the counter-based promotion policy from RFC-0007 without
//! compiling code or calling native code. Future evaluator integration can feed
//! invocation counters and accepted analysis or profile hints into
//! [`TierUpPolicy`], route [`TierUpDecision::PromoteToTier1`] to the Cranelift
//! lowering pipeline, and install the resulting opaque pointer metadata in
//! [`JitTieredCodeSlot`] once that pipeline exists.

use std::{error::Error, fmt, ptr::NonNull};

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

/// Opaque metadata for a finalized compiled-code pointer.
///
/// This wrapper deliberately does not expose a callable function type. The
/// pointer remains valid only according to the lifetime and ownership contract
/// of the backend object that produced it, such as a Cranelift `JITModule`
/// holder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JitCompiledCodePointer {
    ptr: NonNull<u8>,
}

impl JitCompiledCodePointer {
    /// Wraps non-null compiled-code pointer metadata.
    ///
    /// This does not dereference, cast, call, own, or extend the backend
    /// lifetime of the pointer.
    pub const fn from_non_null(ptr: NonNull<u8>) -> Self {
        Self { ptr }
    }

    /// Returns the wrapped non-null pointer metadata.
    ///
    /// The returned pointer is not callable metadata and its validity is still
    /// bounded by the backend owner that produced it.
    pub const fn as_non_null(self) -> NonNull<u8> {
        self.ptr
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

/// A failure while updating safe tiered-code slot metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitTieredCodeSlotError {
    /// Tier-1 code metadata is already installed in the slot.
    Tier1CodeAlreadyInstalled {
        /// The tier currently selected by the slot.
        current_tier: JitTier,
    },
}

impl fmt::Display for JitTieredCodeSlotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tier1CodeAlreadyInstalled { current_tier } => write!(
                formatter,
                "tier-1 code is already installed for slot in {current_tier:?}"
            ),
        }
    }
}

impl Error for JitTieredCodeSlotError {}

/// Safe per-body tier state with an invocation counter beside code metadata.
///
/// The slot models the future thunk or lambda state layout without integrating
/// with the evaluator heap. It stores only safe metadata: the currently selected
/// tier, a saturating invocation counter, and an optional opaque tier-1 code
/// pointer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JitTieredCodeSlot {
    current_tier: JitTier,
    invocation_counter: TierUpCounter,
    tier1_code_ptr: Option<JitCompiledCodePointer>,
}

impl JitTieredCodeSlot {
    /// Creates a cold tier-0 slot with no compiled-code metadata.
    pub const fn new() -> Self {
        Self {
            current_tier: JitTier::Tier0Oracle,
            invocation_counter: TierUpCounter::new(0),
            tier1_code_ptr: None,
        }
    }

    /// Creates a tier-0 slot from an explicit invocation counter.
    pub const fn with_counter(invocation_counter: TierUpCounter) -> Self {
        Self {
            current_tier: JitTier::Tier0Oracle,
            invocation_counter,
            tier1_code_ptr: None,
        }
    }

    /// Returns the tier currently selected by this slot.
    pub const fn current_tier(&self) -> JitTier {
        self.current_tier
    }

    /// Returns the invocation counter stored beside code metadata.
    pub const fn invocation_counter(&self) -> TierUpCounter {
        self.invocation_counter
    }

    /// Returns the installed tier-1 code pointer metadata, when present.
    ///
    /// The slot does not own or extend the backend lifetime for this pointer,
    /// and callers must not cast or call it.
    pub const fn tier1_code_ptr(&self) -> Option<JitCompiledCodePointer> {
        self.tier1_code_ptr
    }

    /// Returns whether tier-1 code metadata has been installed.
    pub const fn is_tier1_installed(&self) -> bool {
        self.tier1_code_ptr.is_some()
    }

    /// Returns the policy observation for the current slot state.
    pub const fn observation(&self) -> TierUpObservation {
        self.invocation_counter
            .observation()
            .with_current_tier(self.current_tier)
    }

    /// Returns the policy observation for the current state with demand evidence.
    pub const fn observation_with_demand_hint(
        &self,
        demand_hint: TierUpDemandHint,
    ) -> TierUpObservation {
        self.invocation_counter
            .observation_with_demand_hint(demand_hint)
            .with_current_tier(self.current_tier)
    }

    /// Records one invocation without accepted multi-use evidence.
    pub fn record_invocation(&mut self, policy: TierUpPolicy) -> TierUpDecision {
        self.record_invocation_with_demand_hint(policy, TierUpDemandHint::NoMultiUseEvidence)
    }

    /// Records one invocation and classifies the slot with `policy`.
    pub fn record_invocation_with_demand_hint(
        &mut self,
        policy: TierUpPolicy,
        demand_hint: TierUpDemandHint,
    ) -> TierUpDecision {
        self.invocation_counter = self.invocation_counter.record_invocation();
        policy.decide(self.observation_with_demand_hint(demand_hint))
    }

    /// Installs opaque tier-1 code metadata for this slot.
    ///
    /// This updates only safe slot metadata. It does not cast the pointer, call
    /// native code, publish into an evaluator heap object, or perform an atomic
    /// compare-and-swap. The slot does not own or extend the backend lifetime
    /// for `code_ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`JitTieredCodeSlotError::Tier1CodeAlreadyInstalled`] if tier-1
    /// code metadata is already present.
    pub fn install_tier1_code(
        &mut self,
        code_ptr: JitCompiledCodePointer,
    ) -> Result<(), JitTieredCodeSlotError> {
        if self.tier1_code_ptr.is_some() {
            return Err(JitTieredCodeSlotError::Tier1CodeAlreadyInstalled {
                current_tier: self.current_tier,
            });
        }

        self.current_tier = JitTier::Tier1Baseline;
        self.tier1_code_ptr = Some(code_ptr);
        Ok(())
    }
}

// JIT is off by construction under the Candidate-C variant; these tier-1 lowering/codegen tests re-enable at S4b (cutover plan section 6.1).
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use super::*;
    use std::ptr::NonNull;

    fn opaque_test_code_pointer() -> JitCompiledCodePointer {
        JitCompiledCodePointer::from_non_null(NonNull::dangling())
    }

    fn opaque_test_code_pointer_at(address: usize) -> JitCompiledCodePointer {
        let ptr = NonNull::new(address as *mut u8).expect("test address is non-null");
        JitCompiledCodePointer::from_non_null(ptr)
    }

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

    #[test]
    fn tiered_code_slot_starts_cold_with_counter_beside_empty_code_pointer() {
        let slot = JitTieredCodeSlot::new();

        assert_eq!(slot.current_tier(), JitTier::Tier0Oracle);
        assert_eq!(slot.invocation_counter().invocations(), 0);
        assert_eq!(slot.tier1_code_ptr(), None);
        assert!(!slot.is_tier1_installed());
        assert_eq!(
            slot.observation(),
            TierUpObservation::new(0).with_current_tier(JitTier::Tier0Oracle)
        );
    }

    #[test]
    fn tiered_code_slot_records_invocations_and_requests_promotion() {
        let mut slot = JitTieredCodeSlot::with_counter(TierUpCounter::new(
            DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
        ));

        let decision = slot.record_invocation(TierUpPolicy::default());

        assert_eq!(
            slot.invocation_counter().invocations(),
            DEFAULT_TIER1_INVOCATION_THRESHOLD
        );
        assert_eq!(slot.current_tier(), JitTier::Tier0Oracle);
        assert_eq!(decision.reasons(), Some(TierUpReasons::new(true, false)));
    }

    #[test]
    fn tiered_code_slot_can_promote_from_multi_use_hint_before_threshold() {
        let mut slot = JitTieredCodeSlot::new();

        let decision = slot.record_invocation_with_demand_hint(
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
        );

        assert_eq!(slot.invocation_counter().invocations(), 1);
        assert_eq!(decision.reasons(), Some(TierUpReasons::new(false, true)));
    }

    #[test]
    fn tiered_code_slot_installs_tier_one_code_metadata_once() {
        let mut slot = JitTieredCodeSlot::new();
        let code_ptr = opaque_test_code_pointer();

        slot.install_tier1_code(code_ptr)
            .expect("tier-1 code metadata installs");

        assert_eq!(slot.current_tier(), JitTier::Tier1Baseline);
        assert_eq!(slot.tier1_code_ptr(), Some(code_ptr));
        assert!(slot.is_tier1_installed());
        assert_eq!(
            slot.tier1_code_ptr()
                .map(JitCompiledCodePointer::as_non_null),
            Some(NonNull::dangling())
        );
    }

    #[test]
    fn tiered_code_slot_rejects_duplicate_tier_one_install() {
        let mut slot = JitTieredCodeSlot::new();
        let first = opaque_test_code_pointer_at(0x10);
        let second = opaque_test_code_pointer_at(0x20);

        slot.install_tier1_code(first)
            .expect("initial install succeeds");

        let error = slot
            .install_tier1_code(second)
            .expect_err("duplicate install is rejected");

        assert_eq!(
            error,
            JitTieredCodeSlotError::Tier1CodeAlreadyInstalled {
                current_tier: JitTier::Tier1Baseline
            }
        );
        assert_eq!(slot.tier1_code_ptr(), Some(first));
    }

    #[test]
    fn installed_tier_one_slot_does_not_request_repeat_promotion() {
        let mut slot = JitTieredCodeSlot::with_counter(TierUpCounter::new(u64::MAX));
        slot.install_tier1_code(opaque_test_code_pointer())
            .expect("tier-1 code metadata installs");

        let decision = slot.record_invocation_with_demand_hint(
            TierUpPolicy::default(),
            TierUpDemandHint::MultiUse,
        );

        assert_eq!(slot.invocation_counter().invocations(), u64::MAX);
        assert_eq!(decision, TierUpDecision::StayInTier(JitTier::Tier1Baseline));
        assert_eq!(decision.reasons(), None);
    }
}
