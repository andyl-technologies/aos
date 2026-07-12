//! Safepoint and user-stack-map policy metadata for compiled tiers.
//!
//! RFC-0007 requires compiled tiers to emit safepoints and user stack maps
//! unconditionally, with safepoints at allocation sites and calls to `aos_force`.
//! This module records that frontend obligation before the CLIF stack-map
//! emission path exists. It does not emit Cranelift stack maps, register runtime
//! symbols, allocate executable memory, or inspect collector roots.

/// A compiled JIT tier that must obey the safepoint policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitSafepointTier {
    /// The baseline Cranelift tier.
    Tier1Baseline,
    /// The optimized Cranelift tier.
    Tier2Optimized,
}

/// A program point where compiled code must expose live GC references.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitSafepointPlacement {
    /// A runtime allocation helper call site.
    AllocationSite,
    /// A call to the `aos_force` runtime helper.
    ForceCall,
}

/// Required safepoint placements for every compiled JIT tier.
pub const REQUIRED_JIT_SAFEPOINT_PLACEMENTS: &[JitSafepointPlacement] = &[
    JitSafepointPlacement::AllocationSite,
    JitSafepointPlacement::ForceCall,
];

/// The safepoint and user-stack-map obligation for compiled JIT tiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JitSafepointPolicy {
    tier: JitSafepointTier,
    emit_unconditionally: bool,
    user_stack_maps_required: bool,
    placements: &'static [JitSafepointPlacement],
}

impl JitSafepointPolicy {
    /// Creates a safepoint policy for one compiled tier.
    pub const fn new(
        tier: JitSafepointTier,
        emit_unconditionally: bool,
        user_stack_maps_required: bool,
        placements: &'static [JitSafepointPlacement],
    ) -> Self {
        Self {
            tier,
            emit_unconditionally,
            user_stack_maps_required,
            placements,
        }
    }

    /// Returns the compiled tier covered by this policy.
    pub const fn tier(self) -> JitSafepointTier {
        self.tier
    }

    /// Returns whether safepoints are emitted even when the active heap ignores them.
    pub const fn emit_unconditionally(self) -> bool {
        self.emit_unconditionally
    }

    /// Returns whether each safepoint must carry user-stack-map metadata.
    pub const fn user_stack_maps_required(self) -> bool {
        self.user_stack_maps_required
    }

    /// Returns the program points that must carry safepoints.
    pub const fn placements(self) -> &'static [JitSafepointPlacement] {
        self.placements
    }

    /// Returns whether this policy requires safepoints at `placement`.
    pub fn requires_placement(self, placement: JitSafepointPlacement) -> bool {
        self.placements.contains(&placement)
    }
}

/// Returns the safepoint policy for a compiled JIT tier.
pub const fn jit_safepoint_policy(tier: JitSafepointTier) -> JitSafepointPolicy {
    JitSafepointPolicy::new(tier, true, true, REQUIRED_JIT_SAFEPOINT_PLACEMENTS)
}

// JIT is off by construction under the Candidate-C variant; these tier-1 lowering/codegen tests re-enable at S4b (cutover plan section 6.1).
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use super::*;

    #[test]
    fn tier1_policy_emits_unconditional_user_stack_maps() {
        let policy = jit_safepoint_policy(JitSafepointTier::Tier1Baseline);

        assert_eq!(policy.tier(), JitSafepointTier::Tier1Baseline);
        assert!(policy.emit_unconditionally());
        assert!(policy.user_stack_maps_required());
    }

    #[test]
    fn tier2_policy_shares_the_compiled_tier_obligation() {
        let policy = jit_safepoint_policy(JitSafepointTier::Tier2Optimized);

        assert_eq!(policy.tier(), JitSafepointTier::Tier2Optimized);
        assert!(policy.emit_unconditionally());
        assert!(policy.user_stack_maps_required());
        assert_eq!(policy.placements(), REQUIRED_JIT_SAFEPOINT_PLACEMENTS);
    }

    #[test]
    fn required_placements_cover_all_collection_trigger_points() {
        let policy = jit_safepoint_policy(JitSafepointTier::Tier1Baseline);

        assert_eq!(
            policy.placements(),
            &[
                JitSafepointPlacement::AllocationSite,
                JitSafepointPlacement::ForceCall,
            ]
        );
        assert!(policy.requires_placement(JitSafepointPlacement::AllocationSite));
        assert!(policy.requires_placement(JitSafepointPlacement::ForceCall));
    }
}
