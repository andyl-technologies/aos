//! Region-placement policy for future sub-arena reclamation.
//!
//! The active heap still uses [`super::BumpArena`] for one-shot evaluation. This
//! module records the conservative decision table that later IR and effect
//! analyses will feed when selecting a more precise allocation region. It is a
//! safe precursor: it does not allocate memory, pop regions, or change heap
//! behavior.

/// The runtime heap tier that receives allocations not proven region-local.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegionRuntimeTier {
    /// One-shot CLI evaluation backed by the root bump arena.
    OneShotArena,
    /// Long-lived daemon evaluation backed by the precise GC heap.
    DaemonGc,
}

/// Whether evaluating or forcing an allocation site may perform observable work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RegionEffect {
    /// The allocation site and any latent force are proven speculable.
    Speculable,
    /// The allocation site or latent force may perform observable work.
    #[default]
    Effectful,
}

/// The static lifetime shape known for an allocation site.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RegionLifetime {
    /// No bounded lexical lifetime has been proven.
    #[default]
    Unbounded,
    /// The value is bounded by a lexical subregion candidate.
    Lexical,
}

/// Whether an allocation participates in globally shared value storage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RegionSharing {
    /// The allocation is private to one evaluation result graph.
    #[default]
    Private,
    /// The allocation is hash-consed or otherwise permanently shared.
    SharedPermanent,
}

/// Conservative facts about one allocation site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AllocationRegionFacts {
    /// Whether the allocated value may escape its allocating frame.
    pub escapes_frame: bool,
    /// Whether a thunk-like value may be forced after its lexical region exits.
    pub has_latent_force: bool,
    /// Whether the allocation site and latent force are speculable.
    pub effect: RegionEffect,
    /// The known static lifetime shape.
    pub lifetime: RegionLifetime,
    /// Whether the value belongs in permanent shared storage.
    pub sharing: RegionSharing,
}

impl Default for AllocationRegionFacts {
    fn default() -> Self {
        Self::conservative()
    }
}

impl AllocationRegionFacts {
    /// Returns the fail-closed fact set for an unanalyzed allocation site.
    pub const fn conservative() -> Self {
        Self {
            escapes_frame: true,
            has_latent_force: true,
            effect: RegionEffect::Effectful,
            lifetime: RegionLifetime::Unbounded,
            sharing: RegionSharing::Private,
        }
    }

    /// Returns facts for a private lexical allocation proven not to escape.
    pub const fn lexical_no_escape() -> Self {
        Self {
            escapes_frame: false,
            has_latent_force: false,
            effect: RegionEffect::Speculable,
            lifetime: RegionLifetime::Lexical,
            sharing: RegionSharing::Private,
        }
    }
}

/// The heap placement selected for one allocation site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegionPlacement {
    /// Allocate in the root one-shot arena.
    RootArena,
    /// Allocate in a lexical subregion that may be popped before process exit.
    LexicalSubregion,
    /// Allocate in permanent shared space that is not reclaimed by region pop.
    PermanentShared,
    /// Allocate in the daemon's tracing heap.
    GarbageCollected,
}

/// Why a region placement was selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegionPlacementReason {
    /// Permanent sharing overrides local region reclamation.
    PermanentSharing,
    /// Positive no-escape, bounded-lifetime, and effect proofs allow a subregion.
    ProvenLexicalNoEscape,
    /// Missing or negative proofs fall back to the active runtime tier.
    ConservativeFallback,
}

/// The conservative region-placement decision for one allocation site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RegionPlan {
    /// The selected heap placement.
    pub placement: RegionPlacement,
    /// The reason the placement was selected.
    pub reason: RegionPlacementReason,
}

impl RegionPlan {
    /// Classifies one allocation site for the active runtime tier.
    pub const fn classify(tier: RegionRuntimeTier, facts: AllocationRegionFacts) -> Self {
        if matches!(facts.sharing, RegionSharing::SharedPermanent) {
            return Self {
                placement: RegionPlacement::PermanentShared,
                reason: RegionPlacementReason::PermanentSharing,
            };
        }

        if !facts.escapes_frame
            && !facts.has_latent_force
            && matches!(facts.effect, RegionEffect::Speculable)
            && matches!(facts.lifetime, RegionLifetime::Lexical)
            && matches!(facts.sharing, RegionSharing::Private)
        {
            return Self {
                placement: RegionPlacement::LexicalSubregion,
                reason: RegionPlacementReason::ProvenLexicalNoEscape,
            };
        }

        Self {
            placement: fallback_placement(tier),
            reason: RegionPlacementReason::ConservativeFallback,
        }
    }

    /// Returns whether this plan permits popping the selected region before the
    /// whole evaluation exits.
    pub const fn permits_early_pop(self) -> bool {
        matches!(self.placement, RegionPlacement::LexicalSubregion)
    }
}

const fn fallback_placement(tier: RegionRuntimeTier) -> RegionPlacement {
    match tier {
        RegionRuntimeTier::OneShotArena => RegionPlacement::RootArena,
        RegionRuntimeTier::DaemonGc => RegionPlacement::GarbageCollected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conservative_facts_fall_back_to_active_tier() {
        assert_eq!(
            AllocationRegionFacts::default(),
            AllocationRegionFacts::conservative()
        );
        assert_eq!(
            RegionPlan::classify(
                RegionRuntimeTier::OneShotArena,
                AllocationRegionFacts::conservative()
            ),
            RegionPlan {
                placement: RegionPlacement::RootArena,
                reason: RegionPlacementReason::ConservativeFallback,
            }
        );
        assert_eq!(
            RegionPlan::classify(
                RegionRuntimeTier::DaemonGc,
                AllocationRegionFacts::conservative()
            )
            .placement,
            RegionPlacement::GarbageCollected
        );
    }

    #[test]
    fn partial_default_facts_stay_conservative_without_positive_proofs() {
        let facts = AllocationRegionFacts {
            effect: RegionEffect::Speculable,
            lifetime: RegionLifetime::Lexical,
            ..AllocationRegionFacts::default()
        };

        let plan = RegionPlan::classify(RegionRuntimeTier::OneShotArena, facts);

        assert_eq!(plan.placement, RegionPlacement::RootArena);
        assert_eq!(plan.reason, RegionPlacementReason::ConservativeFallback);
    }

    #[test]
    fn lexical_no_escape_facts_select_pop_safe_subregions() {
        let plan = RegionPlan::classify(
            RegionRuntimeTier::OneShotArena,
            AllocationRegionFacts::lexical_no_escape(),
        );

        assert_eq!(plan.placement, RegionPlacement::LexicalSubregion);
        assert_eq!(plan.reason, RegionPlacementReason::ProvenLexicalNoEscape);
        assert!(plan.permits_early_pop());
    }

    #[test]
    fn escape_effect_and_latent_force_each_block_region_pop() {
        for facts in [
            AllocationRegionFacts {
                escapes_frame: true,
                ..AllocationRegionFacts::lexical_no_escape()
            },
            AllocationRegionFacts {
                has_latent_force: true,
                ..AllocationRegionFacts::lexical_no_escape()
            },
            AllocationRegionFacts {
                effect: RegionEffect::Effectful,
                ..AllocationRegionFacts::lexical_no_escape()
            },
            AllocationRegionFacts {
                lifetime: RegionLifetime::Unbounded,
                ..AllocationRegionFacts::lexical_no_escape()
            },
        ] {
            let plan = RegionPlan::classify(RegionRuntimeTier::OneShotArena, facts);

            assert_eq!(plan.placement, RegionPlacement::RootArena);
            assert!(!plan.permits_early_pop());
        }
    }

    #[test]
    fn permanent_shared_values_bypass_region_pop() {
        let facts = AllocationRegionFacts {
            sharing: RegionSharing::SharedPermanent,
            ..AllocationRegionFacts::lexical_no_escape()
        };

        let plan = RegionPlan::classify(RegionRuntimeTier::DaemonGc, facts);

        assert_eq!(plan.placement, RegionPlacement::PermanentShared);
        assert_eq!(plan.reason, RegionPlacementReason::PermanentSharing);
        assert!(!plan.permits_early_pop());
    }

    #[test]
    fn lexical_subregions_require_private_sharing() {
        let mut facts = AllocationRegionFacts::lexical_no_escape();
        facts.sharing = RegionSharing::SharedPermanent;

        let plan = RegionPlan::classify(RegionRuntimeTier::OneShotArena, facts);

        assert_eq!(plan.placement, RegionPlacement::PermanentShared);
        assert!(!plan.permits_early_pop());
    }
}
