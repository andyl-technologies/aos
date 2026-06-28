//! Attribute-set representation policy for future Flat/HAMT selection.
//!
//! The active runtime still stores attrsets as [`crate::attrs::FlatAttrs`].
//! This module only records the measured-policy contract for choosing between a
//! flat shaped value array and a future persistent HAMT representation. The
//! decision is deliberately internal: both representations must expose the same
//! ordered attrset view, so the choice can change allocation and copy cost but
//! never observable Nix values or `.drv` bytes.

use thiserror::Error;

/// Default size threshold above which dynamic attrsets prefer HAMT storage.
pub const DEFAULT_FLAT_ATTR_THRESHOLD: usize = 64;
/// Default override-chain depth at which repeated updates prefer HAMT.
pub const DEFAULT_OVERRIDE_CHAIN_THRESHOLD: usize = 4;

/// The backing representation selected for an immutable attrset value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttrSetReprKind {
    /// Shape descriptor plus flat value array.
    Flat,
    /// Persistent HAMT/CHAMP-style map with a memoized ordered view.
    Hamt,
}

/// The construction operation being classified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttrSetConstruction {
    /// A static attrset literal or other shape-stable construction site.
    ///
    /// Static literals are exempt from the flat-size threshold in this
    /// precursor because their shape is known ahead of allocation.
    StaticLiteral {
        /// Number of bindings in the constructed attrset.
        len: usize,
    },
    /// A dynamic attrset construction without a static literal shape proof.
    Dynamic {
        /// Number of bindings in the constructed attrset.
        len: usize,
    },
    /// A `//` update/merge result.
    UpdateMerge {
        /// Representation of the left operand.
        left_repr: AttrSetReprKind,
        /// Number of bindings in the left operand.
        left_len: usize,
        /// Number of bindings introduced or overwritten by the right operand.
        right_len: usize,
        /// Known depth of the override chain ending at this merge.
        override_chain_depth: usize,
    },
}

impl AttrSetConstruction {
    /// Returns the result binding count when it can be derived without overflow.
    ///
    /// For [`AttrSetConstruction::UpdateMerge`], this is a conservative upper
    /// bound because overwritten keys may not increase the final result length.
    pub const fn result_len_upper_bound(self) -> Option<usize> {
        match self {
            Self::StaticLiteral { len } | Self::Dynamic { len } => Some(len),
            Self::UpdateMerge {
                left_len,
                right_len,
                ..
            } => left_len.checked_add(right_len),
        }
    }
}

/// Tunable thresholds for the Flat/HAMT policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttrSetReprPolicy {
    flat_attr_threshold: usize,
    override_chain_threshold: usize,
}

impl AttrSetReprPolicy {
    /// Creates a representation policy with explicit thresholds.
    ///
    /// # Errors
    ///
    /// Returns [`AttrSetReprPolicyError::ZeroFlatThreshold`] when
    /// `flat_attr_threshold` is zero, or
    /// [`AttrSetReprPolicyError::ZeroOverrideChainThreshold`] when
    /// `override_chain_threshold` is zero.
    pub const fn new(
        flat_attr_threshold: usize,
        override_chain_threshold: usize,
    ) -> Result<Self, AttrSetReprPolicyError> {
        if flat_attr_threshold == 0 {
            Err(AttrSetReprPolicyError::ZeroFlatThreshold)
        } else if override_chain_threshold == 0 {
            Err(AttrSetReprPolicyError::ZeroOverrideChainThreshold)
        } else {
            Ok(Self {
                flat_attr_threshold,
                override_chain_threshold,
            })
        }
    }

    /// Returns the maximum result size preferred for flat storage.
    pub const fn flat_attr_threshold(self) -> usize {
        self.flat_attr_threshold
    }

    /// Returns the override-chain depth at or above which HAMT is preferred.
    pub const fn override_chain_threshold(self) -> usize {
        self.override_chain_threshold
    }

    /// Classifies an attrset construction under this policy.
    ///
    /// Static literals stay flat regardless of size because their shape is
    /// known. Small dynamic values also stay flat; existing HAMT left operands,
    /// large update results, and deep override chains prefer HAMT.
    ///
    /// # Errors
    ///
    /// Returns [`AttrSetReprPolicyError::LengthOverflow`] when a merge length
    /// upper bound cannot be represented in `usize`.
    pub const fn classify(
        self,
        construction: AttrSetConstruction,
    ) -> Result<AttrSetReprDecision, AttrSetReprPolicyError> {
        match construction {
            AttrSetConstruction::StaticLiteral { len } => Ok(AttrSetReprDecision::Flat {
                result_len_upper_bound: len,
                reason: AttrSetReprReason::StaticLiteral,
            }),
            AttrSetConstruction::Dynamic { len } => {
                if len <= self.flat_attr_threshold {
                    Ok(AttrSetReprDecision::Flat {
                        result_len_upper_bound: len,
                        reason: AttrSetReprReason::SmallShapeStable,
                    })
                } else {
                    Ok(AttrSetReprDecision::Hamt {
                        result_len_upper_bound: len,
                        reason: AttrSetReprReason::LargeDynamicConstruction,
                    })
                }
            }
            AttrSetConstruction::UpdateMerge {
                left_repr,
                left_len,
                right_len,
                override_chain_depth,
            } => {
                let Some(result_len_upper_bound) = left_len.checked_add(right_len) else {
                    return Err(AttrSetReprPolicyError::LengthOverflow {
                        left_len,
                        right_len,
                    });
                };

                if matches!(left_repr, AttrSetReprKind::Hamt) {
                    Ok(AttrSetReprDecision::Hamt {
                        result_len_upper_bound,
                        reason: AttrSetReprReason::LeftAlreadyHamt,
                    })
                } else if override_chain_depth >= self.override_chain_threshold {
                    Ok(AttrSetReprDecision::Hamt {
                        result_len_upper_bound,
                        reason: AttrSetReprReason::DeepOverrideChain,
                    })
                } else if result_len_upper_bound > self.flat_attr_threshold {
                    Ok(AttrSetReprDecision::Hamt {
                        result_len_upper_bound,
                        reason: AttrSetReprReason::LargeUpdateMerge,
                    })
                } else {
                    Ok(AttrSetReprDecision::Flat {
                        result_len_upper_bound,
                        reason: AttrSetReprReason::SmallShapeStable,
                    })
                }
            }
        }
    }
}

impl Default for AttrSetReprPolicy {
    fn default() -> Self {
        Self {
            flat_attr_threshold: DEFAULT_FLAT_ATTR_THRESHOLD,
            override_chain_threshold: DEFAULT_OVERRIDE_CHAIN_THRESHOLD,
        }
    }
}

/// A representation decision for one attrset construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttrSetReprDecision {
    /// Store as a shape plus flat value array.
    Flat {
        /// Conservative upper bound on the resulting binding count.
        result_len_upper_bound: usize,
        /// Why flat storage was selected.
        reason: AttrSetReprReason,
    },
    /// Store as a future persistent HAMT/CHAMP map.
    Hamt {
        /// Conservative upper bound on the resulting binding count.
        result_len_upper_bound: usize,
        /// Why HAMT storage was selected.
        reason: AttrSetReprReason,
    },
}

impl AttrSetReprDecision {
    /// Returns the selected backing representation.
    pub const fn kind(self) -> AttrSetReprKind {
        match self {
            Self::Flat { .. } => AttrSetReprKind::Flat,
            Self::Hamt { .. } => AttrSetReprKind::Hamt,
        }
    }

    /// Returns the decision reason.
    pub const fn reason(self) -> AttrSetReprReason {
        match self {
            Self::Flat { reason, .. } | Self::Hamt { reason, .. } => reason,
        }
    }

    /// Returns whether this representation needs a memoized ordered view.
    ///
    /// Flat values get ordered iteration from their shape permutation. HAMT
    /// values need an ordered view derived from keys and cached beside the root.
    pub const fn requires_hamt_ordered_view(self) -> bool {
        matches!(self, Self::Hamt { .. })
    }
}

/// The policy reason behind an attrset representation decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttrSetReprReason {
    /// Static literals stay flat because their result shape is known.
    StaticLiteral,
    /// The result is small enough for flat copy to remain preferred.
    SmallShapeStable,
    /// The left operand is already HAMT-backed, so structural sharing continues.
    LeftAlreadyHamt,
    /// The result is too large for flat-copy preference.
    LargeUpdateMerge,
    /// The override chain is deep enough to prefer structural sharing.
    DeepOverrideChain,
    /// A dynamic construction exceeded the flat-size threshold.
    LargeDynamicConstruction,
}

/// A failed attrset representation-policy operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AttrSetReprPolicyError {
    /// The flat-size threshold was zero.
    #[error("flat attrset threshold must be greater than zero")]
    ZeroFlatThreshold,
    /// The override-chain threshold was zero.
    #[error("override-chain threshold must be greater than zero")]
    ZeroOverrideChainThreshold,
    /// A merge result length overflowed `usize`.
    #[error("attrset merge length overflow while combining {left_len} and {right_len}")]
    LengthOverflow {
        /// The left operand length.
        left_len: usize,
        /// The right operand length.
        right_len: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_keeps_static_literals_flat_regardless_of_size() {
        let policy = AttrSetReprPolicy::default();

        assert_eq!(
            policy.classify(AttrSetConstruction::StaticLiteral { len: 10_000 }),
            Ok(AttrSetReprDecision::Flat {
                result_len_upper_bound: 10_000,
                reason: AttrSetReprReason::StaticLiteral,
            })
        );
    }

    #[test]
    fn dynamic_constructions_cross_flat_size_threshold() {
        let policy = AttrSetReprPolicy::new(2, 4).expect("thresholds are nonzero");

        assert_eq!(
            policy
                .classify(AttrSetConstruction::Dynamic { len: 2 })
                .expect("classification succeeds")
                .kind(),
            AttrSetReprKind::Flat
        );
        assert_eq!(
            policy.classify(AttrSetConstruction::Dynamic { len: 3 }),
            Ok(AttrSetReprDecision::Hamt {
                result_len_upper_bound: 3,
                reason: AttrSetReprReason::LargeDynamicConstruction,
            })
        );
    }

    #[test]
    fn small_flat_update_merge_stays_flat() {
        let policy = AttrSetReprPolicy::new(8, 4).expect("thresholds are nonzero");

        assert_eq!(
            policy.classify(AttrSetConstruction::UpdateMerge {
                left_repr: AttrSetReprKind::Flat,
                left_len: 4,
                right_len: 2,
                override_chain_depth: 1,
            }),
            Ok(AttrSetReprDecision::Flat {
                result_len_upper_bound: 6,
                reason: AttrSetReprReason::SmallShapeStable,
            })
        );
    }

    #[test]
    fn existing_hamt_left_operand_preserves_structural_sharing() {
        let policy = AttrSetReprPolicy::new(100, 10).expect("thresholds are nonzero");

        assert_eq!(
            policy.classify(AttrSetConstruction::UpdateMerge {
                left_repr: AttrSetReprKind::Hamt,
                left_len: 1,
                right_len: 1,
                override_chain_depth: 0,
            }),
            Ok(AttrSetReprDecision::Hamt {
                result_len_upper_bound: 2,
                reason: AttrSetReprReason::LeftAlreadyHamt,
            })
        );
    }

    #[test]
    fn large_or_deep_flat_update_merges_prefer_hamt() {
        let policy = AttrSetReprPolicy::new(5, 3).expect("thresholds are nonzero");

        assert_eq!(
            policy.classify(AttrSetConstruction::UpdateMerge {
                left_repr: AttrSetReprKind::Flat,
                left_len: 5,
                right_len: 1,
                override_chain_depth: 1,
            }),
            Ok(AttrSetReprDecision::Hamt {
                result_len_upper_bound: 6,
                reason: AttrSetReprReason::LargeUpdateMerge,
            })
        );
        assert_eq!(
            policy.classify(AttrSetConstruction::UpdateMerge {
                left_repr: AttrSetReprKind::Flat,
                left_len: 1,
                right_len: 1,
                override_chain_depth: 3,
            }),
            Ok(AttrSetReprDecision::Hamt {
                result_len_upper_bound: 2,
                reason: AttrSetReprReason::DeepOverrideChain,
            })
        );
    }

    #[test]
    fn hamt_decisions_require_ordered_view_memoization() {
        let flat = AttrSetReprDecision::Flat {
            result_len_upper_bound: 1,
            reason: AttrSetReprReason::SmallShapeStable,
        };
        let hamt = AttrSetReprDecision::Hamt {
            result_len_upper_bound: 100,
            reason: AttrSetReprReason::LargeUpdateMerge,
        };

        assert!(!flat.requires_hamt_ordered_view());
        assert!(hamt.requires_hamt_ordered_view());
    }

    #[test]
    fn invalid_thresholds_and_length_overflow_are_reported() {
        assert_eq!(
            AttrSetReprPolicy::new(0, 1),
            Err(AttrSetReprPolicyError::ZeroFlatThreshold)
        );
        assert_eq!(
            AttrSetReprPolicy::new(1, 0),
            Err(AttrSetReprPolicyError::ZeroOverrideChainThreshold)
        );

        let policy = AttrSetReprPolicy::default();
        assert_eq!(
            policy.classify(AttrSetConstruction::UpdateMerge {
                left_repr: AttrSetReprKind::Flat,
                left_len: usize::MAX,
                right_len: 1,
                override_chain_depth: 0,
            }),
            Err(AttrSetReprPolicyError::LengthOverflow {
                left_len: usize::MAX,
                right_len: 1,
            })
        );
    }
}
