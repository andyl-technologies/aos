//! Attribute-set representation policy for future Flat/HAMT selection.
//!
//! The active runtime still stores attrsets as [`crate::attrs::FlatAttrs`].
//! This module only records the measured-policy contract for choosing between a
//! flat shaped value array and a future persistent HAMT representation. The
//! decision is deliberately internal: both representations must expose the same
//! ordered attrset view, so the choice can change allocation and copy cost but
//! never observable Nix values or `.drv` bytes.

use thiserror::Error;

use crate::attrs::hamt::{HamtAttrs, HamtError, HamtMergeSummary};
use crate::attrs::{AttrError, FlatAttrs};
use crate::syntax::{Symbol, SymbolTable};
use crate::value::Value;

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

    /// Returns the conservative upper bound on the result binding count.
    pub const fn result_len_upper_bound(self) -> usize {
        match self {
            Self::Flat {
                result_len_upper_bound,
                ..
            }
            | Self::Hamt {
                result_len_upper_bound,
                ..
            } => result_len_upper_bound,
        }
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

/// A safe Flat/HAMT attrset value used by representation-policy precursors.
///
/// This wrapper is not the active evaluator attrset representation. It gives
/// RFC-0007 phase-5 helpers one dispatch point for exercising flat copy versus
/// HAMT structural sharing under [`AttrSetReprPolicy`].
#[derive(Clone, Debug)]
pub enum AttrSetReprValue {
    /// A flat attrset.
    Flat(FlatAttrs),
    /// A HAMT-backed attrset.
    Hamt(HamtAttrs),
}

impl AttrSetReprValue {
    /// Wraps a flat attrset.
    pub const fn from_flat(attrs: FlatAttrs) -> Self {
        Self::Flat(attrs)
    }

    /// Wraps a HAMT attrset.
    pub const fn from_hamt(attrs: HamtAttrs) -> Self {
        Self::Hamt(attrs)
    }

    /// Returns the backing representation kind.
    pub const fn kind(&self) -> AttrSetReprKind {
        match self {
            Self::Flat(_) => AttrSetReprKind::Flat,
            Self::Hamt(_) => AttrSetReprKind::Hamt,
        }
    }

    /// Returns the number of bindings.
    pub fn len(&self) -> usize {
        match self {
            Self::Flat(attrs) => attrs.len(),
            Self::Hamt(attrs) => attrs.len(),
        }
    }

    /// Returns whether this attrset has no bindings.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the value for `key`.
    ///
    /// `key` must come from the same symbol universe used to construct this
    /// attrset.
    pub fn get(&self, key: Symbol) -> Option<Value> {
        match self {
            Self::Flat(attrs) => attrs.get(key),
            Self::Hamt(attrs) => attrs.get(key),
        }
    }

    /// Returns the flat attrset if this value is flat.
    pub const fn as_flat(&self) -> Option<&FlatAttrs> {
        match self {
            Self::Flat(attrs) => Some(attrs),
            Self::Hamt(_) => None,
        }
    }

    /// Returns the HAMT attrset if this value is HAMT-backed.
    pub const fn as_hamt(&self) -> Option<&HamtAttrs> {
        match self {
            Self::Flat(_) => None,
            Self::Hamt(attrs) => Some(attrs),
        }
    }

    /// Applies a flat right-hand operand using the representation policy.
    ///
    /// Small flat-left merges are copied into a new [`FlatAttrs`] preserving
    /// left source-order slots, right-biased values for shared keys, and
    /// right-only keys appended in right source order. Merges classified as
    /// HAMT convert a flat left operand as needed, then use persistent HAMT
    /// insert/replace operations. `self`, `right`, and `symbols` must belong
    /// to the same symbol universe.
    ///
    /// This is a value-level precursor only; the tree-walk evaluator may use it
    /// for shadow telemetry, but it is not the active runtime attrset storage.
    ///
    /// # Errors
    ///
    /// Returns [`AttrSetReprValueError::Policy`] if policy classification
    /// fails, [`AttrSetReprValueError::InconsistentPolicyDecision`] if a
    /// policy decision violates representation-dispatch invariants,
    /// [`AttrSetReprValueError::LengthOverflow`] if flat result planning
    /// overflows, [`AttrSetReprValueError::Flat`] if flat result construction
    /// fails, or [`AttrSetReprValueError::Hamt`] if HAMT conversion or merge
    /// fails.
    pub fn update_from_flat_right(
        &self,
        right: &FlatAttrs,
        policy: AttrSetReprPolicy,
        override_chain_depth: usize,
        symbols: &SymbolTable,
    ) -> Result<AttrSetUpdateMerge, AttrSetReprValueError> {
        let decision = policy.classify(AttrSetConstruction::UpdateMerge {
            left_repr: self.kind(),
            left_len: self.len(),
            right_len: right.len(),
            override_chain_depth,
        })?;

        match (decision.kind(), self) {
            (AttrSetReprKind::Flat, Self::Flat(left)) => {
                let flat = merge_flat_right(left, right, symbols)?;
                Ok(AttrSetUpdateMerge {
                    value: Self::Flat(flat),
                    decision,
                    hamt_summary: None,
                })
            }
            (AttrSetReprKind::Flat, Self::Hamt(_)) => {
                Err(AttrSetReprValueError::InconsistentPolicyDecision {
                    left_repr: AttrSetReprKind::Hamt,
                    decision_repr: AttrSetReprKind::Flat,
                })
            }
            (AttrSetReprKind::Hamt, Self::Flat(left)) => {
                let base = HamtAttrs::from_flat(left, symbols)?;
                let (hamt, summary) = base.update_from_flat(right, symbols)?;
                Ok(AttrSetUpdateMerge {
                    value: Self::Hamt(hamt),
                    decision,
                    hamt_summary: Some(summary),
                })
            }
            (AttrSetReprKind::Hamt, Self::Hamt(left)) => {
                let (hamt, summary) = left.update_from_flat(right, symbols)?;
                Ok(AttrSetUpdateMerge {
                    value: Self::Hamt(hamt),
                    decision,
                    hamt_summary: Some(summary),
                })
            }
        }
    }
}

/// The result of a policy-dispatched update merge.
#[derive(Clone, Debug)]
pub struct AttrSetUpdateMerge {
    value: AttrSetReprValue,
    decision: AttrSetReprDecision,
    hamt_summary: Option<HamtMergeSummary>,
}

impl AttrSetUpdateMerge {
    /// Returns the merged attrset value.
    pub const fn value(&self) -> &AttrSetReprValue {
        &self.value
    }

    /// Consumes this result and returns the merged attrset value.
    pub fn into_value(self) -> AttrSetReprValue {
        self.value
    }

    /// Returns the policy decision used for the merge.
    pub const fn decision(&self) -> AttrSetReprDecision {
        self.decision
    }

    /// Returns HAMT merge accounting when the selected result is HAMT-backed.
    pub const fn hamt_summary(&self) -> Option<HamtMergeSummary> {
        self.hamt_summary
    }
}

fn merge_flat_right(
    left: &FlatAttrs,
    right: &FlatAttrs,
    symbols: &SymbolTable,
) -> Result<FlatAttrs, AttrSetReprValueError> {
    let appended_right = right
        .iter_source_order()
        .filter(|entry| !left.contains_key(entry.key))
        .count();
    let result_len =
        left.len()
            .checked_add(appended_right)
            .ok_or(AttrSetReprValueError::LengthOverflow {
                left_len: left.len(),
                right_len: appended_right,
            })?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(result_len).map_err(|_| {
        AttrSetReprValueError::Flat(AttrError::AllocationFailed {
            entries: result_len,
        })
    })?;

    for entry in left.iter_source_order() {
        entries.push(right.get_entry(entry.key).copied().unwrap_or(*entry));
    }
    for entry in right.iter_source_order() {
        if !left.contains_key(entry.key) {
            entries.push(*entry);
        }
    }

    FlatAttrs::new(entries, symbols).map_err(AttrSetReprValueError::Flat)
}

/// A failed policy-dispatched attrset representation operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AttrSetReprValueError {
    /// Representation-policy classification failed.
    #[error("attrset representation policy failed: {0}")]
    Policy(#[from] AttrSetReprPolicyError),
    /// The policy returned a result representation that violates dispatch invariants.
    #[error("policy selected {decision_repr:?} result for {left_repr:?} left operand")]
    InconsistentPolicyDecision {
        /// The left operand representation.
        left_repr: AttrSetReprKind,
        /// The selected result representation.
        decision_repr: AttrSetReprKind,
    },
    /// A planned flat update result length overflowed.
    #[error("flat attrset update length overflow while combining {left_len} and {right_len}")]
    LengthOverflow {
        /// The left operand length.
        left_len: usize,
        /// The right-only binding count.
        right_len: usize,
    },
    /// Flat attrset construction failed.
    #[error("flat attrset update failed: {0}")]
    Flat(#[from] AttrError),
    /// HAMT construction or update failed.
    #[error("HAMT attrset update failed: {0}")]
    Hamt(#[from] HamtError),
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
    use crate::attrs::{AttrEntry, AttrPosition};
    use crate::syntax::Span;

    fn symbols(names: &[&[u8]]) -> (SymbolTable, Vec<Symbol>) {
        let mut table = SymbolTable::new();
        let mut ids = Vec::new();
        for name in names {
            ids.push(table.intern(name).expect("symbol interns"));
        }
        (table, ids)
    }

    fn source_ints(attrs: &FlatAttrs, symbols: &SymbolTable) -> Vec<(Vec<u8>, i64)> {
        attrs
            .iter_source_order()
            .map(|entry| {
                (
                    symbols.resolve(entry.key).expect("key resolves").to_vec(),
                    entry.value.as_int().expect("value is int"),
                )
            })
            .collect()
    }

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

    #[test]
    fn update_dispatch_keeps_small_flat_merge_flat() {
        let (symbols, ids) = symbols(&[b"a", b"b", b"c", b"d"]);
        let left = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[1], Value::int(20)),
                AttrEntry::new(ids[2], Value::int(30)),
                AttrEntry::new(ids[0], Value::int(10)),
            ],
            &symbols,
        )
        .expect("left flat attrs build");
        let right = FlatAttrs::new(
            vec![
                AttrEntry::with_position(
                    ids[1],
                    Value::int(200),
                    AttrPosition::new(1, Span::new(4, 5)),
                ),
                AttrEntry::new(ids[3], Value::int(40)),
            ],
            &symbols,
        )
        .expect("right flat attrs build");
        let policy = AttrSetReprPolicy::new(8, 4).expect("thresholds are nonzero");

        let result = AttrSetReprValue::from_flat(left)
            .update_from_flat_right(&right, policy, 1, &symbols)
            .expect("update dispatch succeeds");

        assert_eq!(
            result.decision(),
            AttrSetReprDecision::Flat {
                result_len_upper_bound: 5,
                reason: AttrSetReprReason::SmallShapeStable,
            }
        );
        assert_eq!(result.hamt_summary(), None);
        let flat = result.value().as_flat().expect("small merge stays flat");
        assert_eq!(
            source_ints(flat, &symbols),
            vec![
                (b"b".to_vec(), 200),
                (b"c".to_vec(), 30),
                (b"a".to_vec(), 10),
                (b"d".to_vec(), 40),
            ]
        );
        assert_eq!(
            flat.get_entry(ids[1]).expect("b exists").position,
            Some(AttrPosition::new(1, Span::new(4, 5)))
        );
    }

    #[test]
    fn update_dispatch_flat_result_recomputes_raw_byte_lexicographic_order() {
        let (symbols, ids) = symbols(&[b"b", b"a\xff", b"a", b"a\x00"]);
        let left = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[0], Value::int(10)),
                AttrEntry::new(ids[1], Value::int(20)),
            ],
            &symbols,
        )
        .expect("left flat attrs build");
        let right = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[2], Value::int(30)),
                AttrEntry::new(ids[3], Value::int(40)),
            ],
            &symbols,
        )
        .expect("right flat attrs build");
        let policy = AttrSetReprPolicy::new(8, 4).expect("thresholds are nonzero");

        let result = AttrSetReprValue::from_flat(left)
            .update_from_flat_right(&right, policy, 1, &symbols)
            .expect("update dispatch succeeds");

        let flat = result.value().as_flat().expect("small merge stays flat");
        let names: Vec<&[u8]> = flat
            .iter_lexicographic()
            .map(|entry| symbols.resolve(entry.key).expect("key resolves"))
            .collect();
        assert_eq!(
            names,
            vec![
                b"a".as_slice(),
                b"a\x00".as_slice(),
                b"a\xff".as_slice(),
                b"b".as_slice(),
            ]
        );
    }

    #[test]
    fn update_dispatch_promotes_large_flat_merge_to_hamt() {
        let (symbols, ids) = symbols(&[b"b", b"a\xff", b"a", b"a\x00"]);
        let left = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[0], Value::int(10)),
                AttrEntry::new(ids[1], Value::int(20)),
            ],
            &symbols,
        )
        .expect("left flat attrs build");
        let right = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[0], Value::int(100)),
                AttrEntry::new(ids[2], Value::int(30)),
                AttrEntry::new(ids[3], Value::int(40)),
            ],
            &symbols,
        )
        .expect("right flat attrs build");
        let policy = AttrSetReprPolicy::new(2, 4).expect("thresholds are nonzero");

        let result = AttrSetReprValue::from_flat(left)
            .update_from_flat_right(&right, policy, 1, &symbols)
            .expect("update dispatch succeeds");

        assert_eq!(
            result.decision(),
            AttrSetReprDecision::Hamt {
                result_len_upper_bound: 5,
                reason: AttrSetReprReason::LargeUpdateMerge,
            }
        );
        let summary = result.hamt_summary().expect("HAMT summary is recorded");
        assert_eq!(summary.inserted(), 2);
        assert_eq!(summary.replaced(), 1);
        let hamt = result.value().as_hamt().expect("large merge promotes");
        assert_eq!(hamt.get(ids[0]).expect("b exists").as_int(), Ok(100));
        let names: Vec<&[u8]> = hamt
            .iter_lexicographic()
            .map(|entry| symbols.resolve(entry.key).expect("key resolves"))
            .collect();
        assert_eq!(
            names,
            vec![
                b"a".as_slice(),
                b"a\x00".as_slice(),
                b"a\xff".as_slice(),
                b"b".as_slice(),
            ]
        );
    }

    #[test]
    fn update_dispatch_keeps_hamt_left_operand_hamt() {
        let (symbols, ids) = symbols(&[b"a", b"b", b"c"]);
        let left = HamtAttrs::new(
            vec![
                AttrEntry::new(ids[0], Value::int(10)),
                AttrEntry::new(ids[1], Value::int(20)),
            ],
            &symbols,
        )
        .expect("left HAMT builds");
        let right = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[1], Value::int(200)),
                AttrEntry::new(ids[2], Value::int(30)),
            ],
            &symbols,
        )
        .expect("right flat attrs build");
        let policy = AttrSetReprPolicy::new(100, 100).expect("thresholds are nonzero");

        let result = AttrSetReprValue::from_hamt(left)
            .update_from_flat_right(&right, policy, 1, &symbols)
            .expect("update dispatch succeeds");

        assert_eq!(
            result.decision(),
            AttrSetReprDecision::Hamt {
                result_len_upper_bound: 4,
                reason: AttrSetReprReason::LeftAlreadyHamt,
            }
        );
        let summary = result.hamt_summary().expect("HAMT summary is recorded");
        assert_eq!(summary.inserted(), 1);
        assert_eq!(summary.replaced(), 1);
        let hamt = result.value().as_hamt().expect("HAMT left stays HAMT");
        assert_eq!(hamt.len(), 3);
        assert_eq!(hamt.get(ids[1]).expect("b exists").as_int(), Ok(200));
    }
}
