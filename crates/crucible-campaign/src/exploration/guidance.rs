//! Exact fixed-point guidance arithmetic.
//!
//! This module owns the language-neutral integer arithmetic used by future
//! adaptive planner engines. It deliberately does not select a continuation:
//! owner-built reward, novelty, and finding projections must land before a
//! planner version may use these scores to change canonical ordering.

use std::cmp::Ordering;

use crate::{CampaignCodecError, ProgressiveWideningPolicy, PuctPolicy};

/// One whole unit in the campaign fixed-point representation.
pub const GUIDANCE_MICROS_PER_UNIT: u64 = 1_000_000;

/// Exact owner-derived progressive-widening admission decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProgressiveWideningDecision {
    permitted_children: u64,
    required_completed_visits: u128,
    visit_floor_satisfied: bool,
    eligible: bool,
}

impl ProgressiveWideningDecision {
    /// Derives one widening decision without floating-point arithmetic.
    ///
    /// The initial child allocation is available without feedback. Once it is
    /// consumed, every additional child requires at least
    /// `admitted_children * minimum_visits_per_child` completed visits as well
    /// as room under the exact power-law and hard child ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when the authenticated
    /// admitted-child count exceeds the policy's hard ceiling.
    pub fn derive(
        policy: ProgressiveWideningPolicy,
        completed_visits: u64,
        admitted_children: u64,
    ) -> Result<Self, CampaignCodecError> {
        if admitted_children > policy.maximum_children() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "progressive-widening child count exceeds policy",
            });
        }

        let power_law_children =
            power_law_children_capped(policy, completed_visits, policy.maximum_children())?;
        let permitted_children = policy
            .initial_children()
            .max(power_law_children)
            .min(policy.maximum_children());
        let required_completed_visits = if admitted_children < policy.initial_children() {
            0
        } else {
            u128::from(admitted_children) * u128::from(policy.minimum_visits_per_child())
        };
        let visit_floor_satisfied = u128::from(completed_visits) >= required_completed_visits;
        let eligible = admitted_children < permitted_children && visit_floor_satisfied;

        Ok(Self {
            permitted_children,
            required_completed_visits,
            visit_floor_satisfied,
            eligible,
        })
    }

    /// Returns the exact number of children currently permitted by policy.
    #[must_use]
    pub const fn permitted_children(self) -> u64 {
        self.permitted_children
    }

    /// Returns the visit floor for admitting the next child.
    ///
    /// The value is `u128` because a valid policy and admitted count can name a
    /// threshold above `u64::MAX`; such a threshold is intentionally
    /// unreachable by the `u64` completed-visit counter.
    #[must_use]
    pub const fn required_completed_visits(self) -> u128 {
        self.required_completed_visits
    }

    /// Returns whether the current completed visits satisfy the visit floor.
    #[must_use]
    pub const fn is_visit_floor_satisfied(self) -> bool {
        self.visit_floor_satisfied
    }

    /// Returns whether one additional distinct child may be admitted now.
    #[must_use]
    pub const fn is_eligible(self) -> bool {
        self.eligible
    }
}

/// Owner-authenticated statistics required to score one PUCT edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PuctEdgeStatistics {
    parent_visits: u64,
    edge_visits: u64,
    reward_sum_micros: i64,
    prior_micros: u64,
    novel: bool,
    fairness_reserved: bool,
}

impl PuctEdgeStatistics {
    /// Builds one internally consistent PUCT statistics input.
    ///
    /// The prior uses millionths, so `1_000_000` represents probability one.
    /// Novelty and fairness are exact owner-derived predicates; their policy
    /// bonuses are each applied at most once.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when edge visits exceed
    /// parent visits, the prior exceeds one, or a zero-visit edge carries a
    /// nonzero reward sum.
    pub fn new(
        parent_visits: u64,
        edge_visits: u64,
        reward_sum_micros: i64,
        prior_micros: u64,
        novel: bool,
        fairness_reserved: bool,
    ) -> Result<Self, CampaignCodecError> {
        if edge_visits > parent_visits {
            return Err(CampaignCodecError::InvalidValue {
                reason: "PUCT edge visits exceed parent visits",
            });
        }
        if prior_micros > GUIDANCE_MICROS_PER_UNIT {
            return Err(CampaignCodecError::InvalidValue {
                reason: "PUCT prior exceeds one",
            });
        }
        if edge_visits == 0 && reward_sum_micros != 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unvisited PUCT edge has reward",
            });
        }
        Ok(Self {
            parent_visits,
            edge_visits,
            reward_sum_micros,
            prior_micros,
            novel,
            fairness_reserved,
        })
    }

    /// Returns completed visits credited to the parent.
    #[must_use]
    pub const fn parent_visits(self) -> u64 {
        self.parent_visits
    }

    /// Returns completed visits credited to the edge.
    #[must_use]
    pub const fn edge_visits(self) -> u64 {
        self.edge_visits
    }

    /// Returns the edge's signed reward sum in millionths.
    #[must_use]
    pub const fn reward_sum_micros(self) -> i64 {
        self.reward_sum_micros
    }

    /// Returns the exact prior probability in millionths.
    #[must_use]
    pub const fn prior_micros(self) -> u64 {
        self.prior_micros
    }

    /// Returns whether the edge has owner-authenticated novelty.
    #[must_use]
    pub const fn is_novel(self) -> bool {
        self.novel
    }

    /// Returns whether the edge owns the current fairness reservation.
    #[must_use]
    pub const fn is_fairness_reserved(self) -> bool {
        self.fairness_reserved
    }
}

/// Exact decomposed fixed-point PUCT score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PuctScore {
    mean_reward_micros: i64,
    exploration_bonus_micros: u64,
    novelty_bonus_micros: u64,
    fairness_bonus_micros: u64,
    total_micros: i64,
}

impl PuctScore {
    /// Derives the deterministic score for one authenticated edge.
    ///
    /// Divisions of nonnegative terms round down, and the signed reward mean
    /// truncates toward zero. Positive terms and the final sum saturate at
    /// `i64::MAX`; the final sum saturates at `i64::MIN` on the negative side.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] only if the supplied
    /// statistics violate an invariant established by
    /// [`PuctEdgeStatistics::new`].
    pub fn derive(
        policy: PuctPolicy,
        statistics: PuctEdgeStatistics,
    ) -> Result<Self, CampaignCodecError> {
        if statistics.edge_visits > statistics.parent_visits
            || statistics.prior_micros > GUIDANCE_MICROS_PER_UNIT
            || (statistics.edge_visits == 0 && statistics.reward_sum_micros != 0)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "PUCT statistics are inconsistent",
            });
        }

        let mean_reward_micros = mean_reward(statistics);
        let exploration_bonus_micros = exploration_bonus(policy, statistics);
        let novelty_bonus_micros = if statistics.novel {
            cap_positive(policy.novelty_bonus_micros())
        } else {
            0
        };
        let fairness_bonus_micros = if statistics.fairness_reserved {
            cap_positive(policy.fairness_bonus_micros())
        } else {
            0
        };
        let total = i128::from(mean_reward_micros)
            + i128::from(exploration_bonus_micros)
            + i128::from(novelty_bonus_micros)
            + i128::from(fairness_bonus_micros);
        let total_micros = total.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;

        Ok(Self {
            mean_reward_micros,
            exploration_bonus_micros,
            novelty_bonus_micros,
            fairness_bonus_micros,
            total_micros,
        })
    }

    /// Returns the signed mean-reward term in millionths.
    #[must_use]
    pub const fn mean_reward_micros(self) -> i64 {
        self.mean_reward_micros
    }

    /// Returns the nonnegative exploration term in millionths.
    #[must_use]
    pub const fn exploration_bonus_micros(self) -> u64 {
        self.exploration_bonus_micros
    }

    /// Returns the applied novelty term in millionths.
    #[must_use]
    pub const fn novelty_bonus_micros(self) -> u64 {
        self.novelty_bonus_micros
    }

    /// Returns the applied fairness term in millionths.
    #[must_use]
    pub const fn fairness_bonus_micros(self) -> u64 {
        self.fairness_bonus_micros
    }

    /// Returns the saturated total score in millionths.
    #[must_use]
    pub const fn total_micros(self) -> i64 {
        self.total_micros
    }
}

fn mean_reward(statistics: PuctEdgeStatistics) -> i64 {
    if statistics.edge_visits == 0 {
        return 0;
    }
    let quotient = i128::from(statistics.reward_sum_micros) / i128::from(statistics.edge_visits);
    quotient.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn exploration_bonus(policy: PuctPolicy, statistics: PuctEdgeStatistics) -> u64 {
    let scale = u128::from(GUIDANCE_MICROS_PER_UNIT);
    let weighted_prior = u128::from(policy.exploration_weight_micros())
        * u128::from(statistics.prior_micros)
        / scale;
    let scaled_parent = u128::from(statistics.parent_visits) * scale * scale;
    let square_root_micros = integer_square_root(scaled_parent);
    let numerator = weighted_prior * square_root_micros / scale;
    let denominator = u128::from(statistics.edge_visits) + 1;
    let bonus = numerator / denominator;
    bonus.min(i64::MAX as u128) as u64
}

const fn cap_positive(value: u64) -> u64 {
    if value > i64::MAX as u64 {
        i64::MAX as u64
    } else {
        value
    }
}

/// Returns `floor(sqrt(value))` without floating-point arithmetic.
fn integer_square_root(mut value: u128) -> u128 {
    let mut result = 0_u128;
    let mut bit = 1_u128 << 126;
    while bit > value {
        bit >>= 2;
    }
    while bit != 0 {
        if value >= result + bit {
            value -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    result
}

fn power_law_children_capped(
    policy: ProgressiveWideningPolicy,
    completed_visits: u64,
    cap: u64,
) -> Result<u64, CampaignCodecError> {
    let k = policy.k();
    let value = match (policy.alpha().numerator(), policy.alpha().denominator()) {
        (0, 1) => ceil_ratio_capped(u128::from(k.numerator()), k.denominator(), cap),
        (1, 1) => ceil_ratio_capped(
            u128::from(k.numerator()) * u128::from(completed_visits),
            k.denominator(),
            cap,
        ),
        (1, 2) => square_root_ratio_capped(k.numerator(), k.denominator(), completed_visits, cap),
        _ => {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported progressive-widening exponent",
            });
        }
    };
    Ok(value)
}

fn ceil_ratio_capped(numerator: u128, denominator: u64, cap: u64) -> u64 {
    let denominator = u128::from(denominator);
    let quotient = numerator / denominator;
    let rounded = quotient + u128::from(!numerator.is_multiple_of(denominator));
    rounded.min(u128::from(cap)) as u64
}

/// Computes `min(cap, ceil(numerator * sqrt(visits) / denominator))`.
fn square_root_ratio_capped(numerator: u64, denominator: u64, visits: u64, cap: u64) -> u64 {
    if numerator == 0 || visits == 0 || cap == 0 {
        return 0;
    }
    let right = product_u64_factors(&[numerator, numerator, visits]);
    let reaches = |candidate: u64| {
        let left = product_u64_factors(&[candidate, denominator, candidate, denominator]);
        compare_u256(left, right) != Ordering::Less
    };
    if !reaches(cap) {
        return cap;
    }

    let mut low = 0_u64;
    let mut high = cap;
    while low < high {
        let middle = low + (high - low) / 2;
        if reaches(middle) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
}

/// Multiplies at most four `u64` factors into little-endian `u256` limbs.
fn product_u64_factors(factors: &[u64]) -> [u64; 4] {
    let mut product = [1_u64, 0, 0, 0];
    for factor in factors {
        let mut carry = 0_u128;
        for limb in &mut product {
            let value = u128::from(*limb) * u128::from(*factor) + carry;
            *limb = value as u64;
            carry = value >> 64;
        }
        debug_assert_eq!(carry, 0);
    }
    product
}

fn compare_u256(left: [u64; 4], right: [u64; 4]) -> Ordering {
    left.iter().rev().cmp(right.iter().rev())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn fixed_point_puct_score_uses_exact_staged_rounding() {
        let statistics = PuctEdgeStatistics::new(4, 1, -3_000_000, 500_000, true, true)
            .expect("valid PUCT statistics");
        let score = PuctScore::derive(PuctPolicy::new(1_000_000, 200_000, 100_000), statistics)
            .expect("exact PUCT score");

        assert_eq!(score.mean_reward_micros(), -3_000_000);
        assert_eq!(score.exploration_bonus_micros(), 500_000);
        assert_eq!(score.novelty_bonus_micros(), 200_000);
        assert_eq!(score.fairness_bonus_micros(), 100_000);
        assert_eq!(score.total_micros(), -2_200_000);
    }

    #[test]
    fn fixed_point_puct_square_root_rounds_down() {
        let statistics = PuctEdgeStatistics::new(2, 0, 0, 1_000_000, false, false)
            .expect("valid PUCT statistics");
        let score = PuctScore::derive(PuctPolicy::new(1_000_000, 0, 0), statistics)
            .expect("exact PUCT score");

        assert_eq!(score.exploration_bonus_micros(), 1_414_213);
        assert_eq!(score.total_micros(), 1_414_213);
    }

    #[test]
    fn fixed_point_puct_signed_mean_truncates_toward_zero() {
        let statistics = PuctEdgeStatistics::new(2, 2, -3_000_001, 0, false, false)
            .expect("valid PUCT statistics");
        let score =
            PuctScore::derive(PuctPolicy::new(0, 0, 0), statistics).expect("exact PUCT score");

        assert_eq!(score.mean_reward_micros(), -1_500_000);
        assert_eq!(score.total_micros(), -1_500_000);
    }

    #[test]
    fn fixed_point_puct_saturates_positive_terms_and_total() {
        let statistics =
            PuctEdgeStatistics::new(u64::MAX, 1, i64::MAX, GUIDANCE_MICROS_PER_UNIT, true, true)
                .expect("valid PUCT statistics");
        let score = PuctScore::derive(PuctPolicy::new(u64::MAX, u64::MAX, u64::MAX), statistics)
            .expect("saturated PUCT score");

        assert_eq!(score.exploration_bonus_micros(), i64::MAX as u64);
        assert_eq!(score.novelty_bonus_micros(), i64::MAX as u64);
        assert_eq!(score.fairness_bonus_micros(), i64::MAX as u64);
        assert_eq!(score.total_micros(), i64::MAX);
    }

    #[test]
    fn fixed_point_puct_rejects_inconsistent_statistics() {
        assert_eq!(
            PuctEdgeStatistics::new(0, 1, 0, 0, false, false),
            Err(CampaignCodecError::InvalidValue {
                reason: "PUCT edge visits exceed parent visits",
            })
        );
        assert_eq!(
            PuctEdgeStatistics::new(0, 0, 1, 0, false, false),
            Err(CampaignCodecError::InvalidValue {
                reason: "unvisited PUCT edge has reward",
            })
        );
        assert_eq!(
            PuctEdgeStatistics::new(0, 0, 0, GUIDANCE_MICROS_PER_UNIT + 1, false, false,),
            Err(CampaignCodecError::InvalidValue {
                reason: "PUCT prior exceeds one",
            })
        );
    }

    #[test]
    fn progressive_widening_uses_exact_irrational_ceiling() {
        let policy = ProgressiveWideningPolicy::new(
            crate::ExactRational::new(2, 1).expect("widening multiplier"),
            crate::ExactRational::new(1, 2).expect("square-root exponent"),
            0,
            64,
            1,
        )
        .expect("widening policy");

        let after_two =
            ProgressiveWideningDecision::derive(policy, 2, 0).expect("widening decision");
        assert_eq!(after_two.permitted_children(), 3);
        let after_four =
            ProgressiveWideningDecision::derive(policy, 4, 0).expect("widening decision");
        assert_eq!(after_four.permitted_children(), 4);

        assert_eq!(
            square_root_ratio_capped(u64::MAX, u64::MAX, u64::MAX, u64::MAX),
            4_294_967_296
        );
    }

    #[test]
    fn progressive_widening_square_root_matches_small_exact_products() {
        for numerator in 0_u64..=5 {
            for denominator in 1_u64..=5 {
                for visits in 0_u64..=100 {
                    let cap = 20_u64;
                    let right = u128::from(numerator) * u128::from(numerator) * u128::from(visits);
                    let expected = (0..=cap)
                        .find(|candidate| {
                            let scaled = u128::from(*candidate) * u128::from(denominator);
                            scaled * scaled >= right
                        })
                        .unwrap_or(cap);
                    assert_eq!(
                        square_root_ratio_capped(numerator, denominator, visits, cap),
                        expected,
                        "a={numerator}, b={denominator}, N={visits}"
                    );
                }
            }
        }
    }

    #[test]
    fn progressive_widening_initial_allocation_and_visit_floor_are_exact() {
        let policy = ProgressiveWideningPolicy::new(
            crate::ExactRational::new(2, 1).expect("widening multiplier"),
            crate::ExactRational::new(1, 2).expect("square-root exponent"),
            3,
            64,
            2,
        )
        .expect("widening policy");

        let initial =
            ProgressiveWideningDecision::derive(policy, 0, 2).expect("initial widening decision");
        assert_eq!(initial.permitted_children(), 3);
        assert_eq!(initial.required_completed_visits(), 0);
        assert!(initial.is_eligible());

        let blocked = ProgressiveWideningDecision::derive(policy, 5, 3)
            .expect("feedback-gated widening decision");
        assert_eq!(blocked.permitted_children(), 5);
        assert_eq!(blocked.required_completed_visits(), 6);
        assert!(!blocked.is_visit_floor_satisfied());
        assert!(!blocked.is_eligible());

        let ready = ProgressiveWideningDecision::derive(policy, 6, 3)
            .expect("feedback-ready widening decision");
        assert_eq!(ready.permitted_children(), 5);
        assert!(ready.is_visit_floor_satisfied());
        assert!(ready.is_eligible());
    }

    #[test]
    fn progressive_widening_caps_overflowing_power_laws_and_visit_floors() {
        let policy = ProgressiveWideningPolicy::new(
            crate::ExactRational::new(u64::MAX, 1).expect("widening multiplier"),
            crate::ExactRational::new(1, 1).expect("linear exponent"),
            1,
            u64::MAX,
            u64::MAX,
        )
        .expect("widening policy");
        let decision = ProgressiveWideningDecision::derive(policy, u64::MAX, u64::MAX - 1)
            .expect("bounded widening decision");

        assert_eq!(decision.permitted_children(), u64::MAX);
        assert!(decision.required_completed_visits() > u128::from(u64::MAX));
        assert!(!decision.is_eligible());
        assert_eq!(
            ProgressiveWideningDecision::derive(policy, 0, u64::MAX),
            Ok(ProgressiveWideningDecision {
                permitted_children: 1,
                required_completed_visits: u128::from(u64::MAX) * u128::from(u64::MAX),
                visit_floor_satisfied: false,
                eligible: false,
            })
        );
    }

    #[test]
    fn progressive_widening_rejects_children_above_the_hard_cap() {
        let policy = ProgressiveWideningPolicy::new(
            crate::ExactRational::new(1, 1).expect("widening multiplier"),
            crate::ExactRational::new(0, 1).expect("constant exponent"),
            1,
            1,
            1,
        )
        .expect("widening policy");

        assert_eq!(
            ProgressiveWideningDecision::derive(policy, 0, 2),
            Err(CampaignCodecError::InvalidValue {
                reason: "progressive-widening child count exceeds policy",
            })
        );
    }
}
