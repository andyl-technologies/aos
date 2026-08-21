//! Exact fixed-point guidance arithmetic.
//!
//! This module owns the language-neutral integer arithmetic used by future
//! adaptive planner engines. It deliberately does not select a continuation:
//! owner-built reward, novelty, and finding projections must land before a
//! planner version may use these scores to change canonical ordering.

use crate::{CampaignCodecError, PuctPolicy};

/// One whole unit in the campaign fixed-point representation.
pub const GUIDANCE_MICROS_PER_UNIT: u64 = 1_000_000;

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
}
