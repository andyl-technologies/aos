//! Exact statistical endpoint weights and descriptive diagnostics.
//!
//! A report estimates the equal-weight mixture over the terminal draw
//! coordinates declared by one sampling design. Every coordinate must complete
//! even when it is only a shared prefix. Endpoint draws may share ancestry, so
//! effective sample size and concentration describe weights only and do not
//! claim independent observations or an IID confidence interval.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use super::{
    AttemptId, BranchPathId, CampaignCodecError, CampaignPolicyId, CampaignSnapshotId,
    ObservationId, ProposalId,
};

/// A reduced nonnegative rational represented with bounded exact integers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatisticalRational {
    numerator: u128,
    denominator: u128,
}

impl StatisticalRational {
    pub(crate) fn new(numerator: u128, denominator: u128) -> Result<Self, CampaignCodecError> {
        if denominator == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical rational denominator is zero",
            });
        }
        let divisor = greatest_common_divisor_u128(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    pub(crate) const fn one() -> Self {
        Self {
            numerator: 1,
            denominator: 1,
        }
    }

    pub(crate) fn checked_multiply(self, other: Self) -> Result<Self, CampaignCodecError> {
        let left_divisor = greatest_common_divisor_u128(self.numerator, other.denominator);
        let right_divisor = greatest_common_divisor_u128(other.numerator, self.denominator);
        let numerator = (self.numerator / left_divisor)
            .checked_mul(other.numerator / right_divisor)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "statistical rational multiplication overflows",
            })?;
        let denominator = (self.denominator / right_divisor)
            .checked_mul(other.denominator / left_divisor)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "statistical rational multiplication overflows",
            })?;
        Self::new(numerator, denominator)
    }

    pub(crate) fn checked_add(self, other: Self) -> Result<Self, CampaignCodecError> {
        let divisor = greatest_common_divisor_u128(self.denominator, other.denominator);
        let left_scale = other.denominator / divisor;
        let right_scale = self.denominator / divisor;
        let numerator = self
            .numerator
            .checked_mul(left_scale)
            .and_then(|left| {
                other
                    .numerator
                    .checked_mul(right_scale)
                    .and_then(|right| left.checked_add(right))
            })
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "statistical rational addition overflows",
            })?;
        let denominator =
            self.denominator
                .checked_mul(left_scale)
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "statistical rational addition overflows",
                })?;
        Self::new(numerator, denominator)
    }

    pub(crate) fn checked_divide(self, other: Self) -> Result<Self, CampaignCodecError> {
        if other.numerator == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical rational division by zero",
            });
        }
        self.checked_multiply(Self::new(other.denominator, other.numerator)?)
    }

    pub(crate) fn checked_cmp(self, other: Self) -> Result<Ordering, CampaignCodecError> {
        let divisor = greatest_common_divisor_u128(self.denominator, other.denominator);
        let left = self
            .numerator
            .checked_mul(other.denominator / divisor)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "statistical rational comparison overflows",
            })?;
        let right = other
            .numerator
            .checked_mul(self.denominator / divisor)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "statistical rational comparison overflows",
            })?;
        Ok(left.cmp(&right))
    }

    /// Returns the reduced numerator.
    #[must_use]
    pub const fn numerator(self) -> u128 {
        self.numerator
    }

    /// Returns the positive reduced denominator.
    #[must_use]
    pub const fn denominator(self) -> u128 {
        self.denominator
    }
}

/// One declared endpoint draw and its canonical reused observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalEndpointEstimate {
    coordinate: u64,
    proposal: ProposalId,
    attempt: AttemptId,
    observation: ObservationId,
    path: BranchPathId,
    target_probability: StatisticalRational,
    proposal_probability: StatisticalRational,
    importance_weight: StatisticalRational,
}

impl StatisticalEndpointEstimate {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        coordinate: u64,
        proposal: ProposalId,
        attempt: AttemptId,
        observation: ObservationId,
        path: BranchPathId,
        target_probability: StatisticalRational,
        proposal_probability: StatisticalRational,
        importance_weight: StatisticalRational,
    ) -> Self {
        Self {
            coordinate,
            proposal,
            attempt,
            observation,
            path,
            target_probability,
            proposal_probability,
            importance_weight,
        }
    }

    /// Returns the predeclared draw coordinate.
    #[must_use]
    pub const fn coordinate(&self) -> u64 {
        self.coordinate
    }

    /// Returns the proposal that records this draw.
    #[must_use]
    pub const fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// Returns the semantic attempt, which may be shared by several draws.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the one canonical observation reused for this draw.
    #[must_use]
    pub const fn observation(&self) -> ObservationId {
        self.observation
    }

    /// Returns the authenticated semantic path.
    #[must_use]
    pub const fn path(&self) -> BranchPathId {
        self.path
    }

    /// Returns exact `P(path)` across every declared ancestor edge.
    #[must_use]
    pub const fn target_probability(&self) -> StatisticalRational {
        self.target_probability
    }

    /// Returns exact `Q(path)` across every declared ancestor edge.
    #[must_use]
    pub const fn proposal_probability(&self) -> StatisticalRational {
        self.proposal_probability
    }

    /// Returns the reduced importance weight `P(path) / Q(path)`.
    #[must_use]
    pub const fn importance_weight(&self) -> StatisticalRational {
        self.importance_weight
    }
}

/// Descriptive weight diagnostics for a possibly correlated endpoint mixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatisticalWeightDiagnostics {
    concentration: StatisticalRational,
    effective_sample_size: StatisticalRational,
}

impl StatisticalWeightDiagnostics {
    pub(crate) const fn new(
        concentration: StatisticalRational,
        effective_sample_size: StatisticalRational,
    ) -> Self {
        Self {
            concentration,
            effective_sample_size,
        }
    }

    /// Returns `max(weight) / sum(weight)` as a descriptive concentration.
    #[must_use]
    pub const fn concentration(self) -> StatisticalRational {
        self.concentration
    }

    /// Returns `(sum(weight))^2 / sum(weight^2)` without an IID claim.
    #[must_use]
    pub const fn effective_sample_size(self) -> StatisticalRational {
        self.effective_sample_size
    }
}

/// Complete exact evidence for the policy-declared equal-weight endpoint mixture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalEstimateReport {
    snapshot: CampaignSnapshotId,
    policy: CampaignPolicyId,
    endpoints: Vec<StatisticalEndpointEstimate>,
    diagnostics: StatisticalWeightDiagnostics,
}

impl StatisticalEstimateReport {
    pub(crate) const fn new(
        snapshot: CampaignSnapshotId,
        policy: CampaignPolicyId,
        endpoints: Vec<StatisticalEndpointEstimate>,
        diagnostics: StatisticalWeightDiagnostics,
    ) -> Self {
        Self {
            snapshot,
            policy,
            endpoints,
            diagnostics,
        }
    }

    /// Returns the exact complete campaign snapshot used by the projection.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the policy that pins the sampling design.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns every declared endpoint exactly once in coordinate order.
    #[must_use]
    pub fn endpoints(&self) -> &[StatisticalEndpointEstimate] {
        &self.endpoints
    }

    /// Returns descriptive weight diagnostics for the endpoint mixture.
    #[must_use]
    pub const fn diagnostics(&self) -> StatisticalWeightDiagnostics {
        self.diagnostics
    }

    /// Returns the ordinary importance-sampling estimate for an event.
    ///
    /// An observation in `event` selects every draw coordinate that reused that
    /// canonical observation. The fixed denominator is the number of declared
    /// endpoints, so a non-unit realized weight sum remains visible.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an unknown observation or bounded
    /// rational arithmetic overflow.
    pub fn estimate_event(
        &self,
        event: &BTreeSet<ObservationId>,
    ) -> Result<StatisticalRational, CampaignCodecError> {
        if event.iter().any(|observation| {
            !self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.observation == *observation)
        }) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical event contains an unknown observation",
            });
        }
        let mut numerator = StatisticalRational::new(0, 1)?;
        for endpoint in &self.endpoints {
            if event.contains(&endpoint.observation) {
                numerator = numerator.checked_add(endpoint.importance_weight)?;
            }
        }
        numerator.checked_divide(StatisticalRational::new(self.endpoints.len() as u128, 1)?)
    }

    /// Returns the self-normalized importance-sampling estimate for an event.
    ///
    /// Self-normalization divides by the realized weight sum and generally has
    /// finite-sample bias. An observation in `event` selects every draw
    /// coordinate that reused that canonical observation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an unknown observation or bounded
    /// rational arithmetic overflow.
    pub fn estimate_event_self_normalized(
        &self,
        event: &BTreeSet<ObservationId>,
    ) -> Result<StatisticalRational, CampaignCodecError> {
        if event.iter().any(|observation| {
            !self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.observation == *observation)
        }) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical event contains an unknown observation",
            });
        }
        let mut numerator = StatisticalRational::new(0, 1)?;
        let mut denominator = StatisticalRational::new(0, 1)?;
        for endpoint in &self.endpoints {
            denominator = denominator.checked_add(endpoint.importance_weight)?;
            if event.contains(&endpoint.observation) {
                numerator = numerator.checked_add(endpoint.importance_weight)?;
            }
        }
        numerator.checked_divide(denominator)
    }
}

pub(crate) const fn greatest_common_divisor_u128(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    if left == 0 { 1 } else { left }
}
