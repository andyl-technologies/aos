//! Predeclared sequential Monte Carlo sampling contracts.
//!
//! A design fixes the particle and stage bounds, exact resampling threshold,
//! deterministic resampler version, and the semantic selector for every
//! runtime-discovered opportunity before any observation can influence the
//! campaign. The selector intentionally binds semantic context rather than a
//! concrete opportunity ID because later opportunities may be derived from a
//! prior runtime outcome.

use std::collections::BTreeMap;

use super::{ExactRational, MAX_POLICY_ENTRIES, StatisticalDistribution, validate_identifier};
use crate::CampaignCodecError;
use crate::codec::{Canonical, Decoder, Encoder};
use crate::exploration::StopCondition;
use crate::identity::{ChoiceDomainSemanticId, ProbabilityModelId, SelectableSemanticId};

/// Maximum particle transitions represented by one pinned SMC design.
///
/// Generation projection remains lazy, while this aggregate cap bounds the
/// complete genealogy and report work a finished campaign can retain.
pub const MAX_SMC_TOTAL_PARTICLE_TRANSITIONS: u64 = 65_536;

/// Deterministic ancestor-selection algorithm for an SMC design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmcResamplingAlgorithm {
    /// Uses one exact seeded offset and evenly spaced cumulative-weight points.
    SystematicV1,
}

impl Canonical for SmcResamplingAlgorithm {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::SystematicV1 => 1,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            1 => Ok(Self::SystematicV1),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "smc-resampling-algorithm",
                tag,
            }),
        }
    }
}

/// Exact effective-sample-size rule controlling SMC resampling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmcResamplingPolicy {
    algorithm: SmcResamplingAlgorithm,
    effective_sample_size_threshold: ExactRational,
}

impl SmcResamplingPolicy {
    /// Builds a rule that resamples when `ESS <= particle_count * threshold`.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the threshold is zero or greater
    /// than one.
    pub fn new(
        algorithm: SmcResamplingAlgorithm,
        effective_sample_size_threshold: ExactRational,
    ) -> Result<Self, CampaignCodecError> {
        if effective_sample_size_threshold.numerator() == 0
            || effective_sample_size_threshold.numerator()
                > effective_sample_size_threshold.denominator()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "SMC effective-sample-size threshold is outside (0, 1]",
            });
        }
        Ok(Self {
            algorithm,
            effective_sample_size_threshold,
        })
    }

    /// Returns the versioned deterministic ancestor-selection algorithm.
    #[must_use]
    pub const fn algorithm(self) -> SmcResamplingAlgorithm {
        self.algorithm
    }

    /// Returns the exact fraction of particle count used as the ESS threshold.
    #[must_use]
    pub const fn effective_sample_size_threshold(self) -> ExactRational {
        self.effective_sample_size_threshold
    }
}

impl Canonical for SmcResamplingPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        self.algorithm.encode(encoder);
        self.effective_sample_size_threshold.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            SmcResamplingAlgorithm::decode(decoder)?,
            ExactRational::decode(decoder)?,
        )
    }
}

/// A semantic contract selecting one next opportunity beneath a particle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmcOpportunitySelector {
    implementation_version: u32,
    declaration: SelectableSemanticId,
    domain: ChoiceDomainSemanticId,
    instance: String,
    model: ProbabilityModelId,
    stop: StopCondition,
}

impl SmcOpportunitySelector {
    /// Selector version that requires one exact semantic declaration, domain,
    /// instance, and probability model match.
    pub const IMPLEMENTATION_VERSION: u32 = 1;

    /// Builds a pre-observation selector for a runtime-discovered opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when `instance` or `stop` is invalid.
    pub fn new(
        declaration: SelectableSemanticId,
        domain: ChoiceDomainSemanticId,
        instance: impl Into<String>,
        model: ProbabilityModelId,
        stop: StopCondition,
    ) -> Result<Self, CampaignCodecError> {
        let instance = instance.into();
        validate_identifier(&instance, "SMC opportunity instance is invalid")?;
        stop.validate()?;
        Ok(Self {
            implementation_version: Self::IMPLEMENTATION_VERSION,
            declaration,
            domain,
            instance,
            model,
            stop,
        })
    }

    /// Returns the immutable selector implementation version.
    #[must_use]
    pub const fn implementation_version(&self) -> u32 {
        self.implementation_version
    }

    /// Returns the required semantic selectable declaration.
    #[must_use]
    pub const fn declaration(&self) -> SelectableSemanticId {
        self.declaration
    }

    /// Returns the required semantic offered domain.
    #[must_use]
    pub const fn domain(&self) -> ChoiceDomainSemanticId {
        self.domain
    }

    /// Returns the required producer-defined stable instance key.
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Returns the required target probability model.
    #[must_use]
    pub const fn model(&self) -> ProbabilityModelId {
        self.model
    }

    /// Returns the exact boundary for executing the selected branch.
    #[must_use]
    pub const fn stop(&self) -> &StopCondition {
        &self.stop
    }
}

impl Canonical for SmcOpportunitySelector {
    fn encode(&self, encoder: &mut Encoder) {
        self.implementation_version.encode(encoder);
        self.declaration.encode(encoder);
        self.domain.encode(encoder);
        self.instance.encode(encoder);
        self.model.encode(encoder);
        self.stop.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let implementation_version = u32::decode(decoder)?;
        if implementation_version != Self::IMPLEMENTATION_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported SMC opportunity-selector implementation version",
            });
        }
        Self::new(
            SelectableSemanticId::decode(decoder)?,
            ChoiceDomainSemanticId::decode(decoder)?,
            decoder.string_bounded(
                super::MAX_IDENTIFIER_BYTES,
                "SMC opportunity-instance bytes",
            )?,
            ProbabilityModelId::decode(decoder)?,
            StopCondition::decode(decoder)?,
        )
    }
}

/// One predeclared SMC transition after a completed particle generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmcStagePlan {
    parent_stage: u32,
    selector: SmcOpportunitySelector,
}

impl SmcStagePlan {
    /// Builds a stage whose parent generation is fixed before observations.
    #[must_use]
    pub const fn new(parent_stage: u32, selector: SmcOpportunitySelector) -> Self {
        Self {
            parent_stage,
            selector,
        }
    }

    /// Returns the completed stage whose particles feed this transition.
    #[must_use]
    pub const fn parent_stage(&self) -> u32 {
        self.parent_stage
    }

    /// Returns the predeclared next-opportunity selector.
    #[must_use]
    pub const fn selector(&self) -> &SmcOpportunitySelector {
        &self.selector
    }
}

impl Canonical for SmcStagePlan {
    fn encode(&self, encoder: &mut Encoder) {
        self.parent_stage.encode(encoder);
        self.selector.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            u32::decode(decoder)?,
            SmcOpportunitySelector::decode(decoder)?,
        ))
    }
}

/// Bounded version-four sequential Monte Carlo policy extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SequentialMonteCarloDesign {
    particle_count: u32,
    distributions: BTreeMap<ProbabilityModelId, StatisticalDistribution>,
    stages: BTreeMap<u32, SmcStagePlan>,
    resampling: SmcResamplingPolicy,
}

impl SequentialMonteCarloDesign {
    /// Builds a linear sequence of predeclared SMC transitions numbered `1..N`.
    ///
    /// Stage zero is the finite initial particle flight carried by the enclosing
    /// statistical policy. Each later stage must name its immediate predecessor
    /// and a distribution for the selector's model.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid particle bound, empty or
    /// oversized maps, missing stage coordinates or models, or non-linear
    /// ancestry.
    pub fn new(
        particle_count: u32,
        distributions: BTreeMap<ProbabilityModelId, StatisticalDistribution>,
        stages: BTreeMap<u32, SmcStagePlan>,
        resampling: SmcResamplingPolicy,
    ) -> Result<Self, CampaignCodecError> {
        let particle_count_usize =
            usize::try_from(particle_count).map_err(|_| CampaignCodecError::InvalidValue {
                reason: "SMC particle count cannot be represented",
            })?;
        if particle_count_usize == 0
            || particle_count_usize > MAX_POLICY_ENTRIES
            || distributions.is_empty()
            || distributions.len() > MAX_POLICY_ENTRIES
            || stages.is_empty()
            || stages.len() > MAX_POLICY_ENTRIES
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "SMC design is empty or oversized",
            });
        }
        let total_particle_transitions = u64::from(particle_count)
            .checked_mul(u64::try_from(stages.len()).map_err(|_| {
                CampaignCodecError::InvalidValue {
                    reason: "SMC stage count cannot be represented",
                }
            })?)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "SMC total particle transition count overflows",
            })?;
        if total_particle_transitions > MAX_SMC_TOTAL_PARTICLE_TRANSITIONS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "SMC total particle transitions",
            });
        }
        for (expected_stage, (stage, plan)) in (1_u32..).zip(&stages) {
            if *stage != expected_stage
                || plan.parent_stage() != stage.saturating_sub(1)
                || !distributions.contains_key(&plan.selector().model())
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "SMC design has an invalid stage or model",
                });
            }
        }
        Ok(Self {
            particle_count,
            distributions,
            stages,
            resampling,
        })
    }

    /// Returns the fixed number of particle slots in every generation.
    #[must_use]
    pub const fn particle_count(&self) -> u32 {
        self.particle_count
    }

    /// Returns pinned finite distributions keyed by model identity.
    #[must_use]
    pub const fn distributions(&self) -> &BTreeMap<ProbabilityModelId, StatisticalDistribution> {
        &self.distributions
    }

    /// Returns every post-initial stage in canonical order.
    #[must_use]
    pub const fn stages(&self) -> &BTreeMap<u32, SmcStagePlan> {
        &self.stages
    }

    /// Returns one predeclared post-initial stage.
    #[must_use]
    pub fn stage(&self, stage: u32) -> Option<&SmcStagePlan> {
        self.stages.get(&stage)
    }

    /// Returns the exact deterministic resampling rule.
    #[must_use]
    pub const fn resampling(&self) -> SmcResamplingPolicy {
        self.resampling
    }
}

impl Canonical for SequentialMonteCarloDesign {
    fn encode(&self, encoder: &mut Encoder) {
        self.particle_count.encode(encoder);
        self.distributions.encode(encoder);
        self.stages.encode(encoder);
        self.resampling.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            u32::decode(decoder)?,
            decoder.map_bounded(MAX_POLICY_ENTRIES, "SMC distribution count")?,
            decoder.map_bounded(MAX_POLICY_ENTRIES, "SMC stage count")?,
            SmcResamplingPolicy::decode(decoder)?,
        )
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture construction uses exact panic localization.
    #![allow(clippy::expect_used)]

    use crate::{CampaignHash, ChoiceValue};

    use super::*;

    fn model(label: &str) -> ProbabilityModelId {
        ProbabilityModelId::from_hash(CampaignHash::derive("test.smc-model", label.as_bytes()))
    }

    fn distribution() -> StatisticalDistribution {
        StatisticalDistribution::new(
            BTreeMap::from([
                (ChoiceValue::Boolean(false), 1),
                (ChoiceValue::Boolean(true), 1),
            ]),
            BTreeMap::from([
                (ChoiceValue::Boolean(false), 1),
                (ChoiceValue::Boolean(true), 1),
            ]),
        )
        .expect("distribution")
    }

    fn selector(model: ProbabilityModelId, label: &str) -> SmcOpportunitySelector {
        SmcOpportunitySelector::new(
            SelectableSemanticId::from_hash(CampaignHash::derive(
                "test.smc-declaration",
                label.as_bytes(),
            )),
            ChoiceDomainSemanticId::from_hash(CampaignHash::derive(
                "test.smc-domain",
                label.as_bytes(),
            )),
            label,
            model,
            StopCondition::NextChoice,
        )
        .expect("selector")
    }

    fn resampling() -> SmcResamplingPolicy {
        SmcResamplingPolicy::new(
            SmcResamplingAlgorithm::SystematicV1,
            ExactRational::new(1, 2).expect("ESS threshold"),
        )
        .expect("resampling policy")
    }

    #[test]
    fn design_requires_contiguous_linear_stages_and_known_models() {
        let known_model = model("known");
        let unknown_model = model("unknown");
        let distributions = BTreeMap::from([(known_model, distribution())]);

        assert!(matches!(
            SequentialMonteCarloDesign::new(
                2,
                distributions.clone(),
                BTreeMap::from([(2, SmcStagePlan::new(1, selector(known_model, "gap")))]),
                resampling(),
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "SMC design has an invalid stage or model"
            })
        ));
        assert!(matches!(
            SequentialMonteCarloDesign::new(
                2,
                distributions.clone(),
                BTreeMap::from([(1, SmcStagePlan::new(1, selector(known_model, "parent")))]),
                resampling(),
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "SMC design has an invalid stage or model"
            })
        ));
        assert!(matches!(
            SequentialMonteCarloDesign::new(
                2,
                distributions,
                BTreeMap::from([(1, SmcStagePlan::new(0, selector(unknown_model, "model")))]),
                resampling(),
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "SMC design has an invalid stage or model"
            })
        ));
    }

    #[test]
    fn design_caps_total_particle_transitions() {
        let model = model("aggregate");
        let stages = (1..=17)
            .map(|stage| {
                (
                    stage,
                    SmcStagePlan::new(stage - 1, selector(model, &format!("stage-{stage}"))),
                )
            })
            .collect();

        assert!(matches!(
            SequentialMonteCarloDesign::new(
                MAX_POLICY_ENTRIES as u32,
                BTreeMap::from([(model, distribution())]),
                stages,
                resampling(),
            ),
            Err(CampaignCodecError::LimitExceeded {
                limit: "SMC total particle transitions"
            })
        ));
    }
}
