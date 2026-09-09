//! Fixed finite sampling contracts for statistical campaigns.
//!
//! A design pins complete target and proposal distributions, exact draw
//! coordinates, predeclared choice opportunities, ancestry, execution stops,
//! and the equal-depth endpoint set that defines the estimand.

use std::collections::{BTreeMap, BTreeSet};

use super::MAX_POLICY_ENTRIES;
use crate::CampaignCodecError;
use crate::choice::{ChoiceOpportunity, ChoiceValue};
use crate::codec::{Canonical, Decoder, Encoder};
use crate::exploration::StopCondition;
use crate::identity::{
    ChoiceDomainId, ChoiceOpportunityId, ChoiceOpportunitySemanticId, ProbabilityModelId,
};

/// One finite target and proposal distribution pinned by statistical policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalDistribution {
    target_masses: BTreeMap<ChoiceValue, u64>,
    proposal_masses: BTreeMap<ChoiceValue, u64>,
    target_total: u64,
    proposal_total: u64,
}

impl StatisticalDistribution {
    /// Builds exact positive masses over one complete finite support.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the support is empty or oversized,
    /// the `P` and `Q` supports differ, a mass is zero, or a sum overflows.
    pub fn new(
        target_masses: BTreeMap<ChoiceValue, u64>,
        proposal_masses: BTreeMap<ChoiceValue, u64>,
    ) -> Result<Self, CampaignCodecError> {
        if target_masses.is_empty()
            || target_masses.len() > MAX_POLICY_ENTRIES
            || target_masses.keys().ne(proposal_masses.keys())
            || target_masses.values().any(|mass| *mass == 0)
            || proposal_masses.values().any(|mass| *mass == 0)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical distribution has invalid P or Q support",
            });
        }
        let target_total = statistical_policy_mass_total(&target_masses)?;
        let proposal_total = statistical_policy_mass_total(&proposal_masses)?;
        Ok(Self {
            target_masses,
            proposal_masses,
            target_total,
            proposal_total,
        })
    }

    /// Returns the complete positive target masses.
    #[must_use]
    pub const fn target_masses(&self) -> &BTreeMap<ChoiceValue, u64> {
        &self.target_masses
    }

    /// Returns the complete positive proposal masses.
    #[must_use]
    pub const fn proposal_masses(&self) -> &BTreeMap<ChoiceValue, u64> {
        &self.proposal_masses
    }

    /// Returns the exact target-mass sum.
    #[must_use]
    pub const fn target_total(&self) -> u64 {
        self.target_total
    }

    /// Returns the exact proposal-mass sum.
    #[must_use]
    pub const fn proposal_total(&self) -> u64 {
        self.proposal_total
    }
}

impl Canonical for StatisticalDistribution {
    fn encode(&self, encoder: &mut Encoder) {
        self.target_masses.encode(encoder);
        self.proposal_masses.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            decoder.map_bounded(MAX_POLICY_ENTRIES, "statistical-target-value-count")?,
            decoder.map_bounded(MAX_POLICY_ENTRIES, "statistical-proposal-value-count")?,
        )
    }
}

/// One predeclared draw coordinate in a statistical sampling plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalDrawPlan {
    parent: Option<u64>,
    opportunity: ChoiceOpportunityId,
    opportunity_semantics: ChoiceOpportunitySemanticId,
    domain: ChoiceDomainId,
    model: ProbabilityModelId,
    stop: StopCondition,
}

impl StatisticalDrawPlan {
    /// Builds a root or descendant draw over one predeclared opportunity.
    ///
    /// The opportunity identity is independent of the eventual parent
    /// configuration, allowing a descendant draw to be declared before an
    /// earlier draw executes. This initial static design cannot represent an
    /// opportunity whose identity is derived from a prior runtime outcome.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the opportunity has another model,
    /// its identity cannot be derived, or the stop condition is invalid.
    pub fn new(
        parent: Option<u64>,
        opportunity: &ChoiceOpportunity,
        model: ProbabilityModelId,
        stop: StopCondition,
    ) -> Result<Self, CampaignCodecError> {
        if opportunity.model_prior() != Some(model) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical draw opportunity has another probability model",
            });
        }
        stop.validate()?;
        Ok(Self {
            parent,
            opportunity: opportunity.id()?,
            opportunity_semantics: opportunity.semantic_id(),
            domain: opportunity.domain(),
            model,
            stop,
        })
    }

    /// Returns the earlier draw whose endpoint is this draw's parent.
    #[must_use]
    pub const fn parent(&self) -> Option<u64> {
        self.parent
    }

    /// Returns the exact predeclared opportunity for this draw.
    #[must_use]
    pub const fn opportunity(&self) -> ChoiceOpportunityId {
        self.opportunity
    }

    /// Returns the semantic opportunity identity used to derive its branch point.
    #[must_use]
    pub const fn opportunity_semantics(&self) -> ChoiceOpportunitySemanticId {
        self.opportunity_semantics
    }

    /// Returns the exact finite domain for this draw.
    #[must_use]
    pub const fn domain(&self) -> ChoiceDomainId {
        self.domain
    }

    /// Returns the target-model identity selected for this coordinate.
    #[must_use]
    pub const fn model(&self) -> ProbabilityModelId {
        self.model
    }

    /// Returns the exact execution boundary for this draw.
    #[must_use]
    pub const fn stop(&self) -> &StopCondition {
        &self.stop
    }
}

impl Canonical for StatisticalDrawPlan {
    fn encode(&self, encoder: &mut Encoder) {
        self.parent.encode(encoder);
        self.opportunity.encode(encoder);
        self.opportunity_semantics.encode(encoder);
        self.domain.encode(encoder);
        self.model.encode(encoder);
        self.stop.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let value = Self {
            parent: Option::decode(decoder)?,
            opportunity: ChoiceOpportunityId::decode(decoder)?,
            opportunity_semantics: ChoiceOpportunitySemanticId::decode(decoder)?,
            domain: ChoiceDomainId::decode(decoder)?,
            model: ProbabilityModelId::decode(decoder)?,
            stop: StopCondition::decode(decoder)?,
        };
        value.stop.validate()?;
        Ok(value)
    }
}

/// Complete finite distributions and ancestry for a fixed statistical flight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalSamplingDesign {
    distributions: BTreeMap<ProbabilityModelId, StatisticalDistribution>,
    draws: BTreeMap<u64, StatisticalDrawPlan>,
    estimand_endpoints: BTreeSet<u64>,
}

impl StatisticalSamplingDesign {
    /// Builds a bounded plan whose draw coordinates are exactly `0..N`.
    ///
    /// Each parent coordinate must precede its child, and every draw must name
    /// a distribution included in this design.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for empty or oversized collections,
    /// missing coordinates or distributions, or forward parent references.
    pub fn new(
        distributions: BTreeMap<ProbabilityModelId, StatisticalDistribution>,
        draws: BTreeMap<u64, StatisticalDrawPlan>,
        estimand_endpoints: BTreeSet<u64>,
    ) -> Result<Self, CampaignCodecError> {
        if distributions.is_empty()
            || distributions.len() > MAX_POLICY_ENTRIES
            || draws.is_empty()
            || draws.len() > MAX_POLICY_ENTRIES
            || estimand_endpoints.is_empty()
            || estimand_endpoints.len() > MAX_POLICY_ENTRIES
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical sampling design is empty or oversized",
            });
        }
        for (expected, (coordinate, draw)) in (0_u64..).zip(&draws) {
            if *coordinate != expected
                || draw.parent().is_some_and(|parent| parent >= *coordinate)
                || !distributions.contains_key(&draw.model())
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "statistical sampling design has an invalid draw coordinate",
                });
            }
        }
        if estimand_endpoints
            .iter()
            .any(|coordinate| !draws.contains_key(coordinate))
            || draws
                .values()
                .filter_map(|draw| draw.parent())
                .any(|parent| estimand_endpoints.contains(&parent))
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical estimand includes a missing or nonterminal coordinate",
            });
        }
        let mut endpoint_depth = None;
        for coordinate in &estimand_endpoints {
            let mut depth = 1_u64;
            let mut cursor = draws.get(coordinate).and_then(|draw| draw.parent());
            while let Some(parent) = cursor {
                depth = depth
                    .checked_add(1)
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "statistical estimand depth overflows",
                    })?;
                cursor = draws.get(&parent).and_then(|draw| draw.parent());
            }
            if endpoint_depth
                .replace(depth)
                .is_some_and(|prior| prior != depth)
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "statistical estimand mixes endpoint depths",
                });
            }
        }
        Ok(Self {
            distributions,
            draws,
            estimand_endpoints,
        })
    }

    /// Returns pinned distributions keyed by model identity.
    #[must_use]
    pub const fn distributions(&self) -> &BTreeMap<ProbabilityModelId, StatisticalDistribution> {
        &self.distributions
    }

    /// Returns every planned draw in canonical coordinate order.
    #[must_use]
    pub const fn draws(&self) -> &BTreeMap<u64, StatisticalDrawPlan> {
        &self.draws
    }

    /// Returns the complete terminal coordinate set defining the estimand.
    #[must_use]
    pub const fn estimand_endpoints(&self) -> &BTreeSet<u64> {
        &self.estimand_endpoints
    }

    /// Returns one planned draw coordinate.
    #[must_use]
    pub fn draw(&self, coordinate: u64) -> Option<&StatisticalDrawPlan> {
        self.draws.get(&coordinate)
    }
}

impl Canonical for StatisticalSamplingDesign {
    fn encode(&self, encoder: &mut Encoder) {
        self.distributions.encode(encoder);
        self.draws.encode(encoder);
        self.estimand_endpoints.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            decoder.map_bounded(MAX_POLICY_ENTRIES, "statistical-distribution-count")?,
            decoder.map_bounded(MAX_POLICY_ENTRIES, "statistical-draw-count")?,
            decoder.set_bounded(MAX_POLICY_ENTRIES, "statistical-estimand-endpoint-count")?,
        )
    }
}

fn statistical_policy_mass_total(
    masses: &BTreeMap<ChoiceValue, u64>,
) -> Result<u64, CampaignCodecError> {
    masses.values().try_fold(0_u64, |total, mass| {
        total
            .checked_add(*mass)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "statistical policy mass sum exceeds u64",
            })
    })
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture construction uses exact panic localization.
    #![allow(clippy::expect_used)]

    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;
    use crate::{
        CampaignHash, CampaignMode, CampaignPolicy, CampaignSeed, ChoiceDomainSemanticId,
        ExactRational, ExplorerPolicy, FairnessPolicy, RetentionPolicy, ScenarioDefId,
        SelectableSemanticId, SequentialMonteCarloDesign, SmcOpportunitySelector,
        SmcResamplingAlgorithm, SmcResamplingPolicy, SmcStagePlan,
    };

    fn model(label: &str) -> ProbabilityModelId {
        ProbabilityModelId::from_hash(CampaignHash::derive(
            "test.statistical-model",
            label.as_bytes(),
        ))
    }

    fn draw(parent: Option<u64>, model: ProbabilityModelId, label: &str) -> StatisticalDrawPlan {
        StatisticalDrawPlan {
            parent,
            opportunity: ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                format!("opportunity-{label}").as_bytes(),
            ))
            .expect("opportunity ID"),
            opportunity_semantics: ChoiceOpportunitySemanticId::from_hash(CampaignHash::derive(
                "test.statistical-opportunity-semantics",
                label.as_bytes(),
            )),
            domain: ChoiceDomainId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                format!("domain-{label}").as_bytes(),
            ))
            .expect("domain ID"),
            model,
            stop: StopCondition::NextChoice,
        }
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

    #[test]
    fn finite_distribution_rejects_incomplete_or_nonpositive_mass_contracts() {
        assert!(matches!(
            StatisticalDistribution::new(BTreeMap::new(), BTreeMap::new()),
            Err(CampaignCodecError::InvalidValue {
                reason: "statistical distribution has invalid P or Q support"
            })
        ));
        assert!(matches!(
            StatisticalDistribution::new(
                BTreeMap::from([(ChoiceValue::Boolean(false), 1)]),
                BTreeMap::from([(ChoiceValue::Boolean(true), 1)]),
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "statistical distribution has invalid P or Q support"
            })
        ));
        assert!(matches!(
            StatisticalDistribution::new(
                BTreeMap::from([(ChoiceValue::Boolean(false), 0)]),
                BTreeMap::from([(ChoiceValue::Boolean(false), 1)]),
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "statistical distribution has invalid P or Q support"
            })
        ));
        assert!(matches!(
            StatisticalDistribution::new(
                BTreeMap::from([
                    (ChoiceValue::Boolean(false), u64::MAX),
                    (ChoiceValue::Boolean(true), 1),
                ]),
                BTreeMap::from([
                    (ChoiceValue::Boolean(false), 1),
                    (ChoiceValue::Boolean(true), 1),
                ]),
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "statistical policy mass sum exceeds u64"
            })
        ));
    }

    #[test]
    fn sampling_design_rejects_coordinate_and_endpoint_ambiguity() {
        let first_model = model("first");
        let second_model = model("second");
        let distributions = BTreeMap::from([
            (first_model, distribution()),
            (second_model, distribution()),
        ]);

        assert!(matches!(
            StatisticalSamplingDesign::new(
                distributions.clone(),
                BTreeMap::from([(1, draw(None, first_model, "gap"))]),
                BTreeSet::from([1]),
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "statistical sampling design has an invalid draw coordinate"
            })
        ));
        assert!(matches!(
            StatisticalSamplingDesign::new(
                distributions.clone(),
                BTreeMap::from([(0, draw(Some(0), first_model, "forward"))]),
                BTreeSet::from([0]),
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "statistical sampling design has an invalid draw coordinate"
            })
        ));
        assert!(matches!(
            StatisticalSamplingDesign::new(
                distributions.clone(),
                BTreeMap::from([
                    (0, draw(None, first_model, "nonterminal-root")),
                    (1, draw(Some(0), second_model, "nonterminal-leaf")),
                ]),
                BTreeSet::from([0]),
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "statistical estimand includes a missing or nonterminal coordinate"
            })
        ));
        assert!(matches!(
            StatisticalSamplingDesign::new(
                distributions,
                BTreeMap::from([
                    (0, draw(None, first_model, "mixed-root")),
                    (1, draw(None, second_model, "mixed-endpoint")),
                    (2, draw(Some(0), second_model, "mixed-leaf")),
                ]),
                BTreeSet::from([1, 2]),
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "statistical estimand mixes endpoint depths"
            })
        ));
    }

    fn smc_design(
        particle_count: u32,
        model: ProbabilityModelId,
        distribution: StatisticalDistribution,
    ) -> SequentialMonteCarloDesign {
        let selector = SmcOpportunitySelector::new(
            SelectableSemanticId::from_hash(CampaignHash::derive(
                "test.smc-declaration",
                b"declaration",
            )),
            ChoiceDomainSemanticId::from_hash(CampaignHash::derive("test.smc-domain", b"domain")),
            "next-choice",
            model,
            StopCondition::NextChoice,
        )
        .expect("SMC selector");
        let resampling = SmcResamplingPolicy::new(
            SmcResamplingAlgorithm::SystematicV1,
            ExactRational::new(1, 2).expect("ESS threshold"),
        )
        .expect("resampling policy");
        SequentialMonteCarloDesign::new(
            particle_count,
            BTreeMap::from([(model, distribution)]),
            BTreeMap::from([(1, SmcStagePlan::new(0, selector))]),
            resampling,
        )
        .expect("SMC design")
    }

    fn statistical_policy() -> CampaignPolicy {
        CampaignPolicy::new(
            ScenarioDefId::from_hash(CampaignHash::derive("test.scenario", b"scenario")),
            CampaignSeed::from_bytes([0x31; 32]),
            CampaignMode::Statistical,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 16,
            },
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness policy"),
            RetentionPolicy::new(false, 2, false, false),
            false,
        )
        .expect("statistical policy")
    }

    #[test]
    fn smc_policy_binds_initial_particles_and_shared_model_distributions() {
        let shared_model = model("shared");
        let shared_distribution = distribution();
        let initial = StatisticalSamplingDesign::new(
            BTreeMap::from([(shared_model, shared_distribution.clone())]),
            BTreeMap::from([
                (0, draw(None, shared_model, "initial-a")),
                (1, draw(None, shared_model, "initial-b")),
            ]),
            BTreeSet::from([0, 1]),
        )
        .expect("initial design");

        assert!(matches!(
            statistical_policy().with_sequential_monte_carlo_design(
                initial.clone(),
                smc_design(1, shared_model, shared_distribution.clone()),
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "SMC design disagrees with initial statistical flight"
            })
        ));

        let conflicting_distribution = StatisticalDistribution::new(
            BTreeMap::from([
                (ChoiceValue::Boolean(false), 1),
                (ChoiceValue::Boolean(true), 3),
            ]),
            BTreeMap::from([
                (ChoiceValue::Boolean(false), 1),
                (ChoiceValue::Boolean(true), 1),
            ]),
        )
        .expect("conflicting distribution");
        assert!(matches!(
            statistical_policy().with_sequential_monte_carlo_design(
                initial.clone(),
                smc_design(2, shared_model, conflicting_distribution),
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "SMC design disagrees with initial statistical flight"
            })
        ));

        let policy = statistical_policy()
            .with_sequential_monte_carlo_design(
                initial.clone(),
                smc_design(2, shared_model, shared_distribution),
            )
            .expect("SMC policy");
        assert_eq!(policy.schema_version(), 4);
        assert_eq!(
            CampaignPolicy::from_canonical_bytes(&policy.canonical_bytes())
                .expect("canonical SMC policy"),
            policy
        );
        assert!(
            policy
                .clone()
                .with_statistical_sampling_design(initial)
                .is_err()
        );
        assert_eq!(
            policy
                .id()
                .expect("SMC policy ID")
                .content_id()
                .schema_version(),
            4
        );
    }

    #[test]
    fn smc_policy_decode_rechecks_initial_particle_and_distribution_contracts() {
        let shared_model = model("decode-shared");
        let shared_distribution = distribution();
        let initial = StatisticalSamplingDesign::new(
            BTreeMap::from([(shared_model, shared_distribution.clone())]),
            BTreeMap::from([
                (0, draw(None, shared_model, "decode-a")),
                (1, draw(None, shared_model, "decode-b")),
            ]),
            BTreeSet::from([0, 1]),
        )
        .expect("initial design");
        let policy = statistical_policy()
            .with_sequential_monte_carlo_design(
                initial.clone(),
                smc_design(2, shared_model, shared_distribution),
            )
            .expect("SMC policy");

        let mut mismatched_count = policy.clone();
        mismatched_count.statistical_sampling = Some(
            StatisticalSamplingDesign::new(
                initial.distributions().clone(),
                BTreeMap::from([(0, initial.draw(0).expect("first initial draw").clone())]),
                BTreeSet::from([0]),
            )
            .expect("one-particle initial design"),
        );
        assert!(matches!(
            CampaignPolicy::from_canonical_bytes(&crate::codec::encode(&mismatched_count)),
            Err(CampaignCodecError::InvalidValue {
                reason: "SMC design disagrees with initial statistical flight"
            })
        ));

        let conflicting_distribution = StatisticalDistribution::new(
            BTreeMap::from([
                (ChoiceValue::Boolean(false), 3),
                (ChoiceValue::Boolean(true), 1),
            ]),
            BTreeMap::from([
                (ChoiceValue::Boolean(false), 1),
                (ChoiceValue::Boolean(true), 1),
            ]),
        )
        .expect("conflicting distribution");
        let mut conflicting_model = policy;
        conflicting_model.statistical_sampling = Some(
            StatisticalSamplingDesign::new(
                BTreeMap::from([(shared_model, conflicting_distribution)]),
                initial.draws().clone(),
                initial.estimand_endpoints().clone(),
            )
            .expect("conflicting initial design"),
        );
        assert!(matches!(
            CampaignPolicy::from_canonical_bytes(&crate::codec::encode(&conflicting_model)),
            Err(CampaignCodecError::InvalidValue {
                reason: "SMC design disagrees with initial statistical flight"
            })
        ));
    }
}
