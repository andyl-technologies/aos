//! Campaign contracts.

use super::*;

/// Exact fixed-point weight for one canonical guidance signal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GuidanceWeight {
    signal: String,
    weight_micros: u64,
}

impl GuidanceWeight {
    /// Builds one guidance signal weight.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] for an invalid signal name
    /// or zero weight.
    pub fn new(signal: impl Into<String>, weight_micros: u64) -> Result<Self, CampaignCodecError> {
        let signal = signal.into();
        validate_identifier(&signal, "guidance signal is invalid")?;
        if weight_micros == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "guidance weight is zero",
            });
        }
        Ok(Self {
            signal,
            weight_micros,
        })
    }

    /// Returns the stable guidance signal name.
    #[must_use]
    pub fn signal(&self) -> &str {
        &self.signal
    }

    /// Returns the exact fixed-point guidance weight in millionths.
    #[must_use]
    pub const fn weight_micros(&self) -> u64 {
        self.weight_micros
    }
}

impl Canonical for GuidanceWeight {
    fn encode(&self, encoder: &mut Encoder) {
        self.signal.encode(encoder);
        self.weight_micros.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "guidance-signal-bytes")?,
            u64::decode(decoder)?,
        )
    }
}

/// Fairness reservations independent of objective ranking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FairnessPolicy {
    breadth_first_percent: u8,
    novelty_reserve: u64,
}

impl FairnessPolicy {
    /// Builds bounded fairness reservations.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when the percentage exceeds
    /// 100.
    pub fn new(
        breadth_first_percent: u8,
        novelty_reserve: u64,
    ) -> Result<Self, CampaignCodecError> {
        if breadth_first_percent > 100 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "breadth-first fairness percentage exceeds 100",
            });
        }
        Ok(Self {
            breadth_first_percent,
            novelty_reserve,
        })
    }

    /// Returns the breadth-first reservation percentage.
    #[must_use]
    pub const fn breadth_first_percent(self) -> u8 {
        self.breadth_first_percent
    }

    /// Returns the minimum novelty-reserved work allowance.
    #[must_use]
    pub const fn novelty_reserve(self) -> u64 {
        self.novelty_reserve
    }
}

impl Canonical for FairnessPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        self.breadth_first_percent.encode(encoder);
        self.novelty_reserve.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(u8::decode(decoder)?, u64::decode(decoder)?)
    }
}

/// Semantic retention intent; physical tier choices remain operational.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RetentionPolicy {
    retain_all_findings: bool,
    survivor_limit: u64,
    exact_findings: bool,
    exact_user_pins: bool,
}

impl RetentionPolicy {
    /// Builds semantic retention intent.
    #[must_use]
    pub const fn new(
        retain_all_findings: bool,
        survivor_limit: u64,
        exact_findings: bool,
        exact_user_pins: bool,
    ) -> Self {
        Self {
            retain_all_findings,
            survivor_limit,
            exact_findings,
            exact_user_pins,
        }
    }

    /// Returns whether every finding is retained semantically.
    #[must_use]
    pub const fn retain_all_findings(self) -> bool {
        self.retain_all_findings
    }

    /// Returns the retained survivor cap.
    #[must_use]
    pub const fn survivor_limit(self) -> u64 {
        self.survivor_limit
    }

    /// Returns whether finding closures require exact retention.
    #[must_use]
    pub const fn exact_findings(self) -> bool {
        self.exact_findings
    }

    /// Returns whether user pins require exact retention.
    #[must_use]
    pub const fn exact_user_pins(self) -> bool {
        self.exact_user_pins
    }
}

impl Canonical for RetentionPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        self.retain_all_findings.encode(encoder);
        self.survivor_limit.encode(encoder);
        self.exact_findings.encode(encoder);
        self.exact_user_pins.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            retain_all_findings: bool::decode(decoder)?,
            survivor_limit: u64::decode(decoder)?,
            exact_findings: bool::decode(decoder)?,
            exact_user_pins: bool::decode(decoder)?,
        })
    }
}

/// Complete immutable campaign policy revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignPolicy {
    schema_version: u32,
    scenario: ScenarioDefId,
    campaign_seed: CampaignSeed,
    mode: CampaignMode,
    explorer: ExplorerPolicy,
    choice_policies: BTreeMap<String, ChoicePolicy>,
    objectives: BTreeMap<String, Objective>,
    guidance: BTreeMap<String, GuidanceWeight>,
    stop_conditions: BTreeSet<String>,
    fairness: FairnessPolicy,
    retention: RetentionPolicy,
    admit_scenario_defaults: bool,
    intervention_learning: InterventionLearningPolicy,
    pub(super) statistical_sampling: Option<StatisticalSamplingDesign>,
    sequential_monte_carlo: Option<SequentialMonteCarloDesign>,
}

/// Scenario and exploration-engine identity for a campaign policy revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignPolicyIdentity {
    scenario: ScenarioDefId,
    campaign_seed: CampaignSeed,
    mode: CampaignMode,
    explorer: ExplorerPolicy,
}

impl CampaignPolicyIdentity {
    /// Builds the immutable scenario and exploration-engine portion of a policy.
    #[must_use]
    pub fn new(
        scenario: ScenarioDefId,
        campaign_seed: CampaignSeed,
        mode: CampaignMode,
        explorer: ExplorerPolicy,
    ) -> Self {
        Self {
            scenario,
            campaign_seed,
            mode,
            explorer,
        }
    }
}

/// Choice, scoring, stopping, fairness, and retention rules for a campaign policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignPolicyRules {
    choice_policies: BTreeMap<String, ChoicePolicy>,
    objectives: BTreeMap<String, Objective>,
    guidance: BTreeMap<String, GuidanceWeight>,
    stop_conditions: BTreeSet<String>,
    fairness: FairnessPolicy,
    retention: RetentionPolicy,
    admit_scenario_defaults: bool,
}

impl CampaignPolicyRules {
    /// Builds the bounded rule collections and lifecycle policy portion.
    #[must_use]
    pub fn new(
        choice_policies: BTreeMap<String, ChoicePolicy>,
        objectives: BTreeMap<String, Objective>,
        guidance: BTreeMap<String, GuidanceWeight>,
        stop_conditions: BTreeSet<String>,
        fairness: FairnessPolicy,
        retention: RetentionPolicy,
        admit_scenario_defaults: bool,
    ) -> Self {
        Self {
            choice_policies,
            objectives,
            guidance,
            stop_conditions,
            fairness,
            retention,
            admit_scenario_defaults,
        }
    }
}

/// Controls whether intervention observations may guide adaptive exploration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InterventionLearningPolicy {
    /// Retains intervention observations without feeding them into guidance.
    #[default]
    Exclude,
    /// Allows operator and debugger execution bases to influence guidance.
    IncludeInGuidance,
}

impl Canonical for InterventionLearningPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Exclude => 0,
            Self::IncludeInGuidance => 1,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Exclude),
            1 => Ok(Self::IncludeInGuidance),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "intervention-learning-policy",
                tag,
            }),
        }
    }
}

impl CampaignPolicy {
    /// Builds a validated version-one policy with canonical map/set ordering.
    ///
    /// Operator- and debugger-initiated attempts are retained but excluded
    /// from adaptive guidance unless [`Self::with_intervention_learning_policy`]
    /// explicitly opts in.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when a collection exceeds
    /// its bound, a map key disagrees with its value, or a stop name is invalid.
    /// Builds the identity portion accepted by [`Self::new`].
    #[must_use]
    pub fn identity(
        scenario: ScenarioDefId,
        campaign_seed: CampaignSeed,
        mode: CampaignMode,
        explorer: ExplorerPolicy,
    ) -> CampaignPolicyIdentity {
        CampaignPolicyIdentity::new(scenario, campaign_seed, mode, explorer)
    }

    /// Builds the rule portion accepted by [`Self::new`].
    #[must_use]
    pub fn rules(
        choice_policies: BTreeMap<String, ChoicePolicy>,
        objectives: BTreeMap<String, Objective>,
        guidance: BTreeMap<String, GuidanceWeight>,
        stop_conditions: BTreeSet<String>,
        fairness: FairnessPolicy,
        retention: RetentionPolicy,
        admit_scenario_defaults: bool,
    ) -> CampaignPolicyRules {
        CampaignPolicyRules::new(
            choice_policies,
            objectives,
            guidance,
            stop_conditions,
            fairness,
            retention,
            admit_scenario_defaults,
        )
    }

    /// Builds a validated policy from its exploration identity and rules.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when a collection exceeds
    /// its bound, a map key disagrees with its value, or a stop name is invalid.
    pub fn new(
        identity: CampaignPolicyIdentity,
        rules: CampaignPolicyRules,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_for_schema(
            BASE_CAMPAIGN_POLICY_SCHEMA_VERSION,
            identity,
            rules,
            InterventionLearningPolicy::Exclude,
            None,
            None,
        )
    }

    fn new_for_schema(
        schema_version: u32,
        identity: CampaignPolicyIdentity,
        rules: CampaignPolicyRules,
        intervention_learning: InterventionLearningPolicy,
        statistical_sampling: Option<StatisticalSamplingDesign>,
        sequential_monte_carlo: Option<SequentialMonteCarloDesign>,
    ) -> Result<Self, CampaignCodecError> {
        let CampaignPolicyIdentity {
            scenario,
            campaign_seed,
            mode,
            explorer,
        } = identity;
        let CampaignPolicyRules {
            choice_policies,
            objectives,
            guidance,
            stop_conditions,
            fairness,
            retention,
            admit_scenario_defaults,
        } = rules;

        explorer.validate()?;
        let statistical_shape_is_valid = match schema_version {
            BASE_CAMPAIGN_POLICY_SCHEMA_VERSION | INTERVENTION_CAMPAIGN_POLICY_SCHEMA_VERSION => {
                statistical_sampling.is_none() && sequential_monte_carlo.is_none()
            }
            FINITE_STATISTICAL_CAMPAIGN_POLICY_SCHEMA_VERSION => {
                statistical_sampling.is_some()
                    && sequential_monte_carlo.is_none()
                    && mode == CampaignMode::Statistical
                    && matches!(explorer, ExplorerPolicy::Exhaustive { .. })
            }
            CAMPAIGN_POLICY_SCHEMA_VERSION => {
                statistical_sampling.is_some()
                    && sequential_monte_carlo.is_some()
                    && mode == CampaignMode::Statistical
            }
            _ => false,
        };
        if !statistical_shape_is_valid {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical sampling design disagrees with campaign policy",
            });
        }
        if let (Some(initial), Some(sequential)) = (&statistical_sampling, &sequential_monte_carlo)
        {
            let particle_count = usize::try_from(sequential.particle_count()).map_err(|_| {
                CampaignCodecError::InvalidValue {
                    reason: "SMC particle count cannot be represented",
                }
            })?;
            if initial.estimand_endpoints().len() != particle_count
                || initial.distributions().iter().any(|(model, distribution)| {
                    sequential
                        .distributions()
                        .get(model)
                        .is_some_and(|sequential_distribution| {
                            sequential_distribution != distribution
                        })
                })
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "SMC design disagrees with initial statistical flight",
                });
            }
        }
        for length in [
            choice_policies.len(),
            objectives.len(),
            guidance.len(),
            stop_conditions.len(),
        ] {
            if length > MAX_POLICY_ENTRIES {
                return Err(CampaignCodecError::LimitExceeded {
                    limit: "campaign-policy-entry-count",
                });
            }
        }
        for (selector, policy) in &choice_policies {
            if selector != policy.selector() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "choice-policy map key disagrees with selector",
                });
            }
        }
        for (measurement, objective) in &objectives {
            if measurement != objective.measurement() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "objective map key disagrees with measurement",
                });
            }
        }
        for (signal, weight) in &guidance {
            if signal != weight.signal() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "guidance map key disagrees with signal",
                });
            }
        }
        for stop in &stop_conditions {
            validate_identifier(stop, "stop-condition identifier is invalid")?;
        }
        let policy = Self {
            schema_version,
            scenario,
            campaign_seed,
            mode,
            explorer,
            choice_policies,
            objectives,
            guidance,
            stop_conditions,
            fairness,
            retention,
            admit_scenario_defaults,
            intervention_learning,
            statistical_sampling,
            sequential_monte_carlo,
        };
        codec::ensure_encoded_size(
            &policy,
            MAX_CAMPAIGN_POLICY_BYTES,
            "campaign-policy-encoded-bytes",
        )?;
        Ok(policy)
    }

    /// Returns a version-two policy with an explicit intervention-learning rule.
    ///
    /// This setting affects adaptive guidance only. It does not make
    /// intervention observations eligible for statistical estimators.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::LimitExceeded`] if the version-two
    /// representation exceeds the campaign-policy size bound.
    pub fn with_intervention_learning_policy(
        mut self,
        intervention_learning: InterventionLearningPolicy,
    ) -> Result<Self, CampaignCodecError> {
        self.schema_version = self
            .schema_version
            .max(INTERVENTION_CAMPAIGN_POLICY_SCHEMA_VERSION);
        self.intervention_learning = intervention_learning;
        codec::ensure_encoded_size(
            &self,
            MAX_CAMPAIGN_POLICY_BYTES,
            "campaign-policy-encoded-bytes",
        )?;
        Ok(self)
    }

    /// Returns a version-three statistical policy with one pinned finite design.
    ///
    /// The initial implementation admits only the static exhaustive engine;
    /// adaptive Beam and PUCT designs require separately declared resampling
    /// rules before they can make statistical claims.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] unless this is a statistical policy using
    /// the exhaustive engine, or when the representation exceeds its bound.
    pub fn with_statistical_sampling_design(
        mut self,
        design: StatisticalSamplingDesign,
    ) -> Result<Self, CampaignCodecError> {
        if self.mode != CampaignMode::Statistical
            || !matches!(self.explorer, ExplorerPolicy::Exhaustive { .. })
            || self.sequential_monte_carlo.is_some()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical sampling design requires static exhaustive policy",
            });
        }
        self.schema_version = FINITE_STATISTICAL_CAMPAIGN_POLICY_SCHEMA_VERSION;
        self.statistical_sampling = Some(design);
        codec::ensure_encoded_size(
            &self,
            MAX_CAMPAIGN_POLICY_BYTES,
            "campaign-policy-encoded-bytes",
        )?;
        Ok(self)
    }

    /// Returns a version-four policy with a bounded SMC extension.
    ///
    /// The finite design supplies the complete stage-zero particle flight. The
    /// SMC design predeclares all later selector/model contexts and deterministic
    /// resampling policy. Probability reports remain unavailable until the full
    /// SMC planner and estimator validate every generation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if this is not a statistical policy, the
    /// initial endpoint count differs from the fixed particle count, a reused
    /// model ID names conflicting distributions, or the encoded policy exceeds
    /// its size bound.
    pub fn with_sequential_monte_carlo_design(
        mut self,
        initial_sampling: StatisticalSamplingDesign,
        sequential_monte_carlo: SequentialMonteCarloDesign,
    ) -> Result<Self, CampaignCodecError> {
        self.schema_version = CAMPAIGN_POLICY_SCHEMA_VERSION;
        self.statistical_sampling = Some(initial_sampling);
        self.sequential_monte_carlo = Some(sequential_monte_carlo);
        Self::new_for_schema(
            self.schema_version,
            Self::identity(self.scenario, self.campaign_seed, self.mode, self.explorer),
            Self::rules(
                self.choice_policies,
                self.objectives,
                self.guidance,
                self.stop_conditions,
                self.fairness,
                self.retention,
                self.admit_scenario_defaults,
            ),
            self.intervention_learning,
            self.statistical_sampling,
            self.sequential_monte_carlo,
        )
    }

    /// Returns the referenced immutable scenario.
    #[must_use]
    pub const fn scenario(&self) -> ScenarioDefId {
        self.scenario
    }

    /// Returns the policy's reproducibility mode.
    #[must_use]
    pub const fn mode(&self) -> CampaignMode {
        self.mode
    }

    /// Returns the policy's fixed campaign seed.
    #[must_use]
    pub const fn campaign_seed(&self) -> CampaignSeed {
        self.campaign_seed
    }

    /// Returns the configured exploration algorithm.
    #[must_use]
    pub const fn explorer(&self) -> &ExplorerPolicy {
        &self.explorer
    }

    /// Returns selectable policies keyed by stable selector.
    #[must_use]
    pub const fn choice_policies(&self) -> &BTreeMap<String, ChoicePolicy> {
        &self.choice_policies
    }

    /// Returns objectives keyed by measurement name.
    #[must_use]
    pub const fn objectives(&self) -> &BTreeMap<String, Objective> {
        &self.objectives
    }

    pub(crate) fn objective_contract_hash(&self) -> CampaignHash {
        crate::objective::objective_contract_hash(self.objectives.values().map(|objective| {
            (
                objective.measurement(),
                objective.goal(),
                objective.weight_micros(),
            )
        }))
    }

    /// Returns guidance weights keyed by signal name.
    #[must_use]
    pub const fn guidance(&self) -> &BTreeMap<String, GuidanceWeight> {
        &self.guidance
    }

    /// Returns named semantic stop conditions.
    #[must_use]
    pub const fn stop_conditions(&self) -> &BTreeSet<String> {
        &self.stop_conditions
    }

    /// Returns fairness reservations independent of objective ordering.
    #[must_use]
    pub const fn fairness(&self) -> FairnessPolicy {
        self.fairness
    }

    /// Returns semantic retention intent.
    #[must_use]
    pub const fn retention(&self) -> RetentionPolicy {
        self.retention
    }

    /// Returns whether undeclared scenario defaults may be admitted.
    #[must_use]
    pub const fn admits_scenario_defaults(&self) -> bool {
        self.admit_scenario_defaults
    }

    /// Returns the rule for using intervention observations in guidance.
    #[must_use]
    pub const fn intervention_learning_policy(&self) -> InterventionLearningPolicy {
        self.intervention_learning
    }

    /// Returns the finite sampling design pinned for statistical execution.
    #[must_use]
    pub const fn statistical_sampling_design(&self) -> Option<&StatisticalSamplingDesign> {
        self.statistical_sampling.as_ref()
    }

    /// Returns the sequential Monte Carlo extension pinned for this policy.
    #[must_use]
    pub const fn sequential_monte_carlo_design(&self) -> Option<&SequentialMonteCarloDesign> {
        self.sequential_monte_carlo.as_ref()
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = self
            .choice_policies
            .values()
            .enumerate()
            .map(|(index, policy)| {
                (
                    format!("choice-generator.{index:04x}"),
                    policy.generator().content_id(),
                )
            })
            .collect::<Vec<_>>();
        if let Some(design) = &self.statistical_sampling {
            for (coordinate, draw) in design.draws() {
                children.push((
                    format!("statistical-opportunity.{coordinate:04x}"),
                    draw.opportunity().content_id(),
                ));
                children.push((
                    format!("statistical-domain.{coordinate:04x}"),
                    draw.domain().content_id(),
                ));
            }
        }
        children
    }

    /// Returns the canonical binary representation.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Parses and validates the strict canonical binary representation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, oversized,
    /// non-canonical, or semantically invalid bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_CAMPAIGN_POLICY_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "campaign-policy-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the domain-separated policy identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<CampaignPolicyId, CampaignCodecError> {
        CampaignPolicyId::from_content_id(crate::ObjectEnvelope::for_policy(self)?.content_id())
    }
}

impl Canonical for CampaignPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.scenario.encode(encoder);
        self.campaign_seed.encode(encoder);
        self.mode.encode(encoder);
        self.explorer.encode(encoder);
        self.choice_policies.encode(encoder);
        self.objectives.encode(encoder);
        self.guidance.encode(encoder);
        self.stop_conditions.encode(encoder);
        self.fairness.encode(encoder);
        self.retention.encode(encoder);
        self.admit_scenario_defaults.encode(encoder);
        if self.schema_version >= INTERVENTION_CAMPAIGN_POLICY_SCHEMA_VERSION {
            self.intervention_learning.encode(encoder);
        }
        if self.schema_version >= FINITE_STATISTICAL_CAMPAIGN_POLICY_SCHEMA_VERSION {
            self.statistical_sampling.encode(encoder);
        }
        if self.schema_version >= CAMPAIGN_POLICY_SCHEMA_VERSION {
            self.sequential_monte_carlo.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if !matches!(
            schema_version,
            BASE_CAMPAIGN_POLICY_SCHEMA_VERSION
                | INTERVENTION_CAMPAIGN_POLICY_SCHEMA_VERSION
                | FINITE_STATISTICAL_CAMPAIGN_POLICY_SCHEMA_VERSION
                | CAMPAIGN_POLICY_SCHEMA_VERSION
        ) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported campaign-policy schema version",
            });
        }
        let scenario = ScenarioDefId::decode(decoder)?;
        let campaign_seed = CampaignSeed::decode(decoder)?;
        let mode = CampaignMode::decode(decoder)?;
        let explorer = ExplorerPolicy::decode(decoder)?;
        let choice_policies = decoder.map_bounded_by(
            MAX_POLICY_ENTRIES,
            "campaign-choice-policy-count",
            |decoder| decoder.string_bounded(MAX_IDENTIFIER_BYTES, "choice-policy-map-key-bytes"),
            ChoicePolicy::decode,
        )?;
        let objectives = decoder.map_bounded_by(
            MAX_POLICY_ENTRIES,
            "campaign-objective-count",
            |decoder| decoder.string_bounded(MAX_IDENTIFIER_BYTES, "objective-map-key-bytes"),
            Objective::decode,
        )?;
        let guidance = decoder.map_bounded_by(
            MAX_POLICY_ENTRIES,
            "campaign-guidance-count",
            |decoder| decoder.string_bounded(MAX_IDENTIFIER_BYTES, "guidance-map-key-bytes"),
            GuidanceWeight::decode,
        )?;
        let stop_conditions = decoder.set_bounded_by(
            MAX_POLICY_ENTRIES,
            "campaign-stop-condition-count",
            |decoder| decoder.string_bounded(MAX_IDENTIFIER_BYTES, "stop-condition-name-bytes"),
        )?;
        let fairness = FairnessPolicy::decode(decoder)?;
        let retention = RetentionPolicy::decode(decoder)?;
        let admit_scenario_defaults = bool::decode(decoder)?;
        let intervention_learning = if schema_version >= INTERVENTION_CAMPAIGN_POLICY_SCHEMA_VERSION
        {
            InterventionLearningPolicy::decode(decoder)?
        } else {
            InterventionLearningPolicy::Exclude
        };
        let statistical_sampling =
            if schema_version >= FINITE_STATISTICAL_CAMPAIGN_POLICY_SCHEMA_VERSION {
                Option::decode(decoder)?
            } else {
                None
            };
        let sequential_monte_carlo = if schema_version >= CAMPAIGN_POLICY_SCHEMA_VERSION {
            Option::decode(decoder)?
        } else {
            None
        };
        if statistical_sampling.is_some()
            != matches!(
                schema_version,
                FINITE_STATISTICAL_CAMPAIGN_POLICY_SCHEMA_VERSION | CAMPAIGN_POLICY_SCHEMA_VERSION
            )
            || sequential_monte_carlo.is_some()
                != (schema_version == CAMPAIGN_POLICY_SCHEMA_VERSION)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign-policy statistical design disagrees with schema",
            });
        }
        Self::new_for_schema(
            schema_version,
            Self::identity(scenario, campaign_seed, mode, explorer),
            Self::rules(
                choice_policies,
                objectives,
                guidance,
                stop_conditions,
                fairness,
                retention,
                admit_scenario_defaults,
            ),
            intervention_learning,
            statistical_sampling,
            sequential_monte_carlo,
        )
    }
}

pub(crate) fn validate_identifier(
    value: &str,
    reason: &'static str,
) -> Result<(), CampaignCodecError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        });
    if valid {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue { reason })
    }
}

pub(super) const fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    if left == 0 { 1 } else { left }
}
