//! Strict offline authoring for canonical campaign policy records.

use super::*;

use std::collections::{BTreeMap, BTreeSet};

use crucible::ScenarioDefForm;
use crucible_campaign::{
    AlternativeId, CampaignHash, CampaignMode, CampaignSeed, ChoiceClassContext, ChoiceDomainId,
    ChoiceDomainSemanticId, ChoiceOpportunityId, ChoiceOpportunitySemanticId, ChoicePolicy,
    ChoiceValue, ExactRational, ExplorerPolicy, FairnessPolicy, GuidanceWeight, IntegerValue,
    InterventionLearningPolicy, Objective, ObjectiveGoal, ProbabilityModelId,
    ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy, ScenarioDefId, SelectableId,
    SelectableSemanticId, SequentialMonteCarloDesign, SmcOpportunitySelector,
    SmcResamplingAlgorithm, SmcResamplingPolicy, SmcStagePlan, StatisticalDistribution,
    StatisticalDrawPlan, StatisticalSamplingDesign,
};
use crucible_daemon::MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES;
use serde::{Deserialize, Serialize};

use super::authoring::{read_bounded_utf8, write_new_record};

const CAMPAIGN_POLICY_AUTHORING_SCHEMA_VERSION: u32 = 2;
const MAX_CAMPAIGN_POLICY_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const CAMPAIGN_POLICY_COMPILATION_REPORT_SCHEMA: &str =
    "crucible.cli.campaign-policy-compilation.v1";
const MAX_AUTHORED_CHOICE_SELECTOR_TAGS: usize = 16;

/// Result of compiling one strict authored policy.
#[derive(Debug, Serialize)]
pub(super) struct CampaignPolicyCompilationReport {
    schema: &'static str,
    input: String,
    output: String,
    policy: String,
    encoded_bytes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredCampaignPolicy {
    schema_version: u32,
    scenario: String,
    campaign_seed: String,
    mode: AuthoredCampaignMode,
    explorer: AuthoredExplorerPolicy,
    #[serde(default)]
    choices: Vec<AuthoredChoicePolicy>,
    #[serde(default)]
    objectives: Vec<AuthoredObjective>,
    #[serde(default)]
    guidance: Vec<AuthoredGuidance>,
    #[serde(default)]
    stop_conditions: Vec<String>,
    fairness: AuthoredFairnessPolicy,
    retention: AuthoredRetentionPolicy,
    #[serde(default)]
    admit_scenario_defaults: bool,
    #[serde(default)]
    intervention_learning: AuthoredInterventionLearningPolicy,
    #[serde(default)]
    statistical_sampling: Option<AuthoredStatisticalSamplingDesign>,
    #[serde(default)]
    sequential_monte_carlo: Option<AuthoredSequentialMonteCarloDesign>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuthoredCampaignMode {
    Strict,
    Streaming,
    Statistical,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuthoredInterventionLearningPolicy {
    #[default]
    Exclude,
    IncludeInGuidance,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum AuthoredExplorerPolicy {
    TreeSearch {
        exploration_weight_micros: u64,
        novelty_bonus_micros: u64,
        fairness_bonus_micros: u64,
        widening: Option<AuthoredProgressiveWidening>,
    },
    Beam {
        width: u64,
        novelty_reserve: u64,
    },
    Exhaustive {
        maximum_cardinality: u64,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredProgressiveWidening {
    k_numerator: u64,
    k_denominator: u64,
    alpha_numerator: u64,
    alpha_denominator: u64,
    initial_children: u64,
    maximum_children: u64,
    minimum_visits_per_child: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredChoicePolicy {
    selector: AuthoredChoiceSelector,
    generator: String,
    required: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AuthoredChoiceSelector {
    Name(String),
    Expression(AuthoredChoiceSelectorExpression),
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum AuthoredChoiceSelectorExpression {
    Selectable { id: String },
    Tags { all: Vec<String> },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredObjective {
    measurement: String,
    goal: AuthoredObjectiveGoal,
    weight_micros: u64,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuthoredObjectiveGoal {
    Minimize,
    Maximize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredGuidance {
    signal: String,
    weight_micros: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredFairnessPolicy {
    breadth_first_percent: u8,
    novelty_reserve: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredRetentionPolicy {
    retain_all_findings: bool,
    survivor_limit: u64,
    exact_findings: bool,
    exact_user_pins: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredStatisticalSamplingDesign {
    distributions: Vec<AuthoredStatisticalDistribution>,
    draws: Vec<AuthoredStatisticalDraw>,
    estimand_endpoints: Vec<AuthoredU64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredStatisticalDistribution {
    model: String,
    target: Vec<AuthoredStatisticalMass>,
    proposal: Vec<AuthoredStatisticalMass>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredStatisticalMass {
    value: AuthoredStatisticalValue,
    mass: AuthoredU64,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum AuthoredStatisticalValue {
    Boolean { value: bool },
    Discrete { alternative: String },
    Signed { value: i64 },
    Unsigned { value: AuthoredU64 },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredStatisticalDraw {
    coordinate: AuthoredU64,
    parent: Option<AuthoredU64>,
    opportunity: String,
    opportunity_semantics: String,
    domain: String,
    model: String,
    stop: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredSequentialMonteCarloDesign {
    particle_count: u32,
    distributions: Vec<AuthoredStatisticalDistribution>,
    stages: Vec<AuthoredSmcStage>,
    resampling: AuthoredSmcResampling,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredSmcStage {
    stage: u32,
    parent_stage: u32,
    declaration: String,
    domain: String,
    instance: String,
    model: String,
    stop: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredSmcResampling {
    algorithm: AuthoredSmcResamplingAlgorithm,
    effective_sample_size_threshold: AuthoredExactRational,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuthoredSmcResamplingAlgorithm {
    SystematicV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredExactRational {
    numerator: AuthoredU64,
    denominator: AuthoredU64,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum AuthoredU64 {
    Integer(u64),
    Decimal(String),
}

pub(super) fn compile_campaign_policy(
    input: &Path,
    scenario_input: Option<&Path>,
    output: &Path,
) -> Result<CampaignPolicyCompilationReport, CliError> {
    let text = read_bounded_utf8(
        input,
        "campaign policy manifest",
        MAX_CAMPAIGN_POLICY_MANIFEST_BYTES,
    )?;
    let authored: AuthoredCampaignPolicy = toml::from_str(&text).map_err(|error| {
        usage_error(format!(
            "invalid campaign policy manifest at {}: {error}",
            input.display()
        ))
    })?;
    let scenario = scenario_input
        .map(|path| {
            let text = read_bounded_utf8(
                path,
                "campaign policy selector scenario",
                MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES,
            )?;
            ScenarioDefForm::from_canonical_toml(&text).map_err(|error| {
                usage_error(format!(
                    "invalid canonical selector scenario at {}: {error}",
                    path.display()
                ))
            })
        })
        .transpose()?;
    let policy = authored.into_policy(scenario.as_ref())?;
    let policy_id = policy
        .id()
        .map_err(|error| usage_error(format!("invalid authored campaign policy: {error}")))?;
    let bytes = policy.canonical_bytes();

    write_new_record(output, "campaign policy record", &bytes)?;
    Ok(CampaignPolicyCompilationReport {
        schema: CAMPAIGN_POLICY_COMPILATION_REPORT_SCHEMA,
        input: input.display().to_string(),
        output: output.display().to_string(),
        policy: policy_id.to_string(),
        encoded_bytes: bytes.len(),
    })
}

pub(super) fn render_campaign_policy_compilation(
    report: &CampaignPolicyCompilationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            backend_error(format!("campaign policy JSON encoding failed: {error}"))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            backend_error(format!("campaign policy JSON encoding failed: {error}"))
        }),
        OutputFormat::Table => Ok([
            format!("{:<16} {}", "policy", report.policy),
            format!("{:<16} {}", "encoded_bytes", report.encoded_bytes),
            format!("{:<16} {}", "output", report.output),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| policy | {} |\n| encoded bytes | {} |\n| output | {} |",
            report.policy, report.encoded_bytes, report.output
        )),
    }
}

impl AuthoredCampaignPolicy {
    fn into_policy(
        self,
        selector_scenario: Option<&ScenarioDefForm>,
    ) -> Result<CampaignPolicy, CliError> {
        if !matches!(
            self.schema_version,
            1 | CAMPAIGN_POLICY_AUTHORING_SCHEMA_VERSION
        ) {
            return Err(usage_error(format!(
                "unsupported campaign policy manifest schema version {}; expected 1 or {}",
                self.schema_version, CAMPAIGN_POLICY_AUTHORING_SCHEMA_VERSION,
            )));
        }
        if self.schema_version == 1
            && (self.statistical_sampling.is_some() || self.sequential_monte_carlo.is_some())
        {
            return Err(usage_error(
                "statistical policy authoring requires manifest schema_version = 2",
            ));
        }
        let statistical_sampling = self
            .statistical_sampling
            .map(AuthoredStatisticalSamplingDesign::into_policy)
            .transpose()?;
        let sequential_monte_carlo = self
            .sequential_monte_carlo
            .map(AuthoredSequentialMonteCarloDesign::into_policy)
            .transpose()?;
        let scenario = ScenarioDefId::parse(&self.scenario)
            .map_err(|error| usage_error(format!("invalid policy scenario ID: {error}")))?;
        if let Some(selector_scenario) = selector_scenario
            && scenario
                != ScenarioDefId::from_hash(CampaignHash::from_bytes(selector_scenario.id().bytes))
        {
            return Err(usage_error(
                "campaign policy scenario does not match the selector-resolution scenario",
            ));
        }
        let campaign_seed = parse_campaign_seed(&self.campaign_seed)?;
        let explorer = self.explorer.into_policy()?;
        let choices = collect_choices(self.choices, selector_scenario)?;
        let objectives = collect_objectives(self.objectives)?;
        let guidance = collect_guidance(self.guidance)?;
        let stop_conditions = collect_stop_conditions(self.stop_conditions)?;
        let fairness = FairnessPolicy::new(
            self.fairness.breadth_first_percent,
            self.fairness.novelty_reserve,
        )
        .map_err(|error| usage_error(format!("invalid fairness policy: {error}")))?;
        let retention = RetentionPolicy::new(
            self.retention.retain_all_findings,
            self.retention.survivor_limit,
            self.retention.exact_findings,
            self.retention.exact_user_pins,
        );
        let policy = CampaignPolicy::new(
            scenario,
            campaign_seed,
            match self.mode {
                AuthoredCampaignMode::Strict => CampaignMode::Strict,
                AuthoredCampaignMode::Streaming => CampaignMode::Streaming,
                AuthoredCampaignMode::Statistical => CampaignMode::Statistical,
            },
            explorer,
            choices,
            objectives,
            guidance,
            stop_conditions,
            fairness,
            retention,
            self.admit_scenario_defaults,
        )
        .map_err(|error| usage_error(format!("invalid authored campaign policy: {error}")))?;
        let policy = match self.intervention_learning {
            AuthoredInterventionLearningPolicy::Exclude => Ok(policy),
            AuthoredInterventionLearningPolicy::IncludeInGuidance => policy
                .with_intervention_learning_policy(InterventionLearningPolicy::IncludeInGuidance)
                .map_err(|error| usage_error(format!("invalid authored campaign policy: {error}"))),
        }?;
        match (statistical_sampling, sequential_monte_carlo) {
            (None, None) => Ok(policy),
            (Some(initial), None) => {
                policy
                    .with_statistical_sampling_design(initial)
                    .map_err(|error| {
                        usage_error(format!("invalid finite statistical policy: {error}"))
                    })
            }
            (Some(initial), Some(sequential)) => policy
                .with_sequential_monte_carlo_design(initial, sequential)
                .map_err(|error| usage_error(format!("invalid SMC policy: {error}"))),
            (None, Some(_)) => Err(usage_error(
                "sequential_monte_carlo requires statistical_sampling stage-zero design",
            )),
        }
    }
}

impl AuthoredExplorerPolicy {
    fn into_policy(self) -> Result<ExplorerPolicy, CliError> {
        match self {
            Self::TreeSearch {
                exploration_weight_micros,
                novelty_bonus_micros,
                fairness_bonus_micros,
                widening,
            } => Ok(ExplorerPolicy::TreeSearch {
                puct: PuctPolicy::new(
                    exploration_weight_micros,
                    novelty_bonus_micros,
                    fairness_bonus_micros,
                ),
                widening: widening
                    .map(AuthoredProgressiveWidening::into_policy)
                    .transpose()?,
            }),
            Self::Beam {
                width,
                novelty_reserve,
            } => Ok(ExplorerPolicy::Beam {
                width,
                novelty_reserve,
            }),
            Self::Exhaustive {
                maximum_cardinality,
            } => Ok(ExplorerPolicy::Exhaustive {
                maximum_cardinality,
            }),
        }
    }
}

impl AuthoredProgressiveWidening {
    fn into_policy(self) -> Result<ProgressiveWideningPolicy, CliError> {
        let k = ExactRational::new(self.k_numerator, self.k_denominator)
            .map_err(|error| usage_error(format!("invalid widening multiplier: {error}")))?;
        let alpha = ExactRational::new(self.alpha_numerator, self.alpha_denominator)
            .map_err(|error| usage_error(format!("invalid widening exponent: {error}")))?;
        ProgressiveWideningPolicy::new(
            k,
            alpha,
            self.initial_children,
            self.maximum_children,
            self.minimum_visits_per_child,
        )
        .map_err(|error| usage_error(format!("invalid progressive-widening policy: {error}")))
    }
}

impl AuthoredStatisticalSamplingDesign {
    fn into_policy(self) -> Result<StatisticalSamplingDesign, CliError> {
        let distributions = collect_statistical_distributions(self.distributions)?;
        let mut draws = BTreeMap::new();
        for authored in self.draws {
            let coordinate = authored
                .coordinate
                .clone()
                .into_value("statistical draw coordinate")?;
            let draw = authored.into_policy()?;
            if draws.insert(coordinate, draw).is_some() {
                return Err(usage_error(format!(
                    "duplicate statistical draw coordinate {coordinate}"
                )));
            }
        }
        let endpoint_count = self.estimand_endpoints.len();
        let estimand_endpoints = self
            .estimand_endpoints
            .into_iter()
            .map(|endpoint| endpoint.into_value("statistical estimand endpoint"))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if estimand_endpoints.len() != endpoint_count {
            return Err(usage_error(
                "statistical sampling design contains duplicate estimand endpoints",
            ));
        }

        StatisticalSamplingDesign::new(distributions, draws, estimand_endpoints)
            .map_err(|error| usage_error(format!("invalid statistical sampling design: {error}")))
    }
}

impl AuthoredStatisticalDraw {
    fn into_policy(self) -> Result<StatisticalDrawPlan, CliError> {
        let opportunity = ChoiceOpportunityId::parse(&self.opportunity)
            .map_err(|error| usage_error(format!("invalid statistical opportunity ID: {error}")))?;
        let opportunity_semantics = ChoiceOpportunitySemanticId::parse(&self.opportunity_semantics)
            .map_err(|error| {
                usage_error(format!(
                    "invalid statistical opportunity semantic ID: {error}"
                ))
            })?;
        let domain = ChoiceDomainId::parse(&self.domain)
            .map_err(|error| usage_error(format!("invalid statistical domain ID: {error}")))?;
        let model = ProbabilityModelId::parse(&self.model)
            .map_err(|error| usage_error(format!("invalid statistical model ID: {error}")))?;
        let stop = parse_campaign_stop_condition(&self.stop)?;

        StatisticalDrawPlan::from_predeclared_opportunity(
            self.parent
                .map(|parent| parent.into_value("statistical draw parent"))
                .transpose()?,
            opportunity,
            opportunity_semantics,
            domain,
            model,
            stop,
        )
        .map_err(|error| usage_error(format!("invalid statistical draw: {error}")))
    }
}

impl AuthoredSequentialMonteCarloDesign {
    fn into_policy(self) -> Result<SequentialMonteCarloDesign, CliError> {
        let distributions = collect_statistical_distributions(self.distributions)?;
        let mut stages = BTreeMap::new();
        for authored in self.stages {
            let stage = authored.stage;
            let plan = authored.into_policy()?;
            if stages.insert(stage, plan).is_some() {
                return Err(usage_error(format!("duplicate SMC stage {stage}")));
            }
        }
        let threshold = ExactRational::new(
            self.resampling
                .effective_sample_size_threshold
                .numerator
                .into_value("SMC ESS threshold numerator")?,
            self.resampling
                .effective_sample_size_threshold
                .denominator
                .into_value("SMC ESS threshold denominator")?,
        )
        .map_err(|error| usage_error(format!("invalid SMC ESS threshold: {error}")))?;
        let algorithm = match self.resampling.algorithm {
            AuthoredSmcResamplingAlgorithm::SystematicV1 => SmcResamplingAlgorithm::SystematicV1,
        };
        let resampling = SmcResamplingPolicy::new(algorithm, threshold)
            .map_err(|error| usage_error(format!("invalid SMC resampling policy: {error}")))?;

        SequentialMonteCarloDesign::new(self.particle_count, distributions, stages, resampling)
            .map_err(|error| usage_error(format!("invalid SMC design: {error}")))
    }
}

impl AuthoredSmcStage {
    fn into_policy(self) -> Result<SmcStagePlan, CliError> {
        let declaration = SelectableSemanticId::parse(&self.declaration)
            .map_err(|error| usage_error(format!("invalid SMC selectable semantic ID: {error}")))?;
        let domain = ChoiceDomainSemanticId::parse(&self.domain)
            .map_err(|error| usage_error(format!("invalid SMC domain semantic ID: {error}")))?;
        let model = ProbabilityModelId::parse(&self.model)
            .map_err(|error| usage_error(format!("invalid SMC model ID: {error}")))?;
        let stop = parse_campaign_stop_condition(&self.stop)?;
        let selector = SmcOpportunitySelector::new(declaration, domain, self.instance, model, stop)
            .map_err(|error| usage_error(format!("invalid SMC opportunity selector: {error}")))?;
        Ok(SmcStagePlan::new(self.parent_stage, selector))
    }
}

impl AuthoredStatisticalValue {
    fn into_policy(self) -> Result<ChoiceValue, CliError> {
        match self {
            Self::Boolean { value } => Ok(ChoiceValue::Boolean(value)),
            Self::Discrete { alternative } => AlternativeId::parse(&alternative)
                .map(ChoiceValue::Discrete)
                .map_err(|error| {
                    usage_error(format!("invalid statistical alternative ID: {error}"))
                }),
            Self::Signed { value } => Ok(ChoiceValue::Integer(IntegerValue::Signed(value))),
            Self::Unsigned { value } => Ok(ChoiceValue::Integer(IntegerValue::Unsigned(
                value.into_value("statistical unsigned choice value")?,
            ))),
        }
    }
}

impl AuthoredU64 {
    fn into_value(self, field: &str) -> Result<u64, CliError> {
        match self {
            Self::Integer(value) => Ok(value),
            Self::Decimal(value) => {
                let canonical = value == "0"
                    || (!value.starts_with('0')
                        && !value.is_empty()
                        && value.bytes().all(|byte| byte.is_ascii_digit()));
                if !canonical {
                    return Err(usage_error(format!(
                        "{field} must use canonical unsigned decimal syntax"
                    )));
                }
                value
                    .parse()
                    .map_err(|_| usage_error(format!("{field} exceeds the u64 range")))
            }
        }
    }
}

fn collect_statistical_distributions(
    authored: Vec<AuthoredStatisticalDistribution>,
) -> Result<BTreeMap<ProbabilityModelId, StatisticalDistribution>, CliError> {
    let mut distributions = BTreeMap::new();
    for authored in authored {
        let model = ProbabilityModelId::parse(&authored.model)
            .map_err(|error| usage_error(format!("invalid statistical model ID: {error}")))?;
        let target = collect_statistical_masses(authored.target, "target")?;
        let proposal = collect_statistical_masses(authored.proposal, "proposal")?;
        let distribution = StatisticalDistribution::new(target, proposal)
            .map_err(|error| usage_error(format!("invalid statistical distribution: {error}")))?;
        if distributions.insert(model, distribution).is_some() {
            return Err(usage_error(format!(
                "duplicate statistical distribution model {model}"
            )));
        }
    }
    Ok(distributions)
}

fn collect_statistical_masses(
    authored: Vec<AuthoredStatisticalMass>,
    role: &str,
) -> Result<BTreeMap<ChoiceValue, u64>, CliError> {
    let mut masses = BTreeMap::new();
    for authored in authored {
        let value = authored.value.into_policy()?;
        let mass = authored
            .mass
            .into_value(&format!("statistical {role} mass"))?;
        if masses.insert(value, mass).is_some() {
            return Err(usage_error(format!(
                "duplicate statistical {role} mass value"
            )));
        }
    }
    Ok(masses)
}

fn collect_choices(
    authored: Vec<AuthoredChoicePolicy>,
    scenario: Option<&ScenarioDefForm>,
) -> Result<BTreeMap<String, ChoicePolicy>, CliError> {
    let mut choices = BTreeMap::new();
    for entry in authored {
        let selector = resolve_choice_selector(entry.selector, scenario)?;
        let generator = CandidateGeneratorSpecId::parse(&entry.generator)
            .map_err(|error| usage_error(format!("invalid choice generator ID: {error}")))?;
        let policy = ChoicePolicy::new(selector.clone(), generator, entry.required)
            .map_err(|error| usage_error(format!("invalid choice policy: {error}")))?;
        if choices.insert(selector.clone(), policy).is_some() {
            return Err(usage_error(format!(
                "duplicate choice selector {selector:?}"
            )));
        }
    }
    Ok(choices)
}

fn resolve_choice_selector(
    selector: AuthoredChoiceSelector,
    scenario: Option<&ScenarioDefForm>,
) -> Result<String, CliError> {
    let expression = match selector {
        AuthoredChoiceSelector::Name(name) => return Ok(name),
        AuthoredChoiceSelector::Expression(expression) => expression,
    };
    let scenario = scenario.ok_or_else(|| {
        usage_error("selectable-ID and tag choice selectors require --scenario <SCENARIO>")
    })?;
    match expression {
        AuthoredChoiceSelectorExpression::Selectable { id } => {
            let id = SelectableId::parse(&id)
                .map_err(|error| usage_error(format!("invalid selectable selector ID: {error}")))?;
            scenario
                .selectables()
                .declarations()
                .get(&id)
                .map(|declaration| declaration.name().to_owned())
                .ok_or_else(|| {
                    usage_error("selectable selector ID is absent from the supplied scenario")
                })
        }
        AuthoredChoiceSelectorExpression::Tags { all } => {
            if all.is_empty() || all.len() > MAX_AUTHORED_CHOICE_SELECTOR_TAGS {
                return Err(usage_error(format!(
                    "choice tag selector must contain 1..={MAX_AUTHORED_CHOICE_SELECTOR_TAGS} tags"
                )));
            }
            let tag_count = all.len();
            let tags = all.into_iter().collect::<BTreeSet<_>>();
            if tags.len() != tag_count {
                return Err(usage_error("choice tag selector contains duplicate tags"));
            }
            ChoiceClassContext::new(tags.clone())
                .map_err(|error| usage_error(format!("invalid choice selector tags: {error}")))?;
            let mut matches = scenario
                .selectables()
                .declarations()
                .values()
                .filter(|declaration| declaration.semantic_tags().is_superset(&tags));
            let selected = matches.next().ok_or_else(|| {
                usage_error("choice tag selector matches no declaration in the supplied scenario")
            })?;
            if matches.next().is_some() {
                return Err(usage_error(
                    "choice tag selector is ambiguous in the supplied scenario",
                ));
            }
            Ok(selected.name().to_owned())
        }
    }
}

fn collect_objectives(
    authored: Vec<AuthoredObjective>,
) -> Result<BTreeMap<String, Objective>, CliError> {
    let mut objectives = BTreeMap::new();
    for entry in authored {
        let objective = Objective::new(
            entry.measurement.clone(),
            match entry.goal {
                AuthoredObjectiveGoal::Minimize => ObjectiveGoal::Minimize,
                AuthoredObjectiveGoal::Maximize => ObjectiveGoal::Maximize,
            },
            entry.weight_micros,
        )
        .map_err(|error| usage_error(format!("invalid campaign objective: {error}")))?;
        if objectives
            .insert(entry.measurement.clone(), objective)
            .is_some()
        {
            return Err(usage_error(format!(
                "duplicate objective measurement {:?}",
                entry.measurement
            )));
        }
    }
    Ok(objectives)
}

fn collect_guidance(
    authored: Vec<AuthoredGuidance>,
) -> Result<BTreeMap<String, GuidanceWeight>, CliError> {
    let mut guidance = BTreeMap::new();
    for entry in authored {
        let weight = GuidanceWeight::new(entry.signal.clone(), entry.weight_micros)
            .map_err(|error| usage_error(format!("invalid guidance weight: {error}")))?;
        if guidance.insert(entry.signal.clone(), weight).is_some() {
            return Err(usage_error(format!(
                "duplicate guidance signal {:?}",
                entry.signal
            )));
        }
    }
    Ok(guidance)
}

fn collect_stop_conditions(authored: Vec<String>) -> Result<BTreeSet<String>, CliError> {
    let mut stops = BTreeSet::new();
    for stop in authored {
        if !stops.insert(stop.clone()) {
            return Err(usage_error(format!("duplicate stop condition {stop:?}")));
        }
    }
    Ok(stops)
}

fn parse_campaign_seed(encoded: &str) -> Result<CampaignSeed, CliError> {
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(usage_error(
            "campaign_seed must contain exactly 64 hexadecimal characters",
        ));
    }
    let mut bytes = [0_u8; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        *output = u8::from_str_radix(&encoded[start..start + 2], 16)
            .map_err(|_| usage_error("campaign_seed contains invalid hexadecimal"))?;
    }
    Ok(CampaignSeed::from_bytes(bytes))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- authoring tests use exact panic localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use crucible::{ScenarioSelectableLimits, ScenarioSelectables};
    use crucible_campaign::{
        BooleanDomain, CampaignPolicy, ChoiceClassContext, ChoiceDomain, ChoiceSource, ChoiceValue,
        SelectableDeclaration,
    };
    use crucible_cas::content_store::{ContentId, ObjectKind};
    use tempfile::tempdir;

    fn typed_id(schema: &str, kind: ObjectKind, label: &[u8]) -> String {
        format!("{schema}@{}", ContentId::for_bytes(kind, 1, label).encode())
    }

    fn manifest() -> String {
        let scenario = CampaignHash::derive(
            "crucible.cli.test.authored-policy-scenario.v1",
            b"authored-policy-scenario",
        )
        .to_hex();
        let generator = typed_id(
            "crucible.campaign.candidate-generator-spec",
            ObjectKind::Policy,
            b"authored-policy-generator",
        );
        format!(
            r#"schema_version = 1
scenario = "{scenario}"
campaign_seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
mode = "strict"
stop_conditions = ["scenario-complete"]
admit_scenario_defaults = false

[explorer]
kind = "tree-search"
exploration_weight_micros = 1250000
novelty_bonus_micros = 250000
fairness_bonus_micros = 100000

[explorer.widening]
k_numerator = 2
k_denominator = 1
alpha_numerator = 1
alpha_denominator = 2
initial_children = 2
maximum_children = 64
minimum_visits_per_child = 1

[[choices]]
selector = "network.latency"
generator = "{generator}"
required = true

[[objectives]]
measurement = "recovery-time"
goal = "minimize"
weight_micros = 1000000

[[guidance]]
signal = "coverage-rarity"
weight_micros = 500000

[fairness]
breadth_first_percent = 10
novelty_reserve = 4

[retention]
retain_all_findings = true
survivor_limit = 32
exact_findings = true
exact_user_pins = true
"#
        )
    }

    fn manifest_for_scenario(scenario: &ScenarioDefForm) -> String {
        let original = CampaignHash::derive(
            "crucible.cli.test.authored-policy-scenario.v1",
            b"authored-policy-scenario",
        )
        .to_hex();
        manifest().replace(
            &format!("scenario = \"{original}\""),
            &format!("scenario = \"{}\"", scenario.id().to_hex()),
        )
    }

    fn statistical_manifest(include_smc: bool) -> String {
        let scenario = CampaignHash::derive(
            "crucible.cli.test.statistical-policy-scenario.v1",
            b"statistical-policy-scenario",
        )
        .to_hex();
        let model_zero =
            CampaignHash::derive("crucible.cli.test.statistical-model.v1", b"initial-model")
                .to_hex();
        let model_one = CampaignHash::derive(
            "crucible.cli.test.statistical-model.v1",
            b"transition-model",
        )
        .to_hex();
        let transition_declaration = CampaignHash::derive(
            "crucible.cli.test.statistical-declaration.v1",
            b"transition-declaration",
        )
        .to_hex();
        let domain_semantics = CampaignHash::derive(
            "crucible.cli.test.statistical-domain.v1",
            b"boolean-domain-semantics",
        )
        .to_hex();
        let opportunity_semantics = CampaignHash::derive(
            "crucible.cli.test.statistical-opportunity.v1",
            b"initial-opportunity-semantics",
        )
        .to_hex();
        let opportunity_zero = typed_id(
            "crucible.campaign.choice-opportunity",
            ObjectKind::CampaignFact,
            b"initial-opportunity-zero",
        );
        let opportunity_one = typed_id(
            "crucible.campaign.choice-opportunity",
            ObjectKind::CampaignFact,
            b"initial-opportunity-one",
        );
        let domain = typed_id(
            "crucible.campaign.choice-domain",
            ObjectKind::CampaignFact,
            b"initial-domain",
        );
        let smc = if include_smc {
            format!(
                r#"
[sequential_monte_carlo]
particle_count = 2

[[sequential_monte_carlo.distributions]]
model = "{model_one}"
target = [
  {{ mass = 3, value = {{ kind = "boolean", value = false }} }},
  {{ mass = 1, value = {{ kind = "boolean", value = true }} }},
]
proposal = [
  {{ mass = 1, value = {{ kind = "boolean", value = false }} }},
  {{ mass = 1, value = {{ kind = "boolean", value = true }} }},
]

[[sequential_monte_carlo.stages]]
stage = 1
parent_stage = 0
declaration = "{transition_declaration}"
domain = "{domain_semantics}"
instance = "post-initial"
model = "{model_one}"
stop = "terminal"

[sequential_monte_carlo.resampling]
algorithm = "systematic-v1"
effective_sample_size_threshold = {{ numerator = 1, denominator = 2 }}
"#
            )
        } else {
            String::new()
        };
        format!(
            r#"schema_version = 2
scenario = "{scenario}"
campaign_seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
mode = "statistical"
stop_conditions = ["scenario-complete"]

[explorer]
kind = "exhaustive"
maximum_cardinality = 128

[fairness]
breadth_first_percent = 0
novelty_reserve = 0

[retention]
retain_all_findings = true
survivor_limit = 8
exact_findings = true
exact_user_pins = true

[statistical_sampling]
estimand_endpoints = [0, 1]

[[statistical_sampling.distributions]]
model = "{model_zero}"
target = [
  {{ mass = 1, value = {{ kind = "boolean", value = false }} }},
  {{ mass = 1, value = {{ kind = "boolean", value = true }} }},
]
proposal = [
  {{ mass = 1, value = {{ kind = "boolean", value = false }} }},
  {{ mass = 1, value = {{ kind = "boolean", value = true }} }},
]

[[statistical_sampling.draws]]
coordinate = 0
opportunity = "{opportunity_zero}"
opportunity_semantics = "{opportunity_semantics}"
domain = "{domain}"
model = "{model_zero}"
stop = "next-choice"

[[statistical_sampling.draws]]
coordinate = 1
opportunity = "{opportunity_one}"
opportunity_semantics = "{opportunity_semantics}"
domain = "{domain}"
model = "{model_zero}"
stop = "next-choice"
{smc}"#
        )
    }

    fn selector_scenario() -> (ScenarioDefForm, SelectableId) {
        let fixture = crucible::happy_path_scenario().expect("happy-path scenario");
        let base = ScenarioDefForm::from_components(
            fixture.scenario.world(),
            &crucible::Plan::empty(),
            &crucible::Properties::empty(),
            fixture.scenario.seed(),
        )
        .expect("authored scenario");
        let latency = SelectableDeclaration::new(
            "network.latency",
            ChoiceSource::Scheduler {
                producer: String::from("campaign-policy-test"),
            },
            ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain")),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::new()).expect("class context"),
            BTreeSet::from([String::from("network"), String::from("latency")]),
            true,
        )
        .expect("latency selectable");
        let latency_id = latency.id().expect("latency selectable ID");
        let loss = SelectableDeclaration::new(
            "network.loss",
            ChoiceSource::Scheduler {
                producer: String::from("campaign-policy-test"),
            },
            ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain")),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::new()).expect("class context"),
            BTreeSet::from([String::from("network"), String::from("loss")]),
            false,
        )
        .expect("loss selectable");
        let selectables = ScenarioSelectables::new(
            base.world(),
            ScenarioSelectableLimits::default(),
            vec![latency, loss],
        )
        .expect("scenario selectables");
        (
            base.with_selectables(selectables)
                .expect("scenario with selectables"),
            latency_id,
        )
    }

    #[test]
    fn strict_manifest_compiles_to_canonical_policy() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("policy.toml");
        let output = temporary.path().join("policy.bin");
        std::fs::write(&input, manifest()).expect("write manifest");

        let report = compile_campaign_policy(&input, None, &output).expect("compile policy");
        let bytes = std::fs::read(&output).expect("read policy");
        let policy = CampaignPolicy::from_canonical_bytes(&bytes).expect("decode policy");

        assert_eq!(report.policy, policy.id().expect("policy ID").to_string());
        assert_eq!(report.encoded_bytes, bytes.len());
        assert!(policy.choice_policies().contains_key("network.latency"));
        assert!(policy.objectives().contains_key("recovery-time"));
        assert_eq!(
            policy.intervention_learning_policy(),
            InterventionLearningPolicy::Exclude
        );
    }

    #[test]
    fn manifest_can_explicitly_include_interventions_in_guidance() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("policy.toml");
        let output = temporary.path().join("policy.bin");
        let manifest = manifest().replace(
            "mode = \"strict\"",
            "mode = \"strict\"\nintervention_learning = \"include-in-guidance\"",
        );
        std::fs::write(&input, manifest).expect("write opt-in manifest");

        compile_campaign_policy(&input, None, &output).expect("compile opt-in policy");
        let bytes = std::fs::read(output).expect("read opt-in policy");
        let policy = CampaignPolicy::from_canonical_bytes(&bytes).expect("decode opt-in policy");

        assert_eq!(
            policy.intervention_learning_policy(),
            InterventionLearningPolicy::IncludeInGuidance
        );
        assert_eq!(
            policy
                .id()
                .expect("opt-in policy ID")
                .content_id()
                .schema_version(),
            2
        );
    }

    #[test]
    fn schema_two_authors_finite_and_smc_statistical_policies() {
        for (include_smc, expected_schema) in [(false, 3), (true, 4)] {
            let temporary = tempdir().expect("temporary directory");
            let input = temporary.path().join("policy.toml");
            let output = temporary.path().join("policy.bin");
            std::fs::write(&input, statistical_manifest(include_smc))
                .expect("write statistical manifest");

            compile_campaign_policy(&input, None, &output).expect("compile statistical policy");
            let bytes = std::fs::read(output).expect("read statistical policy");
            let policy =
                CampaignPolicy::from_canonical_bytes(&bytes).expect("decode statistical policy");

            assert_eq!(
                policy
                    .id()
                    .expect("statistical policy ID")
                    .content_id()
                    .schema_version(),
                expected_schema
            );
            assert_eq!(
                policy
                    .statistical_sampling_design()
                    .expect("initial design")
                    .estimand_endpoints(),
                &BTreeSet::from([0, 1])
            );
            assert_eq!(
                policy.sequential_monte_carlo_design().is_some(),
                include_smc
            );
        }
    }

    #[test]
    fn statistical_authoring_rejects_duplicate_canonical_keys() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("policy.toml");
        let output = temporary.path().join("policy.bin");
        let duplicate = statistical_manifest(false)
            .replace("estimand_endpoints = [0, 1]", "estimand_endpoints = [0, 0]");
        std::fs::write(&input, duplicate).expect("write duplicate manifest");

        assert!(compile_campaign_policy(&input, None, &output).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn statistical_authoring_accepts_full_u64_decimal_strings() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("policy.toml");
        let output = temporary.path().join("policy.bin");
        let maximum = u64::MAX.to_string();
        let original_distribution = r#"target = [
  { mass = 1, value = { kind = "boolean", value = false } },
  { mass = 1, value = { kind = "boolean", value = true } },
]
proposal = [
  { mass = 1, value = { kind = "boolean", value = false } },
  { mass = 1, value = { kind = "boolean", value = true } },
]"#;
        let full_range_distribution = format!(
            r#"target = [
  {{ mass = "{maximum}", value = {{ kind = "unsigned", value = "{maximum}" }} }},
]
proposal = [
  {{ mass = "{maximum}", value = {{ kind = "unsigned", value = "{maximum}" }} }},
]"#
        );
        let manifest = statistical_manifest(true)
            .replacen(original_distribution, &full_range_distribution, 1)
            .replace(
                "effective_sample_size_threshold = { numerator = 1, denominator = 2 }",
                &format!(
                    "effective_sample_size_threshold = {{ numerator = \"{maximum}\", denominator = \"{maximum}\" }}"
                ),
            );
        std::fs::write(&input, manifest).expect("write full-range manifest");

        compile_campaign_policy(&input, None, &output).expect("compile full-range policy");
        let policy = CampaignPolicy::from_canonical_bytes(
            &std::fs::read(output).expect("read full-range policy"),
        )
        .expect("decode full-range policy");
        let distribution = policy
            .statistical_sampling_design()
            .expect("initial design")
            .distributions()
            .values()
            .next()
            .expect("initial distribution");

        assert_eq!(
            distribution.target_masses(),
            &BTreeMap::from([(
                ChoiceValue::Integer(IntegerValue::Unsigned(u64::MAX)),
                u64::MAX,
            )])
        );
        assert_eq!(
            policy
                .sequential_monte_carlo_design()
                .expect("SMC design")
                .resampling()
                .effective_sample_size_threshold(),
            ExactRational::new(1, 1).expect("unit rational")
        );
    }

    #[test]
    fn schema_one_rejects_statistical_fields_before_writing() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("policy.toml");
        let output = temporary.path().join("policy.bin");
        let manifest =
            statistical_manifest(false).replacen("schema_version = 2", "schema_version = 1", 1);
        std::fs::write(&input, manifest).expect("write version-one manifest");

        assert!(compile_campaign_policy(&input, None, &output).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn invalid_or_duplicate_manifest_does_not_create_output() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("policy.toml");
        let output = temporary.path().join("policy.bin");
        let duplicate = manifest().replace(
            "[fairness]",
            &format!(
                "[[choices]]\nselector = \"network.latency\"\ngenerator = \"{}\"\nrequired = false\n\n[fairness]",
                typed_id(
                    "crucible.campaign.candidate-generator-spec",
                    ObjectKind::Policy,
                    b"authored-policy-generator",
                )
            ),
        );
        std::fs::write(&input, duplicate).expect("write manifest");

        assert!(compile_campaign_policy(&input, None, &output).is_err());
        assert!(!output.exists());

        std::fs::write(
            &input,
            manifest().replace("mode = \"strict\"", "mode = \"strict\"\nunknown = true"),
        )
        .expect("write unknown-field manifest");
        assert!(compile_campaign_policy(&input, None, &output).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn existing_output_is_never_replaced() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("policy.toml");
        let output = temporary.path().join("policy.bin");
        std::fs::write(&input, manifest()).expect("write manifest");
        std::fs::write(&output, b"existing").expect("write existing output");

        assert!(compile_campaign_policy(&input, None, &output).is_err());
        assert_eq!(std::fs::read(&output).expect("read existing"), b"existing");
    }

    #[test]
    fn selectable_id_and_tag_predicates_compile_to_the_same_canonical_policy() {
        let temporary = tempdir().expect("temporary directory");
        let (scenario, latency_id) = selector_scenario();
        let scenario_input = temporary.path().join("scenario.toml");
        std::fs::write(
            &scenario_input,
            scenario.to_canonical_toml().expect("canonical scenario"),
        )
        .expect("write scenario");
        let plain_input = temporary.path().join("plain.toml");
        let id_input = temporary.path().join("id.toml");
        let tags_input = temporary.path().join("tags.toml");
        let plain_output = temporary.path().join("plain.bin");
        let id_output = temporary.path().join("id.bin");
        let tags_output = temporary.path().join("tags.bin");
        let manifest = manifest_for_scenario(&scenario);
        std::fs::write(&plain_input, &manifest).expect("write plain policy");
        std::fs::write(
            &id_input,
            manifest.replace(
                "selector = \"network.latency\"",
                &format!("selector = {{ kind = \"selectable\", id = \"{latency_id}\" }}"),
            ),
        )
        .expect("write selectable-ID policy");
        std::fs::write(
            &tags_input,
            manifest.replace(
                "selector = \"network.latency\"",
                "selector = { kind = \"tags\", all = [\"latency\", \"network\"] }",
            ),
        )
        .expect("write tag policy");

        compile_campaign_policy(&plain_input, None, &plain_output).expect("compile plain policy");
        compile_campaign_policy(&id_input, Some(&scenario_input), &id_output)
            .expect("compile selectable-ID policy");
        compile_campaign_policy(&tags_input, Some(&scenario_input), &tags_output)
            .expect("compile tag policy");

        let plain = std::fs::read(plain_output).expect("read plain policy");
        assert_eq!(std::fs::read(id_output).expect("read ID policy"), plain);
        assert_eq!(std::fs::read(tags_output).expect("read tag policy"), plain);
    }

    #[test]
    fn selector_resolution_rejects_missing_context_ambiguity_and_scenario_drift() {
        let temporary = tempdir().expect("temporary directory");
        let (scenario, latency_id) = selector_scenario();
        let scenario_input = temporary.path().join("scenario.toml");
        std::fs::write(
            &scenario_input,
            scenario.to_canonical_toml().expect("canonical scenario"),
        )
        .expect("write scenario");
        let input = temporary.path().join("policy.toml");
        let output = temporary.path().join("policy.bin");
        let by_id = manifest_for_scenario(&scenario).replace(
            "selector = \"network.latency\"",
            &format!("selector = {{ kind = \"selectable\", id = \"{latency_id}\" }}"),
        );
        std::fs::write(&input, &by_id).expect("write ID policy");
        assert!(compile_campaign_policy(&input, None, &output).is_err());
        assert!(!output.exists());

        let ambiguous = manifest_for_scenario(&scenario).replace(
            "selector = \"network.latency\"",
            "selector = { kind = \"tags\", all = [\"network\"] }",
        );
        std::fs::write(&input, ambiguous).expect("write ambiguous policy");
        assert!(compile_campaign_policy(&input, Some(&scenario_input), &output).is_err());
        assert!(!output.exists());

        let unknown_id = typed_id(
            "crucible.campaign.selectable-declaration",
            ObjectKind::CampaignFact,
            b"unknown-authored-policy-selectable",
        );
        let absent = manifest_for_scenario(&scenario).replace(
            "selector = \"network.latency\"",
            &format!("selector = {{ kind = \"selectable\", id = \"{unknown_id}\" }}"),
        );
        std::fs::write(&input, absent).expect("write absent-ID policy");
        assert!(compile_campaign_policy(&input, Some(&scenario_input), &output).is_err());
        assert!(!output.exists());

        let duplicate_tags = manifest_for_scenario(&scenario).replace(
            "selector = \"network.latency\"",
            "selector = { kind = \"tags\", all = [\"network\", \"network\"] }",
        );
        std::fs::write(&input, duplicate_tags).expect("write duplicate-tag policy");
        assert!(compile_campaign_policy(&input, Some(&scenario_input), &output).is_err());
        assert!(!output.exists());

        std::fs::write(&input, manifest()).expect("write drifted policy");
        assert!(compile_campaign_policy(&input, Some(&scenario_input), &output).is_err());
        assert!(!output.exists());
    }
}
