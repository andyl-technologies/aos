//! Strict offline authoring for canonical campaign policy records.

use super::*;

use std::collections::{BTreeMap, BTreeSet};

use crucible_campaign::{
    CampaignMode, CampaignSeed, ChoicePolicy, ExactRational, ExplorerPolicy, FairnessPolicy,
    GuidanceWeight, Objective, ObjectiveGoal, ProgressiveWideningPolicy, PuctPolicy,
    RetentionPolicy, ScenarioDefId,
};
use serde::{Deserialize, Serialize};

use super::authoring::{read_bounded_utf8, write_new_record};

const CAMPAIGN_POLICY_AUTHORING_SCHEMA_VERSION: u32 = 1;
const MAX_CAMPAIGN_POLICY_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const CAMPAIGN_POLICY_COMPILATION_REPORT_SCHEMA: &str =
    "crucible.cli.campaign-policy-compilation.v1";

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
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuthoredCampaignMode {
    Strict,
    Streaming,
    Statistical,
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
    selector: String,
    generator: String,
    required: bool,
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

pub(super) fn compile_campaign_policy(
    input: &Path,
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
    let policy = authored.into_policy()?;
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
    fn into_policy(self) -> Result<CampaignPolicy, CliError> {
        if self.schema_version != CAMPAIGN_POLICY_AUTHORING_SCHEMA_VERSION {
            return Err(usage_error(format!(
                "unsupported campaign policy manifest schema version {}; expected {}",
                self.schema_version, CAMPAIGN_POLICY_AUTHORING_SCHEMA_VERSION
            )));
        }
        let scenario = ScenarioDefId::parse(&self.scenario)
            .map_err(|error| usage_error(format!("invalid policy scenario ID: {error}")))?;
        let campaign_seed = parse_campaign_seed(&self.campaign_seed)?;
        let explorer = self.explorer.into_policy()?;
        let choices = collect_choices(self.choices)?;
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
        CampaignPolicy::new(
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
        .map_err(|error| usage_error(format!("invalid authored campaign policy: {error}")))
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

fn collect_choices(
    authored: Vec<AuthoredChoicePolicy>,
) -> Result<BTreeMap<String, ChoicePolicy>, CliError> {
    let mut choices = BTreeMap::new();
    for entry in authored {
        let generator = CandidateGeneratorSpecId::parse(&entry.generator)
            .map_err(|error| usage_error(format!("invalid choice generator ID: {error}")))?;
        let policy = ChoicePolicy::new(entry.selector.clone(), generator, entry.required)
            .map_err(|error| usage_error(format!("invalid choice policy: {error}")))?;
        if choices.insert(entry.selector.clone(), policy).is_some() {
            return Err(usage_error(format!(
                "duplicate choice selector {:?}",
                entry.selector
            )));
        }
    }
    Ok(choices)
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

    use crucible_campaign::{CampaignHash, CampaignPolicy};
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

    #[test]
    fn strict_manifest_compiles_to_canonical_policy() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("policy.toml");
        let output = temporary.path().join("policy.bin");
        std::fs::write(&input, manifest()).expect("write manifest");

        let report = compile_campaign_policy(&input, &output).expect("compile policy");
        let bytes = std::fs::read(&output).expect("read policy");
        let policy = CampaignPolicy::from_canonical_bytes(&bytes).expect("decode policy");

        assert_eq!(report.policy, policy.id().expect("policy ID").to_string());
        assert_eq!(report.encoded_bytes, bytes.len());
        assert!(policy.choice_policies().contains_key("network.latency"));
        assert!(policy.objectives().contains_key("recovery-time"));
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

        assert!(compile_campaign_policy(&input, &output).is_err());
        assert!(!output.exists());

        std::fs::write(
            &input,
            manifest().replace("mode = \"strict\"", "mode = \"strict\"\nunknown = true"),
        )
        .expect("write unknown-field manifest");
        assert!(compile_campaign_policy(&input, &output).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn existing_output_is_never_replaced() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("policy.toml");
        let output = temporary.path().join("policy.bin");
        std::fs::write(&input, manifest()).expect("write manifest");
        std::fs::write(&output, b"existing").expect("write existing output");

        assert!(compile_campaign_policy(&input, &output).is_err());
        assert_eq!(std::fs::read(&output).expect("read existing"), b"existing");
    }
}
