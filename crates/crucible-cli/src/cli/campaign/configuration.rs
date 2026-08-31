//! Strict offline authoring for non-genesis campaign configuration bundles.

use super::*;

use crucible::{Configuration, ScenarioDefForm, Schedule};
use crucible_daemon::{
    MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES, decode_crucible_configuration_artifact,
    encode_crucible_configuration_artifact, encode_crucible_scenario_artifact,
};
use serde::Serialize;

use super::authoring::{
    import_manifest_name, read_bounded_bytes, read_bounded_utf8, scenario_body_name,
    schedule_body_name, write_configuration_import_bundle,
};

const CAMPAIGN_CONFIGURATION_COMPILATION_REPORT_SCHEMA: &str =
    "crucible.cli.campaign-configuration-compilation.v1";

/// Result of compiling one scenario and nonempty canonical schedule.
#[derive(Debug, Serialize)]
pub(super) struct CampaignConfigurationCompilationReport {
    schema: &'static str,
    scenario_input: String,
    schedule_input: String,
    directory: String,
    manifest: String,
    scenario_body: String,
    schedule_body: String,
    scenario: String,
    scenario_artifact: String,
    configuration: String,
    configuration_artifact: String,
    decisions: usize,
}

pub(super) fn compile_campaign_configuration(
    scenario_input: &Path,
    schedule_input: &Path,
    output: &Path,
) -> Result<CampaignConfigurationCompilationReport, CliError> {
    let scenario_text = read_bounded_utf8(
        scenario_input,
        "campaign scenario TOML",
        MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES,
    )?;
    let scenario = ScenarioDefForm::from_canonical_toml(&scenario_text).map_err(|error| {
        usage_error(format!(
            "invalid canonical campaign scenario at {}: {error}",
            scenario_input.display()
        ))
    })?;
    let supplied_schedule = read_bounded_bytes(
        schedule_input,
        "campaign schedule",
        MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES,
    )?;
    let schedule = Schedule::from_compact_binary(&supplied_schedule).map_err(|error| {
        usage_error(format!(
            "invalid canonical campaign schedule at {}: {error}",
            schedule_input.display()
        ))
    })?;
    if schedule.is_empty() {
        return Err(usage_error(
            "campaign configuration schedule is empty; use `campaign scenario compile` for genesis",
        ));
    }
    let schedule_body = schedule.to_compact_binary();
    if schedule_body != supplied_schedule {
        return Err(usage_error(
            "campaign configuration schedule is not canonical current-schema Schedule V2",
        ));
    }

    let scenario_body = scenario.to_compact_binary();
    validate_import_body_size("scenario", scenario_body.len())?;
    validate_import_body_size("schedule", schedule_body.len())?;
    let scenario_artifact = encode_crucible_scenario_artifact(&scenario)
        .map_err(|error| usage_error(format!("could not derive scenario artifact: {error}")))?;
    let configuration_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &schedule).map_err(|error| {
            usage_error(format!("could not derive configuration artifact: {error}"))
        })?;
    decode_crucible_configuration_artifact(&scenario, &scenario_artifact, &configuration_artifact)
        .map_err(|error| {
            usage_error(format!(
                "campaign configuration is not independently importable: {error}"
            ))
        })?;
    let scenario_artifact_id = scenario_artifact
        .id()
        .map_err(|error| usage_error(format!("could not address scenario artifact: {error}")))?;
    let configuration_artifact_id = configuration_artifact.id().map_err(|error| {
        usage_error(format!("could not address configuration artifact: {error}"))
    })?;
    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule: schedule.clone(),
    };

    let directory = write_configuration_import_bundle(
        output,
        "campaign configuration bundle",
        &scenario_body,
        &schedule_body,
    )?;

    Ok(CampaignConfigurationCompilationReport {
        schema: CAMPAIGN_CONFIGURATION_COMPILATION_REPORT_SCHEMA,
        scenario_input: scenario_input.display().to_string(),
        schedule_input: schedule_input.display().to_string(),
        manifest: directory.join(import_manifest_name()).display().to_string(),
        scenario_body: directory.join(scenario_body_name()).display().to_string(),
        schedule_body: directory.join(schedule_body_name()).display().to_string(),
        directory: directory.display().to_string(),
        scenario: scenario.id().to_hex(),
        scenario_artifact: scenario_artifact_id.to_string(),
        configuration: configuration.id().to_hex(),
        configuration_artifact: configuration_artifact_id.to_string(),
        decisions: schedule.len(),
    })
}

pub(super) fn render_campaign_configuration_compilation(
    report: &CampaignConfigurationCompilationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            backend_error(format!(
                "campaign configuration compilation JSON encoding failed: {error}"
            ))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            backend_error(format!(
                "campaign configuration compilation JSON encoding failed: {error}"
            ))
        }),
        OutputFormat::Table => Ok([
            format!("{:<24} {}", "scenario", report.scenario),
            format!("{:<24} {}", "scenario_artifact", report.scenario_artifact),
            format!("{:<24} {}", "configuration", report.configuration),
            format!(
                "{:<24} {}",
                "configuration_artifact", report.configuration_artifact
            ),
            format!("{:<24} {}", "decisions", report.decisions),
            format!("{:<24} {}", "manifest", report.manifest),
            format!("{:<24} {}", "directory", report.directory),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| scenario | {} |\n| scenario artifact | {} |\n| configuration | {} |\n| configuration artifact | {} |\n| decisions | {} |\n| manifest | {} |\n| directory | {} |",
            report.scenario,
            report.scenario_artifact,
            report.configuration,
            report.configuration_artifact,
            report.decisions,
            report.manifest,
            report.directory
        )),
    }
}

fn validate_import_body_size(kind: &str, bytes: usize) -> Result<(), CliError> {
    if bytes > MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES {
        return Err(usage_error(format!(
            "compiled {kind} body contains {bytes} bytes; campaign import limit is {MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES}"
        )));
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- authoring tests use exact panic localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use crucible::{Decision, RngDecision, RngStreamId, SelectionDecision};
    use crucible_campaign::{
        BooleanDomain, CampaignHash, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
        ChoiceOpportunity, ChoiceSource, ChoiceValue, SelectableDeclaration, Selection,
        SelectionOrigin,
    };
    use std::collections::BTreeSet;
    use tempfile::tempdir;

    fn authored_scenario() -> ScenarioDefForm {
        let fixture = crucible::happy_path_scenario().expect("happy-path scenario");
        ScenarioDefForm::from_components(
            fixture.scenario.world(),
            &crucible::Plan::empty(),
            &crucible::Properties::empty(),
            fixture.scenario.seed(),
        )
        .expect("authored scenario")
    }

    fn write_scenario(path: &Path, scenario: &ScenarioDefForm) {
        std::fs::write(path, scenario.to_canonical_toml().expect("canonical TOML"))
            .expect("write scenario TOML");
    }

    fn nonempty_schedule() -> Schedule {
        Schedule::from_decisions([Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("campaign-authoring"),
            value: 7,
        })])
    }

    #[test]
    fn canonical_non_genesis_schedule_compiles_to_closed_import_bundle() {
        let temporary = tempdir().expect("temporary directory");
        let scenario_input = temporary.path().join("scenario.toml");
        let schedule_input = temporary.path().join("schedule.bin");
        let output = temporary.path().join("compiled");
        let scenario = authored_scenario();
        let schedule = nonempty_schedule();
        write_scenario(&scenario_input, &scenario);
        std::fs::write(&schedule_input, schedule.to_compact_binary()).expect("write schedule");

        let report = compile_campaign_configuration(&scenario_input, &schedule_input, &output)
            .expect("compile configuration");
        let decoded = Schedule::from_compact_binary(
            &std::fs::read(output.join(schedule_body_name())).expect("read schedule body"),
        )
        .expect("decode schedule body");
        let validation = validate_campaign_import_manifests(&[output.join(import_manifest_name())])
            .expect("validate generated import manifest");

        assert_eq!(decoded, schedule);
        assert_eq!(report.decisions, 1);
        assert_eq!(validation.configurations().len(), 1);
        assert_eq!(
            validation.configurations()[0],
            report.configuration_artifact
        );
        assert_eq!(
            report.configuration,
            Configuration {
                def: scenario.scenario_def(),
                schedule,
            }
            .id()
            .to_hex()
        );
    }

    #[test]
    fn empty_and_legacy_schedules_create_no_bundle() {
        let temporary = tempdir().expect("temporary directory");
        let scenario_input = temporary.path().join("scenario.toml");
        let schedule_input = temporary.path().join("schedule.bin");
        let output = temporary.path().join("compiled");
        write_scenario(&scenario_input, &authored_scenario());
        std::fs::write(&schedule_input, Schedule::empty().to_compact_binary())
            .expect("write empty schedule");
        assert!(compile_campaign_configuration(&scenario_input, &schedule_input, &output).is_err());

        let mut legacy = nonempty_schedule().to_compact_binary();
        legacy[..b"crucible.schedule.v2\0".len()].copy_from_slice(b"crucible.schedule.v1\0");
        std::fs::write(&schedule_input, legacy).expect("write legacy schedule");
        assert!(compile_campaign_configuration(&scenario_input, &schedule_input, &output).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn unresolved_selection_creates_no_bundle() {
        let temporary = tempdir().expect("temporary directory");
        let scenario_input = temporary.path().join("scenario.toml");
        let schedule_input = temporary.path().join("schedule.bin");
        let output = temporary.path().join("compiled");
        let scenario = authored_scenario();
        write_scenario(&scenario_input, &scenario);
        let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain"));
        let declaration = SelectableDeclaration::new(
            "product.test.configuration-authoring",
            ChoiceSource::Scheduler {
                producer: String::from("configuration-authoring-test"),
            },
            domain.clone(),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::new()).expect("class context"),
            BTreeSet::new(),
            true,
        )
        .expect("selectable declaration");
        let opportunity = ChoiceOpportunity::new(
            crucible_campaign::ScenarioDefId::from_hash(CampaignHash::from_bytes(
                scenario.scenario_def().id().bytes,
            )),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive("test", b"configuration-scheduler"),
                producer: CampaignHash::derive("test", b"configuration-producer"),
            },
            "configuration-authoring",
            None,
        )
        .expect("choice opportunity");
        let selection = Selection::new(
            &opportunity,
            &domain,
            ChoiceValue::Boolean(false),
            SelectionOrigin::Default,
        )
        .expect("default selection");
        let schedule =
            Schedule::from_decisions([Decision::Selection(SelectionDecision::new(&selection))]);
        std::fs::write(&schedule_input, schedule.to_compact_binary()).expect("write schedule");

        assert!(compile_campaign_configuration(&scenario_input, &schedule_input, &output).is_err());
        assert!(!output.exists());
    }
}
