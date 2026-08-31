//! Strict offline authoring for importable campaign scenario bundles.

use super::*;

use crucible::{Configuration, ScenarioDefForm, Schedule};
use crucible_daemon::{
    MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact,
};
use serde::Serialize;

use super::authoring::{
    import_manifest_name, read_bounded_utf8, scenario_body_name, schedule_body_name,
    write_configuration_import_bundle,
};

const CAMPAIGN_SCENARIO_COMPILATION_REPORT_SCHEMA: &str =
    "crucible.cli.campaign-scenario-compilation.v1";

/// Result of compiling one canonical scenario and its empty genesis schedule.
#[derive(Debug, Serialize)]
pub(super) struct CampaignScenarioCompilationReport {
    schema: &'static str,
    input: String,
    directory: String,
    manifest: String,
    scenario_body: String,
    schedule_body: String,
    scenario: String,
    scenario_artifact: String,
    genesis: String,
    genesis_artifact: String,
}

pub(super) fn compile_campaign_scenario(
    input: &Path,
    output: &Path,
) -> Result<CampaignScenarioCompilationReport, CliError> {
    let text = read_bounded_utf8(
        input,
        "campaign scenario TOML",
        MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES,
    )?;
    let scenario = ScenarioDefForm::from_canonical_toml(&text).map_err(|error| {
        usage_error(format!(
            "invalid canonical campaign scenario at {}: {error}",
            input.display()
        ))
    })?;
    let schedule = Schedule::empty();
    let scenario_body = scenario.to_compact_binary();
    let schedule_body = schedule.to_compact_binary();
    validate_import_body_size("scenario", scenario_body.len())?;
    validate_import_body_size("schedule", schedule_body.len())?;

    let scenario_artifact = encode_crucible_scenario_artifact(&scenario)
        .map_err(|error| usage_error(format!("could not derive scenario artifact: {error}")))?;
    let genesis_artifact = encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
        .map_err(|error| {
            usage_error(format!(
                "could not derive genesis configuration artifact: {error}"
            ))
        })?;
    let scenario_artifact_id = scenario_artifact
        .id()
        .map_err(|error| usage_error(format!("could not address scenario artifact: {error}")))?;
    let genesis_artifact_id = genesis_artifact.id().map_err(|error| {
        usage_error(format!(
            "could not address genesis configuration artifact: {error}"
        ))
    })?;
    let scenario_id = scenario.id().to_hex();
    let genesis_id = Configuration::genesis(scenario.scenario_def())
        .id()
        .to_hex();

    let directory = write_configuration_import_bundle(
        output,
        "campaign scenario bundle",
        &scenario_body,
        &schedule_body,
    )?;

    Ok(CampaignScenarioCompilationReport {
        schema: CAMPAIGN_SCENARIO_COMPILATION_REPORT_SCHEMA,
        input: input.display().to_string(),
        manifest: directory.join(import_manifest_name()).display().to_string(),
        scenario_body: directory.join(scenario_body_name()).display().to_string(),
        schedule_body: directory.join(schedule_body_name()).display().to_string(),
        directory: directory.display().to_string(),
        scenario: scenario_id,
        scenario_artifact: scenario_artifact_id.to_string(),
        genesis: genesis_id,
        genesis_artifact: genesis_artifact_id.to_string(),
    })
}

pub(super) fn render_campaign_scenario_compilation(
    report: &CampaignScenarioCompilationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            backend_error(format!(
                "campaign scenario compilation JSON encoding failed: {error}"
            ))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            backend_error(format!(
                "campaign scenario compilation JSON encoding failed: {error}"
            ))
        }),
        OutputFormat::Table => Ok([
            format!("{:<20} {}", "scenario", report.scenario),
            format!("{:<20} {}", "scenario_artifact", report.scenario_artifact),
            format!("{:<20} {}", "genesis", report.genesis),
            format!("{:<20} {}", "genesis_artifact", report.genesis_artifact),
            format!("{:<20} {}", "manifest", report.manifest),
            format!("{:<20} {}", "directory", report.directory),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| scenario | {} |\n| scenario artifact | {} |\n| genesis | {} |\n| genesis artifact | {} |\n| manifest | {} |\n| directory | {} |",
            report.scenario,
            report.scenario_artifact,
            report.genesis,
            report.genesis_artifact,
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

    #[test]
    fn canonical_scenario_compiles_to_closed_import_bundle() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("scenario.toml");
        let output = temporary.path().join("compiled");
        let scenario = authored_scenario();
        std::fs::write(
            &input,
            scenario.to_canonical_toml().expect("canonical TOML"),
        )
        .expect("write scenario TOML");

        let report = compile_campaign_scenario(&input, &output).expect("compile scenario");
        let decoded = ScenarioDefForm::from_compact_binary(
            &std::fs::read(output.join(scenario_body_name())).expect("read scenario body"),
        )
        .expect("decode scenario body");
        let schedule = Schedule::from_compact_binary(
            &std::fs::read(output.join(schedule_body_name())).expect("read schedule body"),
        )
        .expect("decode schedule body");
        let validation = validate_campaign_import_manifests(&[output.join(import_manifest_name())])
            .expect("validate generated import manifest");

        assert_eq!(decoded, scenario);
        assert!(schedule.is_empty());
        assert_eq!(validation.manifest_count(), 1);
        assert_eq!(validation.configurations().len(), 1);
        assert_eq!(validation.configurations()[0], report.genesis_artifact);
        assert_eq!(report.scenario, scenario.id().to_hex());
        assert_eq!(
            report.genesis,
            Configuration::genesis(scenario.scenario_def())
                .id()
                .to_hex()
        );
    }

    #[test]
    fn invalid_scenario_creates_no_bundle() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("invalid.toml");
        let output = temporary.path().join("compiled");
        std::fs::write(
            &input,
            "schema = \"crucible.scenario.v7\"\nunknown = true\n",
        )
        .expect("write invalid scenario");

        assert!(compile_campaign_scenario(&input, &output).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn existing_bundle_is_never_replaced() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("scenario.toml");
        let output = temporary.path().join("compiled");
        std::fs::write(
            &input,
            authored_scenario()
                .to_canonical_toml()
                .expect("canonical TOML"),
        )
        .expect("write scenario TOML");
        std::fs::create_dir(&output).expect("create existing output");
        std::fs::write(output.join("sentinel"), b"preserve").expect("write sentinel");

        assert!(compile_campaign_scenario(&input, &output).is_err());
        assert_eq!(
            std::fs::read(output.join("sentinel")).expect("read sentinel"),
            b"preserve"
        );
        assert_eq!(std::fs::read_dir(&output).expect("read output").count(), 1);
    }
}
