//! Strict offline authoring for canonical campaign lineage records.

use super::*;

use std::collections::BTreeMap;

use crucible_campaign::{
    CampaignHash, ConfigurationArtifactId, ConfigurationId, ScenarioArtifactId, ScenarioDefId,
};
use serde::{Deserialize, Serialize};

use super::authoring::{read_bounded_utf8, write_new_record};

const CAMPAIGN_LINEAGE_AUTHORING_SCHEMA_VERSION: u32 = 1;
const MAX_CAMPAIGN_LINEAGE_MANIFEST_BYTES: usize = 1024 * 1024;
const CAMPAIGN_LINEAGE_COMPILATION_REPORT_SCHEMA: &str =
    "crucible.cli.campaign-lineage-compilation.v1";

/// Result of compiling one strict authored lineage.
#[derive(Debug, Serialize)]
pub(super) struct CampaignLineageCompilationReport {
    schema: &'static str,
    input: String,
    output: String,
    lineage: String,
    encoded_bytes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredCampaignLineage {
    schema_version: u32,
    scenario: String,
    scenario_content: String,
    genesis: String,
    genesis_content: String,
    crucible_version: String,
    qemu_build: String,
    protocol_versions: BTreeMap<String, u32>,
    scenario_schema: u32,
    exact_closure_schema: u32,
}

pub(super) fn compile_campaign_lineage(
    input: &Path,
    output: &Path,
) -> Result<CampaignLineageCompilationReport, CliError> {
    let text = read_bounded_utf8(
        input,
        "campaign lineage manifest",
        MAX_CAMPAIGN_LINEAGE_MANIFEST_BYTES,
    )?;
    let authored: AuthoredCampaignLineage = toml::from_str(&text).map_err(|error| {
        usage_error(format!(
            "invalid campaign lineage manifest at {}: {error}",
            input.display()
        ))
    })?;
    let lineage = authored.into_lineage()?;
    let lineage_id = lineage
        .id()
        .map_err(|error| usage_error(format!("invalid authored campaign lineage: {error}")))?;
    let bytes = lineage.canonical_bytes();

    write_new_record(output, "campaign lineage record", &bytes)?;
    Ok(CampaignLineageCompilationReport {
        schema: CAMPAIGN_LINEAGE_COMPILATION_REPORT_SCHEMA,
        input: input.display().to_string(),
        output: output.display().to_string(),
        lineage: lineage_id.to_string(),
        encoded_bytes: bytes.len(),
    })
}

pub(super) fn render_campaign_lineage_compilation(
    report: &CampaignLineageCompilationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            backend_error(format!("campaign lineage JSON encoding failed: {error}"))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            backend_error(format!("campaign lineage JSON encoding failed: {error}"))
        }),
        OutputFormat::Table => Ok([
            format!("{:<16} {}", "lineage", report.lineage),
            format!("{:<16} {}", "encoded_bytes", report.encoded_bytes),
            format!("{:<16} {}", "output", report.output),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| lineage | {} |\n| encoded bytes | {} |\n| output | {} |",
            report.lineage, report.encoded_bytes, report.output
        )),
    }
}

impl AuthoredCampaignLineage {
    fn into_lineage(self) -> Result<CampaignLineage, CliError> {
        if self.schema_version != CAMPAIGN_LINEAGE_AUTHORING_SCHEMA_VERSION {
            return Err(usage_error(format!(
                "unsupported campaign lineage manifest schema version {}; expected {}",
                self.schema_version, CAMPAIGN_LINEAGE_AUTHORING_SCHEMA_VERSION
            )));
        }
        let scenario = parse_semantic_hash(&self.scenario, "scenario")?;
        let genesis = parse_semantic_hash(&self.genesis, "genesis configuration")?;
        let scenario_content = ScenarioArtifactId::parse(&self.scenario_content)
            .map_err(|error| usage_error(format!("invalid scenario artifact ID: {error}")))?;
        let genesis_content = ConfigurationArtifactId::parse(&self.genesis_content)
            .map_err(|error| usage_error(format!("invalid genesis artifact ID: {error}")))?;
        CampaignLineage::new(
            ScenarioDefId::from_hash(scenario),
            scenario_content,
            ConfigurationId::from_hash(genesis),
            genesis_content,
            self.crucible_version,
            self.qemu_build,
            self.protocol_versions,
            self.scenario_schema,
            self.exact_closure_schema,
        )
        .map_err(|error| usage_error(format!("invalid authored campaign lineage: {error}")))
    }
}

fn parse_semantic_hash(encoded: &str, field: &str) -> Result<CampaignHash, CliError> {
    CampaignHash::parse(encoded)
        .map_err(|error| usage_error(format!("invalid {field} semantic identity: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crucible_cas::content_store::{ContentId, ObjectKind};
    use tempfile::tempdir;

    fn artifact_id(schema: &str, kind: ObjectKind, label: &[u8]) -> String {
        format!("{schema}@{}", ContentId::for_bytes(kind, 1, label).encode())
    }

    fn manifest() -> String {
        let scenario = CampaignHash::derive(
            "crucible.cli.test.authored-lineage-scenario.v1",
            b"authored-lineage-scenario",
        )
        .to_hex();
        let genesis = CampaignHash::derive(
            "crucible.cli.test.authored-lineage-genesis.v1",
            b"authored-lineage-genesis",
        )
        .to_hex();
        let scenario_content = artifact_id(
            "crucible.campaign.scenario-artifact",
            ObjectKind::Scenario,
            b"authored-lineage-scenario-content",
        );
        let genesis_content = artifact_id(
            "crucible.campaign.configuration-artifact",
            ObjectKind::Configuration,
            b"authored-lineage-genesis-content",
        );
        format!(
            r#"schema_version = 1
scenario = "{scenario}"
scenario_content = "{scenario_content}"
genesis = "{genesis}"
genesis_content = "{genesis_content}"
crucible_version = "crucible-0.1.0"
qemu_build = "qemu-10.0-crucible"
scenario_schema = 3
exact_closure_schema = 4

[protocol_versions]
control = 2
shared-memory = 5
"#
        )
    }

    #[test]
    fn strict_manifest_compiles_to_canonical_lineage() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("lineage.toml");
        let output = temporary.path().join("lineage.bin");
        std::fs::write(&input, manifest()).expect("write manifest");

        let report = compile_campaign_lineage(&input, &output).expect("compile lineage");
        let bytes = std::fs::read(&output).expect("read lineage");
        let lineage = CampaignLineage::from_canonical_bytes(&bytes).expect("decode lineage");

        assert_eq!(
            report.lineage,
            lineage.id().expect("lineage ID").to_string()
        );
        assert_eq!(report.encoded_bytes, bytes.len());
        assert_eq!(lineage.protocol_versions().get("control"), Some(&2));
        assert_eq!(lineage.exact_closure_schema(), 4);
    }

    #[test]
    fn invalid_manifest_does_not_create_output() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("lineage.toml");
        let output = temporary.path().join("lineage.bin");
        std::fs::write(&input, manifest().replace("control = 2", "control = 0"))
            .expect("write invalid manifest");

        assert!(compile_campaign_lineage(&input, &output).is_err());
        assert!(!output.exists());
    }
}
