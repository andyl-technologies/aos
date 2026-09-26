//! Credential refresh and stopped-owner incomplete-material cleanup.

use super::*;

use serde::Serialize;

use crucible_daemon::{
    CampaignLocalServiceConfig, CampaignLocalServiceMode, CampaignLoopbackEndpointConfig,
    CampaignLoopbackServerConfig, PreparedCampaignLocalService,
};

use crate::cli_campaign_store::{
    authenticate_campaign_store_capabilities, load_campaign_repository_store,
};

const STORE_CREDENTIAL_REFRESH_SCHEMA: &str = "crucible.cli.store-credential-refresh.v1";
const STORE_INCOMPLETE_PACK_CLEANUP_SCHEMA: &str = "crucible.cli.store-incomplete-pack-cleanup.v1";
const MAINTENANCE_OWNER_ENDPOINT: &str = "/tmp/crucible-campaign-store-maintenance-owner.sock";

#[derive(Serialize)]
struct StoreCredentialRefreshReport {
    schema: &'static str,
    configuration: String,
    capabilities: Vec<String>,
    physical_placements: u64,
    reference_generation: String,
    references: u64,
    authenticated: bool,
}

#[derive(Serialize)]
struct StoreIncompletePackCleanupReport {
    schema: &'static str,
    configuration: String,
    node: String,
    index_generation: u64,
    removed_unreferenced_packs: u64,
    removed_staging_packs: u64,
    authenticated: bool,
}

pub(super) fn run_store_credentials(
    args: &StoreCredentialsArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    match &args.operation {
        StoreCredentialsCommand::Refresh(refresh) => {
            let authenticated = authenticate_campaign_store_capabilities(&refresh.deployment)?;
            render_credential_refresh(
                &StoreCredentialRefreshReport {
                    schema: STORE_CREDENTIAL_REFRESH_SCHEMA,
                    configuration: encode_configuration(authenticated.configuration),
                    capabilities: authenticated.capabilities,
                    physical_placements: authenticated.physical_placements,
                    reference_generation: authenticated.reference_generation,
                    references: authenticated.references,
                    authenticated: true,
                },
                format,
            )
        }
    }
}

pub(super) fn run_store_cleanup(
    args: &StoreCleanupArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    match &args.operation {
        StoreCleanupCommand::IncompletePacks(cleanup) => {
            run_incomplete_pack_cleanup(cleanup, format)
        }
    }
}

fn run_incomplete_pack_cleanup(
    args: &StoreIncompletePackCleanupArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    let prepared = prepare_maintenance_owner(&args.state, &args.policy, &args.store)?;
    let authority = prepared.store_maintenance_authority().map_err(|error| {
        maintenance_error(format!("store maintenance authority unavailable: {error}"))
    })?;
    let packed = authority.packed_nodes();
    let selected = match args.node.as_deref() {
        Some(node) => packed
            .into_iter()
            .find(|candidate| candidate.as_str() == node)
            .ok_or_else(|| usage_error(format!("packed store node `{node}` is not admitted")))?,
        None if packed.len() == 1 => packed[0].clone(),
        None => {
            return Err(usage_error(format!(
                "--node is required when the graph has {} packed nodes",
                packed.len()
            )));
        }
    };
    let report = authority
        .cleanup_incomplete_packs(&selected)
        .map_err(|error| maintenance_error(format!("incomplete-pack cleanup failed: {error}")))?;
    render_incomplete_pack_cleanup(
        &StoreIncompletePackCleanupReport {
            schema: STORE_INCOMPLETE_PACK_CLEANUP_SCHEMA,
            configuration: encode_configuration(authority.configuration_id().as_bytes()),
            node: selected.as_str().to_owned(),
            index_generation: report.index_generation(),
            removed_unreferenced_packs: report.removed_unreferenced_packs(),
            removed_staging_packs: report.removed_staging_packs(),
            authenticated: true,
        },
        format,
    )
}

fn prepare_maintenance_owner(
    state: &Path,
    policy: &Path,
    store_path: &Path,
) -> Result<PreparedCampaignLocalService, CliError> {
    let endpoint = CampaignLoopbackEndpointConfig::new(
        MAINTENANCE_OWNER_ENDPOINT,
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
        0o600,
    )
    .map_err(|error| maintenance_error(format!("invalid internal owner endpoint: {error}")))?;
    let config = CampaignLocalServiceConfig::new(
        endpoint,
        state,
        policy,
        CampaignLocalServiceMode::ReadWrite,
        CampaignLoopbackServerConfig::default(),
    )
    .map_err(|error| maintenance_error(format!("invalid campaign owner profile: {error}")))?;
    let store = load_campaign_repository_store(store_path)?;
    config
        .prepare_with_store(store)
        .map_err(|error| maintenance_error(format!("campaign owner acquisition failed: {error}")))
}

fn encode_configuration(configuration: [u8; 32]) -> String {
    configuration
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn render_credential_refresh(
    report: &StoreCredentialRefreshReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(render_error),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(render_error),
        OutputFormat::Table => Ok([
            format!("{:<24} {}", "configuration", report.configuration),
            format!("{:<24} {}", "capabilities", report.capabilities.join(",")),
            format!(
                "{:<24} {}",
                "physical-placements", report.physical_placements
            ),
            format!(
                "{:<24} {}",
                "reference-generation", report.reference_generation
            ),
            format!("{:<24} {}", "references", report.references),
            format!("{:<24} {}", "authenticated", report.authenticated),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| configuration | {} |\n| capabilities | {} |\n| physical placements | {} |\n| reference generation | {} |\n| references | {} |\n| authenticated | {} |",
            report.configuration,
            report.capabilities.join(","),
            report.physical_placements,
            report.reference_generation,
            report.references,
            report.authenticated
        )),
    }
}

fn render_incomplete_pack_cleanup(
    report: &StoreIncompletePackCleanupReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(render_error),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(render_error),
        OutputFormat::Table => Ok([
            format!("{:<28} {}", "configuration", report.configuration),
            format!("{:<28} {}", "node", report.node),
            format!("{:<28} {}", "index-generation", report.index_generation),
            format!(
                "{:<28} {}",
                "removed-unreferenced-packs", report.removed_unreferenced_packs
            ),
            format!(
                "{:<28} {}",
                "removed-staging-packs", report.removed_staging_packs
            ),
            format!("{:<28} {}", "authenticated", report.authenticated),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| configuration | {} |\n| node | {} |\n| index generation | {} |\n| removed unreferenced packs | {} |\n| removed staging packs | {} |\n| authenticated | {} |",
            report.configuration,
            report.node,
            report.index_generation,
            report.removed_unreferenced_packs,
            report.removed_staging_packs,
            report.authenticated
        )),
    }
}

fn render_error(error: serde_json::Error) -> CliError {
    maintenance_error(format!(
        "store maintenance report rendering failed: {error}"
    ))
}

fn maintenance_error(message: impl Into<String>) -> CliError {
    backend_error(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintenance_reports_preserve_authenticated_operational_evidence() {
        let credential_report = StoreCredentialRefreshReport {
            schema: STORE_CREDENTIAL_REFRESH_SCHEMA,
            configuration: "configuration".to_owned(),
            capabilities: vec![
                "refs:s3:archive".to_owned(),
                "s3-endpoint:archive".to_owned(),
            ],
            physical_placements: 7,
            reference_generation: "ref-generation".to_owned(),
            references: 3,
            authenticated: true,
        };
        let Ok(credentials) = render_credential_refresh(&credential_report, OutputFormat::Jsonl)
        else {
            panic!("credential refresh report must render");
        };
        let Ok(credentials): Result<serde_json::Value, _> = serde_json::from_str(&credentials)
        else {
            panic!("credential refresh report must decode");
        };
        assert_eq!(credentials["capabilities"][0], "refs:s3:archive");
        assert_eq!(credentials["physical_placements"], 7);
        assert_eq!(credentials["references"], 3);
        assert_eq!(credentials["authenticated"], true);

        let cleanup_report = StoreIncompletePackCleanupReport {
            schema: STORE_INCOMPLETE_PACK_CLEANUP_SCHEMA,
            configuration: "configuration".to_owned(),
            node: "packed".to_owned(),
            index_generation: 7,
            removed_unreferenced_packs: 2,
            removed_staging_packs: 1,
            authenticated: true,
        };
        let Ok(cleanup) = render_incomplete_pack_cleanup(&cleanup_report, OutputFormat::Jsonl)
        else {
            panic!("incomplete-pack cleanup report must render");
        };
        let Ok(cleanup): Result<serde_json::Value, _> = serde_json::from_str(&cleanup) else {
            panic!("incomplete-pack cleanup report must decode");
        };
        assert_eq!(cleanup["index_generation"], 7);
        assert_eq!(cleanup["removed_unreferenced_packs"], 2);
        assert_eq!(cleanup["removed_staging_packs"], 1);
        assert_eq!(cleanup["authenticated"], true);
    }
}
