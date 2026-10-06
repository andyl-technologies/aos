//! Original deployed storage and metadata custody before finding input decoding.

use crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignOwner;

use super::*;

pub(super) struct FindingSourceAuthentication {
    pub(super) owner: GuardedCampaignOwner,
    pub(super) deployment: crate::cli_verify_serve::GuardedCampaignRunDeployment,
    pub(super) qemu: PathBuf,
    pub(super) plugin: PathBuf,
    pub(super) build_id: String,
    pub(super) workspace: PathBuf,
    pub(super) decoding: crucible_session::engine::owned_decode::DecodeBudget,
}

impl FindingSourceAuthentication {
    /// Admits the original actor and namespace before reading finding metadata.
    pub(super) fn open(cli: &Cli, input: &Path) -> Result<Self, CliError> {
        let (qemu, plugin, build_id) = exact::resolve_immutable_qemu(cli)?;
        let deployment = crate::cli_verify_serve::load_guarded_campaign_deployment(
            cli.campaign_deployment.as_deref(),
        )?;
        let input = std::fs::canonicalize(input)?;
        let lifecycle = crucible_api::ProductionVmLifecycleConfig::for_artifact_authentication(
            &qemu, &plugin, &input,
        );
        let campaign = CampaignName::new("finding-source-authentication").map_err(|error| {
            backend_error(format!("finding source identity is invalid: {error}"))
        })?;
        let config =
            deployment.execution_config(lifecycle, campaign, &input, deployment.resources)?;
        let owner = GuardedCampaignOwner::open(config)
            .map_err(|error| backend_error(format!("finding source admission failed: {error}")))?;
        let authority = owner.repository_metadata_resources().map_err(|error| {
            backend_error(format!("finding source resources are unavailable: {error}"))
        })?;
        let decoding = crucible_session::engine::owned_decode::DecodeBudget::for_store(authority)
            .map_err(|error| {
            backend_error(format!("finding metadata admission failed: {error}"))
        })?;
        let workspace = owner.prepare_import_workspace().map_err(|error| {
            backend_error(format!("finding workspace admission failed: {error}"))
        })?;

        Ok(Self {
            owner,
            deployment,
            qemu,
            plugin,
            build_id,
            workspace,
            decoding,
        })
    }
}
