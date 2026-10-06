//! Original deployed storage and metadata custody before finding input decoding.

use crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignOwner;

use super::*;

pub(crate) struct FindingSourceAuthentication {
    pub(crate) owner: GuardedCampaignOwner,
    pub(crate) deployment: crate::cli_verify_serve::GuardedCampaignRunDeployment,
    pub(crate) qemu: PathBuf,
    pub(crate) plugin: PathBuf,
    pub(crate) build_id: String,
    pub(crate) workspace: PathBuf,
    pub(crate) decoding: crucible_session::engine::owned_decode::DecodeBudget,
}

impl FindingSourceAuthentication {
    /// Admits the original actor and namespace before reading finding metadata.
    ///
    /// # Errors
    /// Refuses mutable native artifacts, invalid deployment or unavailable
    /// original storage, metadata and host capacity.
    pub(crate) fn open(cli: &Cli, input: &Path) -> Result<Self, CliError> {
        let (qemu, plugin, build_id) = exact::resolve_immutable_qemu(cli)?;
        Self::open_with_lifecycle(cli, input, qemu, plugin, build_id, None)
    }

    /// Uses deployed native assets while admitting metadata before replay input reads.
    ///
    /// # Errors
    /// Refuses unavailable native assets, invalid deployment or exhausted
    /// original storage and metadata authority.
    pub(crate) fn open_native_replay(cli: &Cli, input: &Path) -> Result<Self, CliError> {
        let (qemu, plugin, build_id) = exact::resolve_immutable_qemu(cli)?;
        let backend = crate::cli_run_save::require_selftest_qemu_backend(cli)?;
        let lifecycle = production_qemu_lifecycle_config(&backend)?;
        Self::open_with_lifecycle(cli, input, qemu, plugin, build_id, Some(lifecycle))
    }

    fn open_with_lifecycle(
        cli: &Cli,
        input: &Path,
        qemu: PathBuf,
        plugin: PathBuf,
        build_id: String,
        lifecycle: Option<crucible_api::ProductionVmLifecycleConfig>,
    ) -> Result<Self, CliError> {
        let deployment = crate::cli_verify_serve::load_guarded_campaign_deployment(
            cli.campaign_deployment.as_deref(),
        )?;
        let input = std::fs::canonicalize(input)?;
        let lifecycle = lifecycle.unwrap_or_else(|| {
            crucible_api::ProductionVmLifecycleConfig::for_artifact_authentication(
                &qemu, &plugin, &input,
            )
        });
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

    /// Reads one bounded input under the original metadata and descriptor owner.
    ///
    /// # Errors
    /// Refuses exhausted original credits, a nonregular file, changing length,
    /// allocation failure or file I/O errors.
    pub(crate) fn read_input(&self, path: &Path) -> Result<Vec<u8>, CliError> {
        let authority = self
            .owner
            .repository_metadata_resources()
            .map_err(|error| {
                backend_error(format!("artifact input resources are unavailable: {error}"))
            })?;
        crate::cli_input_resources::read_admitted_input(&authority, &self.decoding, path)
    }
}
