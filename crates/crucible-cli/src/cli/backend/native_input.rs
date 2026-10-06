//! Original deployed execution ownership before native Run and Fuzz model reads.
//!
//! Admission opens the real actor and quota namespace with no guest assets.
//! Planning borrows its metadata account; later execution consumes that same
//! unused owner and installs the authenticated guest lifecycle without renewing
//! its supervisor, resource vector, or persistent storage authority.

use super::*;
use crate::cli_input_resources::{StandaloneInputResources, original_budget};
use crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignOwner;
use std::cell::RefCell;

/// Retains concrete owner-admission failures and their original cleanup custody.
#[derive(Debug)]
pub(crate) enum NativeExecutionAdmissionError {
    Owner(Box<crucible_daemon::PackagedQemuExecutorError>),
    Lifecycle(Box<crucible_daemon::qemu_campaign_lifecycle::GuardedFindingMidpointError>),
}

impl fmt::Display for NativeExecutionAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Owner(source) => source.fmt(formatter),
            Self::Lifecycle(source) => source.fmt(formatter),
        }
    }
}

impl Error for NativeExecutionAdmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Owner(source) => Some(source.as_ref()),
            Self::Lifecycle(source) => Some(source.as_ref()),
        }
    }
}

thread_local! {
    static COMMAND_NATIVE_OWNER: RefCell<Option<GuardedCampaignOwner>> = const { RefCell::new(None) };
}

/// Restores a nested command's owner after all its input borrowers have closed.
pub(crate) struct NativeCommandInputOwner {
    previous: Option<GuardedCampaignOwner>,
}

impl Drop for NativeCommandInputOwner {
    fn drop(&mut self) {
        COMMAND_NATIVE_OWNER.with(|current| *current.borrow_mut() = self.previous.take());
    }
}

/// Admits complete deployed authority before model decoding or seed projection.
///
/// # Errors
/// Refuses unavailable native paths, deployment, genuine quota, original
/// supervision, or resource capacity. No guest can launch from this profile.
pub(crate) fn admit_native_command_input(
    cli: &Cli,
) -> Result<(StandaloneInputResources, NativeCommandInputOwner), CliError> {
    #[cfg(test)]
    if cli.campaign_deployment.is_none()
        && let Some(resources) = crate::tests::component_input_resources()
    {
        // Pure input-validation tests reuse their explicitly installed account;
        // they receive no native owner, kernel proof, or execution authority.
        resources
            .decoding
            .check()
            .map_err(CliError::MetadataAdmission)?;
        return Ok((resources, install_native_owner(None)));
    }

    let (qemu, plugin) = native_input_artifact_paths(cli).ok_or_else(|| {
        backend_error("native input admission requires both deployed launch paths")
    })?;
    let deployment = crate::cli_verify_serve::load_guarded_campaign_deployment(
        cli.campaign_deployment.as_deref(),
    )?;
    let state = default_run_store_root(cli);
    let state = if state.is_absolute() {
        state
    } else {
        std::env::current_dir()?.join(state)
    };
    let lifecycle = crucible_api::ProductionVmLifecycleConfig::for_artifact_authentication(
        qemu, plugin, &state,
    );
    let campaign = crucible_campaign::CampaignName::new("native-command-input")
        .map_err(|error| backend_error(format!("native input identity is invalid: {error}")))?;
    let config = deployment.execution_config(lifecycle, campaign, &state, deployment.resources)?;
    let owner =
        GuardedCampaignOwner::open(config).map_err(|source| CliError::ExecutionAdmission {
            context: "native input admission failed",
            source: NativeExecutionAdmissionError::Owner(Box::new(source)),
        })?;
    let authority = owner
        .repository_metadata_resources()
        .map_err(|source| CliError::InputAuthority(Box::new(source)))?;
    Ok((
        StandaloneInputResources::from_authority(authority)?,
        install_native_owner(Some(owner)),
    ))
}

fn install_native_owner(owner: Option<GuardedCampaignOwner>) -> NativeCommandInputOwner {
    let previous = COMMAND_NATIVE_OWNER.with(|current| current.replace(owner));
    NativeCommandInputOwner { previous }
}

/// Transfers the first owner into execution after checking its original account.
///
/// # Errors
/// Refuses expired input authority. The receiving lifecycle binder must still
/// validate native identity and the sole unused owner before any realization.
pub(crate) fn take_native_owner() -> Result<Option<GuardedCampaignOwner>, CliError> {
    let Some(owner) = COMMAND_NATIVE_OWNER.with(|current| current.borrow_mut().take()) else {
        return Ok(None);
    };
    let decoding = original_budget()?;
    decoding.check().map_err(CliError::MetadataAdmission)?;
    Ok(Some(owner))
}
