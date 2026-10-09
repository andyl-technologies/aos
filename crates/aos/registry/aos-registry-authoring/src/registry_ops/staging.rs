//! Administrative commands for local and configured Hub registry candidates.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_cli_ui::output::{OutputMode, Printer};

use super::config::{registry_upload_auth_config, resolve_registry_name, resolve_upload_urls};
use crate::RegistryStageCommand;
use aos_registry_client::config::ApmConfig;
use crate::registry::hub_stage::HubStageClient;
use crate::registry::staging::{LocalStageStore, hub};

/// Lists, inspects, or discards candidates at the configured registry destination.
///
/// Hub destinations use their shared remote catalog. Ordinary static origins use
/// retained local records without creating a stage store during inspection.
///
/// # Errors
///
/// Returns an error for invalid configuration, failed Hub discovery or access,
/// corrupt stages, stale discard revisions, or unsupported dry-run invocation.
pub async fn run_stage(
    config: &ApmConfig,
    command: &RegistryStageCommand,
    printer: &Printer,
) -> Result<()> {
    if aos_registry_client::dry_run::active() {
        bail!(
            "stage administration does not support --dry-run; list or show a candidate before discarding its exact revision"
        );
    }
    let selector = match command {
        RegistryStageCommand::List { registry }
        | RegistryStageCommand::Show { registry, .. }
        | RegistryStageCommand::Discard { registry, .. } => registry.as_deref(),
    };
    let registry = resolve_registry_name(config, selector)?;
    let mut destinations = resolve_upload_urls(config, &registry, &[]);
    if destinations.is_empty() {
        if let Some((configured, _)) = config
            .registries
            .iter()
            .find(|(configured, _)| configured.name == registry)
        {
            destinations.push(configured.url.clone());
        }
    }
    let token = std::env::var("AOS_TOKEN").ok().or_else(|| {
        registry_upload_auth_config(config, &registry).and_then(|auth| auth.token.clone())
    });
    for destination in destinations {
        if let Some(target) = hub::target(&destination, &registry).await? {
            let client =
                HubStageClient::connect(&target.origin, &target.registry, token.as_deref()).await?;
            return run_hub(
                command,
                &client,
                &config.scope.registries_path().join(&registry),
                printer,
            )
            .await;
        }
    }

    let store = LocalStageStore::open_read_only(&config.scope.registries_path().join(&registry))?;
    match command {
        RegistryStageCommand::List { .. } => {
            let stages = store.list()?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::to_value(&stages)?);
            } else {
                for stage in stages {
                    print_row(
                        printer,
                        &stage.revision.id,
                        stage.revision.revision,
                        stage.state,
                        &stage.revision.release_id,
                        &stage.revision.commit,
                    );
                }
            }
        }
        RegistryStageCommand::Show { id, .. } => {
            printer.json(&serde_json::to_value(store.show(id)?)?)
        }
        RegistryStageCommand::Discard { id, revision, .. } => {
            let stage = store.discard(id, *revision)?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::to_value(stage)?);
            } else {
                printer.success(&format!("Discarded stage {id} revision {revision}."));
            }
        }
    }
    Ok(())
}

async fn run_hub(
    command: &RegistryStageCommand,
    client: &HubStageClient,
    local_registry: &Path,
    printer: &Printer,
) -> Result<()> {
    match command {
        RegistryStageCommand::List { .. } => {
            let summaries = client.list().await?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::to_value(&summaries)?);
            } else {
                for stage in summaries {
                    print_row(
                        printer,
                        &stage.id,
                        stage.revision,
                        stage.state,
                        &stage.release_id,
                        &stage.commit,
                    );
                }
            }
        }
        RegistryStageCommand::Show { id, .. } => {
            printer.json(&serde_json::to_value(client.show(id).await?.record)?);
        }
        RegistryStageCommand::Discard { id, revision, .. } => {
            let stage = client.discard(id, *revision).await?;
            release_matching_local_roots(local_registry, &stage.record).with_context(|| {
                format!(
                    "Hub stage {id} revision {revision} was discarded; local roots remain retained: inspect the local stage store and retry exact revision cleanup"
                )
            })?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::to_value(stage.record)?);
            } else {
                printer.success(&format!("Discarded Hub stage {id} revision {revision}."));
            }
        }
    }
    Ok(())
}

/// Releases author-side roots only when the same exact revision was discarded.
fn release_matching_local_roots(
    registry: &Path,
    discarded: &aos_registry_format::staging::StageRecord,
) -> Result<()> {
    if !registry.try_exists()? {
        return Ok(());
    }
    let store = LocalStageStore::open_read_only(registry)?;
    if let Some(local) = store.find(&discarded.revision.id)?
        && local.revision == discarded.revision
    {
        store.discard(&local.revision.id, local.revision.revision)?;
    }
    Ok(())
}

fn print_row(
    printer: &Printer,
    id: &str,
    revision: u64,
    state: aos_registry_format::staging::StageState,
    version: &str,
    commit: &str,
) {
    printer.plain(&format!(
        "{id} revision {revision} {state:?} {version} {commit}"
    ));
}
