//! Metadata acquisition after registering a new authoring origin.
//!
//! This workflow refreshes only the newly added registry. General consumer
//! update selection, aggregate errors, and JSON output belong to the package
//! manager; the authoring caller reports registration and acquisition together.

use anyhow::{Context, Result};
use aos_cli_ui::output::Printer;
use aos_registry_client::config::ApmConfig;
use aos_registry_client::registry::{git, state};

pub(crate) async fn run(config: &ApmConfig, name: &str, printer: &Printer) -> Result<()> {
    let (registry, existing_state) = config.find_registry(name).with_context(|| {
        format!("newly registered origin '{name}' is absent after reloading configuration")
    })?;
    let tracking = registry.tracking_mode()?;
    let mut current_state = existing_state.clone().unwrap_or_default();
    let result = git::sync_git(
        registry,
        &tracking,
        &config.cache_path(),
        &config.scope.registries_path(),
        &config.scope.trusted_keys_dirs(),
        &mut current_state,
        printer,
    )
    .await?;
    state::save_state(&config.registry_overlay_path(name), &current_state)
        .with_context(|| format!("saving state for registry '{name}'"))?;

    printer.success(&format!(
        "Registry '{}': done ({} packages; {} added, {} updated, {} removed; commit {})",
        name,
        result.packages_count,
        result.packages_added,
        result.packages_updated,
        result.packages_removed,
        &result.new_commit[..result.new_commit.len().min(12)]
    ));
    match aos_registry_client::cleanup::prune_orphaned_overlays(config.scope) {
        Ok(pruned) if !pruned.is_empty() => printer.info(&format!(
            "Pruned {} orphaned registry overlay(s): {}",
            pruned.len(),
            pruned.join(", ")
        )),
        Ok(_) => {}
        Err(error) => printer.warning(&format!("could not prune orphaned overlays: {error}")),
    }
    Ok(())
}
