//! `apm update` — sync registry metadata.
//!
//! Fetches the latest package metadata from all enabled registries (or a
//! single named one) and stores it in the local cache.  Registry update now
//! uses git-native sync for both dumb-HTTP and native git origins.

use anyhow::{Context, Result};

use crate::config::ApmConfig;
use crate::registry::{git, state};
use crate::types::{TrackingMode, Transport};
use aos_core::error::AosError;
use aos_core::output::Printer;

// ---------------------------------------------------------------------------
// Sync result
// ---------------------------------------------------------------------------

/// Summary of a sync operation against a single registry.
pub struct SyncResult {
    /// The new HEAD commit SHA after sync.
    pub new_commit: String,
    /// Total number of packages in the registry after sync.
    pub packages_count: usize,
    /// Number of packages that were added or updated.
    pub packages_updated: usize,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run `apm update` — sync all (or one) registry.
pub async fn run(
    config: &ApmConfig,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    // If a specific registry was requested, validate it exists.
    if let Some(name) = registry_filter {
        if config.find_registry(name).is_none() {
            return Err(AosError::RegistryError {
                message: format!("registry '{name}' not found"),
            }
            .into());
        }
    }

    let cache_dir = config.cache_path();
    let registries_dir = config.scope.registries_path();
    let config_dir = config.scope.config_dir();
    let mut any_synced = false;

    for (reg_config, existing_state) in &config.registries {
        // Skip disabled registries.
        if !reg_config.enabled {
            continue;
        }

        // If a filter is set, skip non-matching registries.
        if let Some(name) = registry_filter {
            if reg_config.name != name {
                continue;
            }
        }

        any_synced = true;
        let mut current_state = existing_state.clone().unwrap_or_default();

        // Resolve tracking mode from config.
        let tracking_mode = match reg_config.tracking_mode() {
            Ok(m) => m,
            Err(e) => {
                printer.error(&format!(
                    "Registry '{}': invalid tracking config: {}",
                    reg_config.name, e
                ));
                if registry_filter.is_some() {
                    return Err(e);
                }
                continue;
            }
        };

        // For commit and tag modes, check if already at target.
        match &tracking_mode {
            TrackingMode::Commit(hash) => {
                if current_state.last_commit.as_deref() == Some(hash.as_str()) {
                    printer.info(&format!(
                        "Registry '{}': already at commit {}",
                        reg_config.name,
                        &hash[..hash.len().min(12)],
                    ));
                    continue;
                }
            }
            TrackingMode::Tag(tag) => {
                // If we have a last_commit, we need to check if that commit
                // corresponds to this tag. We can't easily check without
                // the repo, so we proceed with the sync which will be a
                // no-op if already up to date.
                let _ = tag; // proceed to sync
            }
            _ => {}
        }

        printer.header(&format!(
            "Fetching registry '{}' ({})...",
            reg_config.name, tracking_mode,
        ));

        let result = match reg_config.transport() {
            Transport::Http | Transport::Git => git::sync_git(
                reg_config,
                &tracking_mode,
                &cache_dir,
                &registries_dir,
                &mut current_state,
                printer,
            )
            .await
            .map(|r| SyncResult {
                new_commit: r.new_commit,
                packages_count: r.packages_added + r.packages_updated,
                packages_updated: r.packages_updated,
            }),
        };

        match result {
            Ok(sync_result) => {
                // Save state back to the registry config file.
                let state_path = config_dir
                    .join("registries.d")
                    .join(format!("{}.toml", reg_config.name));
                if state_path.exists() {
                    state::save_state(&state_path, &current_state).with_context(|| {
                        format!("saving state for registry '{}'", reg_config.name)
                    })?;
                }

                printer.success(&format!(
                    "Registry '{}': done ({} packages, {} updated, commit {})",
                    reg_config.name,
                    sync_result.packages_count,
                    sync_result.packages_updated,
                    &sync_result.new_commit[..sync_result.new_commit.len().min(12)],
                ));
            }
            Err(e) => {
                printer.error(&format!(
                    "Failed to sync registry '{}': {}",
                    reg_config.name, e
                ));
                // Continue with other registries rather than aborting.
                if registry_filter.is_some() {
                    // If the user asked for a specific registry, propagate the error.
                    return Err(e);
                }
            }
        }
    }

    if !any_synced {
        if let Some(name) = registry_filter {
            return Err(AosError::RegistryError {
                message: format!("registry '{name}' is not enabled"),
            }
            .into());
        }
        printer.warning(&format!(
            "No enabled registries found. Add one with `{} add`.",
            aos_core::invocation::package_registry_command()
        ));
    }

    Ok(())
}
