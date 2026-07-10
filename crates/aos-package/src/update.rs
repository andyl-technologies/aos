//! `apm update` — sync registry metadata.
//!
//! Fetches the latest package metadata from all enabled registries (or a
//! single named one) and stores it in the local cache.  Registry update now
//! uses git-native sync for both dumb-HTTP and native git origins.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::ApmConfig;
use crate::registry::{git, state};
use crate::types::{ProfileScope, TrackingMode, Transport};
use aos_core::error::AosError;
use aos_core::output::{OutputMode, Printer};
use serde_json::json;

// ---------------------------------------------------------------------------
// Sync result
// ---------------------------------------------------------------------------

/// Summary of a sync operation against a single registry.
pub struct SyncResult {
    /// The new HEAD commit SHA after sync.
    pub new_commit: String,
    /// Total number of packages in the registry after sync.
    pub packages_count: usize,
    /// Number of packages added.
    pub packages_added: usize,
    /// Number of packages updated.
    pub packages_updated: usize,
    /// Number of packages removed.
    pub packages_removed: usize,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run `apm update` — sync all (or one) registry.
///
/// Iterates the enabled registries (or just `registry_filter` when given),
/// skips registries whose commit-pinned tracking target is already cached,
/// performs a git-native sync for the rest, and persists the updated sync
/// state next to each registry's config file.
///
/// When syncing all registries, a per-registry failure is reported but does
/// not abort the remaining syncs; when a single registry was requested, its
/// failure is propagated.
///
/// # Errors
///
/// Returns an error if `registry_filter` names a registry that does not
/// exist or is not enabled, if the filtered registry's tracking config is
/// invalid or its sync fails (signature verification, network, or git
/// failures), or if the post-sync state file cannot be written.
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
    let trusted_key_dirs = config.scope.trusted_keys_dirs();
    let config_dir = config.scope.config_dir();
    let mut any_synced = false;
    // Set when a system-provisioned registry (one with no user-level config
    // file) is synced through the user-scope fallback while running as root.
    // Such a sync lands clones and state in the user tree rather than
    // `/var/lib/apm` + `/etc/apm`; nudge the operator toward `--system`.
    let mut nudge_system = false;
    let json_mode = printer.mode() == OutputMode::Json;
    let mut json_registries = Vec::new();

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

        // A user-scope sync of a registry that only exists in the system
        // config (no user-level `registries.d/<name>.toml`) is the fallback
        // path, not a true system update. Flag it when running as root so we
        // can suggest `--system` once the loop finishes.
        if config.scope == ProfileScope::User
            && running_as_root()
            && !config_dir
                .join("registries.d")
                .join(format!("{}.toml", reg_config.name))
                .exists()
        {
            nudge_system = true;
        }

        let mut current_state = existing_state.clone().unwrap_or_default();

        // Resolve tracking mode from config.
        let tracking_mode = match reg_config.tracking_mode() {
            Ok(m) => m,
            Err(e) => {
                if json_mode {
                    json_registries.push(json!({
                        "registry": &reg_config.name,
                        "status": "error",
                        "error": format!("invalid tracking config: {e}"),
                    }));
                } else {
                    printer.error(&format!(
                        "Registry '{}': invalid tracking config: {}",
                        reg_config.name, e
                    ));
                }
                if registry_filter.is_some() {
                    return Err(e);
                }
                continue;
            }
        };
        let tracking = tracking_mode.to_string();

        // For commit and tag modes, check if already at target.
        match &tracking_mode {
            TrackingMode::Commit(hash) => {
                if current_state.last_commit.as_deref() == Some(hash.as_str()) {
                    if json_mode {
                        json_registries.push(json!({
                            "registry": &reg_config.name,
                            "status": "current",
                            "tracking": tracking,
                            "commit": hash,
                        }));
                    } else {
                        printer.info(&format!(
                            "Registry '{}': already at commit {}",
                            reg_config.name,
                            &hash[..hash.len().min(12)],
                        ));
                    }
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

        if !json_mode {
            printer.header(&format!(
                "Fetching registry '{}' ({})...",
                reg_config.name, tracking_mode,
            ));
        }

        let result = match reg_config.transport() {
            Transport::Http | Transport::Git => git::sync_git(
                reg_config,
                &tracking_mode,
                &cache_dir,
                &registries_dir,
                &trusted_key_dirs,
                &mut current_state,
                printer,
            )
            .await
            .map(|r| SyncResult {
                new_commit: r.new_commit,
                packages_count: r.packages_count,
                packages_added: r.packages_added,
                packages_updated: r.packages_updated,
                packages_removed: r.packages_removed,
            }),
        };

        match result {
            Ok(sync_result) => {
                // Save state back to the registry config file.
                if let Some(state_path) =
                    writable_state_path(&config_dir, config.scope, &reg_config.name)
                {
                    save_registry_state(&state_path, reg_config, &current_state).with_context(
                        || format!("saving state for registry '{}'", reg_config.name),
                    )?;
                }

                if json_mode {
                    json_registries.push(json!({
                        "registry": &reg_config.name,
                        "status": "updated",
                        "tracking": tracking,
                        "commit": &sync_result.new_commit,
                        "packages": sync_result.packages_count,
                        "added": sync_result.packages_added,
                        "updated": sync_result.packages_updated,
                        "removed": sync_result.packages_removed,
                    }));
                } else {
                    printer.success(&format!(
                        "Registry '{}': done ({} packages, {} updated, commit {})",
                        reg_config.name,
                        sync_result.packages_count,
                        sync_result.packages_updated,
                        &sync_result.new_commit[..sync_result.new_commit.len().min(12)],
                    ));
                }
            }
            Err(e) => {
                if json_mode {
                    json_registries.push(json!({
                        "registry": &reg_config.name,
                        "status": "error",
                        "tracking": tracking,
                        "error": e.to_string(),
                    }));
                } else {
                    printer.error(&format!(
                        "Failed to sync registry '{}': {}",
                        reg_config.name, e
                    ));
                }
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

    if nudge_system && !json_mode {
        printer.warning(
            "Synced a system registry into the root user's tree; \
             pass --system to update /var/lib/apm with state in /etc/apm.",
        );
    }

    if json_mode {
        let updated = json_registries
            .iter()
            .filter(|entry| {
                entry.get("status").and_then(|status| status.as_str()) == Some("updated")
            })
            .count();
        printer.json(&json!({
            "action": "update",
            "registry": registry_filter,
            "updated": updated,
            "registries": json_registries,
        }));
    }

    Ok(())
}

/// Returns `true` when the process is running with an effective uid of 0.
///
/// Used only to decide whether to print the `--system` discoverability hint;
/// it never gates behavior, so a stale value is harmless.
fn running_as_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// Resolve the config file that should receive updated registry state.
///
/// User-scope configs layer `$XDG_CONFIG_HOME/apm` over the system config
/// directory. A system-provisioned registry may not have a user-level TOML
/// file at all; when the fallback file is writable, persist state there so
/// non-AOS fixture deployments using `APM_SYSTEM_CONFIG_DIR` keep anti-
/// rollback and last-commit state across invocations. When the fallback is
/// read-only, persist a user override so unprivileged updates still retain
/// anti-rollback and last-commit state across invocations.
fn writable_state_path(
    config_dir: &std::path::Path,
    scope: ProfileScope,
    name: &str,
) -> Option<PathBuf> {
    let primary = config_dir.join("registries.d").join(format!("{name}.toml"));
    if primary.exists() {
        return Some(primary);
    }

    if scope != ProfileScope::User {
        return None;
    }

    let fallback = ProfileScope::System
        .config_dir()
        .join("registries.d")
        .join(format!("{name}.toml"));
    if fallback.exists()
        && std::fs::OpenOptions::new()
            .write(true)
            .open(&fallback)
            .is_ok()
    {
        Some(fallback)
    } else if fallback.exists() {
        Some(primary)
    } else {
        None
    }
}

/// Persist registry sync state, creating a user override config when needed.
fn save_registry_state(
    path: &Path,
    reg_config: &crate::types::RegistryConfig,
    registry_state: &crate::types::RegistryState,
) -> Result<()> {
    if path.exists() {
        return state::save_state(path, registry_state);
    }

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

    let registry = match toml::Value::try_from(reg_config.clone())? {
        toml::Value::Table(mut table) => {
            table.insert("state".into(), toml::Value::try_from(registry_state)?);
            table
        }
        _ => anyhow::bail!("registry config did not serialize as a TOML table"),
    };
    let mut root = toml::map::Map::new();
    root.insert("registry".into(), toml::Value::Table(registry));
    let rendered = toml::to_string_pretty(&toml::Value::Table(root))?;
    fs::write(path, rendered).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
