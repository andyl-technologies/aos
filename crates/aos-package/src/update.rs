//! `apm update` — sync registry metadata.
//!
//! Fetches the latest package metadata from all enabled registries (or a
//! single named one) and stores it in the local cache.  Registry update now
//! uses git-native sync for both dumb-HTTP and native git origins.

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
                // Persist the updated sync state as a minimal delta in the
                // writable config layer (`/var/lib/apm/config` for `--system`),
                // never in the read-only `/etc/apm` seed. For a seeded registry
                // this is a `[registry.state]`-only overlay; the registry's
                // url/signing keep inheriting from the seed.
                let state_path = config.registry_overlay_path(&reg_config.name);
                state::save_state(&state_path, &current_state)
                    .with_context(|| format!("saving state for registry '{}'", reg_config.name))?;

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

    // Opportunistically prune orphaned writable-layer overlays: a seeded
    // registry whose seed was blanked leaves a url-less state delta behind that
    // could otherwise resurrect stale anti-rollback state on re-add. Cleanup
    // failures must not fail the sync, so they are only warned about.
    match crate::clean::prune_orphaned_overlays(config.scope) {
        Ok(pruned) if !pruned.is_empty() && !json_mode => {
            printer.info(&format!(
                "Pruned {} orphaned registry overlay(s): {}",
                pruned.len(),
                pruned.join(", ")
            ));
        }
        Ok(_) => {}
        Err(e) => printer.warning(&format!("could not prune orphaned overlays: {e}")),
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
    // SAFETY: `geteuid` is always successful and takes no arguments — it has
    // no preconditions and cannot produce undefined behavior.
    unsafe { libc::geteuid() == 0 }
}
