//! Package command orchestration for verified registry metadata refresh.
//!
//! Selects configured registries, persists consumer state overlays, aggregates
//! refresh failures, and renders `apm update` diagnostics and JSON results.
//! Transport and verification belong to `aos-registry-client`.

use anyhow::{Context, Result};
use aos_cli_ui::output::{OutputMode, Printer};
use aos_registry_client::config::ApmConfig;
use aos_registry_client::registry::{git, state};
use aos_registry_client::sync::{RegistrySyncError, RegistryVerificationError, SyncResult};
use aos_registry_client::types::ProfileScope;
use aos_registry_format::consumer::{TrackingMode, Transport};
use serde_json::json;

/// Formats the human-readable package delta for one completed registry sync.
fn format_sync_summary(registry: &str, result: &SyncResult) -> String {
    format!(
        "Registry '{}': done ({} packages; {} added, {} updated, {} removed; commit {})",
        registry,
        result.packages_count,
        result.packages_added,
        result.packages_updated,
        result.packages_removed,
        &result.new_commit[..result.new_commit.len().min(12)],
    )
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
/// When syncing all registries, a per-registry failure is reported without
/// aborting the remaining syncs. The command still returns an error after all
/// registries have been attempted so automation cannot mistake a partial or
/// wholly failed refresh for success. When a single registry was requested,
/// its failure is propagated immediately.
///
/// # Errors
///
/// Returns an error if `registry_filter` names a registry that does not
/// exist or is not enabled, if the filtered registry's tracking config is
/// invalid, any registry's sync fails (signature verification, network, or git
/// failures), or if the post-sync state file cannot be written.
async fn run_with_options(
    config: &ApmConfig,
    registry_filter: Option<&str>,
    printer: &Printer,
    suggest_system_scope: bool,
) -> Result<()> {
    // If a specific registry was requested, validate it exists.
    if let Some(name) = registry_filter {
        if config.find_registry(name).is_none() {
            return Err(RegistrySyncError {
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
    let mut failed_registries = Vec::new();
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
                failed_registries.push(reg_config.name.clone());
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
            Transport::Http | Transport::Git => {
                git::sync_git(
                    reg_config,
                    &tracking_mode,
                    &cache_dir,
                    &registries_dir,
                    &trusted_key_dirs,
                    &mut current_state,
                    printer,
                )
                .await
            }
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
                    printer.success(&format_sync_summary(&reg_config.name, &sync_result));
                }
            }
            Err(e) => {
                let message = e
                    .downcast_ref::<RegistryVerificationError>()
                    .map(verification_message)
                    .unwrap_or_else(|| e.to_string());
                if json_mode {
                    json_registries.push(json!({
                        "registry": &reg_config.name,
                        "status": "error",
                        "tracking": tracking,
                        "error": message,
                    }));
                } else {
                    printer.error(&format!(
                        "Failed to sync registry '{}': {}",
                        reg_config.name, message
                    ));
                }
                // Continue with other registries rather than aborting.
                if registry_filter.is_some() {
                    // If the user asked for a specific registry, propagate the error.
                    return Err(e);
                }
                failed_registries.push(reg_config.name.clone());
            }
        }
    }

    if !any_synced {
        if let Some(name) = registry_filter {
            return Err(RegistrySyncError {
                message: format!("registry '{name}' is not enabled"),
            }
            .into());
        }
        printer.warning(&format!(
            "No enabled registries found. Add one with `{} add`.",
            aos_cli_ui::invocation::package_registry_command()
        ));
    }

    // Opportunistically prune orphaned writable-layer overlays: a seeded
    // registry whose seed was blanked leaves a url-less state delta behind that
    // could otherwise resurrect stale anti-rollback state on re-add. Cleanup
    // failures must not fail the sync, so they are only warned about.
    match aos_registry_client::cleanup::prune_orphaned_overlays(config.scope) {
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

    // Containers intentionally inherit their system-provisioned registry into
    // user scope; recommending --system would suggest an unavailable operation.
    if nudge_system && !json_mode && suggest_system_scope {
        printer.warning(
            "Synced a system registry into the root user's tree; \
             pass --system to update /var/lib/apm with state in /etc/apm.",
        );
    }

    if !failed_registries.is_empty() {
        return Err(RegistrySyncError {
            message: format!(
                "failed to update {} registry(s): {}",
                failed_registries.len(),
                failed_registries.join(", ")
            ),
        }
        .into());
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

/// Formats a registry verification refusal with command-line recovery guidance.
///
/// The client reports typed security reasons without prescribing an application.
/// This presentation adapter supplies the existing package and registry command
/// hints while retaining the fail-closed reason for the refusal.
pub fn verification_message(error: &RegistryVerificationError) -> String {
    match error {
        RegistryVerificationError::MissingTrustedKey { registry } => format!(
            "{error}.\n\
             Pin a maintainer key with `apr trust pin {registry} <{registry}:Ed25519:base64key>`, or set\n\
             [registry.signing] public_key in the registry config.\n\
             (Setting [registry.signing] required = false disables verification.)"
        ),
        RegistryVerificationError::MissingTrustRoster { .. }
        | RegistryVerificationError::EmptyTrustRoster { .. } => format!(
            "{error}.\n\
             Publish a roster with `apr keys add`, or set [registry.signing] required = false."
        ),
        RegistryVerificationError::MissingChannelTrustedKey { .. } => {
            format!("{error}: pin one with `apr trust pin` or set [registry.signing] public_key")
        }
        RegistryVerificationError::NonFastForward {
            previous_commit,
            selected_commit,
        } => format!(
            "registry downgrade detected: commit {selected_commit} is not a \
             descendant of previously verified commit {previous_commit}.\n\n\
             This could indicate a downgrade attack or a force-pushed \
             registry. If you trust this change, delete the registry state \
             and run `{} update` again.",
            aos_cli_ui::invocation::package_manager_command()
        ),
    }
}

/// Returns `true` when the process is running with an effective uid of 0.
///
/// Used only to decide whether to print the `--system` discoverability hint;
/// it never gates behavior, so a stale value is harmless.
fn running_as_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// Refreshes registries with the hint appropriate to this package runtime.
///
/// # Errors
///
/// Returns an error when registry selection, verification, transport, or
/// persistence fails.
pub async fn run(
    config: &ApmConfig,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    run_with_options(
        config,
        registry_filter,
        printer,
        !crate::runtime_boundary::is_container(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{SyncResult, format_sync_summary};

    #[test]
    fn sync_summary_reports_every_package_delta() {
        let result = SyncResult {
            new_commit: String::from(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            packages_count: 1,
            packages_added: 0,
            packages_updated: 1,
            packages_removed: 2,
        };

        assert_eq!(
            format_sync_summary("stable", &result),
            "Registry 'stable': done (1 packages; 0 added, 1 updated, 2 removed; commit 0123456789ab)"
        );
    }
}
