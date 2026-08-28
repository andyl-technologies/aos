//! `apm remove` and `apm autoremove` — uninstall packages.
//!
//! Removal never touches the Nix store directly: it creates a new profile
//! generation whose GC roots omit the removed packages (and their source
//! derivations), deletes their metadata, rebuilds the merged FHS tree, and
//! switches atomically. The store paths themselves are reclaimed later by
//! `apm gc` once no generation roots them; the previous generation remains
//! available for `apm rollback`.
//!
//! An *orphan* is an auto-installed package (`explicit = false`) whose
//! store-path hash is not in the live closure of any remaining explicit
//! package. `apm remove --autoremove` removes orphans created by the
//! removal; `apm autoremove` removes all current orphans.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;

use anyhow::{Context, Result};

use super::config::ApmConfig;
use super::exposed_units::{
    rebuild_generation_expose_image_roots, rebuild_generation_expose_roots,
    reconcile_system_profile, validate_generation_exposed_units,
};
use super::profile::Profile;
use super::profile::merge::build_generation_fhs_tree;
use super::profile::meta::{delete_meta, list_meta, snapshot_profile_meta_to_generation};
use super::registry::store_path_hash;
use super::store::closure_paths;
use super::types::InstalledMeta;
use aos_core::error::AosError;
use aos_core::output::{OutputMode, Printer};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Summary of what a remove-style operation selected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RemoveOutcome {
    /// Number of orphaned auto-installed packages selected for removal.
    pub orphan_count: usize,
}

/// Run `apm remove <packages>`.
///
/// Removes the named packages from the current profile, creates a new
/// generation without those packages, rebuilds the FHS merge tree, and
/// switches to the new generation.  If `auto_remove` is set, also removes
/// orphaned auto-installed dependencies.
///
/// With `dry_run`, the plan is printed and nothing changes; `yes` (or the
/// `assume_yes` setting) skips the confirmation prompt.
///
/// # Errors
///
/// Returns an error if there is no current generation, a requested package
/// is not installed ([`AosError::PackageNotFound`]), the user declines the
/// prompt ([`AosError::UserCancelled`]), or creating, populating, or
/// switching to the new generation fails.
pub async fn run(
    config: &ApmConfig,
    packages: &[String],
    auto_remove: bool,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<RemoveOutcome> {
    run_inner(config, packages, auto_remove, dry_run, yes, printer, true).await
}

/// Run `apm remove <packages>` without reconciling exposed systemd units.
///
/// This is used by higher-level workflows that perform multiple profile or
/// artifact updates and reconcile the exposed unit surface once at the end.
///
/// # Errors
///
/// Returns the same errors as [`run`].
pub(crate) async fn run_deferred_expose_reconcile(
    config: &ApmConfig,
    packages: &[String],
    auto_remove: bool,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<RemoveOutcome> {
    run_inner(config, packages, auto_remove, dry_run, yes, printer, false).await
}

async fn run_inner(
    config: &ApmConfig,
    packages: &[String],
    auto_remove: bool,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
    reconcile_exposed_units: bool,
) -> Result<RemoveOutcome> {
    if packages.is_empty() {
        printer.info("No packages specified.");
        return Ok(RemoveOutcome::default());
    }

    // Step 1: Inspect profile and get current generation.
    let inspect_profile = Profile::open_readonly(config.scope);
    let current_gen = inspect_profile
        .current_generation()?
        .ok_or_else(|| anyhow::anyhow!("no current generation -- nothing installed"))?;

    // Step 2: Find installed packages matching the requested names.
    let to_remove = find_installed(&inspect_profile, packages)?;

    // Step 3: Collect hashes to remove.
    let mut remove_hashes = root_hashes_for_installed(&to_remove);

    // Step 4: If --autoremove, also find orphaned auto-installed deps.
    let orphans = if auto_remove {
        find_orphans(&inspect_profile, &remove_hashes).await?
    } else {
        Vec::new()
    };

    remove_hashes.extend(root_hashes_for_installed(&orphans));

    // Step 5: Print removal summary.
    print_removal_summary(&to_remove, &orphans, printer);

    if dry_run {
        if printer.mode() == OutputMode::Json {
            printer.json(&remove_result_json(
                "remove",
                "planned",
                packages,
                auto_remove,
                true,
                &to_remove,
                &orphans,
                None,
            ));
        }
        printer.info("Dry run -- no changes made.");
        return Ok(RemoveOutcome {
            orphan_count: orphans.len(),
        });
    }

    // Step 6: Confirm unless --yes.
    if !yes && !config.settings.assume_yes {
        confirm(printer)?;
    }

    let profile = Profile::open(config.scope)?;

    // Step 7: Create new generation, copying roots except removed ones.
    printer.step(1, 3, "Creating new generation...");
    let new_gen = profile.new_generation()?;
    copy_roots_except(&current_gen, &new_gen, &remove_hashes)?;

    // Step 8: Delete metadata for removed packages.
    for meta in to_remove.iter().chain(orphans.iter()) {
        let hash = store_path_hash(&meta.store_path).to_string();
        delete_meta(&profile, &hash)?;
    }
    snapshot_profile_meta_to_generation(&profile, &new_gen)?;
    let future_installed = list_meta(&profile)?;
    rebuild_generation_expose_roots(&new_gen, &future_installed)?;
    rebuild_generation_expose_image_roots(&new_gen, &future_installed)?;
    validate_generation_exposed_units(&new_gen, &future_installed)?;

    // Step 9: Rebuild FHS tree on the new generation.
    printer.step(2, 3, "Rebuilding file tree...");
    build_generation_fhs_tree(&new_gen, printer)?;

    // Step 10: Switch to the new generation.
    profile.switch_to(&new_gen)?;
    if reconcile_exposed_units {
        reconcile_system_profile(config, printer).await?;
    }

    // Step 11: Report success.
    printer.step(3, 3, "Done!");
    let total_removed = to_remove.len() + orphans.len();
    printer.success(&format!(
        "Removed {total_removed} package(s) in generation {}.",
        new_gen.number,
    ));
    if printer.mode() == OutputMode::Json {
        printer.json(&remove_result_json(
            "remove",
            "removed",
            packages,
            auto_remove,
            false,
            &to_remove,
            &orphans,
            Some(new_gen.number),
        ));
    }

    Ok(RemoveOutcome {
        orphan_count: orphans.len(),
    })
}

/// Run `apm autoremove`.
///
/// Finds all auto-installed packages (explicit=false) that are no longer
/// needed by any explicit package, and removes them.
///
/// # Errors
///
/// Returns an error if there is no current generation, the user declines
/// the prompt ([`AosError::UserCancelled`]), a live closure query fails, or
/// creating, populating, or switching to the new generation fails.
pub async fn run_autoremove(
    config: &ApmConfig,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<RemoveOutcome> {
    // Step 1: Inspect profile.
    let inspect_profile = Profile::open_readonly(config.scope);
    let current_gen = inspect_profile
        .current_generation()?
        .ok_or_else(|| anyhow::anyhow!("no current generation -- nothing installed"))?;

    // Step 2: Find orphaned packages.
    let empty_exclude: HashSet<String> = HashSet::new();
    let orphans = find_orphans(&inspect_profile, &empty_exclude).await?;

    if orphans.is_empty() {
        if printer.mode() == OutputMode::Json {
            printer.json(&remove_result_json(
                "autoremove",
                "current",
                &[],
                true,
                false,
                &[],
                &[],
                None,
            ));
        }
        printer.info("No orphaned packages to remove.");
        return Ok(RemoveOutcome::default());
    }

    // Step 3: Collect hashes.
    let remove_hashes = root_hashes_for_installed(&orphans);

    // Step 4: Print summary.
    print_removal_summary(&[], &orphans, printer);

    if dry_run {
        if printer.mode() == OutputMode::Json {
            printer.json(&remove_result_json(
                "autoremove",
                "planned",
                &[],
                true,
                true,
                &[],
                &orphans,
                None,
            ));
        }
        printer.info("Dry run -- no changes made.");
        return Ok(RemoveOutcome {
            orphan_count: orphans.len(),
        });
    }

    // Step 5: Confirm.
    if !yes && !config.settings.assume_yes {
        confirm(printer)?;
    }

    let profile = Profile::open(config.scope)?;

    // Step 6: Create new generation without orphans.
    printer.step(1, 3, "Creating new generation...");
    let new_gen = profile.new_generation()?;
    copy_roots_except(&current_gen, &new_gen, &remove_hashes)?;

    // Delete metadata for orphans.
    for meta in &orphans {
        let hash = store_path_hash(&meta.store_path).to_string();
        delete_meta(&profile, &hash)?;
    }
    snapshot_profile_meta_to_generation(&profile, &new_gen)?;
    let future_installed = list_meta(&profile)?;
    rebuild_generation_expose_roots(&new_gen, &future_installed)?;
    rebuild_generation_expose_image_roots(&new_gen, &future_installed)?;
    validate_generation_exposed_units(&new_gen, &future_installed)?;

    // Step 7: Rebuild FHS tree.
    printer.step(2, 3, "Rebuilding file tree...");
    build_generation_fhs_tree(&new_gen, printer)?;

    // Step 8: Switch.
    profile.switch_to(&new_gen)?;
    reconcile_system_profile(config, printer).await?;

    printer.step(3, 3, "Done!");
    printer.success(&format!(
        "Removed {} orphaned package(s) in generation {}.",
        orphans.len(),
        new_gen.number,
    ));
    if printer.mode() == OutputMode::Json {
        printer.json(&remove_result_json(
            "autoremove",
            "removed",
            &[],
            true,
            false,
            &[],
            &orphans,
            Some(new_gen.number),
        ));
    }

    Ok(RemoveOutcome {
        orphan_count: orphans.len(),
    })
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Build the JSON document for `apm remove`/`autoremove` results.
fn remove_result_json(
    action: &str,
    status: &str,
    packages: &[String],
    auto_remove: bool,
    dry_run: bool,
    explicit_removals: &[InstalledMeta],
    orphan_removals: &[InstalledMeta],
    generation: Option<u32>,
) -> serde_json::Value {
    serde_json::json!({
        "action": action,
        "status": status,
        "requested": packages,
        "autoremove": auto_remove,
        "dry_run": dry_run,
        "generation": generation,
        "removed": explicit_removals.len() + orphan_removals.len(),
        "explicit_removed": explicit_removals.len(),
        "orphan_removed": orphan_removals.len(),
        "packages": explicit_removals
            .iter()
            .map(installed_meta_json)
            .collect::<Vec<_>>(),
        "orphans": orphan_removals
            .iter()
            .map(installed_meta_json)
            .collect::<Vec<_>>(),
    })
}

/// Render one installed entry for JSON output, tolerating missing APM
/// metadata.
fn installed_meta_json(meta: &InstalledMeta) -> serde_json::Value {
    let Some(apm) = &meta.apm else {
        return serde_json::json!({
            "store_path": meta.store_path.as_str(),
            "name": null,
            "version": null,
            "registry": null,
            "explicit": null,
            "held": null,
        });
    };

    serde_json::json!({
        "name": apm.name.as_str(),
        "version": apm.version.as_str(),
        "registry": apm.registry.as_str(),
        "store_path": meta.store_path.as_str(),
        "explicit": apm.explicit,
        "held": apm.held,
    })
}

/// Find installed metadata entries matching package names.
///
/// Returns the matching entries. Errors on any name not found in the profile.
fn find_installed(profile: &Profile, names: &[String]) -> Result<Vec<InstalledMeta>> {
    let all = list_meta(profile)?;
    select_installed_for_removal(&all, names)
}

/// Select installed entries that should be removed for requested package names.
///
/// Explicit entries are profile roots the user intentionally installed. If an
/// explicit entry matches a requested name, keep automatic same-name entries out
/// of the requested removal set so another remaining root can still depend on
/// them. If only automatic entries match, preserve the historical behavior and
/// remove those entries directly.
fn select_installed_for_removal(
    installed: &[InstalledMeta],
    names: &[String],
) -> Result<Vec<InstalledMeta>> {
    let mut selected = Vec::new();
    let mut selected_hashes = HashSet::new();

    for name in names {
        let matches: Vec<InstalledMeta> = installed
            .iter()
            .filter(|meta_entry| {
                meta_entry
                    .apm
                    .as_ref()
                    .map(|apm| apm.name == *name)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();

        if matches.is_empty() {
            return Err(AosError::PackageNotFound { name: name.clone() }.into());
        }

        let explicit_matches: Vec<InstalledMeta> = matches
            .iter()
            .filter(|meta_entry| {
                meta_entry
                    .apm
                    .as_ref()
                    .map(|apm| apm.explicit)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        let removals = if explicit_matches.is_empty() {
            matches
        } else {
            explicit_matches
        };

        for meta_entry in removals {
            let hash = store_path_hash(&meta_entry.store_path).to_string();
            if selected_hashes.insert(hash) {
                selected.push(meta_entry);
            }
        }
    }

    Ok(selected)
}

/// Find orphaned auto-installed packages.
///
/// An orphan is a package with `explicit=false` that would not be needed
/// after removing the packages in `pending_remove_hashes`.
async fn find_orphans(
    profile: &Profile,
    pending_remove_hashes: &HashSet<String>,
) -> Result<Vec<InstalledMeta>> {
    let all = list_meta(profile)?;
    let needed_hashes = needed_hashes_for_remaining_explicit(&all, pending_remove_hashes).await?;

    Ok(find_orphans_from_meta(
        &all,
        pending_remove_hashes,
        &needed_hashes,
    ))
}

/// Union of the live closures (`nix-store -qR`) of every explicit package
/// that is not slated for removal — the set of hashes that must stay.
async fn needed_hashes_for_remaining_explicit(
    installed: &[InstalledMeta],
    pending_remove_hashes: &HashSet<String>,
) -> Result<HashSet<String>> {
    let mut needed = HashSet::new();

    for index in retained_installed_indexes(installed, pending_remove_hashes) {
        let meta = &installed[index];
        let Some(apm) = &meta.apm else { continue };
        for path in closure_paths(&meta.store_path)
            .await
            .with_context(|| format!("querying closure for installed package {}", apm.name))?
        {
            needed.insert(store_path_hash(&path).to_string());
        }
    }

    Ok(needed)
}

/// Return non-removed installed entries retained by explicit packages.
///
/// RFC-0001 `expose.requires` names package-level co-install requirements,
/// which are not necessarily visible in a Nix store closure. Autoremove must
/// therefore keep any installed package named by a remaining explicit package,
/// and repeat that walk transitively.
pub(crate) fn retained_installed_indexes(
    installed: &[InstalledMeta],
    pending_remove_hashes: &HashSet<String>,
) -> Vec<usize> {
    let by_name = installed_indexes_by_package_name(installed, pending_remove_hashes);
    let mut retained = Vec::new();
    let mut seen_hashes = HashSet::new();
    let mut queue = VecDeque::new();

    for (index, meta) in installed.iter().enumerate() {
        let hash = store_path_hash(&meta.store_path);
        if pending_remove_hashes.contains(hash) {
            continue;
        }
        if meta.apm.as_ref().is_some_and(|apm| apm.explicit) {
            queue.push_back(index);
        }
    }

    while let Some(index) = queue.pop_front() {
        let meta = &installed[index];
        let hash = store_path_hash(&meta.store_path);
        if !seen_hashes.insert(hash.to_string()) {
            continue;
        }

        retained.push(index);

        let Some(apm) = &meta.apm else { continue };
        let Some(expose) = &apm.expose else { continue };
        for required in &expose.requires {
            if let Some(indexes) = by_name.get(required.as_str()) {
                queue.extend(indexes.iter().copied());
            }
        }
    }

    retained
}

fn installed_indexes_by_package_name<'a>(
    installed: &'a [InstalledMeta],
    pending_remove_hashes: &HashSet<String>,
) -> HashMap<&'a str, Vec<usize>> {
    let mut by_name: HashMap<&'a str, Vec<usize>> = HashMap::new();
    for (index, meta) in installed.iter().enumerate() {
        let hash = store_path_hash(&meta.store_path);
        if pending_remove_hashes.contains(hash) {
            continue;
        }
        if let Some(apm) = &meta.apm {
            by_name.entry(apm.name.as_str()).or_default().push(index);
        }
    }
    by_name
}

/// Select non-explicit entries that are neither already being removed nor
/// in the needed set.
fn find_orphans_from_meta(
    installed: &[InstalledMeta],
    pending_remove_hashes: &HashSet<String>,
    needed_hashes: &HashSet<String>,
) -> Vec<InstalledMeta> {
    installed
        .iter()
        .filter(|m| {
            let hash = store_path_hash(&m.store_path).to_string();
            m.apm.as_ref().map(|apm| !apm.explicit).unwrap_or(false)
                && !pending_remove_hashes.contains(&hash)
                && !needed_hashes.contains(&hash)
        })
        .cloned()
        .collect()
}

/// Collect each entry's store-path hash plus its source derivation's hash
/// (both have GC roots in the generation).
fn root_hashes_for_installed(installed: &[InstalledMeta]) -> HashSet<String> {
    let mut hashes = HashSet::new();
    for meta in installed {
        hashes.insert(store_path_hash(&meta.store_path).to_string());
        if let Some(apm) = &meta.apm {
            if !apm.source_drv.is_empty() {
                hashes.insert(store_path_hash(&apm.source_drv).to_string());
            }
        }
    }
    hashes
}

/// Copy roots from one generation to another, EXCLUDING specific hashes.
///
/// Copies both `usr/` and `src/` symlinks, skipping any entry whose
/// name (hash) is in the `exclude` set.
fn copy_roots_except(
    from: &super::profile::Generation,
    to: &super::profile::Generation,
    exclude: &HashSet<String>,
) -> Result<()> {
    use std::os::unix::fs::symlink;

    // Copy usr/ roots.
    let from_usr = from.path.join("usr");
    let to_usr = to.path.join("usr");
    std::fs::create_dir_all(&to_usr).with_context(|| format!("creating {}", to_usr.display()))?;

    if from_usr.is_dir() {
        for entry in std::fs::read_dir(&from_usr)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if exclude.contains(&name) {
                continue;
            }
            let target = std::fs::read_link(entry.path())?;
            let dest = to_usr.join(entry.file_name());
            if !dest.symlink_metadata().is_ok() {
                symlink(&target, &dest).with_context(|| {
                    format!("copying root {} -> {}", dest.display(), target.display())
                })?;
            }
        }
    }

    // Copy src/ roots.
    let from_src = from.path.join("src");
    let to_src = to.path.join("src");
    std::fs::create_dir_all(&to_src).with_context(|| format!("creating {}", to_src.display()))?;

    if from_src.is_dir() {
        for entry in std::fs::read_dir(&from_src)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if exclude.contains(&name) {
                continue;
            }
            let target = std::fs::read_link(entry.path())?;
            let dest = to_src.join(entry.file_name());
            if !dest.symlink_metadata().is_ok() {
                symlink(&target, &dest).with_context(|| {
                    format!("copying root {} -> {}", dest.display(), target.display())
                })?;
            }
        }
    }

    Ok(())
}

/// Print the removal summary showing what will be removed.
fn print_removal_summary(
    explicit_removals: &[InstalledMeta],
    orphan_removals: &[InstalledMeta],
    printer: &Printer,
) {
    if !explicit_removals.is_empty() {
        printer.header("The following packages will be REMOVED:");
        for meta in explicit_removals {
            if let Some(ref apm) = meta.apm {
                printer.plain(&format!("  {} ({})", apm.name, apm.version));
            }
        }
    }

    if !orphan_removals.is_empty() {
        printer.header("The following packages will be REMOVED (no longer needed):");
        for meta in orphan_removals {
            if let Some(ref apm) = meta.apm {
                printer.plain(&format!("  {} ({})", apm.name, apm.version));
            }
        }
    }

    let total = explicit_removals.len() + orphan_removals.len();
    printer.plain(&format!(
        "0 upgraded, 0 newly installed, {total} to remove.",
    ));
}

/// Prompt for Y/n confirmation.  Returns `Err(UserCancelled)` on "n".
fn confirm(printer: &Printer) -> Result<()> {
    printer.plain("Do you want to continue? [Y/n] ");

    // Flush stderr since the prompt goes there via `plain`.
    let _ = std::io::stderr().flush();

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("reading user input")?;

    let trimmed = input.trim().to_lowercase();
    if trimmed.is_empty() || trimmed == "y" || trimmed == "yes" {
        Ok(())
    } else {
        Err(AosError::UserCancelled.into())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    use crate::profile::Generation;
    use crate::profile::meta::write_meta;
    use crate::types::{ApmMeta, ExposeMeta, ProfileScope};

    fn test_profile(tmp: &TempDir) -> Profile {
        Profile::open_at(tmp.path().to_path_buf(), ProfileScope::User).unwrap()
    }

    fn sample_installed(name: &str, hash: &str, explicit: bool) -> InstalledMeta {
        InstalledMeta {
            store_path: format!("/var/lib/store/{hash}-{name}-1.0"),
            pushed_at: 1707800000,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: Some(ApmMeta {
                name: name.into(),
                version: "1.0".into(),
                explicit,
                registry: "aos-core".into(),
                installed_at: "2026-02-16T00:00:00Z".into(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                expose: None,
                expose_artifact: None,
                config_module: None,
                documentation: None,
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        }
    }

    fn sample_installed_requiring(
        name: &str,
        hash: &str,
        explicit: bool,
        requires: &[&str],
    ) -> InstalledMeta {
        let mut installed = sample_installed(name, hash, explicit);
        installed.apm.as_mut().unwrap().expose = Some(ExposeMeta {
            target: format!("aos-pkg-{name}.target"),
            units: Vec::new(),
            images: Vec::new(),
            requires: requires.iter().map(|name| (*name).to_string()).collect(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        });
        installed
    }

    fn sample_installed_from_registry(
        name: &str,
        hash: &str,
        registry: &str,
        explicit: bool,
    ) -> InstalledMeta {
        let mut installed = sample_installed(name, hash, explicit);
        installed.apm.as_mut().unwrap().registry = registry.into();
        installed
    }

    // 1. find_installed finds matching packages
    #[test]
    fn find_installed_finds_matching() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        write_meta(
            &profile,
            "abc123",
            &sample_installed("curl", "abc123", true),
        )
        .unwrap();
        write_meta(
            &profile,
            "def456",
            &sample_installed("zlib", "def456", false),
        )
        .unwrap();
        write_meta(&profile, "ghi789", &sample_installed("jq", "ghi789", true)).unwrap();

        let found = find_installed(&profile, &["curl".into(), "jq".into()]).unwrap();
        assert_eq!(found.len(), 2);

        let names: HashSet<String> = found
            .iter()
            .filter_map(|m| m.apm.as_ref().map(|a| a.name.clone()))
            .collect();
        assert!(names.contains("curl"));
        assert!(names.contains("jq"));
    }

    // 2. find_installed returns error for unknown package
    #[test]
    fn find_installed_error_for_unknown() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        write_meta(
            &profile,
            "abc123",
            &sample_installed("curl", "abc123", true),
        )
        .unwrap();

        let result = find_installed(&profile, &["nonexistent".into()]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nonexistent"), "error was: {err}");
    }

    #[test]
    fn select_installed_for_removal_prefers_explicit_duplicate_name() {
        let installed = vec![
            sample_installed_from_registry("priority-client", "aaa111", "low-priority", true),
            sample_installed_from_registry("priority-tool", "bbb222", "low-priority", false),
            sample_installed_from_registry("priority-tool", "ccc333", "high-priority", true),
        ];

        let selected = select_installed_for_removal(&installed, &["priority-tool".into()]).unwrap();

        assert_eq!(selected.len(), 1);
        let apm = selected[0].apm.as_ref().unwrap();
        assert_eq!(apm.name, "priority-tool");
        assert_eq!(apm.registry, "high-priority");
        assert!(apm.explicit);
    }

    #[test]
    fn select_installed_for_removal_keeps_implicit_only_behavior() {
        let installed = vec![sample_installed_from_registry(
            "priority-tool",
            "bbb222",
            "low-priority",
            false,
        )];

        let selected = select_installed_for_removal(&installed, &["priority-tool".into()]).unwrap();

        assert_eq!(selected.len(), 1);
        let apm = selected[0].apm.as_ref().unwrap();
        assert_eq!(apm.registry, "low-priority");
        assert!(!apm.explicit);
    }

    // 3. find_orphans returns auto-installed packages
    #[test]
    fn find_orphans_returns_auto_installed() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        write_meta(
            &profile,
            "abc123",
            &sample_installed("curl", "abc123", true),
        )
        .unwrap();
        write_meta(
            &profile,
            "def456",
            &sample_installed("zlib", "def456", false),
        )
        .unwrap();
        write_meta(
            &profile,
            "ghi789",
            &sample_installed("openssl", "ghi789", false),
        )
        .unwrap();

        let empty: HashSet<String> = HashSet::new();
        let needed: HashSet<String> = HashSet::new();
        let installed = list_meta(&profile).unwrap();
        let orphans = find_orphans_from_meta(&installed, &empty, &needed);
        assert_eq!(orphans.len(), 2);

        let names: HashSet<String> = orphans
            .iter()
            .filter_map(|m| m.apm.as_ref().map(|a| a.name.clone()))
            .collect();
        assert!(names.contains("zlib"));
        assert!(names.contains("openssl"));
    }

    // 4. find_orphans doesn't return explicit packages
    #[test]
    fn find_orphans_excludes_explicit() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        write_meta(
            &profile,
            "abc123",
            &sample_installed("curl", "abc123", true),
        )
        .unwrap();
        write_meta(&profile, "def456", &sample_installed("jq", "def456", true)).unwrap();

        let empty: HashSet<String> = HashSet::new();
        let needed: HashSet<String> = HashSet::new();
        let installed = list_meta(&profile).unwrap();
        let orphans = find_orphans_from_meta(&installed, &empty, &needed);
        assert!(orphans.is_empty());
    }

    // 5. copy_roots_except copies all but excluded hashes
    #[test]
    fn copy_roots_except_excludes_correctly() {
        let tmp = TempDir::new().unwrap();

        // Set up "from" generation with two usr roots.
        let from_path = tmp.path().join("gen-1");
        let from_usr = from_path.join("usr");
        fs::create_dir_all(&from_usr).unwrap();
        symlink("/var/lib/store/abc123-curl-1.0", from_usr.join("abc123")).unwrap();
        symlink("/var/lib/store/def456-zlib-1.0", from_usr.join("def456")).unwrap();

        let from_gen = Generation {
            number: 1,
            path: from_path,
        };

        let to_path = tmp.path().join("gen-2");
        fs::create_dir_all(&to_path).unwrap();
        let to_gen = Generation {
            number: 2,
            path: to_path.clone(),
        };

        // Exclude abc123 (curl).
        let mut exclude = HashSet::new();
        exclude.insert("abc123".to_string());

        copy_roots_except(&from_gen, &to_gen, &exclude).unwrap();

        // def456 should be copied, abc123 should NOT.
        assert!(to_path.join("usr/def456").symlink_metadata().is_ok());
        assert!(to_path.join("usr/abc123").symlink_metadata().is_err());
    }

    // 6. copy_roots_except with empty exclusion copies all
    #[test]
    fn copy_roots_except_empty_exclusion_copies_all() {
        let tmp = TempDir::new().unwrap();

        let from_path = tmp.path().join("gen-1");
        let from_usr = from_path.join("usr");
        fs::create_dir_all(&from_usr).unwrap();
        symlink("/var/lib/store/abc123-curl-1.0", from_usr.join("abc123")).unwrap();
        symlink("/var/lib/store/def456-zlib-1.0", from_usr.join("def456")).unwrap();

        let from_gen = Generation {
            number: 1,
            path: from_path,
        };

        let to_path = tmp.path().join("gen-2");
        fs::create_dir_all(&to_path).unwrap();
        let to_gen = Generation {
            number: 2,
            path: to_path.clone(),
        };

        let exclude: HashSet<String> = HashSet::new();
        copy_roots_except(&from_gen, &to_gen, &exclude).unwrap();

        assert!(to_path.join("usr/abc123").symlink_metadata().is_ok());
        assert!(to_path.join("usr/def456").symlink_metadata().is_ok());
    }

    // 7. Removal summary format is correct
    #[test]
    fn removal_summary_format() {
        let removals = vec![sample_installed("curl", "abc123", true)];
        let orphans = vec![sample_installed("zlib", "def456", false)];

        // Just verify it doesn't panic. The output goes to stderr via Printer.
        let printer = Printer::new(0, true, false);
        print_removal_summary(&removals, &orphans, &printer);
    }

    // 8. find_installed with empty profile returns not-found error
    #[test]
    fn find_installed_empty_profile_errors() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let result = find_installed(&profile, &["curl".into()]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("curl"), "error was: {err}");
    }

    // 9. find_orphans excludes packages already pending removal
    #[test]
    fn find_orphans_excludes_pending_removal() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        write_meta(
            &profile,
            "abc123",
            &sample_installed("curl", "abc123", true),
        )
        .unwrap();
        write_meta(
            &profile,
            "def456",
            &sample_installed("zlib", "def456", false),
        )
        .unwrap();
        write_meta(
            &profile,
            "ghi789",
            &sample_installed("openssl", "ghi789", false),
        )
        .unwrap();

        // Pretend zlib is already being removed.
        let mut pending: HashSet<String> = HashSet::new();
        pending.insert("def456".to_string());

        let needed: HashSet<String> = HashSet::new();
        let installed = list_meta(&profile).unwrap();
        let orphans = find_orphans_from_meta(&installed, &pending, &needed);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].apm.as_ref().unwrap().name, "openssl");
    }

    #[test]
    fn find_orphans_keeps_auto_dep_needed_by_remaining_explicit() {
        let installed = vec![
            sample_installed("left", "aaa111", true),
            sample_installed("right", "bbb222", true),
            sample_installed("shared", "ccc333", false),
        ];
        let pending: HashSet<String> = ["aaa111".to_string()].into_iter().collect();
        let needed: HashSet<String> = ["bbb222".to_string(), "ccc333".to_string()]
            .into_iter()
            .collect();

        let orphans = find_orphans_from_meta(&installed, &pending, &needed);

        assert!(orphans.is_empty());
    }

    #[test]
    fn find_orphans_removes_auto_dep_when_no_remaining_explicit_needs_it() {
        let installed = vec![
            sample_installed("left", "aaa111", true),
            sample_installed("shared", "ccc333", false),
        ];
        let pending: HashSet<String> = ["aaa111".to_string()].into_iter().collect();
        let needed: HashSet<String> = HashSet::new();

        let orphans = find_orphans_from_meta(&installed, &pending, &needed);

        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].apm.as_ref().unwrap().name, "shared");
    }

    #[test]
    fn retained_installed_indexes_keep_name_level_requirements() {
        let installed = vec![
            sample_installed_requiring("client", "aaa111", true, &["provider"]),
            sample_installed("provider", "bbb222", false),
            sample_installed("unused", "ccc333", false),
        ];
        let pending = HashSet::new();

        let retained = retained_installed_indexes(&installed, &pending);

        let names: HashSet<_> = retained
            .iter()
            .filter_map(|index| installed[*index].apm.as_ref().map(|apm| apm.name.as_str()))
            .collect();
        assert!(names.contains("client"));
        assert!(names.contains("provider"));
        assert!(!names.contains("unused"));
    }

    #[test]
    fn retained_installed_indexes_follow_transitive_name_requirements() {
        let installed = vec![
            sample_installed_requiring("client", "aaa111", true, &["proxy"]),
            sample_installed_requiring("proxy", "bbb222", false, &["provider"]),
            sample_installed("provider", "ccc333", false),
        ];
        let pending = HashSet::new();

        let retained = retained_installed_indexes(&installed, &pending);

        let names: HashSet<_> = retained
            .iter()
            .filter_map(|index| installed[*index].apm.as_ref().map(|apm| apm.name.as_str()))
            .collect();
        assert_eq!(names.len(), 3);
        assert!(names.contains("client"));
        assert!(names.contains("proxy"));
        assert!(names.contains("provider"));
    }

    #[test]
    fn root_hashes_for_installed_includes_source_roots() {
        let mut installed = sample_installed("sourceful", "aaa111", true);
        installed.apm.as_mut().unwrap().source_drv =
            "/var/lib/store/src222-sourceful-src.drv".to_string();

        let hashes = root_hashes_for_installed(&[installed]);

        assert!(hashes.contains("aaa111"));
        assert!(hashes.contains("src222"));
    }

    // 10. copy_roots_except also handles src/ roots
    #[test]
    fn copy_roots_except_handles_src() {
        let tmp = TempDir::new().unwrap();

        let from_path = tmp.path().join("gen-1");
        let from_usr = from_path.join("usr");
        let from_src = from_path.join("src");
        fs::create_dir_all(&from_usr).unwrap();
        fs::create_dir_all(&from_src).unwrap();
        symlink("/var/lib/store/abc123-curl-1.0", from_usr.join("abc123")).unwrap();
        symlink(
            "/var/lib/store/src111-curl-1.0.drv",
            from_src.join("src111"),
        )
        .unwrap();
        symlink("/var/lib/store/def456-zlib-1.0", from_usr.join("def456")).unwrap();
        symlink(
            "/var/lib/store/src222-zlib-1.0.drv",
            from_src.join("src222"),
        )
        .unwrap();

        let from_gen = Generation {
            number: 1,
            path: from_path,
        };

        let to_path = tmp.path().join("gen-2");
        fs::create_dir_all(&to_path).unwrap();
        let to_gen = Generation {
            number: 2,
            path: to_path.clone(),
        };

        // Exclude abc123 and its src hash.
        let mut exclude = HashSet::new();
        exclude.insert("abc123".to_string());
        exclude.insert("src111".to_string());

        copy_roots_except(&from_gen, &to_gen, &exclude).unwrap();

        // curl should be excluded from both usr and src.
        assert!(to_path.join("usr/abc123").symlink_metadata().is_err());
        assert!(to_path.join("src/src111").symlink_metadata().is_err());

        // zlib should be copied.
        assert!(to_path.join("usr/def456").symlink_metadata().is_ok());
        assert!(to_path.join("src/src222").symlink_metadata().is_ok());
    }
}
