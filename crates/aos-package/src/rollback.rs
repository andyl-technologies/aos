//! `apm rollback` and `apm generations` — switch between profile generations.
//!
//! Every mutating apm command creates a new profile generation (a directory
//! of symlinks to package store paths, see [`crate::profile`]). Rollback is
//! therefore pure pointer surgery: it repoints the `current` symlink at an
//! older generation and rebuilds the per-package metadata from that
//! generation's roots — no downloads, no store mutations, and the abandoned
//! generation remains available for rolling forward again.
//!
//! Generation roots are resolved against the enabled registry caches where
//! possible so listings show `name version [registry]` instead of bare
//! store paths.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{Result, bail};

use super::config::ApmConfig;
use super::profile::Profile;
use super::profile::meta;
use super::registry::RegistrySet;
use aos_core::output::{OutputMode, Printer};

/// List user package profile generations.
///
/// The listing resolves generation roots through the enabled registry caches
/// when possible so operators can choose rollback targets by package version
/// rather than only by generation number.
///
/// # Errors
///
/// Returns an error if the profile's generations or their root symlinks
/// cannot be read, or if a registry cache fails to load.
pub async fn list(config: &ApmConfig, printer: &Printer) -> Result<()> {
    let profile = Profile::open_readonly(config.scope);
    let generations = profile.list_generations()?;
    let current = profile.current_generation()?.map(|g| g.number);
    let reg_configs = config.enabled_registries();
    let registries = RegistrySet::load(&config.cache_path(), &reg_configs, "x86_64-linux")?;

    if printer.mode() == OutputMode::Json {
        let mut json_generations = Vec::new();
        for generation in &generations {
            let roots = generation.roots()?;
            let mut json_roots = Vec::new();
            for (hash, target) in &roots {
                let mut package = None;
                let mut registry_name = None;
                for registry in registries.registries() {
                    if let Some(meta) = registry.get_by_hash(hash) {
                        package = Some(serde_json::json!({
                            "name": meta.name,
                            "version": meta.version,
                        }));
                        registry_name = Some(registry.config.name.clone());
                        break;
                    }
                }

                json_roots.push(serde_json::json!({
                    "hash": hash,
                    "store_path": target.to_string_lossy(),
                    "registry": registry_name,
                    "package": package,
                }));
            }

            json_generations.push(serde_json::json!({
                    "generation": generation.number,
                    "current": Some(generation.number) == current,
                    "roots": json_roots,
            }));
        }
        printer.json(&serde_json::json!(json_generations));
        return Ok(());
    }

    if generations.is_empty() {
        printer.info("No profile generations.");
        return Ok(());
    }

    printer.header("Profile generations:");
    for generation in &generations {
        let marker = if Some(generation.number) == current {
            " (current)"
        } else {
            ""
        };
        let roots = generation.roots()?;
        if roots.is_empty() {
            printer.plain(&format!("  gen-{}: (empty){marker}", generation.number));
            continue;
        }

        let descriptions: Vec<String> = roots
            .iter()
            .map(|(hash, target)| describe_root(&registries, hash, target))
            .collect();
        printer.plain(&format!(
            "  gen-{}: {}{}",
            generation.number,
            descriptions.join(", "),
            marker,
        ));
    }

    Ok(())
}

/// Run `apm rollback [--generation=N]`.
///
/// Rollback is instantaneous -- no downloads, no store mutations.
/// It switches the `current` symlink to a previous generation and
/// rebuilds metadata from that generation's roots.
///
/// Without `--generation`, the target is the highest-numbered generation
/// below the current one. With `dry_run`, the planned switch is reported
/// but nothing is changed.
///
/// # Errors
///
/// Returns an error if there is no active generation to roll back from, the
/// requested generation does not exist, no previous generation is available,
/// the profile cannot be opened for writing, or the generation switch /
/// metadata rebuild fails.
pub async fn run(
    config: &ApmConfig,
    generation: Option<u32>,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    let json_mode = printer.mode() == OutputMode::Json;
    let inspect_profile = Profile::open_readonly(config.scope);

    // Must have a current generation to roll back from.
    let current = match inspect_profile.current_generation()? {
        Some(g) => g,
        None => bail!("no active generation to roll back from"),
    };

    let all_gens = inspect_profile.list_generations()?;

    // Determine target generation.
    let target = if let Some(n) = generation {
        // Explicit generation number.
        match all_gens.iter().find(|g| g.number == n) {
            Some(g) => g,
            None => bail!("generation {n} not found"),
        }
    } else {
        // Find the highest-numbered generation below the current one.
        match all_gens.iter().rev().find(|g| g.number < current.number) {
            Some(g) => g,
            None => bail!("no previous generation to roll back to"),
        }
    };

    // Show what we are about to do.
    if !json_mode {
        printer.info(&format!(
            "Rolling back from generation {} to generation {}.",
            current.number, target.number
        ));
    }

    // Optionally show package differences.
    let current_roots = current.roots()?;
    let target_roots = target.roots()?;

    let current_hashes: HashSet<&str> = current_roots.iter().map(|(h, _)| h.as_str()).collect();
    let target_hashes: HashSet<&str> = target_roots.iter().map(|(h, _)| h.as_str()).collect();

    let added: Vec<_> = target_hashes.difference(&current_hashes).copied().collect();
    let removed: Vec<_> = current_hashes.difference(&target_hashes).copied().collect();
    let current_by_hash = roots_by_hash(&current_roots);
    let target_by_hash = roots_by_hash(&target_roots);

    if json_mode {
        if dry_run {
            let registries = load_registries(config)?;
            printer.json(&rollback_result_json(
                "planned",
                generation,
                current.number,
                target.number,
                dry_run,
                None,
                &added,
                &removed,
                &target_by_hash,
                &current_by_hash,
                &current_roots,
                &target_roots,
                &registries,
            ));
            return Ok(());
        }
    }

    if printer.mode() != OutputMode::Json && (!added.is_empty() || !removed.is_empty()) {
        if !added.is_empty() {
            printer.plain(&format!("  Restoring {} path(s).", added.len()));
        }
        if !removed.is_empty() {
            printer.plain(&format!("  Removing {} path(s).", removed.len()));
        }
    }

    if dry_run {
        printer.info("Dry run: no changes made.");
        return Ok(());
    }

    let profile = Profile::open(config.scope)?;
    let registries = load_registries(config)?;

    // Switch to the target generation.
    profile.switch_to(target)?;

    // Rebuild metadata from the target generation's roots.
    meta::rebuild_meta(&profile, target, &registries)?;

    if json_mode {
        printer.json(&rollback_result_json(
            "rolled_back",
            generation,
            current.number,
            target.number,
            dry_run,
            Some(target.number),
            &added,
            &removed,
            &target_by_hash,
            &current_by_hash,
            &current_roots,
            &target_roots,
            &registries,
        ));
    } else {
        printer.success(&format!("Rolled back to generation {}.", target.number));
    }

    Ok(())
}

/// Build the JSON document emitted for `apm rollback` (planned or applied).
fn rollback_result_json(
    status: &str,
    requested_generation: Option<u32>,
    from_generation: u32,
    to_generation: u32,
    dry_run: bool,
    generation: Option<u32>,
    restored: &[&str],
    removed: &[&str],
    restored_roots: &HashMap<&str, &PathBuf>,
    removed_roots: &HashMap<&str, &PathBuf>,
    current_roots: &[(String, PathBuf)],
    target_roots: &[(String, PathBuf)],
    registries: &RegistrySet,
) -> serde_json::Value {
    serde_json::json!({
        "action": "rollback",
        "status": status,
        "requested_generation": requested_generation,
        "from_generation": from_generation,
        "to_generation": to_generation,
        "dry_run": dry_run,
        "generation": generation,
        "restored": roots_json(restored, restored_roots, registries),
        "removed": roots_json(removed, removed_roots, registries),
        "current_roots": all_roots_json(current_roots, registries),
        "target_roots": all_roots_json(target_roots, registries),
    })
}

/// Index generation roots by their store-path hash.
fn roots_by_hash(roots: &[(String, PathBuf)]) -> HashMap<&str, &PathBuf> {
    roots
        .iter()
        .map(|(hash, path)| (hash.as_str(), path))
        .collect()
}

/// Render a subset of roots (selected by hash) as sorted JSON entries.
fn roots_json(
    hashes: &[&str],
    roots: &HashMap<&str, &PathBuf>,
    registries: &RegistrySet,
) -> Vec<serde_json::Value> {
    let mut sorted = hashes.to_vec();
    sorted.sort_unstable();
    sorted
        .iter()
        .filter_map(|hash| {
            roots
                .get(*hash)
                .map(|path| root_json(hash, path, registries))
        })
        .collect()
}

/// Render every root of a generation as JSON entries sorted by hash.
fn all_roots_json(roots: &[(String, PathBuf)], registries: &RegistrySet) -> Vec<serde_json::Value> {
    let mut entries = roots
        .iter()
        .map(|(hash, path)| root_json(hash, path, registries))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        let left_hash = left
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let right_hash = right
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        left_hash.cmp(right_hash)
    });
    entries
}

/// Render one root as JSON, attaching package name/version/registry when the
/// hash is known to an enabled registry cache.
fn root_json(hash: &str, path: &PathBuf, registries: &RegistrySet) -> serde_json::Value {
    for registry in registries.registries() {
        if let Some(package) = registry.get_by_hash(hash) {
            return serde_json::json!({
                "hash": hash,
                "store_path": path.to_string_lossy(),
                "registry": registry.config.name.as_str(),
                "package": {
                    "name": package.name.as_str(),
                    "version": package.version.as_str(),
                },
            });
        }
    }

    serde_json::json!({
        "hash": hash,
        "store_path": path.to_string_lossy(),
        "registry": null,
        "package": null,
    })
}

/// Load the enabled registries' caches for root resolution.
fn load_registries(config: &ApmConfig) -> Result<RegistrySet> {
    let reg_configs = config.enabled_registries();
    RegistrySet::load(&config.cache_path(), &reg_configs, "x86_64-linux")
}

/// Human description of a root: `name version [registry]` when resolvable,
/// otherwise the raw store path.
fn describe_root(registries: &RegistrySet, hash: &str, target: &std::path::Path) -> String {
    for registry in registries.registries() {
        if let Some(pkg) = registry.get_by_hash(hash) {
            return format!("{} {} [{}]", pkg.name, pkg.version, registry.config.name);
        }
    }

    target.display().to_string()
}

#[cfg(test)]
mod tests {
    use crate::profile::Profile;
    use crate::types::ProfileScope;
    use tempfile::TempDir;

    fn test_profile(tmp: &TempDir) -> Profile {
        Profile::open_at(tmp.path().to_path_buf(), ProfileScope::User).unwrap()
    }

    #[tokio::test]
    async fn rollback_switches_to_previous_generation() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let g1 = profile.new_generation().unwrap();
        let g2 = profile.new_generation().unwrap();
        profile.switch_to(&g2).unwrap();

        // Verify current is gen-2.
        assert_eq!(profile.current_generation().unwrap().unwrap().number, 2);

        // Rollback should switch to gen-1 (the previous).
        // We cannot use run() directly because it calls Profile::open() which
        // uses the system path. Instead, test the logic manually.
        let all_gens = profile.list_generations().unwrap();
        let current = profile.current_generation().unwrap().unwrap();
        let target = all_gens
            .iter()
            .rev()
            .find(|g| g.number < current.number)
            .unwrap();
        assert_eq!(target.number, g1.number);

        profile.switch_to(target).unwrap();
        assert_eq!(profile.current_generation().unwrap().unwrap().number, 1);
    }

    #[tokio::test]
    async fn rollback_to_specific_generation() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let _g1 = profile.new_generation().unwrap();
        let _g2 = profile.new_generation().unwrap();
        let g3 = profile.new_generation().unwrap();
        profile.switch_to(&g3).unwrap();

        // Roll back to generation 1 specifically.
        let all_gens = profile.list_generations().unwrap();
        let target = all_gens.iter().find(|g| g.number == 1).unwrap();
        profile.switch_to(target).unwrap();

        assert_eq!(profile.current_generation().unwrap().unwrap().number, 1);
    }

    #[tokio::test]
    async fn rollback_no_previous_generation_errors() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let g1 = profile.new_generation().unwrap();
        profile.switch_to(&g1).unwrap();

        // Only one generation exists; no previous generation available.
        let all_gens = profile.list_generations().unwrap();
        let current = profile.current_generation().unwrap().unwrap();
        let target = all_gens.iter().rev().find(|g| g.number < current.number);
        assert!(target.is_none(), "expected no previous generation");
    }

    #[tokio::test]
    async fn rollback_no_current_generation_errors() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        // No switch_to has been called, so current_generation is None.
        assert!(profile.current_generation().unwrap().is_none());
    }
}
