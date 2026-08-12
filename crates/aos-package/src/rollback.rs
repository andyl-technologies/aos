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
use super::exposed_units::{rebuild_generation_expose_roots, reconcile_system_profile};
use super::profile::Profile;
use super::profile::meta::{self, list_meta};
use super::registry::RegistrySet;
use super::types::{ConfigGeneration, ProfileScope, ReactivationPlan};
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
        if let Some(count) = system_generation_hint(config) {
            printer.info(&format!(
                "{count} system generation{} available; did you mean `apm rollback --system --list`?",
                if count == 1 { "" } else { "s" },
            ));
        }
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
        None => match system_generation_hint(config) {
            Some(count) => bail!(
                "no active generation to roll back from ({count} system generation{} available; \
                 did you mean `apm rollback --system`?)",
                if count == 1 { "" } else { "s" },
            ),
            None => bail!("no active generation to roll back from"),
        },
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
    let restored_installed = list_meta(&profile)?;
    rebuild_generation_expose_roots(target, &restored_installed)?;
    reconcile_system_profile(config, printer).await?;

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

/// Number of system generations to surface as a `--system` hint, or `None`.
///
/// The package-profile rollback path operates on the per-user profile
/// selected by the absence of `--system` ([`ProfileScope::User`]). When that
/// profile is empty, operators frequently meant to roll back the *system*
/// profile instead. This returns the count of recorded system generations so
/// the caller can nudge toward `apm rollback --system` — but only when the
/// current scope is the implicit user default and at least one system
/// generation exists. Returns `None` for an explicit system scope, an empty
/// or unreadable system state file, so the hint never fires spuriously.
fn system_generation_hint(config: &ApmConfig) -> Option<usize> {
    if config.scope != ProfileScope::User {
        return None;
    }
    let system_path = ProfileScope::System.profile_path();
    let state = crate::sysroot::load_generation_state_pub(&system_path).ok()?;
    let count = state.generations.len();
    (count > 0).then_some(count)
}

// ---------------------------------------------------------------------------
// Cross-ABI configuration-generation rollback.
// ---------------------------------------------------------------------------

/// Decide how a config-generation may be re-activated under the running image's
/// shared-option ABI according to the generation pin.
///
/// This is the rollback-side entrypoint to [`ConfigGeneration::reactivation_plan`]:
/// it compares the target generation's `module_abi_pinned` against the running
/// image's `running_image_abi` and returns the action required —
/// [`ReactivationPlan::DirectReactivate`] for any generation with the same ABI,
/// or [`ReactivationPlan::CrossAbiReEval`] carrying the
/// retained inputs the running image's evaluator must replay.
///
/// A `DirectReactivate` plan is the existing cheap path: a pure
/// `Profile::switch_to` + `activate <N>` pointer switch over the retained `cfg/`
/// outputs, no eval, no reboot. A `CrossAbiReEval` plan must be executed via
/// [`execute_cross_abi_reeval`] before the generation can be committed.
///
/// # Errors
///
/// Returns an error when the target requires cross-ABI re-eval but a retained
/// input (`config_module_closure`, `host_nix_ref`, or `facts_hash`) is missing
/// from its record — a fail-closed signal that the generation cannot be safely
/// recomputed.
pub fn plan_config_gen_reactivation(
    target: &ConfigGeneration,
    _running_image: u32,
    running_image_abi: u32,
) -> Result<ReactivationPlan> {
    target.reactivation_plan(running_image_abi)
}

/// Execute the cross-ABI re-eval branch of a config-generation rollback
/// by reusing the configuration fixpoint driver.
///
/// Given a [`ReactivationPlan::CrossAbiReEval`]'s retained inputs, this feeds the
/// content-pinned `host.nix` and the rolled-back image's `running_base_lib` into
/// [`crate::config_eval::reeval_cross_abi`], which drives the existing on-host
/// fixpoint to a fresh manifest pinned to the running image's ABI. The §3
/// pre-eval ABI gate still fires inside the fixpoint, so an incompatible config
/// module is refused fail-closed and the old config-gen stays live.
///
/// `source_manifest` is the immutable manifest retained by the selected
/// generation. `eval_root` and `out` select ephemeral re-evaluation outputs.
///
/// # Errors
///
/// Returns an error when the re-eval reaches a terminal state (no manifest is
/// then written, so nothing downstream activates) or its inputs cannot be read.
pub fn execute_cross_abi_reeval(
    inputs: &crate::types::CrossAbiReEvalInputs,
    running_base_lib: &std::path::Path,
    source_manifest: &std::path::Path,
    eval_root: PathBuf,
    out: PathBuf,
    verbose: u8,
) -> Result<()> {
    crate::config_eval::reeval_cross_abi(
        inputs,
        running_base_lib,
        source_manifest,
        eval_root,
        out,
        verbose,
    )
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
    use crate::types::{ConfigGeneration, ProfileScope, ReactivationPlan};
    use tempfile::TempDir;

    fn test_profile(tmp: &TempDir) -> Profile {
        Profile::open_at(tmp.path().to_path_buf(), ProfileScope::User).unwrap()
    }

    /// Builds a configuration-generation record with the supplied axis metadata.
    fn config_gen(number: u32, module_abi_pinned: u32, with_inputs: bool) -> ConfigGeneration {
        ConfigGeneration {
            number,
            created_at: "2026-06-01T00:00:00Z".into(),
            image_gen_parent: 1,
            module_abi_pinned,
            manifest_hash: "sha256:beef".into(),
            config_module_closure: if with_inputs {
                "/nix/store/src0-cfg".to_string()
            } else {
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string()
            },
            config_module_paths: if with_inputs {
                vec!["/nix/store/src0-cfg".to_string()]
            } else {
                vec![]
            },
            config_module_packages: if with_inputs {
                vec!["server".to_string()]
            } else {
                vec![]
            },
            host_nix_ref: "/nix/store/hn0-host.nix".to_string(),
            host_nix_commit: None,
            facts_hash: "sha256:facts".to_string(),
            facts_ref: "/nix/store/fa0-facts.json".to_string(),
            base_lib_ref: "/nix/store/bl0-base-lib".to_string(),
            evaluator_ref: "/nix/store/ev0-evaluator".to_string(),
        }
    }

    // A cross-ABI generation with unauthenticated module identity fails closed.
    #[test]
    fn reactivation_cross_abi_with_mismatched_module_identity_is_rejected() {
        let mut target = config_gen(3, 1, true);
        target.config_module_packages.clear();
        let error = super::plan_config_gen_reactivation(&target, 1, 2).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("authenticated package identities")
        );
    }

    // A host-only configuration has a legitimate empty module closure.
    #[test]
    fn reactivation_cross_abi_accepts_host_only_inputs() {
        let target = config_gen(3, 1, false);
        let plan = super::plan_config_gen_reactivation(&target, 1, 2).unwrap();
        let ReactivationPlan::CrossAbiReEval(inputs) = plan else {
            panic!("cross-ABI host-only reactivation must re-evaluate");
        };
        assert!(inputs.config_module_paths.is_empty());
        assert!(inputs.config_module_packages.is_empty());
    }

    // The same ABI permits direct pointer-switch reactivation across images.
    #[test]
    fn reactivation_same_abi_is_direct() {
        let target = config_gen(3, 2, true);
        let plan = super::plan_config_gen_reactivation(&target, 99, 2).unwrap();
        assert_eq!(plan, ReactivationPlan::DirectReactivate);
    }

    // A different ABI requires reevaluation over the retained inputs.
    #[test]
    fn reactivation_cross_abi_returns_retained_inputs() {
        let target = config_gen(3, 1, true);
        let plan = super::plan_config_gen_reactivation(&target, 1, 2).unwrap();
        match plan {
            ReactivationPlan::CrossAbiReEval(inputs) => {
                assert_eq!(inputs.from_module_abi, 1);
                assert_eq!(inputs.to_module_abi, 2);
                assert_eq!(inputs.config_module_paths, ["/nix/store/src0-cfg"]);
                assert_eq!(inputs.host_nix_ref, "/nix/store/hn0-host.nix");
                assert_eq!(inputs.facts_hash, "sha256:facts");
                assert_eq!(inputs.facts_ref, "/nix/store/fa0-facts.json");
            }
            other => panic!("expected CrossAbiReEval, got {other:?}"),
        }
    }

    // A cross-ABI generation with unauthenticated retained inputs fails closed.
    #[test]
    fn reactivation_cross_abi_mismatched_input_identity_errors() {
        let mut target = config_gen(3, 1, true);
        target.config_module_paths.clear();
        assert!(super::plan_config_gen_reactivation(&target, 1, 2).is_err());
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
