//! `apm upgrade` — move installed packages to their registry candidates.
//!
//! A package is *upgradable* when it was explicitly installed via apm and
//! its source registry now offers the same name at a different store-path
//! hash (a new version or a rebuild). Held packages and `--exclude`d names
//! are reported as held back instead of upgraded.
//!
//! The upgrade itself follows the same pipeline as install: resolve the new
//! closures, enforce the sysroot lock, download/verify/import only the
//! missing NARs, then create a new profile generation that carries forward
//! the untouched roots, drops roots made obsolete by the upgrade (those not
//! needed by any remaining package's closure), adds the new GC roots,
//! rewrites the package metadata, rebuilds the merged FHS tree, and switches
//! atomically. The previous generation remains intact for `apm rollback`.

use std::collections::{HashMap, HashSet};
use std::io::Write;

use anyhow::{Context, Result};

use super::config::ApmConfig;
use super::download::{
    DownloadRequest, ResolvedDownload, default_engine, download_nars, fetch_narinfo_closure,
    resolve_mirror_chain, resolved_downloads_json, split_mirror_chain,
};
use super::exposed_units::{
    rebuild_generation_expose_image_roots, rebuild_generation_expose_roots,
    reconcile_system_profile, validate_generation_exposed_units,
};
use super::policy::admit_package_roots;
use super::profile::Profile;
use super::profile::merge::build_generation_fhs_tree;
use super::profile::meta::{
    delete_meta, list_meta, snapshot_profile_meta_to_generation, write_meta,
};
use super::registry::{RegistrySet, store_path_hash};
use super::remove::retained_installed_indexes;
use super::resolve::resolve_multiple;
use super::store::{closure_paths, create_gc_roots, filter_missing, import_nar};
use super::sysroot_lock::{self, IgnoreSysrootLock};
use super::types::{ApmMeta, ExposeMeta, InstalledMeta, PackageMeta, SysrootImageEntry};
use super::verify::{verify_downloads, verify_nar_hash};
use aos_core::error::AosError;
use aos_core::output::{OutputMode, Printer};

#[derive(Debug, Clone, PartialEq, Eq)]
struct SecondaryArtifactDownload {
    registry_name: String,
    store_path: String,
    nar_hash: String,
    trust_graph_root: bool,
    requires_empty_references: bool,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// An upgrade candidate: a package with newer root or expose-artifact metadata.
pub struct UpgradeCandidate {
    /// Package name.
    pub name: String,
    /// Currently installed version.
    pub old_version: String,
    /// Version offered by the registry.
    pub new_version: String,
    /// Store-path hash of the installed package.
    pub old_store_hash: String,
    /// The registry's current metadata for the package.
    pub new_meta: PackageMeta,
    /// Name of the registry the package was installed from.
    pub registry: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run `apm upgrade [packages]`.
///
/// Compares installed packages against the registry to find upgradable ones,
/// then downloads, verifies, imports, and switches to a new generation.
///
/// With `packages` non-empty, only those names are considered; `exclude`
/// names are held back; `dry_run` stops after printing the plan; `yes`
/// skips the confirmation prompt; `ignore_lock` selectively waives sysroot
/// lock violations.
///
/// # Errors
///
/// Returns an error if the profile or registry caches cannot be loaded, the
/// user declines the confirmation prompt
/// ([`AosError::UserCancelled`]), a sysroot-lock violation is not waived,
/// closure resolution / download / hash verification / NAR import fails, or
/// the new generation cannot be created, populated, or switched to.
pub async fn run(
    config: &ApmConfig,
    packages: &[String],
    exclude: &[String],
    dry_run: bool,
    yes: bool,
    ignore_lock: &IgnoreSysrootLock,
    printer: &Printer,
) -> Result<()> {
    let json_mode = printer.mode() == OutputMode::Json;
    // Step 1: Inspect profile and load installed metadata.
    printer.step(1, 7, "Loading installed packages...");
    let inspect_profile = Profile::open_readonly(config.scope);
    let installed = list_meta(&inspect_profile)?;

    // Step 2: Load registries from cache.
    printer.step(2, 7, "Loading registries...");
    let registries = load_registries(config)?;

    // Step 3: Find upgradable packages.
    let candidates = find_upgradable(&installed, &registries, packages);

    // Step 4: Filter held and excluded packages.
    let (to_upgrade, held_back) = filter_held_and_excluded(candidates, &installed, exclude);

    if to_upgrade.is_empty() {
        if !held_back.is_empty() {
            print_held_back(&held_back, printer);
        }
        if json_mode {
            let status = if held_back.is_empty() {
                "current"
            } else {
                "held_back"
            };
            printer.json(&upgrade_result_json(
                status,
                packages,
                exclude,
                &to_upgrade,
                &held_back,
                dry_run,
                None,
                &[],
                0,
                0,
            ));
        }
        printer.info("All packages are up to date.");
        return Ok(());
    }

    // Step 5: Print upgrade summary.
    print_upgrade_summary(&to_upgrade, &held_back, printer);

    // Step 6: Resolve new closures for each upgraded package.
    printer.step(3, 7, "Resolving dependencies...");
    let mut all_new_metas: Vec<PackageMeta> = Vec::new();
    let mut upgrade_closures: Vec<(String, Vec<PackageMeta>)> = Vec::new();

    for candidate in &to_upgrade {
        let closures = resolve_multiple(
            &registries,
            std::slice::from_ref(&candidate.name),
            Some(&candidate.registry),
        )
        .with_context(|| format!("resolving upgrade for '{}'", candidate.name))?;
        admit_package_roots(closures.iter().flat_map(|closure| closure.closure.iter()))?;
        for closure in closures {
            for meta in &closure.closure {
                let hash = store_path_hash(&meta.store_path).to_string();
                if !all_new_metas
                    .iter()
                    .any(|m| store_path_hash(&m.store_path) == hash)
                {
                    all_new_metas.push(meta.clone());
                }
            }
            upgrade_closures.push((closure.registry_name, closure.closure));
        }
    }
    super::install::verify_package_provenance_entries_from_cache_with_policy(
        config,
        upgrade_closures
            .iter()
            .flat_map(|(registry_name, closure)| {
                closure.iter().map(|meta| (registry_name.as_str(), meta))
            }),
    )?;
    let needed_hashes = needed_hashes_after_upgrade(&installed, &to_upgrade, &all_new_metas)
        .await
        .context("computing post-upgrade profile roots")?;
    let obsolete_hashes = obsolete_installed_hashes(&installed, &needed_hashes);
    let expose_artifacts = collect_expose_artifacts(&to_upgrade)?;

    // Sysroot-lock check for upgraded packages.
    if !matches!(ignore_lock, IgnoreSysrootLock::All) {
        if let Some((sysroot_refs, sys_name, sys_version)) =
            sysroot_lock::get_sysroot_references(config)
        {
            let lookup = sysroot_lock::build_registry_lookup(config);
            for (_reg_name, closure_metas) in &upgrade_closures {
                let pkg_refs: Vec<String> = closure_metas
                    .iter()
                    .map(|m| store_path_hash(&m.store_path).to_string())
                    .collect();

                let violations =
                    sysroot_lock::check_sysroot_lock(&sysroot_refs, &pkg_refs, &lookup);
                let remaining = ignore_lock.filter(violations);

                if !remaining.is_empty() {
                    let msg =
                        sysroot_lock::format_violation_error(&remaining, &sys_name, &sys_version);
                    anyhow::bail!(msg);
                }
            }
        }
    }

    // Trust-graph totality (RFC-0005 §2.6): seed from the WHOLE graph closure
    // of each upgraded root, so the check covers every reachable member
    // (including anonymous non-package paths) over the whole closure, not just
    // the missing subset - a stripped/partial graph fails even when the gap is
    // on an already-local member (the common case on upgrades).
    let trust_roots: Vec<(&str, &str)> = to_upgrade
        .iter()
        .map(|c| (c.registry.as_str(), store_path_hash(&c.new_meta.store_path)))
        .chain(
            expose_artifacts
                .iter()
                .filter(|artifact| artifact.trust_graph_root)
                .map(|artifact| {
                    (
                        artifact.registry_name.as_str(),
                        store_path_hash(&artifact.store_path),
                    )
                }),
        )
        .collect();
    let trust_ctx = registries.trust_context_for_roots(&trust_roots);
    trust_ctx.enforce_totality()?;

    // Filter to only missing store paths.
    let mut store_paths: Vec<String> = all_new_metas.iter().map(|m| m.store_path.clone()).collect();
    store_paths.extend(
        expose_artifacts
            .iter()
            .map(|artifact| artifact.store_path.clone()),
    );
    let missing = filter_missing(&store_paths).await?;
    let missing_set: HashSet<&str> = missing.iter().map(|s| s.as_str()).collect();
    let to_download: Vec<&PackageMeta> = all_new_metas
        .iter()
        .filter(|m| missing_set.contains(m.store_path.as_str()))
        .collect();

    let mut requests = build_download_requests(&upgrade_closures, &to_download, config)?;
    requests.extend(build_expose_artifact_download_requests(
        &registries,
        &expose_artifacts,
        &missing,
        config,
    )?);
    dedupe_download_requests(&mut requests);
    let resolved: Vec<ResolvedDownload> = if !requests.is_empty() {
        printer.step(4, 7, "Planning downloads...");
        let engine = std::sync::Arc::new(default_engine());
        fetch_narinfo_closure(
            std::sync::Arc::clone(&engine),
            &requests,
            config.settings.parallel_downloads,
            printer,
        )
        .await?
    } else {
        Vec::new()
    };
    if dry_run {
        if json_mode {
            printer.json(&upgrade_result_json(
                "planned",
                packages,
                exclude,
                &to_upgrade,
                &held_back,
                true,
                None,
                &resolved,
                0,
                0,
            ));
        }
        printer.info("Dry run -- no changes made.");
        return Ok(());
    }

    // Step 7: Prompt for confirmation (unless --yes).
    if !yes && !config.settings.assume_yes {
        confirm(printer)?;
    }

    // Download missing NARs.
    let mut downloaded_count = 0usize;
    let mut imported_count = 0usize;
    if !resolved.is_empty() {
        printer.step(4, 7, "Downloading packages...");

        let cache_dir = config.nar_cache_path();
        let results = download_nars(
            &resolved,
            &cache_dir,
            config.settings.parallel_downloads,
            printer,
        )
        .await?;
        downloaded_count = results.len();

        // Verify downloads against each path's source-registry store/ graph
        // (RFC-0005); totality was already enforced above.
        printer.step(5, 7, "Verifying downloads...");
        verify_downloads(&results, &trust_ctx, printer)?;
        verify_secondary_artifact_downloads(&results, &expose_artifacts)?;

        // Import NARs into the store.
        printer.step(5, 7, "Importing packages...");
        for result in &results {
            import_nar(
                &result.local_path,
                &result.store_path,
                &result.references,
                result.deriver.as_deref(),
            )
            .await
            .with_context(|| format!("importing {}", result.store_path))?;
        }
        imported_count = results.len();
    } else {
        printer.info("All packages already in store, skipping download.");
    }

    // Step 8: Create new generation.
    printer.step(6, 7, "Updating profile...");
    let profile = Profile::open(config.scope)?;
    let prev_gen = profile.current_generation()?;
    let new_gen = profile.new_generation()?;

    // Copy existing roots from the previous generation.
    if let Some(ref prev) = prev_gen {
        super::install::copy_roots_except_hashes(prev, &new_gen, &obsolete_hashes)?;
    }

    // Create GC roots for all new closure members.
    let unique_for_roots: Vec<PackageMeta> = {
        let mut seen = HashSet::new();
        all_new_metas
            .into_iter()
            .filter(|m| seen.insert(store_path_hash(&m.store_path).to_string()))
            .collect()
    };
    create_gc_roots(&new_gen.path, &unique_for_roots)?;

    // Write metadata for upgraded packages.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let now_iso = format_iso8601(now);
    let installed_flags = installed_flags_by_name(&installed);

    // Carry forward metadata for non-upgraded packages.
    for hash in &obsolete_hashes {
        delete_meta(&profile, hash)?;
    }
    for meta in &installed {
        let hash = store_path_hash(&meta.store_path).to_string();
        if obsolete_hashes.contains(&hash) {
            continue;
        }
        write_meta(&profile, &hash, meta)?;
    }

    // Write new metadata for upgraded packages.
    for (registry_name, closure) in &upgrade_closures {
        for meta in closure {
            let hash = store_path_hash(&meta.store_path).to_string();
            let flags = installed_flags
                .get(meta.name.as_str())
                .copied()
                .unwrap_or_default();

            let installed_meta = InstalledMeta {
                store_path: meta.store_path.clone(),
                pushed_at: now,
                pushed_by: "apm".into(),
                expires_at: None,
                is_root: true,
                last_accessed: now,
                access_count: 0,
                apm: Some(ApmMeta {
                    name: meta.name.clone(),
                    version: meta.version.clone(),
                    explicit: flags.explicit,
                    registry: registry_name.clone(),
                    installed_at: now_iso.clone(),
                    held: flags.held,
                    source_drv: meta.source_drv.clone(),
                    source_nar_hash: meta.source_nar_hash.clone(),
                    expose: meta.expose.clone(),
                    expose_artifact: meta.expose_artifact.clone(),
                    config_module: meta.config_module.clone(),
                    permissions: meta.permissions.clone(),
                    bpf_lsm: meta.bpf_lsm.clone(),
                    attestation: meta.attestation.clone(),
                }),
            };

            write_meta(&profile, &hash, &installed_meta)?;
        }
    }
    snapshot_profile_meta_to_generation(&profile, &new_gen)?;
    let future_installed = list_meta(&profile)?;
    rebuild_generation_expose_roots(&new_gen, &future_installed)?;
    rebuild_generation_expose_image_roots(&new_gen, &future_installed)?;
    validate_generation_exposed_units(&new_gen, &future_installed)?;

    // Build FHS tree for the new generation.
    build_generation_fhs_tree(&new_gen, printer)?;

    // Atomic switch to the new generation.
    profile.switch_to(&new_gen)?;
    reconcile_system_profile(config, printer).await?;

    printer.step(7, 7, "Done!");
    printer.success(&format!(
        "Upgraded {} package(s) in generation {}.",
        to_upgrade.len(),
        new_gen.number,
    ));
    if json_mode {
        printer.json(&upgrade_result_json(
            "upgraded",
            packages,
            exclude,
            &to_upgrade,
            &held_back,
            false,
            Some(new_gen.number),
            &resolved,
            downloaded_count,
            imported_count,
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Upgrade detection
// ---------------------------------------------------------------------------

/// Compare installed packages against registries to find upgradable ones.
///
/// A package is upgradable when:
/// 1. It has apm metadata (was installed via apm)
/// 2. The registry has an entry for the same name
/// 3. The registry entry has a DIFFERENT store path hash (new version/rebuild)
///
/// If `filter` is non-empty, only check those package names.
pub fn find_upgradable(
    installed: &[InstalledMeta],
    registries: &RegistrySet,
    filter: &[String],
) -> Vec<UpgradeCandidate> {
    let mut candidates = Vec::new();
    for meta in installed {
        let Some(apm) = &meta.apm else { continue };
        if !apm.explicit {
            continue;
        }

        // If filter is non-empty, skip packages not in filter.
        if !filter.is_empty() && !filter.iter().any(|f| f == &apm.name) {
            continue;
        }

        // Look up in registry (same registry as original install).
        let Some(reg) = registries.get_registry(&apm.registry) else {
            continue;
        };
        let Some(reg_meta) = reg.get(&apm.name) else {
            continue;
        };

        // Compare store path hashes -- different hash means new version/rebuild.
        // Expose artifacts and images are separate store paths, so renderer or
        // image-only changes must also force a metadata rewrite and attach
        // reconciliation.
        let old_hash = store_path_hash(&meta.store_path);
        let new_hash = store_path_hash(&reg_meta.store_path);
        let old_artifact_hash = apm
            .expose_artifact
            .as_ref()
            .map(|artifact| store_path_hash(&artifact.store_path));
        let new_artifact_hash = reg_meta
            .expose_artifact
            .as_ref()
            .map(|artifact| store_path_hash(&artifact.store_path));
        let images_changed = expose_images_changed(apm.expose.as_ref(), reg_meta.expose.as_ref());

        if old_hash != new_hash || old_artifact_hash != new_artifact_hash || images_changed {
            candidates.push(UpgradeCandidate {
                name: apm.name.clone(),
                old_version: apm.version.clone(),
                new_version: reg_meta.version.clone(),
                old_store_hash: old_hash.to_string(),
                new_meta: reg_meta.clone(),
                registry: apm.registry.clone(),
            });
        }
    }
    candidates
}

fn expose_images_changed(old: Option<&ExposeMeta>, new: Option<&ExposeMeta>) -> bool {
    let old_images: &[SysrootImageEntry] =
        old.map(|expose| expose.images.as_slice()).unwrap_or(&[]);
    let new_images: &[SysrootImageEntry] =
        new.map(|expose| expose.images.as_slice()).unwrap_or(&[]);

    old_images != new_images
}

/// The per-package flags carried forward across an upgrade.
#[derive(Clone, Copy, Default)]
struct InstalledFlags {
    explicit: bool,
    held: bool,
}

/// Index the explicit/held flags of installed packages by name, so upgraded
/// entries keep their previous flags.
fn installed_flags_by_name(installed: &[InstalledMeta]) -> HashMap<&str, InstalledFlags> {
    let mut flags: HashMap<&str, InstalledFlags> = HashMap::new();

    for meta in installed {
        let Some(apm) = meta.apm.as_ref() else {
            continue;
        };
        let incoming = InstalledFlags {
            explicit: apm.explicit,
            held: apm.held,
        };
        match flags.get(apm.name.as_str()) {
            Some(current) if current.explicit => {}
            Some(_) if !incoming.explicit => {}
            _ => {
                flags.insert(apm.name.as_str(), incoming);
            }
        }
    }

    flags
}

/// Compute the set of store-path hashes the profile still needs after the
/// upgrade: every new closure member plus the live closures of all explicit
/// packages that are not being upgraded.
async fn needed_hashes_after_upgrade(
    installed: &[InstalledMeta],
    to_upgrade: &[UpgradeCandidate],
    new_metas: &[PackageMeta],
) -> Result<HashSet<String>> {
    let mut needed: HashSet<String> = new_metas
        .iter()
        .map(|meta| store_path_hash(&meta.store_path).to_string())
        .collect();
    let upgraded_names: HashSet<&str> = to_upgrade.iter().map(|c| c.name.as_str()).collect();
    let pending_remove_hashes = hashes_for_installed_names(installed, &upgraded_names);

    for index in retained_installed_indexes(installed, &pending_remove_hashes) {
        let meta = &installed[index];
        let Some(apm) = meta.apm.as_ref() else {
            continue;
        };

        for path in closure_paths(&meta.store_path)
            .await
            .with_context(|| format!("querying closure for installed package {}", apm.name))?
        {
            needed.insert(store_path_hash(&path).to_string());
        }
    }

    Ok(needed)
}

fn hashes_for_installed_names(
    installed: &[InstalledMeta],
    names: &HashSet<&str>,
) -> HashSet<String> {
    installed
        .iter()
        .filter_map(|meta| {
            let apm = meta.apm.as_ref()?;
            names
                .contains(apm.name.as_str())
                .then(|| store_path_hash(&meta.store_path).to_string())
        })
        .collect()
}

/// Hashes of installed entries (and their source derivations) not in the
/// needed set — their GC roots and metadata are dropped from the new
/// generation.
fn obsolete_installed_hashes(
    installed: &[InstalledMeta],
    needed_hashes: &HashSet<String>,
) -> HashSet<String> {
    let mut hashes = HashSet::new();
    for meta in installed {
        let Some(apm) = meta.apm.as_ref() else {
            continue;
        };

        let hash = store_path_hash(&meta.store_path).to_string();
        if needed_hashes.contains(&hash) {
            continue;
        }

        hashes.insert(hash);
        if !apm.source_drv.is_empty() {
            hashes.insert(store_path_hash(&apm.source_drv).to_string());
        }
    }
    hashes
}

/// Filter out held and excluded packages from upgrade candidates.
///
/// Returns `(to_upgrade, held_back)` where `held_back` includes both
/// held packages and explicitly excluded ones.
pub fn filter_held_and_excluded(
    candidates: Vec<UpgradeCandidate>,
    installed: &[InstalledMeta],
    exclude: &[String],
) -> (Vec<UpgradeCandidate>, Vec<UpgradeCandidate>) {
    let held_names: HashSet<String> = installed
        .iter()
        .filter_map(|m| m.apm.as_ref())
        .filter(|a| a.held)
        .map(|a| a.name.clone())
        .collect();

    let exclude_set: HashSet<&str> = exclude.iter().map(|s| s.as_str()).collect();

    let mut to_upgrade = Vec::new();
    let mut held_back = Vec::new();

    for c in candidates {
        if held_names.contains(&c.name) || exclude_set.contains(c.name.as_str()) {
            held_back.push(c);
        } else {
            to_upgrade.push(c);
        }
    }

    (to_upgrade, held_back)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the JSON document for `apm upgrade` (planned, held_back, current,
/// or upgraded).
fn upgrade_result_json(
    status: &str,
    packages: &[String],
    exclude: &[String],
    upgrades: &[UpgradeCandidate],
    held_back: &[UpgradeCandidate],
    dry_run: bool,
    generation: Option<u32>,
    planned_downloads: &[ResolvedDownload],
    downloaded: usize,
    imported: usize,
) -> serde_json::Value {
    serde_json::json!({
        "action": "upgrade",
        "status": status,
        "requested": packages,
        "exclude": exclude,
        "dry_run": dry_run,
        "generation": generation,
        "upgraded": upgrades.len(),
        "held_back": held_back.iter().map(upgrade_candidate_json).collect::<Vec<_>>(),
        "upgrades": upgrades.iter().map(upgrade_candidate_json).collect::<Vec<_>>(),
        "downloads": {
            "planned": planned_downloads.len(),
            "downloaded": downloaded,
            "imported": imported,
            "paths": resolved_downloads_json(planned_downloads),
        },
    })
}

/// Render one upgrade candidate for JSON output.
fn upgrade_candidate_json(candidate: &UpgradeCandidate) -> serde_json::Value {
    serde_json::json!({
        "name": candidate.name.as_str(),
        "registry": candidate.registry.as_str(),
        "old_version": candidate.old_version.as_str(),
        "new_version": candidate.new_version.as_str(),
        "old_store_hash": candidate.old_store_hash.as_str(),
        "new_store_hash": store_path_hash(&candidate.new_meta.store_path),
        "new_store_path": candidate.new_meta.store_path.as_str(),
        "platform": candidate.new_meta.platform.as_str(),
        "nar_hash": candidate.new_meta.nar_hash.as_str(),
        "nar_size": candidate.new_meta.nar_size,
        "closure_size": candidate.new_meta.closure_size,
    })
}

/// Get the current platform string.
fn platform() -> String {
    "x86_64-linux".to_string()
}

/// Load registries from the config's cache directory.
fn load_registries(config: &ApmConfig) -> Result<RegistrySet> {
    let reg_configs = config.enabled_registries();
    RegistrySet::load(&config.cache_path(), &reg_configs, &platform())
}

/// Prompt for confirmation. Returns `Err(UserCancelled)` on "n".
fn confirm(printer: &Printer) -> Result<()> {
    printer.plain("Do you want to continue? [Y/n] ");

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

/// Format a byte size as a human-readable string.
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }

    let kib = bytes as f64 / 1024.0;
    if kib < 1024.0 {
        return format!("{kib:.1} KiB");
    }

    let mib = kib / 1024.0;
    if mib < 1024.0 {
        return format!("{mib:.1} MiB");
    }

    let gib = mib / 1024.0;
    format!("{gib:.1} GiB")
}

/// Print upgrade summary.
fn print_upgrade_summary(
    to_upgrade: &[UpgradeCandidate],
    held_back: &[UpgradeCandidate],
    printer: &Printer,
) {
    printer.header("The following packages will be upgraded:");
    for c in to_upgrade {
        printer.plain(&format!(
            "  {} ({} -> {})",
            c.name, c.old_version, c.new_version
        ));
    }

    if !held_back.is_empty() {
        print_held_back(held_back, printer);
    }

    let install_size: u64 = to_upgrade.iter().map(|c| c.new_meta.nar_size).sum();

    printer.plain(&format!(
        "\n{} upgraded, 0 newly installed, 0 to remove.",
        to_upgrade.len(),
    ));
    printer.plain(&format!(
        "{} of additional installed size.",
        format_size(install_size),
    ));
}

/// Print held back packages.
fn print_held_back(held_back: &[UpgradeCandidate], printer: &Printer) {
    printer.header("\nThe following packages are held back:");
    for c in held_back {
        printer.plain(&format!("  {} ({})", c.name, c.old_version));
    }
}

/// Build download requests for the upgraded packages.
fn build_download_requests(
    closures: &[(String, Vec<PackageMeta>)],
    to_download: &[&PackageMeta],
    config: &ApmConfig,
) -> Result<Vec<DownloadRequest>> {
    // Build a map of registry_name -> mirror chain (primary + fallbacks).
    let registries_base = config.scope.registries_path();
    let mirror_map: std::collections::HashMap<String, Vec<String>> = closures
        .iter()
        .map(|(registry_name, _)| {
            let reg_config = config
                .registries
                .iter()
                .find(|(cfg, _)| cfg.name == *registry_name)
                .map(|(cfg, _)| cfg);
            let chain = if let Some(cfg) = reg_config {
                resolve_mirror_chain(&registries_base, cfg)
            } else {
                vec![format!("https://registry.aos.dev/{}", registry_name)]
            };
            (registry_name.clone(), chain)
        })
        .collect();

    // Build a map of store_path_hash -> registry_name.
    let mut hash_to_registry: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for (registry_name, closure) in closures {
        for meta in closure {
            let hash = store_path_hash(&meta.store_path).to_string();
            hash_to_registry
                .entry(hash)
                .or_insert_with(|| registry_name.clone());
        }
    }

    let mut requests = Vec::with_capacity(to_download.len());
    for meta in to_download {
        let hash = store_path_hash(&meta.store_path).to_string();
        let registry_name = hash_to_registry
            .get(&hash)
            .context("internal error: missing registry for package")?;
        let chain = mirror_map
            .get(registry_name)
            .context("internal error: missing mirror for registry")?;
        let (mirror_url, fallback_mirrors) = split_mirror_chain(chain);

        requests.push(DownloadRequest {
            store_path: meta.store_path.clone(),
            mirror_url,
            fallback_mirrors,
        });
    }

    Ok(requests)
}

/// Collect rendered expose artifacts and images needed for upgraded explicit roots.
fn collect_expose_artifacts(
    candidates: &[UpgradeCandidate],
) -> Result<Vec<SecondaryArtifactDownload>> {
    let mut artifacts = Vec::new();
    let mut seen = HashMap::<String, usize>::new();

    for candidate in candidates {
        let Some(expose) = candidate.new_meta.expose.as_ref() else {
            continue;
        };
        let Some(artifact) = candidate.new_meta.expose_artifact.as_ref() else {
            anyhow::bail!(
                "package '{}' exposes systemd units but does not record an expose artifact",
                candidate.name
            );
        };
        push_secondary_artifact(
            &mut artifacts,
            &mut seen,
            &candidate.registry,
            &artifact.store_path,
            &artifact.nar_hash,
            true,
            false,
        )?;
        for image in &expose.images {
            push_secondary_artifact(
                &mut artifacts,
                &mut seen,
                &candidate.registry,
                &image.store_path,
                &image.nar_hash,
                false,
                true,
            )?;
        }
    }

    Ok(artifacts)
}

fn push_secondary_artifact(
    artifacts: &mut Vec<SecondaryArtifactDownload>,
    seen: &mut HashMap<String, usize>,
    registry_name: &str,
    store_path: &str,
    nar_hash: &str,
    trust_graph_root: bool,
    requires_empty_references: bool,
) -> Result<()> {
    if let Some(previous_index) = seen.get(store_path).copied() {
        let previous = &artifacts[previous_index];
        if previous.nar_hash != nar_hash {
            anyhow::bail!(
                "secondary expose store path '{}' has conflicting signed NAR hashes",
                store_path
            );
        }
        if previous.trust_graph_root != trust_graph_root
            || previous.requires_empty_references != requires_empty_references
        {
            anyhow::bail!(
                "secondary expose store path '{}' is declared with incompatible roles",
                store_path
            );
        }
        return Ok(());
    }
    seen.insert(store_path.to_string(), artifacts.len());
    artifacts.push(SecondaryArtifactDownload {
        registry_name: registry_name.to_string(),
        store_path: store_path.to_string(),
        nar_hash: nar_hash.to_string(),
        trust_graph_root,
        requires_empty_references,
    });
    Ok(())
}

fn verify_secondary_artifact_downloads(
    results: &[super::download::DownloadResult],
    artifacts: &[SecondaryArtifactDownload],
) -> Result<()> {
    let expected = artifacts
        .iter()
        .map(|artifact| (artifact.store_path.as_str(), artifact))
        .collect::<HashMap<_, _>>();

    for result in results {
        let Some(artifact) = expected.get(result.store_path.as_str()) else {
            continue;
        };
        if artifact.requires_empty_references && !result.references.is_empty() {
            anyhow::bail!(
                "expose image '{}' has runtime references but signed image metadata covers only the image NAR",
                result.store_path
            );
        }
        verify_nar_hash(&result.local_path, &artifact.nar_hash)
            .with_context(|| format!("verifying signed NAR for {}", result.store_path))?;
    }

    Ok(())
}

/// Build NAR download requests for missing expose artifacts and images.
fn build_expose_artifact_download_requests(
    registries: &RegistrySet,
    artifacts: &[SecondaryArtifactDownload],
    missing_store_paths: &[String],
    config: &ApmConfig,
) -> Result<Vec<DownloadRequest>> {
    let missing = missing_store_paths
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut requests = Vec::new();

    for artifact in artifacts {
        if !missing.contains(artifact.store_path.as_str()) {
            continue;
        }
        let registry = registries
            .get_registry(&artifact.registry_name)
            .with_context(|| format!("registry '{}' not loaded", artifact.registry_name))?;
        let chain = crate::download::resolve_mirror_chain(
            &config.scope.registries_path(),
            &registry.config,
        );
        requests.push(DownloadRequest {
            store_path: artifact.store_path.clone(),
            mirror_url: chain.first().cloned().unwrap_or_default(),
            fallback_mirrors: chain.into_iter().skip(1).collect(),
        });
    }

    Ok(requests)
}

/// Deduplicate download requests by store path while preserving first-seen order.
fn dedupe_download_requests(requests: &mut Vec<DownloadRequest>) {
    let mut seen = HashSet::new();
    requests.retain(|request| seen.insert(request.store_path.clone()));
}

/// Format a Unix timestamp as simplified ISO 8601 (`YYYY-MM-DDTHH:MM:SSZ`).
fn format_iso8601(epoch_secs: i64) -> String {
    let secs_per_day: i64 = 86400;
    let days = epoch_secs / secs_per_day;
    let day_secs = (epoch_secs % secs_per_day) as u32;

    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    use crate::registry::parse::CURL_TOML;
    use crate::registry::{Registry, RegistrySet};
    use crate::types::{ApmMeta, ExposeArtifactMeta, InstalledMeta, PackageMeta, RegistryConfig};

    /// Helper: create a registry in a temp directory from TOML test fixtures.
    fn make_registry(
        tmp: &TempDir,
        name: &str,
        priority: u32,
        toml_files: &[(&str, &str)],
    ) -> Registry {
        let reg_dir = tmp.path().join(name).join("packages");
        for (pkg_name, content) in toml_files {
            let first_letter = &pkg_name[..1];
            let dir = reg_dir.join(first_letter);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(format!("{pkg_name}.toml")), content).unwrap();
        }

        let config = RegistryConfig {
            name: name.to_string(),
            url: format!("https://registry.example.com/{name}"),
            priority,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        };

        Registry::load(tmp.path(), &config, "x86_64-linux").unwrap()
    }

    /// Build a sample `InstalledMeta` for testing.
    fn sample_installed(
        name: &str,
        version: &str,
        hash: &str,
        registry: &str,
        held: bool,
    ) -> InstalledMeta {
        sample_installed_with_flags(name, version, hash, registry, true, held)
    }

    fn sample_installed_with_flags(
        name: &str,
        version: &str,
        hash: &str,
        registry: &str,
        explicit: bool,
        held: bool,
    ) -> InstalledMeta {
        InstalledMeta {
            store_path: format!("/var/lib/store/{hash}-{name}-{version}"),
            pushed_at: 1707800000,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: Some(ApmMeta {
                name: name.into(),
                version: version.into(),
                explicit,
                registry: registry.into(),
                installed_at: "2026-02-16T00:00:00Z".into(),
                held,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                expose: None,
                expose_artifact: None,
                config_module: None,
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        }
    }

    fn sample_package_meta(name: &str, version: &str, store_path: &str) -> PackageMeta {
        PackageMeta {
            name: name.to_string(),
            version: version.to_string(),
            description: String::new(),
            homepage: None,
            license: "MIT".to_string(),
            maintainer: "test".to_string(),
            platform: "x86_64-linux".to_string(),
            store_path: store_path.to_string(),
            nar_hash: "sha256:root".to_string(),
            nar_size: 1,
            references: Vec::new(),
            source_drv: String::new(),
            source_nar_hash: String::new(),
            closure_size: 1,
            sysroot: false,
            previous: None,
            images: Vec::new(),
            min_format: None,
            requires_features: Vec::new(),
            expose: None,
            expose_artifact: None,
            config_module: None,
            permissions: Default::default(),
            bpf_lsm: None,
            attestation: Default::default(),
        }
    }

    fn sample_expose_image(store_path: &str, nar_hash: &str) -> SysrootImageEntry {
        SysrootImageEntry {
            format: "dir".to_string(),
            store_path: store_path.to_string(),
            nar_hash: nar_hash.to_string(),
            nar_size: 1,
            delivery: crate::types::test_image_delivery("raw"),
            sb_signer_cert_sha256: None,
            sbat: Vec::new(),
            expected_pcr11: None,
            ukis: Vec::new(),
            recovery_ukis: Vec::new(),
            recovery_bundle: None,
            root_image: None,
            root_verity: None,
            root_hash: None,
            root_hash_sig: None,
        }
    }

    #[test]
    fn collect_expose_artifacts_includes_expose_images() {
        let mut new_meta = sample_package_meta("web", "2.0.0", "/var/lib/store/root-web");
        new_meta.expose = Some(ExposeMeta {
            target: "web.target".to_string(),
            units: vec!["web.service".to_string()],
            images: vec![sample_expose_image(
                "/var/lib/store/image-web",
                "sha256:image",
            )],
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        });
        new_meta.expose_artifact = Some(ExposeArtifactMeta {
            store_path: "/var/lib/store/expose-web".to_string(),
            nar_hash: "sha256:expose".to_string(),
            nar_size: 1,
        });
        let candidate = UpgradeCandidate {
            name: "web".to_string(),
            old_version: "1.0.0".to_string(),
            new_version: "2.0.0".to_string(),
            old_store_hash: "oldweb".to_string(),
            new_meta,
            registry: "test-reg".to_string(),
        };

        let artifacts = collect_expose_artifacts(&[candidate]).expect("collect expose artifacts");

        assert_eq!(
            artifacts,
            vec![
                SecondaryArtifactDownload {
                    registry_name: "test-reg".to_string(),
                    store_path: "/var/lib/store/expose-web".to_string(),
                    nar_hash: "sha256:expose".to_string(),
                    trust_graph_root: true,
                    requires_empty_references: false,
                },
                SecondaryArtifactDownload {
                    registry_name: "test-reg".to_string(),
                    store_path: "/var/lib/store/image-web".to_string(),
                    nar_hash: "sha256:image".to_string(),
                    trust_graph_root: false,
                    requires_empty_references: true,
                },
            ]
        );
    }

    #[test]
    fn collect_expose_artifacts_rejects_incompatible_duplicate_roles() {
        let shared_path = "/var/lib/store/shared-secondary";
        let mut image_meta = sample_package_meta("web", "2.0.0", "/var/lib/store/root-web");
        image_meta.expose = Some(ExposeMeta {
            target: "web.target".to_string(),
            units: vec!["web.service".to_string()],
            images: vec![sample_expose_image(shared_path, "sha256:shared")],
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        });
        image_meta.expose_artifact = Some(ExposeArtifactMeta {
            store_path: "/var/lib/store/expose-web".to_string(),
            nar_hash: "sha256:web-expose".to_string(),
            nar_size: 1,
        });
        let mut artifact_meta = sample_package_meta("api", "2.0.0", "/var/lib/store/root-api");
        artifact_meta.expose = Some(ExposeMeta {
            target: "api.target".to_string(),
            units: vec!["api.service".to_string()],
            images: Vec::new(),
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        });
        artifact_meta.expose_artifact = Some(ExposeArtifactMeta {
            store_path: shared_path.to_string(),
            nar_hash: "sha256:shared".to_string(),
            nar_size: 1,
        });
        let candidates = vec![
            UpgradeCandidate {
                name: "web".to_string(),
                old_version: "1.0.0".to_string(),
                new_version: "2.0.0".to_string(),
                old_store_hash: "oldweb".to_string(),
                new_meta: image_meta,
                registry: "test-reg".to_string(),
            },
            UpgradeCandidate {
                name: "api".to_string(),
                old_version: "1.0.0".to_string(),
                new_version: "2.0.0".to_string(),
                old_store_hash: "oldapi".to_string(),
                new_meta: artifact_meta,
                registry: "test-reg".to_string(),
            },
        ];

        let err = collect_expose_artifacts(&candidates)
            .expect_err("duplicate image/artifact path should be rejected");

        assert!(err.to_string().contains("incompatible roles"));
    }

    #[test]
    fn verify_secondary_artifact_downloads_rejects_image_references() {
        let result = crate::download::DownloadResult {
            store_path: "/var/lib/store/image-web".to_string(),
            local_path: std::path::PathBuf::from("/does/not/exist"),
            download_hash: "sha256:download".to_string(),
            nar_hash: "sha256:image".to_string(),
            references: vec!["/var/lib/store/ref-dep".to_string()],
            deriver: None,
        };
        let artifact = SecondaryArtifactDownload {
            registry_name: "test-reg".to_string(),
            store_path: "/var/lib/store/image-web".to_string(),
            nar_hash: "sha256:image".to_string(),
            trust_graph_root: false,
            requires_empty_references: true,
        };

        let err = verify_secondary_artifact_downloads(&[result], &[artifact])
            .expect_err("referenced expose image should be rejected");

        assert!(err.to_string().contains("runtime references"));
    }

    // A newer version of curl for the registry (different hash).
    const CURL_TOML_NEWER: &str = r#"
[package]
name = "curl"
description = "Command-line tool and library for URL transfers"
homepage = "https://curl.se"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "8.6.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/newh4sh99xx-curl-8.6.0"
nar_hash = "sha256:newnar"
nar_size = 3200000
closure_size = 53000000
source_drv = "/var/lib/store/newsrc-curl-8.6.0.drv"
source_nar_hash = "sha256:newsrc"
references = []
"#;

    const CURL_TOML_REFRESHED_EXPOSE_ARTIFACT: &str = r#"
[package]
name = "curl"
description = "Command-line tool and library for URL transfers"
homepage = "https://curl.se"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "8.5.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/h7j3k8l2m9n4-curl-8.5.0"
nar_hash = "sha256:oldnar"
nar_size = 3100000
closure_size = 52000000
source_drv = "/var/lib/store/oldsrc-curl-8.5.0.drv"
source_nar_hash = "sha256:oldsrc"
root_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
provenance = "attestation/curl.provenance.jsonl"
measurement = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["attestation-v1", "expose-v1", "expose-artifact-v1", "network-policy-v1"]

[versions.platforms.x86_64-linux.expose]
target = "aos-pkg-curl.target"
units = ["curl.service"]

[versions.platforms.x86_64-linux.expose_artifact]
store_path = "/var/lib/store/newartifacthash-curl-expose"
nar_hash = "sha256:newartifact"
nar_size = 42
"#;

    const CURL_TOML_REFRESHED_EXPOSE_IMAGE: &str = r#"
[package]
name = "curl"
description = "Command-line tool and library for URL transfers"
homepage = "https://curl.se"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "8.5.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/h7j3k8l2m9n4-curl-8.5.0"
nar_hash = "sha256:oldnar"
nar_size = 3100000
closure_size = 52000000
source_drv = "/var/lib/store/oldsrc-curl-8.5.0.drv"
source_nar_hash = "sha256:oldsrc"
root_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
provenance = "attestation/curl.provenance.jsonl"
measurement = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["attestation-v1", "expose-v1", "expose-artifact-v1", "network-policy-v1"]

[versions.platforms.x86_64-linux.expose]
target = "aos-pkg-curl.target"
units = ["curl.service"]

[[versions.platforms.x86_64-linux.expose.images]]
format = "dir"
store_path = "/var/lib/store/newimagehash-curl-rootfs"
nar_hash = "sha256:newimage"
nar_size = 42

[versions.platforms.x86_64-linux.expose_artifact]
store_path = "/var/lib/store/artifacthash111-curl-expose"
nar_hash = "sha256:artifact"
nar_size = 42
"#;

    // 1. find_upgradable detects newer version in registry (different hash).
    #[test]
    fn find_upgradable_detects_newer_version() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML_NEWER)]);
        let set = RegistrySet::new(vec![core]);

        let installed = vec![sample_installed(
            "curl",
            "8.5.0",
            "h7j3k8l2m9n4",
            "aos-core",
            false,
        )];

        let candidates = find_upgradable(&installed, &set, &[]);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "curl");
        assert_eq!(candidates[0].old_version, "8.5.0");
        assert_eq!(candidates[0].new_version, "8.6.0");
        assert_eq!(candidates[0].old_store_hash, "h7j3k8l2m9n4");
        assert_eq!(candidates[0].registry, "aos-core");
    }

    // 2. find_upgradable skips up-to-date packages (same hash).
    #[test]
    fn find_upgradable_skips_up_to_date() {
        let tmp = TempDir::new().unwrap();
        // Registry has same version/hash as installed.
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);
        let set = RegistrySet::new(vec![core]);

        let installed = vec![sample_installed(
            "curl",
            "8.5.0",
            "h7j3k8l2m9n4",
            "aos-core",
            false,
        )];

        let candidates = find_upgradable(&installed, &set, &[]);
        assert!(candidates.is_empty());
    }

    #[test]
    fn find_upgradable_detects_expose_artifact_refresh() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML_REFRESHED_EXPOSE_ARTIFACT)],
        );
        let set = RegistrySet::new(vec![core]);

        let mut installed = vec![sample_installed(
            "curl",
            "8.5.0",
            "h7j3k8l2m9n4",
            "aos-core",
            false,
        )];
        let apm = installed[0].apm.as_mut().unwrap();
        apm.expose = Some(ExposeMeta {
            target: "aos-pkg-curl.target".into(),
            units: vec!["curl.service".into()],
            images: Vec::new(),
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        });
        apm.expose_artifact = Some(ExposeArtifactMeta {
            store_path: "/var/lib/store/oldartifacthash-curl-expose".into(),
            nar_hash: "sha256:oldartifact".into(),
            nar_size: 42,
        });

        let candidates = find_upgradable(&installed, &set, &[]);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "curl");
        assert_eq!(candidates[0].old_store_hash, "h7j3k8l2m9n4");
        assert_eq!(
            candidates[0]
                .new_meta
                .expose_artifact
                .as_ref()
                .unwrap()
                .store_path,
            "/var/lib/store/newartifacthash-curl-expose"
        );
    }

    #[test]
    fn find_upgradable_detects_expose_image_refresh() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML_REFRESHED_EXPOSE_IMAGE)],
        );
        let set = RegistrySet::new(vec![core]);

        let mut installed = vec![sample_installed(
            "curl",
            "8.5.0",
            "h7j3k8l2m9n4",
            "aos-core",
            false,
        )];
        let apm = installed[0].apm.as_mut().unwrap();
        apm.expose = Some(ExposeMeta {
            target: "aos-pkg-curl.target".into(),
            units: vec!["curl.service".into()],
            images: vec![sample_expose_image(
                "/var/lib/store/oldimagehash-curl-rootfs",
                "sha256:oldimage",
            )],
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        });
        apm.expose_artifact = Some(ExposeArtifactMeta {
            store_path: "/var/lib/store/artifacthash111-curl-expose".into(),
            nar_hash: "sha256:artifact".into(),
            nar_size: 42,
        });

        let candidates = find_upgradable(&installed, &set, &[]);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "curl");
        assert_eq!(candidates[0].old_store_hash, "h7j3k8l2m9n4");
        assert_eq!(
            candidates[0].new_meta.expose.as_ref().unwrap().images[0].store_path,
            "/var/lib/store/newimagehash-curl-rootfs"
        );
    }

    // 3. find_upgradable with filter only checks named packages.
    #[test]
    fn find_upgradable_with_filter() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML_NEWER)]);
        let set = RegistrySet::new(vec![core]);

        let installed = vec![
            sample_installed("curl", "8.5.0", "h7j3k8l2m9n4", "aos-core", false),
            sample_installed("zlib", "1.3.0", "oldzlibhash1", "aos-core", false),
        ];

        // Filter to only "zlib" -- curl should not appear even though it's upgradable.
        let filter = vec!["zlib".to_string()];
        let candidates = find_upgradable(&installed, &set, &filter);
        // zlib is not in this registry with a different hash, so nothing upgradable.
        assert!(candidates.is_empty());

        // Filter to "curl" -- should find the upgrade.
        let filter = vec!["curl".to_string()];
        let candidates = find_upgradable(&installed, &set, &filter);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "curl");
    }

    #[test]
    fn find_upgradable_skips_auto_installed_dependencies() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML_NEWER)]);
        let set = RegistrySet::new(vec![core]);

        let installed = vec![sample_installed_with_flags(
            "curl",
            "8.5.0",
            "h7j3k8l2m9n4",
            "aos-core",
            false,
            false,
        )];

        let candidates = find_upgradable(&installed, &set, &[]);

        assert!(candidates.is_empty());
    }

    // 4. find_upgradable skips packages without apm metadata.
    #[test]
    fn find_upgradable_skips_non_apm() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML_NEWER)]);
        let set = RegistrySet::new(vec![core]);

        let installed = vec![InstalledMeta {
            store_path: "/var/lib/store/h7j3k8l2m9n4-curl-8.5.0".into(),
            pushed_at: 1707800000,
            pushed_by: "cache".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: None, // No apm metadata.
        }];

        let candidates = find_upgradable(&installed, &set, &[]);
        assert!(candidates.is_empty());
    }

    #[test]
    fn installed_flags_by_name_preserves_explicit_and_held_state() {
        let installed = vec![
            sample_installed_with_flags("tool", "1.0.0", "hash1", "aos-core", true, true),
            sample_installed_with_flags("runtime", "1.0.0", "hash2", "aos-core", false, false),
        ];

        let flags = installed_flags_by_name(&installed);

        assert!(flags["tool"].explicit);
        assert!(flags["tool"].held);
        assert!(!flags["runtime"].explicit);
        assert!(!flags["runtime"].held);
    }

    #[test]
    fn installed_flags_by_name_prefers_explicit_duplicate_name() {
        let installed = vec![
            sample_installed_with_flags(
                "priority-tool",
                "2.0.0",
                "highhash",
                "high-priority",
                true,
                true,
            ),
            sample_installed_with_flags(
                "priority-tool",
                "9.0.0",
                "lowhash",
                "low-priority",
                false,
                false,
            ),
        ];

        let flags = installed_flags_by_name(&installed);
        let entry = flags.get("priority-tool").unwrap();
        assert!(entry.explicit);
        assert!(entry.held);
    }

    #[test]
    fn obsolete_installed_hashes_skips_only_unneeded_apm_roots() {
        let mut old_tool =
            sample_installed_with_flags("tool", "1.0.0", "oldtoolhash", "aos-core", true, false);
        old_tool.apm.as_mut().unwrap().source_drv =
            "/var/lib/store/oldsourcehash-tool-src.drv".to_string();

        let installed = vec![
            old_tool,
            sample_installed_with_flags(
                "runtime",
                "1.0.0",
                "oldruntimehash",
                "aos-core",
                false,
                false,
            ),
            sample_installed_with_flags("kept", "1.0.0", "keptroot", "aos-core", true, false),
            InstalledMeta {
                store_path: "/var/lib/store/nonapmroot-foreign-1.0.0".into(),
                pushed_at: 1707800000,
                pushed_by: "cache".into(),
                expires_at: None,
                is_root: true,
                last_accessed: 1707800000,
                access_count: 0,
                apm: None,
            },
        ];
        let needed = HashSet::from(["keptroot".to_string(), "newruntimehash".to_string()]);

        let obsolete = obsolete_installed_hashes(&installed, &needed);

        assert!(obsolete.contains("oldtoolhash"));
        assert!(obsolete.contains("oldsourcehash"));
        assert!(obsolete.contains("oldruntimehash"));
        assert!(!obsolete.contains("keptroot"));
        assert!(!obsolete.contains("nonapmroot"));
    }

    // 5. filter_held_and_excluded separates held packages.
    #[test]
    fn filter_separates_held() {
        let installed = vec![
            sample_installed("curl", "8.5.0", "hash1", "aos-core", true), // held
            sample_installed("zlib", "1.3.0", "hash2", "aos-core", false),
        ];

        let candidates = vec![
            UpgradeCandidate {
                name: "curl".into(),
                old_version: "8.5.0".into(),
                new_version: "8.6.0".into(),
                old_store_hash: "hash1".into(),
                new_meta: PackageMeta {
                    name: "curl".into(),
                    version: "8.6.0".into(),
                    description: String::new(),
                    homepage: None,
                    license: String::new(),
                    maintainer: String::new(),
                    platform: "x86_64-linux".into(),
                    store_path: "/var/lib/store/newhash-curl-8.6.0".into(),
                    nar_hash: String::new(),
                    nar_size: 0,
                    references: vec![],
                    source_drv: String::new(),
                    source_nar_hash: String::new(),
                    closure_size: 0,
                    sysroot: false,
                    previous: None,
                    images: vec![],
                    min_format: None,
                    requires_features: Vec::new(),
                    expose: None,
                    expose_artifact: None,
                    config_module: None,
                    permissions: Default::default(),
                    bpf_lsm: None,
                    attestation: Default::default(),
                },
                registry: "aos-core".into(),
            },
            UpgradeCandidate {
                name: "zlib".into(),
                old_version: "1.3.0".into(),
                new_version: "1.3.1".into(),
                old_store_hash: "hash2".into(),
                new_meta: PackageMeta {
                    name: "zlib".into(),
                    version: "1.3.1".into(),
                    description: String::new(),
                    homepage: None,
                    license: String::new(),
                    maintainer: String::new(),
                    platform: "x86_64-linux".into(),
                    store_path: "/var/lib/store/newhash-zlib-1.3.1".into(),
                    nar_hash: String::new(),
                    nar_size: 0,
                    references: vec![],
                    source_drv: String::new(),
                    source_nar_hash: String::new(),
                    closure_size: 0,
                    sysroot: false,
                    previous: None,
                    images: vec![],
                    min_format: None,
                    requires_features: Vec::new(),
                    expose: None,
                    expose_artifact: None,
                    config_module: None,
                    permissions: Default::default(),
                    bpf_lsm: None,
                    attestation: Default::default(),
                },
                registry: "aos-core".into(),
            },
        ];

        let (to_upgrade, held_back) = filter_held_and_excluded(candidates, &installed, &[]);
        assert_eq!(to_upgrade.len(), 1);
        assert_eq!(to_upgrade[0].name, "zlib");
        assert_eq!(held_back.len(), 1);
        assert_eq!(held_back[0].name, "curl");
    }

    // 6. filter_held_and_excluded separates excluded packages.
    #[test]
    fn filter_separates_excluded() {
        let installed = vec![
            sample_installed("curl", "8.5.0", "hash1", "aos-core", false),
            sample_installed("zlib", "1.3.0", "hash2", "aos-core", false),
        ];

        let candidates = vec![
            UpgradeCandidate {
                name: "curl".into(),
                old_version: "8.5.0".into(),
                new_version: "8.6.0".into(),
                old_store_hash: "hash1".into(),
                new_meta: PackageMeta {
                    name: "curl".into(),
                    version: "8.6.0".into(),
                    description: String::new(),
                    homepage: None,
                    license: String::new(),
                    maintainer: String::new(),
                    platform: "x86_64-linux".into(),
                    store_path: "/var/lib/store/newhash-curl-8.6.0".into(),
                    nar_hash: String::new(),
                    nar_size: 0,
                    references: vec![],
                    source_drv: String::new(),
                    source_nar_hash: String::new(),
                    closure_size: 0,
                    sysroot: false,
                    previous: None,
                    images: vec![],
                    min_format: None,
                    requires_features: Vec::new(),
                    expose: None,
                    expose_artifact: None,
                    config_module: None,
                    permissions: Default::default(),
                    bpf_lsm: None,
                    attestation: Default::default(),
                },
                registry: "aos-core".into(),
            },
            UpgradeCandidate {
                name: "zlib".into(),
                old_version: "1.3.0".into(),
                new_version: "1.3.1".into(),
                old_store_hash: "hash2".into(),
                new_meta: PackageMeta {
                    name: "zlib".into(),
                    version: "1.3.1".into(),
                    description: String::new(),
                    homepage: None,
                    license: String::new(),
                    maintainer: String::new(),
                    platform: "x86_64-linux".into(),
                    store_path: "/var/lib/store/newhash-zlib-1.3.1".into(),
                    nar_hash: String::new(),
                    nar_size: 0,
                    references: vec![],
                    source_drv: String::new(),
                    source_nar_hash: String::new(),
                    closure_size: 0,
                    sysroot: false,
                    previous: None,
                    images: vec![],
                    min_format: None,
                    requires_features: Vec::new(),
                    expose: None,
                    expose_artifact: None,
                    config_module: None,
                    permissions: Default::default(),
                    bpf_lsm: None,
                    attestation: Default::default(),
                },
                registry: "aos-core".into(),
            },
        ];

        let exclude = vec!["curl".to_string()];
        let (to_upgrade, held_back) = filter_held_and_excluded(candidates, &installed, &exclude);
        assert_eq!(to_upgrade.len(), 1);
        assert_eq!(to_upgrade[0].name, "zlib");
        assert_eq!(held_back.len(), 1);
        assert_eq!(held_back[0].name, "curl");
    }

    // 7. filter_held_and_excluded passes through non-held, non-excluded.
    #[test]
    fn filter_passes_through_normal() {
        let installed = vec![
            sample_installed("curl", "8.5.0", "hash1", "aos-core", false),
            sample_installed("zlib", "1.3.0", "hash2", "aos-core", false),
        ];

        let candidates = vec![
            UpgradeCandidate {
                name: "curl".into(),
                old_version: "8.5.0".into(),
                new_version: "8.6.0".into(),
                old_store_hash: "hash1".into(),
                new_meta: PackageMeta {
                    name: "curl".into(),
                    version: "8.6.0".into(),
                    description: String::new(),
                    homepage: None,
                    license: String::new(),
                    maintainer: String::new(),
                    platform: "x86_64-linux".into(),
                    store_path: "/var/lib/store/newhash-curl-8.6.0".into(),
                    nar_hash: String::new(),
                    nar_size: 0,
                    references: vec![],
                    source_drv: String::new(),
                    source_nar_hash: String::new(),
                    closure_size: 0,
                    sysroot: false,
                    previous: None,
                    images: vec![],
                    min_format: None,
                    requires_features: Vec::new(),
                    expose: None,
                    expose_artifact: None,
                    config_module: None,
                    permissions: Default::default(),
                    bpf_lsm: None,
                    attestation: Default::default(),
                },
                registry: "aos-core".into(),
            },
            UpgradeCandidate {
                name: "zlib".into(),
                old_version: "1.3.0".into(),
                new_version: "1.3.1".into(),
                old_store_hash: "hash2".into(),
                new_meta: PackageMeta {
                    name: "zlib".into(),
                    version: "1.3.1".into(),
                    description: String::new(),
                    homepage: None,
                    license: String::new(),
                    maintainer: String::new(),
                    platform: "x86_64-linux".into(),
                    store_path: "/var/lib/store/newhash-zlib-1.3.1".into(),
                    nar_hash: String::new(),
                    nar_size: 0,
                    references: vec![],
                    source_drv: String::new(),
                    source_nar_hash: String::new(),
                    closure_size: 0,
                    sysroot: false,
                    previous: None,
                    images: vec![],
                    min_format: None,
                    requires_features: Vec::new(),
                    expose: None,
                    expose_artifact: None,
                    config_module: None,
                    permissions: Default::default(),
                    bpf_lsm: None,
                    attestation: Default::default(),
                },
                registry: "aos-core".into(),
            },
        ];

        let (to_upgrade, held_back) = filter_held_and_excluded(candidates, &installed, &[]);
        assert_eq!(to_upgrade.len(), 2);
        assert!(held_back.is_empty());
    }

    // 8. Empty candidates returns empty results.
    #[test]
    fn empty_candidates_returns_empty() {
        let installed = vec![sample_installed(
            "curl", "8.5.0", "hash1", "aos-core", false,
        )];

        let (to_upgrade, held_back) = filter_held_and_excluded(Vec::new(), &installed, &[]);
        assert!(to_upgrade.is_empty());
        assert!(held_back.is_empty());
    }
}
