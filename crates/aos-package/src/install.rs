//! User-scope package installation (`apm install`, `apm reinstall`).
//!
//! [`run`] implements the full consumer install pipeline against the active
//! profile:
//!
//! 1. **Resolve** — load registry metadata from the scope's cache and resolve
//!    each requested package to a [`ResolvedClosure`] (root plus transitive
//!    dependencies). With `--no-deps` the closure is pruned to the roots and
//!    the skipped dependencies must already be present in the store.
//! 2. **Guard** — short-circuit when everything is already installed, when a
//!    package is already provided by the system sysroot, or when the
//!    sysroot-lock check finds the closure would diverge from sysroot-pinned
//!    store paths (bypassable via `--ignore-sysroot-lock`).
//! 3. **Download and import** — fetch narinfos for the missing store paths,
//!    print the summary, confirm, download the NARs, verify both the
//!    compressed download hash and the NAR hash, and import into the store.
//!    `--download-only` stops here.
//! 4. **Switch generations** — create the next profile generation, carry
//!    forward GC roots from the previous one (minus obsolete closure members),
//!    write per-path [`InstalledMeta`] records (explicit/held flags are
//!    preserved across reinstalls), build the merged FHS tree, and atomically
//!    switch the profile's `current` link.
//!
//! Image/sysroot installs (`apm install --system`) are handled by
//! [`crate::sysroot`]. Profile installs handled here can still target the
//! system profile; when an installed root exposes systemd units, this module
//! persists and applies the corresponding preset policy.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{Read as _, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

use super::config::ApmConfig;
use super::download::{
    DownloadRequest, ResolvedDownload, default_engine, download_nars, fetch_narinfo_closure,
    fetch_narinfos, order_resolved_downloads, reference_store_path, resolve_mirror_chain,
    resolved_downloads_json, split_mirror_chain,
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
use super::provenance;
use super::registry::{RegistrySet, keys, store_path_hash};
use super::remove::retained_installed_indexes;
use super::resolve::{ResolvedClosure, collect_unique_metas, resolve_multiple};
use super::store::{closure_paths, create_gc_roots, filter_missing, import_nar};
use super::sysroot_lock::{self, IgnoreSysrootLock};
use super::types::{
    ApmMeta, InstalledMeta, PackageMeta, package_requires_provenance,
    validate_attestation_provenance_ref, validate_registry_name,
};
use super::verify::{verify_downloads, verify_nar_hash};
use aos_core::error::AosError;
use aos_core::nar::info as narinfo;
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
// Public API
// ---------------------------------------------------------------------------

/// Run `apm install <packages>`.
///
/// Full pipeline: resolve -> download -> verify -> import -> profile switch
/// (see the module docs for the step-by-step description). With `reinstall`
/// every requested package must already be installed and is re-resolved from
/// its original source registry; `require_installed` enforces the same
/// precondition without forcing a re-download decision. In JSON output mode
/// a machine-readable result object is emitted alongside the human output.
///
/// # Errors
///
/// Returns an error when:
///
/// - a requested package cannot be resolved, or (for reinstalls) is not
///   currently installed;
/// - the sysroot-lock check finds un-ignored violations;
/// - `--no-deps` is given but a skipped dependency is missing from the store;
/// - narinfo fetch, NAR download, hash verification, or store import fails;
/// - profile generation creation, metadata writes, FHS-tree construction, or
///   the final generation switch fails;
/// - the user declines the confirmation prompt
///   ([`AosError::UserCancelled`]).
pub async fn run(
    config: &ApmConfig,
    packages: &[String],
    registry_filter: Option<&str>,
    reinstall: bool,
    require_installed: bool,
    download_only: bool,
    no_deps: bool,
    dry_run: bool,
    yes: bool,
    ignore_lock: &IgnoreSysrootLock,
    printer: &Printer,
) -> Result<()> {
    run_inner(
        config,
        packages,
        registry_filter,
        reinstall,
        require_installed,
        download_only,
        no_deps,
        dry_run,
        yes,
        ignore_lock,
        printer,
        true,
    )
    .await
}

pub(crate) async fn run_deferred_expose_reconcile(
    config: &ApmConfig,
    packages: &[String],
    registry_filter: Option<&str>,
    reinstall: bool,
    require_installed: bool,
    download_only: bool,
    no_deps: bool,
    dry_run: bool,
    yes: bool,
    ignore_lock: &IgnoreSysrootLock,
    printer: &Printer,
) -> Result<()> {
    run_inner(
        config,
        packages,
        registry_filter,
        reinstall,
        require_installed,
        download_only,
        no_deps,
        dry_run,
        yes,
        ignore_lock,
        printer,
        false,
    )
    .await
}

async fn run_inner(
    config: &ApmConfig,
    packages: &[String],
    registry_filter: Option<&str>,
    reinstall: bool,
    require_installed: bool,
    download_only: bool,
    no_deps: bool,
    dry_run: bool,
    yes: bool,
    ignore_lock: &IgnoreSysrootLock,
    printer: &Printer,
    reconcile_exposed_units: bool,
) -> Result<()> {
    let json_mode = printer.mode() == OutputMode::Json;
    if packages.is_empty() {
        if json_mode {
            printer.json(&serde_json::json!({
                "action": if reinstall { "reinstall" } else { "install" },
                "status": "no_packages",
                "requested": [],
            }));
        } else {
            printer.info("No packages specified.");
        }
        return Ok(());
    }

    // Step 1: Load registries from cache.
    printer.step(1, 7, "Loading registries...");
    let registries = load_registries(config)?;

    let inspect_profile = Profile::open_readonly(config.scope);
    let installed = list_meta(&inspect_profile)?;
    if require_installed || reinstall {
        ensure_reinstall_targets_installed(packages, &installed)?;
    }

    // Step 2: Resolve closures for all requested packages.
    printer.step(2, 7, "Resolving dependencies...");
    let mut closures = resolve_install_closures(
        &registries,
        packages,
        registry_filter,
        reinstall && registry_filter.is_none(),
        &installed,
    )?;
    if no_deps {
        ensure_skipped_dependencies_present(&closures).await?;
        prune_dependency_members(&mut closures);
    }
    admit_package_roots(closures.iter().flat_map(|closure| closure.closure.iter()))?;
    let all_metas = collect_unique_metas(&closures);
    let expose_artifacts = collect_expose_artifacts(&closures)?;
    let mut store_paths: Vec<String> = all_metas.iter().map(|m| m.store_path.clone()).collect();
    store_paths.extend(
        expose_artifacts
            .iter()
            .map(|artifact| artifact.store_path.clone()),
    );
    let missing = if reinstall {
        Vec::new()
    } else {
        filter_missing(&store_paths).await?
    };
    verify_install_provenance_from_cache_with_policy(config, &closures)?;

    if !reinstall
        && missing.is_empty()
        && requested_closures_already_installed(&closures, &installed)
    {
        if json_mode {
            printer.json(&install_result_json(
                "current",
                packages,
                &closures,
                reinstall,
                download_only,
                no_deps,
                false,
                &[],
                0,
                0,
                None,
            ));
        }
        if reconcile_exposed_units {
            reconcile_system_profile(config, printer).await?;
        }
        printer.info("All requested packages are already installed. No changes made.");
        return Ok(());
    }

    // Check if any requested package is already provided by the sysroot.
    for closure in &closures {
        if let Some((sys_name, sys_ver)) =
            crate::sysroot::check_sysroot_containment(&closure.root.references, config)
        {
            if json_mode {
                printer.json(&serde_json::json!({
                    "action": if reinstall { "reinstall" } else { "install" },
                    "status": "sysroot_provided",
                    "requested": packages,
                    "package": install_package_json(&closure.registry_name, &closure.root, true),
                    "sysroot": {
                        "name": sys_name,
                        "version": sys_ver,
                    },
                }));
            } else {
                printer.info(&format!(
                    "{} {} already provided by sysroot {} {}",
                    closure.root.name, closure.root.version, sys_name, sys_ver,
                ));
            }
            return Ok(());
        }
    }

    // Sysroot-lock check: verify package closures don't diverge from sysroot.
    if !matches!(ignore_lock, IgnoreSysrootLock::All) {
        if let Some((sysroot_refs, sys_name, sys_version)) =
            sysroot_lock::get_sysroot_references(config)
        {
            let lookup = sysroot_lock::build_registry_lookup(config);
            for closure in &closures {
                let pkg_refs: Vec<String> = closure
                    .closure
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

    // Step 4: Filter missing store paths.
    let to_download: Vec<&PackageMeta> = if reinstall {
        all_metas.clone()
    } else {
        let missing_set: HashSet<&str> = missing.iter().map(|s| s.as_str()).collect();
        all_metas
            .iter()
            .filter(|m| missing_set.contains(m.store_path.as_str()))
            .copied()
            .collect()
    };

    // Trust-graph totality (RFC-0005 §2.6): seed the context from the WHOLE
    // graph closure of each root (every reachable member, including
    // anonymous non-package store paths), so a stripped or partial graph
    // fails loudly and every byte that gets imported is enforced - not just
    // the resolved packages. Covers members already in the local store too,
    // which never reach the download/verify path.
    let trust_roots: Vec<(&str, &str)> = closures
        .iter()
        .map(|closure| {
            (
                closure.registry_name.as_str(),
                store_path_hash(&closure.root.store_path),
            )
        })
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

    // Step 5: Fetch narinfo for each missing path so the summary can show
    // real compressed sizes and the download can use the cache's URL/hash.
    let mut requests = build_download_requests(&closures, &to_download, config)?;
    requests.extend(build_expose_artifact_download_requests(
        &registries,
        &expose_artifacts,
        &missing,
        reinstall,
        config,
    )?);
    dedupe_download_requests(&mut requests);
    let engine = std::sync::Arc::new(default_engine());
    let resolved: Vec<ResolvedDownload> = if requests.is_empty() {
        Vec::new()
    } else if no_deps {
        let resolved = fetch_narinfos(
            std::sync::Arc::clone(&engine),
            &requests,
            config.settings.parallel_downloads,
            printer,
        )
        .await?;
        ensure_narinfo_references_present(&resolved).await?;
        order_resolved_downloads(&requests, resolved)?
    } else {
        fetch_narinfo_closure(
            std::sync::Arc::clone(&engine),
            &requests,
            config.settings.parallel_downloads,
            printer,
        )
        .await?
    };

    // Step 6: Print install summary.
    print_summary(
        &closures,
        packages,
        &resolved,
        &all_metas,
        reinstall,
        download_only,
        printer,
    );

    if dry_run {
        if json_mode {
            printer.json(&install_result_json(
                "planned",
                packages,
                &closures,
                reinstall,
                download_only,
                no_deps,
                true,
                &resolved,
                0,
                0,
                None,
            ));
        }
        printer.info("Dry run -- no changes made.");
        return Ok(());
    }

    // Step 7: Prompt for confirmation (unless --yes).
    if !yes && !config.settings.assume_yes {
        confirm(printer)?;
    }

    // Step 8: Download missing NARs.
    let mut downloaded_count = 0;
    let mut imported_count = 0;
    if !resolved.is_empty() {
        printer.step(3, 7, "Downloading packages...");

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
        // map (RFC-0005), falling back to narinfo hashes for legacy
        // registries. Closure totality was already enforced above.
        printer.step(4, 7, "Verifying downloads...");
        verify_downloads(&results, &trust_ctx, printer)?;
        verify_secondary_artifact_downloads(&results, &expose_artifacts)?;

        if download_only {
            if json_mode {
                printer.json(&install_result_json(
                    "downloaded",
                    packages,
                    &closures,
                    reinstall,
                    download_only,
                    no_deps,
                    false,
                    &resolved,
                    downloaded_count,
                    0,
                    None,
                ));
            }
            printer.success(&format!(
                "Downloaded {} NAR(s); no profile changes made.",
                results.len(),
            ));
            return Ok(());
        }

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
        if download_only {
            if json_mode {
                printer.json(&install_result_json(
                    "downloaded",
                    packages,
                    &closures,
                    reinstall,
                    download_only,
                    no_deps,
                    false,
                    &[],
                    0,
                    0,
                    None,
                ));
            }
            printer.info("Download only -- no profile changes made.");
            return Ok(());
        }
    }

    // Step 8: Create new profile generation.
    printer.step(6, 7, "Updating profile...");
    let profile = Profile::open(config.scope)?;
    let prev_gen = profile.current_generation()?;
    let new_gen = profile.new_generation()?;
    let explicit_names: HashSet<&str> = packages.iter().map(|s| s.as_str()).collect();
    let obsolete_hashes =
        obsolete_installed_hashes_after_install(&installed, &explicit_names, &closures)
            .await
            .context("computing post-install profile roots")?;

    // Copy existing roots from the previous generation (if any).
    if let Some(ref prev) = prev_gen {
        copy_roots_except_hashes(prev, &new_gen, &obsolete_hashes)?;
    }

    // Create GC roots for all closure members.
    let all_closure_metas: Vec<PackageMeta> = closures
        .iter()
        .flat_map(|c| c.closure.iter().cloned())
        .collect();
    // Deduplicate for GC root creation.
    let unique_for_roots: Vec<PackageMeta> = {
        let mut seen = HashSet::new();
        all_closure_metas
            .into_iter()
            .filter(|m| seen.insert(store_path_hash(&m.store_path).to_string()))
            .collect()
    };
    create_gc_roots(&new_gen.path, &unique_for_roots)?;

    // Write metadata -- explicit packages get explicit=true, deps get explicit=false.
    for hash in &obsolete_hashes {
        delete_meta(&profile, hash)?;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let now_iso = chrono_iso8601(now);
    let installed_flags_by_hash = installed_flags_by_hash(&installed);
    let installed_flags_by_name = installed_flags_by_name(&installed);

    for closure in &closures {
        for meta in &closure.closure {
            let hash = store_path_hash(&meta.store_path).to_string();
            let hash_flags = installed_flags_by_hash
                .get(hash.as_str())
                .copied()
                .unwrap_or_default();
            let name_flags = if explicit_names.contains(meta.name.as_str()) {
                installed_flags_by_name
                    .get(meta.name.as_str())
                    .copied()
                    .unwrap_or_default()
            } else {
                InstalledFlags::default()
            };
            let existing_flags = InstalledFlags {
                explicit: hash_flags.explicit || name_flags.explicit,
                held: hash_flags.held || name_flags.held,
            };
            let is_explicit =
                explicit_names.contains(meta.name.as_str()) || existing_flags.explicit;

            let installed = InstalledMeta {
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
                    explicit: is_explicit,
                    registry: closure.registry_name.clone(),
                    installed_at: now_iso.clone(),
                    held: existing_flags.held,
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

            write_meta(&profile, &hash, &installed)?;
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
    if reconcile_exposed_units {
        reconcile_system_profile(config, printer).await?;
    }

    printer.step(7, 7, "Done!");
    let verb = if reinstall {
        "Reinstalled"
    } else {
        "Installed"
    };
    printer.success(&format!(
        "{verb} {} package(s) in generation {}.",
        packages.len(),
        new_gen.number,
    ));
    if json_mode {
        printer.json(&install_result_json(
            if reinstall {
                "reinstalled"
            } else {
                "installed"
            },
            packages,
            &closures,
            reinstall,
            download_only,
            no_deps,
            false,
            &resolved,
            downloaded_count,
            imported_count,
            Some(new_gen.number),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Get the current platform string.
///
/// For now, hardcodes `x86_64-linux` (AOS target). Could detect from
/// `std::env::consts` in the future.
fn platform() -> String {
    "x86_64-linux".to_string()
}

/// Build the machine-readable result object emitted in JSON output mode:
/// action/status, the requested roots, the deduplicated closure, and
/// download/import counters.
fn install_result_json(
    status: &str,
    packages: &[String],
    closures: &[ResolvedClosure],
    reinstall: bool,
    download_only: bool,
    no_deps: bool,
    dry_run: bool,
    resolved_downloads: &[ResolvedDownload],
    downloaded: usize,
    imported: usize,
    generation: Option<u32>,
) -> serde_json::Value {
    serde_json::json!({
        "action": if reinstall { "reinstall" } else { "install" },
        "status": status,
        "requested": packages,
        "reinstall": reinstall,
        "download_only": download_only,
        "no_deps": no_deps,
        "dry_run": dry_run,
        "generation": generation,
        "roots": install_roots_json(closures),
        "closure": install_closure_json(packages, closures),
        "downloads": {
            "planned": resolved_downloads.len(),
            "downloaded": downloaded,
            "imported": imported,
            "paths": resolved_downloads_json(resolved_downloads),
        },
    })
}

/// JSON entries for the explicitly requested root packages.
fn install_roots_json(closures: &[ResolvedClosure]) -> Vec<serde_json::Value> {
    closures
        .iter()
        .map(|closure| install_package_json(&closure.registry_name, &closure.root, true))
        .collect()
}

/// JSON entries for every closure member, deduplicated by store hash, with
/// each entry flagged `explicit` when its name was requested directly.
fn install_closure_json(
    packages: &[String],
    closures: &[ResolvedClosure],
) -> Vec<serde_json::Value> {
    let explicit_names: HashSet<&str> = packages.iter().map(String::as_str).collect();
    let mut seen = HashSet::new();
    let mut entries = Vec::new();

    for closure in closures {
        for meta in &closure.closure {
            let hash = store_path_hash(&meta.store_path).to_string();
            if !seen.insert(hash) {
                continue;
            }
            entries.push(install_package_json(
                &closure.registry_name,
                meta,
                explicit_names.contains(meta.name.as_str()),
            ));
        }
    }

    entries
}

/// JSON object for a single package (name, version, registry, store path,
/// hashes, sizes, explicit/sysroot flags).
fn install_package_json(registry: &str, meta: &PackageMeta, explicit: bool) -> serde_json::Value {
    serde_json::json!({
        "name": meta.name.as_str(),
        "version": meta.version.as_str(),
        "registry": registry,
        "platform": meta.platform.as_str(),
        "store_path": meta.store_path.as_str(),
        "nar_hash": meta.nar_hash.as_str(),
        "nar_size": meta.nar_size,
        "closure_size": meta.closure_size,
        "explicit": explicit,
        "sysroot": meta.sysroot,
    })
}

/// Load registries from the config's cache directory.
pub(crate) fn load_registries(config: &ApmConfig) -> Result<RegistrySet> {
    let reg_configs = config.enabled_registries();
    RegistrySet::load(&config.cache_path(), &reg_configs, &platform())
}

/// Collect rendered expose artifacts needed for explicitly requested roots.
fn collect_expose_artifacts(
    closures: &[ResolvedClosure],
) -> Result<Vec<SecondaryArtifactDownload>> {
    let mut artifacts = Vec::new();
    let mut seen = HashMap::<String, usize>::new();

    for closure in closures {
        let Some(expose) = closure.root.expose.as_ref() else {
            continue;
        };
        let Some(artifact) = closure.root.expose_artifact.as_ref() else {
            anyhow::bail!(
                "package '{}' exposes systemd units but does not record an expose artifact",
                closure.root.name
            );
        };
        push_secondary_artifact(
            &mut artifacts,
            &mut seen,
            &closure.registry_name,
            &artifact.store_path,
            &artifact.nar_hash,
            true,
            false,
        )?;
        for image in &expose.images {
            push_secondary_artifact(
                &mut artifacts,
                &mut seen,
                &closure.registry_name,
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

#[cfg(test)]
fn verify_install_provenance_from_cache(
    registry_cache_root: &Path,
    closures: &[ResolvedClosure],
) -> Result<usize> {
    verify_package_provenance_entries_from_cache_inner(
        registry_cache_root,
        closures.iter().flat_map(|closure| {
            closure
                .closure
                .iter()
                .map(|meta| (closure.registry_name.as_str(), meta))
        }),
        &HashMap::new(),
    )
}

fn verify_install_provenance_from_cache_with_policy(
    config: &ApmConfig,
    closures: &[ResolvedClosure],
) -> Result<usize> {
    let policies = root_owner_signer_policies(config);
    verify_package_provenance_entries_from_cache_inner(
        &config.cache_path(),
        closures.iter().flat_map(|closure| {
            closure
                .closure
                .iter()
                .map(|meta| (closure.registry_name.as_str(), meta))
        }),
        &policies,
    )
}

pub(crate) fn verify_package_provenance_entries_from_cache_with_policy<'a>(
    config: &ApmConfig,
    entries: impl IntoIterator<Item = (&'a str, &'a PackageMeta)>,
) -> Result<usize> {
    let policies = root_owner_signer_policies(config);
    verify_package_provenance_entries_from_cache_inner(&config.cache_path(), entries, &policies)
}

fn root_owner_signer_policies(config: &ApmConfig) -> HashMap<String, HashSet<String>> {
    config
        .registries
        .iter()
        .map(|(registry, _)| {
            let signers = registry
                .signing
                .as_ref()
                .map(|signing| signing.root_owner_signers.iter().cloned().collect())
                .unwrap_or_default();
            (registry.name.clone(), signers)
        })
        .collect()
}

fn verify_package_provenance_entries_from_cache_inner<'a>(
    registry_cache_root: &Path,
    entries: impl IntoIterator<Item = (&'a str, &'a PackageMeta)>,
    root_owner_signers: &HashMap<String, HashSet<String>>,
) -> Result<usize> {
    let mut verified = 0;
    let mut transparency_logs = HashMap::<String, String>::new();
    let mut trusted_keys = HashMap::<String, Vec<provenance::TrustedProvenanceKey>>::new();

    for (registry_name, meta) in entries {
        let Some(provenance_ref) = meta.attestation.provenance.as_deref() else {
            if package_requires_provenance(meta) {
                anyhow::bail!(
                    "package '{}' uses RFC-0001 exposed or permission metadata but does not declare provenance",
                    meta.name
                );
            }
            continue;
        };
        ensure_safe_provenance_ref(provenance_ref)?;
        let (path, jsonl) =
            read_provenance_artifact(registry_cache_root, registry_name, provenance_ref)?;
        let registry_trusted_keys = match trusted_keys.entry(registry_name.to_string()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => entry.insert(
                read_registry_provenance_trusted_keys(registry_cache_root, registry_name)?,
            ),
        };
        let key_id = provenance::verify_package_statement(
            meta,
            registry_name,
            &jsonl,
            registry_trusted_keys,
        )
        .with_context(|| format!("verifying provenance artifact {}", path.display()))?;
        let transparency_log = match transparency_logs.entry(registry_name.to_string()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let (_, log) = read_registry_cache_artifact(
                    registry_cache_root,
                    registry_name,
                    provenance::PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                    "package transparency log",
                )?;
                entry.insert(log)
            }
        };
        let sequence =
            provenance::verify_transparency_log_inclusion(meta, &jsonl, transparency_log)
                .with_context(|| {
                    format!(
                        "verifying transparency inclusion for provenance artifact {}",
                        path.display()
                    )
                })?;
        provenance::verify_key_allowed_for_transparency_sequence(
            registry_trusted_keys,
            &key_id,
            sequence,
        )
        .with_context(|| format!("verifying provenance key lifetime for {}", path.display()))?;
        enforce_root_owner_signer(meta, registry_name, &key_id, root_owner_signers)?;
        verified += 1;
    }

    Ok(verified)
}

fn enforce_root_owner_signer(
    meta: &PackageMeta,
    registry_name: &str,
    authenticated_signer: &str,
    root_owner_signers: &HashMap<String, HashSet<String>>,
) -> Result<()> {
    if meta
        .config_module
        .as_ref()
        .is_some_and(|module| !module.owns_roots.is_empty())
        && !root_owner_signers
            .get(registry_name)
            .is_some_and(|allowed| allowed.contains(authenticated_signer))
    {
        anyhow::bail!(
            "package '{}@{}' claims shared-root ownership, but authenticated provenance signer '{}' is not in registry '{}' operator allowlist [registry.signing].root_owner_signers",
            meta.name,
            meta.version,
            authenticated_signer,
            registry_name
        );
    }
    Ok(())
}

fn read_provenance_artifact(
    registry_cache_root: &Path,
    registry_name: &str,
    provenance_ref: &str,
) -> Result<(PathBuf, String)> {
    ensure_safe_provenance_ref(provenance_ref)?;
    read_registry_cache_artifact(
        registry_cache_root,
        registry_name,
        provenance_ref,
        "provenance artifact",
    )
}

fn read_registry_provenance_trusted_keys(
    registry_cache_root: &Path,
    registry_name: &str,
) -> Result<Vec<provenance::TrustedProvenanceKey>> {
    let (path, content) =
        read_registry_cache_artifact(registry_cache_root, registry_name, "keys.toml", "keys.toml")?;
    let roster: keys::KeysToml =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    if roster.schema != keys::KEYS_TOML_SCHEMA {
        anyhow::bail!(
            "unsupported keys.toml schema {}: expected {}",
            roster.schema,
            keys::KEYS_TOML_SCHEMA
        );
    }
    if roster.active.is_empty() {
        anyhow::bail!(
            "registry '{}' has provenance but no active keys in keys.toml",
            registry_name
        );
    }
    let mut trusted = Vec::with_capacity(roster.active.len());
    for entry in &roster.active {
        if keys::is_revoked(&roster, &entry.id) {
            anyhow::bail!(
                "registry '{}' key id '{}' is both active and revoked in keys.toml",
                registry_name,
                entry.id
            );
        }
        let (entry_registry, _algorithm, _public_key) =
            super::security::parse_signing_key(&entry.key)
                .with_context(|| format!("invalid active key '{}'", entry.id))?;
        if entry_registry != registry_name {
            anyhow::bail!(
                "active provenance key '{}' belongs to registry '{}', expected '{}'",
                entry.id,
                entry_registry,
                registry_name
            );
        }
        trusted.push(provenance::TrustedProvenanceKey {
            key_id: entry.id.clone(),
            key: entry.key.clone(),
            retired_before_sequence: None,
        });
    }
    for entry in &roster.revoked {
        let Some(key) = entry.key.as_ref() else {
            continue;
        };
        let retired_before_sequence = entry.provenance_before_sequence.with_context(|| {
            format!(
                "revoked provenance key '{}' declares key material without provenance-before-sequence",
                entry.id
            )
        })?;
        let (entry_registry, _algorithm, _public_key) = super::security::parse_signing_key(key)
            .with_context(|| format!("invalid revoked key '{}'", entry.id))?;
        if entry_registry != registry_name {
            anyhow::bail!(
                "revoked provenance key '{}' belongs to registry '{}', expected '{}'",
                entry.id,
                entry_registry,
                registry_name
            );
        }
        trusted.push(provenance::TrustedProvenanceKey {
            key_id: entry.id.clone(),
            key: key.clone(),
            retired_before_sequence: Some(retired_before_sequence),
        });
    }
    Ok(trusted)
}

fn read_registry_cache_artifact(
    registry_cache_root: &Path,
    registry_name: &str,
    artifact_ref: &str,
    label: &str,
) -> Result<(PathBuf, String)> {
    validate_registry_name(registry_name)?;
    let registry_root = registry_cache_root.join(registry_name);
    let registry_meta = std::fs::symlink_metadata(&registry_root)
        .with_context(|| format!("reading registry cache {}", registry_root.display()))?;
    if registry_meta.file_type().is_symlink() {
        anyhow::bail!(
            "registry cache '{}' must not be a symlink",
            registry_root.display()
        );
    }
    if !registry_meta.is_dir() {
        anyhow::bail!(
            "registry cache '{}' is not a directory",
            registry_root.display()
        );
    }
    let mut path = registry_root.clone();
    let mut components = Path::new(artifact_ref).components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(part) = component else {
            anyhow::bail!("{label} path '{artifact_ref}' must not contain '.', '..', or prefixes");
        };
        path.push(part);
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| format!("reading {label} {}", path.display()))?;
        if meta.file_type().is_symlink() {
            anyhow::bail!(
                "{label} path '{}' must not contain symlinks: {}",
                artifact_ref,
                path.display()
            );
        }
        if components.peek().is_some() {
            if !meta.is_dir() {
                anyhow::bail!("{label} parent '{}' is not a directory", path.display());
            }
        } else if !meta.is_file() {
            anyhow::bail!("{label} '{}' is not a regular file", path.display());
        }
    }

    let registry_root = registry_root
        .canonicalize()
        .with_context(|| format!("canonicalizing registry cache {}", registry_root.display()))?;
    let canonical_path = path
        .canonicalize()
        .with_context(|| format!("canonicalizing {label} {}", path.display()))?;
    if !canonical_path.starts_with(&registry_root) {
        anyhow::bail!(
            "{label} '{}' escapes registry cache '{}'",
            canonical_path.display(),
            registry_root.display()
        );
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("reading {label} {}", path.display()))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .with_context(|| format!("reading {label} {}", path.display()))?;
    Ok((path, content))
}

fn ensure_safe_provenance_ref(path: &str) -> Result<()> {
    validate_attestation_provenance_ref(path)
}

/// Build NAR download requests for missing expose artifacts.
fn build_expose_artifact_download_requests(
    registries: &RegistrySet,
    artifacts: &[SecondaryArtifactDownload],
    missing_store_paths: &[String],
    download_all: bool,
    config: &ApmConfig,
) -> Result<Vec<DownloadRequest>> {
    let missing = missing_store_paths
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut requests = Vec::new();

    for artifact in artifacts {
        if !download_all && !missing.contains(artifact.store_path.as_str()) {
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

/// Resolve a closure per requested package.
///
/// With `preserve_installed_sources` (a reinstall without an explicit
/// `--registry`), each package is re-resolved from the registry it was
/// originally installed from instead of the highest-priority provider, so a
/// reinstall cannot silently switch a package's source.
fn resolve_install_closures(
    registries: &RegistrySet,
    packages: &[String],
    registry_filter: Option<&str>,
    preserve_installed_sources: bool,
    installed: &[InstalledMeta],
) -> Result<Vec<ResolvedClosure>> {
    if !preserve_installed_sources {
        return resolve_multiple(registries, packages, registry_filter);
    }

    let mut closures = Vec::with_capacity(packages.len());
    for package in packages {
        let registry_name = installed_source_registry(package, installed)
            .ok_or_else(|| anyhow::anyhow!("package not installed: {package}"))?;
        let resolved = resolve_multiple(
            registries,
            std::slice::from_ref(package),
            Some(registry_name),
        )
        .with_context(|| format!("resolving package '{package}'"))?;
        closures.extend(resolved);
    }
    Ok(closures)
}

/// The registry an installed package was originally installed from, if any.
fn installed_source_registry<'a>(package: &str, installed: &'a [InstalledMeta]) -> Option<&'a str> {
    let mut fallback = None;

    for meta in installed {
        let Some(apm) = meta.apm.as_ref() else {
            continue;
        };
        if apm.name != package {
            continue;
        }

        if apm.explicit {
            return Some(apm.registry.as_str());
        }
        if fallback.is_none() {
            fallback = Some(apm.registry.as_str());
        }
    }

    fallback
}

/// Whether the install would be a no-op: every requested root is already
/// installed explicitly *at the same store hash*, and every closure member
/// has an installed-metadata record.
fn requested_closures_already_installed(
    closures: &[ResolvedClosure],
    installed: &[InstalledMeta],
) -> bool {
    if closures.is_empty() {
        return false;
    }

    closures.iter().all(|closure| {
        let root_hash = store_path_hash(&closure.root.store_path);
        let root_explicit = installed_apm_for_hash(installed, root_hash)
            .map(|apm| apm.explicit)
            .unwrap_or(false);

        root_explicit
            && closure.closure.iter().all(|meta| {
                installed_apm_for_hash(installed, store_path_hash(&meta.store_path)).is_some()
            })
    })
}

/// Fail with a "package(s) not installed" error when any requested name has
/// no installed-metadata record (reinstall precondition).
fn ensure_reinstall_targets_installed(
    packages: &[String],
    installed: &[InstalledMeta],
) -> Result<()> {
    let installed_names: HashSet<&str> = installed
        .iter()
        .filter_map(|meta| meta.apm.as_ref().map(|apm| apm.name.as_str()))
        .collect();
    let missing: Vec<&str> = packages
        .iter()
        .map(String::as_str)
        .filter(|package| !installed_names.contains(package))
        .collect();

    match missing.as_slice() {
        [] => Ok(()),
        [package] => anyhow::bail!("package not installed: {package}"),
        packages => anyhow::bail!("packages not installed: {}", packages.join(", ")),
    }
}

/// Look up the apm metadata record for a store-path hash, if installed.
fn installed_apm_for_hash<'a>(installed: &'a [InstalledMeta], hash: &str) -> Option<&'a ApmMeta> {
    installed.iter().find_map(|meta| {
        if store_path_hash(&meta.store_path) == hash {
            meta.apm.as_ref()
        } else {
            None
        }
    })
}

/// The user-controlled flags carried across reinstalls: whether the package
/// was explicitly installed and whether it is held from upgrades.
#[derive(Clone, Copy, Default)]
struct InstalledFlags {
    explicit: bool,
    held: bool,
}

/// Index existing explicit/held flags by store-path hash, so an unchanged
/// path keeps its flags when its metadata is rewritten.
fn installed_flags_by_hash(installed: &[InstalledMeta]) -> HashMap<&str, InstalledFlags> {
    installed
        .iter()
        .filter_map(|meta| {
            let apm = meta.apm.as_ref()?;
            Some((
                store_path_hash(&meta.store_path),
                InstalledFlags {
                    explicit: apm.explicit,
                    held: apm.held,
                },
            ))
        })
        .collect()
}

/// Index existing explicit/held flags by package name, so a package whose
/// store path changed (reinstall from another registry) still keeps them.
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

/// `--no-deps`: shrink each closure to just its root package and fix up the
/// total NAR size accordingly.
fn prune_dependency_members(closures: &mut [ResolvedClosure]) {
    for closure in closures {
        let root_hash = store_path_hash(&closure.root.store_path).to_string();
        closure
            .closure
            .retain(|meta| store_path_hash(&meta.store_path) == root_hash);

        if closure.closure.is_empty() {
            closure.closure.push(closure.root.clone());
        }

        closure.total_nar_size = closure.closure.iter().map(|m| m.nar_size).sum();
    }
}

/// `--no-deps` safety check against registry metadata: every dependency
/// that would normally be installed must already exist in the local store,
/// otherwise installing only the roots would leave dangling references.
async fn ensure_skipped_dependencies_present(closures: &[ResolvedClosure]) -> Result<()> {
    let requested_hashes: HashSet<String> = closures
        .iter()
        .map(|closure| store_path_hash(&closure.root.store_path).to_string())
        .collect();
    let mut seen = HashSet::new();
    let mut skipped = Vec::new();

    for closure in closures {
        for meta in &closure.closure {
            let hash = store_path_hash(&meta.store_path).to_string();
            if requested_hashes.contains(&hash) || !seen.insert(hash) {
                continue;
            }
            skipped.push(meta);
        }
    }

    if skipped.is_empty() {
        return Ok(());
    }

    let store_paths: Vec<String> = skipped.iter().map(|meta| meta.store_path.clone()).collect();
    let missing = filter_missing(&store_paths).await?;
    if missing.is_empty() {
        return Ok(());
    }

    let missing_set: HashSet<&str> = missing.iter().map(|path| path.as_str()).collect();
    let labels: Vec<String> = skipped
        .iter()
        .filter(|meta| missing_set.contains(meta.store_path.as_str()))
        .map(|meta| format!("{} ({})", meta.name, meta.store_path))
        .collect();

    anyhow::bail!(
        "--no-deps requested but dependency store path(s) are missing: {}",
        labels.join(", ")
    );
}

/// `--no-deps` safety check against fetched narinfos: the references the
/// binary cache reports for each root (which can be more current than the
/// registry metadata) must also be present locally before import.
async fn ensure_narinfo_references_present(resolved: &[ResolvedDownload]) -> Result<()> {
    let requested_hashes: HashSet<String> = resolved
        .iter()
        .map(|item| narinfo::store_hash(&item.narinfo.store_path).to_string())
        .collect();
    let mut seen = HashSet::new();
    let mut references = Vec::new();

    for item in resolved {
        let parent_hash = narinfo::store_hash(&item.narinfo.store_path);

        for reference in &item.narinfo.references {
            let reference_hash = narinfo::store_hash(reference);
            if reference_hash == parent_hash
                || requested_hashes.contains(reference_hash)
                || !seen.insert(reference_hash.to_string())
            {
                continue;
            }

            references.push(reference_store_path(reference, &item.narinfo.store_path));
        }
    }

    if references.is_empty() {
        return Ok(());
    }

    let missing = filter_missing(&references).await?;
    if missing.is_empty() {
        return Ok(());
    }

    anyhow::bail!(
        "--no-deps requested but dependency store path(s) are missing: {}",
        missing.join(", ")
    );
}

/// Store-path hashes no longer needed after an install or reinstall.
///
/// The new closure is always needed. Live closures of unrelated explicit
/// packages are also needed so their shared implicit dependencies remain
/// rooted. Other APM-installed entries can be dropped from the next
/// generation.
async fn obsolete_installed_hashes_after_install(
    installed: &[InstalledMeta],
    explicit_names: &HashSet<&str>,
    closures: &[ResolvedClosure],
) -> Result<HashSet<String>> {
    let mut needed = HashSet::new();
    for closure in closures {
        for meta in &closure.closure {
            needed.insert(store_path_hash(&meta.store_path).to_string());
            if !meta.source_drv.is_empty() {
                needed.insert(store_path_hash(&meta.source_drv).to_string());
            }
        }
    }

    let pending_remove_hashes = hashes_for_installed_names(installed, explicit_names);
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
        if !apm.source_drv.is_empty() {
            needed.insert(store_path_hash(&apm.source_drv).to_string());
        }
    }

    Ok(obsolete_installed_hashes(installed, &needed))
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

/// Copy the `usr/` and `src/` GC-root symlinks from one generation to
/// another, skipping the hashes in `skip_hashes` (replaced packages) and
/// never overwriting links already present in the destination.
pub(crate) fn copy_roots_except_hashes(
    from: &super::profile::Generation,
    to: &super::profile::Generation,
    skip_hashes: &HashSet<String>,
) -> Result<()> {
    use std::os::unix::fs::symlink;

    // Copy usr/ roots.
    let from_usr = from.path.join("usr");
    let to_usr = to.path.join("usr");
    std::fs::create_dir_all(&to_usr).with_context(|| format!("creating {}", to_usr.display()))?;

    if from_usr.is_dir() {
        for entry in std::fs::read_dir(&from_usr)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if skip_hashes.contains(name_str.as_ref()) {
                continue;
            }
            let target = std::fs::read_link(entry.path())?;
            let dest = to_usr.join(&name);
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
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if skip_hashes.contains(name_str.as_ref()) {
                continue;
            }
            let target = std::fs::read_link(entry.path())?;
            let dest = to_src.join(&name);
            if !dest.symlink_metadata().is_ok() {
                symlink(&target, &dest).with_context(|| {
                    format!("copying root {} -> {}", dest.display(), target.display())
                })?;
            }
        }
    }

    Ok(())
}

/// Copy GC root symlinks from a previous generation to a new one,
/// skipping roots for packages being upgraded.
///
/// Used by the upgrade module to carry forward non-upgraded packages while
/// replacing the old store paths of upgraded ones with new ones. Existing
/// links in the destination generation are never overwritten.
///
/// # Errors
///
/// Returns an error when the destination `usr/`/`src/` directories cannot be
/// created, a source entry cannot be read as a symlink, or creating a
/// destination symlink fails.
pub fn copy_roots_for_upgrade(
    from: &super::profile::Generation,
    to: &super::profile::Generation,
    to_upgrade: &[super::upgrade::UpgradeCandidate],
) -> Result<()> {
    use std::os::unix::fs::symlink;

    let skip_hashes: HashSet<&str> = to_upgrade
        .iter()
        .map(|c| c.old_store_hash.as_str())
        .collect();

    // Copy usr/ roots, skipping upgraded packages.
    let from_usr = from.path.join("usr");
    let to_usr = to.path.join("usr");
    std::fs::create_dir_all(&to_usr).with_context(|| format!("creating {}", to_usr.display()))?;

    if from_usr.is_dir() {
        for entry in std::fs::read_dir(&from_usr)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if skip_hashes.contains(name_str.as_ref()) {
                continue;
            }
            let target = std::fs::read_link(entry.path())?;
            let dest = to_usr.join(&name);
            if !dest.symlink_metadata().is_ok() {
                symlink(&target, &dest).with_context(|| {
                    format!("copying root {} -> {}", dest.display(), target.display())
                })?;
            }
        }
    }

    // Copy src/ roots, skipping upgraded packages.
    let from_src = from.path.join("src");
    let to_src = to.path.join("src");
    std::fs::create_dir_all(&to_src).with_context(|| format!("creating {}", to_src.display()))?;

    if from_src.is_dir() {
        for entry in std::fs::read_dir(&from_src)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if skip_hashes.contains(name_str.as_ref()) {
                continue;
            }
            let target = std::fs::read_link(entry.path())?;
            let dest = to_src.join(&name);
            if !dest.symlink_metadata().is_ok() {
                symlink(&target, &dest).with_context(|| {
                    format!("copying root {} -> {}", dest.display(), target.display())
                })?;
            }
        }
    }

    Ok(())
}

/// Prompt for confirmation.  Returns `Err(UserCancelled)` on "n".
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

/// Print the install summary showing what will be installed.
fn print_summary(
    closures: &[ResolvedClosure],
    explicit_names: &[String],
    resolved: &[ResolvedDownload],
    all_metas: &[&PackageMeta],
    reinstall: bool,
    download_only: bool,
    printer: &Printer,
) {
    let explicit_set: HashSet<&str> = explicit_names.iter().map(|s| s.as_str()).collect();

    // Collect explicitly-requested packages.
    let mut new_packages: Vec<String> = Vec::new();
    let mut dep_packages: Vec<String> = Vec::new();

    for closure in closures {
        for meta in &closure.closure {
            let label = format!(
                "{} ({}, {})",
                meta.name, meta.version, closure.registry_name
            );
            if explicit_set.contains(meta.name.as_str()) {
                if !new_packages.iter().any(|s| s.starts_with(&meta.name)) {
                    new_packages.push(label);
                }
            } else if !dep_packages.iter().any(|s| s.starts_with(&meta.name)) {
                dep_packages.push(label);
            }
        }
    }

    if download_only {
        printer.header("The following packages will be downloaded:");
    } else if reinstall {
        printer.header("The following packages will be reinstalled:");
    } else {
        printer.header("The following NEW packages will be installed:");
    }
    for pkg in &new_packages {
        printer.plain(&format!("  {pkg}"));
    }

    if !dep_packages.is_empty() {
        printer.header("Additional dependencies:");
        for pkg in &dep_packages {
            printer.plain(&format!("  {pkg}"));
        }
    }

    let download_size: u64 = resolved
        .iter()
        .map(|r| r.narinfo.file_size.unwrap_or(0))
        .sum();
    let installed_size: u64 = all_metas.iter().map(|m| m.nar_size).sum();

    printer.plain(&format!(
        "Need to download {} / {} installed.",
        format_size(download_size),
        format_size(installed_size),
    ));
}

/// Build `DownloadRequest`s for the missing packages.
///
/// The mirror URL is determined from the registry config that provided
/// each package.
fn build_download_requests(
    closures: &[ResolvedClosure],
    to_download: &[&PackageMeta],
    config: &ApmConfig,
) -> Result<Vec<DownloadRequest>> {
    // Build a map of registry_name -> mirror chain (primary + fallbacks) for
    // quick lookup. The chain enables narinfo/NAR miss-fallthrough.
    let registries_base = config.scope.registries_path();
    let mirror_map: std::collections::HashMap<String, Vec<String>> = closures
        .iter()
        .map(|c| {
            let reg_config = config
                .registries
                .iter()
                .find(|(cfg, _)| cfg.name == c.registry_name)
                .map(|(cfg, _)| cfg);
            let chain = if let Some(cfg) = reg_config {
                resolve_mirror_chain(&registries_base, cfg)
            } else {
                // Fallback: construct from the default pattern.
                vec![format!("https://registry.aos.dev/{}", c.registry_name)]
            };
            (c.registry_name.clone(), chain)
        })
        .collect();

    // Build a map of store_path_hash -> registry_name for each closure member.
    let mut hash_to_registry: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for closure in closures {
        for meta in &closure.closure {
            let hash = store_path_hash(&meta.store_path).to_string();
            hash_to_registry
                .entry(hash)
                .or_insert_with(|| closure.registry_name.clone());
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

/// Format a Unix timestamp as a simplified ISO 8601 string.
///
/// Produces `YYYY-MM-DDTHH:MM:SSZ` in UTC.  Does not depend on external
/// crates -- uses manual division to avoid adding a time dependency.
fn chrono_iso8601(epoch_secs: i64) -> String {
    // Simple approach: delegate to the system for formatting.
    // For a minimal implementation without chrono, we compute manually.
    let secs_per_day: i64 = 86400;
    let days = epoch_secs / secs_per_day;
    let day_secs = (epoch_secs % secs_per_day) as u32;

    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Convert days since epoch to Y-M-D (simplified Gregorian).
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch (1970-01-01) to (year, month, day).
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
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
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    use crate::profile::Generation;
    use crate::types::{
        AttestationMeta, ConfigModuleMeta, ConfigOutputMeta, ExposeArtifactMeta, ExposeMeta,
        ModuleAbiCompat, OwnedRoot, SysrootImageEntry,
    };
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    const TEST_PROVENANCE_KEY_ID: &str = "builder";

    #[test]
    fn format_size_bytes() {
        assert_eq!(format_size(500), "500 B");
    }

    #[test]
    fn format_size_zero() {
        assert_eq!(format_size(0), "0 B");
    }

    #[test]
    fn format_size_kib() {
        assert_eq!(format_size(2048), "2.0 KiB");
    }

    #[test]
    fn format_size_mib() {
        assert_eq!(format_size(3_300_000), "3.1 MiB");
    }

    #[test]
    fn format_size_gib() {
        assert_eq!(format_size(2_147_483_648), "2.0 GiB");
    }

    #[test]
    fn format_size_boundary_1024() {
        // Exactly 1024 bytes should display as KiB.
        assert_eq!(format_size(1024), "1.0 KiB");
    }

    #[test]
    fn platform_returns_valid() {
        let p = platform();
        assert_eq!(p, "x86_64-linux");
    }

    fn sample_package(name: &str, version: &str, store_path: &str) -> PackageMeta {
        PackageMeta {
            name: name.to_string(),
            version: version.to_string(),
            description: String::new(),
            homepage: None,
            license: "MIT".to_string(),
            maintainer: "test".to_string(),
            platform: "x86_64-linux".to_string(),
            store_path: store_path.to_string(),
            nar_hash: "sha256:test".to_string(),
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

    fn add_owned_root(meta: &mut PackageMeta, root: &str) {
        meta.config_module = Some(ConfigModuleMeta {
            config_output: ConfigOutputMeta {
                store_path: "/nix/store/0000000000000000000000000000000a-config".to_string(),
                nar_hash: "sha256:test".to_string(),
                nar_size: 1,
                references: Vec::new(),
            },
            evaluation_base_lib: None,
            module_abi_compat: ModuleAbiCompat { min: 1, max: 1 },
            declares: Vec::new(),
            declaration_schema: Vec::new(),
            requires: Vec::new(),
            owns_roots: vec![OwnedRoot {
                root: root.to_string(),
                interface_abi: 1,
                contributable: Vec::new(),
            }],
            contributes: Vec::new(),
            provides_capabilities: Vec::new(),
        });
    }

    #[test]
    fn root_owner_requires_authenticated_signer_in_operator_allowlist() {
        let mut meta = sample_package("firewall", "1.0.0", "/var/lib/store/root-firewall");
        add_owned_root(&mut meta, "firewall");

        let mut policies = HashMap::new();
        policies.insert(
            "test-reg".to_string(),
            HashSet::from(["release".to_string()]),
        );
        let error = enforce_root_owner_signer(&meta, "test-reg", "builder", &policies)
            .expect_err("non-allowlisted signer must not grant root ownership");
        assert!(error.to_string().contains("operator allowlist"), "{error}");

        policies
            .get_mut("test-reg")
            .expect("test policy")
            .insert("builder".to_string());
        enforce_root_owner_signer(&meta, "test-reg", "builder", &policies)
            .expect("allowlisted authenticated signer grants ownership");
    }

    #[test]
    fn packages_without_root_claims_preserve_compatibility_without_allowlist() {
        let meta = sample_package("curl", "1.0.0", "/var/lib/store/root-curl");
        enforce_root_owner_signer(&meta, "test-reg", "builder", &HashMap::new())
            .expect("ordinary packages do not require the privileged signer allowlist");
    }

    fn sample_installed(name: &str, version: &str, store_path: &str) -> InstalledMeta {
        sample_installed_with_explicit(name, version, store_path, true)
    }

    fn sample_installed_with_explicit(
        name: &str,
        version: &str,
        store_path: &str,
        explicit: bool,
    ) -> InstalledMeta {
        InstalledMeta {
            store_path: store_path.to_string(),
            pushed_at: 1,
            pushed_by: "apm".to_string(),
            expires_at: None,
            is_root: true,
            last_accessed: 1,
            access_count: 0,
            apm: Some(ApmMeta {
                name: name.to_string(),
                version: version.to_string(),
                explicit,
                registry: "test-reg".to_string(),
                installed_at: "2026-06-09T00:00:00Z".to_string(),
                held: false,
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

    fn sample_installed_with_flags(
        name: &str,
        version: &str,
        store_path: &str,
        explicit: bool,
        held: bool,
    ) -> InstalledMeta {
        let mut meta = sample_installed_with_explicit(name, version, store_path, explicit);
        meta.apm.as_mut().unwrap().held = held;
        meta
    }

    fn sample_installed_from_registry(
        name: &str,
        version: &str,
        registry: &str,
        store_path: &str,
    ) -> InstalledMeta {
        sample_installed_from_registry_with_flags(name, version, registry, store_path, true, false)
    }

    fn sample_installed_from_registry_with_flags(
        name: &str,
        version: &str,
        registry: &str,
        store_path: &str,
        explicit: bool,
        held: bool,
    ) -> InstalledMeta {
        let mut meta = sample_installed_with_flags(name, version, store_path, explicit, held);
        meta.apm.as_mut().unwrap().registry = registry.to_string();
        meta
    }

    fn sample_closure(root: PackageMeta, closure: Vec<PackageMeta>) -> ResolvedClosure {
        ResolvedClosure {
            registry_name: "test-reg".to_string(),
            root,
            closure,
            total_nar_size: 1,
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
            root_image: None,
            root_verity: None,
            root_hash: None,
            root_hash_sig: None,
        }
    }

    fn attested_sample_package() -> PackageMeta {
        let root_hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let manifest_digest =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let measurement = crate::package_attestation::package_measurement_digest(
            "web",
            "1.0.0",
            root_hash,
            manifest_digest,
        );
        let measurement_hex = measurement.trim_start_matches("sha256:");
        let mut meta = sample_package("web", "1.0.0", "/nix/store/abc123-web-1.0.0");
        meta.nar_hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();
        meta.source_drv = "/nix/store/srcdrv-web-1.0.0.drv".to_string();
        meta.source_nar_hash = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string();
        meta.attestation = AttestationMeta {
            root_digest: Some(root_hash.to_string()),
            root_hash: Some(root_hash.to_string()),
            root_hash_sig: Some("root.roothash.p7s".to_string()),
            provenance: Some(format!(
                "provenance/w/web/x86_64-linux/{measurement_hex}.intoto.jsonl"
            )),
            measurement: Some(measurement),
        };
        meta
    }

    fn write_test_provenance_keys(root: &Path, registry_name: &str) {
        let registry_root = root.join(registry_name);
        std::fs::create_dir_all(&registry_root).unwrap();
        let keypair = crate::sshkey::Ed25519Keypair::from_seed([42_u8; 32]);
        keys::write_keys_toml(
            &registry_root,
            &keys::KeysToml {
                active: vec![keys::RosterKey {
                    id: TEST_PROVENANCE_KEY_ID.to_string(),
                    key: keypair.trust_key_line(registry_name),
                }],
                ..keys::KeysToml::default()
            },
        )
        .unwrap();
    }

    fn provenance_statement(meta: &PackageMeta) -> String {
        let root_digest = meta.attestation.root_digest.as_deref().unwrap();
        let root_hash = meta.attestation.root_hash.as_deref().unwrap();
        let root_hash_sig = meta.attestation.root_hash_sig.as_deref().unwrap();
        let provenance = meta.attestation.provenance.as_deref().unwrap();
        let measurement = meta.attestation.measurement.as_deref().unwrap();
        let manifest_digest =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let source_uri = format!("nix:{}", meta.source_drv);
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": meta.store_path.as_str(),
                    "digest": crate::provenance::digest_map(&meta.nar_hash),
                },
                {
                    "name": format!(
                        "aos:permissions-manifest:{}:{}:{}",
                        meta.name, meta.version, meta.platform
                    ),
                    "digest": crate::provenance::digest_map(manifest_digest),
                },
                {
                    "name": format!(
                        "aos:package-measurement:{}:{}:{}",
                        meta.name, meta.version, meta.platform
                    ),
                    "digest": crate::provenance::digest_map(measurement),
                },
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://andyl.com/aos/apr-publish/v1",
                    "externalParameters": {
                        "package": meta.name.as_str(),
                        "version": meta.version.as_str(),
                        "platform": meta.platform.as_str(),
                        "store_path": meta.store_path.as_str(),
                        "root_digest": root_digest,
                        "root_hash": root_hash,
                        "root_hash_sig": root_hash_sig,
                        "provenance": provenance,
                    },
                    "resolvedDependencies": [
                        {
                            "uri": source_uri,
                            "digest": crate::provenance::digest_map(&meta.source_nar_hash),
                        },
                    ],
                },
                "runDetails": {
                    "builder": {
                        "id": crate::provenance::builder_id("test-reg", TEST_PROVENANCE_KEY_ID),
                    },
                },
            },
        });
        let tmp = TempDir::new().unwrap();
        let keypair = crate::sshkey::Ed25519Keypair::from_seed([42_u8; 32]);
        let private_key = tmp.path().join("builder_ed25519");
        std::fs::write(&private_key, keypair.to_openssh_private_key("test-reg")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        crate::provenance::sign_statement_dsse_jsonl(
            &statement,
            TEST_PROVENANCE_KEY_ID,
            &private_key,
        )
        .unwrap()
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestTransparencyLogEntry {
        body: TestTransparencyLogBody,
        entry_hash: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestTransparencyLogBody {
        schema: String,
        sequence: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_entry_hash: Option<String>,
        package: String,
        version: String,
        platform: String,
        store_path: String,
        nar_hash: String,
        nar_size: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        root_digest: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        root_hash: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        root_hash_sig: Option<String>,
        provenance: String,
        measurement: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<TestTransparencySource>,
        statement: TestTransparencyStatement,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestTransparencySource {
        store_path: String,
        nar_hash: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestTransparencyStatement {
        path: String,
        jsonl_sha256: String,
    }

    fn write_transparency_log(root: &Path, registry_name: &str, meta: &PackageMeta, jsonl: &str) {
        let provenance_ref = meta.attestation.provenance.as_deref().unwrap();
        let body = TestTransparencyLogBody {
            schema: "https://andyl.com/aos/transparency/package-provenance/v1".to_string(),
            sequence: 0,
            previous_entry_hash: None,
            package: meta.name.clone(),
            version: meta.version.clone(),
            platform: meta.platform.clone(),
            store_path: meta.store_path.clone(),
            nar_hash: meta.nar_hash.clone(),
            nar_size: meta.nar_size,
            root_digest: meta.attestation.root_digest.clone(),
            root_hash: meta.attestation.root_hash.clone(),
            root_hash_sig: meta.attestation.root_hash_sig.clone(),
            provenance: provenance_ref.to_string(),
            measurement: meta.attestation.measurement.clone().unwrap(),
            source: Some(TestTransparencySource {
                store_path: meta.source_drv.clone(),
                nar_hash: meta.source_nar_hash.clone(),
            }),
            statement: TestTransparencyStatement {
                path: provenance_ref.to_string(),
                jsonl_sha256: format!("sha256:{}", test_sha256_hex(jsonl.as_bytes())),
            },
        };
        let payload = serde_json::to_vec(&body).unwrap();
        let entry = TestTransparencyLogEntry {
            body,
            entry_hash: format!("sha256:{}", test_sha256_hex(&payload)),
        };
        let path = root
            .join(registry_name)
            .join(provenance::PACKAGE_PROVENANCE_TRANSPARENCY_LOG);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&entry).unwrap()),
        )
        .unwrap();
    }

    fn test_sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn collect_expose_artifacts_includes_expose_images() {
        let mut root = sample_package("web", "1.0.0", "/var/lib/store/root-web");
        root.expose = Some(ExposeMeta {
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
        root.expose_artifact = Some(ExposeArtifactMeta {
            store_path: "/var/lib/store/expose-web".to_string(),
            nar_hash: "sha256:expose".to_string(),
            nar_size: 1,
        });

        let artifacts = collect_expose_artifacts(&[sample_closure(root.clone(), vec![root])])
            .expect("collect expose artifacts");

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
    fn verify_install_provenance_from_cache_reads_registry_artifact() {
        let tmp = TempDir::new().unwrap();
        let meta = attested_sample_package();
        let provenance = meta.attestation.provenance.as_deref().unwrap();
        let path = tmp.path().join("test-reg").join(provenance);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let jsonl = provenance_statement(&meta);
        std::fs::write(&path, &jsonl).unwrap();
        write_test_provenance_keys(tmp.path(), "test-reg");
        write_transparency_log(tmp.path(), "test-reg", &meta, &jsonl);

        let count = verify_install_provenance_from_cache(
            tmp.path(),
            &[sample_closure(meta.clone(), vec![meta])],
        )
        .unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn verify_install_provenance_from_cache_rejects_missing_artifact() {
        let tmp = TempDir::new().unwrap();
        let meta = attested_sample_package();
        std::fs::create_dir_all(tmp.path().join("test-reg")).unwrap();

        let err = verify_install_provenance_from_cache(
            tmp.path(),
            &[sample_closure(meta.clone(), vec![meta])],
        )
        .unwrap_err();

        assert!(err.to_string().contains("reading provenance artifact"));
    }

    #[test]
    fn verify_install_provenance_from_cache_rejects_unsafe_ref() {
        let tmp = TempDir::new().unwrap();
        let mut meta = attested_sample_package();
        meta.attestation.provenance = Some("../evil.jsonl".to_string());

        let err = verify_install_provenance_from_cache(
            tmp.path(),
            &[sample_closure(meta.clone(), vec![meta])],
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("must not contain '.', '..', or prefixes")
        );
    }

    #[test]
    fn verify_install_provenance_from_cache_rejects_cache_owned_ref() {
        let tmp = TempDir::new().unwrap();
        let mut meta = attested_sample_package();
        meta.attestation.provenance = Some("packages/w/web.provenance.jsonl".to_string());
        let provenance = meta.attestation.provenance.as_deref().unwrap();
        let path = tmp.path().join("test-reg").join(provenance);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, provenance_statement(&meta)).unwrap();

        let err = verify_install_provenance_from_cache(
            tmp.path(),
            &[sample_closure(meta.clone(), vec![meta])],
        )
        .unwrap_err();

        assert!(
            format!("{err:#}").contains("must not target a cache-owned subtree"),
            "{err:#}",
        );
    }

    #[test]
    fn verify_install_provenance_from_cache_rejects_symlink_parent() {
        let tmp = TempDir::new().unwrap();
        let meta = attested_sample_package();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(tmp.path().join("test-reg")).unwrap();
        symlink(&outside, tmp.path().join("test-reg").join("provenance")).unwrap();

        let err = verify_install_provenance_from_cache(
            tmp.path(),
            &[sample_closure(meta.clone(), vec![meta])],
        )
        .unwrap_err();

        assert!(err.to_string().contains("must not contain symlinks"));
    }

    #[test]
    fn verify_install_provenance_from_cache_rejects_symlink_file() {
        let tmp = TempDir::new().unwrap();
        let meta = attested_sample_package();
        let provenance = meta.attestation.provenance.as_deref().unwrap();
        let path = tmp.path().join("test-reg").join(provenance);
        let outside = tmp.path().join("outside.jsonl");
        std::fs::write(&outside, provenance_statement(&meta)).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        symlink(&outside, &path).unwrap();

        let err = verify_install_provenance_from_cache(
            tmp.path(),
            &[sample_closure(meta.clone(), vec![meta])],
        )
        .unwrap_err();

        assert!(err.to_string().contains("must not contain symlinks"));
    }

    #[test]
    fn verify_install_provenance_from_cache_rejects_exposed_without_provenance() {
        let mut meta = sample_package("web", "1.0.0", "/var/lib/store/root-web");
        meta.expose = Some(ExposeMeta {
            target: "web.target".to_string(),
            units: vec!["web.service".to_string()],
            images: Vec::new(),
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        });

        let err = verify_install_provenance_from_cache(
            TempDir::new().unwrap().path(),
            &[sample_closure(meta.clone(), vec![meta])],
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("does not declare provenance"));
    }

    #[test]
    fn collect_expose_artifacts_rejects_incompatible_duplicate_roles() {
        let shared_path = "/var/lib/store/shared-secondary";
        let mut image_root = sample_package("web", "1.0.0", "/var/lib/store/root-web");
        image_root.expose = Some(ExposeMeta {
            target: "web.target".to_string(),
            units: vec!["web.service".to_string()],
            images: vec![sample_expose_image(shared_path, "sha256:shared")],
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        });
        image_root.expose_artifact = Some(ExposeArtifactMeta {
            store_path: "/var/lib/store/expose-web".to_string(),
            nar_hash: "sha256:web-expose".to_string(),
            nar_size: 1,
        });
        let mut artifact_root = sample_package("api", "1.0.0", "/var/lib/store/root-api");
        artifact_root.expose = Some(ExposeMeta {
            target: "api.target".to_string(),
            units: vec!["api.service".to_string()],
            images: Vec::new(),
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        });
        artifact_root.expose_artifact = Some(ExposeArtifactMeta {
            store_path: shared_path.to_string(),
            nar_hash: "sha256:shared".to_string(),
            nar_size: 1,
        });

        let err = collect_expose_artifacts(&[
            sample_closure(image_root.clone(), vec![image_root]),
            sample_closure(artifact_root.clone(), vec![artifact_root]),
        ])
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

    fn package_toml(name: &str, version: &str, store_path: &str) -> String {
        format!(
            r#"[package]
name = "{name}"
description = "test package"
license = "MIT"
maintainer = "test"

[[versions]]
version = "{version}"

[versions.platforms.x86_64-linux]
store_path = "{store_path}"
nar_hash = "sha256-test"
nar_size = 1
closure_size = 1
references = []
source_drv = ""
source_nar_hash = ""
"#
        )
    }

    #[test]
    fn reinstall_resolution_preserves_installed_source_registry() {
        let tmp = TempDir::new().unwrap();
        let high_path = "/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-switch-tool-1.0.0";
        let low_path = "/nix/store/llllllllllllllllllllllllllllllll-switch-tool-1.0.0";
        let high_toml = package_toml("switch-tool", "1.0.0", high_path);
        let low_toml = package_toml("switch-tool", "1.0.0", low_path);
        let high = crate::registry::tests::make_registry(
            &tmp,
            "high-priority",
            900,
            &[("switch-tool", high_toml.as_str())],
        );
        let low = crate::registry::tests::make_registry(
            &tmp,
            "low-priority",
            100,
            &[("switch-tool", low_toml.as_str())],
        );
        let registries = RegistrySet::new(vec![high, low]);
        let installed = vec![sample_installed_from_registry(
            "switch-tool",
            "1.0.0",
            "low-priority",
            low_path,
        )];
        let packages = vec!["switch-tool".to_string()];

        let closures =
            resolve_install_closures(&registries, &packages, None, true, &installed).unwrap();

        assert_eq!(closures.len(), 1);
        assert_eq!(closures[0].registry_name, "low-priority");
        assert_eq!(closures[0].root.store_path, low_path);
    }

    #[test]
    fn reinstall_resolution_prefers_explicit_duplicate_source_registry() {
        let tmp = TempDir::new().unwrap();
        let high_path = "/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-priority-tool-2.0.0";
        let low_path = "/nix/store/llllllllllllllllllllllllllllllll-priority-tool-9.0.0";
        let high_toml = package_toml("priority-tool", "2.0.0", high_path);
        let low_toml = package_toml("priority-tool", "9.0.0", low_path);
        let high = crate::registry::tests::make_registry(
            &tmp,
            "high-priority",
            900,
            &[("priority-tool", high_toml.as_str())],
        );
        let low = crate::registry::tests::make_registry(
            &tmp,
            "low-priority",
            100,
            &[("priority-tool", low_toml.as_str())],
        );
        let registries = RegistrySet::new(vec![high, low]);
        let installed = vec![
            sample_installed_from_registry_with_flags(
                "priority-tool",
                "9.0.0",
                "low-priority",
                low_path,
                false,
                false,
            ),
            sample_installed_from_registry_with_flags(
                "priority-tool",
                "2.0.0",
                "high-priority",
                high_path,
                true,
                true,
            ),
        ];
        let packages = vec!["priority-tool".to_string()];

        let closures =
            resolve_install_closures(&registries, &packages, None, true, &installed).unwrap();

        assert_eq!(closures.len(), 1);
        assert_eq!(closures[0].registry_name, "high-priority");
        assert_eq!(closures[0].root.store_path, high_path);
    }

    #[test]
    fn requested_closures_already_installed_matches_exact_closure() {
        let root_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-idempkg-1.0.0";
        let dep_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-libdep-1.0.0";
        let root = sample_package("idempkg", "1.0.0", root_path);
        let dep = sample_package("libdep", "1.0.0", dep_path);
        let closure = sample_closure(root.clone(), vec![dep.clone(), root]);
        let installed = vec![
            sample_installed("idempkg", "1.0.0", root_path),
            sample_installed("libdep", "1.0.0", dep_path),
        ];

        assert!(requested_closures_already_installed(&[closure], &installed));
    }

    #[test]
    fn requested_closures_already_installed_requires_dependencies() {
        let root_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-idempkg-1.0.0";
        let dep_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-libdep-1.0.0";
        let root = sample_package("idempkg", "1.0.0", root_path);
        let dep = sample_package("libdep", "1.0.0", dep_path);
        let closure = sample_closure(root.clone(), vec![dep, root]);
        let installed = vec![sample_installed("idempkg", "1.0.0", root_path)];

        assert!(!requested_closures_already_installed(
            &[closure],
            &installed
        ));
    }

    #[test]
    fn requested_closures_already_installed_requires_explicit_root() {
        let root_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-idempkg-1.0.0";
        let root = sample_package("idempkg", "1.0.0", root_path);
        let closure = sample_closure(root.clone(), vec![root]);
        let installed = vec![sample_installed_with_explicit(
            "idempkg", "1.0.0", root_path, false,
        )];

        assert!(!requested_closures_already_installed(
            &[closure],
            &installed
        ));
    }

    #[test]
    fn requested_closures_already_installed_detects_changed_store_hash() {
        let old_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-idempkg-1.0.0";
        let new_path = "/nix/store/cccccccccccccccccccccccccccccccc-idempkg-1.0.0";
        let root = sample_package("idempkg", "1.0.0", new_path);
        let closure = sample_closure(root.clone(), vec![root]);
        let installed = vec![sample_installed("idempkg", "1.0.0", old_path)];

        assert!(!requested_closures_already_installed(
            &[closure],
            &installed
        ));
    }

    #[test]
    fn installed_flags_by_hash_preserves_explicit_and_held_state() {
        let installed = vec![sample_installed_with_flags(
            "idempkg",
            "1.0.0",
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-idempkg-1.0.0",
            true,
            true,
        )];

        let flags = installed_flags_by_hash(&installed);
        let entry = flags.get("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert!(entry.explicit);
        assert!(entry.held);
    }

    #[test]
    fn installed_flags_by_name_preserves_explicit_and_held_state() {
        let installed = vec![sample_installed_with_flags(
            "switch-tool",
            "1.0.0",
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-switch-tool-1.0.0",
            true,
            true,
        )];

        let flags = installed_flags_by_name(&installed);
        let entry = flags.get("switch-tool").unwrap();
        assert!(entry.explicit);
        assert!(entry.held);
    }

    #[test]
    fn installed_flags_by_name_prefers_explicit_duplicate_name() {
        let installed = vec![
            sample_installed_from_registry_with_flags(
                "priority-tool",
                "9.0.0",
                "low-priority",
                "/nix/store/llllllllllllllllllllllllllllllll-priority-tool-9.0.0",
                false,
                false,
            ),
            sample_installed_from_registry_with_flags(
                "priority-tool",
                "2.0.0",
                "high-priority",
                "/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-priority-tool-2.0.0",
                true,
                true,
            ),
        ];

        let flags = installed_flags_by_name(&installed);
        let entry = flags.get("priority-tool").unwrap();
        assert!(entry.explicit);
        assert!(entry.held);
    }

    #[test]
    fn prune_dependency_members_keeps_only_requested_roots() {
        let root_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-wrapper-1.0.0";
        let dep_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-libdep-1.0.0";
        let root = sample_package("wrapper", "1.0.0", root_path);
        let dep = sample_package("libdep", "1.0.0", dep_path);
        let mut closures = vec![sample_closure(root.clone(), vec![dep, root])];

        prune_dependency_members(&mut closures);

        assert_eq!(closures[0].closure.len(), 1);
        assert_eq!(closures[0].closure[0].name, "wrapper");
        assert_eq!(closures[0].total_nar_size, 1);
    }

    #[test]
    fn obsolete_installed_hashes_drops_entries_outside_needed_set() {
        let mut old_switch_tool = sample_installed(
            "switch-tool",
            "1.0.0",
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-switch-tool-1.0.0",
        );
        old_switch_tool.apm.as_mut().unwrap().source_drv =
            "/nix/store/cccccccccccccccccccccccccccccccc-switch-tool-src.drv".to_string();

        let installed = vec![
            sample_installed(
                "switch-lib",
                "1.0.0",
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-switch-lib-1.0.0",
            ),
            old_switch_tool,
            sample_installed(
                "kept-tool",
                "1.0.0",
                "/nix/store/dddddddddddddddddddddddddddddddd-kept-tool-1.0.0",
            ),
        ];
        let needed = HashSet::from([
            "dddddddddddddddddddddddddddddddd".to_string(),
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
        ]);
        let hashes = obsolete_installed_hashes(&installed, &needed);

        assert!(hashes.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(hashes.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        assert!(hashes.contains("cccccccccccccccccccccccccccccccc"));
        assert!(!hashes.contains("dddddddddddddddddddddddddddddddd"));
        assert!(!hashes.contains("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"));
    }

    #[test]
    fn chrono_iso8601_epoch() {
        let result = chrono_iso8601(0);
        assert_eq!(result, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn chrono_iso8601_known_date() {
        // 2026-02-16T00:00:00Z = 1771200000 (approximate, we just check format).
        let result = chrono_iso8601(1771200000);
        assert!(result.starts_with("2026-"));
        assert!(result.ends_with('Z'));
        assert_eq!(result.len(), 20); // "YYYY-MM-DDTHH:MM:SSZ"
    }

    #[test]
    fn copy_roots_copies_symlinks() {
        let tmp = TempDir::new().unwrap();

        // Set up "from" generation with usr/ and src/ symlinks.
        let from_path = tmp.path().join("gen-1");
        let from_usr = from_path.join("usr");
        let from_src = from_path.join("src");
        std::fs::create_dir_all(&from_usr).unwrap();
        std::fs::create_dir_all(&from_src).unwrap();
        symlink("/var/lib/store/abc123-curl-8.5.0", from_usr.join("abc123")).unwrap();
        symlink(
            "/var/lib/store/def456-curl-8.5.0.drv",
            from_src.join("def456"),
        )
        .unwrap();

        let from_gen = Generation {
            number: 1,
            path: from_path,
        };

        // Set up "to" generation (empty).
        let to_path = tmp.path().join("gen-2");
        std::fs::create_dir_all(&to_path).unwrap();

        let to_gen = Generation {
            number: 2,
            path: to_path.clone(),
        };

        copy_roots_except_hashes(&from_gen, &to_gen, &HashSet::new()).unwrap();

        // Verify usr/ root was copied.
        let usr_link = to_path.join("usr/abc123");
        assert!(
            usr_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_link(&usr_link).unwrap().to_string_lossy(),
            "/var/lib/store/abc123-curl-8.5.0"
        );

        // Verify src/ root was copied.
        let src_link = to_path.join("src/def456");
        assert!(
            src_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_link(&src_link).unwrap().to_string_lossy(),
            "/var/lib/store/def456-curl-8.5.0.drv"
        );
    }

    #[test]
    fn copy_roots_from_empty_generation() {
        let tmp = TempDir::new().unwrap();

        let from_path = tmp.path().join("gen-1");
        std::fs::create_dir_all(&from_path).unwrap();
        let from_gen = Generation {
            number: 1,
            path: from_path,
        };

        let to_path = tmp.path().join("gen-2");
        std::fs::create_dir_all(&to_path).unwrap();
        let to_gen = Generation {
            number: 2,
            path: to_path.clone(),
        };

        // Should succeed even when from has no usr/ or src/ dirs.
        copy_roots_except_hashes(&from_gen, &to_gen, &HashSet::new()).unwrap();

        // to should have empty usr/ and src/ dirs.
        assert!(to_path.join("usr").is_dir());
        assert!(to_path.join("src").is_dir());
    }

    #[test]
    fn copy_roots_does_not_overwrite_existing() {
        let tmp = TempDir::new().unwrap();

        // From generation: abc123 -> /store/old
        let from_path = tmp.path().join("gen-1");
        let from_usr = from_path.join("usr");
        std::fs::create_dir_all(&from_usr).unwrap();
        symlink("/var/lib/store/old-target", from_usr.join("abc123")).unwrap();

        let from_gen = Generation {
            number: 1,
            path: from_path,
        };

        // To generation already has abc123 -> /store/new
        let to_path = tmp.path().join("gen-2");
        let to_usr = to_path.join("usr");
        std::fs::create_dir_all(&to_usr).unwrap();
        symlink("/var/lib/store/new-target", to_usr.join("abc123")).unwrap();

        let to_gen = Generation {
            number: 2,
            path: to_path.clone(),
        };

        copy_roots_except_hashes(&from_gen, &to_gen, &HashSet::new()).unwrap();

        // Existing symlink in "to" should NOT be overwritten.
        let target = std::fs::read_link(to_path.join("usr/abc123")).unwrap();
        assert_eq!(target.to_string_lossy(), "/var/lib/store/new-target");
    }

    #[test]
    fn copy_roots_except_hashes_skips_replaced_roots() {
        let tmp = TempDir::new().unwrap();

        let from_path = tmp.path().join("gen-1");
        let from_usr = from_path.join("usr");
        let from_src = from_path.join("src");
        std::fs::create_dir_all(&from_usr).unwrap();
        std::fs::create_dir_all(&from_src).unwrap();
        symlink(
            "/var/lib/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-switch-tool-1.0.0",
            from_usr.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .unwrap();
        symlink(
            "/var/lib/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-kept-tool-1.0.0",
            from_usr.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        )
        .unwrap();
        symlink(
            "/var/lib/store/cccccccccccccccccccccccccccccccc-switch-tool.drv",
            from_src.join("cccccccccccccccccccccccccccccccc"),
        )
        .unwrap();

        let from_gen = Generation {
            number: 1,
            path: from_path,
        };
        let to_path = tmp.path().join("gen-2");
        std::fs::create_dir_all(&to_path).unwrap();
        let to_gen = Generation {
            number: 2,
            path: to_path.clone(),
        };
        let skip_hashes = HashSet::from(["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()]);

        copy_roots_except_hashes(&from_gen, &to_gen, &skip_hashes).unwrap();

        assert!(
            to_path
                .join("usr/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .symlink_metadata()
                .is_err()
        );
        assert!(
            to_path
                .join("usr/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .symlink_metadata()
                .is_ok()
        );
        assert!(
            to_path
                .join("src/cccccccccccccccccccccccccccccccc")
                .symlink_metadata()
                .is_ok()
        );
    }

    #[test]
    fn days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2000-01-01 is day 10957 since epoch.
        let (y, m, d) = days_to_ymd(10957);
        assert_eq!((y, m, d), (2000, 1, 1));
    }
}
