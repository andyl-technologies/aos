//! Read-only query commands: `apm search`, `show`, `list`, and `orphans`.
//!
//! All commands open the profile read-only and the registry caches for the
//! current platform; nothing here mutates state, so they work for
//! unprivileged callers.
//!
//! - **`search`**: substring match over names (and descriptions, unless
//!   `--names-only`) across enabled registries, or over the installed set
//!   with `--installed`.
//! - **`show`**: detailed metadata for one package, including dependency
//!   names, sysroot containment, and sysroot-lock violations. An installed
//!   package missing from every registry is still shown from profile
//!   metadata, marked unavailable.
//! - **`list`**: package table with `installed` / `upgradable` / `held` /
//!   `unavailable` status flags and the corresponding filters.
//! - **`orphans`**: installed packages whose source registry has been
//!   removed from the configuration entirely.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, bail};

use super::config::ApmConfig;
use super::profile::Profile;
use super::profile::meta::{list_meta, orphaned_by_registry};
use super::registry::{Registry, RegistrySet, store_path_hash};
use super::store;
use super::sysroot_lock;
use super::types::{ConfinementMeta, InstalledMeta, PackageMeta, PermissionsMeta, ProfileScope};
use aos_core::output::{OutputMode, Printer};

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

/// Search package names and descriptions across all registries.
///
/// Matching is case-insensitive substring search; `names_only` restricts it
/// to names, `installed_only` searches the installed set instead, and
/// `registry_filter` limits the search to one registry. Duplicate names are
/// deduplicated with the highest-priority registry winning.
///
/// # Errors
///
/// Returns an error if the registry caches or (with `installed_only`)
/// profile metadata cannot be loaded.
pub async fn search(
    config: &ApmConfig,
    pattern: &str,
    names_only: bool,
    installed_only: bool,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registries = load_registries(config)?;
    warn_unsynced_scope(config, printer);

    if installed_only {
        return search_installed(
            config,
            &registries,
            pattern,
            names_only,
            registry_filter,
            printer,
        )
        .await;
    }

    // Collect matches: (name, registry_name, version, description).
    let mut results: Vec<(String, String, String, String)> = Vec::new();

    for reg in registries.registries() {
        if let Some(filter) = registry_filter {
            if reg.config.name != filter {
                continue;
            }
        }

        let matches = reg.search(pattern, names_only);

        for meta in matches {
            results.push((
                meta.name.clone(),
                reg.config.name.clone(),
                meta.version.clone(),
                meta.description.clone(),
            ));
        }
    }

    // Sort by name.
    results.sort_by(|a, b| a.0.cmp(&b.0));

    // Deduplicate by name (highest priority registry wins, which comes first
    // since RegistrySet is sorted by priority descending).
    results.dedup_by(|b, a| a.0 == b.0);

    // Output.
    if printer.mode() == OutputMode::Json {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|(name, registry, version, description)| {
                serde_json::json!({
                    "name": name,
                    "registry": registry,
                    "version": version,
                    "description": description,
                })
            })
            .collect();
        printer.json(&serde_json::json!(json_results));
    } else {
        for (name, registry, version, description) in &results {
            printer.plain(&format!("{name}/{registry} {version} - {description}"));
        }
    }

    Ok(())
}

/// `apm search --installed`: match the pattern against installed packages,
/// pulling descriptions from the source registry when still available.
async fn search_installed(
    config: &ApmConfig,
    registries: &RegistrySet,
    pattern: &str,
    names_only: bool,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let profile = Profile::open_readonly(config.scope);
    let meta_list = list_meta(&profile)?;
    let pattern_lower = pattern.to_lowercase();
    let mut results: Vec<(String, String, String, String)> = Vec::new();

    for meta in &meta_list {
        let Some(apm) = meta.apm.as_ref() else {
            continue;
        };
        if let Some(filter) = registry_filter {
            if apm.registry != filter {
                continue;
            }
        }

        let description = installed_description(registries, &apm.registry, &meta.store_path);
        let name_match = apm.name.to_lowercase().contains(&pattern_lower);
        let description_match = !names_only && description.to_lowercase().contains(&pattern_lower);
        if !name_match && !description_match {
            continue;
        }

        results.push((
            apm.name.clone(),
            apm.registry.clone(),
            apm.version.clone(),
            description,
        ));
    }

    results.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    if printer.mode() == OutputMode::Json {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|(name, registry, version, description)| {
                serde_json::json!({
                    "name": name,
                    "registry": registry,
                    "version": version,
                    "description": description,
                })
            })
            .collect();
        printer.json(&serde_json::json!(json_results));
    } else {
        for (name, registry, version, description) in &results {
            printer.plain(&format!("{name}/{registry} {version} - {description}"));
        }
    }

    Ok(())
}

/// Description of an installed package from its source registry, or a
/// placeholder when the registry no longer offers that store path.
fn installed_description(
    registries: &RegistrySet,
    registry_name: &str,
    store_path: &str,
) -> String {
    let hash = store_path_hash(store_path);
    registries
        .get_registry(registry_name)
        .and_then(|reg| reg.get_by_hash(hash))
        .map(|meta| meta.description.clone())
        .unwrap_or_else(|| "installed package unavailable in registry".to_string())
}

// ---------------------------------------------------------------------------
// Show
// ---------------------------------------------------------------------------

/// Display detailed information about a package.
///
/// Resolution order: the named registry (with `registry_filter`) or the
/// highest-priority registry providing the package; if no registry has it
/// but it is installed, the entry is rendered from profile metadata and
/// marked unavailable.
///
/// # Errors
///
/// Returns an error if registry caches or profile metadata cannot be
/// loaded, the filter names an unknown registry, or the package is neither
/// in a registry nor installed.
pub async fn show(
    config: &ApmConfig,
    package: &str,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registries = load_registries(config)?;
    warn_unsynced_scope(config, printer);
    let profile = Profile::open_readonly(config.scope);
    let meta_list = list_meta(&profile)?;

    if let Some(filter) = registry_filter {
        if let Some(reg) = registries.get_registry(filter) {
            if let Some(meta) = reg.get(package) {
                return show_registry_package(config, reg, meta, &meta_list, printer);
            }
        }

        if let Some(installed) = find_installed_package(&meta_list, package, Some(filter)) {
            return show_installed_unavailable(installed, &meta_list, printer).await;
        }

        if registries.get_registry(filter).is_none() {
            bail!("registry '{filter}' not found");
        }
        bail!("package '{package}' not found in registry '{filter}'");
    }

    if let Some((reg, meta)) = registries.resolve(package) {
        show_registry_package(config, reg, meta, &meta_list, printer)
    } else if let Some(installed) = find_installed_package(&meta_list, package, None) {
        show_installed_unavailable(installed, &meta_list, printer).await
    } else {
        bail!("package '{package}' not found in any registry")
    }
}

/// Display package information, or just RFC-0001 permissions.
///
/// `apm info` is the compatibility spelling for users expecting a package
/// information command. Without `--permissions`, it renders the same detail as
/// [`show`]. With `--permissions`, it emits only the signed permission manifest
/// and computed confinement summary.
///
/// # Errors
///
/// Returns an error under the same resolution conditions as [`show`], or when
/// serializing the permission manifest fails.
pub async fn info(
    config: &ApmConfig,
    package: &str,
    registry_filter: Option<&str>,
    permissions_only: bool,
    printer: &Printer,
) -> Result<()> {
    if !permissions_only {
        return show(config, package, registry_filter, printer).await;
    }

    let registries = load_registries(config)?;
    let profile = Profile::open_readonly(config.scope);
    let meta_list = list_meta(&profile)?;

    if let Some(filter) = registry_filter {
        if let Some(reg) = registries.get_registry(filter) {
            if let Some(meta) = reg.get(package) {
                return show_permissions(
                    &meta.name,
                    Some(&reg.config.name),
                    meta.expose.is_some(),
                    &meta.permissions,
                    printer,
                );
            }
        }

        if let Some(installed) = find_installed_package(&meta_list, package, Some(filter)) {
            return show_installed_permissions(installed, printer);
        }

        if registries.get_registry(filter).is_none() {
            bail!("registry '{filter}' not found");
        }
        bail!("package '{package}' not found in registry '{filter}'");
    }

    if let Some((reg, meta)) = registries.resolve(package) {
        show_permissions(
            &meta.name,
            Some(&reg.config.name),
            meta.expose.is_some(),
            &meta.permissions,
            printer,
        )
    } else if let Some(installed) = find_installed_package(&meta_list, package, None) {
        show_installed_permissions(installed, printer)
    } else {
        bail!("package '{package}' not found in any registry")
    }
}

fn show_installed_permissions(installed: &InstalledMeta, printer: &Printer) -> Result<()> {
    let apm = installed
        .apm
        .as_ref()
        .context("installed metadata is missing APM package state")?;
    show_permissions(
        &apm.name,
        Some(&apm.registry),
        apm.expose.is_some(),
        &apm.permissions,
        printer,
    )
}

fn show_permissions(
    package: &str,
    registry: Option<&str>,
    exposed: bool,
    permissions: &PermissionsMeta,
    printer: &Printer,
) -> Result<()> {
    let confinement = confinement_for_display(exposed, permissions);
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "package": package,
            "registry": registry,
            "permissions": permissions,
            "confinement": confinement,
        }));
        return Ok(());
    }

    printer.kv("Package", package);
    if let Some(registry) = registry {
        printer.kv("Registry", registry);
    }
    if let Some(confinement) = &confinement {
        printer.kv("Confinement", &confinement.label);
    }
    if permissions.is_empty() {
        printer.kv("Permissions", "(none)");
    } else {
        let rendered = serde_json::to_string(permissions).context("serializing permissions")?;
        printer.kv("Permissions", &rendered);
    }
    Ok(())
}

fn confinement_for_display(
    exposed: bool,
    permissions: &PermissionsMeta,
) -> Option<ConfinementMeta> {
    if exposed || !permissions.is_empty() {
        Some(permissions.computed_confinement())
    } else {
        None
    }
}

/// Render `apm show` for a package backed by a registry entry, including
/// install state, dependency names, sysroot info, and (when installed)
/// sysroot-lock violations.
fn show_registry_package(
    config: &ApmConfig,
    reg: &Registry,
    meta: &PackageMeta,
    meta_list: &[InstalledMeta],
    printer: &Printer,
) -> Result<()> {
    let registry_name = reg.config.name.clone();

    // Check if installed.
    let pkg_hash = store_path_hash(&meta.store_path).to_string();
    let installed_meta = meta_list
        .iter()
        .find(|m| store_path_hash(&m.store_path) == pkg_hash);

    let is_installed = installed_meta.is_some();

    // Resolve dependency names from references.
    let dep_names = resolve_dependency_names(meta, reg);

    let nar_size_str = format_size(meta.nar_size);
    let confinement = confinement_for_display(meta.expose.is_some(), &meta.permissions);

    if printer.mode() == OutputMode::Json {
        let json_obj = serde_json::json!({
            "name": meta.name,
            "version": meta.version,
            "registry": registry_name,
            "description": meta.description,
            "homepage": meta.homepage,
            "license": meta.license,
            "platform": meta.platform,
            "installed": is_installed,
            "store_path": meta.store_path,
            "nar_size": meta.nar_size,
            "nar_size_human": nar_size_str,
            "dependencies": dep_names,
            "source_drv": meta.source_drv,
            "maintainer": meta.maintainer,
            "expose": meta.expose,
            "permissions": meta.permissions,
            "confinement": confinement,
        });
        printer.json(&json_obj);
    } else {
        printer.kv("Package", &meta.name);
        printer.kv("Version", &meta.version);
        printer.kv("Registry", &registry_name);
        printer.kv("Description", &meta.description);
        if let Some(ref homepage) = meta.homepage {
            printer.kv("Homepage", homepage);
        }
        printer.kv("License", &meta.license);
        printer.kv("Platform", &meta.platform);
        printer.kv("Installed", if is_installed { "yes" } else { "no" });
        printer.kv("Store path", &meta.store_path);
        printer.kv("NAR size", &nar_size_str);
        if dep_names.is_empty() {
            printer.kv("Dependencies", "(none)");
        } else {
            printer.kv("Dependencies", &dep_names.join(", "));
        }
        printer.kv("Source drv", &meta.source_drv);
        printer.kv("Maintainer", &meta.maintainer);
        if let Some(expose) = &meta.expose {
            printer.kv("Expose target", &expose.target);
            if expose.requires.is_empty() {
                printer.kv("Expose requires", "(none)");
            } else {
                printer.kv("Expose requires", &expose.requires.join(", "));
            }
        }
        if let Some(confinement) = &confinement {
            printer.kv("Confinement", &confinement.label);
        }
        if !meta.permissions.is_empty() {
            let rendered =
                serde_json::to_string(&meta.permissions).context("serializing permissions")?;
            printer.kv("Permissions", &rendered);
        }

        // Show sysroot-specific information.
        crate::sysroot::show_sysroot_info(meta, printer);

        // Show sysroot-lock violations if installed.
        if is_installed {
            if let Some((sysroot_refs, _sys_name, _sys_version)) =
                sysroot_lock::get_sysroot_references(config)
            {
                let lookup = sysroot_lock::build_registry_lookup(config);
                let pkg_refs: Vec<String> = meta
                    .references
                    .iter()
                    .cloned()
                    .chain(std::iter::once(
                        store_path_hash(&meta.store_path).to_string(),
                    ))
                    .collect();
                let violations =
                    sysroot_lock::check_sysroot_lock(&sysroot_refs, &pkg_refs, &lookup);
                if !violations.is_empty() {
                    printer.kv("Sysroot-lock violations", "");
                    for v in &violations {
                        printer.plain(&format!(
                            "  {:<16} sysroot: {:<12}  installed: {}",
                            v.name, v.sysroot_version, v.package_version,
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Render `apm show` for an installed package no registry offers anymore,
/// using profile metadata and the live store's reference graph for
/// dependency names.
async fn show_installed_unavailable(
    installed: &InstalledMeta,
    meta_list: &[InstalledMeta],
    printer: &Printer,
) -> Result<()> {
    let apm = installed
        .apm
        .as_ref()
        .context("installed metadata is missing APM package state")?;
    let dep_names = installed_dependency_names(installed, meta_list).await?;

    if printer.mode() == OutputMode::Json {
        let json_obj = serde_json::json!({
            "name": apm.name,
            "version": apm.version,
            "registry": apm.registry,
            "description": "installed package unavailable in registry",
            "homepage": null,
            "license": null,
            "platform": null,
            "installed": true,
            "unavailable": true,
            "store_path": installed.store_path,
            "nar_size": null,
            "nar_size_human": null,
            "dependencies": dep_names,
            "source_drv": null,
            "maintainer": null,
        });
        printer.json(&json_obj);
    } else {
        printer.kv("Package", &apm.name);
        printer.kv("Version", &apm.version);
        printer.kv("Registry", &apm.registry);
        printer.kv("Status", "installed, unavailable in registry");
        printer.kv("Description", "installed package unavailable in registry");
        printer.kv("Installed", "yes");
        printer.kv("Store path", &installed.store_path);
        if dep_names.is_empty() {
            printer.kv("Dependencies", "(none)");
        } else {
            printer.kv("Dependencies", &dep_names.join(", "));
        }
    }

    Ok(())
}

/// Dependency display names for an installed package: direct store
/// references mapped to installed package names, falling back to the raw
/// store-path hash for unknown references.
async fn installed_dependency_names(
    installed: &InstalledMeta,
    meta_list: &[InstalledMeta],
) -> Result<Vec<String>> {
    let root_hash = store_path_hash(&installed.store_path);
    let installed_by_hash: HashMap<String, String> = meta_list
        .iter()
        .filter_map(|meta| {
            let apm = meta.apm.as_ref()?;
            Some((
                store_path_hash(&meta.store_path).to_string(),
                apm.name.clone(),
            ))
        })
        .collect();
    let refs = store::direct_references(&installed.store_path).await?;
    Ok(refs
        .iter()
        .map(|path| store_path_hash(path).to_string())
        .filter(|hash| hash != root_hash)
        .map(|hash| installed_by_hash.get(&hash).cloned().unwrap_or(hash))
        .collect())
}

/// Find an installed package by APM name, optionally restricted to one
/// source registry.
fn find_installed_package<'a>(
    meta_list: &'a [InstalledMeta],
    package: &str,
    registry_filter: Option<&str>,
) -> Option<&'a InstalledMeta> {
    meta_list.iter().find(|meta| {
        let Some(apm) = meta.apm.as_ref() else {
            return false;
        };
        apm.name == package
            && registry_filter
                .map(|filter| apm.registry == filter)
                .unwrap_or(true)
    })
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

/// List packages across registries with optional filters.
///
/// Each entry shows `name/registry version [status]`, where status combines
/// `installed`, `upgradable: <version>`, `held`, sysroot-lock violations,
/// and `unavailable` (installed but no longer in its registry). The default
/// available-package view deduplicates names by registry priority; the
/// filtered views (`installed_only`, `upgradable_only`, `held_only`) do not,
/// so state on lower-priority registries stays visible.
///
/// # Errors
///
/// Returns an error if the registry caches or profile metadata cannot be
/// loaded.
pub async fn list(
    config: &ApmConfig,
    installed_only: bool,
    upgradable_only: bool,
    held_only: bool,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registries = load_registries(config)?;
    warn_unsynced_scope(config, printer);

    // Load profile metadata for install/upgrade/held checks.
    let profile = Profile::open_readonly(config.scope);
    let meta_list = list_meta(&profile)?;
    let running_sysroot = if config.scope == ProfileScope::System {
        crate::sysroot::running_image_generation()
            .ok()
            .map(|generation| (generation.package_name, generation.version))
    } else {
        None
    };

    // Installed state belongs to the registry that supplied the package. The
    // same package name can exist in multiple registries with different store
    // paths, versions, and priority.
    let installed_by_source_map = installed_by_source(&meta_list);

    // Pre-load sysroot references and registry lookup for sysroot-lock checks.
    let sysroot_info_for_lock = sysroot_lock::get_sysroot_references(config);
    let registry_lookup = if sysroot_info_for_lock.is_some() {
        sysroot_lock::build_registry_lookup(config)
    } else {
        HashMap::new()
    };

    // Collect entries: (name, registry_name, version, status).
    let mut entries: Vec<(String, String, String, String)> = Vec::new();
    let mut listed_installed_sources: HashSet<(String, String)> = HashSet::new();

    for reg in registries.registries() {
        if let Some(filter) = registry_filter {
            if reg.config.name != filter {
                continue;
            }
        }

        let mut names: Vec<&str> = reg.names();
        names.sort();

        for name in names {
            let meta = match reg.get(name) {
                Some(m) => m,
                None => continue,
            };

            let installed = installed_by_source_map
                .get(&(name.to_string(), reg.config.name.clone()))
                .copied();
            let running_sysroot_version =
                matching_running_sysroot_version(running_sysroot.as_ref(), name, meta);
            let is_installed = installed.is_some() || running_sysroot_version.is_some();
            if is_installed {
                listed_installed_sources.insert((name.to_string(), reg.config.name.clone()));
            }

            // Determine held status.
            let is_held = installed
                .and_then(|m| m.apm.as_ref())
                .map(|a| a.held)
                .unwrap_or(false);

            // Determine upgradable: installed but registry has different store path hash.
            let is_upgradable = installed.map_or_else(
                || running_sysroot_version.is_some_and(|version| version != &meta.version),
                |installed| is_upgradable_installed_root(installed, meta),
            );

            // Apply filters.
            if installed_only && !is_installed {
                continue;
            }
            if upgradable_only && !is_upgradable {
                continue;
            }
            if held_only && !is_held {
                continue;
            }

            // Check sysroot containment for non-installed packages.
            let sysroot_info = if !is_installed && installed_only {
                crate::sysroot::check_sysroot_containment(&meta.references, config)
            } else {
                None
            };

            // Check sysroot-lock violations for installed explicit packages.
            let lock_violation_names: Vec<String> = if is_installed {
                if let Some((ref sysroot_refs, _, _)) = sysroot_info_for_lock {
                    let pkg_refs: Vec<String> = meta
                        .references
                        .iter()
                        .cloned()
                        .chain(std::iter::once(
                            store_path_hash(&meta.store_path).to_string(),
                        ))
                        .collect();
                    let violations =
                        sysroot_lock::check_sysroot_lock(sysroot_refs, &pkg_refs, &registry_lookup);
                    violations.iter().map(|v| v.name.clone()).collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            // Build status string.
            let status = if let Some((sys_name, sys_ver)) = &sysroot_info {
                format!("via {} {}", sys_name, sys_ver)
            } else {
                let mut base = build_status_string(
                    is_installed,
                    is_upgradable,
                    is_held,
                    if is_upgradable {
                        Some(&meta.version)
                    } else {
                        None
                    },
                );
                if !lock_violation_names.is_empty() {
                    if !base.is_empty() {
                        base.push_str(", ");
                    }
                    base.push_str(&format!(
                        "sysroot-locked: {}",
                        lock_violation_names.join(", "),
                    ));
                }
                base
            };

            let display_version = installed
                .and_then(|installed| installed.apm.as_ref().map(|apm| apm.version.clone()))
                .or_else(|| running_sysroot_version.cloned())
                .unwrap_or_else(|| meta.version.clone());

            entries.push((
                name.to_string(),
                reg.config.name.clone(),
                display_version,
                status,
            ));
        }
    }

    if (installed_only || held_only) && !upgradable_only {
        for meta in &meta_list {
            let Some(apm) = meta.apm.as_ref() else {
                continue;
            };
            if let Some(filter) = registry_filter {
                if apm.registry != filter {
                    continue;
                }
            }
            if held_only && !apm.held {
                continue;
            }
            if listed_installed_sources.contains(&(apm.name.clone(), apm.registry.clone())) {
                continue;
            }

            let mut status = build_status_string(true, false, apm.held, None);
            if !status.is_empty() {
                status.push(',');
            }
            status.push_str("unavailable");

            entries.push((
                apm.name.clone(),
                apm.registry.clone(),
                apm.version.clone(),
                status,
            ));
        }
    }

    // Sort by name while preserving registry priority order for duplicate
    // names, because entries were collected from RegistrySet in priority order.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    // The default available-package view deduplicates duplicate names by
    // priority. Filtered views are state-oriented and should not hide an
    // installed or upgradable package from a lower-priority registry.
    if !installed_only && !upgradable_only && !held_only {
        entries.dedup_by(|b, a| a.0 == b.0);
    }

    // Output.
    if printer.mode() == OutputMode::Json {
        let json_entries: Vec<serde_json::Value> = entries
            .iter()
            .map(|(name, registry, version, status)| {
                serde_json::json!({
                    "name": name,
                    "registry": registry,
                    "version": version,
                    "status": status,
                })
            })
            .collect();
        printer.json(&serde_json::json!(json_entries));
    } else {
        for (name, registry, version, status) in &entries {
            if status.is_empty() {
                printer.plain(&format!("{name}/{registry} {version}"));
            } else {
                printer.plain(&format!("{name}/{registry} {version} [{status}]"));
            }
        }
    }

    Ok(())
}

/// List installed packages whose source registry is no longer configured.
///
/// Implements `apm orphans`. A package is *orphaned* when the registry it was
/// installed from has been removed from the configuration (for example by
/// `apr remove`): it stays installed but can no longer be upgraded, verified,
/// or re-resolved against its source. The profile is opened read-only, so this
/// never creates or mutates profile state and works for unprivileged callers
/// even when the profile lives under a root-owned path.
///
/// # Errors
///
/// Returns an error only if the profile's metadata directory exists but cannot
/// be read; a missing profile yields an empty list.
pub async fn orphans(config: &ApmConfig, printer: &Printer) -> Result<()> {
    // Read-only: never create or require write access to the profile root.
    let profile = Profile::open_readonly(config.scope);

    // A registry counts as "configured" whether enabled or disabled — only an
    // outright-removed registry orphans its packages.
    let configured: HashSet<&str> = config
        .registries
        .iter()
        .map(|(cfg, _)| cfg.name.as_str())
        .collect();

    let mut orphans = orphaned_by_registry(&profile, &configured)?;
    orphans.sort_by(|a, b| {
        let an = a.apm.as_ref().map(|m| m.name.as_str()).unwrap_or("");
        let bn = b.apm.as_ref().map(|m| m.name.as_str()).unwrap_or("");
        an.cmp(bn)
    });

    if printer.mode() == OutputMode::Json {
        let json: Vec<serde_json::Value> = orphans
            .iter()
            .filter_map(|m| m.apm.as_ref())
            .map(|a| {
                serde_json::json!({
                    "name": a.name,
                    "version": a.version,
                    "registry": a.registry,
                    "explicit": a.explicit,
                })
            })
            .collect();
        printer.json(&serde_json::json!(json));
        return Ok(());
    }

    if orphans.is_empty() {
        printer
            .info("No orphaned packages: every installed package's registry is still configured.");
        return Ok(());
    }

    printer.header(&format!("Orphaned packages ({}):", orphans.len()));
    for m in &orphans {
        if let Some(apm) = m.apm.as_ref() {
            printer.plain(&format!(
                "  {} {} (from removed registry '{}')",
                apm.name, apm.version, apm.registry
            ));
        }
    }
    printer.plain("");
    printer.info(&format!(
        "These packages remain installed but can't be upgraded or verified. Re-add the \
         registry with `{reg} add <url>`, reinstall from another registry, or remove them \
         with `{pkg} remove <pkg>`.",
        reg = aos_core::invocation::package_registry_command(),
        pkg = aos_core::invocation::package_manager_command(),
    ));

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load all enabled registries from the config.
fn load_registries(config: &ApmConfig) -> Result<RegistrySet> {
    let enabled = config.enabled_registries();
    let cache_dir = config.cache_path();
    let platform = current_platform();
    RegistrySet::load(&cache_dir, &enabled, &platform)
}

/// Names of enabled registries that have never been synced in the current
/// scope's cache.
///
/// A registry is unsynced here when its package cache directory
/// (`<cache>/<name>/packages`) is absent — exactly the state that makes
/// [`load_registries`] return it with zero packages and no error. This is the
/// silent-empty case behind "I ran `apm update --system` but `apm list` shows
/// nothing": the sync populated one scope's cache and the query read the
/// other's.
fn unsynced_registry_names(config: &ApmConfig) -> Vec<String> {
    unsynced_registry_names_in(&config.cache_path(), &config.enabled_registries())
}

/// Names of `enabled` registries that have no `packages/` directory under
/// `cache_dir` (the scope-independent core of [`unsynced_registry_names`],
/// split out so it can be tested without depending on environment-derived
/// cache paths).
fn unsynced_registry_names_in(
    cache_dir: &std::path::Path,
    enabled: &[&super::types::RegistryConfig],
) -> Vec<String> {
    enabled
        .iter()
        .filter(|cfg| !cache_dir.join(&cfg.name).join("packages").is_dir())
        .map(|cfg| cfg.name.clone())
        .collect()
}

/// Warn when enabled registries have no synced package cache in the current
/// scope, naming the scope and cache path searched and pointing at the other
/// scope.
///
/// Registry-backed query commands call this so that an empty or short result
/// caused by querying the wrong profile scope explains itself instead of
/// failing silently. It is a no-op when every enabled registry has a package
/// cache in this scope (or none are enabled).
pub(crate) fn warn_unsynced_scope(config: &ApmConfig, printer: &Printer) {
    let unsynced = unsynced_registry_names(config);
    if unsynced.is_empty() {
        return;
    }

    let scope = config.scope;
    let label = if unsynced.len() == 1 {
        "registry"
    } else {
        "registries"
    };
    // Point at the other scope's flag: from user scope, add `--system`; from
    // system scope, drop it.
    let (scope_hint, sync_hint) = match scope {
        ProfileScope::User => (
            "retry with `--system` to query the system scope",
            "`apm update`",
        ),
        ProfileScope::System => (
            "retry without `--system` to query the user scope",
            "`apm update --system`",
        ),
    };

    printer.warning(&format!(
        "{label} {names} not synced in the {scope} scope (searched {cache}); \
         {scope_hint}, or run {sync_hint} to sync it here.",
        names = unsynced.join(", "),
        scope = scope.name(),
        cache = config.cache_path().display(),
    ));
}

/// Index installed packages by `(name, source registry)` — the same name
/// may be installed from multiple registries with distinct store paths.
fn installed_by_source(meta_list: &[InstalledMeta]) -> HashMap<(String, String), &InstalledMeta> {
    meta_list
        .iter()
        .filter_map(|m| {
            let apm = m.apm.as_ref()?;
            Some(((apm.name.clone(), apm.registry.clone()), m))
        })
        .collect()
}

/// Whether an explicitly installed package differs from the registry
/// candidate by store-path hash (i.e. an upgrade is available). Implicit
/// (dependency-only) installs are never reported as upgradable.
fn is_upgradable_installed_root(installed: &InstalledMeta, registry_meta: &PackageMeta) -> bool {
    let Some(apm) = installed.apm.as_ref() else {
        return false;
    };
    if !apm.explicit {
        return false;
    }

    store_path_hash(&installed.store_path) != store_path_hash(&registry_meta.store_path)
}

/// Returns the running version when a registry entry represents that sysroot.
fn matching_running_sysroot_version<'a>(
    running: Option<&'a (String, String)>,
    package_name: &str,
    registry_meta: &PackageMeta,
) -> Option<&'a String> {
    running.and_then(|(running_name, version)| {
        (registry_meta.sysroot && running_name == package_name).then_some(version)
    })
}

/// Detect the current platform string (e.g. "x86_64-linux").
fn current_platform() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;

    let nix_arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "arm" => "armv7l",
        "riscv64" => "riscv64",
        _ => arch,
    };

    let nix_os = match os {
        "linux" => "linux",
        "macos" => "darwin",
        _ => os,
    };

    format!("{nix_arch}-{nix_os}")
}

/// Resolve dependency names from a PackageMeta's references using the registry's
/// hash index.
///
/// Returns a Vec of resolved package names. If a reference hash cannot be
/// resolved to a known package, the raw hash string is returned instead.
pub fn resolve_dependency_names(meta: &PackageMeta, registry: &Registry) -> Vec<String> {
    meta.references
        .iter()
        .map(|ref_hash| {
            registry
                .get_by_hash(ref_hash)
                .map(|dep| dep.name.clone())
                .unwrap_or_else(|| ref_hash.clone())
        })
        .collect()
}

/// Format a byte size into a human-readable string using binary units.
///
/// Examples:
/// - 512 -> "512 B"
/// - 1536 -> "1.5 KiB"
/// - 14_893_056 -> "14.2 MiB"
/// - 1_073_741_824 -> "1.0 GiB"
pub fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    let size = bytes as f64;

    if size < KIB {
        format!("{bytes} B")
    } else if size < MIB {
        format!("{:.1} KiB", size / KIB)
    } else if size < GIB {
        format!("{:.1} MiB", size / MIB)
    } else {
        format!("{:.1} GiB", size / GIB)
    }
}

/// Build a human-readable status string for `apm list` output.
fn build_status_string(
    installed: bool,
    upgradable: bool,
    held: bool,
    upgrade_version: Option<&str>,
) -> String {
    let mut parts = Vec::new();

    if installed {
        parts.push("installed".to_string());
    }
    if upgradable {
        if let Some(ver) = upgrade_version {
            parts.push(format!("upgradable: {ver}"));
        } else {
            parts.push("upgradable".to_string());
        }
    }
    if held {
        parts.push("held".to_string());
    }

    parts.join(",")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    use crate::registry::Registry;
    use crate::registry::parse::{CURL_TOML, ZLIB_TOML};
    use crate::types::{ApmMeta, InstalledMeta, RegistryConfig};

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

    fn sample_installed_meta(
        name: &str,
        version: &str,
        registry: &str,
        store_path: &str,
        held: bool,
    ) -> InstalledMeta {
        sample_installed_meta_with_explicit(name, version, registry, store_path, true, held)
    }

    fn sample_installed_meta_with_explicit(
        name: &str,
        version: &str,
        registry: &str,
        store_path: &str,
        explicit: bool,
        held: bool,
    ) -> InstalledMeta {
        InstalledMeta {
            store_path: store_path.into(),
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

    #[test]
    fn confinement_for_display_computes_exposed_default() {
        let empty = PermissionsMeta::default();
        let confinement = super::confinement_for_display(true, &empty).unwrap();

        assert_eq!(confinement.class, crate::types::ConfinementClass::Sandboxed);
        assert_eq!(confinement.label, "sandboxed");
        assert!(super::confinement_for_display(false, &empty).is_none());
    }

    // 1. search_finds_by_name
    #[test]
    fn search_finds_by_name() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );

        let results = reg.search("curl", false);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "curl");
    }

    // 2. search_finds_by_description
    #[test]
    fn search_finds_by_description() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );

        // "compression" is in zlib's description
        let results = reg.search("compression", false);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "zlib");
    }

    // 3. search_names_only_skips_description
    #[test]
    fn search_names_only_skips_description() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );

        // "compression" only appears in zlib's description, not name
        let results = reg.search("compression", true);
        assert!(results.is_empty());
    }

    // 4. resolve_dependency_names_resolves_known
    #[test]
    fn resolve_dependency_names_resolves_known() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );

        let curl_meta = reg.get("curl").unwrap();
        let dep_names = resolve_dependency_names(curl_meta, &reg);

        // r4q1m2kp8v3x is zlib's hash, so it should resolve to "zlib"
        assert!(dep_names.contains(&"zlib".to_string()));
    }

    // 5. resolve_dependency_names_unknown_stays_hash
    #[test]
    fn resolve_dependency_names_unknown_stays_hash() {
        let tmp = TempDir::new().unwrap();
        // Only load curl, not zlib -- so zlib's hash and others won't resolve.
        let reg = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);

        let curl_meta = reg.get("curl").unwrap();
        let dep_names = resolve_dependency_names(curl_meta, &reg);

        // curl has references: ["xr5is7by89v3q", "r4q1m2kp8v3x", "q8mn2pv73w0x", "kl9m3n0o5p6q"]
        // None of these resolve to a named package (zlib not loaded), but
        // some may resolve via hash_index to "curl" itself. The ones that
        // don't resolve at all should stay as raw hashes.
        // At minimum, we should have 4 entries (one per reference).
        assert_eq!(dep_names.len(), 4);

        // xr5is7by89v3q is not zlib, so in a curl-only registry it maps
        // via hash_index fallback to "curl" (the indexer inserts reference
        // hashes pointing back to the referencing package). Check that at
        // least some entries are either "curl" or raw hashes.
        for name in &dep_names {
            assert!(
                name == "curl" || name.chars().all(|c| c.is_alphanumeric()),
                "unexpected dep name: {name}"
            );
        }
    }

    // 6. format_size_units
    #[test]
    fn format_size_units() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(1048576), "1.0 MiB");
        assert_eq!(format_size(14_893_056), "14.2 MiB");
        assert_eq!(format_size(1_073_741_824), "1.0 GiB");
        assert_eq!(format_size(2_684_354_560), "2.5 GiB");
    }

    // 7. list_installed_filters_correctly
    #[test]
    fn list_installed_filters_correctly() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let registries = RegistrySet::new(vec![reg]);

        // Simulate installed: only curl is installed.
        let curl_installed = sample_installed_meta(
            "curl",
            "8.5.0",
            "aos-core",
            "/var/lib/store/h7j3k8l2m9n4-curl-8.5.0",
            false,
        );

        let installed = vec![curl_installed];
        let installed_by_source_map = installed_by_source(&installed);

        // Filter: only installed packages.
        let mut entries = Vec::new();
        for reg in registries.registries() {
            let mut names: Vec<&str> = reg.names();
            names.sort();
            for name in names {
                let meta = reg.get(name).unwrap();
                let installed = installed_by_source_map
                    .get(&(name.to_string(), reg.config.name.clone()))
                    .copied();
                let is_installed = installed.is_some();

                // installed_only filter
                if !is_installed {
                    continue;
                }

                entries.push((name.to_string(), meta.version.clone()));
            }
        }

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "curl");
    }

    // 8. list_upgradable_detects_changes
    #[test]
    fn list_upgradable_detects_changes() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let registries = RegistrySet::new(vec![reg]);

        // curl installed with a different hash (simulating older version)
        let curl_installed = sample_installed_meta(
            "curl",
            "8.4.0",
            "aos-core",
            "/var/lib/store/oldhash12345-curl-8.4.0",
            false,
        );
        // zlib installed with a different hash, but as an auto-installed
        // dependency it should not be advertised as an independent upgrade.
        let zlib_installed = sample_installed_meta_with_explicit(
            "zlib",
            "1.3.0",
            "aos-core",
            "/var/lib/store/oldzlibhash1-zlib-1.3.0",
            false,
            false,
        );

        let installed = vec![curl_installed, zlib_installed];
        let installed_by_source_map = installed_by_source(&installed);

        let mut upgradable = Vec::new();
        for reg in registries.registries() {
            for name in reg.names() {
                let meta = reg.get(name).unwrap();
                if let Some(inst) = installed_by_source_map
                    .get(&(name.to_string(), reg.config.name.clone()))
                    .copied()
                {
                    if is_upgradable_installed_root(inst, meta) {
                        upgradable.push(name.to_string());
                    }
                }
            }
        }

        assert_eq!(upgradable.len(), 1);
        assert_eq!(upgradable[0], "curl");
    }

    #[test]
    fn running_sysroot_is_an_installed_upgrade_source() {
        let tmp = TempDir::new().unwrap();
        let registry = make_registry(&tmp, "production", 900, &[("curl", CURL_TOML)]);
        let mut candidate = registry.get("curl").unwrap().clone();
        candidate.name = "aos".to_string();
        candidate.sysroot = true;
        candidate.version = "test-2".to_string();
        let running = ("aos".to_string(), "0.1.0".to_string());

        let installed_version = matching_running_sysroot_version(Some(&running), "aos", &candidate);

        assert_eq!(installed_version.map(String::as_str), Some("0.1.0"));
        assert_ne!(installed_version, Some(&candidate.version));
    }

    #[test]
    fn installed_by_source_keeps_same_name_registries_distinct() {
        let low = sample_installed_meta(
            "priority-tool",
            "9.0.0",
            "low-priority",
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-priority-tool-9.0.0",
            false,
        );
        let installed = vec![low];
        let by_source = installed_by_source(&installed);

        assert!(
            by_source
                .get(&("priority-tool".to_string(), "high-priority".to_string()))
                .is_none()
        );
        assert_eq!(
            by_source
                .get(&("priority-tool".to_string(), "low-priority".to_string()))
                .and_then(|m| m.apm.as_ref())
                .map(|apm| apm.version.as_str()),
            Some("9.0.0")
        );
    }

    // 9. search_with_registry_filter
    #[test]
    fn search_with_registry_filter() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let extra = make_registry(&tmp, "aos-extra", 400, &[("curl", CURL_TOML)]);

        let registries = RegistrySet::new(vec![core, extra]);

        // Search only in aos-extra: should find curl but not zlib.
        let mut results = Vec::new();
        for reg in registries.registries() {
            if reg.config.name != "aos-extra" {
                continue;
            }
            let matches = reg.search("", false);
            for m in matches {
                results.push(m.name.clone());
            }
        }

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "curl");
    }

    // 10. show_formats_package_info
    #[test]
    fn show_formats_package_info() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );

        let meta = reg.get("curl").unwrap();

        // Verify key fields are present and correct.
        assert_eq!(meta.name, "curl");
        assert_eq!(meta.version, "8.5.0");
        assert_eq!(
            meta.description,
            "Command-line tool and library for URL transfers"
        );
        assert_eq!(meta.homepage.as_deref(), Some("https://curl.se"));
        assert_eq!(meta.license, "MIT");
        assert_eq!(meta.platform, "x86_64-linux");
        assert_eq!(meta.maintainer, "aos-team");
        assert!(!meta.store_path.is_empty());
        assert!(!meta.source_drv.is_empty());
        assert!(meta.nar_size > 0);

        // Verify format_size for this package.
        let size_str = format_size(meta.nar_size);
        assert_eq!(size_str, "3.0 MiB");

        // Verify dependency resolution.
        let dep_names = resolve_dependency_names(meta, &reg);
        assert!(dep_names.contains(&"zlib".to_string()));
    }

    /// Minimal enabled registry config carrying only the name (the field
    /// [`unsynced_registry_names_in`] inspects).
    fn bare_reg_config(name: &str) -> RegistryConfig {
        RegistryConfig {
            name: name.to_string(),
            url: format!("https://registry.example.com/{name}"),
            priority: 50,
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
        }
    }

    #[test]
    fn unsynced_names_flags_registry_without_packages_dir() {
        let tmp = TempDir::new().unwrap();
        // "synced" has a packages/ dir; "fresh" does not.
        fs::create_dir_all(tmp.path().join("synced").join("packages")).unwrap();

        let synced = bare_reg_config("synced");
        let fresh = bare_reg_config("fresh");
        let enabled = [&synced, &fresh];

        let unsynced = unsynced_registry_names_in(tmp.path(), &enabled);
        assert_eq!(unsynced, vec!["fresh".to_string()]);
    }

    #[test]
    fn unsynced_names_empty_when_all_synced() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("andyl").join("packages")).unwrap();

        let andyl = bare_reg_config("andyl");
        let enabled = [&andyl];

        assert!(unsynced_registry_names_in(tmp.path(), &enabled).is_empty());
    }
}
