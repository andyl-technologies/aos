//! Package listing, version selection, removal, and closure integrity verification.

use crate::config::ApmConfig;
use crate::registry::store::StoreMap;
use crate::registry_ops::config::{
    format_size, registry_content_addressed, registry_dir, resolve_registry_name,
};
use crate::registry_ops::git::{commit_registry, current_git_head, refresh_registry_object_store};
use crate::registry_ops::publish::RegistryPublishLock;
use crate::registry_ops::signing::resolve_producer_signing_key;
use crate::registry_ops::store_paths::{extract_hash, first_letter, write_store_files};
use crate::registry_ops::workflow::{current_git_branch, git_branch_entries};
use crate::types::validate_package_name;
use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
use std::collections::HashSet;

/// `apr unpublish <PACKAGE> [VERSION]` — removes package metadata from the
/// registry.
///
/// With neither a version nor `--platform`, the whole package file is
/// deleted. With a version (and optionally a platform) only the matching
/// entries are removed; specifying only `--platform` removes that platform
/// from every version. The file is deleted once no versions remain.
/// Unless `--no-commit` is set, the change is committed (SSH-signed when
/// `--key`/`--key-id` is given) and the dumb-HTTP object store is
/// refreshed. Closure files are left in place.
///
/// # Errors
///
/// Fails when the package name is not safe for registry package paths, when
/// the package, the requested version, or the requested platform does not
/// exist in the registry, or when a file write, the commit, or the
/// object-store refresh fails.
#[allow(clippy::too_many_arguments)]
pub async fn unpublish(
    config: &ApmConfig,
    package: &str,
    version: Option<&str>,
    platform: Option<&str>,
    no_commit: bool,
    message: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_package_name(package)?;
    let dir = registry_dir(config, registry)?;
    let registry_name = resolve_registry_name(config, registry)?;
    let signing_key = if key.is_some() || key_id.is_some() {
        Some(resolve_producer_signing_key(
            config,
            &dir,
            &registry_name,
            key,
            key_id,
        )?)
    } else {
        None
    };
    let _publish_lock = RegistryPublishLock::acquire(&dir)?;
    let letter = first_letter(package);
    let toml_path = dir
        .join("packages")
        .join(&letter)
        .join(format!("{package}.toml"));

    if !toml_path.exists() {
        bail!("package '{package}' not found in registry");
    }

    let mut package_file_removed = false;
    let mut status = "updated";
    if version.is_none() && platform.is_none() {
        // Remove the entire file.
        std::fs::remove_file(&toml_path)?;
        package_file_removed = true;
        status = "removed";
        printer.info(&format!("Removed package '{package}' entirely."));
    } else {
        // Parse and selectively remove.
        let content = std::fs::read_to_string(&toml_path)?;
        let mut toml_val: toml::Value = toml::from_str(&content)?;

        if let Some(versions) = toml_val.get_mut("versions").and_then(|v| v.as_array_mut()) {
            if let Some(ver) = version {
                let idx = versions
                    .iter()
                    .position(|v| v.get("version").and_then(|s| s.as_str()) == Some(ver))
                    .ok_or_else(|| {
                        anyhow::anyhow!("package '{package}' does not contain version '{ver}'")
                    })?;
                if let Some(plat) = platform {
                    // Remove specific platform from specific version.
                    let remove_version = {
                        let platforms = versions[idx]
                            .as_table_mut()
                            .and_then(|t| t.get_mut("platforms"))
                            .and_then(|p| p.as_table_mut())
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "package '{package}' version '{ver}' has no platform entries"
                                )
                            })?;
                        if !platforms.contains_key(plat) {
                            bail!(
                                "package '{package}' version '{ver}' does not contain platform '{plat}'"
                            );
                        }
                        platforms.remove(plat);
                        platforms.is_empty()
                    };
                    if remove_version {
                        versions.remove(idx);
                    }
                } else {
                    // Remove entire version.
                    versions.remove(idx);
                }
            } else if let Some(plat) = platform {
                // Remove platform from all versions.
                let mut removed = false;
                for ver in versions.iter_mut() {
                    if let Some(platforms) = ver
                        .as_table_mut()
                        .and_then(|t| t.get_mut("platforms"))
                        .and_then(|p| p.as_table_mut())
                    {
                        removed |= platforms.remove(plat).is_some();
                    }
                }
                if !removed {
                    bail!("package '{package}' does not contain platform '{plat}'");
                }
                // Remove empty versions.
                versions.retain(|v| {
                    v.get("platforms")
                        .and_then(|p| p.as_table())
                        .map(|t| !t.is_empty())
                        .unwrap_or(false)
                });
            }

            if versions.is_empty() {
                std::fs::remove_file(&toml_path)?;
                package_file_removed = true;
                status = "removed";
                printer.info(&format!(
                    "Removed package '{package}' (no versions remaining)."
                ));
            } else {
                std::fs::write(&toml_path, toml::to_string_pretty(&toml_val)?)?;
                printer.info(&format!("Updated package '{package}'."));
            }
        }
    }

    let mut committed = false;
    let mut commit_message = None;
    if !no_commit {
        let default_msg = format!("unpublish {package}");
        let msg = message.unwrap_or(&default_msg);
        commit_registry(&dir, msg, signing_key.as_ref().map(|k| k.path()))?;
        refresh_registry_object_store(&dir)
            .context("refreshing dumb-HTTP object store after unpublish")?;
        committed = true;
        commit_message = Some(msg.to_string());
        printer.success(&format!("Committed: {msg}"));
    }

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "unpublish",
            "registry": registry_name,
            "package": package,
            "version": version,
            "platform": platform,
            "status": status,
            "package_file": toml_path
                .strip_prefix(&dir)
                .unwrap_or(&toml_path)
                .display()
                .to_string(),
            "package_file_removed": package_file_removed,
            "committed": committed,
            "commit_message": commit_message,
            "current": current_git_branch(&dir)?,
            "head": current_git_head(&dir)?,
            "branches": git_branch_entries(&dir)?,
        }));
    }

    Ok(())
}

fn selected_package_versions(
    toml_val: &toml::Value,
    version: Option<&str>,
) -> Result<Vec<toml::Value>> {
    let versions = matching_package_versions(toml_val, None);
    let Some(version) = version else {
        return Ok(versions);
    };

    let selected = versions
        .into_iter()
        .filter(|entry| entry.get("version").and_then(|v| v.as_str()) == Some(version))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        bail!("package does not contain version '{version}'");
    }
    Ok(selected)
}

fn matching_package_versions(toml_val: &toml::Value, platform: Option<&str>) -> Vec<toml::Value> {
    let Some(versions) = toml_val.get("versions").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    versions
        .iter()
        .filter(|entry| version_has_platform(entry, platform))
        .cloned()
        .collect()
}

fn version_has_platform(entry: &toml::Value, platform: Option<&str>) -> bool {
    let Some(platform) = platform else {
        return true;
    };
    entry
        .get("platforms")
        .and_then(|platforms| platforms.as_table())
        .map(|platforms| platforms.contains_key(platform))
        .unwrap_or(false)
}

fn latest_version_string(versions: &[toml::Value]) -> Option<String> {
    versions
        .iter()
        .filter_map(|entry| entry.get("version").and_then(|version| version.as_str()))
        .max_by(|left, right| compare_registry_versions(left, right))
        .map(ToString::to_string)
}

/// Order version strings semver-first: a parsable semver always beats a
/// non-semver string, and two non-semver strings fall back to lexicographic
/// comparison.
fn compare_registry_versions(left: &str, right: &str) -> std::cmp::Ordering {
    match (semver::Version::parse(left), semver::Version::parse(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        (Ok(_), Err(_)) => std::cmp::Ordering::Greater,
        (Err(_), Ok(_)) => std::cmp::Ordering::Less,
        (Err(_), Err(_)) => left.cmp(right),
    }
}

fn package_toml_with_versions(
    toml_val: &toml::Value,
    versions: &[toml::Value],
) -> Result<toml::Value> {
    let mut filtered = toml_val.clone();
    let Some(root) = filtered.as_table_mut() else {
        bail!("package TOML root is not a table");
    };
    root.insert(
        "versions".to_string(),
        toml::Value::Array(versions.to_vec()),
    );
    Ok(filtered)
}

/// `apr show <PACKAGE>` — prints a package's registry metadata.
///
/// Shows the `[package]` header fields plus each version's per-platform
/// store paths, NAR sizes, and image artifacts. A version argument filters
/// the output to that version; `--raw` prints the package TOML verbatim
/// instead of the formatted view.
///
/// # Errors
///
/// Fails when the package name is not safe for registry package paths, when
/// the package file does not exist in the registry, cannot be parsed, or
/// does not contain the requested version.
pub async fn show(
    config: &ApmConfig,
    package: &str,
    version: Option<&str>,
    raw: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_package_name(package)?;
    let dir = registry_dir(config, registry)?;
    let letter = first_letter(package);
    let toml_path = dir
        .join("packages")
        .join(&letter)
        .join(format!("{package}.toml"));

    if !toml_path.exists() {
        bail!("package '{package}' not found in registry");
    }

    let content = std::fs::read_to_string(&toml_path)?;
    let toml_val: toml::Value = toml::from_str(&content)?;
    let selected_versions = selected_package_versions(&toml_val, version)?;

    if printer.mode() == OutputMode::Json {
        let value = if version.is_some() {
            package_toml_with_versions(&toml_val, &selected_versions)?
        } else {
            toml_val.clone()
        };
        printer.json(&serde_json::to_value(&value)?);
        return Ok(());
    }

    if raw {
        if version.is_some() {
            let filtered = package_toml_with_versions(&toml_val, &selected_versions)?;
            printer.plain(&toml::to_string_pretty(&filtered)?);
        } else {
            printer.plain(&content);
        }
    } else {
        if let Some(pkg) = toml_val.get("package") {
            if let Some(name) = pkg.get("name").and_then(|v| v.as_str()) {
                printer.header(&format!("Package: {name}"));
            }
            if let Some(desc) = pkg.get("description").and_then(|v| v.as_str()) {
                printer.kv("Description", desc);
            }
            if pkg
                .get("sysroot")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                printer.kv("Sysroot", "yes");
            }
            if let Some(hp) = pkg.get("homepage").and_then(|v| v.as_str()) {
                printer.kv("Homepage", hp);
            }
            if let Some(lic) = pkg.get("license").and_then(|v| v.as_str()) {
                printer.kv("License", lic);
            }
            if let Some(maint) = pkg.get("maintainer").and_then(|v| v.as_str()) {
                printer.kv("Maintainer", maint);
            }
        }
        for ver in &selected_versions {
            if let Some(v) = ver.get("version").and_then(|v| v.as_str()) {
                printer.kv("Version", v);
            }
            if let Some(prev) = ver.get("previous").and_then(|v| v.as_str()) {
                printer.kv("Previous", prev);
            }
            if let Some(platforms) = ver.get("platforms").and_then(|v| v.as_table()) {
                for (plat, entry) in platforms {
                    printer.kv(&format!("  {plat}"), "");
                    if let Some(sp) = entry.get("store_path").and_then(|v| v.as_str()) {
                        printer.kv("    Store path", sp);
                    }
                    if let Some(ns) = entry.get("nar_size").and_then(|v| v.as_integer()) {
                        printer.kv("    NAR size", &format_size(ns as u64));
                    }
                    if let Some(images) = entry.get("images").and_then(|v| v.as_array()) {
                        for img in images {
                            if let Some(fmt) = img.get("format").and_then(|v| v.as_str()) {
                                let img_path = img
                                    .get("store_path")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("?");
                                let img_size = img
                                    .get("nar_size")
                                    .and_then(|v| v.as_integer())
                                    .unwrap_or(0);
                                printer.kv(
                                    &format!("    Image ({fmt})"),
                                    &format!("{img_path} ({})", format_size(img_size as u64)),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// `apr packages` — lists every package in the registry with its latest
/// version.
///
/// `--platform` restricts the version selection to versions published for
/// that platform; `--outdated` shows only packages that carry more than
/// one matching version (i.e. that have superseded entries).
///
/// # Errors
///
/// Fails when the registry cannot be resolved or a package metadata file
/// cannot be read or parsed.
pub async fn packages(
    config: &ApmConfig,
    platform: Option<&str>,
    outdated: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let packages_dir = dir.join("packages");

    if !packages_dir.is_dir() {
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!([]));
            return Ok(());
        }
        printer.info("No packages found.");
        return Ok(());
    }

    let mut pkgs = Vec::new();
    for letter_entry in std::fs::read_dir(&packages_dir)?.flatten() {
        if !letter_entry.path().is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(letter_entry.path())?.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "toml").unwrap_or(false) {
                let content = std::fs::read_to_string(&path)?;
                let name = crate::registry::parse::validate_package_file_layout(&path, &content)
                    .with_context(|| format!("validating {}", path.display()))?;
                let toml_val: toml::Value = toml::from_str(&content)?;
                let versions = matching_package_versions(&toml_val, platform);
                if outdated && versions.len() < 2 {
                    continue;
                }
                let Some(version) = latest_version_string(&versions) else {
                    continue;
                };
                pkgs.push((name, version));
            }
        }
    }

    pkgs.sort();

    if printer.mode() == OutputMode::Json {
        let packages_json = pkgs
            .iter()
            .map(|(name, version)| {
                serde_json::json!({
                    "name": name,
                    "version": version,
                })
            })
            .collect::<Vec<_>>();
        printer.json(&serde_json::json!(packages_json));
        return Ok(());
    }

    if pkgs.is_empty() {
        printer.info("No packages found.");
    } else {
        printer.header(&format!("{} packages:", pkgs.len()));
        for (name, version) in &pkgs {
            printer.plain(&format!("  {name} {version}"));
        }
    }

    Ok(())
}

/// One published store path discovered while scanning package TOMLs for
/// `apr verify`.
#[derive(Debug, Clone)]
struct RegistryVerifyStoreEntry {
    store_hash: String,
    store_path: String,
    package_name: String,
}

/// `apr verify` — checks registry-internal metadata consistency.
///
/// Verifies that every package TOML parses and has a `[package]` section,
/// that every published store path has a closure file whose first line is
/// the root hash, that all direct references recorded in the package TOML
/// appear in the closure, and that the closure adjacency list is
/// internally closed (members only reference other members). With `--fix`,
/// closure files are regenerated from the local Nix store before checking,
/// which requires the published store paths to be present locally.
///
/// # Errors
///
/// Fails when a `--package` filter is not a safe package name or matches no
/// package, when `--fix` cannot recompute a closure, or when any
/// verification error was found.
pub async fn verify(
    config: &ApmConfig,
    package: Option<&str>,
    fix: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let packages_dir = dir.join("packages");
    if let Some(package) = package {
        validate_package_name(package)?;
    }

    let mut errors = 0u32;
    let mut checked = 0u32;
    let mut repaired = 0u32;

    // Collect all store path hashes from package TOMLs.
    let mut all_store_entries: Vec<RegistryVerifyStoreEntry> = Vec::new();
    let mut matched_package_filter = package.is_none();

    // Verify package TOML files.
    if packages_dir.is_dir() {
        for letter_entry in std::fs::read_dir(&packages_dir)?.flatten() {
            if !letter_entry.path().is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(letter_entry.path())?.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "toml").unwrap_or(false) {
                    let path_matches_filter = match package {
                        Some(filter) => {
                            path.file_stem().and_then(|stem| stem.to_str()) == Some(filter)
                        }
                        None => true,
                    };
                    if !path_matches_filter {
                        continue;
                    }
                    matched_package_filter = true;
                    checked += 1;
                    let content = std::fs::read_to_string(&path)?;
                    match toml::from_str::<toml::Value>(&content) {
                        Ok(val) => {
                            if val.get("package").is_none() {
                                printer.warning(&format!(
                                    "{}: missing [package] section",
                                    path.display()
                                ));
                                errors += 1;
                                continue;
                            }
                            let pkg_name =
                                match crate::registry::parse::validate_package_file_layout(
                                    &path, &content,
                                ) {
                                    Ok(name) => name,
                                    Err(e) => {
                                        printer.warning(&format!("{}: {e}", path.display()));
                                        errors += 1;
                                        continue;
                                    }
                                };
                            // Extract store hashes from all version/platform entries.
                            if let Some(versions) = val.get("versions").and_then(|v| v.as_array()) {
                                for ver in versions {
                                    if let Some(platforms) =
                                        ver.get("platforms").and_then(|p| p.as_table())
                                    {
                                        for (_plat, plat_val) in platforms {
                                            if let Some(sp) =
                                                plat_val.get("store_path").and_then(|s| s.as_str())
                                            {
                                                let hash = extract_hash(sp).to_string();
                                                all_store_entries.push(RegistryVerifyStoreEntry {
                                                    store_hash: hash.clone(),
                                                    store_path: sp.to_string(),
                                                    package_name: pkg_name.clone(),
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            printer.error(&format!("{}: {e}", path.display()));
                            errors += 1;
                        }
                    }
                }
            }
        }
    }

    if let Some(filter) = package {
        if !matched_package_filter {
            bail!("package '{filter}' not found in registry");
        }
    }

    if fix {
        let content_addressed = registry_content_addressed(&dir);
        let mut seen = HashSet::new();
        for entry in &all_store_entries {
            if seen.insert(entry.store_hash.clone()) {
                write_store_files(&dir, &entry.store_path, content_addressed, false, printer)
                    .with_context(|| {
                        format!(
                            "regenerating store/ records for {} ({})",
                            entry.package_name, entry.store_path
                        )
                    })?;
                repaired += 1;
            }
        }
        if repaired > 0 {
            printer.success(&format!(
                "Regenerated store/ records for {repaired} package(s)."
            ));
        }
    }

    // The store/ realisation graph, for coverage checks below (RFC-0005). A
    // malformed graph is an error; an absent one downgrades to a warning
    // (legacy registry - consumers fall back to unauthenticated narinfo).
    let store_graph = match StoreMap::load(&dir) {
        Ok(map) => {
            if !map.is_present() {
                printer.warning(
                    "registry publishes no store/ realisation graph; consumer NAR \
                     verification falls back to unauthenticated narinfo hashes",
                );
            }
            map
        }
        Err(e) => {
            printer.error(&format!("store/ graph failed to load: {e:#}"));
            errors += 1;
            StoreMap::default()
        }
    };

    // Verify graph coverage: every package root and every member reachable
    // from it via dependency edges must have a record with a blessed NAR.
    let mut roots_checked = 0u32;
    if store_graph.is_present() {
        for entry in &all_store_entries {
            let pkg_name = &entry.package_name;
            roots_checked += 1;
            let mut seen = HashSet::new();
            let mut stack = vec![entry.store_hash.clone()];
            while let Some(hash) = stack.pop() {
                if !seen.insert(hash.clone()) {
                    continue;
                }
                match store_graph.get(&hash) {
                    None => {
                        printer.warning(&format!(
                            "{pkg_name}: closure member {hash} has no store/ record \
                             (run `apr store backfill` or `apr verify --fix`)"
                        ));
                        errors += 1;
                    }
                    Some(record) if record.blessed_nars().is_empty() => {
                        printer.warning(&format!(
                            "{pkg_name}: store/ record {hash} has no blessed NAR"
                        ));
                        errors += 1;
                    }
                    Some(_) => {
                        stack.extend(store_graph.direct_deps(&hash));
                    }
                }
            }
        }
    }

    if errors == 0 {
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "action": "verify",
                "status": "ok",
                "registry": registry_name,
                "package": package,
                "fix": fix,
                "checked": checked,
                "roots": roots_checked,
                "repaired": repaired,
                "errors": 0,
            }));
        } else {
            printer.success(&format!(
                "Verified {checked} package(s), {roots_checked} closure root(s), no errors."
            ));
        }
    } else {
        printer.error(&format!(
            "Verified {checked} package(s), {roots_checked} closure root(s), {errors} error(s) found."
        ));
        bail!("registry verification failed with {errors} error(s)");
    }

    Ok(())
}

#[cfg(test)]
mod tests;
