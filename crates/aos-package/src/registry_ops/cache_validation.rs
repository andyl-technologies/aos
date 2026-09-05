//! HTTP cache reachability validation and removal of missing catalog entries.

use crate::config::ApmConfig;
use crate::registry::store::{NarBytes, StoreMap};
use crate::registry_ops::config::{registry_dir, resolve_mirrors};
use crate::registry_ops::store_paths::extract_hash;
use crate::types::{CacheEntry, validate_package_name};
use anyhow::{Context, Result, bail};
use aos_core::nar::info as narinfo;
use aos_core::output::{OutputMode, Printer};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// `apr validate` — checks that published artifacts are downloadable from
/// the registry's caches.
///
/// For every published store path and image artifact (optionally filtered
/// by `--package` and `--platform`), fetches the `.narinfo` from each
/// cache listed in `registry.toml`, cross-checks its store path and NAR
/// hash against the registry metadata, and probes the referenced NAR with
/// an HTTP `HEAD`. An entry counts as found when any cache passes all
/// checks. Requests run with up to `--jobs` in parallel. With `--fix`,
/// entries missing from every cache are pruned from the registry metadata
/// on disk (the prune is not committed).
///
/// # Errors
///
/// Fails when a `--package` filter is not a safe package name, when
/// `--jobs` is zero, when entries are missing and `--fix` was not given
/// (or pruned nothing), or when reading registry metadata or running the
/// validation tasks fails.
#[allow(clippy::too_many_arguments)]
pub async fn validate(
    config: &ApmConfig,
    package: Option<&str>,
    platform: Option<&str>,
    fix: bool,
    jobs: u32,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let mirrors = resolve_mirrors(&dir);
    if let Some(package) = package {
        validate_package_name(package)?;
    }
    if jobs == 0 {
        bail!("--jobs must be greater than zero");
    }

    if mirrors.is_empty() {
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "status": "no_caches",
                "package": package,
                "platform": platform,
                "fix": fix,
                "jobs": jobs,
                "caches": 0,
                "checked": 0,
                "found": 0,
                "missing": 0,
                "missing_entries": [],
                "removed": 0,
            }));
            return Ok(());
        }
        printer.warning("No caches configured in registry.toml. Cannot validate.");
        return Ok(());
    }

    let entries = collect_cache_validation_entries(&dir, package, platform)?;

    if entries.is_empty() {
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "status": "no_entries",
                "package": package,
                "platform": platform,
                "fix": fix,
                "jobs": jobs,
                "caches": mirrors.len(),
                "checked": 0,
                "found": 0,
                "missing": 0,
                "missing_entries": [],
                "removed": 0,
            }));
            return Ok(());
        }
        printer.info("No entries to validate.");
        return Ok(());
    }

    printer.info(&format!(
        "Validating {} entries against {} cache(s) with {} parallel requests...",
        entries.len(),
        mirrors.len(),
        jobs,
    ));

    let client = reqwest::Client::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(jobs as usize));
    let mut handles = Vec::new();

    for entry in entries {
        let client = client.clone();
        let mirrors = mirrors.clone();
        let permit = semaphore.clone().acquire_owned().await?;

        let handle = tokio::spawn(async move {
            let result = validate_cache_entry(&client, &mirrors, entry).await;
            drop(permit);
            result
        });
        handles.push(handle);
    }

    let mut missing = 0u32;
    let mut ok = 0u32;
    let mut missing_store_paths = HashSet::new();
    let mut results = Vec::new();
    for handle in handles {
        let result = handle.await?;
        if result.found {
            ok += 1;
        } else {
            missing += 1;
            missing_store_paths.insert(result.entry.store_path.clone());
            let detail = result
                .details
                .first()
                .map(|detail| format!(" ({detail})"))
                .unwrap_or_default();
            printer.warning(&format!(
                "{}: {} not found in any cache{}",
                result.entry.name, result.entry.store_path, detail
            ));
        }
        results.push(result);
    }

    if missing == 0 {
        if printer.mode() == OutputMode::Json {
            printer.json(&cache_validation_summary_json(
                "ok",
                package,
                platform,
                fix,
                jobs,
                mirrors.len(),
                ok,
                missing,
                0,
                &results,
            ));
            return Ok(());
        }
        printer.success(&format!("All {ok} entries found in caches."));
    } else if fix {
        let removed = remove_missing_cache_entries(&dir, &missing_store_paths)?;
        if removed == 0 {
            if printer.mode() == OutputMode::Json {
                bail!(
                    "{}; no matching registry entries removed.",
                    cache_validation_missing_error(ok, missing, &results)
                );
            }
            bail!("{ok} found, {missing} missing; no matching registry entries removed.");
        }
        if printer.mode() == OutputMode::Json {
            printer.json(&cache_validation_summary_json(
                "fixed",
                package,
                platform,
                fix,
                jobs,
                mirrors.len(),
                ok,
                missing,
                removed,
                &results,
            ));
            return Ok(());
        }
        let noun = if removed == 1 { "entry" } else { "entries" };
        printer.success(&format!(
            "Removed {removed} missing cache {noun} from registry metadata."
        ));
    } else {
        if printer.mode() == OutputMode::Json {
            bail!("{}", cache_validation_missing_error(ok, missing, &results));
        }
        bail!("{ok} found, {missing} missing.");
    }

    Ok(())
}

/// One (store path, NAR hash) pair that `apr validate` checks against the
/// caches.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheValidationEntry {
    name: String,
    platform: String,
    store_path: String,
    store_hash: String,
    /// Acceptable NAR hashes for this path. A legacy TOML entry has one;
    /// a `store/` record may have several blessed realisations, any
    /// of which a cache may legitimately serve (RFC-0005 §2.2).
    nar_hashes: Vec<String>,
}

/// Outcome of probing the caches for one entry; `details` collects the
/// per-cache failure reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheValidationResult {
    entry: CacheValidationEntry,
    found: bool,
    details: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn cache_validation_summary_json(
    status: &str,
    package: Option<&str>,
    platform: Option<&str>,
    fix: bool,
    jobs: u32,
    caches: usize,
    found: u32,
    missing: u32,
    removed: usize,
    results: &[CacheValidationResult],
) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "package": package,
        "platform": platform,
        "fix": fix,
        "jobs": jobs,
        "caches": caches,
        "checked": found + missing,
        "found": found,
        "missing": missing,
        "missing_entries": results
            .iter()
            .filter(|result| !result.found)
            .map(cache_validation_result_json)
            .collect::<Vec<_>>(),
        "removed": removed,
    })
}

fn cache_validation_result_json(result: &CacheValidationResult) -> serde_json::Value {
    serde_json::json!({
        "name": &result.entry.name,
        "platform": &result.entry.platform,
        "store_path": &result.entry.store_path,
        "store_hash": &result.entry.store_hash,
        "nar_hashes": &result.entry.nar_hashes,
        "details": &result.details,
    })
}

fn cache_validation_missing_error(
    found: u32,
    missing: u32,
    results: &[CacheValidationResult],
) -> String {
    let missing_entries = results
        .iter()
        .filter(|result| !result.found)
        .map(|result| {
            let detail = result
                .details
                .first()
                .map(|detail| format!(" ({detail})"))
                .unwrap_or_default();
            format!(
                "{}: {} not found in any cache{}",
                result.entry.name, result.entry.store_path, detail
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    if missing_entries.is_empty() {
        format!("{found} found, {missing} missing")
    } else {
        format!("{found} found, {missing} missing: {missing_entries}")
    }
}

/// Gather every published (store path, NAR hash) pair from the registry's
/// package TOMLs — including image artifacts — honoring optional package
/// and platform filters. The result is sorted and deduplicated.
fn collect_cache_validation_entries(
    dir: &Path,
    package_filter: Option<&str>,
    platform_filter: Option<&str>,
) -> Result<Vec<CacheValidationEntry>> {
    let packages_dir = dir.join("packages");
    let mut entries = Vec::new();

    if !packages_dir.is_dir() {
        return Ok(entries);
    }

    // Newer registries record output NAR hashes in the store/ graph rather
    // than the package TOML; load it once for the fallback. A malformed graph
    // is a hard error (matching Registry::load) - silently treating it as
    // absent would validate nothing on a post-RFC registry.
    let store_graph = StoreMap::load(dir).context("loading store/ graph for cache validation")?;

    for letter_entry in std::fs::read_dir(&packages_dir)
        .with_context(|| format!("reading {}", packages_dir.display()))?
    {
        let letter_entry = letter_entry?;
        if !letter_entry.path().is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(letter_entry.path())
            .with_context(|| format!("reading {}", letter_entry.path().display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            collect_cache_validation_entries_from_package(
                &path,
                package_filter,
                platform_filter,
                &store_graph,
                &mut entries,
            )?;
        }
    }

    entries.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.platform.cmp(&b.platform))
            .then_with(|| a.store_path.cmp(&b.store_path))
    });
    entries.dedup();
    Ok(entries)
}

fn collect_cache_validation_entries_from_package(
    path: &Path,
    package_filter: Option<&str>,
    platform_filter: Option<&str>,
    store_graph: &StoreMap,
    entries: &mut Vec<CacheValidationEntry>,
) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading package metadata {}", path.display()))?;
    let toml_val: toml::Value =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    let name = toml_val
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    if package_filter.is_some_and(|filter| filter != name) {
        return Ok(());
    }

    let Some(versions) = toml_val.get("versions").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for version in versions {
        let Some(platforms) = version.get("platforms").and_then(|v| v.as_table()) else {
            continue;
        };
        for (platform, entry) in platforms {
            if platform_filter.is_some_and(|filter| filter != platform) {
                continue;
            }
            let Some(store_path) = entry.get("store_path").and_then(|v| v.as_str()) else {
                continue;
            };
            // Acceptable hashes: the legacy TOML nar_hash, or ALL blessed
            // NARs from the store/ graph (a cache may legitimately serve any
            // of them - RFC-0005 §2.3).
            let mut nar_hashes: Vec<String> = entry
                .get("nar_hash")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .into_iter()
                .collect();
            if nar_hashes.is_empty() {
                nar_hashes.extend(
                    store_graph
                        .blessed_nars(extract_hash(store_path))
                        .iter()
                        .map(NarBytes::nar_hash),
                );
            }
            if nar_hashes.is_empty() {
                continue;
            }
            entries.push(CacheValidationEntry {
                name: name.to_string(),
                platform: platform.to_string(),
                store_path: store_path.to_string(),
                store_hash: extract_hash(store_path).to_string(),
                nar_hashes,
            });
            if let Some(images) = entry.get("images").and_then(|v| v.as_array()) {
                for image in images {
                    let Some(image_store_path) = image.get("store_path").and_then(|v| v.as_str())
                    else {
                        continue;
                    };
                    let Some(image_nar_hash) = image.get("nar_hash").and_then(|v| v.as_str())
                    else {
                        continue;
                    };
                    entries.push(CacheValidationEntry {
                        name: name.to_string(),
                        platform: platform.to_string(),
                        store_path: image_store_path.to_string(),
                        store_hash: extract_hash(image_store_path).to_string(),
                        nar_hashes: vec![image_nar_hash.to_string()],
                    });
                }
            }
        }
    }
    Ok(())
}

/// Prune registry metadata entries whose store paths are in
/// `missing_store_paths` (`apr validate --fix`).
///
/// Removes matching platform entries and image artifacts, then drops
/// versions left without platforms and deletes package files left without
/// versions. Returns the number of entries removed. Changes are written to
/// the working tree only — nothing is committed.
fn remove_missing_cache_entries(
    dir: &Path,
    missing_store_paths: &HashSet<String>,
) -> Result<usize> {
    if missing_store_paths.is_empty() {
        return Ok(0);
    }

    let packages_dir = dir.join("packages");
    let mut removed = 0usize;

    if !packages_dir.is_dir() {
        return Ok(removed);
    }

    for letter_entry in fs::read_dir(&packages_dir)
        .with_context(|| format!("reading {}", packages_dir.display()))?
    {
        let letter_entry = letter_entry?;
        if !letter_entry.path().is_dir() {
            continue;
        }

        for entry in fs::read_dir(letter_entry.path())
            .with_context(|| format!("reading {}", letter_entry.path().display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
                continue;
            }
            removed += remove_missing_cache_entries_from_package(&path, missing_store_paths)?;
        }
    }

    Ok(removed)
}

fn remove_missing_cache_entries_from_package(
    path: &Path,
    missing_store_paths: &HashSet<String>,
) -> Result<usize> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading package metadata {}", path.display()))?;
    let mut toml_val: toml::Value =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    let mut removed = 0usize;
    let mut remove_package = false;

    if let Some(versions) = toml_val
        .get_mut("versions")
        .and_then(|value| value.as_array_mut())
    {
        for version in versions.iter_mut() {
            let Some(platforms) = version
                .as_table_mut()
                .and_then(|table| table.get_mut("platforms"))
                .and_then(|value| value.as_table_mut())
            else {
                continue;
            };

            let platform_names: Vec<String> = platforms
                .iter()
                .filter_map(|(platform, entry)| {
                    let store_path = entry.get("store_path").and_then(|value| value.as_str())?;
                    if missing_store_paths.contains(store_path) {
                        Some(platform.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for platform in platform_names {
                if platforms.remove(&platform).is_some() {
                    removed += 1;
                }
            }

            for (_platform_name, platform) in platforms.iter_mut() {
                let Some(platform_table) = platform.as_table_mut() else {
                    continue;
                };
                let remove_images_key = if let Some(images) = platform_table
                    .get_mut("images")
                    .and_then(|value| value.as_array_mut())
                {
                    let before = images.len();
                    images.retain(|image| {
                        let remove = image
                            .get("store_path")
                            .and_then(|value| value.as_str())
                            .map(|store_path| missing_store_paths.contains(store_path))
                            .unwrap_or(false);
                        !remove
                    });
                    removed += before - images.len();
                    images.is_empty()
                } else {
                    false
                };
                if remove_images_key {
                    platform_table.remove("images");
                }
            }
        }

        versions.retain(|version| {
            version
                .get("platforms")
                .and_then(|platforms| platforms.as_table())
                .map(|platforms| !platforms.is_empty())
                .unwrap_or(false)
        });
        remove_package = versions.is_empty();
    }

    if removed > 0 {
        if remove_package {
            fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
        } else {
            fs::write(path, toml::to_string_pretty(&toml_val)?)
                .with_context(|| format!("writing {}", path.display()))?;
        }
    }

    Ok(removed)
}

/// Probe each mirror for one entry: fetch the `.narinfo`, cross-check its
/// store path and NAR hash against the registry metadata, then `HEAD` the
/// NAR it references. The first cache that fully matches wins; every
/// per-cache failure is accumulated as a detail string for diagnostics.
async fn validate_cache_entry(
    client: &reqwest::Client,
    mirrors: &[CacheEntry],
    entry: CacheValidationEntry,
) -> CacheValidationResult {
    let mut details = Vec::new();
    for cache in mirrors {
        let base = cache.url.trim_end_matches('/');
        let narinfo_url =
            crate::download::join_cache_url(base, &format!("{}.narinfo", entry.store_hash));

        let narinfo = match client.get(&narinfo_url).send().await {
            Ok(response) if response.status().is_success() => match response.text().await {
                Ok(text) => match narinfo::parse(&text) {
                    Ok(narinfo) => narinfo,
                    Err(err) => {
                        details.push(format!("{narinfo_url}: invalid narinfo: {err}"));
                        continue;
                    }
                },
                Err(err) => {
                    details.push(format!("{narinfo_url}: failed reading narinfo body: {err}"));
                    continue;
                }
            },
            Ok(response) => {
                details.push(format!("{narinfo_url}: HTTP {}", response.status()));
                continue;
            }
            Err(err) => {
                details.push(format!("{narinfo_url}: {err}"));
                continue;
            }
        };

        if narinfo.store_path != entry.store_path {
            details.push(format!(
                "{narinfo_url}: narinfo store path {} did not match registry path {}",
                narinfo.store_path, entry.store_path
            ));
            continue;
        }
        // Registry hashes may be SRI (legacy TOML) or nixbase32 (store/ graph
        // map); narinfo hashes vary by emitter. Compare normalized, and
        // accept the cache if it serves ANY blessed realisation.
        let narinfo_norm = aos_core::nar::cache::normalize_sha256_nix32(&narinfo.nar_hash);
        if !entry
            .nar_hashes
            .iter()
            .any(|expected| aos_core::nar::cache::normalize_sha256_nix32(expected) == narinfo_norm)
        {
            details.push(format!(
                "{narinfo_url}: narinfo NarHash {} matched none of the registry NarHash(es) [{}]",
                narinfo.nar_hash,
                entry.nar_hashes.join(", ")
            ));
            continue;
        }

        let nar_url = crate::download::join_cache_url(base, &narinfo.url);
        match client.head(&nar_url).send().await {
            Ok(response) if response.status().is_success() => {
                return CacheValidationResult {
                    entry,
                    found: true,
                    details,
                };
            }
            Ok(response) => {
                details.push(format!("{nar_url}: HTTP {}", response.status()));
            }
            Err(err) => {
                details.push(format!("{nar_url}: {err}"));
            }
        }
    }

    CacheValidationResult {
        entry,
        found: false,
        details,
    }
}

#[cfg(test)]
mod tests;
