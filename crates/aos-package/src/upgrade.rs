use std::collections::HashSet;
use std::io::Write;

use anyhow::{Context, Result};

use super::config::ApmConfig;
use super::download::{
    DownloadRequest, ResolvedDownload, default_engine, download_nars, fetch_narinfos,
    resolve_mirror,
};
use super::profile::Profile;
use super::profile::merge::build_fhs_tree;
use super::profile::meta::{list_meta, write_meta};
use super::registry::{RegistrySet, store_path_hash};
use super::resolve::resolve_closure;
use super::store::{create_gc_roots, filter_missing, import_nar};
use super::sysroot_lock::{self, IgnoreSysrootLock};
use super::types::{ApmMeta, InstalledMeta, PackageMeta};
use super::verify::{verify_download_hash, verify_nar_hash};
use aos_core::error::AosError;
use aos_core::output::Printer;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// An upgrade candidate: a package with a different version in the registry.
pub struct UpgradeCandidate {
    pub name: String,
    pub old_version: String,
    pub new_version: String,
    pub old_store_hash: String,
    pub new_meta: PackageMeta,
    pub registry: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run `apm upgrade [packages]`.
///
/// Compares installed packages against the registry to find upgradable ones,
/// then downloads, verifies, imports, and switches to a new generation.
pub async fn run(
    config: &ApmConfig,
    packages: &[String],
    exclude: &[String],
    dry_run: bool,
    yes: bool,
    ignore_lock: &IgnoreSysrootLock,
    printer: &Printer,
) -> Result<()> {
    // Step 1: Open profile and load installed metadata.
    printer.step(1, 7, "Loading installed packages...");
    let profile = Profile::open(config.scope)?;
    let installed = list_meta(&profile)?;

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
        printer.info("All packages are up to date.");
        return Ok(());
    }

    // Step 5: Print upgrade summary.
    print_upgrade_summary(&to_upgrade, &held_back, printer);

    if dry_run {
        printer.info("Dry run -- no changes made.");
        return Ok(());
    }

    // Step 6: Prompt for confirmation (unless --yes).
    if !yes && !config.settings.assume_yes {
        confirm(printer)?;
    }

    // Step 7: Resolve new closures for each upgraded package.
    printer.step(3, 7, "Resolving dependencies...");
    let mut all_new_metas: Vec<PackageMeta> = Vec::new();
    let mut upgrade_closures: Vec<(String, Vec<PackageMeta>)> = Vec::new();

    for candidate in &to_upgrade {
        let closure = resolve_closure(&registries, &candidate.name, Some(&candidate.registry))
            .with_context(|| format!("resolving upgrade for '{}'", candidate.name))?;
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

    // Filter to only missing store paths.
    let store_paths: Vec<String> = all_new_metas.iter().map(|m| m.store_path.clone()).collect();
    let missing = filter_missing(&store_paths).await?;
    let missing_set: HashSet<&str> = missing.iter().map(|s| s.as_str()).collect();
    let to_download: Vec<&PackageMeta> = all_new_metas
        .iter()
        .filter(|m| missing_set.contains(m.store_path.as_str()))
        .collect();

    // Download missing NARs.
    if !to_download.is_empty() {
        printer.step(4, 7, "Downloading packages...");

        let requests = build_download_requests(&upgrade_closures, &to_download, config)?;
        let engine = std::sync::Arc::new(default_engine());
        let resolved: Vec<ResolvedDownload> = fetch_narinfos(
            std::sync::Arc::clone(&engine),
            &requests,
            config.settings.parallel_downloads,
            printer,
        )
        .await?;
        let cache_dir = config.nar_cache_path();

        let results = download_nars(
            &resolved,
            &cache_dir,
            config.settings.parallel_downloads,
            printer,
        )
        .await?;

        // Verify downloads.
        printer.step(5, 7, "Verifying downloads...");
        for result in &results {
            verify_download_hash(&result.local_path, &result.download_hash)
                .with_context(|| format!("verifying download for {}", result.store_path))?;
            verify_nar_hash(&result.local_path, &result.nar_hash)
                .with_context(|| format!("verifying NAR hash for {}", result.store_path))?;
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
    } else {
        printer.info("All packages already in store, skipping download.");
    }

    // Step 8: Create new generation.
    printer.step(6, 7, "Updating profile...");
    let prev_gen = profile.current_generation()?;
    let new_gen = profile.new_generation()?;

    // Copy existing roots from the previous generation.
    if let Some(ref prev) = prev_gen {
        super::install::copy_roots_for_upgrade(prev, &new_gen, &to_upgrade)?;
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

    // Carry forward metadata for non-upgraded packages.
    let upgraded_names: HashSet<&str> = to_upgrade.iter().map(|c| c.name.as_str()).collect();
    for meta in &installed {
        if let Some(ref apm) = meta.apm {
            if upgraded_names.contains(apm.name.as_str()) {
                continue; // Will be replaced with new metadata below.
            }
        }
        let hash = store_path_hash(&meta.store_path).to_string();
        write_meta(&profile, &hash, meta)?;
    }

    // Write new metadata for upgraded packages.
    for (registry_name, closure) in &upgrade_closures {
        for meta in closure {
            let hash = store_path_hash(&meta.store_path).to_string();
            let is_explicit = upgraded_names.contains(meta.name.as_str());

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
                    explicit: is_explicit,
                    registry: registry_name.clone(),
                    installed_at: now_iso.clone(),
                    held: false,
                }),
            };

            write_meta(&profile, &hash, &installed_meta)?;
        }
    }

    // Build FHS tree for the new generation.
    let roots = new_gen.roots()?;
    build_fhs_tree(&new_gen, &roots, printer)?;

    // Atomic switch to the new generation.
    profile.switch_to(&new_gen)?;

    printer.step(7, 7, "Done!");
    printer.success(&format!(
        "Upgraded {} package(s) in generation {}.",
        to_upgrade.len(),
        new_gen.number,
    ));

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
        let old_hash = store_path_hash(&meta.store_path);
        let new_hash = store_path_hash(&reg_meta.store_path);

        if old_hash != new_hash {
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
    // Build a map of registry_name -> mirror_url.
    let mirror_map: std::collections::HashMap<String, String> = closures
        .iter()
        .map(|(registry_name, _)| {
            let reg_config = config
                .registries
                .iter()
                .find(|(cfg, _)| cfg.name == *registry_name)
                .map(|(cfg, _)| cfg);
            let mirror_url = if let Some(cfg) = reg_config {
                resolve_mirror(cfg)
            } else {
                format!("https://registry.aos.dev/{}", registry_name)
            };
            (registry_name.clone(), mirror_url)
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
        let mirror_url = mirror_map
            .get(registry_name)
            .context("internal error: missing mirror for registry")?;

        requests.push(DownloadRequest {
            store_path: meta.store_path.clone(),
            mirror_url: mirror_url.clone(),
        });
    }

    Ok(requests)
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
    use crate::types::{ApmMeta, InstalledMeta, PackageMeta, RegistryConfig};

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
                explicit: true,
                registry: registry.into(),
                installed_at: "2026-02-16T00:00:00Z".into(),
                held,
            }),
        }
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
