use std::collections::HashSet;
use std::io::Write;

use anyhow::{Context, Result};

use super::config::ApmConfig;
use super::download::{download_nars, resolve_mirror, DownloadRequest};
use super::profile::merge::build_fhs_tree;
use super::profile::meta::write_meta;
use super::profile::Profile;
use super::registry::{store_path_hash, RegistrySet};
use super::resolve::{collect_unique_metas, resolve_multiple, ResolvedClosure};
use super::store::{create_gc_roots, filter_missing, import_nar};
use super::types::{ApmMeta, InstalledMeta, PackageMeta};
use super::verify::{verify_download_hash, verify_nar_hash};
use aos_core::error::AosError;
use aos_core::output::Printer;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run `apm install <packages>`.
///
/// Full pipeline: resolve -> download -> verify -> import -> profile switch.
pub async fn run(
    config: &ApmConfig,
    packages: &[String],
    registry_filter: Option<&str>,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<()> {
    if packages.is_empty() {
        printer.info("No packages specified.");
        return Ok(());
    }

    // Step 1: Load registries from cache.
    printer.step(1, 7, "Loading registries...");
    let registries = load_registries(config)?;

    // Step 2: Resolve closures for all requested packages.
    printer.step(2, 7, "Resolving dependencies...");
    let closures = resolve_multiple(&registries, packages, registry_filter)?;

    // Check if any requested package is already provided by the sysroot.
    for closure in &closures {
        if let Some((sys_name, sys_ver)) =
            crate::sysroot::check_sysroot_containment(&closure.root.references, config)
        {
            printer.info(&format!(
                "{} {} already provided by sysroot {} {}",
                closure.root.name, closure.root.version, sys_name, sys_ver,
            ));
            return Ok(());
        }
    }

    // Step 3: Collect unique metas (dedup across closures).
    let all_metas = collect_unique_metas(&closures);

    // Step 4: Filter missing store paths.
    let store_paths: Vec<String> = all_metas.iter().map(|m| m.store_path.clone()).collect();
    let missing = filter_missing(&store_paths).await?;
    let missing_set: HashSet<&str> = missing.iter().map(|s| s.as_str()).collect();
    let to_download: Vec<&PackageMeta> = all_metas
        .iter()
        .filter(|m| missing_set.contains(m.store_path.as_str()))
        .copied()
        .collect();

    // Step 5: Print install summary.
    print_summary(&closures, packages, &to_download, &all_metas, printer);

    if dry_run {
        printer.info("Dry run -- no changes made.");
        return Ok(());
    }

    // Step 6: Prompt for confirmation (unless --yes).
    if !yes && !config.settings.assume_yes {
        confirm(printer)?;
    }

    // Step 7: Download missing NARs.
    if !to_download.is_empty() {
        printer.step(3, 7, "Downloading packages...");

        let requests = build_download_requests(&closures, &to_download, config)?;
        let cache_dir = config.nar_cache_path();

        let results = download_nars(
            &requests,
            &cache_dir,
            config.settings.parallel_downloads,
            printer,
        )
        .await?;

        // Verify downloads.
        printer.step(4, 7, "Verifying downloads...");
        for result in &results {
            verify_download_hash(&result.local_path, &result.download_hash)
                .with_context(|| format!("verifying download for {}", result.store_path))?;
            verify_nar_hash(&result.local_path, &result.nar_hash)
                .with_context(|| format!("verifying NAR hash for {}", result.store_path))?;
        }

        // Import NARs into the store.
        printer.step(5, 7, "Importing packages...");
        for result in &results {
            import_nar(&result.local_path, &result.store_path)
                .await
                .with_context(|| format!("importing {}", result.store_path))?;
        }
    } else {
        printer.info("All packages already in store, skipping download.");
    }

    // Step 8: Create new profile generation.
    printer.step(6, 7, "Updating profile...");
    let profile = Profile::open(config.scope)?;
    let prev_gen = profile.current_generation()?;
    let new_gen = profile.new_generation()?;

    // Copy existing roots from the previous generation (if any).
    if let Some(ref prev) = prev_gen {
        copy_roots(prev, &new_gen)?;
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
    let explicit_names: HashSet<&str> = packages.iter().map(|s| s.as_str()).collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let now_iso = chrono_iso8601(now);

    for closure in &closures {
        for meta in &closure.closure {
            let hash = store_path_hash(&meta.store_path).to_string();
            let is_explicit = explicit_names.contains(meta.name.as_str());

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
                    held: false,
                }),
            };

            write_meta(&profile, &hash, &installed)?;
        }
    }

    // Build FHS tree for the new generation.
    let roots = new_gen.roots()?;
    build_fhs_tree(&new_gen, &roots, printer)?;

    // Atomic switch to the new generation.
    profile.switch_to(&new_gen)?;

    printer.step(7, 7, "Done!");
    printer.success(&format!(
        "Installed {} package(s) in generation {}.",
        packages.len(),
        new_gen.number,
    ));

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

/// Load registries from the config's cache directory.
fn load_registries(config: &ApmConfig) -> Result<RegistrySet> {
    let reg_configs = config.enabled_registries();
    RegistrySet::load(&config.cache_path(), &reg_configs, &platform())
}

/// Copy GC root symlinks from a previous generation to a new one.
///
/// Copies both `usr/` and `src/` symlinks so that the new generation
/// inherits all packages from the previous one.
fn copy_roots(
    from: &super::profile::Generation,
    to: &super::profile::Generation,
) -> Result<()> {
    use std::os::unix::fs::symlink;

    // Copy usr/ roots.
    let from_usr = from.path.join("usr");
    let to_usr = to.path.join("usr");
    std::fs::create_dir_all(&to_usr)
        .with_context(|| format!("creating {}", to_usr.display()))?;

    if from_usr.is_dir() {
        for entry in std::fs::read_dir(&from_usr)? {
            let entry = entry?;
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
    std::fs::create_dir_all(&to_src)
        .with_context(|| format!("creating {}", to_src.display()))?;

    if from_src.is_dir() {
        for entry in std::fs::read_dir(&from_src)? {
            let entry = entry?;
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

/// Copy GC root symlinks from a previous generation to a new one,
/// skipping roots for packages being upgraded.
///
/// Used by the upgrade module to carry forward non-upgraded packages while
/// replacing the old store paths of upgraded ones with new ones.
pub fn copy_roots_for_upgrade(
    from: &super::profile::Generation,
    to: &super::profile::Generation,
    to_upgrade: &[super::upgrade::UpgradeCandidate],
) -> Result<()> {
    use std::os::unix::fs::symlink;

    let skip_hashes: HashSet<&str> = to_upgrade.iter().map(|c| c.old_store_hash.as_str()).collect();

    // Copy usr/ roots, skipping upgraded packages.
    let from_usr = from.path.join("usr");
    let to_usr = to.path.join("usr");
    std::fs::create_dir_all(&to_usr)
        .with_context(|| format!("creating {}", to_usr.display()))?;

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
    std::fs::create_dir_all(&to_src)
        .with_context(|| format!("creating {}", to_src.display()))?;

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
    to_download: &[&PackageMeta],
    all_metas: &[&PackageMeta],
    printer: &Printer,
) {
    let explicit_set: HashSet<&str> = explicit_names.iter().map(|s| s.as_str()).collect();

    // Collect explicitly-requested packages.
    let mut new_packages: Vec<String> = Vec::new();
    let mut dep_packages: Vec<String> = Vec::new();

    for closure in closures {
        for meta in &closure.closure {
            let label = format!("{} ({}, {})", meta.name, meta.version, closure.registry_name);
            if explicit_set.contains(meta.name.as_str()) {
                if !new_packages.iter().any(|s| s.starts_with(&meta.name)) {
                    new_packages.push(label);
                }
            } else if !dep_packages.iter().any(|s| s.starts_with(&meta.name)) {
                dep_packages.push(label);
            }
        }
    }

    printer.header("The following NEW packages will be installed:");
    for pkg in &new_packages {
        printer.plain(&format!("  {pkg}"));
    }

    if !dep_packages.is_empty() {
        printer.header("Additional dependencies:");
        for pkg in &dep_packages {
            printer.plain(&format!("  {pkg}"));
        }
    }

    let download_size: u64 = to_download.iter().map(|m| m.download_size).sum();
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
    // Build a map of registry_name -> mirror_url for quick lookup.
    let mirror_map: std::collections::HashMap<String, String> = closures
        .iter()
        .map(|c| {
            let reg_config = config
                .registries
                .iter()
                .find(|(cfg, _)| cfg.name == c.registry_name)
                .map(|(cfg, _)| cfg);
            let mirror_url = if let Some(cfg) = reg_config {
                resolve_mirror(cfg)
            } else {
                // Fallback: construct from the default pattern.
                format!("https://registry.aos.dev/{}/nar", c.registry_name)
            };
            (c.registry_name.clone(), mirror_url)
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
        let mirror_url = mirror_map
            .get(registry_name)
            .context("internal error: missing mirror for registry")?;

        requests.push(DownloadRequest {
            store_path: meta.store_path.clone(),
            nar_hash: meta.nar_hash.clone(),
            download_hash: meta.download_hash.clone(),
            download_size: meta.download_size,
            mirror_url: mirror_url.clone(),
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

    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z"
    )
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

        copy_roots(&from_gen, &to_gen).unwrap();

        // Verify usr/ root was copied.
        let usr_link = to_path.join("usr/abc123");
        assert!(usr_link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(
            std::fs::read_link(&usr_link).unwrap().to_string_lossy(),
            "/var/lib/store/abc123-curl-8.5.0"
        );

        // Verify src/ root was copied.
        let src_link = to_path.join("src/def456");
        assert!(src_link.symlink_metadata().unwrap().file_type().is_symlink());
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
        copy_roots(&from_gen, &to_gen).unwrap();

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

        copy_roots(&from_gen, &to_gen).unwrap();

        // Existing symlink in "to" should NOT be overwritten.
        let target = std::fs::read_link(to_path.join("usr/abc123")).unwrap();
        assert_eq!(target.to_string_lossy(), "/var/lib/store/new-target");
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
