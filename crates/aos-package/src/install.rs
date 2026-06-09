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
use super::profile::meta::{delete_meta, list_meta, write_meta};
use super::registry::{RegistrySet, store_path_hash};
use super::resolve::{ResolvedClosure, collect_unique_metas, resolve_multiple};
use super::store::{create_gc_roots, filter_missing, import_nar};
use super::sysroot_lock::{self, IgnoreSysrootLock};
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
    reinstall: bool,
    download_only: bool,
    no_deps: bool,
    dry_run: bool,
    yes: bool,
    ignore_lock: &IgnoreSysrootLock,
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
    let mut closures = resolve_multiple(&registries, packages, registry_filter)?;
    if no_deps {
        prune_dependency_members(&mut closures);
    }
    let profile = Profile::open(config.scope)?;
    let installed = list_meta(&profile)?;
    let all_metas = collect_unique_metas(&closures);
    let store_paths: Vec<String> = all_metas.iter().map(|m| m.store_path.clone()).collect();
    let missing = if reinstall {
        Vec::new()
    } else {
        filter_missing(&store_paths).await?
    };

    if !reinstall
        && missing.is_empty()
        && requested_closures_already_installed(&closures, &installed)
    {
        printer.info("All requested packages are already installed. No changes made.");
        return Ok(());
    }

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

    // Step 5: Fetch narinfo for each missing path so the summary can show
    // real compressed sizes and the download can use the cache's URL/hash.
    let requests = build_download_requests(&closures, &to_download, config)?;
    let engine = std::sync::Arc::new(default_engine());
    let resolved: Vec<ResolvedDownload> = if requests.is_empty() {
        Vec::new()
    } else {
        fetch_narinfos(
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
        printer.info("Dry run -- no changes made.");
        return Ok(());
    }

    // Step 7: Prompt for confirmation (unless --yes).
    if !yes && !config.settings.assume_yes {
        confirm(printer)?;
    }

    // Step 8: Download missing NARs.
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

        // Verify downloads.
        printer.step(4, 7, "Verifying downloads...");
        for result in &results {
            verify_download_hash(&result.local_path, &result.download_hash)
                .with_context(|| format!("verifying download for {}", result.store_path))?;
            verify_nar_hash(&result.local_path, &result.nar_hash)
                .with_context(|| format!("verifying NAR hash for {}", result.store_path))?;
        }

        if download_only {
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
    } else {
        printer.info("All packages already in store, skipping download.");
        if download_only {
            printer.info("Download only -- no profile changes made.");
            return Ok(());
        }
    }

    // Step 8: Create new profile generation.
    printer.step(6, 7, "Updating profile...");
    let prev_gen = profile.current_generation()?;
    let new_gen = profile.new_generation()?;
    let explicit_names: HashSet<&str> = packages.iter().map(|s| s.as_str()).collect();
    let replaced_store_hashes = installed_store_hashes_for_names(&installed, &explicit_names);

    // Copy existing roots from the previous generation (if any).
    if let Some(ref prev) = prev_gen {
        copy_roots_except_hashes(prev, &new_gen, &replaced_store_hashes)?;
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
    for hash in &replaced_store_hashes {
        delete_meta(&profile, hash)?;
    }
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

fn installed_apm_for_hash<'a>(installed: &'a [InstalledMeta], hash: &str) -> Option<&'a ApmMeta> {
    installed.iter().find_map(|meta| {
        if store_path_hash(&meta.store_path) == hash {
            meta.apm.as_ref()
        } else {
            None
        }
    })
}

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

fn installed_store_hashes_for_names(
    installed: &[InstalledMeta],
    package_names: &HashSet<&str>,
) -> HashSet<String> {
    installed
        .iter()
        .filter_map(|meta| {
            let apm = meta.apm.as_ref()?;
            if package_names.contains(apm.name.as_str()) {
                Some(store_path_hash(&meta.store_path).to_string())
            } else {
                None
            }
        })
        .collect()
}

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
/// replacing the old store paths of upgraded ones with new ones.
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
    // Build a map of registry_name -> mirror_url for quick lookup.
    let registries_base = config.scope.registries_path();
    let mirror_map: std::collections::HashMap<String, String> = closures
        .iter()
        .map(|c| {
            let reg_config = config
                .registries
                .iter()
                .find(|(cfg, _)| cfg.name == c.registry_name)
                .map(|(cfg, _)| cfg);
            let mirror_url = if let Some(cfg) = reg_config {
                resolve_mirror(&registries_base, cfg)
            } else {
                // Fallback: construct from the default pattern.
                format!("https://registry.aos.dev/{}", c.registry_name)
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
        }
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
            }),
        }
    }

    fn sample_closure(root: PackageMeta, closure: Vec<PackageMeta>) -> ResolvedClosure {
        ResolvedClosure {
            registry_name: "test-reg".to_string(),
            root,
            closure,
            total_nar_size: 1,
        }
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
    fn installed_store_hashes_for_names_selects_replaced_runtime_roots() {
        let installed = vec![
            sample_installed(
                "switch-tool",
                "1.0.0",
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-switch-tool-1.0.0",
            ),
            sample_installed(
                "kept-tool",
                "1.0.0",
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-kept-tool-1.0.0",
            ),
        ];
        let names = HashSet::from(["switch-tool"]);
        let hashes = installed_store_hashes_for_names(&installed, &names);

        assert!(hashes.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(!hashes.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
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
