//! System sysroot management (`apm install --system`, `apm upgrade --system`,
//! `apm rollback --system`).
//!
//! A sysroot package is a regular package with `sysroot = true`. Installing it
//! as a system sysroot creates a numbered generation under
//! `/var/lib/profiles/system/`, runs activation scripts, and compares kernels
//! to determine if a reboot is needed.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use aos_core::output::Printer;

use crate::config::ApmConfig;
use crate::download::{download_nars, resolve_mirror, DownloadRequest};
use crate::registry::{store_path_hash, RegistrySet};
use crate::resolve::{collect_unique_metas, resolve_multiple};
use crate::store::{filter_missing, import_nar};
use crate::types::{PackageMeta, ProfileScope, SystemGeneration, SystemGenerationState};
use crate::verify::{verify_download_hash, verify_nar_hash};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SYSTEM_STATE_FILE: &str = "state.json";
const BOOT_LOADER_ENTRY: &str = "/boot/loader/entries/aos.conf";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// `apm install <pkg> --system` — install a sysroot package as a system generation.
///
/// When `--image <FMT>` is specified, downloads the pre-compiled image instead
/// of the toplevel closure.
#[allow(clippy::too_many_arguments)]
pub async fn install_system(
    config: &ApmConfig,
    packages: &[String],
    registry_filter: Option<&str>,
    image_format: Option<&str>,
    image_output: Option<&str>,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<()> {
    if packages.len() != 1 {
        bail!("--system install requires exactly one package name");
    }
    let pkg_name = &packages[0];

    // Step 1: Load registries and resolve the package.
    printer.step(1, 8, "Loading registries...");
    let registries = load_registries(config)?;
    let closures = resolve_multiple(&registries, packages, registry_filter)?;

    if closures.is_empty() {
        bail!("package '{pkg_name}' not found");
    }

    let closure = &closures[0];
    let toplevel_meta = closure
        .closure
        .iter()
        .find(|m| m.name == *pkg_name)
        .ok_or_else(|| anyhow::anyhow!("resolved closure missing primary package"))?;

    if !toplevel_meta.sysroot {
        bail!(
            "package '{}' is not a sysroot package (missing sysroot = true)",
            pkg_name
        );
    }

    // Handle image download mode.
    if let Some(fmt) = image_format {
        return download_image(config, toplevel_meta, fmt, image_output, dry_run, printer).await;
    }

    // Check if already provided by current sysroot.
    if let Some(current_toplevel) = current_sysroot_store_path()? {
        if current_toplevel == toplevel_meta.store_path {
            printer.info(&format!(
                "{} {} is already the active system sysroot.",
                pkg_name, toplevel_meta.version,
            ));
            return Ok(());
        }
    }

    // Step 2: Determine missing store paths.
    printer.step(2, 8, "Checking store...");
    let all_metas = collect_unique_metas(&closures);
    let store_paths: Vec<String> = all_metas.iter().map(|m| m.store_path.clone()).collect();
    let missing = filter_missing(&store_paths).await?;
    let missing_set: HashSet<&str> = missing.iter().map(|s| s.as_str()).collect();
    let to_download: Vec<&PackageMeta> = all_metas
        .iter()
        .filter(|m| missing_set.contains(m.store_path.as_str()))
        .copied()
        .collect();

    // Step 3: Print summary.
    printer.step(3, 8, "Planning...");
    let download_size: u64 = to_download.iter().map(|m| m.download_size).sum();
    let total_refs = toplevel_meta.references.len();
    printer.kv("Package", &format!("{} {}", pkg_name, toplevel_meta.version));
    printer.kv("Closure paths", &format!("{}", all_metas.len()));
    printer.kv("Missing paths", &format!("{}", to_download.len()));
    printer.kv("Download size", &format_size(download_size));
    printer.kv("References", &format!("{total_refs}"));

    if dry_run {
        printer.info("Dry run -- no changes made.");
        return Ok(());
    }

    // Step 4: Prompt for confirmation.
    if !yes && !config.settings.assume_yes {
        confirm(printer)?;
    }

    // Step 5: Download missing NARs.
    if !to_download.is_empty() {
        printer.step(4, 8, "Downloading...");
        let requests = build_download_requests(&closures, &to_download, config)?;
        let nar_cache = config.nar_cache_path();

        let results = download_nars(
            &requests,
            &nar_cache,
            config.settings.parallel_downloads,
            printer,
        )
        .await?;

        // Step 6: Verify and import.
        printer.step(5, 8, "Verifying...");
        for result in &results {
            verify_download_hash(&result.local_path, &result.download_hash)
                .with_context(|| format!("verifying download for {}", result.store_path))?;
            verify_nar_hash(&result.local_path, &result.nar_hash)
                .with_context(|| format!("verifying NAR hash for {}", result.store_path))?;
        }

        printer.step(6, 8, "Importing...");
        for result in &results {
            import_nar(&result.local_path, &result.store_path)
                .await
                .with_context(|| format!("importing {}", result.store_path))?;
        }
    } else {
        printer.info("All paths already in store.");
    }

    // Step 7: Create new system generation.
    printer.step(7, 8, "Creating system generation...");
    let profile_path = ProfileScope::System.profile_path();
    std::fs::create_dir_all(&profile_path)
        .with_context(|| format!("creating {}", profile_path.display()))?;

    let mut state = load_generation_state(&profile_path)?;
    let old_gen = state.generations.iter().find(|g| g.number == state.current).cloned();

    let gen_num = state.next;
    state.next += 1;

    let now_iso = chrono_iso8601_now();
    let kernel_path = resolve_kernel_path(&toplevel_meta.store_path);

    let new_gen = SystemGeneration {
        number: gen_num,
        toplevel: toplevel_meta.store_path.clone(),
        version: toplevel_meta.version.clone(),
        package_name: pkg_name.clone(),
        registry: closure.registry_name.clone(),
        created_at: now_iso,
        kernel_path: kernel_path.clone(),
    };

    // Create generation directory with a symlink to the toplevel.
    let gen_dir = profile_path.join(format!("gen-{gen_num}"));
    std::fs::create_dir_all(&gen_dir)?;
    let toplevel_link = gen_dir.join("toplevel");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&toplevel_meta.store_path, &toplevel_link)
        .with_context(|| format!("creating toplevel symlink in gen-{gen_num}"))?;

    state.generations.push(new_gen);
    state.current = gen_num;
    save_generation_state(&profile_path, &state)?;

    // Atomic switch: current -> gen-N
    let current_link = profile_path.join("current");
    let tmp_link = profile_path.join(".current.tmp");
    let _ = std::fs::remove_file(&tmp_link);
    #[cfg(unix)]
    std::os::unix::fs::symlink(format!("gen-{gen_num}"), &tmp_link)?;
    std::fs::rename(&tmp_link, &current_link)?;

    // Step 8: Activation and kernel comparison.
    printer.step(8, 8, "Activating...");

    // Run activation script if it exists.
    let activate_script = format!("{}/activate", toplevel_meta.store_path);
    if Path::new(&activate_script).exists() {
        let status = std::process::Command::new(&activate_script)
            .status()
            .with_context(|| format!("running {activate_script}"))?;
        if !status.success() {
            printer.warning("Activation script returned non-zero exit code.");
        }
    }

    // Compare kernels.
    let mut reboot_needed = false;
    if let Some(ref old) = old_gen {
        let old_kernel = old.kernel_path.as_deref().unwrap_or("");
        let new_kernel = kernel_path.as_deref().unwrap_or("");
        if !old_kernel.is_empty() && !new_kernel.is_empty() && old_kernel != new_kernel {
            reboot_needed = true;
            update_boot_loader(new_kernel, &toplevel_meta.store_path)?;
            printer.warning(&format!(
                "Kernel updated: {} -> {}. Reboot required.",
                short_path(old_kernel),
                short_path(new_kernel),
            ));
        }
    }

    // Diff services if both old and new toplevels have etc/systemd.
    if let Some(ref old) = old_gen {
        let diff = diff_services(&old.toplevel, &toplevel_meta.store_path);
        run_service_diff(&diff, printer);
    }

    printer.success(&format!(
        "System generation {gen_num} active: {} {}{}",
        pkg_name,
        toplevel_meta.version,
        if reboot_needed { " (reboot required)" } else { "" },
    ));

    Ok(())
}

/// `apm upgrade --system` — check for newer sysroot version and apply.
pub async fn upgrade_system(
    config: &ApmConfig,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    let profile_path = ProfileScope::System.profile_path();
    let state = load_generation_state(&profile_path)?;

    let current_gen = state
        .generations
        .iter()
        .find(|g| g.number == state.current)
        .ok_or_else(|| anyhow::anyhow!("no active system generation"))?;

    printer.info(&format!(
        "Current sysroot: {} {} (generation {})",
        current_gen.package_name, current_gen.version, current_gen.number,
    ));

    // Load registries and check for newer version.
    let registries = load_registries(config)?;
    let _platform = "x86_64-linux";

    let mut newer_meta: Option<(PackageMeta, String)> = None;
    for reg in registries.registries() {
        if let Some(meta) = reg.packages.get(&current_gen.package_name) {
            if meta.version != current_gen.version && meta.sysroot {
                newer_meta = Some((meta.clone(), reg.config.name.clone()));
                break;
            }
        }
    }

    let (new_meta, reg_name) = match newer_meta {
        Some(m) => m,
        None => {
            printer.success("System is up to date.");
            return Ok(());
        }
    };

    printer.info(&format!(
        "Upgrade available: {} {} -> {}",
        current_gen.package_name, current_gen.version, new_meta.version,
    ));

    if dry_run {
        printer.info("Dry run -- no changes made.");
        return Ok(());
    }

    // Delegate to install_system for the actual upgrade.
    install_system(
        config,
        &[current_gen.package_name.clone()],
        Some(&reg_name),
        None,
        None,
        false,
        true, // auto-yes for upgrade flow
        printer,
    )
    .await
}

/// `apm rollback --system [--generation N] [--list]`
pub async fn rollback_system(
    _config: &ApmConfig,
    generation: Option<u32>,
    list: bool,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    let profile_path = ProfileScope::System.profile_path();
    let mut state = load_generation_state(&profile_path)?;

    if list {
        if state.generations.is_empty() {
            printer.info("No system generations.");
        } else {
            printer.header("System generations:");
            for sysgen in &state.generations {
                let marker = if sysgen.number == state.current {
                    " (current)"
                } else {
                    ""
                };
                printer.plain(&format!(
                    "  gen-{}: {} {} [{}]{}",
                    sysgen.number, sysgen.package_name, sysgen.version, sysgen.created_at, marker,
                ));
            }
        }
        return Ok(());
    }

    let current = state
        .generations
        .iter()
        .find(|g| g.number == state.current)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no active system generation"))?;

    let target = if let Some(n) = generation {
        state
            .generations
            .iter()
            .find(|g| g.number == n)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("generation {n} not found"))?
    } else {
        // Find the most recent generation before current.
        state
            .generations
            .iter()
            .rev()
            .find(|g| g.number < current.number)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no previous system generation to roll back to"))?
    };

    printer.info(&format!(
        "Rolling back system from generation {} ({} {}) to generation {} ({} {}).",
        current.number,
        current.package_name,
        current.version,
        target.number,
        target.package_name,
        target.version,
    ));

    if dry_run {
        printer.info("Dry run -- no changes made.");
        return Ok(());
    }

    // Switch current symlink.
    state.current = target.number;
    save_generation_state(&profile_path, &state)?;

    let current_link = profile_path.join("current");
    let tmp_link = profile_path.join(".current.tmp");
    let _ = std::fs::remove_file(&tmp_link);
    #[cfg(unix)]
    std::os::unix::fs::symlink(format!("gen-{}", target.number), &tmp_link)?;
    std::fs::rename(&tmp_link, &current_link)?;

    // Run activation on the target toplevel.
    let activate_script = format!("{}/activate", target.toplevel);
    if Path::new(&activate_script).exists() {
        let status = std::process::Command::new(&activate_script)
            .status()
            .with_context(|| format!("running {activate_script}"))?;
        if !status.success() {
            printer.warning("Activation script returned non-zero exit code.");
        }
    }

    // Compare kernels.
    let old_kernel = current.kernel_path.as_deref().unwrap_or("");
    let new_kernel = target.kernel_path.as_deref().unwrap_or("");
    if !old_kernel.is_empty() && !new_kernel.is_empty() && old_kernel != new_kernel {
        update_boot_loader(new_kernel, &target.toplevel)?;
        printer.warning(&format!(
            "Kernel changed: {} -> {}. Reboot required.",
            short_path(old_kernel),
            short_path(new_kernel),
        ));
    }

    // Diff services.
    let diff = diff_services(&current.toplevel, &target.toplevel);
    run_service_diff(&diff, printer);

    printer.success(&format!(
        "Rolled back to system generation {} ({} {}).",
        target.number, target.package_name, target.version,
    ));

    Ok(())
}

/// Check whether a package's closure is contained within the current sysroot.
///
/// Returns `Some((sysroot_name, sysroot_version))` if the package is provided
/// by the sysroot, `None` otherwise.
pub fn check_sysroot_containment(
    pkg_refs: &[String],
    config: &ApmConfig,
) -> Option<(String, String)> {
    let profile_path = ProfileScope::System.profile_path();
    let state = match load_generation_state(&profile_path) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let current = state
        .generations
        .iter()
        .find(|g| g.number == state.current)?;

    // Load registries to get the sysroot package's references.
    let registries = match load_registries(config) {
        Ok(r) => r,
        Err(_) => return None,
    };

    for reg in registries.registries() {
        if let Some(meta) = reg.packages.get(&current.package_name) {
            if meta.sysroot {
                let sysroot_refs: HashSet<&str> =
                    meta.references.iter().map(|s| s.as_str()).collect();
                // Also add the sysroot's own hash.
                let sysroot_hash = store_path_hash(&meta.store_path);
                let mut full_refs = sysroot_refs;
                full_refs.insert(sysroot_hash);

                // Check if all of the package's references are in the sysroot.
                let all_contained = pkg_refs.iter().all(|r| full_refs.contains(r.as_str()));
                if all_contained {
                    return Some((current.package_name.clone(), current.version.clone()));
                }
            }
        }
    }

    None
}

/// Show sysroot-specific information for `apm show <pkg>`.
pub fn show_sysroot_info(meta: &PackageMeta, printer: &Printer) {
    if !meta.sysroot {
        return;
    }

    printer.kv("Sysroot", "yes");

    if let Some(ref prev) = meta.previous {
        printer.kv("Previous version", prev);
    }

    printer.kv("Closure packages", &format!("{}", meta.references.len()));

    if !meta.images.is_empty() {
        let formats: Vec<&str> = meta.images.iter().map(|i| i.format.as_str()).collect();
        printer.kv("Image formats", &formats.join(", "));
        for img in &meta.images {
            printer.kv(
                &format!("  {} image", img.format),
                &format!("{} ({})", img.store_path, format_size(img.nar_size)),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Image download
// ---------------------------------------------------------------------------

/// Download a pre-compiled image from a sysroot package.
async fn download_image(
    config: &ApmConfig,
    meta: &PackageMeta,
    format: &str,
    output: Option<&str>,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    let img = meta
        .images
        .iter()
        .find(|i| i.format == format)
        .ok_or_else(|| {
            let available: Vec<&str> = meta.images.iter().map(|i| i.format.as_str()).collect();
            anyhow::anyhow!(
                "image format '{}' not available for {} {}. Available: {}",
                format,
                meta.name,
                meta.version,
                if available.is_empty() {
                    "none".to_string()
                } else {
                    available.join(", ")
                },
            )
        })?;

    let output_path = output.unwrap_or_else(|| {
        // Default output name derived from package + format.
        Box::leak(
            format!("{}-{}.{}", meta.name, meta.version, format).into_boxed_str(),
        )
    });

    printer.kv("Image format", format);
    printer.kv("Store path", &img.store_path);
    printer.kv("Size", &format_size(img.nar_size));
    printer.kv("Output", output_path);

    if dry_run {
        printer.info("Dry run -- no download.");
        return Ok(());
    }

    // Use the existing download pipeline — the image store path is just another
    // store path in the cache.
    let mirror_url = resolve_image_mirror(config, meta);
    let request = DownloadRequest {
        store_path: img.store_path.clone(),
        nar_hash: img.nar_hash.clone(),
        download_hash: img.download_hash.clone(),
        download_size: img.download_size,
        mirror_url,
    };

    let nar_cache = config.nar_cache_path();

    let results = download_nars(
        &[request],
        &nar_cache,
        config.settings.parallel_downloads,
        printer,
    )
    .await?;

    if results.is_empty() {
        bail!("image download failed");
    }

    // Import NAR to get the store path, then copy image file out.
    let result = &results[0];
    verify_download_hash(&result.local_path, &result.download_hash)?;
    verify_nar_hash(&result.local_path, &result.nar_hash)?;
    import_nar(&result.local_path, &result.store_path).await?;

    // Copy the image file from the store path to the output.
    // The image store path typically contains a single large file.
    let store_dir = Path::new(&img.store_path);
    if store_dir.is_dir() {
        // Find the image file (usually the only regular file in the store path).
        let mut found = false;
        if let Ok(entries) = std::fs::read_dir(store_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    std::fs::copy(&path, output_path).with_context(|| {
                        format!("copying {} to {}", path.display(), output_path)
                    })?;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            bail!("no image file found in store path {}", img.store_path);
        }
    } else {
        // Direct file — copy it.
        std::fs::copy(store_dir, output_path)
            .with_context(|| format!("copying image to {output_path}"))?;
    }

    printer.success(&format!(
        "Image {} {} ({}) written to {}.",
        meta.name, meta.version, format, output_path,
    ));

    Ok(())
}

// ---------------------------------------------------------------------------
// Generation state management
// ---------------------------------------------------------------------------

/// Load system generation state from disk (public wrapper for cross-module use).
pub fn load_generation_state_pub(profile_path: &Path) -> Result<SystemGenerationState> {
    load_generation_state(profile_path)
}

/// Load system generation state from disk.
fn load_generation_state(profile_path: &Path) -> Result<SystemGenerationState> {
    let state_path = profile_path.join(SYSTEM_STATE_FILE);
    if !state_path.exists() {
        return Ok(SystemGenerationState {
            current: 0,
            next: 1,
            generations: Vec::new(),
        });
    }
    let content = std::fs::read_to_string(&state_path)
        .with_context(|| format!("reading {}", state_path.display()))?;
    let state: SystemGenerationState = serde_json::from_str(&content)
        .with_context(|| format!("parsing {}", state_path.display()))?;
    Ok(state)
}

/// Save system generation state to disk.
fn save_generation_state(profile_path: &Path, state: &SystemGenerationState) -> Result<()> {
    let state_path = profile_path.join(SYSTEM_STATE_FILE);
    let content = serde_json::to_string_pretty(state)?;
    std::fs::write(&state_path, content)
        .with_context(|| format!("writing {}", state_path.display()))?;
    Ok(())
}

/// Get the current sysroot's store path, if any.
fn current_sysroot_store_path() -> Result<Option<String>> {
    let profile_path = ProfileScope::System.profile_path();
    let state = load_generation_state(&profile_path)?;
    if state.current == 0 {
        return Ok(None);
    }
    Ok(state
        .generations
        .iter()
        .find(|g| g.number == state.current)
        .map(|g| g.toplevel.clone()))
}

// ---------------------------------------------------------------------------
// Service diffing
// ---------------------------------------------------------------------------

/// Represents the diff between two toplevels' systemd units.
struct ServiceDiff {
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
}

/// Compute the service diff between an old and new toplevel.
fn diff_services(old_toplevel: &str, new_toplevel: &str) -> ServiceDiff {
    let old_units = list_unit_files(old_toplevel);
    let new_units = list_unit_files(new_toplevel);

    let old_set: HashSet<&str> = old_units.iter().map(|(n, _)| n.as_str()).collect();
    let new_set: HashSet<&str> = new_units.iter().map(|(n, _)| n.as_str()).collect();

    let added: Vec<String> = new_set
        .difference(&old_set)
        .map(|s| s.to_string())
        .collect();
    let removed: Vec<String> = old_set
        .difference(&new_set)
        .map(|s| s.to_string())
        .collect();

    // Changed: same name, different content hash.
    let old_map: std::collections::HashMap<&str, &str> = old_units
        .iter()
        .map(|(n, h)| (n.as_str(), h.as_str()))
        .collect();
    let new_map: std::collections::HashMap<&str, &str> = new_units
        .iter()
        .map(|(n, h)| (n.as_str(), h.as_str()))
        .collect();

    let changed: Vec<String> = old_set
        .intersection(&new_set)
        .filter(|name| old_map.get(*name) != new_map.get(*name))
        .map(|s| s.to_string())
        .collect();

    ServiceDiff {
        added,
        removed,
        changed,
    }
}

/// List unit files under a toplevel's etc/systemd/system/ directory.
/// Returns (unit_name, content_hash) pairs.
fn list_unit_files(toplevel: &str) -> Vec<(String, String)> {
    let units_dir = PathBuf::from(toplevel).join("etc/systemd/system");
    let mut results = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&units_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                let content = std::fs::read(&path).unwrap_or_default();
                // Simple fingerprint: length + djb2 hash of content.
                let hash = format!("{}-{:x}", content.len(), djb2_hash(&content));
                results.push((name, hash));
            }
        }
    }

    results
}

/// Execute service diff operations via systemctl.
fn run_service_diff(diff: &ServiceDiff, printer: &Printer) {
    if diff.added.is_empty() && diff.removed.is_empty() && diff.changed.is_empty() {
        return;
    }

    // Daemon reload first.
    let _ = std::process::Command::new("systemctl")
        .arg("daemon-reload")
        .status();

    for unit in &diff.removed {
        printer.plain(&format!("  Stopping: {unit}"));
        let _ = std::process::Command::new("systemctl")
            .args(["stop", unit])
            .status();
    }

    for unit in &diff.changed {
        printer.plain(&format!("  Restarting: {unit}"));
        let _ = std::process::Command::new("systemctl")
            .args(["restart", unit])
            .status();
    }

    for unit in &diff.added {
        printer.plain(&format!("  Starting: {unit}"));
        let _ = std::process::Command::new("systemctl")
            .args(["start", unit])
            .status();
    }

    printer.plain(&format!(
        "Services: {} added, {} removed, {} changed.",
        diff.added.len(),
        diff.removed.len(),
        diff.changed.len(),
    ));
}

// ---------------------------------------------------------------------------
// Kernel / boot loader
// ---------------------------------------------------------------------------

/// Resolve the kernel path from a toplevel store path.
fn resolve_kernel_path(toplevel: &str) -> Option<String> {
    let kernel_link = PathBuf::from(toplevel).join("kernel");
    if kernel_link.exists() || kernel_link.symlink_metadata().is_ok() {
        match std::fs::read_link(&kernel_link) {
            Ok(target) => Some(target.to_string_lossy().to_string()),
            Err(_) => {
                // Not a symlink; maybe a regular file.
                Some(kernel_link.to_string_lossy().to_string())
            }
        }
    } else {
        None
    }
}

/// Update the boot loader entry with a new kernel path.
fn update_boot_loader(kernel_path: &str, toplevel: &str) -> Result<()> {
    let initrd_path = PathBuf::from(toplevel).join("initrd");
    let initrd = if initrd_path.exists() {
        match std::fs::read_link(&initrd_path) {
            Ok(target) => format!("{}/initrd", target.display()),
            Err(_) => format!("{toplevel}/initrd/initrd"),
        }
    } else {
        String::new()
    };

    let entry = format!(
        "title   AOS\n\
         linux   {kernel_path}/bzImage\n\
         {}\
         options root=/dev/sda2 console=ttyS0\n",
        if initrd.is_empty() {
            String::new()
        } else {
            format!("initrd  {initrd}\n")
        },
    );

    // Only write if the boot loader directory exists.
    let parent = Path::new(BOOT_LOADER_ENTRY).parent().unwrap();
    if parent.exists() {
        std::fs::write(BOOT_LOADER_ENTRY, &entry)
            .with_context(|| format!("updating {BOOT_LOADER_ENTRY}"))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_registries(config: &ApmConfig) -> Result<RegistrySet> {
    let reg_configs = config.enabled_registries();
    RegistrySet::load(&config.cache_path(), &reg_configs, "x86_64-linux")
}

fn resolve_image_mirror(config: &ApmConfig, _meta: &PackageMeta) -> String {
    // Use the first configured registry's mirror URL.
    if let Some((cfg, _)) = config.registries.first() {
        return resolve_mirror(cfg);
    }
    "https://cache.aos.dev/nar".to_string()
}

fn build_download_requests(
    closures: &[crate::resolve::ResolvedClosure],
    to_download: &[&PackageMeta],
    config: &ApmConfig,
) -> Result<Vec<DownloadRequest>> {
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
                format!("https://registry.aos.dev/{}/nar", c.registry_name)
            };
            (c.registry_name.clone(), mirror_url)
        })
        .collect();

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
        Err(aos_core::error::AosError::UserCancelled.into())
    }
}

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

fn short_path(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Simple DJB2 hash for content fingerprinting (not cryptographic).
fn djb2_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 5381;
    for &byte in data {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}

fn chrono_iso8601_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let secs_per_day: i64 = 86400;
    let days = secs / secs_per_day;
    let day_secs = (secs % secs_per_day) as u32;

    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    let (year, month, day) = days_to_ymd(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z"
    )
}

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

    #[test]
    fn generation_state_round_trip() {
        let state = SystemGenerationState {
            current: 2,
            next: 3,
            generations: vec![
                SystemGeneration {
                    number: 1,
                    toplevel: "/nix/store/abc123-server-2026.03".into(),
                    version: "2026.03".into(),
                    package_name: "server".into(),
                    registry: "aos-core".into(),
                    created_at: "2026-03-01T00:00:00Z".into(),
                    kernel_path: Some("/nix/store/kern1-linux-6.12".into()),
                },
                SystemGeneration {
                    number: 2,
                    toplevel: "/nix/store/def456-server-2026.04".into(),
                    version: "2026.04".into(),
                    package_name: "server".into(),
                    registry: "aos-core".into(),
                    created_at: "2026-04-01T00:00:00Z".into(),
                    kernel_path: Some("/nix/store/kern2-linux-6.13".into()),
                },
            ],
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let parsed: SystemGenerationState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.current, 2);
        assert_eq!(parsed.next, 3);
        assert_eq!(parsed.generations.len(), 2);
        assert_eq!(parsed.generations[1].version, "2026.04");
    }

    #[test]
    fn load_empty_state() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = load_generation_state(tmp.path()).unwrap();
        assert_eq!(state.current, 0);
        assert_eq!(state.next, 1);
        assert!(state.generations.is_empty());
    }

    #[test]
    fn save_and_load_state() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = SystemGenerationState {
            current: 1,
            next: 2,
            generations: vec![SystemGeneration {
                number: 1,
                toplevel: "/nix/store/abc-server".into(),
                version: "1.0".into(),
                package_name: "server".into(),
                registry: "core".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                kernel_path: None,
            }],
        };
        save_generation_state(tmp.path(), &state).unwrap();
        let loaded = load_generation_state(tmp.path()).unwrap();
        assert_eq!(loaded.current, 1);
        assert_eq!(loaded.generations.len(), 1);
    }

    #[test]
    fn diff_services_empty() {
        let diff = diff_services("/nonexistent/old", "/nonexistent/new");
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn format_size_values() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(2048), "2.0 KiB");
        assert_eq!(format_size(3_300_000), "3.1 MiB");
        assert_eq!(format_size(2_147_483_648), "2.0 GiB");
    }

    #[test]
    fn chrono_iso8601_format() {
        let result = chrono_iso8601_now();
        assert!(result.ends_with('Z'));
        assert_eq!(result.len(), 20);
        assert!(result.starts_with("20"));
    }

    #[test]
    fn short_path_extracts_basename() {
        assert_eq!(short_path("/nix/store/abc-linux-6.12"), "abc-linux-6.12");
        assert_eq!(short_path("just-a-name"), "just-a-name");
    }
}
