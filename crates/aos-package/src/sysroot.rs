//! System sysroot management (`apm install --system`, `apm upgrade --system`,
//! `apm rollback --system`).
//!
//! A sysroot package is a regular package with `sysroot = true`. Installing it
//! as a system sysroot creates a numbered generation under
//! `/var/lib/profiles/system/`, runs activation scripts, and compares kernels
//! to determine if a reboot is needed.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use aos_core::output::Printer;
use aos_systemd::{FailedUnitsReport, JobResult, SystemdClient};

use crate::config::ApmConfig;
use crate::unit_diff::{self, UnitDiff};
use crate::download::{
    default_engine, download_nars, fetch_narinfos, resolve_mirror, DownloadRequest,
    ResolvedDownload,
};
use crate::registry::{store_path_hash, RegistrySet};
use crate::resolve::{collect_unique_metas, resolve_multiple};
use crate::store::{filter_missing, import_nar};
use crate::types::{PackageMeta, ProfileScope, SystemGeneration, SystemGenerationState};
use crate::verify::{verify_download_hash, verify_nar_hash};

// ---------------------------------------------------------------------------
// Kernel upgrade mode
// ---------------------------------------------------------------------------

/// How to handle kernel changes during a system update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KernelUpgradeMode {
    /// Default: update bootloader, advise reboot if kernel changed.
    #[default]
    Advisory,
    /// Use kexec to hot-load new kernel (~2-5s disruption).
    Kexec,
    /// Full reboot after activation.
    Reboot,
    /// Skip kernel upgrade entirely, userspace only.
    Live,
}

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
    kernel_mode: KernelUpgradeMode,
    drain: bool,
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

    // Step 3: Plan + fetch narinfo for missing paths so the summary can
    // show real compressed sizes and download_nars has the cache's URLs.
    printer.step(3, 8, "Planning...");
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
    let download_size: u64 = resolved
        .iter()
        .map(|r| r.narinfo.file_size.unwrap_or(0))
        .sum();
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
    if !resolved.is_empty() {
        printer.step(4, 8, "Downloading...");
        let nar_cache = config.nar_cache_path();

        let results = download_nars(
            &resolved,
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

    // Run the toplevel's activate script with the generation number. It
    // rebuilds this gen's /etc overlay, reconciles running daemons, and
    // swaps /etc in atomically (daemon reconciliation now happens inside
    // the activate script, not here). Its exit code is the authority on
    // what happened (see modules/base/activate.sh.in):
    //   0      switch succeeded, every unit healthy
    //   5      switch succeeded; only stale-mount cleanup failed (cosmetic)
    //   6      switch succeeded but some units failed — the upgrade is
    //          applied and the gen stays live, but apm exits non-zero
    //   1/2/3  failed before the swap; the previous gen is still live
    //   4      swap incomplete; /etc indeterminate — operator must intervene
    let mut activate_degraded = false;
    let activate_script = format!("{}/activate", toplevel_meta.store_path);
    if Path::new(&activate_script).exists() {
        let status = std::process::Command::new(&activate_script)
            .arg(gen_num.to_string())
            .status()
            .with_context(|| format!("running {activate_script}"))?;
        match status.code() {
            Some(0) => {}
            Some(5) => printer.warning(
                "Activation succeeded, but cleanup of the previous \
                 generation's mounts failed (stale /run/etc mounts).",
            ),
            Some(6) => activate_degraded = true,
            Some(4) => anyhow::bail!(
                "FATAL: the /etc swap is incomplete; the running system's \
                 /etc may be in an indeterminate state. Manual intervention \
                 is required (gen-{gen_num})."
            ),
            other => anyhow::bail!(
                "Activation failed before the /etc swap (exit {other:?}); the \
                 previous generation is still live."
            ),
        }
    }

    // Handle kernel upgrade according to the chosen mode.
    let old_kernel_path = old_gen.as_ref().and_then(|g| g.kernel_path.clone());
    handle_kernel_upgrade(
        &old_kernel_path,
        &kernel_path,
        &toplevel_meta.store_path,
        kernel_mode,
        drain,
        printer,
    )
    .await?;

    let reboot_hint = match kernel_mode {
        KernelUpgradeMode::Advisory => {
            let kernel_changed = match (&old_kernel_path, &kernel_path) {
                (Some(old), Some(new)) if !old.is_empty() && !new.is_empty() => old != new,
                _ => false,
            };
            if kernel_changed {
                " (reboot required)"
            } else {
                ""
            }
        }
        _ => "",
    };

    if activate_degraded {
        anyhow::bail!(
            "System generation {gen_num} is live, but one or more units failed \
             to (re)start (see the reconcile report above). The upgrade was \
             applied; the failing units need attention."
        );
    }

    printer.success(&format!(
        "System generation {gen_num} active: {} {}{}",
        pkg_name,
        toplevel_meta.version,
        reboot_hint,
    ));

    Ok(())
}

/// `apm upgrade --system` — check for newer sysroot version and apply.
pub async fn upgrade_system(
    config: &ApmConfig,
    dry_run: bool,
    kernel_mode: KernelUpgradeMode,
    drain: bool,
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
        kernel_mode,
        drain,
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
    kernel_mode: KernelUpgradeMode,
    drain: bool,
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

    // Run the target generation's activate script with its gen number.
    // It rebuilds the target gen's /etc overlay, reconciles daemons, and
    // swaps /etc in atomically. Exit-code contract matches install (see
    // modules/base/activate.sh.in).
    let mut activate_degraded = false;
    let activate_script = format!("{}/activate", target.toplevel);
    if Path::new(&activate_script).exists() {
        let status = std::process::Command::new(&activate_script)
            .arg(target.number.to_string())
            .status()
            .with_context(|| format!("running {activate_script}"))?;
        match status.code() {
            Some(0) => {}
            Some(5) => printer.warning(
                "Rollback activation succeeded, but cleanup of the previous \
                 generation's mounts failed (stale /run/etc mounts).",
            ),
            Some(6) => activate_degraded = true,
            Some(4) => anyhow::bail!(
                "FATAL: the /etc swap is incomplete; the running system's \
                 /etc may be in an indeterminate state. Manual intervention \
                 is required (gen-{})." ,
                target.number
            ),
            other => anyhow::bail!(
                "Rollback activation failed before the /etc swap (exit \
                 {other:?}); the previous generation is still live."
            ),
        }
    }

    // Handle kernel upgrade according to the chosen mode.
    handle_kernel_upgrade(
        &current.kernel_path,
        &target.kernel_path,
        &target.toplevel,
        kernel_mode,
        drain,
        printer,
    )
    .await?;

    if activate_degraded {
        anyhow::bail!(
            "Rolled back to system generation {} ({} {}), which is now live, \
             but one or more units failed to (re)start (see the reconcile \
             report above). The rollback was applied; the failing units need \
             attention.",
            target.number,
            target.package_name,
            target.version,
        );
    }

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
        mirror_url,
    };

    let engine = std::sync::Arc::new(default_engine());
    let resolved = fetch_narinfos(
        std::sync::Arc::clone(&engine),
        &[request],
        config.settings.parallel_downloads,
        printer,
    )
    .await?;

    let nar_cache = config.nar_cache_path();

    let results = download_nars(
        &resolved,
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
    import_nar(
        &result.local_path,
        &result.store_path,
        &result.references,
        result.deriver.as_deref(),
    )
    .await?;

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
// Daemon reconciliation reporting helpers
//
// The old toplevel-vs-toplevel `diff_services` path was removed when daemon
// reconciliation moved into the activate script's `apm activate-reconcile`
// slot (see `activate_reconcile`, which diffs the live `/etc` against the
// candidate `/etc` via `crate::unit_diff`). These two helpers — per-job
// warning and the failed-units report formatter — are still used by that
// reconciler and by the kernel-upgrade path.
// ---------------------------------------------------------------------------

/// Warn (but do not fail) when a unit lifecycle job ended in something other
/// than `done`. The hard failure is the post-activation [`failed_units`] scan
/// in [`activate_reconcile`] — a job can report a transient non-`done` result
/// yet the unit still settle active, so the authoritative gate is the final
/// state.
fn warn_if_job_not_done(printer: &Printer, verb: &str, unit: &str, result: &JobResult) {
    if !result.is_done() {
        printer.warning(&format!(
            "  {verb} {unit}: systemd job result '{}'",
            result.label(),
        ));
    }
}

/// Render a [`FailedUnitsReport`] for human display: a one-line summary per
/// failed unit (state / sub-state / exit status) followed by its captured
/// `systemctl status` dump, indented.
fn format_failed_units(report: &FailedUnitsReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} service(s) failed during activation:",
        report.failed.len(),
    );
    for u in &report.failed {
        let status = match u.exec_main_status {
            Some(code) => code.to_string(),
            None => "n/a".to_string(),
        };
        let _ = writeln!(
            out,
            "  - {} (active={}, sub={}, ExecMainStatus={})",
            u.name, u.active_state, u.sub_state, status,
        );
        for line in u.status_dump.lines() {
            let _ = writeln!(out, "      {line}");
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Live daemon reconciliation (`apm activate-reconcile`)
// ---------------------------------------------------------------------------

/// Exit codes for `apm activate-reconcile` (spec §6.10). The activate script
/// maps these into its own contract: 0/1 → proceed to the overlay swap, 2 →
/// abort (no swap). 1 means the switch is valid but some units failed, so apm
/// still exits non-zero (via the activate script's `EX_DEGRADED`).
const RECONCILE_OK: i32 = 0;
const RECONCILE_FAILED_UNITS: i32 = 1;
const RECONCILE_CATASTROPHIC: i32 = 2;

/// Where the reconciler keeps its lock and resume lists. On tmpfs (`/run`), so
/// boot-scoped; nothing else on the boot path creates it.
const APM_RUN_DIR: &str = "/run/apm";

/// `apm activate-reconcile` — reconcile the running systemd against a candidate
/// `/etc` overlay built by the activate script, applying the minimal set of
/// stop / reload / restart / start actions over the D-Bus [`SystemdClient`].
///
/// Returns the process exit code and never bails: every error collapses to the
/// catastrophic code (2) so the activate script can dispatch deterministically
/// on the result (the `aos` `main.rs` would otherwise flatten any `Err` to 1).
/// The caller `std::process::exit`s this directly.
///
/// `new_toplevel` and `old_toplevel_symlink` are part of the stable CLI contract
/// but are deliberately NOT used to compute the diff: the diff is purely
/// filesystem-based (live `/etc` vs candidate `/etc`), so it does not depend on
/// the profile pointer — which `install_system` has already swung to the new
/// generation by the time this runs.
pub async fn activate_reconcile(
    generation: u32,
    candidate_etc: &Path,
    new_toplevel: &Path,
    old_toplevel_symlink: &Path,
    dry_run: bool,
    printer: &Printer,
) -> i32 {
    match reconcile_inner(
        generation,
        candidate_etc,
        new_toplevel,
        old_toplevel_symlink,
        dry_run,
        printer,
    )
    .await
    {
        Ok(code) => code,
        Err(e) => {
            printer.error(&format!("activate-reconcile: {e:#}"));
            RECONCILE_CATASTROPHIC
        }
    }
}

async fn reconcile_inner(
    generation: u32,
    candidate_etc: &Path,
    new_toplevel: &Path,
    old_toplevel_symlink: &Path,
    dry_run: bool,
    printer: &Printer,
) -> Result<i32> {
    // Contract args, intentionally unused by the filesystem diff (see the
    // doc comment on `activate_reconcile`).
    let _ = (new_toplevel, old_toplevel_symlink);

    // The candidate systemd tree must exist and be readable — otherwise the
    // diff would see "everything removed" and stop every running unit. Treat a
    // missing/unreadable candidate as catastrophic.
    let candidate_units = candidate_etc.join("systemd/system");
    if !candidate_units.is_dir() {
        bail!(
            "candidate /etc has no readable systemd/system dir: {}",
            candidate_units.display()
        );
    }

    // Compute the live-vs-candidate diff first. `compute_diff` takes the /etc
    // ROOTS (it appends `systemd/system` and rebases `X-Reload-Triggers` per
    // side). This is pure filesystem work — no lock, no systemd — so a
    // standalone `--dry-run` needs neither `/run/apm` nor the system bus.
    let mut diff = unit_diff::compute_diff(Path::new("/etc"), candidate_etc);
    for w in &diff.warnings {
        printer.warning(w);
    }

    if dry_run {
        print_diff(&diff, printer);
        return Ok(RECONCILE_OK);
    }

    let run_dir = Path::new(APM_RUN_DIR);
    ensure_run_dir(run_dir)?;

    // Exclusive, non-blocking lock for the whole reconcile. Bound to `_lock`
    // (RAII) so it outlives every `.await` below; drop = unlock.
    let _lock = match FlockGuard::acquire(&run_dir.join("system-switch.lock"))? {
        Some(g) => g,
        None => {
            printer
                .error("activate-reconcile: another system switch holds the lock; aborting");
            return Ok(RECONCILE_CATASTROPHIC);
        }
    };

    printer.info(&format!("Reconciling daemons for generation {generation}…"));

    // Fold install-only units (unchanged file, new install wiring) into the
    // start set, then merge any resume lists left by an interrupted prior run.
    let install_only = std::mem::take(&mut diff.install_only);
    for u in install_only {
        if !diff.to_start.contains(&u) {
            diff.to_start.push(u);
        }
    }
    merge_resume_lists(&mut diff, run_dir);

    // Persist the work lists so an interrupted run can resume.
    persist_lists(run_dir, &diff)?;

    let client = SystemdClient::connect()
        .await
        .context("connecting to systemd over D-Bus")?;

    // Always daemon-reload first so systemd ingests the new unit files.
    client.daemon_reload().await.context("daemon-reload")?;

    // Apply in order: stop → reload → restart → start. The diff engine has
    // already ordered sockets first within to_restart / to_start. Each list
    // file is deleted as its phase finishes, so a resumed run skips it.
    for unit in &diff.to_stop {
        printer.plain(&format!("  stopping   {unit}"));
        let outcome = client
            .stop_unit(unit)
            .await
            .with_context(|| format!("stopping {unit}"))?;
        warn_if_job_not_done(printer, "stop", unit, &outcome.result);
    }

    for unit in &diff.to_reload {
        printer.plain(&format!("  reloading  {unit}"));
        let outcome = client
            .reload_unit(unit)
            .await
            .with_context(|| format!("reloading {unit}"))?;
        warn_if_job_not_done(printer, "reload", unit, &outcome.result);
    }
    remove_list(run_dir, "reload-list");

    for unit in &diff.to_restart {
        printer.plain(&format!("  restarting {unit}"));
        let outcome = client
            .restart_unit(unit)
            .await
            .with_context(|| format!("restarting {unit}"))?;
        warn_if_job_not_done(printer, "restart", unit, &outcome.result);
    }
    remove_list(run_dir, "restart-list");

    for unit in &diff.to_start {
        printer.plain(&format!("  starting   {unit}"));
        let outcome = client
            .start_unit(unit)
            .await
            .with_context(|| format!("starting {unit}"))?;
        warn_if_job_not_done(printer, "start", unit, &outcome.result);
    }
    remove_list(run_dir, "start-list");

    // Clear stale failed state from before the switch, then drain late jobs.
    client.reset_failed().await.context("reset-failed")?;
    let late = client.settle().await.context("settling job events")?;
    if late > 0 {
        printer.info(&format!("settled {late} late job event(s)"));
    }

    // Authoritative health gate: a (re)started unit can knock over a dependent
    // one, so scan all units, not just the ones we touched.
    let report = client
        .failed_units()
        .await
        .context("scanning for failed units")?;
    delete_lists(run_dir);

    if !report.is_empty() {
        printer.error(&format_failed_units(&report));
        // The switch is still valid (matches switch-to-configuration): return 1
        // so apm surfaces a non-zero exit without rolling back the swap.
        return Ok(RECONCILE_FAILED_UNITS);
    }

    printer.success(&format!(
        "Reconcile complete: {} stopped, {} reloaded, {} restarted, {} started.",
        diff.to_stop.len(),
        diff.to_reload.len(),
        diff.to_restart.len(),
        diff.to_start.len(),
    ));
    Ok(RECONCILE_OK)
}

/// Create `/run/apm` (mode 0755) if absent.
fn ensure_run_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    // Best-effort: the umask may have masked the group/other read+exec bits.
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    Ok(())
}

/// RAII exclusive `flock` on a lock file. Released on drop (and on process exit
/// via fd close). Must be bound for the whole reconcile so it outlives every
/// `.await`.
struct FlockGuard {
    _file: std::fs::File,
}

impl FlockGuard {
    /// Acquire a non-blocking exclusive lock. `Ok(None)` on contention
    /// (`EWOULDBLOCK`); `Err` on any other failure.
    fn acquire(path: &Path) -> Result<Option<FlockGuard>> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("opening lock file {}", path.display()))?;
        // SAFETY: `file` owns the fd for the duration of this call and the
        // returned guard.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Some(FlockGuard { _file: file }));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Ok(None)
        } else {
            Err(anyhow!("flock {}: {err}", path.display()))
        }
    }
}

impl Drop for FlockGuard {
    fn drop(&mut self) {
        // SAFETY: the fd is still open (we own `_file`); unlock is best-effort.
        let _ = unsafe { libc::flock(self._file.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn list_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
}

/// Read a `/run/apm/*-list` file into a deduped-by-position list of unit names.
/// A missing/unreadable file is an empty list (the common, non-resume case).
fn read_list_file(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|s| {
            s.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn write_list_file(path: &Path, units: &[String]) -> Result<()> {
    let mut body = units.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))
}

/// Persist the reload/restart/start work lists so an interrupted run resumes.
/// (Stops are not persisted: they are idempotent and re-derived from the diff.)
fn persist_lists(dir: &Path, diff: &UnitDiff) -> Result<()> {
    write_list_file(&list_path(dir, "reload-list"), &diff.to_reload)?;
    write_list_file(&list_path(dir, "restart-list"), &diff.to_restart)?;
    write_list_file(&list_path(dir, "start-list"), &diff.to_start)?;
    Ok(())
}

/// Merge any leftover resume lists into the diff's corresponding sets,
/// preserving order and de-duplicating.
fn merge_resume_lists(diff: &mut UnitDiff, dir: &Path) {
    let merge = |target: &mut Vec<String>, extra: Vec<String>| {
        for u in extra {
            if !target.contains(&u) {
                target.push(u);
            }
        }
    };
    merge(&mut diff.to_reload, read_list_file(&list_path(dir, "reload-list")));
    merge(
        &mut diff.to_restart,
        read_list_file(&list_path(dir, "restart-list")),
    );
    merge(&mut diff.to_start, read_list_file(&list_path(dir, "start-list")));
}

fn remove_list(dir: &Path, name: &str) {
    let _ = std::fs::remove_file(list_path(dir, name));
}

fn delete_lists(dir: &Path) {
    for name in ["reload-list", "restart-list", "start-list"] {
        remove_list(dir, name);
    }
}

/// Print the reconciliation plan without applying it (`--dry-run`).
fn print_diff(diff: &UnitDiff, printer: &Printer) {
    let show = |label: &str, units: &[String]| {
        let body = if units.is_empty() {
            "(none)".to_string()
        } else {
            units.join(" ")
        };
        printer.plain(&format!("  {label:<9}{body}"));
    };
    show("stop:", &diff.to_stop);
    show("reload:", &diff.to_reload);
    show("restart:", &diff.to_restart);
    show("start:", &diff.to_start);
    if !diff.install_only.is_empty() {
        show("install:", &diff.install_only);
    }
    if !diff.blanket_targets.is_empty() {
        printer.plain(&format!(
            "  (reload-trigger driven: {})",
            diff.blanket_targets.join(" ")
        ));
    }
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
    let parent = Path::new(BOOT_LOADER_ENTRY)
        .parent()
        .context("BOOT_LOADER_ENTRY has no parent directory")?;
    if parent.exists() {
        std::fs::write(BOOT_LOADER_ENTRY, &entry)
            .with_context(|| format!("updating {BOOT_LOADER_ENTRY}"))?;
    }

    Ok(())
}

/// Extract a human-readable kernel version from a store path.
///
/// Expects paths like `/nix/store/abc123-linux-6.12.1` and returns `6.12.1`.
/// Falls back to the basename if no version pattern is found.
fn extract_kernel_version(path: &Option<String>) -> String {
    match path {
        Some(p) => {
            let base = p.rsplit('/').next().unwrap_or(p);
            // Strip the Nix hash prefix (32 hash chars + '-').
            // A valid store basename needs at least 33 chars (32 hash + dash).
            let name = if base.len() >= 33 && base.as_bytes()[32] == b'-' {
                &base[33..]
            } else {
                base
            };
            // Strip common prefixes like "linux-".
            let version = name.strip_prefix("linux-").unwrap_or(name);
            version.to_string()
        }
        None => "unknown".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Kernel upgrade orchestration
// ---------------------------------------------------------------------------

/// Handle kernel upgrade after activation, according to the chosen mode.
///
/// This is the central dispatch for all kernel upgrade strategies. It is called
/// after the new generation has been activated (services diffed and restarted).
async fn handle_kernel_upgrade(
    old_kernel: &Option<String>,
    new_kernel: &Option<String>,
    new_toplevel: &str,
    mode: KernelUpgradeMode,
    drain: bool,
    printer: &Printer,
) -> Result<()> {
    let kernel_changed = match (old_kernel, new_kernel) {
        (Some(old), Some(new)) if !old.is_empty() && !new.is_empty() => old != new,
        _ => false,
    };

    // Always update boot loader if kernel changed.
    if kernel_changed {
        let new_k = new_kernel.as_deref().unwrap_or("");
        update_boot_loader(new_k, new_toplevel)?;
    }

    match mode {
        KernelUpgradeMode::Advisory => {
            if kernel_changed {
                let old_ver = extract_kernel_version(old_kernel);
                let new_ver = extract_kernel_version(new_kernel);
                printer.warning(&format!(
                    "Kernel updated: {} -> {}",
                    old_ver, new_ver,
                ));
                printer.plain("  Boot loader updated. Reboot required for kernel changes.");
                printer.plain("  Use: apm upgrade --system --kexec  (fast, ~3s)");
                printer.plain("  Or:  apm upgrade --system --reboot (full reboot)");
            }
        }
        KernelUpgradeMode::Kexec => {
            if kernel_changed {
                if drain {
                    drain_workloads(new_toplevel, printer).await?;
                }
                let new_ver = extract_kernel_version(new_kernel);
                printer.plain(&format!("Loading new kernel {} via kexec...", new_ver));
                kexec_kernel(new_toplevel).await?;
                // kexec -e does not return on success.
            } else {
                printer.info("Kernel unchanged, kexec not needed.");
            }
        }
        KernelUpgradeMode::Reboot => {
            if drain {
                drain_workloads(new_toplevel, printer).await?;
            }
            if kernel_changed {
                let new_ver = extract_kernel_version(new_kernel);
                printer.plain(&format!("Rebooting into new kernel {}...", new_ver));
            } else {
                printer.plain("Rebooting (kernel unchanged)...");
            }
            // Queue the reboot over D-Bus (`Manager.Reboot`) rather than
            // shelling out to `systemctl reboot`. Constructed lazily, only on
            // this arm. Returns once systemd has queued the transition; this
            // process then exits or is torn down as systemd stops the system.
            let client = SystemdClient::connect().await?;
            client.reboot().await?;
        }
        KernelUpgradeMode::Live => {
            if kernel_changed {
                let new_ver = extract_kernel_version(new_kernel);
                printer.plain(&format!(
                    "Kernel {} staged for next reboot (current session unchanged).",
                    new_ver,
                ));
            }
        }
    }

    Ok(())
}

/// Load a new kernel via kexec and execute it.
///
/// The kernel and initrd are read from `<toplevel>/kernel` and
/// `<toplevel>/initrd`. The current kernel command line is reused.
async fn kexec_kernel(new_toplevel: &str) -> Result<()> {
    let kernel = format!("{}/kernel", new_toplevel);
    let initrd = format!("{}/initrd", new_toplevel);

    // Verify kexec is available.
    check_command_exists("kexec")?;

    // Load new kernel.
    let mut load_args = vec![
        "-l".to_string(),
        kernel,
        "--reuse-cmdline".to_string(),
    ];
    if Path::new(&initrd).exists() {
        load_args.push(format!("--initrd={}", initrd));
    }
    let load_refs: Vec<&str> = load_args.iter().map(|s| s.as_str()).collect();
    run_command("kexec", &load_refs)?;

    // Sync filesystems before switching.
    run_command("sync", &[])?;

    // Execute the loaded kernel. This does not return on success.
    run_command("kexec", &["-e"])?;

    Ok(())
}

/// Drain workloads before a disruptive kernel switch.
///
/// Checks for a `drain` script in the toplevel. If none exists, attempts to
/// isolate the systemd `drain.target` (if present). If neither mechanism is
/// available, this is a no-op.
async fn drain_workloads(toplevel: &str, printer: &Printer) -> Result<()> {
    let drain_script = format!("{}/drain", toplevel);
    if Path::new(&drain_script).exists() {
        printer.plain("Draining workloads...");
        run_command(&drain_script, &[])?;
        printer.plain("Drain complete.");
        return Ok(());
    }

    // Fall back to the systemd `drain.target` if it exists. The client is
    // constructed lazily here, only on the no-drain-script path (the common
    // case ships a drain script and returns above). `start_unit` awaits the
    // job, giving us the old `systemctl start --wait` semantics for free.
    let client = SystemdClient::connect().await?;
    if client.is_active("drain.target").await? {
        printer.plain("Draining workloads via drain.target...");
        let isolate = client.isolate_unit("drain.target").await?;
        if !isolate.result.is_done() {
            bail!(
                "isolating drain.target failed: systemd job result '{}'",
                isolate.result.label(),
            );
        }
        let complete = client.start_unit("drain-complete.target").await?;
        if !complete.result.is_done() {
            bail!(
                "drain-complete.target failed: systemd job result '{}'",
                complete.result.label(),
            );
        }
        printer.plain("Drain complete.");
    }

    Ok(())
}

/// Check that an external command exists on PATH.
fn check_command_exists(name: &str) -> Result<()> {
    let status = std::process::Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => bail!("required command '{}' not found in PATH", name),
    }
}

/// Run an external command, returning an error if it fails.
fn run_command(cmd: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("running {} {}", cmd, args.join(" ")))?;
    if !status.success() {
        bail!(
            "command '{}' exited with status {}",
            cmd,
            status.code().unwrap_or(-1),
        );
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
    "https://cache.aos.dev".to_string()
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
                format!("https://registry.aos.dev/{}", c.registry_name)
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

/// Simple DJB2 hash for content fingerprinting (not cryptographic).
///
/// `pub(crate)` so the live-vs-candidate diff engine in [`crate::unit_diff`]
/// can share the same deterministic, dependency-free hash. The unit
/// fingerprint is only ever compared within a single `activate-reconcile`
/// process, so a non-cryptographic hash is sufficient and lets us avoid
/// pulling in `twox-hash` (which would churn the vendored Cargo deps hash).
pub(crate) fn djb2_hash(data: &[u8]) -> u64 {
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
    fn extract_kernel_version_from_store_path() {
        // Nix hash is 32 chars, so basename is "01234567890123456789012345678901-linux-6.12.1"
        // After stripping 33-char prefix (hash + '-'), we get "linux-6.12.1", then strip "linux-".
        let path =
            Some("/nix/store/01234567890123456789012345678901-linux-6.12.1".to_string());
        assert_eq!(extract_kernel_version(&path), "6.12.1");
    }

    #[test]
    fn extract_kernel_version_short_path() {
        let path = Some("linux-6.11.0".to_string());
        assert_eq!(extract_kernel_version(&path), "6.11.0");
    }

    #[test]
    fn extract_kernel_version_none() {
        assert_eq!(extract_kernel_version(&None), "unknown");
    }

    #[test]
    fn kernel_upgrade_mode_default() {
        let mode = KernelUpgradeMode::default();
        assert_eq!(mode, KernelUpgradeMode::Advisory);
    }

    #[test]
    fn format_failed_units_lists_each_unit() {
        use aos_systemd::FailedUnit;

        let report = FailedUnitsReport {
            failed: vec![
                FailedUnit {
                    name: "broken.service".into(),
                    active_state: "failed".into(),
                    sub_state: "failed".into(),
                    exec_main_status: Some(1),
                    status_dump: "● broken.service - Broken\n   Active: failed".into(),
                },
                FailedUnit {
                    name: "stuck.service".into(),
                    active_state: "activating".into(),
                    sub_state: "auto-restart".into(),
                    exec_main_status: None,
                    status_dump: String::new(),
                },
            ],
        };

        let out = format_failed_units(&report);
        assert!(out.contains("2 service(s) failed during activation"), "{out}");
        assert!(out.contains("broken.service"), "{out}");
        assert!(out.contains("ExecMainStatus=1"), "{out}");
        // The captured status dump is included, indented.
        assert!(out.contains("      ● broken.service - Broken"), "{out}");
        // A unit with no ExecMainStatus renders as n/a.
        assert!(out.contains("stuck.service"), "{out}");
        assert!(out.contains("ExecMainStatus=n/a"), "{out}");
    }

    // --- activate-reconcile helpers (§8.5) -----------------------------

    #[test]
    fn flock_guard_is_exclusive_and_releases() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lock = tmp.path().join("system-switch.lock");

        let g1 = FlockGuard::acquire(&lock).unwrap();
        assert!(g1.is_some(), "first acquire should succeed");

        // A second acquirer (a distinct open file description) contends.
        let g2 = FlockGuard::acquire(&lock).unwrap();
        assert!(g2.is_none(), "second acquire should report contention");

        drop(g1);
        let g3 = FlockGuard::acquire(&lock).unwrap();
        assert!(g3.is_some(), "acquire after release should succeed");
    }

    #[test]
    fn resume_lists_round_trip_and_delete() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        let diff = UnitDiff {
            to_reload: vec!["nftables.service".to_string()],
            to_restart: vec![
                "systemd-sysctl.service".to_string(),
                "foo.service".to_string(),
            ],
            to_start: vec!["new.service".to_string()],
            ..Default::default()
        };
        persist_lists(dir, &diff).unwrap();

        assert_eq!(
            read_list_file(&dir.join("reload-list")),
            vec!["nftables.service".to_string()]
        );
        assert_eq!(
            read_list_file(&dir.join("restart-list")),
            vec![
                "systemd-sysctl.service".to_string(),
                "foo.service".to_string()
            ]
        );
        assert_eq!(
            read_list_file(&dir.join("start-list")),
            vec!["new.service".to_string()]
        );

        delete_lists(dir);
        assert!(read_list_file(&dir.join("reload-list")).is_empty());
        assert!(read_list_file(&dir.join("restart-list")).is_empty());
        assert!(read_list_file(&dir.join("start-list")).is_empty());
    }

    #[test]
    fn merge_resume_lists_merges_and_dedups() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        write_list_file(
            &dir.join("restart-list"),
            &["a.service".to_string(), "b.service".to_string()],
        )
        .unwrap();
        write_list_file(&dir.join("start-list"), &["c.service".to_string()]).unwrap();

        let mut diff = UnitDiff {
            // a.service is already in the fresh diff — must not be duplicated.
            to_restart: vec!["a.service".to_string()],
            ..Default::default()
        };
        merge_resume_lists(&mut diff, dir);

        assert_eq!(
            diff.to_restart,
            vec!["a.service".to_string(), "b.service".to_string()]
        );
        assert_eq!(diff.to_start, vec!["c.service".to_string()]);
    }

    #[test]
    fn print_diff_does_not_panic() {
        let printer = Printer::new(0, true, false);
        let diff = UnitDiff {
            to_restart: vec!["x.service".to_string()],
            blanket_targets: vec!["x.service".to_string()],
            ..Default::default()
        };
        print_diff(&diff, &printer);
    }
}
