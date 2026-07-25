//! System sysroot management (`apm install --system`, `apm upgrade --system`,
//! `apm rollback --system`).
//!
//! A sysroot package is a regular package with `sysroot = true` whose store
//! path is a system toplevel. Installing it as the system sysroot creates a
//! numbered **generation** under `/var/lib/profiles/system/`: a `gen-N/`
//! directory holding a `toplevel` symlink, recorded in `state.json` (see
//! [`SystemGenerationState`]) alongside a `current` symlink that always
//! points at the live generation.
//!
//! # Install / upgrade / rollback flow
//!
//! [`install_system`] resolves the package, downloads and imports any
//! missing closure paths, writes the new generation, then runs the
//! toplevel's `activate` script with the generation number. [`upgrade_system`]
//! checks the registries for a newer sysroot version and delegates to
//! [`install_system`]; [`rollback_system`] re-activates a previous
//! generation's toplevel. Only after a successful activation is the
//! generation committed as `current`.
//!
//! # Activation exit-code contract
//!
//! The `activate` script (see `modules/base/activate.sh.in`) rebuilds the
//! generation's `/etc` overlay, reconciles running daemons via the hidden
//! [`activate_pre_etc_swap`] / [`activate_post_etc_swap`] split, and swaps
//! `/etc` atomically. Its exit code is the authority on what happened:
//!
//! ```text
//! 0      switch succeeded, every unit healthy
//! 5      switch succeeded; only stale-mount cleanup failed (cosmetic)
//! 6      switch succeeded but some units failed -- the generation stays
//!        live, but apm exits non-zero
//! 1/2/3  failed before the swap; the previous generation is still live
//! 4      swap incomplete; /etc indeterminate -- operator must intervene
//! ```
//!
//! # Kernel upgrade modes
//!
//! When the new generation ships a different kernel, [`KernelUpgradeMode`]
//! selects what happens after activation: `Advisory` (default) updates the
//! boot loader and advises a reboot, `Kexec` hot-loads the new kernel,
//! `Reboot` queues a full reboot via systemd, and `Live` applies userspace
//! only, deferring the kernel to the next reboot. `--drain` runs the
//! toplevel's drain script (or isolates `drain.target`) before a disruptive
//! switch.

use std::collections::HashSet;
use std::fs::{Metadata, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use aos_core::output::{OutputMode, Printer};
use aos_systemd::{FailedUnitsReport, JobResult, SettleOutcome, SystemdClient};

use crate::config::ApmConfig;
use crate::download::{
    DownloadRequest, ResolvedDownload, default_engine, download_nars, fetch_narinfo_closure,
    fetch_narinfos, resolve_mirror_chain, split_mirror_chain,
};
use crate::policy::admit_package_roots;
use crate::registry::sb_certs::{self, SbCertsToml};
use crate::registry::{RegistrySet, store_path_hash};
use crate::resolve::{collect_unique_metas, resolve_multiple};
use crate::store::{filter_missing, import_nar};
use crate::types::{PackageMeta, ProfileScope, SystemGeneration, SystemGenerationState};
use crate::unit_diff::{self, UnitDiff};
use crate::verify::{verify_download_hash, verify_downloads, verify_nar_hash};

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

/// File name of the generation-state JSON inside the system profile dir.
const SYSTEM_STATE_FILE: &str = "state.json";
/// systemd-boot loader entry rewritten when the kernel changes.
const BOOT_LOADER_ENTRY: &str = "/boot/loader/entries/aos.conf";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// `apm install <pkg> --system` — install a sysroot package as a system generation.
///
/// When `--image <FMT>` is specified, downloads the pre-compiled image instead
/// of the toplevel closure.
///
/// Otherwise runs the full pipeline: resolve the package, download/verify/
/// import missing closure paths, create the next `gen-N` directory, run the
/// toplevel's `activate` script (see the module docs for the exit-code
/// contract), commit the generation as `current`, and apply the chosen
/// [`KernelUpgradeMode`]. Note that in `Kexec` and `Reboot` modes a
/// successful kernel switch does not return.
///
/// # Errors
///
/// Returns an error when:
///
/// - `packages` does not contain exactly one name, the package cannot be
///   resolved, or it is not marked `sysroot = true`;
/// - downloading, hash verification, or store import of a closure path fails;
/// - generation state cannot be read or written;
/// - the activate script fails before the `/etc` swap (previous generation
///   stays live), leaves the swap incomplete (exit 4), or completes with
///   failed units (exit 6 — the new generation *is* live, but the error
///   surfaces the degraded state);
/// - the user declines the confirmation prompt
///   ([`aos_core::error::AosError::UserCancelled`]).
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
    admit_package_roots(closures.iter().flat_map(|closure| closure.closure.iter()))?;

    if closures.is_empty() {
        bail!("package '{pkg_name}' not found");
    }

    let closure = closures
        .iter()
        .find(|closure| closure.root.name == *pkg_name)
        .ok_or_else(|| anyhow::anyhow!("resolved closure missing requested sysroot package"))?;
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

    // Trust-graph totality (RFC-0005 §2.6): seed from the WHOLE graph closure
    // of each root (every reachable member, including anonymous paths).
    let trust_roots: Vec<(&str, &str)> = closures
        .iter()
        .map(|closure| {
            (
                closure.registry_name.as_str(),
                store_path_hash(&closure.root.store_path),
            )
        })
        .collect();
    let trust_ctx = registries.trust_context_for_roots(&trust_roots);
    trust_ctx.enforce_totality()?;

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
        fetch_narinfo_closure(
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
    printer.kv(
        "Package",
        &format!("{} {}", pkg_name, toplevel_meta.version),
    );
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

        // Step 6: Verify (against each path's source-registry store/ graph
        // map, RFC-0005; totality enforced above) and import.
        printer.step(5, 8, "Verifying...");
        verify_downloads(&results, &trust_ctx, printer)?;

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

    // Secure Boot validation (RFC-0006 phase 4): the closure is now
    // downloaded, NAR/hash-verified, and imported. Before we create a new
    // generation or touch the boot path, validate the image's recorded
    // Secure Boot facts against the registry's signed catalog so an upgrade
    // the firmware would reject is refused *here* — a clean, recoverable
    // download-time refusal rather than a boot-time brick.
    validate_sysroot_secure_boot(config, toplevel_meta, &closure.registry_name, printer)?;

    // Step 7: Create new system generation.
    printer.step(7, 8, "Creating system generation...");
    let profile_path = ProfileScope::System.profile_path();
    std::fs::create_dir_all(&profile_path)
        .with_context(|| format!("creating {}", profile_path.display()))?;

    let mut state = load_generation_state(&profile_path)?;
    let old_gen = state
        .generations
        .iter()
        .find(|g| g.number == state.current)
        .cloned();

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
        // This single-axis sysroot-install path does not populate two-axis fields;
        // not run the on-host config evaluator, so the config-gen axis metadata
        // is absent. A `None` `module_abi_pinned` makes the rollback pin treat
        // the generation is treated as same-ABI for direct reactivation.
        image_gen_parent: None,
        module_abi_pinned: None,
        manifest_hash: None,
        config_module_closure: None,
        host_nix_ref: None,
        host_nix_commit: None,
        facts_hash: None,
    };

    // Create generation directory with a symlink to the toplevel.
    let gen_dir = profile_path.join(format!("gen-{gen_num}"));
    std::fs::create_dir_all(&gen_dir)?;
    let toplevel_link = gen_dir.join("toplevel");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&toplevel_meta.store_path, &toplevel_link)
        .with_context(|| format!("creating toplevel symlink in gen-{gen_num}"))?;

    state.generations.push(new_gen);
    save_generation_state(&profile_path, &state)?;

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
    commit_current_generation(&profile_path, &mut state, gen_num)?;

    // Handle kernel upgrade according to the chosen mode. Both sides are
    // canonicalized so a seeded generation's `<toplevel>/kernel` symlink
    // form compares equal to the resolved form `resolve_kernel_path`
    // stores.
    let old_kernel_path =
        canonicalize_kernel_path(&old_gen.as_ref().and_then(|g| g.kernel_path.clone()));
    let kernel_path = canonicalize_kernel_path(&kernel_path);
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
        pkg_name, toplevel_meta.version, reboot_hint,
    ));

    Ok(())
}

/// `apm upgrade --system` — check for newer sysroot version and apply.
///
/// Looks up the current generation's package in the configured registries;
/// when a different sysroot version is published, delegates to
/// [`install_system`] (with confirmation auto-accepted) to perform the
/// switch.
///
/// # Errors
///
/// Returns an error when there is no active system generation, when
/// generation state or registries cannot be loaded, or when the delegated
/// [`install_system`] call fails.
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
///
/// With `--list`, prints the recorded system generations and returns.
/// Otherwise re-activates the target generation's toplevel (the explicit
/// `--generation N`, or the most recent generation before the current one),
/// commits it as `current`, and applies the chosen [`KernelUpgradeMode`] —
/// the same activation exit-code contract as [`install_system`] applies.
///
/// # Errors
///
/// Returns an error when there is no active system generation, the requested
/// generation does not exist, there is no previous generation to roll back
/// to, generation state cannot be read or written, or the target's activate
/// script fails (including the degraded exit-6 case, where the rollback is
/// live but some units failed).
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
                 is required (gen-{}).",
                target.number
            ),
            other => anyhow::bail!(
                "Rollback activation failed before the /etc swap (exit \
                 {other:?}); the previous generation is still live."
            ),
        }
    }
    commit_current_generation(&profile_path, &mut state, target.number)?;

    // Handle kernel upgrade according to the chosen mode (canonicalized
    // for the same reason as the upgrade path: the seeded generation
    // records the `kernel` symlink, not its target).
    handle_kernel_upgrade(
        &canonicalize_kernel_path(&current.kernel_path),
        &canonicalize_kernel_path(&target.kernel_path),
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
/// Returns `Some((sysroot_name, sysroot_version))` if every reference in
/// `pkg_refs` is already provided by the active sysroot's closure (in which
/// case a user-scope install would be redundant), `None` otherwise. All
/// failure modes — no system generation, unreadable state, unloadable
/// registries — degrade to `None` rather than erroring, since this is a
/// best-effort advisory check.
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
///
/// Prints the sysroot flag, previous-version chain link, closure size, and
/// any pre-compiled image formats. No-op for non-sysroot packages.
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

/// Download a pre-compiled image from a sysroot package (`--image <FMT>`).
///
/// Fetches the image's NAR through the regular download pipeline, imports it
/// into the store, then copies the image file out to `output` (defaulting to
/// `<name>-<version>.<format>` in the current directory).
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
        Box::leak(format!("{}-{}.{}", meta.name, meta.version, format).into_boxed_str())
    });

    printer.kv("Image format", format);
    printer.kv("Store path", &img.store_path);
    printer.kv("Size", &format_size(img.nar_size));
    printer.kv("Output", output_path);

    if dry_run {
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "action": "image_download",
                "status": "planned",
                "package": &meta.name,
                "version": &meta.version,
                "format": format,
                "store_path": &img.store_path,
                "nar_hash": &img.nar_hash,
                "nar_size": img.nar_size,
                "output": output_path,
                "dry_run": true,
                "downloads": {
                    "planned": 1,
                    "downloaded": 0,
                    "imported": 0,
                },
            }));
        } else {
            printer.info("Dry run -- no download.");
        }
        return Ok(());
    }

    // Use the existing download pipeline — the image store path is just another
    // store path in the cache.
    let chain = resolve_image_mirror(config, meta);
    let (mirror_url, fallback_mirrors) = split_mirror_chain(&chain);
    let request = DownloadRequest {
        store_path: img.store_path.clone(),
        mirror_url,
        fallback_mirrors,
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

    // Import NAR to get the store path, then copy image file out. The
    // expected NAR hash is the image entry from the signed package TOML -
    // not the cache-served narinfo - so the bytes are rooted at the
    // registry signature (images sit outside the store/ graph).
    let result = &results[0];
    verify_download_hash(&result.local_path, &result.download_hash)?;
    verify_nar_hash(&result.local_path, &img.nar_hash)
        .with_context(|| format!("verifying image NAR for {}", img.store_path))?;
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

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "image_download",
            "status": "downloaded",
            "package": &meta.name,
            "version": &meta.version,
            "format": format,
            "store_path": &img.store_path,
            "nar_hash": &img.nar_hash,
            "nar_size": img.nar_size,
            "output": output_path,
            "dry_run": false,
            "downloads": {
                "planned": resolved.len(),
                "downloaded": results.len(),
                "imported": results.len(),
            },
        }));
    } else {
        printer.success(&format!(
            "Image {} {} ({}) written to {}.",
            meta.name, meta.version, format, output_path,
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Generation state management
// ---------------------------------------------------------------------------

/// Load system generation state from disk (public wrapper for cross-module use).
///
/// Reads `state.json` from `profile_path`; a missing file yields the empty
/// initial state (`current = 0`, `next = 1`, no generations).
///
/// # Errors
///
/// Returns an error when the state file exists but cannot be read or parsed
/// as [`SystemGenerationState`] JSON.
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

/// Mark `generation` as current: persist it in `state.json` and atomically
/// repoint the `current` symlink (via a temp link + rename). Called only
/// after the generation's activate script has succeeded.
fn commit_current_generation(
    profile_path: &Path,
    state: &mut SystemGenerationState,
    generation: u32,
) -> Result<()> {
    state.current = generation;
    save_generation_state(profile_path, state)?;

    let current_link = profile_path.join("current");
    let tmp_link = profile_path.join(".current.tmp");
    let _ = std::fs::remove_file(&tmp_link);
    #[cfg(unix)]
    std::os::unix::fs::symlink(format!("gen-{generation}"), &tmp_link)?;
    std::fs::rename(&tmp_link, &current_link)?;
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
// reconciliation moved into the activate script's hidden pre/post split (see
// `activate_pre_etc_swap` / `activate_post_etc_swap`, which diff the live
// `/etc` against the candidate `/etc` via `crate::unit_diff`). These two
// helpers — per-job warning and the failed-units report formatter — are still
// used by that reconciler and by the kernel-upgrade path.
// ---------------------------------------------------------------------------

/// Warn (but do not fail) when a unit lifecycle job ended in something other
/// than `done`. The hard failure is the post-activation `failed_units` scan
/// in [`activate_post_etc_swap`] — a job can report a transient non-`done` result
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

/// Hard ceiling on how long the post-activation health gate waits for a single
/// auto-restarting unit to settle before giving up and reporting it failed.
///
/// Caps the per-unit deadline derived from `RestartSec` (see [`settle_budget`])
/// so a pathological restart policy — a large `RestartSec`, or a unit that
/// auto-restarts forever without ever reaching terminal `failed` — cannot stall
/// the upgrade unboundedly.
const MAX_SETTLE: Duration = Duration::from_secs(90);

/// Floor on the settle deadline: always wait at least this long so a unit with
/// a sub-second `RestartSec` still gets at least one clean retry observed.
const MIN_SETTLE: Duration = Duration::from_secs(5);

/// Restarts to budget for when sizing the settle deadline: enough to observe a
/// fail -> backoff -> retry -> (one more) recovery, which covers the common
/// "failed first start, recovers on retry" case.
const SETTLE_RETRY_BUDGET: u32 = 2;

/// Slack added on top of `RestartSec` * [`SETTLE_RETRY_BUDGET`] for the unit's
/// own start time before it signals ready.
const SETTLE_START_GRACE: Duration = Duration::from_secs(2);

/// Settle budget for a unit, derived from its `RestartSec` and clamped to
/// `[MIN_SETTLE, MAX_SETTLE]`.
fn settle_budget(restart_sec: Duration) -> Duration {
    (restart_sec * SETTLE_RETRY_BUDGET + SETTLE_START_GRACE).clamp(MIN_SETTLE, MAX_SETTLE)
}

/// Resolve units the snapshot scan flagged as auto-restarting before the gate
/// judges them.
///
/// [`SystemdClient::failed_units`] is a point-in-time scan: a `.service` caught
/// in its `RestartSec` backoff appears as `activating (auto-restart)` with a
/// non-zero `ExecMainStatus`, indistinguishable from a unit that will keep
/// failing. This partitions those tentative entries out, waits out each one's
/// backoff (bounded by [`settle_budget`]), and keeps only the ones that end up
/// genuinely failed — units that recover on retry are dropped. Units already in
/// terminal `failed` state pass through untouched.
///
/// Waits run concurrently, so the added latency is the longest single budget,
/// not their sum. Each wait is announced through `printer` (with its computed
/// bound) before blocking, and a unit that never settles within the cap is
/// reported with a warning, so a long wait is never silent and a flapping unit
/// is never silently passed.
async fn settle_auto_restarts(
    client: &SystemdClient,
    printer: &Printer,
    report: FailedUnitsReport,
) -> FailedUnitsReport {
    let (tentative, mut failed): (Vec<_>, Vec<_>) = report
        .failed
        .into_iter()
        .partition(|u| u.active_state != "failed" && u.sub_state == "auto-restart");

    if tentative.is_empty() {
        return FailedUnitsReport { failed };
    }

    // Size each unit's budget from its restart policy and announce before
    // blocking, so the operator sees why the upgrade is pausing and for how long.
    let mut budgets = Vec::with_capacity(tentative.len());
    for u in &tentative {
        let budget = match client.restart_policy(&u.name).await {
            Ok(policy) => settle_budget(policy.restart_sec),
            Err(_) => MIN_SETTLE,
        };
        let status = u
            .exec_main_status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "n/a".to_string());
        printer.info(&format!(
            "{} is auto-restarting (ExecMainStatus={status}); waiting up to {}s for it to settle...",
            u.name,
            budget.as_secs(),
        ));
        budgets.push(budget);
    }

    let outcomes = futures_util::future::join_all(
        tentative
            .iter()
            .zip(&budgets)
            .map(|(u, budget)| client.wait_until_settled(&u.name, *budget)),
    )
    .await;

    for ((u, budget), outcome) in tentative.into_iter().zip(budgets).zip(outcomes) {
        match outcome {
            SettleOutcome::Recovered { n_restarts } => {
                printer.info(&format!(
                    "  {} recovered after {n_restarts} restart(s)",
                    u.name
                ));
            }
            SettleOutcome::Failed => failed.push(u),
            SettleOutcome::StillRestarting => {
                printer.warning(&format!(
                    "  {} did not settle within {}s (still auto-restarting) — not converging",
                    u.name,
                    budget.as_secs(),
                ));
                failed.push(u);
            }
        }
    }

    FailedUnitsReport { failed }
}

// ---------------------------------------------------------------------------
// Live daemon reconciliation (`apm activate-{pre,post}-etc-swap`)
// ---------------------------------------------------------------------------

/// Exit codes for the hidden activation reconciler subcommands. The activate
/// script maps these into its own 0/3/4/5/6 contract.
const RECONCILE_OK: i32 = 0;
const RECONCILE_FAILED_UNITS: i32 = 1;
const RECONCILE_CATASTROPHIC: i32 = 2;

const PLAN_SCHEMA_VERSION: u32 = 1;

/// Where the activation orchestrator keeps the switch lock and plan files. It
/// lives on tmpfs (`/run`), so crash debris disappears on reboot.
const APM_RUN_DIR: &str = "/run/apm";

/// The daemon-reconcile plan handed from the pre-swap phase to the post-swap
/// phase, serialized as root-owned 0600 JSON under [`APM_RUN_DIR`].
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Plan {
    /// Plan format version; must equal [`PLAN_SCHEMA_VERSION`] on read.
    schema_version: u32,
    /// Generation number this plan was computed for.
    generation: u32,
    /// Stopped by the pre-swap phase. Best-effort, informational.
    stopped: Vec<String>,
    /// Remaining post-swap actions, already in apply order.
    to_reload: Vec<String>,
    to_restart: Vec<String>,
    to_start: Vec<String>,
    /// Units reconciled because an `X-Reload-Triggers` path changed.
    blanket_targets: Vec<String>,
    /// Non-fatal diff warnings carried over for display.
    warnings: Vec<String>,
}

/// `apm activate-pre-etc-swap` — compute the live-vs-candidate diff while the
/// old `/etc` is still live, stop removed / stop-if-changed units under their
/// old definitions, and print the post-swap plan path on stdout.
///
/// Returns a process exit code rather than a `Result`: `0` on success
/// (including `--dry-run`), `2` (`RECONCILE_CATASTROPHIC`) on any failure.
/// The activate script maps these into its own 0/3/4/5/6 contract.
pub async fn activate_pre_etc_swap(
    generation: u32,
    candidate_etc: &Path,
    dry_run: bool,
    printer: &Printer,
) -> i32 {
    match activate_pre_etc_swap_inner(generation, candidate_etc, dry_run, printer).await {
        Ok(code) => code,
        Err(e) => {
            printer.error(&format!("activate-pre-etc-swap: {e:#}"));
            RECONCILE_CATASTROPHIC
        }
    }
}

async fn activate_pre_etc_swap_inner(
    generation: u32,
    candidate_etc: &Path,
    dry_run: bool,
    printer: &Printer,
) -> Result<i32> {
    // `compute_diff` takes /etc roots and appends `systemd/system` itself.
    // In this phase live `/etc` is intentionally the old generation.
    let diff = unit_diff::compute_diff(Path::new("/etc"), candidate_etc);
    for w in &diff.warnings {
        printer.warning(w);
    }

    if dry_run {
        print_diff(&diff, printer);
        return Ok(RECONCILE_OK);
    }

    // The candidate systemd tree must exist and be readable; otherwise the
    // diff would look like "everything removed" and stop live units.
    let candidate_units = candidate_etc.join("systemd/system");
    if !candidate_units.is_dir() {
        bail!(
            "candidate /etc has no readable systemd/system dir: {}",
            candidate_units.display()
        );
    }

    let run_dir = Path::new(APM_RUN_DIR);
    ensure_secure_run_dir(run_dir)?;

    let client = SystemdClient::connect()
        .await
        .context("connecting to systemd over D-Bus")?;

    let plan = plan_from_diff(generation, diff);
    let plan_path = write_plan(run_dir, &plan)?;

    printer.info(&format!(
        "Preparing daemon reconcile plan for generation {generation}..."
    ));

    // Clear stale failed state for this whole switch before any action. We do
    // not reset after the post-swap apply, because that would mask failures
    // introduced by this activation before the health scan.
    client.reset_failed().await.context("reset-failed")?;

    for unit in &plan.stopped {
        printer.plain(&format!("  stopping   {unit}"));
        match client.stop_unit(unit).await {
            Ok(outcome) => warn_if_job_not_done(printer, "stop", unit, &outcome.result),
            Err(e) => printer.warning(&format!("  stop {unit}: {e:#}")),
        }
    }

    println!("{}", plan_path.display());
    Ok(RECONCILE_OK)
}

/// `apm activate-post-etc-swap` — consume the plan after `/etc` has been
/// swapped, reload systemd, apply reload/restart/start actions, and scan the
/// final failed-unit state.
///
/// Returns a process exit code rather than a `Result`: `0` when every unit
/// settled healthy, `1` (`RECONCILE_FAILED_UNITS`) when the apply completed
/// but the final scan found failed units, and `2`
/// (`RECONCILE_CATASTROPHIC`) on any other failure (invalid plan, D-Bus
/// errors, ...). The activate script maps these into its own 0/3/4/5/6
/// contract.
pub async fn activate_post_etc_swap(plan_path: &Path, printer: &Printer) -> i32 {
    match activate_post_etc_swap_inner(plan_path, printer).await {
        Ok(code) => code,
        Err(e) => {
            printer.error(&format!("activate-post-etc-swap: {e:#}"));
            RECONCILE_CATASTROPHIC
        }
    }
}

async fn activate_post_etc_swap_inner(plan_path: &Path, printer: &Printer) -> Result<i32> {
    let plan = read_validated_plan(plan_path)?;
    ensure_secure_run_dir(Path::new(APM_RUN_DIR))?;

    let client = SystemdClient::connect()
        .await
        .context("connecting to systemd over D-Bus")?;

    printer.info(&format!(
        "Applying daemon reconcile plan for generation {}...",
        plan.generation
    ));
    if !plan.blanket_targets.is_empty() {
        printer.info(&format!(
            "reload-trigger driven: {}",
            plan.blanket_targets.join(" ")
        ));
    }

    client.daemon_reload().await.context("daemon-reload")?;

    for unit in &plan.to_reload {
        printer.plain(&format!("  reloading  {unit}"));
        let outcome = client
            .reload_unit(unit)
            .await
            .with_context(|| format!("reloading {unit}"))?;
        warn_if_job_not_done(printer, "reload", unit, &outcome.result);
    }

    for unit in &plan.to_restart {
        printer.plain(&format!("  restarting {unit}"));
        let outcome = client
            .restart_unit(unit)
            .await
            .with_context(|| format!("restarting {unit}"))?;
        warn_if_job_not_done(printer, "restart", unit, &outcome.result);
    }

    for unit in &plan.to_start {
        printer.plain(&format!("  starting   {unit}"));
        let outcome = client
            .start_unit(unit)
            .await
            .with_context(|| format!("starting {unit}"))?;
        warn_if_job_not_done(printer, "start", unit, &outcome.result);
    }

    // Drain late job events so the scan below sees settled unit states. Do not
    // reset failed state here; pre-swap reset already cleared stale failures.
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

    let _ = std::fs::remove_file(plan_path);

    // `failed_units` is a point-in-time scan: a unit caught in its RestartSec
    // backoff shows up as `activating (auto-restart)`, indistinguishable from
    // one that will keep failing. Wait those out (bounded by MAX_SETTLE) before
    // the gate judges, so a unit that recovers on retry doesn't fail the upgrade.
    let report = settle_auto_restarts(&client, printer, report).await;

    if !report.is_empty() {
        printer.error(&format_failed_units(&report));
        return Ok(RECONCILE_FAILED_UNITS);
    }

    printer.success(&format!(
        "Reconcile complete: {} stopped, {} reloaded, {} restarted, {} started.",
        plan.stopped.len(),
        plan.to_reload.len(),
        plan.to_restart.len(),
        plan.to_start.len(),
    ));
    Ok(RECONCILE_OK)
}

/// Convert a [`UnitDiff`] into a serializable [`Plan`], folding install-only
/// units (new units with no live counterpart) into the start list.
fn plan_from_diff(generation: u32, mut diff: UnitDiff) -> Plan {
    let install_only = std::mem::take(&mut diff.install_only);
    for unit in install_only {
        if !diff.to_start.contains(&unit) {
            diff.to_start.push(unit);
        }
    }

    Plan {
        schema_version: PLAN_SCHEMA_VERSION,
        generation,
        stopped: diff.to_stop,
        to_reload: diff.to_reload,
        to_restart: diff.to_restart,
        to_start: diff.to_start,
        blanket_targets: diff.blanket_targets,
        warnings: diff.warnings,
    }
}

/// Create `/run/apm` securely if absent; otherwise reject anything other than a
/// root-owned 0700 directory.
fn ensure_secure_run_dir(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", dir.display()))?;
        }
        Err(e) => return Err(e).with_context(|| format!("stat {}", dir.display())),
    }

    validate_secure_dir(dir)
}

/// Reject `dir` unless it is a real (non-symlink) directory, root-owned, and
/// mode 0700 — the plan file's containing directory is part of its trust
/// boundary.
fn validate_secure_dir(dir: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        bail!("{} is not a real directory", dir.display());
    }
    if !root_owned_for_runtime(meta.uid()) {
        bail!("{} is not owned by root", dir.display());
    }
    let mode = meta.mode() & 0o777;
    if mode != 0o700 {
        bail!("{} has mode {mode:o}, expected 700", dir.display());
    }
    Ok(())
}

/// Persist the plan as a unique `plan-*.json` tempfile (mode 0600) in
/// `run_dir`, fsynced, and return its path for the post-swap phase.
fn write_plan(run_dir: &Path, plan: &Plan) -> Result<PathBuf> {
    let f = tempfile::Builder::new()
        .prefix("plan-")
        .suffix(".json")
        .tempfile_in(run_dir)
        .with_context(|| format!("creating plan in {}", run_dir.display()))?;
    serde_json::to_writer(f.as_file(), plan).context("serializing activation plan")?;
    let _ = f.as_file().sync_all();
    let (_, path) = f
        .keep()
        .with_context(|| format!("persisting plan in {}", run_dir.display()))?;
    Ok(path)
}

/// Open and parse a plan file with hardening: `O_NOFOLLOW` (no symlinks),
/// must be a regular root-owned file with mode 0600, and its
/// `schema_version` must match [`PLAN_SCHEMA_VERSION`].
fn read_validated_plan(path: &Path) -> Result<Plan> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening plan {}", path.display()))?;

    let meta = fstat_file(&file).with_context(|| format!("stat plan {}", path.display()))?;
    if !meta.is_file() {
        bail!("plan {} is not a regular file", path.display());
    }
    if !root_owned_for_runtime(meta.uid()) {
        bail!("plan {} is not owned by root", path.display());
    }
    let mode = meta.mode() & 0o777;
    if mode != 0o600 {
        bail!("plan {} has mode {mode:o}, expected 600", path.display());
    }

    let plan: Plan = serde_json::from_reader(file)
        .with_context(|| format!("parsing plan {}", path.display()))?;
    if plan.schema_version != PLAN_SCHEMA_VERSION {
        bail!(
            "plan {} has schema version {}, expected {}",
            path.display(),
            plan.schema_version,
            PLAN_SCHEMA_VERSION
        );
    }
    Ok(plan)
}

/// `fstat(2)` the already-open file descriptor, so the metadata check cannot
/// race against a path swap between open and stat.
fn fstat_file(file: &std::fs::File) -> Result<Metadata> {
    file.metadata().context("fstat")
}

/// Whether `uid` counts as "root-owned" for the security checks. Relaxed
/// under `cfg(test)` so unit tests can exercise the validators as a
/// non-root user.
fn root_owned_for_runtime(uid: u32) -> bool {
    uid == 0 || cfg!(test)
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

/// Canonicalize a stored kernel path to the form [`resolve_kernel_path`]
/// produces (the `kernel` symlink's target).
///
/// Generations seeded at first boot historically recorded the
/// `<toplevel>/kernel` symlink itself rather than its target. Comparing
/// that form against a resolved path reports a spurious kernel change on
/// every upgrade or rollback involving the seeded generation — rewriting
/// the boot loader needlessly and rendering the old version as the
/// literal string "kernel". Resolving the symlink (when it still exists
/// on disk) restores exact-string comparability; paths that cannot be
/// resolved are returned unchanged.
fn canonicalize_kernel_path(path: &Option<String>) -> Option<String> {
    let p = path.as_deref()?;
    match std::fs::read_link(p) {
        Ok(target) => Some(target.to_string_lossy().to_string()),
        Err(_) => Some(p.to_string()),
    }
}

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
                printer.warning(&format!("Kernel updated: {} -> {}", old_ver, new_ver,));
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
    let mut load_args = vec!["-l".to_string(), kernel, "--reuse-cmdline".to_string()];
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

/// Load all enabled registries from the scope's metadata cache.
fn load_registries(config: &ApmConfig) -> Result<RegistrySet> {
    let reg_configs = config.enabled_registries();
    RegistrySet::load(&config.cache_path(), &reg_configs, "x86_64-linux")
}

/// Validate a downloaded sysroot's Secure Boot facts against the registry's
/// signed catalog before activation (RFC-0006 phase 4).
///
/// For every image the sysroot ships that records Secure Boot facts, this
/// enforces, against the registry's committed `sb-certs.toml`:
///
/// 1. the image's `sb_signer_cert_sha256` is in the **active** db-cert set
///    (and not revoked),
/// 2. every SBAT component's generation is **at or above** the revocation
///    floor,
/// 3. (defense in depth) the downloaded UKI's embedded Authenticode
///    signature re-verifies against the catalog's db cert, when a db cert
///    PEM is provisioned locally (`trusted-sb-certs.d/<registry>.pem`).
///
/// On any mismatch it returns an error *before* a new generation is created
/// or the boot path is touched, turning a boot-time Secure Boot rejection
/// into a recoverable download-time refusal.
///
/// # Policy for unsigned images
///
/// Images that record **no** Secure Boot facts (legacy/unsigned/dev builds:
/// `sb_signer_cert_sha256 == None` and an empty `sbat`) are skipped so the
/// existing unsigned development path keeps working. Likewise, if the
/// registry ships no `sb-certs.toml`, there is nothing to validate against
/// and the step is a no-op. Validation engages only when *both* the image
/// carries facts *and* the registry publishes a catalog.
///
/// # Errors
///
/// Returns an error when the registry catalog cannot be loaded or parsed,
/// when an image's signer cert is not in the active db-cert set, when an
/// SBAT generation is below the floor, or when the re-verification of a
/// downloaded UKI against the db cert fails.
fn validate_sysroot_secure_boot(
    config: &ApmConfig,
    toplevel_meta: &PackageMeta,
    registry_name: &str,
    printer: &Printer,
) -> Result<()> {
    // The signed `sb-certs.toml` is materialized by `extract_registry_root`
    // (registry/git.rs) into the registries-storage directory alongside
    // `registry.toml` / `keys.toml` — NOT the metadata cache that holds
    // `packages/` and `closures/`. Read it from the same directory the
    // extractor writes to, or the catalog is silently invisible.
    let registry_tree = config.scope.registries_path().join(registry_name);
    let db_cert = sb_db_cert_pem(config, registry_name);
    validate_sysroot_secure_boot_in(
        &toplevel_meta.images,
        registry_name,
        &registry_tree,
        db_cert.as_deref(),
        printer,
    )
}

/// Catalog-directory-explicit core of [`validate_sysroot_secure_boot`].
///
/// Loads `sb-certs.toml` from `catalog_dir` (the exact directory
/// `extract_registry_root` writes the registry's root files to) and runs the
/// per-image gate. Keeping the directory and db-cert path as parameters lets
/// tests point the validator at a temp tree without relying on the cached
/// scope path resolution.
///
/// # Errors
///
/// Returns an error when the catalog fails to load/parse or any image fails
/// [`validate_image_secure_boot`].
fn validate_sysroot_secure_boot_in(
    images: &[crate::types::SysrootImageEntry],
    registry_name: &str,
    catalog_dir: &Path,
    db_cert: Option<&Path>,
    printer: &Printer,
) -> Result<()> {
    let signed_images: Vec<&crate::types::SysrootImageEntry> = images
        .iter()
        .filter(|img| img.sb_signer_cert_sha256.is_some() || !img.sbat.is_empty())
        .collect();
    if signed_images.is_empty() {
        // Unsigned/legacy sysroot: nothing to validate (dev path).
        return Ok(());
    }

    let Some(catalog) = sb_certs::load_sb_certs_toml(catalog_dir).with_context(|| {
        format!(
            "loading Secure Boot catalog for registry '{registry_name}' from {}",
            catalog_dir.display()
        )
    })?
    else {
        // The registry publishes no Secure Boot catalog; there is no
        // signed floor or active set to enforce against.
        printer.info(
            "Registry publishes no Secure Boot catalog (sb-certs.toml); \
             skipping download-time SB validation.",
        );
        return Ok(());
    };

    for img in signed_images {
        validate_image_secure_boot(img, &catalog, db_cert)?;
    }

    printer.success("Secure Boot catalog validation passed.");
    Ok(())
}

/// Validate one image entry against the registry catalog.
///
/// # Errors
///
/// Returns an error for an unknown/revoked signer cert, a below-floor SBAT
/// generation, or a failed UKI re-verification.
fn validate_image_secure_boot(
    img: &crate::types::SysrootImageEntry,
    catalog: &SbCertsToml,
    db_cert: Option<&Path>,
) -> Result<()> {
    // 1. Signer cert must be active and not revoked.
    match &img.sb_signer_cert_sha256 {
        Some(cert) if catalog.accepts_signer(cert) => {}
        Some(cert) => bail!(
            "Secure Boot validation failed for image '{}': its signer cert \
             {cert} is not in the registry's active db-cert set (it was \
             retired or never trusted). Refusing the upgrade before reboot.",
            img.format,
        ),
        None => bail!(
            "Secure Boot validation failed for image '{}': it records SBAT \
             facts but no signer cert; the registry cannot vouch for it. \
             Refusing the upgrade before reboot.",
            img.format,
        ),
    }

    // 2. Every SBAT component must meet the revocation floor.
    if let Some((component, found, floor)) = catalog.first_below_floor(&img.sbat) {
        bail!(
            "Secure Boot validation failed for image '{}': SBAT component \
             '{component}' generation {found} is below the registry \
             revocation floor {floor}. This component was revoked fleet-wide; \
             refusing the upgrade before reboot.",
            img.format,
        );
    }

    // 3. Defense in depth: re-verify the downloaded UKI against the db cert.
    if let Some(db_cert) = db_cert {
        if let Some(uki) = find_uki_in_image(&img.store_path) {
            reverify_uki(&uki, db_cert).with_context(|| {
                format!(
                    "re-verifying downloaded UKI for image '{}' against the \
                     catalog db cert",
                    img.format
                )
            })?;
        }
    }

    Ok(())
}

/// Locate a provisioned db certificate PEM for `registry`, if present.
///
/// Mirrors the registry trust-anchor delivery: searches the scope's
/// `trusted-sb-certs.d` directories for `<registry>.pem`, returning the
/// first match or `None` when no db cert was baked/provisioned (in which
/// case the re-verification step is skipped).
fn sb_db_cert_pem(config: &ApmConfig, registry: &str) -> Option<PathBuf> {
    config
        .scope
        .trusted_sb_certs_dirs()
        .into_iter()
        .map(|dir| dir.join(format!("{registry}.pem")))
        .find(|path| path.exists())
}

/// Find a UKI (`.efi` PE file) inside an imported image store path.
fn find_uki_in_image(store_path: &str) -> Option<PathBuf> {
    fn walk(dir: &Path) -> Option<PathBuf> {
        let entries = std::fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(found) = walk(&path) {
                    return Some(found);
                }
            } else if path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("efi"))
            {
                return Some(path);
            }
        }
        None
    }
    let root = Path::new(store_path);
    if root.is_file() {
        return root
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("efi"))
            .then(|| root.to_path_buf());
    }
    walk(root)
}

/// Re-verify a downloaded UKI's Authenticode signature against a db cert.
///
/// # Errors
///
/// Returns an error when `sbverify` cannot be spawned or reports the
/// signature does not verify against `db_cert`.
fn reverify_uki(uki: &Path, db_cert: &Path) -> Result<()> {
    let output = std::process::Command::new("sbverify")
        .arg("--cert")
        .arg(db_cert)
        .arg(uki)
        .output()
        .with_context(|| format!("running sbverify --cert on {}", uki.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "downloaded UKI {} failed Secure Boot re-verification against \
             db cert {}: {}",
            uki.display(),
            db_cert.display(),
            if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            }
        );
    }
    Ok(())
}

/// Pick the mirror chain used for image downloads: the first configured
/// registry's mirror chain (primary + fallbacks for miss-fallthrough),
/// falling back to the default public cache.
fn resolve_image_mirror(config: &ApmConfig, _meta: &PackageMeta) -> Vec<String> {
    // Use the first configured registry's mirror chain.
    if let Some((cfg, _)) = config.registries.first() {
        return resolve_mirror_chain(&config.scope.registries_path(), cfg);
    }
    vec!["https://cache.aos.dev".to_string()]
}

/// Build a [`DownloadRequest`] per missing store path, mapping each path back
/// to the mirror URL of the registry that resolved it.
fn build_download_requests(
    closures: &[crate::resolve::ResolvedClosure],
    to_download: &[&PackageMeta],
    config: &ApmConfig,
) -> Result<Vec<DownloadRequest>> {
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
                vec![format!("https://registry.aos.dev/{}", c.registry_name)]
            };
            (c.registry_name.clone(), chain)
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

/// Prompt `[Y/n]` on stderr; empty/`y`/`yes` accepts, anything else returns
/// [`aos_core::error::AosError::UserCancelled`].
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

/// Format a byte count as a human-readable binary size (B/KiB/MiB/GiB).
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
/// fingerprint is only ever compared within a single activation reconcile
/// process, so a non-cryptographic hash is sufficient and lets us avoid
/// pulling in `twox-hash` (which would churn the vendored Cargo deps hash).
pub(crate) fn djb2_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 5381;
    for &byte in data {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`, computed without a time
/// crate (see [`days_to_ymd`]).
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

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since the Unix epoch to a Gregorian `(year, month, day)`
/// using Howard Hinnant's civil-from-days algorithm.
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
    use crate::registry::sb_certs::{RevokedSbCert, SbCert, write_sb_certs_toml};
    use crate::types::{SbatEntry, SysrootImageEntry};
    use tempfile::TempDir;

    const SIGNER_ACTIVE: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const SIGNER_RETIRED: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

    fn sb_sbat(pairs: &[(&str, u32)]) -> Vec<SbatEntry> {
        pairs
            .iter()
            .map(|(c, g)| SbatEntry {
                component: (*c).into(),
                generation: *g,
            })
            .collect()
    }

    fn signed_image(signer: &str, sbat: &[(&str, u32)]) -> SysrootImageEntry {
        SysrootImageEntry {
            format: "raw".into(),
            store_path: "/nix/store/deadbeef-aos-image".into(),
            nar_hash: "sha256:abc".into(),
            nar_size: 4096,
            sb_signer_cert_sha256: Some(signer.into()),
            sbat: sb_sbat(sbat),
            expected_pcr11: None,
            root_image: None,
            root_verity: None,
            root_hash: None,
            root_hash_sig: None,
        }
    }

    fn active_catalog() -> SbCertsToml {
        SbCertsToml {
            active: vec![SbCert {
                id: "db-2026".into(),
                cert_sha256: SIGNER_ACTIVE.into(),
            }],
            sbat_floor: sb_sbat(&[("aos", 1)]),
            ..SbCertsToml::default()
        }
    }

    // --- Real-validator coverage (RFC-0006 phase 4 download-time gate) ---

    #[test]
    fn validate_image_accepts_active_signer_above_floor() {
        let img = signed_image(SIGNER_ACTIVE, &[("aos", 2)]);
        assert!(validate_image_secure_boot(&img, &active_catalog(), None).is_ok());
    }

    #[test]
    fn validate_image_refuses_below_floor() {
        let img = signed_image(SIGNER_ACTIVE, &[("aos", 1)]);
        let raised = SbCertsToml {
            sbat_floor: sb_sbat(&[("aos", 2)]),
            ..active_catalog()
        };
        let err = validate_image_secure_boot(&img, &raised, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("below the registry"), "{msg}");
    }

    #[test]
    fn validate_image_refuses_retired_cert() {
        let catalog = SbCertsToml {
            active: vec![
                SbCert {
                    id: "db-2026".into(),
                    cert_sha256: SIGNER_ACTIVE.into(),
                },
                SbCert {
                    id: "db-2024".into(),
                    cert_sha256: SIGNER_RETIRED.into(),
                },
            ],
            revoked: vec![RevokedSbCert {
                id: "db-2024".into(),
                reason: Some("compromised".into()),
            }],
            sbat_floor: sb_sbat(&[("aos", 1)]),
            ..SbCertsToml::default()
        };
        let retired = signed_image(SIGNER_RETIRED, &[("aos", 5)]);
        assert!(validate_image_secure_boot(&retired, &catalog, None).is_err());
        let active = signed_image(SIGNER_ACTIVE, &[("aos", 5)]);
        assert!(validate_image_secure_boot(&active, &catalog, None).is_ok());
    }

    #[test]
    fn validate_image_refuses_unknown_signer() {
        let img = signed_image(SIGNER_RETIRED, &[("aos", 9)]);
        assert!(validate_image_secure_boot(&img, &active_catalog(), None).is_err());
    }

    /// Regression guard for C1: the validator must read `sb-certs.toml` from
    /// the exact directory `extract_registry_root` writes registry root files
    /// to. This writes the catalog there and confirms the *real* gate
    /// (`validate_sysroot_secure_boot_in`) picks it up and enforces it. With
    /// the original cache-vs-registries path mismatch this test fails because
    /// the catalog is invisible and a below-floor image is wrongly accepted.
    #[test]
    fn validate_sysroot_reads_catalog_from_extract_dir() {
        let tmp = TempDir::new().unwrap();
        let catalog_dir = tmp.path();
        // This is the directory layout extract_registry_root produces:
        // <registries-storage>/<name>/sb-certs.toml at the tree root.
        write_sb_certs_toml(
            catalog_dir,
            &SbCertsToml {
                active: vec![SbCert {
                    id: "db".into(),
                    cert_sha256: SIGNER_ACTIVE.into(),
                }],
                sbat_floor: sb_sbat(&[("aos", 5)]),
                ..SbCertsToml::default()
            },
        )
        .unwrap();
        let printer = Printer::new(0, true, false);

        // Below the floor (gen 1 < floor 5): must be refused now that the
        // catalog is actually read from this directory.
        let below = vec![signed_image(SIGNER_ACTIVE, &[("aos", 1)])];
        assert!(
            validate_sysroot_secure_boot_in(&below, "aos", catalog_dir, None, &printer).is_err(),
            "catalog at the extract dir must be enforced"
        );

        // At/above the floor: accepted.
        let ok = vec![signed_image(SIGNER_ACTIVE, &[("aos", 5)])];
        assert!(validate_sysroot_secure_boot_in(&ok, "aos", catalog_dir, None, &printer).is_ok());
    }

    #[test]
    fn validate_sysroot_skips_unsigned_images() {
        let tmp = TempDir::new().unwrap();
        let printer = Printer::new(0, true, false);
        let unsigned = vec![SysrootImageEntry {
            format: "raw".into(),
            store_path: "/nix/store/x".into(),
            nar_hash: "sha256:y".into(),
            nar_size: 1,
            sb_signer_cert_sha256: None,
            sbat: vec![],
            expected_pcr11: None,
            root_image: None,
            root_verity: None,
            root_hash: None,
            root_hash_sig: None,
        }];
        // No catalog written, no facts on the image: no-op success.
        assert!(
            validate_sysroot_secure_boot_in(&unsigned, "aos", tmp.path(), None, &printer).is_ok()
        );
    }

    #[test]
    fn validate_sysroot_refuses_signed_image_with_no_catalog_floor_satisfied_but_signer_absent() {
        // A signed image plus an empty catalog (no active certs) must refuse:
        // an empty active set vouches for nobody. The catalog file is present
        // but empty so load returns Some(default).
        let tmp = TempDir::new().unwrap();
        write_sb_certs_toml(tmp.path(), &SbCertsToml::default()).unwrap();
        let printer = Printer::new(0, true, false);
        let img = vec![signed_image(SIGNER_ACTIVE, &[("aos", 1)])];
        assert!(validate_sysroot_secure_boot_in(&img, "aos", tmp.path(), None, &printer).is_err());
    }

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
                    image_gen_parent: None,
                    module_abi_pinned: None,
                    manifest_hash: None,
                    config_module_closure: None,
                    host_nix_ref: None,
                    host_nix_commit: None,
                    facts_hash: None,
                },
                SystemGeneration {
                    number: 2,
                    toplevel: "/nix/store/def456-server-2026.04".into(),
                    version: "2026.04".into(),
                    package_name: "server".into(),
                    registry: "aos-core".into(),
                    created_at: "2026-04-01T00:00:00Z".into(),
                    kernel_path: Some("/nix/store/kern2-linux-6.13".into()),
                    image_gen_parent: None,
                    module_abi_pinned: None,
                    manifest_hash: None,
                    config_module_closure: None,
                    host_nix_ref: None,
                    host_nix_commit: None,
                    facts_hash: None,
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
                image_gen_parent: None,
                module_abi_pinned: None,
                manifest_hash: None,
                config_module_closure: None,
                host_nix_ref: None,
                host_nix_commit: None,
                facts_hash: None,
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
        let path = Some("/nix/store/01234567890123456789012345678901-linux-6.12.1".to_string());
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
    fn canonicalize_kernel_path_resolves_seeded_symlink_form() {
        // A seeded generation records `<toplevel>/kernel` (the symlink),
        // not its target. Canonicalizing must yield the target so it
        // compares equal to what resolve_kernel_path stores.
        let dir = tempfile::tempdir().unwrap();
        let target = dir
            .path()
            .join("01234567890123456789012345678901-linux-6.12.1");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("kernel");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let seeded = Some(link.to_string_lossy().to_string());
        assert_eq!(
            canonicalize_kernel_path(&seeded),
            Some(target.to_string_lossy().to_string())
        );
    }

    #[test]
    fn canonicalize_kernel_path_keeps_resolved_and_missing_paths() {
        // Already-resolved paths (not symlinks) and paths that no longer
        // exist pass through unchanged; None stays None.
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("linux-6.12.1");
        std::fs::create_dir(&plain).unwrap();
        let plain_str = plain.to_string_lossy().to_string();
        assert_eq!(
            canonicalize_kernel_path(&Some(plain_str.clone())),
            Some(plain_str)
        );

        let gone = "/nix/store/gcd-toplevel/kernel".to_string();
        assert_eq!(canonicalize_kernel_path(&Some(gone.clone())), Some(gone));
        assert_eq!(canonicalize_kernel_path(&None), None);
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
        assert!(
            out.contains("2 service(s) failed during activation"),
            "{out}"
        );
        assert!(out.contains("broken.service"), "{out}");
        assert!(out.contains("ExecMainStatus=1"), "{out}");
        // The captured status dump is included, indented.
        assert!(out.contains("      ● broken.service - Broken"), "{out}");
        // A unit with no ExecMainStatus renders as n/a.
        assert!(out.contains("stuck.service"), "{out}");
        assert!(out.contains("ExecMainStatus=n/a"), "{out}");
    }

    #[test]
    fn settle_budget_clamps_to_bounds() {
        // A typical RestartSec=5s yields one-or-two retries plus grace, within
        // bounds: 5*2 + 2 = 12s.
        assert_eq!(
            settle_budget(Duration::from_secs(5)),
            Duration::from_secs(12)
        );
        // A sub-second RestartSec floors at MIN_SETTLE rather than ~2s.
        assert_eq!(settle_budget(Duration::from_millis(100)), MIN_SETTLE);
        // A large RestartSec is capped at MAX_SETTLE rather than 2*60+2 = 122s.
        assert_eq!(settle_budget(Duration::from_secs(60)), MAX_SETTLE);
    }

    // --- activate plan helpers -----------------------------------------

    #[test]
    fn plan_round_trips_through_json() {
        let plan = Plan {
            schema_version: PLAN_SCHEMA_VERSION,
            generation: 42,
            stopped: vec!["old.service".to_string()],
            to_reload: vec!["reload.service".to_string()],
            to_restart: vec!["restart.socket".to_string(), "restart.service".to_string()],
            to_start: vec!["new.service".to_string()],
            blanket_targets: vec!["nftables.service".to_string()],
            warnings: vec!["warning".to_string()],
        };

        let json = serde_json::to_string(&plan).unwrap();
        let parsed: Plan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, plan);
        assert_eq!(parsed.schema_version, PLAN_SCHEMA_VERSION);
    }

    #[test]
    fn plan_from_diff_folds_install_only_into_start() {
        let diff = UnitDiff {
            to_start: vec!["y.service".to_string(), "dup.service".to_string()],
            install_only: vec![
                "x.service".to_string(),
                "dup.service".to_string(),
                "z.service".to_string(),
            ],
            ..Default::default()
        };

        let plan = plan_from_diff(7, diff);
        assert_eq!(
            plan.to_start,
            vec![
                "y.service".to_string(),
                "dup.service".to_string(),
                "x.service".to_string(),
                "z.service".to_string(),
            ]
        );
        assert_eq!(plan.generation, 7);
    }

    #[test]
    fn write_plan_file_is_regular_root_readable_0600() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plan = Plan {
            schema_version: PLAN_SCHEMA_VERSION,
            generation: 1,
            ..Default::default()
        };

        let path = write_plan(tmp.path(), &plan).unwrap();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.mode() & 0o777, 0o600);
    }

    #[test]
    fn read_validated_plan_rejects_symlink() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plan = Plan {
            schema_version: PLAN_SCHEMA_VERSION,
            generation: 1,
            ..Default::default()
        };
        let target = write_plan(tmp.path(), &plan).unwrap();
        let link = tmp.path().join("plan-link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(read_validated_plan(&link).is_err());
    }

    #[test]
    fn read_validated_plan_rejects_wrong_mode() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plan = Plan {
            schema_version: PLAN_SCHEMA_VERSION,
            generation: 1,
            ..Default::default()
        };
        let path = write_plan(tmp.path(), &plan).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(read_validated_plan(&path).is_err());
    }

    #[test]
    fn read_validated_plan_round_trips() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plan = Plan {
            schema_version: PLAN_SCHEMA_VERSION,
            generation: 9,
            to_start: vec!["new.service".to_string()],
            ..Default::default()
        };

        let path = write_plan(tmp.path(), &plan).unwrap();
        let parsed = read_validated_plan(&path).unwrap();
        assert_eq!(parsed, plan);
    }

    #[test]
    fn ensure_secure_run_dir_creates_0700_and_validates() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("apm");

        ensure_secure_run_dir(&dir).unwrap();
        let meta = std::fs::symlink_metadata(&dir).unwrap();
        assert!(meta.file_type().is_dir());
        assert_eq!(meta.mode() & 0o777, 0o700);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ensure_secure_run_dir(&dir).is_err());
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
