//! System sysroot management (`apm install --system`, `apm upgrade --system`,
//! `apm rollback --system`).
//!
//! A sysroot package is a regular package with `sysroot = true` whose metadata
//! names both a system toplevel and an authenticated raw OTA payload. Checked
//! image-rollout abilities own immutable image transitions. Configuration generations
//! remain independent native package transactions under
//! `/var/lib/profiles/system/`.
//!
//! # Install / upgrade / rollback flow
//!
//! [`install_system`] authenticates and stages an image, then submits selection
//! through the package's native image abilities. [`upgrade_system`] selects the
//! published update through the same path. [`rollback_image_generation`] submits
//! a retained image; [`rollback_system`] reconciles a retained configuration on
//! the running image.
//!
//! # Image transition modes
//!
//! [`SystemTransitionMode`] controls what happens after staging: `Advisory`
//! (default) leaves the transition pending and advises a reboot, while
//! `Reboot` drains when requested and queues a full reboot. Kexec and a live
//! userspace-only switch are not valid for an immutable image transition.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use aos_core::output::{OutputMode, Printer};

use crate::config::ApmConfig;
use crate::download::{
    DownloadRequest, default_engine, download_nars, fetch_narinfos, resolve_mirror_chain,
    split_mirror_chain,
};
use crate::platform::native_platform;
use crate::registry::{RegistrySet, store_path_hash};
use crate::types::{
    ImageGeneration, ImageGenerationState, ImageRollout, PackageMeta, ProfileScope,
};
use crate::verify::verify_download_hash;

mod activatability;
mod image_prepare;
pub(crate) mod image_rollout;
mod image_stage;
pub use image_prepare::{ImagePreparationPurpose, ImagePrepareOptions, prepare_image};
pub use image_rollout::run_boot_commit_from_process as run_image_rollout_boot_commit;
pub use image_rollout::run_observer_from_process as run_image_rollout_observer;
pub use image_rollout::run_provider_from_process as run_image_rollout_provider;

pub use activatability::{
    ActivatabilityReason, ActivatabilityReasonCode, RETAINED_ACTIVATABILITY_SCHEMA,
    RetainedActivatabilityReport, RetainedActivationMode, RetainedTargetKind,
};

// ---------------------------------------------------------------------------
// Kernel upgrade mode
// ---------------------------------------------------------------------------

/// How to complete an immutable system-image transition after staging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SystemTransitionMode {
    /// Leaves the staged image pending and advises the operator to reboot.
    #[default]
    Advisory,
    /// Requests a full reboot after staging.
    Reboot,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// File name of the generation-state JSON inside the system profile dir.
const IMAGE_STATE_FILE: &str = "state.json";
const IMAGE_PROFILE_DIR: &str = "/var/lib/profiles/image";
const RUNNING_TOPLEVEL_LINK: &str = "/usr/lib/aos/toplevel";
const MAX_IMAGE_METADATA_BYTES: u64 = 64 * 1024;

/// Resolves the booted image generation from immutable image identity.
///
/// The `/var` image index is accepted only after its running record agrees
/// with the baked `/usr/lib/aos/toplevel` pointer, native module-library NAR identity,
/// evaluation descriptor, executor, and package metadata. Boot measurement
/// verification is performed separately by the selected boot implementation.
///
/// # Errors
///
/// Returns an error if any identity input is absent, malformed, or disagrees.
pub(crate) fn running_image_generation() -> Result<ImageGeneration> {
    load_running_image_generation_from(
        Path::new(IMAGE_PROFILE_DIR),
        Path::new(RUNNING_TOPLEVEL_LINK),
        Path::new("/"),
    )
}

pub(crate) fn load_image_generation_state_pub(profile: &Path) -> Result<ImageGenerationState> {
    let path = profile.join(IMAGE_STATE_FILE);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading image generation state {}", path.display()))?;
    let state: ImageGenerationState = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing image generation state {}", path.display()))?;
    state
        .validate()
        .with_context(|| format!("validating image generation state {}", path.display()))?;
    Ok(state)
}

pub(crate) fn record_pending_image_selection(
    profile: &Path,
    state: &mut ImageGenerationState,
    target: u32,
    rollout: ImageRollout,
) -> Result<()> {
    let mut prepared = state.clone();
    prepared.pending = Some(target);
    prepared.active_rollout = Some(rollout);
    image_rollout::validate_active_rollout_selection(
        &prepared,
        prepared
            .active_rollout
            .as_ref()
            .context("prepared image selection lost its rollout")?,
        target,
    )?;
    write_atomic_durable(
        &profile.join(IMAGE_STATE_FILE),
        &serde_json::to_vec_pretty(&prepared)?,
    )?;
    *state = prepared;
    Ok(())
}

/// Records ordinary next-boot selection after the backend durably prepares it.
pub(crate) fn record_pending_unqualified_image_selection(
    profile: &Path,
    state: &mut ImageGenerationState,
    target: u32,
) -> Result<()> {
    state.validate()?;
    ensure!(
        state.active_rollout.is_none(),
        "a qualified image rollout is active"
    );
    ensure!(target != state.running, "selected image is already running");
    ensure!(
        state.generations.iter().any(|image| image.number == target),
        "selected image is not indexed"
    );
    ensure!(
        state.pending.is_none_or(|pending| pending == target),
        "another image selection is pending"
    );

    let mut prepared = state.clone();
    prepared.pending = Some(target);
    prepared.validate()?;
    write_atomic_durable(
        &profile.join(IMAGE_STATE_FILE),
        &serde_json::to_vec_pretty(&prepared)?,
    )?;
    *state = prepared;
    Ok(())
}

fn load_running_image_generation_from(
    image_profile: &Path,
    toplevel_link: &Path,
    immutable_root: &Path,
) -> Result<ImageGeneration> {
    load_running_image_generation_with_device_identity(image_profile, toplevel_link, immutable_root)
}

fn load_running_image_generation_with_device_identity(
    image_profile: &Path,
    toplevel_link: &Path,
    immutable_root: &Path,
) -> Result<ImageGeneration> {
    let state_path = image_profile.join(IMAGE_STATE_FILE);
    let state_bytes = std::fs::read(&state_path)
        .with_context(|| format!("reading image generation state {}", state_path.display()))?;
    let state: ImageGenerationState = serde_json::from_slice(&state_bytes)
        .with_context(|| format!("parsing image generation state {}", state_path.display()))?;
    state
        .validate()
        .with_context(|| format!("validating image generation state {}", state_path.display()))?;
    let running = state.running_generation().cloned().with_context(|| {
        format!(
            "image generation state names missing running generation {}",
            state.running
        )
    })?;
    let baked_toplevel = std::fs::read_link(toplevel_link)
        .with_context(|| format!("reading running image pointer {}", toplevel_link.display()))?;
    let baked_toplevel_text = baked_toplevel
        .to_str()
        .context("running image pointer target is not UTF-8")?;
    let (root, suffix) = crate::deployment::nix::store_root_and_suffix(&baked_toplevel)?;
    ensure!(
        suffix.as_os_str().is_empty()
            && root == baked_toplevel
            && !baked_toplevel_text.contains("//"),
        "running image pointer is not a canonical store root"
    );
    if baked_toplevel != Path::new(&running.toplevel) {
        bail!(
            "running image pointer {} disagrees with image generation {} toplevel {}",
            baked_toplevel.display(),
            running.number,
            running.toplevel
        );
    }
    let read_meta = |name: &str| read_immutable_metadata(immutable_root, &baked_toplevel, name);
    let library: crate::types::ModuleLibraryIdentity =
        serde_json::from_str(&read_meta("module-library.json")?)
            .context("reading immutable native module-library identity")?;
    let descriptor = read_meta("evaluation-descriptor")?;
    let immutable_package = read_meta("package-name")?;
    let immutable_version = read_meta("version")?;
    let immutable_state = read_meta("state-version")?;
    let immutable_executor = read_meta("native-executor-ref")?;
    ensure!(
        library == running.module_library
            && descriptor == running.evaluation_descriptor
            && immutable_package == running.package_name
            && immutable_version == running.version
            && immutable_state == running.state_version
            && immutable_executor == running.native_executor_ref,
        "running immutable toplevel metadata disagrees with image generation {}",
        running.number,
    );
    Ok(running)
}

fn read_immutable_metadata(root: &Path, toplevel: &Path, name: &str) -> Result<String> {
    use rustix::fs::{Mode, OFlags, openat};

    let relative = toplevel
        .strip_prefix("/")
        .context("image toplevel is not absolute")?
        .join("meta")
        .join(name);
    let components = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => Ok(value),
            _ => bail!("image metadata path is not normalized"),
        })
        .collect::<Result<Vec<_>>>()?;
    let (filename, parents) = components
        .split_last()
        .context("image metadata path is empty")?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = openat(rustix::fs::CWD, root, directory_flags, Mode::empty())
        .with_context(|| format!("opening immutable image root {}", root.display()))?;
    for component in parents {
        directory = openat(&directory, *component, directory_flags, Mode::empty())
            .context("image metadata has a symlink or non-directory parent")?;
    }
    let descriptor = openat(
        &directory,
        *filename,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .context("opening immutable image metadata")?;
    let file = std::fs::File::from(descriptor);
    ensure!(
        file.metadata()?.is_file(),
        "image metadata is not a regular file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_IMAGE_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_IMAGE_METADATA_BYTES,
        "image metadata exceeds its byte limit"
    );
    Ok(std::str::from_utf8(&bytes)
        .context("image metadata is not UTF-8")?
        .trim()
        .to_owned())
}

fn read_toplevel_meta(toplevel: &Path, name: &str) -> Result<String> {
    read_immutable_metadata(Path::new("/"), toplevel, name)
}

/// Downloads a sysroot image artifact or rejects direct boot selection installation.
///
/// Image publication, selection, and restart require the checked rollout
/// controller and its selected platform abilities.
///
/// # Errors
///
/// Returns an error when the package cannot be resolved, is not a sysroot
/// package, image admission or staging fails, a required platform operation is
/// unavailable, or the native image-selection transaction fails.
#[allow(clippy::too_many_arguments)]
pub async fn install_system(
    config: &ApmConfig,
    packages: &[String],
    registry_filter: Option<&str>,
    image_format: Option<&str>,
    image_output: Option<&str>,
    dry_run: bool,
    yes: bool,
    transition_mode: SystemTransitionMode,
    drain: bool,
    printer: &Printer,
) -> Result<()> {
    if packages.len() != 1 {
        bail!("--system install requires exactly one package name");
    }
    let package_name = &packages[0];
    let (registries, closure) =
        image_prepare::resolve_candidate(config, package_name, registry_filter)?;
    let package = closure
        .closure
        .iter()
        .find(|metadata| metadata.name == *package_name)
        .ok_or_else(|| anyhow::anyhow!("resolved closure missing requested sysroot package"))?;

    ensure!(
        package.sysroot,
        "package '{package_name}' is not a sysroot package (missing sysroot = true)"
    );

    if let Some(format) = image_format {
        return download_image(config, package, format, image_output, dry_run, printer).await;
    }

    image_rollout::preflight_image_selection(config, transition_mode, drain)?;
    printer.info(&format!(
        "Stage system image {} {}",
        package.name, package.version
    ));
    if dry_run {
        printer.info("Dry run -- image staging and selection have not run.");
        return Ok(());
    }
    if !yes && !config.settings.assume_yes {
        crate::install::confirm(printer)?;
    }

    let epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let created_at = crate::install::chrono_iso8601(epoch.as_secs().try_into()?);
    let cancellation = crate::AbilityCancellationGuard::install()?;
    let candidate = image_stage::stage_candidate(
        config,
        &registries,
        &closure,
        &created_at,
        image_rollout::is_qualified_image_rollout(transition_mode, drain),
        cancellation.token(),
        printer,
    )
    .await?;
    image_rollout::submit_image_selection(config, &candidate, transition_mode, drain, printer)
}

/// Checks for a different sysroot version and stages its image.
///
/// Looks up the current generation's package in the configured registries;
/// when a different sysroot version is published, delegates to
/// [`install_system`], which stages the authenticated candidate and submits
/// native image selection through the current host's platform handlers.
///
/// # Errors
///
/// Returns an error when the running image generation cannot be authenticated,
/// registries cannot be loaded, or the delegated [`install_system`] call fails.
pub async fn upgrade_system(
    config: &ApmConfig,
    dry_run: bool,
    transition_mode: SystemTransitionMode,
    drain: bool,
    printer: &Printer,
) -> Result<()> {
    let current_gen = running_image_generation()?;

    printer.info(&format!(
        "Current sysroot: {} {} (generation {})",
        current_gen.package_name, current_gen.version, current_gen.number,
    ));

    // Load registries and check for newer version.
    let registries = load_registries(config)?;
    let mut newer_meta: Option<(PackageMeta, String)> = None;
    for reg in registries.registries() {
        if let Some(meta) = reg.packages.get(&current_gen.package_name) {
            // A rebuild can publish different immutable content at the same
            // version. The selected toplevel, not its display version, decides
            // whether the running image is current.
            if meta.sysroot && meta.store_path != current_gen.toplevel {
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
        transition_mode,
        drain,
        printer,
    )
    .await
}

/// Rolls back a configuration generation on the running image.
///
/// Lists retained native generations or reconciles a selected generation as
/// a new transaction. Exact retained artifacts and source inputs are admitted
/// before execution. Use [`rollback_image_generation`] for the image axis.
///
/// # Errors
/// Returns an error when the target or authenticated inputs are unavailable,
/// journal recovery is pending, or native reconciliation fails.
pub async fn rollback_system(
    _config: &ApmConfig,
    generation: Option<u32>,
    list: bool,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    let profile = crate::profile::Profile::open(ProfileScope::System)?;
    let generations = profile.list_generations()?;
    let current = profile.current_generation()?;
    if list {
        let reports = generations
            .iter()
            .map(|target| activatability::configuration(&profile, target))
            .collect::<Vec<_>>();
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::to_value(&reports)?);
        } else {
            for (target, report) in generations.iter().zip(&reports) {
                let marker = if current
                    .as_ref()
                    .is_some_and(|value| value.number == target.number)
                {
                    " (current)"
                } else {
                    ""
                };
                printer.plain(&format!(
                    "  gen-{}{} {}",
                    target.number,
                    marker,
                    activatability_label(report)
                ));
            }
        }
        return Ok(());
    }
    let current = current.context("no active system generation")?;
    let target = match generation {
        Some(number) => generations.iter().find(|target| target.number == number),
        None => generations
            .iter()
            .filter(|target| target.number < current.number)
            .max_by_key(|target| target.number),
    }
    .context("requested retained system generation is unavailable")?;
    let report = activatability::configuration(&profile, target);
    print_activatability(&report, printer)?;
    report.require_activatable()?;
    if dry_run {
        printer.info("Dry run -- retained inputs verified; no changes made.");
        return Ok(());
    }
    let activated = crate::install::native::rollback(&profile, target, printer)?;
    printer.success(&format!(
        "Reconciled retained generation {} as native generation {}.",
        target.number, activated.number
    ));
    Ok(())
}

fn activatability_label(report: &RetainedActivatabilityReport) -> String {
    if report.is_activatable() {
        return "[activatable]".to_string();
    }
    let codes = report
        .reasons()
        .iter()
        .map(|reason| format!("{:?}", reason.code))
        .collect::<Vec<_>>()
        .join(",");
    format!("[blocked: {codes}]")
}

fn print_activatability(report: &RetainedActivatabilityReport, printer: &Printer) -> Result<()> {
    if printer.mode() == OutputMode::Json {
        let bytes = report.canonical_bytes()?;
        printer.raw(std::str::from_utf8(&bytes)?);
    } else if report.is_activatable() {
        printer.info("Retained target is currently activatable.");
    } else {
        for reason in report.reasons() {
            printer.warning(&format!("{:?}: {}", reason.code, reason.detail));
        }
    }
    Ok(())
}

/// Lists or selects a retained image through the native platform abilities.
///
/// # Errors
/// Returns an error for an unavailable retained image, incompatible native
/// state, missing platform handlers, or a failed image-selection transaction.
pub async fn rollback_image_generation(
    config: &ApmConfig,
    generation: Option<u32>,
    list: bool,
    dry_run: bool,
    transition_mode: SystemTransitionMode,
    drain: bool,
    printer: &Printer,
) -> Result<()> {
    let profile = Path::new(IMAGE_PROFILE_DIR);
    let state = load_image_generation_state_pub(profile)?;
    if list {
        let system_profile = ProfileScope::System.profile_path();
        let reports = state
            .generations
            .iter()
            .map(|generation| {
                activatability::image(profile, &system_profile, generation, transition_mode, drain)
            })
            .collect::<Vec<_>>();
        if printer.mode() == OutputMode::Json {
            let bytes = aos_contract::canonical::to_vec(&reports)?;
            printer.raw(std::str::from_utf8(&bytes)?);
            return Ok(());
        }
        for (image, report) in state.generations.iter().zip(&reports) {
            let running = if image.number == state.running {
                " (running)"
            } else {
                ""
            };
            printer.plain(&format!(
                "  image-gen-{}: {} {} [{}]{} {}",
                image.number,
                image.package_name,
                image.version,
                image.boot_artifact_contract,
                running,
                activatability_label(report),
            ));
        }
        return Ok(());
    }
    let candidate = match generation {
        Some(number) => state
            .generations
            .iter()
            .find(|image| image.number == number),
        None => state
            .generations
            .iter()
            .filter(|image| image.number < state.running)
            .max_by_key(|image| image.number),
    }
    .context("no matching retained image generation")?;
    ensure!(
        candidate.number != state.running,
        "selected image is already running"
    );
    image_rollout::preflight_image_selection(config, transition_mode, drain)?;
    let system_profile = ProfileScope::System.profile_path();
    activatability::image(profile, &system_profile, candidate, transition_mode, drain)
        .require_activatable()?;
    if dry_run {
        printer.info(&format!(
            "Would select image generation {} ({} {}).",
            candidate.number, candidate.package_name, candidate.version
        ));
        return Ok(());
    }
    image_rollout::submit_image_selection(config, candidate, transition_mode, drain, printer)
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
    let current = match running_image_generation() {
        Ok(image) => image,
        Err(_) => return None,
    };

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

/// Ensures an authenticated image artifact is present in the local store.
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
    crate::verify::verify_nar_hash_with_compression(
        &result.local_path,
        &img.nar_hash,
        &result.compression,
    )
    .with_context(|| format!("verifying image NAR for {}", img.store_path))?;
    crate::store::import_nar_with_compression(
        &result.local_path,
        &result.store_path,
        &result.references,
        result.deriver.as_deref(),
        &result.compression,
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

fn remove_file_durable(path: &Path) -> Result<()> {
    let parent = path.parent().context("durable file path has no parent")?;
    match std::fs::remove_file(path) {
        Ok(()) => sync_directory(parent),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

fn write_atomic_durable(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} has no UTF-8 file name", path.display()))?;
    let temp = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)
        .with_context(|| format!("opening {}", temp.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", temp.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", temp.display()))?;
    std::fs::rename(&temp, path).with_context(|| format!("publishing {}", path.display()))?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<()> {
    let directory = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("opening directory {} for sync", path.display()))?;
    directory
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

fn load_registries(config: &ApmConfig) -> Result<RegistrySet> {
    let reg_configs = config.enabled_registries();
    RegistrySet::load_for_package_operations(&config.cache_path(), &reg_configs, &native_platform())
}

fn resolve_image_mirror(config: &ApmConfig, _meta: &PackageMeta) -> Vec<String> {
    // Use the first configured registry's mirror chain.
    if let Some((cfg, _)) = config.registries.first() {
        return resolve_mirror_chain(&config.scope.registries_path(), cfg);
    }
    vec!["https://cache.aos.dev".to_string()]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BootProviderState;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn boot_provider_state() -> BootProviderState {
        BootProviderState {
            schema: "aos.test.boot-generation-state/v1".into(),
            evidence: serde_json::json!({"provider-identity": "test-entry-1"}),
        }
    }

    fn running_identity_fixture() -> (TempDir, PathBuf, PathBuf, PathBuf) {
        let temp = TempDir::new().unwrap();
        let image_profile = temp.path().join("image");
        let immutable_root = temp.path().join("sysroot");
        let logical_toplevel =
            PathBuf::from(format!("/nix/store/{}-running-toplevel", "0".repeat(32)));
        let toplevel = immutable_root.join(logical_toplevel.strip_prefix("/").unwrap());
        let toplevel_link = immutable_root.join("usr/lib/aos/toplevel");
        std::fs::create_dir_all(toplevel_link.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&image_profile).unwrap();
        std::fs::create_dir_all(toplevel.join("meta")).unwrap();
        let image = ImageGeneration {
            number: 1,
            boot_artifact_contract: format!("/nix/store/{}-boot-contract", "3".repeat(32)),
            boot_provider_state: boot_provider_state(),
            toplevel: logical_toplevel.to_string_lossy().into_owned(),
            package_name: "server".into(),
            version: "1".into(),
            state_version: "1".into(),
            native_executor_ref: format!("/nix/store/{}-executor", "4".repeat(32)),
            registry: "test".into(),
            kernel_path: None,
            module_library: crate::types::ModuleLibraryIdentity {
                store_path: format!("/nix/store/{}-library", "1".repeat(32)),
                nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                nar_size: 1,
            },
            evaluation_descriptor: format!(
                "/nix/store/{}-evaluation/evaluation.json",
                "2".repeat(32)
            ),
            created_at: "2026-08-04T00:00:00Z".into(),
        };
        for (name, value) in [
            (
                "module-library.json",
                serde_json::to_string(&image.module_library).unwrap(),
            ),
            ("evaluation-descriptor", image.evaluation_descriptor.clone()),
            ("package-name", image.package_name.clone()),
            ("version", image.version.clone()),
            ("state-version", image.state_version.clone()),
            ("native-executor-ref", image.native_executor_ref.clone()),
        ] {
            std::fs::write(toplevel.join("meta").join(name), value).unwrap();
        }
        std::os::unix::fs::symlink(&logical_toplevel, &toplevel_link).unwrap();
        let state = ImageGenerationState {
            schema: "aos.image-generation-state/v1".into(),
            running: 1,
            pending: Some(1),
            boot_provider_state: boot_provider_state(),
            active_rollout: None,
            last_rollout: None,
            generations: vec![image],
        };
        std::fs::write(
            image_profile.join("state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        (temp, image_profile, immutable_root, toplevel_link)
    }

    fn load_running_image_generation_fixture(
        image_profile: &Path,
        immutable_root: &Path,
        toplevel_link: &Path,
    ) -> Result<ImageGeneration> {
        load_running_image_generation_with_device_identity(
            image_profile,
            toplevel_link,
            immutable_root,
        )
    }

    #[test]
    fn running_image_reads_native_identity_under_mounted_root() {
        let (_temp, profile, root, link) = running_identity_fixture();

        let image = load_running_image_generation_fixture(&profile, &root, &link).unwrap();

        assert_eq!(image.package_name, "server");
        assert_eq!(image.module_library.nar_size, 1);
        assert!(image.evaluation_descriptor.ends_with("/evaluation.json"));
    }

    #[test]
    fn running_image_rejects_metadata_symlink_escape() {
        let (temp, profile, root, link) = running_identity_fixture();
        let logical = std::fs::read_link(&link).unwrap();
        let toplevel = root.join(logical.strip_prefix("/").unwrap());
        let outside = temp.path().join("outside-version");
        std::fs::write(&outside, "1").unwrap();
        std::fs::remove_file(toplevel.join("meta/version")).unwrap();
        std::os::unix::fs::symlink(&outside, toplevel.join("meta/version")).unwrap();

        assert!(load_running_image_generation_fixture(&profile, &root, &link).is_err());
    }

    #[test]
    fn running_image_rejects_metadata_parent_symlink_escape() {
        let (temp, profile, root, link) = running_identity_fixture();
        let logical = std::fs::read_link(&link).unwrap();
        let toplevel = root.join(logical.strip_prefix("/").unwrap());
        let outside = temp.path().join("outside-meta");
        std::fs::rename(toplevel.join("meta"), &outside).unwrap();
        std::os::unix::fs::symlink(&outside, toplevel.join("meta")).unwrap();

        assert!(load_running_image_generation_fixture(&profile, &root, &link).is_err());
    }

    #[test]
    fn running_image_rejects_tampered_var_index_metadata() {
        let (_tmp, image_profile, immutable_root, toplevel_link) = running_identity_fixture();
        let loaded =
            load_running_image_generation_fixture(&image_profile, &immutable_root, &toplevel_link)
                .unwrap();
        assert_eq!(loaded.module_library.nar_size, 1);

        let state_path = image_profile.join("state.json");
        let mut state: ImageGenerationState =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        state.generations[0].package_name = "attacker".into();
        std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        let error =
            load_running_image_generation_fixture(&image_profile, &immutable_root, &toplevel_link)
                .unwrap_err();
        assert!(error.to_string().contains("immutable toplevel metadata"));
    }

    #[test]
    fn format_size_values() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(2048), "2.0 KiB");
        assert_eq!(format_size(3_300_000), "3.1 MiB");
        assert_eq!(format_size(2_147_483_648), "2.0 GiB");
    }
    #[test]
    fn system_transition_mode_default() {
        let mode = SystemTransitionMode::default();
        assert_eq!(mode, SystemTransitionMode::Advisory);
    }
}
