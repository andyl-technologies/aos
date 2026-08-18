//! System sysroot management (`apm install --system`, `apm upgrade --system`,
//! `apm rollback --system`).
//!
//! A sysroot package is a regular package with `sysroot = true` whose metadata
//! names both a system toplevel and an authenticated raw OTA payload. Installing
//! it stages a numbered image generation under `/var/lib/profiles/image/` in
//! the inactive A/B slot. Configuration generations remain independent under
//! `/var/lib/profiles/system/` (see [`ConfigGenerationState`]).
//!
//! # Install / upgrade / rollback flow
//!
//! [`install_system`] resolves and verifies the package, imports its closure and
//! image payload, writes the inactive root/hash partitions, publishes the UKI,
//! and selects it as the counted next boot. [`upgrade_system`] checks registries
//! for a different sysroot version and delegates to [`install_system`]. After
//! reboot, the boot services evaluate and activate a configuration bound to the
//! image that actually booted. [`rollback_image_generation`] selects another
//! A/B image for the next boot, while [`rollback_system`] rolls back only the
//! configuration axis on the running image.
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
//! # Image transition modes
//!
//! [`KernelUpgradeMode`] controls what happens after staging: `Advisory`
//! (default) and `Live` leave the transition pending and advise a reboot,
//! `Reboot` drains when requested and queues a full reboot, and `Kexec` is
//! rejected because it cannot change the immutable root slot.

use std::collections::{BTreeSet, HashSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

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
use crate::types::{
    ConfigGeneration, ConfigGenerationState, CrossAbiReEvalInputs, ImageGeneration,
    ImageGenerationState, ImageSlot, PackageMeta, ProfileScope, ReactivationPlan,
    RecoveryPublication, RecoveryUkiEntry, SysrootImageEntry, SysrootUkiEntry, UkiSlot,
};
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
const SYSTEM_COMMIT_JOURNAL: &str = ".state-commit.json";
const ACTIVATION_INTENT: &str = ".activation-intent.json";
const IMAGE_STATE_FILE: &str = "state.json";
const IMAGE_TRANSITION_INTENT: &str = ".transition-intent.json";
const IMAGE_PROFILE_DIR: &str = "/var/lib/profiles/image";
const NIX_OVERLAY_UPPER_STORE: &str = "/var/lib/nix-overlay/upper/store";
const BOOT_ROOT: &str = "/boot";
const ROOT_A_DEVICE: &str = "/dev/disk/by-partlabel/root-a";
const ROOT_B_DEVICE: &str = "/dev/disk/by-partlabel/root-b";
const ROOT_A_HASH_DEVICE: &str = "/dev/disk/by-partlabel/root-a-hash";
const ROOT_B_HASH_DEVICE: &str = "/dev/disk/by-partlabel/root-b-hash";
const RUNNING_TOPLEVEL_LINK: &str = "/aos-toplevel";
const RUNNING_OS_RELEASE: &str = "/aos-toplevel/os-release";
const RUNNING_CMDLINE: &str = "/proc/cmdline";
const IMMUTABLE_SECURE_BOOT_DB: &str = "/aos-toplevel/etc-basedir/aos/trust/secure-boot-db.crt";
const SUPPORTED_RECOVERY_ABI: u32 = 1;

/// Recoverable intent record for publishing a generation as current.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct GenerationCommitJournal {
    generation: u32,
    state: ConfigGenerationState,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ActivationIntent {
    generation: u32,
    nonce: String,
    state: ConfigGenerationState,
}

/// Retired bundled generation schema, accepted only by one-shot migration.
#[derive(Debug, serde::Deserialize)]
struct LegacySystemGeneration {
    number: u32,
    toplevel: String,
    created_at: String,
    image_gen_parent: Option<u32>,
    module_abi_pinned: Option<u32>,
    manifest_hash: Option<String>,
    config_module_closure: Option<String>,
    config_module_paths: Option<Vec<String>>,
    config_module_packages: Option<Vec<String>>,
    host_nix_ref: Option<String>,
    host_nix_commit: Option<String>,
    facts_hash: Option<String>,
    facts_ref: Option<String>,
    base_lib_ref: Option<String>,
    evaluator_ref: Option<String>,
}

/// Retired system-profile state, never written by current code.
#[derive(Debug, serde::Deserialize)]
struct LegacySystemGenerationState {
    current: u32,
    next: u32,
    generations: Vec<LegacySystemGeneration>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ImageTransitionIntent {
    target: u32,
    prior_default: u32,
    entry_id: String,
}

/// Filesystem locations used by the offline A/B writer.
struct ImageSlotLayout<'a> {
    boot_root: &'a Path,
    root_a: &'a Path,
    root_b: &'a Path,
    root_a_hash: &'a Path,
    root_b_hash: &'a Path,
}

impl Default for ImageSlotLayout<'static> {
    fn default() -> Self {
        Self {
            boot_root: Path::new(BOOT_ROOT),
            root_a: Path::new(ROOT_A_DEVICE),
            root_b: Path::new(ROOT_B_DEVICE),
            root_a_hash: Path::new(ROOT_A_HASH_DEVICE),
            root_b_hash: Path::new(ROOT_B_HASH_DEVICE),
        }
    }
}

/// Resolves the booted image generation from immutable image identity.
///
/// The `/var` image index is accepted only after its running record agrees
/// with the baked `/aos-toplevel` pointer and metadata, the measured
/// `AOS_MODULE_ABI` and `AOS_BASELIB_DIGEST` fields from the running image's
/// `os-release`, and the root slot/verity hash in `/proc/cmdline`.
/// Config-generation state is deliberately not consulted. The initrd seed
/// service separately compares the early-boot PCR-11 value because PCR-11 has
/// advanced beyond that phase by the time this stage-2 path runs.
///
/// # Errors
///
/// Returns an error if any identity input is absent, malformed, or disagrees.
pub(crate) fn running_image_generation() -> Result<ImageGeneration> {
    load_running_image_generation_from(
        Path::new(IMAGE_PROFILE_DIR),
        Path::new(RUNNING_OS_RELEASE),
        Path::new(RUNNING_TOPLEVEL_LINK),
        Path::new(RUNNING_CMDLINE),
    )
}

pub(crate) fn load_image_generation_state_pub(profile: &Path) -> Result<ImageGenerationState> {
    let path = profile.join(IMAGE_STATE_FILE);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading image generation state {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing image generation state {}", path.display()))
}

fn load_running_image_generation_from(
    image_profile: &Path,
    os_release: &Path,
    toplevel_link: &Path,
    cmdline: &Path,
) -> Result<ImageGeneration> {
    let state_path = image_profile.join(IMAGE_STATE_FILE);
    let state_bytes = std::fs::read(&state_path)
        .with_context(|| format!("reading image generation state {}", state_path.display()))?;
    let state: ImageGenerationState = serde_json::from_slice(&state_bytes)
        .with_context(|| format!("parsing image generation state {}", state_path.display()))?;
    let running = state.running_generation().cloned().with_context(|| {
        format!(
            "image generation state names missing running generation {}",
            state.running
        )
    })?;
    let baked_toplevel = std::fs::read_link(toplevel_link)
        .with_context(|| format!("reading running image pointer {}", toplevel_link.display()))?;
    if baked_toplevel != Path::new(&running.toplevel) {
        bail!(
            "running image pointer {} disagrees with image generation {} toplevel {}",
            baked_toplevel.display(),
            running.number,
            running.toplevel
        );
    }
    let baked_base_lib = std::fs::read_link(toplevel_link.join("base-lib")).with_context(|| {
        format!(
            "reading immutable running base-library pointer {}/base-lib",
            toplevel_link.display()
        )
    })?;
    if baked_base_lib != Path::new(&running.evaluator_ref) {
        bail!(
            "running image base library {} disagrees with image generation {} evaluator_ref {}",
            baked_base_lib.display(),
            running.number,
            running.evaluator_ref
        );
    }
    let immutable_abi = read_toplevel_meta(toplevel_link, "module-abi")?
        .parse::<u32>()
        .context("immutable toplevel has invalid module ABI")?;
    let immutable_digest = read_toplevel_meta(toplevel_link, "baselib-digest")?;
    let immutable_uki = read_toplevel_meta(toplevel_link, "uki-path")?;
    let immutable_package = read_toplevel_meta(toplevel_link, "package-name")?;
    let immutable_version = read_toplevel_meta(toplevel_link, "version")?;
    let recorded_uki = running
        .uki_source_path
        .as_deref()
        .unwrap_or(&running.uki_path);
    if immutable_abi != running.module_abi
        || immutable_digest != running.baselib_digest
        || immutable_uki != recorded_uki
        || immutable_package != running.package_name
        || immutable_version != running.version
    {
        bail!(
            "running immutable toplevel metadata disagrees with image generation {}",
            running.number
        );
    }
    let fields = parse_os_release(os_release)?;
    let abi = fields
        .get("AOS_MODULE_ABI")
        .context("running os-release has no AOS_MODULE_ABI")?
        .parse::<u32>()
        .context("running os-release has invalid AOS_MODULE_ABI")?;
    let digest = fields
        .get("AOS_BASELIB_DIGEST")
        .context("running os-release has no AOS_BASELIB_DIGEST")?;
    if abi != running.module_abi || digest != &running.baselib_digest {
        bail!("running image identity disagrees with image state (abi {abi}, digest {digest})");
    }
    let cmdline_fields = parse_kernel_cmdline(cmdline)?;
    let root_hash = cmdline_fields.get("roothash").cloned();
    if root_hash != running.root_verity_roothash {
        bail!(
            "running kernel roothash disagrees with image generation {}",
            running.number
        );
    }
    if let Some(root) = cmdline_fields
        .get("systemd.verity_root_data")
        .or_else(|| cmdline_fields.get("root"))
    {
        let booted_slot = match root.as_str() {
            ROOT_A_DEVICE => Some(ImageSlot::A),
            ROOT_B_DEVICE => Some(ImageSlot::B),
            _ => None,
        };
        if booted_slot.is_some() && booted_slot != Some(running.slot) {
            bail!(
                "running root slot disagrees with image generation {}",
                running.number
            );
        }
    }
    Ok(running)
}

fn parse_kernel_cmdline(path: &Path) -> Result<std::collections::BTreeMap<String, String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading kernel command line {}", path.display()))?;
    let mut fields = std::collections::BTreeMap::new();
    for word in text.split_ascii_whitespace() {
        let Some((key, value)) = word.split_once('=') else {
            continue;
        };
        // Linux permits repeatable parameters such as `console=` and AOS
        // deliberately configures both a serial and a virtual console. Only
        // the image-identity fields consumed below must be unambiguous.
        if !matches!(key, "roothash" | "root" | "systemd.verity_root_data") {
            continue;
        }
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            bail!("kernel command line repeats {key}");
        }
    }
    Ok(fields)
}

fn parse_os_release(path: &Path) -> Result<std::collections::BTreeMap<String, String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading running image identity {}", path.display()))?;
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let value = raw
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(raw);
        fields.insert(key.to_string(), value.to_string());
    }
    Ok(fields)
}
// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Installs a sysroot package as a pending A/B image generation.
///
/// When `--image <FMT>` is specified, downloads the pre-compiled image instead
/// of the toplevel closure.
///
/// Otherwise resolves and verifies the package, imports its closure and raw OTA
/// payload, writes the inactive root/hash slot, publishes its UKI, and records
/// the image as the durable counted next boot. It does not mutate the live
/// configuration generation. In `Reboot` mode a successful staging operation
/// requests a reboot and does not return; `Kexec` is rejected.
///
/// # Errors
///
/// Returns an error when:
///
/// - `packages` does not contain exactly one name, the package cannot be
///   resolved, or it is not marked `sysroot = true`;
/// - downloading, hash verification, or store import of a closure path fails;
/// - the package lacks an authenticated raw OTA payload or its Secure Boot,
///   root-hash, UKI, slot, or measurement metadata fails validation;
/// - image state, the inactive slot, or the boot-loader default cannot be
///   updated durably;
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

    // Image generations are never activated into the running root. When the
    // two-axis image state exists, import the authenticated OTA
    // payload, write only the inactive root/hash slot, publish its counted UKI
    // last, and let the loader's AOS entry pattern select it. Leaving no exact
    // persistent override is essential: sd-boot can then sort an exhausted
    // counted entry behind the known-good slot. First-boot evaluation under
    // the new image creates the config generation after reboot.
    let image_profile = Path::new(IMAGE_PROFILE_DIR);
    // Non-A/B upgrades do not enter the image-staging branch below. Validate
    // their recorded Secure Boot facts before creating a generation or
    // touching the boot path. A/B upgrades perform the same validation after
    // importing their separately authenticated image artifact, because slot
    // UKIs live in that artifact rather than the toplevel closure.
    if !image_profile.join(IMAGE_STATE_FILE).is_file() {
        validate_sysroot_secure_boot(config, toplevel_meta, &closure.registry_name, printer)?;
    }
    if image_profile.join(IMAGE_STATE_FILE).is_file() {
        if kernel_mode == KernelUpgradeMode::Kexec {
            bail!(
                "A/B image upgrades cannot use kexec because the inactive root slot must become the next boot root; use --reboot or the default advisory mode"
            );
        }
        let image = toplevel_meta
            .images
            .iter()
            .find(|image| image.format == "raw")
            .or_else(|| {
                toplevel_meta
                    .images
                    .iter()
                    .find(|image| image.root_image.is_some())
            })
            .context(
                "sysroot package has no authenticated raw OTA image carrying root.img and slot UKIs",
            )?;
        printer.step(7, 8, "Importing inactive-slot image payload...");
        let image_store = ensure_image_imported(config, toplevel_meta, image, printer).await?;
        validate_sysroot_secure_boot(config, toplevel_meta, &closure.registry_name, printer)?;

        let switch_lock =
            crate::config_eval::activation::ActivateConfigParams::default().switch_lock;
        let _switch_guard = crate::config_eval::activation::acquire_switch_lock_pub(&switch_lock)?;
        printer.step(8, 8, "Staging inactive A/B image slot...");
        let staged = with_writable_boot(|| {
            stage_pending_image_generation_with(
                image_profile,
                &ProfileScope::System.profile_path(),
                Path::new(NIX_OVERLAY_UPPER_STORE),
                &ImageSlotLayout::default(),
                toplevel_meta,
                &closure.registry_name,
                image,
                &image_store,
                |_entry| {
                    let status = std::process::Command::new("bootctl")
                        .arg("set-default")
                        .arg("")
                        .status()
                        .context("clearing the exact boot default for staged image")?;
                    if !status.success() {
                        bail!("clearing the exact boot default failed with {status}");
                    }
                    Ok(())
                },
            )
        })?;
        printer.success(&format!(
            "Image generation {} staged in slot {:?}; configuration remains unchanged until reboot.",
            staged.number, staged.slot
        ));
        match kernel_mode {
            KernelUpgradeMode::Reboot => {
                if drain {
                    drain_workloads(&staged.toplevel, printer).await?;
                }
                SystemdClient::connect().await?.reboot().await?;
            }
            KernelUpgradeMode::Advisory | KernelUpgradeMode::Live => {
                printer.plain(
                    "  Reboot to assess the counted image and re-evaluate host configuration.",
                );
            }
            KernelUpgradeMode::Kexec => unreachable!("kexec rejected before staging"),
        }
        return Ok(());
    }
    bail!(
        "image generation state is absent; refusing to recreate the retired single-axis system-generation authority"
    )
}

fn reeval_and_activate_config_generation(
    config: &ApmConfig,
    profile_path: &Path,
    target: &ConfigGeneration,
    inputs: &crate::types::CrossAbiReEvalInputs,
    running_base_lib: &Path,
    running_abi: u32,
) -> Result<u32> {
    let source_manifest = validate_generation_manifest(profile_path, target)?;
    let eval_root = PathBuf::from(format!(
        "/run/aos/rollback-eval-{}-{}",
        target.number,
        std::process::id()
    ));
    let manifest = eval_root.join("manifest.json");
    crate::config_eval::reeval_cross_abi(
        inputs,
        running_base_lib,
        &source_manifest,
        eval_root.clone(),
        manifest.clone(),
        0,
    )?;
    let graph = eval_root.join("graph.json");
    let marker_root = eval_root.join("markers");
    stage_retained_runtime(config, &manifest, &marker_root)?;
    crate::config_eval::activation::activate_config(
        &crate::config_eval::activation::ActivateConfigParams {
            manifest,
            graph,
            marker_root,
            profile: profile_path.to_path_buf(),
            module_abi: running_abi,
            switch_lock_held: true,
            ..crate::config_eval::activation::ActivateConfigParams::default()
        },
    )
}

/// Re-evaluates the active configuration against the image that actually booted.
///
/// Image transitions retain the exact host input, facts, config modules, and
/// authenticated package pins from the active configuration generation. This
/// function evaluates those immutable inputs with the running image's base
/// library and writes a candidate manifest and graph for the normal boot-time
/// fetch, compile, and activation pipeline.
///
/// # Errors
///
/// Returns an error when there is no active configuration generation, the
/// running image identity is inconsistent, a retained input is unavailable or
/// incompatible with the running module ABI, or evaluation fails.
pub fn reeval_active_config_for_boot(
    profile_path: &Path,
    eval_root: PathBuf,
    out: PathBuf,
    verbose: u8,
) -> Result<()> {
    let state = load_generation_state_readonly(profile_path)?;
    let active = state
        .generations
        .iter()
        .find(|generation| generation.number == state.current)
        .context("no active system configuration generation")?;
    if active.config_module_paths.len() != active.config_module_packages.len() {
        bail!(
            "config-gen {} has {} retained modules but {} authenticated package identities",
            active.number,
            active.config_module_paths.len(),
            active.config_module_packages.len()
        );
    }

    let running = running_image_generation()?;
    let retained = CrossAbiReEvalInputs {
        config_module_paths: active.config_module_paths.clone(),
        config_module_packages: active.config_module_packages.clone(),
        host_nix_ref: active.host_nix_ref.clone(),
        facts_hash: active.facts_hash.clone(),
        facts_ref: active.facts_ref.clone(),
        from_module_abi: active.module_abi_pinned,
        to_module_abi: running.module_abi,
    };
    let source_manifest = validate_generation_manifest(profile_path, active)?;
    crate::config_eval::reeval_cross_abi(
        &retained,
        Path::new(&running.evaluator_ref),
        &source_manifest,
        eval_root,
        out,
        verbose,
    )
}

fn stage_retained_runtime(
    config: &ApmConfig,
    manifest_path: &Path,
    marker_root: &Path,
) -> Result<()> {
    let bytes = std::fs::read(manifest_path)
        .with_context(|| format!("reading rollback manifest {}", manifest_path.display()))?;
    let manifest: crate::config_eval::materialize::ConfigManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing rollback manifest {}", manifest_path.display()))?;
    for path in manifest
        .store_paths
        .iter()
        .chain(manifest.package_outputs.values().flat_map(|package| {
            package
                .closure
                .iter()
                .filter_map(|member| member.store_path.as_ref())
        }))
    {
        if !path.starts_with("/nix/store/") || !Path::new(path).exists() {
            bail!(
                "retained runtime closure path is unavailable: {path}; cross-ABI rollback refused"
            );
        }
    }
    let mut transaction = crate::graph_compile::graph_transaction(&manifest)?;
    transaction.completed = true;
    std::fs::create_dir_all(marker_root)
        .with_context(|| format!("creating rollback marker root {}", marker_root.display()))?;
    std::fs::write(
        crate::graph_compile::transaction_state_path(marker_root),
        serde_json::to_vec(&transaction)?,
    )?;
    for (package, pin) in &transaction.packages {
        let marker = format!("{} {pin}\n", transaction.manifest);
        let fetch = marker_root.join("fetch");
        std::fs::create_dir_all(&fetch)?;
        std::fs::write(fetch.join(format!("{package}.ok")), &marker)?;
        crate::graph_compile::subverbs::stage_retained_package(
            config,
            package,
            manifest_path,
            marker_root,
            &marker_root.join("staging"),
        )?;
    }
    Ok(())
}

/// Validates a retained generation manifest against its recorded content hash.
///
/// # Errors
///
/// Returns an error when the manifest is unreadable, structurally invalid, or
/// does not match the generation record's authenticated hash.
pub(crate) fn validate_generation_manifest(
    profile_path: &Path,
    generation: &ConfigGeneration,
) -> Result<PathBuf> {
    let path = profile_path
        .join(format!("gen-{}", generation.number))
        .join("manifest.json");
    let expected = generation.manifest_hash.as_str();
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading retained manifest {}", path.display()))?;
    let manifest: crate::config_eval::materialize::ConfigManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing retained manifest {}", path.display()))?;
    manifest.validate()?;
    let value = serde_json::to_value(&manifest)?;
    let actual = crate::graph_compile::reproject::hash_cjson(&value);
    if actual != expected {
        bail!(
            "config generation {} manifest hash mismatch: recorded {expected}, actual {actual}",
            generation.number
        );
    }
    Ok(path)
}

/// Authenticates and returns the manifest owned by the active configuration.
///
/// The generation index and `current` symlink must name the same generation,
/// and the retained manifest must hash to that generation's recorded identity.
///
/// # Errors
///
/// Returns an error when generation state, the current pointer, or the retained
/// manifest is missing, malformed, inconsistent, or tampered.
pub(crate) fn authenticated_current_generation_manifest(
    profile_path: &Path,
) -> Result<Option<PathBuf>> {
    let state = load_generation_state_readonly(profile_path)?;
    if state.current == 0 {
        return Ok(None);
    }
    let generation = state
        .generations
        .iter()
        .find(|generation| generation.number == state.current)
        .with_context(|| {
            format!(
                "system generation state names missing current generation {}",
                state.current
            )
        })?;
    let expected_link = PathBuf::from(format!("gen-{}", generation.number));
    let actual_link = std::fs::read_link(profile_path.join("current")).with_context(|| {
        format!(
            "reading current generation pointer in {}",
            profile_path.display()
        )
    })?;
    if actual_link != expected_link {
        bail!(
            "current generation pointer names {}, but state records generation {}",
            actual_link.display(),
            generation.number
        );
    }
    validate_generation_manifest(profile_path, generation).map(Some)
}

fn validate_direct_reactivation(
    target: &ConfigGeneration,
    running: &ImageGeneration,
    manifest_path: &Path,
) -> Result<()> {
    if target.module_abi_pinned != running.module_abi {
        bail!(
            "configuration generation {} is not ABI-compatible with running image generation {}",
            target.number,
            running.number
        );
    }
    let manifest: crate::config_eval::materialize::ConfigManifest =
        serde_json::from_slice(&std::fs::read(manifest_path)?)?;
    if manifest.module_abi != running.module_abi
        || target.base_lib_ref != manifest.inputs.base_lib.store_path
    {
        bail!(
            "configuration generation {} manifest does not match its recorded ABI/base-library binding",
            target.number
        );
    }
    Ok(())
}

fn load_reactivation_record(
    profile_path: &Path,
    target: &ConfigGeneration,
    generation_id: &str,
) -> Result<serde_json::Value> {
    let path = profile_path
        .join(format!("gen-{}", target.number))
        .join("activation.json");
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&path)
            .with_context(|| format!("reading retained activation record {}", path.display()))?,
    )
    .with_context(|| format!("parsing retained activation record {}", path.display()))?;
    if record.get("schema").and_then(serde_json::Value::as_str) != Some("aos.config-activation/v1")
        || record.get("generation").and_then(serde_json::Value::as_u64)
            != Some(u64::from(target.number))
        || record
            .get("generation_id")
            .and_then(serde_json::Value::as_str)
            != Some(generation_id)
        || record
            .get("transaction_manifest")
            .and_then(serde_json::Value::as_str)
            .is_none()
    {
        bail!(
            "retained activation record for configuration generation {} does not authenticate its generation and graph transaction",
            target.number
        );
    }
    Ok(record)
}

fn publish_reactivation_record(
    profile_path: &Path,
    retained: &serde_json::Value,
    activation_exit: i32,
) -> Result<()> {
    let mut record = retained.clone();
    let object = record
        .as_object_mut()
        .context("retained activation record is not an object")?;
    object.insert("activation_exit".to_string(), activation_exit.into());
    object.insert(
        "status".to_string(),
        serde_json::Value::String(if activation_exit == 6 {
            "degraded".to_string()
        } else {
            "complete".to_string()
        }),
    );
    let generation = object
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .context("retained activation record has no generation")?;
    let bytes = serde_json::to_vec_pretty(&record)?;
    write_atomic_durable(
        &profile_path.join(format!("gen-{generation}/activation.json")),
        &bytes,
    )?;
    write_atomic_durable(Path::new("/run/aos/activation.json"), &bytes)
}

/// Checks for a different sysroot version and stages its A/B image.
///
/// Looks up the current generation's package in the configured registries;
/// when a different sysroot version is published, delegates to
/// [`install_system`] (with confirmation auto-accepted) to stage the inactive
/// slot. The running image and configuration remain unchanged until reboot.
///
/// # Errors
///
/// Returns an error when the running image generation cannot be authenticated,
/// registries cannot be loaded, or the delegated [`install_system`] call fails.
pub async fn upgrade_system(
    config: &ApmConfig,
    dry_run: bool,
    kernel_mode: KernelUpgradeMode,
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

/// Rolls back a configuration generation on the running image.
///
/// With `--list`, prints the recorded configuration generations and returns.
/// Otherwise validates and re-activates the explicit `--generation N`, or the
/// most recent generation before the current one. A cross-ABI rollback instead
/// re-evaluates the retained inputs against the running image and commits a new
/// child generation. Use [`rollback_image_generation`] for the A/B image axis.
///
/// # Errors
///
/// Returns an error when there is no active system generation, the requested
/// generation does not exist, there is no previous generation to roll back
/// to, generation state cannot be read or written, or the target's activate
/// script fails (including the degraded exit-6 case, where the rollback is
/// live but some units failed).
pub async fn rollback_system(
    config: &ApmConfig,
    generation: Option<u32>,
    list: bool,
    dry_run: bool,
    kernel_mode: KernelUpgradeMode,
    drain: bool,
    printer: &Printer,
) -> Result<()> {
    let profile_path = ProfileScope::System.profile_path();
    if list {
        let state = load_generation_state_readonly(&profile_path)?;
        if state.generations.is_empty() {
            printer.info("No system generations.");
        } else {
            printer.header("Configuration generations:");
            for sysgen in &state.generations {
                let marker = if sysgen.number == state.current {
                    " (current)"
                } else {
                    ""
                };
                printer.plain(&format!(
                    "  gen-{}: image-gen-{}, ABI {}, {} [{}]{}",
                    sysgen.number,
                    sysgen.image_gen_parent,
                    sysgen.module_abi_pinned,
                    sysgen.manifest_hash,
                    sysgen.created_at,
                    marker,
                ));
            }
        }
        return Ok(());
    }
    let switch_lock = crate::config_eval::activation::ActivateConfigParams::default().switch_lock;
    let _switch_guard = crate::config_eval::activation::acquire_switch_lock_pub(&switch_lock)?;
    let mut state = load_generation_state(&profile_path)?;

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
        "Rolling back configuration from generation {} to generation {}.",
        current.number, target.number,
    ));

    if dry_run {
        printer.info("Dry run -- no changes made.");
        return Ok(());
    }

    if Path::new(IMAGE_PROFILE_DIR)
        .join(IMAGE_STATE_FILE)
        .is_file()
    {
        let running_image = running_image_generation()?;
        let running_abi = running_image.module_abi;
        match target.reactivation_plan(running_abi)? {
            ReactivationPlan::DirectReactivate => {
                let manifest_path = validate_generation_manifest(&profile_path, &target)?;
                validate_direct_reactivation(&target, &running_image, &manifest_path)?;
                let manifest: crate::config_eval::materialize::ConfigManifest =
                    serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
                let reconciliation = crate::credential_artifact::reconcile_secret_refs(
                    &config.settings,
                    &crate::credential_artifact::aos_root_path(),
                    &manifest.credentials,
                )
                .context("resolving retained generation credential references")?;
                let activation_record =
                    load_reactivation_record(&profile_path, &target, &target.manifest_hash)?;
                direct_reactivate_config_generation_with(
                    &profile_path,
                    &mut state,
                    Path::new(&running_image.toplevel),
                    &target,
                    printer,
                    crate::config_eval::activation::run_activation_with_credential_barrier,
                    {
                        let mut reconciliation = Some(reconciliation);
                        move |event| match event {
                            crate::config_eval::activation::CredentialBarrier::StagedView(
                                candidate_etc,
                            ) => reconciliation
                                .as_mut()
                                .context("credential reconciliation already published")?
                                .validate_staged_view(candidate_etc),
                            crate::config_eval::activation::CredentialBarrier::Publish(plan) => {
                                reconciliation
                                    .take()
                                    .context("credential reconciliation published twice")?
                                    .publish_with(|units| {
                                        if units.is_empty() {
                                            Ok(())
                                        } else {
                                            augment_reconcile_plan_with_credential_units(
                                                plan, units,
                                            )
                                        }
                                    })
                                    .map(|_| ())
                            }
                        }
                    },
                    || {
                        crate::attestation::persist_generation_attestation(
                            &profile_path.join(format!("gen-{}", target.number)),
                            &target.manifest_hash,
                            &target.manifest_hash,
                            &manifest,
                            &running_image,
                            crate::attestation::image_requires_generation_quote(&running_image),
                            true,
                        )
                        .map(|_| ())
                    },
                    |activation_exit| {
                        publish_reactivation_record(
                            &profile_path,
                            &activation_record,
                            activation_exit,
                        )
                    },
                )?;
                return Ok(());
            }
            ReactivationPlan::CrossAbiReEval(inputs) => {
                let activated = reeval_and_activate_config_generation(
                    config,
                    &profile_path,
                    &target,
                    &inputs,
                    Path::new(&running_image.evaluator_ref),
                    running_abi,
                )?;
                printer.success(&format!(
                    "Re-evaluated generation {} under module ABI {} and activated it as generation {}.",
                    target.number, running_abi, activated
                ));
                return Ok(());
            }
        }
    }

    let _ = (kernel_mode, drain);
    bail!("image generation state is absent; refusing config rollback through legacy state")
}

/// Copies a store tree into the persistent overlay upper using an atomic
/// destination rename.
fn copy_store_tree_to_upper(source: &Path, upper_store: &Path) -> Result<()> {
    let name = source.file_name().context("store path has no basename")?;
    let destination = upper_store.join(name);
    if destination.exists() || destination.symlink_metadata().is_ok() {
        return Ok(());
    }
    std::fs::create_dir_all(upper_store)
        .with_context(|| format!("creating persistent store upper {}", upper_store.display()))?;
    let temp = upper_store.join(format!(
        ".aos-copyup-{}-{}",
        std::process::id(),
        name.to_string_lossy()
    ));
    if temp.exists() || temp.symlink_metadata().is_ok() {
        if temp.is_dir() && !temp.is_symlink() {
            std::fs::remove_dir_all(&temp)?;
        } else {
            std::fs::remove_file(&temp)?;
        }
    }
    copy_tree(source, &temp)?;
    sync_tree_files(&temp)?;
    std::fs::rename(&temp, &destination)
        .with_context(|| format!("publishing persistent store copy {}", destination.display()))?;
    sync_directory(upper_store)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(source)
        .with_context(|| format!("stat retained store path {}", source.display()))?;
    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(source)?;
        std::os::unix::fs::symlink(target, destination)?;
    } else if metadata.is_dir() {
        std::fs::create_dir(destination)?;
        std::fs::set_permissions(destination, metadata.permissions())?;
        let mut entries = std::fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            copy_tree(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else if metadata.is_file() {
        std::fs::copy(source, destination)?;
        std::fs::set_permissions(destination, metadata.permissions())?;
    } else {
        bail!(
            "retained store path contains unsupported file type: {}",
            source.display()
        );
    }
    Ok(())
}

fn sync_tree_files(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.is_file() {
        OpenOptions::new().read(true).open(path)?.sync_all()?;
    } else if metadata.is_dir() {
        for entry in std::fs::read_dir(path)? {
            sync_tree_files(&entry?.path())?;
        }
        sync_directory(path)?;
    }
    Ok(())
}

/// Materializes an evaluator closure from the current immutable lower into
/// `/var` before its root slot may be overwritten.
fn persist_store_closure_to_upper(evaluator_ref: &str, upper_store: &Path) -> Result<()> {
    let output = std::process::Command::new("nix-store")
        .args(["--query", "--requisites", evaluator_ref])
        .output()
        .context("querying evaluator closure for persistent copy-up")?;
    if !output.status.success() {
        bail!(
            "nix-store --query --requisites failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    for line in String::from_utf8(output.stdout)?.lines() {
        let source = Path::new(line);
        if !source.starts_with("/nix/store") || source.parent() != Some(Path::new("/nix/store")) {
            bail!("nix-store returned unsafe closure path {line}");
        }
        copy_store_tree_to_upper(source, upper_store)?;
    }
    Ok(())
}

fn image_artifact_path(
    image_store: &Path,
    declared: Option<&str>,
    fallback: &str,
) -> Result<PathBuf> {
    let relative = declared.unwrap_or(fallback);
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("unsafe image artifact path {relative:?}");
    }
    let artifact = image_store.join(path);
    let metadata = std::fs::symlink_metadata(&artifact)
        .with_context(|| format!("reading staged image artifact {}", artifact.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!(
            "image artifact is not a regular file: {}",
            artifact.display()
        );
    }
    Ok(artifact)
}

fn copy_payload_to_slot(source: &Path, destination: &Path) -> Result<()> {
    let source_len = std::fs::metadata(source)?.len();
    let production_partlabel = destination.starts_with("/dev/disk/by-partlabel");
    if production_partlabel {
        let resolved = std::fs::canonicalize(destination)
            .with_context(|| format!("resolving inactive image slot {}", destination.display()))?;
        if !resolved.starts_with("/dev") {
            bail!(
                "inactive image slot {} resolves outside /dev: {}",
                destination.display(),
                resolved.display()
            );
        }
    }
    // Open first and validate the file descriptor metadata, avoiding a
    // symlink-swap race between the type check and the destructive write.
    let mut output = OpenOptions::new()
        .write(true)
        .open(destination)
        .with_context(|| format!("opening inactive image slot {}", destination.display()))?;
    let destination_metadata = output.metadata()?;
    if (production_partlabel && !destination_metadata.file_type().is_block_device())
        || (!production_partlabel
            && !(destination_metadata.file_type().is_block_device()
                || destination_metadata.is_file()))
    {
        bail!(
            "inactive image slot is not a block device: {}",
            destination.display()
        );
    }
    if destination_metadata.is_file()
        && destination_metadata.len() != 0
        && destination_metadata.len() < source_len
    {
        bail!(
            "inactive image slot {} is smaller than payload ({} < {})",
            destination.display(),
            destination_metadata.len(),
            source_len
        );
    }
    let mut input = OpenOptions::new().read(true).open(source)?;
    let copied = std::io::copy(&mut input, &mut output)?;
    if copied != source_len {
        bail!("short image-slot write: copied {copied} of {source_len} bytes");
    }
    output.sync_all()?;
    Ok(())
}

/// Temporarily remounts the EFI System Partition writable for one transaction.
///
/// AOS keeps `/boot` read-only during normal operation. Image staging and
/// boot-count blessing are the only transactions that need to publish or
/// rename UKIs, so they use this narrow bracket and restore read-only state on
/// both success and failure.
fn with_writable_boot<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    let expected_device = PathBuf::from(read_toplevel_meta(
        Path::new(RUNNING_TOPLEVEL_LINK),
        "esp-device",
    )?);
    if !expected_device.is_absolute() || !expected_device.starts_with("/dev") {
        bail!(
            "running image records an unsafe EFI System Partition device: {}",
            expected_device.display()
        );
    }
    validate_boot_esp_mount(
        Path::new(BOOT_ROOT),
        Path::new("/proc/self/mountinfo"),
        &expected_device,
        true,
    )?;
    with_writable_boot_using(Path::new(BOOT_ROOT), remount_boot, action)
}

fn validate_boot_esp_mount(
    boot_root: &Path,
    mountinfo: &Path,
    expected_device: &Path,
    require_block_devices: bool,
) -> Result<()> {
    let boot_root = std::fs::canonicalize(boot_root)
        .with_context(|| format!("resolving EFI mount point {}", boot_root.display()))?;
    let expected_device = std::fs::canonicalize(expected_device).with_context(|| {
        format!(
            "resolving expected EFI System Partition {}",
            expected_device.display()
        )
    })?;
    let contents = std::fs::read_to_string(mountinfo)
        .with_context(|| format!("reading mount table {}", mountinfo.display()))?;
    let (mounted_root, filesystem_type, source) = contents
        .lines()
        .find_map(|line| {
            let (mount, filesystem) = line.split_once(" - ")?;
            let mut mount_fields = mount.split_ascii_whitespace();
            let mounted_root = mount_fields.nth(3)?;
            let mountpoint = mount_fields.next()?;
            if Path::new(mountpoint) != boot_root {
                return None;
            }
            let mut filesystem_fields = filesystem.split_ascii_whitespace();
            let filesystem_type = filesystem_fields.next()?;
            let source = filesystem_fields.next()?;
            Some((mounted_root, filesystem_type, source))
        })
        .with_context(|| {
            format!(
                "{} is not a mounted EFI System Partition",
                boot_root.display()
            )
        })?;
    if mounted_root != "/" {
        bail!(
            "{} is a bind/subtree mount (filesystem root {mounted_root:?}), not the ESP root",
            boot_root.display()
        );
    }
    if filesystem_type != "vfat" {
        bail!(
            "{} has filesystem type {filesystem_type:?}, expected vfat",
            boot_root.display()
        );
    }
    // Open both paths before inspecting them so a symlink replacement cannot
    // change the device identity between validation and comparison.
    let expected_file = std::fs::File::open(&expected_device).with_context(|| {
        format!(
            "opening expected EFI System Partition {}",
            expected_device.display()
        )
    })?;
    let mounted_file = std::fs::File::open(source)
        .with_context(|| format!("opening mounted EFI device {source}"))?;
    let expected_metadata = expected_file.metadata()?;
    let mounted_metadata = mounted_file.metadata()?;
    if require_block_devices
        && (!expected_metadata.file_type().is_block_device()
            || !mounted_metadata.file_type().is_block_device())
    {
        bail!("EFI System Partition paths must both be block devices");
    }
    let mounted_device = std::fs::canonicalize(source)
        .with_context(|| format!("resolving mounted EFI device {source}"))?;
    let same_device = if expected_metadata.file_type().is_block_device()
        && mounted_metadata.file_type().is_block_device()
    {
        expected_metadata.rdev() == mounted_metadata.rdev()
    } else {
        mounted_device == expected_device
    };
    if !same_device {
        bail!(
            "{} is mounted from {}, expected {}",
            boot_root.display(),
            mounted_device.display(),
            expected_device.display()
        );
    }
    Ok(())
}

fn with_writable_boot_using<T>(
    boot_root: &Path,
    mut remount: impl FnMut(&Path, bool) -> Result<()>,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    remount(boot_root, true)?;
    let result = action();
    let restore = remount(boot_root, false);
    match (result, restore) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.context("restoring the EFI System Partition read-only")),
        (Err(error), Err(restore_error)) => Err(error.context(format!(
            "the EFI System Partition also failed to return read-only: {restore_error:#}"
        ))),
    }
}

fn remount_boot(boot_root: &Path, writable: bool) -> Result<()> {
    let mode = if writable { "rw" } else { "ro" };
    let status = std::process::Command::new("mount")
        .args(["-o", &format!("remount,{mode}")])
        .arg(boot_root)
        .status()
        .with_context(|| format!("remounting {} {mode}", boot_root.display()))?;
    if !status.success() {
        bail!(
            "remounting {} {mode} failed with {status}",
            boot_root.display()
        );
    }
    Ok(())
}

fn read_toplevel_meta(toplevel: &Path, name: &str) -> Result<String> {
    let value = std::fs::read_to_string(toplevel.join("meta").join(name))
        .with_context(|| format!("reading target image metadata {name}"))?;
    Ok(value.trim().to_string())
}

fn stage_slot_artifacts(
    layout: &ImageSlotLayout<'_>,
    target_slot: ImageSlot,
    image_store: &Path,
    image: &SysrootImageEntry,
    uki_entry: &str,
    reusable_ukis: &[PathBuf],
    recovery: Option<&crate::types::RecoveryGeneration>,
) -> Result<()> {
    stage_slot_artifacts_with(
        layout,
        target_slot,
        image_store,
        image,
        uki_entry,
        reusable_ukis,
        recovery,
        |_| Ok(()),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StageCheckpoint {
    InactiveEntryDisarmed,
    RootWritten,
    VerityWritten,
    NormalUkiStaged,
    RecoveryUkiPublished,
    RecoveryEntryPublished,
    NormalUkiPublished,
}

#[allow(clippy::too_many_arguments)]
fn stage_slot_artifacts_with<F>(
    layout: &ImageSlotLayout<'_>,
    target_slot: ImageSlot,
    image_store: &Path,
    image: &SysrootImageEntry,
    uki_entry: &str,
    reusable_ukis: &[PathBuf],
    recovery: Option<&crate::types::RecoveryGeneration>,
    mut checkpoint: F,
) -> Result<()>
where
    F: FnMut(StageCheckpoint) -> Result<()>,
{
    let (root_device, hash_device, legacy_uki_name) = match target_slot {
        ImageSlot::A => (layout.root_a, layout.root_a_hash, "uki-a.efi"),
        ImageSlot::B => (layout.root_b, layout.root_b_hash, "uki-b.efi"),
    };
    let root = image_artifact_path(image_store, image.root_image.as_deref(), "root.img")?;
    let verity = image
        .root_verity
        .as_deref()
        .map(|path| image_artifact_path(image_store, Some(path), "root.verity"))
        .transpose()?
        .or_else(|| {
            let fallback = image_store.join("root.verity");
            fallback.is_file().then_some(fallback)
        });
    let root_hash_file = image_store.join("root.roothash");
    if root_hash_file.is_file() != verity.is_some() {
        bail!("image root payload and dm-verity metadata are incomplete");
    }
    if let Some(expected) = image.root_hash.as_deref() {
        let actual = std::fs::read_to_string(&root_hash_file)?;
        if actual.trim() != expected {
            bail!("image root hash metadata does not match root.roothash");
        }
    }
    let uki = if let Some(slot) = image_uki_for_slot(image, target_slot)? {
        image_artifact_path(image_store, Some(&slot.path), legacy_uki_name)?
    } else {
        image_artifact_path(image_store, None, legacy_uki_name)?
    };

    let destination = layout.boot_root.join(uki_entry);
    let parent = destination
        .parent()
        .context("UKI destination has no parent")?;
    std::fs::create_dir_all(parent)?;
    let staging_dir = layout.boot_root.join("EFI/.aos-staging");
    std::fs::create_dir_all(&staging_dir)?;
    let slot_name = match target_slot {
        ImageSlot::A => "a",
        ImageSlot::B => "b",
    };
    let disabled_prefix = format!("disabled-{slot_name}-");
    let existing_disabled = std::fs::read_dir(&staging_dir)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(&disabled_prefix)
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    if !reusable_ukis.is_empty() && !existing_disabled.is_empty() {
        // A power loss can occur after the replacement candidate is renamed
        // into EFI/Linux but before the old disabled files are removed. The
        // only safe mixed state is that exact final destination. Disarm it
        // again and replay the whole root/hash/UKI transaction; any other
        // discoverable file is ambiguous and remains fail-closed.
        if reusable_ukis.len() != 1 || reusable_ukis[0] != destination {
            bail!("inactive slot has ambiguous discoverable and previously disabled UKIs");
        }
        let replay = staging_dir.join(format!("slot-{slot_name}.efi"));
        std::fs::rename(&destination, &replay)?;
        sync_directory(parent)?;
        sync_directory(&staging_dir)?;
    }
    if existing_disabled.iter().any(|path| {
        std::fs::symlink_metadata(path)
            .map(|metadata| !metadata.file_type().is_file())
            .unwrap_or(true)
    }) {
        bail!("inactive-slot staging contains a non-regular disabled UKI");
    }
    if existing_disabled.is_empty() {
        for (index, reusable) in reusable_ukis.iter().enumerate() {
            // Disarm every discoverable inactive-slot UKI before touching its
            // root. Unknown UKIs are rejected by discovery before this point.
            let name = reusable
                .file_name()
                .and_then(|name| name.to_str())
                .context("inactive UKI has no UTF-8 filename")?;
            std::fs::rename(
                reusable,
                staging_dir.join(format!("{disabled_prefix}{index}-{name}")),
            )?;
        }
        if !reusable_ukis.is_empty() {
            sync_directory(&layout.boot_root.join("EFI/Linux"))?;
            sync_directory(&staging_dir)?;
            checkpoint(StageCheckpoint::InactiveEntryDisarmed)?;
        }
    }
    let temp = staging_dir.join(format!("slot-{slot_name}.efi"));

    // The replacement UKI is published last: at every earlier crash point
    // sd-boot can see only the still-running slot, never a UKI that targets a
    // partial root.
    copy_payload_to_slot(&root, root_device)?;
    checkpoint(StageCheckpoint::RootWritten)?;
    if let Some(verity) = verity {
        copy_payload_to_slot(&verity, hash_device)?;
        checkpoint(StageCheckpoint::VerityWritten)?;
    }
    let mut input = OpenOptions::new().read(true).open(&uki)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&temp)?;
    let mut normal_hasher = Sha256::new();
    let mut normal_size = 0_u64;
    let mut normal_buffer = [0_u8; 128 * 1024];
    loop {
        let read = input.read(&mut normal_buffer)?;
        if read == 0 {
            break;
        }
        normal_hasher.update(&normal_buffer[..read]);
        output.write_all(&normal_buffer[..read])?;
        normal_size = normal_size
            .checked_add(u64::try_from(read)?)
            .context("normal UKI size overflow")?;
    }
    let normal_digest = hex::encode(normal_hasher.finalize());
    output.sync_all()?;
    checkpoint(StageCheckpoint::NormalUkiStaged)?;

    if let Some(recovery) = recovery {
        let recovery_source =
            image_artifact_path(image_store, Some(&recovery.source_path), "recovery UKI")?;
        let recovery_entry_source = image_artifact_path(
            image_store,
            Some(match target_slot {
                ImageSlot::A => "recovery-a.conf",
                ImageSlot::B => "recovery-b.conf",
            }),
            "recovery loader entry",
        )?;
        let recovery_temp = staging_dir.join(format!("recovery-{slot_name}.efi"));
        let entry_temp = staging_dir.join(format!("recovery-{slot_name}.conf"));
        copy_recovery_file(
            &recovery_source,
            &recovery_temp,
            recovery.byte_size,
            &recovery.sha256,
        )?;
        let entry_bytes = std::fs::read(&recovery_entry_source)?;
        if entry_bytes.len() > 4096 {
            bail!("recovery loader entry exceeds its size bound");
        }
        let mut entry_output = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&entry_temp)?;
        entry_output.write_all(&entry_bytes)?;
        entry_output.sync_all()?;
        sync_directory(&staging_dir)?;

        let recovery_destination = layout.boot_root.join(&recovery.uki_path);
        let recovery_parent = recovery_destination
            .parent()
            .context("recovery UKI destination has no parent")?;
        std::fs::create_dir_all(recovery_parent)?;
        std::fs::rename(&recovery_temp, &recovery_destination)?;
        sync_directory(recovery_parent)?;
        verify_regular_file(
            &recovery_destination,
            recovery.byte_size,
            &recovery.sha256,
            "installed recovery UKI",
        )?;
        checkpoint(StageCheckpoint::RecoveryUkiPublished)?;

        let entry_destination = layout.boot_root.join(&recovery.entry_path);
        let entry_parent = entry_destination
            .parent()
            .context("recovery loader entry destination has no parent")?;
        std::fs::create_dir_all(entry_parent)?;
        std::fs::rename(&entry_temp, &entry_destination)?;
        sync_directory(entry_parent)?;
        if std::fs::read(&entry_destination)? != entry_bytes {
            bail!("installed recovery loader entry failed read-back verification");
        }
        checkpoint(StageCheckpoint::RecoveryEntryPublished)?;
    }

    // Candidate discoverability is the final publication boundary. Recovery
    // is replaced first so a bootloader can never select a normal candidate
    // whose matching recovery copy is still missing or stale.
    std::fs::rename(&temp, &destination)?;
    sync_directory(parent)?;
    verify_regular_file(
        &destination,
        normal_size,
        &normal_digest,
        "installed normal UKI",
    )?;
    checkpoint(StageCheckpoint::NormalUkiPublished)?;
    for entry in std::fs::read_dir(&staging_dir)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(&disabled_prefix)
        {
            std::fs::remove_file(entry.path())?;
        }
    }
    sync_directory(&staging_dir)
}

fn copy_recovery_file(source: &Path, destination: &Path, size: u64, digest: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(source)?;
    if !metadata.file_type().is_file() || metadata.len() != size {
        bail!("recovery source is not the cataloged regular file size");
    }
    let mut input = std::fs::File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(destination)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    output.sync_all()?;
    let actual = hex::encode(hasher.finalize());
    if actual != digest {
        bail!("recovery source digest does not match the signed catalog");
    }
    Ok(())
}

fn verify_regular_file(path: &Path, size: u64, digest: &str, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() != size {
        bail!("{label} failed type or size read-back verification");
    }
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if hex::encode(hasher.finalize()) != digest {
        bail!("{label} failed digest read-back verification");
    }
    Ok(())
}

fn recovery_generation_for_slot(
    image_store: &Path,
    image: &SysrootImageEntry,
    target_slot: ImageSlot,
) -> Result<Option<crate::types::RecoveryGeneration>> {
    if image.recovery_ukis.is_empty() {
        return Ok(None);
    }
    let copy = match target_slot {
        ImageSlot::A => UkiSlot::A,
        ImageSlot::B => UkiSlot::B,
    };
    let entry = image
        .recovery_ukis
        .iter()
        .find(|entry| entry.copy == copy)
        .with_context(|| format!("image records no recovery copy for slot {target_slot:?}"))?;
    let (source_path, source_entry, uki_path, entry_path) = match target_slot {
        ImageSlot::A => (
            "recovery-a.efi",
            "recovery-a.conf",
            "EFI/AOS/recovery-a.efi",
            "loader/entries/recovery-a.conf",
        ),
        ImageSlot::B => (
            "recovery-b.efi",
            "recovery-b.conf",
            "EFI/AOS/recovery-b.efi",
            "loader/entries/recovery-b.conf",
        ),
    };
    if entry.path != source_path || entry.entry_path != source_entry {
        bail!("recovery catalog paths are not canonical for slot {target_slot:?}");
    }
    let source = image_artifact_path(image_store, Some(source_path), "recovery UKI")?;
    let metadata = std::fs::symlink_metadata(&source)?;
    if !metadata.file_type().is_file() || metadata.len() != entry.byte_size {
        bail!("recovery source size changed after catalog verification");
    }
    let mut file = std::fs::File::open(&source)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if hex::encode(hasher.finalize()) != entry.sha256 {
        bail!("recovery source digest changed after catalog verification");
    }
    Ok(Some(crate::types::RecoveryGeneration {
        copy: target_slot,
        uki_path: uki_path.to_string(),
        entry_path: entry_path.to_string(),
        source_path: source_path.to_string(),
        sha256: entry.sha256.clone(),
        byte_size: entry.byte_size,
        release: entry.release.clone(),
        recovery_abi: entry.recovery_abi,
    }))
}

fn discover_installed_slot_ukis(
    layout: &ImageSlotLayout<'_>,
    state: &ImageGenerationState,
    slot: ImageSlot,
    intended_uki: &str,
    authenticate_slot: bool,
) -> Result<Vec<PathBuf>> {
    let linux = layout.boot_root.join("EFI/Linux");
    let mut recorded = std::collections::BTreeMap::new();
    for generation in &state.generations {
        let path = Path::new(&generation.uki_path);
        if path.parent() != Some(Path::new("EFI/Linux")) {
            bail!("image state records a UKI outside EFI/Linux");
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("recorded UKI has no UTF-8 filename")?;
        let stable = stable_uki_entry_id(name)?;
        if recorded
            .insert(stable.clone(), generation.slot)
            .is_some_and(|found| found != generation.slot)
        {
            bail!("image state assigns UKI {stable} to both slots");
        }
    }
    let intended_name = Path::new(intended_uki)
        .file_name()
        .and_then(|name| name.to_str())
        .context("intended UKI has no UTF-8 filename")?;
    let intended_stable = stable_uki_entry_id(intended_name)?;
    if recorded
        .insert(intended_stable.clone(), slot)
        .is_some_and(|found| found != slot)
    {
        bail!("intended UKI {intended_stable} conflicts with recorded slot state");
    }

    let mut discovered = Vec::new();
    if !linux.is_dir() {
        bail!("ESP has no EFI/Linux directory");
    }
    let mut count = 0_usize;
    for entry in std::fs::read_dir(&linux)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("ESP UKI filename is not UTF-8"))?;
        if !name.ends_with(".efi") {
            continue;
        }
        count += 1;
        if count > 128 {
            bail!("ESP contains more than 128 normal UKIs");
        }
        if !entry.file_type()?.is_file() {
            bail!("ESP normal UKI is not a regular file: {name}");
        }
        let stable = stable_uki_entry_id(&name)?;
        let recorded_slot = recorded
            .get(&stable)
            .with_context(|| format!("ESP contains unrecorded normal UKI {name}"))?;
        let authoritative_slot = if authenticate_slot {
            reverify_uki(&entry.path(), Path::new(IMMUTABLE_SECURE_BOOT_DB))?;
            let cmdline = read_uki_section_text(&entry.path(), ".cmdline")?;
            let signed_slot = match aos_boot_identity::parse_normal(&cmdline)
                .with_context(|| {
                    format!("installed UKI {name} has an invalid signed command line")
                })?
                .slot
            {
                aos_boot_identity::BootSlot::A => ImageSlot::A,
                aos_boot_identity::BootSlot::B => ImageSlot::B,
            };
            if *recorded_slot != signed_slot {
                bail!(
                    "image state assigns UKI {name} to slot {recorded_slot:?}, but its authenticated command line selects {signed_slot:?}"
                );
            }
            signed_slot
        } else {
            *recorded_slot
        };
        if authoritative_slot == slot {
            discovered.push(entry.path());
        }
    }
    Ok(discovered)
}

fn validate_known_good_recovery(
    layout: &ImageSlotLayout<'_>,
    state: &ImageGenerationState,
    running: &ImageGeneration,
) -> Result<()> {
    if state.recovery_known_good != Some(running.slot) {
        bail!("recovery known-good evidence does not identify the running slot");
    }
    let recovery = running
        .recovery
        .as_ref()
        .context("running generation has no recovery-copy evidence")?;
    if recovery.copy != running.slot {
        bail!("running generation recovery evidence names the wrong slot");
    }
    if recovery.release != running.version {
        bail!("running recovery evidence disagrees with the authenticated image release");
    }
    if recovery.recovery_abi != SUPPORTED_RECOVERY_ABI {
        bail!("running recovery evidence names an unsupported recovery ABI");
    }
    let (uki_path, entry_path, suffix) = match running.slot {
        ImageSlot::A => (
            "EFI/AOS/recovery-a.efi",
            "loader/entries/recovery-a.conf",
            "A",
        ),
        ImageSlot::B => (
            "EFI/AOS/recovery-b.efi",
            "loader/entries/recovery-b.conf",
            "B",
        ),
    };
    if recovery.uki_path != uki_path || recovery.entry_path != entry_path {
        bail!("running recovery evidence has noncanonical ESP paths");
    }
    verify_regular_file(
        &layout.boot_root.join(uki_path),
        recovery.byte_size,
        &recovery.sha256,
        "known-good recovery UKI",
    )?;
    let recovery_path = layout.boot_root.join(uki_path);
    reverify_uki(&recovery_path, Path::new(IMMUTABLE_SECURE_BOOT_DB))?;
    aos_boot_identity::parse_recovery(&read_uki_section_text(&recovery_path, ".cmdline")?)
        .context("known-good recovery UKI has a noncanonical signed command line")?;
    let os_release = parse_uki_os_release(&recovery_path)?;
    require_uki_os_release(&os_release, "VERSION_ID", &recovery.release)?;
    require_uki_os_release(&os_release, "AOS_RECOVERY_COPY", suffix)?;
    require_uki_os_release(
        &os_release,
        "AOS_RECOVERY_ABI",
        &SUPPORTED_RECOVERY_ABI.to_string(),
    )?;
    let expected_entry = format!(
        "title AOS Recovery {suffix} ({})\nefi /EFI/AOS/recovery-{}.efi\n",
        recovery.release,
        suffix.to_ascii_lowercase()
    );
    let installed_entry = std::fs::read(layout.boot_root.join(entry_path))?;
    if installed_entry != expected_entry.as_bytes() {
        bail!("known-good recovery loader entry failed exact verification");
    }
    Ok(())
}

/// Reads a required PE section as UTF-8 text after removing section padding.
fn read_uki_section_text(uki: &Path, section: &str) -> Result<String> {
    let temporary = tempfile::Builder::new()
        .prefix("aos-installed-uki-section-")
        .tempfile()
        .context("creating temporary UKI section file")?;
    let output = std::process::Command::new("objcopy")
        .arg("-O")
        .arg("binary")
        .arg(format!("--only-section={section}"))
        .arg(uki)
        .arg(temporary.path())
        .output()
        .with_context(|| format!("extracting {section} from {}", uki.display()))?;
    if !output.status.success() {
        bail!(
            "extracting {section} from {} failed: {}",
            uki.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let bytes = std::fs::read(temporary.path())?;
    if bytes.is_empty() {
        bail!("UKI {} has no {section} section", uki.display());
    }
    let content_end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    let text = std::str::from_utf8(&bytes[..content_end])
        .with_context(|| format!("{section} in {} is not UTF-8", uki.display()))?;
    Ok(text.to_string())
}

fn parse_uki_os_release(uki: &Path) -> Result<std::collections::BTreeMap<String, String>> {
    let text = read_uki_section_text(uki, ".osrel")?;
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, raw) = line
            .split_once('=')
            .with_context(|| format!("malformed signed os-release line in {}", uki.display()))?;
        let value = raw
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(raw);
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            bail!("signed os-release in {} repeats {key}", uki.display());
        }
    }
    Ok(fields)
}

fn require_uki_os_release(
    fields: &std::collections::BTreeMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<()> {
    let actual = fields
        .get(key)
        .with_context(|| format!("recovery UKI signed os-release has no {key}"))?;
    if actual != expected {
        bail!("recovery UKI signed {key} is {actual:?}, expected {expected:?}");
    }
    Ok(())
}

fn image_uki_for_slot<'a>(
    image: &'a SysrootImageEntry,
    target_slot: ImageSlot,
) -> Result<Option<&'a SysrootUkiEntry>> {
    if image.ukis.is_empty() {
        if image.sb_signer_cert_sha256.is_some()
            || !image.sbat.is_empty()
            || image.expected_pcr11.is_some()
        {
            bail!(
                "signed A/B image '{}' has no slot-specific UKI metadata",
                image.store_path
            );
        }
        return Ok(None);
    }
    let slot = match target_slot {
        ImageSlot::A => UkiSlot::A,
        ImageSlot::B => UkiSlot::B,
    };
    image
        .ukis
        .iter()
        .find(|entry| entry.slot == slot)
        .map(Some)
        .with_context(|| {
            format!(
                "image '{}' records no UKI for slot {:?}",
                image.store_path, target_slot
            )
        })
}

fn cleanup_replaced_slot_ukis(
    layout: &ImageSlotLayout<'_>,
    state: &ImageGenerationState,
    slot: ImageSlot,
    keep_recorded: &str,
) -> Result<()> {
    let keep_entry = stable_uki_entry_id(
        Path::new(keep_recorded)
            .file_name()
            .and_then(|name| name.to_str())
            .context("published UKI path has no UTF-8 entry id")?,
    )?;
    let linux = layout.boot_root.join("EFI/Linux");
    for previous in state
        .generations
        .iter()
        .filter(|generation| generation.slot == slot)
    {
        let Ok(entry) = resolve_installed_uki_entry(layout.boot_root, &previous.uki_path) else {
            continue;
        };
        if stable_uki_entry_id(&entry)? == keep_entry {
            continue;
        }
        let source = linux.join(entry);
        if source.is_file() {
            std::fs::remove_file(&source)?;
        }
    }
    if linux.is_dir() {
        sync_directory(&linux)?;
    }

    // Remove artifacts left by the pre-publication disable implementation.
    // This directory is AOS-owned and is never part of sd-boot discovery.
    let disabled_dir = layout.boot_root.join("EFI/.aos-disabled");
    if disabled_dir.is_dir() {
        for entry in std::fs::read_dir(&disabled_dir)? {
            let path = entry?.path();
            if path.is_dir() || path.is_symlink() {
                bail!(
                    "unexpected non-file in disabled UKI directory: {}",
                    path.display()
                );
            }
            std::fs::remove_file(path)?;
        }
        std::fs::remove_dir(&disabled_dir)?;
        if let Some(parent) = disabled_dir.parent() {
            sync_directory(parent)?;
        }
    }
    let staging_dir = layout.boot_root.join("EFI/.aos-staging");
    if staging_dir.is_dir() && std::fs::read_dir(&staging_dir)?.next().is_none() {
        std::fs::remove_dir(&staging_dir)?;
        if let Some(parent) = staging_dir.parent() {
            sync_directory(parent)?;
        }
    }
    Ok(())
}

fn stage_pending_image_generation_with<F>(
    profile: &Path,
    system_profile: &Path,
    upper_store: &Path,
    layout: &ImageSlotLayout<'_>,
    package: &PackageMeta,
    registry: &str,
    image: &SysrootImageEntry,
    image_store: &Path,
    select: F,
) -> Result<ImageGeneration>
where
    F: FnOnce(&str) -> Result<()>,
{
    let mut state = load_image_generation_state_pub(profile)?;
    let running = state
        .running_generation()
        .cloned()
        .context("image state has no running generation")?;
    let target_slot = match running.slot {
        ImageSlot::A => ImageSlot::B,
        ImageSlot::B => ImageSlot::A,
    };
    let toplevel = Path::new(&package.store_path);
    let evaluator_ref = std::fs::read_link(toplevel.join("base-lib"))?
        .to_string_lossy()
        .into_owned();
    let module_abi = read_toplevel_meta(toplevel, "module-abi")?
        .parse::<u32>()
        .context("target image has invalid module ABI")?;
    let baselib_digest = read_toplevel_meta(toplevel, "baselib-digest")?;
    let recorded_uki = read_toplevel_meta(toplevel, "uki-path")?;
    // Validate the firmware namespace before either inactive root or the ESP
    // is touched. A merely relative path is not sufficient: image metadata
    // must never be able to overwrite loader configuration or another ESP
    // subtree, and every staged A/B candidate must carry a live boot count.
    validate_staged_uki_path(&recorded_uki)?;

    if let Some(pending) = state.pending.and_then(|number| {
        state
            .generations
            .iter()
            .find(|generation| generation.number == number)
            .cloned()
    }) {
        if pending.toplevel != package.store_path {
            bail!(
                "image generation {} is already pending; refusing to replace it",
                pending.number
            );
        }
        let pending_entry = resolve_installed_uki_entry(layout.boot_root, &pending.uki_path)?;
        select_image_default_with(profile, &mut state, pending.number, &pending_entry, select)?;
        cleanup_replaced_slot_ukis(layout, &state, pending.slot, &pending.uki_path)?;
        return Ok(pending);
    }

    // Allocate the persistent image number before naming the ESP entry. The
    // loader sorts this numeric identity rather than the package's display
    // version, whose ordering may be intentionally non-semantic.
    let existing = state.generations.iter().position(|generation| {
        generation.toplevel == package.store_path && generation.slot == target_slot
    });
    let number = existing.map_or_else(
        || {
            state
                .generations
                .iter()
                .map(|generation| generation.number)
                .max()
                .unwrap_or(0)
                + 1
        },
        |index| state.generations[index].number,
    );
    let created_at = existing.map_or_else(chrono_iso8601_now, |index| {
        state.generations[index].created_at.clone()
    });
    let installed_uki = generation_uki_path(&recorded_uki, number)?;
    let entry_id = validate_staged_uki_path(&installed_uki)?;

    let recovery = recovery_generation_for_slot(image_store, image, target_slot)?;
    if recovery.is_some() {
        validate_known_good_recovery(layout, &state, &running)?;
    } else if state.recovery_known_good.is_some() || running.recovery.is_some() {
        bail!("recovery-enabled image state cannot stage an image without recovery metadata");
    }
    let reusable_ukis = discover_installed_slot_ukis(
        layout,
        &state,
        target_slot,
        &installed_uki,
        recovery.is_some(),
    )?;

    // Copy the lower-backed running evaluator before the inactive slot is
    // overwritten. The target closure arrived through Nix and is copied too,
    // making both baselib roots physical `/var` retention rather than dangling
    // symlinks into whichever immutable root happens to be mounted.
    persist_store_closure_to_upper(&running.evaluator_ref, upper_store)?;
    persist_store_closure_to_upper(&evaluator_ref, upper_store)?;
    if let Some(artifact) = &recovery {
        let publication = RecoveryPublication {
            target: target_slot,
            artifact: artifact.clone(),
        };
        if let Some(existing) = &state.recovery_pending {
            if existing != &publication {
                bail!(
                    "unfinished recovery publication targets slot {:?}; refusing slot {target_slot:?}",
                    existing.target
                );
            }
        } else {
            state.recovery_pending = Some(publication);
            write_atomic_durable(
                &profile.join(IMAGE_STATE_FILE),
                &serde_json::to_vec_pretty(&state)?,
            )?;
        }
    } else if state.recovery_pending.is_some() {
        bail!("unfinished recovery publication cannot resume without catalog metadata");
    }
    stage_slot_artifacts(
        layout,
        target_slot,
        image_store,
        image,
        &installed_uki,
        &reusable_ukis,
        recovery.as_ref(),
    )?;

    // A failed counted-boot attempt leaves an authenticated generation record
    // behind after fallback. Re-arm that record instead of appending a second
    // entry for the same immutable toplevel: early boot deliberately requires
    // a unique toplevel match when it authenticates the running image.
    let generation = ImageGeneration {
        number,
        slot: target_slot,
        uki_path: installed_uki.clone(),
        uki_source_path: (installed_uki != recorded_uki).then_some(recorded_uki.clone()),
        toplevel: package.store_path.clone(),
        package_name: package.name.clone(),
        version: package.version.clone(),
        registry: registry.to_string(),
        kernel_path: resolve_kernel_path(&package.store_path),
        evaluator_ref: evaluator_ref.clone(),
        module_abi,
        baselib_digest,
        root_verity_roothash: image.root_hash.clone().or_else(|| {
            std::fs::read_to_string(image_store.join("root.roothash"))
                .ok()
                .map(|value| value.trim().to_string())
        }),
        expected_pcr11: image_uki_for_slot(image, target_slot)?
            .and_then(|uki| uki.expected_pcr11.clone())
            .or_else(|| image.expected_pcr11.clone()),
        initrd_pcr11: None,
        recovery: recovery.clone(),
        created_at,
    };
    if let Some(index) = existing {
        state.generations[index] = generation.clone();
    } else {
        state.generations.push(generation.clone());
    }
    state.recovery_pending = None;
    crate::store::create_baselib_gc_root(
        &profile.join(format!("image-gen-{number}")),
        module_abi,
        &evaluator_ref,
    )?;
    let configs = load_generation_state_readonly(system_profile)?;
    crate::store::reconcile_baselib_gc_roots(profile, &state, &configs)?;
    select_image_default_with(profile, &mut state, number, &entry_id, select)?;
    cleanup_replaced_slot_ukis(layout, &state, target_slot, &installed_uki)?;
    Ok(generation)
}

/// Selects an older A/B image generation durably with `bootctl set-default`.
///
/// This changes only the next-boot image axis. The currently running image and
/// config pointer remain untouched; after reboot `aos-firstboot-reeval`
/// rebinds configuration to the image that actually booted.
///
/// # Errors
///
/// Returns an error for an unknown image generation, unsafe UKI path,
/// `bootctl` failure, state publication failure, or requested reboot failure.
pub async fn rollback_image_generation(
    generation: Option<u32>,
    list: bool,
    dry_run: bool,
    kernel_mode: KernelUpgradeMode,
    drain: bool,
    printer: &Printer,
) -> Result<()> {
    let profile = Path::new(IMAGE_PROFILE_DIR);
    let mut state = load_image_generation_state_pub(profile)?;
    if list {
        for image in &state.generations {
            let running = if image.number == state.running {
                " (running)"
            } else {
                ""
            };
            let default = if image.number == state.default {
                " (default)"
            } else {
                ""
            };
            printer.plain(&format!(
                "  image-gen-{}: {} {} [{}]{}{}",
                image.number, image.package_name, image.version, image.uki_path, running, default
            ));
        }
        return Ok(());
    }
    let switch_lock = crate::config_eval::activation::ActivateConfigParams::default().switch_lock;
    let _switch_guard = crate::config_eval::activation::acquire_switch_lock_pub(&switch_lock)?;
    state = load_image_generation_state_pub(profile)?;
    let target = match generation {
        Some(number) => state
            .generations
            .iter()
            .find(|image| image.number == number)
            .cloned()
            .with_context(|| format!("image generation {number} not found"))?,
        None => state
            .generations
            .iter()
            .rev()
            .find(|image| image.number < state.running)
            .cloned()
            .context("no previous image generation to roll back to")?,
    };
    let entry_id = resolve_installed_uki_entry(Path::new("/boot"), &target.uki_path)
        .with_context(|| format!("resolving image generation {} UKI", target.number))?;
    if dry_run {
        printer.info(&format!(
            "Would set image generation {} ({}) as the durable next boot.",
            target.number, entry_id
        ));
        return Ok(());
    }
    with_writable_boot(|| {
        select_image_default_with(profile, &mut state, target.number, &entry_id, |entry| {
            let status = std::process::Command::new("bootctl")
                .arg("set-default")
                .arg(entry)
                .status()
                .context("running bootctl set-default")?;
            if !status.success() {
                bail!("bootctl set-default failed with {status}");
            }
            Ok(())
        })
    })?;
    printer.success(&format!(
        "Image generation {} is the durable next-boot default.",
        target.number
    ));
    if kernel_mode == KernelUpgradeMode::Reboot {
        if drain {
            drain_workloads(&target.toplevel, printer).await?;
        }
        SystemdClient::connect().await?.reboot().await?;
    }
    Ok(())
}

fn resolve_installed_uki_entry(boot_root: &Path, recorded: &str) -> Result<String> {
    resolve_installed_uki_entry_with(boot_root, recorded, ExhaustedEntry::Reject)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ExhaustedEntry {
    Reject,
    Allow,
}

fn resolve_installed_uki_entry_with(
    boot_root: &Path,
    recorded: &str,
    exhausted_entry: ExhaustedEntry,
) -> Result<String> {
    let path = Path::new(recorded);
    if path.is_absolute()
        || recorded.is_empty()
        || recorded == "seed"
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("unsafe UKI path {recorded:?}");
    }
    let file = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("image generation UKI path has no UTF-8 entry id")?;
    let stable = stable_uki_entry_id(file)?;
    let directory = path
        .parent()
        .map_or_else(|| boot_root.to_path_buf(), |parent| boot_root.join(parent));
    let exact = directory.join(file);
    if exact.is_file() {
        if entry_remaining_tries(file) == Some(0) && exhausted_entry == ExhaustedEntry::Reject {
            bail!(
                "recorded UKI {recorded:?} has exhausted its boot count; restage it before selecting it as default"
            );
        }
        return Ok(file.to_string());
    }
    if directory.join(&stable).is_file() {
        return Ok(stable);
    }
    let stable_stem = stable
        .strip_suffix(".efi")
        .context("UKI entry does not end in .efi")?;
    let mut counted = std::fs::read_dir(&directory)
        .with_context(|| format!("reading ESP UKI directory {}", directory.display()))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| {
            let remaining = name
                .strip_prefix(stable_stem)
                .and_then(|suffix| suffix.strip_prefix('+'))
                .and_then(|suffix| suffix.strip_suffix(".efi"))
                .and_then(boot_count_remaining)?;
            Some((remaining, name))
        })
        .collect::<Vec<_>>();
    let exhausted = counted.iter().any(|(remaining, _)| *remaining == 0);
    if exhausted_entry == ExhaustedEntry::Reject {
        counted.retain(|(remaining, _)| *remaining > 0);
    }
    counted.sort();
    if let Some((_, name)) = counted.pop() {
        return Ok(name);
    }
    if exhausted {
        bail!(
            "all installed UKIs matching {recorded:?} have exhausted their boot count; restage the image before rollback"
        );
    }
    bail!("no installed UKI matches {recorded:?}")
}

fn stable_uki_entry_id(entry: &str) -> Result<String> {
    let stem = entry
        .strip_suffix(".efi")
        .context("UKI entry does not end in .efi")?;
    let stable = stem.rsplit_once('+').map_or(stem, |(prefix, suffix)| {
        if valid_boot_count_suffix(suffix) {
            prefix
        } else {
            stem
        }
    });
    Ok(format!("{stable}.efi"))
}

fn valid_boot_count_suffix(suffix: &str) -> bool {
    let mut parts = suffix.split('-');
    parts
        .next()
        .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && parts
            .next()
            .is_none_or(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && parts.next().is_none()
}

fn boot_count_remaining(suffix: &str) -> Option<u32> {
    if !valid_boot_count_suffix(suffix) {
        return None;
    }
    suffix.split('-').next()?.parse().ok()
}

fn entry_remaining_tries(entry: &str) -> Option<u32> {
    let stem = entry.strip_suffix(".efi")?;
    let (_, suffix) = stem.rsplit_once('+')?;
    boot_count_remaining(suffix)
}

fn validate_staged_uki_path(recorded: &str) -> Result<String> {
    let path = Path::new(recorded);
    let components = path.components().collect::<Vec<_>>();
    let [
        std::path::Component::Normal(efi),
        std::path::Component::Normal(linux),
        std::path::Component::Normal(file),
    ] = components.as_slice()
    else {
        bail!("target image records unsafe UKI path {recorded:?}");
    };
    if *efi != "EFI" || *linux != "Linux" {
        bail!("target UKI must be installed below EFI/Linux: {recorded:?}");
    }
    let file = file
        .to_str()
        .context("target UKI entry name is not valid UTF-8")?;
    let stem = file
        .strip_suffix(".efi")
        .context("target UKI entry must end in .efi")?;
    let (base, tries) = stem
        .rsplit_once('+')
        .context("target UKI entry has no terminal boot-count suffix")?;
    if base.is_empty()
        || tries.is_empty()
        || !tries.bytes().all(|byte| byte.is_ascii_digit())
        || tries.parse::<u32>().ok().is_none_or(|tries| tries == 0)
    {
        bail!("target UKI entry has an invalid live boot-count suffix: {file:?}");
    }
    Ok(file.to_string())
}

fn generation_uki_path(recorded: &str, generation: u32) -> Result<String> {
    let entry = validate_staged_uki_path(recorded)?;
    let stem = entry
        .strip_suffix(".efi")
        .context("target UKI entry must end in .efi")?;
    let (_, tries) = stem
        .rsplit_once('+')
        .context("target UKI entry has no terminal boot-count suffix")?;
    Ok(format!(
        "EFI/Linux/aos-generation-{generation:010}+{tries}.efi"
    ))
}

fn select_image_default_with<F>(
    profile: &Path,
    state: &mut ImageGenerationState,
    target: u32,
    entry_id: &str,
    select: F,
) -> Result<()>
where
    F: FnOnce(&str) -> Result<()>,
{
    let stable_entry_id = stable_uki_entry_id(entry_id)?;
    let intent_path = profile.join(IMAGE_TRANSITION_INTENT);
    if intent_path.is_file() {
        let existing: ImageTransitionIntent = serde_json::from_slice(&std::fs::read(&intent_path)?)
            .with_context(|| {
                format!("parsing image transition intent {}", intent_path.display())
            })?;
        if existing.target != target || existing.entry_id != entry_id {
            bail!(
                "unfinished image transition targets generation {}; refusing generation {target}",
                existing.target
            );
        }
    } else {
        let intent = ImageTransitionIntent {
            target,
            prior_default: state.default,
            entry_id: entry_id.to_string(),
        };
        write_atomic_durable(&intent_path, &serde_json::to_vec_pretty(&intent)?)?;
    }
    // Publish the complete staged-generation record before changing firmware
    // state. If the machine loses power after `set-default`, early boot can
    // authenticate the candidate from this record instead of inventing seed
    // provenance for an otherwise unknown image.
    let mut prepared = state.clone();
    prepared.pending = Some(target);
    write_atomic_durable(
        &profile.join(IMAGE_STATE_FILE),
        &serde_json::to_vec_pretty(&prepared)?,
    )?;
    *state = prepared;

    // sd-boot renames counted entries before launching them (for example,
    // `image+3.efi` becomes `image+2-1.efi`). Selection therefore receives the
    // stable entry ID even when the caller clears an older exact override and
    // lets the image-owned pattern choose the newest live generation.
    select(&stable_entry_id)?;
    let mut committed = state.clone();
    committed.default = target;
    write_atomic_durable(
        &profile.join(IMAGE_STATE_FILE),
        &serde_json::to_vec_pretty(&committed)?,
    )?;
    remove_file_durable(&intent_path)?;
    *state = committed;
    Ok(())
}

fn direct_reactivate_config_generation_with<F, G, H, I>(
    profile_path: &Path,
    state: &mut ConfigGenerationState,
    running_toplevel: &Path,
    target: &ConfigGeneration,
    printer: &Printer,
    run_activate: F,
    publish_credentials: G,
    persist_attestation: H,
    publish_record: I,
) -> Result<()>
where
    F: FnOnce(
        &Path,
        u32,
        &str,
        &mut dyn FnMut(crate::config_eval::activation::CredentialBarrier<'_>) -> Result<()>,
    ) -> Result<Option<i32>>,
    G: FnMut(crate::config_eval::activation::CredentialBarrier<'_>) -> Result<()>,
    H: FnOnce() -> Result<()>,
    I: FnOnce(i32) -> Result<()>,
{
    let activate = running_toplevel.join("activate");
    let nonce = write_activation_intent_pub(profile_path, state, target.number)?;
    let mut reconcile_credentials = publish_credentials;
    let mut validated_staged_view = false;
    let mut crossed_barrier = false;
    let mut barrier = |event: crate::config_eval::activation::CredentialBarrier<'_>| match event {
        event @ crate::config_eval::activation::CredentialBarrier::StagedView(_) => {
            if validated_staged_view || crossed_barrier {
                bail!("configuration rollback repeated its staged credential validation");
            }
            reconcile_credentials(event)?;
            validated_staged_view = true;
            Ok(())
        }
        event @ crate::config_eval::activation::CredentialBarrier::Publish(_) => {
            if !validated_staged_view || crossed_barrier {
                return Err(
                    crate::config_eval::activation::ActivationFailure::rescue(
                        "configuration rollback crossed an invalid credential publication barrier; rescue mode is required",
                    )
                    .into(),
                );
            }
            reconcile_credentials(event).map_err(|error| {
                crate::config_eval::activation::ActivationFailure::rescue(format!(
                    "configuration rollback swapped /etc but credential publication failed: {error:#}; rescue mode is required"
                ))
            })?;
            crossed_barrier = true;
            Ok(())
        }
    };
    let activation_exit = match run_activate(&activate, target.number, &nonce, &mut barrier)? {
        Some(exit @ (0 | 5 | 6)) => exit,
        Some(4) | None => {
            return Err(crate::config_eval::activation::ActivationFailure::rescue(
                "configuration rollback left /etc indeterminate; rescue mode is required",
            )
            .into());
        }
        other => {
            clear_activation_intent_pub(profile_path)?;
            bail!(
                "Configuration rollback failed before the /etc swap (exit {other:?}); the previous generation remains current."
            )
        }
    };
    if !validated_staged_view || !crossed_barrier {
        return Err(
            crate::config_eval::activation::ActivationFailure::rescue(
                "configuration rollback swapped /etc without publishing credentials; rescue mode is required",
            )
            .into(),
        );
    }
    let degraded = match activation_exit {
        0 => false,
        5 => {
            printer.warning(
                "Configuration rollback succeeded, but cleanup of the previous generation's mounts failed.",
            );
            false
        }
        6 => true,
        other => {
            return Err(
                crate::config_eval::activation::ActivationFailure::rescue(format!(
                    "configuration rollback returned impossible post-swap exit {other}; rescue mode is required"
                ))
                .into(),
            );
        }
    };
    persist_attestation().map_err(|error| {
        crate::config_eval::activation::ActivationFailure::rescue(format!(
            "configuration rollback swapped /etc but attestation publication failed: {error:#}; rescue mode is required"
        ))
    })?;
    commit_current_generation(profile_path, state, target.number).map_err(|error| {
        crate::config_eval::activation::ActivationFailure::rescue(format!(
            "configuration rollback swapped /etc but pointer publication failed: {error:#}; rescue mode is required"
        ))
    })?;
    publish_record(activation_exit).map_err(|error| {
        crate::config_eval::activation::ActivationFailure::rescue(format!(
            "configuration rollback committed its pointer but activation record publication failed: {error:#}; rescue mode is required"
        ))
    })?;
    if degraded {
        bail!(
            "Configuration generation {} is live, but one or more units failed to restart",
            target.number
        );
    }
    printer.success(&format!(
        "Configuration generation {} is active under the running image.",
        target.number
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
async fn ensure_image_imported(
    config: &ApmConfig,
    package: &PackageMeta,
    image: &SysrootImageEntry,
    printer: &Printer,
) -> Result<PathBuf> {
    let store_path = PathBuf::from(&image.store_path);
    if store_path.exists() {
        return Ok(store_path);
    }

    let chain = resolve_image_mirror(config, package);
    let (mirror_url, fallback_mirrors) = split_mirror_chain(&chain);
    let request = DownloadRequest {
        store_path: image.store_path.clone(),
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
    let results = download_nars(
        &resolved,
        &config.nar_cache_path(),
        config.settings.parallel_downloads,
        printer,
    )
    .await?;
    let result = results
        .first()
        .context("image artifact download returned no result")?;
    verify_download_hash(&result.local_path, &result.download_hash)?;
    verify_nar_hash(&result.local_path, &image.nar_hash)
        .with_context(|| format!("verifying image NAR for {}", image.store_path))?;
    import_nar(
        &result.local_path,
        &result.store_path,
        &result.references,
        result.deriver.as_deref(),
    )
    .await?;
    if !store_path.exists() {
        bail!(
            "imported image artifact is absent from its authenticated store path {}",
            store_path.display()
        );
    }
    Ok(store_path)
}

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
/// as [`ConfigGenerationState`] JSON.
pub fn load_generation_state_pub(profile_path: &Path) -> Result<ConfigGenerationState> {
    load_generation_state_readonly(profile_path)
}

/// Recovers interrupted activation journals and then loads generation state.
///
/// The caller must hold the global system switch lock because recovery may
/// publish `state.json` and the `current` pointer.
pub(crate) fn recover_generation_state_pub(profile_path: &Path) -> Result<ConfigGenerationState> {
    load_generation_state(profile_path)
}

/// Persists system-generation state for the configuration activation path.
///
/// This is the write-side companion to [`load_generation_state_pub`]. The
/// caller must hold the system switch lock and must only publish a state whose
/// referenced generation directories are already durable.
///
/// # Errors
///
/// Returns an error when `state.json` cannot be serialized or written.
pub(crate) fn save_generation_state_pub(
    profile_path: &Path,
    state: &ConfigGenerationState,
) -> Result<()> {
    save_generation_state(profile_path, state)
}

pub(crate) fn write_activation_intent_pub(
    profile_path: &Path,
    state: &ConfigGenerationState,
    generation: u32,
) -> Result<String> {
    let nonce = activation_nonce(generation);
    let intent = ActivationIntent {
        generation,
        nonce: nonce.clone(),
        state: state.clone(),
    };
    write_atomic_durable(
        &profile_path.join(ACTIVATION_INTENT),
        &serde_json::to_vec_pretty(&intent)?,
    )?;
    Ok(nonce)
}

fn activation_nonce(generation: u32) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("{generation}-{}-{nanos:x}", std::process::id())
}

pub(crate) fn clear_activation_intent_pub(profile_path: &Path) -> Result<()> {
    remove_file_durable(&profile_path.join(ACTIVATION_INTENT))
}

/// Commits an activated configuration generation as the current generation.
///
/// The activation caller invokes this only after the toplevel activation
/// script has crossed its atomic `/etc` swap point. It persists `state.json`
/// and atomically retargets `current -> gen-N`.
///
/// # Errors
///
/// Returns an error when state persistence or the atomic symlink update fails.
pub(crate) fn commit_current_generation_pub(
    profile_path: &Path,
    state: &mut ConfigGenerationState,
    generation: u32,
) -> Result<()> {
    commit_current_generation(profile_path, state, generation)
}

/// Load system generation state from disk.
fn load_generation_state(profile_path: &Path) -> Result<ConfigGenerationState> {
    recover_activation_intent(profile_path)?;
    recover_generation_commit(profile_path)?;
    crate::clean::recover_config_prune_pub(profile_path)?;
    let state_path = profile_path.join(SYSTEM_STATE_FILE);
    if !state_path.exists() {
        return Ok(ConfigGenerationState {
            current: 0,
            next: 1,
            generations: Vec::new(),
        });
    }
    let content = std::fs::read_to_string(&state_path)
        .with_context(|| format!("reading {}", state_path.display()))?;
    match serde_json::from_str(&content) {
        Ok(state) => Ok(state),
        Err(config_error) => migrate_legacy_generation_state(
            profile_path,
            Path::new(IMAGE_PROFILE_DIR),
            &content,
        )
        .with_context(|| {
            format!(
                "parsing {} as config-generation state failed ({config_error}); authenticated legacy migration also failed",
                state_path.display()
            )
        }),
    }
}

fn migrate_legacy_generation_state(
    profile_path: &Path,
    image_profile: &Path,
    content: &str,
) -> Result<ConfigGenerationState> {
    let legacy: LegacySystemGenerationState =
        serde_json::from_str(content).context("parsing retired system-generation state")?;
    let images = load_image_generation_state_pub(image_profile)
        .context("legacy migration requires an authenticated image-generation index")?;
    let mut generations = Vec::with_capacity(legacy.generations.len());
    for old in legacy.generations {
        let abi = old
            .module_abi_pinned
            .with_context(|| format!("legacy generation {} has no module ABI pin", old.number))?;
        let base_lib_ref = old.base_lib_ref.with_context(|| {
            format!(
                "legacy generation {} has no base-library identity",
                old.number
            )
        })?;
        let matching = images
            .generations
            .iter()
            .filter(|image| {
                image.toplevel == old.toplevel
                    && image.module_abi == abi
                    && image.evaluator_ref == base_lib_ref
                    && old
                        .image_gen_parent
                        .is_none_or(|parent| image.number == parent)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            bail!(
                "legacy generation {} does not authenticate to exactly one image generation",
                old.number
            );
        }
        let parent = matching[0];
        let config_module_closure = old.config_module_closure.with_context(|| {
            format!(
                "legacy generation {} has no config module closure",
                old.number
            )
        })?;
        let config_module_paths = old
            .config_module_paths
            .unwrap_or_else(|| vec![config_module_closure.clone()]);
        let config_module_packages = old.config_module_packages.with_context(|| {
            format!(
                "legacy generation {} has no authenticated config module package identities",
                old.number
            )
        })?;
        if config_module_paths.len() != config_module_packages.len() {
            bail!(
                "legacy generation {} has mismatched module and package identity counts",
                old.number
            );
        }
        let generation = ConfigGeneration {
            number: old.number,
            image_gen_parent: parent.number,
            module_abi_pinned: abi,
            manifest_hash: old.manifest_hash.with_context(|| {
                format!("legacy generation {} has no manifest hash", old.number)
            })?,
            config_module_closure,
            config_module_paths,
            config_module_packages,
            host_nix_ref: old.host_nix_ref.with_context(|| {
                format!(
                    "legacy generation {} has no host.nix content pin",
                    old.number
                )
            })?,
            host_nix_commit: old.host_nix_commit,
            facts_hash: old
                .facts_hash
                .with_context(|| format!("legacy generation {} has no facts hash", old.number))?,
            facts_ref: old.facts_ref.with_context(|| {
                format!("legacy generation {} has no facts store path", old.number)
            })?,
            base_lib_ref,
            evaluator_ref: old.evaluator_ref.with_context(|| {
                format!("legacy generation {} has no evaluator identity", old.number)
            })?,
            created_at: old.created_at,
        };
        validate_generation_manifest(profile_path, &generation)?;
        generations.push(generation);
    }
    if legacy.current != 0
        && !generations
            .iter()
            .any(|generation| generation.number == legacy.current)
    {
        bail!(
            "legacy state names missing current generation {}",
            legacy.current
        );
    }
    let migrated = ConfigGenerationState {
        current: legacy.current,
        next: legacy.next,
        generations,
    };
    save_generation_state(profile_path, &migrated)?;
    Ok(migrated)
}

fn load_generation_state_readonly(profile_path: &Path) -> Result<ConfigGenerationState> {
    let state_path = profile_path.join(SYSTEM_STATE_FILE);
    if !state_path.exists() {
        return Ok(ConfigGenerationState {
            current: 0,
            next: 1,
            generations: Vec::new(),
        });
    }
    let content = std::fs::read_to_string(&state_path)
        .with_context(|| format!("reading {}", state_path.display()))?;
    serde_json::from_str(&content).with_context(|| format!("parsing {}", state_path.display()))
}

fn recover_activation_intent(profile_path: &Path) -> Result<()> {
    let path = profile_path.join(ACTIVATION_INTENT);
    if !path.is_file() {
        return Ok(());
    }
    let intent: ActivationIntent = serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parsing activation intent {}", path.display()))?;
    let live_marker = profile_path
        .join(format!("gen-{}", intent.generation))
        .join(format!(".etc-live-{}", intent.nonce));
    if !live_marker.is_file() {
        // The exact transaction never crossed the /etc swap. Its prepared
        // generation remains available for diagnosis, but it cannot become
        // current and the stale intent must not affect the next switch.
        return remove_file_durable(&path);
    }
    if !intent
        .state
        .generations
        .iter()
        .any(|generation| generation.number == intent.generation)
    {
        bail!(
            "activation intent references unknown generation {}",
            intent.generation
        );
    }
    // Crossing the /etc swap is necessary but no longer sufficient to publish
    // a generation: credential reconciliation, generation attestation, and
    // the transaction-bound activation proof happen afterward. This loader
    // lacks the authenticated inputs needed to resume those phases, so it
    // fails closed and leaves both marker and intent for rescue diagnostics.
    bail!(
        "activation transaction {} crossed the /etc swap without a complete generation proof; rescue mode is required",
        intent.nonce
    )
}

/// Save system generation state to disk.
fn save_generation_state(profile_path: &Path, state: &ConfigGenerationState) -> Result<()> {
    let state_path = profile_path.join(SYSTEM_STATE_FILE);
    let content = serde_json::to_vec_pretty(state)?;
    write_atomic_durable(&state_path, &content)
}

/// Mark `generation` as current: persist it in `state.json` and atomically
/// repoint the `current` symlink (via a temp link + rename). Called only
/// after the generation's activate script has succeeded.
fn commit_current_generation(
    profile_path: &Path,
    state: &mut ConfigGenerationState,
    generation: u32,
) -> Result<()> {
    if !state
        .generations
        .iter()
        .any(|record| record.number == generation)
    {
        bail!("cannot commit unknown system generation {generation}");
    }

    let mut candidate = state.clone();
    candidate.current = generation;
    let journal = GenerationCommitJournal {
        generation,
        state: candidate.clone(),
    };
    let journal_path = profile_path.join(SYSTEM_COMMIT_JOURNAL);
    write_atomic_durable(&journal_path, &serde_json::to_vec_pretty(&journal)?)?;
    publish_current_symlink(profile_path, generation)?;
    save_generation_state(profile_path, &candidate)?;
    remove_commit_journal(profile_path)?;
    clear_activation_intent_pub(profile_path)?;
    *state = candidate;
    Ok(())
}

/// Finishes an interrupted current-generation publication before state is read.
fn recover_generation_commit(profile_path: &Path) -> Result<()> {
    let journal_path = profile_path.join(SYSTEM_COMMIT_JOURNAL);
    if !journal_path.exists() {
        return Ok(());
    }
    let bytes = std::fs::read(&journal_path).with_context(|| {
        format!(
            "reading generation commit journal {}",
            journal_path.display()
        )
    })?;
    let journal: GenerationCommitJournal = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parsing generation commit journal {}",
            journal_path.display()
        )
    })?;
    if journal.state.current != journal.generation
        || !journal
            .state
            .generations
            .iter()
            .any(|record| record.number == journal.generation)
    {
        bail!(
            "generation commit journal {} is internally inconsistent",
            journal_path.display()
        );
    }
    publish_current_symlink(profile_path, journal.generation)?;
    save_generation_state(profile_path, &journal.state)?;
    remove_commit_journal(profile_path)
}

fn publish_current_symlink(profile_path: &Path, generation: u32) -> Result<()> {
    let current_link = profile_path.join("current");
    let tmp_link = profile_path.join(format!(".current.tmp.{}", std::process::id()));
    match std::fs::remove_file(&tmp_link) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("removing {}", tmp_link.display()));
        }
    }
    std::os::unix::fs::symlink(format!("gen-{generation}"), &tmp_link)
        .with_context(|| format!("creating {}", tmp_link.display()))?;
    std::fs::rename(&tmp_link, &current_link).with_context(|| {
        format!(
            "publishing current generation link {} -> gen-{generation}",
            current_link.display()
        )
    })?;
    sync_directory(profile_path)
}

fn remove_commit_journal(profile_path: &Path) -> Result<()> {
    let journal_path = profile_path.join(SYSTEM_COMMIT_JOURNAL);
    match std::fs::remove_file(&journal_path) {
        Ok(()) => sync_directory(profile_path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", journal_path.display())),
    }
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

/// Classifies one unit lifecycle attempt for the activation health result.
///
/// Both a D-Bus error and every terminal result other than `done` degrade the
/// activation. Callers keep iterating so one failed consumer never prevents a
/// later selected consumer from being attempted.
fn reconcile_job_failed<E: std::fmt::Display>(
    printer: &Printer,
    verb: &str,
    unit: &str,
    result: std::result::Result<JobResult, E>,
) -> bool {
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            printer.warning(&format!("  {verb} {unit}: {error}"));
            return true;
        }
    };
    if !result.is_done() {
        printer.warning(&format!(
            "  {verb} {unit}: systemd job result '{}'",
            result.label(),
        ));
        return true;
    }
    false
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
        let _ = reconcile_job_failed(
            printer,
            "stop",
            unit,
            client.stop_unit(unit).await.map(|outcome| outcome.result),
        );
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

    let mut action_failed = false;
    for unit in &plan.to_reload {
        printer.plain(&format!("  reloading  {unit}"));
        action_failed |= reconcile_job_failed(
            printer,
            "reload",
            unit,
            client.reload_unit(unit).await.map(|outcome| outcome.result),
        );
    }

    for unit in &plan.to_restart {
        printer.plain(&format!("  restarting {unit}"));
        action_failed |= reconcile_job_failed(
            printer,
            "restart",
            unit,
            client
                .restart_unit(unit)
                .await
                .map(|outcome| outcome.result),
        );
    }

    for unit in &plan.to_start {
        printer.plain(&format!("  starting   {unit}"));
        action_failed |= reconcile_job_failed(
            printer,
            "start",
            unit,
            client.start_unit(unit).await.map(|outcome| outcome.result),
        );
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

    if action_failed {
        printer.error("one or more daemon reconciliation actions failed");
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
/// units and newly enabled targets into the start list.
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
    if (meta.st_mode & libc::S_IFMT) != libc::S_IFREG {
        bail!("plan {} is not a regular file", path.display());
    }
    if !root_owned_for_runtime(meta.st_uid) {
        bail!("plan {} is not owned by root", path.display());
    }
    let mode = meta.st_mode & 0o777;
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

/// Folds credential-triggered consumer restarts into the post-swap plan.
///
/// A unit already scheduled to start remains a single start. Otherwise a
/// credential change supersedes a reload with one restart. The updated plan
/// is durably replaced before the activation script is allowed to continue.
///
/// # Errors
///
/// Returns an error if the plan fails validation, cannot be serialized, or
/// cannot be replaced durably.
pub(crate) fn augment_reconcile_plan_with_credential_units(
    path: &Path,
    units: &[String],
) -> Result<()> {
    augment_reconcile_plan_with_credential_units_and(path, units, |unit| {
        let output = std::process::Command::new("systemctl")
            .args(["show", "--property=After", "--value", unit])
            .output()
            .with_context(|| format!("querying ordering dependencies of {unit}"))?;
        if !output.status.success() {
            bail!(
                "systemctl failed to query ordering dependencies of {unit}: {}",
                output.status
            );
        }
        Ok(String::from_utf8(output.stdout)
            .with_context(|| format!("reading ordering dependencies of {unit}"))?
            .split_whitespace()
            .map(str::to_string)
            .collect())
    })
}

fn augment_reconcile_plan_with_credential_units_and<F>(
    path: &Path,
    units: &[String],
    after: F,
) -> Result<()>
where
    F: FnMut(&str) -> Result<Vec<String>>,
{
    let parent = path
        .parent()
        .with_context(|| format!("plan {} has no parent", path.display()))?;
    if !cfg!(test) {
        if parent != Path::new(APM_RUN_DIR) {
            bail!(
                "credential reconciliation plan {} is outside {}",
                path.display(),
                APM_RUN_DIR
            );
        }
        validate_secure_dir(parent)?;
    }
    let mut plan = read_validated_plan(path)?;
    let start_units = plan.to_start.iter().collect::<BTreeSet<_>>();
    let credential_restarts = units
        .iter()
        .filter(|unit| !start_units.contains(unit))
        .cloned()
        .collect::<Vec<_>>();
    let credential_restart_set = credential_restarts.iter().collect::<BTreeSet<_>>();
    let restart_insert_at = plan
        .to_restart
        .iter()
        .position(|unit| credential_restart_set.contains(unit))
        .unwrap_or(plan.to_restart.len());

    for unit in units {
        plan.to_reload.retain(|candidate| candidate != unit);
    }
    plan.to_restart
        .retain(|unit| !credential_restart_set.contains(unit));
    let restart_insert_at = restart_insert_at.min(plan.to_restart.len());
    plan.to_restart
        .splice(restart_insert_at..restart_insert_at, credential_restarts);
    deduplicate_units_preserving_order(&mut plan.to_restart);
    plan.to_restart = dependency_order_restart_plan(&plan.to_restart, after)?;
    deduplicate_units_preserving_order(&mut plan.to_reload);
    deduplicate_units_preserving_order(&mut plan.to_restart);
    deduplicate_units_preserving_order(&mut plan.to_start);
    replace_reconcile_plan(path, &plan)
}

fn dependency_order_restart_plan<F>(units: &[String], mut after: F) -> Result<Vec<String>>
where
    F: FnMut(&str) -> Result<Vec<String>>,
{
    let members = units.iter().cloned().collect::<BTreeSet<_>>();
    let mut prerequisites = std::collections::BTreeMap::<String, BTreeSet<String>>::new();
    for unit in units {
        prerequisites.insert(
            unit.clone(),
            after(unit)?
                .into_iter()
                .filter(|dependency| members.contains(dependency))
                .collect(),
        );
    }
    let mut ordered = Vec::with_capacity(units.len());
    let mut remaining = members;
    while !remaining.is_empty() {
        let next = units.iter().find(|unit| {
            remaining.contains(*unit)
                && prerequisites
                    .get(*unit)
                    .is_none_or(|dependencies| dependencies.is_disjoint(&remaining))
        });
        let Some(next) = next else {
            ordered.extend(
                units
                    .iter()
                    .filter(|unit| remaining.contains(*unit))
                    .cloned(),
            );
            break;
        };
        remaining.remove(next);
        ordered.push(next.clone());
    }
    Ok(ordered)
}

fn deduplicate_units_preserving_order(units: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    units.retain(|unit| seen.insert(unit.clone()));
}

fn replace_reconcile_plan(path: &Path, plan: &Plan) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("plan {} has no parent", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("staging updated plan in {}", parent.display()))?;
    serde_json::to_writer(temp.as_file_mut(), plan)
        .context("serializing updated activation plan")?;
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting updated plan mode in {}", parent.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("syncing updated plan in {}", parent.display()))?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("publishing updated plan {}", path.display()))?;
    sync_directory(parent)
}

/// `fstat(2)` the already-open file descriptor, so the metadata check cannot
/// race against a path swap between open and stat.
fn fstat_file(file: &std::fs::File) -> Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` points to valid writable storage and `file` owns a live fd.
    let rc = unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("fstat");
    }
    // SAFETY: fstat returned success, so it initialized the struct.
    Ok(unsafe { stat.assume_init() })
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
        .filter(|img| {
            img.sb_signer_cert_sha256.is_some()
                || !img.sbat.is_empty()
                || img.ukis.iter().any(|uki| {
                    uki.sb_signer_cert_sha256.is_some()
                        || !uki.sbat.is_empty()
                        || uki.expected_pcr11.is_some()
                })
                || !img.recovery_ukis.is_empty()
                || img.recovery_bundle.is_some()
        })
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
    if !img.recovery_ukis.is_empty() && img.ukis.is_empty() {
        bail!("recovery UKI metadata requires slot-specific normal UKI metadata");
    }
    if !img.ukis.is_empty() {
        for uki in &img.ukis {
            validate_uki_secure_boot(img, uki, catalog, db_cert)?;
        }
        for recovery in &img.recovery_ukis {
            validate_recovery_uki_secure_boot(img, recovery, catalog, db_cert)?;
        }
        validate_recovery_bundle_files(img, db_cert)?;
        return Ok(());
    }
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
        if let Some(uki) = find_uki_in_image(&img.store_path)? {
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

fn validate_recovery_bundle_files(
    image: &crate::types::SysrootImageEntry,
    db_cert: Option<&Path>,
) -> Result<()> {
    let Some(bundle) = &image.recovery_bundle else {
        if !image.recovery_ukis.is_empty() {
            bail!("recovery UKIs have no authenticated recovery bundle manifest");
        }
        return Ok(());
    };
    for component in &bundle.components {
        let artifact = image_artifact_path(
            Path::new(&image.store_path),
            Some(&component.path),
            "recovery bundle component",
        )?;
        verify_regular_file(
            &artifact,
            component.byte_size,
            &component.sha256,
            "recovery bundle component",
        )?;
    }
    let store = Path::new(&image.store_path);
    let manifest = image_artifact_path(store, Some("recovery-bundle.json"), "recovery bundle")?;
    let signature = image_artifact_path(
        store,
        Some("recovery-bundle.json.sig"),
        "recovery bundle signature",
    )?;
    if std::fs::metadata(&manifest)?.len() > 256 * 1024
        || std::fs::metadata(&signature)?.len() > 16 * 1024
    {
        bail!("recovery bundle manifest or signature exceeds its size bound");
    }
    let external: crate::types::RecoveryBundleManifest =
        serde_json::from_slice(&std::fs::read(&manifest)?)?;
    if &external != bundle {
        bail!("external recovery bundle manifest disagrees with the signed catalog");
    }
    if let Some(db_cert) = db_cert {
        crate::registry_ops::verify_detached_db_signature(&manifest, &signature, db_cert)?;
    }
    Ok(())
}

fn validate_recovery_uki_secure_boot(
    image: &crate::types::SysrootImageEntry,
    recovery: &RecoveryUkiEntry,
    catalog: &SbCertsToml,
    db_cert: Option<&Path>,
) -> Result<()> {
    if !catalog.accepts_signer(&recovery.sb_signer_cert_sha256) {
        bail!(
            "Secure Boot validation failed for image '{}' recovery {:?}: signer cert {} is not active",
            image.format,
            recovery.copy,
            recovery.sb_signer_cert_sha256
        );
    }
    if let Some((component, found, floor)) = catalog.first_below_floor(&recovery.sbat) {
        bail!(
            "Secure Boot validation failed for image '{}' recovery {:?}: SBAT component '{component}' generation {found} is below floor {floor}",
            image.format,
            recovery.copy
        );
    }
    let artifact = image_artifact_path(
        Path::new(&image.store_path),
        Some(&recovery.path),
        "recovery UKI",
    )?;
    let metadata = std::fs::symlink_metadata(&artifact)?;
    if !metadata.file_type().is_file() || metadata.len() != recovery.byte_size {
        bail!(
            "downloaded recovery UKI for image '{}' copy {:?} has the wrong type or size",
            image.format,
            recovery.copy
        );
    }
    let mut file = std::fs::File::open(&artifact)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hex::encode(hasher.finalize());
    if digest != recovery.sha256 {
        bail!(
            "downloaded recovery UKI for image '{}' copy {:?} has digest {digest}, expected {}",
            image.format,
            recovery.copy,
            recovery.sha256
        );
    }
    if let Some(db_cert) = db_cert {
        reverify_uki(&artifact, db_cert).with_context(|| {
            format!(
                "re-verifying downloaded recovery UKI for image '{}' copy {:?}",
                image.format, recovery.copy
            )
        })?;
    }
    Ok(())
}

fn validate_uki_secure_boot(
    image: &crate::types::SysrootImageEntry,
    uki: &SysrootUkiEntry,
    catalog: &SbCertsToml,
    db_cert: Option<&Path>,
) -> Result<()> {
    let cert = uki.sb_signer_cert_sha256.as_deref().with_context(|| {
        format!(
            "Secure Boot validation failed for image '{}' slot {:?}: no signer cert",
            image.format, uki.slot
        )
    })?;
    if !catalog.accepts_signer(cert) {
        bail!(
            "Secure Boot validation failed for image '{}' slot {:?}: signer cert {cert} is not active",
            image.format,
            uki.slot
        );
    }
    if let Some((component, found, floor)) = catalog.first_below_floor(&uki.sbat) {
        bail!(
            "Secure Boot validation failed for image '{}' slot {:?}: SBAT component '{component}' generation {found} is below floor {floor}",
            image.format,
            uki.slot
        );
    }
    let expected = uki.expected_pcr11.as_deref().with_context(|| {
        format!(
            "Secure Boot validation failed for image '{}' slot {:?}: no expected PCR-11",
            image.format, uki.slot
        )
    })?;
    let artifact = image_artifact_path(Path::new(&image.store_path), Some(&uki.path), "slot UKI")?;
    if let Some(db_cert) = db_cert {
        reverify_uki(&artifact, db_cert).with_context(|| {
            format!(
                "re-verifying downloaded UKI for image '{}' slot {:?}",
                image.format, uki.slot
            )
        })?;
    }
    let actual = crate::registry_ops::extract_expected_pcr11(&artifact)?.with_context(|| {
        format!(
            "downloaded UKI for image '{}' slot {:?} has no calculable PCR-11",
            image.format, uki.slot
        )
    })?;
    if actual != expected {
        bail!(
            "Secure Boot validation failed for image '{}' slot {:?}: measured PCR-11 {actual} does not match catalog {expected}",
            image.format,
            uki.slot
        );
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
fn find_uki_in_image(store_path: &str) -> Result<Option<PathBuf>> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) -> Result<()> {
        let mut entries = std::fs::read_dir(dir)
            .with_context(|| format!("reading image artifact {}", dir.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found)?;
            } else if path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("efi"))
            {
                found.push(path);
            }
        }
        Ok(())
    }
    let root = Path::new(store_path);
    if root.is_file() {
        return Ok(root
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("efi"))
            .then(|| root.to_path_buf()));
    }
    let mut found = Vec::new();
    walk(root, &mut found)?;
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        count => bail!(
            "legacy image artifact {store_path} contains {count} UKIs; deterministic selection requires slot metadata"
        ),
    }
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
            delivery: crate::types::test_image_delivery("raw"),
            sb_signer_cert_sha256: Some(signer.into()),
            sbat: sb_sbat(sbat),
            expected_pcr11: None,
            ukis: Vec::new(),
            recovery_ukis: Vec::new(),
            recovery_bundle: None,
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

    fn running_identity_fixture() -> (TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let image_profile = tmp.path().join("image");
        let toplevel = tmp.path().join("toplevel");
        let toplevel_link = tmp.path().join("aos-toplevel");
        let cmdline = tmp.path().join("cmdline");
        std::fs::create_dir_all(image_profile.as_path()).unwrap();
        std::fs::create_dir_all(toplevel.join("meta")).unwrap();
        std::fs::write(toplevel.join("meta/module-abi"), "7").unwrap();
        std::fs::write(toplevel.join("meta/baselib-digest"), "sha256:base").unwrap();
        std::fs::write(
            toplevel.join("meta/uki-path"),
            "EFI/Linux/aos-server-1+3.efi",
        )
        .unwrap();
        std::fs::write(toplevel.join("meta/package-name"), "server").unwrap();
        std::fs::write(toplevel.join("meta/version"), "1").unwrap();
        std::os::unix::fs::symlink("/nix/store/base-lib", toplevel.join("base-lib")).unwrap();
        std::fs::write(
            toplevel.join("os-release"),
            "VERSION_ID=1\nAOS_MODULE_ABI=7\nAOS_BASELIB_DIGEST=sha256:base\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&toplevel, &toplevel_link).unwrap();
        std::fs::write(
            &cmdline,
            "quiet root=/dev/disk/by-partlabel/root-a roothash=deadbeef\n",
        )
        .unwrap();
        let state = ImageGenerationState {
            running: 1,
            default: 1,
            pending: Some(1),
            recovery_known_good: None,
            recovery_pending: None,
            generations: vec![ImageGeneration {
                number: 1,
                slot: ImageSlot::A,
                uki_path: "EFI/Linux/aos-server-1+3.efi".into(),
                uki_source_path: None,
                toplevel: toplevel.to_string_lossy().into_owned(),
                package_name: "server".into(),
                version: "1".into(),
                registry: "test".into(),
                kernel_path: None,
                evaluator_ref: "/nix/store/base-lib".into(),
                module_abi: 7,
                baselib_digest: "sha256:base".into(),
                root_verity_roothash: Some("deadbeef".into()),
                expected_pcr11: Some("abcd".into()),
                initrd_pcr11: None,
                recovery: None,
                created_at: "2026-08-04T00:00:00Z".into(),
            }],
        };
        std::fs::write(
            image_profile.join("state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        let os_release = toplevel_link.join("os-release");
        (tmp, image_profile, toplevel_link, os_release, cmdline)
    }

    #[test]
    fn running_image_rejects_tampered_var_index_metadata() {
        let (_tmp, image_profile, toplevel_link, os_release, cmdline) = running_identity_fixture();
        let loaded = load_running_image_generation_from(
            &image_profile,
            &os_release,
            &toplevel_link,
            &cmdline,
        )
        .unwrap();
        assert_eq!(loaded.module_abi, 7);

        let state_path = image_profile.join("state.json");
        let mut state: ImageGenerationState =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        state.generations[0].uki_path = "EFI/Linux/attacker.efi".into();
        std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        let error = load_running_image_generation_from(
            &image_profile,
            &os_release,
            &toplevel_link,
            &cmdline,
        )
        .unwrap_err();
        assert!(error.to_string().contains("immutable toplevel metadata"));
    }

    #[test]
    fn running_image_authenticates_the_canonical_uki_source_path() {
        let (_tmp, image_profile, toplevel_link, os_release, cmdline) = running_identity_fixture();
        let state_path = image_profile.join("state.json");
        let mut state: ImageGenerationState =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        state.generations[0].uki_path = "EFI/Linux/aos-generation-0000000001+3.efi".into();
        state.generations[0].uki_source_path = Some("EFI/Linux/aos-server-1+3.efi".into());
        std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();

        let loaded = load_running_image_generation_from(
            &image_profile,
            &os_release,
            &toplevel_link,
            &cmdline,
        )
        .unwrap();
        assert_eq!(loaded.uki_path, "EFI/Linux/aos-generation-0000000001+3.efi");

        state.generations[0].uki_source_path = Some("EFI/Linux/attacker+3.efi".into());
        std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        let error = load_running_image_generation_from(
            &image_profile,
            &os_release,
            &toplevel_link,
            &cmdline,
        )
        .unwrap_err();
        assert!(error.to_string().contains("immutable toplevel metadata"));
    }

    #[test]
    fn running_image_rejects_tampered_roothash_and_slot() {
        let (_tmp, image_profile, toplevel_link, os_release, cmdline) = running_identity_fixture();
        std::fs::write(
            &cmdline,
            "root=/dev/disk/by-partlabel/root-b roothash=bad\n",
        )
        .unwrap();
        let error = load_running_image_generation_from(
            &image_profile,
            &os_release,
            &toplevel_link,
            &cmdline,
        )
        .unwrap_err();
        assert!(error.to_string().contains("roothash"));

        std::fs::write(
            &cmdline,
            "root=/dev/mapper/root systemd.verity_root_data=/dev/disk/by-partlabel/root-b roothash=deadbeef\n",
        )
        .unwrap();
        let error = load_running_image_generation_from(
            &image_profile,
            &os_release,
            &toplevel_link,
            &cmdline,
        )
        .unwrap_err();
        assert!(error.to_string().contains("root slot"));
    }

    #[test]
    fn running_image_allows_repeatable_non_identity_kernel_parameters() {
        let (_tmp, image_profile, toplevel_link, os_release, cmdline) = running_identity_fixture();
        std::fs::write(
            &cmdline,
            "console=ttyS0,115200 console=tty0 root=/dev/disk/by-partlabel/root-a roothash=deadbeef\n",
        )
        .unwrap();
        load_running_image_generation_from(&image_profile, &os_release, &toplevel_link, &cmdline)
            .unwrap();

        std::fs::write(
            &cmdline,
            "root=/dev/disk/by-partlabel/root-a roothash=deadbeef roothash=bad\n",
        )
        .unwrap();
        let error = load_running_image_generation_from(
            &image_profile,
            &os_release,
            &toplevel_link,
            &cmdline,
        )
        .unwrap_err();
        assert!(error.to_string().contains("repeats roothash"));
    }

    #[test]
    fn inactive_slot_staging_does_not_mutate_running_slot() {
        let tmp = TempDir::new().unwrap();
        let boot = tmp.path().join("boot");
        let image_store = tmp.path().join("image");
        let root_a = tmp.path().join("root-a");
        let root_b = tmp.path().join("root-b");
        let hash_a = tmp.path().join("root-a-hash");
        let hash_b = tmp.path().join("root-b-hash");
        std::fs::create_dir_all(&image_store).unwrap();
        std::fs::write(&root_a, vec![b'A'; 64]).unwrap();
        std::fs::write(&root_b, vec![b'b'; 64]).unwrap();
        std::fs::write(&hash_a, vec![b'H'; 64]).unwrap();
        std::fs::write(&hash_b, vec![b'h'; 64]).unwrap();
        std::fs::write(image_store.join("root.img"), b"new-root").unwrap();
        std::fs::write(image_store.join("root.verity"), b"new-verity").unwrap();
        std::fs::write(image_store.join("root.roothash"), b"deadbeef\n").unwrap();
        std::fs::write(image_store.join("uki-a.efi"), b"uki-a").unwrap();
        std::fs::write(image_store.join("uki-b.efi"), b"uki-b").unwrap();
        let layout = ImageSlotLayout {
            boot_root: &boot,
            root_a: &root_a,
            root_b: &root_b,
            root_a_hash: &hash_a,
            root_b_hash: &hash_b,
        };
        let mut image = signed_image(SIGNER_ACTIVE, &[("aos", 2)]);
        image.sb_signer_cert_sha256 = None;
        image.sbat.clear();
        image.ukis = vec![
            SysrootUkiEntry {
                slot: UkiSlot::A,
                path: "uki-a.efi".into(),
                sb_signer_cert_sha256: Some(SIGNER_ACTIVE.into()),
                sbat: sb_sbat(&[("aos", 2)]),
                expected_pcr11: Some("pcr-a".into()),
            },
            SysrootUkiEntry {
                slot: UkiSlot::B,
                path: "uki-b.efi".into(),
                sb_signer_cert_sha256: Some(SIGNER_ACTIVE.into()),
                sbat: sb_sbat(&[("aos", 2)]),
                expected_pcr11: Some("pcr-b".into()),
            },
        ];
        image.root_image = Some("root.img".into());
        image.root_verity = Some("root.verity".into());
        image.root_hash = Some("deadbeef".into());

        stage_slot_artifacts(
            &layout,
            ImageSlot::B,
            &image_store,
            &image,
            "EFI/Linux/aos-next+3.efi",
            &[],
            None,
        )
        .unwrap();

        assert_eq!(std::fs::read(&root_a).unwrap(), vec![b'A'; 64]);
        assert_eq!(std::fs::read(&hash_a).unwrap(), vec![b'H'; 64]);
        assert!(std::fs::read(&root_b).unwrap().starts_with(b"new-root"));
        assert!(std::fs::read(&hash_b).unwrap().starts_with(b"new-verity"));
        assert_eq!(
            std::fs::read(boot.join("EFI/Linux/aos-next+3.efi")).unwrap(),
            b"uki-b"
        );
    }

    #[test]
    fn every_publication_cut_retains_the_opposite_recovery_copy() {
        let checkpoints = [
            StageCheckpoint::InactiveEntryDisarmed,
            StageCheckpoint::RootWritten,
            StageCheckpoint::VerityWritten,
            StageCheckpoint::NormalUkiStaged,
            StageCheckpoint::RecoveryUkiPublished,
            StageCheckpoint::RecoveryEntryPublished,
            StageCheckpoint::NormalUkiPublished,
        ];
        for (target_slot, target_name, opposite_name) in
            [(ImageSlot::A, "a", "b"), (ImageSlot::B, "b", "a")]
        {
            for cut in checkpoints {
                let tmp = TempDir::new().unwrap();
                let boot = tmp.path().join("boot");
                let image_store = tmp.path().join("image");
                let linux = boot.join("EFI/Linux");
                let recovery_dir = boot.join("EFI/AOS");
                let entry_dir = boot.join("loader/entries");
                std::fs::create_dir_all(&image_store).unwrap();
                std::fs::create_dir_all(&linux).unwrap();
                std::fs::create_dir_all(&recovery_dir).unwrap();
                std::fs::create_dir_all(&entry_dir).unwrap();

                let root_a = tmp.path().join("root-a");
                let root_b = tmp.path().join("root-b");
                let hash_a = tmp.path().join("root-a-hash");
                let hash_b = tmp.path().join("root-b-hash");
                for path in [&root_a, &root_b, &hash_a, &hash_b] {
                    std::fs::write(path, vec![0_u8; 128]).unwrap();
                }
                std::fs::write(image_store.join("root.img"), b"new-root").unwrap();
                std::fs::write(image_store.join("root.verity"), b"new-verity").unwrap();
                std::fs::write(image_store.join("root.roothash"), b"deadbeef\n").unwrap();
                std::fs::write(image_store.join("uki-a.efi"), b"normal-a").unwrap();
                std::fs::write(image_store.join("uki-b.efi"), b"normal-b").unwrap();
                let recovery_bytes = format!("new-recovery-{target_name}").into_bytes();
                std::fs::write(
                    image_store.join(format!("recovery-{target_name}.efi")),
                    &recovery_bytes,
                )
                .unwrap();
                std::fs::write(
                image_store.join(format!("recovery-{target_name}.conf")),
                format!(
                    "title AOS Recovery {target_name}\nefi /EFI/AOS/recovery-{target_name}.efi\n"
                ),
            )
            .unwrap();
                let known_good = format!("known-good-recovery-{opposite_name}").into_bytes();
                std::fs::write(
                    recovery_dir.join(format!("recovery-{opposite_name}.efi")),
                    &known_good,
                )
                .unwrap();
                std::fs::write(
                    recovery_dir.join(format!("recovery-{target_name}.efi")),
                    format!("old-recovery-{target_name}"),
                )
                .unwrap();
                let reusable = linux.join(format!("old-{target_name}+3.efi"));
                std::fs::write(&reusable, format!("old-normal-{target_name}")).unwrap();

                let layout = ImageSlotLayout {
                    boot_root: &boot,
                    root_a: &root_a,
                    root_b: &root_b,
                    root_a_hash: &hash_a,
                    root_b_hash: &hash_b,
                };
                let mut image = signed_image(SIGNER_ACTIVE, &[("aos", 2)]);
                image.root_image = Some("root.img".into());
                image.root_verity = Some("root.verity".into());
                image.root_hash = Some("deadbeef".into());
                image.ukis = vec![
                    SysrootUkiEntry {
                        slot: UkiSlot::A,
                        path: "uki-a.efi".into(),
                        sb_signer_cert_sha256: Some(SIGNER_ACTIVE.into()),
                        sbat: sb_sbat(&[("aos", 2)]),
                        expected_pcr11: Some("a".repeat(64)),
                    },
                    SysrootUkiEntry {
                        slot: UkiSlot::B,
                        path: "uki-b.efi".into(),
                        sb_signer_cert_sha256: Some(SIGNER_ACTIVE.into()),
                        sbat: sb_sbat(&[("aos", 2)]),
                        expected_pcr11: Some("b".repeat(64)),
                    },
                ];
                let recovery = crate::types::RecoveryGeneration {
                    copy: target_slot,
                    uki_path: format!("EFI/AOS/recovery-{target_name}.efi"),
                    entry_path: format!("loader/entries/recovery-{target_name}.conf"),
                    source_path: format!("recovery-{target_name}.efi"),
                    sha256: hex::encode(Sha256::digest(&recovery_bytes)),
                    byte_size: recovery_bytes.len() as u64,
                    release: "2".into(),
                    recovery_abi: 1,
                };

                let error = stage_slot_artifacts_with(
                    &layout,
                    target_slot,
                    &image_store,
                    &image,
                    &format!("EFI/Linux/aos-next-{target_name}+3.efi"),
                    std::slice::from_ref(&reusable),
                    Some(&recovery),
                    |checkpoint| {
                        if checkpoint == cut {
                            bail!("injected power cut at {checkpoint:?}");
                        }
                        Ok(())
                    },
                )
                .unwrap_err();
                assert!(error.to_string().contains("injected power cut"));
                assert_eq!(
                    std::fs::read(recovery_dir.join(format!("recovery-{opposite_name}.efi")))
                        .unwrap(),
                    known_good,
                    "{target_name} update cut {cut:?} changed the opposite recovery copy"
                );
                let candidate = linux.join(format!("aos-next-{target_name}+3.efi"));
                assert_eq!(
                    candidate.exists(),
                    cut == StageCheckpoint::NormalUkiPublished,
                    "{target_name} update cut {cut:?} exposed the candidate at the wrong boundary"
                );

                let replay_visible = if candidate.exists() {
                    vec![candidate.clone()]
                } else {
                    Vec::new()
                };
                stage_slot_artifacts_with(
                    &layout,
                    target_slot,
                    &image_store,
                    &image,
                    &format!("EFI/Linux/aos-next-{target_name}+3.efi"),
                    &replay_visible,
                    Some(&recovery),
                    |_| Ok(()),
                )
                .unwrap_or_else(|error| {
                    panic!("{target_name} retry after {cut:?} failed: {error:#}")
                });
                assert!(candidate.is_file());
                let disabled_prefix = format!("disabled-{target_name}-");
                assert!(
                    std::fs::read_dir(boot.join("EFI/.aos-staging"))
                        .unwrap()
                        .all(|entry| !entry
                            .unwrap()
                            .file_name()
                            .to_string_lossy()
                            .starts_with(&disabled_prefix)),
                    "{target_name} retry after {cut:?} left a disabled UKI"
                );
            }
        }
    }

    #[test]
    fn inactive_slot_writer_follows_by_partlabel_style_symlinks() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("root.img");
        let target = tmp.path().join("root-b-device");
        let by_partlabel = tmp.path().join("root-b");
        std::fs::write(&source, b"new-root").unwrap();
        std::fs::write(&target, vec![b'x'; 64]).unwrap();
        std::os::unix::fs::symlink(&target, &by_partlabel).unwrap();

        copy_payload_to_slot(&source, &by_partlabel).unwrap();

        assert!(std::fs::read(&target).unwrap().starts_with(b"new-root"));
    }

    #[test]
    fn writable_boot_bracket_restores_read_only_after_failure() {
        let tmp = TempDir::new().unwrap();
        let events = std::cell::RefCell::new(Vec::new());
        let error = with_writable_boot_using(
            tmp.path(),
            |_path, writable| {
                events.borrow_mut().push(if writable { "rw" } else { "ro" });
                Ok(())
            },
            || -> Result<()> {
                events.borrow_mut().push("action");
                bail!("injected staging failure")
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("injected staging failure"));
        assert_eq!(*events.borrow(), ["rw", "action", "ro"]);
    }

    #[test]
    fn writable_boot_validation_requires_the_expected_esp_device() {
        let tmp = TempDir::new().unwrap();
        let boot = tmp.path().join("boot");
        let devices = tmp.path().join("devices");
        std::fs::create_dir_all(&boot).unwrap();
        std::fs::create_dir_all(&devices).unwrap();
        let esp = devices.join("esp-device");
        let wrong = devices.join("wrong-device");
        std::fs::write(&esp, b"esp").unwrap();
        std::fs::write(&wrong, b"wrong").unwrap();
        let boot_mountpoint = std::fs::canonicalize(&boot).unwrap();
        let expected = devices.join("ESP");
        std::os::unix::fs::symlink(&esp, &expected).unwrap();
        let mountinfo = tmp.path().join("mountinfo");
        std::fs::write(
            &mountinfo,
            format!(
                "31 24 254:1 / {} ro,relatime - vfat {} rw\n",
                boot_mountpoint.display(),
                esp.display()
            ),
        )
        .unwrap();

        validate_boot_esp_mount(&boot, &mountinfo, &expected, false).unwrap();

        std::fs::write(
            &mountinfo,
            format!(
                "31 24 254:2 / {} ro,relatime - vfat {} rw\n",
                boot_mountpoint.display(),
                wrong.display()
            ),
        )
        .unwrap();
        let error = validate_boot_esp_mount(&boot, &mountinfo, &expected, false).unwrap_err();
        assert!(error.to_string().contains("expected"));

        std::fs::write(
            &mountinfo,
            format!(
                "31 24 254:1 /subdir {} ro,relatime - vfat {} rw\n",
                boot_mountpoint.display(),
                esp.display()
            ),
        )
        .unwrap();
        let error = validate_boot_esp_mount(&boot, &mountinfo, &expected, false).unwrap_err();
        assert!(error.to_string().contains("bind/subtree"));

        std::fs::write(
            &mountinfo,
            format!(
                "31 24 254:1 / {} ro,relatime - ext4 {} rw\n",
                boot_mountpoint.display(),
                esp.display()
            ),
        )
        .unwrap();
        let error = validate_boot_esp_mount(&boot, &mountinfo, &expected, false).unwrap_err();
        assert!(error.to_string().contains("expected vfat"));

        std::fs::write(
            &mountinfo,
            format!(
                "31 24 254:1 / {} ro,relatime - vfat {} rw\n",
                boot_mountpoint.display(),
                esp.display()
            ),
        )
        .unwrap();
        let error = validate_boot_esp_mount(&boot, &mountinfo, &expected, true).unwrap_err();
        assert!(error.to_string().contains("block devices"));
    }

    #[test]
    fn replaced_slot_ukis_are_cleaned_only_after_new_entry_is_kept() {
        let tmp = TempDir::new().unwrap();
        let boot = tmp.path().join("boot");
        let linux = boot.join("EFI/Linux");
        let disabled = boot.join("EFI/.aos-disabled");
        std::fs::create_dir_all(&linux).unwrap();
        std::fs::create_dir_all(&disabled).unwrap();
        for name in ["aos-old-1+3.efi", "aos-old-2.efi", "aos-new+3.efi"] {
            std::fs::write(linux.join(name), name.as_bytes()).unwrap();
        }
        std::fs::write(disabled.join("image-gen-1-uki"), b"disabled").unwrap();
        let generation = |number, uki_path: &str| ImageGeneration {
            number,
            slot: ImageSlot::B,
            uki_path: format!("EFI/Linux/{uki_path}"),
            uki_source_path: None,
            toplevel: format!("/nix/store/top-{number}"),
            package_name: "aos".into(),
            version: number.to_string(),
            registry: "core".into(),
            kernel_path: None,
            evaluator_ref: format!("/nix/store/base-{number}"),
            module_abi: 1,
            baselib_digest: format!("digest-{number}"),
            root_verity_roothash: Some(format!("root-{number}")),
            expected_pcr11: Some(format!("pcr-{number}")),
            initrd_pcr11: None,
            recovery: None,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let state = ImageGenerationState {
            running: 1,
            default: 3,
            pending: Some(3),
            recovery_known_good: None,
            recovery_pending: None,
            generations: vec![
                generation(1, "aos-old-1+3.efi"),
                generation(2, "aos-old-2+3.efi"),
                generation(3, "aos-new+3.efi"),
            ],
        };
        let root_a = tmp.path().join("root-a");
        let root_b = tmp.path().join("root-b");
        let hash_a = tmp.path().join("root-a-hash");
        let hash_b = tmp.path().join("root-b-hash");
        let layout = ImageSlotLayout {
            boot_root: &boot,
            root_a: &root_a,
            root_b: &root_b,
            root_a_hash: &hash_a,
            root_b_hash: &hash_b,
        };

        cleanup_replaced_slot_ukis(&layout, &state, ImageSlot::B, "EFI/Linux/aos-new+3.efi")
            .unwrap();

        assert!(!linux.join("aos-old-1+3.efi").exists());
        assert!(!linux.join("aos-old-2.efi").exists());
        assert!(linux.join("aos-new+3.efi").is_file());
        assert!(!disabled.exists());
    }

    #[test]
    fn incomplete_slot_payload_fails_before_mutating_inactive_root() {
        let tmp = TempDir::new().unwrap();
        let boot = tmp.path().join("boot");
        let image_store = tmp.path().join("image");
        let root_a = tmp.path().join("root-a");
        let root_b = tmp.path().join("root-b");
        let hash_a = tmp.path().join("root-a-hash");
        let hash_b = tmp.path().join("root-b-hash");
        std::fs::create_dir_all(&image_store).unwrap();
        for path in [&root_a, &root_b, &hash_a, &hash_b] {
            std::fs::write(path, vec![b'x'; 64]).unwrap();
        }
        std::fs::write(image_store.join("root.img"), b"new-root").unwrap();
        std::fs::write(image_store.join("root.verity"), b"new-verity").unwrap();
        std::fs::write(image_store.join("uki-b.efi"), b"uki-b").unwrap();
        let layout = ImageSlotLayout {
            boot_root: &boot,
            root_a: &root_a,
            root_b: &root_b,
            root_a_hash: &hash_a,
            root_b_hash: &hash_b,
        };
        let mut image = signed_image(SIGNER_ACTIVE, &[("aos", 2)]);
        image.sb_signer_cert_sha256 = None;
        image.sbat.clear();
        image.ukis = vec![
            SysrootUkiEntry {
                slot: UkiSlot::A,
                path: "uki-a.efi".into(),
                sb_signer_cert_sha256: Some(SIGNER_ACTIVE.into()),
                sbat: sb_sbat(&[("aos", 2)]),
                expected_pcr11: Some("pcr-a".into()),
            },
            SysrootUkiEntry {
                slot: UkiSlot::B,
                path: "uki-b.efi".into(),
                sb_signer_cert_sha256: Some(SIGNER_ACTIVE.into()),
                sbat: sb_sbat(&[("aos", 2)]),
                expected_pcr11: Some("pcr-b".into()),
            },
        ];
        image.root_image = Some("root.img".into());
        image.root_verity = Some("root.verity".into());

        let error = stage_slot_artifacts(
            &layout,
            ImageSlot::B,
            &image_store,
            &image,
            "EFI/Linux/aos-next+3.efi",
            &[],
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("incomplete"));
        assert_eq!(std::fs::read(&root_b).unwrap(), vec![b'x'; 64]);
        assert!(!boot.join("EFI/Linux/aos-next+3.efi").exists());
    }

    #[test]
    fn evaluator_copy_up_is_physical_after_lower_disappears() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source-store-path");
        let upper = tmp.path().join("upper-store");
        std::fs::create_dir_all(source.join("bin")).unwrap();
        let executable = source.join("bin/aos-eval");
        std::fs::write(&executable, b"evaluator").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::os::unix::fs::symlink("aos-eval", source.join("bin/eval-link")).unwrap();

        copy_store_tree_to_upper(&source, &upper).unwrap();
        std::fs::remove_dir_all(&source).unwrap();

        let retained = upper.join("source-store-path/bin/aos-eval");
        assert_eq!(std::fs::read(&retained).unwrap(), b"evaluator");
        assert_eq!(
            std::fs::metadata(&retained).unwrap().permissions().mode() & 0o777,
            0o555
        );
        assert_eq!(
            std::fs::read_link(upper.join("source-store-path/bin/eval-link")).unwrap(),
            PathBuf::from("aos-eval")
        );
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
            delivery: crate::types::test_image_delivery("raw"),
            sb_signer_cert_sha256: None,
            sbat: vec![],
            expected_pcr11: None,
            ukis: Vec::new(),
            recovery_ukis: Vec::new(),
            recovery_bundle: None,
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
        let generation = |number, created_at: &str| ConfigGeneration {
            number,
            image_gen_parent: 1,
            module_abi_pinned: 1,
            manifest_hash: format!("sha256:manifest-{number}"),
            config_module_closure: format!("/nix/store/config-{number}"),
            config_module_paths: vec![format!("/nix/store/config-{number}")],
            config_module_packages: vec!["server".into()],
            host_nix_ref: format!("/nix/store/host-{number}"),
            host_nix_commit: None,
            facts_hash: format!("sha256:facts-{number}"),
            facts_ref: format!("/nix/store/facts-{number}"),
            base_lib_ref: "/nix/store/base".into(),
            evaluator_ref: "/nix/store/evaluator".into(),
            created_at: created_at.into(),
        };
        let state = ConfigGenerationState {
            current: 2,
            next: 3,
            generations: vec![
                generation(1, "2026-03-01T00:00:00Z"),
                generation(2, "2026-04-01T00:00:00Z"),
            ],
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let parsed: ConfigGenerationState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.current, 2);
        assert_eq!(parsed.next, 3);
        assert_eq!(parsed.generations.len(), 2);
        assert_eq!(parsed.generations[1].image_gen_parent, 1);
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
        let state = ConfigGenerationState {
            current: 1,
            next: 2,
            generations: vec![ConfigGeneration {
                number: 1,
                created_at: "2026-01-01T00:00:00Z".into(),
                image_gen_parent: 1,
                module_abi_pinned: 1,
                manifest_hash: "sha256:manifest".into(),
                config_module_closure: "/nix/store/config".into(),
                config_module_paths: vec!["/nix/store/config".into()],
                config_module_packages: vec!["server".into()],
                host_nix_ref: "/nix/store/host".into(),
                host_nix_commit: None,
                facts_hash: "sha256:facts".into(),
                facts_ref: "/nix/store/facts".into(),
                base_lib_ref: "/nix/store/base".into(),
                evaluator_ref: "/nix/store/evaluator".into(),
            }],
        };
        save_generation_state(tmp.path(), &state).unwrap();
        let loaded = load_generation_state(tmp.path()).unwrap();
        assert_eq!(loaded.current, 1);
        assert_eq!(loaded.generations.len(), 1);
    }

    #[test]
    fn authenticated_legacy_state_migrates_to_config_only_shape() {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("system");
        let image_profile = root.path().join("image");
        std::fs::create_dir_all(profile.join("gen-1")).unwrap();
        std::fs::create_dir_all(&image_profile).unwrap();
        let manifest_text = include_str!("../tests/fixtures/config_manifest/manifest.json");
        let manifest: crate::config_eval::materialize::ConfigManifest =
            serde_json::from_str(manifest_text).unwrap();
        manifest.validate().unwrap();
        std::fs::write(profile.join("gen-1/manifest.json"), manifest_text).unwrap();
        let manifest_hash =
            crate::graph_compile::reproject::hash_cjson(&serde_json::to_value(&manifest).unwrap());
        let base = manifest.inputs.base_lib.store_path.clone();
        let evaluator = manifest.inputs.evaluator.store_path.clone();
        let modules = manifest.inputs.config_modules.store_paths.clone();
        let packages = manifest.inputs.config_modules.package_names.clone();
        let host = manifest.inputs.host_nix.store_path.clone();
        let facts_hash = manifest.inputs.instance_facts.facts_hash.clone();
        let facts_ref = manifest.inputs.instance_facts.store_path.clone();
        let top = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system";
        let images = ImageGenerationState {
            running: 4,
            default: 4,
            pending: None,
            recovery_known_good: None,
            recovery_pending: None,
            generations: vec![ImageGeneration {
                number: 4,
                slot: ImageSlot::A,
                uki_path: "EFI/Linux/aos+3.efi".into(),
                uki_source_path: None,
                toplevel: top.into(),
                package_name: "aos-system".into(),
                version: "1".into(),
                registry: "core".into(),
                kernel_path: None,
                evaluator_ref: base.clone(),
                module_abi: manifest.module_abi,
                baselib_digest: format!("sha256:{}", "a".repeat(64)),
                root_verity_roothash: None,
                expected_pcr11: None,
                initrd_pcr11: None,
                recovery: None,
                created_at: "2026-01-01T00:00:00Z".into(),
            }],
        };
        std::fs::write(
            image_profile.join(IMAGE_STATE_FILE),
            serde_json::to_vec(&images).unwrap(),
        )
        .unwrap();
        let legacy = serde_json::json!({
            "current": 1,
            "next": 2,
            "generations": [{
                "number": 1,
                "toplevel": top,
                "created_at": "2026-01-01T00:00:00Z",
                "image_gen_parent": 4,
                "module_abi_pinned": manifest.module_abi,
                "manifest_hash": manifest_hash,
                "config_module_closure": modules[0],
                "config_module_paths": modules,
                "config_module_packages": packages,
                "host_nix_ref": host,
                "facts_hash": facts_hash,
                "facts_ref": facts_ref,
                "base_lib_ref": base,
                "evaluator_ref": evaluator
            }]
        });
        let migrated = migrate_legacy_generation_state(
            &profile,
            &image_profile,
            &serde_json::to_string(&legacy).unwrap(),
        )
        .unwrap();
        assert_eq!(migrated.current, 1);
        assert_eq!(migrated.generations[0].image_gen_parent, 4);
        let persisted: serde_json::Value =
            serde_json::from_slice(&std::fs::read(profile.join(SYSTEM_STATE_FILE)).unwrap())
                .unwrap();
        assert!(persisted["generations"][0].get("toplevel").is_none());
        assert_eq!(persisted["generations"][0]["manifest_hash"], manifest_hash);
    }

    #[test]
    fn incomplete_legacy_state_migration_fails_without_publication() {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("system");
        let image_profile = root.path().join("image");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(&image_profile).unwrap();
        let legacy = r#"{"current":1,"next":2,"generations":[{"number":1,"toplevel":"/nix/store/missing","created_at":"2026-01-01T00:00:00Z"}]}"#;
        std::fs::write(profile.join(SYSTEM_STATE_FILE), legacy).unwrap();
        let error = migrate_legacy_generation_state(&profile, &image_profile, legacy).unwrap_err();
        assert!(error.to_string().contains("image-generation index"));
        assert_eq!(
            std::fs::read_to_string(profile.join(SYSTEM_STATE_FILE)).unwrap(),
            legacy
        );
    }

    #[test]
    fn commit_publishes_state_and_current_link_consistently() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = generation_state_for_commit();
        save_generation_state(tmp.path(), &state).unwrap();

        commit_current_generation(tmp.path(), &mut state, 2).unwrap();

        let loaded = load_generation_state(tmp.path()).unwrap();
        assert_eq!(loaded.current, 2);
        assert_eq!(
            std::fs::read_link(tmp.path().join("current")).unwrap(),
            PathBuf::from("gen-2")
        );
        assert!(!tmp.path().join(SYSTEM_COMMIT_JOURNAL).exists());
    }

    #[test]
    fn load_recovers_an_interrupted_generation_commit() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = generation_state_for_commit();
        save_generation_state(tmp.path(), &state).unwrap();
        let mut candidate = state;
        candidate.current = 2;
        let journal = GenerationCommitJournal {
            generation: 2,
            state: candidate,
        };
        std::fs::write(
            tmp.path().join(SYSTEM_COMMIT_JOURNAL),
            serde_json::to_vec_pretty(&journal).unwrap(),
        )
        .unwrap();

        let loaded = load_generation_state(tmp.path()).unwrap();

        assert_eq!(loaded.current, 2);
        assert_eq!(
            loaded.generations[1].config_module_paths,
            [
                "/nix/store/cfg-a-2".to_string(),
                "/nix/store/cfg-b-2".to_string(),
            ]
        );
        assert_eq!(
            std::fs::read_link(tmp.path().join("current")).unwrap(),
            PathBuf::from("gen-2")
        );
        assert!(!tmp.path().join(SYSTEM_COMMIT_JOURNAL).exists());
    }

    #[test]
    fn same_abi_config_rollback_uses_running_image_activator() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = generation_state_for_commit();
        save_generation_state(tmp.path(), &state).unwrap();
        let target = state.generations[1].clone();
        let printer = Printer::new(0, true, false);

        direct_reactivate_config_generation_with(
            tmp.path(),
            &mut state,
            Path::new("/nix/store/test-generation-1"),
            &target,
            &printer,
            |activate, number, _nonce, barrier| {
                assert_eq!(activate, Path::new("/nix/store/test-generation-1/activate"));
                assert_eq!(number, 2);
                barrier(
                    crate::config_eval::activation::CredentialBarrier::StagedView(Path::new(
                        "/run/etc/candidate",
                    )),
                )?;
                barrier(crate::config_eval::activation::CredentialBarrier::Publish(
                    Path::new("/run/apm/test-plan.json"),
                ))?;
                Ok(Some(0))
            },
            |_plan| Ok(()),
            || Ok(()),
            |_activation_exit| Ok(()),
        )
        .unwrap();

        assert_eq!(state.current, 2);
        assert_eq!(
            std::fs::read_link(tmp.path().join("current")).unwrap(),
            PathBuf::from("gen-2")
        );
    }

    #[test]
    fn same_abi_rollback_credential_failure_refuses_pointer_and_evidence() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = generation_state_for_commit();
        save_generation_state(tmp.path(), &state).unwrap();
        let target = state.generations[1].clone();
        let printer = Printer::new(0, true, false);
        let evidence_published = std::cell::Cell::new(false);

        let error = direct_reactivate_config_generation_with(
            tmp.path(),
            &mut state,
            Path::new("/nix/store/test-generation-1"),
            &target,
            &printer,
            |_activate, _number, _nonce, barrier| {
                barrier(
                    crate::config_eval::activation::CredentialBarrier::StagedView(Path::new(
                        "/run/etc/candidate",
                    )),
                )?;
                barrier(crate::config_eval::activation::CredentialBarrier::Publish(
                    Path::new("/run/apm/test-plan.json"),
                ))?;
                Ok(Some(0))
            },
            |event| match event {
                crate::config_eval::activation::CredentialBarrier::StagedView(_) => Ok(()),
                crate::config_eval::activation::CredentialBarrier::Publish(_) => {
                    bail!("injected retained credential publication failure")
                }
            },
            || {
                evidence_published.set(true);
                Ok(())
            },
            |_activation_exit| {
                evidence_published.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("retained credential publication failure"),
            "{error:#}"
        );
        assert_eq!(
            error
                .downcast_ref::<crate::config_eval::activation::ActivationFailure>()
                .unwrap()
                .exit_code(),
            4
        );
        assert_eq!(state.current, 1);
        assert!(!evidence_published.get());
        assert_eq!(load_generation_state(tmp.path()).unwrap().current, 1);
        assert!(!tmp.path().join("current").exists());
    }

    #[test]
    fn same_abi_rollback_staged_credential_failure_precedes_live_mutation() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = generation_state_for_commit();
        save_generation_state(tmp.path(), &state).unwrap();
        let target = state.generations[1].clone();
        let printer = Printer::new(0, true, false);
        let publish_seen = std::cell::Cell::new(false);

        let error = direct_reactivate_config_generation_with(
            tmp.path(),
            &mut state,
            Path::new("/nix/store/test-generation-1"),
            &target,
            &printer,
            |_activate, _number, _nonce, barrier| {
                barrier(
                    crate::config_eval::activation::CredentialBarrier::StagedView(Path::new(
                        "/run/etc/candidate",
                    )),
                )?;
                publish_seen.set(true);
                barrier(crate::config_eval::activation::CredentialBarrier::Publish(
                    Path::new("/run/apm/test-plan.json"),
                ))?;
                Ok(Some(0))
            },
            |event| match event {
                crate::config_eval::activation::CredentialBarrier::StagedView(_) => {
                    bail!("injected staged sealed credential validation failure")
                }
                crate::config_eval::activation::CredentialBarrier::Publish(_) => Ok(()),
            },
            || Ok(()),
            |_activation_exit| Ok(()),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("staged sealed credential"));
        assert!(!publish_seen.get());
        assert_eq!(state.current, 1);
        assert_eq!(load_generation_state(tmp.path()).unwrap().current, 1);
        assert!(!tmp.path().join("current").exists());
    }

    #[test]
    fn activation_recovery_never_publishes_an_incomplete_transaction() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = generation_state_for_commit();
        std::fs::create_dir_all(tmp.path().join("gen-1")).unwrap();
        std::fs::create_dir_all(tmp.path().join("gen-2")).unwrap();
        std::os::unix::fs::symlink("gen-1", tmp.path().join("current")).unwrap();
        save_generation_state(tmp.path(), &state).unwrap();
        let intent = ActivationIntent {
            generation: 2,
            nonce: "new-transaction".into(),
            state: state.clone(),
        };
        std::fs::write(
            tmp.path().join(ACTIVATION_INTENT),
            serde_json::to_vec(&intent).unwrap(),
        )
        .unwrap();
        std::fs::write(tmp.path().join("gen-2/.etc-live-old-transaction"), b"2\n").unwrap();

        let not_recovered = load_generation_state(tmp.path()).unwrap();
        assert_eq!(not_recovered.current, 1);
        assert_eq!(
            std::fs::read_link(tmp.path().join("current")).unwrap(),
            PathBuf::from("gen-1")
        );

        // A pre-swap crash is safe to clear and retry. Re-create the exact
        // intent, then prove a post-swap crash requires rescue rather than
        // bypassing credentials, attestation, and activation proof.
        std::fs::write(
            tmp.path().join(ACTIVATION_INTENT),
            serde_json::to_vec(&intent).unwrap(),
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("gen-2/.etc-live-new-transaction"),
            b"2 new-transaction\n",
        )
        .unwrap();
        let error = load_generation_state(tmp.path()).unwrap_err();
        assert!(error.to_string().contains("rescue mode is required"));
        assert_eq!(
            load_generation_state_readonly(tmp.path()).unwrap().current,
            1
        );
        assert!(tmp.path().join(ACTIVATION_INTENT).exists());
    }

    #[test]
    fn readonly_state_load_never_publishes_recovery_journals() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = generation_state_for_commit();
        std::fs::create_dir_all(tmp.path().join("gen-2")).unwrap();
        save_generation_state(tmp.path(), &state).unwrap();
        let intent = ActivationIntent {
            generation: 2,
            nonce: "transaction".into(),
            state,
        };
        std::fs::write(
            tmp.path().join(ACTIVATION_INTENT),
            serde_json::to_vec(&intent).unwrap(),
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("gen-2/.etc-live-transaction"),
            b"2 transaction\n",
        )
        .unwrap();

        assert_eq!(
            load_generation_state_readonly(tmp.path()).unwrap().current,
            1
        );
        assert!(tmp.path().join(ACTIVATION_INTENT).exists());
        assert!(!tmp.path().join("current").exists());
    }

    #[test]
    fn image_selection_intent_survives_failure_and_retries_idempotently() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = ImageGenerationState {
            running: 1,
            default: 1,
            pending: None,
            recovery_known_good: None,
            recovery_pending: None,
            generations: Vec::new(),
        };
        let error = select_image_default_with(tmp.path(), &mut state, 2, "aos-2+3.efi", |_| {
            bail!("injected bootctl failure")
        })
        .unwrap_err();
        assert!(error.to_string().contains("injected bootctl failure"));
        assert_eq!(state.default, 1);
        assert_eq!(state.pending, Some(2));
        assert!(tmp.path().join(IMAGE_TRANSITION_INTENT).is_file());
        let prepared: ImageGenerationState =
            serde_json::from_slice(&std::fs::read(tmp.path().join(IMAGE_STATE_FILE)).unwrap())
                .unwrap();
        assert_eq!(prepared.default, 1);
        assert_eq!(prepared.pending, Some(2));

        let prepared_path = tmp.path().join(IMAGE_STATE_FILE);
        let mut selected = String::new();
        select_image_default_with(tmp.path(), &mut state, 2, "aos-2+3.efi", |entry| {
            let prepared: ImageGenerationState = serde_json::from_slice(&std::fs::read(
                &prepared_path,
            )?)
            .context("the authenticated pending state must precede external boot selection")?;
            assert_eq!(prepared.default, 1);
            assert_eq!(prepared.pending, Some(2));
            selected = entry.to_string();
            Ok(())
        })
        .unwrap();
        assert_eq!(selected, "aos-2.efi");
        assert_eq!(state.default, 2);
        assert_eq!(state.pending, Some(2));
        assert!(!tmp.path().join(IMAGE_TRANSITION_INTENT).exists());
    }

    #[test]
    fn counted_uki_resolution_follows_sd_boot_renames() {
        let tmp = tempfile::TempDir::new().unwrap();
        let linux = tmp.path().join("EFI/Linux");
        std::fs::create_dir_all(&linux).unwrap();
        std::fs::write(linux.join("aos-server-2+1-2.efi"), b"uki").unwrap();

        assert_eq!(
            resolve_installed_uki_entry(tmp.path(), "EFI/Linux/aos-server-2+3.efi").unwrap(),
            "aos-server-2+1-2.efi"
        );
        std::fs::write(linux.join("aos-server-2.efi"), b"blessed").unwrap();
        assert_eq!(
            resolve_installed_uki_entry(tmp.path(), "EFI/Linux/aos-server-2+3.efi").unwrap(),
            "aos-server-2.efi"
        );
    }

    #[test]
    fn counted_uki_resolution_rejects_exhausted_entries() {
        let tmp = tempfile::TempDir::new().unwrap();
        let linux = tmp.path().join("EFI/Linux");
        std::fs::create_dir_all(&linux).unwrap();
        std::fs::write(linux.join("aos-server-2+0-3.efi"), b"failed uki").unwrap();

        let error = resolve_installed_uki_entry(tmp.path(), "EFI/Linux/aos-server-2+3.efi")
            .expect_err("an exhausted image must not become the next boot default");
        assert!(error.to_string().contains("exhausted"));
        assert_eq!(
            resolve_installed_uki_entry_with(
                tmp.path(),
                "EFI/Linux/aos-server-2+3.efi",
                ExhaustedEntry::Allow,
            )
            .unwrap(),
            "aos-server-2+0-3.efi"
        );
    }

    #[test]
    fn staged_uki_path_is_confined_and_requires_a_live_terminal_count() {
        assert_eq!(
            validate_staged_uki_path("EFI/Linux/aos-1.0+build+3.efi").unwrap(),
            "aos-1.0+build+3.efi"
        );
        for unsafe_path in [
            "loader/loader.conf+3.efi",
            "EFI/Linux/nested/aos+3.efi",
            "EFI/Linux/../loader/aos+3.efi",
            "/EFI/Linux/aos+3.efi",
            "EFI/Linux/aos.efi",
            "EFI/Linux/aos+0.efi",
            "EFI/Linux/aos+3-0.efi",
            "EFI/Linux/aos+live.efi",
        ] {
            assert!(
                validate_staged_uki_path(unsafe_path).is_err(),
                "unexpectedly accepted {unsafe_path:?}"
            );
        }
    }

    #[test]
    fn installed_uki_names_sort_by_persistent_image_generation() {
        assert_eq!(
            generation_uki_path("EFI/Linux/aos-test-2+3.efi", 2).unwrap(),
            "EFI/Linux/aos-generation-0000000002+3.efi"
        );
        assert_eq!(
            generation_uki_path("EFI/Linux/aos-0.1.0+7.efi", 42).unwrap(),
            "EFI/Linux/aos-generation-0000000042+7.efi"
        );
    }

    #[test]
    fn durable_default_uses_the_stable_counted_uki_identity() {
        assert_eq!(
            stable_uki_entry_id("aos-1.0+build+3.efi").unwrap(),
            "aos-1.0+build.efi"
        );
        assert_eq!(
            stable_uki_entry_id("aos-1.0+build.efi").unwrap(),
            "aos-1.0+build.efi"
        );
    }

    fn generation_state_for_commit() -> ConfigGenerationState {
        let generation = |number| ConfigGeneration {
            number,
            created_at: "2026-01-01T00:00:00Z".into(),
            image_gen_parent: 1,
            module_abi_pinned: 1,
            manifest_hash: format!("sha256:{number}"),
            config_module_closure: format!("/nix/store/cfg-{number}"),
            config_module_paths: vec![
                format!("/nix/store/cfg-a-{number}"),
                format!("/nix/store/cfg-b-{number}"),
            ],
            config_module_packages: vec!["cfg-a".into(), "cfg-b".into()],
            host_nix_ref: format!("/nix/store/host-{number}"),
            host_nix_commit: None,
            facts_hash: format!("sha256:facts-{number}"),
            facts_ref: format!("/nix/store/facts-{number}"),
            base_lib_ref: format!("/nix/store/base-{number}"),
            evaluator_ref: format!("/nix/store/evaluator-{number}"),
        };
        ConfigGenerationState {
            current: 1,
            next: 3,
            generations: vec![generation(1), generation(2)],
        }
    }

    fn valid_manifest_for_generation_authentication() -> serde_json::Value {
        serde_json::json!({
            "schema": "aos.config-manifest/v1",
            "module_abi": 1,
            "inputs": {
                "base_lib": {
                    "store_path": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-base",
                    "abi_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "module_abi": 1
                },
                "evaluator": {
                    "store_path": "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-evaluator",
                    "store_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                },
                "config_modules": {
                    "closure_hash": "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
                    "count": 0,
                    "store_paths": [],
                    "nar_hashes": [],
                    "package_names": [],
                    "module_abi_compat": []
                },
                "host_nix": {
                    "content_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "trust_mode": "platform",
                    "platform": "test",
                    "signer_key": null,
                    "store_path": "/nix/store/cccccccccccccccccccccccccccccccc-host-nix"
                },
                "instance_facts": {
                    "facts_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "platform": "test",
                    "store_path": "/nix/store/dddddddddddddddddddddddddddddddd-facts"
                }
            },
            "packages": [],
            "packageOutputs": {},
            "storePaths": [],
            "etc": {},
            "jobScripts": {},
            "units": {},
            "users": [],
            "presets": [],
            "graph": {"edges": {}},
            "config": {},
            "credentials": {},
            "ownership": {
                "etc": {}, "units": {}, "jobScripts": {}, "users": {},
                "presets": {}, "storePaths": {}
            }
        })
    }

    #[test]
    fn current_manifest_authentication_rejects_retained_tampering() {
        let tmp = tempfile::TempDir::new().unwrap();
        let profile = tmp.path().join("system");
        let generation_dir = profile.join("gen-1");
        std::fs::create_dir_all(&generation_dir).unwrap();
        let mut manifest = valid_manifest_for_generation_authentication();
        let parsed: crate::config_eval::materialize::ConfigManifest =
            serde_json::from_value(manifest.clone()).unwrap();
        parsed.validate().unwrap();
        let manifest_hash =
            crate::graph_compile::reproject::hash_cjson(&serde_json::to_value(&parsed).unwrap());
        std::fs::write(
            generation_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let mut state = generation_state_for_commit();
        state.generations.truncate(1);
        state.generations[0].manifest_hash = manifest_hash;
        state.next = 2;
        save_generation_state(&profile, &state).unwrap();
        std::os::unix::fs::symlink("gen-1", profile.join("current")).unwrap();

        assert_eq!(
            authenticated_current_generation_manifest(&profile).unwrap(),
            Some(generation_dir.join("manifest.json"))
        );

        manifest["inputs"]["host_nix"]["content_hash"] = serde_json::Value::String(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        );
        std::fs::write(
            generation_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let error = authenticated_current_generation_manifest(&profile).unwrap_err();
        assert!(format!("{error:#}").contains("manifest hash mismatch"));
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
    fn credential_units_fold_into_plan_once_with_start_precedence() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plan = Plan {
            schema_version: PLAN_SCHEMA_VERSION,
            generation: 9,
            to_reload: vec!["reload.service".to_string(), "rotate.service".to_string()],
            to_restart: vec!["restart.service".to_string()],
            to_start: vec!["new.service".to_string()],
            ..Default::default()
        };
        let path = write_plan(tmp.path(), &plan).unwrap();

        augment_reconcile_plan_with_credential_units_and(
            &path,
            &[
                "new.service".to_string(),
                "rotate.service".to_string(),
                "restart.service".to_string(),
                "unchanged.service".to_string(),
            ],
            |_| Ok(Vec::new()),
        )
        .unwrap();

        let updated = read_validated_plan(&path).unwrap();
        assert_eq!(updated.to_reload, vec!["reload.service"]);
        assert_eq!(
            updated.to_restart,
            vec!["rotate.service", "restart.service", "unchanged.service"]
        );
        assert_eq!(updated.to_start, vec!["new.service"]);
    }

    #[test]
    fn credential_restart_order_includes_existing_planned_dependents() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plan = Plan {
            schema_version: PLAN_SCHEMA_VERSION,
            generation: 10,
            to_restart: vec!["frontend.service".to_string()],
            ..Default::default()
        };
        let path = write_plan(tmp.path(), &plan).unwrap();

        augment_reconcile_plan_with_credential_units_and(
            &path,
            &["database.service".to_string()],
            |unit| match unit {
                "frontend.service" => Ok(vec!["database.service".to_string()]),
                _ => Ok(Vec::new()),
            },
        )
        .unwrap();

        assert_eq!(
            read_validated_plan(&path).unwrap().to_restart,
            ["database.service", "frontend.service"]
        );
    }

    #[test]
    fn reconcile_attempts_continue_and_any_error_is_degraded() {
        let printer = Printer::new(0, true, false);
        let attempts = [
            ("first.service", Err("injected D-Bus error")),
            ("second.service", Ok(JobResult::Dependency)),
            ("third.service", Ok(JobResult::Done)),
        ];
        let mut visited = Vec::new();
        let mut degraded = false;
        for (unit, outcome) in attempts {
            visited.push(unit);
            degraded |= reconcile_job_failed(&printer, "restart", unit, outcome);
        }

        assert_eq!(
            visited,
            ["first.service", "second.service", "third.service"]
        );
        assert!(degraded);
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
