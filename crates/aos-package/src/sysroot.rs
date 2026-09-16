//! System sysroot management (`apm install --system`, `apm upgrade --system`,
//! `apm rollback --system`).
//!
//! A sysroot package is a regular package with `sysroot = true` whose metadata
//! names both a system toplevel and an authenticated raw OTA payload. Checked
//! image-rollout abilities own A/B image transitions. Configuration generations
//! remain independent under `/var/lib/profiles/system/` (see
//! [`ConfigGenerationState`]).
//!
//! # Install / upgrade / rollback flow
//!
//! [`install_system`] permits explicit image downloads and rejects direct A/B
//! mutation. [`upgrade_system`] reports an available image and delegates to the
//! same rejection. Checked rollout orchestration publishes and selects images.
//! [`rollback_image_generation`] lists retained images and rejects direct
//! selection, while [`rollback_system`] rolls back only the configuration axis
//! on the running image.
//!
//! # Image transition modes
//!
//! [`SystemTransitionMode`] controls what happens after staging: `Advisory`
//! (default) leaves the transition pending and advises a reboot, while
//! `Reboot` drains when requested and queues a full reboot. Kexec and a live
//! userspace-only switch are not valid for an immutable A/B image transition.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use aos_core::output::{OutputMode, Printer};

use crate::config::ApmConfig;
use crate::download::{
    DownloadRequest, default_engine, download_nars, fetch_narinfos, resolve_mirror_chain,
    split_mirror_chain,
};
use crate::platform::native_platform;
use crate::registry::{RegistrySet, store_path_hash};
use crate::resolve::resolve_multiple;
use crate::types::{
    ConfigGeneration, ConfigGenerationState, CrossAbiReEvalInputs, ImageGeneration,
    ImageGenerationState, ImageRollout, ImageRolloutStatus, ImageSlot, PackageMeta, ProfileScope,
    ReactivationPlan,
};
use crate::verify::verify_download_hash;

mod activatability;
pub(crate) mod image_rollout;
pub use image_rollout::run_boot_commit_from_process as run_image_rollout_boot_commit;
pub use image_rollout::run_observer_from_process as run_image_rollout_observer;
pub use image_rollout::run_provider_from_process as run_image_rollout_provider;

pub use activatability::{
    ActivatabilityReason, ActivatabilityReasonCode, RETAINED_ACTIVATABILITY_SCHEMA,
    RetainedActivatabilityReport, RetainedActivationMode, RetainedTargetKind,
};

use image_rollout::validate_active_rollout_selection;

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
const SYSTEM_STATE_FILE: &str = "state.json";
const SYSTEM_COMMIT_JOURNAL: &str = ".state-commit.json";
const IMAGE_STATE_FILE: &str = "state.json";
const IMAGE_TRANSITION_INTENT: &str = ".transition-intent.json";
const IMAGE_PROFILE_DIR: &str = "/var/lib/profiles/image";
const ROOT_A_DEVICE: &str = "/dev/disk/by-partlabel/root-a";
const ROOT_B_DEVICE: &str = "/dev/disk/by-partlabel/root-b";
const RUNNING_TOPLEVEL_LINK: &str = "/aos-toplevel";
const RUNNING_CMDLINE: &str = "/proc/cmdline";
const MAX_INSTALLED_UKI_BYTES: u64 = 256 * 1024 * 1024;
const MAX_OS_RELEASE_BYTES: u64 = 64 * 1024;
const MAX_UKI_IDENTITY_SECTION_BYTES: usize = 64 * 1024;

/// Recoverable intent record for publishing a generation as current.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct GenerationCommitJournal {
    generation: u32,
    state: ConfigGenerationState,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ImageTransitionIntent {
    target: u32,
    prior_default: u32,
    entry_id: String,
}

/// Root-device identities used to authenticate the booted A/B slot.
struct ImageSlotLayout {
    root_a: PathBuf,
    root_b: PathBuf,
}

impl Default for ImageSlotLayout {
    fn default() -> Self {
        Self {
            root_a: PathBuf::from(ROOT_A_DEVICE),
            root_b: PathBuf::from(ROOT_B_DEVICE),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootStorageMetadata {
    devices: BootStorageDevices,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootStorageDevices {
    root_a: PathBuf,
    root_b: PathBuf,
}

impl ImageSlotLayout {
    fn from_toplevel(toplevel: &Path) -> Result<Self> {
        let path = toplevel.join("meta/boot-storage.json");
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading boot-storage metadata {}", path.display()))?;
        let metadata: BootStorageMetadata = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing boot-storage metadata {}", path.display()))?;
        for device in [&metadata.devices.root_a, &metadata.devices.root_b] {
            if !device.is_absolute() || !device.starts_with("/dev") {
                bail!(
                    "boot-storage metadata contains unsafe device {}",
                    device.display()
                );
            }
        }
        Ok(Self {
            root_a: metadata.devices.root_a,
            root_b: metadata.devices.root_b,
        })
    }
}

/// Resolves the booted image generation from immutable image identity.
///
/// The `/var` image index is accepted only after its running record agrees
/// with the baked `/aos-toplevel` pointer and metadata, the measured
/// `AOS_MODULE_ABI` and `AOS_BASELIB_ABI_HASH` fields from the running image's
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
        Path::new(RUNNING_TOPLEVEL_LINK),
        Path::new(RUNNING_CMDLINE),
        Path::new("/"),
    )
}

/// Resolves the booted image generation beneath an already mounted root.
///
/// The image profile is supplied explicitly because the initrd sees durable
/// profile state beneath `/sysroot`, while the immutable identity files live
/// beneath `root`. Kernel command-line and block-device evidence remain in the
/// current boot namespace and are checked by the same production validator as
/// [`running_image_generation`].
///
/// # Errors
///
/// Returns an error if any image index, immutable identity, root-slot, or
/// verity input is absent, malformed, or inconsistent.
pub(crate) fn running_image_generation_beneath(
    image_profile: &Path,
    root: &Path,
) -> Result<ImageGeneration> {
    if !root.is_absolute() {
        bail!("running image root must be absolute");
    }

    load_running_image_generation_from(
        image_profile,
        &root.join("aos-toplevel"),
        Path::new(RUNNING_CMDLINE),
        root,
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
    toplevel_link: &Path,
    cmdline: &Path,
    immutable_root: &Path,
) -> Result<ImageGeneration> {
    load_running_image_generation_with_device_identity(
        image_profile,
        toplevel_link,
        cmdline,
        immutable_root,
        block_device_identity,
    )
}

fn load_running_image_generation_with_device_identity<F>(
    image_profile: &Path,
    toplevel_link: &Path,
    cmdline: &Path,
    immutable_root: &Path,
    device_identity: F,
) -> Result<ImageGeneration>
where
    F: Fn(&Path) -> Result<u64>,
{
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
    let baked_toplevel_text = baked_toplevel
        .to_str()
        .context("running image pointer target is not UTF-8")?;
    crate::config_eval::materialize::validate_canonical_store_path(baked_toplevel_text)
        .context("validating running image pointer target")?;
    if baked_toplevel != Path::new(&running.toplevel) {
        bail!(
            "running image pointer {} disagrees with image generation {} toplevel {}",
            baked_toplevel.display(),
            running.number,
            running.toplevel
        );
    }
    let immutable_toplevel = resolve_absolute_path_beneath(immutable_root, &baked_toplevel)?;
    let baked_base_lib =
        std::fs::read_link(immutable_toplevel.join("base-lib")).with_context(|| {
            format!(
                "reading immutable running base-library pointer {}/base-lib",
                immutable_toplevel.display()
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
    let immutable_abi = read_toplevel_meta(&immutable_toplevel, "module-abi")?
        .parse::<u32>()
        .context("immutable toplevel has invalid module ABI")?;
    let immutable_abi_hash = read_toplevel_meta(&immutable_toplevel, "base-lib-abi-hash")?;
    let immutable_uki = read_toplevel_meta(&immutable_toplevel, "uki-path")?;
    let immutable_package = read_toplevel_meta(&immutable_toplevel, "package-name")?;
    let immutable_version = read_toplevel_meta(&immutable_toplevel, "version")?;
    let recorded_uki = running
        .uki_source_path
        .as_deref()
        .unwrap_or(&running.uki_path);
    if immutable_abi != running.module_abi
        || immutable_abi_hash != running.base_lib_abi_hash
        || immutable_uki != recorded_uki
        || immutable_package != running.package_name
        || immutable_version != running.version
    {
        bail!(
            "running immutable toplevel metadata disagrees with image generation {}",
            running.number
        );
    }
    let os_release = std::fs::read_link(immutable_toplevel.join("os-release"))
        .context("reading immutable running os-release pointer")?;
    let fields = read_immutable_os_release(immutable_root, &os_release)
        .context("reading immutable running os-release identity")?;
    let abi = fields
        .get("AOS_MODULE_ABI")
        .context("running os-release has no AOS_MODULE_ABI")?
        .parse::<u32>()
        .context("running os-release has invalid AOS_MODULE_ABI")?;
    let abi_hash = fields
        .get("AOS_BASELIB_ABI_HASH")
        .context("running os-release has no AOS_BASELIB_ABI_HASH")?;
    if abi != running.module_abi || abi_hash != &running.base_lib_abi_hash {
        bail!(
            "running image identity disagrees with image state (module ABI {abi}, base-lib ABI hash {abi_hash})"
        );
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
        let layout = ImageSlotLayout::from_toplevel(&immutable_toplevel)?;
        let booted_slot = image_slot_for_root(Path::new(root), &layout, device_identity)?;
        if booted_slot != running.slot {
            bail!(
                "running root slot disagrees with image generation {}",
                running.number
            );
        }
    }
    Ok(running)
}

fn resolve_absolute_path_beneath(root: &Path, target: &Path) -> Result<PathBuf> {
    ensure!(
        root.is_absolute(),
        "immutable filesystem root must be absolute"
    );
    let relative = target
        .strip_prefix("/")
        .context("immutable path target must be absolute")?;
    Ok(root.join(relative))
}

/// Returns the kernel identity of an opened block device.
fn block_device_identity(path: &Path) -> Result<u64> {
    let device = std::fs::File::open(path)
        .with_context(|| format!("opening image-slot device {}", path.display()))?;
    let metadata = device.metadata()?;
    if !metadata.file_type().is_block_device() {
        bail!("image-slot path is not a block device: {}", path.display());
    }
    Ok(metadata.rdev())
}

/// Resolves a running root device to one distinct declared image slot.
fn image_slot_for_root<F>(
    root: &Path,
    layout: &ImageSlotLayout,
    device_identity: F,
) -> Result<ImageSlot>
where
    F: Fn(&Path) -> Result<u64>,
{
    let root_identity = device_identity(root)?;
    let root_a_identity = device_identity(&layout.root_a)?;
    let root_b_identity = device_identity(&layout.root_b)?;
    if root_a_identity == root_b_identity {
        bail!("declared image slots resolve to the same block device");
    }

    if root_identity == root_a_identity {
        Ok(ImageSlot::A)
    } else if root_identity == root_b_identity {
        Ok(ImageSlot::B)
    } else {
        bail!("running kernel root device is not a declared image slot");
    }
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

fn read_immutable_os_release(
    immutable_root: &Path,
    logical_path: &Path,
) -> Result<std::collections::BTreeMap<String, String>> {
    let logical_path_text = logical_path
        .to_str()
        .context("immutable os-release pointer is not UTF-8")?;
    crate::config_eval::materialize::validate_canonical_store_member_path(logical_path_text)
        .context("validating immutable os-release pointer")?;
    let relative_path = logical_path
        .strip_prefix("/")
        .context("immutable os-release pointer is not absolute")?
        .to_str()
        .context("immutable os-release relative path is not UTF-8")?;
    let bytes = crate::config_eval::materialize::read_bounded_bytes_beneath(
        immutable_root,
        relative_path,
        MAX_OS_RELEASE_BYTES,
    )?;
    let text = std::str::from_utf8(&bytes).context("immutable os-release is not UTF-8")?;

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

/// Downloads a sysroot image artifact or rejects direct A/B installation.
///
/// Image publication, selection, and restart require the checked rollout
/// controller and its selected platform abilities.
///
/// # Errors
///
/// Returns an error when the package cannot be resolved, is not a sysroot
/// package, the requested image download fails, or direct installation is
/// requested.
#[allow(clippy::too_many_arguments)]
pub async fn install_system(
    config: &ApmConfig,
    packages: &[String],
    registry_filter: Option<&str>,
    image_format: Option<&str>,
    image_output: Option<&str>,
    dry_run: bool,
    _yes: bool,
    _transition_mode: SystemTransitionMode,
    _drain: bool,
    printer: &Printer,
) -> Result<()> {
    if packages.len() != 1 {
        bail!("--system install requires exactly one package name");
    }
    let package_name = &packages[0];
    let registries = load_registries(config)?;
    let closures = resolve_multiple(&registries, packages, registry_filter)?;
    let closure = closures
        .iter()
        .find(|closure| closure.root.name == *package_name)
        .ok_or_else(|| anyhow::anyhow!("package '{package_name}' not found"))?;
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

    bail!(
        "direct A/B image installation is retired; submit the image transition through the checked rollout controller"
    )
}

fn reeval_and_activate_config_generation(
    _config: &ApmConfig,
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
        Some(load_generation_state_readonly(profile_path)?.current),
    )?;
    let marker_root = eval_root.join("markers");
    validate_retained_runtime(&manifest)?;
    crate::config_eval::activation::activate_config(
        &crate::config_eval::activation::ActivateConfigParams {
            manifest,
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
    let running = running_image_generation()?;
    let retained = CrossAbiReEvalInputs {
        package_modules: active.package_modules.clone(),
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
        Some(state.current),
    )
}

/// Reconciles the running image transition before boot configuration evaluation.
///
/// This consumes the durable image-selection intent, advances an active
/// qualified rollout to the phase proven by the image that actually booted,
/// and publishes the runtime marker that selects retained configuration
/// re-evaluation.
///
/// # Errors
///
/// Returns an error when image or configuration state is unavailable or
/// malformed, a transition intent does not name the authenticated generation,
/// or an active rollout is internally inconsistent.
pub(crate) fn reconcile_image_boot_for_config_evaluation(
    image_profile: &Path,
    system_profile: &Path,
    reevaluation_marker: &Path,
) -> Result<()> {
    let mut images = load_image_generation_state_pub(image_profile)?;
    let configs = load_generation_state_readonly(system_profile)?;
    let intent_path = image_profile.join(IMAGE_TRANSITION_INTENT);

    if intent_path.is_file() {
        let intent: ImageTransitionIntent = serde_json::from_slice(&std::fs::read(&intent_path)?)
            .with_context(|| {
            format!("parsing image transition intent {}", intent_path.display())
        })?;
        let matching = images
            .generations
            .iter()
            .filter(|generation| generation.number == intent.target)
            .collect::<Vec<_>>();
        ensure!(
            matching.len() == 1,
            "image transition intent target {} is absent or ambiguous",
            intent.target
        );
        let recorded_entry = Path::new(&matching[0].uki_path)
            .file_name()
            .and_then(|entry| entry.to_str())
            .context("image transition generation has no UTF-8 UKI entry name")?;
        ensure!(
            stable_uki_entry_id(recorded_entry)? == stable_uki_entry_id(&intent.entry_id)?,
            "image transition intent disagrees with authenticated generation {}",
            intent.target
        );

        images.default = images.running;
        write_atomic_durable(
            &image_profile.join(IMAGE_STATE_FILE),
            &serde_json::to_vec_pretty(&images)?,
        )?;
        remove_file_durable(&intent_path)?;
    }

    if let Some(rollout) = images.active_rollout.as_mut() {
        ensure!(
            rollout.schema == "aos.image-rollout/v1"
                && rollout.candidate != rollout.prior
                && !rollout.state_version.is_empty()
                && images.pending == Some(rollout.candidate)
                && matches!(
                    rollout.status,
                    ImageRolloutStatus::Staged
                        | ImageRolloutStatus::CandidateBooted
                        | ImageRolloutStatus::HealthFailed
                ),
            "qualified image rollout record is invalid"
        );
        for (role, number) in [("candidate", rollout.candidate), ("prior", rollout.prior)] {
            let matching = images
                .generations
                .iter()
                .filter(|generation| {
                    generation.number == number && generation.state_version == rollout.state_version
                })
                .count();
            ensure!(
                matching == 1,
                "qualified rollout {role} generation {number} is absent, ambiguous, or changed"
            );
        }

        if images.running == rollout.candidate {
            if rollout.status != ImageRolloutStatus::HealthFailed {
                rollout.status = ImageRolloutStatus::CandidateBooted;
            }
        } else if images.running == rollout.prior {
            rollout.status = ImageRolloutStatus::HealthFailed;
        } else {
            bail!("running image is outside the qualified rollout pair");
        }
        write_atomic_durable(
            &image_profile.join(IMAGE_STATE_FILE),
            &serde_json::to_vec_pretty(&images)?,
        )?;
    }

    let image_parent = configs
        .generations
        .iter()
        .find(|generation| generation.number == configs.current)
        .map_or(0, |generation| generation.image_gen_parent);
    if images.running != image_parent || images.pending.is_some() {
        let parent = reevaluation_marker
            .parent()
            .context("image re-evaluation marker has no parent")?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        std::fs::write(reevaluation_marker, format!("{}\n", images.running))
            .with_context(|| format!("writing {}", reevaluation_marker.display()))?;
    } else {
        remove_file_durable(reevaluation_marker)?;
    }
    Ok(())
}

fn validate_retained_runtime(manifest_path: &Path) -> Result<()> {
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
    let actual = crate::canonical_json_digest(&value)?;
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
        transition_mode,
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
    printer: &Printer,
) -> Result<()> {
    let profile_path = ProfileScope::System.profile_path();
    let switch_lock = crate::config_eval::activation::ActivateConfigParams::default().switch_lock;
    let switch_guard = crate::config_eval::activation::acquire_switch_lock_pub(&switch_lock)?;
    if list {
        let state = load_generation_state_readonly(&profile_path)?;
        let running = running_image_generation()?;
        let reports = state
            .generations
            .iter()
            .map(|generation| {
                activatability::configuration(config, &profile_path, generation, &running)
            })
            .collect::<Vec<_>>();
        if printer.mode() == OutputMode::Json {
            let bytes = aos_contract::canonical::to_vec(&reports)?;
            printer.raw(std::str::from_utf8(&bytes)?);
            return Ok(());
        }
        if state.generations.is_empty() {
            printer.info("No system generations.");
        } else {
            printer.header("Configuration generations:");
            for (sysgen, report) in state.generations.iter().zip(&reports) {
                let marker = if sysgen.number == state.current {
                    " (current)"
                } else {
                    ""
                };
                let status = activatability_label(report);
                printer.plain(&format!(
                    "  gen-{}: image-gen-{}, ABI {}, {} [{}]{} {}",
                    sysgen.number,
                    sysgen.image_gen_parent,
                    sysgen.module_abi_pinned,
                    sysgen.manifest_hash,
                    sysgen.created_at,
                    marker,
                    status,
                ));
            }
        }
        return Ok(());
    }
    let state = load_generation_state(&profile_path)?;

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

    let running_image = running_image_generation()?;
    let activatability =
        activatability::configuration(config, &profile_path, &target, &running_image);
    print_activatability(&activatability, printer)?;
    activatability.require_activatable()?;

    if dry_run {
        printer.info("Dry run -- no changes made.");
        return Ok(());
    }

    if Path::new(IMAGE_PROFILE_DIR)
        .join(IMAGE_STATE_FILE)
        .is_file()
    {
        let running_image = running_image;
        let running_abi = running_image.module_abi;
        match target.reactivation_plan(running_abi)? {
            ReactivationPlan::DirectReactivate => {
                let manifest_path = validate_generation_manifest(&profile_path, &target)?;
                drop(switch_guard);
                let marker_root = PathBuf::from(format!(
                    "/run/aos/rollback-native-{}-{}",
                    target.number,
                    std::process::id()
                ));
                validate_retained_runtime(&manifest_path)?;
                let activated = crate::config_eval::activation::activate_config(
                    &crate::config_eval::activation::ActivateConfigParams {
                        manifest: manifest_path,
                        marker_root,
                        profile: profile_path.clone(),
                        module_abi: running_abi,
                        running_image: Some(running_image),
                        switch_lock,
                        ..crate::config_eval::activation::ActivateConfigParams::default()
                    },
                )?;
                printer.success(&format!(
                    "Configuration generation {activated} is active under the running image."
                ));
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

    bail!("image generation state is absent; refusing config rollback through legacy state")
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

fn read_toplevel_meta(toplevel: &Path, name: &str) -> Result<String> {
    let value = std::fs::read_to_string(toplevel.join("meta").join(name))
        .with_context(|| format!("reading target image metadata {name}"))?;
    Ok(value.trim().to_string())
}

/// Reads a required PE section as UTF-8 text after removing section padding.
pub(crate) fn read_uki_section_text(uki: &Path, section: &str) -> Result<String> {
    let metadata = std::fs::symlink_metadata(uki)
        .with_context(|| format!("inspecting installed UKI {}", uki.display()))?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_INSTALLED_UKI_BYTES
    {
        bail!("installed UKI {} is outside its size bound", uki.display());
    }

    let image = std::fs::read(uki).with_context(|| format!("reading UKI {}", uki.display()))?;
    if image.len() as u64 != metadata.len() {
        bail!("installed UKI {} changed while it was read", uki.display());
    }
    let bytes = crate::registry_ops::pe_section(&image, section)?
        .with_context(|| format!("UKI {} has no {section} section", uki.display()))?;
    ensure!(
        bytes.len() <= MAX_UKI_IDENTITY_SECTION_BYTES,
        "{section} in {} exceeds its {}-byte identity bound",
        uki.display(),
        MAX_UKI_IDENTITY_SECTION_BYTES
    );
    let content_end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    let content = &bytes[..content_end];
    ensure!(
        !content.contains(&0),
        "{section} in {} contains an interior NUL byte",
        uki.display()
    );
    let text = std::str::from_utf8(content)
        .with_context(|| format!("{section} in {} is not UTF-8", uki.display()))?;
    Ok(text.to_string())
}

/// Lists A/B image generations and rejects the retired direct rollback route.
///
/// Image selection and restart are available only through the checked rollout
/// controller and its selected platform abilities.
///
/// # Errors
///
/// Returns an error for an unknown image generation or any requested direct
/// rollback mutation.
pub async fn rollback_image_generation(
    _generation: Option<u32>,
    list: bool,
    _dry_run: bool,
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
            let default = if image.number == state.default {
                " (default)"
            } else {
                ""
            };
            printer.plain(&format!(
                "  image-gen-{}: {} {} [{}]{}{} {}",
                image.number,
                image.package_name,
                image.version,
                image.uki_path,
                running,
                default,
                activatability_label(report),
            ));
        }
        return Ok(());
    }
    bail!(
        "direct A/B image rollback is retired; submit the image transition through the checked rollout controller"
    )
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

/// Durably authenticates a candidate and records selection intent.
fn prepare_image_selection(
    profile: &Path,
    state: &mut ImageGenerationState,
    target: u32,
    entry_id: &str,
    rollout: Option<ImageRollout>,
) -> Result<()> {
    stable_uki_entry_id(entry_id)?;
    if let Some(active) = &state.active_rollout {
        validate_active_rollout_selection(state, active, target)?;
        ensure!(
            rollout.as_ref() == Some(active),
            "active qualified image rollout requires the exact drained rollout identity"
        );
    }
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
    if let Some(rollout) = rollout {
        prepared.active_rollout = Some(rollout);
    }
    write_atomic_durable(
        &profile.join(IMAGE_STATE_FILE),
        &serde_json::to_vec_pretty(&prepared)?,
    )?;
    *state = prepared;
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

/// Commits an activated configuration generation as the current generation.
///
/// The activation caller invokes this after the checked generation is durable.
/// It persists `state.json` and atomically retargets `current -> gen-N`.
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
    serde_json::from_str(&content).with_context(|| format!("parsing {}", state_path.display()))
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

/// Save system generation state to disk.
fn save_generation_state(profile_path: &Path, state: &ConfigGenerationState) -> Result<()> {
    let state_path = profile_path.join(SYSTEM_STATE_FILE);
    let content = serde_json::to_vec_pretty(state)?;
    write_atomic_durable(&state_path, &content)
}

/// Mark `generation` as current: persist it in `state.json` and atomically
/// repoint the `current` symlink (via a temp link + rename). Called only
/// after checked activation has committed the generation.
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
    use crate::registry_ops::test_support::synthetic_pe_section;
    use crate::types::{PackageModule, PackageModuleOrigin};

    fn package_module(package: &str, store_path: String) -> PackageModule {
        PackageModule {
            package: package.to_string(),
            document_digest: format!("sha256:{}", "a".repeat(64)),
            store_path,
            nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            entrypoint: "module.nix".to_string(),
            origin: PackageModuleOrigin::Registry,
        }
    }

    #[test]
    fn uki_identity_section_reader_removes_only_nul_padding() {
        let temporary = TempDir::new().unwrap();
        let uki = temporary.path().join("identity.efi");
        let section = b"ID=AOS\nVERSION_ID=1\n\0\0";
        std::fs::write(
            &uki,
            synthetic_pe_section(b".osrel", section.len() as u32, section),
        )
        .unwrap();

        assert_eq!(
            read_uki_section_text(&uki, ".osrel").unwrap(),
            "ID=AOS\nVERSION_ID=1\n"
        );
    }

    #[test]
    fn uki_identity_section_reader_rejects_malformed_and_duplicate_sections() {
        let temporary = TempDir::new().unwrap();
        let malformed_path = temporary.path().join("malformed.efi");
        let duplicate_path = temporary.path().join("duplicate.efi");
        let pe_offset = 0x40_usize;
        let coff = pe_offset + 4;
        let section_table = coff + 20 + 112;

        let mut malformed = synthetic_pe_section(b".cmdline", 5, b"root\0");
        malformed[section_table + 20..section_table + 24].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&malformed_path, malformed).unwrap();

        let mut duplicate = synthetic_pe_section(b".osrel", 5, b"ID=A\n");
        duplicate[coff + 2..coff + 4].copy_from_slice(&2_u16.to_le_bytes());
        let repeated_header = duplicate[section_table..section_table + 40].to_vec();
        duplicate.splice(section_table + 40..section_table + 40, repeated_header);
        std::fs::write(&duplicate_path, duplicate).unwrap();

        assert!(read_uki_section_text(&malformed_path, ".cmdline").is_err());
        assert!(read_uki_section_text(&duplicate_path, ".osrel").is_err());
    }

    #[test]
    fn uki_identity_section_reader_rejects_interior_nul_for_both_sections() {
        let temporary = TempDir::new().unwrap();

        for section in [".cmdline", ".osrel"] {
            let uki = temporary.path().join(section.trim_start_matches('.'));
            let content = b"first\0second\0";
            std::fs::write(
                &uki,
                synthetic_pe_section(section.as_bytes(), content.len() as u32, content),
            )
            .unwrap();

            assert!(read_uki_section_text(&uki, section).is_err());
        }
    }

    #[test]
    fn uki_identity_section_reader_enforces_file_and_section_bounds() {
        let temporary = TempDir::new().unwrap();
        let oversized_file = temporary.path().join("oversized-file.efi");
        let oversized_section = temporary.path().join("oversized-section.efi");

        let file = std::fs::File::create(&oversized_file).unwrap();
        file.set_len(MAX_INSTALLED_UKI_BYTES + 1).unwrap();
        let section = vec![b'x'; MAX_UKI_IDENTITY_SECTION_BYTES + 1];
        std::fs::write(
            &oversized_section,
            synthetic_pe_section(b".cmdline", section.len() as u32, &section),
        )
        .unwrap();

        assert!(read_uki_section_text(&oversized_file, ".cmdline").is_err());
        assert!(read_uki_section_text(&oversized_section, ".cmdline").is_err());
    }
    use tempfile::TempDir;

    #[test]
    fn image_slot_layout_uses_declared_boot_storage_devices() {
        let tmp = TempDir::new().unwrap();
        let metadata_dir = tmp.path().join("meta");
        std::fs::create_dir_all(&metadata_dir).unwrap();
        std::fs::write(
            metadata_dir.join("boot-storage.json"),
            br#"{
              "backend": "zfs-zvol",
              "espDevices": ["/dev/disk/by-partlabel/aos-esp-1", "/dev/disk/by-partlabel/aos-esp-2"],
              "devices": {
                "rootA": "/dev/zvol/rpool/aos/slots/root-a",
                "rootAHash": "/dev/zvol/rpool/aos/slots/root-a-hash",
                "rootB": "/dev/zvol/rpool/aos/slots/root-b",
                "rootBHash": "/dev/zvol/rpool/aos/slots/root-b-hash"
              }
            }"#,
        )
        .unwrap();

        let layout = ImageSlotLayout::from_toplevel(tmp.path()).unwrap();
        assert_eq!(layout.root_a, Path::new("/dev/zvol/rpool/aos/slots/root-a"));
        assert_eq!(layout.root_b, Path::new("/dev/zvol/rpool/aos/slots/root-b"));
    }
    fn running_identity_fixture() -> (TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let image_profile = tmp.path().join("image");
        let immutable_root = tmp.path().join("sysroot");
        let logical_toplevel =
            PathBuf::from(format!("/nix/store/{}-running-toplevel", "0".repeat(32)));
        let logical_base_lib =
            PathBuf::from(format!("/nix/store/{}-running-base-lib", "1".repeat(32)));
        let logical_os_release = PathBuf::from(format!(
            "/nix/store/{}-running-os-release/os-release",
            "2".repeat(32)
        ));
        let toplevel = resolve_absolute_path_beneath(&immutable_root, &logical_toplevel).unwrap();
        let os_release =
            resolve_absolute_path_beneath(&immutable_root, &logical_os_release).unwrap();
        let toplevel_link = immutable_root.join("aos-toplevel");
        let cmdline = tmp.path().join("cmdline");
        std::fs::create_dir_all(image_profile.as_path()).unwrap();
        std::fs::create_dir_all(toplevel.join("meta")).unwrap();
        std::fs::write(toplevel.join("meta/module-abi"), "7").unwrap();
        std::fs::write(toplevel.join("meta/base-lib-abi-hash"), "sha256:base").unwrap();
        std::fs::write(
            toplevel.join("meta/uki-path"),
            "EFI/Linux/aos-server-1+3.efi",
        )
        .unwrap();
        std::fs::write(toplevel.join("meta/package-name"), "server").unwrap();
        std::fs::write(toplevel.join("meta/version"), "1").unwrap();
        std::fs::write(
            toplevel.join("meta/boot-storage.json"),
            br#"{
              "backend": "gpt-partitions",
              "espDevices": ["/dev/disk/by-partlabel/esp"],
              "devices": {
                "rootA": "/dev/disk/by-partlabel/root-a",
                "rootAHash": "/dev/disk/by-partlabel/root-a-hash",
                "rootB": "/dev/disk/by-partlabel/root-b",
                "rootBHash": "/dev/disk/by-partlabel/root-b-hash"
              }
            }"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&logical_base_lib, toplevel.join("base-lib")).unwrap();
        std::os::unix::fs::symlink(&logical_os_release, toplevel.join("os-release")).unwrap();
        std::fs::create_dir_all(os_release.parent().unwrap()).unwrap();
        std::fs::write(
            os_release,
            "VERSION_ID=1\nAOS_MODULE_ABI=7\nAOS_BASELIB_ABI_HASH=sha256:base\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&logical_toplevel, &toplevel_link).unwrap();
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
            active_rollout: None,
            last_rollout: None,
            generations: vec![ImageGeneration {
                number: 1,
                slot: ImageSlot::A,
                uki_path: "EFI/Linux/aos-server-1+3.efi".into(),
                uki_source_path: None,
                toplevel: logical_toplevel.to_string_lossy().into_owned(),
                package_name: "server".into(),
                version: "1".into(),
                state_version: "1".into(),
                native_executor_ref: format!("/nix/store/{}-executor", "e".repeat(32)),
                registry: "test".into(),
                kernel_path: None,
                evaluator_ref: logical_base_lib.to_string_lossy().into_owned(),
                module_abi: 7,
                base_lib_abi_hash: "sha256:base".into(),
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
        (tmp, image_profile, immutable_root, toplevel_link, cmdline)
    }

    fn fixture_device_identity(path: &Path) -> Result<u64> {
        match path.file_name().and_then(|name| name.to_str()) {
            Some("root-a" | "vda2") => Ok(1),
            Some("root-b" | "vda3") => Ok(2),
            _ => bail!("fixture has no device identity for {}", path.display()),
        }
    }

    fn load_running_image_generation_fixture(
        image_profile: &Path,
        immutable_root: &Path,
        toplevel_link: &Path,
        cmdline: &Path,
    ) -> Result<ImageGeneration> {
        load_running_image_generation_with_device_identity(
            image_profile,
            toplevel_link,
            cmdline,
            immutable_root,
            fixture_device_identity,
        )
    }

    #[test]
    fn running_root_matches_the_resolved_block_device_identity() {
        let layout = ImageSlotLayout::default();
        assert_eq!(
            image_slot_for_root(Path::new("/dev/vda2"), &layout, fixture_device_identity).unwrap(),
            ImageSlot::A
        );
        assert_eq!(
            image_slot_for_root(Path::new("/dev/vda3"), &layout, fixture_device_identity).unwrap(),
            ImageSlot::B
        );
    }

    #[test]
    fn running_root_rejects_aliased_image_slots() {
        let layout = ImageSlotLayout::default();
        let error = image_slot_for_root(Path::new("/dev/vda2"), &layout, |path| {
            fixture_device_identity(path).map(|_| 1)
        })
        .unwrap_err();
        assert!(error.to_string().contains("same block device"));
    }

    #[test]
    fn running_image_beneath_resolves_absolute_links_under_mounted_root() {
        let (_tmp, image_profile, immutable_root, toplevel_link, cmdline) =
            running_identity_fixture();
        let logical_toplevel = std::fs::read_link(&toplevel_link).unwrap();
        let physical_toplevel =
            resolve_absolute_path_beneath(&immutable_root, &logical_toplevel).unwrap();
        let logical_os_release = std::fs::read_link(physical_toplevel.join("os-release")).unwrap();

        assert!(logical_toplevel.starts_with("/nix/store"));
        assert!(logical_os_release.starts_with("/nix/store"));
        assert!(!logical_toplevel.exists());
        assert!(!logical_os_release.exists());

        let loaded = load_running_image_generation_fixture(
            &image_profile,
            &immutable_root,
            &toplevel_link,
            &cmdline,
        )
        .expect("absolute store links must resolve beneath the mounted root");
        assert_eq!(loaded.toplevel, logical_toplevel.to_string_lossy());
    }

    #[test]
    fn running_image_rejects_os_release_symlink_escape() {
        let (tmp, image_profile, immutable_root, toplevel_link, cmdline) =
            running_identity_fixture();
        let logical_toplevel = std::fs::read_link(&toplevel_link).unwrap();
        let physical_toplevel =
            resolve_absolute_path_beneath(&immutable_root, &logical_toplevel).unwrap();
        let logical_os_release = std::fs::read_link(physical_toplevel.join("os-release")).unwrap();
        let physical_os_release =
            resolve_absolute_path_beneath(&immutable_root, &logical_os_release).unwrap();
        let outside = tmp.path().join("live-root-os-release");
        std::fs::write(
            &outside,
            "VERSION_ID=1\nAOS_MODULE_ABI=7\nAOS_BASELIB_ABI_HASH=sha256:base\n",
        )
        .unwrap();
        std::fs::remove_file(&physical_os_release).unwrap();
        std::os::unix::fs::symlink(&outside, &physical_os_release).unwrap();

        let error = load_running_image_generation_fixture(
            &image_profile,
            &immutable_root,
            &toplevel_link,
            &cmdline,
        )
        .expect_err("immutable identity reads must not follow a live-root symlink");

        assert!(
            format!("{error:#}").contains("opening"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn running_image_rejects_os_release_parent_symlink_escape() {
        let (tmp, image_profile, immutable_root, toplevel_link, cmdline) =
            running_identity_fixture();
        let logical_toplevel = std::fs::read_link(&toplevel_link).unwrap();
        let physical_toplevel =
            resolve_absolute_path_beneath(&immutable_root, &logical_toplevel).unwrap();
        let logical_os_release = std::fs::read_link(physical_toplevel.join("os-release")).unwrap();
        let physical_os_release =
            resolve_absolute_path_beneath(&immutable_root, &logical_os_release).unwrap();
        let outside = tmp.path().join("live-root-store-object");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(
            outside.join("os-release"),
            "VERSION_ID=1\nAOS_MODULE_ABI=7\nAOS_BASELIB_ABI_HASH=sha256:base\n",
        )
        .unwrap();
        std::fs::remove_file(&physical_os_release).unwrap();
        std::fs::remove_dir(physical_os_release.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside, physical_os_release.parent().unwrap()).unwrap();

        let error = load_running_image_generation_fixture(
            &image_profile,
            &immutable_root,
            &toplevel_link,
            &cmdline,
        )
        .expect_err("immutable identity reads must reject a symlinked parent directory");

        assert!(
            format!("{error:#}").contains("symlink component"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn running_image_rejects_tampered_var_index_metadata() {
        let (_tmp, image_profile, immutable_root, toplevel_link, cmdline) =
            running_identity_fixture();
        let loaded = load_running_image_generation_fixture(
            &image_profile,
            &immutable_root,
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
        let error = load_running_image_generation_fixture(
            &image_profile,
            &immutable_root,
            &toplevel_link,
            &cmdline,
        )
        .unwrap_err();
        assert!(error.to_string().contains("immutable toplevel metadata"));
    }

    #[test]
    fn running_image_authenticates_the_canonical_uki_source_path() {
        let (_tmp, image_profile, immutable_root, toplevel_link, cmdline) =
            running_identity_fixture();
        let state_path = image_profile.join("state.json");
        let mut state: ImageGenerationState =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        state.generations[0].uki_path = "EFI/Linux/aos-generation-0000000001+3.efi".into();
        state.generations[0].uki_source_path = Some("EFI/Linux/aos-server-1+3.efi".into());
        std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();

        let loaded = load_running_image_generation_fixture(
            &image_profile,
            &immutable_root,
            &toplevel_link,
            &cmdline,
        )
        .unwrap();
        assert_eq!(loaded.uki_path, "EFI/Linux/aos-generation-0000000001+3.efi");

        state.generations[0].uki_source_path = Some("EFI/Linux/attacker+3.efi".into());
        std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        let error = load_running_image_generation_fixture(
            &image_profile,
            &immutable_root,
            &toplevel_link,
            &cmdline,
        )
        .unwrap_err();
        assert!(error.to_string().contains("immutable toplevel metadata"));
    }

    #[test]
    fn running_image_rejects_tampered_roothash_and_slot() {
        let (_tmp, image_profile, immutable_root, toplevel_link, cmdline) =
            running_identity_fixture();
        std::fs::write(
            &cmdline,
            "root=/dev/disk/by-partlabel/root-b roothash=bad\n",
        )
        .unwrap();
        let error = load_running_image_generation_fixture(
            &image_profile,
            &immutable_root,
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
        let error = load_running_image_generation_fixture(
            &image_profile,
            &immutable_root,
            &toplevel_link,
            &cmdline,
        )
        .unwrap_err();
        assert!(error.to_string().contains("root slot"));
    }

    #[test]
    fn running_image_allows_repeatable_non_identity_kernel_parameters() {
        let (_tmp, image_profile, immutable_root, toplevel_link, cmdline) =
            running_identity_fixture();
        std::fs::write(
            &cmdline,
            "console=ttyS0,115200 console=tty0 root=/dev/disk/by-partlabel/root-a roothash=deadbeef\n",
        )
        .unwrap();
        load_running_image_generation_fixture(
            &image_profile,
            &immutable_root,
            &toplevel_link,
            &cmdline,
        )
        .unwrap();

        std::fs::write(
            &cmdline,
            "root=/dev/disk/by-partlabel/root-a roothash=deadbeef roothash=bad\n",
        )
        .unwrap();
        let error = load_running_image_generation_fixture(
            &image_profile,
            &immutable_root,
            &toplevel_link,
            &cmdline,
        )
        .unwrap_err();
        assert!(error.to_string().contains("repeats roothash"));
    }
    #[test]
    fn generation_state_round_trip() {
        let generation = |number, created_at: &str| ConfigGeneration {
            number,
            image_gen_parent: 1,
            module_abi_pinned: 1,
            manifest_hash: format!("sha256:manifest-{number}"),
            package_modules: vec![package_module(
                "server",
                format!("/nix/store/config-{number}"),
            )],
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
                package_modules: vec![package_module("server", "/nix/store/config".into())],
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
            loaded.generations[1]
                .package_modules
                .iter()
                .map(|module| module.store_path.clone())
                .collect::<Vec<_>>(),
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
    fn boot_reconciliation_consumes_selection_intent_and_marks_reevaluation() {
        let temporary = tempfile::TempDir::new().unwrap();
        let image_profile = temporary.path().join("image");
        let system_profile = temporary.path().join("system");
        let marker = temporary.path().join("run/image-reeval-required");
        std::fs::create_dir_all(&image_profile).unwrap();
        std::fs::create_dir_all(&system_profile).unwrap();

        let generation = |number| ImageGeneration {
            number,
            slot: if number == 1 {
                ImageSlot::A
            } else {
                ImageSlot::B
            },
            uki_path: format!("EFI/Linux/aos-{number}+3.efi"),
            uki_source_path: None,
            toplevel: format!("/nix/store/top-{number}"),
            package_name: "aos".into(),
            version: number.to_string(),
            state_version: "7".into(),
            native_executor_ref: format!("/nix/store/executor-{number}"),
            registry: "core".into(),
            kernel_path: None,
            evaluator_ref: format!("/nix/store/base-{number}"),
            module_abi: 1,
            base_lib_abi_hash: format!("sha256:base-{number}"),
            root_verity_roothash: None,
            expected_pcr11: None,
            initrd_pcr11: None,
            recovery: None,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let images = ImageGenerationState {
            running: 2,
            default: 1,
            pending: Some(2),
            recovery_known_good: None,
            recovery_pending: None,
            active_rollout: Some(ImageRollout {
                schema: "aos.image-rollout/v1".into(),
                candidate: 2,
                prior: 1,
                state_version: "7".into(),
                status: ImageRolloutStatus::Staged,
            }),
            last_rollout: None,
            generations: vec![generation(1), generation(2)],
        };
        std::fs::write(
            image_profile.join(IMAGE_STATE_FILE),
            serde_json::to_vec(&images).unwrap(),
        )
        .unwrap();
        std::fs::write(
            image_profile.join(IMAGE_TRANSITION_INTENT),
            serde_json::to_vec(&ImageTransitionIntent {
                target: 2,
                prior_default: 1,
                entry_id: "aos-2+2-1.efi".into(),
            })
            .unwrap(),
        )
        .unwrap();
        save_generation_state(&system_profile, &generation_state_for_commit()).unwrap();

        reconcile_image_boot_for_config_evaluation(&image_profile, &system_profile, &marker)
            .unwrap();

        let reconciled = load_image_generation_state_pub(&image_profile).unwrap();
        assert_eq!(reconciled.default, 2);
        assert_eq!(
            reconciled.active_rollout.unwrap().status,
            ImageRolloutStatus::CandidateBooted
        );
        assert!(!image_profile.join(IMAGE_TRANSITION_INTENT).exists());
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "2\n");
    }

    #[test]
    fn image_selection_preparation_precedes_candidate_publication() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = ImageGenerationState {
            running: 1,
            default: 1,
            pending: None,
            recovery_known_good: None,
            recovery_pending: None,
            active_rollout: None,
            last_rollout: None,
            generations: Vec::new(),
        };

        prepare_image_selection(tmp.path(), &mut state, 2, "aos-2+3.efi", None).unwrap();

        assert_eq!(state.default, 1);
        assert_eq!(state.pending, Some(2));
        assert!(tmp.path().join(IMAGE_TRANSITION_INTENT).is_file());
        assert!(!tmp.path().join("aos-2+3.efi").exists());
        let durable: ImageGenerationState =
            serde_json::from_slice(&std::fs::read(tmp.path().join(IMAGE_STATE_FILE)).unwrap())
                .unwrap();
        assert_eq!(durable.pending, Some(2));
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
            package_modules: vec![
                package_module("cfg-a", format!("/nix/store/cfg-a-{number}")),
                package_module("cfg-b", format!("/nix/store/cfg-b-{number}")),
            ],
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
                "package_modules": {"modules": []},
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
            "users": [],
            "graph": {"edges": {}},
            "config": {},
            "credentials": {},
            "ownership": {
                "etc": {}, "jobScripts": {}, "users": {}, "storePaths": {}
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
            crate::canonical_json_digest(&serde_json::to_value(&parsed).unwrap()).unwrap();
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
    fn system_transition_mode_default() {
        let mode = SystemTransitionMode::default();
        assert_eq!(mode, SystemTransitionMode::Advisory);
    }
}
