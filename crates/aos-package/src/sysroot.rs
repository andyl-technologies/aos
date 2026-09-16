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
//! # Image transition modes
//!
//! [`SystemTransitionMode`] controls what happens after staging: `Advisory`
//! (default) leaves the transition pending and advises a reboot, while
//! `Reboot` drains when requested and queues a full reboot. Kexec and a live
//! userspace-only switch are not valid for an immutable A/B image transition.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

use aos_core::output::{OutputMode, Printer};
use aos_systemd::SystemdClient;

use crate::config::ApmConfig;
use crate::download::{
    DownloadRequest, ResolvedDownload, default_engine, download_nars, fetch_narinfo_closure,
    fetch_narinfos, resolve_mirror_chain, split_mirror_chain,
};
use crate::platform::native_platform;
use crate::registry::sb_certs::{self, SbCertsToml};
use crate::registry::{RegistrySet, store_path_hash};
use crate::resolve::{collect_unique_metas, resolve_multiple};
use crate::store::filter_missing;
use crate::types::{
    ConfigGeneration, ConfigGenerationState, CrossAbiReEvalInputs, ImageGeneration,
    ImageGenerationState, ImageRollout, ImageRolloutStatus, ImageSlot, ImageVerificationState,
    PackageMeta, ProfileScope, ReactivationPlan, RecoveryPublication, RecoveryUkiEntry,
    RegistryRootConfig, SysrootImageEntry, SysrootUkiEntry, UkiSlot,
};
use crate::verify::{verify_download_hash, verify_downloads};

mod activatability;
pub(crate) mod image_rollout;
pub use image_rollout::run_boot_commit_from_process as run_image_rollout_boot_commit;
pub use image_rollout::run_observer_from_process as run_image_rollout_observer;
pub use image_rollout::run_provider_from_process as run_image_rollout_provider;

pub use activatability::{
    ActivatabilityReason, ActivatabilityReasonCode, RETAINED_ACTIVATABILITY_SCHEMA,
    RetainedActivatabilityReport, RetainedActivationMode, RetainedTargetKind,
};

use image_rollout::{
    is_qualified_image_rollout, preflight_image_selection, qualified_rollout_record,
    validate_active_rollout_selection,
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
const SYSTEM_STATE_FILE: &str = "state.json";
const SYSTEM_COMMIT_JOURNAL: &str = ".state-commit.json";
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
const IMMUTABLE_DRAIN_SCRIPT: &str = "/usr/lib/aos/drain";
const RUNNING_CMDLINE: &str = "/proc/cmdline";
const IMMUTABLE_ACTIVE_DB_CERTS: &str = "/usr/lib/aos/image-trust/active-db-certs.pem";
const MAX_CONFIGURED_DB_CERTIFICATES: usize = 32;
const MAX_INSTALLED_UKI_BYTES: u64 = 256 * 1024 * 1024;
const MAX_OS_RELEASE_BYTES: u64 = 64 * 1024;
const MAX_UKI_IDENTITY_SECTION_BYTES: usize = 64 * 1024;
const SUPPORTED_RECOVERY_ABI: u32 = 1;

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

/// Filesystem locations used by the offline A/B writer.
struct ImageSlotLayout {
    boot_root: PathBuf,
    esp_devices: Vec<PathBuf>,
    root_a: PathBuf,
    root_b: PathBuf,
    root_a_hash: PathBuf,
    root_b_hash: PathBuf,
}

impl Default for ImageSlotLayout {
    fn default() -> Self {
        Self {
            boot_root: PathBuf::from(BOOT_ROOT),
            esp_devices: vec![PathBuf::from("/dev/disk/by-partlabel/ESP")],
            root_a: PathBuf::from(ROOT_A_DEVICE),
            root_b: PathBuf::from(ROOT_B_DEVICE),
            root_a_hash: PathBuf::from(ROOT_A_HASH_DEVICE),
            root_b_hash: PathBuf::from(ROOT_B_HASH_DEVICE),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootStorageMetadata {
    esp_devices: Vec<PathBuf>,
    devices: BootStorageDevices,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootStorageDevices {
    root_a: PathBuf,
    root_b: PathBuf,
    root_a_hash: PathBuf,
    root_b_hash: PathBuf,
}

impl ImageSlotLayout {
    fn from_running_toplevel() -> Result<Self> {
        Self::from_toplevel(Path::new(RUNNING_TOPLEVEL_LINK))
    }

    fn from_toplevel(toplevel: &Path) -> Result<Self> {
        let path = toplevel.join("meta/boot-storage.json");
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading boot-storage metadata {}", path.display()))?;
        let metadata: BootStorageMetadata = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing boot-storage metadata {}", path.display()))?;
        if metadata.esp_devices.is_empty() {
            bail!("boot-storage metadata has no EFI System Partition devices");
        }
        for device in metadata.esp_devices.iter().chain([
            &metadata.devices.root_a,
            &metadata.devices.root_b,
            &metadata.devices.root_a_hash,
            &metadata.devices.root_b_hash,
        ]) {
            if !device.is_absolute() || !device.starts_with("/dev") {
                bail!(
                    "boot-storage metadata contains unsafe device {}",
                    device.display()
                );
            }
        }
        Ok(Self {
            boot_root: PathBuf::from(BOOT_ROOT),
            esp_devices: metadata.esp_devices,
            root_a: metadata.devices.root_a,
            root_b: metadata.devices.root_b,
            root_a_hash: metadata.devices.root_a_hash,
            root_b_hash: metadata.devices.root_b_hash,
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
    transition_mode: SystemTransitionMode,
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
            crate::store::import_nar_with_compression(
                &result.local_path,
                &result.store_path,
                &result.references,
                result.deriver.as_deref(),
                &result.compression,
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
        let qualified_rollout = is_qualified_image_rollout(transition_mode, drain);
        preflight_image_selection(
            image_profile,
            &ProfileScope::System.profile_path(),
            Path::new(&toplevel_meta.store_path),
            qualified_rollout,
        )?;
        if qualified_rollout {
            drain_workloads(printer).await?;
        }
        printer.step(8, 8, "Staging inactive A/B image slot...");
        let layout = ImageSlotLayout::from_running_toplevel()?;
        let staged = with_writable_boot(|| {
            stage_pending_image_generation_with(
                image_profile,
                &ProfileScope::System.profile_path(),
                Path::new(NIX_OVERLAY_UPPER_STORE),
                &layout,
                toplevel_meta,
                &closure.registry_name,
                image,
                &image_store,
                qualified_rollout,
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
        match transition_mode {
            SystemTransitionMode::Reboot => {
                SystemdClient::connect().await?.reboot().await?;
            }
            SystemTransitionMode::Advisory => {
                printer.plain(
                    "  Reboot to assess the counted image and re-evaluate host configuration.",
                );
            }
        }
        return Ok(());
    }
    bail!(
        "image generation state is absent; refusing to recreate the retired single-axis system-generation authority"
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
    let production_device = destination.starts_with("/dev");
    if production_device {
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
    if (production_device && !destination_metadata.file_type().is_block_device())
        || (!production_device
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
    with_writable_boot_controlled(remount_boot, action)
}

/// Runs one ESP mutation with caller-supplied bounded remount operations.
///
/// The physical mount identity is authenticated before making the ESP writable,
/// and the read-only restoration is attempted even when the mutation fails.
///
/// # Errors
///
/// Returns an error when mount validation, either remount, or the action fails.
pub(crate) fn with_writable_boot_controlled<T>(
    remount: impl FnMut(&Path, bool) -> Result<()>,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let layout = ImageSlotLayout::from_running_toplevel()?;
    validate_boot_esp_mount(
        Path::new(BOOT_ROOT),
        Path::new("/proc/self/mountinfo"),
        &layout.esp_devices,
        true,
    )?;
    with_writable_boot_using(Path::new(BOOT_ROOT), remount, action)
}

fn validate_boot_esp_mount(
    boot_root: &Path,
    mountinfo: &Path,
    expected_devices: &[PathBuf],
    require_block_devices: bool,
) -> Result<()> {
    let boot_root = std::fs::canonicalize(boot_root)
        .with_context(|| format!("resolving EFI mount point {}", boot_root.display()))?;
    if expected_devices.is_empty() {
        bail!("no EFI System Partition devices are configured");
    }
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
    let mounted_file = std::fs::File::open(source)
        .with_context(|| format!("opening mounted EFI device {source}"))?;
    let mounted_metadata = mounted_file.metadata()?;
    if require_block_devices && !mounted_metadata.file_type().is_block_device() {
        bail!("EFI System Partition paths must both be block devices");
    }
    let mounted_device = std::fs::canonicalize(source)
        .with_context(|| format!("resolving mounted EFI device {source}"))?;
    let mut matched = false;
    for expected_device in expected_devices {
        // A failed replica must not prevent validating the ESP that firmware
        // actually selected. Replication still reports the failed member when
        // the transaction attempts to synchronize every configured ESP.
        let Ok(expected_device) = std::fs::canonicalize(expected_device) else {
            continue;
        };
        let Ok(expected_file) = std::fs::File::open(&expected_device) else {
            continue;
        };
        let expected_metadata = expected_file.metadata()?;
        if require_block_devices && !expected_metadata.file_type().is_block_device() {
            bail!("EFI System Partition paths must both be block devices");
        }
        matched = if expected_metadata.file_type().is_block_device()
            && mounted_metadata.file_type().is_block_device()
        {
            expected_metadata.rdev() == mounted_metadata.rdev()
        } else {
            mounted_device == expected_device
        };
        if matched {
            break;
        }
    }
    if !matched {
        bail!(
            "{} is mounted from {}, not a configured EFI System Partition",
            boot_root.display(),
            mounted_device.display()
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

fn verity_roothash_hex(digest: &str) -> &str {
    digest
        .strip_prefix("sha256:")
        .or_else(|| digest.strip_prefix("sha256-"))
        .unwrap_or(digest)
}

fn stage_slot_artifacts(
    layout: &ImageSlotLayout,
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
    layout: &ImageSlotLayout,
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
        ImageSlot::A => (&layout.root_a, &layout.root_a_hash, "uki-a.efi"),
        ImageSlot::B => (&layout.root_b, &layout.root_b_hash, "uki-b.efi"),
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
        if actual.trim() != verity_roothash_hex(expected) {
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
    layout: &ImageSlotLayout,
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
            reverify_installed_uki(&entry.path())?;
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
    layout: &ImageSlotLayout,
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
    reverify_installed_uki(&recovery_path)?;
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
    layout: &ImageSlotLayout,
    state: &ImageGenerationState,
    slot: ImageSlot,
    keep_recorded: &str,
) -> Result<()> {
    let retained_entries = image_rollout::retained_uki_entry_ids(&layout.boot_root)?;
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
        let Ok(entry) = resolve_installed_uki_entry(&layout.boot_root, &previous.uki_path) else {
            continue;
        };
        if stable_uki_entry_id(&entry)? == keep_entry
            || retained_entries.contains(&stable_uki_entry_id(&entry)?)
        {
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
    layout: &ImageSlotLayout,
    package: &PackageMeta,
    registry: &str,
    image: &SysrootImageEntry,
    image_store: &Path,
    qualified_rollout: bool,
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
    let state_version = read_toplevel_meta(toplevel, "state-version")?;
    ensure!(
        !state_version.is_empty(),
        "target image has an empty state version"
    );
    let native_executor_ref = read_toplevel_meta(toplevel, "native-executor-ref")?;
    crate::config_eval::materialize::validate_canonical_store_path(&native_executor_ref)
        .context("validating target native executor identity")?;
    let base_lib_abi_hash = read_toplevel_meta(toplevel, "base-lib-abi-hash")?;
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
        // A crash may occur after the authenticated pending record is durable
        // but before its UKI is published. In that case, fall through and
        // reconstruct the same slot transaction instead of requiring an entry
        // that deliberately does not exist yet.
        if let Ok(pending_entry) = resolve_installed_uki_entry(&layout.boot_root, &pending.uki_path)
        {
            if pending.toplevel != package.store_path {
                bail!(
                    "image generation {} is already published and pending; refusing to replace it",
                    pending.number
                );
            }
            let rollout = qualified_rollout
                .then(|| qualified_rollout_record(&state, pending.number, &pending.state_version))
                .transpose()?;
            select_image_default_with(
                profile,
                &mut state,
                pending.number,
                &pending_entry,
                rollout,
                select,
            )?;
            cleanup_replaced_slot_ukis(layout, &state, pending.slot, &pending.uki_path)?;
            replicate_boot_partitions(layout)?;
            return Ok(pending);
        }
        if pending.toplevel != package.store_path {
            ensure!(
                state.active_rollout.is_none(),
                "unfinished qualified rollout targets image generation {}; refusing to replace its unpublished candidate",
                pending.number
            );
            abort_unpublished_image_selection(profile, &mut state, pending.number)?;
        }
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

    // Copy every lower-backed running identity before the inactive slot is
    // overwritten. The candidate closure arrived through Nix, but copying its
    // exact identities is idempotent and ensures all ordinary image roots point
    // into the persistent upper rather than a replaceable immutable lower.
    persist_store_closure_to_upper(&running.evaluator_ref, upper_store)?;
    persist_store_closure_to_upper(&running.toplevel, upper_store)?;
    persist_store_closure_to_upper(&running.native_executor_ref, upper_store)?;
    persist_store_closure_to_upper(&evaluator_ref, upper_store)?;
    persist_store_closure_to_upper(&package.store_path, upper_store)?;
    persist_store_closure_to_upper(&native_executor_ref, upper_store)?;
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
        state_version: state_version.clone(),
        native_executor_ref,
        registry: registry.to_string(),
        kernel_path: resolve_kernel_path(&package.store_path),
        evaluator_ref: evaluator_ref.clone(),
        module_abi,
        base_lib_abi_hash,
        root_verity_roothash: image
            .root_hash
            .as_deref()
            .map(verity_roothash_hex)
            .map(str::to_string)
            .or_else(|| {
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
    // Authenticate and mark the generation pending before any
    // firmware-discoverable UKI is published. A crash may leave a pending
    // record without an entry, which is safe and retryable; the inverse would
    // let firmware select a candidate that boot assessment refuses to bless.
    write_atomic_durable(
        &profile.join(IMAGE_STATE_FILE),
        &serde_json::to_vec_pretty(&state)?,
    )?;
    let rollout = qualified_rollout
        .then(|| qualified_rollout_record(&state, number, &state_version))
        .transpose()?;
    prepare_image_selection(profile, &mut state, number, &entry_id, rollout.clone())?;
    stage_slot_artifacts(
        layout,
        target_slot,
        image_store,
        image,
        &installed_uki,
        &reusable_ukis,
        recovery.as_ref(),
    )?;
    replicate_boot_partitions(layout)?;
    state.recovery_pending = None;
    crate::store::create_image_gc_roots(&profile.join(format!("image-gen-{number}")), &generation)?;
    let configs = load_generation_state_readonly(system_profile)?;
    crate::store::reconcile_image_gc_roots(profile, &state, &configs)?;
    select_image_default_with(profile, &mut state, number, &entry_id, rollout, select)?;
    cleanup_replaced_slot_ukis(layout, &state, target_slot, &installed_uki)?;
    replicate_boot_partitions(layout)?;
    Ok(generation)
}

/// Clears a durable selection intent whose UKI was never published.
fn abort_unpublished_image_selection(
    profile: &Path,
    state: &mut ImageGenerationState,
    target: u32,
) -> Result<()> {
    ensure!(
        state.active_rollout.is_none(),
        "cannot abort unpublished image generation {target} while its qualified rollout is active"
    );
    if state.pending != Some(target) {
        bail!("cannot abort image generation {target}: it is not pending");
    }
    // Removing the intent first is crash-safe: the authenticated pending
    // record still prevents an unknown image from being blessed, while a
    // retry can repeat this cleanup. This path is called only after proving
    // that no firmware-discoverable candidate exists.
    remove_file_durable(&profile.join(IMAGE_TRANSITION_INTENT))?;
    state.pending = None;
    write_atomic_durable(
        &profile.join(IMAGE_STATE_FILE),
        &serde_json::to_vec_pretty(state)?,
    )
}

fn replicate_boot_partitions(layout: &ImageSlotLayout) -> Result<()> {
    if layout.esp_devices.len() <= 1 {
        return Ok(());
    }
    let status = std::process::Command::new("aos-sync-esps")
        .status()
        .context("replicating EFI System Partitions")?;
    if !status.success() {
        bail!("EFI System Partition replication failed with {status}");
    }
    Ok(())
}

/// Selects an older A/B image generation durably with `bootctl set-default`.
///
/// This changes only the next-boot image axis. The currently running image and
/// config pointer remain untouched; after reboot the compiled configuration
/// evaluation service rebinds configuration to the image that actually booted.
///
/// # Errors
///
/// Returns an error for an unknown image generation, unsafe UKI path,
/// `bootctl` failure, state publication failure, or requested reboot failure.
pub async fn rollback_image_generation(
    generation: Option<u32>,
    list: bool,
    dry_run: bool,
    transition_mode: SystemTransitionMode,
    drain: bool,
    printer: &Printer,
) -> Result<()> {
    let profile = Path::new(IMAGE_PROFILE_DIR);
    let mut state = load_image_generation_state_pub(profile)?;
    let switch_lock = crate::config_eval::activation::ActivateConfigParams::default().switch_lock;
    let _switch_guard = crate::config_eval::activation::acquire_switch_lock_pub(&switch_lock)?;
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
    let system_profile = ProfileScope::System.profile_path();
    let activatability =
        activatability::image(profile, &system_profile, &target, transition_mode, drain);
    print_activatability(&activatability, printer)?;
    activatability.require_activatable()?;
    if dry_run {
        printer.info(&format!(
            "Would set image generation {} ({}) as the durable next boot.",
            target.number, entry_id
        ));
        return Ok(());
    }
    let qualified_rollout = is_qualified_image_rollout(transition_mode, drain);
    preflight_image_selection(
        profile,
        &system_profile,
        Path::new(&target.toplevel),
        qualified_rollout,
    )?;
    let rollout = if qualified_rollout {
        drain_workloads(printer).await?;
        Some(qualified_rollout_record(
            &state,
            target.number,
            &target.state_version,
        )?)
    } else {
        None
    };
    with_writable_boot(|| {
        select_image_default_with(
            profile,
            &mut state,
            target.number,
            &entry_id,
            rollout,
            |entry| {
                let status = std::process::Command::new("bootctl")
                    .arg("set-default")
                    .arg(entry)
                    .status()
                    .context("running bootctl set-default")?;
                if !status.success() {
                    bail!("bootctl set-default failed with {status}");
                }
                Ok(())
            },
        )
    })?;
    printer.success(&format!(
        "Image generation {} is the durable next-boot default.",
        target.number
    ));
    if transition_mode == SystemTransitionMode::Reboot {
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
    #[cfg(test)]
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
    rollout: Option<ImageRollout>,
    select: F,
) -> Result<()>
where
    F: FnOnce(&str) -> Result<()>,
{
    prepare_image_selection(profile, state, target, entry_id, rollout)?;
    let stable_entry_id = stable_uki_entry_id(entry_id)?;

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
    remove_file_durable(&profile.join(IMAGE_TRANSITION_INTENT))?;
    *state = committed;
    Ok(())
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
async fn ensure_image_imported(
    config: &ApmConfig,
    package: &PackageMeta,
    image: &SysrootImageEntry,
    printer: &Printer,
) -> Result<PathBuf> {
    let (authenticated_path, authenticated_hash) = image
        .delivery
        .update_payload
        .as_ref()
        .map(|payload| (payload.store_path.as_str(), payload.nar_hash.as_str()))
        .unwrap_or((image.store_path.as_str(), image.nar_hash.as_str()));
    let store_path = PathBuf::from(authenticated_path);
    if store_path.exists() {
        return Ok(store_path);
    }

    let chain = resolve_image_mirror(config, package);
    let (mirror_url, fallback_mirrors) = split_mirror_chain(&chain);
    let request = DownloadRequest {
        store_path: authenticated_path.to_string(),
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
    crate::verify::verify_nar_hash_with_compression(
        &result.local_path,
        authenticated_hash,
        &result.compression,
    )
    .with_context(|| format!("verifying image update NAR for {authenticated_path}"))?;
    crate::store::import_nar_with_compression(
        &result.local_path,
        &result.store_path,
        &result.references,
        result.deriver.as_deref(),
        &result.compression,
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

/// Returns the directory that carries authenticated in-place update artifacts.
fn image_update_store_path(image: &SysrootImageEntry) -> &Path {
    Path::new(
        image
            .delivery
            .update_payload
            .as_ref()
            .map(|payload| payload.store_path.as_str())
            .unwrap_or(image.store_path.as_str()),
    )
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
/// Runs the current image's immutable hook, falling back to the active
/// toplevel for compatibility with images built before the immutable hook was
/// introduced. If neither script exists, it isolates `drain.target` and waits
/// for `drain-complete.target`. An unavailable or failed drain mechanism is an
/// error: an explicit `--drain` request must never silently reboot workloads.
async fn drain_workloads(printer: &Printer) -> Result<()> {
    let running_toplevel_drain = format!("{RUNNING_TOPLEVEL_LINK}/drain");
    let drain_script = [IMMUTABLE_DRAIN_SCRIPT, running_toplevel_drain.as_str()]
        .into_iter()
        .find(|candidate| Path::new(candidate).exists());
    if let Some(drain_script) = drain_script {
        printer.plain("Draining workloads...");
        run_command(drain_script, &[])?;
        printer.plain("Drain complete.");
        return Ok(());
    }

    // The client is constructed lazily on the no-script path. Queueing the
    // isolate directly makes a missing target fail closed instead of
    // confusing an existing but inactive target with an absent one.
    let client = SystemdClient::connect().await?;
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
    RegistrySet::load_for_package_operations(&config.cache_path(), &reg_configs, &native_platform())
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
/// Returns an error when the registry root or catalog fails to load/parse, the
/// registry requires signed UKIs but an image is not policy-verified, or any
/// signed image fails [`validate_image_secure_boot`].
fn validate_sysroot_secure_boot_in(
    images: &[crate::types::SysrootImageEntry],
    registry_name: &str,
    catalog_dir: &Path,
    db_cert: Option<&Path>,
    printer: &Printer,
) -> Result<()> {
    let registry_config_path = catalog_dir.join("registry.toml");
    let require_signed_ukis = if registry_config_path.is_file() {
        let source = std::fs::read_to_string(&registry_config_path).with_context(|| {
            format!(
                "reading committed registry configuration {}",
                registry_config_path.display()
            )
        })?;
        let root: RegistryRootConfig = toml::from_str(&source).with_context(|| {
            format!(
                "parsing committed registry configuration {}",
                registry_config_path.display()
            )
        })?;
        root.registry.require_signed_ukis
    } else {
        false
    };
    let direct_images = images
        .iter()
        .filter(|image| !image.delivery.is_store_only())
        .collect::<Vec<_>>();
    if require_signed_ukis {
        for image in &direct_images {
            if image.delivery.uki.verification != ImageVerificationState::PolicyVerified {
                bail!(
                    "registry '{registry_name}' requires signed UKIs, but image format '{}' is not policy-verified",
                    image.format
                );
            }
        }
    }

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
        if require_signed_ukis && !direct_images.is_empty() {
            bail!(
                "registry '{registry_name}' requires signed UKIs but publishes no sb-certs.toml policy"
            );
        }
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
        if let Some(uki) = find_uki_in_image(image_update_store_path(img))? {
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
            image_update_store_path(image),
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
    let store = image_update_store_path(image);
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
        image_update_store_path(image),
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
    let artifact =
        image_artifact_path(image_update_store_path(image), Some(&uki.path), "slot UKI")?;
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
fn find_uki_in_image(root: &Path) -> Result<Option<PathBuf>> {
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
            "legacy image artifact {} contains {count} UKIs; deterministic selection requires slot metadata",
            root.display()
        ),
    }
}

/// Re-verifies an installed UKI against the immutable configured db snapshot.
fn reverify_installed_uki(uki: &Path) -> Result<()> {
    let certificates = immutable_active_db_certificates()?;
    let mut temporary_certificates = Vec::new();
    for certificate in certificates {
        let mut temporary = tempfile::Builder::new()
            .prefix("aos-configured-db-")
            .suffix(".crt")
            .tempfile()
            .context("creating temporary configured db certificate")?;
        temporary
            .write_all(certificate.as_bytes())
            .context("writing temporary configured db certificate")?;
        let validation = std::process::Command::new("openssl")
            .args(["x509", "-noout", "-in"])
            .arg(temporary.path())
            .output()
            .context("validating immutable configured db certificate")?;
        if !validation.status.success() {
            bail!("immutable configured db snapshot contains an invalid X.509 certificate");
        }
        temporary_certificates.push(temporary);
    }

    let mut failures = Vec::new();
    for temporary in &temporary_certificates {
        match reverify_uki(uki, temporary.path()) {
            Ok(()) => return Ok(()),
            Err(error) => failures.push(error.to_string()),
        }
    }
    bail!(
        "installed UKI {} is not authorized by the immutable configured db snapshot: {}",
        uki.display(),
        failures.join("; ")
    )
}

fn immutable_active_db_certificates() -> Result<Vec<String>> {
    let mut certificates = Vec::new();
    for source in [PathBuf::from(IMMUTABLE_ACTIVE_DB_CERTS)] {
        let metadata = std::fs::metadata(&source).with_context(|| {
            format!(
                "inspecting configured db certificate source {}",
                source.display()
            )
        })?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 1024 * 1024 {
            bail!(
                "configured db certificate source {} is empty, oversized, or not a regular file",
                source.display()
            );
        }
        let bundle = std::fs::read_to_string(&source).with_context(|| {
            format!(
                "reading configured db certificate source {}",
                source.display()
            )
        })?;
        certificates.extend(parse_pem_certificates(&bundle).with_context(|| {
            format!(
                "parsing configured db certificate source {}",
                source.display()
            )
        })?);
        if certificates.len() > MAX_CONFIGURED_DB_CERTIFICATES {
            bail!(
                "immutable configured db snapshot contains more than {MAX_CONFIGURED_DB_CERTIFICATES} certificates"
            );
        }
    }
    if certificates.is_empty() {
        bail!("immutable configured db snapshot contains no certificates");
    }
    Ok(certificates)
}

fn parse_pem_certificates(bundle: &str) -> Result<Vec<String>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let mut remaining = bundle;
    let mut certificates = Vec::new();
    loop {
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }
        if !remaining.starts_with(BEGIN) {
            bail!("certificate bundle contains data outside a PEM certificate");
        }
        let end = remaining
            .find(END)
            .context("certificate bundle contains an unterminated PEM certificate")?
            + END.len();
        certificates.push(format!("{}\n", &remaining[..end]));
        remaining = &remaining[end..];
    }
    if certificates.is_empty() {
        bail!("certificate bundle contains no PEM certificates");
    }
    Ok(certificates)
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
    use std::os::unix::fs::PermissionsExt as _;

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

    #[test]
    fn parses_only_complete_pem_certificate_sets() {
        let certificate = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";
        let pair = format!("{certificate}\n{certificate}");
        assert_eq!(parse_pem_certificates(&pair).unwrap().len(), 2);
        assert!(parse_pem_certificates(&format!("{certificate}junk")).is_err());
        assert!(parse_pem_certificates("-----BEGIN CERTIFICATE-----\n").is_err());
    }
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

    #[test]
    fn update_staging_prefers_separately_authenticated_payload() {
        let mut image = signed_image(SIGNER_ACTIVE, &[("aos", 1)]);
        assert_eq!(
            image_update_store_path(&image),
            Path::new(&image.store_path)
        );

        image.delivery.update_payload = Some(crate::types::ImageStoreReference {
            store_path: "/nix/store/11111111111111111111111111111111-update-payload".into(),
            nar_hash: format!("sha256:{}", "1".repeat(52)),
            nar_size: 4096,
        });
        assert_eq!(
            image_update_store_path(&image),
            Path::new("/nix/store/11111111111111111111111111111111-update-payload")
        );
    }

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
        assert_eq!(layout.esp_devices.len(), 2);
        assert_eq!(layout.root_b, Path::new("/dev/zvol/rpool/aos/slots/root-b"));
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
            boot_root: boot.clone(),
            esp_devices: vec![tmp.path().join("esp")],
            root_a: root_a.clone(),
            root_b: root_b.clone(),
            root_a_hash: hash_a.clone(),
            root_b_hash: hash_b.clone(),
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
        image.root_hash = Some("sha256:deadbeef".into());

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
                    boot_root: boot.clone(),
                    esp_devices: vec![boot.clone()],
                    root_a: root_a.clone(),
                    root_b: root_b.clone(),
                    root_a_hash: hash_a.clone(),
                    root_b_hash: hash_b.clone(),
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

        validate_boot_esp_mount(&boot, &mountinfo, std::slice::from_ref(&expected), false).unwrap();

        let missing = devices.join("missing-replica");
        validate_boot_esp_mount(&boot, &mountinfo, &[missing, expected.clone()], false).unwrap();

        std::fs::write(
            &mountinfo,
            format!(
                "31 24 254:2 / {} ro,relatime - vfat {} rw\n",
                boot_mountpoint.display(),
                wrong.display()
            ),
        )
        .unwrap();
        let error =
            validate_boot_esp_mount(&boot, &mountinfo, std::slice::from_ref(&expected), false)
                .unwrap_err();
        assert!(error.to_string().contains("not a configured"));

        std::fs::write(
            &mountinfo,
            format!(
                "31 24 254:1 /subdir {} ro,relatime - vfat {} rw\n",
                boot_mountpoint.display(),
                esp.display()
            ),
        )
        .unwrap();
        let error =
            validate_boot_esp_mount(&boot, &mountinfo, std::slice::from_ref(&expected), false)
                .unwrap_err();
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
        let error =
            validate_boot_esp_mount(&boot, &mountinfo, std::slice::from_ref(&expected), false)
                .unwrap_err();
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
        let error =
            validate_boot_esp_mount(&boot, &mountinfo, std::slice::from_ref(&expected), true)
                .unwrap_err();
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
            state_version: "1".into(),
            native_executor_ref: format!("/nix/store/{}-executor", "e".repeat(32)),
            registry: "core".into(),
            kernel_path: None,
            evaluator_ref: format!("/nix/store/base-{number}"),
            module_abi: 1,
            base_lib_abi_hash: format!("digest-{number}"),
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
            active_rollout: None,
            last_rollout: None,
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
            boot_root: boot,
            esp_devices: vec![tmp.path().join("esp")],
            root_a,
            root_b,
            root_a_hash: hash_a,
            root_b_hash: hash_b,
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
            boot_root: boot.clone(),
            esp_devices: vec![tmp.path().join("esp")],
            root_a,
            root_b: root_b.clone(),
            root_a_hash: hash_a,
            root_b_hash: hash_b,
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

        std::fs::write(
            tmp.path().join("registry.toml"),
            "[registry]\nname = \"aos\"\nrequire_signed_ukis = true\n",
        )
        .unwrap();
        assert!(
            validate_sysroot_secure_boot_in(&unsigned, "aos", tmp.path(), None, &printer).is_err()
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
    fn image_selection_intent_survives_failure_and_retries_idempotently() {
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
        let error =
            select_image_default_with(tmp.path(), &mut state, 2, "aos-2+3.efi", None, |_| {
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
        select_image_default_with(tmp.path(), &mut state, 2, "aos-2+3.efi", None, |entry| {
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
    fn unpublished_image_selection_can_be_aborted_for_a_corrected_retry() {
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

        abort_unpublished_image_selection(tmp.path(), &mut state, 2).unwrap();

        assert_eq!(state.default, 1);
        assert_eq!(state.pending, None);
        assert!(!tmp.path().join(IMAGE_TRANSITION_INTENT).exists());
        let durable: ImageGenerationState =
            serde_json::from_slice(&std::fs::read(tmp.path().join(IMAGE_STATE_FILE)).unwrap())
                .unwrap();
        assert_eq!(durable.pending, None);

        prepare_image_selection(tmp.path(), &mut state, 3, "aos-3+3.efi", None).unwrap();
        assert_eq!(state.pending, Some(3));
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
    fn chrono_iso8601_format() {
        let result = chrono_iso8601_now();
        assert!(result.ends_with('Z'));
        assert_eq!(result.len(), 20);
        assert!(result.starts_with("20"));
    }

    #[test]
    fn system_transition_mode_default() {
        let mode = SystemTransitionMode::default();
        assert_eq!(mode, SystemTransitionMode::Advisory);
    }
}
