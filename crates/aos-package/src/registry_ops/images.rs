//! Disk-image producer metadata validation and publication input inspection.
//!
//! The producer JSON manifest is read from a canonical store output. Its identity
//! and delivery sections bind the disk bytes to their parent package and UKI:
//!
//! ```text
//! image-info.json
//!   schemaVersion, name, version, architecture, platform
//!   disk artifact identity and logical disk geometry
//!   partition, ESP, UKI, and recovery metadata
//! ```

use crate::registry::parse::{
    ImageCompression, ImageDelivery, ImageInfoReference, ImageStoreReference, ImageTarget,
    ImageUkiIdentity, ImageVerificationState,
};
use crate::registry_ops::images::files::{
    ValidatedImageDirectory, ValidatedImageFile, file_identity, inheritable_procfd,
    open_canonical_store_regular_file, open_stable_regular_file_at_with_links,
    open_stable_regular_file_with_links, sha256_open_file, validate_lower_sha256,
    validate_portable_relative_path, validate_single_filename, verify_embedded_uki,
    verify_stable_regular_file,
};
use crate::registry_ops::store_paths::{StorePathInfo, store_dir_from_store_path};
use crate::registry_ops::uki::{
    SbFacts, derive_recovery_bundle_manifest, derive_recovery_uki_facts, derive_sb_facts,
    derive_slot_uki_facts, sha256_hex, verify_detached_db_signature,
};
use crate::types::{RecoveryBundleManifest, UkiSlot, validate_package_name};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

/// A fully validated disk-image publication input.
///
/// Unlike the historical NAR-only tuple, this binds the exact disk file and
/// producer metadata that direct-download consumers receive.
pub(in crate::registry_ops) struct PublishedImage {
    pub(in crate::registry_ops) format: String,
    /// Canonical directory store output carrying the A/B update artifacts.
    pub(in crate::registry_ops) payload: StorePathInfo,
    /// Canonical regular-file store output containing the disk encoding.
    pub(in crate::registry_ops) store: StorePathInfo,
    /// Canonical regular-file store output containing `image-info.json`.
    pub(in crate::registry_ops) info_store: StorePathInfo,
    pub(in crate::registry_ops) sb: SbFacts,
    pub(in crate::registry_ops) delivery: ImageDelivery,
    /// Pinned image-output directory that owns the disk and metadata names.
    pub(in crate::registry_ops) directory: ValidatedImageDirectory,
    /// Exact validated disk store output retained through commit.
    pub(in crate::registry_ops) disk: ValidatedImageFile,
    /// Exact validated metadata store output retained through commit.
    pub(in crate::registry_ops) image_info: ValidatedImageFile,
    /// Original producer metadata retained to detect replacement before commit.
    pub(in crate::registry_ops) producer_image_info: ValidatedImageFile,
    /// Exact UKI whose Secure Boot facts were recorded in the catalog.
    pub(in crate::registry_ops) uki: ValidatedImageFile,
    /// Byte offset of the ESP in the canonical raw logical disk.
    pub(in crate::registry_ops) esp_offset_bytes: u64,
    /// Byte interval of the canonical root filesystem payload.
    pub(in crate::registry_ops) root_range: (u64, u64),
    /// Exact byte length of the reconstructed canonical raw disk.
    pub(in crate::registry_ops) virtual_size_bytes: u64,
}

/// Delivery fields emitted by every system image derivation's
/// `image-info.json`.
///
/// The complete, versioned public producer manifest. Unknown top-level and
/// nested fields are rejected so private build-environment data can never be
/// uploaded accidentally.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerImageInfo {
    schema_version: u32,
    name: String,
    version: String,
    architecture: String,
    platform: String,
    format: String,
    filename: String,
    media_type: String,
    compression: ImageCompression,
    byte_size: u64,
    virtual_size_bytes: u64,
    sha256: String,
    logical_disk_sha256: String,
    rootfs_sha256: String,
    artifact_budgets_mi_b: ProducerArtifactBudgets,
    #[serde(default)]
    module_abi: Option<u32>,
    compatible_targets: Vec<ImageTarget>,
    uki: PortableUkiInfo,
    #[serde(default)]
    disk_size_mi_b: Option<u64>,
    #[serde(default)]
    esp_size_mi_b: Option<u64>,
    #[serde(default)]
    esp_budget: Option<ProducerEspBudget>,
    #[serde(default)]
    root_size_mi_b: Option<u64>,
    #[serde(default)]
    partition_table: Option<String>,
    #[serde(default)]
    kernel_params: Option<String>,
    #[serde(default)]
    partitions: Vec<ProducerPartitionInfo>,
    #[serde(default)]
    esp: Option<ProducerEspInfo>,
    #[serde(default)]
    recovery: Option<ProducerRecoveryInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PortableUkiInfo {
    filename: String,
    esp_path: String,
    byte_size: u64,
    sha256: String,
    signed: bool,
    measured: bool,
}

/// Maximum artifact sizes and storage geometry declared by an image producer.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerArtifactBudgets {
    root: u64,
    verity: u64,
    initrd: u64,
    uki: u64,
    esp: u64,
    runtime_closure: u64,
    download: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::registry_ops) struct ProducerRecoveryInfo {
    pub(in crate::registry_ops) abi: u32,
    pub(in crate::registry_ops) release: String,
    pub(in crate::registry_ops) command_line: String,
    pub(in crate::registry_ops) copies: ProducerRecoveryCopies,
    pub(in crate::registry_ops) entries: ProducerRecoveryEntries,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::registry_ops) struct ProducerRecoveryCopies {
    #[serde(rename = "A")]
    pub(in crate::registry_ops) a: ProducerRecoveryCopy,
    #[serde(rename = "B")]
    pub(in crate::registry_ops) b: ProducerRecoveryCopy,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::registry_ops) struct ProducerRecoveryCopy {
    pub(in crate::registry_ops) esp_path: String,
    pub(in crate::registry_ops) byte_size: u64,
    pub(in crate::registry_ops) sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::registry_ops) struct ProducerRecoveryEntries {
    #[serde(rename = "A")]
    pub(in crate::registry_ops) a: String,
    #[serde(rename = "B")]
    pub(in crate::registry_ops) b: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerPartitionInfo {
    number: u32,
    label: String,
    #[serde(rename = "type")]
    kind: String,
    filesystem: String,
    size_mi_b: u64,
    offset_bytes: u64,
    size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerEspInfo {
    uki: String,
    sd_boot: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerEspBudget {
    installed_bytes: u64,
    transaction_bytes: u64,
    required_bytes: u64,
    partition_bytes: u64,
}

/// Verifies that declared budgets agree with observable image metadata.
fn validate_image_artifact_budgets(
    budgets: &ProducerArtifactBudgets,
    download_size: u64,
    uki_size: u64,
    partitions: &[ProducerPartitionInfo],
) -> Result<()> {
    let nonzero = [
        budgets.root,
        budgets.verity,
        budgets.initrd,
        budgets.uki,
        budgets.esp,
        budgets.runtime_closure,
        budgets.download,
    ]
    .into_iter()
    .all(|value| value > 0);
    let uki_fits = uki_size <= budgets.uki.saturating_mul(1024 * 1024);
    let download_fits = download_size <= budgets.download.saturating_mul(1024 * 1024);
    let esp_holds_two_ukis = budgets.esp >= budgets.uki.saturating_mul(2).saturating_add(32);
    let partition_contracts_match = partitions.iter().all(|partition| {
        let exact_size = partition.size_bytes == partition.size_mi_b.saturating_mul(1024 * 1024);
        let budget_matches = match partition.kind.as_str() {
            "esp" => partition.size_mi_b == budgets.esp,
            // Root partitions are fixed storage capacity, while the root
            // budget is an artifact growth ceiling. The image module permits
            // intentional update headroom but rejects undersized partitions.
            "root" => partition.size_mi_b >= budgets.root,
            "verity" => partition.size_mi_b == budgets.verity,
            _ => true,
        };
        exact_size && budget_matches
    });
    if !nonzero || !uki_fits || !download_fits || !esp_holds_two_ukis || !partition_contracts_match
    {
        bail!("image-info artifact budgets disagree with the image payload or partition layout");
    }
    Ok(())
}

const MAX_IMAGE_INFO_BYTES: u64 = 1024 * 1024;

const MAX_LOGICAL_DISK_BYTES: u64 = 8 * 1024 * 1024 * 1024;

const CANONICAL_GPT_TAIL_BYTES: u64 = 1024 * 1024;

pub(in crate::registry_ops) const MAX_ZSTD_WINDOW_LOG: u32 = 27;

/// Rejects decompression sizes that are unbounded or disagree with GPT geometry.
fn validate_logical_disk_geometry(
    virtual_size_bytes: u64,
    partition_ranges: &[(u64, u64)],
) -> Result<()> {
    let partition_end = partition_ranges
        .last()
        .map(|range| range.1)
        .context("image-info must declare at least one partition")?;
    let expected_virtual_size = partition_end
        .checked_add(CANONICAL_GPT_TAIL_BYTES)
        .context("image-info partition geometry overflows")?;
    if virtual_size_bytes != expected_virtual_size || virtual_size_bytes > MAX_LOGICAL_DISK_BYTES {
        bail!(
            "image-info virtualSizeBytes must equal the canonical GPT extent and may not exceed {} bytes",
            MAX_LOGICAL_DISK_BYTES
        );
    }
    Ok(())
}

/// Validates one image store output and constructs its signed delivery entry.
///
/// The payload directory supplies authenticated layout, update, and recovery
/// facts. The downloadable disk and metadata are separate regular-file store
/// outputs, so cache publication never discovers an artifact by enumeration.
pub(in crate::registry_ops) fn inspect_published_image(
    format: &str,
    payload: StorePathInfo,
    disk_store: StorePathInfo,
    info_store: StorePathInfo,
    uki_path: &Path,
    name: &str,
    release: &str,
    platform: &str,
    db_cert: Option<&Path>,
) -> Result<PublishedImage> {
    if store_dir_from_store_path(&payload.path).is_none() {
        bail!("published image payload must be a canonical Nix store path");
    }
    let canonical_payload = fs::canonicalize(&payload.path)
        .with_context(|| format!("canonicalizing image payload {}", payload.path))?;
    if canonical_payload != Path::new(&payload.path) {
        bail!("published image payload must not traverse aliases or symlinks");
    }
    let Some(uki_store) = uki_path.parent() else {
        bail!("published UKI must live directly in a Nix store output");
    };
    let Some(uki_store_text) = uki_store.to_str() else {
        bail!("published UKI store path is not UTF-8");
    };
    if store_dir_from_store_path(uki_store_text).is_none()
        || fs::canonicalize(uki_store)? != uki_store
    {
        bail!("published UKI must live directly in a canonical Nix store output");
    }
    let image = inspect_published_image_with(
        format,
        payload,
        disk_store,
        info_store,
        uki_path,
        name,
        release,
        platform,
        db_cert,
        derive_sb_facts,
    )?;
    verify_embedded_uki(&image)?;
    Ok(image)
}

pub(in crate::registry_ops) fn inspect_published_image_with<F>(
    format: &str,
    payload: StorePathInfo,
    disk_store: StorePathInfo,
    info_store: StorePathInfo,
    uki_path: &Path,
    name: &str,
    release: &str,
    platform: &str,
    db_cert: Option<&Path>,
    derive_secure_boot: F,
) -> Result<PublishedImage>
where
    F: FnOnce(&Path, Option<&Path>) -> Result<SbFacts>,
{
    let root_path = PathBuf::from(&payload.path);
    let root = root_path.as_path();
    let immutable_store_output = store_dir_from_store_path(&payload.path).is_some();
    let root_meta = fs::symlink_metadata(root)
        .with_context(|| format!("inspecting image output {}", root.display()))?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        bail!(
            "image output must be a real directory containing one disk file and image-info.json: {}",
            root.display()
        );
    }
    let root_handle = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening image output directory {}", root.display()))?;
    let root_file = fs::File::from(root_handle);
    let root_identity = file_identity(&root_file.metadata()?);
    if file_identity(&root_meta) != root_identity {
        bail!("image output directory identity changed while opening");
    }

    let info_path = root.join("image-info.json");
    let (mut info_file, info_identity) = open_stable_regular_file_at_with_links(
        &root_file,
        "image-info.json",
        &info_path,
        immutable_store_output,
    )?;
    if info_identity.len == 0 || info_identity.len > MAX_IMAGE_INFO_BYTES {
        bail!("image-info.json size must be between 1 and {MAX_IMAGE_INFO_BYTES} bytes");
    }
    let mut info_bytes = Vec::with_capacity(info_identity.len as usize);
    (&mut info_file)
        .take(MAX_IMAGE_INFO_BYTES + 1)
        .read_to_end(&mut info_bytes)
        .with_context(|| format!("reading image metadata {}", info_path.display()))?;
    if info_bytes.len() as u64 != info_identity.len {
        bail!("image-info.json length changed while it was being read");
    }
    verify_stable_regular_file(&info_path, &info_file, &info_identity)?;
    let producer: ProducerImageInfo = serde_json::from_slice(&info_bytes)
        .with_context(|| format!("parsing {}", info_path.display()))?;
    if producer.schema_version != 2 {
        bail!("image-info schemaVersion must be 2");
    }
    let public_text = std::str::from_utf8(&info_bytes).context("image-info.json is not UTF-8")?;
    if public_text.contains("/nix/store/")
        || public_text.contains("/aos/store/")
        || public_text.contains("file://")
    {
        bail!("image-info.json contains a private build or filesystem path");
    }
    validate_single_filename(&producer.filename, "image filename")?;
    validate_single_filename(&producer.uki.filename, "UKI filename")?;
    validate_portable_relative_path(&producer.uki.esp_path, "UKI ESP path")?;
    if producer.virtual_size_bytes == 0 {
        bail!("image-info virtualSizeBytes must be non-zero");
    }
    validate_lower_sha256(&producer.logical_disk_sha256, "logical disk")?;
    validate_lower_sha256(&producer.rootfs_sha256, "root filesystem")?;
    validate_package_name(&producer.name).context("validating image-info name")?;
    if producer.name != name {
        bail!("image-info name does not match the signed package name");
    }
    if producer.partition_table.as_deref() != Some("gpt")
        || producer.kernel_params.is_none()
        || producer.partitions.is_empty()
        || producer.esp.is_none()
    {
        bail!(
            "image-info must declare canonical GPT layout, kernel parameters, partitions, and ESP facts"
        );
    }
    let mut partition_numbers = HashSet::new();
    let mut partition_ranges = Vec::new();
    for partition in &producer.partitions {
        if !partition_numbers.insert(partition.number)
            || partition.label.is_empty()
            || partition.kind.is_empty()
            || partition.filesystem.is_empty()
            || partition.size_bytes == 0
            || partition.size_mi_b != partition.size_bytes / (1024 * 1024)
            || partition
                .offset_bytes
                .checked_add(partition.size_bytes)
                .is_none_or(|end| end > producer.virtual_size_bytes)
        {
            bail!("image-info contains an invalid partition layout");
        }
        partition_ranges.push((
            partition.offset_bytes,
            partition.offset_bytes + partition.size_bytes,
        ));
    }
    partition_ranges.sort_unstable();
    if partition_ranges
        .windows(2)
        .any(|ranges| ranges[0].1 > ranges[1].0)
    {
        bail!("image-info partition layout overlaps");
    }
    validate_logical_disk_geometry(producer.virtual_size_bytes, &partition_ranges)?;
    if producer
        .esp
        .as_ref()
        .is_some_and(|esp| esp.uki != producer.uki.esp_path)
    {
        bail!("image-info ESP UKI path disagrees with the signed UKI identity");
    }
    let esp_partition = producer
        .partitions
        .iter()
        .find(|partition| partition.kind == "esp" && partition.filesystem == "vfat")
        .context("image-info must identify exactly one vfat ESP partition")?;
    let esp_offset_bytes = esp_partition.offset_bytes;
    if producer
        .partitions
        .iter()
        .filter(|partition| partition.kind == "esp" && partition.filesystem == "vfat")
        .count()
        != 1
    {
        bail!("image-info must identify exactly one vfat ESP partition");
    }
    let roots = producer
        .partitions
        .iter()
        .filter(|partition| partition.kind == "root" && partition.label == "root-a")
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        bail!("image-info must identify exactly one root-a filesystem partition");
    }
    let root_range = (roots[0].offset_bytes, roots[0].size_bytes);
    if let Some(esp) = &producer.esp {
        validate_portable_relative_path(&esp.sd_boot, "systemd-boot ESP path")?;
    }
    if producer
        .disk_size_mi_b
        .is_some_and(|size| size != producer.virtual_size_bytes / (1024 * 1024))
        || producer.esp_size_mi_b == Some(0)
        || producer.root_size_mi_b == Some(0)
    {
        bail!("image-info MiB summaries disagree with the exact logical layout");
    }
    validate_image_artifact_budgets(
        &producer.artifact_budgets_mi_b,
        producer.byte_size,
        producer.uki.byte_size,
        &producer.partitions,
    )?;
    if let Some(budget) = &producer.esp_budget {
        let calculated = budget
            .installed_bytes
            .checked_add(budget.transaction_bytes)
            .and_then(|bytes| bytes.checked_add(32 * 1024 * 1024))
            .context("image-info ESP budget overflows")?;
        if budget.installed_bytes == 0
            || budget.transaction_bytes == 0
            || budget.required_bytes != calculated
            || budget.partition_bytes != esp_partition.size_bytes
            || budget.required_bytes > budget.partition_bytes
        {
            bail!("image-info ESP budget disagrees with the exact partition layout");
        }
    } else if producer.recovery.is_some() {
        bail!("recovery image-info must include the ESP transaction budget");
    }

    let mut entry_count = 0_u8;
    let mut auxiliary_names = HashSet::new();
    for entry in fs::read_dir(root)
        .with_context(|| format!("enumerating image output {}", root.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        if name == std::ffi::OsStr::new("nix-support") {
            validate_image_target_platform_metadata(&entry.path(), &file_type, platform)?;
            continue;
        }
        if file_type.is_symlink() || !file_type.is_file() {
            bail!(
                "image output contains a symlink, directory, or special entry: {}",
                entry.path().display()
            );
        }
        let is_primary = name == std::ffi::OsStr::new("image-info.json")
            || name == std::ffi::OsStr::new(producer.filename.as_str());
        let is_auxiliary = name.to_str().is_some_and(|name| {
            matches!(
                name,
                "root.img"
                    | "root.verity"
                    | "root.roothash"
                    | "root.roothash.p7s"
                    | "uki-a.efi"
                    | "uki-b.efi"
                    | "recovery-a.efi"
                    | "recovery-b.efi"
                    | "recovery-a.conf"
                    | "recovery-b.conf"
                    | "recovery-bundle.json"
                    | "recovery-bundle.json.sig"
            )
        });
        if !is_primary && !is_auxiliary {
            bail!(
                "image output contains an ambiguous unreferenced artifact: {}",
                entry.path().display()
            );
        }
        if is_auxiliary {
            auxiliary_names.insert(name);
        }
        entry_count = entry_count
            .checked_add(1)
            .context("image output contains too many entries")?;
    }
    if entry_count < 2 {
        bail!("image output must contain one disk file and image-info.json");
    }
    let has_uki_a = auxiliary_names.contains(std::ffi::OsStr::new("uki-a.efi"));
    let has_uki_b = auxiliary_names.contains(std::ffi::OsStr::new("uki-b.efi"));
    if has_uki_a != has_uki_b {
        bail!("A/B image output must carry both uki-a.efi and uki-b.efi");
    }
    let recovery_count = [
        "recovery-a.efi",
        "recovery-b.efi",
        "recovery-a.conf",
        "recovery-b.conf",
    ]
    .iter()
    .filter(|name| auxiliary_names.contains(std::ffi::OsStr::new(name)))
    .count();
    if recovery_count != 0 && recovery_count != 4 {
        bail!("recovery image output must carry both UKIs and both loader entries");
    }
    if !auxiliary_names.is_empty() && !auxiliary_names.contains(std::ffi::OsStr::new("root.img")) {
        bail!("runtime-update image output must carry root.img");
    }

    let payload_image_path = root.join(&producer.filename);
    let (mut payload_image_file, payload_image_identity) = open_stable_regular_file_at_with_links(
        &root_file,
        &producer.filename,
        &payload_image_path,
        immutable_store_output,
    )?;
    let payload_sha256 = sha256_open_file(&mut payload_image_file, &payload_image_path)?;
    verify_stable_regular_file(
        &payload_image_path,
        &payload_image_file,
        &payload_image_identity,
    )?;

    let (mut image_file, image_identity, image_path) =
        open_canonical_store_regular_file(&disk_store, "image disk")?;
    let actual_sha256 = sha256_open_file(&mut image_file, &image_path)?;
    verify_stable_regular_file(&image_path, &image_file, &image_identity)?;
    let actual_size = image_identity.len;
    if payload_image_identity.len != actual_size || payload_sha256 != actual_sha256 {
        bail!("image payload disk does not match the explicit disk store output");
    }
    if producer.format != format {
        bail!(
            "--image-format '{format}' does not match image-info format '{}'",
            producer.format
        );
    }
    if producer.version != release {
        bail!("image-info version does not match the signed package release");
    }
    if producer.platform != platform {
        bail!("image-info platform does not match the signed platform");
    }
    if producer.byte_size != actual_size {
        bail!("image-info byteSize does not match the disk file");
    }
    if producer.sha256 != actual_sha256 {
        bail!("image-info sha256 does not match the disk file");
    }
    if !producer.uki.filename.ends_with(".efi") {
        bail!("image-info UKI filename must end in .efi");
    }
    let immutable_uki_output = uki_path
        .parent()
        .and_then(Path::to_str)
        .is_some_and(|parent| store_dir_from_store_path(parent).is_some());
    let (mut uki_file, uki_identity) =
        open_stable_regular_file_with_links(uki_path, immutable_uki_output)?;
    let uki_sha256 = sha256_open_file(&mut uki_file, uki_path)?;
    verify_stable_regular_file(uki_path, &uki_file, &uki_identity)?;
    if producer.uki.byte_size != uki_identity.len || producer.uki.sha256 != uki_sha256 {
        bail!("image-info UKI size or SHA-256 does not match the associated UKI");
    }

    let logical_identity = serde_json::json!({
        "schemaVersion": producer.schema_version,
        "release": &producer.version,
        "platform": &producer.platform,
        "architecture": &producer.architecture,
        "virtualSizeBytes": producer.virtual_size_bytes,
        "logicalDiskSha256": &producer.logical_disk_sha256,
        "rootfsSha256": &producer.rootfs_sha256,
        "partitionTable": &producer.partition_table,
        "kernelParams": &producer.kernel_params,
        "partitions": &producer.partitions,
        "uki": &producer.uki,
        "recovery": &producer.recovery,
    });
    let logical_image_id = sha256_hex(&serde_json::to_vec(&logical_identity)?);
    let producer_uki_signed = producer.uki.signed;
    let producer_uki_measured = producer.uki.measured;

    // Derive every verification claim from the exact pinned UKI descriptor.
    // The outer production path additionally proves these bytes are embedded
    // at the signed ESP path before the catalog can be committed.
    let (_verification_file, verification_path) = inheritable_procfd(&uki_file, uki_path)?;
    let mut sb = derive_secure_boot(&verification_path, db_cert)
        .with_context(|| format!("deriving Secure Boot facts for {}", uki_path.display()))?;
    verify_stable_regular_file(uki_path, &uki_file, &uki_identity)?;
    if producer_uki_signed != sb.signer_cert_sha256.is_some() {
        bail!("image-info UKI signed state does not match its Authenticode signature");
    }
    if producer_uki_measured != sb.expected_pcr11.is_some() {
        bail!("image-info UKI measured state does not match its PCR-11 policy");
    }
    sb.ukis = derive_slot_uki_facts(root, db_cert)?;
    sb.recovery_ukis =
        derive_recovery_uki_facts(root, producer.recovery.as_ref(), &producer.version, db_cert)?;
    if let Some(slot_a) = sb.ukis.iter().find(|uki| uki.slot == UkiSlot::A)
        && (slot_a.sb_signer_cert_sha256 != sb.signer_cert_sha256
            || slot_a.sbat != sb.sbat
            || slot_a.expected_pcr11 != sb.expected_pcr11)
    {
        bail!("slot-A UKI facts disagree with the UKI embedded in the published disk");
    }

    sb.recovery_bundle = derive_recovery_bundle_manifest(
        root,
        producer.recovery.as_ref(),
        producer.module_abi,
        &producer.version,
        &producer.architecture,
        &producer.platform,
    )?;
    if let Some(expected_bundle) = &sb.recovery_bundle {
        let bundle_path = root.join("recovery-bundle.json");
        let signature_path = root.join("recovery-bundle.json.sig");
        let bundle_metadata = fs::symlink_metadata(&bundle_path)?;
        let signature_metadata = fs::symlink_metadata(&signature_path)?;
        if !bundle_metadata.file_type().is_file()
            || bundle_metadata.len() == 0
            || bundle_metadata.len() > 256 * 1024
            || !signature_metadata.file_type().is_file()
            || signature_metadata.len() == 0
            || signature_metadata.len() > 16 * 1024
        {
            bail!("recovery bundle manifest or signature is outside its size bound");
        }
        let published_bundle: RecoveryBundleManifest =
            serde_json::from_slice(&fs::read(&bundle_path)?)
                .context("parsing recovery-bundle.json")?;
        if &published_bundle != expected_bundle {
            bail!("recovery-bundle.json disagrees with the authenticated image components");
        }
        let db_cert =
            db_cert.context("publishing a recovery bundle requires the registry db certificate")?;
        verify_detached_db_signature(&bundle_path, &signature_path, db_cert)?;
    }
    let (mut canonical_info_file, canonical_info_identity, canonical_info_path) =
        open_canonical_store_regular_file(&info_store, "image metadata")?;
    let mut published_info_bytes = Vec::with_capacity(canonical_info_identity.len as usize);
    (&mut canonical_info_file)
        .take(MAX_IMAGE_INFO_BYTES + 1)
        .read_to_end(&mut published_info_bytes)
        .with_context(|| format!("reading image metadata {}", canonical_info_path.display()))?;
    verify_stable_regular_file(
        &canonical_info_path,
        &canonical_info_file,
        &canonical_info_identity,
    )?;
    if published_info_bytes != info_bytes {
        bail!("explicit image metadata output does not match the payload image-info.json");
    }
    let info_sha256 = sha256_hex(&published_info_bytes);
    canonical_info_file.seek(SeekFrom::Start(0))?;
    let delivery = ImageDelivery {
        schema_version: producer.schema_version,
        release: release.to_string(),
        platform: producer.platform,
        architecture: producer.architecture,
        logical_image_id,
        logical_disk_sha256: producer.logical_disk_sha256,
        rootfs_sha256: producer.rootfs_sha256,
        filename: producer.filename,
        object_key: String::new(),
        media_type: producer.media_type,
        compression: producer.compression,
        byte_size: producer.byte_size,
        sha256: producer.sha256,
        compatible_targets: producer.compatible_targets,
        uki: ImageUkiIdentity {
            filename: producer.uki.filename,
            esp_path: producer.uki.esp_path,
            byte_size: producer.uki.byte_size,
            sha256: producer.uki.sha256,
            verification: if producer_uki_signed {
                ImageVerificationState::SignedUnverified
            } else {
                ImageVerificationState::Unsigned
            },
            signer_cert_sha256: sb.signer_cert_sha256.clone(),
            sbat: sb.sbat.clone(),
            measured: producer_uki_measured,
            expected_pcr11: sb.expected_pcr11.clone(),
        },
        image_info: ImageInfoReference {
            filename: "image-info.json".to_string(),
            object_key: String::new(),
            store_path: info_store.path.clone(),
            nar_hash: info_store.nar_hash.clone(),
            nar_size: info_store.nar_size,
            media_type: "application/vnd.aos.image-info+json".to_string(),
            byte_size: published_info_bytes.len() as u64,
            sha256: info_sha256.clone(),
        },
        update_payload: Some(ImageStoreReference {
            store_path: payload.path.clone(),
            nar_hash: payload.nar_hash.clone(),
            nar_size: payload.nar_size,
        }),
    };
    delivery
        .validate(format, release, platform)
        .with_context(|| format!("validating direct delivery contract for {format}"))?;
    Ok(PublishedImage {
        format: format.to_string(),
        payload,
        store: disk_store,
        info_store,
        sb,
        delivery,
        directory: ValidatedImageDirectory {
            path: root_path,
            file: root_file,
            identity: root_identity,
        },
        disk: ValidatedImageFile {
            path: image_path,
            file: image_file,
            identity: image_identity,
            path_bound: true,
        },
        image_info: ValidatedImageFile {
            path: canonical_info_path,
            file: canonical_info_file,
            identity: canonical_info_identity,
            path_bound: true,
        },
        producer_image_info: ValidatedImageFile {
            path: info_path,
            file: info_file,
            identity: info_identity,
            path_bound: true,
        },
        uki: ValidatedImageFile {
            path: uki_path.to_path_buf(),
            file: uki_file,
            identity: uki_identity,
            path_bound: true,
        },
        esp_offset_bytes,
        root_range,
        virtual_size_bytes: producer.virtual_size_bytes,
    })
}

/// Validates the sole derivation metadata entry admitted beside image files.
fn validate_image_target_platform_metadata(
    support: &Path,
    support_type: &fs::FileType,
    platform: &str,
) -> Result<()> {
    if support_type.is_symlink() || !support_type.is_dir() {
        bail!(
            "image output target-platform metadata is not a real directory: {}",
            support.display()
        );
    }

    let mut entries = fs::read_dir(support)
        .with_context(|| format!("enumerating image metadata {}", support.display()))?;
    let marker = entries
        .next()
        .transpose()?
        .context("image output nix-support directory is empty")?;
    if entries.next().transpose()?.is_some()
        || marker.file_name() != std::ffi::OsStr::new("aos-target-platform")
    {
        bail!(
            "image output nix-support must contain only aos-target-platform: {}",
            support.display()
        );
    }
    let marker_type = marker.file_type()?;
    if marker_type.is_symlink() || !marker_type.is_file() {
        bail!(
            "image output target-platform marker is not a regular file: {}",
            marker.path().display()
        );
    }
    const MAX_TARGET_PLATFORM_MARKER_BYTES: u64 = 128;
    let mut stamped = String::new();
    fs::File::open(marker.path())?
        .take(MAX_TARGET_PLATFORM_MARKER_BYTES + 1)
        .read_to_string(&mut stamped)
        .with_context(|| {
            format!(
                "reading image target-platform marker {}",
                marker.path().display()
            )
        })?;
    if stamped.len() as u64 > MAX_TARGET_PLATFORM_MARKER_BYTES {
        bail!("image output target-platform marker exceeds 128 bytes");
    }
    if stamped.trim() != platform {
        bail!(
            "image output target-platform marker '{}' disagrees with published platform '{platform}'",
            stamped.trim()
        );
    }
    Ok(())
}

impl PublishedImage {
    pub(in crate::registry_ops) fn recheck_for_commit(&self) -> Result<()> {
        let path_metadata = fs::symlink_metadata(&self.directory.path)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_dir()
            || file_identity(&path_metadata) != self.directory.identity
            || file_identity(&self.directory.file.metadata()?) != self.directory.identity
        {
            bail!("image output directory identity changed before commit");
        }
        self.disk.recheck()?;
        self.image_info.recheck()?;
        self.producer_image_info.recheck()?;
        self.uki.recheck()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

pub(super) mod files;

pub(super) mod receipts;
