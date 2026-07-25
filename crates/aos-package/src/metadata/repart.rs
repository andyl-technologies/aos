//! Strict validation and `systemd-repart` rendering for the evaluated
//! `aos.provisioning.storage` projection.
//!
//! Nix supplies defaults and merges operator definitions. Rust treats the
//! resulting JSON as an untrusted data contract: unknown fields, unsafe device
//! paths, protected partition types, malformed sizes and ambiguous growth all
//! fail before `systemd-repart` is allowed to mutate a disk.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Directory below the metadata stash for rendered definitions.
pub const REPART_DIR: &str = "repart.d";
/// Canonical validated projection below the metadata stash.
pub const STORAGE_PLAN_FILE: &str = "provisioning-plan.json";
/// Tab-separated target and definition-directory index.
pub const REPART_TARGETS_FILE: &str = "repart-targets";
/// Temporary GPT marker created in the same repart transaction as storage.
pub const PENDING_LABEL: &str = "aos-provisioning-pending-v1";
/// Durable marker for a plan derived from operator `host.nix`.
pub const OPERATOR_LABEL: &str = "aos-provenance-operator-v1";
/// Durable marker for the image's provisioning defaults.
pub const FALLBACK_LABEL: &str = "aos-provenance-fallback-v1";
/// Type GUID reserved exclusively for the one-time provisioning marker.
pub const SENTINEL_TYPE_GUID: &str = "163bea60-58c7-46e7-b69a-6846a5a688af";

/// Closed JSON product of restricted initrd evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningPlan {
    /// Must equal `aos.provisioning-plan/v1`.
    pub schema: String,
    /// One-time storage declaration.
    pub storage: StoragePlan,
}

/// Evaluated storage configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePlan {
    /// Logical partition name to definition.
    pub partitions: BTreeMap<String, PartitionSpec>,
}

/// One additive partition definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PartitionSpec {
    /// Stable `/dev/disk/by-id/...` target, or `null` for the root disk.
    pub device: Option<String>,
    /// GPT partition label.
    pub label: String,
    /// Semantic type or canonical raw GUID.
    #[serde(rename = "type")]
    pub partition_type: String,
    /// Minimum size in systemd size syntax.
    pub size_min: String,
    /// Optional maximum size.
    pub size_max: Option<String>,
    /// Relative free-space allocation weight.
    pub weight: i64,
    /// Optional initial filesystem format.
    pub format: Option<String>,
    /// Optional deterministic partition UUID.
    pub uuid: Option<String>,
    /// Whether this partition consumes remaining free space.
    pub grow: bool,
    /// Whether an existing filesystem may grow.
    pub grow_fs: bool,
    /// Stable placement priority.
    pub priority: i64,
}

/// Validates the complete evaluated provisioning plan.
///
/// # Errors
///
/// Returns an error for an unsupported schema, invalid or duplicated labels,
/// unstable device paths, protected types, malformed sizes or UUIDs, unsafe
/// formatting, multiple grow partitions per device, or a missing root-disk
/// `var` partition.
pub fn validate_provisioning_plan(plan: &ProvisioningPlan, measured_boot: bool) -> Result<()> {
    if plan.schema != "aos.provisioning-plan/v1" {
        bail!("unsupported provisioning plan schema '{}'", plan.schema);
    }
    if plan.storage.partitions.is_empty() {
        bail!("aos.provisioning.storage.partitions must not be empty");
    }

    let mut labels = BTreeSet::new();
    let mut grow_devices = BTreeSet::new();
    let mut root_var = false;
    for (name, partition) in &plan.storage.partitions {
        validate_label(name, "logical partition name")?;
        validate_label(&partition.label, "GPT partition label")?;
        if matches!(
            partition.label.as_str(),
            "root-a"
                | "root-b"
                | "root-a-hash"
                | "root-b-hash"
                | "esp"
                | "ESP"
                | PENDING_LABEL
                | OPERATOR_LABEL
                | FALLBACK_LABEL
        ) {
            bail!(
                "partition label '{}' is reserved or protected",
                partition.label
            );
        }
        if !labels.insert(partition.label.as_str()) {
            bail!("duplicate GPT partition label '{}'", partition.label);
        }
        let device = partition.device.as_deref().unwrap_or("root");
        if device != "root" && !device.starts_with("/dev/disk/by-id/") {
            bail!("partition '{name}' device must be null or /dev/disk/by-id/...");
        }
        validate_partition_type(&partition.partition_type)?;
        validate_size(&partition.size_min, "sizeMin", name)?;
        if let Some(max) = partition.size_max.as_deref() {
            validate_size(max, "sizeMax", name)?;
        }
        if partition.weight <= 0 {
            bail!("partition '{name}' weight must be positive");
        }
        if partition.priority < 0 {
            bail!("partition '{name}' priority must be non-negative");
        }
        if let Some(uuid) = partition.uuid.as_deref() {
            validate_uuid(uuid).with_context(|| format!("partition '{name}' uuid"))?;
        }
        if partition.grow && !grow_devices.insert(device) {
            bail!("device '{device}' has more than one grow partition");
        }
        if (partition.partition_type == "swap") != (partition.format.as_deref() == Some("swap")) {
            bail!("partition '{name}' must use type = \"swap\" exactly when format = \"swap\"");
        }
        if !matches!(
            partition.format.as_deref(),
            None | Some("ext4" | "vfat" | "swap")
        ) {
            bail!("partition '{name}' uses an unsupported format");
        }
        if partition.label == "var" && partition.device.is_none() {
            root_var = true;
            if measured_boot && partition.format.is_some() {
                bail!("measured boot requires root-disk var to remain raw");
            }
        }
    }
    if !root_var {
        bail!("storage plan must declare label 'var' on the root disk");
    }
    Ok(())
}

/// Renders a validated plan into per-device transient repart definitions.
///
/// The root-disk definition set also contains a pending marker. The initrd
/// relabels that marker only after every planned device succeeds, making the
/// one-time commit durable and crash-observable.
///
/// # Errors
///
/// Returns an error when validation fails or outputs cannot be atomically
/// replaced.
pub fn render_provisioning_plan(
    stash_dir: &Path,
    plan: &mut ProvisioningPlan,
    measured_boot: bool,
    marker_label: &str,
    marker_uuid: &str,
) -> Result<Vec<PathBuf>> {
    validate_provisioning_plan(plan, measured_boot)?;
    if !matches!(
        marker_label,
        PENDING_LABEL | OPERATOR_LABEL | FALLBACK_LABEL
    ) {
        bail!("unsupported provisioning marker label '{marker_label}'");
    }
    let marker_uuid = normalize_marker_uuid(marker_uuid)?;
    assign_missing_partition_uuids(plan, &marker_uuid);
    std::fs::write(
        stash_dir.join(STORAGE_PLAN_FILE),
        serde_json::to_vec_pretty(plan).context("serializing provisioning plan")?,
    )
    .context("writing provisioning-plan.json")?;

    let root = stash_dir.join(REPART_DIR);
    if root.exists() {
        std::fs::remove_dir_all(&root).with_context(|| format!("clearing {}", root.display()))?;
    }
    std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;

    let mut groups: BTreeMap<&str, Vec<(&str, &PartitionSpec)>> = BTreeMap::new();
    for (name, partition) in &plan.storage.partitions {
        groups
            .entry(partition.device.as_deref().unwrap_or("root"))
            .or_default()
            .push((name, partition));
    }

    let mut targets = String::new();
    let mut written = Vec::new();
    let mut groups: Vec<_> = groups.into_iter().collect();
    // The root disk must commit its pending marker before another device can
    // be changed. A crash after that point is therefore observable and cannot
    // be mistaken for an untouched first boot.
    groups.sort_by_key(|(device, _)| (*device != "root", *device));
    for (index, (device, mut partitions)) in groups.into_iter().enumerate() {
        // A grow-to-fill partition must be placed after every bounded
        // partition regardless of its authored priority.
        partitions.sort_by_key(|(name, partition)| (partition.grow, partition.priority, *name));
        let dir_name = format!("{index:04}");
        let dir = root.join(&dir_name);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        targets.push_str(device);
        targets.push('\t');
        targets.push_str(&dir_name);
        targets.push('\n');

        for (position, (name, partition)) in partitions.into_iter().enumerate() {
            let path = dir.join(format!("{:04}-{name}.conf", position + 10));
            std::fs::write(&path, render_partition(partition, measured_boot))
                .with_context(|| format!("writing {}", path.display()))?;
            written.push(path);
        }
        if device == "root" {
            // The marker is a fixed-size, high-priority definition placed
            // before operator partitions. Priority prevents repart from
            // dropping the commit record under space pressure.
            let sentinel = dir.join("0000-aos-provisioning-marker.conf");
            std::fs::write(
                &sentinel,
                format!(
                    "[Partition]\nType={SENTINEL_TYPE_GUID}\nLabel={marker_label}\nUUID={marker_uuid}\nSizeMinBytes=1M\nSizeMaxBytes=1M\nPriority=1000000\n"
                ),
            )
            .with_context(|| format!("writing {}", sentinel.display()))?;
            written.push(sentinel);
        }
    }
    std::fs::write(stash_dir.join(REPART_TARGETS_FILE), targets)
        .context("writing repart target index")?;
    Ok(written)
}

/// Generates a random RFC 9562 version-4 UUID for a new GPT marker.
pub fn generate_marker_uuid() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format_uuid(bytes)
}

/// Validates and normalizes an existing GPT marker UUID.
///
/// # Errors
///
/// Returns an error unless `value` is a canonical hyphenated UUID.
pub fn normalize_marker_uuid(value: &str) -> Result<String> {
    validate_uuid(value)?;
    Ok(value.to_ascii_lowercase())
}

fn assign_missing_partition_uuids(plan: &mut ProvisioningPlan, marker_uuid: &str) {
    for (name, partition) in &mut plan.storage.partitions {
        if partition.uuid.is_some() {
            continue;
        }
        let device = partition.device.as_deref().unwrap_or("root");
        let mut digest = Sha256::new();
        digest.update(b"aos.provisioning.partition-uuid/v1\0");
        digest.update(marker_uuid.as_bytes());
        digest.update(b"\0");
        digest.update(device.as_bytes());
        digest.update(b"\0");
        digest.update(name.as_bytes());
        digest.update(b"\0");
        digest.update(partition.label.as_bytes());
        let output = digest.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&output[..16]);
        // RFC 9562 UUID version 8 reserves the payload for application-defined
        // deterministic schemes. Keep the RFC variant bits canonical.
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        partition.uuid = Some(format_uuid(bytes));
    }
}

fn format_uuid(bytes: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

fn render_partition(partition: &PartitionSpec, measured_boot: bool) -> String {
    let partition_type = match partition.partition_type.as_str() {
        "linux-generic" => "linux-generic",
        other => other,
    };
    let mut result = format!(
        "[Partition]\nType={partition_type}\nLabel={}\nSizeMinBytes={}\nWeight={}\nGrowFileSystem={}\n",
        partition.label,
        partition.size_min,
        partition.weight,
        if partition.grow_fs { "yes" } else { "no" },
    );
    if let Some(max) = partition.size_max.as_deref() {
        result.push_str(&format!("SizeMaxBytes={max}\n"));
    } else if !partition.grow {
        result.push_str(&format!("SizeMaxBytes={}\n", partition.size_min));
    }
    let format = if partition.label == "var" && !measured_boot && partition.format.is_none() {
        Some("ext4")
    } else {
        partition.format.as_deref()
    };
    if let Some(format) = format {
        result.push_str(&format!("Format={format}\n"));
    }
    if let Some(uuid) = partition.uuid.as_deref() {
        result.push_str(&format!("UUID={uuid}\n"));
    }
    result
}

fn validate_label(value: &str, kind: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 36
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("{kind} '{value}' must be 1-36 ASCII letters, digits, '.', '_' or '-'");
    }
    Ok(())
}

fn validate_partition_type(value: &str) -> Result<()> {
    if matches!(value, "linux-generic" | "swap") {
        return Ok(());
    }
    let lower = value.to_ascii_lowercase();
    if lower == SENTINEL_TYPE_GUID
        || matches!(
            lower.as_str(),
            "root"
                | "root-a"
                | "root-b"
                | "root-verity"
                | "root-verity-sig"
                | "var"
                | "esp"
                | "xbootldr"
                | "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
                | "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
                | "b921b045-1df0-41c3-af44-4c6f280d3fae"
                | "44479540-f297-41b2-9af7-d131d5f0458a"
                | "72ec70a6-cf74-40e6-bd49-4bda08e8f224"
                | "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5"
                | "df3300ce-d69f-4c92-978c-9bfb0f38d820"
                | "d13c5d3b-b5d1-422a-b29f-9454fdc89d76"
                | "b6ed5582-440b-4209-b8da-5ff7c419ea3d"
                | "41092b05-9fc8-4523-994f-2def0408b176"
        )
    {
        bail!("partition type '{value}' is reserved or protected");
    }
    validate_uuid(value).context("raw partition type GUID")
}

fn validate_size(value: &str, field: &str, name: &str) -> Result<()> {
    let digit_count = value.bytes().take_while(u8::is_ascii_digit).count();
    let suffix = &value[digit_count..];
    if digit_count == 0
        || value[..digit_count].bytes().all(|byte| byte == b'0')
        || !matches!(suffix, "" | "K" | "M" | "G" | "T" | "P")
    {
        bail!("partition '{name}' {field} must be a positive integer with K/M/G/T/P suffix");
    }
    Ok(())
}

fn validate_uuid(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || !bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23) && *byte == b'-'
                || !matches!(index, 8 | 13 | 18 | 23) && byte.is_ascii_hexdigit()
        })
    {
        bail!("'{value}' is not a canonical UUID");
    }
    Ok(())
}
