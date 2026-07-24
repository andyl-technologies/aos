//! Typed first-boot storage plans and `systemd-repart` rendering.
//!
//! The initrd does not evaluate `host.nix`. Instead, an authenticated
//! provisioning bundle may carry a deliberately small storage schema. This
//! module validates that schema and renders additive `repart.d` definitions
//! under `/run`; it never accepts raw INI fragments or a caller-selected disk.
//! The boot unit independently resolves the parent disk of the booted
//! `root-a` partition.
//!
//! ```json
//! {
//!   "partitions": [
//!     {
//!       "label": "swap",
//!       "type": "swap",
//!       "size_min_bytes": 2147483648,
//!       "size_max_bytes": 2147483648
//!     },
//!     {
//!       "label": "var",
//!       "type": "var",
//!       "size_min_bytes": 4294967296,
//!       "grow": true,
//!       "format": "ext4"
//!     }
//!   ]
//! }
//! ```

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Directory name below the metadata stash for rendered definitions.
pub const REPART_DIR: &str = "repart.d";
/// Canonical validated storage-plan filename below the metadata stash.
pub const STORAGE_PLAN_FILE: &str = "storage-plan.json";

/// A closed, typed first-boot storage plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePlan {
    /// Additive partitions to create.
    pub partitions: Vec<PartitionSpec>,
}

/// One additive partition on the booted root disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionSpec {
    /// GPT partition label. Must match the selected partition type.
    pub label: String,
    /// Allowlisted discoverable partition type.
    #[serde(rename = "type")]
    pub partition_type: PartitionType,
    /// Minimum partition size in bytes.
    pub size_min_bytes: u64,
    /// Optional maximum partition size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_max_bytes: Option<u64>,
    /// Whether this partition consumes remaining free space.
    #[serde(default)]
    pub grow: bool,
    /// Optional filesystem format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<PartitionFormat>,
}

/// Partition types the first-boot plan may add.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PartitionType {
    /// Swap partition.
    Swap,
    /// Discoverable `/var` partition.
    Var,
}

impl PartitionType {
    fn repart_type(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Var => "var",
        }
    }

    fn required_label(self) -> &'static str {
        self.repart_type()
    }
}

/// Filesystem formats the first-boot plan may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PartitionFormat {
    /// ext4 filesystem.
    Ext4,
}

impl PartitionFormat {
    fn repart_format(self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
        }
    }
}

/// Validate a storage plan before any partition-table mutation.
///
/// The schema can describe only new swap and `/var` partitions. Labels and
/// types must be unique, sizes must be sensible, and at most one partition may
/// grow. Under measured boot `/var` must remain raw for the TPM-bound LUKS
/// setup.
///
/// # Errors
///
/// Returns an error for an empty plan, duplicate labels or types, mismatched
/// labels, a missing `/var` partition, zero or inverted size bounds, more than
/// one grow partition, a bounded grow partition, formatting swap, or a `/var`
/// format inconsistent with the measured-boot policy.
pub fn validate_storage_plan(plan: &StoragePlan, measured_boot: bool) -> Result<()> {
    if plan.partitions.is_empty() {
        bail!("storage.partitions must contain at least one partition");
    }

    let mut labels = BTreeSet::new();
    let mut types = BTreeSet::new();
    let mut grow_count = 0usize;

    for partition in &plan.partitions {
        if partition.label != partition.partition_type.required_label() {
            bail!(
                "partition type '{}' requires label '{}', got '{}'",
                partition.partition_type.repart_type(),
                partition.partition_type.required_label(),
                partition.label
            );
        }
        if !labels.insert(partition.label.as_str()) {
            bail!("duplicate partition label '{}'", partition.label);
        }
        if !types.insert(partition.partition_type) {
            bail!(
                "duplicate partition type '{}'",
                partition.partition_type.repart_type()
            );
        }
        if partition.size_min_bytes == 0 {
            bail!(
                "partition '{}' size_min_bytes must be positive",
                partition.label
            );
        }
        if let Some(max) = partition.size_max_bytes {
            if max < partition.size_min_bytes {
                bail!(
                    "partition '{}' size_max_bytes is smaller than size_min_bytes",
                    partition.label
                );
            }
        }
        if partition.grow {
            grow_count += 1;
            if partition.size_max_bytes.is_some() {
                bail!(
                    "grow partition '{}' must not set size_max_bytes",
                    partition.label
                );
            }
        }
        if partition.partition_type == PartitionType::Swap && partition.format.is_some() {
            bail!("swap format is implicit and must not be specified");
        }
        if partition.partition_type == PartitionType::Var {
            if measured_boot && partition.format.is_some() {
                bail!("measured boot requires the var partition to remain raw");
            }
            if !measured_boot && partition.format != Some(PartitionFormat::Ext4) {
                bail!("unmeasured boot requires the var partition format to be ext4");
            }
        }
    }

    if !types.contains(&PartitionType::Var) {
        bail!("storage plan must declare a var partition");
    }
    if grow_count > 1 {
        bail!("at most one storage partition may set grow=true");
    }
    Ok(())
}

/// Render a validated plan to transient `repart.d` definitions.
///
/// Existing output is replaced as one set. Filenames are generated from the
/// allowlisted partition types and labels; no operator-provided path or INI
/// text is consumed.
///
/// # Errors
///
/// Returns an error if validation fails or the output cannot be replaced.
pub fn render_storage_plan(
    stash_dir: &Path,
    plan: &StoragePlan,
    measured_boot: bool,
) -> Result<Vec<PathBuf>> {
    validate_storage_plan(plan, measured_boot)?;

    let canonical =
        serde_json::to_vec_pretty(plan).context("serializing validated storage plan")?;
    std::fs::write(stash_dir.join(STORAGE_PLAN_FILE), canonical)
        .context("writing storage-plan.json")?;

    let dir = stash_dir.join(REPART_DIR);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).with_context(|| format!("clearing {}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let mut written = Vec::with_capacity(plan.partitions.len());
    for partition in &plan.partitions {
        let priority = match partition.partition_type {
            PartitionType::Swap => 50,
            PartitionType::Var => 60,
        };
        let path = dir.join(format!("{priority}-{}.conf", partition.label));
        let mut contents = format!(
            "[Partition]\nType={}\nLabel={}\nSizeMinBytes={}\n",
            partition.partition_type.repart_type(),
            partition.label,
            partition.size_min_bytes
        );
        if let Some(max) = partition
            .size_max_bytes
            .or((!partition.grow).then_some(partition.size_min_bytes))
        {
            contents.push_str(&format!("SizeMaxBytes={max}\n"));
        }
        if partition.grow {
            contents.push_str("Weight=1000\n");
        }
        if let Some(format) = partition.format {
            contents.push_str(&format!("Format={}\n", format.repart_format()));
        }
        std::fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}
