//! Array and volume resolution for the evaluated `aos.provisioning.storage`
//! projection.
//!
//! The native storage provider owns the partition layer that `systemd-repart` carves.
//! This module owns what sits on top of it: Linux MD arrays bound from
//! declared partitions, and the volumes (a filesystem, optionally inside a
//! TPM-sealed LUKS2 container) that partitions and arrays carry. It validates
//! the topology against the partition layer and renders two line-oriented
//! files for the initrd units that create, assemble, unlock, and mount them.
//!
//! `storage-arrays` lists one array per line:
//!
//! ```text
//! <name>\t<level>\t<member count>\t<member device>,<member device>,...
//! ```
//!
//! `storage-volumes` lists one volume per line:
//!
//! ```text
//! <name>\t<partition|array>\t<device>\t<label>\t<none|tpm2>\t<filesystem|->
//! ```
//!
//! Member and partition devices are `/dev/disk/by-partlabel/<label>` paths;
//! array devices are `/dev/md/<name>`. Both files are tab separated with no
//! quoting because every field is validated to a conservative character set
//! before rendering.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::{ArraySpec, PartitionSpec, ProvisioningPlan};

/// GPT type GUID for a Linux MD RAID member partition.
pub const LINUX_RAID_TYPE_GUID: &str = "a19d880f-05fc-4d3b-a006-743f0f84911e";
/// Rendered array index below the metadata stash.
pub const ARRAYS_FILE: &str = "storage-arrays";
/// Rendered volume index below the metadata stash.
pub const VOLUMES_FILE: &str = "storage-volumes";
/// Logical name of the system-state volume.
pub const SYSTEM_STATE_VOLUME: &str = "var";

/// Longest filesystem label ext4 stores; longer labels are silently truncated
/// by `mkfs.ext4`, which would break mounting by `/dev/disk/by-label`.
const MAX_EXT4_LABEL_BYTES: usize = 16;
/// Longest filesystem label XFS stores; `mkfs.xfs` rejects longer ones.
const MAX_XFS_LABEL_BYTES: usize = 12;

/// Returns the label capacity of a supported volume filesystem.
fn max_label_bytes(filesystem: &str) -> Option<usize> {
    match filesystem {
        "ext4" => Some(MAX_EXT4_LABEL_BYTES),
        "xfs" => Some(MAX_XFS_LABEL_BYTES),
        _ => None,
    }
}

/// Encryption applied to a volume after policy defaults are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// The filesystem sits on the raw partition or array.
    None,
    /// LUKS2 with the key sealed to the measured-boot TPM policy.
    Tpm2,
}

impl Encryption {
    /// Returns the stable name used in rendered files and CLI output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tpm2 => "tpm2",
        }
    }
}

impl fmt::Display for Encryption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Which layer of the plan carries a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeSource {
    /// A partition carved by `systemd-repart`.
    Partition,
    /// An MD array assembled from partitions.
    Array,
}

impl VolumeSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Partition => "partition",
            Self::Array => "array",
        }
    }
}

/// One MD array after validation against the partition layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrayLayout {
    /// Logical name; also the md name and `/dev/md/<name>` identity.
    pub name: String,
    /// Validated MD RAID level (`raid1`, `raid10`, ...).
    pub level: String,
    /// Stable member device paths in declaration order.
    pub members: Vec<String>,
}

/// One volume after policy defaults are resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeLayout {
    /// Logical name of the partition or array that carries the volume.
    pub name: String,
    /// Which layer carries the volume.
    pub source: VolumeSource,
    /// Stable block device the volume lives on before any unlock.
    pub device: String,
    /// Filesystem label; the mount identity `/dev/disk/by-label/<label>`.
    pub label: String,
    /// Resolved encryption.
    pub encryption: Encryption,
    /// Filesystem created on the volume, or `None` for a raw device.
    pub filesystem: Option<String>,
}

impl VolumeLayout {
    /// Whether this volume is the system-state volume mounted at `/var`.
    pub fn is_system_state(&self) -> bool {
        self.name == SYSTEM_STATE_VOLUME
    }
}

/// The validated array and volume layers of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Topology {
    /// Logical partition names that are array members.
    pub members: BTreeSet<String>,
    /// Arrays in stable order, the system-state array first.
    pub arrays: Vec<ArrayLayout>,
    /// Volumes in stable order, the system-state volume first.
    pub volumes: Vec<VolumeLayout>,
}

impl Topology {
    /// Returns the resolved encryption of a partition, or `None` when the
    /// partition carries no volume (a member, swap, or raw partition).
    pub fn partition_encryption(&self, name: &str) -> Option<Encryption> {
        self.volumes
            .iter()
            .find(|volume| volume.source == VolumeSource::Partition && volume.name == name)
            .map(|volume| volume.encryption)
    }
}

/// Resolves and validates the array and volume layers of an evaluated plan.
///
/// The partition layer is assumed to have passed its own validation. This
/// function checks that every member names a declared, unformatted,
/// unencrypted partition used by exactly one array; that levels have enough
/// members; that array names cannot collide with partition labels; that the
/// system-state volume keeps its root-disk partition; and that encryption
/// respects the measured-boot policy.
///
/// # Errors
///
/// Returns an error describing the first violated rule.
pub fn resolve_topology(plan: &ProvisioningPlan, measured_boot: bool) -> Result<Topology> {
    let partitions = &plan.storage.partitions;
    let arrays = &plan.storage.arrays;

    let members = resolve_members(partitions, arrays)?;
    validate_system_state_placement(partitions, arrays, &members)?;

    // Only a partition that carries its own filesystem competes for a
    // /dev/disk/by-label name; a member's label never reaches udev's label
    // index, which is why the `var` array may share its member's label.
    let partition_labels: BTreeSet<&str> = partitions
        .iter()
        .filter(|(name, _)| !members.contains(*name))
        .map(|(_, partition)| partition.label.as_str())
        .collect();

    let mut array_layouts = Vec::new();
    let mut volumes = Vec::new();
    for (name, array) in arrays {
        validate_array_name(name, array.format.as_deref(), &partition_labels)?;
        validate_level(name, &array.level, array.members.len())?;
        let member_devices = array
            .members
            .iter()
            .map(|member| partition_device(&partitions[member]))
            .collect();
        array_layouts.push(ArrayLayout {
            name: name.clone(),
            level: array.level.clone(),
            members: member_devices,
        });

        let filesystem = validate_array_filesystem(name, array)?;
        let encryption = resolve_encryption(
            array.encryption.as_deref(),
            name == SYSTEM_STATE_VOLUME,
            filesystem.as_deref(),
            measured_boot,
        )
        .with_context(|| format!("array '{name}'"))?;
        volumes.push(VolumeLayout {
            name: name.clone(),
            source: VolumeSource::Array,
            device: format!("/dev/md/{name}"),
            label: name.clone(),
            encryption,
            filesystem,
        });
    }

    for (name, partition) in partitions {
        if members.contains(name) {
            continue;
        }
        let Some(filesystem) = partition_filesystem(name, partition) else {
            if matches!(partition.encryption.as_deref(), Some("tpm2")) {
                bail!("partition '{name}' declares encryption but carries no filesystem");
            }
            continue;
        };
        if let Some(limit) = max_label_bytes(filesystem)
            && partition.label.len() > limit
        {
            bail!(
                "partition '{name}' label '{}' exceeds the {limit}-byte {filesystem} label limit",
                partition.label
            );
        }
        let encryption = resolve_encryption(
            partition.encryption.as_deref(),
            name == SYSTEM_STATE_VOLUME && partition.device.is_none(),
            Some(filesystem),
            measured_boot,
        )
        .with_context(|| format!("partition '{name}'"))?;
        volumes.push(VolumeLayout {
            name: name.clone(),
            source: VolumeSource::Partition,
            device: partition_device(partition),
            label: partition.label.clone(),
            encryption,
            filesystem: Some(filesystem.to_owned()),
        });
    }

    // The initrd consumes the system-state entry first, and every later
    // consumer benefits from a stable, declaration-independent order.
    array_layouts.sort_by_key(|array| (array.name != SYSTEM_STATE_VOLUME, array.name.clone()));
    volumes.sort_by_key(|volume| (!volume.is_system_state(), volume.name.clone()));

    Ok(Topology {
        members,
        arrays: array_layouts,
        volumes,
    })
}

/// Renders the array and volume indexes below the metadata stash.
///
/// Both files are rewritten atomically enough for the initrd: they are only
/// read after the rendering command has exited.
///
/// # Errors
///
/// Returns an error when a file cannot be written.
pub fn render_topology(stash_dir: &Path, topology: &Topology) -> Result<Vec<PathBuf>> {
    let mut arrays = String::new();
    for array in &topology.arrays {
        arrays.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            array.name,
            array.level,
            array.members.len(),
            array.members.join(",")
        ));
    }
    let arrays_path = stash_dir.join(ARRAYS_FILE);
    std::fs::write(&arrays_path, arrays).context("writing storage array index")?;

    let mut volumes = String::new();
    for volume in &topology.volumes {
        volumes.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            volume.name,
            volume.source.as_str(),
            volume.device,
            volume.label,
            volume.encryption,
            volume.filesystem.as_deref().unwrap_or("-")
        ));
    }
    let volumes_path = stash_dir.join(VOLUMES_FILE);
    std::fs::write(&volumes_path, volumes).context("writing storage volume index")?;

    Ok(vec![arrays_path, volumes_path])
}

/// Returns the stable device path of a partition.
pub fn partition_device(partition: &PartitionSpec) -> String {
    format!("/dev/disk/by-partlabel/{}", partition.label)
}

/// Returns the filesystem a non-member partition carries.
///
/// The root-disk system-state partition is ext4 unless declared otherwise;
/// every other partition is raw unless it declares a format. Swap is a
/// format but not a volume.
fn partition_filesystem<'a>(name: &str, partition: &'a PartitionSpec) -> Option<&'a str> {
    match partition.format.as_deref() {
        Some("swap") => None,
        Some(format) => Some(format),
        None if name == SYSTEM_STATE_VOLUME && partition.device.is_none() => Some("ext4"),
        None => None,
    }
}

fn resolve_members(
    partitions: &BTreeMap<String, PartitionSpec>,
    arrays: &BTreeMap<String, ArraySpec>,
) -> Result<BTreeSet<String>> {
    let mut members = BTreeSet::new();
    for (name, array) in arrays {
        let mut seen = BTreeSet::new();
        for member in &array.members {
            if !seen.insert(member.as_str()) {
                bail!("array '{name}' lists member '{member}' more than once");
            }
            let Some(partition) = partitions.get(member) else {
                bail!("array '{name}' member '{member}' is not a declared partition");
            };
            validate_member_partition(member, partition)
                .with_context(|| format!("array '{name}'"))?;
            if !members.insert(member.clone()) {
                bail!("partition '{member}' is a member of more than one array");
            }
        }
    }
    Ok(members)
}

fn validate_member_partition(name: &str, partition: &PartitionSpec) -> Result<()> {
    if partition.format.is_some() {
        bail!(
            "member partition '{name}' must not declare a format; the array carries the filesystem"
        );
    }
    if matches!(partition.encryption.as_deref(), Some("tpm2")) {
        bail!("member partition '{name}' must not declare encryption; encrypt the array instead");
    }
    let lower = partition.partition_type.to_ascii_lowercase();
    if !matches!(
        lower.as_str(),
        "linux-generic" | "linux-raid" | LINUX_RAID_TYPE_GUID
    ) {
        bail!(
            "member partition '{name}' has type '{}', expected linux-generic or linux-raid",
            partition.partition_type
        );
    }
    Ok(())
}

/// The system-state volume is either the root-disk `var` partition or the
/// `var` array that contains it. A `var` array without the root-disk member
/// would leave a second, unrelated ext4 `var` on the boot disk.
fn validate_system_state_placement(
    partitions: &BTreeMap<String, PartitionSpec>,
    arrays: &BTreeMap<String, ArraySpec>,
    members: &BTreeSet<String>,
) -> Result<()> {
    let Some(var) = partitions.get(SYSTEM_STATE_VOLUME) else {
        bail!("storage plan must declare the '{SYSTEM_STATE_VOLUME}' partition on the root disk");
    };
    if var.device.is_some() || var.label != SYSTEM_STATE_VOLUME {
        bail!("the '{SYSTEM_STATE_VOLUME}' partition must keep label 'var' on the root disk");
    }
    match arrays.get(SYSTEM_STATE_VOLUME) {
        Some(array) => {
            if !array
                .members
                .iter()
                .any(|member| member == SYSTEM_STATE_VOLUME)
            {
                bail!(
                    "array '{SYSTEM_STATE_VOLUME}' must include the root-disk '{SYSTEM_STATE_VOLUME}' partition as a member"
                );
            }
        }
        None => {
            if members.contains(SYSTEM_STATE_VOLUME) {
                bail!(
                    "the '{SYSTEM_STATE_VOLUME}' partition may only be a member of the '{SYSTEM_STATE_VOLUME}' array"
                );
            }
        }
    }
    Ok(())
}

/// The array name doubles as its filesystem label, so the filesystem's label
/// capacity bounds it; a raw array only needs an md-safe name.
fn validate_array_name(
    name: &str,
    format: Option<&str>,
    partition_labels: &BTreeSet<&str>,
) -> Result<()> {
    let limit = format
        .and_then(max_label_bytes)
        .unwrap_or(MAX_EXT4_LABEL_BYTES);
    if name.is_empty()
        || name.len() > limit
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("array name '{name}' must be 1-{limit} ASCII letters, digits, '.', '_' or '-'");
    }
    if partition_labels.contains(name) {
        bail!(
            "array name '{name}' collides with a partition label; both would claim /dev/disk/by-label/{name}"
        );
    }
    Ok(())
}

fn validate_level(name: &str, level: &str, member_count: usize) -> Result<()> {
    let minimum = match level {
        "raid0" | "raid1" => 2,
        "raid10" | "raid5" => 3,
        "raid6" => 4,
        other => bail!("array '{name}' has unsupported level '{other}'"),
    };
    if member_count < minimum {
        bail!(
            "array '{name}' level {level} needs at least {minimum} members, found {member_count}"
        );
    }
    Ok(())
}

/// The system-state array is ext4 only: every unit on the boot path, from
/// the seal step to recovery, formats and repairs `/var` as ext4.
fn validate_array_filesystem(name: &str, array: &ArraySpec) -> Result<Option<String>> {
    match array.format.as_deref() {
        Some("ext4") => Ok(Some("ext4".into())),
        Some("xfs") if name != SYSTEM_STATE_VOLUME => Ok(Some("xfs".into())),
        None if name != SYSTEM_STATE_VOLUME => Ok(None),
        None | Some("xfs") => bail!("array '{name}' must carry the ext4 system-state filesystem"),
        Some(other) => bail!("array '{name}' uses unsupported format '{other}'"),
    }
}

/// Resolves the declared encryption against image policy.
///
/// `null` means "image policy": TPM-sealed for the system-state volume on a
/// measured-boot image, plain otherwise. A measured-boot image never accepts
/// a plaintext system-state volume, and no image accepts TPM sealing without
/// measured boot, because the seal would bind to nothing meaningful.
fn resolve_encryption(
    declared: Option<&str>,
    system_state: bool,
    filesystem: Option<&str>,
    measured_boot: bool,
) -> Result<Encryption> {
    let encryption = match declared {
        None if system_state && measured_boot => Encryption::Tpm2,
        None | Some("none") => Encryption::None,
        Some("tpm2") => Encryption::Tpm2,
        Some(other) => bail!("unsupported encryption '{other}'"),
    };
    match encryption {
        Encryption::Tpm2 if !measured_boot => {
            bail!("tpm2 encryption requires a measured-boot image")
        }
        Encryption::Tpm2 if !matches!(filesystem, Some("ext4" | "xfs")) => {
            bail!("tpm2 encryption is only supported for ext4 and xfs volumes")
        }
        Encryption::None if system_state && measured_boot => {
            bail!("a measured-boot image requires the system-state volume to be encrypted")
        }
        _ => Ok(encryption),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    fn topology_plan(
        partitions: &[(&str, Option<&str>, Option<&str>, Option<&str>)],
        arrays: &[(&str, &str, &[&str], Option<&str>, Option<&str>)],
    ) -> crate::ProvisioningPlan {
        use std::collections::BTreeMap;

        use crate::{ArraySpec, PartitionSpec, ProvisioningPlan, StoragePlan};

        let mut partition_map = BTreeMap::new();
        for (name, device, format, encryption) in partitions {
            partition_map.insert(
                (*name).to_owned(),
                PartitionSpec {
                    device: device.map(str::to_owned),
                    label: (*name).to_owned(),
                    partition_type: "linux-generic".into(),
                    size_min: "1G".into(),
                    size_max: Some("1G".into()),
                    weight: 1000,
                    format: format.map(str::to_owned),
                    encryption: encryption.map(str::to_owned),
                    uuid: None,
                    grow: false,
                    grow_fs: true,
                    priority: 1000,
                },
            );
        }
        let mut array_map = BTreeMap::new();
        for (name, level, members, format, encryption) in arrays {
            array_map.insert(
                (*name).to_owned(),
                ArraySpec {
                    level: (*level).to_owned(),
                    members: members.iter().map(|member| (*member).to_owned()).collect(),
                    format: format.map(str::to_owned),
                    encryption: encryption.map(str::to_owned),
                },
            );
        }
        ProvisioningPlan {
            schema: "aos.provisioning-plan/v1".into(),
            storage: StoragePlan {
                partitions: partition_map,
                arrays: array_map,
            },
        }
    }

    #[test]
    fn storage_topology_renders_arrays_and_volumes() {
        use super::{ARRAYS_FILE, VOLUMES_FILE};

        const DISK_B: &str = "/dev/disk/by-id/virtio-b";
        const DISK_C: &str = "/dev/disk/by-id/virtio-c";
        let plan = topology_plan(
            &[
                ("var", None, None, None),
                ("var-mirror", Some(DISK_B), None, None),
                ("data-a", Some(DISK_B), None, None),
                ("data-b", Some(DISK_C), None, None),
                ("scratch", Some(DISK_C), Some("ext4"), None),
            ],
            &[
                ("var", "raid1", &["var", "var-mirror"], Some("ext4"), None),
                ("data", "raid1", &["data-a", "data-b"], Some("ext4"), None),
            ],
        );
        let output = tempdir().unwrap();
        let topology = super::resolve_topology(&plan, false).unwrap();
        super::render_topology(output.path(), &topology).unwrap();

        let arrays = std::fs::read_to_string(output.path().join(ARRAYS_FILE)).unwrap();
        assert_eq!(
            arrays,
            "var\traid1\t2\t/dev/disk/by-partlabel/var,/dev/disk/by-partlabel/var-mirror\n\
         data\traid1\t2\t/dev/disk/by-partlabel/data-a,/dev/disk/by-partlabel/data-b\n"
        );
        let volumes = std::fs::read_to_string(output.path().join(VOLUMES_FILE)).unwrap();
        assert_eq!(
            volumes,
            "var\tarray\t/dev/md/var\tvar\tnone\text4\n\
         data\tarray\t/dev/md/data\tdata\tnone\text4\n\
         scratch\tpartition\t/dev/disk/by-partlabel/scratch\tscratch\tnone\text4\n"
        );

        assert!(topology.members.contains("var"));
        assert!(topology.members.contains("data-a"));
        assert_eq!(
            topology.partition_encryption("scratch"),
            Some(super::Encryption::None)
        );
    }

    #[test]
    fn storage_topology_rejects_invalid_arrays() {
        use crate::validate_provisioning_plan;

        const DISK_B: &str = "/dev/disk/by-id/virtio-b";
        let invalid = [
            // Undeclared member.
            topology_plan(
                &[("var", None, None, None)],
                &[("data", "raid1", &["missing", "var"], Some("ext4"), None)],
            ),
            // Member declares its own filesystem.
            topology_plan(
                &[
                    ("var", None, None, None),
                    ("a", Some(DISK_B), Some("ext4"), None),
                    ("b", Some(DISK_B), None, None),
                ],
                &[("data", "raid1", &["a", "b"], Some("ext4"), None)],
            ),
            // Too few members for the level.
            topology_plan(
                &[("var", None, None, None), ("a", Some(DISK_B), None, None)],
                &[("data", "raid1", &["a"], Some("ext4"), None)],
            ),
            // The var array omits the root-disk var partition.
            topology_plan(
                &[
                    ("var", None, None, None),
                    ("a", Some(DISK_B), None, None),
                    ("b", Some(DISK_B), None, None),
                ],
                &[("var", "raid1", &["a", "b"], Some("ext4"), None)],
            ),
            // The var partition joins an unrelated array.
            topology_plan(
                &[("var", None, None, None), ("a", Some(DISK_B), None, None)],
                &[("data", "raid1", &["var", "a"], Some("ext4"), None)],
            ),
            // Array name collides with a partition label.
            topology_plan(
                &[
                    ("var", None, None, None),
                    ("a", Some(DISK_B), None, None),
                    ("b", Some(DISK_B), None, None),
                    ("data", Some(DISK_B), Some("ext4"), None),
                ],
                &[("data", "raid1", &["a", "b"], Some("ext4"), None)],
            ),
            // One partition in two arrays.
            topology_plan(
                &[
                    ("var", None, None, None),
                    ("a", Some(DISK_B), None, None),
                    ("b", Some(DISK_B), None, None),
                    ("c", Some(DISK_B), None, None),
                ],
                &[
                    ("x", "raid1", &["a", "b"], Some("ext4"), None),
                    ("y", "raid1", &["b", "c"], Some("ext4"), None),
                ],
            ),
            // Unsupported level.
            topology_plan(
                &[
                    ("var", None, None, None),
                    ("a", Some(DISK_B), None, None),
                    ("b", Some(DISK_B), None, None),
                ],
                &[("data", "linear", &["a", "b"], Some("ext4"), None)],
            ),
        ];
        for plan in invalid {
            assert!(
                validate_provisioning_plan(&plan, false).is_err(),
                "{plan:?}"
            );
        }
    }

    #[test]
    fn storage_encryption_follows_measured_boot_policy() {
        use super::{VOLUMES_FILE, resolve_topology};
        use crate::validate_provisioning_plan;

        const DISK_B: &str = "/dev/disk/by-id/virtio-b";

        // Image policy: var is sealed on a measured image, plain otherwise.
        let plan = topology_plan(&[("var", None, None, None)], &[]);
        let measured = resolve_topology(&plan, true).unwrap();
        assert_eq!(measured.volumes[0].encryption.as_str(), "tpm2");
        let unmeasured = resolve_topology(&plan, false).unwrap();
        assert_eq!(unmeasured.volumes[0].encryption.as_str(), "none");

        // A sealed volume is rendered raw so the unlock unit can format it; a data
        // partition may opt in on a measured image.
        let plan = topology_plan(
            &[
                ("var", None, None, None),
                ("data", Some(DISK_B), Some("ext4"), Some("tpm2")),
            ],
            &[],
        );
        let output = tempdir().unwrap();
        let topology = resolve_topology(&plan, true).unwrap();
        super::render_topology(output.path(), &topology).unwrap();
        let volumes = std::fs::read_to_string(output.path().join(VOLUMES_FILE)).unwrap();
        assert_eq!(
            volumes,
            "var\tpartition\t/dev/disk/by-partlabel/var\tvar\ttpm2\text4\n\
         data\tpartition\t/dev/disk/by-partlabel/data\tdata\ttpm2\text4\n"
        );

        let invalid = [
            // Sealing needs measured boot.
            (
                topology_plan(
                    &[
                        ("var", None, None, None),
                        ("data", Some(DISK_B), Some("ext4"), Some("tpm2")),
                    ],
                    &[],
                ),
                false,
            ),
            // A measured image never runs a plaintext system-state volume.
            (
                topology_plan(&[("var", None, None, Some("none"))], &[]),
                true,
            ),
            // Only ext4 volumes can be sealed.
            (
                topology_plan(
                    &[
                        ("var", None, None, None),
                        ("esp2", Some(DISK_B), Some("vfat"), Some("tpm2")),
                    ],
                    &[],
                ),
                true,
            ),
            // Members are never encrypted individually.
            (
                topology_plan(
                    &[
                        ("var", None, None, None),
                        ("a", Some(DISK_B), None, Some("tpm2")),
                        ("b", Some(DISK_B), None, None),
                    ],
                    &[("data", "raid1", &["a", "b"], Some("ext4"), None)],
                ),
                true,
            ),
        ];
        for (plan, measured_boot) in invalid {
            assert!(
                validate_provisioning_plan(&plan, measured_boot).is_err(),
                "{plan:?}"
            );
        }
    }

    #[test]
    fn storage_topology_admits_xfs_data_volumes_only() {
        use super::resolve_topology;
        use crate::validate_provisioning_plan;

        const DISK_B: &str = "/dev/disk/by-id/virtio-b";

        // xfs on a data array and a data partition, sealed or plain.
        let plan = topology_plan(
            &[
                ("var", None, None, None),
                ("a", Some(DISK_B), None, None),
                ("b", Some(DISK_B), None, None),
                ("scratch", Some(DISK_B), Some("xfs"), Some("tpm2")),
            ],
            &[("bulk", "raid1", &["a", "b"], Some("xfs"), None)],
        );
        let topology = resolve_topology(&plan, true).unwrap();
        assert!(topology.volumes.iter().any(|volume| {
            volume.name == "bulk" && volume.filesystem.as_deref() == Some("xfs")
        }));
        assert!(
            topology
                .volumes
                .iter()
                .any(|volume| { volume.name == "scratch" && volume.encryption.as_str() == "tpm2" })
        );

        let invalid = [
            // The system-state array is ext4 only.
            topology_plan(
                &[("var", None, None, None), ("m", Some(DISK_B), None, None)],
                &[("var", "raid1", &["var", "m"], Some("xfs"), None)],
            ),
            // The root-disk var partition is ext4 only.
            topology_plan(&[("var", None, Some("xfs"), None)], &[]),
            // An xfs array name must fit the 12-byte xfs label.
            topology_plan(
                &[
                    ("var", None, None, None),
                    ("a", Some(DISK_B), None, None),
                    ("b", Some(DISK_B), None, None),
                ],
                &[("thirteen-char", "raid1", &["a", "b"], Some("xfs"), None)],
            ),
            // An xfs partition label must fit as well.
            topology_plan(
                &[
                    ("var", None, None, None),
                    ("thirteen-char", Some(DISK_B), Some("xfs"), None),
                ],
                &[],
            ),
        ];
        for plan in invalid {
            assert!(
                validate_provisioning_plan(&plan, false).is_err(),
                "{plan:?}"
            );
        }

        // The same 13-byte name is fine for ext4.
        let ext4 = topology_plan(
            &[
                ("var", None, None, None),
                ("a", Some(DISK_B), None, None),
                ("b", Some(DISK_B), None, None),
            ],
            &[("thirteen-char", "raid1", &["a", "b"], Some("ext4"), None)],
        );
        validate_provisioning_plan(&ext4, false).unwrap();
    }
}
