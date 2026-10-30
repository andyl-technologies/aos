//! Resolves labels to unique block devices and validates disk topology.
//!
//! No consumer trusts a single udev by-label symlink: `blkid` is asked for
//! every match with its cache disabled, exactly one result is required, and the
//! kernel block topology under `/sys/class/block` decides parents and
//! removability. [`InstalledLayout`] applies those rules to the fixed AOS
//! installed-disk partition set.
//!
//! Functions that query labels take the caller's fixed `blkid` executable.

use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::MediaError;

/// The GPT partition labels that identify an installed AOS disk.
pub const INSTALLED_PARTITION_LABELS: [&str; 6] = [
    "ESP",
    "root-a",
    "root-a-hash",
    "root-b",
    "root-b-hash",
    "var",
];

/// Holds canonical device nodes for the one accepted installed disk.
#[derive(Clone, Debug)]
pub struct InstalledLayout {
    /// EFI System Partition.
    pub esp: PathBuf,
    /// Immutable slot-A data partition.
    pub root_a: PathBuf,
    /// Immutable slot-A verity partition.
    pub root_a_hash: PathBuf,
    /// Immutable slot-B data partition.
    pub root_b: PathBuf,
    /// Immutable slot-B verity partition.
    pub root_b_hash: PathBuf,
    /// Persistent-state partition.
    pub var: PathBuf,
    /// Sysfs directory of the shared, non-removable parent disk.
    pub parent: PathBuf,
}

impl InstalledLayout {
    /// Resolves and validates the complete installed-disk partition set.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::Topology`] when a required PARTLABEL is missing
    /// or duplicated, a result is not a block partition, the partitions have
    /// different parents, or the shared parent reports itself as removable.
    pub fn discover(blkid: &Path) -> Result<Self, MediaError> {
        let [esp, root_a, root_a_hash, root_b, root_b_hash, var] =
            INSTALLED_PARTITION_LABELS.map(|label| unique_device(blkid, "PARTLABEL", label));
        let (esp, root_a, root_a_hash, root_b, root_b_hash, var) =
            (esp?, root_a?, root_a_hash?, root_b?, root_b_hash?, var?);

        let parent = partition_parent(&esp)?;
        for device in [&root_a, &root_a_hash, &root_b, &root_b_hash, &var] {
            if partition_parent(device)? != parent {
                return Err(MediaError::Topology(
                    "installed partitions do not share one parent disk".into(),
                ));
            }
        }
        if is_removable(&parent)? {
            return Err(MediaError::Topology(
                "installed parent disk is removable".into(),
            ));
        }

        Ok(Self {
            esp,
            root_a,
            root_a_hash,
            root_b,
            root_b_hash,
            var,
            parent,
        })
    }

    /// Returns the installed partitions keyed by their GPT label.
    #[must_use]
    pub fn by_label(&self) -> [(&'static str, &Path); 6] {
        [
            ("ESP", &self.esp),
            ("root-a", &self.root_a),
            ("root-a-hash", &self.root_a_hash),
            ("root-b", &self.root_b),
            ("root-b-hash", &self.root_b_hash),
            ("var", &self.var),
        ]
    }
}

/// Resolves the one block device whose `field` equals `value`.
///
/// `field` is a `blkid` tag such as `LABEL` or `PARTLABEL`.
///
/// # Errors
///
/// Returns [`MediaError::Topology`] unless exactly one block device matches.
pub fn unique_device(blkid: &Path, field: &str, value: &str) -> Result<PathBuf, MediaError> {
    let matches = matching_devices(blkid, field, value)?;
    match matches.as_slice() {
        [device] => Ok(device.clone()),
        _ => Err(MediaError::Topology(format!(
            "expected one {field}={value} device, found {}",
            matches.len()
        ))),
    }
}

/// Resolves every block device whose `field` equals `value`.
///
/// An absent tag yields an empty list rather than an error.
///
/// # Errors
///
/// Returns [`MediaError`] when `blkid` fails for a reason other than "no
/// match", or a result is not a block device.
pub fn matching_devices(
    blkid: &Path,
    field: &str,
    value: &str,
) -> Result<Vec<PathBuf>, MediaError> {
    let output = Command::new(blkid)
        .args(["-c", "/dev/null", "-o", "device", "-t"])
        .arg(format!("{field}={value}"))
        .output()?;
    // blkid exits 2 when no device carries the requested tag.
    if output.status.code() == Some(2) {
        return Ok(Vec::new());
    }
    if !output.status.success() {
        return Err(MediaError::Topology(format!(
            "blkid could not resolve {field}={value}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| MediaError::Topology(error.to_string()))?;
    let mut devices = Vec::new();
    for line in stdout.lines().filter(|line| !line.is_empty()) {
        let device = fs::canonicalize(line)?;
        if !fs::metadata(&device)?.file_type().is_block_device() {
            return Err(MediaError::Topology(format!(
                "{} is not a block device",
                device.display()
            )));
        }
        devices.push(device);
    }
    Ok(devices)
}

/// Probes the on-disk signature type of a device, ignoring the blkid cache.
///
/// Returns `None` for a device without any recognized signature.
///
/// # Errors
///
/// Returns [`MediaError`] when `blkid` cannot run or prints non-UTF-8 output.
pub fn probe_type(blkid: &Path, device: &Path) -> Result<Option<String>, MediaError> {
    let output = Command::new(blkid)
        .args(["-c", "/dev/null", "-p", "-s", "TYPE", "-o", "value"])
        .arg(device)
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|error| MediaError::Topology(error.to_string()))?;
    let value = value.trim();
    Ok((!value.is_empty()).then(|| value.to_owned()))
}

/// Returns the sysfs directory of the disk that contains a partition.
///
/// # Errors
///
/// Returns [`MediaError::Topology`] when `device` is not a partition.
pub fn partition_parent(device: &Path) -> Result<PathBuf, MediaError> {
    let sys = sysfs_node(device)?;
    if !sys.join("partition").is_file() {
        return Err(MediaError::Topology(format!(
            "{} is not a partition",
            device.display()
        )));
    }
    sys.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| MediaError::Topology("partition has no parent device".into()))
}

/// Returns the sysfs directory of a whole disk, or of a partition's parent disk.
///
/// # Errors
///
/// Returns [`MediaError::Topology`] when the device has no sysfs node.
pub fn disk_of(device: &Path) -> Result<PathBuf, MediaError> {
    let sys = sysfs_node(device)?;
    if sys.join("partition").is_file() {
        return sys
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| MediaError::Topology("partition has no parent device".into()));
    }
    Ok(sys)
}

/// Reports whether a sysfs disk directory describes removable media.
///
/// # Errors
///
/// Returns [`MediaError`] when the `removable` attribute cannot be read.
pub fn is_removable(disk: &Path) -> Result<bool, MediaError> {
    Ok(fs::read_to_string(disk.join("removable"))?.trim() != "0")
}

/// Rejects a device or any of its partitions that is mounted or held.
///
/// A holder is any stacked device, such as device-mapper or MD, that has the
/// node open.
///
/// # Errors
///
/// Returns [`MediaError::Topology`] when the device, or for a whole disk any
/// of its partitions, is mounted or has a holder.
pub fn ensure_unused(device: &Path) -> Result<(), MediaError> {
    let sys = sysfs_node(device)?;
    let mut nodes = partitions(&sys)?;
    nodes.push(sys);

    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    for node in nodes {
        if fs::read_dir(node.join("holders"))?.next().is_some() {
            return Err(MediaError::Topology(format!(
                "{} has an active stacked-device holder",
                node.display()
            )));
        }
        let device_id = fs::read_to_string(node.join("dev"))?;
        let device_id = device_id.trim();
        if mountinfo
            .lines()
            .any(|line| line.split_ascii_whitespace().nth(2) == Some(device_id))
        {
            return Err(MediaError::Topology(format!(
                "{} is mounted",
                node.display()
            )));
        }
    }
    Ok(())
}

/// Lists the partitions of a whole disk as sysfs directories.
///
/// # Errors
///
/// Returns [`MediaError`] when the disk's sysfs directory cannot be read.
pub fn partitions(disk: &Path) -> Result<Vec<PathBuf>, MediaError> {
    let mut found = Vec::new();
    for entry in fs::read_dir(disk)? {
        let path = entry?.path();
        if path.join("partition").is_file() {
            found.push(path);
        }
    }
    found.sort();
    Ok(found)
}

fn sysfs_node(device: &Path) -> Result<PathBuf, MediaError> {
    let resolved = fs::canonicalize(device)?;
    let name = resolved
        .file_name()
        .ok_or_else(|| MediaError::Topology("device has no kernel name".into()))?;
    Ok(fs::canonicalize(Path::new("/sys/class/block").join(name))?)
}
