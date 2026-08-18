//! Resolves the installed disk and rejects ambiguous recovery device labels.
//!
//! Recovery never trusts a single udev by-label symlink. It asks `blkid` for
//! every matching partition, requires exactly one result, resolves the kernel
//! block topology, and proves that every installed partition shares one
//! non-removable parent. Removable recovery media must resolve to a different
//! parent device.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Reports an ambiguous, incomplete, or unsafe block-device topology.
#[derive(Debug)]
pub enum DeviceError {
    /// A fixed-path filesystem or process operation failed.
    Io(io::Error),
    /// Device discovery did not produce one safe installed-disk layout.
    Topology(String),
}

impl fmt::Display for DeviceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "device discovery I/O failure: {error}"),
            Self::Topology(reason) => write!(formatter, "unsafe device topology: {reason}"),
        }
    }
}

impl Error for DeviceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Topology(_) => None,
        }
    }
}

impl From<io::Error> for DeviceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Holds canonical device nodes for the one accepted installed disk.
#[derive(Clone, Debug)]
pub struct HostLayout {
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
    /// Encrypted persistent-state partition.
    pub var: PathBuf,
    parent: PathBuf,
}

/// Resolves and validates the complete installed-disk partition set.
///
/// # Errors
///
/// Returns [`DeviceError`] when a required PARTLABEL is missing or duplicated,
/// a result is not a block partition, the partitions have different parents,
/// or the installed parent reports itself as removable.
pub fn discover_host_layout() -> Result<HostLayout, DeviceError> {
    let esp = unique_blkid("PARTLABEL", "ESP")?;
    let root_a = unique_blkid("PARTLABEL", "root-a")?;
    let root_a_hash = unique_blkid("PARTLABEL", "root-a-hash")?;
    let root_b = unique_blkid("PARTLABEL", "root-b")?;
    let root_b_hash = unique_blkid("PARTLABEL", "root-b-hash")?;
    let var = unique_blkid("PARTLABEL", "var")?;
    let devices = [&esp, &root_a, &root_a_hash, &root_b, &root_b_hash, &var];
    let parent = partition_parent(&esp)?;
    for device in devices.iter().skip(1) {
        if partition_parent(device)? != parent {
            return Err(DeviceError::Topology(
                "installed partitions do not share one parent disk".into(),
            ));
        }
    }
    let removable = fs::read_to_string(parent.join("removable"))?;
    if removable.trim() != "0" {
        return Err(DeviceError::Topology(
            "installed parent disk is removable".into(),
        ));
    }
    Ok(HostLayout {
        esp,
        root_a,
        root_a_hash,
        root_b,
        root_b_hash,
        var,
        parent,
    })
}

/// Resolves the unique removable bundle device outside the installed disk.
///
/// # Errors
///
/// Returns [`DeviceError`] unless exactly one filesystem has the fixed label
/// and its kernel parent differs from the installed parent disk.
pub fn discover_recovery_media(host: &HostLayout) -> Result<PathBuf, DeviceError> {
    let media = unique_blkid("LABEL", "AOS-RECOVERY")?;
    let parent = media_parent(&media)?;
    if parent == host.parent {
        return Err(DeviceError::Topology(
            "recovery media is a partition on the installed disk".into(),
        ));
    }
    let removable = fs::read_to_string(parent.join("removable"))?;
    if removable.trim() != "1" {
        return Err(DeviceError::Topology(
            "recovery media parent is not removable".into(),
        ));
    }
    Ok(media)
}

fn media_parent(device: &Path) -> Result<PathBuf, DeviceError> {
    let name = device
        .file_name()
        .ok_or_else(|| DeviceError::Topology("media device has no kernel name".into()))?;
    let sys = fs::canonicalize(Path::new("/sys/class/block").join(name))?;
    if sys.join("partition").is_file() {
        return sys.parent().map(Path::to_path_buf).ok_or_else(|| {
            DeviceError::Topology("recovery-media partition has no parent device".into())
        });
    }
    Ok(sys)
}

fn unique_blkid(field: &str, value: &str) -> Result<PathBuf, DeviceError> {
    let output = Command::new("/bin/blkid")
        .args(["-c", "/dev/null", "-o", "device", "-t"])
        .arg(format!("{field}={value}"))
        .output()?;
    if !output.status.success() {
        return Err(DeviceError::Topology(format!(
            "blkid could not resolve {field}={value}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| DeviceError::Topology(error.to_string()))?;
    let matches = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(DeviceError::Topology(format!(
            "expected one {field}={value} device, found {}",
            matches.len()
        )));
    }
    let device = fs::canonicalize(matches[0])?;
    if !fs::metadata(&device)?.file_type().is_block_device() {
        return Err(DeviceError::Topology(format!(
            "{} is not a block device",
            device.display()
        )));
    }
    Ok(device)
}

fn partition_parent(device: &Path) -> Result<PathBuf, DeviceError> {
    let name = device
        .file_name()
        .ok_or_else(|| DeviceError::Topology("device has no kernel name".into()))?;
    let sys = fs::canonicalize(Path::new("/sys/class/block").join(name))?;
    if !sys.join("partition").is_file() {
        return Err(DeviceError::Topology(format!(
            "{} is not a partition",
            device.display()
        )));
    }
    sys.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| DeviceError::Topology("partition has no parent device".into()))
}
