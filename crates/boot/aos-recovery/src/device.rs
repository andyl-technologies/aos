//! Resolves the installed disk and rejects ambiguous recovery device labels.
//!
//! Recovery never trusts a single udev by-label symlink. It asks `blkid` for
//! every matching partition, requires exactly one result, resolves the kernel
//! block topology, and proves that every installed partition shares one
//! non-removable parent. Removable recovery media must resolve to a different
//! parent device.

use std::error::Error;
use std::fmt;
use std::io;
use std::path::PathBuf;

use aos_boot_media::device::{self, InstalledLayout};
use aos_boot_media::{MediaError, Tools};

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

impl From<MediaError> for DeviceError {
    fn from(error: MediaError) -> Self {
        match error {
            MediaError::Io(error) => Self::Io(error),
            other => Self::Topology(other.to_string()),
        }
    }
}

/// Holds canonical device nodes for the one accepted installed disk.
pub type HostLayout = InstalledLayout;

/// Resolves and validates the complete installed-disk partition set.
///
/// # Errors
///
/// Returns [`DeviceError`] when a required PARTLABEL is missing or duplicated,
/// a result is not a block partition, the partitions have different parents,
/// the installed parent reports itself as removable, or the `var` partition is
/// an MD array member.
pub fn discover_host_layout() -> Result<HostLayout, DeviceError> {
    let tools = Tools::initrd();
    let layout = InstalledLayout::discover(&tools.blkid)?;
    // A host that mirrors its system state declares a `var` MD array in
    // host.nix; the partition then only carries an MD superblock. Recovery
    // maintenance authenticates and mounts the root-disk partition directly,
    // so it must refuse rather than treat the member as the volume.
    if device::probe_type(&tools.blkid, &layout.var)?.as_deref() == Some("linux_raid_member") {
        return Err(DeviceError::Topology(
            "the var partition is an MD array member; recovery maintenance supports only \
             a system-state volume carried directly by the root-disk partition"
                .into(),
        ));
    }
    Ok(layout)
}

/// Resolves the unique removable bundle device outside the installed disk.
///
/// # Errors
///
/// Returns [`DeviceError`] unless exactly one filesystem has the fixed label
/// and its kernel parent differs from the installed parent disk.
pub fn discover_recovery_media(host: &HostLayout) -> Result<PathBuf, DeviceError> {
    let media = device::unique_device(&Tools::initrd().blkid, "LABEL", "AOS-RECOVERY")?;
    let parent = device::disk_of(&media)?;
    if parent == host.parent {
        return Err(DeviceError::Topology(
            "recovery media is a partition on the installed disk".into(),
        ));
    }
    if !device::is_removable(&parent)? {
        return Err(DeviceError::Topology(
            "recovery media parent is not removable".into(),
        ));
    }
    Ok(media)
}
