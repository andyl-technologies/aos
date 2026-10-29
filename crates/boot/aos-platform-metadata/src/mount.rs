//! Package-owned config-drive probing and read-only mounting.
//!
//! Offline channels (the AOS `AOS-META` drive, NoCloud `cidata`, OpenStack
//! `config-2`) arrive as a labeled ISO9660/vfat block device. `detect` probes
//! the known labels, mounts the first hit read-only, and returns the private
//! mountpoint to the matching [`PlatformFetcher`] within one provider call.
//!
//! The AOS label fits the 11-character FAT volume-label limit and is upper
//! case, matching what Windows, macOS, and `mkfs.fat` write, so a USB stick
//! formatted on any workstation can carry it. A label carried by more than one
//! device is an error: configuration authority is never chosen arbitrarily.
//!
//! [`PlatformFetcher`]: crate::fetcher::PlatformFetcher
//!
//! The probe is behind the [`ConfigDriveProbe`] trait so tests never touch
//! `blkid`/`mount` or require root:
//!
//! - [`BlkidProbe`] — production. Shells out to the AOS-built
//!   `pkgs.util-linux` `blkid` (cache disabled) and `mount -o ro`.
//! - [`FakeProbe`] — test double. Maps a label directly to a fixture
//!   directory, modelling an already-mounted drive.
//!
//! # Label → platform
//!
//! | Label      | Platform       |
//! |------------|----------------|
//! | `AOS-META` | `aos-metadata` |
//! | `cidata`   | `nocloud`      |
//! | `config-2` | `config-drive` |

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// The labels probed for an offline config-drive, in priority order.
///
/// `AOS-META` (the AOS-native channel) wins over the generic cloud-init
/// labels so an operator override short-circuits everything else.
pub const CONFIG_DRIVE_LABELS: &[&str] = &[AOS_METADATA_LABEL, "cidata", "config-2"];

/// The filesystem label of the AOS-native offline metadata drive.
pub const AOS_METADATA_LABEL: &str = "AOS-META";

/// Maps a filesystem label to its provider platform identifier.
///
/// Returns `None` for an unknown label.
pub fn platform_for_label(label: &str) -> Option<&'static str> {
    match label {
        AOS_METADATA_LABEL => Some("aos-metadata"),
        "cidata" => Some("nocloud"),
        "config-2" => Some("config-drive"),
        _ => None,
    }
}

/// A mounted (or fixture) config-drive ready for a fetcher to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDrive {
    /// The filesystem label that matched.
    pub label: String,
    /// The invocation-private directory from which the fetcher reads files.
    pub dir: PathBuf,
}

/// Probe for, and make readable, a labeled config-drive.
///
/// Implementors are responsible for the block-device interrogation and any
/// mount; the caller only needs the resolved directory.
pub trait ConfigDriveProbe {
    /// Probe `labels` in order; for the first present label, ensure its
    /// filesystem is readable at `mountpoint` and return the resolved
    /// [`ConfigDrive`]. Returns `Ok(None)` when no label is present.
    ///
    /// # Errors
    ///
    /// Returns `Err` when a label is found but its device cannot be mounted.
    fn probe_and_mount(&self, labels: &[&str], mountpoint: &Path) -> Result<Option<ConfigDrive>>;
}

/// Production probe: exact cache-free `blkid` label lookup then exact `mount -o ro`.
pub struct BlkidProbe {
    blkid: PathBuf,
    mount: PathBuf,
}

impl BlkidProbe {
    /// Use explicit absolute paths for `blkid` and `mount`.
    pub fn with_tools(blkid: impl Into<PathBuf>, mount: impl Into<PathBuf>) -> Self {
        Self {
            blkid: blkid.into(),
            mount: mount.into(),
        }
    }

    /// Resolve a label to its one device node, or `None` if absent.
    ///
    /// `blkid -L` silently picks one device when several share a label, so the
    /// probe lists every match and rejects ambiguity instead.
    fn device_for_label(&self, label: &str) -> Result<Option<String>> {
        let out = Command::new(&self.blkid)
            .args(["-c", "/dev/null", "-o", "device", "-t"])
            .arg(format!("LABEL={label}"))
            .output()
            .with_context(|| format!("running {} -t LABEL={label}", self.blkid.display()))?;
        if !out.status.success() {
            // blkid exits non-zero when the label is absent — not an error.
            return Ok(None);
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        single_device(label, stdout.lines())
    }
}

/// Selects the one non-empty device line, rejecting a label shared by several devices.
fn single_device<'a>(label: &str, lines: impl Iterator<Item = &'a str>) -> Result<Option<String>> {
    let devices = lines
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    match devices.as_slice() {
        [] => Ok(None),
        [device] => Ok(Some((*device).to_string())),
        _ => bail!(
            "{} devices carry the {label} label ({}); refusing to choose one",
            devices.len(),
            devices.join(", ")
        ),
    }
}

impl ConfigDriveProbe for BlkidProbe {
    fn probe_and_mount(&self, labels: &[&str], mountpoint: &Path) -> Result<Option<ConfigDrive>> {
        for label in labels {
            let Some(dev) = self.device_for_label(label)? else {
                continue;
            };
            std::fs::create_dir_all(mountpoint)
                .with_context(|| format!("creating mountpoint {}", mountpoint.display()))?;
            let status = Command::new(&self.mount)
                // Untrusted media: read-only + nodev,nosuid,noexec hygiene (does
                // not mitigate the kernel fs-driver parse surface, but denies
                // device nodes / setuid / exec from a hostile config drive).
                .arg("-o")
                .arg("ro,nodev,nosuid,noexec")
                .arg(&dev)
                .arg(mountpoint)
                .status()
                .with_context(|| format!("mounting {dev} at {}", mountpoint.display()))?;
            if !status.success() {
                bail!("mount -o ro {dev} {} failed", mountpoint.display());
            }
            return Ok(Some(ConfigDrive {
                label: (*label).to_string(),
                dir: mountpoint.to_path_buf(),
            }));
        }
        Ok(None)
    }
}

/// Test double: a label → fixture-directory map, modelling an already-mounted
/// drive. Never shells out, never requires root.
#[derive(Default)]
pub struct FakeProbe {
    drives: HashMap<String, PathBuf>,
}

impl FakeProbe {
    /// Create an empty fake probe.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `label` as present, served from `dir`.
    pub fn with(mut self, label: &str, dir: impl Into<PathBuf>) -> Self {
        self.drives.insert(label.to_string(), dir.into());
        self
    }
}

impl ConfigDriveProbe for FakeProbe {
    fn probe_and_mount(&self, labels: &[&str], _mountpoint: &Path) -> Result<Option<ConfigDrive>> {
        for label in labels {
            if let Some(dir) = self.drives.get(*label) {
                return Ok(Some(ConfigDrive {
                    label: (*label).to_string(),
                    dir: dir.clone(),
                }));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::single_device;

    #[test]
    fn a_single_labeled_device_is_selected() {
        let selected = single_device("AOS-META", ["", "/dev/sdb1", ""].into_iter());
        assert_eq!(selected.ok().flatten().as_deref(), Some("/dev/sdb1"));
    }

    #[test]
    fn an_absent_label_is_not_an_error() {
        assert_eq!(
            single_device("AOS-META", std::iter::empty()).ok(),
            Some(None)
        );
    }

    #[test]
    fn a_label_shared_by_several_devices_is_rejected() {
        let error = single_device("AOS-META", ["/dev/sdb1", "/dev/sdc1"].into_iter())
            .expect_err("ambiguous label must fail");
        assert!(error.to_string().contains("refusing to choose one"));
    }
}
