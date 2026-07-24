//! The config-drive mount helper — the one capability with no aos primitive.
//!
//! Offline channels (the AOS `aos-metadata` ISO, NoCloud `cidata`, OpenStack
//! `config-2`) arrive as a labeled ISO9660/vfat block device. `detect` probes
//! the known labels, mounts the first hit read-only, and records its
//! mountpoint as `METADATA_DIR`; the matching [`PlatformFetcher`] then reads
//! files from that directory with no network.
//!
//! [`PlatformFetcher`]: crate::metadata::fetcher::PlatformFetcher
//!
//! The probe is behind the [`ConfigDriveProbe`] trait so tests never touch
//! `blkid`/`mount` or require root:
//!
//! - [`BlkidProbe`] — production. Shells out to the AOS-built
//!   `pkgs.util-linux` `blkid -L` and `mount -o ro`.
//! - [`FakeProbe`] — test double. Maps a label directly to a fixture
//!   directory, modelling an already-mounted drive.
//!
//! # Label → platform
//!
//! | Label          | `PLATFORM_ID`  |
//! |----------------|----------------|
//! | `aos-metadata` | `aos-metadata` |
//! | `cidata`       | `nocloud`      |
//! | `config-2`     | `config-drive` |

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// The labels probed for an offline config-drive, in priority order.
///
/// `aos-metadata` (the AOS-native channel) wins over the generic cloud-init
/// labels so an operator override short-circuits everything else.
pub const CONFIG_DRIVE_LABELS: &[&str] = &["aos-metadata", "cidata", "config-2"];

/// Map a filesystem label to the `PLATFORM_ID` its fetcher registers under.
///
/// Returns `None` for an unknown label.
pub fn platform_for_label(label: &str) -> Option<&'static str> {
    match label {
        "aos-metadata" => Some("aos-metadata"),
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
    /// The directory the fetcher reads files from (`METADATA_DIR`).
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
    fn probe_and_mount(
        &self,
        labels: &[&str],
        mountpoint: &Path,
    ) -> Result<Option<ConfigDrive>>;
}

/// Production probe: `blkid -L <label>` then `mount -o ro`.
///
/// `blkid` and `mount` are resolved from `PATH` (the initrd unit wires
/// `pkgs.util-linux` in); override the absolute paths with
/// [`BlkidProbe::with_tools`] when `PATH` is not set.
pub struct BlkidProbe {
    blkid: PathBuf,
    mount: PathBuf,
}

impl Default for BlkidProbe {
    fn default() -> Self {
        Self {
            blkid: PathBuf::from("blkid"),
            mount: PathBuf::from("mount"),
        }
    }
}

impl BlkidProbe {
    /// Use explicit absolute paths for `blkid` and `mount`.
    pub fn with_tools(blkid: impl Into<PathBuf>, mount: impl Into<PathBuf>) -> Self {
        Self {
            blkid: blkid.into(),
            mount: mount.into(),
        }
    }

    /// Resolve a label to a device node via `blkid -L`, or `None` if absent.
    fn device_for_label(&self, label: &str) -> Result<Option<String>> {
        let out = Command::new(&self.blkid)
            .arg("-L")
            .arg(label)
            .output()
            .with_context(|| format!("running {} -L {label}", self.blkid.display()))?;
        if !out.status.success() {
            // blkid exits non-zero when the label is absent — not an error.
            return Ok(None);
        }
        let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if dev.is_empty() {
            Ok(None)
        } else {
            Ok(Some(dev))
        }
    }
}

impl ConfigDriveProbe for BlkidProbe {
    fn probe_and_mount(
        &self,
        labels: &[&str],
        mountpoint: &Path,
    ) -> Result<Option<ConfigDrive>> {
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
    fn probe_and_mount(
        &self,
        labels: &[&str],
        _mountpoint: &Path,
    ) -> Result<Option<ConfigDrive>> {
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
