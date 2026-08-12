//! `aos metadata detect` — platform identification + config-drive probe.
//!
//! Applies the DMI/SMBIOS asset-tag → vendor → BIOS → product decision order
//! over `std::fs` reads of `/sys/class/dmi/id/*`, and runs the config-drive
//! probe first so an offline
//! channel short-circuits the cloud path. The result is written to
//! `/run/aos-metadata/platform.env` as `PLATFORM_ID` (+ `METADATA_DIR` for
//! offline channels, + `NEED_NETWORK` for cloud platforms).
//!
//! Detection order:
//!
//! 1. **Config-drive probe** — `blkid -L {aos-metadata,cidata,config-2}`; a hit
//!    mounts RO and short-circuits with `METADATA_DIR` set and no network.
//! 2. **Asset tag** — Azure writes a fixed chassis asset tag.
//! 3. **`sys_vendor`** — the bulk of cloud platforms.
//! 4. **`bios_vendor`** — AWS Nitro bare-metal.
//! 5. **`product_name`** — GCP and generic QEMU.
//! 6. **Fallback** — `metal`.

use std::path::{Path, PathBuf};

use anyhow::Result;

use super::mount::{CONFIG_DRIVE_LABELS, ConfigDriveProbe, platform_for_label};
use super::stash::{PlatformEnv, Stash};

/// Metadata acquisition capability associated with a detected platform.
///
/// Detection only returns identifiers represented here. Vendors without a
/// native, recorded fetch contract deliberately classify as `metal` rather
/// than advertising a platform that will fail later in the initrd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformCapability {
    /// Metadata is available from a local config drive or firmware channel.
    LocalMetadata,
    /// Metadata requires stage-1 networking.
    NetworkMetadata,
    /// No standardized metadata channel is available.
    NoMetadata,
}

/// Return the acquisition capability for a supported platform identifier.
pub fn platform_capability(platform: &str) -> Option<PlatformCapability> {
    match platform {
        "aos-metadata" | "nocloud" | "config-drive" | "qemu" => {
            Some(PlatformCapability::LocalMetadata)
        }
        "aws" | "gcp" | "azure" | "digitalocean" | "openstack" => {
            Some(PlatformCapability::NetworkMetadata)
        }
        "metal" | "hyperv" | "vmware" | "virtualbox" => Some(PlatformCapability::NoMetadata),
        _ => None,
    }
}

/// Read a `/sys/class/dmi/id/<key>` value, trimmed, or `""` when absent.
fn read_dmi(sysfs_root: &Path, key: &str) -> String {
    let path = sysfs_root.join("sys/class/dmi/id").join(key);
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Decide the `PLATFORM_ID` from DMI strings, porting the Nix decision table
/// verbatim.
///
/// Pure over its inputs (no I/O), so it is exhaustively table-tested. Returns
/// the platform id; never empty (falls back to `"metal"`).
pub fn classify_dmi(sys_vendor: &str, bios_vendor: &str, product: &str, asset_tag: &str) -> String {
    // 2a. Asset tag — Azure.
    let platform = match asset_tag {
        "7783-7084-3265-9085-8269-3286-77" => Some("azure"),
        _ => None,
    };

    // 2b. sys_vendor — the bulk of cloud platforms.
    let platform = platform.or_else(|| match sys_vendor {
        "Amazon EC2" => Some("aws"),
        "Google" => Some("gcp"),
        "Microsoft Corporation" if product == "Virtual Machine" => Some("hyperv"),
        "DigitalOcean" => Some("digitalocean"),
        "OpenStack Foundation" => Some("openstack"),
        "VMware, Inc." => Some("vmware"),
        "innotek GmbH" => Some("virtualbox"),
        "QEMU" => Some("qemu"),
        _ => None,
    });

    // 2c. bios_vendor — AWS Nitro bare-metal.
    let platform = platform.or(match bios_vendor {
        "Amazon EC2" => Some("aws"),
        _ => None,
    });

    // 2d. product_name — GCP and generic QEMU.
    let platform = platform.or_else(|| {
        if product == "Google Compute Engine" {
            Some("gcp")
        } else if product.starts_with("Standard PC") {
            Some("qemu")
        } else {
            None
        }
    });

    // 3. Fallback — bare metal.
    platform.unwrap_or("metal").to_string()
}

/// Whether `platform` needs the initrd network gate raised.
pub fn needs_network(platform: &str) -> bool {
    platform_capability(platform) == Some(PlatformCapability::NetworkMetadata)
}

/// Options for [`run_detect`].
pub struct DetectOptions {
    /// Filesystem root for `/sys` reads (default `/`; a tempdir in tests).
    pub sysfs_root: PathBuf,
    /// The stash directory to write `platform.env` into.
    pub stash_dir: PathBuf,
    /// Mountpoint for an offline config-drive hit.
    pub media_mountpoint: PathBuf,
}

impl Default for DetectOptions {
    fn default() -> Self {
        Self {
            sysfs_root: PathBuf::from("/"),
            stash_dir: PathBuf::from(super::stash::DEFAULT_STASH_DIR),
            media_mountpoint: PathBuf::from(super::stash::DEFAULT_MEDIA_DIR),
        }
    }
}

/// Run the detection table + config-drive probe and produce a [`PlatformEnv`].
///
/// Pure except for the DMI sysfs reads and the injected `probe`; does not write
/// anything, so it is testable with a fake sysfs root and a [`super::mount::FakeProbe`].
///
/// # Errors
///
/// Returns `Err` only when the config-drive probe fails to mount a found
/// device.
pub fn detect(
    sysfs_root: &Path,
    probe: &dyn ConfigDriveProbe,
    media_mountpoint: &Path,
) -> Result<PlatformEnv> {
    // 1. Offline config-drive probe — short-circuits the cloud path.
    if let Some(drive) = probe.probe_and_mount(CONFIG_DRIVE_LABELS, media_mountpoint)? {
        let platform_id = platform_for_label(&drive.label)
            .unwrap_or("aos-metadata")
            .to_string();
        return Ok(PlatformEnv {
            platform_id,
            metadata_dir: Some(drive.dir.display().to_string()),
            need_network: false,
        });
    }

    // 2-3. DMI table.
    let sys_vendor = read_dmi(sysfs_root, "sys_vendor");
    let bios_vendor = read_dmi(sysfs_root, "bios_vendor");
    let product = read_dmi(sysfs_root, "product_name");
    let asset_tag = read_dmi(sysfs_root, "chassis_asset_tag");
    let platform_id = classify_dmi(&sys_vendor, &bios_vendor, &product, &asset_tag);
    let need_network = needs_network(&platform_id);

    Ok(PlatformEnv {
        platform_id,
        metadata_dir: None,
        need_network,
    })
}

/// Run `aos metadata detect`: probe, classify, and write `platform.env`.
///
/// # Errors
///
/// Returns `Err` on probe/mount failure or any write failure.
pub fn run_detect(opts: &DetectOptions, probe: &dyn ConfigDriveProbe) -> Result<()> {
    let env = detect(&opts.sysfs_root, probe, &opts.media_mountpoint)?;
    let stash = Stash::open(&opts.stash_dir)?;
    stash.write_platform_env(&env)?;
    Ok(())
}
