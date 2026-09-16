//! Platform identification and config-drive probing.
//!
//! Applies the DMI/SMBIOS asset-tag → vendor → BIOS → product decision order
//! over `std::fs` reads of `/sys/class/dmi/id/*`, and runs the config-drive
//! probe first so an offline
//! channel short-circuits the cloud path. The result remains inside the
//! package-owned provider until it is published as a typed operation result.
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

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::mount::{CONFIG_DRIVE_LABELS, ConfigDriveProbe, platform_for_label};

/// A metadata platform with one package-owned acquisition implementation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlatformId {
    /// The native AOS config-drive format.
    AosMetadata,
    /// The NoCloud config-drive format.
    Nocloud,
    /// The OpenStack config-drive format.
    ConfigDrive,
    /// QEMU firmware configuration.
    Qemu,
    /// Amazon EC2 instance metadata.
    Aws,
    /// Google Compute Engine instance metadata.
    Gcp,
    /// Microsoft Azure instance metadata.
    Azure,
    /// DigitalOcean instance metadata.
    Digitalocean,
    /// OpenStack instance metadata.
    Openstack,
    /// A physical system without a standard metadata transport.
    Metal,
    /// A Hyper-V guest without a standard metadata transport.
    Hyperv,
    /// A VMware guest without a standard metadata transport.
    Vmware,
    /// A VirtualBox guest without a standard metadata transport.
    Virtualbox,
}

impl PlatformId {
    /// Parses the canonical contract identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when no selected acquisition implementation owns the
    /// identifier.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "aos-metadata" => Ok(Self::AosMetadata),
            "nocloud" => Ok(Self::Nocloud),
            "config-drive" => Ok(Self::ConfigDrive),
            "qemu" => Ok(Self::Qemu),
            "aws" => Ok(Self::Aws),
            "gcp" => Ok(Self::Gcp),
            "azure" => Ok(Self::Azure),
            "digitalocean" => Ok(Self::Digitalocean),
            "openstack" => Ok(Self::Openstack),
            "metal" => Ok(Self::Metal),
            "hyperv" => Ok(Self::Hyperv),
            "vmware" => Ok(Self::Vmware),
            "virtualbox" => Ok(Self::Virtualbox),
            _ => bail!("unsupported metadata platform id {value:?}"),
        }
    }

    /// Returns the canonical contract identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AosMetadata => "aos-metadata",
            Self::Nocloud => "nocloud",
            Self::ConfigDrive => "config-drive",
            Self::Qemu => "qemu",
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
            Self::Digitalocean => "digitalocean",
            Self::Openstack => "openstack",
            Self::Metal => "metal",
            Self::Hyperv => "hyperv",
            Self::Vmware => "vmware",
            Self::Virtualbox => "virtualbox",
        }
    }

    /// Returns the acquisition capability selected for this platform.
    pub const fn capability(self) -> PlatformCapability {
        match self {
            Self::AosMetadata | Self::Nocloud | Self::ConfigDrive | Self::Qemu => {
                PlatformCapability::LocalMetadata
            }
            Self::Aws | Self::Gcp | Self::Azure | Self::Digitalocean | Self::Openstack => {
                PlatformCapability::NetworkMetadata
            }
            Self::Metal | Self::Hyperv | Self::Vmware | Self::Virtualbox => {
                PlatformCapability::NoMetadata
            }
        }
    }

    /// Returns the stable acquisition-source label used in run evidence.
    pub const fn user_data_source(self) -> &'static str {
        match self {
            Self::AosMetadata | Self::Nocloud | Self::ConfigDrive => "config-drive",
            Self::Qemu => "fw_cfg",
            _ => "imds",
        }
    }
}

/// Carries one detected platform and its private mounted media, if any.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionContext {
    /// The selected metadata platform.
    pub platform: PlatformId,
    /// The mounted offline acquisition directory.
    pub metadata_dir: Option<PathBuf>,
}

impl AcquisitionContext {
    /// Returns whether acquisition requires early network readiness.
    pub const fn needs_network(&self) -> bool {
        matches!(
            self.platform.capability(),
            PlatformCapability::NetworkMetadata
        )
    }
}

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
    PlatformId::parse(platform).ok().map(PlatformId::capability)
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

/// Runs the detection table and config-drive probe into an [`AcquisitionContext`].
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
) -> Result<AcquisitionContext> {
    // 1. Offline config-drive probe — short-circuits the cloud path.
    if let Some(drive) = probe.probe_and_mount(CONFIG_DRIVE_LABELS, media_mountpoint)? {
        let platform =
            PlatformId::parse(platform_for_label(&drive.label).unwrap_or("aos-metadata"))?;
        return Ok(AcquisitionContext {
            platform,
            metadata_dir: Some(drive.dir),
        });
    }

    // 2-3. DMI table.
    let sys_vendor = read_dmi(sysfs_root, "sys_vendor");
    let bios_vendor = read_dmi(sysfs_root, "bios_vendor");
    let product = read_dmi(sysfs_root, "product_name");
    let asset_tag = read_dmi(sysfs_root, "chassis_asset_tag");
    let platform = PlatformId::parse(&classify_dmi(
        &sys_vendor,
        &bios_vendor,
        &product,
        &asset_tag,
    ))?;

    Ok(AcquisitionContext {
        platform,
        metadata_dir: None,
    })
}
