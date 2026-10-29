//! Resolution and safety checks for the disk an installation erases.
//!
//! The target comes only from the authorized `aos.provisioning.install`
//! projection. Before any byte is written it must resolve to a whole,
//! non-removable, unused disk that is not the installer media, carries no AOS
//! installation, and is large enough for the image plus every bounded
//! root-disk partition the first boot will create.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_boot_media::device::{self, INSTALLED_PARTITION_LABELS};
use aos_storage_layout::{CanonicalPartitionTarget, CanonicalProvisioningPlan};

/// GPT labels that mark durable AOS provisioning state.
const PROVENANCE_LABELS: [&str; 3] = [
    "aos-provisioning-pending-v1",
    "aos-provenance-operator-v1",
    "aos-provenance-fallback-v1",
];

/// Space reserved beyond the image and bounded partitions: GPT backup header,
/// the 1 MiB provenance marker, and partition alignment.
const LAYOUT_SLACK_BYTES: u64 = 16 * 1024 * 1024;

/// A validated installation target.
#[derive(Debug)]
pub struct Target {
    /// Stable path authorized by `host.nix`.
    pub stable_path: String,
    /// Canonical kernel device node.
    pub device: PathBuf,
    /// Sysfs directory of the disk.
    pub sysfs: PathBuf,
    /// Usable capacity in bytes.
    pub capacity: u64,
    /// Human-readable model string for console confirmation.
    pub model: String,
}

/// Resolves and checks the target named by an unattended install plan.
///
/// `media_disks` are the sysfs directories of every disk the installer media
/// occupies; the target must be none of them.
///
/// # Errors
///
/// Returns an error when the path does not resolve to a whole, non-removable,
/// unused disk outside the installer media, when the disk already carries AOS
/// partitions, or when it is too small for `required_bytes`.
pub fn resolve(stable_path: &str, media_disks: &[PathBuf], required_bytes: u64) -> Result<Target> {
    let device = fs::canonicalize(stable_path)
        .with_context(|| format!("install target {stable_path} is not present on this machine"))?;
    let sysfs = device::disk_of(&device)?;
    ensure!(
        !sysfs.join("partition").exists(),
        "install target {stable_path} is a partition, not a whole disk"
    );
    ensure!(
        !device::is_removable(&sysfs)?,
        "install target {stable_path} is removable media"
    );
    ensure!(
        !media_disks.contains(&sysfs),
        "install target {stable_path} is the installer media itself"
    );
    device::ensure_unused(&device)?;

    let labels = partition_labels(&sysfs)?;
    if let Some(label) = labels.iter().find(|label| {
        INSTALLED_PARTITION_LABELS.contains(&label.as_str())
            || PROVENANCE_LABELS.contains(&label.as_str())
    }) {
        bail!(
            "install target {stable_path} already carries an AOS partition ({label}); \
             wipe it explicitly before reinstalling"
        );
    }

    let capacity = aos_boot_media::block::capacity(&device)?;
    ensure!(
        capacity >= required_bytes,
        "install target {stable_path} holds {capacity} bytes, but the image and first-boot \
         partitions need at least {required_bytes}"
    );

    Ok(Target {
        stable_path: stable_path.to_owned(),
        model: read_attribute(&sysfs.join("device/model")).unwrap_or_default(),
        device,
        sysfs,
        capacity,
    })
}

/// Returns the minimum target capacity for an image and its storage plan.
///
/// Bounded root-disk partitions contribute their `sizeMin`; the single grow
/// partition, normally `var`, contributes its minimum as well.
///
/// # Errors
///
/// Returns an error for a size that is not a systemd-style byte count.
pub fn required_bytes(image_bytes: u64, plan: &CanonicalProvisioningPlan) -> Result<u64> {
    let mut total = image_bytes
        .checked_add(LAYOUT_SLACK_BYTES)
        .context("image size overflow")?;
    for (name, partition) in &plan.partitions {
        if partition.target != CanonicalPartitionTarget::RootDisk {
            continue;
        }
        let size = parse_size(&partition.size_min)
            .with_context(|| format!("partition {name} sizeMin"))?;
        total = total.checked_add(size).context("partition size overflow")?;
    }
    Ok(total)
}

/// Checks that every explicit secondary storage device in the plan is present.
///
/// # Errors
///
/// Returns an error naming the first absent device.
pub fn require_secondary_devices(plan: &CanonicalProvisioningPlan) -> Result<()> {
    for (name, partition) in &plan.partitions {
        if let CanonicalPartitionTarget::Device { path: device } = &partition.target {
            ensure!(
                Path::new(device).exists(),
                "partition {name} names {device}, which is not present on this machine"
            );
        }
    }
    Ok(())
}

/// Parses a systemd size string such as `512M` or `2G` into bytes.
///
/// Suffixes are binary (`K` = 1024), matching systemd-repart.
///
/// # Errors
///
/// Returns an error for an empty, malformed, or overflowing size.
pub fn parse_size(value: &str) -> Result<u64> {
    let digits = value.bytes().take_while(u8::is_ascii_digit).count();
    ensure!(digits > 0, "'{value}' does not start with a byte count");
    let (number, suffix) = value.split_at(digits);
    let number = number.parse::<u64>()?;
    let multiplier: u64 = match suffix {
        "" | "B" => 1,
        "K" => 1 << 10,
        "M" => 1 << 20,
        "G" => 1 << 30,
        "T" => 1 << 40,
        _ => bail!("'{value}' has an unsupported size suffix"),
    };
    number
        .checked_mul(multiplier)
        .with_context(|| format!("'{value}' overflows a byte count"))
}

fn partition_labels(disk: &Path) -> Result<Vec<String>> {
    let mut labels = Vec::new();
    for partition in device::partitions(disk)? {
        let uevent = fs::read_to_string(partition.join("uevent"))?;
        if let Some(label) = uevent
            .lines()
            .find_map(|line| line.strip_prefix("PARTNAME="))
        {
            labels.push(label.to_owned());
        }
    }
    Ok(labels)
}

fn read_attribute(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::parse_size;

    #[test]
    fn sizes_use_binary_suffixes() {
        assert_eq!(parse_size("512").ok(), Some(512));
        assert_eq!(parse_size("4K").ok(), Some(4096));
        assert_eq!(parse_size("2G").ok(), Some(2 << 30));
        assert_eq!(parse_size("1T").ok(), Some(1 << 40));
    }

    #[test]
    fn malformed_sizes_are_rejected() {
        for value in ["", "G", "2 G", "2g", "2GiB", "99999999999T"] {
            assert!(parse_size(value).is_err(), "{value} must be rejected");
        }
    }
}
