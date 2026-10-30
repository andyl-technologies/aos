//! The evaluated `aos.provisioning.install` projection.
//!
//! An installer boot evaluates the same authorized `host.nix` fixed point as a
//! normal first boot and projects this subtree alongside the storage plan. It
//! states whether the boot media may write the release image without operator
//! interaction, and onto which disk. A normal first boot ignores it.
//!
//! The projection arrives from Nix in camel case:
//!
//! ```text
//! { "mode": "unattended", "targetDevice": "/dev/disk/by-id/nvme-..." }
//! ```

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::ProvisioningPlan;

/// Prefix every installation target must carry.
///
/// Kernel names such as `/dev/sda` are assigned in probe order and can name a
/// different disk on the next boot, so they never authorize an erase.
pub const STABLE_DISK_PREFIX: &str = "/dev/disk/by-id/";

/// Whether, and how, boot media may install the release image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstallMode {
    /// The media never writes a disk.
    Disabled,
    /// The media erases `targetDevice` and installs after a console countdown.
    Unattended,
}

/// Evaluated installation intent from `aos.provisioning.install`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InstallPlan {
    /// Installation mode.
    pub mode: InstallMode,
    /// Whole disk that receives the image, as a stable `/dev/disk/by-id` path.
    pub target_device: Option<String>,
}

/// Validates installation intent against the storage plan it will provision.
///
/// The target becomes the root disk, so storage partitions must address it as
/// the implicit root disk rather than by its explicit path.
///
/// # Errors
///
/// Returns an error for invalid intent (see [`validate_install_intent`]) or a
/// storage partition that names the target explicitly.
pub fn validate_install_plan(install: &InstallPlan, storage: &ProvisioningPlan) -> Result<()> {
    let Some(target) = validate_install_intent(install)? else {
        return Ok(());
    };
    for (logical, partition) in &storage.storage.partitions {
        if partition.device.as_deref() == Some(target) {
            bail!(
                "partition '{logical}' names the install target explicitly; \
                 omit its device to place it on the root disk"
            );
        }
    }
    Ok(())
}

/// Validates installation intent on its own and returns the unattended target.
///
/// Returns `None` for a disabled plan.
///
/// # Errors
///
/// Returns an error when unattended mode lacks a target, the target is not a
/// normalized `/dev/disk/by-id` path naming a whole disk, or a disabled plan
/// names a target.
pub fn validate_install_intent(install: &InstallPlan) -> Result<Option<&str>> {
    let target = match (install.mode, install.target_device.as_deref()) {
        (InstallMode::Disabled, None) => return Ok(None),
        (InstallMode::Disabled, Some(_)) => {
            bail!("aos.provisioning.install.targetDevice requires mode = \"unattended\"")
        }
        (InstallMode::Unattended, None) => {
            bail!("unattended installation requires aos.provisioning.install.targetDevice")
        }
        (InstallMode::Unattended, Some(target)) => target,
    };

    let Some(name) = target.strip_prefix(STABLE_DISK_PREFIX) else {
        bail!("install target '{target}' must be a {STABLE_DISK_PREFIX} path");
    };
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        bail!("install target '{target}' must name one entry beneath {STABLE_DISK_PREFIX}");
    }
    // udev names partitions of a by-id disk with a `-partN` suffix.
    if let Some((_, suffix)) = name.rsplit_once("-part")
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("install target '{target}' names a partition, not a whole disk");
    }
    Ok(Some(target))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::{InstallMode, InstallPlan, validate_install_plan};
    use crate::{ProvisioningPlan, StoragePlan};

    const TARGET: &str = "/dev/disk/by-id/nvme-Example_SSD_123";

    fn storage() -> ProvisioningPlan {
        ProvisioningPlan {
            schema: "aos.provisioning-plan/v1".into(),
            storage: StoragePlan {
                partitions: BTreeMap::new(),
                arrays: BTreeMap::new(),
            },
        }
    }

    fn plan(mode: InstallMode, target: Option<&str>) -> InstallPlan {
        InstallPlan {
            mode,
            target_device: target.map(str::to_owned),
        }
    }

    #[test]
    fn disabled_without_target_and_unattended_with_stable_disk_are_accepted() {
        assert!(validate_install_plan(&plan(InstallMode::Disabled, None), &storage()).is_ok());
        assert!(
            validate_install_plan(&plan(InstallMode::Unattended, Some(TARGET)), &storage()).is_ok()
        );
    }

    #[test]
    fn unstable_partition_or_missing_targets_are_rejected() {
        for target in [
            None,
            Some("/dev/sda"),
            Some("/dev/disk/by-id/"),
            Some("/dev/disk/by-id/../sda"),
            Some("/dev/disk/by-id/nvme-Example_SSD_123-part1"),
        ] {
            assert!(
                validate_install_plan(&plan(InstallMode::Unattended, target), &storage()).is_err(),
                "{target:?} must be rejected"
            );
        }
        assert!(
            validate_install_plan(&plan(InstallMode::Disabled, Some(TARGET)), &storage()).is_err()
        );
    }

    #[test]
    fn deserializes_the_nix_projection() {
        let value = serde_json::json!({"mode": "unattended", "targetDevice": TARGET});
        let parsed: InstallPlan = serde_json::from_value(value).expect("projection parses");
        assert_eq!(parsed, plan(InstallMode::Unattended, Some(TARGET)));
    }
}
