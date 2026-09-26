//! Audited `posix_spawn` boundary for the namespace helper.
//!
//! The broker never runs Rust after `fork` in a copied process. It duplicates
//! every source descriptor above the child role range, asks libc's
//! `posix_spawn` file-action engine to map only exact fixed roles, closes all
//! descriptors above the role table, and supplies an empty environment.

use std::collections::BTreeSet;
use std::os::fd::BorrowedFd;
use std::path::Path;

use aos_sandbox_linux::fixed_spawn::{
    FixedDescriptorMappingV1, FixedDescriptorSpawnRequestV1, spawn_fixed_descriptor_process,
};

use crate::{MountError, Result};

/// Fixed child descriptor carrying the sealed helper plan.
pub const PLAN_FD: i32 = 3;
/// Optional fixed child descriptor carrying a detached mount.
pub const DETACHED_MOUNT_FD: i32 = 4;
/// Fixed child descriptor carrying the mount namespace.
pub const MOUNT_NAMESPACE_FD: i32 = 5;
/// Fixed child descriptor carrying the target root.
pub const TARGET_ROOT_FD: i32 = 6;
/// Fixed child descriptor carrying the protected broker underlay slot.
pub const TARGET_SLOT_FD: i32 = 7;
/// Fixed child descriptor carrying the payload attachment anchor.
pub const ATTACHMENT_ANCHOR_FD: i32 = 8;
/// Fixed child descriptor carrying its bounded kernel observation report.
pub const OBSERVATION_FD: i32 = 9;

const FIRST_ROLE_FD: i32 = PLAN_FD;
const LAST_ROLE_FD: i32 = OBSERVATION_FD;

/// Maps one broker-owned descriptor to a fixed helper role.
#[derive(Clone, Copy, Debug)]
pub struct DescriptorMapping<'a> {
    /// Fixed child descriptor number from the constants in this module.
    pub target: i32,
    /// Typed broker-side descriptor borrowed through `posix_spawn`.
    pub source: BorrowedFd<'a>,
}

/// Spawns and synchronously waits for one fixed helper invocation.
///
/// The executable path must be an absolute Nix-store path selected by the
/// system module. Standard input/output/error are inherited for service-log
/// integration; descriptors 3 through 9 exactly match `mappings`; everything
/// above 9 is closed in the child; and the child environment is empty.
///
/// # Errors
///
/// Returns an error for an unsafe executable path, duplicate/unknown/missing
/// mandatory descriptor roles, descriptor duplication, libc spawn setup,
/// launch, wait failure, signal death, or a nonzero helper exit status.
pub fn run_helper(executable: &Path, mappings: &[DescriptorMapping<'_>]) -> Result<()> {
    let status = run_helper_status(executable, mappings)?;
    if status == 0 {
        Ok(())
    } else {
        Err(MountError::Worker(format!(
            "mount helper exited with status {status}"
        )))
    }
}

/// Spawns one helper and returns its normal exit status.
///
/// This variant lets the observation operation reserve status `3` for an
/// absent exact mount. Signals and all launch/wait failures remain errors.
///
/// # Errors
///
/// Returns the same setup, spawn, wait, and signal errors as [`run_helper`].
pub fn run_helper_status(executable: &Path, mappings: &[DescriptorMapping<'_>]) -> Result<i32> {
    validate(executable, mappings)?;
    let mappings = mappings
        .iter()
        .map(|mapping| FixedDescriptorMappingV1::new(mapping.target, mapping.source))
        .collect::<Vec<_>>();
    let mandatory = [
        PLAN_FD,
        MOUNT_NAMESPACE_FD,
        TARGET_ROOT_FD,
        TARGET_SLOT_FD,
        ATTACHMENT_ANCHOR_FD,
        OBSERVATION_FD,
    ];
    let request = FixedDescriptorSpawnRequestV1::new(
        executable,
        FIRST_ROLE_FD,
        LAST_ROLE_FD,
        &mandatory,
        &mappings,
    )
    .map_err(linux_error)?;
    spawn_fixed_descriptor_process(request).map_err(linux_error)
}

fn validate(executable: &Path, mappings: &[DescriptorMapping<'_>]) -> Result<()> {
    let path = executable.as_os_str().as_encoded_bytes();
    if path.is_empty()
        || path.len() > 4096
        || !executable.is_absolute()
        || path.contains(&0)
        || executable
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(MountError::Worker(
            "mount helper executable path is unsafe".to_owned(),
        ));
    }
    let mut targets = BTreeSet::new();
    for mapping in mappings {
        if !(FIRST_ROLE_FD..=LAST_ROLE_FD).contains(&mapping.target)
            || !targets.insert(mapping.target)
        {
            return Err(MountError::Worker(
                "mount helper descriptor role table is invalid".to_owned(),
            ));
        }
    }
    for mandatory in [
        PLAN_FD,
        MOUNT_NAMESPACE_FD,
        TARGET_ROOT_FD,
        TARGET_SLOT_FD,
        ATTACHMENT_ANCHOR_FD,
        OBSERVATION_FD,
    ] {
        if !targets.contains(&mandatory) {
            return Err(MountError::Worker(
                "mount helper descriptor role table is incomplete".to_owned(),
            ));
        }
    }
    Ok(())
}

fn linux_error(error: aos_sandbox_linux::Error) -> MountError {
    MountError::Worker(error.to_string())
}
