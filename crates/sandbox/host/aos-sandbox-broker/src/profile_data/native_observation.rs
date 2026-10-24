//! Mechanical cgroup-anchor DATA for existing closed role recipes.
//!
//! This shares mount opening and descendant resolution only. An anchor carries
//! native directory identity; it cannot construct a selected role, receiving
//! account, Root startup or semantic currentness. The caller owns its actual
//! fixed path, native purpose and complete role admission.

use std::path::Path;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use rustix::fs::{Mode, OFlags, open};
use super::ControllerProfileErrorV1 as NormalRootStartupErrorV1;

/// Resolves an actual native anchor without admitting any process or role.
///
/// # Errors
/// Preserves the existing fixed service classification on mount opening,
/// cgroup-root validation or strict descendant-resolution refusal.
pub fn retain_cgroup_anchor_data_v1(path: &Path)
    -> Result<RetainedCgroupAnchor, NormalRootStartupErrorV1>
{
    let root = CgroupV2Root::from_owned(
        open(
            "/sys/fs/cgroup",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| NormalRootStartupErrorV1::Service)?,
    )
    .map_err(|_| NormalRootStartupErrorV1::Service)?;
    root.resolve(path)
        .map_err(|_| NormalRootStartupErrorV1::Service)
}
