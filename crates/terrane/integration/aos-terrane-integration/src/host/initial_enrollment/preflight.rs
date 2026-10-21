//! Validates every genuine original creator before administrative creation effects.

use super::super::{HostConfig, parse_error};
use super::{model::RolePlan, plan};
use std::{
    collections::BTreeSet,
    io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
};
use terrane_format::gc::publication::BackendBinding;
use terrane_linux::host_quota::{NativeProject, filesystem_uuid, require_unused_project};
use terrane_sdk::bucket::enrollment::NativeInitialBucketEnrollment;

pub(super) fn check(
    config: &HostConfig,
    roles: &RolePlan,
    initial: &[NativeInitialBucketEnrollment],
) -> io::Result<()> {
    if initial.len() != config.owners.len() {
        return Err(io::Error::other(
            "original creator count differs from complete partition",
        ));
    }
    let mut roots = BTreeSet::new();
    let mut inodes = BTreeSet::new();
    for receipt in initial {
        receipt.verify_inline().map_err(parse_error)?;
        let owner = config
            .owners
            .iter()
            .find(|owner| plan::root(owner, "layout-root").is_ok_and(|root| root == receipt.root()))
            .ok_or_else(|| io::Error::other("original creator root is not configured"))?;
        let role = roles
            .owners
            .iter()
            .find(|role| role.owner_id == owner.owner_id && role.domain == owner.domain)
            .ok_or_else(|| io::Error::other("original creator has no explicit role policy"))?;
        if !roots.insert(receipt.root())
            || receipt.operator_uid() != 0
            || receipt.profile().identity != "terrane-v1"
            || receipt.profile().algorithm != "blake3"
            || receipt.profile().chunk != "cdc-1m"
            || receipt.profile().seed != role.chunk_seed
            || !receipt
                .control()
                .starts_with(plan::root(owner, "administrative-root")?)
        {
            return Err(io::Error::other(
                "original creator partition, profile or control scope mismatch",
            ));
        }
        let BackendBinding::Local {
            root,
            root_device,
            root_inode,
            coordination_device,
            coordination_inode,
        } = receipt.binding()
        else {
            return Err(io::Error::other(
                "initial enrollment requires a genuine local creator",
            ));
        };
        let root_observation = receipt
            .directories()
            .find(|entry| entry.path() == receipt.root())
            .ok_or_else(|| io::Error::other("original creator root observation is absent"))?;
        let uuid = filesystem_uuid(root_observation.descriptor())?;
        if root.as_slice() != receipt.root().as_os_str().as_bytes()
            || (*root_device, *root_inode)
                != (
                    root_observation.observed_metadata().dev(),
                    root_observation.observed_metadata().ino(),
                )
            || !receipt.files().any(|file| {
                (
                    file.observed_metadata().dev(),
                    file.observed_metadata().ino(),
                ) == (*coordination_device, *coordination_inode)
            })
        {
            return Err(io::Error::other(
                "original creator binding differs from its retained observations",
            ));
        }
        // Exact canonical genesis bytes remain owned by the genuine receipt;
        // successful encoding is checked before any registry or scaffold effect.
        receipt.genesis().encode().map_err(parse_error)?;
        for directory in receipt.directories() {
            let metadata = directory.observed_metadata();
            if metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || NativeProject::inspect(directory.descriptor())?.project_id != 0
                || filesystem_uuid(directory.descriptor())? != uuid
                || !inodes.insert((metadata.dev(), metadata.ino()))
            {
                return Err(io::Error::other(
                    "original directory lacks unassigned unique host custody",
                ));
            }
        }
        for file in receipt.files() {
            let metadata = file.observed_metadata();
            if metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || metadata.nlink() != 1
                || NativeProject::inspect(file.descriptor())?.project_id != 0
                || filesystem_uuid(file.descriptor())? != uuid
                || !inodes.insert((metadata.dev(), metadata.ino()))
            {
                return Err(io::Error::other(
                    "original file lacks unassigned unique host custody",
                ));
            }
        }
        // This checks only the exact explicit ancestor chain; it creates
        // nothing and rejects unrelated existing administrative descendants.
        for administrative in super::capture::administrative(owner, receipt.control())? {
            administrative.check()?;
        }
        require_unused_project(root_observation.descriptor(), owner.project_id)?;
        receipt.verify_inline().map_err(parse_error)?;
    }
    Ok(())
}
