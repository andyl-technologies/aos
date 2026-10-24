//! Queries the actual privileged helper for a still-retained original index.

use super::{Result, config};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
};
use terrane_linux::{
    host_cache::NativeExposureRootBacking,
    host_quota::{HostQuotaClient, ProjectInode, ProjectInodeBinding, ProjectInodeBirth},
};

pub(super) fn verify(grant: &NativeExposureRootBacking, inputs: &config::Inputs) -> Result<()> {
    let file = File::from(grant.as_fd().try_clone_to_owned()?);
    let metadata = file.metadata()?;
    let excluded = [ProjectInode {
        device: metadata.dev(),
        inode: metadata.ino(),
    }];
    let mut helper = HostQuotaClient::connect(&inputs.quota, 0, config::EPOCH)?;
    let observed = helper.query_project_census(&inputs.owner, &inputs.domain, &excluded)?;
    if observed.all_excluded_closed()
        || observed.quota().filesystem_uuid != inputs.uuid
        || observed.quota().project_id != inputs.project
        || observed.observation().excluded.len() != 1
        || observed.observation().excluded[0].device != metadata.dev()
        || observed.observation().excluded[0].inode != metadata.ino()
    {
        return Err("authenticated helper lost original retained-inode census context".into());
    }
    let birth = ProjectInodeBirth::observe(&file)?;
    let incarnations = [ProjectInodeBinding {
        identity: excluded[0],
        birth: Some(birth),
    }];
    let observation =
        helper.query_project_incarnation_census(&inputs.owner, &inputs.domain, &incarnations)?;
    let original = observation
        .observation()
        .excluded
        .first()
        .ok_or("missing incarnation echo")?;
    let echoed_birth = original
        .birth
        .as_ref()
        .ok_or("missing native creation timestamp echo")?;
    if observation.all_excluded_closed()
        || observation.observation().version != 3
        || original.device != metadata.dev()
        || original.inode != metadata.ino()
        || echoed_birth.seconds != birth.seconds
        || echoed_birth.nanoseconds != birth.nanoseconds
    {
        return Err("authenticated helper lost original retained incarnation".into());
    }
    if helper
        .query_project_incarnation_census(&inputs.owner, "tenant:unconfigured", &incarnations)
        .is_ok()
    {
        return Err("incarnation census accepted an unconfigured owner/domain pair".into());
    }
    if helper
        .query_project_census(&inputs.owner, "tenant:unconfigured", &excluded)
        .is_ok()
    {
        return Err("census helper accepted an unconfigured owner/domain pair".into());
    }
    Ok(())
}
