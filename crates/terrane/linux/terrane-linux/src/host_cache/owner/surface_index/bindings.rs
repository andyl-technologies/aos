//! Captures original sealed backing observations before exposure acknowledgment.

use super::{invalid, same_inode};
use crate::host_cache::owner::retention::Custody;
use crate::host_quota::NativeProject;
use std::{fs::File, io, os::unix::fs::MetadataExt};
use terrane_format::identity::Digest;
use terrane_sdk::host::cache::{ExposureBackingKind, ExposureBackingRecord};

/// Observes only a caller-retained original native source inside physical custody.
pub(in crate::host_cache::owner) fn capture(
    owner: &Custody,
    file: &File,
    kind: ExposureBackingKind,
    hash: &Digest,
) -> io::Result<ExposureBackingRecord> {
    let config = &owner.preparation.config;
    let metadata = file.metadata()?;
    let uid = match kind {
        ExposureBackingKind::Index => config.content_uid,
        ExposureBackingKind::Inline | ExposureBackingKind::Manifest => {
            config.publisher.identities.publish_uid
        }
    };
    if !metadata.is_file()
        || metadata.dev() != owner.preparation.layout().directory_binding("objects")?.0
        || metadata.uid() != uid
        || metadata.gid() != config.content_gid
        || metadata.mode() & 0o222 != 0
        || metadata.nlink() != 1
        || NativeProject::inspect(file)?.project_id != config.project_id
    {
        return Err(invalid("exposure backing lost original native custody"));
    }
    let binding = crate::verity::measure(file)?;
    let allocated = metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| invalid("exposure backing allocation overflow"))?;
    if !same_inode(&metadata, &file.metadata()?) {
        return Err(invalid(
            "exposure backing changed during original observation",
        ));
    }
    Ok(ExposureBackingRecord {
        kind,
        hash: super::state::hex(hash),
        filesystem_uuid: super::state::hex(&config.filesystem_uuid),
        device: metadata.dev(),
        inode: metadata.ino(),
        project_id: config.project_id,
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: (metadata.mode() & 0o7777) as u16,
        size: metadata.len(),
        allocated,
        verity_algorithm: binding.algorithm,
        verity_digest: super::state::hex(&binding.digest),
    })
}
