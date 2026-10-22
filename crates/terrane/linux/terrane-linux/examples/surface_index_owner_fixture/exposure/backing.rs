//! Compares durable original-inode obligations with actual disclosed descriptors.

use super::{Result, config, hex, snapshot};
use std::{fs::File, os::unix::fs::MetadataExt};
use terrane_linux::host_quota::NativeProject;
use terrane_sdk::host::cache::ExposureBackingKind;

pub(super) async fn check(
    file: &File,
    exposure: &str,
    kind: ExposureBackingKind,
    hash: &str,
    inputs: &config::Inputs,
) -> Result<()> {
    let state = snapshot(inputs).await?;
    let row = state
        .exposures
        .iter()
        .find(|row| row.id == exposure)
        .and_then(|row| {
            row.backings
                .iter()
                .find(|binding| binding.kind == kind && binding.hash == hash)
        })
        .ok_or("original descriptor was disclosed without its durable native binding")?;

    let actual = file.metadata()?;
    let project = NativeProject::inspect(file)?.project_id;
    let seal = terrane_linux::verity::measure(file)?;
    let owner = inputs.owner_config()?;
    let uid = match kind {
        ExposureBackingKind::Index => owner.content_uid,
        ExposureBackingKind::Inline | ExposureBackingKind::Manifest => {
            owner.publisher.identities.publish_uid
        }
    };
    if row.filesystem_uuid != hex(&inputs.uuid)
        || row.device != actual.dev()
        || row.inode != actual.ino()
        || row.project_id != project
        || project != inputs.project
        || row.uid != actual.uid()
        || row.uid != uid
        || row.gid != actual.gid()
        || row.gid != owner.content_gid
        || row.mode != (actual.mode() & 0o7777) as u16
        || row.size != actual.len()
        || row.allocated
            != actual
                .blocks()
                .checked_mul(512)
                .ok_or("allocation overflow")?
        || row.verity_algorithm != seal.algorithm
        || row.verity_digest != hex(&seal.digest)
    {
        return Err("durable exposure binding differs from the original native descriptor".into());
    }
    Ok(())
}
