//! Checks real whole-file backing selected through the original served index.

use super::{RepositoryFixture, Result};
use std::{
    fs::File,
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt},
    },
    time::UNIX_EPOCH,
};
use terrane_format::{
    identity::{Descriptor, IdentityKind, TERRANE_V1},
    surface::View,
};
use terrane_linux::host_cache::{NativeFileBacking, NativeMetadataOwner, NativeRootIndex};
use terrane_sdk::store::{Clock, TokioClock};

const BODY: &[u8] = b"signed surface source";

pub(super) fn deadline() -> Result<u64> {
    TokioClock
        .now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| "surface fixture deadline overflow".into())
}

pub(super) async fn admit(
    owner: &NativeMetadataOwner,
    served: &NativeRootIndex,
    fixture: &RepositoryFixture,
    view: &View,
) -> Result<NativeFileBacking> {
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, BODY)?;
    let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, BODY)?;
    let published = owner
        .publish_inline(descriptor, [vec![0], BODY.to_vec()].concat())
        .await?;
    let selection = fixture
        .repository
        .prepare_file_read(view, b"file", fixture.authority.token(), "sdk")
        .await?;
    let backing = owner
        .prepare_surface_file_backing(served, selection, deadline()?)
        .await?;
    let file = File::from(backing.as_fd().try_clone_to_owned()?);
    if file.metadata()?.ino() != published.handle().metadata()?.ino()
        || backing.commit() != served.commit()
        || backing.root() != served.key().root()
        || backing.lease().identity() != &identity
    {
        return Err("surface file lost original served selection or sealed inode".into());
    }
    check(&backing)?;
    drop(published);
    Ok(backing)
}

pub(super) fn check(backing: &NativeFileBacking) -> Result<()> {
    let file = File::from(backing.as_fd().try_clone_to_owned()?);
    let mut body = [0; BODY.len()];
    file.read_exact_at(&mut body, 0)?;
    if body != BODY || backing.size() != BODY.len() as u64 {
        return Err("surface backing lost actual selected file bytes".into());
    }
    Ok(())
}
