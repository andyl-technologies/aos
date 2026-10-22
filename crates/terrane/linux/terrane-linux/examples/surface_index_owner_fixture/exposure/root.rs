//! Checks original-inode scoped index grants and retained readable mappings.

use super::{Result, config, hex};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
};
use terrane_linux::{host_cache::NativeExposureRootBacking, structural_index::MappedIndex};

pub(super) async fn check(
    grant: &NativeExposureRootBacking,
    inputs: &config::Inputs,
) -> Result<()> {
    let key = grant.exposure().key();
    let file = File::from(grant.as_fd().try_clone_to_owned()?);
    let canonical = inputs.root.join("objects").join(format!(
        ".terrane-surface:{}:{}",
        key.version(),
        hex(&key.root())
    ));
    let original = std::fs::metadata(canonical)?;
    let actual = file.metadata()?;
    if (actual.dev(), actual.ino()) != (original.dev(), original.ino())
        || rustix::fs::fcntl_getfl(&file)? & rustix::fs::OFlags::ACCMODE
            != rustix::fs::OFlags::RDONLY
    {
        return Err("scoped root grant lost the original read-only index inode".into());
    }
    let seal = terrane_linux::verity::measure(&file)?;
    super::backing::check(
        &file,
        grant.exposure().id(),
        terrane_sdk::host::cache::ExposureBackingKind::Index,
        &hex(&key.root()),
        inputs,
    )
    .await?;
    let maximum = usize::try_from(actual.len())?;
    let mapped = MappedIndex::open(file.into(), key.root(), &seal, maximum)?;
    if mapped.index().root_hash() != key.root() || mapped.index().lookup(b"file").is_none() {
        return Err("scoped root grant lost its actual checked mapped metadata".into());
    }
    Ok(())
}
