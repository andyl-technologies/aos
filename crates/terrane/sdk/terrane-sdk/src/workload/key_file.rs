//! Loads bounded native signing seeds from independently checked descriptors.

use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

use rustix::fs::{Mode, OFlags};
use zeroize::Zeroizing;

use super::MintError;

pub(super) fn read(path: &Path, owner_uid: u32) -> Result<Zeroizing<[u8; 32]>, MintError> {
    if !path.is_absolute()
        || path
            .components()
            .skip(1)
            .any(|part| !matches!(part, Component::Normal(_)))
        || path.file_name().is_none()
    {
        return Err(MintError::Key);
    }
    // NONBLOCK prevents an attacker-controlled FIFO from blocking startup before
    // fstat can reject its actual inode kind. No key bytes are read before fstat.
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| MintError::Io(error.into()))?;
    let mut file = File::from(descriptor);
    let before = file.metadata().map_err(MintError::Io)?;
    if !before.is_file()
        || before.uid() != owner_uid
        || before.nlink() != 1
        || !matches!(before.mode() & 0o7777, 0o400 | 0o600)
        || before.len() != 32
    {
        return Err(MintError::Key);
    }

    let mut bytes = Zeroizing::new(Vec::with_capacity(33));
    (&mut file)
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(MintError::Io)?;
    let after = file.metadata().map_err(MintError::Io)?;
    if bytes.len() != 32 || !same_observation(&before, &after) {
        return Err(MintError::Key);
    }

    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn same_observation(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}
