//! Traverses protected public-key paths and reads one checked native descriptor.

use std::{
    fs::{File, Metadata},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

use rustix::fs::{Mode, OFlags};

use super::IssuerKeyError;

const MAX_BYTES: u64 = 16 * 1024;

pub(super) fn validate_path(path: &Path) -> Result<(), IssuerKeyError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .skip(1)
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(IssuerKeyError::Invalid("invalid public issuer file path"));
    }
    Ok(())
}

pub(super) fn read(path: &Path, owner_uid: u32) -> Result<Vec<u8>, IssuerKeyError> {
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(
        rustix::fs::open("/", directory_flags, Mode::empty())
            .map_err(|error| IssuerKeyError::Io(error.into()))?,
    );
    check_directory(&directory, owner_uid)?;
    let mut parts = path.components().skip(1).peekable();
    while let Some(part) = parts.next() {
        let Component::Normal(name) = part else {
            return Err(IssuerKeyError::Invalid("invalid public issuer file path"));
        };
        if parts.peek().is_some() {
            directory = File::from(
                rustix::fs::openat(&directory, name, directory_flags, Mode::empty())
                    .map_err(|error| IssuerKeyError::Io(error.into()))?,
            );
            check_directory(&directory, owner_uid)?;
            continue;
        }

        // NONBLOCK prevents a substituted FIFO from delaying fstat. No file
        // contents are read until the actual descriptor passes every check.
        let descriptor = rustix::fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| IssuerKeyError::Io(error.into()))?;
        return read_checked(File::from(descriptor), owner_uid);
    }
    Err(IssuerKeyError::Invalid("missing public issuer file name"))
}

fn check_directory(directory: &File, owner_uid: u32) -> Result<(), IssuerKeyError> {
    let metadata = directory.metadata().map_err(IssuerKeyError::Io)?;
    if !metadata.is_dir() || !trusted_owner(&metadata, owner_uid) || metadata.mode() & 0o022 != 0 {
        return Err(IssuerKeyError::Invalid("unsafe public issuer directory"));
    }
    Ok(())
}

fn read_checked(mut file: File, owner_uid: u32) -> Result<Vec<u8>, IssuerKeyError> {
    let before = file.metadata().map_err(IssuerKeyError::Io)?;
    if !before.is_file()
        || !trusted_owner(&before, owner_uid)
        || before.nlink() != 1
        || !matches!(
            before.mode() & 0o7777,
            0o400 | 0o440 | 0o444 | 0o600 | 0o640 | 0o644
        )
        || before.len() == 0
        || before.len() > MAX_BYTES
    {
        return Err(IssuerKeyError::Invalid("unsafe public issuer file"));
    }

    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(IssuerKeyError::Io)?;
    let after = file.metadata().map_err(IssuerKeyError::Io)?;
    if bytes.len() as u64 != before.len() || !same_observation(&before, &after) {
        return Err(IssuerKeyError::Invalid(
            "public issuer file changed while reading",
        ));
    }
    Ok(bytes)
}

fn trusted_owner(metadata: &Metadata, owner_uid: u32) -> bool {
    metadata.uid() == 0 || metadata.uid() == owner_uid
}

fn same_observation(before: &Metadata, after: &Metadata) -> bool {
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
