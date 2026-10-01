//! Bounded private canonical documents, published without following or replacing links.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path};

use anyhow::{ensure, Context, Result};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
use std::os::fd::OwnedFd;

use super::MAX_DOCUMENT_BYTES;

fn inspect_directory(fd: &OwnedFd, private: bool) -> Result<()> {
    let stat = rustix::fs::fstat(fd)?;
    let mode = stat.st_mode;
    let owner = stat.st_uid == 0 || stat.st_uid == rustix::process::geteuid().as_raw();
    let root_sticky = stat.st_uid == 0 && mode & 0o1000 != 0;
    ensure!(
        FileType::from_raw_mode(mode) == FileType::Directory
            && owner
            && (mode & 0o022 == 0 || (!private && root_sticky))
            && (!private || mode & 0o077 == 0),
        "operator directory custody is invalid (owner {}, mode {:o}, private {})",
        stat.st_uid, mode & 0o7777, private
    );
    Ok(())
}

fn parent(path: &Path) -> Result<(OwnedFd, &std::ffi::OsStr)> {
    let name = path
        .file_name()
        .context("operator output filename absent")?;
    ensure!(name != "." && name != "..", "operator filename invalid");
    let directory = path.parent().context("operator parent absent")?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = rustix::fs::open(
        if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        },
        flags,
        Mode::empty(),
    )?;
    inspect_directory(&fd, false)?;
    for component in directory.components() {
        let Component::Normal(name) = component else {
            ensure!(
                matches!(component, Component::RootDir | Component::CurDir),
                "operator path cannot contain parent traversal"
            );
            continue;
        };
        fd = rustix::fs::openat(&fd, name, flags, Mode::empty())?;
        inspect_directory(&fd, false)?;
    }
    inspect_directory(&fd, true)?;
    Ok((fd, name))
}

fn write_file(directory: &OwnedFd, name: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_DOCUMENT_BYTES,
        "operator document exceeds bound"
    );
    let fd = rustix::fs::openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn publish_directory(path: &Path, documents: &[(&str, Vec<u8>)]) -> Result<()> {
    ensure!(
        !documents.is_empty() && documents.len() <= 2,
        "operator document set invalid"
    );
    for (name, bytes) in documents {
        ensure!(
            !name.contains('/') && bytes.len() <= MAX_DOCUMENT_BYTES,
            "operator document exceeds bound"
        );
    }
    let (parent, name) = parent(path)?;
    let temporary = format!(".operator-bootstrap-{}.partial", uuid::Uuid::new_v4());
    rustix::fs::mkdirat(&parent, &temporary, Mode::RUSR | Mode::WUSR | Mode::XUSR)?;
    let directory = rustix::fs::openat(
        &parent,
        &temporary,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    inspect_directory(&directory, true)?;
    for (filename, bytes) in documents {
        write_file(&directory, filename, bytes)?;
    }
    rustix::fs::fsync(&directory)?;
    // A failed attempt retains its private partial directory for inspection.
    // The final name is published only after every bounded document is durable.
    rustix::fs::renameat_with(&parent, &temporary, &parent, name, RenameFlags::NOREPLACE)?;
    rustix::fs::fsync(&parent)?;
    Ok(())
}

pub(super) fn read_file(path: &Path) -> Result<Vec<u8>> {
    let (parent, name) = parent(path)?;
    let fd = rustix::fs::openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let before = rustix::fs::fstat(&fd)?;
    ensure!(
        FileType::from_raw_mode(before.st_mode) == FileType::RegularFile
            && before.st_mode & 0o077 == 0
            && before.st_nlink == 1
            && (before.st_uid == 0 || before.st_uid == rustix::process::geteuid().as_raw())
            && before.st_size >= 0
            && before.st_size as u64 <= MAX_DOCUMENT_BYTES as u64,
        "operator input custody or size is invalid"
    );
    let mut file = File::from(fd);
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((MAX_DOCUMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let after = rustix::fs::fstat(&file)?;
    let current = rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    ensure!(
        bytes.len() <= MAX_DOCUMENT_BYTES
            && bytes.len() as u64 == before.st_size as u64
            && before.st_dev == current.st_dev
            && before.st_ino == current.st_ino
            && before.st_size == after.st_size
            && before.st_mtime == after.st_mtime
            && before.st_mtime_nsec == after.st_mtime_nsec,
        "operator input changed during bounded read"
    );
    Ok(bytes)
}
