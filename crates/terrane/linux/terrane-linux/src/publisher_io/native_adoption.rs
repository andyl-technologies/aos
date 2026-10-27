//! Opens untrusted canonical candidates and finalizes independently verified adoption.
//!
//! Opening grants no content or seal authority and performs no mutation. The
//! publication engine verifies the kernel seal, plaintext and existing binding
//! before calling the finalizer. This keeps failed rollback opens from changing
//! replacement inodes and lets actual adoption quarantine unsealed or short data.

use super::{compare_inode, invalid};
use rustix::fs::{self, Mode, OFlags};
use std::{
    fs::{File, Metadata},
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

/// Opens an owned regular candidate read-only without trusting its bytes or seal.
///
/// # Errors
/// Refuses symlinks, special files, another owner/device, failed retained-descriptor
/// reopening and actual filesystem errors. File mode and length remain adoption work.
pub(super) fn open_candidate(parent: &File, name: &str, root: &File) -> io::Result<File> {
    let retained = File::from(fs::openat(
        parent,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    check_owned(&retained, root)?;
    // Procfs names only this retained regular inode. No device or FIFO is opened.
    let file = File::from(fs::open(
        format!("/proc/self/fd/{}", retained.as_raw_fd()),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    compare_inode(&retained, &file)?;
    check_owned(&file, root)?;
    Ok(file)
}

/// Installs final read-only mode and synchronizes an already verified adopted inode.
///
/// This is called after independent seal/plaintext/binding verification, before
/// durable binding acknowledgement or any returned publication receipt.
///
/// # Errors
/// Refuses another owner/device, a writable descriptor, failed final permissions,
/// changed retained identity or actual inode synchronization errors.
pub(super) fn synchronize_verified(file: &File, root: &File) -> io::Result<()> {
    let before = check_owned(file, root)?;
    let flags = fs::fcntl_getfl(file)?;
    if flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH) {
        return Err(invalid(
            "adoption synchronization requires a read-only descriptor",
        ));
    }
    if before.mode() & 0o7777 != 0o400 {
        fs::fchmod(file, Mode::from_raw_mode(0o400))?;
    }
    let after = check_owned(file, root)?;
    if (
        before.dev(),
        before.ino(),
        before.gid(),
        before.len(),
        before.nlink(),
    ) != (
        after.dev(),
        after.ino(),
        after.gid(),
        after.len(),
        after.nlink(),
    ) || after.mode() & 0o7777 != 0o400
    {
        return Err(invalid(
            "verified adopted inode changed during finalization",
        ));
    }
    file.sync_all()
}

fn check_owned(file: &File, root: &File) -> io::Result<Metadata> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.dev() != root.metadata()?.dev()
    {
        return Err(invalid("unsafe canonical publisher inode"));
    }
    Ok(metadata)
}
