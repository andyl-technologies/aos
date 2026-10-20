//! Applies fixed checkout metadata through the retained filesystem executor.
//!
//! This private operation changes only an already-created inode's presentation
//! metadata (TREE-9/10). It carries no storage publication or ref authority:
//!
//! ```text
//! created inode observation -> fixed request -> owned worker -> sync -> receipt
//! ```

use std::{
    ffi::OsString,
    fs::{File, Metadata},
    io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
};

use super::{NativeEffectFailure, NativeFsEffect, Plan};

/// Holds the exact created inode and requested presentation metadata.
pub(super) struct Request {
    path: PathBuf,
    expected: Metadata,
    mode: Option<u16>,
    uid: Option<u32>,
    gid: Option<u32>,
    completed: mpsc::Sender<()>,
}

/// Requires acknowledgment from actual native metadata synchronization.
pub(crate) struct Receipt {
    completed: mpsc::Receiver<()>,
}

impl Receipt {
    /// Consumes a completed worker's acknowledgment without accepting a callback.
    ///
    /// # Errors
    /// Returns `Unsupported` if a binding returned without executing the effect.
    pub(crate) fn take(self) -> io::Result<()> {
        self.completed.try_recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "checkout metadata was not synchronized",
            )
        })
    }
}

/// Fixes metadata for a repository-created file, directory or symbolic link.
///
/// The caller captures `expected` immediately after creation. Timestamps are
/// always the canonical epoch, rather than caller-controlled extraction times.
/// Hard-link counts and directory timestamps may change before finalization.
///
/// # Errors
/// Rejects noncanonical absolute paths, unsupported inode kinds, symlink modes
/// and bits outside the POSIX permission mask. Performs no filesystem I/O.
pub(crate) fn effect(
    path: &Path,
    expected: Metadata,
    mode: Option<u16>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> io::Result<(NativeFsEffect, Receipt)> {
    let bytes = path.as_os_str().as_bytes();
    let canonical = bytes.starts_with(b"/")
        && bytes.len() > 1
        && !bytes.contains(&0)
        && bytes[1..]
            .split(|byte| *byte == b'/')
            .all(|part| !matches!(part, b"" | b"." | b".."));
    let kind = expected.file_type();
    if !canonical
        || !(kind.is_file() || kind.is_dir() || kind.is_symlink())
        || (kind.is_symlink() && mode.is_some())
        || mode.is_some_and(|bits| bits & !0o7777 != 0)
        || uid == Some(u32::MAX)
        || gid == Some(u32::MAX)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid checkout metadata request",
        ));
    }

    let (completed, received) = mpsc::channel();
    let request = Request {
        path: path.to_owned(),
        expected,
        mode,
        uid,
        gid,
        completed,
    };
    let operation = NativeFsEffect {
        exclusions: Arc::from([]),
        names: Vec::new(),
        preimages: Vec::new(),
        final_check: None,
        pairs: Vec::new(),
        plan: Plan::CheckoutMetadata(Box::new(request)),
        #[cfg(test)]
        faults: Vec::new(),
        #[cfg(all(test, feature = "tokio"))]
        gates: Vec::new(),
    };

    Ok((
        operation,
        Receipt {
            completed: received,
        },
    ))
}

/// Executes only this fixed presentation request through durability.
///
/// # Errors
/// Rejects replaced names, unsupported inode operations and metadata or sync failures.
pub(super) fn execute(effect: NativeFsEffect) -> Result<(), NativeEffectFailure> {
    let Plan::CheckoutMetadata(request) = effect.plan else {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "incorrect metadata dispatch").into(),
        );
    };
    execute_request(*request)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn execute_request(request: Request) -> io::Result<()> {
    use rustix::fs::{self, AtFlags, Mode, OFlags, Timestamps};
    use std::os::unix::fs::PermissionsExt;

    let names = request
        .path
        .components()
        .skip(1)
        .map(|part| part.as_os_str().to_owned())
        .collect::<Vec<_>>();
    let leaf_name = names
        .last()
        .ok_or_else(|| io::Error::other("missing checkout name"))?;
    let mut parents = vec![File::open("/")?];
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    for name in &names[..names.len() - 1] {
        let parent = parents
            .last()
            .ok_or_else(|| io::Error::other("missing checkout parent"))?;
        let directory = File::from(fs::openat(parent, name, directory_flags, Mode::empty())?);
        parents.push(directory);
    }
    check_parents(&parents, &names)?;

    let parent = parents
        .last()
        .ok_or_else(|| io::Error::other("missing checkout parent"))?;
    let flags = if request.expected.file_type().is_symlink() {
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC
    } else if request.expected.is_dir() {
        directory_flags
    } else {
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK
    };
    let inode = File::from(fs::openat(parent, leaf_name, flags, Mode::empty())?);
    check_inode(&inode.metadata()?, &request.expected)?;
    check_name(parent, leaf_name, &request.expected)?;

    let epoch = Timestamps {
        last_access: fs::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        last_modification: fs::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    // Empty-path operations address the retained inode, including a symlink
    // itself. A pathname swap cannot redirect ownership or timestamp changes.
    let nofollow_inode = AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW;
    fs::utimensat(&inode, "", &epoch, nofollow_inode)?;
    if request.uid.is_some() || request.gid.is_some() {
        fs::chownat(
            &inode,
            "",
            request.uid.map(fs::Uid::from_raw),
            request.gid.map(fs::Gid::from_raw),
            nofollow_inode,
        )?;
    }
    if let Some(mode) = request.mode {
        inode.set_permissions(std::fs::Permissions::from_mode(u32::from(mode)))?;
    }

    if request.expected.file_type().is_symlink() {
        // A symlink cannot be opened for fsync. Flush its containing filesystem
        // so a parent-directory sync alone is not mistaken for inode durability.
        fs::syncfs(parent)?;
    } else {
        inode.sync_all()?;
    }
    parent.sync_all()?;
    check_inode(&inode.metadata()?, &request.expected)?;
    check_name(parent, leaf_name, &request.expected)?;
    check_parents(&parents, &names)?;

    let actual = inode.metadata()?;
    if actual.atime() != 0
        || actual.atime_nsec() != 0
        || actual.mtime() != 0
        || actual.mtime_nsec() != 0
        || request.uid.is_some_and(|uid| actual.uid() != uid)
        || request.gid.is_some_and(|gid| actual.gid() != gid)
        || request
            .mode
            .is_some_and(|mode| actual.mode() & 0o7777 != u32::from(mode))
    {
        return Err(io::Error::other(
            "checkout metadata did not match its request",
        ));
    }
    // The physical worker retains every opened ancestor and the leaf until this
    // point even if its asynchronous caller has already dropped the receiver.
    let _ = request.completed.send(());
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn execute_request(_request: Request) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "retained checkout metadata requires Linux inode-relative operations",
    ))
}

fn check_inode(actual: &Metadata, expected: &Metadata) -> io::Result<()> {
    if actual.dev() != expected.dev()
        || actual.ino() != expected.ino()
        || actual.file_type() != expected.file_type()
    {
        return Err(io::Error::other("checkout inode was replaced"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_name(parent: &File, name: &OsString, expected: &Metadata) -> io::Result<()> {
    let actual = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
    if actual.st_dev != expected.dev()
        || actual.st_ino != expected.ino()
        || actual.st_mode & libc::S_IFMT != expected.mode() & libc::S_IFMT
    {
        return Err(io::Error::other(
            "checkout name no longer denotes its created inode",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_parents(parents: &[File], names: &[OsString]) -> io::Result<()> {
    let named_root = std::fs::symlink_metadata("/")?;
    let root = parents
        .first()
        .ok_or_else(|| io::Error::other("missing root descriptor"))?;
    check_inode(&root.metadata()?, &named_root)?;
    for (index, child) in parents.iter().enumerate().skip(1) {
        let parent = &parents[index - 1];
        check_name(parent, &names[index - 1], &child.metadata()?)?;
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct Scratch(PathBuf);

    impl Scratch {
        fn create() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "terrane-checkout-metadata-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn created_file_gets_canonical_times_before_restrictive_mode()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = Scratch::create()?;
        let path = scratch.0.join("file");
        std::fs::write(&path, b"verified presentation")?;
        let expected = std::fs::symlink_metadata(&path)?;
        let (operation, receipt) = effect(&path, expected, Some(0), None, None)?;

        operation.execute_inline()?;
        receipt.take()?;

        let actual = std::fs::symlink_metadata(&path)?;
        assert_eq!((actual.atime(), actual.mtime()), (0, 0));
        assert_eq!(actual.permissions().mode() & 0o7777, 0);
        Ok(())
    }

    #[test]
    fn symlink_metadata_does_not_touch_its_target() -> Result<(), Box<dyn std::error::Error>> {
        let scratch = Scratch::create()?;
        let target = scratch.0.join("target");
        let link = scratch.0.join("link");
        std::fs::write(&target, b"unchanged target")?;
        symlink("target", &link)?;
        let before = std::fs::symlink_metadata(&target)?;
        let (operation, receipt) =
            effect(&link, std::fs::symlink_metadata(&link)?, None, None, None)?;

        operation.execute_inline()?;
        receipt.take()?;

        let after = std::fs::symlink_metadata(&target)?;
        assert_eq!(
            (
                before.atime(),
                before.atime_nsec(),
                before.mtime(),
                before.mtime_nsec()
            ),
            (
                after.atime(),
                after.atime_nsec(),
                after.mtime(),
                after.mtime_nsec()
            )
        );
        let actual = std::fs::symlink_metadata(&link)?;
        assert_eq!((actual.atime(), actual.mtime()), (0, 0));
        assert_eq!(std::fs::read_link(&link)?, Path::new("target"));
        Ok(())
    }

    #[test]
    fn replaced_inode_is_rejected_before_metadata_changes() -> Result<(), Box<dyn std::error::Error>>
    {
        let scratch = Scratch::create()?;
        let path = scratch.0.join("file");
        std::fs::write(&path, b"original")?;
        let (operation, receipt) = effect(
            &path,
            std::fs::symlink_metadata(&path)?,
            Some(0),
            None,
            None,
        )?;
        std::fs::rename(&path, scratch.0.join("old"))?;
        std::fs::write(&path, b"replacement")?;
        let before = std::fs::symlink_metadata(&path)?;

        assert!(operation.execute_inline().is_err());
        assert!(receipt.take().is_err());

        let after = std::fs::symlink_metadata(&path)?;
        assert_eq!(before.mode(), after.mode());
        assert_eq!(
            (before.atime(), before.mtime()),
            (after.atime(), after.mtime())
        );
        assert_eq!(std::fs::read(&path)?, b"replacement");
        Ok(())
    }

    #[test]
    fn callback_success_without_native_execution_has_no_receipt()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = Scratch::create()?;
        let path = scratch.0.join("file");
        std::fs::write(&path, b"content")?;
        let (_operation, receipt) = effect(
            &path,
            std::fs::symlink_metadata(&path)?,
            Some(0o600),
            None,
            None,
        )?;

        assert!(matches!(receipt.take(), Err(error) if error.kind() == io::ErrorKind::Unsupported));
        Ok(())
    }

    #[test]
    fn ownership_sentinels_are_rejected_before_effect_construction()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = Scratch::create()?;
        let path = scratch.0.join("file");
        std::fs::write(&path, b"content")?;
        for (uid, gid) in [(Some(u32::MAX), None), (None, Some(u32::MAX))] {
            assert!(
                effect(
                    &path,
                    std::fs::symlink_metadata(&path)?,
                    Some(0o600),
                    uid,
                    gid
                )
                .is_err()
            );
        }
        Ok(())
    }
}
