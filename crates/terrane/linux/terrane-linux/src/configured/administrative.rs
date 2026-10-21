//! Retains a protected administrative inode without opening its private children.

use crate::host_quota::open_host_path;
use std::{
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

/// Keeps actual canonical-name custody separate from privileged project queries.
pub(super) struct AdministrativeRoot {
    path: PathBuf,
    file: File,
}

impl AdministrativeRoot {
    pub(super) fn open(path: &Path, device: u64, inode: u64) -> io::Result<Self> {
        let file = open(path)?;
        let metadata = file.metadata()?;
        if (metadata.dev(), metadata.ino()) != (device, inode) {
            return Err(io::Error::other(
                "administrative root differs from authenticated quota root",
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            file,
        })
    }

    pub(super) fn check_current(&self) -> io::Result<()> {
        let current = open(&self.path)?.metadata()?;
        let retained = self.file.metadata()?;
        if (
            current.dev(),
            current.ino(),
            current.uid(),
            current.gid(),
            current.mode(),
        ) != (
            retained.dev(),
            retained.ino(),
            retained.uid(),
            retained.gid(),
            retained.mode(),
        ) {
            return Err(io::Error::other("retained administrative root changed"));
        }
        Ok(())
    }
}

fn open(path: &Path) -> io::Result<File> {
    let parent = open_host_path(
        path.parent()
            .ok_or_else(|| io::Error::other("administrative root has no parent"))?,
        true,
    )?;
    // O_PATH observes the original inode without granting traversal into the
    // root-only publication control. Project/UUID facts come from the live,
    // authenticated host-root helper, which can inspect that private directory.
    let file = File::from(rustix::fs::openat(
        parent,
        path.file_name()
            .ok_or_else(|| io::Error::other("administrative root has no name"))?,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "administrative root lacks protected root custody",
        ));
    }
    Ok(file)
}
