//! Retains the shared directory-creation and durability syscall recipes.
//!
//! The ordinary slot adapter and funded namespace adapter call these same
//! operations. Each original parks syscall results and partial descriptors
//! before checking them; an entered original never repeats a native action.

use super::*;
use aos_sandbox_linux::path::BeneathRootResolveOriginalV2;

#[derive(Default)]
pub(in crate::destination_slot) struct DirectoryParentOriginalV1 {
    entered: bool,
    mkdir: Option<std::result::Result<(), rustix::io::Errno>>,
    resolved: BeneathRootResolveOriginalV2,
    resolution: Option<std::result::Result<(), aos_linux_descriptors::Error>>,
    metadata: Option<std::result::Result<rustix::fs::Stat, rustix::io::Errno>>,
    comparison: Option<Result<()>>,
    root: Option<BeneathRoot>,
    closed: Option<MountError>,
}

impl DirectoryParentOriginalV1 {
    pub(in crate::destination_slot) fn enter_once_v1(
        &mut self,
        parent: &BeneathRoot,
        name: &str,
        mode: u32,
        owner: u32,
    ) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(|| conflict("parent original already entered"));
            return Err(conflict("parent original remains closed"));
        }
        self.entered = true;
        self.mkdir = Some(rustix::fs::mkdirat(parent.as_fd(), name,
            rustix::fs::Mode::from_raw_mode(mode)));
        if !matches!(self.mkdir, Some(Ok(())) | Some(Err(rustix::io::Errno::EXIST))) {
            return Err(conflict("parent mkdir retained an error"));
        }
        self.resolution = Some(self.resolved.resolve_once(parent, Path::new(name),
            ResolveOptions::directory()));
        if !matches!(self.resolution, Some(Ok(()))) {
            return Err(conflict("parent resolution retained an error"));
        }
        // The strict resolver keeps its descriptor throughout these checks.
        // Move it only after the same owner/mode predicate has succeeded.
        self.root = self.resolved.take_directory_root_once();
        let root = self.root.as_ref().ok_or_else(|| corrupt("parent resolution is not a directory"))?;
        self.metadata = Some(rustix::fs::fstat(root.as_fd()));
        self.comparison = Some((|| {
            let stat = self.metadata.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| conflict("parent metadata retained an error"))?;
            if root.identity().file_type != FileType::Directory
                || stat.st_uid != owner || stat.st_mode & 0o7777 != mode
            {
                return Err(corrupt("destination-slot directory ownership or mode changed"));
            }
            Ok(())
        })());
        if matches!(self.comparison, Some(Ok(()))) { Ok(()) }
        else { Err(conflict("parent original retained a comparison error")) }
    }

    pub(in crate::destination_slot) fn root_v1(&self) -> Option<&BeneathRoot> {
        if self.failure_v1().is_some() || !matches!(self.comparison, Some(Ok(()))) {
            return None;
        }
        self.root.as_ref()
    }

    pub(in crate::destination_slot) fn take_root_once_v1(&mut self) -> Option<BeneathRoot> {
        if self.failure_v1().is_some() || !matches!(self.comparison, Some(Ok(()))) {
            return None;
        }
        self.root.take()
    }

    pub(in crate::destination_slot) fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.mkdir.as_ref().and_then(|result| result.as_ref().err())
            .filter(|cause| **cause != rustix::io::Errno::EXIST).map(|cause| cause as _)
            .or_else(|| self.resolved.failure().map(|cause| cause as _))
            .or_else(|| self.metadata.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.comparison.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(in crate::destination_slot) fn receiving_obligations_v1(path_bytes: usize)
        -> Option<(usize, usize, usize)> {
        let native = BeneathRootResolveOriginalV2::receiving_obligations_v2(path_bytes)?;
        Some((std::mem::size_of::<Self>().checked_mul(2)?.checked_add(native.0)?,
            native.1, native.2))
    }
}

#[derive(Default)]
pub(in crate::destination_slot) struct DirectorySyncOriginalV1 {
    entered: bool,
    descriptor: Option<std::result::Result<OwnedFd, rustix::io::Errno>>,
    synced: Option<std::result::Result<(), rustix::io::Errno>>,
    closed: Option<MountError>,
}

impl DirectorySyncOriginalV1 {
    pub(in crate::destination_slot) fn enter_once_v1(&mut self, directory: &BeneathRoot) -> Result<()> {
        self.enter_descriptor_once_v1(directory.as_fd())
    }

    pub(in crate::destination_slot) fn enter_descriptor_once_v1(&mut self, directory: BorrowedFd<'_>) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(|| conflict("directory sync already entered"));
            return Err(conflict("directory sync remains closed"));
        }
        self.entered = true;
        self.descriptor = Some(rustix::fs::openat(directory, ".",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()));
        let descriptor = self.descriptor.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| conflict("directory sync retained its open error"))?;
        self.synced = Some(rustix::fs::fsync(descriptor));
        if matches!(self.synced, Some(Ok(()))) { Ok(()) }
        else { Err(conflict("directory sync retained its fsync error")) }
    }

    pub(in crate::destination_slot) fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.descriptor.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.synced.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(in crate::destination_slot) fn receiving_obligations_v1() -> Option<(usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?, 1))
    }
}

// Both ordinary slots and the no-slot namespace use this exact non-recursive
// rooted syscall. Authority, identity and retained results remain with callers.
pub(in crate::destination_slot) fn unlink_empty_directory_v1(
    parent: BorrowedFd<'_>,
    name: &str,
) -> std::result::Result<(), rustix::io::Errno> {
    rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::REMOVEDIR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn root(directory: &Path) -> BeneathRoot {
        let fd = rustix::fs::open(directory, rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()).unwrap();
        BeneathRoot::from_owned(fd).unwrap()
    }

    #[test]
    fn parent_owner_refusal_retains_actual_directory_and_cannot_repeat() {
        let directory = tempfile::tempdir().unwrap();
        let root = root(directory.path());
        let owner = rustix::process::geteuid().as_raw();
        let wrong_owner = if owner == 0 { 1 } else { 0 };
        let mut original = DirectoryParentOriginalV1::default();

        assert!(original.enter_once_v1(&root, "child", 0o700, wrong_owner).is_err());
        assert!(original.failure_v1().is_some());
        assert!(original.root_v1().is_none());
        let pin = original.root.as_ref().unwrap();
        let identity = pin.identity();
        assert_eq!(rustix::fs::fstat(pin.as_fd()).unwrap().st_ino as u64, identity.inode);
        let first = original.failure_v1().unwrap() as *const dyn std::error::Error;

        assert!(original.enter_once_v1(&root, "replacement", 0o700, owner).is_err());
        assert!(std::ptr::eq(first, original.failure_v1().unwrap() as *const dyn std::error::Error));
        assert!(!directory.path().join("replacement").exists());
        assert_eq!(rustix::fs::fstat(original.root.as_ref().unwrap().as_fd()).unwrap().st_ino as u64,
            identity.inode);
    }

    #[test]
    fn shared_parent_engine_moves_only_its_same_validated_directory_once() {
        let directory = tempfile::tempdir().unwrap();
        let root = root(directory.path());
        let mut original = DirectoryParentOriginalV1::default();
        original.enter_once_v1(&root, "child", 0o700,
            rustix::process::geteuid().as_raw()).unwrap();
        let identity = original.root_v1().unwrap().identity();
        let moved = original.take_root_once_v1().unwrap();

        assert!(original.take_root_once_v1().is_none());
        assert_eq!(moved.identity(), identity);
        assert_eq!(rustix::fs::fstat(moved.as_fd()).unwrap().st_mode & 0o7777, 0o700);
        assert_eq!(std::fs::metadata(directory.path().join("child")).unwrap().permissions().mode() & 0o7777,
            0o700);
    }

    #[test]
    fn independent_sync_keeps_its_actual_descriptor_and_refuses_reentry() {
        let directory = tempfile::tempdir().unwrap();
        let root = root(directory.path());
        let mut original = DirectorySyncOriginalV1::default();
        original.enter_once_v1(&root).unwrap();
        let fd = original.descriptor.as_ref().unwrap().as_ref().unwrap();
        let first = rustix::fs::fstat(fd).unwrap().st_ino;

        assert!(original.enter_once_v1(&root).is_err());
        assert_eq!(rustix::fs::fstat(original.descriptor.as_ref().unwrap().as_ref().unwrap()).unwrap().st_ino,
            first);
        assert!(matches!(original.synced, Some(Ok(()))));
    }
}
