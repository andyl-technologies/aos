//! Retains the actual Output source ancestry, fixed read and metadata results.
//!
//! The ordinary adapter and selected original share these native operations and
//! protection checks. This private DATA owner supplies no path or key authority.

use super::*;
use std::error::Error;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd};

struct ParentStep {
    opened: Option<Result<OwnedFd, rustix::io::Errno>>,
    metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    validation: Option<Result<(), StorageServiceError>>,
}

impl ParentStep {
    const fn new() -> Self {
        Self {
            opened: None,
            metadata: None,
            validation: None,
        }
    }

    fn open_root(&mut self) -> Result<(), StorageServiceError> {
        self.opened = Some(open("/", OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()));
        self.fd().map(|_| ()).ok_or_else(|| invalid("output credential source root is unavailable"))
    }

    fn open_child(&mut self, parent: BorrowedFd<'_>, name: &OsStr) -> Result<(), StorageServiceError> {
        self.opened = Some(openat2(parent, name,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS));
        self.fd().map(|_| ()).ok_or_else(|| invalid("output credential source ancestor is unsafe"))
    }

    fn validate(&mut self) -> Result<(), StorageServiceError> {
        let descriptor = self.fd().ok_or_else(|| invalid("output credential source ancestor failed"))?;
        self.metadata = Some(fstat(descriptor));
        let metadata = self.metadata.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| invalid("output credential source ancestor failed"))?;
        self.validation = Some(if is_root_controlled_directory(metadata.st_mode, metadata.st_uid) {
            Ok(())
        } else {
            Err(invalid("output credential source ancestor is not root controlled"))
        });
        if matches!(self.validation, Some(Ok(()))) { Ok(()) } else {
            Err(invalid("output credential source ancestor is not root controlled"))
        }
    }

    fn fd(&self) -> Option<&OwnedFd> {
        self.opened.as_ref().and_then(|result| result.as_ref().ok())
    }

    fn take_fd(&mut self) -> Option<OwnedFd> {
        self.opened.take().and_then(Result::ok)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.opened.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error)
            .or_else(|| self.metadata.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
            .or_else(|| self.validation.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
    }
}

struct ParentOriginal {
    steps: Vec<ParentStep>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
}

impl ParentOriginal {
    const fn new() -> Self {
        Self {
            steps: Vec::new(),
            allocation: None,
        }
    }

    fn fd(&self) -> Option<&OwnedFd> {
        self.steps.last().and_then(ParentStep::fd)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.allocation.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error)
            .or_else(|| self.steps.iter().find_map(ParentStep::failure))
    }
}

fn walk_parent(path: &Path, mut original: Option<&mut ParentOriginal>)
    -> Result<Option<OwnedFd>, StorageServiceError>
{
    if !path.is_absolute() {
        return Err(invalid("output credential source path is not absolute"));
    }
    let mut local = ParentStep::new();
    if let Some(original) = original.as_deref_mut() {
        original.allocation = Some(original.steps.try_reserve_exact(path.components().count() + 1));
        if !matches!(original.allocation, Some(Ok(()))) {
            return Err(invalid("output credential source root is unavailable"));
        }
        original.steps.push(ParentStep::new());
        let step = original.steps.last_mut().ok_or_else(|| invalid("output credential source root is unavailable"))?;
        step.open_root()?;
        step.validate()?;
    } else {
        local.open_root()?;
        local.validate()?;
    }
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                if let Some(original) = original.as_deref_mut() {
                    original.steps.push(ParentStep::new());
                    let count = original.steps.len();
                    let (previous, current) = original.steps.split_at_mut(count - 1);
                    let parent = previous.last().and_then(ParentStep::fd)
                        .ok_or_else(|| invalid("output credential source ancestor is unsafe"))?;
                    current[0].open_child(parent.as_fd(), name)?;
                    current[0].validate()?;
                } else {
                    let mut next = ParentStep::new();
                    let parent = local.fd().ok_or_else(|| invalid("output credential source ancestor is unsafe"))?;
                    next.open_child(parent.as_fd(), name)?;
                    // Preserve the ordinary assignment frontier: the previous
                    // directory closes before validating the newly opened one.
                    local = next;
                    local.validate()?;
                }
            }
            _ => return Err(invalid("output credential source path is invalid")),
        }
    }
    if original.is_some() { Ok(None) } else { Ok(local.take_fd()) }
}

pub(super) fn open_parent(path: &Path) -> Result<OwnedFd, StorageServiceError> {
    walk_parent(path, None)?.ok_or_else(|| invalid("output credential source root is unavailable"))
}

struct LeafOriginal {
    // Retain ordinary reverse-local buffer-before-File destruction order.
    bytes: Zeroizing<Vec<u8>>,
    opened: Option<Result<OwnedFd, rustix::io::Errno>>,
    before: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    validation: Option<Result<(), StorageServiceError>>,
    read: Option<Result<(), std::io::Error>>,
    trailing: Option<Result<usize, std::io::Error>>,
    after: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    stable: Option<Result<(), StorageServiceError>>,
    file: Option<File>,
}

impl LeafOriginal {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            opened: None,
            before: None,
            validation: None,
            read: None,
            trailing: None,
            after: None,
            stable: None,
            file: None,
        }
    }

    fn capture(&mut self, directory: &OwnedFd, name: &OsStr, owner: u32)
        -> Result<(), StorageServiceError>
    {
        self.opened = Some(openat2(directory, name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS));
        let descriptor = self.opened.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| invalid("output credential source file is unsafe"))?;
        self.before = Some(fstat(descriptor));
        let before = self.before.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| invalid("output credential source stat failed"))?;
        self.validation = Some(if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != owner || !matches!(before.st_mode & 0o7777, 0o400 | 0o600)
            || before.st_nlink != 1 || before.st_size != CREDENTIAL_BYTES as i64
        {
            Err(invalid("output credential source protection is invalid"))
        } else {
            Ok(())
        });
        if !matches!(self.validation, Some(Ok(()))) {
            return Err(invalid("output credential source protection is invalid"));
        }
        self.file = self.opened.take().and_then(Result::ok).map(File::from);
        let file = self.file.as_mut().ok_or_else(|| invalid("output credential source file is unsafe"))?;
        self.bytes.resize(CREDENTIAL_BYTES, 0);
        self.read = Some(file.read_exact(&mut self.bytes));
        if !matches!(self.read, Some(Ok(()))) {
            return Err(invalid("output credential source read failed"));
        }
        let mut extra = [0; 1];
        self.trailing = Some(file.read(&mut extra));
        match self.trailing {
            Some(Ok(0)) => {}
            Some(Ok(_)) => return Err(invalid("output credential source changed")),
            _ => return Err(invalid("output credential source read failed")),
        }
        self.after = Some(fstat(file));
        let after = self.after.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| invalid("output credential source stat failed"))?;
        self.stable = Some(if source_identity(before) == source_identity(after) {
            Ok(())
        } else {
            Err(invalid("output credential source changed"))
        });
        if matches!(self.stable, Some(Ok(()))) { Ok(()) } else {
            Err(invalid("output credential source changed"))
        }
    }

    fn take_record(&mut self) -> Option<(SourceIdentity, Zeroizing<Vec<u8>>)> {
        if !matches!(self.stable, Some(Ok(()))) { return None; }
        let after = self.after.as_ref()?.as_ref().ok()?;
        let identity = source_identity(after);
        Some((identity, std::mem::replace(&mut self.bytes, Zeroizing::new(Vec::new()))))
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.opened.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error)
            .or_else(|| self.before.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
            .or_else(|| self.validation.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
            .or_else(|| self.read.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
            .or_else(|| self.trailing.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
            .or_else(|| self.stable.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
    }
}

pub(super) fn read_leaf(directory: &OwnedFd, name: &OsStr, owner: u32)
    -> Result<(SourceIdentity, Zeroizing<Vec<u8>>), StorageServiceError>
{
    let mut original = LeafOriginal::new();
    original.capture(directory, name, owner)?;
    original.take_record().ok_or_else(|| invalid("output credential source changed"))
}

pub(super) struct SourceOriginal {
    parent: ParentOriginal,
    leaf: LeafOriginal,
    result: Option<Result<(), StorageServiceError>>,
    source: Option<PinnedSource>,
    reentered: bool,
}

impl SourceOriginal {
    pub(super) fn new() -> Self {
        Self {
            parent: ParentOriginal::new(),
            leaf: LeafOriginal::new(),
            result: None,
            source: None,
            reentered: false,
        }
    }

    pub(super) fn capture_once(&mut self, path: &Path) -> Result<(), ()> {
        if self.result.is_some() { self.reentered = true; return Err(()); }
        self.result = Some(self.capture(path));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    fn capture(&mut self, path: &Path) -> Result<(), StorageServiceError> {
        let parent = path.parent().ok_or_else(|| invalid("output credential source path is invalid"))?;
        let name = path.file_name().ok_or_else(|| invalid("output credential source path is invalid"))?;
        walk_parent(parent, Some(&mut self.parent))?;
        let directory = self.parent.fd().ok_or_else(|| invalid("output credential source root is unavailable"))?;
        self.leaf.capture(directory, name, 0)?;
        let (identity, bytes) = self.leaf.take_record().ok_or_else(|| invalid("output credential source changed"))?;
        self.source = Some(PinnedSource { path: path.to_path_buf(), identity, bytes });
        Ok(())
    }

    pub(super) fn source(&self) -> Option<&PinnedSource> {
        if self.reentered || !matches!(self.result, Some(Ok(()))) { return None; }
        self.source.as_ref()
    }

    pub(super) fn take_source(&mut self) -> Option<PinnedSource> {
        self.source()?;
        self.source.take()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.parent.failure().or_else(|| self.leaf.failure())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
    }

    pub(super) fn settle_positive(&mut self) {
        if !self.reentered && matches!(self.result, Some(Ok(()))) {
            self.parent.steps = Vec::new();
            self.leaf.file = None;
        }
    }

    pub(super) fn parent_step_bytes() -> usize { std::mem::size_of::<ParentStep>() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    #[test]
    fn failed_ancestry_keeps_the_open_root_and_first_reached_cause() {
        let path = PathBuf::from(format!("/rfc21-missing-output-{}", std::process::id()));
        let mut parent = ParentOriginal::new();
        assert!(walk_parent(&path, Some(&mut parent)).is_err());
        assert!(parent.steps.first().and_then(ParentStep::fd).is_some());
        let first = parent.steps.iter().find_map(ParentStep::failure).unwrap();
        let cause = parent.failure().unwrap();
        if let Some(first) = first.downcast_ref::<rustix::io::Errno>() {
            let cause = cause.downcast_ref::<rustix::io::Errno>().unwrap();
            assert!(std::ptr::eq(first, cause));
            assert_eq!(*cause, rustix::io::Errno::NOENT);
            assert!(parent.steps.last().unwrap().metadata.is_none());
        } else {
            // A user-namespace test root can be owned by an unmapped UID.
            // Its real policy refusal precedes the attempted missing child.
            let first = first.downcast_ref::<StorageServiceError>().unwrap();
            let cause = cause.downcast_ref::<StorageServiceError>().unwrap();
            assert!(std::ptr::eq(first, cause));
            assert_eq!(parent.steps.len(), 1);
            assert!(matches!(parent.steps[0].validation, Some(Err(_))));
        }
    }

    #[test]
    fn missing_child_native_open_keeps_the_parent_descriptor_and_errno() {
        let name = format!("rfc21-missing-output-{}", std::process::id());
        let mut root = ParentStep::new();
        root.open_root().unwrap();
        let mut child = ParentStep::new();

        // Raw custody DATA only: this exercises the actual shared open step,
        // without asserting that an unmapped test root is protected authority.
        assert!(child.open_child(root.fd().unwrap().as_fd(), OsStr::new(&name)).is_err());
        let cause = child.failure().unwrap().downcast_ref::<rustix::io::Errno>().unwrap();

        assert_eq!(*cause, rustix::io::Errno::NOENT);
        assert!(root.fd().is_some());
        assert!(child.metadata.is_none());
    }

    #[test]
    fn wrong_leaf_length_keeps_original_file_metadata_after_external_repair() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        std::fs::write(&path, [1_u8; CREDENTIAL_BYTES - 1]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let descriptor = open(directory.path(), OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty()).unwrap();
        let owner = path.metadata().unwrap().uid();
        let mut original = LeafOriginal::new();

        assert!(original.capture(&descriptor, OsStr::new("key"), owner).is_err());
        let before = original.before.as_ref().unwrap().as_ref().unwrap();
        let identity = (before.st_dev, before.st_ino, before.st_size);
        std::fs::write(&path, [2_u8; CREDENTIAL_BYTES]).unwrap();

        let held = original.opened.as_ref().unwrap().as_ref().unwrap();
        let current = fstat(held).unwrap();
        assert_eq!((current.st_dev, current.st_ino), (identity.0, identity.1));
        assert_eq!(identity.2, (CREDENTIAL_BYTES - 1) as i64);
        assert_eq!(current.st_size, CREDENTIAL_BYTES as i64);
        assert!(original.read.is_none());
        assert!(original.take_record().is_none());
    }

    #[test]
    fn successful_source_leaf_retains_actual_exact_and_trailing_read_results() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        std::fs::write(&path, [8_u8; CREDENTIAL_BYTES]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let descriptor = open(directory.path(), OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty()).unwrap();
        let owner = path.metadata().unwrap().uid();
        let mut original = LeafOriginal::new();

        original.capture(&descriptor, OsStr::new("key"), owner).unwrap();
        let (identity, bytes) = original.take_record().unwrap();

        assert_eq!(bytes.as_slice(), &[8; CREDENTIAL_BYTES]);
        assert!(matches!(original.read, Some(Ok(()))));
        assert!(matches!(original.trailing, Some(Ok(0))));
        assert_eq!(source_identity(original.before.as_ref().unwrap().as_ref().unwrap()), identity);
        assert_eq!(source_identity(original.after.as_ref().unwrap().as_ref().unwrap()), identity);
        assert!(original.file.is_some());
    }
}
