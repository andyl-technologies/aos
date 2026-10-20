//! Shares Storage's existing protected directory and exact credential reads.
//!
//! Ordinary adapters keep their consuming local disposition. Selected initial
//! batches retain all reached Files, buffers and native results in the actual
//! startup owner. This is fixed input custody, never a payer or role original.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, openat, openat2};
use zeroize::Zeroizing;

use super::{FileIdentity, PinnedCredential, StorageServiceError, identity, invalid};

const STORAGE_CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-storaged.service";

type NativeStat = Result<rustix::fs::Stat, rustix::io::Errno>;

#[derive(Default)]
struct DirectoryRead {
    // Native errors drop before the owned directory in the ordinary adapter.
    completion: Option<Result<FileIdentity, StorageServiceError>>,
    stat: Option<NativeStat>,
    open: Option<Result<OwnedFd, rustix::io::Errno>>,
}

impl DirectoryRead {
    fn capture(&mut self, path: &Path) {
        if self.completion.is_none() {
            self.completion = Some(self.capture_inner(path));
        }
    }

    fn capture_inner(&mut self, path: &Path) -> Result<FileIdentity, StorageServiceError> {
        if !path.is_absolute() {
            return Err(invalid("operator credential directory is not absolute"));
        }
        self.open = Some(openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ));
        let fd = self.fd().ok_or_else(|| invalid("operator credential directory is unsafe"))?;
        self.stat = Some(fstat(fd));
        let observed = self.stat.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| invalid("operator credential directory is unavailable"))?;
        if FileType::from_raw_mode(observed.st_mode) != FileType::Directory
            || observed.st_uid != 0
            || observed.st_mode & 0o077 != 0
        {
            return Err(invalid("operator credential directory protection is invalid"));
        }
        Ok(identity(observed))
    }

    fn fd(&self) -> Option<&OwnedFd> {
        self.open.as_ref()?.as_ref().ok()
    }

    fn identity(&self) -> Option<FileIdentity> {
        self.completion.as_ref()?.as_ref().ok().copied()
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.open { return Some(cause); }
        if let Some(Err(cause)) = &self.stat { return Some(cause); }
        self.completion.as_ref()?.as_ref().err()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

#[derive(Default)]
struct FileRead {
    // Preserve the ordinary error/buffer/File disposal order in its local slot.
    completion: Option<Result<FileIdentity, StorageServiceError>>,
    after: Option<NativeStat>,
    exact: Option<std::io::Result<()>>,
    bytes: Option<Zeroizing<Vec<u8>>>,
    file: Option<File>,
    before: Option<NativeStat>,
    open: Option<Result<OwnedFd, rustix::io::Errno>>,
}

impl FileRead {
    fn capture(&mut self, directory: &OwnedFd, name: &'static str, length: usize) {
        if self.completion.is_none() {
            self.completion = Some(self.capture_inner(directory, name, length));
        }
    }

    fn capture_inner(
        &mut self,
        directory: &OwnedFd,
        name: &'static str,
        length: usize,
    ) -> Result<FileIdentity, StorageServiceError> {
        self.open = Some(openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let fd = self.open.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| invalid("operator credential is absent"))?;
        self.before = Some(fstat(fd));
        let before = self.before.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| invalid("operator credential metadata is unavailable"))?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != 0
            || before.st_mode & 0o077 != 0
            || before.st_nlink != 1
            || before.st_size != length as i64
        {
            return Err(invalid("operator credential protection is invalid"));
        }
        let before_identity = identity(before);
        let Some(Ok(fd)) = self.open.take() else {
            return Err(invalid("operator credential is absent"));
        };
        self.file = Some(File::from(fd));
        self.bytes = Some(Zeroizing::new(vec![0; length]));
        let file = self.file.as_mut().ok_or_else(|| invalid("operator credential is absent"))?;
        let bytes = self.bytes.as_mut().ok_or_else(|| invalid("operator credential read failed"))?;
        self.exact = Some(file.read_exact(bytes));
        if !matches!(self.exact, Some(Ok(()))) {
            return Err(invalid("operator credential read failed"));
        }
        self.after = Some(fstat(file));
        let after = self.after.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| invalid("operator credential changed"))?;
        if before_identity != identity(after) {
            return Err(invalid("operator credential changed"));
        }
        Ok(identity(after))
    }

    fn identity(&self) -> Option<FileIdentity> {
        self.completion.as_ref()?.as_ref().ok().copied()
    }

    fn bytes(&self) -> Option<&[u8]> {
        self.identity()?;
        Some(self.bytes.as_ref()?.as_slice())
    }

    fn take_pin(&mut self, name: &'static str) -> Option<PinnedCredential> {
        let identity = self.identity()?;
        Some(PinnedCredential { name, identity, bytes: self.bytes.take()? })
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.open { return Some(cause); }
        if let Some(Err(cause)) = &self.before { return Some(cause); }
        if let Some(Err(cause)) = &self.exact { return Some(cause); }
        if let Some(Err(cause)) = &self.after { return Some(cause); }
        self.completion.as_ref()?.as_ref().err()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

pub(super) fn open_directory_local(path: &Path) -> Result<(OwnedFd, FileIdentity), StorageServiceError> {
    let mut slot = DirectoryRead::default();
    slot.capture(path);
    let observed = slot.completion.take()
        .ok_or_else(|| invalid("operator credential directory is unavailable"))??;
    let descriptor = slot.open.take()
        .ok_or_else(|| invalid("operator credential directory is unsafe"))?
        .map_err(|_| invalid("operator credential directory is unsafe"))?;
    Ok((descriptor, observed))
}

pub(super) fn read_credential_local(
    directory: &OwnedFd,
    name: &'static str,
    length: usize,
) -> Result<PinnedCredential, StorageServiceError> {
    let mut slot = FileRead::default();
    slot.capture(directory, name, length);
    let observed = slot.completion.take()
        .ok_or_else(|| invalid("operator credential read failed"))??;
    let bytes = slot.bytes.take().ok_or_else(|| invalid("operator credential read failed"))?;
    Ok(PinnedCredential { name, identity: observed, bytes })
}

/// Retains the fixed initial Storage directory and its exact named readback.
///
/// The enclosing key/operator startup supplies only compiled role names/widths
/// after actual receiving admission. No borrowed scalar creates a resource loan.
pub(crate) struct InitialStorageCredentialBatchV1<const N: usize> {
    original_directory: DirectoryRead,
    originals: [FileRead; N],
    named_directory: DirectoryRead,
    named: [FileRead; N],
    original_directory_posts: [Option<NativeStat>; 2],
    original_file_posts: [[Option<NativeStat>; 2]; N],
    capture: Option<Result<(), StorageServiceError>>,
    post: Option<Result<(), StorageServiceError>>,
    closed: Option<StorageServiceError>,
    settled: bool,
}

impl<const N: usize> InitialStorageCredentialBatchV1<N> {
    pub(crate) fn new() -> Self {
        Self {
            original_directory: DirectoryRead::default(),
            originals: std::array::from_fn(|_| FileRead::default()),
            named_directory: DirectoryRead::default(),
            named: std::array::from_fn(|_| FileRead::default()),
            original_directory_posts: std::array::from_fn(|_| None),
            original_file_posts: std::array::from_fn(|_| std::array::from_fn(|_| None)),
            capture: None,
            post: None,
            closed: None,
            settled: false,
        }
    }

    pub(crate) fn capture_once(&mut self, names: &[&'static str; N], lengths: &[usize; N]) -> Result<(), ()> {
        if self.capture.is_some() || self.closed.is_some() || self.settled {
            self.closed.get_or_insert_with(|| invalid("initial credential capture repeated"));
            return Err(());
        }
        self.capture = Some(self.capture_inner(names, lengths));
        if matches!(self.capture, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    fn capture_inner(&mut self, names: &[&'static str; N], lengths: &[usize; N]) -> Result<(), StorageServiceError> {
        self.original_directory.capture(Path::new(STORAGE_CREDENTIAL_DIRECTORY));
        self.original_directory.identity()
            .ok_or_else(|| invalid("initial credential directory failed"))?;
        let directory = self.original_directory.fd()
            .ok_or_else(|| invalid("initial credential directory failed"))?;
        for index in 0..N {
            self.originals[index].capture(directory, names[index], lengths[index]);
            self.originals[index].identity()
                .ok_or_else(|| invalid("initial credential capture failed"))?;
        }
        Ok(())
    }

    pub(crate) fn post_once(&mut self, names: &[&'static str; N], lengths: &[usize; N]) -> Result<(), ()> {
        if self.post.is_some() || self.settled {
            self.closed.get_or_insert_with(|| invalid("initial credential post repeated"));
            return Err(());
        }
        self.post = Some(self.post_inner(names, lengths));
        if matches!(self.post, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    fn post_inner(&mut self, names: &[&'static str; N], lengths: &[usize; N]) -> Result<(), StorageServiceError> {
        // This independent available post runs even after an earlier capture
        // or semantic error. Missing original slots refuse without replacement.
        let original = self.original_directory.fd()
            .ok_or_else(|| invalid("initial credential directory failed"))?;
        self.original_directory_posts[0] = Some(fstat(original));
        require_same_stat(&self.original_directory_posts[0], self.original_directory.identity())?;
        self.named_directory.capture(Path::new(STORAGE_CREDENTIAL_DIRECTORY));
        if self.named_directory.identity() != self.original_directory.identity()
            || self.named_directory.identity().is_none()
        {
            return Err(invalid("initial credential directory changed"));
        }
        let directory = self.named_directory.fd()
            .ok_or_else(|| invalid("initial credential directory failed"))?;
        for index in 0..N {
            let original = self.originals[index].file.as_ref()
                .ok_or_else(|| invalid("initial credential is absent"))?;
            self.original_file_posts[index][0] = Some(fstat(original));
            require_same_stat(&self.original_file_posts[index][0], self.originals[index].identity())?;
            self.named[index].capture(directory, names[index], lengths[index]);
            if self.named[index].identity() != self.originals[index].identity()
                || self.named[index].bytes() != self.originals[index].bytes()
                || self.named[index].identity().is_none()
            {
                return Err(invalid("initial credential changed"));
            }
            self.original_file_posts[index][1] = Some(fstat(original));
            require_same_stat(&self.original_file_posts[index][1], self.originals[index].identity())?;
        }
        self.original_directory_posts[1] = Some(fstat(original));
        require_same_stat(&self.original_directory_posts[1], self.original_directory.identity())
    }

    pub(crate) fn bytes(&self, index: usize) -> Option<&[u8]> {
        if !matches!(self.capture, Some(Ok(()))) { return None; }
        self.originals.get(index)?.bytes()
    }

    pub(crate) fn post_bytes(&self, index: usize) -> Option<&[u8]> {
        if !matches!(self.post, Some(Ok(()))) { return None; }
        self.named.get(index)?.bytes()
    }

    pub(crate) fn ready_for_handoff(&self) -> bool {
        !self.settled && self.failure().is_none()
            && matches!(self.capture, Some(Ok(())))
            && matches!(self.post, Some(Ok(())))
    }

    pub(crate) fn directory_identity(&self) -> Option<FileIdentity> {
        self.original_directory.identity()
    }

    pub(crate) fn directory_path() -> PathBuf {
        PathBuf::from(STORAGE_CREDENTIAL_DIRECTORY)
    }

    pub(crate) fn take_pin(&mut self, index: usize, name: &'static str) -> Option<PinnedCredential> {
        if self.failure().is_some() || !matches!(self.post, Some(Ok(()))) { return None; }
        self.originals.get_mut(index)?.take_pin(name)
    }

    pub(crate) fn settle_positive_native_once(&mut self) -> Result<(), ()> {
        if self.settled || self.failure().is_some()
            || !matches!(self.capture, Some(Ok(()))) || !matches!(self.post, Some(Ok(())))
        {
            return Err(());
        }
        self.settled = true;
        // Typed wrappers park their same normal output before this actual
        // disposal. The completed original cannot be retried or rearmed.
        self.original_directory.open = None;
        self.named_directory.open = None;
        for slot in self.originals.iter_mut().chain(self.named.iter_mut()) {
            slot.file = None;
            slot.bytes = None;
            slot.open = None;
        }
        Ok(())
    }

    pub(crate) fn capture_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if matches!(self.capture, Some(Err(_))) {
            if let Some(cause) = self.original_directory.failure() { return Some(cause); }
            for slot in &self.originals {
                if let Some(cause) = slot.failure() { return Some(cause); }
            }
            return self.capture.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static));
        }
        None
    }

    pub(crate) fn post_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if matches!(self.post, Some(Err(_))) {
            // Native post errors are ordered as the actual recipe, rather
            // than by a later coarse comparison/projection marker.
            if let Some(Err(cause)) = &self.original_directory_posts[0] { return Some(cause); }
            if let Some(cause) = self.named_directory.failure() { return Some(cause); }
            for (posts, named) in self.original_file_posts.iter().zip(&self.named) {
                if let Some(Err(cause)) = &posts[0] { return Some(cause); }
                if let Some(cause) = named.failure() { return Some(cause); }
                if let Some(Err(cause)) = &posts[1] { return Some(cause); }
            }
            if let Some(Err(cause)) = &self.original_directory_posts[1] { return Some(cause); }
            return self.post.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static));
        }
        self.closed.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.capture_failure().or_else(|| self.post_failure())
    }
}

fn require_same_stat(observed: &Option<NativeStat>, expected: Option<FileIdentity>) -> Result<(), StorageServiceError> {
    let observed = observed.as_ref().and_then(|result| result.as_ref().ok())
        .ok_or_else(|| invalid("initial credential metadata failed"))?;
    if Some(identity(observed)) != expected {
        return Err(invalid("initial credential metadata changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn missing_read_keeps_the_actual_errno_when_the_name_later_appears() {
        let directory = tempfile::tempdir().unwrap();
        let root = rustix::fs::open(
            directory.path(), OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ).unwrap();
        let mut slot = FileRead::default();
        slot.capture(&root, "missing", 160);
        let first = slot.open.as_ref().unwrap().as_ref().unwrap_err() as *const _;
        assert_eq!(*slot.open.as_ref().unwrap().as_ref().unwrap_err(), rustix::io::Errno::NOENT);
        assert!(slot.before.is_none());
        assert!(slot.bytes.is_none());

        std::fs::write(directory.path().join("missing"), [7_u8; 160]).unwrap();
        slot.capture(&root, "missing", 160);

        assert_eq!(slot.open.as_ref().unwrap().as_ref().unwrap_err() as *const _, first);
        let retained = slot.failure().unwrap().downcast_ref::<rustix::io::Errno>().unwrap();
        assert_eq!(retained as *const _, first);
        assert!(slot.before.is_none());
        assert!(slot.bytes.is_none());
    }

    #[test]
    fn protection_failure_retains_actual_open_and_metadata_without_allocating_input() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        std::fs::write(&path, [7_u8; 160]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let root = rustix::fs::open(
            directory.path(), OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ).unwrap();
        let mut slot = FileRead::default();

        // Real unsafe native input; this does not construct protected role
        // authority or claim a genuine Storage receiving admission.
        slot.capture(&root, "key", 160);

        assert!(matches!(slot.completion, Some(Err(_))));
        assert!(matches!(slot.before, Some(Ok(_))));
        assert!(slot.file.is_none());
        assert!(slot.bytes.is_none());
        let original = slot.open.as_ref().unwrap().as_ref().unwrap();
        let descriptor = original.as_raw_fd();
        assert_eq!(rustix::fs::fstat(original).unwrap().st_ino,
            slot.before.as_ref().unwrap().as_ref().unwrap().st_ino);
        let first = slot.completion.as_ref().unwrap().as_ref().unwrap_err() as *const _;

        // Reentry cannot reopen, replace or discard the reached prefix.
        slot.capture(&root, "missing", 160);

        assert_eq!(slot.completion.as_ref().unwrap().as_ref().unwrap_err() as *const _, first);
        assert_eq!(slot.open.as_ref().unwrap().as_ref().unwrap().as_raw_fd(), descriptor);
    }

}
