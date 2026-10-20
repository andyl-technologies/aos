//! Retains selected protected-root recheck descriptors through negative posts.
//!
//! The ordinary absolute opener consumes the same recipe immediately, dropping
//! its slash anchor before returning the reopened directory as before. Selected
//! callers retain both descriptors and every actual error; this supplies no
//! publication admission, resource permit or replacement root constructor.

use super::*;

#[derive(Default)]
pub(super) struct AbsoluteDirectoryOriginalsV1 {
    // The old absolute opener drops its slash anchor before yielding the
    // reopened descriptor. The consuming adapter preserves that order.
    root: Option<File>,
    opened: Option<OwnedFd>,
    // Field drop follows declaration order. Keep the CString after the root
    // so failed ordinary opens close their anchor before freeing the path,
    // matching the prior reverse-local lifetime schedule.
    path: Option<CString>,
    result: Option<Result<(), PublicationRootError>>,
}

impl AbsoluteDirectoryOriginalsV1 {
    pub(super) fn capture_once(&mut self, path: &Path) {
        if self.result.is_some() { return; }
        self.result = Some(self.capture_inner(path));
    }

    fn capture_inner(&mut self, path: &Path) -> Result<(), PublicationRootError> {
        let relative = path.strip_prefix(Path::new("/"))
            .map_err(|_| PublicationRootError::AdmissionRace)?;
        if relative.as_os_str().is_empty() || relative.as_os_str().as_bytes().len() > 4096 {
            return Err(PublicationRootError::AdmissionRace);
        }
        self.path = Some(CString::new(relative.as_os_str().as_bytes())
            .map_err(|_| PublicationRootError::AdmissionRace)?);
        self.root = Some(File::open("/")
            .map_err(|source| PublicationRootError::Linux(io_error("open root directory", source)))?);
        let root = self.root.as_ref().ok_or(PublicationRootError::AdmissionRace)?;
        let flags = u64::try_from(libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC
            | libc::O_NOFOLLOW | libc::O_NOCTTY).map_err(|_| PublicationRootError::AdmissionRace)?;
        let path = self.path.as_ref().ok_or(PublicationRootError::AdmissionRace)?;
        self.opened = Some(uapi::openat2(root.as_fd(), path, &OpenHow {
            flags, mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        }).map_err(PublicationRootError::Linux)?);
        Ok(())
    }

    pub(super) fn into_result(mut self) -> Result<OwnedFd, PublicationRootError> {
        let result = self.result.take().ok_or(PublicationRootError::AdmissionRace)?;
        result?;
        // Dispose the actual anchor before yielding the opened child, exactly
        // as the prior local-root expression did on the ordinary path.
        self.root = None;
        self.opened.take().ok_or(PublicationRootError::AdmissionRace)
    }

    fn failure(&self) -> Option<&PublicationRootError> {
        self.result.as_ref().and_then(|result| result.as_ref().err())
    }
}

/// Retains one actual protected publication-root recheck and its native errors.
///
/// Empty construction performs no IO and grants no authority. A selected
/// caller must fund this fixed descriptor/path carrier before capture and keep
/// it through every required independent post after a failed check.
#[derive(Default)]
pub struct PublicationRootRecheckOriginalsV1 {
    opening: AbsoluteDirectoryOriginalsV1,
    identity: Option<Result<RootIdentity, PublicationRootError>>,
    filesystem: Option<Result<libc::c_long, Error>>,
    result: Option<Result<(), PublicationRootError>>,
}

impl PublicationRootRecheckOriginalsV1 {
    /// Creates an inert once-only destination without opening a file.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Borrows the earliest actual native or comparison failure.
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.opening.failure().map(|error| error as _)
            .or_else(|| self.identity.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.filesystem.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
    }

    /// Counts the fresh descriptors still owned by this actual destination.
    #[must_use]
    pub fn retained_file_count(&self) -> usize {
        usize::from(self.opening.root.is_some()) + usize::from(self.opening.opened.is_some())
    }
}

impl FsVerityPublicationRoot {
    /// Rechecks this same admitted root into a selected resident destination.
    ///
    /// # Errors
    /// Refuses reentry or a changed protected root. The actual opening,
    /// identity and filesystem cause remains in `original`; returned
    /// `AdmissionRace` is only a coarse projection after that retained result.
    pub fn recheck_protected_path_into(
        &self,
        original: &mut PublicationRootRecheckOriginalsV1,
    ) -> Result<(), PublicationRootError> {
        if original.result.is_some() { return Err(PublicationRootError::AdmissionRace); }
        original.result = Some((|| {
            let path = self.protected_path.as_deref().ok_or(PublicationRootError::AdmissionRace)?;
            original.opening.capture_once(path);
            if original.opening.failure().is_some() { return Err(PublicationRootError::AdmissionRace); }
            let opened = original.opening.opened.as_ref().ok_or(PublicationRootError::AdmissionRace)?;
            original.identity = Some(inspect_root(opened.as_fd()));
            let identity = original.identity.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(PublicationRootError::AdmissionRace)?;
            if *identity != self.identity { return Err(PublicationRootError::AdmissionRace); }
            original.filesystem = Some(uapi::filesystem_type(opened.as_fd()));
            let filesystem = original.filesystem.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(PublicationRootError::AdmissionRace)?;
            if !is_kernel_verity_filesystem(*filesystem) { return Err(PublicationRootError::AdmissionRace); }
            Ok(())
        })());
        if matches!(original.result, Some(Ok(()))) { Ok(()) }
        else { Err(PublicationRootError::AdmissionRace) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_absolute_open_retains_actual_slash_anchor_and_native_cause_without_retry() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("absent-native-child");
        let mut original = AbsoluteDirectoryOriginalsV1::default();

        original.capture_once(&missing);

        assert!(original.root.is_some());
        assert!(original.path.is_some());
        assert!(original.opened.is_none());
        let cause = original.failure().unwrap() as *const PublicationRootError;
        original.capture_once(directory.path());
        assert!(std::ptr::eq(original.failure().unwrap(), cause));
        assert!(original.root.is_some());
        assert!(original.opened.is_none());
    }

    #[test]
    fn ordinary_absolute_adapter_returns_the_same_actual_opened_directory() {
        let directory = tempfile::tempdir().unwrap();
        let opened = open_protected_absolute_directory(directory.path()).unwrap();
        let expected = std::fs::metadata(directory.path()).unwrap();
        use std::os::unix::fs::MetadataExt as _;
        let actual = uapi::fstat(opened.as_fd()).unwrap();
        assert_eq!(actual.st_dev, expected.dev());
        assert_eq!(actual.st_ino, expected.ino());
    }
}
