//! Owned, same-descriptor admission of fs-verity backing files.
//!
//! This module proves a kernel immutability measurement and exact size, not
//! publication authorization or permission to disclose the resulting bytes.

use std::marker::PhantomData;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use super::{FsVerityDigest, ImmutableFileError, ObservedFile, inspect, measurement_matches};
use crate::path::BeneathRoot;
use crate::uapi;

/// Pins a read-only file whose fs-verity measurement and size were verified.
///
/// The expected measurement must come from independent authenticated data;
/// an AOS content digest is not an fs-verity measurement. This type does not
/// authenticate that data, authorize publication or disclosure, assign a cache
/// domain, or register a FUSE backing. Those checks belong to the caller's
/// authority boundary before using the descriptor. No pathname or device/inode
/// tuple becomes durable authorization through this API.
///
/// Fs-verity protects file contents, not mutable ownership, mode bits or xattrs.
/// A broker must independently bind the presentation policy before registering
/// this backing. Read-only access describes this file description only; it does
/// not prove mount flags or restrict credentials used by a later kernel reopen.
///
/// The descriptor stays owned by this non-`Clone` value. Safe callers can
/// borrow it and explicitly duplicate it through normal descriptor APIs;
/// this is not a revocable capability. Dropping this value, or issuing FUSE
/// `BACKING_CLOSE` for a later registration, does not revoke other descriptors
/// or existing kernel opens and mappings. Later storage corruption can still
/// make reads fail despite successful admission.
///
/// ```compile_fail
/// use aos_sandbox_linux::immutable_file::FsVerityBacking;
/// use std::os::fd::{AsFd, BorrowedFd};
/// fn escape(backing: FsVerityBacking) -> BorrowedFd<'static> {
///     backing.as_fd()
/// }
/// ```
///
/// ```compile_fail
/// use aos_sandbox_linux::immutable_file::FsVerityBacking;
/// fn duplicate(backing: FsVerityBacking) -> FsVerityBacking {
///     backing.clone()
/// }
/// ```
#[derive(Debug)]
pub struct FsVerityBacking {
    file: OwnedFd,
    observed: ObservedFile,
}

impl FsVerityBacking {
    /// Opens and verifies one descendant of a pinned root without mapping it.
    ///
    /// Resolution rejects symlinks, magic links, traversal outside the root,
    /// and mount crossings. The file is opened once, read-only and close-on-exec.
    /// Size and measurement are checked on that same descriptor; identity,
    /// size and measurement are rechecked before returning. No successful
    /// validation is followed by reopening a pathname.
    /// The same-descriptor filesystem check admits only the kernel fs-verity
    /// implementations documented by the parent module, never FUSE or overlay.
    ///
    /// `maximum_bytes` is a hard admission ceiling, independent of address-space
    /// mapping limits. The expected size is checked against it before opening.
    /// Zero-byte files are allowed when their measured seal and size match.
    ///
    /// # Errors
    ///
    /// Returns an error for size admission, unsafe resolution, a nonregular or
    /// non-read-only descriptor, missing or mismatched fs-verity, Linux operation
    /// failure, or an identity/size/measurement change during admission.
    pub fn open_beneath(
        root: &BeneathRoot,
        relative: &Path,
        expected_verity: FsVerityDigest,
        expected_bytes: u64,
        maximum_bytes: u64,
    ) -> Result<Self, ImmutableFileError> {
        if expected_bytes > maximum_bytes {
            return Err(ImmutableFileError::BackingLimitExceeded);
        }

        let file = root.open_regular(relative)?.into_owned_fd();
        let before = inspect_read_only(file.as_fd())?;
        if before.bytes != expected_bytes {
            return Err(ImmutableFileError::SizeMismatch);
        }
        if !measurement_matches(file.as_fd(), expected_verity)? {
            return Err(ImmutableFileError::VerityMeasurementMismatch);
        }

        if inspect_read_only(file.as_fd())? != before
            || !measurement_matches(file.as_fd(), expected_verity)?
        {
            return Err(ImmutableFileError::AdmissionRace);
        }

        Ok(Self {
            file,
            observed: before,
        })
    }

    /// Returns kernel identity diagnostics tied to this descriptor's borrow.
    #[must_use]
    pub fn identity(&self) -> BackingFileIdentity<'_> {
        BackingFileIdentity {
            observed: self.observed,
            backing: PhantomData,
        }
    }
}

impl AsFd for FsVerityBacking {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

/// Describes the inode pinned by one borrowed verified backing descriptor.
///
/// Device and inode numbers are kernel-session diagnostics, not publication
/// identities or recovery authority. Their relevance ends with the descriptor
/// pin. The borrow prevents this value from outliving that pin; copying numeric
/// fields does not turn them into durable identity.
///
/// ```compile_fail
/// use aos_sandbox_linux::immutable_file::{BackingFileIdentity, FsVerityBacking};
/// fn escape(backing: FsVerityBacking) -> BackingFileIdentity<'static> {
///     backing.identity()
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackingFileIdentity<'backing> {
    observed: ObservedFile,
    backing: PhantomData<&'backing FsVerityBacking>,
}

impl BackingFileIdentity<'_> {
    /// Returns the kernel-session device number.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.observed.device
    }

    /// Returns the kernel-session inode number.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.observed.inode
    }

    /// Returns the exact admitted file length.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.observed.bytes
    }
}

fn inspect_read_only(fd: BorrowedFd<'_>) -> Result<ObservedFile, ImmutableFileError> {
    let observed = inspect(fd)?;
    if observed.file_type != libc::S_IFREG {
        return Err(ImmutableFileError::NotRegular);
    }
    let flags = uapi::get_status_flags(fd)?;
    if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_PATH != 0 {
        return Err(ImmutableFileError::DescriptorNotReadOnly);
    }
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;

    use super::*;

    fn candidate() -> (tempfile::TempDir, BeneathRoot) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("file"), b"bytes").unwrap();
        let root = BeneathRoot::from_owned(File::open(temp.path()).unwrap().into()).unwrap();
        (temp, root)
    }

    #[test]
    fn size_ceiling_is_checked_before_path_resolution() {
        let (_temp, root) = candidate();
        assert!(matches!(
            FsVerityBacking::open_beneath(
                &root,
                Path::new("missing"),
                FsVerityDigest::Sha256([0; 32]),
                u64::MAX,
                4096,
            ),
            Err(ImmutableFileError::BackingLimitExceeded)
        ));
    }

    #[test]
    fn exact_size_is_checked_before_verity_measurement() {
        let (_temp, root) = candidate();
        for size in [0, 4, 6] {
            assert!(matches!(
                FsVerityBacking::open_beneath(
                    &root,
                    Path::new("file"),
                    FsVerityDigest::Sha256([0; 32]),
                    size,
                    4096,
                ),
                Err(ImmutableFileError::SizeMismatch)
            ));
        }
    }

    #[test]
    fn ordinary_files_never_gain_verity_authority() {
        let (temp, root) = candidate();
        std::fs::write(temp.path().join("empty"), []).unwrap();
        for (name, size) in [("file", 5), ("empty", 0)] {
            assert!(matches!(
                FsVerityBacking::open_beneath(
                    &root,
                    Path::new(name),
                    FsVerityDigest::Sha256([0; 32]),
                    size,
                    size,
                ),
                Err(ImmutableFileError::Linux(_) | ImmutableFileError::UnsupportedVerityFilesystem)
            ));
        }
    }

    #[test]
    fn unsafe_paths_and_nonregular_candidates_are_rejected() {
        let (temp, root) = candidate();
        std::os::unix::fs::symlink("file", temp.path().join("link")).unwrap();
        std::fs::create_dir(temp.path().join("directory")).unwrap();
        for name in ["link", "../file", "/file", "directory"] {
            assert!(
                matches!(
                    FsVerityBacking::open_beneath(
                        &root,
                        Path::new(name),
                        FsVerityDigest::Sha256([0; 32]),
                        5,
                        4096,
                    ),
                    Err(ImmutableFileError::Linux(_))
                ),
                "accepted candidate {name}"
            );
        }
    }

    #[test]
    fn descriptor_precheck_requires_read_only_regular_access() {
        let (temp, root) = candidate();
        let readonly = root
            .open_regular(Path::new("file"))
            .unwrap()
            .into_owned_fd();
        let observed = inspect_read_only(readonly.as_fd()).unwrap();
        assert_eq!(observed.bytes, 5);
        let direct = inspect(readonly.as_fd()).unwrap();
        assert_eq!(observed, direct);

        for flags in [libc::O_WRONLY, libc::O_RDWR, libc::O_PATH] {
            let mut options = OpenOptions::new();
            options
                .read(flags != libc::O_WRONLY)
                .write(flags != libc::O_PATH);
            if flags == libc::O_PATH {
                options.custom_flags(libc::O_PATH);
            }
            let file = options.open(temp.path().join("file")).unwrap();
            assert!(matches!(
                inspect_read_only(file.as_fd()),
                Err(ImmutableFileError::DescriptorNotReadOnly)
            ));
        }
        let directory = File::open(temp.path()).unwrap();
        assert!(matches!(
            inspect_read_only(directory.as_fd()),
            Err(ImmutableFileError::NotRegular)
        ));
    }
}
