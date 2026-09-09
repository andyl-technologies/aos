//! Descriptor-relative observation of already-published fs-verity inodes.
//!
//! This boundary returns the actual Linux SHA-256 fs-verity measurement. It
//! does not authenticate expected content or prove that mandatory access
//! control protects the retained final directory. Callers must independently
//! supply that authority before decoding the observed bytes as protected state.

use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use super::{
    FsVerityPublicationRoot, PrivateIdentity, PublicationName, PublicationRootError, inspect_root,
    is_kernel_verity_filesystem, strict_resolution,
};
use crate::Error;
use crate::immutable_file::FsVerityDigest;
use crate::uapi::{self, OpenHow};

/// Reports failure to observe one already-published sealed inode.
#[derive(Debug, thiserror::Error)]
pub enum ObserveSealedPublicationError {
    /// A Linux descriptor or filesystem operation failed.
    #[error("sealed-publication observation failed: {0}")]
    Linux(#[from] Error),
    /// The published inode exceeds the caller's explicit read ceiling.
    #[error("sealed publication exceeds its configured byte ceiling")]
    ByteLimitExceeded,
    /// The named inode violates the exact regular-file protection contract.
    #[error("sealed publication inode protection invariant failed")]
    InodeInvariant,
    /// The kernel measurement is not the required SHA-256 fs-verity profile.
    #[error("sealed publication has an unexpected fs-verity measurement profile")]
    UnexpectedMeasurement,
    /// The retained root, name, inode identity, or measurement changed during observation.
    #[error("sealed publication changed during observation")]
    AdmissionRace,
}

/// Pins one named, read-only inode with an observed SHA-256 fs-verity seal.
///
/// The actual measurement is observation data, not externally authenticated
/// content identity. This type proves only that the exact returned descriptor
/// was reached beneath the retained root under the publication invariants and
/// was already sealed when observed. A higher layer must independently
/// authenticate the final-directory provenance and decoded record semantics.
#[derive(Debug)]
pub struct ObservedSealedPublicationFile<'root> {
    file: OwnedFd,
    _root: &'root FsVerityPublicationRoot,
    name: PublicationName,
    identity: PrivateIdentity,
    verity: FsVerityDigest,
}

impl ObservedSealedPublicationFile<'_> {
    /// Returns the exact basename resolved beneath the retained root.
    #[must_use]
    pub fn name(&self) -> &PublicationName {
        &self.name
    }

    /// Returns the observed byte length after caller-ceiling admission.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.identity.bytes
    }

    /// Returns the session-local device number.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.identity.device
    }

    /// Returns the session-local inode number.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.identity.inode
    }

    /// Returns the actual SHA-256 fs-verity measurement observed from Linux.
    ///
    /// The caller must not treat this value as independently authenticated
    /// expected content.
    #[must_use]
    pub const fn observed_verity_digest(&self) -> FsVerityDigest {
        self.verity
    }
}

impl AsFd for ObservedSealedPublicationFile<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl FsVerityPublicationRoot {
    /// Opens one exact final name and observes its existing fs-verity seal.
    ///
    /// Resolution is descriptor-relative and rejects traversal, symlinks,
    /// magic links, and mount crossings. The named inode must be a read-only
    /// opened, current-user-owned regular file of exact mode 0600 and link
    /// count one. Its size is rejected before a caller can allocate or read its
    /// bytes. The root, name-to-inode binding, inode identity, and actual
    /// SHA-256 fs-verity measurement are rechecked before return.
    ///
    /// This is an observation API. The returned actual measurement does not
    /// authenticate expected content or prove that a mandatory-access-control
    /// policy protects the final directory.
    ///
    /// # Errors
    ///
    /// Returns `Ok(None)` only when the initial exact-name open returns
    /// `ENOENT` and the retained root remains exact. Every other open failure,
    /// a later disappearance, an oversized file, missing or non-SHA-256
    /// fs-verity, protection mismatch, or observation race is an error.
    pub fn open_named_sealed<'root>(
        &'root self,
        name: &PublicationName,
        maximum_bytes: u64,
    ) -> Result<Option<ObservedSealedPublicationFile<'root>>, ObserveSealedPublicationError> {
        self.recheck_observation_root()?;
        let file = match open_published_name(self, name) {
            Ok(file) => file,
            Err(error) if syscall_errno(&error) == Some(libc::ENOENT) => {
                self.recheck_observation_root()?;
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let identity = inspect_observed_publication(file.as_fd(), maximum_bytes)?;
        let verity = observed_sha256_verity(file.as_fd())?;

        validate_reopened_observation(
            identity,
            verity,
            || {
                let named = open_published_name(self, name)?;
                Ok((
                    inspect_observed_publication(named.as_fd(), maximum_bytes)?,
                    observed_sha256_verity(named.as_fd())?,
                ))
            },
            || self.recheck_observation_root(),
            || {
                Ok((
                    inspect_observed_publication(file.as_fd(), maximum_bytes)?,
                    observed_sha256_verity(file.as_fd())?,
                ))
            },
        )?;

        Ok(Some(ObservedSealedPublicationFile {
            file: file.into(),
            _root: self,
            name: name.clone(),
            identity,
            verity,
        }))
    }

    fn recheck_observation_root(&self) -> Result<(), ObserveSealedPublicationError> {
        let observed = inspect_root(self.directory.as_fd()).map_err(|error| match error {
            PublicationRootError::Linux(error) => ObserveSealedPublicationError::Linux(error),
            _ => ObserveSealedPublicationError::AdmissionRace,
        })?;
        if observed != self.identity
            || !is_kernel_verity_filesystem(uapi::filesystem_type(self.directory.as_fd())?)
        {
            return Err(ObserveSealedPublicationError::AdmissionRace);
        }
        Ok(())
    }
}

fn validate_reopened_observation<E>(
    expected_identity: PrivateIdentity,
    expected_verity: FsVerityDigest,
    reopen_name: impl FnOnce() -> Result<(PrivateIdentity, FsVerityDigest), E>,
    recheck_root: impl FnOnce() -> Result<(), E>,
    recheck_pinned: impl FnOnce() -> Result<(PrivateIdentity, FsVerityDigest), E>,
) -> Result<(), E>
where
    E: From<ObserveSealedPublicationError>,
{
    if reopen_name()? != (expected_identity, expected_verity) {
        return Err(ObserveSealedPublicationError::AdmissionRace.into());
    }
    recheck_root()?;
    if recheck_pinned()? != (expected_identity, expected_verity) {
        return Err(ObserveSealedPublicationError::AdmissionRace.into());
    }
    Ok(())
}

fn open_published_name(
    root: &FsVerityPublicationRoot,
    name: &PublicationName,
) -> Result<File, Error> {
    let flags = u64::try_from(
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
    )
    .map_err(|_| Error::invalid("open flags", "platform flag conversion failed"))?;
    uapi::openat2(
        root.directory.as_fd(),
        name.as_c_str(),
        &OpenHow {
            flags,
            mode: 0,
            resolve: strict_resolution(),
        },
    )
    .map(File::from)
}

fn inspect_observed_publication(
    file: BorrowedFd<'_>,
    maximum_bytes: u64,
) -> Result<PrivateIdentity, ObserveSealedPublicationError> {
    let stat = uapi::fstat(file)?;
    let bytes = u64::try_from(stat.st_size)
        .map_err(|_| ObserveSealedPublicationError::ByteLimitExceeded)?;
    if bytes > maximum_bytes {
        return Err(ObserveSealedPublicationError::ByteLimitExceeded);
    }
    let flags = uapi::get_status_flags(file)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != uapi::effective_uid()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || flags & libc::O_ACCMODE != libc::O_RDONLY
        || flags & libc::O_PATH != 0
    {
        return Err(ObserveSealedPublicationError::InodeInvariant);
    }
    Ok(PrivateIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        bytes,
    })
}

fn observed_sha256_verity(
    file: BorrowedFd<'_>,
) -> Result<FsVerityDigest, ObserveSealedPublicationError> {
    let measurement = uapi::measure_verity(file)?;
    if measurement.algorithm != 1 || measurement.length != 32 {
        return Err(ObserveSealedPublicationError::UnexpectedMeasurement);
    }
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&measurement.digest[..32]);
    Ok(FsVerityDigest::Sha256(digest))
}

fn syscall_errno(error: &Error) -> Option<i32> {
    match error {
        Error::Syscall { source, .. } => source.raw_os_error(),
        Error::InvalidInput { .. }
        | Error::WrongDescriptorType { .. }
        | Error::MalformedKernelResponse { .. }
        | Error::ObservationLimitExceeded { .. }
        | Error::DeadlineExceeded { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ffi::OsStr;
    use std::io;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn test_root(directory: &File) -> FsVerityPublicationRoot {
        FsVerityPublicationRoot {
            identity: inspect_root(directory.as_fd()).unwrap(),
            directory: directory.as_fd().try_clone_to_owned().unwrap(),
        }
    }

    fn identity(seed: u64) -> PrivateIdentity {
        PrivateIdentity {
            device: seed,
            inode: seed * 10,
            bytes: seed * 100,
        }
    }

    #[test]
    fn exact_open_distinguishes_absence_and_rejects_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let directory = File::open(temp.path()).unwrap();
        let root = test_root(&directory);
        let missing = PublicationName::new(OsStr::new("missing")).unwrap();
        let target = PublicationName::new(OsStr::new("target")).unwrap();
        std::fs::write(temp.path().join("target"), b"record").unwrap();
        std::os::unix::fs::symlink("target", temp.path().join("link")).unwrap();
        let link = PublicationName::new(OsStr::new("link")).unwrap();

        let missing = open_published_name(&root, &missing).unwrap_err();
        assert_eq!(syscall_errno(&missing), Some(libc::ENOENT));
        assert!(open_published_name(&root, &target).is_ok());
        let link = open_published_name(&root, &link).unwrap_err();
        assert_ne!(syscall_errno(&link), Some(libc::ENOENT));
    }

    #[test]
    fn size_is_admitted_before_read_and_exact_inode_protection_is_required() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("published");
        std::fs::write(&path, b"record").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let file = File::open(&path).unwrap();

        let observed = inspect_observed_publication(file.as_fd(), 6).unwrap();
        assert_eq!(observed.bytes, 6);
        assert!(matches!(
            inspect_observed_publication(file.as_fd(), 5),
            Err(ObserveSealedPublicationError::ByteLimitExceeded)
        ));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            inspect_observed_publication(file.as_fd(), 6),
            Err(ObserveSealedPublicationError::InodeInvariant)
        ));
    }

    #[test]
    fn extra_links_and_non_readonly_descriptions_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("published");
        std::fs::write(&path, b"record").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let other = temp.path().join("other-name");
        std::fs::hard_link(&path, &other).unwrap();
        let file = File::open(&path).unwrap();

        assert!(matches!(
            inspect_observed_publication(file.as_fd(), 6),
            Err(ObserveSealedPublicationError::InodeInvariant)
        ));

        std::fs::remove_file(other).unwrap();
        let writable = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        assert!(matches!(
            inspect_observed_publication(writable.as_fd(), 6),
            Err(ObserveSealedPublicationError::InodeInvariant)
        ));
    }

    #[test]
    fn ordinary_unsealed_file_never_becomes_observed_seal_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("unsealed");
        std::fs::write(&path, b"record").unwrap();
        let file = File::open(path).unwrap();

        assert!(matches!(
            observed_sha256_verity(file.as_fd()),
            Err(ObserveSealedPublicationError::Linux(_))
        ));
    }

    #[test]
    fn reopen_root_and_pinned_races_are_each_rejected() {
        let expected_identity = identity(1);
        let expected_verity = FsVerityDigest::Sha256([2; 32]);
        for mismatch in 0..3 {
            let result = validate_reopened_observation(
                expected_identity,
                expected_verity,
                || {
                    Ok::<_, ObserveSealedPublicationError>(if mismatch == 0 {
                        (identity(3), expected_verity)
                    } else {
                        (expected_identity, expected_verity)
                    })
                },
                || {
                    if mismatch == 1 {
                        Err(ObserveSealedPublicationError::AdmissionRace)
                    } else {
                        Ok(())
                    }
                },
                || {
                    Ok(if mismatch == 2 {
                        (expected_identity, FsVerityDigest::Sha256([4; 32]))
                    } else {
                        (expected_identity, expected_verity)
                    })
                },
            );
            assert!(matches!(
                result,
                Err(ObserveSealedPublicationError::AdmissionRace)
            ));
        }
    }

    #[test]
    fn only_enoent_is_absence_and_resolution_rejects_mount_crossings() {
        let missing = Error::Syscall {
            operation: "openat2 published inode",
            source: io::Error::from_raw_os_error(libc::ENOENT),
        };
        let denied = Error::Syscall {
            operation: "openat2 published inode",
            source: io::Error::from_raw_os_error(libc::EACCES),
        };

        assert_eq!(syscall_errno(&missing), Some(libc::ENOENT));
        assert_eq!(syscall_errno(&denied), Some(libc::EACCES));
        assert_eq!(syscall_errno(&Error::invalid("name", "invalid")), None);
        assert_ne!(strict_resolution() & crate::uapi::RESOLVE_NO_XDEV, 0);
    }
}
