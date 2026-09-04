//! Scoped, read-only mappings of seal-proven immutable files.
//!
//! This generic Linux boundary distinguishes transient fully sealed memfds
//! from durable fs-verity files. It owns no filesystem-view semantics and does
//! not authenticate an AOS object descriptor. A caller composes validation
//! inside the higher-ranked scoped callback and may retain borrowed validated
//! state for that callback's complete worker loop; safe code cannot let bytes
//! escape after the mapping is dropped.
//!
//! Read-only mode bits, a read-only descriptor, a pathname, or a content hash
//! alone is not an immutability proof. Filesystem-snapshot proofs require a
//! separate backend type and are not implemented here.

use std::marker::PhantomData;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::ptr::NonNull;

use crate::path::BeneathRoot;
use crate::{Error, uapi};

/// Describes the inode pinned for one scoped immutable mapping.
///
/// Device and inode numbers are session-local diagnostics meaningful only
/// while the callback holds the pin. They are never durable catalog identity
/// and must not be persisted for recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImmutableFileIdentity<'mapping> {
    device: u64,
    inode: u64,
    bytes: u64,
    mapping: PhantomData<&'mapping [u8]>,
}

impl ImmutableFileIdentity<'_> {
    /// Returns the session-local device number.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the session-local inode number.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Returns the exact admitted byte length.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// Authenticated fs-verity measurement expected for a durable inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsVerityDigest {
    /// Linux fs-verity hash algorithm 1.
    Sha256([u8; 32]),
    /// Linux fs-verity hash algorithm 2.
    Sha512([u8; 64]),
}

impl FsVerityDigest {
    fn matches(self, algorithm: u16, digest: &[u8]) -> bool {
        match self {
            Self::Sha256(expected) => algorithm == 1 && digest == expected,
            Self::Sha512(expected) => algorithm == 2 && digest == expected,
        }
    }
}

/// Reports immutable-file opening, mapping, or proof failure.
#[derive(Debug, thiserror::Error)]
pub enum ImmutableFileError {
    /// A Linux descriptor or mapping operation failed.
    #[error("immutable-file Linux operation failed: {0}")]
    Linux(#[from] Error),
    /// The descriptor does not name a regular file.
    #[error("immutable-file descriptor is not a regular file")]
    NotRegular,
    /// The descriptor cannot be read through this file description.
    #[error("immutable-file descriptor is write-only")]
    WriteOnlyDescriptor,
    /// The memfd lacks one or more seals required to prove stable bytes.
    #[error("memfd lacks required write/grow/shrink/seal protection")]
    MissingSeals,
    /// The file size differs from the authenticated expected size.
    #[error("immutable-file size differs from the authenticated expected size")]
    SizeMismatch,
    /// The expected size exceeds the mapping admission ceiling.
    #[error("immutable-file mapping exceeds its configured byte ceiling")]
    MappingLimitExceeded,
    /// The pinned file identity, size, or proof changed during admission.
    #[error("immutable file changed during mapping admission")]
    AdmissionRace,
    /// The fs-verity measurement differs from publication authority.
    #[error("fs-verity measurement does not match publication authority")]
    VerityMeasurementMismatch,
}

/// Opens scoped mappings of transient, fully sealed memfds.
///
/// Memfds are not durable cache-publication authority. Both `O_RDONLY` and
/// `O_RDWR` handoffs are accepted after the complete seal set is proven; the
/// latter cannot modify the sealed inode. `F_SEAL_FUTURE_WRITE` is not accepted
/// in place of `F_SEAL_WRITE`.
///
/// ```compile_fail
/// use std::os::fd::OwnedFd;
/// use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
///
/// fn escape(file: OwnedFd) -> &'static [u8] {
///     SealedMemfdMapping::run(file, 5, 5, |bytes, _| bytes).unwrap()
/// }
/// ```
pub struct SealedMemfdMapping;

impl SealedMemfdMapping {
    /// Runs one callback with the exact bytes of a sealed memfd.
    ///
    /// The callback should authenticate and validate the bytes before serving
    /// them. Its higher-ranked lifetime prevents the slice, or validation
    /// proofs borrowing it, from escaping the mapping session.
    ///
    /// # Errors
    ///
    /// Returns [`ImmutableFileError`] for type/access failures, incomplete
    /// seals, size admission, mapping failure, or an observation race.
    pub fn run<R, F>(
        file: OwnedFd,
        expected_bytes: u64,
        maximum_mapped_bytes: u64,
        use_bytes: F,
    ) -> Result<R, ImmutableFileError>
    where
        F: for<'mapping> FnOnce(&'mapping [u8], ImmutableFileIdentity<'mapping>) -> R,
    {
        uapi::ensure_cloexec(file.as_fd())?;
        let before = inspect(file.as_fd())?;
        if before.file_type != libc::S_IFREG {
            return Err(ImmutableFileError::NotRegular);
        }
        if uapi::get_status_flags(file.as_fd())? & libc::O_ACCMODE == libc::O_WRONLY {
            return Err(ImmutableFileError::WriteOnlyDescriptor);
        }
        let seals = uapi::get_seals(file.as_fd())?;
        if seals & uapi::REQUIRED_IMMUTABLE_SEALS != uapi::REQUIRED_IMMUTABLE_SEALS {
            return Err(ImmutableFileError::MissingSeals);
        }
        run_mapping(
            file,
            before,
            expected_bytes,
            maximum_mapped_bytes,
            use_bytes,
        )
    }
}

/// Opens scoped mappings of durable fs-verity-protected files.
///
/// The verity measurement is independent authenticated publication data. A
/// content descriptor or digest from the mapped candidate cannot substitute
/// for it.
pub struct FsVerityMapping;

impl FsVerityMapping {
    /// Opens one catalog descendant and runs a callback with its exact bytes.
    ///
    /// The file is opened once with beneath, no-magic-link, no-symlink, and
    /// no-mount-crossing resolution. The same descriptor is measured before
    /// and after mapping; the implementation never validates then reopens.
    ///
    /// If storage corruption is detected on a later mapped-page fault, Linux
    /// may deliver `SIGBUS`. Callers must run the callback in an isolated
    /// worker and treat its death as attachment failure; signal recovery is
    /// outside this API.
    ///
    /// # Errors
    ///
    /// Returns [`ImmutableFileError`] for resolution, size admission, a
    /// missing or mismatched verity measurement, mapping failure, or an
    /// observation race.
    pub fn run_beneath<R, F>(
        root: &BeneathRoot,
        relative: &Path,
        expected_verity: FsVerityDigest,
        expected_bytes: u64,
        maximum_mapped_bytes: u64,
        use_bytes: F,
    ) -> Result<R, ImmutableFileError>
    where
        F: for<'mapping> FnOnce(&'mapping [u8], ImmutableFileIdentity<'mapping>) -> R,
    {
        let file = root.open_regular(relative)?.into_owned_fd();
        let before = inspect(file.as_fd())?;
        if before.file_type != libc::S_IFREG {
            return Err(ImmutableFileError::NotRegular);
        }
        let measurement = uapi::measure_verity(file.as_fd())?;
        if !expected_verity.matches(
            measurement.algorithm,
            &measurement.digest[..measurement.length],
        ) {
            return Err(ImmutableFileError::VerityMeasurementMismatch);
        }

        run_mapping_with_postcheck(
            file,
            before,
            expected_bytes,
            maximum_mapped_bytes,
            use_bytes,
            |fd| {
                let measurement = uapi::measure_verity(fd)?;
                if expected_verity.matches(
                    measurement.algorithm,
                    &measurement.digest[..measurement.length],
                ) {
                    Ok(())
                } else {
                    Err(ImmutableFileError::AdmissionRace)
                }
            },
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObservedFile {
    device: u64,
    inode: u64,
    bytes: u64,
    file_type: libc::mode_t,
}

fn inspect(fd: BorrowedFd<'_>) -> Result<ObservedFile, ImmutableFileError> {
    let stat = uapi::fstat(fd)?;
    let bytes = u64::try_from(stat.st_size).map_err(|_| ImmutableFileError::SizeMismatch)?;
    Ok(ObservedFile {
        device: stat.st_dev,
        inode: stat.st_ino,
        bytes,
        file_type: stat.st_mode & libc::S_IFMT,
    })
}

fn run_mapping<R, F>(
    file: OwnedFd,
    before: ObservedFile,
    expected_bytes: u64,
    maximum_mapped_bytes: u64,
    use_bytes: F,
) -> Result<R, ImmutableFileError>
where
    F: for<'mapping> FnOnce(&'mapping [u8], ImmutableFileIdentity<'mapping>) -> R,
{
    run_mapping_with_postcheck(
        file,
        before,
        expected_bytes,
        maximum_mapped_bytes,
        use_bytes,
        |_| Ok(()),
    )
}

fn run_mapping_with_postcheck<R, F, P>(
    file: OwnedFd,
    before: ObservedFile,
    expected_bytes: u64,
    maximum_mapped_bytes: u64,
    use_bytes: F,
    postcheck: P,
) -> Result<R, ImmutableFileError>
where
    F: for<'mapping> FnOnce(&'mapping [u8], ImmutableFileIdentity<'mapping>) -> R,
    P: FnOnce(BorrowedFd<'_>) -> Result<(), ImmutableFileError>,
{
    if expected_bytes == 0 || expected_bytes > maximum_mapped_bytes {
        return Err(ImmutableFileError::MappingLimitExceeded);
    }
    if before.bytes != expected_bytes {
        return Err(ImmutableFileError::SizeMismatch);
    }
    let length =
        usize::try_from(expected_bytes).map_err(|_| ImmutableFileError::MappingLimitExceeded)?;
    let mapping = ReadOnlyMapping::new(file.as_fd(), length)?;
    let after = inspect(file.as_fd())?;
    if before != after {
        return Err(ImmutableFileError::AdmissionRace);
    }
    postcheck(file.as_fd())?;

    let identity = ImmutableFileIdentity {
        device: before.device,
        inode: before.inode,
        bytes: before.bytes,
        mapping: PhantomData,
    };
    Ok(use_bytes(mapping.bytes(), identity))
}

struct ReadOnlyMapping {
    address: NonNull<u8>,
    length: usize,
}

impl ReadOnlyMapping {
    fn new(fd: BorrowedFd<'_>, length: usize) -> Result<Self, Error> {
        let raw = uapi::map_readonly_shared(fd, length)?;
        let address = match NonNull::new(raw.cast::<u8>()) {
            Some(address) => address,
            None => {
                uapi::unmap(raw, length);
                return Err(Error::MalformedKernelResponse {
                    object: "mmap",
                    message: "kernel returned a null successful mapping".to_string(),
                });
            }
        };
        Ok(Self { address, length })
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: construction owns a readable mapping of exactly `length`
        // bytes. The caller-specific immutable proof prevents writes and size
        // changes, this type exposes no mutable reference, and drop unmaps only
        // after all callback borrows have ended.
        unsafe { std::slice::from_raw_parts(self.address.as_ptr(), self.length) }
    }
}

impl Drop for ReadOnlyMapping {
    fn drop(&mut self) {
        uapi::unmap(self.address.as_ptr().cast(), self.length);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::fd::{AsRawFd, OwnedFd};

    use super::*;

    fn memfd_with_seals(bytes: &[u8], seals: libc::c_int) -> (OwnedFd, OwnedFd) {
        let publisher =
            uapi::create_sealable_memfd().unwrap_or_else(|error| panic!("memfd failed: {error}"));
        let mut writer = File::from(
            uapi::duplicate_at_least(publisher.as_fd(), 0)
                .unwrap_or_else(|error| panic!("duplicate failed: {error}")),
        );
        writer
            .write_all(bytes)
            .unwrap_or_else(|error| panic!("write failed: {error}"));
        drop(writer);
        if seals != 0 {
            uapi::add_seals(publisher.as_fd(), seals)
                .unwrap_or_else(|error| panic!("seal failed: {error}"));
        }
        let reader: OwnedFd = OpenOptions::new()
            .read(true)
            .open(format!("/proc/self/fd/{}", publisher.as_raw_fd()))
            .unwrap_or_else(|error| panic!("read-only reopen failed: {error}"))
            .into();
        (publisher, reader)
    }

    fn memfd_with(bytes: &[u8], seal: bool) -> (OwnedFd, OwnedFd) {
        memfd_with_seals(
            bytes,
            if seal {
                uapi::REQUIRED_IMMUTABLE_SEALS
            } else {
                0
            },
        )
    }

    #[test]
    fn sealed_memfd_pins_exact_bytes_after_publisher_drop() {
        let expected = b"authenticated bytes";
        let (publisher, reader) = memfd_with(expected, true);
        SealedMemfdMapping::run(reader, expected.len() as u64, 4096, |bytes, identity| {
            drop(publisher);
            assert_eq!(bytes, expected);
            assert_eq!(identity.bytes(), expected.len() as u64);
        })
        .unwrap_or_else(|error| panic!("mapping failed: {error}"));
    }

    #[test]
    fn fully_sealed_read_write_handoff_is_safe_and_unsealed_is_rejected() {
        let bytes = b"index";
        let (writable, _reader) = memfd_with(bytes, true);
        SealedMemfdMapping::run(writable, bytes.len() as u64, 4096, |mapped, _| {
            assert_eq!(mapped, bytes);
        })
        .unwrap_or_else(|error| panic!("read-write sealed handoff failed: {error}"));

        let (_publisher, reader) = memfd_with(bytes, false);
        assert!(matches!(
            SealedMemfdMapping::run(reader, bytes.len() as u64, 4096, |_, _| ()),
            Err(ImmutableFileError::MissingSeals)
        ));

        const F_SEAL_FUTURE_WRITE: libc::c_int = 0x0010;
        let required = uapi::REQUIRED_IMMUTABLE_SEALS;
        for missing in [
            libc::F_SEAL_SEAL,
            libc::F_SEAL_SHRINK,
            libc::F_SEAL_GROW,
            libc::F_SEAL_WRITE,
        ] {
            let mut partial = required & !missing;
            if missing == libc::F_SEAL_WRITE {
                partial |= F_SEAL_FUTURE_WRITE;
            }
            let (_publisher, reader) = memfd_with_seals(bytes, partial);
            assert!(matches!(
                SealedMemfdMapping::run(reader, bytes.len() as u64, 4096, |_, _| ()),
                Err(ImmutableFileError::MissingSeals)
            ));
        }
    }

    #[test]
    fn seal_prevents_mutation_and_size_is_pre_admitted() {
        let bytes = b"index";
        let (publisher, reader) = memfd_with(bytes, true);
        let mut writer = File::from(publisher);
        let write_error = match writer.write_all(b"replacement") {
            Ok(()) => panic!("sealed memfd unexpectedly accepted a write"),
            Err(error) => error,
        };
        assert_eq!(write_error.raw_os_error(), Some(libc::EPERM));
        let shrink_error = match writer.set_len(1) {
            Ok(()) => panic!("sealed memfd unexpectedly shrank"),
            Err(error) => error,
        };
        assert_eq!(shrink_error.raw_os_error(), Some(libc::EPERM));
        let grow_error = match writer.set_len(32) {
            Ok(()) => panic!("sealed memfd unexpectedly grew"),
            Err(error) => error,
        };
        assert_eq!(grow_error.raw_os_error(), Some(libc::EPERM));
        assert!(matches!(
            SealedMemfdMapping::run(reader, bytes.len() as u64, 4, |_, _| ()),
            Err(ImmutableFileError::MappingLimitExceeded)
        ));
        let (_publisher, reader) = memfd_with(bytes, true);
        assert!(matches!(
            SealedMemfdMapping::run(reader, bytes.len() as u64 + 1, 4096, |_, _| ()),
            Err(ImmutableFileError::SizeMismatch)
        ));
    }

    #[test]
    fn verity_path_open_rejects_symlink_substitution() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        std::fs::write(temp.path().join("candidate"), b"index")
            .unwrap_or_else(|error| panic!("candidate write failed: {error}"));
        std::os::unix::fs::symlink("candidate", temp.path().join("index"))
            .unwrap_or_else(|error| panic!("symlink failed: {error}"));
        let root: OwnedFd = File::open(temp.path())
            .unwrap_or_else(|error| panic!("root open failed: {error}"))
            .into();
        let root = BeneathRoot::from_owned(root)
            .unwrap_or_else(|error| panic!("root adoption failed: {error}"));

        assert!(matches!(
            FsVerityMapping::run_beneath(
                &root,
                Path::new("index"),
                FsVerityDigest::Sha256([0; 32]),
                5,
                4096,
                |_, _| (),
            ),
            Err(ImmutableFileError::Linux(_))
        ));
    }

    #[test]
    fn ordinary_regular_file_is_not_verity_authority() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        std::fs::write(temp.path().join("index"), b"index")
            .unwrap_or_else(|error| panic!("candidate write failed: {error}"));
        let root: OwnedFd = File::open(temp.path())
            .unwrap_or_else(|error| panic!("root open failed: {error}"))
            .into();
        let root = BeneathRoot::from_owned(root)
            .unwrap_or_else(|error| panic!("root adoption failed: {error}"));

        assert!(matches!(
            FsVerityMapping::run_beneath(
                &root,
                Path::new("index"),
                FsVerityDigest::Sha256([0; 32]),
                5,
                4096,
                |_, _| (),
            ),
            Err(ImmutableFileError::Linux(_))
        ));
    }
}
