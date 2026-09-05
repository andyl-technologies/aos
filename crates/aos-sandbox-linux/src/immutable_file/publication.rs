//! Fresh-inode materialization and private fs-verity sealing.
//!
//! This module owns the Linux mechanics before catalog publication. It copies
//! a readable source into a newly created private inode beneath a retained,
//! protected directory, lets the caller verify exactly the copied stream,
//! closes the never-exposed writer, enables fs-verity, and returns the measured
//! read-only inode. Its naming submodule can durably apply a caller-selected
//! no-replace basename, but this module does not authenticate content, select a
//! cache domain, authorize a canonical catalog name, commit catalog state, or
//! authorize cleanup of retained failures.

mod naming;

pub use naming::{
    AfterRenameFailure, AmbiguousNamedSealedFile, BeforeRenameFailure, DurablyNamedSealedFile,
    NoReplacePublicationError, RenamedSealedFile,
};

use std::error::Error as StdError;
use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileExt as _;

use super::{FsVerityDigest, is_kernel_verity_filesystem};
use crate::Error;
use crate::uapi::{
    self, OpenHow, RESOLVE_BENEATH, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV,
};

const MAXIMUM_NAME_BYTES: usize = 255;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// Reports an invalid private publication basename.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("publication name must be one ordinary 1..=255-byte basename without NUL")]
pub struct InvalidPublicationName;

/// Stores one syntactically valid, non-authorizing private publication name.
///
/// A valid name conveys no content, placement, catalog, or cleanup authority.
/// Higher layers derive names from authenticated operations before calling the
/// Linux boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationName(CString);

impl PublicationName {
    /// Validates one ordinary filesystem basename.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPublicationName`] for an empty or overlong name, `.`,
    /// `..`, a slash, or an embedded NUL.
    pub fn new(name: &OsStr) -> Result<Self, InvalidPublicationName> {
        let bytes = name.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAXIMUM_NAME_BYTES
            || bytes == b"."
            || bytes == b".."
            || bytes.contains(&b'/')
        {
            return Err(InvalidPublicationName);
        }
        CString::new(bytes)
            .map(Self)
            .map_err(|_| InvalidPublicationName)
    }

    /// Returns the validated basename as an operating-system string.
    #[must_use]
    pub fn as_os_str(&self) -> &OsStr {
        OsStr::from_bytes(self.0.as_bytes())
    }

    fn as_c_str(&self) -> &CStr {
        &self.0
    }
}

/// Reports failure to adopt a protected fs-verity publication directory.
#[derive(Debug, thiserror::Error)]
pub enum PublicationRootError {
    /// A Linux descriptor operation failed.
    #[error("publication-root Linux operation failed: {0}")]
    Linux(#[from] Error),
    /// The descriptor does not name a directory.
    #[error("publication root is not a directory")]
    NotDirectory,
    /// The retained directory description is not read-only or is `O_PATH`.
    #[error("publication root descriptor is not a readable directory description")]
    DescriptorAccess,
    /// The directory is not owned by the process effective user.
    #[error("publication root is not owned by the effective service user")]
    WrongOwner,
    /// The directory mode is not exactly 0700.
    #[error("publication root mode is not exactly 0700")]
    WrongMode,
    /// The directory does not reside on an admitted kernel fs-verity filesystem.
    #[error("publication root filesystem is not an admitted fs-verity implementation")]
    UnsupportedFilesystem,
    /// Root metadata changed while it was being admitted.
    #[error("publication root changed during admission")]
    AdmissionRace,
}

/// Lets a caller checkpoint work and verify exactly the bytes copied.
///
/// `checkpoint` is invoked before inode creation and each source read, before
/// each destination write or retry, after each callback-accepted chunk, before
/// final verification, before data synchronization, before sealing, and after
/// durable private sealing. It cannot interrupt a kernel filesystem operation
/// that has already begun.
pub trait MaterializationCallbacks {
    /// Error returned by cancellation, deadline, or content verification.
    type Error: StdError + 'static;

    /// Checks whether materialization may continue at the next boundary.
    ///
    /// # Errors
    ///
    /// Returns the caller's cancellation or deadline failure.
    fn checkpoint(&mut self) -> Result<(), Self::Error>;

    /// Verifies one contiguous chunk after it was completely written.
    ///
    /// # Errors
    ///
    /// Returns the caller's streaming-verification failure.
    fn verify_chunk(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Finishes verification after source end-of-file.
    ///
    /// # Errors
    ///
    /// Returns the caller's final size or content-verification failure.
    fn finish_verification(&mut self) -> Result<(), Self::Error>;
}

/// Identifies the last confirmed state of a retained failed private inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedPrivatePhase {
    /// The fresh inode exists and may contain a partial stream.
    Materializing,
    /// The callback accepted the complete copied stream.
    Verified,
    /// File data was synchronized before closing the writer.
    DataSynchronized,
    /// The writable description was closed and the inode was reopened read-only.
    WriterClosed,
    /// Fs-verity enable succeeded, but later validation or synchronization failed.
    SealEnabled,
    /// The seal, inode fsync, and private-directory fsync completed, but the final checkpoint failed.
    Sealed,
}

/// Describes a failed private artifact that only recovery may inspect.
///
/// The name and inode numbers are observation evidence, not cleanup, adoption,
/// content, or catalog authority. The private inode may disappear after a crash
/// because this outcome does not promise that its directory entry was durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedPrivateArtifact {
    name: PublicationName,
    device: Option<u64>,
    inode: Option<u64>,
    confirmed_bytes: u64,
    phase: RetainedPrivatePhase,
}

impl RetainedPrivateArtifact {
    /// Returns the private basename selected by the caller.
    #[must_use]
    pub fn name(&self) -> &PublicationName {
        &self.name
    }

    /// Returns the session-local device number when creation inspection succeeded.
    #[must_use]
    pub const fn device(&self) -> Option<u64> {
        self.device
    }

    /// Returns the session-local inode number when creation inspection succeeded.
    #[must_use]
    pub const fn inode(&self) -> Option<u64> {
        self.inode
    }

    /// Returns the copied prefix accepted by the callback.
    ///
    /// A partial write or callback failure can leave the retained inode longer
    /// than this value. Recovery must inspect the inode rather than treating
    /// this diagnostic counter as its exact size.
    #[must_use]
    pub const fn confirmed_bytes(&self) -> u64 {
        self.confirmed_bytes
    }

    /// Returns the last completed materialization phase.
    #[must_use]
    pub const fn phase(&self) -> RetainedPrivatePhase {
        self.phase
    }
}

/// Reports why fresh private materialization failed.
#[derive(Debug, thiserror::Error)]
pub enum MaterializationFailure<E: StdError + 'static> {
    /// A Linux descriptor or filesystem operation failed.
    #[error("private materialization Linux operation failed: {0}")]
    Linux(#[source] Error),
    /// The source is not a regular file.
    #[error("materialization source is not a regular file")]
    SourceNotRegular,
    /// The source file description cannot be read with positional I/O.
    #[error("materialization source descriptor is not readable")]
    SourceNotReadable,
    /// The source or copied stream exceeds the caller's hard byte ceiling.
    #[error("materialization source exceeds its configured byte ceiling")]
    ByteLimitExceeded,
    /// Caller checkpointing or content verification rejected the operation.
    #[error("materialization callback rejected the operation: {0}")]
    Callback(#[source] E),
    /// The newly created private inode violated ownership, mode, link, or identity invariants.
    #[error("private inode identity or protection invariant failed")]
    PrivateInodeInvariant,
    /// The kernel returned a measurement different from the requested SHA-256 profile.
    #[error("fs-verity returned an unexpected measurement profile")]
    UnexpectedMeasurement,
    /// The protected root changed after admission.
    #[error("publication root changed after admission")]
    RootChanged,
}

/// Couples a materialization cause to any retained private-artifact evidence.
#[derive(Debug, thiserror::Error)]
#[error("{cause}")]
pub struct MaterializationError<E: StdError + 'static> {
    #[source]
    cause: MaterializationFailure<E>,
    retained: Option<RetainedPrivateArtifact>,
}

impl<E: StdError + 'static> MaterializationError<E> {
    /// Returns the underlying failure.
    #[must_use]
    pub const fn cause(&self) -> &MaterializationFailure<E> {
        &self.cause
    }

    /// Returns non-authorizing evidence for the private inode left in place.
    #[must_use]
    pub const fn retained_artifact(&self) -> Option<&RetainedPrivateArtifact> {
        self.retained.as_ref()
    }

    /// Separates the failure from any retained private-artifact evidence.
    #[must_use]
    pub fn into_parts(self) -> (MaterializationFailure<E>, Option<RetainedPrivateArtifact>) {
        (self.cause, self.retained)
    }
}

/// Pins one freshly materialized private inode with verified fs-verity creation evidence.
///
/// Its measurement proves the kernel seal created by this operation, not AOS
/// content identity or publication authority. The private name has not been
/// promoted to a canonical catalog name or durably committed to a catalog.
///
/// ```compile_fail
/// use aos_sandbox_linux::immutable_file::SealedPrivateFile;
/// fn extend(file: SealedPrivateFile<'_>) -> SealedPrivateFile<'static> {
///     file
/// }
/// ```
#[derive(Debug)]
pub struct SealedPrivateFile<'root> {
    file: OwnedFd,
    name: PublicationName,
    root: &'root FsVerityPublicationRoot,
    identity: PrivateIdentity,
    verity: FsVerityDigest,
}

impl SealedPrivateFile<'_> {
    /// Returns the still-private basename.
    #[must_use]
    pub fn name(&self) -> &PublicationName {
        &self.name
    }

    /// Returns the fs-verity measurement created and rechecked on this descriptor.
    #[must_use]
    pub const fn verity_digest(&self) -> FsVerityDigest {
        self.verity
    }

    /// Returns the exact copied byte count.
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
}

impl AsFd for SealedPrivateFile<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

/// Retains the protected directory used for fresh private materialization.
///
/// Construction validates mechanics only. The caller must obtain the
/// descriptor from trusted placement resolution, dedicate its exact service
/// UID and mode-0700 directory to the publisher, and serialize mutation with
/// its external journal lock. This type is not placement, cache-domain, or
/// cleanup authority and cannot exclude another process running under the same
/// UID.
#[derive(Debug)]
pub struct FsVerityPublicationRoot {
    directory: OwnedFd,
    identity: RootIdentity,
}

impl FsVerityPublicationRoot {
    /// Validates and retains one already-resolved publication directory.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationRootError`] unless the descriptor is a stable,
    /// read-only, current-user-owned directory of exact mode 0700 on an admitted
    /// kernel fs-verity filesystem.
    pub fn from_owned(directory: OwnedFd) -> Result<Self, PublicationRootError> {
        uapi::ensure_cloexec(directory.as_fd())?;
        let before = inspect_root(directory.as_fd())?;
        let flags = uapi::get_status_flags(directory.as_fd())?;
        if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_PATH != 0 {
            return Err(PublicationRootError::DescriptorAccess);
        }
        if before.uid != uapi::effective_uid() {
            return Err(PublicationRootError::WrongOwner);
        }
        if before.mode != 0o700 {
            return Err(PublicationRootError::WrongMode);
        }
        if !is_kernel_verity_filesystem(uapi::filesystem_type(directory.as_fd())?) {
            return Err(PublicationRootError::UnsupportedFilesystem);
        }
        if inspect_root(directory.as_fd())? != before {
            return Err(PublicationRootError::AdmissionRace);
        }
        Ok(Self {
            directory,
            identity: before,
        })
    }

    /// Copies, caller-verifies, synchronizes, and seals one fresh private inode.
    ///
    /// Positional reads start at source offset zero and do not consume or depend
    /// on the source file description's shared offset. The source must be a
    /// readable regular file. A fixed 64-KiB buffer bounds memory; checked byte
    /// accounting rejects the initial size or a concurrent growth beyond
    /// `maximum_bytes` before writing the out-of-bound byte.
    ///
    /// The destination is created mode 0600 with no-replace semantics and its
    /// writable descriptor never leaves this function. The caller callback
    /// observes each chunk only after that entire chunk was written. Successful
    /// verification is followed by data synchronization, a same-inode read-only
    /// reopen, writer closure, SHA-256/4096 fs-verity enable and measurement,
    /// stable identity/measurement rechecks, inode fsync, and directory fsync.
    ///
    /// On any failure after creation, the private name is deliberately retained
    /// and returned as observation evidence. This function never deletes,
    /// adopts, or replaces an existing name; only higher-level recovery has
    /// cleanup authority.
    ///
    /// # Errors
    ///
    /// Returns [`MaterializationError`] for source or root admission failure,
    /// byte-ceiling exhaustion, callback rejection, I/O or fs-verity failure,
    /// or a private-inode identity/protection race. The error identifies whether
    /// a newly created private inode may remain for recovery.
    pub fn materialize_and_seal<'root, C: MaterializationCallbacks>(
        &'root self,
        source: OwnedFd,
        private_name: PublicationName,
        maximum_bytes: u64,
        callbacks: &mut C,
    ) -> Result<SealedPrivateFile<'root>, MaterializationError<C::Error>> {
        let source = File::from(source);
        if let Err(cause) = inspect_source(source.as_fd(), maximum_bytes) {
            return Err(MaterializationError {
                cause,
                retained: None,
            });
        }
        if let Err(cause) = self.recheck_root() {
            return Err(MaterializationError {
                cause,
                retained: None,
            });
        }
        if let Err(error) = callbacks.checkpoint() {
            return Err(MaterializationError {
                cause: MaterializationFailure::Callback(error),
                retained: None,
            });
        }

        let writer = match self.create_private(&private_name) {
            Ok(writer) => writer,
            Err(cause) => {
                return Err(MaterializationError {
                    cause,
                    retained: None,
                });
            }
        };
        let mut retained = RetainedPrivateArtifact {
            name: private_name.clone(),
            device: None,
            inode: None,
            confirmed_bytes: 0,
            phase: RetainedPrivatePhase::Materializing,
        };
        let identity = match inspect_created(writer.as_fd()) {
            Ok(identity) => identity,
            Err(cause) => {
                return Err(MaterializationError {
                    cause,
                    retained: Some(retained),
                });
            }
        };
        retained.device = Some(identity.device);
        retained.inode = Some(identity.inode);
        if let Err(source) = writer.set_permissions(
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        ) {
            return Err(MaterializationError {
                cause: MaterializationFailure::Linux(io_error("fchmod private inode", source)),
                retained: Some(retained),
            });
        }
        if let Err(cause) = inspect_private(writer.as_fd()) {
            return Err(MaterializationError {
                cause,
                retained: Some(retained),
            });
        }

        match self.finish_materialization(
            source,
            writer,
            private_name,
            maximum_bytes,
            callbacks,
            &mut retained,
            identity,
        ) {
            Ok(sealed) => Ok(sealed),
            Err(cause) => Err(MaterializationError {
                cause,
                retained: Some(retained),
            }),
        }
    }

    fn create_private<E: StdError + 'static>(
        &self,
        name: &PublicationName,
    ) -> Result<File, MaterializationFailure<E>> {
        let flags = u64::try_from(
            libc::O_CREAT
                | libc::O_EXCL
                | libc::O_RDWR
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NOCTTY,
        )
        .map_err(|_| MaterializationFailure::PrivateInodeInvariant)?;
        let descriptor = uapi::openat2(
            self.directory.as_fd(),
            name.as_c_str(),
            &OpenHow {
                flags,
                mode: 0o600,
                resolve: strict_resolution(),
            },
        )
        .map_err(MaterializationFailure::Linux)?;
        Ok(File::from(descriptor))
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_materialization<'root, C: MaterializationCallbacks>(
        &'root self,
        source: File,
        mut writer: File,
        private_name: PublicationName,
        maximum_bytes: u64,
        callbacks: &mut C,
        retained: &mut RetainedPrivateArtifact,
        created: PrivateIdentity,
    ) -> Result<SealedPrivateFile<'root>, MaterializationFailure<C::Error>> {
        copy_and_verify(&source, &mut writer, maximum_bytes, callbacks, retained)?;
        callbacks
            .checkpoint()
            .map_err(MaterializationFailure::Callback)?;
        callbacks
            .finish_verification()
            .map_err(MaterializationFailure::Callback)?;
        retained.phase = RetainedPrivatePhase::Verified;

        callbacks
            .checkpoint()
            .map_err(MaterializationFailure::Callback)?;
        writer.sync_data().map_err(|source| {
            MaterializationFailure::Linux(io_error("fdatasync private inode", source))
        })?;
        retained.phase = RetainedPrivatePhase::DataSynchronized;
        let synchronized = inspect_private(writer.as_fd())?;
        if synchronized.device != created.device
            || synchronized.inode != created.inode
            || synchronized.bytes != retained.confirmed_bytes
        {
            return Err(MaterializationFailure::PrivateInodeInvariant);
        }

        let reader = self.open_private_readonly::<C::Error>(&private_name)?;
        let reopened = inspect_private(reader.as_fd())?;
        if reopened != synchronized {
            return Err(MaterializationFailure::PrivateInodeInvariant);
        }
        drop(writer);
        retained.phase = RetainedPrivatePhase::WriterClosed;

        callbacks
            .checkpoint()
            .map_err(MaterializationFailure::Callback)?;
        uapi::enable_verity_sha256_4096(reader.as_fd()).map_err(MaterializationFailure::Linux)?;
        retained.phase = RetainedPrivatePhase::SealEnabled;
        let verity = sha256_measurement(reader.as_fd())?;
        reader.sync_all().map_err(|source| {
            MaterializationFailure::Linux(io_error("fsync sealed private inode", source))
        })?;
        if inspect_private(reader.as_fd())? != reopened
            || sha256_measurement(reader.as_fd())? != verity
        {
            return Err(MaterializationFailure::PrivateInodeInvariant);
        }
        self.recheck_root()?;
        uapi::fsync(self.directory.as_fd()).map_err(MaterializationFailure::Linux)?;
        retained.phase = RetainedPrivatePhase::Sealed;
        callbacks
            .checkpoint()
            .map_err(MaterializationFailure::Callback)?;

        Ok(SealedPrivateFile {
            file: reader.into(),
            name: private_name,
            root: self,
            identity: reopened,
            verity,
        })
    }

    fn open_private_readonly<E: StdError + 'static>(
        &self,
        name: &PublicationName,
    ) -> Result<File, MaterializationFailure<E>> {
        let flags = u64::try_from(
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
        )
        .map_err(|_| MaterializationFailure::PrivateInodeInvariant)?;
        uapi::openat2(
            self.directory.as_fd(),
            name.as_c_str(),
            &OpenHow {
                flags,
                mode: 0,
                resolve: strict_resolution(),
            },
        )
        .map(File::from)
        .map_err(MaterializationFailure::Linux)
    }

    fn recheck_root<E: StdError + 'static>(&self) -> Result<(), MaterializationFailure<E>> {
        if inspect_root(self.directory.as_fd()).map_err(|error| match error {
            PublicationRootError::Linux(error) => MaterializationFailure::Linux(error),
            _ => MaterializationFailure::RootChanged,
        })? != self.identity
            || !is_kernel_verity_filesystem(
                uapi::filesystem_type(self.directory.as_fd())
                    .map_err(MaterializationFailure::Linux)?,
            )
        {
            return Err(MaterializationFailure::RootChanged);
        }
        Ok(())
    }
}

fn strict_resolution() -> u64 {
    RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV
}

fn copy_and_verify<C: MaterializationCallbacks>(
    source: &File,
    writer: &mut File,
    maximum_bytes: u64,
    callbacks: &mut C,
    retained: &mut RetainedPrivateArtifact,
) -> Result<(), MaterializationFailure<C::Error>> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        callbacks
            .checkpoint()
            .map_err(MaterializationFailure::Callback)?;
        let remaining = maximum_bytes
            .checked_sub(retained.confirmed_bytes)
            .ok_or(MaterializationFailure::ByteLimitExceeded)?;
        let admitted = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64))
            .map_err(|_| MaterializationFailure::ByteLimitExceeded)?;
        let probe_bytes = if admitted == 0 { 1 } else { admitted };
        let read = loop {
            match source.read_at(&mut buffer[..probe_bytes], retained.confirmed_bytes) {
                Ok(read) => break read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    callbacks
                        .checkpoint()
                        .map_err(MaterializationFailure::Callback)?;
                }
                Err(source) => {
                    return Err(MaterializationFailure::Linux(io_error(
                        "pread materialization source",
                        source,
                    )));
                }
            }
        };
        if read == 0 {
            return Ok(());
        }
        if admitted == 0 {
            return Err(MaterializationFailure::ByteLimitExceeded);
        }

        write_all_controlled(writer, &buffer[..read], callbacks)?;
        callbacks
            .verify_chunk(&buffer[..read])
            .map_err(MaterializationFailure::Callback)?;
        retained.confirmed_bytes = retained
            .confirmed_bytes
            .checked_add(
                u64::try_from(read).map_err(|_| MaterializationFailure::ByteLimitExceeded)?,
            )
            .ok_or(MaterializationFailure::ByteLimitExceeded)?;
        callbacks
            .checkpoint()
            .map_err(MaterializationFailure::Callback)?;
    }
}

fn write_all_controlled<C: MaterializationCallbacks>(
    writer: &mut File,
    mut bytes: &[u8],
    callbacks: &mut C,
) -> Result<(), MaterializationFailure<C::Error>> {
    while !bytes.is_empty() {
        callbacks
            .checkpoint()
            .map_err(MaterializationFailure::Callback)?;
        match writer.write(bytes) {
            Ok(0) => {
                return Err(MaterializationFailure::Linux(io_error(
                    "write private inode",
                    std::io::Error::from(std::io::ErrorKind::WriteZero),
                )));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
            Err(source) => {
                return Err(MaterializationFailure::Linux(io_error(
                    "write private inode",
                    source,
                )));
            }
        }
    }
    Ok(())
}

fn inspect_source<E: StdError + 'static>(
    source: BorrowedFd<'_>,
    maximum_bytes: u64,
) -> Result<(), MaterializationFailure<E>> {
    uapi::ensure_cloexec(source).map_err(MaterializationFailure::Linux)?;
    let stat = uapi::fstat(source).map_err(MaterializationFailure::Linux)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(MaterializationFailure::SourceNotRegular);
    }
    let flags = uapi::get_status_flags(source).map_err(MaterializationFailure::Linux)?;
    if flags & libc::O_ACCMODE == libc::O_WRONLY || flags & libc::O_PATH != 0 {
        return Err(MaterializationFailure::SourceNotReadable);
    }
    let bytes =
        u64::try_from(stat.st_size).map_err(|_| MaterializationFailure::ByteLimitExceeded)?;
    if bytes > maximum_bytes {
        return Err(MaterializationFailure::ByteLimitExceeded);
    }
    Ok(())
}

fn inspect_private<E: StdError + 'static>(
    file: BorrowedFd<'_>,
) -> Result<PrivateIdentity, MaterializationFailure<E>> {
    let stat = uapi::fstat(file).map_err(MaterializationFailure::Linux)?;
    let bytes =
        u64::try_from(stat.st_size).map_err(|_| MaterializationFailure::PrivateInodeInvariant)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != uapi::effective_uid()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(MaterializationFailure::PrivateInodeInvariant);
    }
    Ok(PrivateIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        bytes,
    })
}

fn inspect_created<E: StdError + 'static>(
    file: BorrowedFd<'_>,
) -> Result<PrivateIdentity, MaterializationFailure<E>> {
    let stat = uapi::fstat(file).map_err(MaterializationFailure::Linux)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != uapi::effective_uid()
        || stat.st_size != 0
        || stat.st_nlink != 1
    {
        return Err(MaterializationFailure::PrivateInodeInvariant);
    }
    Ok(PrivateIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        bytes: 0,
    })
}

fn inspect_root(directory: BorrowedFd<'_>) -> Result<RootIdentity, PublicationRootError> {
    let stat = uapi::fstat(directory)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(PublicationRootError::NotDirectory);
    }
    Ok(RootIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        uid: stat.st_uid,
        mode: stat.st_mode & 0o7777,
    })
}

fn sha256_measurement<E: StdError + 'static>(
    file: BorrowedFd<'_>,
) -> Result<FsVerityDigest, MaterializationFailure<E>> {
    let measurement = uapi::measure_verity(file).map_err(MaterializationFailure::Linux)?;
    if measurement.algorithm != 1 || measurement.length != 32 {
        return Err(MaterializationFailure::UnexpectedMeasurement);
    }
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&measurement.digest[..32]);
    Ok(FsVerityDigest::Sha256(digest))
}

fn io_error(operation: &'static str, source: std::io::Error) -> Error {
    Error::Syscall { operation, source }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: libc::mode_t,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
}

impl<E: StdError + 'static> From<Error> for MaterializationFailure<E> {
    fn from(error: Error) -> Self {
        Self::Linux(error)
    }
}

impl fmt::Display for PublicationName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_os_str().to_string_lossy().fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::unix::fs::OpenOptionsExt as _;

    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("stopped")]
    struct Stopped;

    struct RecordingCallbacks {
        bytes: Vec<u8>,
        checkpoints: usize,
        stop_at: Option<usize>,
        finish: bool,
    }

    impl MaterializationCallbacks for RecordingCallbacks {
        type Error = Stopped;

        fn checkpoint(&mut self) -> Result<(), Self::Error> {
            self.checkpoints += 1;
            if self.stop_at == Some(self.checkpoints) {
                Err(Stopped)
            } else {
                Ok(())
            }
        }

        fn verify_chunk(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }

        fn finish_verification(&mut self) -> Result<(), Self::Error> {
            self.finish = true;
            Ok(())
        }
    }

    fn callbacks() -> RecordingCallbacks {
        RecordingCallbacks {
            bytes: Vec::new(),
            checkpoints: 0,
            stop_at: None,
            finish: false,
        }
    }

    #[test]
    fn publication_names_are_single_bounded_components() {
        for valid in ["object", ".private-123"] {
            assert!(PublicationName::new(OsStr::new(valid)).is_ok());
        }
        for invalid in ["", ".", "..", "a/b", "nul\0byte"] {
            assert_eq!(
                PublicationName::new(OsStr::new(invalid)),
                Err(InvalidPublicationName)
            );
        }
        let long = OsStr::from_bytes(&[b'x'; MAXIMUM_NAME_BYTES + 1]);
        assert_eq!(PublicationName::new(long), Err(InvalidPublicationName));
    }

    #[test]
    fn copy_uses_offset_zero_without_changing_shared_offset() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        std::fs::write(&source_path, b"source bytes").unwrap();
        let mut source = std::fs::OpenOptions::new()
            .read(true)
            .open(source_path)
            .unwrap();
        std::io::Read::read_exact(&mut source, &mut [0_u8; 3]).unwrap();
        let destination_path = temp.path().join("destination");
        let mut destination = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&destination_path)
            .unwrap();
        let mut callbacks = callbacks();
        let mut retained = RetainedPrivateArtifact {
            name: PublicationName::new(OsStr::new("destination")).unwrap(),
            device: Some(1),
            inode: Some(1),
            confirmed_bytes: 0,
            phase: RetainedPrivatePhase::Materializing,
        };

        copy_and_verify(&source, &mut destination, 64, &mut callbacks, &mut retained).unwrap();

        assert_eq!(callbacks.bytes, b"source bytes");
        assert_eq!(std::fs::read(destination_path).unwrap(), b"source bytes");
        let mut next = [0_u8; 1];
        std::io::Read::read_exact(&mut source, &mut next).unwrap();
        assert_eq!(next, [b'r']);
    }

    #[test]
    fn copy_checks_ceiling_before_writing_excess_byte() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        std::fs::write(&source_path, b"12345").unwrap();
        let source = File::open(source_path).unwrap();
        let destination_path = temp.path().join("destination");
        let mut destination = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&destination_path)
            .unwrap();
        let mut callbacks = callbacks();
        let mut retained = RetainedPrivateArtifact {
            name: PublicationName::new(OsStr::new("destination")).unwrap(),
            device: Some(1),
            inode: Some(1),
            confirmed_bytes: 0,
            phase: RetainedPrivatePhase::Materializing,
        };

        assert!(matches!(
            copy_and_verify(&source, &mut destination, 4, &mut callbacks, &mut retained),
            Err(MaterializationFailure::ByteLimitExceeded)
        ));
        assert_eq!(callbacks.bytes, b"1234");
        assert_eq!(std::fs::read(destination_path).unwrap(), b"1234");
        assert_eq!(retained.confirmed_bytes(), 4);
    }

    #[test]
    fn callback_stops_between_bounded_copy_chunks() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        std::fs::write(&source_path, vec![7_u8; COPY_BUFFER_BYTES * 2]).unwrap();
        let source = File::open(source_path).unwrap();
        let destination_path = temp.path().join("destination");
        let mut destination = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&destination_path)
            .unwrap();
        let mut callbacks = callbacks();
        callbacks.stop_at = Some(3);
        let mut retained = RetainedPrivateArtifact {
            name: PublicationName::new(OsStr::new("destination")).unwrap(),
            device: Some(1),
            inode: Some(1),
            confirmed_bytes: 0,
            phase: RetainedPrivatePhase::Materializing,
        };

        assert!(matches!(
            copy_and_verify(
                &source,
                &mut destination,
                u64::MAX,
                &mut callbacks,
                &mut retained,
            ),
            Err(MaterializationFailure::Callback(_))
        ));
        assert_eq!(retained.confirmed_bytes(), COPY_BUFFER_BYTES as u64);
        assert_eq!(
            std::fs::metadata(destination_path).unwrap().len(),
            COPY_BUFFER_BYTES as u64
        );
    }

    #[test]
    fn source_admission_rejects_nonregular_unreadable_and_oversized() {
        let temp = tempfile::tempdir().unwrap();
        let directory = File::open(temp.path()).unwrap();
        assert!(matches!(
            inspect_source::<Stopped>(directory.as_fd(), 10),
            Err(MaterializationFailure::SourceNotRegular)
        ));

        let path = temp.path().join("source");
        std::fs::write(&path, b"12345").unwrap();
        let write_only = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert!(matches!(
            inspect_source::<Stopped>(write_only.as_fd(), 10),
            Err(MaterializationFailure::SourceNotReadable)
        ));
        let readable = File::open(path).unwrap();
        assert!(matches!(
            inspect_source::<Stopped>(readable.as_fd(), 4),
            Err(MaterializationFailure::ByteLimitExceeded)
        ));
    }

    #[test]
    fn protected_root_validation_rejects_mode_and_unsupported_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            temp.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        assert!(matches!(
            FsVerityPublicationRoot::from_owned(File::open(temp.path()).unwrap().into()),
            Err(PublicationRootError::WrongMode)
        ));

        std::fs::set_permissions(
            temp.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let result = FsVerityPublicationRoot::from_owned(File::open(temp.path()).unwrap().into());
        if let Err(error) = result {
            assert!(matches!(
                error,
                PublicationRootError::UnsupportedFilesystem
                    | PublicationRootError::Linux(_)
                    | PublicationRootError::AdmissionRace
            ));
        }
    }

    #[test]
    fn io_errors_keep_their_stable_operation_label() {
        let error = io_error("test operation", io::Error::other("failure"));
        assert!(error.to_string().contains("test operation"));
    }
}
