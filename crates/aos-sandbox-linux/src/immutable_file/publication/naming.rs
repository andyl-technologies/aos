//! Same-directory no-replace naming of a sealed private inode.
//!
//! This module advances one lifetime-bound private inode through the Linux
//! rename and parent-fsync boundary. It owns no catalog, reservation, content,
//! placement, disclosure, adoption, or cleanup authority.

use std::convert::Infallible;
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use super::{
    FsVerityPublicationRoot, PrivateIdentity, PublicationName, SealedPrivateFile, inspect_private,
    inspect_root, is_kernel_verity_filesystem, sha256_measurement, strict_resolution,
};
use crate::Error;
use crate::uapi::{self, OpenHow};

/// Reports a failure known to precede the no-replace rename effect.
#[derive(Debug, thiserror::Error)]
pub enum BeforeRenameFailure {
    /// Private and final names are identical.
    #[error("private and final publication names are identical")]
    SameName,
    /// The retained publication root changed after admission.
    #[error("publication root changed before rename")]
    RootChanged,
    /// The pinned descriptor or private name no longer has the exact sealed identity.
    #[error("private sealed inode failed exact pre-rename validation")]
    PrivateInvariant,
    /// The final name already exists; no existing object was opened or adopted.
    #[error("final publication name already exists")]
    DestinationExists,
    /// A Linux observation failed before rename.
    #[error("pre-rename Linux operation failed: {0}")]
    Linux(#[source] Error),
}

/// Reports a failure after `renameat2` definitely returned success.
#[derive(Debug, thiserror::Error)]
pub enum AfterRenameFailure {
    /// The retained publication root changed around parent synchronization.
    #[error("publication root changed after rename")]
    RootChanged,
    /// The final name or pinned descriptor failed exact sealed-inode validation.
    #[error("renamed sealed inode failed exact post-rename validation")]
    FinalInvariant,
    /// Synchronizing the final parent directory failed.
    #[error("final publication parent synchronization failed: {0}")]
    DirectorySync(#[source] Error),
    /// A Linux observation failed after rename.
    #[error("post-rename Linux observation failed: {0}")]
    Linux(#[source] Error),
}

/// Retains both candidate names after a non-`EEXIST` rename error.
///
/// The syscall outcome is deliberately treated as ambiguous. The pinned file
/// and names are observation evidence for authority-bound recovery; this type
/// does not permit retry, adoption, rollback, or cleanup.
///
/// ```compile_fail
/// use aos_sandbox_linux::immutable_file::AmbiguousNamedSealedFile;
/// fn extend(file: AmbiguousNamedSealedFile<'_>) -> AmbiguousNamedSealedFile<'static> {
///     file
/// }
/// ```
#[derive(Debug)]
pub struct AmbiguousNamedSealedFile<'root> {
    file: OwnedFd,
    _root: &'root FsVerityPublicationRoot,
    private_name: PublicationName,
    final_name: PublicationName,
    identity: PrivateIdentity,
    verity: super::FsVerityDigest,
}

impl AmbiguousNamedSealedFile<'_> {
    /// Returns the name used before the rename attempt.
    #[must_use]
    pub fn private_name(&self) -> &PublicationName {
        &self.private_name
    }

    /// Returns the requested final name.
    #[must_use]
    pub fn final_name(&self) -> &PublicationName {
        &self.final_name
    }

    /// Returns the exact pinned byte length.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.identity.bytes
    }

    /// Returns the measured seal creation evidence.
    #[must_use]
    pub const fn verity_digest(&self) -> super::FsVerityDigest {
        self.verity
    }
}

impl AsFd for AmbiguousNamedSealedFile<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

/// Pins a sealed inode after rename success but before durable completion.
///
/// This token means the rename syscall returned success. It does not mean the
/// final directory entry survived a crash, because parent fsync or a later
/// validation failed.
///
/// ```compile_fail
/// use aos_sandbox_linux::immutable_file::RenamedSealedFile;
/// fn extend(file: RenamedSealedFile<'_>) -> RenamedSealedFile<'static> {
///     file
/// }
/// ```
#[derive(Debug)]
pub struct RenamedSealedFile<'root> {
    file: OwnedFd,
    root: &'root FsVerityPublicationRoot,
    private_name: PublicationName,
    final_name: PublicationName,
    identity: PrivateIdentity,
    verity: super::FsVerityDigest,
}

impl RenamedSealedFile<'_> {
    /// Returns the name from which the inode was renamed.
    #[must_use]
    pub fn private_name(&self) -> &PublicationName {
        &self.private_name
    }

    /// Returns the final name selected by the caller.
    #[must_use]
    pub fn final_name(&self) -> &PublicationName {
        &self.final_name
    }

    /// Returns the exact pinned byte length.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.identity.bytes
    }

    /// Returns the measured seal creation evidence.
    #[must_use]
    pub const fn verity_digest(&self) -> super::FsVerityDigest {
        self.verity
    }
}

impl AsFd for RenamedSealedFile<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

/// Pins a sealed inode whose no-replace name and parent fsync completed.
///
/// This is Linux naming durability evidence only. It is not a catalog commit,
/// reservation or pin decision, AOS content identity, placement authority, or
/// permission to disclose the file.
///
/// ```compile_fail
/// use aos_sandbox_linux::immutable_file::DurablyNamedSealedFile;
/// fn extend(file: DurablyNamedSealedFile<'_>) -> DurablyNamedSealedFile<'static> {
///     file
/// }
/// ```
#[derive(Debug)]
pub struct DurablyNamedSealedFile<'root> {
    file: OwnedFd,
    _root: &'root FsVerityPublicationRoot,
    final_name: PublicationName,
    identity: PrivateIdentity,
    verity: super::FsVerityDigest,
}

impl DurablyNamedSealedFile<'_> {
    /// Returns the durably synchronized name.
    #[must_use]
    pub fn final_name(&self) -> &PublicationName {
        &self.final_name
    }

    /// Returns the exact pinned byte length.
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

    /// Returns the measured seal creation evidence.
    #[must_use]
    pub const fn verity_digest(&self) -> super::FsVerityDigest {
        self.verity
    }
}

impl AsFd for DurablyNamedSealedFile<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

/// Preserves the pinned inode across every no-replace naming failure.
#[derive(Debug, thiserror::Error)]
pub enum NoReplacePublicationError<'root> {
    /// The failure is known to precede any rename effect.
    #[error("sealed private publication failed before rename: {failure}")]
    BeforeRename {
        /// Exact pre-effect reason.
        #[source]
        failure: BeforeRenameFailure,
        /// Boxed original private token, still owned by the caller.
        private: Box<SealedPrivateFile<'root>>,
    },
    /// A non-`EEXIST` rename error has an outcome that recovery must observe.
    #[error("no-replace rename outcome is ambiguous: {source}")]
    RenameOutcomeAmbiguous {
        /// Linux rename error.
        #[source]
        source: Error,
        /// Boxed pinned inode and both candidate names.
        artifact: Box<AmbiguousNamedSealedFile<'root>>,
    },
    /// Rename succeeded, but validation or parent synchronization failed.
    #[error("sealed publication failed after rename: {failure}")]
    AfterRename {
        /// Exact post-effect reason.
        #[source]
        failure: AfterRenameFailure,
        /// Boxed pinned renamed inode and both names for recovery.
        renamed: Box<RenamedSealedFile<'root>>,
    },
}

impl<'root> SealedPrivateFile<'root> {
    /// Renames this exact private inode without replacement and synchronizes its parent.
    ///
    /// The consuming token carries a borrow of the exact retained publication
    /// root that created it; no arbitrary second root can be supplied. This
    /// method revalidates the pinned descriptor, private name, identity, size,
    /// link count, mode, owner, filesystem provenance, and fs-verity measurement
    /// before rename. After rename success it validates the final name, requires
    /// the private name to be absent, fsyncs the retained parent, and repeats the
    /// validation before returning.
    ///
    /// An exact `EEXIST` is a typed pre-effect conflict and never opens or adopts
    /// the existing destination. Every other rename error is conservatively
    /// ambiguous. No failure path deletes, replaces, adopts, or rolls back a
    /// name, and every error returns ownership of the pinned inode.
    ///
    /// # Errors
    ///
    /// Returns [`NoReplacePublicationError::BeforeRename`] for prevalidation,
    /// same-name, or exact destination-conflict failures,
    /// [`NoReplacePublicationError::RenameOutcomeAmbiguous`] for another rename
    /// syscall error, or [`NoReplacePublicationError::AfterRename`] when rename
    /// succeeded but observation or parent synchronization failed.
    pub fn publish_noreplace(
        self,
        final_name: PublicationName,
    ) -> Result<DurablyNamedSealedFile<'root>, NoReplacePublicationError<'root>> {
        if self.name == final_name {
            return Err(before(BeforeRenameFailure::SameName, self));
        }
        if let Err(failure) = validate_private(&self) {
            return Err(before(map_before(failure), self));
        }

        match uapi::renameat2(
            self.root.directory.as_fd(),
            self.name.as_c_str(),
            self.root.directory.as_fd(),
            final_name.as_c_str(),
            uapi::RENAME_NOREPLACE,
        ) {
            Ok(()) => (),
            Err(source) if syscall_errno(&source) == Some(libc::EEXIST) => {
                if let Err(failure) = validate_private(&self) {
                    return Err(before(map_before(failure), self));
                }
                return Err(before(BeforeRenameFailure::DestinationExists, self));
            }
            Err(source) => {
                return Err(NoReplacePublicationError::RenameOutcomeAmbiguous {
                    source,
                    artifact: Box::new(AmbiguousNamedSealedFile::from_private(self, final_name)),
                });
            }
        }

        let renamed = RenamedSealedFile::from_private(self, final_name);
        if let Err((step, failure)) = run_after_rename(
            || validate_renamed(&renamed),
            || uapi::fsync(renamed.root.directory.as_fd()).map_err(MechanicsFailure::Linux),
            || validate_renamed(&renamed),
        ) {
            return Err(NoReplacePublicationError::AfterRename {
                failure: map_after(step, failure),
                renamed: Box::new(renamed),
            });
        }

        Ok(renamed.into_durable())
    }
}

impl<'root> AmbiguousNamedSealedFile<'root> {
    fn from_private(private: SealedPrivateFile<'root>, final_name: PublicationName) -> Self {
        Self {
            file: private.file,
            _root: private.root,
            private_name: private.name,
            final_name,
            identity: private.identity,
            verity: private.verity,
        }
    }
}

impl<'root> RenamedSealedFile<'root> {
    fn from_private(private: SealedPrivateFile<'root>, final_name: PublicationName) -> Self {
        Self {
            file: private.file,
            root: private.root,
            private_name: private.name,
            final_name,
            identity: private.identity,
            verity: private.verity,
        }
    }

    fn into_durable(self) -> DurablyNamedSealedFile<'root> {
        DurablyNamedSealedFile {
            file: self.file,
            _root: self.root,
            final_name: self.final_name,
            identity: self.identity,
            verity: self.verity,
        }
    }
}

fn before<'root>(
    failure: BeforeRenameFailure,
    private: SealedPrivateFile<'root>,
) -> NoReplacePublicationError<'root> {
    NoReplacePublicationError::BeforeRename {
        failure,
        private: Box::new(private),
    }
}

fn validate_private(private: &SealedPrivateFile<'_>) -> Result<(), MechanicsFailure> {
    validate_root(private.root)?;
    validate_pinned(private.file.as_fd(), private.identity, private.verity)?;
    validate_named(
        private.root,
        &private.name,
        private.identity,
        private.verity,
    )
}

fn validate_renamed(renamed: &RenamedSealedFile<'_>) -> Result<(), MechanicsFailure> {
    validate_root(renamed.root)?;
    validate_pinned(renamed.file.as_fd(), renamed.identity, renamed.verity)?;
    validate_named(
        renamed.root,
        &renamed.final_name,
        renamed.identity,
        renamed.verity,
    )?;
    require_absent(renamed.root, &renamed.private_name)
}

fn validate_root(root: &FsVerityPublicationRoot) -> Result<(), MechanicsFailure> {
    let observed = inspect_root(root.directory.as_fd()).map_err(|error| match error {
        super::PublicationRootError::Linux(error) => MechanicsFailure::Linux(error),
        _ => MechanicsFailure::RootChanged,
    })?;
    if observed != root.identity
        || !is_kernel_verity_filesystem(
            uapi::filesystem_type(root.directory.as_fd()).map_err(MechanicsFailure::Linux)?,
        )
    {
        return Err(MechanicsFailure::RootChanged);
    }
    Ok(())
}

fn validate_pinned(
    file: BorrowedFd<'_>,
    expected: PrivateIdentity,
    verity: super::FsVerityDigest,
) -> Result<(), MechanicsFailure> {
    let flags = uapi::get_status_flags(file).map_err(MechanicsFailure::Linux)?;
    if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_PATH != 0 {
        return Err(MechanicsFailure::InodeInvariant);
    }
    if observed_private(file)? != expected || observed_verity(file)? != verity {
        return Err(MechanicsFailure::InodeInvariant);
    }
    Ok(())
}

fn validate_named(
    root: &FsVerityPublicationRoot,
    name: &PublicationName,
    expected: PrivateIdentity,
    verity: super::FsVerityDigest,
) -> Result<(), MechanicsFailure> {
    let file = open_name(root, name)?;
    if observed_private(file.as_fd())? != expected || observed_verity(file.as_fd())? != verity {
        return Err(MechanicsFailure::InodeInvariant);
    }
    Ok(())
}

fn require_absent(
    root: &FsVerityPublicationRoot,
    name: &PublicationName,
) -> Result<(), MechanicsFailure> {
    match open_name(root, name) {
        Err(MechanicsFailure::Linux(error)) if syscall_errno(&error) == Some(libc::ENOENT) => {
            Ok(())
        }
        Err(error) => Err(error),
        Ok(_) => Err(MechanicsFailure::InodeInvariant),
    }
}

fn open_name(
    root: &FsVerityPublicationRoot,
    name: &PublicationName,
) -> Result<File, MechanicsFailure> {
    let flags = u64::try_from(
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
    )
    .map_err(|_| MechanicsFailure::InodeInvariant)?;
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
    .map_err(MechanicsFailure::Linux)
}

fn observed_private(file: BorrowedFd<'_>) -> Result<PrivateIdentity, MechanicsFailure> {
    inspect_private::<Infallible>(file).map_err(|error| match error {
        super::MaterializationFailure::Linux(error) => MechanicsFailure::Linux(error),
        _ => MechanicsFailure::InodeInvariant,
    })
}

fn observed_verity(file: BorrowedFd<'_>) -> Result<super::FsVerityDigest, MechanicsFailure> {
    sha256_measurement::<Infallible>(file).map_err(|error| match error {
        super::MaterializationFailure::Linux(error) => MechanicsFailure::Linux(error),
        _ => MechanicsFailure::InodeInvariant,
    })
}

fn syscall_errno(error: &Error) -> Option<i32> {
    match error {
        Error::Syscall { source, .. } => source.raw_os_error(),
        Error::InvalidInput { .. }
        | Error::WrongDescriptorType { .. }
        | Error::MalformedKernelResponse { .. }
        | Error::ObservationLimitExceeded { .. } => None,
    }
}

fn map_before(failure: MechanicsFailure) -> BeforeRenameFailure {
    match failure {
        MechanicsFailure::RootChanged => BeforeRenameFailure::RootChanged,
        MechanicsFailure::InodeInvariant => BeforeRenameFailure::PrivateInvariant,
        MechanicsFailure::Linux(error) => BeforeRenameFailure::Linux(error),
    }
}

fn map_after(step: AfterRenameStep, failure: MechanicsFailure) -> AfterRenameFailure {
    match (step, failure) {
        (AfterRenameStep::DirectorySync, MechanicsFailure::Linux(error)) => {
            AfterRenameFailure::DirectorySync(error)
        }
        (_, MechanicsFailure::RootChanged) => AfterRenameFailure::RootChanged,
        (_, MechanicsFailure::InodeInvariant) => AfterRenameFailure::FinalInvariant,
        (_, MechanicsFailure::Linux(error)) => AfterRenameFailure::Linux(error),
    }
}

fn run_after_rename<E>(
    validate_before_sync: impl FnOnce() -> Result<(), E>,
    synchronize_parent: impl FnOnce() -> Result<(), E>,
    validate_after_sync: impl FnOnce() -> Result<(), E>,
) -> Result<(), (AfterRenameStep, E)> {
    validate_before_sync().map_err(|error| (AfterRenameStep::InitialValidation, error))?;
    synchronize_parent().map_err(|error| (AfterRenameStep::DirectorySync, error))?;
    validate_after_sync().map_err(|error| (AfterRenameStep::FinalValidation, error))
}

#[derive(Debug)]
enum MechanicsFailure {
    RootChanged,
    InodeInvariant,
    Linux(Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AfterRenameStep {
    InitialValidation,
    DirectorySync,
    FinalValidation,
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[test]
    fn post_rename_order_is_validate_sync_validate() {
        let calls = RefCell::new(Vec::new());
        let result = run_after_rename(
            || {
                calls.borrow_mut().push("validate-before");
                Ok::<_, ()>(())
            },
            || {
                calls.borrow_mut().push("sync");
                Ok::<_, ()>(())
            },
            || {
                calls.borrow_mut().push("validate-after");
                Ok::<_, ()>(())
            },
        );

        assert_eq!(result, Ok(()));
        assert_eq!(
            calls.into_inner(),
            ["validate-before", "sync", "validate-after"]
        );
    }

    #[test]
    fn post_rename_failure_reports_exact_effect_phase_and_stops() {
        for (failure, expected_calls) in [
            (AfterRenameStep::InitialValidation, 1),
            (AfterRenameStep::DirectorySync, 2),
            (AfterRenameStep::FinalValidation, 3),
        ] {
            let calls = RefCell::new(0_usize);
            let invoke = || {
                *calls.borrow_mut() += 1;
                if *calls.borrow() == expected_calls {
                    Err("injected")
                } else {
                    Ok(())
                }
            };
            let result = run_after_rename(invoke, invoke, invoke);
            assert_eq!(result, Err((failure, "injected")));
            assert_eq!(*calls.borrow(), expected_calls);
        }
    }
}
