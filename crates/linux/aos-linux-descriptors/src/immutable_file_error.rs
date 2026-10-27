//! Owning errors for immutable descriptor admission and mapping.

use crate::Error;

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
    /// The backing file description is not opened for read-only access.
    #[error("immutable backing descriptor is not read-only")]
    DescriptorNotReadOnly,
    /// The backing descriptor could leak into a later exec.
    #[error("immutable backing descriptor is not close-on-exec")]
    DescriptorNotCloseOnExec,
    /// A transferred immutable file is not owned by the creating identity.
    #[error("immutable file is not owned by the current effective user")]
    UnexpectedOwner,
    /// A transient immutable file has a persistent directory link.
    #[error("transient immutable file is not anonymous")]
    NotAnonymous,
    /// The expected backing size exceeds the explicit admission ceiling.
    #[error("immutable backing exceeds its configured byte ceiling")]
    BackingLimitExceeded,
    /// The filesystem is not an admitted kernel fs-verity implementation.
    #[error("filesystem is not an admitted kernel fs-verity implementation")]
    UnsupportedVerityFilesystem,
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
