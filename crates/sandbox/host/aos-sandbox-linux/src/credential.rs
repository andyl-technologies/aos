//! Shared bounded file admission for optional, separate-purpose role credentials.
//!
//! Callers retain their own role codec, seed correspondence, and key-reuse
//! checks. This reader only preserves the common systemd file boundary.

use std::collections::TryReserveError;
use std::fs::{File, Metadata};
use std::os::unix::fs::FileExt as _;
use std::os::unix::ffi::OsStrExt as _;
use std::io::{self, Read as _};
use std::num::TryFromIntError;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use rustix::fs::{CWD, Mode, OFlags, openat};
use zeroize::Zeroizing;

/// Reports a missing safety property of an optional fixed role credential.
#[derive(Debug, thiserror::Error)]
#[error("fixed role credential is unsafe or malformed")]
pub struct FixedRoleCredentialErrorV1;

/// Selects whether a role also pins the file owner to root or this process.
#[derive(Clone, Copy)]
pub enum CredentialOwnerPolicyV1 {
    /// Preserves a caller-owned role policy without adding an owner comparison.
    Any,
    /// Requires the observed file owner to be root.
    Root,
    /// Requires root or the current effective UID as the observed file owner.
    RootOrCurrent,
}

// The public signer reader historically checked only regular-file type and
// nonempty bounded length. Preserve that ordinary profile while sharing the
// exact same open/metadata/allocation/read/trailing engine with protected roles.
#[derive(Clone, Copy)]
enum MetadataPolicy {
    Protected {
        private: bool,
        owner: CredentialOwnerPolicyV1,
    },
    PublicRegular,
}

/// Parks one bounded credential read without establishing role admission.
///
/// Construction performs no file access. Entry is single-shot: later calls keep
/// the original descriptor, native results, and any partially filled zeroizing
/// buffer. Only a completed present read exposes credential bytes. The owner
/// must retain this object for as long as failed acquisition custody is needed.
/// No process-wide memory fit or custody of allocator internals is implied.
pub struct FixedRoleCredentialReadV1 {
    // Mapped I/O errors drop before the buffer, then metadata and the file,
    // matching the ordinary reader's early-return and zeroization order.
    exact: Option<io::Result<()>>,
    trailing: Option<io::Result<usize>>,
    allocation: Option<Result<(), TryReserveError>>,
    bytes: Option<Zeroizing<Vec<u8>>>,
    trailing_byte: Zeroizing<[u8; 1]>,
    admission: Option<Result<(), FixedRoleCredentialErrorV1>>,
    size: Option<Result<usize, TryFromIntError>>,
    metadata: Option<io::Result<Metadata>>,
    open: Option<Result<File, rustix::io::Errno>>,
    fixed_length: Option<Result<usize, TryFromIntError>>,
    completion: Option<Result<Option<()>, FixedRoleCredentialErrorV1>>,
    entered: bool,
    positional_open: Option<io::Result<Option<File>>>,
    retired_completed_file: bool,
}

/// Borrows the original reached outcomes of one nonauthorizing file read.
///
/// Unreached operations are absent. Errors are borrowed from their native
/// storage; this view does not reconstruct a cause from an error label.
pub struct FixedRoleCredentialReadViewV1<'a> {
    /// Retains the fixed-length conversion when the fixed reader was selected.
    pub fixed_length: Option<&'a Result<usize, TryFromIntError>>,
    /// Records explicit disposal of a complete positive read's native File.
    pub retired_completed_file: bool,
    /// Retains the positional read duplicate or its original native error.
    /// Successful complete positional reads dispose their actual duplicate.
    pub positional_open: Option<&'a io::Result<Option<File>>>,
    /// Retains the actual opened file or the original open errno.
    pub open: Option<&'a Result<File, rustix::io::Errno>>,
    /// Retains the metadata result from that same opened file.
    pub metadata: Option<&'a io::Result<Metadata>>,
    /// Retains the conversion of the observed file length to the native size.
    pub size: Option<&'a Result<usize, TryFromIntError>>,
    /// Retains the selected public/protected metadata and length check result.
    pub admission: Option<&'a Result<(), FixedRoleCredentialErrorV1>>,
    /// Retains the actual reservation result only for a retained read.
    pub allocation: Option<&'a Result<(), TryReserveError>>,
    /// Retains the exact read result, including its original I/O error.
    pub exact: Option<&'a io::Result<()>>,
    /// Retains the trailing read result, including its original I/O error.
    pub trailing: Option<&'a io::Result<usize>>,
    /// Borrows the actual trailing byte, kept zeroizing even on failure.
    pub trailing_byte: &'a Zeroizing<[u8; 1]>,
    /// Retains the ordinary optional completion, including missing-file `None`.
    pub completion: Option<&'a Result<Option<()>, FixedRoleCredentialErrorV1>>,
}

impl FixedRoleCredentialReadV1 {
    /// Constructs an empty read reservoir without opening or allocating a buffer.
    pub fn prearmed() -> Self {
        Self {
            exact: None,
            trailing: None,
            allocation: None,
            bytes: None,
            trailing_byte: Zeroizing::new([0_u8; 1]),
            admission: None,
            size: None,
            metadata: None,
            open: None,
            fixed_length: None,
            completion: None,
            entered: false,
            positional_open: None,
            retired_completed_file: false,
        }
    }

    /// Bounds transient joined-path conversion before a credential open.
    ///
    /// This pure byte geometry creates no path or receiving authority. The
    /// consuming native argument conversion ends before the next reader starts.
    /// Returns `None` on checked size overflow.
    #[must_use]
    pub fn joined_path_receiving_bytes_v1(directory: &Path, name: &str) -> Option<usize> {
        Self::joined_path_receiving_bytes_for_lengths_v1(
            directory.as_os_str().as_bytes().len(), name.len(),
        )
    }

    /// Bounds the same conversion from already bounded directory and leaf sizes.
    ///
    /// Three path extents cover growth and CString boxing overlap, including
    /// separator/NUL. Headers belong to the byte peak, not namespace entries.
    /// No allocation occurs; `None` reports checked representation overflow.
    #[must_use]
    pub fn joined_path_receiving_bytes_for_lengths_v1(
        directory_bytes: usize,
        name_bytes: usize,
    ) -> Option<usize> {
        directory_bytes.checked_add(name_bytes)?
            .checked_add(2)?.checked_mul(3)?
            .checked_add(std::mem::size_of::<std::path::PathBuf>())?
            .checked_add(std::mem::size_of::<std::ffi::OsString>())?
            .checked_add(std::mem::size_of::<Vec<u8>>())?
            .checked_add(std::mem::size_of::<Result<std::ffi::CString, std::ffi::NulError>>())?
            .checked_add(std::mem::size_of::<std::borrow::Cow<'static, std::ffi::CStr>>())
    }

    /// Enters the common bounded reader once and parks all reached outcomes.
    ///
    /// Later entries do nothing, even after failure. Inspect `outcome` for the
    /// optional result and `view` for borrowed native causes. This operation
    /// supplies file custody only, without role or startup authority.
    pub fn read_once(
        &mut self,
        directory: &Path,
        name: &str,
        minimum: usize,
        maximum: usize,
        private: bool,
        owner_policy: CredentialOwnerPolicyV1,
    ) {
        if self.entered {
            return;
        }
        self.entered = true;

        self.completion = Some(read_bounded_role_credential_v1::<true>(
            directory,
            name,
            minimum,
            maximum,
            MetadataPolicy::Protected { private, owner: owner_policy },
            self,
        ));
    }

    /// Parks a bounded public regular-file read under its original metadata policy.
    ///
    /// The public signer profile adds no private-mode, link-count or owner
    /// check. Missing input stays optional DATA until its role requires it.
    /// Reentry preserves the first native outcomes and cannot reread a file.
    pub fn read_public_once(&mut self, directory: &Path, name: &str, maximum: usize) {
        if self.entered {
            return;
        }
        self.entered = true;
        self.completion = Some(read_bounded_role_credential_v1::<true>(
            directory, name, 1, maximum, MetadataPolicy::PublicRegular, self,
        ));
    }

    /// Disposes only actual Files from a complete, present native-positive read.
    ///
    /// The closed higher owner calls this after its entire typed constructor
    /// succeeded. Raw bytes, metadata, read outcomes and the one-shot latch
    /// remain; absent, failed and unentered slots are untouched. This operation
    /// supplies no authority, currentness, financial refund or reusable grant.
    /// Source and Ownership readers do not call it automatically.
    #[must_use]
    pub fn retire_completed_file_once_v1(&mut self) -> bool {
        if self.retired_completed_file
            || !matches!(self.completion, Some(Ok(Some(()))))
            || self.failure().is_some()
        {
            return false;
        }
        let mut disposed = false;
        if matches!(self.open, Some(Ok(_))) {
            // The native success is now represented by the explicit retired
            // marker; errors can never enter this branch or be taken away.
            drop(self.open.take());
            disposed = true;
        }
        if let Some(Ok(file)) = self.positional_open.as_mut() {
            if file.is_some() {
                drop(file.take());
                disposed = true;
            }
        }
        self.retired_completed_file = disposed;
        disposed
    }

    /// Reads an exact bounded prefix positionally through one retained duplicate.
    ///
    /// The genuine caller has already checked metadata and paid the buffer/file
    /// peak. This shares the exact/trailing byte engine, supplies no role or key
    /// authority, and never changes the original descriptor's stream offset.
    /// Partial bytes, the native duplicate and failed outcomes remain resident.
    /// Complete positive reads dispose the duplicate at the ordinary read return
    /// frontier, while keeping bytes and actual native results in this owner.
    pub fn read_exact_at_once(&mut self, descriptor: std::os::fd::BorrowedFd<'_>, length: usize) {
        if self.entered {
            return;
        }
        self.entered = true;
        self.completion = Some((|| {
            let bytes = self.bytes.insert(Zeroizing::new(Vec::new()));
            self.allocation = Some(bytes.try_reserve_exact(length));
            if !matches!(self.allocation, Some(Ok(()))) {
                return Err(FixedRoleCredentialErrorV1);
            }
            bytes.resize(length, 0);
            self.positional_open = Some(descriptor.try_clone_to_owned()
                .map(|file| Some(File::from(file))));
            let file = match self.positional_open.as_ref() {
                Some(Ok(Some(file))) => file,
                _ => return Err(FixedRoleCredentialErrorV1),
            };
            read_credential_bytes_v1(CredentialBytePositionV1::AtZero(file), bytes,
                &mut self.exact, &mut self.trailing, Some(&mut *self.trailing_byte))?;
            Ok(Some(()))
        })());
        if matches!(self.completion, Some(Ok(Some(())))) {
            if let Some(Ok(file)) = self.positional_open.as_mut() {
                drop(file.take());
            }
        }
    }

    /// Reads a bounded leaf relative to the caller's retained directory once.
    ///
    /// This shares the ordinary admission/read engine and returns only file
    /// custody. The caller retains the directory, purpose, currentness and
    /// resource obligations; neither the descriptor nor a successful read
    /// constructs a role original.
    pub fn read_at_once(
        &mut self,
        directory: std::os::fd::BorrowedFd<'_>,
        name: &str,
        minimum: usize,
        maximum: usize,
        private: bool,
        owner_policy: CredentialOwnerPolicyV1,
    ) {
        if self.entered {
            return;
        }
        self.entered = true;
        let opened = openat(directory, name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty()).map(File::from);
        self.completion = Some(read_opened_role_credential_v1::<true>(
            opened, minimum, maximum, MetadataPolicy::Protected { private, owner: owner_policy }, self,
        ));
    }

    /// Enters the same fixed reader once, retaining its native length conversion.
    ///
    /// Missing files remain optional `None`. Repeated entry cannot retry or
    /// replace any reached outcome, including a failed length conversion.
    pub fn read_fixed_once(
        &mut self,
        directory: &Path,
        name: &str,
        length: u64,
        private: bool,
    ) {
        if self.entered {
            return;
        }
        self.entered = true;
        self.fixed_length = Some(usize::try_from(length));

        let length = match self.fixed_length.as_ref() {
            Some(Ok(length)) => *length,
            _ => {
                self.completion = Some(Err(FixedRoleCredentialErrorV1));
                return;
            }
        };
        self.completion = Some(read_bounded_role_credential_v1::<true>(
            directory,
            name,
            length,
            length,
            MetadataPolicy::Protected { private, owner: CredentialOwnerPolicyV1::Any },
            self,
        ));
    }

    /// Borrows only a completed optional read or its original completion error.
    ///
    /// Before entry no outcome exists. A present buffer is exposed only after
    /// successful exact and trailing reads; partial secret bytes stay parked.
    ///
    /// # Errors
    /// Borrows the existing failure for an unsafe, unavailable, unallocatable,
    /// or inexact read; missing files retain their successful optional `None`.
    pub fn outcome(
        &self,
    ) -> Option<Result<Option<&Zeroizing<Vec<u8>>>, &FixedRoleCredentialErrorV1>> {
        match self.completion.as_ref()? {
            Ok(None) => Some(Ok(None)),
            Ok(Some(())) => self.bytes.as_ref().map(|bytes| Ok(Some(bytes))),
            Err(error) => Some(Err(error)),
        }
    }

    /// Moves the exact completed input buffer to its existing role destination.
    ///
    /// Only a wholly successful present read permits this once-only transfer.
    /// Partial secret bytes and all original file and native outcomes remain
    /// in this owner on failure. After transfer, [`Self::outcome`] returns
    /// `None`; [`Self::view`] still exposes the actual completed read results.
    /// This operation neither clones the credential nor releases its file.
    pub fn take_success_bytes_once(&mut self) -> Option<Vec<u8>> {
        if !matches!(self.completion, Some(Ok(Some(())))) {
            return None;
        }
        let mut bytes = self.bytes.take()?;
        Some(std::mem::take(&mut *bytes))
    }

    /// Borrows the first reached native or admission failure in read order.
    ///
    /// A native absence error remains available here. Callers interpret optional
    /// absence from the completed read outcome and retain any fixed-role refusal
    /// separately; this borrower does not decide whether presence is required.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.fixed_length.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.open.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.metadata.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.size.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.admission.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.allocation.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.positional_open.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.exact.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.trailing.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.completion.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    /// Borrows each reached native result without copying errors or secret bytes.
    pub fn view(&self) -> FixedRoleCredentialReadViewV1<'_> {
        FixedRoleCredentialReadViewV1 {
            fixed_length: self.fixed_length.as_ref(),
            retired_completed_file: self.retired_completed_file,
            positional_open: self.positional_open.as_ref(),
            open: self.open.as_ref(),
            metadata: self.metadata.as_ref(),
            size: self.size.as_ref(),
            admission: self.admission.as_ref(),
            allocation: self.allocation.as_ref(),
            exact: self.exact.as_ref(),
            trailing: self.trailing.as_ref(),
            trailing_byte: &self.trailing_byte,
            completion: self.completion.as_ref(),
        }
    }
}

/// Reads an optional bounded credential through the common systemd file boundary.
///
/// The buffer is wiped on failed reads; successful callers retain responsibility
/// for wiping secret bytes once their role-specific validation is complete.
///
/// # Errors
/// Rejects unsafe metadata, out-of-bounds length, unavailable or inexact reads.
pub fn read_optional_bounded_role_credential_v1(
    directory: &Path,
    name: &str,
    minimum: usize,
    maximum: usize,
    private: bool,
    owner_policy: CredentialOwnerPolicyV1,
) -> Result<Option<Vec<u8>>, FixedRoleCredentialErrorV1> {
    let mut read = FixedRoleCredentialReadV1::prearmed();
    let present = read_bounded_role_credential_v1::<false>(
        directory,
        name,
        minimum,
        maximum,
        MetadataPolicy::Protected { private, owner: owner_policy },
        &mut read,
    )?;

    match present {
        None => Ok(None),
        Some(()) => match read.bytes.as_mut() {
            Some(bytes) => Ok(Some(std::mem::take(&mut **bytes))),
            None => Err(FixedRoleCredentialErrorV1),
        },
    }
}

/// Reads a required public regular-file credential through the shared engine.
///
/// This preserves the original public signer metadata policy: regular-file
/// type, nonempty bounded length, no followed final symlink, and exact input.
/// It deliberately adds no owner, link-count or private-mode requirement.
///
/// # Errors
/// Rejects missing/unavailable input, a nonregular or oversized file, allocation
/// or native read failure, and a trailing byte beyond the observed length.
pub fn read_required_public_role_credential_v1(
    directory: &Path,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, FixedRoleCredentialErrorV1> {
    let mut read = FixedRoleCredentialReadV1::prearmed();
    let present = read_bounded_role_credential_v1::<false>(
        directory, name, 1, maximum, MetadataPolicy::PublicRegular, &mut read,
    )?;
    if present.is_none() {
        return Err(FixedRoleCredentialErrorV1);
    }
    let bytes = read.bytes.as_mut().ok_or(FixedRoleCredentialErrorV1)?;
    Ok(std::mem::take(&mut **bytes))
}

// `RETAINED = false` keeps the original vec allocation, transient trailing-byte
// buffer, error projection, and successful Vec transfer. Both specializations
// run this one ordered file admission and read engine.
fn read_bounded_role_credential_v1<const RETAINED: bool>(
    directory: &Path,
    name: &str,
    minimum: usize,
    maximum: usize,
    metadata_policy: MetadataPolicy,
    read: &mut FixedRoleCredentialReadV1,
) -> Result<Option<()>, FixedRoleCredentialErrorV1> {
    let opened = openat(
        CWD,
        directory.join(name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ).map(File::from);
    read_opened_role_credential_v1::<RETAINED>(
        opened, minimum, maximum, metadata_policy, read,
    )
}

fn read_opened_role_credential_v1<const RETAINED: bool>(
    opened: Result<File, rustix::io::Errno>,
    minimum: usize,
    maximum: usize,
    metadata_policy: MetadataPolicy,
    read: &mut FixedRoleCredentialReadV1,
) -> Result<Option<()>, FixedRoleCredentialErrorV1> {
    read.open = Some(opened);
    let file = match read.open.as_mut() {
        Some(Ok(file)) => file,
        Some(Err(rustix::io::Errno::NOENT)) => return Ok(None),
        _ => return Err(FixedRoleCredentialErrorV1),
    };

    read.metadata = Some(file.metadata());
    let metadata = match read.metadata.as_ref() {
        Some(Ok(metadata)) => metadata,
        _ => return Err(FixedRoleCredentialErrorV1),
    };
    read.size = Some(usize::try_from(metadata.len()));
    let size = match read.size.as_ref() {
        Some(Ok(size)) => *size,
        _ => return Err(FixedRoleCredentialErrorV1),
    };
    let valid_metadata = match metadata_policy {
        MetadataPolicy::PublicRegular => metadata.is_file(),
        MetadataPolicy::Protected { private, owner } => {
            let valid_owner = match owner {
                CredentialOwnerPolicyV1::Any => true,
                CredentialOwnerPolicyV1::Root => metadata.uid() == 0,
                CredentialOwnerPolicyV1::RootOrCurrent => {
                    metadata.uid() == 0 || metadata.uid() == rustix::process::geteuid().as_raw()
                }
            };
            metadata.is_file()
                && valid_owner
                && metadata.nlink() == 1
                && metadata.mode() & 0o022 == 0
                && (!private || metadata.mode() & 0o077 == 0)
        }
    };
    if !valid_metadata || !(minimum..=maximum).contains(&size) {
        read.admission = Some(Err(FixedRoleCredentialErrorV1));
        return Err(FixedRoleCredentialErrorV1);
    }
    read.admission = Some(Ok(()));

    let bytes = read.bytes.insert(if RETAINED {
        Zeroizing::new(Vec::new())
    } else {
        Zeroizing::new(vec![0; size])
    });
    if RETAINED {
        read.allocation = Some(bytes.try_reserve_exact(size));
        if !matches!(read.allocation, Some(Ok(()))) {
            return Err(FixedRoleCredentialErrorV1);
        }
        bytes.resize(size, 0);
    }

    read_credential_bytes_v1(CredentialBytePositionV1::Sequential(file), bytes,
        &mut read.exact, &mut read.trailing,
        if RETAINED { Some(&mut *read.trailing_byte) } else { None })?;
    Ok(Some(()))
}

enum CredentialBytePositionV1<'file> {
    Sequential(&'file mut File),
    AtZero(&'file File),
}

// Both sequential credentials and Broker's existing positional reads execute
// this same exact-then-trailing engine. Custody/metadata/authority stay outside.
fn read_credential_bytes_v1(
    mut position: CredentialBytePositionV1<'_>,
    bytes: &mut [u8],
    exact: &mut Option<io::Result<()>>,
    trailing: &mut Option<io::Result<usize>>,
    retained_trailing: Option<&mut [u8; 1]>,
) -> Result<(), FixedRoleCredentialErrorV1> {
    *exact = Some(match &mut position {
        CredentialBytePositionV1::Sequential(file) => file.read_exact(bytes),
        CredentialBytePositionV1::AtZero(file) => file.read_exact_at(bytes, 0),
    });
    if !matches!(exact, Some(Ok(()))) {
        return Err(FixedRoleCredentialErrorV1);
    }
    let mut local_trailing = [0_u8; 1];
    let tail = retained_trailing.unwrap_or(&mut local_trailing);
    *trailing = Some(match &mut position {
        CredentialBytePositionV1::Sequential(file) => file.read(tail),
        CredentialBytePositionV1::AtZero(file) => file.read_at(tail, bytes.len() as u64),
    });
    if !matches!(trailing, Some(Ok(0))) {
        return Err(FixedRoleCredentialErrorV1);
    }
    Ok(())
}

/// Reports the unchanged exact/trailing result of a positional credential read.
#[derive(Debug, thiserror::Error)]
pub enum CredentialBytesAtErrorV1 {
    /// The exact or trailing native read failed.
    #[error(transparent)]
    Native(#[from] io::Error),
    /// The native trailing read observed bytes beyond the admitted length.
    #[error("credential has trailing bytes")]
    TrailingBytes,
}

/// Reads exact credential bytes at offset zero through the shared byte engine.
///
/// The caller retains its existing descriptor, metadata policy and buffer. This
/// performs neither a duplicate nor any financial or role admission.
///
/// # Errors
/// Preserves the original exact/trailing native error or excess-byte refusal.
pub fn read_credential_bytes_at_v1(file: &File, bytes: &mut [u8])
    -> Result<(), CredentialBytesAtErrorV1>
{
    let mut exact = None;
    let mut trailing = None;
    let mut tail = Zeroizing::new([0_u8; 1]);
    if read_credential_bytes_v1(CredentialBytePositionV1::AtZero(file), bytes,
        &mut exact, &mut trailing, Some(&mut *tail)).is_ok() {
        return Ok(());
    }
    if let Some(Err(error)) = exact {
        return Err(CredentialBytesAtErrorV1::Native(error));
    }
    if let Some(Err(error)) = trailing {
        return Err(CredentialBytesAtErrorV1::Native(error));
    }
    Err(CredentialBytesAtErrorV1::TrailingBytes)
}

/// Reads one fixed, bounded systemd credential without following its final name.
///
/// # Errors
/// Rejects unsafe metadata, unavailable files or inexact bounded reads.
pub fn read_optional_fixed_role_credential_v1(
    directory: &Path,
    name: &str,
    length: u64,
    private: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, FixedRoleCredentialErrorV1> {
    let length = usize::try_from(length).map_err(|_| FixedRoleCredentialErrorV1)?;
    read_optional_bounded_role_credential_v1(
        directory,
        name,
        length,
        length,
        private,
        CredentialOwnerPolicyV1::Any,
    )
    .map(|bytes| bytes.map(Zeroizing::new))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn public_profile_shares_reads_without_adding_protected_metadata_rules() {
        let directory = tempfile::tempdir().unwrap();
        let public = directory.path().join("public");
        fs::write(&public, b"public-key").unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o666)).unwrap();
        fs::hard_link(&public, directory.path().join("alias")).unwrap();

        let ordinary = read_required_public_role_credential_v1(
            directory.path(), "public", 32,
        ).unwrap();
        let mut retained = FixedRoleCredentialReadV1::prearmed();
        retained.read_public_once(directory.path(), "public", 32);

        assert_eq!(ordinary, b"public-key");
        assert_eq!(retained.outcome().unwrap().unwrap().unwrap().as_slice(), ordinary);
        assert!(read_optional_bounded_role_credential_v1(
            directory.path(), "public", 1, 32, false, CredentialOwnerPolicyV1::Any,
        ).is_err());
        assert!(matches!(retained.view().open, Some(Ok(_))));
        assert!(matches!(retained.view().metadata, Some(Ok(_))));
        assert!(matches!(retained.view().exact, Some(Ok(()))));
        assert!(matches!(retained.view().trailing, Some(Ok(0))));
    }

    #[test]
    fn successful_buffer_transfer_moves_once_and_keeps_native_read_custody() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("role");
        fs::write(&path, [1, 2, 3]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut read = FixedRoleCredentialReadV1::prearmed();
        read.read_once(directory.path(), "role", 3, 3, true, CredentialOwnerPolicyV1::Any);
        let original = read.outcome().unwrap().unwrap().unwrap().as_ptr();

        let bytes = read.take_success_bytes_once().unwrap();

        assert_eq!(bytes, [1, 2, 3]);
        assert_eq!(bytes.as_ptr(), original);
        assert!(read.take_success_bytes_once().is_none());
        assert!(read.outcome().is_none());
        assert!(matches!(read.view().open, Some(Ok(_))));
        assert!(matches!(read.view().completion, Some(Ok(Some(())))));
    }

    #[test]
    fn refused_buffer_transfer_keeps_the_same_failed_read() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("role");
        fs::write(&path, [1, 2, 3, 4]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut read = FixedRoleCredentialReadV1::prearmed();
        read.read_once(directory.path(), "role", 3, 3, true, CredentialOwnerPolicyV1::Any);

        assert!(read.take_success_bytes_once().is_none());
        assert!(matches!(read.view().admission, Some(Err(_))));
        assert!(matches!(read.view().open, Some(Ok(_))));
        assert!(matches!(read.view().completion, Some(Err(_))));
    }

    #[test]
    fn bounded_reader_rejects_missing_bounds_and_unsafe_leaves() {
        let directory = tempfile::tempdir().unwrap();
        let read = |name| {
            read_optional_bounded_role_credential_v1(
                directory.path(),
                name,
                1,
                3,
                true,
                CredentialOwnerPolicyV1::Any,
            )
        };
        assert!(read("credential").unwrap().is_none());

        let path = directory.path().join("credential");
        fs::write(&path, [1, 2]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read("credential").unwrap().unwrap(), [1, 2]);

        fs::write(&path, []).unwrap();
        assert!(read("credential").is_err());
        fs::write(&path, [1, 2, 3, 4]).unwrap();
        assert!(read("credential").is_err());
        fs::write(&path, [1, 2, 3]).unwrap();
        assert_eq!(read("credential").unwrap().unwrap(), [1, 2, 3]);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read("credential").is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&path, directory.path().join("link")).unwrap();
        assert!(read("link").is_err());
    }

    #[test]
    fn unrun_shared_reader_retains_owner_type_link_and_public_mode_policy() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("role");
        fs::write(&path, [1, 2, 3]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().uid(),
            rustix::process::geteuid().as_raw(),
        );
        let read = |name, private| {
            read_optional_bounded_role_credential_v1(
                directory.path(),
                name,
                1,
                3,
                private,
                CredentialOwnerPolicyV1::RootOrCurrent,
            )
        };

        assert_eq!(read("role", false).unwrap().unwrap(), [1, 2, 3]);
        assert!(read("role", true).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap();
        assert!(read("role", false).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, directory.path().join("linked")).unwrap();
        assert!(read("role", true).is_err());
        assert!(read("linked", true).is_err());
        fs::create_dir(directory.path().join("not-file")).unwrap();
        assert!(read("not-file", false).is_err());
    }

    #[test]
    fn unrun_fixed_reader_preserves_exact_length_and_zeroizing_success_container() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixed");
        fs::write(&path, [4, 5]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let bytes: Zeroizing<Vec<u8>> = read_optional_fixed_role_credential_v1(
            directory.path(),
            "fixed",
            2,
            true,
        )
        .unwrap()
        .unwrap();

        assert_eq!(bytes.as_slice(), &[4, 5]);
        assert!(read_optional_fixed_role_credential_v1(
            directory.path(),
            "fixed",
            1,
            true,
        )
        .is_err());
        assert!(read_optional_fixed_role_credential_v1(
            directory.path(),
            "absent",
            2,
            true,
        )
        .unwrap()
        .is_none());
        assert!(read_optional_bounded_role_credential_v1(
            directory.path(),
            "fixed",
            3,
            2,
            true,
            CredentialOwnerPolicyV1::Any,
        )
        .is_err());
    }

    #[test]
    fn retained_directory_reader_uses_original_after_its_name_is_replaced() {
        use std::os::fd::AsFd as _;

        let parent = tempfile::tempdir().unwrap();
        let original_path = parent.path().join("credential-directory");
        fs::create_dir(&original_path).unwrap();
        fs::write(original_path.join("key"), [1, 2, 3]).unwrap();
        fs::set_permissions(original_path.join("key"), fs::Permissions::from_mode(0o600)).unwrap();
        let directory = File::open(&original_path).unwrap();
        fs::rename(&original_path, parent.path().join("retained-original")).unwrap();
        fs::create_dir(&original_path).unwrap();
        fs::write(original_path.join("key"), [9, 9, 9]).unwrap();
        fs::set_permissions(original_path.join("key"), fs::Permissions::from_mode(0o600)).unwrap();
        let mut read = FixedRoleCredentialReadV1::prearmed();

        read.read_at_once(directory.as_fd(), "key", 3, 3, true,
            CredentialOwnerPolicyV1::RootOrCurrent);

        assert_eq!(read.outcome().unwrap().unwrap().unwrap().as_slice(), &[1, 2, 3]);
        assert!(read.failure().is_none());
        assert!(read.view().open.unwrap().is_ok());
    }


    #[test]
    fn positional_partial_read_keeps_duplicate_bytes_and_original_io_cause() {
        use std::os::fd::AsFd as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("short");
        fs::write(&path, [7, 8]).unwrap();
        let file = File::open(&path).unwrap();
        let mut read = FixedRoleCredentialReadV1::prearmed();

        read.read_exact_at_once(file.as_fd(), 4);

        assert!(read.outcome().unwrap().is_err());
        assert!(matches!(read.view().positional_open, Some(Ok(Some(_)))));
        assert!(matches!(read.view().exact, Some(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof));
        assert!(read.view().trailing.is_none());
        assert_eq!(&read.bytes.as_ref().unwrap()[..2], &[7, 8]);
        let first = read.failure().unwrap().downcast_ref::<io::Error>().unwrap() as *const io::Error;
        read.read_exact_at_once(file.as_fd(), 2);
        assert_eq!(read.failure().unwrap().downcast_ref::<io::Error>().unwrap() as *const _, first);
        assert!(matches!(read.view().positional_open, Some(Ok(Some(_)))));
    }

    #[test]
    fn positive_positional_read_closes_only_duplicate_and_preserves_stream_offset() {
        use std::io::{Seek as _, SeekFrom};
        use std::os::fd::AsFd as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("value");
        fs::write(&path, [1, 2, 3]).unwrap();
        let mut file = File::open(&path).unwrap();
        file.seek(SeekFrom::Start(1)).unwrap();
        let mut read = FixedRoleCredentialReadV1::prearmed();

        read.read_exact_at_once(file.as_fd(), 3);

        assert!(read.failure().is_none());
        assert!(matches!(read.view().positional_open, Some(Ok(None))));
        assert_eq!(read.take_success_bytes_once().unwrap(), [1, 2, 3]);
        assert_eq!(file.stream_position().unwrap(), 1);
    }


    #[test]
    fn explicit_positive_file_retirement_preserves_bytes_and_native_read_results() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("value");
        fs::write(&path, [1, 2, 3]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut read = FixedRoleCredentialReadV1::prearmed();
        read.read_once(directory.path(), "value", 3, 3, true,
            CredentialOwnerPolicyV1::RootOrCurrent);
        let bytes = read.outcome().unwrap().unwrap().unwrap().as_ptr();

        assert!(read.retire_completed_file_once_v1());

        assert!(read.view().open.is_none());
        assert!(read.view().retired_completed_file);
        assert!(matches!(read.view().metadata, Some(Ok(_))));
        assert!(matches!(read.view().exact, Some(Ok(()))));
        assert!(matches!(read.view().trailing, Some(Ok(0))));
        assert_eq!(read.outcome().unwrap().unwrap().unwrap().as_ptr(), bytes);
        assert!(!read.retire_completed_file_once_v1());
        assert!(read.failure().is_none());
    }

    #[test]
    fn explicit_retirement_cannot_dispose_absent_or_failed_file_originals() {
        let directory = tempfile::tempdir().unwrap();
        let mut absent = FixedRoleCredentialReadV1::prearmed();
        absent.read_once(directory.path(), "absent", 1, 3, true,
            CredentialOwnerPolicyV1::RootOrCurrent);
        assert!(!absent.retire_completed_file_once_v1());
        assert!(matches!(absent.view().open, Some(Err(rustix::io::Errno::NOENT))));
        assert!(!absent.view().retired_completed_file);

        let path = directory.path().join("value");
        fs::write(&path, [1, 2, 3, 4]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut failed = FixedRoleCredentialReadV1::prearmed();
        failed.read_once(directory.path(), "value", 1, 3, true,
            CredentialOwnerPolicyV1::RootOrCurrent);
        assert!(!failed.retire_completed_file_once_v1());
        assert!(matches!(failed.view().open, Some(Ok(_))));
        assert!(!failed.view().retired_completed_file);
        assert!(failed.failure().is_some());
    }

}
