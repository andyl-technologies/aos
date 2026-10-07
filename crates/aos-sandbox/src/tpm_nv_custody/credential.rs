//! Shared bounded file admission for optional, separate-purpose role credentials.
//!
//! Callers retain their own role codec, seed correspondence, and key-reuse
//! checks. This reader only preserves the common systemd file boundary.

use std::collections::TryReserveError;
use std::fs::{File, Metadata};
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
    /// Requires root or the current effective UID as the observed file owner.
    RootOrCurrent,
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
}

/// Borrows the original reached outcomes of one nonauthorizing file read.
///
/// Unreached operations are absent. Errors are borrowed from their native
/// storage; this view does not reconstruct a cause from an error label.
pub struct FixedRoleCredentialReadViewV1<'a> {
    /// Retains the fixed-length conversion when the fixed reader was selected.
    pub fixed_length: Option<&'a Result<usize, TryFromIntError>>,
    /// Retains the actual opened file or the original open errno.
    pub open: Option<&'a Result<File, rustix::io::Errno>>,
    /// Retains the metadata result from that same opened file.
    pub metadata: Option<&'a io::Result<Metadata>>,
    /// Retains the conversion of the observed file length to the native size.
    pub size: Option<&'a Result<usize, TryFromIntError>>,
    /// Retains the existing type, owner, link, mode, and bound check result.
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
        }
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
            private,
            owner_policy,
            self,
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
            private,
            CredentialOwnerPolicyV1::Any,
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

    /// Borrows each reached native result without copying errors or secret bytes.
    pub fn view(&self) -> FixedRoleCredentialReadViewV1<'_> {
        FixedRoleCredentialReadViewV1 {
            fixed_length: self.fixed_length.as_ref(),
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
        private,
        owner_policy,
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

// `RETAINED = false` keeps the original vec allocation, transient trailing-byte
// buffer, error projection, and successful Vec transfer. Both specializations
// run this one ordered file admission and read engine.
fn read_bounded_role_credential_v1<const RETAINED: bool>(
    directory: &Path,
    name: &str,
    minimum: usize,
    maximum: usize,
    private: bool,
    owner_policy: CredentialOwnerPolicyV1,
    read: &mut FixedRoleCredentialReadV1,
) -> Result<Option<()>, FixedRoleCredentialErrorV1> {
    read.open = Some(
        openat(
            CWD,
            directory.join(name),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from),
    );
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
    let valid_owner = match owner_policy {
        CredentialOwnerPolicyV1::Any => true,
        CredentialOwnerPolicyV1::RootOrCurrent => {
            metadata.uid() == 0 || metadata.uid() == rustix::process::geteuid().as_raw()
        }
    };
    if !metadata.is_file()
        || !valid_owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || private && metadata.mode() & 0o077 != 0
        || !(minimum..=maximum).contains(&size)
    {
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

    read.exact = Some(file.read_exact(bytes));
    if !matches!(read.exact, Some(Ok(()))) {
        return Err(FixedRoleCredentialErrorV1);
    }
    read.trailing = Some(if RETAINED {
        file.read(&mut *read.trailing_byte)
    } else {
        file.read(&mut [0_u8; 1])
    });
    if !matches!(read.trailing, Some(Ok(0))) {
        return Err(FixedRoleCredentialErrorV1);
    }
    Ok(Some(()))
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
}
