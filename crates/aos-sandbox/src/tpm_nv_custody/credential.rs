//! Shared bounded file admission for optional, separate-purpose role credentials.
//!
//! Callers retain their own role codec, seed correspondence, and key-reuse
//! checks. This reader only preserves the common systemd file boundary.

use std::fs::File;
use std::io::Read as _;
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
    let descriptor = match openat(
        CWD,
        directory.join(name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(FixedRoleCredentialErrorV1),
    };
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| FixedRoleCredentialErrorV1)?;
    let size = usize::try_from(metadata.len()).map_err(|_| FixedRoleCredentialErrorV1)?;
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
        return Err(FixedRoleCredentialErrorV1);
    }

    let mut bytes = Zeroizing::new(vec![0; size]);
    file.read_exact(&mut bytes)
        .map_err(|_| FixedRoleCredentialErrorV1)?;
    if file
        .read(&mut [0_u8; 1])
        .map_err(|_| FixedRoleCredentialErrorV1)?
        != 0
    {
        return Err(FixedRoleCredentialErrorV1);
    }
    Ok(Some(std::mem::take(&mut *bytes)))
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
