//! Shares the existing bounded credential reader without changing role policies.
//!
//! Callers retain their role codec, seed correspondence and key-reuse checks.
//! The lower shared primitive is file admission only, never floor authority.

pub(crate) use aos_sandbox::tpm_nv_custody::credential::{
    CredentialOwnerPolicyV1, FixedRoleCredentialErrorV1,
    read_optional_bounded_role_credential_v1, read_optional_fixed_role_credential_v1,
};

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
}
