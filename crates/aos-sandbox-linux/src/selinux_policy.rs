//! Shared, bounded comparison of a live enforcing SELinux policy with AOS's
//! immutable, deployment-kernel-bound canonical readback package.
//!
//! The proof is point-in-time. Callers keep their own authorization and
//! subject-label checks; matching policy bytes alone grants neither.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd};

use rustix::fs::{FileType, Mode, OFlags, fstat, fstatfs, open};
use sha2::{Digest as _, Sha256};

// selinuxfs serializes the loaded policydb, not the original compiled input.
// Only the selected kernel's canonical readback is a valid byte expectation.
const POLICY_SUFFIX: &str = "/policy.33";
const POLICY_PACKAGE: &str = "aos-selinux-kernel-policy-readback-1";
const STORE_HASH_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
const MAX_POLICY_BYTES: u64 = 64 * 1024 * 1024;
const SELINUXFS_MAGIC: u64 = 0xf97c_ff8c;

/// Reports an invalid live policy, package path, or kernel readback.
#[derive(Debug, thiserror::Error)]
#[error("SELinux policy readback rejected: {0}")]
pub struct PolicyReadbackError(&'static str);

/// Retains the digest of one exact enforcing policy comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedLiveSelinuxPolicy {
    digest: [u8; 32],
}

impl VerifiedLiveSelinuxPolicy {
    /// Compares the active policy to an immutable deployment-kernel readback.
    ///
    /// The caller supplies its image-pinned canonical readback path. Compiled
    /// policy inputs are not accepted: the loaded kernel serialization may
    /// differ even when the input was loaded without modification.
    ///
    /// # Errors
    ///
    /// Rejects a foreign path, permissive state, non-selinuxfs readback,
    /// changed or oversized package file, unequal bytes, or any read failure.
    pub fn verify(expected_path: &str) -> Result<Self, PolicyReadbackError> {
        validate_policy_path(expected_path)?;
        require_enforcing()?;

        let expected_fd = open(
            expected_path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| PolicyReadbackError("cannot open deployed policy"))?;
        let before =
            fstat(&expected_fd).map_err(|_| PolicyReadbackError("cannot stat deployed policy"))?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != 0
            || before.st_mode & 0o022 != 0
            || before.st_size <= 0
            || u64::try_from(before.st_size).unwrap_or(u64::MAX) > MAX_POLICY_BYTES
        {
            return Err(PolicyReadbackError(
                "deployed policy is not a bounded protected file",
            ));
        }

        let kernel_fd = open(
            "/sys/fs/selinux/policy",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| PolicyReadbackError("cannot open active policy"))?;
        require_selinuxfs(kernel_fd.as_fd())?;

        let mut expected = File::from(expected_fd);
        let mut kernel = File::from(kernel_fd);
        let digest = compare_policy_bytes(&mut expected, &mut kernel, before.st_size as u64)?;
        let after = fstat(expected.as_fd())
            .map_err(|_| PolicyReadbackError("cannot restat deployed policy"))?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_size != after.st_size
            || before.st_mode != after.st_mode
            || before.st_uid != after.st_uid
            || before.st_mtime != after.st_mtime
            || before.st_mtime_nsec != after.st_mtime_nsec
            || before.st_ctime != after.st_ctime
            || before.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(PolicyReadbackError(
                "deployed policy changed during comparison",
            ));
        }

        require_enforcing()?;
        Ok(Self { digest })
    }

    /// Repeats the comparison and requires the same policy digest.
    ///
    /// # Errors
    ///
    /// Rejects any change in enforcement, package custody, or policy bytes.
    pub fn revalidate(self, expected_path: &str) -> Result<(), PolicyReadbackError> {
        if Self::verify(expected_path)? != self {
            return Err(PolicyReadbackError(
                "active policy changed after verification",
            ));
        }
        Ok(())
    }

    /// Returns the digest of the exact live policy bytes.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

fn validate_policy_path(path: &str) -> Result<(), PolicyReadbackError> {
    let entry = path
        .strip_prefix("/nix/store/")
        .and_then(|value| value.strip_suffix(POLICY_SUFFIX))
        .ok_or(PolicyReadbackError("production policy path is not exact"))?;
    let (hash, package) = entry.split_once('-').ok_or(PolicyReadbackError(
        "production policy derivation is malformed",
    ))?;
    if hash.len() != 32
        || !hash.bytes().all(|byte| STORE_HASH_ALPHABET.contains(&byte))
        || package != POLICY_PACKAGE
    {
        return Err(PolicyReadbackError(
            "production policy derivation is not exact",
        ));
    }
    Ok(())
}

fn require_selinuxfs(fd: BorrowedFd<'_>) -> Result<(), PolicyReadbackError> {
    if fstatfs(fd)
        .map_err(|_| PolicyReadbackError("cannot identify SELinux filesystem"))?
        .f_type as u64
        != SELINUXFS_MAGIC
    {
        return Err(PolicyReadbackError("readback is not from selinuxfs"));
    }
    Ok(())
}

/// Requires the actual selinuxfs enforcement state without admitting a policy.
///
/// This kernel observation is not subject, image, or effect authority.
///
/// # Errors
///
/// Rejects absent or foreign selinuxfs, unreadable state, or permissive mode.
pub fn require_enforcing() -> Result<(), PolicyReadbackError> {
    let fd = open(
        "/sys/fs/selinux/enforce",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PolicyReadbackError("cannot open SELinux enforcement"))?;
    require_selinuxfs(fd.as_fd())?;

    let mut state = Vec::new();
    File::from(fd)
        .take(9)
        .read_to_end(&mut state)
        .map_err(|_| PolicyReadbackError("cannot read SELinux enforcement"))?;
    if state != b"1" && state != b"1\n" {
        return Err(PolicyReadbackError("SELinux is not enforcing"));
    }
    Ok(())
}

fn compare_policy_bytes(
    expected: &mut File,
    kernel: &mut File,
    size: u64,
) -> Result<[u8; 32], PolicyReadbackError> {
    let mut expected_chunk = [0_u8; 16 * 1024];
    let mut kernel_chunk = [0_u8; 16 * 1024];
    let mut remaining = size;
    let mut digest = Sha256::new();

    while remaining != 0 {
        let count = usize::try_from(remaining.min(expected_chunk.len() as u64))
            .map_err(|_| PolicyReadbackError("policy length is invalid"))?;
        expected
            .read_exact(&mut expected_chunk[..count])
            .map_err(|_| PolicyReadbackError("cannot read deployed policy"))?;
        kernel
            .read_exact(&mut kernel_chunk[..count])
            .map_err(|_| PolicyReadbackError("cannot read active policy"))?;
        if expected_chunk[..count] != kernel_chunk[..count] {
            return Err(PolicyReadbackError(
                "active policy differs from deployed policy",
            ));
        }
        digest.update(&expected_chunk[..count]);
        remaining -= count as u64;
    }

    let mut extra = [0_u8; 1];
    if expected
        .read(&mut extra)
        .map_err(|_| PolicyReadbackError("cannot finish deployed policy read"))?
        != 0
        || kernel
            .read(&mut extra)
            .map_err(|_| PolicyReadbackError("cannot finish active policy read"))?
            != 0
    {
        return Err(PolicyReadbackError(
            "policy length changed during comparison",
        ));
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, Write as _};

    use super::*;

    #[test]
    fn policy_path_is_exact_kernel_readback_derivation() {
        let valid = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aos-selinux-kernel-policy-readback-1/policy.33";
        assert!(validate_policy_path(valid).is_ok());

        for rejected in [
            "/tmp/policy.33".to_owned(),
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aos-selinux-production-policy-1/etc/selinux/aos/policy/policy.33".to_owned(),
            valid.replace("kernel-policy-readback", "test-policy-readback"),
            valid.replace("readback-1/", "readback-10/"),
            valid.replace("readback-1/", "readback-1-extra/"),
            valid.replace("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
            valid.replace("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            valid.replace("/policy.33", "/../policy.33"),
            format!("{valid}/extra"),
        ] {
            assert!(validate_policy_path(&rejected).is_err(), "{rejected}");
        }
    }

    #[test]
    fn canonical_policy_bytes_reject_input_or_changed_serialization() {
        let mut expected = tempfile::tempfile().unwrap();
        let mut active = tempfile::tempfile().unwrap();
        expected.write_all(b"canonical-policy").unwrap();
        active.write_all(b"compiled-policy!").unwrap();
        expected.rewind().unwrap();
        active.rewind().unwrap();

        assert!(compare_policy_bytes(&mut expected, &mut active, 16).is_err());
    }

    #[test]
    fn policy_streams_require_exact_bytes_and_length() {
        let mut expected = tempfile::tempfile().unwrap();
        let mut active = tempfile::tempfile().unwrap();
        expected.write_all(b"policy-one").unwrap();
        active.write_all(b"policy-one").unwrap();
        expected.rewind().unwrap();
        active.rewind().unwrap();
        let digest: [u8; 32] = Sha256::digest(b"policy-one").into();
        assert_eq!(
            compare_policy_bytes(&mut expected, &mut active, 10).unwrap(),
            digest
        );

        expected.rewind().unwrap();
        active.rewind().unwrap();
        assert!(compare_policy_bytes(&mut expected, &mut active, 9).is_err());
        active.rewind().unwrap();
        active.set_len(9).unwrap();
        expected.rewind().unwrap();
        assert!(compare_policy_bytes(&mut expected, &mut active, 10).is_err());
    }
}
