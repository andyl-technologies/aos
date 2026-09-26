//! Shared, bounded comparison of a live enforcing SELinux policy with AOS's
//! immutable production-policy package.
//!
//! The proof is point-in-time. Callers keep their own authorization and
//! subject-label checks; matching policy bytes alone grants neither.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd};

use rustix::fs::{FileType, Mode, OFlags, fstat, fstatfs, open};
use sha2::{Digest as _, Sha256};

const POLICY_SUFFIX: &str = "/etc/selinux/aos/policy/policy.33";
const POLICY_PACKAGE: &str = "aos-selinux-production-policy-1";
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
    /// Compares the active kernel policy to the immutable production package.
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
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
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

fn require_enforcing() -> Result<(), PolicyReadbackError> {
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
    fn policy_path_is_exact_production_derivation() {
        let valid = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aos-selinux-production-policy-1/etc/selinux/aos/policy/policy.33";
        assert!(validate_policy_path(valid).is_ok());
        assert!(validate_policy_path("/tmp/policy.33").is_err());
        assert!(validate_policy_path(&valid.replace("production-policy", "test-policy")).is_err());
        assert!(validate_policy_path(&format!("{valid}/extra")).is_err());
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
