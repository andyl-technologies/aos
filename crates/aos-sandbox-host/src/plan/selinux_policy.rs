//! Independent readback of the enforcing kernel SELinux policy.
//!
//! The source is the deployed, immutable AOS production-policy derivation,
//! not a phase-0 publisher digest. This proves one live MAC condition only;
//! it does not authorize a sandbox launch or replace per-payload inspection.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::AsFd as _;

use rustix::fs::{FileType, Mode, OFlags, fstat, fstatfs, open};
use sha2::{Digest as _, Sha256};

use crate::{HostError, Result};

const PRODUCTION_POLICY_SUFFIX: &str = "/etc/selinux/aos/policy/policy.33";
const MAXIMUM_POLICY_BYTES: u64 = 64 * 1024 * 1024;
const SELINUXFS_MAGIC: u64 = 0xf97c_ff8c;

/// Retains the digest of a production policy independently matched to the kernel.
///
/// The proof is point-in-time. Call [`Self::revalidate`] immediately before
/// any future operation that would consume it; current Host launch does not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedLiveSelinuxPolicyV1 {
    digest: [u8; 32],
}

impl VerifiedLiveSelinuxPolicyV1 {
    /// Compares the active enforcing policy with the exact deployed derivation.
    ///
    /// The policy path must name the immutable AOS production-policy output,
    /// and every byte of the kernel selinuxfs readback must match it. The
    /// separate enforcing flag is read both before and after comparison.
    ///
    /// # Errors
    ///
    /// Rejects a foreign path or filesystem, non-enforcing mode, a changed or
    /// oversized package, a mismatched kernel policy, or any read failure.
    pub fn verify(deployed_policy_path: &str) -> Result<Self> {
        validate_policy_path(deployed_policy_path)?;
        verify_enforcing()?;

        let expected_fd = open(
            deployed_policy_path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| {
            HostError::State(format!("cannot open deployed SELinux policy: {error}"))
        })?;
        let expected_before = fstat(&expected_fd).map_err(|error| {
            HostError::State(format!("cannot stat deployed SELinux policy: {error}"))
        })?;
        if FileType::from_raw_mode(expected_before.st_mode) != FileType::RegularFile
            || expected_before.st_uid != 0
            || expected_before.st_mode & 0o022 != 0
            || expected_before.st_size <= 0
            || u64::try_from(expected_before.st_size).unwrap_or(u64::MAX) > MAXIMUM_POLICY_BYTES
        {
            return Err(HostError::State(
                "deployed SELinux policy is not a bounded protected file".to_owned(),
            ));
        }

        let kernel_fd = open(
            "/sys/fs/selinux/policy",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| HostError::State(format!("cannot open active SELinux policy: {error}")))?;
        if fstatfs(&kernel_fd)
            .map_err(|error| {
                HostError::State(format!("cannot identify SELinux filesystem: {error}"))
            })?
            .f_type as u64
            != SELINUXFS_MAGIC
        {
            return Err(HostError::State(
                "active SELinux policy is not from selinuxfs".to_owned(),
            ));
        }

        let mut expected = File::from(expected_fd);
        let mut kernel = File::from(kernel_fd);
        let digest =
            compare_policy_bytes(&mut expected, &mut kernel, expected_before.st_size as u64)?;
        let expected_after = fstat(expected.as_fd()).map_err(|error| {
            HostError::State(format!("cannot restat deployed SELinux policy: {error}"))
        })?;
        if expected_before.st_dev != expected_after.st_dev
            || expected_before.st_ino != expected_after.st_ino
            || expected_before.st_size != expected_after.st_size
            || expected_before.st_mode != expected_after.st_mode
            || expected_before.st_uid != expected_after.st_uid
            || expected_before.st_mtime != expected_after.st_mtime
            || expected_before.st_mtime_nsec != expected_after.st_mtime_nsec
            || expected_before.st_ctime != expected_after.st_ctime
            || expected_before.st_ctime_nsec != expected_after.st_ctime_nsec
        {
            return Err(HostError::State(
                "deployed SELinux policy changed during comparison".to_owned(),
            ));
        }
        verify_enforcing()?;
        Ok(Self { digest })
    }

    /// Repeats the kernel/package comparison and requires the same policy.
    ///
    /// # Errors
    ///
    /// Returns an error if enforcement, package identity, or policy changed.
    pub fn revalidate(self, deployed_policy_path: &str) -> Result<()> {
        if Self::verify(deployed_policy_path)? != self {
            return Err(HostError::State(
                "active SELinux policy changed after verification".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the digest of the exact active production policy.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

fn validate_policy_path(path: &str) -> Result<()> {
    let Some(store_entry) = path.strip_prefix("/nix/store/") else {
        return Err(HostError::State(
            "production SELinux policy is not a Nix-store path".to_owned(),
        ));
    };
    let Some(derivation) = store_entry.strip_suffix(PRODUCTION_POLICY_SUFFIX) else {
        return Err(HostError::State(
            "production SELinux policy has the wrong package path".to_owned(),
        ));
    };
    let Some((hash, package_name)) = derivation.split_once('-') else {
        return Err(HostError::State(
            "production SELinux policy has the wrong derivation".to_owned(),
        ));
    };
    if hash.len() != 32
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || package_name != "aos-selinux-production-policy-1"
    {
        return Err(HostError::State(
            "production SELinux policy has the wrong derivation".to_owned(),
        ));
    }
    Ok(())
}

fn verify_enforcing() -> Result<()> {
    let fd = open(
        "/sys/fs/selinux/enforce",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| HostError::State(format!("cannot open SELinux enforcement: {error}")))?;
    if fstatfs(&fd)
        .map_err(|error| HostError::State(format!("cannot identify SELinux enforcement: {error}")))?
        .f_type as u64
        != SELINUXFS_MAGIC
    {
        return Err(HostError::State(
            "SELinux enforcement is not from selinuxfs".to_owned(),
        ));
    }
    let mut bytes = Vec::new();
    File::from(fd)
        .take(9)
        .read_to_end(&mut bytes)
        .map_err(|error| HostError::State(format!("cannot read SELinux enforcement: {error}")))?;
    if bytes != b"1" && bytes != b"1\n" {
        return Err(HostError::State("SELinux is not enforcing".to_owned()));
    }
    Ok(())
}

fn compare_policy_bytes(expected: &mut File, kernel: &mut File, size: u64) -> Result<[u8; 32]> {
    let mut expected_buffer = [0u8; 16 * 1024];
    let mut kernel_buffer = [0u8; 16 * 1024];
    let mut remaining = size;
    let mut hasher = Sha256::new();

    while remaining != 0 {
        let amount = usize::try_from(remaining.min(expected_buffer.len() as u64))
            .map_err(|_| HostError::State("SELinux policy length is invalid".to_owned()))?;
        expected
            .read_exact(&mut expected_buffer[..amount])
            .map_err(|error| {
                HostError::State(format!("cannot read deployed SELinux policy: {error}"))
            })?;
        kernel
            .read_exact(&mut kernel_buffer[..amount])
            .map_err(|error| {
                HostError::State(format!("cannot read active SELinux policy: {error}"))
            })?;
        if expected_buffer[..amount] != kernel_buffer[..amount] {
            return Err(HostError::State(
                "active SELinux policy differs from the deployed policy".to_owned(),
            ));
        }
        hasher.update(&expected_buffer[..amount]);
        remaining -= amount as u64;
    }
    let mut extra = [0u8; 1];
    if expected
        .read(&mut extra)
        .map_err(|error| HostError::State(error.to_string()))?
        != 0
        || kernel
            .read(&mut extra)
            .map_err(|error| HostError::State(error.to_string()))?
            != 0
    {
        return Err(HostError::State(
            "SELinux policy length changed during comparison".to_owned(),
        ));
    }
    Ok(hasher.finalize().into())
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
