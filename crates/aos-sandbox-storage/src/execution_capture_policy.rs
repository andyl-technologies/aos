//! Root-owned allocation and pool-identity policy for execution capture.
//!
//! The fixed file is loaded through a retained directory descriptor. Its
//! generation and exact digest are pinned for the process lifetime; a changed
//! publication requires restart before another candidate may be observed.
//! Root and domain selection comes separately from the protected resolver
//! policy catalog for the complete current assignment.
//!
//! ```text
//! AOSCCP01 | generation:u64be | authority-binding[32]
//!          | resolver-catalog-digest[32] | expected-pool-guid:u64be
//!          | metadata-headroom:u64be | minimum-remaining:u64be
//!          | maximum-allocation:u64be | sha256[32]
//! ```

use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_core::ObjectDigest;
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use sha2::{Digest as _, Sha256};

const FILE_NAME: &str = "execution-capture-policy.v1";
const MAGIC: &[u8; 8] = b"AOSCCP01";
const BYTES: usize = 144;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-allocation-policy.v1\0";

/// Reports an unsafe or changed protected capture allocation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CaptureAllocationPolicyErrorV1 {
    /// The directory or file cannot be safely opened and read.
    #[error("execution capture allocation policy path is insecure or absent")]
    ProtectedPath,
    /// The fixed policy is malformed or bound to another Storage authority.
    #[error("execution capture allocation policy is malformed")]
    Malformed,
    /// An atomic policy replacement changed the pinned generation or content.
    #[error("execution capture allocation policy changed after startup")]
    Changed,
    /// The admission exceeds protected allocation bounds.
    #[error("execution capture allocation exceeds protected policy")]
    Capacity,
}

/// Retains a protected directory and process-pinned capture policy generation.
pub(crate) struct ProtectedCaptureAllocationPolicyV1 {
    directory: OwnedFd,
    expected_uid: u32,
    authority_binding: ObjectDigest,
    pinned: CaptureAllocationV1,
}

/// Holds current, checksum-valid Storage-selected capture allocation limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CaptureAllocationV1 {
    generation: u64,
    digest: ObjectDigest,
    resolver_catalog_digest: ObjectDigest,
    expected_pool_guid: u64,
    metadata_headroom_bytes: u64,
    minimum_remaining_bytes: u64,
    maximum_allocation_bytes: u64,
}

impl ProtectedCaptureAllocationPolicyV1 {
    pub(crate) const fn authority_binding(&self) -> ObjectDigest {
        self.authority_binding
    }

    /// Opens the immutable generation from a root-owned policy directory.
    pub(crate) fn open_root_owned(
        path: &Path,
        authority_binding: ObjectDigest,
    ) -> Result<Self, CaptureAllocationPolicyErrorV1> {
        Self::open_with_owner(path, authority_binding, 0)
    }

    fn open_with_owner(
        path: &Path,
        authority_binding: ObjectDigest,
        expected_uid: u32,
    ) -> Result<Self, CaptureAllocationPolicyErrorV1> {
        if authority_binding.as_bytes() == &[0; 32] {
            return Err(CaptureAllocationPolicyErrorV1::Malformed);
        }
        let directory = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| CaptureAllocationPolicyErrorV1::ProtectedPath)?;
        validate_directory(&directory, expected_uid)?;
        let pinned = read_policy(&directory, expected_uid, authority_binding)?;
        Ok(Self {
            directory,
            expected_uid,
            authority_binding,
            pinned,
        })
    }

    /// Reopens the fixed file and rejects replacement before readback.
    pub(crate) fn load_pinned(
        &self,
    ) -> Result<CaptureAllocationV1, CaptureAllocationPolicyErrorV1> {
        validate_directory(&self.directory, self.expected_uid)?;
        let current = read_policy(&self.directory, self.expected_uid, self.authority_binding)?;
        if current != self.pinned {
            return Err(CaptureAllocationPolicyErrorV1::Changed);
        }
        Ok(current)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        path: &Path,
        authority_binding: ObjectDigest,
        expected_uid: u32,
    ) -> Result<Self, CaptureAllocationPolicyErrorV1> {
        Self::open_with_owner(path, authority_binding, expected_uid)
    }
}

impl CaptureAllocationV1 {
    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }

    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }

    pub(crate) const fn resolver_catalog_digest(self) -> ObjectDigest {
        self.resolver_catalog_digest
    }

    pub(crate) const fn expected_pool_guid(self) -> u64 {
        self.expected_pool_guid
    }

    pub(crate) const fn metadata_headroom_bytes(self) -> u64 {
        self.metadata_headroom_bytes
    }

    pub(crate) const fn minimum_remaining_bytes(self) -> u64 {
        self.minimum_remaining_bytes
    }

    pub(crate) fn allocation_for(
        self,
        admitted_bytes: u64,
    ) -> Result<u64, CaptureAllocationPolicyErrorV1> {
        admitted_bytes
            .checked_add(self.metadata_headroom_bytes)
            .filter(|allocation| *allocation <= self.maximum_allocation_bytes)
            .ok_or(CaptureAllocationPolicyErrorV1::Capacity)
    }
}

fn validate_directory(
    directory: &OwnedFd,
    expected_uid: u32,
) -> Result<(), CaptureAllocationPolicyErrorV1> {
    let metadata = fstat(directory).map_err(|_| CaptureAllocationPolicyErrorV1::ProtectedPath)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != expected_uid
        || !matches!(metadata.st_mode & 0o7777, 0o500 | 0o700)
    {
        return Err(CaptureAllocationPolicyErrorV1::ProtectedPath);
    }
    Ok(())
}

fn read_policy(
    directory: &OwnedFd,
    expected_uid: u32,
    authority_binding: ObjectDigest,
) -> Result<CaptureAllocationV1, CaptureAllocationPolicyErrorV1> {
    let descriptor = openat(
        directory,
        FILE_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| CaptureAllocationPolicyErrorV1::ProtectedPath)?;
    let before = fstat(&descriptor).map_err(|_| CaptureAllocationPolicyErrorV1::ProtectedPath)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != expected_uid
        || before.st_nlink != 1
        || !matches!(before.st_mode & 0o7777, 0o400 | 0o600)
        || before.st_size != BYTES as i64
    {
        return Err(CaptureAllocationPolicyErrorV1::ProtectedPath);
    }

    let mut file = std::fs::File::from(descriptor);
    let mut bytes = [0; BYTES];
    file.read_exact(&mut bytes)
        .map_err(|_| CaptureAllocationPolicyErrorV1::ProtectedPath)?;
    let mut extra = [0; 1];
    if file
        .read(&mut extra)
        .map_err(|_| CaptureAllocationPolicyErrorV1::ProtectedPath)?
        != 0
    {
        return Err(CaptureAllocationPolicyErrorV1::ProtectedPath);
    }
    let after = fstat(&file).map_err(|_| CaptureAllocationPolicyErrorV1::ProtectedPath)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid
        || before.st_gid != after.st_gid
        || before.st_nlink != after.st_nlink
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(CaptureAllocationPolicyErrorV1::ProtectedPath);
    }
    decode(&bytes, authority_binding)
}

fn decode(
    bytes: &[u8; BYTES],
    authority_binding: ObjectDigest,
) -> Result<CaptureAllocationV1, CaptureAllocationPolicyErrorV1> {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(&bytes[..112]);
    let digest = ObjectDigest::from_bytes(hasher.finalize().into());
    let generation = u64::from_be_bytes(field_8(&bytes[8..16]));
    let resolver_catalog_digest = ObjectDigest::from_bytes(field_32(&bytes[48..80]));
    let expected_pool_guid = u64::from_be_bytes(field_8(&bytes[80..88]));
    let metadata_headroom_bytes = u64::from_be_bytes(field_8(&bytes[88..96]));
    let minimum_remaining_bytes = u64::from_be_bytes(field_8(&bytes[96..104]));
    let maximum_allocation_bytes = u64::from_be_bytes(field_8(&bytes[104..112]));
    if &bytes[..8] != MAGIC
        || generation == 0
        || &bytes[16..48] != authority_binding.as_bytes()
        || resolver_catalog_digest.as_bytes() == &[0; 32]
        || expected_pool_guid == 0
        || metadata_headroom_bytes == 0
        || minimum_remaining_bytes == 0
        || maximum_allocation_bytes <= metadata_headroom_bytes
        || digest.as_bytes() != &bytes[112..144]
    {
        return Err(CaptureAllocationPolicyErrorV1::Malformed);
    }
    Ok(CaptureAllocationV1 {
        generation,
        digest,
        resolver_catalog_digest,
        expected_pool_guid,
        metadata_headroom_bytes,
        minimum_remaining_bytes,
        maximum_allocation_bytes,
    })
}

fn field_8(bytes: &[u8]) -> [u8; 8] {
    let mut field = [0; 8];
    field.copy_from_slice(bytes);
    field
}

fn field_32(bytes: &[u8]) -> [u8; 32] {
    let mut field = [0; 32];
    field.copy_from_slice(bytes);
    field
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use rustix::process::geteuid;
    use tempfile::TempDir;

    use super::*;

    fn policy_bytes() -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..16].copy_from_slice(&3_u64.to_be_bytes());
        bytes[16..48].fill(1);
        bytes[48..80].fill(2);
        bytes[80..88].copy_from_slice(&17_u64.to_be_bytes());
        bytes[88..96].copy_from_slice(&20_u64.to_be_bytes());
        bytes[96..104].copy_from_slice(&30_u64.to_be_bytes());
        bytes[104..112].copy_from_slice(&200_u64.to_be_bytes());
        checksum(&mut bytes);
        bytes
    }

    fn checksum(bytes: &mut [u8; BYTES]) {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(&bytes[..112]);
        bytes[112..144].copy_from_slice(&hasher.finalize());
    }

    #[test]
    fn protected_generation_pins_exact_capacity_and_pool_identity() {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join(FILE_NAME);
        fs::write(&path, policy_bytes()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = geteuid().as_raw();
        let protected = ProtectedCaptureAllocationPolicyV1::open_for_test(
            directory.path(),
            ObjectDigest::from_bytes([1; 32]),
            uid,
        )
        .unwrap();
        let policy = protected.load_pinned().unwrap();
        assert_eq!(policy.generation(), 3);
        assert_eq!(policy.resolver_catalog_digest().as_bytes(), &[2; 32]);
        assert_eq!(policy.expected_pool_guid(), 17);
        assert_eq!(policy.allocation_for(100).unwrap(), 120);
        assert!(policy.allocation_for(181).is_err());

        let mut replacement = policy_bytes();
        replacement[8..16].copy_from_slice(&4_u64.to_be_bytes());
        checksum(&mut replacement);
        fs::write(&path, replacement).unwrap();
        assert_eq!(
            protected.load_pinned(),
            Err(CaptureAllocationPolicyErrorV1::Changed)
        );
    }

    #[test]
    fn symlink_and_malformed_policy_fail_closed() {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join(FILE_NAME);
        let mut malformed = policy_bytes();
        malformed[80..88].fill(0);
        checksum(&mut malformed);
        fs::write(&path, malformed).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = geteuid().as_raw();
        assert!(
            ProtectedCaptureAllocationPolicyV1::open_for_test(
                directory.path(),
                ObjectDigest::from_bytes([1; 32]),
                uid,
            )
            .is_err()
        );

        fs::remove_file(&path).unwrap();
        let target = directory.path().join("target");
        fs::write(&target, policy_bytes()).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(
            ProtectedCaptureAllocationPolicyV1::open_for_test(
                directory.path(),
                ObjectDigest::from_bytes([1; 32]),
                uid,
            )
            .err(),
            Some(CaptureAllocationPolicyErrorV1::ProtectedPath)
        );
    }
}
