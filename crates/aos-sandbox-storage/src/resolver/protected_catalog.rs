//! Root-owned assignment policy for Storage preparation and held-snapshot readback.
//!
//! The policy publisher atomically replaces one bounded canonical file:
//!
//! ```text
//! AOSSRPC2 | version:u16=2 | reserved:u16 | generation:u64 |
//! authority-binding:32 | entry-count:u32 | catalog-digest:32 | entries...
//!
//! entry = complete-broker-assignment | managed-root | expected-pool-guid:u64 |
//!         storage-domains |
//!         project-ancestor | aggregate-limits | workspace-limits
//! ```
//!
//! The catalog digest excludes its own 32-byte field and covers every other
//! byte under a domain separator. Entries are strictly ordered by the complete
//! canonical assignment, so the caller cannot select policy by sandbox alone.

use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, ObjectDigest, SandboxId,
};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use sha2::{Digest as _, Sha256};

use crate::{ManagedDatasetRoot, ProjectAncestorPolicyV1, ResolvedDataset, StorageDomainsV1};

use super::policy::ProtectedStorageResolverPolicyV1;

const FILE_NAME: &str = "storage-resolver-policy.catalog";
const MAGIC: &[u8; 8] = b"AOSSRPC2";
const VERSION: u16 = 2;
const HEADER_PREFIX_BYTES: usize = 56;
const HEADER_BYTES: usize = 88;
const MAXIMUM_CATALOG_BYTES: usize = 1024 * 1024;
const MAXIMUM_ENTRIES: usize = 256;
const MAXIMUM_NAME_BYTES: usize = 255;
const ASSIGNMENT_BYTES: usize = 80;
const CATALOG_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.resolver-policy-catalog.v2\0";
const ENTRY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.resolver-policy-entry.v2\0";

/// Reports an unavailable, insecure, malformed, or mismatched policy catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum StorageResolverPolicyError {
    /// The protected directory or fixed catalog file could not be trusted.
    #[error("Storage resolver policy publication is unavailable or insecure")]
    ProtectedPath,
    /// Canonical bytes, bounds, ordering, or typed policy validation failed.
    #[error("Storage resolver policy catalog is malformed")]
    Malformed,
    /// The catalog belongs to a different protected Storage authority.
    #[error("Storage resolver policy catalog authority binding does not match")]
    AuthorityMismatch,
    /// No policy exists for the complete assignment or managed root.
    #[error("Storage resolver policy has no exact assignment or managed-root entry")]
    AssignmentUnknown,
}

/// Binds one fresh resolution to the monotone policy catalog and exact entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageResolverPolicyBindingV1 {
    catalog: StorageResolverPolicyCatalogBindingV1,
    entry_digest: ObjectDigest,
}

impl StorageResolverPolicyBindingV1 {
    fn new(
        catalog: StorageResolverPolicyCatalogBindingV1,
        entry_digest: ObjectDigest,
    ) -> Result<Self, StorageResolverPolicyError> {
        if entry_digest.as_bytes() == &[0; 32] {
            return Err(StorageResolverPolicyError::Malformed);
        }

        Ok(Self {
            catalog,
            entry_digest,
        })
    }

    pub(crate) fn from_authenticated_parts(
        generation: u64,
        catalog_digest: ObjectDigest,
        entry_digest: ObjectDigest,
    ) -> Result<Self, StorageResolverPolicyError> {
        let catalog = StorageResolverPolicyCatalogBindingV1::new(generation, catalog_digest)?;
        Self::new(catalog, entry_digest)
    }

    pub(crate) const fn generation(self) -> u64 {
        self.catalog.generation
    }

    pub(crate) const fn catalog_digest(self) -> ObjectDigest {
        self.catalog.digest
    }

    pub(crate) const fn entry_digest(self) -> ObjectDigest {
        self.entry_digest
    }

    pub(crate) const fn catalog_binding(self) -> StorageResolverPolicyCatalogBindingV1 {
        self.catalog
    }
}

/// Identifies one complete trusted resolver-policy publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageResolverPolicyCatalogBindingV1 {
    generation: u64,
    digest: ObjectDigest,
}

impl StorageResolverPolicyCatalogBindingV1 {
    fn new(generation: u64, digest: ObjectDigest) -> Result<Self, StorageResolverPolicyError> {
        if generation == 0 || digest.as_bytes() == &[0; 32] {
            return Err(StorageResolverPolicyError::Malformed);
        }
        Ok(Self { generation, digest })
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }

    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }

    #[cfg(test)]
    #[allow(clippy::expect_used)]
    pub(crate) fn from_parts_for_test(generation: u64, digest: ObjectDigest) -> Self {
        Self::new(generation, digest).expect("test policy binding must be nonzero")
    }
}

/// Retains the protected directory used for atomic policy replacement.
pub(crate) struct ProtectedStorageResolverPolicyDirectoryV1 {
    directory: OwnedFd,
    authority_binding: ObjectDigest,
    expected_uid: u32,
}

impl ProtectedStorageResolverPolicyDirectoryV1 {
    pub(crate) fn open_root_owned(
        path: &Path,
        authority_binding: ObjectDigest,
    ) -> Result<Self, StorageResolverPolicyError> {
        Self::open_with_owner(path, authority_binding, 0)
    }

    fn open_with_owner(
        path: &Path,
        authority_binding: ObjectDigest,
        expected_uid: u32,
    ) -> Result<Self, StorageResolverPolicyError> {
        if authority_binding.as_bytes() == &[0; 32] {
            return Err(StorageResolverPolicyError::AuthorityMismatch);
        }
        let directory = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StorageResolverPolicyError::ProtectedPath)?;
        let metadata = fstat(&directory).map_err(|_| StorageResolverPolicyError::ProtectedPath)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || metadata.st_uid != expected_uid
            || !matches!(metadata.st_mode & 0o7777, 0o500 | 0o700)
        {
            return Err(StorageResolverPolicyError::ProtectedPath);
        }

        Ok(Self {
            directory,
            authority_binding,
            expected_uid,
        })
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        path: &Path,
        authority_binding: ObjectDigest,
        expected_uid: u32,
    ) -> Result<Self, StorageResolverPolicyError> {
        Self::open_with_owner(path, authority_binding, expected_uid)
    }

    /// Reloads and validates the complete current publication from one opened FD.
    pub(crate) fn load(
        &self,
    ) -> Result<LoadedStorageResolverPolicyCatalogV1, StorageResolverPolicyError> {
        let directory_metadata =
            fstat(&self.directory).map_err(|_| StorageResolverPolicyError::ProtectedPath)?;
        if FileType::from_raw_mode(directory_metadata.st_mode) != FileType::Directory
            || directory_metadata.st_uid != self.expected_uid
            || !matches!(directory_metadata.st_mode & 0o7777, 0o500 | 0o700)
        {
            return Err(StorageResolverPolicyError::ProtectedPath);
        }
        let descriptor = openat(
            &self.directory,
            FILE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| StorageResolverPolicyError::ProtectedPath)?;
        let metadata = fstat(&descriptor).map_err(|_| StorageResolverPolicyError::ProtectedPath)?;
        let declared_size = usize::try_from(metadata.st_size)
            .map_err(|_| StorageResolverPolicyError::ProtectedPath)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_uid != self.expected_uid
            || metadata.st_nlink != 1
            || !matches!(metadata.st_mode & 0o7777, 0o400 | 0o600)
            || !(HEADER_BYTES..=MAXIMUM_CATALOG_BYTES).contains(&declared_size)
        {
            return Err(StorageResolverPolicyError::ProtectedPath);
        }

        let mut bytes = Vec::with_capacity(declared_size);
        let mut file = std::fs::File::from(descriptor);
        (&mut file)
            .take((MAXIMUM_CATALOG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| StorageResolverPolicyError::ProtectedPath)?;
        let current = fstat(&file).map_err(|_| StorageResolverPolicyError::ProtectedPath)?;
        if bytes.len() != declared_size
            || current.st_dev != metadata.st_dev
            || current.st_ino != metadata.st_ino
            || current.st_size != metadata.st_size
            || current.st_mode != metadata.st_mode
            || current.st_uid != metadata.st_uid
            || current.st_gid != metadata.st_gid
            || current.st_nlink != metadata.st_nlink
            || current.st_mtime != metadata.st_mtime
            || current.st_mtime_nsec != metadata.st_mtime_nsec
            || current.st_ctime != metadata.st_ctime
            || current.st_ctime_nsec != metadata.st_ctime_nsec
        {
            return Err(StorageResolverPolicyError::ProtectedPath);
        }

        LoadedStorageResolverPolicyCatalogV1::decode(&bytes, self.authority_binding)
    }
}

/// Carries one freshly validated canonical policy snapshot.
pub(crate) struct LoadedStorageResolverPolicyCatalogV1 {
    generation: u64,
    digest: ObjectDigest,
    entries: Vec<LoadedStorageResolverPolicyEntryV1>,
}

impl LoadedStorageResolverPolicyCatalogV1 {
    fn decode(
        bytes: &[u8],
        expected_authority: ObjectDigest,
    ) -> Result<Self, StorageResolverPolicyError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC || decoder.u16()? != VERSION || decoder.u16()? != 0 {
            return Err(StorageResolverPolicyError::Malformed);
        }
        let generation = decoder.u64()?;
        let authority_binding = ObjectDigest::from_bytes(decoder.array()?);
        let entry_count =
            usize::try_from(decoder.u32()?).map_err(|_| StorageResolverPolicyError::Malformed)?;
        let stated_digest = ObjectDigest::from_bytes(decoder.array()?);
        if generation == 0
            || authority_binding.as_bytes() == &[0; 32]
            || stated_digest.as_bytes() == &[0; 32]
            || entry_count > MAXIMUM_ENTRIES
        {
            return Err(StorageResolverPolicyError::Malformed);
        }
        if authority_binding != expected_authority {
            return Err(StorageResolverPolicyError::AuthorityMismatch);
        }

        let mut entries = Vec::with_capacity(entry_count);
        let mut previous_assignment = None;
        for _ in 0..entry_count {
            let start = decoder.offset();
            let assignment_bytes = decoder.take(ASSIGNMENT_BYTES)?;
            if previous_assignment
                .as_ref()
                .is_some_and(|previous: &Vec<u8>| previous.as_slice() >= assignment_bytes)
            {
                return Err(StorageResolverPolicyError::Malformed);
            }
            previous_assignment = Some(assignment_bytes.to_vec());
            let assignment = decode_assignment(assignment_bytes)?;
            let pool = decoder.text()?;
            let dataset_prefix = decoder.text()?;
            let root_guid = decoder.u64()?;
            let expected_pool_guid = decoder.u64()?;
            let domains = decode_domains(&mut decoder)?;
            let ancestor_name = decoder.text()?;
            let ancestor_guid = decoder.u64()?;
            let ancestor_handle = decoder.array()?;
            let project_quota = decoder.u64()?;
            let filesystem_limit = decoder.u64()?;
            let snapshot_limit = decoder.u64()?;
            let maximum_workspace_quota = decoder.u64()?;
            let maximum_workspace_reservation = decoder.u64()?;

            let root = ManagedDatasetRoot::from_catalog(pool, dataset_prefix, root_guid)
                .map_err(|_| StorageResolverPolicyError::Malformed)?;
            let ancestor = ResolvedDataset::from_catalog(
                root.clone(),
                ancestor_name,
                ancestor_guid,
                ancestor_handle,
                domains,
            )
            .map_err(|_| StorageResolverPolicyError::Malformed)?;
            let project_ancestor = ProjectAncestorPolicyV1::new(
                ancestor,
                project_quota,
                filesystem_limit,
                snapshot_limit,
            )
            .map_err(|_| StorageResolverPolicyError::Malformed)?;
            let policy = ProtectedStorageResolverPolicyV1::new(
                assignment,
                root,
                expected_pool_guid,
                domains,
                project_ancestor,
                maximum_workspace_quota,
                maximum_workspace_reservation,
            )
            .map_err(|_| StorageResolverPolicyError::Malformed)?;
            let entry_digest = digest_entry(&bytes[start..decoder.offset()]);
            entries.push(LoadedStorageResolverPolicyEntryV1 {
                assignment_bytes: assignment_bytes.to_vec(),
                entry_digest,
                policy,
            });
        }
        decoder.finish()?;

        let actual_digest = digest_catalog(bytes)?;
        if actual_digest != stated_digest {
            return Err(StorageResolverPolicyError::Malformed);
        }
        StorageResolverPolicyCatalogBindingV1::new(generation, actual_digest)?;

        Ok(Self {
            generation,
            digest: actual_digest,
            entries,
        })
    }

    pub(crate) fn select(
        self,
        assignment: BrokerAssignment,
    ) -> Result<SelectedStorageResolverPolicyV1, StorageResolverPolicyError> {
        let assignment_bytes = encode_assignment(assignment);
        let catalog = self.binding()?;
        let index = self
            .entries
            .binary_search_by(|entry| entry.assignment_bytes.as_slice().cmp(&assignment_bytes))
            .map_err(|_| StorageResolverPolicyError::AssignmentUnknown)?;
        let entry = self
            .entries
            .into_iter()
            .nth(index)
            .ok_or(StorageResolverPolicyError::Malformed)?;
        let binding = StorageResolverPolicyBindingV1::new(catalog, entry.entry_digest)?;

        Ok(SelectedStorageResolverPolicyV1 {
            binding,
            policy: entry.policy,
        })
    }

    /// Resolves one current, protected pool assignment for an exact managed root.
    ///
    /// Multiple assignments may share the root, but conflicting pool GUIDs
    /// make that root ambiguous and cannot constrain a physical readback.
    pub(crate) fn expected_pool_guid_for_root(
        &self,
        root: &ManagedDatasetRoot,
    ) -> Result<u64, StorageResolverPolicyError> {
        let mut expected = None;
        for entry in &self.entries {
            if entry.policy.root() != root {
                continue;
            }
            let guid = entry.policy.expected_pool_guid();
            if expected.is_some_and(|prior| prior != guid) {
                return Err(StorageResolverPolicyError::Malformed);
            }
            expected = Some(guid);
        }
        expected.ok_or(StorageResolverPolicyError::AssignmentUnknown)
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(crate) fn binding(
        &self,
    ) -> Result<StorageResolverPolicyCatalogBindingV1, StorageResolverPolicyError> {
        StorageResolverPolicyCatalogBindingV1::new(self.generation, self.digest)
    }
}

struct LoadedStorageResolverPolicyEntryV1 {
    assignment_bytes: Vec<u8>,
    entry_digest: ObjectDigest,
    policy: ProtectedStorageResolverPolicyV1,
}

/// Couples exact protected policy with its durable catalog provenance.
pub(crate) struct SelectedStorageResolverPolicyV1 {
    binding: StorageResolverPolicyBindingV1,
    policy: ProtectedStorageResolverPolicyV1,
}

impl SelectedStorageResolverPolicyV1 {
    pub(crate) const fn binding(&self) -> StorageResolverPolicyBindingV1 {
        self.binding
    }

    pub(crate) fn into_policy(self) -> ProtectedStorageResolverPolicyV1 {
        self.policy
    }
}

fn decode_assignment(bytes: &[u8]) -> Result<BrokerAssignment, StorageResolverPolicyError> {
    if bytes.len() != ASSIGNMENT_BYTES {
        return Err(StorageResolverPolicyError::Malformed);
    }
    BrokerAssignment::new(
        SandboxId::from_bytes(array_at(bytes, 0)?),
        IncarnationId::from_bytes(array_at(bytes, 16)?),
        AssignmentEpoch::new(u64::from_be_bytes(array_at(bytes, 32)?)),
        DesiredGeneration::new(u64::from_be_bytes(array_at(bytes, 40)?)),
        ObjectDigest::from_bytes(array_at(bytes, 48)?),
    )
    .map_err(|_| StorageResolverPolicyError::Malformed)
}

fn encode_assignment(assignment: BrokerAssignment) -> [u8; ASSIGNMENT_BYTES] {
    let mut bytes = [0; ASSIGNMENT_BYTES];
    bytes[..16].copy_from_slice(assignment.sandbox().as_bytes());
    bytes[16..32].copy_from_slice(assignment.incarnation().as_bytes());
    bytes[32..40].copy_from_slice(&assignment.epoch().get().to_be_bytes());
    bytes[40..48].copy_from_slice(&assignment.desired_generation().get().to_be_bytes());
    bytes[48..].copy_from_slice(assignment.digest().as_bytes());
    bytes
}

fn decode_domains(
    decoder: &mut Decoder<'_>,
) -> Result<StorageDomainsV1, StorageResolverPolicyError> {
    StorageDomainsV1::new(
        ObjectDigest::from_bytes(decoder.array()?),
        ObjectDigest::from_bytes(decoder.array()?),
        ObjectDigest::from_bytes(decoder.array()?),
        ObjectDigest::from_bytes(decoder.array()?),
    )
    .map_err(|_| StorageResolverPolicyError::Malformed)
}

fn digest_catalog(bytes: &[u8]) -> Result<ObjectDigest, StorageResolverPolicyError> {
    if bytes.len() < HEADER_BYTES {
        return Err(StorageResolverPolicyError::Malformed);
    }
    let mut digest = Sha256::new();
    digest.update(CATALOG_DIGEST_DOMAIN);
    digest.update(&bytes[..HEADER_PREFIX_BYTES]);
    digest.update(&bytes[HEADER_BYTES..]);
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

fn digest_entry(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(ENTRY_DIGEST_DOMAIN);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn array_at<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], StorageResolverPolicyError> {
    bytes
        .get(offset..offset + N)
        .ok_or(StorageResolverPolicyError::Malformed)?
        .try_into()
        .map_err(|_| StorageResolverPolicyError::Malformed)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn offset(&self) -> usize {
        self.offset
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StorageResolverPolicyError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StorageResolverPolicyError::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(StorageResolverPolicyError::Malformed)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StorageResolverPolicyError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StorageResolverPolicyError::Malformed)
    }

    fn u16(&mut self) -> Result<u16, StorageResolverPolicyError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, StorageResolverPolicyError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, StorageResolverPolicyError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn text(&mut self) -> Result<&'a str, StorageResolverPolicyError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > MAXIMUM_NAME_BYTES {
            return Err(StorageResolverPolicyError::Malformed);
        }
        std::str::from_utf8(self.take(length)?).map_err(|_| StorageResolverPolicyError::Malformed)
    }

    fn finish(self) -> Result<(), StorageResolverPolicyError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(StorageResolverPolicyError::Malformed)
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) fn encode_catalog_for_test(
    generation: u64,
    authority_binding: ObjectDigest,
    policies: &[ProtectedStorageResolverPolicyV1],
) -> Vec<u8> {
    let mut entries: Vec<_> = policies
        .iter()
        .map(|policy| (encode_assignment(policy.assignment()), policy))
        .collect();
    entries.sort_by_key(|(assignment, _)| *assignment);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(authority_binding.as_bytes());
    bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&[0; 32]);
    for (assignment, policy) in entries {
        bytes.extend_from_slice(&assignment);
        encode_text(&mut bytes, policy.root().pool());
        encode_text(&mut bytes, policy.root().dataset_prefix());
        bytes.extend_from_slice(&policy.root().guid().to_be_bytes());
        bytes.extend_from_slice(&policy.expected_pool_guid().to_be_bytes());
        for digest in [
            policy.domains().disclosure(),
            policy.domains().encryption(),
            policy.domains().accounting(),
            policy.domains().retention(),
        ] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        let ancestor = policy.project_ancestor();
        encode_text(&mut bytes, ancestor.dataset().name());
        bytes.extend_from_slice(&ancestor.dataset().guid().to_be_bytes());
        bytes.extend_from_slice(&ancestor.dataset().storage_handle());
        bytes.extend_from_slice(&ancestor.quota_bytes().to_be_bytes());
        bytes.extend_from_slice(&ancestor.filesystem_limit().to_be_bytes());
        bytes.extend_from_slice(&ancestor.snapshot_limit().to_be_bytes());
        bytes.extend_from_slice(&policy.maximum_workspace_quota_bytes().to_be_bytes());
        bytes.extend_from_slice(&policy.maximum_workspace_reservation_bytes().to_be_bytes());
    }
    let digest = digest_catalog(&bytes).expect("test policy catalog must have a complete header");
    bytes[HEADER_PREFIX_BYTES..HEADER_BYTES].copy_from_slice(digest.as_bytes());
    bytes
}

#[cfg(test)]
fn encode_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use tempfile::TempDir;

    use super::*;

    fn assignment(incarnation: u8, epoch: u64) -> BrokerAssignment {
        BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([incarnation; 16]),
            AssignmentEpoch::new(epoch),
            DesiredGeneration::new(4),
            ObjectDigest::from_bytes([incarnation.wrapping_add(20); 32]),
        )
        .unwrap()
    }

    fn policy(assignment: BrokerAssignment) -> ProtectedStorageResolverPolicyV1 {
        policy_with_pool_guid(assignment, 17)
    }

    fn policy_with_pool_guid(
        assignment: BrokerAssignment,
        pool_guid: u64,
    ) -> ProtectedStorageResolverPolicyV1 {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([31; 32]),
            ObjectDigest::from_bytes([32; 32]),
            ObjectDigest::from_bytes([33; 32]),
            ObjectDigest::from_bytes([34; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 35).unwrap();
        let ancestor =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 36, [37; 32], domains)
                .unwrap();
        ProtectedStorageResolverPolicyV1::new(
            assignment,
            root,
            pool_guid,
            domains,
            ProjectAncestorPolicyV1::new(ancestor, 1 << 30, 64, 128).unwrap(),
            1 << 28,
            1 << 26,
        )
        .unwrap()
    }

    fn authority() -> ObjectDigest {
        ObjectDigest::from_bytes([41; 32])
    }

    fn refresh_digest(bytes: &mut [u8]) {
        let digest = digest_catalog(bytes).unwrap();
        bytes[HEADER_PREFIX_BYTES..HEADER_BYTES].copy_from_slice(digest.as_bytes());
    }

    fn protected_directory() -> (TempDir, std::path::PathBuf, u32) {
        let temporary = TempDir::new().unwrap();
        let directory = temporary.path().join("policy");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&directory).unwrap().uid();
        (temporary, directory, uid)
    }

    fn publish(directory: &Path, bytes: &[u8]) {
        let staging = directory.join("next");
        fs::write(&staging, bytes).unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(staging, directory.join(FILE_NAME)).unwrap();
    }

    #[test]
    fn canonical_catalog_selects_only_the_complete_assignment() {
        let first = assignment(2, 3);
        let second = assignment(3, 4);
        let bytes = encode_catalog_for_test(7, authority(), &[policy(second), policy(first)]);
        let loaded = LoadedStorageResolverPolicyCatalogV1::decode(&bytes, authority()).unwrap();

        assert_eq!(loaded.generation(), 7);
        assert_eq!(loaded.digest(), digest_catalog(&bytes).unwrap());
        let selected = loaded.select(first).unwrap();
        assert_eq!(selected.into_policy().assignment(), first);

        let sibling = assignment(4, 3);
        let loaded = LoadedStorageResolverPolicyCatalogV1::decode(&bytes, authority()).unwrap();
        assert_eq!(
            loaded.select(sibling).err(),
            Some(StorageResolverPolicyError::AssignmentUnknown)
        );
    }

    #[test]
    fn held_snapshot_pool_guid_requires_one_protected_root_assignment() {
        let first = assignment(2, 3);
        let second = assignment(3, 4);
        let root = policy(first).root().clone();
        let bytes = encode_catalog_for_test(
            7,
            authority(),
            &[policy(first), policy_with_pool_guid(second, 17)],
        );
        let loaded = LoadedStorageResolverPolicyCatalogV1::decode(&bytes, authority()).unwrap();
        assert_eq!(loaded.expected_pool_guid_for_root(&root), Ok(17));

        let hostile_root = ManagedDatasetRoot::from_catalog("tank", "tank/other", 35).unwrap();
        assert_eq!(
            loaded.expected_pool_guid_for_root(&hostile_root),
            Err(StorageResolverPolicyError::AssignmentUnknown)
        );

        let conflicting = encode_catalog_for_test(
            7,
            authority(),
            &[policy(first), policy_with_pool_guid(second, 18)],
        );
        let loaded =
            LoadedStorageResolverPolicyCatalogV1::decode(&conflicting, authority()).unwrap();
        assert_eq!(
            loaded.expected_pool_guid_for_root(&root),
            Err(StorageResolverPolicyError::Malformed)
        );
    }

    #[test]
    fn pool_guid_schema_rejects_old_version_and_zero_guid() {
        let mut bytes = encode_catalog_for_test(7, authority(), &[policy(assignment(2, 3))]);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        refresh_digest(&mut bytes);
        assert!(LoadedStorageResolverPolicyCatalogV1::decode(&bytes, authority()).is_err());

        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        let pool_guid_offset =
            HEADER_BYTES + ASSIGNMENT_BYTES + 2 + "tank".len() + 2 + "tank/aos".len() + 8;
        bytes[pool_guid_offset..pool_guid_offset + 8].fill(0);
        refresh_digest(&mut bytes);
        assert!(LoadedStorageResolverPolicyCatalogV1::decode(&bytes, authority()).is_err());
    }

    #[test]
    fn empty_catalog_is_a_canonical_revoke_all_publication() {
        let bytes = encode_catalog_for_test(9, authority(), &[]);
        let loaded = LoadedStorageResolverPolicyCatalogV1::decode(&bytes, authority()).unwrap();

        assert_eq!(loaded.binding().unwrap().generation(), 9);
        assert_eq!(
            loaded.binding().unwrap().digest(),
            digest_catalog(&bytes).unwrap()
        );
        assert_eq!(
            loaded.select(assignment(2, 3)).err(),
            Some(StorageResolverPolicyError::AssignmentUnknown)
        );
    }

    #[test]
    fn digest_canonicality_ordering_and_authority_fail_closed() {
        let original = encode_catalog_for_test(7, authority(), &[policy(assignment(2, 3))]);

        let mut tampered = original.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(LoadedStorageResolverPolicyCatalogV1::decode(&tampered, authority()).is_err());

        let duplicates = encode_catalog_for_test(
            7,
            authority(),
            &[policy(assignment(2, 3)), policy(assignment(2, 3))],
        );
        assert!(LoadedStorageResolverPolicyCatalogV1::decode(&duplicates, authority()).is_err());

        let mut out_of_order = encode_catalog_for_test(
            7,
            authority(),
            &[policy(assignment(2, 3)), policy(assignment(3, 4))],
        );
        let entry_bytes = (out_of_order.len() - HEADER_BYTES) / 2;
        let first = out_of_order[HEADER_BYTES..HEADER_BYTES + entry_bytes].to_vec();
        let second = out_of_order[HEADER_BYTES + entry_bytes..].to_vec();
        out_of_order[HEADER_BYTES..HEADER_BYTES + entry_bytes].copy_from_slice(&second);
        out_of_order[HEADER_BYTES + entry_bytes..].copy_from_slice(&first);
        refresh_digest(&mut out_of_order);
        assert!(LoadedStorageResolverPolicyCatalogV1::decode(&out_of_order, authority()).is_err());

        let mut reserved = original.clone();
        reserved[10] = 1;
        refresh_digest(&mut reserved);
        assert!(LoadedStorageResolverPolicyCatalogV1::decode(&reserved, authority()).is_err());
        assert_eq!(
            LoadedStorageResolverPolicyCatalogV1::decode(
                &original,
                ObjectDigest::from_bytes([42; 32])
            )
            .err(),
            Some(StorageResolverPolicyError::AuthorityMismatch)
        );

        let mut trailing = original;
        trailing.push(0);
        refresh_digest(&mut trailing);
        assert!(LoadedStorageResolverPolicyCatalogV1::decode(&trailing, authority()).is_err());
    }

    #[test]
    fn retained_directory_observes_only_complete_atomic_replacements() {
        let (_temporary, directory, uid) = protected_directory();
        let first = encode_catalog_for_test(7, authority(), &[policy(assignment(2, 3))]);
        publish(&directory, &first);
        let protected = ProtectedStorageResolverPolicyDirectoryV1::open_with_owner(
            &directory,
            authority(),
            uid,
        )
        .unwrap();
        assert_eq!(protected.load().unwrap().generation(), 7);

        let replacement = encode_catalog_for_test(8, authority(), &[]);
        publish(&directory, &replacement);
        let loaded = protected.load().unwrap();
        assert_eq!(loaded.generation(), 8);
        assert_eq!(loaded.digest(), digest_catalog(&replacement).unwrap());
    }

    #[test]
    fn substituted_protected_pool_guid_changes_current_policy_head() {
        let (_temporary, directory, uid) = protected_directory();
        let assignment = assignment(2, 3);
        let root = policy(assignment).root().clone();
        let first = encode_catalog_for_test(7, authority(), &[policy(assignment)]);
        publish(&directory, &first);
        let protected = ProtectedStorageResolverPolicyDirectoryV1::open_with_owner(
            &directory,
            authority(),
            uid,
        )
        .unwrap();
        let original = protected.load().unwrap();
        let original_head = original.binding().unwrap();
        assert_eq!(original.expected_pool_guid_for_root(&root), Ok(17));

        let replacement =
            encode_catalog_for_test(7, authority(), &[policy_with_pool_guid(assignment, 18)]);
        publish(&directory, &replacement);
        let substituted = protected.load().unwrap();
        assert_ne!(substituted.binding().unwrap(), original_head);
        assert_eq!(substituted.expected_pool_guid_for_root(&root), Ok(18));
    }

    #[test]
    fn protected_loader_rechecks_file_directory_and_symlink_policy() {
        let (_temporary, directory, uid) = protected_directory();
        let bytes = encode_catalog_for_test(7, authority(), &[]);
        publish(&directory, &bytes);
        let protected = ProtectedStorageResolverPolicyDirectoryV1::open_with_owner(
            &directory,
            authority(),
            uid,
        )
        .unwrap();

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            protected.load().err(),
            Some(StorageResolverPolicyError::ProtectedPath)
        );
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

        let file = directory.join(FILE_NAME);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            protected.load().err(),
            Some(StorageResolverPolicyError::ProtectedPath)
        );
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();

        let extra_link = directory.join("extra-link");
        fs::hard_link(&file, &extra_link).unwrap();
        assert_eq!(
            protected.load().err(),
            Some(StorageResolverPolicyError::ProtectedPath)
        );
        fs::remove_file(extra_link).unwrap();

        publish(&directory, &vec![0; MAXIMUM_CATALOG_BYTES + 1]);
        assert_eq!(
            protected.load().err(),
            Some(StorageResolverPolicyError::ProtectedPath)
        );

        fs::remove_file(directory.join(FILE_NAME)).unwrap();
        fs::write(directory.join("target"), &bytes).unwrap();
        fs::set_permissions(directory.join("target"), fs::Permissions::from_mode(0o600)).unwrap();
        symlink("target", directory.join(FILE_NAME)).unwrap();
        assert_eq!(
            protected.load().err(),
            Some(StorageResolverPolicyError::ProtectedPath)
        );
    }
}
