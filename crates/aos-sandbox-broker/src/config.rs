//! Protected node-local broker-authority configuration.
//!
//! The loader opens a real root-owned directory without following a final
//! symlink, then opens every fixed-name child relative to that descriptor. Each
//! child must be a singly-linked, root-owned, non-executable regular file with
//! no group or other permissions. Reads are bounded and use the already-checked
//! descriptors, so path replacement cannot substitute a different inode after
//! validation.
//!
//! The directory contains these files:
//!
//! ```text
//! broker-plan-policy.cbor          canonical TrustPolicy (<= 64 KiB)
//! broker-plan-public-key           raw Ed25519 public key (32 bytes)
//! broker-revocation-scope          raw nonzero RevocationScopeId (16 bytes)
//! ownership-lease-policy.cbor      canonical TrustPolicy (<= 64 KiB)
//! ownership-lease-public-key       raw Ed25519 public key (32 bytes)
//! node-id                          raw nonzero NodeId (16 bytes)
//! journal-mac-key                  key ID (16 bytes) || secret (32 bytes)
//! ```
//!
//! A policy may carry multiple rotation generations. The configured public
//! key must identify exactly one policy entry by its SHA-256 fingerprint;
//! ambiguous reuse of one physical key across policy generations fails closed.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use aos_sandbox_core::format::decode_trust_policy;
use aos_sandbox_core::model::{KeyReference, KeyUsage, SignaturePurpose};
use aos_sandbox_core::{
    BrokerPlanTrustAnchor, DecodeLimits, MediaType, NodeId, ObjectDigest,
    OwnershipLeaseTrustAnchor, PortableMediaType, RevocationScopeId, descriptor_for_bytes,
};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{BrokerAuthority, BrokerDomain};

const MAXIMUM_POLICY_BYTES: usize = 64 * 1024;
const PLAN_POLICY_FILE: &str = "broker-plan-policy.cbor";
const PLAN_PUBLIC_KEY_FILE: &str = "broker-plan-public-key";
const PLAN_REVOCATION_SCOPE_FILE: &str = "broker-revocation-scope";
const LEASE_POLICY_FILE: &str = "ownership-lease-policy.cbor";
const LEASE_PUBLIC_KEY_FILE: &str = "ownership-lease-public-key";
const NODE_ID_FILE: &str = "node-id";
const JOURNAL_MAC_KEY_FILE: &str = "journal-mac-key";

/// Reports rejection of protected broker-authority configuration.
#[derive(Debug, thiserror::Error)]
pub enum BrokerAuthorityConfigError {
    /// A protected filesystem operation failed.
    #[error("cannot read protected broker-authority {object}: {source}")]
    Filesystem {
        /// Stable public name for the object being read.
        object: &'static str,
        /// Underlying operating-system error.
        source: std::io::Error,
    },
    /// A protected object violates its fixed schema or security invariants.
    #[error("protected broker-authority {0} is invalid")]
    Invalid(&'static str),
}

/// Names each non-secret protected credential that a Guardian consumes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedBrokerPublicCredentialRole {
    /// Controller-plan trust policy.
    BrokerPlanPolicy,
    /// Controller-plan Ed25519 public key.
    BrokerPlanPublicKey,
    /// Controller-plan revocation scope.
    BrokerPlanRevocationScope,
    /// Ownership-lease trust policy.
    OwnershipLeasePolicy,
    /// Ownership-authority Ed25519 public key.
    OwnershipLeasePublicKey,
    /// Sole node identity accepted by the broker.
    NodeId,
}

/// Identifies the exact non-secret bytes retained for one public credential.
///
/// This snapshot is released only after the complete six-descriptor set has
/// passed a current metadata and repeated-read comparison against the bytes
/// used to construct the broker authority. It contains no journal MAC key
/// material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedBrokerPublicCredentialSnapshot {
    device: u64,
    inode: u64,
    bytes: usize,
    sha256: [u8; 32],
}

impl ProtectedBrokerPublicCredentialSnapshot {
    /// Returns the device containing the retained credential inode.
    #[must_use]
    pub const fn device(self) -> u64 {
        self.device
    }

    /// Returns the retained credential inode number.
    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }

    /// Returns the exact retained credential length.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.bytes
    }

    /// Returns SHA-256 over the exact retained credential bytes.
    #[must_use]
    pub const fn sha256(self) -> [u8; 32] {
        self.sha256
    }
}

impl ProtectedBrokerPublicCredentialRole {
    /// Lists the complete role set in the Guardian activation order.
    pub const ALL: [Self; 6] = [
        Self::BrokerPlanPolicy,
        Self::BrokerPlanPublicKey,
        Self::BrokerPlanRevocationScope,
        Self::OwnershipLeasePolicy,
        Self::OwnershipLeasePublicKey,
        Self::NodeId,
    ];

    /// Returns the fixed protected-configuration filename for this role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrokerPlanPolicy => PLAN_POLICY_FILE,
            Self::BrokerPlanPublicKey => PLAN_PUBLIC_KEY_FILE,
            Self::BrokerPlanRevocationScope => PLAN_REVOCATION_SCOPE_FILE,
            Self::OwnershipLeasePolicy => LEASE_POLICY_FILE,
            Self::OwnershipLeasePublicKey => LEASE_PUBLIC_KEY_FILE,
            Self::NodeId => NODE_ID_FILE,
        }
    }
}

/// Owns the exact six public descriptors used to construct broker authority.
///
/// The journal MAC key is intentionally absent. Descriptors are exposed only
/// as borrows so callers cannot separate their custody from this complete set.
pub struct ProtectedBrokerPublicCredentials {
    credentials: [ProtectedBrokerPublicCredential; 6],
}

impl ProtectedBrokerPublicCredentials {
    /// Revalidates and borrows the complete descriptor set.
    ///
    /// Validation compares identity, ownership, link count, permissions,
    /// timestamps, length, and an exact repeated-read digest with the snapshot
    /// taken while constructing the authority. A protected file changed in
    /// place or atomically replaced since startup therefore fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAuthorityConfigError`] when any retained descriptor no
    /// longer names the exact protected bytes used to construct the authority.
    pub fn revalidated_descriptors(
        &self,
    ) -> Result<
        [(ProtectedBrokerPublicCredentialRole, BorrowedFd<'_>); 6],
        BrokerAuthorityConfigError,
    > {
        for (role, credential) in ProtectedBrokerPublicCredentialRole::ALL
            .iter()
            .zip(&self.credentials)
        {
            credential.revalidate(*role)?;
        }

        Ok(std::array::from_fn(|index| {
            (
                ProtectedBrokerPublicCredentialRole::ALL[index],
                self.credentials[index].descriptor.as_fd(),
            )
        }))
    }

    /// Revalidates and describes the complete public credential set.
    ///
    /// Every returned snapshot describes the original bytes used to construct
    /// the authority. The method produces no output unless all six retained
    /// descriptors still match those bytes and their protected metadata.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAuthorityConfigError`] when any retained descriptor no
    /// longer names the exact protected bytes used to construct the authority.
    pub fn revalidated_descriptor_evidence(
        &self,
    ) -> Result<
        [(
            ProtectedBrokerPublicCredentialRole,
            BorrowedFd<'_>,
            ProtectedBrokerPublicCredentialSnapshot,
        ); 6],
        BrokerAuthorityConfigError,
    > {
        self.revalidated_descriptor_evidence_with(inspect_protected_descriptor)
    }

    fn revalidated_descriptor_evidence_with(
        &self,
        inspect: impl Copy
        + Fn(
            BorrowedFd<'_>,
            &'static str,
            usize,
        ) -> Result<ProtectedCredentialMetadata, BrokerAuthorityConfigError>,
    ) -> Result<
        [(
            ProtectedBrokerPublicCredentialRole,
            BorrowedFd<'_>,
            ProtectedBrokerPublicCredentialSnapshot,
        ); 6],
        BrokerAuthorityConfigError,
    > {
        for (role, credential) in ProtectedBrokerPublicCredentialRole::ALL
            .iter()
            .zip(&self.credentials)
        {
            credential.revalidate_with(role.as_str(), role.maximum_bytes(), inspect)?;
        }

        Ok(std::array::from_fn(|index| {
            let credential = &self.credentials[index];
            (
                ProtectedBrokerPublicCredentialRole::ALL[index],
                credential.descriptor.as_fd(),
                credential.snapshot.public(),
            )
        }))
    }
}

struct ProtectedBrokerPublicCredential {
    descriptor: OwnedFd,
    snapshot: ProtectedCredentialSnapshot,
}

impl ProtectedBrokerPublicCredential {
    fn revalidate(
        &self,
        role: ProtectedBrokerPublicCredentialRole,
    ) -> Result<(), BrokerAuthorityConfigError> {
        let name = role.as_str();
        let maximum_bytes = role.maximum_bytes();
        self.revalidate_with(name, maximum_bytes, inspect_protected_descriptor)
    }

    fn revalidate_with(
        &self,
        name: &'static str,
        maximum_bytes: usize,
        inspect: impl Fn(
            BorrowedFd<'_>,
            &'static str,
            usize,
        ) -> Result<ProtectedCredentialMetadata, BrokerAuthorityConfigError>,
    ) -> Result<(), BrokerAuthorityConfigError> {
        let before = inspect(self.descriptor.as_fd(), name, maximum_bytes)?;
        let content = read_descriptor_exactly(self.descriptor.as_fd(), name, before.bytes)?;
        let repeated = read_descriptor_exactly(self.descriptor.as_fd(), name, before.bytes)?;
        let after = inspect(self.descriptor.as_fd(), name, maximum_bytes)?;
        let observed = ProtectedCredentialSnapshot {
            metadata: before,
            sha256: Sha256::digest(&content).into(),
        };
        if !retained_snapshot_matches(&self.snapshot, &observed, &after, &content, &repeated) {
            return Err(BrokerAuthorityConfigError::Invalid(name));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProtectedCredentialMetadata {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    links: u64,
    bytes: usize,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProtectedCredentialSnapshot {
    metadata: ProtectedCredentialMetadata,
    sha256: [u8; 32],
}

impl ProtectedCredentialSnapshot {
    const fn public(self) -> ProtectedBrokerPublicCredentialSnapshot {
        ProtectedBrokerPublicCredentialSnapshot {
            device: self.metadata.device,
            inode: self.metadata.inode,
            bytes: self.metadata.bytes,
            sha256: self.sha256,
        }
    }
}

impl ProtectedBrokerPublicCredentialRole {
    const fn maximum_bytes(self) -> usize {
        match self {
            Self::BrokerPlanPolicy | Self::OwnershipLeasePolicy => MAXIMUM_POLICY_BYTES,
            Self::BrokerPlanPublicKey | Self::OwnershipLeasePublicKey => 32,
            Self::BrokerPlanRevocationScope | Self::NodeId => 16,
        }
    }
}

/// Holds one protected authority and the journal key read with it.
///
/// Audience crates that authenticate their own durable records should consume
/// this value once and construct both objects from the same protected read.
/// The loader does not support live in-place rotation: provision the complete
/// directory before startup and restart the broker to rotate it.
pub struct ProtectedBrokerAuthorityConfiguration {
    authority: BrokerAuthority,
    public_credentials: ProtectedBrokerPublicCredentials,
    public_binding: ObjectDigest,
    journal_key_id: [u8; 16],
    journal_secret: Zeroizing<[u8; 32]>,
}

impl ProtectedBrokerAuthorityConfiguration {
    /// Loads one protected fixed-file configuration snapshot.
    ///
    /// Every child is opened relative to the same retained root directory.
    /// This guarantees that the returned authority and journal key use the
    /// same bytes; it does not make concurrent replacement of multiple child
    /// files an atomic rotation protocol.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAuthorityConfigError`] when the directory or any fixed
    /// child is absent, insecure, malformed, oversized, or inconsistent.
    pub fn from_protected_directory(
        path: impl AsRef<Path>,
        domain: BrokerDomain,
    ) -> Result<Self, BrokerAuthorityConfigError> {
        let directory = open(
            path.as_ref(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| filesystem("directory", source))?;
        validate_directory(&directory)?;

        load_from_directory(&directory, domain)
    }

    /// Separates the authority and its exact journal-key bytes.
    ///
    /// The returned secret must be transferred immediately into an
    /// audience-specific zeroizing key owner.
    #[must_use]
    pub fn into_parts(self) -> (BrokerAuthority, [u8; 16], Zeroizing<[u8; 32]>) {
        (self.authority, self.journal_key_id, self.journal_secret)
    }

    /// Separates authority from the exact public descriptors used to build it.
    ///
    /// This path deliberately drops the separately held journal-key bytes.
    /// The returned [`BrokerAuthority`] retains its private MAC key internally,
    /// while the public descriptor set never contains that secret credential.
    #[must_use]
    pub fn into_authority_and_public_credentials(
        self,
    ) -> (BrokerAuthority, ProtectedBrokerPublicCredentials) {
        (self.authority, self.public_credentials)
    }

    /// Returns the non-secret binding of the complete protected authority.
    ///
    /// The binding covers the domain, exact trust policies and selected public
    /// keys, revocation scope, node identity, and journal key identifier. It
    /// deliberately excludes the journal secret.
    #[must_use]
    pub const fn public_binding(&self) -> ObjectDigest {
        self.public_binding
    }
}

impl BrokerAuthority {
    /// Loads authority exclusively from a protected root-owned directory.
    ///
    /// The method never accepts key material, policy bytes, node identity, or
    /// revocation state from a request. Callers should provision the directory
    /// atomically before starting the broker and restart the broker to rotate
    /// an anchor.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAuthorityConfigError`] when the directory or any fixed
    /// child is absent, is not a protected real object, exceeds its exact byte
    /// bound, or does not construct internally consistent trust anchors.
    pub fn from_protected_directory(
        path: impl AsRef<Path>,
        domain: BrokerDomain,
    ) -> Result<Self, BrokerAuthorityConfigError> {
        ProtectedBrokerAuthorityConfiguration::from_protected_directory(path, domain)
            .map(|configuration| configuration.authority)
    }
}

fn load_from_directory(
    directory: &OwnedFd,
    domain: BrokerDomain,
) -> Result<ProtectedBrokerAuthorityConfiguration, BrokerAuthorityConfigError> {
    let (plan_policy, plan_policy_descriptor) =
        read_protected(directory, PLAN_POLICY_FILE, MAXIMUM_POLICY_BYTES)?;
    let (plan_public_key, plan_public_key_descriptor) =
        read_exact::<32>(directory, PLAN_PUBLIC_KEY_FILE)?;
    let (revocation_scope, revocation_scope_descriptor) =
        read_exact::<16>(directory, PLAN_REVOCATION_SCOPE_FILE)?;
    let (lease_policy, lease_policy_descriptor) =
        read_protected(directory, LEASE_POLICY_FILE, MAXIMUM_POLICY_BYTES)?;
    let (lease_public_key, lease_public_key_descriptor) =
        read_exact::<32>(directory, LEASE_PUBLIC_KEY_FILE)?;
    let (node, node_descriptor) = read_exact::<16>(directory, NODE_ID_FILE)?;
    let journal_key = read_secret_exact::<48>(directory, JOURNAL_MAC_KEY_FILE)?;

    let plan_signer = select_policy_key(
        &plan_policy,
        &plan_public_key,
        SignaturePurpose::BrokerAuthorization,
        KeyUsage::BrokerAuthorization,
    )?;
    let lease_authority = select_policy_key(
        &lease_policy,
        &lease_public_key,
        SignaturePurpose::OwnershipLease,
        KeyUsage::OwnershipLease,
    )?;
    let plan_policy_model = decode_trust_policy(&plan_policy, policy_limits())
        .map_err(|_| BrokerAuthorityConfigError::Invalid(PLAN_POLICY_FILE))?;
    let lease_policy_model = decode_trust_policy(&lease_policy, policy_limits())
        .map_err(|_| BrokerAuthorityConfigError::Invalid(LEASE_POLICY_FILE))?;
    let policy_media_type = MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
        .map_err(|_| BrokerAuthorityConfigError::Invalid("trust-policy media type"))?;
    let plan_descriptor = descriptor_for_bytes(policy_media_type.clone(), &plan_policy);
    let lease_descriptor = descriptor_for_bytes(policy_media_type, &lease_policy);
    let mut journal_key_id = [0_u8; 16];
    journal_key_id.copy_from_slice(&journal_key[..16]);
    let mut journal_secret = Zeroizing::new([0_u8; 32]);
    journal_secret.copy_from_slice(&journal_key[16..]);
    let public_binding = protected_configuration_binding(
        domain,
        &plan_policy,
        &plan_public_key,
        &revocation_scope,
        &lease_policy,
        &lease_public_key,
        &node,
        &journal_key_id,
    );

    let plan_anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
        plan_policy,
        plan_descriptor,
        plan_policy_model.trust_scope(),
        plan_signer,
        plan_public_key,
        RevocationScopeId::from_bytes(revocation_scope),
        policy_limits(),
    )
    .map_err(|_| BrokerAuthorityConfigError::Invalid("broker plan trust anchor"))?;
    let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
        lease_policy,
        lease_descriptor,
        lease_policy_model.trust_scope(),
        lease_authority,
        lease_public_key,
        policy_limits(),
    )
    .map_err(|_| BrokerAuthorityConfigError::Invalid("ownership lease trust anchor"))?;
    let authority = BrokerAuthority::new(
        domain,
        plan_anchor,
        lease_anchor,
        NodeId::from_bytes(node),
        journal_key_id,
        *journal_secret,
    )
    .map_err(|_| BrokerAuthorityConfigError::Invalid("broker authority"))?;

    Ok(ProtectedBrokerAuthorityConfiguration {
        authority,
        public_credentials: ProtectedBrokerPublicCredentials {
            credentials: [
                plan_policy_descriptor,
                plan_public_key_descriptor,
                revocation_scope_descriptor,
                lease_policy_descriptor,
                lease_public_key_descriptor,
                node_descriptor,
            ],
        },
        public_binding,
        journal_key_id,
        journal_secret,
    })
}

#[allow(clippy::too_many_arguments)]
fn protected_configuration_binding(
    domain: BrokerDomain,
    plan_policy: &[u8],
    plan_public_key: &[u8; 32],
    revocation_scope: &[u8; 16],
    lease_policy: &[u8],
    lease_public_key: &[u8; 32],
    node: &[u8; 16],
    journal_key_id: &[u8; 16],
) -> ObjectDigest {
    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.broker.protected-configuration.v1\0");
    hash.update([match domain {
        BrokerDomain::Host => 1,
        BrokerDomain::Mount => 2,
        BrokerDomain::Storage => 3,
        BrokerDomain::Network => 4,
    }]);
    hash.update((plan_policy.len() as u64).to_be_bytes());
    hash.update(plan_policy);
    hash.update(plan_public_key);
    hash.update(revocation_scope);
    hash.update((lease_policy.len() as u64).to_be_bytes());
    hash.update(lease_policy);
    hash.update(lease_public_key);
    hash.update(node);
    hash.update(journal_key_id);
    ObjectDigest::from_bytes(hash.finalize().into())
}

fn validate_directory(directory: &OwnedFd) -> Result<(), BrokerAuthorityConfigError> {
    let metadata = fstat(directory).map_err(|source| filesystem("directory", source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != 0
        || !protected_directory_permissions(metadata.st_mode)
    {
        return Err(BrokerAuthorityConfigError::Invalid("directory"));
    }
    Ok(())
}

fn read_exact<const N: usize>(
    directory: &OwnedFd,
    name: &'static str,
) -> Result<([u8; N], ProtectedBrokerPublicCredential), BrokerAuthorityConfigError> {
    let (fd, initial) = open_protected(directory, name, N)?;
    require_exact_length::<N>(initial.bytes, name)?;
    let (bytes, credential) = read_bounded(fd, name, N, initial)?;
    let bytes = Zeroizing::new(bytes);
    let exact = bytes
        .as_slice()
        .try_into()
        .map_err(|_| BrokerAuthorityConfigError::Invalid(name))?;
    Ok((exact, credential))
}

fn read_protected(
    directory: &OwnedFd,
    name: &'static str,
    maximum_bytes: usize,
) -> Result<(Vec<u8>, ProtectedBrokerPublicCredential), BrokerAuthorityConfigError> {
    let (fd, initial) = open_protected(directory, name, maximum_bytes)?;
    read_bounded(fd, name, maximum_bytes, initial)
}

fn read_secret_exact<const N: usize>(
    directory: &OwnedFd,
    name: &'static str,
) -> Result<Zeroizing<[u8; N]>, BrokerAuthorityConfigError> {
    let (fd, initial) = open_protected(directory, name, N)?;
    require_exact_length::<N>(initial.bytes, name)?;
    let bytes = read_descriptor_exactly_zeroizing(fd.as_fd(), name, initial.bytes)?;
    let repeated = read_descriptor_exactly_zeroizing(fd.as_fd(), name, initial.bytes)?;
    let after = inspect_protected_descriptor(fd.as_fd(), name, N)?;
    if bytes != repeated || initial != after {
        return Err(BrokerAuthorityConfigError::Invalid(name));
    }

    let mut exact = Zeroizing::new([0_u8; N]);
    exact.copy_from_slice(&bytes);
    Ok(exact)
}

fn require_exact_length<const N: usize>(
    actual: usize,
    name: &'static str,
) -> Result<(), BrokerAuthorityConfigError> {
    if actual != N {
        return Err(BrokerAuthorityConfigError::Invalid(name));
    }
    Ok(())
}

fn open_protected(
    directory: &OwnedFd,
    name: &'static str,
    maximum_bytes: usize,
) -> Result<(OwnedFd, ProtectedCredentialMetadata), BrokerAuthorityConfigError> {
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| filesystem(name, source))?;
    let metadata = inspect_protected_descriptor(fd.as_fd(), name, maximum_bytes)?;

    Ok((fd, metadata))
}

fn read_bounded(
    fd: OwnedFd,
    name: &'static str,
    maximum_bytes: usize,
    initial: ProtectedCredentialMetadata,
) -> Result<(Vec<u8>, ProtectedBrokerPublicCredential), BrokerAuthorityConfigError> {
    let bytes = read_descriptor_exactly(fd.as_fd(), name, initial.bytes)?;
    let repeated = read_descriptor_exactly(fd.as_fd(), name, initial.bytes)?;
    let after = inspect_protected_descriptor(fd.as_fd(), name, maximum_bytes)?;
    if bytes != repeated || initial != after {
        return Err(BrokerAuthorityConfigError::Invalid(name));
    }
    let snapshot = ProtectedCredentialSnapshot {
        metadata: initial,
        sha256: Sha256::digest(&bytes).into(),
    };
    let observed = ProtectedCredentialSnapshot {
        metadata: after,
        sha256: Sha256::digest(&bytes).into(),
    };
    if !retained_snapshot_matches(&snapshot, &observed, &after, &bytes, &repeated) {
        return Err(BrokerAuthorityConfigError::Invalid(name));
    }
    Ok((
        bytes,
        ProtectedBrokerPublicCredential {
            descriptor: fd,
            snapshot,
        },
    ))
}

fn retained_snapshot_matches(
    expected: &ProtectedCredentialSnapshot,
    observed: &ProtectedCredentialSnapshot,
    after: &ProtectedCredentialMetadata,
    content: &[u8],
    repeated: &[u8],
) -> bool {
    expected == observed && observed.metadata == *after && content == repeated
}

fn inspect_protected_descriptor(
    descriptor: BorrowedFd<'_>,
    name: &'static str,
    maximum_bytes: usize,
) -> Result<ProtectedCredentialMetadata, BrokerAuthorityConfigError> {
    let metadata = fstat(descriptor).map_err(|source| filesystem(name, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != 0
        || metadata.st_nlink != 1
        || !protected_file_permissions(metadata.st_mode)
    {
        return Err(BrokerAuthorityConfigError::Invalid(name));
    }
    let bytes = usize::try_from(metadata.st_size)
        .ok()
        .filter(|bytes| *bytes > 0 && *bytes <= maximum_bytes)
        .ok_or(BrokerAuthorityConfigError::Invalid(name))?;

    Ok(ProtectedCredentialMetadata {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        mode: metadata.st_mode,
        owner: metadata.st_uid,
        links: metadata.st_nlink,
        bytes,
        modified_seconds: metadata.st_mtime,
        modified_nanoseconds: metadata.st_mtime_nsec,
        changed_seconds: metadata.st_ctime,
        changed_nanoseconds: metadata.st_ctime_nsec,
    })
}

fn read_descriptor_exactly(
    descriptor: BorrowedFd<'_>,
    name: &'static str,
    length: usize,
) -> Result<Vec<u8>, BrokerAuthorityConfigError> {
    let mut content = vec![0; length];
    read_descriptor_into(descriptor, name, &mut content)?;
    Ok(content)
}

fn read_descriptor_exactly_zeroizing(
    descriptor: BorrowedFd<'_>,
    name: &'static str,
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, BrokerAuthorityConfigError> {
    let mut content = Zeroizing::new(vec![0; length]);
    read_descriptor_into(descriptor, name, &mut content)?;
    Ok(content)
}

fn read_descriptor_into(
    descriptor: BorrowedFd<'_>,
    name: &'static str,
    content: &mut [u8],
) -> Result<(), BrokerAuthorityConfigError> {
    let file = std::fs::File::from(descriptor.try_clone_to_owned().map_err(|source| {
        BrokerAuthorityConfigError::Filesystem {
            object: name,
            source,
        }
    })?);
    file.read_exact_at(content, 0)
        .map_err(|source| BrokerAuthorityConfigError::Filesystem {
            object: name,
            source,
        })?;
    let mut trailing = Zeroizing::new([0_u8; 1]);
    if file
        .read_at(&mut trailing[..], content.len() as u64)
        .map_err(|source| BrokerAuthorityConfigError::Filesystem {
            object: name,
            source,
        })?
        != 0
    {
        return Err(BrokerAuthorityConfigError::Invalid(name));
    }
    Ok(())
}

fn select_policy_key(
    policy_bytes: &[u8],
    public_key: &[u8; 32],
    purpose: SignaturePurpose,
    usage: KeyUsage,
) -> Result<KeyReference, BrokerAuthorityConfigError> {
    let policy = decode_trust_policy(policy_bytes, policy_limits())
        .map_err(|_| BrokerAuthorityConfigError::Invalid("trust policy"))?;
    if policy.purpose() != purpose {
        return Err(BrokerAuthorityConfigError::Invalid("trust policy purpose"));
    }
    let fingerprint = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
    let mut matches = policy
        .allowed_keys()
        .iter()
        .filter(|key| key.usage() == usage && key.public_key_sha256() == fingerprint);
    let selected = matches
        .next()
        .cloned()
        .ok_or(BrokerAuthorityConfigError::Invalid("configured public key"))?;
    if matches.next().is_some() {
        return Err(BrokerAuthorityConfigError::Invalid(
            "ambiguous configured public key",
        ));
    }
    Ok(selected)
}

const fn protected_directory_permissions(mode: u32) -> bool {
    matches!(mode & 0o7777, 0o500 | 0o700)
}

const fn protected_file_permissions(mode: u32) -> bool {
    matches!(mode & 0o7777, 0o400 | 0o600)
}

const fn policy_limits() -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: MAXIMUM_POLICY_BYTES,
        maximum_collection_items: 2_048,
        maximum_total_items: 65_536,
        maximum_byte_string_bytes: MAXIMUM_POLICY_BYTES,
        maximum_text_bytes: 64 * 1024,
        maximum_depth: 128,
    }
}

fn filesystem(object: &'static str, source: rustix::io::Errno) -> BrokerAuthorityConfigError {
    BrokerAuthorityConfigError::Filesystem {
        object,
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;
    use std::os::fd::AsFd as _;

    use aos_sandbox_core::TrustScopeId;
    use aos_sandbox_core::format::encode_trust_policy;
    use aos_sandbox_core::model::{StableKeyId, TrustPolicy};

    use super::*;

    fn key(name: &str, generation: u64, public_key: &[u8; 32]) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(name.to_owned()).unwrap(),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(public_key).into()),
            KeyUsage::BrokerAuthorization,
        )
    }

    fn policy(keys: Vec<KeyReference>) -> Vec<u8> {
        encode_trust_policy(
            &TrustPolicy::new(
                TrustScopeId::from_bytes([1; 16]),
                SignaturePurpose::BrokerAuthorization,
                keys,
                Vec::new(),
            )
            .unwrap(),
        )
    }

    fn unprotected_snapshot(
        descriptor: BorrowedFd<'_>,
        content: &[u8],
    ) -> ProtectedCredentialSnapshot {
        let metadata = fstat(descriptor).unwrap();
        ProtectedCredentialSnapshot {
            metadata: ProtectedCredentialMetadata {
                device: metadata.st_dev,
                inode: metadata.st_ino,
                mode: metadata.st_mode,
                owner: metadata.st_uid,
                links: metadata.st_nlink,
                bytes: usize::try_from(metadata.st_size).unwrap(),
                modified_seconds: metadata.st_mtime,
                modified_nanoseconds: metadata.st_mtime_nsec,
                changed_seconds: metadata.st_ctime,
                changed_nanoseconds: metadata.st_ctime_nsec,
            },
            sha256: Sha256::digest(content).into(),
        }
    }

    fn inspect_unprotected_descriptor(
        descriptor: BorrowedFd<'_>,
        name: &'static str,
        maximum_bytes: usize,
    ) -> Result<ProtectedCredentialMetadata, BrokerAuthorityConfigError> {
        let metadata = fstat(descriptor).map_err(|source| filesystem(name, source))?;
        let bytes = usize::try_from(metadata.st_size)
            .ok()
            .filter(|bytes| *bytes > 0 && *bytes <= maximum_bytes)
            .ok_or(BrokerAuthorityConfigError::Invalid(name))?;
        let mut snapshot = unprotected_snapshot(descriptor, &[]).metadata;
        snapshot.bytes = bytes;
        Ok(snapshot)
    }

    #[test]
    fn public_key_selects_one_generation_from_rotation_policy() {
        let first_public_key = [1; 32];
        let selected_public_key = [2; 32];
        let selected = key("second", 7, &selected_public_key);
        let bytes = policy(vec![key("first", 6, &first_public_key), selected.clone()]);

        assert_eq!(
            select_policy_key(
                &bytes,
                &selected_public_key,
                SignaturePurpose::BrokerAuthorization,
                KeyUsage::BrokerAuthorization,
            )
            .unwrap(),
            selected
        );
    }

    #[test]
    fn physical_key_reuse_across_generations_is_ambiguous() {
        let public_key = [3; 32];
        let bytes = policy(vec![
            key("first", 6, &public_key),
            key("second", 7, &public_key),
        ]);

        assert!(
            select_policy_key(
                &bytes,
                &public_key,
                SignaturePurpose::BrokerAuthorization,
                KeyUsage::BrokerAuthorization,
            )
            .is_err()
        );
    }

    #[test]
    fn protected_modes_reject_special_and_shared_permissions() {
        assert!(protected_directory_permissions(0o040700));
        assert!(protected_directory_permissions(0o040500));
        assert!(!protected_directory_permissions(0o041700));
        assert!(!protected_directory_permissions(0o042700));
        assert!(!protected_directory_permissions(0o040750));

        assert!(protected_file_permissions(0o100400));
        assert!(protected_file_permissions(0o100600));
        assert!(!protected_file_permissions(0o104400));
        assert!(!protected_file_permissions(0o102600));
        assert!(!protected_file_permissions(0o100640));
        assert!(!protected_file_permissions(0o100700));
    }

    #[test]
    fn public_roles_are_complete_and_exclude_the_journal_key() {
        assert_eq!(
            ProtectedBrokerPublicCredentialRole::ALL.map(|role| role.as_str()),
            [
                PLAN_POLICY_FILE,
                PLAN_PUBLIC_KEY_FILE,
                PLAN_REVOCATION_SCOPE_FILE,
                LEASE_POLICY_FILE,
                LEASE_PUBLIC_KEY_FILE,
                NODE_ID_FILE,
            ]
        );
        assert!(
            ProtectedBrokerPublicCredentialRole::ALL
                .iter()
                .all(|role| role.as_str() != JOURNAL_MAC_KEY_FILE)
        );
    }

    #[test]
    fn exact_length_validation_rejects_short_secret_without_panicking() {
        assert!(require_exact_length::<48>(1, JOURNAL_MAC_KEY_FILE).is_err());
        assert!(require_exact_length::<48>(47, JOURNAL_MAC_KEY_FILE).is_err());
        assert!(require_exact_length::<48>(48, JOURNAL_MAC_KEY_FILE).is_ok());
    }

    #[test]
    fn retained_snapshot_detects_same_length_in_place_rewrite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        fs::write(&path, b"original").unwrap();
        let descriptor: OwnedFd = fs::File::open(&path).unwrap().into();
        let credential = ProtectedBrokerPublicCredential {
            snapshot: unprotected_snapshot(descriptor.as_fd(), b"original"),
            descriptor,
        };
        assert!(
            credential
                .revalidate_with(PLAN_POLICY_FILE, 8, inspect_unprotected_descriptor)
                .is_ok()
        );

        let rewritten = b"mutated!";
        assert_eq!(rewritten.len(), b"original".len());
        fs::write(&path, rewritten).unwrap();

        // An ordinary cargo test substitutes unprivileged metadata inspection
        // for protected-object validation. It still exercises the production
        // retained FD, repeated read, fstat, and original-snapshot comparison.
        assert!(
            credential
                .revalidate_with(PLAN_POLICY_FILE, 8, inspect_unprotected_descriptor)
                .is_err()
        );
    }

    #[test]
    fn retained_snapshot_detects_replacement_and_link_count_drift() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        let replacement = directory.path().join("replacement");
        fs::write(&path, b"original").unwrap();
        let descriptor: OwnedFd = fs::File::open(&path).unwrap().into();
        let credential = ProtectedBrokerPublicCredential {
            snapshot: unprotected_snapshot(descriptor.as_fd(), b"original"),
            descriptor,
        };
        assert!(
            credential
                .revalidate_with(PLAN_POLICY_FILE, 8, inspect_unprotected_descriptor)
                .is_ok()
        );

        fs::write(&replacement, b"replacement").unwrap();
        fs::rename(&replacement, &path).unwrap();
        let observed = unprotected_snapshot(credential.descriptor.as_fd(), b"original");

        assert_eq!(observed.metadata.links, 0);
        assert!(
            credential
                .revalidate_with(PLAN_POLICY_FILE, 8, inspect_unprotected_descriptor)
                .is_err()
        );
    }

    #[test]
    fn snapshot_evidence_is_all_or_nothing_and_matches_authority_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let contents = [
            b"plan-policy".as_slice(),
            b"plan-key".as_slice(),
            b"revocation".as_slice(),
            b"lease-policy".as_slice(),
            b"lease-key".as_slice(),
            b"node-id".as_slice(),
        ];
        let credentials = ProtectedBrokerPublicCredentials {
            credentials: std::array::from_fn(|index| {
                let path = directory.path().join(format!("credential-{index}"));
                fs::write(&path, contents[index]).unwrap();
                let descriptor: OwnedFd = fs::File::open(path).unwrap().into();
                ProtectedBrokerPublicCredential {
                    snapshot: unprotected_snapshot(descriptor.as_fd(), contents[index]),
                    descriptor,
                }
            }),
        };

        let evidence = credentials
            .revalidated_descriptor_evidence_with(inspect_unprotected_descriptor)
            .unwrap();
        for (index, (role, descriptor, snapshot)) in evidence.iter().enumerate() {
            let metadata = fstat(*descriptor).unwrap();
            assert_eq!(*role, ProtectedBrokerPublicCredentialRole::ALL[index]);
            assert_eq!(snapshot.device(), metadata.st_dev);
            assert_eq!(snapshot.inode(), metadata.st_ino);
            assert_eq!(snapshot.bytes(), contents[index].len());
            assert_eq!(
                snapshot.sha256(),
                Sha256::digest(contents[index]).as_slice()
            );
        }

        fs::write(directory.path().join("credential-3"), b"other-policy").unwrap();
        assert!(
            credentials
                .revalidated_descriptor_evidence_with(inspect_unprotected_descriptor)
                .is_err()
        );
    }

    #[test]
    fn public_binding_commits_every_non_secret_authority_input() {
        let plan_policy = b"canonical-plan-policy".as_slice();
        let plan_public_key = [11; 32];
        let revocation_scope = [12; 16];
        let lease_policy = b"canonical-lease-policy".as_slice();
        let lease_public_key = [13; 32];
        let node = [14; 16];
        let journal_key_id = [15; 16];
        let baseline = protected_configuration_binding(
            BrokerDomain::Storage,
            plan_policy,
            &plan_public_key,
            &revocation_scope,
            lease_policy,
            &lease_public_key,
            &node,
            &journal_key_id,
        );

        let changed = [
            protected_configuration_binding(
                BrokerDomain::Network,
                plan_policy,
                &plan_public_key,
                &revocation_scope,
                lease_policy,
                &lease_public_key,
                &node,
                &journal_key_id,
            ),
            protected_configuration_binding(
                BrokerDomain::Storage,
                b"changed-plan-policy",
                &plan_public_key,
                &revocation_scope,
                lease_policy,
                &lease_public_key,
                &node,
                &journal_key_id,
            ),
            protected_configuration_binding(
                BrokerDomain::Storage,
                plan_policy,
                &[21; 32],
                &revocation_scope,
                lease_policy,
                &lease_public_key,
                &node,
                &journal_key_id,
            ),
            protected_configuration_binding(
                BrokerDomain::Storage,
                plan_policy,
                &plan_public_key,
                &[22; 16],
                lease_policy,
                &lease_public_key,
                &node,
                &journal_key_id,
            ),
            protected_configuration_binding(
                BrokerDomain::Storage,
                plan_policy,
                &plan_public_key,
                &revocation_scope,
                b"changed-lease-policy",
                &lease_public_key,
                &node,
                &journal_key_id,
            ),
            protected_configuration_binding(
                BrokerDomain::Storage,
                plan_policy,
                &plan_public_key,
                &revocation_scope,
                lease_policy,
                &[23; 32],
                &node,
                &journal_key_id,
            ),
            protected_configuration_binding(
                BrokerDomain::Storage,
                plan_policy,
                &plan_public_key,
                &revocation_scope,
                lease_policy,
                &lease_public_key,
                &[24; 16],
                &journal_key_id,
            ),
            protected_configuration_binding(
                BrokerDomain::Storage,
                plan_policy,
                &plan_public_key,
                &revocation_scope,
                lease_policy,
                &lease_public_key,
                &node,
                &[25; 16],
            ),
        ];

        assert!(changed.into_iter().all(|binding| binding != baseline));
        assert_eq!(
            protected_configuration_binding(
                BrokerDomain::Storage,
                plan_policy,
                &plan_public_key,
                &revocation_scope,
                lease_policy,
                &lease_public_key,
                &node,
                &journal_key_id,
            ),
            baseline
        );
    }
}
