//! Nonauthorizing signed project authorization source for Source-tree limits.
//!
//! A privileged administrative signer, distinct from the Controller seed
//! signer, may assert seven initial-tree limits against one current protected
//! publisher head. This verifier does not install credentials, retain the
//! packet, spend an epoch, or authorize a Source journal append.
//!
//! ```text
//! AOSPSC02 | version:u16be | reserved:u16be | signer-generation:u64be |
//! project:16 | publisher-generation:u64be | AOSPOLH1 digest:32 |
//! AOSPOLR1 digest:32 | request-id:16 | issuer-epoch:u64be |
//! seven TreeLimitsV1 ceilings:u32be each | Ed25519 signature:64
//!
//! AOSPAK02 | signer-generation:u64be | Ed25519 public key:32 |
//! SHA-256(key-domain || preceding 48 bytes):32
//! ```

use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::hierarchy::model::TreeLimitsV1;
use crate::journal::RecordNamespace;
use crate::role_credential::{
    ROLE_CREDENTIAL_BYTES, decode_role_credential, encode_role_credential,
};

use super::{PublisherPolicyError, PublisherPolicyStore, policy_current_key, policy_revision_key};

const MAGIC: &[u8; 8] = b"AOSPSC02";
const KEY_MAGIC: &[u8; 8] = b"AOSPAK02";
const VERSION: u16 = 2;
const BODY_BYTES: usize = 160;
pub(super) const PACKET_BYTES: usize = BODY_BYTES + 64;
const KEY_BYTES: usize = ROLE_CREDENTIAL_BYTES;
const SIGNING_DOMAIN: &[u8] =
    b"aos.sandbox.publisher-project-authorization-source.v2\0/var/lib/aos/sandboxd/controller.journal\0";
const KEY_DOMAIN: &[u8] = b"aos.sandbox.publisher-project-authorization-verifier.v2\0";
pub(super) const HEAD_DOMAIN: &[u8] =
    b"aos.sandbox.publisher-project-authorization.current-head.v2\0";
pub(super) const REVISION_DOMAIN: &[u8] =
    b"aos.sandbox.publisher-project-authorization.current-revision.v2\0";
pub(super) const PACKET_DOMAIN: &[u8] = b"aos.sandbox.publisher-project-authorization.packet.v2\0";

/// Reports an invalid or stale signed project authorization source.
#[derive(Debug, Error)]
pub enum ProjectAuthorizationSourceErrorV2 {
    /// A source packet, issuer credential, or tree limit is noncanonical.
    #[error("invalid project authorization source")]
    NonCanonical,
    /// The packet does not match the pinned role or current protected head.
    #[error("project authorization source is stale")]
    Stale,
    /// The pinned issuer did not sign these exact source bytes.
    #[error("project authorization source signature is invalid")]
    Signature,
    /// Publisher policy replay cannot establish a current head.
    #[error(transparent)]
    Publisher(#[from] PublisherPolicyError),
}

/// Holds a public-only, independently provisioned project issuer pin.
///
/// Decoding this credential does not install it as a trust root. Its bytes
/// must come from privileged deployment configuration, never the packet.
pub struct PinnedPublisherProjectAuthorizationIssuerV2 {
    generation: u64,
    key: VerifyingKey,
}

impl PinnedPublisherProjectAuthorizationIssuerV2 {
    /// Decodes the role-specific public verifier credential.
    ///
    /// # Errors
    ///
    /// Rejects a foreign role, malformed key, zero generation, or alteration.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProjectAuthorizationSourceErrorV2> {
        let (generation, key) = decode_role_credential(bytes, KEY_MAGIC, KEY_DOMAIN)
            .ok_or(ProjectAuthorizationSourceErrorV2::NonCanonical)?;
        Ok(Self { generation, key })
    }

    /// Returns the externally pinned signer generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the role-specific public key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

/// Encodes a public-only project issuer credential for offline provisioning.
///
/// This does not install an issuer or permit Source-tree creation.
///
/// # Errors
///
/// Rejects generation zero.
pub fn encode_project_authorization_issuer_credential_v2(
    generation: u64,
    key: &VerifyingKey,
) -> Result<[u8; KEY_BYTES], ProjectAuthorizationSourceErrorV2> {
    encode_role_credential(generation, key, KEY_MAGIC, KEY_DOMAIN)
        .ok_or(ProjectAuthorizationSourceErrorV2::NonCanonical)
}

/// Selects a trusted project, request, and previously spent issuer epoch.
///
/// The future issuer must derive these values from protected administrative
/// custody. An arbitrary caller-created expectation grants no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectAuthorizationSourceExpectedV2 {
    project: ProjectId,
    request_id: [u8; 16],
    last_epoch: u64,
}

impl ProjectAuthorizationSourceExpectedV2 {
    /// Constructs a nonauthorizing expected request and replay floor.
    ///
    /// # Errors
    ///
    /// Rejects sentinel project or request identities.
    pub fn new(
        project: ProjectId,
        request_id: [u8; 16],
        last_epoch: u64,
    ) -> Result<Self, ProjectAuthorizationSourceErrorV2> {
        if project.as_bytes() == &[0; 16] || request_id == [0; 16] {
            return Err(ProjectAuthorizationSourceErrorV2::NonCanonical);
        }
        Ok(Self {
            project,
            request_id,
            last_epoch,
        })
    }
}

/// Carries signature-checked limits and protected-head comparisons only.
///
/// It is not a project authorization record, durable epoch, or Source append
/// capability. A future issuer must retain the protected Controller writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPublisherProjectAuthorizationSourceV2 {
    project: ProjectId,
    limits: TreeLimitsV1,
    issuer_generation: u64,
    publisher_generation: u64,
    publisher_head_digest: ObjectDigest,
    publisher_revision_digest: ObjectDigest,
    request_id: [u8; 16],
    epoch: u64,
    packet_digest: ObjectDigest,
}

impl VerifiedPublisherProjectAuthorizationSourceV2 {
    /// Returns the signed project identity.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the seven explicit administrative ceilings.
    #[must_use]
    pub const fn limits(self) -> TreeLimitsV1 {
        self.limits
    }

    /// Returns the independently pinned administrative issuer generation.
    #[must_use]
    pub const fn issuer_generation(self) -> u64 {
        self.issuer_generation
    }

    /// Returns the matched protected publisher generation.
    #[must_use]
    pub const fn publisher_generation(self) -> u64 {
        self.publisher_generation
    }

    /// Returns the signed digest of the exact protected AOSPOLH1 pointer.
    #[must_use]
    pub const fn publisher_head_digest(self) -> ObjectDigest {
        self.publisher_head_digest
    }

    /// Returns the signed digest of the selected protected AOSPOLR1 revision.
    #[must_use]
    pub const fn publisher_revision_digest(self) -> ObjectDigest {
        self.publisher_revision_digest
    }

    /// Returns the signed original request identity.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the signed but not durably spent issuer epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the domain-separated digest of the exact signed packet.
    #[must_use]
    pub const fn packet_digest(self) -> ObjectDigest {
        self.packet_digest
    }
}

/// Parses packet claims without treating them as authenticated authority.
pub(super) struct UnverifiedProjectAuthorizationClaimsV2 {
    pub(super) project: ProjectId,
    pub(super) limits: TreeLimitsV1,
    pub(super) issuer_generation: u64,
    pub(super) publisher_generation: u64,
    pub(super) publisher_head_digest: ObjectDigest,
    pub(super) publisher_revision_digest: ObjectDigest,
    pub(super) request_id: [u8; 16],
    pub(super) epoch: u64,
}

pub(super) fn parse_unverified_project_authorization_claims_v2(
    bytes: &[u8],
) -> Result<UnverifiedProjectAuthorizationClaimsV2, ProjectAuthorizationSourceErrorV2> {
    if bytes.len() != PACKET_BYTES {
        return Err(ProjectAuthorizationSourceErrorV2::NonCanonical);
    }
    let body = &bytes[..BODY_BYTES];
    if body[..8] != MAGIC[..]
        || take::<2>(body, 8)? != VERSION.to_be_bytes()
        || take::<2>(body, 10)? != [0; 2]
    {
        return Err(ProjectAuthorizationSourceErrorV2::NonCanonical);
    }
    let limits = TreeLimitsV1::new(
        read_limit(body, 132)?,
        read_limit(body, 136)?,
        read_limit(body, 140)?,
        read_limit(body, 144)?,
        read_limit(body, 148)?,
        read_limit(body, 152)?,
        read_limit(body, 156)?,
    )
    .map_err(|_| ProjectAuthorizationSourceErrorV2::NonCanonical)?;
    let claims = UnverifiedProjectAuthorizationClaimsV2 {
        project: ProjectId::from_bytes(take::<16>(body, 20)?),
        limits,
        issuer_generation: u64::from_be_bytes(take::<8>(body, 12)?),
        publisher_generation: u64::from_be_bytes(take::<8>(body, 36)?),
        publisher_head_digest: ObjectDigest::from_bytes(take::<32>(body, 44)?),
        publisher_revision_digest: ObjectDigest::from_bytes(take::<32>(body, 76)?),
        request_id: take::<16>(body, 108)?,
        epoch: u64::from_be_bytes(take::<8>(body, 124)?),
    };
    if claims.project.as_bytes() == &[0; 16]
        || claims.request_id == [0; 16]
        || claims.issuer_generation == 0
        || claims.publisher_generation == 0
        || claims.publisher_head_digest.as_bytes() == &[0; 32]
        || claims.publisher_revision_digest.as_bytes() == &[0; 32]
        || claims.epoch == 0
    {
        return Err(ProjectAuthorizationSourceErrorV2::NonCanonical);
    }
    Ok(claims)
}

/// Verifies a V2 source against its pin and actual protected publisher head.
///
/// The packet binds both the `AOSPOLH1` current pointer and the selected
/// `AOSPOLR1` revision, so a validly encoded replacement with the same
/// portable descriptor cannot silently reuse this statement. The caller must
/// still protect the expected request and epoch floor, retain the Controller
/// writer through issuance, and persist an authorization head before Source
/// may append a tree. Legacy `AOSPSC01` packets are never accepted.
///
/// # Errors
///
/// Rejects malformed framing or limits, a missing or rotated signer, changed
/// publisher heads, request/epoch replay, or invalid signature.
pub fn verify_current_project_authorization_source_v2(
    store: &PublisherPolicyStore<'_>,
    bytes: &[u8],
    issuer: &PinnedPublisherProjectAuthorizationIssuerV2,
    expected: ProjectAuthorizationSourceExpectedV2,
) -> Result<VerifiedPublisherProjectAuthorizationSourceV2, ProjectAuthorizationSourceErrorV2> {
    let claims = parse_unverified_project_authorization_claims_v2(bytes)?;
    let body = &bytes[..BODY_BYTES];
    if claims.issuer_generation != issuer.generation {
        return Err(ProjectAuthorizationSourceErrorV2::Stale);
    }
    let signature = Signature::from_bytes(&take::<64>(bytes, BODY_BYTES)?);
    issuer
        .key
        .verify_strict(&signing_preimage(body), &signature)
        .map_err(|_| ProjectAuthorizationSourceErrorV2::Signature)?;

    if claims.project != expected.project
        || claims.request_id != expected.request_id
        || claims.epoch <= expected.last_epoch
    {
        return Err(ProjectAuthorizationSourceErrorV2::Stale);
    }

    let current = store
        .current_policy(claims.project)?
        .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
    let head = store
        .journal
        .get(
            RecordNamespace::PublisherPolicy,
            &policy_current_key(claims.project),
        )
        .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
    let revision = store
        .journal
        .get(
            RecordNamespace::PublisherPolicy,
            &policy_revision_key(claims.project, current.generation()),
        )
        .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
    if current.generation() != claims.publisher_generation
        || commitment(HEAD_DOMAIN, head) != claims.publisher_head_digest
        || commitment(REVISION_DOMAIN, revision) != claims.publisher_revision_digest
    {
        return Err(ProjectAuthorizationSourceErrorV2::Stale);
    }
    Ok(VerifiedPublisherProjectAuthorizationSourceV2 {
        project: claims.project,
        limits: claims.limits,
        issuer_generation: claims.issuer_generation,
        publisher_generation: claims.publisher_generation,
        publisher_head_digest: claims.publisher_head_digest,
        publisher_revision_digest: claims.publisher_revision_digest,
        request_id: claims.request_id,
        epoch: claims.epoch,
        packet_digest: commitment(PACKET_DOMAIN, bytes),
    })
}

pub(super) fn commitment(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(domain)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn read_limit(bytes: &[u8], offset: usize) -> Result<usize, ProjectAuthorizationSourceErrorV2> {
    usize::try_from(u32::from_be_bytes(take::<4>(bytes, offset)?))
        .map_err(|_| ProjectAuthorizationSourceErrorV2::NonCanonical)
}

fn signing_preimage(body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + body.len());
    bytes.extend_from_slice(SIGNING_DOMAIN);
    bytes.extend_from_slice(body);
    bytes
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ProjectAuthorizationSourceErrorV2> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ProjectAuthorizationSourceErrorV2::NonCanonical)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::PathBuf;

    use aos_sandbox_core::format::encode_policy;
    use aos_sandbox_core::model::{
        CacheDomain, CacheDomainKind, Policy, ResourceProfile, RevocationMode, RevocationPolicy,
    };
    use aos_sandbox_core::{CacheDomainId, DecodeLimits};
    use ed25519_dalek::{Signer as _, SigningKey};

    use crate::{Journal, JournalLimits, JournalRecord, JournalTransaction};

    use super::*;
    use crate::publisher_policy::{PreparedPublisherPolicyRevisionV1, PublisherPolicyLimits};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-project-authorization-v2-{}-{}",
                std::process::id(),
                ProjectId::new()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn open(&self) -> Journal {
            let uid = fs::metadata(&self.0).unwrap().uid();
            Journal::open_protected_at_uid(
                &self.0,
                "controller.journal",
                JournalLimits::default(),
                uid,
            )
            .unwrap()
            .0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn policy(
        project: ProjectId,
        generation: u64,
        not_before: i64,
    ) -> PreparedPublisherPolicyRevisionV1 {
        let policy = Policy::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ResourceProfile::new(Vec::new()).unwrap(),
            Vec::new(),
            CacheDomain::new(
                CacheDomainKind::Project,
                CacheDomainId::from_bytes(*project.as_bytes()),
            ),
            RevocationPolicy::new(RevocationMode::DenyNew, 0),
            None,
            Vec::new(),
        )
        .unwrap();
        PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            project,
            generation,
            not_before,
            1_000,
            &encode_policy(&policy),
            DecodeLimits::default(),
        )
        .unwrap()
    }

    fn packet(
        store: &PublisherPolicyStore<'_>,
        project: ProjectId,
        key: &SigningKey,
        signer_generation: u64,
        request_id: [u8; 16],
        epoch: u64,
    ) -> [u8; PACKET_BYTES] {
        let current = store.current_policy(project).unwrap().unwrap();
        let head = store
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &policy_current_key(project),
            )
            .unwrap();
        let revision = store
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &policy_revision_key(project, current.generation()),
            )
            .unwrap();
        let mut bytes = [0; PACKET_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[12..20].copy_from_slice(&signer_generation.to_be_bytes());
        bytes[20..36].copy_from_slice(project.as_bytes());
        bytes[36..44].copy_from_slice(&current.generation().to_be_bytes());
        bytes[44..76].copy_from_slice(commitment(HEAD_DOMAIN, head).as_bytes());
        bytes[76..108].copy_from_slice(commitment(REVISION_DOMAIN, revision).as_bytes());
        bytes[108..124].copy_from_slice(&request_id);
        bytes[124..132].copy_from_slice(&epoch.to_be_bytes());
        for (index, limit) in [1_u32, 8, 7, 6, 5, 4, 3].into_iter().enumerate() {
            let offset = 132 + index * 4;
            bytes[offset..offset + 4].copy_from_slice(&limit.to_be_bytes());
        }
        resign(&mut bytes, key);
        bytes
    }

    fn resign(bytes: &mut [u8; PACKET_BYTES], key: &SigningKey) {
        let signature = key.sign(&signing_preimage(&bytes[..BODY_BYTES]));
        bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    }

    fn pin(key: &SigningKey, generation: u64) -> PinnedPublisherProjectAuthorizationIssuerV2 {
        let credential =
            encode_project_authorization_issuer_credential_v2(generation, &key.verifying_key())
                .unwrap();
        PinnedPublisherProjectAuthorizationIssuerV2::decode(&credential).unwrap()
    }

    #[test]
    fn signed_limits_join_exact_protected_publisher_head_and_cold_replay() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let key = SigningKey::from_bytes(&[2; 32]);
        let mut journal = directory.open();
        let mut store =
            PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).unwrap();
        store
            .publish_policy_from_trusted_controller([3; 16], None, &policy(project, 1, 100))
            .unwrap();
        let packet = packet(&store, project, &key, 7, [4; 16], 9);
        let expected = ProjectAuthorizationSourceExpectedV2::new(project, [4; 16], 8).unwrap();
        let verified = verify_current_project_authorization_source_v2(
            &store,
            &packet,
            &pin(&key, 7),
            expected,
        )
        .unwrap();
        assert_eq!(verified.project(), project);
        assert_eq!(
            verified.limits(),
            TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).unwrap()
        );
        assert_eq!(verified.publisher_generation(), 1);
        assert_eq!(verified.request_id(), [4; 16]);
        assert_eq!(verified.epoch(), 9);
        assert_eq!(verified.packet_digest(), commitment(PACKET_DOMAIN, &packet));
        drop(store);
        drop(journal);

        let mut reopened = directory.open();
        let store =
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).unwrap();
        assert!(
            verify_current_project_authorization_source_v2(
                &store,
                &packet,
                &pin(&key, 7),
                expected
            )
            .is_ok()
        );
        let spent = ProjectAuthorizationSourceExpectedV2::new(project, [4; 16], 9).unwrap();
        assert!(matches!(
            verify_current_project_authorization_source_v2(&store, &packet, &pin(&key, 7), spent),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
    }

    #[test]
    fn role_rotation_tampering_and_signed_invalid_limits_fail_closed() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let key = SigningKey::from_bytes(&[2; 32]);
        let mut journal = directory.open();
        let mut store =
            PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).unwrap();
        store
            .publish_policy_from_trusted_controller([3; 16], None, &policy(project, 1, 100))
            .unwrap();
        let packet = packet(&store, project, &key, 7, [4; 16], 9);
        let expected = ProjectAuthorizationSourceExpectedV2::new(project, [4; 16], 8).unwrap();

        for offset in [
            12, 20, 36, 44, 76, 108, 124, 132, 136, 140, 144, 148, 152, 156, 160,
        ] {
            let mut altered = packet;
            altered[offset] ^= 1;
            assert!(
                verify_current_project_authorization_source_v2(
                    &store,
                    &altered,
                    &pin(&key, 7),
                    expected
                )
                .is_err()
            );
        }
        for offset in [0, 8, 10] {
            let mut altered = packet;
            altered[offset] ^= 1;
            assert!(matches!(
                verify_current_project_authorization_source_v2(
                    &store,
                    &altered,
                    &pin(&key, 7),
                    expected
                ),
                Err(ProjectAuthorizationSourceErrorV2::NonCanonical)
            ));
        }
        let mut invalid_limits = packet;
        invalid_limits[136..140].copy_from_slice(&65_537_u32.to_be_bytes());
        resign(&mut invalid_limits, &key);
        assert!(matches!(
            verify_current_project_authorization_source_v2(
                &store,
                &invalid_limits,
                &pin(&key, 7),
                expected
            ),
            Err(ProjectAuthorizationSourceErrorV2::NonCanonical)
        ));
        assert!(
            verify_current_project_authorization_source_v2(
                &store,
                &packet[..packet.len() - 1],
                &pin(&key, 7),
                expected
            )
            .is_err()
        );
        assert!(
            verify_current_project_authorization_source_v2(
                &store,
                &[0; 272],
                &pin(&key, 7),
                expected
            )
            .is_err()
        );
        assert!(
            verify_current_project_authorization_source_v2(
                &store,
                &packet,
                &pin(&key, 8),
                expected
            )
            .is_err()
        );
        assert!(
            verify_current_project_authorization_source_v2(
                &store,
                &packet,
                &pin(&SigningKey::from_bytes(&[5; 32]), 7),
                expected
            )
            .is_err()
        );

        let mut credential =
            encode_project_authorization_issuer_credential_v2(7, &key.verifying_key()).unwrap();
        credential[79] ^= 1;
        assert!(PinnedPublisherProjectAuthorizationIssuerV2::decode(&credential).is_err());
    }

    #[test]
    fn stale_request_epoch_head_and_revision_are_rejected() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let key = SigningKey::from_bytes(&[2; 32]);
        let mut journal = directory.open();
        let mut store =
            PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).unwrap();
        store
            .publish_policy_from_trusted_controller([3; 16], None, &policy(project, 1, 100))
            .unwrap();
        let stale_packet = packet(&store, project, &key, 7, [4; 16], 9);
        for expected in [
            ProjectAuthorizationSourceExpectedV2::new(project, [5; 16], 8).unwrap(),
            ProjectAuthorizationSourceExpectedV2::new(project, [4; 16], 9).unwrap(),
            ProjectAuthorizationSourceExpectedV2::new(ProjectId::from_bytes([6; 16]), [4; 16], 8)
                .unwrap(),
        ] {
            assert!(matches!(
                verify_current_project_authorization_source_v2(
                    &store,
                    &stale_packet,
                    &pin(&key, 7),
                    expected
                ),
                Err(ProjectAuthorizationSourceErrorV2::Stale)
            ));
        }

        store
            .publish_policy_from_trusted_controller([7; 16], Some(1), &policy(project, 2, 100))
            .unwrap();
        let expected = ProjectAuthorizationSourceExpectedV2::new(project, [4; 16], 8).unwrap();
        assert!(matches!(
            verify_current_project_authorization_source_v2(
                &store,
                &stale_packet,
                &pin(&key, 7),
                expected
            ),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
        drop(store);

        let previous = policy(project, 1, 101);
        let transaction = JournalTransaction::new(
            [8; 16],
            vec![JournalRecord::put(
                RecordNamespace::PublisherPolicy,
                policy_revision_key(project, 1),
                super::super::encode_policy_revision(&previous).unwrap(),
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();
        let store =
            PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).unwrap();
        let packet_for_current = packet(&store, project, &key, 7, [4; 16], 10);
        drop(store);

        let changed = policy(project, 2, 101);
        let transaction = JournalTransaction::new(
            [9; 16],
            vec![JournalRecord::put(
                RecordNamespace::PublisherPolicy,
                policy_revision_key(project, 2),
                super::super::encode_policy_revision(&changed).unwrap(),
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();
        let store =
            PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).unwrap();
        assert!(matches!(
            verify_current_project_authorization_source_v2(
                &store,
                &packet_for_current,
                &pin(&key, 7),
                ProjectAuthorizationSourceExpectedV2::new(project, [4; 16], 9).unwrap()
            ),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
    }
}
