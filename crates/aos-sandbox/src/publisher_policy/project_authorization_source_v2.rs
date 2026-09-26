//! Nonauthorizing signed project authorization source for Source-tree limits.
//!
//! A privileged administrative signer, distinct from the Controller seed
//! signer, may assert seven initial-tree limits against one current protected
//! publisher head. Packet verification alone does not install credentials,
//! retain the packet, spend an epoch, or authorize a Source journal append.
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
use crate::public_api_session::PinnedSystemdCredential;
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
    /// The fixed privileged issuer credential is missing or has changed.
    #[error("project authorization issuer credential is unavailable")]
    Credential,
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

/// Holds the fixed systemd issuer pin and its protected file identity.
///
/// The Controller obtains this credential by its fixed name. A packet or
/// caller cannot select the trust root used for a retained decision.
pub(super) struct ProtectedProjectAuthorizationIssuerV2 {
    credential: PinnedSystemdCredential,
    pin: PinnedPublisherProjectAuthorizationIssuerV2,
}

impl ProtectedProjectAuthorizationIssuerV2 {
    pub(super) fn from_systemd_credentials() -> Result<Self, ProjectAuthorizationSourceErrorV2> {
        let credential = PinnedSystemdCredential::load_project_authorization_issuer_v2()
            .map_err(|_| ProjectAuthorizationSourceErrorV2::Credential)?;
        let pin = PinnedPublisherProjectAuthorizationIssuerV2::decode(credential.bytes())?;
        credential
            .recheck()
            .map_err(|_| ProjectAuthorizationSourceErrorV2::Credential)?;
        Ok(Self { credential, pin })
    }

    pub(super) fn pin(&self) -> &PinnedPublisherProjectAuthorizationIssuerV2 {
        &self.pin
    }

    pub(super) fn recheck(&self) -> Result<(), ProjectAuthorizationSourceErrorV2> {
        self.credential
            .recheck()
            .map_err(|_| ProjectAuthorizationSourceErrorV2::Credential)
    }
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
    use ed25519_dalek::SigningKey;

    use crate::{JournalRecord, JournalTransaction};

    use super::*;
    use crate::publisher_policy::PublisherPolicyLimits;
    use crate::publisher_policy::project_authorization_test_fixture::{
        TestDirectory, packet, pin, policy, resign,
    };

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
        assert!(PinnedPublisherProjectAuthorizationIssuerV2::decode(&credential[..79]).is_err());
        assert!(
            encode_project_authorization_issuer_credential_v2(0, &key.verifying_key()).is_err()
        );

        let source_seed_credential =
            crate::hierarchy::source_seed::encode_controller_source_tree_seed_credential_v1(
                7,
                &key.verifying_key(),
            )
            .unwrap();
        assert!(
            PinnedPublisherProjectAuthorizationIssuerV2::decode(&source_seed_credential).is_err()
        );
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
