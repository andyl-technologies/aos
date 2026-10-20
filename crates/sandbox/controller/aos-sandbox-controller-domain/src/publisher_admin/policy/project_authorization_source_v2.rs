//! Joins the fixed issuer and canonical signature DATA to the actual C policy head.
//!
//! Portable encoding and signature verification have one implementation in
//! Protocol. This owner keeps real protected credential rechecks, the actual
//! PublisherPolicyStore borrow, current-head lookup and error projection at
//! their existing frontiers. Signature DATA alone grants no Source mutation.

use aos_sandbox_model::source_tree_model::TreeLimitsV1;
use aos_sandbox_model::{ObjectDigest, ProjectId, ResourceVector};
use aos_sandbox_protocol::source_project_authorization::{
    ProjectAuthorizationSourceDataErrorV2, project_authorization_packet_digest,
};
use aos_sandbox_protocol::publisher_project_authorization::{
    HEAD_DOMAIN, REVISION_DOMAIN, PinnedPublisherProjectAuthorizationIssuerV2,
    ProjectAuthorizationSignatureErrorV2, commitment,
    verify_signed_project_authorization_claims_v2,
};
use aos_sandbox_broker::systemd_credentials::PinnedSystemdCredential;
use thiserror::Error;

#[cfg(test)]
use aos_sandbox_protocol::publisher_project_authorization::encode_project_authorization_issuer_credential_v2;

use crate::journal::RecordNamespace;
use super::{PublisherPolicyError, PublisherPolicyStore, policy_current_key, policy_revision_key};

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

impl From<ProjectAuthorizationSourceDataErrorV2> for ProjectAuthorizationSourceErrorV2 {
    fn from(error: ProjectAuthorizationSourceDataErrorV2) -> Self {
        match error {
            ProjectAuthorizationSourceDataErrorV2::NonCanonical => Self::NonCanonical,
        }
    }
}

impl From<ProjectAuthorizationSignatureErrorV2> for ProjectAuthorizationSourceErrorV2 {
    fn from(error: ProjectAuthorizationSignatureErrorV2) -> Self {
        match error {
            ProjectAuthorizationSignatureErrorV2::NonCanonical => Self::NonCanonical,
            ProjectAuthorizationSignatureErrorV2::Stale => Self::Stale,
            ProjectAuthorizationSignatureErrorV2::Signature => Self::Signature,
        }
    }
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
    resource_envelope: Option<ResourceVector>,
}

impl VerifiedPublisherProjectAuthorizationSourceV2 {
    /// Returns the explicit signed resource envelope, or none for legacy V2.
    ///
    /// This observation is DATA, not paid capacity or a bank admission proof.
    #[must_use]
    pub const fn resource_envelope(self) -> Option<ResourceVector> {
        self.resource_envelope
    }

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

/// Verifies a V2 or V3 source against its pin and protected publisher head.
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
    let claims = verify_signed_project_authorization_claims_v2(bytes, issuer)?;

    if claims.project() != expected.project
        || claims.request_id() != expected.request_id
        || claims.epoch() <= expected.last_epoch
    {
        return Err(ProjectAuthorizationSourceErrorV2::Stale);
    }

    let current = store
        .current_policy(claims.project())?
        .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
    let head = store
        .journal
        .get(
            RecordNamespace::PublisherPolicy,
            &policy_current_key(claims.project()),
        )
        .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
    let revision = store
        .journal
        .get(
            RecordNamespace::PublisherPolicy,
            &policy_revision_key(claims.project(), current.generation()),
        )
        .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
    if current.generation() != claims.publisher_generation()
        || commitment(HEAD_DOMAIN, head) != claims.publisher_head_digest()
        || commitment(REVISION_DOMAIN, revision) != claims.publisher_revision_digest()
    {
        return Err(ProjectAuthorizationSourceErrorV2::Stale);
    }
    Ok(VerifiedPublisherProjectAuthorizationSourceV2 {
        project: claims.project(),
        limits: claims.limits(),
        issuer_generation: claims.issuer_generation(),
        publisher_generation: claims.publisher_generation(),
        publisher_head_digest: claims.publisher_head_digest(),
        publisher_revision_digest: claims.publisher_revision_digest(),
        request_id: claims.request_id(),
        epoch: claims.epoch(),
        packet_digest: project_authorization_packet_digest(bytes)?,
        resource_envelope: claims.resource_envelope(),
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use aos_sandbox_protocol::source_project_authorization::parse_unverified_project_authorization_claims_v2;

    use crate::{JournalRecord, JournalTransaction};

    use super::*;
    use crate::publisher_admin::policy::PublisherPolicyLimits;
    use crate::publisher_admin::policy::project_authorization_test_fixture::{
        TestDirectory, packet, pin, policy, resign,
    };

    #[test]
    fn malformed_data_preserves_existing_role_and_genesis_error_categories() {
        let error = parse_unverified_project_authorization_claims_v2(&[]).unwrap_err();

        assert!(matches!(
            ProjectAuthorizationSourceErrorV2::from(error),
            ProjectAuthorizationSourceErrorV2::NonCanonical,
        ));
        assert!(matches!(
            crate::publisher_admin::policy::PublisherProjectGenesisErrorV1::from(error),
            crate::publisher_admin::policy::PublisherProjectGenesisErrorV1::Authorization(
                ProjectAuthorizationSourceErrorV2::NonCanonical,
            ),
        ));
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
        assert_eq!(
            verified.packet_digest(),
            commitment(b"aos.sandbox.publisher-project-authorization.packet.v2\0", &packet),
        );
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
            aos_sandbox_protocol::controller_source_seed::encode_controller_source_tree_seed_credential_v1(
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
