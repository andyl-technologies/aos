//! Publisher-domain plan preparation for protected controller signing.
//!
//! This module specializes the authority module's shared canonical-object and
//! detached-signature machinery for publisher plans. A completed artifact
//! proves only that the configured publisher authority signed exact plan bytes;
//! it does not authorize materialization, naming, catalog, or disclosure effects.

use aos_sandbox_core::format::encode_publisher_domain_plan;
use aos_sandbox_core::model::SignaturePurpose;
use aos_sandbox_core::{ObjectDescriptor, PublisherDomainPlan, TrustScopeId};

use super::{
    AuthorizationPreparationError, PreparedArtifact, PreparedSigningRequest, ReturnedSignature,
    SigningAuthority, accept_signature, prepare_artifact,
};

/// Holds one immutable publisher-domain plan while protected signing is pending.
#[derive(Debug)]
pub struct PublisherPlanPreparation {
    plan: PublisherDomainPlan,
    artifact: PreparedArtifact,
}

impl PublisherPlanPreparation {
    /// Canonicalizes and freezes one publisher-domain plan for protected signing.
    ///
    /// This method authenticates no request and grants no publication authority.
    /// The caller must derive `plan` from current controller-owned admission state
    /// before constructing the preparation.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationPreparationError`] when `authority` is not a
    /// publisher-plan authority, its signer generation or trust scope uses a
    /// reserved zero value, or statement construction rejects the plan.
    pub fn new(
        plan: PublisherDomainPlan,
        authority: SigningAuthority,
    ) -> Result<Self, AuthorizationPreparationError> {
        if authority.purpose != SignaturePurpose::PublisherAuthorization {
            return Err(AuthorizationPreparationError::PurposeMismatch);
        }
        if authority.signer.generation() == 0 {
            return Err(AuthorizationPreparationError::SignerMismatch);
        }
        if authority.trust_scope == TrustScopeId::from_bytes([0; 16]) {
            return Err(AuthorizationPreparationError::TrustScopeMismatch);
        }

        let canonical = encode_publisher_domain_plan(&plan);
        let artifact = prepare_artifact(
            canonical,
            aos_sandbox_core::PortableMediaType::PublisherDomainPlan,
            authority,
            plan.fields().issued_seconds,
            plan.fields().expires_seconds,
        )?;
        Ok(Self { plan, artifact })
    }

    /// Returns the exact publisher-plan signing request.
    #[must_use]
    pub fn signing_request(&self) -> PreparedSigningRequest<'_> {
        self.artifact.signing_request()
    }

    /// Returns the frozen canonical publisher-plan bytes.
    #[must_use]
    pub fn canonical_plan(&self) -> &[u8] {
        &self.artifact.canonical_object
    }

    /// Accepts a protected signer response and produces an immutable signed plan.
    ///
    /// Completion verifies the exact prepared statement, canonical envelope,
    /// pinned policy and key, signature, and static validity interval. It does
    /// not re-establish online admission currentness or authorize an effect.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationPreparationError`] when the response is malformed,
    /// noncanonical, substituted, cryptographically invalid, or outside the
    /// plan's static validity interval.
    pub fn complete(
        self,
        signature: ReturnedSignature<'_>,
        now_seconds: i64,
    ) -> Result<SignedPublisherPlan, AuthorizationPreparationError> {
        let canonical_signature = accept_signature(&self.artifact, signature, now_seconds)?;
        Ok(SignedPublisherPlan {
            plan: self.plan,
            descriptor: self.artifact.statement.subject().clone(),
            canonical_plan: self.artifact.canonical_object,
            canonical_signature,
        })
    }
}

/// Owns one verified, byte-exact controller-signed publisher-domain plan.
///
/// This non-cloneable artifact carries static authenticity only. It has no API
/// that converts it into a completion permit or filesystem effect authority.
///
/// ```compile_fail
/// use aos_sandbox::SignedPublisherPlan;
///
/// fn duplicate(plan: &SignedPublisherPlan) -> SignedPublisherPlan {
///     plan.clone()
/// }
/// ```
///
/// ```compile_fail
/// use aos_sandbox::{SignedPublisherPlan};
/// use aos_sandbox_core::{ObjectDescriptor, PublisherDomainPlan};
///
/// fn forge(
///     plan: PublisherDomainPlan,
///     descriptor: ObjectDescriptor,
///     canonical_plan: Vec<u8>,
///     canonical_signature: Vec<u8>,
/// ) -> SignedPublisherPlan {
///     SignedPublisherPlan { plan, descriptor, canonical_plan, canonical_signature }
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct SignedPublisherPlan {
    plan: PublisherDomainPlan,
    descriptor: ObjectDescriptor,
    canonical_plan: Vec<u8>,
    canonical_signature: Vec<u8>,
}

impl SignedPublisherPlan {
    /// Returns the decoded immutable publisher-domain plan.
    #[must_use]
    pub const fn plan(&self) -> &PublisherDomainPlan {
        &self.plan
    }

    /// Returns the full descriptor of the exact canonical plan bytes.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }

    /// Returns the exact canonical publisher-domain plan bytes.
    #[must_use]
    pub fn canonical_plan(&self) -> &[u8] {
        &self.canonical_plan
    }

    /// Returns the exact canonical detached-signature envelope bytes.
    #[must_use]
    pub fn canonical_signature(&self) -> &[u8] {
        &self.canonical_signature
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::ReturnedSignature;
    use aos_sandbox_core::format::{decode_signature, encode_signature, encode_trust_policy};
    use aos_sandbox_core::model::{
        CacheDomain, CacheDomainKind, KeyReference, KeyUsage, Signature, SignatureBytes,
        StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        CacheDomainId, CapabilityId, ChannelBinding, DecodeLimits, MediaType, NodeId, ObjectDigest,
        OperationId, PortableMediaType, PrincipalId, ProjectId, ProtocolVersion,
        PublicationReservationId, PublisherAdmissionClaimV1, PublisherAdmissionRequestDraftV1,
        PublisherAdmissionRequestV1, PublisherAuthorityBindings, PublisherChallengeV1,
        PublisherDomainPlanDraft, PublisherInstanceId, PublisherPlanExpectation,
        PublisherPlanTrustAnchor, PublisherPlanVerificationError, PublisherRequest,
        PublisherRequestCommitment, PublisherTarget, ResourceId, RevocationScopeId,
        descriptor_for_bytes, sign_statement, verify_publisher_domain_plan,
    };

    struct Fixture {
        plan: PublisherDomainPlan,
        authority: SigningAuthority,
        anchor: PublisherPlanTrustAnchor,
        key: SigningKey,
    }

    fn media(kind: PortableMediaType) -> MediaType {
        MediaType::new(kind.as_str().to_owned())
            .unwrap_or_else(|error| panic!("test media type failed: {error}"))
    }

    fn plan() -> PublisherDomainPlan {
        PublisherDomainPlan::new(PublisherDomainPlanDraft {
            protocol_version: ProtocolVersion::new(1, 0),
            target: PublisherTarget {
                principal: PrincipalId::from_bytes([1; 16]),
                instance: PublisherInstanceId::from_bytes([2; 16]),
                node: NodeId::from_bytes([3; 16]),
                project: ProjectId::from_bytes([4; 16]),
                cache_domain: CacheDomain::new(
                    CacheDomainKind::Project,
                    CacheDomainId::from_bytes([5; 16]),
                ),
                isolation_policy: ObjectDigest::from_bytes([6; 32]),
            },
            request: PublisherRequest {
                holder: PrincipalId::from_bytes([7; 16]),
                channel: ChannelBinding::new([8; 32]),
                operation: OperationId::from_bytes([9; 16]),
                reservation: PublicationReservationId::from_bytes([10; 16]),
                content: aos_sandbox_core::ObjectDescriptor::new(
                    media(PortableMediaType::Content),
                    ObjectDigest::from_bytes([11; 32]),
                    4_096,
                ),
                source_authorization: ObjectDigest::from_bytes([12; 32]),
                commitment: PublisherRequestCommitment::from_digest(ObjectDigest::from_bytes(
                    [13; 32],
                ))
                .unwrap_or_else(|error| panic!("test commitment failed: {error}")),
                maximum_bytes: 8_192,
            },
            authority: PublisherAuthorityBindings {
                policy: ObjectDigest::from_bytes([14; 32]),
                policy_generation: 15,
                controller_generation: 16,
                revocation_scope: RevocationScopeId::from_bytes([17; 16]),
                revocation_generation: 18,
                root_registry_generation: 19,
            },
            issued_seconds: 100,
            expires_seconds: 200,
            required_features: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("test publisher plan failed: {error}"))
    }

    fn fixture_with(generation: u64, scope: TrustScopeId) -> Fixture {
        let key = SigningKey::from_bytes(&[21; 32]);
        let signer = KeyReference::new(
            StableKeyId::new("publisher-controller".to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            KeyUsage::PublisherAuthorization,
        );
        let policy = TrustPolicy::new(
            scope,
            SignaturePurpose::PublisherAuthorization,
            vec![signer.clone()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test policy failed: {error}"));
        let policy_bytes = encode_trust_policy(&policy);
        let policy_descriptor =
            descriptor_for_bytes(media(PortableMediaType::TrustPolicy), &policy_bytes);
        let authority = SigningAuthority::new(
            policy_bytes.clone(),
            policy_descriptor.clone(),
            scope,
            signer.clone(),
            key.verifying_key().to_bytes(),
            SignaturePurpose::PublisherAuthorization,
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test authority failed: {error}"));
        let anchor = PublisherPlanTrustAnchor::from_trusted_configuration(
            policy_bytes,
            policy_descriptor,
            scope,
            signer,
            key.verifying_key().to_bytes(),
            RevocationScopeId::from_bytes([17; 16]),
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test anchor failed: {error}"));
        Fixture {
            plan: plan(),
            authority,
            anchor,
            key,
        }
    }

    fn fixture() -> Fixture {
        fixture_with(7, TrustScopeId::from_bytes([22; 16]))
    }

    fn admission_draft(plan: &PublisherDomainPlan) -> PublisherAdmissionRequestDraftV1 {
        let fields = plan.fields();
        PublisherAdmissionRequestDraftV1 {
            capability: CapabilityId::from_bytes([27; 16]),
            cache_resource: ResourceId::from_bytes([28; 16]),
            challenge: PublisherChallengeV1::from_bytes([29; 32])
                .unwrap_or_else(|error| panic!("test challenge failed: {error}")),
            protocol_version: fields.protocol_version,
            target: fields.target.clone(),
            claim: PublisherAdmissionClaimV1 {
                holder: fields.request.holder,
                channel: fields.request.channel,
                operation: fields.request.operation,
                reservation: fields.request.reservation,
                content: fields.request.content.clone(),
                source_authorization: fields.request.source_authorization,
                maximum_bytes: fields.request.maximum_bytes,
            },
            authority: fields.authority.clone(),
            issued_seconds: fields.issued_seconds,
            expires_seconds: fields.expires_seconds,
            required_features: fields.required_features.clone(),
        }
    }

    fn signature(preparation: &PublisherPlanPreparation, key: &SigningKey) -> Signature {
        sign_statement(preparation.signing_request().statement().clone(), key)
            .unwrap_or_else(|error| panic!("test signing failed: {error}"))
    }

    #[test]
    fn raw_and_envelope_completion_are_byte_exact_and_core_verified() {
        let raw_fixture = fixture();
        let raw_preparation =
            PublisherPlanPreparation::new(raw_fixture.plan.clone(), raw_fixture.authority.clone())
                .unwrap_or_else(|error| panic!("test preparation failed: {error}"));
        let raw_signature = signature(&raw_preparation, &raw_fixture.key);
        let expected_envelope = encode_signature(&raw_signature);
        let raw = raw_preparation
            .complete(ReturnedSignature::Bytes(raw_signature.signature()), 150)
            .unwrap_or_else(|error| panic!("raw completion failed: {error}"));

        let envelope_fixture = fixture();
        let envelope_preparation = PublisherPlanPreparation::new(
            envelope_fixture.plan.clone(),
            envelope_fixture.authority,
        )
        .unwrap_or_else(|error| panic!("test preparation failed: {error}"));
        let envelope = envelope_preparation
            .complete(ReturnedSignature::Envelope(&expected_envelope), 150)
            .unwrap_or_else(|error| panic!("envelope completion failed: {error}"));

        assert_eq!(raw, envelope);
        assert_eq!(raw.plan(), &raw_fixture.plan);
        assert_eq!(raw.canonical_plan(), envelope.canonical_plan());
        assert_eq!(raw.canonical_signature(), expected_envelope);
        assert_eq!(
            raw.descriptor().digest().to_string(),
            "sha256:117da571aac212ddd14ce6331d6d0330052164024219703412f1d913f753d4c6"
        );
        assert_eq!(raw.descriptor().encoded_size(), 424);
        assert_eq!(
            raw_signature.signature().as_bytes(),
            &[
                0x47, 0xdb, 0xed, 0x9d, 0x40, 0xd0, 0x0d, 0xc6, 0xe5, 0xfd, 0x16, 0x21, 0x71, 0xf4,
                0xd4, 0xa9, 0x61, 0x5d, 0x06, 0x21, 0x05, 0xf4, 0xe2, 0x85, 0xdb, 0x31, 0x78, 0xe6,
                0xce, 0x2d, 0xbe, 0xed, 0x5f, 0x3b, 0x5a, 0x47, 0x23, 0x7b, 0xa5, 0xc7, 0x67, 0x50,
                0x13, 0x19, 0x0d, 0x0c, 0x50, 0x21, 0xf1, 0x1d, 0xd1, 0x16, 0xe4, 0xb7, 0x74, 0x34,
                0x4f, 0x4c, 0xf9, 0x5d, 0x88, 0x9b, 0x39, 0x07,
            ]
        );

        let decoded = decode_signature(raw.canonical_signature(), DecodeLimits::default())
            .unwrap_or_else(|error| panic!("completed signature decode failed: {error}"));
        let verified = verify_publisher_domain_plan(
            raw.canonical_plan(),
            &decoded,
            &raw_fixture.anchor,
            PublisherPlanExpectation {
                expected_plan: raw.plan().fields(),
                now_seconds: 150,
            },
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("core verification failed: {error}"));
        assert_eq!(verified.descriptor(), raw.descriptor());
    }

    #[test]
    fn admission_request_plan_remains_bound_through_signing_and_verification() {
        let fixture = fixture();
        let draft = admission_draft(&fixture.plan);
        let request = PublisherAdmissionRequestV1::new(draft.clone())
            .unwrap_or_else(|error| panic!("test admission request failed: {error}"));
        let preparation = PublisherPlanPreparation::new(request.plan().clone(), fixture.authority)
            .unwrap_or_else(|error| panic!("test preparation failed: {error}"));
        let returned = signature(&preparation, &fixture.key);
        let signed = preparation
            .complete(ReturnedSignature::Bytes(returned.signature()), 150)
            .unwrap_or_else(|error| panic!("test completion failed: {error}"));
        let envelope = decode_signature(signed.canonical_signature(), DecodeLimits::default())
            .unwrap_or_else(|error| panic!("completed signature decode failed: {error}"));

        let verified = verify_publisher_domain_plan(
            signed.canonical_plan(),
            &envelope,
            &fixture.anchor,
            PublisherPlanExpectation {
                expected_plan: request.plan().fields(),
                now_seconds: 150,
            },
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("core verification failed: {error}"));
        assert_eq!(verified.plan(), signed.plan());
        assert_eq!(request.validate_plan_binding(signed.plan()), Ok(()));

        let mutations: &[fn(&mut PublisherAdmissionRequestDraftV1)] = &[
            |changed| {
                changed.challenge = PublisherChallengeV1::from_bytes([30; 32])
                    .unwrap_or_else(|error| panic!("test challenge failed: {error}"));
            },
            |changed| changed.capability = CapabilityId::from_bytes([31; 16]),
            |changed| changed.cache_resource = ResourceId::from_bytes([32; 16]),
        ];
        for mutate in mutations {
            let mut changed = draft.clone();
            mutate(&mut changed);
            let changed_request = PublisherAdmissionRequestV1::new(changed)
                .unwrap_or_else(|error| panic!("changed request failed: {error}"));
            assert!(matches!(
                verify_publisher_domain_plan(
                    signed.canonical_plan(),
                    &envelope,
                    &fixture.anchor,
                    PublisherPlanExpectation {
                        expected_plan: changed_request.plan().fields(),
                        now_seconds: 150,
                    },
                    DecodeLimits::default(),
                ),
                Err(PublisherPlanVerificationError::PlanMismatch)
            ));
            assert!(matches!(
                changed_request.validate_plan_binding(signed.plan()),
                Err(aos_sandbox_core::InvalidPublisherAdmissionRequest::PlanMismatch)
            ));
        }
    }

    #[test]
    fn wrong_purpose_and_reserved_authority_identity_fail_before_preparation() {
        let publisher_fixture = fixture();
        let broker_key = SigningKey::from_bytes(&[23; 32]);
        let broker_signer = KeyReference::new(
            StableKeyId::new("broker-controller".to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            1,
            ObjectDigest::from_bytes(Sha256::digest(broker_key.verifying_key().as_bytes()).into()),
            KeyUsage::BrokerAuthorization,
        );
        let broker_scope = TrustScopeId::from_bytes([24; 16]);
        let broker_policy = TrustPolicy::new(
            broker_scope,
            SignaturePurpose::BrokerAuthorization,
            vec![broker_signer.clone()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test broker policy failed: {error}"));
        let broker_policy_bytes = encode_trust_policy(&broker_policy);
        let broker_authority = SigningAuthority::new(
            broker_policy_bytes.clone(),
            descriptor_for_bytes(media(PortableMediaType::TrustPolicy), &broker_policy_bytes),
            broker_scope,
            broker_signer,
            broker_key.verifying_key().to_bytes(),
            SignaturePurpose::BrokerAuthorization,
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test broker authority failed: {error}"));
        assert!(matches!(
            PublisherPlanPreparation::new(publisher_fixture.plan, broker_authority),
            Err(AuthorizationPreparationError::PurposeMismatch)
        ));

        let zero_generation = fixture();
        let zero_generation_signer = KeyReference::new(
            zero_generation.authority.signer.stable_key_id().clone(),
            0,
            zero_generation.authority.signer.public_key_sha256(),
            KeyUsage::PublisherAuthorization,
        );
        let mut zero_generation_authority = zero_generation.authority;
        zero_generation_authority.signer = zero_generation_signer;
        assert!(matches!(
            PublisherPlanPreparation::new(zero_generation.plan, zero_generation_authority),
            Err(AuthorizationPreparationError::SignerMismatch)
        ));
        let zero_scope = fixture();
        let mut zero_scope_authority = zero_scope.authority;
        zero_scope_authority.trust_scope = TrustScopeId::from_bytes([0; 16]);
        assert!(matches!(
            PublisherPlanPreparation::new(zero_scope.plan, zero_scope_authority),
            Err(AuthorizationPreparationError::TrustScopeMismatch)
        ));
    }

    #[test]
    fn authority_policy_key_time_and_signature_substitution_fail_closed() {
        let authority_fixture = fixture();
        let wrong_key = [0; 32];
        assert!(matches!(
            SigningAuthority::new(
                authority_fixture.authority.canonical_policy.clone(),
                authority_fixture.authority.policy_descriptor.clone(),
                authority_fixture.authority.trust_scope,
                authority_fixture.authority.signer.clone(),
                wrong_key,
                SignaturePurpose::PublisherAuthorization,
                DecodeLimits::default(),
            ),
            Err(AuthorizationPreparationError::PublicKeyFingerprintMismatch)
        ));
        let wrong_policy_descriptor = aos_sandbox_core::ObjectDescriptor::new(
            authority_fixture
                .authority
                .policy_descriptor
                .media_type()
                .clone(),
            ObjectDigest::from_bytes([25; 32]),
            authority_fixture.authority.policy_descriptor.encoded_size(),
        );
        assert!(matches!(
            SigningAuthority::new(
                authority_fixture.authority.canonical_policy,
                wrong_policy_descriptor,
                authority_fixture.authority.trust_scope,
                authority_fixture.authority.signer,
                authority_fixture.key.verifying_key().to_bytes(),
                SignaturePurpose::PublisherAuthorization,
                DecodeLimits::default(),
            ),
            Err(AuthorizationPreparationError::PolicyDescriptorMismatch)
        ));

        let stale = fixture();
        let stale_preparation = PublisherPlanPreparation::new(stale.plan, stale.authority)
            .unwrap_or_else(|error| panic!("test preparation failed: {error}"));
        let stale_signature = signature(&stale_preparation, &stale.key);
        assert!(matches!(
            stale_preparation.complete(ReturnedSignature::Bytes(stale_signature.signature()), 200,),
            Err(AuthorizationPreparationError::Signature(
                aos_sandbox_core::SignatureVerificationError::Expired
            ))
        ));

        let forged = fixture();
        let forged_preparation = PublisherPlanPreparation::new(forged.plan, forged.authority)
            .unwrap_or_else(|error| panic!("test preparation failed: {error}"));
        assert!(matches!(
            forged_preparation
                .complete(ReturnedSignature::Bytes(SignatureBytes::new([0; 64])), 150,),
            Err(AuthorizationPreparationError::Signature(
                aos_sandbox_core::SignatureVerificationError::InvalidSignature
            ))
        ));

        let substituted = fixture();
        let substituted_preparation =
            PublisherPlanPreparation::new(substituted.plan, substituted.authority)
                .unwrap_or_else(|error| panic!("test preparation failed: {error}"));
        let original = signature(&substituted_preparation, &substituted.key);
        let mut statement = original.statement().clone();
        // A valid envelope for another plan is rejected before signature use.
        let other_subject = aos_sandbox_core::ObjectDescriptor::new(
            statement.subject().media_type().clone(),
            ObjectDigest::from_bytes([26; 32]),
            statement.subject().encoded_size(),
        );
        statement = aos_sandbox_core::model::SignatureStatement::new(
            other_subject,
            statement.trust_scope(),
            statement.signer().clone(),
            statement.purpose(),
            statement.issued_seconds(),
            statement.expires_seconds(),
            statement.verification_policy().clone(),
        )
        .unwrap_or_else(|error| panic!("test substituted statement failed: {error}"));
        let substituted_envelope =
            encode_signature(&Signature::new(statement, original.signature()));
        assert!(matches!(
            substituted_preparation
                .complete(ReturnedSignature::Envelope(&substituted_envelope), 150,),
            Err(AuthorizationPreparationError::ReturnedStatementMismatch)
        ));
    }
}
