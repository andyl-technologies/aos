//! Authentication of controller-signed publisher-domain plans.
//!
//! Verification proves that canonical plan bytes were signed under one pinned
//! publisher trust configuration and exactly match independently trusted local
//! expectations. It does not prove that any generation remains current and it
//! does not authorize materialization, naming, catalog, or disclosure effects.

use sha2::{Digest as _, Sha256};

use crate::format::{
    CanonicalCborError, DecodeLimits, decode_publisher_domain_plan, decode_trust_policy,
    descriptor_for_bytes,
};
use crate::model::{KeyReference, Signature, SignaturePurpose};
use crate::publisher::{PublisherDomainPlan, PublisherDomainPlanDraft};
use crate::{
    MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, RegistryError, RevocationScopeId,
    SignatureVerificationError, TrustScopeId, verify_signature,
};

/// Pins the controller trust generation accepted for publisher plans.
#[derive(Debug)]
pub struct PublisherPlanTrustAnchor {
    canonical_policy: Vec<u8>,
    policy_descriptor: ObjectDescriptor,
    trust_scope: TrustScopeId,
    signer: KeyReference,
    public_key: [u8; 32],
    revocation_scope: RevocationScopeId,
}

impl PublisherPlanTrustAnchor {
    /// Constructs one explicit publisher-plan anchor from protected configuration.
    ///
    /// Callers must obtain every argument from protected local configuration.
    /// Policy bytes, keys, generations, or scopes supplied by a publication
    /// request are not trust anchors.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherPlanVerificationError`] unless the canonical policy,
    /// descriptor, trust scope, publisher purpose, signer generation, key
    /// fingerprint, and revocation scope are exact and non-sentinel.
    #[allow(clippy::too_many_arguments)]
    pub fn from_trusted_configuration(
        canonical_policy: Vec<u8>,
        policy_descriptor: ObjectDescriptor,
        trust_scope: TrustScopeId,
        signer: KeyReference,
        public_key: [u8; 32],
        revocation_scope: RevocationScopeId,
        limits: DecodeLimits,
    ) -> Result<Self, PublisherPlanVerificationError> {
        let policy = decode_trust_policy(&canonical_policy, limits)?;
        crate::validate_required_features(policy.required_features())?;
        crate::validate_descriptor_role(
            crate::DescriptorRole::SignatureVerificationPolicy,
            &policy_descriptor,
        )?;
        let computed =
            descriptor_for_bytes(policy_descriptor.media_type().clone(), &canonical_policy);
        if computed != policy_descriptor
            || policy.trust_scope() != trust_scope
            || trust_scope.as_bytes() == &[0; 16]
            || policy.purpose() != SignaturePurpose::PublisherAuthorization
            || !policy.allowed_keys().contains(&signer)
            || signer.generation() == 0
            || signer.public_key_sha256()
                != ObjectDigest::from_bytes(Sha256::digest(public_key).into())
            || revocation_scope.as_bytes() == &[0; 16]
        {
            return Err(PublisherPlanVerificationError::InvalidTrustAnchor);
        }

        Ok(Self {
            canonical_policy,
            policy_descriptor,
            trust_scope,
            signer,
            public_key,
            revocation_scope,
        })
    }
}

/// Supplies exact local facts that an authentic publisher plan must match.
#[derive(Clone, Copy, Debug)]
pub struct PublisherPlanExpectation<'a> {
    /// Entire expected plan, obtained independently of the signed request.
    pub expected_plan: &'a PublisherDomainPlanDraft,
    /// Verification clock as a Unix second.
    pub now_seconds: i64,
}

/// Reports failed cryptographic or semantic publisher-plan authentication.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublisherPlanVerificationError {
    /// Canonical plan decoding or its closed registries failed.
    #[error("invalid canonical publisher-domain plan: {0}")]
    Plan(#[from] CanonicalCborError),
    /// Detached signature verification failed.
    #[error("publisher authorization signature verification failed: {0}")]
    Signature(#[from] SignatureVerificationError),
    /// The signature does not authenticate a publisher-domain plan.
    #[error("signature subject does not match the publisher-domain plan")]
    SubjectMismatch,
    /// The controller used a different trust scope, policy, or signer generation.
    #[error("publisher authorization signature does not match the pinned trust anchor")]
    TrustAnchorMismatch,
    /// Signature statement and publisher plan time bounds differ.
    #[error("signature and publisher-domain plan validity differ")]
    ValidityMismatch,
    /// The authentic plan differs from independently trusted expected fields.
    #[error("publisher-domain plan does not match the exact local expectation")]
    PlanMismatch,
    /// The plan is expired or not yet valid.
    #[error("publisher-domain plan is outside its validity interval")]
    InvalidTime,
    /// A required semantic feature is unknown locally.
    #[error("publisher plan registry validation failed: {0}")]
    Registry(#[from] RegistryError),
    /// The configured trust anchor is internally inconsistent.
    #[error("invalid publisher-plan trust anchor")]
    InvalidTrustAnchor,
    /// Plan revocation scope differs from the pinned anchor.
    #[error("publisher-plan revocation scope mismatch")]
    RevocationScopeMismatch,
}

/// Proves plan authenticity without authorizing a publication effect.
///
/// The proof intentionally is not `Clone`. Consumers must still resolve
/// current controller state, retain the reservation, and obtain the relevant
/// materialization, naming, catalog, and disclosure authorities.
///
/// ```compile_fail
/// use aos_sandbox_core::publisher::VerifiedPublisherDomainPlan;
///
/// fn duplicate(proof: &VerifiedPublisherDomainPlan) -> VerifiedPublisherDomainPlan {
///     proof.clone()
/// }
/// ```
///
/// ```compile_fail
/// use aos_sandbox_core::publisher::{PublisherDomainPlan, VerifiedPublisherDomainPlan};
/// use aos_sandbox_core::ObjectDescriptor;
///
/// fn forge(
///     plan: PublisherDomainPlan,
///     descriptor: ObjectDescriptor,
/// ) -> VerifiedPublisherDomainPlan {
///     VerifiedPublisherDomainPlan { plan, descriptor }
/// }
/// ```
#[derive(Debug)]
pub struct VerifiedPublisherDomainPlan {
    plan: PublisherDomainPlan,
    descriptor: ObjectDescriptor,
}

impl VerifiedPublisherDomainPlan {
    /// Returns the fully decoded and structurally validated plan.
    #[must_use]
    pub const fn plan(&self) -> &PublisherDomainPlan {
        &self.plan
    }

    /// Returns the full canonical object descriptor authenticated by the signature.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
}

/// Verifies canonical publisher-plan bytes and a detached controller signature.
///
/// The expected plan must come from independently trusted configuration. Exact
/// equality is a binding check, not evidence that its authority generations are
/// current. Success authenticates the plan only and grants no effect authority.
/// Static plan expiry does not cancel an independently retained completion permit.
///
/// # Errors
///
/// Returns [`PublisherPlanVerificationError`] unless canonical decoding,
/// required features, signature subject and purpose, pinned trust anchor,
/// validity, revocation scope, and every expected plan field match exactly.
pub fn verify_publisher_domain_plan(
    canonical_plan: &[u8],
    signature: &Signature,
    anchor: &PublisherPlanTrustAnchor,
    expectation: PublisherPlanExpectation<'_>,
    limits: DecodeLimits,
) -> Result<VerifiedPublisherDomainPlan, PublisherPlanVerificationError> {
    let plan = decode_publisher_domain_plan(canonical_plan, limits)?;
    crate::validate_required_features(&plan.fields().required_features)?;

    let descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::PublisherDomainPlan.as_str().to_owned()).map_err(
            |error| CanonicalCborError::InvalidSemantics {
                object: "publisher-domain plan media type",
                message: error.to_string(),
            },
        )?,
        canonical_plan,
    );
    let statement = signature.statement();
    if statement.subject() != &descriptor
        || statement.purpose() != SignaturePurpose::PublisherAuthorization
    {
        return Err(PublisherPlanVerificationError::SubjectMismatch);
    }
    if statement.signer() != &anchor.signer
        || statement.verification_policy() != &anchor.policy_descriptor
        || statement.trust_scope() != anchor.trust_scope
    {
        return Err(PublisherPlanVerificationError::TrustAnchorMismatch);
    }
    if statement.issued_seconds() != plan.fields().issued_seconds
        || statement.expires_seconds() != Some(plan.fields().expires_seconds)
    {
        return Err(PublisherPlanVerificationError::ValidityMismatch);
    }

    verify_signature(
        signature,
        &anchor.canonical_policy,
        &anchor.public_key,
        expectation.now_seconds,
        limits,
    )?;

    if plan.fields().authority.revocation_scope != anchor.revocation_scope {
        return Err(PublisherPlanVerificationError::RevocationScopeMismatch);
    }
    if plan.fields() != expectation.expected_plan {
        return Err(PublisherPlanVerificationError::PlanMismatch);
    }
    if expectation.now_seconds < plan.fields().issued_seconds
        || expectation.now_seconds >= plan.fields().expires_seconds
    {
        return Err(PublisherPlanVerificationError::InvalidTime);
    }

    Ok(VerifiedPublisherDomainPlan { plan, descriptor })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::format::{encode_publisher_domain_plan, encode_trust_policy};
    use crate::model::{
        CacheDomain, CacheDomainKind, KeyUsage, SignatureBytes, SignatureStatement, StableKeyId,
        TrustPolicy,
    };
    use crate::publisher::{
        PublisherAuthorityBindings, PublisherRequest, PublisherRequestCommitment, PublisherTarget,
    };
    use crate::{
        CacheDomainId, ChannelBinding, NodeId, OperationId, PrincipalId, ProjectId,
        ProtocolVersion, PublicationReservationId, PublisherInstanceId,
    };

    struct Fixture {
        plan: PublisherDomainPlan,
        plan_bytes: Vec<u8>,
        signature: Signature,
        anchor: PublisherPlanTrustAnchor,
        signing_key: SigningKey,
    }

    fn id<const BYTE: u8>() -> [u8; 16] {
        [BYTE; 16]
    }

    fn media(kind: PortableMediaType) -> MediaType {
        MediaType::new(kind.as_str().to_owned())
            .unwrap_or_else(|error| panic!("test media type failed: {error}"))
    }

    fn signer(signing_key: &SigningKey, usage: KeyUsage) -> KeyReference {
        KeyReference::new(
            StableKeyId::new("publisher-controller".to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            7,
            ObjectDigest::from_bytes(Sha256::digest(signing_key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn plan_draft() -> PublisherDomainPlanDraft {
        PublisherDomainPlanDraft {
            protocol_version: ProtocolVersion::new(1, 0),
            target: PublisherTarget {
                principal: PrincipalId::from_bytes(id::<1>()),
                instance: PublisherInstanceId::from_bytes(id::<2>()),
                node: NodeId::from_bytes(id::<3>()),
                project: ProjectId::from_bytes(id::<4>()),
                cache_domain: CacheDomain::new(
                    CacheDomainKind::Project,
                    CacheDomainId::from_bytes(id::<5>()),
                ),
                isolation_policy: ObjectDigest::from_bytes([6; 32]),
            },
            request: PublisherRequest {
                holder: PrincipalId::from_bytes(id::<7>()),
                channel: ChannelBinding::new([8; 32]),
                operation: OperationId::from_bytes(id::<9>()),
                reservation: PublicationReservationId::from_bytes(id::<10>()),
                content: ObjectDescriptor::new(
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
                revocation_scope: RevocationScopeId::from_bytes(id::<17>()),
                revocation_generation: 18,
                root_registry_generation: 19,
            },
            issued_seconds: 100,
            expires_seconds: 200,
            required_features: Vec::new(),
        }
    }

    fn fixture() -> Fixture {
        let signing_key = SigningKey::from_bytes(&[21; 32]);
        let signer = signer(&signing_key, KeyUsage::PublisherAuthorization);
        let scope = TrustScopeId::from_bytes(id::<22>());
        let policy = TrustPolicy::new(
            scope,
            SignaturePurpose::PublisherAuthorization,
            vec![signer.clone()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test trust policy failed: {error}"));
        let policy_bytes = encode_trust_policy(&policy);
        let policy_descriptor =
            descriptor_for_bytes(media(PortableMediaType::TrustPolicy), &policy_bytes);
        let plan = PublisherDomainPlan::new(plan_draft())
            .unwrap_or_else(|error| panic!("test publisher plan failed: {error}"));
        let plan_bytes = encode_publisher_domain_plan(&plan);
        let plan_descriptor =
            descriptor_for_bytes(media(PortableMediaType::PublisherDomainPlan), &plan_bytes);
        let statement = SignatureStatement::new(
            plan_descriptor,
            scope,
            signer.clone(),
            SignaturePurpose::PublisherAuthorization,
            plan.fields().issued_seconds,
            Some(plan.fields().expires_seconds),
            policy_descriptor.clone(),
        )
        .unwrap_or_else(|error| panic!("test statement failed: {error}"));
        let signature = crate::sign_statement(statement, &signing_key)
            .unwrap_or_else(|error| panic!("test signing failed: {error}"));
        let anchor = PublisherPlanTrustAnchor::from_trusted_configuration(
            policy_bytes,
            policy_descriptor,
            scope,
            signer,
            *signing_key.verifying_key().as_bytes(),
            plan.fields().authority.revocation_scope,
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test anchor failed: {error}"));

        Fixture {
            plan,
            plan_bytes,
            signature,
            anchor,
            signing_key,
        }
    }

    fn verify(
        fixture: &Fixture,
        expected_plan: &PublisherDomainPlanDraft,
    ) -> Result<VerifiedPublisherDomainPlan, PublisherPlanVerificationError> {
        verify_publisher_domain_plan(
            &fixture.plan_bytes,
            &fixture.signature,
            &fixture.anchor,
            PublisherPlanExpectation {
                expected_plan,
                now_seconds: 150,
            },
            DecodeLimits::default(),
        )
    }

    #[test]
    fn signed_exact_plan_returns_non_authorizing_proof() {
        let fixture = fixture();
        let verified = verify(&fixture, fixture.plan.fields())
            .unwrap_or_else(|error| panic!("valid publisher plan failed: {error}"));

        assert_eq!(verified.plan(), &fixture.plan);
        assert_eq!(
            verified.descriptor(),
            fixture.signature.statement().subject()
        );
        assert_eq!(
            verified.descriptor().encoded_size(),
            fixture.plan_bytes.len() as u64
        );
        assert_eq!(
            verified.descriptor().digest().to_string(),
            "sha256:117da571aac212ddd14ce6331d6d0330052164024219703412f1d913f753d4c6"
        );
        assert_eq!(verified.descriptor().encoded_size(), 424);
        assert_eq!(
            fixture.signature.signature().as_bytes(),
            &[
                0x47, 0xdb, 0xed, 0x9d, 0x40, 0xd0, 0x0d, 0xc6, 0xe5, 0xfd, 0x16, 0x21, 0x71, 0xf4,
                0xd4, 0xa9, 0x61, 0x5d, 0x06, 0x21, 0x05, 0xf4, 0xe2, 0x85, 0xdb, 0x31, 0x78, 0xe6,
                0xce, 0x2d, 0xbe, 0xed, 0x5f, 0x3b, 0x5a, 0x47, 0x23, 0x7b, 0xa5, 0xc7, 0x67, 0x50,
                0x13, 0x19, 0x0d, 0x0c, 0x50, 0x21, 0xf1, 0x1d, 0xd1, 0x16, 0xe4, 0xb7, 0x74, 0x34,
                0x4f, 0x4c, 0xf9, 0x5d, 0x88, 0x9b, 0x39, 0x07,
            ]
        );
    }

    #[test]
    fn every_plan_binding_must_match_independent_expectation() {
        let fixture = fixture();
        let original = fixture.plan.fields();
        let mut mutations: Vec<(&str, PublisherDomainPlanDraft)> = Vec::new();
        macro_rules! mutation {
            ($name:literal, $change:expr) => {{
                let mut draft = original.clone();
                $change(&mut draft);
                mutations.push(($name, draft));
            }};
        }

        mutation!(
            "protocol version",
            |draft: &mut PublisherDomainPlanDraft| draft.protocol_version =
                ProtocolVersion::new(1, 1)
        );
        mutation!(
            "target principal",
            |draft: &mut PublisherDomainPlanDraft| draft.target.principal =
                PrincipalId::from_bytes(id::<31>())
        );
        mutation!("target instance", |draft: &mut PublisherDomainPlanDraft| {
            draft.target.instance = PublisherInstanceId::from_bytes(id::<32>())
        });
        mutation!("target node", |draft: &mut PublisherDomainPlanDraft| {
            draft.target.node = NodeId::from_bytes(id::<33>())
        });
        mutation!("target project", |draft: &mut PublisherDomainPlanDraft| {
            draft.target.project = ProjectId::from_bytes(id::<34>())
        });
        mutation!("cache kind", |draft: &mut PublisherDomainPlanDraft| draft
            .target
            .cache_domain =
            CacheDomain::new(
                CacheDomainKind::Private,
                draft.target.cache_domain.domain_id(),
            ));
        mutation!("cache domain", |draft: &mut PublisherDomainPlanDraft| {
            draft.target.cache_domain = CacheDomain::new(
                CacheDomainKind::Project,
                CacheDomainId::from_bytes(id::<35>()),
            )
        });
        mutation!(
            "isolation policy",
            |draft: &mut PublisherDomainPlanDraft| draft.target.isolation_policy =
                ObjectDigest::from_bytes([36; 32])
        );
        mutation!("request holder", |draft: &mut PublisherDomainPlanDraft| {
            draft.request.holder = PrincipalId::from_bytes(id::<37>())
        });
        mutation!("request channel", |draft: &mut PublisherDomainPlanDraft| {
            draft.request.channel = ChannelBinding::new([38; 32])
        });
        mutation!(
            "request operation",
            |draft: &mut PublisherDomainPlanDraft| draft.request.operation =
                OperationId::from_bytes(id::<39>())
        );
        mutation!(
            "request reservation",
            |draft: &mut PublisherDomainPlanDraft| draft.request.reservation =
                PublicationReservationId::from_bytes(id::<40>())
        );
        mutation!(
            "content media type",
            |draft: &mut PublisherDomainPlanDraft| draft.request.content = ObjectDescriptor::new(
                media(PortableMediaType::Tree),
                draft.request.content.digest(),
                draft.request.content.encoded_size(),
            )
        );
        mutation!("content digest", |draft: &mut PublisherDomainPlanDraft| {
            draft.request.content = ObjectDescriptor::new(
                draft.request.content.media_type().clone(),
                ObjectDigest::from_bytes([41; 32]),
                draft.request.content.encoded_size(),
            )
        });
        mutation!("content size", |draft: &mut PublisherDomainPlanDraft| {
            draft.request.content = ObjectDescriptor::new(
                draft.request.content.media_type().clone(),
                draft.request.content.digest(),
                draft.request.content.encoded_size() + 1,
            )
        });
        mutation!(
            "source authorization",
            |draft: &mut PublisherDomainPlanDraft| draft.request.source_authorization =
                ObjectDigest::from_bytes([42; 32])
        );
        mutation!(
            "request commitment",
            |draft: &mut PublisherDomainPlanDraft| draft.request.commitment =
                PublisherRequestCommitment::from_digest(ObjectDigest::from_bytes([43; 32]))
                    .unwrap_or_else(|error| panic!("test commitment failed: {error}"))
        );
        mutation!("maximum bytes", |draft: &mut PublisherDomainPlanDraft| {
            draft.request.maximum_bytes += 1
        });
        mutation!(
            "authority policy",
            |draft: &mut PublisherDomainPlanDraft| draft.authority.policy =
                ObjectDigest::from_bytes([44; 32])
        );
        mutation!(
            "policy generation",
            |draft: &mut PublisherDomainPlanDraft| draft.authority.policy_generation += 1
        );
        mutation!(
            "controller generation",
            |draft: &mut PublisherDomainPlanDraft| draft.authority.controller_generation += 1
        );
        mutation!(
            "revocation scope",
            |draft: &mut PublisherDomainPlanDraft| draft.authority.revocation_scope =
                RevocationScopeId::from_bytes(id::<45>())
        );
        mutation!(
            "revocation generation",
            |draft: &mut PublisherDomainPlanDraft| draft.authority.revocation_generation += 1
        );
        mutation!(
            "root registry generation",
            |draft: &mut PublisherDomainPlanDraft| draft.authority.root_registry_generation += 1
        );
        mutation!("issued time", |draft: &mut PublisherDomainPlanDraft| {
            draft.issued_seconds += 1
        });
        mutation!("expiry time", |draft: &mut PublisherDomainPlanDraft| {
            draft.expires_seconds += 1
        });
        mutation!(
            "required features",
            |draft: &mut PublisherDomainPlanDraft| draft.required_features = vec![
                crate::FeatureRef::new("aos.test.untrusted", 1, 0)
                    .unwrap_or_else(|error| panic!("test feature failed: {error}"))
            ]
        );

        for (field, expected) in mutations {
            assert_eq!(
                verify(&fixture, &expected).map(|_| ()),
                Err(PublisherPlanVerificationError::PlanMismatch),
                "mutated {field} was accepted"
            );
        }
    }

    #[test]
    fn wrong_purpose_signature_and_signature_bytes_fail() {
        let fixture = fixture();
        let broker_key = SigningKey::from_bytes(&[46; 32]);
        let broker_signer = signer(&broker_key, KeyUsage::BrokerAuthorization);
        let wrong_statement = SignatureStatement::new(
            fixture.signature.statement().subject().clone(),
            fixture.anchor.trust_scope,
            broker_signer,
            SignaturePurpose::BrokerAuthorization,
            100,
            Some(200),
            fixture.anchor.policy_descriptor.clone(),
        )
        .unwrap_or_else(|error| panic!("test cross-purpose statement failed: {error}"));
        let wrong_purpose = Signature::new(wrong_statement, SignatureBytes::new([0; 64]));
        assert_eq!(
            verify_publisher_domain_plan(
                &fixture.plan_bytes,
                &wrong_purpose,
                &fixture.anchor,
                PublisherPlanExpectation {
                    expected_plan: fixture.plan.fields(),
                    now_seconds: 150,
                },
                DecodeLimits::default(),
            )
            .map(|_| ()),
            Err(PublisherPlanVerificationError::SubjectMismatch)
        );

        let invalid = Signature::new(
            fixture.signature.statement().clone(),
            SignatureBytes::new([0; 64]),
        );
        assert_eq!(
            verify_publisher_domain_plan(
                &fixture.plan_bytes,
                &invalid,
                &fixture.anchor,
                PublisherPlanExpectation {
                    expected_plan: fixture.plan.fields(),
                    now_seconds: 150,
                },
                DecodeLimits::default(),
            )
            .map(|_| ()),
            Err(PublisherPlanVerificationError::Signature(
                SignatureVerificationError::InvalidSignature
            ))
        );
    }

    #[test]
    fn trust_anchor_and_validity_are_pinned() {
        let fixture = fixture();
        let wrong_signer = KeyReference::new(
            fixture.anchor.signer.stable_key_id().clone(),
            fixture.anchor.signer.generation() + 1,
            fixture.anchor.signer.public_key_sha256(),
            KeyUsage::PublisherAuthorization,
        );
        assert_eq!(
            PublisherPlanTrustAnchor::from_trusted_configuration(
                fixture.anchor.canonical_policy.clone(),
                fixture.anchor.policy_descriptor.clone(),
                fixture.anchor.trust_scope,
                wrong_signer,
                fixture.anchor.public_key,
                fixture.anchor.revocation_scope,
                DecodeLimits::default(),
            )
            .map(|_| ()),
            Err(PublisherPlanVerificationError::InvalidTrustAnchor)
        );
        assert_eq!(
            PublisherPlanTrustAnchor::from_trusted_configuration(
                fixture.anchor.canonical_policy.clone(),
                fixture.anchor.policy_descriptor.clone(),
                fixture.anchor.trust_scope,
                fixture.anchor.signer.clone(),
                [0; 32],
                fixture.anchor.revocation_scope,
                DecodeLimits::default(),
            )
            .map(|_| ()),
            Err(PublisherPlanVerificationError::InvalidTrustAnchor)
        );
        let wrong_descriptor = ObjectDescriptor::new(
            fixture.anchor.policy_descriptor.media_type().clone(),
            ObjectDigest::from_bytes([48; 32]),
            fixture.anchor.policy_descriptor.encoded_size(),
        );
        assert_eq!(
            PublisherPlanTrustAnchor::from_trusted_configuration(
                fixture.anchor.canonical_policy.clone(),
                wrong_descriptor,
                fixture.anchor.trust_scope,
                fixture.anchor.signer.clone(),
                fixture.anchor.public_key,
                fixture.anchor.revocation_scope,
                DecodeLimits::default(),
            )
            .map(|_| ()),
            Err(PublisherPlanVerificationError::InvalidTrustAnchor)
        );
        assert_eq!(
            PublisherPlanTrustAnchor::from_trusted_configuration(
                fixture.anchor.canonical_policy.clone(),
                fixture.anchor.policy_descriptor.clone(),
                fixture.anchor.trust_scope,
                fixture.anchor.signer.clone(),
                fixture.anchor.public_key,
                RevocationScopeId::from_bytes([0; 16]),
                DecodeLimits::default(),
            )
            .map(|_| ()),
            Err(PublisherPlanVerificationError::InvalidTrustAnchor)
        );

        let mismatched_statement = SignatureStatement::new(
            fixture.signature.statement().subject().clone(),
            fixture.anchor.trust_scope,
            fixture.anchor.signer.clone(),
            SignaturePurpose::PublisherAuthorization,
            101,
            Some(200),
            fixture.anchor.policy_descriptor.clone(),
        )
        .unwrap_or_else(|error| panic!("test statement failed: {error}"));
        let mismatched_signature =
            crate::sign_statement(mismatched_statement, &fixture.signing_key)
                .unwrap_or_else(|error| panic!("test signature failed: {error}"));
        assert_eq!(
            verify_publisher_domain_plan(
                &fixture.plan_bytes,
                &mismatched_signature,
                &fixture.anchor,
                PublisherPlanExpectation {
                    expected_plan: fixture.plan.fields(),
                    now_seconds: 150,
                },
                DecodeLimits::default(),
            )
            .map(|_| ()),
            Err(PublisherPlanVerificationError::ValidityMismatch)
        );

        let other_revocation_anchor = PublisherPlanTrustAnchor {
            revocation_scope: RevocationScopeId::from_bytes(id::<47>()),
            canonical_policy: fixture.anchor.canonical_policy.clone(),
            policy_descriptor: fixture.anchor.policy_descriptor.clone(),
            trust_scope: fixture.anchor.trust_scope,
            signer: fixture.anchor.signer.clone(),
            public_key: fixture.anchor.public_key,
        };
        assert_eq!(
            verify_publisher_domain_plan(
                &fixture.plan_bytes,
                &fixture.signature,
                &other_revocation_anchor,
                PublisherPlanExpectation {
                    expected_plan: fixture.plan.fields(),
                    now_seconds: 150,
                },
                DecodeLimits::default(),
            )
            .map(|_| ()),
            Err(PublisherPlanVerificationError::RevocationScopeMismatch)
        );
    }

    #[test]
    fn time_window_and_trailing_bytes_fail_closed() {
        let fixture = fixture();
        for now_seconds in [99, 200] {
            assert!(matches!(
                verify_publisher_domain_plan(
                    &fixture.plan_bytes,
                    &fixture.signature,
                    &fixture.anchor,
                    PublisherPlanExpectation {
                        expected_plan: fixture.plan.fields(),
                        now_seconds,
                    },
                    DecodeLimits::default(),
                ),
                Err(PublisherPlanVerificationError::Signature(
                    SignatureVerificationError::NotYetValid | SignatureVerificationError::Expired
                ))
            ));
        }

        let mut trailing = fixture.plan_bytes.clone();
        trailing.push(0);
        assert!(matches!(
            verify_publisher_domain_plan(
                &trailing,
                &fixture.signature,
                &fixture.anchor,
                PublisherPlanExpectation {
                    expected_plan: fixture.plan.fields(),
                    now_seconds: 150,
                },
                DecodeLimits::default(),
            ),
            Err(PublisherPlanVerificationError::Plan(_))
        ));
    }
}
