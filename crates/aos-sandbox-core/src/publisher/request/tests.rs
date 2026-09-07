//! Request-preimage consistency and exact-field substitution regressions.

#![allow(clippy::unwrap_used, reason = "Invalid test fixtures must panic.")]

use super::*;
use crate::format::{decode_publisher_admission_request_v1, encode_publisher_admission_request_v1};
use crate::model::{CacheDomain, CacheDomainKind};
use crate::{
    CacheDomainId, DecodeLimits, NodeId, ProjectId, PublisherInstanceId, RevocationScopeId,
};

fn draft() -> PublisherAdmissionRequestDraftV1 {
    let plan = crate::publisher::tests::draft();
    PublisherAdmissionRequestDraftV1 {
        capability: CapabilityId::from_bytes([14; 16]),
        cache_resource: ResourceId::from_bytes([15; 16]),
        challenge: PublisherChallengeV1::from_bytes([16; 32]).unwrap(),
        protocol_version: plan.protocol_version,
        target: plan.target,
        claim: PublisherAdmissionClaimV1 {
            holder: plan.request.holder,
            channel: plan.request.channel,
            operation: plan.request.operation,
            reservation: plan.request.reservation,
            content: plan.request.content,
            source_authorization: plan.request.source_authorization,
            maximum_bytes: plan.request.maximum_bytes,
        },
        authority: plan.authority,
        issued_seconds: plan.issued_seconds,
        expires_seconds: plan.expires_seconds,
        required_features: plan.required_features,
    }
}

#[test]
fn encoding_reconstructs_the_plan_commitment_without_a_self_referential_field() {
    let request = PublisherAdmissionRequestV1::new(draft()).unwrap();
    let canonical = encode_publisher_admission_request_v1(&request);
    assert_eq!(
        request.plan().fields().request.commitment,
        PublisherRequestCommitment::for_canonical_bytes(&canonical)
    );
    assert_eq!(
        decode_publisher_admission_request_v1(&canonical, DecodeLimits::default()).unwrap(),
        request
    );
    assert_eq!(request.validate_plan_binding(request.plan()), Ok(()));

    let mut changed = request.plan().fields().clone();
    changed.request.commitment = PublisherRequestCommitment::for_canonical_bytes(b"unrelated");
    assert_eq!(
        request.validate_plan_binding(&PublisherDomainPlan::new(changed).unwrap()),
        Err(InvalidPublisherAdmissionRequest::PlanMismatch)
    );
}

#[test]
fn each_admissible_request_field_changes_the_plan_commitment() {
    type Mutation = fn(&mut PublisherAdmissionRequestDraftV1);
    let cases: &[(&str, Mutation)] = &[
        ("capability", |p| {
            p.capability = CapabilityId::from_bytes([90; 16])
        }),
        ("cache resource", |p| {
            p.cache_resource = ResourceId::from_bytes([90; 16])
        }),
        ("challenge", |p| {
            p.challenge = PublisherChallengeV1::from_bytes([90; 32]).unwrap()
        }),
        ("publisher principal", |p| {
            p.target.principal = PrincipalId::from_bytes([90; 16])
        }),
        ("publisher instance", |p| {
            p.target.instance = PublisherInstanceId::from_bytes([90; 16])
        }),
        ("node", |p| p.target.node = NodeId::from_bytes([90; 16])),
        ("project", |p| {
            p.target.project = ProjectId::from_bytes([90; 16])
        }),
        ("cache domain", |p| {
            p.target.cache_domain = CacheDomain::new(
                CacheDomainKind::Project,
                CacheDomainId::from_bytes([90; 16]),
            )
        }),
        ("isolation policy", |p| {
            p.target.isolation_policy = ObjectDigest::from_bytes([90; 32])
        }),
        ("holder", |p| {
            p.claim.holder = PrincipalId::from_bytes([90; 16])
        }),
        ("channel", |p| {
            p.claim.channel = ChannelBinding::new([90; 32])
        }),
        ("operation", |p| {
            p.claim.operation = OperationId::from_bytes([90; 16])
        }),
        ("reservation", |p| {
            p.claim.reservation = PublicationReservationId::from_bytes([90; 16])
        }),
        ("content digest", |p| {
            p.claim.content = ObjectDescriptor::new(
                p.claim.content.media_type().clone(),
                ObjectDigest::from_bytes([90; 32]),
                p.claim.content.encoded_size(),
            )
        }),
        ("content size", |p| {
            p.claim.content = ObjectDescriptor::new(
                p.claim.content.media_type().clone(),
                p.claim.content.digest(),
                8,
            )
        }),
        ("source authorization", |p| {
            p.claim.source_authorization = ObjectDigest::from_bytes([90; 32])
        }),
        ("maximum bytes", |p| p.claim.maximum_bytes = 8192),
        ("policy", |p| {
            p.authority.policy = ObjectDigest::from_bytes([90; 32])
        }),
        ("policy generation", |p| p.authority.policy_generation = 90),
        ("controller generation", |p| {
            p.authority.controller_generation = 90
        }),
        ("revocation scope", |p| {
            p.authority.revocation_scope = RevocationScopeId::from_bytes([90; 16])
        }),
        ("revocation generation", |p| {
            p.authority.revocation_generation = 90
        }),
        ("root registry", |p| {
            p.authority.root_registry_generation = 90
        }),
        ("issued", |p| p.issued_seconds = 101),
        ("expires", |p| p.expires_seconds = 201),
        ("required features", |p| {
            p.required_features =
                vec![FeatureRef::new("aos.sandbox.identity.posix32", 1, 0).unwrap()]
        }),
    ];
    let original = PublisherAdmissionRequestV1::new(draft()).unwrap();
    for (name, mutate) in cases {
        let mut changed = draft();
        mutate(&mut changed);
        let request = PublisherAdmissionRequestV1::new(changed).unwrap();
        assert_ne!(
            request.plan().fields().request.commitment,
            original.plan().fields().request.commitment,
            "{name}"
        );
        assert_eq!(
            original.validate_plan_binding(request.plan()),
            Err(InvalidPublisherAdmissionRequest::PlanMismatch),
            "{name}"
        );
    }
}

#[test]
fn lookup_handles_and_challenge_cannot_be_unspecified() {
    let mut changed = draft();
    changed.capability = CapabilityId::from_bytes([0; 16]);
    assert_eq!(
        PublisherAdmissionRequestV1::new(changed),
        Err(InvalidPublisherAdmissionRequest::UnspecifiedCapability)
    );
    let mut changed = draft();
    changed.cache_resource = ResourceId::from_bytes([0; 16]);
    assert_eq!(
        PublisherAdmissionRequestV1::new(changed),
        Err(InvalidPublisherAdmissionRequest::UnspecifiedCacheResource)
    );
    assert_eq!(
        PublisherChallengeV1::from_bytes([0; 32]),
        Err(InvalidPublisherAdmissionRequest::UnspecifiedChallenge)
    );
}

#[test]
fn constructing_the_same_request_does_not_claim_challenge_freshness() {
    // Construction is deterministic. A durable authority must distinguish
    // permitted exact receipt replay from reusing this challenge for new work.
    let first = PublisherAdmissionRequestV1::new(draft()).unwrap();
    assert_eq!(PublisherAdmissionRequestV1::new(draft()).unwrap(), first);
}

#[test]
fn allocation_and_protocol_bounds_apply_before_a_request_can_be_used() {
    assert_eq!(
        decode_publisher_admission_request_v1(
            &vec![0; MAXIMUM_PUBLISHER_ADMISSION_REQUEST_BYTES + 1],
            DecodeLimits::default()
        ),
        Err(crate::CanonicalCborError::ObjectTooLarge)
    );
    let mut changed = draft();
    changed.required_features =
        vec![FeatureRef::new("aos.sandbox.identity.posix32", 1, 0).unwrap(); 65];
    assert_eq!(
        PublisherAdmissionRequestV1::new(changed),
        Err(InvalidPublisherAdmissionRequest::Plan(
            InvalidPublisherDomainPlan::InvalidFeatures
        ))
    );
    let mut changed = draft();
    changed.protocol_version = ProtocolVersion::new(1, 1);
    assert!(matches!(
        PublisherAdmissionRequestV1::new(changed),
        Err(InvalidPublisherAdmissionRequest::Plan(
            InvalidPublisherDomainPlan::Registry(_)
        ))
    ));
}
