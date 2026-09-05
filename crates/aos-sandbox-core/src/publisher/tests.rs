//! Structural rejection and hash-domain tests for inert publisher plans.

#![allow(clippy::unwrap_used, reason = "Invalid test fixtures must panic.")]

use super::*;
use crate::{CacheDomainId, MediaType, descriptor_for_bytes};

fn draft() -> PublisherDomainPlanDraft {
    PublisherDomainPlanDraft {
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
            content: descriptor_for_bytes(
                MediaType::new(PortableMediaType::Content.as_str()).unwrap(),
                b"content",
            ),
            source_authorization: ObjectDigest::from_bytes([11; 32]),
            commitment: PublisherRequestCommitment::for_canonical_bytes(b"request"),
            maximum_bytes: 4096,
        },
        authority: PublisherAuthorityBindings {
            policy: ObjectDigest::from_bytes([12; 32]),
            policy_generation: 1,
            controller_generation: 2,
            revocation_scope: RevocationScopeId::from_bytes([13; 16]),
            revocation_generation: 3,
            root_registry_generation: 4,
        },
        issued_seconds: 100,
        expires_seconds: 200,
        required_features: Vec::new(),
    }
}

#[test]
fn raw_content_plan_needs_no_sandbox_assignment() {
    let input = draft();
    let plan = PublisherDomainPlan::new(input.clone()).unwrap();
    assert_eq!(plan.fields(), &input);
}

#[test]
fn existing_project_capabilities_distinguish_publish_from_read() {
    use crate::{
        AuditId, AuthorizationContext, AuthorizationError, CapabilityDraft, CapabilityId,
        CapabilityRecord, DelegationLimits, Grant, GrantId, Operation, OperationSet, ResourceId,
        ResourceKind, ResourceVector, Revision, Selector,
    };

    let plan = draft();
    // Controller-selected logical resource, not a filename or a caller-selected
    // conversion of cache-domain bytes. This tests evaluation, not online issuance.
    let selector = Selector::Resource {
        resource: ResourceId::new(),
    };
    let capability = CapabilityRecord::issue(CapabilityDraft {
        id: CapabilityId::new(),
        issuer: PrincipalId::new(),
        audience: plan.target.principal,
        holder: plan.request.holder,
        channel_binding: plan.request.channel,
        root_subject: PrincipalId::new(),
        project: plan.target.project,
        sandbox: None,
        incarnation: None,
        grants: vec![
            Grant::new(
                GrantId::new(),
                ResourceKind::CachePublish,
                OperationSet::one(Operation::Publish),
                selector.clone(),
                false,
            )
            .unwrap(),
        ],
        policy_digest: plan.authority.policy,
        assignment_epoch: None,
        not_before: 100,
        expires_at: 200,
        revocation_scope: plan.authority.revocation_scope,
        revocation_generation: Revision::new(3),
        delegation: DelegationLimits::new(0, 0, ResourceVector::ZERO),
        parent_decision: AuditId::new(),
    })
    .unwrap();
    let mut context = AuthorizationContext {
        now: 150,
        audience: plan.target.principal,
        holder: plan.request.holder,
        channel_binding: plan.request.channel,
        project: plan.target.project,
        sandbox: None,
        incarnation: None,
        assignment_epoch: None,
        revocation_generation: Revision::new(3),
    };
    assert_eq!(
        capability.authorize(
            &context,
            ResourceKind::CachePublish,
            Operation::Publish,
            &selector
        ),
        Ok(())
    );
    assert_eq!(
        capability.authorize(
            &context,
            ResourceKind::CacheRead,
            Operation::ContentRead,
            &selector
        ),
        Err(AuthorizationError::Denied)
    );
    context.revocation_generation = Revision::new(4);
    assert_eq!(
        capability.authorize(
            &context,
            ResourceKind::CachePublish,
            Operation::Publish,
            &selector
        ),
        Err(AuthorizationError::Revoked)
    );
}

#[test]
fn every_authority_sentinel_fails_closed() {
    type Mutation = fn(&mut PublisherDomainPlanDraft);
    let cases: &[(&str, Mutation)] = &[
        ("publisher principal", |p| {
            p.target.principal = PrincipalId::from_bytes([0; 16])
        }),
        ("publisher instance", |p| {
            p.target.instance = PublisherInstanceId::from_bytes([0; 16])
        }),
        ("node", |p| p.target.node = NodeId::from_bytes([0; 16])),
        ("project", |p| {
            p.target.project = ProjectId::from_bytes([0; 16])
        }),
        ("cache domain", |p| {
            p.target.cache_domain =
                CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([0; 16]))
        }),
        ("holder", |p| {
            p.request.holder = PrincipalId::from_bytes([0; 16])
        }),
        ("operation", |p| {
            p.request.operation = OperationId::from_bytes([0; 16])
        }),
        ("reservation", |p| {
            p.request.reservation = PublicationReservationId::from_bytes([0; 16])
        }),
        ("revocation scope", |p| {
            p.authority.revocation_scope = RevocationScopeId::from_bytes([0; 16])
        }),
        ("isolation policy", |p| {
            p.target.isolation_policy = ObjectDigest::from_bytes([0; 32])
        }),
        ("source authorization", |p| {
            p.request.source_authorization = ObjectDigest::from_bytes([0; 32])
        }),
        ("policy", |p| {
            p.authority.policy = ObjectDigest::from_bytes([0; 32])
        }),
        ("channel", |p| {
            p.request.channel = ChannelBinding::new([0; 32])
        }),
        ("policy generation", |p| p.authority.policy_generation = 0),
        ("controller generation", |p| {
            p.authority.controller_generation = 0
        }),
        ("revocation generation", |p| {
            p.authority.revocation_generation = 0
        }),
        ("root registry generation", |p| {
            p.authority.root_registry_generation = 0
        }),
    ];
    for (field, mutate) in cases {
        let mut input = draft();
        mutate(&mut input);
        assert_eq!(
            PublisherDomainPlan::new(input),
            Err(InvalidPublisherDomainPlan::Unspecified { field }),
            "{field}"
        );
    }
}

#[test]
fn project_publication_cannot_promote_or_cross_disclosure_classes() {
    for kind in [
        CacheDomainKind::Private,
        CacheDomainKind::TrustDomain,
        CacheDomainKind::Public,
    ] {
        let mut input = draft();
        input.target.cache_domain = CacheDomain::new(kind, CacheDomainId::from_bytes([5; 16]));
        assert_eq!(
            PublisherDomainPlan::new(input),
            Err(InvalidPublisherDomainPlan::NotProjectDomain)
        );
    }
}

#[test]
fn byte_ceilings_allow_empty_content_but_reject_overflow_and_short_reservations() {
    let mut input = draft();
    input.request.maximum_bytes = 6;
    assert_eq!(
        PublisherDomainPlan::new(input),
        Err(InvalidPublisherDomainPlan::InvalidByteCeiling)
    );

    let mut input = draft();
    input.request.maximum_bytes = u64::MAX;
    assert_eq!(
        PublisherDomainPlan::new(input),
        Err(InvalidPublisherDomainPlan::InvalidByteCeiling)
    );

    let mut input = draft();
    input.request.content = descriptor_for_bytes(
        MediaType::new(PortableMediaType::Content.as_str()).unwrap(),
        b"",
    );
    input.request.maximum_bytes = 0;
    assert!(PublisherDomainPlan::new(input).is_ok());
}

#[test]
fn other_media_types_and_unsupported_protocols_are_not_raw_publication() {
    let mut input = draft();
    input.request.content = descriptor_for_bytes(
        MediaType::new(PortableMediaType::Tree.as_str()).unwrap(),
        b"content",
    );
    assert_eq!(
        PublisherDomainPlan::new(input),
        Err(InvalidPublisherDomainPlan::NotRawContent)
    );
    for version in [
        ProtocolVersion::new(0, 0),
        ProtocolVersion::new(1, 1),
        ProtocolVersion::new(2, 0),
    ] {
        let mut input = draft();
        input.protocol_version = version;
        assert!(matches!(
            PublisherDomainPlan::new(input),
            Err(InvalidPublisherDomainPlan::Registry(_))
        ));
    }
}

#[test]
fn invalid_intervals_and_required_semantics_fail_closed() {
    for expiry in [99, 100] {
        let mut input = draft();
        input.expires_seconds = expiry;
        assert_eq!(
            PublisherDomainPlan::new(input),
            Err(InvalidPublisherDomainPlan::InvalidValidity)
        );
    }
    let mut input = draft();
    input.required_features = vec![FeatureRef::new("org.example.unimplemented", 1, 0).unwrap()];
    assert!(matches!(
        PublisherDomainPlan::new(input),
        Err(InvalidPublisherDomainPlan::Registry(_))
    ));
    let mut input = draft();
    input.required_features = vec![FeatureRef::new("org.example.unimplemented", 1, 0).unwrap(); 65];
    assert_eq!(
        PublisherDomainPlan::new(input),
        Err(InvalidPublisherDomainPlan::InvalidFeatures)
    );
}

#[test]
fn request_commitment_is_separate_from_broker_arguments_and_raw_sha256() {
    use sha2::{Digest as _, Sha256};
    let bytes = b"same canonical bytes";
    let publisher = PublisherRequestCommitment::for_canonical_bytes(bytes).digest();
    assert_ne!(
        publisher,
        crate::BrokerArgumentCommitment::for_canonical_bytes(bytes).digest()
    );
    assert_ne!(
        publisher,
        ObjectDigest::from_bytes(Sha256::digest(bytes).into())
    );
    assert_eq!(
        PublisherRequestCommitment::from_digest(ObjectDigest::from_bytes([0; 32])),
        Err(InvalidPublisherDomainPlan::Unspecified {
            field: "request commitment"
        })
    );
}
