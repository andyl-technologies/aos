//! Tests actual checked inputs and one protected decision/time-floor advance.
//!
//! Transport evidence is synthetic and confined to this test module. Protected
//! registry/policy evaluation and request binding use their real implementations;
//! these tests do not qualify an installed TLS peer or a worker read grant.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::{
    CacheDomainId, CapabilityRecord, DecodeLimits, Grant, GrantId, OperationSet, ResourceId,
    format::encode_policy,
    model::{
        CacheDomain, CacheDomainKind, Policy, ResourceProfile, RevocationMode, RevocationPolicy,
    },
};

use super::*;
use crate::controller::ControllerProtectedClockV1;
use crate::publisher_policy::{
    PreparedPublisherPolicyRevisionV1, PublisherControllerHeadV1, PublisherRevocationHeadV1,
};

fn fixture() -> (
    tempfile::TempDir,
    Journal,
    CapabilityRecord,
    PreparedPublisherPolicyRevisionV1,
) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = Journal::open_protected_at_uid(
        root.path(),
        "controller.journal",
        crate::JournalLimits::default(),
        fs::metadata(root.path()).unwrap().uid(),
    )
    .unwrap()
    .0;
    let now = ControllerProtectedClockV1::open_fixed()
        .unwrap()
        .sample()
        .unwrap()
        .wall_seconds();
    let seed = crate::publisher_authority::tests::capability(
        CapabilityId::from_bytes([61; 16]),
        now + 300,
    );
    let encoded_policy = encode_policy(
        &Policy::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ResourceProfile::new(Vec::new()).unwrap(),
            Vec::new(),
            CacheDomain::new(
                CacheDomainKind::Project,
                CacheDomainId::from_bytes([62; 16]),
            ),
            RevocationPolicy::new(RevocationMode::Freeze, 1),
            None,
            Vec::new(),
        )
        .unwrap(),
    );
    let policy = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        seed.claims().project,
        1,
        now - 10,
        now + 300,
        &encoded_policy,
        DecodeLimits::default(),
    )
    .unwrap();
    let mut draft = seed.claims().clone();
    draft.not_before = now - 10;
    draft.policy_digest = policy.descriptor().digest();
    draft.revocation_generation = aos_sandbox_core::Revision::new(1);
    draft.grants = vec![
        Grant::new(
            GrantId::from_bytes([63; 16]),
            ResourceKind::Tree,
            OperationSet::one(Operation::Attach),
            draft.grants[0].selector().clone(),
            false,
        )
        .unwrap(),
    ];
    let capability = CapabilityRecord::issue(draft).unwrap();
    let claims = capability.claims();
    {
        let mut store =
            PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).unwrap();
        store
            .advance_controller_from_trusted_controller(
                [64; 16],
                None,
                PublisherControllerHeadV1 {
                    principal: claims.audience,
                    generation: 1,
                },
            )
            .unwrap();
        store
            .advance_revocation_from_trusted_controller(
                [65; 16],
                None,
                PublisherRevocationHeadV1 {
                    scope: claims.revocation_scope,
                    generation: 1,
                },
            )
            .unwrap();
        store
            .publish_policy_from_trusted_controller([66; 16], None, &policy)
            .unwrap();
    }
    PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default())
        .unwrap()
        .install_from_trusted_controller([67; 16], capability.clone())
        .unwrap();
    (root, journal, capability, policy)
}

#[test]
fn checked_admission_projection_keeps_actual_inputs_and_advances_floor_once() {
    let (_root, mut journal, capability, policy) = fixture();
    let claims = capability.claims();
    let (canonical, fence) = canonical_public_mutation_request_v2(
        PublicApiAuditMethodV1::AttachView,
        ResourceKind::Tree,
        Operation::Attach,
        claims.grants[0].selector().clone(),
        b"synthetic-exact-protobuf-body",
    )
    .unwrap();
    let decoded = DecodedAuthenticatedCliRequestV1::decode_authenticated(&canonical).unwrap();
    let identity =
        AuthenticatedCliIdentityEvidenceV1::from_verified_transport_identity(claims.holder)
            .unwrap();
    let session_bytes = b"synthetic-authenticated-session";
    let session =
        AuthenticatedCliSessionEvidenceV1::from_verified_session(claims.holder, session_bytes)
            .unwrap();
    let channel = AuthenticatedCliChannelEvidenceV1::from_verified_channel(
        claims.holder,
        session_bytes,
        claims.channel_binding,
        &canonical,
        b"synthetic-schema",
    )
    .unwrap();
    let sequence = journal.snapshot_sequence();

    let (checked, decision) =
        CurrentProtectedCliAuthorizationV1::from_current_protected_capability_with_decision(
            &mut journal,
            PublisherAuthorityLimits::default(),
            PublisherPolicyLimits::default(),
            capability.id(),
            claims.project,
            &mut ControllerProtectedClockV1::open_fixed().unwrap(),
            &decoded,
            &identity,
            &channel,
        )
        .unwrap();
    assert_eq!(decision.capability(), &capability);
    assert_eq!(decision.policy(), &policy);
    assert_eq!(
        checked.original_coordinates,
        decision.original_coordinates(checked.original_coordinates.session_commitment)
    );
    assert_eq!(
        checked.authorized_wall_seconds,
        decision.authorized_wall_seconds()
    );
    assert_eq!(decision.time_floor.generation, 1);
    let floor = decision.time_floor;
    let full_revision = [
        claims.id.as_bytes().as_slice(),
        claims.revocation_scope.as_bytes().as_slice(),
        &claims.revocation_generation.get().to_be_bytes(),
        claims.policy_digest.as_bytes().as_slice(),
        &decision.controller.generation.to_be_bytes(),
        &decision.policy.generation().to_be_bytes(),
        &floor.generation.to_be_bytes(),
        floor.clock.provenance().as_bytes().as_slice(),
        floor.clock.host_boot_id().as_slice(),
        &floor.clock.wall_seconds().to_be_bytes(),
        &floor.clock.boottime_nanoseconds().to_be_bytes(),
        floor.digest.as_bytes().as_slice(),
    ]
    .concat();
    assert_eq!(full_revision.len(), 176);
    assert_eq!(
        checked.revision,
        AuthorizationRevisionDigestV1::commit(&full_revision)
    );
    for byte in 24..32 {
        let mut changed = floor;
        let mut digest = *changed.digest.as_bytes();
        digest[byte] ^= 1;
        changed.digest = ObjectDigest::from_bytes(digest);
        assert_ne!(
            protected_authorization_revision(
                &capability,
                decision.controller.generation,
                decision.policy.generation(),
                changed
            ),
            checked.revision,
            "the complete trailing floor digest is committed"
        );
    }

    // One Begin, two Put records and Commit; conversion must not evaluate a
    // second time or re-advance the floor behind the retained projection.
    assert_eq!(journal.snapshot_sequence(), sequence + 4);

    let authenticated =
        DormantAuthenticatedCliRequestV1::bind(decoded, identity, session, channel, checked)
            .unwrap();
    let authorization = authenticated.authorize_public_mutation(fence).unwrap();
    let coordinates = authorization.original_coordinates().unwrap();
    assert_eq!(
        coordinates,
        decision.original_coordinates(coordinates.session_commitment)
    );
    assert_eq!(
        authorization.accepted_wall_seconds(),
        decision.authorized_wall_seconds()
    );
    assert_eq!(
        authorization.policy_generation(),
        decision.policy().generation()
    );
    assert_eq!(journal.snapshot_sequence(), sequence + 4);
    assert_eq!(
        load_protected_time_floor(&journal).unwrap().unwrap().digest,
        decision.time_floor.digest
    );
}

#[test]
fn shared_checked_admission_projection_keeps_holder_key_and_project_checks() {
    let (_root, mut journal, capability, _) = fixture();
    let claims = capability.claims();
    let selector = Selector::Resource {
        resource: ResourceId::from_bytes([3; 16]),
    };
    for (project, holder, key) in [
        (
            ProjectId::from_bytes([68; 16]),
            claims.holder,
            claims.channel_binding,
        ),
        (
            claims.project,
            PrincipalId::from_bytes([69; 16]),
            claims.channel_binding,
        ),
        (claims.project, claims.holder, ChannelBinding::new([70; 32])),
    ] {
        assert!(
            evaluate_current_protected_capability(
                &mut journal,
                PublisherAuthorityLimits::default(),
                PublisherPolicyLimits::default(),
                capability.id(),
                project,
                holder,
                key,
                &mut ControllerProtectedClockV1::open_fixed().unwrap(),
                ResourceKind::Tree,
                Operation::Attach,
                &selector,
            )
            .is_err()
        );
    }
}
