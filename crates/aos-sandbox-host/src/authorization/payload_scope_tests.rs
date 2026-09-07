//! Signed payload-scope authority regressions using the Host broker's test keys.

use super::*;
use aos_proto::aos::sandbox::local::v1::ObservePayloadScopeRequest;
use aos_sandbox_core::{BrokerArgumentCommitment, BrokerVerb};
use aos_sandbox_protocol::payload_scope::{
    ValidatedPayloadScopeRequest, decode_payload_scope_request,
};
use aos_sandbox_protocol::semantics::payload_scope::canonical_payload_scope_semantics_v1;

#[test]
fn mount_scope_requires_distinct_signed_authority_for_the_exact_retained_scope() {
    use aos_proto::aos::sandbox::local::v1::ObserveMountScopeRequest;
    use aos_sandbox_protocol::mount_scope::decode_mount_scope_request;
    use aos_sandbox_protocol::semantics::mount_scope::canonical_mount_scope_semantics_v1;

    let fixture = AuthorityFixture::new();
    let authority = fixture.authority();
    let launch = request(90, 1, 4);
    let (payload_bytes, payload_query) = query_for(&launch);
    let payload_raw = ObservePayloadScopeRequest::decode_from_slice(&payload_bytes).unwrap();

    let mut raw = ObserveMountScopeRequest {
        header: payload_raw.header,
        fence: payload_raw.fence,
        runtime_handle: payload_raw.runtime_handle,
        payload_scope_handle: vec![72; 32],
        ..Default::default()
    };
    raw.header.get_or_insert_default().protocol_minor = 3;
    raw.header.get_or_insert_default().audience = Audience::AUDIENCE_ROOT_MOUNT.into();

    let decode = |raw: &ObserveMountScopeRequest| {
        decode_mount_scope_request(
            &raw.encode_to_vec(),
            PeerCredentials {
                uid: 0,
                gid: 0,
                pid: Some(7),
            },
            PeerPolicy {
                uid: 0,
                gid: Some(0),
                audience: Audience::AUDIENCE_ROOT_MOUNT,
            },
            TEST_BOOTTIME_NANOSECONDS,
        )
        .unwrap()
    };
    let query = decode(&raw);
    let commitment = canonical_mount_scope_semantics_v1(&query)
        .unwrap()
        .commitment();
    let artifacts = scope_artifacts(&fixture, &launch, &payload_query, commitment, 1);
    let (sealed, current) = install_fence(&authority, &launch, &artifacts);

    let admitted = authority
        .admit_mount_scope(&artifacts, &query, &raw.encode_to_vec(), &clock(), &sealed)
        .unwrap();
    assert_eq!(admitted.fence, current);

    let payload_commitment = canonical_payload_scope_semantics_v1(&payload_query)
        .unwrap()
        .commitment();
    let controller_artifacts =
        scope_artifacts(&fixture, &launch, &payload_query, payload_commitment, 1);
    let (controller_fence, _) = install_fence(&authority, &launch, &controller_artifacts);

    assert!(
        authority
            .admit_mount_scope(
                &controller_artifacts,
                &query,
                &raw.encode_to_vec(),
                &clock(),
                &controller_fence,
            )
            .is_err()
    );
    assert!(
        authority
            .admit_payload_scope(
                &artifacts,
                &payload_query,
                &payload_bytes,
                &clock(),
                &sealed,
            )
            .is_err()
    );

    raw.payload_scope_handle[0] ^= 1;
    let replacement = decode(&raw);

    assert!(
        authority
            .admit_mount_scope(
                &artifacts,
                &replacement,
                &raw.encode_to_vec(),
                &clock(),
                &sealed,
            )
            .is_err()
    );
}

fn query_for(launch: &[u8]) -> (Vec<u8>, ValidatedPayloadScopeRequest) {
    let launch = ApplyRuntimeRequest::decode_from_slice(launch).unwrap();
    let mut query = ObservePayloadScopeRequest {
        header: launch.header,
        fence: launch.fence,
        ..Default::default()
    };
    query.header.get_or_insert_default().protocol_minor = 2;
    query.header.get_or_insert_default().request_id = vec![91; 16];
    query
        .header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = 100_000_000_100;
    let fence = query.fence.as_option().unwrap();
    query.runtime_handle = runtime_handle_v1(
        fence.incarnation_id.as_slice().try_into().unwrap(),
        fence.assignment_epoch,
        fence.assignment_digest.as_slice().try_into().unwrap(),
    )
    .to_vec();
    let bytes = query.encode_to_vec();
    let validated =
        decode_payload_scope_request(&bytes, peer(), policy(), TEST_BOOTTIME_NANOSECONDS).unwrap();
    (bytes, validated)
}

/// Signs one immutable assignment plan containing launch and a separate query grant.
fn scope_artifacts(
    fixture: &AuthorityFixture,
    launch_bytes: &[u8],
    query: &ValidatedPayloadScopeRequest,
    query_commitment: BrokerArgumentCommitment,
    lease_generation: u64,
) -> ValidatedUntrustedAuthorizationArtifacts {
    let launch =
        decode_runtime_request(launch_bytes, peer(), policy(), TEST_BOOTTIME_NANOSECONDS).unwrap();
    let launch_semantics =
        crate::authorization::semantics_v1::canonical_host_semantics_v1(&launch).unwrap();
    let scope_semantics = canonical_payload_scope_semantics_v1(query).unwrap();
    let assignment = BrokerAssignment::new(
        SandboxId::from_bytes(*launch.fence().sandbox_id()),
        IncarnationId::from_bytes(*launch.fence().incarnation_id()),
        AssignmentEpoch::new(launch.fence().assignment_epoch()),
        DesiredGeneration::new(launch.fence().desired_generation()),
        ObjectDigest::from_bytes(*launch.fence().assignment_digest()),
    )
    .unwrap();
    let grants = vec![
        BrokerGrant::new(
            launch_semantics.verb(),
            launch_semantics.target(),
            launch_semantics.commitment(),
            8192,
            0,
        )
        .unwrap(),
        BrokerGrant::new(
            BrokerVerb::HostObserve,
            scope_semantics.target(),
            query_commitment,
            8192,
            0,
        )
        .unwrap(),
    ];
    let plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Host,
        ProtocolId::HostBroker,
        ProtocolVersion::new(1, 1),
        assignment,
        TEST_NODE,
        fixture.lease_signer.clone(),
        grants,
        ObjectDigest::from_bytes([48; 32]),
        fixture.revocation_scope,
        100,
        300,
        Vec::new(),
    )
    .unwrap();
    let broker_plan = encode_broker_authorization_plan(&plan);
    let broker_plan_signature = signed_object(
        &broker_plan,
        PortableMediaType::BrokerAuthorizationPlan,
        fixture.plan_scope,
        fixture.plan_signer.clone(),
        SignaturePurpose::BrokerAuthorization,
        &fixture.plan_policy_descriptor,
        &fixture.plan_key,
    );
    let lease = OwnershipLease::new(
        LeaseAssignment::new(
            assignment.sandbox(),
            assignment.incarnation(),
            assignment.epoch(),
            assignment.digest(),
        )
        .unwrap(),
        TEST_NODE,
        lease_generation,
        100,
        200,
        10,
        [u8::try_from(lease_generation).unwrap(); 16],
    )
    .unwrap();
    let ownership_lease = encode_ownership_lease(&lease);
    // The lease profile requires the signature interval to equal its payload
    // interval, not merely contain it. The shared helper fixes expiry at 300.
    let statement = SignatureStatement::new(
        descriptor_for_bytes(
            MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned()).unwrap(),
            &ownership_lease,
        ),
        fixture.lease_scope,
        fixture.lease_signer.clone(),
        SignaturePurpose::OwnershipLease,
        100,
        Some(200),
        fixture.lease_policy_descriptor.clone(),
    )
    .unwrap();
    let ownership_lease_signature =
        encode_signature(&sign_statement(statement, &fixture.lease_key).unwrap());
    validated_artifacts(BrokerAuthorizationArtifactsV1 {
        broker_plan,
        broker_plan_signature,
        ownership_lease,
        ownership_lease_signature,
        ..Default::default()
    })
}

fn install_fence(
    authority: &HostAuthorityV1,
    launch_bytes: &[u8],
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
) -> (Vec<u8>, aos_sandbox_broker::BrokerAuthorizationFenceV1) {
    let launch =
        decode_runtime_request(launch_bytes, peer(), policy(), TEST_BOOTTIME_NANOSECONDS).unwrap();
    let admitted = authority
        .admit(
            artifacts,
            &launch,
            launch_bytes,
            ProtocolVersion::new(1, 1),
            &clock(),
            None,
        )
        .unwrap();
    let sealed = authority
        .seal_fence(launch.fence().sandbox_id(), &admitted.fence)
        .unwrap();
    (sealed, admitted.fence)
}

#[test]
fn payload_scope_requires_its_exact_preinstalled_signed_grant() {
    let fixture = AuthorityFixture::new();
    let authority = fixture.authority();
    let launch = request(90, 1, 4);
    let (query_bytes, query) = query_for(&launch);
    let commitment = canonical_payload_scope_semantics_v1(&query)
        .unwrap()
        .commitment();
    let artifacts = scope_artifacts(&fixture, &launch, &query, commitment, 1);
    let (sealed, current) = install_fence(&authority, &launch, &artifacts);
    let admitted = authority
        .admit_payload_scope(&artifacts, &query, &query_bytes, &clock(), &sealed)
        .unwrap();
    assert_eq!(admitted.fence, current);

    // A grant sharing the HostObserve verb and runtime target still cannot
    // substitute an ordinary observation's distinct argument meaning.
    let ordinary = scope_artifacts(
        &fixture,
        &launch,
        &query,
        BrokerArgumentCommitment::for_canonical_bytes(b"ordinary runtime observation"),
        1,
    );
    let (ordinary_sealed, _) = install_fence(&authority, &launch, &ordinary);
    assert!(
        authority
            .admit_payload_scope(&ordinary, &query, &query_bytes, &clock(), &ordinary_sealed)
            .is_err()
    );
    // Installing the query grant later silently changes the same-assignment
    // plan digest, which cannot be adopted through this observation path.
    assert!(
        authority
            .admit_payload_scope(&artifacts, &query, &query_bytes, &clock(), &ordinary_sealed)
            .is_err()
    );
}

#[test]
fn payload_scope_checks_live_ownership_and_exact_assignment() {
    let fixture = AuthorityFixture::new();
    let authority = fixture.authority();
    let launch = request(90, 1, 4);
    let (query_bytes, query) = query_for(&launch);
    let commitment = canonical_payload_scope_semantics_v1(&query)
        .unwrap()
        .commitment();
    let artifacts = scope_artifacts(&fixture, &launch, &query, commitment, 1);
    let (sealed, current) = install_fence(&authority, &launch, &artifacts);
    assert!(
        authority
            .admit_payload_scope(
                &artifacts,
                &query,
                &query_bytes,
                &clock_at(200, 50_000_000_100),
                &sealed
            )
            .is_err()
    );
    let mut changed = ObservePayloadScopeRequest::decode_from_slice(&query_bytes).unwrap();
    changed.fence.get_or_insert_default().desired_generation += 1;
    let changed_bytes = changed.encode_to_vec();
    let changed =
        decode_payload_scope_request(&changed_bytes, peer(), policy(), TEST_BOOTTIME_NANOSECONDS)
            .unwrap();
    assert!(
        authority
            .admit_payload_scope(&artifacts, &changed, &changed_bytes, &clock(), &sealed)
            .is_err()
    );

    // Shared admission can propose a valid renewal. FD release must separately
    // demand equality with the installed durable fence; this is not installation.
    let renewal = scope_artifacts(&fixture, &launch, &query, commitment, 2);
    let proposed = authority
        .admit_payload_scope(&renewal, &query, &query_bytes, &clock(), &sealed)
        .unwrap();
    assert_ne!(proposed.fence, current);
    assert_eq!(
        authority
            .open_fence(query.fence().sandbox_id(), &sealed)
            .unwrap(),
        current
    );
}

#[tokio::test]
async fn payload_scope_query_rejects_uninstalled_renewal_without_mutating_state() {
    let fixture = AuthorityFixture::new();
    let store = MemoryStore::default();
    let worker = FakeWorker::default();
    let calls = worker.calls.clone();
    let mut broker = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker,
        Some(nspawn()),
        fixture.authority(),
    )
    .unwrap();
    let launch = request(90, 1, 4);
    let (query_bytes, query) = query_for(&launch);
    let commitment = canonical_payload_scope_semantics_v1(&query)
        .unwrap()
        .commitment();
    let original = scope_artifacts(&fixture, &launch, &query, commitment, 1);
    broker
        .apply_runtime(
            &launch,
            &original,
            ProtocolVersion::new(1, 1),
            peer(),
            policy(),
            || Ok(clock()),
        )
        .await
        .unwrap();
    let before = store.load().unwrap();
    let renewal = scope_artifacts(&fixture, &launch, &query, commitment, 2);
    let result = broker
        .prepare_payload_scope(&renewal, &query, &query_bytes, &mut || Ok(clock()))
        .await;
    assert!(matches!(
        result,
        Err(HostError::Fence(
            "payload query does not match installed authority"
        ))
    ));
    drop(result);
    assert_eq!(store.load().unwrap(), before);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // An exact matching plan and lease still cannot reconstruct missing live
    // payload pins from the completed launch receipt held by this fake worker.
    assert!(matches!(
        broker
            .prepare_payload_scope(&original, &query, &query_bytes, &mut || Ok(clock()))
            .await,
        Err(HostError::UnknownHandle)
    ));
    assert_eq!(store.load().unwrap(), before);
}
