//! Pure signed canonical Mount graph fixtures, without IO or custody constructors.

use super::protocol;
use super::protocol::mount_source_acquisition_state::checkpoint::validate_session_checkpoint;
use super::protocol::mount_source_acquisition_state::format::execution_digest;
use super::protocol::mount_source_acquisition_state::*;
use super::protocol::{
    PeerCredentials, PeerPolicy, ValidatedAcquireMountSourceRequest,
    decode_historical_acquire_mount_source_request, decode_mount_request, semantics,
};
use aos_proto::aos::sandbox::local::v1::{
    AcquireMountSourceRequest, ApplyMountRequest, Audience, MountAction, MountSourceConsistency,
};
use aos_sandbox_core::{
    MediaType, ObjectDescriptor, ObjectDigest, encode_view_source, model::ViewSource,
};
use aos_sandbox_source_provider_protocol::{
    AcquireSourceRequestV1, NormalizedAcquisitionIntentV2, ProviderCatalogFloorV1,
    SourceProviderAuthorityV1, SourceProviderHelloV1, SourceProviderKeyUsageV1,
    SourceProviderMethod, SourceProviderPeerRole, SourceProviderSigningKeyV1, SourceUseV1,
    digest_logical_binding_bytes, digest_signed_hello, digest_signed_request,
    encode_acquire_request, sign_hello, sign_request, source_acquisition_id_v2,
    source_provider_session_binding_v1, source_provider_signer_set_commitment_v1,
};
use buffa::Message as _;
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;

const HOLDER: [u8; 16] = [1; 16];
const PROVIDER: [u8; 16] = [2; 16];
const BOOT: [u8; 16] = [3; 16];
const PROCESS: [u8; 16] = [4; 16];
const NODE: [u8; 16] = [5; 16];
const ROUTE: [u8; 16] = [6; 16];

/// Derives signed original Pending2 and its exact Acquisition/Head successors.
pub(super) fn pending_original_rows(
    rows: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> BTreeMap<Vec<u8>, Vec<u8>> {
    use aos_sandbox_source_provider_protocol::{
        AcquireSourceResponseV1, SourceProviderResponseStatusV1, SourceProviderStatus,
        empty_descriptor_set_commitment_v1, encode_acquire_response, response_result_digest_v1,
        sign_response_status,
    };
    use sha2::{Digest as _, Sha256};

    let state = validate_mount_source_state_graph_v2(
        rows.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap();
    let mut attempt = state
        .provider_attempts
        .values()
        .find(|attempt| attempt.method == ProviderMethodV2::Acquire && attempt.attempt_number == 1)
        .unwrap()
        .clone();
    let session = &state.provider_sessions[&attempt.session_id];
    let key = SigningKey::from_bytes(&[14; 32]);
    let result_digest = response_result_digest_v1(
        SourceProviderMethod::Acquire,
        SourceProviderStatus::Pending,
        None,
    );
    let status = sign_response_status(
        SourceProviderResponseStatusV1::new(
            SourceProviderMethod::Acquire,
            attempt.request_id,
            ObjectDigest::from_bytes(attempt.signed_request_digest),
            SourceProviderStatus::Pending,
            session.provider_process_instance,
            ObjectDigest::from_bytes(session.session_binding),
            attempt.request_sequence,
            result_digest,
            empty_descriptor_set_commitment_v1(),
        )
        .unwrap(),
        signer(PROVIDER, [24; 16], SourceProviderKeyUsageV1::ProviderOutcome, &key),
        &key,
    )
    .unwrap();
    let response = encode_acquire_response(&AcquireSourceResponseV1::new(status.clone(), None).unwrap());
    let mut anchor = OutcomeVerificationAnchorV2 {
        verification_started_seconds: 110,
        verification_completed_seconds: 111,
        kernel_boot_id: session.kernel_boot_id,
        trusted_clock_evidence_digest: session.trusted_clock_evidence_digest,
        anchor_digest: [0; 32],
    };
    anchor.anchor_digest = outcome_verification_anchor_digest_v2(
        &anchor,
        session.session_id,
        attempt.attempt_id,
        attempt.request_sequence,
        attempt.request_sequence,
        Sha256::digest(response).into(),
    );

    attempt.revision = 2;
    attempt.state = ProviderAttemptStateV2::DispositionConsumed {
        response_sequence: attempt.request_sequence,
        verification_anchor: anchor,
        status: ProviderStatusV2::Pending,
        signed_status_digest: Sha256::digest(status.to_canonical_bytes()).into(),
        signed_status: status.to_canonical_bytes(),
        signed_result: Vec::new(),
        signed_result_digest: *result_digest.as_bytes(),
    };
    let StoredRecordV2::ProviderQueryAttempt { value: attempt } =
        seal_record(StoredRecordV2::ProviderQueryAttempt { value: attempt }).unwrap()
    else {
        panic!("sealed Pending attempt");
    };
    let reference = RecordRefV2 {
        id: attempt.attempt_id,
        revision: 2,
        record_digest: attempt.record_digest,
    };
    let mut row = state.acquisitions[&attempt.owner.owner_id()].clone();
    row.revision += 1;
    row.acquire_lineage.root = reference;
    row.acquire_lineage.tail = reference;
    let mut head = state.provider_heads[&(
        attempt.scope.holder_authority_id,
        attempt.scope.provider_authority_id,
    )]
        .clone();
    head.revision += 1;
    head.next_response_sequence += 1;
    head.pending_attempt = None;

    let mut pending = rows.clone();
    for record in [
        StoredRecordV2::ProviderQueryAttempt { value: attempt },
        seal_record(StoredRecordV2::Acquisition { value: row }).unwrap(),
        seal_record(StoredRecordV2::ProviderHead { value: head }).unwrap(),
    ] {
        let (key, value) = encode_mount_source_state_record_v2(&record).unwrap();
        pending.insert(key, value);
    }
    pending
}

pub(super) fn signer(
    authority: [u8; 16],
    key_id: [u8; 16],
    usage: SourceProviderKeyUsageV1,
    signing_key: &SigningKey,
) -> SourceProviderSigningKeyV1 {
    SourceProviderSigningKeyV1::for_signing_key(
        authority,
        1,
        ObjectDigest::from_bytes(if authority == HOLDER {
            [7; 32]
        } else {
            [8; 32]
        }),
        key_id,
        1,
        usage,
        signing_key,
    )
    .expect("valid fixture signer")
}

fn signer_snapshot(
    role: SignerRoleV2,
    signer: &SourceProviderSigningKeyV1,
    key: &SigningKey,
) -> SignerSnapshotV2 {
    SignerSnapshotV2 {
        role,
        authority_id: signer.authority_id(),
        authority_generation: signer.authority_generation(),
        authority_digest: *signer.authority_digest().as_bytes(),
        key_id: signer.key_id(),
        key_generation: signer.key_generation(),
        public_key: *key.verifying_key().as_bytes(),
        public_key_fingerprint: *signer.public_key_digest().as_bytes(),
        authority_valid_from_seconds: 1,
        authority_valid_until_seconds: 1000,
        key_valid_from_seconds: 1,
        key_valid_until_seconds: 1000,
        authority_state: AuthorityAdmissionStateV2::Trusted,
        key_state: KeyAdmissionStateV2::Eligible,
        superseded_by_key_generation: 0,
    }
}

fn trust(authority_id: [u8; 16], authority_digest: [u8; 32]) -> AuthorityTrustSnapshotV2 {
    AuthorityTrustSnapshotV2 {
        authority_id,
        authority_generation: 1,
        authority_digest,
        valid_from_seconds: 1,
        valid_until_seconds: 1000,
        state: AuthorityAdmissionStateV2::Trusted,
    }
}

pub(super) fn signed_session(root_instance: [u8; 16], nonce: u8) -> SourceProviderSessionV2 {
    let root_hello_key = SigningKey::from_bytes(&[11; 32]);
    let root_traffic_key = SigningKey::from_bytes(&[12; 32]);
    let provider_hello_key = SigningKey::from_bytes(&[13; 32]);
    let provider_traffic_key = SigningKey::from_bytes(&[14; 32]);
    let root_hello_signer = signer(
        HOLDER,
        [21; 16],
        SourceProviderKeyUsageV1::RootMountHello,
        &root_hello_key,
    );
    let root_traffic_signer = signer(
        HOLDER,
        [22; 16],
        SourceProviderKeyUsageV1::RootMountRecord,
        &root_traffic_key,
    );
    let provider_hello_signer = signer(
        PROVIDER,
        [23; 16],
        SourceProviderKeyUsageV1::ProviderHello,
        &provider_hello_key,
    );
    let provider_traffic_signer = signer(
        PROVIDER,
        [24; 16],
        SourceProviderKeyUsageV1::ProviderOutcome,
        &provider_traffic_key,
    );
    let root_hello = SourceProviderHelloV1::new(
        SourceProviderPeerRole::RootMount,
        [nonce; 32],
        root_instance,
        BOOT,
        root_traffic_signer.clone(),
        provider_traffic_signer.clone(),
        ROUTE,
        1,
        ObjectDigest::from_bytes([9; 32]),
        None,
        0b1111,
        true,
        true,
    )
    .expect("valid Root Mount hello");
    let signed_root = sign_hello(root_hello, root_hello_signer.clone(), &root_hello_key)
        .expect("signed Root Mount hello");
    let provider_hello = SourceProviderHelloV1::new(
        SourceProviderPeerRole::Provider,
        [nonce.wrapping_add(1); 32],
        PROCESS,
        BOOT,
        provider_traffic_signer.clone(),
        root_traffic_signer.clone(),
        ROUTE,
        1,
        ObjectDigest::from_bytes([9; 32]),
        Some(digest_signed_hello(&signed_root)),
        0b1111,
        true,
        true,
    )
    .expect("valid Provider hello");
    let signed_provider = sign_hello(
        provider_hello,
        provider_hello_signer.clone(),
        &provider_hello_key,
    )
    .expect("signed Provider hello");

    let mut session = SourceProviderSessionV2 {
        session_id: [0; 32],
        revision: 1,
        predecessor_session_id: None,
        barrier_idle_replacement: None,
        scope: ProviderScopeV2 {
            holder_authority_id: HOLDER,
            provider_authority_id: PROVIDER,
            route_id: ROUTE,
            resource_namespace_digest: [10; 32],
        },
        node_id: NODE,
        kernel_boot_id: BOOT,
        root_mount_authority_generation: 1,
        root_mount_authority_digest: [7; 32],
        provider_authority_generation: 1,
        provider_authority_digest: [8; 32],
        route_generation: 1,
        route_digest: [9; 32],
        negotiated_capabilities: NegotiatedCapabilitiesV2 {
            proof_class_capabilities: 0b1111,
            supports_recursive: true,
            supports_kernel_coupled: true,
            signed_lease_receipts: true,
            separated_signing_roles: true,
        },
        signed_root_mount_hello: signed_root.to_canonical_bytes(),
        signed_root_mount_hello_digest: *digest_signed_hello(&signed_root).as_bytes(),
        signed_provider_hello: signed_provider.to_canonical_bytes(),
        signed_provider_hello_digest: *digest_signed_hello(&signed_provider).as_bytes(),
        session_binding: *source_provider_session_binding_v1(&signed_root, &signed_provider)
            .as_bytes(),
        signer_set_commitment: *source_provider_signer_set_commitment_v1(
            &root_hello_signer,
            &root_traffic_signer,
            &provider_hello_signer,
            &provider_traffic_signer,
        )
        .as_bytes(),
        authenticated_at_seconds: 100,
        current_valid_until_seconds: 1000,
        trusted_clock_evidence_digest: [15; 32],
        trust_generation: 1,
        trust_digest: [16; 32],
        revocation_generation: 1,
        revocation_digest: [17; 32],
        authority_trust: [trust(HOLDER, [7; 32]), trust(PROVIDER, [8; 32])],
        signers: [
            signer_snapshot(
                SignerRoleV2::RootMountHello,
                &root_hello_signer,
                &root_hello_key,
            ),
            signer_snapshot(
                SignerRoleV2::RootMountRecord,
                &root_traffic_signer,
                &root_traffic_key,
            ),
            signer_snapshot(
                SignerRoleV2::ProviderHello,
                &provider_hello_signer,
                &provider_hello_key,
            ),
            signer_snapshot(
                SignerRoleV2::ProviderOutcome,
                &provider_traffic_signer,
                &provider_traffic_key,
            ),
        ],
        root_mount_process_instance: root_instance,
        actual_writer_root_mount_process: ActualWriterRootMountSnapshotV2 {
            uid: 0,
            gid: 0,
            tgid: 100,
            start_time_ticks: 200,
            cgroup_digest: [18; 32],
        },
        provider_process_instance: PROCESS,
        provider_execution: ProviderExecutionSnapshotV2 {
            pid: 300,
            tgid: 300,
            ppid: 1,
            start_time_ticks: 400,
            cgroup_id: 500,
            real_uid: 0,
            effective_uid: 0,
            saved_uid: 0,
            filesystem_uid: 0,
            real_gid: 0,
            effective_gid: 0,
            saved_gid: 0,
            filesystem_gid: 0,
            process_execution_digest: [0; 32],
        },
        record_digest: [0; 32],
    };
    session.provider_execution.process_execution_digest =
        execution_digest(&session).expect("valid execution digest");
    session.session_id = session_id(&session);
    let StoredRecordV2::ProviderSession { value: session } =
        seal_record(StoredRecordV2::ProviderSession { value: session })
            .expect("sealed signed session")
    else {
        panic!("signed fixture changed record kind");
    };
    validate_session_checkpoint(&session).expect("signed session checkpoint");
    session
}

pub(super) fn mount_acquire_request() -> (Vec<u8>, ValidatedAcquireMountSourceRequest) {
    let media_type = MediaType::new("application/vnd.aos.sandbox.tree.v1+cbor".to_owned())
        .expect("valid tree media type");
    let tree = ObjectDescriptor::new(media_type, ObjectDigest::from_bytes([42; 32]), 1);
    let mut mount = ApplyMountRequest::default();
    let header = mount.header.get_or_insert_default();
    header.protocol_major = 2;
    header.request_id = vec![51; 16];
    header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
    header.deadline_boottime_nanoseconds = 101;
    header.maximum_response_bytes = 4096;
    let fence = mount.fence.get_or_insert_default();
    fence.sandbox_id = vec![52; 16];
    fence.incarnation_id = vec![53; 16];
    fence.assignment_epoch = 1;
    fence.desired_generation = 1;
    fence.assignment_digest = vec![54; 32];
    mount.action = MountAction::MOUNT_ACTION_CREATE_DETACHED.into();
    mount.attachment_id = vec![55; 16];
    mount.destination_slot_id = vec![56; 16];
    mount.source_generation = 1;
    mount.namespace_generation = 1;
    mount.desired_attachment_generation = 1;
    mount.resource_attachment_generation = 1;
    mount.source_view_id = vec![57; 16];
    mount.source_consistency =
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION.into();
    mount.source_handle = encode_view_source(&ViewSource::ImmutableTree { tree });
    mount.attachment_lease_id = vec![58; 16];
    mount.attachment_lease_issued_seconds = 10;
    mount.attachment_lease_expires_seconds = 20;
    let attributes = mount.attributes.get_or_insert_default();
    attributes.read_only = true;
    attributes.no_suid = true;
    attributes.no_device = true;
    attributes.recursive = true;
    let descriptor = mount.view_revision.get_or_insert_default();
    descriptor.media_type = "application/vnd.aos.sandbox.view.v1+cbor".to_owned();
    descriptor.sha256 = vec![59; 32];
    descriptor.encoded_size = 1;

    let peer = PeerCredentials {
        uid: 100,
        gid: 200,
        pid: Some(300),
    };
    let policy = PeerPolicy {
        uid: 100,
        gid: Some(200),
        audience: Audience::AUDIENCE_NODE_CONTROLLER,
    };
    let validated = decode_mount_request(&mount.encode_to_vec(), peer, policy, 100)
        .expect("valid Mount Create");
    let template = semantics::canonical_precatalog_mount_create_template_v1(&validated, &[])
        .expect("valid precatalog semantics");
    let binding = validated
        .source_binding()
        .expect("Mount Create source binding");
    let binding_bytes = binding.canonical_bytes();
    let template_bytes = template.canonical_bytes().to_vec();
    let acquire = AcquireMountSourceRequest {
        header: mount.header,
        fence: mount.fence,
        prospective_mount_template_digest:
            aos_sandbox_source_provider_protocol::prospective_mount_apply_template_digest_v1(
                &template_bytes,
            )
            .expect("template digest")
            .as_bytes()
            .to_vec(),
        prospective_mount_template: template_bytes,
        source_binding_digest: aos_sandbox_source_provider_protocol::digest_logical_binding_bytes(
            &binding_bytes,
        )
        .as_bytes()
        .to_vec(),
        source_binding: binding_bytes,
        requested_lease_seconds: 60,
        requested_maximum_submounts: 0,
        ..Default::default()
    };
    let bytes = acquire.encode_to_vec();
    let decoded = decode_historical_acquire_mount_source_request(&bytes)
        .expect("valid historical Acquire Mount request");
    (bytes, decoded.request().clone())
}

pub(super) fn initial_signed_graph_with_catalog(
    session: SourceProviderSessionV2,
    provider_deadline_seconds: i64,
    catalog_digest: [u8; 32],
    catalog_head_commitment: [u8; 32],
    native_catalog: Option<aos_sandbox_source_provider_protocol::NativeAcquireCatalogBindingV3>,
) -> Vec<StoredRecordV2> {
    let (mount_bytes, mount) = mount_acquire_request();
    let provider_acquisition = ProviderAcquisitionIdentityV2 {
        holder_authority_id: session.scope.holder_authority_id,
        holder_authority_generation: session.root_mount_authority_generation,
        holder_authority_digest: session.root_mount_authority_digest,
        acquisition_sequence: 1,
        acquisition_id: *source_acquisition_id_v2(
            session.scope.holder_authority_id,
            session.root_mount_authority_generation,
            ObjectDigest::from_bytes(session.root_mount_authority_digest),
            1,
        )
        .as_bytes(),
    };
    let intent = ProviderIntentV2::Acquire {
        value: acquire_intent(
            session.scope,
            &mount,
            mount_bytes.clone(),
            [60; 32],
            [61; 32],
        ),
    };
    let immutable_intent_digest = intent_digest(&intent).expect("Acquire intent digest");
    let mut attempt = SourceProviderQueryAttemptV2 {
        attempt_id: [0; 32],
        revision: 1,
        scope: session.scope,
        method: ProviderMethodV2::Acquire,
        owner: ProviderQueryOwnerV2::Acquire {
            acquisition_id: *mount.acquisition_id().as_bytes(),
        },
        intent,
        provider_acquisition: Some(provider_acquisition),
        immutable_intent_digest,
        lineage_root_attempt_id: [0; 32],
        previous_attempt_id: None,
        attempt_number: 1,
        session_id: session.session_id,
        session_record_digest: session.record_digest,
        signer_set_commitment: session.signer_set_commitment,
        trust_digest: session.trust_digest,
        revocation_digest: session.revocation_digest,
        route_digest: session.route_digest,
        process_execution_digest: session.provider_execution.process_execution_digest,
        normalized_acquire_intent: None,
        acquire_verification_floor: None,
        inventory_correlations: None,
        request_id: [0; 16],
        request_sequence: 1,
        signed_request: Vec::new(),
        signed_request_digest: [0; 32],
        owner_predecessor_revision: 0,
        owner_predecessor_digest: [0; 32],
        owner_predecessor: None,
        state: ProviderAttemptStateV2::Reserved,
        record_digest: [0; 32],
    };
    attempt.attempt_id = attempt_id(&attempt);
    attempt.lineage_root_attempt_id = attempt.attempt_id;
    attempt.request_id = request_id(attempt.attempt_id);

    let binding = mount.source_binding().canonical_bytes();
    let request = AcquireSourceRequestV1::new_v2(
        ObjectDigest::from_bytes(session.session_binding),
        1,
        attempt.request_id,
        1,
        mount.prospective_mount_template().to_vec(),
        mount.prospective_mount_template_digest(),
        SourceUseV1::MountCreate,
        session.node_id,
        session.kernel_boot_id,
        session.scope.holder_authority_id,
        session.root_mount_authority_generation,
        ObjectDigest::from_bytes(session.root_mount_authority_digest),
        binding.clone(),
        aos_sandbox_source_provider_protocol::digest_logical_binding_bytes(&binding),
        provider_deadline_seconds,
        mount.requested_lease_seconds(),
        ObjectDigest::from_bytes(session.revocation_digest),
        mount.recursive(),
        mount.requested_maximum_submounts(),
        mount.kernel_coupled(),
    )
    .expect("valid provider Acquire request");
    let request = match native_catalog {
        Some(catalog) => {
            AcquireSourceRequestV1::new_native_v3(request, catalog).expect("native fixture request")
        }
        None => request,
    };
    let normalized = NormalizedAcquisitionIntentV2::from_original_acquire_request(
        &request,
        SourceProviderAuthorityV1::new(
            session.scope.provider_authority_id,
            session.provider_authority_generation,
            ObjectDigest::from_bytes(session.provider_authority_digest),
        )
        .expect("Provider authority"),
        SourceProviderAuthorityV1::new(
            session.scope.holder_authority_id,
            session.root_mount_authority_generation,
            ObjectDigest::from_bytes(session.root_mount_authority_digest),
        )
        .expect("holder authority"),
        session.node_id,
        session.kernel_boot_id,
        session.scope.route_id,
        session.route_generation,
        ObjectDigest::from_bytes(session.route_digest),
        ObjectDigest::from_bytes(session.scope.resource_namespace_digest),
        session.revocation_generation,
        ObjectDigest::from_bytes(session.revocation_digest),
    )
    .expect("normalized provider Acquire");
    attempt.normalized_acquire_intent = Some(AttemptNormalizedAcquireV2 {
        bytes: normalized.to_canonical_bytes(),
        digest: *normalized.digest().as_bytes(),
        maximum_lease_expiry_seconds: provider_deadline_seconds,
    });
    let catalog = ProviderCatalogFloorV1::new(
        session.scope.provider_authority_id,
        ObjectDigest::from_bytes(session.scope.resource_namespace_digest),
        1,
        ObjectDigest::from_bytes(catalog_digest),
    )
    .expect("provider catalog floor");
    attempt.acquire_verification_floor = Some(acquire_verification_floor_v2(
        &catalog,
        None,
        Some(catalog_head_commitment),
    ));
    let request_key = SigningKey::from_bytes(&[12; 32]);
    let signed_request = sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(&request),
        signer(
            HOLDER,
            [22; 16],
            SourceProviderKeyUsageV1::RootMountRecord,
            &request_key,
        ),
        &request_key,
    )
    .expect("signed provider Acquire request");
    attempt.signed_request_digest = *digest_signed_request(&signed_request).as_bytes();
    attempt.signed_request = signed_request.to_canonical_bytes();
    let attempt = sealed_attempt(attempt).expect("sealed Acquire attempt");
    let attempt_ref = RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    };
    let row = sealed_row(initial_row(
        &mount,
        mount_bytes,
        [60; 32],
        [61; 32],
        provider_acquisition,
        session.scope,
        immutable_intent_digest,
        attempt_ref,
    ))
    .expect("sealed initial acquisition");
    let rows = BTreeMap::from([(row.acquisition_id, row.clone())]);
    let head = sealed_head(
        initial_provider_head(&session, &rows, attempt_ref).expect("initial provider head"),
    )
    .expect("sealed initial provider head");
    let StoredRecordV2::HolderSequence { value: holder } =
        seal_record(StoredRecordV2::HolderSequence {
            value: HolderSequenceV2 {
                revision: 1,
                holder_authority_id: session.scope.holder_authority_id,
                last_allocated_acquisition_sequence: 1,
                next_acquisition_sequence: 2,
                record_digest: [0; 32],
            },
        })
        .expect("sealed holder sequence")
    else {
        panic!("holder sequence fixture changed kind");
    };

    vec![
        StoredRecordV2::ProviderSession { value: session },
        StoredRecordV2::ProviderQueryAttempt { value: attempt },
        StoredRecordV2::Acquisition { value: row },
        StoredRecordV2::ProviderHead { value: head },
        StoredRecordV2::HolderSequence { value: holder },
    ]
}

fn acquire_intent(
    scope: ProviderScopeV2,
    request: &protocol::ValidatedAcquireMountSourceRequest,
    mount_request: Vec<u8>,
    mount_plan_digest: [u8; 32],
    ownership_lease_digest: [u8; 32],
) -> AcquireIntentV2 {
    let source_binding = request.source_binding().canonical_bytes();
    AcquireIntentV2 {
        scope,
        acquisition_id: *request.acquisition_id().as_bytes(),
        mount_request,
        mount_request_digest: *request.request_digest().as_bytes(),
        assignment: assignment(request),
        mount_plan_digest,
        ownership_lease_digest,
        prospective_mount_template: request.prospective_mount_template().to_vec(),
        prospective_mount_template_digest: *request.prospective_mount_template_digest().as_bytes(),
        source_binding_digest: *digest_logical_binding_bytes(&source_binding).as_bytes(),
        source_binding,
        requested_lease_seconds: request.requested_lease_seconds(),
        requested_maximum_submounts: request.requested_maximum_submounts(),
        recursive: request.recursive(),
        kernel_coupled: request.kernel_coupled(),
    }
}

fn assignment(request: &protocol::ValidatedAcquireMountSourceRequest) -> AssignmentV2 {
    AssignmentV2 {
        sandbox_id: *request.fence().sandbox_id(),
        incarnation_id: *request.fence().incarnation_id(),
        assignment_epoch: request.fence().assignment_epoch(),
        desired_generation: request.fence().desired_generation(),
        assignment_digest: *request.fence().assignment_digest(),
        namespace_generation: request.prospective_namespace_generation(),
    }
}

#[allow(clippy::too_many_arguments)]
fn initial_row(
    request: &protocol::ValidatedAcquireMountSourceRequest,
    mount_request: Vec<u8>,
    mount_plan_digest: [u8; 32],
    ownership_lease_digest: [u8; 32],
    provider_acquisition: ProviderAcquisitionIdentityV2,
    scope: ProviderScopeV2,
    acquire_intent_digest: [u8; 32],
    attempt: RecordRefV2,
) -> SourceAcquisitionRowV2 {
    let source_binding = request.source_binding().canonical_bytes();
    SourceAcquisitionRowV2 {
        acquisition_id: *request.acquisition_id().as_bytes(),
        provider_acquisition,
        revision: 1,
        phase: SourceAcquisitionPhaseV2::PendingQuery,
        scope,
        acquire: MountOperationV2 {
            operation_id: *request.header().request_id(),
            request_digest: *request.request_digest().as_bytes(),
        },
        mount_acquire_request: mount_request,
        acquire_intent_digest,
        acquire_lineage: QueryLineageV2 {
            root: attempt,
            tail: attempt,
            next_attempt_number: 2,
        },
        acquire_terminal_attempt: None,
        release: None,
        mount_release_request: None,
        release_authority: None,
        release_from_phase: None,
        release_intent_digest: None,
        release_lineage: None,
        release_terminal_attempt: None,
        release_inventory_fence: None,
        assignment: assignment(request),
        prospective_mount_template: request.prospective_mount_template().to_vec(),
        prospective_mount_template_digest: *request.prospective_mount_template_digest().as_bytes(),
        source_binding_digest: *digest_logical_binding_bytes(&source_binding).as_bytes(),
        source_binding,
        mount_plan_digest,
        ownership_lease_digest,
        evidence: None,
        manager_custody: None,
        manager_custody_loss: None,
        descriptor_custody_digest: None,
        positive_custody_digest: None,
        consumption: None,
        release_proof: None,
        negative_custody_digest: None,
        faulted_from: None,
        fault_digest: None,
        retained_faulted_from: None,
        retained_fault_digest: None,
        recovery: AcquisitionRecoveryV2::Ready,
        record_digest: [0; 32],
    }
}

pub(super) fn initial_provider_head(
    session: &SourceProviderSessionV2,
    rows: &std::collections::BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
    pending_attempt: RecordRefV2,
) -> Result<SourceProviderHeadV2> {
    let projection =
        projection_from_entries(session.scope, 1, &projection_entries(session.scope, rows))?;
    Ok(SourceProviderHeadV2 {
        revision: 1,
        scope: session.scope,
        holder_authority_generation: session.root_mount_authority_generation,
        holder_authority_digest: session.root_mount_authority_digest,
        provider_authority_generation: session.provider_authority_generation,
        provider_authority_digest: session.provider_authority_digest,
        current_session_id: session.session_id,
        current_session_record_digest: session.record_digest,
        next_request_sequence: 2,
        next_response_sequence: 1,
        pending_attempt: Some(pending_attempt),
        inventory_observation_ordinal: 0,
        inventory_floor: None,
        last_inventory_attempt: None,
        current_projection_epoch: projection.epoch,
        current_projection_digest: projection.digest,
        last_reconciliation: None,
        recovery_barrier: None,
        record_digest: [0; 32],
    })
}

fn sealed_attempt(value: SourceProviderQueryAttemptV2) -> Result<SourceProviderQueryAttemptV2> {
    let StoredRecordV2::ProviderQueryAttempt { value } =
        seal_record(StoredRecordV2::ProviderQueryAttempt { value })?
    else {
        panic!("fixture attempt variant");
    };
    Ok(value)
}

fn sealed_row(value: SourceAcquisitionRowV2) -> Result<SourceAcquisitionRowV2> {
    let StoredRecordV2::Acquisition { value } = seal_record(StoredRecordV2::Acquisition { value })?
    else {
        panic!("fixture row variant");
    };
    Ok(value)
}

fn sealed_head(value: SourceProviderHeadV2) -> Result<SourceProviderHeadV2> {
    let StoredRecordV2::ProviderHead { value } =
        seal_record(StoredRecordV2::ProviderHead { value })?
    else {
        panic!("fixture head variant");
    };
    Ok(value)
}
