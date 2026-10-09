//! Signed SourceProvider session fixture for protected native-recovery replay.
//!
//! The fixed owner additionally requires installed root-owned custody. That
//! move-only CAS is VM-gated; these tests exercise actual signatures, typed
//! state validation, and protected journal persistence without minting test
//! owner authority.

#[path = "native_recovery_fixture/installed_vm.rs"]
mod installed_vm;

#[path = "native_recovery_fixture/disposition.rs"]
mod disposition;

use aos_proto::aos::sandbox::local::v1::{
    AcquireMountSourceRequest, ApplyMountRequest, Audience, MountAction, MountSourceConsistency,
};
use aos_sandbox::journal::{
    Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_core::{MediaType, ObjectDescriptor, encode_view_source, model::ViewSource};
use aos_sandbox_protocol::mount_source_acquisition_state::{
    AcquisitionRecoveryV2, ActualWriterRootMountSnapshotV2, AttemptNormalizedAcquireV2,
    AuthorityAdmissionStateV2, AuthorityTrustSnapshotV2, HolderSequenceV2, KeyAdmissionStateV2,
    NegotiatedCapabilitiesV2, ProviderAcquisitionIdentityV2, ProviderAttemptStateV2,
    ProviderExecutionSnapshotV2, ProviderIntentV2, ProviderMethodV2, ProviderQueryOwnerV2,
    ProviderScopeV2, RecordRefV2, SignerRoleV2, SignerSnapshotV2, SourceAcquisitionPhaseV2,
    SourceProviderQueryAttemptV2, SourceProviderSessionV2, StoredRecordV2,
    acquire_verification_floor_v2, attempt_id, checkpoint::validate_session_checkpoint,
    encode_mount_source_state_record_v2, format::execution_digest, intent_digest,
    native_recovery_settlement_digest_v2, request_id, seal_record, session_id,
    validate_mount_source_state_graph_v2,
};
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ValidatedAcquireMountSourceRequest,
    decode_historical_acquire_mount_source_request, decode_mount_request, semantics,
};
use aos_sandbox_source_provider_protocol::{
    AcquireSourceRequestV1, NativeRecoveryTerminalDigestsV1, NormalizedAcquisitionIntentV2,
    ProviderCatalogFloorV1, RecoveryCurrentnessQueryV1, SignedNativeRecoveryUnavailableV1,
    SourceProviderAuthorityV1, SourceProviderHelloV1, SourceProviderKeyUsageV1,
    SourceProviderMethod, SourceProviderPeerRole, SourceProviderSigningKeyV1, SourceUseV1,
    digest_signed_hello, digest_signed_request, encode_acquire_request, sign_hello, sign_request,
    source_acquisition_id_v2, source_provider_session_binding_v1,
    source_provider_signer_set_commitment_v1,
};
use buffa::Message as _;
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::PermissionsExt as _;

use super::super::{reservation, transition};

const HOLDER: [u8; 16] = [1; 16];
const PROVIDER: [u8; 16] = [2; 16];
const BOOT: [u8; 16] = [3; 16];
const PROCESS: [u8; 16] = [4; 16];
const NODE: [u8; 16] = [5; 16];
const ROUTE: [u8; 16] = [6; 16];

fn signer(
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

fn signed_session(root_instance: [u8; 16], nonce: u8) -> SourceProviderSessionV2 {
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

fn mount_acquire_request() -> (Vec<u8>, ValidatedAcquireMountSourceRequest) {
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

fn initial_signed_graph() -> Vec<StoredRecordV2> {
    initial_signed_graph_for_session(signed_session([19; 16], 31), 500, [62; 32], [63; 32])
}

fn initial_signed_graph_for_session(
    session: SourceProviderSessionV2,
    provider_deadline_seconds: i64,
    catalog_digest: [u8; 32],
    catalog_head_commitment: [u8; 32],
) -> Vec<StoredRecordV2> {
    initial_signed_graph_with_catalog(
        session,
        provider_deadline_seconds,
        catalog_digest,
        catalog_head_commitment,
        None,
    )
}

fn initial_signed_graph_with_catalog(
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
        value: reservation::acquire_intent(
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
    let attempt = reservation::sealed_attempt(attempt).expect("sealed Acquire attempt");
    let attempt_ref = RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    };
    let row = reservation::sealed_row(reservation::initial_row(
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
    let head = reservation::sealed_head(
        transition::initial_provider_head(&session, &rows, attempt_ref)
            .expect("initial provider head"),
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

fn superseded_signed_graph() -> Vec<StoredRecordV2> {
    let records = initial_signed_graph();
    let StoredRecordV2::ProviderSession { value: predecessor } = &records[0] else {
        panic!("fixture predecessor session changed kind");
    };
    let StoredRecordV2::ProviderQueryAttempt { value: original } = &records[1] else {
        panic!("fixture original attempt changed kind");
    };
    let StoredRecordV2::Acquisition { value: row } = &records[2] else {
        panic!("fixture acquisition changed kind");
    };
    let StoredRecordV2::ProviderHead { value: head } = &records[3] else {
        panic!("fixture Provider head changed kind");
    };

    let mut successor = signed_session([20; 16], 32);
    successor.predecessor_session_id = Some(predecessor.session_id);
    successor.record_digest = [0; 32];
    let StoredRecordV2::ProviderSession { value: successor } =
        seal_record(StoredRecordV2::ProviderSession { value: successor })
            .expect("sealed successor session")
    else {
        panic!("fixture successor session changed kind");
    };
    let mut superseded = original.clone();
    superseded.revision = 2;
    superseded.state = ProviderAttemptStateV2::SupersededIndeterminate {
        successor_session_id: successor.session_id,
        recovery_root_attempt_id: original.attempt_id,
        outcome_may_exist: true,
    };
    superseded.record_digest = [0; 32];
    let superseded = reservation::sealed_attempt(superseded).expect("sealed superseded attempt");
    let superseded_ref = RecordRefV2 {
        id: superseded.attempt_id,
        revision: superseded.revision,
        record_digest: superseded.record_digest,
    };
    let mut pending = row.clone();
    pending.revision = 2;
    pending.acquire_lineage.root = superseded_ref;
    pending.acquire_lineage.tail = superseded_ref;
    pending.recovery = AcquisitionRecoveryV2::Ready;
    pending.record_digest = [0; 32];
    let pending = reservation::sealed_row(pending).expect("sealed superseded acquisition");
    let mut idle = head.clone();
    idle.revision = 2;
    idle.current_session_id = successor.session_id;
    idle.current_session_record_digest = successor.record_digest;
    idle.next_request_sequence = 1;
    idle.next_response_sequence = 1;
    idle.pending_attempt = None;
    idle.record_digest = [0; 32];
    let idle = reservation::sealed_head(idle).expect("sealed idle successor head");

    vec![
        records[0].clone(),
        StoredRecordV2::ProviderSession { value: successor },
        StoredRecordV2::ProviderQueryAttempt { value: superseded },
        StoredRecordV2::Acquisition { value: pending },
        StoredRecordV2::ProviderHead { value: idle },
        records[4].clone(),
    ]
}

fn restarted_signed_graph() -> Vec<StoredRecordV2> {
    let records = superseded_signed_graph();
    let StoredRecordV2::ProviderSession { value: predecessor } = &records[1] else {
        panic!("fixture first successor session changed kind");
    };
    let StoredRecordV2::ProviderHead { value: head } = &records[4] else {
        panic!("fixture first idle head changed kind");
    };

    let mut successor = signed_session([21; 16], 34);
    successor.predecessor_session_id = Some(predecessor.session_id);
    successor.record_digest = [0; 32];
    let StoredRecordV2::ProviderSession { value: successor } =
        seal_record(StoredRecordV2::ProviderSession { value: successor })
            .expect("sealed repeated Mount successor")
    else {
        panic!("fixture repeated successor changed kind");
    };
    let mut idle = head.clone();
    idle.revision = 3;
    idle.current_session_id = successor.session_id;
    idle.current_session_record_digest = successor.record_digest;
    idle.record_digest = [0; 32];
    let idle = reservation::sealed_head(idle).expect("sealed repeated idle head");

    vec![
        records[0].clone(),
        records[1].clone(),
        StoredRecordV2::ProviderSession { value: successor },
        records[2].clone(),
        records[3].clone(),
        StoredRecordV2::ProviderHead { value: idle },
        records[5].clone(),
    ]
}

fn terminal_signed_graph() -> Vec<StoredRecordV2> {
    let records = restarted_signed_graph();
    let StoredRecordV2::ProviderSession { value: session } = &records[2] else {
        panic!("fixture settlement session changed kind");
    };
    let StoredRecordV2::ProviderQueryAttempt { value: attempt } = &records[3] else {
        panic!("fixture superseded attempt changed kind");
    };
    let StoredRecordV2::Acquisition { value: row } = &records[4] else {
        panic!("fixture pending acquisition changed kind");
    };
    let StoredRecordV2::ProviderHead { value: head } = &records[5] else {
        panic!("fixture idle Provider head changed kind");
    };

    let query = RecoveryCurrentnessQueryV1::new(
        ObjectDigest::from_bytes(session.session_binding),
        [64; 32],
        1,
        PROVIDER,
        HOLDER,
        ObjectDigest::from_bytes(row.acquisition_id),
        ObjectDigest::from_bytes(attempt.signed_request_digest),
        ObjectDigest::from_bytes(attempt.record_digest),
    )
    .expect("exact native recovery query");
    let key = SigningKey::from_bytes(&[14; 32]);
    let signed = SignedNativeRecoveryUnavailableV1::sign(
        &query,
        NativeRecoveryTerminalDigestsV1 {
            reservation: ObjectDigest::from_bytes([71; 32]),
            faulted_acquisition: ObjectDigest::from_bytes([72; 32]),
            retired_attempt: ObjectDigest::from_bytes([73; 32]),
            cleared_session: ObjectDigest::from_bytes([74; 32]),
        },
        signer(
            PROVIDER,
            [24; 16],
            SourceProviderKeyUsageV1::ProviderOutcome,
            &key,
        ),
        &key,
    )
    .expect("signed Provider terminal proof");
    let signed_bytes = signed.to_canonical_bytes();
    let mut terminal = attempt.clone();
    terminal.revision = 3;
    terminal.state = ProviderAttemptStateV2::NativeNoDispatchSettled {
        prior_state: Box::new(attempt.state.clone()),
        canonical_query: query.to_canonical_bytes().to_vec(),
        signed_settlement: signed_bytes.clone(),
        settlement_session_id: session.session_id,
    };
    terminal.record_digest = [0; 32];
    let terminal = reservation::sealed_attempt(terminal).expect("sealed terminal attempt");
    let terminal_ref = RecordRefV2 {
        id: terminal.attempt_id,
        revision: terminal.revision,
        record_digest: terminal.record_digest,
    };
    let mut faulted = row.clone();
    faulted.revision = 3;
    faulted.phase = SourceAcquisitionPhaseV2::Faulted;
    faulted.faulted_from = Some(SourceAcquisitionPhaseV2::PendingQuery);
    faulted.fault_digest = Some(native_recovery_settlement_digest_v2(&signed_bytes));
    faulted.acquire_lineage.root = terminal_ref;
    faulted.acquire_lineage.tail = terminal_ref;
    faulted.record_digest = [0; 32];
    let faulted = reservation::sealed_row(faulted).expect("sealed terminal acquisition");
    let mut cleared = head.clone();
    cleared.revision = 4;
    cleared.recovery_barrier = None;
    cleared.record_digest = [0; 32];
    let cleared = reservation::sealed_head(cleared).expect("sealed terminal head");

    vec![
        records[0].clone(),
        records[1].clone(),
        records[2].clone(),
        StoredRecordV2::ProviderQueryAttempt { value: terminal },
        StoredRecordV2::Acquisition { value: faulted },
        StoredRecordV2::ProviderHead { value: cleared },
        records[6].clone(),
    ]
}

fn validate_fixture_graph(records: &[StoredRecordV2]) {
    let encoded: Vec<_> = records
        .iter()
        .map(|record| {
            aos_sandbox_protocol::mount_source_acquisition_state::encode_mount_source_state_record_v2(record)
                .expect("canonical record")
        })
        .collect();
    validate_mount_source_state_graph_v2(
        encoded
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .expect("valid signed Acquire graph");
}

fn commit_graph_delta(
    journal: &mut Journal,
    previous: &[StoredRecordV2],
    next: &[StoredRecordV2],
    transaction_id: [u8; 16],
) {
    let mut before = BTreeMap::new();
    for record in previous {
        let (key, value) =
            aos_sandbox_protocol::mount_source_acquisition_state::encode_mount_source_state_record_v2(record)
                .expect("canonical prior record");
        before.insert(key, value);
    }
    let changed = next
        .iter()
        .filter_map(|record| {
            let (key, value) =
                aos_sandbox_protocol::mount_source_acquisition_state::encode_mount_source_state_record_v2(record)
                    .expect("canonical next record");
            (before.get(&key) != Some(&value)).then(|| {
                JournalRecord::put(RecordNamespace::MountSourceAcquisition, key, value)
            })
        })
        .collect();
    let transaction = JournalTransaction::new(transaction_id, changed)
        .expect("nonempty native recovery transaction");
    journal
        .commit(&transaction)
        .expect("protected journal commit");
}

fn validate_protected_graph(
    journal: &Journal,
) -> aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2 {
    validate_mount_source_state_graph_v2(journal.records(RecordNamespace::MountSourceAcquisition))
        .expect("protected graph survives typed replay")
}

#[test]
fn authentic_session_fixture_survives_checkpoint_validation() {
    let first = signed_session([19; 16], 31);
    let second = signed_session([20; 16], 32);

    assert_ne!(first.session_id, second.session_id);
    assert_eq!(
        first.provider_process_instance,
        second.provider_process_instance
    );
    assert_eq!(first.provider_execution, second.provider_execution);
}

#[test]
fn mount_acquire_fixture_has_real_precatalog_semantics() {
    let (bytes, request) = mount_acquire_request();

    assert!(!bytes.is_empty());
    assert_ne!(*request.acquisition_id().as_bytes(), [0; 32]);
}

#[test]
fn initial_signed_acquire_graph_passes_full_typed_replay() {
    validate_fixture_graph(&initial_signed_graph());
    validate_fixture_graph(&superseded_signed_graph());
    validate_fixture_graph(&restarted_signed_graph());
    validate_fixture_graph(&terminal_signed_graph());
}

#[test]
fn kind2_private_installation_gate_refuses_changed_table_before_retirement() {
    let encoded: Vec<_> = initial_signed_graph()
        .iter()
        .map(|record| encode_mount_source_state_record_v2(record).unwrap())
        .collect();
    let current = validate_mount_source_state_graph_v2(
        encoded
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap();
    let mut table = super::super::SourceAcquisitionTableV2::from_state(current.clone());
    assert!(super::super::require_kind2_installed_table(&table, &current).is_ok());

    table.provider_heads.clear();
    // The actual private coordinator propagates this error before obtaining or
    // consuming a lower DELETE. This pure DATA vector mints no writer/readback.
    assert!(super::super::require_kind2_installed_table(&table, &current).is_err());
}

fn initial_signed_native_graph() -> Vec<StoredRecordV2> {
    let session = signed_session([19; 16], 31);
    let catalog = aos_sandbox_source_provider_protocol::NativeAcquireCatalogBindingV3::new(
        ObjectDigest::from_bytes(session.scope.resource_namespace_digest),
        1,
        ObjectDigest::from_bytes([62; 32]),
        1,
        ObjectDigest::from_bytes([62; 32]),
        ObjectDigest::from_bytes([63; 32]),
        ObjectDigest::from_bytes([64; 32]),
    )
    .unwrap();
    initial_signed_graph_with_catalog(session, 500, [62; 32], [63; 32], Some(catalog))
}

#[test]
fn native_normalization_survives_mount_cold_replay_and_retry_profile_reconstruction() {
    let records = initial_signed_native_graph();
    validate_fixture_graph(&records);
    let StoredRecordV2::ProviderQueryAttempt { value: original } = &records[1] else {
        panic!("native fixture attempt changed kind");
    };
    let normalized = original.normalized_acquire_intent.as_ref().unwrap();
    let value = NormalizedAcquisitionIntentV2::from_canonical_bytes(&normalized.bytes).unwrap();
    let native_catalog = value.native_catalog().unwrap().clone();

    // Reconstruct only DATA here. The real signer deliberately refuses V3
    // until the fresh remote-currentness and actual selection producer exists.
    let legacy_records = initial_signed_graph();
    let StoredRecordV2::ProviderQueryAttempt { value: legacy } = &legacy_records[1] else {
        panic!("legacy fixture attempt changed kind");
    };
    let signed =
        aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1::from_canonical_bytes(
            &legacy.signed_request,
        )
        .unwrap();
    let mut retry_bytes = signed.subject().to_vec();
    retry_bytes[40..48].copy_from_slice(&2_u64.to_be_bytes());
    let request =
        aos_sandbox_source_provider_protocol::decode_acquire_request(&retry_bytes).unwrap();
    let retry = super::super::retry::restore_acquire_profile(&value, request).unwrap();
    assert_eq!(retry.native_catalog(), Some(&native_catalog));
    assert!(value.matches_original_acquire_request(&retry));

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = directory.path().metadata().unwrap().uid();
    let (mut journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "normalized-native.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    commit_graph_delta(&mut journal, &[], &records, [91; 16]);
    drop(journal);
    let (reopened, _) = Journal::open_existing_protected_at_uid(
        directory.path(),
        "normalized-native.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap();
    let replayed = validate_protected_graph(&reopened);
    assert_eq!(
        replayed.provider_attempts[&original.attempt_id]
            .normalized_acquire_intent
            .as_ref(),
        Some(normalized)
    );
}

#[test]
fn native_normalization_substitution_is_rejected_after_local_record_repairs() {
    use aos_sandbox_protocol::mount_source_acquisition_state::encode_mount_source_state_record_v2;

    let mut records = initial_signed_native_graph();
    let StoredRecordV2::ProviderQueryAttempt { value: original } = &records[1] else {
        panic!("native fixture attempt changed kind");
    };
    let mut changed = original.clone();
    let normalized = changed.normalized_acquire_intent.as_mut().unwrap();
    normalized.bytes[587] ^= 1; // Legal alternate full publication digest.
    let value = NormalizedAcquisitionIntentV2::from_canonical_bytes(&normalized.bytes).unwrap();
    normalized.digest = *value.digest().as_bytes();
    changed.record_digest = [0; 32];
    let changed = reservation::sealed_attempt(changed).unwrap();
    let reference = RecordRefV2 {
        id: changed.attempt_id,
        revision: changed.revision,
        record_digest: changed.record_digest,
    };
    records[1] = StoredRecordV2::ProviderQueryAttempt { value: changed };
    let StoredRecordV2::Acquisition { value: row } = &records[2] else {
        panic!("native fixture row changed kind");
    };
    let mut row = row.clone();
    row.acquire_lineage.root = reference;
    row.acquire_lineage.tail = reference;
    row.record_digest = [0; 32];
    records[2] = StoredRecordV2::Acquisition {
        value: reservation::sealed_row(row).unwrap(),
    };
    let StoredRecordV2::ProviderHead { value: head } = &records[3] else {
        panic!("native fixture head changed kind");
    };
    let mut head = head.clone();
    head.pending_attempt = Some(reference);
    head.record_digest = [0; 32];
    records[3] = StoredRecordV2::ProviderHead {
        value: reservation::sealed_head(head).unwrap(),
    };
    let encoded: Vec<_> = records
        .iter()
        .map(|record| encode_mount_source_state_record_v2(record).unwrap())
        .collect();
    let error = validate_mount_source_state_graph_v2(
        encoded
            .iter()
            .map(|(key, bytes)| (key.as_slice(), bytes.as_slice())),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("provider Acquire request contradicts immutable intent"),
        "{error}"
    );
}

#[test]
fn protected_native_recovery_graph_reopens_before_and_after_terminal_commit() {
    let directory = tempfile::tempdir().expect("private test directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private protected-journal directory mode");
    let expected_uid = directory
        .path()
        .metadata()
        .expect("directory metadata")
        .uid();
    let limits = JournalLimits::default();
    let (mut journal, _) = Journal::open_protected_at_uid(
        directory.path(),
        "mount-source.journal",
        limits,
        expected_uid,
    )
    .expect("protected Mount test journal");
    let initial = initial_signed_graph();
    let superseded = superseded_signed_graph();
    let pending = restarted_signed_graph();
    let terminal = terminal_signed_graph();
    commit_graph_delta(&mut journal, &[], &initial, [81; 16]);
    commit_graph_delta(&mut journal, &initial, &superseded, [82; 16]);
    commit_graph_delta(&mut journal, &superseded, &pending, [83; 16]);
    drop(journal);

    let (mut reopened, _) = Journal::open_existing_protected_at_uid(
        directory.path(),
        "mount-source.journal",
        limits,
        expected_uid,
    )
    .expect("reopen before Mount terminal CAS");
    let before = validate_protected_graph(&reopened);
    assert!(matches!(
        before
            .provider_attempts
            .values()
            .next()
            .map(|attempt| &attempt.state),
        Some(ProviderAttemptStateV2::SupersededIndeterminate { .. })
    ));
    assert!(matches!(
        before.acquisitions.values().next().map(|row| row.phase),
        Some(SourceAcquisitionPhaseV2::PendingQuery)
    ));

    commit_graph_delta(&mut reopened, &pending, &terminal, [84; 16]);
    drop(reopened);
    let (replayed, _) = Journal::open_existing_protected_at_uid(
        directory.path(),
        "mount-source.journal",
        limits,
        expected_uid,
    )
    .expect("reopen after Mount terminal CAS");
    let after = validate_protected_graph(&replayed);
    assert!(matches!(
        after
            .provider_attempts
            .values()
            .next()
            .map(|attempt| &attempt.state),
        Some(ProviderAttemptStateV2::NativeNoDispatchSettled { .. })
    ));
    assert!(matches!(
        after.acquisitions.values().next().map(|row| row.phase),
        Some(SourceAcquisitionPhaseV2::Faulted)
    ));
    assert!(
        after
            .provider_heads
            .values()
            .all(|head| head.recovery_barrier.is_none())
    );
}
