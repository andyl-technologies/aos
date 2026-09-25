//! Authenticated Network Inventory semantic-composite regressions.

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, Audience, BrokerAuthorizationArtifactsV1, BrokerClientHello,
    BrokerDescriptorDisposition, BrokerDescriptorDispositionEntry, BrokerDescriptorEntry,
    BrokerDescriptorRole, BrokerError, BrokerErrorCode, BrokerMethod, BrokerRequestEnvelope,
    BrokerResponseEnvelope, BrokerServerHello, Feature, InventoryNetworkResourcesResponse,
    InventoryNetworksRequest, NetworkNamespaceInventoryRecord, NetworkState, RequestHeader,
};
use aos_sandbox_broker_session_protocol::{
    BrokerClientHelloSubjectV1, BrokerHelloSubjectV1, BrokerOutcomeSubjectV1,
    BrokerRequestSubjectV1, BrokerSessionKeyUsageV1, BrokerSessionProtocolV1,
    BrokerSessionSequenceError, BrokerSessionSignerReferenceV1, ProtectedBrokerSessionKeyV1,
    ProtectedBrokerSessionVerificationContextV1, SignedBrokerRequestV1,
    client_hello_fields_digest_v1, complete_signed_client_hello_digest_v1,
    complete_signed_request_digest_v1, encode_signed_client_hello_packet_v1,
    encode_signed_request_packet_v1, encode_signed_response_packet_v1,
    encode_signed_server_hello_packet_v1, outcome_fields_digest_v1, request_fields_digest_v1,
    server_hello_fields_digest_v1, sign_broker_hello_v1, sign_client_hello_v1, sign_outcome_v1,
    sign_request_v1,
};
use aos_sandbox_protocol::{
    AuthenticatedBrokerSessionError, AuthenticatedBrokerSessionStateV1,
    AuthenticatedNetworkInventoryOutcomeAdmissionV1,
    AuthenticatedNetworkInventoryRequestAdmissionV1, AuthenticatedNetworkInventoryResultV1,
    PeerCredentials, PeerPolicy, ProtocolValidationError,
};
use buffa::Message as _;
use ed25519_dalek::SigningKey;

const NODE: [u8; 16] = [11; 16];
const BOOT: [u8; 16] = [12; 16];
const CLIENT_PROCESS: [u8; 16] = [13; 16];
const BROKER_PROCESS: [u8; 16] = [14; 16];
const CLIENT_NONCE: [u8; 32] = [15; 32];
const BROKER_NONCE: [u8; 32] = [16; 32];
const REQUEST_ID: [u8; 16] = [17; 16];
const PEER: PeerCredentials = PeerCredentials {
    uid: 100,
    gid: 200,
    pid: Some(300),
};
const POLICY: PeerPolicy = PeerPolicy {
    uid: 100,
    gid: Some(200),
    audience: Audience::AUDIENCE_NODE_CONTROLLER,
};

struct Keys {
    signing: [SigningKey; 4],
    signers: [BrokerSessionSignerReferenceV1; 4],
}

struct Handshake {
    keys: Keys,
    context: ProtectedBrokerSessionVerificationContextV1,
    client_packet: Vec<u8>,
    broker_packet: Vec<u8>,
}

fn feature() -> Feature {
    Feature {
        namespace: "aos.sandbox.authentication.broker-session".to_owned(),
        major: 1,
        minor: 0,
        ..Default::default()
    }
}

fn keys() -> Keys {
    let signing = [
        SigningKey::from_bytes(&[21; 32]),
        SigningKey::from_bytes(&[22; 32]),
        SigningKey::from_bytes(&[23; 32]),
        SigningKey::from_bytes(&[24; 32]),
    ];
    let uses = [
        BrokerSessionKeyUsageV1::ClientHello,
        BrokerSessionKeyUsageV1::BrokerHello,
        BrokerSessionKeyUsageV1::ClientRecord,
        BrokerSessionKeyUsageV1::BrokerOutcome,
    ];
    let signers = std::array::from_fn(|index| {
        BrokerSessionSignerReferenceV1::for_signing_key(
            [31 + index as u8; 16],
            10 + index as u64,
            [41 + index as u8; 32],
            [51 + index as u8; 16],
            20 + index as u64,
            uses[index],
            &signing[index],
        )
        .unwrap_or_else(|error| panic!("test signer failed: {error}"))
    });
    Keys { signing, signers }
}

fn protected_keys(keys: &Keys, revoked: Option<usize>) -> [ProtectedBrokerSessionKeyV1; 4] {
    std::array::from_fn(|index| {
        ProtectedBrokerSessionKeyV1::new(
            keys.signers[index].clone(),
            keys.signing[index].verifying_key().to_bytes(),
            keys.signers[index].authority_generation(),
            keys.signers[index].key_generation(),
            revoked == Some(index),
            None,
        )
        .unwrap_or_else(|error| panic!("protected key failed: {error}"))
    })
}

fn context(keys: &Keys, revoked: Option<usize>) -> ProtectedBrokerSessionVerificationContextV1 {
    ProtectedBrokerSessionVerificationContextV1::new(
        [61; 16],
        [62; 16],
        1,
        [63; 32],
        2,
        [64; 32],
        3,
        [65; 32],
        NODE,
        BOOT,
        BrokerSessionProtocolV1::Network,
        1,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        CLIENT_PROCESS,
        BROKER_PROCESS,
        protected_keys(keys, revoked),
    )
    .unwrap_or_else(|error| panic!("test context failed: {error}"))
}

fn handshake() -> Handshake {
    handshake_with_methods(
        vec![BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES],
        vec![BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES],
    )
}

fn handshake_with_methods(
    required_methods: Vec<BrokerMethod>,
    advertised_methods: Vec<BrokerMethod>,
) -> Handshake {
    let keys = keys();
    let context = context(&keys, None);
    let protected_context = context.protected_context_digest();
    let client_message = BrokerClientHello {
        protocol_major: 1,
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        required_features: vec![feature()],
        maximum_response_bytes: 65_536,
        required_methods: required_methods.into_iter().map(Into::into).collect(),
        ..Default::default()
    };
    let client_fields = client_hello_fields_digest_v1(&client_message)
        .unwrap_or_else(|error| panic!("client projection failed: {error}"));
    let client_subject = BrokerClientHelloSubjectV1::new(
        NODE,
        BOOT,
        BrokerSessionProtocolV1::Network,
        1,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        CLIENT_PROCESS,
        CLIENT_NONCE,
        protected_context,
        client_fields,
    )
    .unwrap_or_else(|error| panic!("client subject failed: {error}"));
    let client = sign_client_hello_v1(client_subject, keys.signers[0].clone(), &keys.signing[0])
        .unwrap_or_else(|error| panic!("client signing failed: {error}"));
    let client_packet = encode_signed_client_hello_packet_v1(client_message, &client)
        .unwrap_or_else(|error| panic!("client packet encoding failed: {error}"));

    let broker_message = BrokerServerHello {
        protocol_major: 1,
        features: vec![feature()],
        maximum_request_bytes: 1_048_576,
        maximum_response_bytes: 65_536,
        methods: advertised_methods.into_iter().map(Into::into).collect(),
        ..Default::default()
    };
    let broker_fields = server_hello_fields_digest_v1(&broker_message)
        .unwrap_or_else(|error| panic!("broker projection failed: {error}"));
    let broker_subject = BrokerHelloSubjectV1::new(
        NODE,
        BOOT,
        BrokerSessionProtocolV1::Network,
        1,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        BROKER_PROCESS,
        BROKER_NONCE,
        protected_context,
        complete_signed_client_hello_digest_v1(&client),
        broker_fields,
    )
    .unwrap_or_else(|error| panic!("broker subject failed: {error}"));
    let broker = sign_broker_hello_v1(broker_subject, keys.signers[1].clone(), &keys.signing[1])
        .unwrap_or_else(|error| panic!("broker signing failed: {error}"));
    let broker_packet = encode_signed_server_hello_packet_v1(broker_message, &broker)
        .unwrap_or_else(|error| panic!("broker packet encoding failed: {error}"));

    Handshake {
        keys,
        context,
        client_packet,
        broker_packet,
    }
}

fn state(handshake: &Handshake) -> AuthenticatedBrokerSessionStateV1 {
    AuthenticatedBrokerSessionStateV1::from_hello_packets(
        &handshake.client_packet,
        &handshake.broker_packet,
        &handshake.context,
    )
    .unwrap_or_else(|error| panic!("authenticated state failed: {error}"))
}

fn request_body(
    request_id: [u8; 16],
    deadline: u64,
    maximum_response_bytes: u32,
    major: u32,
    audience: Audience,
) -> Vec<u8> {
    InventoryNetworksRequest {
        header: Some(RequestHeader {
            protocol_major: major,
            request_id: request_id.to_vec(),
            audience: audience.into(),
            deadline_boottime_nanoseconds: deadline,
            maximum_response_bytes,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
    .encode_to_vec()
}

fn signed_request(
    handshake: &Handshake,
    binding: [u8; 32],
    sequence: u64,
    signed_request_id: [u8; 16],
    body: Vec<u8>,
    descriptors: Vec<BrokerDescriptorEntry>,
    authorization: Option<BrokerAuthorizationArtifactsV1>,
) -> (SignedBrokerRequestV1, Vec<u8>) {
    let message = BrokerRequestEnvelope {
        method: BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES.into(),
        body,
        descriptors,
        authorization: authorization.into(),
        ..Default::default()
    };
    let fields = request_fields_digest_v1(&message)
        .unwrap_or_else(|error| panic!("request projection failed: {error}"));
    let subject =
        BrokerRequestSubjectV1::new(binding, CLIENT_PROCESS, sequence, signed_request_id, fields)
            .unwrap_or_else(|error| panic!("request subject failed: {error}"));
    let signed = sign_request_v1(
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
        subject,
        handshake.keys.signers[2].clone(),
        &handshake.keys.signing[2],
    )
    .unwrap_or_else(|error| panic!("request signing failed: {error}"));
    let packet = encode_signed_request_packet_v1(message, &signed)
        .unwrap_or_else(|error| panic!("request packet encoding failed: {error}"));
    (signed, packet)
}

fn valid_request(
    handshake: &Handshake,
    sequence: u64,
    request_id: [u8; 16],
    response_bound: u32,
) -> (SignedBrokerRequestV1, Vec<u8>) {
    valid_request_with_deadline(handshake, sequence, request_id, response_bound, 10_000)
}

fn valid_request_with_deadline(
    handshake: &Handshake,
    sequence: u64,
    request_id: [u8; 16],
    response_bound: u32,
    deadline: u64,
) -> (SignedBrokerRequestV1, Vec<u8>) {
    signed_request(
        handshake,
        session_binding(handshake),
        sequence,
        request_id,
        request_body(
            request_id,
            deadline,
            response_bound,
            1,
            Audience::AUDIENCE_NODE_CONTROLLER,
        ),
        Vec::new(),
        None,
    )
}

fn session_binding(handshake: &Handshake) -> [u8; 32] {
    // The binding is exposed only after admission, so recover it from the
    // signed hello pair using the foundation verifier for outbound test data.
    let client = aos_sandbox_broker_session_protocol::decode_canonical_client_hello_v1(
        &handshake.client_packet,
    )
    .unwrap();
    let broker = aos_sandbox_broker_session_protocol::decode_canonical_server_hello_v1(
        &handshake.broker_packet,
    )
    .unwrap();
    aos_sandbox_broker_session_protocol::verify_broker_session_transcript_v1(
        &client,
        &broker,
        &handshake.context,
    )
    .unwrap()
    .session_binding()
}

fn valid_inventory_body() -> Vec<u8> {
    inventory_body_with_records(1)
}

fn inventory_body_with_records(count: u64) -> Vec<u8> {
    let networks = (1..=count)
        .map(|identity| {
            let mut handle = [0; 32];
            handle[24..].copy_from_slice(&identity.to_be_bytes());
            NetworkNamespaceInventoryRecord {
                network_handle: handle.to_vec(),
                fence: Some(AssignmentFence {
                    sandbox_id: vec![72; 16],
                    incarnation_id: vec![73; 16],
                    assignment_epoch: 4,
                    desired_generation: 5,
                    assignment_digest: vec![74; 32],
                    ..Default::default()
                })
                .into(),
                resource_kernel_boot_id: BOOT.to_vec(),
                namespace_device: identity + 5,
                namespace_inode: identity + 10_000,
                state: NetworkState::NETWORK_STATE_DEFAULT_DROP.into(),
                resource_digest: vec![75; 32],
                ..Default::default()
            }
        })
        .collect();
    InventoryNetworkResourcesResponse {
        kernel_boot_id: BOOT.to_vec(),
        broker_instance_id: BROKER_PROCESS.to_vec(),
        journal_sequence: 2,
        catalog_generation: 3,
        networks,
        ..Default::default()
    }
    .encode_to_vec()
}

#[derive(Default)]
struct OutcomePayload {
    body: Vec<u8>,
    error: Option<BrokerError>,
    descriptors: Vec<BrokerDescriptorEntry>,
    dispositions: Vec<BrokerDescriptorDispositionEntry>,
}

fn signed_outcome(
    handshake: &Handshake,
    binding: [u8; 32],
    request: &SignedBrokerRequestV1,
    sequence: u64,
    request_id: [u8; 16],
    payload: OutcomePayload,
) -> Vec<u8> {
    let message = BrokerResponseEnvelope {
        request_id: request_id.to_vec(),
        method: BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES.into(),
        body: payload.body,
        descriptors: payload.descriptors,
        error: payload.error.into(),
        request_descriptor_dispositions: payload.dispositions,
        ..Default::default()
    };
    let fields = outcome_fields_digest_v1(&message)
        .unwrap_or_else(|error| panic!("outcome projection failed: {error}"));
    let subject = BrokerOutcomeSubjectV1::new(
        binding,
        BROKER_PROCESS,
        sequence,
        request_id,
        complete_signed_request_digest_v1(request),
        fields,
    )
    .unwrap_or_else(|error| panic!("outcome subject failed: {error}"));
    let signed = sign_outcome_v1(
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
        subject,
        handshake.keys.signers[3].clone(),
        &handshake.keys.signing[3],
    )
    .unwrap_or_else(|error| panic!("outcome signing failed: {error}"));
    encode_signed_response_packet_v1(message, &signed)
        .unwrap_or_else(|error| panic!("outcome packet encoding failed: {error}"))
}

fn pending(
    handshake: &Handshake,
    response_bound: u32,
) -> (
    AuthenticatedBrokerSessionStateV1,
    SignedBrokerRequestV1,
    Vec<u8>,
    [u8; 32],
) {
    let initial = state(handshake);
    let binding = session_binding(handshake);
    let (signed, packet) = valid_request(handshake, 1, REQUEST_ID, response_bound);
    let pending = match initial
        .admit_network_inventory_request(&packet, 0, PEER, POLICY, 1, &handshake.context)
        .unwrap_or_else(|error| panic!("request admission failed: {error}"))
    {
        AuthenticatedNetworkInventoryRequestAdmissionV1::New {
            request,
            next_state,
        } => {
            assert_eq!(request.request_id(), REQUEST_ID);
            assert_eq!(request.maximum_response_bytes(), response_bound);
            assert_eq!(request.client_sequence(), 1);
            assert!(request.descriptor_roles().is_empty());
            *next_state
        }
        AuthenticatedNetworkInventoryRequestAdmissionV1::ExactReplay { .. } => {
            panic!("first request became replay")
        }
    };
    (pending, signed, packet, binding)
}

#[test]
fn valid_sequence_one_request_derives_all_header_and_signed_links() {
    let handshake = handshake();
    let initial = state(&handshake);
    assert_eq!(initial.maximum_request_receive_bytes(), 1_048_576);
    assert_eq!(initial.maximum_outcome_receive_bytes(), None);
    let (signed, packet) = valid_request(&handshake, 1, REQUEST_ID, 8_192);
    let admitted = initial
        .admit_network_inventory_request(&packet, 0, PEER, POLICY, 1, &handshake.context)
        .unwrap();
    let AuthenticatedNetworkInventoryRequestAdmissionV1::New {
        request,
        next_state,
    } = admitted
    else {
        panic!("first request became replay")
    };

    assert_eq!(request.canonical_packet_bytes(), packet);
    assert_eq!(
        request.exact_body_bytes(),
        request_body(
            REQUEST_ID,
            10_000,
            8_192,
            1,
            Audience::AUDIENCE_NODE_CONTROLLER
        )
    );
    assert_eq!(request.request_id(), REQUEST_ID);
    assert_eq!(request.maximum_response_bytes(), 8_192);
    assert_eq!(request.signed_request_bytes(), signed.to_canonical_bytes());
    assert_eq!(
        request.signed_request_digest(),
        complete_signed_request_digest_v1(&signed)
    );
    assert_eq!(request.session_binding(), session_binding(&handshake));
    assert_eq!(next_state.maximum_outcome_receive_bytes(), Some(8_192));
}

#[test]
fn inventory_need_only_be_broker_advertised_not_client_required() {
    let handshake = handshake_with_methods(
        vec![BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY],
        vec![
            BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY,
            BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
        ],
    );
    let (_, packet) = valid_request(&handshake, 1, REQUEST_ID, 4_096);
    assert!(matches!(
        state(&handshake)
            .admit_network_inventory_request(&packet, 0, PEER, POLICY, 1, &handshake.context)
            .unwrap(),
        AuthenticatedNetworkInventoryRequestAdmissionV1::New { .. }
    ));

    let missing = handshake_with_methods(
        vec![BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY],
        vec![BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY],
    );
    let (_, packet) = valid_request(&missing, 1, REQUEST_ID, 4_096);
    assert_eq!(
        state(&missing).admit_network_inventory_request(
            &packet,
            0,
            PEER,
            POLICY,
            1,
            &missing.context,
        ),
        Err(AuthenticatedBrokerSessionError::UnsupportedProfile)
    );
}

#[test]
fn request_rejects_body_crosslinks_profile_deadline_budget_authority_and_descriptors() {
    let handshake = handshake();
    let initial = state(&handshake);
    let binding = session_binding(&handshake);
    let cases = [
        request_body(
            [18; 16],
            10_000,
            4_096,
            1,
            Audience::AUDIENCE_NODE_CONTROLLER,
        ),
        request_body(
            REQUEST_ID,
            10_000,
            4_096,
            2,
            Audience::AUDIENCE_NODE_CONTROLLER,
        ),
        request_body(REQUEST_ID, 10_000, 4_096, 1, Audience::AUDIENCE_ROOT_MOUNT),
        request_body(REQUEST_ID, 1, 4_096, 1, Audience::AUDIENCE_NODE_CONTROLLER),
        request_body(
            REQUEST_ID,
            10_000,
            4_095,
            1,
            Audience::AUDIENCE_NODE_CONTROLLER,
        ),
        request_body(
            REQUEST_ID,
            10_000,
            65_537,
            1,
            Audience::AUDIENCE_NODE_CONTROLLER,
        ),
    ];
    for (index, body) in cases.into_iter().enumerate() {
        let (_, packet) =
            signed_request(&handshake, binding, 1, REQUEST_ID, body, Vec::new(), None);
        let result = initial.admit_network_inventory_request(
            &packet,
            0,
            PEER,
            POLICY,
            1,
            &handshake.context,
        );
        if index == 3 {
            assert_eq!(
                result,
                Err(AuthenticatedBrokerSessionError::Semantics(
                    ProtocolValidationError::DeadlineExpired,
                ))
            );
        } else {
            assert!(result.is_err(), "invalid body case {index} passed");
        }
    }

    let (_, authority_packet) = signed_request(
        &handshake,
        binding,
        1,
        REQUEST_ID,
        request_body(
            REQUEST_ID,
            10_000,
            4_096,
            1,
            Audience::AUDIENCE_NODE_CONTROLLER,
        ),
        Vec::new(),
        Some(BrokerAuthorizationArtifactsV1::default()),
    );
    assert!(
        initial
            .admit_network_inventory_request(
                &authority_packet,
                0,
                PEER,
                POLICY,
                1,
                &handshake.context
            )
            .is_err()
    );

    let descriptor = BrokerDescriptorEntry {
        index: 0,
        role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER.into(),
        ..Default::default()
    };
    let (_, descriptor_packet) = signed_request(
        &handshake,
        binding,
        1,
        REQUEST_ID,
        request_body(
            REQUEST_ID,
            10_000,
            4_096,
            1,
            Audience::AUDIENCE_NODE_CONTROLLER,
        ),
        vec![descriptor],
        None,
    );
    assert!(
        initial
            .admit_network_inventory_request(
                &descriptor_packet,
                1,
                PEER,
                POLICY,
                1,
                &handshake.context
            )
            .is_err()
    );

    let (_, valid_packet) = valid_request(&handshake, 1, REQUEST_ID, 4_096);
    assert!(
        initial
            .admit_network_inventory_request(
                &valid_packet,
                0,
                PeerCredentials { uid: 101, ..PEER },
                POLICY,
                1,
                &handshake.context,
            )
            .is_err()
    );
    assert!(
        initial
            .admit_network_inventory_request(
                &valid_packet,
                0,
                PEER,
                PeerPolicy {
                    audience: Audience::AUDIENCE_ROOT_MOUNT,
                    ..POLICY
                },
                1,
                &handshake.context,
            )
            .is_err()
    );
    assert_eq!(
        initial.admit_network_inventory_request(
            &valid_packet,
            1,
            PEER,
            POLICY,
            1,
            &handshake.context
        ),
        Err(AuthenticatedBrokerSessionError::Semantics(
            ProtocolValidationError::DescriptorTableMismatch
        ))
    );
}

#[test]
fn deadline_applies_only_to_new_work_and_not_exact_no_write_replay() {
    let handshake = handshake();
    let initial = state(&handshake);
    let binding = session_binding(&handshake);
    let (signed, packet) = valid_request_with_deadline(&handshake, 1, REQUEST_ID, 8_192, 100);
    let pending = match initial
        .admit_network_inventory_request(&packet, 0, PEER, POLICY, 1, &handshake.context)
        .unwrap()
    {
        AuthenticatedNetworkInventoryRequestAdmissionV1::New { next_state, .. } => *next_state,
        AuthenticatedNetworkInventoryRequestAdmissionV1::ExactReplay { .. } => {
            panic!("first request became replay")
        }
    };
    for now in [100, 101] {
        assert!(matches!(
            pending
                .admit_network_inventory_request(&packet, 0, PEER, POLICY, now, &handshake.context,)
                .unwrap(),
            AuthenticatedNetworkInventoryRequestAdmissionV1::ExactReplay { .. }
        ));
    }

    let changed = valid_request_with_deadline(&handshake, 1, REQUEST_ID, 8_192, 101).1;
    assert_eq!(
        pending
            .admit_network_inventory_request(&changed, 0, PEER, POLICY, 100, &handshake.context,),
        Err(AuthenticatedBrokerSessionError::Traffic(
            BrokerSessionSequenceError::Equivocation,
        ))
    );

    let response = signed_outcome(
        &handshake,
        binding,
        &signed,
        1,
        REQUEST_ID,
        OutcomePayload {
            body: valid_inventory_body(),
            ..Default::default()
        },
    );
    let completed = match pending
        .admit_network_inventory_outcome(&response, 0, &handshake.context)
        .unwrap()
    {
        AuthenticatedNetworkInventoryOutcomeAdmissionV1::New { next_state, .. } => *next_state,
        AuthenticatedNetworkInventoryOutcomeAdmissionV1::ExactReplay { .. } => {
            panic!("first outcome became replay")
        }
    };
    for now in [100, 101] {
        assert!(matches!(
            completed
                .admit_network_inventory_request(&packet, 0, PEER, POLICY, now, &handshake.context,)
                .unwrap(),
            AuthenticatedNetworkInventoryRequestAdmissionV1::ExactReplay { .. }
        ));
    }

    let expired = valid_request_with_deadline(&handshake, 1, REQUEST_ID, 4_096, 1).1;
    assert_eq!(
        initial.admit_network_inventory_request(&expired, 0, PEER, POLICY, 1, &handshake.context,),
        Err(AuthenticatedBrokerSessionError::Semantics(
            ProtocolValidationError::DeadlineExpired,
        ))
    );
    let corrected = valid_request_with_deadline(&handshake, 1, REQUEST_ID, 4_096, 2).1;
    assert!(matches!(
        initial
            .admit_network_inventory_request(&corrected, 0, PEER, POLICY, 1, &handshake.context,)
            .unwrap(),
        AuthenticatedNetworkInventoryRequestAdmissionV1::New { .. }
    ));
}

#[test]
fn valid_success_inventory_advances_only_after_complete_semantics() {
    let handshake = handshake();
    let (pending, signed_request, _, binding) = pending(&handshake, 8_192);
    let response = signed_outcome(
        &handshake,
        binding,
        &signed_request,
        1,
        REQUEST_ID,
        OutcomePayload {
            body: valid_inventory_body(),
            ..Default::default()
        },
    );
    let admitted = pending
        .admit_network_inventory_outcome(&response, 0, &handshake.context)
        .unwrap();
    let AuthenticatedNetworkInventoryOutcomeAdmissionV1::New {
        outcome,
        next_state,
    } = admitted
    else {
        panic!("first outcome became replay")
    };
    let AuthenticatedNetworkInventoryResultV1::Success(inventory) = outcome.result() else {
        panic!("success became error")
    };
    assert_eq!(inventory.kernel_boot_id(), &BOOT);
    assert_eq!(inventory.broker_instance_id(), &BROKER_PROCESS);
    assert_eq!(inventory.networks().len(), 1);
    assert!(outcome.descriptor_roles().is_empty());
    assert_eq!(next_state.maximum_outcome_receive_bytes(), Some(8_192));
}

#[test]
fn otherwise_valid_success_over_cleared_budget_becomes_bounded_signed_error() {
    let handshake = handshake();
    let (pending, _, _, _) = pending(&handshake, 4_096);
    let plan = pending
        .into_network_inventory_success_outcome_plan(
            inventory_body_with_records(40),
            &handshake.context,
        )
        .unwrap();
    let signed = sign_outcome_v1(
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
        plan.signing_subject().clone(),
        handshake.keys.signers[3].clone(),
        &handshake.keys.signing[3],
    )
    .unwrap();
    let prepared = plan.finalize(&signed, &handshake.context).unwrap();
    let (packet, outcome, completed) = prepared.into_parts();

    assert!(packet.len() <= 4_096);
    assert!(matches!(
        outcome.result(),
        AuthenticatedNetworkInventoryResultV1::Error(error)
            if error.code() == BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED
                && error.safe_message()
                    == "authoritative Network inventory exceeds response bound"
                && error.retryable()
    ));
    assert!(completed.has_initial_traffic_proof());
}

#[test]
fn every_closed_error_is_a_valid_signed_terminal_outcome() {
    let handshake = handshake();
    let (pending, request, _, binding) = pending(&handshake, 8_192);
    for code in [
        BrokerErrorCode::BROKER_ERROR_CODE_INVALID_REQUEST,
        BrokerErrorCode::BROKER_ERROR_CODE_UNAUTHENTICATED_PEER,
        BrokerErrorCode::BROKER_ERROR_CODE_WRONG_AUDIENCE,
        BrokerErrorCode::BROKER_ERROR_CODE_STALE_ASSIGNMENT,
        BrokerErrorCode::BROKER_ERROR_CODE_STALE_GENERATION,
        BrokerErrorCode::BROKER_ERROR_CODE_UNKNOWN_HANDLE,
        BrokerErrorCode::BROKER_ERROR_CODE_CONFLICT,
        BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED,
        BrokerErrorCode::BROKER_ERROR_CODE_REQUIRED_FEATURE_UNAVAILABLE,
        BrokerErrorCode::BROKER_ERROR_CODE_DEADLINE_EXPIRED,
        BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE,
        BrokerErrorCode::BROKER_ERROR_CODE_INTEGRITY_FAILURE,
    ] {
        let missing =
            (code == BrokerErrorCode::BROKER_ERROR_CODE_REQUIRED_FEATURE_UNAVAILABLE).then(feature);
        let response = signed_outcome(
            &handshake,
            binding,
            &request,
            1,
            REQUEST_ID,
            OutcomePayload {
                error: Some(BrokerError {
                    code: code.into(),
                    safe_message: "closed error".to_owned(),
                    retryable: code == BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED,
                    missing_feature: missing.into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let admitted = pending
            .admit_network_inventory_outcome(&response, 0, &handshake.context)
            .unwrap_or_else(|error| panic!("closed error {code:?} failed: {error}"));
        let (outcome, completed) = match admitted {
            AuthenticatedNetworkInventoryOutcomeAdmissionV1::New {
                outcome,
                next_state,
            } => (outcome, *next_state),
            AuthenticatedNetworkInventoryOutcomeAdmissionV1::ExactReplay { .. } => {
                panic!("new error became replay")
            }
        };
        let AuthenticatedNetworkInventoryResultV1::Error(error) = outcome.result() else {
            panic!("signed error became success")
        };
        assert_eq!(error.code(), code);
        assert!(matches!(
            completed
                .admit_network_inventory_outcome(&response, 0, &handshake.context)
                .unwrap(),
            AuthenticatedNetworkInventoryOutcomeAdmissionV1::ExactReplay { .. }
        ));

        let next_id = [90; 16];
        let (_, next_packet) = valid_request(&handshake, 2, next_id, 4_096);
        assert!(matches!(
            completed
                .admit_network_inventory_request(
                    &next_packet,
                    0,
                    PEER,
                    POLICY,
                    1,
                    &handshake.context,
                )
                .unwrap(),
            AuthenticatedNetworkInventoryRequestAdmissionV1::New { .. }
        ));
    }
}

#[test]
fn semantic_failure_withholds_candidate_and_corrected_same_sequence_remains_admissible() {
    let handshake = handshake();
    let (pending, request, _, binding) = pending(&handshake, 8_192);
    let mut identity_mismatch =
        InventoryNetworkResourcesResponse::decode_from_slice(&valid_inventory_body()).unwrap();
    identity_mismatch.kernel_boot_id = vec![99; 16];
    let invalid = signed_outcome(
        &handshake,
        binding,
        &request,
        1,
        REQUEST_ID,
        OutcomePayload {
            body: identity_mismatch.encode_to_vec(),
            ..Default::default()
        },
    );
    assert!(
        pending
            .admit_network_inventory_outcome(&invalid, 0, &handshake.context)
            .is_err()
    );

    let corrected = signed_outcome(
        &handshake,
        binding,
        &request,
        1,
        REQUEST_ID,
        OutcomePayload {
            body: valid_inventory_body(),
            ..Default::default()
        },
    );
    assert!(matches!(
        pending
            .admit_network_inventory_outcome(&corrected, 0, &handshake.context)
            .unwrap(),
        AuthenticatedNetworkInventoryOutcomeAdmissionV1::New { .. }
    ));
}

#[test]
fn malformed_outcome_shapes_and_descriptor_carriers_fail_closed() {
    let handshake = handshake();
    let (pending, request, _, binding) = pending(&handshake, 8_192);
    let malformed_errors = [
        BrokerError {
            code: BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE.into(),
            safe_message: String::new(),
            ..Default::default()
        },
        BrokerError {
            code: BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE.into(),
            safe_message: "error\ncontrol".to_owned(),
            ..Default::default()
        },
    ];
    for error in malformed_errors {
        let packet = signed_outcome(
            &handshake,
            binding,
            &request,
            1,
            REQUEST_ID,
            OutcomePayload {
                error: Some(error),
                ..Default::default()
            },
        );
        assert!(
            pending
                .admit_network_inventory_outcome(&packet, 0, &handshake.context)
                .is_err()
        );
    }

    let body_and_error = signed_outcome(
        &handshake,
        binding,
        &request,
        1,
        REQUEST_ID,
        OutcomePayload {
            body: valid_inventory_body(),
            error: Some(BrokerError {
                code: BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE.into(),
                safe_message: "error".to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    assert!(
        pending
            .admit_network_inventory_outcome(&body_and_error, 0, &handshake.context)
            .is_err()
    );

    let descriptor = BrokerDescriptorEntry {
        index: 0,
        role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER.into(),
        ..Default::default()
    };
    let descriptor_packet = signed_outcome(
        &handshake,
        binding,
        &request,
        1,
        REQUEST_ID,
        OutcomePayload {
            body: valid_inventory_body(),
            descriptors: vec![descriptor],
            ..Default::default()
        },
    );
    assert!(
        pending
            .admit_network_inventory_outcome(&descriptor_packet, 0, &handshake.context)
            .is_err()
    );

    let disposition_packet = signed_outcome(
        &handshake,
        binding,
        &request,
        1,
        REQUEST_ID,
        OutcomePayload {
            body: valid_inventory_body(),
            dispositions: vec![BrokerDescriptorDispositionEntry {
                request_index: 0,
                role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER.into(),
                disposition: BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED
                    .into(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    assert!(
        pending
            .admit_network_inventory_outcome(&disposition_packet, 0, &handshake.context)
            .is_err()
    );

    let valid = signed_outcome(
        &handshake,
        binding,
        &request,
        1,
        REQUEST_ID,
        OutcomePayload {
            body: valid_inventory_body(),
            ..Default::default()
        },
    );
    assert_eq!(
        pending.admit_network_inventory_outcome(&valid, 1, &handshake.context),
        Err(AuthenticatedBrokerSessionError::Semantics(
            ProtocolValidationError::DescriptorTableMismatch
        ))
    );
}

#[test]
fn exact_replay_equivocation_and_context_change_preserve_pure_state() {
    let handshake = handshake();
    let (pending, request, request_packet, binding) = pending(&handshake, 8_192);
    let response = signed_outcome(
        &handshake,
        binding,
        &request,
        1,
        REQUEST_ID,
        OutcomePayload {
            body: valid_inventory_body(),
            ..Default::default()
        },
    );
    let completed = match pending
        .admit_network_inventory_outcome(&response, 0, &handshake.context)
        .unwrap()
    {
        AuthenticatedNetworkInventoryOutcomeAdmissionV1::New { next_state, .. } => *next_state,
        AuthenticatedNetworkInventoryOutcomeAdmissionV1::ExactReplay { .. } => {
            panic!("first outcome became replay")
        }
    };
    assert!(matches!(
        completed
            .admit_network_inventory_request(
                &request_packet,
                0,
                PEER,
                POLICY,
                1,
                &handshake.context
            )
            .unwrap(),
        AuthenticatedNetworkInventoryRequestAdmissionV1::ExactReplay { .. }
    ));
    assert!(matches!(
        completed
            .admit_network_inventory_outcome(&response, 0, &handshake.context)
            .unwrap(),
        AuthenticatedNetworkInventoryOutcomeAdmissionV1::ExactReplay { .. }
    ));

    let mut changed = BrokerResponseEnvelope::decode_from_slice(&response).unwrap();
    changed.body.push(1);
    assert_eq!(
        completed.admit_network_inventory_outcome(&changed.encode_to_vec(), 0, &handshake.context),
        Err(AuthenticatedBrokerSessionError::Traffic(
            BrokerSessionSequenceError::Equivocation,
        ))
    );

    let revoked = context(&handshake.keys, Some(2));
    assert!(matches!(
        completed.admit_network_inventory_request(&request_packet, 0, PEER, POLICY, 1, &revoked),
        Err(AuthenticatedBrokerSessionError::Traffic(_))
    ));
}

#[test]
fn retained_n_replays_with_smaller_n_plus_one_outstanding_bound() {
    let handshake = handshake();
    let (first_pending, first_request, first_packet, binding) = pending(&handshake, 8_192);
    let first_response = signed_outcome(
        &handshake,
        binding,
        &first_request,
        1,
        REQUEST_ID,
        OutcomePayload {
            body: inventory_body_with_records(40),
            ..Default::default()
        },
    );
    assert!(first_response.len() > 4_096);
    assert!(first_response.len() <= 8_192);
    let first_completed = match first_pending
        .admit_network_inventory_outcome(&first_response, 0, &handshake.context)
        .unwrap()
    {
        AuthenticatedNetworkInventoryOutcomeAdmissionV1::New { next_state, .. } => *next_state,
        AuthenticatedNetworkInventoryOutcomeAdmissionV1::ExactReplay { .. } => {
            panic!("first outcome became replay")
        }
    };

    let second_id = [18; 16];
    let (second_request, second_packet) = valid_request(&handshake, 2, second_id, 4_096);
    let second_pending = match first_completed
        .admit_network_inventory_request(&second_packet, 0, PEER, POLICY, 1, &handshake.context)
        .unwrap()
    {
        AuthenticatedNetworkInventoryRequestAdmissionV1::New { next_state, .. } => *next_state,
        AuthenticatedNetworkInventoryRequestAdmissionV1::ExactReplay { .. } => {
            panic!("second request became replay")
        }
    };
    assert_eq!(second_pending.maximum_outcome_receive_bytes(), Some(8_192));
    for now in [10_000, 10_001] {
        assert!(matches!(
            second_pending
                .admit_network_inventory_request(
                    &first_packet,
                    0,
                    PEER,
                    POLICY,
                    now,
                    &handshake.context,
                )
                .unwrap(),
            AuthenticatedNetworkInventoryRequestAdmissionV1::ExactReplay { .. }
        ));
    }
    assert!(matches!(
        second_pending
            .admit_network_inventory_outcome(&first_response, 0, &handshake.context)
            .unwrap(),
        AuthenticatedNetworkInventoryOutcomeAdmissionV1::ExactReplay { .. }
    ));

    let second_response = signed_outcome(
        &handshake,
        binding,
        &second_request,
        2,
        second_id,
        OutcomePayload {
            body: valid_inventory_body(),
            ..Default::default()
        },
    );
    assert!(matches!(
        second_pending
            .admit_network_inventory_outcome(&second_response, 0, &handshake.context)
            .unwrap(),
        AuthenticatedNetworkInventoryOutcomeAdmissionV1::New { .. }
    ));
}
