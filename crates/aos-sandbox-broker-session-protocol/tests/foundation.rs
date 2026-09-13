//! Independent Broker Session Authentication 1.0 wire and state regressions.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerAuthorizationArtifactsV1, BrokerClientHello, BrokerDescriptorDisposition,
    BrokerDescriptorDispositionEntry, BrokerDescriptorEntry, BrokerDescriptorRole, BrokerError,
    BrokerErrorCode, BrokerMethod, BrokerRequestEnvelope, BrokerResponseEnvelope,
    BrokerServerHello, Feature,
};
use aos_sandbox_broker_session_protocol::{
    AUTHENTICATED_HOST_QUERY_CLEARED_MAXIMUM_BYTES,
    AUTHENTICATED_MOUNT_PREPARE_CATALOG_CLEARED_MAXIMUM_BYTES,
    AUTHENTICATED_ORDINARY_REQUEST_CLEARED_MAXIMUM_BYTES,
    AUTHENTICATED_RESPONSE_CLEARED_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
    BrokerClientHelloSubjectV1, BrokerHelloSubjectV1, BrokerOutcomeAdmissionV1,
    BrokerOutcomeSubjectV1, BrokerRequestAdmissionV1, BrokerRequestSubjectV1,
    BrokerSessionKeyUsageV1, BrokerSessionProtocolV1, BrokerSessionSequenceError,
    BrokerSessionSignerReferenceV1, BrokerSessionTrafficStateV1, BrokerSessionTranscriptError,
    BrokerSessionTranscriptPhaseV1, ProtectedBrokerSessionKeyV1,
    ProtectedBrokerSessionVerificationContextV1, SignedBrokerClientHelloV1, SignedBrokerHelloV1,
    SignedBrokerOutcomeV1, SignedBrokerRequestV1, client_hello_fields_digest_v1,
    complete_signed_client_hello_digest_v1, complete_signed_request_digest_v1,
    decode_canonical_client_hello_v1, decode_canonical_request_v1, decode_canonical_response_v1,
    decode_canonical_server_hello_v1, outcome_fields_digest_v1, request_fields_digest_v1,
    server_hello_fields_digest_v1, sign_broker_hello_v1, sign_client_hello_v1, sign_outcome_v1,
    sign_request_v1, signer_set_digest_v1, verify_broker_session_transcript_v1,
    verify_client_hello_context_v1, verify_client_hello_signature_v1,
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

struct Keys {
    signing: [SigningKey; 4],
    signers: [BrokerSessionSignerReferenceV1; 4],
}

struct Handshake {
    keys: Keys,
    context: ProtectedBrokerSessionVerificationContextV1,
    method: BrokerMethod,
    client: SignedBrokerClientHelloV1,
    broker: SignedBrokerHelloV1,
    client_packet: Vec<u8>,
    broker_packet: Vec<u8>,
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

fn feature() -> Feature {
    Feature {
        namespace: "aos.sandbox.authentication.broker-session".to_owned(),
        major: 1,
        minor: 0,
        ..Default::default()
    }
}

fn signed_plan_feature() -> Feature {
    Feature {
        namespace: "aos.sandbox.authorization.signed-plan-lease".to_owned(),
        major: 1,
        minor: 0,
        ..Default::default()
    }
}

fn context(
    protocol: BrokerSessionProtocolV1,
    major: u16,
    keys: &Keys,
) -> ProtectedBrokerSessionVerificationContextV1 {
    context_with_inactive_key(protocol, major, keys, None)
}

fn context_with_inactive_key(
    protocol: BrokerSessionProtocolV1,
    major: u16,
    keys: &Keys,
    inactive: Option<(usize, bool, Option<u64>)>,
) -> ProtectedBrokerSessionVerificationContextV1 {
    let protected = protected_keys(keys, inactive);
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
        protocol,
        major,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        CLIENT_PROCESS,
        BROKER_PROCESS,
        protected,
    )
    .unwrap_or_else(|error| panic!("test context failed: {error}"))
}

fn protected_keys(
    keys: &Keys,
    inactive: Option<(usize, bool, Option<u64>)>,
) -> [ProtectedBrokerSessionKeyV1; 4] {
    std::array::from_fn(|index| {
        let (revoked, superseded) = inactive
            .filter(|(inactive_index, _, _)| *inactive_index == index)
            .map_or((false, None), |(_, revoked, superseded)| {
                (revoked, superseded)
            });
        ProtectedBrokerSessionKeyV1::new(
            keys.signers[index].clone(),
            keys.signing[index].verifying_key().to_bytes(),
            keys.signers[index].authority_generation(),
            keys.signers[index].key_generation(),
            revoked,
            superseded,
        )
        .unwrap_or_else(|error| panic!("test protected key failed: {error}"))
    })
}

#[allow(clippy::too_many_arguments)]
fn explicit_context(
    domain_id: [u8; 16],
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: [u8; 32],
    trust_generation: u64,
    trust_digest: [u8; 32],
    revocation_generation: u64,
    revocation_digest: [u8; 32],
    node_id: [u8; 16],
    boot_id: [u8; 16],
    protocol: BrokerSessionProtocolV1,
    major: u16,
    minor: u16,
    audience: Audience,
    client_process: [u8; 16],
    broker_process: [u8; 16],
    keys: [ProtectedBrokerSessionKeyV1; 4],
) -> ProtectedBrokerSessionVerificationContextV1 {
    ProtectedBrokerSessionVerificationContextV1::new(
        domain_id,
        route_id,
        route_generation,
        route_digest,
        trust_generation,
        trust_digest,
        revocation_generation,
        revocation_digest,
        node_id,
        boot_id,
        protocol,
        major,
        minor,
        audience,
        client_process,
        broker_process,
        keys,
    )
    .unwrap_or_else(|error| panic!("explicit test context failed: {error}"))
}

fn protected_keys_with_substitution(
    keys: &Keys,
    target: usize,
    substitution: usize,
) -> [ProtectedBrokerSessionKeyV1; 4] {
    std::array::from_fn(|index| {
        let original = &keys.signers[index];
        let alternate = SigningKey::from_bytes(&[90 + index as u8; 32]);
        let signer = if index == target {
            let changed = match substitution {
                0 => BrokerSessionSignerReferenceV1::for_signing_key(
                    original.authority_id(),
                    original.authority_generation(),
                    original.authority_digest(),
                    original.key_id(),
                    original.key_generation(),
                    original.usage(),
                    &alternate,
                ),
                1..=5 => BrokerSessionSignerReferenceV1::new(
                    if substitution == 1 {
                        [80 + index as u8; 16]
                    } else {
                        original.authority_id()
                    },
                    original.authority_generation() + u64::from(substitution == 2),
                    if substitution == 3 {
                        [81 + index as u8; 32]
                    } else {
                        original.authority_digest()
                    },
                    if substitution == 4 {
                        [82 + index as u8; 16]
                    } else {
                        original.key_id()
                    },
                    original.key_generation() + u64::from(substitution == 5),
                    original.public_key_digest(),
                    original.usage(),
                ),
                _ => Ok(original.clone()),
            };
            changed.unwrap_or_else(|error| panic!("changed signer failed: {error}"))
        } else {
            original.clone()
        };
        let public_key = if index == target && substitution == 0 {
            alternate.verifying_key().to_bytes()
        } else {
            keys.signing[index].verifying_key().to_bytes()
        };
        let authority_floor = if index == target && substitution == 6 {
            original.authority_generation() - 1
        } else {
            original.authority_generation()
        };
        let key_floor = if index == target && substitution == 7 {
            original.key_generation() - 1
        } else {
            original.key_generation()
        };
        let revoked = index == target && substitution == 8;
        let superseded =
            (index == target && substitution == 9).then_some(signer.key_generation() + 1);
        ProtectedBrokerSessionKeyV1::new(
            signer,
            public_key,
            authority_floor,
            key_floor,
            revoked,
            superseded,
        )
        .unwrap_or_else(|error| panic!("substituted protected key failed: {error}"))
    })
}

fn handshake(protocol: BrokerSessionProtocolV1, major: u16) -> Handshake {
    let keys = keys();
    let context = context(protocol, major, &keys);
    let protected_context = context.protected_context_digest();
    let method = match protocol {
        BrokerSessionProtocolV1::Host => BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
        BrokerSessionProtocolV1::Storage => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
        BrokerSessionProtocolV1::Mount => BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
        BrokerSessionProtocolV1::Network => BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
    };
    let mut client_message = aos_proto::aos::sandbox::local::v1::BrokerClientHello {
        protocol_major: u32::from(major),
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        required_features: vec![feature(), signed_plan_feature()],
        maximum_response_bytes: 65_536,
        required_methods: vec![method.into()],
        ..Default::default()
    };
    let client_fields = client_hello_fields_digest_v1(&client_message)
        .unwrap_or_else(|error| panic!("client projection failed: {error}"));
    let client_subject = BrokerClientHelloSubjectV1::new(
        NODE,
        BOOT,
        protocol,
        major,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        CLIENT_PROCESS,
        CLIENT_NONCE,
        protected_context,
        client_fields,
    )
    .unwrap_or_else(|error| panic!("client subject failed: {error}"));
    let client = sign_client_hello_v1(client_subject, keys.signers[0].clone(), &keys.signing[0])
        .unwrap_or_else(|error| panic!("client signature failed: {error}"));
    client_message.signed_session_hello = client.to_canonical_bytes();
    let client_packet = client_message.encode_to_vec();

    let mut broker_message = BrokerServerHello {
        protocol_major: u32::from(major),
        features: vec![feature(), signed_plan_feature()],
        maximum_request_bytes:
            aos_sandbox_broker_session_protocol::maximum_broker_session_request_bytes_v1(protocol)
                as u32,
        maximum_response_bytes: 65_536,
        methods: vec![method.into()],
        ..Default::default()
    };
    let broker_fields = server_hello_fields_digest_v1(&broker_message)
        .unwrap_or_else(|error| panic!("broker projection failed: {error}"));
    let broker_subject = BrokerHelloSubjectV1::new(
        NODE,
        BOOT,
        protocol,
        major,
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
        .unwrap_or_else(|error| panic!("broker signature failed: {error}"));
    broker_message.signed_session_hello = broker.to_canonical_bytes();
    let broker_packet = broker_message.encode_to_vec();
    Handshake {
        keys,
        context,
        method,
        client,
        broker,
        client_packet,
        broker_packet,
    }
}

fn transcript(
    handshake: &Handshake,
) -> aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1 {
    let client = decode_canonical_client_hello_v1(&handshake.client_packet)
        .unwrap_or_else(|error| panic!("client decode failed: {error}"));
    let broker = decode_canonical_server_hello_v1(&handshake.broker_packet)
        .unwrap_or_else(|error| panic!("broker decode failed: {error}"));
    verify_broker_session_transcript_v1(&client, &broker, &handshake.context)
        .unwrap_or_else(|error| panic!("transcript failed: {error}"))
}

fn resign_hellos(
    handshake: &Handshake,
    mut client_message: BrokerClientHello,
    mut broker_message: BrokerServerHello,
) -> (Vec<u8>, Vec<u8>) {
    client_message.signed_session_hello.clear();
    let client_fields = client_hello_fields_digest_v1(&client_message)
        .unwrap_or_else(|error| panic!("resigned client projection failed: {error}"));
    let client_subject = BrokerClientHelloSubjectV1::new(
        NODE,
        BOOT,
        handshake.context.protocol(),
        handshake.context.protocol_major(),
        handshake.context.protocol_minor(),
        handshake.context.audience(),
        CLIENT_PROCESS,
        CLIENT_NONCE,
        handshake.context.protected_context_digest(),
        client_fields,
    )
    .unwrap_or_else(|error| panic!("resigned client subject failed: {error}"));
    let client = sign_client_hello_v1(
        client_subject,
        handshake.keys.signers[0].clone(),
        &handshake.keys.signing[0],
    )
    .unwrap_or_else(|error| panic!("resigned client failed: {error}"));
    client_message.signed_session_hello = client.to_canonical_bytes();

    broker_message.signed_session_hello.clear();
    let broker_fields = server_hello_fields_digest_v1(&broker_message)
        .unwrap_or_else(|error| panic!("resigned broker projection failed: {error}"));
    let broker_subject = BrokerHelloSubjectV1::new(
        NODE,
        BOOT,
        handshake.context.protocol(),
        handshake.context.protocol_major(),
        handshake.context.protocol_minor(),
        handshake.context.audience(),
        BROKER_PROCESS,
        BROKER_NONCE,
        handshake.context.protected_context_digest(),
        complete_signed_client_hello_digest_v1(&client),
        broker_fields,
    )
    .unwrap_or_else(|error| panic!("resigned broker subject failed: {error}"));
    let broker = sign_broker_hello_v1(
        broker_subject,
        handshake.keys.signers[1].clone(),
        &handshake.keys.signing[1],
    )
    .unwrap_or_else(|error| panic!("resigned broker failed: {error}"));
    broker_message.signed_session_hello = broker.to_canonical_bytes();

    (
        client_message.encode_to_vec(),
        broker_message.encode_to_vec(),
    )
}

fn verify_resigned_hellos(
    handshake: &Handshake,
    client: BrokerClientHello,
    broker: BrokerServerHello,
) -> bool {
    let (client, broker) = resign_hellos(handshake, client, broker);
    let client = decode_canonical_client_hello_v1(&client)
        .unwrap_or_else(|error| panic!("resigned client decode failed: {error}"));
    let broker = decode_canonical_server_hello_v1(&broker)
        .unwrap_or_else(|error| panic!("resigned broker decode failed: {error}"));
    verify_broker_session_transcript_v1(&client, &broker, &handshake.context).is_ok()
}

#[test]
fn client_hello_signature_stage_precedes_dynamic_context_comparison() {
    let handshake = handshake(BrokerSessionProtocolV1::Network, 1);
    let client = decode_canonical_client_hello_v1(&handshake.client_packet)
        .unwrap_or_else(|error| panic!("client decode failed: {error}"));
    let key = &handshake.context.keys()[0];
    let signed = verify_client_hello_signature_v1(&client, key)
        .unwrap_or_else(|error| panic!("signature stage failed: {error}"));
    assert_eq!(signed.authenticated_client_process(), CLIENT_PROCESS);
    assert!(verify_client_hello_context_v1(signed, &handshake.context).is_ok());

    let wrong_key = &handshake.context.keys()[1];
    assert!(verify_client_hello_signature_v1(&client, wrong_key).is_err());
}

#[test]
fn legacy_pair_verifier_preserves_multi_invalid_error_precedence() {
    let handshake = handshake(BrokerSessionProtocolV1::Network, 1);
    let client = decode_canonical_client_hello_v1(&handshake.client_packet)
        .unwrap_or_else(|error| panic!("client decode failed: {error}"));
    let broker = decode_canonical_server_hello_v1(&handshake.broker_packet)
        .unwrap_or_else(|error| panic!("broker decode failed: {error}"));

    let inactive = context_with_inactive_key(
        BrokerSessionProtocolV1::Network,
        1,
        &handshake.keys,
        Some((3, true, None)),
    );
    let mut invalid_broker_message = broker.message().clone();
    invalid_broker_message.maximum_response_bytes = 1;
    invalid_broker_message.signed_session_hello = handshake.broker.to_canonical_bytes();
    let invalid_broker = decode_canonical_server_hello_v1(&invalid_broker_message.encode_to_vec())
        .unwrap_or_else(|error| panic!("invalid broker decode failed: {error}"));
    assert!(matches!(
        verify_broker_session_transcript_v1(&client, &invalid_broker, &inactive),
        Err(BrokerSessionTranscriptError::Signer(_))
    ));

    let mut invalid_client_message = client.message().clone();
    invalid_client_message.signed_session_hello = handshake.client.to_canonical_bytes();
    let signature_index = invalid_client_message.signed_session_hello.len() - 1;
    invalid_client_message.signed_session_hello[signature_index] ^= 1;
    let invalid_client = decode_canonical_client_hello_v1(&invalid_client_message.encode_to_vec())
        .unwrap_or_else(|error| panic!("invalid client decode failed: {error}"));
    let mismatched_context = explicit_context(
        [61; 16],
        [99; 16],
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
        protected_keys(&handshake.keys, None),
    );
    assert!(matches!(
        verify_broker_session_transcript_v1(&invalid_client, &invalid_broker, &mismatched_context,),
        Err(BrokerSessionTranscriptError::Negotiation(_))
    ));
}

fn signed_request(handshake: &Handshake, binding: [u8; 32]) -> (SignedBrokerRequestV1, Vec<u8>) {
    signed_request_at(handshake, binding, 1, REQUEST_ID, vec![1, 2, 3])
}

fn signed_request_at(
    handshake: &Handshake,
    binding: [u8; 32],
    sequence: u64,
    request_id: [u8; 16],
    body: Vec<u8>,
) -> (SignedBrokerRequestV1, Vec<u8>) {
    signed_request_for_method_at(
        handshake,
        binding,
        handshake.method,
        sequence,
        request_id,
        body,
    )
}

fn signed_request_for_method_at(
    handshake: &Handshake,
    binding: [u8; 32],
    method: BrokerMethod,
    sequence: u64,
    request_id: [u8; 16],
    body: Vec<u8>,
) -> (SignedBrokerRequestV1, Vec<u8>) {
    let mut message = BrokerRequestEnvelope {
        method: method.into(),
        body,
        descriptors: vec![BrokerDescriptorEntry {
            index: 0,
            role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER.into(),
            ..Default::default()
        }],
        authorization: Some(BrokerAuthorizationArtifactsV1 {
            broker_plan: vec![4],
            broker_plan_signature: vec![5],
            ownership_lease: vec![6],
            ownership_lease_signature: vec![7],
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    let fields = request_fields_digest_v1(&message)
        .unwrap_or_else(|error| panic!("request projection failed: {error}"));
    let subject =
        BrokerRequestSubjectV1::new(binding, CLIENT_PROCESS, sequence, request_id, fields)
            .unwrap_or_else(|error| panic!("request subject failed: {error}"));
    let signed = sign_request_v1(
        method,
        subject,
        handshake.keys.signers[2].clone(),
        &handshake.keys.signing[2],
    )
    .unwrap_or_else(|error| panic!("request signature failed: {error}"));
    message.signed_session_request = signed.to_canonical_bytes();
    (signed, message.encode_to_vec())
}

fn signed_outcome(
    handshake: &Handshake,
    binding: [u8; 32],
    request: &SignedBrokerRequestV1,
) -> (SignedBrokerOutcomeV1, Vec<u8>) {
    signed_outcome_at(handshake, binding, request, 1, REQUEST_ID)
}

fn signed_outcome_at(
    handshake: &Handshake,
    binding: [u8; 32],
    request: &SignedBrokerRequestV1,
    sequence: u64,
    request_id: [u8; 16],
) -> (SignedBrokerOutcomeV1, Vec<u8>) {
    let mut message = BrokerResponseEnvelope {
        request_id: request_id.to_vec(),
        method: handshake.method.into(),
        error: Some(BrokerError {
            code: BrokerErrorCode::BROKER_ERROR_CODE_REQUIRED_FEATURE_UNAVAILABLE.into(),
            safe_message: "feature unavailable".to_owned(),
            retryable: false,
            missing_feature: Some(feature()).into(),
            ..Default::default()
        })
        .into(),
        request_descriptor_dispositions: vec![BrokerDescriptorDispositionEntry {
            request_index: 0,
            role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER.into(),
            disposition: BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED.into(),
            ..Default::default()
        }],
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
        handshake.method,
        subject,
        handshake.keys.signers[3].clone(),
        &handshake.keys.signing[3],
    )
    .unwrap_or_else(|error| panic!("outcome signature failed: {error}"));
    message.signed_session_outcome = signed.to_canonical_bytes();
    (signed, message.encode_to_vec())
}

fn signed_success_outcome(
    handshake: &Handshake,
    binding: [u8; 32],
    request: &SignedBrokerRequestV1,
) -> (SignedBrokerOutcomeV1, Vec<u8>) {
    let mut message = BrokerResponseEnvelope {
        request_id: REQUEST_ID.to_vec(),
        method: handshake.method.into(),
        body: vec![8, 9, 10],
        descriptors: vec![BrokerDescriptorEntry {
            index: 0,
            role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER.into(),
            ..Default::default()
        }],
        request_descriptor_dispositions: vec![BrokerDescriptorDispositionEntry {
            request_index: 0,
            role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER.into(),
            disposition: BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CONSUMED.into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let fields = outcome_fields_digest_v1(&message)
        .unwrap_or_else(|error| panic!("success outcome projection failed: {error}"));
    let subject = BrokerOutcomeSubjectV1::new(
        binding,
        BROKER_PROCESS,
        1,
        REQUEST_ID,
        complete_signed_request_digest_v1(request),
        fields,
    )
    .unwrap_or_else(|error| panic!("success outcome subject failed: {error}"));
    let signed = sign_outcome_v1(
        handshake.method,
        subject,
        handshake.keys.signers[3].clone(),
        &handshake.keys.signing[3],
    )
    .unwrap_or_else(|error| panic!("success outcome signature failed: {error}"));
    message.signed_session_outcome = signed.to_canonical_bytes();
    (signed, message.encode_to_vec())
}

fn signed_sized_success_outcome(
    handshake: &Handshake,
    binding: [u8; 32],
    request: &SignedBrokerRequestV1,
    total_bytes: usize,
) -> Vec<u8> {
    let cleared_bytes = total_bytes - 343;
    let mut message = BrokerResponseEnvelope {
        request_id: REQUEST_ID.to_vec(),
        method: handshake.method.into(),
        ..Default::default()
    };
    message.body.resize(cleared_bytes, 0x6b);
    loop {
        let encoded_len = message.encode_to_vec().len();
        if encoded_len == cleared_bytes {
            break;
        }
        if encoded_len > cleared_bytes {
            message
                .body
                .truncate(message.body.len() - (encoded_len - cleared_bytes));
        } else {
            message
                .body
                .resize(message.body.len() + cleared_bytes - encoded_len, 0x6b);
        }
    }
    assert_eq!(message.encode_to_vec().len(), cleared_bytes);
    let fields = outcome_fields_digest_v1(&message)
        .unwrap_or_else(|error| panic!("sized outcome projection failed: {error}"));
    let subject = BrokerOutcomeSubjectV1::new(
        binding,
        BROKER_PROCESS,
        1,
        REQUEST_ID,
        complete_signed_request_digest_v1(request),
        fields,
    )
    .unwrap_or_else(|error| panic!("sized outcome subject failed: {error}"));
    let signed = sign_outcome_v1(
        handshake.method,
        subject,
        handshake.keys.signers[3].clone(),
        &handshake.keys.signing[3],
    )
    .unwrap_or_else(|error| panic!("sized outcome signature failed: {error}"));
    message.signed_session_outcome = signed.to_canonical_bytes();
    let encoded = message.encode_to_vec();
    assert_eq!(encoded.len(), total_bytes);
    encoded
}

#[test]
fn exact_artifact_widths_and_all_byte_mutations_fail_closed() {
    let handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let transcript = transcript(&handshake);
    let (request, _) = signed_request(&handshake, transcript.session_binding());
    let (outcome, _) = signed_outcome(&handshake, transcript.session_binding(), &request);
    let vectors = [
        (handshake.client.to_canonical_bytes(), 354usize, 0usize),
        (handshake.broker.to_canonical_bytes(), 386, 1),
        (request.to_canonical_bytes(), 308, 2),
        (outcome.to_canonical_bytes(), 340, 3),
    ];
    for (bytes, expected, key_index) in vectors {
        assert_eq!(bytes.len(), expected);
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            let verified = match expected {
                354 => {
                    SignedBrokerClientHelloV1::from_canonical_bytes(&changed).and_then(|value| {
                        value.verify_with_public_key(
                            handshake.keys.signing[key_index].verifying_key().as_bytes(),
                        )
                    })
                }
                386 => SignedBrokerHelloV1::from_canonical_bytes(&changed).and_then(|value| {
                    value.verify_with_public_key(
                        handshake.keys.signing[key_index].verifying_key().as_bytes(),
                    )
                }),
                308 => SignedBrokerRequestV1::from_canonical_bytes(&changed).and_then(|value| {
                    value.verify_with_public_key(
                        handshake.keys.signing[key_index].verifying_key().as_bytes(),
                    )
                }),
                _ => SignedBrokerOutcomeV1::from_canonical_bytes(&changed).and_then(|value| {
                    value.verify_with_public_key(
                        handshake.keys.signing[key_index].verifying_key().as_bytes(),
                    )
                }),
            };
            assert!(
                verified.is_err(),
                "mutation {index} of width {expected} survived"
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        let rejected = match expected {
            354 => SignedBrokerClientHelloV1::from_canonical_bytes(&trailing).is_err(),
            386 => SignedBrokerHelloV1::from_canonical_bytes(&trailing).is_err(),
            308 => SignedBrokerRequestV1::from_canonical_bytes(&trailing).is_err(),
            _ => SignedBrokerOutcomeV1::from_canonical_bytes(&trailing).is_err(),
        };
        assert!(rejected);
    }
}

#[test]
fn all_broker_protocols_have_distinct_working_transcripts() {
    let cases = [
        (BrokerSessionProtocolV1::Host, 1),
        (BrokerSessionProtocolV1::Storage, 1),
        (BrokerSessionProtocolV1::Mount, 2),
        (BrokerSessionProtocolV1::Network, 1),
    ];
    let bindings =
        cases.map(|(protocol, major)| transcript(&handshake(protocol, major)).session_binding());
    for left in 0..bindings.len() {
        for right in left + 1..bindings.len() {
            assert_ne!(bindings[left], bindings[right]);
        }
    }
}

#[test]
fn provisional_transcript_requires_first_request_and_signed_error_outcome() {
    let handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let transcript = transcript(&handshake);
    assert_eq!(
        transcript.phase(),
        BrokerSessionTranscriptPhaseV1::Provisional
    );
    let state = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript)
        .unwrap_or_else(|error| panic!("traffic state failed: {error}"));
    let (signed_request, request_packet) =
        signed_request(&handshake, state.transcript().session_binding());

    let request = decode_canonical_request_v1(&request_packet)
        .unwrap_or_else(|error| panic!("request decode failed: {error}"));
    let admitted = state
        .admit_request(&request, REQUEST_ID, 65_536, &handshake.context)
        .unwrap_or_else(|error| panic!("request verification failed: {error}"));
    let (verified, pending) = match admitted {
        BrokerRequestAdmissionV1::New {
            request,
            next_state,
        } => (request, next_state),
        BrokerRequestAdmissionV1::ExactReplay(_) => {
            panic!("first request was classified as replay")
        }
    };
    assert!(verified.is_first_traffic_key_proof());
    assert_eq!(
        pending.transcript().phase(),
        BrokerSessionTranscriptPhaseV1::TrafficKeyProved
    );
    assert!(pending.has_outstanding_request());

    let replay = pending
        .admit_request(&request, REQUEST_ID, 65_536, &handshake.context)
        .unwrap_or_else(|error| panic!("exact replay failed: {error}"));
    assert!(matches!(replay, BrokerRequestAdmissionV1::ExactReplay(_)));
    assert_eq!(
        pending.admit_request(&request, REQUEST_ID, 65_535, &handshake.context),
        Err(BrokerSessionSequenceError::Equivocation)
    );
    let changed_context = explicit_context(
        [61; 16],
        [62; 16],
        1,
        [63; 32],
        2,
        [64; 32],
        3,
        [65; 32],
        [99; 16],
        BOOT,
        BrokerSessionProtocolV1::Host,
        1,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        CLIENT_PROCESS,
        BROKER_PROCESS,
        protected_keys(&handshake.keys, None),
    );
    assert!(
        pending
            .admit_request(&request, REQUEST_ID, 65_536, &changed_context)
            .is_err()
    );
    let revoked_context = context_with_inactive_key(
        BrokerSessionProtocolV1::Host,
        1,
        &handshake.keys,
        Some((0, true, None)),
    );
    assert!(
        pending
            .admit_request(&request, REQUEST_ID, 65_536, &revoked_context)
            .is_err()
    );

    let (_, outcome_packet) = signed_outcome(
        &handshake,
        pending.transcript().session_binding(),
        &signed_request,
    );
    let outcome = decode_canonical_response_v1(&outcome_packet)
        .unwrap_or_else(|error| panic!("outcome decode failed: {error}"));
    let completed = pending
        .admit_outcome(&outcome, &handshake.context)
        .unwrap_or_else(|error| panic!("outcome verification failed: {error}"));
    let completed = match completed {
        BrokerOutcomeAdmissionV1::New { next_state, .. } => next_state,
        BrokerOutcomeAdmissionV1::ExactReplay(_) => {
            panic!("first outcome was classified as replay")
        }
    };
    assert!(!completed.has_outstanding_request());
    assert_eq!(completed.next_client_sequence(), 2);
    assert_eq!(completed.next_broker_sequence(), 2);

    let replay = completed
        .admit_outcome(&outcome, &handshake.context)
        .unwrap_or_else(|error| panic!("exact outcome replay failed: {error}"));
    assert!(matches!(replay, BrokerOutcomeAdmissionV1::ExactReplay(_)));
    assert!(completed.admit_outcome(&outcome, &changed_context).is_err());
    assert!(completed.admit_outcome(&outcome, &revoked_context).is_err());
}

#[test]
fn stop_and_wait_rejects_gaps_equivocation_and_second_outstanding_request() {
    let handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let transcript = transcript(&handshake);
    let state = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript)
        .unwrap_or_else(|error| panic!("traffic state failed: {error}"));
    let binding = state.transcript().session_binding();

    for method in [
        BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
    ] {
        let (_, packet) =
            signed_request_for_method_at(&handshake, binding, method, 1, REQUEST_ID, vec![1, 2, 3]);
        let request = decode_canonical_request_v1(&packet)
            .unwrap_or_else(|error| panic!("unnegotiated request decode failed: {error}"));
        assert_eq!(
            state.admit_request(&request, REQUEST_ID, 65_536, &handshake.context),
            Err(BrokerSessionSequenceError::Continuity)
        );
    }

    let (_, gap_packet) = signed_request_at(&handshake, binding, 2, REQUEST_ID, vec![1, 2, 3]);
    let gap = decode_canonical_request_v1(&gap_packet)
        .unwrap_or_else(|error| panic!("gap request decode failed: {error}"));
    assert_eq!(
        state.admit_request(&gap, REQUEST_ID, 65_536, &handshake.context),
        Err(BrokerSessionSequenceError::Gap)
    );

    let (signed, request_packet) = signed_request(&handshake, binding);
    let request = decode_canonical_request_v1(&request_packet)
        .unwrap_or_else(|error| panic!("request decode failed: {error}"));
    let pending = match state
        .admit_request(&request, REQUEST_ID, 65_536, &handshake.context)
        .unwrap_or_else(|error| panic!("request admission failed: {error}"))
    {
        BrokerRequestAdmissionV1::New { next_state, .. } => next_state,
        BrokerRequestAdmissionV1::ExactReplay(_) => panic!("first request became replay"),
    };

    let (_, changed_packet) = signed_request_at(&handshake, binding, 1, REQUEST_ID, vec![1, 2, 4]);
    let changed = decode_canonical_request_v1(&changed_packet)
        .unwrap_or_else(|error| panic!("changed request decode failed: {error}"));
    assert_eq!(
        pending.admit_request(&changed, REQUEST_ID, 65_536, &handshake.context),
        Err(BrokerSessionSequenceError::Equivocation)
    );

    let second_id = [18; 16];
    let (_, second_packet) = signed_request_at(&handshake, binding, 2, second_id, vec![4, 5, 6]);
    let second = decode_canonical_request_v1(&second_packet)
        .unwrap_or_else(|error| panic!("second request decode failed: {error}"));
    assert_eq!(
        pending.admit_request(&second, second_id, 65_536, &handshake.context),
        Err(BrokerSessionSequenceError::Outstanding)
    );

    let (_, outcome_gap_packet) = signed_outcome_at(&handshake, binding, &signed, 2, REQUEST_ID);
    let outcome_gap = decode_canonical_response_v1(&outcome_gap_packet)
        .unwrap_or_else(|error| panic!("gap outcome decode failed: {error}"));
    assert_eq!(
        pending.admit_outcome(&outcome_gap, &handshake.context),
        Err(BrokerSessionSequenceError::Gap)
    );
}

#[test]
fn canonical_protobuf_rejects_reorder_duplicate_unknown_and_trailing_bytes() {
    let handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let canonical = handshake.client_packet;
    assert!(decode_canonical_client_hello_v1(&canonical).is_ok());

    let contribution = 357;
    let split = canonical.len() - contribution;
    let mut reordered = canonical[split..].to_vec();
    reordered.extend_from_slice(&canonical[..split]);
    assert!(decode_canonical_client_hello_v1(&reordered).is_err());

    let mut duplicate = canonical.clone();
    duplicate.extend_from_slice(&canonical[split..]);
    assert!(decode_canonical_client_hello_v1(&duplicate).is_err());

    let mut unknown = canonical.clone();
    unknown.extend_from_slice(&[0xf8, 0x01, 0x01]);
    assert!(decode_canonical_client_hello_v1(&unknown).is_err());

    let mut trailing = canonical;
    trailing.push(0);
    assert!(decode_canonical_client_hello_v1(&trailing).is_err());
}

#[test]
fn authentication_fields_have_exact_tags_lengths_and_contributions() {
    let handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let transcript = transcript(&handshake);
    let (request, request_packet) = signed_request(&handshake, transcript.session_binding());
    let (outcome, outcome_packet) =
        signed_outcome(&handshake, transcript.session_binding(), &request);

    let client_artifact = handshake.client.to_canonical_bytes();
    let broker_artifact = handshake.broker.to_canonical_bytes();
    let request_artifact = request.to_canonical_bytes();
    let outcome_artifact = outcome.to_canonical_bytes();
    let cases = [
        (
            &handshake.client_packet,
            client_artifact.as_slice(),
            357usize,
            [0x3a, 0xe2, 0x02],
        ),
        (
            &handshake.broker_packet,
            broker_artifact.as_slice(),
            389,
            [0x42, 0x82, 0x03],
        ),
        (
            &request_packet,
            request_artifact.as_slice(),
            311,
            [0x2a, 0xb4, 0x02],
        ),
        (
            &outcome_packet,
            outcome_artifact.as_slice(),
            343,
            [0x3a, 0xd4, 0x02],
        ),
    ];
    for (packet, artifact, contribution, prefix) in cases {
        let offset = packet
            .windows(prefix.len())
            .position(|window| window == prefix)
            .unwrap_or_else(|| panic!("authentication tag and length are absent"));
        let field = &packet[offset..offset + contribution];
        assert_eq!(field[..3], prefix);
        assert_eq!(field.len(), contribution);
        assert_eq!(&field[3..], artifact);
    }
}

#[test]
fn request_and_outcome_projections_commit_nested_body_authority_error_and_tables() {
    let handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let transcript = transcript(&handshake);
    let state = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript)
        .unwrap_or_else(|error| panic!("traffic state failed: {error}"));
    let (signed_request, request_packet) =
        signed_request(&handshake, state.transcript().session_binding());

    let mut repeated_request_role = BrokerRequestEnvelope::decode_from_slice(&request_packet)
        .unwrap_or_else(|error| panic!("test request decode failed: {error}"));
    repeated_request_role.signed_session_request.clear();
    repeated_request_role
        .descriptors
        .push(BrokerDescriptorEntry {
            index: 1,
            role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER.into(),
            ..Default::default()
        });
    assert!(request_fields_digest_v1(&repeated_request_role).is_err());

    for mutation in 0..3 {
        let mut message = BrokerRequestEnvelope::decode_from_slice(&request_packet)
            .unwrap_or_else(|error| panic!("test request decode failed: {error}"));
        match mutation {
            0 => message.body.push(9),
            1 => {
                message.descriptors[0].role =
                    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT.into()
            }
            _ => message
                .authorization
                .as_option_mut()
                .unwrap_or_else(|| panic!("test authorization disappeared"))
                .broker_plan
                .push(9),
        }
        let changed = decode_canonical_request_v1(&message.encode_to_vec())
            .unwrap_or_else(|error| panic!("changed request was not canonical: {error}"));
        assert!(
            state
                .admit_request(&changed, REQUEST_ID, 65_536, &handshake.context)
                .is_err()
        );
    }

    let request = decode_canonical_request_v1(&request_packet)
        .unwrap_or_else(|error| panic!("request decode failed: {error}"));
    let pending = match state
        .admit_request(&request, REQUEST_ID, 65_536, &handshake.context)
        .unwrap_or_else(|error| panic!("request admission failed: {error}"))
    {
        BrokerRequestAdmissionV1::New { next_state, .. } => next_state,
        BrokerRequestAdmissionV1::ExactReplay(_) => panic!("new request became replay"),
    };
    let (_, outcome_packet) = signed_outcome(
        &handshake,
        pending.transcript().session_binding(),
        &signed_request,
    );
    let mut repeated_response_role = BrokerResponseEnvelope::decode_from_slice(&outcome_packet)
        .unwrap_or_else(|error| panic!("test outcome decode failed: {error}"));
    repeated_response_role.signed_session_outcome.clear();
    repeated_response_role.descriptors = vec![
        BrokerDescriptorEntry {
            index: 0,
            role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER.into(),
            ..Default::default()
        },
        BrokerDescriptorEntry {
            index: 1,
            role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER.into(),
            ..Default::default()
        },
    ];
    assert!(outcome_fields_digest_v1(&repeated_response_role).is_err());
    for mutation in 0..3 {
        let mut message = BrokerResponseEnvelope::decode_from_slice(&outcome_packet)
            .unwrap_or_else(|error| panic!("test outcome decode failed: {error}"));
        match mutation {
            0 => message
                .error
                .as_option_mut()
                .unwrap_or_else(|| panic!("test error disappeared"))
                .safe_message
                .push('!'),
            1 => {
                message
                    .error
                    .as_option_mut()
                    .unwrap_or_else(|| panic!("test error disappeared"))
                    .missing_feature
                    .as_option_mut()
                    .unwrap_or_else(|| panic!("test feature disappeared"))
                    .minor = 1
            }
            _ => {
                message.request_descriptor_dispositions[0].disposition =
                    BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_RETURNED.into()
            }
        }
        let changed = decode_canonical_response_v1(&message.encode_to_vec())
            .unwrap_or_else(|error| panic!("changed outcome was not canonical: {error}"));
        assert!(pending.admit_outcome(&changed, &handshake.context).is_err());
    }
}

#[test]
fn feature_version_and_role_key_distinctness_fail_closed() {
    let handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let mut client_message =
        aos_proto::aos::sandbox::local::v1::BrokerClientHello::decode_from_slice(
            &handshake.client_packet,
        )
        .unwrap_or_else(|error| panic!("test hello decode failed: {error}"));
    client_message.required_features[0].minor = 1;
    assert!(
        decode_canonical_client_hello_v1(&client_message.encode_to_vec()).is_err() || {
            let client = decode_canonical_client_hello_v1(&client_message.encode_to_vec())
                .unwrap_or_else(|error| panic!("mutated canonical hello failed early: {error}"));
            let broker = decode_canonical_server_hello_v1(&handshake.broker_packet)
                .unwrap_or_else(|error| panic!("broker hello failed: {error}"));
            verify_broker_session_transcript_v1(&client, &broker, &handshake.context).is_err()
        }
    );

    let mut unsorted = aos_proto::aos::sandbox::local::v1::BrokerClientHello::decode_from_slice(
        &handshake.client_packet,
    )
    .unwrap_or_else(|error| panic!("test hello decode failed: {error}"));
    unsorted.required_features.push(Feature {
        namespace: "aos.sandbox.runtime.linux-systemd".to_owned(),
        major: 1,
        minor: 0,
        ..Default::default()
    });
    assert!(decode_canonical_client_hello_v1(&unsorted.encode_to_vec()).is_err());

    let keys = keys();
    let repeated = [
        ProtectedBrokerSessionKeyV1::new(
            keys.signers[0].clone(),
            keys.signing[0].verifying_key().to_bytes(),
            10,
            20,
            false,
            None,
        )
        .unwrap_or_else(|error| panic!("test repeated key failed: {error}")),
        ProtectedBrokerSessionKeyV1::new(
            keys.signers[0].clone(),
            keys.signing[0].verifying_key().to_bytes(),
            10,
            20,
            false,
            None,
        )
        .unwrap_or_else(|error| panic!("test repeated key failed: {error}")),
        ProtectedBrokerSessionKeyV1::new(
            keys.signers[2].clone(),
            keys.signing[2].verifying_key().to_bytes(),
            12,
            22,
            false,
            None,
        )
        .unwrap_or_else(|error| panic!("test repeated key failed: {error}")),
        ProtectedBrokerSessionKeyV1::new(
            keys.signers[3].clone(),
            keys.signing[3].verifying_key().to_bytes(),
            13,
            23,
            false,
            None,
        )
        .unwrap_or_else(|error| panic!("test repeated key failed: {error}")),
    ];
    assert!(
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
            BrokerSessionProtocolV1::Host,
            1,
            0,
            Audience::AUDIENCE_NODE_CONTROLLER,
            CLIENT_PROCESS,
            BROKER_PROCESS,
            repeated,
        )
        .is_err()
    );
}

#[test]
fn authenticated_negotiation_rejects_downgrade_subset_version_role_and_ceiling_changes() {
    let make_handshake = handshake;
    let handshake = make_handshake(BrokerSessionProtocolV1::Host, 1);
    let client = BrokerClientHello::decode_from_slice(&handshake.client_packet)
        .unwrap_or_else(|error| panic!("client decode failed: {error}"));
    let broker = BrokerServerHello::decode_from_slice(&handshake.broker_packet)
        .unwrap_or_else(|error| panic!("broker decode failed: {error}"));
    assert!(verify_resigned_hellos(
        &handshake,
        client.clone(),
        broker.clone()
    ));

    let mut changed_client = client.clone();
    changed_client.required_features.remove(0);
    assert!(!verify_resigned_hellos(
        &handshake,
        changed_client,
        broker.clone()
    ));

    let mut changed_broker = broker.clone();
    changed_broker.features.remove(0);
    assert!(!verify_resigned_hellos(
        &handshake,
        client.clone(),
        changed_broker
    ));

    let mut changed_client = client.clone();
    changed_client.required_features = vec![feature()];
    let mut changed_broker = broker.clone();
    changed_broker.features = vec![feature()];
    assert!(!verify_resigned_hellos(
        &handshake,
        changed_client,
        changed_broker
    ));

    let mut changed_client = client.clone();
    changed_client.required_features.insert(
        0,
        Feature {
            namespace: "aos.sandbox.runtime.linux-systemd".to_owned(),
            major: 1,
            minor: 0,
            ..Default::default()
        },
    );
    assert!(!verify_resigned_hellos(
        &handshake,
        changed_client,
        broker.clone()
    ));

    let mut changed_client = client.clone();
    changed_client
        .required_methods
        .push(BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME.into());
    assert!(!verify_resigned_hellos(
        &handshake,
        changed_client,
        broker.clone()
    ));

    let mut changed_client = client.clone();
    changed_client.protocol_major = 2;
    let mut changed_broker = broker.clone();
    changed_broker.protocol_major = 2;
    assert!(!verify_resigned_hellos(
        &handshake,
        changed_client,
        changed_broker
    ));

    let mut changed_client = client.clone();
    changed_client.audience = Audience::AUDIENCE_ROOT_MOUNT.into();
    assert!(!verify_resigned_hellos(
        &handshake,
        changed_client,
        broker.clone()
    ));

    let mut changed_client = client.clone();
    changed_client.maximum_response_bytes = 4_095;
    assert!(!verify_resigned_hellos(
        &handshake,
        changed_client,
        broker.clone()
    ));
    let mut changed_broker = broker.clone();
    changed_broker.maximum_response_bytes = 4_095;
    assert!(!verify_resigned_hellos(
        &handshake,
        client.clone(),
        changed_broker
    ));
    let mut changed_broker = broker.clone();
    changed_broker.maximum_response_bytes = client.maximum_response_bytes + 1;
    assert!(!verify_resigned_hellos(
        &handshake,
        client.clone(),
        changed_broker
    ));
    let mut changed_broker = broker;
    changed_broker.maximum_request_bytes = 1_048_641;
    assert!(!verify_resigned_hellos(&handshake, client, changed_broker));

    let unsupported = make_handshake(BrokerSessionProtocolV1::Host, 2);
    let unsupported_client = decode_canonical_client_hello_v1(&unsupported.client_packet)
        .unwrap_or_else(|error| panic!("unsupported client decode failed: {error}"));
    let unsupported_broker = decode_canonical_server_hello_v1(&unsupported.broker_packet)
        .unwrap_or_else(|error| panic!("unsupported broker decode failed: {error}"));
    assert!(
        verify_broker_session_transcript_v1(
            &unsupported_client,
            &unsupported_broker,
            &unsupported.context,
        )
        .is_err()
    );

    let mount = make_handshake(BrokerSessionProtocolV1::Mount, 2);
    let mut mount_client = BrokerClientHello::decode_from_slice(&mount.client_packet)
        .unwrap_or_else(|error| panic!("mount client decode failed: {error}"));
    let source_feature = Feature {
        namespace: "aos.sandbox.mount.source-acquisition".to_owned(),
        major: 1,
        minor: 0,
        ..Default::default()
    };
    mount_client
        .required_features
        .insert(0, source_feature.clone());
    mount_client
        .required_methods
        .push(BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE.into());
    let mut mount_broker = BrokerServerHello::decode_from_slice(&mount.broker_packet)
        .unwrap_or_else(|error| panic!("mount broker decode failed: {error}"));
    mount_broker.features.insert(0, source_feature);
    mount_broker
        .methods
        .push(BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE.into());
    assert!(!verify_resigned_hellos(&mount, mount_client, mount_broker));

    let effect_handshake = make_handshake(BrokerSessionProtocolV1::Host, 1);
    let mut inventory_client =
        BrokerClientHello::decode_from_slice(&effect_handshake.client_packet)
            .unwrap_or_else(|error| panic!("effect client decode failed: {error}"));
    inventory_client.required_features = vec![feature()];
    inventory_client.required_methods =
        vec![BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME.into()];
    let mut effect_broker = BrokerServerHello::decode_from_slice(&effect_handshake.broker_packet)
        .unwrap_or_else(|error| panic!("effect broker decode failed: {error}"));
    effect_broker.methods = vec![
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME.into(),
        BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME.into(),
    ];
    let (client_packet, broker_packet) =
        resign_hellos(&effect_handshake, inventory_client, effect_broker);
    let client_hello = decode_canonical_client_hello_v1(&client_packet)
        .unwrap_or_else(|error| panic!("effect client canonical decode failed: {error}"));
    let broker_hello = decode_canonical_server_hello_v1(&broker_packet)
        .unwrap_or_else(|error| panic!("effect broker canonical decode failed: {error}"));
    let transcript = verify_broker_session_transcript_v1(
        &client_hello,
        &broker_hello,
        &effect_handshake.context,
    )
    .unwrap_or_else(|error| panic!("advertised-only effect transcript failed: {error}"));
    let state = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript)
        .unwrap_or_else(|error| panic!("advertised-only effect state failed: {error}"));
    let (_, effect_packet) =
        signed_request(&effect_handshake, state.transcript().session_binding());
    assert_eq!(
        state.decode_and_admit_request(
            &effect_packet,
            REQUEST_ID,
            4_096,
            &effect_handshake.context,
        ),
        Err(BrokerSessionSequenceError::Continuity)
    );
}

#[test]
fn equal_nonces_and_current_context_mismatches_fail_closed() {
    let handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let client = decode_canonical_client_hello_v1(&handshake.client_packet)
        .unwrap_or_else(|error| panic!("client decode failed: {error}"));
    let mut broker_message = BrokerServerHello::decode_from_slice(&handshake.broker_packet)
        .unwrap_or_else(|error| panic!("broker decode failed: {error}"));
    broker_message.signed_session_hello.clear();
    let fields = server_hello_fields_digest_v1(&broker_message)
        .unwrap_or_else(|error| panic!("broker projection failed: {error}"));
    let subject = BrokerHelloSubjectV1::new(
        NODE,
        BOOT,
        BrokerSessionProtocolV1::Host,
        1,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        BROKER_PROCESS,
        CLIENT_NONCE,
        handshake.context.protected_context_digest(),
        complete_signed_client_hello_digest_v1(&handshake.client),
        fields,
    )
    .unwrap_or_else(|error| panic!("equal nonce subject failed: {error}"));
    let broker = sign_broker_hello_v1(
        subject,
        handshake.keys.signers[1].clone(),
        &handshake.keys.signing[1],
    )
    .unwrap_or_else(|error| panic!("equal nonce signature failed: {error}"));
    broker_message.signed_session_hello = broker.to_canonical_bytes();
    let broker = decode_canonical_server_hello_v1(&broker_message.encode_to_vec())
        .unwrap_or_else(|error| panic!("equal nonce broker decode failed: {error}"));
    assert!(verify_broker_session_transcript_v1(&client, &broker, &handshake.context).is_err());

    let mismatched_context = ProtectedBrokerSessionVerificationContextV1::new(
        [61; 16],
        [62; 16],
        1,
        [63; 32],
        2,
        [64; 32],
        3,
        [65; 32],
        [99; 16],
        BOOT,
        BrokerSessionProtocolV1::Host,
        1,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        CLIENT_PROCESS,
        BROKER_PROCESS,
        handshake.context.keys().clone(),
    )
    .unwrap_or_else(|error| panic!("mismatched context failed construction: {error}"));
    let original_broker = decode_canonical_server_hello_v1(&handshake.broker_packet)
        .unwrap_or_else(|error| panic!("broker decode failed: {error}"));
    assert!(
        verify_broker_session_transcript_v1(&client, &original_broker, &mismatched_context)
            .is_err()
    );
}

#[test]
fn protected_context_digest_commits_every_component_key_and_currentness_shape() {
    let keys = keys();
    let base = context(BrokerSessionProtocolV1::Host, 1, &keys);
    let base_digest = base.protected_context_digest();
    let signed_handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let signed_client = decode_canonical_client_hello_v1(&signed_handshake.client_packet)
        .unwrap_or_else(|error| panic!("client decode failed: {error}"));
    for case in 0..16 {
        let changed = explicit_context(
            if case == 0 { [70; 16] } else { [61; 16] },
            if case == 1 { [71; 16] } else { [62; 16] },
            if case == 2 { 4 } else { 1 },
            if case == 3 { [72; 32] } else { [63; 32] },
            if case == 4 { 5 } else { 2 },
            if case == 5 { [73; 32] } else { [64; 32] },
            if case == 6 { 6 } else { 3 },
            if case == 7 { [74; 32] } else { [65; 32] },
            if case == 8 { [75; 16] } else { NODE },
            if case == 9 { [76; 16] } else { BOOT },
            if case == 10 {
                BrokerSessionProtocolV1::Storage
            } else {
                BrokerSessionProtocolV1::Host
            },
            if case == 11 { 2 } else { 1 },
            if case == 12 { 1 } else { 0 },
            if case == 13 {
                Audience::AUDIENCE_ROOT_MOUNT
            } else {
                Audience::AUDIENCE_NODE_CONTROLLER
            },
            if case == 14 { [77; 16] } else { CLIENT_PROCESS },
            if case == 15 { [78; 16] } else { BROKER_PROCESS },
            protected_keys(&keys, None),
        );
        assert_ne!(
            changed.protected_context_digest(),
            base_digest,
            "case {case}"
        );
        let staged = verify_client_hello_signature_v1(&signed_client, &changed.keys()[0])
            .unwrap_or_else(|error| panic!("unchanged client key failed: {error}"));
        assert!(
            verify_client_hello_context_v1(staged, &changed).is_err(),
            "staged context case {case}"
        );
    }

    for key_index in 0..4 {
        for substitution in 0..10 {
            let changed = explicit_context(
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
                BrokerSessionProtocolV1::Host,
                1,
                0,
                Audience::AUDIENCE_NODE_CONTROLLER,
                CLIENT_PROCESS,
                BROKER_PROCESS,
                protected_keys_with_substitution(&keys, key_index, substitution),
            );
            assert_ne!(
                changed.protected_context_digest(),
                base_digest,
                "key {key_index} substitution {substitution}"
            );
            if let Ok(staged) = verify_client_hello_signature_v1(&signed_client, &changed.keys()[0])
            {
                assert!(
                    verify_client_hello_context_v1(staged, &changed).is_err(),
                    "staged key {key_index} substitution {substitution}"
                );
            }
        }
    }
}

#[test]
fn revocation_supersession_and_cross_session_transplants_fail_closed() {
    let host_handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let client = decode_canonical_client_hello_v1(&host_handshake.client_packet)
        .unwrap_or_else(|error| panic!("client decode failed: {error}"));
    let broker = decode_canonical_server_hello_v1(&host_handshake.broker_packet)
        .unwrap_or_else(|error| panic!("broker decode failed: {error}"));
    for key_index in 0..4 {
        let revoked = context_with_inactive_key(
            BrokerSessionProtocolV1::Host,
            1,
            &host_handshake.keys,
            Some((key_index, true, None)),
        );
        assert!(
            verify_broker_session_transcript_v1(&client, &broker, &revoked).is_err(),
            "revoked role {key_index} remained usable"
        );

        let superseded = context_with_inactive_key(
            BrokerSessionProtocolV1::Host,
            1,
            &host_handshake.keys,
            Some((key_index, false, Some(99))),
        );
        assert!(
            verify_broker_session_transcript_v1(&client, &broker, &superseded).is_err(),
            "superseded role {key_index} remained usable"
        );
    }

    let host_transcript = transcript(&host_handshake);
    let host_state = BrokerSessionTrafficStateV1::from_provisional_transcript(host_transcript)
        .unwrap_or_else(|error| panic!("host traffic state failed: {error}"));
    let network = handshake(BrokerSessionProtocolV1::Network, 1);
    let network_transcript = transcript(&network);
    let (_, network_request) = signed_request(&network, network_transcript.session_binding());
    let transplanted = decode_canonical_request_v1(&network_request)
        .unwrap_or_else(|error| panic!("network request decode failed: {error}"));
    assert!(
        host_state
            .admit_request(&transplanted, REQUEST_ID, 65_536, &host_handshake.context)
            .is_err()
    );
}

#[test]
fn response_budget_is_exactly_fifteen_mebibytes() {
    assert_eq!(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES, 15 * 1024 * 1024);
    assert!(
        aos_sandbox_broker_session_protocol::projection::validate_authenticated_response_budget_v1(
            AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as u32,
            AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as u32,
        )
        .is_ok()
    );
    assert!(
        aos_sandbox_broker_session_protocol::projection::validate_authenticated_response_budget_v1(
            AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as u32 + 1,
            AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as u32,
        )
        .is_err()
    );
}

#[test]
fn traffic_admission_enforces_signed_request_and_per_request_response_bounds() {
    let handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let transcript = transcript(&handshake);
    let state = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript)
        .unwrap_or_else(|error| panic!("traffic state failed: {error}"));
    let binding = state.transcript().session_binding();
    let (signed_record, request_packet) = signed_request(&handshake, binding);
    let pending = match state
        .decode_and_admit_request(&request_packet, REQUEST_ID, 4_096, &handshake.context)
        .unwrap_or_else(|error| panic!("bounded request admission failed: {error}"))
    {
        BrokerRequestAdmissionV1::New { next_state, .. } => next_state,
        BrokerRequestAdmissionV1::ExactReplay(_) => panic!("first request became replay"),
    };

    let exact_response = signed_sized_success_outcome(&handshake, binding, &signed_record, 4_096);
    assert!(
        pending
            .decode_and_admit_outcome(&exact_response, &handshake.context)
            .is_ok()
    );
    let mut response_plus_one = exact_response;
    response_plus_one.push(0);
    assert_eq!(response_plus_one.len(), 4_097);
    assert_eq!(
        pending.decode_and_admit_outcome(&response_plus_one, &handshake.context),
        Err(BrokerSessionSequenceError::Projection(
            aos_sandbox_broker_session_protocol::BrokerSessionProjectionError::TooLarge
        ))
    );
    assert!(
        state
            .decode_and_admit_request(&request_packet, REQUEST_ID, 4_095, &handshake.context)
            .is_err()
    );

    let client = BrokerClientHello::decode_from_slice(&handshake.client_packet)
        .unwrap_or_else(|error| panic!("client decode failed: {error}"));
    let mut broker = BrokerServerHello::decode_from_slice(&handshake.broker_packet)
        .unwrap_or_else(|error| panic!("broker decode failed: {error}"));
    broker.maximum_request_bytes = request_packet.len() as u32;
    let (client_packet, broker_packet) = resign_hellos(&handshake, client.clone(), broker.clone());
    let client_hello = decode_canonical_client_hello_v1(&client_packet)
        .unwrap_or_else(|error| panic!("bounded client decode failed: {error}"));
    let broker_hello = decode_canonical_server_hello_v1(&broker_packet)
        .unwrap_or_else(|error| panic!("bounded broker decode failed: {error}"));
    let transcript =
        verify_broker_session_transcript_v1(&client_hello, &broker_hello, &handshake.context)
            .unwrap_or_else(|error| panic!("bounded transcript failed: {error}"));
    let state = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript)
        .unwrap_or_else(|error| panic!("bounded traffic state failed: {error}"));
    let (_, exact_request) = signed_request(&handshake, state.transcript().session_binding());
    assert_eq!(exact_request.len(), request_packet.len());
    assert!(
        state
            .decode_and_admit_request(&exact_request, REQUEST_ID, 4_096, &handshake.context)
            .is_ok()
    );

    broker.maximum_request_bytes = (request_packet.len() - 1) as u32;
    let (client_packet, broker_packet) = resign_hellos(&handshake, client, broker);
    let client_hello = decode_canonical_client_hello_v1(&client_packet)
        .unwrap_or_else(|error| panic!("smaller client decode failed: {error}"));
    let broker_hello = decode_canonical_server_hello_v1(&broker_packet)
        .unwrap_or_else(|error| panic!("smaller broker decode failed: {error}"));
    let transcript =
        verify_broker_session_transcript_v1(&client_hello, &broker_hello, &handshake.context)
            .unwrap_or_else(|error| panic!("smaller transcript failed: {error}"));
    let state = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript)
        .unwrap_or_else(|error| panic!("smaller traffic state failed: {error}"));
    let (_, oversized_request) = signed_request(&handshake, state.transcript().session_binding());
    assert_eq!(oversized_request.len(), request_packet.len());
    assert_eq!(
        state.decode_and_admit_request(&oversized_request, REQUEST_ID, 4_096, &handshake.context,),
        Err(BrokerSessionSequenceError::Projection(
            aos_sandbox_broker_session_protocol::BrokerSessionProjectionError::TooLarge
        ))
    );
}

#[test]
fn latest_completed_replay_survives_next_outstanding_and_commits_complete_response() {
    let handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let state = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript(&handshake))
        .unwrap_or_else(|error| panic!("traffic state failed: {error}"));
    let binding = state.transcript().session_binding();
    let (first_signed_request, first_request_packet) = signed_request(&handshake, binding);
    let first_pending = match state
        .decode_and_admit_request(&first_request_packet, REQUEST_ID, 8_192, &handshake.context)
        .unwrap_or_else(|error| panic!("first request failed: {error}"))
    {
        BrokerRequestAdmissionV1::New { next_state, .. } => next_state,
        BrokerRequestAdmissionV1::ExactReplay(_) => panic!("first request became replay"),
    };
    let first_outcome_packet =
        signed_sized_success_outcome(&handshake, binding, &first_signed_request, 5_000);
    let completed = match first_pending
        .decode_and_admit_outcome(&first_outcome_packet, &handshake.context)
        .unwrap_or_else(|error| panic!("first outcome failed: {error}"))
    {
        BrokerOutcomeAdmissionV1::New { next_state, .. } => next_state,
        BrokerOutcomeAdmissionV1::ExactReplay(_) => panic!("first outcome became replay"),
    };

    let second_id = [18; 16];
    let (second_signed_request, second_request_packet) =
        signed_request_at(&handshake, binding, 2, second_id, vec![4, 5, 6]);
    let second_pending = match completed
        .decode_and_admit_request(&second_request_packet, second_id, 4_096, &handshake.context)
        .unwrap_or_else(|error| panic!("second request failed: {error}"))
    {
        BrokerRequestAdmissionV1::New { next_state, .. } => next_state,
        BrokerRequestAdmissionV1::ExactReplay(_) => panic!("second request became replay"),
    };

    assert!(matches!(
        second_pending
            .decode_and_admit_request(&first_request_packet, REQUEST_ID, 8_192, &handshake.context,)
            .unwrap_or_else(|error| panic!("completed request replay failed: {error}")),
        BrokerRequestAdmissionV1::ExactReplay(_)
    ));
    assert!(matches!(
        second_pending
            .decode_and_admit_outcome(&first_outcome_packet, &handshake.context)
            .unwrap_or_else(|error| panic!("completed outcome replay failed: {error}")),
        BrokerOutcomeAdmissionV1::ExactReplay(_)
    ));

    for mutation in 0..5 {
        let mut message = BrokerResponseEnvelope::decode_from_slice(&first_outcome_packet)
            .unwrap_or_else(|error| panic!("completed outcome decode failed: {error}"));
        match mutation {
            0 => message.body.push(1),
            1 => {
                message.error = Some(BrokerError {
                    code: BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE.into(),
                    safe_message: "unavailable".to_owned(),
                    retryable: true,
                    ..Default::default()
                })
                .into()
            }
            2 => message.descriptors.push(BrokerDescriptorEntry {
                index: 0,
                role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT.into(),
                ..Default::default()
            }),
            3 => message
                .request_descriptor_dispositions
                .push(BrokerDescriptorDispositionEntry {
                    request_index: 0,
                    role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER.into(),
                    disposition: BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED
                        .into(),
                    ..Default::default()
                }),
            _ => message.request_id = vec![19; 16],
        }
        assert_eq!(
            second_pending.decode_and_admit_outcome(&message.encode_to_vec(), &handshake.context),
            Err(BrokerSessionSequenceError::Equivocation),
            "cleared completed outcome mutation {mutation} became exact replay"
        );
    }

    let (_, changed_first_request) =
        signed_request_at(&handshake, binding, 1, REQUEST_ID, vec![1, 2, 4]);
    assert!(
        second_pending
            .decode_and_admit_request(
                &changed_first_request,
                REQUEST_ID,
                8_192,
                &handshake.context,
            )
            .is_err()
    );

    let (_, second_outcome_packet) =
        signed_outcome_at(&handshake, binding, &second_signed_request, 2, second_id);
    let completed_second = match second_pending
        .decode_and_admit_outcome(&second_outcome_packet, &handshake.context)
        .unwrap_or_else(|error| panic!("second outcome failed: {error}"))
    {
        BrokerOutcomeAdmissionV1::New { next_state, .. } => next_state,
        BrokerOutcomeAdmissionV1::ExactReplay(_) => panic!("second outcome became replay"),
    };
    let stale_id = [20; 16];
    let (_, stale_packet) = signed_request_at(&handshake, binding, 1, stale_id, vec![7, 8, 9]);
    let stale = decode_canonical_request_v1(&stale_packet)
        .unwrap_or_else(|error| panic!("stale request decode failed: {error}"));
    assert_eq!(
        completed_second.admit_request(&stale, stale_id, 4_096, &handshake.context),
        Err(BrokerSessionSequenceError::Rollback)
    );

    for sequence in [u64::MAX - 1, u64::MAX] {
        let terminal_id = sequence.to_be_bytes().repeat(2);
        let terminal_id: [u8; 16] = terminal_id
            .try_into()
            .unwrap_or_else(|_| panic!("terminal request ID has wrong width"));
        let (_, terminal_packet) =
            signed_request_at(&handshake, binding, sequence, terminal_id, vec![7, 8, 9]);
        let terminal = decode_canonical_request_v1(&terminal_packet)
            .unwrap_or_else(|error| panic!("terminal request decode failed: {error}"));
        assert_eq!(
            completed_second.admit_request(&terminal, terminal_id, 4_096, &handshake.context,),
            Err(BrokerSessionSequenceError::Gap),
            "terminal sequence {sequence} bypassed public state sequencing"
        );
    }
}

#[test]
fn request_and_response_decoders_accept_exact_maxima_and_reject_plus_one() {
    let handshake = handshake(BrokerSessionProtocolV1::Host, 1);
    let transcript = transcript(&handshake);

    for (method, cleared_maximum) in [
        (
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            AUTHENTICATED_ORDINARY_REQUEST_CLEARED_MAXIMUM_BYTES,
        ),
        (
            BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT,
            AUTHENTICATED_HOST_QUERY_CLEARED_MAXIMUM_BYTES,
        ),
        (
            BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG,
            AUTHENTICATED_MOUNT_PREPARE_CATALOG_CLEARED_MAXIMUM_BYTES,
        ),
    ] {
        let mut message = BrokerRequestEnvelope {
            method: method.into(),
            body: vec![0x5a; cleared_maximum - 6],
            ..Default::default()
        };
        assert_eq!(message.encode_to_vec().len(), cleared_maximum);
        let fields = request_fields_digest_v1(&message)
            .unwrap_or_else(|error| panic!("maximum request projection failed: {error}"));
        let subject = BrokerRequestSubjectV1::new(
            transcript.session_binding(),
            CLIENT_PROCESS,
            1,
            REQUEST_ID,
            fields,
        )
        .unwrap_or_else(|error| panic!("maximum request subject failed: {error}"));
        let signed = sign_request_v1(
            method,
            subject,
            handshake.keys.signers[2].clone(),
            &handshake.keys.signing[2],
        )
        .unwrap_or_else(|error| panic!("maximum request signature failed: {error}"));
        message.signed_session_request = signed.to_canonical_bytes();
        let exact = message.encode_to_vec();
        assert_eq!(exact.len(), cleared_maximum + 311);
        assert!(decode_canonical_request_v1(&exact).is_ok());

        message.body.push(0x5a);
        let plus_one = message.encode_to_vec();
        assert_eq!(plus_one.len(), exact.len() + 1);
        assert!(decode_canonical_request_v1(&plus_one).is_err());
    }

    let (signed_request, _) = signed_request(&handshake, transcript.session_binding());
    let mut response = BrokerResponseEnvelope {
        request_id: REQUEST_ID.to_vec(),
        method: BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME.into(),
        body: vec![0x6b; AUTHENTICATED_RESPONSE_CLEARED_MAXIMUM_BYTES - 25],
        ..Default::default()
    };
    assert_eq!(
        response.encode_to_vec().len(),
        AUTHENTICATED_RESPONSE_CLEARED_MAXIMUM_BYTES
    );
    let fields = outcome_fields_digest_v1(&response)
        .unwrap_or_else(|error| panic!("maximum response projection failed: {error}"));
    let subject = BrokerOutcomeSubjectV1::new(
        transcript.session_binding(),
        BROKER_PROCESS,
        1,
        REQUEST_ID,
        complete_signed_request_digest_v1(&signed_request),
        fields,
    )
    .unwrap_or_else(|error| panic!("maximum response subject failed: {error}"));
    let signed = sign_outcome_v1(
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
        subject,
        handshake.keys.signers[3].clone(),
        &handshake.keys.signing[3],
    )
    .unwrap_or_else(|error| panic!("maximum response signature failed: {error}"));
    response.signed_session_outcome = signed.to_canonical_bytes();
    let exact = response.encode_to_vec();
    assert_eq!(exact.len(), AUTHENTICATED_RESPONSE_MAXIMUM_BYTES);
    assert!(decode_canonical_response_v1(&exact).is_ok());

    response.body.push(0x6b);
    let plus_one = response.encode_to_vec();
    assert_eq!(plus_one.len(), AUTHENTICATED_RESPONSE_MAXIMUM_BYTES + 1);
    assert!(decode_canonical_response_v1(&plus_one).is_err());
}

#[test]
fn independent_hex_vectors_are_stable() {
    let cases = [
        ("HOST", BrokerSessionProtocolV1::Host, 1),
        ("STORAGE", BrokerSessionProtocolV1::Storage, 1),
        ("MOUNT", BrokerSessionProtocolV1::Mount, 2),
        ("NETWORK", BrokerSessionProtocolV1::Network, 1),
    ];
    let mut actual = Vec::new();
    for (name, protocol, major) in cases {
        let handshake = handshake(protocol, major);
        let client = decode_canonical_client_hello_v1(&handshake.client_packet)
            .unwrap_or_else(|error| panic!("golden client decode failed: {error}"));
        let broker = decode_canonical_server_hello_v1(&handshake.broker_packet)
            .unwrap_or_else(|error| panic!("golden broker decode failed: {error}"));
        let transcript = verify_broker_session_transcript_v1(&client, &broker, &handshake.context)
            .unwrap_or_else(|error| panic!("golden transcript failed: {error}"));
        let (request, request_packet) = signed_request(&handshake, transcript.session_binding());
        let decoded_request = decode_canonical_request_v1(&request_packet)
            .unwrap_or_else(|error| panic!("golden request decode failed: {error}"));
        let (error_outcome, error_packet) =
            signed_outcome(&handshake, transcript.session_binding(), &request);
        let decoded_error = decode_canonical_response_v1(&error_packet)
            .unwrap_or_else(|error| panic!("golden error decode failed: {error}"));
        let (success_outcome, success_packet) =
            signed_success_outcome(&handshake, transcript.session_binding(), &request);
        let decoded_success = decode_canonical_response_v1(&success_packet)
            .unwrap_or_else(|error| panic!("golden success decode failed: {error}"));

        actual.extend([
            (
                format!("{name}_CLIENT"),
                hex::encode(handshake.client.to_canonical_bytes()),
            ),
            (
                format!("{name}_BROKER"),
                hex::encode(handshake.broker.to_canonical_bytes()),
            ),
            (
                format!("{name}_REQUEST"),
                hex::encode(request.to_canonical_bytes()),
            ),
            (
                format!("{name}_ERROR_OUTCOME"),
                hex::encode(error_outcome.to_canonical_bytes()),
            ),
            (
                format!("{name}_SUCCESS_OUTCOME"),
                hex::encode(success_outcome.to_canonical_bytes()),
            ),
            (
                format!("{name}_SIGNER_SET"),
                hex::encode(signer_set_digest_v1(&handshake.keys.signers)),
            ),
            (
                format!("{name}_PROTECTED_CONTEXT"),
                hex::encode(handshake.context.protected_context_digest()),
            ),
            (
                format!("{name}_CLIENT_FIELDS"),
                hex::encode(client.cleared_fields_digest()),
            ),
            (
                format!("{name}_SERVER_FIELDS"),
                hex::encode(broker.cleared_fields_digest()),
            ),
            (
                format!("{name}_REQUEST_FIELDS"),
                hex::encode(decoded_request.cleared_fields_digest()),
            ),
            (
                format!("{name}_ERROR_FIELDS"),
                hex::encode(decoded_error.cleared_fields_digest()),
            ),
            (
                format!("{name}_SUCCESS_FIELDS"),
                hex::encode(decoded_success.cleared_fields_digest()),
            ),
            (
                format!("{name}_CLIENT_COMPLETE"),
                hex::encode(complete_signed_client_hello_digest_v1(&handshake.client)),
            ),
            (
                format!("{name}_REQUEST_COMPLETE"),
                hex::encode(complete_signed_request_digest_v1(&request)),
            ),
            (
                format!("{name}_SESSION"),
                hex::encode(transcript.session_binding()),
            ),
        ]);
    }
    let expected = include_str!("fixtures/broker-session-v1.hex")
        .lines()
        .map(|line| {
            line.split_once('=')
                .unwrap_or_else(|| panic!("invalid golden line"))
        })
        .collect::<Vec<_>>();
    assert_eq!(actual.len(), expected.len());
    for ((actual_name, actual_hex), (expected_name, expected_hex)) in actual.iter().zip(expected) {
        assert_eq!(actual_name, expected_name);
        assert_eq!(actual_hex, expected_hex);
    }
}
