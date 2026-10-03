//! UNRUN historical DATA and live comparison parity vectors.
//!
//! Local keys create real canonical signed hellos/envelopes through the existing
//! engines. They are not fixed production pins, a current peer or floor custody.
//! Live-decoder peer/clock inputs appear only in explicit live parity tests.

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, BrokerClientHello, BrokerRequestEnvelope, BrokerServerHello, Feature,
    RequestHeader,
};
use aos_sandbox_broker_session_protocol::{
    BrokerClientHelloSubjectV1, BrokerHelloSubjectV1, BrokerRequestSubjectV1,
    BrokerSessionKeyUsageV1, BrokerSessionSignerReferenceV1, ProtectedBrokerSessionKeyV1,
    ProtectedBrokerSessionVerificationContextV1, client_hello_fields_digest_v1,
    complete_signed_client_hello_digest_v1, decode_canonical_client_hello_v1,
    decode_canonical_request_v1, decode_canonical_server_hello_v1,
    encode_signed_client_hello_packet_v1, encode_signed_request_packet_v1,
    encode_signed_server_hello_packet_v1, maximum_broker_session_request_bytes_v1,
    request_fields_digest_v1, server_hello_fields_digest_v1, sign_broker_hello_v1,
    sign_client_hello_v1, sign_request_v1, verify_broker_session_transcript_v1,
};
use aos_sandbox_core::{MediaType, ObjectDigest, PortableMediaType, descriptor_for_bytes};
use buffa::Message as _;
use ed25519_dalek::SigningKey;

use super::*;
use crate::{PeerCredentials, PeerPolicy};
use crate::nix_build::{
    NixExpectedOutputV2, NixStoreObjectV2, decode_nix_build_observation_v2,
    decode_nix_build_request_v2, decode_nix_build_response_v2,
};

const METHODS: [BrokerMethod; 3] = [
    BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2,
    BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2,
    BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2,
];

struct SignedFixture {
    transcript: VerifiedBrokerSessionTranscriptV1,
    traffic_key: SigningKey,
    traffic_signer: BrokerSessionSignerReferenceV1,
}

fn signed_fixture(nonce: u8) -> SignedFixture {
    let keys = std::array::from_fn::<_, 4, _>(|index| {
        SigningKey::from_bytes(&[21 + index as u8; 32])
    });
    let usages = [
        BrokerSessionKeyUsageV1::ClientHello,
        BrokerSessionKeyUsageV1::BrokerHello,
        BrokerSessionKeyUsageV1::ClientRecord,
        BrokerSessionKeyUsageV1::BrokerOutcome,
    ];
    let signers = std::array::from_fn::<_, 4, _>(|index| {
        BrokerSessionSignerReferenceV1::for_signing_key(
            [31 + index as u8; 16],
            1,
            [41 + index as u8; 32],
            [51 + index as u8; 16],
            1,
            usages[index],
            &keys[index],
        )
        .unwrap()
    });
    let protected = std::array::from_fn(|index| {
        ProtectedBrokerSessionKeyV1::new(
            signers[index].clone(),
            keys[index].verifying_key().to_bytes(),
            1,
            1,
            false,
            None,
        )
        .unwrap()
    });
    let context = ProtectedBrokerSessionVerificationContextV1::new(
        [61; 16],
        [62; 16],
        1,
        [63; 32],
        1,
        [64; 32],
        1,
        [65; 32],
        [11; 16],
        [12; 16],
        BrokerSessionProtocolV1::Nix,
        1,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        [13; 16],
        [14; 16],
        protected,
    )
    .unwrap();
    let features = [
        aos_sandbox_core::NIX_NARROWING_PROXY_FEATURE_NAMESPACE,
        "aos.sandbox.authentication.broker-session",
        "aos.sandbox.authorization.signed-plan-lease",
    ]
    .map(|namespace| Feature {
        namespace: namespace.to_owned(),
        major: 1,
        minor: 0,
        ..Default::default()
    })
    .to_vec();

    let client_message = BrokerClientHello {
        protocol_major: 1,
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        required_features: features.clone(),
        maximum_response_bytes: 65_536,
        required_methods: METHODS.map(Into::into).to_vec(),
        ..Default::default()
    };
    let client_subject = BrokerClientHelloSubjectV1::new(
        [11; 16],
        [12; 16],
        BrokerSessionProtocolV1::Nix,
        1,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        [13; 16],
        [nonce; 32],
        context.protected_context_digest(),
        client_hello_fields_digest_v1(&client_message).unwrap(),
    )
    .unwrap();
    let client = sign_client_hello_v1(client_subject, signers[0].clone(), &keys[0]).unwrap();
    let client_packet = encode_signed_client_hello_packet_v1(client_message, &client).unwrap();

    let broker_message = BrokerServerHello {
        protocol_major: 1,
        features,
        maximum_request_bytes: maximum_broker_session_request_bytes_v1(
            BrokerSessionProtocolV1::Nix,
        ) as u32,
        maximum_response_bytes: 65_536,
        methods: METHODS.map(Into::into).to_vec(),
        ..Default::default()
    };
    let broker_subject = BrokerHelloSubjectV1::new(
        [11; 16],
        [12; 16],
        BrokerSessionProtocolV1::Nix,
        1,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        [14; 16],
        [16; 32],
        context.protected_context_digest(),
        complete_signed_client_hello_digest_v1(&client),
        server_hello_fields_digest_v1(&broker_message).unwrap(),
    )
    .unwrap();
    let broker = sign_broker_hello_v1(broker_subject, signers[1].clone(), &keys[1]).unwrap();
    let broker_packet = encode_signed_server_hello_packet_v1(broker_message, &broker).unwrap();

    let client = decode_canonical_client_hello_v1(&client_packet).unwrap();
    let broker = decode_canonical_server_hello_v1(&broker_packet).unwrap();
    let transcript = verify_broker_session_transcript_v1(&client, &broker, &context).unwrap();
    SignedFixture {
        transcript,
        traffic_key: keys[2].clone(),
        traffic_signer: signers[2].clone(),
    }
}

fn request_wire(method: BrokerMethod) -> NixBuildRequestV2 {
    NixBuildRequestV2 {
        header: Some(RequestHeader {
            protocol_major: 1,
            protocol_minor: 0,
            request_id: vec![1; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 100,
            maximum_response_bytes: 4096,
            ..Default::default()
        })
        .into(),
        fence: Some(AssignmentFence {
            sandbox_id: vec![2; 16],
            incarnation_id: vec![3; 16],
            assignment_epoch: 1,
            desired_generation: 1,
            assignment_digest: vec![4; 32],
            ..Default::default()
        })
        .into(),
        operation_id: vec![5; 16],
        recipe_digest: vec![6; 32],
        domain_digest: vec![7; 32],
        disclosure_digest: vec![8; 32],
        environment_digest: vec![9; 32],
        parent_admission_digest: vec![10; 32],
        input_presentation_digest: vec![11; 32],
        expected_output_map_digest: vec![12; 32],
        build_transaction_digest: if method == METHODS[0] {
            Vec::new()
        } else {
            vec![13; 32]
        },
        original_realization_digest: if method == METHODS[2] {
            vec![14; 32]
        } else {
            Vec::new()
        },
        ..Default::default()
    }
}

fn envelope(
    fixture: &SignedFixture,
    method: BrokerMethod,
    body: Vec<u8>,
    request_id: [u8; 16],
) -> CanonicalBrokerRequestEnvelopeV1 {
    let message = BrokerRequestEnvelope {
        method: method.into(),
        body,
        ..Default::default()
    };
    let subject = BrokerRequestSubjectV1::new(
        fixture.transcript.session_binding(),
        fixture.transcript.client_process(),
        1,
        request_id,
        request_fields_digest_v1(&message).unwrap(),
    )
    .unwrap();
    let signed = sign_request_v1(
        method,
        subject,
        fixture.traffic_signer.clone(),
        &fixture.traffic_key,
    )
    .unwrap();
    let packet = encode_signed_request_packet_v1(message, &signed).unwrap();
    decode_canonical_request_v1(&packet).unwrap()
}

fn live(
    bytes: &[u8],
    method: BrokerMethod,
    now: u64,
) -> Result<super::super::ValidatedNixBuildRequestV2, ProtocolValidationError> {
    decode_nix_build_request_v2(
        bytes,
        method,
        PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(123),
        },
        PeerPolicy {
            uid: 1000,
            gid: Some(1000),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        now,
    )
}

fn object(name: char) -> NixStoreObjectV2 {
    NixStoreObjectV2 {
        path: format!("/nix/store/{}-{name}", "0".repeat(32)),
        portable: descriptor_for_bytes(
            MediaType::new(PortableMediaType::Content.as_str()).unwrap(),
            b"content",
        ),
        nar_sha256: ObjectDigest::from_bytes([15; 32]),
        nar_size: 64,
        references: Vec::new(),
        portable_objects: Vec::new(),
    }
}

fn observation(request: &HistoricalNixBuildRequestV2) -> NixBuildObservationV2 {
    let resolve = request.method == METHODS[0];
    NixBuildObservationV2 {
        method: request.method as u16,
        request: ObjectDigest::from_bytes(request.commitment),
        operation: [5; 16],
        recipe: ObjectDigest::from_bytes([6; 32]),
        domain: ObjectDigest::from_bytes([7; 32]),
        disclosure: ObjectDigest::from_bytes([8; 32]),
        environment: ObjectDigest::from_bytes([9; 32]),
        parent_admission: ObjectDigest::from_bytes([10; 32]),
        input_presentation: ObjectDigest::from_bytes([11; 32]),
        expected_output_map: ObjectDigest::from_bytes([12; 32]),
        build_transaction: (!resolve).then_some(ObjectDigest::from_bytes([13; 32])),
        original_realization: (request.method == METHODS[2]).then_some(ObjectDigest::from_bytes([14; 32])),
        attempt: (!resolve).then_some(ObjectDigest::from_bytes([16; 32])),
        retained_roots: (!resolve).then_some(ObjectDigest::from_bytes([17; 32])),
        inputs: vec![object('a')],
        outputs: if resolve {
            Vec::new()
        } else {
            vec![NixExpectedOutputV2 {
                name: "out".into(),
                object: object('b'),
            }]
        },
    }
}

#[test]
fn signed_originals_share_all_three_live_body_comparisons() {
    let fixture = signed_fixture(15);

    for method in METHODS {
        let body = request_wire(method).encode_to_vec();
        let original = envelope(&fixture, method, body.clone(), [1; 16]);
        let historical = decode_historical_nix_build_request_v2(&original, &fixture.transcript).unwrap();
        let admitted = live(&body, method, 1).unwrap();

        assert_eq!(historical.wire(), admitted.wire());
        assert_eq!(historical.fence(), admitted.fence());
        assert_eq!(historical.commitment(), admitted.commitment());
        assert_eq!(historical.request_id(), admitted.header().request_id());
        assert_eq!(historical.method(), method);
        assert_eq!(historical.session_binding(), fixture.transcript.session_binding());
        assert_eq!(historical.client_process(), fixture.transcript.client_process());
    }
}

#[test]
fn historical_deadline_is_preserved_without_renewing_live_admission() {
    let fixture = signed_fixture(15);
    let body = request_wire(METHODS[0]).encode_to_vec();
    let original = envelope(&fixture, METHODS[0], body.clone(), [1; 16]);

    let historical = decode_historical_nix_build_request_v2(&original, &fixture.transcript).unwrap();

    assert_eq!(historical.wire().header.as_option().unwrap().deadline_boottime_nanoseconds, 100);
    assert_eq!(live(&body, METHODS[0], 100).unwrap_err(), ProtocolValidationError::DeadlineExpired);
}

#[test]
fn historical_header_must_equal_the_original_signed_request_id() {
    let fixture = signed_fixture(15);
    let original = envelope(&fixture, METHODS[0], request_wire(METHODS[0]).encode_to_vec(), [2; 16]);

    assert_eq!(
        decode_historical_nix_build_request_v2(&original, &fixture.transcript).unwrap_err(),
        ProtocolValidationError::InvalidField("Nix historical header"),
    );
}

#[test]
fn different_real_signed_hello_pair_cannot_replace_original_session() {
    let fixture = signed_fixture(15);
    let foreign = signed_fixture(18);
    let original = envelope(&fixture, METHODS[0], request_wire(METHODS[0]).encode_to_vec(), [1; 16]);

    assert_ne!(fixture.transcript.session_binding(), foreign.transcript.session_binding());
    assert_eq!(
        decode_historical_nix_build_request_v2(&original, &foreign.transcript).unwrap_err(),
        ProtocolValidationError::InvalidField("Nix historical session"),
    );
}

#[test]
fn canonical_outer_packet_does_not_hide_changed_cleared_body_projection() {
    let fixture = signed_fixture(15);
    let original = envelope(&fixture, METHODS[0], request_wire(METHODS[0]).encode_to_vec(), [1; 16]);
    let mut changed = original.message().clone();
    let mut wire = request_wire(METHODS[0]);
    wire.environment_digest = vec![20; 32];
    changed.body = wire.encode_to_vec();
    changed.signed_session_request = original.signed_artifact().to_canonical_bytes();

    let changed = decode_canonical_request_v1(&changed.encode_to_vec()).unwrap();

    assert_eq!(
        decode_historical_nix_build_request_v2(&changed, &fixture.transcript).unwrap_err(),
        ProtocolValidationError::InvalidField("Nix historical session"),
    );
}

#[test]
fn historical_header_rejects_zero_deadline_foreign_audience_and_response_overflow() {
    let fixture = signed_fixture(15);
    let mut zero = request_wire(METHODS[0]);
    zero.header.get_or_insert_default().deadline_boottime_nanoseconds = 0;
    let mut foreign = request_wire(METHODS[0]);
    foreign.header.get_or_insert_default().audience = Audience::AUDIENCE_ROOT_MOUNT.into();
    let mut excess = request_wire(METHODS[0]);
    excess.header.get_or_insert_default().maximum_response_bytes = 65_537;

    for (wire, expected) in [
        (zero, ProtocolValidationError::DeadlineExpired),
        (foreign, ProtocolValidationError::InvalidField("Nix historical audience")),
        (excess, ProtocolValidationError::InvalidResponseBound),
    ] {
        let original = envelope(&fixture, METHODS[0], wire.encode_to_vec(), [1; 16]);
        assert_eq!(
            decode_historical_nix_build_request_v2(&original, &fixture.transcript).unwrap_err(),
            expected,
        );
    }
}

#[test]
fn shared_wire_decoder_rejects_unknown_fields_before_missing_header() {
    let fixture = signed_fixture(15);
    let unknown = vec![0x78, 1];
    let original = envelope(&fixture, METHODS[0], unknown.clone(), [1; 16]);

    assert_eq!(live(&unknown, METHODS[0], 1).unwrap_err(), ProtocolValidationError::UnknownFields);
    assert_eq!(
        decode_historical_nix_build_request_v2(&original, &fixture.transcript).unwrap_err(),
        ProtocolValidationError::UnknownFields,
    );
}

#[test]
fn live_size_method_and_deadline_error_order_remains_closed() {
    let oversized = vec![0; super::super::NIX_REQUEST_MAXIMUM_BYTES_V2 + 1];
    assert_eq!(
        live(&oversized, BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME, 1).unwrap_err(),
        ProtocolValidationError::RequestTooLarge,
    );
    assert_eq!(
        live(&[0xff], BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME, 1).unwrap_err(),
        ProtocolValidationError::MethodMismatch,
    );

    let mut wire = request_wire(METHODS[0]);
    wire.fence = None.into();
    wire.operation_id.clear();
    assert_eq!(
        live(&wire.encode_to_vec(), METHODS[0], 100).unwrap_err(),
        ProtocolValidationError::DeadlineExpired,
    );
    assert_eq!(
        live(&wire.encode_to_vec(), METHODS[0], 1).unwrap_err(),
        ProtocolValidationError::MissingField("fence"),
    );
}

#[test]
fn all_three_responses_and_observations_use_the_same_comparison_engine() {
    let fixture = signed_fixture(15);

    for method in METHODS {
        let body = request_wire(method).encode_to_vec();
        let original = envelope(&fixture, method, body.clone(), [1; 16]);
        let historical = decode_historical_nix_build_request_v2(&original, &fixture.transcript).unwrap();
        let admitted = live(&body, method, 1).unwrap();
        let observation = observation(&historical).canonical_bytes().unwrap();
        let response = NixBuildResponseV2 {
            request_id: vec![1; 16],
            recipe_digest: vec![6; 32],
            domain_digest: vec![7; 32],
            recipe_admission: if method == METHODS[0] { vec![1] } else { Vec::new() },
            observation: observation.clone(),
            ..Default::default()
        }.encode_to_vec();

        assert_eq!(
            decode_historical_nix_build_response_v2(&response, &historical, method),
            decode_nix_build_response_v2(&response, &admitted, method),
        );
        assert!(decode_historical_nix_build_response_v2(&response, &historical, method).is_ok());
        assert_eq!(
            decode_historical_nix_build_observation_v2(&observation, &historical),
            decode_nix_build_observation_v2(&observation, &admitted),
        );
    }
}

#[test]
fn response_size_then_method_precedence_matches_both_wrappers() {
    let fixture = signed_fixture(15);
    let body = request_wire(METHODS[0]).encode_to_vec();
    let original = envelope(&fixture, METHODS[0], body.clone(), [1; 16]);
    let historical = decode_historical_nix_build_request_v2(&original, &fixture.transcript).unwrap();
    let admitted = live(&body, METHODS[0], 1).unwrap();
    let oversized = vec![0; super::super::NIX_RESPONSE_MAXIMUM_BYTES_V2 + 1];

    for (bytes, expected) in [
        (oversized.as_slice(), ProtocolValidationError::ResponseTooLarge),
        (&[0xff][..], ProtocolValidationError::MethodMismatch),
    ] {
        assert_eq!(decode_historical_nix_build_response_v2(bytes, &historical, METHODS[1]).unwrap_err(), expected);
        assert_eq!(decode_nix_build_response_v2(bytes, &admitted, METHODS[1]).unwrap_err(), expected);
    }
}

#[test]
fn canonical_observation_substitution_is_rejected_by_both_wrappers() {
    let fixture = signed_fixture(15);
    let body = request_wire(METHODS[2]).encode_to_vec();
    let original = envelope(&fixture, METHODS[2], body.clone(), [1; 16]);
    let historical = decode_historical_nix_build_request_v2(&original, &fixture.transcript).unwrap();
    let admitted = live(&body, METHODS[2], 1).unwrap();
    let mut changed = observation(&historical);
    changed.environment = ObjectDigest::from_bytes([20; 32]);
    let bytes = changed.canonical_bytes().unwrap();

    let expected = ProtocolValidationError::InvalidField("Nix observation original coordinates");
    assert_eq!(decode_historical_nix_build_observation_v2(&bytes, &historical).unwrap_err(), expected);
    assert_eq!(decode_nix_build_observation_v2(&bytes, &admitted).unwrap_err(), expected);
}

#[test]
fn method_specific_effect_coordinates_and_commitments_are_not_interchangeable() {
    let fixture = signed_fixture(15);
    let body = request_wire(METHODS[1]).encode_to_vec();
    let original = envelope(&fixture, METHODS[0], body.clone(), [1; 16]);

    assert_eq!(
        decode_historical_nix_build_request_v2(&original, &fixture.transcript).unwrap_err(),
        ProtocolValidationError::InvalidField("resolve effect coordinates"),
    );
    assert_eq!(
        live(&body, METHODS[0], 1).unwrap_err(),
        ProtocolValidationError::InvalidField("resolve effect coordinates"),
    );

    let mut changed = request_wire(METHODS[1]);
    changed.environment_digest = vec![20; 32];
    let before = live(&body, METHODS[1], 1).unwrap();
    let after = live(&changed.encode_to_vec(), METHODS[1], 1).unwrap();
    assert_ne!(before.commitment(), after.commitment());
}

#[test]
fn historical_body_ceiling_precedes_wire_and_original_version_checks() {
    let fixture = signed_fixture(15);
    let oversized = vec![0; super::super::NIX_REQUEST_MAXIMUM_BYTES_V2 + 1];
    let original = envelope(&fixture, METHODS[0], oversized, [1; 16]);

    assert_eq!(
        decode_historical_nix_build_request_v2(&original, &fixture.transcript).unwrap_err(),
        ProtocolValidationError::RequestTooLarge,
    );

    let mut foreign = request_wire(METHODS[0]);
    foreign.header.get_or_insert_default().protocol_major = 2;
    foreign.fence = None.into();
    let original = envelope(&fixture, METHODS[0], foreign.encode_to_vec(), [1; 16]);

    assert!(matches!(
        decode_historical_nix_build_request_v2(&original, &fixture.transcript),
        Err(ProtocolValidationError::Protocol(_)),
    ));
}

#[test]
fn canonical_response_coordinates_and_recipe_presence_preserve_live_errors() {
    let fixture = signed_fixture(15);
    let body = request_wire(METHODS[0]).encode_to_vec();
    let original = envelope(&fixture, METHODS[0], body.clone(), [1; 16]);
    let historical = decode_historical_nix_build_request_v2(&original, &fixture.transcript).unwrap();
    let admitted = live(&body, METHODS[0], 1).unwrap();
    let response = NixBuildResponseV2 {
        request_id: vec![1; 16],
        recipe_digest: vec![6; 32],
        domain_digest: vec![7; 32],
        recipe_admission: vec![1],
        observation: observation(&historical).canonical_bytes().unwrap(),
        ..Default::default()
    };
    let mut request_id = response.clone();
    request_id.request_id = vec![2; 16];
    let mut domain = response.clone();
    domain.domain_digest = vec![20; 32];
    let mut recipe = response;
    recipe.recipe_admission.clear();

    for changed in [request_id, domain, recipe] {
        let bytes = changed.encode_to_vec();
        let expected = ProtocolValidationError::InvalidField("Nix original response");
        assert_eq!(
            decode_historical_nix_build_response_v2(&bytes, &historical, METHODS[0]).unwrap_err(),
            expected,
        );
        assert_eq!(
            decode_nix_build_response_v2(&bytes, &admitted, METHODS[0]).unwrap_err(),
            expected,
        );
    }
}
