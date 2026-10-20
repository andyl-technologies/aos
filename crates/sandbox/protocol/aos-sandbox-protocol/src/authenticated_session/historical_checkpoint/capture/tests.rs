//! Real signed DATA regressions; no current-session or protected-owner fixture.

use super::*;
use aos_sandbox_api::aos::sandbox::local::v1::{Audience, BrokerClientHello, BrokerServerHello, Feature, BrokerMethod};
use aos_sandbox_broker_session_protocol::{
    BrokerClientHelloSubjectV1, BrokerHelloSubjectV1, BrokerSessionKeyUsageV1,
    BrokerSessionSignerReferenceV1, ProtectedBrokerSessionKeyV1, BrokerSessionProtocolV1,
    client_hello_fields_digest_v1, complete_signed_client_hello_digest_v1,
    encode_signed_client_hello_packet_v1, encode_signed_server_hello_packet_v1,
    maximum_broker_session_request_bytes_v1, server_hello_fields_digest_v1,
    sign_broker_hello_v1, sign_client_hello_v1,
};
use ed25519_dalek::SigningKey;

const METHODS: [BrokerMethod; 3] = [
    BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2,
    BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2,
    BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2,
];

fn signed_checkpoint(nonce: u8) -> HistoricalSessionCheckpointV1 {
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
        aos_sandbox_model::NIX_NARROWING_PROXY_FEATURE_NAMESPACE,
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
    HistoricalSessionCheckpointV1::new(
        context, &client_packet, &broker_packet,
        PeerCredentials { uid: 1000, gid: 1000, pid: Some(123) }, &transcript,
    ).unwrap()
}

#[test]
fn ordinary_and_retained_signed_checkpoint_outputs_agree_without_copying_taken_vec() {
    let checkpoint = signed_checkpoint(15);
    let ordinary = checkpoint.encode().unwrap();
    let mut encode = HistoricalSessionCheckpointEncodeCaptureV1::new();
    checkpoint.encode_retaining(&mut encode).unwrap();
    let original_pointer = encode.encoded().unwrap().as_ptr();
    let taken = encode.take_encoded_once().unwrap();

    assert_eq!(taken, ordinary);
    assert_eq!(taken.as_ptr(), original_pointer);
    assert!(encode.take_encoded_once().is_err());

    let mut decode = HistoricalSessionCheckpointDecodeCaptureV1::new();
    HistoricalSessionCheckpointV1::decode_retaining(&ordinary, &mut decode).unwrap();
    let decoded = decode.take_checkpoint_once().unwrap();
    assert_eq!(decoded, HistoricalSessionCheckpointV1::decode(&ordinary).unwrap());
    assert!(decode.take_checkpoint_once().is_err());

    let mut verify = HistoricalSessionCheckpointVerifyCaptureV1::new();
    decoded.verify_retaining(&mut verify).unwrap();
    assert_eq!(verify.transcript().unwrap(), &decoded.verify().unwrap());
    assert_eq!(verify.take_transcript_once().unwrap(), checkpoint.verify().unwrap());
}

#[test]
fn canonical_digest_mismatch_keeps_checkpoint_encoding_and_same_original_cause() {
    let checkpoint = signed_checkpoint(15);
    let valid = checkpoint.encode().unwrap();
    let mut changed = valid.clone();
    *changed.last_mut().unwrap() ^= 1;
    let mut captured = HistoricalSessionCheckpointDecodeCaptureV1::new();

    assert_eq!(HistoricalSessionCheckpointV1::decode(&changed), Err(HistoricalCheckpointErrorV1::Invalid));
    assert!(HistoricalSessionCheckpointV1::decode_retaining(&changed, &mut captured).is_err());
    assert_eq!(captured.checkpoint(), Some(&checkpoint));
    assert_eq!(captured.encode.encoded(), Some(valid.as_slice()));
    let pointer = captured.encode.encoded().unwrap().as_ptr();
    let original = captured.canonical.as_ref().unwrap().as_ref().unwrap_err()
        as *const HistoricalCheckpointErrorV1;
    assert!(std::ptr::eq(captured.failure().unwrap().downcast_ref::<HistoricalCheckpointErrorV1>().unwrap(), original));

    assert!(HistoricalSessionCheckpointV1::decode_retaining(&valid, &mut captured).is_err());
    assert_eq!(captured.encode.encoded().unwrap().as_ptr(), pointer);
    assert!(std::ptr::eq(captured.failure().unwrap().downcast_ref::<HistoricalCheckpointErrorV1>().unwrap(), original));
}

#[test]
fn malformed_broker_keeps_real_verified_client_and_actual_projection_refusal() {
    let mut checkpoint = signed_checkpoint(15);
    checkpoint.broker_hello = vec![0x82, 0x80];
    let bytes = checkpoint.encode().unwrap();
    let mut captured = HistoricalSessionCheckpointDecodeCaptureV1::new();

    assert!(HistoricalSessionCheckpointV1::decode_retaining(&bytes, &mut captured).is_err());
    assert!(captured.verify.client.is_some());
    assert!(captured.verify.broker.is_none());
    assert_eq!(captured.checkpoint(), Some(&checkpoint));
    let original = captured.verify.broker_capture.failure().unwrap()
        as *const aos_sandbox_broker_session_protocol::projection::BrokerSessionProjectionError;
    assert!(std::ptr::eq(captured.failure().unwrap()
        .downcast_ref::<aos_sandbox_broker_session_protocol::projection::BrokerSessionProjectionError>().unwrap(), original));
    assert!(captured.encode.encoded().is_none());
}

#[test]
fn encoder_keeps_reached_context_but_bounded_frontier_refuses_before_it() {
    let mut checkpoint = signed_checkpoint(15);
    checkpoint.peer.pid = Some(0);
    let mut invalid = HistoricalSessionCheckpointEncodeCaptureV1::new();
    let mut before_context = HistoricalSessionCheckpointEncodeCaptureV1::new();

    assert!(checkpoint.encode_retaining(&mut invalid).is_err());
    assert_eq!(invalid.context.as_ref().unwrap().len(),
        ProtectedBrokerSessionVerificationContextV1::checkpoint_encoded_bytes_v1());
    assert!(invalid.encoded.is_none());
    assert!(checkpoint.encode_bounded_retaining(1, &mut before_context).is_err());
    assert!(before_context.context.is_none());
    assert_eq!(checkpoint.encode_bounded(1), Err(HistoricalCheckpointErrorV1::Invalid));
}

#[test]
fn receiving_helpers_cover_small_inputs_and_refuse_checked_overflow() {
    let checkpoint = signed_checkpoint(15);
    let extent = checkpoint.client_hello.len() + checkpoint.broker_hello.len();
    let bound = HistoricalSessionCheckpointDecodeCaptureV1::receiving_nonprojection_heap_bytes_v1(extent).unwrap();

    assert!(bound >= extent + checkpoint.encode().unwrap().len());
    assert!(HistoricalSessionCheckpointDecodeCaptureV1::receiving_metadata_cells_v1().unwrap() > 0);
    assert!(HistoricalSessionCheckpointVerifyCaptureV1::receiving_table_metadata_cells_v1(extent).unwrap() >= extent);
    assert!(HistoricalSessionCheckpointDecodeCaptureV1::receiving_nonprojection_heap_bytes_v1(usize::MAX).is_none());
}


#[test]
fn retained_constructor_matches_ordinary_and_moves_the_same_checkpoint_buffers() {
    let original = signed_checkpoint(15);
    let transcript = original.verify().unwrap();
    let mut construction = HistoricalSessionCheckpointConstructionCaptureV1::new();

    HistoricalSessionCheckpointV1::new_retaining(
        original.context.clone(), &original.client_hello, &original.broker_hello,
        original.peer, &transcript, &mut construction,
    ).unwrap();
    let client_pointer = construction.provisional_checkpoint().unwrap().client_hello.as_ptr();
    let completed = construction.take_checkpoint_once().unwrap();

    assert_eq!(completed, original);
    assert_eq!(completed.client_hello.as_ptr(), client_pointer);
    assert!(construction.take_checkpoint_once().is_err());
}

#[test]
fn retained_constructor_keeps_provisional_bytes_and_first_nested_projection_cause() {
    let original = signed_checkpoint(15);
    let transcript = original.verify().unwrap();
    let malformed = [0x82, 0x80];
    let mut construction = HistoricalSessionCheckpointConstructionCaptureV1::new();

    assert!(HistoricalSessionCheckpointV1::new_retaining(
        original.context.clone(), &original.client_hello, &malformed,
        original.peer, &transcript, &mut construction,
    ).is_err());
    let provisional = construction.provisional_checkpoint().unwrap();
    assert_eq!(provisional.client_hello, original.client_hello);
    assert_eq!(provisional.broker_hello, malformed);
    let original_cause = construction.failure().unwrap()
        .downcast_ref::<aos_sandbox_broker_session_protocol::projection::BrokerSessionProjectionError>()
        .unwrap() as *const _;

    assert!(HistoricalSessionCheckpointV1::new_retaining(
        original.context.clone(), &original.client_hello, &original.broker_hello,
        original.peer, &transcript, &mut construction,
    ).is_err());
    assert!(construction.take_checkpoint_once().is_err());
    assert_eq!(construction.provisional_checkpoint().unwrap().broker_hello, malformed);
    assert!(std::ptr::eq(construction.failure().unwrap()
        .downcast_ref::<aos_sandbox_broker_session_protocol::projection::BrokerSessionProjectionError>()
        .unwrap(), original_cause));
}

#[test]
fn retained_constructor_refuses_a_different_valid_transcript_like_ordinary() {
    let original = signed_checkpoint(15);
    // This valid client nonce must differ from the fixture broker nonce [16; 32].
    let other = signed_checkpoint(17).verify().unwrap();
    let mut construction = HistoricalSessionCheckpointConstructionCaptureV1::new();

    assert_eq!(HistoricalSessionCheckpointV1::new(
        original.context.clone(), &original.client_hello, &original.broker_hello,
        original.peer, &other,
    ), Err(HistoricalCheckpointErrorV1::Invalid));
    assert!(HistoricalSessionCheckpointV1::new_retaining(
        original.context.clone(), &original.client_hello, &original.broker_hello,
        original.peer, &other, &mut construction,
    ).is_err());
    assert_eq!(construction.provisional_checkpoint(), Some(&original));
    assert!(construction.failure().unwrap().is::<HistoricalCheckpointErrorV1>());
}
