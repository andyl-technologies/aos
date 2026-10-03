//! Pure original-history DATA vectors, authored and UNRUN.
//!
//! Literal archive/bundle framing is assembled independently of the production
//! encoder. Fixed test keys sign inert historical packets only. No fixture
//! opens a journal, descriptor, clock, live endpoint or TPM, or creates an owner.
//! The signed fixture deliberately lacks valid method-37 body/authorization
//! semantics: authentic traffic alone must not pass the selected original join.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerClientHello, BrokerRequestEnvelope, BrokerServerHello, Feature,
};
use aos_sandbox_broker_session_protocol as broker;
use broker::manifest::BrokerSessionManifestKeyPinV1;
use ed25519_dalek::SigningKey;

use super::*;

const ORIGINAL_ID: [u8; 16] = [7; 16];
const NODE: [u8; 16] = [11; 16];

fn literal_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(domain).chain_update(bytes).finalize().into()
}

fn reseal(bytes: &mut [u8], domain: &[u8]) {
    let end = bytes.len() - 32;
    let checksum = literal_hash(domain, &bytes[..end]);
    bytes[end..].copy_from_slice(&checksum);
}

fn literal_archive(magic: &[u8; 8], request_id: [u8; 16], history: &[u8]) -> Vec<u8> {
    let domain: &[u8] = match magic {
        b"AOSHAR01" => b"aos.sandbox.broker-session.host-argument-archive-value.v1\0",
        b"AOSHTA01" => b"aos.sandbox.broker-session.host-terminal-archive.v1\0",
        _ => panic!("closed test archive purpose"),
    };
    let mut frame = Vec::new();
    frame.extend_from_slice(magic);
    frame.extend_from_slice(&[0, 1]);
    frame.extend_from_slice(&request_id);
    frame.extend_from_slice(&(history.len() as u32).to_be_bytes());
    frame.extend_from_slice(history);
    let checksum = literal_hash(domain, &frame);
    frame.extend_from_slice(&checksum);
    frame
}

fn literal_bundle(original: &[u8], terminal: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AOSCFH04");
    bytes.extend_from_slice(&[0, 4, 0, 0]);
    bytes.extend_from_slice(&(original.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&(terminal.len() as u32).to_be_bytes());
    bytes.extend_from_slice(original);
    bytes.extend_from_slice(terminal);
    let checksum = literal_hash(b"aos.sandbox.create-failure.original-histories.v4\0", &bytes);
    bytes.extend_from_slice(&checksum);
    bytes
}

fn small_bundle() -> Vec<u8> {
    literal_bundle(
        &literal_archive(b"AOSHAR01", ORIGINAL_ID, b"H"),
        &literal_archive(b"AOSHTA01", ORIGINAL_ID, b"T"),
    )
}

#[test]
fn literal_offsets_and_domains_match_exact_borrowed_codec() {
    let bytes = small_bundle();
    let decoded = FailedCreateOriginalHistoriesDataV4::decode(&bytes).unwrap();

    assert_eq!(bytes.len(), 20 + 63 + 63 + 32);
    assert_eq!(&bytes[..12], b"AOSCFH04\0\x04\0\0");
    assert_eq!(&bytes[12..16], &63_u32.to_be_bytes());
    assert_eq!(&bytes[16..20], &63_u32.to_be_bytes());
    assert_eq!(&decoded.original_archive()[8..10], &[0, 1]);
    assert_eq!(&decoded.original_archive()[10..26], &ORIGINAL_ID);
    assert_eq!(&decoded.original_archive()[26..30], &1_u32.to_be_bytes());
    assert_eq!(decoded.original_archive()[30], b'H');
    assert_eq!(decoded.original_request_id(), ORIGINAL_ID);
    assert_eq!(decoded.original_archive().as_ptr(), bytes[20..].as_ptr());
    assert_eq!(decoded.terminal_archive().as_ptr(), bytes[83..].as_ptr());
    assert_eq!(encode_failed_create_original_histories_v4(
        decoded.original_archive(), decoded.terminal_archive(),
    ).unwrap(), bytes);
}

#[test]
fn outer_header_lengths_checksum_truncation_and_trailing_refuse() {
    let original = small_bundle();
    for offset in [0, 8, 9, 10, 11, 12, 15, 16, 19] {
        let mut changed = original.clone();
        changed[offset] ^= 1;
        reseal(&mut changed, BUNDLE_DOMAIN);
        assert!(FailedCreateOriginalHistoriesDataV4::decode(&changed).is_err(), "offset {offset}");
    }
    for length in 0..original.len() {
        assert!(FailedCreateOriginalHistoriesDataV4::decode(&original[..length]).is_err());
    }
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(FailedCreateOriginalHistoriesDataV4::decode(&trailing).is_err());
    let mut corrupt = original;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(FailedCreateOriginalHistoriesDataV4::decode(&corrupt).is_err());
}

#[test]
fn shared_sizing_checks_u32_overflow_empty_and_exact_aggregate_limit() {
    assert_eq!(FAILED_CREATE_ORIGINAL_HISTORIES_MAXIMUM_BYTES_V4, 1_048_576);
    assert_eq!(failed_create_original_histories_encoded_len_v4(63, 63).unwrap(), 178);
    assert_eq!(failed_create_original_histories_encoded_len_v4(1, 1_048_523).unwrap(), 1_048_576);
    for pair in [(0, 1), (1, 0), (1, 1_048_524), (usize::MAX, 1), (1, usize::MAX)] {
        assert!(failed_create_original_histories_encoded_len_v4(pair.0, pair.1).is_err());
    }
    let mut impossible = small_bundle();
    impossible[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    reseal(&mut impossible, BUNDLE_DOMAIN);
    assert!(FailedCreateOriginalHistoriesDataV4::decode(&impossible).is_err());
}

#[test]
fn exact_one_mib_carrier_is_accepted_but_one_more_byte_is_not() {
    let original = literal_archive(b"AOSHAR01", ORIGINAL_ID, &vec![1; 1_048_399]);
    let terminal = literal_archive(b"AOSHTA01", ORIGINAL_ID, b"T");
    let bytes = literal_bundle(&original, &terminal);
    assert_eq!(bytes.len(), 1_048_576);
    assert!(FailedCreateOriginalHistoriesDataV4::decode(&bytes).is_ok());
    assert_eq!(encode_failed_create_original_histories_v4(&original, &terminal).unwrap(), bytes);

    let larger_original = literal_archive(b"AOSHAR01", ORIGINAL_ID, &vec![1; 1_048_400]);
    let oversized = literal_bundle(&larger_original, &terminal);
    assert!(FailedCreateOriginalHistoriesDataV4::decode(&oversized).is_err());
    assert!(encode_failed_create_original_histories_v4(&larger_original, &terminal).is_err());
}

#[test]
fn archive_versions_request_ids_purposes_and_nested_lengths_refuse() {
    let good_h = literal_archive(b"AOSHAR01", ORIGINAL_ID, b"H");
    let good_t = literal_archive(b"AOSHTA01", ORIGINAL_ID, b"T");
    for offset in [0, 8, 9, 26, 29] {
        let mut bad_h = good_h.clone();
        bad_h[offset] ^= 1;
        reseal(&mut bad_h, ORIGINAL_DOMAIN);
        assert!(FailedCreateOriginalHistoriesDataV4::decode(&literal_bundle(&bad_h, &good_t)).is_err());
        assert!(encode_failed_create_original_histories_v4(&bad_h, &good_t).is_err());
    }
    for request_id in [[0; 16], [8; 16]] {
        let bad_t = literal_archive(b"AOSHTA01", request_id, b"T");
        assert!(FailedCreateOriginalHistoriesDataV4::decode(&literal_bundle(&good_h, &bad_t)).is_err());
    }
    assert!(FailedCreateOriginalHistoriesDataV4::decode(&literal_bundle(&good_t, &good_h)).is_err());
    let empty_h = literal_archive(b"AOSHAR01", ORIGINAL_ID, b"");
    assert!(FailedCreateOriginalHistoriesDataV4::decode(&literal_bundle(&empty_h, &good_t)).is_err());
    let mut wrong_domain = good_h;
    reseal(&mut wrong_domain, TERMINAL_DOMAIN);
    assert!(FailedCreateOriginalHistoriesDataV4::decode(&literal_bundle(&wrong_domain, &good_t)).is_err());
}

struct SignedHistoryFixture {
    manifest: BrokerSessionManifestV1,
    stored: StoredBrokerSessionHistoryV1,
    record: BrokerSessionDurableRecordV1,
}

fn manifest(revoked: bool, route_digest: [u8; 32]) -> BrokerSessionManifestV1 {
    let uses = [
        broker::BrokerSessionKeyUsageV1::ClientHello,
        broker::BrokerSessionKeyUsageV1::BrokerHello,
        broker::BrokerSessionKeyUsageV1::ClientRecord,
        broker::BrokerSessionKeyUsageV1::BrokerOutcome,
    ];
    let keys = std::array::from_fn(|index| {
        let signing = SigningKey::from_bytes(&[21 + index as u8; 32]);
        let signer = broker::BrokerSessionSignerReferenceV1::for_signing_key(
            [31 + index as u8; 16],
            10,
            [41 + index as u8; 32],
            [51 + index as u8; 16],
            20,
            uses[index],
            &signing,
        ).unwrap();
        BrokerSessionManifestKeyPinV1::new(
            signer, signing.verifying_key().to_bytes(), 10, 20, revoked, None,
        ).unwrap()
    });
    BrokerSessionManifestV1::new(
        BrokerSessionProtocolV1::Host, BrokerSessionManifestAudienceV1::NodeController,
        1, 0, [61; 16], [62; 16], 1, route_digest, 2, [64; 32], 3, [65; 32], NODE, keys,
    ).unwrap()
}

fn signed_history() -> SignedHistoryFixture {
    let manifest = manifest(false, [63; 32]);
    let context = manifest.verification_context([12; 16], [13; 16], [14; 16]).unwrap();
    let features: Vec<Feature> = [
        "aos.sandbox.authentication.broker-session",
        "aos.sandbox.authorization.signed-plan-lease",
    ].into_iter().map(|namespace| Feature {
        namespace: namespace.to_owned(), major: 1, ..Default::default()
    }).collect();
    let method = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT;
    let client_message = BrokerClientHello {
        protocol_major: 1,
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        required_features: features.clone(),
        maximum_response_bytes: 65_536,
        required_methods: vec![method.into()],
        ..Default::default()
    };
    let client_subject = broker::BrokerClientHelloSubjectV1::new(
        NODE, [12; 16], BrokerSessionProtocolV1::Host, 1, 0,
        Audience::AUDIENCE_NODE_CONTROLLER, [13; 16], [15; 32],
        context.protected_context_digest(), broker::client_hello_fields_digest_v1(&client_message).unwrap(),
    ).unwrap();
    let client = broker::sign_client_hello_v1(
        client_subject, manifest.key_pins()[0].signer().clone(), &SigningKey::from_bytes(&[21; 32]),
    ).unwrap();
    let client_packet = broker::encode_signed_client_hello_packet_v1(client_message, &client).unwrap();
    let broker_message = BrokerServerHello {
        protocol_major: 1,
        features,
        maximum_request_bytes: broker::maximum_broker_session_request_bytes_v1(BrokerSessionProtocolV1::Host) as u32,
        maximum_response_bytes: 65_536,
        methods: vec![method.into()],
        ..Default::default()
    };
    let broker_subject = broker::BrokerHelloSubjectV1::new(
        NODE, [12; 16], BrokerSessionProtocolV1::Host, 1, 0,
        Audience::AUDIENCE_NODE_CONTROLLER, [14; 16], [16; 32], context.protected_context_digest(),
        broker::complete_signed_client_hello_digest_v1(&client),
        broker::server_hello_fields_digest_v1(&broker_message).unwrap(),
    ).unwrap();
    let broker_hello = broker::sign_broker_hello_v1(
        broker_subject, manifest.key_pins()[1].signer().clone(), &SigningKey::from_bytes(&[22; 32]),
    ).unwrap();
    let broker_packet = broker::encode_signed_server_hello_packet_v1(broker_message, &broker_hello).unwrap();
    let transcript = broker::verify_broker_session_transcript_v1(
        &broker::decode_canonical_client_hello_v1(&client_packet).unwrap(),
        &broker::decode_canonical_server_hello_v1(&broker_packet).unwrap(), &context,
    ).unwrap();
    let checkpoint = HistoricalSessionCheckpointV1::new(
        context.clone(), &client_packet, &broker_packet,
        aos_sandbox_protocol::PeerCredentials { uid: 0, gid: 0, pid: Some(9) }, &transcript,
    ).unwrap();
    let envelope = BrokerRequestEnvelope {
        method: method.into(),
        body: vec![1],
        ..Default::default()
    };
    let subject = broker::BrokerRequestSubjectV1::new(
        transcript.session_binding(), [13; 16], 1, ORIGINAL_ID,
        broker::request_fields_digest_v1(&envelope).unwrap(),
    ).unwrap();
    let signed = broker::sign_request_v1(
        method, subject, manifest.key_pins()[2].signer().clone(), &SigningKey::from_bytes(&[23; 32]),
    ).unwrap();
    let packet = broker::encode_signed_request_packet_v1(envelope, &signed).unwrap();
    let publication = literal_hash(ENDPOINT_PUBLICATION_DOMAIN, &[
        &[1, 1][..], manifest.binding().as_bytes(), &[13; 16],
    ].concat());
    let bindings = broker::BrokerSessionProtectedBindingsV1::new(
        context.protected_context_digest(), publication, [66; 32],
    ).unwrap();
    let companion = broker::BrokerSessionRequestCompanionV1::try_from_parts(
        BrokerSessionProtocolV1::Host, method, 100, 8192, signed,
    ).unwrap();
    let record = BrokerSessionDurableRecordV1::new_request(
        1, [0; 32], BrokerSessionDurableEndpointV1::Client, transcript.session_binding(),
        broker::BrokerSessionPeerBindingV1::new([67; 32]).unwrap(), bindings, [68; 32],
        ORIGINAL_ID, companion, packet,
    ).unwrap();
    let history = BrokerSessionDurableHistoryV1::from_records(vec![record.clone()]).unwrap();
    let stored = StoredBrokerSessionHistoryV1 {
        protocol: BrokerSessionProtocolV1::Host,
        endpoint: BrokerSessionDurableEndpointV1::Client,
        generation: 1,
        stable_endpoint_identity: literal_hash(STABLE_ENDPOINT_DOMAIN, &[
            &[1, 1][..], manifest.binding().as_bytes(),
        ].concat()),
        endpoint_publication: publication,
        current_catalog: [66; 32],
        current_head: history.head_commitment(),
        history: history.encode().unwrap(),
        checkpoint: Some(checkpoint),
    };
    SignedHistoryFixture {
        manifest,
        stored,
        record,
    }
}

fn profile_and_pins() -> (PurposeProfileV1, RootRolePinsV1) {
    let epoch = [2; 16];
    let digests = [[0xa1; 32], [0xa2; 32], [0xa3; 32]];
    let mut salt_name = [3; 34];
    salt_name[..2].copy_from_slice(&[0, 11]);
    let profile = PurposeProfileV1 {
        endpoint: NvCustodyEndpointV1::RootCreateFailure,
        node: NODE,
        epoch,
        stable_endpoint: [3; 32],
        domain_binding: [0; 32],
        nv_name: nv_name(NvCustodyEndpointV1::RootCreateFailure),
        salt_name,
        genesis: [4; 32],
        role_pins: Some(digests),
        scope: [5; 32],
    };
    let pins = RootRolePinsV1 {
        keys: [1_u8, 2, 3].map(|seed| SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()),
        assignments: [
            CreateFailureServiceRoleV1::Controller, CreateFailureServiceRoleV1::Host,
            CreateFailureServiceRoleV1::Root,
        ].map(|role| canonical_create_failure_service_binding_v1(role, NODE, epoch).unwrap()),
        digests,
    };
    (profile, pins)
}

fn literal_source(request_id: [u8; 16]) -> ControllerExecutionArgumentAttemptV1 {
    let mut bytes = [0; 336];
    bytes[..8].copy_from_slice(b"AOSCIA02");
    bytes[8..24].fill(1);
    bytes[24..40].fill(2);
    bytes[40..56].copy_from_slice(&request_id);
    bytes[56..248].fill(3);
    bytes[248..264].fill(8);
    bytes[264..296].fill(9);
    bytes[296..304].copy_from_slice(&100_u64.to_be_bytes());
    reseal(&mut bytes, b"aos.sandbox.controller-argument-attempt.v1\0");
    ControllerExecutionArgumentAttemptV1::decode_canonical(&bytes).unwrap()
}

#[test]
fn signed_historical_traffic_is_data_but_not_complete_original_semantics() {
    let fixture = signed_history();
    let frame = literal_archive(b"AOSHAR01", ORIGINAL_ID, &fixture.stored.encode().unwrap());
    let verified = historical_archive(&frame, b"AOSHAR01", ORIGINAL_DOMAIN, &fixture.manifest).unwrap();

    assert_eq!(verified.history.head_commitment(), fixture.stored.current_head);
    let packet_digest: [u8; 32] = Sha256::digest(fixture.record.request_packet()).into();
    assert_ne!(verified.history.head_commitment(), packet_digest);
    assert!(historical_request(&verified, 0).is_err());
}

#[test]
fn v2_no_checkpoint_and_foreign_independent_manifest_refuse() {
    let mut fixture = signed_history();
    let frame = literal_archive(b"AOSHAR01", ORIGINAL_ID, &fixture.stored.encode().unwrap());
    assert!(historical_archive(&frame, b"AOSHAR01", ORIGINAL_DOMAIN, &manifest(false, [70; 32])).is_err());

    fixture.stored.checkpoint = None;
    let v2 = fixture.stored.encode().unwrap();
    assert_eq!(&v2[8..10], &[0, 2]);
    assert!(StoredBrokerSessionHistoryV1::decode(&canonical_protocol_key_v1(BrokerSessionProtocolV1::Host), &v2).is_ok());
    let legacy = literal_archive(b"AOSHAR01", ORIGINAL_ID, &v2);
    assert!(historical_archive(&legacy, b"AOSHAR01", ORIGINAL_DOMAIN, &fixture.manifest).is_err());
}

#[test]
fn v3_zero_checkpoint_length_does_not_upgrade_legacy_evidence() {
    let fixture = signed_history();
    let mut encoded = fixture.stored.encode().unwrap();
    let history_length = u32::from_be_bytes(encoded[148..152].try_into().unwrap()) as usize;
    let checkpoint_length_offset = 152 + history_length;
    encoded[checkpoint_length_offset..checkpoint_length_offset + 4].fill(0);
    reseal(&mut encoded, b"aos.sandbox.broker-session.protected-history.v3\0");
    let frame = literal_archive(b"AOSHAR01", ORIGINAL_ID, &encoded);

    assert!(historical_archive(&frame, b"AOSHAR01", ORIGINAL_DOMAIN, &fixture.manifest).is_err());
}

#[test]
fn private_verifier_requires_independent_exact_manifest_and_original_source() {
    let fixture = signed_history();
    let encoded = fixture.stored.encode().unwrap();
    let bundle = literal_bundle(
        &literal_archive(b"AOSHAR01", ORIGINAL_ID, &encoded),
        &literal_archive(b"AOSHTA01", ORIGINAL_ID, &encoded),
    );
    let independent_manifest = fixture.manifest.encode();
    let mut wire_manifest = independent_manifest;
    wire_manifest[56] ^= 1;
    let (profile, pins) = profile_and_pins();
    let source = literal_source(ORIGINAL_ID);
    let slots: [&[u8]; 7] = [b"1", b"2", b"3", b"4", b"5", b"6", &wire_manifest];

    assert!(verify_original_join_v3(
        &bundle, &independent_manifest, slots, &source, &profile, &pins,
    ).is_err());
    let slots: [&[u8]; 7] = [b"1", b"2", b"3", b"4", b"5", b"6", &independent_manifest];
    let foreign_source = literal_source([8; 16]);
    assert!(verify_original_join_v3(
        &bundle, &independent_manifest, slots, &foreign_source, &profile, &pins,
    ).is_err());
}

#[test]
fn independently_pinned_profile_node_roles_and_keys_are_not_wire_authority() {
    let active_manifest = manifest(false, [63; 32]);
    let (profile, mut pins) = profile_and_pins();
    require_manifest_and_pins(&active_manifest, &profile, &pins).unwrap();
    assert!(require_manifest_and_pins(&manifest(true, [63; 32]), &profile, &pins).is_err());

    let mut foreign = profile;
    foreign.node = [1; 16];
    assert!(require_manifest_and_pins(&active_manifest, &foreign, &pins).is_err());
    let mut wrong_purpose = profile;
    wrong_purpose.endpoint = NvCustodyEndpointV1::RuntimeDeployment;
    assert!(require_manifest_and_pins(&active_manifest, &wrong_purpose, &pins).is_err());
    let mut wrong_salt = profile;
    wrong_salt.salt_name[0] ^= 1;
    assert!(require_manifest_and_pins(&active_manifest, &wrong_salt, &pins).is_err());
    let mut wrong_nv_name = profile;
    wrong_nv_name.nv_name[2] ^= 1;
    assert!(require_manifest_and_pins(&active_manifest, &wrong_nv_name, &pins).is_err());
    pins.assignments[0][0] ^= 1;
    assert!(require_manifest_and_pins(&active_manifest, &profile, &pins).is_err());
    pins.assignments[0][0] ^= 1;

    pins.digests[1][0] ^= 1;
    assert!(require_manifest_and_pins(&active_manifest, &profile, &pins).is_err());
    pins.digests[1][0] ^= 1;
    pins.keys[1] = *active_manifest.key_pins()[0].public_key();
    assert!(require_manifest_and_pins(&active_manifest, &profile, &pins).is_err());
    pins.keys[1] = pins.keys[0];
    assert!(require_manifest_and_pins(&active_manifest, &profile, &pins).is_err());
}

#[test]
fn signed_hello_corruption_cannot_be_repaired_by_archive_checksums() {
    let fixture = signed_history();
    let checkpoint = fixture.stored.checkpoint.as_ref().unwrap();
    let mut encoded = checkpoint.encode().unwrap();
    let context_len = u32::from_be_bytes(encoded[10..14].try_into().unwrap()) as usize;
    let client_len = u32::from_be_bytes(encoded[14..18].try_into().unwrap()) as usize;
    let client_end = 34 + context_len + client_len;
    encoded[client_end - 1] ^= 1;
    reseal(&mut encoded, b"aos.sandbox.broker-session.historical-checkpoint.v1\0");
    assert!(HistoricalSessionCheckpointV1::decode(&encoded).is_err());
}

#[test]
fn complete_history_head_and_endpoint_publication_tampering_refuse() {
    let fixture = signed_history();
    let encoded = fixture.stored.encode().unwrap();
    for offset in [20, 52, 116] {
        let mut changed = encoded.clone();
        changed[offset] ^= 1;
        reseal(&mut changed, b"aos.sandbox.broker-session.protected-history.v3\0");
        let frame = literal_archive(b"AOSHAR01", ORIGINAL_ID, &changed);
        assert!(historical_archive(&frame, b"AOSHAR01", ORIGINAL_DOMAIN, &fixture.manifest).is_err());
    }
}

#[test]
fn strict_request_signature_is_not_replaced_by_valid_history_checksums() {
    let mut fixture = signed_history();
    let canonical = decode_canonical_request_v1(fixture.record.request_packet()).unwrap();
    let mut artifact = canonical.signed_artifact().to_canonical_bytes();
    let signature_start = artifact.len() - 64;
    artifact[signature_start] ^= 1;
    let changed = broker::SignedBrokerRequestV1::from_canonical_bytes(&artifact).unwrap();
    let mut envelope = canonical.message().clone();
    envelope.signed_session_request.clear();
    let packet = broker::encode_signed_request_packet_v1(envelope, &changed).unwrap();
    let companion = broker::BrokerSessionRequestCompanionV1::try_from_parts(
        BrokerSessionProtocolV1::Host, fixture.record.method(), 100, 8192, changed,
    ).unwrap();
    let record = BrokerSessionDurableRecordV1::new_request(
        1, [0; 32], BrokerSessionDurableEndpointV1::Client, fixture.record.session_binding(),
        fixture.record.peer_binding(), fixture.record.protected_bindings(),
        fixture.record.request_semantic_binding(), ORIGINAL_ID, companion, packet,
    ).unwrap();
    let history = BrokerSessionDurableHistoryV1::from_records(vec![record]).unwrap();
    fixture.stored.current_head = history.head_commitment();
    fixture.stored.history = history.encode().unwrap();
    let frame = literal_archive(b"AOSHAR01", ORIGINAL_ID, &fixture.stored.encode().unwrap());
    assert!(historical_archive(&frame, b"AOSHAR01", ORIGINAL_DOMAIN, &fixture.manifest).is_err());
}

#[test]
fn checked_reader_never_wraps_or_accepts_truncated_arrays() {
    assert_eq!(array::<2>(&[1, 2, 3], 1).unwrap(), [2, 3]);
    assert!(array::<2>(&[1, 2, 3], usize::MAX).is_err());
    assert!(array::<2>(&[1, 2, 3], 2).is_err());
}

#[test]
fn checked_parts_preserve_bounded_full_frames_and_nested_slices() {
    for (original_length, terminal_length) in [(1, 1), (7, 3), (1_048_399, 1)] {
        let original_history = vec![b'H'; original_length];
        let terminal_history = vec![b'T'; terminal_length];
        let original = literal_archive(b"AOSHAR01", ORIGINAL_ID, &original_history);
        let terminal = literal_archive(b"AOSHTA01", ORIGINAL_ID, &terminal_history);
        let bytes = literal_bundle(&original, &terminal);

        let checked = checked_original_histories_parts_v4(&bytes).unwrap();
        let public = FailedCreateOriginalHistoriesDataV4::decode(&bytes).unwrap();

        assert_eq!(checked.data, public);
        assert_eq!(checked.data.original_archive(), original);
        assert_eq!(checked.data.terminal_archive(), terminal);
        assert_eq!(checked.original_stored, original_history);
        assert_eq!(checked.terminal_stored, terminal_history);
        assert_eq!(checked.original_stored.as_ptr(), bytes[20 + 30..].as_ptr());
        assert_eq!(
            checked.terminal_stored.as_ptr(),
            bytes[20 + original.len() + 30..].as_ptr(),
        );
        assert_eq!(
            checked.original_stored.as_ptr(),
            public.original_archive()[30..].as_ptr(),
        );
        assert_eq!(
            checked.terminal_stored.as_ptr(),
            public.terminal_archive()[30..].as_ptr(),
        );
        assert!(bytes.len() <= 1_048_576);
    }

    let mut malformed = small_bundle();
    malformed[20 + 30] ^= 1;
    reseal(&mut malformed, BUNDLE_DOMAIN);
    assert!(checked_original_histories_parts_v4(&malformed).is_err());
    assert!(FailedCreateOriginalHistoriesDataV4::decode(&malformed).is_err());

    let original = literal_archive(b"AOSHAR01", ORIGINAL_ID, &vec![b'H'; 1_048_400]);
    let terminal = literal_archive(b"AOSHTA01", ORIGINAL_ID, b"T");
    let oversized = literal_bundle(&original, &terminal);
    assert_eq!(oversized.len(), 1_048_577);
    assert!(checked_original_histories_parts_v4(&oversized).is_err());
}

#[test]
fn checked_stored_history_matches_complete_checked_wrapper() {
    let fixture = signed_history();
    let stored = fixture.stored.encode().unwrap();
    let bytes = literal_bundle(
        &literal_archive(b"AOSHAR01", ORIGINAL_ID, &stored),
        &literal_archive(b"AOSHTA01", ORIGINAL_ID, &stored),
    );
    let checked = checked_original_histories_parts_v4(&bytes).unwrap();

    for (frame, nested, magic, domain) in [
        (
            checked.data.original_archive(), checked.original_stored,
            b"AOSHAR01", ORIGINAL_DOMAIN,
        ),
        (
            checked.data.terminal_archive(), checked.terminal_stored,
            b"AOSHTA01", TERMINAL_DOMAIN,
        ),
    ] {
        let wrapped = historical_archive(frame, magic, domain, &fixture.manifest).unwrap();
        let retained = historical_stored_archive(nested, &fixture.manifest).unwrap();

        assert_eq!(retained.checkpoint, wrapped.checkpoint);
        assert_eq!(
            retained.checkpoint,
            *fixture.stored.checkpoint.as_ref().unwrap(),
        );
        assert_eq!(retained.transcript, wrapped.transcript);
        assert_eq!(
            retained.history.encode().unwrap(),
            wrapped.history.encode().unwrap(),
        );
        assert_eq!(retained.history.head_commitment(), fixture.stored.current_head);
        assert!(historical_request(&retained, 0).is_err());
        assert!(historical_stored_archive(nested, &manifest(false, [70; 32])).is_err());
    }
}
