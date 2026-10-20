//! Private byte-observer regressions without a live flight, clock or role loan.

use super::*;
use aos_sandbox_protocol::domain_ledger::create_q04_history::Q04_ORIGINAL_QUERY_MAGIC_V1;
use aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::{
    MAXIMUM_PREVIEW_BYTES, PREVIEW_PREFIX_BYTES, bounded_input_transfer_index,
};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use sha2::Digest as _;

const CLIENT_NONCE: [u8; 16] = [0x13; 16];
const ROOT_NONCE: [u8; 16] = [0x27; 16];
const SOURCE_UID: u32 = 1000;

fn query() -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(Q04_ORIGINAL_QUERY_MAGIC_V1);
    bytes[8..24].copy_from_slice(&CLIENT_NONCE);
    bytes
}

fn hello() -> [u8; 56] {
    let mut bytes = [0; 56];
    bytes[..8].copy_from_slice(wire::ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..32].copy_from_slice(&CLIENT_NONCE);
    bytes[32..48].copy_from_slice(&ROOT_NONCE);
    bytes[48..52].copy_from_slice(&SOURCE_UID.to_be_bytes());
    bytes[52..56].copy_from_slice(&SOURCE_UID.to_be_bytes());
    bytes
}

fn connected() -> Original {
    let mut original = Original::new();
    original.observe_sent(&query(), CLIENT_NONCE);
    original.observe_received(&hello(), CLIENT_NONCE, SOURCE_UID);
    assert!(!original.refused);
    assert!(original.purpose == Purpose::Q04);
    assert_eq!(original.facts.nonce, Some(ROOT_NONCE));
    original
}

fn frame(kind: Kind, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    wire::encode_root_create_q04_transfer_v1(&mut bytes, kind, ROOT_NONCE, payload).unwrap();
    bytes
}

fn fixed_frame(kind: Kind, byte: u8) -> Vec<u8> {
    frame(kind, &vec![byte; kind.fixed_payload_bytes().unwrap()])
}

fn receive(original: &mut Original, bytes: &[u8]) {
    original.observe_received(bytes, CLIENT_NONCE, SOURCE_UID);
}

fn preview_frames() -> (Vec<u8>, Vec<u8>) {
    // Only the metadata prefix is interpreted here. The observer does not
    // certify this untrusted preview as a complete semantic input.
    let mut preview = vec![0; PREVIEW_PREFIX_BYTES + 120];
    preview[..8].copy_from_slice(b"AOSQ4V01");
    preview[8..10].copy_from_slice(&1_u16.to_be_bytes());
    preview[16..20].copy_from_slice(&120_u32.to_be_bytes());
    preview[PREVIEW_PREFIX_BYTES..PREVIEW_PREFIX_BYTES + 32].fill(0x42);
    let index = bounded_input_transfer_index(
        &preview,
        b"private wire observer preview",
        MAXIMUM_PREVIEW_BYTES,
    )
    .unwrap();
    let mut chunk = Vec::new();
    Q04ChunkPurposeV1::Preview
        .encode_chunk(&preview, index[..32].try_into().unwrap(), 0, &mut chunk)
        .unwrap();
    (frame(Kind::PreviewIndex, &index), frame(Kind::PreviewChunk, &chunk))
}

fn decision_observed() -> Original {
    // Historical comparison DATA alone supplies no held prehold or native
    // authority. Later typed decision/phase validation is deliberately absent.
    let mut body = [0; PREHOLD_RESPONSE_BYTES];
    body[16..32].copy_from_slice(&ROOT_NONCE);
    body[32..128].fill(1);
    body[128..144].fill(2);
    body[144..160].fill(3);
    body[160..384].fill(4);
    body[384..392].copy_from_slice(&1_u64.to_be_bytes());
    body[392..400].copy_from_slice(&1_u64.to_be_bytes());
    let names = ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6));
    body[400..448].copy_from_slice(&names.to_bytes());
    body[448..452].copy_from_slice(&3432_u32.to_be_bytes());
    body[452..454].copy_from_slice(&2_u16.to_be_bytes());
    body[454..456].copy_from_slice(&1_u16.to_be_bytes());
    for offset in (456..472).step_by(4) {
        body[offset..offset + 4].copy_from_slice(&1_u32.to_be_bytes());
    }
    let prehold = Q04PreholdPublicationDataV1::from_body(body, ROOT_NONCE).unwrap();

    let mut original = connected();
    receive(&mut original, &frame(Kind::PreholdRecipe, prehold.bytes()));
    receive(&mut original, &fixed_frame(Kind::Decision, 0x51));
    assert!(!original.refused);
    assert_eq!(original.facts.prehold.as_ref(), Some(prehold.bytes()));
    assert_eq!(original.facts.decision, Some([0x51; DECISION_BYTES]));
    original
}

#[test]
fn query_hello_and_fixed_frames_wait_for_their_final_byte() {
    let mut original = Original::new();
    original.observe_sent(&query()[..31], CLIENT_NONCE);
    receive(&mut original, &hello());
    assert!(original.purpose == Purpose::Undecided);
    assert_eq!(original.outgoing.used, 31);
    assert_eq!(original.incoming.used, 0);
    assert_eq!(original.facts.nonce, None);

    original.observe_sent(&query()[31..], CLIENT_NONCE);
    receive(&mut original, &hello()[..55]);
    assert!(original.purpose == Purpose::Q04);
    assert_eq!(original.outgoing.used, 0);
    assert_eq!(original.incoming.used, 55);
    assert_eq!(original.facts.nonce, None);

    receive(&mut original, &hello()[55..]);
    assert_eq!(original.facts.nonce, Some(ROOT_NONCE));
    assert_eq!(original.incoming.used, 0);

    let observation = fixed_frame(Kind::SourceObservation, 0x61);
    receive(&mut original, &observation[..observation.len() - 1]);
    assert_eq!(original.facts.source_observations, 0);
    assert_eq!(original.incoming.used, observation.len() - 1);
    receive(&mut original, &observation[observation.len() - 1..]);
    assert_eq!(original.facts.source_observations, 1);
    assert_eq!(original.incoming.used, 0);
    assert!(!original.refused);
}

#[test]
fn resource_width_and_embedded_header_preserve_byte_zero_framing() {
    for width in [
        Kind::SourceObservation.fixed_payload_bytes().unwrap(),
        Kind::SourceObservation.resource_payload_bytes().unwrap(),
    ] {
        let mut original = connected();
        let mut payload = vec![0x62; width];
        let embedded = fixed_frame(Kind::PolicyAccepted, 0x63);
        payload[17..49].copy_from_slice(&embedded[..32]);
        let observation = frame(Kind::SourceObservation, &payload);

        for fragment in observation.chunks(7) {
            receive(&mut original, fragment);
        }

        assert!(!original.refused);
        assert_eq!(original.facts.source_observations, 1);
        assert_eq!(original.facts.received, 0);
        assert_eq!(original.facts.sent, 0);
        assert!(original.facts.acknowledgements.iter().all(Option::is_none));
        assert_eq!(original.incoming.used, 0);
    }
}

#[test]
fn variable_preview_waits_for_prefix_then_complete_checksum() {
    let mut original = connected();
    let (index, chunk) = preview_frames();
    receive(&mut original, &index);
    let prefix_end = 32 + CLAIM_CHUNK_PREFIX_BYTES;

    receive(&mut original, &chunk[..32]);
    assert!(original.incoming.shape.is_none());
    receive(&mut original, &chunk[32..prefix_end - 1]);
    assert!(original.incoming.shape.is_none());
    receive(&mut original, &chunk[prefix_end - 1..prefix_end]);
    assert!(matches!(
        original.incoming.shape,
        Some((length, Some(Kind::PreviewChunk))) if length == chunk.len()
    ));
    assert_eq!(original.facts.preview_metadata, None);

    receive(&mut original, &chunk[prefix_end..chunk.len() - 1]);
    assert_eq!(original.facts.preview_metadata, None);
    receive(&mut original, &chunk[chunk.len() - 1..]);
    assert_eq!(original.facts.preview_metadata, Some([0x42; 32]));
    assert_eq!(original.incoming.used, 0);
    assert!(!original.refused);
}

#[test]
fn invalid_chunk_checksum_retains_refusal_and_original_frame() {
    let mut original = connected();
    let (index, valid_chunk) = preview_frames();
    receive(&mut original, &index);
    let retained_index = original.facts.preview_index;
    let mut corrupt_chunk = valid_chunk.clone();
    *corrupt_chunk.last_mut().unwrap() ^= 1;

    receive(&mut original, &corrupt_chunk);
    assert!(original.refused);
    assert_eq!(original.incoming.current(), corrupt_chunk.as_slice());
    assert_eq!(original.facts.preview_index, retained_index);
    assert_eq!(original.facts.preview_metadata, None);

    receive(&mut original, &valid_chunk);
    original.observe_sent(&fixed_frame(Kind::SourceRefresh, 0x64), CLIENT_NONCE);
    assert!(original.refused);
    assert_eq!(original.incoming.current(), corrupt_chunk.as_slice());
    assert_eq!(original.outgoing.used, 0);
    assert_eq!(original.facts.preview_index, retained_index);
    assert_eq!(original.facts.preview_metadata, None);
}

#[test]
fn all_four_acknowledgements_hash_payload_and_gate_the_next_phase() {
    let mut original = decision_observed();
    let pairs = [
        (Kind::PolicyAcknowledgement, Kind::PolicyAccepted),
        (Kind::ReleaseAcknowledgement, Kind::ReleaseAuthorized),
        (Kind::SettlementAcknowledgement, Kind::Settled),
        (Kind::ClearanceAcknowledgement, Kind::FinalClearance),
    ];
    for (index, (ack_kind, phase_kind)) in pairs.into_iter().enumerate() {
        let ack = fixed_frame(ack_kind, 0x70 + index as u8);
        let expected = ObjectDigest::from_bytes(Sha256::digest(&ack[32..]).into());
        let header_inclusive = ObjectDigest::from_bytes(Sha256::digest(&ack).into());
        original.observe_sent(&ack[..ack.len() - 1], CLIENT_NONCE);
        assert_eq!(original.facts.sent, index);
        assert_eq!(original.facts.acknowledgements[index], None);

        original.observe_sent(&ack[ack.len() - 1..], CLIENT_NONCE);
        assert_eq!(original.facts.sent, index + 1);
        assert_eq!(original.facts.acknowledgements[index], Some(expected));
        assert_ne!(expected, header_inclusive);
        assert_eq!(original.facts.received, index);

        // Opaque phase bytes exercise only observer ordering and retention;
        // they never pass through the later identity/phase authorization path.
        let phase_byte = 0x80 + index as u8;
        let phase = fixed_frame(phase_kind, phase_byte);
        receive(&mut original, &phase[..phase.len() - 1]);
        assert_eq!(original.facts.received, index);
        receive(&mut original, &phase[phase.len() - 1..]);
        assert_eq!(original.facts.received, index + 1);
        assert_eq!(original.facts.phases[index], [phase_byte; PHASE_BYTES]);
        assert!(!original.refused);
    }
    assert_eq!(original.facts.sent, 4);
    assert_eq!(original.facts.received, 4);
}

#[test]
fn early_duplicate_and_out_of_order_acknowledgements_are_sticky_refusals() {
    let mut early_phase = decision_observed();
    receive(&mut early_phase, &fixed_frame(Kind::PolicyAccepted, 0x81));
    assert!(early_phase.refused);
    assert_eq!(early_phase.facts.received, 0);
    assert_eq!(early_phase.facts.phases[0], [0; PHASE_BYTES]);

    let mut out_of_order = decision_observed();
    out_of_order.observe_sent(&fixed_frame(Kind::ReleaseAcknowledgement, 0x72), CLIENT_NONCE);
    assert!(out_of_order.refused);
    assert_eq!(out_of_order.facts.sent, 0);
    assert!(out_of_order.facts.acknowledgements.iter().all(Option::is_none));

    let mut duplicate = decision_observed();
    let policy_ack = fixed_frame(Kind::PolicyAcknowledgement, 0x71);
    duplicate.observe_sent(&policy_ack, CLIENT_NONCE);
    let digest = duplicate.facts.acknowledgements[0];
    duplicate.observe_sent(&policy_ack, CLIENT_NONCE);
    assert!(duplicate.refused);
    receive(&mut duplicate, &fixed_frame(Kind::PolicyAccepted, 0x82));
    assert_eq!(duplicate.facts.sent, 1);
    assert_eq!(duplicate.facts.received, 0);
    assert_eq!(duplicate.facts.acknowledgements[0], digest);
    assert_eq!(duplicate.facts.phases[0], [0; PHASE_BYTES]);
}

#[test]
fn bad_query_and_hello_bindings_refuse_without_nonce_adoption() {
    for offset in [8, 24] {
        let mut original = Original::new();
        let mut invalid = query();
        invalid[offset] ^= 1;
        original.observe_sent(&invalid, CLIENT_NONCE);
        assert!(original.refused);
        original.observe_sent(&query(), CLIENT_NONCE);
        receive(&mut original, &hello());
        assert_eq!(original.outgoing.current(), invalid);
        assert_eq!(original.facts.nonce, None);
    }

    for offset in [8, 16, 48, 52] {
        let mut original = Original::new();
        original.observe_sent(&query(), CLIENT_NONCE);
        let mut invalid = hello();
        invalid[offset] ^= 1;
        receive(&mut original, &invalid);
        assert!(original.refused);
        receive(&mut original, &hello());
        assert_eq!(original.incoming.current(), invalid);
        assert_eq!(original.facts.nonce, None);
    }
}

#[test]
fn ordinary_selection_is_sticky_and_unknown_q04_header_is_not_rescanned() {
    let mut ordinary = Original::new();
    let mut other_query = query();
    other_query[0] ^= 1;
    ordinary.observe_sent(&other_query, CLIENT_NONCE);
    ordinary.observe_sent(&query(), CLIENT_NONCE);
    receive(&mut ordinary, &hello());
    assert!(ordinary.purpose == Purpose::Ordinary);
    assert!(!ordinary.refused);
    assert_eq!(ordinary.outgoing.used, 0);
    assert_eq!(ordinary.incoming.used, 0);
    assert_eq!(ordinary.facts.nonce, None);

    let mut q04 = connected();
    let mut unknown = fixed_frame(Kind::SourceObservation, 0x65);
    unknown[0] ^= 1;
    receive(&mut q04, &unknown);
    assert!(q04.refused);
    assert_eq!(q04.incoming.current(), &unknown[..32]);
    receive(&mut q04, &fixed_frame(Kind::SourceObservation, 0x66));
    assert_eq!(q04.incoming.current(), &unknown[..32]);
    assert_eq!(q04.facts.source_observations, 0);
}

#[test]
fn source_refresh_requires_each_observation_and_enforces_the_fixed_limit() {
    let observation = fixed_frame(Kind::SourceObservation, 0x67);
    let refresh = fixed_frame(Kind::SourceRefresh, 0x68);
    let mut early_refresh = connected();
    early_refresh.observe_sent(&refresh, CLIENT_NONCE);
    assert!(early_refresh.refused);
    assert_eq!(early_refresh.facts.source_refreshes, 0);

    let mut duplicate_observation = connected();
    receive(&mut duplicate_observation, &observation);
    receive(&mut duplicate_observation, &observation);
    assert!(duplicate_observation.refused);
    assert_eq!(duplicate_observation.facts.source_observations, 1);

    let mut original = connected();
    receive(&mut original, &observation);
    for index in 0..SOURCE_REFRESHES {
        original.observe_sent(&refresh, CLIENT_NONCE);
        assert_eq!(original.facts.source_refreshes, index + 1);
        receive(&mut original, &observation);
        assert_eq!(original.facts.source_observations, index + 2);
        assert!(!original.refused);
    }
    original.observe_sent(&refresh, CLIENT_NONCE);
    assert!(original.refused);
    assert_eq!(original.facts.source_refreshes, SOURCE_REFRESHES);
    assert_eq!(original.facts.source_observations, SOURCE_REFRESHES + 1);
    assert_eq!(original.facts.last_source_phase_count, 0);
}
