//! Exercises real portable codecs and replay failures without an IO authority.

use super::*;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Schema;

impl ProtectedDomainSchemaV1 for Schema {
    type Kind = u8;
    type ReplayValidator = bool;

    const MAGIC: [u8; 8] = *b"TESTDOM1";
    const HASH_DOMAIN: &'static [u8] = b"test.projection-retention\0";
    const KEY_PREFIX: &'static [u8] = b"test/";
    const MAXIMUM_PAYLOAD_BYTES: usize = 4096;

    fn kind_code(kind: u8) -> u8 { kind }
    fn kind_from_code(code: u8) -> Option<u8> { (code == 1).then_some(code) }
    fn namespace(_: u8) -> RecordNamespace { RecordNamespace::DesiredState }
    fn order(_: u8) -> u8 { 1 }
    fn role(_: u8) -> ProtectedRecordRoleV1 { ProtectedRecordRoleV1::State }
    fn is_checkpoint(_: u8) -> bool { false }
    fn family(_: u8) -> u8 { 1 }
    fn decode_reducer_phase(validator: &bool, _: u8, _: &[u8], body: &[u8]) -> Option<ProtectedReducerPhaseV1> {
        (*validator && body == b"body0001").then_some(ProtectedReducerPhaseV1::Prepared)
    }
    fn validates_identity(_: u8, identity: &[u8]) -> bool {
        identity.len() == 1 && identity[0] != 0
    }
}

fn envelope(identity: u8) -> ProtectedDomainEnvelopeV1<Schema> {
    let key = ProtectedDomainKeyV1::<Schema>::new(1, vec![identity]).unwrap();
    let payload = encode_reducer_payload_with_validator(&key, b"body0001", &true).unwrap();
    ProtectedDomainEnvelopeV1::new_with_validator(key, 1, None, payload, &true).unwrap()
}

fn member(identity: u8, id: u8, digest: Option<ObjectDigest>) -> DurableDomainMemberV1<Schema> {
    let envelope = envelope(identity);
    let transaction = [id; 16];
    let set = digest.unwrap_or_else(||
        domain_transaction_set_digest::<Schema>(transaction, std::slice::from_ref(&envelope)));
    encode_durable_member(transaction, 0, 1, set, envelope).unwrap()
}

fn rows(members: &[DurableDomainMemberV1<Schema>])
    -> impl Iterator<Item = (RecordNamespace, &[u8], &[u8])>
{
    members.iter().map(|member|
        (RecordNamespace::DesiredState, member.envelope().key().as_bytes(), member.encoded()))
}

#[test]
fn completed_replay_matches_ordinary_and_moves_the_same_projection_once() {
    let members = [member(2, 8, None), member(1, 7, None)];
    let ordinary = replay_projection_records::<Schema>(rows(&members), &true).unwrap();
    let mut capture = ReplayProjectionRecordsCaptureV1::<Schema>::new();

    replay_projection_records_retaining_v1(rows(&members), &true, &mut capture).unwrap();
    assert_eq!(capture.projection(), Some(&ordinary));
    let records = capture.projection().unwrap().records.as_ptr();
    let taken = capture.take_projection_once().unwrap();

    assert_eq!(taken, ordinary);
    assert_eq!(taken.records.as_ptr(), records);
    assert!(capture.take_projection_once().is_none());
}

#[test]
fn malformed_later_member_keeps_prior_rows_current_key_and_original_cause() {
    let first = member(1, 7, None);
    let second = member(2, 8, None);
    let mut malformed = second.encoded().to_vec();
    malformed[10] = 1;
    let rows = || [
        (RecordNamespace::DesiredState, first.envelope().key().as_bytes(), first.encoded()),
        (RecordNamespace::DesiredState, second.envelope().key().as_bytes(), malformed.as_slice()),
    ].into_iter();
    let mut capture = ReplayProjectionRecordsCaptureV1::<Schema>::new();

    assert!(replay_projection_records::<Schema>(rows(), &true).is_err());
    assert!(replay_projection_records_retaining_v1(rows(), &true, &mut capture).is_err());
    assert_eq!(capture.work.members.len(), 1);
    assert_eq!(capture.work.members[0].encoded(), first.encoded());
    assert_eq!(capture.work.seen.len(), 2);
    assert_eq!(capture.work.decode.key.as_ref(), Some(second.envelope().key()));
    let cause = capture.failure().unwrap() as *const _;
    let bytes = capture.work.members[0].encoded().as_ptr();

    assert!(replay_projection_records_retaining_v1(rows(), &true, &mut capture).is_err());
    assert_eq!(capture.failure().unwrap() as *const _, cause);
    assert_eq!(capture.work.members[0].encoded().as_ptr(), bytes);
    assert!(capture.take_projection_once().is_none());
}

#[test]
fn invalid_schema_identity_keeps_the_actual_partial_identity() {
    let mut invalid = Schema::KEY_PREFIX.to_vec();
    invalid.extend_from_slice(&[1, 1, 0, 1, 0]);
    let mut capture = ReplayProjectionRecordsCaptureV1::<Schema>::new();

    assert!(replay_projection_records_retaining_v1(
        [(RecordNamespace::DesiredState, invalid.as_slice(), &[][..])].into_iter(),
        &true, &mut capture,
    ).is_err());

    assert_eq!(capture.work.decode.identity, [0]);
    assert!(capture.work.decode.key.is_none());
    assert!(capture.work.members.is_empty());
}

#[test]
fn forged_envelope_digest_keeps_candidate_and_roundtrip_before_outer_refusal() {
    let valid = member(1, 7, None);
    let mut bytes = valid.encoded().to_vec();
    let last_envelope_digest = bytes.len() - 33;
    bytes[last_envelope_digest] ^= 1;
    let end = bytes.len() - 32;
    let digest: [u8; 32] = Sha256::new().chain_update(Schema::HASH_DOMAIN)
        .chain_update(b"durable-member\0").chain_update(&bytes[..end]).finalize().into();
    bytes[end..].copy_from_slice(&digest);
    let mut capture = ReplayProjectionRecordsCaptureV1::<Schema>::new();

    assert!(replay_projection_records_retaining_v1(
        [(RecordNamespace::DesiredState, valid.envelope().key().as_bytes(), bytes.as_slice())].into_iter(),
        &true, &mut capture,
    ).is_err());

    assert_eq!(capture.work.decode.envelope.as_ref(), Some(valid.envelope()));
    assert_eq!(capture.work.decode.roundtrip, valid.envelope().encode());
    assert!(!capture.work.decode.derived.is_empty());
    assert!(!capture.work.decode.decoded_companions.is_empty());
}

#[test]
fn bad_member_set_keeps_completed_groups_and_the_current_cloned_envelopes() {
    let members = [member(1, 1, None), member(2, 2, Some(ObjectDigest::from_bytes([9; 32])))];
    let mut capture = ReplayProjectionRecordsCaptureV1::<Schema>::new();

    assert!(replay_projection_records::<Schema>(rows(&members), &true).is_err());
    assert!(replay_projection_records_retaining_v1(rows(&members), &true, &mut capture).is_err());

    assert_eq!(capture.work.members.len(), 2);
    assert_eq!(capture.work.reconstruction.transactions.len(), 1);
    assert_eq!(capture.work.reconstruction.records, [members[1].envelope().clone()]);
    assert_eq!(capture.work.reconstruction.group, [1]);
    assert!(capture.projection().is_none());
}

#[test]
fn reached_geometry_is_checked_and_includes_current_partial_work() {
    assert!(ReplayProjectionRecordsCaptureV1::<Schema>::receiving_construction_bytes_v1()
        .is_some_and(|bytes| bytes >= 2 * size_of::<ReplayProjectionRecordsCaptureV1<Schema>>()));
    assert!(ReplayProjectionRecordsCaptureV1::<Schema>::receiving_carrier_bytes_v1(usize::MAX).is_none());
    assert!(ReplayProjectionRecordsCaptureV1::<Schema>::receiving_metadata_cells_v1(usize::MAX).is_none());
}

#[test]
fn schema_refusal_keeps_generic_key_payload_and_derived_prefix() {
    let valid = member(1, 7, None);
    let mut capture = ReplayProjectionRecordsCaptureV1::<Schema>::new();

    assert!(replay_projection_records_retaining_v1(
        rows(std::slice::from_ref(&valid)), &false, &mut capture,
    ).is_err());

    assert_eq!(capture.work.decode.key.as_ref(), Some(valid.envelope().key()));
    assert_eq!(capture.work.decode.payload, valid.envelope().payload());
    assert!(!capture.work.decode.derived.is_empty());
    assert!(!capture.work.decode.encoded_derived.is_empty());
    assert!(capture.work.decode.envelope.is_none());
}

#[test]
fn duplicate_key_keeps_the_actual_duplicate_allocation_before_insertion() {
    let valid = member(1, 7, None);
    let mut capture = ReplayProjectionRecordsCaptureV1::<Schema>::new();
    let record = (RecordNamespace::DesiredState,
        valid.envelope().key().as_bytes(), valid.encoded());

    assert!(replay_projection_records_retaining_v1(
        [record, record].into_iter(), &true, &mut capture,
    ).is_err());

    assert_eq!(capture.work.members.len(), 1);
    assert_eq!(capture.work.seen.len(), 1);
    assert_eq!(capture.work.seen_candidate.as_deref(), Some(valid.envelope().key().as_bytes()));
}

#[test]
fn independent_reducer_capture_keeps_companions_and_negative_prefix() {
    let envelope = envelope(1);
    let mut positive = ReducerPayloadDecodeCaptureV1::new();
    decode_reducer_payload_retaining_v1(
        envelope.key(), envelope.payload(), &true, &mut positive,
    ).unwrap();
    let ordinary = decode_reducer_payload_with_validator(
        envelope.key(), envelope.payload(), &true,
    ).unwrap();
    assert_eq!(&envelope.payload()[positive.body_range_v1().unwrap()], ordinary.body());
    assert_eq!(positive.companions(), ordinary.companions());
    assert_eq!(positive.phase_v1(), Some(ordinary.phase()));

    let mut negative = ReducerPayloadDecodeCaptureV1::new();
    assert!(decode_reducer_payload_retaining_v1(
        envelope.key(), envelope.payload(), &false, &mut negative,
    ).is_err());
    assert!(!negative.derived.is_empty());
    assert!(!negative.encoded_derived.is_empty());
    let cause = negative.failure().unwrap() as *const _;
    assert!(decode_reducer_payload_retaining_v1(
        envelope.key(), envelope.payload(), &true, &mut negative,
    ).is_err());
    assert_eq!(negative.failure().unwrap() as *const _, cause);
    assert!(negative.body_range_v1().is_none());
}


#[derive(Default)]
pub(super) struct SchemaOriginals {
    reached_body: Vec<u8>,
    calls: usize,
    refuse: bool,
}

impl ProtectedDomainSchemaReplayCaptureV1 for Schema {
    type ReplayCapture = SchemaOriginals;

    fn decode_reducer_phase_retaining_v1(
        validator: &bool, kind: u8, identity: &[u8], body: &[u8],
        capture: &mut SchemaOriginals,
    ) -> Option<ProtectedReducerPhaseV1> {
        capture.calls += 1;
        capture.reached_body = body.to_vec();
        if capture.refuse {
            None
        } else {
            Self::decode_reducer_phase(validator, kind, identity, body)
        }
    }
}

#[test]
fn associated_schema_sink_observes_the_actual_reducer_without_replacing_framing() {
    let valid = member(1, 7, None);
    let ordinary = replay_projection_records::<Schema>(rows(std::slice::from_ref(&valid)), &true).unwrap();
    let mut portable = ReplayProjectionRecordsCaptureV1::<Schema>::new();
    let mut schema = SchemaOriginals::default();

    replay_projection_records_with_schema_capture_v1(
        rows(std::slice::from_ref(&valid)), &true, &mut portable, &mut schema,
    ).unwrap();

    assert_eq!(portable.projection(), Some(&ordinary));
    assert_eq!(schema.reached_body, b"body0001");
    assert_eq!(schema.calls, 1);
}

#[test]
fn negative_schema_prefix_stays_beside_the_generic_failed_payload() {
    let valid = member(1, 7, None);
    let mut portable = ReplayProjectionRecordsCaptureV1::<Schema>::new();
    let mut schema = SchemaOriginals { refuse: true, ..SchemaOriginals::default() };

    assert!(replay_projection_records_with_schema_capture_v1(
        rows(std::slice::from_ref(&valid)), &true, &mut portable, &mut schema,
    ).is_err());
    assert_eq!(schema.reached_body, b"body0001");
    assert_eq!(portable.work.decode.payload, valid.envelope().payload());
    let generic_cause = portable.failure().unwrap() as *const _;

    assert!(replay_projection_records_with_schema_capture_v1(
        rows(std::slice::from_ref(&valid)), &true, &mut portable, &mut schema,
    ).is_err());
    assert_eq!(schema.calls, 1);
    assert_eq!(portable.failure().unwrap() as *const _, generic_cause);
}

#[test]
fn independent_reducer_schema_sink_shares_the_exact_validation_position() {
    let valid = envelope(1);
    let mut portable = ReducerPayloadDecodeCaptureV1::new();
    let mut schema = SchemaOriginals::default();

    decode_reducer_payload_with_schema_capture_v1(
        valid.key(), valid.payload(), &true, &mut portable, &mut schema,
    ).unwrap();

    assert_eq!(&valid.payload()[portable.body_range_v1().unwrap()], schema.reached_body);
    assert_eq!(schema.calls, 1);
}

#[test]
fn borrowed_framing_matches_actual_retained_codecs_without_adopting_schema_evidence() {
    use super::super::borrowed::{borrow_protected_key_data_v1, DurableMemberFrameDataV1,
        ProtectedEnvelopeFrameDataV1, ReducerFrameDataV1};
    let actual = member(7, 8, None);
    let bytes = actual.encoded();
    let key = actual.envelope().key();
    assert_eq!(borrow_protected_key_data_v1(key.as_bytes(), Schema::KEY_PREFIX).unwrap(), (1, &[7][..]));
    let member = DurableMemberFrameDataV1::decode(bytes, Schema::MAXIMUM_PAYLOAD_BYTES, Schema::HASH_DOMAIN).unwrap();
    let envelope = ProtectedEnvelopeFrameDataV1::decode(member.envelope, key.as_bytes(),
        &Schema::MAGIC, 1, Schema::MAXIMUM_PAYLOAD_BYTES, Schema::HASH_DOMAIN).unwrap();
    let reducer = ReducerFrameDataV1::decode(envelope.payload, 1, 1,
        Schema::MAXIMUM_PAYLOAD_BYTES, Schema::HASH_DOMAIN).unwrap();
    assert_eq!(member.transaction_id, [8;16]);
    assert_eq!(envelope.revision, actual.envelope().revision());
    assert_eq!(envelope.payload, actual.envelope().payload());
    assert_eq!(reducer.body, b"body0001");
    assert_eq!(reducer.phase, ProtectedReducerPhaseV1::Prepared);
    // Framing deliberately does not adopt schema evidence: the canonical full
    // decoder independently refuses the exact same bytes under a failed validator.
    assert!(decode_durable_member::<Schema>(key.clone(), bytes, &false).is_err());
    for index in [0, 8, 11, 12, 28, 30, 32, 64, bytes.len()-1] {
        let mut changed = bytes.to_vec(); changed[index] ^= 1;
        assert!(DurableMemberFrameDataV1::decode(&changed, Schema::MAXIMUM_PAYLOAD_BYTES, Schema::HASH_DOMAIN).is_err());
    }
}
