//! Real signed Capture60 and Host first-Observe fixture DATA.
//!
//! This fixture reuses the canonical registration, BSA and companion engines.
//! It creates no live native Capture, permission or completed Storage owner.

use super::*;
use crate::controller_capture_admission::ControllerCaptureAdmissionAnchorDataV1;
use crate::host_execution::admission_content::HostExecutionAdmissionContentV5;
use crate::storage_capture_grant::{StorageCaptureGrantMethodV1, StorageCaptureGrantSourceV1};
use crate::storage_output_reserve::{StorageOutputReserveRecordsV1, fixture::{fixture, seal}};

pub(super) struct CaptureFixtureData {
    pub(super) source: StorageCaptureGrantSourceV1,
    pub(super) ongoing: crate::storage_capture_grant::StorageCaptureGrantSourceV2,
    pub(super) anchor: Vec<u8>,
    pub(super) effect_cutoff: u64,
    registration: Vec<u8>,
    response: Vec<u8>,
}

impl CaptureFixtureData {
    pub(super) fn content(&self, specification: &[u8]) -> Vec<u8> {
        HostExecutionAdmissionContentV5::new_capture_v5(
            specification, &self.registration, &self.ongoing, &self.response)
            .unwrap().encode().unwrap()

    }
}

fn registration_source(spec: &ExecutionSpecV1) -> ReserveStorageExecutionOutputRequestV1 {
    let (mut request, _) = fixture();
    let assignment = spec.resources().output_bytes().assignment().broker_assignment().unwrap();
    let mut source: [u8; 688] = request.canonical_controller_attempt[8..696].try_into().unwrap();
    source[120..128].copy_from_slice(&100_000_u64.to_be_bytes());
    source[296..328].copy_from_slice(assignment.digest().as_bytes());
    source[552..568].copy_from_slice(assignment.sandbox().as_bytes());
    source[568..584].copy_from_slice(assignment.incarnation().as_bytes());
    source[584..600].copy_from_slice(&[4; 16]);
    source[600..608].copy_from_slice(&assignment.epoch().get().to_be_bytes());
    source[608..616].copy_from_slice(&assignment.desired_generation().get().to_be_bytes());
    source[624..656].copy_from_slice(assignment.digest().as_bytes());
    let digest = Sha256::new().chain_update(b"aos.sandbox.controller-execution-preissue.v1\0")
        .chain_update(&source[8..160]).finalize();
    source[160..192].copy_from_slice(&digest);
    let digest = Sha256::digest(&source[192..488]);
    source[488..520].copy_from_slice(&digest);
    seal(b"aos.sandbox.controller-execution-reserve-source.v1\0", &mut source, 656);
    let semantic = crate::semantics::host_output_reserve_grant_v1(assignment, [12; 16], &source).unwrap();
    let attempt = &mut request.canonical_controller_attempt;
    attempt[8..696].copy_from_slice(&source);
    attempt[744..776].copy_from_slice(semantic.commitment().digest().as_bytes());
    attempt[776..784].copy_from_slice(&CUTOFF.to_be_bytes());
    seal(b"aos.sandbox.controller-output-attempt.v1\0", attempt, 784);
    let settlement = &mut request.canonical_controller_settlement;
    settlement[40..72].copy_from_slice(&attempt[784..816]);
    seal(b"aos.sandbox.controller-output-settlement.v1\0", settlement, 176);
    let mut request_header = header([18; 16]);
    request_header.maximum_response_bytes = 4096;
    request.header = Some(request_header).into();
    request
}

pub(super) fn logical_data_v5(spec: &ExecutionSpecV1) -> (
    StorageOutputReserveRecordsV1, Vec<u8>, Vec<u8>, Vec<u8>, BrokerAuthorizationArtifactsV1,
) {
    let assignment = spec.resources().output_bytes().assignment().broker_assignment().unwrap();
    let original = registration_source(spec);
    let records = StorageOutputReserveRecordsV1::from_canonical_records(
        &original.canonical_controller_attempt, &original.canonical_controller_settlement).unwrap();
    let body = original.encode_to_vec();
    let logical_grant = crate::storage_output_reserve::storage_output_reserve_grant_v1(
        assignment, [18; 16], &body).unwrap();
    let logical_authority = authorization_artifacts_for(assignment, logical_grant,
        BrokerAudience::Storage, ProtocolId::StorageBroker);

    // These are synthetic returned historical bytes, never a Storage MAC or
    // native writer proof. Their exact bytes are covered by the real BSA.
    let mut row = vec![9; 177];
    row[..8].copy_from_slice(b"AOSEOR03");
    row[8..24].copy_from_slice(spec.execution().as_bytes());
    row[24..40].copy_from_slice(&[2; 16]);
    row[40..72].copy_from_slice(assignment.digest().as_bytes());
    row[72..104].copy_from_slice(records.host_locator().claim_digest().as_bytes());
    row[104..128].fill(0);
    row[128] = 1;
    row[129..145].fill(0);
    let mut marker = vec![10; 184];
    marker[..8].copy_from_slice(b"AOSEOS01");
    marker[8..24].copy_from_slice(&[18; 16]);
    marker[24..40].copy_from_slice(spec.execution().as_bytes());
    marker[40..56].copy_from_slice(&[2; 16]);
    marker[56..88].copy_from_slice(descriptor_for_bytes(
        MediaType::new(PortableMediaType::BrokerAuthorizationPlan.as_str().to_owned()).unwrap(),
        &logical_authority.broker_plan).digest().as_bytes());
    marker[120..152].copy_from_slice(&Sha256::digest(&row));
    let registration = StorageOutputRegistrationResponseV1 {
        canonical_reservation: row.clone(), canonical_original_marker: marker,
        ..Default::default()
    }.encode_to_vec();
    (records, body, row, registration, logical_authority)
}

pub(super) fn lifetime_data_v5(spec: &ExecutionSpecV1, original_lease_digest: ObjectDigest)
    -> crate::storage_capture_lifetime::StorageCaptureExecutionLifetimeDataV2
{
    let assignment = spec.resources().output_bytes().assignment().broker_assignment().unwrap();
    let original_clock = RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted([1; 16]).unwrap(), [4; 16], 50, 40_000).unwrap();
    let before = RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted([1; 16]).unwrap(), [4; 16], 50, 45_000).unwrap();
    let origins = crate::storage_capture_lifetime::StorageCaptureLifetimeOriginsDataV2 {
        original_target_clock: original_clock,
        original_lease_digest,
        original_lease_generation: 1,
        original_lease_authority_expires_seconds: 200,
        original_lease_maximum_clock_skew_seconds: 10,
        original_root_plan_expires_seconds: Some(200),
        original_residency_deadline_boottime_nanoseconds: original_clock
            .conservative_lease_expiry_deadline_data_v2(200, 10).unwrap()
            .min(original_clock.conservative_expiry_deadline_data_v1(200).unwrap()),
        first_pre_spawn_clock: before,
        execution_parent_plan_expires_seconds: 200,
    };
    crate::storage_capture_lifetime::StorageCaptureExecutionLifetimeDataV2::from_pre_spawn_sources_data_v2(
        spec, OperationId::from_bytes([2; 16]), OperationId::from_bytes([2; 16]),
        ObjectDigest::from_bytes([18; 32]), assignment, &origins).unwrap()
}

fn capture_data() -> CaptureFixtureData {
    let spec = fixture_spec(257);
    let assignment = spec.resources().output_bytes().assignment().broker_assignment().unwrap();
    let (records, body, row, registration, logical_authority) = logical_data_v5(&spec);
    let methods = [BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT,
        BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1,
        BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1];
    let mut history = HistoryFixture { signed: signed_checkpoint_for(BrokerSessionProtocolV1::Storage, &methods, 2),
        records: Vec::new(), catalog: [37; 32] };
    let original_lease_digest = descriptor_for_bytes(MediaType::new(
        PortableMediaType::OwnershipLease.as_str().to_owned()).unwrap(),
        &logical_authority.ownership_lease).digest();
    history.append(methods[0], [18; 16], body.clone(), logical_authority, registration.clone());

    let mut source = [0; 512];
    source[..8].copy_from_slice(b"AOSSCG01");
    source[8..216].copy_from_slice(records.settlement());
    source[216..248].copy_from_slice(&Sha256::digest(&row));
    source[248..280].copy_from_slice(records.host_locator().claim_digest().as_bytes());
    source[280..296].copy_from_slice(&records.host_locator().original_request_id());
    source[296..312].copy_from_slice(assignment.sandbox().as_bytes());
    source[312..328].copy_from_slice(assignment.incarnation().as_bytes());
    source[328..336].copy_from_slice(&assignment.epoch().get().to_be_bytes());
    source[336..344].copy_from_slice(&assignment.desired_generation().get().to_be_bytes());
    source[344..376].copy_from_slice(assignment.digest().as_bytes());
    source[376..392].copy_from_slice(&[4; 16]);
    source[392..408].copy_from_slice(&[25; 16]);
    source[408..440].copy_from_slice(&[26; 32]);
    source[464..472].copy_from_slice(&200_u64.to_be_bytes());
    source[472..480].copy_from_slice(&20_u64.to_be_bytes());
    source[480..488].copy_from_slice(&30_u64.to_be_bytes());
    source[488..496].copy_from_slice(&CUTOFF.to_be_bytes());
    source[496..512].copy_from_slice(&[25; 16]);
    let source = StorageCaptureGrantSourceV1::from_canonical_bytes(&source).unwrap();
    let lifetime = lifetime_data_v5(&spec, original_lease_digest);
    let ongoing = crate::storage_capture_grant::StorageCaptureGrantSourceV2::from_original_data_v2(source, lifetime).unwrap();
    let grant = ongoing.broker_grant_v2(StorageCaptureGrantMethodV1::Reserve, [25; 16]).unwrap();
    let authority = authorization_artifacts_for(assignment, grant, BrokerAudience::Storage, ProtocolId::StorageBroker);
    let mut request_header = header([25; 16]);
    request_header.deadline_boottime_nanoseconds = CUTOFF;
    request_header.maximum_response_bytes = 4096;
    let request = ReserveStorageExecutionCaptureRequestV1 { header: Some(request_header).into(),
        canonical_grant_source: ongoing.canonical_bytes_v2().to_vec(),
        canonical_original_storage_output_request: body, ..Default::default() };
    let locator = ongoing.locator_v2();
    let effect_cutoff = ongoing.effective_execution_deadline_v2();
    let response = StorageExecutionCaptureAttemptV1 {
        status: StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_EFFECT_POSSIBLE.into(),
        execution_id: locator.execution().as_bytes().to_vec(),
        create_operation_id: locator.create_operation().as_bytes().to_vec(),
        original_reserve_request_id: locator.original_reserve_request_id().to_vec(),
        grant_source_digest: locator.source_digest().as_bytes().to_vec(),
        output_record_digest: locator.output_record_digest().as_bytes().to_vec(),
        attempt_id: vec![27; 16], durable_attempt_digest: vec![28; 32],
        effective_deadline_boottime_nanoseconds: effect_cutoff, ..Default::default()
    }.encode_to_vec();
    history.append(methods[1], [25; 16], request.encode_to_vec(), authority, response.clone());
    let anchor = ControllerCaptureAdmissionAnchorDataV1::new_ongoing_v4(
        &ongoing, &response, &history.stored()).unwrap().canonical_bytes_v1().to_vec();
    // A later genuine signed61 uses the same original selector and returns no
    // new admission. The immutable60 anchor retains the earlier exact prefix.
    let query_grant = ongoing.broker_grant_v2(StorageCaptureGrantMethodV1::Query, [29; 16]).unwrap();
    let query_authority = authorization_artifacts_for(assignment, query_grant,
        BrokerAudience::Storage, ProtocolId::StorageBroker);
    let mut query_header = header([29; 16]);
    query_header.deadline_boottime_nanoseconds = CUTOFF;
    query_header.maximum_response_bytes = 4096;
    let query = QueryStorageExecutionCaptureRequestV1 { header: Some(query_header).into(),
        canonical_grant_source: ongoing.canonical_bytes_v2().to_vec(), ..Default::default() };
    let queried = history.append(methods[2], [29; 16], query.encode_to_vec(), query_authority, response.clone());
    let checkpoint = &history.signed.checkpoint;
    let recovered = historical_terminal_outcome(&history.records, history.records.len() - 1,
        checkpoint, &checkpoint.verify().unwrap()).unwrap();
    assert_eq!(recovered.canonical_packet(), queried.canonical_packet());
    assert_eq!(recovered.request().canonical_packet(), queried.request().canonical_packet());
    assert_eq!(ControllerCaptureAdmissionAnchorDataV1::decode(&anchor).unwrap().source_v1(), &source);
    CaptureFixtureData { source, ongoing, anchor, effect_cutoff, registration, response }
}

/// Builds real signed ongoing-Capture historical DATA through the sole codecs.
///
/// # Panics
/// Panics if synthetic fixed test identities or canonical signed joins disagree.
#[must_use]
pub fn signed_ongoing_capture_observe_completion_fixture_v3() -> (SignedObserveCompletionFixtureV1, Vec<u8>) {
    let (fixture, anchor) = signed_observe_fixture_engine(Some(capture_data()));
    (fixture, anchor.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_request_borrow_requires_full_actual_signed_v5_content_validation() {
        let physical = capture_data();
        let (fixture, _) = signed_observe_fixture_engine(Some(capture_data()));
        let (core, _, _) = crate::domain_ledger::execution_observe_reservation::completion::admission::split(
            fixture.completion.bytes()).unwrap();
        let fields = crate::domain_ledger::execution_observe_reservation::completion::split(core).unwrap();
        let stored = StoredBrokerSessionHistoryV1::decode(
            &canonical_protocol_key_v1(BrokerSessionProtocolV1::Host), fields.session).unwrap();
        let checkpoint = stored.checkpoint.as_ref().unwrap();
        let transcript = checkpoint.verify().unwrap();
        let model = stored.history_model().unwrap();
        let records = model.records();
        let actual = historical_terminal_outcome(records, records.len() - 3, checkpoint, &transcript).unwrap();
        let peer = checkpoint.peer();
        let policy = crate::PeerPolicy { uid: peer.uid, gid: Some(peer.gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER };
        let mut apply = crate::host_execution::decode_host_execution_apply_v1(
            actual.request().exact_body(), peer, policy, 50_000).unwrap();
        assert!(apply.admission_accepted_request_digest_v5().is_none());
        assert!(apply.verify_content(b"foreign sealed content").is_err());
        assert!(apply.admission_accepted_request_digest_v5().is_none());

        let current_content = physical.content(&fixture.specification);
        let mut obsolete_content = current_content.clone();
        obsolete_content[..8].copy_from_slice(b"AOSHEC04");
        assert!(apply.verify_content(&obsolete_content).is_err());
        apply.verify_content(&current_content).unwrap();
        let actual_fields = ExecutionSpecAttemptFieldsV1::decode(&fixture.specification).unwrap();
        assert_eq!(apply.admission_accepted_request_digest_v5(), Some(actual_fields.accepted_request_digest));
        assert_eq!(apply.specification().unwrap(), &actual_fields.decoded_specification().unwrap());
    }

    #[test]
    fn signed_ongoing_capture_reopens_exact_full_source_and_rejects_old_wrapper() {
        let (fixture, anchor) = signed_ongoing_capture_observe_completion_fixture_v3();
        let decoded = ObserveChildCompletionDataV1::decode(
            &fixture.reservation, &fixture.receipt, fixture.completion.bytes()).unwrap();
        assert_eq!(decoded, fixture.completion);
        assert_eq!(&decoded.bytes()[..8], b"AOSCOC04");
        assert_eq!(decoded.sources().unwrap().capture_admission_anchor, Some(anchor.as_slice()));

        let original = ControllerCaptureAdmissionAnchorDataV1::decode(&anchor).unwrap();
        let source = original.ongoing_source_v2().unwrap();
        assert!(source.effective_execution_deadline_v2()
            > source.original_source_v1().original_deadline_boottime_nanoseconds());
        let fields = ExecutionSpecAttemptFieldsV1::decode(&fixture.specification).unwrap();
        source.lifetime_v2().require_specification_data_v2(&fields.decoded_specification().unwrap(),
            fields.create_operation, fields.create_operation, fields.accepted_request_digest).unwrap();
        assert!(source.lifetime_v2().require_specification_data_v2(&fields.decoded_specification().unwrap(),
            fields.create_operation, OperationId::from_bytes([99; 16]), fields.accepted_request_digest).is_err());
        assert!(source.lifetime_v2().require_specification_data_v2(&fields.decoded_specification().unwrap(),
            fields.create_operation, fields.create_operation, ObjectDigest::from_bytes([99; 32])).is_err());

        let (core, registration, selector) = crate::domain_ledger::execution_observe_reservation::completion::admission::split(decoded.bytes()).unwrap();
        let fields = super::super::super::split(core).unwrap();
        let admission = super::super::admission::reconstruct_content_v5(&fields, registration, selector).unwrap();
        let mut old_anchor = anchor.clone();
        old_anchor[..8].copy_from_slice(b"AOSCCA01");
        assert!(crate::domain_ledger::execution_observe_reservation::completion::admission::encode(core, &admission, Some(&old_anchor)).is_err());
        assert!(ObserveChildCompletionDataV1::decode(&fixture.reservation, &fixture.receipt, core).is_err());
        let mut old_wrapper = decoded.bytes().to_vec();
        old_wrapper[..8].copy_from_slice(b"AOSCOC02");
        assert!(ObserveChildCompletionDataV1::decode(&fixture.reservation, &fixture.receipt, &old_wrapper).is_err());
    }

    #[test]
    fn ongoing_begin_has_distinct_acquisition_and_execution_bounds_without_renewal() {
        use crate::storage_capture_session::ongoing::{CaptureHeldBeginDataV3, CAPTURE_BEGIN_BYTES_V3};
        let fixture = capture_data();
        let source = fixture.ongoing;
        let attempt = crate::storage_capture_grant::decode_storage_capture_attempt_response_ongoing_v2(
            &fixture.response, &source, false).unwrap();
        let ongoing = source.effective_execution_deadline_v2();
        let acquisition = source.original_source_v1().original_deadline_boottime_nanoseconds();
        let begin = CaptureHeldBeginDataV3::new([71; 32], ongoing, acquisition,
            acquisition - 1, source, attempt).unwrap();
        let encoded = begin.encode().unwrap();
        assert_eq!(encoded.len(), CAPTURE_BEGIN_BYTES_V3);
        assert_eq!(&encoded[..8], b"AOSEOHS3");
        assert_eq!(CaptureHeldBeginDataV3::decode(&encoded).unwrap(), begin);
        let mut obsolete = encoded;
        obsolete[..8].copy_from_slice(b"AOSEOHS2");
        assert!(CaptureHeldBeginDataV3::decode(&obsolete[..620]).is_err());

        let mut changed = begin;
        changed.cutoff_boottime_nanoseconds = ongoing + 1;
        assert!(changed.encode().is_err());
        changed = begin;
        changed.acquisition_cutoff_boottime_nanoseconds = acquisition + 1;
        assert!(changed.encode().is_err());
        changed = begin;
        changed.acquisition_deadline_boottime_nanoseconds = acquisition + 1;
        assert!(changed.encode().is_err());
        let mut changed = encoded;
        changed[60 + 944 - 1] ^= 1;
        assert!(CaptureHeldBeginDataV3::decode(&changed).is_err());
    }

    #[test]
    fn signed_capture_reopens_exact_anchor_and_rejects_unwrapped_completion() {
        let (fixture, anchor) = signed_ongoing_capture_observe_completion_fixture_v3();
        let sources = fixture.completion.sources().unwrap();
        assert_eq!(sources.capture_admission_anchor, Some(anchor.as_slice()));
        let (core, registration, selector) = crate::domain_ledger::execution_observe_reservation::completion::admission::split(
            fixture.completion.bytes()).unwrap();
        assert_eq!(selector.capture_anchor_v5(), Some(anchor.as_slice()));
        let fields = super::super::super::split(core).unwrap();
        let admission = super::super::admission::reconstruct_content_v5(&fields, registration, selector).unwrap();
        assert!(ObserveChildCompletionDataV1::decode(&fixture.reservation, &fixture.receipt, core).is_err());
        assert_eq!(ObserveChildCompletionDataV1::decode(&fixture.reservation, &fixture.receipt,
            fixture.completion.bytes()).unwrap(), fixture.completion);
        let applied = crate::domain_ledger::effect_history::EffectLedgerRecord::from_parts((
            crate::domain_ledger::effect_history::EffectPlan::reserved_observe(&fixture.reservation),
            crate::domain_ledger::effect_history::EffectState::Applied { attempt: 1,
                receipt: crate::domain_ledger::effect_history::EffectReceipt::new(fixture.receipt.to_vec()).unwrap() },
            None, None));
        let encoded = crate::domain_ledger::effect_history::observe_completion::encode_completed_observe_effect_v1(
            &applied, &fixture.completion).unwrap();
        assert_eq!(crate::domain_ledger::effect_history::decode_effect(&encoded).unwrap(), applied);
        assert_eq!(crate::domain_ledger::effect_history::observe_completion::decode_completed_observe_effect_v1(
            &encoded).unwrap().1, fixture.completion);

        let mut changed_anchor = anchor.clone();
        let last = changed_anchor.len() - 1;
        changed_anchor[last] ^= 1;
        let changed = crate::domain_ledger::execution_observe_reservation::completion::admission::encode(
            core, &admission, Some(&changed_anchor)).unwrap();
        assert!(ObserveChildCompletionDataV1::decode(&fixture.reservation, &fixture.receipt, &changed).is_err());
        let fields = super::super::super::split(core).unwrap();
        assert_eq!(fields.cutoff, CUTOFF);
        let current = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(), [4; 16], 50, 50_000).unwrap();
        // The signed ongoing lifetime never extends the initial59 acquisition
        // cutoff of this completed first-Observe companion.
        assert!(ObserveChildCompletionDataV1::new_lifetime_v5(&fixture.reservation, fields.specification,
            fields.argument_receipt, fields.session, &admission, Some(&anchor), current, CUTOFF + 1, &fixture.receipt).is_err());
        let expired = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(), [4; 16], 50, CUTOFF).unwrap();
        assert!(ObserveChildCompletionDataV1::new_lifetime_v5(&fixture.reservation, fields.specification,
            fields.argument_receipt, fields.session, &admission, Some(&anchor), expired, CUTOFF, &fixture.receipt).is_err());
    }
}
