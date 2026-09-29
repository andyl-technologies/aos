//! Genuine native Complete/CAS/Accepted and current terminal metadata vectors.

use super::*;
use crate::mount_source_acquisition_state::*;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    assertion::{
        NativeHeldSettlementV1, ProviderNativeSettlementAssertionV1,
        StorageNativeSettlementAssertionV1,
    },
    recovery::*,
    witness::{
        NativeHeldRecordFamilyV1 as Family, PROVIDER_NATIVE_WITNESS_FAMILIES_V1,
        ProviderNativeHeldWitnessV1, StorageNativeHeldWitnessV1,
    },
};
use aos_sandbox_source_provider_protocol::*;
use ed25519_dalek::Signer as _;

mod receipt_fixture;
mod recovery;
mod v2;

fn native_fixture() -> Fixture {
    let session = fixture::signed_session([19; 16], 31);
    let (_, mount) = fixture::mount_acquire_request();
    let catalog = receipt_fixture::native_catalog(
        &session,
        digest_logical_binding_bytes(&mount.source_binding().canonical_bytes()),
    );
    let binding = NativeAcquireCatalogBindingV3::new(
        catalog.namespace_digest(),
        catalog.generation(),
        catalog.digest(),
        catalog.generation(),
        catalog.digest(),
        digest(63),
        digest(64),
    )
    .unwrap();
    Fixture::with_catalog(Some(binding), *catalog.digest().as_bytes())
}

fn provider_w(fixture: &Fixture) -> NativeHeldSectionV1 {
    let w = ProviderNativeHeldWitnessV1 {
        root_local_cookie: 9,
        storage_local_cookie: 10,
        completion_sequence: 11,
        challenge_sequence: 12,
        authority: SourceProviderAuthorityV1::new([2; 16], 1, digest(8)).unwrap(),
        native_namespace: digest(10),
        catalog_head: fixture.witness.provider_head,
        catalog_floor: fixture.witness.provider_floor,
        head_commitment: digest(63),
        publication: digest(64),
        selected_manifest: digest(65),
        backend_manifest: digest(66),
        verifier_manifest: digest(67),
        records: PROVIDER_NATIVE_WITNESS_FAMILIES_V1.map(terminal::provider_witness),
    };
    NativeHeldSectionV1::new(
        Tag::Witness,
        NativeHeldOwnerWitnessV1::Provider(w)
            .to_canonical_bytes()
            .unwrap(),
    )
    .unwrap()
}

fn sign_source(prepared: PreparedNativeHeldControlV1) -> SignedNativeHeldControlV1 {
    let signature = SigningKey::from_bytes(&[14; 32])
        .sign(&prepared.signature_message())
        .to_bytes();
    prepared.with_signature(signature)
}

fn root_w(fixture: &Fixture, records: [NativeHeldByteWitnessV1; 4]) -> NativeHeldSectionV1 {
    let mut w = fixture.witness.clone();
    w.records = records;
    NativeHeldSectionV1::new(
        Tag::Witness,
        NativeHeldOwnerWitnessV1::Root(w)
            .to_canonical_bytes()
            .unwrap(),
    )
    .unwrap()
}

struct AcceptedPrefix {
    fixture: Fixture,
    capture: receipt_fixture::OriginalNative,
    one: SignedNativeHeldControlV1,
    three: SignedNativeHeldControlV1,
    before_cas: RootNativeHeldGraphV1,
    after_cas: RootNativeHeldGraphV1,
    accepted: RootNativeHeldGraphV1,
    r: RootNativeDispositionAssertionV1,
    four: PreparedNativeHeldControlV1,
    cas_id: [u8; 16],
}

fn accepted_prefix() -> AcceptedPrefix {
    let fixture = native_fixture();
    let capture = receipt_fixture::original_native(&fixture);
    let one = sign(fixture.prepared());
    let full = NativeHeldScopeV1 {
        provider_attempt: capture.request.request().claims().attempt(),
        original_native_request: capture.request.digest(),
        ..fixture.scope
    };
    let mut issuance_key = vec![78; 16];
    issuance_key.extend_from_slice(capture.request.digest().as_bytes());
    let storage_w = StorageNativeHeldWitnessV1 {
        local_socket_cookie: 26,
        primary_sequence: 27,
        workspace_sequence: 28,
        request_trust_sequence: 29,
        issuance_sequence: 30,
        request_trust_generation: 31,
        request_trust_file: digest(32),
        issuance: NativeHeldByteWitnessV1::new(Family::StorageIssuance, issuance_key, digest(33))
            .unwrap(),
    };
    let two = PreparedNativeHeldControlV1::new(
        Kind::StorageHeld,
        full,
        one.digest(),
        vec![
            NativeHeldSectionV1::new(
                Tag::Witness,
                NativeHeldOwnerWitnessV1::Storage(storage_w)
                    .to_canonical_bytes()
                    .unwrap(),
            )
            .unwrap(),
            NativeHeldSectionV1::new(Tag::RootPrepared, one.to_canonical_bytes()).unwrap(),
            NativeHeldSectionV1::new(Tag::NativeReply, capture.reply.to_canonical_bytes()).unwrap(),
        ],
        NativeHeldSignerV1::Storage(capture.reply.acceptance().signer()),
    )
    .unwrap();
    let signature = SigningKey::from_bytes(&[77; 32])
        .sign(&two.signature_message())
        .to_bytes();
    let two = two.with_signature(signature);
    let artifact = super::super::graph::response_artifact(&capture.completed).unwrap();
    let three = sign_source(
        PreparedNativeHeldControlV1::new(
            Kind::ProviderHeld,
            full,
            two.digest(),
            vec![
                provider_w(&fixture),
                NativeHeldSectionV1::new(Tag::StorageHeld, two.to_canonical_bytes()).unwrap(),
                NativeHeldSectionV1::new(Tag::SourceArtifact, artifact.as_bytes().to_vec())
                    .unwrap(),
            ],
            NativeHeldSignerV1::SourceProvider(capture.request.signer().clone()),
        )
        .unwrap(),
    );
    let before_cas =
        fixture.graph(&fixture.sidecar(2, None, vec![one.clone(), three.clone()], None));
    let cas_id = [101; 16];

    let attempt = &capture.completed;
    let reference = RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    };
    let mut rows = before_cas.legacy().acquisitions.clone();
    let row = rows.get_mut(&attempt.owner.owner_id()).unwrap();
    row.revision += 1;
    row.acquire_lineage.root = reference;
    row.acquire_lineage.tail = reference;
    row.acquire_terminal_attempt = Some(reference);
    row.evidence = Some(receipt_fixture::acquire_evidence(row, attempt, &fixture.session).unwrap());
    let StoredRecordV2::Acquisition { value: sealed_row } =
        seal_record(StoredRecordV2::Acquisition { value: row.clone() }).unwrap()
    else {
        panic!("sealed acquisition variant");
    };
    *row = sealed_row.clone();
    let mut head = before_cas.legacy().provider_heads[&([1; 16], [2; 16])].clone();
    head.revision += 1;
    head.next_response_sequence += 1;
    head.pending_attempt = None;
    head.current_projection_epoch += 1;
    head.current_projection_digest = projection_from_entries(
        head.scope,
        head.current_projection_epoch,
        &projection_entries(head.scope, &rows),
    )
    .unwrap()
    .digest;
    head.last_reconciliation = None;
    let StoredRecordV2::ProviderHead { value: head } =
        seal_record(StoredRecordV2::ProviderHead { value: head }).unwrap()
    else {
        panic!("sealed head variant");
    };
    let mut canonical = fixture.legacy.clone();
    for record in [
        StoredRecordV2::ProviderQueryAttempt {
            value: attempt.clone(),
        },
        StoredRecordV2::Acquisition { value: sealed_row },
        StoredRecordV2::ProviderHead { value: head },
    ] {
        let (key, bytes) = encode_mount_source_state_record_v2(&record).unwrap();
        canonical.insert(key, bytes);
    }
    let sidecar = RootNativeHeldSidecarV1::new(
        fixture.scope,
        cas_id,
        None,
        None,
        None,
        NativeHeldCompletionSuffixV1::new(
            Owner::Root,
            3,
            fixture.scope.flight,
            None,
            vec![one.clone(), three.clone()],
        )
        .unwrap(),
    )
    .unwrap();
    let key = native_root_sidecar_key_v1(fixture.attempt.attempt_id).unwrap();
    canonical.insert(key.clone(), sidecar.to_canonical_bytes().unwrap());
    let after_cas = checked(&canonical).unwrap();
    let records = super::super::graph::companion_witnesses(&after_cas, &sidecar).unwrap();
    let r = RootNativeDispositionAssertionV1 {
        disposition: NativeHeldDispositionV1::Accepted,
        observation: RootNativeObservationV1::ProviderHeldObserved,
        scope: full,
        source_artifact: artifact,
        descriptor_commitment: source_root_descriptor_commitment_v1(&capture.descriptor),
        records: records.clone(),
    };
    let four = PreparedNativeHeldControlV1::new(
        Kind::RootAccepted,
        full,
        three.digest(),
        vec![
            root_w(&fixture, records),
            NativeHeldSectionV1::new(Tag::SourceArtifact, artifact.as_bytes().to_vec()).unwrap(),
            NativeHeldSectionV1::new(
                Tag::RootDispositionAssertion,
                r.to_canonical_bytes().unwrap().to_vec(),
            )
            .unwrap(),
        ],
        one.prepared().signer().clone(),
    )
    .unwrap();
    let sidecar = RootNativeHeldSidecarV1::new(
        fixture.scope,
        cas_id,
        Some(r.clone()),
        None,
        None,
        NativeHeldCompletionSuffixV1::new(
            Owner::Root,
            4,
            fixture.scope.flight,
            Some(four.clone()),
            vec![one.clone(), three.clone()],
        )
        .unwrap(),
    )
    .unwrap();
    canonical.insert(key, sidecar.to_canonical_bytes().unwrap());
    let accepted = checked(&canonical).unwrap();
    AcceptedPrefix {
        fixture,
        capture,
        one,
        three,
        before_cas,
        after_cas,
        accepted,
        r,
        four,
        cas_id,
    }
}

#[test]
fn complete_response_cas_and_accepted_preparation_use_genuine_canonical_rows() {
    let prefix = accepted_prefix();
    let attempt = prefix.fixture.attempt.attempt_id;
    let phase0 = prefix.fixture.graph(&prefix.fixture.phase0());
    let phase1 = prefix.fixture.graph(&prefix.fixture.phase1());
    let initial = checked(&BTreeMap::new()).unwrap();
    assert_eq!(
        validate_native_root_transition_v1(&initial, &phase0, attempt, [100; 16])
            .unwrap()
            .kind,
        RootNativeTransitionKindV1::PreparedAssertionRecorded
    );
    assert_eq!(
        validate_native_root_transition_v1(&phase0, &phase1, attempt, [121; 16])
            .unwrap()
            .kind,
        RootNativeTransitionKindV1::PreparedStored
    );
    assert_eq!(
        validate_native_root_transition_v1(&phase1, &prefix.before_cas, attempt, [122; 16])
            .unwrap()
            .kind,
        RootNativeTransitionKindV1::HeldStored
    );
    let cas = validate_native_root_transition_v1(
        &prefix.before_cas,
        &prefix.after_cas,
        attempt,
        prefix.cas_id,
    )
    .unwrap();
    assert_eq!(
        cas.kind,
        RootNativeTransitionKindV1::ResponseDispositionRecorded
    );
    assert_eq!(cas.puts.len(), 4);
    assert_eq!(cas.maximum_remaining_transactions, 4);
    assert_eq!(
        prefix.after_cas.legacy().provider_attempts[&attempt].revision,
        2
    );
    assert!(
        validate_native_root_transition_v1(
            &prefix.before_cas,
            &prefix.after_cas,
            attempt,
            [102; 16]
        )
        .is_err()
    );
    assert!(
        validate_native_root_cold_transition_v1(
            &prefix.before_cas,
            &prefix.after_cas,
            attempt,
            prefix.cas_id
        )
        .is_err()
    );

    let accepted =
        validate_native_root_transition_v1(&prefix.after_cas, &prefix.accepted, attempt, [103; 16])
            .unwrap();
    assert_eq!(
        accepted.kind,
        RootNativeTransitionKindV1::AcceptedAssertionRecorded
    );
    assert_eq!(accepted.puts.len(), 1);
    assert_eq!(accepted.maximum_remaining_transactions, 3);
    assert!(
        validate_native_root_cold_transition_v1(
            &prefix.after_cas,
            &prefix.accepted,
            attempt,
            [103; 16]
        )
        .is_err()
    );
    let row = &prefix.accepted.legacy().acquisitions[&prefix.fixture.attempt.owner.owner_id()];
    assert_eq!(row.phase, SourceAcquisitionPhaseV2::PendingQuery);
    assert!(row.manager_custody.is_none());
    assert!(row.positive_custody_digest.is_none());
    assert_eq!(
        row.evidence.as_ref().unwrap().descriptor_commitment,
        *prefix.r.descriptor_commitment.as_bytes()
    );
    assert_eq!(
        prefix.capture.reply.acceptance().acceptance().digest(),
        prefix.capture.acceptance.digest()
    );
    assert_eq!(
        prefix.capture.reply.acceptance().digest(),
        prefix.capture.signed_acceptance_digest
    );
    assert_eq!(
        prefix.capture.request.digest(),
        prefix.capture.request_digest
    );

    let mut canonical = prefix.accepted.canonical_records().clone();
    let stored = RootNativeHeldSidecarV1::new(
        prefix.fixture.scope,
        prefix.cas_id,
        Some(prefix.r.clone()),
        None,
        None,
        NativeHeldCompletionSuffixV1::new(
            Owner::Root,
            5,
            prefix.fixture.scope.flight,
            None,
            vec![
                prefix.one.clone(),
                prefix.three.clone(),
                sign(prefix.four.clone()),
            ],
        )
        .unwrap(),
    )
    .unwrap();
    canonical.insert(
        native_root_sidecar_key_v1(attempt).unwrap(),
        stored.to_canonical_bytes().unwrap(),
    );
    let after = checked(&canonical).unwrap();
    assert_eq!(
        validate_native_root_transition_v1(&prefix.accepted, &after, attempt, [104; 16])
            .unwrap()
            .kind,
        RootNativeTransitionKindV1::DispositionStored
    );
    assert!(
        validate_native_root_transition_v1(&after, &prefix.accepted, attempt, [105; 16]).is_err()
    );
}

#[test]
fn normal_accepted_terminal_and_original_hot13_finish_the_eight_append_profile() {
    let prefix = accepted_prefix();
    let attempt = prefix.fixture.attempt.attempt_id;
    let storage = StorageNativeSettlementAssertionV1 {
        disposition: NativeHeldDispositionV1::Accepted,
        scope: prefix.r.scope,
        root_disposition: prefix.r.digest().unwrap(),
        acceptance: prefix.capture.acceptance.clone(),
    };
    let provider = ProviderNativeSettlementAssertionV1 {
        disposition: NativeHeldDispositionV1::Accepted,
        scope: prefix.r.scope,
        root_disposition: storage.root_disposition,
        storage_settlement: storage.digest().unwrap(),
        source_artifact: prefix.r.source_artifact,
    };
    let s = NativeHeldSettlementV1 {
        disposition: NativeHeldDispositionV1::Accepted,
        root_disposition: storage.root_disposition,
        storage_settlement: storage.digest().unwrap(),
        provider_settlement: provider.digest().unwrap(),
    };
    let two = SignedNativeHeldControlV1::from_canonical_bytes(
        prefix.three.section(Tag::StorageHeld).unwrap(),
    )
    .unwrap();
    let four = sign(prefix.four.clone());
    let five = sign_source(
        PreparedNativeHeldControlV1::new(
            Kind::ProviderRelay,
            prefix.r.scope,
            four.digest(),
            vec![
                provider_w(&prefix.fixture),
                NativeHeldSectionV1::new(Tag::RootDispositionControl, four.to_canonical_bytes())
                    .unwrap(),
            ],
            NativeHeldSignerV1::SourceProvider(prefix.capture.request.signer().clone()),
        )
        .unwrap(),
    );
    let six = PreparedNativeHeldControlV1::new(
        Kind::StorageSettled,
        prefix.r.scope,
        five.digest(),
        vec![
            NativeHeldSectionV1::new(Tag::Witness, two.section(Tag::Witness).unwrap().to_vec())
                .unwrap(),
            NativeHeldSectionV1::new(
                Tag::Settlement,
                NativeHeldSettlementV1 {
                    provider_settlement: digest(0),
                    ..s
                }
                .to_canonical_bytes()
                .unwrap()
                .to_vec(),
            )
            .unwrap(),
        ],
        NativeHeldSignerV1::Storage(prefix.capture.reply.acceptance().signer()),
    )
    .unwrap();
    let signature = SigningKey::from_bytes(&[77; 32])
        .sign(&six.signature_message())
        .to_bytes();
    let six = six.with_signature(signature);
    let seven = sign_source(
        PreparedNativeHeldControlV1::new(
            Kind::ProviderSettled,
            prefix.r.scope,
            six.digest(),
            vec![
                provider_w(&prefix.fixture),
                NativeHeldSectionV1::new(Tag::Settlement, s.to_canonical_bytes().unwrap().to_vec())
                    .unwrap(),
            ],
            NativeHeldSignerV1::SourceProvider(prefix.capture.request.signer().clone()),
        )
        .unwrap(),
    );
    let thirteen = PreparedNativeHeldControlV1::new(
        Kind::RootTerminalRecorded,
        prefix.r.scope,
        seven.digest(),
        vec![
            root_w(&prefix.fixture, prefix.r.records.clone()),
            NativeHeldSectionV1::new(Tag::Settlement, s.to_canonical_bytes().unwrap().to_vec())
                .unwrap(),
        ],
        prefix.one.prepared().signer().clone(),
    )
    .unwrap();
    let make = |phase, prepared, controls, settlement| {
        RootNativeHeldSidecarV1::new(
            prefix.fixture.scope,
            prefix.cas_id,
            Some(prefix.r.clone()),
            settlement,
            None,
            NativeHeldCompletionSuffixV1::new(
                Owner::Root,
                phase,
                prefix.fixture.scope.flight,
                prepared,
                controls,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let stored = make(
        5,
        None,
        vec![prefix.one.clone(), prefix.three.clone(), four.clone()],
        None,
    );
    let recorded = make(
        6,
        Some(thirteen.clone()),
        vec![
            prefix.one.clone(),
            prefix.three.clone(),
            four.clone(),
            seven.clone(),
        ],
        Some(s),
    );
    let ack = make(
        7,
        None,
        vec![
            prefix.one.clone(),
            prefix.three.clone(),
            four,
            seven,
            sign(thirteen),
        ],
        Some(s),
    );
    let graph = |sidecar: RootNativeHeldSidecarV1| {
        let mut rows = prefix.accepted.canonical_records().clone();
        rows.insert(
            native_root_sidecar_key_v1(attempt).unwrap(),
            sidecar.to_canonical_bytes().unwrap(),
        );
        checked(&rows).unwrap()
    };
    let before = graph(stored);
    let after = graph(recorded);
    let last = graph(ack);
    let terminal = validate_native_root_transition_v1(&before, &after, attempt, [124; 16]).unwrap();
    assert_eq!(terminal.kind, RootNativeTransitionKindV1::TerminalRecorded);
    assert_eq!(terminal.maximum_remaining_transactions, 1);
    let ack = validate_native_root_transition_v1(&after, &last, attempt, [125; 16]).unwrap();
    assert_eq!(ack.kind, RootNativeTransitionKindV1::TerminalAckStored);
    assert_eq!(ack.maximum_remaining_transactions, 0);
    assert!(validate_native_root_cold_transition_v1(&after, &last, attempt, [125; 16]).is_err());
    assert!(
        last.legacy().acquisitions[&prefix.fixture.attempt.owner.owner_id()]
            .manager_custody
            .is_none()
    );
}
