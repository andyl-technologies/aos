//! UNRUN Source5 DATA vectors with independent byte orders and literal domains.
//!
//! Synthetic signatures and witness claims are format fixtures only. No test
//! creates a protected admission, authenticated clock, Source writer, or route.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, RawClockProvenance, RawPairedClockSample};
use aos_sandbox_source_provider_ledger::ledger::native_completion::OriginalSourceProvenanceClaimsV5;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1, NativeHeldScopeV1, NativeHeldSectionTagV1,
    frame::{NativeHeldSectionV1, NativeHeldSignerV1, PreparedNativeHeldControlV1},
    native_held_flight_digest_v1,
    witness::{
        NativeHeldByteWitnessV1, NativeHeldGenerationClaimV1, NativeHeldOwnerWitnessV1,
        NativeHeldRecordFamilyV1, RootNativeHeldWitnessV1,
    },
};
use aos_sandbox_source_provider_protocol::{
    ProviderHeldSnapshotCatalogV1, ProviderHeldSnapshotRowV1, SourceProviderKeyUsageV1,
    SourceProviderSigningKeyV1, StorageZfsHoldTransportRequestV1, ZfsHeldSnapshotProofV1,
};

use super::*;
use crate::journal::capacity_reservation::family::{
    CanonicalCapacityFamily, canonical_reservations, require_legacy_owner,
    require_legacy_reservations,
};
use crate::journal::capacity_reservation::native_held::{
    NativeHeldCapacityRecordV3, OriginalRootCapacityRecordV5,
};

fn digest(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn witness(
    family: NativeHeldRecordFamilyV1,
    prefix: &[u8],
    subject: &[u8],
) -> NativeHeldByteWitnessV1 {
    let mut key = prefix.to_vec();
    key.extend_from_slice(subject);
    NativeHeldByteWitnessV1::new(family, key, digest(50)).unwrap()
}

fn fixture_claims() -> OriginalSourceProvenanceClaimsV5 {
    let signer = SourceProviderSigningKeyV1::new(
        [2; 16],
        1,
        digest(3),
        [4; 16],
        1,
        digest(5),
        SourceProviderKeyUsageV1::RootMountRecord,
    )
    .unwrap();
    let scope = NativeHeldScopeV1 {
        flight: native_held_flight_digest_v1(digest(6), digest(7), digest(8)),
        original_source_session: digest(8),
        mount_attempt: digest(7),
        provider_attempt: digest(0),
        provider_acquisition: digest(9),
        original_root_request: digest(6),
        original_native_request: digest(0),
    };
    let generation = NativeHeldGenerationClaimV1 {
        generation: 1,
        digest: digest(10),
    };
    let root_witness = RootNativeHeldWitnessV1 {
        local_socket_cookie: 1,
        journal_sequence: 1,
        planning_sequence: 1,
        trust: generation,
        revocation: generation,
        provider_head: generation,
        provider_floor: generation,
        publication: digest(11),
        records: [
            witness(
                NativeHeldRecordFamilyV1::RootSession,
                b"aos.mount.source-provider-session.v2\0",
                &[8; 32],
            ),
            witness(
                NativeHeldRecordFamilyV1::RootAttempt,
                b"aos.mount.source-provider-query-attempt.v2\0",
                &[7; 32],
            ),
            witness(
                NativeHeldRecordFamilyV1::RootAcquisition,
                b"aos.mount.source-acquisition.v2\0",
                &[9; 32],
            ),
            witness(
                NativeHeldRecordFamilyV1::RootHead,
                b"aos.mount.source-provider-head.v2\0",
                &[1; 32],
            ),
        ],
    };
    let root_prepared = PreparedNativeHeldControlV1::new(
        NativeHeldControlKindV1::RootPrepared,
        scope,
        digest(0),
        vec![NativeHeldSectionV1::new(
            NativeHeldSectionTagV1::Witness,
            NativeHeldOwnerWitnessV1::Root(root_witness)
                .to_canonical_bytes()
                .unwrap(),
        )
        .unwrap()],
        NativeHeldSignerV1::SourceProvider(signer),
    )
    .unwrap()
    .with_signature([0xa1; 64]);
    let snapshot = ZfsHeldSnapshotProofV1::new(
        [12; 32],
        1,
        1,
        2,
        3,
        [13; 16],
        1,
        digest(14),
        digest(15),
        digest(16),
    )
    .unwrap();
    let row = ProviderHeldSnapshotRowV1::new(
        digest(17),
        [18; 32],
        1,
        digest(19),
        1,
        digest(20),
        snapshot,
    )
    .unwrap();
    let catalog = ProviderHeldSnapshotCatalogV1::new(1, digest(21), vec![row]).unwrap();
    let claims = StorageZfsHoldTransportRequestV1::new(
        1,
        [22; 32],
        digest(23),
        [1; 16],
        [2; 16],
        digest(8),
        digest(9),
        digest(17),
        digest(24),
        100,
        130,
        catalog,
    )
    .unwrap();
    let mut attempt_subject = [0; 65];
    attempt_subject[..16].fill(1);
    attempt_subject[16..32].fill(2);
    attempt_subject[32..48].fill(4);
    attempt_subject[48] = 2;
    attempt_subject[49..].fill(25);
    let mut acquisition_subject = [0; 64];
    acquisition_subject[..16].fill(1);
    acquisition_subject[16..32].fill(2);
    acquisition_subject[32..].fill(9);
    let mut history_subject = acquisition_subject;
    history_subject[32..].fill(8);
    let mut holder_subject = [0; 32];
    holder_subject[..16].fill(1);
    holder_subject[16..].fill(2);

    OriginalSourceProvenanceClaimsV5 {
        root_prepared,
        claims,
        initial: RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [26; 16],
            100,
            1_000_000_000,
        )
        .unwrap(),
        original_deadline: 40_000_000_000,
        narrowed_deadline: 30_000_000_000,
        journal_sequence: 1,
        configuration: digest(27),
        records: [
            witness(
                NativeHeldRecordFamilyV1::ProviderAttempt,
                b"aos.source-provider.attempt.v1\0",
                &attempt_subject,
            ),
            witness(
                NativeHeldRecordFamilyV1::ProviderAcquisition,
                b"aos.source-provider.acquisition.v1\0",
                &acquisition_subject,
            ),
            witness(
                NativeHeldRecordFamilyV1::ProviderHolder,
                b"aos.source-provider.session.v1\0",
                &holder_subject,
            ),
            witness(
                NativeHeldRecordFamilyV1::ProviderHistory,
                b"aos.source-provider.session-history.v1\0",
                &history_subject,
            ),
        ],
    }
}

fn fixture() -> OriginalSourceCapacityRecordV5 {
    let provenance = OriginalSourceProvenanceV5::new_untrusted(fixture_claims()).unwrap();
    let owner = Sha256::new()
        .chain_update(b"aos.sandbox.source-provider.native-dispatch-capacity-owner.v2\0")
        .chain_update([1; 16])
        .chain_update([2; 16])
        .chain_update([9; 32])
        .finalize()
        .into();
    let request = NativeHeldCapacityRequestV3 {
        purpose: NativeHeldCapacityPurposeV3::Provider,
        owner_id: owner,
        owner_digest: [28; 32],
        operation_id: [29; 16],
        artifact_digest: [23; 32],
        checkpoint_digest: [6; 32],
        chain_head_digest: [8; 32],
        future_transactions: 20,
        terminal_records: 100,
        terminal_bytes: 10_000,
        poison_records: 110,
        poison_bytes: 11_000,
    };
    let origin = OriginalSourceCapacityBudgetsV5 {
        terminal_records: 100,
        terminal_bytes: 10_000,
        poison_records: 110,
        poison_bytes: 11_000,
    };
    OriginalSourceCapacityRecordV5::new(request, [30; 16], origin, provenance).unwrap()
}

// This preimage intentionally does not call either production tail/scalar encoder.
fn independent_payload(record: &OriginalSourceCapacityRecordV5) -> Vec<u8> {
    let request = record.request();
    let data = record.original_provenance().claims();
    let mut bytes = b"AOSJCR01\0\x05\x29\x0b\0\0".to_vec();
    for field in [request.owner_id, request.owner_digest] {
        bytes.extend_from_slice(&field);
    }
    bytes.extend_from_slice(&request.operation_id);
    for field in [
        request.artifact_digest,
        request.checkpoint_digest,
        request.chain_head_digest,
    ] {
        bytes.extend_from_slice(&field);
    }
    bytes.extend_from_slice(&request.terminal_records.to_be_bytes());
    bytes.extend_from_slice(&request.terminal_bytes.to_be_bytes());
    bytes.extend_from_slice(&request.poison_records.to_be_bytes());
    bytes.extend_from_slice(&request.poison_bytes.to_be_bytes());
    bytes.extend_from_slice(&request.future_transactions.to_be_bytes());
    bytes.extend_from_slice(&[30; 16]);
    bytes.extend_from_slice(&100_u32.to_be_bytes());
    bytes.extend_from_slice(&10_000_u64.to_be_bytes());
    bytes.extend_from_slice(&110_u32.to_be_bytes());
    bytes.extend_from_slice(&11_000_u64.to_be_bytes());
    let root = data.root_prepared.to_canonical_bytes();
    bytes.extend_from_slice(&(root.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&root);
    let claims = data.claims.to_canonical_bytes();
    bytes.extend_from_slice(&(claims.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&claims);
    bytes.extend_from_slice(b"aos-kernel-clock");
    bytes.extend_from_slice(&[26; 16]);
    bytes.extend_from_slice(&100_i64.to_be_bytes());
    bytes.extend_from_slice(&1_000_000_000_u64.to_be_bytes());
    bytes.extend_from_slice(&40_000_000_000_u64.to_be_bytes());
    bytes.extend_from_slice(&30_000_000_000_u64.to_be_bytes());
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&[27; 32]);
    for (witness, width) in data.records.iter().zip([96_u16, 99, 63, 103]) {
        bytes.extend_from_slice(&41_u16.to_be_bytes());
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&[50; 32]);
        bytes.extend_from_slice(witness.key());
    }
    bytes
}

#[test]
fn independent_source5_preimage_identity_key_and_offsets_are_exact() {
    let record = fixture();
    let payload = independent_payload(&record);
    let identity: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.journal.source-original-native-capacity.v5\0")
        .chain_update((payload.len() as u32).to_be_bytes())
        .chain_update(&payload)
        .finalize()
        .into();
    let mut expected = payload.clone();
    expected.extend_from_slice(&identity);
    let mut key = b"aos.journal.global-capacity-reservation.v1\0".to_vec();
    key.extend_from_slice(&identity);
    let encoded = record.to_journal_record().unwrap();

    assert_eq!(ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5, 30_413);
    assert_eq!(encoded.key(), key);
    assert_eq!(key.len(), 75);
    assert_eq!(encoded.value(), Some(expected.as_slice()));
    assert_eq!(&expected[8..14], &[0, 5, 41, 11, 0, 0]);
    assert_eq!(&expected[214..218], &20_u32.to_be_bytes());
    assert_eq!(&expected[218..234], &[30; 16]);
    assert_eq!(&expected[234..238], &100_u32.to_be_bytes());
    assert_eq!(
        OriginalSourceCapacityRecordV5::from_journal_record(&encoded).unwrap(),
        record,
    );
    assert_eq!(record.origin_reservation_id().unwrap(), identity);
}

#[test]
fn successor_retains_origin_without_widening_general_v3() {
    let initial = fixture();
    assert!(NativeHeldCapacityRecordV3::new(initial.request(), [30; 16]).is_err());
    let mut request = initial.request();
    request.future_transactions = 19;
    request.terminal_records -= 1;
    request.terminal_bytes -= 100;
    let successor = OriginalSourceCapacityRecordV5::new(
        request,
        initial.admission_transaction_id(),
        initial.origin_budgets(),
        initial.original_provenance().clone(),
    )
    .unwrap();

    assert_ne!(successor.reservation_id(), initial.reservation_id());
    assert_eq!(
        successor.origin_reservation_id().unwrap(),
        initial.reservation_id(),
    );
    assert_eq!(
        NativeHeldCapacityPurposeV3::Provider.maximum_future_transactions(),
        19,
    );
    assert_eq!(NativeHeldCapacityPurposeV3::Root.maximum_future_transactions(), 7);
    for count in [0, 21] {
        request.future_transactions = count;
        assert!(
            OriginalSourceCapacityRecordV5::new(
                request,
                [30; 16],
                initial.origin_budgets(),
                initial.original_provenance().clone(),
            )
            .is_err()
        );
    }
    request.future_transactions = 19;
    request.poison_bytes += 1;
    assert!(
        OriginalSourceCapacityRecordV5::new(
            request,
            [30; 16],
            initial.origin_budgets(),
            initial.original_provenance().clone(),
        )
        .is_err()
    );
}

#[test]
fn source5_tuple_substitution_and_all_row_legacy_gates_fail_closed() {
    let encoded = fixture().to_journal_record().unwrap();
    assert!(OriginalRootCapacityRecordV5::from_journal_record(&encoded).is_err());
    let family = CanonicalCapacityFamily::decode(encoded.key(), encoded.value().unwrap()).unwrap();
    assert_eq!(
        family.owner_namespace(),
        RecordNamespace::SourceProviderAuthority,
    );
    assert!(matches!(
        family.require_legacy(),
        Err(JournalError::ProtectedBoundary),
    ));
    assert_eq!(family.accounting().unwrap().maximum_transactions, 20);
    let mut state = BTreeMap::from([(
        (encoded.namespace(), encoded.key().to_vec()),
        encoded.value().unwrap().to_vec(),
    )]);
    assert!(canonical_reservations(&state).is_ok());
    assert!(matches!(
        require_legacy_reservations(&state),
        Err(JournalError::ProtectedBoundary),
    ));
    assert!(matches!(
        require_legacy_owner(&state, RecordNamespace::SourceProviderAuthority),
        Err(JournalError::ProtectedBoundary),
    ));
    state.insert(
        (RecordNamespace::GlobalCapacityReservation, vec![0xff]),
        b"bad".to_vec(),
    );
    assert!(matches!(
        require_legacy_reservations(&state),
        Err(JournalError::MalformedRecord(_)),
    ));

    for (offset, replacement) in [(10, 40), (11, 9), (12, 1), (13, 1), (8, 1)] {
        let mut bytes = encoded.value().unwrap().to_vec();
        bytes[offset] = replacement;
        assert!(CanonicalCapacityFamily::decode(encoded.key(), &bytes).is_err());
    }
    for length in [0, 13, 257, 906, encoded.value().unwrap().len() - 1] {
        assert!(
            CanonicalCapacityFamily::decode(encoded.key(), &encoded.value().unwrap()[..length])
                .is_err()
        );
    }
    let mut substituted = encoded.key().to_vec();
    substituted[74] ^= 1;
    assert!(CanonicalCapacityFamily::decode(&substituted, encoded.value().unwrap()).is_err());
}

#[test]
fn archived_subject_and_cutoff_substitution_is_rejected_before_floor_selection() {
    let data = fixture_claims();
    let valid = OriginalSourceProvenanceV5::new_untrusted(data.clone()).unwrap();
    let bytes = valid.to_canonical_bytes();
    assert_eq!(
        OriginalSourceProvenanceV5::from_canonical_bytes(&bytes).unwrap(),
        valid,
    );
    assert_eq!(
        bytes.len(),
        617 + data.root_prepared.to_canonical_bytes().len() + data.claims.to_canonical_bytes().len(),
    );
    for index in 0..4 {
        let mut changed = data.clone();
        let witness = &changed.records[index];
        let mut key = witness.key().to_vec();
        let subject_start = [31, 35, 31, 39][index];
        key[subject_start] ^= 1;
        changed.records[index] =
            NativeHeldByteWitnessV1::new(witness.family(), key, witness.digest()).unwrap();
        assert!(OriginalSourceProvenanceV5::new_untrusted(changed).is_err());
    }
    for mutate in [0, 1, 2, 3] {
        let mut changed = data.clone();
        match mutate {
            0 => changed.narrowed_deadline += 1,
            1 => changed.original_deadline += 1,
            2 => changed.original_deadline = 20_000_000_000,
            _ => changed.configuration = digest(0),
        }
        assert!(OriginalSourceProvenanceV5::new_untrusted(changed).is_err());
    }
    let mut oversized_length = bytes.clone();
    oversized_length[..4].copy_from_slice(&8_193_u32.to_be_bytes());
    assert!(OriginalSourceProvenanceV5::from_canonical_bytes(&oversized_length).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(OriginalSourceProvenanceV5::from_canonical_bytes(&trailing).is_err());
}
