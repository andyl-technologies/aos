//! Exercises the exact finite Stop framing without adopting native authority.

use super::*;
use crate::domain_ledger::provisioning_root::execution_no_apply::acquisition::encode_acquisition_raw_pair_data_v2;
use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};

fn sample(boottime: u64) -> RawPairedClockSample {
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted([1; 16]).unwrap(),
        [2; 16],
        100,
        boottime,
    )
    .unwrap()
}

fn encode<const N: usize>(magic: &[u8; 8], fields: [&[u8]; N]) -> Vec<u8> {
    let mut bytes = vec![0; framing::fields_bytes(fields).unwrap()];
    framing::encode_fields(magic, fields, &mut bytes).unwrap();
    bytes
}

#[test]
fn exact_opening_and_subject_join_fresh_pair_without_renewing_recover() {
    let key = CreateFinalityObservationAdmissionDataV1::key_from_original_v1([3; 16], [4; 32]);
    let recover = encode_acquisition_raw_pair_data_v2(sample(10));
    let first = encode_acquisition_raw_pair_data_v2(sample(20));
    let recover_cutoff = 80_u64.to_be_bytes();
    let cutoff = 70_u64.to_be_bytes();
    let expiry = 200_i64.to_be_bytes();
    let value = StopCleanupSubjectDataV1 {
        admission_key: &key,
        admission: &[4; 32],
        recover_original: &recover,
        recover_cutoff: &recover_cutoff,
        recover_wall_expiry: &expiry,
        cleanup: &[5; 16],
        controller_first: &first,
        cleanup_cutoff: &cutoff,
        source_parent: &[6; 32],
        host_query: &[7; 16],
        host_session: &[8; 32],
        host_request: &[9; 32],
        host_outcome: &[10; 32],
        host_body: &[11; 32],
    };
    let query = StopCleanupQueryDataV1 {
        controller_nonce: [5; 16],
        original_boot: [2; 16],
        original_boottime_ns: 20,
        original_cutoff_ns: 70,
        subject_bytes: SUBJECT_BYTES_V1 as u64,
        subject_digest: value.digest_v1().unwrap(),
    };
    let mut bytes = vec![0; value.encoded_bytes_v1().unwrap()];
    value.encode_range_v1(0, &mut bytes).unwrap();
    assert_eq!(bytes.len(), SUBJECT_BYTES_V1);
    assert_eq!(query.encode_v1().unwrap().len(), 96);
    assert_eq!(
        StopCleanupQueryDataV1::decode_v1(&query.encode_v1().unwrap()).unwrap(),
        query
    );
    StopCleanupSubjectDataV1::decode_v1(&bytes)
        .unwrap()
        .require_query_v1(query)
        .unwrap();

    for changed in [
        StopCleanupQueryDataV1 {
            controller_nonce: [12; 16],
            ..query
        },
        StopCleanupQueryDataV1 {
            original_boottime_ns: 21,
            ..query
        },
        StopCleanupQueryDataV1 {
            original_cutoff_ns: 71,
            ..query
        },
        StopCleanupQueryDataV1 {
            subject_digest: [12; 32],
            ..query
        },
    ] {
        assert!(value.require_query_v1(changed).is_err());
    }
    let renewed = 81_u64.to_be_bytes();
    assert!(
        StopCleanupSubjectDataV1 {
            cleanup_cutoff: &renewed,
            ..value
        }
        .encoded_bytes_v1()
        .is_err()
    );
    bytes.push(0);
    assert!(StopCleanupSubjectDataV1::decode_v1(&bytes).is_err());
}

#[test]
fn signature_and_observation_acknowledgement_have_disjoint_purposes() {
    let signature = StopCleanupSignatureDataV1 {
        query_digest: &[1; 32],
        decision_digest: &[2; 32],
        canonical_signature: &[3; 19],
    };
    let mut bytes = vec![0; signature.encoded_bytes_v1().unwrap()];
    signature.encode_range_v1(0, &mut bytes).unwrap();
    assert!(StopCleanupSignatureDataV1::decode_v1(&bytes).is_ok());
    assert!(StopCleanupObservedDecisionDataV1::decode_v1(&bytes).is_err());
    let observed = encode(b"AOSHSD02", [&[1; 32][..], &[2; 32]]);
    assert!(StopCleanupObservedDecisionDataV1::decode_v1(&observed).is_ok());
    assert!(StopCleanupSignatureDataV1::decode_v1(&observed).is_err());

    for split in 0..=bytes.len() {
        let mut segmented = vec![0; bytes.len()];
        signature
            .encode_range_v1(0, &mut segmented[..split])
            .unwrap();
        signature
            .encode_range_v1(split, &mut segmented[split..])
            .unwrap();
        assert_eq!(segmented, bytes);
    }
}

#[test]
fn receipt_and_final_request_preserve_all_distinct_packet_commitments() {
    let final_data = StopCleanupFinalDataV1 {
        query_digest: &[1; 32],
        host_query: &[2; 16],
        host_session: &[3; 32],
        host_request: &[4; 32],
        host_outcome: &[5; 32],
        host_body: &[6; 32],
    };
    let mut bytes = vec![0; final_data.encoded_bytes_v1().unwrap()];
    final_data.encode_range_v1(0, &mut bytes).unwrap();
    let decoded = StopCleanupFinalDataV1::decode_v1(&bytes).unwrap();
    assert_eq!(decoded.host_request, &[4; 32]);
    assert_eq!(decoded.host_outcome, &[5; 32]);
    assert_eq!(decoded.host_body, &[6; 32]);
    bytes.push(0);
    assert!(StopCleanupFinalDataV1::decode_v1(&bytes).is_err());

    let cutoff = 80_u64.to_be_bytes();
    let receipt = StopCleanupReceiptDataV1 {
        query_digest: &[1; 32],
        decision_digest: &[7; 32],
        terminal_host_outcome: &[5; 32],
        cutoff: &cutoff,
    };
    let mut bytes = vec![0; receipt.encoded_bytes_v1().unwrap()];
    receipt.encode_range_v1(0, &mut bytes).unwrap();
    assert_eq!(bytes.len(), RECEIPT_BYTES_V1);
    assert_eq!(
        StopCleanupReceiptDataV1::declared_bytes_v1(&bytes[..RECEIPT_HEADER_BYTES_V1]).unwrap(),
        bytes.len()
    );
    assert!(StopCleanupReplyDataV1::decode_v1(&bytes).is_err());
}

#[test]
fn observed_union_rejects_pending_history_wrong_tags_and_changed_outer_query() {
    use crate::host_recovered_namespace::{
        HostRecoveredNamespaceDataV7, HostRecoveryStopPhaseDataV7,
    };
    let old = crate::host_stopped_namespace::HostStoppedNamespaceDataV4::from_data_v4(
        [6; 16],
        crate::ValidatedAssignmentFence {
            sandbox_id: [1; 16],
            incarnation_id: [2; 16],
            assignment_epoch: 3,
            desired_generation: 4,
            assignment_digest: [5; 32],
        },
        [7; 32],
        ([8; 16], [9; 32], [10; 32]),
        ([11; 16], [12; 32], [13; 32]),
    )
    .unwrap();
    let absence = crate::host_inventory_absence::HostInventoryAbsenceDataV5::from_data_v5(
        [14; 16], [2; 16], [16; 16], 17, 18,
    )
    .unwrap();
    let root = encode_acquisition_raw_pair_data_v2(sample(20));
    let expiry = 200_i64.to_be_bytes();
    let cutoff = 80_u64.to_be_bytes();

    for phase in [
        HostRecoveryStopPhaseDataV7::Complete,
        HostRecoveryStopPhaseDataV7::AuthorizedAbsent,
        HostRecoveryStopPhaseDataV7::PayloadPending,
    ] {
        let row = HostRecoveredNamespaceDataV7::from_data_v7(old, absence, phase).encode_v7();
        let fields = [&[1; 32][..], &[1], &row, &root, &expiry, &cutoff];
        let bytes = encode(b"AOSHSO02", fields);
        let result = StopCleanupObservedDataV1::decode_v1(&bytes);
        assert_eq!(
            result.is_ok(),
            phase == HostRecoveryStopPhaseDataV7::Complete
        );
        if result.is_err() {
            continue;
        }

        let outer = encode(b"AOSHSP02", [&[1; 32][..], &bytes]);
        assert!(matches!(
            StopCleanupReplyDataV1::decode_v1(&outer)
                .unwrap()
                .decision_v1()
                .unwrap(),
            StopCleanupDecisionDataV1::Observed(_)
        ));
        assert_eq!(
            StopCleanupReplyDataV1::declared_bytes_v1(&outer[..REPLY_HEADER_BYTES_V1]).unwrap(),
            outer.len()
        );
        let changed = encode(b"AOSHSP02", [&[2; 32][..], &bytes]);
        assert!(StopCleanupReplyDataV1::decode_v1(&changed).is_err());
        let wrong_kind = encode(
            b"AOSHSO02",
            [&[1; 32][..], &[2], &row, &root, &expiry, &cutoff],
        );
        assert!(StopCleanupObservedDataV1::decode_v1(&wrong_kind).is_err());
        let unknown_kind = encode(
            b"AOSHSO02",
            [&[1; 32][..], &[3], &row, &root, &expiry, &cutoff],
        );
        assert!(StopCleanupObservedDataV1::decode_v1(&unknown_kind).is_err());
    }
}
