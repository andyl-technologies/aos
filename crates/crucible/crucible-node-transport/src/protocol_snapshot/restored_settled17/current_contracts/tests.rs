//! Checks actual DTO serialization against the new raw-object capacity codec.

use super::*;
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 65536,
        maximum_nodes: 1024,
        maximum_depth: 32,
        maximum_owned_backing_bytes: 65536,
        maximum_tree_entries: 1024,
    }
}

fn proof() -> PacketCompleteRestoreTransferProof {
    let mut schema = String::with_capacity(137);
    schema.push_str("source-owned.packet-complete-restore-prepare-proof/12");
    let mut algorithm = String::with_capacity(83);
    algorithm.push_str("blake3-keyed-canonical/1");
    let mut digest = Vec::with_capacity(71);
    digest.extend_from_slice(&[3; 32]);
    let mut mac = Vec::with_capacity(79);
    mac.extend_from_slice(&[4; 32]);
    PacketCompleteRestoreTransferProof {
        schema,
        algorithm,
        context_digest: Bytes::new(digest),
        mac: Bytes::new(mac),
    }
}

#[test]
fn actual_raw_proof_retains_all_independent_spare_backing() {
    let actual = proof();
    let input = serde_json::to_vec(&actual).unwrap();
    let mut records = MetadataRecordBank::reserve(16).unwrap();
    let mut observer = MetadataObserver::recording(&mut records);
    actual.observe_current(&mut observer).unwrap();
    let _ = observer.finish();
    let rows = serde_json::to_vec(&records).unwrap();
    let validated = ValidatedMetadataRecords::validate(&rows, 16, 65536).unwrap();

    let mut borrowed = Ledger::new(validated.rows(), limits());
    assert!(
        borrowed
            .read::<CurrentDto17<PacketCompleteRestoreTransferProof>>(&input, false)
            .unwrap()
            .is_none()
    );
    assert!(borrowed.rows.next().is_none());
    let mut building = Ledger::new(validated.rows(), limits());
    let restored = building
        .read::<CurrentDto17<PacketCompleteRestoreTransferProof>>(&input, true)
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(restored.schema.capacity(), actual.schema.capacity());
    assert_eq!(restored.algorithm.capacity(), actual.algorithm.capacity());
    assert_eq!(
        restored.context_digest.allocation_capacity(),
        actual.context_digest.allocation_capacity()
    );
    assert_eq!(
        restored.mac.allocation_capacity(),
        actual.mac.allocation_capacity()
    );
    assert_eq!(serde_json::to_vec(&restored).unwrap(), input);
    assert!(building.rows.next().is_none());
}

#[test]
fn unknown_field_and_one_short_actual_byte_row_refuse() {
    let actual = proof();
    let input = serde_json::to_vec(&actual).unwrap();
    let mut records = MetadataRecordBank::reserve(16).unwrap();
    let mut observer = MetadataObserver::recording(&mut records);
    actual.observe_current(&mut observer).unwrap();
    let _ = observer.finish();
    let rows = serde_json::to_vec(&records).unwrap();
    let validated = ValidatedMetadataRecords::validate(&rows, 16, 65536).unwrap();
    let mut changed = input[..input.len() - 1].to_vec();
    changed.extend_from_slice(br#","unexpected":true}"#);
    let mut ledger = Ledger::new(validated.rows(), limits());
    assert!(
        ledger
            .read::<CurrentDto17<PacketCompleteRestoreTransferProof>>(&changed, false)
            .is_err()
    );

    let mut rows: Vec<(String, usize, usize, usize)> = serde_json::from_slice(&rows).unwrap();
    rows[2].1 = 31;
    let rows = serde_json::to_vec(&rows).unwrap();
    let validated = ValidatedMetadataRecords::validate(&rows, 16, 65536).unwrap();
    let mut ledger = Ledger::new(validated.rows(), limits());
    assert!(
        ledger
            .read::<CurrentDto17<PacketCompleteRestoreTransferProof>>(&input, false)
            .is_err()
    );
}

#[test]
fn defining_selection_serialization_matches_the_only_historical_grammar() {
    use crate::protocol_snapshot::owned11::typed::HistoricalType;
    use crate::reference_packet::service::{
        capture_allocation::PacketNative5CaptureAllocationSelection,
        complete_restore::{
            PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
        },
    };

    fn check<T: HistoricalType + serde::Serialize + PartialEq + std::fmt::Debug>(
        value: T,
        changed_case: &[u8],
    ) {
        let input = serde_json::to_vec(&value).unwrap();
        let rows = ValidatedMetadataRecords::validate(b"[]", 1, 65536).unwrap();
        let mut ledger = Ledger::new(rows.rows(), limits());
        assert_eq!(ledger.read::<T>(&input, true).unwrap(), Some(value));
        assert!(ledger.rows.next().is_none());

        let mut changed = Ledger::new(rows.rows(), limits());
        assert!(changed.read::<T>(changed_case, false).is_err());
    }

    check(
        PacketNative5CompleteRestoreSelection::SourceSignedOwned11,
        br#""source_signed_owned11""#,
    );
    check(
        PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
        br#""source_signed_transfer12""#,
    );
    check(
        PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12,
        br#""canonical_sdk_restore_inputs12""#,
    );
    check(
        PacketNative5CaptureAllocationSelection::OriginalObserve12,
        br#""OriginalObserve12""#,
    );
}
