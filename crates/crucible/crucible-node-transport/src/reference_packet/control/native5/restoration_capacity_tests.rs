//! Checks retained native partials from finite models, never a native adopter.
//!
//! No Source, Boot, Window, private child or restoration capability is issued.
//! The actual public DTO/model owners establish only independently retained DATA.

use super::*;
use crate::reference_packet::service::complete_restore::{
    PacketNativeRestoredRecord,
    activation::{
        observe_restoration_native_capacity_data,
        restoration_activation_retained_native_evidence_data,
    },
};
use crate::retained_metadata::{
    MetadataObserver, RetainedCaptureProtocolData,
    records::{MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind},
};
use std::mem::size_of;

fn originals(reactive: bool) -> (PacketNativeRestoredRecord, PacketNative5UnderlyingRecord) {
    let mut control = current_control17_fixture_data(reactive).unwrap();
    tests::bind_storage(&mut control);
    let original = crate::envelope::tests::request();
    let model = match &control.program {
        NativeProgram::OutputOnly(program) => {
            PacketNative5UnderlyingRecord::Producer(Box::new(PacketNativeRecord {
                schema: "source-owned.packet-native/2".into(),
                native_pid: U64::new(1),
                original: original.clone(),
                inventory: program.inventory(),
                grant: None,
            }))
        }
        NativeProgram::Connected(program) => {
            PacketNative5UnderlyingRecord::Reactive(Box::new(PacketConnectedNativeRecord {
                schema: "source-owned.packet-native/4".into(),
                native_pid: U64::new(1),
                original: original.clone(),
                inventory: program.inventory().unwrap(),
                grant: None,
            }))
        }
        NativeProgram::RestorationInProgress => panic!("finite fixture unexpectedly restores"),
    };
    let value = match &model {
        PacketNative5UnderlyingRecord::Producer(model) => {
            serde_json::to_value(model.as_ref()).unwrap()
        }
        PacketNative5UnderlyingRecord::Reactive(model) => {
            serde_json::to_value(model.as_ref()).unwrap()
        }
    };
    let encoded = canonical::canonical_json(&value).unwrap();
    let reference = canonical::content_ref(&encoded, "application/json").unwrap();
    let receipt = control
        .original_complete_receipt_data(&original, reference.clone())
        .unwrap();
    let mut schema = String::with_capacity(181);
    schema.push_str("incomplete failed restored record");
    let mut digest = Vec::with_capacity(179);
    digest.push(7);
    let record = PacketNativeRestoredRecord {
        schema,
        native_receipt: receipt,
        captured_owner_state: reference.clone(),
        captured_journal: reference.clone(),
        mapping: reference.clone(),
        restore_commit: reference.clone(),
        restore_response: reference,
        context_digest: crucible_node_format::Bytes::new(digest),
        physical_gate_held: false,
    };
    (record, model)
}

#[test]
fn restoration_native_capacity_keeps_both_box_families_and_independent_missing_receipts() {
    for reactive in [false, true] {
        let (record, model) = originals(reactive);
        let expected =
            restoration_activation_retained_native_evidence_data(&record, Some(&model)).unwrap();

        let complete =
            RetainedCaptureProtocolData::RestorationNativeEvidence(Some(&record), Some(&model))
                .observe_retained_metadata()
                .unwrap();
        let partial = RetainedCaptureProtocolData::RestorationNativeEvidence(None, Some(&model))
            .observe_retained_metadata()
            .unwrap();

        assert_eq!(complete, expected);
        assert_eq!(
            partial.boxed_value_bytes,
            if reactive {
                size_of::<PacketConnectedNativeRecord>()
            } else {
                size_of::<PacketNativeRecord>()
            }
        );
        assert!(partial.capacity_records > 1);
        assert!(complete.capacity_records > partial.capacity_records);
        assert!(record.validate_data().is_err());
        assert!(!record.physical_gate_held);
    }
}

#[test]
fn restoration_native_capacity_appends_exact_and_short_physical_prefixes_without_alias_discount() {
    for reactive in [false, true] {
        let (record, model) = originals(reactive);
        let expected =
            restoration_activation_retained_native_evidence_data(&record, Some(&model)).unwrap();
        let prefix = MetadataCapacityRecord {
            kind: MetadataRecordKind::Vector,
            extent: 173,
            element_bytes: 1,
            alignment: 1,
        };
        let mut bank = MetadataRecordBank::reserve(1 + 2 * expected.capacity_records).unwrap();
        bank.append(prefix).unwrap();
        let backing = bank.allocated_bytes();
        for _ in 0..2 {
            let mut observer = MetadataObserver::appending(&mut bank);
            observe_restoration_native_capacity_data(Some(&record), Some(&model), &mut observer)
                .unwrap();
            assert_eq!(observer.finish(), expected);
        }
        assert_eq!(bank.rows()[0], prefix);
        assert_eq!(
            &bank.rows()[1..1 + expected.capacity_records],
            &bank.rows()[1 + expected.capacity_records..]
        );
        assert_eq!(bank.allocated_bytes(), backing);

        let mut short = MetadataRecordBank::reserve(2).unwrap();
        short.append(prefix).unwrap();
        let mut observer = MetadataObserver::appending(&mut short);
        assert!(
            observe_restoration_native_capacity_data(Some(&record), Some(&model), &mut observer)
                .is_err()
        );
        let _partial = observer.finish();
        assert_eq!(short.rows()[0], prefix);
        assert_eq!(short.rows()[1].kind, MetadataRecordKind::String);
        assert_eq!(short.rows()[1].extent, record.schema.capacity());
        assert!(!record.physical_gate_held);
    }
}
