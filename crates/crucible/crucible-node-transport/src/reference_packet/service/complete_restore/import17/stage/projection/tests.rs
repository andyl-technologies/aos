//! Compares defining crypto projections with actual constructors and serializers.

use super::*;
use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use crucible_node_format::Bytes;
use serde::Serialize;

fn context(phase: PacketNativeImport17Stage) -> PacketNativeImport17StageContext {
    PacketNativeImport17StageContext {
        schema: "source-owned.packet-native-import-stage-context/17".into(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
        phase,
        birth_context_digest: Bytes::new(vec![1; 32]),
        stage_binding_digest: Bytes::new(vec![2; 32]),
        assigned_original_digest: Bytes::new(vec![3; 32]),
    }
}

fn actual_shape<T: Serialize + crate::retained_metadata::ObserveMetadata>(value: &T) -> Shape {
    let mut observer = MetadataObserver::new();
    observer.observe(value).unwrap();
    actual_serialization_storage_data(value, observer.finish(), usize::MAX).unwrap()
}

#[test]
fn all_defining_shapes_match_actual_serializers_for_each_stage() {
    for phase in [
        PacketNativeImport17Stage::Arm,
        PacketNativeImport17Stage::World,
        PacketNativeImport17Stage::FirstObserve,
    ] {
        let context = context(phase);
        let proof = native_import17_stage_proof_data(&[4; 32], &context).unwrap();
        let receipt = native_import17_stage_receipt_data(&[4; 32], &context, &[5; 32]).unwrap();
        let projected = native_import17_stage_crypto_projection_data(phase, usize::MAX).unwrap();
        let mut unsigned = serde_json::to_value(&receipt).unwrap();
        unsigned.as_object_mut().unwrap().remove("mac");
        let unsigned_bytes = canonical::canonical_json(&unsigned).unwrap();
        let derived = blake3::derive_key(phase.receipt_domain(), &[4; 32]);
        assert_eq!(
            blake3::keyed_hash(&derived, &unsigned_bytes).as_bytes(),
            receipt.mac.as_slice(),
            "every complete wire field except mac belongs to the receipt MAC"
        );

        for (projected, actual) in projected.shapes.iter().zip([
            actual_shape(&context),
            actual_shape(&proof),
            actual_shape(&receipt),
            actual_shape(&unsigned),
        ]) {
            assert_eq!(
                projected.maximum_encoded_bytes,
                actual.maximum_encoded_bytes
            );
            assert_eq!(
                projected.serialized_value_nodes,
                actual.serialized_value_nodes
            );
            assert_eq!(
                projected.serialized_capacity_records,
                actual.serialized_capacity_records
            );
            assert_eq!(
                projected.retained_value_backing_bytes,
                actual.retained_value_backing_bytes
            );
            assert_eq!(
                projected.projected_parser_requested_bytes,
                actual.projected_parser_requested_bytes
            );
            assert_eq!(
                projected.canonical_output_requested_bytes,
                actual.canonical_output_requested_bytes
            );
        }
        let encoded = projected.maximum_encoded_bytes_data();
        assert!(encoded[0] <= MAXIMUM_NATIVE_IMPORT17_STAGE_CONTEXT_BYTES);
        assert!(encoded[1] <= MAXIMUM_NATIVE_IMPORT17_STAGE_PROOF_BYTES);
        assert!(encoded[2] <= MAXIMUM_NATIVE_IMPORT17_STAGE_RECEIPT_BYTES);
        assert!(encoded[3] < encoded[2]);
    }
}

#[test]
fn crypto_row_covers_actual_backing_and_overlapping_canonical_work_without_ceiling_credit() {
    for phase in [
        PacketNativeImport17Stage::Arm,
        PacketNativeImport17Stage::World,
        PacketNativeImport17Stage::FirstObserve,
    ] {
        let context = context(phase);
        let proof = native_import17_stage_proof_data(&[4; 32], &context).unwrap();
        let receipt = native_import17_stage_receipt_data(&[4; 32], &context, &[5; 32]).unwrap();
        let mut observer = MetadataObserver::new();
        observer.observe(&context).unwrap();
        observer.observe(&proof).unwrap();
        observer.observe(&receipt).unwrap();
        let backing = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
        let row = native_import17_stage_crypto_construction_data(phase, usize::MAX).unwrap();
        assert_eq!(row[0], backing);
        let projected = native_import17_stage_crypto_projection_data(phase, usize::MAX).unwrap();
        let overlap = projected.shapes[0].canonical_output_requested_bytes
            + canonical_work(&projected.shapes[3]).unwrap();
        assert!(row[1] >= overlap + 43 + constructor_headers());
        assert_eq!(row[2], native_import17_stage_crypto_counter_scratch_data());
        let peak = row
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .unwrap();
        assert_eq!(
            native_import17_stage_crypto_construction_data(phase, peak).unwrap(),
            row
        );
        assert!(native_import17_stage_crypto_construction_data(phase, peak - 1).is_err());
        assert_eq!(
            native_import17_stage_crypto_construction_data(phase, peak + 4096).unwrap(),
            row
        );
    }
}
