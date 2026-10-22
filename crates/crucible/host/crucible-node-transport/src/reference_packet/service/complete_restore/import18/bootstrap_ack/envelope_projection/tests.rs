//! Compares prospective envelopes with independently materialized inert DATA.

use super::*;
use crate::envelope::Nullable;
use crate::retained_metadata::{
    MetadataObserver, requested_metadata_backing_storage_data,
    serialization_storage::actual_serialization_storage_data,
};
use serde_json::Value;

fn envelopes(width: usize, row: PacketNativeStartupAllocationRow) -> [Envelope; 2] {
    let request = PacketNativeImport18BootstrapRequest {
        schema: NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.into(),
        recipe_identity: Bytes::new(vec![1; 32]),
        initial_funding: row,
    };
    request.validate_data().unwrap();

    let mut original = crate::envelope::tests::request();
    original.method = Method::NativeImport18Bootstrap;
    original.sequence = U64::new(2);
    original.session_id = Nullable(Some(Id::new("s".repeat(width)).unwrap()));
    original.incarnation_id = Nullable(Some(Id::new("i".repeat(width)).unwrap()));
    original.request_id = Nullable(Some(Id::new("r".repeat(width)).unwrap()));
    original.node_id = Nullable(None);
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(None);
    original.operation_id = Nullable(None);
    original.body = serde_json::to_value(&request)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    original.extensions.clear();
    // Arbitrary fixed-width MAC bytes are structural DATA, never Source proof.
    original.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        serde_json::to_value(PacketNativeImport18BootstrapAckProof {
            schema: NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
            context_digest: Bytes::new(vec![2; 32]),
            mac: Bytes::new(vec![3; 32]),
        })
        .unwrap(),
    );

    let mut response = original.clone();
    response.message = MessageKind::Response;
    response.body = serde_json::json!({
        "status": "completed", "operation_state": "completed", "extensions": {},
        "result": {
            "schema": NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA,
            "state": "bootstrap_only", "recipe_identity": request.recipe_identity,
            "initial_funding": row,
        },
    })
    .as_object()
    .unwrap()
    .clone();
    response.extensions.clear();
    response.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(),
        serde_json::to_value(PacketNativeImport18BootstrapAckReceipt {
            schema: NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(),
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
            state: PacketNativeImport18BootstrapAckState::BootstrapOnly,
            context_digest: Bytes::new(vec![4; 32]),
            assigned_response: Bytes::new(vec![5; 32]),
            mac: Bytes::new(vec![6; 32]),
        })
        .unwrap(),
    );
    [original, response]
}

#[test]
fn closed_shapes_cover_actual_values_backing_and_canonical_output() {
    let projected = native_import18_bootstrap_envelope_projection_data(usize::MAX).unwrap();
    let rows = [
        PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(1),
            maximum_simultaneous_transient_bytes: U64::new(2),
            declared_counter_scratch_bytes: U64::new(3),
        },
        PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(u64::MAX - 2),
            maximum_simultaneous_transient_bytes: U64::new(1),
            declared_counter_scratch_bytes: U64::new(1),
        },
    ];

    for width in [1, MAX_ID_BYTES] {
        for row in rows {
            for (index, envelope) in envelopes(width, row).iter().enumerate() {
                envelope.validate().unwrap();
                let value = serde_json::to_value(envelope).unwrap();
                let mut observer = MetadataObserver::new();
                observer.observe(&value).unwrap();
                let metadata = observer.finish();
                let backing = requested_metadata_backing_storage_data(&metadata).unwrap();
                let actual =
                    actual_serialization_storage_data(&value, metadata, usize::MAX).unwrap();
                let shape = [&projected.request, &projected.response][index];

                assert_eq!(shape.serialized_value_nodes, [49, 63][index]);
                assert_eq!(shape.serialized_value_nodes, actual.serialized_value_nodes);
                assert_eq!(
                    shape.serialized_capacity_records,
                    actual.serialized_capacity_records
                );
                assert_eq!(shape.sequence_containers, 0);
                assert_eq!(shape.sequence_elements, 0);
                assert!(shape.retained_value_backing_bytes >= backing + size_of::<Value>());
                assert!(
                    shape.dom_and_canonical_scratch_bytes >= actual.dom_and_canonical_scratch_bytes
                );
                assert!(
                    shape.projected_parser_requested_bytes
                        >= actual.projected_parser_requested_bytes
                );
                let bytes = canonical::canonical_json(&value).unwrap();
                assert!(bytes.len() <= shape.maximum_encoded_bytes);
                assert!(shape.canonical_output_requested_bytes >= bytes.capacity());
                assert_eq!(canonical::parse_json(&bytes, bytes.len()).unwrap(), value);
            }
        }
    }
}

#[test]
fn restriction_checks_derived_demand_without_becoming_demand() {
    let full = native_import18_bootstrap_envelope_projection_data(usize::MAX).unwrap();
    let needed = full
        .request
        .requested_total()
        .unwrap()
        .max(full.response.requested_total().unwrap());
    let exact = native_import18_bootstrap_envelope_projection_data(needed).unwrap();

    assert_eq!(
        exact.maximum_encoded_bytes_data(),
        full.maximum_encoded_bytes_data()
    );
    assert_eq!(
        exact.serialization_requested_bytes_data(),
        full.serialization_requested_bytes_data()
    );
    assert_eq!(
        exact.retained_value_backing_bytes_data(),
        full.retained_value_backing_bytes_data()
    );
    assert!(native_import18_bootstrap_envelope_projection_data(needed - 1).is_err());
    assert!(native_import18_bootstrap_envelope_projection_data(0).is_err());
    assert!(native_import18_bootstrap_envelope_projection_counter_scratch_data() > 0);
}
