//! Checks the combined actual ACK operands without issuing Source or ACK credit.
//!
//! Existing individual-view cases supply independent field oracles. This model
//! callback checks the combined roster, joins, Copy hashes and original cuts.

use super::*;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;

pub(super) fn assert_child(case: &str, original: &mut OriginalImport18RawBootstrap) {
    if case.ends_with("operands_callback_refused") {
        let entered = std::cell::Cell::new(false);
        assert!(
            original
                .with_bootstrap_ack_operands_data::<()>(|_| {
                    entered.set(true);
                    Err(ProviderError::Conflict("operand callback model"))
                })
                .is_err()
        );
        assert!(entered.get());
        original
            .with_hello_authority_data(|lease| lease.ensure_live())
            .unwrap();
        return;
    }
    if case.ends_with("operands_changed_loan_cut") {
        let prior = original.cut;
        let entered = std::cell::Cell::new(false);
        original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
        assert!(
            original
                .with_bootstrap_ack_operands_data(|_| {
                    entered.set(true);
                    Ok(())
                })
                .is_err()
        );
        assert!(!entered.get());
        original.cut = prior;
        original
            .with_hello_authority_data(|lease| lease.ensure_live())
            .unwrap();
        return;
    }
    if case.ends_with("operands_loan_expired") || case.ends_with("operands_error_expired") {
        let entered = std::cell::Cell::new(false);
        assert!(
            original
                .with_bootstrap_ack_operands_data(|_| {
                    entered.set(true);
                    std::thread::sleep(Duration::from_secs(5));
                    if case.ends_with("operands_error_expired") {
                        Err(ProviderError::Conflict("expired operand callback model"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert!(entered.get());
        assert!(original.cut.is_expired());
        assert!(
            original
                .with_hello_authority_data(|lease| lease.ensure_live())
                .is_err()
        );
        return;
    }

    let before = original.retained_requested_bytes().unwrap();
    let actual = original
        .with_bootstrap_ack_operands_data(|operands| {
            let shapes = operands.serialization_shapes_data(usize::MAX)?;
            let peak = shapes
                .iter()
                .map(|shape| shape.requested_total().unwrap())
                .max()
                .unwrap();
            let expected_shapes = shapes.each_ref().map(shape_fields);
            for restriction in [peak, peak + 4096] {
                let actual = operands.serialization_shapes_data(restriction)?;
                assert_eq!(actual.each_ref().map(shape_fields), expected_shapes);
            }
            assert!(operands.serialization_shapes_data(peak - 1).is_err());
            assert!(operands.serialization_shapes_data(1).is_err());
            assert!(shapes.iter().all(|shape| shape.maximum_encoded_bytes > 0));
            let values = [
                serde_json::to_value(operands.birth).unwrap(),
                serde_json::to_value(operands.kernel).unwrap(),
                serde_json::to_value(operands.policy).unwrap(),
                serde_json::to_value(operands.registration).unwrap(),
            ];
            for (value, expected) in values.iter().zip([
                "source-owned.packet-native-import-bootstrap-birth-association/18",
                "source-owned.packet-canonical-ack-kernel-binding/5",
                "source-owned.packet-native-import-bootstrap-policy-binding/18",
                "source-owned.packet-canonical-ack-registration/5",
            ]) {
                assert_eq!(value["schema"], expected);
            }
            assert_eq!(
                values
                    .each_ref()
                    .map(|value| value.as_object().unwrap().len()),
                [6, 3, 5, 9]
            );
            assert_eq!(values[0]["source_binding"], values[2]["source_binding"]);
            assert_eq!(values[2]["negotiated"]["limits"], values[3]["limits"]);
            assert_eq!(values[2]["negotiated"]["features"], values[3]["features"]);
            assert_eq!(values[3]["role"], "native");
            Ok(values.each_ref().map(digest))
        })
        .unwrap();
    for (index, digest) in actual.iter().enumerate() {
        assert!(!actual[..index].contains(digest));
    }
    assert_eq!(original.retained_requested_bytes().unwrap(), before);
    let compact =
        OriginalImport18RawBootstrap::bootstrap_ack_operands_counter_scratch_data::<()>().unwrap();
    let large =
        OriginalImport18RawBootstrap::bootstrap_ack_operands_counter_scratch_data::<[u8; 4096]>()
            .unwrap();
    assert!(large >= compact + 8192);
    assert!(
        compact
            > OriginalImport18RawBootstrap::bootstrap_kernel_loan_counter_scratch_data::<()>()
                .unwrap()
    );
}

fn digest(value: &Value) -> [u8; 32] {
    let bytes = canonical::canonical_json(value).unwrap();
    *blake3::hash(&bytes).as_bytes()
}

fn shape_fields(shape: &OriginalSerializationStorageData) -> [usize; 11] {
    [
        shape.dom_and_canonical_scratch_bytes,
        shape.retained_value_backing_bytes,
        shape.projected_parser_requested_bytes,
        shape.canonical_output_requested_bytes,
        shape.serializer_temporary_requested_bytes,
        shape.declared_counter_scratch_bytes,
        shape.maximum_encoded_bytes,
        shape.sequence_elements,
        shape.sequence_containers,
        shape.serialized_value_nodes,
        shape.serialized_capacity_records,
    ]
}
