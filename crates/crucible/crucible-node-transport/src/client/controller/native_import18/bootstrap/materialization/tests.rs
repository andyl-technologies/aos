//! Checks component accounting without constructing opaque Controller operands.

use super::*;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA, native_import18_bootstrap_assignment_into_data,
    native_import18_bootstrap_assignment_quote_data,
};
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;

fn inputs() -> (
    PacketNativeImport18BootstrapAssignmentData,
    PacketNativeImport18BootstrapAckProof,
) {
    let ids = ["session", "incarnation", "request"].map(|text| Id::new(text).unwrap());
    let request = PacketNativeImport18BootstrapRequest {
        schema: NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.into(),
        recipe_identity: Bytes::new(vec![7; 32]),
        initial_funding: PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(1),
            maximum_simultaneous_transient_bytes: U64::new(2),
            declared_counter_scratch_bytes: U64::new(3),
        },
    };
    let mut assignment = None;
    native_import18_bootstrap_assignment_into_data(
        ids.each_ref(),
        &request,
        &native_import18_bootstrap_assignment_quote_data(usize::MAX).unwrap(),
        usize::MAX,
        &mut assignment,
    )
    .unwrap();
    let proof = PacketNativeImport18BootstrapAckProof {
        schema: NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        algorithm: "blake3-keyed-canonical/1".into(),
        context_digest: Bytes::new(vec![11; 32]),
        mac: Bytes::new(vec![13; 32]),
    };
    (assignment.unwrap(), proof)
}

#[test]
fn actual_component_and_enclosing_controls_are_separate_at_the_exact_restriction() {
    let (assignment, proof) = inputs();
    let component =
        native_import18_bootstrap_sealing_quote_data(&assignment, &proof, usize::MAX).unwrap();
    let row = quote_materialization(&assignment, &proof, usize::MAX).unwrap();

    assert_eq!(row.component, component);
    let component_axes = component.requested_storage_data();
    assert_eq!(
        row.axes[0] - component_axes[0],
        size_of::<PacketNativeImport18BootstrapMaterializationRowData>()
    );
    assert_eq!(
        row.axes[1] - component_axes[1],
        size_of::<PacketNativeImport18BootstrapMaterializationRowData>() * 2
    );
    assert_eq!(
        row.axes[2] - component_axes[2],
        CnpController::original_native_import18_bootstrap_materialization_counter_scratch_data()
    );
    let exact = storage::checked_sum_data(&row.axes).unwrap();
    assert_eq!(
        quote_materialization(&assignment, &proof, exact).unwrap(),
        row
    );
    assert!(quote_materialization(&assignment, &proof, exact - 1).is_err());
}

#[test]
fn changed_typed_backing_is_requoted_and_malformed_proof_refuses_without_consuming_inputs() {
    let (assignment, mut proof) = inputs();
    let first = quote_materialization(&assignment, &proof, usize::MAX).unwrap();
    let old_capacity = proof.mac.allocation_capacity();
    let mut mac = Vec::with_capacity(4096);
    mac.extend_from_slice(proof.mac.as_slice());
    proof.mac = Bytes::new(mac);
    let changed = quote_materialization(&assignment, &proof, usize::MAX).unwrap();

    assert_eq!(changed.axes[0] - first.axes[0], 4096 - old_capacity);
    assert_eq!(changed.axes[1..], first.axes[1..]);
    assert!(
        assignment
            .borrowed_history_data()
            .original
            .unwrap()
            .extensions
            .is_empty()
    );
    proof.schema.push('x');
    assert!(quote_materialization(&assignment, &proof, usize::MAX).is_err());
    assert_eq!(proof.mac.allocation_capacity(), 4096);
    assert!(assignment.borrowed_history_data().assigned);
}
