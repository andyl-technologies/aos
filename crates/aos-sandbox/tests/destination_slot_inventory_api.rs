//! Verifies that downstream controllers can name slot inventory results.

#![cfg(target_os = "linux")]

use aos_sandbox::{
    CurrentDestinationSlotReconciliationV1, DestinationSlotInventorySnapshotOutcomeV1,
    DestinationSlotReconciliationActionV1, DurableAttachmentSlotV1,
    DurableDestinationSlotInventorySnapshotV1,
};
use aos_sandbox_core::{ObjectDigest, OperationId};
use aos_sandbox_protocol::ValidatedDestinationSlotInventory;

#[test]
fn downstream_code_can_inspect_destination_slot_inventory_results() {
    fn accept_opaque_results(
        _: Option<DurableDestinationSlotInventorySnapshotV1>,
        _: Option<CurrentDestinationSlotReconciliationV1>,
    ) {
    }

    let snapshot_outcome: fn(
        &DurableDestinationSlotInventorySnapshotV1,
    ) -> DestinationSlotInventorySnapshotOutcomeV1 =
        DurableDestinationSlotInventorySnapshotV1::outcome;
    let inventory: fn(
        &DurableDestinationSlotInventorySnapshotV1,
    ) -> &ValidatedDestinationSlotInventory = DurableDestinationSlotInventorySnapshotV1::inventory;
    let slot: fn(&CurrentDestinationSlotReconciliationV1) -> &DurableAttachmentSlotV1 =
        CurrentDestinationSlotReconciliationV1::slot;
    let action: fn(
        &CurrentDestinationSlotReconciliationV1,
    ) -> DestinationSlotReconciliationActionV1 = CurrentDestinationSlotReconciliationV1::action;

    let example = DestinationSlotReconciliationActionV1::Reap {
        operation_id: OperationId::from_bytes([1; 16]),
        expected_resource_digest: ObjectDigest::from_bytes([2; 32]),
    };
    assert!(matches!(
        example,
        DestinationSlotReconciliationActionV1::Reap { .. }
    ));
    let _ = (
        accept_opaque_results,
        snapshot_outcome,
        inventory,
        slot,
        action,
    );
}
