//! Exercises cleanup-chain physical succession without minting native custody.

use super::cleanup_lineage_successor_data_v1;
use aos_sandbox_protocol::{
    host_cleanup_lineage::HostCleanupLineageDataV1,
    host_inventory_absence::HostInventoryAbsenceDataV5,
    host_stop_cleanup::HostStopCleanupSubjectDataV1,
    host_stopped_namespace::{HostStoppedInventoryDataV1, HostStoppedNamespaceDataV4},
};

fn row(request: u8, before: u64, after: u64) -> HostCleanupLineageDataV1 {
    // Decode the actual public fixed format; Core cannot manufacture Protocol's
    // private validated fence fields, and these DATA create no authenticated IO.
    let mut encoded = [1; 328];
    encoded[..8].copy_from_slice(b"AOSHNS04");
    encoded[56..64].copy_from_slice(&1_u64.to_le_bytes());
    encoded[64..72].copy_from_slice(&1_u64.to_le_bytes());
    encoded[136..168].copy_from_slice(&aos_sandbox_protocol::semantics::host::runtime_handle_v1(
        &[1; 16], 1, &[1; 32],
    ));
    encoded[248..264].copy_from_slice(&[2; 16]);
    encoded[296..328].copy_from_slice(&[3; 32]);
    let scope = HostStoppedNamespaceDataV4::decode_v4(&encoded).unwrap();
    let subject = HostStopCleanupSubjectDataV1::from_data_v1(
        scope, [4; 16], [5; 16], [6; 32], [7; 16], [8; 32], 100,
    )
    .unwrap();
    HostCleanupLineageDataV1::from_data_v1(
        subject,
        ([5; 16], [9; 32], [10; 32]),
        HostInventoryAbsenceDataV5::from_data_v5([request; 16], [11; 16], [12; 16], before, after)
            .unwrap(),
        [13; 32],
    )
    .unwrap()
}

#[test]
fn new_census_changes_literal_evidence_without_changing_chain_and_must_advance() {
    let before = row(14, 20, 22);
    let after = row(15, 23, 25);

    assert_ne!(before.encode_v1(), after.encode_v1());
    assert_eq!(
        HostStoppedInventoryDataV1::Cleanup(before).cleanup_physical_commitment_v1(),
        HostStoppedInventoryDataV1::Cleanup(after).cleanup_physical_commitment_v1()
    );
    assert!(cleanup_lineage_successor_data_v1(Some(before), Some(after)));
    assert!(!cleanup_lineage_successor_data_v1(
        Some(before),
        Some(before)
    ));
    assert!(!cleanup_lineage_successor_data_v1(
        Some(after),
        Some(before)
    ));
    assert!(!cleanup_lineage_successor_data_v1(
        Some(before),
        Some(row(15, 21, 25))
    ));
    let foreign = HostCleanupLineageDataV1::from_data_v1(
        *after.subject_v1(),
        after.child_v1(),
        *after.observation_v1(),
        [16; 32],
    )
    .unwrap();
    assert!(!cleanup_lineage_successor_data_v1(
        Some(before),
        Some(foreign)
    ));
    assert!(!cleanup_lineage_successor_data_v1(Some(before), None));
}
