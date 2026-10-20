//! Retires actual paired mechanism custody from the prepaid construction lane.
//!
//! This is not a Source/native provider: no node, subdivision or roster is made.

use super::*;
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};

#[test]
fn construction_retirement_frees_the_same_credit_once_without_a_roster() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let operation = original.status().unwrap().operation_id;
    let (credit, resident, metadata) =
        OriginalNativeAccountCredit::mechanism_credit(Arc::clone(&original)).unwrap();
    let resident_bytes = credit.full_resident_bytes;
    let metadata_bytes = credit.total_metadata_bytes;
    let mut node = NormalNode {
        world: 7,
        state: NormalNodeState::Constructing(NodeConstruction {
            node: None,
            subdivision: None,
            credit: Some(credit),
            attempted: true,
        }),
    };

    assert!(node.binding().is_none());
    assert!(!node.can_remove());
    assert!(resident.reserve_resources(0, 0, 1).is_err());
    assert!(metadata.reserve_resources(0, 0, 1).is_err());
    node.try_close().unwrap();

    assert!(node.can_remove());
    assert!(node.binding().is_none());
    assert_eq!(node.world, 7);
    assert_eq!(original.status().unwrap().operation_id, operation);
    let resident_loan = resident.reserve_resources(0, 0, resident_bytes).unwrap();
    let metadata_loan = metadata.reserve_resources(0, 0, metadata_bytes).unwrap();
    // An already emptied stage cannot release those independent new loans.
    node.try_close().unwrap();
    assert!(node.can_remove());
    assert!(resident.reserve_resources(0, 0, 1).is_err());
    assert!(metadata.reserve_resources(0, 0, 1).is_err());
    drop((resident_loan, metadata_loan));
}
