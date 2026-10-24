//! Rejects copied roster geometry without an actual normal subdivision.

use super::*;
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};

#[test]
fn matching_control_bytes_without_normal_purpose_cannot_publish_a_roster() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let (mut credit, resident, metadata) =
        OriginalNativeAccountCredit::mechanism_credit(Arc::clone(&original)).unwrap();
    // Copying inert geometry does not manufacture a normal native purpose.
    credit.normal_controls_bytes = OriginalNativeAccountRoster::shared_allocation_extent().unwrap();
    let mut source = Some(credit);
    let retained = std::ptr::from_ref(source.as_ref().unwrap());
    let operation = original.status().unwrap().operation_id;

    let result = OriginalNativeAccountRoster::publish_normal_credit(&mut source);

    assert!(matches!(
        result,
        Err(OriginalActorAccountError::Unavailable)
    ));
    assert_eq!(std::ptr::from_ref(source.as_ref().unwrap()), retained);
    assert!(
        source
            .as_ref()
            .unwrap()
            .original
            .as_ref()
            .unwrap()
            .normal
            .is_none()
    );
    assert_eq!(original.status().unwrap().operation_id, operation);
    assert!(resident.reserve_resources(0, 0, 1).is_err());
    assert!(metadata.reserve_resources(0, 0, 1).is_err());

    source
        .as_mut()
        .unwrap()
        .retire_after_control_free()
        .unwrap();
    assert!(source.as_ref().unwrap().is_physically_returned());
    assert!(resident.reserve_resources(0, 0, 1).is_ok());
    assert!(metadata.reserve_resources(0, 0, 1).is_ok());
}
