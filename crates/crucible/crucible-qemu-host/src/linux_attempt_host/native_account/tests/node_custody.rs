//! Refuses overwrite of genuine paired mechanism credit without native authority.

use super::*;

#[test]
fn occupied_credit_destination_keeps_the_same_original_and_real_account_pair() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let operation = original.status().unwrap().operation_id;
    let (credit, resident, metadata) =
        OriginalNativeAccountCredit::mechanism_credit(Arc::clone(&original)).unwrap();
    let mut source = None;
    let mut destination = Some(credit);
    let retained = std::ptr::from_ref(destination.as_ref().unwrap());

    let error = OriginalNativeAccountCredit::move_from_normal_subdivision(
        &mut source,
        &mut destination,
        &original,
        1,
    )
    .unwrap_err();

    assert!(matches!(error, OriginalActorAccountError::Unavailable));
    assert!(source.is_none());
    assert_eq!(std::ptr::from_ref(destination.as_ref().unwrap()), retained);
    assert!(Arc::ptr_eq(
        &destination
            .as_ref()
            .unwrap()
            .original
            .as_ref()
            .unwrap()
            .preparation,
        &original
    ));
    assert_eq!(original.status().unwrap().operation_id, operation);
    assert!(resident.reserve_resources(0, 0, 1).is_err());
    assert!(metadata.reserve_resources(0, 0, 1).is_err());

    destination
        .as_mut()
        .unwrap()
        .retire_after_control_free()
        .unwrap();
    assert!(destination.as_ref().unwrap().is_physically_returned());
    assert!(resident.reserve_resources(0, 0, 1).is_ok());
    assert!(metadata.reserve_resources(0, 0, 1).is_ok());
}
