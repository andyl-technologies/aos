//! Checks independently derived SDK component demand without forging an owner.

use super::*;

#[test]
fn independent_sdk_rows_restrict_actual_components_and_keep_operation_identity() {
    let component =
        Connection::<DeadlineStream>::original_bootstrap_sealing_construction_data(usize::MAX)
            .unwrap();
    let registration = quote(false, usize::MAX).unwrap();
    let publication = quote(true, usize::MAX).unwrap();

    assert_ne!(registration, publication);
    assert_eq!(
        registration.requested_storage_data(),
        publication.requested_storage_data()
    );
    for (outer, inner) in registration
        .requested_storage_data()
        .into_iter()
        .zip(component)
    {
        assert!(outer > inner);
    }
    let exact = storage::checked_sum_data(&registration.requested_storage_data()).unwrap();
    assert_eq!(quote(false, exact).unwrap(), registration);
    assert_eq!(quote(true, exact).unwrap(), publication);
    assert!(quote(false, exact - 1).is_err());
    assert!(quote(true, exact - 1).is_err());
}
