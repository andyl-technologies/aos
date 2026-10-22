//! Checks independently derived receipt rows without forging a Controller owner.

use super::*;

#[test]
fn receive_row_retains_raw_demand_and_restricts_each_enclosing_component() {
    let row = quote(65536, usize::MAX).unwrap();
    let component = row.raw_component_data();
    for (outer, inner) in row
        .requested_storage_data()
        .into_iter()
        .zip(component.requested_storage_data())
    {
        assert!(outer > inner);
    }
    assert_eq!(component.maximum_body_bytes_data(), 65536);
    let exact = storage::checked_sum_data(&row.requested_storage_data()).unwrap();
    assert_eq!(quote(65536, exact).unwrap(), row);
    assert!(quote(65536, exact - 1).is_err());
    assert!(quote(0, usize::MAX).is_err());
}
