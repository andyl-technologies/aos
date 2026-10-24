//! Checks typed/SDK settlement demand without forging opaque Controller inputs.

use super::*;

#[test]
fn settlement_row_keeps_decoder_sdk_and_moved_request_demand_independent() {
    let row = quote(usize::MAX).unwrap();
    let component = row.decoder_component_data().requested_storage_data();
    for (outer, inner) in row.requested_storage_data().into_iter().zip(component) {
        assert!(outer > inner);
    }
    let exact = sum(&row.requested_storage_data()).unwrap();
    assert_eq!(quote(exact).unwrap(), row);
    assert!(quote(exact - 1).is_err());
}
