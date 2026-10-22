//! Checks strict scalar borrower observations independently of graph certificates.

use serde_json::json;

use super::native_worker_tests::prepared_report;
use crate::qmp::hot_fork::block_barrier::parse_hot_fork_block_barrier_state;

#[test]
fn borrower_counts_remain_observations_of_live_maps() -> Result<(), crate::QmpError> {
    let mut report = prepared_report();
    let block = &mut report["block-barrier"];
    block["ram-paging-requested"] = json!(true);
    block["ram-bounce-maps"] = json!(2);
    let state = parse_hot_fork_block_barrier_state(block)?;
    assert!(state.ram_borrowers().consistent);
    assert!(state.ram_borrowers().paging_requested);
    assert_eq!(state.ram_borrowers().bounce_maps, 2);
    // The block graph drain cannot certify the independent physical RAM closure.
    assert!(state.quiescent());

    block["ram-borrow-generation"] = json!(0);
    block["ram-borrowers-consistent"] = json!(false);
    assert!(
        !parse_hot_fork_block_barrier_state(block)?
            .ram_borrowers()
            .consistent
    );
    Ok(())
}

#[test]
fn borrower_inventory_requires_current_closed_typed_fields() {
    let baseline = prepared_report();
    for (field, value) in [
        ("schema-version", json!(4)),
        ("ram-borrow-generation", json!(0)),
        ("ram-direct-maps", json!(-1)),
        ("ram-bounce-maps", json!("1")),
        ("ram-caches", json!(null)),
        ("ram-direct-caches", json!(false)),
        ("ram-paging-requested", json!(1)),
        ("ram-borrowers-consistent", json!(1)),
        ("unknown-borrower", json!(0)),
    ] {
        let mut block = baseline["block-barrier"].clone();
        block[field] = value;
        assert!(
            parse_hot_fork_block_barrier_state(&block).is_err(),
            "{field}"
        );
    }
    for field in [
        "ram-borrow-generation",
        "ram-direct-maps",
        "ram-bounce-maps",
        "ram-caches",
        "ram-direct-caches",
        "ram-paging-requested",
        "ram-borrowers-consistent",
    ] {
        let mut block = baseline["block-barrier"].clone();
        if let Some(object) = block.as_object_mut() {
            object.remove(field);
        }
        assert!(
            parse_hot_fork_block_barrier_state(&block).is_err(),
            "{field}"
        );
    }
}
