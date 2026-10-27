//! Checks absent preconstruction DATA without inventing a native association.

use super::super::tests::{coordinator, installation, producer, storage_selection};
use super::*;

#[test]
fn preconstruction_capacity_absent_busy_and_foreign_sources_keep_their_original_slot() {
    let coordinator = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&coordinator, 0),
        producer(),
        coordinator,
        storage_selection(),
    )
    .unwrap();
    let before = source.original_preconstruction_capacity_data(None).unwrap();
    assert_eq!(before.capacity_records, 0);
    assert!(source.authenticate_original_preconstruction().is_err());
    let held = source.preconstruction.borrow_mut();
    assert_eq!(
        source.original_preconstruction_capacity_data(None),
        Err(RuntimeError::OwnerBusy)
    );
    drop(held);
    assert_eq!(
        source.original_preconstruction_capacity_data(None).unwrap(),
        before
    );
    let creator = source.process;
    source.process = creator.wrapping_add(1);
    let held = source.preconstruction.borrow_mut();
    assert_eq!(
        source.original_preconstruction_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );
    drop(held);
    source.process = creator;
    assert!(source.preconstruction.borrow().is_none());
    assert!(source.authenticate_original_preconstruction().is_err());
    assert!(
        PacketCompleteSemanticSource::original_preconstruction_capacity_counter_scratch_data() > 0
    );
}
