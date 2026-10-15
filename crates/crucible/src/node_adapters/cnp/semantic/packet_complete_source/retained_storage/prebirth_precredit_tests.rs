//! Checks the actual never-born Source code observation and its exact boundary.

use super::super::tests::{coordinator, installation, producer, storage_selection};
use super::super::*;
use crate::node_contract::RuntimeError;
use std::rc::Rc;

#[test]
fn actual_never_born_code_source_raw_exact_and_one_short_preserve_legacy_backing()
-> Result<(), String> {
    let coordinator = coordinator();
    let mut program = producer();
    program.events.reserve(29);
    let source = Rc::new(
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            installation(&coordinator, 0),
            program,
            coordinator,
            storage_selection(),
        )
        .map_err(|error| format!("{error:?}"))?,
    );
    let legacy = source
        .original_complete_code_retained_storage_data(usize::MAX)
        .map_err(|error| format!("{error:?}"))?;
    let actual = source
        .original_complete_code_retained_storage_precredit_data(usize::MAX)
        .map_err(|error| format!("{error:?}"))?;
    assert!(actual > 0);
    assert_eq!(actual, legacy);
    assert_eq!(
        source.original_complete_code_retained_storage_precredit_data(actual),
        Ok(actual)
    );
    assert!(
        source
            .original_complete_code_retained_storage_precredit_data(actual - 1)
            .is_err()
    );
    assert_eq!(
        source
            .original_complete_code_retained_storage_data(usize::MAX)
            .map_err(|error| format!("{error:?}"))?,
        legacy
    );
    // This explicit code phase cannot become a ready-birth observation.
    assert_eq!(
        source.original_complete_report_startup_retained_storage_precredit_data(usize::MAX),
        Err(RuntimeError::UnsupportedFacet)
    );
    assert!(source.capture_banks.borrow().is_none());
    assert!(source.ack_peer_birth.borrow().is_none());
    Ok(())
}
