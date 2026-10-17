//! Checks actual unlaunched Source owners without constructing native authority.

use super::super::tests::{coordinator, installation, producer, reactive, storage_selection};
use super::*;

type TestResult = Result<(), String>;

fn producer_source(spare: usize) -> Result<Rc<PacketCompleteSemanticSource>, String> {
    let installed = coordinator();
    let mut program = producer();
    program.events.reserve(spare);
    PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&installed, 0),
        program,
        installed,
        storage_selection(),
    )
    .map(Rc::new)
    .map_err(|failure| format!("{failure:?}"))
}

#[test]
fn code_source_observer_counts_actual_spare_backing_at_exact_bound() -> TestResult {
    let original = producer_source(0)?;
    let spare = producer_source(31)?;
    let original_bytes = original
        .original_complete_code_retained_storage_data(usize::MAX)
        .map_err(|failure| format!("{failure:?}"))?;
    let spare_bytes = spare
        .original_complete_code_retained_storage_data(usize::MAX)
        .map_err(|failure| format!("{failure:?}"))?;
    assert!(spare_bytes > original_bytes);
    assert_eq!(
        spare
            .original_complete_code_retained_storage_data(spare_bytes)
            .map_err(|failure| format!("{failure:?}"))?,
        spare_bytes
    );
    assert!(
        spare
            .original_complete_code_retained_storage_data(spare_bytes - 1)
            .is_err()
    );
    assert!(
        spare
            .original_complete_code_retained_storage_data(spare_bytes)
            .is_ok()
    );
    assert!(spare.authenticate_current_native().is_err());
    assert!(
        spare
            .capture_banks
            .try_borrow()
            .map_err(|error| error.to_string())?
            .is_none()
    );
    assert!(
        spare
            .original_complete_retained_storage_data(usize::MAX)
            .is_err()
    );
    Ok(())
}

#[test]
fn reactive_code_source_counts_absent_unattempted_input_and_native_banks() -> TestResult {
    let installed = coordinator();
    let source = Rc::new(
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation(&installed, 1),
            reactive(&installed, 1),
            installed,
            storage_selection(),
        )
        .map_err(|failure| format!("{failure:?}"))?,
    );
    let actual = source
        .original_complete_code_retained_storage_data(usize::MAX)
        .map_err(|failure| format!("{failure:?}"))?;
    assert!(actual > std::mem::size_of::<PacketCompleteSemanticSource>());
    assert_eq!(
        source
            .original_complete_code_retained_storage_data(actual)
            .map_err(|failure| format!("{failure:?}"))?,
        actual
    );
    assert!(
        source
            .original_complete_code_retained_storage_data(actual - 1)
            .is_err()
    );
    assert!(source.original_complete_input_static_storage().is_err());
    assert!(source.authenticate_current_native().is_err());
    Ok(())
}

#[test]
fn code_source_observer_refuses_busy_and_spent_phases_without_clearing_them() -> TestResult {
    let mut source = producer_source(0)?;
    let before = source
        .original_complete_code_retained_storage_data(usize::MAX)
        .map_err(|failure| format!("{failure:?}"))?;
    let held = source
        .preconstruction
        .try_borrow_mut()
        .map_err(|error| error.to_string())?;
    assert!(
        source
            .original_complete_code_retained_storage_data(usize::MAX)
            .is_err()
    );
    drop(held);
    assert_eq!(
        source
            .original_complete_code_retained_storage_data(usize::MAX)
            .map_err(|failure| format!("{failure:?}"))?,
        before
    );
    assert!(
        source
            .original_complete_report_startup_retained_storage_data(usize::MAX)
            .is_err()
    );
    assert!(
        source
            .ack_peer_birth
            .try_borrow()
            .map_err(|error| error.to_string())?
            .is_none()
    );

    // Model the already-spent private-birth attempt without entropy or file I/O.
    Rc::get_mut(&mut source)
        .ok_or("unique actual Source")?
        .ack_birth_attempted = true;
    assert!(
        source
            .original_complete_code_retained_storage_data(usize::MAX)
            .is_err()
    );
    assert!(source.ack_birth_attempted);
    assert!(
        source
            .original_complete_report_startup_retained_storage_data(usize::MAX)
            .is_err()
    );
    assert!(source.authenticate_current_native().is_err());

    let unlaunched = producer_source(0)?;
    unlaunched.complete_bytes_launch_reserved.set(true);
    assert!(
        unlaunched
            .original_complete_code_retained_storage_data(usize::MAX)
            .is_err()
    );
    assert!(unlaunched.complete_bytes_launch_reserved.get());
    assert!(unlaunched.authenticate_current_native().is_err());
    Ok(())
}
