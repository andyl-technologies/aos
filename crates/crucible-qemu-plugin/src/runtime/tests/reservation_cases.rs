//! Runtime-singleton reservation regression cases.

use super::*;

#[test]
fn duplicate_reservation_fails_before_protocol_io_can_begin() {
    let _runtime_state = isolate_runtime_state_for_test();
    let _first =
        reserve_runtime().unwrap_or_else(|error| panic!("first runtime should reserve: {error}"));

    assert!(matches!(
        reserve_runtime(),
        Err(PluginRuntimeInstallError::RuntimeAlreadyReserved)
    ));
}

#[test]
fn irreversible_reservation_failure_blocks_second_install_attempt() {
    let _runtime_state = isolate_runtime_state_for_test();
    {
        let mut reservation =
            reserve_runtime().unwrap_or_else(|error| panic!("runtime should reserve: {error}"));
        reservation.mark_irreversible();
    }

    assert_eq!(RUNTIME_STATE.load(Ordering::Acquire), RUNTIME_FAILED);
    assert!(matches!(
        reserve_runtime(),
        Err(PluginRuntimeInstallError::RuntimeAlreadyReserved)
    ));
}
