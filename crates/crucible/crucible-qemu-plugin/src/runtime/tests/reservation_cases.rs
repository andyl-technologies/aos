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

#[test]
fn runtime_request_retains_the_worker_registry_allocation() {
    let configured = prebirth::RuntimeAllocationRequests::configured(1, false)
        .unwrap_or_else(|error| panic!("configured runtime requests should be valid: {error}"));
    let requests = configured.layouts();

    // A worker registry is a genuinely shared body with a mutex and condition
    // variable. Its request must not reuse the small callback gate or merely
    // price the Arc pointer stored inline in the runtime Box.
    assert!(requests[2].size() > std::mem::size_of::<LiveWorkerQuiescence>());
    assert!(requests[2].size() > requests[1].size());
    assert!(requests[2].size() > std::mem::size_of::<Arc<LiveWorkerQuiescence>>());
    assert!(requests[2].align() >= std::mem::align_of::<LiveWorkerQuiescence>());
}
