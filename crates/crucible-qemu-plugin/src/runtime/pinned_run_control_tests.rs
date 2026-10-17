//! Actual socket and pinned-allocation ownership controls without native eligibility.

use super::*;

#[test]
fn original_run_actor_remains_in_same_registered_allocation() {
    let _runtime_state = isolate_runtime_state_for_test();
    reset_capability_call_counts();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
    let mut reservation = reserve_runtime().expect("test runtime reservation");
    let mut runtime = install_live_runtime(
        41,
        fixture.args(),
        test_capabilities(),
        &SuccessfulCallbackRegistrar,
        &mut reservation,
    )
    .expect("actual setup owner");
    host.join().expect("setup host reaped");
    let original = runtime
        ._retained_control
        .take()
        .expect("original RUN socket");
    let descriptor = original.as_raw_fd();
    let state = runtime._callbacks.state.as_ref().get_ref();
    let allocation = std::ptr::from_ref(state);

    let preparation = state.prepare_original_run_control(original);

    assert!(preparation.status.is_ok());
    let stored = state
        .original_run_control
        .get()
        .expect("actor retained in userdata");
    assert!(Arc::ptr_eq(stored, &preparation.owner));
    assert_eq!(
        stored.descriptor().expect("original descriptor"),
        descriptor
    );
    assert_eq!(
        std::ptr::from_ref(runtime._callbacks.state.as_ref().get_ref()),
        allocation
    );
    assert_eq!(stored.snapshot().expect("original prefix").received, 0);
    drop(preparation);
    assert_eq!(Arc::strong_count(stored), 1);
    assert_eq!(
        stored.descriptor().expect("descriptor still owned"),
        descriptor
    );
    fixture.assert_control_silent();
}

#[test]
fn refused_preparation_retains_actual_socket_before_status() {
    let _runtime_state = isolate_runtime_state_for_test();
    reset_capability_call_counts();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
    let mut reservation = reserve_runtime().expect("test runtime reservation");
    let runtime = install_live_runtime(
        41,
        fixture.args(),
        test_capabilities(),
        &SuccessfulCallbackRegistrar,
        &mut reservation,
    )
    .expect("actual setup owner");
    host.join().expect("setup host reaped");
    // This separately offered non-RUN socket is deliberately refused. It is
    // a physical retention control, not an authentic whole constructor.
    let (_peer, socket) = UnixStream::pair().expect("offered socket");
    let descriptor = socket.as_raw_fd();
    let offered =
        ControlLifecycleStream::connected_unix_stream(socket).expect("connected lifecycle");
    let state = runtime._callbacks.state.as_ref().get_ref();

    let preparation = state.prepare_original_run_control(offered);

    assert!(matches!(
        preparation.status,
        Err(native_run_control::NativeRunControlError::NotRunning)
    ));
    let stored = state
        .original_run_control
        .get()
        .expect("refused owner retained");
    assert!(Arc::ptr_eq(stored, &preparation.owner));
    drop(preparation);
    assert_eq!(
        stored.descriptor().expect("refused socket still owned"),
        descriptor
    );
    assert_eq!(
        stored.snapshot().expect("retained refused prefix").received,
        0
    );
}

#[test]
fn duplicate_attachment_preserves_first_and_returns_second_owner() {
    let _runtime_state = isolate_runtime_state_for_test();
    reset_capability_call_counts();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
    let mut reservation = reserve_runtime().expect("test runtime reservation");
    let mut runtime = install_live_runtime(
        41,
        fixture.args(),
        test_capabilities(),
        &SuccessfulCallbackRegistrar,
        &mut reservation,
    )
    .expect("actual setup owner");
    host.join().expect("setup host reaped");
    let original = runtime
        ._retained_control
        .take()
        .expect("original RUN socket");
    let descriptor = original.as_raw_fd();
    let state = runtime._callbacks.state.as_ref().get_ref();
    let first = state.prepare_original_run_control(original);
    assert!(first.status.is_ok());
    let (_peer, offered) = native_run_control::test_running_pair();
    let second_descriptor = offered.as_raw_fd();

    let second = state.prepare_original_run_control(offered);

    assert!(matches!(
        second.status,
        Err(native_run_control::NativeRunControlError::Ownership)
    ));
    let stored = state
        .original_run_control
        .get()
        .expect("first retained actor");
    assert!(Arc::ptr_eq(stored, &first.owner));
    assert!(!Arc::ptr_eq(stored, &second.owner));
    assert_eq!(stored.descriptor().expect("original FD"), descriptor);
    assert_eq!(
        second.owner.descriptor().expect("returned second FD"),
        second_descriptor
    );
    assert_eq!(
        stored
            .snapshot()
            .expect("unchanged original bytes")
            .received,
        0
    );
    assert_eq!(
        second
            .owner
            .snapshot()
            .expect("unchanged offered bytes")
            .received,
        0
    );
}
