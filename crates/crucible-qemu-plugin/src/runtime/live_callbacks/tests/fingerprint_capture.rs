//! Exact-boundary fingerprint capture callback tests.

use super::*;

#[test]
fn requested_control_callback_captures_and_acknowledges_each_exact_request() {
    let node_slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 7, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    node_slot
        .publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let fingerprint_slot = FingerprintSampleSlot::new();
    let introspector = crate::PluginVcpuIntrospector::require(
        Some(test_fingerprint_read_vcpu_regs),
        Some(test_fingerprint_read_rr_cursor),
    )
    .unwrap_or_else(|error| panic!("test introspector should bind: {error}"));
    let sampling = crate::fingerprint_sampler::PluginFingerprintSampling::from_test_exports(
        introspector,
        test_fingerprint_capture,
    );
    let state = test_live_state(80, 1, 0, 0, &node_slot)
        .and_then(|state| {
            state.attach_fingerprint(
                sampling,
                &fingerprint_slot,
                LiveWorkerQuiescence::new(crate::runtime::worker_quiescence::WORKER_ALL),
            )
        })
        .unwrap_or_else(|error| panic!("live fingerprint state should build: {error}"));

    TEST_FINGERPRINT_CAPTURE_COUNT.set(0);
    TEST_FINGERPRINT_CAPTURE_SEED.set(0x10);
    state
        .publish_current_icount(7)
        .unwrap_or_else(|error| panic!("exact quantum should publish: {error}"));
    assert_eq!(fingerprint_slot.snapshot(), None);

    let ordinary_control_request = node_slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("ordinary control request should publish: {error}"));
    state
        .on_control_boundary(7)
        .unwrap_or_else(|error| panic!("ordinary control request should complete: {error}"));
    assert_eq!(TEST_FINGERPRINT_CAPTURE_COUNT.get(), 0);
    assert_eq!(fingerprint_slot.snapshot(), None);
    assert_eq!(
        node_slot.snapshot().control_boundary_ack,
        ordinary_control_request.wrapping_add(1)
    );

    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    state
        .header
        .get()
        .request_pause([&node_slot])
        .unwrap_or_else(|error| panic!("pause should publish: {error}"));
    let pause_control_request = node_slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("pause control request should publish: {error}"));
    state
        .on_control_boundary(7)
        .unwrap_or_else(|error| panic!("pause control request should complete: {error}"));
    assert_eq!(TEST_FINGERPRINT_CAPTURE_COUNT.get(), 0);
    assert_eq!(fingerprint_slot.snapshot(), None);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    assert_eq!(
        node_slot.snapshot().control_boundary_ack,
        pause_control_request.wrapping_add(1)
    );
    state.header.get().clear_pause();

    let first_capture_request = fingerprint_slot.request_capture_v1();
    let first_control_request = node_slot
        .request_control_boundary(0, Some(first_capture_request))
        .unwrap_or_else(|error| panic!("first control request should publish: {error}"));
    state
        .on_control_boundary(7)
        .unwrap_or_else(|error| panic!("first capture request should complete: {error}"));
    let first_sample = wait_for_fingerprint_sample(&fingerprint_slot, first_capture_request);
    assert_eq!(first_sample.sample_icount, 7);
    assert_eq!(
        fingerprint_slot.capture_request_generation(),
        first_capture_request.wrapping_add(1)
    );
    assert_eq!(
        node_slot.snapshot().control_boundary_ack,
        first_control_request.wrapping_add(1)
    );

    TEST_FINGERPRINT_CAPTURE_SEED.set(0x40);
    let second_capture_request = fingerprint_slot.request_capture_v1();
    let second_control_request = node_slot
        .request_control_boundary(0, Some(second_capture_request))
        .unwrap_or_else(|error| panic!("second control request should publish: {error}"));
    state
        .on_control_boundary(7)
        .unwrap_or_else(|error| panic!("same-icount recapture should complete: {error}"));
    let second_sample = wait_for_fingerprint_sample(&fingerprint_slot, second_capture_request);

    assert_eq!(TEST_FINGERPRINT_CAPTURE_COUNT.get(), 2);
    assert_eq!(second_sample.sample_icount, first_sample.sample_icount);
    assert_ne!(second_sample.ram_digest, first_sample.ram_digest);
    assert_eq!(
        fingerprint_slot.capture_request_generation(),
        second_capture_request.wrapping_add(1)
    );
    assert_eq!(
        node_slot.snapshot().control_boundary_ack,
        second_control_request.wrapping_add(1)
    );
}

#[test]
fn fingerprint_projection_rejects_an_in_flight_device_before_capture() {
    let node_slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 7, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    node_slot
        .publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let fingerprint_slot = FingerprintSampleSlot::new();
    let introspector = crate::PluginVcpuIntrospector::require(
        Some(test_fingerprint_read_vcpu_regs),
        Some(test_fingerprint_read_rr_cursor),
    )
    .unwrap_or_else(|error| panic!("test introspector should bind: {error}"));
    let sampling = crate::fingerprint_sampler::PluginFingerprintSampling::from_test_exports(
        introspector,
        test_fingerprint_capture,
    );
    let state = test_live_state(81, 1, 0, 0, &node_slot)
        .and_then(|state| {
            state.attach_fingerprint(
                sampling,
                &fingerprint_slot,
                LiveWorkerQuiescence::new(crate::runtime::worker_quiescence::WORKER_ALL),
            )
        })
        .unwrap_or_else(|error| panic!("live fingerprint state should build: {error}"));

    TEST_FINGERPRINT_CAPTURE_COUNT.set(0);
    let _capture_request = fingerprint_slot.request_capture_v1();
    node_slot
        .request_control_boundary(0, Some(_capture_request))
        .unwrap_or_else(|error| panic!("control request should publish: {error}"));
    node_slot.mark_device_io_active();
    let Err(error) = state.on_control_boundary(7) else {
        panic!("an in-flight device must prevent fingerprint projection");
    };

    assert!(error.to_string().contains("device I/O quiesced"));
    assert_eq!(TEST_FINGERPRINT_CAPTURE_COUNT.get(), 0);
    assert_eq!(fingerprint_slot.snapshot(), None);
}

pub(super) extern "C" fn test_clock_deadline_ns() -> i64 {
    TEST_CLOCK_DEADLINE_NS.get()
}
