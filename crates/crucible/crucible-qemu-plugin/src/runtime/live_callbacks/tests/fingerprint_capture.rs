//! Exact-boundary fingerprint capture callback tests.

use super::*;

#[test]
fn requested_control_callback_captures_and_acknowledges_each_exact_request() {
    let node_slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 350, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    node_slot
        .publish_scheduler_advance(ceiling, crucible_qemu_shmem::AdvanceStopCondition::Ceiling)
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
    let state = test_live_state(80, 1, 0, &node_slot)
        .and_then(|state| attach_test_fingerprint(state, sampling, &fingerprint_slot))
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
    assert_eq!(first_sample.sample_icount, 350);
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
    let ceiling = authorize_advance_ceiling(0, 350, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    node_slot
        .publish_scheduler_advance(ceiling, crucible_qemu_shmem::AdvanceStopCondition::Ceiling)
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
    let state = test_live_state(81, 1, 0, &node_slot)
        .and_then(|state| attach_test_fingerprint(state, sampling, &fingerprint_slot))
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

pub(super) extern "C" fn test_clock_deadline_ps() -> i64 {
    TEST_CLOCK_DEADLINE_PS.get()
}

extern "C" fn capture_unknown_negative_fd(
    out: *mut crate::fingerprint_sampler::QemuFingerprintCaptureV2,
) -> i32 {
    let status = test_fingerprint_capture(out);
    if status != 0 {
        return status;
    }
    -libc::EIO
}

extern "C" fn capture_invalid_schema(
    out: *mut crate::fingerprint_sampler::QemuFingerprintCaptureV2,
) -> i32 {
    let status = test_fingerprint_capture(out);
    if status == 0 {
        // SAFETY: the successful local fixture initialized this complete record.
        unsafe { (*out).schema = 0 };
    }
    status
}

fn local_capture_state(
    slot: &NodeSlot,
    sample_slot: &FingerprintSampleSlot,
    capture: crate::fingerprint_sampler::QemuCaptureFingerprintMaterialFn,
) -> LiveVcpuTimeCallbackState {
    let introspector = crate::PluginVcpuIntrospector::require(
        Some(test_fingerprint_read_vcpu_regs),
        Some(test_fingerprint_read_rr_cursor),
    )
    .unwrap();
    let sampling = crate::fingerprint_sampler::PluginFingerprintSampling::from_test_exports(
        introspector,
        capture,
    );
    attach_test_fingerprint(
        test_live_state(89, 1, 0, slot).unwrap(),
        sampling,
        sample_slot,
    )
    .unwrap()
}

#[test]
fn negative_native_output_is_saved_raw_without_adoption_or_recapture() {
    let slot = NodeSlot::new(KIND_VM);
    let sample_slot = FingerprintSampleSlot::new();
    let state = local_capture_state(&slot, &sample_slot, capture_unknown_negative_fd);
    TEST_FINGERPRINT_CAPTURE_COUNT.set(0);
    let request = sample_slot.request_capture_v1();

    assert!(
        state
            .publish_fingerprint_sample(0, "negative capture fixture", request)
            .is_err()
    );
    let (output, status) = state
        .fingerprint
        .as_ref()
        .unwrap()
        .capture_attempt
        .try_lock()
        .unwrap()
        .fixture_journal();
    assert_eq!(status, Some(-libc::EIO));
    assert!(output.device_fd >= 0);
    assert!(state.capture_material_disposition().is_err());
    assert!(
        state
            .publish_fingerprint_sample(0, "repeat fixture", request)
            .is_err()
    );
    assert_eq!(TEST_FINGERPRINT_CAPTURE_COUNT.get(), 1);
    assert_eq!(sample_slot.snapshot(), None);
    assert_eq!(sample_slot.pending_capture_request_v1(), Some(request));

    drop(state);
    // SAFETY: this deliberately nonconforming fixture created this exact FD.
    // Production neither adopts nor closes it on the negative return. After
    // its local model has dropped, this test alone reclaims that known resource.
    let file = unsafe { File::from_raw_fd(output.device_fd) };
    assert_eq!(file.metadata().unwrap().len(), 1);
    drop(file);
}

#[test]
fn validation_refusal_retains_file_across_all_parent_transfer_gates_and_drop() {
    let slot = NodeSlot::new(KIND_VM);
    let sample_slot = FingerprintSampleSlot::new();
    let state = local_capture_state(&slot, &sample_slot, capture_invalid_schema);
    let request = sample_slot.request_capture_v1();
    TEST_FINGERPRINT_CAPTURE_COUNT.set(0);
    assert!(
        state
            .publish_fingerprint_sample(0, "invalid capture fixture", request)
            .is_err()
    );
    let (output, status) = state
        .fingerprint
        .as_ref()
        .unwrap()
        .capture_attempt
        .try_lock()
        .unwrap()
        .fixture_journal();
    assert_eq!(status, Some(0));
    assert_eq!(output.schema, 0);
    assert!(state.capture_material_disposition().is_err());

    // SAFETY: these calls refuse at the retained capture journal before any
    // worker/Native transfer, so they obtain no artificial parked receipt.
    unsafe {
        assert!(state.hold_fingerprint_workspace().is_err());
        assert!(state.restore_fingerprint_workspace().is_err());
        assert!(state.hold_fingerprint_workspace_for_parent_park().is_err());
        assert!(
            state
                .restore_fingerprint_workspace_for_parent_park()
                .is_err()
        );
    }
    assert!(
        state
            .publish_fingerprint_sample(0, "repeat fixture", request)
            .is_err()
    );
    assert_eq!(TEST_FINGERPRINT_CAPTURE_COUNT.get(), 1);
    drop(state);
    // SAFETY: only this model created/transferred the descriptor, then retained
    // it without close. Reclaiming the forgotten local File claims no Source return.
    let file = unsafe { File::from_raw_fd(output.device_fd) };
    assert_eq!(file.metadata().unwrap().len(), 1);
    drop(file);
}

#[test]
fn closed_worker_keeps_valid_capture_in_callback_and_blocks_a_second_effect() {
    let slot = NodeSlot::new(KIND_VM);
    let sample_slot = FingerprintSampleSlot::new();
    let state = local_capture_state(&slot, &sample_slot, test_fingerprint_capture);
    state
        .fingerprint
        .as_ref()
        .unwrap()
        .worker
        .close_fixture_admission();
    let request = sample_slot.request_capture_v1();
    TEST_FINGERPRINT_CAPTURE_COUNT.set(0);

    assert!(
        state
            .publish_fingerprint_sample(0, "closed queue fixture", request)
            .is_err()
    );
    let fingerprint = state.fingerprint.as_ref().unwrap();
    let mut attempt = fingerprint.capture_attempt.try_lock().unwrap();
    let (output, status) = attempt.fixture_journal();
    assert_eq!(status, Some(0));
    assert!(attempt.pending().is_some());
    drop(attempt);
    assert!(state.capture_material_disposition().is_err());
    assert!(
        state
            .publish_fingerprint_sample(0, "repeat fixture", request)
            .is_err()
    );
    assert_eq!(TEST_FINGERPRINT_CAPTURE_COUNT.get(), 1);
    assert_eq!(sample_slot.snapshot(), None);
    assert_eq!(sample_slot.pending_capture_request_v1(), Some(request));
    drop(state);
    // SAFETY: local fixture-only reclamation of its once-created retained File.
    let file = unsafe { File::from_raw_fd(output.device_fd) };
    assert_eq!(file.metadata().unwrap().len(), 1);
    drop(file);
}

#[test]
fn foreign_creator_refuses_before_the_contended_capture_mutex() {
    let slot = NodeSlot::new(KIND_VM);
    let sample_slot = FingerprintSampleSlot::new();
    let mut state = local_capture_state(&slot, &sample_slot, test_fingerprint_capture);
    let creator = std::process::id();
    state
        .fingerprint
        .as_mut()
        .unwrap()
        .worker
        .set_fixture_creator_process(creator.wrapping_add(1));
    let held = state
        .fingerprint
        .as_ref()
        .unwrap()
        .capture_attempt
        .try_lock()
        .unwrap();
    TEST_FINGERPRINT_CAPTURE_COUNT.set(0);

    assert!(
        matches!(state.fingerprint.as_ref().unwrap().capture_guard(), Err(status) if status == -libc::EPERM)
    );
    assert_eq!(state.capture_material_disposition(), Err(-libc::EPERM));
    // SAFETY: only this local model exists. Wrong-creator rejection must precede
    // the deliberately held capture mutex and every worker/workspace effect.
    unsafe {
        assert_eq!(
            state.hold_fingerprint_workspace_for_parent_park(),
            Err(-libc::EPERM)
        );
        assert_eq!(
            state.restore_fingerprint_workspace_for_parent_park(),
            Err(-libc::EPERM)
        );
        assert!(state.hold_fingerprint_workspace().is_err());
        assert!(state.restore_fingerprint_workspace().is_err());
    }
    assert!(
        state
            .publish_fingerprint_sample(0, "foreign creator fixture", 1)
            .is_err()
    );
    assert_eq!(TEST_FINGERPRINT_CAPTURE_COUNT.get(), 0);

    drop(held);
    // Restore only this local model's actual creator for fixture retirement.
    state
        .fingerprint
        .as_mut()
        .unwrap()
        .worker
        .set_fixture_creator_process(creator);
}
