//! Unit tests for the production host-I/O checkpoint boundary.

use super::*;

#[test]
fn bounded_poll_attempts_is_at_least_one() {
    assert_eq!(
        bounded_poll_attempts(Duration::ZERO, Duration::from_millis(1)),
        1
    );
    assert_eq!(
        bounded_poll_attempts(Duration::from_micros(1), Duration::from_millis(1)),
        1
    );
}

#[test]
fn bounded_poll_attempts_divides_the_budget() {
    assert_eq!(
        bounded_poll_attempts(Duration::from_millis(10), Duration::from_millis(1)),
        10
    );
    assert_eq!(
        bounded_poll_attempts(Duration::from_millis(1), Duration::from_micros(250)),
        4
    );
}

#[test]
fn bounded_poll_attempts_tolerates_a_zero_interval() {
    assert_eq!(
        bounded_poll_attempts(Duration::from_millis(1), Duration::ZERO),
        1000
    );
}

#[test]
fn unacknowledged_device_wake_invalidates_an_idle_snapshot() {
    let idle = crate::QemuNodeIdleState {
        current_icount: crucible::Icount { retired: 40 },
        next_deadline: Some(crucible::Icount { retired: 200 }),
    };

    assert_eq!(
        classify_after_host_wake(&idle, 100, false),
        QuantumBoundary::Paused {
            at: 40,
            deadline: 200,
        }
    );
    assert_eq!(
        classify_after_host_wake(&idle, 100, true),
        QuantumBoundary::Pending
    );
}

#[test]
fn unacknowledged_device_wake_preserves_a_reached_boundary() {
    let idle = crate::QemuNodeIdleState {
        current_icount: crucible::Icount { retired: 100 },
        next_deadline: Some(crucible::Icount { retired: 200 }),
    };

    assert_eq!(
        classify_after_host_wake(&idle, 100, true),
        QuantumBoundary::Reached { icount: 100 }
    );
}

#[test]
fn unobserved_scheduler_input_invalidates_a_future_idle_boundary() {
    let idle = crate::QemuNodeIdleState {
        current_icount: crucible::Icount { retired: 40 },
        next_deadline: Some(crucible::Icount { retired: 200 }),
    };

    assert_eq!(
        classify_after_scheduler_and_host_wake(&idle, 100, true, false),
        QuantumBoundary::Pending,
    );
    assert_eq!(
        classify_after_scheduler_and_host_wake(&idle, 100, false, false),
        QuantumBoundary::Paused {
            at: 40,
            deadline: 200,
        },
    );
}

#[test]
fn advance_requires_a_plugin_publication_after_a_device_wake() {
    let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
    let initial = slot.snapshot();
    assert!(device_wake_publication_is_unobserved(
        Some(initial.publish_gen),
        &initial,
    ));

    slot.publish_control_boundary(0, 0, 0)
        .unwrap_or_else(|error| panic!("control boundary should publish: {error}"));
    let published = slot.snapshot();
    assert!(!device_wake_publication_is_unobserved(
        Some(initial.publish_gen),
        &published,
    ));

    assert!(!device_wake_publication_is_unobserved(None, &initial));
}

#[test]
fn advance_rejects_checkpoint_idle_until_qemu_releases_it() {
    let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
    slot.arm_external_state_restore_ceiling(200)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot.publish_idle(40, 40, 0)
        .unwrap_or_else(|error| panic!("checkpoint idle should publish: {error}"));
    let checkpoint_idle = slot.snapshot();
    let coordinate = checkpoint_idle_coordinate(&checkpoint_idle);
    assert_eq!(coordinate, Some(40));
    assert!(checkpoint_idle_publication_is_unreleased(
        coordinate,
        &checkpoint_idle,
    ));

    slot.publish_idle(40, 200, 0)
        .unwrap_or_else(|error| panic!("future idle should publish: {error}"));
    assert!(!checkpoint_idle_publication_is_unreleased(
        coordinate,
        &slot.snapshot(),
    ));
}

#[test]
fn advance_accepts_future_idle_without_a_generation_fence() {
    let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
    slot.arm_external_state_restore_ceiling(200)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot.publish_idle(40, 200, 0)
        .unwrap_or_else(|error| panic!("future idle should publish: {error}"));
    let future_idle = slot.snapshot();

    assert_eq!(checkpoint_idle_coordinate(&future_idle), None);
    assert!(!checkpoint_idle_publication_is_unreleased(
        None,
        &future_idle,
    ));
}

#[test]
fn checkpoint_pause_wakes_reached_boundary_but_not_device_idle_waiter() {
    let running_slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
    running_slot
        .arm_external_state_restore_ceiling(200)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    running_slot
        .publish_reached_icount(40, 0)
        .unwrap_or_else(|error| panic!("test progress should publish: {error}"));
    let running = running_slot.snapshot();
    assert!(checkpoint_pause_requires_control_doorbell(&running, true));

    let idle_slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
    idle_slot
        .arm_external_state_restore_ceiling(200)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    idle_slot
        .publish_idle(40, 200, 0)
        .unwrap_or_else(|error| panic!("test idle should publish: {error}"));
    let idle = idle_slot.snapshot();
    assert!(!checkpoint_pause_requires_control_doorbell(&idle, true));
    assert!(checkpoint_pause_requires_control_doorbell(&idle, false));

    idle_slot
        .publish_idle(40, 40, 0)
        .unwrap_or_else(|error| panic!("test zero-length idle should publish: {error}"));
    let zero_length_idle = idle_slot.snapshot();
    assert!(checkpoint_pause_requires_control_doorbell(
        &zero_length_idle,
        true
    ));
}

#[test]
fn advance_accepts_its_control_acknowledgement_and_later_serials() {
    let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
    let request = slot
        .request_control_boundary()
        .unwrap_or_else(|error| panic!("control request should publish: {error}"));
    slot.publish_control_boundary(0, 0, 0)
        .unwrap_or_else(|error| panic!("control boundary should publish: {error}"));
    slot.acknowledge_control_boundary();
    let acknowledged_with_publication = slot.snapshot();

    let mut later_acknowledgement = acknowledged_with_publication;
    later_acknowledgement.control_boundary_ack = request.wrapping_add(3);
    assert!(control_boundary_request_is_acknowledged(
        request,
        &later_acknowledgement,
    ));

    let mut stale_acknowledgement = acknowledged_with_publication;
    stale_acknowledgement.control_boundary_ack = request.wrapping_sub(1);
    assert!(!control_boundary_request_is_acknowledged(
        request,
        &stale_acknowledgement,
    ));
}

#[test]
fn control_acknowledgement_order_wraps_without_accepting_stale_serials() {
    let mut snapshot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM).snapshot();
    snapshot.control_boundary_ack = 1;
    assert!(control_boundary_request_is_acknowledged(0, &snapshot));

    snapshot.control_boundary_ack = u32::MAX;
    assert!(!control_boundary_request_is_acknowledged(0, &snapshot));
}

#[test]
fn completed_clamp_accepts_preserved_future_idle_deadline() {
    let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
    slot.arm_external_state_restore_ceiling(200)
        .unwrap_or_else(|error| panic!("idle ceiling should publish: {error}"));
    slot.publish_idle(40, 200, 0)
        .unwrap_or_else(|error| panic!("idle state should publish: {error}"));
    slot.publish_scheduler_ceiling(
        authorize_advance_ceiling(40, 40, None)
            .unwrap_or_else(|error| panic!("clamp should authorize: {error}")),
    )
    .unwrap_or_else(|error| panic!("clamp should publish: {error}"));
    let snapshot = slot.snapshot();

    assert!(completed_quantum_clamp_is_settled(
        true, 40, 200, false, &snapshot,
    ));
    assert!(completed_quantum_clamp_is_settled(
        true, 40, 40, false, &snapshot,
    ));

    slot.publish_idle(40, 180, 0)
        .unwrap_or_else(|error| panic!("tightened idle state should publish: {error}"));
    assert!(completed_quantum_clamp_is_settled(
        true,
        40,
        200,
        false,
        &slot.snapshot(),
    ));

    slot.publish_idle(40, 201, 0)
        .unwrap_or_else(|error| panic!("extended idle state should publish: {error}"));
    assert!(!completed_quantum_clamp_is_settled(
        true,
        40,
        200,
        false,
        &slot.snapshot(),
    ));

    slot.publish_idle(40, 40, 0)
        .unwrap_or_else(|error| panic!("current idle state should publish: {error}"));
    assert!(!completed_quantum_clamp_is_settled(
        true,
        40,
        200,
        false,
        &slot.snapshot(),
    ));

    slot.publish_idle(40, 180, 0)
        .unwrap_or_else(|error| panic!("retained idle state should publish: {error}"));
    slot.mark_running();
    assert!(completed_quantum_clamp_is_settled(
        true,
        40,
        200,
        false,
        &slot.snapshot(),
    ));

    slot.arm_external_state_restore_ceiling(41)
        .unwrap_or_else(|error| panic!("extended ceiling should publish: {error}"));
    assert!(!completed_quantum_clamp_is_settled(
        true,
        40,
        200,
        false,
        &slot.snapshot(),
    ));
}

#[test]
fn completed_clamp_rejects_unacknowledged_or_active_boundary() {
    let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
    let snapshot = slot.snapshot();

    assert!(completed_quantum_clamp_is_settled(
        true, 0, 0, false, &snapshot,
    ));
    assert!(!completed_quantum_clamp_is_settled(
        false, 0, 0, false, &snapshot,
    ));
    assert!(!completed_quantum_clamp_is_settled(
        true, 0, 0, true, &snapshot,
    ));

    slot.publish_idle(0, 10, 0)
        .unwrap_or_else(|error| panic!("fresh idle deadline should publish: {error}"));
    assert!(completed_quantum_clamp_is_settled(
        true,
        0,
        0,
        false,
        &slot.snapshot(),
    ));
}

#[test]
fn completed_clamp_uses_current_coordinate_after_device_progress() {
    let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
    slot.arm_external_state_restore_ceiling(200)
        .unwrap_or_else(|error| panic!("idle ceiling should publish: {error}"));
    slot.publish_idle(40, 200, 0)
        .unwrap_or_else(|error| panic!("idle state should publish: {error}"));
    slot.publish_scheduler_ceiling(
        authorize_advance_ceiling(40, 40, None)
            .unwrap_or_else(|error| panic!("clamp should authorize: {error}")),
    )
    .unwrap_or_else(|error| panic!("clamp should publish: {error}"));
    slot.mark_running();
    slot.publish_control_boundary(40, 40, 0)
        .unwrap_or_else(|error| panic!("post-device boundary should publish: {error}"));
    let snapshot = slot.snapshot();

    assert!(completed_quantum_clamp_is_settled(
        true, 40, 40, false, &snapshot,
    ));
    assert!(!completed_quantum_clamp_is_settled(
        true, 40, 200, false, &snapshot,
    ));

    slot.publish_idle(40, 180, 0)
        .unwrap_or_else(|error| panic!("fresh post-device deadline should publish: {error}"));
    assert!(completed_quantum_clamp_is_settled(
        true,
        40,
        40,
        false,
        &slot.snapshot(),
    ));
}
