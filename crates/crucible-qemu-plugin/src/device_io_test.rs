//! Tests extracted from the adjacent production module.

use super::*;

use crucible_shmem::{KIND_VM, NodeSlot};

#[test]
fn device_io_submit_sets_active_before_return_and_increments_pending() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();

    let token = begin_submit(&mut freeze, &slot, 40);

    assert_eq!(token.owner_id(), freeze.owner_id());
    assert_eq!(token.request_seq(), 0);
    assert_eq!(token.submit_icount(), 40);
    assert_eq!(freeze.pending_requests(), 1);
    assert!(!freeze.burst_active());
    assert!(freeze.is_tick_hold_active(&slot));
    assert_eq!(slot.snapshot().device_io_active, 1);
}

#[test]
fn device_io_completion_clears_single_request_hold() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let token = begin_submit(&mut freeze, &slot, 50);
    let before_wake = slot.snapshot().wake_signal;

    let release = complete_request(&mut freeze, &slot, token);

    assert_eq!(release.owner_id(), freeze.owner_id());
    assert_eq!(release.request_seq(), 0);
    assert_eq!(release.submit_icount(), 50);
    assert_eq!(release.pending_requests(), 0);
    assert_eq!(release.outcome(), DeviceIoRequestOutcome::Completed);
    assert!(!release.burst_active());
    assert!(!release.device_io_active());
    assert!(release.release_wake().is_some());
    assert!(!freeze.is_tick_hold_active(&slot));
    let snapshot = slot.snapshot();
    assert_eq!(snapshot.device_io_active, 0);
    assert_eq!(snapshot.wake_signal, before_wake.wrapping_add(1));
}

#[test]
fn device_io_failure_releases_the_same_pending_counter() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let token = begin_submit(&mut freeze, &slot, 60);
    let before_wake = slot.snapshot().wake_signal;

    let release = fail_request(&mut freeze, &slot, token);

    assert_eq!(release.pending_requests(), 0);
    assert_eq!(release.outcome(), DeviceIoRequestOutcome::Failed);
    assert!(!release.device_io_active());
    assert!(release.release_wake().is_some());
    let snapshot = slot.snapshot();
    assert_eq!(snapshot.device_io_active, 0);
    assert_eq!(snapshot.wake_signal, before_wake.wrapping_add(1));
}

#[test]
fn device_io_burst_holds_flag_until_burst_done() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();

    let started = match freeze.begin_burst(&slot) {
        Ok(state) => state,
        Err(error) => panic!("burst should start: {error}"),
    };
    assert_eq!(started.pending_requests(), 0);
    assert!(started.burst_active());
    assert!(started.device_io_active());
    assert_eq!(started.release_wake(), None);

    let first = begin_submit(&mut freeze, &slot, 70);
    let second = begin_submit(&mut freeze, &slot, 70);
    assert_eq!(freeze.pending_requests(), 2);

    let first_release = complete_request(&mut freeze, &slot, first);
    assert_eq!(first_release.pending_requests(), 1);
    assert!(first_release.device_io_active());
    assert_eq!(first_release.release_wake(), None);

    let second_release = complete_request(&mut freeze, &slot, second);
    assert_eq!(second_release.pending_requests(), 0);
    assert!(second_release.burst_active());
    assert!(second_release.device_io_active());
    assert_eq!(second_release.release_wake(), None);
    assert!(freeze.is_tick_hold_active(&slot));
    let before_done_wake = slot.snapshot().wake_signal;

    let done = match freeze.burst_done(&slot) {
        Ok(state) => state,
        Err(error) => panic!("burst_done should release an answered burst: {error}"),
    };
    assert_eq!(done.pending_requests(), 0);
    assert!(!done.burst_active());
    assert!(!done.device_io_active());
    assert!(done.release_wake().is_some());
    assert!(!freeze.is_tick_hold_active(&slot));
    let snapshot = slot.snapshot();
    assert_eq!(snapshot.device_io_active, 0);
    assert_eq!(snapshot.wake_signal, before_done_wake.wrapping_add(1));
}

#[test]
fn device_io_burst_done_rejects_pending_requests_and_keeps_flag_active() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    if let Err(error) = freeze.begin_burst(&slot) {
        panic!("burst should start: {error}");
    }
    let _token = begin_submit(&mut freeze, &slot, 80);

    assert_eq!(
        freeze.burst_done(&slot),
        Err(DeviceIoFreezeError::BurstDoneWithPendingRequests {
            pending_requests: 1,
        })
    );
    assert!(freeze.burst_active());
    assert_eq!(freeze.pending_requests(), 1);
    assert!(freeze.is_tick_hold_active(&slot));
    assert_eq!(slot.snapshot().device_io_active, 1);
}

#[test]
fn device_io_foreign_token_with_target_pending_is_fail_loud() {
    let source_slot = NodeSlot::new(KIND_VM);
    let target_slot = NodeSlot::new(KIND_VM);
    let mut source = PluginDeviceIoFreeze::new();
    let mut target = PluginDeviceIoFreeze::new();
    let token = begin_submit(&mut source, &source_slot, 90);
    let _target_token = begin_submit(&mut target, &target_slot, 91);

    assert_eq!(
        target.complete_request(&target_slot, token),
        Err(DeviceIoFreezeError::CompletionForDifferentFreezeState {
            expected_owner_id: target.owner_id(),
            actual_owner_id: source.owner_id(),
            request_seq: 0,
            submit_icount: 90,
            outcome: DeviceIoRequestOutcome::Completed,
        })
    );
    assert_eq!(target.pending_requests(), 1);
    assert_eq!(target_slot.snapshot().device_io_active, 1);
}

#[test]
fn device_io_completion_without_matching_pending_request_is_fail_loud() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let token = DeviceIoRequestToken {
        owner_id: freeze.owner_id(),
        request_seq: 17,
        submit_icount: 90,
        burst_member: false,
    };

    assert_eq!(
        freeze.complete_request(&slot, token),
        Err(DeviceIoFreezeError::CompletionWithoutPendingRequest {
            request_seq: 17,
            submit_icount: 90,
            outcome: DeviceIoRequestOutcome::Completed,
        })
    );
    assert_eq!(freeze.pending_requests(), 0);
    assert_eq!(slot.snapshot().device_io_active, 0);
}

#[test]
fn device_io_counter_overflow_does_not_publish_active_flag() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze {
        owner_id: 4242,
        pending_requests: u32::MAX,
        burst_pending_requests: 0,
        burst_active: false,
        next_request_seq: 0,
    };

    assert_eq!(
        freeze.begin_submit(&slot, 100),
        Err(DeviceIoFreezeError::PendingCounterOverflow {
            pending_requests: u32::MAX,
        })
    );
    assert_eq!(slot.snapshot().device_io_active, 0);
}

#[test]
fn device_io_sequence_overflow_does_not_publish_active_flag() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze {
        owner_id: 4243,
        pending_requests: 0,
        burst_pending_requests: 0,
        burst_active: false,
        next_request_seq: u64::MAX,
    };

    assert_eq!(
        freeze.begin_submit(&slot, 110),
        Err(DeviceIoFreezeError::RequestSequenceOverflow {
            next_request_seq: u64::MAX,
        })
    );
    assert_eq!(freeze.pending_requests(), 0);
    assert_eq!(slot.snapshot().device_io_active, 0);
}

#[test]
fn independent_request_keeps_hold_after_unrelated_burst_finishes() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    freeze
        .begin_burst(&slot)
        .unwrap_or_else(|error| panic!("burst should start: {error}"));
    let burst_request = begin_submit(&mut freeze, &slot, 120);
    let independent = freeze
        .begin_independent_submit(&slot, 121)
        .unwrap_or_else(|error| panic!("independent request should submit: {error}"));

    let burst_release = complete_request(&mut freeze, &slot, burst_request);
    assert_eq!(burst_release.pending_requests(), 1);
    let burst_done = freeze
        .burst_done(&slot)
        .unwrap_or_else(|error| panic!("answered burst should finish: {error}"));
    assert_eq!(burst_done.pending_requests(), 1);
    assert!(!burst_done.burst_active());
    assert!(burst_done.device_io_active());
    assert_eq!(burst_done.release_wake(), None);

    let independent_release = complete_request(&mut freeze, &slot, independent);
    assert_eq!(independent_release.pending_requests(), 0);
    assert!(!independent_release.device_io_active());
    assert!(independent_release.release_wake().is_some());
}

fn begin_submit(
    freeze: &mut PluginDeviceIoFreeze,
    slot: &NodeSlot,
    submit_icount: u64,
) -> DeviceIoRequestToken {
    match freeze.begin_submit(slot, submit_icount) {
        Ok(token) => token,
        Err(error) => panic!("device I/O submit should begin: {error}"),
    }
}

fn complete_request(
    freeze: &mut PluginDeviceIoFreeze,
    slot: &NodeSlot,
    token: DeviceIoRequestToken,
) -> DeviceIoRequestRelease {
    match freeze.complete_request(slot, token) {
        Ok(release) => release,
        Err(error) => panic!("device I/O completion should release: {error}"),
    }
}

fn fail_request(
    freeze: &mut PluginDeviceIoFreeze,
    slot: &NodeSlot,
    token: DeviceIoRequestToken,
) -> DeviceIoRequestRelease {
    match freeze.fail_request(slot, token) {
        Ok(release) => release,
        Err(error) => panic!("device I/O failure should release: {error}"),
    }
}
