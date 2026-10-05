//! Exercises the real mapped ACK handshake with the isolated poll cap.

use super::*;
use crucible::Icount;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

fn fixture<T>(result: Result<T, impl std::fmt::Debug>) -> T {
    result.unwrap_or_else(|error| panic!("ACK fixture setup failed: {error:?}"))
}

fn mapped_runtime() -> (MappedSetupRegion, QemuLiveHostIoRuntime, UnixStream) {
    let allocation = fixture(crucible_shmem::RegionAllocation::new_model(
        crucible_shmem::RegionConfig::new(1, 2),
    ));
    let layout = allocation.layout();
    let mut shmem = std::fs::File::from(fixture(crate::spawn::memfd_region(layout.region_size)));
    fixture(shmem.write_all(&fixture(allocation.setup_region_bytes())));
    let (notifications, wake) = fixture(UnixStream::pair());
    fixture(notifications.set_read_timeout(Some(Duration::from_secs(1))));
    let plugin = fixture(crucible_shmem::mmap_setup_region(
        shmem.as_fd(),
        layout.region_size,
    ));
    let slot = fixture(plugin.node_slot(0));
    fixture(slot.arm_external_state_restore_ceiling(40));
    fixture(slot.publish_reached_icount(40));
    let runtime = fixture(QemuLiveHostIoRuntime::from_shmem_fd(
        shmem.as_fd(),
        wake.as_fd(),
        layout.region_size,
        0,
    ));
    (plugin, runtime, notifications)
}

#[test]
fn ack_poll_cap_preserves_real_publication_and_discovery_interval() {
    for short_poll in [false, true] {
        let (plugin, mut runtime, mut notifications) = mapped_runtime();
        if short_poll {
            runtime.use_short_clamp_ack_poll_for_test();
        }
        let expected_interval = Duration::from_micros(if short_poll { 100 } else { 1000 });
        assert_eq!(runtime.poll_interval, Duration::from_millis(1));
        assert_eq!(
            runtime.clamp_ack_poll_interval(Duration::from_secs(1)),
            expected_interval
        );
        assert_eq!(
            runtime.clamp_ack_poll_interval(Duration::from_micros(50)),
            Duration::from_micros(50)
        );

        let host =
            std::thread::spawn(move || runtime.fence_priming_handoff(Duration::from_secs(1)));
        let mut counter = [0_u8; 8];
        fixture(notifications.read_exact(&mut counter));
        assert_eq!(u64::from_ne_bytes(counter), 1);
        let slot = fixture(plugin.node_slot(0));
        let requested = slot.snapshot();
        assert_eq!(requested.control_boundary_ack & 1, 0);
        assert_eq!(requested.max_advance_icount, 40);
        fixture(slot.publish_idle(40, 40));
        fixture(slot.publish_control_boundary(40, 0));
        slot.acknowledge_control_boundary();

        fixture(fixture(host.join()));
        let settled = slot.snapshot();
        assert_eq!(
            settled.control_boundary_ack,
            requested.control_boundary_ack + 1
        );
        assert_eq!(settled.current_icount, 40);
        assert_eq!(settled.max_advance_icount, 40);
        assert_eq!(settled.idle_wake_icount, 40);
    }
}

#[test]
fn ack_poll_cap_does_not_accept_an_absent_ack_or_extend_expired_guard() {
    let (plugin, mut runtime, _notifications) = mapped_runtime();
    runtime.use_short_clamp_ack_poll_for_test();

    let result = runtime.fence_priming_handoff(Duration::ZERO);

    let error = result
        .err()
        .unwrap_or_else(|| panic!("missing ACK was accepted"));
    assert!(error.to_string().contains("requested token"));
    assert!(error.to_string().contains("within 0ns"));
    let refused = fixture(plugin.node_slot(0)).snapshot();
    assert_eq!(refused.control_boundary_ack & 1, 0);
    assert_eq!(refused.current_icount, 40);
    assert_eq!(refused.max_advance_icount, 40);
}

#[test]
fn mapped_settled_clamp_keeps_coordinates_across_idle_publication_phases() {
    let (plugin, runtime, _notifications) = mapped_runtime();
    let slot = fixture(plugin.node_slot(0));
    fixture(slot.publish_idle(40, 200));
    let generation = fixture(slot.request_control_boundary(0, None));
    fixture(slot.publish_control_boundary(40, 0));
    slot.acknowledge_control_boundary();
    let snapshot = || fixture(runtime.region.node_slot(0)).snapshot();

    let idle_snapshot = snapshot();
    assert_eq!(
        idle_snapshot.control_boundary_ack,
        generation.wrapping_add(1)
    );
    assert!(completed_quantum_clamp_is_settled(
        true,
        true,
        40,
        200,
        false,
        &idle_snapshot
    ));
    let idle = crate::quantum::idle_state_from_snapshot(idle_snapshot);
    assert_eq!(idle.next_deadline, Some(Icount { retired: 200 }));

    slot.mark_running();
    let running_snapshot = snapshot();
    assert!(completed_quantum_clamp_is_settled(
        true,
        true,
        40,
        200,
        false,
        &running_snapshot
    ));
    let running = crate::quantum::idle_state_from_snapshot(running_snapshot);
    assert_eq!(running.next_deadline, None);

    fixture(slot.publish_idle(40, 180));
    let tightened_snapshot = snapshot();
    assert!(completed_quantum_clamp_is_settled(
        true,
        true,
        40,
        200,
        false,
        &tightened_snapshot
    ));
    assert_eq!(
        crate::quantum::idle_state_from_snapshot(tightened_snapshot).next_deadline,
        Some(Icount { retired: 180 })
    );

    for observed in [idle_snapshot, running_snapshot, tightened_snapshot] {
        assert_eq!(observed.current_icount, 40);
        assert_eq!(observed.logical_time_raw_icount, 0);
        assert_eq!(observed.max_advance_icount, 40);
        assert_eq!(observed.control_boundary_ack, generation.wrapping_add(1));
        assert_eq!(observed.device_io_active, 0);
    }
    assert_eq!(
        running_snapshot.idle_wake_icount,
        idle_snapshot.idle_wake_icount
    );
}
