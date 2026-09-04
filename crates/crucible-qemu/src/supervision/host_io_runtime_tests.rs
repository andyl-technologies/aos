//! Unit tests for the production host-I/O checkpoint boundary.

use super::*;

/// Builds the real mapped host runtime after exercising lossless event retry.
pub(crate) fn staged_fault_event_runtime(
    event: DequeuedFaultEvent,
) -> Result<QemuLiveHostIoRuntime, Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::os::fd::AsFd;

    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 4, 0))?;
    let layout = allocation.layout();
    let bytes = allocation.setup_region_bytes()?;
    let mut shmem = tempfile::tempfile()?;
    shmem.set_len(layout.region_size)?;
    shmem.write_all(&bytes)?;
    {
        let mut producer = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let transport = producer.fault_event_transport_mut(0)?;
        crucible_shmem::enqueue_fault_event(
            transport.ring,
            transport.slots,
            transport.arena_header,
            transport.arena,
            transport.arena_region_offset,
            event.header,
            &event.payload,
        )?;
    }
    let wake = tempfile::tempfile()?;
    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd_with_poll_interval(
        shmem.as_fd(),
        wake.as_fd(),
        layout.region_size,
        0,
        Duration::from_millis(1),
    )?;
    let timeout = Duration::from_secs(1);

    let rejected = runtime.drain_fault_events_for_pump(
        0,
        &HostSupervisionDeadline::start(timeout),
        timeout,
        "test rejected host fault-event drain",
    );
    let Err(error) = rejected else {
        panic!("zero-capacity drain should reject");
    };
    assert_eq!(
        error.fault_event_storage_coordinates(),
        Some((0, 1, HARD_FAULT_EVENT_CAPACITY as u64))
    );
    assert!(runtime.staged_fault_events.is_empty());

    runtime.drain_fault_events_for_pump(
        1,
        &HostSupervisionDeadline::start(timeout),
        timeout,
        "test admitted host fault-event drain",
    )?;
    assert_eq!(runtime.staged_fault_events.len(), 1);
    Ok(runtime)
}

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
fn preparation_result_is_admitted_before_exact_storage_allocation() {
    assert_eq!(fault_result::admit_fault_preparation_result(31, 31), Ok(()));
    assert_eq!(
        fault_result::admit_fault_preparation_result(32, 31),
        Err(QemuAsyncDriverRuntimeError::fault_result_storage(32, 31))
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
fn fault_result_publication_waits_for_the_full_control_pump() {
    let slot = crucible_shmem::NodeSlot::new(crucible_shmem::KIND_VM);
    let request = slot
        .request_control_boundary()
        .unwrap_or_else(|error| panic!("control request should publish: {error}"));

    // A result can become visible while the plugin is still translating the
    // paired QEMU occurrence event. The even request token remains unacknowledged
    // throughout that window and must not be treated as a completed pump.
    assert!(!control_boundary_request_is_acknowledged(
        request,
        &slot.snapshot(),
    ));

    slot.publish_control_boundary(0, 0, 0)
        .unwrap_or_else(|error| panic!("control boundary should publish: {error}"));
    slot.acknowledge_control_boundary();
    assert!(control_boundary_request_is_acknowledged(
        request,
        &slot.snapshot(),
    ));
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

#[cfg(target_os = "linux")]
struct TestBlockCoordinator;

#[cfg(target_os = "linux")]
impl QemuBlockFaultCoordinator for TestBlockCoordinator {
    fn apply_boundary_actions(
        &mut self,
        _servicer: &mut QemuLiveBlockIoServicer,
        _coordinate: crucible::model::FaultCoordinate,
        _evaluation_sequence: u64,
        _actions: &[crucible::model::ResolvedBindingAction],
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    fn service_block_io(
        &mut self,
        servicer: &mut QemuLiveBlockIoServicer,
        guest_icount: u64,
    ) -> Result<crate::QemuLiveBlockIoServiceStep, QemuAsyncDriverRuntimeError> {
        servicer.service(guest_icount).map_err(|source| {
            QemuAsyncDriverRuntimeError::new("test block coordinator", source.to_string())
        })
    }
}

#[cfg(target_os = "linux")]
struct TestNinepCoordinator;

#[cfg(target_os = "linux")]
impl QemuNinepFaultCoordinator for TestNinepCoordinator {
    fn service_ninep_io(
        &mut self,
        servicer: &mut QemuLive9pIoServicer,
        guest_icount: u64,
    ) -> Result<crate::QemuLive9pIoServiceStep, QemuAsyncDriverRuntimeError> {
        servicer.service(guest_icount).map_err(|source| {
            QemuAsyncDriverRuntimeError::new("test 9p coordinator", source.to_string())
        })
    }
}

#[cfg(target_os = "linux")]
fn private_region_pair() -> Result<(std::fs::File, std::fs::File, u64), Box<dyn std::error::Error>>
{
    use std::io::Write;

    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 4, 0))?;
    let layout = allocation.layout();
    let bytes = allocation.setup_region_bytes()?;
    let mut source = tempfile::tempfile()?;
    source.set_len(layout.region_size)?;
    source.write_all(&bytes)?;
    let mut child = tempfile::tempfile()?;
    child.set_len(layout.region_size)?;
    child.write_all(&bytes)?;
    Ok((source, child, layout.region_size))
}

#[cfg(target_os = "linux")]
#[test]
fn hot_fork_clone_reconstructs_private_host_devices_without_aliasing_source()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::fd::AsFd;

    let (source_region, child_region, region_len) = private_region_pair()?;
    let source_wake = tempfile::tempfile()?;
    let child_wake = tempfile::tempfile()?;
    let block =
        QemuLiveBlockIoServicer::from_shmem_fd(source_region.as_fd(), region_len, 0, 0, 16 * 1024)?;
    let ninep = QemuLive9pIoServicer::from_shmem_fd(source_region.as_fd(), region_len, 0, 0)?;
    let accelerator =
        QemuLiveAcceleratorServicer::from_shmem_fd(source_region.as_fd(), region_len, 0)?;
    let mut source = QemuLiveHostIoRuntime::from_shmem_fd(
        source_region.as_fd(),
        source_wake.as_fd(),
        region_len,
        0,
    )?
    .with_block_servicer(block, BlockIoDiagnostics::shared())?
    .with_ninep_servicer(ninep, NinepIoDiagnostics::shared())
    .with_accelerator_servicer(accelerator);
    let binding = ContentHash::from_bytes(b"branch-private-host-io");
    let before = source.checkpoint_host_io(binding)?;
    let source_block = source
        .shared_block_device()
        .ok_or("source block device should be present")?;

    let mut child = source.clone_hot_fork_host_io_continuation(
        binding,
        child_region.as_fd(),
        child_wake.as_fd(),
        region_len,
        None,
    )?;

    assert_eq!(source.checkpoint_host_io(binding)?, before);
    assert_eq!(child.checkpoint_host_io(binding)?, before);
    let child_block = child
        .shared_block_device()
        .ok_or("child block device should be present")?;
    assert!(!source_block.ptr_eq(&child_block));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn hot_fork_clone_requires_fresh_branch_local_fault_coordinator()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::fd::AsFd;

    let (source_region, child_region, region_len) = private_region_pair()?;
    let source_wake = tempfile::tempfile()?;
    let child_wake = tempfile::tempfile()?;
    let block =
        QemuLiveBlockIoServicer::from_shmem_fd(source_region.as_fd(), region_len, 0, 0, 16 * 1024)?;
    let mut source = QemuLiveHostIoRuntime::from_shmem_fd(
        source_region.as_fd(),
        source_wake.as_fd(),
        region_len,
        0,
    )?
    .with_block_servicer(block, BlockIoDiagnostics::shared())?;
    source.install_block_fault_coordinator(Box::new(TestBlockCoordinator))?;
    let binding = ContentHash::from_bytes(b"coordinator-isolation");
    let mut child = source.clone_hot_fork_host_io_continuation(
        binding,
        child_region.as_fd(),
        child_wake.as_fd(),
        region_len,
        None,
    )?;
    let coordinate = crucible::model::FaultCoordinate {
        virtual_nanos: 0,
        retired_instructions: Some(0),
    };

    assert!(
        child
            .apply_block_boundary_actions(coordinate, 0, &[])
            .is_err()
    );
    child.install_block_fault_coordinator(Box::new(TestBlockCoordinator))?;
    child.apply_block_boundary_actions(coordinate, 0, &[])?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn hot_fork_clone_does_not_fall_back_to_uncoordinated_ninep_service()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::fd::AsFd;

    let (source_region, child_region, region_len) = private_region_pair()?;
    let source_wake = tempfile::tempfile()?;
    let child_wake = tempfile::tempfile()?;
    let ninep = QemuLive9pIoServicer::from_shmem_fd(source_region.as_fd(), region_len, 0, 0)?;
    let mut source = QemuLiveHostIoRuntime::from_shmem_fd(
        source_region.as_fd(),
        source_wake.as_fd(),
        region_len,
        0,
    )?
    .with_ninep_servicer(ninep, NinepIoDiagnostics::shared());
    source.install_ninep_fault_coordinator(Box::new(TestNinepCoordinator))?;
    let mut child = source.clone_hot_fork_host_io_continuation(
        ContentHash::from_bytes(b"ninep-coordinator-isolation"),
        child_region.as_fd(),
        child_wake.as_fd(),
        region_len,
        None,
    )?;

    assert!(
        child
            .await_child(QemuAsyncWait::AdvanceCompletion, Duration::from_millis(1))
            .is_err()
    );
    child.install_ninep_fault_coordinator(Box::new(TestNinepCoordinator))?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn hot_fork_clone_requires_and_accepts_fresh_child_console()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    let (source_region, child_region, region_len) = private_region_pair()?;
    let source_wake = tempfile::tempfile()?;
    let child_wake = tempfile::tempfile()?;
    let (mut source_writer, reader) = UnixStream::pair()?;
    let console = crate::console_observation::QemuConsoleObservationReader::new(
        reader,
        crate::console_observation::QemuConsoleObservationSpool::new(),
    )?;
    let mut source = QemuLiveHostIoRuntime::from_shmem_fd(
        source_region.as_fd(),
        source_wake.as_fd(),
        region_len,
        0,
    )?
    .with_console_observation(console)?;

    let missing = source.clone_hot_fork_host_io_continuation(
        ContentHash::from_bytes(b"unsupported-console"),
        child_region.as_fd(),
        child_wake.as_fd(),
        region_len,
        None,
    );
    assert!(missing.is_err());

    let (mut child_writer, child_reader) = UnixStream::pair()?;
    let child_console = crate::QemuHotForkChildConsoleObservation::from_stream(child_reader)?;
    let child_spool = child_console.spool();
    let mut child = source.clone_hot_fork_host_io_continuation(
        ContentHash::from_bytes(b"branch-private-console"),
        child_region.as_fd(),
        child_wake.as_fd(),
        region_len,
        Some(child_console),
    )?;
    source_writer.write_all(b"source-only")?;
    child_writer.write_all(b"child-only")?;
    let _completion = child.await_child(QemuAsyncWait::AdvanceCompletion, Duration::from_millis(1));
    assert_eq!(child_spool.take()?, b"child-only");
    drop(child);
    Ok(())
}
