//! Pending-wait diagnostic bounds and real mapped-transport noninterference.

use std::os::fd::AsFd;

use super::*;

#[test]
fn disabled_and_unadmitted_budgets_never_reserve_a_capture() {
    for maximum in [0, 257, u16::MAX] {
        let mut observation = WaitObservation::with_budget(maximum);
        observation.begin(Duration::from_secs(180));
        assert!(!observation.due(Duration::ZERO));
        assert_eq!(observation.remaining, 0);
    }
}

#[test]
fn short_waits_preserve_budget_for_late_pending_phase_and_rate_limit_it() {
    let mut observation = WaitObservation::with_budget(256);
    for _ in 0..10_000 {
        observation.begin(Duration::from_secs(180));
        assert!(!observation.due(Duration::from_secs(176)));
    }
    assert_eq!(observation.remaining, 256);

    assert!(observation.due(Duration::from_secs(175)));
    assert!(!observation.due(Duration::from_secs(175)));
    assert!(!observation.due(Duration::from_secs(171)));
    assert!(observation.due(Duration::from_secs(170)));
    // A skipped sample is one record, not an unbounded catch-up burst.
    assert!(observation.due(Duration::from_secs(90)));
    assert!(!observation.due(Duration::from_secs(90)));
    assert_eq!(observation.remaining, 253);

    for _ in 0..253 {
        observation.begin(Duration::from_secs(180));
        assert!(observation.due(Duration::from_secs(175)));
    }
    observation.begin(Duration::from_secs(180));
    assert!(!observation.due(Duration::ZERO));
    assert_eq!(observation.remaining, 0);
}

#[test]
fn phase_reset_requires_another_five_seconds_and_small_deadlines_do_not_sample() {
    let mut observation = WaitObservation::with_budget(2);
    observation.begin(Duration::from_secs(180));
    assert!(observation.due(Duration::from_secs(175)));
    observation.begin(Duration::from_secs(180));
    assert!(!observation.due(Duration::from_secs(176)));
    assert!(observation.due(Duration::from_secs(175)));

    let mut short = WaitObservation::with_budget(1);
    short.begin(Duration::from_millis(100));
    assert!(!short.due(Duration::ZERO));
    assert_eq!(short.remaining, 1);
}

#[test]
fn one_second_clamp_reports_once_after_half_budget_and_short_success_preserves_budget() {
    let mut observation = WaitObservation::with_budget(2);
    for _ in 0..10_000 {
        observation.begin_clamp(Duration::from_secs(1));
        assert!(!observation.due(Duration::from_millis(800)));
    }
    assert_eq!(observation.remaining, 2);

    observation.begin_clamp(Duration::from_secs(1));
    assert!(!observation.due(Duration::from_millis(501)));
    assert!(observation.due(Duration::from_millis(500)));
    assert!(!observation.due(Duration::from_millis(499)));
    assert!(!observation.due(Duration::ZERO));
    assert_eq!(observation.remaining, 1);

    // Long clamps retain the existing five-second sampling interval.
    observation.begin_clamp(Duration::from_secs(180));
    assert!(!observation.due(Duration::from_secs(176)));
    assert!(observation.due(Duration::from_secs(175)));
    observation.begin_clamp(Duration::ZERO);
    assert!(!observation.due(Duration::ZERO));
}

#[test]
fn real_advance_wait_keeps_timeout_and_owned_state_with_diagnostics_enabled_or_disabled()
-> Result<(), Box<dyn std::error::Error>> {
    for maximum in [0, 256] {
        let (mut runtime, plugin) = mapped_runtime()?;
        runtime.wait_observation = WaitObservation::with_budget(maximum);
        let ceiling = crucible_shmem::authorize_advance_ceiling(0, 1000, None)?;
        plugin
            .node_slot(0)?
            .publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
        plugin.node_slot(0)?.publish_reached_icount(0)?;
        let original = plugin.node_slot(0)?.snapshot();
        let indices = runtime.wait_ring_indices();
        let result = runtime.poll_advance_completion(Duration::from_millis(10))?;
        assert_eq!(result, crate::QemuAsyncWaitOutcome::TimedOut);
        assert_eq!(plugin.node_slot(0)?.snapshot(), original);
        assert_eq!(runtime.wait_ring_indices(), indices);
        assert_eq!(runtime.wait_observation.remaining, maximum);
    }
    Ok(())
}

#[test]
fn early_renewal_counts_only_original_observed_consumption() {
    let mut observation = WaitObservation::with_budget(2);
    observation.begin(Duration::from_secs(1));
    for _ in 0..10_000 {
        observation.renew(Duration::from_secs(1));
        assert!(!observation.due(Duration::from_secs(1)));
    }
    assert_eq!(observation.consumed_slices, Duration::ZERO);
    assert_eq!(observation.remaining, 2);

    observation.observe_remaining(Duration::from_millis(600));
    observation.renew(Duration::from_secs(1));
    assert_eq!(observation.consumed_slices, Duration::from_millis(400));
    assert!(!observation.due(Duration::ZERO));
    observation.renew(Duration::from_secs(1));
    assert_eq!(observation.consumed_slices, Duration::from_millis(1400));

    observation.begin(Duration::from_secs(1));
    assert_eq!(observation.consumed_slices, Duration::ZERO);
    assert!(!observation.due(Duration::ZERO));
    assert_eq!(observation.remaining, 2);
}

#[test]
fn real_one_second_renewals_sample_pending_advance_without_resetting_cadence()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{QemuAsyncWait, QemuAsyncWaitOutcome, QemuHostIoRuntime};

    let (mut runtime, plugin) = mapped_runtime()?;
    runtime.wait_observation = WaitObservation::with_budget(2);
    let ceiling = crucible_shmem::authorize_advance_ceiling(0, 1000, None)?;
    plugin
        .node_slot(0)?
        .publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
    plugin.node_slot(0)?.publish_reached_icount(0)?;
    let original = plugin.node_slot(0)?.snapshot();
    let indices = runtime.wait_ring_indices();
    let timeout = Duration::from_secs(1);

    // This is the driver's actual await -> TimedOut -> renew -> repoll path.
    for slice in 0..6 {
        let outcome = if slice == 0 {
            runtime.await_child(QemuAsyncWait::AdvanceCompletion, timeout)?
        } else {
            runtime.repoll_child(QemuAsyncWait::AdvanceCompletion, timeout)?
        };
        assert_eq!(outcome, QemuAsyncWaitOutcome::TimedOut);
        if slice < 5 {
            assert_eq!(runtime.wait_observation.remaining, 2);
        }
        runtime.renew_advance_completion_poll(timeout)?;
    }
    assert_eq!(runtime.wait_observation.remaining, 1);
    assert_eq!(plugin.node_slot(0)?.snapshot(), original);
    assert_eq!(runtime.wait_ring_indices(), indices);

    // A new advance resets elapsed sampling without replenishing its lifetime cap.
    assert_eq!(
        runtime.await_child(QemuAsyncWait::AdvanceCompletion, Duration::from_millis(10))?,
        QemuAsyncWaitOutcome::TimedOut,
    );
    assert_eq!(runtime.wait_observation.consumed_slices, Duration::ZERO);
    assert_eq!(runtime.wait_observation.remaining, 1);
    let (new_runtime, _) = mapped_runtime()?;
    assert_eq!(new_runtime.wait_observation.consumed_slices, Duration::ZERO);
    Ok(())
}

#[test]
fn real_short_successes_preserve_the_lifetime_record_budget()
-> Result<(), Box<dyn std::error::Error>> {
    for maximum in [0, 256] {
        let (mut runtime, plugin) = mapped_runtime()?;
        runtime.wait_observation = WaitObservation::with_budget(maximum);
        let ceiling = crucible_shmem::authorize_advance_ceiling(0, 1000, None)?;
        plugin
            .node_slot(0)?
            .publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
        plugin.node_slot(0)?.mark_done();
        let original = plugin.node_slot(0)?.snapshot();

        for _ in 0..100 {
            assert_eq!(
                runtime.poll_advance_completion(Duration::from_secs(1))?,
                crate::QemuAsyncWaitOutcome::Completed,
            );
            assert_eq!(runtime.wait_observation.remaining, maximum);
            assert_eq!(runtime.wait_observation.consumed_slices, Duration::ZERO);
        }
        assert_eq!(plugin.node_slot(0)?.snapshot(), original);
    }
    Ok(())
}

fn mapped_runtime()
-> Result<(QemuLiveHostIoRuntime, crucible_shmem::MappedSetupRegion), Box<dyn std::error::Error>> {
    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 4))?;
    let layout = allocation.layout();
    let mut shmem = std::fs::File::from(crate::spawn::memfd_region(layout.region_size)?);
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let plugin = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let wake = tempfile::tempfile()?;
    let runtime = QemuLiveHostIoRuntime::from_shmem_fd_with_poll_interval(
        shmem.as_fd(),
        wake.as_fd(),
        layout.region_size,
        0,
        Duration::from_millis(1),
    )?;
    Ok((runtime, plugin))
}

#[test]
fn admitted_observation_keeps_original_snapshot_and_all_transport_cursors()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut runtime, mut plugin) = mapped_runtime()?;
    runtime.wait_observation = WaitObservation::with_budget(1);
    runtime.wait_observation.region_inode = Some(1234);
    runtime
        .wait_observation
        .host_published_device_deadline
        .set(Some(3000));
    runtime.scheduler_input_publish_generation = Some(20);
    runtime.device_wake_publish_generation = Some(22);
    plugin.node_slot(0)?.publish_pause_quiesced(1000, 20)?;
    let original = plugin.node_slot(0)?.snapshot();
    let frame = crucible_shmem::FrameEntry::new(1000, 0, 1, b"retained-payload")?;
    {
        let rings = plugin.node_directed_ring_pair_mut(
            0,
            0,
            crucible_shmem::SLOT_NET_ROUTER as u32,
            crucible_shmem::SLOT_NET_ROUTER as u32,
            0,
        )?;
        rings.first.header.enqueue(rings.first.entries, &frame)?;
        rings.second.header.enqueue(rings.second.entries, &frame)?;
    }
    let indices = runtime.wait_ring_indices();
    assert_eq!(indices.tx, Some((0, 1)));
    assert_eq!(indices.rx, Some((0, 1)));
    plugin.node_slot(0)?.publish_pause_quiesced(2000, 40)?;
    let fresh = plugin.node_slot(0)?.snapshot();
    let request = PendingControlBoundary {
        generation: u32::MAX - 1,
        fault_command_frontier: 17,
        fingerprint_capture_request: None,
    };
    let mut bytes = Vec::new();
    let expectation = ClampExpectation {
        request,
        current_ps: 1000,
        idle_ps: 1000,
        acknowledgement_seen: false,
        device_progress: false,
    };
    runtime.emit_pending_wait_to(
        "clamp-ack-pending",
        &original,
        Some(expectation),
        Duration::from_secs(175),
        &mut bytes,
    );
    let record = std::str::from_utf8(&bytes)?;
    assert!(record.starts_with(
        "CRUCIBLE-HOST-WAIT-V1 phase=clamp-ack-pending slot=0 region_inode=Some(1234) "
    ));
    assert!(record.contains("current_ps=1000 "));
    assert!(record.contains("raw_instructions=20 "));
    assert!(record.contains("expected_ack=Some(4294967295) request=Some(4294967294) "));
    assert!(record.contains("scheduler_pending_gen=Some(20) device_pending_gen=Some(22) "));
    assert!(record.contains("host_published_device_deadline_ps=Some(3000) "));
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
    assert!(bytes.len() < 2048);
    assert_eq!(runtime.wait_ring_indices(), indices);
    assert_eq!(plugin.node_slot(0)?.snapshot(), fresh);

    struct ClosedSink;
    impl Write for ClosedSink {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    runtime.emit_pending_wait_to(
        "advance-pending",
        &original,
        None,
        Duration::from_secs(175),
        &mut ClosedSink,
    );
    assert_eq!(runtime.wait_ring_indices(), indices);
    assert_eq!(plugin.node_slot(0)?.snapshot(), fresh);
    Ok(())
}

#[test]
fn largest_scalar_record_stays_within_fixture_line_bound_and_missing_views_are_nonfatal()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut runtime, plugin) = mapped_runtime()?;
    runtime.wait_observation.region_inode = Some(u64::MAX);
    runtime
        .wait_observation
        .host_published_device_deadline
        .set(Some(u64::MAX));
    runtime.scheduler_input_publish_generation = Some(u32::MAX);
    runtime.device_wake_publish_generation = Some(u32::MAX);
    let mut snapshot = plugin.node_slot(0)?.snapshot();
    snapshot.current_icount = u64::MAX;
    snapshot.max_advance_icount = u64::MAX;
    snapshot.idle_wake_icount = u64::MAX;
    snapshot.logical_time_raw_icount = u64::MAX;
    snapshot.status = u8::MAX;
    snapshot.device_io_active = u8::MAX;
    snapshot.publish_gen = u32::MAX;
    snapshot.wake_signal = u32::MAX;
    snapshot.control_boundary_ack = u32::MAX;
    snapshot.control_boundary_fault_command_frontier = u64::MAX;
    snapshot.control_boundary_capture_request = u32::MAX;
    snapshot.advance_publication_sequence = u64::MAX - 1;
    snapshot.advance_stop_condition = u8::MAX;
    runtime.wait_observation = WaitObservation::with_budget(256);
    runtime.wait_observation.region_inode = Some(u64::MAX);
    runtime
        .wait_observation
        .retain_initial_advance(&snapshot, Some(u64::MAX));
    runtime.wait_observation.checkpoint_idle_unreleased = Some(true);
    let clamp = ClampExpectation {
        request: PendingControlBoundary {
            generation: u32::MAX - 1,
            fault_command_frontier: u64::MAX,
            fingerprint_capture_request: Some(u32::MAX),
        },
        current_ps: u64::MAX,
        idle_ps: u64::MAX,
        acknowledgement_seen: false,
        device_progress: false,
    };
    let key = crucible_shmem::FrameDeliveryKey {
        delivery_icount: u64::MAX,
        src_node: u32::MAX,
        seq: u32::MAX,
    };
    runtime.wait_observation.device_deadlines.set(Some(
        super::super::device_wait_observation::DeviceDeadlines {
            block: super::super::device_wait_observation::CompletionCandidate::worker(
                Some(u64::MAX),
                Some((u64::MAX, Some(u32::MAX), u64::MAX, u64::MAX)),
            ),
            ninep: super::super::device_wait_observation::CompletionCandidate::queued(
                Some(u64::MAX),
                Some((key, u32::MAX)),
            ),
            accelerator: Some(u64::MAX),
        },
    ));
    let largest = (u64::MAX, u64::MAX);
    let indices = RingIndices {
        tx: Some(largest),
        rx: Some(largest),
        fault_command: Some(largest),
        fault_event: Some(largest),
        fault_result: Some(largest),
        block: Some((largest, largest)),
        ninep: Some((largest, largest)),
    };
    let mut bytes = Vec::new();
    write_observation(
        &mut bytes,
        &runtime,
        "clamp-ack-pending",
        &snapshot,
        Some(clamp),
        Duration::MAX,
        &indices,
    )?;
    assert!(
        bytes.len() < 2048,
        "maximum clamp row bytes={}",
        bytes.len()
    );
    bytes.clear();
    write_observation(
        &mut bytes,
        &runtime,
        "advance-pending",
        &snapshot,
        None,
        Duration::MAX,
        &indices,
    )?;
    assert!(
        bytes.len() < 2048,
        "maximum advance row bytes={}",
        bytes.len()
    );

    let original = plugin.node_slot(0)?.snapshot();
    // Every accessor must reject a slot outside its admitted mapped layout.
    runtime.vm_slot = 1;
    bytes.clear();
    runtime.emit_pending_wait_to(
        "advance-pending",
        &snapshot,
        None,
        Duration::from_secs(175),
        &mut bytes,
    );
    let record = std::str::from_utf8(&bytes)?;
    assert!(record.contains("expected_ack=None request=None "));
    assert!(record.contains("tx_read_write=None rx_read_write=None "));
    assert!(record.contains(
        "fault_command_read_write=None fault_event_read_write=None fault_result_read_write=None"
    ));
    assert_eq!(plugin.node_slot(0)?.snapshot(), original);
    Ok(())
}

#[test]
fn device_wait_observation_keeps_matching_head_separate_from_newer_worker_pin() {
    use super::super::device_wait_observation::{
        CompletionCandidate, DeviceDeadlines, write_deadlines,
    };
    let head = crucible_shmem::FrameDeliveryKey {
        delivery_icount: 10,
        src_node: 3,
        seq: 7,
    };
    let queued = DeviceDeadlines {
        block: CompletionCandidate::queued(Some(10), Some((head, 21))),
        ninep: CompletionCandidate::queued(Some(10), None),
        accelerator: Some(20),
    };
    let mut bytes = Vec::new();
    write_deadlines(&mut bytes, Some(queued)).unwrap_or_else(|e| panic!("queue observation: {e}"));
    let row = std::str::from_utf8(&bytes).unwrap_or_else(|e| panic!("row: {e}"));
    assert!(row.contains("device_min_families=3"));
    assert!(row.contains("block_head=10:3:7:21 block_owner_request=21"));
    assert!(row.contains("ninep_owner_request=unavailable"));

    let worker = DeviceDeadlines {
        block: CompletionCandidate::worker(Some(10), Some((8, Some(22), 11, 50))),
        ..queued
    };
    bytes.clear();
    write_deadlines(&mut bytes, Some(worker)).unwrap_or_else(|e| panic!("worker observation: {e}"));
    let row = std::str::from_utf8(&bytes).unwrap_or_else(|e| panic!("row: {e}"));
    assert!(row.contains("block_head=unavailable block_owner_request=unavailable"));
    assert!(row.contains("block_pin=8:Some(22):11:50"));
    assert!(row.contains("device_min_families=3"));
}

#[cfg(target_os = "linux")]
#[test]
fn device_wait_observation_reads_actual_mapped_block_head_without_consuming_it() {
    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 4))
            .unwrap_or_else(|e| panic!("allocation: {e}"));
    let layout = allocation.layout();
    let mut file = std::fs::File::from(
        crate::spawn::memfd_region(layout.region_size).unwrap_or_else(|e| panic!("region: {e}")),
    );
    file.write_all(
        &allocation
            .setup_region_bytes()
            .unwrap_or_else(|e| panic!("region bytes: {e}")),
    )
    .unwrap_or_else(|e| panic!("region write: {e}"));
    let wake = tempfile::tempfile().unwrap_or_else(|e| panic!("wake: {e}"));
    let mut plugin = crucible_shmem::mmap_setup_region(file.as_fd(), layout.region_size)
        .unwrap_or_else(|e| panic!("map: {e}"));
    let mut block = super::super::QemuLiveBlockIoServicer::from_shmem_fd(
        file.as_fd(),
        layout.region_size,
        0,
        4096,
    )
    .unwrap_or_else(|e| panic!("block: {e}"));
    for (sequence, request_id) in [(7, 21), (8, 22)] {
        let payload = crucible_device::BlockRequest::read(request_id, 0, 8)
            .encode()
            .unwrap_or_else(|e| panic!("request: {e}"));
        let frame = crucible_shmem::FrameEntry::new(0, 0, sequence, &payload)
            .unwrap_or_else(|e| panic!("frame: {e}"));
        let pair = plugin
            .node_directed_ring_pair_mut(
                0,
                0,
                crucible_shmem::SLOT_BLK_IO as u32,
                crucible_shmem::SLOT_BLK_IO as u32,
                0,
            )
            .unwrap_or_else(|e| panic!("ring: {e}"));
        pair.first
            .header
            .enqueue(pair.first.entries, &frame)
            .unwrap_or_else(|e| panic!("enqueue: {e}"));
        assert_eq!(
            block
                .process_one_storage_request()
                .unwrap_or_else(|e| panic!("compute: {e}"))
                .processed,
            1
        );
    }
    let original = block
        .completion_head_observation()
        .unwrap_or_else(|e| panic!("head: {e}"));
    assert_eq!(original.1.map(|(_, request)| request), Some(21));
    let runtime =
        QemuLiveHostIoRuntime::from_shmem_fd(file.as_fd(), wake.as_fd(), layout.region_size, 0)
            .unwrap_or_else(|e| panic!("runtime: {e}"));
    let mut runtime = runtime
        .with_block_servicer(block, super::super::BlockIoDiagnostics::shared())
        .unwrap_or_else(|e| panic!("attach: {e}"));
    let before = runtime.wait_ring_indices();
    runtime
        .publish_device_completion_deadline()
        .unwrap_or_else(|e| panic!("ordinary publication: {e}"));
    assert!(runtime.wait_observation.device_deadlines.get().is_none());
    let ordinary = plugin
        .node_slot(0)
        .unwrap_or_else(|e| panic!("slot: {e}"))
        .device_completion_deadline_tick();
    runtime.wait_observation = WaitObservation::with_budget(256);
    runtime
        .publish_device_completion_deadline()
        .unwrap_or_else(|e| panic!("observed publication: {e}"));
    assert_eq!(
        plugin
            .node_slot(0)
            .unwrap_or_else(|e| panic!("slot: {e}"))
            .device_completion_deadline_tick(),
        ordinary
    );
    assert_eq!(Some(ordinary), original.0);
    assert_eq!(runtime.wait_ring_indices(), before);
    let mut row = Vec::new();
    super::super::device_wait_observation::write_deadlines(
        &mut row,
        runtime.wait_observation.device_deadlines.get(),
    )
    .unwrap_or_else(|e| panic!("row: {e}"));
    let row = std::str::from_utf8(&row).unwrap_or_else(|e| panic!("row text: {e}"));
    assert!(row.contains("block_owner_request=21"));
    assert!(!row.contains("block_owner_request=22"));
    let retained = runtime
        .block
        .as_ref()
        .unwrap_or_else(|| panic!("block owner"))
        .lock_servicer("inspect test retained head")
        .unwrap_or_else(|e| panic!("owner: {e}"))
        .completion_head_observation()
        .unwrap_or_else(|e| panic!("retained head: {e}"));
    assert_eq!(retained, original);
}

#[cfg(target_os = "linux")]
#[test]
fn device_wait_observation_reads_actual_mapped_ninep_head_and_preserves_delivery_frontier() {
    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 4))
            .unwrap_or_else(|e| panic!("allocation: {e}"));
    let layout = allocation.layout();
    let mut file = std::fs::File::from(
        crate::spawn::memfd_region(layout.region_size).unwrap_or_else(|e| panic!("region: {e}")),
    );
    file.write_all(
        &allocation
            .setup_region_bytes()
            .unwrap_or_else(|e| panic!("region bytes: {e}")),
    )
    .unwrap_or_else(|e| panic!("region write: {e}"));
    let wake = tempfile::tempfile().unwrap_or_else(|e| panic!("wake: {e}"));
    let mut plugin = crucible_shmem::mmap_setup_region(file.as_fd(), layout.region_size)
        .unwrap_or_else(|e| panic!("map: {e}"));
    let mut ninep =
        super::super::QemuLive9pIoServicer::from_shmem_fd(file.as_fd(), layout.region_size, 0)
            .unwrap_or_else(|e| panic!("ninep: {e}"));
    let version = b"9P2000.L";
    let mut payload = Vec::new();
    payload.extend_from_slice(&((7 + 4 + 2 + version.len()) as u32).to_le_bytes());
    payload.push(crucible_device::ninep::codec::TVERSION);
    payload.extend_from_slice(&9_u16.to_le_bytes());
    payload.extend_from_slice(&4096_u32.to_le_bytes());
    payload.extend_from_slice(&(version.len() as u16).to_le_bytes());
    payload.extend_from_slice(version);
    let frame = crucible_shmem::FrameEntry::new(0, 0, 77, &payload)
        .unwrap_or_else(|e| panic!("frame: {e}"));
    {
        let pair = plugin
            .node_directed_ring_pair_mut(
                0,
                0,
                crucible_shmem::SLOT_9P_IO as u32,
                crucible_shmem::SLOT_9P_IO as u32,
                0,
            )
            .unwrap_or_else(|e| panic!("ring: {e}"));
        pair.first
            .header
            .enqueue(pair.first.entries, &frame)
            .unwrap_or_else(|e| panic!("enqueue: {e}"));
    }
    assert_eq!(
        ninep
            .service(0)
            .unwrap_or_else(|e| panic!("compute: {e}"))
            .processed,
        1
    );
    let original = ninep.completion_head_observation();
    assert_eq!(original.1.map(|(_, request)| request), Some(77));
    let runtime =
        QemuLiveHostIoRuntime::from_shmem_fd(file.as_fd(), wake.as_fd(), layout.region_size, 0)
            .unwrap_or_else(|e| panic!("runtime: {e}"));
    let mut runtime =
        runtime.with_ninep_servicer(ninep, super::super::NinepIoDiagnostics::shared());
    let before = runtime.wait_ring_indices();
    runtime
        .publish_device_completion_deadline()
        .unwrap_or_else(|e| panic!("ordinary publication: {e}"));
    assert!(runtime.wait_observation.device_deadlines.get().is_none());
    let ordinary = plugin
        .node_slot(0)
        .unwrap_or_else(|e| panic!("slot: {e}"))
        .device_completion_deadline_tick();
    runtime.wait_observation = WaitObservation::with_budget(256);
    runtime
        .publish_device_completion_deadline()
        .unwrap_or_else(|e| panic!("observed publication: {e}"));
    assert_eq!(Some(ordinary), original.0);
    assert_eq!(runtime.wait_ring_indices(), before);
    assert_eq!(
        runtime
            .ninep
            .as_ref()
            .unwrap_or_else(|| panic!("ninep owner"))
            .servicer
            .completion_head_observation(),
        original
    );
    let mut row = Vec::new();
    super::super::device_wait_observation::write_deadlines(
        &mut row,
        runtime.wait_observation.device_deadlines.get(),
    )
    .unwrap_or_else(|e| panic!("row: {e}"));
    let row = std::str::from_utf8(&row).unwrap_or_else(|e| panic!("text: {e}"));
    assert!(row.contains("device_min_families=2"));
    assert!(row.contains("ninep_owner_request=77"));
}

#[test]
fn original_idle_guard_context_distinguishes_plugin_republication_from_scheduler_authorization()
-> Result<(), Box<dyn std::error::Error>> {
    use super::super::boundary::{
        checkpoint_idle_coordinate, checkpoint_idle_publication_is_unreleased,
    };

    let (mut runtime, plugin) = mapped_runtime()?;
    runtime.wait_observation = WaitObservation::with_budget(4);
    let slot = plugin.node_slot(0)?;
    let ceiling = crucible_shmem::authorize_advance_ceiling(0, 1000, None)?;
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
    slot.publish_idle(100, 100)?;
    let initial = slot.snapshot();
    let coordinate = checkpoint_idle_coordinate(&initial);
    let indices = runtime.wait_ring_indices();
    runtime.wait_observation.begin(Duration::from_secs(300));
    runtime
        .wait_observation
        .retain_initial_advance(&initial, coordinate);

    for expected_new_authorization in [false, false, true] {
        if expected_new_authorization {
            let ceiling = crucible_shmem::authorize_advance_ceiling(0, 2000, None)?;
            slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
        }
        slot.publish_idle(100, 100)?;
        let current = slot.snapshot();
        let unreleased = checkpoint_idle_publication_is_unreleased(coordinate, &current);
        assert!(unreleased);
        assert_ne!(current.publish_gen, initial.publish_gen);
        assert_eq!(
            current.advance_publication_sequence != initial.advance_publication_sequence,
            expected_new_authorization
        );
        runtime.wait_observation.checkpoint_idle_unreleased = Some(unreleased);
        let mut bytes = Vec::new();
        runtime.emit_pending_wait_to(
            "advance-pending",
            &current,
            None,
            Duration::from_secs(295),
            &mut bytes,
        );
        let record = std::str::from_utf8(&bytes)?;
        assert!(record.contains("initial_checkpoint_idle_ps=Some(100) "));
        assert!(record.contains(&format!(
            "initial_advance_sequence=Some({}) ",
            initial.advance_publication_sequence
        )));
        assert!(record.contains("initial_advance_ceiling_ps=Some(1000) "));
        assert!(record.contains("checkpoint_idle_unreleased=Some(true) "));
        assert!(record.contains(&format!(
            "advance_sequence={} ",
            current.advance_publication_sequence
        )));
        assert_eq!(slot.snapshot(), current);
        assert_eq!(runtime.wait_ring_indices(), indices);
        assert!(runtime.completed_boundary.is_none());
    }

    slot.publish_reached_icount(101)?;
    let released = slot.snapshot();
    assert!(!checkpoint_idle_publication_is_unreleased(
        coordinate, &released
    ));
    runtime.wait_observation.checkpoint_idle_unreleased = Some(false);
    let mut bytes = Vec::new();
    runtime.emit_pending_wait_to(
        "advance-pending",
        &released,
        None,
        Duration::from_secs(290),
        &mut bytes,
    );
    assert!(std::str::from_utf8(&bytes)?.contains("checkpoint_idle_unreleased=Some(false) "));
    assert_eq!(
        runtime.wait_observation.slice_timeout,
        Duration::from_secs(300)
    );
    assert_eq!(
        runtime
            .wait_observation
            .initial_advance
            .map(|value| value.checkpoint_idle_coordinate),
        Some(Some(100))
    );
    Ok(())
}

#[test]
fn disabled_or_unacquired_initial_context_remains_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut runtime, plugin) = mapped_runtime()?;
    let snapshot = plugin.node_slot(0)?.snapshot();
    for budget in [0, 1] {
        runtime.wait_observation = WaitObservation::with_budget(budget);
        runtime.wait_observation.begin(Duration::from_secs(300));
        if budget == 0 {
            runtime
                .wait_observation
                .retain_initial_advance(&snapshot, Some(100));
        }
        assert!(runtime.wait_observation.initial_advance.is_none());
        let mut bytes = Vec::new();
        runtime.emit_pending_wait_to(
            "advance-pending",
            &snapshot,
            None,
            Duration::from_secs(295),
            &mut bytes,
        );
        let row = std::str::from_utf8(&bytes)?;
        assert!(row.contains("initial_checkpoint_idle_ps=None initial_advance_sequence=None "));
        assert!(row.contains("checkpoint_idle_unreleased=None "));
    }
    Ok(())
}
