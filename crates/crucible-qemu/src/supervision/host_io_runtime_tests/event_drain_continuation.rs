//! Event-consumer progress preserves the original clamp request owner.
//!
//! The callback provider models a callback that retained publication work after
//! its first delivery. It uses the public mapped transport and a real eventfd;
//! it does not model native callback scheduling or certify physical delivery.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;

use super::*;

type TestResult<T = ()> = Result<T, EventContinuationTestError>;

#[derive(Debug, thiserror::Error)]
enum EventContinuationTestError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Poll(#[from] rustix::io::Errno),
    #[error(transparent)]
    Spawn(#[from] crate::QemuSpawnError),
    #[error(transparent)]
    Runtime(#[from] QemuAsyncDriverRuntimeError),
    #[error(transparent)]
    HostRuntime(#[from] crate::QemuLiveHostIoRuntimeError),
    #[error(transparent)]
    Layout(#[from] crucible_shmem::RegionLayoutError),
    #[error(transparent)]
    Serialization(#[from] crucible_shmem::RegionSerializationError),
    #[error(transparent)]
    Mapping(#[from] crucible_shmem::SetupRegionMapError),
    #[error(transparent)]
    Access(#[from] crucible_shmem::MappedSetupRegionAccessError),
    #[error(transparent)]
    Slot(#[from] crucible_shmem::NodeSlotError),
    #[error(transparent)]
    Transport(#[from] crucible_shmem::FaultTransportError),
    #[error(transparent)]
    Accelerator(#[from] crate::QemuLiveAcceleratorServicerError),
    #[error(transparent)]
    AcceleratorEntry(#[from] crucible_shmem::AcceleratorEntryError),
    #[error(transparent)]
    Ring(#[from] crucible_shmem::SpscRingError),
    #[error("unexpected eventfd continuation notification")]
    UnexpectedWake,
    #[error("continuation arrived before the original event drain")]
    ContinuationBeforeDrain,
    #[error("callback provider panicked")]
    ProviderPanicked,
    #[error("accelerator is not attached")]
    MissingAccelerator,
    #[error("expected refusal: {0}")]
    ExpectedRefusal(&'static str),
}

struct EventRuntime {
    runtime: QemuLiveHostIoRuntime,
    producer: MappedSetupRegion,
    shmem: File,
    wake: File,
    region_size: u64,
}

impl EventRuntime {
    fn new() -> TestResult<Self> {
        let allocation =
            crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 2))?;
        let layout = allocation.layout();
        let mut shmem = File::from(crate::spawn::memfd_region(layout.region_size)?);
        shmem.write_all(&allocation.setup_region_bytes()?)?;
        let wake = File::from(crate::node::create_nonblocking_eventfd()?);
        let producer = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        producer.node_slot(0)?.publish_pause_quiesced(100, 2)?;
        let runtime = QemuLiveHostIoRuntime::from_shmem_fd_with_poll_interval(
            shmem.as_fd(),
            wake.as_fd(),
            layout.region_size,
            0,
            Duration::from_millis(1),
        )?;
        Ok(Self {
            runtime,
            producer,
            shmem,
            wake,
            region_size: layout.region_size,
        })
    }
}

fn publish_event(producer: &mut MappedSetupRegion, sequence: u64) -> TestResult {
    let transport = producer.fault_event_transport_mut(0)?;
    crucible_shmem::enqueue_fault_event(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
        crucible_shmem::FaultEventHeaderV1 {
            command_kind: crucible_shmem::FaultCommandKind::MemoryAccessTransform,
            outcome: crucible_shmem::FaultEventOutcomeV1::Applied,
            event_sequence: sequence,
            rule_command_sequence: 1,
            observed_icount: 100,
            model_phase: 18,
            target_kind: 4,
            generation: 1,
            binding_hash: [1; 32],
            opportunity_hash: [2; 32],
            action_hash: [3; 32],
            target_hash: [4; 32],
            before_hash: [5; 32],
            after_hash: [6; 32],
            evidence_hash: [0; 32],
            payload_hash: [0; 32],
            payload_offset: 0,
            payload_length: 0,
        },
        b"retained-event",
    )?;
    Ok(())
}

fn read_wake(wake: &mut File) -> std::io::Result<u64> {
    let mut bytes = [0; 8];
    wake.read_exact(&mut bytes)?;
    Ok(u64::from_ne_bytes(bytes))
}

/// Waits on real delivery or the test owner's teardown signal, without polling.
fn wait_for_delivery(wake: &mut File, stop: &File) -> TestResult<(Option<u64>, bool)> {
    use rustix::event::{PollFd, PollFlags, poll};

    let (delivered, stopped) = {
        let mut descriptors = [
            PollFd::new(&*wake, PollFlags::IN),
            PollFd::new(stop, PollFlags::IN),
        ];
        poll(&mut descriptors, None)?;
        (
            descriptors[0].revents().contains(PollFlags::IN),
            descriptors[1].revents().contains(PollFlags::IN),
        )
    };
    Ok((
        if delivered {
            Some(read_wake(wake)?)
        } else {
            None
        },
        stopped,
    ))
}

fn assert_no_wake(wake: &mut File) -> TestResult {
    let Err(error) = read_wake(wake) else {
        return Err(EventContinuationTestError::UnexpectedWake);
    };
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    Ok(())
}

fn drain_one(fixture: &mut EventRuntime) -> TestResult<usize> {
    let timeout = Duration::from_secs(1);
    Ok(fixture.runtime.drain_fault_events_for_pump(
        4,
        &HostSupervisionDeadline::start(timeout),
        timeout,
        "test clamp event drain",
    )?)
}

#[test]
fn clamp_event_drain_redelivers_the_original_request() -> TestResult {
    let mut fixture = EventRuntime::new()?;
    publish_event(&mut fixture.producer, 1)?;
    let initial = fixture.producer.node_slot(0)?.snapshot();
    let shmem = fixture.shmem.try_clone()?;
    let mut wake = fixture.wake.try_clone()?;
    let region_size = fixture.region_size;
    let mut stop = File::from(crate::node::create_nonblocking_eventfd()?);
    let stopped = stop.try_clone()?;
    let provider = std::thread::spawn(move || -> TestResult<u64> {
        let mut producer = crucible_shmem::mmap_setup_region(shmem.as_fd(), region_size)?;
        let mut deliveries = 0;
        loop {
            let (count, stopping) = wait_for_delivery(&mut wake, &stopped)?;
            deliveries += count.unwrap_or(0);
            if stopping {
                return Ok(deliveries);
            }
            if deliveries < 2 {
                continue;
            }

            // This explicit provider requires a continuation delivery after
            // the host frees event capacity. It release-acks the same request.
            let transport = producer.fault_event_transport_mut(0)?;
            if transport.ring.read_index() != 1 || transport.ring.write_index() != 1 {
                return Err(EventContinuationTestError::ContinuationBeforeDrain);
            }
            publish_event(&mut producer, 2)?;
            let slot = producer.node_slot(0)?;
            slot.publish_control_boundary(100, 2)?;
            slot.acknowledge_control_boundary();
            return Ok(deliveries);
        }
    });

    let outcome = fixture
        .runtime
        .clamp_completed_quantum(&initial, Duration::from_secs(1));
    stop.write_all(&1_u64.to_ne_bytes())?;
    let deliveries = provider
        .join()
        .map_err(|_| EventContinuationTestError::ProviderPanicked)??;
    outcome?;

    assert_eq!(deliveries, 2);
    assert_eq!(fixture.runtime.staged_fault_events.len(), 2);
    assert_eq!(
        fixture.runtime.staged_fault_events[0].header.event_sequence,
        1
    );
    assert_eq!(
        fixture.runtime.staged_fault_events[1].header.event_sequence,
        2
    );
    let final_slot = fixture.producer.node_slot(0)?.snapshot();
    assert_eq!(final_slot.control_boundary_ack, 3);
    assert_eq!(final_slot.control_boundary_fault_command_frontier, 0);
    assert_eq!(final_slot.control_boundary_capture_request, 0);
    assert_eq!(final_slot.current_icount, 100);
    assert_eq!(final_slot.logical_time_raw_icount, 2);
    assert_eq!(final_slot.max_advance_icount, 100);
    assert_eq!(final_slot.idle_wake_icount, 100);
    assert_no_wake(&mut fixture.wake)?;
    Ok(())
}

#[test]
fn empty_event_polls_do_not_renotify_a_pending_clamp() -> TestResult {
    let mut fixture = EventRuntime::new()?;
    let request = fixture.runtime.signal_wake(Some(1))?;
    assert_eq!(read_wake(&mut fixture.wake)?, 1);
    let before = fixture.producer.node_slot(0)?.snapshot();

    for _ in 0..3 {
        let drained = drain_one(&mut fixture)?;
        fixture
            .runtime
            .renotify_clamp_after_event_drain(request, drained, false)?;
    }

    assert_no_wake(&mut fixture.wake)?;
    assert_eq!(fixture.producer.node_slot(0)?.snapshot(), before);
    assert!(fixture.runtime.staged_fault_events.is_empty());
    Ok(())
}

#[test]
fn ack_racing_event_progress_keeps_one_publication_and_original_epoch() -> TestResult {
    let mut fixture = EventRuntime::new()?;
    publish_event(&mut fixture.producer, 1)?;
    let initial = fixture.producer.node_slot(0)?.snapshot();
    let shmem = fixture.shmem.try_clone()?;
    let mut wake = fixture.wake.try_clone()?;
    let region_size = fixture.region_size;
    let mut stop = File::from(crate::node::create_nonblocking_eventfd()?);
    let stopped = stop.try_clone()?;
    let provider = std::thread::spawn(move || -> TestResult<(u64, u64)> {
        let producer = crucible_shmem::mmap_setup_region(shmem.as_fd(), region_size)?;
        let mut deliveries = 0;
        let mut publications = 0;
        loop {
            let (count, stopping) = wait_for_delivery(&mut wake, &stopped)?;
            deliveries += count.unwrap_or(0);
            if count.is_none() {
                return Ok((deliveries, publications));
            }
            let slot = producer.node_slot(0)?;
            if slot.snapshot().control_boundary_ack & 1 == 0 {
                slot.publish_control_boundary(100, 2)?;
                slot.acknowledge_control_boundary();
                publications += 1;
            }
            if stopping {
                return Ok((deliveries, publications));
            }
        }
    });

    let outcome = fixture
        .runtime
        .clamp_completed_quantum(&initial, Duration::from_secs(1));
    stop.write_all(&1_u64.to_ne_bytes())?;
    let (deliveries, publications) = provider
        .join()
        .map_err(|_| EventContinuationTestError::ProviderPanicked)??;
    outcome?;

    // The event consumer and callback race legitimately. At most one progress
    // notification may join the first delivery, and an odd request is inert.
    assert!((1..=2).contains(&deliveries));
    assert_eq!(publications, 1);
    assert_eq!(
        fixture
            .producer
            .node_slot(0)?
            .snapshot()
            .control_boundary_ack,
        3
    );
    assert_eq!(fixture.runtime.staged_fault_events.len(), 1);
    assert_eq!(
        fixture.runtime.staged_fault_events[0].header.event_sequence,
        1
    );
    assert_no_wake(&mut fixture.wake)?;
    Ok(())
}

#[test]
fn event_progress_keeps_the_exact_capture_and_request_without_repeat() -> TestResult {
    let mut fixture = EventRuntime::new()?;
    publish_event(&mut fixture.producer, 1)?;
    let request = fixture.runtime.signal_wake(Some(1))?;
    assert_eq!(read_wake(&mut fixture.wake)?, 1);
    let before = fixture.producer.node_slot(0)?.snapshot();

    let drained = drain_one(&mut fixture)?;
    fixture
        .runtime
        .renotify_clamp_after_event_drain(request, drained, false)?;
    assert_eq!(read_wake(&mut fixture.wake)?, 1);
    let drained = drain_one(&mut fixture)?;
    fixture
        .runtime
        .renotify_clamp_after_event_drain(request, drained, false)?;

    assert_no_wake(&mut fixture.wake)?;
    assert_eq!(fixture.producer.node_slot(0)?.snapshot(), before);
    assert_eq!(fixture.runtime.staged_fault_events.len(), 1);
    assert_eq!(
        fixture.runtime.staged_fault_events[0].payload,
        b"retained-event"
    );
    assert_eq!(fixture.runtime.fault_event_ring_indices()?, (1, 1));
    Ok(())
}

#[test]
fn acknowledged_or_replaced_requests_do_not_receive_old_continuations() -> TestResult {
    let mut fixture = EventRuntime::new()?;
    let request = fixture.runtime.signal_wake(None)?;
    assert_eq!(read_wake(&mut fixture.wake)?, 1);
    publish_event(&mut fixture.producer, 1)?;
    let drained = drain_one(&mut fixture)?;
    fixture
        .producer
        .node_slot(0)?
        .acknowledge_control_boundary();

    fixture
        .runtime
        .renotify_clamp_after_event_drain(request, drained, false)?;
    assert_no_wake(&mut fixture.wake)?;
    let replacement = fixture
        .producer
        .node_slot(0)?
        .request_control_boundary(1, Some(3))?;
    let before = fixture.producer.node_slot(0)?.snapshot();
    fixture
        .runtime
        .renotify_clamp_after_event_drain(request, drained, false)?;

    assert_no_wake(&mut fixture.wake)?;
    assert_ne!(replacement, request.generation);
    assert_eq!(fixture.producer.node_slot(0)?.snapshot(), before);
    Ok(())
}

#[test]
fn unbound_frontier_capture_or_odd_request_cannot_renotify() -> TestResult {
    let mut fixture = EventRuntime::new()?;
    let request = fixture.runtime.signal_wake(Some(1))?;
    assert_eq!(read_wake(&mut fixture.wake)?, 1);
    publish_event(&mut fixture.producer, 1)?;
    let drained = drain_one(&mut fixture)?;
    let before = fixture.producer.node_slot(0)?.snapshot();
    let invalid_requests = [
        PendingControlBoundary {
            fault_command_frontier: 1,
            ..request
        },
        PendingControlBoundary {
            fingerprint_capture_request: Some(3),
            ..request
        },
        PendingControlBoundary {
            generation: request.generation + 1,
            ..request
        },
    ];

    for invalid in invalid_requests {
        fixture
            .runtime
            .renotify_clamp_after_event_drain(invalid, drained, false)?;
        assert_no_wake(&mut fixture.wake)?;
        assert_eq!(fixture.producer.node_slot(0)?.snapshot(), before);
    }
    Ok(())
}

#[test]
fn new_command_publication_invalidates_the_bound_event_continuation() -> TestResult {
    let mut fixture = EventRuntime::new()?;
    let request = fixture.runtime.signal_wake(None)?;
    assert_eq!(read_wake(&mut fixture.wake)?, 1);
    publish_event(&mut fixture.producer, 1)?;
    let drained = drain_one(&mut fixture)?;
    let before = fixture.producer.node_slot(0)?.snapshot();
    let transport = fixture.producer.fault_command_transport_mut(0)?;
    crucible_shmem::enqueue_fault_command(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
        crucible_shmem::FaultCommandHeaderV1 {
            abi_major: crucible_shmem::FAULT_COMMAND_ABI_MAJOR,
            abi_minor: crucible_shmem::FAULT_COMMAND_ABI_MINOR,
            command_kind: crucible_shmem::FaultCommandKind::BoundaryProbe,
            command_flags: 0,
            phase: crucible_shmem::FaultBoundaryPhase::NodeBoundary,
            semantic_version: crucible_shmem::FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence: 1,
            target_node_hash: [1; 32],
            target_icount: 100,
            authorization_ceiling_icount: 100,
            binding_hash: [2; 32],
            opportunity_hash: [0; 32],
            expected_precondition_hash: [0; 32],
            payload_hash: [0; 32],
            payload_offset: 0,
            payload_length: 0,
        },
        &[],
    )?;

    fixture
        .runtime
        .renotify_clamp_after_event_drain(request, drained, false)?;

    assert_no_wake(&mut fixture.wake)?;
    assert_eq!(fixture.producer.fault_command_write_index(0)?, 1);
    assert_eq!(fixture.producer.node_slot(0)?.snapshot(), before);
    Ok(())
}

#[test]
fn actual_device_progress_already_notifies_the_pending_event_request() -> TestResult {
    let mut fixture = EventRuntime::new()?;
    let accelerator =
        QemuLiveAcceleratorServicer::from_shmem_fd(fixture.shmem.as_fd(), fixture.region_size, 0)?;
    fixture.runtime = fixture.runtime.with_accelerator_servicer(accelerator);
    let request = fixture.runtime.signal_wake(None)?;
    assert_eq!(read_wake(&mut fixture.wake)?, 1);
    publish_event(&mut fixture.producer, 1)?;
    let drained = drain_one(&mut fixture)?;
    let input = [
        1_u32.to_le_bytes(),
        2_i32.to_le_bytes(),
        3_i32.to_le_bytes(),
    ]
    .concat();
    let job = crucible_shmem::AcceleratorEntry::new(
        1,
        1,
        [4; 32],
        crucible_shmem::AcceleratorClass::Gpu,
        1,
        0,
        0,
        false,
        1,
        4,
        &input,
    )?;
    fixture
        .producer
        .plugin_accelerator_rings_mut(0)?
        .requests
        .enqueue(job)?;
    let before = fixture.producer.node_slot(0)?.snapshot();

    let progressed = fixture.runtime.service_accelerator_io(&before)?;
    assert!(progressed);
    fixture
        .runtime
        .renotify_clamp_after_event_drain(request, drained, progressed)?;

    assert_eq!(read_wake(&mut fixture.wake)?, 1);
    assert_no_wake(&mut fixture.wake)?;
    assert_eq!(fixture.producer.node_slot(0)?.snapshot(), before);
    let mut rings = fixture.producer.plugin_accelerator_rings_mut(0)?;
    assert_eq!(rings.requests.live_len()?, 0);
    assert!(rings.completions.dequeue()?.is_none());
    assert_eq!(
        fixture
            .runtime
            .accelerator
            .as_ref()
            .ok_or(EventContinuationTestError::MissingAccelerator)?
            .next_completion_icount(),
        Some(101),
    );
    assert_eq!(fixture.runtime.staged_fault_events.len(), 1);
    Ok(())
}

#[test]
fn failed_event_drain_preserves_pending_request_without_notification() -> TestResult {
    for limit in [0, 1] {
        let mut fixture = EventRuntime::new()?;
        publish_event(&mut fixture.producer, 1)?;
        publish_event(&mut fixture.producer, 2)?;
        fixture.runtime.fault_event_staging_limit = limit;
        let initial = fixture.producer.node_slot(0)?.snapshot();

        let error = fixture
            .runtime
            .clamp_completed_quantum(&initial, Duration::from_secs(1))
            .err()
            .ok_or(EventContinuationTestError::ExpectedRefusal(
                "insufficient staging",
            ))?;

        assert!(error.fault_event_storage_coordinates().is_some());
        assert_eq!(read_wake(&mut fixture.wake)?, 1);
        assert_no_wake(&mut fixture.wake)?;
        assert_eq!(fixture.runtime.staged_fault_events.len(), limit);
        assert_eq!(
            fixture.runtime.fault_event_ring_indices()?,
            (limit as u64, 2)
        );
        let slot = fixture.producer.node_slot(0)?.snapshot();
        assert_eq!(slot.control_boundary_ack, 2);
        assert_eq!(slot.current_icount, initial.current_icount);
        assert_eq!(
            slot.logical_time_raw_icount,
            initial.logical_time_raw_icount
        );
    }
    Ok(())
}

#[test]
fn doorbell_failure_retains_the_original_request_and_consumed_event() -> TestResult {
    let mut fixture = EventRuntime::new()?;
    let request = fixture.runtime.signal_wake(None)?;
    assert_eq!(read_wake(&mut fixture.wake)?, 1);
    publish_event(&mut fixture.producer, 1)?;
    let drained = drain_one(&mut fixture)?;
    let before = fixture.producer.node_slot(0)?.snapshot();
    let readonly = tempfile::NamedTempFile::new()?;
    fixture.runtime.wake = Arc::new(File::open(readonly.path())?);

    let error = fixture
        .runtime
        .renotify_clamp_after_event_drain(request, drained, false)
        .err()
        .ok_or(EventContinuationTestError::ExpectedRefusal(
            "read-only wake descriptor",
        ))?;

    assert!(error.to_string().contains("signal plugin wake"));
    assert_eq!(fixture.producer.node_slot(0)?.snapshot(), before);
    assert_eq!(fixture.runtime.staged_fault_events.len(), 1);
    assert_no_wake(&mut fixture.wake)?;
    Ok(())
}
