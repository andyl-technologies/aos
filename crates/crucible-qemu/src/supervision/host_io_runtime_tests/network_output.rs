//! Mapped-runtime output freshness and mandatory control acknowledgement.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use super::*;

#[derive(Debug, thiserror::Error)]
enum NetworkOutputTestError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
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
    Lookahead(#[from] crucible_shmem::LookaheadGateError),
    #[error(transparent)]
    Frame(#[from] crucible_shmem::FrameEntryError),
    #[error(transparent)]
    Ring(#[from] crucible_shmem::SpscRingError),
    #[error("{0}")]
    ThreadPanicked(&'static str),
}

fn read_wake(stream: &mut UnixStream) -> Result<(), NetworkOutputTestError> {
    let mut bytes = [0; std::mem::size_of::<u64>()];
    stream.read_exact(&mut bytes)?;
    assert_eq!(u64::from_ne_bytes(bytes), 1);
    Ok(())
}

#[test]
fn network_output_witness_waits_for_the_matching_producer_publication()
-> Result<(), NetworkOutputTestError> {
    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 4))?;
    let layout = allocation.layout();
    let mut shmem = std::fs::File::from(crate::spawn::memfd_region(layout.region_size)?);
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let mut plugin = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let (_notifications, wake) = UnixStream::pair()?;
    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd_with_poll_interval(
        shmem.as_fd(),
        wake.as_fd(),
        layout.region_size,
        0,
        Duration::from_millis(1),
    )?;
    let ceiling = authorize_advance_ceiling(0, 2_000, None)?;
    plugin
        .node_slot(0)?
        .publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
    plugin.node_slot(0)?.publish_pause_quiesced(1_000, 20)?;
    let old_pause = plugin.node_slot(0)?.snapshot();

    // The real TX callback publishes its running coordinate before releasing
    // the frame and then publishes the output pause. Polling an earlier slot
    // sample during that interval must wait for the matching publication.
    plugin.node_slot(0)?.publish_reached_icount(1_500)?;
    let frame = crucible_shmem::FrameEntry::new(1_500, 0, 23, b"new-coordinate")?;
    {
        let rings = plugin.node_directed_ring_pair_mut(
            0,
            0,
            crucible_shmem::SLOT_NET_ROUTER as u32,
            crucible_shmem::SLOT_NET_ROUTER as u32,
            0,
        )?;
        rings.first.header.enqueue(rings.first.entries, &frame)?;
    }
    assert_eq!(runtime.network_output_stop_write_index(&old_pause)?, None);
    let running = plugin.node_slot(0)?.snapshot();
    assert_eq!(runtime.network_output_stop_write_index(&running)?, None);

    plugin.node_slot(0)?.publish_pause_quiesced(1_500, 30)?;
    let output_pause = plugin.node_slot(0)?.snapshot();
    assert_eq!(
        runtime.network_output_stop_write_index(&output_pause)?,
        Some(1),
    );
    plugin.node_slot(0)?.publish_pause_quiesced(1_400, 28)?;
    let inconsistent_pause = plugin.node_slot(0)?.snapshot();
    assert!(
        runtime
            .network_output_stop_write_index(&inconsistent_pause)
            .is_err()
    );
    Ok(())
}

#[test]
fn network_output_at_unchanged_tick_requires_a_fresh_ring_frontier_and_control_ack()
-> Result<(), NetworkOutputTestError> {
    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 4))?;
    let layout = allocation.layout();
    let mut shmem = std::fs::File::from(crate::spawn::memfd_region(layout.region_size)?);
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let mut plugin = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let (mut notifications, wake) = UnixStream::pair()?;
    notifications.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd_with_poll_interval(
        shmem.as_fd(),
        wake.as_fd(),
        layout.region_size,
        0,
        Duration::from_millis(1),
    )?;
    let ceiling = authorize_advance_ceiling(0, 2_000, None)?;
    plugin
        .node_slot(0)?
        .publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
    plugin.node_slot(0)?.publish_pause_quiesced(1_000, 20)?;
    let host = std::thread::spawn(move || {
        let result = runtime.await_child(QemuAsyncWait::AdvanceCompletion, Duration::from_secs(1));
        (runtime, result)
    });

    // An acknowledged control republish at the old coordinate cannot create
    // an output stop. The later periodic wake proves polling remains active.
    read_wake(&mut notifications)?;
    plugin.node_slot(0)?.publish_control_boundary(1_000, 20)?;
    let first_ack = plugin.node_slot(0)?.acknowledge_control_boundary();
    read_wake(&mut notifications)?;
    assert_eq!(plugin.node_slot(0)?.snapshot().max_advance_icount, 2_000);
    plugin.node_slot(0)?.publish_control_boundary(1_000, 20)?;
    plugin.node_slot(0)?.acknowledge_control_boundary();

    let frame = crucible_shmem::FrameEntry::new(1_000, 0, 17, b"zero-retirement-reply")?;
    {
        let rings = plugin.node_directed_ring_pair_mut(
            0,
            0,
            crucible_shmem::SLOT_NET_ROUTER as u32,
            crucible_shmem::SLOT_NET_ROUTER as u32,
            0,
        )?;
        rings.first.header.enqueue(rings.first.entries, &frame)?;
    }
    plugin.node_slot(0)?.publish_pause_quiesced(1_000, 20)?;
    let mut clamped = plugin.node_slot(0)?.snapshot();
    for _ in 0..16 {
        read_wake(&mut notifications)?;
        clamped = plugin.node_slot(0)?.snapshot();
        if clamped.max_advance_icount == 1_000 {
            break;
        }
        plugin.node_slot(0)?.publish_control_boundary(1_000, 20)?;
        plugin.node_slot(0)?.acknowledge_control_boundary();
    }
    assert_eq!(clamped.max_advance_icount, 1_000);
    assert_eq!(clamped.control_boundary_ack & 1, 0);
    assert_ne!(clamped.control_boundary_ack, first_ack);
    assert!(!host.is_finished());

    plugin.node_slot(0)?.publish_control_boundary(1_000, 20)?;
    let final_ack = plugin.node_slot(0)?.acknowledge_control_boundary();
    let (mut runtime, result) = host
        .join()
        .map_err(|_| NetworkOutputTestError::ThreadPanicked("host output poll panicked"))?;
    assert_eq!(result?, QemuAsyncWaitOutcome::Completed);
    assert_eq!(final_ack, clamped.control_boundary_ack.wrapping_add(1));
    assert_eq!(runtime.completed_outbound_write_index, 1);
    {
        let rings = plugin.node_directed_ring_pair_mut(
            0,
            0,
            crucible_shmem::SLOT_NET_ROUTER as u32,
            crucible_shmem::SLOT_NET_ROUTER as u32,
            0,
        )?;
        assert_eq!(rings.first.header.read_index(), 0);
        assert_eq!(
            rings.first.header.peek(rings.first.entries)?,
            Some(frame.clone())
        );
    }

    // Keep the old frame deliberately unconsumed. A new ceiling, fresh
    // control ACK, and appended frame cannot authenticate the old ring head
    // against its preceding producer frontier.
    plugin
        .node_slot(0)?
        .publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)?;
    let host = std::thread::spawn(move || {
        runtime.await_child(QemuAsyncWait::AdvanceCompletion, Duration::from_millis(80))
    });
    read_wake(&mut notifications)?;
    plugin.node_slot(0)?.publish_control_boundary(1_000, 20)?;
    plugin.node_slot(0)?.acknowledge_control_boundary();
    read_wake(&mut notifications)?;
    assert_eq!(plugin.node_slot(0)?.snapshot().max_advance_icount, 2_000);
    {
        let rings = plugin.node_directed_ring_pair_mut(
            0,
            0,
            crucible_shmem::SLOT_NET_ROUTER as u32,
            crucible_shmem::SLOT_NET_ROUTER as u32,
            0,
        )?;
        let fresh_tail = crucible_shmem::FrameEntry::new(1_000, 0, 18, b"later-reply")?;
        rings
            .first
            .header
            .enqueue(rings.first.entries, &fresh_tail)?;
        assert_eq!(rings.first.header.write_index(), 2);
        assert_eq!(rings.first.header.read_index(), 0);
        assert_eq!(rings.first.header.peek(rings.first.entries)?, Some(frame));
    }
    plugin.node_slot(0)?.publish_pause_quiesced(1_000, 20)?;
    assert_eq!(
        host.join()
            .map_err(|_| NetworkOutputTestError::ThreadPanicked("stale output poll panicked"))??,
        QemuAsyncWaitOutcome::TimedOut,
    );
    Ok(())
}
