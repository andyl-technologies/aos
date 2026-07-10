//! Checks owned mapped shared-memory QEMU quantum channels.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(unix)]
use std::error::Error;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use crucible::{
    AdvanceOutcome, BasicBlockCoverageConfig, EventLog, EventLogCoverageObservation,
    ExecutionHorizon, Icount, NodeId, SchedulerError, SchedulerNodeId, SchedulerSendAuthorization,
    SchedulerSendAuthorizer, event_log_coverage_projection,
};
#[cfg(unix)]
use crucible_qemu::{
    QemuMappedQuantumShmemHotPath, QemuQuantumOperation, QemuQuantumOperationPlane,
    QemuQuantumShmemConfig, QemuShmemHotPathChannel,
};
#[cfg(unix)]
use crucible_shmem::{
    CoverageEntry, FrameEntry, MappedSetupRegion, RegionAllocation, RegionConfig, SLOT_NET_ROUTER,
    authorize_advance_ceiling, mmap_setup_region,
};

#[cfg(unix)]
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
#[test]
fn mapped_quantum_can_publish_shared_shutdown_without_marking_plugin_done()
-> Result<(), Box<dyn Error>> {
    let region = mapped_region(6, None, &[])?;
    let hot_path = QemuMappedQuantumShmemHotPath::new(qemu_config(), region, AllowAllSends)?;

    hot_path.request_plugin_shutdown()?;

    assert!(!hot_path.plugin_teardown_done()?);
    Ok(())
}

#[cfg(unix)]
#[test]
fn mapped_quantum_split_completion_keeps_full_operation_log() -> Result<(), Box<dyn Error>> {
    let region = mapped_region(6, None, &[])?;
    let config = qemu_config();
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(config, region, AllowAllSends)?;

    let pending = QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        ExecutionHorizon { icount: icount(6) },
    )?;
    let completion = QemuShmemHotPathChannel::finish_quantum(&mut hot_path, pending)?;

    assert_eq!(completion.outcome, AdvanceOutcome::ReachedHorizon);
    assert_eq!(
        QemuShmemHotPathChannel::current_icount(&mut hot_path)?,
        icount(6)
    );
    assert!(
        completion
            .operations
            .contains(&QemuQuantumOperation::ComputeSchedulerCeiling)
    );
    assert!(
        completion
            .operations
            .contains(&QemuQuantumOperation::FutexWake)
    );
    assert!(
        completion
            .operations
            .contains(&QemuQuantumOperation::ObservePluginReport)
    );
    assert!(
        completion
            .operations
            .iter()
            .all(|operation| operation.plane() == QemuQuantumOperationPlane::SharedMemory)
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn mapped_quantum_emit_frame_reads_owned_outbound_ring() -> Result<(), Box<dyn Error>> {
    let outbound = FrameEntry::new(7, 0, 3, b"egress")?;
    let region = mapped_region(7, Some(outbound), &[])?;
    let config = qemu_config();
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(config, region, AllowAllSends)?;

    let emitted =
        QemuShmemHotPathChannel::emit_frame(&mut hot_path)?.ok_or("expected outbound frame")?;

    assert_eq!(emitted.source, node_id("vm-a"));
    assert_eq!(emitted.destination, node_id("net-router"));
    assert_eq!(emitted.emit_icount, icount(7));
    assert_eq!(emitted.sequence, 3);
    assert_eq!(emitted.payload, b"egress");
    assert!(QemuShmemHotPathChannel::emit_frame(&mut hot_path)?.is_none());

    Ok(())
}

#[cfg(unix)]
#[test]
fn mapped_quantum_drains_coverage_into_the_unified_event_log() -> Result<(), Box<dyn Error>> {
    let guest_pc = 0x4010;
    let map_index = crucible::basic_block_coverage_map_index(
        guest_pc,
        crucible_shmem::COVERAGE_QUEUE_CAPACITY as usize,
    )?;
    let coverage = [
        CoverageEntry::new(5, 0, guest_pc, 4, map_index as u64)?,
        CoverageEntry::new(6, 1, 0x5000, 8, map_index_for(0x5000))?,
    ];
    let region = mapped_region(6, None, &coverage)?;
    let config = qemu_config().with_coverage(BasicBlockCoverageConfig::on());
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(config, region, AllowAllSends)?;

    let pending = QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        ExecutionHorizon { icount: icount(6) },
    )?;
    let completion = QemuShmemHotPathChannel::finish_quantum(&mut hot_path, pending)?;
    assert!(QemuShmemHotPathChannel::coverage_enabled(&hot_path));
    assert!(
        completion
            .operations
            .iter()
            .all(|operation| operation.plane() == QemuQuantumOperationPlane::SharedMemory)
    );

    let mut event_log = EventLog::new();
    let observations = QemuShmemHotPathChannel::drain_observable_events(&mut hot_path)?;
    assert_eq!(observations.len(), 2);
    let append = event_log.append_observable_events(observations)?;
    let projection = event_log_coverage_projection(&append.entries);
    assert_eq!(projection.len(), 2);
    assert_eq!(
        append.entries[0].class(),
        crucible::SchedulerEventLogClass::Observational
    );
    assert_eq!(projection.entries()[0].at.icount, icount(5));
    assert_eq!(projection.entries()[1].at.icount, icount(6));
    assert_eq!(
        projection.entries()[0].observation,
        EventLogCoverageObservation::BasicBlock {
            node: node_id("vm-a"),
            guest_pc,
            block_len: 4,
        }
    );
    assert_eq!(
        projection.entries()[1].observation,
        EventLogCoverageObservation::BasicBlock {
            node: node_id("vm-a"),
            guest_pc: 0x5000,
            block_len: 8,
        }
    );
    assert!(QemuShmemHotPathChannel::drain_observable_events(&mut hot_path)?.is_empty());

    Ok(())
}

#[cfg(unix)]
#[test]
fn mapped_quantum_rejects_duplicate_novelty_and_future_icount_loudly() -> Result<(), Box<dyn Error>>
{
    let duplicate_index = map_index_for(0x4010);
    let duplicate_entries = [
        CoverageEntry::new(5, 0, 0x4010, 4, duplicate_index)?,
        CoverageEntry::new(6, 0, 0x4010, 4, duplicate_index)?,
    ];
    let duplicate_region = mapped_region(6, None, &duplicate_entries)?;
    let config = qemu_config().with_coverage(BasicBlockCoverageConfig::on());
    let mut duplicate =
        QemuMappedQuantumShmemHotPath::new(config.clone(), duplicate_region, AllowAllSends)?;
    let error = QemuShmemHotPathChannel::drain_observable_events(&mut duplicate)
        .expect_err("duplicate novelty must fail the run");
    assert!(error.message.contains("published more than once"));

    let future_entries = [CoverageEntry::new(7, 0, 0x6000, 4, map_index_for(0x6000))?];
    let future_region = mapped_region(6, None, &future_entries)?;
    let mut future = QemuMappedQuantumShmemHotPath::new(config, future_region, AllowAllSends)?;
    let error = QemuShmemHotPathChannel::drain_observable_events(&mut future)
        .expect_err("future coverage must fail the run");
    assert!(error.message.contains("exceeds completed quantum boundary"));
    Ok(())
}

#[cfg(unix)]
struct AllowAllSends;

#[cfg(unix)]
impl SchedulerSendAuthorizer for AllowAllSends {
    fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError> {
        Ok(SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: 0,
        })
    }
}

#[cfg(unix)]
fn mapped_region(
    current_icount: u64,
    outbound: Option<FrameEntry>,
    coverage: &[CoverageEntry],
) -> Result<MappedSetupRegion, Box<dyn Error>> {
    let mut allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))?;
    {
        let slot = allocation.node_slot(0).ok_or("VM slot 0 should exist")?;
        let ceiling = authorize_advance_ceiling(0, current_icount, None)?;
        slot.publish_scheduler_ceiling(ceiling)?;
        slot.publish_reached_icount(current_icount, 0)?;
    }
    if let Some(frame) = outbound {
        allocation.enqueue_directed_frame(0, SLOT_NET_ROUTER as u32, &frame)?;
    }
    for entry in coverage {
        allocation.enqueue_coverage_entry(0, *entry)?;
    }

    let layout = allocation.layout();
    let bytes = allocation.setup_region_bytes()?;
    let mut temp = temp_region_file()?;
    temp.set_len(layout.region_size)?;
    temp.write_all(&bytes)?;
    Ok(mmap_setup_region(temp.as_fd(), layout.region_size)?)
}

#[cfg(unix)]
fn map_index_for(guest_pc: u64) -> u64 {
    crucible::basic_block_coverage_map_index(
        guest_pc,
        crucible_shmem::COVERAGE_QUEUE_CAPACITY as usize,
    )
    .unwrap_or_else(|error| panic!("coverage map index should fold: {error}")) as u64
}

#[cfg(unix)]
fn qemu_config() -> QemuQuantumShmemConfig {
    QemuQuantumShmemConfig::new(node_id("vm-a"), 0)
        .with_router(node_id("net-router"), SLOT_NET_ROUTER as u32)
}

#[cfg(unix)]
fn icount(retired: u64) -> Icount {
    Icount { retired }
}

#[cfg(unix)]
fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

#[cfg(unix)]
fn temp_region_file() -> Result<fs::File, Box<dyn Error>> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "crucible-qemu-mapped-quantum-{}-{}",
        std::process::id(),
        unique_temp_suffix()
    ));

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    fs::remove_file(&path)?;
    Ok(file)
}

#[cfg(unix)]
fn unique_temp_suffix() -> u64 {
    NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
}
