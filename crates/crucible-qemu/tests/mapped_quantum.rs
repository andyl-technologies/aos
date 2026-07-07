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
    AdvanceOutcome, ExecutionHorizon, Icount, NodeId, SchedulerError, SchedulerNodeId,
    SchedulerSendAuthorization, SchedulerSendAuthorizer,
};
#[cfg(unix)]
use crucible_qemu::{
    QemuMappedQuantumShmemHotPath, QemuQuantumOperation, QemuQuantumOperationPlane,
    QemuQuantumShmemConfig, QemuShmemHotPathChannel,
};
#[cfg(unix)]
use crucible_shmem::{
    FrameEntry, MappedSetupRegion, RegionAllocation, RegionConfig, SLOT_NET_ROUTER,
    authorize_advance_ceiling, mmap_setup_region,
};

#[cfg(unix)]
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
#[test]
fn mapped_quantum_split_completion_keeps_full_operation_log() -> Result<(), Box<dyn Error>> {
    let region = mapped_region(6, None)?;
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
    let region = mapped_region(7, Some(outbound))?;
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

    let layout = allocation.layout();
    let bytes = allocation.setup_region_bytes()?;
    let mut temp = temp_region_file()?;
    temp.set_len(layout.region_size)?;
    temp.write_all(&bytes)?;
    Ok(mmap_setup_region(temp.as_fd(), layout.region_size)?)
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
