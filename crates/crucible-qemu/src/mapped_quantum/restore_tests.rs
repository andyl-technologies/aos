//! Stopped-state restore control-boundary handshake tests.

use std::io::Write as _;
use std::os::fd::AsFd as _;

use crucible::{NodeId, SchedulerError, SchedulerSendAuthorization, SchedulerSendAuthorizer};
use crucible_shmem::{RegionAllocation, RegionConfig, mmap_setup_region};

use super::*;

struct AllowRestoreTestSends;

impl SchedulerSendAuthorizer for AllowRestoreTestSends {
    fn authorize_cross_node_send(
        &self,
        producer: &crucible::SchedulerNodeId,
        consumer: &crucible::SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError> {
        Ok(SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: 0,
        })
    }
}

#[test]
fn stopped_restore_requires_a_paired_control_boundary_ack() -> Result<(), Box<dyn std::error::Error>>
{
    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4))?;
    let layout = allocation.layout();
    let mut shmem = tempfile::tempfile()?;
    shmem.set_len(layout.region_size)?;
    shmem.write_all(&allocation.setup_region_bytes()?)?;

    let region = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let config = QemuQuantumShmemConfig::new(
        NodeId {
            name: String::from("restore-node"),
        },
        0,
    );
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(config, region, AllowRestoreTestSends)?;
    let calibration = crate::QemuLogicalTimeCalibration {
        logical_icount: 900,
        raw_icount: 17,
    };

    let boundary = hot_path.arm_logical_time_restore_boundary(calibration.logical_icount)?;
    let producer = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let slot = producer.node_slot(0)?;
    assert!(slot.control_boundary_is_requested());
    assert!(!hot_path.logical_time_restore_boundary_acknowledged(boundary, calibration)?);

    let request = slot
        .pending_logical_time_restore()
        .ok_or("logical-time request was not armed")?;
    slot.acknowledge_logical_time_restore(
        request,
        calibration.logical_icount,
        calibration.raw_icount,
    )?;
    assert!(!hot_path.logical_time_restore_boundary_acknowledged(boundary, calibration)?);
    slot.acknowledge_control_boundary();
    assert!(hot_path.logical_time_restore_boundary_acknowledged(boundary, calibration)?);

    slot.request_control_boundary(0, None)?;
    assert!(hot_path.arm_logical_time_restore_boundary(901).is_err());
    Ok(())
}
