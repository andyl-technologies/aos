//! Coverage-generation restore regressions for the mapped hot path.

use std::io::Write as _;
use std::os::fd::AsFd as _;

use crucible::{
    BasicBlockCoverageConfig, NodeId, SchedulerError, SchedulerSendAuthorization,
    SchedulerSendAuthorizer, basic_block_coverage_map_index,
};
use crucible_shmem::{CoverageEntry, RegionAllocation, RegionConfig, mmap_setup_region};

use super::*;

struct AllowCoverageTestSends;

impl SchedulerSendAuthorizer for AllowCoverageTestSends {
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
fn acknowledged_restore_resets_host_novelty_and_coordinate_state()
-> Result<(), Box<dyn std::error::Error>> {
    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))?;
    let layout = allocation.layout();
    let mut shmem = tempfile::tempfile()?;
    shmem.set_len(layout.region_size)?;
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let map_index = u64::try_from(basic_block_coverage_map_index(
        0x4010,
        BasicBlockCoverageConfig::on().map_entries(),
    )?)?;
    {
        let mut producer = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let ring = producer.coverage_ring_mut(0)?;
        ring.header.enqueue_coverage(
            ring.entries,
            CoverageEntry::new(50, 0, 0x4010, 4, map_index)?,
        )?;
        producer.node_slot(0)?.publish_pause_quiesced(50, 50, 0)?;
    }

    let region = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let config = QemuQuantumShmemConfig::new(
        NodeId {
            name: String::from("vm-a"),
        },
        0,
    )
    .with_coverage(BasicBlockCoverageConfig::on());
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(config, region, AllowCoverageTestSends)?;
    let setup = QemuShmemHotPathChannel::drain_observable_events(&mut hot_path)?;
    assert_eq!(setup.len(), 1);

    let generation = {
        let mut producer = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let (generation, request) = {
            let slot = producer.node_slot(0)?;
            let generation = slot.arm_logical_time_restore(900)?;
            let request = slot
                .pending_logical_time_restore()
                .ok_or("restore request should be pending")?;
            (generation, request)
        };
        {
            let ring = producer.coverage_ring_mut(0)?;
            assert_eq!(ring.header.read_index(), 1);
            ring.header.discard_coverage_at_restore(ring.entries)?;
        }
        producer
            .node_slot(0)?
            .acknowledge_logical_time_restore(request, 900, 17, 0)?;
        generation
    };
    hot_path.commit_coverage_restore_generation(generation)?;

    {
        let mut producer = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let ring = producer.coverage_ring_mut(0)?;
        ring.header.enqueue_coverage(
            ring.entries,
            CoverageEntry::new(900, 0, 0x4010, 4, map_index)?,
        )?;
        producer.node_slot(0)?.publish_pause_quiesced(900, 900, 0)?;
    }
    let restored = QemuShmemHotPathChannel::drain_observable_events(&mut hot_path)?;
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].at().ticks, 900);
    Ok(())
}

#[test]
fn host_rejects_acknowledgement_before_the_plugin_empties_coverage()
-> Result<(), Box<dyn std::error::Error>> {
    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))?;
    let layout = allocation.layout();
    let mut shmem = tempfile::tempfile()?;
    shmem.set_len(layout.region_size)?;
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let generation = {
        let mut producer = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let (generation, request) = {
            let slot = producer.node_slot(0)?;
            let generation = slot.arm_logical_time_restore(40)?;
            let request = slot
                .pending_logical_time_restore()
                .ok_or("restore request should be pending")?;
            (generation, request)
        };
        {
            let ring = producer.coverage_ring_mut(0)?;
            ring.header
                .enqueue_coverage(ring.entries, CoverageEntry::new(3, 0, 0x4010, 4, 7)?)?;
        }
        producer
            .node_slot(0)?
            .acknowledge_logical_time_restore(request, 40, 3, 0)?;
        generation
    };

    let region = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let config = QemuQuantumShmemConfig::new(
        NodeId {
            name: String::from("vm-a"),
        },
        0,
    )
    .with_coverage(BasicBlockCoverageConfig::on());
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(config, region, AllowCoverageTestSends)?;
    let error = match hot_path.commit_coverage_restore_generation(generation) {
        Ok(()) => panic!("an acknowledged nonempty producer generation must fail closed"),
        Err(error) => error,
    };
    assert!(error.message.contains("coverage cursors"));
    Ok(())
}
