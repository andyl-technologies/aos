//! Mapped production fault-event resource propagation regressions.

use std::io::Write as _;
use std::os::fd::AsFd as _;

use crucible::model::{FaultResourceLimitError, FaultResourceLimits};
use crucible::{NodeId, SchedulerError, SchedulerSendAuthorization};
use crucible_shmem::{
    FAULT_EVENT_HEADER_V1_BYTES, FaultCommandKind, FaultEventHeaderV1, FaultEventOutcomeV1,
    RegionAllocation, RegionConfig, enqueue_fault_event, mmap_setup_region,
};

use super::*;
use crate::ProductionFaultRuntimeError;

struct AllowMappedTestSends;

impl SchedulerSendAuthorizer for AllowMappedTestSends {
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
fn mapped_preview_preserves_exact_production_resource_coordinates()
-> Result<(), Box<dyn std::error::Error>> {
    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))?;
    let layout = allocation.layout();
    let mut shmem = tempfile::tempfile()?;
    shmem.set_len(layout.region_size)?;
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let payload = b"mapped-event-budget";
    {
        let mut producer = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let transport = producer.fault_event_transport_mut(0)?;
        enqueue_fault_event(
            transport.ring,
            transport.slots,
            transport.arena_header,
            transport.arena,
            transport.arena_region_offset,
            FaultEventHeaderV1 {
                command_kind: FaultCommandKind::CpuService,
                outcome: FaultEventOutcomeV1::Applied,
                event_sequence: 1,
                rule_command_sequence: 1,
                observed_icount: 1,
                model_phase: 1,
                target_kind: 1,
                generation: 1,
                binding_hash: [1; 32],
                opportunity_hash: [2; 32],
                action_hash: [3; 32],
                target_hash: [4; 32],
                before_hash: [5; 32],
                after_hash: [6; 32],
                evidence_hash: [7; 32],
                payload_hash: [0; 32],
                payload_offset: 0,
                payload_length: 0,
            },
            payload,
        )?;
    }

    let region = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let config = QemuQuantumShmemConfig::new(
        NodeId {
            name: String::from("vm-a"),
        },
        0,
    );
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(config, region, AllowMappedTestSends)?;
    let mut preview = Vec::with_capacity(1);
    let mut current = 9;
    let requested = payload.len() + FAULT_EVENT_HEADER_V1_BYTES;
    let configured = current + requested - 1;
    let error = QemuShmemHotPathChannel::snapshot_fault_events(
        &mut hot_path,
        &mut preview,
        &mut current,
        configured,
        payload.len(),
    )
    .err()
    .ok_or("mapped preview should reject the aggregate byte limit")?;
    let production = crate::production_fault_runtime::map_fault_event_drain_error(error);

    assert!(matches!(
        production,
        ProductionFaultRuntimeError::ResourceLimit(FaultResourceLimitError::Exceeded {
            field: "event_log_bytes",
            current: 9,
            requested: observed_requested,
            configured: observed_configured,
            hard,
        }) if observed_requested == requested as u64
            && observed_configured == configured as u64
            && hard == FaultResourceLimits::compiled_maximum().event_log_bytes
    ));
    assert!(preview.is_empty());
    assert_eq!(current, 9);
    assert_eq!(
        QemuShmemHotPathChannel::fault_event_count(&mut hot_path)?,
        1
    );
    Ok(())
}
