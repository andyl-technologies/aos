//! Mapped deferred-selectable transport regressions.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::os::fd::AsFd as _;

use crucible::{NodeId, SchedulerError, SchedulerSendAuthorization};
use crucible_protocol::selectable_catalog_plan::{
    SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanDeclaration,
    SelectablePlanLimits, SelectablePlanPhase, SelectablePlanPresence,
};
use crucible_protocol::selectable_transport::{
    SelectablePendingTransportRecord, WHITEBOX_SHMEM_KIND_SELECTABLE_COMPLETED,
    WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING,
};
use crucible_protocol::{SelectionReply, SelectionRequest};
use crucible_shmem::{RegionAllocation, RegionConfig, WhiteboxMarkerEntry, mmap_setup_region};

use super::*;

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
fn mapped_catalog_retains_pending_until_exact_reply_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let declaration = SelectablePlanDeclaration::new(
        "network.policy",
        vec![1, 2],
        vec![1],
        vec!["network".to_owned()],
        SelectablePlanPresence::Required,
    )?;
    let continuation = SelectablePlanContinuation::new(
        SelectablePlanPhase::Frozen,
        BTreeSet::from(["network.policy".to_owned()]),
        Some(1),
        BTreeMap::new(),
        None,
        None,
    )?;
    let plan = SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 8, 8)?,
        vec![declaration],
        continuation,
    )?;
    let request = SelectionRequest::new(2, "network.policy", "epoch/4", None, 192)?;
    let record = SelectablePendingTransportRecord::new(request.clone(), 0xfeed_4000)?;

    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))?;
    let layout = allocation.layout();
    let mut shmem = tempfile::tempfile()?;
    shmem.set_len(layout.region_size)?;
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    {
        let mut producer = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let ring = producer.whitebox_marker_ring_mut(0)?;
        ring.header.enqueue_whitebox_marker(
            ring.entries,
            WhiteboxMarkerEntry::new(
                0,
                0,
                WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING,
                &record.encode()?,
            )?,
        )?;
    }

    let region = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let config = QemuQuantumShmemConfig::new(
        NodeId {
            name: String::from("vm-a"),
        },
        0,
    );
    let mut hot_path = QemuMappedQuantumShmemHotPath::new_with_selectable_catalog_plan(
        config,
        region,
        AllowMappedTestSends,
        plan,
    )?;
    let pending = hot_path.drain_pending_selectable_requests()?.remove(0);
    let reply = SelectionReply::selected(2, [1; 32], [2; 32], vec![1])?;
    hot_path.enqueue_selectable_reply(&pending, &reply)?;
    assert!(!hot_path.selectable_reply_is_checkpoint_quiescent());
    assert!(
        hot_path
            .selectable_catalog_plan()
            .and_then(|plan| plan.continuation().pending())
            .is_some()
    );

    {
        let mut producer = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let ring = producer.whitebox_marker_ring_mut(0)?;
        ring.header.enqueue_whitebox_marker(
            ring.entries,
            WhiteboxMarkerEntry::new(
                0,
                0,
                WHITEBOX_SHMEM_KIND_SELECTABLE_COMPLETED,
                &reply.encode()?,
            )?,
        )?;
    }
    assert!(hot_path.drain_observable_events()?.is_empty());
    assert!(hot_path.selectable_reply_is_checkpoint_quiescent());
    let mirrored = hot_path
        .selectable_catalog_plan()
        .ok_or("selectable plan disappeared")?;
    assert!(mirrored.continuation().pending().is_none());
    assert_eq!(mirrored.continuation().total_completed_requests(), 1);
    Ok(())
}

#[test]
fn mapped_marker_yields_one_exact_pending_request() -> Result<(), Box<dyn std::error::Error>> {
    let request = SelectionRequest::new(19, "network.policy", "epoch/4", Some(vec![2]), 192)?;
    let record = SelectablePendingTransportRecord::new(request.clone(), 0xfeed_4000)?;

    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))?;
    let layout = allocation.layout();
    let mut shmem = tempfile::tempfile()?;
    shmem.set_len(layout.region_size)?;
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    {
        let mut producer = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let ring = producer.whitebox_marker_ring_mut(0)?;
        ring.header.enqueue_whitebox_marker(
            ring.entries,
            WhiteboxMarkerEntry::new(
                0,
                3,
                WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING,
                &record.encode()?,
            )?,
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

    // An observational drain may consume the shared marker queue first, but it
    // must retain the typed causal request for its dedicated authority boundary.
    assert!(hot_path.drain_observable_events()?.is_empty());
    let pending = hot_path.drain_pending_selectable_requests()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].request(), &request);
    assert_eq!(pending[0].icount(), 0);
    assert_eq!(pending[0].vcpu_index(), 3);
    assert_eq!(pending[0].guest_virtual_address(), 0xfeed_4000);
    assert!(hot_path.drain_pending_selectable_requests()?.is_empty());
    Ok(())
}
