//! Mapped deferred-selectable transport regressions.

use std::io::Write as _;
use std::os::fd::AsFd as _;

use crucible::{NodeId, SchedulerError, SchedulerSendAuthorization};
use crucible_protocol::SelectionRequest;
use crucible_protocol::selectable_transport::{
    SelectablePendingTransportRecord, WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING,
};
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
