//! Branch-private mapped hot-fork continuation regressions.

use std::io::Write as _;
use std::os::fd::AsFd as _;
use std::sync::Arc;

use crucible::{
    AppRandomDecision, Decision, NodeId, ObservableEvent, RngStreamId, SchedulerError,
    SchedulerSendAuthorization, SchedulerSendAuthorizer, VirtualTime,
};
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;
use crucible_protocol::{SelectionReply, SelectionRequest};
use crucible_shmem::{
    FrameDeliveryKey, MappedSetupRegion, RegionAllocation, RegionConfig, mmap_setup_region,
};

use super::*;

#[derive(Clone)]
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
            topology_epoch: 19,
        })
    }
}

fn mapped_model_region() -> Result<MappedSetupRegion, Box<dyn std::error::Error>> {
    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))?;
    let layout = allocation.layout();
    let mut shmem = tempfile::tempfile()?;
    shmem.set_len(layout.region_size)?;
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    Ok(mmap_setup_region(shmem.as_fd(), layout.region_size)?)
}

#[test]
fn hot_fork_clone_copies_host_state_onto_an_independent_private_mapping()
-> Result<(), Box<dyn std::error::Error>> {
    let config = QemuQuantumShmemConfig::new(
        NodeId {
            name: String::from("vm-a"),
        },
        0,
    );
    let mut source =
        QemuMappedQuantumShmemHotPath::new(config, mapped_model_region()?, AllowMappedTestSends)?;
    source.next_router_inbound_sequence = 7;
    source.inbound_delivery_ledger.push_back(FrameDeliveryKey {
        delivery_icount: 31,
        src_node: 2,
        seq: 5,
    });
    source.next_coverage_sequence = 11;
    source.last_coverage_icount = Some(29);
    source.next_marker_sequence = 13;
    source.next_guest_introspection_request_sequence = 17;
    source.next_guest_introspection_response_sequence = 19;
    source.last_marker_icount = Some(23);
    source
        .pending_marker_events
        .push(ObservableEvent::network_delivered(
            VirtualTime { ticks: 41 },
            None,
            [1, 2, 3],
        ));
    source
        .pending_app_random_decisions
        .push(Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: String::from("vm-a"),
            },
            stream: RngStreamId::from_name("branch-private"),
            request_id: 43,
            width: 8,
            value: 47,
        }));
    source
        .pending_selectable_requests
        .push(SelectablePlanPendingRequest::new(
            SelectionRequest::new(53, "network.policy", "epoch/7", None, 192)?,
            59,
            0,
            0xfeed_4000,
        ));
    source.queued_selectable_reply = Some(SelectionReply::selected(53, [1; 32], [2; 32], vec![3])?);

    let source_identity = source.region.backing_identity();
    let mut child = source.clone_onto_hot_fork_region(mapped_model_region()?)?;

    assert_ne!(child.region.backing_identity(), source_identity);
    assert_eq!(
        child.next_router_inbound_sequence,
        source.next_router_inbound_sequence
    );
    assert_eq!(
        child.inbound_delivery_ledger,
        source.inbound_delivery_ledger
    );
    assert_eq!(child.next_coverage_sequence, source.next_coverage_sequence);
    assert_eq!(child.last_coverage_icount, source.last_coverage_icount);
    assert_eq!(child.next_marker_sequence, source.next_marker_sequence);
    assert_eq!(
        child.next_guest_introspection_request_sequence,
        source.next_guest_introspection_request_sequence
    );
    assert_eq!(
        child.next_guest_introspection_response_sequence,
        source.next_guest_introspection_response_sequence
    );
    assert_eq!(child.last_marker_icount, source.last_marker_icount);
    assert_eq!(child.pending_marker_events, source.pending_marker_events);
    assert_eq!(
        child.pending_app_random_decisions,
        source.pending_app_random_decisions
    );
    assert_eq!(
        child.pending_selectable_requests,
        source.pending_selectable_requests
    );
    assert_eq!(
        child.queued_selectable_reply,
        source.queued_selectable_reply
    );
    assert!(Arc::ptr_eq(&child.send_authorizer, &source.send_authorizer));

    child.next_router_inbound_sequence += 1;
    child.inbound_delivery_ledger.clear();
    child.pending_marker_events.clear();
    child.pending_app_random_decisions.clear();
    child.pending_selectable_requests.clear();
    child.queued_selectable_reply = None;

    assert_eq!(source.next_router_inbound_sequence, 7);
    assert_eq!(source.inbound_delivery_ledger.len(), 1);
    assert_eq!(source.pending_marker_events.len(), 1);
    assert_eq!(source.pending_app_random_decisions.len(), 1);
    assert_eq!(source.pending_selectable_requests.len(), 1);
    assert!(source.queued_selectable_reply.is_some());
    Ok(())
}
