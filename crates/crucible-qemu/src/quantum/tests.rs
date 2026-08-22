//! Tests for the QEMU per-quantum shared-memory hot path.

use super::*;

mod channel_behavior;
mod completion;
mod network_delivery;
mod source_assertions;
use crucible_shmem::{
    AdvanceCeiling, FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT, FrameEntry, NodeSlot, STATUS_IDLE,
    STATUS_RUNNING,
};
use source_assertions::{assert_source_order, function_source};

const QUANTUM_SOURCE: &str = include_str!("../quantum.rs");
static ALLOW_ALL_SENDS: AllowAllSchedulerSendAuthorizer = AllowAllSchedulerSendAuthorizer;

struct AllowAllSchedulerSendAuthorizer;

impl crucible::SchedulerSendAuthorizer for AllowAllSchedulerSendAuthorizer {
    fn authorize_cross_node_send(
        &self,
        producer: &crucible::SchedulerNodeId,
        consumer: &crucible::SchedulerNodeId,
    ) -> Result<crucible::SchedulerSendAuthorization, crucible::SchedulerError> {
        Ok(crucible::SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: 0,
        })
    }
}

#[test]
fn qemu_quantum_binds_external_shmem_and_finishes_after_plugin_report() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );

    let pending = match hot_path.start_quantum(horizon(10)) {
        Ok(pending) => pending,
        Err(error) => panic!("quantum start should publish ceiling: {error}"),
    };
    assert_eq!(slot.snapshot().max_advance_icount, 10);
    assert_eq!(slot.snapshot().current_icount, 0);
    assert!(
        hot_path
            .operation_log()
            .contains(&QemuQuantumOperation::FutexWake)
    );

    if let Err(error) = slot.publish_reached_icount(10, 0) {
        panic!("plugin report should publish through shared node slot: {error}");
    }
    let report = match hot_path.finish_quantum(pending) {
        Ok(report) => report,
        Err(error) => panic!("quantum finish should observe plugin report: {error}"),
    };

    assert_eq!(report.initial_state.current_icount, icount(0));
    assert_eq!(report.ceiling, icount(10));
    assert_eq!(report.final_state.current_icount, icount(10));
    assert_eq!(report.outcome, AdvanceOutcome::ReachedHorizon);
    assert_eq!(report.inbound_frames_consumed, 0);
    assert!(report.emitted_frames.is_empty());
    assert!(assert_qemu_quantum_hot_path_is_shmem_only(&report.operations).is_ok());
    assert!(
        report
            .operations
            .contains(&QemuQuantumOperation::ReadNodeReport)
    );
    assert!(
        report
            .operations
            .contains(&QemuQuantumOperation::StoreSchedulerCeiling)
    );
    assert!(report.operations.contains(&QemuQuantumOperation::FutexWake));
    assert!(
        report
            .operations
            .contains(&QemuQuantumOperation::ObservePluginReport)
    );
    assert_eq!(slot.snapshot().status, STATUS_RUNNING);
}

#[test]
fn qemu_quantum_start_uses_ordered_scheduler_wake_handoff() {
    let source = function_source("pub fn start_quantum(");
    assert_source_order(
        source,
        &[
            "self.record(QemuQuantumOperation::StoreSchedulerCeiling);",
            "self.record(QemuQuantumOperation::FutexWake);",
            ".publish_scheduler_inbox_and_ceiling(",
            "self.config.vm_slot,",
            "self.config.router_slot,",
            "self.view.inbound_ring,",
            "self.view.inbound_entries,",
            "&[],",
            "ceiling,",
        ],
        "QEMU start_quantum must publish RUN through the ordered inbox/ceiling/wake helper",
    );
}

#[test]
fn qemu_quantum_inbound_uses_ordered_scheduler_wake_handoff() {
    let source = function_source("fn publish_inbound_entry_and_wake(");
    assert_source_order(
        source,
        &[
            "self.record(QemuQuantumOperation::EnqueueInboundFrame);",
            "self.record(QemuQuantumOperation::StoreSchedulerCeiling);",
            "self.record(QemuQuantumOperation::FutexWake);",
            ".publish_scheduler_inbox_and_ceiling(",
            "self.config.vm_slot,",
            "entry.src_node,",
            "self.view.inbound_ring,",
            "self.view.inbound_entries,",
            "std::slice::from_ref(entry),",
            "ceiling,",
        ],
        "QEMU inbound publication must publish the nonempty inbox frame through the ordered helper",
    );
}

#[test]
fn qemu_quantum_rejects_finish_before_reaching_a_boundary() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );

    let pending = match hot_path.start_quantum(horizon(10)) {
        Ok(pending) => pending,
        Err(error) => panic!("quantum start should publish ceiling: {error}"),
    };
    let result = hot_path.finish_quantum(pending);

    assert!(matches!(
        result,
        Err(QemuQuantumError::PluginReportNotPublished {
            current_icount: 0,
            ceiling: 10,
        })
    ));
}

#[test]
fn qemu_quantum_reports_idle_before_horizon() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );

    let pending = match hot_path.start_quantum(horizon(10)) {
        Ok(pending) => pending,
        Err(error) => panic!("quantum start should publish ceiling: {error}"),
    };
    if let Err(error) = slot.publish_idle(4, 12, 0) {
        panic!("plugin idle report should publish through shared node slot: {error}");
    }
    let report = match hot_path.finish_quantum(pending) {
        Ok(report) => report,
        Err(error) => panic!("idle quantum should finish: {error}"),
    };

    assert_eq!(report.outcome, AdvanceOutcome::Paused { at: icount(4) });
    assert_eq!(report.final_state.current_icount, icount(4));
    assert_eq!(report.final_state.next_deadline, Some(icount(12)));
    assert_eq!(slot.snapshot().status, STATUS_IDLE);
    assert_eq!(slot.snapshot().idle_wake_icount, 12);
}

#[test]
fn qemu_quantum_preserves_backpressured_due_frame_for_retry() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );
    let expected = frame(5, 31, 1, b"plugin-owned");
    assert!(
        hot_path
            .enqueue_inbound_frame(QemuInboundFrame {
                delivery_icount: icount(5),
                src_node: expected.src_node,
                sequence: expected.seq,
                payload: expected.payload().unwrap_or_default().to_vec(),
            })
            .is_ok()
    );
    let pending = hot_path
        .start_quantum(horizon(5))
        .unwrap_or_else(|error| panic!("delivery quantum should start: {error}"));
    slot.publish_reached_icount(5, 0)
        .unwrap_or_else(|error| panic!("plugin boundary should publish: {error}"));
    plugin_mark_inbound_retained(&hot_path, 5);

    let report = hot_path
        .finish_quantum(pending)
        .unwrap_or_else(|error| panic!("backpressured delivery should remain canonical: {error}"));
    assert_eq!(report.inbound_frames_consumed, 0);
    assert_eq!(inbound_ring.read_index(), 0);
}

#[test]
fn qemu_quantum_caps_horizon_at_retained_fifo_head_retry() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );

    hot_path
        .enqueue_inbound_frame(QemuInboundFrame {
            delivery_icount: icount(5),
            src_node: 31,
            sequence: 1,
            payload: b"retained-head".to_vec(),
        })
        .unwrap_or_else(|error| panic!("retained head should enqueue: {error}"));
    let first = hot_path
        .start_quantum(horizon(5))
        .unwrap_or_else(|error| panic!("first delivery quantum should start: {error}"));
    slot.publish_reached_icount(5, 0)
        .unwrap_or_else(|error| panic!("first delivery boundary should publish: {error}"));
    plugin_mark_inbound_retained(&hot_path, 5);
    hot_path
        .finish_quantum(first)
        .unwrap_or_else(|error| panic!("retained delivery quantum should finish: {error}"));

    hot_path
        .enqueue_inbound_frame(QemuInboundFrame {
            delivery_icount: icount(FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT),
            src_node: 31,
            sequence: 2,
            payload: b"later-pending".to_vec(),
        })
        .unwrap_or_else(|error| panic!("later pending frame should enqueue: {error}"));
    let retry = hot_path
        .start_quantum(horizon(FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT + 10))
        .unwrap_or_else(|error| panic!("retained retry quantum should start: {error}"));

    assert_eq!(
        retry.ceiling,
        icount(5 + FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT)
    );
    let initial_publish_generation = retry.report_generation;
    assert_eq!(
        retry.completion_fence,
        Some(QemuAdvanceCompletionFence {
            initial_publish_generation,
        })
    );
}

#[test]
fn qemu_quantum_accepts_canonical_retained_frame_behind_current_icount() {
    let slot = NodeSlot::default();
    if let Err(error) = slot.publish_scheduler_ceiling(ceiling(0, 5)) {
        panic!("test ceiling should publish: {error}");
    }
    if let Err(error) = slot.publish_reached_icount(5, 0) {
        panic!("test current icount should publish: {error}");
    }
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    enqueue_raw(
        &inbound_ring,
        &mut inbound_entries,
        frame(4, 31, 7, b"retained"),
    );
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );
    plugin_mark_inbound_retained(&hot_path, 5);

    let pending = hot_path
        .start_quantum(horizon(5))
        .unwrap_or_else(|error| panic!("retained-frame quantum should start: {error}"));
    let report = hot_path
        .finish_quantum(pending)
        .unwrap_or_else(|error| panic!("retained late head should remain canonical: {error}"));

    assert_eq!(report.inbound_frames_consumed, 0);
    assert_eq!(inbound_ring.read_index(), 0);
}

#[test]
fn qemu_quantum_caps_horizon_at_next_possible_frame_delivery() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );
    let enqueue = hot_path.enqueue_inbound_frame(QemuInboundFrame {
        delivery_icount: icount(5),
        src_node: 31,
        sequence: 7,
        payload: vec![1, 2, 3],
    });
    assert!(enqueue.is_ok());

    let pending = match hot_path.start_quantum(horizon(6)) {
        Ok(pending) => pending,
        Err(error) => panic!("pending delivery should cap the quantum: {error}"),
    };
    assert_eq!(pending.requested_horizon, icount(6));
    assert_eq!(pending.ceiling, icount(5));
    assert_eq!(
        pending.completion_fence,
        Some(QemuAdvanceCompletionFence {
            initial_publish_generation: 0,
        })
    );
    let consumed = plugin_consume_inbound(&mut hot_path, 1);
    if let Err(error) = slot.publish_reached_icount(5, 0) {
        panic!("plugin should stop at the delivery boundary: {error}");
    }
    let report = match hot_path.finish_quantum(pending) {
        Ok(report) => report,
        Err(error) => panic!("delivery-capped quantum should finish: {error}"),
    };

    assert_eq!(report.ceiling, icount(5));
    assert_eq!(report.outcome, AdvanceOutcome::Paused { at: icount(5) });
    assert_eq!(report.inbound_frames_consumed, 1);
    assert_eq!(
        consumed[0].delivery_key(),
        frame(5, 31, 7, &[1, 2, 3]).delivery_key()
    );
    assert_eq!(inbound_ring.read_index(), 1);
}

#[test]
fn qemu_quantum_rejects_unproven_frame_behind_current_icount() {
    let slot = NodeSlot::default();
    if let Err(error) = slot.publish_scheduler_ceiling(ceiling(0, 5)) {
        panic!("test ceiling should publish: {error}");
    }
    if let Err(error) = slot.publish_reached_icount(5, 0) {
        panic!("test current icount should publish: {error}");
    }
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    enqueue_raw(
        &inbound_ring,
        &mut inbound_entries,
        frame(4, 31, 7, b"late"),
    );
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );

    let pending = hot_path
        .start_quantum(horizon(5))
        .unwrap_or_else(|error| panic!("late-frame rejection quantum should start: {error}"));
    assert_eq!(
        hot_path.finish_quantum(pending),
        Err(QemuQuantumError::InboundFrameNotConsumedAtDelivery {
            current_icount: 5,
            frame: frame(4, 31, 7, b"late").delivery_key(),
        })
    );
    assert_eq!(inbound_ring.read_index(), 0);
}

#[test]
fn qemu_quantum_rejects_unconsumed_mid_quantum_publication() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );

    let pending = match hot_path.start_quantum(horizon(10)) {
        Ok(pending) => pending,
        Err(error) => panic!("quantum should start with no known inbound frame: {error}"),
    };
    enqueue_raw(
        &inbound_ring,
        hot_path.view.inbound_entries,
        frame(5, 31, 7, b"late-mid-quantum"),
    );
    if let Err(error) = slot.publish_reached_icount(10, 0) {
        panic!("plugin report should publish through shared node slot: {error}");
    }

    assert_eq!(
        hot_path.finish_quantum(pending),
        Err(QemuQuantumError::InboundFrameNotConsumedAtDelivery {
            current_icount: 10,
            frame: frame(5, 31, 7, b"").delivery_key(),
        })
    );
    assert_eq!(inbound_ring.read_index(), 0);
}

#[test]
fn qemu_quantum_accepts_ledgered_mid_quantum_publication() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );

    let pending = hot_path
        .start_quantum(horizon(10))
        .unwrap_or_else(|error| panic!("quantum should start without inbound frames: {error}"));
    hot_path
        .enqueue_inbound_frame(QemuInboundFrame {
            delivery_icount: icount(5),
            src_node: 31,
            sequence: 7,
            payload: b"mid-quantum".to_vec(),
        })
        .unwrap_or_else(|error| panic!("host publication should join the ledger: {error}"));
    let consumed = plugin_consume_inbound(&mut hot_path, 1);
    slot.publish_reached_icount(10, 0)
        .unwrap_or_else(|error| panic!("plugin report should publish: {error}"));

    let report = hot_path
        .finish_quantum(pending)
        .unwrap_or_else(|error| panic!("ledgered publication should finish: {error}"));
    assert_eq!(report.inbound_frames_consumed, 1);
    assert_eq!(
        consumed[0].delivery_key(),
        frame(5, 31, 7, b"").delivery_key()
    );
}

fn hot_path<'a>(
    slot: &'a NodeSlot,
    inbound_ring: &'a RingHeader,
    inbound_entries: &'a mut [FrameEntry],
    outbound_ring: &'a RingHeader,
    outbound_entries: &'a mut [FrameEntry],
) -> QemuQuantumShmemHotPath<'a> {
    hot_path_with_send_authorizer(
        slot,
        inbound_ring,
        inbound_entries,
        outbound_ring,
        outbound_entries,
        &ALLOW_ALL_SENDS,
    )
}

fn hot_path_with_send_authorizer<'a>(
    slot: &'a NodeSlot,
    inbound_ring: &'a RingHeader,
    inbound_entries: &'a mut [FrameEntry],
    outbound_ring: &'a RingHeader,
    outbound_entries: &'a mut [FrameEntry],
    send_authorizer: &'a dyn crucible::SchedulerSendAuthorizer,
) -> QemuQuantumShmemHotPath<'a> {
    static FINGERPRINT_SAMPLE: FingerprintSampleSlot = FingerprintSampleSlot::new();
    let view = match QemuQuantumShmemView::new(
        slot,
        &FINGERPRINT_SAMPLE,
        inbound_ring,
        inbound_entries,
        outbound_ring,
        outbound_entries,
    ) {
        Ok(view) => view,
        Err(error) => panic!("view should bind to shared-memory objects: {error}"),
    };
    let config =
        QemuQuantumShmemConfig::new(node_id("vm-a"), 0).with_router(node_id("net-router"), 31);
    match QemuQuantumShmemHotPath::new(config, view, send_authorizer) {
        Ok(hot_path) => hot_path,
        Err(error) => panic!("hot path should construct: {error}"),
    }
}

fn pending_topology_scheduler() -> crucible::SingleScheduler {
    let vm = qemu_scheduler_node(&node_id("vm-a"), SchedulingNodeKind::Vm);
    let router = qemu_scheduler_node(&node_id("net-router"), SchedulingNodeKind::Network);
    let scenario = crucible::SchedulerLivenessScenario::from_canonical_material(
        "qemu-outbound-send-freeze",
        crucible::Shift::new(0).expect("test shift should be valid"),
        8,
        crucible::SimInstant { nanos: 40 },
        vec![crucible::SchedulerScenarioNode {
            id: vm.clone(),
            counter: crucible::NodeCounter { ticks: 0 },
            activity: crucible::SchedulerNodeActivity::Runnable,
            network_lookahead: crucible::NetworkLookahead::Infinite,
            exact_local_event: crucible::ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![crucible::SchedulerLookaheadEdge::new(
        vm.clone(),
        router.clone(),
        crucible::SimDuration { nanos: 20 },
    )]);
    let mut scheduler = crucible::SingleScheduler::new(scenario).expect("scenario should build");
    scheduler.queue_topology_change(crucible::SchedulerTopologyChange::new(
        1,
        crucible::SchedulerTopologyChangeTrigger::LatencyChange,
        vec![crucible::SchedulerLookaheadEdge::new(
            vm,
            router,
            crucible::SimDuration { nanos: 5 },
        )],
    ));
    scheduler
}

fn frame_entries(count: usize) -> Vec<FrameEntry> {
    vec![FrameEntry::default(); count]
}

fn enqueue_raw(ring: &RingHeader, entries: &mut [FrameEntry], frame: FrameEntry) {
    if let Err(error) = ring.enqueue(entries, &frame) {
        panic!("test frame should enqueue: {error}");
    }
}

fn plugin_consume_inbound(
    hot_path: &mut QemuQuantumShmemHotPath<'_>,
    count: usize,
) -> Vec<FrameEntry> {
    let mut frames = (0..count)
        .map(|_| {
            hot_path
                .view
                .inbound_ring
                .dequeue(hot_path.view.inbound_entries)
                .unwrap_or_else(|error| panic!("plugin dequeue should succeed: {error}"))
                .unwrap_or_else(|| panic!("plugin dequeue should find a published frame"))
        })
        .collect::<Vec<_>>();
    frames.sort_by_key(FrameEntry::delivery_key);
    frames
}

fn plugin_mark_inbound_retained(hot_path: &QemuQuantumShmemHotPath<'_>, current_icount: u64) {
    hot_path
        .view
        .inbound_ring
        .peek(hot_path.view.inbound_entries)
        .unwrap_or_else(|error| panic!("plugin retained peek should succeed: {error}"))
        .unwrap_or_else(|| panic!("plugin retained peek should find a published frame"));
    let slot = (hot_path.view.inbound_ring.read_index()
        & (hot_path.view.inbound_entries.len() as u64 - 1)) as usize;
    let entry = &hot_path.view.inbound_entries[slot];
    entry
        .record_delivery_attempt(current_icount, crucible_shmem::MAX_FRAME_DELIVERY_ATTEMPTS)
        .unwrap_or_else(|error| panic!("shared delivery attempt should succeed: {error}"));
    entry
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("shared retained mark should succeed: {error}"));
}

fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
    match FrameEntry::new(delivery_icount, src_node, seq, payload) {
        Ok(frame) => frame,
        Err(error) => panic!("test frame should fit: {error}"),
    }
}

fn horizon(retired: u64) -> ExecutionHorizon {
    ExecutionHorizon {
        icount: icount(retired),
    }
}

fn ceiling(current_icount: u64, max_advance_icount: u64) -> AdvanceCeiling {
    match authorize_advance_ceiling(current_icount, max_advance_icount, None) {
        Ok(ceiling) => ceiling,
        Err(error) => panic!("test ceiling should authorize: {error}"),
    }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}
