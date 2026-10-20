//! Transfers original accepted clamp evidence without replacing live state.

use super::*;
use crate::{QemuMappedQuantumShmemHotPath, QemuQuantumShmemConfig, QemuShmemHotPathChannel};
use crucible::{
    AdvanceOutcome, ExecutionHorizon, Icount, SchedulerSendAuthorization, SchedulerSendAuthorizer,
};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

struct Sends;

impl SchedulerSendAuthorizer for Sends {
    fn authorize_cross_node_send(
        &self,
        producer: &crucible::SchedulerNodeId,
        consumer: &crucible::SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, crucible::SchedulerError> {
        Ok(SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: 0,
        })
    }
}

fn fixture<T>(value: Result<T, impl std::fmt::Debug>) -> T {
    value.unwrap_or_else(|error| panic!("mapped completion fixture failed: {error:?}"))
}

pub(crate) struct MappedCompletion {
    pub(crate) producer: MappedSetupRegion,
    pub(crate) channel: QemuMappedQuantumShmemHotPath,
    pub(crate) runtime: QemuLiveHostIoRuntime,
    pub(crate) notifications: UnixStream,
}

impl MappedCompletion {
    pub(crate) fn new() -> Self {
        let allocation = fixture(crucible_shmem::RegionAllocation::new_model(
            crucible_shmem::RegionConfig::new(1, 8),
        ));
        let layout = allocation.layout();
        let mut file = std::fs::File::from(fixture(crate::spawn::memfd_region(layout.region_size)));
        fixture(file.write_all(&fixture(allocation.setup_region_bytes())));
        let (notifications, wake) = fixture(UnixStream::pair());
        fixture(notifications.set_read_timeout(Some(Duration::from_secs(1))));
        let producer = fixture(crucible_shmem::mmap_setup_region(
            file.as_fd(),
            layout.region_size,
        ));
        let region = fixture(crucible_shmem::mmap_setup_region(
            file.as_fd(),
            layout.region_size,
        ));
        let channel = fixture(QemuMappedQuantumShmemHotPath::new(
            QemuQuantumShmemConfig::new(
                crucible::NodeId {
                    name: "completed".into(),
                },
                0,
            ),
            region,
            Sends,
        ));
        let runtime = fixture(QemuLiveHostIoRuntime::from_shmem_fd(
            file.as_fd(),
            wake.as_fd(),
            layout.region_size,
            0,
        ));
        Self {
            producer,
            channel,
            runtime,
            notifications,
        }
    }

    fn settle(
        mut self,
        original_deadline: Option<u64>,
        accepted_deadline: Option<u64>,
        resumed: bool,
    ) -> (Self, crate::QemuNodePendingQuantum) {
        let pending = fixture(self.channel.start_quantum(
            ExecutionHorizon {
                icount: Icount { retired: 100 },
            },
            crate::QemuQuantumStopCondition::Ceiling,
        ));
        fixture(
            self.runtime
                .arm_advance_completion_fence(pending.completion_fence()),
        );
        let slot = fixture(self.producer.node_slot(0));
        fixture(slot.publish_reached_icount(100));
        if let Some(deadline) = original_deadline {
            fixture(slot.publish_idle(100, deadline));
        }
        let discovery = slot.snapshot();
        let mut runtime = self.runtime;
        let host = std::thread::spawn(move || {
            let result = runtime.clamp_completed_quantum(&discovery, Duration::from_secs(1));
            (runtime, result)
        });
        let mut counter = [0_u8; 8];
        fixture(self.notifications.read_exact(&mut counter));
        assert_eq!(u64::from_ne_bytes(counter), 1);
        if let Some(deadline) = accepted_deadline {
            fixture(slot.publish_idle(100, deadline));
        }
        fixture(slot.publish_control_boundary(100, 1));
        slot.acknowledge_control_boundary();
        if resumed {
            slot.mark_running();
        }

        let (runtime, result) = fixture(host.join());
        fixture(result);
        self.runtime = runtime;
        (self, pending)
    }

    fn capture(&self) -> crate::QemuCompletedQuantumBoundary {
        self.runtime
            .completed_quantum_boundary()
            .unwrap_or_else(|| panic!("real acknowledged clamp omitted its original evidence"))
    }
}

#[test]
fn current_deadline_evidence_survives_resume_without_changing_live_state() {
    let mut boundaries = Vec::new();
    for resumed in [false, true] {
        let (mut mapped, mut pending) = MappedCompletion::new().settle(None, None, resumed);
        let boundary = mapped.capture();
        // Force the later report to observe RUNNING in both cases. The retained
        // evidence must still describe the original control-owned idle boundary.
        fixture(mapped.producer.node_slot(0)).mark_running();
        pending.completed_boundary = Some(boundary);

        let report = fixture(mapped.channel.poll_quantum(&mut pending));

        assert_eq!(report.final_state.next_deadline, None);
        let captured = report
            .completed_boundary
            .unwrap_or_else(|| panic!("mapped report lost evidence"));
        assert_eq!(
            captured.idle_state().next_deadline,
            Some(Icount { retired: 100 })
        );
        assert_eq!(
            captured.calibration(),
            crate::QemuLogicalTimeCalibration {
                logical_icount: 100,
                raw_icount: 1
            }
        );
        boundaries.push((captured.idle_state(), captured.calibration()));
    }
    assert_eq!(boundaries[0], boundaries[1]);
}

#[test]
fn genuine_deadlines_remain_distinct_and_later_scheduler_wake_is_live() {
    for (original, accepted) in [(Some(300), 200), (None, 300)] {
        let (mut mapped, mut pending) =
            MappedCompletion::new().settle(original, Some(accepted), true);
        let boundary = mapped.capture();
        fixture(fixture(mapped.producer.node_slot(0)).publish_idle(100, 150));
        pending.completed_boundary = Some(boundary);

        let report = fixture(mapped.channel.poll_quantum(&mut pending));

        assert_eq!(
            report.final_state.next_deadline,
            Some(Icount { retired: 150 })
        );
        assert_eq!(
            report
                .completed_boundary
                .map(|value| value.idle_state().next_deadline),
            Some(Some(Icount { retired: accepted }))
        );
        assert_eq!(
            boundary.idle_state().next_deadline,
            Some(Icount { retired: accepted })
        );
    }
}

#[test]
fn foreign_mapping_and_stale_pending_refuse_before_ring_consumption() {
    let (mut first, mut first_pending) = MappedCompletion::new().settle(None, None, false);
    let (mut foreign, mut foreign_pending) = MappedCompletion::new().settle(None, None, false);
    {
        let rings = fixture(
            foreign
                .producer
                .node_directed_ring_pair_mut(0, 31, 0, 0, 31),
        );
        fixture(rings.second.header.enqueue(
            rings.second.entries,
            &fixture(crucible_shmem::FrameEntry::new(
                100,
                0,
                1,
                b"retained frame",
            )),
        ));
    }
    foreign_pending.completed_boundary = Some(first.capture());
    let original = fixture(foreign.channel.hot_fork_ring_io_snapshot());

    assert!(foreign.channel.poll_quantum(&mut foreign_pending).is_err());
    assert_eq!(
        fixture(foreign.channel.hot_fork_ring_io_snapshot()),
        original
    );
    foreign_pending.completed_boundary = Some(foreign.capture());
    let report = fixture(foreign.channel.poll_quantum(&mut foreign_pending));
    assert_eq!(report.emitted_frames.len(), 1);
    assert_eq!(report.emitted_frames[0].payload, b"retained frame");

    let mut next = fixture(first.channel.start_quantum(
        ExecutionHorizon {
            icount: Icount { retired: 200 },
        },
        crate::QemuQuantumStopCondition::Ceiling,
    ));
    next.completed_boundary = Some(first.capture());
    assert!(first.channel.poll_quantum(&mut next).is_err());
    // The old accepted evidence also cannot authorize after a new advance.
    first_pending.completed_boundary = Some(first.capture());
    assert!(first.channel.poll_quantum(&mut first_pending).is_err());
}

#[test]
fn next_arm_clears_evidence_and_wrong_request_cannot_supply_it() {
    let (mut mapped, _pending) = MappedCompletion::new().settle(None, None, false);
    let slot = fixture(mapped.producer.node_slot(0));
    let snapshot = slot.snapshot();
    let wrong = crate::QemuCompletedQuantumBoundary::accepted(
        mapped.producer.backing_identity(),
        0,
        snapshot,
        snapshot.control_boundary_ack.wrapping_add(1),
        0,
        snapshot,
    );
    assert!(wrong.is_none());
    fixture(mapped.runtime.arm_advance_completion_fence(None));
    assert!(mapped.runtime.completed_quantum_boundary().is_none());
}

/// Runs a second quantum that QEMU settles without retiring an instruction.
///
/// The node sits at tick 100 and the ceiling is one tick ahead. QEMU settles
/// the ceiling at its current clock; after the host's clamp it dispatches
/// again and settles the clamp's own advance, which replaces the slot record.
fn settle_without_retiring(
    mut mapped: MappedCompletion,
) -> (MappedCompletion, crate::QemuNodePendingQuantum) {
    let pending = fixture(mapped.channel.start_quantum(
        ExecutionHorizon {
            icount: Icount { retired: 101 },
        },
        crate::QemuQuantumStopCondition::Ceiling,
    ));
    fixture(
        mapped
            .runtime
            .arm_advance_completion_fence(pending.completion_fence()),
    );
    let slot = fixture(mapped.producer.node_slot(0));
    assert!(fixture(slot.publish_settled_icount(100, 101)));
    let discovery = slot.snapshot();
    assert!(discovery.settles_current_advance());

    let mut runtime = mapped.runtime;
    let host = std::thread::spawn(move || {
        let result = runtime.clamp_completed_quantum(&discovery, Duration::from_secs(1));
        (runtime, result)
    });
    let mut counter = [0_u8; 8];
    fixture(mapped.notifications.read_exact(&mut counter));
    fixture(slot.publish_control_boundary(100, 1));
    slot.acknowledge_control_boundary();
    let (runtime, result) = fixture(host.join());
    fixture(result);
    mapped.runtime = runtime;

    // QEMU's next pass finds the clamped ceiling already reached and settles it.
    assert!(fixture(slot.publish_settled_icount(100, 100)));
    let replaced = slot.snapshot();
    assert!(!replaced.settles(101, discovery.advance_publication_sequence));
    (mapped, pending)
}

#[test]
fn zero_retirement_settlement_reaches_its_ceiling_after_the_clamp() {
    let (mut mapped, mut first) = MappedCompletion::new().settle(None, None, false);
    first.completed_boundary = Some(mapped.capture());
    let first = fixture(mapped.channel.poll_quantum(&mut first));
    assert_eq!(first.outcome, AdvanceOutcome::ReachedHorizon);

    let (mut mapped, mut pending) = settle_without_retiring(mapped);
    pending.completed_boundary = Some(mapped.capture());
    let report = fixture(mapped.channel.poll_quantum(&mut pending));

    // Settled through 101 with the clock still at 100 (RFC-0010 SCHED-12).
    assert_eq!(report.outcome, AdvanceOutcome::ReachedHorizon);
    assert_eq!(report.ceiling, Icount { retired: 101 });
    assert_eq!(report.final_state.current_icount, Icount { retired: 100 });
}

#[test]
fn zero_retirement_settlement_needs_the_clamp_discovery_record() {
    let (mut mapped, mut first) = MappedCompletion::new().settle(None, None, false);
    first.completed_boundary = Some(mapped.capture());
    fixture(mapped.channel.poll_quantum(&mut first));

    // Without the accepted clamp, only the replaced slot record remains, and
    // it attests nothing about the pending ceiling.
    let (mut mapped, mut pending) = settle_without_retiring(mapped);
    let report = fixture(mapped.channel.poll_quantum(&mut pending));

    assert_eq!(
        report.outcome,
        AdvanceOutcome::Paused {
            at: Icount { retired: 100 }
        }
    );
}
