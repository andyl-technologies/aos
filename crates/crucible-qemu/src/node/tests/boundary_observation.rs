//! Post-completed mapped publication contention and lossless observation drains.
//!
//! The original node driver/clamp and real mapped rings execute here. The
//! publisher models QEMU's coherent slot stores; it is not guest execution.

#![cfg(test)]

use super::*;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::sync::mpsc;

use crucible_protocol::selectable_transport::{
    SelectablePendingTransportRecord, WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING,
};
use crucible_protocol::{
    SelectionRequest, WhiteboxLifecycleMarkerEvent, WhiteboxMarkerPayload,
    encode_whitebox_marker_payload_body,
};
use crucible_shmem::{MappedSetupRegion, RegionLayout, WhiteboxMarkerEntry};

use crate::supervision::host_io_runtime::tests::publication_access::MappedPublication;

struct CompletedObservation {
    node: QemuNode,
    producer: MappedSetupRegion,
    file: std::fs::File,
    layout: RegionLayout,
    notifications: std::os::unix::net::UnixStream,
}

impl CompletedObservation {
    fn new() -> Result<Self, Box<dyn Error>> {
        let MappedPublication {
            file,
            layout,
            producer,
            channel,
            runtime,
            mut notifications,
        } = MappedPublication::new()?;
        notifications.set_nonblocking(false)?;
        notifications.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut node = scripted_node(shared_log(), false, false, false)?;
        node.channels.shmem_hot_path = Box::new(channel);
        node.host_io_runtime = Box::new(runtime);
        node.async_policy = QemuAsyncDriverPolicy::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let slot = producer.node_slot(0)?;

        let node = std::thread::scope(|scope| -> Result<_, Box<dyn Error>> {
            let host = scope.spawn(move || {
                let result = Backend::advance_to_horizon(
                    &mut node,
                    ExecutionHorizon {
                        icount: Icount { retired: 100 },
                    },
                );
                (node, result)
            });
            // Service the genuine initial request and completed clamp. Each
            // notification read is bounded, and the driver's own budget remains.
            for generation in [2, 4] {
                let mut wake = [0; 8];
                loop {
                    notifications.read_exact(&mut wake)?;
                    if slot.snapshot().control_boundary_ack == generation {
                        break;
                    }
                }
                slot.publish_reached_icount(100)?;
                slot.publish_control_boundary(100, 1)?;
                slot.acknowledge_control_boundary();
                slot.mark_running();
            }
            let (node, result) = host.join().map_err(|_| "mapped node driver panicked")?;
            assert_eq!(result?, AdvanceOutcome::ReachedHorizon);
            assert!(node.completed_quantum_boundary().is_some());
            Ok(node)
        })?;
        notifications.set_nonblocking(true)?;
        Ok(Self {
            node,
            producer,
            file,
            layout,
            notifications,
        })
    }

    fn publish_sequence(&self, sequence: u32) -> Result<(), std::io::Error> {
        self.file.write_all_at(
            &sequence.to_ne_bytes(),
            self.layout.node_slots_off + crucible_shmem::NODE_SLOT_PUBLISH_GEN_OFFSET as u64,
        )
    }

    fn enqueue_setup(&mut self) -> Result<(), Box<dyn Error>> {
        let setup = WhiteboxMarkerPayload::Lifecycle(WhiteboxLifecycleMarkerEvent::SetupComplete);
        let ring = self.producer.whitebox_marker_ring_mut(0)?;
        ring.header.enqueue_whitebox_marker(
            ring.entries,
            WhiteboxMarkerEntry::new(
                100,
                0,
                setup.kind().wire_value(),
                &encode_whitebox_marker_payload_body(&setup)?,
            )?,
        )?;
        Ok(())
    }
}

#[test]
fn completed_observation_waits_for_coherence_then_drains_exactly_once() -> Result<(), Box<dyn Error>>
{
    let mut fixture = CompletedObservation::new()?;
    fixture.enqueue_setup()?;
    let original = fixture.producer.node_slot(0)?.snapshot();
    let completed = fixture.node.completed_quantum_boundary();
    fixture.publish_sequence(original.publish_gen + 1)?;
    let (entered, receiver) = mpsc::channel();
    let mut node = fixture.node;

    let (mut node, events, attempts) = std::thread::scope(|scope| -> Result<_, Box<dyn Error>> {
        let reader = scope.spawn(move || {
            let mut attempts = 0;
            let result = node.read_boundary_observation("drain observable events", |channel| {
                attempts += 1;
                let result = channel.drain_observable_events();
                if result
                    .as_ref()
                    .is_err_and(QemuNodeChannelError::is_publication_unavailable)
                {
                    let _delivered = entered.send(());
                }
                result
            });
            (node, result, attempts)
        });
        receiver.recv_timeout(Duration::from_secs(1))?;
        let ring = fixture.producer.whitebox_marker_ring_mut(0)?;
        assert_eq!(
            (ring.header.read_index(), ring.header.write_index()),
            (0, 1)
        );
        fixture.file.write_all_at(
            &(original.publish_gen + 2).to_ne_bytes(),
            fixture.layout.node_slots_off + crucible_shmem::NODE_SLOT_PUBLISH_GEN_OFFSET as u64,
        )?;
        let (node, events, attempts) = reader.join().map_err(|_| "observation reader panicked")?;
        Ok((node, events?, attempts))
    })?;
    assert!(
        attempts >= 2,
        "at least one genuine busy read must precede success"
    );
    assert_eq!(events.len(), 1);
    assert!(SimulationBackend::drain_observable_events(&mut node)?.is_empty());
    let ring = fixture.producer.whitebox_marker_ring_mut(0)?;
    assert_eq!(
        (ring.header.read_index(), ring.header.write_index()),
        (1, 1)
    );
    assert_eq!(node.completed_quantum_boundary(), completed);
    let later = fixture.producer.node_slot(0)?.snapshot();
    assert_eq!(
        later.advance_publication_sequence,
        original.advance_publication_sequence
    );
    assert_eq!(later.control_boundary_ack, original.control_boundary_ack);
    let mut wake = [0; 8];
    assert_eq!(
        fixture
            .notifications
            .read(&mut wake)
            .err()
            .ok_or("unexpected observation wake")?
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    node.shutdown_child()?;
    Ok(())
}

#[test]
fn expired_original_observation_budget_refuses_dead_odd_without_consumption()
-> Result<(), Box<dyn Error>> {
    let mut fixture = CompletedObservation::new()?;
    fixture.enqueue_setup()?;
    let original = fixture.producer.node_slot(0)?.snapshot();
    fixture.publish_sequence(original.publish_gen + 1)?;
    let budget = Duration::from_secs(1);
    // Consume the genuine RUN's already prepared deadline; do not replace it.
    assert_eq!(
        fixture
            .node
            .host_io_runtime
            .await_node_publication(budget)?,
        QemuAsyncWaitOutcome::TimedOut
    );

    let error = fixture
        .node
        .drain_scheduler_observable_events()
        .err()
        .ok_or("dead odd publication was accepted")?;
    let QemuNodeError::Crashed { status, shutdown } = error else {
        return Err("dead publication did not return a typed timeout".into());
    };
    let crate::QemuNodeRunStatus::Crashed(status) = *status else {
        return Err("dead publication did not report an infrastructure failure".into());
    };
    assert_eq!(
        status.cause,
        crate::QemuCrashCause::BoundedAwaitTimeout(crate::QemuBoundedAwaitTimeout {
            operation: "drain observable events".into(),
            timeout: budget,
        })
    );
    assert!(shutdown.reaped && !shutdown.leaked);
    assert!(fixture.node.child_reaped());
    let ring = fixture.producer.whitebox_marker_ring_mut(0)?;
    assert_eq!(
        (ring.header.read_index(), ring.header.write_index()),
        (0, 1)
    );
    Ok(())
}

#[test]
fn malformed_marker_after_partial_consumption_is_not_retried() -> Result<(), Box<dyn Error>> {
    let mut fixture = CompletedObservation::new()?;
    fixture.enqueue_setup()?;
    let setup = WhiteboxMarkerPayload::Lifecycle(WhiteboxLifecycleMarkerEvent::SetupComplete);
    let ring = fixture.producer.whitebox_marker_ring_mut(0)?;
    ring.header.enqueue_whitebox_marker(
        ring.entries,
        WhiteboxMarkerEntry::new(100, 0, setup.kind().wire_value(), &[255])?,
    )?;
    let mut attempts = 0;
    let error = fixture
        .node
        .read_boundary_observation("drain observable events", |channel| {
            attempts += 1;
            channel.drain_observable_events()
        })
        .err()
        .ok_or("malformed marker accepted")?;
    assert_eq!(attempts, 1);
    assert!(matches!(
        error,
        QemuNodeError::Channel {
            operation: "drain white-box markers",
            ..
        }
    ));
    let ring = fixture.producer.whitebox_marker_ring_mut(0)?;
    assert_eq!(
        (ring.header.read_index(), ring.header.write_index()),
        (2, 2)
    );
    fixture.node.shutdown_child()?;
    Ok(())
}

#[test]
fn completed_selectable_drain_keeps_the_original_request_and_empty_second_batch()
-> Result<(), Box<dyn Error>> {
    let mut fixture = CompletedObservation::new()?;
    let request = SelectionRequest::new(2, "network.policy", "epoch/4", None, 192)?;
    let pending = SelectablePendingTransportRecord::new(request.clone(), 0xfeed_4000, 0)?;
    fixture
        .producer
        .node_slot(0)?
        .publish_pause_quiesced(100, 1)?;
    let ring = fixture.producer.whitebox_marker_ring_mut(0)?;
    ring.header.enqueue_whitebox_marker(
        ring.entries,
        WhiteboxMarkerEntry::new(
            50,
            0,
            WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING,
            &pending.encode()?,
        )?,
    )?;

    let retained = fixture.node.drain_pending_selectable_requests()?;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].request(), &request);
    assert!(fixture.node.drain_pending_selectable_requests()?.is_empty());
    fixture.node.shutdown_child()?;
    Ok(())
}
