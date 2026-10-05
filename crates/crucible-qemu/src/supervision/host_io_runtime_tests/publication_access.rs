//! Coherent acquisition and effect-free mapped quantum startup controls.

#![cfg(test)]

use super::*;
use crate::{QemuMappedQuantumShmemHotPath, QemuQuantumShmemConfig, QemuShmemHotPathChannel};
use crucible::{
    BackendInput, ExecutionHorizon, Icount, SchedulerSendAuthorization, SchedulerSendAuthorizer,
};
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
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

/// Owns a real mapping and an explicitly modeled publication writer.
pub(crate) struct MappedPublication {
    pub(crate) file: std::fs::File,
    pub(crate) layout: crucible_shmem::RegionLayout,
    pub(crate) producer: MappedSetupRegion,
    pub(crate) channel: QemuMappedQuantumShmemHotPath,
    pub(crate) runtime: QemuLiveHostIoRuntime,
    pub(crate) notifications: UnixStream,
}

impl MappedPublication {
    pub(crate) fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let allocation =
            crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 8))?;
        let layout = allocation.layout();
        let mut file = std::fs::File::from(crate::spawn::memfd_region(layout.region_size)?);
        file.write_all(&allocation.setup_region_bytes()?)?;
        let (notifications, wake) = UnixStream::pair()?;
        notifications.set_nonblocking(true)?;
        let producer = crucible_shmem::mmap_setup_region(file.as_fd(), layout.region_size)?;
        let region = crucible_shmem::mmap_setup_region(file.as_fd(), layout.region_size)?;
        let channel = QemuMappedQuantumShmemHotPath::new(
            QemuQuantumShmemConfig::new(
                crucible::NodeId {
                    name: "publication".into(),
                },
                0,
            ),
            region,
            Sends,
        )?;
        let runtime = QemuLiveHostIoRuntime::from_shmem_fd(
            file.as_fd(),
            wake.as_fd(),
            layout.region_size,
            0,
        )?;
        Ok(Self {
            file,
            layout,
            producer,
            channel,
            runtime,
            notifications,
        })
    }

    pub(crate) fn set_producer_sequence(&self, sequence: u32) -> Result<(), std::io::Error> {
        self.file.write_all_at(
            &sequence.to_ne_bytes(),
            self.layout.node_slots_off + crucible_shmem::NODE_SLOT_PUBLISH_GEN_OFFSET as u64,
        )
    }

    pub(crate) fn set_scheduler_sequence(&self, sequence: u64) -> Result<(), std::io::Error> {
        self.file.write_all_at(
            &sequence.to_ne_bytes(),
            self.layout.node_slots_off
                + crucible_shmem::NODE_SLOT_ADVANCE_PUBLICATION_SEQUENCE_OFFSET as u64,
        )
    }

    pub(crate) fn horizon() -> ExecutionHorizon {
        ExecutionHorizon {
            icount: Icount { retired: 100 },
        }
    }
}

#[test]
fn both_publication_sequences_refuse_getters_and_start_without_effects()
-> Result<(), Box<dyn std::error::Error>> {
    for scheduler_busy in [false, true] {
        let mut mapped = MappedPublication::new()?;
        let original = mapped.producer.node_slot(0)?.snapshot();
        if scheduler_busy {
            mapped.set_scheduler_sequence(1)?;
        } else {
            mapped.set_producer_sequence(1)?;
        }
        assert!(mapped.producer.node_slot(0)?.try_snapshot().is_none());

        let error = mapped
            .channel
            .current_icount()
            .err()
            .ok_or("incomplete report cannot supply a clock")?;
        assert!(error.is_publication_unavailable() && error.retryable);
        let error = mapped
            .channel
            .start_quantum(
                MappedPublication::horizon(),
                crate::QemuQuantumStopCondition::Ceiling,
            )
            .err()
            .ok_or("incomplete report authorized a RUN")?;
        assert!(error.is_publication_unavailable());
        let error = mapped
            .channel
            .deliver_frame_at(
                BackendInput {
                    node: crucible::NodeId {
                        name: "publication".into(),
                    },
                    payload: vec![1, 2, 3],
                },
                Icount { retired: 1 },
            )
            .err()
            .ok_or("canary cannot publish before acquiring its origin")?;
        assert!(error.is_publication_unavailable());

        mapped.set_producer_sequence(0)?;
        mapped.set_scheduler_sequence(0)?;
        assert_eq!(mapped.producer.node_slot(0)?.try_snapshot(), Some(original));
        let network = mapped.channel.checkpoint_network_transport()?;
        assert!(network.inbound.frames.is_empty() && network.outbound.frames.is_empty());
    }
    Ok(())
}

#[test]
fn initial_busy_publication_does_not_wake_and_recovers_original_checkpoint_choice()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut mapped = MappedPublication::new()?;
    mapped.producer.node_slot(0)?.publish_scheduler_advance(
        authorize_advance_ceiling(0, 100, None)?,
        crucible_shmem::AdvanceStopCondition::Ceiling,
    )?;
    mapped.producer.node_slot(0)?.publish_idle(0, 0)?;
    let before = mapped.producer.node_slot(0)?.snapshot();
    mapped.set_producer_sequence(before.publish_gen + 1)?;
    let (mut console_writer, console_output) = UnixStream::pair()?;
    let console_spool = crate::console_observation::QemuConsoleObservationSpool::new();
    mapped.runtime = mapped.runtime.with_console_observation(
        crate::console_observation::QemuConsoleObservationReader::new(
            console_output,
            console_spool.clone(),
        )?,
    )?;
    console_writer.write_all(b"original console publication")?;
    mapped
        .runtime
        .set_advance_completion_poll_slice(Some(Duration::from_millis(5)))?;
    let budget = Duration::from_secs(1);

    assert_eq!(
        mapped
            .runtime
            .await_child(QemuAsyncWait::AdvanceCompletion, budget)?,
        QemuAsyncWaitOutcome::Pending
    );
    let mut notification = [0; 8];
    assert_eq!(
        mapped
            .notifications
            .read(&mut notification)
            .err()
            .ok_or("busy acquisition must not wake")?
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(mapped.runtime.initial_advance_wake_pending);
    assert_eq!(console_spool.try_diagnostic_tail(), Some(Vec::new()));
    assert_eq!(mapped.runtime.checkpoint_idle_coordinate, None);
    assert_eq!(mapped.runtime.completed_boundary, None);

    mapped.set_producer_sequence(before.publish_gen + 2)?;
    assert_eq!(
        mapped
            .runtime
            .repoll_child(QemuAsyncWait::AdvanceCompletion, budget)?,
        QemuAsyncWaitOutcome::Pending
    );
    assert!(!mapped.runtime.initial_advance_wake_pending);
    assert_eq!(
        console_spool.try_diagnostic_tail(),
        Some(b"original console publication".to_vec())
    );
    assert_eq!(mapped.notifications.read(&mut notification)?, 8);
    assert_eq!(u64::from_ne_bytes(notification), 1);
    assert_eq!(
        mapped.runtime.checkpoint_idle_coordinate,
        checkpoint_idle_coordinate(&before)
    );
    // The coherent checkpoint was acquired, but an unreleased original request
    // is not a completed guest boundary and must not choose another wake.
    assert_eq!(
        mapped
            .runtime
            .repoll_child(QemuAsyncWait::AdvanceCompletion, budget)?,
        QemuAsyncWaitOutcome::Pending
    );
    assert_eq!(
        mapped
            .notifications
            .read(&mut notification)
            .err()
            .ok_or("initial wake must be single use")?
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    Ok(())
}

#[test]
fn prepared_acquisition_budget_is_not_restarted_by_first_completion_wait()
-> Result<(), Box<dyn std::error::Error>> {
    let mut mapped = MappedPublication::new()?;
    mapped.set_scheduler_sequence(1)?;
    let budget = Duration::from_millis(20);
    mapped.runtime.prepare_advance_completion(budget)?;
    assert_eq!(
        mapped.runtime.await_node_publication(budget)?,
        QemuAsyncWaitOutcome::TimedOut
    );
    mapped.set_scheduler_sequence(2)?;

    assert_eq!(
        mapped
            .runtime
            .await_child(QemuAsyncWait::AdvanceCompletion, budget)?,
        QemuAsyncWaitOutcome::TimedOut
    );
    assert!(mapped.runtime.initial_advance_wake_pending);
    assert_eq!(mapped.runtime.completed_boundary, None);
    Ok(())
}

#[test]
fn handoff_acquisition_spends_the_original_clamp_budget() -> Result<(), Box<dyn std::error::Error>>
{
    let mut mapped = MappedPublication::new()?;
    let before = mapped.producer.node_slot(0)?.snapshot();
    mapped.set_producer_sequence(before.publish_gen + 1)?;
    let file = mapped.file.try_clone()?;
    let offset = mapped.layout.node_slots_off + crucible_shmem::NODE_SLOT_PUBLISH_GEN_OFFSET as u64;
    let budget = Duration::from_secs(2);

    // An independent mapped wait consumes part of the handoff policy while
    // the same real slot is odd. This modeled writer supplies no control ACK.
    let writer_wake = tempfile::tempfile()?;
    let mut writer_runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        file.as_fd(),
        writer_wake.as_fd(),
        mapped.layout.region_size,
        0,
    )?;
    let writer = std::thread::spawn(move || {
        let outcome =
            writer_runtime.await_child(QemuAsyncWait::AdvanceCompletion, Duration::from_secs(1))?;
        if outcome != QemuAsyncWaitOutcome::TimedOut {
            return Err(QemuAsyncDriverRuntimeError::new(
                "contain modeled publication writer",
                "odd slot supplied a completed boundary",
            ));
        }
        file.write_all_at(&(before.publish_gen + 2).to_ne_bytes(), offset)
            .map_err(|error| {
                QemuAsyncDriverRuntimeError::new("complete modeled publication", error.to_string())
            })
    });
    let result = mapped.runtime.fence_priming_handoff(budget);
    writer.join().map_err(|_| "modeled writer panicked")??;
    let error = result.err().ok_or("absent original ACK was accepted")?;
    let detail = error.to_string();

    assert!(detail.contains("requested token"), "{detail}");
    assert!(detail.contains("within "), "{detail}");
    assert!(
        !detail.contains("within 2s:"),
        "handoff renewed its budget: {detail}"
    );
    let retained = mapped
        .producer
        .node_slot(0)?
        .try_snapshot()
        .ok_or("coherent clamp missing")?;
    assert_eq!(retained.current_icount, before.current_icount);
    assert_eq!(retained.max_advance_icount, before.current_icount);
    assert_eq!(retained.control_boundary_ack & 1, 0);
    assert_eq!(
        retained.control_boundary_ack,
        before.control_boundary_ack + 1
    );
    Ok(())
}
