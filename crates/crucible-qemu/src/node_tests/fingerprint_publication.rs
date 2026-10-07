//! Actual mapped fingerprint reads and owned-child deadline supervision.

#![cfg(test)]

use super::*;
use crate::supervision::host_io_runtime::tests::publication_access::MappedPublication;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::process::Stdio;
use std::sync::mpsc;

fn sample(coordinate: u64) -> QemuFingerprintSample {
    QemuFingerprintSample {
        sample_icount: coordinate,
        vcpu_count: 1,
        ram_bytes: 4096,
        ram_digest: [11; 32],
        device_state_bytes: 128,
        device_state_sections: 1,
        device_state_digest: [22; 32],
        device_state_schema_digest: [33; 32],
        ..QemuFingerprintSample::default()
    }
}

fn mapped() -> Result<MappedPublication, Box<dyn Error>> {
    let mapped = MappedPublication::new()?;
    mapped.producer.node_slot(0)?.publish_scheduler_advance(
        crucible_shmem::authorize_advance_ceiling(0, 100, None)?,
        crucible_shmem::AdvanceStopCondition::Ceiling,
    )?;
    mapped.producer.node_slot(0)?.publish_reached_icount(100)?;
    Ok(mapped)
}

fn sample_sequence(mapped: &MappedPublication, sequence: u32) -> Result<(), std::io::Error> {
    mapped.file.write_all_at(
        &sequence.to_ne_bytes(),
        mapped.layout.fingerprint_sample_off
            + crucible_shmem::FINGERPRINT_SAMPLE_SLOT_GEN_OFFSET as u64,
    )
}

fn node(
    channel: impl QemuShmemHotPathChannel + 'static,
    runtime: crate::supervision::QemuLiveHostIoRuntime,
    budget: Duration,
) -> Result<(QemuNode, std::process::ChildStdin), Box<dyn Error>> {
    let mut node = scripted_node_with_options(
        shared_log(),
        ScriptedNodeOptions::default(),
        std::iter::empty(),
    )?;
    node.child.force_kill_and_reap_failed_realization()?;

    // The explicit AOS Bash child models only process liveness and owns no
    // descendants. Shared-memory and capture transport use production code.
    let mut child = Command::new("bash")
        .args(["-c", "printf R; IFS= read -r release; exit 1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let input = child.stdin.take().ok_or("owned stdin absent")?;
    let mut output = child.stdout.take().ok_or("owned stdout absent")?;
    let child = QemuNodeChild::new(child);
    let mut ready = [0];
    output.read_exact(&mut ready)?;
    assert_eq!(ready, *b"R");
    node.child = QemuNodeProcessControl::Direct(child);
    node.channels.shmem_hot_path = Box::new(channel);
    node.host_io_runtime = Box::new(runtime);
    node.async_policy.advance_completion_timeout = budget;
    Ok((node, input))
}

fn assert_no_wake(notifications: &mut std::os::unix::net::UnixStream) {
    let mut byte = [0];
    assert_eq!(
        notifications.read(&mut byte).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn busy_fingerprint_and_node_reads_preserve_deadline_without_capture() -> Result<(), Box<dyn Error>>
{
    for sample_busy in [false, true] {
        let mut mapped = mapped()?;
        if sample_busy {
            sample_sequence(&mapped, 1)?;
        } else {
            mapped
                .set_producer_sequence(mapped.producer.node_slot(0)?.snapshot().publish_gen + 1)?;
        }
        let error = mapped.channel.execution_fingerprint().unwrap_err();
        assert!(error.is_publication_unavailable());
        let MappedPublication {
            channel,
            runtime,
            producer,
            mut notifications,
            ..
        } = mapped;
        let (mut node, _input) = node(channel, runtime, Duration::from_millis(200))?;

        if sample_busy {
            assert!(matches!(
                node.fingerprint_sample(),
                Err(QemuNodeError::PublicationUnavailable { .. })
            ));
        }
        let error = node.execution_fingerprint().unwrap_err();
        assert!(error.to_string().contains("within 200ms"));
        assert_eq!(
            producer.fingerprint_sample(0)?.capture_request_generation(),
            0
        );
        assert_no_wake(&mut notifications);
        assert!(!node.child.reaped());
        node.child.force_kill_and_reap_failed_realization()?;
    }
    Ok(())
}

#[test]
fn actual_owned_exit_wins_over_expired_busy_fingerprint_wait() -> Result<(), Box<dyn Error>> {
    let mapped = mapped()?;
    sample_sequence(&mapped, 1)?;
    let MappedPublication {
        channel,
        runtime,
        producer,
        mut notifications,
        ..
    } = mapped;
    let (mut node, mut release) = node(channel, runtime, Duration::ZERO)?;
    release.write_all(b"exit\n")?;
    let pid = rustix::process::Pid::from_raw(i32::try_from(node.child.process_id())?)
        .ok_or("owned PID is not positive")?;
    rustix::process::waitid(
        rustix::process::WaitId::Pid(pid),
        rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
    )?
    .ok_or("owned child exit was not observable")?;

    let error = node.execution_fingerprint().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("QEMU exited with exit status: 1 before publishing")
    );
    assert!(node.child.reaped());
    assert_eq!(
        producer.fingerprint_sample(0)?.capture_request_generation(),
        0
    );
    assert_no_wake(&mut notifications);
    Ok(())
}

#[test]
fn coherent_first_sample_accepts_zero_budget_and_original_refusals() -> Result<(), Box<dyn Error>> {
    let mut mapped = mapped()?;
    assert!(matches!(mapped.channel.fingerprint_sample(), Ok(None)));
    let original = sample(100);
    mapped.producer.fingerprint_sample(0)?.publish(&original)?;
    let expected = crate::mapped_quantum::black_box_execution_fingerprint(
        &NodeId {
            name: "publication".into(),
        },
        &original,
    )?;
    assert_eq!(
        QemuShmemHotPathChannel::fingerprint_sample(&mut mapped.channel)?,
        original
    );
    mapped
        .producer
        .fingerprint_sample(0)?
        .publish(&sample(90))?;
    let behind = mapped.channel.execution_fingerprint().unwrap_err();
    assert!(behind.is_retryable() && !behind.is_publication_unavailable());
    mapped
        .producer
        .fingerprint_sample(0)?
        .publish(&sample(110))?;
    let ahead = mapped.channel.execution_fingerprint().unwrap_err();
    assert!(!ahead.is_retryable() && ahead.message.contains("ahead of current boundary 100"));
    let mut failed = original;
    failed.component_failures = 4;
    mapped.producer.fingerprint_sample(0)?.publish(&failed)?;
    let failure = mapped.channel.execution_fingerprint().unwrap_err();
    assert!(!failure.is_retryable() && failure.message.contains("component failure mask 0x4"));
    mapped.producer.fingerprint_sample(0)?.publish(&original)?;
    let MappedPublication {
        channel,
        runtime,
        producer,
        mut notifications,
        ..
    } = mapped;
    let (mut node, _input) = node(channel, runtime, Duration::ZERO)?;

    assert_eq!(node.execution_fingerprint()?, expected);
    assert_eq!(node.fingerprint_sample()?, original);
    assert_eq!(
        producer.fingerprint_sample(0)?.capture_request_generation(),
        0
    );
    assert_no_wake(&mut notifications);
    node.child.force_kill_and_reap_failed_realization()?;
    Ok(())
}

/// Synchronizes the test publisher only after a real mapped read reports busy.
/// Required channel methods delegate to their production owner, including the read.
struct ReadGate {
    inner: crate::QemuMappedQuantumShmemHotPath,
    busy: Option<Box<dyn FnOnce() + Send>>,
}

impl QemuShmemHotPathChannel for ReadGate {
    fn checkpoint_network_transport(
        &mut self,
    ) -> Result<crate::QemuNetworkTransportCheckpoint, QemuNodeChannelError> {
        QemuShmemHotPathChannel::checkpoint_network_transport(&mut self.inner)
    }

    fn restore_network_transport(
        &mut self,
        checkpoint: &crate::QemuNetworkTransportCheckpoint,
    ) -> Result<(), QemuNodeChannelError> {
        QemuShmemHotPathChannel::restore_network_transport(&mut self.inner, checkpoint)
    }

    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError> {
        QemuShmemHotPathChannel::current_icount(&mut self.inner)
    }

    fn logical_time_calibration(
        &mut self,
    ) -> Result<QemuLogicalTimeCalibration, QemuNodeChannelError> {
        QemuShmemHotPathChannel::logical_time_calibration(&mut self.inner)
    }

    fn virtual_timer_fire_witness(
        &mut self,
    ) -> Result<Option<QemuVirtualTimerFireWitness>, QemuNodeChannelError> {
        QemuShmemHotPathChannel::virtual_timer_fire_witness(&mut self.inner)
    }

    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
        stop_condition: crate::QemuQuantumStopCondition,
    ) -> Result<QemuNodePendingQuantum, QemuNodeChannelError> {
        QemuShmemHotPathChannel::start_quantum(&mut self.inner, horizon, stop_condition)
    }

    fn poll_quantum(
        &mut self,
        pending: &mut QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        QemuShmemHotPathChannel::poll_quantum(&mut self.inner, pending)
    }

    fn publish_preemption_command(
        &mut self,
        command: SchedulerPreemptionCommand,
    ) -> Result<(), QemuNodeChannelError> {
        QemuShmemHotPathChannel::publish_preemption_command(&mut self.inner, command)
    }

    fn enqueue_fault_command(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
    ) -> Result<(), QemuNodeChannelError> {
        QemuShmemHotPathChannel::enqueue_fault_command(&mut self.inner, header, payload)
    }

    fn dequeue_fault_result(
        &mut self,
    ) -> Result<Option<DequeuedFaultResult>, QemuNodeChannelError> {
        QemuShmemHotPathChannel::dequeue_fault_result(&mut self.inner)
    }

    fn dequeue_fault_event(&mut self) -> Result<Option<DequeuedFaultEvent>, QemuNodeChannelError> {
        QemuShmemHotPathChannel::dequeue_fault_event(&mut self.inner)
    }

    fn fault_event_pending(&mut self) -> Result<bool, QemuNodeChannelError> {
        QemuShmemHotPathChannel::fault_event_pending(&mut self.inner)
    }

    fn fault_event_count(&mut self) -> Result<usize, QemuNodeChannelError> {
        QemuShmemHotPathChannel::fault_event_count(&mut self.inner)
    }

    fn snapshot_fault_events(
        &mut self,
        destination: &mut Vec<DequeuedFaultEvent>,
        canonical_payload_bytes: &mut usize,
        configured_payload_bytes: usize,
        configured_inline_payload_bytes: usize,
    ) -> Result<(), QemuNodeError> {
        QemuShmemHotPathChannel::snapshot_fault_events(
            &mut self.inner,
            destination,
            canonical_payload_bytes,
            configured_payload_bytes,
            configured_inline_payload_bytes,
        )
    }

    fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError> {
        QemuShmemHotPathChannel::deliver_frame(&mut self.inner, input)
    }

    fn deliver_frame_at(
        &mut self,
        input: BackendInput,
        delivery_icount: Icount,
    ) -> Result<(), QemuNodeChannelError> {
        QemuShmemHotPathChannel::deliver_frame_at(&mut self.inner, input, delivery_icount)
    }

    fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError> {
        QemuShmemHotPathChannel::emit_frame(&mut self.inner)
    }

    fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeChannelError> {
        QemuShmemHotPathChannel::idle_state(&mut self.inner)
    }

    fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
        let result = QemuShmemHotPathChannel::execution_fingerprint(&mut self.inner);
        if result
            .as_ref()
            .is_err_and(|error| error.is_publication_unavailable())
            && let Some(busy) = self.busy.take()
        {
            busy();
        }
        result
    }

    fn fingerprint_sample(&mut self) -> Result<QemuFingerprintSample, QemuNodeChannelError> {
        QemuShmemHotPathChannel::fingerprint_sample(&mut self.inner)
    }
}

#[derive(Clone, Copy, Debug)]
enum Recovery {
    Current,
    Missing,
    Behind,
    AfterCapture,
}

#[test]
fn transient_busy_reads_recover_without_duplicate_capture() -> Result<(), Box<dyn Error>> {
    for recovery in [
        Recovery::Current,
        Recovery::Missing,
        Recovery::Behind,
        Recovery::AfterCapture,
    ] {
        let mapped = mapped()?;
        let original_node = mapped.producer.node_slot(0)?.snapshot();
        match recovery {
            Recovery::Current => {
                mapped
                    .producer
                    .fingerprint_sample(0)?
                    .publish(&sample(100))?;
                sample_sequence(&mapped, 3)?;
            }
            Recovery::Missing => mapped.set_producer_sequence(original_node.publish_gen + 1)?,
            Recovery::Behind => {
                mapped
                    .producer
                    .fingerprint_sample(0)?
                    .publish(&sample(90))?;
                mapped.set_producer_sequence(original_node.publish_gen + 1)?;
            }
            Recovery::AfterCapture => {}
        }
        let (busy_tx, busy_rx) = mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = mpsc::sync_channel(0);
        let MappedPublication {
            channel,
            runtime,
            producer,
            file,
            layout,
            mut notifications,
        } = mapped;
        let gate = ReadGate {
            inner: channel,
            busy: Some(Box::new(move || {
                busy_tx.send(()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            })),
        };
        let (mut node, _input) = node(gate, runtime, Duration::from_secs(2))?;
        let owner = std::thread::spawn(move || {
            let result = node.execution_fingerprint();
            (result, node)
        });

        notifications.set_nonblocking(false)?;
        notifications.set_read_timeout(Some(Duration::from_secs(3)))?;
        if matches!(recovery, Recovery::AfterCapture) {
            let mut wake = [0; 8];
            notifications.read_exact(&mut wake)?;
            assert_eq!(u64::from_ne_bytes(wake), 1);
            publish_capture(&producer, Some((&file, layout.fingerprint_sample_off)))?;
        }
        busy_rx.recv_timeout(Duration::from_secs(3))?;
        let capture_before = producer.fingerprint_sample(0)?.capture_request_generation();
        assert_eq!(
            capture_before,
            if matches!(recovery, Recovery::AfterCapture) {
                2
            } else {
                0
            }
        );

        // The read gate holds only the test caller after its genuine mapped
        // unavailable result. The explicit publisher now completes that same
        // publication; it supplies no synthetic sample or channel result.
        match recovery {
            Recovery::Current | Recovery::AfterCapture => file.write_all_at(
                &4_u32.to_ne_bytes(),
                layout.fingerprint_sample_off
                    + crucible_shmem::FINGERPRINT_SAMPLE_SLOT_GEN_OFFSET as u64,
            )?,
            Recovery::Missing | Recovery::Behind => file.write_all_at(
                &(original_node.publish_gen + 2).to_ne_bytes(),
                layout.node_slots_off + crucible_shmem::NODE_SLOT_PUBLISH_GEN_OFFSET as u64,
            )?,
        }
        resume_tx.send(())?;
        if matches!(recovery, Recovery::Missing | Recovery::Behind) {
            let mut wake = [0; 8];
            notifications.read_exact(&mut wake)?;
            assert_eq!(u64::from_ne_bytes(wake), 1);
            publish_capture(&producer, None)?;
        }
        let (result, mut node) = owner
            .join()
            .map_err(|_panic| "fingerprint owner panicked")?;
        let expected = crate::mapped_quantum::black_box_execution_fingerprint(
            &NodeId {
                name: "publication".into(),
            },
            &sample(100),
        )?;
        assert_eq!(result?, expected, "{recovery:?}");
        assert_eq!(node.fingerprint_sample()?, sample(100));
        assert_eq!(
            producer.fingerprint_sample(0)?.capture_request_generation(),
            if matches!(recovery, Recovery::Current) {
                0
            } else {
                2
            }
        );
        node.child.force_kill_and_reap_failed_realization()?;
    }
    Ok(())
}

fn publish_capture(
    producer: &crucible_shmem::MappedSetupRegion,
    interrupted: Option<(&std::fs::File, u64)>,
) -> Result<(), Box<dyn Error>> {
    let fingerprint = producer.fingerprint_sample(0)?;
    let request = fingerprint
        .pending_capture_request_v1()
        .ok_or("exact capture was not requested")?;
    assert_eq!(request, 1);
    fingerprint.publish(&sample(100))?;
    if let Some((file, offset)) = interrupted {
        // Model a subsequent interrupted writer after the complete sample was
        // published, before the host observes this capture's acknowledgement.
        file.write_all_at(
            &3_u32.to_ne_bytes(),
            offset + crucible_shmem::FINGERPRINT_SAMPLE_SLOT_GEN_OFFSET as u64,
        )?;
    }
    assert!(fingerprint.acknowledge_capture_v1(request));
    producer.node_slot(0)?.publish_control_boundary(100, 0)?;
    producer.node_slot(0)?.acknowledge_control_boundary();
    Ok(())
}
