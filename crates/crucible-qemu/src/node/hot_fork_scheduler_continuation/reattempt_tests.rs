//! Original child installer reattempts with real mapped Restore publications.
//!
//! The fork process, released native status, capability, CLOSED frontier and
//! ACK remain explicit external providers. This executes neither QEMU nor a
//! native child; the installer, decoder, mapped arming and paired body are real.

use std::error::Error;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_protocol::native_console::NativeConsoleFrontier;
use crucible_shmem::MappedSetupRegion;

use super::*;

/// Cancels the fixture peer before a scope joins, even if an error owns QMP.
struct ScopedQmpShutdown(UnixStream);

impl Drop for ScopedQmpShutdown {
    fn drop(&mut self) {
        // Descriptor duplicates share the socket's shutdown state. A retained
        // installer error may still own the client, but cannot keep this peer
        // blocked after the scope closure returns or unwinds.
        let _result = self.0.shutdown(Shutdown::Both);
    }
}

#[derive(Debug)]
struct RetainedProcess(Box<dyn crate::QemuNodeExternalProcessControl>);

impl crate::QemuNodeExternalProcessControl for RetainedProcess {
    fn hot_fork_process_basis(&self) -> crate::QemuHotForkChildProcessBasis {
        self.0.hot_fork_process_basis()
    }

    fn process_id(&self) -> u32 {
        self.0.process_id()
    }

    fn reaped(&self) -> bool {
        self.0.reaped()
    }

    fn try_wait_natural_exit(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, crate::QemuShutdownTargetError> {
        self.0.try_wait_natural_exit()
    }

    fn send_sigterm(&mut self) -> Result<(), crate::QemuShutdownTargetError> {
        self.0.send_sigterm()
    }

    fn send_sigkill(&mut self) -> Result<(), crate::QemuShutdownTargetError> {
        self.0.send_sigkill()
    }

    fn wait_for_exit(
        &mut self,
        rung: crate::QemuShutdownRung,
        timeout: std::time::Duration,
    ) -> Result<crate::QemuChildWait, crate::QemuShutdownTargetError> {
        self.0.wait_for_exit(rung, timeout)
    }

    fn reap(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<crate::QemuReap, crate::QemuShutdownTargetError> {
        self.0.reap(timeout)
    }
}

struct WakeOnce {
    original: Box<dyn QemuPluginIpcControlChannel>,
    region: MappedSetupRegion,
    attempts: AtomicUsize,
}

impl QemuPluginIpcControlChannel for WakeOnce {
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.original.send_quit()
    }

    fn signal_stopped_control(&self) -> Result<(), QemuNodeChannelError> {
        if self.attempts.fetch_add(1, Ordering::Relaxed) == 0 {
            return Err(QemuNodeChannelError::new(
                "wake stopped child control",
                "injected original installer wake failure",
            ));
        }
        self.original.signal_stopped_control()?;

        // A native CLOSED/Restore peer is modeled here, after the real wake.
        // It consumes the actual paired request and body, never a guessed ACK.
        let result = (|| {
            let segment = self.region.native_console_segment(0)?;
            let pair = self.region.native_console_clamp_for_request(0)?;
            let body = segment.authorization.snapshot()?;
            let slot = self.region.node_slot(0)?;
            let restore = slot.pending_logical_time_restore().ok_or_else(|| {
                QemuNodeChannelError::new("model child Restore", "request is absent")
            })?;
            slot.acknowledge_logical_time_restore(restore, 100, 2)?;
            segment.frontier.store(NativeConsoleFrontier {
                sequence: 7,
                ring_end: 23,
                logical_ps: 100,
                raw_prefix: 2,
                owner: body.owner,
                accepted_advance: pair.advance,
                logical_generation: 0,
                request: pair.request,
                plan_hash: segment.capability.copy()?.plan_hash,
            })?;
            assert_eq!(
                slot.acknowledge_control_boundary(),
                pair.request.wrapping_add(1)
            );
            Ok::<_, Box<dyn Error>>(())
        })();
        result
            .map_err(|source| QemuNodeChannelError::new("model child Restore", source.to_string()))
    }
}

fn released_status(scheduler: &QemuHotForkSchedulerNodeContinuation) -> serde_json::Value {
    let request = scheduler.request;
    let identity = scheduler.endpoint_stage.identity();
    serde_json::json!({
        "schema-version": crate::qmp::QMP_HOT_FORK_CHILD_RUNTIME_SCHEMA_VERSION,
        "generation": 3, "registered": true, "manifest-consistent": true,
        "plugin-id": 1, "process-generation": request.child_process_generation(),
        "phase": "active", "callbacks-held": false, "mapping-installed": true,
        "workers-ready": false, "active": true, "failed": false,
        "parent-process-generation": request.parent_process_generation(),
        "child-process-generation": request.child_process_generation(),
        "template-generation": request.template_generation(),
        "private-ring-generation": request.private_ring_generation(),
        "plugin-endpoint-generation": request.plugin_endpoint_generation(),
        "plugin-barrier-generation": request.plugin_barrier_generation(),
        "control-socket-cookie": identity.control_socket_cookie(),
        "wake-eventfd-id": identity.wake_eventfd_id(),
        "source-mapping-start": 4096, "source-mapping-length": 4096,
        "source-mapping-offset": 0, "worker-mask": scheduler.endpoint_stage.worker_mask(),
        "parked-worker-mask": 0, "pending-worker-mask": 0,
        "worker-operations-in-flight": 0, "readiness-proof-acknowledged": false
    })
}

fn serve_released_qmp(mut socket: UnixStream, status: serde_json::Value) -> std::io::Result<()> {
    writeln!(
        socket,
        "{{\"QMP\":{{\"version\":{{}},\"capabilities\":[\"oob\"]}}}}"
    )?;
    let mut reader = BufReader::new(socket.try_clone()?);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let request: serde_json::Value = serde_json::from_str(&line)?;
        let response = match request["execute"].as_str().or(request["exec-oob"].as_str()) {
            Some("qmp_capabilities") => serde_json::json!({}),
            Some("query-status") => serde_json::json!({"status":"paused", "running":false}),
            Some("query-crucible-hot-fork-child-runtime") => status.clone(),
            command => return Err(std::io::Error::other(format!("unexpected QMP {command:?}"))),
        };
        writeln!(
            socket,
            "{}",
            serde_json::json!({"return":response, "id":request["id"]})
        )?;
    }
}

#[test]
fn child_installer_retains_ceiling_and_restore_receipt_after_failed_wake()
-> Result<(), Box<dyn Error>> {
    let (_operation_artifacts, stopped_restore_ack) =
        crate::artifact_identity::tests::modeled_stopped_restore_ack_capability()?;

    let (mut source, mut scheduler, process, mut diagnostics) =
        crate::node::tests::console_reattempt_scheduler_continuation(Some(
            stopped_restore_ack.launch_identity(),
        ))?;
    let fixture = crate::native_console_owner::ChildFixture::with_request(scheduler.request())?;
    fixture.publish_capability()?;
    let descriptor = fixture.descriptor()?;
    let region =
        crucible_shmem::mmap_setup_region(descriptor.as_fd(), fixture.region.region_len())?;
    scheduler.state.last_observed_time = VirtualTime { ticks: 100 };
    scheduler.state.last_step_ceiling = Some(Icount { retired: 200 });
    scheduler.state.native_console = Some(fixture.saved.clone());
    scheduler.state.console_calibration = Some(QemuLogicalTimeCalibration {
        logical_icount: 100,
        raw_icount: 2,
    });
    scheduler.ring_descriptor = descriptor;
    scheduler.channels.shmem_hot_path = Box::new(fixture.channel);
    let (mut wake_notifications, wake) = UnixStream::pair()?;
    scheduler.host_io_runtime = Box::new(
        crate::supervision::QemuLiveHostIoRuntime::from_shmem_fd_with_poll_interval(
            scheduler.ring_descriptor.as_fd(),
            wake.as_fd(),
            region.region_len(),
            0,
            std::time::Duration::from_millis(1),
        )?,
    );
    drop(wake);

    let status = released_status(&scheduler);
    std::thread::scope(|scope| -> Result<(), Box<dyn Error>> {
        let (host, peer) = UnixStream::pair()?;
        let shutdown = ScopedQmpShutdown(host.try_clone()?);
        let peer = scope.spawn(move || serve_released_qmp(peer, status));
        scheduler.channels.qmp_machine_control =
            Box::new(crate::QemuQmpExactSnapshotControlChannel::new(
                QemuQmpVmStateControlChannel::new(crate::QmpClient::connect(host)?),
            ));
        scheduler.channels.plugin_control = Box::new(WakeOnce {
            original: scheduler.channels.plugin_control,
            region: crucible_shmem::mmap_setup_region(
                scheduler.ring_descriptor.as_fd(),
                region.region_len(),
            )?,
            attempts: AtomicUsize::new(0),
        });

        // A stale inherited ceiling exercises the original counter validation,
        // which refuses before either ceiling or console Restore publication.
        // Boundary publication alone does not gate the original arming method.
        region.node_slot(0)?.publish_pause_quiesced(100, 2)?;
        scheduler.state.last_observed_time = VirtualTime { ticks: 99 };
        scheduler.state.last_step_ceiling = Some(Icount { retired: 99 });
        let original_slot = region.node_slot(0)?.snapshot();
        let original_control = region.node_slot(0)?.control_boundary_token();
        let refusal = scheduler
            .into_qemu_node(
                crucible::NodeId { name: "vm".into() },
                RetainedProcess(process),
                QemuShutdownPolicy::fast_test(),
                QemuAsyncDriverPolicy::fast_test(),
                QemuCrashDetector::new("child"),
                Some(&stopped_restore_ack),
            )
            .err()
            .ok_or("stale inherited ceiling did not refuse initial arming")?;
        let (mut scheduler, process, error) = refusal.into_parts();
        let expected = QemuNodeChannelError::from(crate::QemuQuantumError::NodeSlot {
            operation: "arm VMState restore ceiling",
            source: crucible_shmem::NodeSlotError::CeilingBeforePublishedCurrent {
                current_icount: 100,
                max_advance_icount: 99,
            },
        });
        assert_eq!(error, expected);
        assert!(!scheduler.child_ceiling_armed);
        assert!(scheduler.console_restore.is_none());
        assert_eq!(
            region.node_slot(0)?.snapshot().advance_publication_sequence,
            original_slot.advance_publication_sequence
        );
        assert!(
            region
                .native_console_segment(0)?
                .authorization
                .snapshot()
                .is_err()
        );

        assert_eq!(
            region.node_slot(0)?.control_boundary_token(),
            original_control
        );
        assert_eq!(
            region.node_slot(0)?.snapshot().logical_time_restore_request,
            original_slot.logical_time_restore_request
        );
        assert!(region.native_console_segment(0)?.clamp.snapshot().is_err());
        assert_eq!(
            (
                region.native_console_segment(0)?.ring.read_index(),
                region.native_console_segment(0)?.ring.write_index(),
            ),
            (23, 23)
        );

        // Correct the fixture's stale inherited bound, retaining the same
        // returned linear continuation and its sealed origins/calibration.
        scheduler.state.last_observed_time = VirtualTime { ticks: 100 };
        scheduler.state.last_step_ceiling = Some(Icount { retired: 200 });

        let failure = scheduler
            .into_qemu_node(
                crucible::NodeId { name: "vm".into() },
                RetainedProcess(process),
                QemuShutdownPolicy::fast_test(),
                QemuAsyncDriverPolicy::fast_test(),
                QemuCrashDetector::new("child"),
                Some(&stopped_restore_ack),
            )
            .err()
            .ok_or("first real installer wake was not refused")?;
        let (scheduler, process, error) = failure.into_parts();
        assert!(
            error
                .to_string()
                .contains("injected original installer wake failure")
        );
        assert!(scheduler.child_ceiling_armed);
        let segment = region.native_console_segment(0)?;
        let body = segment.authorization.snapshot()?;
        let pair = region.native_console_clamp_for_request(0)?;
        let slot = region.node_slot(0)?.snapshot();
        let deadline = scheduler
            .console_restore
            .as_ref()
            .ok_or("Restore custody absent")?
            .retained_deadline_for_test();
        assert_eq!(body.advance, pair.advance);
        assert_eq!(body.advance, slot.advance_publication_sequence);

        // Possession of another supported receipt cannot replace the launch
        // pair retained by this already-published Restore transaction.
        let (_foreign_artifacts, foreign_capability) =
            crate::artifact_identity::tests::modeled_stopped_restore_ack_capability()?;
        let failure = scheduler
            .into_qemu_node(
                crucible::NodeId { name: "vm".into() },
                RetainedProcess(process),
                QemuShutdownPolicy::fast_test(),
                QemuAsyncDriverPolicy::fast_test(),
                QemuCrashDetector::new("child"),
                Some(&foreign_capability),
            )
            .err()
            .ok_or("retained Restore accepted another launch receipt")?;
        let (scheduler, process, error) = failure.into_parts();
        assert!(error.to_string().contains("selected launch identity"));
        assert_eq!(region.node_slot(0)?.snapshot(), slot);
        assert_eq!(segment.authorization.snapshot()?, body);
        assert_eq!(segment.clamp.snapshot()?, pair);
        assert_eq!(
            scheduler
                .console_restore
                .as_ref()
                .ok_or("Restore custody absent")?
                .retained_deadline_for_test(),
            deadline,
        );

        let installed = scheduler.into_qemu_node(
            crucible::NodeId { name: "vm".into() },
            RetainedProcess(process),
            QemuShutdownPolicy::fast_test(),
            QemuAsyncDriverPolicy::fast_test(),
            QemuCrashDetector::new("child"),
            Some(&stopped_restore_ack),
        )?;
        assert_eq!(segment.authorization.snapshot()?, body);
        assert_eq!(segment.clamp.snapshot()?, pair);
        assert_eq!(
            region.node_slot(0)?.snapshot().advance_publication_sequence,
            body.advance
        );
        assert_eq!(
            region.node_slot(0)?.control_boundary_token(),
            pair.request.wrapping_add(1)
        );
        assert!(deadline.has_not_elapsed());
        assert!(installed.native_console.is_some());
        assert!(installed.hot_fork_resume_pending);
        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            (23, 23)
        );
        // The native Restore peer above is explicit fixture evidence. The
        // installed host runtime and its next fingerprint publisher are real:
        // they must retain the same accepted child custody as the mapped path.
        let host = scope.spawn(move || {
            let mut installed = installed;
            let result = installed
                .host_io_runtime
                .publish_current_execution_fingerprint(std::time::Duration::from_secs(1));
            (installed, result)
        });
        wake_notifications.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        let mut notification = [0_u8; std::mem::size_of::<u64>()];
        wake_notifications.read_exact(&mut notification)?;
        assert_eq!(u64::from_ne_bytes(notification), 1);

        let observed = region.node_slot(0)?.snapshot();
        let observation = segment.clamp.snapshot()?;
        let capture = region.fingerprint_sample(0)?.capture_request_generation();
        assert_eq!(observed.control_boundary_ack, 4);
        assert_eq!(capture, 1);
        assert_eq!(observation.request, observed.control_boundary_ack);
        assert_eq!(observation.capture, capture);
        assert_eq!(
            observation.kind,
            crucible_protocol::native_console::NativeConsoleControlKind::Observation
        );
        assert!(observation.last_issued.is_none());
        assert_eq!(observation.advance, body.advance);
        assert_eq!(observed.current_icount, 100);
        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            (23, 23)
        );
        assert!(!region.header().pause_requested());

        // A matching odd control ACK alone must not substitute for the new
        // sample. The second real wake proves the host is still waiting.
        assert_eq!(region.node_slot(0)?.acknowledge_control_boundary(), 5);
        wake_notifications.read_exact(&mut notification)?;
        assert_eq!(u64::from_ne_bytes(notification), 1);
        region
            .fingerprint_sample(0)?
            .publish(&crucible_shmem::FingerprintSample::default())?;
        assert!(
            region
                .fingerprint_sample(0)?
                .acknowledge_capture_v1(capture)
        );
        let (installed, result) = host.join().map_err(|_| "fingerprint host panicked")?;
        result?;
        assert!(installed.hot_fork_resume_pending);
        drop(installed);
        drop(shutdown);
        peer.join().map_err(|_| "released QMP peer panicked")??;
        Ok(())
    })?;

    source.release_hot_fork_plugin_endpoints()?;
    source.release_hot_fork_child_qmp()?;
    source.release_hot_fork_child_diagnostics_with_consumer(&mut diagnostics)?;
    drop(source.release_hot_fork_private_ring_mapping()?);
    source.shutdown_child()?;
    Ok(())
}

#[test]
fn missing_operation_capability_refuses_before_ceiling_pause_or_restore_publication()
-> Result<(), Box<dyn Error>> {
    let (_source_artifacts, source_launch) =
        crate::artifact_identity::tests::modeled_cold_launch_identity()?;
    let (mut source, mut scheduler, process, mut diagnostics) =
        crate::node::tests::console_reattempt_scheduler_continuation(Some(&source_launch))?;
    let fixture = crate::native_console_owner::ChildFixture::with_request(scheduler.request())?;
    fixture.publish_capability()?;
    let descriptor = fixture.descriptor()?;
    let region =
        crucible_shmem::mmap_setup_region(descriptor.as_fd(), fixture.region.region_len())?;
    scheduler.state.last_observed_time = VirtualTime { ticks: 100 };
    scheduler.state.last_step_ceiling = Some(Icount { retired: 200 });
    scheduler.state.native_console = Some(fixture.saved.clone());
    scheduler.state.console_calibration = Some(QemuLogicalTimeCalibration {
        logical_icount: 100,
        raw_icount: 2,
    });
    scheduler.ring_descriptor = descriptor;
    scheduler.channels.shmem_hot_path = Box::new(fixture.channel);

    assert_eq!(
        scheduler.authenticated_launch.as_ref(),
        Some(&source_launch)
    );
    let slot_before = region.node_slot(0)?.snapshot();
    let header_before = region.header_snapshot();
    let segment = region.native_console_segment(0)?;
    let body_before = segment.authorization.snapshot();
    let pair_before = segment.clamp.snapshot();
    let request_before = scheduler.request();
    let failure = scheduler
        .into_qemu_node(
            crucible::NodeId { name: "vm".into() },
            RetainedProcess(process),
            QemuShutdownPolicy::fast_test(),
            QemuAsyncDriverPolicy::fast_test(),
            QemuCrashDetector::new("child"),
            None,
        )
        .err()
        .ok_or("console Restore accepted an absent operation capability")?;
    let (scheduler, process, error) = failure.into_parts();

    assert!(
        error
            .to_string()
            .contains("authenticated stopped-Restore ACK")
    );
    assert_eq!(scheduler.request(), request_before);
    assert!(!scheduler.child_ceiling_armed);
    assert!(scheduler.console_restore.is_none());
    assert_eq!(region.node_slot(0)?.snapshot(), slot_before);
    assert_eq!(region.header_snapshot(), header_before);
    assert_eq!(segment.authorization.snapshot(), body_before);
    assert_eq!(segment.clamp.snapshot(), pair_before);
    assert_eq!(
        (segment.ring.read_index(), segment.ring.write_index()),
        (23, 23)
    );

    let (_foreign_artifacts, foreign) =
        crate::artifact_identity::tests::modeled_stopped_restore_ack_capability()?;
    let failure = scheduler
        .into_qemu_node(
            crucible::NodeId { name: "vm".into() },
            RetainedProcess(process),
            QemuShutdownPolicy::fast_test(),
            QemuAsyncDriverPolicy::fast_test(),
            QemuCrashDetector::new("child"),
            Some(&foreign),
        )
        .err()
        .ok_or("first-entry foreign capability authorized console Restore")?;
    let (scheduler, process, error) = failure.into_parts();
    assert!(
        error
            .to_string()
            .contains("differs from the selected launch identity")
    );
    assert!(!scheduler.child_ceiling_armed);
    assert!(scheduler.console_restore.is_none());
    assert_eq!(scheduler.request(), request_before);
    assert_eq!(region.node_slot(0)?.snapshot(), slot_before);
    assert_eq!(region.header_snapshot(), header_before);
    assert_eq!(segment.authorization.snapshot(), body_before);
    assert_eq!(segment.clamp.snapshot(), pair_before);
    assert_eq!(
        (segment.ring.read_index(), segment.ring.write_index()),
        (23, 23)
    );

    drop(scheduler);
    drop(process);
    source.release_hot_fork_plugin_endpoints()?;
    source.release_hot_fork_child_qmp()?;
    source.release_hot_fork_child_diagnostics_with_consumer(&mut diagnostics)?;
    drop(source.release_hot_fork_private_ring_mapping()?);
    source.shutdown_child()?;
    Ok(())
}

#[test]
fn child_installer_error_reaps_qmp_peer_while_continuation_is_retained()
-> Result<(), Box<dyn Error>> {
    let (_operation_artifacts, stopped_restore_ack) =
        crate::artifact_identity::tests::modeled_stopped_restore_ack_capability()?;

    let (mut source, mut scheduler, process, mut diagnostics) =
        crate::node::tests::console_reattempt_scheduler_continuation(Some(
            stopped_restore_ack.launch_identity(),
        ))?;
    let fixture = crate::native_console_owner::ChildFixture::with_request(scheduler.request())?;
    fixture.publish_capability()?;
    let descriptor = fixture.descriptor()?;
    let region =
        crucible_shmem::mmap_setup_region(descriptor.as_fd(), fixture.region.region_len())?;
    scheduler.state.last_observed_time = VirtualTime { ticks: 100 };
    scheduler.state.last_step_ceiling = Some(Icount { retired: 200 });
    scheduler.state.native_console = Some(fixture.saved.clone());
    scheduler.state.console_calibration = Some(QemuLogicalTimeCalibration {
        logical_icount: 100,
        raw_icount: 2,
    });
    scheduler.ring_descriptor = descriptor;
    scheduler.channels.shmem_hot_path = Box::new(fixture.channel);

    let status = released_status(&scheduler);
    let peer_exit = Arc::new(AtomicUsize::new(0));
    let outcome = std::thread::scope(|scope| -> Result<(), Box<dyn Error>> {
        let (host, peer) = UnixStream::pair()?;
        let _shutdown = ScopedQmpShutdown(host.try_clone()?);
        let exit = Arc::clone(&peer_exit);
        let _peer = scope.spawn(move || {
            let result = serve_released_qmp(peer, status);
            exit.store(if result.is_ok() { 1 } else { 2 }, Ordering::Release);
            result
        });
        scheduler.channels.qmp_machine_control =
            Box::new(crate::QemuQmpExactSnapshotControlChannel::new(
                QemuQmpVmStateControlChannel::new(crate::QmpClient::connect(host)?),
            ));
        scheduler.channels.plugin_control = Box::new(WakeOnce {
            original: scheduler.channels.plugin_control,
            region: crucible_shmem::mmap_setup_region(
                scheduler.ring_descriptor.as_fd(),
                region.region_len(),
            )?,
            attempts: AtomicUsize::new(0),
        });

        // `?` returns the actual error with its QMP client still owned. The
        // local shutdown guard must run before scope's automatic peer join.
        let _installed = scheduler.into_qemu_node(
            crucible::NodeId { name: "vm".into() },
            RetainedProcess(process),
            QemuShutdownPolicy::fast_test(),
            QemuAsyncDriverPolicy::fast_test(),
            QemuCrashDetector::new("child"),
            Some(&stopped_restore_ack),
        )?;
        Ok(())
    });

    let error = outcome.err().ok_or("installer wake was not refused")?;
    let retained = error
        .downcast_ref::<QemuHotForkSchedulerNodeInstallError>()
        .ok_or("the actual installer error was not retained")?;
    assert!(
        retained
            .source
            .to_string()
            .contains("injected original installer wake failure")
    );
    assert!(retained.continuation.child_ceiling_armed);
    assert!(retained.continuation.console_restore.is_some());
    let segment = region.native_console_segment(0)?;
    let body = segment.authorization.snapshot()?;
    let pair = region.native_console_clamp_for_request(0)?;
    assert_eq!(body.advance, pair.advance);
    assert_eq!(
        body.advance,
        region.node_slot(0)?.snapshot().advance_publication_sequence
    );
    assert_eq!(peer_exit.load(Ordering::Acquire), 1);

    // The error remains alive through the exit and scope-join assertions.
    drop(error);
    source.release_hot_fork_plugin_endpoints()?;
    source.release_hot_fork_child_qmp()?;
    source.release_hot_fork_child_diagnostics_with_consumer(&mut diagnostics)?;
    drop(source.release_hot_fork_private_ring_mapping()?);
    source.shutdown_child()?;
    Ok(())
}

#[test]
fn child_installer_retains_restore_after_late_unavailable_publication() -> Result<(), Box<dyn Error>>
{
    let (_operation_artifacts, stopped_restore_ack) =
        crate::artifact_identity::tests::modeled_stopped_restore_ack_capability()?;

    let (mut source, mut scheduler, process, mut diagnostics) =
        crate::node::tests::console_reattempt_scheduler_continuation(Some(
            stopped_restore_ack.launch_identity(),
        ))?;
    let fixture = crate::native_console_owner::ChildFixture::with_request(scheduler.request())?;
    fixture.publish_capability()?;
    let descriptor = fixture.descriptor()?;
    let region =
        crucible_shmem::mmap_setup_region(descriptor.as_fd(), fixture.region.region_len())?;
    scheduler.state.last_observed_time = VirtualTime { ticks: 100 };
    scheduler.state.last_step_ceiling = Some(Icount { retired: 200 });
    scheduler.state.native_console = Some(fixture.saved.clone());
    scheduler.state.console_calibration = Some(QemuLogicalTimeCalibration {
        logical_icount: 100,
        raw_icount: 2,
    });
    scheduler.ring_descriptor = descriptor;
    scheduler.channels.shmem_hot_path = Box::new(fixture.channel);
    let (_wake_notifications, wake) = UnixStream::pair()?;
    scheduler.host_io_runtime = Box::new(
        crate::supervision::QemuLiveHostIoRuntime::from_shmem_fd_with_poll_interval(
            scheduler.ring_descriptor.as_fd(),
            wake.as_fd(),
            region.region_len(),
            0,
            std::time::Duration::from_millis(1),
        )?,
    );
    drop(wake);

    let status = released_status(&scheduler);
    std::thread::scope(|scope| -> Result<(), Box<dyn Error>> {
        let (host, peer) = UnixStream::pair()?;
        let shutdown = ScopedQmpShutdown(host.try_clone()?);
        let peer = scope.spawn(move || serve_released_qmp(peer, status));
        scheduler.channels.qmp_machine_control =
            Box::new(crate::QemuQmpExactSnapshotControlChannel::new(
                QemuQmpVmStateControlChannel::new(crate::QmpClient::connect(host)?),
            ));
        scheduler.channels.plugin_control = Box::new(WakeOnce {
            original: scheduler.channels.plugin_control,
            region: crucible_shmem::mmap_setup_region(
                scheduler.ring_descriptor.as_fd(),
                region.region_len(),
            )?,
            attempts: AtomicUsize::new(0),
        });

        // The original ceiling arm does not read boundary publication. Its
        // successful advance precedes the actual console arm's coherent read.
        let original_advance = region.node_slot(0)?.snapshot().advance_publication_sequence;
        let original_control = region.node_slot(0)?.control_boundary_token();
        let mut refused = None;
        region
            .node_slot(0)?
            .publish_pause_quiesced_with_effect(100, 2, |_| {
                refused = Some(
                    scheduler
                        .into_qemu_node(
                            crucible::NodeId { name: "vm".into() },
                            RetainedProcess(process),
                            QemuShutdownPolicy::fast_test(),
                            QemuAsyncDriverPolicy::fast_test(),
                            QemuCrashDetector::new("child"),
                            Some(&stopped_restore_ack),
                        )
                        .err()
                        .ok_or("odd console publication was not refused")?,
                );
                Ok::<_, Box<dyn Error>>(())
            })?;
        let (scheduler, process, error) = refused.ok_or("late refusal is absent")?.into_parts();
        assert_eq!(
            error,
            QemuNodeChannelError::publication_unavailable("arm child console restore")
        );
        assert!(error.is_publication_unavailable());
        assert!(error.is_retryable());
        assert!(scheduler.child_ceiling_armed);
        let deadline = scheduler
            .console_restore
            .as_ref()
            .ok_or("late refusal lost the original Restore custody")?
            .retained_deadline_for_test();
        let armed_advance = original_advance.wrapping_add(2);
        let snapshot = region.node_slot(0)?.snapshot();
        assert_eq!(snapshot.advance_publication_sequence, armed_advance);
        assert_eq!(snapshot.logical_time_restore_request, 0);
        assert_eq!(
            region.node_slot(0)?.control_boundary_token(),
            original_control
        );
        let segment = region.native_console_segment(0)?;
        assert!(segment.authorization.snapshot().is_err());
        assert!(segment.clamp.snapshot().is_err());
        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            (23, 23)
        );

        let failure = scheduler
            .into_qemu_node(
                crucible::NodeId { name: "vm".into() },
                RetainedProcess(process),
                QemuShutdownPolicy::fast_test(),
                QemuAsyncDriverPolicy::fast_test(),
                QemuCrashDetector::new("child"),
                Some(&stopped_restore_ack),
            )
            .err()
            .ok_or("first real installer wake was not refused")?;
        let (mut scheduler, process, error) = failure.into_parts();
        assert!(
            error
                .to_string()
                .contains("injected original installer wake failure")
        );
        assert!(scheduler.child_ceiling_armed);
        let segment = region.native_console_segment(0)?;
        let body = segment.authorization.snapshot()?;
        let pair = region.native_console_clamp_for_request(0)?;
        let slot = region.node_slot(0)?.snapshot();
        assert_eq!(
            scheduler
                .console_restore
                .as_ref()
                .ok_or("Restore custody absent")?
                .retained_deadline_for_test(),
            deadline
        );
        // The first paired Restore owns its own original advance writer;
        // retries preserve this receipt, not the earlier ceiling-arm receipt.
        let restore_advance = armed_advance.wrapping_add(2);
        assert_eq!(body.advance, restore_advance);
        assert_eq!(body.advance, pair.advance);
        assert_eq!(body.advance, slot.advance_publication_sequence);

        // Acceptance has its own bounded publication read. A refused read
        // keeps the already-issued body/pair and does not accept the prefix.
        let mut accept_error = None;
        region
            .node_slot(0)?
            .publish_pause_quiesced_with_effect(100, 2, |_| {
                accept_error = Some(
                    scheduler
                        .console_restore
                        .as_mut()
                        .ok_or("Restore custody absent before acceptance")?
                        .accept()
                        .err()
                        .ok_or("odd acceptance publication was not refused")?,
                );
                Ok::<_, Box<dyn Error>>(())
            })?;
        let accept_error = accept_error.ok_or("acceptance refusal is absent")?;
        assert_eq!(
            accept_error,
            QemuNodeChannelError::publication_unavailable("accept child console restore")
        );
        assert!(accept_error.is_retryable());
        assert!(
            scheduler
                .console_restore
                .as_ref()
                .ok_or("acceptance refusal lost Restore custody")?
                .accepted_custody()
                .is_err()
        );
        assert_eq!(segment.authorization.snapshot()?, body);
        assert_eq!(segment.clamp.snapshot()?, pair);
        assert_eq!(
            region.node_slot(0)?.snapshot().advance_publication_sequence,
            restore_advance
        );
        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            (23, 23)
        );

        let installed = scheduler.into_qemu_node(
            crucible::NodeId { name: "vm".into() },
            RetainedProcess(process),
            QemuShutdownPolicy::fast_test(),
            QemuAsyncDriverPolicy::fast_test(),
            QemuCrashDetector::new("child"),
            Some(&stopped_restore_ack),
        )?;
        assert_eq!(segment.authorization.snapshot()?, body);
        assert_eq!(segment.clamp.snapshot()?, pair);
        assert_eq!(
            region.node_slot(0)?.snapshot().advance_publication_sequence,
            body.advance
        );
        assert_eq!(
            region.node_slot(0)?.control_boundary_token(),
            pair.request.wrapping_add(1)
        );
        assert!(deadline.has_not_elapsed());
        assert!(installed.native_console.is_some());
        assert!(installed.hot_fork_resume_pending);
        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            (23, 23)
        );
        drop(installed);
        drop(shutdown);
        peer.join().map_err(|_| "released QMP peer panicked")??;
        Ok(())
    })?;

    source.release_hot_fork_plugin_endpoints()?;
    source.release_hot_fork_child_qmp()?;
    source.release_hot_fork_child_diagnostics_with_consumer(&mut diagnostics)?;
    drop(source.release_hot_fork_private_ring_mapping()?);
    source.shutdown_child()?;
    Ok(())
}

#[test]
fn child_console_capability_refusal_remains_fatal() -> Result<(), Box<dyn Error>> {
    let (_source_artifacts, stopped_restore_ack) =
        crate::artifact_identity::tests::modeled_stopped_restore_ack_capability()?;
    let (mut source, scheduler, process, mut diagnostics) =
        crate::node::tests::console_reattempt_scheduler_continuation(Some(
            stopped_restore_ack.launch_identity(),
        ))?;
    let request = scheduler.request();
    let mut fixture = crate::native_console_owner::ChildFixture::with_request(request)?;
    let descriptor = fixture.descriptor()?;
    let region =
        crucible_shmem::mmap_setup_region(descriptor.as_fd(), fixture.region.region_len())?;
    let before = region.node_slot(0)?.snapshot();
    let segment = region.native_console_segment(0)?;
    let capability_error = segment
        .capability
        .copy()
        .err()
        .ok_or("absent capability unexpectedly decoded")?;
    let admission = QemuHotForkConsoleAdmission {
        request,
        descriptor,
        saved: fixture.saved.clone(),
        calibration: QemuLogicalTimeCalibration {
            logical_icount: 100,
            raw_icount: 2,
        },
        deadline: crate::supervision::HostSupervisionAbsoluteDeadline::checked_after(
            std::time::Duration::from_secs(1),
        )
        .ok_or("test host deadline overflows")?,
        stopped_restore_ack,
    };

    // Absent installation framing is a real mapped capability refusal, not
    // coherent publication contention and not a native phase receipt.
    let error = fixture
        .channel
        .prepare_hot_fork_console_restore(&admission)
        .err()
        .ok_or("absent capability unexpectedly admitted Restore")?;
    let expected = QemuNodeChannelError::new(
        "admit child console capability",
        crate::native_console_owner::ConsoleOwnerError::Shape(capability_error).to_string(),
    );
    assert_eq!(error, expected);
    assert!(!error.is_publication_unavailable());
    assert!(!error.is_retryable());
    let after = region.node_slot(0)?.snapshot();
    assert_eq!(
        after.advance_publication_sequence,
        before.advance_publication_sequence
    );
    assert_eq!(
        after.logical_time_restore_request,
        before.logical_time_restore_request
    );
    assert!(segment.authorization.snapshot().is_err());
    assert!(segment.clamp.snapshot().is_err());
    assert_eq!(
        (segment.ring.read_index(), segment.ring.write_index()),
        (23, 23)
    );
    drop(scheduler);
    drop(process);
    source.release_hot_fork_plugin_endpoints()?;
    source.release_hot_fork_child_qmp()?;
    source.release_hot_fork_child_diagnostics_with_consumer(&mut diagnostics)?;
    drop(source.release_hot_fork_private_ring_mapping()?);
    source.shutdown_child()?;
    Ok(())
}
