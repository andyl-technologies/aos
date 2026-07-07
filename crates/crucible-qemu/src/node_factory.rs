//! Linux factory for already-spawned QEMU nodes.
//!
//! This module composes the post-spawn pieces into the scheduler-facing
//! [`QemuNode`] wrapper after Linux descriptor setup and QMP negotiation have
//! already completed. It deliberately wraps VMState QMP in a shutdown-only
//! machine-control adapter so the generic backend snapshot/restore methods
//! cannot issue `savevm` or `loadvm` without the explicit realization-policy
//! authorization path.

use crucible::{Checkpoint, SchedulerSendAuthorizer};
use crucible_shmem::{SetupRegionMapError, mmap_setup_region};
use thiserror::Error;

use crate::{
    QemuAsyncDriverPolicy, QemuCrashDetector, QemuHostIoRuntime, QemuHostPluginSetup,
    QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError, QemuNode,
    QemuNodeChannelError, QemuNodeChannels, QemuNodeChild, QemuQmpMachineControlChannel,
    QemuQmpVmStateControlChannel, QemuQuantumShmemConfig, QemuShutdownPolicy, QmpTimeoutStream,
};

/// QMP machine-control adapter that only exposes graceful shutdown.
#[derive(Debug)]
pub struct QemuQmpShutdownOnlyControlChannel<S> {
    vmstate: QemuQmpVmStateControlChannel<S>,
}

impl<S> QemuQmpShutdownOnlyControlChannel<S> {
    /// Wraps an explicitly VMState-authorized QMP channel for node shutdown use.
    #[must_use]
    pub const fn new(vmstate: QemuQmpVmStateControlChannel<S>) -> Self {
        Self { vmstate }
    }

    #[cfg(test)]
    fn into_inner(self) -> QemuQmpVmStateControlChannel<S> {
        self.vmstate
    }
}

impl<S> QemuQmpMachineControlChannel for QemuQmpShutdownOnlyControlChannel<S>
where
    S: QmpTimeoutStream,
{
    fn save_checkpoint(&mut self) -> Result<Checkpoint, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "save_checkpoint",
            "generic QEMU node checkpointing requires explicit VMState policy authorization",
        ))
    }

    fn restore_checkpoint(&mut self, _checkpoint: &Checkpoint) -> Result<(), QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "restore_checkpoint",
            "generic QEMU node restore requires explicit VMState policy authorization",
        ))
    }

    fn quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.vmstate.quit().map(|_complete| ())
    }
}

/// Errors returned while assembling a completed QEMU node.
#[derive(Debug, Error)]
pub enum QemuNodeFactoryError {
    /// The completed setup memfd could not be mapped.
    #[error("completed QEMU setup region mapping failed")]
    SetupRegionMap {
        /// Underlying setup-region mapping error.
        source: SetupRegionMapError,
    },
    /// The mapped shared-memory hot-path adapter could not be created.
    #[error("mapped QEMU shared-memory hot-path binding failed")]
    MappedHotPath {
        /// Underlying mapped hot-path binding error.
        source: QemuMappedQuantumShmemHotPathError,
    },
    /// The completed setup slot did not match the shared-memory hot-path slot.
    #[error(
        "completed QEMU setup slot {setup_slot} does not match shmem config VM slot {shmem_slot}"
    )]
    SetupSlotMismatch {
        /// Slot negotiated with the plugin during setup.
        setup_slot: u32,
        /// VM slot requested by the shared-memory hot-path config.
        shmem_slot: u32,
    },
}

/// Builds a scheduler-facing QEMU node from completed Linux setup pieces.
///
/// The caller must provide an already-spawned child, a completed plugin setup,
/// an already-connected QMP VMState channel, shared-memory hot-path config, and
/// the runtime policies used by [`QemuNode`]. The returned node owns the plugin
/// IPC control channel, a mapped shared-memory hot path, and a QMP shutdown
/// adapter. Generic backend snapshot/restore operations remain disabled; VMState
/// save/load must continue to go through the explicit realization-policy API.
///
/// # Errors
///
/// Returns [`QemuNodeFactoryError`] when the completed setup slot does not match
/// the shared-memory hot-path config, when the setup memfd cannot be mapped, or
/// when the mapped hot-path adapter rejects the completed region.
pub fn build_qemu_node_from_completed_setup<S, A, R>(
    child: QemuNodeChild,
    setup: QemuHostPluginSetup,
    qmp: QemuQmpVmStateControlChannel<S>,
    shmem_config: QemuQuantumShmemConfig,
    send_authorizer: A,
    shutdown_policy: QemuShutdownPolicy,
    async_policy: QemuAsyncDriverPolicy,
    crash_detector: QemuCrashDetector,
    host_io_runtime: R,
) -> Result<QemuNode, QemuNodeFactoryError>
where
    S: QmpTimeoutStream + 'static,
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
{
    let setup_slot = setup.negotiated_handshake().slot_index;
    if setup_slot != shmem_config.vm_slot {
        return Err(QemuNodeFactoryError::SetupSlotMismatch {
            setup_slot,
            shmem_slot: shmem_config.vm_slot,
        });
    }

    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuNodeFactoryError::SetupRegionMap { source })?;
    let shmem_hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, send_authorizer)
        .map_err(|source| QemuNodeFactoryError::MappedHotPath { source })?;
    let qmp_machine_control = QemuQmpShutdownOnlyControlChannel::new(qmp);
    let channels = QemuNodeChannels::new(setup, shmem_hot_path, qmp_machine_control);

    Ok(QemuNode::new(
        child,
        channels,
        shutdown_policy,
        async_policy,
        crash_detector,
        host_io_runtime,
    ))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use std::error::Error;
    use std::io::{self, Cursor, Read, Write};
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::net::UnixStream;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    use crucible::{
        Backend, Checkpoint, CheckpointKind, ContentHash, NodeId, SchedulerError, SchedulerNodeId,
        SchedulerSendAuthorization, SchedulerSendAuthorizer,
    };
    use crucible_protocol::{
        CONTROL_PROTOCOL_VERSION, ControlLifecycleStream, PluginHandshakeConfig,
    };
    use crucible_shmem::{ABI_VERSION, RegionConfig, RegionLayout, SLOT_NET_ROUTER};
    use serde_json::Value;

    use crate::spawn::create_test_spawn_resource_pair;
    use crate::{
        QMP_CAPABILITIES_COMMAND, QMP_QUIT_COMMAND_NAME, QemuAsyncDriverRuntimeError,
        QemuAsyncWait, QemuAsyncWaitOutcome, QemuNodeChannelPlane, QemuNodeChild,
        QemuNodeLifecycleState, QemuQmpVmStateControlChannel,
    };

    use super::*;

    #[test]
    fn qmp_shutdown_only_rejects_generic_snapshot_restore_but_quits() -> Result<(), Box<dyn Error>>
    {
        let qmp = QemuQmpVmStateControlChannel::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            r#"{"return":{}}"#,
        ]))?;
        let mut control = QemuQmpShutdownOnlyControlChannel::new(qmp);
        let checkpoint = checkpoint_with_hash_byte(0xab);

        let save = QemuQmpMachineControlChannel::save_checkpoint(&mut control);
        assert!(matches!(
            save,
            Err(error)
                if error.operation == "save_checkpoint"
                    && error.message.contains("explicit VMState policy authorization")
        ));
        let restore = QemuQmpMachineControlChannel::restore_checkpoint(&mut control, &checkpoint);
        assert!(matches!(
            restore,
            Err(error)
                if error.operation == "restore_checkpoint"
                    && error.message.contains("explicit VMState policy authorization")
        ));
        QemuQmpMachineControlChannel::quit(&mut control)?;

        let stream = control.into_inner().into_inner().into_inner();
        let lines = written_json_lines(&stream)?;
        assert_eq!(
            execute_name(json_line(&lines, 0)),
            Some(QMP_CAPABILITIES_COMMAND)
        );
        assert_eq!(
            execute_name(json_line(&lines, 1)),
            Some(QMP_QUIT_COMMAND_NAME)
        );

        Ok(())
    }

    #[test]
    fn factory_assembles_node_from_completed_setup_with_shutdown_only_qmp()
    -> Result<(), Box<dyn Error>> {
        let config = RegionConfig::new(1, 4, 0);
        let layout = RegionLayout::for_config(config)?;
        let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
        let plugin_peer = thread::spawn(move || {
            plugin_peer_complete_setup(plugin_socket, PluginPeerAfterRun::WaitForQuit)
        });
        let setup =
            crate::complete_qemu_host_plugin_setup(resources.into_setup_resources(), config, 0)?;
        let child = Command::new("sleep").arg("60").spawn()?;
        let qmp = QemuQmpVmStateControlChannel::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            r#"{"return":{}}"#,
        ]))?;

        let mut node = build_qemu_node_from_completed_setup(
            QemuNodeChild::new(child),
            setup,
            qmp,
            qemu_config(),
            AllowAllSends,
            node_shutdown_policy(),
            QemuAsyncDriverPolicy::fast_test(),
            QemuCrashDetector::new("vm-a"),
            ImmediateRuntime,
        )?;

        assert_eq!(
            node.channel_roles(),
            [
                QemuNodeChannelPlane::PluginIpcControl,
                QemuNodeChannelPlane::ShmemHotPath,
                QemuNodeChannelPlane::QmpMachineControl,
            ]
        );
        assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);
        assert!(matches!(
            Backend::snapshot(&mut node),
            Err(crucible::BackendError::Rejected { message })
                if message.contains("explicit VMState policy authorization")
        ));

        let report = node.shutdown_child()?;
        assert!(report.reaped);
        assert!(node.child_reaped());
        assert_eq!(
            node.lifecycle_state(),
            QemuNodeLifecycleState::ShutdownRequested
        );

        let plugin_region = match plugin_peer.join() {
            Ok(Ok(region)) => region,
            Ok(Err(error)) => return Err(error.into()),
            Err(_panic) => return Err("plugin setup peer panicked".into()),
        };
        assert_eq!(plugin_region.region_len, layout.region_size);

        Ok(())
    }

    #[test]
    fn factory_rejects_setup_slot_mismatch_before_binding_hot_path() -> Result<(), Box<dyn Error>> {
        let config = RegionConfig::new(2, 4, 0);
        let layout = RegionLayout::for_config(config)?;
        let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
        let plugin_peer = thread::spawn(move || {
            plugin_peer_complete_setup(plugin_socket, PluginPeerAfterRun::Return)
        });
        let setup =
            crate::complete_qemu_host_plugin_setup(resources.into_setup_resources(), config, 0)?;
        let child = Command::new("sleep").arg("60").spawn()?;
        let qmp = QemuQmpVmStateControlChannel::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
        ]))?;

        let error = build_qemu_node_from_completed_setup(
            QemuNodeChild::new(child),
            setup,
            qmp,
            qemu_config_for_slot(1),
            AllowAllSends,
            node_shutdown_policy(),
            QemuAsyncDriverPolicy::fast_test(),
            QemuCrashDetector::new("vm-a"),
            ImmediateRuntime,
        )
        .err()
        .ok_or("factory should reject mismatched setup and shmem slots")?;

        assert!(matches!(
            error,
            QemuNodeFactoryError::SetupSlotMismatch {
                setup_slot: 0,
                shmem_slot: 1
            }
        ));

        let plugin_region = match plugin_peer.join() {
            Ok(Ok(region)) => region,
            Ok(Err(error)) => return Err(error.into()),
            Err(_panic) => return Err("plugin setup peer panicked".into()),
        };
        assert_eq!(plugin_region.region_len, layout.region_size);

        Ok(())
    }

    struct AllowAllSends;

    impl SchedulerSendAuthorizer for AllowAllSends {
        fn authorize_cross_node_send(
            &self,
            producer: &SchedulerNodeId,
            consumer: &SchedulerNodeId,
        ) -> Result<SchedulerSendAuthorization, SchedulerError> {
            Ok(SchedulerSendAuthorization {
                producer: producer.clone(),
                consumer: consumer.clone(),
                topology_epoch: 0,
            })
        }
    }

    struct ImmediateRuntime;

    impl QemuHostIoRuntime for ImmediateRuntime {
        fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
            Ok(())
        }

        fn await_child(
            &mut self,
            _wait: QemuAsyncWait,
            _timeout: Duration,
        ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
            Ok(QemuAsyncWaitOutcome::Completed)
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum PluginPeerAfterRun {
        Return,
        WaitForQuit,
    }

    fn plugin_peer_complete_setup(
        plugin_socket: UnixStream,
        after_run: PluginPeerAfterRun,
    ) -> Result<crucible_shmem::ValidatedSetupRegion, String> {
        let mut plugin = ControlLifecycleStream::connected_unix_stream(plugin_socket)
            .map_err(|error| error.to_string())?;
        let negotiated = plugin
            .plugin_start_handshake(PluginHandshakeConfig {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: ABI_VERSION,
            })
            .map_err(|error| error.to_string())?;
        if negotiated.slot_index != 0 {
            return Err(format!(
                "expected slot 0 from host handshake, got {}",
                negotiated.slot_index
            ));
        }

        let setup = plugin
            .plugin_recv_setup_with_descriptors()
            .map_err(|error| error.to_string())?;
        let mapped =
            crucible_shmem::mmap_setup_region(setup.descriptors.shmem_fd.as_fd(), setup.region_len)
                .map_err(|error| error.to_string())?;
        let validated = mapped
            .validate_header()
            .map_err(|error| error.to_string())?;
        assert_fd_open(setup.descriptors.wake_fd.as_raw_fd()).map_err(|error| error.to_string())?;

        plugin
            .plugin_send_ready_setup_ack()
            .map_err(|error| error.to_string())?;
        plugin
            .enter_run_via_shared_memory()
            .map_err(|error| error.to_string())?;
        if matches!(after_run, PluginPeerAfterRun::WaitForQuit) {
            plugin
                .plugin_read_run_control_frame()
                .map_err(|error| error.to_string())?;
        }

        Ok(validated)
    }

    fn assert_fd_open(fd: std::os::fd::RawFd) -> Result<(), io::Error> {
        let result = unsafe {
            // SAFETY: `fcntl` validates the descriptor number and reads flags only.
            libc::fcntl(fd, libc::F_GETFD)
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn qemu_config() -> QemuQuantumShmemConfig {
        qemu_config_for_slot(0)
    }

    fn qemu_config_for_slot(vm_slot: u32) -> QemuQuantumShmemConfig {
        QemuQuantumShmemConfig::new(node_id("vm-a"), vm_slot)
            .with_router(node_id("net-router"), SLOT_NET_ROUTER as u32)
    }

    fn node_shutdown_policy() -> QemuShutdownPolicy {
        let mut policy = QemuShutdownPolicy::fast_test();
        policy.sigterm_wait = Duration::from_secs(2);
        policy.sigkill_wait = Duration::from_secs(1);
        policy.reap_wait = Duration::from_secs(1);
        policy
    }

    fn node_id(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
        }
    }

    fn checkpoint_with_hash_byte(byte: u8) -> Checkpoint {
        Checkpoint::new(
            content_hash_with_byte(byte),
            content_hash_with_byte(byte.wrapping_add(1)),
            CheckpointKind::Fat,
        )
    }

    fn content_hash_with_byte(byte: u8) -> ContentHash {
        ContentHash { bytes: [byte; 32] }
    }

    fn scripted_qmp<const N: usize>(lines: [&str; N]) -> ScriptedQmpStream {
        let mut input = Vec::new();
        for line in lines {
            input.extend_from_slice(line.as_bytes());
            input.extend_from_slice(b"\r\n");
        }
        ScriptedQmpStream {
            read: Cursor::new(input),
            written: Vec::new(),
            read_timeouts: Vec::new(),
            write_timeouts: Vec::new(),
        }
    }

    fn written_json_lines(stream: &ScriptedQmpStream) -> Result<Vec<Value>, serde_json::Error> {
        String::from_utf8_lossy(&stream.written)
            .lines()
            .map(serde_json::from_str)
            .collect()
    }

    fn json_line(lines: &[Value], index: usize) -> &Value {
        match lines.get(index) {
            Some(line) => line,
            None => panic!("missing written QMP line {index}"),
        }
    }

    fn execute_name(value: &Value) -> Option<&str> {
        value.get("execute").and_then(Value::as_str)
    }

    #[derive(Debug)]
    struct ScriptedQmpStream {
        read: Cursor<Vec<u8>>,
        written: Vec<u8>,
        read_timeouts: Vec<Duration>,
        write_timeouts: Vec<Duration>,
    }

    impl Read for ScriptedQmpStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read.read(buf)
        }
    }

    impl Write for ScriptedQmpStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl QmpTimeoutStream for ScriptedQmpStream {
        fn set_qmp_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
            self.read_timeouts.push(timeout);
            Ok(())
        }

        fn set_qmp_write_timeout(&mut self, timeout: Duration) -> io::Result<()> {
            self.write_timeouts.push(timeout);
            Ok(())
        }
    }
}
