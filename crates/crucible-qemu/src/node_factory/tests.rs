//! Tests for Linux QEMU node factory composition.

use std::collections::BTreeMap;
use std::error::Error;
use std::io::{self, Cursor, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crucible::{
    Backend, Checkpoint, CheckpointKind, ContentHash, Icount, NodeBlobRef, NodeId, ReadyPoint,
    SchedulerError, SchedulerNodeId, SchedulerSendAuthorization, SchedulerSendAuthorizer,
    SimulationBackend, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};
use crucible_protocol::{CONTROL_PROTOCOL_VERSION, ControlLifecycleStream, PluginHandshakeConfig};
use crucible_shmem::{ABI_VERSION, RegionConfig, RegionLayout, SLOT_NET_ROUTER};
use serde_json::Value;

use crate::spawn::create_test_spawn_resource_pair;
use crate::{
    LaunchProfileCandidate, QMP_CAPABILITIES_COMMAND, QMP_CONT_COMMAND, QMP_JOB_DISMISS_COMMAND,
    QMP_QUERY_JOBS_COMMAND, QMP_QUERY_STATUS_COMMAND, QMP_QUIT_COMMAND_NAME,
    QMP_SNAPSHOT_DELETE_COMMAND, QMP_SNAPSHOT_LOAD_COMMAND, QMP_SNAPSHOT_SAVE_COMMAND,
    QMP_STOP_COMMAND, QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome,
    QemuBakedGenesisRestoreAdmission, QemuBakedGenesisSnapshot, QemuExactSnapshotPolicy,
    QemuLaunchArtifact, QemuLaunchCommand, QemuLaunchCommandBuilder, QemuLaunchPluginConfig,
    QemuLoadvmCommandAuthorization, QemuLoadvmCommandPurpose, QemuLoadvmRealizationAdmission,
    QemuNodeChannelPlane, QemuNodeChild, QemuNodeLifecycleState, QemuQmpVmStateControlChannel,
    QemuVmLaunchConfig,
};

use super::*;

mod probe_restore;
mod restore_continuation;

#[test]
fn qmp_node_control_saves_deletes_and_quits() -> Result<(), Box<dyn Error>> {
    let (stream, written) = scripted_qmp_with_written([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-save-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-delete-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
    ]);
    let qmp = QemuQmpVmStateControlChannel::connect(stream)?;
    let mut control = QemuQmpExactSnapshotControlChannel::new(qmp);
    let checkpoint = checkpoint_with_hash_byte(0xab);

    QemuQmpMachineControlChannel::save_checkpoint_vmstate(&mut control, &checkpoint)?;
    QemuQmpMachineControlChannel::delete_checkpoint_vmstate(&mut control, &checkpoint)?;
    QemuQmpMachineControlChannel::quit(&mut control)?;

    drop(control);
    let lines = written_json_lines_from_shared(&written)?;
    assert_eq!(
        execute_name(json_line(&lines, 0)),
        Some(QMP_CAPABILITIES_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_SNAPSHOT_SAVE_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 3)),
        Some(QMP_JOB_DISMISS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 4)),
        Some(QMP_SNAPSHOT_DELETE_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 5)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 6)),
        Some(QMP_JOB_DISMISS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 7)),
        Some(QMP_QUIT_COMMAND_NAME)
    );

    Ok(())
}

#[test]
fn factory_assembles_node_with_exact_snapshot_qmp_control() -> Result<(), Box<dyn Error>> {
    let config = RegionConfig::new(1, 4, 0);
    let layout = RegionLayout::for_config(config)?;
    let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
    let plugin_peer = thread::spawn(move || {
        plugin_peer_complete_setup(plugin_socket, PluginPeerAfterRun::WaitForQuit)
    });
    let setup = crate::complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        config,
        0,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    )?;
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
        node_factory_runtime(),
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
            if message.contains("capture_exact_snapshot")
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
fn post_load_host_restore_failure_kills_child_without_resuming_qemu() -> Result<(), Box<dyn Error>>
{
    let config = RegionConfig::new(1, 4, 0);
    let layout = RegionLayout::for_config(config)?;
    let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
    let plugin_peer = thread::spawn(move || {
        plugin_peer_complete_setup(plugin_socket, PluginPeerAfterRun::Return)
    });
    let setup = crate::complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        config,
        0,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    )?;
    let child = Command::new("sleep").arg("60").spawn()?;
    let child_pid = child.id();
    let (qmp_stream, qmp_written) = scripted_qmp_with_written([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"running":true,"status":"running"}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"running":false,"status":"paused"}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-load-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
    ]);
    let qmp = QemuQmpVmStateControlChannel::connect(qmp_stream)?;
    let checkpoint = checkpoint_with_hash_byte(0xab);
    let runtime = QemuNodeFactoryRuntime::new(
        qemu_config_for_slot(0),
        AllowAllSends,
        node_shutdown_policy(),
        QemuAsyncDriverPolicy::fast_test(),
        QemuCrashDetector::new("vm-a"),
        FailRestoreRuntime,
    );

    let result = build_qemu_node_from_restored_checkpoint(
        QemuNodeChild::new(child),
        setup,
        qmp,
        QemuNodeRestorePlan::new(
            &checkpoint,
            QemuLoadvmCommandAuthorization::runtime_realization_for_test(),
            test_admission(),
        ),
        runtime,
    );
    assert!(matches!(
        result,
        Err(QemuNodeFactoryError::HostIoCheckpointRestore { .. })
    ));
    assert_process_is_gone(child_pid)?;
    match plugin_peer.join() {
        Ok(Ok(_region)) => {}
        Ok(Err(error)) => return Err(error.into()),
        Err(_panic) => return Err("plugin setup peer panicked".into()),
    }

    let lines = written_json_lines_from_shared(&qmp_written)?;
    assert_eq!(lines.len(), 7);
    assert!(
        lines
            .iter()
            .all(|line| execute_name(line) != Some(QMP_CONT_COMMAND))
    );
    Ok(())
}

#[test]
fn missing_post_load_calibration_ack_kills_child_before_exposure() -> Result<(), Box<dyn Error>> {
    let config = RegionConfig::new(1, 4, 0);
    let layout = RegionLayout::for_config(config)?;
    let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
    let plugin_peer = thread::spawn(move || {
        plugin_peer_complete_setup(plugin_socket, PluginPeerAfterRun::HoldRestoreUnacked)
    });
    let setup = crate::complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        config,
        0,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    )?;
    let child = Command::new("sleep").arg("60").spawn()?;
    let child_pid = child.id();
    let (qmp_stream, qmp_written) = scripted_qmp_with_written([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"running":true,"status":"running"}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"running":false,"status":"paused"}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-load-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
    ]);
    let qmp = QemuQmpVmStateControlChannel::connect(qmp_stream)?;
    let checkpoint = checkpoint_with_hash_byte(0xab);

    let result = build_qemu_node_from_restored_checkpoint(
        QemuNodeChild::new(child),
        setup,
        qmp,
        QemuNodeRestorePlan::new(
            &checkpoint,
            QemuLoadvmCommandAuthorization::runtime_realization_for_test(),
            test_admission(),
        ),
        node_factory_runtime(),
    );
    assert!(matches!(
        result,
        Err(QemuNodeFactoryError::LogicalTimeRestoreBoundary {
            stage: "await acknowledgement",
            ..
        })
    ));
    assert_process_is_gone(child_pid)?;
    match plugin_peer.join() {
        Ok(Ok(_region)) => {}
        Ok(Err(error)) => return Err(error.into()),
        Err(_panic) => return Err("plugin setup peer panicked".into()),
    }

    let lines = written_json_lines_from_shared(&qmp_written)?;
    assert_eq!(lines.len(), 7);
    assert!(
        lines
            .iter()
            .all(|line| execute_name(line) != Some(QMP_CONT_COMMAND))
    );
    assert!(
        lines
            .iter()
            .all(|line| execute_name(line) != Some(QMP_QUIT_COMMAND_NAME))
    );
    Ok(())
}

#[test]
fn factory_restores_baked_genesis_without_oracle_admission() -> Result<(), Box<dyn Error>> {
    let config = RegionConfig::new(1, 4, 0);
    let layout = RegionLayout::for_config(config)?;
    let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
    let plugin_peer = thread::spawn(move || {
        plugin_peer_complete_setup(
            plugin_socket,
            PluginPeerAfterRun::AcknowledgeRestoreThenWaitForQuit,
        )
    });
    let setup = crate::complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        config,
        0,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    )?;
    let child = Command::new("sleep").arg("60").spawn()?;
    let (qmp_stream, qmp_written) = scripted_qmp_with_written([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"running":true,"status":"running"}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"running":false,"status":"paused"}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-load-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"running":false,"status":"paused"}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
    ]);
    let qmp = QemuQmpVmStateControlChannel::connect(qmp_stream)?;
    let world = baked_world()?;
    let snapshot = baked_genesis_snapshot(&world);
    let admission = QemuBakedGenesisRestoreAdmission::new(
        &snapshot,
        &world,
        QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
    )?;

    let mut node = build_qemu_node_from_restored_checkpoint(
        QemuNodeChild::new(child),
        setup,
        qmp,
        QemuNodeRestorePlan::baked_genesis(admission),
        node_factory_runtime(),
    )?;

    assert!(node.shutdown_child()?.reaped);

    let plugin_region = match plugin_peer.join() {
        Ok(Ok(region)) => region,
        Ok(Err(error)) => return Err(error.into()),
        Err(_panic) => return Err("plugin setup peer panicked".into()),
    };
    assert_eq!(plugin_region.region_len, layout.region_size);

    let lines = written_json_lines_from_shared(&qmp_written)?;
    assert_eq!(
        execute_name(json_line(&lines, 0)),
        Some(QMP_CAPABILITIES_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_STATUS_COMMAND)
    );
    assert_eq!(execute_name(json_line(&lines, 2)), Some(QMP_STOP_COMMAND));
    assert_eq!(
        execute_name(json_line(&lines, 3)),
        Some(QMP_QUERY_STATUS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 4)),
        Some(QMP_SNAPSHOT_LOAD_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 5)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 6)),
        Some(QMP_JOB_DISMISS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 7)),
        Some(QMP_QUERY_STATUS_COMMAND)
    );
    assert_eq!(execute_name(json_line(&lines, 8)), Some(QMP_CONT_COMMAND));
    assert_eq!(
        execute_name(json_line(&lines, 9)),
        Some(QMP_QUIT_COMMAND_NAME)
    );

    Ok(())
}

#[test]
fn warm_restore_launch_requires_qmp_channel_before_spawn() -> Result<(), Box<dyn Error>> {
    let command = launch_command_without_qmp()?;
    let world = baked_world()?;
    let snapshot = baked_genesis_snapshot(&world);
    let admission = QemuBakedGenesisRestoreAdmission::new(
        &snapshot,
        &world,
        QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
    )?;

    let error = spawn_setup_and_restore_qemu_node(
        &command,
        "/tmp/crucible-node-factory-test",
        RegionConfig::new(1, 4, 0),
        0,
        QemuNodeRestorePlan::baked_genesis(admission),
        node_factory_runtime(),
        |_current_icount| {},
    )
    .err()
    .ok_or("warm restore launch should reject commands without QMP before spawn")?;

    assert!(matches!(
        error,
        QemuWarmRestoreLaunchError::MissingQmpChannel
    ));

    Ok(())
}

#[test]
fn factory_rejects_baked_authorization_for_replay_oracle_restore() -> Result<(), Box<dyn Error>> {
    let config = RegionConfig::new(1, 4, 0);
    let layout = RegionLayout::for_config(config)?;
    let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
    let plugin_peer = thread::spawn(move || {
        plugin_peer_complete_setup(plugin_socket, PluginPeerAfterRun::Return)
    });
    let setup = crate::complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        config,
        0,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    )?;
    let child = Command::new("sleep").arg("60").spawn()?;
    let (qmp_stream, qmp_written) = scripted_qmp_with_written([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
    ]);
    let qmp = QemuQmpVmStateControlChannel::connect(qmp_stream)?;
    let checkpoint = checkpoint_with_hash_byte(0xab);

    let error = build_qemu_node_from_restored_checkpoint(
        QemuNodeChild::new(child),
        setup,
        qmp,
        QemuNodeRestorePlan::new(
            &checkpoint,
            QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
            test_admission(),
        ),
        node_factory_runtime(),
    )
    .err()
    .ok_or("factory should reject baked authorization for replay-oracle restore")?;

    assert!(matches!(
        error,
        QemuNodeFactoryError::VmStateRestoreAuthorization {
            purpose: QemuLoadvmCommandPurpose::BakedGenesisRealization
        }
    ));
    assert_qmp_wrote_only_capabilities(&qmp_written)?;

    let plugin_region = match plugin_peer.join() {
        Ok(Ok(region)) => region,
        Ok(Err(error)) => return Err(error.into()),
        Err(_panic) => return Err("plugin setup peer panicked".into()),
    };
    assert_eq!(plugin_region.region_len, layout.region_size);

    Ok(())
}

#[test]
fn factory_rejects_restore_slot_mismatch_before_vmstate_restore() -> Result<(), Box<dyn Error>> {
    let config = RegionConfig::new(2, 4, 0);
    let layout = RegionLayout::for_config(config)?;
    let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
    let plugin_peer = thread::spawn(move || {
        plugin_peer_complete_setup(plugin_socket, PluginPeerAfterRun::Return)
    });
    let setup = crate::complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        config,
        0,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    )?;
    let child = Command::new("sleep").arg("60").spawn()?;
    let (qmp_stream, qmp_written) = scripted_qmp_with_written([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
    ]);
    let qmp = QemuQmpVmStateControlChannel::connect(qmp_stream)?;
    let checkpoint = checkpoint_with_hash_byte(0xab);

    let error = build_qemu_node_from_restored_checkpoint(
        QemuNodeChild::new(child),
        setup,
        qmp,
        QemuNodeRestorePlan::new(
            &checkpoint,
            QemuLoadvmCommandAuthorization::runtime_realization_for_test(),
            test_admission(),
        ),
        node_factory_runtime_for_slot(1),
    )
    .err()
    .ok_or("factory should reject mismatched setup and shmem slots before VMState restore")?;

    assert!(matches!(
        error,
        QemuNodeFactoryError::SetupSlotMismatch {
            setup_slot: 0,
            shmem_slot: 1
        }
    ));
    assert_qmp_wrote_only_capabilities(&qmp_written)?;

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
    let setup = crate::complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        config,
        0,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    )?;
    let child = Command::new("sleep").arg("60").spawn()?;
    let qmp = QemuQmpVmStateControlChannel::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
    ]))?;

    let error = build_qemu_node_from_completed_setup(
        QemuNodeChild::new(child),
        setup,
        qmp,
        node_factory_runtime_for_slot(1),
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

    fn repoll_child(
        &mut self,
        _wait: QemuAsyncWait,
        _timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        Ok(QemuAsyncWaitOutcome::Completed)
    }
}

struct FailRestoreRuntime;

impl QemuHostIoRuntime for FailRestoreRuntime {
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

    fn repoll_child(
        &mut self,
        _wait: QemuAsyncWait,
        _timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        Ok(QemuAsyncWaitOutcome::Completed)
    }

    fn restore_host_io_checkpoint(
        &mut self,
        _execution_binding: ContentHash,
        _checkpoint: &crate::QemuHostIoCheckpoint,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Err(QemuAsyncDriverRuntimeError::new(
            "restore host-I/O checkpoint",
            "injected post-load restore failure",
        ))
    }
}

#[derive(Clone, Copy, Debug)]
enum PluginPeerAfterRun {
    Return,
    WaitForQuit,
    AcknowledgeRestoreThenWaitForQuit,
    HoldRestoreUnacked,
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
    let mut mapped =
        crucible_shmem::mmap_setup_region(setup.descriptors.shmem_fd.as_fd(), setup.region_len)
            .map_err(|error| error.to_string())?;
    let validated = mapped
        .validate_header()
        .map_err(|error| error.to_string())?;
    assert_fd_open(setup.descriptors.wake_fd.as_raw_fd()).map_err(|error| error.to_string())?;
    crate::host_setup::tests::publish_test_admission_results(&mut mapped)
        .map_err(|error| error.to_string())?;

    plugin
        .plugin_send_ready_setup_ack()
        .map_err(|error| error.to_string())?;
    plugin
        .enter_run_via_shared_memory()
        .map_err(|error| error.to_string())?;
    if matches!(
        after_run,
        PluginPeerAfterRun::AcknowledgeRestoreThenWaitForQuit
    ) {
        let node_slot = mapped.node_slot(0).map_err(|error| error.to_string())?;
        let mut acknowledged = false;
        for _attempt in 0..1_000 {
            if let Some(request) = node_slot.pending_logical_time_restore() {
                node_slot
                    .acknowledge_logical_time_restore(
                        request,
                        request.target_icount,
                        request.target_icount,
                        0,
                    )
                    .map_err(|error| error.to_string())?;
                acknowledged = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        if !acknowledged {
            return Err("timed out waiting for the logical-time restore request".to_owned());
        }
    }
    if matches!(after_run, PluginPeerAfterRun::HoldRestoreUnacked) {
        thread::sleep(Duration::from_millis(20));
    }
    if matches!(
        after_run,
        PluginPeerAfterRun::WaitForQuit | PluginPeerAfterRun::AcknowledgeRestoreThenWaitForQuit
    ) {
        plugin
            .plugin_read_run_control_frame()
            .map_err(|error| error.to_string())?;
    }

    Ok(validated)
}

fn assert_process_is_gone(pid: u32) -> Result<(), Box<dyn Error>> {
    let pid = libc::pid_t::try_from(pid)?;
    let result = unsafe {
        // SAFETY: `kill(pid, 0)` probes process existence without sending a signal.
        libc::kill(pid, 0)
    };
    if result == 0 {
        return Err("child process still exists after fail-closed factory return".into());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(Box::new(error))
    }
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

fn node_factory_runtime() -> QemuNodeFactoryRuntime<AllowAllSends, ImmediateRuntime> {
    node_factory_runtime_for_slot(0)
}

fn node_factory_runtime_for_slot(
    vm_slot: u32,
) -> QemuNodeFactoryRuntime<AllowAllSends, ImmediateRuntime> {
    let async_policy = QemuAsyncDriverPolicy::new(
        Duration::from_millis(50),
        Duration::from_millis(500),
        Duration::from_millis(50),
        Duration::from_millis(50),
    );
    QemuNodeFactoryRuntime::new(
        qemu_config_for_slot(vm_slot),
        AllowAllSends,
        node_shutdown_policy(),
        async_policy,
        QemuCrashDetector::new("vm-a"),
        ImmediateRuntime,
    )
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

fn baked_world() -> Result<World, Box<dyn Error>> {
    Ok(World::from_nodes(vec![WorldNode {
        id: node_id("vm-a"),
        arch: VmArchitecture::X86_64,
        memory_mib: 512,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount::default(),
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: 1,
        icount_shift: 0,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?)
}

fn baked_genesis_snapshot(world: &World) -> QemuBakedGenesisSnapshot {
    let node = world
        .vm_nodes()
        .first()
        .map(|node| node.id.clone())
        .unwrap_or_else(|| node_id("vm-a"));
    let node_blobs = BTreeMap::from([(
        node,
        NodeBlobRef::baked(ContentHash::from_canonical_material(
            "crucible.qemu.node-factory.test.baked-blob.v1",
            "vm-a",
        )),
    )]);
    QemuBakedGenesisSnapshot {
        world_id: world.id(),
        checkpoint: Checkpoint::with_node_blobs(
            content_hash_with_byte(0xab),
            content_hash_with_byte(0xac),
            CheckpointKind::Fat,
            node_blobs,
        ),
    }
}

fn launch_command_without_qmp() -> Result<QemuLaunchCommand, Box<dyn Error>> {
    Ok(QemuLaunchCommandBuilder::new_for_live_gate(
        LaunchProfileCandidate::default().try_into_deterministic()?,
        QemuVmLaunchConfig::new(
            "vm-a",
            launch_artifact("kernel"),
            launch_artifact("root-image"),
        ),
        "/nix/store/00000000000000000000000000000000-qemu/bin/qemu-system-x86_64",
        QemuLaunchPluginConfig::new(
            "/nix/store/00000000000000000000000000000000-crucible-qemu-plugin/lib/crucible.so",
            0,
        )
        .with_fault_target_node("vm-a"),
        crate::LivePluginGuestArchitecture::X86_64,
    )
    .build()?)
}

fn launch_artifact(name: &str) -> QemuLaunchArtifact {
    QemuLaunchArtifact::new(
        ContentHash::from_canonical_material(
            "crucible.qemu.node-factory.test.launch-artifact.v1",
            name,
        ),
        format!("/nix/store/00000000000000000000000000000000-crucible-{name}"),
    )
}

fn content_hash_with_byte(byte: u8) -> ContentHash {
    ContentHash { bytes: [byte; 32] }
}

fn test_admission() -> QemuLoadvmRealizationAdmission {
    QemuLoadvmRealizationAdmission::for_test(content_hash_with_byte(0xcd))
}

type SharedQmpWritten = Arc<Mutex<Vec<u8>>>;

fn scripted_qmp<const N: usize>(lines: [&str; N]) -> ScriptedQmpStream {
    scripted_qmp_with_written(lines).0
}

fn scripted_qmp_with_written<const N: usize>(
    lines: [&str; N],
) -> (ScriptedQmpStream, SharedQmpWritten) {
    let mut input = Vec::new();
    for line in lines {
        input.extend_from_slice(line.as_bytes());
        input.extend_from_slice(b"\r\n");
    }
    let written = Arc::new(Mutex::new(Vec::new()));
    (
        ScriptedQmpStream {
            read: Cursor::new(input),
            written: Arc::clone(&written),
            read_timeouts: Vec::new(),
            write_timeouts: Vec::new(),
        },
        written,
    )
}

fn written_json_lines_from_shared(
    written: &SharedQmpWritten,
) -> Result<Vec<Value>, serde_json::Error> {
    let bytes = written.lock().unwrap();
    String::from_utf8_lossy(bytes.as_slice())
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

fn assert_qmp_wrote_only_capabilities(written: &SharedQmpWritten) -> Result<(), Box<dyn Error>> {
    let lines = written_json_lines_from_shared(written)?;
    assert_eq!(
        execute_name(json_line(&lines, 0)),
        Some(QMP_CAPABILITIES_COMMAND)
    );
    assert_eq!(lines.len(), 1);
    Ok(())
}

#[derive(Debug)]
struct ScriptedQmpStream {
    read: Cursor<Vec<u8>>,
    written: SharedQmpWritten,
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
        self.written.lock().unwrap().extend_from_slice(buf);
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
