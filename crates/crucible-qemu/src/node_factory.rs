//! Linux factory for already-spawned QEMU nodes.
//!
//! This module composes the post-spawn pieces into the scheduler-facing
//! [`QemuNode`] wrapper after Linux descriptor setup and QMP negotiation have
//! already completed. It wraps QMP in an exact-capture control adapter;
//! runtime restore is accepted only from version-nine descriptors before assembly.

#[cfg(unix)]
use std::os::fd::BorrowedFd;
use std::thread;
use std::time::Duration;

use crucible::{Checkpoint, SchedulerSendAuthorizer};
use crucible_shmem::{SetupRegionMapError, mmap_setup_region};
use thiserror::Error;

use crate::{
    QemuAsyncDriverPolicy, QemuCrashDetector, QemuHostIoRuntime, QemuHostPluginSetup,
    QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError, QemuNode,
    QemuNodeChannelError, QemuNodeChannels, QemuNodeChild, QemuQmpMachineControlChannel,
    QemuQmpVmStateControlChannel, QemuQuantumShmemConfig, QemuShmemHotPathChannel,
    QemuShutdownPolicy, QmpTimeoutStream,
};

mod restore_cleanup;
mod restore_plan;
use restore_cleanup::*;

#[cfg(target_os = "linux")]
pub(crate) use restore_plan::{
    QemuExactCheckpointRestoreDescriptors, QemuGuardedBakedRestoreAdmission,
    QemuGuardedProbeRestoreAdmission,
};
pub(crate) use restore_plan::{QemuNodeCheckpointAssertion, QemuNodeRestorePlan};

/// QMP machine-control adapter for exact snapshot capture and graceful shutdown.
#[derive(Debug)]
pub(crate) struct QemuQmpExactSnapshotControlChannel<S> {
    vmstate: QemuQmpVmStateControlChannel<S>,
}

impl<S> QemuQmpExactSnapshotControlChannel<S> {
    /// Wraps an explicitly VMState-authorized QMP channel for node shutdown use.
    #[must_use]
    pub(crate) const fn new(vmstate: QemuQmpVmStateControlChannel<S>) -> Self {
        Self { vmstate }
    }
}

impl<S> QemuQmpMachineControlChannel for QemuQmpExactSnapshotControlChannel<S>
where
    S: QmpTimeoutStream,
{
    fn stop_for_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        self.vmstate.stop_for_checkpoint()
    }

    fn resume_after_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        self.vmstate.resume_guest_acknowledged()
    }

    #[cfg(unix)]
    fn install_exact_checkpoint_descriptor(
        &mut self,
        name: &crate::QmpDescriptorName,
        descriptor: BorrowedFd<'_>,
    ) -> Result<(), QemuNodeChannelError> {
        self.vmstate
            .install_exact_checkpoint_descriptor(name, descriptor)
    }

    fn capture_exact_checkpoint(
        &mut self,
        request: &crate::QmpCheckpointCaptureRequest,
    ) -> Result<crate::QmpCheckpointCapture, QemuNodeChannelError> {
        self.vmstate.capture_exact_checkpoint(request)
    }

    fn commit_exact_checkpoint(
        &mut self,
        identity: crate::QmpCheckpointIdentity,
    ) -> Result<crate::QmpCheckpointEpochState, QemuNodeChannelError> {
        self.vmstate.commit_exact_checkpoint(identity)
    }

    fn abort_exact_checkpoint(
        &mut self,
        identity: crate::QmpCheckpointIdentity,
        expected_committed: Option<crate::QmpCheckpointIdentity>,
    ) -> Result<crate::QmpCheckpointEpochState, QemuNodeChannelError> {
        self.vmstate
            .abort_exact_checkpoint(identity, expected_committed)
    }

    fn query_exact_checkpoint_epoch(
        &mut self,
    ) -> Result<crate::QmpCheckpointEpochState, QemuNodeChannelError> {
        self.vmstate.query_exact_checkpoint_epoch()
    }

    fn query_hot_fork_plugin_resource_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkPluginResourceInventory, QemuNodeChannelError> {
        self.vmstate.query_hot_fork_plugin_resource_inventory()
    }

    fn query_hot_fork_child_runtime(
        &mut self,
    ) -> Result<crate::QmpHotForkChildRuntimeState, QemuNodeChannelError> {
        self.vmstate.query_hot_fork_child_runtime()
    }

    fn query_hot_fork_plugin_barrier(
        &mut self,
    ) -> Result<crate::QmpHotForkPluginBarrierState, QemuNodeChannelError> {
        self.vmstate.query_hot_fork_plugin_barrier()
    }

    fn prepare_hot_fork_template(
        &mut self,
        block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        self.vmstate
            .prepare_hot_fork_template(block_snapshot_bindings)
    }

    fn query_hot_fork_template(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        self.vmstate.query_hot_fork_template()
    }

    fn adopt_hot_fork_child_as_template_source(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        self.vmstate.adopt_hot_fork_child_as_template_source()
    }

    fn prepare_hot_fork_template_barriers(
        &mut self,
        block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        self.vmstate
            .prepare_hot_fork_template_barriers(block_snapshot_bindings)
    }

    fn abort_hot_fork_template(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        self.vmstate.abort_hot_fork_template()
    }

    #[cfg(target_os = "linux")]
    fn hot_fork(
        &mut self,
        request: crate::QmpHotForkRequest,
    ) -> Result<crate::QmpHotForkState, crate::QemuHotForkCommandError> {
        self.vmstate.hot_fork(request)
    }

    #[cfg(target_os = "linux")]
    fn query_hot_fork_child_process(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessState, crate::QemuNodeChannelError> {
        self.vmstate
            .query_hot_fork_child_process(generation)
            .map_err(crate::QemuNodeChannelError::from)
    }

    #[cfg(target_os = "linux")]
    fn release_hot_fork_child_process(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessState, crate::QemuNodeChannelError> {
        self.vmstate
            .release_hot_fork_child_process(generation)
            .map_err(crate::QemuNodeChannelError::from)
    }

    #[cfg(target_os = "linux")]
    fn install_hot_fork_child_process_contract(
        &mut self,
        names: &crate::QmpHotForkChildProcessContractNames,
        cgroup: std::os::fd::BorrowedFd<'_>,
        cgroup_procs: std::os::fd::BorrowedFd<'_>,
        cancellation: std::os::fd::BorrowedFd<'_>,
        identity: crate::QmpHotForkChildProcessContractIdentity,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessContractState, crate::QemuNodeChannelError> {
        self.vmstate.install_hot_fork_child_process_contract(
            names,
            cgroup,
            cgroup_procs,
            cancellation,
            identity,
            template_generation,
        )
    }

    #[cfg(target_os = "linux")]
    fn release_hot_fork_child_process_contract(
        &mut self,
        names: &crate::QmpHotForkChildProcessContractNames,
        identity: crate::QmpHotForkChildProcessContractIdentity,
    ) -> Result<crate::QmpHotForkChildProcessContractState, crate::QemuNodeChannelError> {
        self.vmstate
            .release_hot_fork_child_process_contract(names, identity)
    }

    fn query_hot_fork_child_process_contract(
        &mut self,
    ) -> Result<crate::QmpHotForkChildProcessContractState, crate::QemuNodeChannelError> {
        self.vmstate.query_hot_fork_child_process_contract()
    }

    #[cfg(target_os = "linux")]
    fn install_hot_fork_child_files(
        &mut self,
        files: &[crate::QmpHotForkChildFile],
        descriptors: &[std::os::fd::BorrowedFd<'_>],
        maximum_bytes: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildFilesState, crate::QemuNodeChannelError> {
        self.vmstate.install_hot_fork_child_files(
            files,
            descriptors,
            maximum_bytes,
            template_generation,
        )
    }

    #[cfg(target_os = "linux")]
    fn release_hot_fork_child_files(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildFilesState, crate::QemuNodeChannelError> {
        self.vmstate.release_hot_fork_child_files(generation)
    }

    fn query_hot_fork_child_files(
        &mut self,
    ) -> Result<crate::QmpHotForkChildFilesState, crate::QemuNodeChannelError> {
        self.vmstate.query_hot_fork_child_files()
    }

    #[cfg(target_os = "linux")]
    fn install_hot_fork_private_ring_descriptor(
        &mut self,
        name: &crate::QmpDescriptorName,
        descriptor: std::os::fd::BorrowedFd<'_>,
        identity: crucible_shmem::SetupRegionBackingIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.vmstate
            .install_hot_fork_private_ring_descriptor(name, descriptor, identity)
    }

    #[cfg(target_os = "linux")]
    fn close_hot_fork_private_ring_descriptor(
        &mut self,
        name: &crate::QmpDescriptorName,
        identity: crucible_shmem::SetupRegionBackingIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.vmstate
            .close_hot_fork_private_ring_descriptor(name, identity)
    }

    fn query_hot_fork_private_rings(
        &mut self,
    ) -> Result<crate::QmpHotForkPrivateRingState, QemuNodeChannelError> {
        self.vmstate.query_hot_fork_private_rings()
    }

    #[cfg(target_os = "linux")]
    fn install_hot_fork_plugin_endpoints(
        &mut self,
        control_name: &crate::QmpDescriptorName,
        control: std::os::fd::BorrowedFd<'_>,
        wake_name: &crate::QmpDescriptorName,
        wake: std::os::fd::BorrowedFd<'_>,
        identity: crate::QmpHotForkPluginEndpointIdentity,
        private_ring_generation: u64,
    ) -> Result<crate::QmpHotForkPluginEndpointState, QemuNodeChannelError> {
        self.vmstate.install_hot_fork_plugin_endpoints(
            control_name,
            control,
            wake_name,
            wake,
            identity,
            private_ring_generation,
        )
    }

    #[cfg(target_os = "linux")]
    fn close_hot_fork_plugin_endpoints(
        &mut self,
        control_name: &crate::QmpDescriptorName,
        wake_name: &crate::QmpDescriptorName,
        identity: crate::QmpHotForkPluginEndpointIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.vmstate
            .close_hot_fork_plugin_endpoints(control_name, wake_name, identity)
    }

    #[cfg(target_os = "linux")]
    fn install_hot_fork_child_diagnostics(
        &mut self,
        name: &crate::QmpDescriptorName,
        descriptor: std::os::fd::BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildDiagnosticState, QemuNodeChannelError> {
        self.vmstate.install_hot_fork_child_diagnostics(
            name,
            descriptor,
            socket_cookie,
            template_generation,
        )
    }

    #[cfg(target_os = "linux")]
    fn close_hot_fork_child_diagnostics(
        &mut self,
        name: &crate::QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.vmstate
            .close_hot_fork_child_diagnostics(name, socket_cookie)
    }

    fn query_hot_fork_child_diagnostics(
        &mut self,
    ) -> Result<crate::QmpHotForkChildDiagnosticState, QemuNodeChannelError> {
        self.vmstate.query_hot_fork_child_diagnostics()
    }

    #[cfg(target_os = "linux")]
    fn install_hot_fork_child_qmp(
        &mut self,
        name: &crate::QmpDescriptorName,
        descriptor: std::os::fd::BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
        self.vmstate.install_hot_fork_child_qmp(
            name,
            descriptor,
            socket_cookie,
            template_generation,
        )
    }

    #[cfg(target_os = "linux")]
    fn close_hot_fork_child_qmp(
        &mut self,
        name: &crate::QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.vmstate.close_hot_fork_child_qmp(name, socket_cookie)
    }

    fn query_hot_fork_child_qmp(
        &mut self,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
        self.vmstate.query_hot_fork_child_qmp()
    }

    #[cfg(target_os = "linux")]
    fn install_hot_fork_child_console(
        &mut self,
        name: &crate::QmpDescriptorName,
        descriptor: std::os::fd::BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildConsoleState, QemuNodeChannelError> {
        self.vmstate.install_hot_fork_child_console(
            name,
            descriptor,
            socket_cookie,
            template_generation,
        )
    }

    #[cfg(target_os = "linux")]
    fn close_hot_fork_child_console(
        &mut self,
        name: &crate::QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.vmstate
            .close_hot_fork_child_console(name, socket_cookie)
    }

    fn query_hot_fork_child_console(
        &mut self,
    ) -> Result<crate::QmpHotForkChildConsoleState, QemuNodeChannelError> {
        self.vmstate.query_hot_fork_child_console()
    }

    fn complete_terminal_lifecycle_exit(
        &mut self,
        action: crucible::ContentHash,
        evidence: crucible::ContentHash,
        process_generation: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.vmstate
            .complete_terminal_lifecycle_exit(action, evidence, process_generation)
    }

    fn save_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeChannelError> {
        self.vmstate
            .save_checkpoint_vmstate(checkpoint)
            .map(|_complete| ())
    }

    fn delete_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeChannelError> {
        self.vmstate
            .delete_checkpoint_vmstate(checkpoint)
            .map(|_complete| ())
    }

    fn quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.vmstate.quit().map(|_complete| ())
    }

    fn retire_process_scoped_endpoints_after_reap(&mut self) {
        self.vmstate.retire_process_scoped_endpoints_after_reap();
    }

    fn activate_debug_guest(&mut self) -> Result<(), QemuNodeChannelError> {
        self.vmstate.activate_debug_guest().map(|_complete| ())
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
    /// QMP failed to restore VMState before the node was assembled.
    #[error("QEMU VMState restore before node assembly failed")]
    VmStateRestore {
        /// Underlying VMState restore channel error.
        source: QemuNodeChannelError,
    },
    /// The host-I/O half did not match before QMP was allowed to change state.
    #[error("QEMU host-I/O checkpoint prevalidation failed")]
    HostIoCheckpointValidation {
        /// Exact host runtime validation failure.
        source: crate::QemuAsyncDriverRuntimeError,
    },
    /// The prevalidated host-I/O half could not be committed after QMP restore.
    #[error("QEMU host-I/O checkpoint restore failed after VMState restore")]
    HostIoCheckpointRestore {
        /// Exact host runtime commit failure.
        source: crate::QemuAsyncDriverRuntimeError,
    },
    /// The shared scheduler slot could not be armed for the restored icount.
    #[error("QEMU VMState restore ceiling could not be armed")]
    VmStateRestoreCeiling {
        /// Underlying mapped shared-memory channel failure.
        source: QemuNodeChannelError,
    },
    /// The fresh process could not enter the coordinated restore barrier.
    #[error("QEMU restore checkpoint pause failed")]
    CheckpointPause {
        /// Underlying host runtime failure.
        source: crate::QemuAsyncDriverRuntimeError,
    },
    /// QMP could not confirm the native paused run state after the exact plugin boundary.
    #[error("QEMU restore checkpoint stop failed")]
    CheckpointStop {
        /// Underlying QMP machine-control failure.
        source: QemuNodeChannelError,
    },
    /// QMP stop failed and the plugin pause request also could not be released.
    #[error(
        "QEMU restore checkpoint stop failed ({stop}); releasing the plugin pause also failed ({release})"
    )]
    CheckpointStopAndPauseRelease {
        /// Primary QMP stop failure.
        stop: QemuNodeChannelError,
        /// Independent plugin-pause release failure.
        release: Box<crate::QemuAsyncDriverRuntimeError>,
    },
    /// The stopped process could not release its plugin pause request.
    #[error("QEMU restore plugin-pause release failed")]
    CheckpointPauseRelease {
        /// Underlying host runtime failure.
        source: crate::QemuAsyncDriverRuntimeError,
    },
    /// The fresh process could not resume after a successful restore.
    #[error("QEMU restore checkpoint resume failed")]
    CheckpointResume {
        /// Underlying QMP machine-control failure.
        source: QemuNodeChannelError,
    },
    /// The post-load logical-time boundary transaction failed.
    #[error("QEMU post-load logical-time restore boundary failed during {stage}: {message}")]
    LogicalTimeRestoreBoundary {
        /// Exact transaction stage that failed.
        stage: &'static str,
        /// Deterministic channel or timeout detail.
        message: String,
    },
    /// A fresh realization failed and its child could not be reaped.
    #[error("QEMU restore failed ({primary}); mandatory child reap also failed ({cleanup})")]
    FailedRestoreCleanup {
        /// Primary realization failure.
        primary: Box<QemuNodeFactoryError>,
        /// Independent force-kill/reap failure.
        cleanup: crate::QemuShutdownTargetError,
        /// Nonduplicable direct-child handle retained after failed reap.
        unreaped_child: Option<Box<QemuNodeChild>>,
    },
    /// Scheduler-facing Apache node continuation could not be restored.
    #[error("QEMU node continuation restore failed: {message}")]
    NodeContinuationRestore {
        /// Deterministic validation or restoration detail.
        message: String,
    },
}

impl QemuNodeFactoryError {
    /// Extracts a direct child whose mandatory synchronous reap failed.
    pub(crate) fn take_unreaped_child(&mut self) -> Option<QemuNodeChild> {
        match self {
            Self::FailedRestoreCleanup { unreaped_child, .. } => {
                unreaped_child.take().map(|child| *child)
            }
            _ => None,
        }
    }
}

struct PreparedQemuNodeSetup {
    plugin_control: QemuHostPluginSetup,
    shmem_hot_path: QemuMappedQuantumShmemHotPath,
    next_fault_command_sequence: u64,
    fault_capabilities: Vec<crucible_shmem::FaultCapabilityRowV1>,
    ready_markers: std::collections::BTreeSet<crucible::model::FaultObjectId>,
    exact_fault_manifests: Option<crate::fault_capability::QemuExactFaultManifests>,
}

/// Runtime inputs shared by cold and restored QEMU node factory paths.
pub(crate) struct QemuNodeFactoryRuntime<A, R> {
    shmem_config: QemuQuantumShmemConfig,
    send_authorizer: A,
    shutdown_policy: QemuShutdownPolicy,
    async_policy: QemuAsyncDriverPolicy,
    crash_detector: QemuCrashDetector,
    host_io_runtime: R,
}

impl<A, R> QemuNodeFactoryRuntime<A, R> {
    /// Creates the runtime inputs needed to assemble a scheduler-facing node.
    #[must_use]
    pub(crate) fn new(
        shmem_config: QemuQuantumShmemConfig,
        send_authorizer: A,
        shutdown_policy: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
        crash_detector: QemuCrashDetector,
        host_io_runtime: R,
    ) -> Self {
        Self {
            shmem_config,
            send_authorizer,
            shutdown_policy,
            async_policy,
            crash_detector,
            host_io_runtime,
        }
    }
}

/// Builds a scheduler-facing QEMU node from completed Linux setup pieces.
///
/// The caller must provide an already-spawned child, a completed plugin setup,
/// an already-connected QMP VMState channel, and the runtime inputs used by
/// [`QemuNode`]. The returned node owns the plugin
/// IPC control channel, a mapped shared-memory hot path, and a QMP shutdown
/// adapter. VMState capture uses the paired exact-snapshot API; restore
/// authority is consumed before this generic assembly path.
///
/// # Errors
///
/// Returns [`QemuNodeFactoryError`] when the completed setup slot does not match
/// the shared-memory hot-path config, when the setup memfd cannot be mapped, or
/// when the mapped hot-path adapter rejects the completed region.
pub(crate) fn build_qemu_node_from_completed_setup<S, A, R>(
    child: QemuNodeChild,
    setup: QemuHostPluginSetup,
    qmp: QemuQmpVmStateControlChannel<S>,
    runtime: QemuNodeFactoryRuntime<A, R>,
) -> Result<QemuNode, QemuNodeFactoryError>
where
    S: QmpTimeoutStream + 'static,
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
{
    let QemuNodeFactoryRuntime {
        shmem_config,
        send_authorizer,
        shutdown_policy,
        async_policy,
        crash_detector,
        host_io_runtime,
    } = runtime;
    let prepared_setup = prepare_qemu_node_setup(setup, shmem_config, send_authorizer)?;
    Ok(build_qemu_node_from_prepared_setup(
        child,
        prepared_setup,
        qmp,
        shutdown_policy,
        async_policy,
        crash_detector,
        host_io_runtime,
    ))
}

/// Restores a version-nine QEMU checkpoint, then builds a scheduler-facing node.
///
/// This is the checkpoint realization factory path: callers must provide exact
/// version-nine descriptors and matching admission proof before the QMP
/// channel is reduced to exact-snapshot capture and shutdown control. Baked
/// genesis and replay probes remain distinct host-side admissions, but both
/// enter QEMU through the same authenticated descriptor restore. Generic backend
/// snapshot/restore remains disabled on the returned [`QemuNode`].
///
/// # Errors
///
/// Returns [`QemuNodeFactoryError`] when the completed setup slot does not match
/// the shared-memory hot-path config, when QMP rejects the descriptor-backed restore,
/// when the setup memfd cannot be mapped, or when the mapped hot-path
/// adapter rejects the completed region.
pub(crate) fn build_qemu_node_from_restored_checkpoint<S, A, R>(
    child: QemuNodeChild,
    setup: QemuHostPluginSetup,
    qmp: QemuQmpVmStateControlChannel<S>,
    restore: QemuNodeRestorePlan<'_>,
    runtime: QemuNodeFactoryRuntime<A, R>,
) -> Result<QemuNode, QemuNodeFactoryError>
where
    S: QmpTimeoutStream + 'static,
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
{
    build_qemu_node_from_restored_checkpoint_inner(child, setup, qmp, restore, runtime, true)
}

/// Restores a version-nine QEMU checkpoint into a node that remains paused.
///
/// This is the power-off realization path. It performs the complete restore
/// handshake, including a stopped-state control wake that acknowledges
/// logical-time calibration without executing guest instructions, but does not
/// resume the guest after the final native stop.
///
/// # Errors
///
/// Returns [`QemuNodeFactoryError`] under the same conditions as
/// [`build_qemu_node_from_restored_checkpoint`].
pub(crate) fn build_qemu_node_from_restored_checkpoint_paused<S, A, R>(
    child: QemuNodeChild,
    setup: QemuHostPluginSetup,
    qmp: QemuQmpVmStateControlChannel<S>,
    restore: QemuNodeRestorePlan<'_>,
    runtime: QemuNodeFactoryRuntime<A, R>,
) -> Result<QemuNode, QemuNodeFactoryError>
where
    S: QmpTimeoutStream + 'static,
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
{
    build_qemu_node_from_restored_checkpoint_inner(child, setup, qmp, restore, runtime, false)
}

const RESTORE_BOUNDARY_POLL_INTERVAL: Duration = Duration::from_millis(1);

fn bounded_restore_boundary_polls(timeout: Duration) -> u64 {
    let interval = RESTORE_BOUNDARY_POLL_INTERVAL.as_micros().max(1);
    u64::try_from(timeout.as_micros() / interval)
        .unwrap_or(u64::MAX)
        .max(1)
}

fn build_qemu_node_from_restored_checkpoint_inner<S, A, R>(
    child: QemuNodeChild,
    setup: QemuHostPluginSetup,
    mut qmp: QemuQmpVmStateControlChannel<S>,
    restore: QemuNodeRestorePlan<'_>,
    runtime: QemuNodeFactoryRuntime<A, R>,
    resume_guest: bool,
) -> Result<QemuNode, QemuNodeFactoryError>
where
    S: QmpTimeoutStream + 'static,
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
{
    if let Err(source) = restore.validate_immutable_descriptors() {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::VmStateRestore {
                source: QemuNodeChannelError::new(
                    "validate exact checkpoint descriptors",
                    source.to_string(),
                ),
            },
        ));
    }
    let QemuNodeFactoryRuntime {
        shmem_config,
        send_authorizer,
        shutdown_policy,
        async_policy,
        crash_detector,
        mut host_io_runtime,
    } = runtime;
    let QemuNodeRestorePlan {
        checkpoint,
        host_io_checkpoint,
        node_continuation,
        exact_checkpoint,
    } = restore;
    if exact_checkpoint.request.identity().checkpoint() != checkpoint.id {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::VmStateRestore {
                source: QemuNodeChannelError::new(
                    "restore exact QEMU checkpoint",
                    "exact RAM request identity does not name the restored host checkpoint",
                ),
            },
        ));
    }
    if node_continuation.execution_binding() != checkpoint.id {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::NodeContinuationRestore {
                message: String::from("node continuation belongs to another VMState checkpoint"),
            },
        ));
    }
    if node_continuation.next_fault_command_sequence() < 2 {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::NodeContinuationRestore {
                message: String::from(
                    "restored fault-command sequence precedes setup capability admission",
                ),
            },
        ));
    }
    let calibration = node_continuation.logical_time_calibration();
    if calibration.logical_icount != node_continuation.last_observed_time().ticks {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::NodeContinuationRestore {
                message: String::from(
                    "logical-time calibration does not match the scheduler continuation boundary",
                ),
            },
        ));
    }
    if let Err(source) = calibration.offset() {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::NodeContinuationRestore {
                message: source.to_string(),
            },
        ));
    }
    let mut prepared_setup = match prepare_qemu_node_setup(setup, shmem_config, send_authorizer) {
        Ok(prepared_setup) => prepared_setup,
        Err(error) => return Err(reap_failed_restore_child(child, error)),
    };
    if let Err(source) = host_io_runtime.quiesce_for_checkpoint(async_policy.qmp_command_timeout) {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::CheckpointPause { source },
        ));
    }
    // Prevalidate while the plugin's exact barrier is still acknowledged and
    // guest/device dispatch is frozen. Delaying this work until after QMP stop
    // and pause release admits a transient callback publication; delaying
    // pause release until after validation can instead strand the stopped
    // callback behind the BQL. Validation is read-only, so this position keeps
    // both halves exact without extending the native stopped interval.
    if let Err(source) =
        host_io_runtime.validate_host_io_checkpoint(checkpoint.id, host_io_checkpoint)
    {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::HostIoCheckpointValidation { source },
        ));
    }
    if let Err(stop) = qmp.stop_for_checkpoint() {
        let primary = match host_io_runtime.abort_checkpoint_pause() {
            Ok(()) => QemuNodeFactoryError::CheckpointStop { source: stop },
            Err(release) => QemuNodeFactoryError::CheckpointStopAndPauseRelease {
                stop,
                release: Box::new(release),
            },
        };
        return Err(reap_failed_restore_child(child, primary));
    }
    if let Err(release) = host_io_runtime.clear_checkpoint_pause_while_stopped() {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::CheckpointPauseRelease { source: release },
        ));
    }
    let restore_result = (|| {
        let restored_icount = node_continuation.last_observed_time().ticks;
        let published_icount =
            QemuShmemHotPathChannel::current_icount(&mut prepared_setup.shmem_hot_path)
                .map_err(|source| QemuNodeFactoryError::VmStateRestoreCeiling { source })?
                .retired;
        let restore_ceiling = restored_icount.max(published_icount);
        prepared_setup
            .shmem_hot_path
            .arm_vmstate_restore_ceiling(restore_ceiling)
            .map_err(|source| QemuNodeFactoryError::VmStateRestoreCeiling { source })?;
        {
            if exact_checkpoint.request.layers().len() != exact_checkpoint.descriptors.ram.len() {
                return Err(QemuNodeFactoryError::VmStateRestore {
                    source: QemuNodeChannelError::new(
                        "restore exact QEMU checkpoint",
                        "RAM layer descriptor count differs from the restore request",
                    ),
                });
            }
            for (layer, descriptor) in exact_checkpoint
                .request
                .layers()
                .iter()
                .zip(exact_checkpoint.descriptors.ram.iter().copied())
            {
                qmp.install_exact_checkpoint_descriptor(layer.descriptor(), descriptor)
                    .map_err(|source| QemuNodeFactoryError::VmStateRestore { source })?;
            }
            qmp.install_exact_checkpoint_descriptor(
                exact_checkpoint.request.device_descriptor(),
                exact_checkpoint.descriptors.device,
            )
            .map_err(|source| QemuNodeFactoryError::VmStateRestore { source })?;
            qmp.install_exact_checkpoint_descriptor(
                exact_checkpoint.request.cancellation_descriptor(),
                exact_checkpoint.descriptors.cancellation,
            )
            .map_err(|source| QemuNodeFactoryError::VmStateRestore { source })?;
            let restored = qmp
                .restore_exact_checkpoint(exact_checkpoint.request)
                .map_err(|source| QemuNodeFactoryError::VmStateRestore { source })?;
            if restored.topology() != exact_checkpoint.topology {
                return Err(QemuNodeFactoryError::VmStateRestore {
                    source: QemuNodeChannelError::new(
                        "restore exact QEMU checkpoint",
                        "restored RAM topology differs from the authenticated manifest",
                    ),
                });
            }
        }
        host_io_runtime
            .restore_host_io_checkpoint(checkpoint.id, host_io_checkpoint)
            .map_err(|source| QemuNodeFactoryError::HostIoCheckpointRestore { source })
    })();
    if let Err(error) = restore_result {
        // A post-load error may not return until the fresh child is killed and
        // synchronously reaped; destructor cleanup has a bounded fallback and
        // is deliberately insufficient for this realization transaction.
        return Err(reap_failed_restore_child(child, error));
    }

    let restored_calibration = node_continuation.logical_time_calibration();
    let restored_icount = restored_calibration.logical_icount;
    let restore_boundary = prepared_setup
        .shmem_hot_path
        .arm_logical_time_restore_boundary(restored_icount)
        .map_err(|source| QemuNodeFactoryError::LogicalTimeRestoreBoundary {
            stage: "arm",
            message: source.to_string(),
        });
    let restore_boundary = match restore_boundary {
        Ok(boundary) => boundary,
        Err(error) => return Err(reap_failed_restore_child(child, error)),
    };
    if let Err(source) = prepared_setup.plugin_control.signal_plugin_wake() {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::LogicalTimeRestoreBoundary {
                stage: "signal stopped control wake",
                message: source.to_string(),
            },
        ));
    }
    let polls = bounded_restore_boundary_polls(async_policy.qmp_command_timeout);
    let mut acknowledged = false;
    for attempt in 0..polls {
        let boundary_acknowledged = prepared_setup
            .shmem_hot_path
            .logical_time_restore_boundary_acknowledged(restore_boundary, restored_calibration)
            .map_err(|source| QemuNodeFactoryError::LogicalTimeRestoreBoundary {
                stage: "observe acknowledgement",
                message: source.to_string(),
            });
        let boundary_acknowledged = match boundary_acknowledged {
            Ok(acknowledged) => acknowledged,
            Err(error) => return Err(reap_failed_restore_child(child, error)),
        };
        if boundary_acknowledged {
            acknowledged = true;
            break;
        }
        if attempt + 1 < polls {
            if let Err(source) = prepared_setup.plugin_control.signal_plugin_wake() {
                return Err(reap_failed_restore_child(
                    child,
                    QemuNodeFactoryError::LogicalTimeRestoreBoundary {
                        stage: "wake plugin",
                        message: source.to_string(),
                    },
                ));
            }
            thread::sleep(RESTORE_BOUNDARY_POLL_INTERVAL);
        }
    }
    if !acknowledged {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::LogicalTimeRestoreBoundary {
                stage: "await acknowledgement",
                message: format!(
                    "plugin did not acknowledge generation {} at icount {restored_icount} within {:?}",
                    restore_boundary.logical_generation(),
                    async_policy.qmp_command_timeout
                ),
            },
        ));
    }
    if let Err(source) = qmp.confirm_restore_boundary_pause() {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::LogicalTimeRestoreBoundary {
                stage: "confirm native stop",
                message: source.to_string(),
            },
        ));
    }
    if let Err(source) = prepared_setup
        .shmem_hot_path
        .commit_coverage_restore_generation(restore_boundary.logical_generation())
    {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::LogicalTimeRestoreBoundary {
                stage: "commit coverage generation reset",
                message: source.to_string(),
            },
        ));
    }
    prepared_setup
        .shmem_hot_path
        .clear_logical_time_restore_pause();

    let mut node = build_qemu_node_from_prepared_setup(
        child,
        prepared_setup,
        qmp,
        shutdown_policy,
        async_policy,
        crash_detector,
        host_io_runtime,
    );
    if let Err(source) = node.restore_node_continuation(node_continuation) {
        let primary = QemuNodeFactoryError::NodeContinuationRestore {
            message: source.to_string(),
        };
        return Err(reap_failed_restored_node(node, primary));
    }
    if resume_guest && let Err(source) = node.resume_after_restore() {
        let primary = QemuNodeFactoryError::CheckpointResume {
            source: QemuNodeChannelError::new("resume restored QEMU", source.to_string()),
        };
        return Err(reap_failed_restored_node(node, primary));
    }
    Ok(node)
}

fn prepare_qemu_node_setup<A>(
    setup: QemuHostPluginSetup,
    shmem_config: QemuQuantumShmemConfig,
    send_authorizer: A,
) -> Result<PreparedQemuNodeSetup, QemuNodeFactoryError>
where
    A: SchedulerSendAuthorizer + 'static,
{
    validate_setup_slot_matches_config(&setup, &shmem_config)?;

    let fault_capabilities = setup.fault_capabilities().to_vec();
    let ready_markers = setup.ready_markers().clone();
    let exact_fault_manifests = setup.exact_fault_manifests();
    let next_fault_command_sequence = setup.next_fault_command_sequence();
    let selectable_catalog_plan = setup.selectable_catalog_plan().clone();

    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuNodeFactoryError::SetupRegionMap { source })?;
    let shmem_hot_path = QemuMappedQuantumShmemHotPath::new_with_selectable_catalog_plan(
        shmem_config,
        region,
        send_authorizer,
        selectable_catalog_plan,
    )
    .map_err(|source| QemuNodeFactoryError::MappedHotPath { source })?;

    Ok(PreparedQemuNodeSetup {
        plugin_control: setup,
        shmem_hot_path,
        next_fault_command_sequence,
        fault_capabilities,
        ready_markers,
        exact_fault_manifests,
    })
}

fn build_qemu_node_from_prepared_setup<S, R>(
    child: QemuNodeChild,
    prepared_setup: PreparedQemuNodeSetup,
    qmp: QemuQmpVmStateControlChannel<S>,
    shutdown_policy: QemuShutdownPolicy,
    async_policy: QemuAsyncDriverPolicy,
    crash_detector: QemuCrashDetector,
    host_io_runtime: R,
) -> QemuNode
where
    S: QmpTimeoutStream + 'static,
    R: QemuHostIoRuntime + 'static,
{
    let qmp_machine_control = QemuQmpExactSnapshotControlChannel::new(qmp);
    let channels = QemuNodeChannels::new(
        prepared_setup.plugin_control,
        prepared_setup.shmem_hot_path,
        qmp_machine_control,
    );

    QemuNode::new(
        child,
        channels,
        shutdown_policy,
        async_policy,
        crash_detector,
        host_io_runtime,
        prepared_setup.next_fault_command_sequence,
    )
    .with_fault_capabilities(prepared_setup.fault_capabilities)
    .with_ready_markers(prepared_setup.ready_markers)
    .with_exact_fault_manifests(prepared_setup.exact_fault_manifests)
}

mod validation;
use validation::*;

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
