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
    QemuLoadvmCommandAuthorization, QemuLoadvmCommandPurpose, QemuLoadvmRealizationAdmission,
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
    /// QMP failed to restore VMState before the node was assembled.
    #[error("QEMU VMState restore before node assembly failed")]
    VmStateRestore {
        /// Underlying VMState restore channel error.
        source: QemuNodeChannelError,
    },
    /// The authorization token was not issued for runtime realization.
    #[error("QEMU VMState restore requires runtime-realization authorization, got {purpose:?}")]
    VmStateRestoreAuthorization {
        /// Purpose attached to the rejected authorization token.
        purpose: QemuLoadvmCommandPurpose,
    },
}

struct PreparedQemuNodeSetup {
    plugin_control: QemuHostPluginSetup,
    shmem_hot_path: QemuMappedQuantumShmemHotPath,
}

/// Runtime inputs shared by cold and warm QEMU node factory paths.
pub struct QemuNodeFactoryRuntime<A, R> {
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
    pub fn new(
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

/// Authorized VMState restore inputs for warm QEMU node realization.
pub struct QemuNodeRestorePlan<'a> {
    checkpoint: &'a Checkpoint,
    authorization: QemuLoadvmCommandAuthorization,
    admission: QemuLoadvmRealizationAdmission,
}

impl<'a> QemuNodeRestorePlan<'a> {
    /// Creates a warm-restore plan from the checkpoint and policy proof.
    #[must_use]
    pub const fn new(
        checkpoint: &'a Checkpoint,
        authorization: QemuLoadvmCommandAuthorization,
        admission: QemuLoadvmRealizationAdmission,
    ) -> Self {
        Self {
            checkpoint,
            authorization,
            admission,
        }
    }
}

/// Builds a scheduler-facing QEMU node from completed Linux setup pieces.
///
/// The caller must provide an already-spawned child, a completed plugin setup,
/// an already-connected QMP VMState channel, and the runtime inputs used by
/// [`QemuNode`]. The returned node owns the plugin
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

/// Restores QEMU VMState, then builds a scheduler-facing QEMU node.
///
/// This is the warm-realization factory path: callers must provide an explicit
/// runtime-realization `loadvm` authorization token and admission proof before
/// the QMP channel is reduced to shutdown-only node control. Generic backend
/// snapshot/restore remains disabled on the returned [`QemuNode`].
///
/// # Errors
///
/// Returns [`QemuNodeFactoryError`] when the authorization was not issued for
/// runtime realization, when the completed setup slot does not match the
/// shared-memory hot-path config, when QMP rejects the authorized VMState
/// restore, when the setup memfd cannot be mapped, or when the mapped hot-path
/// adapter rejects the completed region.
pub fn build_qemu_node_from_restored_checkpoint<S, A, R>(
    child: QemuNodeChild,
    setup: QemuHostPluginSetup,
    mut qmp: QemuQmpVmStateControlChannel<S>,
    restore: QemuNodeRestorePlan<'_>,
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
    let QemuNodeRestorePlan {
        checkpoint,
        authorization,
        admission,
    } = restore;
    let _admitted_runtime_hash = admission.runtime_hash();
    validate_runtime_restore_authorization(authorization)?;
    let prepared_setup = prepare_qemu_node_setup(setup, shmem_config, send_authorizer)?;
    qmp.restore_checkpoint_vmstate(checkpoint, authorization)
        .map_err(|source| QemuNodeFactoryError::VmStateRestore { source })?;

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

fn prepare_qemu_node_setup<A>(
    setup: QemuHostPluginSetup,
    shmem_config: QemuQuantumShmemConfig,
    send_authorizer: A,
) -> Result<PreparedQemuNodeSetup, QemuNodeFactoryError>
where
    A: SchedulerSendAuthorizer + 'static,
{
    validate_setup_slot_matches_config(&setup, &shmem_config)?;

    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuNodeFactoryError::SetupRegionMap { source })?;
    let shmem_hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, send_authorizer)
        .map_err(|source| QemuNodeFactoryError::MappedHotPath { source })?;

    Ok(PreparedQemuNodeSetup {
        plugin_control: setup,
        shmem_hot_path,
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
    let qmp_machine_control = QemuQmpShutdownOnlyControlChannel::new(qmp);
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
    )
}

fn validate_setup_slot_matches_config(
    setup: &QemuHostPluginSetup,
    shmem_config: &QemuQuantumShmemConfig,
) -> Result<(), QemuNodeFactoryError> {
    let setup_slot = setup.negotiated_handshake().slot_index;
    if setup_slot != shmem_config.vm_slot {
        return Err(QemuNodeFactoryError::SetupSlotMismatch {
            setup_slot,
            shmem_slot: shmem_config.vm_slot,
        });
    }
    Ok(())
}

fn validate_runtime_restore_authorization(
    authorization: QemuLoadvmCommandAuthorization,
) -> Result<(), QemuNodeFactoryError> {
    let purpose = authorization.purpose();
    if purpose != QemuLoadvmCommandPurpose::RuntimeRealization {
        return Err(QemuNodeFactoryError::VmStateRestoreAuthorization { purpose });
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests;
