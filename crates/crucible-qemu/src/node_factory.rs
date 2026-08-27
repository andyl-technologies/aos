//! Linux factory for already-spawned QEMU nodes.
//!
//! This module composes the post-spawn pieces into the scheduler-facing
//! [`QemuNode`] wrapper after Linux descriptor setup and QMP negotiation have
//! already completed. It wraps VMState QMP in an exact-capture control adapter;
//! runtime `loadvm` remains confined to the explicit realization-policy path.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::{
    BasicBlockCoverageConfig, Checkpoint, ExecutionHorizon, Icount, SchedulerError,
    SchedulerNodeId, SchedulerSendAuthorization, SchedulerSendAuthorizer,
};
use crucible_shmem::{
    RegionAllocation, RegionConfig, RegionLayoutError, SetupRegionMapError, mmap_setup_region,
};
use thiserror::Error;

use crate::{
    QemuAsyncDriverPolicy, QemuChildProcessContract, QemuCrashDetector, QemuHostIoRuntime,
    QemuHostPluginSetup, QemuHostPluginSetupError, QemuLaunchCommand, QemuLaunchPluginSwitch,
    QemuLoadvmCommandAuthorization, QemuLoadvmCommandPurpose, QemuMappedQuantumShmemHotPath,
    QemuMappedQuantumShmemHotPathError, QemuNode, QemuNodeChannelError, QemuNodeChannels,
    QemuNodeChild, QemuPreparedRunDirectory, QemuQmpMachineControlChannel,
    QemuQmpVmStateControlChannel, QemuQuantumShmemConfig, QemuShmemHotPathChannel,
    QemuShutdownPolicy, QemuSpawnError, QemuVmStateBinding, QmpError, QmpTimeoutStream,
    complete_qemu_host_plugin_setup_with_plugin_setup_plan,
    spawn_prepared_qemu_child_with_fds_in_directory_guarded,
    spawn_qemu_child_with_fds_in_directory,
};

mod restore_cleanup;
mod restore_plan;
use restore_cleanup::*;

pub use restore_plan::{QemuNodeRestoreAdmission, QemuNodeRestorePlan};

/// QMP machine-control adapter for exact snapshot capture and graceful shutdown.
#[derive(Debug)]
pub struct QemuQmpExactSnapshotControlChannel<S> {
    vmstate: QemuQmpVmStateControlChannel<S>,
}

impl<S> QemuQmpExactSnapshotControlChannel<S> {
    /// Wraps an explicitly VMState-authorized QMP channel for node shutdown use.
    #[must_use]
    pub const fn new(vmstate: QemuQmpVmStateControlChannel<S>) -> Self {
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
        self.vmstate.resume_after_checkpoint()
    }

    fn query_hot_fork_readiness(
        &mut self,
    ) -> Result<crate::QmpHotForkReadiness, QemuNodeChannelError> {
        self.vmstate.query_hot_fork_readiness()
    }

    fn query_hot_fork_thread_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkThreadInventory, QemuNodeChannelError> {
        self.vmstate.query_hot_fork_thread_inventory()
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
    /// QMP could not release the consumed restore anchor from the working image.
    #[error("QEMU VMState restore anchor release failed after load")]
    VmStateRestoreAnchorRelease {
        /// Underlying VMState snapshot-delete channel error.
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
    /// The authorization token did not match the restore admission kind.
    #[error("QEMU VMState restore authorization does not match admission kind, got {purpose:?}")]
    VmStateRestoreAuthorization {
        /// Purpose attached to the rejected authorization token.
        purpose: QemuLoadvmCommandPurpose,
    },
}

/// Errors returned while spawning and restoring a QEMU node from a launch command.
#[derive(Debug, Error)]
pub enum QemuWarmRestoreLaunchError {
    /// The launch command did not include the QMP channel required for VMState restore.
    #[error("QEMU warm restore launch requires a QMP channel")]
    MissingQmpChannel,
    /// The requested shared-memory region layout could not be computed.
    #[error("QEMU warm restore shared-memory layout failed")]
    RegionLayout {
        /// Underlying shared-memory layout error.
        source: RegionLayoutError,
    },
    /// QEMU process spawning failed.
    #[error("QEMU warm restore spawn failed")]
    Spawn {
        /// Underlying spawn error.
        source: QemuSpawnError,
    },
    /// Host/plugin setup failed before VMState restore.
    #[error("QEMU warm restore plugin setup failed")]
    HostSetup {
        /// Underlying host setup error.
        source: QemuHostPluginSetupError,
    },
    /// Connecting the typed VMState QMP client failed.
    #[error("QEMU warm restore QMP connection failed")]
    QmpConnect {
        /// Underlying QMP error.
        source: QmpError,
    },
    /// The priming region could not be mapped.
    #[error("QEMU warm restore priming region map failed")]
    PrimeRegionMap {
        /// Underlying region map error.
        source: SetupRegionMapError,
    },
    /// The priming hot path could not be constructed.
    #[error("QEMU warm restore priming hot path failed")]
    PrimeHotPath {
        /// Underlying hot-path error.
        source: QemuMappedQuantumShmemHotPathError,
    },
    /// A priming hot-path operation failed.
    #[error("QEMU warm restore priming: {context}")]
    Prime {
        /// What the priming step was doing.
        context: String,
        /// Underlying channel error.
        source: QemuNodeChannelError,
    },
    /// The guest did not reach the priming ceiling before the deadline.
    #[error("QEMU warm restore priming stalled below ceiling {ceiling_icount}")]
    PrimeStalled {
        /// The priming ceiling the guest failed to reach.
        ceiling_icount: u64,
    },
    /// Final scheduler-facing node assembly failed.
    #[error("QEMU warm restore node assembly failed")]
    Factory {
        /// Underlying node factory error.
        source: QemuNodeFactoryError,
    },
    /// A post-spawn launch step failed and the direct child could not be reaped.
    #[error("QEMU warm restore failed ({primary}); mandatory child reap also failed ({cleanup})")]
    FailedCleanup {
        /// Primary warm-restore launch failure.
        primary: Box<QemuWarmRestoreLaunchError>,
        /// Independent force-kill/reap failure.
        cleanup: crate::QemuShutdownTargetError,
        /// Nonduplicable direct-child handle retained after failed reap.
        unreaped_child: Option<Box<QemuNodeChild>>,
    },
}

impl QemuWarmRestoreLaunchError {
    fn prime(context: &str, source: QemuNodeChannelError) -> Self {
        Self::Prime {
            context: context.to_owned(),
            source,
        }
    }

    /// Extracts a direct child whose mandatory synchronous reap failed.
    pub(crate) fn take_unreaped_child(&mut self) -> Option<QemuNodeChild> {
        match self {
            Self::Factory { source } => source.take_unreaped_child(),
            Self::FailedCleanup { unreaped_child, .. } => unreaped_child.take().map(|child| *child),
            _ => None,
        }
    }
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

/// Builds a scheduler-facing QEMU node from completed Linux setup pieces.
///
/// The caller must provide an already-spawned child, a completed plugin setup,
/// an already-connected QMP VMState channel, and the runtime inputs used by
/// [`QemuNode`]. The returned node owns the plugin
/// IPC control channel, a mapped shared-memory hot path, and a QMP shutdown
/// adapter. VMState capture uses the paired exact-snapshot API, while `loadvm`
/// remains confined to the explicit realization-policy API.
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

/// Ceiling for the boot-barrier priming quantum (nonzero, releases the BQL).
///
/// Kept small: priming advances the guest's raw icount off the boot barrier only
/// far enough to release the BQL so the QEMU main loop can service the QMP
/// `qmp_capabilities` handshake. The subsequent authorized `loadvm` restores the
/// checkpoint's full VMState -- guest RAM, CPU, devices, and icount -- so the
/// priming advance is overwritten and never reaches the warm-restore fingerprint.
const WARM_RESTORE_PRIME_CEILING_ICOUNT: u64 = 1_000_000;
/// Host poll interval while priming or pulsing the QMP wake.
const WARM_RESTORE_POLL_INTERVAL: Duration = Duration::from_millis(1);
/// Bounded deadline for the guest to reach the priming ceiling.
const WARM_RESTORE_PRIME_TIMEOUT: Duration = Duration::from_secs(120);
/// Wake pulse interval while connecting QMP.
const WARM_RESTORE_QMP_WAKE_INTERVAL: Duration = Duration::from_millis(10);

/// No-op send authorizer for the priming quantum's throwaway hot path.
///
/// Priming publishes a single ceiling to the node's own slot and never routes a
/// cross-node frame, so authorization is unconditional -- exactly as the live
/// bring-up gates authorize their priming hot paths.
struct PrimeSendAuthorizer;

impl SchedulerSendAuthorizer for PrimeSendAuthorizer {
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

/// Drives one priming quantum off the boot barrier, servicing each poll.
///
/// Right after the setup handshake the guest is parked at the boot barrier
/// holding the BQL while the plugin waits for its first ceiling, so QEMU's main
/// loop cannot acquire the BQL and a plain QMP connect times out. Publishing a
/// first ceiling (via `start_quantum` alone, exactly as the M1 install gate
/// releases the boot barrier) makes the guest execute and then park BETWEEN
/// quanta, where the patch-0025 `rr_wait_io_event` wait releases the BQL. The
/// throwaway hot path maps the same shared descriptor the node's own hot path
/// will map, so no ownership handoff is needed. `on_poll` is invoked with the
/// observed guest icount each poll so a block-capable caller can service device
/// I/O during priming (the guest's early virtio-blk probe otherwise blocks the
/// boot barrier); a non-servicing caller passes a no-op.
///
/// # Errors
///
/// Returns [`QemuWarmRestoreLaunchError`] when the region cannot be mapped, the
/// hot path cannot be constructed, the priming quantum cannot be published or
/// polled, or the guest does not reach the priming ceiling within `timeout`.
fn prime_off_boot_barrier(
    setup: &QemuHostPluginSetup,
    shmem_config: QemuQuantumShmemConfig,
    timeout: Duration,
    mut on_poll: impl FnMut(u64),
) -> Result<(), QemuWarmRestoreLaunchError> {
    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuWarmRestoreLaunchError::PrimeRegionMap { source })?;
    let mut hot_path =
        QemuMappedQuantumShmemHotPath::new(shmem_config, region, PrimeSendAuthorizer)
            .map_err(|source| QemuWarmRestoreLaunchError::PrimeHotPath { source })?;

    let horizon = ExecutionHorizon {
        icount: Icount {
            retired: WARM_RESTORE_PRIME_CEILING_ICOUNT,
        },
    };
    let pending = QemuShmemHotPathChannel::start_quantum(&mut hot_path, horizon)
        .map_err(|source| QemuWarmRestoreLaunchError::prime("start priming quantum", source))?;

    let max_polls = bounded_warm_restore_polls(timeout);
    let mut reached = false;
    for _ in 0..max_polls {
        let _ = setup.signal_plugin_wake();
        let current = QemuShmemHotPathChannel::current_icount(&mut hot_path)
            .map_err(|source| QemuWarmRestoreLaunchError::prime("poll priming icount", source))?
            .retired;
        on_poll(current);
        if current >= WARM_RESTORE_PRIME_CEILING_ICOUNT {
            reached = true;
            break;
        }
        thread::sleep(WARM_RESTORE_POLL_INTERVAL);
    }

    if !reached {
        return Err(QemuWarmRestoreLaunchError::PrimeStalled {
            ceiling_icount: WARM_RESTORE_PRIME_CEILING_ICOUNT,
        });
    }
    QemuShmemHotPathChannel::finish_quantum(&mut hot_path, pending)
        .map_err(|source| QemuWarmRestoreLaunchError::prime("finish priming quantum", source))?;
    Ok(())
}

/// Connects the typed QMP VMState channel while pulsing the plugin wake eventfd.
///
/// Even after priming releases the boot barrier the main loop can briefly re-park
/// between quanta, so a short-lived primer thread pulses the plugin wake to keep
/// the main loop iterating until the capabilities handshake completes.
///
/// # Errors
///
/// Returns [`QmpError`] when the QMP capabilities handshake still cannot complete.
fn connect_qmp_with_wake_pulsing(
    setup: &QemuHostPluginSetup,
    socket_path: &Path,
) -> Result<QemuQmpVmStateControlChannel<std::os::unix::net::UnixStream>, QmpError> {
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let primer = scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                let _ = setup.signal_plugin_wake();
                thread::sleep(WARM_RESTORE_QMP_WAKE_INTERVAL);
            }
        });
        let result = QemuQmpVmStateControlChannel::connect_unix_socket(socket_path);
        stop.store(true, Ordering::Relaxed);
        let _ = primer.join();
        result
    })
}

/// Returns the number of polls that fit within `timeout`, at least one.
fn bounded_warm_restore_polls(timeout: Duration) -> u64 {
    let interval = WARM_RESTORE_POLL_INTERVAL.as_micros().max(1);
    let budget = timeout.as_micros();
    u64::try_from(budget / interval).unwrap_or(u64::MAX).max(1)
}

/// Spawns QEMU, completes plugin setup, restores VMState, and assembles a node.
///
/// This is the Linux warm-realization composition path that the real QEMU
/// resume executor uses after launch command construction. It keeps each
/// lower-level boundary explicit: spawn owns fixed descriptor inheritance,
/// host setup owns plugin handoff, QMP owns checkpoint-tagged VMState restore,
/// and [`build_qemu_node_from_restored_checkpoint`] reduces QMP to
/// exact-snapshot capture control before returning the scheduler-facing [`QemuNode`].
///
/// # Boot-barrier priming
///
/// Immediately after the setup handshake the guest is parked at the boot barrier
/// holding the BQL, so a plain QMP connect would time out (the same BUG-1/BUG-2
/// the live bring-up gates solve). This path therefore drives one small priming
/// quantum off the boot barrier and pulses the plugin wake while connecting QMP.
/// `service_prime_poll` is invoked with the observed guest icount each priming
/// poll so a block-capable caller can service device I/O during priming; a
/// non-servicing caller passes `|_| {}`. Priming advances only the guest's raw
/// icount, which the subsequent authorized `loadvm` overwrites when it restores
/// the checkpoint's VMState (including icount) -- so the warm-restore fingerprint
/// is accounted for entirely by the restored checkpoint, not the priming advance.
///
/// # Errors
///
/// Returns [`QemuWarmRestoreLaunchError`] when the launch command has no QMP
/// channel, shared-memory layout computation fails, QEMU cannot be spawned, the
/// plugin setup handshake fails, priming the guest off the boot barrier stalls,
/// the QMP VMState channel cannot be connected, or final node assembly rejects
/// the restore plan.
pub fn spawn_setup_and_restore_qemu_node<A, R>(
    command: &QemuLaunchCommand,
    run_directory: impl AsRef<Path>,
    region_config: RegionConfig,
    slot_index: u32,
    restore: QemuNodeRestorePlan<'_>,
    mut runtime: QemuNodeFactoryRuntime<A, R>,
    service_prime_poll: impl FnMut(u64),
) -> Result<QemuNode, QemuWarmRestoreLaunchError>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
{
    let run_directory = run_directory.as_ref();
    runtime.shmem_config.coverage = match command.plugin_coverage() {
        QemuLaunchPluginSwitch::Off => BasicBlockCoverageConfig::off(),
        QemuLaunchPluginSwitch::On => BasicBlockCoverageConfig::on(),
    };
    let qmp = command
        .qmp_channel()
        .ok_or(QemuWarmRestoreLaunchError::MissingQmpChannel)?;
    let allocation = RegionAllocation::new(region_config)
        .map_err(|source| QemuWarmRestoreLaunchError::RegionLayout { source })?;
    let spawned = spawn_qemu_child_with_fds_in_directory(
        command,
        run_directory,
        allocation.layout().region_size,
    )
    .map_err(|source| QemuWarmRestoreLaunchError::Spawn { source })?;
    let (child, resources) = spawned.into_parts();
    let setup = match complete_qemu_host_plugin_setup_with_plugin_setup_plan(
        resources.into_setup_resources(),
        region_config,
        slot_index,
        command.fault_capability_requirement(),
        command.plugin_setup_plan(),
    ) {
        Ok(setup) => setup,
        Err(source) => {
            return Err(reap_failed_warm_restore_child(
                child,
                QemuWarmRestoreLaunchError::HostSetup { source },
            ));
        }
    };

    // Release the boot barrier before connecting QMP; service block I/O during
    // priming so a block-capable guest's early probe cannot wedge the barrier.
    if let Err(error) = prime_off_boot_barrier(
        &setup,
        runtime.shmem_config.clone(),
        WARM_RESTORE_PRIME_TIMEOUT,
        service_prime_poll,
    ) {
        return Err(reap_failed_warm_restore_child(child, error));
    }

    let qmp = match connect_qmp_with_wake_pulsing(&setup, &qmp.socket_path(run_directory)) {
        Ok(qmp) => qmp,
        Err(source) => {
            return Err(reap_failed_warm_restore_child(
                child,
                QemuWarmRestoreLaunchError::QmpConnect { source },
            ));
        }
    };
    build_qemu_node_from_restored_checkpoint(child, setup, qmp, restore, runtime)
        .map_err(|source| QemuWarmRestoreLaunchError::Factory { source })
}

/// Exact-root-bound inputs retained across one prepared warm restore.
pub(crate) struct QemuPreparedWarmRestoreLaunch<'a> {
    command: &'a QemuLaunchCommand,
    run_directory: &'a QemuPreparedRunDirectory,
    vmstate_binding: QemuVmStateBinding,
    process_contract: &'a QemuChildProcessContract,
    region_config: RegionConfig,
    slot_index: u32,
}

impl<'a> QemuPreparedWarmRestoreLaunch<'a> {
    /// Binds one prepared run directory to its process and shared-memory basis.
    pub(crate) const fn new(
        command: &'a QemuLaunchCommand,
        run_directory: &'a QemuPreparedRunDirectory,
        vmstate_binding: QemuVmStateBinding,
        process_contract: &'a QemuChildProcessContract,
        region_config: RegionConfig,
        slot_index: u32,
    ) -> Self {
        Self {
            command,
            run_directory,
            vmstate_binding,
            process_contract,
            region_config,
            slot_index,
        }
    }
}

/// Spawns and restores QEMU from one guarded prepared run directory.
///
/// Exact-root launch rejects a missing or different VMState binding before
/// shared-memory allocation or child spawn. A trusted baked-genesis or cached-
/// ancestor launcher instead supplies a separately authenticated thin-artifact
/// binding. Both paths use the child process contract to install cgroup
/// membership, sticky cancellation, file-size defense, and unprivileged
/// credentials in `pre_exec`.
/// The prepared directory remains descriptor-pinned throughout launch and QMP
/// socket resolution uses only its diagnostic path after guarded spawn has
/// reauthenticated the retained directory, VMState inode, and any required
/// root-overlay inode.
///
/// # Errors
///
/// Returns [`QemuWarmRestoreLaunchError`] when a required checkpoint-root
/// binding is absent or changed, the guarded spawn contract rejects launch,
/// plugin setup or priming fails, QMP cannot connect, or restored-node assembly
/// fails.
pub(crate) fn spawn_setup_and_restore_prepared_qemu_node_guarded<A, R>(
    launch: QemuPreparedWarmRestoreLaunch<'_>,
    restore: QemuNodeRestorePlan<'_>,
    mut runtime: QemuNodeFactoryRuntime<A, R>,
    service_prime_poll: impl FnMut(u64),
) -> Result<QemuNode, QemuWarmRestoreLaunchError>
where
    A: SchedulerSendAuthorizer + 'static,
    R: QemuHostIoRuntime + 'static,
{
    launch
        .run_directory
        .require_exact_launch_artifacts(launch.command, launch.vmstate_binding)
        .map_err(|source| QemuWarmRestoreLaunchError::Spawn { source })?;
    runtime.shmem_config.coverage = match launch.command.plugin_coverage() {
        QemuLaunchPluginSwitch::Off => BasicBlockCoverageConfig::off(),
        QemuLaunchPluginSwitch::On => BasicBlockCoverageConfig::on(),
    };
    let qmp = launch
        .command
        .qmp_channel()
        .ok_or(QemuWarmRestoreLaunchError::MissingQmpChannel)?;
    let allocation = RegionAllocation::new(launch.region_config)
        .map_err(|source| QemuWarmRestoreLaunchError::RegionLayout { source })?;
    let spawned = spawn_prepared_qemu_child_with_fds_in_directory_guarded(
        launch.command,
        launch.run_directory,
        allocation.layout().region_size,
        launch.process_contract,
    )
    .map_err(|source| QemuWarmRestoreLaunchError::Spawn { source })?;
    let (child, resources) = spawned.into_parts();
    let setup = match complete_qemu_host_plugin_setup_with_plugin_setup_plan(
        resources.into_setup_resources(),
        launch.region_config,
        launch.slot_index,
        launch.command.fault_capability_requirement(),
        launch.command.plugin_setup_plan(),
    ) {
        Ok(setup) => setup,
        Err(source) => {
            return Err(reap_failed_warm_restore_child(
                child,
                QemuWarmRestoreLaunchError::HostSetup { source },
            ));
        }
    };

    if let Err(error) = prime_off_boot_barrier(
        &setup,
        runtime.shmem_config.clone(),
        WARM_RESTORE_PRIME_TIMEOUT,
        service_prime_poll,
    ) {
        return Err(reap_failed_warm_restore_child(child, error));
    }

    let qmp = match connect_qmp_with_wake_pulsing(
        &setup,
        &qmp.socket_path(launch.run_directory.path()),
    ) {
        Ok(qmp) => qmp,
        Err(source) => {
            return Err(reap_failed_warm_restore_child(
                child,
                QemuWarmRestoreLaunchError::QmpConnect { source },
            ));
        }
    };
    build_qemu_node_from_restored_checkpoint(child, setup, qmp, restore, runtime)
        .map_err(|source| QemuWarmRestoreLaunchError::Factory { source })
}

/// Restores QEMU VMState, then builds a scheduler-facing QEMU node.
///
/// This is the warm-realization factory path: callers must provide an explicit
/// `loadvm` authorization token and matching admission proof before the QMP
/// channel is reduced to exact-snapshot capture and shutdown control. Baked-genesis restores use
/// an admission object produced by the realization coordinator after validating
/// the baked snapshot against its world; exact fat-checkpoint restores use
/// replay-oracle admission. Snapshot-completeness probes carry a probe-only
/// admission that cannot authorize a production runtime. Generic backend
/// snapshot/restore remains disabled on the returned [`QemuNode`].
///
/// # Errors
///
/// Returns [`QemuNodeFactoryError`] when the authorization does not match the
/// supplied admission proof, when the completed setup slot does not match the
/// shared-memory hot-path config, when QMP rejects the authorized VMState
/// restore, when the setup memfd cannot be mapped, or when the mapped hot-path
/// adapter rejects the completed region.
pub fn build_qemu_node_from_restored_checkpoint<S, A, R>(
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

/// Restores QEMU VMState into a scheduler-facing node that remains paused.
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
pub fn build_qemu_node_from_restored_checkpoint_paused<S, A, R>(
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
        authorization,
        admission,
        host_io_checkpoint,
        node_continuation,
    } = restore;
    if let Err(error) = validate_runtime_restore_authorization(authorization, admission) {
        return Err(reap_failed_restore_child(child, error));
    }
    if let Some(continuation) = node_continuation {
        if continuation.execution_binding() != checkpoint.id {
            return Err(reap_failed_restore_child(
                child,
                QemuNodeFactoryError::NodeContinuationRestore {
                    message: String::from(
                        "node continuation belongs to another VMState checkpoint",
                    ),
                },
            ));
        }
        if continuation.next_fault_command_sequence() < 2 {
            return Err(reap_failed_restore_child(
                child,
                QemuNodeFactoryError::NodeContinuationRestore {
                    message: String::from(
                        "restored fault-command sequence precedes setup capability admission",
                    ),
                },
            ));
        }
        let calibration = continuation.logical_time_calibration();
        if calibration.logical_icount != continuation.last_observed_time().ticks {
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
    }
    let mut prepared_setup = match prepare_qemu_node_setup(setup, shmem_config, send_authorizer) {
        Ok(prepared_setup) => prepared_setup,
        Err(error) => return Err(reap_failed_restore_child(child, error)),
    };
    let no_block_checkpoint = crate::QemuHostIoCheckpoint::without_devices(checkpoint.id);
    let host_io_checkpoint = host_io_checkpoint.unwrap_or(&no_block_checkpoint);
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
        let restored_icount = node_continuation
            .map_or(checkpoint.virtual_time.ticks, |continuation| {
                continuation.last_observed_time().ticks
            });
        let published_icount =
            QemuShmemHotPathChannel::current_icount(&mut prepared_setup.shmem_hot_path)
                .map_err(|source| QemuNodeFactoryError::VmStateRestoreCeiling { source })?
                .retired;
        let restore_ceiling = restored_icount.max(published_icount);
        prepared_setup
            .shmem_hot_path
            .arm_vmstate_restore_ceiling(restore_ceiling)
            .map_err(|source| QemuNodeFactoryError::VmStateRestoreCeiling { source })?;
        qmp.restore_checkpoint_vmstate_authorized(checkpoint)
            .map_err(|source| QemuNodeFactoryError::VmStateRestore { source })?;
        // The durable checkpoint closure retains the authoritative VMState
        // image. This child owns a materialized working copy. Once load has
        // completed, remove the consumed internal snapshot from that copy so a
        // deterministic replay may capture the same checkpoint identity again.
        // Keeping the anchor would make a correct replay fail with QEMU's
        // "snapshot already exists" error even though the live state matches.
        qmp.delete_checkpoint_vmstate(checkpoint)
            .map_err(|source| QemuNodeFactoryError::VmStateRestoreAnchorRelease { source })?;
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

    let restored_calibration = node_continuation.map_or(
        crate::QemuLogicalTimeCalibration {
            logical_icount: checkpoint.virtual_time.ticks,
            raw_icount: checkpoint.virtual_time.ticks,
        },
        crate::QemuNodeContinuationCheckpoint::logical_time_calibration,
    );
    let restored_icount = restored_calibration.logical_icount;
    let restore_generation = prepared_setup
        .shmem_hot_path
        .arm_logical_time_restore_boundary(restored_icount)
        .map_err(|source| QemuNodeFactoryError::LogicalTimeRestoreBoundary {
            stage: "arm",
            message: source.to_string(),
        });
    let restore_generation = match restore_generation {
        Ok(generation) => generation,
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
    let polls = bounded_warm_restore_polls(async_policy.qmp_command_timeout);
    let mut acknowledged = false;
    for attempt in 0..polls {
        let boundary_acknowledged = prepared_setup
            .shmem_hot_path
            .logical_time_restore_boundary_acknowledged(restore_generation, restored_calibration)
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
            thread::sleep(WARM_RESTORE_POLL_INTERVAL);
        }
    }
    if !acknowledged {
        return Err(reap_failed_restore_child(
            child,
            QemuNodeFactoryError::LogicalTimeRestoreBoundary {
                stage: "await acknowledgement",
                message: format!(
                    "plugin did not acknowledge generation {restore_generation} at icount {restored_icount} within {:?}",
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
    if let Some(continuation) = node_continuation
        && let Err(source) = node.restore_node_continuation(continuation)
    {
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
