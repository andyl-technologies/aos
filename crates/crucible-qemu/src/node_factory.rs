//! Linux factory for already-spawned QEMU nodes.
//!
//! This module composes the post-spawn pieces into the scheduler-facing
//! [`QemuNode`] wrapper after Linux descriptor setup and QMP negotiation have
//! already completed. It deliberately wraps VMState QMP in a shutdown-only
//! machine-control adapter so the generic backend snapshot/restore methods
//! cannot issue `savevm` or `loadvm` without the explicit realization-policy
//! authorization path.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::{
    BasicBlockCoverageConfig, Checkpoint, ContentHash, ExecutionHorizon, Icount, SchedulerError,
    SchedulerNodeId, SchedulerSendAuthorization, SchedulerSendAuthorizer,
};
use crucible_shmem::{
    RegionAllocation, RegionConfig, RegionLayoutError, SetupRegionMapError, mmap_setup_region,
};
use thiserror::Error;

use crate::{
    QemuAsyncDriverPolicy, QemuBakedGenesisRestoreAdmission, QemuCrashDetector, QemuHostIoRuntime,
    QemuHostPluginSetup, QemuHostPluginSetupError, QemuLaunchCommand, QemuLaunchPluginSwitch,
    QemuLoadvmCommandAuthorization, QemuLoadvmCommandPurpose, QemuLoadvmRealizationAdmission,
    QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError, QemuNode,
    QemuNodeChannelError, QemuNodeChannels, QemuNodeChild, QemuQmpMachineControlChannel,
    QemuQmpVmStateControlChannel, QemuQuantumShmemConfig, QemuShmemHotPathChannel,
    QemuShutdownPolicy, QemuSpawnError, QmpError, QmpTimeoutStream, complete_qemu_host_plugin_setup,
    spawn_qemu_child_with_fds_in_directory,
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
}

impl QemuWarmRestoreLaunchError {
    fn prime(context: &str, source: QemuNodeChannelError) -> Self {
        Self::Prime {
            context: context.to_owned(),
            source,
        }
    }
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
    admission: QemuNodeRestoreAdmission,
}

/// Admission proof for the VMState snapshot restored before node assembly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuNodeRestoreAdmission {
    /// The trusted baked ready-point snapshot produced by QEMU genesis baking.
    BakedGenesis {
        /// World identity whose baked genesis was validated.
        world_id: ContentHash,
    },
    /// A replay-oracle-validated exact fat checkpoint runtime.
    ReplayOracle(QemuLoadvmRealizationAdmission),
}

impl<'a> QemuNodeRestorePlan<'a> {
    /// Creates a warm-restore plan for an exact fat checkpoint.
    #[must_use]
    pub const fn new(
        checkpoint: &'a Checkpoint,
        authorization: QemuLoadvmCommandAuthorization,
        admission: QemuLoadvmRealizationAdmission,
    ) -> Self {
        Self {
            checkpoint,
            authorization,
            admission: QemuNodeRestoreAdmission::ReplayOracle(admission),
        }
    }

    /// Creates a warm-restore plan for a baked genesis ready-point checkpoint.
    #[must_use]
    pub fn baked_genesis(admission: QemuBakedGenesisRestoreAdmission<'a>) -> Self {
        Self {
            checkpoint: admission.checkpoint(),
            authorization: admission.authorization(),
            admission: QemuNodeRestoreAdmission::BakedGenesis {
                world_id: admission.world_id(),
            },
        }
    }

    /// Returns the checkpoint whose VMState will be restored.
    #[must_use]
    pub const fn checkpoint(&self) -> &'a Checkpoint {
        self.checkpoint
    }

    /// Returns the low-level QMP `loadvm` authorization token.
    #[must_use]
    pub const fn authorization(&self) -> QemuLoadvmCommandAuthorization {
        self.authorization
    }

    /// Returns the admission proof paired with the restore authorization.
    #[must_use]
    pub const fn admission(&self) -> QemuNodeRestoreAdmission {
        self.admission
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
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, PrimeSendAuthorizer)
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
/// shutdown-only control before returning the scheduler-facing [`QemuNode`].
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
    let setup = complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        region_config,
        slot_index,
    )
    .map_err(|source| QemuWarmRestoreLaunchError::HostSetup { source })?;

    // Release the boot barrier before connecting QMP; service block I/O during
    // priming so a block-capable guest's early probe cannot wedge the barrier.
    prime_off_boot_barrier(
        &setup,
        runtime.shmem_config.clone(),
        WARM_RESTORE_PRIME_TIMEOUT,
        service_prime_poll,
    )?;

    let qmp = connect_qmp_with_wake_pulsing(&setup, &qmp.socket_path(run_directory))
        .map_err(|source| QemuWarmRestoreLaunchError::QmpConnect { source })?;
    build_qemu_node_from_restored_checkpoint(child, setup, qmp, restore, runtime)
        .map_err(|source| QemuWarmRestoreLaunchError::Factory { source })
}

/// Restores QEMU VMState, then builds a scheduler-facing QEMU node.
///
/// This is the warm-realization factory path: callers must provide an explicit
/// `loadvm` authorization token and matching admission proof before the QMP
/// channel is reduced to shutdown-only node control. Baked-genesis restores use
/// an admission object produced by the realization coordinator after validating
/// the baked snapshot against its world; exact fat-checkpoint restores use
/// replay-oracle admission. Generic backend snapshot/restore remains disabled
/// on the returned [`QemuNode`].
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
    validate_runtime_restore_authorization(authorization, admission)?;
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
    admission: QemuNodeRestoreAdmission,
) -> Result<(), QemuNodeFactoryError> {
    let purpose = authorization.purpose();
    match (purpose, admission) {
        (
            QemuLoadvmCommandPurpose::RuntimeRealization,
            QemuNodeRestoreAdmission::ReplayOracle(admission),
        ) => {
            let _admitted_runtime_hash = admission.runtime_hash();
            Ok(())
        }
        (
            QemuLoadvmCommandPurpose::BakedGenesisRealization,
            QemuNodeRestoreAdmission::BakedGenesis { world_id },
        ) => {
            let _admitted_world_id = world_id;
            Ok(())
        }
        (purpose, _) => Err(QemuNodeFactoryError::VmStateRestoreAuthorization { purpose }),
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests;
