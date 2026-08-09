//! Live [`QemuNode`] block-I/O bring-up gate -- the CP3 / T-PLUG-12 acceptance
//! vehicle for real guest block I/O through the production node shape.
//!
//! This gate boots the diskless-firmware guest with a `crucible-shmem`
//! virtio-blk device attached to a real [`QemuNode`] (QMP + host-I/O runtime),
//! weaving a [`QemuLiveBlockIoServicer`] into BOTH the boot-barrier priming
//! quantum and every advance poll, and then drives the node toward a busy-window
//! ceiling and classifies the outcome:
//!
//! - **Pre-0039 baseline (today).** The guest blocks on its early virtio-blk
//!   probe read and cannot advance past the host-computed completion
//!   `delivery_icount` (the SCHED-8 device-horizon gap: nothing advances a guest
//!   halted on device I/O). The gate asserts this KNOWN stall SIGNATURE
//!   (a request was processed, none delivered, device I/O still held, the guest
//!   never reached the completion horizon) and exits cleanly -- a characterization
//!   baseline, not a timeout.
//! - **Post-0039 (once the device-completion delivery patch lands).** The guest
//!   progresses past the block I/O; the same harness flips to asserting real
//!   progress (a response delivered, the guest advanced past the completion),
//!   run-twice byte-identical, and the baseline leg becomes the negative control
//!   (servicer withheld => the stall signature reappears).
//!
//! Until 0039 lands this gate is a green characterization of the gap; the
//! `block_io_gate` raw-drive diagnostic remains the observation companion.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::{
    AdvanceOutcome, Icount, NodeId, SchedulerError, SchedulerNodeId, SchedulerSendAuthorization,
    SchedulerSendAuthorizer,
};
use crucible_shmem::{RegionAllocation, RegionConfig, SLOT_NET_ROUTER, mmap_setup_region};
use thiserror::Error;

use super::block_io_servicer::{
    BlockIoDiagnostics, BlockIoDiagnosticsSnapshot, QemuLiveBlockIoServicer,
    QemuLiveBlockIoServicerError,
};
use super::{QemuLiveHostIoRuntime, QemuLiveHostIoRuntimeError};
use crate::{
    CrucibleShmemBlockDevice, LaunchProfileCandidate, LaunchProfileError, QemuAsyncDriverPolicy,
    QemuCrashDetector, QemuHostPluginSetup, QemuHostPluginSetupError, QemuLaunchArtifact,
    QemuLaunchCommandBuilder, QemuLaunchCommandError, QemuLaunchPluginConfig,
    QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError, QemuNode,
    QemuNodeChannelError, QemuNodeError, QemuNodeFactoryError, QemuNodeFactoryRuntime,
    QemuQmpChannelConfig, QemuQmpVmStateControlChannel, QemuQuantumShmemConfig,
    QemuShmemHotPathChannel, QemuShutdownPolicy, QemuVmLaunchConfig, QmpError,
    build_qemu_node_from_completed_setup, complete_qemu_host_plugin_setup,
    spawn_qemu_child_with_fds_in_directory,
};

/// Content-addressing domain for block-node launch artifacts.
const GATE_DOMAIN: &str = "crucible.loaded-qemu-live-block-node.v1";
const GATE_NODE: &str = "live-block-node-vm";
const GATE_ROUTER: &str = "live-block-node-router";
const GATE_SLOT: u32 = 0;
const GATE_QUEUE_CAPACITY: u32 = 4;
const GATE_MEMORY_MIB: u32 = 64;
const GATE_QMP_SOCKET_FILE_NAME: &str = "crucible-live-block-node-qmp.sock";
const GATE_CRASH_NODE_ID: &str = "live-block-node";

/// Ceiling for the boot-barrier priming quantum (nonzero, releases the BQL).
const PRIME_CEILING_ICOUNT: u64 = 1_000_000;
/// Host poll interval while priming / driving.
const POLL_INTERVAL: Duration = Duration::from_millis(1);
/// Wake pulse interval while connecting QMP.
const QMP_PRIMER_WAKE_INTERVAL: Duration = Duration::from_millis(10);
/// Consecutive no-progress advance polls before the drive is declared stalled.
const DRIVE_STALL_POLLS: u64 = 4_000;

/// Inputs for one live block-node gate run.
#[derive(Clone, Debug)]
pub struct QemuLiveBlockNodeGateConfig {
    qemu_executable: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    firmware: PathBuf,
    run_directory: PathBuf,
    initrd: Option<PathBuf>,
    kernel_cmdline: Option<String>,
    device_size_bytes: u64,
    busy_ceiling_icount: u64,
    completion_timeout: Duration,
}

impl QemuLiveBlockNodeGateConfig {
    /// Builds a block-node configuration with bounded defaults.
    #[must_use]
    pub fn new(
        qemu_executable: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
        kernel: impl Into<PathBuf>,
        firmware: impl Into<PathBuf>,
        run_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            qemu_executable: qemu_executable.into(),
            plugin: plugin.into(),
            kernel: kernel.into(),
            firmware: firmware.into(),
            run_directory: run_directory.into(),
            initrd: None,
            kernel_cmdline: None,
            device_size_bytes: 4 * 1024 * 1024,
            busy_ceiling_icount: 12_000_000,
            completion_timeout: Duration::from_secs(60),
        }
    }

    /// Returns this configuration with a content-addressed initrd.
    #[must_use]
    pub fn with_initrd(mut self, initrd: impl Into<PathBuf>) -> Self {
        self.initrd = Some(initrd.into());
        self
    }

    /// Returns this configuration with an explicit guest kernel command line.
    #[must_use]
    pub fn with_kernel_cmdline(mut self, kernel_cmdline: impl Into<String>) -> Self {
        self.kernel_cmdline = Some(kernel_cmdline.into());
        self
    }

    /// Returns this configuration with a different block-device size.
    #[must_use]
    pub const fn with_device_size_bytes(mut self, device_size_bytes: u64) -> Self {
        self.device_size_bytes = device_size_bytes;
        self
    }

    /// Returns this configuration with a different busy-window ceiling.
    #[must_use]
    pub const fn with_busy_ceiling_icount(mut self, busy_ceiling_icount: u64) -> Self {
        self.busy_ceiling_icount = busy_ceiling_icount;
        self
    }

    /// Returns this configuration with a different per-phase completion bound.
    #[must_use]
    pub const fn with_completion_timeout(mut self, completion_timeout: Duration) -> Self {
        self.completion_timeout = completion_timeout;
        self
    }
}

/// How the drive toward the busy ceiling resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockNodeOutcome {
    /// Pre-0039 baseline: the guest stalled on device I/O with the known
    /// device-horizon signature (request processed, none delivered, device I/O
    /// held, guest never reached the completion horizon).
    DeviceHorizonStall,
    /// Post-0039: the guest progressed past the serviced block I/O and advanced
    /// beyond the completion horizon.
    ProgressedPastBlockIo,
}

/// The observed outcome of one block-node gate run.
#[derive(Clone, Debug)]
pub struct QemuLiveBlockNodeReport {
    outcome: BlockNodeOutcome,
    diagnostics: BlockIoDiagnosticsSnapshot,
    reached_icount: u64,
}

impl QemuLiveBlockNodeReport {
    /// Returns the classified drive outcome.
    #[must_use]
    pub const fn outcome(&self) -> BlockNodeOutcome {
        self.outcome
    }

    /// Returns the accumulated block-I/O observations.
    #[must_use]
    pub const fn diagnostics(&self) -> &BlockIoDiagnosticsSnapshot {
        &self.diagnostics
    }

    /// Returns the highest guest icount reached during the drive.
    #[must_use]
    pub const fn reached_icount(&self) -> u64 {
        self.reached_icount
    }

    /// Returns whether the guest progressed past the serviced block I/O.
    #[must_use]
    pub const fn guest_progressed_past_block_io(&self) -> bool {
        matches!(self.outcome, BlockNodeOutcome::ProgressedPastBlockIo)
    }
}

/// Boots the diskless-firmware guest with a `crucible-shmem` block device on a
/// live [`QemuNode`], services block I/O through priming and advance, and
/// classifies whether the guest stalled on the device horizon (pre-0039) or
/// progressed past it (post-0039).
///
/// # Errors
///
/// Returns [`QemuLiveBlockNodeGateError`] when launch, host setup, priming, QMP
/// connect, node construction, or the drive fails for a reason other than the
/// characterized device-horizon stall (which is a successful classification).
pub fn run_qemu_live_block_node_gate(
    config: &QemuLiveBlockNodeGateConfig,
) -> Result<QemuLiveBlockNodeReport, QemuLiveBlockNodeGateError> {
    fs::create_dir_all(&config.run_directory).map_err(|source| {
        QemuLiveBlockNodeGateError::PrepareRunDirectory {
            path: config.run_directory.clone(),
            source,
        }
    })?;

    let mut candidate = LaunchProfileCandidate::default().with_memory_mib(GATE_MEMORY_MIB);
    if let Some(cmdline) = &config.kernel_cmdline {
        candidate = candidate.with_kernel_cmdline(cmdline.clone());
    }
    let profile = candidate
        .try_into_deterministic()
        .map_err(|source| QemuLiveBlockNodeGateError::LaunchProfile { source })?;
    let icount_shift = profile.icount_shift();
    profile
        .guest_entropy_seed_file()
        .write_to_dir(&config.run_directory)
        .map_err(|source| QemuLiveBlockNodeGateError::GuestEntropySeed {
            path: config.run_directory.clone(),
            source,
        })?;

    let qmp_config = QemuQmpChannelConfig::new(GATE_QMP_SOCKET_FILE_NAME)
        .map_err(|source| QemuLiveBlockNodeGateError::QmpChannelConfig { source })?;
    let plugin = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT)
        .with_fault_target_node(GATE_NODE);
    let command = QemuLaunchCommandBuilder::new_for_live_gate(
        profile,
        vm_launch_config(config),
        path_text(&config.qemu_executable),
        plugin,
        crate::LivePluginGuestArchitecture::X86_64,
    )
    .with_qmp(qmp_config.clone())
    .build()
    .map_err(|source| QemuLiveBlockNodeGateError::LaunchCommand { source })?;

    let region_config = RegionConfig::new(1, GATE_QUEUE_CAPACITY, 0);
    let allocation = RegionAllocation::new(region_config)
        .map_err(|source| QemuLiveBlockNodeGateError::RegionLayout { source })?;
    let spawned = spawn_qemu_child_with_fds_in_directory(
        &command,
        &config.run_directory,
        allocation.layout().region_size,
    )
    .map_err(|source| QemuLiveBlockNodeGateError::Spawn { source })?;
    let (child, resources) = spawned.into_parts();

    let setup = complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        region_config,
        GATE_SLOT,
        command.fault_capability_requirement(),
    )
    .map_err(|source| QemuLiveBlockNodeGateError::HostSetup { source })?;
    if !setup.setup_ack().can_schedule() {
        return Err(QemuLiveBlockNodeGateError::SetupAckNotReady);
    }

    let runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        setup.shmem_as_fd(),
        setup.wake_as_fd(),
        setup.region().region_len,
        GATE_SLOT,
    )
    .map_err(|source| QemuLiveBlockNodeGateError::HostIoRuntime { source })?;

    // The block servicer owns a writable mapping confined to the SLOT_BLK_IO
    // ring pair; diagnostics are shared so observations survive teardown.
    let diagnostics = BlockIoDiagnostics::shared();
    let mut servicer = QemuLiveBlockIoServicer::from_shmem_fd(
        setup.shmem_as_fd(),
        setup.region().region_len,
        GATE_SLOT,
        icount_shift,
        config.device_size_bytes,
    )
    .map_err(|source| QemuLiveBlockNodeGateError::BlockServicer { source })?;

    // Prime off the boot barrier WHILE servicing block I/O. Without servicing
    // during priming the guest blocks on the virtio-blk probe read before the
    // boot barrier lifts; with servicing the request is drained and its deadline
    // published, though (pre-0039) the guest still cannot advance to it.
    let prime_reached =
        prime_guest_servicing_block_io(&setup, &mut servicer, &diagnostics, config)?;

    let qmp = if prime_reached {
        Some(
            connect_qmp_priming_main_loop(&setup, &qmp_config.socket_path(&config.run_directory))
                .map_err(|source| QemuLiveBlockNodeGateError::QmpConnect { source })?,
        )
    } else {
        None
    };

    // If priming never lifted the guest off the boot barrier (the pre-0039
    // reality with a block device attached), classify the device-horizon stall
    // from the priming observations rather than attempting node construction.
    let Some(qmp) = qmp else {
        let mut reap = child;
        let _ = reap_child(&mut reap, config.completion_timeout);
        return classify(&diagnostics, BlockNodeOutcome::DeviceHorizonStall);
    };

    let runtime = runtime
        .with_block_servicer(servicer, Arc::clone(&diagnostics))
        .map_err(|source| QemuLiveBlockNodeGateError::BlockServicer { source })?;
    let shmem_config = QemuQuantumShmemConfig::new(node_id(GATE_NODE), GATE_SLOT)
        .with_router(node_id(GATE_ROUTER), SLOT_NET_ROUTER as u32);
    let factory_runtime = QemuNodeFactoryRuntime::new(
        shmem_config,
        GateSendAuthorizer,
        gate_shutdown_policy(),
        gate_async_policy(config.completion_timeout),
        QemuCrashDetector::new(GATE_CRASH_NODE_ID),
        runtime,
    );
    let mut node = build_qemu_node_from_completed_setup(child, setup, qmp, factory_runtime)
        .map_err(|source| QemuLiveBlockNodeGateError::NodeFactory { source })?;

    let outcome = drive_or_detect_stall(&mut node, &diagnostics, config)?;

    let _ = node.shutdown_child();
    drop(node);

    classify(&diagnostics, outcome)
}

/// Builds the final report, asserting the classification's invariants.
fn classify(
    diagnostics: &BlockIoDiagnostics,
    outcome: BlockNodeOutcome,
) -> Result<QemuLiveBlockNodeReport, QemuLiveBlockNodeGateError> {
    let snapshot = diagnostics.snapshot();
    match outcome {
        BlockNodeOutcome::DeviceHorizonStall => {
            // Pre-0039 baseline signature: the guest issued a block request that
            // the servicer processed, the servicer computed a completion horizon,
            // the guest never advanced to that horizon, and no response was
            // delivered.
            let horizon = snapshot.first_completion_horizon;
            let stalled = snapshot.frames_processed >= 1
                && snapshot.frames_delivered == 0
                && horizon.is_some_and(|h| snapshot.max_current_icount < h);
            if !stalled {
                return Err(QemuLiveBlockNodeGateError::UnexpectedSignature {
                    detail: format!(
                        "device-horizon stall signature not met: processed={} delivered={} horizon={:?} max_icount={}",
                        snapshot.frames_processed,
                        snapshot.frames_delivered,
                        horizon,
                        snapshot.max_current_icount
                    ),
                });
            }
        }
        BlockNodeOutcome::ProgressedPastBlockIo => {
            let horizon = snapshot.first_completion_horizon;
            let progressed = snapshot.frames_delivered >= 1
                && horizon.is_some_and(|h| snapshot.max_current_icount >= h);
            if !progressed {
                return Err(QemuLiveBlockNodeGateError::UnexpectedSignature {
                    detail: format!(
                        "progress signature not met: delivered={} horizon={:?} max_icount={}",
                        snapshot.frames_delivered, horizon, snapshot.max_current_icount
                    ),
                });
            }
        }
    }
    Ok(QemuLiveBlockNodeReport {
        outcome,
        reached_icount: snapshot.max_current_icount,
        diagnostics: snapshot,
    })
}

/// Drives the priming quantum while servicing block I/O; returns whether the
/// guest reached the priming ceiling (i.e. got off the boot barrier).
fn prime_guest_servicing_block_io(
    setup: &QemuHostPluginSetup,
    servicer: &mut QemuLiveBlockIoServicer,
    diagnostics: &BlockIoDiagnostics,
    config: &QemuLiveBlockNodeGateConfig,
) -> Result<bool, QemuLiveBlockNodeGateError> {
    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuLiveBlockNodeGateError::PrimeRegionMap { source })?;
    let shmem_config = QemuQuantumShmemConfig::new(node_id(GATE_NODE), GATE_SLOT)
        .with_router(node_id(GATE_ROUTER), SLOT_NET_ROUTER as u32);
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, GateSendAuthorizer)
        .map_err(|source| QemuLiveBlockNodeGateError::PrimeHotPath { source })?;

    let horizon = crucible::ExecutionHorizon {
        icount: Icount {
            retired: PRIME_CEILING_ICOUNT,
        },
    };
    let pending = QemuShmemHotPathChannel::start_quantum(&mut hot_path, horizon)
        .map_err(|source| QemuLiveBlockNodeGateError::prime("start priming quantum", source))?;

    let max_polls = bounded_polls(config.completion_timeout);
    let mut reached = false;
    for _ in 0..max_polls {
        let _ = setup.signal_plugin_wake();
        if let Ok(snapshot) = servicer.vm_node_snapshot() {
            let serviced = servicer
                .service(snapshot.current_icount)
                .map_err(|source| QemuLiveBlockNodeGateError::BlockServicer { source })?;
            diagnostics.record(
                snapshot.current_icount,
                snapshot.device_io_active != 0,
                snapshot.idle_wake_icount,
                &serviced,
            );
            if snapshot.current_icount >= PRIME_CEILING_ICOUNT {
                reached = true;
                break;
            }
        }
        thread::sleep(POLL_INTERVAL);
    }

    let _ = QemuShmemHotPathChannel::finish_quantum(&mut hot_path, pending);
    Ok(reached)
}

/// Drives the node toward the busy ceiling, classifying stall versus progress.
fn drive_or_detect_stall(
    node: &mut QemuNode,
    diagnostics: &BlockIoDiagnostics,
    config: &QemuLiveBlockNodeGateConfig,
) -> Result<BlockNodeOutcome, QemuLiveBlockNodeGateError> {
    let ceiling = config.busy_ceiling_icount;
    let mut last_icount = 0_u64;
    let mut stall_polls = 0_u64;
    let max_polls = bounded_polls(config.completion_timeout);
    for _ in 0..max_polls {
        let outcome = node
            .advance_to_ceiling(Icount { retired: ceiling })
            .map_err(|source| QemuLiveBlockNodeGateError::node_op("advance to ceiling", source))?;
        let current = node
            .current_icount()
            .map_err(|source| QemuLiveBlockNodeGateError::node_op("read icount", source))?
            .retired;

        let snapshot = diagnostics.snapshot();
        if snapshot.frames_delivered >= 1
            && snapshot
                .first_completion_horizon
                .is_some_and(|h| current >= h)
        {
            return Ok(BlockNodeOutcome::ProgressedPastBlockIo);
        }
        if matches!(outcome, AdvanceOutcome::ReachedHorizon) && current >= ceiling {
            return Ok(BlockNodeOutcome::ProgressedPastBlockIo);
        }

        if current > last_icount {
            last_icount = current;
            stall_polls = 0;
        } else {
            stall_polls += 1;
            if stall_polls >= DRIVE_STALL_POLLS {
                return Ok(BlockNodeOutcome::DeviceHorizonStall);
            }
        }
        thread::sleep(POLL_INTERVAL);
    }
    Ok(BlockNodeOutcome::DeviceHorizonStall)
}

/// Connects the typed QMP channel while pulsing the plugin wake eventfd.
fn connect_qmp_priming_main_loop(
    setup: &QemuHostPluginSetup,
    socket_path: &Path,
) -> Result<QemuQmpVmStateControlChannel<std::os::unix::net::UnixStream>, QmpError> {
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let primer = scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                let _ = setup.signal_plugin_wake();
                thread::sleep(QMP_PRIMER_WAKE_INTERVAL);
            }
        });
        let result = QemuQmpVmStateControlChannel::connect_unix_socket(socket_path);
        stop.store(true, Ordering::Relaxed);
        let _ = primer.join();
        result
    })
}

/// Reaps the child within a bounded budget, relying on Drop to force-kill.
fn reap_child(child: &mut crate::QemuNodeChild, timeout: Duration) -> bool {
    let max_polls = bounded_polls(timeout);
    for _ in 0..max_polls {
        match child.try_wait_natural_exit() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(_) => return false,
        }
    }
    false
}

/// Returns the number of polls that fit within `timeout`, at least one.
fn bounded_polls(timeout: Duration) -> u64 {
    let interval = POLL_INTERVAL.as_micros().max(1);
    let budget = timeout.as_micros();
    u64::try_from(budget / interval).unwrap_or(u64::MAX).max(1)
}

/// Builds the diskless-firmware VM launch config with a crucible-shmem block device.
fn vm_launch_config(config: &QemuLiveBlockNodeGateConfig) -> QemuVmLaunchConfig {
    let kernel = launch_artifact("kernel", &config.kernel);
    let vm = QemuVmLaunchConfig::new_diskless(
        GATE_NODE,
        kernel,
        launch_artifact("firmware", &config.firmware),
    )
    .with_crucible_shmem_block(CrucibleShmemBlockDevice::new(config.device_size_bytes));
    match &config.initrd {
        Some(initrd) => vm.with_initrd(launch_artifact("initrd", initrd)),
        None => vm,
    }
}

fn launch_artifact(kind: &str, path: &Path) -> QemuLaunchArtifact {
    let path = path_text(path);
    QemuLaunchArtifact::new(
        crucible::ContentHash::from_canonical_material(GATE_DOMAIN, &format!("{kind}={path}")),
        path,
    )
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn gate_shutdown_policy() -> QemuShutdownPolicy {
    QemuShutdownPolicy {
        control_quit_wait: Duration::from_secs(2),
        qmp_quit_wait: Duration::from_secs(5),
        sigterm_wait: Duration::from_secs(5),
        sigkill_wait: Duration::from_secs(5),
        reap_wait: Duration::from_secs(5),
    }
}

fn gate_async_policy(completion_timeout: Duration) -> QemuAsyncDriverPolicy {
    QemuAsyncDriverPolicy::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        completion_timeout,
    )
}

/// Authorizes every scheduler send for this single-node gate.
///
/// The gate has one VM and one router slot and never routes a real cross-node
/// frame, so authorization is unconditional.
struct GateSendAuthorizer;

impl SchedulerSendAuthorizer for GateSendAuthorizer {
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

/// Error raised while running the live block-node gate.
#[derive(Debug, Error)]
pub enum QemuLiveBlockNodeGateError {
    /// The run directory could not be prepared.
    #[error("prepare run directory {path}")]
    PrepareRunDirectory {
        /// The directory that could not be created.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The deterministic launch profile could not be built.
    #[error("build launch profile")]
    LaunchProfile {
        /// Underlying profile error.
        source: LaunchProfileError,
    },
    /// The guest entropy seed could not be written.
    #[error("write guest entropy seed to {path}")]
    GuestEntropySeed {
        /// The directory that could not receive the seed.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The QMP channel configuration was invalid.
    #[error("configure QMP channel")]
    QmpChannelConfig {
        /// Underlying launch-command error.
        source: QemuLaunchCommandError,
    },
    /// The launch command could not be built.
    #[error("build launch command")]
    LaunchCommand {
        /// Underlying command error.
        source: QemuLaunchCommandError,
    },
    /// The shared-memory region layout was invalid.
    #[error("allocate shared-memory region")]
    RegionLayout {
        /// Underlying region error.
        source: crucible_shmem::RegionLayoutError,
    },
    /// The QEMU child could not be spawned.
    #[error("spawn QEMU child")]
    Spawn {
        /// Underlying spawn error.
        source: crate::QemuSpawnError,
    },
    /// The host plugin setup handshake failed.
    #[error("complete host plugin setup")]
    HostSetup {
        /// Underlying setup error.
        source: QemuHostPluginSetupError,
    },
    /// The setup handshake reported the node could not be scheduled.
    #[error("setup ack not ready to schedule")]
    SetupAckNotReady,
    /// The host-I/O runtime could not be constructed.
    #[error("construct host-I/O runtime")]
    HostIoRuntime {
        /// Underlying runtime error.
        source: QemuLiveHostIoRuntimeError,
    },
    /// The block servicer could not be constructed or serviced.
    #[error("block servicer")]
    BlockServicer {
        /// Underlying servicer error.
        source: QemuLiveBlockIoServicerError,
    },
    /// The priming region could not be mapped.
    #[error("map priming region")]
    PrimeRegionMap {
        /// Underlying map error.
        source: crucible_shmem::SetupRegionMapError,
    },
    /// The priming hot path could not be constructed.
    #[error("construct priming hot path")]
    PrimeHotPath {
        /// Underlying hot-path error.
        source: QemuMappedQuantumShmemHotPathError,
    },
    /// A priming hot-path operation failed.
    #[error("priming: {context}")]
    Prime {
        /// What the priming step was doing.
        context: String,
        /// Underlying channel error.
        source: QemuNodeChannelError,
    },
    /// The QMP capabilities handshake could not complete.
    #[error("connect QMP")]
    QmpConnect {
        /// Underlying QMP error.
        source: QmpError,
    },
    /// The node could not be constructed from the completed setup.
    #[error("construct node from completed setup")]
    NodeFactory {
        /// Underlying factory error.
        source: QemuNodeFactoryError,
    },
    /// A node operation failed during the drive.
    #[error("node op: {context}")]
    NodeOp {
        /// What the node operation was doing.
        context: String,
        /// Underlying node error.
        source: QemuNodeError,
    },
    /// The classified outcome did not meet its required signature.
    #[error("unexpected outcome signature: {detail}")]
    UnexpectedSignature {
        /// Human-readable signature mismatch detail.
        detail: String,
    },
}

impl QemuLiveBlockNodeGateError {
    fn prime(context: &str, source: QemuNodeChannelError) -> Self {
        Self::Prime {
            context: context.to_owned(),
            source,
        }
    }

    fn node_op(context: &str, source: QemuNodeError) -> Self {
        Self::NodeOp {
            context: context.to_owned(),
            source,
        }
    }
}
