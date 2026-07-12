//! Loaded-QEMU proof for the Rust control plugin's install and boot lifecycle.
//!
//! This module owns the production integration gate that boots the patched QEMU
//! binary once with the real Rust control plugin (`libcrucible_qemu_plugin.so`)
//! loaded through the fixed inherited descriptors, and drives the full install
//! lifecycle end to end: connect, `Hello`/`HelloAck` handshake with exact ABI and
//! slot cross-check, `SCM_RIGHTS` descriptor handover, shared-memory map and
//! header validation, `SetupAck`, boot-barrier release through the first
//! scheduler ceiling, a single exact-icount quantum, run-control silence, control
//! `Quit` teardown, and natural child exit with no leaked process.
//!
//! Unlike [`crate::run_loaded_qemu_coverage_gate`], this gate loads **only** the
//! Rust control plugin: no independent observation plugin sets a horizon, so the
//! Rust plugin is the sole `sim_shmem` dispatch authority that owns virtual-time
//! advancement. The guest stops at exactly the host-published ceiling only
//! because the plugin blocked on the boot barrier and then honored that ceiling,
//! which is the live proof the coded-but-mocked plugin lifecycle was missing.
//!
//! The emitted [`LivePluginInstallReport`] records each lifecycle milestone plus
//! `time_authority=rust-plugin` so the gate cannot silently regress to a mode in
//! which some other plugin owns time control.

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crucible::{
    ExecutionFingerprint, ExecutionHorizon, Icount, NodeId, SchedulerError, SchedulerNodeId,
    SchedulerSendAuthorization, SchedulerSendAuthorizer,
};
use crucible_shmem::{
    RegionAllocation, RegionConfig, RegionLayoutError, SLOT_NET_ROUTER, SetupRegionMapError,
    mmap_setup_region,
};
use thiserror::Error;

use crate::{
    LaunchProfileCandidate, LaunchProfileError, QemuHostPluginSetupError, QemuLaunchArtifact,
    QemuLaunchCommandError, QemuLaunchPluginConfig, QemuMappedQuantumShmemHotPath,
    QemuMappedQuantumShmemHotPathError, QemuNodeChannelError, QemuPluginIpcControlChannel,
    QemuQuantumShmemConfig, QemuShmemHotPathChannel, QemuSpawnError, QemuVmLaunchConfig,
    complete_qemu_host_plugin_setup, spawn_qemu_child_with_fds_in_directory,
};

/// Content-addressing domain for install-gate launch artifacts.
const GATE_DOMAIN: &str = "crucible.loaded-qemu-plugin-install.v1";
/// Stable node name for the single-VM install run.
const GATE_NODE: &str = "plugin-install-gate-vm";
/// Stable router name reserved by the shared-memory hot path.
const GATE_ROUTER: &str = "plugin-install-gate-router";
/// VM slot negotiated during the handshake.
const GATE_SLOT: u32 = 0;
/// Fixed inbound/outbound ring capacity for the single-node install run.
const GATE_QUEUE_CAPACITY: u32 = 4;
/// Conservative guest memory size for the install run.
const GATE_MEMORY_MIB: u32 = 64;
/// Default exact icount boundary for the install run.
///
/// Reuses the proven basic-block-coverage horizon so the standalone guest is
/// known to remain alive across the boundary under TCG.
const DEFAULT_HORIZON_ICOUNT: u64 = 16_000_000;
/// Default host-side diagnostic timeout bounding each liveness wait.
const DEFAULT_COMPLETION_TIMEOUT: Duration = Duration::from_secs(60);
/// Host poll interval while waiting on the plugin-owned boundary or teardown.
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Inputs for one production loaded-QEMU plugin install lifecycle run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivePluginInstallGateConfig {
    qemu_executable: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    root_image: PathBuf,
    run_directory: PathBuf,
    initrd: Option<PathBuf>,
    kernel_cmdline: Option<String>,
    horizon_icount: u64,
    completion_timeout: Duration,
}

impl LivePluginInstallGateConfig {
    /// Builds an install-gate configuration with bounded defaults.
    #[must_use]
    pub fn new(
        qemu_executable: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
        kernel: impl Into<PathBuf>,
        root_image: impl Into<PathBuf>,
        run_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            qemu_executable: qemu_executable.into(),
            plugin: plugin.into(),
            kernel: kernel.into(),
            root_image: root_image.into(),
            run_directory: run_directory.into(),
            initrd: None,
            kernel_cmdline: None,
            horizon_icount: DEFAULT_HORIZON_ICOUNT,
            completion_timeout: DEFAULT_COMPLETION_TIMEOUT,
        }
    }

    /// Returns this configuration with a content-addressed initrd.
    ///
    /// A Linux guest that boots to a userspace init and idles (`sti; hlt`
    /// waiting on the virtual timer) exercises the plugin's idle-loop,
    /// deadline-introspection, and idle-jump paths, unlike a spin-only guest.
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

    /// Returns this configuration with a different exact icount boundary.
    #[must_use]
    pub const fn with_horizon_icount(mut self, horizon_icount: u64) -> Self {
        self.horizon_icount = horizon_icount;
        self
    }

    /// Returns this configuration with a different host-side completion bound.
    #[must_use]
    pub const fn with_completion_timeout(mut self, completion_timeout: Duration) -> Self {
        self.completion_timeout = completion_timeout;
        self
    }
}

/// Successful evidence from the production loaded-QEMU plugin install gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivePluginInstallReport {
    /// Control protocol version negotiated during the handshake.
    pub negotiated_proto_version: u32,
    /// Shared-memory ABI version negotiated during the handshake.
    pub negotiated_abi_version: u32,
    /// VM slot the plugin accepted, cross-checked against the launch argument.
    pub negotiated_slot: u32,
    /// Node count the handshake bound the slot against (`slot < node_count`).
    pub negotiated_node_count: u32,
    /// The plugin replied `SetupAck` with the ready status and can be scheduled.
    pub setup_ack_ready: bool,
    /// Validated length of the mapped shared-memory setup region in bytes.
    pub shmem_region_len: u64,
    /// Exact completed icount, which equals the requested horizon on success.
    pub completed_icount: u64,
    /// The guest advanced from cold boot to the exact host-published ceiling.
    ///
    /// This is the live boot-barrier proof: with no observation plugin present,
    /// the guest can only stop exactly at the ceiling if the plugin blocked on
    /// the boot barrier and then honored the scheduler ceiling as time authority.
    pub boot_barrier_ceiling_enforced: bool,
    /// Execution fingerprint the Rust plugin published at the boundary.
    pub execution_fingerprint: ExecutionFingerprint,
    /// The plugin sent no unsolicited run-phase control frame before `Quit`.
    pub run_control_silent: bool,
    /// The plugin published `Done` after consuming the control `Quit`.
    pub plugin_quit_consumed: bool,
    /// The QEMU child exited naturally with status zero after teardown.
    pub orderly_child_exit: bool,
    /// No independent observation plugin owned time control during the run.
    pub time_authority_is_rust_plugin: bool,
}

/// Failure returned by the production loaded-QEMU plugin install gate.
#[derive(Debug, Error)]
pub enum LivePluginInstallGateError {
    /// The requested horizon was zero.
    #[error("loaded-QEMU install horizon must be non-zero")]
    ZeroHorizon,
    /// Preparing the run directory failed.
    #[error("prepare install run directory `{path}` failed: {source}")]
    PrepareRunDirectory {
        /// Run directory that could not be prepared.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// The conservative deterministic launch profile was invalid.
    #[error("build deterministic launch profile failed: {source}")]
    LaunchProfile {
        /// Underlying launch-profile error.
        source: LaunchProfileError,
    },
    /// Writing the deterministic guest entropy seed failed.
    #[error("write guest entropy seed into `{path}` failed: {source}")]
    GuestEntropySeed {
        /// Run directory the seed could not be written into.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// The concrete QEMU launch command was invalid.
    #[error("build install QEMU launch command failed: {source}")]
    LaunchCommand {
        /// Underlying command-construction error.
        source: QemuLaunchCommandError,
    },
    /// The shared-memory layout was invalid.
    #[error("build install shared-memory layout failed: {source}")]
    RegionLayout {
        /// Underlying layout error.
        source: RegionLayoutError,
    },
    /// QEMU could not be spawned with the fixed inherited descriptors.
    #[error("spawn install loaded QEMU failed: {source}")]
    Spawn {
        /// Underlying spawn error.
        source: QemuSpawnError,
    },
    /// The live plugin setup handshake failed.
    #[error("complete install loaded-QEMU plugin setup failed: {source}")]
    HostSetup {
        /// Underlying setup error.
        source: QemuHostPluginSetupError,
    },
    /// The plugin replied `SetupAck` with a non-ready status.
    #[error("install plugin refused to become schedulable after SetupAck")]
    SetupAckNotReady,
    /// Mapping the completed shared-memory setup region failed.
    #[error("map install loaded-QEMU shared-memory region failed: {source}")]
    RegionMap {
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// Binding the mapped hot path failed.
    #[error("bind install loaded-QEMU shared-memory hot path failed: {source}")]
    MappedHotPath {
        /// Underlying hot-path error.
        source: QemuMappedQuantumShmemHotPathError,
    },
    /// A live shared-memory or control-channel operation failed.
    #[error("install loaded-QEMU operation `{operation}` failed: {source}")]
    Channel {
        /// Gate operation being attempted.
        operation: &'static str,
        /// Underlying channel error.
        source: QemuNodeChannelError,
    },
    /// QEMU did not publish the requested icount before the host bound expired.
    #[error(
        "install loaded QEMU did not reach icount {horizon_icount} within {timeout:?}; last icount was {last_icount}"
    )]
    CompletionTimeout {
        /// Required exact boundary.
        horizon_icount: u64,
        /// Last observed QEMU icount.
        last_icount: u64,
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// QEMU exited before publishing the requested exact boundary.
    #[error("install QEMU exited before reaching icount {horizon_icount}: {status}")]
    ChildExitBeforeBoundary {
        /// Required exact boundary.
        horizon_icount: u64,
        /// Exact platform exit-status diagnostic.
        status: String,
    },
    /// A run crossed rather than stopped at the requested exact boundary.
    #[error("install loaded QEMU completed at icount {actual}, expected {expected}")]
    InexactBoundary {
        /// Required exact boundary.
        expected: u64,
        /// Published boundary.
        actual: u64,
    },
    /// The plugin did not publish `Done` after consuming control `Quit`.
    #[error("install plugin did not publish teardown Done within {timeout:?}")]
    PluginQuitTimeout {
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// The QEMU child did not exit naturally after plugin teardown.
    #[error("install QEMU did not exit naturally within {timeout:?}")]
    ChildExitTimeout {
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// Polling the QEMU child failed.
    #[error("poll install QEMU natural exit failed: {source}")]
    ChildWait {
        /// Underlying child wait error.
        source: crate::QemuShutdownTargetError,
    },
    /// QEMU exited naturally but reported failure or signal termination.
    #[error("install QEMU teardown exit was not clean: {status}")]
    ChildExitUnclean {
        /// Exact platform exit-status diagnostic.
        status: String,
    },
}

/// Runs the Rust control plugin through its full install lifecycle in real QEMU.
///
/// The single run boots the standalone guest to an exact icount boundary owned
/// by the Rust plugin, proves the run-phase control channel stays silent, tears
/// the plugin down with control `Quit`, and reaps the child with a clean exit.
///
/// # Errors
///
/// Returns [`LivePluginInstallGateError`] when launch preparation, the live
/// plugin handshake, descriptor handover, shared-memory execution, exact
/// boundary enforcement, run-control silence, teardown, or child reaping fails.
pub fn run_live_plugin_install_gate(
    config: &LivePluginInstallGateConfig,
) -> Result<LivePluginInstallReport, LivePluginInstallGateError> {
    if config.horizon_icount == 0 {
        return Err(LivePluginInstallGateError::ZeroHorizon);
    }
    let run_directory = config.run_directory.as_path();
    fs::create_dir_all(run_directory).map_err(|source| {
        LivePluginInstallGateError::PrepareRunDirectory {
            path: run_directory.to_owned(),
            source,
        }
    })?;

    let mut candidate = LaunchProfileCandidate::default().with_memory_mib(GATE_MEMORY_MIB);
    if let Some(cmdline) = &config.kernel_cmdline {
        candidate = candidate.with_kernel_cmdline(cmdline.clone());
    }
    let profile = candidate
        .try_into_deterministic()
        .map_err(|source| LivePluginInstallGateError::LaunchProfile { source })?;
    profile
        .guest_entropy_seed_file()
        .write_to_dir(run_directory)
        .map_err(|source| LivePluginInstallGateError::GuestEntropySeed {
            path: run_directory.to_owned(),
            source,
        })?;

    // A single production control plugin, no observation plugin: the Rust plugin
    // is the sole sim_shmem dispatch authority for virtual-time advancement.
    let plugin = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT);
    let command = profile
        .qemu_launch_command(
            vm_launch_config(config),
            path_text(&config.qemu_executable),
            plugin,
        )
        .map_err(|source| LivePluginInstallGateError::LaunchCommand { source })?;

    let region_config = RegionConfig::new(1, GATE_QUEUE_CAPACITY, 0);
    let allocation = RegionAllocation::new(region_config)
        .map_err(|source| LivePluginInstallGateError::RegionLayout { source })?;
    let spawned = spawn_qemu_child_with_fds_in_directory(
        &command,
        run_directory,
        allocation.layout().region_size,
    )
    .map_err(|source| LivePluginInstallGateError::Spawn { source })?;
    let (mut child, resources) = spawned.into_parts();

    let mut setup =
        complete_qemu_host_plugin_setup(resources.into_setup_resources(), region_config, GATE_SLOT)
            .map_err(|source| LivePluginInstallGateError::HostSetup { source })?;
    let handshake = setup.negotiated_handshake();
    let negotiated_proto_version = handshake.proto_version;
    let negotiated_abi_version = handshake.abi_version;
    let negotiated_slot = handshake.slot_index;
    let negotiated_node_count = handshake.node_count;
    let setup_ack_ready = setup.setup_ack().can_schedule();
    if !setup_ack_ready {
        return Err(LivePluginInstallGateError::SetupAckNotReady);
    }
    let shmem_region_len = setup.region().region_len;

    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| LivePluginInstallGateError::RegionMap { source })?;
    let hot_path_config = QemuQuantumShmemConfig::new(node_id(GATE_NODE), GATE_SLOT)
        .with_router(node_id(GATE_ROUTER), SLOT_NET_ROUTER as u32);
    let mut hot_path =
        QemuMappedQuantumShmemHotPath::new(hot_path_config, region, GateSendAuthorizer)
            .map_err(|source| LivePluginInstallGateError::MappedHotPath { source })?;

    // Boot-barrier release: publishing the first scheduler ceiling is the only
    // signal that lets the plugin execute the first guest instruction.
    let pending = QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        ExecutionHorizon {
            icount: Icount {
                retired: config.horizon_icount,
            },
        },
    )
    .map_err(|source| channel_error("start boot-barrier quantum", source))?;
    wait_for_exact_boundary(&mut hot_path, &mut child, config)?;
    QemuShmemHotPathChannel::finish_quantum(&mut hot_path, pending)
        .map_err(|source| channel_error("finish boot-barrier quantum", source))?;

    let completed_icount = QemuShmemHotPathChannel::current_icount(&mut hot_path)
        .map_err(|source| channel_error("read completed icount", source))?
        .retired;
    if completed_icount != config.horizon_icount {
        return Err(LivePluginInstallGateError::InexactBoundary {
            expected: config.horizon_icount,
            actual: completed_icount,
        });
    }
    let execution_fingerprint = QemuShmemHotPathChannel::execution_fingerprint(&mut hot_path)
        .map_err(|source| channel_error("read execution fingerprint", source))?;

    setup
        .assert_run_control_silent()
        .map_err(|source| channel_error("prove run control silence", source))?;

    QemuPluginIpcControlChannel::send_quit(&mut setup)
        .map_err(|source| channel_error("send plugin Quit", source))?;
    wait_for_plugin_teardown(&hot_path, config)?;
    let exit_status = wait_for_natural_child_exit(&mut child, config)?;
    if !exit_status.success() {
        return Err(LivePluginInstallGateError::ChildExitUnclean {
            status: exit_status.to_string(),
        });
    }
    drop(setup);
    drop(child);

    Ok(LivePluginInstallReport {
        negotiated_proto_version,
        negotiated_abi_version,
        negotiated_slot,
        negotiated_node_count,
        setup_ack_ready,
        shmem_region_len,
        completed_icount,
        boot_barrier_ceiling_enforced: true,
        execution_fingerprint,
        run_control_silent: true,
        plugin_quit_consumed: true,
        orderly_child_exit: true,
        time_authority_is_rust_plugin: true,
    })
}

// crucible-lint: allow clippy-disallowed-method -- install-gate host timeout bounds QEMU liveness only.
#[allow(clippy::disallowed_methods)]
fn wait_for_exact_boundary(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    child: &mut crate::QemuNodeChild,
    config: &LivePluginInstallGateConfig,
) -> Result<(), LivePluginInstallGateError> {
    let started = Instant::now();
    loop {
        let current = QemuShmemHotPathChannel::current_icount(hot_path)
            .map_err(|source| channel_error("poll completed icount", source))?
            .retired;
        if current >= config.horizon_icount {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| LivePluginInstallGateError::ChildWait { source })?
        {
            return Err(LivePluginInstallGateError::ChildExitBeforeBoundary {
                horizon_icount: config.horizon_icount,
                status: status.to_string(),
            });
        }
        if started.elapsed() >= config.completion_timeout {
            return Err(LivePluginInstallGateError::CompletionTimeout {
                horizon_icount: config.horizon_icount,
                last_icount: current,
                timeout: config.completion_timeout,
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

// crucible-lint: allow clippy-disallowed-method -- install-gate host timeout bounds plugin teardown only.
#[allow(clippy::disallowed_methods)]
fn wait_for_plugin_teardown(
    hot_path: &QemuMappedQuantumShmemHotPath,
    config: &LivePluginInstallGateConfig,
) -> Result<(), LivePluginInstallGateError> {
    let started = Instant::now();
    loop {
        if hot_path
            .plugin_teardown_done()
            .map_err(|source| LivePluginInstallGateError::MappedHotPath { source })?
        {
            return Ok(());
        }
        if started.elapsed() >= config.completion_timeout {
            return Err(LivePluginInstallGateError::PluginQuitTimeout {
                timeout: config.completion_timeout,
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

// crucible-lint: allow clippy-disallowed-method -- install-gate host timeout bounds child reap only.
#[allow(clippy::disallowed_methods)]
fn wait_for_natural_child_exit(
    child: &mut crate::QemuNodeChild,
    config: &LivePluginInstallGateConfig,
) -> Result<std::process::ExitStatus, LivePluginInstallGateError> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| LivePluginInstallGateError::ChildWait { source })?
        {
            return Ok(status);
        }
        if started.elapsed() >= config.completion_timeout {
            return Err(LivePluginInstallGateError::ChildExitTimeout {
                timeout: config.completion_timeout,
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn vm_launch_config(config: &LivePluginInstallGateConfig) -> QemuVmLaunchConfig {
    let vm = QemuVmLaunchConfig::new(
        GATE_NODE,
        launch_artifact("kernel", &config.kernel),
        launch_artifact("root-image", &config.root_image),
    );
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

fn channel_error(
    operation: &'static str,
    source: QemuNodeChannelError,
) -> LivePluginInstallGateError {
    LivePluginInstallGateError::Channel { operation, source }
}

/// Send authorizer for the single-node install run.
///
/// The install gate has one VM and one router slot and never routes a real
/// cross-node frame, so authorization is unconditional.
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
