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
//! which supplies the live proof the earlier scaffolded lifecycle was missing.
//!
//! The emitted [`LivePluginInstallReport`] records each lifecycle milestone plus
//! `time_authority=rust-plugin` so the gate cannot silently regress to a mode in
//! which some other plugin owns time control.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use crucible::{
    DecisionRecorder, DecisionRngState, EventLog, EventLogCoverageObservation,
    ExecutionFingerprint, ExecutionHorizon, Icount, RngStreamId, RngStreamPosition,
    event_log_coverage_projection,
};
// crucible-lint: allow host-nondeterminism-state -- this seeded value is reconstructed before admission.
use crucible::Configuration;
// crucible-lint: allow host-nondeterminism-state -- live causal values remain untrusted until recorder validation.
use crucible::Decision;
// crucible-lint: allow host-nondeterminism-state -- the gate reconstructs fixed scenario material rather than host timing.
use crucible::ScenarioDef;
use crucible_shmem::{RegionAllocation, RegionConfig, SLOT_NET_ROUTER, mmap_setup_region};
mod error;
mod support;
// crucible-lint: allow host-nondeterminism-state -- this typed error exports failures, not host-derived state.
pub use error::LivePluginInstallGateError;
use support::*;

use crate::{
    LaunchProfileCandidate, QemuLaunchAppRandomConfig, QemuLaunchArtifact, QemuLaunchPluginConfig,
    QemuMappedQuantumShmemHotPath, QemuNodeChannelError, QemuPluginIpcControlChannel,
    QemuQuantumShmemConfig, QemuShmemHotPathChannel, QemuVmLaunchConfig,
    complete_qemu_host_plugin_setup, probe_x86_whitebox_setup,
    spawn_qemu_child_with_fds_in_directory, validate_aarch64_whitebox_setup,
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
    root_image_format: crate::QemuRootImageFormat,
    architecture: crate::LivePluginGuestArchitecture,
    whitebox: crate::QemuLaunchPluginSwitch,
    app_random: Option<QemuLaunchAppRandomConfig>,
    fingerprint: crate::QemuLaunchPluginSwitch,
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
        architecture: crate::LivePluginGuestArchitecture,
    ) -> Self {
        Self {
            qemu_executable: qemu_executable.into(),
            plugin: plugin.into(),
            kernel: kernel.into(),
            root_image: root_image.into(),
            run_directory: run_directory.into(),
            initrd: None,
            kernel_cmdline: None,
            root_image_format: crate::QemuRootImageFormat::Qcow2,
            architecture,
            whitebox: crate::QemuLaunchPluginSwitch::Off,
            app_random: None,
            fingerprint: crate::QemuLaunchPluginSwitch::Off,
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

    /// Returns this configuration with the declared immutable root-image format.
    #[must_use]
    pub fn with_root_image_format(mut self, format: crate::QemuRootImageFormat) -> Self {
        self.root_image_format = format;
        self
    }

    /// Returns this configuration with the optional white-box callback enabled.
    #[must_use]
    pub const fn with_whitebox(mut self, whitebox: crate::QemuLaunchPluginSwitch) -> Self {
        self.whitebox = whitebox;
        self
    }

    /// Returns this configuration with the seeded app-random path enabled.
    #[must_use]
    pub fn with_app_random(mut self, app_random: QemuLaunchAppRandomConfig) -> Self {
        self.app_random = Some(app_random);
        self
    }

    /// Returns this configuration with live boundary fingerprint sampling set.
    #[must_use]
    pub const fn with_fingerprint(mut self, fingerprint: crate::QemuLaunchPluginSwitch) -> Self {
        self.fingerprint = fingerprint;
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
    /// Setup-time x86 port-map region observed at the reserved doorbell port.
    pub whitebox_setup_region: Option<String>,
    /// Number of guest coverage markers admitted through the unified event log.
    pub whitebox_marker_count: usize,
    /// Exact icount of the first admitted guest coverage marker, when present.
    pub whitebox_marker_icount: Option<u64>,
    /// Semantic point of the first admitted guest coverage marker, when present.
    pub whitebox_marker_point: Option<String>,
    /// Number of live app-random decisions validated against the host recorder.
    pub app_random_decision_count: usize,
    /// First guest request id served by the live path.
    pub app_random_request_id: Option<u64>,
    /// First live value validated against the scenario-seeded host recorder.
    pub app_random_value: Option<u64>,
    /// First live app-random width in bits.
    pub app_random_width_bits: Option<u8>,
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
// crucible-lint: allow host-nondeterminism-state -- this public gate validates live observations before returning its report.
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
    if config.architecture == crate::LivePluginGuestArchitecture::Aarch64 {
        candidate = candidate
            .with_machine_type("virt-9.2")
            .with_cpu_model("cortex-a57");
    }
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
    let vm = vm_launch_config(config);
    let plugin_base = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT)
        .with_fingerprint(config.fingerprint);
    let (plugin, whitebox_setup_region) = if config.whitebox == crate::QemuLaunchPluginSwitch::On {
        let probe_command = profile
            .qemu_launch_command(
                vm.clone(),
                path_text(&config.qemu_executable),
                plugin_base.clone(),
            )
            .map_err(|source| LivePluginInstallGateError::LaunchCommand { source })?;
        let validation = match config.architecture {
            crate::LivePluginGuestArchitecture::X86_64 => {
                probe_x86_whitebox_setup(&probe_command, run_directory)
            }
            crate::LivePluginGuestArchitecture::Aarch64 => validate_aarch64_whitebox_setup(&[]),
        }
        .map_err(|source| LivePluginInstallGateError::WhiteboxSetup { source })?;
        let region = validation.observed_region().to_owned();
        let mut plugin = plugin_base
            .with_whitebox(config.whitebox)
            .with_whitebox_setup(validation);
        if let Some(app_random) = &config.app_random {
            plugin = plugin.with_app_random(app_random.clone());
        }
        (plugin, Some(region))
    } else {
        let mut plugin = plugin_base.with_whitebox(config.whitebox);
        if let Some(app_random) = &config.app_random {
            plugin = plugin.with_app_random(app_random.clone());
        }
        (plugin, None)
    };
    let command = profile
        .qemu_launch_command(vm, path_text(&config.qemu_executable), plugin)
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

    let mut setup = complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        region_config,
        GATE_SLOT,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    )
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
    let causal_decisions = QemuShmemHotPathChannel::drain_causal_decisions(&mut hot_path)
        .map_err(|source| channel_error("drain boundary causal decisions", source))?;
    let app_random_evidence = validate_app_random_decisions(config, causal_decisions)?;
    let observations = QemuShmemHotPathChannel::drain_observable_events(&mut hot_path)
        .map_err(|source| channel_error("drain boundary observations", source))?;
    let mut event_log = EventLog::new();
    let append = event_log
        .append_observable_events(observations)
        .map_err(|source| LivePluginInstallGateError::EventLog { source })?;
    let coverage_projection = event_log_coverage_projection(&append.entries);
    let mut whitebox_markers =
        coverage_projection
            .entries()
            .iter()
            .filter_map(|entry| match &entry.observation {
                EventLogCoverageObservation::Named { marker, .. } => {
                    Some((entry.at.icount.retired, marker.name.clone()))
                }
                EventLogCoverageObservation::BasicBlock { .. } => None,
            });
    let first_whitebox_marker = whitebox_markers.next();
    let whitebox_marker_count =
        usize::from(first_whitebox_marker.is_some()) + whitebox_markers.count();
    let (whitebox_marker_icount, whitebox_marker_point) =
        first_whitebox_marker.map_or((None, None), |(icount, point)| (Some(icount), Some(point)));

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
        whitebox_setup_region,
        whitebox_marker_count,
        whitebox_marker_icount,
        whitebox_marker_point,
        app_random_decision_count: app_random_evidence.count,
        app_random_request_id: app_random_evidence.request_id,
        app_random_value: app_random_evidence.value,
        app_random_width_bits: app_random_evidence.width_bits,
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LiveAppRandomEvidence {
    count: usize,
    request_id: Option<u64>,
    value: Option<u64>,
    width_bits: Option<u8>,
}

fn validate_app_random_decisions(
    config: &LivePluginInstallGateConfig,
    // crucible-lint: allow host-nondeterminism-state -- this batch is verified against the authoritative seeded recorder.
    decisions: Vec<Decision>,
) -> Result<LiveAppRandomEvidence, LivePluginInstallGateError> {
    if decisions.is_empty() {
        return Ok(LiveAppRandomEvidence::default());
    }
    let app_random = config
        .app_random
        .as_ref()
        .ok_or(LivePluginInstallGateError::AppRandomNotConfigured)?;
    // crucible-lint: allow host-nondeterminism-state -- fixed gate material reconstructs the authoritative scenario.
    let scenario = ScenarioDef::from_canonical_material_with_seed_and_app_random_draw_cap(
        GATE_DOMAIN,
        "scenario=live-app-random-doorbell",
        app_random.authoritative_seed(),
        app_random.draw_cap,
    );
    let continuation = DecisionRngState {
        positions: app_random
            .stream_positions
            .iter()
            .map(|(name, draws)| {
                (
                    RngStreamId::from_name(name.clone()),
                    RngStreamPosition::new(*draws),
                )
            })
            .collect(),
    };
    let mut recorder = DecisionRecorder::from_seed_and_positions(
        // crucible-lint: allow host-nondeterminism-state -- this configuration is seeded canonical material, not a host observation.
        Configuration::genesis(scenario),
        app_random.authoritative_seed(),
        &continuation,
    );
    let mut evidence = LiveAppRandomEvidence::default();
    let mut branch_applied = false;
    for decision in decisions {
        let current_draw = app_random.draw_offset.saturating_add(evidence.count as u64);
        if !branch_applied
            && app_random.branch_after_draws == Some(current_draw)
            && let Some(branch_seed) = app_random.branch_seed()
        {
            recorder = DecisionRecorder::from_seed_and_positions(
                recorder.into_configuration(),
                branch_seed,
                &DecisionRngState::empty(),
            );
            branch_applied = true;
        }
        // crucible-lint: allow host-nondeterminism-state -- the plugin conjecture is compared and rejected on any mismatch.
        let Decision::AppRandom(expected) = decision else {
            return Err(LivePluginInstallGateError::UnsupportedCausalDecision {
                decision: format!("{decision:?}"),
            });
        };
        let host_value = recorder
            .serve_app_random_request(
                expected.node.clone(),
                expected.stream.clone(),
                expected.request_id,
                expected.width,
            )
            .map_err(|error| LivePluginInstallGateError::AppRandomRecorder {
                message: error.to_string(),
            })?;
        if host_value != expected.value {
            return Err(LivePluginInstallGateError::AppRandomValueMismatch {
                actual: expected.value,
                expected: host_value,
            });
        }
        if evidence.count == 0 {
            evidence.request_id = Some(expected.request_id);
            evidence.value = Some(expected.value);
            evidence.width_bits = Some(expected.width);
        }
        evidence.count = evidence.count.saturating_add(1);
    }
    Ok(evidence)
}
