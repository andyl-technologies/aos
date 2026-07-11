//! Loaded-QEMU proof for the optional basic-block coverage callback.
//!
//! This module owns the production integration gate that was intentionally not
//! represented by the callback model alone. It launches the patched QEMU binary
//! twice with the production plugin, completes the real descriptor and shared-
//! memory setup handshake, and advances the same uninstrumented guest to an
//! identical instruction-count boundary. The first run leaves coverage off; the
//! second enables the registration-time callback and must publish at least one
//! observation without changing the host execution fingerprint. An independent
//! observation plugin also compares the instruction stream, all vCPU registers,
//! round-robin cursor, RAM, and current serialized non-RAM VMState across the
//! two runs through a cryptographic acceptance projection and chained execution
//! trajectory. Noncryptographic rolling hashes remain diagnostics only. Both runs
//! admit their live observations and exact quantum boundary through one
//! [`EventLog`], then compare its canonical causal projection byte-for-byte.

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crucible::{
    BasicBlockCoverageConfig, ContentHash, EventLog, EventLogCoverageObservation,
    ExecutionFingerprint, ExecutionHorizon, Icount, NodeId, SchedulerError,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, SchedulerNodeId,
    SchedulerSendAuthorization, SchedulerSendAuthorizer, VirtualTime,
    compare_event_log_determinism, event_log_coverage_projection,
};
use crucible_shmem::{
    RegionAllocation, RegionConfig, RegionLayoutError, SLOT_NET_ROUTER, SetupRegionMapError,
    mmap_setup_region,
};
use serde_json::Value;
use thiserror::Error;

use crate::{
    LaunchProfileCandidate, LaunchProfileError, QemuHostPluginSetupError, QemuLaunchArtifact,
    QemuLaunchCommandError, QemuLaunchPluginConfig, QemuLaunchPluginSwitch,
    QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError, QemuNodeChannelError,
    QemuPluginIpcControlChannel, QemuQuantumShmemConfig, QemuShmemHotPathChannel, QemuSpawnError,
    QemuVmLaunchConfig, complete_qemu_host_plugin_setup, spawn_qemu_child_with_fds_in_directory,
};

mod trace;

use trace::{read_trace_sample, trace_plugin_argument};

pub(super) const GATE_DOMAIN: &str = "crucible.loaded-qemu-basic-block-coverage.v1";
const GATE_NODE: &str = "coverage-gate-vm";
const GATE_ROUTER: &str = "coverage-gate-router";
const GATE_SLOT: u32 = 0;
const GATE_QUEUE_CAPACITY: u32 = 4;
const DEFAULT_HORIZON_ICOUNT: u64 = 16_000_000;
const GUEST_TEXT_START: u64 = 0x0010_0000;
const GUEST_TEXT_END_EXCLUSIVE: u64 = 0x0010_1000;
const GUEST_POST_IO_PC: u64 = 0x0010_0800;
const DEFAULT_COMPLETION_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(1);

fn wait_for_poll_interval() {
    thread::sleep(POLL_INTERVAL);
}

/// Inputs for a production loaded-QEMU coverage equivalence run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedQemuCoverageGateConfig {
    qemu_executable: PathBuf,
    plugin: PathBuf,
    trace_plugin: PathBuf,
    kernel: PathBuf,
    root_image: PathBuf,
    coverage_off_run_directory: PathBuf,
    coverage_on_run_directory: PathBuf,
    horizon_icount: u64,
    completion_timeout: Duration,
}

impl LoadedQemuCoverageGateConfig {
    /// Builds a loaded-QEMU gate configuration with bounded defaults.
    #[must_use]
    pub fn new(
        qemu_executable: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
        trace_plugin: impl Into<PathBuf>,
        kernel: impl Into<PathBuf>,
        root_image: impl Into<PathBuf>,
        coverage_off_run_directory: impl Into<PathBuf>,
        coverage_on_run_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            qemu_executable: qemu_executable.into(),
            plugin: plugin.into(),
            trace_plugin: trace_plugin.into(),
            kernel: kernel.into(),
            root_image: root_image.into(),
            coverage_off_run_directory: coverage_off_run_directory.into(),
            coverage_on_run_directory: coverage_on_run_directory.into(),
            horizon_icount: DEFAULT_HORIZON_ICOUNT,
            completion_timeout: DEFAULT_COMPLETION_TIMEOUT,
        }
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

/// Successful evidence from the production loaded-QEMU coverage gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedQemuCoverageGateReport {
    /// Execution fingerprint from the coverage-disabled run.
    pub coverage_off_fingerprint: ExecutionFingerprint,
    /// Execution fingerprint from the coverage-enabled run.
    pub coverage_on_fingerprint: ExecutionFingerprint,
    /// Independent instruction/register/RAM/device trace fingerprint.
    pub independent_trace_fingerprint: ContentHash,
    /// Exact completed icount shared by both runs.
    pub completed_icount: u64,
    /// Number of novel basic-block observations drained from the live callback.
    pub coverage_observation_count: usize,
    /// Number of live observations whose block starts in the standalone guest text.
    pub guest_coverage_observation_count: usize,
    /// Canonical causal event-log fingerprint shared by coverage-off and coverage-on.
    pub canonical_event_log_fingerprint: ContentHash,
    /// Production plugin argument used for the coverage-disabled run.
    pub coverage_off_plugin_argument: String,
    /// Production plugin argument used for the coverage-enabled run.
    pub coverage_on_plugin_argument: String,
    /// Both runs proved that the RUN control channel was silent before teardown.
    pub run_control_silent: bool,
    /// The coverage-on run observed plugin `Done` after control `Quit`.
    pub plugin_quit_consumed: bool,
    /// The coverage-off run observed plugin `Done` after mapped shared shutdown.
    pub shared_shutdown_consumed: bool,
    /// Both QEMU children exited naturally with status zero after plugin teardown.
    pub orderly_child_exit: bool,
}

/// Failure returned by the production loaded-QEMU coverage gate.
#[derive(Debug, Error)]
pub enum LoadedQemuCoverageGateError {
    /// The requested horizon was zero.
    #[error("loaded-QEMU coverage horizon must be non-zero")]
    ZeroHorizon,
    /// The two runs would share a mutable working directory.
    #[error("coverage-off and coverage-on runs must use different directories")]
    SharedRunDirectory,
    /// Preparing one run directory failed.
    #[error("prepare {mode} run directory `{path}` failed: {source}")]
    PrepareRunDirectory {
        /// Coverage mode being prepared.
        mode: &'static str,
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
    /// The concrete QEMU launch command was invalid.
    #[error("build {mode} QEMU launch command failed: {source}")]
    LaunchCommand {
        /// Coverage mode being launched.
        mode: &'static str,
        /// Underlying command-construction error.
        source: QemuLaunchCommandError,
    },
    /// The shared-memory layout was invalid.
    #[error("build loaded-QEMU shared-memory layout failed: {source}")]
    RegionLayout {
        /// Underlying layout error.
        source: RegionLayoutError,
    },
    /// QEMU could not be spawned with the fixed inherited descriptors.
    #[error("spawn {mode} loaded QEMU failed: {source}")]
    Spawn {
        /// Coverage mode being launched.
        mode: &'static str,
        /// Underlying spawn error.
        source: QemuSpawnError,
    },
    /// The live plugin setup handshake failed.
    #[error("complete {mode} loaded-QEMU plugin setup failed: {source}")]
    HostSetup {
        /// Coverage mode being launched.
        mode: &'static str,
        /// Underlying setup error.
        source: QemuHostPluginSetupError,
    },
    /// Mapping the completed shared-memory setup region failed.
    #[error("map {mode} loaded-QEMU shared-memory region failed: {source}")]
    RegionMap {
        /// Coverage mode being launched.
        mode: &'static str,
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// Binding the mapped hot path failed.
    #[error("bind {mode} loaded-QEMU shared-memory hot path failed: {source}")]
    MappedHotPath {
        /// Coverage mode being launched.
        mode: &'static str,
        /// Underlying hot-path error.
        source: QemuMappedQuantumShmemHotPathError,
    },
    /// A live shared-memory or control-channel operation failed.
    #[error("{mode} loaded-QEMU operation `{operation}` failed: {source}")]
    Channel {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Gate operation being attempted.
        operation: &'static str,
        /// Underlying channel error.
        source: QemuNodeChannelError,
    },
    /// QEMU did not publish the requested icount before the host bound expired.
    #[error(
        "{mode} loaded QEMU did not reach icount {horizon_icount} within {timeout:?}; last icount was {last_icount}"
    )]
    CompletionTimeout {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Required exact boundary.
        horizon_icount: u64,
        /// Last observed QEMU icount.
        last_icount: u64,
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// QEMU exited before publishing the requested exact boundary.
    #[error("{mode} QEMU exited before reaching icount {horizon_icount}: {status}")]
    ChildExitBeforeBoundary {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Required exact boundary.
        horizon_icount: u64,
        /// Exact platform exit-status diagnostic.
        status: String,
    },
    /// The plugin did not publish `Done` after consuming control `Quit`.
    #[error("{mode} plugin did not publish teardown Done within {timeout:?}")]
    PluginQuitTimeout {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// The plugin did not publish `Done` after the mapped shared shutdown request.
    #[error("{mode} plugin did not consume shared shutdown within {timeout:?}")]
    SharedShutdownTimeout {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// The QEMU child did not exit naturally after plugin teardown.
    #[error("{mode} QEMU did not exit naturally within {timeout:?}")]
    ChildExitTimeout {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Host-side diagnostic timeout.
        timeout: Duration,
    },
    /// Polling the QEMU child failed.
    #[error("poll {mode} QEMU natural exit failed: {source}")]
    ChildWait {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Underlying child wait error.
        source: crate::QemuShutdownTargetError,
    },
    /// QEMU exited naturally but reported failure or signal termination.
    #[error("{mode} QEMU teardown exit was not clean: {status}")]
    ChildExitUnclean {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Exact platform exit-status diagnostic.
        status: String,
    },
    /// Appending the live run boundary or callback observations to the unified log failed.
    #[error("append {mode} loaded-QEMU {operation} to the unified event log failed: {source}")]
    EventLogAppend {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Event-log operation that failed.
        operation: &'static str,
        /// Underlying canonical event-log error.
        source: SchedulerError,
    },
    /// A run crossed rather than stopped at the requested exact boundary.
    #[error("{mode} loaded QEMU completed at icount {actual}, expected {expected}")]
    InexactBoundary {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Required exact boundary.
        expected: u64,
        /// Published boundary.
        actual: u64,
    },
    /// Coverage-off unexpectedly installed or published coverage state.
    #[error("coverage-off loaded QEMU published {observations} coverage observations")]
    CoverageOffPublished {
        /// Unexpected observation count.
        observations: usize,
    },
    /// Coverage-on failed to produce a live basic-block observation.
    #[error("coverage-on loaded QEMU produced no basic-block observations")]
    CoverageOnEmpty,
    /// Coverage-on produced observations, but none came from the standalone guest.
    #[error(
        "coverage-on loaded QEMU produced no block in standalone guest text {GUEST_TEXT_START:#x}..{GUEST_TEXT_END_EXCLUSIVE:#x}"
    )]
    CoverageOnGuestUnattributed,
    /// Enabling coverage changed the execution fingerprint.
    #[error("loaded-QEMU coverage opt-in changed the execution fingerprint")]
    FingerprintMismatch,
    /// Coverage changed the canonical causal event-log bytes.
    #[error("loaded-QEMU coverage opt-in changed the canonical causal event log")]
    CanonicalEventLogMismatch,
    /// Reading the independent fingerprint trace failed.
    #[error("read {mode} independent fingerprint trace `{path}` failed: {source}")]
    TraceRead {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Trace file being read.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// One independent fingerprint trace record was invalid JSON.
    #[error("decode {mode} independent fingerprint trace record failed: {source}")]
    TraceDecode {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Underlying JSON error.
        source: serde_json::Error,
    },
    /// The independent plugin did not publish the exact-boundary sample.
    #[error("{mode} independent fingerprint trace omitted icount {horizon_icount}")]
    TraceSampleMissing {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Required sample boundary.
        horizon_icount: u64,
    },
    /// The independent sample omitted required state or reported a failed read.
    #[error("{mode} independent fingerprint sample is incomplete: {reason}")]
    TraceSampleIncomplete {
        /// Coverage mode being exercised.
        mode: &'static str,
        /// Failed completeness invariant.
        reason: &'static str,
    },
    /// Coverage changed the independent instruction/register/RAM/device trace.
    #[error("loaded-QEMU coverage opt-in changed the independent state fingerprint")]
    IndependentFingerprintMismatch,
}

/// Runs the production plugin in patched QEMU with coverage off and on.
///
/// Both runs execute the same uninstrumented kernel to the same exact icount.
/// The coverage-enabled run must drain live basic-block observations from ABI-v2
/// shared memory, while both host execution fingerprints must remain equal.
///
/// # Errors
///
/// Returns [`LoadedQemuCoverageGateError`] when launch preparation, the live
/// plugin handshake, shared-memory execution, coverage observation, exact
/// boundary enforcement, or fingerprint equivalence fails.
pub fn run_loaded_qemu_coverage_gate(
    config: &LoadedQemuCoverageGateConfig,
) -> Result<LoadedQemuCoverageGateReport, LoadedQemuCoverageGateError> {
    validate_gate_config(config)?;
    let off = run_loaded_qemu_once(config, QemuLaunchPluginSwitch::Off)?;
    let on = run_loaded_qemu_once(config, QemuLaunchPluginSwitch::On)?;

    let off_coverage = event_log_coverage_projection(&off.event_log_entries);
    let on_coverage = event_log_coverage_projection(&on.event_log_entries);
    if !off_coverage.is_empty() {
        return Err(LoadedQemuCoverageGateError::CoverageOffPublished {
            observations: off_coverage.len(),
        });
    }
    if on_coverage.is_empty() {
        return Err(LoadedQemuCoverageGateError::CoverageOnEmpty);
    }
    let guest_coverage_observation_count =
        guest_coverage_observation_count(&on_coverage, config.horizon_icount);
    if guest_coverage_observation_count == 0 {
        return Err(LoadedQemuCoverageGateError::CoverageOnGuestUnattributed);
    }
    if off.fingerprint != on.fingerprint {
        return Err(LoadedQemuCoverageGateError::FingerprintMismatch);
    }
    let event_log_comparison =
        compare_event_log_determinism(&off.event_log_entries, &on.event_log_entries);
    if !event_log_comparison.passes() {
        return Err(LoadedQemuCoverageGateError::CanonicalEventLogMismatch);
    }
    if off.trace_sample != on.trace_sample {
        return Err(LoadedQemuCoverageGateError::IndependentFingerprintMismatch);
    }
    let independent_trace_fingerprint =
        ContentHash::from_canonical_material(GATE_DOMAIN, &off.trace_sample.to_string());

    Ok(LoadedQemuCoverageGateReport {
        coverage_off_fingerprint: off.fingerprint,
        coverage_on_fingerprint: on.fingerprint,
        independent_trace_fingerprint,
        completed_icount: off.completed_icount,
        coverage_observation_count: on_coverage.len(),
        guest_coverage_observation_count,
        canonical_event_log_fingerprint: event_log_comparison.expected().content_hash(),
        coverage_off_plugin_argument: off.plugin_argument,
        coverage_on_plugin_argument: on.plugin_argument,
        run_control_silent: off.run_control_silent && on.run_control_silent,
        plugin_quit_consumed: on.plugin_quit_consumed,
        shared_shutdown_consumed: off.shared_shutdown_consumed,
        orderly_child_exit: off.orderly_child_exit && on.orderly_child_exit,
    })
}

fn validate_gate_config(
    config: &LoadedQemuCoverageGateConfig,
) -> Result<(), LoadedQemuCoverageGateError> {
    if config.horizon_icount == 0 {
        return Err(LoadedQemuCoverageGateError::ZeroHorizon);
    }
    if config.coverage_off_run_directory == config.coverage_on_run_directory {
        return Err(LoadedQemuCoverageGateError::SharedRunDirectory);
    }
    Ok(())
}

struct LoadedQemuRun {
    fingerprint: ExecutionFingerprint,
    completed_icount: u64,
    event_log_entries: Vec<SchedulerEventLogEntry>,
    plugin_argument: String,
    trace_sample: Value,
    run_control_silent: bool,
    plugin_quit_consumed: bool,
    shared_shutdown_consumed: bool,
    orderly_child_exit: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoadedTeardownTrigger {
    SharedShutdown,
    ControlQuit,
}

fn run_loaded_qemu_once(
    config: &LoadedQemuCoverageGateConfig,
    coverage: QemuLaunchPluginSwitch,
) -> Result<LoadedQemuRun, LoadedQemuCoverageGateError> {
    let mode = coverage_mode_label(coverage);
    let run_directory = run_directory(config, coverage);
    prepare_run_directory(run_directory, mode)?;

    let profile = LaunchProfileCandidate::default()
        .with_memory_mib(64)
        .try_into_deterministic()
        .map_err(|source| LoadedQemuCoverageGateError::LaunchProfile { source })?;
    profile
        .guest_entropy_seed_file()
        .write_to_dir(run_directory)
        .map_err(|source| LoadedQemuCoverageGateError::PrepareRunDirectory {
            mode,
            path: run_directory.to_owned(),
            source,
        })?;

    let plugin =
        QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT).with_coverage(coverage);
    let plugin_argument = plugin.qemu_plugin_argument();
    let command = profile
        .qemu_launch_command(
            vm_launch_config(config),
            path_text(&config.qemu_executable),
            plugin,
        )
        .map_err(|source| LoadedQemuCoverageGateError::LaunchCommand { mode, source })?;
    let trace_path = run_directory.join("independent-fingerprint.jsonl");
    let trace_argument = trace_plugin_argument(config, &trace_path);
    let command = command
        .with_observation_plugin(trace_argument)
        .map_err(|source| LoadedQemuCoverageGateError::LaunchCommand { mode, source })?;

    let region_config = RegionConfig::new(1, GATE_QUEUE_CAPACITY, 0);
    let allocation = RegionAllocation::new(region_config)
        .map_err(|source| LoadedQemuCoverageGateError::RegionLayout { source })?;
    let spawned = spawn_qemu_child_with_fds_in_directory(
        &command,
        run_directory,
        allocation.layout().region_size,
    )
    .map_err(|source| LoadedQemuCoverageGateError::Spawn { mode, source })?;
    let (mut child, resources) = spawned.into_parts();
    let mut setup =
        complete_qemu_host_plugin_setup(resources.into_setup_resources(), region_config, GATE_SLOT)
            .map_err(|source| LoadedQemuCoverageGateError::HostSetup { mode, source })?;
    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| LoadedQemuCoverageGateError::RegionMap { mode, source })?;
    let coverage_config = match coverage {
        QemuLaunchPluginSwitch::Off => BasicBlockCoverageConfig::off(),
        QemuLaunchPluginSwitch::On => BasicBlockCoverageConfig::on(),
    };
    let hot_path_config = QemuQuantumShmemConfig::new(node_id(GATE_NODE), GATE_SLOT)
        .with_router(node_id(GATE_ROUTER), SLOT_NET_ROUTER as u32)
        .with_coverage(coverage_config);
    let mut hot_path =
        QemuMappedQuantumShmemHotPath::new(hot_path_config, region, GateSendAuthorizer)
            .map_err(|source| LoadedQemuCoverageGateError::MappedHotPath { mode, source })?;

    let pending = QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        ExecutionHorizon {
            icount: Icount {
                retired: config.horizon_icount,
            },
        },
    )
    .map_err(|source| channel_error(mode, "start exact quantum", source))?;
    wait_for_exact_boundary(&mut hot_path, &mut child, config, mode)?;
    QemuShmemHotPathChannel::finish_quantum(&mut hot_path, pending)
        .map_err(|source| channel_error(mode, "finish exact quantum", source))?;
    let completed_icount = QemuShmemHotPathChannel::current_icount(&mut hot_path)
        .map_err(|source| channel_error(mode, "read completed icount", source))?
        .retired;
    if completed_icount != config.horizon_icount {
        return Err(LoadedQemuCoverageGateError::InexactBoundary {
            mode,
            expected: config.horizon_icount,
            actual: completed_icount,
        });
    }
    let fingerprint = QemuShmemHotPathChannel::execution_fingerprint(&mut hot_path)
        .map_err(|source| channel_error(mode, "read execution fingerprint", source))?;
    let observations = QemuShmemHotPathChannel::drain_observable_events(&mut hot_path)
        .map_err(|source| channel_error(mode, "drain live coverage observations", source))?;
    let event_log_entries = record_loaded_run_event_log(mode, config.horizon_icount, observations)?;
    let trace_sample = read_trace_sample(&trace_path, config, mode)?;

    setup
        .assert_run_control_silent()
        .map_err(|source| channel_error(mode, "prove run control silence", source))?;
    let teardown_trigger = teardown_trigger_for_coverage(coverage);
    match teardown_trigger {
        LoadedTeardownTrigger::SharedShutdown => {
            hot_path
                .request_plugin_shutdown()
                .map_err(|source| LoadedQemuCoverageGateError::MappedHotPath { mode, source })?;
            setup.signal_plugin_wake().map_err(|source| {
                channel_error(mode, "wake busy shared-shutdown boundary", source)
            })?;
        }
        LoadedTeardownTrigger::ControlQuit => {
            QemuPluginIpcControlChannel::send_quit(&mut setup)
                .map_err(|source| channel_error(mode, "send plugin Quit", source))?;
        }
    }
    wait_for_plugin_teardown(&hot_path, config, mode, teardown_trigger)?;
    let exit_status = wait_for_natural_child_exit(&mut child, config, mode)?;
    if !exit_status.success() {
        return Err(LoadedQemuCoverageGateError::ChildExitUnclean {
            mode,
            status: exit_status.to_string(),
        });
    }
    drop(setup);
    drop(child);

    Ok(LoadedQemuRun {
        fingerprint,
        completed_icount,
        event_log_entries,
        plugin_argument,
        trace_sample,
        run_control_silent: true,
        plugin_quit_consumed: teardown_trigger == LoadedTeardownTrigger::ControlQuit,
        shared_shutdown_consumed: teardown_trigger == LoadedTeardownTrigger::SharedShutdown,
        orderly_child_exit: true,
    })
}

// crucible-lint: allow clippy-disallowed-method -- loaded-gate host timeout bounds plugin teardown only.
#[allow(clippy::disallowed_methods)]
fn wait_for_plugin_teardown(
    hot_path: &QemuMappedQuantumShmemHotPath,
    config: &LoadedQemuCoverageGateConfig,
    mode: &'static str,
    trigger: LoadedTeardownTrigger,
) -> Result<(), LoadedQemuCoverageGateError> {
    let started = Instant::now();
    loop {
        if hot_path
            .plugin_teardown_done()
            .map_err(|source| LoadedQemuCoverageGateError::MappedHotPath { mode, source })?
        {
            return Ok(());
        }
        if started.elapsed() >= config.completion_timeout {
            return Err(match trigger {
                LoadedTeardownTrigger::SharedShutdown => {
                    LoadedQemuCoverageGateError::SharedShutdownTimeout {
                        mode,
                        timeout: config.completion_timeout,
                    }
                }
                LoadedTeardownTrigger::ControlQuit => {
                    LoadedQemuCoverageGateError::PluginQuitTimeout {
                        mode,
                        timeout: config.completion_timeout,
                    }
                }
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

const fn teardown_trigger_for_coverage(coverage: QemuLaunchPluginSwitch) -> LoadedTeardownTrigger {
    match coverage {
        QemuLaunchPluginSwitch::Off => LoadedTeardownTrigger::SharedShutdown,
        QemuLaunchPluginSwitch::On => LoadedTeardownTrigger::ControlQuit,
    }
}

// crucible-lint: allow clippy-disallowed-method -- loaded-gate host timeout bounds child reap only.
#[allow(clippy::disallowed_methods)]
fn wait_for_natural_child_exit(
    child: &mut crate::QemuNodeChild,
    config: &LoadedQemuCoverageGateConfig,
    mode: &'static str,
) -> Result<std::process::ExitStatus, LoadedQemuCoverageGateError> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| LoadedQemuCoverageGateError::ChildWait { mode, source })?
        {
            return Ok(status);
        }
        if started.elapsed() >= config.completion_timeout {
            return Err(LoadedQemuCoverageGateError::ChildExitTimeout {
                mode,
                timeout: config.completion_timeout,
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn record_loaded_run_event_log(
    mode: &'static str,
    horizon_icount: u64,
    observations: Vec<crucible::ObservableEvent>,
) -> Result<Vec<SchedulerEventLogEntry>, LoadedQemuCoverageGateError> {
    let mut event_log = EventLog::new();
    let mut entries = event_log
        .append_observable_events(observations)
        .map_err(|source| LoadedQemuCoverageGateError::EventLogAppend {
            mode,
            operation: "callback observation batch",
            source,
        })?
        .entries;
    let boundary = event_log
        .append_evaluation_boundary(
            VirtualTime {
                ticks: horizon_icount,
            },
            SchedulerEvaluationBoundaryKind::Quantum,
        )
        .map_err(|source| LoadedQemuCoverageGateError::EventLogAppend {
            mode,
            operation: "causal quantum boundary",
            source,
        })?
        .entries;
    entries.extend(boundary);
    Ok(entries)
}

fn guest_coverage_observation_count(
    coverage: &crucible::EventLogCoverageProjection,
    horizon_icount: u64,
) -> usize {
    coverage
        .entries()
        .iter()
        .filter(|entry| {
            let EventLogCoverageObservation::BasicBlock {
                node,
                guest_pc,
                block_len,
            } = &entry.observation
            else {
                return false;
            };
            let block_end = guest_pc.saturating_add(u64::from(*block_len));
            node.name == GATE_NODE
                && entry.at.icount.retired <= horizon_icount
                && *guest_pc >= GUEST_TEXT_START
                && block_end <= GUEST_TEXT_END_EXCLUSIVE
        })
        .count()
}

// crucible-lint: allow clippy-disallowed-method -- loaded-gate host timeout bounds QEMU liveness only.
#[allow(clippy::disallowed_methods)]
fn wait_for_exact_boundary(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    child: &mut crate::QemuNodeChild,
    config: &LoadedQemuCoverageGateConfig,
    mode: &'static str,
) -> Result<(), LoadedQemuCoverageGateError> {
    let started = Instant::now();
    loop {
        let current = QemuShmemHotPathChannel::current_icount(hot_path)
            .map_err(|source| channel_error(mode, "poll completed icount", source))?
            .retired;
        if current >= config.horizon_icount {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| LoadedQemuCoverageGateError::ChildWait { mode, source })?
        {
            return Err(LoadedQemuCoverageGateError::ChildExitBeforeBoundary {
                mode,
                horizon_icount: config.horizon_icount,
                status: status.to_string(),
            });
        }
        if started.elapsed() >= config.completion_timeout {
            return Err(LoadedQemuCoverageGateError::CompletionTimeout {
                mode,
                horizon_icount: config.horizon_icount,
                last_icount: current,
                timeout: config.completion_timeout,
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn prepare_run_directory(
    run_directory: &Path,
    mode: &'static str,
) -> Result<(), LoadedQemuCoverageGateError> {
    fs::create_dir_all(run_directory).map_err(|source| {
        LoadedQemuCoverageGateError::PrepareRunDirectory {
            mode,
            path: run_directory.to_owned(),
            source,
        }
    })
}

fn vm_launch_config(config: &LoadedQemuCoverageGateConfig) -> QemuVmLaunchConfig {
    QemuVmLaunchConfig::new(
        GATE_NODE,
        launch_artifact("kernel", &config.kernel),
        launch_artifact("root-image", &config.root_image),
    )
}

fn launch_artifact(kind: &str, path: &Path) -> QemuLaunchArtifact {
    let path = path_text(path);
    QemuLaunchArtifact::new(
        ContentHash::from_canonical_material(GATE_DOMAIN, &format!("{kind}={path}")),
        path,
    )
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn run_directory(config: &LoadedQemuCoverageGateConfig, coverage: QemuLaunchPluginSwitch) -> &Path {
    match coverage {
        QemuLaunchPluginSwitch::Off => &config.coverage_off_run_directory,
        QemuLaunchPluginSwitch::On => &config.coverage_on_run_directory,
    }
}

const fn coverage_mode_label(coverage: QemuLaunchPluginSwitch) -> &'static str {
    match coverage {
        QemuLaunchPluginSwitch::Off => "coverage-off",
        QemuLaunchPluginSwitch::On => "coverage-on",
    }
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn channel_error(
    mode: &'static str,
    operation: &'static str,
    source: QemuNodeChannelError,
) -> LoadedQemuCoverageGateError {
    LoadedQemuCoverageGateError::Channel {
        mode,
        operation,
        source,
    }
}

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

#[cfg(test)]
mod tests;
