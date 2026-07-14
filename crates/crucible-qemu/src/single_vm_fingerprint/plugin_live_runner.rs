//! Live single-VM fingerprint runner driven by the Rust control plugin.
//!
//! This is the production [`SingleVmFingerprintRunner`] backend: it boots the
//! patched QEMU binary once with the real Rust control plugin loaded and
//! `fingerprint=on`, drives the shared-memory quantum hot path to a fixed
//! ascending cadence of aggregate-icount targets, and reads the black-box
//! [`FingerprintSample`] the plugin publishes into its per-node slot at each
//! boundary. The Rust plugin — not the imported C trace plugin — is the sole
//! fingerprint authority here, so the definition digest binds
//! `rust_plugin_build_digest` (see [`definition`]).
//!
//! Bring-up mirrors [`crate::run_live_plugin_quantum_gate`]'s `run_one_scenario`
//! exactly (launch profile, fd-passing spawn, host plugin setup handshake,
//! mapped quantum hot path), adding only `.with_fingerprint(On)` and the
//! per-target [`QemuMappedQuantumShmemHotPath::fingerprint_sample`] read.
//!
//! Every cadence target is below the diskless firmware guest's idle onset, so
//! each is reached by a busy quantum that stops exactly at the host-published
//! ceiling. That gives an instruction-exact guest state at every boundary and a
//! deterministic stream that reproduces byte-for-byte across the run-twice gate,
//! including the second run under deliberate host CPU load.

mod definition;
mod probe;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crucible::{
    AdvanceOutcome, ContentHash, ExecutionHorizon, Icount, NodeId, SchedulerError, SchedulerNodeId,
    SchedulerSendAuthorization, SchedulerSendAuthorizer,
};
use crucible_shmem::{
    FingerprintSample, RegionAllocation, RegionConfig, SLOT_NET_ROUTER, mmap_setup_region,
};
use thiserror::Error;

use crate::single_vm_fingerprint::{
    PluginFingerprintBoundary, SingleVmFingerprintGateError, SingleVmFingerprintRunError,
    SingleVmFingerprintRunOrdinal, SingleVmFingerprintRunRequest, SingleVmFingerprintRunner,
    SingleVmFingerprintStream, SingleVmFingerprintTrigger, build_plugin_fingerprint_stream,
};
use crate::{
    LaunchProfileCandidate, QemuLaunchArtifact, QemuLaunchPluginConfig, QemuLaunchPluginSwitch,
    QemuMappedQuantumShmemHotPath, QemuNodeChannelError, QemuNodeChild,
    QemuPluginIpcControlChannel, QemuQuantumShmemConfig, QemuShmemHotPathChannel,
    QemuVmLaunchConfig, complete_qemu_host_plugin_setup, spawn_qemu_child_with_fds_in_directory,
};

pub use definition::{
    CADENCE_ICOUNT, RUST_PLUGIN_FINGERPRINT_DOMAIN, RustPluginFingerprintDefinition, TARGET_ICOUNTS,
};

/// Content-addressing domain for the fingerprint runner's launch artifacts.
const RUNNER_DOMAIN: &str = "crucible.rust-plugin-fingerprint-runner.v1";
/// Stable node name for the single-VM fingerprint run.
const RUNNER_NODE: &str = "rust-plugin-fingerprint-vm";
/// Stable router name reserved by the shared-memory hot path.
const RUNNER_ROUTER: &str = "rust-plugin-fingerprint-router";
/// VM slot negotiated during the handshake.
const RUNNER_SLOT: u32 = 0;
/// Fixed inbound/outbound ring capacity for the single-node run.
const RUNNER_QUEUE_CAPACITY: u32 = 4;
/// Default guest memory size for the run.
///
/// The diskless single-vCPU idle guest boots comfortably in 64 MiB. A busy
/// multi-vCPU SMP guest needs more headroom; raise it with
/// [`PluginFingerprintRunnerConfig::with_memory_mib`].
const DEFAULT_RUNNER_MEMORY_MIB: u32 = 64;
/// Default vCPU count for the runner's launch contract.
///
/// The single-vCPU path is what the loaded-QEMU quantum gate proves live, so a
/// runner built without [`PluginFingerprintRunnerConfig::with_smp_vcpus`] stays
/// on it. M3 raises the count to drive the multi-vCPU aggregate-icount clock and
/// sample every vCPU's register file into the N-vCPU fingerprint.
const DEFAULT_RUNNER_SMP_VCPUS: u16 = 1;
/// Number of background threads used to stress host scheduling on the load run.
const HOST_LOAD_WORKERS: usize = 4;
/// Host poll interval while waiting on the plugin-owned boundary or teardown.
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Immutable launch inputs shared by every run of one fingerprint scenario.
///
/// The QEMU and Rust plugin binaries are content-hashed at construction and the
/// resulting digests bind the fingerprint definition, so a stream produced
/// against a different QEMU or plugin build can never compare as equal.
#[derive(Clone, Debug)]
pub struct PluginFingerprintRunnerConfig {
    qemu_executable: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    firmware: PathBuf,
    initrd: Option<PathBuf>,
    run_directory: PathBuf,
    kernel_cmdline: Option<String>,
    completion_timeout: Duration,
    second_run_host_load: bool,
    qemu_build_digest: String,
    rust_plugin_build_digest: String,
    rr_switch_quantum: u64,
    smp_vcpus: u16,
    memory_mib: u32,
}

impl PluginFingerprintRunnerConfig {
    /// Builds a runner configuration, hashing the QEMU and plugin binaries.
    ///
    /// The diskless `firmware` selects the no-block-device launch shape the
    /// busy-boot cadence requires, mirroring the quantum gate.
    ///
    /// # Errors
    ///
    /// Returns [`PluginFingerprintRunnerError::ReadBuildArtifact`] when the QEMU
    /// executable or the plugin shared object cannot be read for hashing.
    pub fn new(
        qemu_executable: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
        kernel: impl Into<PathBuf>,
        firmware: impl Into<PathBuf>,
        run_directory: impl Into<PathBuf>,
    ) -> Result<Self, PluginFingerprintRunnerError> {
        let qemu_executable = qemu_executable.into();
        let plugin = plugin.into();
        let qemu_build_digest = hash_file(&qemu_executable)?;
        let rust_plugin_build_digest = hash_file(&plugin)?;
        Ok(Self {
            qemu_executable,
            plugin,
            kernel: kernel.into(),
            firmware: firmware.into(),
            initrd: None,
            run_directory: run_directory.into(),
            kernel_cmdline: None,
            completion_timeout: Duration::from_secs(240),
            second_run_host_load: true,
            qemu_build_digest,
            rust_plugin_build_digest,
            rr_switch_quantum: 0,
            smp_vcpus: DEFAULT_RUNNER_SMP_VCPUS,
            memory_mib: DEFAULT_RUNNER_MEMORY_MIB,
        })
    }

    /// Returns this configuration with a fixed guest memory size in MiB.
    ///
    /// Guest memory is a launch parameter only; it is not part of the
    /// fingerprint definition digest.
    #[must_use]
    pub const fn with_memory_mib(mut self, memory_mib: u32) -> Self {
        self.memory_mib = memory_mib;
        self
    }

    /// Returns this configuration with a fixed vCPU count for the launch.
    ///
    /// The count is bound into both the launch `-smp` flag and the fingerprint
    /// definition digest (via [`RustPluginFingerprintDefinition`]), so a run at a
    /// different topology can never compare as equal. It must equal the vCPU
    /// count the scenario's N-vCPU contract declares.
    #[must_use]
    pub const fn with_smp_vcpus(mut self, smp_vcpus: u16) -> Self {
        self.smp_vcpus = smp_vcpus;
        self
    }

    /// Returns the launch-pinned vCPU count.
    #[must_use]
    pub const fn smp_vcpus(&self) -> u16 {
        self.smp_vcpus
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

    /// Returns this configuration with a different host-side completion bound.
    #[must_use]
    pub const fn with_completion_timeout(mut self, completion_timeout: Duration) -> Self {
        self.completion_timeout = completion_timeout;
        self
    }

    /// Returns this configuration with host CPU load on the second run toggled.
    #[must_use]
    pub const fn with_second_run_host_load(mut self, second_run_host_load: bool) -> Self {
        self.second_run_host_load = second_run_host_load;
        self
    }

    /// Returns the content digest of the pinned QEMU build.
    #[must_use]
    pub fn qemu_build_digest(&self) -> &str {
        &self.qemu_build_digest
    }

    /// Returns the content digest of the pinned Rust plugin build.
    #[must_use]
    pub fn rust_plugin_build_digest(&self) -> &str {
        &self.rust_plugin_build_digest
    }
}

/// The live Rust-plugin single-VM fingerprint backend.
///
/// Holds the immutable launch configuration and the minted fingerprint
/// definition. A fresh QEMU process is spawned for every run and every probe,
/// so no guest state survives between observations.
#[derive(Clone, Debug)]
pub struct PluginFingerprintRunner {
    config: PluginFingerprintRunnerConfig,
    definition: RustPluginFingerprintDefinition,
    probe_count: u64,
}

impl PluginFingerprintRunner {
    /// Builds a runner and mints its content-addressed fingerprint definition.
    ///
    /// `rr_switch_quantum` must equal the scenario's launch-pinned RR switch
    /// quantum; it is bound into the definition digest.
    ///
    /// # Errors
    ///
    /// Returns [`PluginFingerprintRunnerError::Definition`] when the definition
    /// cannot be minted from the topology and build digests.
    pub fn new(
        mut config: PluginFingerprintRunnerConfig,
        rr_switch_quantum: u64,
    ) -> Result<Self, PluginFingerprintRunnerError> {
        config.rr_switch_quantum = rr_switch_quantum;
        let definition = RustPluginFingerprintDefinition::new(
            rr_switch_quantum,
            u32::from(config.smp_vcpus),
            config.qemu_build_digest.clone(),
            config.rust_plugin_build_digest.clone(),
        )
        .map_err(PluginFingerprintRunnerError::Definition)?;
        Ok(Self {
            config,
            definition,
            probe_count: 0,
        })
    }

    /// Returns the minted fingerprint definition.
    #[must_use]
    pub const fn definition(&self) -> &RustPluginFingerprintDefinition {
        &self.definition
    }

    /// Returns the 32-byte content-addressed fingerprint definition digest.
    #[must_use]
    pub fn definition_digest(&self) -> [u8; 32] {
        self.definition.definition_digest()
    }

    /// Returns how many exact-icount probes this runner has executed.
    #[must_use]
    pub const fn probe_count(&self) -> u64 {
        self.probe_count
    }

    /// Drives one fresh run to `targets` and returns the per-boundary samples.
    ///
    /// The returned pairs are `(target_icount, sample)` in ascending order, one
    /// per requested target. `role` selects the run subdirectory and whether
    /// deliberate host CPU load runs concurrently.
    fn run_to_targets(
        &self,
        role: RunRole,
        targets: &[u64],
    ) -> Result<Vec<(u64, FingerprintSample)>, PluginFingerprintRunnerError> {
        let run_directory = self.config.run_directory.join(role.subdir());
        fs::create_dir_all(&run_directory).map_err(|source| {
            PluginFingerprintRunnerError::PrepareRunDirectory {
                path: run_directory.clone(),
                source,
            }
        })?;

        let host_load = HostLoad::start_if(role.applies_host_load());

        let mut candidate = LaunchProfileCandidate::default()
            .with_memory_mib(self.config.memory_mib)
            .with_smp_vcpus(self.config.smp_vcpus);
        if let Some(cmdline) = &self.config.kernel_cmdline {
            candidate = candidate.with_kernel_cmdline(cmdline.clone());
        }
        let profile = candidate
            .try_into_deterministic()
            .map_err(|source| PluginFingerprintRunnerError::LaunchProfile { source })?;
        profile
            .guest_entropy_seed_file()
            .write_to_dir(&run_directory)
            .map_err(|source| PluginFingerprintRunnerError::GuestEntropySeed {
                path: run_directory.clone(),
                source,
            })?;

        // A single production control plugin with fingerprint sampling enabled:
        // the Rust plugin is the sole time authority and the fingerprint author.
        let plugin = QemuLaunchPluginConfig::new(path_text(&self.config.plugin), RUNNER_SLOT)
            .with_fingerprint(QemuLaunchPluginSwitch::On);
        let command = profile
            .qemu_launch_command(
                self.vm_launch_config(),
                path_text(&self.config.qemu_executable),
                plugin,
            )
            .map_err(|source| PluginFingerprintRunnerError::LaunchCommand { source })?;

        let region_config = RegionConfig::new(1, RUNNER_QUEUE_CAPACITY, 0);
        let allocation = RegionAllocation::new(region_config)
            .map_err(|source| PluginFingerprintRunnerError::RegionLayout { source })?;
        let spawned = spawn_qemu_child_with_fds_in_directory(
            &command,
            &run_directory,
            allocation.layout().region_size,
        )
        .map_err(|source| PluginFingerprintRunnerError::Spawn { source })?;
        let (mut child, resources) = spawned.into_parts();

        let mut setup = complete_qemu_host_plugin_setup(
            resources.into_setup_resources(),
            region_config,
            RUNNER_SLOT,
        )
        .map_err(|source| PluginFingerprintRunnerError::HostSetup { source })?;
        if !setup.setup_ack().can_schedule() {
            return Err(PluginFingerprintRunnerError::SetupAckNotReady);
        }

        let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
            .map_err(|source| PluginFingerprintRunnerError::RegionMap { source })?;
        let hot_path_config = QemuQuantumShmemConfig::new(node_id(RUNNER_NODE), RUNNER_SLOT)
            .with_router(node_id(RUNNER_ROUTER), SLOT_NET_ROUTER as u32);
        let mut hot_path =
            QemuMappedQuantumShmemHotPath::new(hot_path_config, region, RunnerSendAuthorizer)
                .map_err(|source| PluginFingerprintRunnerError::MappedHotPath { source })?;

        let mut boundaries = Vec::with_capacity(targets.len());
        for &target in targets {
            let reached = self.drive_to_target(&mut hot_path, &mut child, &setup, target)?;
            let sample = hot_path
                .fingerprint_sample()
                .map_err(|source| PluginFingerprintRunnerError::MappedHotPath { source })?
                .ok_or(PluginFingerprintRunnerError::MissingFingerprintSample {
                    target_icount: target,
                })?;
            if sample.sample_icount != reached {
                return Err(
                    PluginFingerprintRunnerError::FingerprintSampleIcountMismatch {
                        target_icount: target,
                        reached_icount: reached,
                        sample_icount: sample.sample_icount,
                    },
                );
            }
            boundaries.push((reached, sample));
        }

        setup
            .assert_run_control_silent()
            .map_err(|source| channel_error("prove run control silence", source))?;
        QemuPluginIpcControlChannel::send_quit(&mut setup)
            .map_err(|source| channel_error("send plugin Quit", source))?;
        self.wait_for_plugin_teardown(&hot_path)?;
        let exit_status = self.wait_for_natural_child_exit(&mut child)?;
        if !exit_status.success() {
            return Err(PluginFingerprintRunnerError::ChildExitUnclean {
                status: exit_status.to_string(),
            });
        }
        drop(setup);
        drop(child);
        drop(host_load);

        Ok(boundaries)
    }

    /// Raises the ceiling to `target` in one quantum and returns the reached icount.
    ///
    /// Every cadence target is below the guest idle onset, so a busy quantum
    /// stops exactly at the ceiling. A guest that parks before the target
    /// (reports an idle deadline beyond it) is a determinism fault for these
    /// targets and is rejected.
    fn drive_to_target(
        &self,
        hot_path: &mut QemuMappedQuantumShmemHotPath,
        child: &mut QemuNodeChild,
        setup: &crate::QemuHostPluginSetup,
        target: u64,
    ) -> Result<u64, PluginFingerprintRunnerError> {
        let pending = QemuShmemHotPathChannel::start_quantum(
            hot_path,
            ExecutionHorizon {
                icount: Icount { retired: target },
            },
        )
        .map_err(|source| channel_error("start quantum", source))?;
        // Rouse the parked vCPU on its inherited wake eventfd once per quantum,
        // exactly as the quantum gate does: a shared-memory futex wake alone does
        // not release a guest that idled on a prior quantum.
        setup
            .signal_plugin_wake()
            .map_err(|source| channel_error("wake plugin for next quantum", source))?;
        let reached = self.wait_for_target_boundary(hot_path, child, target)?;
        let completion = QemuShmemHotPathChannel::finish_quantum(hot_path, pending)
            .map_err(|source| channel_error("finish quantum", source))?;
        match completion.outcome {
            AdvanceOutcome::ReachedHorizon => Ok(reached),
            outcome => Err(PluginFingerprintRunnerError::TargetNotReached {
                target_icount: target,
                reached_icount: reached,
                outcome: format!("{outcome:?}"),
            }),
        }
    }

    // crucible-lint: allow clippy-disallowed-method -- host timeout bounds QEMU liveness only.
    #[allow(clippy::disallowed_methods)]
    fn wait_for_target_boundary(
        &self,
        hot_path: &mut QemuMappedQuantumShmemHotPath,
        child: &mut QemuNodeChild,
        target: u64,
    ) -> Result<u64, PluginFingerprintRunnerError> {
        let started = Instant::now();
        loop {
            let idle = QemuShmemHotPathChannel::idle_state(hot_path)
                .map_err(|source| channel_error("poll idle state", source))?;
            let current = idle.current_icount.retired;
            if current >= target {
                return Ok(current);
            }
            if let Some(deadline) = idle.next_deadline
                && deadline.retired > target
            {
                return Err(PluginFingerprintRunnerError::GuestIdledBeforeTarget {
                    target_icount: target,
                    idle_icount: current,
                    deadline_icount: deadline.retired,
                });
            }
            if let Some(status) = child
                .try_wait_natural_exit()
                .map_err(|source| PluginFingerprintRunnerError::ChildWait { source })?
            {
                return Err(PluginFingerprintRunnerError::ChildExitBeforeBoundary {
                    target_icount: target,
                    status: status.to_string(),
                });
            }
            if started.elapsed() >= self.config.completion_timeout {
                return Err(PluginFingerprintRunnerError::QuantumTimeout {
                    target_icount: target,
                    last_icount: current,
                    timeout: self.config.completion_timeout,
                });
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    // crucible-lint: allow clippy-disallowed-method -- host timeout bounds plugin teardown only.
    #[allow(clippy::disallowed_methods)]
    fn wait_for_plugin_teardown(
        &self,
        hot_path: &QemuMappedQuantumShmemHotPath,
    ) -> Result<(), PluginFingerprintRunnerError> {
        let started = Instant::now();
        loop {
            if hot_path
                .plugin_teardown_done()
                .map_err(|source| PluginFingerprintRunnerError::MappedHotPath { source })?
            {
                return Ok(());
            }
            if started.elapsed() >= self.config.completion_timeout {
                return Err(PluginFingerprintRunnerError::PluginQuitTimeout {
                    timeout: self.config.completion_timeout,
                });
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    // crucible-lint: allow clippy-disallowed-method -- host timeout bounds child reap only.
    #[allow(clippy::disallowed_methods)]
    fn wait_for_natural_child_exit(
        &self,
        child: &mut QemuNodeChild,
    ) -> Result<std::process::ExitStatus, PluginFingerprintRunnerError> {
        let started = Instant::now();
        loop {
            if let Some(status) = child
                .try_wait_natural_exit()
                .map_err(|source| PluginFingerprintRunnerError::ChildWait { source })?
            {
                return Ok(status);
            }
            if started.elapsed() >= self.config.completion_timeout {
                return Err(PluginFingerprintRunnerError::ChildExitTimeout {
                    timeout: self.config.completion_timeout,
                });
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    /// Builds a validated fingerprint stream from ascending `(icount, sample)` pairs.
    fn stream_from_samples(
        &self,
        samples: &[(u64, FingerprintSample)],
        run_horizon_icount: u64,
    ) -> Result<SingleVmFingerprintStream, PluginFingerprintRunnerError> {
        let boundaries = samples
            .iter()
            .map(|(icount, sample)| PluginFingerprintBoundary {
                icount: *icount,
                trigger: SingleVmFingerprintTrigger::Periodic,
                sample,
            })
            .collect::<Vec<_>>();
        build_plugin_fingerprint_stream(
            self.definition.definition_digest().to_vec(),
            RUNNER_NODE,
            run_horizon_icount,
            &boundaries,
        )
        .map_err(PluginFingerprintRunnerError::BuildStream)
    }

    fn vm_launch_config(&self) -> QemuVmLaunchConfig {
        let kernel = self.launch_artifact("kernel", &self.config.kernel);
        let vm = QemuVmLaunchConfig::new_diskless(
            RUNNER_NODE,
            kernel,
            self.launch_artifact("firmware", &self.config.firmware),
        );
        match &self.config.initrd {
            Some(initrd) => vm.with_initrd(self.launch_artifact("initrd", initrd)),
            None => vm,
        }
    }

    fn launch_artifact(&self, kind: &str, path: &Path) -> QemuLaunchArtifact {
        let path = path_text(path);
        QemuLaunchArtifact::new(
            ContentHash::from_canonical_material(RUNNER_DOMAIN, &format!("{kind}={path}")),
            path,
        )
    }
}

impl SingleVmFingerprintRunner for PluginFingerprintRunner {
    fn run_single_vm_fingerprint(
        &mut self,
        request: &SingleVmFingerprintRunRequest,
    ) -> Result<SingleVmFingerprintStream, SingleVmFingerprintRunError> {
        let role = self.role_for(request.ordinal());
        let run_horizon_icount = request.scenario().run_horizon_icount();
        let samples = self
            .run_to_targets(role, &self.definition.targets())
            .map_err(to_run_error)?;
        self.stream_from_samples(&samples, run_horizon_icount)
            .map_err(to_run_error)
    }

    fn bisect_single_vm_fingerprint_mismatch(
        &mut self,
        request: &crate::single_vm_fingerprint::SingleVmFingerprintBisectionRequest,
    ) -> Result<
        crate::single_vm_fingerprint::SingleVmFingerprintBisectionReport,
        crate::single_vm_fingerprint::SingleVmFingerprintBisectionError,
    > {
        crate::single_vm_fingerprint::bisect_single_vm_fingerprint_with_probes(self, request)
    }
}

impl PluginFingerprintRunner {
    /// Maps a run ordinal to its subdirectory and host-load role.
    ///
    /// The second run applies deliberate host CPU load when enabled, which is
    /// the run-twice determinism evidence: a plugin that owns icount-derived
    /// virtual time must produce a byte-identical stream regardless of host
    /// scheduling pressure.
    fn role_for(&self, ordinal: SingleVmFingerprintRunOrdinal) -> RunRole {
        match ordinal {
            SingleVmFingerprintRunOrdinal::First => RunRole::Reference,
            SingleVmFingerprintRunOrdinal::Second if self.config.second_run_host_load => {
                RunRole::HostLoad
            }
            SingleVmFingerprintRunOrdinal::Second => RunRole::Repeat,
        }
    }
}

/// Which run this is, controlling the run subdirectory and host load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunRole {
    Reference,
    HostLoad,
    Repeat,
    Probe,
}

impl RunRole {
    const fn subdir(self) -> &'static str {
        match self {
            Self::Reference => "run-reference",
            Self::HostLoad => "run-host-load",
            Self::Repeat => "run-repeat",
            Self::Probe => "run-probe",
        }
    }

    const fn applies_host_load(self) -> bool {
        matches!(self, Self::HostLoad)
    }
}

/// A background host-CPU load generator that stresses scheduling around a run.
///
/// The busy threads consume CPU without touching the guest, the plugin, or the
/// shared-memory region, so a deterministic, icount-owning plugin must produce
/// an identical fingerprint whether or not the load is present.
struct HostLoad {
    stop: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl HostLoad {
    fn start_if(enabled: bool) -> Option<Self> {
        if !enabled {
            return None;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(HOST_LOAD_WORKERS);
        for _ in 0..HOST_LOAD_WORKERS {
            let stop = Arc::clone(&stop);
            workers.push(thread::spawn(move || {
                let mut accumulator: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    for value in 0..4096_u64 {
                        accumulator = accumulator
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(value);
                    }
                    std::hint::black_box(accumulator);
                }
            }));
        }
        Some(Self { stop, workers })
    }
}

impl Drop for HostLoad {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// Send authorizer for the single-node fingerprint run.
///
/// The run has one VM and one router slot and never routes a real cross-node
/// frame, so authorization is unconditional.
struct RunnerSendAuthorizer;

impl SchedulerSendAuthorizer for RunnerSendAuthorizer {
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

/// An error produced while running the live Rust-plugin fingerprint backend.
#[derive(Debug, Error)]
pub enum PluginFingerprintRunnerError {
    /// A QEMU or plugin build artifact could not be read for hashing.
    #[error("cannot read build artifact {path} for content hashing")]
    ReadBuildArtifact {
        /// Artifact path that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The fingerprint definition could not be minted.
    #[error("cannot mint the rust-plugin fingerprint definition: {0}")]
    Definition(SingleVmFingerprintGateError),
    /// The per-run directory could not be prepared.
    #[error("cannot prepare run directory {path}")]
    PrepareRunDirectory {
        /// Directory that could not be created.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The deterministic launch profile could not be derived.
    #[error("cannot derive deterministic launch profile")]
    LaunchProfile {
        /// Underlying launch profile error.
        source: crate::LaunchProfileError,
    },
    /// The guest entropy seed file could not be written.
    #[error("cannot write guest entropy seed into {path}")]
    GuestEntropySeed {
        /// Directory that could not receive the seed.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The QEMU launch command could not be assembled.
    #[error("cannot assemble QEMU launch command")]
    LaunchCommand {
        /// Underlying launch command error.
        source: crate::QemuLaunchCommandError,
    },
    /// The shared-memory region layout could not be computed.
    #[error("cannot compute shared-memory region layout")]
    RegionLayout {
        /// Underlying region layout error.
        source: crucible_shmem::RegionLayoutError,
    },
    /// The QEMU child could not be spawned with passed descriptors.
    #[error("cannot spawn QEMU child with passed descriptors")]
    Spawn {
        /// Underlying spawn error.
        source: crate::QemuSpawnError,
    },
    /// The host plugin setup handshake failed.
    #[error("QEMU host plugin setup handshake failed")]
    HostSetup {
        /// Underlying host setup error.
        source: crate::QemuHostPluginSetupError,
    },
    /// The setup acknowledgement was not schedulable.
    #[error("QEMU setup acknowledgement was not schedulable")]
    SetupAckNotReady,
    /// The setup shared-memory region could not be mapped.
    #[error("cannot map the setup shared-memory region")]
    RegionMap {
        /// Underlying region map error.
        source: crucible_shmem::SetupRegionMapError,
    },
    /// The mapped quantum hot path could not be bound or read.
    #[error("mapped quantum hot path failed")]
    MappedHotPath {
        /// Underlying mapped hot-path error.
        source: crate::QemuMappedQuantumShmemHotPathError,
    },
    /// A quantum stopped without reaching the requested target.
    #[error("quantum for target {target_icount} stopped at {reached_icount} ({outcome})")]
    TargetNotReached {
        /// Requested aggregate-icount target.
        target_icount: u64,
        /// Aggregate icount actually reached.
        reached_icount: u64,
        /// The plugin's reported advance outcome.
        outcome: String,
    },
    /// The guest parked idle before reaching a busy-phase target.
    #[error(
        "guest idled at {idle_icount} (deadline {deadline_icount}) before target {target_icount}"
    )]
    GuestIdledBeforeTarget {
        /// Requested aggregate-icount target.
        target_icount: u64,
        /// Aggregate icount at which the guest parked.
        idle_icount: u64,
        /// Published next virtual-timer deadline.
        deadline_icount: u64,
    },
    /// The plugin published no fingerprint sample at a boundary.
    #[error("no fingerprint sample was published at target {target_icount}")]
    MissingFingerprintSample {
        /// Target with no published sample.
        target_icount: u64,
    },
    /// A published fingerprint sample was stamped with an unexpected icount.
    #[error(
        "fingerprint sample icount {sample_icount} != reached {reached_icount} for target {target_icount}"
    )]
    FingerprintSampleIcountMismatch {
        /// Requested aggregate-icount target.
        target_icount: u64,
        /// Aggregate icount actually reached.
        reached_icount: u64,
        /// The icount stamped into the sample.
        sample_icount: u64,
    },
    /// A quantum did not reach its boundary before the host timeout.
    #[error("quantum for target {target_icount} timed out at {last_icount} after {timeout:?}")]
    QuantumTimeout {
        /// Requested aggregate-icount target.
        target_icount: u64,
        /// Last observed aggregate icount.
        last_icount: u64,
        /// Host completion bound.
        timeout: Duration,
    },
    /// The QEMU child exited before a quantum boundary.
    #[error("QEMU child exited before target {target_icount}: {status}")]
    ChildExitBeforeBoundary {
        /// Target the child never reached.
        target_icount: u64,
        /// Child exit status text.
        status: String,
    },
    /// Waiting on the QEMU child failed.
    #[error("cannot wait on the QEMU child")]
    ChildWait {
        /// Underlying wait error.
        source: crate::QemuShutdownTargetError,
    },
    /// The plugin did not publish terminal teardown before the host timeout.
    #[error("plugin teardown did not complete within {timeout:?}")]
    PluginQuitTimeout {
        /// Host completion bound.
        timeout: Duration,
    },
    /// The QEMU child did not exit naturally before the host timeout.
    #[error("QEMU child did not exit within {timeout:?}")]
    ChildExitTimeout {
        /// Host completion bound.
        timeout: Duration,
    },
    /// The QEMU child exited with a non-success status.
    #[error("QEMU child exited uncleanly: {status}")]
    ChildExitUnclean {
        /// Child exit status text.
        status: String,
    },
    /// A shared-memory hot-path channel operation failed.
    #[error("hot-path channel operation '{operation}' failed: {source}")]
    Channel {
        /// The failing operation name.
        operation: &'static str,
        /// Underlying channel error.
        source: QemuNodeChannelError,
    },
    /// The fingerprint stream could not be assembled from the samples.
    #[error("cannot build fingerprint stream: {0}")]
    BuildStream(SingleVmFingerprintGateError),
}

/// Converts a runner error into the trait-level run error.
fn to_run_error(error: PluginFingerprintRunnerError) -> SingleVmFingerprintRunError {
    SingleVmFingerprintRunError::new(error.to_string())
}

fn channel_error(
    operation: &'static str,
    source: QemuNodeChannelError,
) -> PluginFingerprintRunnerError {
    PluginFingerprintRunnerError::Channel { operation, source }
}

fn hash_file(path: &Path) -> Result<String, PluginFingerprintRunnerError> {
    let bytes =
        fs::read(path).map_err(|source| PluginFingerprintRunnerError::ReadBuildArtifact {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(ContentHash::from_bytes(&bytes).to_hex())
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}
