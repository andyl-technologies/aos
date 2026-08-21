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

mod config;
mod definition;
mod error;
mod probe;
mod raw_dump;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::single_vm_fingerprint::{
    PluginFingerprintBoundary, SingleVmFingerprintEventBoundary, SingleVmFingerprintRunError,
    SingleVmFingerprintRunOrdinal, SingleVmFingerprintRunRequest, SingleVmFingerprintRunner,
    SingleVmFingerprintStream, SingleVmFingerprintTrigger, build_plugin_fingerprint_stream,
};

use crate::{
    CrucibleShmemNetworkDevice, LaunchProfileCandidate, QemuLaunchArtifact,
    QemuLaunchCommandBuilder, QemuLaunchPluginConfig, QemuLaunchPluginSwitch,
    QemuMappedQuantumShmemHotPath, QemuNodeChild, QemuPluginIpcControlChannel,
    QemuQuantumShmemConfig, QemuShmemHotPathChannel, QemuVmLaunchConfig,
    complete_qemu_host_plugin_setup, spawn_qemu_child_with_fds_in_directory,
};
pub use config::PluginFingerprintRunnerConfig;
use crucible::{
    AdvanceOutcome, BackendInput, ContentHash, ExecutionHorizon, Icount, SchedulerError,
    SchedulerNodeId, SchedulerSendAuthorization, SchedulerSendAuthorizer,
};
use crucible_shmem::{
    FingerprintSample, RegionAllocation, RegionConfig, SLOT_NET_ROUTER, SchedulerPreemptionCommand,
    SchedulerPreemptionKind, mmap_setup_region,
};

pub use definition::{
    CADENCE_ICOUNT, FRAME_DELIVERY_ICOUNT, RUST_PLUGIN_FINGERPRINT_DOMAIN,
    RustPluginFingerprintDefinition, SAMPLE_ICOUNTS, SIGNAL_EFFECT_BOUNDARY_ICOUNT,
};
pub use error::PluginFingerprintRunnerError;
use error::{channel_error, hash_file, node_id, path_text, to_run_error};
use raw_dump::{PreparedStateDumpPair, RawStateArtifact, read_raw_state_artifact};

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
/// File emitted by gate-only translation-prefetch experiment launches.
pub const TRANSLATION_PREFETCH_REPORT_FILE: &str = "translation-prefetch.report";
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
    state_dump_cache: Option<PreparedStateDumpPair>,
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
            state_dump_cache: None,
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
        self.run_to_targets_inner(role, targets, None)
            .map(|result| result.boundaries)
    }

    /// Drives one fresh run and terminally exports full state at one target.
    fn run_to_targets_with_state_dump(
        &self,
        role: RunRole,
        target: u64,
    ) -> Result<RawStateArtifact, PluginFingerprintRunnerError> {
        let mut targets = SAMPLE_ICOUNTS
            .into_iter()
            .filter(|boundary| *boundary < target)
            .collect::<Vec<_>>();
        targets.push(target);
        self.run_to_targets_inner(role, &targets, Some(target))?
            .state_dump
            .ok_or(PluginFingerprintRunnerError::MissingStateDump {
                target_icount: target,
            })
    }

    fn run_to_targets_inner(
        &self,
        role: RunRole,
        targets: &[u64],
        state_dump_target: Option<u64>,
    ) -> Result<PluginRunResult, PluginFingerprintRunnerError> {
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
            let cmdline = if self.config.second_run_divergence_control
                && matches!(role, RunRole::HostLoad | RunRole::Repeat)
            {
                format!("{cmdline} crucible_negative_control=1")
            } else {
                cmdline.clone()
            };
            candidate = candidate.with_kernel_cmdline(cmdline);
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
        let mut plugin = QemuLaunchPluginConfig::new(path_text(&self.config.plugin), RUNNER_SLOT)
            .with_fault_target_node(RUNNER_NODE)
            .with_fingerprint(QemuLaunchPluginSwitch::On);
        if self.config.synchronous_oracle {
            plugin = plugin.with_fingerprint_oracle(QemuLaunchPluginSwitch::On);
        }
        let state_dump_path =
            state_dump_target.map(|target| run_directory.join(format!("state-dump-{target}.bin")));
        if let Some(path) = &state_dump_path {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(PluginFingerprintRunnerError::PrepareStateDump {
                        path: path.clone(),
                        source,
                    });
                }
            }
            plugin = plugin
                .with_terminal_state_dump(state_dump_target.unwrap_or_default(), path_text(path));
        }
        let report_path = self
            .config
            .translation_prefetch_experiment
            .map(|_| run_directory.join(TRANSLATION_PREFETCH_REPORT_FILE));
        if let Some(path) = &report_path {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(
                        PluginFingerprintRunnerError::PrepareTranslationPrefetchReport {
                            path: path.clone(),
                            source,
                        },
                    );
                }
            }
        }
        let mut command_builder = QemuLaunchCommandBuilder::new_for_live_gate(
            profile,
            self.vm_launch_config(),
            path_text(&self.config.qemu_executable),
            plugin,
            crate::LivePluginGuestArchitecture::X86_64,
        );
        if let (Some(enabled), Some(path)) =
            (self.config.translation_prefetch_experiment, &report_path)
        {
            command_builder =
                command_builder.with_translation_prefetch_experiment(enabled, path_text(path));
        }
        let command = command_builder
            .build()
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
            command.fault_capability_requirement(),
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
            if target == FRAME_DELIVERY_ICOUNT {
                let payload = if self.config.second_run_divergence_control
                    && matches!(role, RunRole::HostLoad | RunRole::Repeat)
                {
                    b"crucible-fingerprint-frame-negative-control-v1".to_vec()
                } else {
                    b"crucible-fingerprint-frame-v1".to_vec()
                };
                QemuShmemHotPathChannel::deliver_frame(
                    &mut hot_path,
                    BackendInput {
                        node: node_id(RUNNER_NODE),
                        payload,
                    },
                )
                .map_err(|source| channel_error("enqueue fingerprint frame event", source))?;
            }
            let preemption_sequence = if target == SIGNAL_EFFECT_BOUNDARY_ICOUNT {
                let irq = if self.config.second_run_divergence_control
                    && matches!(role, RunRole::HostLoad | RunRole::Repeat)
                {
                    0xf2
                } else {
                    0xf1
                };
                Some(
                    hot_path
                        .publish_preemption_command(SchedulerPreemptionCommand {
                            at_icount: target,
                            deadline_icount: target,
                            ceiling_icount: target,
                            kind: SchedulerPreemptionKind::InterruptAt {
                                target_vcpu: 0,
                                irq,
                            },
                        })
                        .map_err(|source| PluginFingerprintRunnerError::MappedHotPath { source })?,
                )
            } else {
                None
            };
            let reached = self.drive_to_target(&mut hot_path, &mut child, &setup, target)?;
            if let Some(expected) = preemption_sequence {
                let observed = hot_path
                    .consumed_preemption_sequence()
                    .map_err(|source| PluginFingerprintRunnerError::MappedHotPath { source })?;
                if observed != expected {
                    return Err(
                        PluginFingerprintRunnerError::SignalEffectBoundaryNotConsumed {
                            target_icount: target,
                            expected_sequence: expected,
                            observed_sequence: observed,
                        },
                    );
                }
            }
            let sample =
                self.wait_for_fingerprint_sample(&hot_path, &mut child, target, reached)?;
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

        let state_dump = match state_dump_path {
            Some(path) => {
                self.wait_for_state_dump(&path, state_dump_target.unwrap_or_default())?;
                Some(read_raw_state_artifact(&path)?)
            }
            None => None,
        };

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
        if let (Some(enabled), Some(path)) =
            (self.config.translation_prefetch_experiment, &report_path)
        {
            validate_translation_prefetch_report(path, enabled)?;
        }
        drop(setup);
        drop(child);
        drop(host_load);

        Ok(PluginRunResult {
            boundaries,
            state_dump,
        })
    }

    // crucible-lint: allow clippy-disallowed-method -- host timeout bounds terminal export liveness only.
    #[allow(clippy::disallowed_methods)]
    fn wait_for_state_dump(
        &self,
        path: &Path,
        target_icount: u64,
    ) -> Result<(), PluginFingerprintRunnerError> {
        let started = Instant::now();
        loop {
            match fs::metadata(path) {
                Ok(metadata) if metadata.len() > 0 => return Ok(()),
                Ok(_) => {}
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(PluginFingerprintRunnerError::ReadStateDump {
                        path: path.to_path_buf(),
                        source,
                    });
                }
            }
            if started.elapsed() >= self.config.completion_timeout {
                return Err(PluginFingerprintRunnerError::StateDumpTimeout {
                    target_icount,
                    timeout: self.config.completion_timeout,
                });
            }
            thread::sleep(POLL_INTERVAL);
        }
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

    // crucible-lint: allow clippy-disallowed-method -- host timeout bounds digest-worker liveness only.
    #[allow(clippy::disallowed_methods)]
    fn wait_for_fingerprint_sample(
        &self,
        hot_path: &QemuMappedQuantumShmemHotPath,
        child: &mut QemuNodeChild,
        target: u64,
        reached: u64,
    ) -> Result<FingerprintSample, PluginFingerprintRunnerError> {
        let started = Instant::now();
        loop {
            if let Some(sample) = hot_path
                .fingerprint_sample()
                .map_err(|source| PluginFingerprintRunnerError::MappedHotPath { source })?
            {
                if sample.sample_icount == reached {
                    return Ok(sample);
                }
                if sample.sample_icount > reached {
                    return Err(
                        PluginFingerprintRunnerError::FingerprintSampleIcountMismatch {
                            target_icount: target,
                            reached_icount: reached,
                            sample_icount: sample.sample_icount,
                        },
                    );
                }
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
                return Err(PluginFingerprintRunnerError::MissingFingerprintSample {
                    target_icount: target,
                });
            }
            thread::sleep(POLL_INTERVAL);
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
                trigger: trigger_for_icount(*icount),
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
        )
        .with_crucible_shmem_network(CrucibleShmemNetworkDevice::new());
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

fn validate_translation_prefetch_report(
    path: &Path,
    expected_enabled: bool,
) -> Result<(), PluginFingerprintRunnerError> {
    let report = fs::read_to_string(path).map_err(|source| {
        PluginFingerprintRunnerError::ReadTranslationPrefetchReport {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let expected = if expected_enabled {
        "enabled=true"
    } else {
        "enabled=false"
    };
    if !report.lines().any(|line| line == expected) {
        return Err(
            PluginFingerprintRunnerError::InvalidTranslationPrefetchReport {
                path: path.to_path_buf(),
                reason: "enabled mode does not match the requested launch",
            },
        );
    }
    if !report
        .lines()
        .any(|line| line == "mode=dedicated-demand-tcg-helper")
    {
        return Err(
            PluginFingerprintRunnerError::InvalidTranslationPrefetchReport {
                path: path.to_path_buf(),
                reason: "dedicated helper mode is absent",
            },
        );
    }
    if expected_enabled {
        let started = report
            .lines()
            .any(|line| line == "helper_thread_started=true");
        let requests = report
            .lines()
            .find_map(|line| line.strip_prefix("requests="))
            .and_then(|value| value.parse::<u64>().ok());
        let completions = report
            .lines()
            .find_map(|line| line.strip_prefix("completions="))
            .and_then(|value| value.parse::<u64>().ok());
        if !started || requests.is_none_or(|count| count == 0) || completions != requests {
            return Err(
                PluginFingerprintRunnerError::InvalidTranslationPrefetchReport {
                    path: path.to_path_buf(),
                    reason: "enabled helper did not complete every translation request",
                },
            );
        }
    }
    Ok(())
}

fn trigger_for_icount(icount: u64) -> SingleVmFingerprintTrigger {
    match icount {
        FRAME_DELIVERY_ICOUNT => {
            SingleVmFingerprintTrigger::Event(SingleVmFingerprintEventBoundary::FrameDelivery)
        }
        SIGNAL_EFFECT_BOUNDARY_ICOUNT => SingleVmFingerprintTrigger::Event(
            SingleVmFingerprintEventBoundary::SignalEffectBoundary,
        ),
        _ => SingleVmFingerprintTrigger::Periodic,
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
}

struct PluginRunResult {
    boundaries: Vec<(u64, FingerprintSample)>,
    state_dump: Option<RawStateArtifact>,
}

impl RunRole {
    const fn subdir(self) -> &'static str {
        match self {
            Self::Reference => "run-reference",
            Self::HostLoad => "run-host-load",
            Self::Repeat => "run-repeat",
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
