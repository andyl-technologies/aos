//! Production execution of one-sample terminal horizon observations.
//!
//! [`LiveTerminalHorizonExecutor`] is deliberately narrower than a general
//! fingerprint runner. It admits only configurations whose cadence equals the
//! nonzero run horizon, so strict trace import yields exactly one authoritative
//! horizon sample. The dedicated terminal trace contract proves that QEMU
//! paused before exporting raw RAM and sealed VMState. This module does not
//! provide exact refinement or divergence dumps.

use std::fs::{self, File};
use std::io::{self, BufReader};

use thiserror::Error;

use crate::single_vm_fingerprint::{
    QemuTerminalHorizonTraceImport, QemuTraceFingerprintDefinition,
    QemuTraceFingerprintImportError, QemuTraceProcessArgvContract, SingleVmFingerprintRunRequest,
    SingleVmFingerprintScenario, SingleVmFingerprintStream,
};

use super::{
    LiveDefinitionPreflightEvidence, LiveInvocationIdentity, LiveObservationControl,
    LiveObservationMode, LiveObservationProcessError, LiveObservationShutdown,
    LiveObservationShutdownPolicy, LivePreparationError, LivePreparationRequest,
    LivePreparedLaunch, LiveRunnerArtifactRoot, LiveRunnerArtifacts, LiveRunnerArtifactsError,
    LiveRunnerConfig, LiveRunnerLaunchKind, LiveRunnerQmpConnector, LiveRunnerQmpObservation,
    LiveRunnerQmpPoller, LiveRunnerSleeper, RawUnixArgvIdentity, spawn_live_observation_process,
};

/// Auditable result of one completed terminal horizon observation.
///
/// Every retained identity and lifecycle observation belongs to the same
/// process whose strictly imported trace produced [`Self::stream`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveTerminalHorizonReport {
    stream: SingleVmFingerprintStream,
    prepared: LivePreparedLaunch,
    qmp_observation: LiveRunnerQmpObservation,
    shutdown: LiveObservationShutdown,
}

impl LiveTerminalHorizonReport {
    /// Returns the imported one-sample terminal horizon stream.
    #[must_use]
    pub const fn stream(&self) -> &SingleVmFingerprintStream {
        &self.stream
    }

    /// Consumes the report and returns its imported stream.
    #[must_use]
    pub fn into_stream(self) -> SingleVmFingerprintStream {
        self.stream
    }

    /// Returns the fresh attempt number bound into every retained identity.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.prepared.artifacts().attempt()
    }

    /// Returns the exact launch consumed by the completed process.
    #[must_use]
    pub const fn prepared_launch(&self) -> &LivePreparedLaunch {
        &self.prepared
    }

    /// Returns the validated observation-control identity.
    #[must_use]
    pub const fn control(&self) -> &LiveObservationControl {
        self.prepared.control()
    }

    /// Returns the validated process invocation identity.
    #[must_use]
    pub const fn invocation(&self) -> &LiveInvocationIdentity {
        self.prepared.invocation()
    }

    /// Returns the independently computed raw Unix argv identity.
    #[must_use]
    pub const fn argv_identity(&self) -> &RawUnixArgvIdentity {
        self.prepared.argv_identity()
    }

    /// Returns the contract checked against QEMU's raw argv self-attestation.
    #[must_use]
    pub const fn process_argv_contract(&self) -> QemuTraceProcessArgvContract {
        self.prepared.process_argv_contract()
    }

    /// Returns the accepted typed QMP non-running paused boundary.
    #[must_use]
    pub const fn qmp_observation(&self) -> &LiveRunnerQmpObservation {
        &self.qmp_observation
    }

    /// Returns the retained natural successful shutdown evidence.
    #[must_use]
    pub const fn shutdown(&self) -> LiveObservationShutdown {
        self.shutdown
    }
}

/// Fresh-process executor for one-sample terminal horizon observations.
#[derive(Debug)]
pub struct LiveTerminalHorizonExecutor<C, S> {
    config: LiveRunnerConfig,
    artifact_root: LiveRunnerArtifactRoot,
    poller: LiveRunnerQmpPoller<C, S>,
    shutdown_policy: LiveObservationShutdownPolicy,
    preflight: LiveDefinitionPreflightEvidence,
    definition_digest: [u8; 32],
    scenario: SingleVmFingerprintScenario,
    next_attempt: u64,
}

impl<C, S> LiveTerminalHorizonExecutor<C, S>
where
    C: LiveRunnerQmpConnector,
    S: LiveRunnerSleeper,
{
    /// Builds an executor whose sole sample is the terminal horizon boundary.
    ///
    /// The cadence must equal the horizon. The independently executed
    /// definition preflight and complete scenario are rebound to `config`
    /// before any attempt can be allocated.
    ///
    /// # Errors
    ///
    /// Returns [`LiveTerminalHorizonExecutorError`] when cadence precedes the
    /// horizon, shutdown bounds are invalid, or preflight/scenario evidence
    /// differs from the verified live configuration.
    pub fn new(
        config: LiveRunnerConfig,
        artifact_root: LiveRunnerArtifactRoot,
        poller: LiveRunnerQmpPoller<C, S>,
        shutdown_policy: LiveObservationShutdownPolicy,
        preflight: LiveDefinitionPreflightEvidence,
        scenario: SingleVmFingerprintScenario,
    ) -> Result<Self, LiveTerminalHorizonExecutorError> {
        if config.cadence_icount() != config.horizon_icount() {
            return Err(LiveTerminalHorizonExecutorError::CadenceBeforeHorizon {
                cadence: config.cadence_icount(),
                horizon: config.horizon_icount(),
            });
        }
        let shutdown_policy = shutdown_policy.validate()?;
        validate_live_preflight(&config, &preflight, scenario.id())?;
        let definition_digest = QemuTraceFingerprintDefinition::new(
            config.cadence_icount(),
            preflight.imported().observation(),
        )?
        .definition_digest();
        validate_scenario(&config, &scenario, definition_digest)?;
        Ok(Self {
            config,
            artifact_root,
            poller,
            shutdown_policy,
            preflight,
            definition_digest,
            scenario,
            next_attempt: 1,
        })
    }

    /// Returns the independently derived fingerprint-definition digest.
    #[must_use]
    pub const fn definition_digest(&self) -> [u8; 32] {
        self.definition_digest
    }

    /// Executes one fresh terminal horizon observation.
    ///
    /// # Errors
    ///
    /// Returns [`LiveTerminalHorizonExecutorError`] when request validation,
    /// fresh allocation, process supervision, typed QMP admission, natural
    /// shutdown, trace import, or the one-sample postcondition fails.
    pub fn run(
        &mut self,
        request: &SingleVmFingerprintRunRequest,
    ) -> Result<SingleVmFingerprintStream, LiveTerminalHorizonExecutorError> {
        self.run_report(request)
            .map(LiveTerminalHorizonReport::into_stream)
    }

    /// Executes one fresh observation and retains its completed attempt evidence.
    ///
    /// # Errors
    ///
    /// Returns [`LiveTerminalHorizonExecutorError`] under the same fail-closed
    /// conditions as [`Self::run`].
    pub fn run_report(
        &mut self,
        request: &SingleVmFingerprintRunRequest,
    ) -> Result<LiveTerminalHorizonReport, LiveTerminalHorizonExecutorError> {
        let node = self.scenario.id().to_owned();
        let definition_digest = self.definition_digest;
        let horizon = self.config.horizon_icount();
        let observation = self.preflight.imported().observation().clone();
        self.run_report_with_boundary(request, move |prepared, poller, shutdown_policy| {
            let retained = prepared.clone();
            let attempt = spawn_live_observation_process(prepared)?.observe(poller)?;
            let qmp_observation = attempt.observation().clone();
            let importer = QemuTerminalHorizonTraceImport::new(
                node,
                definition_digest,
                horizon,
                observation,
                retained.process_argv_contract(),
            )?;
            wait_for_terminal_publication(poller, attempt.artifacts().trace(), &importer)?;
            let shutdown = attempt.shutdown(shutdown_policy)?;
            Ok(CompletedTerminalAttempt {
                prepared: retained,
                qmp_observation,
                shutdown,
            })
        })
    }

    fn run_report_with_boundary<F>(
        &mut self,
        request: &SingleVmFingerprintRunRequest,
        boundary: F,
    ) -> Result<LiveTerminalHorizonReport, LiveTerminalHorizonExecutorError>
    where
        F: FnOnce(
            LivePreparedLaunch,
            &mut LiveRunnerQmpPoller<C, S>,
            LiveObservationShutdownPolicy,
        ) -> Result<CompletedTerminalAttempt, LiveTerminalHorizonExecutorError>,
    {
        self.validate_request(request)?;
        let artifacts = self.allocate_attempt()?;
        let prepared = LivePreparedLaunch::new(
            &self.config,
            LiveRunnerLaunchKind::Observation,
            &artifacts,
            LivePreparationRequest {
                node: self.scenario.id().to_owned(),
                mode: LiveObservationMode::ObservationHorizon {
                    cadence_icount: self.config.cadence_icount(),
                    ordinal: request.ordinal(),
                },
                definition_digest: Some(self.definition_digest),
            },
        )?;
        validate_prepared(
            &prepared,
            &self.config,
            self.scenario.id(),
            request,
            self.definition_digest,
        )?;

        let completed = boundary(prepared, &mut self.poller, self.shutdown_policy)?;
        validate_prepared(
            &completed.prepared,
            &self.config,
            self.scenario.id(),
            request,
            self.definition_digest,
        )?;
        validate_terminal_qmp(&self.config, &completed.qmp_observation)?;
        match completed.shutdown {
            LiveObservationShutdown::NaturalExit { success: true } => {}
            LiveObservationShutdown::NaturalExit { success: false } => {
                return Err(LiveTerminalHorizonExecutorError::UnsuccessfulExit);
            }
            LiveObservationShutdown::ForcedByOwnerDrop => {
                return Err(LiveTerminalHorizonExecutorError::ForcedTeardown);
            }
        }

        let trace = File::open(completed.prepared.artifacts().trace()).map_err(|source| {
            LiveTerminalHorizonExecutorError::TraceIo {
                operation: "open terminal horizon trace",
                source,
            }
        })?;
        let importer = QemuTerminalHorizonTraceImport::new(
            self.scenario.id(),
            self.definition_digest,
            self.config.horizon_icount(),
            self.preflight.imported().observation().clone(),
            completed.prepared.process_argv_contract(),
        )?;
        let stream = importer.import(BufReader::new(trace))?;
        validate_one_sample_stream(&stream, self.config.horizon_icount())?;
        Ok(LiveTerminalHorizonReport {
            stream,
            prepared: completed.prepared,
            qmp_observation: completed.qmp_observation,
            shutdown: completed.shutdown,
        })
    }

    fn validate_request(
        &self,
        request: &SingleVmFingerprintRunRequest,
    ) -> Result<(), LiveTerminalHorizonExecutorError> {
        if request.scenario() != &self.scenario {
            return Err(LiveTerminalHorizonExecutorError::RequestMismatch {
                field: "fixed scenario",
            });
        }
        Ok(())
    }

    fn allocate_attempt(
        &mut self,
    ) -> Result<LiveRunnerArtifacts, LiveTerminalHorizonExecutorError> {
        let attempt = u32::try_from(self.next_attempt)
            .map_err(|_| LiveTerminalHorizonExecutorError::AttemptSequenceExhausted)?;
        self.next_attempt += 1;
        self.artifact_root
            .create_attempt(attempt)
            .map_err(LiveTerminalHorizonExecutorError::Artifacts)
    }
}

fn wait_for_terminal_publication<C, S>(
    poller: &mut LiveRunnerQmpPoller<C, S>,
    trace: &std::path::Path,
    importer: &QemuTerminalHorizonTraceImport,
) -> Result<(), LiveTerminalHorizonExecutorError>
where
    C: LiveRunnerQmpConnector,
    S: LiveRunnerSleeper,
{
    let published = poller.poll_publication(|| {
        let bytes = match fs::read(trace) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(LiveTerminalHorizonExecutorError::TraceIo {
                    operation: "read terminal horizon publication",
                    source,
                });
            }
        };
        importer
            .complete_trace_is_published(&bytes)
            .map(|complete| complete.then_some(()))
            .map_err(LiveTerminalHorizonExecutorError::Trace)
    })?;
    published.ok_or(LiveTerminalHorizonExecutorError::PublicationExhausted)
}

#[derive(Debug)]
struct CompletedTerminalAttempt {
    prepared: LivePreparedLaunch,
    qmp_observation: LiveRunnerQmpObservation,
    shutdown: LiveObservationShutdown,
}

fn validate_live_preflight(
    config: &LiveRunnerConfig,
    evidence: &LiveDefinitionPreflightEvidence,
    expected_node: &str,
) -> Result<(), LiveTerminalHorizonExecutorError> {
    let prepared = evidence.prepared_launch();
    if prepared.kind() != LiveRunnerLaunchKind::DefinitionPreflight {
        return Err(LiveTerminalHorizonExecutorError::PreflightMismatch {
            field: "launch kind",
        });
    }
    let fields = prepared.control().fields();
    if fields.mode != LiveObservationMode::DefinitionPreflight
        || fields.node != expected_node
        || fields.attempt != prepared.artifacts().attempt()
        || fields.definition_digest.is_some()
        || fields.base_launch_digest != config.base_launch_digest()
        || fields.fixed_run_digest != config.fixed_run_digest()
        || fields.horizon_icount != config.horizon_icount()
        || fields.actual_argv_digest != prepared.argv_identity().digest()
    {
        return Err(LiveTerminalHorizonExecutorError::PreflightMismatch {
            field: "definition-preflight control identity",
        });
    }
    validate_invocation(prepared).map_err(|_| {
        LiveTerminalHorizonExecutorError::PreflightMismatch {
            field: "definition-preflight process invocation",
        }
    })?;
    let qmp = evidence.qmp_observation();
    if qmp.run_state.running
        || qmp.run_state.status != crate::QmpRunStateKind::Prelaunch
        || qmp.cpu_indexes != expected_cpu_ids(config)
    {
        return Err(LiveTerminalHorizonExecutorError::PreflightMismatch {
            field: "typed QMP prelaunch evidence",
        });
    }
    if evidence.shutdown() != (LiveObservationShutdown::NaturalExit { success: true }) {
        return Err(LiveTerminalHorizonExecutorError::PreflightMismatch {
            field: "natural successful exit",
        });
    }
    let observation = evidence.imported().observation();
    if observation.qmp_cpu_ids() != qmp.cpu_indexes
        || observation.rr_switch_quantum() != config.rr_switch_quantum()
        || observation.identity().launch_definition_digest()
            != lower_hex(&config.verified_run_inputs().launch_definition_digest())
        || observation.identity().qemu_build_digest() != lower_hex(&config.qemu_build_digest())
        || observation.identity().trace_plugin_build_digest()
            != lower_hex(&config.trace_plugin_build_digest())
    {
        return Err(LiveTerminalHorizonExecutorError::PreflightMismatch {
            field: "imported definition trace",
        });
    }
    Ok(())
}

fn validate_scenario(
    config: &LiveRunnerConfig,
    scenario: &SingleVmFingerprintScenario,
    definition_digest: [u8; 32],
) -> Result<(), LiveTerminalHorizonExecutorError> {
    if scenario.run_horizon_icount() != config.horizon_icount() {
        return Err(LiveTerminalHorizonExecutorError::RequestMismatch {
            field: "run horizon",
        });
    }
    if scenario.fingerprint_definition_digest() != definition_digest {
        return Err(LiveTerminalHorizonExecutorError::RequestMismatch {
            field: "fingerprint definition digest",
        });
    }
    let run_inputs = config.verified_run_inputs().to_run_inputs().map_err(|_| {
        LiveTerminalHorizonExecutorError::InvalidContract {
            reason: "verified live run inputs could not be re-derived",
        }
    })?;
    if scenario.run_inputs() != &run_inputs {
        return Err(LiveTerminalHorizonExecutorError::RequestMismatch {
            field: "run inputs",
        });
    }
    if scenario.expected_vcpu_count() != usize::from(config.vcpus()) {
        return Err(LiveTerminalHorizonExecutorError::RequestMismatch {
            field: "vCPU count",
        });
    }
    if scenario.expected_rr_switch_quantum() != config.rr_switch_quantum() {
        return Err(LiveTerminalHorizonExecutorError::RequestMismatch {
            field: "RR switch quantum",
        });
    }
    Ok(())
}

fn validate_prepared(
    prepared: &LivePreparedLaunch,
    config: &LiveRunnerConfig,
    node: &str,
    request: &SingleVmFingerprintRunRequest,
    definition_digest: [u8; 32],
) -> Result<(), LiveTerminalHorizonExecutorError> {
    if prepared.kind() != LiveRunnerLaunchKind::Observation {
        return Err(LiveTerminalHorizonExecutorError::PreparedIdentityDrift {
            field: "launch kind",
        });
    }
    let fields = prepared.control().fields();
    let expected_mode = LiveObservationMode::ObservationHorizon {
        cadence_icount: config.cadence_icount(),
        ordinal: request.ordinal(),
    };
    if fields.mode != expected_mode
        || fields.node != node
        || fields.attempt != prepared.artifacts().attempt()
        || fields.definition_digest != Some(definition_digest)
        || fields.base_launch_digest != config.base_launch_digest()
        || fields.fixed_run_digest != config.fixed_run_digest()
        || fields.horizon_icount != config.horizon_icount()
        || fields.actual_argv_digest != prepared.argv_identity().digest()
    {
        return Err(LiveTerminalHorizonExecutorError::PreparedIdentityDrift {
            field: "observation control",
        });
    }
    validate_invocation(prepared)
}

fn validate_invocation(
    prepared: &LivePreparedLaunch,
) -> Result<(), LiveTerminalHorizonExecutorError> {
    if prepared.spec().executable().as_os_str() != prepared.argv_identity().argv0()
        || prepared.spec().argv() != prepared.argv_identity().argv()
        || prepared.invocation().argv_digest() != prepared.argv_identity().digest()
        || prepared.invocation().paths().cwd != prepared.artifacts().directory()
        || prepared.invocation().paths().qmp_socket != prepared.artifacts().qmp_socket()
        || prepared.invocation().paths().stdout != prepared.artifacts().stdout_log()
        || prepared.invocation().paths().stderr != prepared.artifacts().stderr_log()
        || !prepared.invocation().stdin_is_null()
        || !prepared.invocation().environment_is_cleared()
    {
        return Err(LiveTerminalHorizonExecutorError::PreparedIdentityDrift {
            field: "process invocation",
        });
    }
    let process_argv = prepared.process_argv_contract();
    if process_argv.argc() != prepared.argv_identity().argc()
        || process_argv.raw_bytes() != prepared.argv_identity().raw_byte_count()
        || process_argv.digest() != prepared.argv_identity().digest()
    {
        return Err(LiveTerminalHorizonExecutorError::PreparedIdentityDrift {
            field: "process argv attestation",
        });
    }
    Ok(())
}

fn validate_terminal_qmp(
    config: &LiveRunnerConfig,
    observation: &LiveRunnerQmpObservation,
) -> Result<(), LiveTerminalHorizonExecutorError> {
    if observation.run_state.running
        || observation.run_state.status != crate::QmpRunStateKind::Paused
    {
        return Err(LiveTerminalHorizonExecutorError::PreparedIdentityDrift {
            field: "typed QMP non-running paused state",
        });
    }
    if observation.cpu_indexes != expected_cpu_ids(config) {
        return Err(LiveTerminalHorizonExecutorError::PreparedIdentityDrift {
            field: "typed QMP vCPU topology",
        });
    }
    Ok(())
}

fn validate_one_sample_stream(
    stream: &SingleVmFingerprintStream,
    horizon: u64,
) -> Result<(), LiveTerminalHorizonExecutorError> {
    if stream.samples.len() != 1
        || stream.samples.first().map(|sample| sample.icount) != Some(horizon)
        || stream.final_icount != horizon
    {
        return Err(LiveTerminalHorizonExecutorError::InvalidTerminalStream);
    }
    Ok(())
}

fn expected_cpu_ids(config: &LiveRunnerConfig) -> Vec<u64> {
    (0..u64::from(config.vcpus())).collect()
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Failure while validating or executing a terminal horizon observation.
#[derive(Debug, Error)]
pub enum LiveTerminalHorizonExecutorError {
    /// Executor construction received an invalid fixed contract.
    #[error("invalid live terminal horizon executor contract: {reason}")]
    InvalidContract {
        /// Rejected contract detail.
        reason: &'static str,
    },
    /// Periodic cadence would require observations before the terminal horizon.
    #[error(
        "live terminal horizon executor requires cadence equal to horizon; got cadence {cadence}, horizon {horizon}"
    )]
    CadenceBeforeHorizon {
        /// Rejected cadence.
        cadence: u64,
        /// Configured horizon.
        horizon: u64,
    },
    /// Preflight evidence did not describe the configured launch.
    #[error("live terminal horizon preflight mismatched {field}")]
    PreflightMismatch {
        /// Mismatching evidence field.
        field: &'static str,
    },
    /// Scenario or request material differed from the executor contract.
    #[error("live terminal horizon request mismatched {field}")]
    RequestMismatch {
        /// Mismatching request field.
        field: &'static str,
    },
    /// Prepared identity material changed across the process boundary.
    #[error("live terminal horizon prepared launch drifted in {field}")]
    PreparedIdentityDrift {
        /// Identity boundary that drifted.
        field: &'static str,
    },
    /// Strict import returned something other than one terminal sample.
    #[error("live terminal horizon trace did not contain exactly one horizon sample")]
    InvalidTerminalStream,
    /// The bounded post-pause publication barrier expired.
    #[error("live terminal horizon state publication did not complete before the bounded deadline")]
    PublicationExhausted,
    /// No fresh attempt number remains representable.
    #[error("live terminal horizon attempt sequence exhausted u32")]
    AttemptSequenceExhausted,
    /// QEMU returned a nonzero status after typed quit.
    #[error("live terminal horizon QEMU exited unsuccessfully after typed quit")]
    UnsuccessfulExit,
    /// QEMU did not exit naturally within the bounded shutdown policy.
    #[error("live terminal horizon QEMU required owner-forced teardown")]
    ForcedTeardown,
    /// Fresh artifact allocation failed.
    #[error("live terminal horizon artifact allocation failed: {0}")]
    Artifacts(#[from] LiveRunnerArtifactsError),
    /// Launch preparation failed.
    #[error("live terminal horizon launch preparation failed: {0}")]
    Preparation(#[from] LivePreparationError),
    /// Process spawning, QMP observation, or shutdown failed.
    #[error("live terminal horizon process boundary failed: {0}")]
    Process(#[from] LiveObservationProcessError),
    /// Terminal trace opening failed.
    #[error("{operation} failed: {source}")]
    TraceIo {
        /// File operation being attempted.
        operation: &'static str,
        /// Underlying I/O failure.
        source: io::Error,
    },
    /// Definition or terminal trace content failed strict import.
    #[error("live terminal horizon trace import failed: {0}")]
    Trace(#[from] QemuTraceFingerprintImportError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::*;
    use crate::{
        DiskImageMode, GuestBackingStateMode, IcountShiftSetting, LaunchProfileCandidate,
        LiveRunnerImmutableInputs, LiveRunnerLaunchFields, LiveRunnerQmpPollError,
        LiveRunnerQmpPollPolicy, LiveRunnerQmpSession, QEMU_TRACE_FINGERPRINT_SCHEMA,
        QmpCpuTopology, QmpRunState, QmpRunStateKind, SingleVmFingerprintRunOrdinal,
        SingleVmHostProfile, SingleVmNvcpuFingerprintContract,
    };

    #[derive(Debug)]
    struct FakeSession {
        topology: Option<QmpCpuTopology>,
        quit_observed: Arc<AtomicBool>,
    }

    impl LiveRunnerQmpSession for FakeSession {
        fn query_status(&mut self) -> Result<QmpRunState, LiveRunnerQmpPollError> {
            Ok(QmpRunState {
                running: false,
                status: QmpRunStateKind::Paused,
            })
        }

        fn query_topology(&mut self) -> Result<QmpCpuTopology, LiveRunnerQmpPollError> {
            self.topology
                .take()
                .ok_or_else(|| LiveRunnerQmpPollError::Qmp {
                    operation: "query fake topology",
                    detail: "topology was already consumed".to_owned(),
                })
        }

        fn quit(&mut self) -> Result<(), LiveRunnerQmpPollError> {
            self.quit_observed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FakeConnector {
        vcpus: usize,
        quit_observed: Arc<AtomicBool>,
    }

    impl LiveRunnerQmpConnector for FakeConnector {
        type Session = FakeSession;

        fn connect(&mut self, _socket: &Path) -> Result<Self::Session, LiveRunnerQmpPollError> {
            Ok(FakeSession {
                topology: Some(QmpCpuTopology::from_test_cpu_indexes(
                    (0..self.vcpus as u64).collect(),
                )),
                quit_observed: Arc::clone(&self.quit_observed),
            })
        }
    }

    #[derive(Debug, Default)]
    struct NoSleep;

    impl LiveRunnerSleeper for NoSleep {
        fn sleep(&mut self, _duration: Duration) {}
    }

    fn config(cadence: u64, horizon: u64) -> Result<LiveRunnerConfig, Box<dyn Error>> {
        let profile = LaunchProfileCandidate::default()
            .with_memory_mib(128)
            .with_smp_vcpus(2)
            .with_rr_switch_quantum(8)
            .with_icount_shift(IcountShiftSetting::Fixed(0))
            .with_disk_image_mode(DiskImageMode::NoBlockDevice)
            .with_guest_backing_state(GuestBackingStateMode::NoBlockDevice)
            .try_into_deterministic()?;
        Ok(LiveRunnerConfig::from_verified_test_inputs(
            LiveRunnerImmutableInputs {
                qemu: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-qemu/bin/qemu-system-x86_64"
                    .into(),
                firmware: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-firmware/bios.bin".into(),
                kernel: "/nix/store/cccccccccccccccccccccccccccccccc-kernel/bzImage".into(),
                initrd: "/nix/store/dddddddddddddddddddddddddddddddd-initrd/initrd".into(),
                seed_file: "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-seed/seed.bin".into(),
                trace_plugin: "/nix/store/ffffffffffffffffffffffffffffffff-plugin/lib/plugin.so"
                    .into(),
            },
            profile,
            LiveRunnerLaunchFields {
                cadence_icount: cadence,
                horizon_icount: horizon,
            },
        )?)
    }

    fn artifact_root(label: &str) -> Result<(LiveRunnerArtifactRoot, PathBuf), Box<dyn Error>> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(1);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "crucible-terminal-horizon-{label}-{}-{sequence}",
            std::process::id()
        ));
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        Ok((LiveRunnerArtifactRoot::new(&path)?, path))
    }

    fn prepared_preflight(
        config: &LiveRunnerConfig,
        label: &str,
    ) -> Result<(PathBuf, LivePreparedLaunch), Box<dyn Error>> {
        let (root, root_path) = artifact_root(label)?;
        let artifacts = root.create_attempt(1)?;
        let prepared = LivePreparedLaunch::new(
            config,
            LiveRunnerLaunchKind::DefinitionPreflight,
            &artifacts,
            LivePreparationRequest {
                node: "node-a".to_owned(),
                mode: LiveObservationMode::DefinitionPreflight,
                definition_digest: None,
            },
        )?;
        Ok((root_path, prepared))
    }

    fn preflight_evidence(
        config: &LiveRunnerConfig,
        label: &str,
    ) -> Result<LiveDefinitionPreflightEvidence, Box<dyn Error>> {
        let (root_path, prepared) = prepared_preflight(config, label)?;
        let record = definition_record(config, prepared.process_argv_contract());
        std::fs::write(
            prepared.artifacts().preflight_trace(),
            serde_json::to_vec(&record)?,
        )?;
        let evidence = LiveDefinitionPreflightEvidence::import_completed_for_test(
            config,
            prepared,
            LiveRunnerQmpObservation {
                run_state: QmpRunState {
                    running: false,
                    status: QmpRunStateKind::Prelaunch,
                },
                cpu_indexes: expected_cpu_ids(config),
            },
            LiveObservationShutdown::NaturalExit { success: true },
        )?;
        std::fs::remove_dir_all(root_path)?;
        Ok(evidence)
    }

    fn definition_record(
        config: &LiveRunnerConfig,
        process_argv: QemuTraceProcessArgvContract,
    ) -> Value {
        let vcpus = usize::from(config.vcpus());
        json!({
            "kind": "definition",
            "schema": QEMU_TRACE_FINGERPRINT_SCHEMA,
            "definition_only": true,
            "observed_non_running": true,
            "device_state_complete": true,
            "retired": 0,
            "observed_icount": 0,
            "tracked_vcpus": vcpus,
            "rr_switch_quantum": config.rr_switch_quantum(),
            "rr_state_status": 0,
            "rr_current_vcpu_present": false,
            "rr_current_vcpu": 0,
            "rr_cursor_position": 0,
            "launch_definition_digest": lower_hex(
                &config.verified_run_inputs().launch_definition_digest()
            ),
            "qemu_build_digest": lower_hex(&config.qemu_build_digest()),
            "trace_plugin_build_digest": lower_hex(&config.trace_plugin_build_digest()),
            "process_argv_attestation_version": 2,
            "process_argv_encoding": "raw-unix-argv-v2",
            "process_argv_argc": process_argv.argc(),
            "process_argv_raw_bytes": process_argv.raw_bytes(),
            "process_argv_digest": lower_hex(&process_argv.digest()),
            "process_argv_status": 0,
            "register_counts": (0..vcpus).map(|_| 24).collect::<Vec<_>>(),
            "register_file_bytes": (0..vcpus).map(|_| 184).collect::<Vec<_>>(),
            "register_digests": (0..vcpus)
                .map(|vcpu| format!("{:02x}", vcpu + 3).repeat(32))
                .collect::<Vec<_>>(),
            "register_schema_digests": (0..vcpus)
                .map(|vcpu| format!("{:02x}", vcpu + 1).repeat(32))
                .collect::<Vec<_>>(),
            "ram_bytes": 128 * 1024 * 1024_u64,
            "ram_digest": "33".repeat(32),
            "ram_status": 0,
            "device_state_bytes": 4096,
            "device_state_digest": "43".repeat(32),
            "device_state_sections": 5,
            "device_state_schema_digest": "44".repeat(32),
            "device_state_status": 0,
            "device_state_schema_status": 0,
            "sample_register_failures": 0,
            "register_read_failures": 0,
            "device_state_failures": 0
        })
    }

    fn scenario(
        config: &LiveRunnerConfig,
        definition_digest: [u8; 32],
        node: &str,
    ) -> Result<SingleVmFingerprintScenario, Box<dyn Error>> {
        Ok(SingleVmFingerprintScenario::new_with_nvcpu_contract(
            node,
            definition_digest,
            config.horizon_icount(),
            SingleVmNvcpuFingerprintContract::new(
                usize::from(config.vcpus()),
                config.rr_switch_quantum(),
            )?,
            config.verified_run_inputs().to_run_inputs()?,
            SingleVmHostProfile::phase1_adversarial(),
        )?)
    }

    fn poller(
        config: &LiveRunnerConfig,
        quit_observed: Arc<AtomicBool>,
    ) -> Result<LiveRunnerQmpPoller<FakeConnector, NoSleep>, Box<dyn Error>> {
        Ok(LiveRunnerQmpPoller::new(
            FakeConnector {
                vcpus: usize::from(config.vcpus()),
                quit_observed,
            },
            NoSleep,
            LiveRunnerQmpPollPolicy {
                connect_attempts: 1,
                status_attempts: 1,
                interval: Duration::from_millis(1),
            },
        )?)
    }

    fn executor(
        config: LiveRunnerConfig,
        root: LiveRunnerArtifactRoot,
        quit_observed: Arc<AtomicBool>,
    ) -> Result<LiveTerminalHorizonExecutor<FakeConnector, NoSleep>, Box<dyn Error>> {
        let preflight = preflight_evidence(&config, "executor-preflight")?;
        let definition_digest = QemuTraceFingerprintDefinition::new(
            config.cadence_icount(),
            preflight.imported().observation(),
        )?
        .definition_digest();
        let expected_scenario = scenario(&config, definition_digest, "node-a")?;
        let poller = poller(&config, quit_observed)?;
        Ok(LiveTerminalHorizonExecutor::new(
            config,
            root,
            poller,
            LiveObservationShutdownPolicy {
                poll_attempts: 1,
                interval: Duration::from_millis(1),
            },
            preflight,
            expected_scenario,
        )?)
    }

    fn terminal_trace(
        config: &LiveRunnerConfig,
        process_argv: QemuTraceProcessArgvContract,
    ) -> Vec<Value> {
        let horizon = config.horizon_icount();
        let vcpus = usize::from(config.vcpus());
        let base = horizon / vcpus as u64;
        let remainder = horizon % vcpus as u64;
        let register_retired = (0..vcpus)
            .map(|vcpu| base + u64::from((vcpu as u64) < remainder))
            .collect::<Vec<_>>();
        let common = json!({
            "schema": QEMU_TRACE_FINGERPRINT_SCHEMA,
            "launch_definition_digest": lower_hex(
                &config.verified_run_inputs().launch_definition_digest()
            ),
            "qemu_build_digest": lower_hex(&config.qemu_build_digest()),
            "trace_plugin_build_digest": lower_hex(&config.trace_plugin_build_digest()),
            "process_argv_attestation_version": 2,
            "process_argv_encoding": "raw-unix-argv-v2",
            "process_argv_argc": process_argv.argc(),
            "process_argv_raw_bytes": process_argv.raw_bytes(),
            "process_argv_digest": lower_hex(&process_argv.digest()),
            "process_argv_status": 0
        });
        let mut sample = common.clone();
        sample["kind"] = json!("terminal_horizon");
        sample["terminal_state_schema"] = json!("crucible.qemu.terminal-horizon.v1");
        sample["retired"] = json!(horizon);
        sample["observed_icount"] = json!(horizon);
        sample["vcpu"] = json!(0);
        sample["final"] = json!(false);
        sample["tracked_vcpus"] = json!(vcpus);
        sample["stop_at"] = json!(horizon);
        sample["stop_requested"] = json!(true);
        sample["trigger"] = json!("event");
        sample["event_boundary"] = json!("horizon-advance");
        sample["observed_non_running"] = json!(true);
        sample["terminal_pause_status"] = json!(0);
        sample["terminal_capture_status"] = json!(0);
        sample["terminal_state_complete"] = json!(true);
        sample["terminal_vmstate_export"] = json!(true);
        sample["rr_current_vcpu"] = json!(0);
        sample["rr_cursor_position"] = json!(0);
        sample["rr_switch_quantum"] = json!(config.rr_switch_quantum());
        sample["rr_cursor_valid"] = json!(true);
        sample["rr_cursor_source"] = json!("terminal_paused_boundary");
        sample["stream_hash"] = json!(format!("{horizon:016x}"));
        sample["register_digests"] = json!(
            (0..vcpus)
                .map(|vcpu| format!("{:02x}", vcpu + 0x21).repeat(32))
                .collect::<Vec<_>>()
        );
        sample["register_counts"] = json!((0..vcpus).map(|_| 24).collect::<Vec<_>>());
        sample["register_file_bytes"] = json!((0..vcpus).map(|_| 184).collect::<Vec<_>>());
        sample["register_schema_digests"] = json!(
            (0..vcpus)
                .map(|vcpu| format!("{:02x}", vcpu + 1).repeat(32))
                .collect::<Vec<_>>()
        );
        sample["register_retired"] = json!(register_retired);
        sample["raw_ram_digest"] = json!("61".repeat(32));
        sample["raw_ram_region_map_digest"] = json!("63".repeat(32));
        sample["raw_ram_regions"] = json!(1);
        sample["raw_ram_bytes"] = json!(128 * 1024 * 1024_u64);
        sample["raw_ram_status"] = json!(0);
        sample["vmstate_digest"] = json!("62".repeat(32));
        sample["vmstate_bytes"] = json!(4096);
        sample["vmstate_status"] = json!(0);
        sample["memory_event_hash"] = json!(format!("{:016x}", horizon + 4));
        sample["device_event_hash"] = json!(format!("{:016x}", horizon + 5));
        sample["memory_events"] = json!(horizon);
        sample["io_events"] = json!(horizon / 2);
        sample["memory_events_enabled"] = json!(true);
        sample["sample_register_failures"] = json!(0);
        sample["register_read_failures"] = json!(0);
        sample["trajectory_digest_failures"] = json!(0);

        let mut terminal = common;
        terminal["kind"] = json!("terminal_final");
        terminal["terminal_state_schema"] = json!("crucible.qemu.terminal-horizon.v1");
        terminal["retired"] = json!(horizon);
        terminal["observed_icount"] = json!(horizon);
        terminal["final"] = json!(true);
        terminal["stop_at"] = json!(horizon);
        terminal["stop_requested"] = json!(true);
        terminal["terminal_pause_requested"] = json!(true);
        terminal["terminal_pause_status"] = json!(0);
        terminal["terminal_callback_completed"] = json!(true);
        terminal["terminal_state_emitted"] = json!(true);
        terminal["terminal_state_complete"] = json!(true);
        vec![sample, terminal]
    }

    fn write_terminal_trace(
        config: &LiveRunnerConfig,
        prepared: &LivePreparedLaunch,
    ) -> Result<(), LiveTerminalHorizonExecutorError> {
        let encoded = terminal_trace(config, prepared.process_argv_contract())
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(prepared.artifacts().trace(), format!("{encoded}\n")).map_err(|source| {
            LiveTerminalHorizonExecutorError::TraceIo {
                operation: "write fake terminal trace",
                source,
            }
        })
    }

    fn encoded_trace(values: &[Value]) -> String {
        let mut encoded = values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        encoded.push('\n');
        encoded
    }

    fn prepared_importer(
        config: &LiveRunnerConfig,
        executor: &mut LiveTerminalHorizonExecutor<FakeConnector, NoSleep>,
    ) -> Result<(LivePreparedLaunch, QemuTerminalHorizonTraceImport), Box<dyn Error>> {
        let artifacts = executor.allocate_attempt()?;
        let prepared = LivePreparedLaunch::new(
            config,
            LiveRunnerLaunchKind::Observation,
            &artifacts,
            LivePreparationRequest {
                node: "node-a".to_owned(),
                mode: LiveObservationMode::ObservationHorizon {
                    cadence_icount: config.cadence_icount(),
                    ordinal: SingleVmFingerprintRunOrdinal::First,
                },
                definition_digest: Some(executor.definition_digest()),
            },
        )?;
        let importer = QemuTerminalHorizonTraceImport::new(
            "node-a",
            executor.definition_digest(),
            config.horizon_icount(),
            executor.preflight.imported().observation().clone(),
            prepared.process_argv_contract(),
        )?;
        Ok((prepared, importer))
    }

    fn completed(
        config: &LiveRunnerConfig,
        prepared: LivePreparedLaunch,
        poller: &mut LiveRunnerQmpPoller<FakeConnector, NoSleep>,
    ) -> Result<CompletedTerminalAttempt, LiveTerminalHorizonExecutorError> {
        let retained = prepared.clone();
        let mut connection = poller
            .observe_stopped(
                prepared.artifacts().qmp_socket(),
                prepared.expected_vcpus(),
                QmpRunStateKind::Paused,
            )
            .map_err(LiveObservationProcessError::Qmp)?;
        connection
            .session
            .quit()
            .map_err(LiveObservationProcessError::Qmp)?;
        write_terminal_trace(config, &prepared)?;
        Ok(CompletedTerminalAttempt {
            prepared: retained,
            qmp_observation: connection.observation,
            shutdown: LiveObservationShutdown::NaturalExit { success: true },
        })
    }

    #[test]
    fn fresh_ordinals_import_exactly_one_terminal_sample() -> Result<(), Box<dyn Error>> {
        let config = config(100, 100)?;
        let (root, root_path) = artifact_root("success")?;
        let quit_observed = Arc::new(AtomicBool::new(false));
        let mut executor = executor(config.clone(), root, Arc::clone(&quit_observed))?;
        let expected_scenario = scenario(&config, executor.definition_digest(), "node-a")?;

        for (attempt, ordinal) in [
            (1, SingleVmFingerprintRunOrdinal::First),
            (2, SingleVmFingerprintRunOrdinal::Second),
        ] {
            quit_observed.store(false, Ordering::SeqCst);
            let request = SingleVmFingerprintRunRequest::new(expected_scenario.clone(), ordinal);
            let report = executor.run_report_with_boundary(&request, |prepared, poller, _| {
                completed(&config, prepared, poller)
            })?;
            assert_eq!(report.attempt(), attempt);
            assert_eq!(report.stream().samples.len(), 1);
            assert_eq!(report.stream().samples[0].icount, config.horizon_icount());
            assert_eq!(report.stream().final_icount, config.horizon_icount());
            assert_eq!(report.control().fields().mode.ordinal(), Some(ordinal));
            assert_eq!(
                report.invocation().argv_digest(),
                report.argv_identity().digest()
            );
            assert_eq!(
                report.process_argv_contract().digest(),
                report.argv_identity().digest()
            );
            assert_eq!(
                report.qmp_observation().run_state,
                QmpRunState {
                    running: false,
                    status: QmpRunStateKind::Paused,
                }
            );
            assert_eq!(
                report.shutdown(),
                LiveObservationShutdown::NaturalExit { success: true }
            );
            assert!(quit_observed.load(Ordering::SeqCst));
        }
        assert!(root_path.join("attempt-00000001").is_dir());
        assert!(root_path.join("attempt-00000002").is_dir());
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }

    #[test]
    fn cadence_before_horizon_is_rejected_before_any_attempt() -> Result<(), Box<dyn Error>> {
        let config = config(100, 1_000)?;
        let preflight = preflight_evidence(&config, "cadence-preflight")?;
        let definition_digest = QemuTraceFingerprintDefinition::new(
            config.cadence_icount(),
            preflight.imported().observation(),
        )?
        .definition_digest();
        let expected_scenario = scenario(&config, definition_digest, "node-a")?;
        let (root, root_path) = artifact_root("cadence-rejected")?;
        let result = LiveTerminalHorizonExecutor::new(
            config.clone(),
            root,
            poller(&config, Arc::new(AtomicBool::new(false)))?,
            LiveObservationShutdownPolicy::default(),
            preflight,
            expected_scenario,
        );
        assert!(matches!(
            result,
            Err(LiveTerminalHorizonExecutorError::CadenceBeforeHorizon {
                cadence: 100,
                horizon: 1_000
            })
        ));
        assert!(!root_path.join("attempt-00000001").exists());
        if root_path.exists() {
            std::fs::remove_dir_all(root_path)?;
        }
        Ok(())
    }

    #[test]
    fn request_drift_is_rejected_before_attempt_allocation() -> Result<(), Box<dyn Error>> {
        let config = config(100, 100)?;
        let (root, root_path) = artifact_root("request-drift")?;
        let mut executor = executor(config.clone(), root, Arc::new(AtomicBool::new(false)))?;
        let drifted = scenario(&config, executor.definition_digest(), "node-b")?;
        let request =
            SingleVmFingerprintRunRequest::new(drifted, SingleVmFingerprintRunOrdinal::First);
        assert!(matches!(
            executor.run_report_with_boundary(&request, |_, _, _| unreachable!()),
            Err(LiveTerminalHorizonExecutorError::RequestMismatch {
                field: "fixed scenario"
            })
        ));
        assert!(!root_path.join("attempt-00000001").exists());
        if root_path.exists() {
            std::fs::remove_dir_all(root_path)?;
        }
        Ok(())
    }

    #[test]
    fn qmp_and_shutdown_evidence_fail_closed() -> Result<(), Box<dyn Error>> {
        let config = config(100, 100)?;
        let (root, root_path) = artifact_root("boundary-failures")?;
        let mut executor = executor(config.clone(), root, Arc::new(AtomicBool::new(false)))?;
        let expected_scenario = scenario(&config, executor.definition_digest(), "node-a")?;
        let request = SingleVmFingerprintRunRequest::new(
            expected_scenario,
            SingleVmFingerprintRunOrdinal::First,
        );
        let wrong_state = executor.run_report_with_boundary(&request, |prepared, _, _| {
            Ok(CompletedTerminalAttempt {
                prepared,
                qmp_observation: LiveRunnerQmpObservation {
                    run_state: QmpRunState {
                        running: false,
                        status: QmpRunStateKind::Prelaunch,
                    },
                    cpu_indexes: expected_cpu_ids(&config),
                },
                shutdown: LiveObservationShutdown::NaturalExit { success: true },
            })
        });
        assert!(matches!(
            wrong_state,
            Err(LiveTerminalHorizonExecutorError::PreparedIdentityDrift {
                field: "typed QMP non-running paused state"
            })
        ));

        let forced = executor.run_report_with_boundary(&request, |prepared, _, _| {
            Ok(CompletedTerminalAttempt {
                prepared,
                qmp_observation: LiveRunnerQmpObservation {
                    run_state: QmpRunState {
                        running: false,
                        status: QmpRunStateKind::Paused,
                    },
                    cpu_indexes: expected_cpu_ids(&config),
                },
                shutdown: LiveObservationShutdown::ForcedByOwnerDrop,
            })
        });
        assert!(matches!(
            forced,
            Err(LiveTerminalHorizonExecutorError::ForcedTeardown)
        ));
        assert!(root_path.join("attempt-00000001").is_dir());
        assert!(root_path.join("attempt-00000002").is_dir());
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }

    #[test]
    fn attempt_collision_and_u32_exhaustion_fail_closed() -> Result<(), Box<dyn Error>> {
        let config = config(100, 100)?;
        let (root, root_path) = artifact_root("attempt-bounds")?;
        let mut executor = executor(config, root.clone(), Arc::new(AtomicBool::new(false)))?;
        root.create_attempt(1)?;
        assert!(matches!(
            executor.allocate_attempt(),
            Err(LiveTerminalHorizonExecutorError::Artifacts(
                LiveRunnerArtifactsError::AttemptAlreadyExists { .. }
            ))
        ));
        executor.next_attempt = u64::from(u32::MAX);
        assert_eq!(executor.allocate_attempt()?.attempt(), u32::MAX);
        assert!(matches!(
            executor.allocate_attempt(),
            Err(LiveTerminalHorizonExecutorError::AttemptSequenceExhausted)
        ));
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }

    #[test]
    fn publication_requires_complete_final_and_rejects_duplicates() -> Result<(), Box<dyn Error>> {
        let config = config(100, 100)?;
        let (root, root_path) = artifact_root("publication")?;
        let mut executor = executor(config.clone(), root, Arc::new(AtomicBool::new(false)))?;
        let (prepared, importer) = prepared_importer(&config, &mut executor)?;
        let values = terminal_trace(&config, prepared.process_argv_contract());

        std::fs::write(prepared.artifacts().trace(), [])?;
        assert!(matches!(
            wait_for_terminal_publication(
                &mut executor.poller,
                prepared.artifacts().trace(),
                &importer,
            ),
            Err(LiveTerminalHorizonExecutorError::PublicationExhausted)
        ));
        let state_only = encoded_trace(&values[..1]);
        assert!(!importer.complete_trace_is_published(state_only.as_bytes())?);
        let partial_final = format!("{}{{\"kind\":\"terminal_final\"", state_only);
        assert!(!importer.complete_trace_is_published(partial_final.as_bytes())?);
        assert!(importer.complete_trace_is_published(encoded_trace(&values).as_bytes())?);

        let duplicate = vec![values[0].clone(), values[0].clone(), values[1].clone()];
        assert!(
            importer
                .complete_trace_is_published(encoded_trace(&duplicate).as_bytes())
                .is_err()
        );
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }

    #[test]
    fn strict_terminal_import_rejects_partial_status_and_legacy_records()
    -> Result<(), Box<dyn Error>> {
        let config = config(100, 100)?;
        let (root, root_path) = artifact_root("strict-import")?;
        let mut executor = executor(config.clone(), root, Arc::new(AtomicBool::new(false)))?;
        let (prepared, importer) = prepared_importer(&config, &mut executor)?;
        let values = terminal_trace(&config, prepared.process_argv_contract());

        let complete = encoded_trace(&values);
        assert!(importer.import(complete.as_bytes()).is_ok());
        assert!(
            importer
                .import(complete.trim_end_matches('\n').as_bytes())
                .is_err()
        );

        let mut failed = values.clone();
        failed[0]["trajectory_digest_failures"] = json!(1);
        assert!(importer.import(encoded_trace(&failed).as_bytes()).is_err());

        let mut cached_cursor = values.clone();
        cached_cursor[0]["rr_cursor_source"] = json!("terminal_last_executed_instruction");
        assert!(
            importer
                .import(encoded_trace(&cached_cursor).as_bytes())
                .is_ok()
        );

        let mut wrong_cursor = values.clone();
        wrong_cursor[0]["rr_cursor_source"] = json!("guessed_after_pause");
        assert!(
            importer
                .import(encoded_trace(&wrong_cursor).as_bytes())
                .is_err()
        );

        let mut legacy = values.clone();
        legacy[0]["kind"] = json!("sample");
        assert!(importer.import(encoded_trace(&legacy).as_bytes()).is_err());

        let duplicate_field = complete.replacen('{', "{\"kind\":\"terminal_horizon\",", 1);
        assert!(importer.import(duplicate_field.as_bytes()).is_err());

        let mut unexpected = values;
        unexpected[0]["unreviewed_extension"] = json!(true);
        assert!(
            importer
                .import(encoded_trace(&unexpected).as_bytes())
                .is_err()
        );
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }

    #[test]
    fn raw_ram_region_map_drift_changes_canonical_stream() -> Result<(), Box<dyn Error>> {
        let config = config(100, 100)?;
        let (root, root_path) = artifact_root("ram-map")?;
        let mut executor = executor(config.clone(), root, Arc::new(AtomicBool::new(false)))?;
        let (prepared, importer) = prepared_importer(&config, &mut executor)?;
        let first = terminal_trace(&config, prepared.process_argv_contract());
        let mut second = first.clone();
        second[0]["raw_ram_region_map_digest"] = json!("64".repeat(32));
        let first_stream = importer.import(encoded_trace(&first).as_bytes())?;
        let second_stream = importer.import(encoded_trace(&second).as_bytes())?;
        assert_ne!(
            first_stream.final_fingerprint,
            second_stream.final_fingerprint
        );
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }
}
