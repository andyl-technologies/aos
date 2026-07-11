//! Production execution of fresh, instruction-free genesis probes.
//!
//! [`LiveGenesisProbeExecutor`] deliberately admits only target zero. Each
//! request receives a new artifact directory and a newly spawned QEMU process,
//! which must reach typed QMP `prelaunch`, report the exact pinned topology,
//! accept typed `quit`, and exit successfully without owner-forced teardown.
//! The resulting one-record trace is imported against the independent
//! definition preflight. Nonzero exact probes and state dumps remain separate
//! capabilities.

use std::fs::File;
use std::io::{self, BufReader};

use thiserror::Error;

use crate::single_vm_fingerprint::{
    QemuTraceDefinitionPreflight, QemuTraceFingerprintDefinition, QemuTraceFingerprintImportError,
    QemuTraceGenesisFingerprintImport, QemuTraceProcessArgvContract,
    SingleVmFingerprintBisectionError, SingleVmFingerprintProbe, SingleVmFingerprintProbeRequest,
    SingleVmFingerprintScenario,
};

use super::{
    LiveInvocationIdentity, LiveObservationControl, LiveObservationMode,
    LiveObservationProcessError, LiveObservationShutdown, LiveObservationShutdownPolicy,
    LivePreparationError, LivePreparationRequest, LivePreparedLaunch, LiveRunnerArtifactRoot,
    LiveRunnerArtifacts, LiveRunnerArtifactsError, LiveRunnerConfig, LiveRunnerLaunchKind,
    LiveRunnerQmpConnector, LiveRunnerQmpObservation, LiveRunnerQmpPollError, LiveRunnerQmpPoller,
    LiveRunnerSleeper, RawUnixArgvIdentity, spawn_live_observation_process,
};

/// Verified evidence from a dedicated live definition-preflight process.
///
/// This value retains the exact prepared launch, accepted typed QMP boundary,
/// natural successful exit, and strictly imported definition trace. Its fields
/// are private, and the only public constructor executes a
/// [`LiveRunnerLaunchKind::DefinitionPreflight`] launch; a genesis observation
/// therefore cannot be substituted for independent preflight evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveDefinitionPreflightEvidence {
    prepared: LivePreparedLaunch,
    qmp_observation: LiveRunnerQmpObservation,
    shutdown: LiveObservationShutdown,
    imported: QemuTraceDefinitionPreflight,
}

impl LiveDefinitionPreflightEvidence {
    /// Executes and verifies one dedicated live definition preflight.
    ///
    /// The retained raw argv is spawned with an empty environment. The process
    /// must report typed QMP `prelaunch` with the configured topology, accept
    /// typed `quit`, exit naturally with success, and emit exactly one valid
    /// definition record through its definition-preflight trace path.
    ///
    /// # Errors
    ///
    /// Returns [`LiveDefinitionPreflightError`] when preparation, process
    /// supervision, typed QMP evidence, natural exit, trace import, or binding
    /// to `config` fails.
    pub fn execute<C, S>(
        config: &LiveRunnerConfig,
        artifacts: &LiveRunnerArtifacts,
        node: String,
        poller: &mut LiveRunnerQmpPoller<C, S>,
        shutdown_policy: LiveObservationShutdownPolicy,
    ) -> Result<Self, LiveDefinitionPreflightError>
    where
        C: LiveRunnerQmpConnector,
        S: LiveRunnerSleeper,
    {
        let shutdown_policy = shutdown_policy.validate()?;
        let prepared = LivePreparedLaunch::new(
            config,
            LiveRunnerLaunchKind::DefinitionPreflight,
            artifacts,
            LivePreparationRequest {
                node,
                mode: LiveObservationMode::DefinitionPreflight,
                definition_digest: None,
            },
        )?;
        validate_definition_prepared(config, &prepared)?;
        let retained = prepared.clone();
        let attempt = spawn_live_observation_process(prepared)?.observe(poller)?;
        let qmp_observation = attempt.observation().clone();
        let shutdown = attempt.shutdown(shutdown_policy)?;
        Self::import_completed(config, retained, qmp_observation, shutdown)
    }

    fn import_completed(
        config: &LiveRunnerConfig,
        prepared: LivePreparedLaunch,
        qmp_observation: LiveRunnerQmpObservation,
        shutdown: LiveObservationShutdown,
    ) -> Result<Self, LiveDefinitionPreflightError> {
        validate_definition_prepared(config, &prepared)?;
        validate_preflight_qmp(config, &qmp_observation)?;
        match shutdown {
            LiveObservationShutdown::NaturalExit { success: true } => {}
            LiveObservationShutdown::NaturalExit { success: false } => {
                return Err(LiveDefinitionPreflightError::UnsuccessfulExit);
            }
            LiveObservationShutdown::ForcedByOwnerDrop => {
                return Err(LiveDefinitionPreflightError::ForcedTeardown);
            }
        }
        let trace = File::open(prepared.artifacts().preflight_trace()).map_err(|source| {
            LiveDefinitionPreflightError::TraceIo {
                operation: "open definition preflight trace",
                source,
            }
        })?;
        let imported = QemuTraceDefinitionPreflight::import(
            BufReader::new(trace),
            prepared.process_argv_contract(),
        )?;
        validate_trace_preflight(config, &imported)
            .map_err(|field| LiveDefinitionPreflightError::PreflightMismatch { field })?;
        if imported.observation().qmp_cpu_ids() != qmp_observation.cpu_indexes {
            return Err(LiveDefinitionPreflightError::PreflightMismatch {
                field: "trace and typed QMP vCPU topology",
            });
        }
        Ok(Self {
            prepared,
            qmp_observation,
            shutdown,
            imported,
        })
    }

    #[cfg(test)]
    pub(super) fn import_completed_for_test(
        config: &LiveRunnerConfig,
        prepared: LivePreparedLaunch,
        qmp_observation: LiveRunnerQmpObservation,
        shutdown: LiveObservationShutdown,
    ) -> Result<Self, LiveDefinitionPreflightError> {
        Self::import_completed(config, prepared, qmp_observation, shutdown)
    }

    /// Returns the exact definition-preflight launch and all bound identities.
    #[must_use]
    pub const fn prepared_launch(&self) -> &LivePreparedLaunch {
        &self.prepared
    }

    /// Returns the accepted typed QMP prelaunch and topology observation.
    #[must_use]
    pub const fn qmp_observation(&self) -> &LiveRunnerQmpObservation {
        &self.qmp_observation
    }

    /// Returns the retained natural successful shutdown evidence.
    #[must_use]
    pub const fn shutdown(&self) -> LiveObservationShutdown {
        self.shutdown
    }

    /// Returns the strictly imported definition-only trace evidence.
    #[must_use]
    pub const fn imported(&self) -> &QemuTraceDefinitionPreflight {
        &self.imported
    }
}

/// Auditable result of one completed live genesis probe attempt.
///
/// The report retains the exact completed launch rather than reconstructing an
/// audit invocation. Its control, invocation, raw argv, typed QMP admission,
/// and natural-exit evidence therefore describe the same process whose trace
/// produced [`Self::probe`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveGenesisProbeReport {
    probe: SingleVmFingerprintProbe,
    prepared: LivePreparedLaunch,
    qmp_observation: LiveRunnerQmpObservation,
    shutdown: LiveObservationShutdown,
}

impl LiveGenesisProbeReport {
    /// Returns the imported target-zero fingerprint probe.
    #[must_use]
    pub const fn probe(&self) -> &SingleVmFingerprintProbe {
        &self.probe
    }

    /// Consumes the report and returns the imported target-zero probe.
    #[must_use]
    pub fn into_probe(self) -> SingleVmFingerprintProbe {
        self.probe
    }

    /// Returns the fresh attempt number bound into all retained identities.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.prepared.artifacts().attempt()
    }

    /// Returns the exact completed launch and all of its validated identities.
    #[must_use]
    pub const fn prepared_launch(&self) -> &LivePreparedLaunch {
        &self.prepared
    }

    /// Returns the validated observation-control identity.
    #[must_use]
    pub const fn control(&self) -> &LiveObservationControl {
        self.prepared.control()
    }

    /// Returns the validated host-visible process invocation identity.
    #[must_use]
    pub const fn invocation(&self) -> &LiveInvocationIdentity {
        self.prepared.invocation()
    }

    /// Returns the independently computed raw Unix argv identity.
    #[must_use]
    pub const fn argv_identity(&self) -> &RawUnixArgvIdentity {
        self.prepared.argv_identity()
    }

    /// Returns the contract validated against QEMU's raw argv self-attestation.
    #[must_use]
    pub const fn process_argv_contract(&self) -> QemuTraceProcessArgvContract {
        self.prepared.process_argv_contract()
    }

    /// Returns the accepted typed QMP non-running prelaunch and topology evidence.
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

/// Fresh-process executor for exact target-zero fingerprint probes.
#[derive(Debug)]
pub struct LiveGenesisProbeExecutor<C, S> {
    config: LiveRunnerConfig,
    artifact_root: LiveRunnerArtifactRoot,
    poller: LiveRunnerQmpPoller<C, S>,
    shutdown_policy: LiveObservationShutdownPolicy,
    preflight: LiveDefinitionPreflightEvidence,
    definition_digest: [u8; 32],
    scenario: SingleVmFingerprintScenario,
    next_attempt: u64,
}

impl<C, S> LiveGenesisProbeExecutor<C, S>
where
    C: LiveRunnerQmpConnector,
    S: LiveRunnerSleeper,
{
    /// Builds a genesis executor from verified launch and preflight contracts.
    ///
    /// The canonical definition digest is recomputed from `preflight` and the
    /// configuration cadence. Launch identity, topology, and RR quantum must
    /// agree before any process can be spawned.
    ///
    /// # Errors
    ///
    /// Returns [`LiveGenesisProbeExecutorError`] when shutdown bounds are
    /// invalid, the preflight or scenario does not match the verified launch,
    /// or the canonical fingerprint definition cannot be constructed.
    pub fn new(
        config: LiveRunnerConfig,
        artifact_root: LiveRunnerArtifactRoot,
        poller: LiveRunnerQmpPoller<C, S>,
        shutdown_policy: LiveObservationShutdownPolicy,
        preflight: LiveDefinitionPreflightEvidence,
        scenario: SingleVmFingerprintScenario,
    ) -> Result<Self, LiveGenesisProbeExecutorError> {
        let shutdown_policy = shutdown_policy.validate()?;
        validate_live_preflight_evidence(&config, &preflight, scenario.id())?;
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

    /// Executes one fresh target-zero probe and imports its actual machine state.
    ///
    /// This method never resumes the guest. It spawns the retained raw argv with
    /// an empty environment, requires QMP `prelaunch` and the exact topology,
    /// requests typed QMP quit, and admits only a natural successful exit.
    ///
    /// # Errors
    ///
    /// Returns [`LiveGenesisProbeExecutorError`] when the request differs from
    /// the verified scenario, attempt allocation or process supervision fails,
    /// QEMU requires forced teardown or exits unsuccessfully, or the genesis
    /// trace fails provenance and state validation.
    pub fn probe_genesis(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<SingleVmFingerprintProbe, LiveGenesisProbeExecutorError> {
        self.probe_genesis_report(request)
            .map(LiveGenesisProbeReport::into_probe)
    }

    /// Executes one fresh genesis probe and retains its completed attempt evidence.
    ///
    /// # Errors
    ///
    /// Returns [`LiveGenesisProbeExecutorError`] under the same fail-closed
    /// conditions as [`Self::probe_genesis`].
    pub fn probe_genesis_report(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<LiveGenesisProbeReport, LiveGenesisProbeExecutorError> {
        self.probe_report_with_boundary(request, |prepared, poller, shutdown_policy| {
            let retained = prepared.clone();
            let attempt = spawn_live_observation_process(prepared)?.observe(poller)?;
            let qmp_observation = attempt.observation().clone();
            let shutdown = attempt.shutdown(shutdown_policy)?;
            Ok(CompletedGenesisAttempt {
                prepared: retained,
                qmp_observation,
                shutdown,
            })
        })
    }

    #[cfg(test)]
    fn probe_with_boundary<F>(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
        boundary: F,
    ) -> Result<SingleVmFingerprintProbe, LiveGenesisProbeExecutorError>
    where
        F: FnOnce(
            LivePreparedLaunch,
            &mut LiveRunnerQmpPoller<C, S>,
            LiveObservationShutdownPolicy,
        ) -> Result<CompletedGenesisAttempt, LiveGenesisProbeExecutorError>,
    {
        self.probe_report_with_boundary(request, boundary)
            .map(LiveGenesisProbeReport::into_probe)
    }

    fn probe_report_with_boundary<F>(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
        boundary: F,
    ) -> Result<LiveGenesisProbeReport, LiveGenesisProbeExecutorError>
    where
        F: FnOnce(
            LivePreparedLaunch,
            &mut LiveRunnerQmpPoller<C, S>,
            LiveObservationShutdownPolicy,
        ) -> Result<CompletedGenesisAttempt, LiveGenesisProbeExecutorError>,
    {
        self.validate_request(request)?;
        let attempt = self.allocate_attempt()?;
        let prepared = LivePreparedLaunch::new(
            &self.config,
            LiveRunnerLaunchKind::Genesis,
            &attempt,
            LivePreparationRequest {
                node: self.scenario.id().to_owned(),
                mode: LiveObservationMode::ExactTarget {
                    cadence_icount: self.config.cadence_icount(),
                    target_icount: 0,
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
        validate_genesis_qmp(&self.config, &completed.qmp_observation)?;
        match completed.shutdown {
            LiveObservationShutdown::NaturalExit { success: true } => {}
            LiveObservationShutdown::NaturalExit { success: false } => {
                return Err(LiveGenesisProbeExecutorError::UnsuccessfulExit);
            }
            LiveObservationShutdown::ForcedByOwnerDrop => {
                return Err(LiveGenesisProbeExecutorError::ForcedTeardown);
            }
        }

        let trace = File::open(completed.prepared.artifacts().trace()).map_err(|source| {
            LiveGenesisProbeExecutorError::TraceIo {
                operation: "open genesis trace",
                source,
            }
        })?;
        let importer = QemuTraceGenesisFingerprintImport::new(
            self.preflight.imported().observation().clone(),
            completed.prepared.process_argv_contract(),
        );
        let prefix_fingerprint = importer.import(BufReader::new(trace))?;
        let probe = SingleVmFingerprintProbe::new(
            request.ordinal(),
            self.scenario.id(),
            0,
            self.definition_digest,
            self.config.fixed_run_digest(),
            prefix_fingerprint,
        )
        .map_err(LiveGenesisProbeExecutorError::Probe)?;
        Ok(LiveGenesisProbeReport {
            probe,
            prepared: completed.prepared,
            qmp_observation: completed.qmp_observation,
            shutdown: completed.shutdown,
        })
    }

    fn validate_request(
        &self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<(), LiveGenesisProbeExecutorError> {
        let scenario = request.scenario();
        if request.target_icount() != 0 {
            return Err(LiveGenesisProbeExecutorError::NonGenesisTarget {
                target: request.target_icount(),
            });
        }
        if scenario != &self.scenario {
            return Err(LiveGenesisProbeExecutorError::RequestMismatch {
                field: "fixed scenario",
            });
        }
        Ok(())
    }

    fn allocate_attempt(
        &mut self,
    ) -> Result<super::LiveRunnerArtifacts, LiveGenesisProbeExecutorError> {
        let attempt = u32::try_from(self.next_attempt)
            .map_err(|_| LiveGenesisProbeExecutorError::AttemptSequenceExhausted)?;
        self.next_attempt += 1;
        self.artifact_root
            .create_attempt(attempt)
            .map_err(LiveGenesisProbeExecutorError::Artifacts)
    }
}

fn validate_scenario(
    config: &LiveRunnerConfig,
    scenario: &SingleVmFingerprintScenario,
    definition_digest: [u8; 32],
) -> Result<(), LiveGenesisProbeExecutorError> {
    if scenario.run_horizon_icount() != config.horizon_icount() {
        return Err(LiveGenesisProbeExecutorError::RequestMismatch {
            field: "run horizon",
        });
    }
    if scenario.fingerprint_definition_digest() != definition_digest {
        return Err(LiveGenesisProbeExecutorError::RequestMismatch {
            field: "fingerprint definition digest",
        });
    }
    let verified_run_inputs = config.verified_run_inputs().to_run_inputs().map_err(|_| {
        LiveGenesisProbeExecutorError::InvalidContract {
            reason: "verified live run inputs could not be re-derived",
        }
    })?;
    if scenario.run_inputs() != &verified_run_inputs {
        return Err(LiveGenesisProbeExecutorError::RequestMismatch {
            field: "run inputs",
        });
    }
    if scenario.expected_vcpu_count() != usize::from(config.vcpus()) {
        return Err(LiveGenesisProbeExecutorError::RequestMismatch {
            field: "vCPU count",
        });
    }
    if scenario.expected_rr_switch_quantum() != config.rr_switch_quantum() {
        return Err(LiveGenesisProbeExecutorError::RequestMismatch {
            field: "RR switch quantum",
        });
    }
    Ok(())
}

#[derive(Debug)]
struct CompletedGenesisAttempt {
    prepared: LivePreparedLaunch,
    qmp_observation: LiveRunnerQmpObservation,
    shutdown: LiveObservationShutdown,
}

fn validate_trace_preflight(
    config: &LiveRunnerConfig,
    preflight: &QemuTraceDefinitionPreflight,
) -> Result<(), &'static str> {
    let observation = preflight.observation();
    let expected_cpu_ids = (0..u64::from(config.vcpus())).collect::<Vec<_>>();
    if observation.qmp_cpu_ids() != expected_cpu_ids {
        return Err("QMP vCPU topology");
    }
    if observation.rr_switch_quantum() != config.rr_switch_quantum() {
        return Err("RR switch quantum");
    }
    let identity = observation.identity();
    if identity.launch_definition_digest()
        != lower_hex(&config.verified_run_inputs().launch_definition_digest())
    {
        return Err("launch definition identity");
    }
    if identity.qemu_build_digest() != lower_hex(&config.qemu_build_digest()) {
        return Err("QEMU build identity");
    }
    if identity.trace_plugin_build_digest() != lower_hex(&config.trace_plugin_build_digest()) {
        return Err("trace plugin build identity");
    }
    Ok(())
}

fn validate_preflight_qmp(
    config: &LiveRunnerConfig,
    observation: &LiveRunnerQmpObservation,
) -> Result<(), LiveDefinitionPreflightError> {
    if observation.run_state.running
        || observation.run_state.status != crate::QmpRunStateKind::Prelaunch
    {
        return Err(LiveDefinitionPreflightError::PreflightMismatch {
            field: "typed QMP non-running prelaunch state",
        });
    }
    let expected_cpu_ids = (0..u64::from(config.vcpus())).collect::<Vec<_>>();
    if observation.cpu_indexes != expected_cpu_ids {
        return Err(LiveDefinitionPreflightError::PreflightMismatch {
            field: "typed QMP vCPU topology",
        });
    }
    Ok(())
}

fn validate_genesis_qmp(
    config: &LiveRunnerConfig,
    observation: &LiveRunnerQmpObservation,
) -> Result<(), LiveGenesisProbeExecutorError> {
    if observation.run_state.running
        || observation.run_state.status != crate::QmpRunStateKind::Prelaunch
    {
        return Err(LiveGenesisProbeExecutorError::PreparedIdentityDrift {
            field: "typed QMP non-running prelaunch state",
        });
    }
    let expected_cpu_ids = (0..u64::from(config.vcpus())).collect::<Vec<_>>();
    if observation.cpu_indexes != expected_cpu_ids {
        return Err(LiveGenesisProbeExecutorError::PreparedIdentityDrift {
            field: "typed QMP vCPU topology",
        });
    }
    Ok(())
}

fn validate_definition_prepared(
    config: &LiveRunnerConfig,
    prepared: &LivePreparedLaunch,
) -> Result<(), LiveDefinitionPreflightError> {
    if prepared.kind() != LiveRunnerLaunchKind::DefinitionPreflight {
        return Err(LiveDefinitionPreflightError::PreparedIdentityDrift {
            field: "launch kind",
        });
    }
    let fields = prepared.control().fields();
    if fields.mode != LiveObservationMode::DefinitionPreflight
        || fields.attempt != prepared.artifacts().attempt()
        || fields.definition_digest.is_some()
        || fields.base_launch_digest != config.base_launch_digest()
        || fields.fixed_run_digest != config.fixed_run_digest()
        || fields.horizon_icount != config.horizon_icount()
        || fields.actual_argv_digest != prepared.argv_identity().digest()
    {
        return Err(LiveDefinitionPreflightError::PreparedIdentityDrift {
            field: "observation control",
        });
    }
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
        return Err(LiveDefinitionPreflightError::PreparedIdentityDrift {
            field: "process invocation",
        });
    }
    let process_argv = prepared.process_argv_contract();
    if process_argv.argc() != prepared.argv_identity().argc()
        || process_argv.raw_bytes() != prepared.argv_identity().raw_byte_count()
        || process_argv.digest() != prepared.argv_identity().digest()
    {
        return Err(LiveDefinitionPreflightError::PreparedIdentityDrift {
            field: "process argv attestation",
        });
    }
    Ok(())
}

fn validate_live_preflight_evidence(
    config: &LiveRunnerConfig,
    evidence: &LiveDefinitionPreflightEvidence,
    expected_node: &str,
) -> Result<(), LiveGenesisProbeExecutorError> {
    validate_definition_prepared(config, evidence.prepared_launch()).map_err(|_| {
        LiveGenesisProbeExecutorError::PreflightMismatch {
            field: "prepared definition-preflight launch",
        }
    })?;
    if evidence.prepared_launch().control().fields().node != expected_node {
        return Err(LiveGenesisProbeExecutorError::PreflightMismatch {
            field: "scenario node",
        });
    }
    validate_preflight_qmp(config, evidence.qmp_observation()).map_err(|_| {
        LiveGenesisProbeExecutorError::PreflightMismatch {
            field: "typed QMP prelaunch evidence",
        }
    })?;
    if evidence.shutdown() != (LiveObservationShutdown::NaturalExit { success: true }) {
        return Err(LiveGenesisProbeExecutorError::PreflightMismatch {
            field: "natural successful exit",
        });
    }
    validate_trace_preflight(config, evidence.imported())
        .map_err(|field| LiveGenesisProbeExecutorError::PreflightMismatch { field })?;
    if evidence.imported().observation().qmp_cpu_ids() != evidence.qmp_observation().cpu_indexes {
        return Err(LiveGenesisProbeExecutorError::PreflightMismatch {
            field: "trace and typed QMP vCPU topology",
        });
    }
    Ok(())
}

fn validate_prepared(
    prepared: &LivePreparedLaunch,
    config: &LiveRunnerConfig,
    node: &str,
    request: &SingleVmFingerprintProbeRequest,
    definition_digest: [u8; 32],
) -> Result<(), LiveGenesisProbeExecutorError> {
    if prepared.kind() != LiveRunnerLaunchKind::Genesis {
        return Err(LiveGenesisProbeExecutorError::PreparedIdentityDrift {
            field: "launch kind",
        });
    }
    let fields = prepared.control().fields();
    let expected_mode = LiveObservationMode::ExactTarget {
        cadence_icount: config.cadence_icount(),
        target_icount: 0,
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
        return Err(LiveGenesisProbeExecutorError::PreparedIdentityDrift {
            field: "observation control",
        });
    }
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
        return Err(LiveGenesisProbeExecutorError::PreparedIdentityDrift {
            field: "process invocation",
        });
    }
    let process_argv = prepared.process_argv_contract();
    if process_argv.argc() != prepared.argv_identity().argc()
        || process_argv.raw_bytes() != prepared.argv_identity().raw_byte_count()
        || process_argv.digest() != prepared.argv_identity().digest()
    {
        return Err(LiveGenesisProbeExecutorError::PreparedIdentityDrift {
            field: "process argv attestation",
        });
    }
    Ok(())
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

/// Failure while executing or validating a dedicated live definition preflight.
#[derive(Debug, Error)]
pub enum LiveDefinitionPreflightError {
    /// Prepared preflight identity material differed from the configured launch.
    #[error("live definition preflight prepared launch drifted in {field}")]
    PreparedIdentityDrift {
        /// Identity boundary that drifted.
        field: &'static str,
    },
    /// Typed QMP or imported trace evidence did not describe the configured launch.
    #[error("live definition preflight mismatched {field}")]
    PreflightMismatch {
        /// Mismatching evidence field.
        field: &'static str,
    },
    /// QEMU returned a nonzero status after typed quit.
    #[error("live definition preflight QEMU exited unsuccessfully after typed quit")]
    UnsuccessfulExit,
    /// QEMU did not exit naturally within the bounded shutdown policy.
    #[error("live definition preflight QEMU required owner-forced teardown")]
    ForcedTeardown,
    /// Launch preparation failed.
    #[error("live definition preflight launch preparation failed: {0}")]
    Preparation(#[from] LivePreparationError),
    /// Process spawning, QMP observation, or shutdown failed.
    #[error("live definition preflight process boundary failed: {0}")]
    Process(#[from] LiveObservationProcessError),
    /// Definition trace opening failed.
    #[error("{operation} failed: {source}")]
    TraceIo {
        /// File operation being attempted.
        operation: &'static str,
        /// Underlying I/O failure.
        source: io::Error,
    },
    /// Definition trace content failed strict import.
    #[error("live definition preflight trace import failed: {0}")]
    Trace(#[from] QemuTraceFingerprintImportError),
}

/// Failure while validating or executing a live genesis probe.
#[derive(Debug, Error)]
pub enum LiveGenesisProbeExecutorError {
    /// Executor construction received an invalid fixed contract.
    #[error("invalid live genesis executor contract: {reason}")]
    InvalidContract {
        /// Rejected contract detail.
        reason: &'static str,
    },
    /// Preflight evidence did not describe the configured launch.
    #[error("live genesis preflight mismatched {field}")]
    PreflightMismatch {
        /// Mismatching preflight field.
        field: &'static str,
    },
    /// A request asked this deliberately narrow executor to run guest code.
    #[error("live genesis executor requires target zero, got {target}")]
    NonGenesisTarget {
        /// Rejected exact target.
        target: u64,
    },
    /// Request scenario material differed from the executor contract.
    #[error("live genesis request mismatched {field}")]
    RequestMismatch {
        /// Mismatching request field.
        field: &'static str,
    },
    /// Prepared identity material changed across the process boundary.
    #[error("live genesis prepared launch drifted in {field}")]
    PreparedIdentityDrift {
        /// Identity boundary that drifted.
        field: &'static str,
    },
    /// No fresh attempt number remains representable.
    #[error("live genesis attempt sequence exhausted u32")]
    AttemptSequenceExhausted,
    /// QEMU returned a nonzero status after typed quit.
    #[error("live genesis QEMU exited unsuccessfully after typed quit")]
    UnsuccessfulExit,
    /// QEMU did not exit naturally within the bounded shutdown policy.
    #[error("live genesis QEMU required owner-forced teardown")]
    ForcedTeardown,
    /// Fresh artifact allocation failed.
    #[error("live genesis artifact allocation failed: {0}")]
    Artifacts(#[from] LiveRunnerArtifactsError),
    /// Launch preparation failed.
    #[error("live genesis launch preparation failed: {0}")]
    Preparation(#[from] LivePreparationError),
    /// Process spawning, QMP observation, or shutdown failed.
    #[error("live genesis process boundary failed: {0}")]
    Process(#[from] LiveObservationProcessError),
    /// A direct typed QMP boundary operation failed.
    #[error("live genesis QMP boundary failed: {0}")]
    Qmp(#[from] LiveRunnerQmpPollError),
    /// Genesis trace opening failed.
    #[error("{operation} failed: {source}")]
    TraceIo {
        /// File operation being attempted.
        operation: &'static str,
        /// Underlying I/O failure.
        source: io::Error,
    },
    /// Genesis trace content failed strict import.
    #[error("live genesis trace import failed: {0}")]
    Trace(#[from] QemuTraceFingerprintImportError),
    /// The canonical probe constructor rejected imported material.
    #[error("live genesis probe construction failed: {0}")]
    Probe(SingleVmFingerprintBisectionError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::*;
    use crate::{
        DiskImageMode, GuestBackingStateMode, IcountShiftSetting, LaunchProfileCandidate,
        LiveRunnerImmutableInputs, LiveRunnerLaunchFields, LiveRunnerQmpPollPolicy,
        LiveRunnerQmpSession, QEMU_TRACE_FINGERPRINT_SCHEMA, QemuTraceProcessArgvContract,
        QmpCpuTopology, QmpRunState, QmpRunStateKind, SingleVmFingerprintRunOrdinal,
        SingleVmFingerprintScenario, SingleVmHostProfile, SingleVmNvcpuFingerprintContract,
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
                status: QmpRunStateKind::Prelaunch,
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

    fn config() -> Result<LiveRunnerConfig, Box<dyn Error>> {
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
                cadence_icount: 100,
                horizon_icount: 1_000,
            },
        )?)
    }

    fn artifact_root(label: &str) -> Result<(LiveRunnerArtifactRoot, PathBuf), Box<dyn Error>> {
        let path =
            std::env::temp_dir().join(format!("crucible-genesis-{label}-{}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        Ok((LiveRunnerArtifactRoot::new(&path)?, path))
    }

    fn preflight_evidence(
        config: &LiveRunnerConfig,
        label: &str,
    ) -> Result<LiveDefinitionPreflightEvidence, Box<dyn Error>> {
        let (root_path, prepared) = prepared_preflight(config, label)?;
        let value = definition_record(
            config,
            prepared.process_argv_contract(),
            [0x33; 32],
            [0x43; 32],
        );
        std::fs::write(
            prepared.artifacts().preflight_trace(),
            serde_json::to_vec(&value)?,
        )?;
        let evidence = LiveDefinitionPreflightEvidence::import_completed(
            config,
            prepared,
            valid_preflight_qmp(config),
            LiveObservationShutdown::NaturalExit { success: true },
        )?;
        std::fs::remove_dir_all(root_path)?;
        Ok(evidence)
    }

    fn prepared_preflight(
        config: &LiveRunnerConfig,
        label: &str,
    ) -> Result<(PathBuf, LivePreparedLaunch), Box<dyn Error>> {
        static PREFLIGHT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
        let sequence = PREFLIGHT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let (root, root_path) = artifact_root(&format!("{label}-{sequence}"))?;
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

    fn valid_preflight_qmp(config: &LiveRunnerConfig) -> LiveRunnerQmpObservation {
        LiveRunnerQmpObservation {
            run_state: QmpRunState {
                running: false,
                status: QmpRunStateKind::Prelaunch,
            },
            cpu_indexes: (0..u64::from(config.vcpus())).collect(),
        }
    }

    fn definition_record(
        config: &LiveRunnerConfig,
        process_argv: QemuTraceProcessArgvContract,
        ram_digest: [u8; 32],
        device_digest: [u8; 32],
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
            "ram_digest": lower_hex(&ram_digest),
            "ram_status": 0,
            "device_state_bytes": 4096,
            "device_state_digest": lower_hex(&device_digest),
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
    ) -> Result<SingleVmFingerprintScenario, Box<dyn Error>> {
        scenario_named(config, definition_digest, "node-a")
    }

    fn scenario_named(
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

    fn executor(
        config: LiveRunnerConfig,
        root: LiveRunnerArtifactRoot,
        quit_observed: Arc<AtomicBool>,
    ) -> Result<LiveGenesisProbeExecutor<FakeConnector, NoSleep>, Box<dyn Error>> {
        let preflight = preflight_evidence(&config, "executor-preflight")?;
        let definition_digest = QemuTraceFingerprintDefinition::new(
            config.cadence_icount(),
            preflight.imported().observation(),
        )?
        .definition_digest();
        let expected_scenario = scenario(&config, definition_digest)?;
        let poller = LiveRunnerQmpPoller::new(
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
        )?;
        Ok(LiveGenesisProbeExecutor::new(
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

    #[test]
    fn fresh_genesis_attempts_bind_ordinals_and_import_equal_state() -> Result<(), Box<dyn Error>> {
        let config = config()?;
        let (root, root_path) = artifact_root("success")?;
        let quit_observed = Arc::new(AtomicBool::new(false));
        let mut executor = executor(config.clone(), root, Arc::clone(&quit_observed))?;
        let scenario = scenario(&config, executor.definition_digest())?;
        let argv_digests = Arc::new(Mutex::new(Vec::new()));

        let mut run = |ordinal| -> Result<SingleVmFingerprintProbe, Box<dyn Error>> {
            quit_observed.store(false, Ordering::SeqCst);
            let request = SingleVmFingerprintProbeRequest::new(scenario.clone(), ordinal, 0)?;
            let captured = Arc::clone(&argv_digests);
            let report = executor.probe_report_with_boundary(
                &request,
                |prepared, poller, _shutdown_policy| {
                    let retained = prepared.clone();
                    let mut connection = poller.observe_stopped(
                        prepared.artifacts().qmp_socket(),
                        prepared.expected_vcpus(),
                        QmpRunStateKind::Prelaunch,
                    )?;
                    connection.session.quit()?;
                    captured
                        .lock()
                        .map_err(|_| LiveGenesisProbeExecutorError::InvalidContract {
                            reason: "test argv capture mutex was poisoned",
                        })?
                        .push(prepared.argv_identity().digest());
                    let record = definition_record(
                        &config,
                        prepared.process_argv_contract(),
                        [0x71; 32],
                        [0x72; 32],
                    );
                    let encoded = serde_json::to_vec(&record).map_err(|source| {
                        LiveGenesisProbeExecutorError::TraceIo {
                            operation: "encode fake genesis trace",
                            source: io::Error::other(source),
                        }
                    })?;
                    std::fs::write(prepared.artifacts().trace(), encoded).map_err(|source| {
                        LiveGenesisProbeExecutorError::TraceIo {
                            operation: "write fake genesis trace",
                            source,
                        }
                    })?;
                    Ok(CompletedGenesisAttempt {
                        prepared: retained,
                        qmp_observation: valid_preflight_qmp(&config),
                        shutdown: LiveObservationShutdown::NaturalExit { success: true },
                    })
                },
            )?;
            assert!(quit_observed.load(Ordering::SeqCst));
            assert_eq!(
                report.control().digest(),
                report.prepared_launch().control().digest()
            );
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
                    status: QmpRunStateKind::Prelaunch,
                }
            );
            assert_eq!(
                report.shutdown(),
                LiveObservationShutdown::NaturalExit { success: true }
            );
            Ok(report.into_probe())
        };

        let first = run(SingleVmFingerprintRunOrdinal::First)?;
        let second = run(SingleVmFingerprintRunOrdinal::Second)?;
        assert_eq!(first.icount(), 0);
        assert_eq!(first.node(), "node-a");
        assert_eq!(first.ordinal(), SingleVmFingerprintRunOrdinal::First);
        assert_eq!(second.ordinal(), SingleVmFingerprintRunOrdinal::Second);
        assert_eq!(first.definition_digest(), second.definition_digest());
        assert_eq!(first.run_inputs_digest(), second.run_inputs_digest());
        assert_eq!(first.prefix_fingerprint(), second.prefix_fingerprint());
        let captured = argv_digests
            .lock()
            .map_err(|_| "test argv capture mutex was poisoned")?;
        assert_eq!(captured.len(), 2);
        assert_ne!(captured[0], captured[1]);
        assert!(root_path.join("attempt-00000001").is_dir());
        assert!(root_path.join("attempt-00000002").is_dir());
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }

    #[test]
    fn nonzero_targets_and_forced_teardown_fail_closed() -> Result<(), Box<dyn Error>> {
        let config = config()?;
        let (root, root_path) = artifact_root("fail-closed")?;
        let quit_observed = Arc::new(AtomicBool::new(false));
        let mut executor = executor(config.clone(), root, quit_observed)?;
        let scenario = scenario(&config, executor.definition_digest())?;
        let nonzero = SingleVmFingerprintProbeRequest::new(
            scenario.clone(),
            SingleVmFingerprintRunOrdinal::First,
            1,
        )?;
        assert!(matches!(
            executor.probe_with_boundary(&nonzero, |_, _, _| unreachable!()),
            Err(LiveGenesisProbeExecutorError::NonGenesisTarget { target: 1 })
        ));
        assert!(!root_path.join("attempt-00000001").exists());

        let genesis = SingleVmFingerprintProbeRequest::new(
            scenario,
            SingleVmFingerprintRunOrdinal::First,
            0,
        )?;
        let result = executor.probe_with_boundary(&genesis, |prepared, _, _| {
            Ok(CompletedGenesisAttempt {
                prepared,
                qmp_observation: valid_preflight_qmp(&config),
                shutdown: LiveObservationShutdown::ForcedByOwnerDrop,
            })
        });
        assert!(matches!(
            result,
            Err(LiveGenesisProbeExecutorError::ForcedTeardown)
        ));
        assert!(root_path.join("attempt-00000001").is_dir());

        let result = executor.probe_with_boundary(&genesis, |prepared, _, _| {
            Ok(CompletedGenesisAttempt {
                prepared,
                qmp_observation: valid_preflight_qmp(&config),
                shutdown: LiveObservationShutdown::NaturalExit { success: false },
            })
        });
        assert!(matches!(
            result,
            Err(LiveGenesisProbeExecutorError::UnsuccessfulExit)
        ));
        assert!(root_path.join("attempt-00000002").is_dir());
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }

    #[test]
    fn live_preflight_rejects_topology_exit_and_argv_drift() -> Result<(), Box<dyn Error>> {
        let config = config()?;

        let (topology_root, topology_prepared) = prepared_preflight(&config, "topology-drift")?;
        let topology_record = definition_record(
            &config,
            topology_prepared.process_argv_contract(),
            [0x31; 32],
            [0x41; 32],
        );
        std::fs::write(
            topology_prepared.artifacts().preflight_trace(),
            serde_json::to_vec(&topology_record)?,
        )?;
        let mut wrong_topology = valid_preflight_qmp(&config);
        wrong_topology.cpu_indexes.pop();
        assert!(matches!(
            LiveDefinitionPreflightEvidence::import_completed(
                &config,
                topology_prepared,
                wrong_topology,
                LiveObservationShutdown::NaturalExit { success: true },
            ),
            Err(LiveDefinitionPreflightError::PreflightMismatch {
                field: "typed QMP vCPU topology"
            })
        ));
        std::fs::remove_dir_all(topology_root)?;

        for (label, shutdown, forced) in [
            (
                "unsuccessful-exit",
                LiveObservationShutdown::NaturalExit { success: false },
                false,
            ),
            (
                "forced-exit",
                LiveObservationShutdown::ForcedByOwnerDrop,
                true,
            ),
        ] {
            let (root, prepared) = prepared_preflight(&config, label)?;
            let result = LiveDefinitionPreflightEvidence::import_completed(
                &config,
                prepared,
                valid_preflight_qmp(&config),
                shutdown,
            );
            if forced {
                assert!(matches!(
                    result,
                    Err(LiveDefinitionPreflightError::ForcedTeardown)
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(LiveDefinitionPreflightError::UnsuccessfulExit)
                ));
            }
            std::fs::remove_dir_all(root)?;
        }

        let (argv_root, argv_prepared) = prepared_preflight(&config, "argv-drift")?;
        let wrong_argv = QemuTraceProcessArgvContract::new(1, 4, [0x55; 32])?;
        let argv_record = definition_record(&config, wrong_argv, [0x32; 32], [0x42; 32]);
        std::fs::write(
            argv_prepared.artifacts().preflight_trace(),
            serde_json::to_vec(&argv_record)?,
        )?;
        assert!(matches!(
            LiveDefinitionPreflightEvidence::import_completed(
                &config,
                argv_prepared,
                valid_preflight_qmp(&config),
                LiveObservationShutdown::NaturalExit { success: true },
            ),
            Err(LiveDefinitionPreflightError::Trace(_))
        ));
        std::fs::remove_dir_all(argv_root)?;
        Ok(())
    }

    #[test]
    fn live_preflight_and_scenario_drift_fail_closed() -> Result<(), Box<dyn Error>> {
        let config = config()?;
        let (root, prepared) = prepared_preflight(&config, "trace-contract-drift")?;
        let mut record = definition_record(
            &config,
            prepared.process_argv_contract(),
            [0x35; 32],
            [0x45; 32],
        );
        record["rr_switch_quantum"] = json!(config.rr_switch_quantum() + 1);
        std::fs::write(
            prepared.artifacts().preflight_trace(),
            serde_json::to_vec(&record)?,
        )?;
        assert!(matches!(
            LiveDefinitionPreflightEvidence::import_completed(
                &config,
                prepared,
                valid_preflight_qmp(&config),
                LiveObservationShutdown::NaturalExit { success: true },
            ),
            Err(LiveDefinitionPreflightError::PreflightMismatch {
                field: "RR switch quantum"
            })
        ));
        std::fs::remove_dir_all(root)?;

        let evidence = preflight_evidence(&config, "scenario-node-drift")?;
        let definition_digest = QemuTraceFingerprintDefinition::new(
            config.cadence_icount(),
            evidence.imported().observation(),
        )?
        .definition_digest();
        let wrong_scenario = scenario_named(&config, definition_digest, "node-b")?;
        let (probe_root, probe_root_path) = artifact_root("scenario-node-drift-probes")?;
        let poller = LiveRunnerQmpPoller::new(
            FakeConnector {
                vcpus: usize::from(config.vcpus()),
                quit_observed: Arc::new(AtomicBool::new(false)),
            },
            NoSleep,
            LiveRunnerQmpPollPolicy {
                connect_attempts: 1,
                status_attempts: 1,
                interval: Duration::from_millis(1),
            },
        )?;
        assert!(matches!(
            LiveGenesisProbeExecutor::new(
                config,
                probe_root,
                poller,
                LiveObservationShutdownPolicy {
                    poll_attempts: 1,
                    interval: Duration::from_millis(1),
                },
                evidence,
                wrong_scenario,
            ),
            Err(LiveGenesisProbeExecutorError::PreflightMismatch {
                field: "scenario node"
            })
        ));
        if probe_root_path.exists() {
            std::fs::remove_dir_all(probe_root_path)?;
        }
        Ok(())
    }

    #[test]
    fn attempt_collision_and_final_u32_attempt_fail_closed() -> Result<(), Box<dyn Error>> {
        let config = config()?;
        let (root, root_path) = artifact_root("attempt-boundaries")?;
        let quit_observed = Arc::new(AtomicBool::new(false));
        let mut executor = executor(config.clone(), root.clone(), quit_observed)?;
        root.create_attempt(1)?;
        assert!(matches!(
            executor.allocate_attempt(),
            Err(LiveGenesisProbeExecutorError::Artifacts(
                LiveRunnerArtifactsError::AttemptAlreadyExists { .. }
            ))
        ));

        executor.next_attempt = u64::from(u32::MAX);
        let final_attempt = executor.allocate_attempt()?;
        assert_eq!(final_attempt.attempt(), u32::MAX);
        assert!(final_attempt.directory().is_dir());
        assert!(matches!(
            executor.allocate_attempt(),
            Err(LiveGenesisProbeExecutorError::AttemptSequenceExhausted)
        ));
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }
}
