//! Fresh-process terminal observations at arbitrary nonzero instruction targets.
//!
//! [`LiveTerminalTargetExecutor`] uses [`SingleVmFingerprintProbeRequest`] only
//! as typed scenario, run-ordinal, and target input. Its output is one exact
//! current-state terminal observation from a fresh process. It is not a
//! [`crate::SingleVmFingerprintProbe`], does not implement
//! [`crate::SingleVmFingerprintProbeRunner`], and is not a cumulative prefix
//! from the scenario's periodic fingerprint stream.

use std::fs::File;
use std::io::{self, BufReader};

use thiserror::Error;

use crate::single_vm_fingerprint::{
    QemuTerminalHorizonTraceImport, QemuTraceFingerprintDefinition,
    QemuTraceFingerprintImportError, QemuTraceProcessArgvContract, SingleVmFingerprintProbeRequest,
    SingleVmFingerprintRunOrdinal, SingleVmFingerprintSample, SingleVmFingerprintScenario,
    SingleVmFingerprintStream,
};

use super::terminal_common::{
    TerminalPublicationInspectionError, expected_cpu_ids, inspect_terminal_publication,
    is_one_sample_at, lower_hex, prepared_invocation_drift, terminal_qmp_drift,
};
use super::{
    LiveDefinitionPreflightEvidence, LiveInvocationIdentity, LiveObservationControl,
    LiveObservationMode, LiveObservationProcessError, LiveObservationShutdown,
    LiveObservationShutdownPolicy, LivePreparationError, LivePreparationRequest,
    LivePreparedLaunch, LiveRunnerArtifactRoot, LiveRunnerArtifacts, LiveRunnerArtifactsError,
    LiveRunnerConfig, LiveRunnerLaunchKind, LiveRunnerQmpConnector, LiveRunnerQmpObservation,
    LiveRunnerQmpPoller, LiveRunnerSleeper, RawUnixArgvIdentity, spawn_live_observation_process,
};

/// One exact current-state terminal observation from a fresh QEMU process.
///
/// The request type supplies a scenario, ordinal, and target, but this value is
/// intentionally not a [`crate::SingleVmFingerprintProbe`]. The retained sample was
/// imported as a single isolated terminal state. Its fingerprint begins from
/// the definition's initial value and therefore must not be interpreted as the
/// cumulative prefix produced by periodic samples through the same target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveTerminalTargetObservation {
    ordinal: SingleVmFingerprintRunOrdinal,
    node: String,
    target_icount: u64,
    definition_digest: [u8; 32],
    run_inputs_digest: [u8; 32],
    sample: SingleVmFingerprintSample,
}

impl LiveTerminalTargetObservation {
    fn from_stream(
        request: &SingleVmFingerprintProbeRequest,
        definition_digest: [u8; 32],
        run_inputs_digest: [u8; 32],
        stream: SingleVmFingerprintStream,
    ) -> Result<Self, LiveTerminalTargetExecutorError> {
        let target_icount = request.target_icount();
        if !is_one_sample_at(&stream, target_icount) {
            return Err(LiveTerminalTargetExecutorError::InvalidTerminalObservation);
        }
        let mut samples = stream.samples.into_iter();
        let sample = samples
            .next()
            .ok_or(LiveTerminalTargetExecutorError::InvalidTerminalObservation)?;
        if samples.next().is_some() {
            return Err(LiveTerminalTargetExecutorError::InvalidTerminalObservation);
        }
        Ok(Self {
            ordinal: request.ordinal(),
            node: request.scenario().id().to_owned(),
            target_icount,
            definition_digest,
            run_inputs_digest,
            sample,
        })
    }

    /// Returns which fixed-run ordinal was executed in the fresh process.
    #[must_use]
    pub const fn ordinal(&self) -> SingleVmFingerprintRunOrdinal {
        self.ordinal
    }

    /// Returns the fixed scenario node observed by the process.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Returns the exact nonzero aggregate instruction target.
    #[must_use]
    pub const fn target_icount(&self) -> u64 {
        self.target_icount
    }

    /// Returns the independently derived observation-definition digest.
    #[must_use]
    pub const fn definition_digest(&self) -> &[u8; 32] {
        &self.definition_digest
    }

    /// Returns the digest of the fixed image, command line, seed, and launch tuple.
    #[must_use]
    pub const fn run_inputs_digest(&self) -> &[u8; 32] {
        &self.run_inputs_digest
    }

    /// Returns the imported one-sample exact terminal state.
    ///
    /// The sample's rolling fingerprint starts from the definition's initial
    /// value. It is a fingerprint of this isolated terminal observation, not a
    /// cumulative prefix of earlier periodic samples.
    #[must_use]
    pub const fn sample(&self) -> &SingleVmFingerprintSample {
        &self.sample
    }

    /// Returns the isolated one-sample state fingerprint.
    ///
    /// This digest must not be compared as though it were a cumulative
    /// [`crate::SingleVmFingerprintProbe`] prefix.
    #[must_use]
    pub fn state_fingerprint(&self) -> &[u8] {
        &self.sample.rolling_fingerprint
    }
}

/// Auditable result of one completed arbitrary terminal-target observation.
///
/// All retained identities, QMP evidence, and shutdown evidence belong to the
/// same process that produced [`Self::observation`]. The observation is a
/// one-sample current state, not a cumulative fingerprint prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveTerminalTargetReport {
    observation: LiveTerminalTargetObservation,
    prepared: LivePreparedLaunch,
    qmp_observation: LiveRunnerQmpObservation,
    shutdown: LiveObservationShutdown,
}

impl LiveTerminalTargetReport {
    /// Returns the isolated exact current-state terminal observation.
    #[must_use]
    pub const fn observation(&self) -> &LiveTerminalTargetObservation {
        &self.observation
    }

    /// Consumes the report and returns its isolated terminal observation.
    #[must_use]
    pub fn into_observation(self) -> LiveTerminalTargetObservation {
        self.observation
    }

    /// Returns the fresh attempt number bound into all retained identities.
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

/// Fresh-process executor for isolated nonzero terminal-target observations.
#[derive(Debug)]
pub struct LiveTerminalTargetExecutor<C, S> {
    config: LiveRunnerConfig,
    artifact_root: LiveRunnerArtifactRoot,
    poller: LiveRunnerQmpPoller<C, S>,
    shutdown_policy: LiveObservationShutdownPolicy,
    preflight: LiveDefinitionPreflightEvidence,
    definition_digest: [u8; 32],
    scenario: SingleVmFingerprintScenario,
    next_attempt: u64,
}

impl<C, S> LiveTerminalTargetExecutor<C, S>
where
    C: LiveRunnerQmpConnector,
    S: LiveRunnerSleeper,
{
    /// Builds an arbitrary terminal-target executor from verified contracts.
    ///
    /// Unlike [`super::LiveTerminalHorizonExecutor`], this executor does not
    /// require the definition cadence to equal the scenario horizon. The
    /// cadence remains fixed in launch identity while each request selects one
    /// fresh nonzero terminal target.
    ///
    /// # Errors
    ///
    /// Returns [`LiveTerminalTargetExecutorError`] when shutdown bounds are
    /// invalid or preflight/scenario evidence differs from `config`.
    pub fn new(
        config: LiveRunnerConfig,
        artifact_root: LiveRunnerArtifactRoot,
        poller: LiveRunnerQmpPoller<C, S>,
        shutdown_policy: LiveObservationShutdownPolicy,
        preflight: LiveDefinitionPreflightEvidence,
        scenario: SingleVmFingerprintScenario,
    ) -> Result<Self, LiveTerminalTargetExecutorError> {
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

    /// Executes one fresh isolated terminal observation at the requested target.
    ///
    /// [`SingleVmFingerprintProbeRequest`] is used only for typed scenario,
    /// ordinal, and target input. The returned value is not a
    /// [`crate::SingleVmFingerprintProbe`] and not a cumulative prefix fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`LiveTerminalTargetExecutorError`] when request validation,
    /// allocation, process supervision, typed QMP admission, publication,
    /// natural shutdown, strict import, or the one-sample postcondition fails.
    pub fn observe(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<LiveTerminalTargetObservation, LiveTerminalTargetExecutorError> {
        self.observe_report(request)
            .map(LiveTerminalTargetReport::into_observation)
    }

    /// Executes one fresh target and retains the completed process evidence.
    ///
    /// # Errors
    ///
    /// Returns [`LiveTerminalTargetExecutorError`] under the same fail-closed
    /// conditions as [`Self::observe`].
    pub fn observe_report(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<LiveTerminalTargetReport, LiveTerminalTargetExecutorError> {
        let node = self.scenario.id().to_owned();
        let definition_digest = self.definition_digest;
        let target_icount = request.target_icount();
        let preflight = self.preflight.imported().observation().clone();
        self.observe_report_with_boundary(request, move |prepared, poller, shutdown_policy| {
            let retained = prepared.clone();
            let attempt = spawn_live_observation_process(prepared)?.observe(poller)?;
            let qmp_observation = attempt.observation().clone();
            let importer = QemuTerminalHorizonTraceImport::new(
                node,
                definition_digest,
                target_icount,
                preflight,
                retained.process_argv_contract(),
            )?;
            wait_for_terminal_publication(poller, attempt.artifacts().trace(), &importer)?;
            let shutdown = attempt.shutdown(shutdown_policy)?;
            Ok(CompletedTerminalTargetAttempt {
                prepared: retained,
                qmp_observation,
                shutdown,
            })
        })
    }

    fn observe_report_with_boundary<F>(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
        boundary: F,
    ) -> Result<LiveTerminalTargetReport, LiveTerminalTargetExecutorError>
    where
        F: FnOnce(
            LivePreparedLaunch,
            &mut LiveRunnerQmpPoller<C, S>,
            LiveObservationShutdownPolicy,
        )
            -> Result<CompletedTerminalTargetAttempt, LiveTerminalTargetExecutorError>,
    {
        self.validate_request(request)?;
        let artifacts = self.allocate_attempt()?;
        let target_icount = request.target_icount();
        let prepared = LivePreparedLaunch::new(
            &self.config,
            LiveRunnerLaunchKind::TerminalTarget { target_icount },
            &artifacts,
            LivePreparationRequest {
                node: self.scenario.id().to_owned(),
                mode: LiveObservationMode::ExactTarget {
                    cadence_icount: self.config.cadence_icount(),
                    target_icount,
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
                return Err(LiveTerminalTargetExecutorError::UnsuccessfulExit);
            }
            LiveObservationShutdown::ForcedByOwnerDrop => {
                return Err(LiveTerminalTargetExecutorError::ForcedTeardown);
            }
        }

        let trace = File::open(completed.prepared.artifacts().trace()).map_err(|source| {
            LiveTerminalTargetExecutorError::TraceIo {
                operation: "open terminal target trace",
                source,
            }
        })?;
        let importer = QemuTerminalHorizonTraceImport::new(
            self.scenario.id(),
            self.definition_digest,
            target_icount,
            self.preflight.imported().observation().clone(),
            completed.prepared.process_argv_contract(),
        )?;
        let stream = importer.import(BufReader::new(trace))?;
        let observation = LiveTerminalTargetObservation::from_stream(
            request,
            self.definition_digest,
            self.config.fixed_run_digest(),
            stream,
        )?;
        Ok(LiveTerminalTargetReport {
            observation,
            prepared: completed.prepared,
            qmp_observation: completed.qmp_observation,
            shutdown: completed.shutdown,
        })
    }

    fn validate_request(
        &self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<(), LiveTerminalTargetExecutorError> {
        let target = request.target_icount();
        if target == 0 {
            return Err(LiveTerminalTargetExecutorError::GenesisTarget);
        }
        if target > self.config.horizon_icount() {
            return Err(LiveTerminalTargetExecutorError::TargetBeyondHorizon {
                target,
                horizon: self.config.horizon_icount(),
            });
        }
        if request.scenario() != &self.scenario {
            return Err(LiveTerminalTargetExecutorError::RequestMismatch {
                field: "fixed scenario",
            });
        }
        Ok(())
    }

    fn allocate_attempt(&mut self) -> Result<LiveRunnerArtifacts, LiveTerminalTargetExecutorError> {
        let attempt = u32::try_from(self.next_attempt)
            .map_err(|_| LiveTerminalTargetExecutorError::AttemptSequenceExhausted)?;
        self.next_attempt += 1;
        self.artifact_root
            .create_attempt(attempt)
            .map_err(LiveTerminalTargetExecutorError::Artifacts)
    }
}

fn wait_for_terminal_publication<C, S>(
    poller: &mut LiveRunnerQmpPoller<C, S>,
    trace: &std::path::Path,
    importer: &QemuTerminalHorizonTraceImport,
) -> Result<(), LiveTerminalTargetExecutorError>
where
    C: LiveRunnerQmpConnector,
    S: LiveRunnerSleeper,
{
    let published = poller
        .poll_publication(|| inspect_terminal_publication(trace, importer))
        .map_err(|error| match error {
            TerminalPublicationInspectionError::Io(source) => {
                LiveTerminalTargetExecutorError::TraceIo {
                    operation: "read terminal target publication",
                    source,
                }
            }
            TerminalPublicationInspectionError::Trace(source) => {
                LiveTerminalTargetExecutorError::Trace(source)
            }
        })?;
    published.ok_or(LiveTerminalTargetExecutorError::PublicationExhausted)
}

#[derive(Debug)]
struct CompletedTerminalTargetAttempt {
    prepared: LivePreparedLaunch,
    qmp_observation: LiveRunnerQmpObservation,
    shutdown: LiveObservationShutdown,
}

fn validate_live_preflight(
    config: &LiveRunnerConfig,
    evidence: &LiveDefinitionPreflightEvidence,
    expected_node: &str,
) -> Result<(), LiveTerminalTargetExecutorError> {
    let prepared = evidence.prepared_launch();
    if prepared.kind() != LiveRunnerLaunchKind::DefinitionPreflight {
        return Err(LiveTerminalTargetExecutorError::PreflightMismatch {
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
        return Err(LiveTerminalTargetExecutorError::PreflightMismatch {
            field: "definition-preflight control identity",
        });
    }
    if prepared_invocation_drift(prepared).is_some() {
        return Err(LiveTerminalTargetExecutorError::PreflightMismatch {
            field: "definition-preflight process invocation",
        });
    }
    let qmp = evidence.qmp_observation();
    if qmp.run_state.running
        || qmp.run_state.status != crate::QmpRunStateKind::Prelaunch
        || qmp.cpu_indexes != expected_cpu_ids(config)
    {
        return Err(LiveTerminalTargetExecutorError::PreflightMismatch {
            field: "typed QMP prelaunch evidence",
        });
    }
    if evidence.shutdown() != (LiveObservationShutdown::NaturalExit { success: true }) {
        return Err(LiveTerminalTargetExecutorError::PreflightMismatch {
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
        return Err(LiveTerminalTargetExecutorError::PreflightMismatch {
            field: "imported definition trace",
        });
    }
    Ok(())
}

fn validate_scenario(
    config: &LiveRunnerConfig,
    scenario: &SingleVmFingerprintScenario,
    definition_digest: [u8; 32],
) -> Result<(), LiveTerminalTargetExecutorError> {
    if scenario.run_horizon_icount() != config.horizon_icount() {
        return Err(LiveTerminalTargetExecutorError::RequestMismatch {
            field: "run horizon",
        });
    }
    if scenario.fingerprint_definition_digest() != definition_digest {
        return Err(LiveTerminalTargetExecutorError::RequestMismatch {
            field: "fingerprint definition digest",
        });
    }
    let run_inputs = config.verified_run_inputs().to_run_inputs().map_err(|_| {
        LiveTerminalTargetExecutorError::InvalidContract {
            reason: "verified live run inputs could not be re-derived",
        }
    })?;
    if scenario.run_inputs() != &run_inputs {
        return Err(LiveTerminalTargetExecutorError::RequestMismatch {
            field: "run inputs",
        });
    }
    if scenario.expected_vcpu_count() != usize::from(config.vcpus()) {
        return Err(LiveTerminalTargetExecutorError::RequestMismatch {
            field: "vCPU count",
        });
    }
    if scenario.expected_rr_switch_quantum() != config.rr_switch_quantum() {
        return Err(LiveTerminalTargetExecutorError::RequestMismatch {
            field: "RR switch quantum",
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
) -> Result<(), LiveTerminalTargetExecutorError> {
    let target_icount = request.target_icount();
    if prepared.kind() != (LiveRunnerLaunchKind::TerminalTarget { target_icount }) {
        return Err(LiveTerminalTargetExecutorError::PreparedIdentityDrift {
            field: "launch kind",
        });
    }
    let fields = prepared.control().fields();
    let expected_mode = LiveObservationMode::ExactTarget {
        cadence_icount: config.cadence_icount(),
        target_icount,
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
        return Err(LiveTerminalTargetExecutorError::PreparedIdentityDrift {
            field: "observation control",
        });
    }
    if let Some(field) = prepared_invocation_drift(prepared) {
        return Err(LiveTerminalTargetExecutorError::PreparedIdentityDrift { field });
    }
    Ok(())
}

fn validate_terminal_qmp(
    config: &LiveRunnerConfig,
    observation: &LiveRunnerQmpObservation,
) -> Result<(), LiveTerminalTargetExecutorError> {
    if let Some(field) = terminal_qmp_drift(config, observation) {
        return Err(LiveTerminalTargetExecutorError::PreparedIdentityDrift { field });
    }
    Ok(())
}

/// Failure while validating or executing an arbitrary terminal target.
#[derive(Debug, Error)]
pub enum LiveTerminalTargetExecutorError {
    /// Executor construction received an invalid fixed contract.
    #[error("invalid live terminal-target executor contract: {reason}")]
    InvalidContract {
        /// Rejected contract detail.
        reason: &'static str,
    },
    /// Preflight evidence did not describe the configured launch.
    #[error("live terminal-target preflight mismatched {field}")]
    PreflightMismatch {
        /// Mismatching evidence field.
        field: &'static str,
    },
    /// Target zero belongs to the instruction-free genesis executor.
    #[error("live terminal-target executor rejects target zero; use the genesis executor")]
    GenesisTarget,
    /// The requested target exceeded the fixed scenario horizon.
    #[error("live terminal target {target} exceeds configured horizon {horizon}")]
    TargetBeyondHorizon {
        /// Rejected target.
        target: u64,
        /// Inclusive configured maximum.
        horizon: u64,
    },
    /// Scenario or request material differed from the executor contract.
    #[error("live terminal-target request mismatched {field}")]
    RequestMismatch {
        /// Mismatching request field.
        field: &'static str,
    },
    /// Prepared identity material changed across the process boundary.
    #[error("live terminal-target prepared launch drifted in {field}")]
    PreparedIdentityDrift {
        /// Identity boundary that drifted.
        field: &'static str,
    },
    /// Strict import returned something other than one exact target sample.
    #[error("live terminal-target trace did not contain exactly one target sample")]
    InvalidTerminalObservation,
    /// The bounded post-pause publication barrier expired.
    #[error("live terminal-target state publication did not complete before the bounded deadline")]
    PublicationExhausted,
    /// No fresh attempt number remains representable.
    #[error("live terminal-target attempt sequence exhausted u32")]
    AttemptSequenceExhausted,
    /// QEMU returned a nonzero status after typed quit.
    #[error("live terminal-target QEMU exited unsuccessfully after typed quit")]
    UnsuccessfulExit,
    /// QEMU did not exit naturally within the bounded shutdown policy.
    #[error("live terminal-target QEMU required owner-forced teardown")]
    ForcedTeardown,
    /// Fresh artifact allocation failed.
    #[error("live terminal-target artifact allocation failed: {0}")]
    Artifacts(#[from] LiveRunnerArtifactsError),
    /// Launch preparation failed.
    #[error("live terminal-target launch preparation failed: {0}")]
    Preparation(#[from] LivePreparationError),
    /// Process spawning, QMP observation, or shutdown failed.
    #[error("live terminal-target process boundary failed: {0}")]
    Process(#[from] LiveObservationProcessError),
    /// Terminal trace opening or publication failed.
    #[error("{operation} failed: {source}")]
    TraceIo {
        /// File operation being attempted.
        operation: &'static str,
        /// Underlying I/O failure.
        source: io::Error,
    },
    /// Definition or terminal trace content failed strict import.
    #[error("live terminal-target trace import failed: {0}")]
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
        QmpCpuTopology, QmpRunState, QmpRunStateKind, SingleVmHostProfile,
        SingleVmNvcpuFingerprintContract,
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
                cadence_icount: 10,
                horizon_icount: 100,
            },
        )?)
    }

    fn artifact_root(label: &str) -> Result<(LiveRunnerArtifactRoot, PathBuf), Box<dyn Error>> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(1);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "crucible-terminal-target-{label}-{}-{sequence}",
            std::process::id()
        ));
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        Ok((LiveRunnerArtifactRoot::new(&path)?, path))
    }

    fn preflight_evidence(
        config: &LiveRunnerConfig,
        label: &str,
    ) -> Result<LiveDefinitionPreflightEvidence, Box<dyn Error>> {
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
        std::fs::write(
            prepared.artifacts().preflight_trace(),
            serde_json::to_vec(&definition_record(config, prepared.process_argv_contract()))?,
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
        horizon: u64,
    ) -> Result<SingleVmFingerprintScenario, Box<dyn Error>> {
        Ok(SingleVmFingerprintScenario::new_with_nvcpu_contract(
            node,
            definition_digest,
            horizon,
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
    ) -> Result<LiveTerminalTargetExecutor<FakeConnector, NoSleep>, Box<dyn Error>> {
        let preflight = preflight_evidence(&config, "executor-preflight")?;
        let definition_digest = QemuTraceFingerprintDefinition::new(
            config.cadence_icount(),
            preflight.imported().observation(),
        )?
        .definition_digest();
        let expected_scenario = scenario(
            &config,
            definition_digest,
            "node-a",
            config.horizon_icount(),
        )?;
        let poller = poller(&config, quit_observed)?;
        Ok(LiveTerminalTargetExecutor::new(
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
        target: u64,
        process_argv: QemuTraceProcessArgvContract,
    ) -> Vec<Value> {
        let vcpus = usize::from(config.vcpus());
        let base = target / vcpus as u64;
        let remainder = target % vcpus as u64;
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
        sample["retired"] = json!(target);
        sample["observed_icount"] = json!(target);
        sample["vcpu"] = json!(0);
        sample["final"] = json!(false);
        sample["tracked_vcpus"] = json!(vcpus);
        sample["stop_at"] = json!(target);
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
        sample["stream_hash"] = json!(format!("{target:016x}"));
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
        // FlatView-mapped RAM is a different quantity from the RAMBlock backing
        // store: on pc-q35 it is 256 KiB short, because the legacy-BIOS PAM
        // window (0xC0000-0xFFFFF) is ROM-shadowed once firmware has run and is
        // not RAM-mapped at the terminal boundary. Model that gap (128 MiB
        // RAMBlock minus the 256 KiB shadow) rather than the old raw==guest
        // equality that terminal_trace normalization documents as false for
        // pc-q35 and never exercised by a live run.
        sample["raw_ram_bytes"] = json!(128 * 1024 * 1024_u64 - 256 * 1024);
        sample["raw_ram_status"] = json!(0);
        sample["vmstate_digest"] = json!("62".repeat(32));
        sample["vmstate_bytes"] = json!(4096);
        sample["vmstate_status"] = json!(0);
        sample["memory_event_hash"] = json!(format!("{:016x}", target + 4));
        sample["device_event_hash"] = json!(format!("{:016x}", target + 5));
        sample["memory_events"] = json!(target);
        sample["io_events"] = json!(target / 2);
        sample["memory_events_enabled"] = json!(true);
        sample["sample_register_failures"] = json!(0);
        sample["register_read_failures"] = json!(0);
        sample["trajectory_digest_failures"] = json!(0);

        let mut terminal = common;
        terminal["kind"] = json!("terminal_final");
        terminal["terminal_state_schema"] = json!("crucible.qemu.terminal-horizon.v1");
        terminal["retired"] = json!(target);
        terminal["observed_icount"] = json!(target);
        terminal["final"] = json!(true);
        terminal["stop_at"] = json!(target);
        terminal["stop_requested"] = json!(true);
        terminal["terminal_pause_requested"] = json!(true);
        terminal["terminal_pause_status"] = json!(0);
        terminal["terminal_callback_completed"] = json!(true);
        terminal["terminal_state_emitted"] = json!(true);
        terminal["terminal_state_complete"] = json!(true);
        vec![sample, terminal]
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

    fn write_terminal_trace(
        config: &LiveRunnerConfig,
        target: u64,
        prepared: &LivePreparedLaunch,
    ) -> Result<(), LiveTerminalTargetExecutorError> {
        std::fs::write(
            prepared.artifacts().trace(),
            encoded_trace(&terminal_trace(
                config,
                target,
                prepared.process_argv_contract(),
            )),
        )
        .map_err(|source| LiveTerminalTargetExecutorError::TraceIo {
            operation: "write fake terminal target trace",
            source,
        })
    }

    fn completed(
        config: &LiveRunnerConfig,
        target: u64,
        prepared: LivePreparedLaunch,
        poller: &mut LiveRunnerQmpPoller<FakeConnector, NoSleep>,
    ) -> Result<CompletedTerminalTargetAttempt, LiveTerminalTargetExecutorError> {
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
        write_terminal_trace(config, target, &prepared)?;
        Ok(CompletedTerminalTargetAttempt {
            prepared: retained,
            qmp_observation: connection.observation,
            shutdown: LiveObservationShutdown::NaturalExit { success: true },
        })
    }

    #[test]
    fn fresh_first_middle_and_horizon_targets_are_identity_distinct() -> Result<(), Box<dyn Error>>
    {
        let config = config()?;
        let (root, root_path) = artifact_root("success")?;
        let quit_observed = Arc::new(AtomicBool::new(false));
        let mut executor = executor(config.clone(), root, Arc::clone(&quit_observed))?;
        let fixed = scenario(
            &config,
            executor.definition_digest(),
            "node-a",
            config.horizon_icount(),
        )?;
        let mut controls = Vec::new();
        let mut invocations = Vec::new();
        let mut argv = Vec::new();
        for (attempt, target, ordinal) in [
            (1, 1, SingleVmFingerprintRunOrdinal::First),
            (2, 50, SingleVmFingerprintRunOrdinal::Second),
            (3, 100, SingleVmFingerprintRunOrdinal::First),
        ] {
            quit_observed.store(false, Ordering::SeqCst);
            let request = SingleVmFingerprintProbeRequest::new(fixed.clone(), ordinal, target)?;
            let report = executor
                .observe_report_with_boundary(&request, |prepared, poller, _| {
                    completed(&config, target, prepared, poller)
                })?;
            assert_eq!(report.attempt(), attempt);
            assert_eq!(report.observation().target_icount(), target);
            assert_eq!(report.observation().ordinal(), ordinal);
            assert_eq!(report.observation().sample().icount, target);
            assert_eq!(report.observation().sample().seq, 0);
            assert_eq!(
                report.prepared_launch().kind(),
                LiveRunnerLaunchKind::TerminalTarget {
                    target_icount: target
                }
            );
            assert_eq!(
                report.control().fields().mode,
                LiveObservationMode::ExactTarget {
                    cadence_icount: config.cadence_icount(),
                    target_icount: target,
                    ordinal,
                }
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
            controls.push(report.control().digest());
            invocations.push(report.invocation().digest());
            argv.push(report.argv_identity().digest());
        }
        assert!(controls.windows(2).all(|pair| pair[0] != pair[1]));
        assert!(invocations.windows(2).all(|pair| pair[0] != pair[1]));
        assert!(argv.windows(2).all(|pair| pair[0] != pair[1]));
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }

    #[test]
    fn zero_overshoot_and_scenario_drift_do_not_allocate_attempts() -> Result<(), Box<dyn Error>> {
        let config = config()?;
        let (root, root_path) = artifact_root("request-rejections")?;
        let mut executor = executor(config.clone(), root, Arc::new(AtomicBool::new(false)))?;
        let fixed = scenario(
            &config,
            executor.definition_digest(),
            "node-a",
            config.horizon_icount(),
        )?;
        let zero = SingleVmFingerprintProbeRequest::new(
            fixed.clone(),
            SingleVmFingerprintRunOrdinal::First,
            0,
        )?;
        assert!(matches!(
            executor.observe_report_with_boundary(&zero, |_, _, _| unreachable!()),
            Err(LiveTerminalTargetExecutorError::GenesisTarget)
        ));

        let larger = scenario(
            &config,
            executor.definition_digest(),
            "node-a",
            config.horizon_icount() + 1,
        )?;
        let overshoot = SingleVmFingerprintProbeRequest::new(
            larger,
            SingleVmFingerprintRunOrdinal::First,
            config.horizon_icount() + 1,
        )?;
        assert!(matches!(
            executor.observe_report_with_boundary(&overshoot, |_, _, _| unreachable!()),
            Err(LiveTerminalTargetExecutorError::TargetBeyondHorizon {
                target: 101,
                horizon: 100
            })
        ));

        let drifted = scenario(
            &config,
            executor.definition_digest(),
            "node-b",
            config.horizon_icount(),
        )?;
        let drift = SingleVmFingerprintProbeRequest::new(
            drifted,
            SingleVmFingerprintRunOrdinal::First,
            50,
        )?;
        assert!(matches!(
            executor.observe_report_with_boundary(&drift, |_, _, _| unreachable!()),
            Err(LiveTerminalTargetExecutorError::RequestMismatch {
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
    fn qmp_shutdown_and_publication_fail_closed() -> Result<(), Box<dyn Error>> {
        let config = config()?;
        let (root, root_path) = artifact_root("boundary")?;
        let mut executor = executor(config.clone(), root, Arc::new(AtomicBool::new(false)))?;
        let fixed = scenario(
            &config,
            executor.definition_digest(),
            "node-a",
            config.horizon_icount(),
        )?;
        let request =
            SingleVmFingerprintProbeRequest::new(fixed, SingleVmFingerprintRunOrdinal::First, 50)?;
        let wrong_qmp = executor.observe_report_with_boundary(&request, |prepared, _, _| {
            Ok(CompletedTerminalTargetAttempt {
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
            wrong_qmp,
            Err(LiveTerminalTargetExecutorError::PreparedIdentityDrift {
                field: "typed QMP non-running paused state"
            })
        ));
        let forced = executor.observe_report_with_boundary(&request, |prepared, _, _| {
            Ok(CompletedTerminalTargetAttempt {
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
            Err(LiveTerminalTargetExecutorError::ForcedTeardown)
        ));
        let unsuccessful = executor.observe_report_with_boundary(&request, |prepared, _, _| {
            Ok(CompletedTerminalTargetAttempt {
                prepared,
                qmp_observation: LiveRunnerQmpObservation {
                    run_state: QmpRunState {
                        running: false,
                        status: QmpRunStateKind::Paused,
                    },
                    cpu_indexes: expected_cpu_ids(&config),
                },
                shutdown: LiveObservationShutdown::NaturalExit { success: false },
            })
        });
        assert!(matches!(
            unsuccessful,
            Err(LiveTerminalTargetExecutorError::UnsuccessfulExit)
        ));

        let artifacts = executor.allocate_attempt()?;
        let prepared = LivePreparedLaunch::new(
            &config,
            LiveRunnerLaunchKind::TerminalTarget { target_icount: 50 },
            &artifacts,
            LivePreparationRequest {
                node: "node-a".to_owned(),
                mode: LiveObservationMode::ExactTarget {
                    cadence_icount: config.cadence_icount(),
                    target_icount: 50,
                    ordinal: SingleVmFingerprintRunOrdinal::First,
                },
                definition_digest: Some(executor.definition_digest()),
            },
        )?;
        let importer = QemuTerminalHorizonTraceImport::new(
            "node-a",
            executor.definition_digest(),
            50,
            executor.preflight.imported().observation().clone(),
            prepared.process_argv_contract(),
        )?;
        std::fs::write(prepared.artifacts().trace(), [])?;
        assert!(matches!(
            wait_for_terminal_publication(
                &mut executor.poller,
                prepared.artifacts().trace(),
                &importer
            ),
            Err(LiveTerminalTargetExecutorError::PublicationExhausted)
        ));
        std::fs::write(
            prepared.artifacts().trace(),
            encoded_trace(&terminal_trace(
                &config,
                50,
                prepared.process_argv_contract(),
            )),
        )?;
        wait_for_terminal_publication(
            &mut executor.poller,
            prepared.artifacts().trace(),
            &importer,
        )?;
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }

    #[test]
    fn attempt_collision_and_u32_exhaustion_fail_closed() -> Result<(), Box<dyn Error>> {
        let config = config()?;
        let (root, root_path) = artifact_root("attempts")?;
        let mut executor = executor(config, root.clone(), Arc::new(AtomicBool::new(false)))?;
        root.create_attempt(1)?;
        assert!(matches!(
            executor.allocate_attempt(),
            Err(LiveTerminalTargetExecutorError::Artifacts(
                LiveRunnerArtifactsError::AttemptAlreadyExists { .. }
            ))
        ));
        executor.next_attempt = u64::from(u32::MAX);
        assert_eq!(executor.allocate_attempt()?.attempt(), u32::MAX);
        assert!(matches!(
            executor.allocate_attempt(),
            Err(LiveTerminalTargetExecutorError::AttemptSequenceExhausted)
        ));
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }
}
