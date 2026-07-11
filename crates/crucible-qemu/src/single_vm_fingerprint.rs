//! Single-VM execution-fingerprint gate hook.
//!
//! This module owns the safe host-side contract consumed by
//! `gate:single-vm-fingerprint`: run one fixed single-VM scenario twice and
//! compare the canonical fingerprint streams byte-for-byte. Later QEMU process
//! supervision code plugs into [`SingleVmFingerprintRunner`]; the gate driver
//! here is independent of how a backend obtains register, memory, device, and
//! RR-scheduler digests.
//!
//! Module map: [`types`] owns the public scenario, stream, runner, and error
//! data contracts; [`compare`] owns first-mismatch localization; [`run`] owns
//! the run-twice gate driver; [`probe`] owns fallible instruction-exact
//! refinement; [`state_dump`] owns both-side architectural diagnostics; and
//! [`trace`] imports the real QEMU trace plugin's host-observed samples into the
//! canonical stream contract; and Linux-only [`live_runner`] owns fresh launch,
//! artifact, typed-QMP, and bounded process-lifecycle primitives.

mod compare;
#[cfg(target_os = "linux")]
mod live_runner;
mod probe;
mod run;
mod state_dump;
mod trace;
mod types;

pub use compare::{
    SingleVmFingerprintMismatch, SingleVmFingerprintMismatchKind,
    SingleVmFingerprintSampleDifference, compare_single_vm_fingerprint_streams,
};
#[cfg(target_os = "linux")]
pub use live_runner::{
    LiveDefinitionPreflightError, LiveDefinitionPreflightEvidence, LiveGenesisProbeExecutor,
    LiveGenesisProbeExecutorError, LiveGenesisProbeReport, LiveIdentityError,
    LiveInvocationIdentity, LiveInvocationPaths, LiveObservationAttempt, LiveObservationControl,
    LiveObservationControlFields, LiveObservationMode, LiveObservationModeFlags,
    LiveObservationProcess, LiveObservationProcessError, LiveObservationShutdown,
    LiveObservationShutdownPolicy, LivePreparationError, LivePreparationRequest,
    LivePreparedLaunch, LiveRunnerArtifactRoot, LiveRunnerArtifacts, LiveRunnerArtifactsError,
    LiveRunnerConfig, LiveRunnerConfigError, LiveRunnerImmutableInputs, LiveRunnerLaunchFields,
    LiveRunnerLaunchKind, LiveRunnerLaunchSpec, LiveRunnerQmpConnector, LiveRunnerQmpObservation,
    LiveRunnerQmpPollError, LiveRunnerQmpPollPolicy, LiveRunnerQmpPoller, LiveRunnerQmpSession,
    LiveRunnerSleeper, RawUnixArgvIdentity, ThreadLiveRunnerSleeper, TypedLiveRunnerQmpConnector,
    VerifiedGuestImageDigests, VerifiedLiveRunInputs, VerifiedLiveRunInputsError,
    spawn_live_observation_process,
};
pub use probe::{
    SingleVmFingerprintProbe, SingleVmFingerprintProbeRequest, SingleVmFingerprintProbeRunner,
    SingleVmFingerprintStateDumpProbe, bisect_single_vm_fingerprint_with_probes,
};
pub use run::run_single_vm_fingerprint_gate;
pub use state_dump::{
    SINGLE_VM_FINGERPRINT_STATE_DUMP_EVENT_LIMIT, SingleVmFingerprintCanonicalEvent,
    SingleVmFingerprintDivergenceStateDump, SingleVmFingerprintMemoryRegionState,
    SingleVmFingerprintRunStateDump, SingleVmFingerprintVcpuState,
};
pub use trace::{
    QEMU_TRACE_FINGERPRINT_SCHEMA, QemuTraceDefinitionPreflight, QemuTraceFingerprintDefinition,
    QemuTraceFingerprintImport, QemuTraceFingerprintImportError, QemuTraceGenesisFingerprintImport,
    QemuTraceIdentityContract, QemuTraceObservationContract, QemuTraceProcessArgvContract,
    QemuTraceVcpuContract,
};
pub use types::{
    SINGLE_VM_FINGERPRINT_DIGEST_BYTES, SingleVmFingerprintBisectionError,
    SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionRequest,
    SingleVmFingerprintEventBoundary, SingleVmFingerprintGateError, SingleVmFingerprintGateReport,
    SingleVmFingerprintRunError, SingleVmFingerprintRunInputs, SingleVmFingerprintRunOrdinal,
    SingleVmFingerprintRunRequest, SingleVmFingerprintRunner, SingleVmFingerprintSample,
    SingleVmFingerprintSampleMaterial, SingleVmFingerprintScenario, SingleVmFingerprintStream,
    SingleVmFingerprintTrigger, SingleVmHostProfile, SingleVmNvcpuFingerprintContract,
    SingleVmNvcpuFingerprintMaterial, SingleVmQmpVcpuTopology, SingleVmRoundRobinCursor,
    SingleVmVcpuRegisterDigest, compute_single_vm_sample_rolling_fingerprint,
    initial_single_vm_rolling_fingerprint,
};
