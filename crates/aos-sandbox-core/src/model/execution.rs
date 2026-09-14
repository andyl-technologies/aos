//! Portable execution admission and observation semantics.
//!
//! [`ExecutionSpecV1`] binds an execution to signed assignment authority, an
//! exact project environment, a runtime-qualified argument envelope, admitted
//! resource sublimits, and a closed access route. Live OpenSSH routes carry a
//! holder key; detached capture routes deliberately do not. The types do not
//! contain host paths, process identifiers, units, sockets, or backend command
//! lines. [`ExecutionObservationV1`] versions the extended execution
//! lifecycle separately from the legacy Serde-backed [`crate::state::ExecutionPhase`].
//!
//! The `command` submodule owns target and exec-envelope values, `resource`
//! owns local limits and nonauthorizing assignment-bound output claims, and
//! `validation` centralizes checked cross-field and bounded-encoding invariants.

mod command;
mod resource;
mod validation;

pub use command::{
    ExecutionArgumentEnvelopeV1, ExecutionCommandV1, ExecutionCredentialsV1,
    ExecutionEnvironmentEntry, ExecutionRuntimeArgumentLimitV1, ExecutionTargetV1, PayloadBootId,
};
pub use resource::{
    ExecutionOutputByteAdmissionV1, ExecutionResourceAdmissionV1, ExecutionResourceRequestV1,
    ExecutionResourceRequestValueV1, ExecutionResourceSublimitV1, ExecutionResourceSublimitValueV1,
};

use validation::*;

use crate::state::{
    ExecutionPhase, ObservationAdvanceError, ObservedPhase, ObservedState, ReasonCode,
    TransitionTime,
};
use crate::{
    AuditId, DesiredGeneration, ExecutionId, ObjectDescriptor, ObjectDigest, ObservationSequence,
    PrincipalId, Revision,
};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use super::Environment;

/// Maximum argument count in one portable execution.
pub const MAX_EXECUTION_ARGUMENTS: usize = 4_096;
/// Maximum aggregate raw argument bytes before exec framing overhead.
pub const MAX_EXECUTION_ARGUMENT_BYTES: usize = 2 * 1_048_576;
/// Linux `MAX_ARG_STRLEN`, including the terminating NUL byte.
pub const MAX_EXECUTION_STRING_BYTES: usize = 128 * 1_024;
/// Maximum raw bytes in one argument before its terminating NUL byte.
pub const MAX_EXECUTION_ARGUMENT_STRING_BYTES: usize = MAX_EXECUTION_STRING_BYTES - 1;
/// Maximum environment-overlay entries in one portable execution.
pub const MAX_EXECUTION_ENVIRONMENT_ENTRIES: usize = 4_096;
/// Maximum bytes in one overlay variable name.
///
/// The 255-byte ceiling is deliberately narrower than the project-environment
/// schema. Overlay names enter public request, diagnostics, and policy-index
/// paths; the smaller stable bound prevents those surfaces from inheriting the
/// much larger stored-environment text ceiling. Base environment names remain
/// byte-accounted and are subject to [`MAX_EXECUTION_STRING_BYTES`] at exec.
pub const MAX_EXECUTION_ENVIRONMENT_NAME_BYTES: usize = 255;
/// Maximum bytes in one environment-overlay value.
///
/// This leaves room for a nonempty one-byte name, `=`, and the terminating NUL
/// inside [`MAX_EXECUTION_STRING_BYTES`]. Longer names are checked when the
/// effective environment is derived.
pub const MAX_EXECUTION_ENVIRONMENT_VALUE_BYTES: usize = MAX_EXECUTION_STRING_BYTES - 3;
/// Maximum aggregate overlay name and value bytes before exec framing overhead.
pub const MAX_EXECUTION_ENVIRONMENT_BYTES: usize = 2 * 1_048_576;
/// Maximum canonical project-environment bytes embedded for admission verification.
pub const MAX_EXECUTION_BASE_ENVIRONMENT_BYTES: usize = 8 * 1_048_576;
/// Maximum aggregate CBOR items in one embedded project environment.
pub const MAX_EXECUTION_BASE_ENVIRONMENT_CBOR_ITEMS: usize = 65_536;
/// Maximum closure descriptors or command-search paths in the embedded environment.
pub(crate) const MAX_EXECUTION_BASE_ENVIRONMENT_COLLECTION_ITEMS: usize = 4_096;
/// Maximum required features in the embedded environment.
pub(crate) const MAX_EXECUTION_BASE_ENVIRONMENT_FEATURES: usize = 64;
/// Maximum canonical assignment bytes embedded in an output-reservation claim.
pub(crate) const MAX_EXECUTION_OUTPUT_ASSIGNMENT_BYTES: usize = 2 * 1_048_576;
/// Maximum supplementary group count in one credential projection.
pub const MAX_EXECUTION_SUPPLEMENTARY_GROUPS: usize = 256;
/// Maximum requested or admitted resource entries in one execution.
pub const MAX_EXECUTION_RESOURCE_SETTINGS: usize = 16;
/// Maximum closed endpoint capabilities in one OpenSSH access route.
pub const MAX_EXECUTION_ENDPOINT_CAPABILITIES: usize = 9;
/// Maximum final captured-stream descriptors in one execution observation.
pub const MAX_EXECUTION_CAPTURED_STREAMS: usize = 2;

const EXEC_ARGUMENT_POINTER_BYTES: usize = 8;
// Reserves a fixed 16-KiB allowance for platform alignment, auxiliary-vector
// growth, and backend framing not represented by argv/envp.
const EXEC_ARGUMENT_FIXED_HEADROOM_BYTES: usize = 16 * 1_024;
const EFFECTIVE_ENVIRONMENT_DIGEST_DOMAIN: &[u8] = b"aos-sandbox-effective-environment-v1\0";
const OPENSSH_PUBLIC_KEY_DIGEST_DOMAIN: &[u8] = b"aos-sandbox-openssh-public-key-v1\0";
const RUNTIME_ARGUMENT_EVIDENCE_DOMAIN: &[u8] = b"aos-sandbox-runtime-argument-limit-evidence-v1\0";
const OUTPUT_RESERVATION_COMMITMENT_DOMAIN: &[u8] =
    b"aos-sandbox-execution-output-reservation-v1\0";

/// Reports execution admission semantics that are incomplete or noncanonical.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidExecutionSpec {
    /// An identity, generation, descriptor, or digest uses its zero sentinel.
    #[error("execution specification contains an unspecified identity, generation, or digest")]
    Unspecified,
    /// A descriptor or required enforcement/runtime feature is not registered.
    #[error("execution registry validation failed: {0}")]
    Registry(#[from] crate::RegistryError),
    /// Canonical environment bytes do not reproduce the committed descriptor.
    #[error("execution base environment does not match its exact descriptor")]
    EnvironmentDescriptorMismatch,
    /// The embedded environment exceeds an execution-v1 collection or byte bound.
    #[error("execution base environment exceeds portable execution bounds")]
    BaseEnvironmentExceeded,
    /// The argument vector is empty, contains NUL, or exceeds a portable bound.
    #[error("execution arguments are empty, contain NUL, or exceed portable bounds")]
    InvalidArguments,
    /// An environment name or value violates exec-compatible byte rules.
    #[error("execution environment entry violates portable exec rules")]
    InvalidEnvironmentEntry,
    /// The environment overlay is oversized, duplicated, or not in canonical name order.
    #[error("execution environment overlay must be a canonical bounded map")]
    EnvironmentNotCanonical,
    /// The runtime argument limit is absent or the complete envelope exceeds it.
    #[error("execution argument and environment envelope exceeds the runtime limit")]
    ArgumentEnvelopeExceeded,
    /// Runtime argument-limit evidence is unspecified or belongs to another target.
    #[error("execution runtime argument-limit evidence is invalid for the exact target")]
    RuntimeArgumentEvidenceMismatch,
    /// An encoded argument-envelope claim differs from the value derived from exact inputs.
    #[error("execution argument-envelope commitment does not match exact inputs")]
    ArgumentEnvelopeMismatch,
    /// A guest UID or GID uses the kernel overflow sentinel.
    #[error("execution credentials must not use the u32 maximum overflow identity")]
    OverflowIdentity,
    /// Supplementary groups are oversized, duplicated, or not in canonical order.
    #[error("execution supplementary groups must be a canonical bounded set")]
    SupplementaryGroupsNotCanonical,
    /// The primary group is repeated in the supplementary group set.
    #[error("execution primary group must not be repeated as a supplementary group")]
    PrimaryGroupRepeated,
    /// A resource dimension or value has the wrong execution-local semantics or range.
    #[error("execution resource setting is invalid for its dimension")]
    InvalidResourceSetting,
    /// A resource dimension names an enforcement feature outside its closed mapping.
    #[error("execution resource setting uses the wrong enforcement feature")]
    ResourceEnforcementMismatch,
    /// Resource settings are oversized, duplicated, or not in canonical dimension order.
    #[error("execution resource settings must be canonical bounded sets")]
    ResourceSettingsNotCanonical,
    /// Requested and admitted resource dimensions do not correspond exactly.
    #[error("requested and admitted execution resource dimensions differ")]
    ResourceAdmissionShapeMismatch,
    /// CPU and I/O scheduling weights must both have explicit admitted values.
    #[error("execution admission requires explicit CPU and I/O weights")]
    RequiredWeightAdmissionMissing,
    /// Parent policy lacks the admitted dimension or uses unresolved inheritance.
    #[error("parent resource profile cannot authorize the admitted sublimit")]
    ParentResourceUnavailable,
    /// An admitted sublimit exceeds its request or exact parent ceiling.
    #[error("admitted execution resource sublimit exceeds its governing bound")]
    ResourceSublimitExceeded,
    /// The exact parent profile does not reproduce its supplied commitment.
    #[error("parent resource profile does not match its exact commitment")]
    ParentResourceCommitmentMismatch,
    /// The submitted OpenSSH public key is malformed or weak.
    #[error("execution OpenSSH public key is invalid")]
    InvalidPublicKey,
    /// Endpoint capabilities are duplicated, unordered, or incompatible with I/O policy.
    #[error("execution endpoint capabilities are noncanonical or incompatible")]
    InvalidEndpointCapabilities,
    /// Terminal, output, disconnect, and route selections cannot be combined safely.
    #[error("execution I/O and access policy contains an incompatible combination")]
    IncompatibleAccessPolicy,
    /// Captured output exceeds its distinct claimed output-byte reservation.
    #[error("execution capture exceeds its claimed output-retention bound")]
    CaptureLimitExceeded,
    /// An output-byte claim is malformed or exceeds its exact parent reservation.
    #[error("execution output-byte claim exceeds its exact parent reservation")]
    InvalidOutputAdmission,
    /// The output-byte claim is bound to a different assignment target.
    #[error("execution output-byte claim does not match the assignment target")]
    OutputReservationBindingMismatch,
    /// A monotonic timeout must be an explicit positive duration.
    #[error("execution monotonic timeout must be greater than zero")]
    InvalidTimeout,
    /// A versioned observation has bad ordering counters or specification binding.
    #[error("execution observation ordering or specification binding is invalid")]
    InvalidObservation,
    /// A terminal result is absent, duplicated, or incompatible with its phase.
    #[error("execution terminal result is incompatible with its observation phase")]
    InvalidTerminalResult,
    /// Captured output is malformed or exceeds the execution I/O claim.
    #[error("execution captured-output evidence is invalid for its admitted I/O policy")]
    InvalidCapturedOutput,
}

/// Identifies the closed public-key algorithm accepted by OpenSSH v1 access.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ExecutionPublicKeyAlgorithmV1 {
    /// Uses a raw 32-byte Ed25519 verification key for `ssh-ed25519`.
    SshEd25519 = 0,
}

/// Stores validated bounded key material and its internally derived digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPublicKeyV1 {
    algorithm: ExecutionPublicKeyAlgorithmV1,
    key_material: [u8; 32],
    digest: ObjectDigest,
}

impl ExecutionPublicKeyV1 {
    /// Validates one raw OpenSSH holder public key and derives its exact digest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec::InvalidPublicKey`] when Ed25519 parsing
    /// fails or the key is weak. The digest is never accepted from the caller.
    pub fn new_ssh_ed25519(key_material: [u8; 32]) -> Result<Self, InvalidExecutionSpec> {
        let key = VerifyingKey::from_bytes(&key_material)
            .map_err(|_| InvalidExecutionSpec::InvalidPublicKey)?;
        if key.is_weak() {
            return Err(InvalidExecutionSpec::InvalidPublicKey);
        }
        let mut digest = Sha256::new();
        digest.update(OPENSSH_PUBLIC_KEY_DIGEST_DOMAIN);
        digest.update([ExecutionPublicKeyAlgorithmV1::SshEd25519 as u8]);
        digest.update((key_material.len() as u64).to_be_bytes());
        digest.update(key_material);
        Ok(Self {
            algorithm: ExecutionPublicKeyAlgorithmV1::SshEd25519,
            key_material,
            digest: ObjectDigest::from_bytes(digest.finalize().into()),
        })
    }

    /// Returns the closed public-key algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> ExecutionPublicKeyAlgorithmV1 {
        self.algorithm
    }

    /// Returns the exact raw public-key material.
    #[must_use]
    pub const fn key_material(&self) -> &[u8; 32] {
        &self.key_material
    }

    /// Returns the domain-separated digest of algorithm and canonical key bytes.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

/// Names one closed capability carried by an OpenSSH execution endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ExecutionEndpointCapabilityV1 {
    /// Permits the client-to-command standard-input stream.
    StandardInput = 0,
    /// Permits the command-to-client standard-output stream.
    StandardOutput = 1,
    /// Permits the command-to-client standard-error stream.
    StandardError = 2,
    /// Permits terminal window-size changes for an allocated PTY.
    TerminalResize = 3,
    /// Permits forwarding a closed supported signal set.
    SignalForwarding = 4,
    /// Permits the forced SFTP subsystem.
    Sftp = 5,
    /// Permits the forced Git subsystem.
    Git = 6,
    /// Permits explicitly policy-authorized TCP forwarding.
    TcpForwarding = 7,
    /// Permits explicitly policy-authorized agent forwarding.
    AgentForwarding = 8,
}

/// Stores one validated holder-bound OpenSSH route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionOpenSshRouteV1 {
    public_key: ExecutionPublicKeyV1,
    capabilities: Vec<ExecutionEndpointCapabilityV1>,
}

impl ExecutionOpenSshRouteV1 {
    /// Constructs a holder-bound OpenSSH route with canonical capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec::InvalidEndpointCapabilities`] when the
    /// capability set is oversized, duplicated, or not strictly ordered.
    pub fn new(
        public_key: ExecutionPublicKeyV1,
        capabilities: Vec<ExecutionEndpointCapabilityV1>,
    ) -> Result<Self, InvalidExecutionSpec> {
        if capabilities.len() > MAX_EXECUTION_ENDPOINT_CAPABILITIES
            || !strictly_increasing(&capabilities)
        {
            return Err(InvalidExecutionSpec::InvalidEndpointCapabilities);
        }
        Ok(Self {
            public_key,
            capabilities,
        })
    }

    /// Returns the holder public key used for certificate issuance.
    #[must_use]
    pub const fn public_key(&self) -> &ExecutionPublicKeyV1 {
        &self.public_key
    }

    /// Returns explicit endpoint rights in strict closed-enum order.
    #[must_use]
    pub fn capabilities(&self) -> &[ExecutionEndpointCapabilityV1] {
        &self.capabilities
    }
}

/// Selects the versioned holder-bound execution access route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionAccessRouteV1 {
    /// Issues no live data-plane credential for a detached execution.
    Detached,
    /// Issues a forced-command OpenSSH credential for a validated route.
    OpenSsh(ExecutionOpenSshRouteV1),
}

impl ExecutionAccessRouteV1 {
    /// Constructs a holder-bound OpenSSH route with canonical capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec::InvalidEndpointCapabilities`] when the
    /// capability set is oversized, duplicated, or not strictly ordered.
    pub fn open_ssh(
        public_key: ExecutionPublicKeyV1,
        capabilities: Vec<ExecutionEndpointCapabilityV1>,
    ) -> Result<Self, InvalidExecutionSpec> {
        ExecutionOpenSshRouteV1::new(public_key, capabilities).map(Self::OpenSsh)
    }

    /// Returns the holder key for an OpenSSH route.
    #[must_use]
    pub const fn public_key(&self) -> Option<&ExecutionPublicKeyV1> {
        match self {
            Self::Detached => None,
            Self::OpenSsh(route) => Some(route.public_key()),
        }
    }

    /// Returns the exact closed capability set, or an empty set when detached.
    #[must_use]
    pub fn capabilities(&self) -> &[ExecutionEndpointCapabilityV1] {
        match self {
            Self::Detached => &[],
            Self::OpenSsh(route) => route.capabilities(),
        }
    }
}

/// Identifies terminal allocation semantics for one execution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutionTerminalModeV1 {
    /// Uses independent byte streams without a controlling terminal.
    None,
    /// Allocates one controlling pseudoterminal.
    Pty,
}

/// Identifies how stdout and stderr are retained or delivered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionOutputModeV1 {
    /// Delivers live output without durable stream replay.
    Stream,
    /// Stores output up to explicit per-stream byte ceilings.
    Capture {
        /// Maximum retained stdout bytes.
        maximum_stdout_bytes: u64,
        /// Maximum retained stderr bytes.
        maximum_stderr_bytes: u64,
    },
}

/// Identifies one portable signal terminal result without host signal numbers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ExecutionSignalV1 {
    /// Hangup was requested or the controlling session ended.
    Hangup = 0,
    /// Interactive interrupt terminated the command.
    Interrupt = 1,
    /// Interactive quit terminated the command.
    Quit = 2,
    /// The command executed an illegal instruction.
    IllegalInstruction = 3,
    /// A tracing or breakpoint trap terminated the command.
    Trap = 4,
    /// The command aborted itself.
    Abort = 5,
    /// A bus access fault terminated the command.
    Bus = 6,
    /// A floating-point exception terminated the command.
    FloatingPointException = 7,
    /// An unconditional kill terminated the command.
    Kill = 8,
    /// A caller-defined user signal terminated the command.
    User1 = 9,
    /// A segmentation fault terminated the command.
    SegmentationFault = 10,
    /// A second caller-defined user signal terminated the command.
    User2 = 11,
    /// A broken pipe terminated the command.
    BrokenPipe = 12,
    /// An alarm timer terminated the command.
    Alarm = 13,
    /// A termination request ended the command.
    Terminate = 14,
    /// A stack fault terminated the command.
    StackFault = 15,
    /// The CPU-time limit terminated the command.
    CpuLimit = 16,
    /// The file-size limit terminated the command.
    FileSizeLimit = 17,
    /// A virtual interval timer terminated the command.
    VirtualAlarm = 18,
    /// A profiling timer terminated the command.
    Profiling = 19,
    /// Asynchronous I/O notification terminated the command.
    Io = 20,
    /// A power event terminated the command.
    Power = 21,
    /// A forbidden system call terminated the command.
    BadSystemCall = 22,
}

impl ExecutionSignalV1 {
    /// Reports whether this signal can produce a core image under v1 semantics.
    #[must_use]
    pub const fn can_dump_core(self) -> bool {
        matches!(
            self,
            Self::Quit
                | Self::IllegalInstruction
                | Self::Trap
                | Self::Abort
                | Self::Bus
                | Self::FloatingPointException
                | Self::SegmentationFault
                | Self::CpuLimit
                | Self::FileSizeLimit
                | Self::BadSystemCall
        )
    }
}

/// Classifies a failed execution independently of diagnostic prose.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ExecutionFailureReasonV1 {
    /// Assignment or request admission failed.
    Admission = 0,
    /// Exact environment realization failed.
    Environment = 1,
    /// Resource reservation or enforcement failed.
    Resource = 2,
    /// Guest credential projection failed.
    Credentials = 3,
    /// Process setup or exec failed before the command ran.
    Start = 4,
    /// Runtime supervision failed after startup.
    Runtime = 5,
    /// Durable output capture failed.
    OutputCapture = 6,
    /// Monotonic execution timeout enforcement failed.
    Timeout = 7,
    /// A closed implementation invariant failed without a narrower class.
    Internal = 8,
}

/// Stores the exact terminal outcome corresponding to a terminal phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionTerminalResultV1 {
    /// The process exited normally with the exact portable status byte.
    Exited {
        /// Exact process exit status.
        code: u8,
    },
    /// The process terminated because of one closed portable signal.
    Signaled {
        /// Portable signal identity.
        signal: ExecutionSignalV1,
        /// Whether a core-capable signal produced a core image.
        core_dumped: bool,
    },
    /// Cancellation won before a normal terminal status was committed.
    Canceled,
    /// Admission, startup, supervision, or capture failed.
    Failed {
        /// Stable typed failure class.
        reason: ExecutionFailureReasonV1,
    },
    /// The exact admitted runtime generation became unobservable.
    Lost,
}

/// Selects one independently captured output stream.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ExecutionCapturedStreamKindV1 {
    /// Standard output bytes.
    Stdout = 0,
    /// Standard error bytes.
    Stderr = 1,
}

/// Binds final captured bytes and truncation to one exact content object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedStreamV1 {
    stream: ExecutionCapturedStreamKindV1,
    descriptor: ObjectDescriptor,
    captured_bytes: u64,
    truncated: bool,
}

impl CapturedStreamV1 {
    /// Constructs exact final evidence for one captured stream.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec::InvalidCapturedOutput`] unless the
    /// descriptor is nonzero content and its encoded size equals
    /// `captured_bytes` exactly.
    pub fn new(
        stream: ExecutionCapturedStreamKindV1,
        descriptor: ObjectDescriptor,
        captured_bytes: u64,
        truncated: bool,
    ) -> Result<Self, InvalidExecutionSpec> {
        crate::validate_descriptor_role(crate::DescriptorRole::FileContent, &descriptor)
            .map_err(|_| InvalidExecutionSpec::InvalidCapturedOutput)?;
        if descriptor.digest().as_bytes() == &[0; 32] || descriptor.encoded_size() != captured_bytes
        {
            return Err(InvalidExecutionSpec::InvalidCapturedOutput);
        }
        Ok(Self {
            stream,
            descriptor,
            captured_bytes,
            truncated,
        })
    }

    /// Returns the captured stream identity.
    #[must_use]
    pub const fn stream(&self) -> ExecutionCapturedStreamKindV1 {
        self.stream
    }

    /// Returns the exact content descriptor for retained stream bytes.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }

    /// Returns the exact number of retained stream bytes.
    #[must_use]
    pub const fn captured_bytes(&self) -> u64 {
        self.captured_bytes
    }

    /// Reports whether bytes beyond the admitted stream ceiling were discarded.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Reports whether final capture evidence is complete, partial, or unavailable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionCapturedOutputV1 {
    /// The runtime could not retain or recover any final capture evidence.
    Unavailable,
    /// Some final stream evidence is available, but capture did not complete.
    Partial {
        /// Available streams in strict stream order.
        streams: Vec<CapturedStreamV1>,
    },
    /// Capture completed with exact stdout and stderr evidence.
    Complete {
        /// Exact stdout then stderr descriptors.
        streams: [CapturedStreamV1; MAX_EXECUTION_CAPTURED_STREAMS],
    },
}

impl ExecutionCapturedOutputV1 {
    /// Returns available stream evidence in strict stream order.
    #[must_use]
    pub fn streams(&self) -> &[CapturedStreamV1] {
        match self {
            Self::Unavailable => &[],
            Self::Partial { streams } => streams,
            Self::Complete { streams } => streams,
        }
    }
}

/// Selects what happens when the live client data channel disconnects.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutionDisconnectPolicyV1 {
    /// Cancels the execution when its live data channel is lost.
    Cancel,
    /// Continues a detached execution that writes only bounded captured output.
    Continue,
}

/// Stores closed terminal, output, disconnect, and access-route behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionIoV1 {
    terminal_mode: ExecutionTerminalModeV1,
    output_mode: ExecutionOutputModeV1,
    disconnect_policy: ExecutionDisconnectPolicyV1,
    access_route: ExecutionAccessRouteV1,
}

impl ExecutionIoV1 {
    /// Constructs one coherent execution data-channel and credential policy.
    ///
    /// Streaming requires OpenSSH and disconnect cancellation. Detached
    /// continuation requires non-PTY capture and no live route. Terminal resize
    /// requires a PTY, while SFTP and Git are mutually exclusive and forbid PTY.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec`] for capture-size overflow or an illegal
    /// terminal, output, disconnect, route, or endpoint-capability combination.
    pub fn new(
        terminal_mode: ExecutionTerminalModeV1,
        output_mode: ExecutionOutputModeV1,
        disconnect_policy: ExecutionDisconnectPolicyV1,
        access_route: ExecutionAccessRouteV1,
    ) -> Result<Self, InvalidExecutionSpec> {
        let capture_valid = match output_mode {
            ExecutionOutputModeV1::Stream => true,
            ExecutionOutputModeV1::Capture {
                maximum_stdout_bytes,
                maximum_stderr_bytes,
            } => maximum_stdout_bytes
                .checked_add(maximum_stderr_bytes)
                .is_some(),
        };
        let route_valid = matches!(
            (output_mode, disconnect_policy, &access_route),
            (
                ExecutionOutputModeV1::Stream,
                ExecutionDisconnectPolicyV1::Cancel,
                ExecutionAccessRouteV1::OpenSsh(_)
            ) | (
                ExecutionOutputModeV1::Capture { .. },
                ExecutionDisconnectPolicyV1::Continue,
                ExecutionAccessRouteV1::Detached
            )
        );
        let terminal_valid = !matches!(
            (terminal_mode, output_mode),
            (
                ExecutionTerminalModeV1::Pty,
                ExecutionOutputModeV1::Capture { .. }
            )
        );
        if !capture_valid || !route_valid || !terminal_valid {
            return Err(InvalidExecutionSpec::IncompatibleAccessPolicy);
        }
        validate_endpoint_capabilities(terminal_mode, &access_route)?;
        Ok(Self {
            terminal_mode,
            output_mode,
            disconnect_policy,
            access_route,
        })
    }

    /// Returns the terminal allocation mode.
    #[must_use]
    pub const fn terminal_mode(&self) -> ExecutionTerminalModeV1 {
        self.terminal_mode
    }

    /// Returns the live-stream or bounded-capture mode.
    #[must_use]
    pub const fn output_mode(&self) -> ExecutionOutputModeV1 {
        self.output_mode
    }

    /// Returns the client-disconnect behavior.
    #[must_use]
    pub const fn disconnect_policy(&self) -> ExecutionDisconnectPolicyV1 {
        self.disconnect_policy
    }

    /// Returns the detached or holder-bound OpenSSH access route.
    #[must_use]
    pub const fn access_route(&self) -> &ExecutionAccessRouteV1 {
        &self.access_route
    }
}

/// Stores a positive monotonic execution duration in nanoseconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutionTimeoutV1(u64);

impl ExecutionTimeoutV1 {
    /// Constructs an explicit monotonic duration.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec::InvalidTimeout`] when `nanoseconds` is
    /// zero. Assignment-lease and compiled-policy ceilings may narrow it.
    pub const fn new(nanoseconds: u64) -> Result<Self, InvalidExecutionSpec> {
        if nanoseconds == 0 {
            Err(InvalidExecutionSpec::InvalidTimeout)
        } else {
            Ok(Self(nanoseconds))
        }
    }

    /// Returns the monotonic duration in nanoseconds.
    #[must_use]
    pub const fn nanoseconds(self) -> u64 {
        self.0
    }
}

/// Stores the complete immutable semantic input to one admitted execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionSpecV1 {
    execution: ExecutionId,
    target: ExecutionTargetV1,
    environment_descriptor: ObjectDescriptor,
    base_environment: Environment,
    environment_generation: Revision,
    command: ExecutionCommandV1,
    argument_envelope: ExecutionArgumentEnvelopeV1,
    resources: ExecutionResourceAdmissionV1,
    io: ExecutionIoV1,
    timeout: ExecutionTimeoutV1,
    principal: PrincipalId,
    audit: AuditId,
}

impl ExecutionSpecV1 {
    /// Constructs one validated execution admission specification.
    ///
    /// The environment descriptor is reproduced from the embedded canonical
    /// base environment, the argument envelope is derived rather than trusted,
    /// and capture ceilings are checked against the assignment-bound
    /// `OutputBytes` claim rather than a storage limit. The retained parent
    /// profile commitment must equal the assignment's resource commitment.
    /// Runtime argument evidence is target-bound but nonauthorizing. Before any
    /// effectful exec, a protected adapter must verify the committed profile and
    /// target freshness and enforce the same observed limit. It must also obtain
    /// protected broker-ledger admission that is bound to this execution ID,
    /// revalidates the current assignment, and reserves the claimed output bytes
    /// before execution or capture effects. This source-only specification and
    /// its output claim do not authorize ledger consumption.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec`] for sentinel identities, environment
    /// substitution, resource-commitment mismatch, argument-envelope failure,
    /// or capture exceeding its claim.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution: ExecutionId,
        target: ExecutionTargetV1,
        environment_descriptor: ObjectDescriptor,
        base_environment: Environment,
        environment_generation: Revision,
        command: ExecutionCommandV1,
        runtime_argument_evidence: ExecutionRuntimeArgumentLimitV1,
        resources: ExecutionResourceAdmissionV1,
        io: ExecutionIoV1,
        timeout: ExecutionTimeoutV1,
        principal: PrincipalId,
        audit: AuditId,
    ) -> Result<Self, InvalidExecutionSpec> {
        if execution.as_bytes() == &[0; 16]
            || environment_descriptor.digest().as_bytes() == &[0; 32]
            || environment_descriptor.encoded_size() == 0
            || environment_generation.get() == 0
            || principal.as_bytes() == &[0; 16]
            || audit.as_bytes() == &[0; 16]
        {
            return Err(InvalidExecutionSpec::Unspecified);
        }
        crate::validate_descriptor_role(
            crate::DescriptorRole::SandboxEnvironment,
            &environment_descriptor,
        )?;
        if base_environment.closure().len() > MAX_EXECUTION_BASE_ENVIRONMENT_COLLECTION_ITEMS
            || base_environment.variables().len() > MAX_EXECUTION_ENVIRONMENT_ENTRIES
            || base_environment.command_search_path().len()
                > MAX_EXECUTION_BASE_ENVIRONMENT_COLLECTION_ITEMS
            || base_environment.required_features().len() > MAX_EXECUTION_BASE_ENVIRONMENT_FEATURES
        {
            return Err(InvalidExecutionSpec::BaseEnvironmentExceeded);
        }
        let base_variable_bytes =
            base_environment
                .variables()
                .iter()
                .try_fold(0_usize, |total, entry| {
                    total
                        .checked_add(entry.name().len())?
                        .checked_add(entry.value().len())
                });
        if base_variable_bytes.is_none_or(|bytes| bytes > MAX_EXECUTION_BASE_ENVIRONMENT_BYTES) {
            return Err(InvalidExecutionSpec::BaseEnvironmentExceeded);
        }
        for descriptor in base_environment.closure() {
            crate::validate_descriptor_role(crate::DescriptorRole::EnvironmentClosure, descriptor)?;
            if descriptor.digest().as_bytes() == &[0; 32] {
                return Err(InvalidExecutionSpec::Unspecified);
            }
        }
        crate::validate_required_features(base_environment.required_features())?;
        checked_environment_cbor_items(&base_environment)?;
        let expected_environment_bytes = checked_environment_encoded_size(&base_environment)?;
        let canonical_environment = crate::format::encode_environment(&base_environment);
        if canonical_environment.len() != expected_environment_bytes
            || canonical_environment.len() > MAX_EXECUTION_BASE_ENVIRONMENT_BYTES
        {
            return Err(InvalidExecutionSpec::BaseEnvironmentExceeded);
        }
        let reproduced_descriptor = crate::format::descriptor_for_bytes(
            environment_descriptor.media_type().clone(),
            &canonical_environment,
        );
        if reproduced_descriptor != environment_descriptor {
            return Err(InvalidExecutionSpec::EnvironmentDescriptorMismatch);
        }
        if runtime_argument_evidence.target() != &target {
            return Err(InvalidExecutionSpec::RuntimeArgumentEvidenceMismatch);
        }
        let output_assignment = resources.output_bytes().assignment();
        if output_assignment.digest() != target.assignment_digest()
            || output_assignment.manifest().sandbox() != target.sandbox()
            || output_assignment.manifest().incarnation() != target.incarnation()
            || output_assignment.manifest().epoch() != target.assignment_epoch()
            || output_assignment.manifest().namespace_generation() != target.namespace_generation()
            || output_assignment.manifest().environment() != &environment_descriptor
        {
            return Err(InvalidExecutionSpec::OutputReservationBindingMismatch);
        }
        if resources.parent_profile_commitment()
            != output_assignment.manifest().resource_commitment()
        {
            return Err(InvalidExecutionSpec::ParentResourceCommitmentMismatch);
        }
        let argument_envelope = ExecutionArgumentEnvelopeV1::derive(
            runtime_argument_evidence,
            &base_environment,
            &command,
        )?;
        validate_capture_limit(io.output_mode(), &resources)?;
        Ok(Self {
            execution,
            target,
            environment_descriptor,
            base_environment,
            environment_generation,
            command,
            argument_envelope,
            resources,
            io,
            timeout,
            principal,
            audit,
        })
    }

    /// Returns the durable execution identity.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the signed assignment and observed namespace target.
    #[must_use]
    pub const fn target(&self) -> &ExecutionTargetV1 {
        &self.target
    }

    /// Returns the exact descriptor of the embedded base environment.
    #[must_use]
    pub const fn environment_descriptor(&self) -> &ObjectDescriptor {
        &self.environment_descriptor
    }

    /// Returns the exact base environment used to derive effective exec state.
    #[must_use]
    pub const fn base_environment(&self) -> &Environment {
        &self.base_environment
    }

    /// Returns the logical environment generation selected at admission.
    #[must_use]
    pub const fn environment_generation(&self) -> Revision {
        self.environment_generation
    }

    /// Returns the byte-exact command and guest credential projection.
    #[must_use]
    pub const fn command(&self) -> &ExecutionCommandV1 {
        &self.command
    }

    /// Returns the derived runtime-qualified argument envelope.
    #[must_use]
    pub const fn argument_envelope(&self) -> &ExecutionArgumentEnvelopeV1 {
        &self.argument_envelope
    }

    /// Returns requested resources, admitted sublimits, and exact parent policy.
    #[must_use]
    pub const fn resources(&self) -> &ExecutionResourceAdmissionV1 {
        &self.resources
    }

    /// Returns terminal, output, disconnect, and route semantics.
    #[must_use]
    pub const fn io(&self) -> &ExecutionIoV1 {
        &self.io
    }

    /// Returns the admitted monotonic execution duration.
    #[must_use]
    pub const fn timeout(&self) -> ExecutionTimeoutV1 {
        self.timeout
    }

    /// Returns the authenticated principal bound to execution access.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    /// Returns the durable authorization audit identity.
    #[must_use]
    pub const fn audit(&self) -> AuditId {
        self.audit
    }
}

/// Defines the closed v1 observed lifecycle, including terminal loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionObservationPhaseV1 {
    /// The request exists but has no committed reservation.
    Requested,
    /// Incarnation, limits, environment, and route commitments are durable.
    Admitted,
    /// The guest is starting the command.
    Starting,
    /// The command is running.
    Running,
    /// The command exited and its exact final status is durable.
    Exited,
    /// Cancellation won before a normal exit was observed.
    Canceled,
    /// Admission or execution failed with a typed diagnostic.
    Failed,
    /// The admitted payload generation became terminally unobservable.
    Lost,
}

impl ExecutionObservationPhaseV1 {
    /// Reports whether `next` is an allowed v1 edge or an idempotent observation.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        ObservedPhase::can_transition_to(self, next)
    }

    /// Projects a v1 phase into the legacy unversioned phase vocabulary.
    ///
    /// `Lost` deliberately returns `None`: silently projecting it to `Failed`
    /// would erase the recovery distinction, while adding it to the old Serde
    /// enum would change that enum's compatibility contract.
    #[must_use]
    pub const fn legacy_projection(self) -> Option<ExecutionPhase> {
        match self {
            Self::Requested => Some(ExecutionPhase::Requested),
            Self::Admitted => Some(ExecutionPhase::Admitted),
            Self::Starting => Some(ExecutionPhase::Starting),
            Self::Running => Some(ExecutionPhase::Running),
            Self::Exited => Some(ExecutionPhase::Exited),
            Self::Canceled => Some(ExecutionPhase::Canceled),
            Self::Failed => Some(ExecutionPhase::Failed),
            Self::Lost => None,
        }
    }
}

impl ObservedPhase for ExecutionObservationPhaseV1 {
    fn can_transition_to(self, next: Self) -> bool {
        use ExecutionObservationPhaseV1 as E;
        self == next
            || matches!(
                (self, next),
                (E::Requested, E::Admitted | E::Canceled | E::Failed)
                    | (E::Admitted, E::Starting | E::Canceled | E::Failed | E::Lost)
                    | (
                        E::Starting,
                        E::Running | E::Exited | E::Canceled | E::Failed | E::Lost
                    )
                    | (E::Running, E::Exited | E::Canceled | E::Failed | E::Lost)
            )
    }
}

/// Stores one versioned, monotonically ordered execution observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionObservationV1 {
    execution: ExecutionId,
    specification_digest: ObjectDigest,
    state: ObservedState<ExecutionObservationPhaseV1>,
    terminal_result: Option<ExecutionTerminalResultV1>,
    captured_output: Option<ExecutionCapturedOutputV1>,
}

impl ExecutionObservationV1 {
    /// Constructs one versioned observation bound to an exact execution spec.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec`] for zero ordering counters, a terminal
    /// result incompatible with `phase`, or captured-output evidence that is
    /// noncanonical or exceeds `specification`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        specification: &ExecutionSpecV1,
        phase: ExecutionObservationPhaseV1,
        desired_generation: DesiredGeneration,
        sequence: ObservationSequence,
        terminal_result: Option<ExecutionTerminalResultV1>,
        captured_output: Option<ExecutionCapturedOutputV1>,
        reason: ReasonCode,
        transition_time: TransitionTime,
    ) -> Result<Self, InvalidExecutionSpec> {
        if desired_generation.get() == 0 || sequence.get() == 0 {
            return Err(InvalidExecutionSpec::InvalidObservation);
        }
        validate_terminal_result(phase, terminal_result)?;
        validate_captured_output(
            phase,
            terminal_result,
            captured_output.as_ref(),
            specification.io().output_mode(),
        )?;
        Ok(Self {
            execution: specification.execution(),
            specification_digest: crate::format::execution_spec_digest_v1(specification),
            state: ObservedState::new(phase, desired_generation, sequence, reason, transition_time),
            terminal_result,
            captured_output,
        })
    }

    /// Returns the exact execution identity whose specification was observed.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the exact execution-specification digest bound to this observation.
    #[must_use]
    pub const fn specification_digest(&self) -> ObjectDigest {
        self.specification_digest
    }

    /// Returns the versioned observed phase.
    #[must_use]
    pub const fn phase(&self) -> ExecutionObservationPhaseV1 {
        self.state.phase()
    }

    /// Returns the desired generation reconciled by this observation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.state.desired_generation()
    }

    /// Returns the strictly monotonic observation sequence.
    #[must_use]
    pub const fn sequence(&self) -> ObservationSequence {
        self.state.sequence()
    }

    /// Returns the exact outcome for a terminal phase.
    #[must_use]
    pub const fn terminal_result(&self) -> Option<ExecutionTerminalResultV1> {
        self.terminal_result
    }

    /// Returns final captured-output disposition when capture was requested.
    #[must_use]
    pub const fn captured_output(&self) -> Option<&ExecutionCapturedOutputV1> {
        self.captured_output.as_ref()
    }

    /// Returns the stable machine-readable reason.
    #[must_use]
    pub const fn reason(&self) -> &ReasonCode {
        self.state.reason()
    }

    /// Returns the diagnostic wall-clock transition time.
    #[must_use]
    pub const fn transition_time(&self) -> TransitionTime {
        self.state.transition_time()
    }

    /// Advances the observation under exact spec binding and the v1 phase graph.
    /// A terminal observation may only be reaffirmed at a newer sequence; its
    /// desired generation, phase, result, capture, reason, and time are frozen.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionObservationAdvanceError`] for a spec mismatch, stale
    /// counter, invalid edge, changed terminal fact, incompatible terminal
    /// result, or invalid captured-output evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn advance(
        &self,
        specification: &ExecutionSpecV1,
        phase: ExecutionObservationPhaseV1,
        desired_generation: DesiredGeneration,
        sequence: ObservationSequence,
        terminal_result: Option<ExecutionTerminalResultV1>,
        captured_output: Option<ExecutionCapturedOutputV1>,
        reason: ReasonCode,
        transition_time: TransitionTime,
    ) -> Result<Self, ExecutionObservationAdvanceError> {
        let specification_digest = crate::format::execution_spec_digest_v1(specification);
        if specification.execution() != self.execution
            || specification_digest != self.specification_digest
        {
            return Err(InvalidExecutionSpec::InvalidObservation.into());
        }
        validate_terminal_result(phase, terminal_result)?;
        validate_captured_output(
            phase,
            terminal_result,
            captured_output.as_ref(),
            specification.io().output_mode(),
        )?;
        if is_terminal_phase(self.phase()) {
            if terminal_result != self.terminal_result {
                return Err(InvalidExecutionSpec::InvalidTerminalResult.into());
            }
            if captured_output != self.captured_output {
                return Err(InvalidExecutionSpec::InvalidCapturedOutput.into());
            }
            if desired_generation != self.desired_generation()
                || &reason != self.reason()
                || transition_time != self.transition_time()
            {
                return Err(InvalidExecutionSpec::InvalidObservation.into());
            }
        }
        let state =
            self.state
                .advance(phase, desired_generation, sequence, reason, transition_time)?;
        Ok(Self {
            execution: self.execution,
            specification_digest: self.specification_digest,
            state,
            terminal_result,
            captured_output,
        })
    }

    /// Projects a representable v1 observation into the legacy state type.
    ///
    /// # Errors
    ///
    /// Returns [`UnrepresentableLegacyExecutionObservation`] for `Lost`; no
    /// lossy substitute is selected.
    pub fn project_legacy(
        &self,
    ) -> Result<ObservedState<ExecutionPhase>, UnrepresentableLegacyExecutionObservation> {
        let phase = self
            .phase()
            .legacy_projection()
            .ok_or(UnrepresentableLegacyExecutionObservation)?;
        Ok(ObservedState::new(
            phase,
            self.desired_generation(),
            self.sequence(),
            self.reason().clone(),
            self.transition_time(),
        ))
    }
}

/// Reports invalid execution-observation content or ordering.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExecutionObservationAdvanceError {
    /// Observation ordering or the phase edge is invalid.
    #[error(transparent)]
    Ordering(#[from] ObservationAdvanceError<ExecutionObservationPhaseV1>),
    /// Terminal or captured-output content is invalid.
    #[error(transparent)]
    Content(#[from] InvalidExecutionSpec),
}

/// Reports that a versioned execution observation has no faithful legacy form.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("lost execution observation cannot be projected into the legacy phase vocabulary")]
pub struct UnrepresentableLegacyExecutionObservation;
