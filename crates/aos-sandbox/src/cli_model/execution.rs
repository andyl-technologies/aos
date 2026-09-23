//! Lossless bounded execution, terminal, signal, and result grammar.

use std::fmt;

use super::grammar::{
    CliIdempotencyKeyV1, CliRelativePathV1, CliResourceVersionV1, CliWaitDurationV1, CliWaitV1,
    ExecutionArgumentsV1, InvalidCliGrammar,
};
use crate::controller_query::portable::CheckedFeatureSetV1;

/// Maximum environment rows supplied to one execution.
pub const MAXIMUM_EXEC_ENVIRONMENT: usize = aos_sandbox_core::MAX_EXECUTION_ENVIRONMENT_ENTRIES;
/// Maximum bytes in one environment name.
pub const MAXIMUM_EXEC_ENVIRONMENT_NAME_BYTES: usize =
    aos_sandbox_core::MAX_EXECUTION_ENVIRONMENT_NAME_BYTES;
/// Maximum bytes in one environment value.
pub const MAXIMUM_EXEC_ENVIRONMENT_VALUE_BYTES: usize =
    aos_sandbox_core::MAX_EXECUTION_ENVIRONMENT_VALUE_BYTES;
/// Maximum aggregate environment bytes.
pub const MAXIMUM_EXEC_ENVIRONMENT_BYTES: usize = aos_sandbox_core::MAX_EXECUTION_ENVIRONMENT_BYTES;
/// Maximum detached output capture bytes.
pub const MAXIMUM_EXEC_CAPTURE_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum public-key or proof bytes used for endpoint admission.
pub const MAXIMUM_ENDPOINT_PROOF_BYTES: usize = 64 * 1024;
/// States execution fields that require public proto integration before use.
pub const EXECUTION_REQUEST_INTEGRATION_REQUIRED: &str = "execution request and terminal-result contracts are source-complete; transport activation and qualification remain deliberately deferred";

/// Stores one nonzero exact 128-bit public resource identity.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CliIdentityV1([u8; 16]);

impl CliIdentityV1 {
    /// Checks a fixed-width public identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidOpaqueValue`] for the zero sentinel.
    pub fn new(value: [u8; 16]) -> Result<Self, InvalidCliGrammar> {
        if value == [0; 16] {
            Err(InvalidCliGrammar::InvalidOpaqueValue)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns exact identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for CliIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CliIdentityV1(<redacted>)")
    }
}

/// Stores a canonical POSIX environment variable.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExecutionEnvironmentVariableV1 {
    name: String,
    value: Vec<u8>,
}

impl ExecutionEnvironmentVariableV1 {
    /// Checks one environment row without interpreting its value as text.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidArguments`] for a non-portable name,
    /// a NUL byte, or an oversized name/value.
    pub fn new(name: String, value: Vec<u8>) -> Result<Self, InvalidCliGrammar> {
        let name_is_valid = !name.is_empty()
            && name.len() <= MAXIMUM_EXEC_ENVIRONMENT_NAME_BYTES
            && name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
            });
        if !name_is_valid
            || value.len() > MAXIMUM_EXEC_ENVIRONMENT_VALUE_BYTES
            || value.contains(&0)
            || name.len() + 1 + value.len() + 1 > aos_sandbox_core::MAX_EXECUTION_STRING_BYTES
        {
            Err(InvalidCliGrammar::InvalidArguments)
        } else {
            Ok(Self { name, value })
        }
    }

    /// Returns the portable variable name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns opaque variable bytes to the public request adapter.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl fmt::Debug for ExecutionEnvironmentVariableV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionEnvironmentVariableV1")
            .field("name", &self.name)
            .field("redacted_value_bytes", &self.value.len())
            .finish()
    }
}

/// Stores a bounded canonical environment sorted by name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionEnvironmentV1(Vec<ExecutionEnvironmentVariableV1>);

impl ExecutionEnvironmentV1 {
    /// Checks count, aggregate bytes, order, and uniqueness.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidArguments`] for an oversized or
    /// noncanonical environment.
    pub fn new(values: Vec<ExecutionEnvironmentVariableV1>) -> Result<Self, InvalidCliGrammar> {
        let bytes = values.iter().try_fold(0_usize, |total, value| {
            total
                .checked_add(value.name.len())
                .and_then(|sum| sum.checked_add(value.value.len()))
                .ok_or(InvalidCliGrammar::InvalidArguments)
        })?;
        if values.len() > MAXIMUM_EXEC_ENVIRONMENT
            || bytes > MAXIMUM_EXEC_ENVIRONMENT_BYTES
            || !values.windows(2).all(|pair| pair[0].name < pair[1].name)
        {
            Err(InvalidCliGrammar::InvalidArguments)
        } else {
            Ok(Self(values))
        }
    }

    /// Returns canonical environment rows.
    #[must_use]
    pub fn as_slice(&self) -> &[ExecutionEnvironmentVariableV1] {
        &self.0
    }
}

/// Selects direct arguments or an explicitly requested sandbox shell.
#[derive(Clone, Eq, PartialEq)]
pub enum ExecutionProgramV1 {
    /// Executes the exact argument vector without a shell.
    Direct(ExecutionArgumentsV1),
    /// Passes bounded script bytes to a sandbox-resident shell.
    SandboxShell(ExecutionShellScriptV1),
}

/// Stores explicitly requested bounded sandbox-shell input.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionShellScriptV1(Vec<u8>);

impl ExecutionShellScriptV1 {
    /// Checks byte-preserving shell input without interpreting it client-side.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidArguments`] for NUL-containing or
    /// oversized script bytes.
    pub fn new(script: Vec<u8>) -> Result<Self, InvalidCliGrammar> {
        if script.is_empty()
            || script.len() > super::grammar::MAXIMUM_EXEC_ARGUMENT_BYTES
            || script.contains(&0)
        {
            Err(InvalidCliGrammar::InvalidArguments)
        } else {
            Ok(Self(script))
        }
    }

    /// Returns exact shell bytes to the public request adapter.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ExecutionShellScriptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionShellScriptV1")
            .field("redacted_bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl ExecutionProgramV1 {
    /// Checks explicitly requested shell input.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidArguments`] for NUL-containing or
    /// oversized script bytes.
    pub fn sandbox_shell(script: Vec<u8>) -> Result<Self, InvalidCliGrammar> {
        Ok(Self::SandboxShell(ExecutionShellScriptV1::new(script)?))
    }
}

impl fmt::Debug for ExecutionProgramV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(arguments) => arguments.fmt(formatter),
            Self::SandboxShell(script) => script.fmt(formatter),
        }
    }
}

/// Stores a nonzero detached capture limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionCaptureLimitV1(u64);

impl ExecutionCaptureLimitV1 {
    /// Checks a detached capture limit.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidBound`] for zero or excessive bytes.
    pub const fn new(bytes: u64) -> Result<Self, InvalidCliGrammar> {
        if bytes == 0 || bytes > MAXIMUM_EXEC_CAPTURE_BYTES {
            Err(InvalidCliGrammar::InvalidBound)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns the checked capture-byte ceiling.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }
}

/// Selects one complete execution I/O contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionIoContractV1 {
    /// Streams noninteractive standard channels.
    Stream,
    /// Allocates a live resizable PTY canceled on disconnect.
    Pty {
        /// Supplies the initial terminal dimensions.
        initial_size: PtySizeV1,
    },
    /// Runs detached and captures bounded historical output.
    Detached(ExecutionCaptureLimitV1),
}

/// Stores a complete lossless execution creation request.
#[derive(Clone, Debug, PartialEq)]
pub struct CreateExecutionCommandV1 {
    /// Names the sandbox after authorized selector resolution.
    pub sandbox_id: CliIdentityV1,
    /// Supplies every incarnation-specific mutation fence.
    pub mutation: ExecutionMutationFenceV1,
    /// Supplies direct arguments or explicit shell semantics.
    pub program: ExecutionProgramV1,
    /// Supplies a canonical environment overlay.
    pub environment: ExecutionEnvironmentV1,
    /// Selects a relative working directory.
    pub working_directory: Option<CliRelativePathV1>,
    /// Bounds the sandbox process lifetime independently of RPC admission.
    pub execution_timeout: CliWaitDurationV1,
    /// Selects stream, PTY, or detached capture semantics.
    pub io: ExecutionIoContractV1,
    /// Declares negotiated endpoint stream features.
    pub stream_features: CheckedFeatureSetV1,
    /// Carries endpoint public-key and possession proof material.
    pub endpoint_proof: EndpointProofV1,
}

/// Stores every required incarnation-specific execution mutation fence.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionMutationFenceV1 {
    expected_resource_version: CliResourceVersionV1,
    expected_incarnation: CliIdentityV1,
    operation_timeout: CliWaitDurationV1,
    required_features: CheckedFeatureSetV1,
    idempotency_key: CliIdempotencyKeyV1,
    client_wait: CliWaitV1,
}

impl ExecutionMutationFenceV1 {
    /// Constructs an exact execution fence inside an authenticated adapter.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_authenticated(
        _provenance: &super::provenance::RequestProvenanceV1,
        expected_resource_version: CliResourceVersionV1,
        expected_incarnation: CliIdentityV1,
        operation_timeout: CliWaitDurationV1,
        required_features: CheckedFeatureSetV1,
        idempotency_key: CliIdempotencyKeyV1,
        client_wait: CliWaitV1,
    ) -> Self {
        Self {
            expected_resource_version,
            expected_incarnation,
            operation_timeout,
            required_features,
            idempotency_key,
            client_wait,
        }
    }

    /// Returns independent local return-or-wait behavior.
    #[must_use]
    pub const fn client_wait(&self) -> CliWaitV1 {
        self.client_wait
    }

    /// Returns the exact sandbox resource-version fence.
    #[must_use]
    pub(crate) const fn expected_resource_version(&self) -> &CliResourceVersionV1 {
        &self.expected_resource_version
    }

    /// Returns the exact active incarnation fence.
    #[must_use]
    pub(crate) const fn expected_incarnation(&self) -> CliIdentityV1 {
        self.expected_incarnation
    }

    /// Returns the bounded server operation timeout.
    #[must_use]
    pub(crate) const fn operation_timeout(&self) -> CliWaitDurationV1 {
        self.operation_timeout
    }

    /// Returns the canonical required execution features.
    #[must_use]
    pub(crate) const fn required_features(&self) -> &CheckedFeatureSetV1 {
        &self.required_features
    }

    /// Returns the idempotency key to the authenticated adapter.
    #[must_use]
    pub(crate) const fn idempotency_key(&self) -> &CliIdempotencyKeyV1 {
        &self.idempotency_key
    }
}

/// Stores bounded endpoint admission proof bytes without revealing `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct EndpointProofV1 {
    public_key: Vec<u8>,
    proof: Vec<u8>,
}

impl EndpointProofV1 {
    /// Checks public-key and proof byte bounds.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidOpaqueValue`] for empty or oversized values.
    pub fn new(public_key: Vec<u8>, proof: Vec<u8>) -> Result<Self, InvalidCliGrammar> {
        if public_key.is_empty()
            || proof.is_empty()
            || public_key.len() > MAXIMUM_ENDPOINT_PROOF_BYTES
            || proof.len() > MAXIMUM_ENDPOINT_PROOF_BYTES
        {
            Err(InvalidCliGrammar::InvalidOpaqueValue)
        } else {
            Ok(Self { public_key, proof })
        }
    }

    /// Returns public-key bytes to the request adapter.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns possession-proof bytes to the request adapter.
    #[must_use]
    pub(crate) fn proof(&self) -> &[u8] {
        &self.proof
    }
}

impl fmt::Debug for EndpointProofV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointProofV1")
            .field("public_key_bytes", &self.public_key.len())
            .field("redacted_proof_bytes", &self.proof.len())
            .finish_non_exhaustive()
    }
}

/// Stores a nonzero PTY size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PtySizeV1 {
    /// Terminal rows.
    rows: u16,
    /// Terminal columns.
    columns: u16,
}

impl PtySizeV1 {
    /// Checks nonzero row and column counts.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidBound`] for a zero dimension.
    pub const fn new(rows: u16, columns: u16) -> Result<Self, InvalidCliGrammar> {
        if rows == 0 || columns == 0 {
            Err(InvalidCliGrammar::InvalidBound)
        } else {
            Ok(Self { rows, columns })
        }
    }

    /// Returns checked terminal rows.
    #[must_use]
    pub const fn rows(self) -> u16 {
        self.rows
    }

    /// Returns checked terminal columns.
    #[must_use]
    pub const fn columns(self) -> u16 {
        self.columns
    }
}

/// Identifies portable execution signals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionSignalV1 {
    /// Hangup.
    Hangup,
    /// Interactive interrupt.
    Interrupt,
    /// Interactive quit.
    Quit,
    /// Graceful termination.
    Terminate,
    /// Immediate kill.
    Kill,
    /// User-defined signal one.
    User1,
    /// User-defined signal two.
    User2,
}

impl ExecutionSignalV1 {
    /// Returns the portable POSIX signal number used for shell status projection.
    #[must_use]
    pub const fn posix_number(self) -> u8 {
        match self {
            Self::Hangup => 1,
            Self::Interrupt => 2,
            Self::Quit => 3,
            Self::Kill => 9,
            Self::User1 => 10,
            Self::User2 => 12,
            Self::Terminate => 15,
        }
    }
}

/// Models follow-up execution control without shell or numeric-signal ambiguity.
#[derive(Clone, Debug, PartialEq)]
pub enum ExecutionControlCommandV1 {
    /// Attaches to a live execution endpoint.
    Attach {
        /// Selects the execution.
        execution: CliIdentityV1,
        /// Proves custody of the OpenSSH key to be certified for this attach.
        endpoint_proof: EndpointProofV1,
        /// Supplies the full authenticated incarnation mutation fence.
        mutation: ExecutionMutationFenceV1,
    },
    /// Resizes a live PTY.
    Resize {
        /// Selects the execution.
        execution: CliIdentityV1,
        /// Supplies the new checked terminal size.
        size: PtySizeV1,
        /// Supplies the full authenticated incarnation mutation fence.
        mutation: ExecutionMutationFenceV1,
    },
    /// Sends one closed portable signal.
    Signal {
        /// Selects the live execution endpoint.
        execution: CliIdentityV1,
        /// Supplies the closed signal.
        signal: ExecutionSignalV1,
        /// Supplies the full authenticated incarnation mutation fence.
        mutation: ExecutionMutationFenceV1,
    },
    /// Explicitly cancels an execution operation.
    Cancel {
        /// Names the execution being canceled.
        execution: CliIdentityV1,
        /// Names the sandbox whose active incarnation owns the execution.
        sandbox_id: CliIdentityV1,
        /// Supplies the full authenticated sandbox/incarnation mutation fence.
        mutation: ExecutionMutationFenceV1,
    },
}

impl ExecutionControlCommandV1 {
    /// Reports whether this control returns an operation.
    #[must_use]
    pub const fn returns_operation(&self) -> bool {
        true
    }
}

/// Represents an exact terminal execution outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionTerminalOutcomeV1 {
    /// The process exited normally with its exact code.
    ExitCode(i32),
    /// The process terminated from one closed signal.
    Signal(ExecutionSignalV1),
    /// Authority or node loss prevented a process result.
    Lost,
}

impl ExecutionTerminalOutcomeV1 {
    /// Converts the exact terminal classification into established public fields.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidArguments`] when the timestamp is
    /// noncanonical or the public reason contains control characters or is oversized.
    pub fn to_proto(
        self,
        exited_at: aos_proto::aos::sandbox::v1::Timestamp,
        safe_reason: String,
    ) -> Result<aos_proto::aos::sandbox::v1::ExecutionResult, InvalidCliGrammar> {
        if !(-62_135_596_800..=253_402_300_799).contains(&exited_at.seconds)
            || exited_at.nanoseconds >= 1_000_000_000
            || safe_reason.len() > 16 * 1024
            || safe_reason.chars().any(char::is_control)
        {
            return Err(InvalidCliGrammar::InvalidArguments);
        }
        let (exit_code, termination_kind, signal) = match self {
            Self::ExitCode(code) => (code, 1, 0),
            Self::Signal(signal) => (0, 2, execution_signal_proto(signal)),
            Self::Lost => (0, 3, 0),
        };
        Ok(aos_proto::aos::sandbox::v1::ExecutionResult {
            exit_code,
            termination_reason: safe_reason,
            exited_at: exited_at.into(),
            termination_kind: termination_kind.into(),
            signal: signal.into(),
            ..Default::default()
        })
    }

    /// Decodes the exact public terminal classification without inferring from text.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidArguments`] for an unspecified or
    /// inconsistent termination kind, signal, or exit-code combination.
    pub fn try_from_proto(
        value: &aos_proto::aos::sandbox::v1::ExecutionResult,
    ) -> Result<Self, InvalidCliGrammar> {
        let timestamp = value
            .exited_at
            .as_option()
            .ok_or(InvalidCliGrammar::InvalidArguments)?;
        if !(-62_135_596_800..=253_402_300_799).contains(&timestamp.seconds)
            || timestamp.nanoseconds >= 1_000_000_000
            || value.termination_reason.len() > 16 * 1024
            || value.termination_reason.chars().any(char::is_control)
        {
            return Err(InvalidCliGrammar::InvalidArguments);
        }
        match (
            value.termination_kind.to_i32(),
            value.signal.to_i32(),
            value.exit_code,
        ) {
            (1, 0, code) => Ok(Self::ExitCode(code)),
            (2, signal, 0) => execution_signal_from_proto(signal)
                .map(Self::Signal)
                .ok_or(InvalidCliGrammar::InvalidArguments),
            (3, 0, 0) => Ok(Self::Lost),
            _ => Err(InvalidCliGrammar::InvalidArguments),
        }
    }
}

const fn execution_signal_proto(value: ExecutionSignalV1) -> i32 {
    match value {
        ExecutionSignalV1::Hangup => 1,
        ExecutionSignalV1::Interrupt => 2,
        ExecutionSignalV1::Quit => 3,
        ExecutionSignalV1::Terminate => 4,
        ExecutionSignalV1::Kill => 5,
        ExecutionSignalV1::User1 => 6,
        ExecutionSignalV1::User2 => 7,
    }
}

const fn execution_signal_from_proto(value: i32) -> Option<ExecutionSignalV1> {
    match value {
        1 => Some(ExecutionSignalV1::Hangup),
        2 => Some(ExecutionSignalV1::Interrupt),
        3 => Some(ExecutionSignalV1::Quit),
        4 => Some(ExecutionSignalV1::Terminate),
        5 => Some(ExecutionSignalV1::Kill),
        6 => Some(ExecutionSignalV1::User1),
        7 => Some(ExecutionSignalV1::User2),
        _ => None,
    }
}
