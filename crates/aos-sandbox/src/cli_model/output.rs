//! Stable output framing, redaction surface, and process exit classification.

use std::fmt::Write as _;

use super::execution::ExecutionTerminalOutcomeV1;
use super::grammar::{
    CacheCommandV1, CapabilitiesCommandV1, CliResourceKindV1, CliWaitV1, CreateCommandV1,
    CreateModeV1, SandboxCommandV1, ViewCommandV1,
};
use super::proto_json::{CheckedProtoJsonV1, StructuredOutputSchemaV1};
use super::requests::{CapabilityCommandV1, ResolvedPublicMutationV1};
use crate::controller_query::resource::CheckedOperationPhaseV1;

/// Maximum UTF-8 bytes in one rendered output record.
pub const MAXIMUM_CLI_OUTPUT_RECORD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum structured records emitted for one response page.
pub const MAXIMUM_CLI_OUTPUT_PAGE_RECORDS: u16 = 1_024;
/// Maximum rendered and framing bytes emitted for one response page.
pub const MAXIMUM_CLI_OUTPUT_PAGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum unescaped public text accepted for diagnostic rendering.
pub const MAXIMUM_PUBLIC_TEXT_SOURCE_BYTES: usize = 4 * 1024 * 1024;
/// States structured response schemas still required before CLI activation.
pub const OUTPUT_PROTO_INTEGRATION_REQUIRED: &str = "structured output contracts are source-complete; transport activation and qualification remain deliberately deferred";

/// Selects the requested CLI renderer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliOutputModeV1 {
    /// Produces human-oriented text whose layout may improve over time.
    Human,
    /// Produces one established public ProtoJSON document.
    Json,
    /// Produces one established public ProtoJSON document per line.
    JsonLines,
}

/// Defines stable record framing without retaining resource data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliOutputPlanV1 {
    /// Selects human, single-document, or line-delimited rendering.
    mode: CliOutputModeV1,
    /// Selects the established public schema used for structured records.
    schema: StructuredOutputSchemaV1,
}

impl CliOutputPlanV1 {
    /// Constructs a rendering plan if mode and schema are compatible.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOutputPlan::IncompatibleMode`] when text or an entire
    /// list document is paired with a structured framing mode it cannot use.
    pub const fn new(
        mode: CliOutputModeV1,
        schema: StructuredOutputSchemaV1,
    ) -> Result<Self, InvalidOutputPlan> {
        let compatible = match (mode, schema) {
            (CliOutputModeV1::Human, _) => true,
            (CliOutputModeV1::Json, StructuredOutputSchemaV1::CompletionScript) => false,
            (CliOutputModeV1::Json, _) => true,
            (CliOutputModeV1::JsonLines, schema) => matches!(
                schema,
                StructuredOutputSchemaV1::Sandbox
                    | StructuredOutputSchemaV1::Operation
                    | StructuredOutputSchemaV1::Execution
                    | StructuredOutputSchemaV1::FilesystemView
                    | StructuredOutputSchemaV1::Attachment
                    | StructuredOutputSchemaV1::Snapshot
                    | StructuredOutputSchemaV1::Capability
                    | StructuredOutputSchemaV1::NodeCapabilities
                    | StructuredOutputSchemaV1::Event
                    | StructuredOutputSchemaV1::SandboxTree
            ),
            _ => false,
        };
        if compatible {
            Ok(Self { mode, schema })
        } else {
            Err(InvalidOutputPlan::IncompatibleMode)
        }
    }

    /// Validates the exact response schema for a checked command.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOutputPlan`] for a command/schema mismatch, JSON Lines
    /// on a non-paged command, or structured completion output.
    pub fn for_command(
        command: &SandboxCommandV1,
        mode: CliOutputModeV1,
        schema: StructuredOutputSchemaV1,
    ) -> Result<Self, InvalidOutputPlan> {
        if command_output_schema(command, mode) != Some(schema) {
            return Err(InvalidOutputPlan::CommandSchemaMismatch);
        }
        Self::new(mode, schema)
    }

    /// Returns the checked renderer mode.
    #[must_use]
    pub const fn mode(self) -> CliOutputModeV1 {
        self.mode
    }

    /// Returns the established schema selected for structured records.
    #[must_use]
    pub const fn schema(self) -> StructuredOutputSchemaV1 {
        self.schema
    }
}

fn command_output_schema(
    command: &SandboxCommandV1,
    mode: CliOutputModeV1,
) -> Option<StructuredOutputSchemaV1> {
    use StructuredOutputSchemaV1 as S;

    let schema = match command {
        SandboxCommandV1::ResolvedMutation(value) => mutation_output_schema(value.mutation()),
        SandboxCommandV1::Create(CreateCommandV1 {
            mode: CreateModeV1::DryRun,
            ..
        }) => S::PolicyPlan,
        SandboxCommandV1::Create(CreateCommandV1 {
            mode: CreateModeV1::Apply(control),
            ..
        }) => wait_schema(control.wait, S::Sandbox),
        SandboxCommandV1::Get(value) => resource_kind_schema(value.resource_kind),
        SandboxCommandV1::List(_) => {
            if mode == CliOutputModeV1::JsonLines {
                S::Sandbox
            } else {
                S::SandboxList
            }
        }
        SandboxCommandV1::Tree(_) => S::SandboxTree,
        SandboxCommandV1::Children(_) => {
            if mode == CliOutputModeV1::JsonLines {
                S::Sandbox
            } else {
                S::ChildrenList
            }
        }
        SandboxCommandV1::Ancestors(_) => {
            if mode == CliOutputModeV1::JsonLines {
                S::Sandbox
            } else {
                S::AncestorsList
            }
        }
        SandboxCommandV1::Lifecycle { target, .. } => wait_schema(target.control.wait, S::Sandbox),
        SandboxCommandV1::Exec(value) => wait_schema(value.sandbox.control.wait, S::Execution),
        SandboxCommandV1::AttachExec(value)
            if value.resource_kind == CliResourceKindV1::Execution =>
        {
            S::Execution
        }
        SandboxCommandV1::AttachExec(_) => return None,
        SandboxCommandV1::CancelExec(_) => S::Operation,
        SandboxCommandV1::Snapshot(value) => wait_schema(value.source.control.wait, S::Snapshot),
        SandboxCommandV1::DeleteSnapshot(value) => wait_schema(value.control.wait, S::Snapshot),
        SandboxCommandV1::Restore(value) | SandboxCommandV1::Fork(value) => {
            wait_schema(value.control.wait, S::Sandbox)
        }
        SandboxCommandV1::Delete(value) => wait_schema(value.target.control.wait, S::Sandbox),
        SandboxCommandV1::CancelOperation(value) => wait_schema(value.control.wait, S::Operation),
        SandboxCommandV1::Events(_) => S::Event,
        SandboxCommandV1::View(ViewCommandV1::List(_)) => {
            if mode == CliOutputModeV1::JsonLines {
                S::FilesystemView
            } else {
                S::ViewList
            }
        }
        SandboxCommandV1::View(ViewCommandV1::Create { control, .. }) => {
            wait_schema(control.wait, S::FilesystemView)
        }
        SandboxCommandV1::View(ViewCommandV1::Attach { control, .. }) => {
            wait_schema(control.wait, S::Attachment)
        }
        SandboxCommandV1::View(ViewCommandV1::Replace { attachment, .. })
        | SandboxCommandV1::View(ViewCommandV1::Detach(attachment)) => {
            wait_schema(attachment.control.wait, S::Attachment)
        }
        SandboxCommandV1::Cache(CacheCommandV1::Status(_)) => S::CacheStatus,
        SandboxCommandV1::Cache(CacheCommandV1::Pin { control, .. })
        | SandboxCommandV1::Cache(CacheCommandV1::Unpin { control, .. }) => {
            wait_schema(control.wait, S::Operation)
        }
        SandboxCommandV1::Capabilities(CapabilitiesCommandV1::PublicApiRegistry) => {
            S::PublicFeatureRegistry
        }
        SandboxCommandV1::Capabilities(CapabilitiesCommandV1::NodeBackend(_)) => {
            S::NodeCapabilities
        }
        SandboxCommandV1::CapabilityService(value) => match value {
            CapabilityCommandV1::Inspect(_) | CapabilityCommandV1::Attenuate { .. } => {
                S::Capability
            }
            CapabilityCommandV1::Renew { mutation, .. }
            | CapabilityCommandV1::Revoke { mutation, .. } => {
                wait_schema(mutation.client_wait(), S::Capability)
            }
        },
        SandboxCommandV1::Completions(_) => S::CompletionScript,
        SandboxCommandV1::OperatorRecovery(_) => S::Operation,
    };

    let supports_json_lines = matches!(
        command,
        SandboxCommandV1::List(_)
            | SandboxCommandV1::Tree(_)
            | SandboxCommandV1::Children(_)
            | SandboxCommandV1::Ancestors(_)
            | SandboxCommandV1::Events(_)
            | SandboxCommandV1::View(ViewCommandV1::List(_))
    );
    if mode == CliOutputModeV1::JsonLines && !supports_json_lines {
        None
    } else {
        Some(schema)
    }
}

const fn resource_kind_schema(kind: CliResourceKindV1) -> StructuredOutputSchemaV1 {
    match kind {
        CliResourceKindV1::Sandbox => StructuredOutputSchemaV1::Sandbox,
        CliResourceKindV1::Operation => StructuredOutputSchemaV1::Operation,
        CliResourceKindV1::Execution => StructuredOutputSchemaV1::Execution,
        CliResourceKindV1::FilesystemView => StructuredOutputSchemaV1::FilesystemView,
        CliResourceKindV1::Attachment => StructuredOutputSchemaV1::Attachment,
        CliResourceKindV1::Snapshot => StructuredOutputSchemaV1::Snapshot,
        CliResourceKindV1::Capability => StructuredOutputSchemaV1::Capability,
    }
}

const fn wait_schema(
    wait: CliWaitV1,
    completed: StructuredOutputSchemaV1,
) -> StructuredOutputSchemaV1 {
    match wait {
        CliWaitV1::ReturnOperation => StructuredOutputSchemaV1::Operation,
        CliWaitV1::Bounded(_) => completed,
    }
}

fn mutation_output_schema(value: &ResolvedPublicMutationV1) -> StructuredOutputSchemaV1 {
    use ResolvedPublicMutationV1 as M;
    use StructuredOutputSchemaV1 as S;

    if let M::ExecutionControl(control) = value {
        return if control.returns_operation() {
            S::Operation
        } else {
            S::ExecutionControlResult
        };
    }

    let completed = match value {
        M::CreateSandbox(_)
        | M::UpdatePolicy { .. }
        | M::Lifecycle { .. }
        | M::DeleteSandbox { .. }
        | M::RestoreSnapshot { .. }
        | M::ForkSnapshot { .. } => S::Sandbox,
        M::CreateExecution(_) | M::ExecutionControl(_) => S::Execution,
        M::CreateView { .. } | M::ReleaseView { .. } => S::FilesystemView,
        M::AttachView { .. } | M::ReplaceAttachment { .. } | M::DetachView { .. } => S::Attachment,
        M::CreateSnapshot { .. } | M::DeleteSnapshot { .. } => S::Snapshot,
        M::Capability(_) => S::Capability,
        M::CachePin { .. } | M::CacheUnpin { .. } | M::CancelOperation { .. } => S::Operation,
    };
    value
        .client_wait()
        .map_or(completed, |wait| wait_schema(wait, completed))
}

/// Stores one complete checked command and its rendering contract.
#[derive(Clone, Debug, PartialEq)]
pub struct SandboxCliInvocationV1 {
    /// Selects one complete RFC-0021 command path.
    command: SandboxCommandV1,
    /// Defines stable human or structured output framing.
    output: CliOutputPlanV1,
}

impl SandboxCliInvocationV1 {
    /// Constructs a command with its command-derived output contract.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOutputPlan`] when the requested mode cannot frame the command.
    pub fn new(
        command: SandboxCommandV1,
        mode: CliOutputModeV1,
        schema: StructuredOutputSchemaV1,
    ) -> Result<Self, InvalidOutputPlan> {
        let output = CliOutputPlanV1::for_command(&command, mode, schema)?;
        Ok(Self { command, output })
    }

    /// Returns the checked command.
    #[must_use]
    pub const fn command(&self) -> &SandboxCommandV1 {
        &self.command
    }

    /// Returns the command-derived output contract.
    #[must_use]
    pub const fn output(&self) -> CliOutputPlanV1 {
        self.output
    }
}

/// Selects the process stream for one rendered record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliOutputChannelV1 {
    /// Carries requested command output.
    StandardOutput,
    /// Carries non-resource diagnostics.
    StandardError,
}

/// Stores one bounded rendered record without deriving a revealing `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct CliOutputRecordV1 {
    plan: CliOutputPlanV1,
    channel: CliOutputChannelV1,
    rendered: String,
}

impl CliOutputRecordV1 {
    /// Checks one human record while rejecting terminal-control injection.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOutputPlan::InvalidRecord`] for non-human plans, empty
    /// or oversized text, or any unescaped control character.
    pub fn human(
        plan: CliOutputPlanV1,
        channel: CliOutputChannelV1,
        rendered: String,
    ) -> Result<Self, InvalidOutputPlan> {
        let unsafe_control = rendered.chars().any(char::is_control);
        if plan.mode != CliOutputModeV1::Human
            || rendered.is_empty()
            || rendered.len() > MAXIMUM_CLI_OUTPUT_RECORD_BYTES
            || unsafe_control
        {
            Err(InvalidOutputPlan::InvalidRecord)
        } else {
            Ok(Self {
                plan,
                channel,
                rendered,
            })
        }
    }

    /// Frames a checked completion script while retaining required newlines.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOutputPlan::InvalidRecord`] unless this is the human
    /// completion-script plan or the script contains unsafe controls.
    pub fn completion_script(
        plan: CliOutputPlanV1,
        rendered: String,
    ) -> Result<Self, InvalidOutputPlan> {
        let unsafe_control = rendered
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'));
        if plan.mode != CliOutputModeV1::Human
            || plan.schema != StructuredOutputSchemaV1::CompletionScript
            || rendered.is_empty()
            || rendered.len() > MAXIMUM_CLI_OUTPUT_RECORD_BYTES
            || unsafe_control
        {
            return Err(InvalidOutputPlan::InvalidRecord);
        }
        Ok(Self {
            plan,
            channel: CliOutputChannelV1::StandardOutput,
            rendered,
        })
    }

    /// Frames already escaped public text for a human output plan.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOutputPlan::InvalidRecord`] for a structured plan.
    pub fn escaped_human(
        plan: CliOutputPlanV1,
        channel: CliOutputChannelV1,
        rendered: EscapedPublicTextV1,
    ) -> Result<Self, InvalidOutputPlan> {
        if plan.mode != CliOutputModeV1::Human {
            return Err(InvalidOutputPlan::InvalidRecord);
        }
        Ok(Self {
            plan,
            channel,
            rendered: rendered.0,
        })
    }

    /// Wraps checked established ProtoJSON on standard output.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOutputPlan::InvalidRecord`] for a human plan.
    pub fn structured(
        plan: CliOutputPlanV1,
        rendered: CheckedProtoJsonV1,
    ) -> Result<Self, InvalidOutputPlan> {
        if plan.mode == CliOutputModeV1::Human || plan.schema != rendered.schema() {
            return Err(InvalidOutputPlan::InvalidRecord);
        }
        Ok(Self {
            plan,
            channel: CliOutputChannelV1::StandardOutput,
            rendered: rendered.as_str().to_owned(),
        })
    }

    /// Returns the selected process stream.
    #[must_use]
    pub const fn channel(&self) -> CliOutputChannelV1 {
        self.channel
    }

    /// Returns the rendering contract that admitted this record.
    #[must_use]
    pub const fn plan(&self) -> CliOutputPlanV1 {
        self.plan
    }

    /// Returns the checked rendered UTF-8 record.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.rendered
    }
}

impl std::fmt::Debug for CliOutputRecordV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CliOutputRecordV1")
            .field("plan", &self.plan)
            .field("channel", &self.channel)
            .field("redacted_bytes", &self.rendered.len())
            .finish_non_exhaustive()
    }
}

/// Stores bounded text with every control character visibly escaped.
#[derive(Clone, Eq, PartialEq)]
pub struct EscapedPublicTextV1(String);

impl EscapedPublicTextV1 {
    /// Escapes controls before public terminal or log presentation.
    ///
    /// Newline, carriage return, and tab use their short escapes; every other
    /// control uses a fixed-width Unicode escape. Backslash is doubled so the
    /// representation is unambiguous; other non-control text is retained.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOutputPlan::InvalidRecord`] when source or escaped
    /// output exceeds its compiled byte ceiling.
    pub fn new(source: &str) -> Result<Self, InvalidOutputPlan> {
        if source.is_empty() || source.len() > MAXIMUM_PUBLIC_TEXT_SOURCE_BYTES {
            return Err(InvalidOutputPlan::InvalidRecord);
        }
        let mut escaped = String::with_capacity(source.len());
        for character in source.chars() {
            match character {
                '\\' => escaped.push_str("\\\\"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                character if character.is_control() => {
                    write!(&mut escaped, "\\u{{{:04x}}}", character as u32)
                        .map_err(|_| InvalidOutputPlan::InvalidRecord)?;
                }
                character => escaped.push(character),
            }
            if escaped.len() > MAXIMUM_CLI_OUTPUT_RECORD_BYTES {
                return Err(InvalidOutputPlan::InvalidRecord);
            }
        }
        Ok(Self(escaped))
    }

    /// Returns visibly escaped public text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EscapedPublicTextV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EscapedPublicTextV1")
            .field("redacted_bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Reports invalid stable output framing or rendered bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidOutputPlan {
    /// The mode cannot frame the selected established schema.
    #[error("CLI output mode is incompatible with the selected public schema")]
    IncompatibleMode,
    /// The response schema does not exactly match the selected command.
    #[error("CLI response schema does not match the selected command")]
    CommandSchemaMismatch,
    /// A rendered record violates channel, size, or framing requirements.
    #[error("CLI output record is invalid")]
    InvalidRecord,
}

/// Stores immutable per-page renderer ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliOutputPageBudgetV1 {
    maximum_records: u16,
    maximum_bytes: usize,
}

impl CliOutputPageBudgetV1 {
    /// Checks count and byte ceilings for one emitted response page.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOutputPlan::InvalidRecord`] for zero or excessive bounds.
    pub const fn new(
        maximum_records: u16,
        maximum_bytes: usize,
    ) -> Result<Self, InvalidOutputPlan> {
        if maximum_records == 0
            || maximum_records > MAXIMUM_CLI_OUTPUT_PAGE_RECORDS
            || maximum_bytes == 0
            || maximum_bytes > MAXIMUM_CLI_OUTPUT_PAGE_BYTES
        {
            Err(InvalidOutputPlan::InvalidRecord)
        } else {
            Ok(Self {
                maximum_records,
                maximum_bytes,
            })
        }
    }

    /// Returns the checked record ceiling.
    #[must_use]
    pub const fn maximum_records(self) -> u16 {
        self.maximum_records
    }

    /// Returns the checked byte ceiling.
    #[must_use]
    pub const fn maximum_bytes(self) -> usize {
        self.maximum_bytes
    }
}

/// Accumulates one response page under checked record and byte ceilings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliOutputPageReducerV1 {
    plan: CliOutputPlanV1,
    budget: CliOutputPageBudgetV1,
    records: Vec<CliOutputRecordV1>,
    rendered_bytes: usize,
}

impl CliOutputPageReducerV1 {
    /// Creates an empty bounded output page.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOutputPlan::InvalidRecord`] unless JSON is bounded to
    /// exactly one document. JSON Lines retains its independent page bound.
    pub const fn new(
        plan: CliOutputPlanV1,
        budget: CliOutputPageBudgetV1,
    ) -> Result<Self, InvalidOutputPlan> {
        if plan.mode == CliOutputModeV1::Json && budget.maximum_records != 1 {
            return Err(InvalidOutputPlan::InvalidRecord);
        }
        Ok(Self {
            plan,
            budget,
            records: Vec::new(),
            rendered_bytes: 0,
        })
    }

    /// Appends one checked record without exceeding page bounds.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOutputPlan::InvalidRecord`] before mutation on count
    /// or aggregate byte overflow.
    pub fn try_push(&mut self, record: CliOutputRecordV1) -> Result<(), InvalidOutputPlan> {
        let next_records = self
            .records
            .len()
            .checked_add(1)
            .ok_or(InvalidOutputPlan::InvalidRecord)?;
        let framing_bytes = match self.plan.mode {
            CliOutputModeV1::JsonLines => 1,
            CliOutputModeV1::Human => usize::from(!record.rendered.ends_with('\n')),
            CliOutputModeV1::Json => 0,
        };
        let record_bytes = record
            .rendered
            .len()
            .checked_add(framing_bytes)
            .ok_or(InvalidOutputPlan::InvalidRecord)?;
        let next_bytes = self
            .rendered_bytes
            .checked_add(record_bytes)
            .ok_or(InvalidOutputPlan::InvalidRecord)?;
        if record.plan != self.plan
            || next_records > usize::from(self.budget.maximum_records())
            || next_bytes > self.budget.maximum_bytes()
        {
            return Err(InvalidOutputPlan::InvalidRecord);
        }
        self.records.push(record);
        self.rendered_bytes = next_bytes;
        Ok(())
    }

    /// Returns checked records accumulated for this page.
    #[must_use]
    pub fn records(&self) -> &[CliOutputRecordV1] {
        &self.records
    }

    /// Returns aggregate rendered, separator, and line-ending bytes.
    #[must_use]
    pub const fn rendered_bytes(&self) -> usize {
        self.rendered_bytes
    }

    /// Finishes framing and returns bounded page records.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOutputPlan::InvalidRecord`] when a JSON response has
    /// not emitted its exactly one required document.
    pub fn into_records(self) -> Result<Vec<CliOutputRecordV1>, InvalidOutputPlan> {
        if self.plan.mode == CliOutputModeV1::Json && self.records.len() != 1 {
            Err(InvalidOutputPlan::InvalidRecord)
        } else {
            Ok(self.records)
        }
    }
}

/// Classifies stable public transport outcomes without backend diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicTransportOutcomeV1 {
    /// The request succeeded.
    Success,
    /// Public input was malformed.
    InvalidArgument,
    /// Authentication was missing or invalid.
    Unauthenticated,
    /// The principal lacks authority.
    PermissionDenied,
    /// The resource is absent or concealed.
    NotFound,
    /// An exact concurrency or idempotency fence conflicted.
    Conflict,
    /// The client must obtain a fresh baseline.
    ResyncRequired,
    /// Transport failed before a semantic result was known.
    Unavailable,
}

/// Classifies a completed CLI outcome independently of transport libraries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliOutcomeClassV1 {
    /// The requested command completed successfully.
    Success,
    /// Local command syntax or bounded validation failed.
    Usage,
    /// Authentication was missing or invalid.
    Unauthenticated,
    /// The authenticated principal lacks authority.
    PermissionDenied,
    /// The resource is absent or policy-concealed.
    NotFound,
    /// Optimistic concurrency, generation, assignment, or idempotency conflicted.
    Conflict,
    /// A list or watch baseline must be reacquired.
    ResyncRequired,
    /// An accepted durable operation reached a failure terminal state.
    OperationFailed,
    /// The bounded local wait elapsed while the operation may continue.
    WaitExpired,
    /// A transport failed before a semantic result was known.
    TransportFailure,
    /// A local invariant failed without exposing protected diagnostics.
    InternalFailure,
}

/// Provides stable process exit codes for automation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StableExitCodeV1 {
    /// Successful completion.
    Success = 0,
    /// Accepted operation failed.
    OperationFailed = 1,
    /// Invalid local command usage.
    Usage = 2,
    /// Missing or invalid authentication.
    Unauthenticated = 3,
    /// Authenticated but unauthorized.
    PermissionDenied = 4,
    /// Absent or concealed resource.
    NotFound = 5,
    /// Concurrency or idempotency conflict.
    Conflict = 6,
    /// Fresh list or watch bootstrap required.
    ResyncRequired = 7,
    /// Bounded wait elapsed without canceling the operation.
    WaitExpired = 9,
    /// Transport result is unknown.
    TransportFailure = 10,
    /// Non-disclosing local invariant failure.
    InternalFailure = 70,
}

impl StableExitCodeV1 {
    /// Maps one semantic outcome class to its stable process status.
    #[must_use]
    pub const fn for_outcome(outcome: CliOutcomeClassV1) -> Self {
        match outcome {
            CliOutcomeClassV1::Success => Self::Success,
            CliOutcomeClassV1::Usage => Self::Usage,
            CliOutcomeClassV1::Unauthenticated => Self::Unauthenticated,
            CliOutcomeClassV1::PermissionDenied => Self::PermissionDenied,
            CliOutcomeClassV1::NotFound => Self::NotFound,
            CliOutcomeClassV1::Conflict => Self::Conflict,
            CliOutcomeClassV1::ResyncRequired => Self::ResyncRequired,
            CliOutcomeClassV1::OperationFailed => Self::OperationFailed,
            CliOutcomeClassV1::WaitExpired => Self::WaitExpired,
            CliOutcomeClassV1::TransportFailure => Self::TransportFailure,
            CliOutcomeClassV1::InternalFailure => Self::InternalFailure,
        }
    }

    /// Returns the stable operating-system process status.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Maps a closed public transport result to a stable status.
    #[must_use]
    pub const fn for_transport(outcome: PublicTransportOutcomeV1) -> Self {
        match outcome {
            PublicTransportOutcomeV1::Success => Self::Success,
            PublicTransportOutcomeV1::InvalidArgument => Self::Usage,
            PublicTransportOutcomeV1::Unauthenticated => Self::Unauthenticated,
            PublicTransportOutcomeV1::PermissionDenied => Self::PermissionDenied,
            PublicTransportOutcomeV1::NotFound => Self::NotFound,
            PublicTransportOutcomeV1::Conflict => Self::Conflict,
            PublicTransportOutcomeV1::ResyncRequired => Self::ResyncRequired,
            PublicTransportOutcomeV1::Unavailable => Self::TransportFailure,
        }
    }

    /// Maps a checked operation phase, preserving pending acceptance as success.
    #[must_use]
    pub const fn for_operation(phase: CheckedOperationPhaseV1) -> Self {
        match phase {
            CheckedOperationPhaseV1::Succeeded => Self::Success,
            CheckedOperationPhaseV1::FailedBeforeCommit
            | CheckedOperationPhaseV1::CanceledBeforeCommit
            | CheckedOperationPhaseV1::CommittedWithResidualCleanup
            | CheckedOperationPhaseV1::PermanentlyBlocked => Self::OperationFailed,
            CheckedOperationPhaseV1::Accepted
            | CheckedOperationPhaseV1::Preparing
            | CheckedOperationPhaseV1::Committing
            | CheckedOperationPhaseV1::Committed => Self::Success,
        }
    }

    /// Maps an exact terminal execution outcome.
    #[must_use]
    pub const fn for_execution(outcome: ExecutionTerminalOutcomeV1) -> Self {
        match outcome {
            ExecutionTerminalOutcomeV1::ExitCode(0) => Self::Success,
            ExecutionTerminalOutcomeV1::ExitCode(_)
            | ExecutionTerminalOutcomeV1::Signal(_)
            | ExecutionTerminalOutcomeV1::Lost => Self::OperationFailed,
        }
    }
}

/// Preserves an exact execution result alongside its portable shell status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StableExecutionExitV1 {
    terminal: ExecutionTerminalOutcomeV1,
    shell_status: u8,
}

impl StableExecutionExitV1 {
    /// Projects one exact execution terminal result without discarding it.
    #[must_use]
    pub const fn new(terminal: ExecutionTerminalOutcomeV1) -> Self {
        let shell_status = match terminal {
            ExecutionTerminalOutcomeV1::ExitCode(0) => 0,
            ExecutionTerminalOutcomeV1::ExitCode(code) if code > 0 && code <= 125 => code as u8,
            ExecutionTerminalOutcomeV1::ExitCode(_) | ExecutionTerminalOutcomeV1::Lost => 1,
            ExecutionTerminalOutcomeV1::Signal(signal) => 128 + signal.posix_number(),
        };
        Self {
            terminal,
            shell_status,
        }
    }

    /// Returns the exact remote exit code, signal, or loss classification.
    #[must_use]
    pub const fn terminal(self) -> ExecutionTerminalOutcomeV1 {
        self.terminal
    }

    /// Returns the portable shell-compatible process status.
    #[must_use]
    pub const fn shell_status(self) -> i32 {
        self.shell_status as i32
    }
}
