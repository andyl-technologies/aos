//! Complete bounded command grammar for `aos sandbox`.

use std::fmt;

use super::execution::{
    CliIdentityV1, EndpointProofV1, ExecutionEnvironmentV1, ExecutionIoContractV1,
    ExecutionProgramV1,
};
use super::provenance::{AuditAuthorizationV1, AuthorizedResolvedMutationV1};
use super::requests::{CapabilityCommandV1, ViewMutationModeV1};
use crate::controller_query::portable::CheckedFeatureSetV1;

/// Maximum UTF-8 bytes in a project, resource, or relative selector.
pub const MAXIMUM_CLI_SELECTOR_BYTES: usize = 4 * 1024;
/// Maximum decoded bytes in an opaque resource version or cursor.
pub const MAXIMUM_CLI_OPAQUE_BYTES: usize = 4 * 1024;
/// Maximum bytes in an idempotency key.
pub const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 256;
/// Maximum arguments accepted by one execution.
pub const MAXIMUM_EXEC_ARGUMENTS: usize = aos_sandbox_core::MAX_EXECUTION_ARGUMENTS;
/// Maximum bytes in one execution argument.
pub const MAXIMUM_EXEC_ARGUMENT_BYTES: usize =
    aos_sandbox_core::MAX_EXECUTION_ARGUMENT_STRING_BYTES;
/// Maximum aggregate bytes in an execution argument vector.
pub const MAXIMUM_EXEC_ARGUMENT_VECTOR_BYTES: usize =
    aos_sandbox_core::MAX_EXECUTION_ARGUMENT_BYTES;
/// Maximum bounded tree depth.
pub const MAXIMUM_TREE_DEPTH: u16 = 1_024;
/// Maximum resources requested in one page.
pub const MAXIMUM_CLI_PAGE_SIZE: u16 = 1_024;
/// Maximum pages consumed by one CLI invocation.
pub const MAXIMUM_CLI_PAGES: u16 = 4_096;
/// Maximum normalized filters accepted by a list or event command.
pub const MAXIMUM_CLI_FILTERS: usize = 64;
/// Maximum events retained by one command invocation.
pub const MAXIMUM_CLI_EVENTS: u32 = 65_536;
/// Maximum client-side wait duration in nanoseconds.
pub const MAXIMUM_CLI_WAIT_NANOSECONDS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

/// Reports invalid bounded CLI grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidCliGrammar {
    /// A selector is empty, oversized, or contains control text.
    #[error("CLI selector is invalid")]
    InvalidSelector,
    /// A relative path is absolute, ambiguous, or oversized.
    #[error("CLI relative path is invalid")]
    InvalidRelativePath,
    /// An opaque value or idempotency key is empty or oversized.
    #[error("CLI opaque value is invalid")]
    InvalidOpaqueValue,
    /// A page, depth, or wait bound is zero or excessive.
    #[error("CLI bound is invalid")]
    InvalidBound,
    /// An execution argument vector is empty or exceeds a byte/count bound.
    #[error("CLI execution argument vector is invalid")]
    InvalidArguments,
}

/// Stores a bounded non-control UTF-8 CLI selector.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct CliSelectorV1(String);

impl CliSelectorV1 {
    /// Checks a project- or resource-scoped selector.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidSelector`] for empty, oversized,
    /// NUL-containing, or control-containing text.
    pub fn new(value: String) -> Result<Self, InvalidCliGrammar> {
        if value.is_empty()
            || value.len() > MAXIMUM_CLI_SELECTOR_BYTES
            || value.chars().any(char::is_control)
        {
            Err(InvalidCliGrammar::InvalidSelector)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the checked selector for request construction.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CliSelectorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CliSelectorV1")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Stores a bounded normalized relative byte path.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct CliRelativePathV1(Vec<u8>);

impl CliRelativePathV1 {
    /// Checks a slash-separated relative byte path.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidRelativePath`] for empty, absolute,
    /// NUL-containing, oversized, empty-component, `.` or `..` paths.
    pub fn new(value: Vec<u8>) -> Result<Self, InvalidCliGrammar> {
        let components_are_valid = value
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..");
        if value.is_empty()
            || value.len() > MAXIMUM_CLI_SELECTOR_BYTES
            || value.starts_with(b"/")
            || value.contains(&0)
            || !components_are_valid
        {
            Err(InvalidCliGrammar::InvalidRelativePath)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns normalized relative path bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CliRelativePathV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CliRelativePathV1")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

macro_rules! define_opaque_cli_value {
    ($name:ident, $summary:literal, $maximum:ident) => {
        #[doc = $summary]
        #[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Checks decoded opaque bytes from the matching CLI option.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidCliGrammar::InvalidOpaqueValue`] for empty or
            /// oversized values.
            pub fn new(value: Vec<u8>) -> Result<Self, InvalidCliGrammar> {
                if value.is_empty() || value.len() > $maximum {
                    Err(InvalidCliGrammar::InvalidOpaqueValue)
                } else {
                    Ok(Self(value))
                }
            }

            /// Returns decoded bytes for the matching public request field.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("redacted_bytes", &self.0.len())
                    .finish_non_exhaustive()
            }
        }
    };
}

define_opaque_cli_value!(
    CliResourceVersionV1,
    "Stores a decoded optimistic-concurrency resource version.",
    MAXIMUM_CLI_OPAQUE_BYTES
);
define_opaque_cli_value!(
    CliPageTokenV1,
    "Stores a decoded server-issued pagination token.",
    MAXIMUM_CLI_OPAQUE_BYTES
);
define_opaque_cli_value!(
    CliWatchCursorV1,
    "Stores a decoded server-issued watch cursor.",
    MAXIMUM_CLI_OPAQUE_BYTES
);
define_opaque_cli_value!(
    CliIdempotencyKeyV1,
    "Stores a non-logging idempotency key.",
    MAXIMUM_IDEMPOTENCY_KEY_BYTES
);

/// Stores a checked client-side polling duration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliWaitDurationV1(u64);

impl CliWaitDurationV1 {
    /// Constructs a checked polling duration.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidBound`] for zero or excessive time.
    pub const fn new(timeout_nanos: u64) -> Result<Self, InvalidCliGrammar> {
        if timeout_nanos == 0 || timeout_nanos > MAXIMUM_CLI_WAIT_NANOSECONDS {
            Err(InvalidCliGrammar::InvalidBound)
        } else {
            Ok(Self(timeout_nanos))
        }
    }

    /// Returns the checked monotonic duration.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }
}

/// Controls whether a mutation returns immediately or performs a bounded wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliWaitV1 {
    /// Returns the accepted operation without polling it.
    ReturnOperation,
    /// Polls for the checked client-side duration.
    Bounded(CliWaitDurationV1),
}

/// Stores common controls for every mutating command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationControlV1 {
    /// Supplies the idempotency key scoped by the authenticated request.
    pub idempotency_key: CliIdempotencyKeyV1,
    /// Bounds server-side operation processing independently of local waiting.
    pub operation_timeout: CliWaitDurationV1,
    /// Selects return-immediately or bounded-wait behavior.
    pub wait: CliWaitV1,
}

/// Stores one target and its required optimistic-concurrency fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationTargetV1 {
    /// Selects the target resource without changing its identity.
    pub target: CliSelectorV1,
    /// Names the exact expected resource version.
    pub expected_version: CliResourceVersionV1,
    /// Carries common idempotency and wait controls.
    pub control: MutationControlV1,
}

/// Defines bounded page consumption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliPageRequestV1 {
    /// Requests at most this many resources from each server page.
    pub page_size: CliPageSizeV1,
    /// Starts from this exact server-issued token when present.
    pub page_token: Option<CliPageTokenV1>,
    /// Stops after this many pages even if a continuation remains.
    pub maximum_pages: CliMaximumPagesV1,
}

/// Stores a checked per-page resource count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliPageSizeV1(u16);

impl CliPageSizeV1 {
    /// Checks a per-page resource count.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidBound`] for zero or excessive values.
    pub const fn new(value: u16) -> Result<Self, InvalidCliGrammar> {
        if value == 0 || value > MAXIMUM_CLI_PAGE_SIZE {
            Err(InvalidCliGrammar::InvalidBound)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the checked page size.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Stores a checked maximum page count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliMaximumPagesV1(u16);

impl CliMaximumPagesV1 {
    /// Checks an invocation-wide page count.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidBound`] for zero or excessive values.
    pub const fn new(value: u16) -> Result<Self, InvalidCliGrammar> {
        if value == 0 || value > MAXIMUM_CLI_PAGES {
            Err(InvalidCliGrammar::InvalidBound)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the checked maximum page count.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Selects the source of a declarative sandbox specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpecificationSourceV1 {
    /// Reads the specification from standard input.
    StandardInput,
    /// Reads the specification from a caller-selected local path.
    LocalPath(CliSelectorV1),
    /// Resolves a checked-in project preset through the public service.
    ProjectPreset(CliSelectorV1),
}

/// Models `aos sandbox create`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateCommandV1 {
    /// Selects the target project.
    pub project: CliSelectorV1,
    /// Selects the authorized parent when explicitly supplied.
    pub parent: Option<CliSelectorV1>,
    /// Supplies the declarative specification.
    pub specification: SpecificationSourceV1,
    /// Selects pure planning or effectful application.
    pub mode: CreateModeV1,
}

/// Selects pure creation planning or effectful application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateModeV1 {
    /// Resolves a plan without performing effects.
    DryRun,
    /// Applies the request with idempotency and bounded wait controls.
    Apply(MutationControlV1),
}

/// Models resource get, attach-exec, and other single-target reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetCommandV1 {
    /// Selects the exact established response resource type.
    pub resource_kind: CliResourceKindV1,
    /// Selects the resource.
    pub target: CliSelectorV1,
}

/// Identifies a concrete established public resource response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliResourceKindV1 {
    /// A sandbox resource.
    Sandbox,
    /// An operation resource.
    Operation,
    /// An execution resource.
    Execution,
    /// A filesystem-view resource.
    FilesystemView,
    /// An attachment resource.
    Attachment,
    /// A snapshot resource.
    Snapshot,
    /// A capability resource.
    Capability,
}

/// Models `aos sandbox list`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListCommandV1 {
    /// Limits the list to a project when present.
    pub project: Option<CliSelectorV1>,
    /// Supplies normalized public filters.
    pub filters: CliFilterSetV1,
    /// Defines bounded page consumption.
    pub page: CliPageRequestV1,
}

/// Stores a bounded normalized filter set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliFilterSetV1(Vec<CliSelectorV1>);

impl CliFilterSetV1 {
    /// Checks a normalized filter set.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidBound`] when the filter set is too large.
    pub fn new(filters: Vec<CliSelectorV1>) -> Result<Self, InvalidCliGrammar> {
        if filters.len() > MAXIMUM_CLI_FILTERS || !filters.windows(2).all(|pair| pair[0] < pair[1])
        {
            Err(InvalidCliGrammar::InvalidBound)
        } else {
            Ok(Self(filters))
        }
    }

    /// Returns normalized filters in request order.
    #[must_use]
    pub fn as_slice(&self) -> &[CliSelectorV1] {
        &self.0
    }
}

/// Models bounded `tree` and `children` traversal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeCommandV1 {
    /// Selects the authorized traversal root.
    pub root: CliSelectorV1,
    /// Limits recursive depth; `1` represents immediate children.
    pub maximum_depth: CliTreeDepthV1,
    /// Defines bounded page consumption.
    pub page: CliPageRequestV1,
}

/// Models non-recursive `aos sandbox children` traversal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildrenCommandV1 {
    /// Selects the authorized parent.
    pub parent: CliSelectorV1,
    /// Defines bounded page consumption.
    pub page: CliPageRequestV1,
}

/// Stores a checked tree traversal depth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliTreeDepthV1(u16);

impl CliTreeDepthV1 {
    /// Checks bounded tree traversal depth.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidBound`] for zero or excessive depth.
    pub const fn new(value: u16) -> Result<Self, InvalidCliGrammar> {
        if value == 0 || value > MAXIMUM_TREE_DEPTH {
            Err(InvalidCliGrammar::InvalidBound)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the checked traversal depth.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Identifies a sandbox lifecycle subcommand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleActionV1 {
    /// Starts the target sandbox.
    Start,
    /// Stops the target sandbox.
    Stop,
    /// Suspends the target sandbox.
    Suspend,
    /// Resumes the target sandbox.
    Resume,
}

/// Stores a bounded execution argument vector as raw bytes, never shell text.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionArgumentsV1(Vec<Vec<u8>>);

impl ExecutionArgumentsV1 {
    /// Checks a portable argument vector.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidArguments`] for a missing or empty
    /// executable, NUL bytes, count overflow, item overflow, or aggregate overflow.
    pub fn new(arguments: Vec<Vec<u8>>) -> Result<Self, InvalidCliGrammar> {
        if arguments.first().is_none_or(Vec::is_empty) || arguments.len() > MAXIMUM_EXEC_ARGUMENTS {
            return Err(InvalidCliGrammar::InvalidArguments);
        }
        let total = arguments.iter().try_fold(0_usize, |total, argument| {
            if argument.len() > MAXIMUM_EXEC_ARGUMENT_BYTES || argument.contains(&0) {
                return Err(InvalidCliGrammar::InvalidArguments);
            }
            total
                .checked_add(argument.len())
                .ok_or(InvalidCliGrammar::InvalidArguments)
        })?;
        if total > MAXIMUM_EXEC_ARGUMENT_VECTOR_BYTES {
            Err(InvalidCliGrammar::InvalidArguments)
        } else {
            Ok(Self(arguments))
        }
    }

    /// Returns raw argument bytes in order.
    #[must_use]
    pub fn as_slice(&self) -> &[Vec<u8>] {
        &self.0
    }
}

impl fmt::Debug for ExecutionArgumentsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: usize = self.0.iter().map(Vec::len).sum();
        formatter
            .debug_struct("ExecutionArgumentsV1")
            .field("redacted_arguments", &self.0.len())
            .field("redacted_bytes", &bytes)
            .finish_non_exhaustive()
    }
}

/// Models every `aos sandbox exec` option without inventing a shell transport.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecCommandV1 {
    /// Selects and resource-version-fences the target sandbox.
    pub sandbox: MutationTargetV1,
    /// Fences the exact active incarnation.
    pub expected_incarnation: CliIdentityV1,
    /// Supplies an argument vector or explicitly requested sandbox shell.
    pub program: ExecutionProgramV1,
    /// Supplies the canonical byte-preserving environment overlay.
    pub environment: ExecutionEnvironmentV1,
    /// Selects a relative sandbox working directory.
    pub working_directory: Option<CliRelativePathV1>,
    /// Bounds the sandbox process lifetime.
    pub execution_timeout: CliWaitDurationV1,
    /// Bounds server-side operation admission.
    pub operation_timeout: CliWaitDurationV1,
    /// Selects live streams, a sized PTY, or bounded detached capture.
    pub io: ExecutionIoContractV1,
    /// Declares required execution semantics.
    pub required_features: CheckedFeatureSetV1,
    /// Declares endpoint stream semantics.
    pub stream_features: CheckedFeatureSetV1,
    /// Carries endpoint key and possession proof without logging it.
    pub endpoint_proof: EndpointProofV1,
}

/// Selects a snapshot purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotPurposeV1 {
    /// Creates an ordinary durable snapshot.
    Durable,
    /// Creates a stable noninterfering inspection snapshot.
    Inspect,
}

/// Models `aos sandbox snapshot`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotCommandV1 {
    /// Selects and fences the source sandbox.
    pub source: MutationTargetV1,
    /// States why the snapshot is requested.
    pub purpose: SnapshotPurposeV1,
}

/// Models snapshot restore or fork.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotSourceCommandV1 {
    /// Selects the immutable source snapshot.
    pub snapshot: CliSelectorV1,
    /// Selects the destination sandbox or project context.
    pub destination: CliSelectorV1,
    /// Carries idempotency and wait controls.
    pub control: MutationControlV1,
}

/// Models reviewed sandbox deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteCommandV1 {
    /// Selects and fences the deletion root.
    pub target: MutationTargetV1,
    /// Deletes a reviewed authorized subtree in post-order.
    pub cascade: bool,
    /// Stops for hard revocation before deferred cleanup.
    pub force: bool,
}

/// Selects event delivery mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventStartV1 {
    /// Performs bounded snapshot bootstrap before live events.
    Bootstrap,
    /// Resumes strictly after this server-issued cursor.
    Resume(CliWatchCursorV1),
}

/// Selects portable resource events or separately authorized audit events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventSurfaceV1 {
    /// Shows portable public resource events.
    Public,
    /// Shows public-safe structured audit events under audit authorization.
    Audit(AuditAuthorizationV1),
}

/// Models `aos sandbox events` with bounded retention and follow policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventsCommandV1 {
    /// Supplies the normalized public event filter.
    pub filters: CliFilterSetV1,
    /// Chooses bootstrap or exact-cursor resume.
    pub start: EventStartV1,
    /// Chooses public or separately authorized audit events.
    pub surface: EventSurfaceV1,
    /// Continues following after the initial bounded response.
    pub follow: bool,
    /// Bounds accepted events before a clean resume is required.
    pub maximum_events: CliEventLimitV1,
}

/// Stores a checked event-consumption count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliEventLimitV1(u32);

impl CliEventLimitV1 {
    /// Checks an event-consumption bound.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidBound`] for zero event capacity.
    pub const fn new(value: u32) -> Result<Self, InvalidCliGrammar> {
        if value == 0 || value > MAXIMUM_CLI_EVENTS {
            Err(InvalidCliGrammar::InvalidBound)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the checked event count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Models filesystem-view subcommands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ViewCommandV1 {
    /// Creates a view from a public source selector.
    Create {
        /// Selects the source tree, snapshot, or live export.
        source: CliSelectorV1,
        /// Carries idempotency and wait controls.
        control: MutationControlV1,
    },
    /// Attaches a view at a normalized relative slot.
    Attach {
        /// Selects the view.
        view: CliSelectorV1,
        /// Selects the consumer sandbox.
        sandbox: CliSelectorV1,
        /// Selects the normalized attachment slot.
        slot: CliRelativePathV1,
        /// Selects one of all five registered mutation modes.
        mode: ViewMutationModeV1,
        /// Denies execution from the attachment.
        noexec: bool,
        /// Carries idempotency and wait controls.
        control: MutationControlV1,
    },
    /// Atomically replaces one named attachment.
    Replace {
        /// Selects and fences the existing attachment.
        attachment: MutationTargetV1,
        /// Selects the replacement view.
        replacement_view: CliSelectorV1,
    },
    /// Detaches one named attachment.
    Detach(MutationTargetV1),
    /// Lists views with bounded pagination.
    List(ListCommandV1),
}

/// Models cache subcommands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheCommandV1 {
    /// Reads bounded cache status.
    Status(ListCommandV1),
    /// Pins one public content descriptor.
    Pin {
        /// Selects the descriptor.
        object: CliSelectorV1,
        /// Selects the view holding the dependency.
        view: CliSelectorV1,
        /// Selects the attached consumer when one exists.
        attachment: Option<CliSelectorV1>,
        /// Carries idempotency and wait controls.
        control: MutationControlV1,
    },
    /// Removes one cache pin without invalidating active holders.
    Unpin {
        /// Selects the descriptor.
        object: CliSelectorV1,
        /// Selects the view holding the dependency.
        view: CliSelectorV1,
        /// Selects the attached consumer when one exists.
        attachment: Option<CliSelectorV1>,
        /// Carries idempotency and wait controls.
        control: MutationControlV1,
    },
}

/// Identifies a supported completion-script target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionShellV1 {
    /// Bash completion syntax.
    Bash,
    /// Fish completion syntax.
    Fish,
    /// Z shell completion syntax.
    Zsh,
}

/// Selects public feature-registry or node/backend capability discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilitiesCommandV1 {
    /// Prints the CLI's closed public semantic-feature registry.
    PublicApiRegistry,
    /// Queries one authorized logical node without exposing backend-local names.
    NodeBackend(CliSelectorV1),
}

/// Enumerates every RFC-0021 `aos sandbox` command path.
#[derive(Clone, Debug, PartialEq)]
pub enum SandboxCommandV1 {
    /// Carries a fully resolved, exactly fenced public mutation request.
    ResolvedMutation(AuthorizedResolvedMutationV1),
    /// `aos sandbox create`.
    Create(CreateCommandV1),
    /// `aos sandbox get`.
    Get(GetCommandV1),
    /// `aos sandbox list`.
    List(ListCommandV1),
    /// `aos sandbox tree`.
    Tree(TreeCommandV1),
    /// `aos sandbox children`.
    Children(ChildrenCommandV1),
    /// `aos sandbox ancestors`.
    Ancestors(TreeCommandV1),
    /// `aos sandbox start|stop|suspend|resume`.
    Lifecycle {
        /// Selects the lifecycle action.
        action: LifecycleActionV1,
        /// Selects and fences the sandbox.
        target: MutationTargetV1,
    },
    /// `aos sandbox exec`.
    Exec(ExecCommandV1),
    /// `aos sandbox attach-exec`.
    AttachExec(GetCommandV1),
    /// `aos sandbox cancel-exec`.
    CancelExec(MutationTargetV1),
    /// `aos sandbox snapshot`.
    Snapshot(SnapshotCommandV1),
    /// `aos sandbox delete-snapshot`.
    DeleteSnapshot(MutationTargetV1),
    /// `aos sandbox restore`.
    Restore(SnapshotSourceCommandV1),
    /// `aos sandbox fork`.
    Fork(SnapshotSourceCommandV1),
    /// `aos sandbox delete`.
    Delete(DeleteCommandV1),
    /// `aos sandbox cancel-operation`.
    CancelOperation(MutationTargetV1),
    /// `aos sandbox events`.
    Events(EventsCommandV1),
    /// `aos sandbox view ...`.
    View(ViewCommandV1),
    /// `aos sandbox cache ...`.
    Cache(CacheCommandV1),
    /// `aos sandbox capabilities` discovery.
    Capabilities(CapabilitiesCommandV1),
    /// Models the public capability-service request family.
    CapabilityService(CapabilityCommandV1),
    /// Emits shell completions for this complete grammar.
    Completions(CompletionShellV1),
    /// Applies one exactly fenced protected operator recovery action.
    OperatorRecovery(super::observation_adapter::OperatorRecoveryRequestV1),
}
