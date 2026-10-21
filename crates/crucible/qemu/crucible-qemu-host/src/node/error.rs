//! Scheduler-facing QEMU node channel roles and errors.

use std::borrow::Cow;
use std::fmt;
use std::time::Duration;

use crucible_engine::owned_decode::DecodeAdmissionError;
use crucible_engine::{BackendError, BackendOperationalCause, BackendOperationalFailureKind};
use crucible_host_resources::host_supervision::{HostOperationState, HostSupervisionError};
use thiserror::Error;

use crate::{
    BoundedSchedulerPreemptionError, QemuAsyncDriverError, QemuNodeRunStatus, QemuShutdownError,
    QemuShutdownReport,
};

/// Process-control states that cannot safely admit a new pidfd adversary.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum QemuBoundedSchedulerPreemptionTargetError {
    /// The QEMU process is parented and reaped by a retained outer lifecycle.
    #[error("the QEMU process is externally owned")]
    ExternallyOwned,
    /// The directly owned QEMU child has already been reaped.
    #[error("the directly owned QEMU process was already reaped")]
    AlreadyReaped,
}

/// The role assigned to one QEMU node channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QemuNodeChannelPlane {
    /// Plugin IPC control carries setup and teardown messages only.
    PluginIpcControl,
    /// Shared memory carries all per-quantum timing and frame data.
    ShmemHotPath,
    /// QMP carries out-of-band machine-control commands.
    QmpMachineControl,
}

impl fmt::Display for QemuNodeChannelPlane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PluginIpcControl => f.write_str("plugin IPC control"),
            Self::ShmemHotPath => f.write_str("shmem hot path"),
            Self::QmpMachineControl => f.write_str("QMP machine control"),
        }
    }
}

/// Retains a fingerprint protocol or component-capture failure without formatting.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum QemuFingerprintSampleError {
    /// The actual shared-memory sample violates its protocol contract.
    #[error("{source}")]
    Protocol {
        /// Original shared-memory validation failure.
        #[source]
        source: crucible_qemu_shmem::FingerprintSampleError,
    },
    /// The latest published sample has not reached the current boundary.
    #[error(
        "black-box fingerprint sample at icount {sample_icount} is behind current boundary {current_icount}"
    )]
    BehindBoundary {
        /// Actual sample coordinate, retained without another capture request.
        sample_icount: u64,
        /// Actual node boundary requiring a matching sample.
        current_icount: u64,
    },
    /// The latest published sample is beyond the current node boundary.
    #[error(
        "black-box fingerprint sample at icount {sample_icount} is ahead of current boundary {current_icount}"
    )]
    AheadOfBoundary {
        /// Actual sample coordinate that cannot identify this boundary.
        sample_icount: u64,
        /// Actual node boundary requiring a matching sample.
        current_icount: u64,
    },
    /// The plugin reported failed component captures in its actual sample.
    #[error("black-box fingerprint sample has component failure mask {mask:#x}")]
    ComponentFailures {
        /// Complete failure bitset, retained without interpreting unknown bits.
        mask: u32,
    },
}

/// Reports a channel-local operation error before node-plane context is attached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuNodeChannelError {
    /// Operation being attempted on the channel.
    pub operation: &'static str,
    /// Authored detail, borrowed for static text and empty for typed causes.
    pub message: Cow<'static, str>,
    /// Timeout budget when this channel error came from a bounded await timeout.
    pub timeout: Option<Duration>,
    /// Whether the operation may be retried without republishing its request.
    pub retryable: bool,
    detail: ChannelFailureDetail,
}

/// Retains typed causes inline; shared decode refusals keep their original allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ChannelFailureDetail {
    Message,
    Supervision(HostSupervisionError),
    DecodeAdmission(DecodeAdmissionError),
    FingerprintSample(QemuFingerprintSampleError),
    MappedRegionAccess(crucible_qemu_shmem::MappedSetupRegionAccessError),
    QuantumNodeSlot {
        operation: &'static str,
        source: crucible_qemu_shmem::NodeSlotError,
    },
}

impl QemuNodeChannelError {
    /// Creates a channel operation error without copying its diagnostic.
    ///
    /// Static text is borrowed. An owned message retains its allocation and
    /// still requires separate admission before the caller constructs it.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            operation,
            message: message.into(),
            timeout: None,
            retryable: false,
            detail: ChannelFailureDetail::Message,
        }
    }

    /// Creates a transient channel error for a request that remains in flight.
    #[must_use]
    pub fn retryable(operation: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            operation,
            message: message.into(),
            timeout: None,
            retryable: true,
            detail: ChannelFailureDetail::Message,
        }
    }

    /// Creates a channel error classified as a bounded await timeout.
    #[must_use]
    pub fn bounded_await_timeout(
        operation: &'static str,
        message: impl Into<Cow<'static, str>>,
        timeout: Duration,
    ) -> Self {
        Self {
            operation,
            message: message.into(),
            timeout: Some(timeout),
            retryable: false,
            detail: ChannelFailureDetail::Message,
        }
    }

    /// Retains a typed operational refusal without formatting a diagnostic.
    ///
    /// This carries the original cause and issues no operation or return authority.
    #[must_use]
    pub fn operational_supervision(operation: &'static str, source: HostSupervisionError) -> Self {
        Self {
            operation,
            message: Cow::Borrowed(""),
            timeout: None,
            retryable: false,
            detail: ChannelFailureDetail::Supervision(source),
        }
    }

    /// Returns the original typed supervision refusal, when present.
    #[must_use]
    pub const fn operational_supervision_source(&self) -> Option<HostSupervisionError> {
        match self.detail {
            ChannelFailureDetail::Supervision(source) => Some(source),
            _ => None,
        }
    }

    /// Retains the actual finite decode-account refusal without formatting it.
    ///
    /// The existing shared cause keeps its original allocation. This grants no
    /// replacement capacity or operation authority.
    #[must_use]
    pub fn artifact_decode_admission(
        operation: &'static str,
        source: DecodeAdmissionError,
    ) -> Self {
        Self {
            operation,
            message: Cow::Borrowed(""),
            timeout: None,
            retryable: false,
            detail: ChannelFailureDetail::DecodeAdmission(source),
        }
    }

    /// Returns the original shared decode-account refusal, when present.
    #[must_use]
    pub const fn artifact_decode_admission_source(&self) -> Option<&DecodeAdmissionError> {
        match &self.detail {
            ChannelFailureDetail::DecodeAdmission(source) => Some(source),
            _ => None,
        }
    }

    /// Retains an actual fingerprint failure without allocating its diagnostic.
    ///
    /// Only a sample behind the current boundary remains retryable. This
    /// classification issues no fresh capture request or publication authority.
    #[must_use]
    pub fn fingerprint_sample(operation: &'static str, source: QemuFingerprintSampleError) -> Self {
        Self {
            operation,
            message: Cow::Borrowed(""),
            timeout: None,
            retryable: matches!(source, QemuFingerprintSampleError::BehindBoundary { .. }),
            detail: ChannelFailureDetail::FingerprintSample(source),
        }
    }

    /// Returns the original fingerprint failure, when present.
    #[must_use]
    pub const fn fingerprint_sample_source(&self) -> Option<QemuFingerprintSampleError> {
        match self.detail {
            ChannelFailureDetail::FingerprintSample(source) => Some(source),
            _ => None,
        }
    }

    /// Retains the mapped quantum adapter's actual region-access refusal.
    ///
    /// The existing adapter diagnostic remains unchanged. The cause retains
    /// its original coordinates without allocating a replacement message.
    #[must_use]
    pub fn mapped_region_access(
        operation: &'static str,
        source: crucible_qemu_shmem::MappedSetupRegionAccessError,
    ) -> Self {
        Self {
            operation,
            message: Cow::Borrowed(""),
            timeout: None,
            retryable: false,
            detail: ChannelFailureDetail::MappedRegionAccess(source),
        }
    }

    /// Returns the original mapped-region access failure, when present.
    #[must_use]
    pub const fn mapped_region_access_source(
        &self,
    ) -> Option<&crucible_qemu_shmem::MappedSetupRegionAccessError> {
        match &self.detail {
            ChannelFailureDetail::MappedRegionAccess(source) => Some(source),
            _ => None,
        }
    }

    /// Retains a quantum slot refusal without allocating replacement text.
    ///
    /// Only an occupied or changed publication permits polling the same
    /// pending request again. This never republishes its ceiling or wake.
    pub(crate) fn quantum_node_slot(
        operation: &'static str,
        source: crucible_qemu_shmem::NodeSlotError,
    ) -> Self {
        Self {
            operation: "qemu_quantum_shmem_hot_path",
            message: Cow::Borrowed(""),
            timeout: None,
            retryable: matches!(
                source,
                crucible_qemu_shmem::NodeSlotError::NodeReportChanged { .. }
                    | crucible_qemu_shmem::NodeSlotError::AdvancePublicationOccupied { .. }
            ),
            detail: ChannelFailureDetail::QuantumNodeSlot { operation, source },
        }
    }

    /// Returns the actual quantum slot refusal without formatting its coordinates.
    #[must_use]
    pub const fn quantum_node_slot_source(&self) -> Option<&crucible_qemu_shmem::NodeSlotError> {
        match &self.detail {
            ChannelFailureDetail::QuantumNodeSlot { source, .. } => Some(source),
            _ => None,
        }
    }

    /// Returns the bounded await timeout that caused this channel failure.
    #[must_use]
    pub const fn bounded_timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Returns whether the same in-flight operation may be polled again.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }
}

impl fmt::Display for QemuNodeChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            match &self.detail {
                ChannelFailureDetail::Supervision(source) => {
                    return write!(formatter, "{} failed: {source}", self.operation);
                }
                ChannelFailureDetail::DecodeAdmission(source) => {
                    return write!(formatter, "{} failed: {source}", self.operation);
                }
                ChannelFailureDetail::FingerprintSample(source) => {
                    return write!(formatter, "{} failed: {source}", self.operation);
                }
                ChannelFailureDetail::MappedRegionAccess(_) => {
                    return write!(
                        formatter,
                        "{} failed: mapped QEMU quantum shared-memory access failed",
                        self.operation
                    );
                }
                ChannelFailureDetail::QuantumNodeSlot { operation, source } => {
                    return write!(
                        formatter,
                        "{} failed: QEMU quantum node-slot operation {operation} failed: {source}",
                        self.operation
                    );
                }
                ChannelFailureDetail::Message => {}
            }
        }
        write!(formatter, "{} failed: {}", self.operation, self.message)
    }
}

impl std::error::Error for QemuNodeChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.detail {
            ChannelFailureDetail::Supervision(source) => Some(source),
            ChannelFailureDetail::DecodeAdmission(source) => Some(source),
            ChannelFailureDetail::FingerprintSample(source) => Some(source),
            ChannelFailureDetail::MappedRegionAccess(source) => Some(source),
            ChannelFailureDetail::QuantumNodeSlot { source, .. } => Some(source),
            ChannelFailureDetail::Message => None,
        }
    }
}

/// Reports a failure returned by the scheduler-facing QEMU node wrapper.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuNodeError {
    /// Capture failed before the separately observed process cleanup.
    #[error("{source}; checkpoint cleanup refusal: {cleanup:?}")]
    CheckpointCleanup {
        /// Initiating failure, retained as the actual typed carrier.
        #[source]
        source: Box<QemuNodeError>,
        /// Secondary cleanup failure; absence means that cleanup succeeded.
        cleanup: Option<Box<QemuNodeError>>,
    },
    /// Capture work failed before its independently checked original postcut.
    #[cfg(target_os = "linux")]
    #[error("{source}; checkpoint original postcut: {original_after}")]
    CheckpointPostcut {
        /// Initiating node failure, preserved without diagnostic replacement.
        #[source]
        source: Box<QemuNodeError>,
        /// Same retained original's separate post-operation refusal.
        original_after: HostSupervisionError,
    },
    /// The actual checkpoint original or its matched native receiver refused.
    #[cfg(target_os = "linux")]
    #[error("checkpoint original refused: {source}")]
    CheckpointOriginal {
        /// Typed first cause and independent original postcut.
        source: super::exact_snapshot::capture_original::CheckpointOriginalError,
    },
    /// A role-specific child channel failed an operation.
    #[error("{plane} channel operation {operation} failed: {message}")]
    Channel {
        /// Channel role that was used for the failed operation.
        plane: QemuNodeChannelPlane,
        /// Channel-local operation name.
        operation: &'static str,
        /// Failure detail retaining the channel's borrowed or owned storage.
        message: Cow<'static, str>,
    },
    /// A channel retained its actual operational supervision refusal.
    #[error("{plane} channel operation {operation} failed: {source}")]
    ChannelSupervision {
        /// Channel role in which the original operation refused.
        plane: QemuNodeChannelPlane,
        /// Operation attempted before the original refusal.
        operation: &'static str,
        /// Actual typed original cause, without diagnostic replacement.
        #[source]
        source: HostSupervisionError,
    },
    /// A channel retained its actual artifact decode-account refusal.
    #[error("{plane} channel operation {operation} failed: {source}")]
    ChannelDecodeAdmission {
        /// Channel role whose active decode account refused admission.
        plane: QemuNodeChannelPlane,
        /// Operation attempted under the same finite decode account.
        operation: &'static str,
        /// Actual shared refusal without a replacement diagnostic allocation.
        #[source]
        source: DecodeAdmissionError,
    },
    /// A channel retained its actual fingerprint validation failure.
    #[error("{plane} channel operation {operation} failed: {source}")]
    ChannelFingerprintSample {
        /// Channel role that returned the invalid sample.
        plane: QemuNodeChannelPlane,
        /// Operation whose sample validation failed.
        operation: &'static str,
        /// Original protocol failure or complete component-failure bitset.
        #[source]
        source: QemuFingerprintSampleError,
    },
    /// A mapped quantum channel retained its actual region-access failure.
    #[error(
        "{plane} channel operation {operation} failed: mapped QEMU quantum shared-memory access failed"
    )]
    ChannelMappedRegionAccess {
        /// Channel role whose mapped view refused access.
        plane: QemuNodeChannelPlane,
        /// Operation that attempted the mapped access.
        operation: &'static str,
        /// Original geometry, topology or segment failure.
        #[source]
        source: crucible_qemu_shmem::MappedSetupRegionAccessError,
    },
    /// A quantum channel retained its actual bounded node-slot refusal.
    #[error(
        "{plane} channel operation qemu_quantum_shmem_hot_path failed: QEMU quantum node-slot operation {operation} failed: {source}"
    )]
    ChannelQuantumNodeSlot {
        /// Channel role whose slot observation or transition refused.
        plane: QemuNodeChannelPlane,
        /// Actual operation performed on that node slot.
        operation: &'static str,
        /// Original slot failure, including its observed generation coordinates.
        #[source]
        source: crucible_qemu_shmem::NodeSlotError,
    },
    /// RAM source cleanup failed while its service remains retained.
    #[error("{operation} failed: {source}")]
    RamSourceCleanup {
        /// Cleanup boundary that observed the original source failure.
        operation: &'static str,
        /// Same typed worker cause or direct cleanup refusal.
        #[source]
        source: crate::QemuAsyncDriverHealthError,
    },
    /// The nominal Target binding could not lend its actual cleanup origin.
    #[error("retain Target RAM cleanup: {source}")]
    RamCleanupLender {
        /// Actual canonical binding/roster refusal without diagnostic erasure.
        #[source]
        source: BackendOperationalCause,
    },
    /// A saved lender refusal precedes this same stage's independent cleanup.
    #[error("{first}; later staged RAM cleanup: {later}")]
    RamStageCleanup {
        /// First actual nominal-lender failure, retained without another issuer.
        first: BackendOperationalCause,
        /// Later actual physical cleanup or saved-original history.
        #[source]
        later: Box<QemuNodeError>,
    },
    /// Staged source publication retained its actual first and independent posts.
    #[error(
        "staged RAM source preparation refused: first={first:?}; observations={observations:?}; completed={completed}"
    )]
    RamStagePreparation {
        /// Actual source creation failure retained before diagnostic formatting.
        #[source]
        first: Option<BackendOperationalCause>,
        /// Saved Preparation entry, independent post, and completion result.
        observations: [Option<HostSupervisionError>; 3],
        /// Actual completion effect, which does not erase a negative post.
        completed: bool,
    },
    /// The actual monitor close returned a refusal or ambiguous result.
    #[error("staged RAM monitor close: {source}")]
    RamStageClose {
        /// Complete first channel failure before any later factual return.
        #[source]
        source: QemuNodeChannelError,
    },
    /// Actual RAM returns remain incomplete in this same node.
    #[error("node RAM cleanup remains physically pending")]
    RamCleanupPending,
    /// Complete raw RAM leaf histories retained after their independent posts.
    #[error("node RAM cleanup refused: sources={sources:?}; controllers={controllers:?}")]
    RamCleanup {
        /// Actual staged target cleanup under its distinct saved lender.
        #[source]
        stage: Option<Box<QemuNodeError>>,
        /// Latest independently observed stage failure; the first stays above.
        stage_latest: Option<Box<QemuNodeError>>,
        /// Source histories for staged, direct and installed-fork bodies.
        sources: [Option<crate::ram_source::QemuRamSourceStopHistory>; 3],
        /// Direct and fork controller-return histories.
        controllers: [Option<crate::ram_control::RamControlRetirementHistory>; 2],
    },
    /// An initiating process failure and independent RAM return both refused.
    #[error("{first}; independent RAM return: {ram}")]
    ShutdownAndRam {
        /// Actual initiating process or Original failure.
        first: Box<QemuNodeError>,
        /// Independent actual RAM cleanup history.
        ram: Box<QemuNodeError>,
    },
    /// A timed-out channel failed before its independent physical shutdown.
    #[error("{first}; crash status={status:?}; shutdown refusal: {shutdown}")]
    ShutdownAfterChannelFailure {
        /// Actual initiating channel error, preserved before cleanup.
        first: QemuNodeChannelError,
        /// Original crash classification before cleanup was attempted.
        status: QemuNodeRunStatus,
        /// Independently retained physical cleanup failure.
        shutdown: Box<QemuNodeError>,
    },
    /// Child cleanup retains its actual live-check and completion observations.
    #[error(
        "child cleanup Original refused: begin={begin:?}; phases={observations:?}; completion={completion:?}; report={report:?}"
    )]
    ShutdownOriginal {
        /// One-time cleanup entry refusal, if entry did not succeed.
        begin: Option<HostSupervisionError>,
        /// First precheck and independent post for each ordered shutdown rung.
        observations: [(Option<HostSupervisionError>, Option<HostSupervisionError>); 5],
        /// Whether the actual completion effect occurred before its post.
        completion_effect: bool,
        /// Same operation's independent completion/post result.
        completion: Option<HostSupervisionError>,
        /// Actual rung outputs retained before their statuses were interpreted.
        report: QemuShutdownReport,
    },
    /// The owned-child shutdown ladder failed.
    #[error("owned QEMU child shutdown failed: {source}")]
    Shutdown {
        /// Underlying shutdown escalation error.
        source: QemuShutdownError,
    },
    /// The bounded async driver failed around a node step.
    #[error("bounded QEMU async driver failed: {source}")]
    AsyncDriver {
        /// Underlying async-driver failure.
        source: QemuAsyncDriverError,
    },
    /// The host-only bounded scheduling adversary failed closed.
    #[error("bounded QEMU scheduler preemption failed: {message}")]
    BoundedSchedulerPreemption {
        /// Deterministic failure detail from the pidfd controller.
        message: String,
    },
    /// The node cannot prove that its numeric PID still names its owned child.
    #[error("bounded QEMU scheduler preemption rejected its process target: {target}")]
    BoundedSchedulerPreemptionTarget {
        /// Ownership or lifecycle state that made pidfd admission unsafe.
        target: QemuBoundedSchedulerPreemptionTargetError,
    },
    /// The bounded async driver classified the child as crashed and shut it down.
    #[error("QEMU node crashed during bounded await: {status:?}; shutdown={shutdown:?}")]
    Crashed {
        /// Scheduler-facing crashed-node status.
        status: Box<QemuNodeRunStatus>,
        /// Shutdown escalation report.
        shutdown: Box<QemuShutdownReport>,
    },
    /// Coverage observations were produced through an API without an event-log owner.
    #[error("coverage-enabled QEMU execution requires a unified event-log sink")]
    CoverageEventLogRequired,
    /// The unified event log rejected a coverage observation batch.
    #[error("append QEMU coverage observations to unified event log failed: {message}")]
    CoverageEventLog {
        /// Deterministic event-log failure diagnostic.
        message: String,
    },
    /// A coordinated QEMU/host-I/O checkpoint transaction failed.
    #[error("QEMU exact checkpoint failed: {message}")]
    Checkpoint {
        /// Deterministic capture, binding, or cleanup failure detail.
        message: String,
    },
    /// A plugin-emitted network frame broke the per-node sequence contract.
    #[error("QEMU network output sequence mismatch: expected {expected}, observed {observed}")]
    NetworkOutputSequence {
        /// Next sequence required by the host continuation.
        expected: u64,
        /// Sequence carried by the emitted frame.
        observed: u64,
    },
    /// A frame batch was not paired with its exact physical producer stop.
    #[error("QEMU network output boundary mismatch: {message}")]
    NetworkOutputBoundary {
        /// Missing or inconsistent producer boundary evidence.
        message: String,
    },
    /// A live QEMU fault command violated its admitted boundary contract.
    #[error("QEMU fault command failed closed: {message}")]
    FaultCommand {
        /// Deterministic command, capability, coordinate, or result mismatch.
        message: String,
    },
    /// Precommit storage for the lossless QEMU result payload could not be reserved.
    #[error(
        "cannot admit or reserve {requested} bytes for the QEMU fault result against limit {configured}"
    )]
    FaultResultStorage {
        /// Exact result storage requested before visible mutation.
        requested: u64,
        /// Authored or hard byte ceiling governing the request.
        configured: u64,
    },
    /// Lossless occurrence-event staging exceeded its authored record ceiling.
    #[error(
        "cannot stage {requested} QEMU fault event records at current {current} against limit {configured}"
    )]
    FaultEventStorage {
        /// Events already retained by the in-flight command fence.
        current: u64,
        /// Additional records required before the plugin can acknowledge.
        requested: u64,
        /// Authored record ceiling governing the operation.
        configured: u64,
    },
    /// Non-consuming occurrence preview exceeded its authored event-log byte ceiling.
    #[error(
        "cannot stage {requested} QEMU fault-event log bytes at current {current} against limit {configured}"
    )]
    FaultEventPayloadStorage {
        /// Event-log bytes already retained by the production event continuation.
        current: u64,
        /// Additional canonical header and payload bytes required by the event.
        requested: u64,
        /// Authored aggregate event-log byte ceiling.
        configured: u64,
    },
    /// Non-consuming occurrence preview exceeded its authored inline payload ceiling.
    #[error(
        "cannot stage a QEMU fault-event payload of {requested} bytes against inline limit {configured}"
    )]
    FaultEventInlinePayloadStorage {
        /// Payload bytes required by the previewed event.
        requested: u64,
        /// Authored per-event inline payload ceiling.
        configured: u64,
    },
    /// A host-I/O adapter exceeded an authored production resource ceiling.
    #[error(
        "cannot reserve {requested} units of `{field}` at current {current}; configured {configured}, hard {hard}"
    )]
    ResourceLimit {
        /// Closed resource field whose reservation failed.
        field: &'static str,
        /// Existing admitted usage in field units.
        current: u64,
        /// Additional requested usage in field units.
        requested: u64,
        /// Scenario-authored ceiling in field units.
        configured: u64,
        /// Compiled ceiling in field units.
        hard: u64,
    },
}

impl QemuNodeError {
    fn shutdown_original_failure(&self) -> Option<HostSupervisionError> {
        match self {
            Self::ChannelSupervision { source, .. } => Some(*source),
            Self::ShutdownOriginal {
                begin,
                observations,
                completion,
                ..
            } => begin
                .or_else(|| observations.iter().find_map(|(pre, post)| pre.or(*post)))
                .or(*completion),
            Self::ShutdownAndRam { first, .. } => first.shutdown_original_failure(),
            Self::RamStagePreparation { observations, .. } => {
                observations.iter().copied().flatten().next()
            }
            Self::RamCleanup {
                stage,
                sources,
                controllers,
                ..
            } => {
                if let Some(stage) = stage {
                    return stage.shutdown_original_failure();
                }
                sources
                    .iter()
                    .flatten()
                    .find_map(|history| {
                        history
                            .observations
                            .iter()
                            .find_map(|(pre, post)| pre.or(*post))
                    })
                    .or_else(|| {
                        controllers
                            .iter()
                            .flatten()
                            .find_map(|history| history.before.or(history.after))
                    })
            }
            _ => None,
        }
    }

    /// Attaches a node channel role while preserving its typed cause or text.
    #[must_use]
    pub fn from_channel(plane: QemuNodeChannelPlane, source: QemuNodeChannelError) -> Self {
        match source.detail {
            ChannelFailureDetail::Supervision(supervision) => Self::ChannelSupervision {
                plane,
                operation: source.operation,
                source: supervision,
            },
            ChannelFailureDetail::DecodeAdmission(admission) => Self::ChannelDecodeAdmission {
                plane,
                operation: source.operation,
                source: admission,
            },
            ChannelFailureDetail::FingerprintSample(fingerprint) => {
                Self::ChannelFingerprintSample {
                    plane,
                    operation: source.operation,
                    source: fingerprint,
                }
            }
            ChannelFailureDetail::MappedRegionAccess(access) => Self::ChannelMappedRegionAccess {
                plane,
                operation: source.operation,
                source: access,
            },
            ChannelFailureDetail::QuantumNodeSlot { operation, source } => {
                Self::ChannelQuantumNodeSlot {
                    plane,
                    operation,
                    source,
                }
            }
            ChannelFailureDetail::Message => Self::Channel {
                plane,
                operation: source.operation,
                message: source.message,
            },
        }
    }

    /// Retains a source cleanup cause without replacing its worker allocation.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn from_ram_source_cleanup(
        operation: &'static str,
        source: crate::ram_source::QemuRamSourceError,
    ) -> Self {
        Self::RamSourceCleanup {
            operation,
            source: crate::QemuAsyncDriverHealthError::ram_source(source),
        }
    }

    /// Attaches scheduler-node context to a shutdown escalation error.
    #[must_use]
    pub const fn from_shutdown(source: QemuShutdownError) -> Self {
        Self::Shutdown { source }
    }

    /// Attaches scheduler-node context to an async-driver failure.
    #[must_use]
    pub fn from_async_driver(source: QemuAsyncDriverError) -> Self {
        if let QemuAsyncDriverError::Runtime(runtime) = &source
            && runtime.operational_supervision_post().is_none()
            && let Some((field, current, requested, configured, hard)) =
                runtime.resource_limit_coordinates()
        {
            return Self::ResourceLimit {
                field,
                current,
                requested,
                configured,
                hard,
            };
        }
        Self::AsyncDriver { source }
    }

    /// Converts a pidfd scheduling-adversary failure into node context.
    #[must_use]
    pub fn from_bounded_scheduler_preemption(source: BoundedSchedulerPreemptionError) -> Self {
        Self::bounded_scheduler_preemption_message(source.to_string())
    }

    /// Attaches node context to a host-adversary evidence failure.
    #[must_use]
    pub fn bounded_scheduler_preemption_message(message: impl Into<String>) -> Self {
        Self::BoundedSchedulerPreemption {
            message: message.into(),
        }
    }

    /// Creates a coordinated checkpoint error.
    #[must_use]
    pub fn checkpoint(message: impl Into<String>) -> Self {
        Self::Checkpoint {
            message: message.into(),
        }
    }

    /// Creates a fail-closed live fault-command error.
    #[must_use]
    pub fn fault_command(message: impl Into<String>) -> Self {
        Self::FaultCommand {
            message: message.into(),
        }
    }
}

impl From<QemuNodeError> for BackendError {
    fn from(error: QemuNodeError) -> Self {
        let error = match error {
            error @ QemuNodeError::ShutdownOriginal { .. } => {
                let QemuNodeError::ShutdownOriginal {
                    begin,
                    observations,
                    completion,
                    ..
                } = &error
                else {
                    return Self::Rejected {
                        message: error.to_string(),
                    };
                };
                let source = begin
                    .or_else(|| {
                        observations
                            .iter()
                            .find_map(|(before, after)| before.or(*after))
                    })
                    .or(*completion);
                if let Some(source) = source {
                    return Self::RetainedOperationalFailure {
                        kind: operational_failure_kind(source),
                        source: BackendOperationalCause::new(error),
                    };
                }
                error
            }
            QemuNodeError::RamCleanup {
                stage,
                stage_latest,
                mut sources,
                controllers,
            } => {
                // A sole worker cause already owns its original allocation and
                // lease. Reuse it instead of allocating another report owner.
                let sole_worker = stage.is_none()
                    && stage_latest.is_none()
                    && controllers.iter().all(Option::is_none)
                    && sources.iter().flatten().count() == 1
                    && sources.iter().flatten().all(|history| {
                        history.worker.is_some()
                            && history.cancellation.is_none()
                            && history.panic.is_none()
                            && history.native.is_none()
                            && !history.uncertain
                            && history
                                .observations
                                .iter()
                                .all(|(pre, post)| pre.is_none() && post.is_none())
                    });
                if sole_worker {
                    for history in sources.iter_mut().flatten() {
                        if let Some(worker) = history.worker.take() {
                            let source = crate::QemuAsyncDriverHealthError::ram_source(
                                crate::ram_source::QemuRamSourceError::WorkerFailed(worker),
                            );
                            return Self::RetainedOperationalFailure {
                                kind: source.operational_kind(),
                                source: source.into_backend_cause(),
                            };
                        }
                    }
                }
                let kind = stage
                    .as_ref()
                    .map(|first| {
                        first.shutdown_original_failure().map_or(
                            BackendOperationalFailureKind::Unavailable,
                            operational_failure_kind,
                        )
                    })
                    .unwrap_or_else(|| {
                        sources
                            .iter()
                            .flatten()
                            .find_map(|history| {
                                history
                                    .observations
                                    .iter()
                                    .find_map(|(pre, post)| pre.or(*post))
                            })
                            .or_else(|| {
                                controllers
                                    .iter()
                                    .flatten()
                                    .find_map(|history| history.before.or(history.after))
                            })
                            .map_or(
                                BackendOperationalFailureKind::Unavailable,
                                operational_failure_kind,
                            )
                    });
                return Self::RetainedOperationalFailure {
                    kind,
                    source: BackendOperationalCause::new(QemuNodeError::RamCleanup {
                        stage,
                        stage_latest,
                        sources,
                        controllers,
                    }),
                };
            }
            error @ QemuNodeError::ShutdownAndRam { .. } => {
                let kind = match &error {
                    QemuNodeError::ShutdownAndRam { first, .. } => {
                        first.shutdown_original_failure().map_or(
                            BackendOperationalFailureKind::Unavailable,
                            operational_failure_kind,
                        )
                    }
                    _ => BackendOperationalFailureKind::Unavailable,
                };
                return Self::RetainedOperationalFailure {
                    kind,
                    source: BackendOperationalCause::new(error),
                };
            }
            error @ (QemuNodeError::ChannelSupervision { .. }
            | QemuNodeError::ChannelDecodeAdmission { .. }
            | QemuNodeError::ChannelQuantumNodeSlot { .. }
            | QemuNodeError::Shutdown { .. }
            | QemuNodeError::ShutdownAfterChannelFailure { .. }
            | QemuNodeError::RamCleanupLender { .. }
            | QemuNodeError::RamStageCleanup { .. }
            | QemuNodeError::RamStageClose { .. }
            | QemuNodeError::RamStagePreparation { .. }
            | QemuNodeError::RamCleanupPending) => {
                return Self::RetainedOperationalFailure {
                    kind: error.shutdown_original_failure().map_or(
                        BackendOperationalFailureKind::Unavailable,
                        operational_failure_kind,
                    ),
                    source: BackendOperationalCause::new(error),
                };
            }
            QemuNodeError::AsyncDriver {
                source: QemuAsyncDriverError::OperationalHealth(source),
            }
            | QemuNodeError::RamSourceCleanup { source, .. } => {
                return Self::RetainedOperationalFailure {
                    kind: source.operational_kind(),
                    source: source.into_backend_cause(),
                };
            }
            QemuNodeError::AsyncDriver {
                source:
                    QemuAsyncDriverError::ChannelOriginalPost {
                        source,
                        original_after,
                    },
            } => {
                let kind = source
                    .operational_supervision_source()
                    .unwrap_or(original_after);
                return Self::RetainedOperationalFailure {
                    kind: operational_failure_kind(kind),
                    source: BackendOperationalCause::new(
                        QemuAsyncDriverError::ChannelOriginalPost {
                            source,
                            original_after,
                        },
                    ),
                };
            }
            QemuNodeError::AsyncDriver {
                source: QemuAsyncDriverError::Runtime(runtime),
            } => {
                let kind = runtime
                    .operational_supervision_source()
                    .map(operational_failure_kind)
                    .or_else(|| {
                        runtime.operational_supervision_post().map(|post| {
                            // Preserve the initiating typed capacity category,
                            // while retaining the independent post in the same
                            // error instead of projecting away its history.
                            if runtime.resource_limit_coordinates().is_some()
                                || runtime.fault_result_storage_coordinates().is_some()
                                || runtime.fault_event_storage_coordinates().is_some()
                            {
                                BackendOperationalFailureKind::CapacityExhausted
                            } else {
                                operational_failure_kind(post)
                            }
                        })
                    });
                if let Some(kind) = kind {
                    return Self::RetainedOperationalFailure {
                        kind,
                        source: BackendOperationalCause::new(runtime),
                    };
                }
                QemuNodeError::AsyncDriver {
                    source: QemuAsyncDriverError::Runtime(runtime),
                }
            }
            error => error,
        };

        match error {
            QemuNodeError::ResourceLimit {
                field,
                current,
                requested,
                configured,
                hard,
            } => Self::ResourceLimit {
                field,
                current,
                requested,
                configured,
                hard,
            },
            error => Self::Rejected {
                message: error.to_string(),
            },
        }
    }
}

fn operational_failure_kind(source: HostSupervisionError) -> BackendOperationalFailureKind {
    match source {
        HostSupervisionError::DeadlineExpired { .. } => BackendOperationalFailureKind::Expired,
        HostSupervisionError::Terminal {
            state: HostOperationState::Canceled,
        } => BackendOperationalFailureKind::Canceled,
        HostSupervisionError::Terminal {
            state: HostOperationState::Expired,
        } => BackendOperationalFailureKind::Expired,
        HostSupervisionError::Terminal { .. } | HostSupervisionError::BorrowedOperation => {
            BackendOperationalFailureKind::Terminal
        }
        HostSupervisionError::InvalidBudget
        | HostSupervisionError::UnboundedInfrastructure { .. } => {
            BackendOperationalFailureKind::InvalidPolicy
        }
        HostSupervisionError::RevisionConflict { .. } => {
            BackendOperationalFailureKind::RevisionConflict
        }
        HostSupervisionError::CapacityExhausted => BackendOperationalFailureKind::CapacityExhausted,
        HostSupervisionError::IdentityExhausted => BackendOperationalFailureKind::IdentityExhausted,
        HostSupervisionError::ProgressRegressed => BackendOperationalFailureKind::ProgressRegressed,
        HostSupervisionError::Unavailable => BackendOperationalFailureKind::Unavailable,
    }
}

#[cfg(test)]
mod tests;
