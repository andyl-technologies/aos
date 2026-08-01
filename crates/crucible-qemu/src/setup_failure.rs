//! Setup-failure classification and abort handling.
//!
//! RFC-0010 PROTO-21 requires every setup failure to become a clean node abort:
//! the node must never become schedulable, and any spawned QEMU child must go
//! through the shutdown escalation ladder and be reaped.

#[cfg(unix)]
use crucible_protocol::DescriptorHandoverError;
use crucible_protocol::{FrameIoError, HandshakeError, SchedulableNodeSetup, SetupCompletionError};
use crucible_shmem::{
    RegionHeaderSnapshot, RegionSetupValidationError, ValidatedSetupRegion,
    validate_setup_region_header,
};
use thiserror::Error;

use crate::{
    QemuShutdownError, QemuShutdownPolicy, QemuShutdownReport, QemuShutdownTarget,
    shutdown_qemu_child,
};

/// Host-classified reason a node setup cannot continue to scheduling.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuSetupFailureKind {
    /// Host and plugin control-protocol versions did not overlap.
    #[error(
        "no control-protocol version overlap: plugin max {plugin_max}, host range {host_min}..={host_max}"
    )]
    NoProtocolVersionOverlap {
        /// Highest control-protocol version offered by the plugin.
        plugin_max: u32,
        /// Lowest control-protocol version supported by the host.
        host_min: u32,
        /// Highest control-protocol version supported by the host.
        host_max: u32,
    },
    /// The plugin and host were built against different shmem ABIs.
    #[error("shared-memory ABI mismatch: plugin {plugin_abi}, host {host_abi}")]
    AbiMismatch {
        /// ABI version offered by the plugin.
        plugin_abi: u32,
        /// ABI version required by the host.
        host_abi: u32,
    },
    /// The assigned node slot is outside the declared node count.
    #[error("assigned slot {slot_index} is outside node_count {node_count}")]
    BadSlot {
        /// Slot index carried by the handshake.
        slot_index: u32,
        /// Node count carried by the handshake.
        node_count: u32,
    },
    /// The setup frame carried a descriptor count other than shmem plus wake fd.
    #[error("setup frame carried {count} descriptors, expected 2")]
    WrongFdCount {
        /// Number of descriptors received with the setup frame.
        count: usize,
    },
    /// The plugin rejected the advertised shmem region length, header, or ABI marker.
    #[error("setup shared-memory region was too short or failed validation")]
    ShortOrInvalidRegion,
    /// The plugin returned a non-ready setup acknowledgement.
    #[error("setup acknowledgement status {status} is non-zero")]
    NonZeroSetupAck {
        /// Nonzero `SetupAck.status` byte.
        status: u8,
    },
    /// The control socket closed before setup completed.
    #[error("control socket closed before setup acknowledgement")]
    PrematureSocketClose,
    /// Setup failed before scheduling for a protocol reason outside PROTO-21's
    /// narrower enumerated cases.
    #[error("setup protocol operation {operation} failed before scheduling")]
    UnexpectedSetupProtocolFailure {
        /// Setup operation that failed.
        operation: &'static str,
    },
}

impl QemuSetupFailureKind {
    /// Classifies a handshake failure when it is a PROTO-21 setup failure.
    #[must_use]
    pub const fn from_handshake_error(error: &HandshakeError) -> Option<Self> {
        match error {
            HandshakeError::ProtocolVersionNoOverlap {
                plugin_max,
                host_min,
                host_max,
            } => Some(Self::NoProtocolVersionOverlap {
                plugin_max: *plugin_max,
                host_min: *host_min,
                host_max: *host_max,
            }),
            HandshakeError::AbiMismatch {
                plugin_abi,
                host_abi,
            } => Some(Self::AbiMismatch {
                plugin_abi: *plugin_abi,
                host_abi: *host_abi,
            }),
            HandshakeError::InvalidSlot {
                slot_index,
                node_count,
            } => Some(Self::BadSlot {
                slot_index: *slot_index,
                node_count: *node_count,
            }),
            HandshakeError::Io { source } if is_premature_control_close(*source) => {
                Some(Self::PrematureSocketClose)
            }
            _ => None,
        }
    }

    /// Classifies a setup descriptor handover failure when it is a PROTO-21 setup failure.
    #[cfg(unix)]
    #[must_use]
    pub const fn from_descriptor_handover_error(error: &DescriptorHandoverError) -> Option<Self> {
        match error {
            DescriptorHandoverError::WrongDescriptorCount { count } => {
                Some(Self::WrongFdCount { count: *count })
            }
            DescriptorHandoverError::PeerClosed { .. } => Some(Self::PrematureSocketClose),
            _ => None,
        }
    }

    /// Classifies a setup-region validation failure.
    #[must_use]
    pub const fn from_region_validation_error(_error: &RegionSetupValidationError) -> Self {
        Self::ShortOrInvalidRegion
    }

    /// Classifies a setup-acknowledgement failure when it is a PROTO-21 setup failure.
    #[must_use]
    pub const fn from_setup_completion_error(error: &SetupCompletionError) -> Option<Self> {
        match error {
            SetupCompletionError::NonZeroSetupAck { status } => {
                Some(Self::NonZeroSetupAck { status: *status })
            }
            SetupCompletionError::Io { source } if is_premature_control_close(*source) => {
                Some(Self::PrematureSocketClose)
            }
            _ => None,
        }
    }
}

/// Source error that must abort setup before the node can be scheduled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QemuSetupFailureSource {
    /// Initial `Hello`/`HelloAck` negotiation failed.
    Handshake(HandshakeError),
    /// Setup descriptor handover failed.
    #[cfg(unix)]
    DescriptorHandover(DescriptorHandoverError),
    /// Shared-memory region length, header, or ABI marker validation failed.
    RegionValidation(RegionSetupValidationError),
    /// Setup acknowledgement handling failed.
    SetupCompletion(SetupCompletionError),
}

impl QemuSetupFailureSource {
    /// Returns the setup failure kind used for reporting and failed-node tokens.
    #[must_use]
    pub fn reason(&self) -> QemuSetupFailureKind {
        match self {
            Self::Handshake(error) => classify_handshake_error(error),
            #[cfg(unix)]
            Self::DescriptorHandover(error) => classify_descriptor_handover_error(error),
            Self::RegionValidation(error) => {
                QemuSetupFailureKind::from_region_validation_error(error)
            }
            Self::SetupCompletion(error) => classify_setup_completion_error(error),
        }
    }
}

impl From<HandshakeError> for QemuSetupFailureSource {
    fn from(source: HandshakeError) -> Self {
        Self::Handshake(source)
    }
}

#[cfg(unix)]
impl From<DescriptorHandoverError> for QemuSetupFailureSource {
    fn from(source: DescriptorHandoverError) -> Self {
        Self::DescriptorHandover(source)
    }
}

impl From<RegionSetupValidationError> for QemuSetupFailureSource {
    fn from(source: RegionSetupValidationError) -> Self {
        Self::RegionValidation(source)
    }
}

impl From<SetupCompletionError> for QemuSetupFailureSource {
    fn from(source: SetupCompletionError) -> Self {
        Self::SetupCompletion(source)
    }
}

/// Setup operations that must complete before a QEMU node can be scheduled.
pub trait QemuSetupDriver: QemuShutdownTarget {
    /// Runs the host-side handshake.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] when version negotiation, ABI matching, slot
    /// assignment, or control-frame I/O fails.
    fn accept_handshake(&mut self) -> Result<(), HandshakeError>;

    /// Receives the setup frame and its fixed descriptor pair.
    ///
    /// # Errors
    ///
    /// Returns [`DescriptorHandoverError`] when descriptor handover fails.
    #[cfg(unix)]
    fn receive_setup_descriptors(&mut self) -> Result<(), DescriptorHandoverError>;

    /// Validates the setup shared-memory region header.
    ///
    /// # Errors
    ///
    /// Returns [`RegionSetupValidationError`] when the mapped region is too
    /// short, carries the wrong ABI marker, or has invalid geometry.
    fn validate_setup_region(&mut self)
    -> Result<ValidatedSetupRegion, RegionSetupValidationError>;

    /// Accepts the setup acknowledgement from the plugin.
    ///
    /// # Errors
    ///
    /// Returns [`SetupCompletionError`] when the plugin reports failure, the
    /// socket closes, or the acknowledgement cannot be decoded.
    fn accept_setup_ack(&mut self) -> Result<SchedulableNodeSetup, SetupCompletionError>;
}

/// Host-side setup token for a node that may enter the scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuSchedulableNodeSetup {
    setup_ack: SchedulableNodeSetup,
    region: ValidatedSetupRegion,
}

impl QemuSchedulableNodeSetup {
    /// Returns the accepted protocol setup acknowledgement.
    #[must_use]
    pub const fn setup_ack(self) -> SchedulableNodeSetup {
        self.setup_ack
    }

    /// Returns the validated shared-memory region token.
    #[must_use]
    pub const fn region(self) -> ValidatedSetupRegion {
        self.region
    }

    /// Returns whether this node may be scheduled.
    #[must_use]
    pub const fn can_schedule(self) -> bool {
        self.setup_ack.can_schedule()
    }
}

/// Result of running host-side setup for one QEMU child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QemuNodeSetup {
    /// Setup completed and the node may be scheduled.
    Schedulable(QemuSchedulableNodeSetup),
    /// Setup failed, the node may not be scheduled, and the child was reaped.
    Failed(FailedQemuNodeSetup),
}

impl QemuNodeSetup {
    /// Returns whether this setup outcome permits scheduler admission.
    #[must_use]
    pub const fn can_schedule(&self) -> bool {
        match self {
            Self::Schedulable(setup) => setup.can_schedule(),
            Self::Failed(setup) => setup.can_schedule(),
        }
    }
}

/// Host-side evidence that setup failed and the QEMU child was torn down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedQemuNodeSetup {
    reason: QemuSetupFailureKind,
    shutdown_report: QemuShutdownReport,
}

impl FailedQemuNodeSetup {
    /// Returns the classified setup failure reason.
    #[must_use]
    pub const fn reason(&self) -> &QemuSetupFailureKind {
        &self.reason
    }

    /// Returns the shutdown escalation report produced while aborting setup.
    #[must_use]
    pub const fn shutdown_report(&self) -> &QemuShutdownReport {
        &self.shutdown_report
    }

    /// Returns whether this node may be scheduled.
    #[must_use]
    pub const fn can_schedule(&self) -> bool {
        false
    }
}

/// Error returned when setup abort cannot prove the child was reaped.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuSetupAbortError {
    /// Shutdown escalation failed while handling a setup failure.
    #[error("setup failure teardown failed for {reason}")]
    Shutdown {
        /// Classified setup failure that triggered teardown.
        reason: QemuSetupFailureKind,
        /// Underlying shutdown escalation error.
        source: QemuShutdownError,
    },
}

/// Runs host-side setup and forces any failure through teardown before returning.
///
/// A schedulable token is returned only after handshake, descriptor handover,
/// region validation, and ready setup acknowledgement have all completed.
///
/// # Errors
///
/// Returns [`QemuSetupAbortError`] when a setup failure occurs but shutdown
/// escalation cannot prove the child was reaped.
pub fn complete_qemu_node_setup<T>(
    target: &mut T,
    policy: QemuShutdownPolicy,
) -> Result<QemuNodeSetup, QemuSetupAbortError>
where
    T: QemuSetupDriver,
{
    if let Err(source) = target.accept_handshake() {
        return abort_setup_source(target, source, policy);
    }

    #[cfg(unix)]
    if let Err(source) = target.receive_setup_descriptors() {
        return abort_setup_source(target, source, policy);
    }

    let region = match target.validate_setup_region() {
        Ok(region) => region,
        Err(source) => return abort_setup_source(target, source, policy),
    };
    let setup_ack = match target.accept_setup_ack() {
        Ok(setup_ack) => setup_ack,
        Err(source) => return abort_setup_source(target, source, policy),
    };

    Ok(QemuNodeSetup::Schedulable(QemuSchedulableNodeSetup {
        setup_ack,
        region,
    }))
}

/// Validates a setup shared-memory header through the real shmem ABI validator.
///
/// # Errors
///
/// Returns [`RegionSetupValidationError`] when the mapped region is too short,
/// carries the wrong ABI marker, or has invalid geometry.
pub fn validate_qemu_setup_region_header(
    snapshot: RegionHeaderSnapshot,
    region_len: u64,
) -> Result<ValidatedSetupRegion, RegionSetupValidationError> {
    validate_setup_region_header(snapshot, region_len)
}

/// Aborts a failed QEMU setup and reaps the child before returning.
///
/// # Errors
///
/// Returns [`QemuSetupAbortError`] when the shutdown escalation cannot prove the
/// child was reaped.
pub fn abort_qemu_setup_failure<T>(
    target: &mut T,
    failure: impl Into<QemuSetupFailureSource>,
    policy: QemuShutdownPolicy,
) -> Result<FailedQemuNodeSetup, QemuSetupAbortError>
where
    T: QemuShutdownTarget,
{
    abort_failed_qemu_setup_kind(target, failure.into().reason(), policy)
}

fn abort_setup_source<T>(
    target: &mut T,
    failure: impl Into<QemuSetupFailureSource>,
    policy: QemuShutdownPolicy,
) -> Result<QemuNodeSetup, QemuSetupAbortError>
where
    T: QemuShutdownTarget,
{
    abort_qemu_setup_failure(target, failure, policy).map(QemuNodeSetup::Failed)
}

fn abort_failed_qemu_setup_kind<T>(
    target: &mut T,
    reason: QemuSetupFailureKind,
    policy: QemuShutdownPolicy,
) -> Result<FailedQemuNodeSetup, QemuSetupAbortError>
where
    T: QemuShutdownTarget,
{
    let shutdown_report =
        shutdown_qemu_child(target, policy).map_err(|source| QemuSetupAbortError::Shutdown {
            reason: reason.clone(),
            source,
        })?;
    Ok(FailedQemuNodeSetup {
        reason,
        shutdown_report,
    })
}

fn classify_handshake_error(error: &HandshakeError) -> QemuSetupFailureKind {
    match QemuSetupFailureKind::from_handshake_error(error) {
        Some(reason) => reason,
        None => QemuSetupFailureKind::UnexpectedSetupProtocolFailure {
            operation: "handshake",
        },
    }
}

#[cfg(unix)]
fn classify_descriptor_handover_error(error: &DescriptorHandoverError) -> QemuSetupFailureKind {
    match QemuSetupFailureKind::from_descriptor_handover_error(error) {
        Some(reason) => reason,
        None => QemuSetupFailureKind::UnexpectedSetupProtocolFailure {
            operation: "setup descriptor handover",
        },
    }
}

fn classify_setup_completion_error(error: &SetupCompletionError) -> QemuSetupFailureKind {
    match QemuSetupFailureKind::from_setup_completion_error(error) {
        Some(reason) => reason,
        None => QemuSetupFailureKind::UnexpectedSetupProtocolFailure {
            operation: "setup acknowledgement",
        },
    }
}

const fn is_premature_control_close(error: FrameIoError) -> bool {
    matches!(
        error,
        FrameIoError::TruncatedLengthPrefix | FrameIoError::TruncatedPayload { .. }
    )
}
