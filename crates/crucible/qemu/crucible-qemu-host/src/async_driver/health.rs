//! Retains typed host-source failure identity through node execution and cleanup.
//!
//! A source failure is infrastructure evidence. It never supplies a completed
//! guest outcome or releases a pending process, transport, or backing claim.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use crate::ram_source::{QemuRamSourceError, QemuRamWorkerFailure};
use crucible_engine::{BackendOperationalCause, BackendOperationalFailureKind};
use crucible_host_resources::host_supervision::{HostOperationState, HostSupervisionError};

/// An owned host service failure observed during node execution or cleanup.
///
/// Clones retain the original error allocation. Equality identifies observers
/// of that same failure and independent operation post, rather than comparing
/// mutable diagnostics or clocks.
#[derive(Clone, Debug)]
pub struct QemuAsyncDriverHealthError {
    source: HealthFailure,
    original_after: Option<HostSupervisionError>,
}

#[derive(Clone, Debug)]
enum HealthFailure {
    Worker(QemuRamWorkerFailure),
    Direct(Arc<QemuRamSourceError>),
}

impl HealthFailure {
    fn failure(&self) -> &QemuRamSourceError {
        match self {
            Self::Worker(source) => source,
            Self::Direct(source) => source,
        }
    }
}

impl QemuAsyncDriverHealthError {
    /// Retains one original source failure without converting it to a message.
    #[must_use]
    pub fn ram_source(source: QemuRamSourceError) -> Self {
        let source = match source {
            QemuRamSourceError::WorkerFailed(source) => HealthFailure::Worker(source),
            source => HealthFailure::Direct(Arc::new(source)),
        };
        Self {
            source,
            original_after: None,
        }
    }

    /// Returns the original typed source cause and its retained error chain.
    #[must_use]
    pub fn source_failure(&self) -> &QemuRamSourceError {
        self.source.failure()
    }

    /// Returns an infrastructure category from the original typed source cause.
    #[must_use]
    pub fn operational_kind(&self) -> BackendOperationalFailureKind {
        source_kind(self.source.failure())
    }

    /// Returns the independent failure of the same entered operation after health returned.
    #[must_use]
    pub const fn operational_supervision_post(&self) -> Option<HostSupervisionError> {
        self.original_after
    }

    pub(crate) fn with_operational_supervision_post(
        mut self,
        source: HostSupervisionError,
    ) -> Self {
        if self.original_after.is_none() {
            self.original_after = Some(source);
        }
        self
    }

    pub(crate) fn into_backend_cause(self) -> BackendOperationalCause {
        // The worker shortcut is valid only when it cannot discard an
        // independently observed failure of the entered operation.
        if self.original_after.is_some() {
            return BackendOperationalCause::new(self);
        }
        match self.source {
            HealthFailure::Worker(source) => source.into_backend_cause(),
            source => BackendOperationalCause::new(Self {
                source,
                original_after: None,
            }),
        }
    }
}

fn source_kind(source: &QemuRamSourceError) -> BackendOperationalFailureKind {
    match source {
        QemuRamSourceError::WorkerFailed(source) => source_kind(source),
        QemuRamSourceError::BackingFailure { kind, .. }
        | QemuRamSourceError::RamBackingFailure { kind, .. } => *kind,
        QemuRamSourceError::Canceled => BackendOperationalFailureKind::Canceled,
        QemuRamSourceError::Io(_) | QemuRamSourceError::Backing(_) => {
            BackendOperationalFailureKind::Unavailable
        }
        QemuRamSourceError::Protocol(
            crucible_qemu_protocol::ram_page::RamPageProtocolError::Io(_),
        ) => BackendOperationalFailureKind::Unavailable,
        QemuRamSourceError::Services(_) => BackendOperationalFailureKind::CapacityExhausted,
        QemuRamSourceError::Supervision(
            HostSupervisionError::DeadlineExpired { .. }
            | HostSupervisionError::Terminal {
                state: HostOperationState::Expired,
            },
        ) => BackendOperationalFailureKind::Expired,
        QemuRamSourceError::Supervision(HostSupervisionError::Terminal {
            state: HostOperationState::Canceled,
        }) => BackendOperationalFailureKind::Canceled,
        QemuRamSourceError::Supervision(HostSupervisionError::CapacityExhausted) => {
            BackendOperationalFailureKind::CapacityExhausted
        }
        QemuRamSourceError::Ownership
        | QemuRamSourceError::NativeJoinUnsupported
        | QemuRamSourceError::Proof(_)
        | QemuRamSourceError::WorkerPanicked
        | QemuRamSourceError::Protocol(_)
        | QemuRamSourceError::Supervision(_) => BackendOperationalFailureKind::Terminal,
    }
}

impl fmt::Display for QemuAsyncDriverHealthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.failure().fmt(formatter)?;
        if let Some(post) = self.original_after {
            write!(formatter, "; independent Original post: {post}")?;
        }
        Ok(())
    }
}

impl Error for QemuAsyncDriverHealthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.failure())
    }
}

impl PartialEq for QemuAsyncDriverHealthError {
    fn eq(&self, other: &Self) -> bool {
        self.original_after == other.original_after
            && match (&self.source, &other.source) {
                (HealthFailure::Worker(left), HealthFailure::Worker(right)) => left == right,
                (HealthFailure::Direct(left), HealthFailure::Direct(right)) => {
                    Arc::ptr_eq(left, right)
                }
                _ => false,
            }
    }
}

impl Eq for QemuAsyncDriverHealthError {}
