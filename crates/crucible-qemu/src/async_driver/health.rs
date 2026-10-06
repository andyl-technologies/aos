//! Retains typed host-source failure identity through an asynchronous quantum.
//!
//! A source failure is infrastructure evidence. It never supplies a completed
//! guest outcome or releases a pending process, transport, or backing claim.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use crate::ram_source::QemuRamSourceError;
use crucible::BackendOperationalFailureKind;
use crucible_linux_resource::host_supervision::{HostOperationState, HostSupervisionError};

/// An owned host service failure while a guest quantum remains pending.
///
/// Clones retain the original error allocation. Equality identifies observers
/// of that same failure, rather than comparing mutable diagnostics or clocks.
#[derive(Clone, Debug)]
pub struct QemuAsyncDriverHealthError {
    source: Arc<QemuRamSourceError>,
}

impl QemuAsyncDriverHealthError {
    /// Retains one original source failure without converting it to a message.
    #[must_use]
    pub fn ram_source(source: QemuRamSourceError) -> Self {
        Self {
            source: Arc::new(source),
        }
    }

    /// Returns the original typed source cause and its retained error chain.
    #[must_use]
    pub fn source_failure(&self) -> &QemuRamSourceError {
        &self.source
    }

    /// Returns an infrastructure category from the original typed source cause.
    #[must_use]
    pub fn operational_kind(&self) -> BackendOperationalFailureKind {
        source_kind(&self.source)
    }
}

fn source_kind(source: &QemuRamSourceError) -> BackendOperationalFailureKind {
    match source {
        QemuRamSourceError::WorkerFailed(source) => source_kind(source),
        QemuRamSourceError::BackingFailure { kind, .. } => *kind,
        QemuRamSourceError::Canceled => BackendOperationalFailureKind::Canceled,
        QemuRamSourceError::Io(_) | QemuRamSourceError::Backing(_) => {
            BackendOperationalFailureKind::Unavailable
        }
        QemuRamSourceError::Protocol(crucible_protocol::ram_page::RamPageProtocolError::Io(_)) => {
            BackendOperationalFailureKind::Unavailable
        }
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
        | QemuRamSourceError::Proof(_)
        | QemuRamSourceError::WorkerPanicked
        | QemuRamSourceError::Protocol(_)
        | QemuRamSourceError::Supervision(_) => BackendOperationalFailureKind::Terminal,
    }
}

impl fmt::Display for QemuAsyncDriverHealthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for QemuAsyncDriverHealthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl PartialEq for QemuAsyncDriverHealthError {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.source, &other.source)
    }
}

impl Eq for QemuAsyncDriverHealthError {}
