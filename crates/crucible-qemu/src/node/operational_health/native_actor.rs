//! Refuses a guest cut after an authenticated isolated fault-actor failure.

use crate::QemuAsyncDriverHealthError;
use crate::ram_control::RamControlRegistration;
use crate::ram_source::QemuRamSourceError;
use crucible::{BackendOperationalCause, BackendOperationalFailureKind};
use crucible_protocol::ram_control::{
    RamControlFailureCause, RamControlFaultActorFailure, RamControlFaultActorReport,
    RamControlOperationFailure, RamControlSupervisionFailure,
};

/// Preserves actual portable worker identity and original terminal category.
#[derive(Debug, thiserror::Error)]
#[error("native RAM fault actor {report:?} failed")]
pub struct QemuNativeFaultActorFailure {
    /// Authenticated worker identity, original terminal category and disposition.
    pub report: RamControlFaultActorReport,
}

/// Preserves the original failed physical operation across the process boundary.
#[derive(Debug, thiserror::Error)]
#[error("native RAM operation {failure:?} failed")]
pub struct QemuNativeOperationFailure {
    /// Authenticated operation, exact policy/topology binding and original cause.
    pub failure: RamControlOperationFailure,
}

pub(in crate::node) fn check(
    registration: Option<&RamControlRegistration>,
) -> Result<(), QemuAsyncDriverHealthError> {
    let Some(registration) = registration else {
        return Ok(());
    };
    let (report, operation_failure) = registration
        .registrar
        .native_paging_health(registration.target)
        .map_err(|source| {
            QemuAsyncDriverHealthError::ram_source(QemuRamSourceError::BackingFailure {
                kind: BackendOperationalFailureKind::Unavailable,
                source: BackendOperationalCause::new(source),
            })
        })?;
    if let Some(failure) = operation_failure {
        let kind = match failure.cause {
            RamControlFailureCause::Io { .. } => BackendOperationalFailureKind::Unavailable,
            RamControlFailureCause::Supervision { kind } => match kind {
                RamControlSupervisionFailure::Expired => BackendOperationalFailureKind::Expired,
                RamControlSupervisionFailure::Canceled => BackendOperationalFailureKind::Canceled,
                RamControlSupervisionFailure::Capacity => {
                    BackendOperationalFailureKind::CapacityExhausted
                }
                RamControlSupervisionFailure::MissingPolicy
                | RamControlSupervisionFailure::Uncertain => {
                    BackendOperationalFailureKind::Terminal
                }
            },
            RamControlFailureCause::Native { .. } | RamControlFailureCause::Other => {
                BackendOperationalFailureKind::Terminal
            }
        };
        return Err(QemuAsyncDriverHealthError::ram_source(
            QemuRamSourceError::BackingFailure {
                kind,
                source: BackendOperationalCause::new(QemuNativeOperationFailure { failure }),
            },
        ));
    }
    let Some(report) = report.filter(|report| report.failure.is_some()) else {
        return Ok(());
    };
    let kind = match report.failure {
        Some(RamControlFaultActorFailure::Io { .. }) => BackendOperationalFailureKind::Unavailable,
        Some(RamControlFaultActorFailure::RequestedExit | RamControlFaultActorFailure::Other)
        | None => BackendOperationalFailureKind::Terminal,
    };
    Err(QemuAsyncDriverHealthError::ram_source(
        QemuRamSourceError::BackingFailure {
            kind,
            source: BackendOperationalCause::new(QemuNativeFaultActorFailure { report }),
        },
    ))
}
