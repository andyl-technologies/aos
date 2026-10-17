//! Original service preadmission and exclusive provider-error ownership.
//!
//! Post-bootstrap constructor refusals remain inline. Both existing service
//! accounts grant their leases before covered service storage is allocated.
//! Earlier supervisor and allocator controls require separate original funding.
//! Lower checks preserve their typed cause without a second I/O wrapper.

use std::alloc::Layout;
use std::sync::atomic::AtomicUsize;

use crucible_cas::content_store::{
    ProviderDiagnosticError, ProviderDiagnosticPermit, ProviderFailureKind, StoreError,
};
use crucible_linux_resource::LinuxProjectQuotaError;
use crucible_linux_resource::host_services::{HostServiceError, HostServiceLease};
use crucible_linux_resource::host_supervision::HostSupervisionError;

/// Maximum new diagnostic path owned by one bounded provider refusal.
pub(crate) const MAXIMUM_PROVIDER_ERROR_PATH_BYTES: usize = 4096;

/// Inline refusal while constructing the original provider service.
#[derive(Debug, thiserror::Error)]
pub enum ProviderServiceAdmissionError {
    /// An existing authored resource allocator refused the initial reservation.
    #[error("{0}")]
    Resources(#[from] HostServiceError),
    /// Original supervision refused before covered diagnostic storage was constructed.
    #[error("{0}")]
    Supervision(#[from] HostSupervisionError),
    /// An existing policy or previously owning store failure refused admission.
    #[error("{0}")]
    Store(#[from] StoreError),
}

/// One bounded lower cause, moved into its funded box without path copying.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProviderCause {
    #[error("{0}")]
    Resources(#[from] HostServiceError),
    #[error("{0}")]
    Supervision(#[from] HostSupervisionError),
    #[error("{0}")]
    PhysicalQuota(#[from] LinuxProjectQuotaError),
}

/// Returns the complete conservative diagnostic peak in each original bank.
pub(crate) const fn provider_diagnostic_bytes() -> u64 {
    (MAXIMUM_PROVIDER_ERROR_PATH_BYTES
        + std::mem::size_of::<ProviderCause>()
        + std::mem::size_of::<ProviderDiagnosticError>()) as u64
}

/// Returns the complete Arc allocation, including aligned counter/header space.
pub(crate) fn arc_allocation_bytes<T>() -> Result<usize, StoreError> {
    Layout::new::<(AtomicUsize, AtomicUsize)>()
        .extend(Layout::new::<T>())
        .map(|(layout, _)| layout.pad_to_align().size())
        .map_err(|_| StoreError::Quota)
}

/// Returns only the new shared lease allocation; owner bodies include its value.
pub(crate) fn lease_control_bytes() -> Result<usize, StoreError> {
    usize::try_from(HostServiceLease::metadata_bytes())
        .ok()
        .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<HostServiceLease>()))
        .ok_or(StoreError::Quota)
}

/// Refuses an unbounded path before any lower diagnostic path is copied.
pub(crate) fn check_provider_error_path(path: &std::path::Path) -> Result<(), StoreError> {
    if path.as_os_str().len() > MAXIMUM_PROVIDER_ERROR_PATH_BYTES {
        return Err(StoreError::InvalidComposition {
            reason: "provider diagnostic path exceeds its precharged bound",
        });
    }
    Ok(())
}

/// Preserves a paid lower cause with source destruction before slot reuse.
pub(crate) fn retain_provider_cause(
    permit: ProviderDiagnosticPermit,
    cause: ProviderCause,
) -> StoreError {
    let kind = match &cause {
        ProviderCause::Resources(_) => ProviderFailureKind::Resources,
        ProviderCause::Supervision(_)
        | ProviderCause::PhysicalQuota(LinuxProjectQuotaError::Supervision(_)) => {
            ProviderFailureKind::Supervision
        }
        ProviderCause::PhysicalQuota(_) => ProviderFailureKind::PhysicalQuota,
    };
    StoreError::ProviderDiagnostic {
        source: permit.retain(kind, Box::new(cause)),
    }
}

#[cfg(test)]
mod tests;
