//! Transfers the genuine Mount/Network stdin listener after the paid entrance.

use std::error::Error;
use std::path::Path;

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::{ListenerAdmissionFailureRefV1,
    RecordSubjectListener, RecordSubjectListenerAdmissionAttemptV1};

use super::fixed_service_operation::FixedServiceOperationClosedV4 as Closed;
use super::fixed_service_receiving::{FixedServiceReceivingCaptureV1, FixedServiceRoleV1};
use super::representation::RepresentationDemandDebitV1;

/// Retains the one original listener duplicate through native admission/move.
///
/// No caller descriptor, path, role or account is accepted. Only the real
/// fixed service flight can pay and enter the capture; native acceptance and
/// request authority remain separate from this mechanical listener handoff.
#[must_use]
pub struct FixedServiceListenerOriginalV4 {
    entered: bool,
    moved: bool,
    duplicate: Option<Result<(), aos_linux_descriptors::Error>>,
    admission: Option<RecordSubjectListenerAdmissionAttemptV1>,
    admitted: Option<Result<(), Closed>>,
    geometry: Option<Result<ResourceVector, AccountingError>>,
    funding_failed: bool,
    closed: Option<Closed>,
}

impl Default for FixedServiceListenerOriginalV4 {
    fn default() -> Self { Self::new() }
}

impl FixedServiceListenerOriginalV4 {
    /// Creates empty destinations without touching the inherited table/socket.
    #[must_use]
    pub fn new() -> Self {
        Self { entered: false, moved: false, duplicate: None, admission: None,
            admitted: None, geometry: None, funding_failed: false, closed: None }
    }

    /// Prices the compiled owner, one duplicate, and bounded native address.
    ///
    /// # Errors
    /// Rejects checked layout conversion without allocating or observing IO.
    pub fn receiving_demand_v4() -> Result<ResourceVector, AccountingError> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<rustix::net::SocketAddrUnix>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<rustix::net::SocketAddrUnix>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        // Existing socket pathname and stdin are already image/native-owned;
        // duplication creates no additional namespace or filesystem object.
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles, 1))
    }

    /// Moves the same completely admitted listener once, without further IO.
    ///
    /// The actual receiving service must park it before its next fallible step.
    #[must_use]
    pub fn take_completed_listener_once_v4(&mut self) -> Option<RecordSubjectListener> {
        if self.closed.is_some() || self.moved || !matches!(self.admitted, Some(Ok(()))) { return None; }
        let listener = self.admission.as_mut()?.take_completed_listener()?;
        self.moved = true;
        Some(listener)
    }

    /// Borrows the first actual native, geometry, or retained closed cause.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.duplicate.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| match self.admission.as_ref()?.first_failure()? {
                ListenerAdmissionFailureRefV1::Cause(cause) => Some(cause as _),
                ListenerAdmissionFailureRefV1::Closed => None,
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Identifies a refusal whose actual arithmetic cause remains on Common.
    pub fn original_funding_failed_v4(&self) -> bool { self.funding_failed }
}

impl FixedServiceReceivingCaptureV1<Closed> {
    /// Captures only this genuine Mount/Network service's original stdin socket.
    ///
    /// It never rescans the descriptor table, adopts an ordinary activation
    /// result, or reconstructs an origin from its decoded DATA.
    ///
    /// # Errors
    /// Pays before duplication and preserves every reached descriptor/error.
    /// Failed admission permanently closes positive service operation entry.
    pub fn capture_service_listener_once_v4(&mut self, original: &mut FixedServiceListenerOriginalV4) -> Result<(), Closed> {
        if original.entered || self.listener_entered || self.operation_active || self.operation_closed
            || !matches!(self.role, FixedServiceRoleV1::Mount | FixedServiceRoleV1::Network)
            || self.require_permanent_fd_coverage_v1().is_err()
            || !self.service_startup.as_ref().is_some_and(|owner| owner.before_complete() && !owner.complete())
        {
            original.closed.get_or_insert(Closed);
            self.operation_closed = true;
            return Err(Closed);
        }
        self.listener_entered = true;
        original.entered = true;
        original.geometry = Some((|| {
            let shape = FixedServiceListenerOriginalV4::receiving_demand_v4()?;
            let attempted = self.fixed_startup_demand()?.get(D::OpenFiles)
                .checked_add(self.operation_files)
                .and_then(|files| files.checked_add(self.service_startup.as_ref().map_or(0, |owner| owner.committed_files())))
                .and_then(|files| files.checked_add(shape.get(D::OpenFiles)))
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
            let limit = self.permanent_open_files().map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
            if attempted > limit { return Err(AccountingError::LimitExceeded { dimension: D::OpenFiles, limit, attempted }); }
            Ok(shape)
        })());
        let shape = match original.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(shape) => shape,
            None => { original.closed = Some(Closed); self.operation_closed = true; return Err(Closed); }
        };
        if !self.representation.as_mut().is_some_and(|ledger| ledger.reserve(shape.with(D::OpenFiles, 0)).is_ok()) {
            original.funding_failed = true;
            original.closed = Some(Closed);
            self.operation_closed = true;
            return Err(Closed);
        }
        self.operation_files = self.operation_files.checked_add(shape.get(D::OpenFiles)).ok_or(Closed)?;
        match aos_sandbox_linux::inherited_fd::duplicate_inherited_descriptor(0) {
            Ok(descriptor) => {
                original.admission = Some(RecordSubjectListenerAdmissionAttemptV1::new(descriptor));
                original.duplicate = Some(Ok(()));
            }
            Err(cause) => original.duplicate = Some(Err(cause)),
        }
        let path = match self.role {
            FixedServiceRoleV1::Mount => "/run/aos/sandbox-mount/control.sock",
            FixedServiceRoleV1::Network => "/run/aos/sandbox-network/control.sock",
            _ => return Err(Closed),
        };
        original.admitted = Some(match original.admission.as_mut() {
            Some(admission) => admission.admit_once(Path::new(path)).map_err(|_| Closed),
            None => Err(Closed),
        });
        if !matches!(original.admitted, Some(Ok(()))) {
            original.closed = Some(Closed);
            self.operation_closed = true;
            return Err(Closed);
        }
        Ok(())
    }
}

impl Drop for FixedServiceListenerOriginalV4 {
    fn drop(&mut self) {
        if self.entered && (self.closed.is_some() || !self.moved) {
            std::process::abort();
        }
    }
}
