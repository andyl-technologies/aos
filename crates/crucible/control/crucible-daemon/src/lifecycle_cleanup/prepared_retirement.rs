//! Protects original Main-held first causes across local caller abandonment.
//!
//! A public failure contains only the original role selector and phase label.
//! Formatting borrows the actual retained cause; it allocates no replacement
//! report. Cleanup and terminal extraction continue through the same role.

use std::error::Error;
use std::fmt;

use super::post_body::ProductionVmConstructionPostBody;
use super::*;

/// Describes a refused same-role observation without replacing its raw cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum PreparedSourceRefusal {
    /// The genuine containing Main or exact occupied epoch is unavailable.
    #[error("same prepared Source role is unavailable")]
    RoleUnavailable,
    /// The same role remains borrowed by another bounded operation.
    #[error("same prepared Source role is borrowed")]
    Borrowed,
    /// Actual body, native return, Service release or terminal custody remains.
    #[error("same prepared Source retirement remains pending")]
    Pending,
    /// Actual destruction or ownership is uncertain and credit remains occupied.
    #[error("same prepared Source destruction is uncertain")]
    DestructionUncertain,
}

/// Retains a phase report linked to its actual durable Main-owned first cause.
///
/// The cause stays inside the original Main body. Dropping this report requests
/// retirement; it does not drop that body or return a role, loan or budget.
#[must_use = "retain the actual Source retirement or let Main continue owning it"]
pub struct PreparedSourceFailure {
    access: Option<ServiceMainPreclaimError>,
    pub(super) receiver: Option<prepared_service::ServiceMainReceiver>,
    retirement: PreparedSourceRetirement,
    phase: &'static str,
}

/// Drives the original Main role without a replacement owner or cleanup clock.
#[must_use = "actual Main ownership remains until terminal body disposal"]
pub struct PreparedSourceRetirement {
    key: ServiceMainPreclaim,
    report_reference: bool,
    access: Option<ServiceMainPreclaimError>,
    receiver: Option<prepared_service::ServiceMainReceiver>,
}

impl prepared_service::PreparedSourceSelector {
    /// Reports the actual Main-held cause and permanently abandons new work.
    pub(crate) fn failure(&self, phase: &'static str) -> PreparedSourceFailure {
        let retirement = PreparedSourceRetirement::for_key(self.key.copy_selection());
        retirement.abandon_export();
        retirement.request_retirement();
        PreparedSourceFailure {
            access: None,
            receiver: None,
            retirement,
            phase,
        }
    }

    /// Retains the original access refusal independently of the initiating cause.
    pub(crate) fn failure_with_refusal(
        &self,
        phase: &'static str,
        access: ServiceMainPreclaimError,
    ) -> PreparedSourceFailure {
        let mut failure = self.failure(phase);
        failure.access = Some(access);
        failure
    }

    /// Drives this same role while preserving a designated imported export.
    pub(crate) fn into_retirement(self) -> PreparedSourceRetirement {
        let retirement = PreparedSourceRetirement::for_key(self.key);
        retirement.request_retirement();
        retirement
    }
}

impl<T: Send + 'static> prepared_service::PreparedSourceHandle<T> {
    /// Pins this role's terminal reports without closing its work gate.
    ///
    /// The runtime installs this observer before exporting its actual body.
    /// Dropping the observer requests retirement under the existing Main owner.
    ///
    /// # Errors
    /// Refuses a missing, stale or unavailable containing role.
    pub(crate) fn observe_retirement(
        &self,
    ) -> Result<PreparedSourceRetirement, ServiceMainPreclaimError> {
        let observer = PreparedSourceRetirement::for_key(self.key.copy_selection());
        if !observer.report_reference {
            return Err(ServiceMainPreclaimError::Role(
                "prepared retirement observer is unavailable",
            ));
        }
        Ok(observer)
    }

    /// Reports the actual Main-held failure and irreversibly bars further work.
    pub(crate) fn failure(&self, phase: &'static str) -> PreparedSourceFailure {
        self.erase().failure(phase)
    }

    /// Retains the original access refusal independently of the initiating cause.
    pub(crate) fn failure_with_refusal(
        &self,
        phase: &'static str,
        access: ServiceMainPreclaimError,
    ) -> PreparedSourceFailure {
        self.erase().failure_with_refusal(phase, access)
    }

    /// Moves this selector into the same role's existing retirement path.
    pub(crate) fn into_retirement(self) -> PreparedSourceRetirement {
        self.erase().into_retirement()
    }
}

impl prepared_service::ServiceMainHandle {
    /// Reports the actual Main-held failure without knowing its Pending type.
    pub(crate) fn failure(&self, phase: &'static str) -> PreparedSourceFailure {
        self.prepared_selector().failure(phase)
    }

    /// Retains the original access refusal without replacing its typed leaf.
    pub(crate) fn failure_with_refusal(
        &self,
        phase: &'static str,
        access: ServiceMainPreclaimError,
    ) -> PreparedSourceFailure {
        self.prepared_selector().failure_with_refusal(phase, access)
    }

    /// Drives the same occupied role without extracting a Service or native guard.
    pub(crate) fn into_retirement(self) -> PreparedSourceRetirement {
        self.prepared_selector().into_retirement()
    }
}

impl PreparedSourceFailure {
    /// Names the actual operation that refused, without a copied diagnostic.
    #[must_use]
    pub fn phase(&self) -> &'static str {
        self.phase
    }

    /// Borrows the actual typed first cause for the duration of a callback.
    ///
    /// Returns `None` when the exact role is unavailable or has no first cause.
    /// Neither outcome claims physical closure or permits another Source.
    pub fn with_first_error<R>(
        &self,
        apply: impl FnOnce(&(dyn Error + 'static)) -> R,
    ) -> Option<R> {
        let mut apply = Some(apply);
        if let Some(result) = self
            .retirement
            .with_first_error(|first| apply.take().map(|apply| apply(first)))
        {
            return result;
        }
        self.access
            .as_ref()
            .and_then(|first| apply.take().map(|apply| apply(first)))
    }

    /// Borrows each stored history without moving it outside its paid role.
    ///
    /// The callback must not reenter this role. Returns `false` if the exact
    /// role cannot currently be borrowed; that does not erase stored evidence.
    pub fn with_history(&self, apply: impl FnMut(&'static str, &(dyn Error + 'static))) -> bool {
        self.retirement.with_history(apply)
    }

    /// Retains the exact returned receiver without a replacement allocation.
    ///
    /// # Errors
    /// Returns both original values on a foreign role or occupied receiver slot.
    pub fn retain_receiver(
        mut self,
        receiver: prepared_service::ServiceMainReceiver,
    ) -> Result<Self, (Self, prepared_service::ServiceMainReceiver)> {
        if self.receiver.is_some() || !self.retirement.key.same_role(&receiver.key) {
            return Err((self, receiver));
        }
        self.receiver = Some(receiver);
        Ok(self)
    }

    /// Moves the same selector into physical retirement without replacing cause.
    pub fn into_retirement(self) -> PreparedSourceRetirement {
        let Self {
            access,
            receiver,
            mut retirement,
            ..
        } = self;
        retirement.access = access;
        retirement.receiver = receiver;
        retirement
    }
}

impl PreparedSourceRetirement {
    /// Pins another report over the same retained cause without another owner.
    pub(crate) fn report_failure(&self, phase: &'static str) -> PreparedSourceFailure {
        self.key.handle().failure(phase)
    }

    fn for_key(key: ServiceMainPreclaim) -> Self {
        let report_reference = key.queue.upgrade().is_some_and(|queue| {
            queue
                .slots
                .get(key.index)
                .is_some_and(|slot| report_refs::register(slot, key.epoch))
        });
        Self {
            key,
            report_reference,
            access: None,
            receiver: None,
        }
    }

    fn abandon_export(&self) {
        let Some(queue) = self.key.queue.upgrade() else {
            return;
        };
        let Some(slot) = queue.slots.get(self.key.index) else {
            return;
        };
        if slot.epoch.load(Ordering::Acquire) == self.key.epoch {
            slot.export_abandoned.store(true, Ordering::Release);
        }
    }

    fn request_retirement(&self) {
        let Some(queue) = self.key.queue.upgrade() else {
            return;
        };
        let Some(slot) = queue.slots.get(self.key.index) else {
            return;
        };
        if slot.epoch.load(Ordering::Acquire) == self.key.epoch {
            slot.request_retirement();
        }
    }

    fn with_first_error<R>(&self, apply: impl FnOnce(&(dyn Error + 'static)) -> R) -> Option<R> {
        let queue = self.key.queue.upgrade()?;
        let slot = queue.slots.get(self.key.index)?;
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch {
            return None;
        }
        let service = slot.service.try_lock().ok()?;
        if slot.is(CleanupPhase::TerminalOwned) || slot.is(CleanupPhase::TerminalDisposing) {
            return None;
        }
        if service.epoch == self.key.epoch
            && let Some(first) = service.start.as_ref().and_then(|start| start.first())
        {
            return Some(apply(first));
        }
        if service.epoch == self.key.epoch
            && let Some(first) = service
                .start
                .as_ref()
                .and_then(|start| start.adopted_semantic_shutdown_failure())
        {
            return Some(apply(first));
        }
        drop(service);
        let prepared = slot.prepared.try_lock().ok()?;
        if slot.is(CleanupPhase::TerminalOwned) || slot.is(CleanupPhase::TerminalDisposing) {
            return None;
        }
        if prepared.epoch == self.key.epoch
            && let (Some(owner), Some(project)) = (&prepared.owner, prepared.projection)
            && let Some(first) = project(owner.as_ref())
        {
            return Some(apply(first));
        }
        if prepared.epoch == self.key.epoch
            && let Some(first) = &prepared.terminal_access
        {
            return Some(apply(first));
        }
        drop(prepared);
        let service = slot.service.try_lock().ok()?;
        if service.epoch != self.key.epoch
            || slot.is(CleanupPhase::TerminalOwned)
            || slot.is(CleanupPhase::TerminalDisposing)
        {
            return None;
        }
        service
            .start
            .as_ref()
            .and_then(terminal::first_service_tail_failure)
            .or_else(|| {
                service
                    .return_body
                    .as_ref()
                    .and_then(|body| body.first_failure())
            })
            .map(apply)
    }

    /// Borrows all available raw history under the same original role.
    ///
    /// The callback must not reenter this role. A `false` result means that
    /// custody is unavailable or borrowed, rather than that its history is empty.
    pub fn with_history(
        &self,
        mut apply: impl FnMut(&'static str, &(dyn Error + 'static)),
    ) -> bool {
        let Some(queue) = self.key.queue.upgrade() else {
            return false;
        };
        let Some(slot) = queue.slots.get(self.key.index) else {
            return false;
        };
        let Ok(prepared) = slot.prepared.try_lock() else {
            return false;
        };
        let Ok(service) = slot.service.try_lock() else {
            return false;
        };
        let Ok(cell) = slot.cell.try_lock() else {
            return false;
        };
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch
            || prepared.epoch != self.key.epoch
            || service.epoch != self.key.epoch
            || cell.epoch != self.key.epoch
            || slot.is(CleanupPhase::TerminalOwned)
            || slot.is(CleanupPhase::TerminalDisposing)
        {
            return false;
        }
        if let Some(start) = &service.start {
            terminal::visit_service_history(start, &mut apply);
        }
        if let (Some(owner), Some(project)) = (&prepared.owner, prepared.history_projection)
            && let Some(history) = project(owner.as_ref())
        {
            apply("Source preparation", history);
        }
        if let Some(first) = &prepared.cleanup_failure {
            apply("prepared body cleanup", first);
        }
        if let Some(first) = &prepared.terminal_access {
            apply("terminal role access", first);
        }
        if let Some(first) = &cell.first_failure {
            apply("published body cleanup", first);
        }
        if let Some(first) = &cell.control_failure {
            apply("containing controls", first);
        }
        if let Some(first) = cell
            .retirement_input
            .as_ref()
            .and_then(|input| input.semantic_shutdown_failure())
        {
            apply("receiving semantic shutdown", first);
        }
        if let Some(body) = &cell.post_body {
            body.visit_history(&mut apply);
        }
        if let Some(body) = &service.return_body {
            body.visit_history(&mut apply);
        }
        if let Some(first) = &self.access {
            apply("Source role access", first);
        }
        true
    }

    /// Runs one bounded existing-owner attempt and independently observes return.
    ///
    /// # Errors
    /// Retains the same role on unavailable, borrowed or uncertain custody. No
    /// error changes a physical return already recorded by the same native loan.
    pub fn retry(&mut self) -> Result<bool, PreparedSourceRefusal> {
        let queue = self
            .key
            .queue
            .upgrade()
            .ok_or(PreparedSourceRefusal::RoleUnavailable)?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or(PreparedSourceRefusal::RoleUnavailable)?;
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch {
            return Err(PreparedSourceRefusal::RoleUnavailable);
        }
        self.request_retirement();
        let attempted = retry_slot(slot, Some(self.key.epoch));
        if slot.is(CleanupPhase::TerminalReady) {
            return Ok(true);
        }
        if slot.is(CleanupPhase::DestructionRefused) {
            return Err(PreparedSourceRefusal::DestructionUncertain);
        }
        attempted.map_err(|_| PreparedSourceRefusal::Pending)?;
        Ok(false)
    }

    /// Moves terminal reports while retaining their actual Main-funded role.
    ///
    /// The returned value disposes actual nested owners before freeing that
    /// exact role. Merely reporting it does not certify native return.
    ///
    /// # Errors
    /// Returns this same selector until body destruction, controls, native World
    /// return and the same Service discharge are all factual and consistent.
    pub fn finish(mut self) -> Result<ProductionVmConstructionPostBody, Self> {
        if !self.report_reference {
            return Err(self);
        }
        match terminal::take_terminal_body_with_reports(
            &self.key,
            &mut self.access,
            &mut self.receiver,
        ) {
            Ok(body) => {
                self.report_reference = false;
                Ok(body)
            }
            Err(_) => Err(self),
        }
    }
}

impl fmt::Debug for PreparedSourceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSourceFailure")
            .field("phase", &self.phase)
            .field("role", &self.retirement.key)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for PreparedSourceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.phase)?;
        match self.with_first_error(|first| write!(formatter, ": {first}")) {
            Some(result) => result,
            None => formatter.write_str(": actual first cause is unavailable from the same role"),
        }
    }
}

impl Error for PreparedSourceFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.access.as_ref().map(|first| first as &dyn Error)
    }
}

impl fmt::Debug for PreparedSourceRetirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSourceRetirement")
            .field("key", &self.key)
            .finish()
    }
}

impl Drop for PreparedSourceRetirement {
    fn drop(&mut self) {
        self.request_retirement();
        // Owned access/receiver leaves precede their actual report-reference
        // return. A role cannot be reused while an outside report owns a leaf.
        drop(self.access.take());
        drop(self.receiver.take());
        if !self.report_reference {
            return;
        }
        self.abandon_export();
        terminal::return_report_reference(&self.key, false);
    }
}
