//! Retains genuine native returns and their raw history after body destruction.
//!
//! A transferred tombstone carries history only. It cannot satisfy a Source
//! role's World-return requirement. Two actual body obligations fit inline;
//! the existing Target Pending Box is moved by operation-only upcast.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use crucible_linux_resource::host_services::process_birth::{
    AuthenticatedNativeWorldCleanupLoan, NativePoolReturnError, ServiceBirthError,
};

use crate::vm_lifecycle::ProductionHotForkCleanupObserver;
use crate::{ProductionVmConstructionCleanupError, SourceCleanupHistory};
use crucible_api::LifecycleApiError;

use super::target_post_body::{TargetConstructionPostBody, TargetReturn};

use crate::qemu_lifecycle_launcher::SourceWorldNotStarted;

/// Keeps actual returned-body obligations and typed reports under their role.
///
/// The Main cell owns this value until both actual native return and Service
/// release are observed. Its terminal move retains that same role while the
/// caller reports by borrowing. Disposal destroys nested causes before the
/// role is made reusable; moving a diagnostic is never native return evidence.
#[must_use = "terminal history remains paid until the same value is disposed"]
pub struct ProductionVmConstructionPostBody {
    pub(super) terminal: Option<super::terminal::TerminalCustody>,
    returns: [Option<NativeReturn>; 2],
    not_started: Option<SourceWorldNotStarted>,
    constructor_first: [Option<LifecycleApiError>; 2],
    cleanup_first: Option<ProductionVmConstructionCleanupError>,
    source_history: Option<SourceCleanupHistory>,
    source_retirement_history:
        Option<crate::vm_lifecycle::ProductionVmHotForkSourceRetirementHistory>,
}

enum NativeReturn {
    World(WorldReturn),
    Target(TargetReturn),
}

struct WorldReturn {
    loan: AuthenticatedNativeWorldCleanupLoan,
    observer: Option<Arc<dyn ProductionHotForkCleanupObserver>>,
    returned: bool,
    observer_returned: bool,
    first: Option<NativePoolReturnError>,
    observation: Option<ServiceBirthError>,
    observer_first: Option<crucible_api::host_operational::HostOperationalError>,
    observer_panic_payload: Option<Box<dyn std::any::Any + Send>>,
}

impl ProductionVmConstructionPostBody {
    pub(crate) const fn history_only() -> Self {
        Self {
            terminal: None,
            returns: [None, None],
            not_started: None,
            constructor_first: [None, None],
            cleanup_first: None,
            source_history: None,
            source_retirement_history: None,
        }
    }

    /// Moves the original loan; it does not issue or enter Cleanup.
    pub(crate) fn world(
        loan: AuthenticatedNativeWorldCleanupLoan,
        observer: Option<Arc<dyn ProductionHotForkCleanupObserver>>,
    ) -> Self {
        let mut body = Self::history_only();
        body.returns[0] = Some(NativeReturn::World(WorldReturn {
            loan,
            observer_returned: observer.is_none(),
            observer,
            returned: false,
            first: None,
            observation: None,
            observer_first: None,
            observer_panic_payload: None,
        }));
        body
    }

    pub(crate) fn never_entered(journal: SourceWorldNotStarted) -> Self {
        let mut body = Self::history_only();
        body.not_started = Some(journal);
        body
    }

    /// Retains only the exact selector to the already Main-owned Target Box.
    pub(crate) fn target<T: TargetConstructionPostBody>(
        selector: super::prepared_service::PreparedSourceSelector,
    ) -> Self {
        let mut body = Self::history_only();
        body.returns[0] = Some(NativeReturn::Target(TargetReturn::new::<T>(selector)));
        body
    }

    /// Checks the whole merge before moving either independently owned body.
    pub(crate) fn can_append(&self, other: &Self) -> bool {
        let returns =
            self.returns.iter().flatten().count() + other.returns.iter().flatten().count();
        let reports = self.constructor_first.iter().flatten().count()
            + other.constructor_first.iter().flatten().count();
        self.terminal.is_none()
            && other.terminal.is_none()
            && returns <= 2
            && reports <= 2
            && !(self.not_started.is_some() && other.not_started.is_some())
            && !(self.cleanup_first.is_some() && other.cleanup_first.is_some())
            && !(self.source_history.is_some() && other.source_history.is_some())
            && !(self.source_retirement_history.is_some()
                && other.source_retirement_history.is_some())
    }

    /// Merges two real bodies without allocating or discarding either on refusal.
    pub(crate) fn append(&mut self, mut other: Self) -> Result<(), Self> {
        if !self.can_append(&other) {
            return Err(other);
        }
        for incoming in &mut other.returns {
            if incoming.is_some() {
                for vacant in &mut self.returns {
                    if vacant.is_none() {
                        *vacant = incoming.take();
                        break;
                    }
                }
            }
        }
        for incoming in &mut other.constructor_first {
            if incoming.is_some() {
                for vacant in &mut self.constructor_first {
                    if vacant.is_none() {
                        *vacant = incoming.take();
                        break;
                    }
                }
            }
        }
        if self.not_started.is_none() {
            self.not_started = other.not_started.take();
        }
        if self.cleanup_first.is_none() {
            self.cleanup_first = other.cleanup_first.take();
        }
        if self.source_history.is_none() {
            self.source_history = other.source_history.take();
        }
        if self.source_retirement_history.is_none() {
            self.source_retirement_history = other.source_retirement_history.take();
        }
        Ok(())
    }

    pub(crate) fn retain_constructor_first(
        &mut self,
        first: LifecycleApiError,
    ) -> Result<(), LifecycleApiError> {
        for slot in &mut self.constructor_first {
            if slot.is_none() {
                *slot = Some(first);
                return Ok(());
            }
        }
        Err(first)
    }

    pub(crate) fn retain_source_history(
        &mut self,
        history: SourceCleanupHistory,
    ) -> Result<(), SourceCleanupHistory> {
        if self.source_history.is_some() {
            return Err(history);
        }
        self.source_history = Some(history);
        Ok(())
    }

    pub(crate) fn retain_cleanup_first(&mut self, first: ProductionVmConstructionCleanupError) {
        ProductionVmConstructionCleanupError::retain_first(&mut self.cleanup_first, first);
    }

    /// Refuses a transferred tombstone as a standalone Source-return proof.
    pub(crate) fn has_source_return(&self) -> bool {
        self.not_started.is_some()
            || self
                .returns
                .iter()
                .flatten()
                .any(|body| matches!(body, NativeReturn::World(_)))
    }

    pub(crate) fn has_target_return(&self) -> bool {
        self.returns
            .iter()
            .flatten()
            .any(|body| matches!(body, NativeReturn::Target(_)))
    }

    pub(crate) fn world_never_entered(&self) -> bool {
        self.not_started.is_some() && self.returns.iter().all(Option::is_none)
    }

    /// Drives real postbody owners, preserving physical facts after post refusal.
    pub(crate) fn retry_returns(&mut self) -> bool {
        let mut returned = true;
        for body in self.returns.iter_mut().flatten() {
            returned &= match body {
                NativeReturn::World(world) => world.retry(),
                NativeReturn::Target(target) => {
                    if target.is_physically_returned() {
                        true
                    } else {
                        // The same Target owner retains its typed failure.
                        let _returned = target.retry_after_body();
                        target.is_physically_returned()
                    }
                }
            };
        }
        returned
    }

    pub(super) fn has_world_return(&self) -> bool {
        self.returns
            .iter()
            .flatten()
            .any(|body| matches!(body, NativeReturn::World(_)))
    }

    pub(super) fn worlds_physically_returned(&self) -> bool {
        self.has_world_return()
            && self.returns.iter().flatten().all(|body| match body {
                NativeReturn::World(world) => world.returned,
                NativeReturn::Target(_) => false,
            })
    }

    /// Observes only actual Target returns, without certifying a Source World.
    pub(super) fn targets_physically_returned(&self) -> bool {
        self.has_target_return()
            && self.returns.iter().flatten().all(|body| match body {
                NativeReturn::Target(target) => target.is_physically_returned(),
                NativeReturn::World(_) => false,
            })
    }

    pub(super) fn matches_world_controls(
        &self,
        controls: &crucible_linux_resource::host_services::process_birth::AuthenticatedNativeWorldControlLease,
    ) -> bool {
        let mut found = false;
        for body in self.returns.iter().flatten() {
            if let NativeReturn::World(world) = body {
                found = true;
                if controls.verify_world_loan(&world.loan).is_err() {
                    return false;
                }
            }
        }
        found
    }

    /// Observes each original return journal without creating another operation.
    pub(super) fn native_returns_observed(&self) -> bool {
        if self.world_never_entered() {
            return true;
        }
        self.returns.iter().any(Option::is_some)
            && self.returns.iter().flatten().all(|body| match body {
                NativeReturn::World(world) => world.returned && world.observer_returned,
                NativeReturn::Target(target) => target.is_physically_returned(),
            })
    }

    pub(crate) fn retained_source_cleanup(
        &self,
    ) -> Option<
        Result<
            Arc<crucible_linux_resource::host_supervision::HostOperationGuard>,
            ServiceBirthError,
        >,
    > {
        if self.returns.iter().flatten().count() != 1 {
            return None;
        }
        match self.returns.iter().flatten().next()? {
            NativeReturn::World(world) => Some(world.loan.retained_cleanup()),
            NativeReturn::Target(_) => None,
        }
    }

    pub(crate) fn retain_source_retirement_history(
        &mut self,
        history: crate::vm_lifecycle::ProductionVmHotForkSourceRetirementHistory,
    ) -> Result<(), crate::vm_lifecycle::ProductionVmHotForkSourceRetirementHistory> {
        if self.source_retirement_history.is_some() {
            return Err(history);
        }
        self.source_retirement_history = Some(history);
        Ok(())
    }

    /// Borrows the original typed prepared body only after terminal transfer.
    ///
    /// The same role remains pinned throughout this pure final ownership tail.
    /// The callback may move existing metadata or dispose reported history; it
    /// may not issue native work or treat a failed type check as physical return.
    /// The result cannot borrow the scoped body, and no Box is extracted.
    pub(crate) fn with_terminal_prepared<T: Send + 'static, R>(
        &mut self,
        apply: impl FnOnce(&mut T) -> R,
    ) -> Option<R> {
        let terminal = self.terminal.as_mut()?;
        let owner = terminal.prepared.as_mut()?.downcast_mut::<T>()?;
        Some(apply(owner))
    }

    /// Returns metadata to this terminal Target's actual retained Source parent.
    ///
    /// The Target must already have physically returned, and this same terminal
    /// value must own its original prepared body. Only the Source selector held
    /// by that body can select the parent. Work may be barred and its external
    /// body destroyed, but its actual Pending must still retain the open return
    /// destination. A missing type or busy mutex proves no physical return.
    ///
    /// The fixed caller only validates/moves existing metadata. It must destroy
    /// observed row history before entry, and may perform no IO, Original entry,
    /// callback or destructor while the Source prepared mutex is held. The
    /// result cannot borrow either scoped body. Generic Loop-return gates are
    /// intentionally unchanged.
    pub(crate) fn with_terminal_target_parent_metadata<
        T: TargetConstructionPostBody,
        S: Send + 'static,
        R,
    >(
        &mut self,
        apply: impl FnOnce(&mut T, &mut S) -> R,
    ) -> Option<R> {
        let terminal = self.terminal.as_mut()?;
        let target = terminal.prepared.as_mut()?.downcast_mut::<T>()?;
        if !target.is_physically_returned() {
            return None;
        }
        let source = target.source_selector().clone();
        if source.same_role(&super::prepared_service::PreparedSourceSelector {
            key: terminal.key.copy_selection(),
        }) || !source.key.queue.ptr_eq(&Arc::downgrade(&terminal.queue))
        {
            return None;
        }
        let slot = terminal.queue.slots.get(source.key.index)?;
        let mut prepared = slot.prepared.try_lock().ok()?;
        if slot.epoch.load(std::sync::atomic::Ordering::Acquire) != source.key.epoch
            || prepared.epoch != source.key.epoch
            || !(slot.is(super::CleanupPhase::Reserved)
                || slot.is(super::CleanupPhase::RetryingPrepared)
                || slot.is(super::CleanupPhase::OwnerDestroyed)
                || slot.is(super::CleanupPhase::Completing))
            || prepared.body_closed
            || prepared.post_body_taken
            || prepared.panic_payload.is_some()
        {
            return None;
        }
        let parent = prepared.owner.as_mut()?.downcast_mut::<S>()?;
        Some(apply(target, parent))
    }

    /// Borrows all retained histories without releasing their actual paid role.
    ///
    /// Each callback borrows the original typed leaf or the original finite
    /// history report. No callback may reenter the containing role.
    pub fn visit_history(&self, mut apply: impl FnMut(&'static str, &(dyn Error + 'static))) {
        if let Some(terminal) = &self.terminal {
            terminal.visit_history(&mut apply);
        }
        if let Some(history) = &self.source_retirement_history
            && !history.is_empty()
        {
            apply("Source retirement", history);
        }
        if let Some(history) = &self.source_history {
            apply("Source cleanup", history);
        }
        for first in self.constructor_first.iter().flatten() {
            apply("construction", first);
        }
        if let Some(first) = &self.cleanup_first {
            apply("body cleanup", first);
        }
        for body in self.returns.iter().flatten() {
            if let NativeReturn::World(world) = body {
                if let Some(first) = &world.first {
                    apply("World return", first);
                }
                if let Some(first) = &world.observation {
                    apply("World return observation", first);
                }
                if let Some(first) = &world.observer_first {
                    apply("Source observer", first);
                }
            }
        }
    }

    /// Borrows the actual first owned report after its protected terminal move.
    pub fn first_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.terminal
            .as_ref()
            .and_then(super::terminal::TerminalCustody::first_failure)
            .or_else(|| {
                self.source_retirement_history
                    .as_ref()
                    .filter(|history| !history.is_empty())
                    .map(|first| first as &dyn Error)
            })
            .or_else(|| {
                self.source_history
                    .as_ref()
                    .map(|first| first as &dyn Error)
            })
            .or_else(|| {
                self.constructor_first
                    .iter()
                    .flatten()
                    .next()
                    .map(|first| first as &dyn Error)
            })
            .or_else(|| self.cleanup_first.as_ref().map(|first| first as &dyn Error))
            .or_else(|| {
                self.returns
                    .iter()
                    .flatten()
                    .find_map(NativeReturn::first_failure)
            })
    }
}

impl WorldReturn {
    fn observe_return(&mut self) {
        if self.returned {
            return;
        }
        match self.loan.observe_physically_returned() {
            Ok(true) => self.returned = true,
            Ok(false) => {}
            Err(first) => {
                self.observation.get_or_insert(first);
            }
        }
    }

    fn retry(&mut self) -> bool {
        self.observe_return();
        if !self.returned {
            if let Err(first) = self.loan.try_finish_after_members_returned() {
                self.first.get_or_insert(first);
            }
            // Native return latches consumption before its independent post.
            // A negative post must never cause a second physical debt return.
            self.observe_return();
        }
        if !self.returned || self.observer_returned || self.observer_panic_payload.is_some() {
            return self.returned && self.observer_returned;
        }
        let Some(observer) = self.observer.as_ref() else {
            return false;
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            observer.after_world_cleanup()
        })) {
            Ok(Ok(())) => self.observer_returned = true,
            Ok(Err(first)) => {
                self.observer_first.get_or_insert(first);
            }
            Err(payload) => self.observer_panic_payload = Some(payload),
        }
        self.returned && self.observer_returned
    }
}

impl NativeReturn {
    fn first_failure(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Target(_) => None,
            Self::World(world) => world
                .first
                .as_ref()
                .map(|first| first as &dyn Error)
                .or_else(|| world.observation.as_ref().map(|first| first as &dyn Error))
                .or_else(|| {
                    world
                        .observer_first
                        .as_ref()
                        .map(|first| first as &dyn Error)
                }),
        }
    }
}

impl fmt::Debug for ProductionVmConstructionPostBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionVmConstructionPostBody")
            .field("native_returns", &self.returns.iter().flatten().count())
            .field("never_entered", &self.not_started.is_some())
            .field("first_failure", &self.first_failure())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ProductionVmConstructionPostBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.first_failure() {
            Some(first) => write!(formatter, "Source terminal history: {first}"),
            None => formatter.write_str("Source physically returned without a retained failure"),
        }
    }
}

impl Error for ProductionVmConstructionPostBody {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.first_failure()
    }
}

impl Drop for ProductionVmConstructionPostBody {
    fn drop(&mut self) {
        let Some(terminal) = self.terminal.take() else {
            return;
        };
        let key = terminal.key.copy_selection();
        let queue = Arc::clone(&terminal.queue);
        // The terminal reference is transferred, never duplicated. All nested
        // actual leaves and Main-paid shells die outside the role metadata lock.
        // Take every field before starting destruction. If any destructor
        // unwinds, no later automatic field drop can escape this observed cut.
        let payload = (
            std::mem::take(&mut self.returns),
            self.not_started.take(),
            std::mem::take(&mut self.constructor_first),
            self.cleanup_first.take(),
            self.source_history.take(),
            self.source_retirement_history.take(),
            terminal,
        );
        let slot = &queue.slots[key.index];
        if !super::terminal::destroy_payload(slot, payload) {
            return;
        }
        super::terminal::return_report_reference(&key, true);
    }
}
