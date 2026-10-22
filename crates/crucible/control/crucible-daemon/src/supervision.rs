//! Private operational clocks for process supervision and fork-rate admission.
//!
//! These clocks never define guest time, an execution horizon, campaign fuel,
//! or a persisted execution result. Process deadlines only stop host waiting;
//! the fork clock feeds the process-wide launch-rate limiter, not planner
//! selection. Neither clock exposes its host timestamp to callers.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::ExecutionCancellation;
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationState,
    HostOperationSupervisor,
};

/// Measures elapsed host time solely for operational fork-rate admission.
pub(super) struct ForkRateClock {
    origin: Instant,
}

impl ForkRateClock {
    pub(super) fn new() -> Self {
        Self { origin: now() }
    }

    pub(super) fn elapsed_nanos(&self) -> u64 {
        let elapsed = now().saturating_duration_since(self.origin);
        u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
    }
}

/// Bounds one host process operation without exposing an absolute timestamp.
#[derive(Clone, Copy)]
pub(super) struct ProcessDeadline {
    deadline: Instant,
}

impl ProcessDeadline {
    /// Wraps an existing host deadline without exposing clock reads to callers.
    pub(super) const fn at(deadline: Instant) -> Self {
        Self { deadline }
    }

    /// Returns no deadline if the requested host duration cannot be represented.
    pub(super) fn after(timeout: Duration) -> Option<Self> {
        now().checked_add(timeout).map(|deadline| Self { deadline })
    }

    /// Returns the remaining operational wait allowance.
    pub(super) fn remaining(self) -> Duration {
        self.deadline.saturating_duration_since(now())
    }

    pub(super) fn expired(self) -> bool {
        now() >= self.deadline
    }

    /// Caps a process-poll pause at the remaining operational wait allowance.
    pub(super) fn pause(self, maximum: Duration) {
        std::thread::sleep(maximum.min(self.remaining()));
    }
}

/// Explicit stack reservation for the independently admitted watchdog task.
pub(crate) const HOST_WATCHDOG_STACK_BYTES: usize = 256 * 1024;

/// Monotonic, clone-shared operational deadline for one accepted assignment.
#[derive(Clone, Debug)]
pub(super) struct AssignmentHostWatchdog {
    supervisor: HostOperationSupervisor,
    // Context aliases retain the same whole-family guard beyond watcher join.
    // Its last Arc/control free remains covered by the external original payer.
    #[cfg(feature = "private-measurement-domain")]
    original: Option<Arc<HostOperationGuard>>,
}

impl AssignmentHostWatchdog {
    /// Wraps the already-verified child and its same admitted original alias.
    #[cfg(feature = "private-measurement-domain")]
    pub(crate) fn for_original_capture(
        supervisor: HostOperationSupervisor,
        original: Arc<HostOperationGuard>,
    ) -> Self {
        Self {
            supervisor,
            original: Some(original),
        }
    }

    /// Reports whether the assignment budget elapsed or its watcher fired.
    pub(super) fn expired(&self) -> bool {
        #[cfg(feature = "private-measurement-domain")]
        if let Some(original) = &self.original
            && original.wait_slice().is_err()
        {
            return true;
        }
        self.supervisor.outer_cap_status().map_or(true, |status| {
            matches!(
                status.state,
                HostOperationState::Expired | HostOperationState::Canceled
            )
        })
    }

    pub(super) fn supervisor(&self) -> &HostOperationSupervisor {
        &self.supervisor
    }
}

/// Cancels a live QEMU child when the whole assignment exceeds its host budget.
pub(super) struct AssignmentHostWatchdogGuard {
    complete_outer: bool,
    service_stop_expired: Option<bool>,
    caller: Option<HostOperationSupervisor>,
    stopped: Arc<AtomicBool>,
    operation_expired: WatchdogExpiration,
    operation: Option<Arc<HostOperationGuard>>,
    cancellation: ExecutionCancellation,
    registry: Option<crate::HostOperationalRegistry>,
    watcher: Option<JoinHandle<()>>,
    pub(super) state: AssignmentHostWatchdog,
}

enum WatchdogExpiration {
    Operation(Arc<AtomicBool>),
    Service(Arc<ServiceWatchdogExpiration>),
}

impl WatchdogExpiration {
    fn is_expired(&self) -> bool {
        match self {
            Self::Operation(expired) => expired.load(Ordering::Acquire),
            Self::Service(expiration) => expiration.expired.load(Ordering::Acquire),
        }
    }

    fn take_service_failure(&self) -> (Option<ServiceWatchdogFailure>, bool) {
        match self {
            Self::Operation(_) => (None, false),
            Self::Service(expiration) => expiration.take_service_failure(),
        }
    }
}

#[derive(Default)]
struct ServiceWatchdogExpiration {
    expired: AtomicBool,
    service_failure: Mutex<ServiceWatchdogFailure>,
}

/// Retains the actual first Service-watcher trigger and its cancellation results.
#[derive(Debug, Default)]
pub(crate) struct ServiceWatchdogFailure {
    pub(crate) trigger: Option<ServiceWatchdogTrigger>,
    pub(crate) cancellation:
        Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    pub(crate) pager_cancellation: Option<crucible_control_api::host_operational::HostOperationalError>,
}

/// Identifies the observed Service-watcher stop condition without erasing it.
#[derive(Debug)]
pub(crate) enum ServiceWatchdogTrigger {
    Cancellation,
    Original(crucible_host_resources::host_supervision::HostSupervisionError),
    Caller(crucible_host_resources::host_supervision::HostSupervisionError),
}

impl ServiceWatchdogExpiration {
    fn record_service_trigger(&self, trigger: ServiceWatchdogTrigger) {
        // This is a diagnostic journal in the existing shared watcher body.
        // Poison recovery preserves its owned values; it supplies no authority
        // and does not repair or clear the original synchronization failure.
        let mut journal = self
            .service_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        journal.trigger = Some(trigger);
    }

    fn record_service_cancellation(
        &self,
        first: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    ) {
        let mut journal = self
            .service_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        journal.cancellation = first;
    }

    fn record_service_pager_cancellation(
        &self,
        first: Option<crucible_control_api::host_operational::HostOperationalError>,
    ) {
        let mut journal = self
            .service_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        journal.pager_cancellation = first;
    }

    fn take_service_failure(&self) -> (Option<ServiceWatchdogFailure>, bool) {
        match self.service_failure.lock() {
            Ok(mut journal) => (Some(std::mem::take(&mut *journal)), false),
            Err(poisoned) => (Some(std::mem::take(&mut *poisoned.into_inner())), true),
        }
    }
}

/// Retains raw Service-watchdog outcomes after its actual thread handle is consumed.
///
/// A join error carries the original panic payload. It still records a consumed
/// join, separately from original completion, cancellation and actor discharge.
pub(crate) struct ServiceWatchdogStop {
    pub(crate) completion_attempted: bool,
    pub(crate) completion: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    pub(crate) join_attempted: bool,
    pub(crate) join_failure: Option<Box<dyn std::any::Any + Send>>,
    pub(crate) caller: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    pub(crate) cancellation:
        Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    pub(crate) pager_cancellation: Option<crucible_control_api::host_operational::HostOperationalError>,
    pub(crate) expired: bool,
    pub(crate) watcher_failure: Option<ServiceWatchdogFailure>,
    pub(crate) watcher_history_poisoned: bool,
}

impl std::fmt::Debug for ServiceWatchdogStop {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceWatchdogStop")
            .field("completion_attempted", &self.completion_attempted)
            .field("completion", &self.completion)
            .field("join_attempted", &self.join_attempted)
            .field("join_panicked", &self.join_failure.is_some())
            .field("caller", &self.caller)
            .field("cancellation", &self.cancellation)
            .field("pager_cancellation", &self.pager_cancellation)
            .field("expired", &self.expired)
            .field("watcher_failure", &self.watcher_failure)
            .field("watcher_history_poisoned", &self.watcher_history_poisoned)
            .finish()
    }
}

/// Keeps the original watcher charged through linear result publication.
#[derive(Clone, Default)]
pub(crate) struct PublicationSupervision {
    ownership: Arc<Mutex<PublicationOwnership>>,
}

#[derive(Default)]
struct PublicationOwnership {
    watcher: Option<AssignmentHostWatchdogGuard>,
    caller: Option<HostOperationSupervisor>,
    metadata: Option<crucible_engine::owned_decode::DecodeCustody>,
}

impl std::fmt::Debug for PublicationSupervision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicationSupervision")
            .finish_non_exhaustive()
    }
}

impl PublicationSupervision {
    /// Retains the successful worker input's original metadata account.
    pub(crate) fn retain_metadata(
        &self,
        metadata: crucible_engine::owned_decode::DecodeCustody,
    ) -> std::io::Result<()> {
        let mut ownership = self
            .ownership
            .lock()
            .map_err(|_| std::io::Error::other("publication ownership poisoned"))?;
        if ownership.metadata.is_some() {
            return Err(std::io::Error::other(
                "publication metadata already retained",
            ));
        }
        ownership.metadata = Some(metadata);
        Ok(())
    }

    /// Restores original worker metadata on the synchronous publication thread.
    pub(crate) fn enter_metadata(
        &self,
    ) -> std::io::Result<Option<crucible_engine::owned_decode::DecodeScope>> {
        let metadata = self
            .ownership
            .lock()
            .map_err(|_| std::io::Error::other("publication ownership poisoned"))?
            .metadata
            .clone();
        Ok(metadata.and_then(|metadata| metadata.enter()))
    }

    /// Binds the original caller before any assignment watcher is started.
    pub(crate) fn bind_caller(&self, caller: &HostOperationSupervisor) -> std::io::Result<()> {
        caller
            .wait_for_active_work_change()
            .map_err(std::io::Error::other)?;
        let mut ownership = self
            .ownership
            .lock()
            .map_err(|_| std::io::Error::other("publication ownership poisoned"))?;
        if ownership.watcher.is_some() || ownership.caller.is_some() {
            return Err(std::io::Error::other(
                "caller supervision already bound or started",
            ));
        }
        ownership.caller = Some(caller.clone());
        Ok(())
    }

    pub(crate) fn start(
        &self,
        milliseconds: Option<u64>,
        cancellation: ExecutionCancellation,
        budgets: HostOperationBudgets,
        registry: Option<crate::HostOperationalRegistry>,
    ) -> std::io::Result<(AssignmentHostWatchdog, bool)> {
        let mut slot = self
            .ownership
            .lock()
            .map_err(|_| std::io::Error::other("publication ownership poisoned"))?;
        if let Some(watcher) = &slot.watcher {
            // Operational retries share the first assignment's original cap.
            return Ok((watcher.state.clone(), false));
        }
        let watcher = AssignmentHostWatchdogGuard::start_under(
            milliseconds,
            cancellation,
            budgets,
            slot.caller.clone(),
            registry,
        )?;
        let state = watcher.state.clone();
        slot.watcher = Some(watcher);
        Ok((state, true))
    }

    pub(crate) fn begin_publication(&self) -> std::io::Result<()> {
        let mut slot = self
            .ownership
            .lock()
            .map_err(|_| std::io::Error::other("publication ownership poisoned"))?;
        if let Some(caller) = &slot.caller {
            caller
                .wait_for_active_work_change()
                .map_err(std::io::Error::other)?;
        }
        let watcher = slot
            .watcher
            .as_mut()
            .ok_or_else(|| std::io::Error::other("original assignment owner unavailable"))?;
        let publication = Arc::new(
            watcher
                .state
                .supervisor
                .begin(HostOperationClass::CheckpointPublication)
                .map_err(std::io::Error::other)?,
        );
        if let Some(operation) = &watcher.operation {
            operation.complete().map_err(std::io::Error::other)?;
        }
        watcher.operation = Some(publication);
        Ok(())
    }

    pub(crate) fn guard(
        &self,
    ) -> Result<Arc<HostOperationGuard>, crucible_control_api::host_operational::HostOperationalError> {
        self.ownership
            .lock()
            .map_err(|_| crucible_control_api::host_operational::HostOperationalError::Unavailable)?
            .watcher
            .as_ref()
            .and_then(|watcher| watcher.operation.clone())
            .ok_or(crucible_control_api::host_operational::HostOperationalError::Unavailable)
    }

    /// Joins the real watcher before its host task and stack charge is discharged.
    pub(crate) fn finish(
        &self,
    ) -> Result<(), crucible_control_api::host_operational::HostOperationalError> {
        let mut slot = self
            .ownership
            .lock()
            .map_err(|_| crucible_control_api::host_operational::HostOperationalError::Unavailable)?;
        if let Some(mut watcher) = slot.watcher.take() {
            watcher.stop();
        }
        Ok(())
    }
}

impl AssignmentHostWatchdogGuard {
    /// Starts operational supervision for one accepted assignment.
    // crucible-lint: allow clippy-disallowed-method -- host time never enters campaign semantic state.
    #[allow(clippy::disallowed_methods)]
    #[cfg(test)]
    pub(super) fn start(
        milliseconds: Option<u64>,
        cancellation: ExecutionCancellation,
        budgets: HostOperationBudgets,
    ) -> std::io::Result<Self> {
        Self::start_under(milliseconds, cancellation, budgets, None, None)
    }

    fn start_under(
        milliseconds: Option<u64>,
        cancellation: ExecutionCancellation,
        budgets: HostOperationBudgets,
        caller: Option<HostOperationSupervisor>,
        registry: Option<crate::HostOperationalRegistry>,
    ) -> std::io::Result<Self> {
        let supervisor =
            HostOperationSupervisor::new(budgets, milliseconds.map(Duration::from_millis))
                .map_err(std::io::Error::other)?;
        // Backend operations own their class scopes. A Quantum guard here
        // would incorrectly charge VM setup, capture, and publication to guest
        // execution time instead of their independently authored allowances.
        Self::start_service_under(supervisor, cancellation, caller, registry)
    }

    /// Retains a separately registered preparation cap and its finite class guard.
    pub(super) fn start_preparation(
        supervisor: HostOperationSupervisor,
        cancellation: ExecutionCancellation,
    ) -> std::io::Result<Self> {
        Self::start_operation(supervisor, HostOperationClass::Preparation, cancellation)
    }

    /// Watches only active work of a retained service; idle time has no class cap.
    pub(super) fn start_service(
        supervisor: HostOperationSupervisor,
        cancellation: ExecutionCancellation,
        registry: Option<crate::HostOperationalRegistry>,
    ) -> std::io::Result<Self> {
        Self::start_service_under(supervisor, cancellation, None, registry)
    }

    fn start_service_under(
        supervisor: HostOperationSupervisor,
        cancellation: ExecutionCancellation,
        caller: Option<HostOperationSupervisor>,
        registry: Option<crate::HostOperationalRegistry>,
    ) -> std::io::Result<Self> {
        let stopped = Arc::new(AtomicBool::new(false));
        let operation_expired = Arc::new(ServiceWatchdogExpiration::default());
        let watcher_stopped = stopped.clone();
        let watcher_expired = operation_expired.clone();
        let watcher_cancellation = cancellation.clone();
        let watcher_supervisor = supervisor.clone();
        let watcher_caller = caller.clone();
        let watcher_registry = registry.clone();
        let watcher = thread::Builder::new()
            .name(String::from("retained-service-watchdog"))
            .stack_size(HOST_WATCHDOG_STACK_BYTES)
            .spawn(move || {
                while !watcher_stopped.load(Ordering::Acquire) {
                    // One already charged watcher observes both original caps.
                    // It neither renews nor completes the caller's authority.
                    let trigger = if watcher_cancellation.is_canceled() {
                        Some(ServiceWatchdogTrigger::Cancellation)
                    } else if let Err(first) = watcher_supervisor.wait_for_active_work_change() {
                        Some(ServiceWatchdogTrigger::Original(first))
                    } else {
                        watcher_caller.as_ref().and_then(|caller| {
                            caller
                                .wait_for_active_work_change()
                                .err()
                                .map(ServiceWatchdogTrigger::Caller)
                        })
                    };
                    if let Some(trigger) = trigger {
                        if !watcher_stopped.load(Ordering::Acquire) {
                            watcher_expired.record_service_trigger(trigger);
                            watcher_expired.expired.store(true, Ordering::Release);
                            watcher_expired
                                .record_service_cancellation(watcher_supervisor.cancel().err());
                            // Containment is published independently of the
                            // pager's acknowledgment and its retained raw error.
                            watcher_cancellation.cancel();
                            if let Some(registry) = &watcher_registry {
                                watcher_expired.record_service_pager_cancellation(
                                    registry.cancel_registered_pagers(&watcher_supervisor).err(),
                                );
                            }
                        }
                        break;
                    }
                }
            })?;
        Ok(Self {
            complete_outer: true,
            service_stop_expired: None,
            caller,
            stopped,
            operation_expired: WatchdogExpiration::Service(operation_expired),
            operation: None,
            cancellation,
            registry,
            watcher: Some(watcher),
            state: AssignmentHostWatchdog {
                supervisor,
                #[cfg(feature = "private-measurement-domain")]
                original: None,
            },
        })
    }

    /// Joins one borrowed roster without completing its caller's original cap.
    pub(super) fn start_borrowed_service(
        supervisor: HostOperationSupervisor,
        cancellation: ExecutionCancellation,
        registry: Option<crate::HostOperationalRegistry>,
    ) -> std::io::Result<Self> {
        let mut watcher = Self::start_service(supervisor, cancellation, registry)?;
        watcher.complete_outer = false;
        Ok(watcher)
    }

    fn start_operation(
        supervisor: HostOperationSupervisor,
        class: HostOperationClass,
        cancellation: ExecutionCancellation,
    ) -> std::io::Result<Self> {
        let operation = Arc::new(supervisor.begin(class).map_err(std::io::Error::other)?);
        let state = AssignmentHostWatchdog {
            supervisor,
            #[cfg(feature = "private-measurement-domain")]
            original: None,
        };
        let stopped = Arc::new(AtomicBool::new(false));
        let operation_expired = Arc::new(AtomicBool::new(false));
        let watcher_expired = operation_expired.clone();
        let watcher_supervisor = state.supervisor.clone();
        let watcher_stopped = stopped.clone();
        let watcher_cancellation = cancellation.clone();
        let watcher = thread::Builder::new()
            .name(String::from("campaign-host-watchdog"))
            .stack_size(HOST_WATCHDOG_STACK_BYTES)
            .spawn(move || {
                while !watcher_stopped.load(Ordering::Acquire) {
                    if watcher_supervisor.wait_for_active_work_change().is_err() {
                        if !watcher_stopped.load(Ordering::Acquire) {
                            watcher_expired.store(true, Ordering::Release);
                            watcher_cancellation.cancel();
                        }
                        break;
                    }
                }
            })?;
        Ok(Self {
            complete_outer: true,
            service_stop_expired: None,
            caller: None,
            stopped,
            operation_expired: WatchdogExpiration::Operation(operation_expired),
            operation: Some(operation),
            cancellation,
            registry: None,
            watcher: Some(watcher),
            state,
        })
    }

    /// Consumes this Service watcher once and retains its independent raw results.
    ///
    /// Joining consumes the actual thread handle even if the thread panicked.
    /// Original completion and cancellation errors remain observations; neither
    /// error authorizes replaying a join or completing a replacement Original.
    pub(crate) fn stop_service_owned(mut self) -> ServiceWatchdogStop {
        // Record consumption before any effect, including original completion.
        self.service_stop_expired = Some(true);
        self.stopped.store(true, Ordering::Release);
        let completion_attempted = self.complete_outer;
        let completion = self
            .complete_outer
            .then(|| self.state.supervisor.complete().err())
            .flatten();
        let join_attempted = self.watcher.is_some();
        let join_failure = self.watcher.take().and_then(|watcher| watcher.join().err());
        let caller = self
            .caller
            .as_ref()
            .and_then(|caller| caller.wait_for_active_work_change().err());
        let expired = caller.is_some()
            || join_failure.is_some()
            || self.state.expired()
            || self.operation_expired.is_expired();

        let mut cancellation = None;
        let mut pager_cancellation = None;
        if expired {
            self.cancellation.cancel();
            if !self.operation_expired.is_expired()
                && let Some(registry) = &self.registry
            {
                cancellation = self.state.supervisor.cancel().err();
                pager_cancellation = registry
                    .cancel_registered_pagers(&self.state.supervisor)
                    .err();
            }
        }
        let (watcher_failure, watcher_history_poisoned) =
            self.operation_expired.take_service_failure();
        self.service_stop_expired = Some(expired);
        ServiceWatchdogStop {
            completion_attempted,
            completion,
            join_attempted,
            join_failure,
            caller,
            cancellation,
            pager_cancellation,
            expired,
            watcher_failure,
            watcher_history_poisoned,
        }
    }

    /// Stops supervision and reports whether the host allowance expired.
    pub(super) fn stop(&mut self) -> bool {
        if let Some(expired) = self.service_stop_expired {
            return expired;
        }
        // A completed candidate cannot win a race against the assignment deadline
        // merely because the watchdog thread has not been scheduled yet.
        let phase_expired = self.operation.as_ref().is_some_and(|operation| {
            operation.status().map_or(true, |status| {
                matches!(
                    status.state,
                    HostOperationState::Expired | HostOperationState::Canceled
                )
            })
        });
        self.stopped.store(true, Ordering::Release);
        // Completion and amendments share the same original-start expiry check.
        // Terminal state also wakes every waiter before this thread joins.
        if self.complete_outer {
            let _ = self.state.supervisor.complete();
        }
        let joined = self
            .watcher
            .take()
            .is_none_or(|watcher| watcher.join().is_ok());
        let caller_expired = self
            .caller
            .as_ref()
            .is_some_and(|caller| caller.wait_for_active_work_change().is_err());
        let expired = caller_expired
            || phase_expired
            || !joined
            || self.state.expired()
            || self.operation_expired.is_expired();
        if expired {
            self.cancellation.cancel();
            if !self.operation_expired.is_expired()
                && let Some(registry) = &self.registry
            {
                let _ = self.state.supervisor.cancel();
                let _ = registry.cancel_registered_pagers(&self.state.supervisor);
            }
        }
        expired
    }
}

impl Drop for AssignmentHostWatchdogGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

// Host time controls operational waiting and admission only. Keeping the read
// here prevents public lifecycle APIs from exporting a raw host-clock basis.
// crucible-lint: allow clippy-disallowed-method -- monotonic host time bounds only process supervision and operational fork admission.
#[allow(clippy::disallowed_methods)]
fn now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_process_allowance_is_already_expired() {
        assert!(ProcessDeadline::after(Duration::ZERO).is_some_and(ProcessDeadline::expired));
    }

    #[test]
    fn overflowing_process_allowance_is_rejected() {
        assert!(ProcessDeadline::after(Duration::MAX).is_none());
    }

    #[test]
    fn fork_rate_clock_never_moves_backwards() {
        let clock = ForkRateClock::new();
        let first = clock.elapsed_nanos();
        assert!(clock.elapsed_nanos() >= first);
    }

    #[test]
    fn caller_cancellation_reaches_the_same_assignment_watcher() {
        let budgets = HostOperationBudgets {
            classes: [crucible_host_resources::host_supervision::HostOperationBudget::finite(
                Duration::from_secs(9),
            );
                crucible_host_resources::host_supervision::HOST_OPERATION_CLASS_COUNT],
        };
        let caller = HostOperationSupervisor::new(budgets, Some(Duration::from_secs(8)))
            .unwrap_or_else(|error| panic!("original caller: {error}"));
        let cancellation = ExecutionCancellation::default();
        let observer = cancellation
            .observer_for_test()
            .unwrap_or_else(|error| panic!("actual process cancellation hook: {error}"));
        let publication = PublicationSupervision::default();
        publication
            .bind_caller(&caller)
            .unwrap_or_else(|error| panic!("bind original caller: {error}"));
        let (state, _) = publication
            .start(Some(7_000), cancellation.clone(), budgets, None)
            .unwrap_or_else(|error| panic!("independent assignment cap: {error}"));
        assert_ne!(state.supervisor().cap_id(), caller.cap_id());
        assert!(publication.bind_caller(&caller).is_err());

        caller
            .cancel()
            .unwrap_or_else(|error| panic!("cancel original caller: {error}"));
        assert!(observer.wait_for_cancellation(Duration::from_secs(2)));
        assert!(publication.begin_publication().is_err());
        publication
            .finish()
            .unwrap_or_else(|error| panic!("join actual watcher: {error}"));
        assert_eq!(
            caller
                .outer_cap_status()
                .unwrap_or_else(|error| panic!("caller status: {error}"))
                .state,
            HostOperationState::Canceled
        );
    }

    #[test]
    fn assignment_completion_does_not_complete_the_callers_outer_cap() {
        let budgets = HostOperationBudgets {
            classes: [crucible_host_resources::host_supervision::HostOperationBudget::finite(
                Duration::from_secs(9),
            );
                crucible_host_resources::host_supervision::HOST_OPERATION_CLASS_COUNT],
        };
        let caller = HostOperationSupervisor::new(budgets, Some(Duration::from_secs(8)))
            .unwrap_or_else(|error| panic!("original caller: {error}"));
        let original = caller
            .outer_cap_binding()
            .unwrap_or_else(|error| panic!("original anchor: {error}"));
        let publication = PublicationSupervision::default();
        publication
            .bind_caller(&caller)
            .unwrap_or_else(|error| panic!("bind original caller: {error}"));
        publication
            .start(Some(7_000), ExecutionCancellation::default(), budgets, None)
            .unwrap_or_else(|error| panic!("assignment watcher: {error}"));
        publication
            .finish()
            .unwrap_or_else(|error| panic!("join actual watcher: {error}"));
        let retained = caller
            .outer_cap_binding()
            .unwrap_or_else(|error| panic!("caller still live: {error}"));
        assert_eq!(retained, original);
        assert_eq!(retained.state, HostOperationState::Running);
    }

    #[test]
    fn publication_keeps_authored_roster_and_original_outer_cap_until_join() {
        let budgets = HostOperationBudgets {
            classes: [crucible_host_resources::host_supervision::HostOperationBudget::finite(
                Duration::from_secs(9),
            );
                crucible_host_resources::host_supervision::HOST_OPERATION_CLASS_COUNT],
        };
        let cancellation = ExecutionCancellation::default();
        let publication = PublicationSupervision::default();
        let (state, first_start) = publication
            .start(Some(5_000), cancellation.clone(), budgets, None)
            .unwrap_or_else(|error| panic!("authored original watcher: {error}"));
        assert!(first_start);
        let supervisor = state.supervisor().clone();
        let original = supervisor
            .outer_cap_binding()
            .unwrap_or_else(|error| panic!("original binding: {error}"));
        let (retry, restarted) = publication
            .start(Some(50_000), cancellation.clone(), budgets, None)
            .unwrap_or_else(|error| panic!("borrow original retry scope: {error}"));
        assert!(!restarted);
        assert_eq!(retry.supervisor().cap_id(), supervisor.cap_id());
        assert_eq!(
            retry
                .supervisor()
                .outer_cap_binding()
                .unwrap_or_else(|error| panic!("retry original allowance: {error}"))
                .allowance,
            original.allowance
        );
        publication
            .begin_publication()
            .unwrap_or_else(|error| panic!("same-owner handoff: {error}"));
        let guard = publication
            .guard()
            .unwrap_or_else(|error| panic!("live publication: {error}"));

        let current = supervisor
            .outer_cap_binding()
            .unwrap_or_else(|error| panic!("current binding: {error}"));
        assert_eq!(current.cap_id, original.cap_id);
        assert_eq!(
            current.original_monotonic_ns,
            original.original_monotonic_ns
        );
        assert_eq!(
            supervisor
                .budgets()
                .unwrap_or_else(|error| panic!("authored roster: {error}"))
                .1,
            budgets
        );
        assert!(guard.wait_slice().is_ok());
        supervisor
            .cancel()
            .unwrap_or_else(|error| panic!("cancel original owner: {error}"));
        assert!(guard.wait_slice().is_err());
        publication
            .finish()
            .unwrap_or_else(|error| panic!("actual watcher join: {error}"));
        assert!(cancellation.is_canceled());
        assert!(publication.guard().is_err());
    }
}
