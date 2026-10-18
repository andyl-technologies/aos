//! Operation-only mapped-transport fixtures without a standing Source issuer.
//!
//! A component action borrows the actual operation budget for its whole loop.
//! Its peer supplies a separate modeled physical-return receipt after the ACK
//! assertions. None of these types constructs a Source binding or native loan.

#![cfg(test)]

use super::action_scope::ControlActionScope;
use super::control::PendingControlBoundary;
use super::*;
use crucible_host_resources::host_supervision::{HostOperationGuard, HostOperationSupervisor};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Default)]
struct ModelReturns {
    next: u64,
    pending: Option<ModelAction>,
}

struct ModelAction {
    serial: u64,
    request: PendingControlBoundary,
    awaiting_return: bool,
    returned: bool,
}

/// Supplies only the fixture peer's modeled return, independently of mapped ACKs.
pub(crate) struct ComponentPhysicalReturn {
    returns: Arc<Mutex<ModelReturns>>,
}

/// Names one observed component return cut without issuing native authority.
pub(crate) struct ComponentReturnTicket {
    serial: u64,
}

impl ComponentPhysicalReturn {
    /// Observes that the shared loop is awaiting its separate modeled return.
    ///
    /// # Errors
    /// Refuses poisoned state or a loop that never reaches the return cut within
    /// the test's bounded observation timeout. It publishes neither ACK nor return.
    // crucible-lint: allow clippy-disallowed-method -- this peer timeout bounds host observation only; elapsed time never enters modeled state.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn wait_until_awaited(
        &self,
        timeout: Duration,
    ) -> Result<ComponentReturnTicket, QemuAsyncDriverRuntimeError> {
        let started = Instant::now();
        loop {
            {
                let state = self
                    .returns
                    .lock()
                    .map_err(|_| model_error("poisoned return"))?;
                if let Some(action) = &state.pending
                    && action.awaiting_return
                {
                    return Ok(ComponentReturnTicket {
                        serial: action.serial,
                    });
                }
            }
            if started.elapsed() >= timeout {
                return Err(model_error("loop did not reach the physical-return cut"));
            }
            std::thread::yield_now();
        }
    }

    /// Supplies the peer's return of the same previously observed model action.
    ///
    /// # Errors
    /// Refuses a changed, missing, already-returned or poisoned model action.
    pub(crate) fn return_action(
        &self,
        ticket: ComponentReturnTicket,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let mut state = self
            .returns
            .lock()
            .map_err(|_| model_error("poisoned return"))?;
        let action = state
            .pending
            .as_mut()
            .ok_or_else(|| model_error("missing modeled action"))?;
        if action.serial != ticket.serial || !action.awaiting_return || action.returned {
            return Err(model_error("changed or duplicate modeled physical return"));
        }
        action.returned = true;
        Ok(())
    }

    /// Supplies a distinct peer return after observing the loop's return cut.
    ///
    /// # Errors
    /// Refuses the same conditions as waiting for and returning the model action.
    pub(crate) fn return_when_awaited(
        &self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let ticket = self.wait_until_awaited(timeout)?;
        self.return_action(ticket)
    }
}

/// Wraps only explicit component tests around the existing mapped transport loops.
pub(crate) struct ComponentHostIoRuntime {
    runtime: QemuLiveHostIoRuntime,
    returns: Arc<Mutex<ModelReturns>>,
}

impl QemuLiveHostIoRuntime {
    /// Separates a mapped-only component fixture from production Source admission.
    ///
    /// # Errors
    /// Refuses an actual Source publisher instead of replacing its ownership.
    pub(crate) fn into_control_component(
        self,
    ) -> Result<(ComponentHostIoRuntime, ComponentPhysicalReturn), QemuAsyncDriverRuntimeError>
    {
        if self.source_supervision.is_some() {
            return Err(model_error("a live Source cannot become a component model"));
        }
        let returns = Arc::new(Mutex::new(ModelReturns::default()));
        Ok((
            ComponentHostIoRuntime {
                runtime: self,
                returns: Arc::clone(&returns),
            },
            ComponentPhysicalReturn { returns },
        ))
    }
}

/// Keeps the borrowed real guards alive without claiming a Source subscription.
struct ComponentAction<'budget, 'guard> {
    budget: &'budget OperationPollBudget<'guard>,
    returns: &'budget Mutex<ModelReturns>,
    serial: Option<u64>,
}

impl<'budget, 'guard> ComponentAction<'budget, 'guard> {
    fn new(
        budget: &'budget OperationPollBudget<'guard>,
        returns: &'budget Mutex<ModelReturns>,
    ) -> Self {
        Self {
            budget,
            returns,
            serial: None,
        }
    }
}

impl ControlActionScope for ComponentAction<'_, '_> {
    fn lend(
        &mut self,
        runtime: &mut QemuLiveHostIoRuntime,
        budget: &OperationPollBudget<'_>,
        capture: Option<u32>,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        if !std::ptr::eq(self.budget, budget) {
            return Err(model_error("changed component operation budget"));
        }
        self.budget
            .remaining("lend component control")?
            .ok_or_else(|| model_error("expired operation"))?;
        let mapping = runtime.region.as_ref().ok_or_else(region_missing)?;
        let frontier = mapping
            .fault_command_write_index(runtime.vm_slot)
            .map_err(map_slot_error)?;
        let generation = mapping
            .node_slot(runtime.vm_slot)
            .map_err(map_slot_error)?
            .preview_action_token(frontier, capture)
            .map_err(|error| model_error(error.to_string()))?;
        let mut returns = self
            .returns
            .lock()
            .map_err(|_| model_error("poisoned return"))?;
        if returns.pending.is_some() {
            return Err(model_error(
                "previous modeled physical return remains pending",
            ));
        }
        let serial = returns
            .next
            .checked_add(1)
            .ok_or_else(|| model_error("model serial exhausted"))?;
        returns.next = serial;
        returns.pending = Some(ModelAction {
            serial,
            request: PendingControlBoundary {
                generation,
                fault_command_frontier: frontier,
                fingerprint_capture_request: capture,
            },
            awaiting_return: false,
            returned: false,
        });
        self.serial = Some(serial);
        Ok(true)
    }

    fn lend_pause(
        &mut self,
        runtime: &mut QemuLiveHostIoRuntime,
        budget: &OperationPollBudget<'_>,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        self.lend(runtime, budget, None)
    }

    fn validate(&self, request: PendingControlBoundary) -> Result<(), QemuAsyncDriverRuntimeError> {
        let returns = self
            .returns
            .lock()
            .map_err(|_| model_error("poisoned return"))?;
        let action = returns
            .pending
            .as_ref()
            .ok_or_else(|| model_error("missing modeled action"))?;
        if Some(action.serial) != self.serial || action.request != request {
            return Err(model_error(
                "published request differs from the component's retained request",
            ));
        }
        Ok(())
    }

    fn refresh(&self, _runtime: &QemuLiveHostIoRuntime) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.budget
            .remaining("refresh component control")?
            .ok_or_else(|| model_error("expired operation"))?;
        Ok(())
    }

    fn finish(
        &mut self,
        _runtime: &QemuLiveHostIoRuntime,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let mut returns = self
            .returns
            .lock()
            .map_err(|_| model_error("poisoned return"))?;
        let action = returns
            .pending
            .as_mut()
            .ok_or_else(|| model_error("missing modeled action"))?;
        if Some(action.serial) != self.serial {
            return Err(model_error("changed modeled action"));
        }
        action.awaiting_return = true;
        if !action.returned {
            return Ok(false);
        }
        returns.pending = None;
        self.serial = None;
        Ok(true)
    }
}

impl ComponentHostIoRuntime {
    fn capture(
        &mut self,
        budget: &OperationPollBudget<'_>,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.settle_pending_control_action()?;
        let mut action = ComponentAction::new(budget, &self.returns);
        self.runtime
            .capture_execution_fingerprint_with_actions(budget, timeout, &mut action)
    }
}

impl QemuHostIoRuntime for ComponentHostIoRuntime {
    fn host_operation_supervisor(&self) -> Option<&HostOperationSupervisor> {
        self.runtime.host_operation_supervisor()
    }

    fn set_host_operation_supervisor(
        &mut self,
        supervisor: HostOperationSupervisor,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.runtime.set_host_operation_supervisor(supervisor)
    }

    fn publish_current_execution_fingerprint(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let budget = OperationPollBudget::begin(
            self.runtime.host_operation_supervisor.as_ref(),
            HostOperationClass::FingerprintUpdate,
            timeout,
            "publish current execution fingerprint",
        )?;
        self.capture(&budget, timeout)
    }

    fn publish_current_execution_fingerprint_under_original(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let budget = OperationPollBudget::borrow_original(
            original,
            "publish current execution fingerprint",
        )?;
        let timeout = budget
            .remaining("publish current execution fingerprint")?
            .ok_or_else(|| model_error("expired original"))?;
        self.capture(&budget, timeout)
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn publish_current_execution_fingerprint_under_originals(
        &mut self,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let budget = OperationPollBudget::borrow_quiescence_pair(
            actor,
            family,
            "publish current execution fingerprint",
        )?;
        let timeout = budget
            .remaining("publish current execution fingerprint")?
            .ok_or_else(|| model_error("expired original pair"))?;
        self.capture(&budget, timeout)
    }

    fn quiesce_for_checkpoint_under_original(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.settle_pending_control_action()?;
        let budget =
            OperationPollBudget::borrow_checkpoint_original(original, "quiesce for checkpoint")?;
        let timeout = budget
            .remaining("quiesce for checkpoint")?
            .ok_or_else(|| model_error("expired original"))?;
        let mut action = ComponentAction::new(&budget, &self.returns);
        self.runtime.pause_checkpoint_boundary_with_actions(
            &budget,
            timeout,
            Some(original),
            &mut action,
        )
    }

    fn settle_pending_control_action(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        let returns = self
            .returns
            .lock()
            .map_err(|_| model_error("poisoned return"))?;
        if returns.pending.is_some() {
            return Err(model_error(
                "previous modeled physical return remains pending",
            ));
        }
        Ok(())
    }

    fn await_fault_result(
        &mut self,
        timeout: Duration,
        payload: Vec<u8>,
        maximum_events: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        self.settle_pending_control_action()?;
        let budget = OperationPollBudget::begin(
            self.runtime.host_operation_supervisor.as_ref(),
            HostOperationClass::Preparation,
            timeout,
            "await fault result",
        )?;
        let mut action = ComponentAction::new(&budget, &self.returns);
        self.runtime.poll_fault_result_with_actions(
            timeout,
            payload,
            maximum_events,
            &budget,
            &mut action,
        )
    }

    fn await_fault_preparation_result(
        &mut self,
        timeout: Duration,
        maximum_bytes: usize,
        maximum_events: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        self.settle_pending_control_action()?;
        let budget = OperationPollBudget::begin(
            self.runtime.host_operation_supervisor.as_ref(),
            HostOperationClass::Preparation,
            timeout,
            "await fault preparation result",
        )?;
        let mut action = ComponentAction::new(&budget, &self.returns);
        self.runtime.poll_fault_preparation_result_with_actions(
            timeout,
            maximum_bytes,
            maximum_events,
            &budget,
            &mut action,
        )
    }

    fn set_fault_event_staging_limit(
        &mut self,
        maximum: usize,
        offset: usize,
        configured: usize,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.runtime
            .set_fault_event_staging_limit(maximum, offset, configured)
    }

    fn take_staged_fault_events(
        &mut self,
    ) -> Result<Vec<DequeuedFaultEvent>, QemuAsyncDriverRuntimeError> {
        self.runtime.take_staged_fault_events()
    }

    fn staged_fault_events(&self) -> &[DequeuedFaultEvent] {
        self.runtime.staged_fault_events()
    }

    fn staged_fault_events_pending(&self) -> bool {
        self.runtime.staged_fault_events_pending()
    }

    fn staged_fault_event_count(&self) -> usize {
        self.runtime.staged_fault_event_count()
    }

    fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.runtime.yield_to_control_plane()
    }

    fn await_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        self.runtime.await_child(wait, timeout)
    }

    fn repoll_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        self.runtime.repoll_child(wait, timeout)
    }
}

fn model_error(reason: impl ToString) -> QemuAsyncDriverRuntimeError {
    QemuAsyncDriverRuntimeError::new("component control action", reason.to_string())
}
