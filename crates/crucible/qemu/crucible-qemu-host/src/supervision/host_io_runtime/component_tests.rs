//! Operation-only mapped-transport fixtures without a standing Source issuer.
//!
//! A component action borrows the actual operation budget for its whole loop.
//! Its peer supplies a separate modeled physical-return receipt after the ACK
//! assertions. None of these types constructs a Source binding or native loan.

#![cfg(test)]

use super::action_scope::ControlActionScope;
use super::control::PendingControlBoundary;
use super::*;
use crucible_host_resources::host_supervision::{
    HostOperationGuard, HostOperationState, HostOperationSupervisor, HostSupervisionError,
};
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

    fn lend_probe(
        &mut self,
        runtime: &mut QemuLiveHostIoRuntime,
        budget: &OperationPollBudget<'_>,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        self.lend(runtime, budget, None)
    }

    fn lend_pause(
        &mut self,
        runtime: &mut QemuLiveHostIoRuntime,
        budget: &OperationPollBudget<'_>,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        self.lend(runtime, budget, None)
    }

    fn begin_pause_publication(
        &mut self,
        runtime: &mut QemuLiveHostIoRuntime,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        // Component construction rejects a real Source. This invokes the same
        // Source-absent transport seam without manufacturing a Source selector.
        runtime.begin_pause_action_publication(None)
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

fn probe_runtime() -> Result<
    (
        QemuLiveHostIoRuntime,
        crucible_qemu_shmem::MappedSetupRegion,
    ),
    Box<dyn std::error::Error>,
> {
    use std::io::Write;
    use std::os::fd::AsFd;

    let allocation = crucible_qemu_shmem::RegionAllocation::new_model(
        crucible_qemu_shmem::RegionConfig::new(1, 4),
    )?;
    let layout = allocation.layout();
    let mut shmem = File::from(crate::spawn::memfd_region(layout.region_size)?);
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let observer = crucible_qemu_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let wake = tempfile::tempfile()?;
    let runtime =
        QemuLiveHostIoRuntime::from_shmem_fd(shmem.as_fd(), wake.as_fd(), layout.region_size, 0)?;
    Ok((runtime, observer))
}

fn probe_supervisor() -> HostOperationSupervisor {
    HostOperationSupervisor::new(
        crucible_host_resources::host_supervision::HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )
    .unwrap()
}

#[test]
fn source_absent_probe_keeps_fixture_transport_without_claiming_a_loan()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut runtime, observer) = probe_runtime()?;
    let budget = OperationPollBudget::begin(
        None,
        HostOperationClass::Quiescence,
        Duration::from_secs(2),
        "fixture probe",
    )?;
    let before = observer.node_slot(0)?.snapshot();
    let mut action = super::action_scope::SourceControlAction::default();

    assert!(!action.lend_probe(&mut runtime, &budget)?);
    assert_eq!(observer.node_slot(0)?.snapshot(), before);
    assert!(budget.action_producers()?.is_none());
    let request = runtime.signal_wake(None)?;
    action.validate(request)?;
    assert_eq!(
        observer.node_slot(0)?.control_boundary_token(),
        request.generation,
    );
    assert_eq!(
        observer.node_slot(0)?.acknowledge_control_boundary(),
        request.generation.wrapping_add(1),
    );
    assert!(action.finish(&runtime)?);
    budget.complete("fixture probe")?;
    Ok(())
}

#[test]
fn fixture_cannot_supply_the_required_probe_original() -> Result<(), Box<dyn std::error::Error>> {
    let (_runtime, observer) = probe_runtime()?;
    let budget = OperationPollBudget::begin(
        None,
        HostOperationClass::Quiescence,
        Duration::from_secs(2),
        "fixture producer refusal",
    )?;
    let before = observer.node_slot(0)?.snapshot();

    let error = super::action::check_probe_original(&budget).unwrap_err();

    assert_eq!(
        error.operational_supervision_source(),
        Some(HostSupervisionError::Unavailable),
    );
    assert_eq!(observer.node_slot(0)?.snapshot(), before);
    assert!(budget.action_producers()?.is_none());
    Ok(())
}

#[test]
fn supervised_and_borrowed_probe_use_one_actual_original() -> Result<(), Box<dyn std::error::Error>>
{
    let supervisor = probe_supervisor();
    let budget = OperationPollBudget::begin(
        Some(&supervisor),
        HostOperationClass::Quiescence,
        Duration::ZERO,
        "same probe Original",
    )?;
    let OperationPollBudget::Supervised(original) = &budget else {
        panic!("a real supervisor must retain its actual Original");
    };
    let borrowed = OperationPollBudget::borrow_original(original, "borrow same probe Original")?;

    for budget in [&budget, &borrowed] {
        super::action::check_probe_original(budget)?;
        let producers = budget.action_producers()?.unwrap();
        assert!(std::ptr::eq(producers[0].unwrap(), original));
        assert!(producers[1].is_none());
    }
    borrowed.complete("retain borrowed probe Original")?;
    let statuses = supervisor.operation_statuses()?;
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].state, HostOperationState::Running);
    assert_eq!(statuses[0].completed_work_units, 0);
    Ok(())
}

#[test]
fn canceled_probe_original_refuses_without_replacement() -> Result<(), Box<dyn std::error::Error>> {
    let supervisor = probe_supervisor();
    let original = supervisor.begin(HostOperationClass::Quiescence)?;
    let budget = OperationPollBudget::borrow_original(&original, "borrow canceled probe")?;
    supervisor.cancel()?;

    let error = super::action::check_probe_original(&budget).unwrap_err();

    assert_eq!(
        error.operational_supervision_source(),
        Some(HostSupervisionError::Terminal {
            state: HostOperationState::Canceled,
        }),
    );
    assert_eq!(supervisor.operation_statuses()?.len(), 1);
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
#[test]
fn source_absent_pair_probe_keeps_the_actual_pair_refusal_before_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let (_actor_owner, actor, actor_supervisor, _actor_event, _actor_account) =
        crate::node::checkpoint_original_loan_fixture();
    let (_family_owner, family, family_supervisor, _family_event, _family_account) =
        crate::node::checkpoint_original_loan_fixture();
    let budget = OperationPollBudget::borrow_quiescence_pair(
        actor.guard(),
        family.guard(),
        "same pair probe",
    )?;
    let (mut runtime, observer) = probe_runtime()?;
    let before = observer.node_slot(0)?.snapshot();
    let mut action = super::action_scope::SourceControlAction::default();

    assert!(action.lend_probe(&mut runtime, &budget).is_err());
    assert_eq!(observer.node_slot(0)?.snapshot(), before);
    budget.complete("pair remains owned")?;
    for supervisor in [&actor_supervisor, &family_supervisor] {
        let statuses = supervisor.operation_statuses()?;
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, HostOperationState::Running);
        assert_eq!(statuses[0].completed_work_units, 0);
    }
    Ok(())
}

#[test]
fn component_probe_keeps_same_budget_and_ack_separate_from_return()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = probe_supervisor();
    let original = supervisor.begin(HostOperationClass::Quiescence)?;
    let budget = OperationPollBudget::borrow_original(&original, "component probe")?;
    let other_budget = OperationPollBudget::borrow_original(&original, "different budget object")?;
    let (mut runtime, observer) = probe_runtime()?;
    let returns = Arc::new(Mutex::new(ModelReturns::default()));
    let peer = ComponentPhysicalReturn {
        returns: Arc::clone(&returns),
    };
    let mut action = ComponentAction::new(&budget, &returns);
    let before = observer.node_slot(0)?.snapshot();

    assert!(action.lend_probe(&mut runtime, &other_budget).is_err());
    assert!(returns.lock().unwrap().pending.is_none());
    assert_eq!(observer.node_slot(0)?.snapshot(), before);
    assert!(action.lend_probe(&mut runtime, &budget)?);
    let request = runtime.signal_wake(None)?;
    action.validate(request)?;
    assert_eq!(
        observer.node_slot(0)?.acknowledge_control_boundary(),
        request.generation.wrapping_add(1),
    );
    assert!(!action.finish(&runtime)?);
    let ticket = peer.wait_until_awaited(Duration::from_secs(2))?;
    peer.return_action(ticket)?;
    assert!(action.finish(&runtime)?);
    budget.complete("borrowed probe does not complete its owner")?;
    let statuses = supervisor.operation_statuses()?;
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].state, HostOperationState::Running);
    assert_eq!(statuses[0].completed_work_units, 0);
    Ok(())
}
