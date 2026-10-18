//! Separates operation polling from the owner of a control action's lifetime.
//!
//! The shared transport loops use static dispatch. Production always selects
//! the standing Source implementation; component tests supply a distinct model
//! whose physical-return receipt cannot be confused with either transport ACK.

use super::control::PendingControlBoundary;
use super::*;

/// Keeps one action owner around the common mapped-transport algorithm.
pub(super) trait ControlActionScope {
    /// Lends the action before its capture generation or control token is visible.
    ///
    /// # Errors
    /// Refuses the owner's actual admission or still-retained previous action.
    fn lend(
        &mut self,
        runtime: &mut QemuLiveHostIoRuntime,
        budget: &OperationPollBudget<'_>,
        capture: Option<u32>,
    ) -> Result<bool, QemuAsyncDriverRuntimeError>;

    /// Lends the appropriate Pause action before the mapped Pause effect.
    ///
    /// # Errors
    /// Refuses unavailable paired admission or retained prior action debt.
    fn lend_pause(
        &mut self,
        runtime: &mut QemuLiveHostIoRuntime,
        budget: &OperationPollBudget<'_>,
    ) -> Result<bool, QemuAsyncDriverRuntimeError>;

    /// Compares the published request with this owner's retained selector.
    ///
    /// # Errors
    /// Refuses a changed token, frontier or capture generation.
    fn validate(&self, request: PendingControlBoundary) -> Result<(), QemuAsyncDriverRuntimeError>;

    /// Rechecks the same live lenders without entering another operation.
    ///
    /// # Errors
    /// Returns the original owner's actual continuation refusal.
    fn refresh(&self, runtime: &QemuLiveHostIoRuntime) -> Result<(), QemuAsyncDriverRuntimeError>;

    /// Observes physical return independently of control and sample ACKs.
    ///
    /// # Errors
    /// Refuses changed, negative or uncertain return disposition.
    fn finish(
        &mut self,
        runtime: &QemuLiveHostIoRuntime,
    ) -> Result<bool, QemuAsyncDriverRuntimeError>;
}

/// Keeps the actual Source selector without substituting for its nominal owner.
#[derive(Default)]
pub(super) struct SourceControlAction {
    binding: Option<crucible_qemu_protocol::boundary_action::ActionBinding>,
}

impl ControlActionScope for SourceControlAction {
    fn lend(
        &mut self,
        runtime: &mut QemuLiveHostIoRuntime,
        budget: &OperationPollBudget<'_>,
        capture: Option<u32>,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        self.binding = runtime.lend_control_action(budget, capture)?;
        Ok(self.binding.is_some())
    }

    fn lend_pause(
        &mut self,
        runtime: &mut QemuLiveHostIoRuntime,
        budget: &OperationPollBudget<'_>,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        self.binding = runtime.lend_paired_pause_action(budget)?;
        Ok(self.binding.is_some())
    }

    fn validate(&self, request: PendingControlBoundary) -> Result<(), QemuAsyncDriverRuntimeError> {
        super::action::validate_control_action_request(request, self.binding)
    }

    fn refresh(&self, runtime: &QemuLiveHostIoRuntime) -> Result<(), QemuAsyncDriverRuntimeError> {
        runtime.refresh_control_action()
    }

    fn finish(
        &mut self,
        runtime: &QemuLiveHostIoRuntime,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        runtime.finish_control_action()
    }
}
