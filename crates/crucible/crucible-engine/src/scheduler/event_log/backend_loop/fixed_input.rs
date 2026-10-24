//! Retained stopped input settlement before any scheduler PICK.
//!
//! Partial consumption never removes actor events or publishes a guest STEP.
//! The exact original batch and factual progress survive every fallible call.

use super::*;
use crate::{BackendFixedInputResult, BackendFixedInputState, PreparedHostFixedInput};

#[derive(Clone, Debug)]
pub(super) struct RetainedFixedInput {
    prepared: PreparedHostFixedInput,
    consumed: usize,
    last: Option<BackendFixedInputResult>,
}

impl<L, B, I> BackendQuantumLoop<L, B, I>
where
    L: std::borrow::Borrow<SingleScheduler> + std::borrow::BorrowMut<SingleScheduler>,
    B: SimulationBackend,
{
    #[cfg(test)]
    pub(crate) fn retained_fixed_input_for_test(&self) -> Option<&PreparedHostFixedInput> {
        self.pending_fixed_input
            .as_ref()
            .map(|retained| &retained.prepared)
    }

    /// Polls the original stopped consumer without admitting guest execution.
    ///
    /// A pending result retains all due actor events and the exact same owner.
    /// Published retires only that consumer's selected canonical batch. The
    /// independently authenticated backend is responsible for Source reseal and
    /// actual directed-inbox publication; this method infers neither from ACKs.
    /// Returns `Some` for every selected consumer result, including Published;
    /// `None` means a fresh observation selected no current-time consumer.
    ///
    /// # Errors
    ///
    /// Refuses a poisoned actor, held RUN, stale source, changed owner, regressing
    /// consumption or premature Published result. Backend failure preserves the
    /// owner cleanup-only because its physical publication may be uncertain.
    pub fn settle_current_fixed_input(
        &mut self,
    ) -> Result<Option<BackendFixedInputResult>, SchedulerError> {
        self.settle_current_fixed_input_excluding(&BTreeSet::new())
    }

    pub(super) fn settle_current_fixed_input_excluding(
        &mut self,
        published_consumers: &BTreeSet<NodeId>,
    ) -> Result<Option<BackendFixedInputResult>, SchedulerError> {
        if self.continuation_poisoned
            || self.held_host_continuation.is_some()
            || self.preselection.is_some()
            || self.device_group_selection.is_retained()
        {
            return Err(super::super::super::fixed_input::fixed_input_error(
                "fixed input cannot cross another retained actor owner",
            ));
        }
        if self.selected_dispatch_contract()? == crate::BackendDispatchContract::ControlV3
            || self.backend.io_inventory_authority()
                == crate::BackendIoInventoryAuthority::SchedulerOwnedModel
        {
            // Control 3 keeps genuine queue service in its installed backend.
            // It supplies no native Source inventory or fixed-input receipt.
            return Ok(None);
        }
        if self.pending_fixed_input.is_none() {
            self.import_initial_io_inventories()?;
            let prepared = self
                .loop_impl
                .borrow_mut()
                .prepare_current_fixed_input(published_consumers)?;
            self.pending_fixed_input = prepared.map(|prepared| RetainedFixedInput {
                prepared,
                consumed: 0,
                last: None,
            });
        }
        let Some(retained) = &self.pending_fixed_input else {
            return Ok(None);
        };
        let prepared = retained.prepared.clone();
        let previous_consumed = retained.consumed;
        if let Err(error) = self
            .loop_impl
            .borrow()
            .validate_current_fixed_input(&prepared)
        {
            self.continuation_poisoned = true;
            return Err(error);
        }
        let result = match self.backend.settle_fixed_input(&prepared) {
            Ok(result) => result,
            Err(error) => {
                self.continuation_poisoned = true;
                return Err(error.into());
            }
        };
        // Keep even a malformed observation for cleanup and diagnosis before
        // validating it; it cannot retire events or authorize another consumer.
        if let Some(retained) = &mut self.pending_fixed_input {
            retained.last = Some(result.clone());
        }
        if result.prepared != prepared
            || result.consumed < previous_consumed
            || result.consumed > prepared.events().len()
            || (result.state == BackendFixedInputState::Pending && result.consumed != 0)
            || (result.state == BackendFixedInputState::Published
                && result.consumed != prepared.events().len())
        {
            self.continuation_poisoned = true;
            return Err(super::super::super::fixed_input::fixed_input_error(
                "fixed input result differs from its retained original batch or frontier",
            ));
        }
        if result.state != BackendFixedInputState::Published {
            if let Some(retained) = &mut self.pending_fixed_input {
                retained.consumed = result.consumed;
            }
            return Ok(Some(result));
        }
        if let Err(error) = self
            .loop_impl
            .borrow_mut()
            .finish_current_fixed_input(&prepared)
        {
            self.continuation_poisoned = true;
            return Err(error);
        }
        self.pending_fixed_input = None;
        // Publication is truthful progress, not absence of all other batches.
        // The caller re-observes Sources and arbitrates the next consumer before PICK.
        Ok(Some(result))
    }
}
