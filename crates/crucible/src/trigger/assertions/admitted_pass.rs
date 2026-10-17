//! Atomic mutable assertion passes under original resource custody.
//!
//! Definitions and resolution tables are shared immutable inputs. Each pass
//! copies only mutable continuation state into a separately retained account;
//! refusal discards that candidate before any verdict or lifecycle publication.

use super::*;
use crate::owned_decode::DecodeBudget;
use super::owned_storage::copy_json;

pub(super) fn condition_result(
    result: Result<bool, EngineError>,
    failure: &mut Option<EngineError>,
) -> bool {
    match result {
        Ok(value) => value,
        Err(error) => {
            if failure.is_none() {
                *failure = Some(error);
            }
            // This is an unpublished candidate transition. The public pass
            // refuses it before updating the original evaluator or returning
            // any candidate outcome.
            false
        }
    }
}

impl HostAssertionEvaluator {
    /// Observes a prefix and atomically publishes its mutable assertion state.
    ///
    /// # Errors
    /// Returns the original metadata or predicate-evaluation refusal. Failed
    /// passes leave assertion lifecycles, Once latches and positions unchanged.
    pub fn observe_prefix<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> Result<Vec<HostAssertionOutcome>, EngineError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let _original = self._definition_custody.enter();
        let budget = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = budget.enter();
        let mut staged = self.stage_mutable(&budget)?;
        let outcomes = staged.observe_prefix_inner(prefix, oracle)?;
        staged.check_pass(&budget)?;
        *self = staged;
        Ok(outcomes)
    }

    /// Finalizes a prefix and publishes the complete assertion pass atomically.
    ///
    /// # Errors
    /// Returns original metadata or predicate failures without publishing a
    /// partial verdict, including failure after an earlier assertion succeeded.
    pub fn finalize_prefix<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> Result<HostAssertionReport, EngineError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let _original = self._definition_custody.enter();
        let budget = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = budget.enter();
        let mut staged = self.stage_mutable(&budget)?;
        let report = staged.finalize_prefix_inner(prefix, oracle)?;
        staged.check_pass(&budget)?;
        *self = staged;
        Ok(report)
    }

    fn check_pass(&mut self, budget: &DecodeBudget) -> Result<(), EngineError> {
        if let Some(error) = self.evaluation_failure.take() {
            return Err(error);
        }
        budget.check().map_err(admission)?;
        Ok(())
    }

    fn stage_mutable(&self, budget: &DecodeBudget) -> Result<Self, EngineError> {
        crate::owned_decode::charge_array::<HostAssertionState>(self.states.len())
            .map_err(admission)?;
        let mut states = Vec::new();
        states
            .try_reserve_exact(self.states.len())
            .map_err(allocation)?;
        for state in &self.states {
            states.push(HostAssertionState {
                assertion: std::sync::Arc::clone(&state.assertion),
                lifecycle: state.lifecycle,
                terminal: copy_json(&state.terminal)?,
                evaluated: state.evaluated,
                eventually_triggered: state.eventually_triggered,
                eventually_satisfied_at: state.eventually_satisfied_at,
                pending_eventually: copy_json(&state.pending_eventually)?,
                proximity: state.proximity.clone(),
            });
        }
        let guest_marker_states = copy_json(&self.guest_marker_states)?;
        crate::owned_decode::charge_array::<Condition>(self.once_latches.len())
            .map_err(admission)?;
        let mut once_latches = Vec::new();
        once_latches
            .try_reserve_exact(self.once_latches.len())
            .map_err(allocation)?;
        for predicate in &self.once_latches {
            once_latches.push(predicate.try_clone_admitted()?);
        }
        Ok(Self {
            states,
            guest_marker_states,
            once_latches,
            white_box_policies: std::sync::Arc::clone(&self.white_box_policies),
            code_points: std::sync::Arc::clone(&self.code_points),
            mem_places: std::sync::Arc::clone(&self.mem_places),
            terminal_quiescence: self.terminal_quiescence.clone(),
            last_position: self.last_position,
            _definition_custody: self._definition_custody.clone(),
            _mutable_custody: budget.custody(),
            evaluation_failure: None,
        })
    }
}

fn admission(source: crate::owned_decode::DecodeAdmissionError) -> EngineError {
    EngineError::ArtifactDecodeAdmission { source }
}

fn allocation(source: std::collections::TryReserveError) -> EngineError {
    admission(crate::owned_decode::DecodeAdmissionError::new(source))
}

#[cfg(test)]
mod tests;
