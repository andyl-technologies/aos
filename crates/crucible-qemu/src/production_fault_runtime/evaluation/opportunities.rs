//! Device and architectural opportunity evaluation.

use super::*;

impl ProductionFaultRuntime {
    /// Evaluates one exact device or architectural opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] under the same transaction and evidence
    /// rules as [`Self::evaluate_boundary`].
    pub fn evaluate_opportunity(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
        nodes: &mut QemuNodeSet,
    ) -> Result<BindingEvaluation, ProductionFaultRuntimeError> {
        self.require_usable()?;
        if self.lifecycle_work_in_flight.is_some() || self.lifecycle_release_in_flight.is_some() {
            return Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork);
        }
        self.apply_event_staging_capacity(nodes, &[], None)?;
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(BindingEvaluation::default());
        };
        let mut preview = runtime.preview_opportunity(opportunity, same_coordinate_sequence)?;
        validate_production_event_state(
            &self.emitted_events,
            &preview.emitted_events,
            &self.pending_qemu_observations,
            &[],
            &self.pending_qemu_events,
            self.resource_limits,
        )?;
        let staged_qemu_ledger = self.stage_qemu_action_ledger(&preview.actions)?;
        let publication =
            StagedEvaluationPublication::stage(self, opportunity.coordinate(), &mut preview)?;
        let maximum_event_records = self.apply_event_staging_capacity(
            nodes,
            publication.emitted_events(),
            Some(&staged_qemu_ledger),
        )?;
        let mut sink = ProductionFaultActionSink::new_with_event_limit(
            &mut self.host,
            nodes,
            self.resource_limits,
            maximum_event_records,
        );
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        let evaluation = runtime.evaluate_opportunity_with_backend(
            opportunity,
            same_coordinate_sequence,
            &mut sink,
        )?;
        let qemu_commits = sink.take_qemu_commit_evidence();
        if evaluation.actions != preview.actions
            || evaluation.emitted_events != publication.emitted_events()
            || evaluation.state_machine_events != preview.state_machine_events
            || evaluation.search_choices != publication.search_choices()
            || evaluation.observations.len() != publication.expected_observations()
        {
            runtime.poison();
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        if let Err(error) = self.commit_staged_qemu_action_ledger(staged_qemu_ledger, qemu_commits)
        {
            if let Some(runtime) = &mut self.runtime {
                runtime.poison();
            }
            return Err(error);
        }
        publication.publish(self);
        Ok(evaluation)
    }

    /// Evaluates one host-device opportunity without borrowing the live node set.
    ///
    /// Storage and 9p opportunities can arise while a node's host-I/O runtime is
    /// itself inside `advance_to_ceiling`, so re-borrowing that node set would be
    /// impossible and semantically unnecessary. Opportunity targeting guarantees
    /// that only host-adapter actions can match; a node action is rejected by the
    /// host sink and poisons the same authoritative continuation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when evaluation, transactional host
    /// application, evidence validation, or checkpointing fails.
    pub fn evaluate_host_opportunity(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
    ) -> Result<BindingEvaluation, ProductionFaultRuntimeError> {
        self.require_usable()?;
        if self.lifecycle_work_in_flight.is_some() || self.lifecycle_release_in_flight.is_some() {
            return Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork);
        }
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(BindingEvaluation::default());
        };
        let mut preview = runtime.preview_opportunity(opportunity, same_coordinate_sequence)?;
        validate_production_event_state(
            &self.emitted_events,
            &preview.emitted_events,
            &self.pending_qemu_observations,
            &[],
            &self.pending_qemu_events,
            self.resource_limits,
        )?;
        let publication =
            StagedEvaluationPublication::stage(self, opportunity.coordinate(), &mut preview)?;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        let evaluation = runtime.evaluate_opportunity_with_backend(
            opportunity,
            same_coordinate_sequence,
            &mut self.host,
        )?;
        if evaluation.emitted_events != publication.emitted_events()
            || evaluation.state_machine_events != preview.state_machine_events
            || evaluation.search_choices != publication.search_choices()
            || evaluation.observations.len() != publication.expected_observations()
        {
            runtime.poison();
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        publication.publish(self);
        Ok(evaluation)
    }

    /// Replaces the one-boundary-delayed telemetry snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the snapshot is invalid or the
    /// current continuation cannot be authenticated and checkpointed.
    pub fn set_boundary_snapshot(
        &mut self,
        boundary: SignalBoundarySnapshot,
    ) -> Result<(), ProductionFaultRuntimeError> {
        self.require_usable()?;
        if self.lifecycle_work_in_flight.is_some() || self.lifecycle_release_in_flight.is_some() {
            return Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork);
        }
        if let Some(runtime) = &mut self.runtime {
            runtime.set_boundary_snapshot(boundary)?;
        }
        Ok(())
    }
}
