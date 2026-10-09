//! Borrowed equality of authenticated World, scheduler and controller state.
//!
//! Physical RAM and native CPU/device material are separate evidence. Capture
//! identities remain exact until their future uses have a common state proof.

use super::*;

impl DecodedProductionExactCheckpoint {
    /// Compares complete modeled continuations under their own scenario definitions.
    ///
    /// The comparison borrows both decoded owners and the complete source forms.
    /// It checks actual event and signal bytes, all scheduler/controller fields,
    /// and each target's modeled checkpoint and Apache continuation. It does not
    /// read, clone or certify physical RAM, native device state, storage paths,
    /// or daemon campaign-choice records. Those require their own retained
    /// authenticated materials at the same stopped boundary.
    ///
    /// Closure, fault and failed-node fingerprint identities remain exact. This
    /// component therefore refuses cross-edition identity differences even when
    /// a separate host/node component excludes only its own capture bindings.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when either complete source definition
    /// differs from its decoded configuration's authenticated definition.
    pub fn same_modeled_continuation(
        &self,
        source: &ScenarioDefForm,
        other: &Self,
        other_source: &ScenarioDefForm,
    ) -> Result<bool, LifecycleApiError> {
        let Self {
            checkpoint,
            expected_snapshots,
        } = self;
        let Self {
            checkpoint: other_checkpoint,
            expected_snapshots: other_expected_snapshots,
        } = other;
        authenticate_source(checkpoint, source)?;
        authenticate_source(other_checkpoint, other_source)?;

        Ok(source == other_source
            && expected_snapshots == other_expected_snapshots
            && same_checkpoint(checkpoint, other_checkpoint))
    }
}

fn authenticate_source(
    checkpoint: &ProductionVmExactCheckpointSet,
    source: &ScenarioDefForm,
) -> Result<(), LifecycleApiError> {
    let definition = &checkpoint.configuration.def;
    if definition.id() != source.id()
        || definition.seed() != source.seed()
        || definition.app_random_draw_cap() != source.app_random_draw_cap()
    {
        return Err(loop_factory_error(
            "modeled checkpoint comparison source does not match its captured definition",
        ));
    }
    Ok(())
}

fn same_checkpoint(
    checkpoint: &ProductionVmExactCheckpointSet,
    other: &ProductionVmExactCheckpointSet,
) -> bool {
    // Exhaustive patterns force a comparison policy for every future field.
    // Restore readers and leases stay owned; their location is not modeled state.
    let ProductionVmExactCheckpointSet {
        identity,
        configuration,
        scheduler,
        event_log_objects,
        signal_artifact_objects,
        trigger_state,
        assertion_state,
        terminal_verdict,
        terminal_cause,
        initial_lifecycle_observations_pending,
        branch,
        recorded_controls,
        selectable_catalog_plans,
        fault_checkpoint,
        targets,
        failed_host_io,
        node_generations,
        node_service_states,
        repository_restore: _,
    } = checkpoint;
    let ProductionVmExactCheckpointSet {
        identity: other_identity,
        configuration: other_configuration,
        scheduler: other_scheduler,
        event_log_objects: other_event_log_objects,
        signal_artifact_objects: other_signal_artifact_objects,
        trigger_state: other_trigger_state,
        assertion_state: other_assertion_state,
        terminal_verdict: other_terminal_verdict,
        terminal_cause: other_terminal_cause,
        initial_lifecycle_observations_pending: other_initial_lifecycle_observations_pending,
        branch: other_branch,
        recorded_controls: other_recorded_controls,
        selectable_catalog_plans: other_selectable_catalog_plans,
        fault_checkpoint: other_fault_checkpoint,
        targets: other_targets,
        failed_host_io: other_failed_host_io,
        node_generations: other_node_generations,
        node_service_states: other_node_service_states,
        repository_restore: _,
    } = other;

    identity == other_identity
        && configuration == other_configuration
        && scheduler == other_scheduler
        && event_log_objects == other_event_log_objects
        && signal_artifact_objects == other_signal_artifact_objects
        && trigger_state == other_trigger_state
        && assertion_state.same_continuation(other_assertion_state)
        && terminal_verdict == other_terminal_verdict
        && terminal_cause == other_terminal_cause
        && initial_lifecycle_observations_pending == other_initial_lifecycle_observations_pending
        && branch == other_branch
        && recorded_controls == other_recorded_controls
        && selectable_catalog_plans == other_selectable_catalog_plans
        && fault_checkpoint == other_fault_checkpoint
        && targets.len() == other_targets.len()
        && targets.iter().all(|(node, target)| {
            other_targets
                .get(node)
                .is_some_and(|other_target| same_target(target, other_target))
        })
        && failed_host_io == other_failed_host_io
        && node_generations == other_node_generations
        && node_service_states == other_node_service_states
}

fn same_target(
    target: &ProductionVmExactCheckpointTarget,
    other: &ProductionVmExactCheckpointTarget,
) -> bool {
    let ProductionVmExactCheckpointTarget {
        configuration,
        immutable_backing,
        counter,
        scheduler_time,
        snapshot,
        materialization: _,
    } = target;
    let ProductionVmExactCheckpointTarget {
        configuration: other_configuration,
        immutable_backing: other_immutable_backing,
        counter: other_counter,
        scheduler_time: other_scheduler_time,
        snapshot: other_snapshot,
        materialization: _,
    } = other;

    configuration == other_configuration
        && immutable_backing == other_immutable_backing
        && counter == other_counter
        && scheduler_time == other_scheduler_time
        && snapshot.checkpoint() == other_snapshot.checkpoint()
        && snapshot.same_host_continuation(other_snapshot)
}

#[cfg(all(test, feature = "test-support"))]
mod tests;
