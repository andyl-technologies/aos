//! Atomic action-batch validation, commit, and rejection handling.

use super::*;

fn validate_prepared_batch(
    actions: &[ResolvedBindingAction],
    batch: PreparedActionBatch,
) -> Result<Vec<PreparedActionResult>, BindingRuntimeError> {
    if batch.transaction == ContentHash::default() || actions.len() != batch.results.len() {
        return Err(BindingRuntimeError::AdapterResult);
    }
    let mut results = Vec::with_capacity(batch.results.len());
    for (action, result) in actions.iter().zip(batch.results) {
        let expected_kind = match action.kind {
            BindingActionKind::UpsertPersistent => FaultObservationKind::BindingActivation,
            BindingActionKind::RemovePersistent => FaultObservationKind::BindingDeactivation,
            BindingActionKind::Apply => FaultObservationKind::EffectCommitted,
        };
        let observation = result.observation;
        if result.action != action.id()
            || observation.semantic_version != FAULT_RUNTIME_STATE_VERSION
            || observation.kind != expected_kind
            || observation.binding.as_ref() != Some(&action.binding)
            || observation.target.as_ref() != Some(&action.target)
            || observation.opportunity != action.opportunity
            || !action.accepts_observation_coordinate(observation.coordinate)
            || observation.evidence == ContentHash::default()
        {
            return Err(BindingRuntimeError::AdapterResult);
        }
        results.push(PreparedActionResult {
            action: result.action,
            precondition: result.precondition,
            observation,
        });
    }
    Ok(results)
}

pub(super) fn prepare_and_commit(
    sink: &mut dyn FaultActionSink,
    actions: &[ResolvedBindingAction],
) -> Result<Vec<PreparedActionResult>, BindingRuntimeError> {
    if actions.is_empty() {
        return Ok(Vec::new());
    }
    let prepared = match sink.prepare_batch(actions) {
        Ok(prepared) => prepared,
        Err(rejected) => {
            if validate_rejected_batch(actions, &rejected) {
                return Err(BindingRuntimeError::AdapterRejected(rejected));
            }
            return Err(BindingRuntimeError::AdapterResult);
        }
    };
    let transaction = prepared.transaction;
    match sink.commit_batch(transaction) {
        Ok(committed) if committed.transaction == transaction => {
            validate_prepared_batch(actions, committed).map_err(|_error| {
                BindingRuntimeError::AdapterCommit(FaultRuntimeError::IncompleteAdapterState)
            })
        }
        Ok(_) => Err(BindingRuntimeError::AdapterCommit(
            FaultRuntimeError::IncompleteAdapterState,
        )),
        Err(FaultActionCommitError::Rejected(rejected))
            if validate_rejected_batch(actions, &rejected) =>
        {
            Err(BindingRuntimeError::AdapterRejected(rejected))
        }
        Err(FaultActionCommitError::Rejected(_)) => Err(BindingRuntimeError::AdapterResult),
        Err(FaultActionCommitError::Fatal(error)) => Err(BindingRuntimeError::AdapterCommit(error)),
    }
}

fn validate_rejected_batch(actions: &[ResolvedBindingAction], batch: &RejectedActionBatch) -> bool {
    let Some(rejected) = batch.rejected_action else {
        return false;
    };
    let Some(action) = actions.iter().find(|action| action.id() == rejected) else {
        return false;
    };
    batch.observations.len() == 1
        && batch.observations.iter().all(|observation| {
            observation.semantic_version == FAULT_RUNTIME_STATE_VERSION
                && observation.kind == FaultObservationKind::EffectRejected
                && observation.binding.as_ref() == Some(&action.binding)
                && observation.target.as_ref() == Some(&action.target)
                && observation.opportunity == action.opportunity
                && observation.coordinate == action.coordinate
                && observation.evidence != ContentHash::default()
        })
}
