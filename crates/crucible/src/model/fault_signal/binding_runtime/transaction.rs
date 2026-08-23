//! Atomic action-batch validation, commit, and rejection handling.

use super::*;

fn validate_prepared_batch(
    actions: &[ResolvedBindingAction],
    batch: &PreparedActionBatch,
    allow_unrefined_node_preview: bool,
) -> Result<(), BindingRuntimeError> {
    if batch.transaction == ContentHash::default() || actions.len() != batch.results.len() {
        return Err(BindingRuntimeError::AdapterResult);
    }
    for (action, result) in actions.iter().zip(&batch.results) {
        let expected_kind = match action.kind {
            BindingActionKind::UpsertPersistent => FaultObservationKind::BindingActivation,
            BindingActionKind::RemovePersistent => FaultObservationKind::BindingDeactivation,
            BindingActionKind::Apply => FaultObservationKind::EffectCommitted,
        };
        let observation = &result.observation;
        let coordinate_matches = action.accepts_observation_coordinate(observation.coordinate)
            || (allow_unrefined_node_preview
                && action.effect.kind().descriptor().adapter == FaultAdapter::Node
                && action.coordinate.retired_instructions.is_none()
                && action.coordinate == observation.coordinate);
        if result.action != action.id()
            || observation.semantic_version != FAULT_RUNTIME_STATE_VERSION
            || observation.kind != expected_kind
            || observation.binding.as_ref() != Some(&action.binding)
            || observation.target.as_ref() != Some(&action.target)
            || observation.opportunity != action.opportunity
            || !coordinate_matches
            || observation.evidence == ContentHash::default()
        {
            return Err(BindingRuntimeError::AdapterResult);
        }
    }
    Ok(())
}

fn validate_prepared_order(
    actions: &[ResolvedBindingAction],
    batch: &PreparedActionBatch,
) -> Result<(), BindingRuntimeError> {
    if batch.transaction == ContentHash::default()
        || actions.len() != batch.results.len()
        || actions
            .iter()
            .zip(&batch.results)
            .any(|(action, result)| action.id() != result.action)
    {
        return Err(BindingRuntimeError::AdapterResult);
    }
    Ok(())
}

pub(super) struct PreparedActionTransaction(Option<ContentHash>);

pub(super) fn prepare_actions(
    sink: &mut dyn FaultActionSink,
    actions: &[ResolvedBindingAction],
) -> Result<PreparedActionTransaction, BindingRuntimeError> {
    if actions.is_empty() {
        return Ok(PreparedActionTransaction(None));
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
    if validate_prepared_order(actions, &prepared).is_err() {
        sink.abort_batch(transaction)
            .map_err(BindingRuntimeError::AdapterAbort)?;
        return Err(BindingRuntimeError::AdapterResult);
    }
    Ok(PreparedActionTransaction(Some(transaction)))
}

pub(super) fn commit_prepared_actions(
    sink: &mut dyn FaultActionSink,
    actions: &[ResolvedBindingAction],
    transaction: PreparedActionTransaction,
    allow_unrefined_node_preview: bool,
) -> Result<Vec<PreparedActionResult>, BindingRuntimeError> {
    let Some(transaction) = transaction.0 else {
        return Ok(Vec::new());
    };
    match sink.commit_batch(transaction) {
        Ok(committed) if committed.transaction == transaction => {
            validate_prepared_batch(actions, &committed, allow_unrefined_node_preview).map_err(
                |_error| {
                    BindingRuntimeError::AdapterCommit(FaultRuntimeError::IncompleteAdapterState)
                },
            )?;
            Ok(committed.results)
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

pub(super) fn prepare_and_commit(
    sink: &mut dyn FaultActionSink,
    actions: &[ResolvedBindingAction],
    allow_unrefined_node_preview: bool,
) -> Result<Vec<PreparedActionResult>, BindingRuntimeError> {
    let transaction = prepare_actions(sink, actions)?;
    commit_prepared_actions(sink, actions, transaction, allow_unrefined_node_preview)
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
