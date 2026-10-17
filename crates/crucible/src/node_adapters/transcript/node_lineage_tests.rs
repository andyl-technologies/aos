//! Tests actual model token and cursor guards without native qualification.

use super::*;

fn input_model() -> Result<(TranscriptReplayNode, NodeRuntime, RuntimeInputBatch), OperationFailure>
{
    let (mut node, runtime, activation, _) = super::super::tests::model();
    let mut cursor = crate::node_adapters::transcript::tests::tape2_models::input_model_cursor();
    let next = cursor
        .peek()
        .ok_or_else(|| failure("model Stage absent", EffectKnowledge::None))?;
    let request: ControlRequest = serde_json::from_slice(&next.request.bytes)
        .map_err(|error| failure(error, EffectKnowledge::None))?;
    let ControlRequest::Stage { mut input } = request else {
        return Err(failure("model request is not Stage", EffectKnowledge::None));
    };
    // This is a precondition-only model. No parsed event or altered tape can
    // qualify source lineage; the test never consumes this synthetic record.
    input.deliveries.push(
        crate::node_adapters::transcript::tests::tape2_models::zero_byte_delivery(&input.node),
    );
    let body = crate::node_adapters::transcript::codec::encode(&ControlRequest::Stage {
        input: input.clone(),
    })
    .map_err(|error| failure(error, EffectKnowledge::None))?;
    let record = &mut Rc::make_mut(&mut cursor.source.data).records[0];
    record.request.content = canonical::content_ref(&body, "application/json")
        .map_err(|error| failure(error, EffectKnowledge::None))?;
    record.request.bytes = body;
    let batch = RuntimeInputBatch {
        activation,
        node: input.node,
        stage_operation: input.stage_operation,
        batch: input.batch,
        owners: node.route.owners.clone(),
        cutoff: input.cutoff,
        inventory: input.inventory,
        deliveries: input.deliveries,
        payloads: input.payloads,
    };
    node.cursor = Some(cursor);
    Ok((node, runtime, batch))
}

#[test]
fn conditional_tape2_scope_keeps_first_and_current_activation_separate()
-> Result<(), OperationFailure> {
    let (mut node, _runtime, batch) = input_model()?;
    let scope = node
        .original_input_lineage_scope(&batch)?
        .ok_or_else(|| failure("model scope absent", EffectKnowledge::None))?;
    assert_ne!(
        scope.source_activation.activation_id,
        batch.activation().record().activation_id
    );
    assert_eq!(scope.stage_operation, *batch.stage_operation());
    assert_eq!(
        node.cursor_snapshot()
            .map(|cursor| cursor.next_record.get()),
        Some(0)
    );
    node.validate_original_input_lineage_scope(&batch, &scope)?;
    assert!(
        node.original_lineage_tape()
            .map_err(|error| failure(error, EffectKnowledge::None))?
            .input(batch.stage_operation())
            .is_err()
    );
    Ok(())
}

#[test]
fn authentic_changed_tape2_input_precondition_sticks_diverged() -> Result<(), OperationFailure> {
    let (mut node, _runtime, batch) = input_model()?;
    let mut changed = batch.retained_copy();
    changed.stage_operation = node.route.node.clone();
    assert!(node.original_input_lineage_scope(&changed).is_err());
    assert!(node.cursor_snapshot().is_some_and(|cursor| cursor.diverged));
    assert!(node.original_input_lineage_scope(&batch).is_err());
    assert_eq!(
        node.cursor_snapshot()
            .map(|cursor| cursor.next_record.get()),
        Some(0)
    );
    assert!(node.inputs.is_empty());
    Ok(())
}

#[test]
fn foreign_tape2_target_refuses_without_poisoning_original_cursor() -> Result<(), OperationFailure>
{
    let (mut node, _runtime, batch) = input_model()?;
    let mut foreign = batch.retained_copy();
    foreign.owners.clear();
    assert!(node.original_input_lineage_scope(&foreign).is_err());
    assert!(!node.cursor_snapshot().is_some_and(|cursor| cursor.diverged));
    assert!(node.original_input_lineage_scope(&batch)?.is_some());
    Ok(())
}

#[test]
fn conditional_tape2_empty_batch_needs_no_original_lineage_claim() -> Result<(), OperationFailure> {
    let (mut node, _runtime, mut batch) = input_model()?;
    batch.deliveries.clear();
    batch.payloads.clear();
    assert!(!node.requires_original_input_lineage(&batch));
    assert!(node.original_input_lineage_scope(&batch)?.is_none());
    assert_eq!(
        node.cursor_snapshot()
            .map(|cursor| cursor.next_record.get()),
        Some(0)
    );
    assert!(!node.cursor_snapshot().is_some_and(|cursor| cursor.diverged));
    Ok(())
}
