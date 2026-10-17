//! Checks complete borrowed producer/staging custody with synthetic native eligibility.

#![cfg(test)]

use super::*;

#[test]
fn original_stage_projection_preserves_full_producer_bodies_and_refuses_omission()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut runtime, states, _, mut batch) = fixture();
    batch.owners = runtime.nodes[batch.node()].route().owners.clone();
    let lineage = runtime
        .prepare_original_input_lineage(&batch)?
        .ok_or(RuntimeError::UnsupportedFacet)?;
    let claim = &lineage.publications()[0];
    let provenance = InputProvenanceClosure::from_validated(
        &batch,
        vec![claim.published.clone()],
        claim.objects.clone(),
    );
    let acknowledgement = crate::node_scheduling::NativeInputAcknowledgement {
        stage_operation: batch.stage_operation().clone(),
        batch: batch.batch().clone(),
        node: batch.node().clone(),
        owners: batch.owners().to_vec(),
        cutoff: batch.cutoff(),
        inventory: batch.inventory().clone(),
        proof_ref: batch.payloads()[0].reference.clone(),
    };
    // Graph/native staging eligibility is modeled here; actual sealed producer
    // association above uses the original retained model publication callback.
    let admission = OperationAdmission {
        token: OperationToken {
            authority: Rc::clone(&runtime.authority),
            operation: id("consumer"),
            route: runtime.nodes[batch.node()].route().clone(),
        },
        activation: batch.activation().clone(),
        request: OperationRequest::BoundarySettle {
            start: position(1001),
            limit: position(2000),
        },
        inputs: Some(Rc::new(batch.retained_copy())),
    };
    runtime.input_batches.insert(
        batch.stage_operation().clone(),
        super::super::inputs::RetainedInput {
            batch,
            provenance: Some(provenance),
            lineage: Some(lineage),
            acknowledgement: Some(acknowledgement),
            failure: None,
            committed: false,
            commit: None,
        },
    );
    let reads = states[0].borrow().lineage_reads;
    let validations = states[0].borrow().lineage_validations;

    let view = runtime
        .observe_original_staged_input(&admission)?
        .ok_or(RuntimeError::UnsupportedFacet)?;
    let retained = &runtime.input_batches[&id("stage")];
    assert!(std::ptr::eq(
        view.lineage().ok_or(RuntimeError::UnsupportedFacet)?,
        retained
            .lineage
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
    ));
    assert!(std::ptr::eq(
        view.provenance().ok_or(RuntimeError::UnsupportedFacet)?,
        retained
            .provenance
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
    ));
    assert_eq!(
        view.lineage()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .publications()[0]
            .objects
            .len(),
        2
    );
    assert_eq!(view.batch().deliveries()[0].native_sequence, 7.into());
    assert_eq!(view.batch().deliveries()[0].source_sequence, 900.into());

    runtime
        .input_batches
        .get_mut(&id("stage"))
        .ok_or(RuntimeError::InvalidReceipt)?
        .provenance = None;
    assert!(matches!(
        runtime.observe_original_staged_input(&admission),
        Err(RuntimeError::UnsupportedFacet)
    ));
    assert_eq!(states[0].borrow().lineage_reads, reads);
    assert_eq!(states[0].borrow().lineage_validations, validations);
    assert_eq!(states[1].borrow().begin_calls, 0);
    Ok(())
}
