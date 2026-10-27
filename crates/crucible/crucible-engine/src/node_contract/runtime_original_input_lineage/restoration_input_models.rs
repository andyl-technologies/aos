//! Checks saved staging facts without converting failed native ACKs into success.
//!
//! These synthetic Core controls qualify no installed native restoration class.

use super::*;
use crate::node_scheduling::NativeInputAcknowledgement;

fn acknowledgement(model: &Model) -> NativeInputAcknowledgement {
    let input = &model.record.inputs[0];
    NativeInputAcknowledgement {
        node: input.node.clone(),
        stage_operation: input.stage_operation.clone(),
        batch: input.batch.clone(),
        owners: input.owners.clone(),
        cutoff: input.cutoff,
        inventory: input.inventory.clone(),
        proof_ref: model.source.clone(),
    }
}

#[test]
fn original_lineage_context_rejects_impossible_input_custody_before_native_verification()
-> Result<(), RuntimeError> {
    for mutation in [
        "committed_without_ack",
        "committed_without_coordinator",
        "coordinator_without_ack",
        "committed_with_failure",
        "coordinator_with_failure",
        "ack_node",
        "ack_stage",
        "ack_batch",
        "ack_owners",
        "ack_cutoff",
        "ack_inventory",
        "ack_proof",
        "ack_empty_proof",
    ] {
        let mut model = Model::new();
        model.record.inputs[0].acknowledgement = Some(acknowledgement(&model));
        let input = &mut model.record.inputs[0];
        match mutation {
            "committed_without_ack" => {
                input.committed = true;
                input.coordinator_committed = true;
                input.acknowledgement = None;
            }
            "committed_without_coordinator" => input.committed = true,
            "coordinator_without_ack" => {
                input.coordinator_committed = true;
                input.acknowledgement = None;
            }
            "committed_with_failure" | "coordinator_with_failure" => {
                input.coordinator_committed = true;
                input.committed = mutation == "committed_with_failure";
                input.failure = Some(OperationFailure {
                    effects: EffectKnowledge::Unknown,
                    reason: "original failed staging".into(),
                });
            }
            _ => {
                let ack = input
                    .acknowledgement
                    .as_mut()
                    .ok_or(RuntimeError::InvalidReceipt)?;
                match mutation {
                    "ack_node" => ack.node = id("foreign-node"),
                    "ack_stage" => ack.stage_operation = id("foreign-stage"),
                    "ack_batch" => ack.batch = id("foreign-batch"),
                    "ack_owners" => ack.owners.clear(),
                    "ack_cutoff" => ack.cutoff.time_ps = (ack.cutoff.time_ps.get() + 1).into(),
                    "ack_inventory" => ack.inventory = model.source.clone(),
                    "ack_proof" => ack.proof_ref.media_type.clear(),
                    "ack_empty_proof" => ack.proof_ref.length = 0.into(),
                    _ => unreachable!(),
                }
            }
        }
        model.reauthenticate_record();
        let mut verifier = Verifier::new(&model);

        assert!(
            matches!(
                model.prepare(&mut verifier),
                Err(RuntimeError::InvalidReceipt)
            ),
            "invalid {mutation} must not form a restoration context"
        );

        assert_eq!(verifier.calls, 0, "{mutation}");
        model.no_native_effects();
    }
    Ok(())
}

#[test]
fn original_lineage_metadata_preserves_staging_prefixes_and_failed_ack_evidence()
-> Result<(), RuntimeError> {
    for (committed, coordinator_committed, acknowledged, failed) in [
        (false, false, false, false),
        (false, false, true, false),
        (false, true, true, false),
        (true, true, true, false),
        (false, false, false, true),
        (false, false, true, true),
    ] {
        let mut model = Model::new();
        let mut ack = acknowledgement(&model);
        if failed {
            // A rejected native ACK remains exact failure evidence. It cannot
            // become an authenticated ACK or discharge the staging obligation.
            ack.node = id("rejected-native-ack-node");
            ack.proof_ref.media_type.clear();
        }
        let input = &mut model.record.inputs[0];
        input.committed = committed;
        input.coordinator_committed = coordinator_committed;
        input.acknowledgement = acknowledged.then_some(ack);
        input.failure = failed.then(|| OperationFailure {
            effects: EffectKnowledge::Unknown,
            reason: "retained original rejected acknowledgement".into(),
        });
        let original = input.clone();

        model
            .record
            .validate_metadata(OriginalInputLineageLimits::default(), 1024 * 1024)?;

        assert_eq!(model.record.inputs[0], original);
        model.no_native_effects();
    }
    Ok(())
}

#[test]
fn original_lineage_snapshot_retains_rejected_native_ack_and_unknown_failure()
-> Result<(), RuntimeError> {
    let (mut runtime, lineage, historical) = preservation_record();
    let batch = lineage.original().retained_copy();
    let publication = &lineage.publications()[0];
    let provenance = InputProvenanceClosure::from_validated(
        &batch,
        vec![publication.origin.measurement.clone()],
        publication.objects.clone(),
    );
    let acknowledgement = NativeInputAcknowledgement {
        node: id("rejected-native-node"),
        stage_operation: batch.stage_operation().clone(),
        batch: batch.batch().clone(),
        owners: batch.owners().to_vec(),
        cutoff: batch.cutoff(),
        inventory: batch.inventory().clone(),
        proof_ref: ContentRef {
            media_type: String::new(),
            ..publication.origin.measurement.clone()
        },
    };
    let failure = OperationFailure {
        effects: EffectKnowledge::Unknown,
        reason: "original native acknowledgement rejected".into(),
    };
    runtime.input_batches.insert(
        batch.stage_operation().clone(),
        inputs::RetainedInput {
            batch,
            provenance: Some(provenance),
            lineage: Some(lineage),
            acknowledgement: Some(acknowledgement.clone()),
            failure: Some(failure.clone()),
            committed: false,
            commit: None,
        },
    );

    let record = runtime.original_lineage_runtime_snapshot(
        position(2000),
        1.into(),
        OriginalInputLineageLimits::default(),
        1024 * 1024,
    )?;

    assert_eq!(record.inputs[0].acknowledgement, Some(acknowledgement));
    assert_eq!(record.inputs[0].failure, Some(failure));
    assert!(!record.inputs[0].coordinator_committed);
    assert!(!record.inputs[0].committed);
    assert_eq!(record.operations, historical.operations);
    assert_eq!(record.owners, historical.owners);
    Ok(())
}
