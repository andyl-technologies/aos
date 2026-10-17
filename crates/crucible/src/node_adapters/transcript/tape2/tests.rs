//! Checks historical Tape2 cutoff and source geometry with synthetic signed data.
//!
//! These data models do not qualify a native source, readiness or preservation.

use super::*;
use crate::node_adapters::transcript::tape2::{
    OriginalLineageTapePrefix, RecordedLineage, RecordedTape2, bounded_metadata,
};
use crate::node_scheduling::NativeInputAcknowledgement;

fn tape_source() -> (Directory, AuthenticatedTranscript, ContentRef, Id) {
    let directory = Directory::new();
    let source = origin();
    let inventory = object(b"[]").reference;
    let stage = id("original/stage");
    let saved = SavedOriginalInputLineage {
        schema_version: 1,
        source: SavedOriginalInputScope {
            source_activation: source.activation.clone(),
            node: source.route.node.clone(),
            stage_operation: stage.clone(),
            batch: id("original/batch"),
            owners: source.route.owners.clone(),
            cutoff: position(1),
            inventory: inventory.clone(),
        },
        publications: Vec::new(),
    };
    let body = ControlRequest::Stage {
        input: RecordedInput {
            node: saved.source.node.clone(),
            stage_operation: stage.clone(),
            batch: saved.source.batch.clone(),
            owners: saved.source.owners.clone(),
            cutoff: saved.source.cutoff,
            inventory: inventory.clone(),
            deliveries: Vec::new(),
            payloads: Vec::new(),
            provenance: None,
        },
    };
    let acknowledgement_body = object(b"{\"original_ack\":1}");
    let acknowledgement = NativeInputAcknowledgement {
        stage_operation: stage.clone(),
        batch: saved.source.batch.clone(),
        node: saved.source.node.clone(),
        owners: saved.source.owners.clone(),
        cutoff: saved.source.cutoff,
        inventory,
        proof_ref: acknowledgement_body.reference.clone(),
    };
    // crucible-lint: allow panic-shortcut -- The synthetic reference-only metadata is deliberately a valid exact Stage fixture.
    let metadata = RecordedTape2::capture(
        &source,
        stage.clone(),
        RecordedLineage::Input {
            input: Box::new(saved),
        },
        100_000,
    )
    .unwrap();
    // crucible-lint: allow panic-shortcut -- This source-data model deliberately reserves a valid bounded capture.
    let mut capture = CaptureSession::new(source, limits()).unwrap();
    // crucible-lint: allow panic-shortcut -- The first model record fits its declared capture credit.
    let reservation = capture.reserve().unwrap();
    // crucible-lint: allow panic-shortcut -- The fixture context was created from valid closed source data.
    let context = capture.context().unwrap();
    // crucible-lint: allow panic-shortcut -- The exact original Stage is deliberately valid model data.
    let first_request = request(
        TranscriptAction::StageInput,
        stage.clone(),
        position(0),
        context,
        &body,
    )
    .unwrap();
    // crucible-lint: allow panic-shortcut -- The synthetic acknowledgement is serializable closed data.
    let response = encode(&ControlResponse::Input(Box::new(acknowledgement))).unwrap();
    // crucible-lint: allow panic-shortcut -- The complete first model record fits all declared bounds.
    capture
        .retain(
            reservation,
            first_request,
            response,
            vec![metadata, acknowledgement_body],
            Vec::new(),
            PhysicalTimingUncertainty::Unbounded,
        )
        .unwrap();

    let future = object(b"{\"not_yet_consumed\":true}");
    let reference = future.reference.clone();
    // crucible-lint: allow panic-shortcut -- The second model record fits its declared capture credit.
    let reservation = capture.reserve().unwrap();
    // crucible-lint: allow panic-shortcut -- The fixture context remains the unchanged original scope.
    let context = capture.context().unwrap();
    // crucible-lint: allow panic-shortcut -- This later synthetic request is deliberately valid control data.
    let request = request(
        TranscriptAction::Acknowledge,
        id("original/later"),
        position(1),
        context,
        &ControlRequest::Acknowledge {
            operation: id("original/later"),
            outputs: Vec::new(),
        },
    )
    .unwrap();
    // crucible-lint: allow panic-shortcut -- The terminal synthetic response has a closed representation.
    let response = encode(&ControlResponse::Acknowledged).unwrap();
    // crucible-lint: allow panic-shortcut -- The later evidence is retained only in the second original interaction.
    capture
        .retain(
            reservation,
            request,
            response,
            vec![future],
            Vec::new(),
            PhysicalTimingUncertainty::Unbounded,
        )
        .unwrap();
    // crucible-lint: allow panic-shortcut -- The two complete data-model reservations have settled.
    let captured = capture.finish().unwrap();
    // crucible-lint: allow panic-shortcut -- The private model archive directory has valid ownership and bounded limits.
    let archive = TranscriptArchive::open(&directory.0, limits()).unwrap();
    // crucible-lint: allow panic-shortcut -- Persisting this model capture exercises the real archive integrity path without native qualification.
    let source = archive.persist(captured).unwrap();
    (directory, source, reference, stage)
}

fn qualified_model_cursor(source: AuthenticatedTranscript) -> ReplayCursor {
    let mut cursor = cursor(source);
    // This deliberately synthetic installed evidence is confined to this data
    // fixture; production defaults cannot mint a Tape2 qualification from it.
    cursor.original_lineage = Some(ReplayQualification {
        proof: object(b"{\"synthetic_tape2_policy\":true}"),
        source_context: cursor.qualification.source_context.clone(),
        target_world: cursor.qualification.target_world.clone(),
        target_binding: cursor.qualification.target_binding.clone(),
        target_route: cursor.qualification.target_route.clone(),
    });
    cursor
}

#[test]
fn tape2_never_reads_a_future_stage_or_body() {
    let (_directory, source, future, stage) = tape_source();
    let mut cursor = qualified_model_cursor(source);
    // crucible-lint: allow panic-shortcut -- This explicit model qualification permits only an empty consumed prefix.
    let prefix = OriginalLineageTapePrefix::from_cursor(&cursor).unwrap();
    assert!(prefix.input(&stage).is_err());
    assert!(
        prefix
            .read_original_bodies(std::slice::from_ref(&future), 100_000)
            .is_err()
    );
    // crucible-lint: allow panic-shortcut -- The source contains the deliberately valid first Stage request.
    let request = cursor.peek().unwrap().request.clone();
    // crucible-lint: allow panic-shortcut -- Consuming the identical first request is the tested valid data-model branch.
    cursor.replay(&request).unwrap();
    // crucible-lint: allow panic-shortcut -- The explicit model qualification survives the first exact interaction.
    let prefix = OriginalLineageTapePrefix::from_cursor(&cursor).unwrap();
    // crucible-lint: allow panic-shortcut -- The original Stage metadata is now in the consumed prefix.
    assert_eq!(prefix.input(&stage).unwrap().source.stage_operation, stage);
    assert!(
        prefix
            .read_original_bodies(std::slice::from_ref(&future), 100_000)
            .is_err()
    );
    // crucible-lint: allow panic-shortcut -- The fixture retains its later exact original request.
    let request = cursor.peek().unwrap().request.clone();
    // crucible-lint: allow panic-shortcut -- This identical later request is a valid model interaction.
    cursor.replay(&request).unwrap();
    // crucible-lint: allow panic-shortcut -- The final model prefix contains both original interactions.
    let prefix = OriginalLineageTapePrefix::from_cursor(&cursor).unwrap();
    assert!(
        prefix
            .read_original_bodies(std::slice::from_ref(&future), 0)
            .is_err()
    );
    // crucible-lint: allow panic-shortcut -- The exact future role is readable only after its interaction is consumed.
    assert_eq!(
        prefix
            .read_original_bodies(std::slice::from_ref(&future), 100_000)
            .unwrap()[0]
            .reference,
        future
    );
}

#[test]
fn tape2_ordinary_qualification_cannot_enable_the_reader() {
    let (_directory, source, _, _) = tape_source();
    let cursor = cursor(source);
    assert!(OriginalLineageTapePrefix::from_cursor(&cursor).is_err());
}

#[test]
fn tape2_whole_metadata_is_counted_before_body_allocation() {
    let value =
        serde_json::json!({"first":"unchanged", "source_capture":"distinct", "target":"fresh"});
    // crucible-lint: allow panic-shortcut -- This finite synthetic metadata has a valid canonical representation.
    let size = encode(&value).unwrap().len();
    assert!(bounded_metadata(&value, size - 1).is_err());
    assert!(bounded_metadata(&value, size).is_ok());
}

#[test]
fn tape2_foreign_capture_and_inventory_refuse_before_prefix_use() {
    let (_directory, source, _, _) = tape_source();
    let original = &source.transcript().records[0];
    let original_metadata = &original.evidence[0];
    for changed in ["capture", "inventory", "edition", "unknown"] {
        // crucible-lint: allow panic-shortcut -- The original model metadata is deliberately valid closed Tape2 data.
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&original_metadata.bytes).unwrap();
        match changed {
            "capture" => {
                metadata["source_capture"]["activation_id"] =
                    serde_json::json!("foreign/activation")
            }
            "inventory" => {
                metadata["lineage"]["input"]["source"]["inventory"] =
                    serde_json::json!(object(b"{}").reference)
            }
            "edition" => metadata["schema_version"] = serde_json::json!(3),
            _ => metadata["undeclared"] = serde_json::json!(true),
        }
        // crucible-lint: allow panic-shortcut -- Serializing altered data intentionally creates genuine changed-body counterexamples.
        let changed = object(&encode(&metadata).unwrap());
        let changed = InputPayload {
            reference: ContentRef {
                media_type: super::super::tape2::MEDIA_TYPE.into(),
                ..changed.reference
            },
            bytes: changed.bytes,
        };
        assert!(
            RecordedTape2::decode(&changed, &source.transcript().origin, original).is_err(),
            "accepted {changed:?}"
        );
    }
}

#[test]
fn tape2_missing_or_changed_original_acknowledgement_refuses() {
    let (_directory, source, _, _) = tape_source();
    let original = &source.transcript().records[0];
    for changed in ["missing", "batch", "scope"] {
        let mut record = original.clone();
        if changed == "missing" {
            record.evidence.truncate(1);
        } else {
            // crucible-lint: allow panic-shortcut -- The synthetic record contains the exact valid closed acknowledgement response.
            let mut response: ControlResponse =
                serde_json::from_slice(&record.response_bytes).unwrap();
            if let ControlResponse::Input(acknowledgement) = &mut response {
                if changed == "batch" {
                    acknowledgement.batch = id("foreign/batch");
                } else {
                    acknowledgement.owners.clear();
                }
            }
            // crucible-lint: allow panic-shortcut -- The changed closed response is a finite intentional custody counterexample.
            record.response_bytes = encode(&response).unwrap();
        }
        assert!(
            RecordedTape2::decode(&record.evidence[0], &source.transcript().origin, &record)
                .is_err(),
            "accepted {changed}"
        );
    }
}

pub(in crate::node_adapters::transcript) fn input_model_cursor() -> ReplayCursor {
    let (_directory, source, _, _) = tape_source();
    qualified_model_cursor(source)
}

/// Supplies an inert event occurrence whose zero-byte payload still needs ancestry.
pub(in crate::node_adapters::transcript) fn zero_byte_delivery(
    consumer: &Id,
) -> crate::node_scheduling::event::Delivery {
    let endpoint = crucible_node_contract::Endpoint {
        node_id: id("synthetic/producer"),
        port_id: id("synthetic/port"),
        lane_id: id("synthetic/output"),
    };
    crate::node_scheduling::event::Delivery {
        connection_id: Some(id("synthetic/connection")),
        connection_policy_ref: Some(object(b"{}").reference),
        external_root: None,
        provenance_ref: object(b"{\"synthetic_proof\":true}").reference,
        publication_id: id("original/zero-byte-event"),
        producer: endpoint.node_id.clone(),
        consumer: consumer.clone(),
        producer_endpoint: endpoint,
        consumer_endpoint: crucible_node_contract::Endpoint {
            node_id: consumer.clone(),
            port_id: id("synthetic/port"),
            lane_id: id("synthetic/input"),
        },
        source_sequence: 0.into(),
        native_sequence: 0.into(),
        evaluation: None,
        causal_parents: Vec::new(),
        publication: Position::new(0.into(), 0.into(), Phase::Publication),
        delivery: Position::new(0.into(), 0.into(), Phase::Delivery),
        payload: object(b"").reference,
    }
}

#[test]
fn tape2_empty_stage_retains_original_ack_without_lineage_claim() -> Result<(), TranscriptError> {
    let (_directory, mut source, _, _) = tape_source();
    // The older inert prefix fixture deliberately has empty ancestry metadata.
    // Selected source validation rejects that fabricated empty-event claim.
    assert!(super::super::tape2::validate_selected_source(&source).is_err());
    let data = std::rc::Rc::make_mut(&mut source.data);
    let record = &mut data.records[0];
    record.evidence.remove(0);
    assert!(super::super::tape2::validate_selected_source(&source).is_ok());
    let response: ControlResponse = serde_json::from_slice(&source.data.records[0].response_bytes)
        .map_err(super::super::codec::invalid)?;
    assert!(matches!(response, ControlResponse::Input(_)));
    Ok(())
}

#[test]
fn tape2_zero_byte_event_still_requires_original_metadata_before_qualification()
-> Result<(), TranscriptError> {
    let (_directory, mut source, _, _) = tape_source();
    let data = std::rc::Rc::make_mut(&mut source.data);
    let record = &mut data.records[0];
    record.evidence.remove(0);
    let mut request: ControlRequest =
        serde_json::from_slice(&record.request.bytes).map_err(super::super::codec::invalid)?;
    let ControlRequest::Stage { input } = &mut request else {
        return Err(super::super::codec::invalid("synthetic Stage absent"));
    };
    input.deliveries.push(zero_byte_delivery(&input.node));
    input.payloads.push(object(b""));
    record.request.bytes = encode(&request)?;
    record.request.content = canonical::content_ref(&record.request.bytes, "application/json")
        .map_err(super::super::codec::invalid)?;
    assert!(super::super::tape2::validate_selected_source(&source).is_err());
    Ok(())
}

#[test]
fn tape2_original_scheduling_owners_refuse_before_capture_owner_association()
-> Result<(), super::TranscriptError> {
    use crate::node_contract::{OperationOutcome, ProgressEvidence};
    use crate::node_scheduling::NativeSchedulingObservation;
    let original = origin();
    let proof = object(b"inert-stopped-receipt");
    let observation = NativeSchedulingObservation {
        node: original.route.node.clone(),
        owners: original.route.owners.clone(),
        reached: position(0),
        closed_prefix: position(0),
        bounds: Vec::new(),
        publications: Vec::new(),
        input_progress: None,
        external_inputs: Vec::new(),
        proof_ref: proof.reference.clone(),
    };
    let outcome = OperationOutcome {
        operation: id("original/empty-completion"),
        node: original.route.node.clone(),
        owners: original.route.owners.clone(),
        progress: ProgressEvidence::Administrative,
        retained_outputs: Vec::new(),
        scheduling: Some(observation),
    };
    for (changed_node, changed_owner) in [(false, false), (true, false), (false, true)] {
        let mut value = outcome.clone();
        if changed_node || changed_owner {
            let observation = value.scheduling.as_mut().ok_or_else(|| {
                crate::node_adapters::transcript::codec::invalid("synthetic scheduling absent")
            })?;
            if changed_node {
                observation.node = id("foreign/original-node");
            }
            if changed_owner {
                observation.owners[0].incarnation = id("foreign/original-owner");
            }
        }
        let mut capture = CaptureSession::new(original.clone(), limits())?;
        let request = request(
            TranscriptAction::Complete,
            outcome.operation.clone(),
            position(0),
            capture.context()?,
            &ControlRequest::Complete {
                operation: outcome.operation.clone(),
            },
        )?;
        let reservation = capture.reserve()?;
        capture.retain(
            reservation,
            request,
            encode(&ControlResponse::Outcome(Box::new(value)))?,
            vec![proof.clone()],
            Vec::new(),
            PhysicalTimingUncertainty::Unbounded,
        )?;
        let captured = capture.finish()?;
        let directory = Directory::new();
        let source = TranscriptArchive::open(&directory.0, limits())?.persist(captured)?;
        assert_eq!(
            crate::node_adapters::transcript::tape2::validate_selected_source(&source).is_err(),
            changed_node || changed_owner
        );
    }
    Ok(())
}
