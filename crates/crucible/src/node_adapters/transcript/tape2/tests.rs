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
