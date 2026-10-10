//! Retained evaluator-binding regressions without native qualification claims.

use super::*;
use crucible_node_contract::{Endpoint, U64};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn position(time: u64, microstep: u64, phase: Phase) -> Position {
    Position::new(U64::new(time), U64::new(microstep), phase)
}

fn source() -> Result<Endpoint, crucible_node_contract::ContractError> {
    Ok(Endpoint {
        node_id: Id::new("disk")?,
        port_id: Id::new("data")?,
        lane_id: Id::new("output")?,
    })
}

fn definition() -> TestResultDefinition {
    let disk = crate::NodeId {
        name: "disk".into(),
    };
    let namespace = crate::model::PropertyNamespace::new(
        std::collections::BTreeMap::from([(
            disk.clone(),
            std::collections::BTreeSet::from([crate::model::PropertyObservation::Io(
                IoEventKind::Any,
            )]),
        )]),
        false,
        false,
        std::collections::BTreeSet::new(),
    )?;
    let properties = crate::Properties::from_assertions_for_namespace(
        &namespace,
        vec![crate::AssertionDef {
            id: crate::AssertionId::from_name("first-completion"),
            message: "the real native completion is the selected condition".into(),
            property: Property::Sometimes {
                predicate: Predicate::IoPattern {
                    node: disk,
                    kind: IoEventKind::Any,
                },
            },
        }],
    )?;
    Ok(ConditionDebugDefinition {
        version: 1,
        condition: Id::new("first-completion")?,
        evaluation: HostSemanticDefinition {
            version: 1,
            properties: Bytes::new(properties.to_compact_binary()),
            inputs: vec![super::super::semantic_model::HostSemanticInput {
                source: source()?,
                kind: super::super::semantic_model::HostSemanticInputKind::BlockCompletion,
            }],
        },
    })
}

type TestResultDefinition = Result<ConditionDebugDefinition, Box<dyn std::error::Error>>;

fn delivery(bytes: &[u8]) -> Result<Delivery, crucible_node_contract::ContractError> {
    let producer_endpoint = source()?;
    let consumer_endpoint = Endpoint {
        node_id: Id::new("semantics")?,
        port_id: Id::new("data")?,
        lane_id: Id::new("input")?,
    };
    Ok(Delivery {
        connection_id: Some(Id::new("disk/semantics")?),
        connection_policy_ref: Some(canonical::content_ref(
            b"installed connection policy",
            "text/plain",
        )?),
        external_root: None,
        provenance_ref: canonical::content_ref(b"fixture original proof bytes", "text/plain")?,
        publication_id: Id::new("disk-original-output/0")?,
        producer: producer_endpoint.node_id.clone(),
        consumer: consumer_endpoint.node_id.clone(),
        producer_endpoint,
        consumer_endpoint,
        source_sequence: U64::new(0),
        native_sequence: U64::new(0),
        evaluation: Some(position(3, 0, Phase::Reaction)),
        causal_parents: Vec::new(),
        publication: position(3, 1, Phase::Publication),
        delivery: position(3, 1, Phase::Delivery),
        payload: canonical::content_ref(bytes, "application/octet-stream")?,
    })
}

fn hit() -> Result<(ConditionDebugModel, Delivery), Box<dyn std::error::Error>> {
    let mut model =
        ConditionDebugModel::new(definition()?, 1 << 20, 128).map_err(|error| error.reason)?;
    let reply =
        crucible_device::BlockResponse::ok(7, b"original native bytes".to_vec()).encode()?;
    let delivery = delivery(&reply)?;
    model
        .consume(&delivery, &reply, position(3, 2, Phase::Reaction))
        .map_err(|error| error.reason)?;
    Ok((model, delivery))
}

#[test]
fn original_match_restores_without_prefix_reevaluation_or_second_hit() -> TestResult {
    let (mut model, input) = hit()?;
    model
        .park(position(3, 3, Phase::BoundaryControl))
        .map_err(|error| error.reason)?;
    let bytes = model.capture().map_err(|error| error.reason)?;
    let mut restored = ConditionDebugModel::restore(definition()?, &bytes, 1 << 20, 128)
        .map_err(|error| error.reason)?;

    assert_eq!(restored.capture().map_err(|error| error.reason)?, bytes);
    assert_eq!(restored.candidate(), model.candidate());
    assert!(restored.awaiting_control());
    assert!(
        restored
            .consume(&input, b"replacement", position(3, 4, Phase::Reaction))
            .is_err()
    );
    assert!(
        restored
            .park(position(4, 0, Phase::BoundaryControl))
            .is_err()
    );
    assert_eq!(restored.capture().map_err(|error| error.reason)?, bytes);
    Ok(())
}

#[test]
fn candidate_cannot_be_omitted_or_labelled_as_resumed() -> TestResult {
    let (model, _) = hit()?;
    let captured = model.capture().map_err(|error| error.reason)?;
    for change in 0..2 {
        let (mut wire, store) = decoded_index(&captured)?;
        if change == 0 {
            wire.candidate = None;
        } else {
            wire.resumed = true;
        }
        let bytes = edited_index(wire, store)?;
        assert!(ConditionDebugModel::restore(definition()?, &bytes, 1 << 20, 128).is_err());
    }
    Ok(())
}

#[test]
fn changed_inner_outcome_facts_or_extra_fields_refuse_saved_hit() -> TestResult {
    let (model, _) = hit()?;
    let captured = model.capture().map_err(|error| error.reason)?;
    for change in 0..8 {
        let (mut wire, store) = decoded_index(&captured)?;
        let hit = wire.candidate.as_mut().ok_or("missing original hit")?;
        let mut value: serde_json::Value = serde_json::from_slice(hit.outcome.bytes.as_slice())?;
        match change {
            0 => value["evaluation"]["microstep"] = "9".into(),
            1 => value["quantifier"] = "Always".into(),
            2 => value["message"] = "substituted message".into(),
            3 => value["reason"] = "manufactured reason".into(),
            4 => value["outcome_time_ps"] = 4.into(),
            5 => value["lifecycle"] = "Declared".into(),
            6 => value["unqualified_authority"] = true.into(),
            _ => value["assertion"] = "foreign-condition".into(),
        }
        hit.outcome.bytes = Bytes::new(canonical::canonical_json(&value)?);
        let bytes = edited_index(wire, store)?;
        assert!(
            ConditionDebugModel::restore(definition()?, &bytes, 1 << 20, 128).is_err(),
            "mutation {change}"
        );
    }
    Ok(())
}

#[test]
fn changed_original_delivery_or_outer_causal_cut_refuses_saved_hit() -> TestResult {
    let (model, _) = hit()?;
    let captured = model.capture().map_err(|error| error.reason)?;
    for change in 0..4 {
        let (mut wire, store) = decoded_index(&captured)?;
        let hit = wire.candidate.as_mut().ok_or("missing original hit")?;
        match change {
            0 => hit.input.native_sequence = U64::new(99),
            1 => hit.input.provenance_ref = canonical::content_ref(b"foreign", "text/plain")?,
            2 => hit.outcome.parents.clear(),
            _ => hit.evaluation = position(3, 1, Phase::Reaction),
        }
        let bytes = edited_index(wire, store)?;
        assert!(ConditionDebugModel::restore(definition()?, &bytes, 1 << 20, 128).is_err());
    }
    Ok(())
}

#[test]
fn invalid_reply_or_exhausted_capture_credit_preserves_whole_original_model() -> TestResult {
    let mut model =
        ConditionDebugModel::new(definition()?, 1 << 20, 128).map_err(|error| error.reason)?;
    let captured = model.capture().map_err(|error| error.reason)?;
    let reply = crucible_device::BlockResponse::ok(7, vec![1, 2, 3]).encode()?;
    let input = delivery(&reply)?;
    assert!(
        model
            .consume(&input, b"changed", position(3, 2, Phase::Reaction))
            .is_err()
    );
    model.maximum_bytes = captured.len();
    assert!(
        model
            .consume(&input, &reply, position(3, 2, Phase::Reaction))
            .is_err()
    );
    assert_eq!(model.capture().map_err(|error| error.reason)?, captured);
    assert!(!model.awaiting_control());
    Ok(())
}

#[test]
fn different_program_and_unknown_editions_refuse_before_evaluation() -> TestResult {
    let (model, _) = hit()?;
    let captured = model.capture().map_err(|error| error.reason)?;
    let mut other = definition()?;
    other.condition = Id::new("other")?;
    assert!(ConditionDebugModel::restore(other, &captured, 1 << 20, 128).is_err());
    for version in [0, 2, 65535] {
        let mut other = definition()?;
        other.version = version;
        assert!(ConditionDebugModel::new(other, 1 << 20, 128).is_err());
    }
    Ok(())
}

#[test]
fn multiple_original_proof_indexes_retain_one_complete_shared_body() -> TestResult {
    let mut model =
        ConditionDebugModel::new(definition()?, 1 << 20, 128).map_err(|error| error.reason)?;
    let body = vec![0x5c; 65_537];
    let reference = canonical::content_ref(&body, "application/octet-stream")?;
    let mut prior_size = 0;
    for sequence in 0..16 {
        model
            .provenance
            .push(crate::node_contract::SavedInputProvenance {
                schema_version: 1,
                node: Id::new("observer")?,
                stage_operation: Id::new(format!("original-stage-{sequence}"))?,
                batch: Id::new(format!("original-batch-{sequence}"))?,
                inventory: canonical::content_ref(
                    format!("inventory-{sequence}").as_bytes(),
                    "text/plain",
                )?,
                roots: vec![reference.clone()],
                objects: vec![crate::node_scheduling::InputPayload {
                    reference: reference.clone(),
                    bytes: body.clone(),
                }],
            });
        model.validate_provenance().map_err(|error| error.reason)?;
        let bytes = model.capture().map_err(|error| error.reason)?;
        let (_, store) = model.capture_dag().map_err(|error| error.reason)?;
        assert_eq!(store.objects().count(), sequence + 3);
        if prior_size != 0 {
            assert!(bytes.len() - prior_size < 4096);
        }
        prior_size = bytes.len();
        let restored = ConditionDebugModel::restore(definition()?, &bytes, 1 << 20, 128)
            .map_err(|error| error.reason)?;
        assert_eq!(restored.capture().map_err(|error| error.reason)?, bytes);
        assert_eq!(restored.provenance, model.provenance);
    }
    assert!(prior_size < 200_000);
    Ok(())
}

fn decoded_index(
    bytes: &[u8],
) -> Result<(Continuation, dag::EvidenceDag), Box<dyn std::error::Error>> {
    let (store, roots) =
        dag::EvidenceDag::decode(bytes, 1040, 1 << 20).map_err(|error| error.reason)?;
    let wire = serde_json::from_slice(store.body(&roots[0]).map_err(|error| error.reason)?)?;
    Ok((wire, store))
}

fn edited_index(
    wire: Continuation,
    original: dag::EvidenceDag,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut store = dag::EvidenceDag::new(1040, 1 << 20);
    let mut dependencies = wire.provenance.clone();
    dependencies.extend(wire.journal.clone());
    let mut queue = dependencies.clone();
    let mut visited = std::collections::BTreeSet::new();
    while let Some(reference) = queue.pop() {
        if !visited.insert(reference.clone()) {
            continue;
        }
        let object = original
            .objects()
            .find(|object| object.reference == reference)
            .ok_or("original index dependency omitted")?;
        queue.extend(object.dependencies.iter().cloned());
        store
            .insert(
                reference,
                object.bytes.as_slice(),
                object.dependencies.clone(),
            )
            .map_err(|error| error.reason)?;
    }
    let bytes = native::canonical_bytes(&wire).map_err(|error| error.reason)?;
    let root = store
        .add(&bytes, "application/octet-stream", dependencies)
        .map_err(|error| error.reason)?;
    Ok(store.encode(vec![root]).map_err(|error| error.reason)?)
}

#[test]
fn repeated_original_provenance_references_refuse_before_model_body_expansion() -> TestResult {
    let mut model =
        ConditionDebugModel::new(definition()?, 1 << 20, 128).map_err(|error| error.reason)?;
    let body = vec![0x7c; 65_537];
    let reference = canonical::content_ref(&body, "application/octet-stream")?;
    model
        .provenance
        .push(crate::node_contract::SavedInputProvenance {
            schema_version: 1,
            node: Id::new("observer")?,
            stage_operation: Id::new("original-stage")?,
            batch: Id::new("original-batch")?,
            inventory: canonical::content_ref(b"original inventory", "text/plain")?,
            roots: vec![reference.clone()],
            objects: vec![crate::node_scheduling::InputPayload {
                reference: reference.clone(),
                bytes: body.clone(),
            }],
        });
    let original = model.capture().map_err(|error| error.reason)?;
    let (mut wire, source) = decoded_index(&original)?;
    let mut index: ProvenanceIndex = serde_json::from_slice(
        source
            .body(&wire.provenance[0])
            .map_err(|error| error.reason)?,
    )?;
    index.objects = vec![reference.clone(); (64 << 20) / body.len() + 1];

    let mut store = dag::EvidenceDag::new(1040, 1 << 20);
    store
        .insert(reference.clone(), &body, Vec::new())
        .map_err(|error| error.reason)?;
    let index = store
        .add(
            &native::canonical_bytes(&index).map_err(|error| error.reason)?,
            "application/json",
            vec![reference],
        )
        .map_err(|error| error.reason)?;
    wire.provenance = vec![index.clone()];
    let root = store
        .add(
            &native::canonical_bytes(&wire).map_err(|error| error.reason)?,
            "application/octet-stream",
            vec![index],
        )
        .map_err(|error| error.reason)?;
    let malicious = store.encode(vec![root]).map_err(|error| error.reason)?;
    assert!(malicious.len() < 1 << 20);

    let refused = ConditionDebugModel::restore(definition()?, &malicious, 1 << 20, 128)
        .err()
        .ok_or("amplified model unexpectedly reopened")?;
    assert_eq!(
        refused.reason,
        "condition expanded association credit exhausted"
    );
    assert_eq!(model.capture().map_err(|error| error.reason)?, original);
    Ok(())
}
