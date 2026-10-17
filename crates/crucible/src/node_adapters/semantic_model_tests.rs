//! Genuine evaluator-state regressions; fixtures do not qualify a native adapter.

use crucible_node_contract::Id;

use super::*;
use crate::{AssertionDef, AssertionId, Predicate, Property};

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
    let disk = NodeId {
        name: "disk".into(),
    };
    let namespace = PropertyNamespace::new(
        BTreeMap::from([(
            disk.clone(),
            BTreeSet::from([PropertyObservation::Io(IoEventKind::Any)]),
        )]),
        false,
        false,
        BTreeSet::new(),
    )?;
    let properties = Properties::from_assertions_for_namespace(
        &namespace,
        vec![AssertionDef {
            id: AssertionId::from_name("eventual-native-completion"),
            message: "original pending obligation consumes a real decoded reply".into(),
            property: Property::Eventually {
                trigger: Predicate::at(VirtualTime { ticks: 1 }),
                property: Predicate::IoPattern {
                    node: disk,
                    kind: IoEventKind::Any,
                },
                deadline: VirtualTime { ticks: 5 },
            },
        }],
    )?;
    Ok(HostSemanticDefinition {
        version: 1,
        properties: Bytes::new(properties.to_compact_binary()),
        inputs: vec![HostSemanticInput {
            source: source()?,
            kind: HostSemanticInputKind::BlockCompletion,
        }],
    })
}

type TestResultDefinition = Result<HostSemanticDefinition, Box<dyn std::error::Error>>;

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

#[test]
fn pending_eventually_state_survives_restore_without_prefix_reevaluation() -> TestResult {
    let definition = definition()?;
    let mut original =
        HostSemanticModel::new(definition.clone(), 1 << 20, 128).map_err(|error| error.reason)?;
    original
        .settle(position(1, 0, Phase::Reaction))
        .map_err(|error| error.reason)?;
    original
        .park(position(2, 0, Phase::BoundaryControl))
        .map_err(|error| error.reason)?;
    let captured = original.capture().map_err(|error| error.reason)?;
    let mut restored = HostSemanticModel::restore(definition, &captured, 1 << 20, 128)
        .map_err(|error| error.reason)?;

    assert_eq!(restored.capture().map_err(|error| error.reason)?, captured);
    assert_eq!(restored.pending_count(), 0);
    let reply = crucible_device::BlockResponse::ok(7, b"native bytes".to_vec()).encode()?;
    let delivery = delivery(&reply)?;
    let reaction = position(3, 2, Phase::Reaction);
    original
        .consume(&delivery, &reply, reaction)
        .map_err(|error| error.reason)?;
    restored
        .consume(&delivery, &reply, reaction)
        .map_err(|error| error.reason)?;

    assert_eq!(
        original.capture().map_err(|error| error.reason)?,
        restored.capture().map_err(|error| error.reason)?
    );
    let outcomes = restored.take_publications();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].evaluation, reaction);
    assert_eq!(outcomes[0].parents, vec![delivery.delivery]);
    let value: serde_json::Value = serde_json::from_slice(outcomes[0].bytes.as_slice())?;
    assert_eq!(value["kind"], "Satisfied");
    assert!(restored.consume(&delivery, &reply, reaction).is_err());
    assert_eq!(restored.pending_count(), 0);
    Ok(())
}

#[test]
fn queued_original_outcome_and_full_cut_survive_unchanged_capture() -> TestResult {
    let definition = definition()?;
    let mut model =
        HostSemanticModel::new(definition.clone(), 1 << 20, 128).map_err(|error| error.reason)?;
    model
        .settle(position(1, 0, Phase::Reaction))
        .map_err(|error| error.reason)?;
    let reply = crucible_device::BlockResponse::ok(7, vec![1, 2, 3]).encode()?;
    model
        .consume(&delivery(&reply)?, &reply, position(3, 2, Phase::Reaction))
        .map_err(|error| error.reason)?;
    let captured = model.capture().map_err(|error| error.reason)?;
    let mut restored = HostSemanticModel::restore(definition, &captured, 1 << 20, 128)
        .map_err(|error| error.reason)?;

    assert_eq!(restored.position(), model.position());
    assert_eq!(restored.take_publications(), model.take_publications());
    assert_eq!(
        restored.capture().map_err(|error| error.reason)?,
        model.capture().map_err(|error| error.reason)?
    );
    Ok(())
}

#[test]
fn changed_source_payload_or_reaction_refuses_without_mutating_original_state() -> TestResult {
    let mut model =
        HostSemanticModel::new(definition()?, 1 << 20, 128).map_err(|error| error.reason)?;
    let original = model.capture().map_err(|error| error.reason)?;
    let reply = crucible_device::BlockResponse::ok(7, vec![1, 2, 3]).encode()?;
    let input = delivery(&reply)?;
    assert!(
        model
            .consume(&input, b"changed", position(3, 2, Phase::Reaction))
            .is_err()
    );
    assert!(
        model
            .consume(&input, &reply, position(3, 1, Phase::Reaction))
            .is_err()
    );
    let mut foreign = input;
    foreign.producer_endpoint.node_id = Id::new("foreign")?;
    assert!(
        model
            .consume(&foreign, &reply, position(3, 2, Phase::Reaction))
            .is_err()
    );
    assert_eq!(model.capture().map_err(|error| error.reason)?, original);
    Ok(())
}

#[test]
fn changed_full_position_prefix_or_input_sidecar_cannot_restore() -> TestResult {
    let definition = definition()?;
    let mut model =
        HostSemanticModel::new(definition.clone(), 1 << 20, 128).map_err(|error| error.reason)?;
    model
        .settle(position(1, 0, Phase::Reaction))
        .map_err(|error| error.reason)?;
    let reply = crucible_device::BlockResponse::ok(7, vec![1, 2, 3]).encode()?;
    model
        .consume(&delivery(&reply)?, &reply, position(3, 2, Phase::Reaction))
        .map_err(|error| error.reason)?;
    let captured = model.capture().map_err(|error| error.reason)?;
    let original: serde_json::Value = serde_json::from_slice(&captured)?;
    for change in 0..3 {
        let mut wire = original.clone();
        match change {
            0 => wire["segments"][1]["position"]["microstep"] = "3".into(),
            1 => wire["segments"][1]["input"]["producer"] = "foreign".into(),
            _ => wire["segments"][1]["input"]["payload"]["length"] = "1".into(),
        }
        assert!(
            HostSemanticModel::restore(
                definition.clone(),
                &canonical::canonical_json(&wire)?,
                1 << 20,
                128
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn changed_pending_outcome_context_refuses_without_reevaluation() -> TestResult {
    let definition = definition()?;
    let mut model =
        HostSemanticModel::new(definition.clone(), 1 << 20, 128).map_err(|error| error.reason)?;
    model
        .settle(position(1, 0, Phase::Reaction))
        .map_err(|error| error.reason)?;
    let reply = crucible_device::BlockResponse::ok(7, vec![1, 2, 3]).encode()?;
    model
        .consume(&delivery(&reply)?, &reply, position(3, 2, Phase::Reaction))
        .map_err(|error| error.reason)?;
    let captured = model.capture().map_err(|error| error.reason)?;

    for change in 0..5 {
        let mut wire: Continuation = serde_json::from_slice(&captured)?;
        let publication = &mut wire.pending[0];
        let mut payload: serde_json::Value = serde_json::from_slice(publication.bytes.as_slice())?;
        match change {
            0 => payload["assertion"] = "foreign-property".into(),
            1 => payload["evaluation"]["microstep"] = "3".into(),
            2 => payload["outcome_time_ps"] = 99.into(),
            3 => publication.parents.clear(),
            _ => {}
        }
        let mut payload = canonical::canonical_json(&payload)?;
        if change == 4 {
            payload.push(b'\n');
        }
        publication.bytes = Bytes::new(payload);
        let altered = canonical::canonical_json(&serde_json::to_value(wire)?)?;

        assert!(HostSemanticModel::restore(definition.clone(), &altered, 1 << 20, 128).is_err());
        assert_eq!(model.capture().map_err(|error| error.reason)?, captured);
    }
    Ok(())
}

#[test]
fn deadline_read_is_pure_and_expiry_follows_all_deadline_instant_microsteps() -> TestResult {
    let definition = definition()?;
    let mut model =
        HostSemanticModel::new(definition.clone(), 1 << 20, 128).map_err(|error| error.reason)?;
    model
        .settle(position(1, 0, Phase::Reaction))
        .map_err(|error| error.reason)?;
    let checkpoint = model.evaluator.checkpoint().canonical_bytes()?;

    assert_eq!(
        model.evaluator.next_eventually_deadline(),
        Some(VirtualTime { ticks: 6 })
    );
    assert_eq!(model.evaluator.checkpoint().canonical_bytes()?, checkpoint);
    assert_eq!(model.next_position(), Some(position(7, 0, Phase::Reaction)));
    model
        .park(position(6, 0, Phase::BoundaryControl))
        .map_err(|error| error.reason)?;
    let saved = model.capture().map_err(|error| error.reason)?;
    let mut expired = HostSemanticModel::restore(definition, &saved, 1 << 20, 128)
        .map_err(|error| error.reason)?;

    let reply = crucible_device::BlockResponse::ok(7, vec![1, 2, 3]).encode()?;
    let mut input = delivery(&reply)?;
    input.evaluation = Some(position(6, 0, Phase::Reaction));
    input.publication = position(6, 20, Phase::Publication);
    input.delivery = position(6, 20, Phase::Delivery);
    model
        .consume(&input, &reply, position(6, 21, Phase::Reaction))
        .map_err(|error| error.reason)?;
    expired
        .settle(position(7, 0, Phase::Reaction))
        .map_err(|error| error.reason)?;

    let passed = model.take_publications();
    let failed = expired.take_publications();
    assert_eq!(passed.len(), 1);
    assert_eq!(failed.len(), 1);
    let passed: serde_json::Value = serde_json::from_slice(passed[0].bytes.as_slice())?;
    let failed: serde_json::Value = serde_json::from_slice(failed[0].bytes.as_slice())?;
    assert_eq!(passed["kind"], "Satisfied");
    assert_eq!(failed["kind"], "Violated");
    assert_eq!(failed["outcome_time_ps"], 6);
    Ok(())
}

fn terminal_definition() -> TestResultDefinition {
    let namespace = PropertyNamespace::new(BTreeMap::new(), false, true, BTreeSet::new())?;
    let properties = Properties::from_assertions_for_namespace(
        &namespace,
        vec![
            AssertionDef {
                id: AssertionId::from_name("already-satisfied"),
                message: "original early result".into(),
                property: Property::Sometimes {
                    predicate: Predicate::at(VirtualTime { ticks: 0 }),
                },
            },
            AssertionDef {
                id: AssertionId::from_name("terminal-safety"),
                message: "actual terminal evaluation".into(),
                property: Property::AfterQuiescence {
                    predicate: Predicate::at(VirtualTime { ticks: 0 }),
                },
            },
        ],
    )?;
    Ok(HostSemanticDefinition {
        version: 2,
        properties: Bytes::new(properties.to_compact_binary()),
        inputs: Vec::new(),
    })
}

// Typed admissions here are deliberate internal fixture construction, not a
// native EOF qualification or a public way to issue runtime authority.
fn terminal_admission(
    model: &HostSemanticModel,
) -> Result<crate::node_contract::OperationAdmission, Box<dyn std::error::Error>> {
    use crate::node_contract::*;
    let owner = OwnerIdentity {
        owner: Id::new("semantic-owner")?,
        incarnation: Id::new("original-semantic")?,
        generation: U64::new(1),
    };
    let activation = WorldActivation {
        authority: std::rc::Rc::new(()),
        nodes: std::rc::Rc::from([]),
        preparation: None,
        record: ActivationRecord {
            generation: U64::new(1),
            activation_id: Id::new("original-world")?,
            world_binding_hash: canonical::json_hash("fixture-world", &0)?,
            owners: vec![owner.clone()],
            boundary: position(0, 0, Phase::BoundaryControl),
        },
    };
    let node = Id::new("semantics")?;
    let operation = Id::new("original-terminal")?;
    let record = WorldTerminalRecord {
        version: 1,
        operation: operation.clone(),
        node: node.clone(),
        source: activation.record().into(),
        cut: model.position(),
        scheduler: Bytes::new(b"fixture complete scheduler".to_vec()),
        native: vec![NativeTerminalInventory {
            node: node.clone(),
            owners: vec![owner.clone()],
            boundary: model.position(),
            disposition: NativeTerminalDisposition::Unconditional,
            receipt: crate::node_scheduling::InputPayload {
                reference: canonical::content_ref(
                    b"fixture complete native inventory",
                    "text/plain",
                )?,
                bytes: b"fixture complete native inventory".to_vec(),
            },
        }],
    };
    let bytes = canonical::canonical_json(&serde_json::to_value(&record)?)?;
    Ok(OperationAdmission {
        token: OperationToken {
            authority: std::rc::Rc::new(()),
            operation,
            route: NodeRoute {
                node,
                owners: vec![owner],
            },
        },
        activation,
        inputs: None,
        request: OperationRequest::FinalizeAssertions {
            barrier: Box::new(record),
            receipt: canonical::content_ref(&bytes, "application/json")?,
        },
    })
}

#[test]
fn terminal_finalization_is_explicit_and_does_not_republish_original_results() -> TestResult {
    let mut model =
        HostSemanticModel::new(terminal_definition()?, 65_536, 32).map_err(|error| error.reason)?;
    model
        .settle(position(0, 0, Phase::Reaction))
        .map_err(|error| error.reason)?;
    let early = model.take_publications();
    assert_eq!(early.len(), 1);
    assert!(model.terminal_report().is_none());
    let before = model.capture().map_err(|error| error.reason)?;
    let reread = HostSemanticModel::restore(terminal_definition()?, &before, 65_536, 32)
        .map_err(|error| error.reason)?;
    assert!(reread.terminal_report().is_none());

    let admission = terminal_admission(&model)?;
    let report = model.finalize(&admission).map_err(|error| error.reason)?;
    let value: serde_json::Value = serde_json::from_slice(&report.bytes)?;
    assert_eq!(value["outcomes"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        value["newly_terminal"],
        serde_json::json!(["terminal-safety"])
    );
    assert_eq!(model.pending_count(), 0);
    let finalized = model.capture().map_err(|error| error.reason)?;

    assert_eq!(
        model.finalize(&admission).map_err(|error| error.reason)?,
        report
    );
    assert_eq!(model.capture().map_err(|error| error.reason)?, finalized);
    assert!(model.park(position(1, 0, Phase::BoundaryControl)).is_err());
    assert!(model.settle(position(1, 0, Phase::Reaction)).is_err());
    Ok(())
}

#[test]
fn terminal_cold_decode_preserves_original_report_marker_and_context() -> TestResult {
    let mut model =
        HostSemanticModel::new(terminal_definition()?, 65_536, 32).map_err(|error| error.reason)?;
    model
        .settle(position(0, 0, Phase::Reaction))
        .map_err(|error| error.reason)?;
    model.take_publications();
    let admission = terminal_admission(&model)?;
    let original = model.finalize(&admission).map_err(|error| error.reason)?;
    let bytes = model.capture().map_err(|error| error.reason)?;

    let mut restored = HostSemanticModel::restore(terminal_definition()?, &bytes, 65_536, 32)
        .map_err(|error| error.reason)?;
    assert_eq!(restored.terminal_report(), Some(&original));
    assert_eq!(
        restored
            .finalize(&admission)
            .map_err(|error| error.reason)?,
        original
    );
    assert_eq!(restored.capture().map_err(|error| error.reason)?, bytes);
    let mut changed = admission;
    if let crate::node_contract::OperationRequest::FinalizeAssertions { receipt, .. } =
        &mut changed.request
    {
        *receipt = canonical::content_ref(b"changed original context", "text/plain")?;
    }
    assert!(restored.finalize(&changed).is_err());
    assert_eq!(restored.capture().map_err(|error| error.reason)?, bytes);
    Ok(())
}

#[test]
fn terminal_refuses_pending_original_work_and_legacy_definition() -> TestResult {
    let mut pending =
        HostSemanticModel::new(terminal_definition()?, 65_536, 32).map_err(|error| error.reason)?;
    let admission = terminal_admission(&pending)?;
    let before = pending.capture().map_err(|error| error.reason)?;
    assert!(pending.finalize(&admission).is_err());
    assert_eq!(pending.capture().map_err(|error| error.reason)?, before);

    let mut legacy =
        HostSemanticModel::new(definition()?, 65_536, 32).map_err(|error| error.reason)?;
    let admission = terminal_admission(&legacy)?;
    assert!(legacy.finalize(&admission).is_err());
    Ok(())
}

#[test]
fn terminal_restore_cannot_omit_finalized_marker_or_original_emission_history() -> TestResult {
    let mut model =
        HostSemanticModel::new(terminal_definition()?, 65_536, 32).map_err(|error| error.reason)?;
    model
        .settle(position(0, 0, Phase::Reaction))
        .map_err(|error| error.reason)?;
    model.take_publications();
    let early = model.capture().map_err(|error| error.reason)?;
    let mut omitted: serde_json::Value = serde_json::from_slice(&early)?;
    omitted
        .as_object_mut()
        .ok_or("continuation object absent")?
        .remove("reported");
    let omitted = canonical::canonical_json(&omitted)?;
    assert!(HostSemanticModel::restore(terminal_definition()?, &omitted, 65_536, 32).is_err());

    model
        .finalize(&terminal_admission(&model)?)
        .map_err(|error| error.reason)?;
    let finalized = model.capture().map_err(|error| error.reason)?;
    let mut omitted: serde_json::Value = serde_json::from_slice(&finalized)?;
    omitted
        .as_object_mut()
        .ok_or("continuation object absent")?
        .remove("terminal");
    let omitted = canonical::canonical_json(&omitted)?;
    assert!(HostSemanticModel::restore(terminal_definition()?, &omitted, 65_536, 32).is_err());
    assert_eq!(model.capture().map_err(|error| error.reason)?, finalized);
    Ok(())
}
