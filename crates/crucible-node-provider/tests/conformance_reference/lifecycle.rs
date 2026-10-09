//! Independent full native-window oracles using only public CNP messages.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::*;
use crucible_node_provider::conformance::{
    CheckKind, Expectation, IdentityKind, ProbePlan, ProbeStep,
};
use serde_json::{Value, json};

use super::fixture::{NativeService, id};
use super::scenario::{assertion, envelope, error, exchange, hello};

pub(super) fn native_window(service: &NativeService) -> ProbePlan {
    let bootstrap = &service.bootstrap;
    let (binding, owner) = service.profile.bind(bootstrap.authority.clone()).unwrap();
    let owner_hash = owner.identity().unwrap();
    let payload = canonical::content_ref(&[1, 2], "application/octet-stream").unwrap();
    let publication = Position::new(0.into(), 0.into(), Phase::Publication);
    let delivery = Position::new(0.into(), 1.into(), Phase::Delivery);
    let batch = InputBatch {
        schema_version: 1,
        execution_owner_id: bootstrap.owner_id.clone(),
        input_epoch: bootstrap.authority.input_epoch.clone(),
        batch_id: id("input-batch/1"),
        batch_sequence: 1.into(),
        events: vec![Event {
            schema_version: 1,
            id: id("fixture-input/1"),
            source: Endpoint {
                node_id: id("fixture-input"),
                port_id: id("data"),
                lane_id: id("output"),
            },
            destination: Endpoint {
                node_id: bootstrap.node_id.clone(),
                port_id: id("data"),
                lane_id: id("input"),
            },
            position: delivery,
            stage: EventStage::Delivery,
            publication_position: publication,
            delivery_position: Some(delivery),
            source_sequence: 1.into(),
            causal_parent_ids: Vec::new(),
            payload: payload.clone(),
            provenance_ref: bootstrap.admission_receipt.clone(),
            extensions: Extensions::new(),
        }],
        extensions: Extensions::new(),
    };
    batch.validate().unwrap();
    let batch_value = serde_json::to_value(&batch).unwrap();
    let batch_bytes = canonical::canonical_json(&batch_value).unwrap();
    let batch_ref = canonical::content_ref(&batch_bytes, "application/json").unwrap();
    let mut steps = vec![hello(service)];
    steps.push(exchange(
        "realize-withheld",
        CheckKind::PausedActivation,
        envelope(
            service,
            "realize",
            "realize",
            json!({
                "realization_id": bootstrap.authority.realization_id,
                "configuration": service.profile.configuration_ref,
                "requested_node_ids": [bootstrap.node_id],
                "resource_limits": bootstrap.resource_limits,
                "extensions": {}
            }),
        ),
        Expectation::Completed,
        vec![
            assertion(
                "/body/result/prepared_token",
                json!(bootstrap.prepared_token),
            ),
            assertion(
                "/body/result/realization_manifest/descriptors",
                json!([service.profile.descriptor]),
            ),
        ],
        BTreeMap::new(),
    ));
    steps.push(exchange(
        "admit-original-binding",
        CheckKind::DescriptorBinding,
        envelope(
            service,
            "admit",
            "admit",
            json!({
                "bindings": [binding],
                "world_binding_hash": bootstrap.world_binding_hash,
                "admission_receipt": bootstrap.admission_receipt,
                "extensions": {}
            }),
        ),
        Expectation::Completed,
        vec![assertion(
            "/body/result/accepted_binding_hashes",
            json!([binding.identity().unwrap()]),
        )],
        BTreeMap::new(),
    ));
    let arguments = json!({
        "grant_id":"window/0","participant_ids":[bootstrap.node_id],"realization_id":bootstrap.authority.realization_id,
        "activation_id":bootstrap.activation_id,"world_generation":bootstrap.world_generation,"owner_generation":bootstrap.authority.owner_generation,
        "input_epoch":bootstrap.authority.input_epoch,"mode":"quantized","ordering_profile":"superdense-v1","quantum_index":"0",
        "from_ps":"0","until_ps":"1000","input_batch":batch_ref,"input_watermark":"1",
        "policy_hash":service.profile.operating_contract.policy_ref.hash,"wall_budget_ns":bootstrap.host_budget_ns
    });
    let window_begin = begin(
        service,
        &owner_hash,
        "quantum_begin",
        "native-window/0",
        "begin-window",
        arguments,
    );
    let mut withheld = window_begin.clone();
    withheld["request_id"] = json!("withheld-window");
    withheld["operation_id"] = json!("withheld-window/0");
    steps.push(exchange(
        "no-work-before-world-activation",
        CheckKind::ActivationGate,
        withheld.clone(),
        error("INVALID_STATE"),
        Vec::new(),
        capture("original-withheld-result", "/body"),
    ));
    steps.push(exchange(
        "stage-owner-readiness",
        CheckKind::PausedActivation,
        envelope(
            service,
            "activate",
            "stage",
            json!({
                "admission_id": bootstrap.admission_id,
                "activation_id": bootstrap.activation_id,
                "world_generation": bootstrap.world_generation,
                "prepared_token": bootstrap.prepared_token,
                "world_binding_hash": bootstrap.world_binding_hash,
                "gate_id": bootstrap.gate_id,
                "extensions": {}
            }),
        ),
        Expectation::Completed,
        vec![assertion("/body/result/staged", json!(true))],
        capture("ready-receipt", "/body/result/activation_receipt"),
    ));
    steps.push(ProbeStep::CanonicalContent {
        id: id("activation-manifest"),
        value: json!({
            "schema_version": 1,
            "transaction_id": bootstrap.transaction_id,
            "activation_id": bootstrap.activation_id,
            "world_generation": bootstrap.world_generation,
            "gate_id": bootstrap.gate_id,
            "world_binding_hash": bootstrap.world_binding_hash,
            "owners": [{
                "owner_id": bootstrap.owner_id,
                "incarnation_id": bootstrap.authority.incarnation_id,
                "owner_generation": bootstrap.authority.owner_generation,
                "prepared_token": bootstrap.prepared_token,
                "binding_hashes": [binding.identity().unwrap()],
                "ready_receipt": bound("ready-receipt"),
                "extensions": {}
            }],
            "coordinator_state_ref": service.profile.descriptor.initialization_ref,
            "extensions": {}
        }),
        reference_binding: id("activation-ref"),
        bytes_binding: id("activation-bytes"),
    });
    upload(
        &mut steps,
        service,
        "activation",
        bound("activation-ref"),
        bound("activation-bytes"),
    );
    steps.push(exchange(
        "publish-world-activation",
        CheckKind::WorldActivation,
        envelope(
            service,
            "world_activate",
            "world-activate",
            json!({
                "transaction_id": bootstrap.transaction_id,
                "activation_id": bootstrap.activation_id,
                "world_generation": bootstrap.world_generation,
                "prepared_token": bootstrap.prepared_token,
                "world_binding_hash": bootstrap.world_binding_hash,
                "gate_id": bootstrap.gate_id,
                "activation_manifest": bound("activation-ref"),
                "extensions": {}
            }),
        ),
        Expectation::Completed,
        vec![assertion(
            "/body/result/armed_owner_ids",
            json!([bootstrap.owner_id]),
        )],
        BTreeMap::new(),
    ));
    steps.push(exchange(
        "original-preactivation-refusal-survives-activation",
        CheckKind::Duplicate,
        withheld,
        error("INVALID_STATE"),
        vec![assertion("/body", bound("original-withheld-result"))],
        BTreeMap::new(),
    ));
    let capture_request = begin(
        service,
        &owner_hash,
        "capture",
        "unsupported-capture",
        "capture",
        json!({
            "capture_id":"capture/1","participant_ids":[bootstrap.node_id],"cut_id":"initial-cut",
            "cut":Position::new(0.into(),0.into(),Phase::BoundaryControl),"event_ordinal":"0",
            "ordering_profile":"superdense-v1","preservation_contract":"exact-modeled-state"
        }),
    );
    steps.push(exchange(
        "truthful-capture-refusal",
        CheckKind::Capture,
        capture_request,
        error("UNSUPPORTED_FEATURE"),
        Vec::new(),
        BTreeMap::new(),
    ));
    upload(
        &mut steps,
        service,
        "input-payload",
        json!(payload),
        json!(Bytes::new(vec![1, 2])),
    );
    upload(
        &mut steps,
        service,
        "input-batch",
        json!(batch_ref),
        json!(Bytes::new(batch_bytes)),
    );
    steps.push(exchange(
        "retain-actual-input",
        CheckKind::Input,
        owned(
            service,
            "input",
            "input",
            json!({
                "binding_hash": owner_hash,
                "owner_generation": bootstrap.authority.owner_generation,
                "batch_id": batch.batch_id,
                "batch_sequence": batch.batch_sequence,
                "input_epoch": batch.input_epoch,
                "events": batch.events,
                "batch_hash": batch.identity().unwrap(),
                "extensions": {}
            }),
        ),
        Expectation::Completed,
        vec![
            assertion(
                "/body/result/accepted_event_ids",
                json!(["fixture-input/1"]),
            ),
            assertion("/body/result/input_watermark", json!("1")),
        ],
        BTreeMap::new(),
    ));
    steps.push(exchange(
        "execute-native-window",
        CheckKind::Grant,
        window_begin,
        Expectation::Completed,
        vec![
            assertion("/body/result/grant_id", json!("window/0")),
            assertion("/body/result/budget_outcome", json!("within_budget")),
        ],
        BTreeMap::from([
            ("stop-ref".into(), "/body/result/stop_receipt".into()),
            (
                "staged-batch-ref".into(),
                "/body/result/observation_batch".into(),
            ),
            (
                "pending-ref".into(),
                "/body/result/pending_inventory".into(),
            ),
            (
                "measurement-ref".into(),
                "/body/result/physical_measurement_ref".into(),
            ),
        ]),
    ));
    let shutdown_arguments =
        json!({"participant_ids":[bootstrap.node_id],"reason":"test-complete"});
    let capacity_probe = begin(
        service,
        &owner_hash,
        "shutdown",
        "capacity-probe",
        "capacity-probe",
        shutdown_arguments.clone(),
    );
    steps.push(exchange(
        "bounded-native-operation-credit",
        CheckKind::Resources,
        capacity_probe.clone(),
        error("RESOURCE_EXHAUSTED"),
        Vec::new(),
        capture("original-capacity-refusal", "/body"),
    ));
    steps.push(exchange(
        "observe-original-native-output",
        CheckKind::Publication,
        owned(
            service,
            "observe",
            "observe",
            json!({
                "binding_hash": owner_hash,
                "owner_generation": bootstrap.authority.owner_generation,
                "after_observation_sequence": "0",
                "maximum_items": "4",
                "extensions": {}
            }),
        ),
        Expectation::Completed,
        vec![assertion(
            "/body/result/observations/0/visibility",
            json!("staged"),
        )],
        BTreeMap::from([
            (
                "payload-ref".into(),
                "/body/result/observations/0/events/0/payload".into(),
            ),
            ("native-batch".into(), "/body/result/observations/0".into()),
        ]),
    ));
    for (name, reference) in [
        ("payload", "payload-ref"),
        ("measurement", "measurement-ref"),
        ("pending", "pending-ref"),
        ("staged-batch", "staged-batch-ref"),
        ("stop", "stop-ref"),
    ] {
        receive(&mut steps, name, reference);
    }
    steps.push(ProbeStep::InspectContent {
        id: id("actual-checksum-oracle"),
        reference: bound("received-payload-ref"),
        bytes: bound("received-payload-bytes"),
        assertions: vec![
            assertion("/bytes_processed", json!("2")),
            assertion("/checksum", json!("259")),
        ],
        captures: BTreeMap::new(),
    });
    steps.push(ProbeStep::Identity {
        id: id("original-batch-identity"),
        kind: IdentityKind::ObservationBatch,
        value: bound("native-batch"),
        identity_binding: id("native-batch-hash"),
    });
    steps.push(exchange(
        "commit-fixed-publication-boundary",
        CheckKind::Publication,
        owned(
            service,
            "quantum_close",
            "close",
            json!({
                "grant_id": "window/0",
                "activation_id": bootstrap.activation_id,
                "world_generation": bootstrap.world_generation,
                "owner_generation": bootstrap.authority.owner_generation,
                "input_epoch": bootstrap.authority.input_epoch,
                "quantum_index": "0",
                "participant_ids": [bootstrap.node_id],
                "cut": Position::new(1000.into(), 0.into(), Phase::BoundaryControl),
                "policy_hash": service.profile.operating_contract.policy_ref.hash,
                "observation_batch_hash": bound("native-batch-hash"),
                "input_watermark": "1",
                "deadline_disposition": "within_budget",
                "extensions": {}
            }),
        ),
        Expectation::Completed,
        vec![assertion(
            "/body/result/cut",
            json!(Position::new(1000.into(), 0.into(), Phase::BoundaryControl)),
        )],
        capture("committed-batch-ref", "/body/result/committed_batch"),
    ));
    steps.push(exchange(
        "deliver-committed-batch",
        CheckKind::Publication,
        owned(
            service,
            "observe",
            "observe-committed",
            json!({
                "binding_hash": owner_hash,
                "owner_generation": bootstrap.authority.owner_generation,
                "after_observation_sequence": "1",
                "maximum_items": "4",
                "extensions": {}
            }),
        ),
        Expectation::Completed,
        Vec::new(),
        BTreeMap::new(),
    ));
    receive(&mut steps, "committed-batch", "committed-batch-ref");
    steps.push(ProbeStep::InspectContent {
        id: id("committed-publication-oracle"),
        reference: bound("received-committed-batch-ref"),
        bytes: bound("received-committed-batch-bytes"),
        assertions: vec![
            assertion("/visibility", json!("committed")),
            assertion(
                "/events/0/position",
                json!(Position::new(1000.into(), 0.into(), Phase::Publication)),
            ),
        ],
        captures: BTreeMap::new(),
    });
    steps.push(ProbeStep::CanonicalContent {
        id: id("actual-publication-consumption"),
        value: json!({
            "schema": "reference-device/publication-consumption-v1",
            "session_id": bootstrap.authority.session_id,
            "incarnation_id": bootstrap.authority.incarnation_id,
            "operation_id": "native-window/0",
            "grant_id": "window/0",
            "world_binding_hash": bootstrap.world_binding_hash,
            "observation_batch_hash": bound("native-batch-hash"),
            "stop_receipt": bound("stop-ref"),
            "publication": Position::new(1000.into(), 0.into(), Phase::Publication),
            "extensions": {}
        }),
        reference_binding: id("consumption-ref"),
        bytes_binding: id("consumption-bytes"),
    });
    upload(
        &mut steps,
        service,
        "consumption",
        bound("consumption-ref"),
        bound("consumption-bytes"),
    );
    steps.push(exchange(
        "acknowledge-original-publication",
        CheckKind::Consumption,
        envelope(
            service,
            "retire",
            "consume",
            json!({
                "request_ids": ["begin-window"],
                "operation_ids": ["native-window/0"],
                "disposition": "consumed",
                "custody_receipt": bound("consumption-ref"),
                "extensions": {}
            }),
        ),
        Expectation::Completed,
        vec![assertion(
            "/body/result/retired_operation_ids",
            json!(["native-window/0"]),
        )],
        BTreeMap::new(),
    ));
    steps.push(exchange(
        "original-resource-refusal-survives-credit-release",
        CheckKind::Duplicate,
        capacity_probe,
        error("RESOURCE_EXHAUSTED"),
        vec![assertion("/body", bound("original-capacity-refusal"))],
        BTreeMap::new(),
    ));
    steps.push(exchange(
        "reap-actual-child",
        CheckKind::Release,
        begin(
            service,
            &owner_hash,
            "shutdown",
            "shutdown",
            "shutdown",
            shutdown_arguments,
        ),
        Expectation::Completed,
        vec![
            assertion("/body/result/stopped", json!(true)),
            assertion("/body/result/reaped", json!(true)),
        ],
        BTreeMap::new(),
    ));
    steps.push(exchange(
        "release-native-owner",
        CheckKind::Release,
        envelope(
            service,
            "release",
            "release",
            json!({"realization_id":bootstrap.authority.realization_id,"extensions":{}}),
        ),
        Expectation::Completed,
        vec![assertion("/body/result/released", json!(true))],
        BTreeMap::new(),
    ));
    ProbePlan {
        schema_version: 1,
        fixture: id("source-built-reference-window/1"),
        required_checks: BTreeSet::from([
            CheckKind::Hello,
            CheckKind::DescriptorBinding,
            CheckKind::PausedActivation,
            CheckKind::ActivationGate,
            CheckKind::WorldActivation,
            CheckKind::ContentTransfer,
            CheckKind::Input,
            CheckKind::Capture,
            CheckKind::Grant,
            CheckKind::Resources,
            CheckKind::Publication,
            CheckKind::Consumption,
            CheckKind::Release,
            CheckKind::Duplicate,
        ]),
        steps,
    }
}

fn bound(name: &str) -> Value {
    json!({"$binding":name})
}

fn capture(name: &str, pointer: &str) -> BTreeMap<String, String> {
    BTreeMap::from([(name.into(), pointer.into())])
}

fn owned(service: &NativeService, method: &str, request: &str, body: Value) -> Value {
    let mut value = envelope(service, method, request, body);
    value["execution_owner_id"] = json!(service.bootstrap.owner_id);
    value
}

fn begin(
    service: &NativeService,
    owner: &HashRef,
    kind: &str,
    operation: &str,
    request: &str,
    arguments: Value,
) -> Value {
    let mut value = owned(
        service,
        "begin",
        request,
        json!({"kind":kind,"binding_hash":owner,
        "owner_generation":service.bootstrap.authority.owner_generation,"activation_id":service.bootstrap.activation_id,
        "world_generation":service.bootstrap.world_generation,"arguments":arguments,"extensions":{}}),
    );
    value["operation_id"] = json!(operation);
    value
}

fn upload(
    steps: &mut Vec<ProbeStep>,
    service: &NativeService,
    name: &str,
    reference: Value,
    bytes: Value,
) {
    for (suffix, method, body) in [
        (
            "begin",
            "blob_begin",
            json!({"transfer_id":name,"content":reference,"extensions":{}}),
        ),
        (
            "chunk",
            "blob_chunk",
            json!({"transfer_id":name,"offset":"0","bytes":bytes,"extensions":{}}),
        ),
        (
            "finish",
            "blob_finish",
            json!({"transfer_id":name,"extensions":{}}),
        ),
    ] {
        let request = format!("{name}/{suffix}");
        steps.push(exchange(
            &request,
            CheckKind::ContentTransfer,
            envelope(service, method, &request, body),
            Expectation::Completed,
            Vec::new(),
            BTreeMap::new(),
        ));
    }
}

fn receive(steps: &mut Vec<ProbeStep>, name: &str, reference: &str) {
    steps.push(ProbeStep::ReceiveBlob {
        id: id(&format!("receive-{name}")),
        reference: bound(reference),
        maximum_chunks: 16,
        reference_binding: id(&format!("received-{name}-ref")),
        bytes_binding: id(&format!("received-{name}-bytes")),
    });
}
