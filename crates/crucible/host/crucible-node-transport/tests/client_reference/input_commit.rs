//! Actual source-owned input commitments through the original Unix transport.

use super::*;
use crucible_node_transport::conformance::{Expectation, ProbeStep};
use crucible_node_transport::input_commit::*;

#[path = "../conformance_reference/scenario.rs"]
#[allow(dead_code)]
mod scenario;

#[path = "../conformance_reference/lifecycle.rs"]
mod lifecycle;

fn connect(service: &fixture::NativeService, selected: bool) -> (Handshake, ReferenceController) {
    let bootstrap = &service.bootstrap;
    let (binding, _) = service.profile.bind(bootstrap.authority.clone()).unwrap();
    let mut features = vec![
        fixture::id("cnp.control-evidence/1"),
        fixture::id("cnp.core/1"),
    ];
    if selected {
        features.push(fixture::id(INPUT_COMMIT_FEATURE));
    }
    let mut token = [0; 32];
    token.copy_from_slice(bootstrap.admission_token.as_slice());
    let mut handshake = Handshake::new(
        TrustedInstallation {
            session_id: bootstrap.authority.session_id.clone(),
            incarnation_id: bootstrap.authority.incarnation_id.clone(),
            measured_implementation: service.profile.implementation.clone(),
            launch_receipt: bootstrap.admission_receipt.clone(),
            admission_token: token,
        },
        NegotiationPolicy {
            supported_features: features.clone(),
            required_features: features.clone(),
            provider_limits: bootstrap.limits,
            required_schemas: Vec::new(),
            required_guarantees: binding.compatibility.guarantees_ref,
            envelope_extension_features: if selected {
                BTreeMap::from([(
                    INPUT_COMMIT_FEATURE.into(),
                    fixture::id(INPUT_COMMIT_FEATURE),
                )])
            } else {
                BTreeMap::new()
            },
        },
    )
    .unwrap();
    let mut hello = request(service, Method::Hello, "input-commit-hello", json!({}));
    hello.session_id = Nullable(None);
    hello.incarnation_id = Nullable(None);
    hello.sequence = 1.into();
    hello.body = body(HelloRequest {
        versions: vec!["CNP/1".into()],
        session_id: bootstrap.authority.session_id.clone(),
        controller_nonce: Bytes::new(vec![9; 32]),
        required_features: features,
        optional_features: Vec::new(),
        limits: bootstrap.limits,
        admission_token: bootstrap.admission_token.clone(),
        resume_session: None,
        extensions: Extensions::new(),
    });
    let peer = ClientPeer {
        pid: service.process.id(),
        uid: rustix::process::geteuid().as_raw(),
        executable: crucible_node_transport::conformance::measure_executable(Path::new(env!(
            "CARGO_BIN_EXE_crucible-reference-provider"
        )))
        .unwrap(),
    };
    let session = ClientSession::negotiate(
        UnixStream::connect(service.socket()).unwrap(),
        &peer,
        &hello,
        fixture::id("input-commit-connection"),
        &mut handshake,
        &mut Installed(service),
        Rc::new(Supervisor::default()),
        Rc::new(Schemas),
        Duration::from_secs(3),
        1_048_576,
        64,
    )
    .unwrap();
    let custody = ClientCustody::new(
        256,
        ClientContent::new(16 * 1024 * 1024, 256, 16_384).unwrap(),
    )
    .unwrap();
    let controller = ReferenceController::new(
        service.profile.clone(),
        bootstrap.clone(),
        session,
        custody,
        Duration::from_secs(3),
    )
    .unwrap();
    (handshake, controller)
}

fn resolve(value: &Value, bindings: &BTreeMap<String, Value>) -> Value {
    match value {
        Value::Object(object) if object.len() == 1 && object.contains_key("$binding") => {
            bindings[object["$binding"].as_str().unwrap()].clone()
        }
        Value::Object(object) if object.len() == 1 && object.contains_key("$sequence") => {
            json!("2")
        }
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), resolve(value, bindings)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| resolve(value, bindings))
                .collect(),
        ),
        value => value.clone(),
    }
}

fn stage(
    service: &fixture::NativeService,
    controller: &mut ReferenceController,
) -> (Envelope, InputResult, Envelope) {
    let plan = lifecycle::native_window(service);
    let mut bindings = service.private_bindings.clone();
    bindings.insert(
        "incarnation".into(),
        json!(service.bootstrap.authority.incarnation_id),
    );
    let mut input = None;
    for step in plan.steps.iter().skip(1) {
        match step {
            ProbeStep::CanonicalContent {
                value,
                reference_binding,
                bytes_binding,
                ..
            } => {
                let bytes = canonical::canonical_json(&resolve(value, &bindings)).unwrap();
                bindings.insert(
                    reference_binding.to_string(),
                    json!(canonical::content_ref(&bytes, "application/json").unwrap()),
                );
                bindings.insert(bytes_binding.to_string(), json!(Bytes::new(bytes)));
            }
            ProbeStep::Exchange {
                id,
                request,
                expected,
                captures,
                ..
            } => {
                let request: Envelope =
                    serde_json::from_value(resolve(request, &bindings)).unwrap();
                if id.as_str() == "commit-original-input-cut" {
                    continue;
                }
                if id.as_str() == "execute-native-window" {
                    let (input, result) = input.unwrap();
                    return (input, result, request);
                }
                if request.method == Method::BlobBegin {
                    let reference: ContentRef =
                        serde_json::from_value(request.body["content"].clone()).unwrap();
                    let bytes = plan
                        .steps
                        .iter()
                        .find_map(|step| {
                            let ProbeStep::Exchange { request: chunk, .. } = step else {
                                return None;
                            };
                            if chunk["method"] != "blob_chunk"
                                || chunk["body"]["transfer_id"] != request.body["transfer_id"]
                            {
                                return None;
                            }
                            Some(
                                serde_json::from_value::<Bytes>(resolve(
                                    &chunk["body"]["bytes"],
                                    &bindings,
                                ))
                                .unwrap(),
                            )
                        })
                        .unwrap();
                    controller.upload(&reference, bytes.as_slice()).unwrap();
                    continue;
                }
                if matches!(request.method, Method::BlobChunk | Method::BlobFinish) {
                    continue;
                }
                let response = controller
                    .call(
                        request.request_id.0.clone().unwrap(),
                        request.operation_id.0.clone(),
                        request.method,
                        request.execution_owner_id.0.is_some(),
                        request.body.clone(),
                    )
                    .unwrap_or_else(|error| panic!("original setup {id}: {error}"));
                if let Some(MethodResult::Realize(realized)) = &response.result {
                    let receipt: ControlReceipt =
                        controller.record(&realized.closed_gate_receipt).unwrap();
                    let gate: ClosedGateRecord = controller.record(&receipt.record_ref).unwrap();
                    let physical = canonical::parse_json(
                        controller.content(&gate.physical_status_ref).unwrap(),
                        1_048_576,
                    )
                    .unwrap();
                    let pid: U64 = serde_json::from_value(physical["child_pid"].clone()).unwrap();
                    let status =
                        std::fs::read_to_string(format!("/proc/{}/status", pid.get())).unwrap();
                    assert!(
                        status
                            .lines()
                            .any(|line| line == format!("PPid:\t{}", service.process.id()))
                    );
                    assert_eq!(
                        std::fs::read_link(format!("/proc/{}/exe", pid.get())).unwrap(),
                        Path::new(env!("CARGO_BIN_EXE_crucible-reference-device"))
                    );
                    assert_eq!(physical["application_status"], "parked");
                }
                let value = json!({"body":response.shape});
                match expected {
                    Expectation::Completed => {
                        assert_eq!(value["body"]["status"], "completed", "{id}: {value}")
                    }
                    Expectation::Error { code, .. } => {
                        assert_eq!(value["body"]["error"]["code"], json!(code), "{id}: {value}")
                    }
                    _ => panic!("unsupported original fixture step"),
                }
                for (key, pointer) in captures {
                    bindings.insert(key.to_string(), value.pointer(pointer).unwrap().clone());
                }
                if let Some(MethodResult::Input(result)) = response.result {
                    input = Some((request, result));
                }
            }
            _ => panic!("unexpected pre-execution fixture step"),
        }
    }
    panic!("original native window missing")
}

fn intent(
    service: &fixture::NativeService,
    controller: &mut ReferenceController,
    input: &Envelope,
    staged: &InputResult,
) -> InputCommitIntentV1 {
    let request: InputRequest = serde_json::from_value(json!(input.body)).unwrap();
    let events = &request.events;
    let deliveries = events
        .iter()
        .map(|event| CommittedDeliveryV1 {
            connection_id: Nullable(None),
            connection_policy_ref: Nullable(None),
            external_root: Nullable(Some(event.source.clone())),
            provenance_ref: event.provenance_ref.clone(),
            publication_id: event.id.clone(),
            producer: event.source.node_id.clone(),
            consumer: event.destination.node_id.clone(),
            producer_endpoint: event.source.clone(),
            consumer_endpoint: event.destination.clone(),
            source_sequence: U64::new(77),
            native_sequence: event.source_sequence,
            evaluation: Nullable(None),
            causal_parents: Vec::new(),
            publication: event.publication_position,
            delivery: event.position,
            payload: event.payload.clone(),
        })
        .collect::<Vec<_>>();
    let bytes = canonical::canonical_json(&json!(deliveries)).unwrap();
    let inventory =
        canonical::content_ref(&bytes, "application/vnd.crucible.input-inventory+json").unwrap();
    controller.upload(&inventory, &bytes).unwrap();
    InputCommitIntentV1 {
        schema_version: 1,
        session_id: service.bootstrap.authority.session_id.clone(),
        incarnation_id: service.bootstrap.authority.incarnation_id.clone(),
        node_id: service.bootstrap.node_id.clone(),
        execution_owner_id: service.bootstrap.owner_id.clone(),
        owner_generation: service.bootstrap.authority.owner_generation,
        activation_id: service.bootstrap.activation_id.clone(),
        world_generation: service.bootstrap.world_generation,
        world_binding_hash: service.bootstrap.world_binding_hash.clone(),
        stage_operation_id: fixture::id("original-host-stage"),
        input_request_id: input.request_id.0.clone().unwrap(),
        batch_id: request.batch_id,
        batch_hash: request.batch_hash,
        staging_receipt: staged.custody_receipt.clone(),
        delivery_inventory: inventory,
        cutoff: Position::new(1.into(), 0.into(), Phase::BoundaryControl),
    }
}

fn commit(
    controller: &mut ReferenceController,
    input: &Envelope,
    intent: &InputCommitIntentV1,
    request: &str,
) -> ResponseBody {
    controller
        .call_with_extensions(
            fixture::id(request),
            None,
            Method::Input,
            true,
            input.body.clone(),
            Extensions::from([(INPUT_COMMIT_FEATURE.into(), json!(intent))]),
        )
        .unwrap()
}

fn begin(
    controller: &mut ReferenceController,
    original: &Envelope,
    identity: &str,
) -> ResponseBody {
    controller
        .call(
            fixture::id(identity),
            Some(fixture::id(&format!("operation-{identity}"))),
            Method::Begin,
            true,
            original.body.clone(),
        )
        .unwrap()
}

fn verify_native_result(
    controller: &ReferenceController,
    executed: &ResponseBody,
    service: &fixture::NativeService,
    bytes: u64,
    checksum: u64,
) {
    let Some(MethodResult::QuantumBegin(result)) = &executed.result else {
        panic!("actual native quantum did not complete");
    };
    let measurement = canonical::parse_json(
        controller
            .content(&result.physical_measurement_ref)
            .unwrap(),
        1_048_576,
    )
    .unwrap();
    let native: crucible_node_transport::reference_device::DeviceReceipt =
        serde_json::from_value(measurement).unwrap();
    assert_eq!(native.grant.owner_id, service.bootstrap.owner_id);
    assert_eq!(
        native.grant.incarnation_id,
        service.bootstrap.authority.incarnation_id
    );
    assert_eq!(
        native.grant.generation,
        service.bootstrap.authority.owner_generation
    );
    assert_eq!(native.grant.input_batch_id, fixture::id("input-batch/1"));
    assert_eq!(native.output.bytes_processed.get(), bytes);
    assert_eq!(native.output.checksum.get(), checksum);
    assert!(native.application_parked);
}

#[test]
fn original_native_input_ack_stays_closed_until_source_commits_the_exact_empty_cut() {
    let service = fixture::NativeService::launch_public_linked(
        Path::new(env!("CARGO_BIN_EXE_crucible-reference-provider")),
        Path::new(env!("CARGO_BIN_EXE_crucible-reference-device")),
        32,
        true,
    );
    let (_original_handshake, mut controller) = connect(&service, true);
    let (input, staged, window) = stage(&service, &mut controller);
    assert_eq!(
        begin(&mut controller, &window, "withheld-after-stage")
            .shape
            .operation_state(),
        OperationState::NotStarted
    );
    let intent = intent(&service, &mut controller, &input, &staged);
    let mut foreign = intent.clone();
    foreign.incarnation_id = fixture::id("foreign-incarnation");
    assert!(
        commit(&mut controller, &input, &foreign, "foreign-commit")
            .result
            .is_none()
    );
    assert!(
        begin(&mut controller, &window, "withheld-after-foreign")
            .result
            .is_none()
    );
    let accepted = commit(&mut controller, &input, &intent, "original-commit");
    let Some(MethodResult::Input(result)) = accepted.result else {
        panic!("actual source commitment refused");
    };
    let receipt: ControlReceipt = controller.record(&result.custody_receipt).unwrap();
    let custody: InputCustodyRecord = controller.record(&receipt.record_ref).unwrap();
    assert_eq!(custody.execution_owner_id, service.bootstrap.owner_id);
    assert_eq!(
        custody.owner_generation,
        service.bootstrap.authority.owner_generation
    );
    assert_eq!(custody.evidence_refs.len(), 1);
    assert_eq!(custody.pending_inventory.hash, result.inventory_hash);
    let record: InputCommitRecordV1 = controller.record(&custody.evidence_refs[0]).unwrap();
    assert_eq!(record.intent, intent);
    assert_eq!(record.request_id, fixture::id("original-commit"));
    assert!(controller.content(&record.staged_bytes).unwrap().is_empty());
    assert_ne!(result.custody_receipt, staged.custody_receipt);
    let repeated = commit(&mut controller, &input, &intent, "original-commit");
    assert_eq!(json!(repeated.shape), json!(accepted.shape));
    let executed = begin(&mut controller, &window, "run-committed");
    verify_native_result(&controller, &executed, &service, 0, 0);
    controller.fence();
}

#[test]
fn source_commit_rejects_a_changed_native_delivery_population_and_retains_original_bytes() {
    let service = fixture::NativeService::launch_public_linked(
        Path::new(env!("CARGO_BIN_EXE_crucible-reference-provider")),
        Path::new(env!("CARGO_BIN_EXE_crucible-reference-device")),
        32,
        false,
    );
    let (_original_handshake, mut controller) = connect(&service, true);
    let (input, staged, window) = stage(&service, &mut controller);
    let intent = intent(&service, &mut controller, &input, &staged);
    let mut foreign = intent.clone();
    let inventory =
        canonical::content_ref(b"[]", "application/vnd.crucible.input-inventory+json").unwrap();
    controller.upload(&inventory, b"[]").unwrap();
    foreign.delivery_inventory = inventory;
    assert!(
        commit(&mut controller, &input, &foreign, "truncated-input-commit")
            .result
            .is_none()
    );
    assert!(
        begin(&mut controller, &window, "withheld-after-truncation")
            .result
            .is_none()
    );
    let accepted = commit(&mut controller, &input, &intent, "complete-input-commit");
    let Some(MethodResult::Input(result)) = accepted.result else {
        panic!("original complete input refused");
    };
    let receipt: ControlReceipt = controller.record(&result.custody_receipt).unwrap();
    let custody: InputCustodyRecord = controller.record(&receipt.record_ref).unwrap();
    assert_eq!(custody.execution_owner_id, service.bootstrap.owner_id);
    assert_eq!(
        custody.owner_generation,
        service.bootstrap.authority.owner_generation
    );
    assert_eq!(custody.evidence_refs.len(), 1);
    assert_eq!(custody.pending_inventory.hash, result.inventory_hash);
    let record: InputCommitRecordV1 = controller.record(&custody.evidence_refs[0]).unwrap();
    assert_eq!(controller.content(&record.staged_bytes).unwrap(), &[1, 2]);
    let executed = begin(&mut controller, &window, "run-complete-input");
    verify_native_result(&controller, &executed, &service, 2, 259);
    controller.fence();
}

#[test]
fn unnegotiated_source_commit_cannot_replace_an_original_staging_ack() {
    let service = fixture::NativeService::launch_public_linked(
        Path::new(env!("CARGO_BIN_EXE_crucible-reference-provider")),
        Path::new(env!("CARGO_BIN_EXE_crucible-reference-device")),
        32,
        true,
    );
    let (_original_handshake, mut controller) = connect(&service, false);
    let (input, staged, window) = stage(&service, &mut controller);
    assert!(
        begin(&mut controller, &window, "unnegotiated-withheld")
            .result
            .is_none()
    );
    let intent = intent(&service, &mut controller, &input, &staged);
    assert!(
        controller
            .call_with_extensions(
                fixture::id("unnegotiated-commit"),
                None,
                Method::Input,
                true,
                input.body,
                Extensions::from([(INPUT_COMMIT_FEATURE.into(), json!(intent))])
            )
            .is_err()
    );
    controller.fence();
}
