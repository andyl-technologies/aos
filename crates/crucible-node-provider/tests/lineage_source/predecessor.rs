//! Actual second public window preserves first-window commit and semantic ACK custody.

use super::*;
use crucible_node_contract::*;
use crucible_node_provider::{bodies::MethodResult, client::*, envelope::Method};
use serde_json::{Value, json};

#[test]
fn cumulative_lineage_borrows_actual_preceding_public_ack_with_ordered_zero_byte_entry() {
    let provider = Path::new(env!("CARGO_BIN_EXE_crucible-reference-lineage-provider"));
    let device = Path::new(env!("CARGO_BIN_EXE_crucible-reference-lineage-device"));
    let service = fixture::NativeService::launch(provider, device, false);
    let (_handshake, mut controller) = client::connect(&service);
    let mut plan = lifecycle::native_window(&service);
    let reap = plan.steps.iter().position(|step| matches!(step,
        crucible_node_provider::conformance::ProbeStep::Exchange { id, .. } if id.as_str() == "reap-actual-child"
    )).unwrap();
    plan.steps.truncate(reap);
    let first = sdk_plan::execute(&mut controller, &plan, service.private_bindings.clone());
    let first_consumption: ContentRef =
        serde_json::from_value(first["consumption-ref"].clone()).unwrap();

    let realize_id = fixture::id("realize");
    let first_input = fixture::id("input");
    let first_begin = fixture::id("begin-window");
    let original = controller
        .original_lineage_window(LineageWindowRequests {
            realization: &realize_id,
            input: &first_input,
            begin: &first_begin,
        })
        .unwrap();
    let prior_native = original.native_receipt().clone();
    let template = original.input_batch().events[0].clone();
    let prior_native_pid = original.native_pid();
    drop(original);

    let empty = canonical::content_ref(&[], "application/octet-stream").unwrap();
    controller.upload(&empty, &[]).unwrap();
    let publication = Position::new(1000.into(), 0.into(), Phase::Publication);
    let delivery = Position::new(1000.into(), 1.into(), Phase::Delivery);
    let events = (0..3)
        .map(|index| {
            let mut event = template.clone();
            event.id = fixture::id(&format!("fixture-input/{}", index + 2));
            event.source_sequence = U64::new(index + 2);
            event.position = delivery;
            event.publication_position = publication;
            event.delivery_position = Some(delivery);
            if index == 1 {
                event.payload = empty.clone();
            }
            event
        })
        .collect();
    let batch = InputBatch {
        schema_version: 1,
        execution_owner_id: service.bootstrap.owner_id.clone(),
        input_epoch: service.bootstrap.authority.input_epoch.clone(),
        batch_id: fixture::id("input-batch/2"),
        batch_sequence: 2.into(),
        events,
        extensions: Extensions::new(),
    };
    batch.validate().unwrap();
    let bytes = canonical::canonical_json(&json!(batch)).unwrap();
    let batch_ref = canonical::content_ref(&bytes, "application/json").unwrap();
    controller.upload(&batch_ref, &bytes).unwrap();
    let (_, owner) = service
        .profile
        .bind(service.bootstrap.authority.clone())
        .unwrap();
    call(
        &mut controller,
        "input/2",
        None,
        Method::Input,
        true,
        json!({
            "binding_hash":owner.identity().unwrap(), "owner_generation":service.bootstrap.authority.owner_generation,
            "batch_id":batch.batch_id,"batch_sequence":batch.batch_sequence,
            "input_epoch":batch.input_epoch,"events":batch.events,"batch_hash":batch.identity().unwrap(),"extensions":{}
        }),
    );
    let arguments = json!({
        "grant_id":"window/1","participant_ids":[service.bootstrap.node_id],
        "realization_id":service.bootstrap.authority.realization_id,"activation_id":service.bootstrap.activation_id,
        "world_generation":service.bootstrap.world_generation,"owner_generation":service.bootstrap.authority.owner_generation,
        "input_epoch":batch.input_epoch,"mode":"quantized","ordering_profile":"superdense-v1","quantum_index":"1",
        "from_ps":"1000","until_ps":"2000","input_batch":batch_ref,"input_watermark":"2",
        "policy_hash":service.profile.operating_contract.policy_ref.hash,"wall_budget_ns":service.bootstrap.host_budget_ns
    });
    let result = call(
        &mut controller,
        "begin-window/2",
        Some("native-window/1"),
        Method::Begin,
        true,
        json!({
            "kind":"quantum_begin","binding_hash":owner.identity().unwrap(),
            "owner_generation":service.bootstrap.authority.owner_generation,"activation_id":service.bootstrap.activation_id,
            "world_generation":service.bootstrap.world_generation,"arguments":arguments,"extensions":{}
        }),
    );
    let MethodResult::QuantumBegin(result) = result else {
        panic!("wrong actual second window");
    };

    let input_id = fixture::id("input/2");
    let begin_id = fixture::id("begin-window/2");
    let view = controller
        .original_lineage_window(LineageWindowRequests {
            realization: &realize_id,
            input: &input_id,
            begin: &begin_id,
        })
        .unwrap();
    assert_eq!(view.native_pid(), prior_native_pid);
    assert_native_inventory(&view);
    let evidence = view.native_evidence(72, 600 * 1024).unwrap();
    assert!(
        evidence
            .external_dependencies()
            .contains(&prior_native.identity().unwrap())
    );
    let batch_object = evidence
        .objects()
        .iter()
        .find(|object| object.reference() == view.input_batch_reference())
        .unwrap();
    assert_eq!(batch_object.dependencies().len(), 3);
    let zero_payload = &view.input_batch().events[1].payload;
    assert!(evidence.external_dependencies().contains(zero_payload));

    assert_eq!(
        view.preceding_public_acknowledgement(),
        Some(&first_consumption)
    );
    assert_eq!(
        view.native_receipt().checksum_before,
        prior_native.output.checksum
    );
    assert_eq!(
        view.native_receipt().previous_closed,
        Some(prior_native.identity().unwrap())
    );
    let consumed = &view.native_receipt().consumed;
    assert_eq!(consumed.len(), 3);
    assert_eq!(
        (consumed[0].byte_start.get(), consumed[0].byte_end.get()),
        (0, 2)
    );
    assert_eq!(
        (consumed[1].byte_start.get(), consumed[1].byte_end.get()),
        (2, 2)
    );
    assert_eq!(
        (consumed[2].byte_start.get(), consumed[2].byte_end.get()),
        (2, 4)
    );
    assert_eq!(consumed[0].checksum_after, consumed[1].checksum_after);
    assert_eq!(view.observation().events[0].id.as_str(), "checksum-2");
    assert!(view.observation().events[0].causal_parent_ids.is_empty());
    let observation = view.observation().clone();
    drop(view);

    let cut = Position::new(2000.into(), 0.into(), Phase::BoundaryControl);
    call(
        &mut controller,
        "close/2",
        None,
        Method::QuantumClose,
        true,
        json!({
            "grant_id":"window/1","activation_id":service.bootstrap.activation_id,
            "world_generation":service.bootstrap.world_generation,"owner_generation":service.bootstrap.authority.owner_generation,
            "input_epoch":batch.input_epoch,"quantum_index":"1","participant_ids":[service.bootstrap.node_id],
            "cut":cut,"policy_hash":service.profile.operating_contract.policy_ref.hash,
            "observation_batch_hash":observation.identity().unwrap(),"input_watermark":"2",
            "deadline_disposition":"within_budget","extensions":{}
        }),
    );
    let consumption = crucible_node_provider::reference_service::PublicationConsumption {
        schema: "reference-device/publication-consumption-v1".into(),
        session_id: service.bootstrap.authority.session_id.clone(),
        incarnation_id: service.bootstrap.authority.incarnation_id.clone(),
        operation_id: fixture::id("native-window/1"),
        grant_id: fixture::id("window/1"),
        world_binding_hash: service.bootstrap.world_binding_hash.clone(),
        observation_batch_hash: observation.identity().unwrap(),
        stop_receipt: result.stop_receipt,
        publication: Position::new(2000.into(), 0.into(), Phase::Publication),
        extensions: Extensions::new(),
    };
    let bytes = canonical::canonical_json(&json!(consumption)).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    controller.upload(&reference, &bytes).unwrap();
    call(
        &mut controller,
        "consume/2",
        None,
        Method::Retire,
        false,
        json!({
            "request_ids":["begin-window/2"],"operation_ids":["native-window/1"],
            "disposition":"consumed","custody_receipt":reference,"extensions":{}
        }),
    );
    let mut bindings = first;
    let full = lifecycle::native_window(&service);
    let mut tail = full;
    tail.steps.drain(1..reap);
    bindings = sdk_plan::execute(&mut controller, &tail, bindings);
    assert!(bindings.contains_key("measurement-ref"));
    assert!(!Path::new(&format!("/proc/{}", prior_native_pid.get())).exists());
    controller.fence();
}

fn call(
    controller: &mut ReferenceController,
    request: &str,
    operation: Option<&str>,
    method: Method,
    owned: bool,
    body: Value,
) -> MethodResult {
    let response = controller
        .call(
            fixture::id(request),
            operation.map(fixture::id),
            method,
            owned,
            body,
        )
        .unwrap();
    response
        .result
        .unwrap_or_else(|| panic!("original {request} was not completed: {:?}", response.shape))
}
