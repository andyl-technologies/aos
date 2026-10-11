//! Executes the same original lifecycle through the SDK's complete evidence path.
//!
//! Local bindings retain exact originals. No response is reconstructed into
//! authority, and no missing dependency is inferred from an object hash.

use crucible_node_contract::*;
use crucible_node_provider::{
    client::ReferenceController,
    conformance::*,
    envelope::{Envelope, Method},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn execute(
    controller: &mut ReferenceController,
    plan: &ProbePlan,
    mut bindings: BTreeMap<String, Value>,
) -> BTreeMap<String, Value> {
    bindings.insert(
        "incarnation".into(),
        json!(controller.bootstrap.authority.incarnation_id),
    );
    for step in plan.steps.iter().skip(1) {
        match step {
            ProbeStep::Exchange {
                id,
                request,
                expected,
                assertions,
                captures,
                ..
            } => {
                let request: Envelope =
                    serde_json::from_value(resolve(request, &bindings)).unwrap();
                // SDK uploads reserve the original local body before BlobFinish;
                // a hand-written transfer lacks that mandatory custody preflight.
                if request.method == Method::BlobBegin {
                    let reference: ContentRef =
                        serde_json::from_value(request.body["content"].clone()).unwrap();
                    let transfer = &request.body["transfer_id"];
                    let bytes = plan
                        .steps
                        .iter()
                        .find_map(|step| {
                            let ProbeStep::Exchange { request, .. } = step else {
                                return None;
                            };
                            if request["method"] != "blob_chunk"
                                || &request["body"]["transfer_id"] != transfer
                            {
                                return None;
                            }
                            Some(
                                serde_json::from_value::<Bytes>(resolve(
                                    &request["body"]["bytes"],
                                    &bindings,
                                ))
                                .unwrap(),
                            )
                        })
                        .unwrap();
                    controller
                        .upload(&reference, bytes.as_slice())
                        .unwrap_or_else(|error| panic!("{id}: {error}"));
                    continue;
                }
                if matches!(request.method, Method::BlobChunk | Method::BlobFinish) {
                    continue;
                }
                if id.as_str() == "retain-actual-input" {
                    // The foreign record has real verified bytes but no original
                    // selected native dependency row. It must not be adopted.
                    let bytes = br#"{"schema":"crucible.reference.consumption-relation.v1","untrusted":true}"#;
                    let reference = canonical::content_ref(
                        bytes,
                        "application/vnd.crucible.reference-consumption-relation+json",
                    )
                    .unwrap();
                    controller.upload(&reference, bytes).unwrap();
                    let mut changed = request.body.clone();
                    changed["events"][0]["provenance_ref"] = json!(reference);
                    let original: InputBatch = serde_json::from_value(json!({
                        "schema_version":1, "execution_owner_id":controller.bootstrap.owner_id,
                        "input_epoch":changed["input_epoch"], "batch_id":changed["batch_id"],
                        "batch_sequence":changed["batch_sequence"], "events":changed["events"], "extensions":{}
                    })).unwrap();
                    changed.insert("batch_hash".into(), json!(original.identity().unwrap()));
                    let refused = controller
                        .call(
                            super::fixture::id("foreign-nonleaf-input"),
                            None,
                            Method::Input,
                            true,
                            changed,
                        )
                        .unwrap();
                    let crucible_node_provider::bodies::ResponseShape::Error { error, .. } =
                        refused.shape
                    else {
                        panic!("foreign nonleaf input was accepted");
                    };
                    assert_eq!(
                        error.effect,
                        crucible_node_provider::bodies::EffectCertainty::NotStarted
                    );
                }
                let response = controller
                    .call(
                        request.request_id.0.unwrap(),
                        request.operation_id.0,
                        request.method,
                        request.execution_owner_id.0.is_some(),
                        request.body,
                    )
                    .unwrap_or_else(|error| panic!("{id}: {error}"));
                let value = json!({"body":response.shape});
                if id.as_str() == "realize-withheld" {
                    super::gate::verify(controller, &value);
                }
                if id.as_str() == "execute-native-window" {
                    let realization = super::fixture::id("realize");
                    let input = super::fixture::id("input");
                    let begin = super::fixture::id("begin-window");
                    let held = controller
                        .original_lineage_window(
                            crucible_node_provider::client::LineageWindowRequests {
                                realization: &realization,
                                input: &input,
                                begin: &begin,
                            },
                        )
                        .unwrap();
                    assert!(
                        std::path::Path::new(&format!("/proc/{}", held.native_pid().get()))
                            .exists()
                    );
                    assert_eq!(held.native_receipt().output.checksum.get(), 259);
                    assert_eq!(held.observation().events[0].id.as_str(), "checksum-1");
                }
                match expected {
                    Expectation::Completed => {
                        assert_eq!(value["body"]["status"], "completed", "{id}: {value}")
                    }
                    Expectation::Error { code, effect } => {
                        assert_eq!(value["body"]["error"]["code"], json!(code), "{id}: {value}");
                        assert_eq!(
                            value["body"]["error"]["effect"],
                            json!(effect),
                            "{id}: {value}"
                        );
                    }
                    _ => panic!("unsupported SDK oracle expectation: {id}"),
                }
                check(&value, assertions, captures, &mut bindings);
            }
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
            ProbeStep::ReceiveBlob {
                reference,
                reference_binding,
                bytes_binding,
                ..
            } => {
                let reference: ContentRef =
                    serde_json::from_value(resolve(reference, &bindings)).unwrap();
                let bytes = controller.content(&reference).unwrap();
                reference.verify(bytes).unwrap();
                bindings.insert(reference_binding.to_string(), json!(reference));
                bindings.insert(bytes_binding.to_string(), json!(Bytes::new(bytes.to_vec())));
            }
            ProbeStep::InspectContent {
                reference,
                bytes,
                assertions,
                captures,
                ..
            } => {
                let reference: ContentRef =
                    serde_json::from_value(resolve(reference, &bindings)).unwrap();
                let bytes: Bytes = serde_json::from_value(resolve(bytes, &bindings)).unwrap();
                reference.verify(bytes.as_slice()).unwrap();
                check(
                    &canonical::parse_json(bytes.as_slice(), 65536).unwrap(),
                    assertions,
                    captures,
                    &mut bindings,
                );
            }
            ProbeStep::Identity {
                kind: IdentityKind::ObservationBatch,
                value,
                identity_binding,
                ..
            } => {
                let batch: ObservationBatch =
                    serde_json::from_value(resolve(value, &bindings)).unwrap();
                bindings.insert(
                    identity_binding.to_string(),
                    json!(batch.identity().unwrap()),
                );
            }
            _ => panic!("unsupported SDK oracle action: {}", step.id()),
        }
    }
    bindings
}

fn check(
    value: &Value,
    assertions: &[ReplyAssertion],
    captures: &BTreeMap<String, String>,
    bindings: &mut BTreeMap<String, Value>,
) {
    for assertion in assertions {
        assert_eq!(
            value.pointer(&assertion.pointer).unwrap(),
            &resolve(&assertion.equals, bindings),
            "{}",
            assertion.pointer
        );
    }
    for (name, pointer) in captures {
        assert!(
            bindings
                .insert(name.clone(), value.pointer(pointer).unwrap().clone())
                .is_none()
        );
    }
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
        Value::Array(array) => {
            Value::Array(array.iter().map(|value| resolve(value, bindings)).collect())
        }
        _ => value.clone(),
    }
}
