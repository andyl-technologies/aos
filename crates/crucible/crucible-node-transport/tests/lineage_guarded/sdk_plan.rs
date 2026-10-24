//! Executes the same original lifecycle through the SDK's complete evidence path.
//!
//! Local bindings retain exact originals. No response is reconstructed into
//! authority, and no missing dependency is inferred from an object hash.

use crucible_node_format::*;
use crucible_node_transport::{
    conformance::*,
    envelope::{Envelope, Method},
    reference_lineage::LineageSourceGuard,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn execute(
    controller: &mut LineageSourceGuard,
    service: &super::fixture::NativeService,
    plan: &ProbePlan,
    mut bindings: BTreeMap<String, Value>,
) -> BTreeMap<String, Value> {
    bindings.insert(
        "incarnation".into(),
        json!(service.bootstrap.authority.incarnation_id),
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
                        "schema_version":1, "execution_owner_id":service.bootstrap.owner_id,
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
                    let crucible_node_transport::bodies::ResponseShape::Error { error, .. } =
                        refused.shape
                    else {
                        panic!("foreign nonleaf input was accepted");
                    };
                    assert_eq!(
                        error.effect,
                        crucible_node_transport::bodies::EffectCertainty::NotStarted
                    );
                }
                let commitment_hash = if id.as_str() == "commit-original-input-cut" {
                    let realization = super::fixture::id("realize");
                    assert!(
                        controller
                            .original_input_commit_features(&super::fixture::id(
                                "foreign-realization"
                            ))
                            .is_err()
                    );
                    let selected = controller
                        .original_input_commit_features(&realization)
                        .unwrap();
                    assert!(selected.iter().any(|feature| {
                        feature.as_str()
                            == crucible_node_transport::input_commit::INPUT_COMMIT_FEATURE
                    }));
                    let body = serde_json::from_value(request.body.clone().into()).unwrap();
                    Some(
                        controller
                            .original_input_commit_request_hash(
                                &realization,
                                request.request_id.0.as_ref().unwrap().clone(),
                                &body,
                                request.extensions.clone(),
                            )
                            .unwrap(),
                    )
                } else {
                    None
                };
                let response = controller
                    .call_with_extensions(
                        request.request_id.0.unwrap(),
                        request.operation_id.0,
                        request.method,
                        request.execution_owner_id.0.is_some(),
                        request.body,
                        request.extensions,
                    )
                    .unwrap_or_else(|error| panic!("{id}: {error}"));
                if let Some(expected) = commitment_hash {
                    let crucible_node_transport::bodies::MethodResult::Input(result) =
                        response.result.as_ref().unwrap()
                    else {
                        panic!("original guarded commitment did not complete");
                    };
                    let receipt: ControlReceipt = serde_json::from_slice(
                        controller.content(&result.custody_receipt).unwrap(),
                    )
                    .unwrap();
                    let custody: InputCustodyRecord =
                        serde_json::from_slice(controller.content(&receipt.record_ref).unwrap())
                            .unwrap();
                    assert_eq!(custody.evidence_refs.len(), 1);
                    let record: crucible_node_transport::input_commit::InputCommitRecordV1 =
                        serde_json::from_slice(
                            controller.content(&custody.evidence_refs[0]).unwrap(),
                        )
                        .unwrap();
                    record.validate().unwrap();
                    assert_eq!(record.request_hash, expected);
                    let bytes = controller.content(&record.staged_bytes).unwrap();
                    record.staged_bytes.verify(bytes).unwrap();
                    assert_eq!(bytes, &[1, 2]);
                }
                let value = json!({"body":response.shape});
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
