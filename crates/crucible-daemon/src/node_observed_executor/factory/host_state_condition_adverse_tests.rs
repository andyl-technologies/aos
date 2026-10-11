//! Same-reader tampering controls over an actual captured original condition Stop.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- These same-reader tampering controls panic when an authentic fixture or expected refusal changes.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible::node_adapters::{HostModelResources, validate_host_continuation};
use crucible::node_contract::{ConditionControlRequest, OperationRequest, RuntimeSnapshot};

pub(super) fn verify_original_body_controls(
    record: &HostArchiveRecord,
    runtime: &NodeRuntime,
    graph: &AdmittedGraph,
    cut: Position,
) {
    let original = runtime
        .condition_runtime_snapshot(cut, 1.into(), 32 << 20)
        .unwrap();
    let node = id("observer");
    let descriptor = graph.descriptor(&node).unwrap();
    let binding = graph.binding(&node).unwrap();
    let owner = record
        .manifest()
        .owners
        .iter()
        .find(|owner| owner.participant_ids == [node.clone()])
        .unwrap();
    let bytes = record
        .content_bytes(owner.state_ref.as_ref().unwrap(), 16 << 20)
        .unwrap();
    let inspect = |source: &RuntimeSnapshot, native: &[u8]| {
        validate_host_continuation(
            native,
            source,
            descriptor,
            binding,
            HostModelResources::default(),
        )
    };
    inspect(&original, &bytes).unwrap();
    let producer_proof = original
        .inputs
        .iter()
        .flat_map(|input| &input.deliveries)
        .find(|delivery| delivery.producer == id("disk"))
        .unwrap()
        .provenance_ref
        .clone();
    let producer_body = record.content_bytes(&producer_proof, 16 << 20).unwrap();
    condition::verify_required_input_key(&producer_body).unwrap();

    for proof in [false, true] {
        let mut changed = original.clone();
        let request = changed
            .operations
            .iter_mut()
            .find_map(|operation| {
                if let OperationRequest::DebugConditionV1(request) = &mut operation.request {
                    Some(request.as_mut())
                } else {
                    None
                }
            })
            .unwrap();
        let ConditionControlRequest::Stop { barrier, .. } = request else {
            panic!("actual captured control is not the original Stop");
        };
        let inventory = barrier
            .native
            .iter_mut()
            .find(|inventory| {
                if proof {
                    !inventory.proof_objects.is_empty()
                } else {
                    !inventory.receipt.bytes.is_empty()
                }
            })
            .unwrap();
        if proof {
            let body = inventory
                .proof_objects
                .iter_mut()
                .find(|body| !body.bytes.is_empty())
                .unwrap();
            body.bytes[0] ^= 1;
        } else {
            inventory.receipt.bytes[0] ^= 1;
        }
        // The canonical index deliberately excludes these owned native bytes.
        assert_eq!(
            serde_json::to_value(&changed.operations).unwrap(),
            serde_json::to_value(&original.operations).unwrap()
        );
        let failure = inspect(&changed, &bytes).err().unwrap();
        assert!(
            failure.reason.contains("request changed"),
            "{}",
            failure.reason
        );
    }

    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let inner: Bytes = serde_json::from_value(envelope["original"].clone()).unwrap();
    let dag: serde_json::Value = serde_json::from_slice(inner.as_slice()).unwrap();
    for missing in [true, false] {
        let mut changed = dag.clone();
        let objects = changed["objects"].as_array_mut().unwrap();
        if missing {
            let index = objects
                .iter()
                .position(|object| !object["dependencies"].as_array().unwrap().is_empty())
                .unwrap();
            let dependency = objects[index]["dependencies"][0].clone();
            let row = objects
                .iter()
                .position(|object| object["reference"] == dependency)
                .unwrap();
            objects.remove(row);
        } else {
            let object = objects
                .iter_mut()
                .find(|object| !object["dependencies"].as_array().unwrap().is_empty())
                .unwrap();
            object["dependencies"][0] = serde_json::to_value(
                canonical::content_ref(b"unavailable original dependency", "text/plain").unwrap(),
            )
            .unwrap();
        }
        let inner = canonical::canonical_json(&changed).unwrap();
        envelope["original"] = serde_json::to_value(Bytes::new(inner)).unwrap();
        let changed_bytes = canonical::canonical_json(&envelope).unwrap();
        assert!(inspect(&original, &changed_bytes).is_err());
    }
    inspect(&original, &bytes).unwrap();
}
