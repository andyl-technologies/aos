//! Checks data correspondence without manufacturing a native admission owner.
//!
//! crucible-lint: panic-shortcut: invariant failures intentionally stop these tests.

use super::*;
use crate::bodies::{AdmitRequest, AdmitResult, OperationState, ResponseShape};
use crucible_node_format::{Extensions, Id};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn original_admit() -> Result<Envelope, ProviderError> {
    let (_, _, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let body = serde_json::to_value(AdmitRequest {
        bindings: selection.realization.bindings,
        world_binding_hash: selection.world,
        admission_receipt: selection.admission_receipt,
        extensions: Extensions::new(),
    })
    .map_err(crucible_node_format::ContractError::from)?;
    let Value::Object(body) = body else {
        return Err(refused());
    };
    let mut original = crate::envelope::tests::request();
    original.method = Method::Admit;
    original.body = body;
    // The full original proof must stay inside the committed envelope.
    original
        .extensions
        .insert("fixture-proof".into(), json!({"mac":"original"}));
    Ok(original)
}

fn frame(original: &Envelope) -> Result<Vec<u8>, ProviderError> {
    let value =
        serde_json::to_value(original).map_err(crucible_node_format::ContractError::from)?;
    let body = crucible_node_format::canonical::canonical_json(&value)?;
    let mut bytes = u32::try_from(body.len())
        .map_err(|_| refused())?
        .to_be_bytes()
        .to_vec();
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

#[test]
fn completed_admit_literal_commits_full_original_proof_and_exact_framing() -> TestResult {
    let original = original_admit()?;
    let bytes = frame(&original)?;
    authenticate_request_literal_data(&original, &bytes)?;
    let first = Role::AdmitRequest.verified_canonical_body_digest(&bytes[4..]);

    let mut changed = original.clone();
    changed
        .extensions
        .insert("fixture-proof".into(), json!({"mac":"changed"}));
    assert!(authenticate_request_literal_data(&changed, &bytes).is_err());
    let changed_bytes = frame(&changed)?;
    assert_ne!(
        Role::AdmitRequest.verified_canonical_body_digest(&changed_bytes[4..]),
        first
    );
    assert_ne!(
        Role::Query.verified_canonical_body_digest(&bytes[4..]),
        first
    );

    let mut bad_header = bytes.clone();
    bad_header[3] ^= 1;
    assert!(authenticate_request_literal_data(&original, &bad_header).is_err());
    let mut spaced = bytes.clone();
    spaced.push(b' ');
    let extent = u32::try_from(spaced.len() - 4)?.to_be_bytes();
    spaced[..4].copy_from_slice(&extent);
    assert!(authenticate_request_literal_data(&original, &spaced).is_err());
    Ok(())
}

#[test]
fn actual_typed_admit_result_requires_closed_completed_body_and_binding_domain() -> TestResult {
    let (_, _, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let result = serde_json::to_value(AdmitResult {
        accepted_binding_hashes: vec![selection.realization.bindings[0].identity()?],
        admission_id: Id::new("actual-admission-result")?,
    })
    .map_err(crucible_node_format::ContractError::from)?;
    let Value::Object(result) = result else {
        return Err("result is not object".into());
    };
    let shape = serde_json::to_value(ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result,
        extensions: Extensions::new(),
    })
    .map_err(crucible_node_format::ContractError::from)?;
    let Value::Object(body) = shape else {
        return Err("shape is not object".into());
    };
    let mut original = original_admit()?;
    original.message = MessageKind::Response;
    original.extensions.clear();
    original.body = body;
    authenticate_response_data(&original)?;

    // Shape validation accepts every valid Id. The original Control selection
    // and response commitment authenticate its value in the enclosing caller.
    let mut alternative = original.clone();
    alternative.body.get_mut("result").ok_or("missing result")?["admission_id"] = json!("changed");
    authenticate_response_data(&alternative)?;

    for (pointer, replacement) in [
        ("/status", json!("changed")),
        ("/operation_state", json!("changed")),
        ("/result/admission_id", json!("")),
        ("/result/accepted_binding_hashes/0/domain", json!("changed")),
    ] {
        let mut value =
            serde_json::to_value(&original).map_err(crucible_node_format::ContractError::from)?;
        *value
            .pointer_mut(&format!("/body{pointer}"))
            .ok_or("missing field")? = replacement;
        let changed: Envelope =
            serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
        assert!(authenticate_response_data(&changed).is_err(), "{pointer}");
    }
    let mut changed = original.clone();
    changed.message = MessageKind::Request;
    assert!(authenticate_response_data(&changed).is_err());
    changed = original.clone();
    changed.method = Method::Observe;
    assert!(authenticate_response_data(&changed).is_err());
    changed = original.clone();
    changed.body.insert("extra".into(), Value::Null);
    assert!(authenticate_response_data(&changed).is_err());
    Ok(())
}

#[test]
fn accepted_binding_identity_matches_the_actual_canonical_admit_payload() -> TestResult {
    let admit = original_admit()?;
    let bytes = frame(&admit)?;
    authenticate_request_literal_data(&admit, &bytes)?;
    let binding = admit
        .body
        .get("bindings")
        .and_then(Value::as_array)
        .and_then(|bindings| bindings.first())
        .ok_or("missing binding")?;
    let binding: crucible_node_format::NodeBinding = serde_json::from_value(binding.clone())
        .map_err(crucible_node_format::ContractError::from)?;
    // This is the SAME typed method invoked by the actual Control Admit writer.
    let identity = binding.identity()?;
    let mut response = admit.clone();
    response.message = MessageKind::Response;
    response.extensions.clear();
    response.body = json!({"status":"completed", "operation_state":"completed", "extensions":{},
        "result":{"admission_id":"actual-admission", "accepted_binding_hashes":[identity]}})
    .as_object()
    .ok_or("missing response")?
    .clone();
    authenticate_response_data(&response)?;
    authenticate_binding_result_data(&admit, &bytes[4..], &response)?;

    let mut changed = response.clone();
    changed.body.get_mut("result").ok_or("missing result")?["accepted_binding_hashes"][0]["digest"] =
        json!("0".repeat(64));
    authenticate_response_data(&changed)?;
    assert!(authenticate_binding_result_data(&admit, &bytes[4..], &changed).is_err());

    let mut changed_admit = admit.clone();
    changed_admit
        .body
        .get_mut("bindings")
        .and_then(Value::as_array_mut)
        .and_then(|bindings| bindings.first_mut())
        .ok_or("missing binding")?["extensions"] = json!({"counterfactual":"changed"});
    let changed_bytes = frame(&changed_admit)?;
    authenticate_request_literal_data(&changed_admit, &changed_bytes)?;
    // Wrapper extensions are intentionally excluded from durable identity,
    // while the full original Admit role commitment still includes them.
    authenticate_binding_result_data(&changed_admit, &changed_bytes[4..], &response)?;
    assert_ne!(
        Role::AdmitRequest.verified_canonical_body_digest(&bytes[4..]),
        Role::AdmitRequest.verified_canonical_body_digest(&changed_bytes[4..])
    );

    let mut changed_admit = admit.clone();
    changed_admit
        .body
        .get_mut("bindings")
        .and_then(Value::as_array_mut)
        .and_then(|bindings| bindings.first_mut())
        .ok_or("missing binding")?["compatibility"]["node_id"] = json!("other-compatibility-node");
    let changed_bytes = frame(&changed_admit)?;
    authenticate_request_literal_data(&changed_admit, &changed_bytes)?;
    assert!(
        authenticate_binding_result_data(&changed_admit, &changed_bytes[4..], &response).is_err()
    );
    Ok(())
}

#[test]
fn fresh_query_owner_matches_the_complete_typed_owner_identity() -> TestResult {
    let (_, _, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let owner = &selection.realization.owner_bindings[0];
    let identity = owner.identity()?;
    let mut query = crate::envelope::tests::request();
    query.method = Method::Observe;
    query
        .body
        .insert("binding_hash".into(), serde_json::to_value(&identity)?);
    let source = json!({"selection": selection});
    let canonical = crucible_node_format::canonical::canonical_json(&source)?;
    authenticate_source_owner_binding_data(&source, &canonical, &query)?;

    for field in [
        "schema_version",
        "owner",
        "owner_roles",
        "node_bindings",
        "ownership_ref",
        "extensions",
    ] {
        let mut changed = source.clone();
        changed["selection"]["realization"]["owner_bindings"][0][field] = json!({"changed": field});
        let bytes = crucible_node_format::canonical::canonical_json(&changed)?;
        assert!(
            authenticate_source_owner_binding_data(&changed, &bytes, &query).is_err(),
            "{field}"
        );
    }
    let mut wrong_query = query.clone();
    wrong_query
        .body
        .get_mut("binding_hash")
        .ok_or("missing binding")?["domain"] = json!("cnp.node-binding.v1");
    assert!(authenticate_source_owner_binding_data(&source, &canonical, &wrong_query).is_err());
    wrong_query = query.clone();
    wrong_query
        .body
        .get_mut("binding_hash")
        .ok_or("missing binding")?["digest"] = json!("0".repeat(64));
    assert!(authenticate_source_owner_binding_data(&source, &canonical, &wrong_query).is_err());

    let mut changed = source.clone();
    let owners = changed["selection"]["realization"]["owner_bindings"]
        .as_array_mut()
        .ok_or("missing owners")?;
    owners.push(owners[0].clone());
    let bytes = crucible_node_format::canonical::canonical_json(&changed)?;
    assert!(authenticate_source_owner_binding_data(&changed, &bytes, &query).is_err());
    Ok(())
}
