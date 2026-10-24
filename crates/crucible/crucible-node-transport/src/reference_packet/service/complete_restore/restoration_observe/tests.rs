//! Checks closed observation DATA without issuing a Window or native permission.

use super::*;
use crate::envelope::{Envelope, MessageKind, Nullable};
use crucible_node_format::{Extensions, Id, canonical};
use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn request() -> Result<PacketRestorationObservationRequest, ProviderError> {
    Ok(PacketRestorationObservationRequest {
        schema: PACKET_RESTORATION_OBSERVE_FEATURE.into(),
        scope: super::super::activation::tests::request()?.scope,
        world_original: canonical::content_ref(b"world-original-data", "application/json")?,
        world_terminal: canonical::content_ref(b"world-terminal-data", "application/json")?,
        maximum_items: U64::new(1),
        native_allocation: PacketRestorationActivationAllocationRow {
            retained_requested_bytes: U64::new(100),
            maximum_simultaneous_transient_bytes: U64::new(200),
            declared_counter_scratch_bytes: U64::new(300),
        },
    })
}

fn original(request: &PacketRestorationObservationRequest) -> Result<Envelope, ProviderError> {
    let target = &request.scope.target;
    let body = crate::bodies::ObserveRequest {
        binding_hash: target.binding_hash.clone(),
        owner_generation: target.owner_generation,
        after_observation_sequence: U64::new(0),
        maximum_items: U64::new(1),
        extensions: Extensions::new(),
    };
    request.authenticate_body_data(&body)?;
    let Value::Object(body) =
        serde_json::to_value(body).map_err(crucible_node_format::ContractError::from)?
    else {
        return Err(invalid());
    };
    let mut unsigned = serde_json::Map::new();
    unsigned.insert(
        "request".into(),
        serde_json::to_value(request).map_err(crucible_node_format::ContractError::from)?,
    );
    let mut extensions = Extensions::new();
    extensions.insert(
        PACKET_RESTORATION_OBSERVE_FEATURE.into(),
        Value::Object(unsigned),
    );
    Ok(Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(target.session.clone())),
        incarnation_id: Nullable(Some(target.incarnation.clone())),
        node_id: Nullable(Some(target.node.clone())),
        execution_owner_id: Nullable(Some(target.owner.clone())),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(Id::new("observe-data")?)),
        sequence: U64::new(9),
        method: crate::envelope::Method::Observe,
        body,
        extensions,
    })
}

#[test]
fn observe_mac_binds_whole_world_pair_and_independent_native_axes() -> TestResult {
    let request = request()?;
    let context = PacketRestorationObservationContext {
        request,
        assigned_request: Bytes::new(vec![7; 32]),
    };
    let proof = restoration_observe_proof_data(&[3; 32], &context)?;
    verify_restoration_observe_proof_data(&[3; 32], &context, &proof)?;
    for field in [0, 1, 2] {
        let mut changed = context.clone();
        match field {
            0 => {
                changed.request.world_original =
                    canonical::content_ref(b"foreign-world", "application/json")?
            }
            1 => {
                changed.request.world_terminal =
                    canonical::content_ref(b"foreign-terminal", "application/json")?
            }
            _ => changed.request.native_allocation.retained_requested_bytes = U64::new(101),
        }
        assert!(verify_restoration_observe_proof_data(&[3; 32], &changed, &proof).is_err());
    }
    assert!(verify_restoration_observe_proof_data(&[4; 32], &context, &proof).is_err());
    Ok(())
}

#[test]
fn observe_projection_excludes_only_own_proof_and_keeps_assigned_sequence() -> TestResult {
    let request = request()?;
    let mut original = original(&request)?;
    let digest = restoration_observe_assigned_request_digest(&original, 65_536)?;
    let context = PacketRestorationObservationContext {
        request,
        assigned_request: Bytes::new(digest.to_vec()),
    };
    let proof = restoration_observe_proof_data(&[3; 32], &context)?;
    original
        .extensions
        .get_mut(PACKET_RESTORATION_OBSERVE_FEATURE)
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)?
        .insert("proof".into(), serde_json::to_value(proof)?);
    assert_eq!(
        restoration_observe_assigned_request_digest(&original, 65_536)?,
        digest
    );
    original.sequence = U64::new(10);
    assert_ne!(
        restoration_observe_assigned_request_digest(&original, 65_536)?,
        digest
    );
    original.extensions.insert("foreign".into(), Value::Null);
    assert!(restoration_observe_assigned_request_digest(&original, 65_536).is_err());
    Ok(())
}

#[test]
fn observe_closed_allowance_body_and_full_definition_refuse_changes() -> TestResult {
    let mut request = request()?;
    request.maximum_items = U64::new(2);
    assert!(request.validate_data().is_err());
    request.maximum_items = U64::new(1);
    let original = original(&request)?;
    let mut body: crate::bodies::ObserveRequest =
        serde_json::from_value(Value::Object(original.body))?;
    request.authenticate_body_data(&body)?;
    body.after_observation_sequence = U64::new(1);
    assert!(request.authenticate_body_data(&body).is_err());
    let mut schema = restoration_observe_schema()?;
    authenticate_restoration_observe_schema_data(&schema)?;
    schema.definition.length = U64::new(schema.definition.length.get() + 1);
    assert!(authenticate_restoration_observe_schema_data(&schema).is_err());
    Ok(())
}

#[test]
fn observe_raw_proof_walk_counts_actual_spare_digest_backing() -> TestResult {
    let context = PacketRestorationObservationContext {
        request: request()?,
        assigned_request: Bytes::new(vec![7; 32]),
    };
    let proof = restoration_observe_proof_data(&[3; 32], &context)?;
    let mut changed = proof.clone();
    let mut bank = Vec::with_capacity(97);
    bank.extend_from_slice(proof.mac.as_slice());
    let expected = bank.capacity() - proof.mac.allocation_capacity();
    changed.mac = Bytes::new(bank);
    let before =
        RetainedRestorationObservationData::Proof(&proof).original_retained_metadata_facts()?;
    let after =
        RetainedRestorationObservationData::Proof(&changed).original_retained_metadata_facts()?;
    assert!(expected > 0);
    assert_eq!(
        after.vector_capacity_bytes - before.vector_capacity_bytes,
        expected
    );
    assert_eq!(after.string_capacity_bytes, before.string_capacity_bytes);
    Ok(())
}

#[test]
fn observe_assigned_digest_refuses_each_changed_baseline_before_signing() -> TestResult {
    let request = request()?;
    let saved = original(&request)?;
    restoration_observe_assigned_request_digest(&saved, 65_536)?;
    for field in 0..5 {
        let mut changed = saved.clone();
        match field {
            0 => {
                changed.body.insert(
                    "after_observation_sequence".into(),
                    Value::String("1".into()),
                );
            }
            1 => {
                changed
                    .body
                    .insert("maximum_items".into(), Value::String("2".into()));
            }
            2 => {
                changed
                    .body
                    .insert("owner_generation".into(), Value::String("2".into()));
            }
            3 => {
                changed.body.insert(
                    "binding_hash".into(),
                    serde_json::to_value(canonical::hash("cnp.owner-binding.v1", b"foreign")?)?,
                );
            }
            _ => {
                changed.body.insert("unknown".into(), Value::Null);
            }
        }
        assert!(restoration_observe_assigned_request_digest(&changed, 65_536).is_err());
    }
    let maximum = crate::connection::serialized_credit(&saved, 65_536)?;
    restoration_observe_assigned_request_digest(&saved, maximum)?;
    assert!(restoration_observe_assigned_request_digest(&saved, maximum - 1).is_err());
    Ok(())
}
