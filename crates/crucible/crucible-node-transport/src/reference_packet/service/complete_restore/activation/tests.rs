//! Exercises inert activation grammar and complete assigned-original projections.
//!
//! These controls construct no Controller, Core claim, registered native owner,
//! process, socket or backend. A passing MAC comparison is DATA only.

use super::*;
use crate::{
    bodies::WorldActivateRequest,
    envelope::{Envelope, MessageKind, Nullable},
};
use crucible_node_format::{Extensions, canonical};
use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn reference(bytes: &[u8]) -> Result<ContentRef, ProviderError> {
    Ok(canonical::content_ref(bytes, "application/json")?)
}

pub(crate) fn request() -> Result<PacketRestorationActivationRequest, ProviderError> {
    Ok(PacketRestorationActivationRequest {
        schema: PACKET_RESTORATION_ACTIVATION_FEATURE.into(),
        phase: PacketRestorationActivationPhase::WorldActivate,
        scope: PacketRestorationActivationScope {
            source_birth: reference(b"source-birth-data")?,
            source_runtime: reference(b"source-runtime-data")?,
            scope_proof: reference(b"scope-proof-data")?,
            target: PacketRestorationActivationTarget {
                native_pid: U64::new(1),
                session: Id::new("session")?,
                incarnation: Id::new("incarnation")?,
                node: Id::new("node")?,
                owner: Id::new("owner")?,
                owner_generation: U64::new(1),
                binding_hash: canonical::hash("cnp.owner-binding.v1", b"owner-data")?,
                world: canonical::hash("cnp.world-binding.v1", b"world-data")?,
                activation: Id::new("activation")?,
                generation: U64::new(1),
                prepared_token: Id::new("prepared")?,
                gate: Id::new("gate")?,
                admission: Id::new("admission")?,
                transaction: Id::new("transaction")?,
            },
            restoration: PacketRestorationActivationOriginals {
                captured_owner_state: reference(b"owner-state-data")?,
                captured_control: reference(b"control-data")?,
                captured_journal: reference(b"journal-data")?,
                mapping: reference(b"mapping-data")?,
                commit_request: reference(b"commit-request-data")?,
                commit_response: reference(b"commit-response-data")?,
                context_digest: Bytes::new(vec![3; 32]),
            },
        },
        native_allocation: PacketRestorationActivationAllocationRow {
            retained_requested_bytes: U64::new(100),
            maximum_simultaneous_transient_bytes: U64::new(200),
            declared_counter_scratch_bytes: U64::new(300),
        },
    })
}

fn original(request: &PacketRestorationActivationRequest) -> Result<Envelope, ProviderError> {
    let target = &request.scope.target;
    let body = WorldActivateRequest {
        transaction_id: target.transaction.clone(),
        activation_id: target.activation.clone(),
        world_generation: target.generation,
        prepared_token: target.prepared_token.clone(),
        world_binding_hash: target.world.clone(),
        gate_id: target.gate.clone(),
        activation_manifest: reference(b"actual-manifest-data")?,
        extensions: Extensions::new(),
    };
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
        PACKET_RESTORATION_ACTIVATION_FEATURE.into(),
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
        request_id: Nullable(Some(Id::new("assigned-activation")?)),
        sequence: U64::new(42),
        method: request.phase.method(),
        body,
        extensions,
    })
}

#[test]
fn assigned_projection_excludes_only_nested_proof_and_preserves_real_request_fields() -> TestResult
{
    let request = request()?;
    let original = original(&request)?;
    let expected =
        restoration_activation_assigned_request_digest(&original, request.phase, 65_536)?;
    let mut sealed = original.clone();
    sealed
        .extensions
        .get_mut(PACKET_RESTORATION_ACTIVATION_FEATURE)
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)?
        .insert(
            "proof".into(),
            serde_json::json!({"untrusted":"projection-only"}),
        );
    assert_eq!(
        expected,
        restoration_activation_assigned_request_digest(&sealed, request.phase, 65_536)?
    );

    for axis in 0..6 {
        let mut changed = original.clone();
        match axis {
            0 => changed.sequence = U64::new(43),
            1 => changed.request_id = Nullable(Some(Id::new("other-original")?)),
            2 => changed.session_id = Nullable(Some(Id::new("other-session")?)),
            3 => changed.node_id = Nullable(Some(Id::new("other-node")?)),
            4 => {
                changed.body.insert(
                    "activation_id".into(),
                    serde_json::json!("other-activation"),
                );
            }
            _ => {
                let value = changed
                    .extensions
                    .get_mut(PACKET_RESTORATION_ACTIVATION_FEATURE)
                    .and_then(Value::as_object_mut)
                    .ok_or_else(invalid)?;
                value
                    .get_mut("request")
                    .and_then(Value::as_object_mut)
                    .ok_or_else(invalid)?
                    .get_mut("native_allocation")
                    .and_then(Value::as_object_mut)
                    .ok_or_else(invalid)?
                    .insert("retained_requested_bytes".into(), serde_json::json!("101"));
            }
        }
        assert_ne!(
            expected,
            restoration_activation_assigned_request_digest(&changed, request.phase, 65_536)?
        );
    }
    Ok(())
}

#[test]
fn activation_mac_binds_phase_scope_native_row_and_assigned_original() -> TestResult {
    let request = request()?;
    let original = original(&request)?;
    let context = PacketRestorationActivationContext {
        request,
        assigned_request: Bytes::new(
            restoration_activation_assigned_request_digest(
                &original,
                PacketRestorationActivationPhase::WorldActivate,
                65_536,
            )?
            .to_vec(),
        ),
    };
    let proof = restoration_activation_proof_data(&[7; 32], &context)?;
    verify_restoration_activation_proof_data(&[7; 32], &context, &proof)?;
    assert!(verify_restoration_activation_proof_data(&[8; 32], &context, &proof).is_err());
    for axis in 0..4 {
        let mut changed = context.clone();
        match axis {
            0 => changed.request.phase = PacketRestorationActivationPhase::Arm,
            1 => changed.request.scope.restoration.mapping = reference(b"foreign-mapping")?,
            2 => changed.request.native_allocation.retained_requested_bytes = U64::new(101),
            _ => changed.assigned_request = Bytes::new(vec![9; 32]),
        }
        assert!(verify_restoration_activation_proof_data(&[7; 32], &changed, &proof).is_err());
    }
    Ok(())
}

#[test]
fn activation_full_schema_comparison_refuses_each_reference_axis() -> TestResult {
    let schema = restoration_activation_schema()?;
    authenticate_restoration_activation_schema_data(&schema)?;
    for axis in 0..8 {
        let mut changed = schema.clone();
        match axis {
            0 => changed.id = Id::new("foreign-schema")?,
            1 => changed.version = 2,
            2 => changed.definition.hash.algorithm = "foreign".into(),
            3 => changed.definition.hash.domain = "foreign".into(),
            4 => changed.definition.hash.digest.push('0'),
            5 => changed.definition.length = U64::new(changed.definition.length.get() + 1),
            6 => changed.definition.media_type = "application/octet-stream".into(),
            _ => {
                changed.extensions.insert("foreign".into(), Value::Null);
            }
        }
        assert!(authenticate_restoration_activation_schema_data(&changed).is_err());
    }
    Ok(())
}

#[test]
fn activation_closed_shape_and_exact_full_frame_limit_refuse_before_projection() -> TestResult {
    let request = request()?;
    let original = original(&request)?;
    let maximum = crate::connection::serialized_credit(&original, 65_536)?;
    restoration_activation_assigned_request_digest(&original, request.phase, maximum)?;
    assert!(
        restoration_activation_assigned_request_digest(&original, request.phase, maximum - 1)
            .is_err()
    );
    let mut unknown = original.clone();
    unknown
        .extensions
        .insert("unknown-activation".into(), Value::Null);
    assert!(
        restoration_activation_assigned_request_digest(&unknown, request.phase, 65_536).is_err()
    );
    let mut request_value = serde_json::to_value(&request)?;
    request_value
        .as_object_mut()
        .ok_or_else(invalid)?
        .insert("unknown".into(), Value::Null);
    assert!(serde_json::from_value::<PacketRestorationActivationRequest>(request_value).is_err());
    let mut missing = request;
    missing.native_allocation.declared_counter_scratch_bytes = U64::new(0);
    assert!(missing.validate_data().is_err());
    Ok(())
}
