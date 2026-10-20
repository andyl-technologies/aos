//! Exercises the actual closed Prepare header before typed Begin allocation.
//!
//! These are data predicates over an original admitted handshake fixture. They
//! do not construct a boot6 scope, grant a Prepare action or complete a query.

use super::*;
use crate::bodies::{BeginKind, BeginRequest, PrepareRestoreArguments};
use crate::envelope::Nullable;
use crate::reference_packet::coordinator::original_canonical_ack_controller_scope;
use crate::reference_packet::service::complete_restore::*;
use crucible_node_format::{Bytes, Phase, Position, Tick, U64};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn original(
    selection: &PacketControlSelection,
    authority: &crate::handshake::ConnectionAuthority,
) -> Result<Envelope, Box<dyn std::error::Error>> {
    let binding = &selection.realization.bindings[0];
    let owner = &selection.realization.owner_bindings[0];
    let reference = canonical::content_ref(b"{}", "application/json")?;
    let owner_hash = canonical::hash("cnp.owner-binding.v1", b"fresh")?;
    let restoration = PacketCompleteRestoreRequest {
        schema: PACKET_COMPLETE_RESTORE_FEATURE.into(),
        archive_index: reference.clone(),
        capture_manifest: reference.clone(),
        owner_state: reference.clone(),
        journal: reference.clone(),
        source_runtime: reference.clone(),
        backend_implementation: reference.clone(),
        backend_schema: complete_restore_request_schema()?,
        archived_cut: Position::new(Tick::new(0), U64::new(0), Phase::BoundaryControl),
        archived_ordinal: 0.into(),
        target_world: canonical::hash("cnp.world-binding.v1", b"fresh")?,
        target_owner: owner.owner.id.clone(),
        target_owner_binding: owner_hash.clone(),
        target_activation: Id::new("activation/fresh")?,
        target_generation: 1.into(),
        target_owner_generation: 1.into(),
        mapping: reference.clone(),
        nonce: Bytes::new(vec![1; 32]),
    };
    let request = PacketCompleteRestorePrepareRequest {
        schema: PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION.into(),
        restoration,
        host_protocol: reference.clone(),
        native_protocol: reference.clone(),
        native_control: reference.clone(),
        native_anchor: reference.clone(),
        transaction_id: Id::new("restore/transaction")?,
        generation: 1.into(),
        allocation: PacketCompleteRestoreInputAllocation {
            maximum_known_requested_bytes: (64 * 1024 * 1024).into(),
            maximum_input_bytes: (8 * 1024 * 1024).into(),
            maximum_nodes: 65536.into(),
            maximum_depth: 32.into(),
            maximum_owned_backing_bytes: (8 * 1024 * 1024).into(),
            maximum_tree_entries: 4096.into(),
            maximum_metadata_rows: 16384.into(),
            maximum_literal_backing_bytes: (8 * 1024 * 1024).into(),
            maximum_content_transfers: 1024.into(),
            maximum_content_objects: 1024.into(),
            maximum_content_groups: 1024.into(),
            maximum_content_bytes: (8 * 1024 * 1024).into(),
            maximum_content_metadata_bytes: (1024 * 1024).into(),
            maximum_model_bytes: (1024 * 1024).into(),
        },
    };
    let proof = PacketCompleteRestoreTransferProof {
        schema: PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION.into(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
        context_digest: Bytes::new(vec![2; 32]),
        mac: Bytes::new(vec![3; 32]),
    };
    let arguments = PrepareRestoreArguments {
        transaction_id: request.transaction_id.clone(),
        capture_manifest: reference,
        expected_world_binding_hash: request.restoration.target_world.clone(),
        expected_owner_binding_hash: owner_hash.clone(),
        destination_owner_ids: vec![owner.owner.id.clone()],
    };
    let arguments = serde_json::to_value(arguments)?;
    let begin = BeginRequest {
        kind: BeginKind::PrepareRestore,
        binding_hash: owner_hash,
        owner_generation: binding.authority.owner_generation,
        activation_id: Nullable(Some(request.restoration.target_activation.clone())),
        world_generation: 1.into(),
        arguments: arguments.as_object().ok_or("arguments object")?.clone(),
        extensions: Default::default(),
    };
    let body = serde_json::to_value(begin)?;
    Ok(
        crate::client::CnpController::original_assigned_transfer_envelope_fixture_data(
            authority,
            &crate::client::ControllerRoute {
                node: binding.compatibility.node_id.clone(),
                execution_owner: owner.owner.id.clone(),
            },
            Id::new("prepare/original")?,
            1.into(),
            body.as_object().ok_or("Begin object")?.clone(),
            [
                (
                    PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION.into(),
                    serde_json::to_value(request)?,
                ),
                (
                    PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION.into(),
                    serde_json::to_value(proof)?,
                ),
            ]
            .into(),
        ),
    )
}

#[test]
fn actual_typed_prepare_passes_closed_header_and_independent_scope_changes_refuse() -> TestResult {
    let (_handshake, authority, selection, _installed) = original_canonical_ack_controller_scope();
    let actual = original(&selection, &authority)?;
    authenticate_original_native_prepare_header_data(&selection, false, &actual)?;
    assert!(matches!(
        crate::bodies::decode_request(actual.method, &actual.body)?,
        RequestBody::Begin(_)
    ));

    for group in 0..11 {
        let mut changed = actual.clone();
        match group {
            0 => changed.session_id = Nullable(Some(Id::new("foreign/session")?)),
            1 => changed.incarnation_id = Nullable(Some(Id::new("foreign/incarnation")?)),
            2 => changed.node_id = Nullable(Some(Id::new("foreign/node")?)),
            3 => changed.execution_owner_id = Nullable(Some(Id::new("foreign/owner")?)),
            4 => changed.capture_owner_id = Nullable(Some(Id::new("unexpected/capture")?)),
            5 => changed.method = Method::Observe,
            6 => changed.message = MessageKind::Response,
            7 => {
                changed.body.insert("kind".into(), "capture".into());
            }
            8 => {
                changed
                    .extensions
                    .insert("unknown/extension".into(), true.into());
            }
            9 => changed.operation_id = Nullable(Some(Id::new("unexpected/operation")?)),
            _ => changed.request_id = Nullable(None),
        }
        assert!(
            authenticate_original_native_prepare_header_data(&selection, false, &changed).is_err(),
            "group {group}"
        );
    }
    Ok(())
}

#[test]
fn actual_prepare_closed_arguments_and_extension_limits_precede_typed_decode() -> TestResult {
    let (_handshake, authority, selection, _installed) = original_canonical_ack_controller_scope();
    let actual = original(&selection, &authority)?;
    authenticate_original_native_prepare_header_data(&selection, false, &actual)?;

    let mut changed = actual.clone();
    changed.body.get_mut("arguments").ok_or("arguments")?["destination_owner_ids"] =
        serde_json::json!(["foreign/owner"]);
    assert!(authenticate_original_native_prepare_header_data(&selection, false, &changed).is_err());
    let mut changed = actual.clone();
    changed.body.get_mut("arguments").ok_or("arguments")?["extra"] = true.into();
    assert!(authenticate_original_native_prepare_header_data(&selection, false, &changed).is_err());
    let mut changed = actual.clone();
    changed
        .extensions
        .get_mut(PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION)
        .ok_or("request")?["restoration"]["backend_schema"]["extensions"] =
        serde_json::json!({"large": "x".repeat(MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES)});
    assert!(authenticate_original_native_prepare_header_data(&selection, false, &changed).is_err());
    assert!(crate::bodies::decode_request(actual.method, &actual.body).is_ok());
    Ok(())
}
