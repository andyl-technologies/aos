//! Builds inert wire DTO fixtures, never opaque Initial/Recipe or native owners.

use super::super::restored_settled18::{
    NATIVE_IMPORT18_PRIVATE_BOOT_SCHEMA, NATIVE_IMPORT18_SOURCE_BINDING_SCHEMA,
};
use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use serde_json::{Value, json};

/// Builds matching Source fields for DATA checks without validating a program.
pub(in crate::reference_packet) fn source_birth(launch: &PacketNative5SourceLaunch) -> Value {
    json!({
        "schema": "source-owned.packet-canonical-ack-source-binding/6",
        "selection": launch.selection,
        "program": launch.program,
        "coordinator": canonical::parse_json(launch.initial_coordinator.bytes.as_slice(), usize::MAX).unwrap(),
        "limits": launch.limits,
        "storage": launch.storage,
        "capture_profile": launch.capture_profile,
        "confirmation_selection": launch.confirmation_selection,
        "ack_emitter_selection": launch.ack_emitter_selection,
        "codec_metadata_extent": "CanonicalAck512KiB",
    })
}

pub(in crate::reference_packet) fn recipe() -> Value {
    json!({
        "schema": NATIVE_IMPORT18_PREBIRTH_RECIPE_SCHEMA,
        "native_family": "snapshot17",
        "source_family": "captured17",
        "semantic_spend_family": "complete18",
        "geometry_identity": ([0u8; 32]),
        "historical_shape_identity": ([0u8; 32]),
        "selected_launch_identity": ([0u8; 32]),
        "private_launch_identity": ([0u8; 32]),
        "lease_identity": ([0u8; 32]),
        "nonce": ([0u8; 32]),
        "generation": "1",
        "archived_reference_identities": ([[0u8; 32]; 5]),
        "archived_lengths": (["1"; 5]),
        "semantic_reference_identity": ([0u8; 32]),
        "semantic_length": "1",
        "decoder_limits": (["1"; 10]),
        "maximum_target_requested_bytes": "1",
        "maximum_before_bytes": "1",
        "normalization_projection_bytes": "1",
        "normalization_maximum": "1",
        "semantic_spend_maximum": "1",
        "escrow": (["1"; 3]),
        "phases": ([["1"; 3]; 5]),
        "identity": ([0u8; 32]),
    })
}

pub(in crate::reference_packet) fn boot(source_bytes: usize, registration: Value) -> Value {
    json!({
        "schema": NATIVE_IMPORT18_PRIVATE_BOOT_SCHEMA,
        "private_key": Bytes::new(vec![23; 32]),
        "birth_id": Bytes::new(vec![17; 32]),
        "source_birth": {
            "schema": NATIVE_IMPORT18_SOURCE_BINDING_SCHEMA,
            "declaration": {
                "schema": NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA,
                "source_birth": Bytes::new(vec![255; source_bytes]),
                "fresh_restore_allocation_selection": "completed_admit13",
            },
            "mechanism": "SourceSignedImport18",
            "prebirth_recipe": recipe(),
            "initial_funding": {
                "retained_requested_bytes": "1",
                "maximum_simultaneous_transient_bytes": "1",
                "declared_counter_scratch_bytes": "1",
            },
        },
        "expected_host_registration": registration,
        "private_launch": "private.data",
        "host_executable": canonical::content_ref(b"inert", "application/octet-stream").unwrap(),
    })
}

pub(in crate::reference_packet) fn selected_launch(reactive: bool) -> Value {
    let (_, _, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    // Real closed DTOs exercise the nested container layouts. The empty model
    // deliberately supplies no validated native launch or Source authority.
    let program = if reactive {
        json!({
            "kind": "reactive",
            "program": {
                "schema": "source-owned.packet-connected-program/4",
                "connections": [],
                "output": null,
            },
        })
    } else {
        json!({
            "kind": "producer",
            "program": {"schema": "source-owned.packet-program.v1", "events": []},
        })
    };
    json!({
        "schema_version": 9,
        "mechanism": "SourceSignedImport18",
        "prebirth_recipe_identity": ([0u8; 32]),
        "initial_funding": {
            "retained_requested_bytes": "1",
            "maximum_simultaneous_transient_bytes": "1",
            "declared_counter_scratch_bytes": "1",
        },
        "launch": {
            "schema_version": 5,
            "selection": selection,
            "program": program,
            "controller_pid": "1",
            "controller_uid": "0",
            "controller_executable": coordinator.reference,
            "admission_token": Bytes::new(vec![7; 32]),
            "initial_coordinator": coordinator,
            "limits": {
                "frame_bytes": "65536",
                "nesting": "64",
                "requests": "64",
                "journal_entries": "256",
                "blob_chunk_bytes": "1024",
            },
            "storage": {
                "snapshot_bytes": "16384",
                "control_snapshot_bytes": "8192",
                "protocol_snapshot_bytes": "65536",
                "frame_bank_bytes": "65536",
                "frames_per_direction": "256",
                "hello_bytes": "131080",
                "settlement_bytes": "65536",
            },
            "effects": "/not-opened-by-bootstrap-layout-control",
        },
    })
}
