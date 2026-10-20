//! Runs the complete packet fixture against a separately built provider binary.
//!
//! The executable is measured before graph installation. Declaration helpers
//! populate immutable rosters before binding hashes; no declaration is a live
//! restoration ticket, native readiness result or operation permission.

use super::*;
use crucible_node_format::{ProviderManifest, Validate};
use crucible_node_transport::reference_packet::{
    continuation_contracts::{
        PacketNative5CompleteRestoreDeclaration,
        complete_packet_fresh_restore_allocation_declaration,
    },
    service::{
        PacketNative5ConfirmationSelection,
        ack_emitter::PacketNative5AckEmitterSelection,
        capture_allocation::PacketNative5CaptureAllocationSelection,
        complete_restore::{
            PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
            activation::{
                PACKET_RESTORATION_ACTIVATION_FEATURE, restoration_activation_contract_data,
                restoration_activation_schema,
                upload::{
                    PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
                    restoration_activation_upload_contract_data,
                    restoration_activation_upload_schema,
                },
            },
            restoration_observe::{
                PACKET_RESTORATION_OBSERVE_FEATURE, restoration_observe_contract_data,
                restoration_observe_schema,
            },
        },
        fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
        native_snapshot::{native_owned14_snapshot_contract, native_owned14_snapshot_schema},
        native_startup::{
            PACKET_RESTORATION_SUFFIX_FEATURE, restoration_suffix_contract_data,
            restoration_suffix_schema,
        },
    },
};

pub(super) fn restore_declaration(
    provider: &ProviderManifest,
    confirmation: Option<&PacketNative5ConfirmationSelection>,
    ack: Option<&PacketNative5AckEmitterSelection>,
) -> PacketNative5CompleteRestoreDeclaration {
    let mut declaration = complete_packet_fresh_restore_allocation_declaration(
        provider,
        confirmation,
        ack,
        Some(&PacketNative5CompleteRestoreSelection::SourceSignedTransfer12),
        Some(&PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12),
        Some(&PacketNative5CaptureAllocationSelection::OriginalObserve12),
        Some(&PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13),
    )
    .unwrap();

    // Original execution keeps its observation declaration and startup15. The
    // same immutable suffix grammar is available to a distinct ticketed target;
    // merely listing it here never selects the suffix constructor.
    let definitions = [
        (
            native_owned14_snapshot_schema().unwrap(),
            native_owned14_snapshot_contract().unwrap(),
        ),
        (
            restoration_activation_schema().unwrap(),
            restoration_activation_contract_data().to_vec(),
        ),
        (
            restoration_activation_upload_schema().unwrap(),
            restoration_activation_upload_contract_data().to_vec(),
        ),
        (
            restoration_observe_schema().unwrap(),
            restoration_observe_contract_data().to_vec(),
        ),
        (
            restoration_suffix_schema().unwrap(),
            restoration_suffix_contract_data().to_vec(),
        ),
    ];
    for (schema, bytes) in definitions {
        schema.definition.verify(&bytes).unwrap();
        let formats = &mut declaration.peer.provider.implementation.formats;
        if let Some(previous) = formats.iter().find(|one| one.id == schema.id) {
            assert_eq!(previous, &schema);
        } else {
            formats.push(schema.clone());
        }
        declaration.restoration.push((schema, bytes));
    }
    for feature in [
        PACKET_RESTORATION_ACTIVATION_FEATURE,
        PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
        PACKET_RESTORATION_OBSERVE_FEATURE,
        PACKET_RESTORATION_SUFFIX_FEATURE,
    ] {
        let features = &mut declaration.peer.provider.extensions_supported;
        let feature = id(feature);
        if !features.contains(&feature) {
            features.push(feature);
        }
    }
    declaration
        .peer
        .provider
        .implementation
        .formats
        .sort_by(|a, b| a.id.cmp(&b.id));
    declaration.peer.provider.extensions_supported.sort();
    declaration.peer.provider.validate().unwrap();
    declaration
}

pub(super) fn scene(executable: &std::path::Path) -> Scene {
    Scene::with_selected_report_startup_executable(
        false,
        &[1, 2],
        Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5),
        Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5),
        true,
        Some(64 * 1024),
        Some(executable),
    )
}

pub(in super::super) fn declaration(executable: &std::path::Path) -> (Scene, serde_json::Value) {
    let scene = scene(executable);
    let mut declaration = super::scene_declaration(&scene);
    declaration["schema"] = serde_json::json!("crucible.complete-scene.installation/5");
    declaration["mechanism"] = serde_json::json!({
        "complete_restore": "SourceSignedTransfer12",
        "restore_input_emitter": "CanonicalSdkRestoreInputs12",
        "fresh_restore_allocation": "completed_admit13",
    });
    declaration["resources"]["memory_bytes"] =
        serde_json::to_value(crucible_node_format::U64::new(4u64 * 1024 * 1024 * 1024)).unwrap();

    let peer = scene.measurements.peer.content.length.get();
    let host = scene.measurements.host.length.get();
    // Graph admission fetches each of the three native implementation artifacts
    // independently, plus the Host implementation. Keep the explicit 64MiB
    // metadata-fetch allowance beside those actual repeated file occurrences.
    let content = peer
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(host))
        .and_then(|bytes| bytes.checked_add(64 * 1024 * 1024))
        .unwrap();
    declaration["resources"]["content_bytes"] =
        serde_json::to_value(crucible_node_format::U64::new(content)).unwrap();
    (scene, declaration)
}

/// Declares finite fetch and archive budgets for the actual measured artifacts.
pub(in super::super) fn capture_declaration(
    executable: &std::path::Path,
) -> (
    Scene,
    serde_json::Value,
    crucible_engine::node_state::NativeArchiveLimits,
) {
    let (scene, declaration) = declaration(executable);
    let peer = scene.measurements.peer.content.length.get();
    let host = scene.measurements.host.length.get();
    let content: crucible_node_format::U64 =
        serde_json::from_value(declaration["resources"]["content_bytes"].clone()).unwrap();
    let mut limits = crucible_engine::node_state::NativeArchiveLimits::default();
    limits.state.maximum_content_bytes = limits
        .state
        .maximum_content_bytes
        .max(usize::try_from(peer.max(host)).unwrap());
    limits.state.maximum_total_content_bytes = usize::try_from(content.get()).unwrap();
    (scene, declaration, limits)
}

#[path = "native_roundtrip/target_declaration.rs"]
mod target_declaration;
pub(in super::super) use target_declaration::{target_declaration, target_declaration_for};
