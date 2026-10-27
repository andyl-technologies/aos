//! Runs the complete packet fixture against a separately built provider binary.
//!
//! The executable is measured before graph installation. Declaration helpers
//! populate immutable rosters before binding hashes; no declaration is a live
//! restoration ticket, native readiness result or operation permission.

use super::*;
use crucible_node_transport::reference_packet::service::{
    PacketNative5ConfirmationSelection, ack_emitter::PacketNative5AckEmitterSelection,
};

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
