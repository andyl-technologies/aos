//! Checks selected pre-Child library gates without issuing native permission.
//!
//! Every provider, binding and template comes from the selected fixture builder
//! before hashes. The tests measure only the original fixture files; they create
//! no Child, native key, Hello, assigned Admit, marker or active graph.

use super::*;
use crucible_engine::node_adapters::cnp::CnpSemanticSource;
use crucible_node_transport::reference_packet::service::{
    PacketNative5ConfirmationSelection, ack_emitter::PacketNative5AckEmitterSelection,
    confirmation::native_after_confirmation_schema,
};

fn selected_scene(native_extent: bool) -> Scene {
    Scene::with_selected_effect_phases(
        false,
        &[1, 2],
        Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5),
        Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5),
        native_extent,
    )
}

#[test]
fn selected_prechild_graph_authority_and_private_launch_gates_agree() {
    let scene = selected_scene(true);
    let launches = authority::launches(&scene);
    for launch in &launches {
        launch.validate().unwrap();
        assert_eq!(launch.selection.provider.implementation.formats.len(), 8);
    }
    let (owner, authority) =
        authority::try_collection_authority(&scene, authority::launches(&scene)).unwrap();
    authority.current().unwrap();
    for (member, launch) in launches.iter().enumerate() {
        authority
            .authenticate_private_peer(
                launch,
                &scene.measurements.peer.path,
                &scene._directory.path().join(format!("peer-{member}")),
            )
            .unwrap();
    }
    // These static gates authenticate preparation data and measured files only.
    assert!(scene.roster.current_native().is_err());
    assert!(
        owner
            .graph_policy()
            .unwrap()
            .authenticate_original_participants()
            .is_err()
    );
    assert!(scene.world.host_source.authenticate_current().is_err());
}

#[test]
fn selected_prechild_graph_requires_every_original_registered_definition_body() {
    let scene = selected_scene(true);
    let schema = native_after_confirmation_schema().unwrap();
    let mut missing = scene.world.content.clone();
    missing.remove(&schema.definition);
    assert!(PacketCompleteGraphOwner::install(scene.request(&missing)).is_err());

    let mut foreign = scene.world.content.clone();
    foreign.insert(schema.definition, br#"{"foreign":"confirmation"}"#.to_vec());
    assert!(PacketCompleteGraphOwner::install(scene.request(&foreign)).is_err());
}

#[test]
fn selected_prechild_authority_refuses_independently_unbound_native_extent() {
    // The definitions and graph use the same selected grammar. A launch with a
    // valid selected native codec still cannot replace the Source's own choice.
    let scene = selected_scene(false);
    let mut launches = authority::launches(&scene);
    for launch in &mut launches {
        launch.native_codec_metadata_extent = Some(
            crucible_node_transport::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
        );
        launch.validate().unwrap();
    }
    assert!(authority::try_collection_authority(&scene, launches).is_err());
}

#[test]
fn selected_private_launch_predicate_refuses_changed_original_directory() {
    let scene = selected_scene(true);
    let launches = authority::launches(&scene);
    let (_owner, authority) =
        authority::try_collection_authority(&scene, authority::launches(&scene)).unwrap();
    assert!(
        authority
            .authenticate_private_peer(
                &launches[0],
                &scene.measurements.peer.path,
                &scene._directory.path().join("foreign-peer"),
            )
            .is_err()
    );
    authority.current().unwrap();
}

#[test]
fn unselected_prechild_scene_keeps_five_formats_and_absent_marker_choices() {
    let scene = Scene::new();
    let launches = authority::launches(&scene);
    for launch in &launches {
        assert_eq!(launch.selection.provider.implementation.formats.len(), 5);
        assert!(launch.confirmation_selection.is_none());
        assert!(launch.ack_emitter_selection.is_none());
        assert!(launch.native_codec_metadata_extent.is_none());
        launch.validate().unwrap();
    }
    let (_owner, _authority) = authority::try_collection_authority(&scene, launches).unwrap();
}

#[test]
fn selected_launch_predicate_requires_each_independent_source_choice() {
    let scene = selected_scene(true);
    let [launch, _, _] = authority::launches(&scene);
    let source = &scene.roster.sources[0];
    let authenticate = super::super::authority::authenticate_expected_launch_selections;
    authenticate(source, &launch).unwrap();

    let [mut wrong_confirmation, _, _] = authority::launches(&scene);
    wrong_confirmation.confirmation_selection = None;
    assert!(authenticate(source, &wrong_confirmation).is_err());
    let [mut wrong_ack, _, _] = authority::launches(&scene);
    wrong_ack.ack_emitter_selection = None;
    assert!(authenticate(source, &wrong_ack).is_err());
    let mut wrong_extent = launch;
    wrong_extent.native_codec_metadata_extent = None;
    assert!(authenticate(source, &wrong_extent).is_err());
}

#[test]
fn confirmation_only_prechild_graph_requires_exact_six_registered_formats() {
    let scene = Scene::with_selected_effect_phases(
        false,
        &[1, 2],
        Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5),
        None,
        false,
    );
    for source in &scene.roster.sources {
        assert_eq!(
            source.installation().provider.implementation.formats.len(),
            6
        );
    }
    let _owner = PacketCompleteGraphOwner::install(scene.request(&scene.world.content)).unwrap();
    assert!(scene.roster.current_native().is_err());
}
