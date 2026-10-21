//! Exercises canonical launch commitments as DATA without live startup owners.

use super::super::inert_bootstrap_fixtures;
use super::*;

fn launch() -> PacketNative5SourceLaunch {
    let mut selected = inert_bootstrap_fixtures::selected_launch(false);
    serde_json::from_value(selected["launch"].take()).unwrap()
}

fn encode(launch: &PacketNative5SourceLaunch) -> Vec<u8> {
    canonical::canonical_json(&serde_json::to_value(launch).unwrap()).unwrap()
}

#[test]
fn canonical_derivation_matches_the_independent_base5_correspondence_path() {
    let launch = launch();
    let private = Id::new("original-private-launch").unwrap();
    let base5 = encode(&launch);
    let actual =
        derive_native_import18_launch_identity_data(&launch, &private, base5.len()).unwrap();
    let checked =
        native_import18_launch_identity_data(&launch, &base5, &private, base5.len()).unwrap();

    assert_eq!(
        actual.selected_launch_identity_data(),
        checked.selected_launch_identity_data()
    );
    assert_eq!(
        actual.private_launch_identity_data(),
        checked.private_launch_identity_data()
    );
    assert_eq!(
        actual.selected_launch_identity_data(),
        blake3::derive_key(
            "source-owned.packet-native-import-selected-launch-identity/18",
            &base5
        )
    );
    assert!(
        derive_native_import18_launch_identity_data(&launch, &private, base5.len() - 1).is_err()
    );
    let mut changed = base5;
    changed[0] ^= 1;
    assert!(
        native_import18_launch_identity_data(&launch, &changed, &private, changed.len()).is_err()
    );
}

#[test]
fn launch_and_private_id_changes_affect_their_separate_commitments() {
    let mut launch = launch();
    let first = Id::new("first-private-launch").unwrap();
    let second = Id::new("other-private-launch").unwrap();
    let original =
        derive_native_import18_launch_identity_data(&launch, &first, usize::MAX).unwrap();
    let changed_private =
        derive_native_import18_launch_identity_data(&launch, &second, usize::MAX).unwrap();
    launch.controller_pid = U64::new(launch.controller_pid.get() + 1);
    let changed_launch =
        derive_native_import18_launch_identity_data(&launch, &first, usize::MAX).unwrap();

    assert_eq!(
        original.selected_launch_identity_data(),
        changed_private.selected_launch_identity_data()
    );
    assert_ne!(
        original.private_launch_identity_data(),
        changed_private.private_launch_identity_data()
    );
    assert_ne!(
        original.selected_launch_identity_data(),
        changed_launch.selected_launch_identity_data()
    );
    assert_eq!(
        original.private_launch_identity_data(),
        changed_launch.private_launch_identity_data()
    );
}

#[test]
fn construction_ignores_spare_capacity_without_discounting_retained_storage() {
    let mut launch = launch();
    let before = native_import18_launch_identity_construction_data(&launch, usize::MAX).unwrap();
    let prewalk = native_import18_launch_identity_projection_data(&launch).unwrap();
    let canonical = encode(&launch);
    let retained = crate::retained_metadata::observe_retained_native_launch(&launch).unwrap();

    let mut spare = Vec::with_capacity(4096);
    spare.extend_from_slice(launch.admission_token.as_slice());
    launch.admission_token = Bytes::new(spare);
    if let crate::reference_packet::service::PacketConnectedSourceProgram::Producer { program } =
        &mut launch.program
    {
        program.events.reserve_exact(1024);
    }

    assert_eq!(
        before,
        native_import18_launch_identity_construction_data(&launch, usize::MAX).unwrap()
    );
    assert_eq!(
        prewalk,
        native_import18_launch_identity_projection_data(&launch).unwrap()
    );
    assert_eq!(canonical, encode(&launch));
    let after = crate::retained_metadata::observe_retained_native_launch(&launch).unwrap();
    assert!(after.vector_capacity_bytes > retained.vector_capacity_bytes);
}
