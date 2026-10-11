//! Verifies genuine reconstructed event-zero peers cannot claim original birth.

// Panics report failure of actual native lineage and supervised reclamation.
// crucible-lint: allow panic-shortcut -- Actual child lineage and owning reclamation failures invalidate the native witness.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;

use crucible_node_provider::gem5::Gem5RestoreTarget;

use super::*;

#[test]
#[ignore = "requires the compiled RF native package and genuine DMTCP reconstruction"]
fn independently_qualified_restored_at_zero_refuses_original_preparation() {
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = InstalledMixedEngine::new(directory, 8).unwrap();
    let _cleanup = OriginalNativeCleanup(&engine);
    let profile = MixedProfile::build_public(
        engine.installed.clone(),
        &measure_executable(&engine.host).unwrap(),
        "x86_64",
    )
    .unwrap();
    let source_activation = fresh_target(&profile, None).unwrap();
    let source_owner = cpu_owner(&source_activation).unwrap();
    let namespace = engine.namespace().unwrap();
    let source_slot = engine
        .native
        .reserve(NativeOwnerScope {
            activation: source_activation.clone(),
            owner: source_owner,
            publication: PublicationKnowledge::NotAttempted,
            backing: NativeBacking::Fresh {
                files: [
                    "native_executable",
                    "controller",
                    "model",
                    "auditor",
                    "image_guard",
                    "dmtcp_launch",
                    "dmtcp_restart",
                    "mtcp_restart",
                ]
                .into_iter()
                .map(|key| File::open(engine.installed.artifact(key).unwrap().path).unwrap())
                .chain(std::iter::once(
                    File::open(engine.installed.guest("x86_64").unwrap().path).unwrap(),
                ))
                .collect(),
            },
        })
        .unwrap();
    let mut source = Gem5NativeProcess::spawn(
        launch(
            &engine.installed,
            "x86_64",
            &cpu_owner(&source_activation).unwrap(),
            &namespace,
        )
        .unwrap(),
        source_slot,
    )
    .unwrap();
    let image = source
        .capture(
            Id::new("preparation/original-zero").unwrap(),
            &namespace.join("initial"),
        )
        .unwrap();
    let auditor = engine.installed.artifact("auditor").unwrap();
    let certificate = source
        .qualify_capture(&image, &namespace, &auditor, engine.installed.as_ref())
        .unwrap();
    let source_authority = source
        .qualify_exact(
            &image,
            &certificate,
            &auditor,
            engine.installed.as_ref(),
            engine.installed.maximum_microsteps(),
        )
        .unwrap();
    let original_packet = source
        .initial_prepared_session(&source_authority)
        .unwrap()
        .packet();
    let original_packet = (original_packet.0.clone(), original_packet.1.to_vec());
    original_packet.0.verify(&original_packet.1).unwrap();

    let mut target_activation = source_activation;
    target_activation.activation_id = Id::new("preparation/restored-zero").unwrap();
    target_activation.generation = U64::new(2);
    let target_owner = target_activation
        .owners
        .iter_mut()
        .find(|owner| owner.owner.as_str() == "owner/cpu")
        .unwrap();
    target_owner.incarnation = Id::new("preparation/restored-zero-owner").unwrap();
    target_owner.generation = U64::new(target_owner.generation.get() + 1);
    let target_owner = target_owner.clone();
    let restored_namespace = engine.namespace().unwrap();
    let restored_slot = engine
        .native
        .reserve(NativeOwnerScope {
            activation: target_activation,
            owner: target_owner.clone(),
            publication: PublicationKnowledge::NotAttempted,
            backing: NativeBacking::Fresh {
                files: image
                    .artifacts()
                    .map(|artifact| File::open(&artifact.path).unwrap())
                    .collect(),
            },
        })
        .unwrap();
    let mut restored = Gem5NativeProcess::restore(
        &image,
        Gem5RestoreTarget {
            incarnation: target_owner.incarnation,
            generation: target_owner.generation,
            resource_root: restored_namespace.join("native"),
            image_root: restored_namespace.join("images"),
            temporary_root: restored_namespace.join("temporary"),
            timeout: Duration::from_secs(60),
        },
        restored_slot,
    )
    .unwrap();
    let current_image = restored
        .capture(
            Id::new("preparation/restored-current-zero").unwrap(),
            &restored_namespace.join("initial"),
        )
        .unwrap();
    let current_certificate = restored
        .qualify_capture(
            &current_image,
            &restored_namespace,
            &auditor,
            engine.installed.as_ref(),
        )
        .unwrap();
    let fresh_authority = restored
        .qualify_exact(
            &current_image,
            &current_certificate,
            &auditor,
            engine.installed.as_ref(),
            engine.installed.maximum_microsteps(),
        )
        .unwrap();

    assert_eq!(
        restored.logical_position(),
        Position::new(0.into(), 0.into(), Phase::BoundaryControl)
    );
    assert!(
        restored
            .initial_prepared_session(&source_authority)
            .is_err()
    );
    assert!(restored.initial_prepared_session(&fresh_authority).is_err());
    let retained = source
        .initial_prepared_session(&source_authority)
        .unwrap()
        .packet();
    assert_eq!(retained.0, &original_packet.0);
    assert_eq!(retained.1, original_packet.1.as_slice());

    drop(restored);
    drop(source);
    reclaim_original_native(&engine);
}

struct OriginalNativeCleanup<'a>(&'a InstalledMixedEngine);

impl Drop for OriginalNativeCleanup<'_> {
    fn drop(&mut self) {
        reclaim_original_native(self.0);
    }
}

fn reclaim_original_native(engine: &InstalledMixedEngine) {
    let mut originals = Vec::new();
    for _ in 0..6000 {
        match engine.native.take_reclaimed() {
            Ok(retired) => originals.extend(retired),
            Err(error) if !std::thread::panicking() => panic!("{error}"),
            Err(_) => {}
        }
        if engine.native.reserved_owners() == 0 && engine.native.all_groups_reclaimed() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !std::thread::panicking() {
        panic!("original preparation peers remain quarantined without authentic group proof");
    }
    eprintln!("original preparation peers remain owned by the installed cleanup actor");
}
