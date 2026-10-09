//! Installed-package measurement and refusal checks without native authority.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

use crucible_node_contract::Id;
use crucible_node_provider::gem5::Gem5ProcessImageTools;

use super::*;

fn installed_manifest_path() -> &'static Path {
    // Ordinary application test targets may compile without the native package.
    // Explicitly running these ignored qualification checks requires its pin.
    match option_env!("CRUCIBLE_GEM5_CLOSED_PROFILE_MANIFEST") {
        Some(path) => Path::new(path),
        None => panic!("requires the compile-time source-built gem5 closed-profile package"),
    }
}

fn installed_manifest() -> serde_json::Value {
    let bytes = fs::read(installed_manifest_path()).unwrap();
    canonical::parse_json(&bytes, MAX_MANIFEST_BYTES).unwrap()
}

fn installed_launch(policy: &InstalledGem5ClosedProfile, root: &Path) -> Gem5Launch {
    Gem5Launch {
        executable: policy.artifact("native_executable").unwrap(),
        owner_script: policy.artifact("controller").unwrap(),
        model_script: policy.artifact("model").unwrap(),
        guest: policy.guest("x86_64").unwrap(),
        guest_isa: "x86_64".into(),
        owner: Id::new("installed-policy-test-owner").unwrap(),
        incarnation: Id::new("installed-policy-test-incarnation").unwrap(),
        generation: U64::new(1),
        resource_root: root.into(),
        timeout: Duration::from_secs(1),
        process_images: Some(Gem5ProcessImageTools {
            launcher: policy.artifact("dmtcp_launch").unwrap(),
            restarter: policy.artifact("dmtcp_restart").unwrap(),
            reconstruction_executable: policy.artifact("mtcp_restart").unwrap(),
            resource_helper: policy.artifact("image_guard").unwrap(),
            image_root: root.join("images"),
            temporary_root: root.join("temporary"),
        }),
    }
}

#[test]
#[ignore = "requires the compile-time source-built gem5 qualification package"]
fn actual_installed_package_measures_and_refuses_foreign_launch_scope() {
    let policy = InstalledGem5ClosedProfile::built_in().unwrap();
    let root = tempfile::tempdir().unwrap();
    let guest = policy.guest("x86_64").unwrap();
    let guest_bytes = fs::read(&guest.path).unwrap();

    assert_eq!(
        guest.content,
        canonical::content_ref(&guest_bytes, "application/octet-stream").unwrap()
    );
    assert_eq!(policy.maximum_microsteps(), U64::new(1_000_000));
    assert!(policy.guest("riscv64").is_err());
    assert!(policy.artifact("caller_executable").is_err());

    let launch = installed_launch(&policy, root.path());
    let auditor = policy.artifact("auditor").unwrap();
    policy.verify_opaque_profile(&launch, &auditor).unwrap();
    policy
        .verify_superdense_mapping(&launch, policy.maximum_microsteps())
        .unwrap();

    let mut changed = launch.clone();
    changed.guest = policy.guest("aarch64").unwrap();
    assert!(policy.verify_opaque_profile(&changed, &auditor).is_err());
    changed = launch.clone();
    changed.executable.path = root.path().join("uninstalled-gem5");
    assert!(policy.verify_opaque_profile(&changed, &auditor).is_err());
    changed = launch.clone();
    changed.model_script.content.hash.digest = "0".repeat(64);
    assert!(policy.verify_opaque_profile(&changed, &auditor).is_err());
    changed = launch.clone();
    changed.process_images = None;
    assert!(policy.verify_opaque_profile(&changed, &auditor).is_err());
    assert!(
        policy
            .verify_superdense_mapping(&launch, U64::new(1_000_001))
            .is_err()
    );
}

#[test]
#[ignore = "requires the compile-time source-built gem5 qualification package"]
fn actual_managed_copies_preserve_policy_and_refuse_changed_routes_or_bytes() {
    let policy = InstalledGem5ClosedProfile::built_in().unwrap();
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut launch = installed_launch(&policy, root.path());
    for (artifact, name) in [
        (&mut launch.owner_script, "native-owner.py"),
        (&mut launch.model_script, "native-owner-model.py"),
        (&mut launch.guest, "guest.elf"),
    ] {
        let target = root.path().join(name);
        fs::copy(&artifact.path, &target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        artifact.path = target;
    }
    let auditor = policy.artifact("auditor").unwrap();
    policy.verify_opaque_profile(&launch, &auditor).unwrap();
    policy
        .verify_superdense_mapping(&launch, policy.maximum_microsteps())
        .unwrap();

    let mut changed = launch.clone();
    changed.guest.path = root.path().join("guest-renamed.elf");
    fs::copy(&launch.guest.path, &changed.guest.path).unwrap();
    assert!(policy.verify_opaque_profile(&changed, &auditor).is_err());
    fs::remove_file(&changed.guest.path).unwrap();

    let mut guest_bytes = fs::read(&launch.guest.path).unwrap();
    guest_bytes[0] ^= 1;
    fs::write(&launch.guest.path, &guest_bytes).unwrap();
    assert!(policy.verify_opaque_profile(&launch, &auditor).is_err());
    guest_bytes[0] ^= 1;
    fs::write(&launch.guest.path, &guest_bytes).unwrap();

    let alias = root.path().join("guest-alias");
    fs::hard_link(&launch.guest.path, &alias).unwrap();
    assert!(policy.verify_opaque_profile(&launch, &auditor).is_err());
    fs::remove_file(alias).unwrap();
    fs::remove_file(&launch.guest.path).unwrap();
    std::os::unix::fs::symlink(policy.guest("x86_64").unwrap().path, &launch.guest.path).unwrap();
    assert!(policy.verify_opaque_profile(&launch, &auditor).is_err());
    fs::remove_file(&launch.guest.path).unwrap();
    fs::write(&launch.guest.path, guest_bytes).unwrap();
    fs::set_permissions(&launch.guest.path, fs::Permissions::from_mode(0o600)).unwrap();

    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(policy.verify_opaque_profile(&launch, &auditor).is_err());
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    policy.verify_opaque_profile(&launch, &auditor).unwrap();
}

#[test]
#[ignore = "requires the compile-time source-built gem5 qualification package"]
fn actual_package_metadata_cannot_broaden_qualification() {
    let original = installed_manifest();
    let parsed: Manifest = serde_json::from_value(original.clone()).unwrap();
    parsed.validate().unwrap();

    for (field, replacement) in [
        (
            "full_system_device_parity_qualified",
            serde_json::json!(true),
        ),
        ("modeled_diagnostics_complete", serde_json::json!(true)),
        ("policy_version", serde_json::json!("2")),
    ] {
        let mut changed = original.clone();
        changed[field] = replacement;
        let parsed: Manifest = serde_json::from_value(changed).unwrap();
        assert!(parsed.validate().is_err(), "accepted changed {field}");
    }
    for isa in ["x86_64", "aarch64"] {
        for field in [
            "source_dead_before_restore",
            "group_reclaimed",
            "full_position_single_callback_at_budget_ceiling",
            "original_receipt_retry",
            "fresh_reconstruction_capture_closure",
            "original_image_namespace_absent",
            "authenticated_saved_copy_relocation",
            "private_launch_artifact_modes_preserved",
        ] {
            let mut changed = original.clone();
            changed["witnesses"][isa][field] = serde_json::json!(false);
            let parsed: Manifest = serde_json::from_value(changed).unwrap();
            assert!(
                parsed.validate().is_err(),
                "accepted incomplete {field} for {isa}"
            );
        }
        for field in [
            "fresh_reconstruction_capture_closure",
            "original_image_namespace_absent",
            "authenticated_saved_copy_relocation",
            "private_launch_artifact_modes_preserved",
        ] {
            let mut changed = original.clone();
            changed["witnesses"][isa]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                serde_json::from_value::<Manifest>(changed).is_err(),
                "accepted legacy witness without {field} for {isa}"
            );
        }
    }
    let mut changed = original.clone();
    changed["model"]["ingress"] = serde_json::json!(["stdin"]);
    let parsed: Manifest = serde_json::from_value(changed).unwrap();
    assert!(parsed.validate().is_err());
    let mut changed = original.clone();
    changed["guests"]["x86_64"]["syscalls"] = serde_json::json!(["read", "exit"]);
    let parsed: Manifest = serde_json::from_value(changed).unwrap();
    assert!(parsed.validate().is_err());

    let mut changed = original.clone();
    changed["operator_qualification_override"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Manifest>(changed).is_err());
    for pointer in [
        "/source",
        "/model",
        "/witnesses/x86_64",
        "/witnesses/x86_64/host_abi",
        "/source/patches/0",
        "/dmtcp_patches/0",
    ] {
        let mut changed = original.clone();
        changed.pointer_mut(pointer).unwrap()["qualification_override"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<Manifest>(changed).is_err(),
            "accepted an unknown field under {pointer}"
        );
    }
    let root = installed_manifest_path().parent().unwrap();
    for pointer in ["/source/recipeSha256", "/source/patches/0/sha256"] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = serde_json::json!("0".repeat(64));
        let parsed: Manifest = serde_json::from_value(changed).unwrap();
        assert!(
            parsed.measure_provenance(root).is_err(),
            "accepted changed {pointer}"
        );
    }
    let mut changed = original.clone();
    changed["source"]["patches"][0]["file"] = serde_json::json!("../outside.patch");
    let parsed: Manifest = serde_json::from_value(changed).unwrap();
    assert!(parsed.measure_provenance(root).is_err());

    let mut changed = original;
    changed["source_artifacts"]["gem5-upstream.tar.gz"]["sha256"] =
        serde_json::json!("0".repeat(64));
    let parsed: Manifest = serde_json::from_value(changed).unwrap();
    assert!(parsed.measure_provenance(root).is_err());
}
