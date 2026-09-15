//! Acceptance tests for the persisted two-axis generation model.

use aos_package::types::{
    ConfigGeneration, ConfigGenerationState, ImageGeneration, ImageGenerationState, ImageSlot,
    PackageModule, PackageModuleOrigin,
};

fn config_generation(parent: u32, abi: u32) -> ConfigGeneration {
    ConfigGeneration {
        number: 7,
        created_at: "2026-01-01T00:00:00Z".into(),
        image_gen_parent: parent,
        module_abi_pinned: abi,
        manifest_hash: "sha256:manifest".into(),
        package_modules: vec![PackageModule {
            package: "service".into(),
            document_digest: format!("sha256:{}", "a".repeat(64)),
            store_path: "/nix/store/cfg-config".into(),
            nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            entrypoint: "module.nix".into(),
            origin: PackageModuleOrigin::Registry,
        }],
        host_nix_ref: "/nix/store/host-host.nix".into(),
        host_nix_commit: None,
        facts_hash: "sha256:facts".into(),
        facts_ref: "/nix/store/facts-json".into(),
        base_lib_ref: "/nix/store/base-lib".into(),
        evaluator_ref: "/nix/store/evaluator".into(),
    }
}

#[test]
fn generation_axes_round_trip_independently() {
    let image = ImageGeneration {
        number: 3,
        slot: ImageSlot::A,
        uki_path: "EFI/Linux/aos-3+3.efi".into(),
        uki_source_path: None,
        toplevel: "/nix/store/top-aos".into(),
        package_name: "aos".into(),
        version: "3".into(),
        state_version: "1".into(),
        native_executor_ref: "/nix/store/executor".into(),
        registry: "core".into(),
        kernel_path: Some("/nix/store/kernel".into()),
        evaluator_ref: "/nix/store/base-lib".into(),
        module_abi: 9,
        base_lib_abi_hash: "sha256:base".into(),
        root_verity_roothash: None,
        initrd_pcr11: None,
        expected_pcr11: None,
        recovery: None,
        created_at: "2026-01-01T00:00:00Z".into(),
    };
    let images = ImageGenerationState {
        running: 3,
        default: 3,
        pending: None,
        recovery_known_good: None,
        recovery_pending: None,
        active_rollout: None,
        last_rollout: None,
        generations: vec![image],
    };
    let decoded: ImageGenerationState =
        serde_json::from_str(&serde_json::to_string(&images).expect("serialize image state"))
            .expect("parse image state");
    assert_eq!(
        decoded
            .running_generation()
            .expect("running image")
            .module_abi,
        9
    );

    let configs = ConfigGenerationState {
        current: 7,
        next: 8,
        generations: vec![config_generation(3, 9)],
    };
    let encoded = serde_json::to_string(&configs).expect("serialize config state");
    assert!(!encoded.contains("toplevel"));
    assert!(!encoded.contains("kernel_path"));
    let decoded: ConfigGenerationState =
        serde_json::from_str(&encoded).expect("parse config state");
    assert_eq!(decoded.generations[0].image_gen_parent, 3);
    assert_eq!(decoded.generations[0].module_abi_pinned, 9);
    assert_eq!(decoded.generations[0].package_modules[0].package, "service");
}

#[test]
fn cross_image_same_abi_directly_reactivates() {
    let target = config_generation(2, 9);
    assert!(matches!(
        target.reactivation_plan(9).expect("plan"),
        aos_package::types::ReactivationPlan::DirectReactivate
    ));
}

#[test]
fn cross_abi_reactivation_replays_retained_inputs() {
    let target = config_generation(2, 8);
    let plan = target
        .reactivation_plan(9)
        .expect("retained inputs permit cross-ABI replay");
    let aos_package::types::ReactivationPlan::CrossAbiReEval(inputs) = plan else {
        panic!("different ABI must never directly reactivate");
    };
    assert_eq!(inputs.from_module_abi, 8);
    assert_eq!(inputs.to_module_abi, 9);
    assert_eq!(
        inputs.package_modules[0].store_path,
        "/nix/store/cfg-config"
    );
    assert_eq!(inputs.host_nix_ref, "/nix/store/host-host.nix");
    assert_eq!(inputs.facts_ref, "/nix/store/facts-json");
}

#[test]
fn legacy_bundled_state_is_not_live_config_authority() {
    let legacy = r#"{
        "current": 1,
        "next": 2,
        "generations": [{
            "number": 1,
            "toplevel": "/nix/store/top-aos",
            "version": "1",
            "package_name": "aos",
            "registry": "core",
            "created_at": "2026-01-01T00:00:00Z"
        }]
    }"#;
    let error = serde_json::from_str::<ConfigGenerationState>(legacy)
        .expect_err("legacy bundled records must require authenticated migration");
    assert!(error.to_string().contains("image_gen_parent"));
}

#[test]
fn generation_state_rejects_parallel_package_module_vectors() {
    let state = ConfigGenerationState {
        current: 7,
        next: 8,
        generations: vec![config_generation(3, 9)],
    };
    let mut encoded = serde_json::to_value(state).expect("serialize config state");
    let obsolete_field = ["package_module_", "paths"].concat();
    encoded["generations"][0][obsolete_field] = serde_json::json!(["/nix/store/cfg-config"]);

    let error = serde_json::from_value::<ConfigGenerationState>(encoded)
        .expect_err("parallel package-module vectors must fail closed");
    assert!(
        error
            .to_string()
            .contains(&["package_module_", "paths"].concat()),
        "{error}"
    );
}
