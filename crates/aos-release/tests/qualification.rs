//! Adversarial validation of the shared source-controlled qualification policy.
//!
//! The fixture is the contract exported by the Nix side; its destination
//! table is sorted by `<surface>/<tier>/<channel>`.

use aos_release::{
    canonical,
    plan::{ReleaseClass, SurfaceRole},
    qualification::{
        ChangeScope, ClaimSelection, PackageExecution, QualificationContract, QualificationPhase,
        QualificationScope, change_scope::CHANGE_SCOPE,
    },
    registry::{RegistryTier, channel_kind},
};

#[path = "../src/test_support/qualification/mod.rs"]
#[allow(dead_code)]
mod qualification_fixture;

fn contract() -> QualificationContract {
    qualification_fixture::contract().unwrap()
}

fn gate_ids(
    contract: &QualificationContract,
    tier: RegistryTier,
    surface: SurfaceRole,
    kind: &str,
    scope: Option<&ChangeScope>,
) -> Vec<String> {
    let destination = contract.destination(tier, surface, kind).unwrap();
    contract
        .gates(destination, scope)
        .unwrap()
        .into_iter()
        .map(|gate| gate.policy_id)
        .collect()
}

fn scope(image_affecting: bool, container_affecting: bool) -> ChangeScope {
    ChangeScope {
        schema_version: CHANGE_SCOPE.into(),
        predecessor_manifest_digest: Some(aos_release::Sha256Digest::of_bytes("predecessor")),
        image_affecting,
        container_affecting,
        changed_package_cells: Vec::new(),
        reason: "test scope".into(),
    }
}

#[test]
fn shipped_contract_has_the_exact_destination_table() {
    let contract = contract();
    contract.validate().unwrap();
    let table: Vec<_> = contract
        .destinations
        .iter()
        .map(|destination| {
            format!(
                "{}/{}/{}={}",
                destination.surface,
                destination.registry_tier,
                destination.channel,
                destination.profile
            )
        })
        .collect();
    assert_eq!(
        table,
        [
            "production/production/candidate=functional",
            "production/production/edge=smoke",
            "production/production/stable=soak",
            "production/testing/edge=smoke",
            "staging/production/candidate=build",
            "staging/production/edge=build",
            "staging/production/stable=build",
            "staging/testing/edge=build",
        ]
    );
    assert_eq!(contract.destinations_for(RegistryTier::Testing).count(), 2);
    assert_eq!(
        contract.destinations_for(RegistryTier::Production).count(),
        6
    );
    // The same channel kind selects the same profile on both tiers: the tier
    // changes the infrastructure behind a release, not its obligations.
    for tier in [RegistryTier::Testing, RegistryTier::Production] {
        assert_eq!(
            contract
                .destination(tier, SurfaceRole::Production, "edge")
                .unwrap()
                .profile,
            "smoke"
        );
    }
    assert_eq!(contract.profile("soak").unwrap().soak_seconds, 604_800);
    assert_eq!(contract.profile("soak").unwrap().rollout.rings.len(), 4);
    assert!(contract.profile("emergency").is_err());
    assert!(
        contract
            .destination(RegistryTier::Testing, SurfaceRole::Production, "candidate")
            .is_err()
    );
    assert!(
        contract
            .destination(RegistryTier::Testing, SurfaceRole::Production, "stable")
            .is_err()
    );
}

#[test]
fn gates_follow_the_destination_profile() {
    let contract = contract();
    let tier = RegistryTier::Production;
    let staging = gate_ids(&contract, tier, SurfaceRole::Staging, "stable", None);
    assert_eq!(staging, ["build-integrity"]);

    let candidate = gate_ids(&contract, tier, SurfaceRole::Production, "candidate", None);
    let stable = gate_ids(&contract, tier, SurfaceRole::Production, "stable", None);
    assert!(candidate.iter().all(|id| stable.contains(id)));
    assert!(candidate.contains(&"rollout-health".to_owned()));
    assert!(!candidate.contains(&"rollout-observation".to_owned()));
    assert!(!candidate.iter().any(|id| id.ends_with("-qualified")));
    assert!(stable.contains(&"rollout-observation".to_owned()));
    assert_eq!(
        stable
            .iter()
            .filter(|id| id.ends_with("-qualified"))
            .count(),
        4
    );

    // The same requirement has one identity across destinations, so evidence
    // for unrelated destinations is not invalidated by soak or review changes.
    let candidate_destination = contract
        .destination(tier, SurfaceRole::Production, "candidate")
        .unwrap();
    let stable_destination = contract
        .destination(tier, SurfaceRole::Production, "stable")
        .unwrap();
    let digest_of = |gates: Vec<aos_release::evidence::GateRequirement>| {
        gates
            .into_iter()
            .find(|gate| gate.policy_id == "package-function")
            .unwrap()
            .policy_digest
    };
    assert_eq!(
        digest_of(contract.gates(candidate_destination, None).unwrap()),
        digest_of(contract.gates(stable_destination, None).unwrap())
    );
}

#[test]
fn change_scope_narrows_smoke_claims() {
    let contract = contract();
    let tier = RegistryTier::Testing;
    let smoke = contract
        .destination(tier, SurfaceRole::Production, "edge")
        .unwrap();
    assert!(contract.gates(smoke, None).is_err());

    let unchanged = gate_ids(
        &contract,
        tier,
        SurfaceRole::Production,
        "edge",
        Some(&scope(false, false)),
    );
    assert!(!unchanged.iter().any(|id| id.starts_with("claim-")));
    assert!(unchanged.contains(&"package-function".to_owned()));

    let containers = gate_ids(
        &contract,
        tier,
        SurfaceRole::Production,
        "edge",
        Some(&scope(false, true)),
    );
    assert!(
        containers
            .iter()
            .any(|id| id.starts_with("claim-container-"))
    );
    assert!(!containers.iter().any(|id| id.starts_with("claim-disk-")));

    let everything = gate_ids(
        &contract,
        tier,
        SurfaceRole::Production,
        "edge",
        Some(&scope(true, true)),
    );
    assert!(everything.iter().any(|id| id.starts_with("claim-disk-")));
    assert!(!everything.iter().any(|id| id.ends_with("-qualified")));
}

#[test]
fn omitted_or_reclassified_mandatory_requirement_is_rejected() {
    for id in [
        "image-update-recovery",
        "build-integrity",
        "package-function",
        "rollout-health",
        "rollout-observation",
    ] {
        let mut policy = contract();
        policy.requirements.retain(|gate| gate.id != id);
        assert!(policy.validate().is_err(), "omitted {id}");
    }
    let mut policy = contract();
    policy
        .requirements
        .iter_mut()
        .find(|gate| gate.id == "image-update-recovery")
        .unwrap()
        .scope = QualificationScope::Release;
    assert!(policy.validate().is_err());
    let mut policy = contract();
    policy
        .requirements
        .iter_mut()
        .find(|gate| gate.id == "rollout-health")
        .unwrap()
        .phase = QualificationPhase::Build;
    assert!(policy.validate().is_err());
}

#[test]
fn contract_rejects_weakened_platform_and_profile_obligations() {
    let mut policy = contract();
    policy.targets.pop();
    assert!(policy.validate().is_err());
    let mut policy = contract();
    policy.package_rules[0].inherit_dependency_obligations = false;
    assert!(policy.validate().is_err());
    let mut policy = contract();
    policy.package_rules[0].execution = Some(PackageExecution::RecoveryImage {
        system_variant: String::new(),
    });
    assert!(policy.validate().is_err());

    let weaken = |change: fn(&mut QualificationContract)| {
        let mut policy = contract();
        change(&mut policy);
        policy.validate()
    };
    fn profile(policy: &QualificationContract, name: &str) -> usize {
        policy
            .profiles
            .iter()
            .position(|profile| profile.name == name)
            .unwrap()
    }
    for (label, result) in [
        (
            "soak below a day",
            weaken(|policy| {
                let index = profile(policy, "soak");
                policy.profiles[index].soak_seconds = 86_399;
            }),
        ),
        (
            "no build-integrity",
            weaken(|policy| {
                let index = profile(policy, "smoke");
                policy.profiles[index]
                    .requirements
                    .retain(|id| id != "build-integrity");
            }),
        ),
        (
            "qualified without observation",
            weaken(|policy| {
                let index = profile(policy, "soak");
                policy.profiles[index]
                    .requirements
                    .retain(|id| id != "rollout-observation");
            }),
        ),
        (
            "unreviewed production claims",
            weaken(|policy| {
                let index = profile(policy, "functional");
                policy.profiles[index].review_threshold = 0;
            }),
        ),
        (
            "rings not ending at 256",
            weaken(|policy| {
                let index = profile(policy, "soak");
                policy.profiles[index].rollout.rings.pop();
            }),
        ),
        (
            "unknown fitness kind",
            weaken(|policy| {
                policy.fitness.retain(|kind| kind.kind != "key-rotation");
            }),
        ),
        (
            "target-scoped profile requirement",
            weaken(|policy| {
                let index = profile(policy, "smoke");
                policy.profiles[index]
                    .requirements
                    .push("image-lifecycle".into());
            }),
        ),
        (
            "testing candidate",
            weaken(|policy| {
                policy.destinations[2].channel = "candidate".into();
            }),
        ),
        (
            "production edge",
            weaken(|policy| {
                policy.destinations[0].channel = "edge".into();
                policy.destinations[0].registry_tier = RegistryTier::Production;
            }),
        ),
        (
            "duplicate destination",
            weaken(|policy| {
                let duplicate = policy.destinations[0].clone();
                policy.destinations.push(duplicate);
            }),
        ),
        (
            "production without staging",
            weaken(|policy| {
                policy.destinations[0].after.clear();
            }),
        ),
        (
            "unknown profile",
            weaken(|policy| {
                policy.destinations[0].profile = "emergency".into();
            }),
        ),
        (
            "unknown identity",
            weaken(|policy| {
                policy.id = "aos-server".into();
            }),
        ),
    ] {
        assert!(result.is_err(), "accepted {label}");
    }
    assert!(
        contract()
            .profiles
            .iter()
            .any(|profile| profile.claims == ClaimSelection::Qualified)
    );
}

#[test]
fn unknown_and_duplicate_contract_fields_fail_closed() {
    let mut value = serde_json::to_value(contract()).unwrap();
    value["allow_failed_gates"] = true.into();
    assert!(serde_json::from_value::<QualificationContract>(value).is_err());
    assert!(
        canonical::from_slice::<QualificationContract>(
            br#"{"id":"a","id":"b"}"#,
            "duplicate contract"
        )
        .is_err()
    );
}

#[test]
fn contract_identity_is_its_rust_canonical_encoding() {
    let contract = contract();
    let encoded = canonical::to_vec(&contract).unwrap();
    let reparsed: QualificationContract = canonical::from_slice(&encoded, "re-encoded").unwrap();
    assert_eq!(reparsed, contract);
    assert_eq!(
        contract.digest().unwrap(),
        aos_release::Sha256Digest::of_canonical(
            aos_release::qualification::QUALIFICATION_CONTRACT,
            &contract
        )
        .unwrap()
    );
    let text = String::from_utf8(encoded).unwrap();
    for key in ["\"production_only\"", "\"thresholds\"", "\"configuration\""] {
        assert!(!text.contains(key), "contract encoding carries {key}");
    }
}

#[test]
fn release_class_and_channel_kind_derive_from_names() {
    assert_eq!(
        ReleaseClass::from_version("2026.9.0-dev.20260929.1").unwrap(),
        ReleaseClass::Edge
    );
    assert_eq!(
        ReleaseClass::from_version("2026.9.0-rc.2").unwrap(),
        ReleaseClass::Candidate
    );
    assert_eq!(
        ReleaseClass::from_version("2026.9.0").unwrap(),
        ReleaseClass::Stable
    );
    for invalid in [
        "v2026.9.0",
        "2026.13.0",
        "2025.9.0",
        "2026.9.0-beta.1",
        "latest",
    ] {
        assert!(ReleaseClass::from_version(invalid).is_err(), "{invalid}");
    }
    assert_eq!(channel_kind("stable-2026.3").unwrap(), "stable");
    assert_eq!(channel_kind("edge").unwrap(), "edge");
    assert!(channel_kind("emergency").is_err());
}

#[test]
fn arm64_container_evidence_requires_the_complete_tcg_topology() {
    use aos_release::platform::Platform;
    use aos_release::qualification::environment::{Accelerator, Backend, EnvironmentInventory};

    let policy = contract();
    let target = policy
        .targets
        .iter()
        .find(|target| target.id == "container-aarch64-linux")
        .unwrap();
    let profile = &target.environment;
    profile.validate(Platform::Aarch64Linux).unwrap();

    // Test-only observations exercise admission; they are never release evidence.
    let mut value = serde_json::to_value(profile).unwrap();
    value.as_object_mut().unwrap().remove("kernel_options");
    value["schema_version"] = "aos.release.environment-inventory/v1".into();
    value["firmware"] = serde_json::Value::Null;
    value["image_capabilities_digest"] = serde_json::Value::Null;
    value["resources"]["memory_mib"] = 8192.into();
    for layer in value["layers"].as_array_mut().unwrap() {
        layer["cpu"] = serde_json::json!({
            "vendor": "test-vendor",
            "model": "test-model",
            "sku": null,
            "revision": null,
            "microcode": null,
            "features": []
        });
        layer["kernel_release"] = "test-kernel".into();
        for identity in layer["backend"].as_object_mut().unwrap().values_mut() {
            if identity.is_null() {
                *identity = "test-identity".into();
            }
        }
    }
    let observed: EnvironmentInventory = serde_json::from_value(value).unwrap();
    profile.matches(&observed).unwrap();

    let mut missing_host = observed.clone();
    missing_host.layers.remove(0);
    assert!(profile.matches(&missing_host).is_err());

    let mut missing_guest = observed.clone();
    missing_guest.layers.remove(1);
    assert!(profile.matches(&missing_guest).is_err());

    let mut native_arm64 = observed.clone();
    native_arm64.layers.remove(1);
    native_arm64.layers[0].platform = Platform::Aarch64Linux;
    native_arm64.validate().unwrap();
    assert!(profile.matches(&native_arm64).is_err());

    let mut false_kvm = observed.clone();
    if let Backend::Qemu { accelerator, .. } = &mut false_kvm.layers[1].backend {
        *accelerator = Accelerator::Kvm;
    } else {
        panic!("ARM64 reference scope must contain a QEMU layer");
    }
    assert!(profile.matches(&false_kvm).is_err());

    let mut missing_emulator_version = observed;
    if let Backend::Qemu { version, .. } = &mut missing_emulator_version.layers[1].backend {
        *version = None;
    }
    assert!(profile.matches(&missing_emulator_version).is_err());
}
