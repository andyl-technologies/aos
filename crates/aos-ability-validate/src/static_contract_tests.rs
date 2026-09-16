//! Tests for static ability contracts.

use super::*;
use aos_ability_model::encode_canonical;
use serde_json::{Value, json};

const EMPTY_CONTAINER: &[u8] = br#"{"platforms":[{"abilities":[],"packages":[],"platform":{"architecture":"amd64","os":"linux"},"unresolved_launch_obligations":[]}],"runtime_grants":[],"schema":"aos.container.static-abilities/v1"}"#;

fn expectation() -> StaticAbilityContractExpectation {
    StaticAbilityContractExpectation {
        artifact_class: StaticAbilityArtifactClass::Container,
        execution_stage: None,
        platform: Some(StaticAbilityPlatform {
            os: "linux".to_string(),
            architecture: "amd64".to_string(),
            variant: None,
            target: None,
        }),
    }
}

fn aggregate_expectation() -> StaticAbilityContractExpectation {
    StaticAbilityContractExpectation {
        artifact_class: StaticAbilityArtifactClass::Container,
        execution_stage: None,
        platform: None,
    }
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn artifact(store_path: &str, byte: char) -> Value {
    json!({
        "content": digest(byte),
        "store_path": store_path,
        "nar_hash": digest(byte),
        "closure": digest(byte),
    })
}

fn manifest(store_path: &str, byte: char) -> Value {
    json!({
        "store_path": store_path,
        "digest": digest(byte),
    })
}

fn interface(name: &str, byte: char) -> Value {
    json!({
        "name": name,
        "abi": 1,
        "descriptor": digest(byte),
    })
}

fn requirement(alias: &str) -> Value {
    json!({
        "alias": alias,
        "description": "Describes this consumed ability.",
        "accepted_interfaces": [
            interface("aos.test.alpha", '1'),
            interface("aos.test.beta", '2'),
        ],
        "methods": ["apply", "remove"],
        "guarantees": [
            {"name": "aos.test.alpha", "version": 1, "descriptor": digest('3')},
            {"name": "aos.test.beta", "version": 1, "descriptor": digest('4')},
        ],
        "strength": "required",
        "fallback": null,
    })
}

fn populated_container_contract() -> Value {
    let package_a_path = "/nix/store/00000000000000000000000000000000-package-a";
    let package_b_path = "/nix/store/11111111111111111111111111111111-package-b";
    let provider_a_path = "/nix/store/22222222222222222222222222222222-provider-a";
    let provider_b_path = "/nix/store/33333333333333333333333333333333-provider-b";
    let package_a_manifest = manifest(package_a_path, '5');

    json!({
        "schema": "aos.container.static-abilities/v1",
        "platforms": [{
            "platform": {"os": "linux", "architecture": "amd64"},
            "packages": [
                {
                    "name": "package-a",
                    "version": "1",
                    "payload": artifact(package_a_path, '6'),
                    "manifest": package_a_manifest,
                },
                {
                    "name": "package-b",
                    "version": "1",
                    "payload": artifact(package_b_path, '7'),
                    "manifest": manifest(package_b_path, '8'),
                },
            ],
            "abilities": [
                {
                    "package": package_a_manifest,
                    "export": "alpha",
                    "interface": interface("aos.test.alpha", '1'),
                    "implementation": digest('9'),
                    "implementation_artifact": artifact(provider_a_path, 'a'),
                    "availability": "baked",
                },
                {
                    "package": package_a_manifest,
                    "export": "beta",
                    "interface": interface("aos.test.beta", '2'),
                    "implementation": digest('b'),
                    "implementation_artifact": artifact(provider_b_path, 'c'),
                    "availability": "baked",
                },
            ],
            "unresolved_launch_obligations": [
                {
                    "kind": "ability-requirement",
                    "consumer": {"package": package_a_manifest},
                    "requirement": requirement("alpha"),
                    "disposition": "external-launch-obligation",
                },
                {
                    "kind": "ability-requirement",
                    "consumer": {"package": package_a_manifest},
                    "requirement": requirement("beta"),
                    "disposition": "external-launch-obligation",
                },
            ],
        }],
        "runtime_grants": [],
    })
}

fn artifact_backed_container_contract() -> (Value, StaticPackageArtifacts) {
    let fixture = crate::test_support::stateful_owner_plan_fixture();
    let mut package = fixture.binding_inputs.packages[0].clone();
    let accepted_interface = fixture.interfaces[0]
        .interface_key()
        .expect("fixture interface must have an exact key");
    package.requirements = vec![RequirementDeclaration {
        description: "Describes this declaration.".to_string(),
        alias: LocalKey::new("package-required").expect("fixture alias must be valid"),
        accepted_interfaces: vec![accepted_interface.clone().into()],
        methods: Vec::new(),
        guarantees: Vec::new(),
        strength: RequirementStrength::Required,
        fallback: None,
    }];

    let provider = &mut package.implementation.providers[0];
    provider.requirements = vec![RequirementDeclaration {
        description: "Describes this declaration.".to_string(),
        alias: LocalKey::new("provider-required").expect("fixture alias must be valid"),
        accepted_interfaces: vec![accepted_interface.into()],
        methods: Vec::new(),
        guarantees: Vec::new(),
        strength: RequirementStrength::Required,
        fallback: None,
    }];
    let provider_interface = provider.interface.clone();
    let provider_descriptor = provider
        .descriptor_digest()
        .expect("fixture provider must have a descriptor");
    package
        .exports
        .iter_mut()
        .find(|export| export.interface == provider_interface)
        .expect("fixture provider must be exported")
        .implementation = provider_descriptor;

    let manifest_bytes = encode_canonical(&package)
        .expect("artifact-backed package fixture must encode canonically");
    let manifest_path = "/nix/store/44444444444444444444444444444444-package-manifest";
    let manifest_reference = json!({
        "store_path": manifest_path,
        "digest": Sha256Digest::of_bytes(&manifest_bytes),
    });
    let mut abilities = package
        .exports
        .iter()
        .map(|export| {
            let provider = package
                .implementation
                .providers
                .iter()
                .find(|provider| {
                    provider.interface == export.interface
                        && provider.descriptor_digest().ok() == Some(export.implementation)
                })
                .expect("fixture export must have an exact provider");
            (
                (export.interface.clone(), export.name.clone()),
                json!({
                    "package": manifest_reference,
                    "export": export.name,
                    "interface": export.interface,
                    "implementation": export.implementation,
                    "implementation_artifact": provider.artifact,
                    "availability": "baked",
                }),
            )
        })
        .collect::<Vec<_>>();
    abilities.sort_by(|left, right| left.0.cmp(&right.0));
    let abilities = abilities
        .into_iter()
        .map(|(_, ability)| ability)
        .collect::<Vec<_>>();
    let exact_provider = package
        .implementation
        .providers
        .iter()
        .find(|provider| provider.interface == provider_interface)
        .expect("fixture provider must remain present");
    let obligations = vec![
        json!({
            "kind": "ability-requirement",
            "consumer": {"package": manifest_reference},
            "requirement": package.requirements[0],
            "disposition": "external-launch-obligation",
        }),
        json!({
            "kind": "ability-requirement",
            "consumer": {
                "package": manifest_reference,
                "ability": exact_provider.interface,
            },
            "requirement": exact_provider.requirements[0],
            "disposition": "external-launch-obligation",
        }),
    ];
    let contract = json!({
        "schema": "aos.container.static-abilities/v1",
        "platforms": [{
            "platform": {"os": "linux", "architecture": "amd64"},
            "packages": [{
                "name": package.package.name,
                "version": package.package.version,
                "payload": package.package.payload,
                "manifest": manifest_reference,
            }],
            "abilities": abilities,
            "unresolved_launch_obligations": obligations,
        }],
        "runtime_grants": [],
    });
    let retained_interfaces = fixture
        .interfaces
        .iter()
        .map(|interface| {
            encode_canonical(interface).expect("fixture interface must encode canonically")
        })
        .collect();

    (
        contract,
        StaticPackageArtifacts {
            manifest: manifest_bytes,
            retained_interfaces,
        },
    )
}

fn assert_artifact_contract_rejected(contract: &Value, artifacts: &StaticPackageArtifacts) {
    let bytes = aos_contract::canonical::to_vec(contract)
        .expect("static contract fixture must encode canonically");
    validate_static_ability_contract(&bytes, &aggregate_expectation())
        .expect("artifact mutation must remain a valid byte-level contract");

    validate_static_ability_artifacts_with(&bytes, &aggregate_expectation(), |store_path| {
        ensure!(
            store_path == "/nix/store/44444444444444444444444444444444-package-manifest",
            "unexpected fixture manifest path"
        );
        Ok(artifacts.clone())
    })
    .expect_err("artifact-backed identity mutation must fail closed");
}

fn set_manifest_digest(contract: &mut Value, digest: Value) {
    contract["platforms"][0]["packages"][0]["manifest"]["digest"] = digest.clone();
    contract["platforms"][0]["abilities"]
        .as_array_mut()
        .expect("fixture abilities must be an array")
        .iter_mut()
        .for_each(|ability| {
            ability["package"]["digest"] = digest.clone();
        });
    contract["platforms"][0]["unresolved_launch_obligations"]
        .as_array_mut()
        .expect("fixture obligations must be an array")
        .iter_mut()
        .for_each(|obligation| {
            obligation["consumer"]["package"]["digest"] = digest.clone();
        });
}

fn assert_contract_rejected(contract: &Value, expected_error: &str) {
    let bytes = aos_contract::canonical::to_vec(contract)
        .expect("static contract fixture must encode canonically");
    let error = validate_static_ability_contract(&bytes, &aggregate_expectation())
        .expect_err("noncanonical semantic order must fail closed");

    assert!(
        error.source.to_string().contains(expected_error),
        "unexpected validation error: {error:?}"
    );
}

#[test]
fn accepts_a_canonical_empty_container_contract() {
    let checked = validate_static_ability_contract(EMPTY_CONTAINER, &expectation())
        .expect("canonical static contract must validate");
    assert_eq!(checked.platform_count(), 1);
    assert_eq!(checked.packages().len(), 0);
}

#[test]
fn retains_an_authenticated_target_platform() {
    let mut contract: Value = serde_json::from_slice(EMPTY_CONTAINER).unwrap();
    contract["platforms"][0]["target"] = json!({
        "system": "freebsd",
        "architecture": "riscv64",
    });
    let bytes = aos_contract::canonical::to_vec(&contract).unwrap();

    let checked = validate_static_ability_contract(&bytes, &aggregate_expectation()).unwrap();
    let target = checked.platforms()[0].target.as_ref().unwrap();

    assert_eq!(target.system.as_str(), "freebsd");
    assert_eq!(target.architecture.as_str(), "riscv64");
}

#[test]
fn rejects_a_runtime_grant_even_when_json_is_canonical() {
    let bytes = br#"{"platforms":[{"abilities":[],"packages":[],"platform":{"architecture":"amd64","os":"linux"},"unresolved_launch_obligations":[]}],"runtime_grants":[{}],"schema":"aos.container.static-abilities/v1"}"#;
    validate_static_ability_contract(bytes, &expectation())
        .expect_err("static runtime grants must fail closed");
}

#[test]
fn accepts_strictly_ordered_static_contract_records() {
    let bytes = aos_contract::canonical::to_vec(&populated_container_contract())
        .expect("static contract fixture must encode canonically");

    let checked = validate_static_ability_contract(&bytes, &aggregate_expectation())
        .expect("strictly ordered static records must validate");
    let packages = checked.packages().collect::<Vec<_>>();
    assert_eq!(packages.len(), 2);
    assert_eq!(packages[0].name().as_str(), "package-a");
    assert_eq!(packages[0].version(), "1");
    assert_eq!(
        packages[0].manifest().store_path(),
        "/nix/store/00000000000000000000000000000000-package-a"
    );
    assert!(packages[0].package_document().is_none());
}

#[test]
fn rejects_reordered_and_duplicate_static_contract_records() {
    for (field, expected_error) in [
        ("packages", "static contract package records"),
        ("abilities", "static contract ability records"),
        (
            "unresolved_launch_obligations",
            "static contract launch obligations",
        ),
    ] {
        let mut reordered = populated_container_contract();
        reordered["platforms"][0][field]
            .as_array_mut()
            .expect("fixture field must be an array")
            .reverse();
        assert_contract_rejected(&reordered, expected_error);

        let mut duplicated = populated_container_contract();
        let records = duplicated["platforms"][0][field]
            .as_array_mut()
            .expect("fixture field must be an array");
        records.insert(1, records[0].clone());
        assert_contract_rejected(&duplicated, expected_error);
    }
}

#[test]
fn rejects_reordered_and_duplicate_platform_records() {
    let mut canonical = populated_container_contract();
    let mut arm64 = canonical["platforms"][0].clone();
    arm64["platform"]["architecture"] = json!("arm64");
    canonical["platforms"] = json!([canonical["platforms"][0].clone(), arm64]);

    let mut reordered = canonical.clone();
    reordered["platforms"]
        .as_array_mut()
        .expect("fixture platforms must be an array")
        .reverse();
    assert_contract_rejected(&reordered, "static contract platform records");

    let mut duplicated = canonical;
    let platforms = duplicated["platforms"]
        .as_array_mut()
        .expect("fixture platforms must be an array");
    platforms.insert(1, platforms[0].clone());
    assert_contract_rejected(&duplicated, "static contract platform records");
}

#[test]
fn rejects_reordered_and_duplicate_requirement_members() {
    for (field, expected_error) in [
        (
            "accepted_interfaces",
            "ability requirement accepted interfaces",
        ),
        ("methods", "ability requirement methods"),
        ("guarantees", "ability requirement guarantees"),
    ] {
        let mut reordered = populated_container_contract();
        reordered["platforms"][0]["unresolved_launch_obligations"][0]["requirement"][field]
            .as_array_mut()
            .expect("fixture requirement member must be an array")
            .reverse();
        assert_contract_rejected(&reordered, expected_error);

        let mut duplicated = populated_container_contract();
        let members = duplicated["platforms"][0]["unresolved_launch_obligations"][0]["requirement"]
            [field]
            .as_array_mut()
            .expect("fixture requirement member must be an array");
        members.insert(1, members[0].clone());
        assert_contract_rejected(&duplicated, expected_error);
    }
}

#[test]
fn accepts_exact_artifact_backed_package_and_ability_projections() {
    let (contract, artifacts) = artifact_backed_container_contract();
    let bytes = aos_contract::canonical::to_vec(&contract)
        .expect("static contract fixture must encode canonically");

    let checked = validate_static_ability_artifacts_with(&bytes, &aggregate_expectation(), |_| {
        Ok(artifacts.clone())
    })
    .expect("exact artifact-backed projection must validate");
    let package = checked
        .packages()
        .next()
        .expect("artifact-backed contract must retain its package selection");
    assert_eq!(
        package.name(),
        &package.package_document().unwrap().package.name
    );
    assert_eq!(
        package.payload(),
        &package.package_document().unwrap().package.payload
    );
}

#[test]
fn reads_exact_package_companions_from_an_immutable_store_root() {
    let (contract, artifacts) = artifact_backed_container_contract();
    let bytes = aos_contract::canonical::to_vec(&contract)
        .expect("static contract fixture must encode canonically");
    let root = std::env::temp_dir().join(format!(
        "aos-static-contract-store-root-{}",
        std::process::id()
    ));
    let package = root.join("44444444444444444444444444444444-package-manifest");
    let interfaces = package.join("interfaces");
    std::fs::create_dir_all(&interfaces).expect("fixture store root must be created");
    std::fs::write(package.join("package.json"), &artifacts.manifest)
        .expect("fixture package manifest must be written");
    for (index, interface) in artifacts.retained_interfaces.iter().enumerate() {
        std::fs::write(interfaces.join(format!("{index}.json")), interface)
            .expect("fixture interface must be written");
    }

    let checked =
        validate_static_ability_artifacts_at_store_root(&bytes, &aggregate_expectation(), &root)
            .expect("immutable-root package companions must validate");
    let selected = checked
        .packages()
        .next()
        .expect("checked contract must retain its package selection");

    assert!(selected.package_document().is_some());
    std::fs::remove_dir_all(root).expect("fixture store root must be removed");
}

#[test]
fn rejects_forged_artifact_backed_package_identities() {
    let (contract, artifacts) = artifact_backed_container_contract();

    let mut changed_name = contract.clone();
    changed_name["platforms"][0]["packages"][0]["name"] = json!("forged-package");
    assert_artifact_contract_rejected(&changed_name, &artifacts);

    let mut changed_version = contract.clone();
    changed_version["platforms"][0]["packages"][0]["version"] = json!("9.9.9");
    assert_artifact_contract_rejected(&changed_version, &artifacts);

    let mut changed_payload = contract.clone();
    changed_payload["platforms"][0]["packages"][0]["payload"]["content"] = json!(digest('0'));
    assert_artifact_contract_rejected(&changed_payload, &artifacts);

    let mut changed_manifest_digest = contract;
    set_manifest_digest(&mut changed_manifest_digest, json!(digest('0')));
    assert_artifact_contract_rejected(&changed_manifest_digest, &artifacts);
}

#[test]
fn rejects_semantically_invalid_artifact_backed_package_companions() {
    let (mut contract, mut artifacts) = artifact_backed_container_contract();
    let mut package: Value =
        aos_contract::canonical::from_slice(&artifacts.manifest, "artifact-backed package fixture")
            .expect("artifact-backed package fixture must decode");
    package["exports"][0]["implementation"] = json!(digest('0'));
    artifacts.manifest = aos_contract::canonical::to_vec(&package)
        .expect("mutated package fixture must encode canonically");
    set_manifest_digest(
        &mut contract,
        json!(Sha256Digest::of_bytes(&artifacts.manifest)),
    );

    assert_artifact_contract_rejected(&contract, &artifacts);
}

#[test]
fn rejects_forged_artifact_backed_export_and_provider_identities() {
    let (contract, artifacts) = artifact_backed_container_contract();

    let mut changed_export = contract.clone();
    changed_export["platforms"][0]["abilities"][0]["export"] = json!("forged-export");
    assert_artifact_contract_rejected(&changed_export, &artifacts);

    let mut changed_interface = contract.clone();
    changed_interface["platforms"][0]["abilities"][0]["interface"]["descriptor"] =
        json!(digest('0'));
    let original_interface = contract["platforms"][0]["abilities"][0]["interface"].clone();
    changed_interface["platforms"][0]["unresolved_launch_obligations"]
        .as_array_mut()
        .expect("fixture obligations must be an array")
        .iter_mut()
        .filter(|obligation| obligation["consumer"].get("ability") == Some(&original_interface))
        .for_each(|obligation| {
            obligation["consumer"]["ability"]["descriptor"] = json!(digest('0'));
        });
    assert_artifact_contract_rejected(&changed_interface, &artifacts);

    let mut changed_implementation = contract.clone();
    changed_implementation["platforms"][0]["abilities"][0]["implementation"] = json!(digest('0'));
    assert_artifact_contract_rejected(&changed_implementation, &artifacts);

    let mut changed_provider_artifact = contract;
    changed_provider_artifact["platforms"][0]["abilities"][0]["implementation_artifact"]["content"] =
        json!(digest('0'));
    assert_artifact_contract_rejected(&changed_provider_artifact, &artifacts);
}

#[test]
fn rejects_mutated_or_incomplete_artifact_backed_required_obligations() {
    let (contract, artifacts) = artifact_backed_container_contract();

    let mut changed_requirement = contract.clone();
    changed_requirement["platforms"][0]["unresolved_launch_obligations"][0]["requirement"]["methods"] =
        json!(["forged-method"]);
    assert_artifact_contract_rejected(&changed_requirement, &artifacts);

    let mut missing_requirement = contract;
    missing_requirement["platforms"][0]["unresolved_launch_obligations"]
        .as_array_mut()
        .expect("fixture obligations must be an array")
        .remove(0);
    assert_artifact_contract_rejected(&missing_requirement, &artifacts);
}
