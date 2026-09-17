//! Tests for package ability projections.

use super::{
    decode_package_projection, resolve_artifact_selectors, resolve_package_projection,
    validate_projection_value_budget,
};
use aos_ability_model::{
    ABILITY_LIMITS_V1, ArtifactReference, LimitProfile, LocalKey, VersionedDocument,
};
use aos_contract::Sha256Digest;
use serde_json::json;

fn artifact(label: &str, store_path: &str) -> ArtifactReference {
    ArtifactReference {
        content: Sha256Digest::of_bytes(format!("{label}-content")),
        store_path: store_path.to_string(),
        nar_hash: Sha256Digest::of_bytes(format!("{label}-nar")),
        closure: Sha256Digest::of_bytes(format!("{label}-closure")),
    }
}

fn projection() -> serde_json::Value {
    json!({
        "schema": "aos.ability.package-projection/v1",
        "required_features": ["abilities-v1"],
        "package": {"name": "owner", "version": "1"},
        "artifacts": [
            {"package": "dependency", "output": "bin"},
            {"package": "self", "output": "out"}
        ],
        "interfaces": {},
        "guarantees": {},
        "package_module": {
            "artifact": {"package": "self", "output": "module"},
            "path": "module.nix"
        },
        "option_declarations": [],
        "exports": [],
        "interface_documents": [],
        "requirements": [],
        "implementation": {"providers": [], "handlers": {}},
        "qualification": {"implementations": {}}
    })
}

fn package_probe() -> serde_json::Value {
    fn template(fragment: serde_json::Value) -> serde_json::Value {
        json!({"fragments": [fragment]})
    }

    json!({
        "primary": {
            "input": "A fixed input document.",
            "operation": "Copy the document through the package executable.",
            "expected": "The output exactly matches the input.",
            "files": {
                "input.txt": template(json!({
                    "kind": "literal",
                    "text": "qualified input\n"
                }))
            },
            "steps": [{
                "argv": [
                    template(json!({
                        "kind": "artifact-path",
                        "artifact": {"package": "self", "output": "out"},
                        "path": "bin/copy"
                    })),
                    template(json!({"kind": "work-path", "path": "input.txt"}))
                ],
                "stdout": template(json!({
                    "kind": "literal",
                    "text": "qualified input\n"
                })),
                "exit_code": 0,
                "observes_rejection": false
            }],
            "artifacts": []
        },
        "bad_input": {
            "input": "An unsupported command-line option.",
            "operation": "Invoke the package executable with that option.",
            "expected": "The executable rejects the option.",
            "files": {},
            "steps": [{
                "argv": [
                    template(json!({"kind": "harness", "tool": "bash"})),
                    template(json!({"kind": "literal", "text": "--invalid"}))
                ],
                "exit_code": 2,
                "observes_rejection": true
            }],
            "artifacts": [{
                "kind": "text",
                "path": "diagnostic.txt",
                "text": "unsupported option\n"
            }]
        }
    })
}

fn resolve(projection: serde_json::Value) -> aos_ability_model::PackageDocument {
    let bytes = aos_contract::canonical::to_vec(&projection).unwrap();
    let projection = decode_package_projection(&bytes).unwrap();
    let payload = artifact("payload", "/nix/store/payload");
    let source = artifact("source", "/nix/store/source.drv");

    resolve_package_projection(projection, payload.clone(), source, |selector| {
        match (selector.package.as_str(), selector.output.as_str()) {
            ("self", "out") => Ok(payload.clone()),
            ("self", "module") => Ok(artifact("module", "/nix/store/owner-module")),
            ("dependency", "bin") => Ok(artifact("dependency", "/nix/store/dependency-bin")),
            _ => unreachable!("fixture contains only declared selectors"),
        }
    })
    .unwrap()
}

#[test]
fn recursive_projection_budget_rejects_wide_values() {
    let limits = LimitProfile {
        max_collection_items: 4,
        ..ABILITY_LIMITS_V1
    };
    let value = json!([null, null, null, null, null]);
    let mut items = 0;

    assert!(validate_projection_value_budget(&value, 1, &mut items, &limits).is_err());
}

#[test]
fn selector_order_matches_the_nix_projection_boundary() {
    let expected = json!([
        {"package": "ability-package-smoke", "output": "out"},
        {"package": "ability-package-smoke-provider", "output": "out"},
        {"package": "self", "output": "module"},
        {"package": "self", "output": "out"}
    ]);
    let mut canonical = projection();
    canonical["artifacts"] = expected;
    let canonical_bytes = aos_contract::canonical::to_vec(&canonical).unwrap();

    decode_package_projection(&canonical_bytes).unwrap();

    let mut output_first = canonical;
    output_first["artifacts"] = json!([
        {"package": "self", "output": "module"},
        {"package": "ability-package-smoke", "output": "out"},
        {"package": "ability-package-smoke-provider", "output": "out"},
        {"package": "self", "output": "out"}
    ]);
    let output_first_bytes = aos_contract::canonical::to_vec(&output_first).unwrap();

    assert!(decode_package_projection(&output_first_bytes).is_err());
}

#[test]
fn resolves_symbolic_selectors_into_exact_artifact_references() {
    let bytes = aos_contract::canonical::to_vec(&projection()).unwrap();
    let projection = decode_package_projection(&bytes).unwrap();
    let payload = artifact("payload", "/nix/store/payload");
    let source = artifact("source", "/nix/store/source.drv");

    let document = resolve_package_projection(
        projection,
        payload.clone(),
        source.clone(),
        |selector| match (selector.package.as_str(), selector.output.as_str()) {
            ("self", "out") => Ok(payload.clone()),
            ("dependency", "bin") => Ok(artifact("dependency", "/nix/store/dependency-bin")),
            ("self", "module") => Ok(artifact("module", "/nix/store/owner-module")),
            _ => unreachable!("fixture contains only declared selectors"),
        },
    )
    .unwrap();

    assert_eq!(document.package.payload, payload);
    assert_eq!(document.package.source, source);
    assert_eq!(document.artifacts.len(), 3);
    assert!(
        document
            .artifacts
            .iter()
            .any(|artifact| artifact.store_path == "/nix/store/payload")
    );
    assert!(
        document
            .artifacts
            .iter()
            .any(|artifact| artifact.store_path == "/nix/store/dependency-bin")
    );
    assert!(
        document
            .artifacts
            .iter()
            .any(|artifact| artifact.store_path == "/nix/store/owner-module")
    );
}

#[test]
fn resolves_probe_only_packages_without_an_ability_module() {
    let mut value = projection();
    value["package_module"] = serde_json::Value::Null;
    value["qualification"]["package_probe"] = package_probe();

    let document = resolve(value);
    let probe = document
        .qualification
        .package_probe
        .as_ref()
        .expect("package probe should be retained");
    let fragment = &probe.primary.steps[0].argv[0].fragments[0];

    assert!(document.package_module.is_none());
    assert!(matches!(
        fragment,
        aos_ability_model::PackageProbeTemplateFragment::ArtifactPath { artifact, path }
            if artifact == &document.package.payload && path.as_str() == "bin/copy"
    ));
}

#[test]
fn rejects_publishable_projection_without_module_or_probe() {
    let mut value = projection();
    value["package_module"] = serde_json::Value::Null;
    let bytes = aos_contract::canonical::to_vec(&value).unwrap();
    let projection = decode_package_projection(&bytes).unwrap();
    let payload = artifact("payload", "/nix/store/payload");
    let source = artifact("source", "/nix/store/source.drv");

    let error = resolve_package_projection(projection, payload, source, |_| {
        unreachable!("projection has no symbolic artifact references")
    })
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("neither a module nor a package probe")
    );
}

#[test]
fn rejects_open_package_probe_fragments() {
    let mut value = projection();
    value["package_module"] = serde_json::Value::Null;
    value["qualification"]["package_probe"] = package_probe();
    value["qualification"]["package_probe"]["primary"]["steps"][0]["argv"][0]["fragments"][0]["unchecked"] =
        json!(true);
    let bytes = aos_contract::canonical::to_vec(&value).unwrap();

    assert!(decode_package_projection(&bytes).is_err());
}

#[test]
fn package_probe_identity_uses_artifact_content_without_store_locator() {
    let mut value = projection();
    value["package_module"] = serde_json::Value::Null;
    value["qualification"]["package_probe"] = package_probe();
    let document = resolve(value);
    let semantic = document.content_digest().unwrap();

    let mut relocated = document.clone();
    let probe = relocated
        .qualification
        .package_probe
        .as_mut()
        .expect("package probe should be retained");
    let aos_ability_model::PackageProbeTemplateFragment::ArtifactPath {
        artifact: selected_artifact,
        ..
    } = &mut probe.primary.steps[0].argv[0].fragments[0]
    else {
        panic!("fixture should retain one artifact-path fragment");
    };
    selected_artifact.store_path = "/nix/store/relocated-payload".to_string();
    assert_eq!(semantic, relocated.content_digest().unwrap());

    let mut changed = document;
    let probe = changed
        .qualification
        .package_probe
        .as_mut()
        .expect("package probe should be retained");
    let aos_ability_model::PackageProbeTemplateFragment::ArtifactPath {
        artifact: selected_artifact,
        ..
    } = &mut probe.primary.steps[0].argv[0].fragments[0]
    else {
        panic!("fixture should retain one artifact-path fragment");
    };
    selected_artifact.closure = Sha256Digest::of_bytes("changed probe closure");
    assert_ne!(semantic, changed.content_digest().unwrap());
}

#[test]
fn rejects_package_probe_artifacts_outside_the_retained_package_set() {
    let mut value = projection();
    value["package_module"] = serde_json::Value::Null;
    value["qualification"]["package_probe"] = package_probe();
    let mut document = resolve(value);
    let probe = document
        .qualification
        .package_probe
        .as_mut()
        .expect("package probe should be retained");
    let aos_ability_model::PackageProbeTemplateFragment::ArtifactPath {
        artifact: selected_artifact,
        ..
    } = &mut probe.primary.steps[0].argv[0].fragments[0]
    else {
        panic!("fixture should retain one artifact-path fragment");
    };
    *selected_artifact = artifact("foreign", "/nix/store/foreign");

    assert!(aos_ability_model::encode_canonical(&document).is_err());
}

#[test]
fn rejects_private_nix_selector_markers() {
    let mut projection = projection();
    projection["artifacts"][0]["_type"] = json!("aos-package-output-selector");
    let bytes = aos_contract::canonical::to_vec(&projection).unwrap();

    assert!(decode_package_projection(&bytes).is_err());
}

#[test]
fn rejects_noncanonical_selector_order_before_resolution() {
    let mut projection = projection();
    projection["artifacts"] = json!([
        {"package": "self", "output": "out"},
        {"package": "dependency", "output": "bin"}
    ]);
    let bytes = aos_contract::canonical::to_vec(&projection).unwrap();

    let error = decode_package_projection(&bytes).unwrap_err();
    assert!(error.to_string().contains("canonically ordered"));
}

#[test]
fn artifact_deduplication_uses_the_complete_semantic_identity() {
    let mut projection = projection();
    projection["artifacts"]
        .as_array_mut()
        .unwrap()
        .push(json!({"package": "sibling", "output": "out"}));
    let bytes = aos_contract::canonical::to_vec(&projection).unwrap();
    let projection = decode_package_projection(&bytes).unwrap();
    let payload = artifact("payload", "/nix/store/payload");
    let source = artifact("source", "/nix/store/source.drv");

    let document =
        resolve_package_projection(projection, payload.clone(), source, |selector| {
            match (selector.package.as_str(), selector.output.as_str()) {
                ("self", "out") => Ok(payload.clone()),
                ("self", "module") => Ok(artifact("module", "/nix/store/module")),
                ("dependency", "bin") => Ok(artifact("shared", "/nix/store/dependency")),
                ("sibling", "out") => {
                    let mut selected = artifact("shared", "/nix/store/sibling");
                    selected.closure = Sha256Digest::of_bytes(b"distinct closure");
                    Ok(selected)
                }
                _ => unreachable!("fixture contains only declared selectors"),
            }
        })
        .unwrap();

    let shared_content = artifact("shared", "").content;
    assert_eq!(
        document
            .artifacts
            .iter()
            .filter(|artifact| artifact.content == shared_content)
            .count(),
        2
    );
}

#[test]
fn retains_distinct_local_aliases_for_one_interface_document() {
    let fixture = crate::test_support::stateful_owner_plan_fixture();
    let interface = fixture.interfaces[0].clone();
    let identity = interface
        .interface_key()
        .expect("fixture interface identity should derive");
    let mut value = projection();
    value["interfaces"] = json!({
        "echo": identity,
        "echo-alias": identity,
    });
    value["interface_documents"] = json!([{
        "descriptor": identity.descriptor,
        "document": interface,
    }]);
    let bytes = aos_contract::canonical::to_vec(&value).unwrap();
    let projection = decode_package_projection(&bytes).unwrap();
    let payload = artifact("payload", "/nix/store/payload");
    let source = artifact("source", "/nix/store/source.drv");

    let document =
        resolve_package_projection(projection, payload.clone(), source, |selector| {
            match (selector.package.as_str(), selector.output.as_str()) {
                ("self", "out") => Ok(payload.clone()),
                ("dependency", "bin") => Ok(artifact("dependency", "/nix/store/dependency-bin")),
                ("self", "module") => Ok(artifact("module", "/nix/store/owner-module")),
                _ => unreachable!("fixture contains only declared selectors"),
            }
        })
        .expect("distinct declaration aliases may retain one interface document");

    assert_eq!(document.interfaces.len(), 2);
    assert_eq!(
        document.interfaces[&LocalKey::new("echo").unwrap()],
        identity
    );
    assert_eq!(
        document.interfaces[&LocalKey::new("echo-alias").unwrap()],
        identity
    );
}

#[test]
fn guarantee_prose_changes_signed_bytes_without_changing_semantic_identity() {
    fn resolve(description: &str) -> aos_ability_model::PackageDocument {
        let mut value = projection();
        value["guarantees"] = json!({
            "supervision": {
                "name": "aos.service.supervision",
                "version": 1,
                "semantics": "The service remains supervised while requested.",
                "description": description,
            }
        });
        let bytes = aos_contract::canonical::to_vec(&value).unwrap();
        let projection = decode_package_projection(&bytes).unwrap();
        let payload = artifact("payload", "/nix/store/payload");
        let source = artifact("source", "/nix/store/source.drv");

        resolve_package_projection(projection, payload.clone(), source, |selector| {
            match (selector.package.as_str(), selector.output.as_str()) {
                ("self", "out") => Ok(payload.clone()),
                ("dependency", "bin") => Ok(artifact("dependency", "/nix/store/dependency-bin")),
                ("self", "module") => Ok(artifact("module", "/nix/store/owner-module")),
                _ => unreachable!("fixture contains only declared selectors"),
            }
        })
        .unwrap()
    }

    let first = resolve("Keeps one requested service process supervised.");
    let second = resolve("Supervises the requested service process continuously.");

    assert_eq!(
        first.content_digest().unwrap(),
        second.content_digest().unwrap()
    );
    assert_ne!(
        aos_contract::canonical::to_vec(&first).unwrap(),
        aos_contract::canonical::to_vec(&second).unwrap()
    );
}

#[test]
fn package_semantic_identity_uses_module_content_and_relative_path() {
    let bytes = aos_contract::canonical::to_vec(&projection()).unwrap();
    let projection = decode_package_projection(&bytes).unwrap();
    let payload = artifact("payload", "/nix/store/payload");
    let source = artifact("source", "/nix/store/source.drv");
    let resolve = |projection| {
        resolve_package_projection(
            projection,
            payload.clone(),
            source.clone(),
            |selector| match (selector.package.as_str(), selector.output.as_str()) {
                ("self", "out") => Ok(payload.clone()),
                ("self", "module") => Ok(artifact("module", "/nix/store/owner-module")),
                ("dependency", "bin") => Ok(artifact("dependency", "/nix/store/dependency-bin")),
                _ => unreachable!("fixture contains only declared selectors"),
            },
        )
        .unwrap()
    };
    let original = resolve(projection);

    let mut relocated = original.clone();
    relocated
        .package_module
        .as_mut()
        .unwrap()
        .artifact
        .store_path = "/nix/store/relocated-module".to_string();
    assert_eq!(
        original.content_digest().unwrap(),
        relocated.content_digest().unwrap()
    );

    let mut changed_closure = original.clone();
    changed_closure
        .package_module
        .as_mut()
        .unwrap()
        .artifact
        .closure = Sha256Digest::of_bytes("new closure");
    assert_ne!(
        original.content_digest().unwrap(),
        changed_closure.content_digest().unwrap()
    );

    let mut changed_nar = original.clone();
    changed_nar
        .package_module
        .as_mut()
        .unwrap()
        .artifact
        .nar_hash = Sha256Digest::of_bytes("new nar");
    assert_ne!(
        original.content_digest().unwrap(),
        changed_nar.content_digest().unwrap()
    );

    let mut changed_content = original.clone();
    changed_content
        .package_module
        .as_mut()
        .unwrap()
        .artifact
        .content = Sha256Digest::of_bytes("new module content");
    assert_ne!(
        original.content_digest().unwrap(),
        changed_content.content_digest().unwrap()
    );

    let mut changed_path = original.clone();
    changed_path.package_module.as_mut().unwrap().path =
        aos_ability_model::RelativePath::new("provider/module.nix").unwrap();
    assert_ne!(
        original.content_digest().unwrap(),
        changed_path.content_digest().unwrap()
    );
}

#[test]
fn qualification_identity_uses_observer_semantics_without_store_locator() {
    let bytes = aos_contract::canonical::to_vec(&projection()).unwrap();
    let projection = decode_package_projection(&bytes).unwrap();
    let payload = artifact("payload", "/nix/store/payload");
    let source = artifact("source", "/nix/store/source.drv");
    let mut document =
        resolve_package_projection(projection, payload.clone(), source, |selector| {
            match (selector.package.as_str(), selector.output.as_str()) {
                ("self", "out") => Ok(payload.clone()),
                ("self", "module") => Ok(artifact("module", "/nix/store/owner-module")),
                ("dependency", "bin") => Ok(artifact("dependency", "/nix/store/dependency-bin")),
                _ => unreachable!("fixture contains only declared selectors"),
            }
        })
        .unwrap();
    let observer = artifact("observer", "/nix/store/observer");
    document.qualification.implementations.insert(
        Sha256Digest::of_bytes("implementation"),
        aos_ability_model::ProviderQualification {
            adapter: LocalKey::new("fixture-adapter").unwrap(),
            scope: LocalKey::new("fixture-scope").unwrap(),
            observation_kind: LocalKey::new("fixture-observation").unwrap(),
            conformance_families: vec![LocalKey::new("lifecycle").unwrap()],
            observer: aos_ability_model::HandlerDescriptor {
                artifact: observer,
                entry_point: "bin/observe".to_string(),
                arguments: serde_json::from_value(json!({"kind": "boolean"})).unwrap(),
                result: serde_json::from_value(json!({"kind": "boolean"})).unwrap(),
            },
        },
    );

    let semantic = document.content_digest().unwrap();
    let mut relocated = document.clone();
    relocated
        .qualification
        .implementations
        .values_mut()
        .next()
        .unwrap()
        .observer
        .artifact
        .store_path = "/nix/store/relocated-observer".to_string();
    assert_eq!(semantic, relocated.content_digest().unwrap());

    let mut changed = document;
    changed
        .qualification
        .implementations
        .values_mut()
        .next()
        .unwrap()
        .observer
        .artifact
        .closure = Sha256Digest::of_bytes("changed observer closure");
    assert_ne!(semantic, changed.content_digest().unwrap());
}

#[test]
fn resolves_selectors_nested_in_portable_executable_values() {
    let selected = artifact("service", "/nix/store/service");
    let mut executable = json!({
        "artifact": {
            "_type": "aos-package-output-selector",
            "package": "self",
            "output": "out"
        },
        "entry_point": "bin/service",
        "arguments": ["--foreground"]
    });

    resolve_artifact_selectors(&mut executable, |selector| {
        assert_eq!(selector.package.as_str(), "self");
        assert_eq!(selector.output.as_str(), "out");
        Ok(selected.clone())
    })
    .unwrap();

    assert_eq!(
        executable["artifact"],
        serde_json::to_value(selected).unwrap()
    );
    assert_eq!(executable["entry_point"], "bin/service");
    assert_eq!(executable["arguments"], json!(["--foreground"]));
}

#[test]
fn rejects_nonclosed_nested_selectors() {
    let mut executable = json!({
        "artifact": {
            "_type": "aos-package-output-selector",
            "package": "self",
            "output": "out",
            "store_path": "/nix/store/untrusted"
        },
        "entry_point": "bin/service",
        "arguments": []
    });

    assert!(
        resolve_artifact_selectors(&mut executable, |_| unreachable!(
            "a malformed selector must fail before resolution"
        ),)
        .is_err()
    );
}

#[test]
fn preserves_the_canonical_runtime_path_expression_for_later_typed_resolution() {
    let mut value = json!({
        "_type": "aos-runtime-path",
        "base": "/nix/store/service",
        "relative_path": "bin/daemon"
    });
    let original = value.clone();

    resolve_artifact_selectors(&mut value, |_| {
        unreachable!("fixture contains no package selector")
    })
    .unwrap();

    assert_eq!(value, original);
}
