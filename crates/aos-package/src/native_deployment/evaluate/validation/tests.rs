//! Exercises offline declaration replay without registry candidates or effects.

use std::collections::BTreeSet;
use std::path::PathBuf;

use aos_contract::Sha256Digest;

use super::*;
use crate::deployment::model::{Artifact, ModuleDependency, ModuleSource, ResolvedPackages};
use crate::native_deployment::{LockedEdge, ResolutionLock};

fn envelope(name: &str, version: &str, hash: char) -> Envelope {
    let path = format!("/nix/store/{}-{name}", hash.to_string().repeat(32));
    Envelope {
        schema: "aos.package.deployment".into(),
        system: "x86_64-linux".into(),
        package: Artifact {
            name: name.into(),
            version: version.into(),
            path: path.clone(),
            outputs: BTreeMap::from([("out".into(), path)]),
            main_program: None,
        },
        module: Some(ModuleSource {
            name: name.into(),
            version: version.into(),
            source: format!("/nix/store/{}-{name}-module", hash.to_string().repeat(32)),
            entrypoint: "module.nix".into(),
        }),
        version_requirement: None,
        os_version: None,
        runtime_dependencies: BTreeMap::new(),
        module_dependencies: Vec::new(),
    }
}

fn companion(envelope: &Envelope) -> PathBuf {
    PathBuf::from(format!(
        "/nix/store/{}-{}-envelope",
        "d".repeat(32),
        envelope.package.name
    ))
}

fn fixture(ranged: bool, moduleless: bool) -> (EvaluationInput, BTreeMap<PathBuf, Envelope>) {
    let provider = envelope("provider", "19.4.0", 'b');
    let source = provider.module.clone().unwrap();
    let dependency = if ranged {
        ModuleDependency::Ranged {
            package: source.clone(),
            package_version: "^19".into(),
        }
    } else {
        ModuleDependency::Exact(source.clone())
    };
    let mut consumer = envelope("consumer", "1.0.0", 'a');
    if moduleless {
        consumer.module = None;
    }
    consumer.module_dependencies.push(dependency.clone());
    let envelopes = [consumer.clone(), provider];
    let resolution_lock = ranged.then(|| ResolutionLock {
        schema: "aos.package.resolution-lock".into(),
        edges: vec![LockedEdge {
            requester: consumer.package.canonical_catalog(),
            requirement: dependency,
            selected: source,
        }],
        requesters: BTreeMap::from([(
            consumer.package.canonical_catalog().path,
            companion(&consumer),
        )]),
    });
    let descriptor = EvaluationInput {
        os_release: None,
        package_envelopes: BTreeMap::from([(consumer.package.path.clone(), companion(&consumer))]),
        schema: "aos.package.evaluation-input".into(),
        library: PathBuf::from(format!("/nix/store/{}-library/default.nix", "f".repeat(32))),
        library_nar_hash: Sha256Digest::of_bytes(b"library"),
        scope: vec!["profile".into(), "system".into()],
        packages: ResolvedPackages {
            system: "x86_64-linux".into(),
            artifacts: vec![consumer.package],
            modules: envelopes
                .iter()
                .filter_map(Envelope::module_record)
                .collect(),
        },
        module_envelopes: envelopes
            .iter()
            .filter(|envelope| envelope.module.is_some())
            .map(|envelope| (envelope.package.name.clone(), companion(envelope)))
            .collect(),
        resolution_lock,
        configuration: Vec::new(),
        runtime_configuration: Vec::new(),
        supplemental_inputs: Vec::new(),
    };
    let bytes = serde_json::to_vec(&descriptor).unwrap();
    let descriptor = EvaluationInput::decode(&bytes).unwrap();
    let companions = envelopes
        .into_iter()
        .map(|envelope| (companion(&envelope), envelope))
        .collect();
    (descriptor, companions)
}

fn check(descriptor: &EvaluationInput, companions: &BTreeMap<PathBuf, Envelope>) -> Result<()> {
    validate_with(descriptor, |path| {
        ensure!(path.file_name().unwrap() == "deployment.json");
        let envelope = companions
            .get(path.parent().unwrap())
            .context("fixture companion is absent")?;
        Ok(serde_json::to_vec(envelope)?)
    })
    .map(|_| ())
}

#[test]
fn replays_exact_and_locked_modules_without_registry_discovery() {
    for ranged in [false, true] {
        let (descriptor, companions) = fixture(ranged, false);
        check(&descriptor, &companions).unwrap();
    }
}

#[test]
fn rejects_edited_original_requirement_and_selected_source() {
    let (descriptor, companions) = fixture(true, false);
    let mut requirement = descriptor.clone();
    let edge = &mut requirement.resolution_lock.as_mut().unwrap().edges[0];
    if let ModuleDependency::Ranged {
        package_version, ..
    } = &mut edge.requirement
    {
        *package_version = "^2".into();
    }
    assert!(check(&requirement, &companions).is_err());

    let mut selected = descriptor;
    selected.resolution_lock.as_mut().unwrap().edges[0]
        .selected
        .source = format!("/nix/store/{}-replacement-module", "c".repeat(32));
    assert!(check(&selected, &companions).is_err());
}

#[test]
fn rejects_moduleless_os_requirements_without_a_matching_retained_release() {
    for ranged in [false, true] {
        let (mut descriptor, mut companions) = fixture(ranged, true);
        let consumer = companions
            .get_mut(&descriptor.package_envelopes[&descriptor.packages.artifacts[0].path])
            .unwrap();
        consumer.os_version = Some("^2".into());
        assert!(check(&descriptor, &companions).is_err());

        descriptor.os_release = Some(aos_doc_model::runtime::OsRelease {
            name: "aos".into(),
            version: "1.0.0".into(),
        });
        assert!(check(&descriptor, &companions).is_err());

        descriptor.os_release.as_mut().unwrap().version = "2.1.0".into();
        check(&descriptor, &companions).unwrap();
        let projected = validate_with(&descriptor, |path| {
            Ok(serde_json::to_vec(&companions[path.parent().unwrap()])?)
        })
        .unwrap();
        assert_eq!(
            projected.os_requirements,
            vec![aos_doc_model::runtime::OsRequirement {
                owner: "consumer".into(),
                os_version: "^2".into(),
            }]
        );
    }
}

#[test]
fn rejects_changed_module_os_requirements_even_with_a_compatible_host() {
    let (mut descriptor, mut companions) = fixture(false, false);
    companions
        .get_mut(&descriptor.module_envelopes["provider"])
        .unwrap()
        .os_version = Some("^2".into());
    descriptor.os_release = Some(aos_doc_model::runtime::OsRelease {
        name: "aos".into(),
        version: "2.0.0".into(),
    });
    assert!(check(&descriptor, &companions).is_err());
}

#[test]
fn opens_moduleless_requesters_and_checks_their_original_edges() {
    let (descriptor, companions) = fixture(true, true);
    let mut opened = BTreeSet::new();
    validate_with(&descriptor, |path| {
        opened.insert(path.parent().unwrap().to_path_buf());
        Ok(serde_json::to_vec(&companions[path.parent().unwrap()])?)
    })
    .unwrap();
    assert_eq!(opened.len(), 2);

    let requester = descriptor
        .resolution_lock
        .as_ref()
        .unwrap()
        .requesters
        .values()
        .next()
        .unwrap();
    let mut changed = companions;
    changed
        .get_mut(requester)
        .unwrap()
        .module_dependencies
        .clear();
    assert!(check(&descriptor, &changed).is_err());
}

#[test]
fn rejects_missing_or_unselected_requester_companions() {
    let (mut descriptor, mut companions) = fixture(true, true);
    let requester = descriptor
        .resolution_lock
        .as_ref()
        .unwrap()
        .requesters
        .values()
        .next()
        .unwrap()
        .clone();
    let original = companions.remove(&requester).unwrap();
    assert!(check(&descriptor, &companions).is_err());

    companions.insert(requester, original);
    descriptor.packages.artifacts.clear();
    assert!(check(&descriptor, &companions).is_err());
}

#[test]
fn rejects_extra_module_or_missing_requester_catalog_entries_before_reading() {
    let (descriptor, _) = fixture(true, false);
    let mut extra = descriptor.clone();
    extra.module_envelopes.insert(
        "unselected".into(),
        PathBuf::from(format!("/nix/store/{}-unselected-envelope", "c".repeat(32))),
    );
    assert!(validate_with(&extra, |_| panic!("unexpected envelope read")).is_err());

    let mut missing = descriptor;
    missing.resolution_lock.as_mut().unwrap().requesters.clear();
    assert!(validate_with(&missing, |_| panic!("unexpected envelope read")).is_err());
}

#[test]
fn rejects_exact_dependency_source_drift_and_missing_modules() {
    let (descriptor, companions) = fixture(false, false);
    let mut drifted = companions.clone();
    let consumer = drifted
        .get_mut(&descriptor.module_envelopes["consumer"])
        .unwrap();
    if let ModuleDependency::Exact(source) = &mut consumer.module_dependencies[0] {
        source.source = format!("/nix/store/{}-replacement-module", "c".repeat(32));
    }
    assert!(check(&descriptor, &drifted).is_err());

    let mut missing = descriptor;
    missing
        .packages
        .modules
        .retain(|module| module.name != "provider");
    missing.module_envelopes.remove("provider");
    assert!(check(&missing, &companions).is_err());
}

#[test]
fn retains_canonical_envelopes_for_named_payload_outputs() {
    let (mut descriptor, mut companions) = fixture(false, true);
    let canonical_path = descriptor.packages.artifacts[0].path.clone();
    let companion_path = descriptor.package_envelopes[&canonical_path].clone();
    let selected_path = format!("/nix/store/{}-consumer-tools", "g".repeat(32));

    let envelope = companions.get_mut(&companion_path).unwrap();
    envelope
        .package
        .outputs
        .insert("tools".into(), selected_path.clone());
    let payload = &mut descriptor.packages.artifacts[0];
    payload.outputs = envelope.package.outputs.clone();
    payload.path = selected_path;

    let decoded = EvaluationInput::decode(&serde_json::to_vec(&descriptor).unwrap()).unwrap();
    assert_eq!(decoded.package_envelopes[&canonical_path], companion_path);
    check(&decoded, &companions).unwrap();
}

#[test]
fn rejects_payloads_without_retained_envelope_catalogs() {
    let (mut descriptor, _) = fixture(false, true);
    descriptor.package_envelopes.clear();

    assert!(EvaluationInput::decode(&serde_json::to_vec(&descriptor).unwrap()).is_err());
    assert!(validate_with(&descriptor, |_| panic!("unexpected envelope read")).is_err());
}

#[test]
fn checks_current_target_without_changing_historical_replay() {
    for moduleless in [false, true] {
        let (mut descriptor, mut companions) = fixture(false, moduleless);
        let root = descriptor.package_envelopes[&descriptor.packages.artifacts[0].path].clone();
        companions.get_mut(&root).unwrap().os_version = Some("^1".into());
        descriptor.packages.modules = companions
            .values()
            .filter_map(Envelope::module_record)
            .collect();
        descriptor.os_release = Some(aos_doc_model::runtime::OsRelease {
            name: "Original OS".into(),
            version: "1.2.0".into(),
        });
        let original = descriptor.clone();
        let read = |path: &Path| -> Result<Vec<u8>> {
            Ok(serde_json::to_vec(&companions[path.parent().unwrap()])?)
        };

        check(&descriptor, &companions).unwrap();
        let current = Some(aos_doc_model::runtime::OsRelease {
            name: "Updated OS".into(),
            version: "2.0.0".into(),
        });
        assert!(validate_with_release(&descriptor, current, read).is_err());
        assert!(validate_with_release(&descriptor, None, read).is_err());
        assert_eq!(descriptor, original);
        check(&descriptor, &companions).unwrap();
    }
}

#[test]
fn accepts_a_compatible_current_target_without_replacing_retained_identity() {
    let (mut descriptor, mut companions) = fixture(false, true);
    let root = descriptor.package_envelopes[&descriptor.packages.artifacts[0].path].clone();
    companions.get_mut(&root).unwrap().os_version = Some(">=1, <3".into());
    descriptor.os_release = Some(aos_doc_model::runtime::OsRelease {
        name: "Original OS".into(),
        version: "1.0.0".into(),
    });
    let original = descriptor.clone();

    let current = Some(aos_doc_model::runtime::OsRelease {
        name: "Updated OS".into(),
        version: "2.0.0".into(),
    });
    validate_with_release(&descriptor, current, |path| {
        Ok(serde_json::to_vec(&companions[path.parent().unwrap()])?)
    })
    .unwrap();

    assert_eq!(descriptor, original);
}

#[test]
fn projects_original_recipe_policy_for_moduleless_payload_releases() {
    let (descriptor, mut companions) = fixture(false, true);
    let root = descriptor.package_envelopes[&descriptor.packages.artifacts[0].path].clone();
    companions.get_mut(&root).unwrap().version_requirement = Some("^1.0.0".into());

    let declarations = validate_with(&descriptor, |path| {
        Ok(serde_json::to_vec(&companions[path.parent().unwrap()])?)
    })
    .unwrap();

    let consumer = declarations
        .package_releases
        .iter()
        .find(|release| release.name == "consumer")
        .unwrap();
    assert_eq!(consumer.version, "1.0.0");
    assert_eq!(consumer.version_requirement.as_deref(), Some("^1.0.0"));
    let provider = declarations
        .package_releases
        .iter()
        .find(|release| release.name == "provider")
        .unwrap();
    assert_eq!(provider.version_requirement, None);
}
