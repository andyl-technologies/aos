//! Exercises offline declaration replay without registry candidates or effects.

use std::collections::BTreeSet;
use std::path::PathBuf;

use aos_contract::Sha256Digest;

use super::*;
use crate::deployment::model::{
    AbilityExport, Artifact, ModuleDependency, ModuleSource, ResolvedPackages,
};
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
        ability_exports: BTreeMap::new(),
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
    let mut provider = envelope("provider", "19.4.0", 'b');
    provider.ability_exports.insert(
        "storage".into(),
        AbilityExport {
            version: "1.4.0".into(),
        },
    );
    let source = provider.module.clone().unwrap();
    let dependency = if ranged {
        ModuleDependency::Ranged {
            package: source.clone(),
            abilities: BTreeMap::from([("storage".into(), "^1".into())]),
            package_version: Some("^19".into()),
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
    if let ModuleDependency::Ranged { abilities, .. } = &mut edge.requirement {
        abilities.insert("storage".into(), "^2".into());
    }
    assert!(check(&requirement, &companions).is_err());

    let mut selected = descriptor;
    selected.resolution_lock.as_mut().unwrap().edges[0]
        .selected
        .source = format!("/nix/store/{}-replacement-module", "c".repeat(32));
    assert!(check(&selected, &companions).is_err());
}

#[test]
fn rejects_incompatible_or_changed_ability_exports() {
    let (mut descriptor, mut companions) = fixture(true, false);
    let provider_path = descriptor.module_envelopes["provider"].clone();
    let provider = companions.get_mut(&provider_path).unwrap();
    provider.ability_exports.get_mut("storage").unwrap().version = "2.0.0".into();
    assert!(check(&descriptor, &companions).is_err());

    // Even when the copied catalog agrees with the changed export, the
    // original requester's independent ability range still rejects it.
    descriptor.packages.modules = companions
        .values()
        .filter_map(Envelope::module_record)
        .collect();
    assert!(check(&descriptor, &companions).is_err());
}

#[test]
fn rejects_duplicate_ability_owners_even_for_exact_only_closures() {
    let (mut descriptor, mut companions) = fixture(false, false);
    let consumer_path = descriptor.module_envelopes["consumer"].clone();
    companions
        .get_mut(&consumer_path)
        .unwrap()
        .ability_exports
        .insert(
            "storage".into(),
            AbilityExport {
                version: "1.4.0".into(),
            },
        );
    descriptor.packages.modules = companions
        .values()
        .filter_map(Envelope::module_record)
        .collect();

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
