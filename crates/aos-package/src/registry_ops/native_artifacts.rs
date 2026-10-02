//! Authenticated publication of native deployment envelopes and module references.
//!
//! Native artifacts keep their evaluator-produced JSON inside immutable directory
//! roots. The catalog binds the JSON bytes; the signed store graph retains the
//! source and payload closure without translating it into another schema.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use aos_core::output::Printer;
use aos_doc_model::runtime::RuntimeDocument;
use aos_release::inventory::DerivationPackage;

use super::metadata::record_native_artifacts;
use super::sha256_hex;
use super::store_paths::{
    first_letter, introspect_store_path, validate_store_path_release_policy, write_store_files,
};
use crate::deployment::model::Envelope;
use crate::types::NativeArtifactMeta;

/// Retains evaluator-owned deployment and documentation beside one package entry.
///
/// # Errors
/// Returns an error for unavailable artifacts, mismatched coordinates or payloads,
/// malformed native documents, incomplete retention, or catalog writes.
pub(super) fn publish_native_artifacts(
    directory: &Path,
    package: &DerivationPackage,
    platform: &str,
    printer: &Printer,
) -> Result<()> {
    let version = &package
        .publication
        .as_ref()
        .context("package lacks publication identity")?
        .version;
    let deployment = package
        .deployment
        .as_ref()
        .context("evaluated package lacks its native deployment artifact")?;
    for artifact in std::iter::once(deployment)
        .chain(
            package
                .outputs
                .iter()
                .filter_map(|output| output.deployment.as_ref()),
        )
        .chain(package.module_documentation.iter())
        .chain(package.qualification.iter())
    {
        let result = super::store_paths::nix_command("nix-store")?
            .args(["--realise", &artifact.derivation])
            .output()?;
        ensure!(
            result.status.success(),
            "building native publication artifact failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        ensure!(
            String::from_utf8_lossy(&result.stdout)
                .lines()
                .any(|path| path == artifact.store_path),
            "native publication build returned another artifact root"
        );
    }
    let outputs = package
        .outputs
        .iter()
        .map(|output| (output.name.clone(), output.store_path.clone()))
        .collect();
    publish_native_documents(
        directory,
        &package.name,
        version,
        platform,
        &outputs,
        &deployment.store_path,
        package
            .module_documentation
            .as_ref()
            .map(|artifact| artifact.store_path.as_str()),
        package
            .qualification
            .as_ref()
            .map(|artifact| artifact.store_path.as_str()),
        printer,
    )?;
    for output in &package.outputs {
        if let Some(companion) = &output.deployment {
            if companion.store_path == deployment.store_path {
                continue;
            }
            publish_native_documents(
                directory,
                &package.name,
                version,
                platform,
                &outputs,
                &companion.store_path,
                package
                    .module_documentation
                    .as_ref()
                    .map(|artifact| artifact.store_path.as_str()),
                package
                    .qualification
                    .as_ref()
                    .map(|artifact| artifact.store_path.as_str()),
                printer,
            )?;
        }
    }
    Ok(())
}

// Qualification selectors name packages. Runtime dependency map keys are local
// roles, so they cannot authenticate a package coordinate. Build-only bindings
// remain authorized by the companion's exact signed NAR reference edges above.
fn check_qualification_runtime_binding(
    envelope: &Envelope,
    binding: &aos_release::qualification_document::QualificationBinding,
) -> Result<()> {
    for dependency in envelope.runtime_dependencies.values() {
        if dependency.name == binding.selector.package {
            ensure!(
                dependency.outputs.get(&binding.selector.output) == Some(&binding.path),
                "qualification dependency binding differs from native envelope"
            );
        }
    }
    Ok(())
}

/// Binds built native artifacts to exact frozen release outputs.
///
/// # Errors
/// Returns an error when artifact bytes, package coordinates, or retained store
/// roots differ from the frozen release inputs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_native_documents(
    directory: &Path,
    name: &str,
    version: &str,
    platform: &str,
    outputs: &BTreeMap<String, String>,
    deployment_path: &str,
    documentation_path: Option<&str>,
    qualification_path: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let (deployment_meta, deployment_bytes) =
        inspect_native_artifact(deployment_path, "deployment.json")?;
    let envelope = Envelope::decode(&deployment_bytes)?;
    ensure!(
        envelope.package.name == name
            && envelope.package.version == version
            && envelope.system == platform,
        "native envelope differs from its authenticated release coordinate"
    );
    ensure!(
        &envelope.package.outputs == outputs,
        "native envelope differs from evaluated payload outputs"
    );

    ensure!(
        outputs.values().any(|path| path == &envelope.package.path),
        "native envelope selection differs from authenticated payload outputs"
    );

    // Roots embedded in JSON are retained explicitly even when the artifact
    // builder's text serialization does not preserve every Nix string context.
    let mut roots = envelope
        .package
        .outputs
        .values()
        .cloned()
        .collect::<Vec<_>>();
    roots.extend(
        envelope
            .runtime_dependencies
            .values()
            .flat_map(|artifact| artifact.outputs.values().cloned()),
    );
    roots.extend(
        envelope
            .module
            .iter()
            .chain(
                envelope
                    .module_dependencies
                    .iter()
                    .map(|dependency| dependency.seed()),
            )
            .map(|module| module.source.clone()),
    );
    roots.push(deployment_path.to_owned());

    let documentation = if let Some(artifact) = documentation_path {
        let (metadata, bytes) = inspect_native_artifact(artifact, "options.json")?;
        let reference = RuntimeDocument::from_json(&bytes)?;
        reference.verify_package_identity(name, version, platform)?;
        verify_documented_resolution(&envelope, &reference)?;
        roots.push(artifact.to_owned());
        Some(metadata)
    } else {
        ensure!(
            envelope.module.is_none(),
            "module package lacks generated reference documentation"
        );
        None
    };
    let qualification = if let Some(artifact) = qualification_path {
        let (metadata, bytes) = inspect_native_artifact(artifact, "qualification.json")?;
        let document = aos_release::qualification_document::QualificationDocument::decode(
            &bytes, name, version,
        )?;
        for binding in document.artifacts() {
            ensure!(
                metadata
                    .references
                    .contains(&crate::registry::store_path_hash(&binding.path).to_owned()),
                "qualification payload is absent from artifact NAR references"
            );
            if binding.selector.package == name {
                ensure!(
                    outputs.get(&binding.selector.output) == Some(&binding.path),
                    "qualification owner binding differs from frozen output"
                );
            } else {
                check_qualification_runtime_binding(&envelope, binding)?;
            }
            roots.push(binding.path.clone());
        }
        roots.push(artifact.to_owned());
        Some(metadata)
    } else {
        None
    };
    roots.sort();
    roots.dedup();
    for root in roots {
        let info = introspect_store_path(&root)?;
        validate_store_path_release_policy(&info)?;
        write_store_files(directory, &root, false, false, printer)?;
    }

    let path = directory
        .join("packages")
        .join(first_letter(name))
        .join(format!("{name}.toml"));
    let content =
        fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    if outputs.get("out") != Some(&envelope.package.path) {
        let catalog = crate::registry::parse::parse_package_file(&content)?;
        let primary = catalog
            .versions
            .iter()
            .find(|candidate| candidate.version == version)
            .and_then(|candidate| candidate.platforms.get(platform))
            .context("named output lacks its primary native catalog")?;
        envelope.verify_catalog_resolution(
            primary.version_requirement.as_deref(),
            primary.os_version.as_deref(),
            &primary.module_dependencies,
        )?;
        let output = outputs
            .iter()
            .find(|(_, path)| *path == &envelope.package.path)
            .map(|(name, _)| name)
            .context("native selected output is absent")?;
        let content = super::output_evidence::record_output_facts(
            &content,
            name,
            version,
            platform,
            output,
            Some(&deployment_meta),
            None,
        )?;
        return fs::write(&path, content).with_context(|| format!("writing {}", path.display()));
    }
    let content = record_native_artifacts(
        &content,
        name,
        version,
        platform,
        &deployment_meta,
        documentation.as_ref(),
        qualification.as_ref(),
        envelope.version_requirement.as_deref(),
        envelope.os_version.as_deref(),
        &envelope.module_dependencies,
    )?;
    fs::write(&path, content).with_context(|| format!("writing {}", path.display()))
}

// The reference and discovery index come from the same native declarations.
// Checking their owned projections prevents a signed, stale companion from
// advertising a contract that the published module no longer declares.
fn verify_documented_resolution(envelope: &Envelope, document: &RuntimeDocument) -> Result<()> {
    use crate::deployment::model::{ModuleDependency, ModuleRequirement};

    let reference = document
        .reference()
        .context("native module reference is absent")?;
    let identities = reference
        .packages
        .iter()
        .filter(|package| package.name == envelope.package.name)
        .collect::<Vec<_>>();
    ensure!(
        identities.len() == 1
            && identities[0].version == envelope.package.version
            && identities[0].version_requirement == envelope.version_requirement,
        "module documentation package requirement differs from native envelope"
    );

    let declared_os =
        envelope
            .os_version
            .as_ref()
            .map(|requirement| aos_doc_model::runtime::OsRequirement {
                owner: envelope.package.name.clone(),
                os_version: requirement.clone(),
            });
    let documented_os = reference
        .os_requirements
        .iter()
        .filter(|requirement| requirement.owner == envelope.package.name)
        .collect::<Vec<_>>();
    ensure!(
        documented_os == declared_os.as_ref().into_iter().collect::<Vec<_>>(),
        "module documentation OS requirement differs from native envelope"
    );

    let mut documented = reference
        .module_requirements
        .iter()
        .filter(|requirement| requirement.owner == envelope.package.name)
        .map(|requirement| ModuleRequirement {
            package: requirement.package.clone(),
            package_version: requirement.package_version.clone(),
        })
        .collect::<Vec<_>>();
    let mut declared = envelope
        .module_dependencies
        .iter()
        .filter_map(ModuleDependency::requirement)
        .collect::<Vec<_>>();
    documented.sort_by(|left, right| left.package.cmp(&right.package));
    declared.sort_by(|left, right| left.package.cmp(&right.package));
    ensure!(
        documented == declared,
        "module documentation requirements differ from native envelope"
    );
    Ok(())
}

pub(super) fn inspect_native_artifact(
    store_path: &str,
    filename: &str,
) -> Result<(NativeArtifactMeta, Vec<u8>)> {
    let info = introspect_store_path(store_path)?;
    validate_store_path_release_policy(&info)?;
    let path = Path::new(store_path).join(filename);
    let metadata =
        fs::symlink_metadata(&path).with_context(|| format!("inspecting {}", path.display()))?;
    ensure!(
        metadata.is_file()
            && metadata.len() > 0
            && metadata.len() <= aos_doc_model::runtime::MAX_RUNTIME_DOCUMENT_BYTES as u64,
        "native artifact must contain a bounded regular JSON file"
    );
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "native artifact changed during reading"
    );
    let mut references = info.references.clone();
    references.sort();
    references.dedup();
    let artifact = NativeArtifactMeta {
        store_path: info.path,
        nar_hash: info.nar_hash,
        nar_size: info.nar_size,
        references,
        document_sha256: format!("sha256:{}", sha256_hex(&bytes)),
        document_size: bytes.len() as u64,
    };
    artifact.validate()?;
    Ok((artifact, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_reference_versions_and_requirements_match_the_exact_envelope() {
        use serde_json::json;

        let path = "/nix/store/00000000000000000000000000000000-example";
        let envelope = Envelope::decode(&serde_json::to_vec(&json!({
            "schema":"aos.package.deployment","system":"x86_64-linux",
            "package":{"name":"example","version":"7.0.0","path":path,"outputs":{"out":path},"mainProgram":null},
            "module":{"name":"example","version":"7.0.0","source":"/nix/store/11111111111111111111111111111111-example-source","entrypoint":"module.nix"},
            "versionRequirement":"~7.0.0","osVersion":"^1.0","runtimeDependencies":{},
            "moduleDependencies":[{"package":{"name":"interfaces","version":"9","source":"/nix/store/22222222222222222222222222222222-interfaces","entrypoint":"module.nix"},"packageVersion":"^9.0"}]
        })).unwrap()).unwrap();
        let mut reference = json!({"schema":"aos.module.documentation","scope":["package","example"],
            "system":"x86_64-linux","packages":[{"name":"example","version":"7.0.0","versionRequirement":"~7.0.0"}],"options":[],"abilities":{},
            "osRequirements":[{"owner":"example","osVersion":"^1.0"}],
            "moduleRequirements":[{"owner":"example","package":"interfaces","packageVersion":"^9.0"}]});
        let decode = |value: &serde_json::Value| {
            RuntimeDocument::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
        };

        verify_documented_resolution(&envelope, &decode(&reference)).unwrap();

        reference["packages"][0]["versionRequirement"] = json!("^7.0.0");
        assert!(verify_documented_resolution(&envelope, &decode(&reference)).is_err());
        reference["packages"][0]["versionRequirement"] = json!("~7.0.0");
        reference["osRequirements"][0]["osVersion"] = json!("^2.0");
        assert!(verify_documented_resolution(&envelope, &decode(&reference)).is_err());
        reference["osRequirements"][0]["osVersion"] = json!("^1.0");
        reference["moduleRequirements"][0]["packageVersion"] = json!("^10.0");
        assert!(verify_documented_resolution(&envelope, &decode(&reference)).is_err());
    }

    #[test]
    fn qualification_package_coordinates_do_not_borrow_runtime_role_names() {
        use crate::deployment::model::Artifact;
        use aos_release::qualification_document::{QualificationBinding, QualificationSelector};

        let path = "/nix/store/11111111111111111111111111111111-tool".to_owned();
        let dependency = Artifact {
            name: "actual-tool".into(),
            version: "1".into(),
            path: path.clone(),
            outputs: BTreeMap::from([("out".into(), path.clone())]),
            main_program: None,
        };
        let mut envelope = Envelope {
            schema: "aos.package.deployment".into(),
            system: "x86_64-linux".into(),
            package: dependency.clone(),
            module: None,
            version_requirement: None,
            os_version: None,
            runtime_dependencies: BTreeMap::from([("lexical-role".into(), dependency.clone())]),
            module_dependencies: Vec::new(),
        };
        let mut binding = QualificationBinding {
            selector: QualificationSelector {
                package: "actual-tool".into(),
                output: "out".into(),
            },
            path,
        };
        check_qualification_runtime_binding(&envelope, &binding).unwrap();

        binding.path = "/nix/store/22222222222222222222222222222222-other-tool".into();
        assert!(check_qualification_runtime_binding(&envelope, &binding).is_err());
        let mut conflicting = dependency;
        conflicting
            .outputs
            .insert("out".into(), binding.path.clone());
        envelope
            .runtime_dependencies
            .insert("second-role".into(), conflicting);
        assert!(check_qualification_runtime_binding(&envelope, &binding).is_err());
    }

    #[test]
    fn native_catalog_binding_retires_legacy_projection_and_gates_consumption() {
        use crate::deployment::model::{ModuleDependency, ModuleSource};

        let dependencies = vec![ModuleDependency::Ranged {
            package: ModuleSource {
                name: "interfaces".into(),
                version: "7.0.0".into(),
                source: "/nix/store/22222222222222222222222222222222-interfaces".into(),
                entrypoint: "module.nix".into(),
            },
            package_version: "^7.0".into(),
        }];
        let artifact = NativeArtifactMeta {
            store_path: "/nix/store/00000000000000000000000000000000-reference".to_owned(),
            nar_hash: format!("sha256:{}", "1".repeat(64)),
            nar_size: 512,
            references: Vec::new(),
            document_sha256: format!("sha256:{}", "2".repeat(64)),
            document_size: 128,
        };
        let content = r#"
[package]
name = "example"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/11111111111111111111111111111111-example"
references = []
documentation = { legacy = true }
contract = { legacy = true }
"#;

        let encoded = record_native_artifacts(
            content,
            "example",
            "1.0.0",
            "x86_64-linux",
            &artifact,
            Some(&artifact),
            Some(&artifact),
            Some("^1.0.0"),
            Some("^1.0"),
            &dependencies,
        )
        .unwrap();
        let document: toml::Value = toml::from_str(&encoded).unwrap();
        let platform = &document["versions"][0]["platforms"]["x86_64-linux"];
        assert!(platform.get("documentation").is_none());
        assert!(platform.get("contract").is_none());
        assert_eq!(
            platform["deployment"]["store_path"].as_str(),
            Some(artifact.store_path.as_str())
        );
        assert_eq!(
            platform["module_documentation"]["document_sha256"].as_str(),
            Some(artifact.document_sha256.as_str())
        );
        assert_eq!(
            platform["requires-features"][0].as_str(),
            Some("native-package-modules-v1")
        );
        assert_eq!(
            platform["references"]["requires-features"][0].as_str(),
            Some("native-package-modules-v1")
        );
        assert_eq!(platform["version_requirement"].as_str(), Some("^1.0.0"));
        assert_eq!(platform["osVersion"].as_str(), Some("^1.0"));
        let decoded: Vec<ModuleDependency> =
            platform["module_dependencies"].clone().try_into().unwrap();
        assert_eq!(decoded, dependencies);

        let rewritten = record_native_artifacts(
            &encoded,
            "example",
            "1.0.0",
            "x86_64-linux",
            &artifact,
            Some(&artifact),
            Some(&artifact),
            None,
            None,
            &[],
        )
        .unwrap();
        let rewritten: toml::Value = toml::from_str(&rewritten).unwrap();
        let rewritten = &rewritten["versions"][0]["platforms"]["x86_64-linux"];
        assert!(rewritten.get("version_requirement").is_none());
        assert!(rewritten.get("osVersion").is_none());
        assert!(rewritten.get("module_dependencies").is_none());
        assert!(
            record_native_artifacts(
                content,
                "different",
                "1.0.0",
                "x86_64-linux",
                &artifact,
                None,
                None,
                None,
                None,
                &[],
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod publication_tests {
    use super::super::metadata::build_package_toml;
    use super::super::test_support::init_authoring_clone;
    use super::*;

    #[test]
    fn evaluated_native_publication_retains_exact_artifacts_and_module_sources() {
        let Ok(fixture) = std::env::var("AOS_TEST_NATIVE_PUBLICATION_FIXTURE") else {
            return;
        };
        let fixture: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
        let registry = tempfile::tempdir().unwrap();
        init_authoring_clone(registry.path());
        let publications = fixture["publications"].as_array().unwrap();
        assert!(!publications.is_empty());

        for publication in publications {
            let envelope_path = Path::new(publication["envelope"].as_str().unwrap());
            let documentation_path = publication["documentation"].as_str().map(Path::new);
            let qualification_path = publication["qualification"].as_str().map(Path::new);
            let envelope = Envelope::decode(&fs::read(envelope_path).unwrap()).unwrap();
            let runtime = introspect_store_path(&envelope.package.path).unwrap();
            let encoded = build_package_toml(
                "",
                &envelope.package.name,
                &envelope.package.version,
                &envelope.system,
                &runtime,
                Some("Native publication fixture"),
                None,
                Some("Apache-2.0"),
                Some("AOS test"),
                false,
                None,
                &[],
                None,
            )
            .unwrap();
            let directory = registry
                .path()
                .join("packages")
                .join(first_letter(&envelope.package.name));
            fs::create_dir_all(&directory).unwrap();
            let catalog_path = directory.join(format!("{}.toml", envelope.package.name));
            fs::write(&catalog_path, encoded).unwrap();

            publish_native_documents(
                registry.path(),
                &envelope.package.name,
                &envelope.package.version,
                &envelope.system,
                &envelope.package.outputs,
                envelope_path.parent().unwrap().to_str().unwrap(),
                documentation_path.map(|path| path.parent().unwrap().to_str().unwrap()),
                qualification_path.map(|path| path.parent().unwrap().to_str().unwrap()),
                &Printer::new(0, true, false),
            )
            .unwrap();

            let package = crate::registry::parse::parse_package_file(
                &fs::read_to_string(&catalog_path).unwrap(),
            )
            .unwrap();
            let platform = &package.versions[0].platforms[&envelope.system];
            let deployment = platform.deployment.as_ref().unwrap();
            assert_eq!(
                crate::native_artifact::read_envelope(
                    deployment,
                    &envelope.package.name,
                    &envelope.package.version,
                    &envelope.system
                )
                .unwrap(),
                envelope
            );
            if let Some(path) = documentation_path {
                let documentation = platform.module_documentation.as_ref().unwrap();
                assert_eq!(
                    crate::native_artifact::read_document(documentation, "options.json").unwrap(),
                    fs::read(path).unwrap()
                );
            }
            if qualification_path.is_some() {
                let qualification = platform.qualification.as_ref().unwrap();
                let document = crate::native_artifact::read_qualification(
                    qualification,
                    &envelope.package.name,
                    &envelope.package.version,
                )
                .unwrap();
                for binding in document.artifacts() {
                    assert!(
                        qualification
                            .references
                            .contains(&crate::registry::store_path_hash(&binding.path).to_owned())
                    );
                }
            }
            let graph = crate::registry::store::StoreMap::load(registry.path()).unwrap();
            for root in std::iter::once(&deployment.store_path)
                .chain(
                    platform
                        .module_documentation
                        .iter()
                        .map(|artifact| &artifact.store_path),
                )
                .chain(platform.qualification.iter().flat_map(|artifact| {
                    std::iter::once(&artifact.store_path).chain(artifact.references.iter())
                }))
                .chain(envelope.module.iter().map(|module| &module.source))
                .chain(
                    envelope
                        .module_dependencies
                        .iter()
                        .map(|dependency| &dependency.seed().source),
                )
            {
                assert!(
                    graph.get(crate::registry::store_path_hash(root)).is_some(),
                    "unretained root {root}"
                );
            }
        }
    }
}
