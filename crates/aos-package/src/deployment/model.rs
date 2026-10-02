//! Native package envelopes and module-generated transaction documents.
//!
//! Envelopes bind artifacts to a package coordinate. Transaction documents carry
//! one resolved package module set and its generated effect graph:
//!
//! ```json
//! {"schema":"aos.package.transaction","scope":["profile","main"],"system":"x86_64-linux","artifacts":[],"inputs":[],"packages":[],"retire":[],"graph":{"schema":"aos.activation.graph","nodes":{},"order":[]}}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use aos_ability_plan::module_graph::{CheckedModuleGraph, GRAPH_LIMITS, Handler};
use aos_contract::{Sha256Digest, canonical};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Re-exports native declaration and dependency contracts shared with signed catalogs.
pub use aos_registry_surface::native_dependencies::{
    ModuleDependency, ModuleRequirement, ModuleSource,
};

/// Identifies realized package outputs without reconstructing a derivation.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Artifact {
    /// Names the package in the resolved catalog.
    pub name: String,
    /// Names its selected package version.
    pub version: String,
    /// Identifies the selected output for a payload, or canonical output in a module catalog.
    pub path: String,
    /// Names authenticated available outputs; listing one does not select or retain it.
    pub outputs: BTreeMap<String, String>,
    /// Selects the main binary when this artifact supplies a terminal handler.
    pub main_program: Option<String>,
}

/// Publishes a package's artifacts and explicit configuration dependencies.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Envelope {
    /// Identifies the native deployment envelope format.
    pub schema: String,
    /// Identifies the payload target platform.
    pub system: String,
    /// Describes this package's payload.
    pub package: Artifact,
    /// Supplies an optional deployment module.
    pub module: Option<ModuleSource>,
    /// Retains the generated compatibility requirement for this package release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_requirement: Option<String>,
    /// Restricts the host operating system release accepted by this package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Exposes exact runtime artifacts under package-owned local binding names.
    pub runtime_dependencies: BTreeMap<String, Artifact>,
    /// Names the module dependency closure's direct edges.
    pub module_dependencies: Vec<ModuleDependency>,
}

impl Envelope {
    /// Checks that a signed discovery catalog projects this exact envelope's declarations.
    ///
    /// # Errors
    /// Returns an error when OS constraints or dependency requests differ from authenticated bytes.
    pub fn verify_catalog_resolution(
        &self,
        version_requirement: Option<&str>,
        os_version: Option<&str>,
        dependencies: &[ModuleDependency],
    ) -> Result<()> {
        ensure!(
            self.version_requirement.as_deref() == version_requirement
                && self.os_version.as_deref() == os_version
                && self.module_dependencies == dependencies,
            "native resolution catalog differs from its authenticated envelope"
        );
        Ok(())
    }

    /// Decodes a bounded envelope; publication authenticity remains the resolver's responsibility.
    ///
    /// # Errors
    /// Returns an error for malformed records or inconsistent package identities.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let envelope: Self = GRAPH_LIMITS.decode(bytes, "package envelope")?;
        ensure!(
            envelope.schema == "aos.package.deployment",
            "unsupported package envelope"
        );
        ensure!(
            !envelope.system.is_empty(),
            "package target platform is absent"
        );
        envelope.package.check()?;
        aos_registry_surface::native_dependencies::check_version_requirement(
            &envelope.package.version,
            envelope.version_requirement.as_deref(),
        )?;
        if let Some(module) = &envelope.module {
            module.check()?;
            ensure!(
                module.name == envelope.package.name && module.version == envelope.package.version,
                "module differs from its package identity"
            );
        }
        for (name, artifact) in &envelope.runtime_dependencies {
            artifact.check()?;
            ensure!(!name.is_empty(), "runtime dependency binding is empty");
        }
        aos_registry_surface::native_dependencies::check_resolution_metadata(
            envelope.os_version.as_deref(),
            &envelope.module_dependencies,
        )?;
        Ok(envelope)
    }

    /// Produces the evaluator's resolved module record when the package has a module.
    #[must_use]
    pub fn module_record(&self) -> Option<PackageModule> {
        self.module.as_ref().map(|module| PackageModule {
            name: module.name.clone(),
            version: module.version.clone(),
            config_root: module.source.clone(),
            module: format!("{}/{}", module.source, module.entrypoint),
            version_requirement: self.version_requirement.clone(),
            os_version: self.os_version.clone(),
            module_requirements: self
                .module_dependencies
                .iter()
                .filter_map(ModuleDependency::requirement)
                .collect(),
            artifacts: ArtifactContext {
                package: self.package.canonical_catalog(),
                dependencies: self.runtime_dependencies.clone(),
            },
        })
    }
}

impl Artifact {
    /// Normalizes module identity independently of the selected payload output.
    ///
    /// The `out` output is preferred; packages without it use the first named
    /// output in canonical key order. The available catalog remains exact.
    #[must_use]
    pub fn canonical_catalog(&self) -> Self {
        let mut catalog = self.clone();
        if let Some(path) = self
            .outputs
            .get("out")
            .or_else(|| self.outputs.values().next())
        {
            catalog.path = path.clone();
        }
        catalog
    }

    pub(super) fn check(&self) -> Result<()> {
        ensure!(
            !self.name.is_empty() && !self.version.is_empty(),
            "artifact has no package coordinate"
        );
        store_root(&self.path)?;
        ensure!(
            !self.outputs.is_empty() && self.outputs.values().any(|path| path == &self.path),
            "artifact default output is absent from its output set"
        );
        for path in self.outputs.values() {
            store_root(path)?;
        }
        if let Some(program) = &self.main_program {
            ensure!(
                !program.is_empty()
                    && !matches!(program.as_str(), "." | "..")
                    && program
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"+-._".contains(&byte)),
                "invalid main program"
            );
        }
        Ok(())
    }
}

/// Supplies only the artifact values visible to one package module.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactContext {
    /// Supplies this package's payload outputs.
    pub package: Artifact,
    /// Supplies runtime artifacts under local binding names, independently of package coordinates.
    pub dependencies: BTreeMap<String, Artifact>,
}

/// Carries a module source and its resolver-owned evaluation context.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageModule {
    /// Identifies the module's declaring package.
    pub name: String,
    /// Identifies the selected package version.
    pub version: String,
    /// Retains the canonical source directory identity.
    pub config_root: String,
    /// Names its canonical module entry point.
    pub module: String,
    /// Retains the generated compatibility requirement for this package release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_requirement: Option<String>,
    /// Retains the host release compatibility constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Retains original ranged dependency requirements after exact resolution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub module_requirements: Vec<ModuleRequirement>,
    /// Supplies realized artifact references to module arguments.
    pub artifacts: ArtifactContext,
}

/// Carries both payloads and modules selected before entering a fixed point.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedPackages {
    /// Selects one explicit target platform for the entire scope.
    pub system: String,
    /// Includes only explicit payload selections; module and runtime catalogs remain available.
    pub artifacts: Vec<Artifact>,
    /// Supplies modules and their individual artifact contexts.
    pub modules: Vec<PackageModule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionDocument {
    schema: String,
    scope: Vec<String>,
    system: String,
    artifacts: Vec<Artifact>,
    inputs: Vec<String>,
    packages: Vec<PackageModule>,
    graph: Value,
    retire: Vec<String>,
}

/// Contains a checked transaction bound to one resolved package module set.
#[derive(Clone, Debug)]
pub struct Deployment {
    document: Value,
    scope: Vec<String>,
    system: String,
    artifacts: Vec<Artifact>,
    inputs: Vec<String>,
    packages: Vec<PackageModule>,
    graph: CheckedModuleGraph,
    retire: BTreeSet<String>,
}

impl Deployment {
    /// Decodes a transaction and binds its artifact references to the resolved input set.
    ///
    /// # Errors
    /// Returns an error for incompatible scopes, unresolved packages or handlers,
    /// malformed graphs, or package context changes during evaluation.
    pub fn decode(bytes: &[u8], expected: &ResolvedPackages) -> Result<Self> {
        let document: Value = GRAPH_LIMITS.decode(bytes, "package transaction")?;
        let transaction: TransactionDocument = serde_json::from_value(document.clone())?;
        ensure!(
            transaction.schema == "aos.package.transaction",
            "unsupported package transaction"
        );
        ensure!(
            !transaction.scope.is_empty() && transaction.scope.iter().all(|part| !part.is_empty()),
            "deployment scope must be explicit"
        );
        let index = |records: &[PackageModule]| -> Result<BTreeMap<String, PackageModule>> {
            let mut indexed = BTreeMap::new();
            for record in records {
                record.artifacts.package.check()?;
                aos_registry_surface::native_dependencies::check_version_requirement(
                    &record.version,
                    record.version_requirement.as_deref(),
                )?;
                store_root(&record.config_root)?;
                ensure!(
                    record.module == format!("{}/module.nix", record.config_root),
                    "module entrypoint differs from its source"
                );
                ensure!(
                    record.name == record.artifacts.package.name
                        && record.version == record.artifacts.package.version,
                    "package module coordinate mismatch"
                );
                for (name, artifact) in &record.artifacts.dependencies {
                    artifact.check()?;
                    ensure!(!name.is_empty(), "runtime dependency binding is empty");
                }
                aos_registry_surface::native_dependencies::check_resolution_metadata(
                    record.os_version.as_deref(),
                    &[],
                )?;
                let mut required_packages = BTreeSet::new();
                for requirement in &record.module_requirements {
                    requirement.check()?;
                    ensure!(
                        required_packages.insert(&requirement.package),
                        "duplicate module requirement"
                    );
                }
                ensure!(
                    indexed
                        .insert(record.name.clone(), record.clone())
                        .is_none(),
                    "duplicate package module"
                );
            }
            Ok(indexed)
        };
        for input in &transaction.inputs {
            store_root(input)?;
        }
        ensure!(
            transaction.system == expected.system && !transaction.system.is_empty(),
            "evaluation changed the target platform"
        );
        let artifact_index = |artifacts: &[Artifact]| -> Result<BTreeMap<String, Artifact>> {
            let mut result = BTreeMap::new();
            for artifact in artifacts {
                artifact.check()?;
                ensure!(
                    result
                        .insert(artifact.path.clone(), artifact.clone())
                        .is_none(),
                    "duplicate payload package"
                );
            }
            Ok(result)
        };
        let payloads = artifact_index(&expected.artifacts)?;
        ensure!(
            artifact_index(&transaction.artifacts)? == payloads,
            "evaluation changed the payload set"
        );
        let expected = index(&expected.modules)?;
        ensure!(
            index(&transaction.packages)? == expected,
            "evaluation changed the resolved package set"
        );
        let graph = CheckedModuleGraph::decode(&serde_json::to_vec(&transaction.graph)?)?;
        let retire = aos_ability_plan::module_graph::check_retirement(&graph, &transaction.retire)?;
        let roots: BTreeSet<_> = transaction
            .packages
            .iter()
            .flat_map(|record| {
                std::iter::once(&record.artifacts.package)
                    .chain(record.artifacts.dependencies.values())
            })
            .chain(transaction.artifacts.iter())
            .flat_map(|artifact| artifact.outputs.values())
            .collect();
        for effect in graph.graph().nodes.values() {
            ensure!(
                effect.identity.starts_with(&transaction.scope),
                "effect escaped its deployment scope"
            );
            ensure!(
                effect.owner == "@environment" || expected.contains_key(&effect.owner),
                "effect owner is not a resolved package"
            );
            if let Handler::Process { artifact, .. } = &effect.handler {
                ensure!(
                    roots.contains(artifact),
                    "handler is outside the resolved package artifacts"
                );
                ensure!(
                    transaction.inputs.contains(artifact)
                        || transaction
                            .artifacts
                            .iter()
                            .any(|selected| &selected.path == artifact),
                    "handler is available but not retained by the transaction"
                );
            }
        }
        Ok(Self {
            document,
            scope: transaction.scope,
            system: transaction.system,
            artifacts: transaction.artifacts,
            inputs: transaction.inputs,
            packages: transaction.packages,
            graph,
            retire,
        })
    }

    /// Returns the immutable execution graph.
    pub fn graph(&self) -> &CheckedModuleGraph {
        &self.graph
    }

    /// Returns the explicit retained-effect retirement decision.
    pub fn retire(&self) -> &BTreeSet<String> {
        &self.retire
    }

    /// Returns the explicit installation scope.
    pub fn scope(&self) -> &[String] {
        &self.scope
    }

    /// Returns immutable evaluation inputs retained alongside the package modules.
    pub fn inputs(&self) -> &[String] {
        &self.inputs
    }

    /// Returns all selected payloads, including packages without modules.
    pub fn artifacts(&self) -> &[Artifact] {
        &self.artifacts
    }

    /// Returns the resolved inputs bound to this generation.
    pub fn resolved(&self) -> ResolvedPackages {
        ResolvedPackages {
            system: self.system.clone(),
            artifacts: self.artifacts.clone(),
            modules: self.packages.clone(),
        }
    }

    /// Returns the module records retained for replay and documentation.
    pub fn packages(&self) -> &[PackageModule] {
        &self.packages
    }

    /// Serializes the exact retained transaction document.
    ///
    /// # Errors
    /// Returns an error if canonical JSON encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical::to_vec(&self.document)
    }

    /// Computes the generation's content identity.
    ///
    /// # Errors
    /// Returns an error if canonical JSON encoding fails.
    pub fn id(&self) -> Result<String> {
        Ok(Sha256Digest::of_bytes(self.canonical_bytes()?).hex())
    }
}

fn store_root(path: &str) -> Result<()> {
    let (_, suffix) = super::nix::store_root_and_suffix(std::path::Path::new(path))?;
    ensure!(
        suffix.as_os_str().is_empty(),
        "artifact must identify a store root"
    );
    Ok(())
}

#[cfg(test)]
mod resolution_tests {
    use super::*;
    use serde_json::json;

    fn document() -> Value {
        let payload = "/nix/store/00000000000000000000000000000000-example";
        json!({"schema":"aos.package.deployment","system":"x86_64-linux",
            "package":{"name":"example","version":"7","path":payload,
                "outputs":{"out":payload},"mainProgram":null},
            "module":{"name":"example","version":"7",
                "source":"/nix/store/11111111111111111111111111111111-example-source","entrypoint":"module.nix"},
            "osVersion":"^1.0",
            "runtimeDependencies":{},"moduleDependencies":[]})
    }

    #[test]
    fn os_constraint_matches_signed_discovery_metadata() {
        let mut value = document();
        let envelope = Envelope::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        envelope
            .verify_catalog_resolution(
                envelope.version_requirement.as_deref(),
                envelope.os_version.as_deref(),
                &[],
            )
            .unwrap();
        assert!(envelope.verify_catalog_resolution(None, None, &[]).is_err());
        assert_eq!(
            envelope.module_record().unwrap().os_version,
            envelope.os_version
        );

        value["module"] = Value::Null;
        assert!(Envelope::decode(&serde_json::to_vec(&value).unwrap()).is_ok());
    }

    #[test]
    fn generated_package_requirement_is_bound_to_catalog_and_module_identity() {
        let mut value = document();
        value["package"]["version"] = json!("7.2.3");
        value["module"]["version"] = json!("7.2.3");
        value["versionRequirement"] = json!("~7.2.3");
        let envelope = Envelope::decode(&serde_json::to_vec(&value).unwrap()).unwrap();

        assert_eq!(
            envelope
                .module_record()
                .unwrap()
                .version_requirement
                .as_deref(),
            Some("~7.2.3")
        );
        envelope
            .verify_catalog_resolution(Some("~7.2.3"), Some("^1.0"), &[])
            .unwrap();
        assert!(
            envelope
                .verify_catalog_resolution(Some("^7.2.3"), Some("^1.0"), &[])
                .is_err()
        );
        value["versionRequirement"] = json!("~7.2.4");
        assert!(Envelope::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn ranged_requests_survive_exact_runtime_record_projection() {
        let mut value = document();
        value["moduleDependencies"] = json!([{"package":{"name":"interfaces","version":"2",
            "source":"/nix/store/22222222222222222222222222222222-interfaces","entrypoint":"module.nix"},
            "packageVersion":"^2.0"}]);
        let envelope = Envelope::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        let module = envelope.module_record().unwrap();

        assert_eq!(module.module_requirements[0].package, "interfaces");
        assert_eq!(module.module_requirements[0].package_version, "^2.0");
        assert!(
            envelope
                .verify_catalog_resolution(
                    envelope.version_requirement.as_deref(),
                    envelope.os_version.as_deref(),
                    &[]
                )
                .is_err()
        );
    }
}
