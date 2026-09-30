//! Native package envelopes and module-generated transaction documents.
//!
//! Envelopes bind artifacts to a package coordinate. Transaction documents carry
//! one resolved package module set and its generated effect graph:
//!
//! ```json
//! {"schema":"aos.package.transaction","scope":["profile","main"],"system":"x86_64-linux","artifacts":[],"inputs":[],"packages":[],"graph":{"schema":"aos.activation.graph","nodes":{},"order":[]}}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use aos_ability_plan::module_graph::{CheckedModuleGraph, GRAPH_LIMITS, Handler};
use aos_contract::{Sha256Digest, canonical};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Identifies realized package outputs without reconstructing a derivation.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Artifact {
    /// Names the package in the resolved catalog.
    pub name: String,
    /// Names its selected package version.
    pub version: String,
    /// Identifies the default runtime output.
    pub path: String,
    /// Names the exact available output roots.
    pub outputs: BTreeMap<String, String>,
    /// Selects the main binary when this artifact supplies a terminal handler.
    pub main_program: Option<String>,
}

/// Identifies a package's retained module source independently of its payload.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSource {
    /// Names the declaring package.
    pub name: String,
    /// Identifies the selected source version.
    pub version: String,
    /// Identifies the immutable source directory.
    pub source: String,
    /// Names its relative module entry point.
    pub entrypoint: String,
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
    /// Exposes exact runtime dependencies to that module.
    pub runtime_dependencies: BTreeMap<String, Artifact>,
    /// Names the module dependency closure's direct edges.
    pub module_dependencies: Vec<ModuleSource>,
}

impl Envelope {
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
        if let Some(module) = &envelope.module {
            module.check()?;
            ensure!(
                module.name == envelope.package.name && module.version == envelope.package.version,
                "module differs from its package identity"
            );
        }
        for (name, artifact) in &envelope.runtime_dependencies {
            artifact.check()?;
            ensure!(
                name == &artifact.name,
                "runtime dependency key differs from its package"
            );
        }
        let mut names = BTreeSet::new();
        for module in &envelope.module_dependencies {
            module.check()?;
            ensure!(names.insert(&module.name), "duplicate module dependency");
        }
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
            artifacts: ArtifactContext {
                package: self.package.clone(),
                dependencies: self.runtime_dependencies.clone(),
            },
        })
    }
}

impl Artifact {
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

impl ModuleSource {
    fn check(&self) -> Result<()> {
        store_root(&self.source)?;
        ensure!(
            !self.name.is_empty() && !self.version.is_empty() && self.entrypoint == "module.nix",
            "invalid package module locator"
        );
        Ok(())
    }
}

/// Supplies only the artifact values visible to one package module.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactContext {
    /// Supplies this package's payload outputs.
    pub package: Artifact,
    /// Supplies the package's explicit runtime dependency artifacts.
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
    /// Supplies realized artifact references to module arguments.
    pub artifacts: ArtifactContext,
}

/// Carries both payloads and modules selected before entering a fixed point.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedPackages {
    /// Selects one explicit target platform for the entire scope.
    pub system: String,
    /// Includes selected payloads and their explicit runtime dependency artifacts.
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
                    ensure!(name == &artifact.name, "dependency coordinate mismatch");
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
        for record in &expected.modules {
            ensure!(
                payloads.get(&record.artifacts.package.path) == Some(&record.artifacts.package),
                "module payload is not selected"
            );
        }
        let expected = index(&expected.modules)?;
        ensure!(
            index(&transaction.packages)? == expected,
            "evaluation changed the resolved package set"
        );
        let graph = CheckedModuleGraph::decode(&serde_json::to_vec(&transaction.graph)?)?;
        let roots: BTreeSet<_> = transaction
            .packages
            .iter()
            .flat_map(|record| {
                std::iter::once(&record.artifacts.package)
                    .chain(record.artifacts.dependencies.values())
            })
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
        })
    }

    /// Returns the immutable execution graph.
    pub fn graph(&self) -> &CheckedModuleGraph {
        &self.graph
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
