//! Pure package-module evaluation over a resolved dependency closure.
//!
//! Evaluation imports the generic module library, explicit package modules, and
//! operator definitions. The caller supplies the resolved artifacts and fixed
//! host release; evaluation checks their declared compatibility requirements.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_ability_plan::module_graph::GRAPH_LIMITS;
use aos_ability_runtime::adapter::CancellationToken;
use serde_json::Value;

use super::model::{Deployment, Envelope, ModuleDependency, ResolvedPackages};
use super::nix::{nix_string, pure_eval_command_in, store_root_and_suffix};
use super::process::{FixedBudgetControl, run_bounded_with_input_limit};

/// Resolves authenticated native envelopes for one pinned package release set.
pub trait PackageResolver {
    /// Loads the exact source and payload selected for a module dependency.
    ///
    /// # Errors
    /// Returns an error for unavailable artifacts, identity mismatch, or failed
    /// registry authentication. Implementations must not silently select another version.
    fn resolve(&mut self, module: &ModuleDependency) -> Result<Envelope>;
}

/// Closes explicit module dependencies before entering the Nix fixed point.
///
/// # Errors
/// Returns an error for conflicting package identities, unresolved dependencies,
/// or a dependency whose source differs from its pinned module locator.
pub fn resolve_packages(
    system: &str,
    roots: Vec<Envelope>,
    resolver: &mut impl PackageResolver,
) -> Result<ResolvedPackages> {
    ensure!(!system.is_empty(), "target platform must be explicit");
    let mut artifacts = BTreeMap::new();
    for root in &roots {
        if let Some(previous) = artifacts.insert(root.package.path.clone(), root.package.clone()) {
            ensure!(
                previous == root.package,
                "one selected output has conflicting artifact identities"
            );
        }
    }
    let mut pending = roots;
    let mut selected: BTreeMap<String, Envelope> = BTreeMap::new();
    while let Some(mut package) = pending.pop() {
        package.package = package.package.canonical_catalog();
        ensure!(
            package.system == system,
            "package closure contains another target platform"
        );
        if let Some(previous) = selected.get(&package.package.name) {
            ensure!(
                previous == &package,
                "module closure contains conflicting package identities"
            );
            continue;
        }
        ensure!(
            selected.len() < 16_384,
            "module closure exceeds its package bound"
        );
        for dependency in &package.module_dependencies {
            let resolved = resolver.resolve(dependency)?;
            let source = resolved
                .module
                .as_ref()
                .context("resolved dependency has no module")?;
            ensure!(
                dependency.accepts(source, &resolved.package.version)?,
                "resolved module does not satisfy its original dependency"
            );
            pending.push(resolved);
        }
        selected.insert(package.package.name.clone(), package);
    }
    Ok(ResolvedPackages {
        system: system.to_owned(),
        modules: selected
            .values()
            .filter_map(Envelope::module_record)
            .collect(),
        artifacts: artifacts.into_values().collect(),
    })
}

/// Supplies the immutable inputs for one target-independent evaluation.
pub struct Evaluation {
    /// Projects original selected releases and their recipe compatibility policy.
    pub package_releases: Vec<aos_doc_model::runtime::PackageIdentity>,
    /// Supplies the fixed host release for runtime compatibility checks.
    pub os_release: Option<aos_doc_model::runtime::OsRelease>,
    /// Projects authenticated requirements from moduleless payload envelopes.
    pub os_requirements: Vec<aos_doc_model::runtime::OsRequirement>,
    /// Selects the immutable Nix tool suite used for source access and evaluation.
    pub nix_store: PathBuf,
    /// Identifies the generic AOS module library, rather than an image base library.
    pub library: PathBuf,
    /// Separates this profile or deployment from other installations.
    pub scope: Vec<String>,
    /// Contains the already-resolved package module dependency closure.
    pub packages: ResolvedPackages,
    /// Projects ranged dependencies from admitted locks, including moduleless requesters.
    /// Package module records supply their own declarations during evaluation.
    pub module_requirements: Vec<aos_doc_model::runtime::ModuleRequirement>,
    /// Lists immutable operator module files in their intended merge order.
    pub configuration: Vec<PathBuf>,
    /// Retains immutable envelope, documentation, and other caller-admitted artifacts.
    /// These inputs are rooted with the generation but are not imported as modules.
    pub retained_inputs: Vec<PathBuf>,
    /// Supplies an admitted immutable descriptor of the pre-evaluation inputs.
    pub evaluation_input: Option<PathBuf>,
}

impl Evaluation {
    fn expression_for(
        &self,
        output: &str,
        views: &super::source_views::SourceViews,
        check_definitions: bool,
    ) -> Result<String> {
        let lock = |path: &Path| views.expression(path);
        let library = lock(&self.library)?;
        let roots: BTreeSet<_> = self
            .packages
            .modules
            .iter()
            .map(|package| &package.config_root)
            .collect();
        let sources = roots
            .into_iter()
            .map(|source| {
                Ok(format!(
                    "{} = {};",
                    nix_string(source),
                    lock(Path::new(source))?
                ))
            })
            .collect::<Result<Vec<_>>>()?
            .join("\n");
        let configuration = self
            .configuration
            .iter()
            .map(|path| lock(path))
            .collect::<Result<Vec<_>>>()?
            .join("\n");
        let scope = nix_string(&serde_json::to_string(&self.scope)?);
        let packages = nix_string(&serde_json::to_string(&self.packages.modules)?);
        let artifacts = nix_string(&serde_json::to_string(&self.packages.artifacts)?);
        let requirements = nix_string(&serde_json::to_string(&self.module_requirements)?);
        let package_releases = nix_string(&serde_json::to_string(&self.package_releases)?);
        let os_release = nix_string(&serde_json::to_string(&self.os_release)?);
        let os_requirements = nix_string(&serde_json::to_string(&self.os_requirements)?);
        let system = nix_string(&self.packages.system);
        let inputs = nix_string(&serde_json::to_string(&self.inputs()?)?);
        let evaluation_input = self
            .evaluation_input
            .as_ref()
            .map(|path| {
                path.to_str()
                    .map(nix_string)
                    .context("evaluation descriptor is not UTF-8")
            })
            .transpose()?
            .unwrap_or_else(|| "null".into());
        Ok(format!(
            "let lib = import {library} {{ system = {system}; }};\n\
             evaluated = lib.evalPackageModules {{\n\
               checkDefinitions = {check_definitions};\n\
               scope = builtins.fromJSON {scope};\n\
               evaluationInputs = builtins.fromJSON {inputs};\n\
               evaluationInput = {evaluation_input};\n\
               packageModules = builtins.fromJSON {packages};\n\
               packageArtifacts = builtins.fromJSON {artifacts};\n\
               moduleRequirements = builtins.fromJSON {requirements};\n\
               packageReleases = builtins.fromJSON {package_releases};\n\
               osRelease = builtins.fromJSON {os_release};\n\
               osRequirements = builtins.fromJSON {os_requirements};\n\
               enforceOsRequirements = true;\n\
               packageImportRoots = {{ {sources} }};\n\
               operatorModules = [ {configuration} ];\n\
             }}; in {output}\n"
        ))
    }

    /// Evaluates the closed module set without building any package or executing effects.
    ///
    /// # Errors
    /// Returns an error for evaluation failure, timeout, cancellation, malformed
    /// output, or a plan that differs from the resolved package context.
    pub fn evaluate(
        &self,
        staging: &Path,
        timeout_ms: u64,
        cancellation: &CancellationToken,
    ) -> Result<Deployment> {
        let value = self.run(staging, timeout_ms, cancellation, false)?;
        let deployment = Deployment::decode(&serde_json::to_vec(&value)?, &self.packages)?;
        ensure!(
            self.inputs()?
                .iter()
                .all(|root| deployment.inputs().contains(root)),
            "evaluation removed a retained source input"
        );
        let available: BTreeSet<_> = self
            .packages
            .modules
            .iter()
            .flat_map(|package| {
                std::iter::once(&package.artifacts.package)
                    .chain(package.artifacts.dependencies.values())
            })
            .chain(self.packages.artifacts.iter())
            .flat_map(|artifact| artifact.outputs.values())
            .chain(
                self.packages
                    .modules
                    .iter()
                    .map(|package| &package.config_root),
            )
            .collect();
        let source_inputs = self.inputs()?;
        ensure!(
            deployment
                .inputs()
                .iter()
                .all(|root| source_inputs.contains(root) || available.contains(root)),
            "evaluation added a retained root outside its authenticated catalogs"
        );
        Ok(deployment)
    }

    /// Projects documentation without forcing configured effects or selected handlers.
    ///
    /// # Errors
    /// Returns an error for evaluation failure, timeout, cancellation, or malformed output.
    pub fn documentation(
        &self,
        staging: &Path,
        timeout_ms: u64,
        cancellation: &CancellationToken,
    ) -> Result<Value> {
        self.run(staging, timeout_ms, cancellation, true)
    }

    /// Projects one configuration path from the same immutable module fixed point.
    ///
    /// Path segments are serialized as data; callers cannot supply Nix expressions.
    /// The domain owning the selected value must validate its application contract.
    ///
    /// # Errors
    /// Returns an error for an empty path, evaluation failure, cancellation, timeout,
    /// a missing attribute, or a value that cannot cross the bounded JSON boundary.
    pub fn project(
        &self,
        path: &[String],
        staging: &Path,
        timeout_ms: u64,
        cancellation: &CancellationToken,
    ) -> Result<Value> {
        ensure!(
            !path.is_empty() && path.iter().all(|part| !part.is_empty()),
            "configuration projection requires nonempty path segments"
        );
        let path = nix_string(&serde_json::to_string(path)?);
        self.run_output(staging, timeout_ms, cancellation, &format!(
            "builtins.foldl' (value: key: builtins.getAttr key value) evaluated.config (builtins.fromJSON {path})"
        ))
    }

    /// Projects an optional configuration path from the immutable module fixed point.
    ///
    /// A missing attribute yields JSON null. Evaluation and type errors remain
    /// errors, so callers can distinguish an absent feature from a broken module.
    ///
    /// # Errors
    /// Returns an error for empty path segments, evaluation failure, cancellation,
    /// timeout, or a value that cannot cross the bounded JSON boundary.
    pub fn project_optional(
        &self,
        path: &[String],
        staging: &Path,
        timeout_ms: u64,
        cancellation: &CancellationToken,
    ) -> Result<Value> {
        ensure!(
            !path.is_empty() && path.iter().all(|part| !part.is_empty()),
            "configuration projection requires nonempty path segments"
        );
        let path = nix_string(&serde_json::to_string(path)?);
        self.run_output(staging, timeout_ms, cancellation, &format!(
            "builtins.foldl' (value: key: if builtins.isAttrs value && builtins.hasAttr key value then builtins.getAttr key value else null) evaluated.config (builtins.fromJSON {path})"
        ))
    }

    /// Projects package roots before their configuration modules are acquired.
    ///
    /// Only the declared selection option is demanded. Definitions belonging to
    /// unavailable packages remain unchecked until the complete, ordinary
    /// evaluation; this projection never produces an executable deployment.
    ///
    /// # Errors
    /// Returns an error for malformed package names, conflicting or mistyped
    /// selection definitions, source failure, cancellation, or timeout.
    pub(crate) fn selected_packages(
        &self,
        staging: &Path,
        cancellation: &CancellationToken,
    ) -> Result<Vec<String>> {
        let value = self.run_output_checked(
            staging,
            60_000,
            cancellation,
            "evaluated.config.aos.apm.desiredPackages or []",
            false,
        )?;
        let names: Vec<String> = serde_json::from_value(value)?;
        ensure!(names.len() <= 16_384, "package selection exceeds its bound");
        for name in &names {
            crate::types::validate_package_name(name)?;
        }
        Ok(names
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }

    /// Projects the closed provisioning namespace before host packages exist.
    ///
    /// The initrd checks every provisioning definition and its declared types.
    /// Unavailable host package options are checked during host admission; they
    /// cannot contribute executable effects through this data-only projection.
    ///
    /// # Errors
    /// Returns an error for undeclared or mistyped provisioning configuration,
    /// source failure, cancellation, timeout, or malformed projected output.
    pub(crate) fn provisioning_storage(
        &self,
        staging: &Path,
        timeout_ms: u64,
        cancellation: &CancellationToken,
    ) -> Result<Value> {
        self.run_output_checked(
            staging,
            timeout_ms,
            cancellation,
            "(evaluated.extendModules { checkDefinitionPaths = [[\"aos\" \"provisioning\"]]; }).config.aos.provisioning.storage",
            false,
        )
    }

    fn inputs(&self) -> Result<Vec<String>> {
        std::iter::once(&self.library)
            .chain(self.configuration.iter())
            .chain(self.retained_inputs.iter())
            .chain(self.evaluation_input.iter())
            .map(|path| {
                let (root, _) = store_root_and_suffix(path)?;
                Ok(root
                    .to_str()
                    .context("evaluation input is not UTF-8")?
                    .to_owned())
            })
            .collect::<Result<BTreeSet<_>>>()
            .map(|roots| roots.into_iter().collect())
    }

    fn run(
        &self,
        staging: &Path,
        timeout_ms: u64,
        cancellation: &CancellationToken,
        documentation: bool,
    ) -> Result<Value> {
        self.run_output(
            staging,
            timeout_ms,
            cancellation,
            if documentation {
                "evaluated.documentation"
            } else {
                "evaluated.deployment"
            },
        )
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "evaluation uses one monotonic subprocess deadline"
    )]
    fn run_output(
        &self,
        staging: &Path,
        timeout_ms: u64,
        cancellation: &CancellationToken,
        output: &str,
    ) -> Result<Value> {
        self.run_output_checked(staging, timeout_ms, cancellation, output, true)
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "evaluation uses one monotonic subprocess deadline"
    )]
    fn run_output_checked(
        &self,
        staging: &Path,
        timeout_ms: u64,
        cancellation: &CancellationToken,
        output: &str,
        check_definitions: bool,
    ) -> Result<Value> {
        ensure!(!cancellation.is_cancelled(), "package evaluation cancelled");
        let control = EvaluationBudget {
            cancellation,
            budget: FixedBudgetControl::new(timeout_ms),
            started: std::time::Instant::now(),
        };
        let paths = std::iter::once(self.library.as_path())
            .chain(self.configuration.iter().map(PathBuf::as_path))
            .chain(
                self.packages
                    .modules
                    .iter()
                    .map(|module| Path::new(&module.config_root)),
            );
        let views =
            super::source_views::SourceViews::prepare(&self.nix_store, paths, staging, &control)?;
        let expression = self.expression_for(output, &views, check_definitions)?;
        let store = evaluator_store()?;
        let mut command = pure_eval_command_in(
            &self.nix_store,
            store.as_deref(),
            Some(views.directory()),
            staging,
        )?;
        command.arg("-");
        let environment: Vec<_> = command
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
            .collect();
        let output = run_bounded_with_input_limit(
            &mut command,
            Some(expression.as_bytes()),
            GRAPH_LIMITS.max_bytes,
            GRAPH_LIMITS.max_bytes,
            &control,
            &environment,
        )
        .context("running package module evaluator")?;
        ensure!(
            output.status.success(),
            "package module evaluation exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        GRAPH_LIMITS.decode(&output.stdout, "evaluated package document")
    }
}

struct EvaluationBudget<'a> {
    cancellation: &'a CancellationToken,
    budget: FixedBudgetControl,
    started: std::time::Instant,
}

impl aos_ability_runtime::adapter::RuntimeControl for EvaluationBudget<'_> {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn elapsed_millis(&self) -> u64 {
        0
    }

    fn attempt_remaining_millis(&self) -> u64 {
        self.budget
            .attempt_remaining_millis()
            .saturating_sub(self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64)
    }

    fn recovery_remaining_millis(&self) -> u64 {
        self.attempt_remaining_millis()
    }
}

/// Selects the same explicit store for source hashing and pure evaluation.
/// Ambient Nix store variables remain scrubbed by the subprocess boundary.
fn evaluator_store() -> Result<Option<std::ffi::OsString>> {
    let store = std::env::var_os("AOS_NIX_EVAL_STORE");
    ensure!(
        store.as_ref().is_none_or(|value| !value.is_empty()),
        "AOS_NIX_EVAL_STORE must not be empty"
    );
    Ok(store)
}
