//! The P1 stock-Nix evaluator and registry fetcher (build-spec §3, §4).
//!
//! [`StockNixEvaluator`] renders the working set into `entry.nix`, runs a cold
//! stock-Nix subprocess under the determinism flags, and classifies its result
//! via [`super::classify`]. It is **builder-gated** because it requires a real
//! stock-nix, so it cannot run on a developer's macOS host and is unit-tested
//! here only for `entry.nix` rendering.
//!
//! # The eval invocation
//!
//! ```text
//! nix-instantiate --eval --strict --json --pure-eval \
//!   --extra-experimental-features 'nix-command flakes' \
//!   --option restrict-eval true \                  # read only explicit store roots
//!   --option allow-import-from-derivation false \  # no IFD ⇒ no build sneaks in
//!   --option allowed-uris path:/nix/store/ \
//!   -A manifest -
//! ```
//!
//! `--pure-eval` removes ambient evaluator inputs such as `currentTime`,
//! `currentSystem`, and environment variables. `restrict-eval` independently
//! confines filesystem reads to explicit store roots, while
//! `allow-import-from-derivation = false` prevents evaluation from triggering a
//! build. The generated expression arrives on standard input, so it has no
//! mutable filesystem identity; facts are rendered inline. Every store input
//! is admitted through a fixed-NAR-hash `fetchTree` expression.
//!
//! `entry.nix` is regenerated each iteration from the current working set, with
//! the verified `host.nix` injected as an operator-provenance module (the
//! operator module seam) and each provider's config-only module
//! imported by store path.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::{Context, Result, bail, ensure};
use aos_ability_model::{
    ArtifactReference, Binding, ProviderImplementation, ProviderImplementationReference,
    VersionedDocument,
};
use aos_ability_plan::VerifiedPlanningSnapshot;
use base64::Engine as _;
use serde::Deserialize;

use super::ability_rounds::{
    AbilityFixedPointProjection, AbilityRoundEvaluation, AbilityRoundEvaluator,
    AbilityRoundResolver, AbilityRoundSelections, CompleteAbilityRound, PendingAbilityProjection,
    SelectedAbilityBinding, SelectedProviderModule,
};
use super::classify::{EvalClass, KillReason, classify};
use super::system_roots::{PackageModuleResolver, ResolvedPackageModule};
use super::{EvalAttempt, NixEvaluator, WorkingSetMember};
use crate::platform::native_platform;
use crate::registry::RegistrySet;

/// The default on-host eval root that `aos-eval.service` prepares.
pub const DEFAULT_EVAL_ROOT: &str = "/run/aos-eval";

/// The default manifest path the converged eval emits.
pub const DEFAULT_MANIFEST_PATH: &str = "/run/aos/manifest.json";

/// The normalized metadata facts consumed by the production evaluator.
pub const DEFAULT_FACTS_PATH: &str = "/run/aos-metadata/facts.json";

/// A cold stock-Nix evaluator over a prepared eval root.
///
/// Each [`NixEvaluator::evaluate`] call writes `entry.nix` into the root and
/// runs `nix-instantiate --eval` under the determinism flags. The subprocess is
/// expected to run inside the hardened transient scope authored by
/// `aos-eval.service`; this type does not create the scope, it only invokes the
/// evaluator and classifies.
pub struct StockNixEvaluator {
    /// The mutable staging root for generated evaluator source.
    root: PathBuf,
    /// `verbose > 0` adds `--show-trace`.
    verbose: u8,
}

/// Binds one stock-Nix evaluator to the unchanged inputs of a complete module graph.
pub struct StockAbilityRoundEvaluator<'a> {
    evaluator: &'a StockNixEvaluator,
    attempt: EvalAttempt<'a>,
    stage: Option<BuildAbilityStage<'a>>,
}

#[derive(Clone, Copy)]
struct BuildAbilityStage<'a> {
    stage: &'a str,
    authority: &'a str,
    key: &'a str,
}

/// Selects child providers only from authenticated packages in one working set.
pub(super) struct StockAbilityRoundResolver<'a> {
    working_set: &'a [WorkingSetMember],
    planning: &'a VerifiedPlanningSnapshot,
    artifact_locators: Option<
        &'a BTreeMap<
            String,
            BTreeMap<aos_ability_validate::PackageOutputSelector, ArtifactReference>,
        >,
    >,
}

impl<'a> StockAbilityRoundResolver<'a> {
    /// Creates a resolver over one replayed checked plan and its exact package set.
    pub(super) const fn new(
        working_set: &'a [WorkingSetMember],
        planning: &'a VerifiedPlanningSnapshot,
    ) -> Self {
        Self {
            working_set,
            planning,
            artifact_locators: None,
        }
    }

    /// Creates the build-stage resolver over exact checked output locators.
    pub(super) const fn for_build_stage(
        working_set: &'a [WorkingSetMember],
        planning: &'a VerifiedPlanningSnapshot,
        artifact_locators: &'a BTreeMap<
            String,
            BTreeMap<aos_ability_validate::PackageOutputSelector, ArtifactReference>,
        >,
    ) -> Self {
        Self {
            working_set,
            planning,
            artifact_locators: Some(artifact_locators),
        }
    }

    fn checked_binding(
        &self,
        request: &super::ability_rounds::PendingAbilityRequest,
    ) -> Result<&Binding> {
        let matches = self
            .planning
            .checked_binding()
            .bindings()
            .iter()
            .filter(|binding| binding.request == *request.identity())
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [selected] => Ok(selected),
            [] => bail!(
                "pending ability request {:?} has no binding in the replayed checked plan",
                request.request()
            ),
            _ => bail!(
                "pending ability request {:?} has several bindings in the replayed checked plan",
                request.request()
            ),
        }
    }

    fn implementation(
        &self,
        binding: &Binding,
    ) -> Result<(&'a WorkingSetMember, &'a ProviderImplementation, String)> {
        let package_digest = binding
            .provider_package
            .context("checked package-backed binding has no provider package digest")?;
        let mut matches = Vec::new();
        for member in self.working_set {
            let Some(package) = &member.ability else {
                continue;
            };
            if package.content_digest()? != package_digest {
                continue;
            }
            for provider in &package.implementation.providers {
                let reference = ProviderImplementationReference {
                    descriptor: provider.descriptor_digest()?,
                    artifact: provider.artifact.clone(),
                    handler: provider.handler.clone(),
                };
                if reference == binding.implementation && provider.interface == binding.interface {
                    matches.push((
                        member,
                        provider,
                        format!("{}:{}", member.package, provider.name.as_str()),
                    ));
                }
            }
        }
        let [(member, provider, implementation)] = matches.as_slice() else {
            bail!(
                "checked binding {:?} resolves to {} exact authenticated implementations",
                binding.id.0.as_str(),
                matches.len()
            );
        };

        ensure!(
            member.package
                == member
                    .ability
                    .as_ref()
                    .map_or("", |package| package.package.name.as_str()),
            "checked implementation package identity differs from its working-set declaration"
        );
        Ok((*member, *provider, implementation.clone()))
    }

    fn provider_instance(
        pending: &PendingAbilityProjection,
        binding: &Binding,
        implementation: &str,
    ) -> Result<String> {
        let matches = pending
            .provider_instances
            .iter()
            .filter(|(_, instance)| {
                instance.identity == binding.provider
                    && instance.implementation.as_deref() == Some(implementation)
            })
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        let [name] = matches.as_slice() else {
            bail!(
                "checked binding {:?} resolves to {} exact provider instances in the module fixed point",
                binding.id.0.as_str(),
                matches.len()
            );
        };
        Ok(name.clone())
    }

    fn contribution_slot(
        binding: &Binding,
        request: &super::ability_rounds::PendingAbilityRequest,
    ) -> Result<String> {
        let contributions = binding
            .caller_grant
            .contributions
            .iter()
            .filter(|permission| permission.aggregate.provider == binding.provider)
            .collect::<Vec<_>>();
        match contributions.as_slice() {
            [permission] => Ok(permission.slot.as_str().to_string()),
            [] => request
                .expected_slot()
                .map(str::to_string)
                .with_context(|| {
                    format!(
                        "checked root binding {:?} has no exact contribution slot",
                        binding.id.0.as_str()
                    )
                }),
            _ => bail!(
                "checked binding {:?} grants {} exact contribution slots",
                binding.id.0.as_str(),
                contributions.len()
            ),
        }
    }

    fn selected_module(
        &self,
        member: &WorkingSetMember,
        provider: &ProviderImplementation,
    ) -> Result<Option<SelectedProviderModule>> {
        let Some(locator) = provider.provider_module.clone() else {
            return Ok(None);
        };
        let version = member.version.clone().with_context(|| {
            format!(
                "selected provider package {} has no authenticated version",
                member.package
            )
        })?;
        ensure!(
            member.outputs.self_output.is_some(),
            "selected provider package {} has no authenticated runtime output",
            member.package
        );

        Ok(Some(SelectedProviderModule {
            package: member.package.clone(),
            version,
            locator,
            outputs: member.outputs.clone(),
            // Current provider modules consume exact values and resource
            // references from the fixed point. They do not resolve additional
            // package-output selectors during an outer round.
            artifact_locators: self
                .artifact_locators
                .and_then(|catalog| catalog.get(&member.package))
                .cloned()
                .unwrap_or_default(),
        }))
    }
}

impl AbilityRoundResolver for StockAbilityRoundResolver<'_> {
    fn select(&self, pending: &PendingAbilityProjection) -> Result<Vec<SelectedAbilityBinding>> {
        let mut selections = Vec::with_capacity(pending.requests.len());
        for request in pending.requests.values() {
            let binding = self.checked_binding(request)?;
            let checked_request = self
                .planning
                .checked_binding()
                .document()
                .requests
                .iter()
                .find(|candidate| candidate.id == binding.request)
                .context("checked binding names an absent request")?;
            let parameters = request
                .declaration()
                .as_json()
                .get("parameters")
                .context("module request has no typed parameters")?;
            ensure!(
                checked_request.parameters.as_json() == parameters,
                "module request differs from the replayed checked request value"
            );
            let (member, provider, implementation) = self.implementation(binding)?;
            let provider_instance = Self::provider_instance(pending, binding, &implementation)?;
            let slot = Self::contribution_slot(binding, request)?;
            if let Some(expected) = request.expected_slot() {
                ensure!(
                    slot == expected,
                    "checked binding changes the provider-authored child contribution slot"
                );
            }

            selections.push(SelectedAbilityBinding {
                key: binding.id.0.as_str().to_string(),
                request: request.request().to_string(),
                implementation,
                provider_instance,
                slot,
                provider_module: self.selected_module(member, provider)?,
            });
        }
        Ok(selections)
    }
}

impl<'a> StockAbilityRoundEvaluator<'a> {
    /// Creates a complete-fixed-point adapter around one immutable eval attempt.
    #[must_use]
    pub const fn new(evaluator: &'a StockNixEvaluator, attempt: EvalAttempt<'a>) -> Self {
        Self {
            evaluator,
            attempt,
            stage: None,
        }
    }

    /// Creates a build-stage evaluator over one normalized intent module.
    pub(super) const fn for_build_stage(
        evaluator: &'a StockNixEvaluator,
        attempt: EvalAttempt<'a>,
        stage: &'a str,
        authority: &'a str,
        key: &'a str,
    ) -> Self {
        Self {
            evaluator,
            attempt,
            stage: Some(BuildAbilityStage {
                stage,
                authority,
                key,
            }),
        }
    }
}

impl StockNixEvaluator {
    /// Creates an evaluator over `root` (typically [`DEFAULT_EVAL_ROOT`]).
    pub fn new(root: impl Into<PathBuf>, verbose: u8) -> Self {
        Self {
            root: root.into(),
            verbose,
        }
    }

    /// Renders the `entry.nix` for one attempt.
    ///
    /// The verified `host.nix` is passed as `operatorModules` (the CS4
    /// operator-provenance seam in `lib/modules.nix` / `default.nix` `mkSystem`)
    /// and each provider's config-only module is imported by store path. The
    /// expression evaluates to an attrset whose `manifest` attribute is the
    /// rendered data contract forced by `nix-instantiate ... -A manifest`.
    ///
    /// The exact base-lib entrypoint (`evalHostConfig`) is provided by the
    /// in-image module library and is therefore builder-gated; this renderer
    /// only guarantees a syntactically valid, deterministic expression.
    ///
    /// # Errors
    ///
    /// Returns an error when a supplied facts document cannot be read, parsed,
    /// or normalized into its typed Nix module.
    #[cfg(test)]
    pub fn render_entry_nix(&self, attempt: &EvalAttempt<'_>) -> Result<String> {
        let package_modules = render_package_module_list(attempt.working_set, false)?;
        self.render_entry_nix_with_inputs(
            attempt,
            &package_modules,
            "[ ]",
            "{}",
            &nix_path(attempt.base_lib),
            &nix_path(attempt.host_nix),
        )
    }

    fn render_locked_entry_nix(&self, attempt: &EvalAttempt<'_>) -> Result<String> {
        let package_modules = render_package_module_list(attempt.working_set, true)?;
        let base = locked_store_input(attempt.base_lib, None)?;
        let host = locked_store_input(attempt.host_nix, None)?;
        self.render_entry_nix_with_inputs(attempt, &package_modules, "[ ]", "{}", &base, &host)
    }

    fn render_locked_ability_round_entry_nix(
        &self,
        attempt: &EvalAttempt<'_>,
        selections: &AbilityRoundSelections,
        stage: Option<BuildAbilityStage<'_>>,
    ) -> Result<String> {
        let package_modules = render_package_module_list(attempt.working_set, true)?;
        let provider_modules = render_selected_provider_module_list(selections, true)?;
        let bindings = render_selected_ability_bindings(selections);
        let base = locked_store_input(attempt.base_lib, None)?;
        let host = locked_store_input(attempt.host_nix, None)?;
        if let Some(stage) = stage {
            return Ok(format!(
                "# Generated by the AOS build-stage ability resolver; do not edit.\n\
                 let\n\
                \x20 baseLib = import {base};\n\
                \x20 intentModule = import {host};\n\
                \x20 evaluated = baseLib.evalAbilityStage {{\n\
                \x20   stage = {stage_name};\n\
                \x20   authority = {authority};\n\
                \x20   key = {key};\n\
                \x20   intentModules = [ intentModule ];\n\
                \x20   packageModules = {package_modules};\n\
                \x20   selectedProviderModules = {provider_modules};\n\
                \x20   abilityBindings = {bindings};\n\
                \x20 }};\n\
                 in {{ abilityRound = baseLib.projectAbilityRound evaluated {{}}; }}\n",
                stage_name = nix_string(stage.stage),
                authority = nix_string(stage.authority),
                key = nix_string(stage.key),
            ));
        }
        self.render_entry_nix_with_inputs(
            attempt,
            &package_modules,
            &provider_modules,
            &bindings,
            &base,
            &host,
        )
    }

    fn render_entry_nix_with_inputs(
        &self,
        attempt: &EvalAttempt<'_>,
        package_modules: &str,
        selected_provider_modules: &str,
        ability_bindings: &str,
        base: &str,
        host: &str,
    ) -> Result<String> {
        let runtime_modules = attempt
            .runtime_modules
            .iter()
            .map(|path| locked_store_input(path, None).map(|input| format!("(import {input})")))
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        let facts_module = attempt
            .facts_json
            .map(|facts_json| -> Result<String> {
                let raw = std::fs::read(facts_json)
                    .with_context(|| format!("reading facts {}", facts_json.display()))?;
                let facts: crate::metadata::fetcher::Facts = serde_json::from_slice(&raw)
                    .with_context(|| format!("parsing facts {}", facts_json.display()))?;
                Ok(crate::metadata::facts_render::render_host_facts_nix(&facts))
            })
            .transpose()?;
        let facts_binding = facts_module.as_ref().map_or_else(String::new, |module| {
            format!("\x20 factsModule = (\n{module}\n\x20 );\n")
        });
        let facts_modules = facts_module.as_ref().map_or("[ ]", |_| "[ factsModule ]");
        Ok(format!(
            "# Generated by aos config eval; do not edit.\n\
             let\n\
            \x20 baseLib = import {base};\n\
            \x20 hostModule = import {host};\n\
             {facts_binding}\
            \x20 system = baseLib.evalHostConfig {{\n\
            \x20   operatorModules = [ hostModule ];\n\
            \x20   runtimeModules = [ {runtime_modules} ];\n\
            \x20   packageModules = {modules};\n\
            \x20   selectedProviderModules = {selected_provider_modules};\n\
            \x20   abilityBindings = {ability_bindings};\n\
            \x20   factsModules = {facts_modules};\n\
            \x20 }};\n\
            \x20 baselineSystem = baseLib.evalHostConfig {{\n\
            \x20   operatorModules = [ ];\n\
            \x20   packageModules = [ ];\n\
            \x20   factsModules = [ ];\n\
            \x20 }};\n\
            \x20 candidate = system.config.system.build.configManifest;\n\
            \x20 baseline = baselineSystem.config.system.build.configManifest;\n\
            \x20 mergedManifest = baseLib.mergeImageManifest {{ inherit baseline candidate; }};\n\
            \x20 finalManifest = mergedManifest // {{\n\
            \x20   config = baseLib.lib.recursiveUpdate\n\
            \x20     candidate.config\n\
            \x20     system.config.aos.apm.installAtBoot.config;\n\
            \x20   credentials = baseLib.lib.recursiveUpdate\n\
            \x20     candidate.credentials\n\
            \x20     (baseLib.lib.recursiveUpdate\n\
            \x20       system.config.aos.apm.installAtBoot.credentials\n\
            \x20       (builtins.mapAttrs\n\
            \x20         (_package: handles: builtins.mapAttrs\n\
            \x20           (name: systemCredential: {{\n\
            \x20             inherit name;\n\
            \x20             source = null;\n\
            \x20             encrypted = true;\n\
            \x20             units = [];\n\
            \x20             ref = \"system-credential:${{systemCredential}}\";\n\
            \x20           }})\n\
            \x20           handles)\n\
            \x20         system.config.aos.apm.installAtBoot.systemCredentials));\n\
            \x20 }};\n\
            \x20 pendingAbilityRequests = system.config.aos.abilities.compositionPendingRequests;\n\
             in {{\n\
            \x20 optionWrites = system._optionWrites;\n\
            \x20 manifest = finalManifest;\n\
            \x20 abilityRound =\n\
            \x20   if pendingAbilityRequests == {{}}\n\
            \x20   then {{\n\
            \x20     status = \"complete\";\n\
            \x20     manifest = finalManifest;\n\
            \x20     fixedPoint = {{\n\
            \x20       inherit (system.config.aos.abilities) bindings resolvedResources;\n\
            \x20     }};\n\
            \x20   }}\n\
            \x20   else {{\n\
            \x20     status = \"pending\";\n\
            \x20     pending = {{\n\
            \x20       requests = pendingAbilityRequests;\n\
            \x20       requirements = system.config.aos.abilities.compositionRequirements;\n\
            \x20       providerInstances = builtins.mapAttrs\n\
            \x20         (_: instance: {{ inherit (instance) implementation; }})\n\
            \x20         system.config.aos.abilities.instances;\n\
            \x20     }};\n\
            \x20   }};\n\
             }}\n",
            base = base,
            host = host,
            modules = package_modules,
            selected_provider_modules = selected_provider_modules,
            ability_bindings = ability_bindings,
            facts_binding = facts_binding,
            facts_modules = facts_modules,
            runtime_modules = runtime_modules,
        ))
    }

    /// Writes the generated Nix source into a dedicated staging directory.
    fn write_locked_entry(&self, attempt: &EvalAttempt<'_>) -> Result<PathBuf> {
        self.write_rendered_entry(self.render_locked_entry_nix(attempt)?)
    }

    #[cfg(test)]
    pub(super) fn write_entry(&self, attempt: &EvalAttempt<'_>) -> Result<PathBuf> {
        self.write_rendered_entry(self.render_entry_nix(attempt)?)
    }

    fn write_rendered_entry(&self, expression: String) -> Result<PathBuf> {
        let source_root = self.root.join("nix-source");
        let entry = source_root.join("entry.nix");
        std::fs::create_dir_all(&source_root)
            .with_context(|| format!("creating eval source root {}", source_root.display()))?;
        match std::fs::remove_file(source_root.join("host-facts.nix")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context("removing stale rendered host facts module");
            }
        }
        std::fs::write(&entry, expression)
            .with_context(|| format!("writing {}", entry.display()))?;
        Ok(entry)
    }
}

impl NixEvaluator for StockNixEvaluator {
    fn evaluate(&self, attempt: &EvalAttempt<'_>) -> Result<EvalClass> {
        let staged_entry = self.write_locked_entry(attempt)?;
        let expression = std::fs::read_to_string(&staged_entry)
            .with_context(|| format!("reading {}", staged_entry.display()))?;

        let mut cmd = pure_eval_command()?;

        // Standard input is not a mutable filesystem input. Every imported
        // path is independently admitted by its fixed NAR hash in the source.
        cmd.arg("-A").arg("manifest").arg("-");
        if self.verbose > 0 {
            cmd.arg("--show-trace");
        }

        let output = output_with_expression(&mut cmd, &expression)
            .context("running `nix-instantiate --eval`")?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let kill = kill_reason(&output.status, &stderr);

        classify(output.status.success(), &stdout, &stderr, kill)
    }
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum StockAbilityRoundResult {
    Complete {
        manifest: serde_json::Value,
        #[serde(rename = "fixedPoint")]
        fixed_point: AbilityFixedPointProjection,
    },
    Pending {
        pending: PendingAbilityProjection,
    },
}

impl AbilityRoundEvaluator for StockAbilityRoundEvaluator<'_> {
    fn evaluate(
        &self,
        _round: u32,
        selections: &AbilityRoundSelections,
    ) -> Result<AbilityRoundEvaluation> {
        let expression = self.evaluator.render_locked_ability_round_entry_nix(
            &self.attempt,
            selections,
            self.stage,
        )?;
        let mut command = pure_eval_command()?;
        command.arg("-A").arg("abilityRound").arg("-");
        if self.evaluator.verbose > 0 {
            command.arg("--show-trace");
        }

        let output = output_with_expression(&mut command, &expression)
            .context("running bounded ability-round module evaluation")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let kill = kill_reason(&output.status, &stderr);
            bail!(
                "complete ability module evaluation failed{}: {}",
                kill.map_or_else(String::new, |reason| format!(" ({reason:?})")),
                stderr.trim()
            );
        }

        let result: StockAbilityRoundResult = serde_json::from_slice(&output.stdout)
            .context("decoding complete ability-round module result")?;
        match result {
            StockAbilityRoundResult::Complete {
                manifest,
                fixed_point,
            } => Ok(AbilityRoundEvaluation::Complete(CompleteAbilityRound {
                manifest: serde_json::to_string(&manifest)?,
                fixed_point,
            })),
            StockAbilityRoundResult::Pending { pending } => {
                Ok(AbilityRoundEvaluation::Pending(pending))
            }
        }
    }
}

/// Runs a pure evaluator command with its generated expression on stdin.
///
/// Feeding the expression through stdin avoids both a mutable source pathname
/// and the operating system's command-line length limit.
///
/// # Errors
///
/// Returns an error when the evaluator cannot be spawned, its stdin cannot be
/// written, or the child cannot be reaped.
pub(super) fn output_with_expression(command: &mut Command, expression: &str) -> Result<Output> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("spawning pure Nix evaluator")?;
    let mut stdin = child
        .stdin
        .take()
        .context("pure Nix evaluator did not expose stdin")?;
    let write_result = stdin.write_all(expression.as_bytes());
    drop(stdin);
    let output = child
        .wait_with_output()
        .context("waiting for Nix evaluator")?;
    write_result.context("writing generated expression to Nix evaluator")?;
    Ok(output)
}

/// Resolves an AOS-built executable before constructing a scrubbed command.
fn command_from_path(name: &str) -> Result<Command> {
    let path = std::env::var_os("PATH").context("PATH is unavailable while resolving evaluator")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Ok(Command::new(candidate));
        }
    }
    anyhow::bail!("cannot find {name} in the AOS command path")
}

/// Constructs the single scrubbed stock-Nix command used by both evaluation
/// passes.
///
/// The executable is resolved before the environment is cleared. Callers add
/// only exact authenticated inputs and the expression/attribute they need.
pub(super) fn pure_eval_command() -> Result<Command> {
    let mut command = command_from_path("nix-instantiate")?;
    let nix_cache_home = std::env::var_os("XDG_CACHE_HOME");
    configure_pure_eval_command(&mut command, nix_cache_home.as_deref());
    Ok(command)
}

fn configure_pure_eval_command(command: &mut Command, nix_cache_home: Option<&OsStr>) {
    let store = std::env::var_os("AOS_NIX_EVAL_STORE");
    command.env_clear();
    if let Some(store) = store {
        command.arg("--store").arg(store);
    }
    // Nix creates client cache state even for pure evaluation. Preserve only
    // the service-owned cache directory across the environment scrub so the
    // hardened read-only home does not make evaluation fail before it starts.
    if let Some(nix_cache_home) = nix_cache_home {
        command.env("XDG_CACHE_HOME", nix_cache_home);
    }
    command
        .args(["--extra-experimental-features", "nix-command flakes"])
        .args(["--eval", "--strict", "--json", "--pure-eval"])
        .args(["--option", "restrict-eval", "true"])
        .args(["--option", "allow-import-from-derivation", "false"])
        .args(["--option", "allowed-uris", "path:/nix/store/"]);
}

/// Infer a [`KillReason`] when the subprocess was terminated by a signal.
///
/// A cgroup OOM or `RuntimeMaxSec` deadline kills `nix` with `SIGKILL` and
/// little or no stderr; the driver treats that as a kill rather than an opaque
/// eval error. Precise OOM-vs-timeout attribution comes from the transient
/// scope's `Result` property, which `aos-eval.service` can pass via the
/// `AOS_EVAL_SCOPE_RESULT` environment variable.
fn kill_reason(status: &std::process::ExitStatus, stderr: &str) -> Option<KillReason> {
    if let Ok(result) = std::env::var("AOS_EVAL_SCOPE_RESULT") {
        match result.as_str() {
            "oom-kill" => return Some(KillReason::Oom),
            "timeout" => return Some(KillReason::Timeout),
            _ => {}
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if status.signal().is_some() && stderr.trim().is_empty() {
            return Some(KillReason::Unknown);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (status, stderr);
    }
    None
}

/// Renders authenticated working-set modules as resolver-owned provenance records.
fn render_package_module_list(members: &[WorkingSetMember], locked: bool) -> Result<String> {
    render_package_module_list_with(members, locked, locked_store_input)
}

/// Renders package modules with an injectable locked-input renderer.
///
/// Production evaluation uses [`locked_store_input`] above. Keeping the
/// renderer injectable lets unit tests prove that every resolver-authenticated
/// runtime output crosses the admission boundary without requiring a real Nix
/// store path in the test process.
fn render_package_module_list_with<F>(
    members: &[WorkingSetMember],
    locked: bool,
    mut lock_input: F,
) -> Result<String>
where
    F: FnMut(&Path, Option<&str>) -> Result<String>,
{
    let mut items = Vec::new();
    for member in members {
        let module = member.ability.as_ref().and_then(|document| {
            document.package_module.as_ref().map(|locator| {
                (
                    locator.artifact.store_path.as_str(),
                    locator.artifact.nar_hash.to_string(),
                    locator.path.as_str(),
                )
            })
        });
        if let Some((path, nar_hash, entry_point)) = module {
            let config_root = if locked {
                if nar_hash.is_empty() {
                    bail!(
                        "working-set package {} has a module without an authenticated NAR hash",
                        member.package
                    );
                }
                let authenticated = lock_input(Path::new(path), Some(&nar_hash))?;
                // `fetchTree.outPath` is a context-bearing string, while the
                // module boundary deliberately requires a Nix path. The NAR
                // hash above has already authenticated the exact tree; drop
                // only its string context before path coercion so recursive
                // package imports retain their confined path provenance.
                format!("(/. + builtins.unsafeDiscardStringContext ({authenticated}))")
            } else {
                nix_path_str(path)
            };
            let self_output = member
                .outputs
                .self_output
                .as_deref()
                .map(|output| {
                    if locked {
                        lock_input(Path::new(output), None)
                    } else {
                        Ok(nix_string(output))
                    }
                })
                .transpose()?
                .unwrap_or_else(|| "null".to_string());
            let dependency_outputs = member
                .outputs
                .dependencies
                .iter()
                .map(|(package, output)| {
                    let output = if locked {
                        lock_input(Path::new(output), None)?
                    } else {
                        nix_string(output)
                    };
                    Ok(format!("{} = {output};", nix_string(package)))
                })
                .collect::<Result<Vec<_>>>()?
                .join(" ");
            let package_version = member.version.as_deref().with_context(|| {
                format!(
                    "working-set package {} has a module without an authenticated package version",
                    member.package
                )
            })?;
            items.push(format!(
                    "    (let configRoot = {config_root}; in {{ name = {}; packageVersion = {}; inherit configRoot; module = configRoot + {}; outputs = {{ self = {self_output}; dependencies = {{ {dependency_outputs} }}; }}; }})",
                    nix_string(&member.package),
                    nix_string(package_version),
                    nix_string(&format!("/{entry_point}")),
                ));
        }
    }
    if items.is_empty() {
        Ok("[ ]".to_string())
    } else {
        Ok(format!("[\n{}\n  ]", items.join("\n")))
    }
}

fn render_selected_provider_module_list(
    selections: &AbilityRoundSelections,
    locked: bool,
) -> Result<String> {
    let mut items = Vec::new();
    for selected in selections.provider_modules() {
        let artifact = &selected.locator.artifact;
        let authenticated_root = if locked {
            let input = locked_store_input(
                Path::new(&artifact.store_path),
                Some(&artifact.nar_hash.to_string()),
            )?;
            format!("(/. + builtins.unsafeDiscardStringContext ({input}))")
        } else {
            nix_path_str(&artifact.store_path)
        };
        let self_output = selected
            .outputs
            .self_output
            .as_deref()
            .context("selected provider module has no authenticated self output")?;
        let self_output = render_output_path(self_output, locked)?;
        let dependencies = selected
            .outputs
            .dependencies
            .iter()
            .map(|(package, output)| {
                Ok(format!(
                    "{} = {};",
                    nix_string(package),
                    render_output_path(output, locked)?
                ))
            })
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        let artifact_locators = selected
            .artifact_locators
            .iter()
            .map(|(selector, artifact)| {
                let selector_json = serde_json::to_string(selector)
                    .context("encoding selected package-output selector")?;
                let artifact_json = serde_json::to_string(artifact)
                    .context("encoding authenticated artifact reference")?;
                let path = render_output_path(&artifact.store_path, locked)?;
                Ok(format!(
                    "{} = {{ artifactReference = builtins.fromJSON {}; path = {path}; }};",
                    nix_string(&selector_json),
                    nix_string(&artifact_json),
                ))
            })
            .collect::<Result<Vec<_>>>()?
            .join(" ");

        items.push(format!(
            "    (let configRoot = {authenticated_root}; in {{ name = {}; packageVersion = {}; inherit configRoot; module = configRoot + {}; outputs = {{ self = {self_output}; dependencies = {{ {dependencies} }}; }}; artifactLocators = {{ {artifact_locators} }}; }})",
            nix_string(&selected.package),
            nix_string(&selected.version),
            nix_string(&format!("/{}", selected.locator.path.as_str())),
        ));
    }

    if items.is_empty() {
        Ok("[ ]".to_string())
    } else {
        Ok(format!("[\n{}\n  ]", items.join("\n")))
    }
}

fn render_output_path(path: &str, locked: bool) -> Result<String> {
    if locked {
        locked_store_input(Path::new(path), None)
    } else {
        Ok(nix_string(path))
    }
}

fn render_selected_ability_bindings(selections: &AbilityRoundSelections) -> String {
    if selections.bindings().is_empty() {
        return "{}".to_string();
    }

    let bindings = selections
        .bindings()
        .iter()
        .map(|(key, binding)| {
            format!(
                "  {} = {{ request = {}; implementation = {}; providerInstance = {}; slot = {}; }};",
                nix_string(key),
                nix_string(&binding.request),
                nix_string(&binding.implementation),
                nix_string(&binding.provider_instance),
                nix_string(&binding.slot),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("{{\n{bindings}\n}}")
}

/// Renders one store path as a fixed, pure evaluator input.
pub(super) fn locked_store_input(path: &Path, expected_nar_hash: Option<&str>) -> Result<String> {
    let (root, suffix) = store_root_and_suffix(path)?;
    let nar_hash = expected_nar_hash.map_or_else(
        || super::retained_store_path_nar_hash(&root),
        |hash| Ok(hash.to_string()),
    )?;
    let nar_hash = sha256_sri(&nar_hash)?;
    let root = root
        .to_str()
        .context("evaluator store input path is not UTF-8")?;
    let fetched = format!(
        "(builtins.fetchTree {{ type = \"path\"; path = {}; narHash = {}; }}).outPath",
        nix_string(root),
        nix_string(&nar_hash),
    );
    if suffix.as_os_str().is_empty() {
        Ok(fetched)
    } else {
        let suffix = suffix
            .to_str()
            .context("evaluator store input suffix is not UTF-8")?;
        Ok(format!(
            "({fetched} + {})",
            nix_string(&format!("/{suffix}"))
        ))
    }
}

pub(crate) fn store_root_and_suffix(path: &Path) -> Result<(PathBuf, PathBuf)> {
    let relative = path
        .strip_prefix("/nix/store")
        .with_context(|| format!("evaluator input {} is outside /nix/store", path.display()))?;
    let mut components = relative.components();
    let Some(std::path::Component::Normal(root_name)) = components.next() else {
        bail!("evaluator input has no valid store object component");
    };
    let root_name = root_name
        .to_str()
        .context("evaluator store object name is not UTF-8")?;
    let (hash, name) = root_name
        .split_at_checked(32)
        .and_then(|(hash, suffix)| suffix.strip_prefix('-').map(|name| (hash, name)))
        .context("evaluator input has a malformed store object name")?;
    ensure!(
        hash.bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte)),
        "evaluator input has an invalid Nix store hash"
    );
    ensure!(
        !name.is_empty()
            && name.len() <= 211
            && name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
            }),
        "evaluator input has an invalid Nix store name"
    );

    let root = Path::new("/nix/store").join(root_name);
    let mut suffix = PathBuf::new();
    for component in components {
        let std::path::Component::Normal(component) = component else {
            bail!("evaluator input has a non-canonical store-path suffix");
        };
        suffix.push(component);
    }
    Ok((root, suffix))
}

fn sha256_sri(hash: &str) -> Result<String> {
    let hex = crate::verify::sha256_digest_hex(hash)?;
    let digest = hex::decode(hex).context("decoding normalized evaluator input hash")?;
    Ok(format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    ))
}

/// Renders a Rust string as a quoted Nix string literal.
pub(super) fn nix_string(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace("${", "\\${")
    )
}

/// Render a path as a bare Nix path literal when it is an absolute store-style
/// path, else as a quoted string (so the expression always parses).
#[cfg(test)]
fn nix_path(path: &Path) -> String {
    nix_path_str(&path.to_string_lossy())
}

fn nix_path_str(path: &str) -> String {
    if path.starts_with('/') && path.bytes().all(is_nix_path_byte) {
        path.to_string()
    } else {
        nix_string(path)
    }
}

fn is_nix_path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_' | b'+')
}

/// The on-host package-contract resolver used by configuration evaluation.
pub struct RegistryPackageModules {
    registries: RegistrySet,
    image_packages: BTreeMap<String, super::runtime::LocalRuntimePackage>,
}

impl RegistryPackageModules {
    /// Wraps an already-loaded registry set.
    pub fn new(registries: RegistrySet) -> Self {
        Self {
            registries,
            image_packages: BTreeMap::new(),
        }
    }

    /// Returns the registry snapshot used for package-contract lookup.
    pub fn registries(&self) -> &RegistrySet {
        &self.registries
    }

    /// Returns packages authenticated by, and seeded from, the running image.
    pub fn image_packages(&self) -> &BTreeMap<String, super::runtime::LocalRuntimePackage> {
        &self.image_packages
    }

    /// Loads the on-host system-scope registry snapshot and immutable image catalog.
    ///
    /// # Errors
    ///
    /// Returns an error when APM configuration, a registry, or image package
    /// metadata cannot be loaded and authenticated.
    pub fn load_system() -> Result<Self> {
        let scope = crate::types::ProfileScope::System;
        let config = crate::config::ApmConfig::load(scope)?;
        let enabled = config.enabled_registries();
        let registries = RegistrySet::load_for_config_evaluation(
            &config.cache_path(),
            &enabled,
            &native_platform(),
        )?;
        let profile = crate::profile::Profile::open_readonly(scope);
        let mut image_catalog = None;
        let mut image_packages = BTreeMap::new();
        for record in crate::profile::meta::list_meta(&profile)? {
            let Some(mut apm) = record.apm else {
                continue;
            };
            let is_image = record.pushed_by == "aos-image" && apm.registry == "seed";
            if !is_image {
                continue;
            }
            if image_catalog.is_none() {
                image_catalog = Some(immutable_image_seed_catalog()?);
            }
            let image_catalog = image_catalog
                .as_ref()
                .context("loading the immutable image package catalog")?;
            let catalog_record = image_catalog.get(&record.store_path).with_context(|| {
                format!(
                    "image-seeded package '{}' is absent from the immutable image catalog",
                    apm.name
                )
            })?;
            let catalog_apm = catalog_record.apm.as_ref().with_context(|| {
                format!(
                    "immutable image catalog entry {} has no APM metadata",
                    record.store_path
                )
            })?;
            validate_image_seed_metadata(&apm, catalog_apm)?;
            apm = catalog_apm.clone();
            require_immutable_image_path(&record.store_path, "runtime output")?;
            image_packages.insert(
                apm.name,
                super::runtime::LocalRuntimePackage {
                    version: apm.version,
                    store_path: record.store_path,
                    expose: apm.expose,
                    expose_artifact: apm.expose_artifact,
                    ability: apm.ability,
                    closure: std::cell::RefCell::new(None),
                },
            );
        }
        Ok(Self {
            registries,
            image_packages,
        })
    }
}

fn resolved_registry_package_module(
    registry: &crate::registry::Registry,
    package: &crate::types::PackageMeta,
) -> Result<Option<ResolvedPackageModule>> {
    let Some(document) = crate::ability_package::resolve_package_document(package)? else {
        return Ok(None);
    };
    let ability_store_path = package
        .ability
        .as_ref()
        .context("resolved package document has no authenticated companion")?
        .store_path
        .clone();
    let Some(module) = document.package_module.as_ref() else {
        return Ok(None);
    };
    let root = crate::registry::store_path_hash(&module.artifact.store_path);

    Ok(Some(ResolvedPackageModule {
        registry: registry.config.name.clone(),
        release_trust: registry.release_trust().cloned(),
        realization: registry
            .store_map()
            .realization_subset_hash(&[root.to_string()])
            .ok(),
        package: package.name.clone(),
        version: package.version.clone(),
        platform: package.platform.clone(),
        runtime_output: package.store_path.clone(),
        ability_store_path,
        document,
    }))
}

fn resolved_image_package_module(
    name: &str,
    package: &super::runtime::LocalRuntimePackage,
) -> Result<Option<ResolvedPackageModule>> {
    let Some(ability) = package.ability.clone() else {
        return Ok(None);
    };
    let ability_store_path = ability.store_path.clone();
    let manifest = crate::ability_package::read_package_manifest(&ability_store_path)?;
    let decoded = crate::ability_package::decode_package_manifest(&manifest)?;
    if decoded.package_module.is_none() {
        return Ok(None);
    }
    let package_meta = crate::types::PackageMeta {
        name: name.to_string(),
        version: package.version.clone(),
        description: "immutable image package".to_string(),
        homepage: None,
        license: "LicenseRef-AOS-Image".to_string(),
        maintainer: "AOS image".to_string(),
        platform: "x86_64-linux".to_string(),
        store_path: package.store_path.clone(),
        nar_hash: decoded.package.payload.nar_hash.to_string(),
        nar_size: 0,
        references: Vec::new(),
        source_drv: String::new(),
        source_nar_hash: String::new(),
        closure_size: 0,
        sysroot: false,
        previous: None,
        images: Vec::new(),
        min_format: None,
        requires_features: Vec::new(),
        expose: package.expose.clone(),
        expose_artifact: package.expose_artifact.clone(),
        config_module: None,
        documentation: None,
        ability: Some(ability),
        permissions: Default::default(),
        bpf_lsm: None,
        attestation: Default::default(),
    };
    let document = crate::ability_package::resolve_package_document(&package_meta)?;

    Ok(document.map(|document| ResolvedPackageModule {
        registry: String::new(),
        release_trust: None,
        realization: None,
        package: name.to_string(),
        version: package.version.clone(),
        platform: "image".to_string(),
        runtime_output: package.store_path.clone(),
        ability_store_path: ability_store_path.clone(),
        document,
    }))
}

fn immutable_image_seed_catalog() -> Result<BTreeMap<String, crate::types::InstalledMeta>> {
    let toplevel = std::fs::read_link("/aos-toplevel")
        .context("reading the booted immutable toplevel link")?;
    let toplevel = toplevel
        .to_str()
        .context("booted immutable toplevel path is not UTF-8")?;
    let lower_toplevel = super::runtime::immutable_lower_store_path(toplevel)?;
    if !lower_toplevel.exists() {
        anyhow::bail!("booted toplevel {toplevel} is absent from the immutable image store");
    }
    let seed_link = lower_toplevel.join("package-profile-seed");
    let seed = std::fs::read_link(&seed_link).with_context(|| {
        format!(
            "reading immutable package seed link {}",
            seed_link.display()
        )
    })?;
    let seed = seed
        .to_str()
        .context("immutable package seed path is not UTF-8")?;
    let lower_seed = super::runtime::immutable_lower_store_path(seed)?;
    let meta_dir = lower_seed.join("meta");
    let mut files = std::fs::read_dir(&meta_dir)
        .with_context(|| {
            format!(
                "reading immutable image package catalog {}",
                meta_dir.display()
            )
        })?
        .collect::<std::io::Result<Vec<_>>>()?;
    files.sort_by_key(std::fs::DirEntry::file_name);

    let mut catalog = BTreeMap::new();
    for entry in files {
        if !entry.file_type()?.is_file()
            || entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("json")
        {
            continue;
        }
        let record: crate::types::InstalledMeta = serde_json::from_slice(
            &std::fs::read(entry.path())
                .with_context(|| format!("reading {}", entry.path().display()))?,
        )
        .with_context(|| format!("parsing {}", entry.path().display()))?;
        let apm = record.apm.as_ref().with_context(|| {
            format!(
                "immutable image catalog entry {} has no APM metadata",
                entry.path().display()
            )
        })?;
        if record.pushed_by != "aos-image" || apm.registry != "seed" {
            anyhow::bail!(
                "immutable image catalog entry '{}' has invalid image provenance",
                apm.name
            );
        }
        require_immutable_image_path(&record.store_path, "catalog runtime output")?;
        if catalog.insert(record.store_path.clone(), record).is_some() {
            anyhow::bail!("immutable image package catalog contains a duplicate store path");
        }
    }
    Ok(catalog)
}

fn require_immutable_image_path(path: &str, kind: &str) -> Result<PathBuf> {
    let lower = super::runtime::immutable_lower_store_path(path)?;
    if !lower.exists() {
        anyhow::bail!("image {kind} {path} is absent from the immutable image store");
    }
    Ok(lower)
}

fn validate_image_seed_metadata(
    profile: &crate::types::ApmMeta,
    immutable: &crate::types::ApmMeta,
) -> Result<()> {
    if serde_json::to_value(profile)? != serde_json::to_value(immutable)? {
        anyhow::bail!(
            "image-seeded package '{}' disagrees with immutable image metadata",
            profile.name
        );
    }
    Ok(())
}

impl PackageModuleResolver for RegistryPackageModules {
    fn package_module(&self, package: &str) -> Result<Option<ResolvedPackageModule>> {
        if let Ok(Some((registry, resolved))) =
            self.registries.resolve_for_config_evaluation(package)
        {
            return resolved_registry_package_module(registry, resolved);
        }

        let Some((local_name, local)) = self.image_packages.get_key_value(package) else {
            return Ok(None);
        };
        resolved_image_package_module(local_name, local)
    }

    fn package_module_exact(
        &self,
        package: &str,
        version: Option<&str>,
        runtime_output: Option<&str>,
    ) -> Result<Option<ResolvedPackageModule>> {
        let exact =
            self.registries
                .resolve_exact_for_config_evaluation(package, version, runtime_output);
        match exact {
            Ok(Some((registry, resolved))) => {
                return resolved_registry_package_module(registry, resolved);
            }
            Ok(None) | Err(_) => {}
        }
        if self
            .registries
            .resolve_for_config_evaluation(package)
            .is_ok_and(|resolved| resolved.is_some())
        {
            return Ok(None);
        }

        let Some((local_name, local)) = self.image_packages.get_key_value(package) else {
            return Ok(None);
        };
        if version.is_some_and(|want| want != local.version)
            || runtime_output.is_some_and(|want| want != local.store_path)
        {
            return Ok(None);
        }
        resolved_image_package_module(local_name, local)
    }
}

#[cfg(test)]
mod tests {
    use aos_ability_model::document::PackageSubject;
    use aos_ability_model::{
        AbilityActivationMode, ArtifactReference, LocalKey, ModuleLocator, PackageDocument,
        PackageImplementation, RelativePath, RequiredFeature, VersionedDocument,
    };
    use aos_ability_validate::PackageOutputSelector;
    use aos_contract::Sha256Digest;

    use super::*;
    use crate::config_eval::PackageOutputs;
    use crate::config_eval::ability_rounds::{
        PendingAbilityRequest, SelectedAbilityBinding, SelectedProviderModule,
    };
    use crate::types::{ApmMeta, ConfigModuleMeta, ConfigOutputMeta, ModuleAbiCompat};

    fn member(pkg: &str, module_artifact: Option<&str>) -> WorkingSetMember {
        WorkingSetMember {
            registry: None,
            release_trust: None,
            config_realization: None,
            package: pkg.to_string(),
            version: Some("1.0.0".to_string()),
            ability: None,
            ability_store_path: None,
            module_artifact: module_artifact.map(str::to_string),
            module_artifact_nar_hash: module_artifact.map(|_| "sha256:test".to_string()),
            module_abi_compat: Some(ModuleAbiCompat { min: 1, max: 2 }),
            outputs: super::super::PackageOutputs::default(),
        }
    }

    fn ability_document(package: &str, package_module: ModuleLocator) -> PackageDocument {
        let artifact = package_module.artifact.clone();

        PackageDocument {
            schema: PackageDocument::SCHEMA.to_string(),
            required_features: vec![RequiredFeature::new("abilities-v1").unwrap()],
            activation_mode: AbilityActivationMode::ContractsOnly,
            package: PackageSubject {
                name: LocalKey::new(package).unwrap(),
                version: "1.0.0".to_string(),
                payload: artifact.clone(),
                source: artifact.clone(),
            },
            artifacts: vec![artifact],
            interfaces: BTreeMap::new(),
            guarantees: BTreeMap::new(),
            package_module: Some(package_module),
            option_declarations: Vec::new(),
            exports: Vec::new(),
            requirements: Vec::new(),
            implementation: PackageImplementation {
                providers: Vec::new(),
                handlers: BTreeMap::new(),
            },
            qualification: Default::default(),
        }
    }

    fn image_seed_metadata() -> ApmMeta {
        ApmMeta {
            name: "web".to_string(),
            version: "1.0.0".to_string(),
            explicit: true,
            registry: "seed".to_string(),
            installed_at: "1970-01-01T00:00:00Z".to_string(),
            held: false,
            source_drv: "/nix/store/source-web.drv".to_string(),
            source_nar_hash: "sha256:source".to_string(),
            expose: None,
            expose_artifact: None,
            config_module: None,
            documentation: None,
            ability: None,
            permissions: Default::default(),
            bpf_lsm: None,
            attestation: Default::default(),
        }
    }

    fn image_config_module() -> ConfigModuleMeta {
        ConfigModuleMeta {
            module_artifact: ConfigOutputMeta {
                store_path: "/nix/store/11111111111111111111111111111111-image-web-config"
                    .to_string(),
                nar_hash: "sha256:test".to_string(),
                nar_size: 1,
                references: Vec::new(),
            },
            evaluation_base_lib: None,
            dependency_outputs: BTreeMap::new(),
            module_abi_compat: ModuleAbiCompat { min: 1, max: 1 },
            declares: Vec::new(),
            declaration_schema: Vec::new(),
            requires: Vec::new(),
            owns_roots: Vec::new(),
            contributes: Vec::new(),
            provides_capabilities: Vec::new(),
            artifacts: Default::default(),
        }
    }

    #[test]
    fn mutable_image_seed_metadata_must_match_the_immutable_catalog() {
        let immutable = image_seed_metadata();
        let mut profile = immutable.clone();
        assert!(validate_image_seed_metadata(&profile, &immutable).is_ok());

        profile.held = true;
        let error = validate_image_seed_metadata(&profile, &immutable)
            .expect_err("mutable profile forgery must be rejected");
        assert!(
            error
                .to_string()
                .contains("disagrees with immutable image metadata"),
            "{error:#}"
        );
    }

    #[test]
    fn unavailable_registry_uses_image_module_with_exact_identity_pins() {
        let temp = tempfile::TempDir::new().unwrap();
        let missing = crate::registry::tests::registry_config("andyl", 500);
        let registries =
            RegistrySet::load_for_config_evaluation(temp.path(), &[&missing], "x86_64-linux")
                .unwrap();
        let store_path = "/nix/store/00000000000000000000000000000000-image-web";
        let image_packages = BTreeMap::from([(
            "image-web".to_string(),
            super::super::runtime::LocalRuntimePackage {
                version: "1.2.3".to_string(),
                store_path: store_path.to_string(),
                expose: None,
                expose_artifact: None,
                config_module: Some(image_config_module()),
                ability: None,
                closure: std::cell::RefCell::new(None),
            },
        )]);
        let resolver = RegistryConfigModules {
            registries,
            installed: Vec::new(),
            image_packages,
        };

        let by_name = resolver.config_module("image-web").unwrap();
        let exact = resolver
            .config_module_exact("image-web", Some("1.2.3"), Some(store_path))
            .unwrap();

        assert_eq!(by_name.registry, "");
        assert_eq!(by_name.platform, "image");
        assert_eq!(exact.version, "1.2.3");
        assert_eq!(exact.runtime_output, store_path);
        assert!(
            resolver
                .config_module_exact("image-web", Some("9.9.9"), Some(store_path))
                .is_none()
        );
        assert!(
            resolver
                .config_module_exact(
                    "image-web",
                    Some("1.2.3"),
                    Some("/nix/store/22222222222222222222222222222222-other"),
                )
                .is_none()
        );
    }

    #[test]
    fn loaded_registry_name_prevents_exact_image_fallback_across_a_gap() {
        let temp = tempfile::TempDir::new().unwrap();
        let loaded = crate::registry::tests::registry_config("loaded", 600);
        let missing = crate::registry::tests::registry_config("missing", 500);
        let nar_digest = "0".repeat(52);
        let catalog = format!(
            r#"[package]
name = "image-web"
description = "registry package with the same name as an image package"
license = "MIT"
maintainer = "test"

[[versions]]
version = "2.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/22222222222222222222222222222222-image-web"
nar_hash = "sha256:{nar_digest}"
nar_size = 1
closure_size = 1
source_drv = "/nix/store/33333333333333333333333333333333-image-web.drv"
source_nar_hash = "sha256:{nar_digest}"
provenance = "provenance/image-web.jsonl"

[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["config-module-v1", "attestation-v1"]

[versions.platforms.x86_64-linux.config_module.module_artifact]
store_path = "/nix/store/44444444444444444444444444444444-image-web-config"
nar_hash = "sha256:{nar_digest}"
nar_size = 1
references = []

[versions.platforms.x86_64-linux.config_module.module_abi_compat]
min = 1
max = 1
"#
        );
        let _ = crate::registry::tests::make_registry(
            &temp,
            &loaded.name,
            loaded.priority,
            &[("image-web", &catalog)],
        );
        let registries = RegistrySet::load_for_config_evaluation(
            temp.path(),
            &[&loaded, &missing],
            "x86_64-linux",
        )
        .unwrap();
        let image_store_path = "/nix/store/00000000000000000000000000000000-image-web";
        let image_packages = BTreeMap::from([(
            "image-web".to_string(),
            super::super::runtime::LocalRuntimePackage {
                version: "1.2.3".to_string(),
                store_path: image_store_path.to_string(),
                expose: None,
                expose_artifact: None,
                config_module: Some(image_config_module()),
                ability: None,
                closure: std::cell::RefCell::new(None),
            },
        )]);
        let resolver = RegistryConfigModules {
            registries,
            installed: Vec::new(),
            image_packages,
        };

        let by_name = resolver.config_module("image-web").unwrap();

        assert_eq!(by_name.registry, "loaded");
        assert_eq!(by_name.version, "2.0.0");
        assert!(
            resolver
                .config_module_exact("image-web", Some("1.2.3"), Some(image_store_path))
                .is_none()
        );
    }

    #[test]
    fn entry_nix_injects_host_as_operator_module() {
        let evaluator = StockNixEvaluator::new("/run/aos-eval", 0);
        let working = vec![
            member("web", Some("/nix/store/hash-web-config")),
            member("firewall", Some("/nix/store/hash-firewall-config")),
        ];
        let attempt = EvalAttempt {
            host_nix: Path::new("/nix/store/hash-host.nix"),
            runtime_modules: &[],
            base_lib: Path::new("/nix/store/hash-aos-base-lib"),
            facts_json: None,
            working_set: &working,
            iteration: 0,
        };
        let text = evaluator.render_entry_nix(&attempt).unwrap();

        assert!(text.contains("operatorModules = [ hostModule ]"), "{text}");
        assert!(text.contains("import /nix/store/hash-host.nix"), "{text}");
        assert!(
            text.contains("import /nix/store/hash-aos-base-lib"),
            "{text}"
        );
        assert!(
            text.contains("let configRoot = /nix/store/hash-web-config; in { name = \"web\""),
            "{text}"
        );
        assert!(
            text.contains(
                "let configRoot = /nix/store/hash-firewall-config; in { name = \"firewall\""
            ),
            "{text}"
        );
        assert!(text.contains("module = configRoot + \"/module.nix\""));
        assert!(text.contains("baselineSystem = baseLib.evalHostConfig"));
        assert!(text.contains("baseLib.mergeImageManifest"));
        assert!(text.contains("manifest = mergedManifest //"));
        assert!(!text.contains("mergeImageDefaults ="));
        assert!(text.contains("installAtBoot.config"), "{text}");
        assert!(text.contains("installAtBoot.systemCredentials"), "{text}");
        assert!(
            text.contains("ref = \"system-credential:${systemCredential}\""),
            "{text}"
        );
    }

    #[test]
    fn locked_entry_coerces_authenticated_config_roots_to_nix_paths() {
        let mut web = member(
            "web",
            Some("/nix/store/00000000000000000000000000000000-web-config"),
        );
        web.module_artifact_nar_hash = Some(format!("sha256:{}", "00".repeat(32)));
        let working = vec![web];
        let text = render_package_module_list(&working, true).unwrap();

        assert!(
            text.contains(
                "let configRoot = (/. + builtins.unsafeDiscardStringContext ((builtins.fetchTree"
            ),
            "{text}"
        );
        assert!(text.contains("module = configRoot + \"/module.nix\""));
    }

    #[test]
    fn locked_entry_imports_the_authenticated_package_module_and_version() {
        let mut web = member("web", None);
        web.ability = Some(ability_document(
            "web",
            ModuleLocator {
                artifact: ArtifactReference {
                    content: Sha256Digest::of_bytes(b"web module"),
                    store_path: "/nix/store/00000000000000000000000000000000-web-module"
                        .to_string(),
                    nar_hash: Sha256Digest::of_bytes(b"web module NAR"),
                    closure: Sha256Digest::of_bytes(b"web module closure"),
                },
                path: RelativePath::new("abilities/module.nix").unwrap(),
            },
        ));

        let mut admitted = Vec::new();
        let rendered = render_package_module_list_with(&[web], true, |path, nar_hash| {
            admitted.push((path.to_path_buf(), nar_hash.map(str::to_string)));
            Ok("(authenticated-module-root)".to_string())
        })
        .unwrap();

        assert_eq!(
            admitted,
            [(
                PathBuf::from("/nix/store/00000000000000000000000000000000-web-module"),
                Some(Sha256Digest::of_bytes(b"web module NAR").to_string()),
            )]
        );
        assert!(rendered.contains("packageVersion = \"1.0.0\""));
        assert!(rendered.contains("module = configRoot + \"/abilities/module.nix\""));
    }

    #[test]
    fn package_module_and_legacy_config_module_cannot_coexist() {
        let mut web = member(
            "web",
            Some("/nix/store/11111111111111111111111111111111-web-config"),
        );
        web.ability = Some(ability_document(
            "web",
            ModuleLocator {
                artifact: ArtifactReference {
                    content: Sha256Digest::of_bytes(b"web module"),
                    store_path: "/nix/store/00000000000000000000000000000000-web-module"
                        .to_string(),
                    nar_hash: Sha256Digest::of_bytes(b"web module NAR"),
                    closure: Sha256Digest::of_bytes(b"web module closure"),
                },
                path: RelativePath::new("module.nix").unwrap(),
            },
        ));

        let error = render_package_module_list(&[web], true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("both current ability-module and legacy")
        );
    }

    #[test]
    fn locked_entry_admits_self_and_dependency_outputs() {
        let mut web = member(
            "web",
            Some("/nix/store/00000000000000000000000000000000-web-config"),
        );
        web.module_artifact_nar_hash = Some(format!("sha256:{}", "00".repeat(32)));
        web.outputs.self_output = Some("/nix/store/hash-web-runtime".to_string());
        web.outputs.dependencies.insert(
            "openssl".to_string(),
            "/nix/store/hash-openssl-runtime".to_string(),
        );

        let mut admitted = Vec::new();
        let text = render_package_module_list_with(&[web], true, |path, _nar_hash| {
            admitted.push(path.to_path_buf());
            Ok(format!("(admit {})", nix_path(path)))
        })
        .unwrap();

        assert_eq!(
            admitted,
            [
                PathBuf::from("/nix/store/hash-web-runtime"),
                PathBuf::from("/nix/store/hash-openssl-runtime"),
            ]
        );
        assert!(text.contains("self = (admit /nix/store/hash-web-runtime)"));
        assert!(text.contains("\"openssl\" = (admit /nix/store/hash-openssl-runtime);"));
        assert!(!text.contains("authorization"), "{text}");
    }

    #[test]
    fn entry_nix_empty_working_set_renders_empty_list() {
        let evaluator = StockNixEvaluator::new("/run/aos-eval", 0);
        let attempt = EvalAttempt {
            host_nix: Path::new("/nix/store/hash-host.nix"),
            runtime_modules: &[],
            base_lib: Path::new("/nix/store/hash-aos-base-lib"),
            facts_json: None,
            working_set: &[],
            iteration: 0,
        };
        let text = evaluator.render_entry_nix(&attempt).unwrap();
        assert!(text.contains("packageModules = [ ]"), "{text}");
    }

    #[test]
    fn selected_provider_round_keeps_original_inputs_and_exact_selections() {
        let evaluator = StockNixEvaluator::new("/run/aos-eval", 0);
        let working = vec![member("consumer", Some("/nix/store/hash-consumer-config"))];
        let attempt = EvalAttempt {
            host_nix: Path::new("/nix/store/hash-host.nix"),
            runtime_modules: &[],
            base_lib: Path::new("/nix/store/hash-aos-base-lib"),
            facts_json: None,
            working_set: &working,
            iteration: 0,
        };
        let module = SelectedProviderModule {
            package: "provider".to_string(),
            version: "1.0.0".to_string(),
            locator: ModuleLocator {
                artifact: ArtifactReference {
                    content: Sha256Digest::from_bytes([1; 32]),
                    store_path: "/nix/store/00000000000000000000000000000000-provider".to_string(),
                    nar_hash: Sha256Digest::from_bytes([2; 32]),
                    closure: Sha256Digest::from_bytes([3; 32]),
                },
                path: RelativePath::new("lib/aos/provider.nix").unwrap(),
            },
            outputs: PackageOutputs {
                self_output: Some(
                    "/nix/store/00000000000000000000000000000000-provider".to_string(),
                ),
                dependencies: BTreeMap::from([(
                    "helper".to_string(),
                    "/nix/store/11111111111111111111111111111111-helper".to_string(),
                )]),
            },
            artifact_locators: BTreeMap::from([(
                PackageOutputSelector {
                    package: LocalKey::new("helper").unwrap(),
                    output: LocalKey::new("out").unwrap(),
                },
                ArtifactReference {
                    content: Sha256Digest::from_bytes([4; 32]),
                    store_path: "/nix/store/11111111111111111111111111111111-helper".to_string(),
                    nar_hash: Sha256Digest::from_bytes([5; 32]),
                    closure: Sha256Digest::from_bytes([6; 32]),
                },
            )]),
        };
        let binding = SelectedAbilityBinding {
            key: "binding-child".to_string(),
            request: "request-child".to_string(),
            implementation: "provider:implementation".to_string(),
            provider_instance: "provider:instance".to_string(),
            slot: "service".to_string(),
            provider_module: Some(module.clone()),
        };
        let selections = AbilityRoundSelections {
            bindings: BTreeMap::from([(binding.key.clone(), binding)]),
            provider_modules: BTreeMap::from([("module".to_string(), module)]),
        };

        let package_modules = render_package_module_list(&working, false).unwrap();
        let provider_modules = render_selected_provider_module_list(&selections, false).unwrap();
        let bindings = render_selected_ability_bindings(&selections);
        let rendered = evaluator
            .render_entry_nix_with_inputs(
                &attempt,
                &package_modules,
                &provider_modules,
                &bindings,
                &nix_path(attempt.base_lib),
                &nix_path(attempt.host_nix),
            )
            .unwrap();

        assert!(rendered.contains("operatorModules = [ hostModule ]"));
        assert!(rendered.contains("name = \"consumer\""));
        assert!(rendered.contains("name = \"provider\""));
        assert!(rendered.contains("module = configRoot + \"/lib/aos/provider.nix\""));
        assert!(rendered.contains("artifactLocators"));
        assert!(rendered.contains("artifactReference = builtins.fromJSON"));
        assert!(rendered.contains("\"binding-child\" = { request = \"request-child\""));
        assert!(!rendered.contains("-A abilityRound"));
    }

    #[test]
    fn pending_child_projection_decodes_from_the_real_module_fixed_point() {
        let Ok(mut command) = command_from_path("nix-instantiate") else {
            return;
        };
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repository = crate_root
            .parent()
            .and_then(Path::parent)
            .expect("aos-package must remain below the workspace root");
        let expression = format!(
            "let pkgs = import {} {{}}; in import {} {{ inherit (pkgs) lib; returnPending = true; }}",
            nix_path(&repository.join("default.nix")),
            nix_path(&repository.join("tests/abilities/composition-driver.nix")),
        );
        command.env_remove("LD_LIBRARY_PATH");
        command.args(["--eval", "--strict", "--json", "--expr", &expression]);

        let output = command
            .output()
            .expect("the AOS Nix evaluator must execute the fixed-point fixture");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let projection: PendingAbilityProjection = serde_json::from_slice(&output.stdout)
            .expect("the real camelCase Nix projection must decode");
        let pending = projection
            .requests
            .values()
            .next()
            .expect("the fixture must emit one pending child");

        assert_eq!(projection.requests.len(), 1);
        assert_eq!(pending.local_request_key, "child");
        assert_eq!(pending.requirement, "network");
        assert_eq!(pending.provider_instance, "provider:manager");
    }

    #[test]
    fn entry_nix_imports_rendered_typed_facts_module() {
        let root = std::env::temp_dir().join(format!(
            "aos-stock-facts-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let facts_json = root.join("facts.json");
        std::fs::write(
            &facts_json,
            r#"{"hostname":"node-1","mac_to_iface":[{"mac":"AA:BB:CC:DD:EE:FF","iface":"ens5"}]}"#,
        )
        .unwrap();
        let evaluator = StockNixEvaluator::new(&root, 0);
        let attempt = EvalAttempt {
            host_nix: Path::new("/nix/store/hash-host.nix"),
            runtime_modules: &[],
            base_lib: Path::new("/nix/store/hash-aos-base-lib"),
            facts_json: Some(&facts_json),
            working_set: &[],
            iteration: 0,
        };

        let entry_path = evaluator.write_entry(&attempt).unwrap();
        assert_eq!(entry_path, root.join("nix-source/entry.nix"));
        let entry = std::fs::read_to_string(entry_path).unwrap();
        assert!(entry.contains("factsModules = [ factsModule ]"), "{entry}");
        assert!(entry.contains("factsModule = ("), "{entry}");
        assert!(!entry.contains(root.to_string_lossy().as_ref()), "{entry}");
        assert!(entry.contains("hostname = \"node-1\";"), "{entry}");
        assert!(
            entry.contains("\"aa:bb:cc:dd:ee:ff\" = { names = [ \"ens5\" ]"),
            "{entry}"
        );
        assert!(!root.join("nix-source/host-facts.nix").exists());
    }

    #[test]
    fn members_without_module_artifact_are_skipped() {
        // A seed with no config module contributes nothing to the import list.
        let working = vec![member("web", None)];
        let rendered = render_package_module_list(&working, false).unwrap();
        assert_eq!(rendered, "[ ]");
    }

    #[test]
    fn package_modules_receive_only_authenticated_output_map() {
        let mut web = member("web", Some("/nix/store/hash-web-config"));
        web.outputs.self_output =
            Some("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-web".to_string());
        web.outputs.dependencies.insert(
            "openssl".to_string(),
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl".to_string(),
        );
        let rendered = render_package_module_list(&[web], false).unwrap();
        assert!(
            rendered.contains(
                "outputs = { self = \"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-web\"; dependencies = { \"openssl\" = \"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-openssl\"; }; };"
            ),
            "{rendered}"
        );
        assert!(!rendered.contains("pkgs ="), "{rendered}");
    }

    #[test]
    fn non_store_paths_are_quoted_so_the_expression_parses() {
        assert_eq!(
            nix_path_str("/run/aos-eval/host.nix"),
            "/run/aos-eval/host.nix"
        );
        assert_eq!(nix_path_str("/has spaces/x"), "\"/has spaces/x\"");
    }

    #[test]
    fn evaluator_command_is_pure_restricted_and_environment_scrubbed() {
        let mut command = Command::new("nix-instantiate");
        command.env("AOS_AMBIENT_SENTINEL", "must-not-survive");
        configure_pure_eval_command(&mut command, Some(OsStr::new("/var/cache/aos/nix-eval")));

        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.iter().any(|arg| arg == "--pure-eval"), "{args:?}");
        assert!(
            args.windows(2)
                .any(|args| { args == ["--extra-experimental-features", "nix-command flakes"] })
        );
        assert!(
            args.windows(3)
                .any(|args| { args == ["--option", "restrict-eval", "true"] })
        );
        assert!(
            args.windows(3)
                .any(|args| { args == ["--option", "allow-import-from-derivation", "false"] })
        );
        assert!(
            args.windows(3)
                .any(|args| { args == ["--option", "allowed-uris", "path:/nix/store/"] })
        );
        assert!(
            command
                .get_envs()
                .all(|(name, _)| name != "AOS_AMBIENT_SENTINEL")
        );
        assert!(command.get_envs().any(|(name, value)| {
            name == "XDG_CACHE_HOME"
                && value.is_some_and(|value| value == "/var/cache/aos/nix-eval")
        }));
    }

    #[test]
    fn realise_command_uses_registry_caches_without_delegating_trust() {
        let mut command = Command::new("nix-store");
        configure_realise_command(
            &mut command,
            "/nix/store/hash-config",
            &[
                "https://cache-one.example".to_string(),
                "https://cache-two.example".to_string(),
            ],
            Path::new("/run/aos-eval/nix-cache"),
            1,
        );

        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "--realise",
                "/nix/store/hash-config",
                "--option",
                "substituters",
                "https://cache-one.example https://cache-two.example",
                "--option",
                "require-sigs",
                "false",
                "-v",
            ]
        );
        assert!(command.get_envs().any(|(name, value)| {
            name == "XDG_CACHE_HOME"
                && value.is_some_and(|value| value == "/run/aos-eval/nix-cache")
        }));
    }
}
