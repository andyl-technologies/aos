//! The P1 stock-Nix evaluator and registry fetcher (build-spec §3, §4).
//!
//! [`StockNixEvaluator`] renders the working set into `entry.nix`, runs a cold
//! stock-Nix subprocess under the determinism flags, and classifies its result
//! via [`super::classify`]. [`SubstituterFetcher`] realises a provider's
//! `config` output through the configured substituter (the registry static
//! cache). Both are **builder-gated**: they require a real stock-nix and a
//! reachable registry, so they cannot run on a developer's macOS host and are
//! unit-tested here only for `entry.nix` rendering.
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

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::ability_rounds::{
    AbilityRoundEvaluation, AbilityRoundEvaluator, AbilityRoundSelections, PendingAbilityProjection,
};
use super::classify::{EvalClass, KillReason, classify};
use super::system_roots::{ConfigModuleResolver, ResolvedAbilityModule, ResolvedConfigModule};
use super::{ConfigOutputFetcher, EvalAttempt, NixEvaluator, SelectedProvider, WorkingSetMember};
use crate::platform::native_platform;
use crate::registry::RegistrySet;
use crate::types::ProfileScope;

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
}

impl<'a> StockAbilityRoundEvaluator<'a> {
    /// Creates a complete-fixed-point adapter around one immutable eval attempt.
    #[must_use]
    pub const fn new(evaluator: &'a StockNixEvaluator, attempt: EvalAttempt<'a>) -> Self {
        Self { evaluator, attempt }
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
    ) -> Result<String> {
        let package_modules = render_package_module_list(attempt.working_set, true)?;
        let provider_modules = render_selected_provider_module_list(selections, true)?;
        let bindings = render_selected_ability_bindings(selections);
        let base = locked_store_input(attempt.base_lib, None)?;
        let host = locked_store_input(attempt.host_nix, None)?;
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
            \x20   then {{ status = \"complete\"; manifest = finalManifest; }}\n\
            \x20   else {{\n\
            \x20     status = \"pending\";\n\
            \x20     pending = {{\n\
            \x20       requests = pendingAbilityRequests;\n\
            \x20       requirements = system.config.aos.abilities.compositionRequirements;\n\
            \x20       providerInstances = builtins.attrNames system.config.aos.abilities.instances;\n\
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
    Complete { manifest: serde_json::Value },
    Pending { pending: PendingAbilityProjection },
}

impl AbilityRoundEvaluator for StockAbilityRoundEvaluator<'_> {
    fn evaluate(
        &self,
        _round: u32,
        selections: &AbilityRoundSelections,
    ) -> Result<AbilityRoundEvaluation> {
        let expression = self
            .evaluator
            .render_locked_ability_round_entry_nix(&self.attempt, selections)?;
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
            StockAbilityRoundResult::Complete { manifest } => Ok(AbilityRoundEvaluation::Complete(
                serde_json::to_string(&manifest)?,
            )),
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
        if member.package_module.is_some() && member.config_output.is_some() {
            bail!(
                "working-set package {} carries both current ability-module and legacy config-module authority",
                member.package
            );
        }
        let module = member.package_module.as_ref().map(|locator| {
            (
                locator.artifact.store_path.as_str(),
                locator.artifact.nar_hash.to_string(),
                locator.path.as_str(),
            )
        });
        let legacy_module = member.config_output.as_deref().map(|path| {
            (
                path,
                member.config_output_nar_hash.clone().unwrap_or_default(),
                "module.nix",
            )
        });
        if let Some((path, nar_hash, entry_point)) = module.or(legacy_module) {
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
            "    (let configRoot = {authenticated_root}; in {{ name = {}; inherit configRoot; module = configRoot + {}; outputs = {{ self = {self_output}; dependencies = {{ {dependencies} }}; }}; artifactLocators = {{ {artifact_locators} }}; }})",
            nix_string(&selected.package),
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

/// Fetches a provider's `config` output by realising it through substituters.
///
/// On AOS the registry static cache is a configured substituter, so realising
/// the content-addressed `config` output path materializes it locally (and only
/// it — the `out` binary closure is fetched lazily, later, by the install path).
/// Builder-gated: it requires a reachable registry substituter.
pub struct SubstituterFetcher {
    verbose: u8,
    substituters: Vec<String>,
    nix_cache_dir: PathBuf,
}

impl SubstituterFetcher {
    /// Creates a fetcher from the cache endpoints in a registry snapshot.
    ///
    /// Cache locations are taken from the already-authenticated local registry
    /// snapshots rather than ambient Nix configuration. Cache signatures are
    /// not used as an authority here: the selected output's NAR hash and size
    /// are independently checked against signed registry metadata after
    /// realization.
    pub fn new(
        verbose: u8,
        registries: &RegistrySet,
        scope: ProfileScope,
        nix_cache_dir: impl Into<PathBuf>,
    ) -> Self {
        let registries_base = scope.registries_path();
        let mut seen = HashSet::new();
        let mut substituters = Vec::new();
        for registry in registries.registries() {
            let registry_name = &registry.config.name;
            let registry_dir = registries_base.join(registry_name);
            let mirrors =
                crate::registry_ops::resolve_mirrors_for_registry(&registry_dir, &registry.config);
            if verbose > 0 && mirrors.is_empty() {
                eprintln!(
                    "config-eval: registry '{registry_name}' has no cache endpoints in {}",
                    registry_dir.display()
                );
            }
            for cache in mirrors {
                let url = cache.url.trim_end_matches('/').to_string();
                if !url.is_empty() && seen.insert(url.clone()) {
                    if verbose > 0 {
                        eprintln!(
                            "config-eval: using cache endpoint from registry '{registry_name}': {url}"
                        );
                    }
                    substituters.push(url);
                }
            }
        }
        Self {
            verbose,
            substituters,
            nix_cache_dir: nix_cache_dir.into(),
        }
    }
}

/// Configures a Nix realization against the authenticated registry cache set.
fn configure_realise_command(
    command: &mut Command,
    store_path: &str,
    substituters: &[String],
    nix_cache_dir: &Path,
    verbose: u8,
) {
    command.env("XDG_CACHE_HOME", nix_cache_dir);
    command.arg("--realise").arg(store_path);
    if !substituters.is_empty() {
        command
            .args(["--option", "substituters"])
            .arg(substituters.join(" "))
            // Registry metadata pins the expected NAR identity, so an
            // independently signed narinfo is optional for this fetch path.
            .args(["--option", "require-sigs", "false"]);
    }
    if verbose > 0 {
        command.arg("-v");
    }
}

impl ConfigOutputFetcher for SubstituterFetcher {
    fn fetch_config_output(&self, provider: &SelectedProvider<'_>) -> Result<()> {
        std::fs::create_dir_all(&self.nix_cache_dir).with_context(|| {
            format!("creating Nix client cache {}", self.nix_cache_dir.display())
        })?;
        let mut cmd = command_from_path("nix-store")?;
        configure_realise_command(
            &mut cmd,
            provider.config_output,
            &self.substituters,
            &self.nix_cache_dir,
            self.verbose,
        );
        let output = cmd
            .output()
            .context("failed to spawn `nix-store --realise`")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "realising config output {} for '{}' failed: {}",
                provider.config_output,
                provider.package,
                stderr.trim()
            );
        }
        let dump = command_from_path("nix-store")?
            .args(["--dump", provider.config_output])
            .output()
            .with_context(|| {
                format!(
                    "dumping realised config output {} for verification",
                    provider.config_output
                )
            })?;
        if !dump.status.success() {
            anyhow::bail!(
                "verifying config output {} for '{}' failed: {}",
                provider.config_output,
                provider.package,
                String::from_utf8_lossy(&dump.stderr).trim()
            );
        }
        let actual_hash = format!("sha256:{:x}", Sha256::digest(&dump.stdout));
        let actual_size =
            u64::try_from(dump.stdout.len()).context("config output NAR too large")?;
        let expected =
            crate::registry::store::NarBytes::from_hash(provider.nar_hash, provider.nar_size)
                .with_context(|| {
                    format!(
                        "invalid authenticated config-output pin for '{}'",
                        provider.package
                    )
                })?;
        if !expected.matches(&actual_hash, actual_size) {
            anyhow::bail!(
                "realised config output {} for '{}' does not match authenticated NAR {}:{} \
                 (actual {}:{})",
                provider.config_output,
                provider.package,
                expected.nar_hash(),
                expected.size,
                actual_hash,
                actual_size
            );
        }
        Ok(())
    }
}

/// The on-host registry set exposed as a by-name [`ConfigModuleResolver`].
///
/// This is the production replacement for the removed registry-wide provides
/// index: it answers "does a package named `<root>` ship a config module?" by
/// reading each package's `config_module` block from `registry.toml`. It backs
/// both the [`SystemRoots`](super::SystemRoots) build (the installed set's
/// config modules) and the resolver's structural fallback for private
/// `{pkg}.*` roots.
pub struct RegistryConfigModules {
    registries: RegistrySet,
    installed: Vec<InstalledModulePin>,
    image_packages: BTreeMap<String, super::runtime::LocalRuntimePackage>,
}

#[derive(Debug, Clone)]
struct InstalledModulePin {
    package: String,
    version: String,
    runtime_output: String,
    module: crate::types::ConfigModuleMeta,
}

impl RegistryConfigModules {
    /// Wraps an already-loaded registry set.
    pub fn new(registries: RegistrySet) -> Self {
        Self {
            registries,
            installed: Vec::new(),
            image_packages: BTreeMap::new(),
        }
    }

    /// Returns the registry snapshot used for config-module lookup.
    ///
    /// Runtime output resolution must use this same snapshot so a registry
    /// update cannot split module evaluation from package activation.
    pub fn registries(&self) -> &RegistrySet {
        &self.registries
    }

    /// Returns packages authenticated by, and seeded from, the running image.
    pub fn image_packages(&self) -> &BTreeMap<String, super::runtime::LocalRuntimePackage> {
        &self.image_packages
    }

    /// Loads the on-host system-scope registry snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when system APM configuration or any configured
    /// registry cannot be loaded. Production evaluation must distinguish
    /// corrupt/untrusted registry state from a legitimate empty registry set.
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
        let mut installed = Vec::new();
        let mut image_packages = BTreeMap::new();
        for record in crate::profile::meta::list_meta(&profile)? {
            let Some(mut apm) = record.apm else {
                continue;
            };
            let is_image = record.pushed_by == "aos-image" && apm.registry == "seed";
            if is_image {
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
                if let Some(artifact) = &apm.expose_artifact {
                    require_immutable_image_path(&artifact.store_path, "expose artifact")?;
                }
            }
            let mut config_module = apm.config_module.clone();
            if is_image && let Some(module) = config_module.as_mut() {
                let lower = require_immutable_image_path(
                    &module.config_output.store_path,
                    "config-module output",
                )?;
                let (nar_hash, nar_size) = super::runtime::local_store_identity_at(
                    &module.config_output.store_path,
                    &lower,
                )?;
                module.config_output.nar_hash = nar_hash;
                module.config_output.nar_size = nar_size;
            }
            if let Some(module) = config_module.clone() {
                installed.push(InstalledModulePin {
                    package: apm.name.clone(),
                    version: apm.version.clone(),
                    runtime_output: record.store_path.clone(),
                    module,
                });
            }
            if is_image {
                image_packages.insert(
                    apm.name,
                    super::runtime::LocalRuntimePackage {
                        version: apm.version,
                        store_path: record.store_path,
                        expose: apm.expose,
                        expose_artifact: apm.expose_artifact,
                        config_module,
                        ability: apm.ability,
                        closure: std::cell::RefCell::new(None),
                    },
                );
            }
        }
        Ok(Self {
            registries,
            installed,
            image_packages,
        })
    }
}

fn resolved_registry_config_module<'a>(
    registry: &'a crate::registry::Registry,
    package: &'a crate::types::PackageMeta,
) -> Option<ResolvedConfigModule<'a>> {
    let module = package.config_module.as_ref()?;
    let root = crate::registry::store_path_hash(&module.config_output.store_path);
    Some(ResolvedConfigModule {
        registry: &registry.config.name,
        release_trust: registry.release_trust(),
        config_realization: registry
            .store_map()
            .realization_subset_hash(&[root.to_string()])
            .ok(),
        package: &package.name,
        version: &package.version,
        platform: &package.platform,
        runtime_output: &package.store_path,
        module,
    })
}

fn resolved_registry_ability_module(
    registry: &crate::registry::Registry,
    package: &crate::types::PackageMeta,
) -> Result<Option<ResolvedAbilityModule>> {
    ensure!(
        package.ability.is_none() || package.config_module.is_none(),
        "package {} carries both current ability and legacy config module metadata",
        package.name
    );
    let Some(module) = crate::ability_package::resolve_package_module(package)? else {
        return Ok(None);
    };
    let root = crate::registry::store_path_hash(&module.artifact.store_path);

    Ok(Some(ResolvedAbilityModule {
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
        module,
    }))
}

fn resolved_image_config_module<'a>(
    name: &'a str,
    package: &'a super::runtime::LocalRuntimePackage,
) -> Option<ResolvedConfigModule<'a>> {
    Some(ResolvedConfigModule {
        registry: "",
        release_trust: None,
        config_realization: None,
        package: name,
        version: &package.version,
        platform: "image",
        runtime_output: &package.store_path,
        module: package.config_module.as_ref()?,
    })
}

fn resolved_image_ability_module(
    name: &str,
    package: &super::runtime::LocalRuntimePackage,
) -> Result<Option<ResolvedAbilityModule>> {
    ensure!(
        package.ability.is_none() || package.config_module.is_none(),
        "image package {name} carries both current ability and legacy config module metadata"
    );
    let Some(ability) = package.ability.clone() else {
        return Ok(None);
    };
    let manifest = crate::ability_package::read_package_manifest(&ability.store_path)?;
    let decoded = crate::ability_package::decode_package_manifest(&manifest)?;
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
        config_module: package.config_module.clone(),
        documentation: None,
        ability: Some(ability),
        permissions: Default::default(),
        bpf_lsm: None,
        attestation: Default::default(),
    };
    let module = crate::ability_package::resolve_package_module(&package_meta)?;

    Ok(module.map(|module| ResolvedAbilityModule {
        registry: String::new(),
        release_trust: None,
        realization: None,
        package: name.to_string(),
        version: package.version.clone(),
        platform: "image".to_string(),
        runtime_output: package.store_path.clone(),
        module,
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

impl ConfigModuleResolver for RegistryConfigModules {
    fn ability_module(&self, package: &str) -> Result<Option<ResolvedAbilityModule>> {
        if let Ok(Some((registry, resolved))) =
            self.registries.resolve_for_config_evaluation(package)
        {
            return resolved_registry_ability_module(registry, resolved);
        }

        let (local_name, local) = match self.image_packages.get_key_value(package) {
            Some(value) => value,
            None => return Ok(None),
        };
        resolved_image_ability_module(local_name, local)
    }

    fn ability_module_exact(
        &self,
        package: &str,
        version: Option<&str>,
        runtime_output: Option<&str>,
    ) -> Result<Option<ResolvedAbilityModule>> {
        let exact =
            self.registries
                .resolve_exact_for_config_evaluation(package, version, runtime_output);
        match exact {
            Ok(Some((registry, resolved))) => {
                return resolved_registry_ability_module(registry, resolved);
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
        resolved_image_ability_module(local_name, local)
    }

    fn config_module(&self, package: &str) -> Option<ResolvedConfigModule<'_>> {
        if let Ok(Some((registry, resolved))) =
            self.registries.resolve_for_config_evaluation(package)
        {
            return resolved_registry_config_module(registry, resolved);
        }

        let (local_name, local) = self.image_packages.get_key_value(package)?;
        resolved_image_config_module(local_name, local)
    }

    fn config_module_exact(
        &self,
        package: &str,
        version: Option<&str>,
        runtime_output: Option<&str>,
    ) -> Option<ResolvedConfigModule<'_>> {
        let exact =
            self.registries
                .resolve_exact_for_config_evaluation(package, version, runtime_output);
        match exact {
            Ok(Some((registry, resolved))) => {
                return resolved_registry_config_module(registry, resolved);
            }
            Ok(None) | Err(_) => {}
        }
        if self
            .registries
            .resolve_for_config_evaluation(package)
            .is_ok_and(|resolved| resolved.is_some())
        {
            return None;
        }

        {
            let (local_name, local) = self.image_packages.get_key_value(package)?;
            if version.is_some_and(|want| want != local.version)
                || runtime_output.is_some_and(|want| want != local.store_path)
            {
                return None;
            }
            resolved_image_config_module(local_name, local)
        }
    }

    fn installed_config_modules(&self) -> Vec<ResolvedConfigModule<'_>> {
        self.installed
            .iter()
            .map(|pin| ResolvedConfigModule {
                registry: "",
                release_trust: None,
                config_realization: None,
                package: &pin.package,
                version: &pin.version,
                platform: "image",
                runtime_output: &pin.runtime_output,
                module: &pin.module,
            })
            .collect()
    }

    fn known_shared_roots(&self) -> BTreeSet<String> {
        let mut roots = self
            .registries
            .registries_before_config_evaluation_gap()
            .into_iter()
            .flat_map(|registry| registry.package_versions())
            .filter_map(|meta| meta.config_module.as_ref())
            .flat_map(|module| module.owns_roots.iter().map(|owned| owned.root.clone()))
            .collect::<BTreeSet<_>>();
        roots.extend(
            self.image_packages
                .values()
                .filter_map(|package| package.config_module.as_ref())
                .flat_map(|module| module.owns_roots.iter().map(|owned| owned.root.clone())),
        );
        roots
    }
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{ArtifactReference, LocalKey, ModuleLocator, RelativePath};
    use aos_ability_validate::PackageOutputSelector;
    use aos_contract::Sha256Digest;

    use super::*;
    use crate::config_eval::PackageOutputs;
    use crate::config_eval::ability_rounds::{SelectedAbilityBinding, SelectedProviderModule};
    use crate::types::{ApmMeta, ConfigModuleMeta, ConfigOutputMeta, ModuleAbiCompat};

    fn member(pkg: &str, config_output: Option<&str>) -> WorkingSetMember {
        WorkingSetMember {
            registry: None,
            release_trust: None,
            config_realization: None,
            package: pkg.to_string(),
            version: Some("1.0.0".to_string()),
            package_module: None,
            config_output: config_output.map(str::to_string),
            config_output_nar_hash: config_output.map(|_| "sha256:test".to_string()),
            module_abi_compat: Some(ModuleAbiCompat { min: 1, max: 2 }),
            outputs: super::super::PackageOutputs::default(),
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
            config_output: ConfigOutputMeta {
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

[versions.platforms.x86_64-linux.config_module.config_output]
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
        web.config_output_nar_hash = Some(format!("sha256:{}", "00".repeat(32)));
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
        web.package_module = Some(ModuleLocator {
            artifact: ArtifactReference {
                content: Sha256Digest::of_bytes(b"web module"),
                store_path: "/nix/store/00000000000000000000000000000000-web-module".to_string(),
                nar_hash: Sha256Digest::of_bytes(b"web module NAR"),
                closure: Sha256Digest::of_bytes(b"web module closure"),
            },
            path: RelativePath::new("abilities/module.nix").unwrap(),
        });

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
        web.package_module = Some(ModuleLocator {
            artifact: ArtifactReference {
                content: Sha256Digest::of_bytes(b"web module"),
                store_path: "/nix/store/00000000000000000000000000000000-web-module".to_string(),
                nar_hash: Sha256Digest::of_bytes(b"web module NAR"),
                closure: Sha256Digest::of_bytes(b"web module closure"),
            },
            path: RelativePath::new("module.nix").unwrap(),
        });

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
        web.config_output_nar_hash = Some(format!("sha256:{}", "00".repeat(32)));
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
    fn members_without_config_output_are_skipped() {
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
