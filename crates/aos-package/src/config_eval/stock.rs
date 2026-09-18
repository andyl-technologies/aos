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
use base64::Engine as _;

use super::classify::{EvalClass, KillReason, classify};
use super::system_roots::{PackageModuleResolver, ResolvedPackageModule};
use super::{EvalAttempt, NixEvaluator, WorkingSetMember};
use crate::platform::native_platform;
use crate::registry::RegistrySet;

/// The default on-host eval root that `aos-eval.service` prepares.
pub const DEFAULT_EVAL_ROOT: &str = "/run/aos-eval";

/// The default manifest path the converged eval emits.
pub const DEFAULT_MANIFEST_PATH: &str = "/run/aos/manifest.json";

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
    /// Selected immutable physical view for canonical package identities.
    store_view: Option<super::store_view::StoreViewLocator>,
}

impl StockNixEvaluator {
    /// Creates an evaluator over `root` (typically [`DEFAULT_EVAL_ROOT`]).
    pub fn new(root: impl Into<PathBuf>, verbose: u8) -> Self {
        Self {
            root: root.into(),
            verbose,
            store_view: None,
        }
    }

    /// Creates an evaluator whose direct reads use one selected store view.
    pub fn in_store_view(
        root: impl Into<PathBuf>,
        verbose: u8,
        store_view: super::store_view::StoreViewLocator,
    ) -> Self {
        Self {
            root: root.into(),
            verbose,
            store_view: Some(store_view),
        }
    }

    fn lock_store_path(&self, path: &Path, expected_nar_hash: Option<&str>) -> Result<String> {
        let input = match &self.store_view {
            Some(store_view) => {
                super::EvaluatorInput::in_store_view(path.to_path_buf(), store_view)?
            }
            None => super::EvaluatorInput::canonical(path.to_path_buf()),
        };
        self.lock_evaluator_input(&input, expected_nar_hash)
    }

    fn lock_evaluator_input(
        &self,
        input: &super::EvaluatorInput,
        expected_nar_hash: Option<&str>,
    ) -> Result<String> {
        let store = super::selected_eval_store_uri()?;
        locked_evaluator_input_in(input, expected_nar_hash, store.as_deref())
    }

    fn pure_eval_command(&self) -> Result<Command> {
        let store = super::selected_eval_store_uri()?;
        pure_eval_command_in(
            store.as_deref(),
            self.store_view
                .as_ref()
                .map(|view| view.read_root.as_path()),
            &self.root,
        )
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
            &nix_path(&attempt.base_lib.identity),
            &nix_path(&attempt.host_nix.identity),
        )
    }

    fn render_locked_entry_nix(&self, attempt: &EvalAttempt<'_>) -> Result<String> {
        let package_modules =
            render_package_module_list_with(attempt.working_set, true, |path, hash| {
                self.lock_store_path(path, hash)
            })?;
        let base = self.lock_evaluator_input(attempt.base_lib, None)?;
        let host = self.lock_evaluator_input(attempt.host_nix, None)?;
        self.render_entry_nix_with_inputs(attempt, &package_modules, &base, &host)
    }

    fn render_entry_nix_with_inputs(
        &self,
        attempt: &EvalAttempt<'_>,
        package_modules: &str,
        base: &str,
        host: &str,
    ) -> Result<String> {
        let runtime_modules = attempt
            .runtime_modules
            .iter()
            .map(|input| {
                self.lock_evaluator_input(input, None)
                    .map(|locked| format!("(import {locked})"))
            })
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        let facts_module = attempt
            .facts_json
            .map(|facts_json| -> Result<String> {
                let raw = std::fs::read(facts_json)
                    .with_context(|| format!("reading facts {}", facts_json.display()))?;
                let facts: aos_metadata::fetcher::Facts = serde_json::from_slice(&raw)
                    .with_context(|| format!("parsing facts {}", facts_json.display()))?;
                Ok(aos_metadata::facts_render::render_host_facts_nix(&facts))
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
            \x20 }};\n\
             in {{\n\
            \x20 optionWrites = system._optionWrites;\n\
            \x20 manifest = finalManifest;\n\
             }}\n",
            base = base,
            host = host,
            modules = package_modules,
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

        let mut cmd = self.pure_eval_command()?;

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
/// Constructs the scrubbed evaluator command for one exact selected store.
pub(super) fn pure_eval_command_in(
    store: Option<&OsStr>,
    read_root: Option<&Path>,
    eval_root: &Path,
) -> Result<Command> {
    let mut command = command_from_path("nix-instantiate")?;
    let nix_cache_home = std::env::var_os("XDG_CACHE_HOME");
    configure_pure_eval_command(
        &mut command,
        eval_root,
        nix_cache_home.as_deref(),
        store,
        read_root,
    )?;
    Ok(command)
}

fn configure_pure_eval_command(
    command: &mut Command,
    eval_root: &Path,
    nix_cache_home: Option<&OsStr>,
    store: Option<&OsStr>,
    read_root: Option<&Path>,
) -> Result<()> {
    let nix_cache_home = match nix_cache_home.filter(|path| !path.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => std::path::absolute(eval_root.join("nix-cache"))
            .context("resolving the evaluator's Nix cache directory")?,
    };

    command.env_clear();
    if let Some(store) = store {
        command.arg("--store").arg(store);
    }
    // Nix creates client cache state even for pure evaluation. The service
    // supplies a persistent cache; interactive evaluation instead uses its
    // writable staging root and never falls back to the image's read-only home.
    command.env("XDG_CACHE_HOME", nix_cache_home);
    let allowed_uris = read_root.map_or_else(
        || "path:/nix/store/".to_string(),
        |root| format!("path:/nix/store/ path:{}/", root.display()),
    );
    command
        .args(["--extra-experimental-features", "nix-command flakes"])
        .args(["--eval", "--strict", "--json", "--pure-eval"])
        .args(["--option", "restrict-eval", "true"])
        .args(["--option", "allow-import-from-derivation", "false"])
        .args(["--option", "allowed-uris", &allowed_uris]);

    Ok(())
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
#[cfg(test)]
fn render_package_module_list(members: &[WorkingSetMember], locked: bool) -> Result<String> {
    render_package_module_list_with(members, locked, locked_store_input)
}

/// Renders package modules with an injectable locked-input renderer.
///
/// Production evaluation injects the evaluator's selected store view. Keeping
/// the renderer injectable lets unit tests prove that every resolver-authenticated
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
        let module = member.contract.as_ref().and_then(|contract| {
            contract.document.package_module.as_ref().map(|locator| {
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
            // Runtime outputs are authenticated names, not evaluator inputs.
            // Keeping them as data prevents configuration evaluation from
            // realizing binary closures before the fixed point converges.
            let self_output = member
                .outputs
                .self_output
                .as_deref()
                .map_or_else(|| "null".to_string(), nix_string);
            let dependency_outputs = member
                .outputs
                .dependencies
                .iter()
                .map(|(package, output)| {
                    format!("{} = {};", nix_string(package), nix_string(output))
                })
                .collect::<Vec<_>>()
                .join(" ");
            let package_version = member.version.as_deref().with_context(|| {
                format!(
                    "working-set package {} has a module without an authenticated package version",
                    member.package
                )
            })?;
            items.push(format!(
                    "    (let configRoot = {config_root}; in {{ name = {}; version = {}; inherit configRoot; module = configRoot + {}; outputs = {{ self = {self_output}; dependencies = {{ {dependency_outputs} }}; }}; }})",
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

/// Renders one store path as a fixed, pure evaluator input.
#[cfg(test)]
pub(super) fn locked_store_input(path: &Path, expected_nar_hash: Option<&str>) -> Result<String> {
    let input = super::EvaluatorInput::canonical(path.to_path_buf());
    locked_evaluator_input_in(&input, expected_nar_hash, None)
}

#[cfg(test)]
pub(super) fn locked_evaluator_input(
    input: &super::EvaluatorInput,
    expected_nar_hash: Option<&str>,
) -> Result<String> {
    locked_evaluator_input_in(input, expected_nar_hash, None)
}

pub(super) fn locked_evaluator_input_in(
    input: &super::EvaluatorInput,
    expected_nar_hash: Option<&str>,
    eval_store: Option<&OsStr>,
) -> Result<String> {
    let (identity_root, suffix) = store_root_and_suffix(&input.identity)?;
    let read_root = input
        .read_path
        .ancestors()
        .nth(suffix.components().count())
        .context("evaluator read path is shorter than its canonical suffix")?;
    let nar_hash = expected_nar_hash.map_or_else(
        || super::retained_store_path_nar_hash_in(&identity_root, eval_store),
        |hash| Ok(hash.to_string()),
    )?;
    let nar_hash = sha256_sri(&nar_hash)?;
    let root = read_root
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
    store_view: Option<super::store_view::StoreViewLocator>,
}

impl RegistryPackageModules {
    /// Wraps an already-loaded registry set.
    pub fn new(registries: RegistrySet) -> Self {
        Self {
            registries,
            image_packages: BTreeMap::new(),
            store_view: None,
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

    /// Loads the on-host registry snapshot and checked immutable image selection.
    ///
    /// # Errors
    ///
    /// Returns an error when APM configuration, a registry, or image package
    /// static contract cannot be loaded and authenticated.
    pub fn load_system(store_view: &super::store_view::StoreViewLocator) -> Result<Self> {
        let scope = crate::types::ProfileScope::System;
        let config = crate::config::ApmConfig::load(scope)?;
        let enabled = config.enabled_registries();
        let registries = RegistrySet::load_for_config_evaluation(
            &config.cache_path(),
            &enabled,
            &native_platform(),
        )?;
        let image_packages = super::static_packages::load(store_view)
            .context("loading checked packages from the host static ability contract")?;
        Ok(Self {
            registries,
            image_packages,
            store_view: Some(store_view.clone()),
        })
    }
}

fn resolved_registry_package_module(
    registry: &crate::registry::Registry,
    package: &crate::types::PackageMeta,
) -> Result<Option<ResolvedPackageModule>> {
    let Some((document, interfaces)) = crate::package_contract::resolve_package_contract(package)?
    else {
        return Ok(None);
    };
    let Some(module) = document.package_module.as_ref() else {
        return Ok(None);
    };
    let root = crate::registry::store_path_hash(&module.artifact.store_path);
    let selector_outputs = selector_outputs(
        &package.name,
        package
            .contract
            .as_ref()
            .into_iter()
            .flat_map(|contract| contract.selectors.iter())
            .map(|selector| {
                (
                    selector.package.as_str(),
                    selector.output.as_str(),
                    selector.artifact.store_path.as_str(),
                )
            }),
    )?;

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
        selector_outputs,
        contract: super::ResolvedPackageContract {
            document,
            interfaces,
        },
    }))
}

fn resolved_image_package_module(
    name: &str,
    package: &super::runtime::LocalRuntimePackage,
    store_view: &super::store_view::StoreViewLocator,
) -> Result<Option<ResolvedPackageModule>> {
    let Some(origin) = package.contract.as_ref() else {
        return Ok(None);
    };
    let resolved = super::static_packages::resolve(
        name,
        &package.version,
        &package.platform,
        &package.store_path,
        &package.nar_hash,
        origin,
        store_view,
    )?;
    let selector_outputs = selector_outputs(
        name,
        resolved.resolved_outputs.iter().map(|output| {
            (
                output.package.as_str(),
                output.output.as_str(),
                output.artifact.store_path.as_str(),
            )
        }),
    )?;

    Ok(Some(ResolvedPackageModule {
        registry: String::new(),
        release_trust: None,
        realization: None,
        package: name.to_string(),
        version: package.version.clone(),
        platform: package.platform.clone(),
        runtime_output: package.store_path.clone(),
        selector_outputs,
        contract: super::ResolvedPackageContract {
            document: resolved.document,
            interfaces: resolved.interfaces,
        },
    }))
}

fn selector_outputs<'a>(
    owner: &str,
    outputs: impl Iterator<Item = (&'a str, &'a str, &'a str)>,
) -> Result<BTreeMap<String, String>> {
    #[derive(serde::Serialize)]
    struct Selector<'a> {
        output: &'a str,
        package: &'a str,
    }

    outputs
        .map(|(package, output, store_path)| {
            let package = if package == "self" { owner } else { package };
            let key = serde_json::to_string(&Selector { output, package })
                .context("serializing authenticated package output selector")?;
            Ok((key, store_path.to_string()))
        })
        .collect()
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
        resolved_image_package_module(
            local_name,
            local,
            self.store_view
                .as_ref()
                .context("image package resolver has no selected store view")?,
        )
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
        resolved_image_package_module(
            local_name,
            local,
            self.store_view
                .as_ref()
                .context("image package resolver has no selected store view")?,
        )
    }
}

#[cfg(test)]
mod tests {
    use aos_ability_model::document::PackageSubject;
    use aos_ability_model::{
        ArtifactReference, LocalKey, ModuleLocator, PackageDocument, PackageImplementation,
        RelativePath, RequiredFeature, VersionedDocument,
    };
    use aos_contract::Sha256Digest;

    use super::*;

    fn input(path: &str) -> super::super::EvaluatorInput {
        super::super::EvaluatorInput::canonical(path.into())
    }

    fn member(pkg: &str, module_artifact: Option<&str>) -> WorkingSetMember {
        let contract =
            module_artifact.map(|store_path| crate::config_eval::ResolvedPackageContract {
                document: ability_document(
                    pkg,
                    ModuleLocator {
                        artifact: ArtifactReference {
                            content: Sha256Digest::of_bytes(store_path.as_bytes()),
                            store_path: store_path.to_string(),
                            nar_hash: Sha256Digest::of_bytes(b"module NAR"),
                            closure: Sha256Digest::of_bytes(b"module closure"),
                        },
                        path: RelativePath::new("module.nix").unwrap(),
                    },
                ),
                interfaces: Vec::new(),
            });
        WorkingSetMember {
            registry: None,
            release_trust: None,
            config_realization: None,
            package: pkg.to_string(),
            version: Some("1.0.0".to_string()),
            contract,
            outputs: super::super::PackageOutputs::default(),
        }
    }

    fn ability_document(package: &str, package_module: ModuleLocator) -> PackageDocument {
        let artifact = package_module.artifact.clone();

        PackageDocument {
            schema: PackageDocument::SCHEMA.to_string(),
            required_features: vec![RequiredFeature::new("abilities-v1").unwrap()],
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

    #[test]
    fn entry_nix_injects_host_as_operator_module() {
        let evaluator = StockNixEvaluator::new("/run/aos-eval", 0);
        let working = vec![
            member("web", Some("/nix/store/hash-web-config")),
            member("firewall", Some("/nix/store/hash-firewall-config")),
        ];
        let host_nix = input("/nix/store/hash-host.nix");
        let base_lib = input("/nix/store/hash-aos-base-lib");
        let attempt = EvalAttempt {
            host_nix: &host_nix,
            runtime_modules: &[],
            base_lib: &base_lib,
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
        assert!(text.contains("manifest = finalManifest;"));
        assert!(!text.contains("mergeImageDefaults ="));
        assert!(text.contains("installAtBoot.config"), "{text}");
        assert!(
            !text.contains("credentials = baseLib.lib.recursiveUpdate"),
            "{text}"
        );
    }

    #[test]
    fn locked_entry_coerces_authenticated_config_roots_to_nix_paths() {
        let web = member(
            "web",
            Some("/nix/store/00000000000000000000000000000000-web-config"),
        );
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
    fn locked_input_keeps_identity_hashing_separate_from_physical_reads() {
        let input = super::super::EvaluatorInput {
            identity: PathBuf::from(
                "/nix/store/00000000000000000000000000000000-package/module.nix",
            ),
            read_path: PathBuf::from(
                "/immutable/store/00000000000000000000000000000000-package/module.nix",
            ),
        };

        let rendered = locked_evaluator_input(
            &input,
            Some(&Sha256Digest::of_bytes(b"package NAR").to_string()),
        )
        .expect("render selected store input");

        assert!(
            rendered
                .contains("path = \"/immutable/store/00000000000000000000000000000000-package\""),
            "{rendered}"
        );
        assert!(rendered.ends_with(" + \"/module.nix\")"), "{rendered}");
        assert!(!rendered.contains("path = \"/nix/store/"), "{rendered}");
    }

    #[test]
    fn locked_entry_imports_the_authenticated_package_module_and_version() {
        let mut web = member("web", None);
        web.contract = Some(crate::config_eval::ResolvedPackageContract {
            document: ability_document(
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
            ),
            interfaces: Vec::new(),
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
        assert!(rendered.contains("version = \"1.0.0\""));
        assert!(rendered.contains("module = configRoot + \"/abilities/module.nix\""));
    }

    #[test]
    fn locked_entry_preserves_runtime_outputs_as_strings() {
        let mut web = member(
            "web",
            Some("/nix/store/00000000000000000000000000000000-web-config"),
        );
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
            [PathBuf::from(
                "/nix/store/00000000000000000000000000000000-web-config"
            )]
        );
        assert!(text.contains("self = \"/nix/store/hash-web-runtime\""));
        assert!(text.contains("\"openssl\" = \"/nix/store/hash-openssl-runtime\";"));
        assert!(!text.contains("authorization"), "{text}");
    }

    #[test]
    fn entry_nix_empty_working_set_renders_empty_list() {
        let evaluator = StockNixEvaluator::new("/run/aos-eval", 0);
        let host_nix = input("/nix/store/hash-host.nix");
        let base_lib = input("/nix/store/hash-aos-base-lib");
        let attempt = EvalAttempt {
            host_nix: &host_nix,
            runtime_modules: &[],
            base_lib: &base_lib,
            facts_json: None,
            working_set: &[],
            iteration: 0,
        };
        let text = evaluator.render_entry_nix(&attempt).unwrap();
        assert!(text.contains("packageModules = [ ]"), "{text}");
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
        let host_nix = input("/nix/store/hash-host.nix");
        let base_lib = input("/nix/store/hash-aos-base-lib");
        let attempt = EvalAttempt {
            host_nix: &host_nix,
            runtime_modules: &[],
            base_lib: &base_lib,
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
        configure_pure_eval_command(
            &mut command,
            Path::new("/run/aos-eval"),
            Some(OsStr::new("/var/cache/aos/nix-eval")),
            None,
            None,
        )
        .unwrap();

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
}
