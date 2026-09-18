//! The on-host resolve/evaluate fixpoint driver.
//!
//! Package selection resolves the complete runtime closure and each selected
//! package's authenticated contract before Nix evaluates the module fixed
//! point. [`run_fixpoint`] evaluates that closed set once and preserves typed
//! Nix failures for the command boundary.
//!
//! # Module map
//!
//! - [`classify`] — the fragile string parse of stock-Nix throw strings into
//!   the [`EvalClass`] seam (build-spec §2).
//! - [`stock`] — the production [`NixEvaluator`] that renders `entry.nix`,
//!   shells out to `nix-instantiate --eval --strict --json --pure-eval
//!   --option restrict-eval true
//!   --option allow-import-from-derivation false` with an empty environment,
//!   and classifies the result. Builder-gated: it requires a real stock-nix,
//!   so it is unit-tested only for `entry.nix` rendering.
//!
//! # The seam
//!
//! The evaluator boundary is `eval(working_set, host_nix, base_lib) ->
//! Result<EvalClass>`. Contract authentication, package resolution, and
//! manifest construction remain outside it.
//!
//! # Failure-safe
//!
//! The fixpoint produces *only* a manifest and never activates. Every terminal
//! state — a [`FixpointError`] or non-convergence at the iteration cap — is a
//! clean no-op on the live system: no generation exists until a downstream
//! service consumes a returned manifest.

pub mod ability;
pub mod ability_activation;
pub mod ability_policy;
pub mod ability_policy_authority;
pub mod bound_handler;
mod bound_handler_store;
pub mod source_stage;
pub(crate) mod transaction_store;
pub use transaction_store::RetainedAbilityDiagnosticSource;
pub mod activation;
pub mod classify;
mod command_handler;
pub mod diagnostics;
pub mod dry_run;
mod handler_dispatch;
mod handler_process;
pub mod materialize;
mod native_activation;
mod protected_fs;
mod transaction_blob;
mod transaction_verification;
pub use native_activation::supported_native_ability_features;
pub(crate) use native_activation::{RetainedNativePreflightError, preflight_retained_manifest};
mod cancellation;
mod execution_observer;
pub(crate) mod provisioning_evaluator;
pub mod provisioning_evaluator_provider;
pub mod registry_snapshot_provider;
pub mod runtime;
pub mod runtime_modules;
pub mod service;
pub mod stage_handoff;
pub(crate) mod static_packages;
pub mod stock;
pub mod store_view;
pub mod system_roots;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use aos_ability_model::VersionedDocument;
use sha2::{Digest, Sha256};

pub use classify::{ConflictDef, EvalClass, KillReason, MissingOption, MissingOptionKind};
pub use system_roots::{PackageModuleResolver, ResolvedPackageContract, ResolvedPackageModule};

use crate::types::option_path_root;

/// Absolute ceiling on re-evals, so a pathological registry cannot make the
/// loop unbounded (build-spec §5).
pub const ITER_CAP_CEILING: u32 = 64;

// ---------------------------------------------------------------------------
// Working set
// ---------------------------------------------------------------------------

/// One package in the fixpoint working set.
///
/// The seed set is supplied by the caller from the host's desired packages;
/// package-contract documents are resolved before the module fixed point runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkingSetMember {
    /// Registry that authenticated this member's package module artifact.
    pub registry: Option<String>,
    /// Signed release identity for the extracted registry tree.
    pub release_trust: Option<crate::registry::ReleaseTrustReceipt>,
    /// Hash of the signed store subgraph rooted at this package module artifact.
    pub config_realization: Option<String>,
    /// Package name.
    pub package: String,
    /// Package version, when known.
    pub version: Option<String>,
    /// Resolved package contract, including its retained document source.
    pub contract: Option<ResolvedPackageContract>,
    /// Resolver-authenticated runtime outputs exposed to this module.
    pub outputs: PackageOutputs,
}

/// Runtime output strings a package module may consume during evaluation.
///
/// The resolver supplies only the package's own output and outputs of its
/// authenticated runtime dependencies. Modules never receive an ambient
/// package set or an unrestricted store-path lookup surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageOutputs {
    /// This package's exact runtime output.
    pub self_output: Option<String>,
    /// Direct authenticated dependency outputs keyed by package name.
    pub dependencies: BTreeMap<String, String>,
}

impl WorkingSetMember {
    /// Builds a bare seed member with no config-module metadata.
    pub fn seed(package: impl Into<String>) -> Self {
        Self {
            registry: None,
            release_trust: None,
            config_realization: None,
            package: package.into(),
            version: None,
            contract: None,
            outputs: PackageOutputs::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Inputs / outputs
// ---------------------------------------------------------------------------

/// Immutable inputs for one `switch` (build-spec §1).
#[derive(Debug, Clone)]
pub struct FixpointInputs {
    /// The delivered leaf `host.nix` path.
    pub host_nix: EvaluatorInput,
    /// Ordered, generation-pinned runtime operator module entrypoints.
    pub runtime_modules: Vec<EvaluatorInput>,
    /// The in-image, ABI-pinned module library.
    pub base_lib: EvaluatorInput,
    /// Optional normalized metadata facts consumed as a typed Nix module.
    pub facts_json: Option<PathBuf>,
    /// Packages explicitly installed (`desired.toml`): the starting working set.
    pub seed_set: Vec<WorkingSetMember>,
}

/// Keeps one canonical store identity separate from its selected readable path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatorInput {
    /// Canonical package-store identity used by Nix store operations.
    pub identity: PathBuf,
    /// Physical immutable path used only for direct byte reads.
    pub read_path: PathBuf,
}

impl EvaluatorInput {
    pub(crate) fn canonical(path: PathBuf) -> Self {
        Self {
            read_path: path.clone(),
            identity: path,
        }
    }

    fn in_store_view(identity: PathBuf, store_view: &store_view::StoreViewLocator) -> Result<Self> {
        let read_path = store_view.read_path(&identity)?;
        Ok(Self {
            identity,
            read_path,
        })
    }
}

/// One step of the causal chain, recorded for the non-convergence dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IterRecord {
    /// 0-based iteration at which the provider was added.
    pub iter: u32,
    /// The missing option that triggered the fetch (full leaf or root).
    pub missing_path: String,
    /// Whether the trigger was a write (Case A) or a read (Case B).
    pub kind: MissingOptionKind,
    /// The provider package added to the working set.
    pub provider_added: String,
    /// The reader/writer locus, when stock Nix reported it.
    pub read_by: Option<String>,
}

/// A converged fixpoint: the rendered manifest plus its provenance.
#[derive(Debug, Clone)]
pub struct FixpointOutcome {
    /// The JSON manifest text the final eval produced.
    pub manifest: String,
    /// The converged working set (seed plus every fetched provider).
    pub working_set: Vec<WorkingSetMember>,
    /// The causal chain of provider additions.
    pub trace: Vec<IterRecord>,
    /// Number of re-eval iterations performed.
    pub iterations: u32,
}

/// Operator-visible information produced by a successful configuration eval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvalCommandReport {
    /// Causal provider additions made while resolving the module fixpoint.
    pub resolution_trace: Vec<String>,
}

// ---------------------------------------------------------------------------
// Terminal errors
// ---------------------------------------------------------------------------

/// A terminal fixpoint failure. Every variant is a clean no-op on the live
/// system (build-spec §1).
#[derive(Debug)]
pub enum FixpointError {
    /// A missing option whose root no installed package owns and whose name no
    /// registry package matches.
    NoProvider {
        /// The unresolved root segment.
        path: String,
        /// The reader/writer locus, when known.
        read_by: Option<String>,
    },
    /// A *declared* option was left undefined with no default (`:744`).
    UndefinedOption {
        /// The declared-but-unset option path.
        path: String,
        /// The defining locus, when reported.
        file: Option<String>,
    },
    /// A scalar/type conflict between definitions.
    Conflict {
        /// Every conflicting definition stock Nix listed.
        defs: Vec<ConflictDef>,
    },
    /// A forced assertion failed.
    AssertionFailed {
        /// The assertion message as authored.
        msg: String,
        /// The defining locus, when reported.
        file: Option<String>,
    },
    /// The eval subprocess was OOM-/timeout-killed by its transient scope.
    EvalKilled {
        /// Why the subprocess was killed.
        reason: KillReason,
    },
    /// An opaque Nix failure that matched no known pattern.
    EvalError {
        /// The raw stderr, preserved for the operator.
        stderr: String,
    },
    /// Fetching a selected provider's `config` output failed terminally.
    Fetch {
        /// The provider whose fetch failed.
        provider: String,
        /// The underlying fetch error.
        source: anyhow::Error,
    },
    /// The loop did not converge within the iteration cap.
    NonConvergence {
        /// The causal chain, for the operator dump.
        trace: Vec<IterRecord>,
        /// The cap that was hit.
        iterations: u32,
    },
}

impl std::fmt::Display for FixpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FixpointError::NoProvider { path, read_by } => {
                write!(
                    f,
                    "no installed package owns root '{path}' and no package named '{path}' exists in the registry"
                )?;
                if let Some(loc) = read_by {
                    write!(f, " (read by {loc})")?;
                }
                Ok(())
            }
            FixpointError::UndefinedOption { path, file } => {
                write!(f, "the option '{path}' is declared but left undefined")?;
                if let Some(file) = file {
                    write!(f, " (at {file})")?;
                }
                Ok(())
            }
            FixpointError::Conflict { defs } => {
                write!(f, "conflicting definitions:")?;
                for def in defs {
                    let value = def.value.as_deref().unwrap_or("?");
                    let file = def.file.as_deref().unwrap_or("?");
                    write!(f, "\n  - '{value}' (defined in {file})")?;
                }
                Ok(())
            }
            FixpointError::AssertionFailed { msg, file } => {
                write!(f, "assertion failed: {msg}")?;
                if let Some(file) = file {
                    write!(f, " (at {file})")?;
                }
                Ok(())
            }
            FixpointError::EvalKilled { reason } => write!(f, "config eval killed: {reason}"),
            FixpointError::EvalError { stderr } => write!(f, "config eval failed:\n{stderr}"),
            FixpointError::Fetch { provider, source } => {
                write!(
                    f,
                    "fetching package module artifact for '{provider}' failed: {source}"
                )
            }
            FixpointError::NonConvergence { trace, iterations } => {
                write!(f, "{}", render_trace(trace, *iterations))
            }
        }
    }
}

impl std::error::Error for FixpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FixpointError::Fetch { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// Render the build-spec §5 non-convergence dump from the causal chain.
fn render_trace(trace: &[IterRecord], iterations: u32) -> String {
    let mut out = format!("config eval did not converge after {iterations} iterations:\n");
    for record in trace {
        let loc = record
            .read_by
            .as_deref()
            .map(|l| format!(" [{l}]"))
            .unwrap_or_default();
        out.push_str(&format!(
            "  iter {}: {} '{}' ({}) -> +{}{}\n",
            record.iter,
            record.kind.label(),
            record.missing_path,
            record.kind.label(),
            record.provider_added,
            loc,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Injected collaborators
// ---------------------------------------------------------------------------

/// One eval attempt's inputs, handed to a [`NixEvaluator`].
#[derive(Debug)]
pub struct EvalAttempt<'a> {
    /// The trusted leaf `host.nix`, passed as an operator-provenance module.
    pub host_nix: &'a EvaluatorInput,
    /// Ordered direct runtime operator module entrypoints.
    pub runtime_modules: &'a [EvaluatorInput],
    /// The in-image module library.
    pub base_lib: &'a EvaluatorInput,
    /// Optional normalized metadata facts file.
    pub facts_json: Option<&'a Path>,
    /// The current working set rendered into `entry.nix`.
    pub working_set: &'a [WorkingSetMember],
    /// 0-based iteration counter.
    pub iteration: u32,
}

/// The evaluator seam: render the working set and classify the eval result.
///
/// The production implementation ([`stock::StockNixEvaluator`]) renders
/// `entry.nix`, runs a cold stock-Nix subprocess, and parses stderr via
/// [`classify`]. Tests inject a scripted mock at this boundary.
pub trait NixEvaluator {
    /// Evaluate `attempt` and return its classified outcome.
    ///
    /// # Errors
    ///
    /// Returns an error only when the evaluator cannot be *driven* at all (e.g.
    /// the subprocess could not be spawned). Eval-level failures (missing
    /// options, conflicts, kills) are reported in-band as [`EvalClass`].
    fn evaluate(&self, attempt: &EvalAttempt<'_>) -> Result<EvalClass>;
}

// ---------------------------------------------------------------------------
// The fixpoint
// ---------------------------------------------------------------------------

/// Drive `evalModules` to a complete configuration (build-spec §1).
///
/// Package selection and package-contract resolution complete before this
/// function runs. The full selected module set is evaluated once; an unresolved
/// option is therefore a terminal missing-provider error.
///
/// # Errors
///
/// Returns a [`FixpointError`] for every terminal evaluator state. Every
/// terminal state is a clean no-op: no manifest is emitted, so nothing
/// downstream activates.
pub fn run_fixpoint<E: NixEvaluator>(
    inputs: &FixpointInputs,
    evaluator: &E,
) -> std::result::Result<FixpointOutcome, FixpointError> {
    let working_set = inputs.seed_set.clone();
    let attempt = EvalAttempt {
        host_nix: &inputs.host_nix,
        runtime_modules: &inputs.runtime_modules,
        base_lib: &inputs.base_lib,
        facts_json: inputs.facts_json.as_deref(),
        working_set: &working_set,
        iteration: 0,
    };
    let class = evaluator
        .evaluate(&attempt)
        .map_err(|error| FixpointError::EvalError {
            stderr: format!("{error:#}"),
        })?;

    match class {
        EvalClass::Manifest(manifest) => Ok(FixpointOutcome {
            manifest,
            working_set,
            trace: Vec::new(),
            iterations: 0,
        }),
        EvalClass::Missing(missing) => {
            let first = missing.first();
            Err(FixpointError::NoProvider {
                path: first
                    .map(|missing| option_path_root(&missing.path).to_string())
                    .unwrap_or_default(),
                read_by: first.and_then(|missing| missing.read_by.clone()),
            })
        }
        EvalClass::UndefinedOption { path, file } => {
            Err(FixpointError::UndefinedOption { path, file })
        }
        EvalClass::Conflict { defs } => Err(FixpointError::Conflict { defs }),
        EvalClass::Assertion { msg, file } => Err(FixpointError::AssertionFailed { msg, file }),
        EvalClass::Killed(reason) => Err(FixpointError::EvalKilled { reason }),
        EvalClass::Other { stderr } => Err(FixpointError::EvalError { stderr }),
    }
}

/// Resolves every selected seed's authenticated module before the first full evaluation.
///
/// Seed package modules may define defaults and assertions without first
/// triggering a missing-option error. Leaving those modules unloaded would
/// therefore produce a false fixpoint. This preflight pins their registry
/// identity, ABI-gates them, fetches the package module artifact, and makes iteration
/// zero evaluate the complete selected module set.
fn hydrate_seed_modules<R>(
    seeds: &mut [WorkingSetMember],
    resolver: &R,
) -> std::result::Result<(), FixpointError>
where
    R: PackageModuleResolver,
{
    for seed in seeds {
        let Some(resolved) = resolver
            .package_module_exact(
                &seed.package,
                seed.version.as_deref(),
                seed.outputs.self_output.as_deref(),
            )
            .map_err(|source| FixpointError::Fetch {
                provider: seed.package.clone(),
                source,
            })?
        else {
            continue;
        };
        seed.registry = (!resolved.registry.is_empty()).then_some(resolved.registry);
        seed.release_trust = resolved.release_trust;
        seed.config_realization = resolved.realization;
        seed.version = Some(resolved.version);
        seed.outputs.self_output = Some(resolved.runtime_output);
        seed.outputs.dependencies = resolved.selector_outputs;
        seed.contract = Some(resolved.contract);
    }
    Ok(())
}

/// Installs the exact runtime-output map authenticated by one resolution.
fn assign_runtime_outputs(members: &mut [WorkingSetMember], runtime: &runtime::RuntimeResolution) {
    for member in members {
        if let Some(package) = runtime.packages.get(&member.package) {
            member.outputs.self_output = Some(package.store_path.clone());
        }
    }
}

// Private runtime driver (`aos-package-runtime __eval`)
// ---------------------------------------------------------------------------

/// Parameters for the on-host config-eval command.
#[derive(Debug, Clone)]
pub struct EvalCommand {
    /// Selected immutable view of the running image's package store.
    pub store_view: store_view::StoreViewLocator,
    /// The delivered leaf `host.nix` path.
    pub host_nix: PathBuf,
    /// Ordered runtime operator module entrypoints from one immutable set.
    pub runtime_modules: Vec<EvaluatorInput>,
    /// Immutable runtime source root, including when the ordered set is empty.
    pub runtime_module_root: Option<PathBuf>,
    /// Active generation sampled before evaluation for activation CAS.
    pub expected_current_generation: Option<u32>,
    /// The in-image module library store path.
    pub base_lib: PathBuf,
    /// Optional normalized metadata facts file.
    pub facts_json: Option<PathBuf>,
    /// Optional `desired.toml` whose `packages` seed the working set.
    pub desired: Option<PathBuf>,
    /// The running image's base-lib ABI.
    pub module_abi: u32,
    /// Where to write the converged manifest (only on success).
    pub out: PathBuf,
    /// The eval root that holds `entry.nix` (`-I` search path).
    pub eval_root: PathBuf,
    /// Verbosity forwarded to `nix`.
    pub verbose: u8,
    /// Operator trust-anchor directories holding
    /// `trusted-config-keys.d/<op>.pub`.
    pub trusted_config_keys_dirs: Vec<PathBuf>,

    /// Previously validated platform-host and facts evidence retained verbatim.
    pub retained_host_inputs: Option<RetainedHostInputs>,

    /// Treats `host_nix` as the image-authored empty fallback module.
    ///
    /// This is used only by the boot service when neither current metadata nor
    /// the durable last-known-good input supplies an operator module. It keeps
    /// a no-input first boot and image transition on the normal transactional
    /// config-generation path without mislabelling the empty module as
    /// platform-authored input.
    pub image_default_host: bool,

    /// Binds provisioning evaluation to one protected synchronized authority.
    pub(crate) registry_snapshot: Option<registry_snapshot_provider::SynchronizedSnapshot>,

    /// Require the delivered `host.nix` to carry a valid detached signature.
    /// The default trusts the deployment platform that supplied instance
    /// metadata. Signed mode is fail-closed when anchors or signatures are
    /// missing or invalid.
    pub require_signed_host_nix: bool,
}

/// Validated host and facts identity carried forward without reclassifying trust.
#[derive(Debug, Clone)]
pub struct RetainedHostInputs {
    /// Exact retained host identity and authorization evidence.
    pub host_nix: materialize::HostNixInput,
    /// Exact retained instance-facts identity.
    pub instance_facts: materialize::InstanceFactsInput,
}

#[derive(Debug, Clone)]
struct PreparedEvaluatorInputs {
    host_nix: EvaluatorInput,
    runtime_modules: Vec<EvaluatorInput>,
    base_lib: EvaluatorInput,
    facts_json: Option<PathBuf>,
}

fn prepare_evaluator_inputs(cmd: &EvalCommand) -> Result<PreparedEvaluatorInputs> {
    let host_nix = match &cmd.retained_host_inputs {
        Some(retained) => EvaluatorInput::in_store_view(
            PathBuf::from(&retained.host_nix.store_path),
            &cmd.store_view,
        )?,
        None => EvaluatorInput::canonical(
            add_fixed_eval_host_source(&cmd.host_nix, &cmd.eval_root)
                .context("pinning authorized host.nix before pure evaluation")?,
        ),
    };
    let base_lib = EvaluatorInput::in_store_view(cmd.base_lib.clone(), &cmd.store_view)?;
    let runtime_modules = cmd.runtime_modules.clone();
    let facts_json = match (&cmd.retained_host_inputs, &cmd.facts_json) {
        (Some(retained), Some(_)) => Some(
            cmd.store_view
                .read_path(Path::new(&retained.instance_facts.store_path))?,
        ),
        (_, path) => path.clone(),
    };

    Ok(PreparedEvaluatorInputs {
        host_nix,
        runtime_modules,
        base_lib,
        facts_json,
    })
}

fn enforce_host_nix_trust_policy(cmd: &EvalCommand) -> Result<()> {
    if cmd.image_default_host {
        let bytes = std::fs::read(&cmd.host_nix).with_context(|| {
            format!(
                "reading image-default host input {}",
                cmd.host_nix.display()
            )
        })?;
        let text = std::str::from_utf8(&bytes).context("image-default host input is not UTF-8")?;
        anyhow::ensure!(
            text.trim() == "{}",
            "image-default host input must be the empty Nix module"
        );
        eprintln!("using image-authored empty host configuration");
        return Ok(());
    }

    if !cmd.require_signed_host_nix {
        eprintln!("using host.nix from the configured trusted source");
        return Ok(());
    }

    match crate::config_trust::authenticate_host_nix_file(
        &cmd.host_nix,
        &cmd.trusted_config_keys_dirs,
    ) {
        Ok(trust) => {
            eprintln!(
                "host.nix authenticated (operator '{}', key {})",
                trust.operator_id, trust.operator_key
            );
            Ok(())
        }
        Err(err) => {
            anyhow::bail!("host.nix failed signature verification: {err}; no manifest emitted")
        }
    }
}

/// Runs the on-host fixpoint with the production stock Nix evaluator and fetcher.
///
/// Loads the on-host registries (as the by-name [`PackageModuleResolver`]) and
/// seed set from disk, drives [`run_fixpoint`], and — **only on convergence** —
/// writes the manifest to [`EvalCommand::out`]. Any terminal failure prints a
/// legible diagnostic and returns an error *without* writing a manifest, so the
/// downstream `ConditionPathExists` guard makes the install step a no-op and
/// leaves the active configuration unchanged.
///
/// The per-system [`SystemRoots`] map is derived inside [`run_fixpoint`] from the
/// authenticated installed/selected module set; nothing registry-wide is
/// published or fetched. Registry configuration errors are terminal rather
/// than being reinterpreted as an empty package universe.
///
/// # Errors
///
/// Returns an error when the desired file cannot be read or parsed, when the
/// fixpoint reaches a terminal state, or when the manifest cannot be written.
/// The private runtime caller maps this to a non-zero exit;
/// the service treats it as best-effort.
pub fn run_eval_command(cmd: &EvalCommand) -> Result<()> {
    run_eval_command_with_report(cmd).map(|_| ())
}

/// Runs the production evaluator and returns its resolution trace.
///
/// This is the reporting variant used by `apm switch`: the hidden boot-time
/// evaluator deliberately discards the report, while dry-run must expose the
/// exact provider-addition trace produced by the same transaction.
///
/// # Errors
///
/// Returns the same failures as [`run_eval_command`]. No report or manifest is
/// produced unless the fixpoint converges and the manifest is validated.
pub(crate) fn run_eval_command_with_report(cmd: &EvalCommand) -> Result<EvalCommandReport> {
    cmd.store_view
        .validate()
        .context("validating the selected package-store read view")?;

    // A failed re-evaluation must never leave an older manifest looking like
    // fresh output to ConditionPathExists or checked activation preflight.
    remove_if_present(&cmd.out)?;
    let graph_out = cmd.out.with_file_name("graph.json");
    remove_if_present(&graph_out)?;

    // The default path trusts configuration delivered by the deployment
    // platform's metadata channel. Signed mode adds an independent trust root
    // for environments where that transport is not trusted. Authentication
    // runs before the fixpoint so failures cannot emit a manifest.
    enforce_host_nix_trust_policy(cmd)?;

    // Direct reads use the selected immutable view while Nix operations retain
    // canonical store identities. Keeping both paths explicit prevents a
    // physical boot-store alias from becoming a second package identity.
    let prepared = prepare_evaluator_inputs(cmd)?;

    // The by-name config-module resolver is the on-host registry set: it reads
    // each package's authenticated package module. This replaces
    // the removed registry-wide provides index. When apm config is
    // unavailable or corrupt, fail closed before selecting or fetching any
    // package. Off-host callers inject an explicit resolver instead.
    let resolver = stock::RegistryPackageModules::load_system(&cmd.store_view)
        .context("loading authenticated system registry snapshot for config evaluation")?;
    if let Some(snapshot) = &cmd.registry_snapshot {
        validate_registry_authority(&resolver, snapshot, &cmd.store_view)?;
    }

    let mut seed_set = load_host_selection(cmd, &prepared)?;
    for legacy_seed in load_seed_set(cmd.desired.as_deref())? {
        if !seed_set
            .iter()
            .any(|member| member.package == legacy_seed.package)
        {
            seed_set.push(legacy_seed);
        }
    }

    let evaluator = stock::StockNixEvaluator::in_store_view(
        cmd.eval_root.clone(),
        cmd.verbose,
        cmd.store_view.clone(),
    );
    // Resolve the selected names before evaluation. This both pins the exact
    // runtime outputs and adds signed package-level dependencies (`requires`
    // and capability providers) to the module working set.
    let initially_selected: Vec<String> = seed_set
        .iter()
        .map(|member| member.package.clone())
        .collect();
    let mut runtime = runtime::resolve_runtime_with_local(
        resolver.registries(),
        resolver.image_packages(),
        &initially_selected,
        &cmd.store_view,
    )
    .context("resolving selected runtime package closures")?;
    for package in runtime.packages.keys() {
        if !seed_set.iter().any(|member| &member.package == package) {
            seed_set.push(WorkingSetMember::seed(package.clone()));
        }
    }
    hydrate_seed_modules(&mut seed_set, &resolver).map_err(eval_command_failure)?;
    assign_runtime_outputs(&mut seed_set, &runtime);

    // A config provider discovered by the inner option fixpoint can itself
    // declare package-level runtime dependencies. Close that outer set too,
    // re-running evaluation only when resolution added a package. Both loops
    // are finite and share the same hard ceiling.
    let mut outer_iterations = 0;
    let outcome = loop {
        if outer_iterations >= ITER_CAP_CEILING {
            return Err(eval_command_failure(FixpointError::NonConvergence {
                trace: Vec::new(),
                iterations: ITER_CAP_CEILING,
            }));
        }
        let inputs = FixpointInputs {
            host_nix: prepared.host_nix.clone(),
            runtime_modules: prepared.runtime_modules.clone(),
            base_lib: prepared.base_lib.clone(),
            facts_json: prepared.facts_json.clone().filter(|path| path.is_file()),
            seed_set,
        };
        let candidate = run_fixpoint(&inputs, &evaluator).map_err(eval_command_failure)?;
        let selected: Vec<String> = candidate
            .working_set
            .iter()
            .map(|member| member.package.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        runtime = runtime::resolve_runtime_with_local(
            resolver.registries(),
            resolver.image_packages(),
            &selected,
            &cmd.store_view,
        )
        .context("resolving converged runtime package closures")?;
        let mut next = candidate.working_set.clone();
        for package in runtime.packages.keys() {
            if !next.iter().any(|member| &member.package == package) {
                next.push(WorkingSetMember::seed(package.clone()));
            }
        }
        assign_runtime_outputs(&mut next, &runtime);
        if next == candidate.working_set {
            break candidate;
        }
        hydrate_seed_modules(&mut next, &resolver).map_err(eval_command_failure)?;
        seed_set = next;
        outer_iterations += 1;
    };

    let manifest = enrich_manifest(cmd, &prepared, &outcome, &runtime)?;
    if let Some(parent) = cmd.out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let encoded = serde_json::to_vec(&manifest).context("serializing config manifest")?;
    std::fs::write(&cmd.out, encoded)
        .with_context(|| format!("writing manifest {}", cmd.out.display()))?;
    let graph =
        serde_json::to_vec(&manifest.graph).context("serializing config dependency graph")?;
    std::fs::write(&graph_out, graph)
        .with_context(|| format!("writing graph {}", graph_out.display()))?;
    eprintln!(
        "config eval converged after {} iteration(s); manifest written to {}",
        outcome.iterations,
        cmd.out.display()
    );
    Ok(EvalCommandReport {
        resolution_trace: outcome.trace.iter().map(render_iter_record).collect(),
    })
}

fn validate_registry_authority(
    resolver: &stock::RegistryPackageModules,
    snapshot: &registry_snapshot_provider::SynchronizedSnapshot,
    store_view: &store_view::StoreViewLocator,
) -> Result<()> {
    registry_snapshot_provider::validate_synchronized_snapshot(snapshot)?;
    let releases = resolver
        .registries()
        .registries()
        .iter()
        .map(|registry| {
            let receipt = registry
                .release_trust()
                .context("configuration registry has no authenticated release receipt")?;
            Ok(registry_snapshot_provider::ReleaseIdentity {
                registry: receipt.registry.clone(),
                release_tag: receipt.release_tag.clone(),
                commit: receipt.commit.clone(),
                tag_signer_key: receipt.tag_signer_key.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let releases = registry_snapshot_provider::canonical_releases(releases)?;
    anyhow::ensure!(
        releases == snapshot.releases,
        "configuration registry authority differs from the synchronized snapshot"
    );
    let (static_contract, _) = static_packages::checked_host_selection(store_view)
        .context("revalidating the synchronized immutable package contract")?;
    anyhow::ensure!(
        static_contract == snapshot.static_contract,
        "immutable package authority differs from the synchronized snapshot"
    );
    Ok(())
}

/// Renders one provider-discovery step for the dry-run JSON contract.
fn render_iter_record(record: &IterRecord) -> String {
    let locus = record
        .read_by
        .as_deref()
        .map(|value| format!(" (read by {value})"))
        .unwrap_or_default();
    format!(
        "iter {}: {} '{}' -> +{}{}",
        record.iter,
        record.kind.label(),
        record.missing_path,
        record.provider_added,
        locus
    )
}

fn eval_command_failure(error: FixpointError) -> anyhow::Error {
    anyhow::Error::new(diagnostics::EvalCommandFailure::from_fixpoint(&error))
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing stale {}", path.display())),
    }
}

fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Reads and cross-checks the options-only ABI identity shipped by a base lib.
fn read_base_lib_abi_hash(base_lib: &Path, expected_abi: u32) -> Result<String> {
    let recorded_abi = std::fs::read_to_string(base_lib.join("module-abi"))
        .with_context(|| format!("reading {}/module-abi", base_lib.display()))?;
    let recorded_abi = recorded_abi
        .trim()
        .parse::<u32>()
        .with_context(|| format!("parsing module ABI from {}/module-abi", base_lib.display()))?;
    if recorded_abi != expected_abi {
        anyhow::bail!(
            "base library {} records module ABI {recorded_abi}, but evaluation requested {expected_abi}",
            base_lib.display()
        );
    }
    let abi_hash = std::fs::read_to_string(base_lib.join("abi-hash"))
        .with_context(|| format!("reading {}/abi-hash", base_lib.display()))?;
    let abi_hash = abi_hash.trim().to_string();
    materialize::validate_content_sha256(&abi_hash)
        .context("base library contains an invalid ABI hash")?;
    let schema_bytes = std::fs::read(base_lib.join("option-schema.json"))
        .with_context(|| format!("reading {}/option-schema.json", base_lib.display()))?;
    let schema = serde_json::from_slice::<serde_json::Value>(&schema_bytes)
        .with_context(|| format!("parsing {}/option-schema.json", base_lib.display()))?;
    if !schema.is_array() {
        anyhow::bail!("base library option-schema.json is not an array");
    }
    let expected_hash = crate::canonical_json_digest(&serde_json::json!({
        "abi": recorded_abi,
        "schema": schema,
    }))?;
    if abi_hash != expected_hash {
        anyhow::bail!(
            "base library {} ABI hash does not match its module ABI and option schema",
            base_lib.display()
        );
    }
    Ok(abi_hash)
}

/// Derives the evaluator identity from its Nix store-path component.
fn evaluator_store_hash(executable: &Path) -> Result<String> {
    let root = evaluator_store_root(executable)?;
    let basename = root
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .context("evaluator store path is not UTF-8")?;
    let encoded = basename
        .split_once('-')
        .map(|(hash, _)| hash)
        .filter(|hash| hash.len() == 32)
        .context("evaluator store path has no 32-character hash component")?;
    let decoded = aos_core::nar::cache::decode_nix_base32(encoded)
        .context("evaluator store path contains an invalid Nix base32 hash")?;
    if decoded.len() != 20 {
        anyhow::bail!(
            "evaluator store-path hash decoded to {} bytes instead of 20",
            decoded.len()
        );
    }
    Ok(format!("sha256:{}", hex::encode(decoded)))
}

/// Returns the canonical store root containing the evaluator executable.
fn evaluator_store_root(executable: &Path) -> Result<&Path> {
    let store_dir = Path::new("/nix/store");
    executable
        .ancestors()
        .find(|candidate| candidate.parent() == Some(store_dir))
        .with_context(|| {
            format!(
                "evaluator {} is not contained in a canonical /nix/store path",
                executable.display()
            )
        })
}

/// Hashes the authenticated package-module-artifact set independently of evaluator order.
fn package_module_inputs(
    working_set: &[WorkingSetMember],
) -> Result<Vec<crate::types::PackageModule>> {
    let mut modules = Vec::new();
    for member in working_set {
        let Some(contract) = member.contract.as_ref() else {
            continue;
        };
        let document = &contract.document;
        let Some(locator) = document.package_module.as_ref() else {
            continue;
        };
        anyhow::ensure!(
            document.package.name.as_str() == member.package,
            "package document subject disagrees with working-set identity"
        );
        modules.push(crate::types::PackageModule {
            package: member.package.clone(),
            document_digest: document.content_digest()?.to_string(),
            store_path: locator.artifact.store_path.clone(),
            nar_hash: locator.artifact.nar_hash.to_string(),
            entrypoint: locator.path.as_str().to_string(),
            origin: if member.registry.is_some() {
                crate::types::PackageModuleOrigin::Registry
            } else {
                crate::types::PackageModuleOrigin::Image
            },
        });
    }
    modules.sort_by(|left, right| left.package.cmp(&right.package));
    Ok(modules)
}

fn package_module_release_identity(
    working_set: &[WorkingSetMember],
) -> Result<(
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
)> {
    let modules = working_set
        .iter()
        .filter(|member| {
            member
                .contract
                .as_ref()
                .is_some_and(|contract| contract.document.package_module.is_some())
                && member.registry.is_some()
        })
        .collect::<Vec<_>>();
    if modules.is_empty() {
        return Ok((None, None, None, None));
    }
    let first = modules[0];
    let registry = first
        .registry
        .as_deref()
        .context("package module has no authenticated source registry")?;
    let receipt = first
        .release_trust
        .as_ref()
        .context("package module registry has no verified signed-release receipt")?;
    if receipt.registry != registry {
        anyhow::bail!("package module registry disagrees with its signed-release receipt");
    }
    let mut realization_members = Vec::with_capacity(modules.len());
    for member in modules {
        let member_registry = member
            .registry
            .as_deref()
            .context("package module has no authenticated source registry")?;
        let member_receipt = member
            .release_trust
            .as_ref()
            .context("package module registry has no verified signed-release receipt")?;
        if member_registry != registry || member_receipt != receipt {
            anyhow::bail!("one configuration generation cannot mix signed registry releases");
        }
        realization_members.push(serde_json::json!([
            member.package,
            member
                .config_realization
                .as_deref()
                .context("package module has no authenticated store realization")?,
        ]));
    }
    realization_members.sort_by(|left, right| {
        left[0]
            .as_str()
            .unwrap_or_default()
            .cmp(right[0].as_str().unwrap_or_default())
    });
    let realization = crate::canonical_json_digest(&serde_json::Value::Array(realization_members))?;
    Ok((
        Some(registry.to_string()),
        Some(receipt.release_tag.clone()),
        Some(receipt.tag_signer_key.clone()),
        Some(realization),
    ))
}

fn enrich_manifest(
    cmd: &EvalCommand,
    prepared: &PreparedEvaluatorInputs,
    outcome: &FixpointOutcome,
    runtime: &runtime::RuntimeResolution,
) -> Result<materialize::ConfigManifest> {
    let mut raw: serde_json::Value =
        serde_json::from_str(&outcome.manifest).context("parsing evaluated config manifest")?;
    let object = raw
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("evaluated config manifest is not an object"))?;
    let ability_activation = object
        .get_mut("inputs")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|inputs| inputs.remove("ability_activation"));

    enrich_runtime_projection(object, runtime)?;
    let ability_activation =
        enrich_ability_activation(ability_activation, runtime, &cmd.store_view)?;
    if let Some(activation) = &ability_activation {
        retain_ability_sidecar_roots(object, activation)?;
    }

    let host_bytes = std::fs::read(&prepared.host_nix.read_path).with_context(|| {
        format!(
            "reading host input {}",
            prepared.host_nix.read_path.display()
        )
    })?;
    let evaluator = std::env::current_exe().context("resolving evaluator executable")?;
    let evaluator_store_path = evaluator_store_root(&evaluator)?;
    let package_modules = package_module_inputs(&outcome.working_set)?;

    let (facts, retained_facts_bytes, facts_input_path) =
        match prepared.facts_json.as_deref().filter(|path| path.is_file()) {
            Some(path) => {
                let bytes = std::fs::read(path)
                    .with_context(|| format!("reading facts {}", path.display()))?;
                let facts = serde_json::from_slice::<aos_metadata::fetcher::Facts>(&bytes)
                    .with_context(|| format!("parsing facts {}", path.display()))?;
                (facts, bytes, Some(path))
            }
            None => {
                let facts = aos_metadata::fetcher::Facts::default();
                let bytes =
                    serde_json::to_vec(&facts).context("serializing default instance facts")?;
                (facts, bytes, None)
            }
        };

    let normalized_facts = aos_metadata::facts_render::normalize_host_facts(&facts);
    let facts_identity = serde_json::to_vec(&normalized_facts)?;
    let retained_facts = cmd.eval_root.join("instance-facts.json");
    std::fs::create_dir_all(&cmd.eval_root)
        .with_context(|| format!("creating eval root {}", cmd.eval_root.display()))?;
    std::fs::write(&retained_facts, &retained_facts_bytes)
        .with_context(|| format!("writing retained facts {}", retained_facts.display()))?;
    // Reuse an already immutable facts input instead of asking Nix to import an
    // identical copy. Besides avoiding needless store traffic on-host, this
    // keeps hermetic preflight checks independent of a writable Nix state dir.
    let facts_store_path = match &cmd.retained_host_inputs {
        Some(retained) => PathBuf::from(&retained.instance_facts.store_path),
        None => {
            let facts_store_source = facts_input_path
                .filter(|path| path.starts_with("/nix/store"))
                .unwrap_or(&retained_facts);
            add_fixed_input_to_store(facts_store_source)?
        }
    };

    let (platform, trust_mode, signer_key) = if cmd.image_default_host {
        ("image".to_string(), "image".to_string(), None)
    } else {
        let trust_mode = if cmd.require_signed_host_nix {
            "signed"
        } else {
            "platform"
        };
        ("unknown".to_string(), trust_mode.to_string(), None)
    };
    let base_abi_hash = read_base_lib_abi_hash(&prepared.base_lib.read_path, cmd.module_abi)?;
    let evaluator_store_hash = evaluator_store_hash(&evaluator)?;
    let (config_registry, config_release_tag, config_tag_signer_key, config_realization) =
        package_module_release_identity(&outcome.working_set)?;
    let host_store_path = match &cmd.retained_host_inputs {
        Some(retained) => PathBuf::from(&retained.host_nix.store_path),
        None => add_fixed_input_to_store(&prepared.host_nix.read_path)?,
    };
    let runtime_module_identities = cmd
        .runtime_modules
        .iter()
        .map(|input| input.identity.clone())
        .collect::<Vec<_>>();
    let runtime_modules = runtime_module_manifest_input(
        &runtime_module_identities,
        cmd.runtime_module_root.as_deref(),
    )?;

    let computed_host_hash = sha256_identity(&host_bytes);
    let computed_facts_hash = sha256_identity(&facts_identity);
    let (host_input, facts_input) = if let Some(retained) = &cmd.retained_host_inputs {
        anyhow::ensure!(
            retained.host_nix.content_hash == computed_host_hash
                && retained.host_nix.store_path == host_store_path.to_string_lossy(),
            "retained host identity does not match the evaluated host input"
        );
        anyhow::ensure!(
            retained.instance_facts.facts_hash == computed_facts_hash
                && retained.instance_facts.store_path == facts_store_path.to_string_lossy(),
            "retained facts identity does not match the evaluated facts input"
        );
        (retained.host_nix.clone(), retained.instance_facts.clone())
    } else {
        (
            materialize::HostNixInput {
                content_hash: computed_host_hash,
                trust_mode,
                platform: platform.clone(),
                signer_key,
                store_path: host_store_path.to_string_lossy().into_owned(),
            },
            materialize::InstanceFactsInput {
                facts_hash: computed_facts_hash,
                platform,
                store_path: facts_store_path.to_string_lossy().into_owned(),
            },
        )
    };

    let mut inputs = serde_json::json!({
        "base_lib": {
            "store_path": cmd.base_lib,
            "abi_hash": base_abi_hash,
            "module_abi": cmd.module_abi,
        },
        "evaluator": {
            "store_path": evaluator_store_path,
            "store_hash": evaluator_store_hash,
        },
        "package_modules": {
            "registry": config_registry,
            "release_tag": config_release_tag,
            "tag_signer_key": config_tag_signer_key,
            "realization": config_realization,
            "modules": package_modules,
        },
        "host_nix": host_input,
        "instance_facts": facts_input,
        "store_view": cmd.store_view,
    });
    if let Some(runtime_modules) = runtime_modules {
        inputs
            .as_object_mut()
            .context("manifest inputs did not serialize as an object")?
            .insert("runtime_modules".into(), runtime_modules);
    }
    if let Some(ability_activation) = ability_activation {
        inputs
            .as_object_mut()
            .context("manifest inputs did not serialize as an object")?
            .insert("ability_activation".into(), ability_activation);
    }
    if inputs.get("runtime_modules").is_some() || inputs.get("ability_activation").is_some() {
        let expected = cmd.expected_current_generation.context(
            "transactional evaluation requires a caller-supplied active generation snapshot",
        )?;
        inputs
            .as_object_mut()
            .context("manifest inputs did not serialize as an object")?
            .insert(
                "expected_current_generation".into(),
                serde_json::json!(expected),
            );
    }
    object.insert("inputs".into(), inputs);
    let manifest: materialize::ConfigManifest =
        serde_json::from_value(raw).context("validating config manifest structure")?;
    manifest.validate()?;
    Ok(manifest)
}

fn enrich_ability_activation(
    input: Option<serde_json::Value>,
    runtime: &runtime::RuntimeResolution,
    store_view: &store_view::StoreViewLocator,
) -> Result<Option<serde_json::Value>> {
    let requires_effect_activation =
        runtime
            .packages
            .iter()
            .try_fold(false, |required, (name, package)| -> Result<bool> {
                let Some(contract) = &package.contract else {
                    return Ok(required);
                };
                let resolved = static_packages::resolve(
                    name,
                    &package.version,
                    &package.platform,
                    &package.store_path,
                    &package.nar_hash,
                    contract,
                    store_view,
                )?;
                Ok(required
                    || resolved.document.required_features.iter().any(|feature| {
                        feature.as_str() == aos_ability_model::FEATURE_ABILITY_EFFECTS_V1
                    }))
            })?;
    if requires_effect_activation && input.is_none() {
        anyhow::bail!("effect-bearing package selection requires an ability_activation input");
    }
    let Some(mut input) = input else {
        return Ok(None);
    };
    let object = input
        .as_object_mut()
        .context("manifest inputs.ability_activation must be an object")?;
    object.insert(
        "schema".to_string(),
        serde_json::Value::String(materialize::AbilityActivationInput::SCHEMA.to_string()),
    );
    Ok(Some(input))
}

fn retain_ability_sidecar_roots(
    manifest: &mut serde_json::Map<String, serde_json::Value>,
    activation: &serde_json::Value,
) -> Result<()> {
    let sidecar_paths = ["desired_state", "authenticated_policy_set"]
        .into_iter()
        .map(|field| {
            activation
                .get(field)
                .and_then(|sidecar| sidecar.get("store_path"))
                .and_then(serde_json::Value::as_str)
                .with_context(|| format!("ability_activation.{field}.store_path is missing"))
        })
        .collect::<Result<Vec<_>>>()?;
    let store_paths = manifest
        .get_mut("storePaths")
        .and_then(serde_json::Value::as_array_mut)
        .context("evaluated manifest storePaths is not an array")?;
    for path in &sidecar_paths {
        store_paths.push(serde_json::Value::String((*path).to_string()));
    }
    store_paths.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    store_paths.dedup();

    let owners = manifest
        .get_mut("ownership")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|ownership| ownership.get_mut("storePaths"))
        .and_then(serde_json::Value::as_object_mut)
        .context("evaluated manifest ownership.storePaths is not an object")?;
    for path in sidecar_paths {
        match owners.get(path).and_then(serde_json::Value::as_str) {
            Some("@host") | None => {
                owners.insert(
                    path.to_string(),
                    serde_json::Value::String("@host".to_string()),
                );
            }
            Some(owner) => anyhow::bail!(
                "ability activation sidecar {path} conflicts with store owner {owner:?}"
            ),
        }
    }
    Ok(())
}

pub(crate) fn current_config_generation_number(state_path: &Path) -> Result<u32> {
    match std::fs::read(state_path) {
        Ok(bytes) => {
            let state: crate::types::ConfigGenerationState = serde_json::from_slice(&bytes)
                .with_context(|| {
                    format!("parsing config generation state {}", state_path.display())
                })?;
            Ok(state.current)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error).with_context(|| format!("reading {}", state_path.display())),
    }
}

fn runtime_module_manifest_input(
    paths: &[PathBuf],
    root_hint: Option<&Path>,
) -> Result<Option<serde_json::Value>> {
    if paths.is_empty() && root_hint.is_none() {
        return Ok(None);
    }

    let root_hint = root_hint
        .map(|path| {
            let text = path
                .to_str()
                .with_context(|| format!("runtime module root is not UTF-8: {}", path.display()))?;
            let root = manifest_store_root(text).with_context(|| {
                format!("runtime module root is not a canonical store path: {text}")
            })?;
            anyhow::ensure!(root == text, "runtime module root must name one store root");
            Ok::<_, anyhow::Error>(root)
        })
        .transpose()?;
    let mut root = root_hint;
    let mut entrypoints = Vec::with_capacity(paths.len());
    for path in paths {
        let text = path
            .to_str()
            .with_context(|| format!("runtime module path is not UTF-8: {}", path.display()))?;
        let candidate_root = manifest_store_root(text).with_context(|| {
            format!("runtime module is not beneath a canonical store root: {text}")
        })?;
        if let Some(expected) = root {
            anyhow::ensure!(
                expected == candidate_root,
                "runtime module entrypoints must share one immutable source root"
            );
        } else {
            root = Some(candidate_root);
        }
        let relative = path
            .strip_prefix(candidate_root)
            .with_context(|| format!("deriving runtime module entrypoint for {text}"))?;
        let relative = relative
            .strip_prefix("/")
            .unwrap_or(relative)
            .to_str()
            .context("runtime module entrypoint is not UTF-8")?
            .to_string();
        entrypoints.push(relative);
    }
    anyhow::ensure!(
        entrypoints.windows(2).all(|pair| pair[0] < pair[1]),
        "runtime module entrypoints must be sorted and deduplicated"
    );
    let root = root.context("runtime module set unexpectedly had no source root")?;
    let nar_hash = retained_store_path_nar_hash(Path::new(root))?;
    Ok(Some(serde_json::json!({
        "schema": "aos.runtime-module-set/v1",
        "trust_mode": "local-root",
        "store_path": root,
        "nar_hash": nar_hash,
        "entrypoints": entrypoints,
    })))
}

/// Adds exact runtime pins and their ownership to an evaluated manifest value.
fn enrich_runtime_projection(
    object: &mut serde_json::Map<String, serde_json::Value>,
    runtime: &runtime::RuntimeResolution,
) -> Result<()> {
    object
        .entry("config")
        .or_insert_with(|| serde_json::json!({}));
    let packages: Vec<String> = runtime.packages.keys().cloned().collect();
    object.insert("packages".into(), serde_json::to_value(&packages)?);
    object.insert(
        "graph".into(),
        serde_json::json!({ "edges": runtime.edges }),
    );
    object.insert(
        "packageOutputs".into(),
        serde_json::to_value(&runtime.packages).context("serializing runtime package pins")?,
    );
    let mut store_paths: BTreeSet<String> = object
        .get("storePaths")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_string)
        .collect();
    store_paths.extend(
        runtime
            .packages
            .values()
            .map(|package| package.store_path.clone()),
    );
    let etc_store_owners = {
        let etc = object
            .get("etc")
            .and_then(serde_json::Value::as_object)
            .context("manifest etc must be an object")?;
        let etc_ownership = object
            .get("ownership")
            .and_then(serde_json::Value::as_object)
            .and_then(|ownership| ownership.get("etc"))
            .and_then(serde_json::Value::as_object)
            .context("manifest ownership.etc must be an object")?;
        let mut derived = BTreeMap::<String, BTreeSet<String>>::new();
        for (path, entry) in etc {
            if entry.get("kind").and_then(serde_json::Value::as_str) == Some("store-symlink")
                && let Some(target) = entry.get("target").and_then(serde_json::Value::as_str)
                && let Some(root) = manifest_store_root(target)
            {
                let owner = etc_ownership
                    .get(path)
                    .and_then(serde_json::Value::as_str)
                    .with_context(|| {
                        format!(
                            "store-symlink etc entry {path:?} has no string ownership.etc entry"
                        )
                    })?;
                derived
                    .entry(root.to_string())
                    .or_default()
                    .insert(owner.to_string());
                store_paths.insert(root.to_string());
            }
        }
        derived
    };
    let store_paths: Vec<String> = store_paths.into_iter().collect();
    object.insert("storePaths".into(), serde_json::to_value(&store_paths)?);
    let ownership = object
        .get_mut("ownership")
        .and_then(serde_json::Value::as_object_mut)
        .context("manifest ownership must be an object")?;
    let owned = ownership
        .get_mut("storePaths")
        .and_then(serde_json::Value::as_object_mut)
        .context("manifest ownership.storePaths must be an object")?;

    for (name, package) in &runtime.packages {
        for package_path in [package.store_path.as_str()] {
            if let Some(existing) = owned.get(package_path) {
                let existing = existing.as_str().with_context(|| {
                    format!("manifest ownership.storePaths.{package_path} must be a string")
                })?;
                if existing != name {
                    if existing == "@base"
                        && package_path == package.store_path
                        && package.origin != runtime::RuntimePackageOrigin::Image
                    {
                        anyhow::bail!(
                            "registry runtime output {} for authenticated package {name} aliases an image-bundled store path owned by @base; base content cannot be reclassified as a package output",
                            package.store_path
                        );
                    }
                    if existing != "@base" {
                        anyhow::bail!(
                            "runtime artifact {package_path} is owned by {existing}, not authenticated package {name}"
                        );
                    }
                }
            }
            owned
                .entry(package_path.to_string())
                .or_insert_with(|| serde_json::Value::String(name.clone()));
        }
    }

    for (path, referencing_owners) in etc_store_owners {
        if let Some(existing) = owned.get(&path) {
            let existing = existing.as_str().with_context(|| {
                format!("manifest ownership.storePaths.{path} must be a string")
            })?;
            for artifact_owner in &referencing_owners {
                if !materialize::owner_can_reference_store(artifact_owner, existing, &runtime.edges)
                {
                    anyhow::bail!(
                        "store root {path} ownership {existing} is not authorized for referencing /etc owner {artifact_owner}"
                    );
                }
            }
        } else if referencing_owners.len() == 1 {
            let owner = referencing_owners
                .into_iter()
                .next()
                .context("single referencing owner disappeared")?;
            owned.insert(path, serde_json::Value::String(owner));
        } else {
            anyhow::bail!(
                "store root {path} has no independent owner and is referenced by multiple /etc owners: {}",
                referencing_owners
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    for path in &store_paths {
        if !owned.contains_key(path) {
            anyhow::bail!("manifest store path {path} has no authenticated artifact owner");
        }
    }
    Ok(())
}

fn add_fixed_input_to_store(path: &Path) -> Result<PathBuf> {
    if let Some(root) = manifest_store_root(path.to_string_lossy().as_ref()) {
        let root = Path::new(root);
        if path == root {
            return Ok(path.to_path_buf());
        }
    }
    let output = std::process::Command::new("nix-store")
        .args(["--add-fixed", "sha256"])
        .arg(path)
        .output()
        .with_context(|| {
            format!(
                "adding fixed evaluator input {} to the store",
                path.display()
            )
        })?;
    if !output.status.success() {
        anyhow::bail!(
            "adding fixed evaluator input to the store failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let store_path = String::from_utf8(output.stdout)
        .context("nix-store returned a non-UTF-8 evaluator input path")?;
    let store_path = PathBuf::from(store_path.trim());
    if !store_path.starts_with("/nix/store") {
        anyhow::bail!("nix-store returned invalid path {}", store_path.display());
    }
    Ok(store_path)
}

fn add_fixed_eval_host_source(path: &Path, eval_root: &Path) -> Result<PathBuf> {
    if let Some(root) = manifest_store_root(path.to_string_lossy().as_ref()) {
        if Path::new(root)
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.split_once('-'))
            .is_some_and(|(_, name)| name == "source")
        {
            return Ok(path.to_path_buf());
        }
    }

    let source = eval_root.join("host-input/source");
    match std::fs::remove_dir_all(&source) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("removing stale host evaluator source"),
    }
    std::fs::create_dir_all(&source)
        .with_context(|| format!("creating host evaluator source {}", source.display()))?;
    std::fs::copy(path, source.join("host.nix"))
        .with_context(|| format!("copying authorized host input {}", path.display()))?;

    let output = std::process::Command::new("nix-store")
        .args(["--add-fixed", "--recursive", "sha256"])
        .arg(&source)
        .output()
        .context("adding host evaluator source to the store")?;
    if !output.status.success() {
        anyhow::bail!(
            "adding host evaluator source to the store failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let store_root = String::from_utf8(output.stdout)
        .context("nix-store returned a non-UTF-8 host evaluator source path")?;
    let store_root = PathBuf::from(store_root.trim());
    if !store_root.starts_with("/nix/store") || store_root.file_name().is_none() {
        anyhow::bail!(
            "nix-store returned invalid host evaluator source {}",
            store_root.display()
        );
    }
    Ok(store_root.join("host.nix"))
}

fn manifest_store_root(target: &str) -> Option<&str> {
    let suffix = target.strip_prefix("/nix/store/")?;
    let first = suffix.split('/').next()?;
    (!first.is_empty()).then_some(&target[.."/nix/store/".len() + first.len()])
}

/// Re-evaluate a config-generation across an ABI boundary from its retained
/// retained inputs used for cross-ABI rollback.
///
/// When a config-gen's `module_abi_pinned` differs from the running image's
/// `module_abi`, direct re-activation is refused and the generation is instead
/// **re-evaluated** — never blindly replayed — against the rolled-back image's
/// evaluator. This entrypoint maps the
/// [`CrossAbiReEvalInputs`](crate::types::CrossAbiReEvalInputs) the rollback
/// path looked up (the `host.nix` content-pin, the running base lib, the target
/// ABI) into one exact evaluator attempt over the retained ordered module
/// list. No mutable registry or desired-package file participates.
///
/// `running_base_lib` is the rolled-back image's base-lib store path (the ABI
/// artifact retained on `/var` by the `image-gen-N/baselib/<module_abi>` root).
/// `source_manifest` supplies the authenticated runtime pins from the old
/// intent, while `eval_root` and `out` select ephemeral outputs. The retained
/// per-module ABI bands are checked before evaluation; an incompatible module
/// is refused fail-closed and the old generation stays live.
///
/// # Errors
///
/// Returns an error when a retained input is absent or inconsistent, an ABI
/// band excludes the running image, evaluation does not produce a manifest,
/// or the new manifest cannot be written. No manifest is emitted on failure.
pub fn reeval_cross_abi(
    retained: &crate::types::CrossAbiReEvalInputs,
    running_base_lib: &Path,
    source_manifest: &Path,
    eval_root: PathBuf,
    out: PathBuf,
    verbose: u8,
    expected_current_generation: Option<u32>,
) -> Result<()> {
    let source = load_cross_abi_source(source_manifest)?;
    let store_view = source.inputs.store_view.clone();

    reeval_cross_abi_with_source(
        retained,
        running_base_lib,
        source,
        &store_view,
        eval_root,
        out,
        verbose,
        expected_current_generation,
    )
}

pub(crate) fn reeval_cross_abi_in_store_view(
    retained: &crate::types::CrossAbiReEvalInputs,
    running_base_lib: &Path,
    source_manifest: &Path,
    store_view: &store_view::StoreViewLocator,
    eval_root: PathBuf,
    out: PathBuf,
    verbose: u8,
    expected_current_generation: Option<u32>,
) -> Result<()> {
    let source = load_cross_abi_source(source_manifest)?;

    reeval_cross_abi_with_source(
        retained,
        running_base_lib,
        source,
        store_view,
        eval_root,
        out,
        verbose,
        expected_current_generation,
    )
}

fn load_cross_abi_source(source_manifest: &Path) -> Result<materialize::ConfigManifest> {
    let source_bytes = std::fs::read(source_manifest)
        .with_context(|| format!("reading retained manifest {}", source_manifest.display()))?;
    let source = serde_json::from_slice::<materialize::ConfigManifest>(&source_bytes)
        .with_context(|| format!("parsing retained manifest {}", source_manifest.display()))?;
    source
        .validate()
        .with_context(|| format!("validating retained manifest {}", source_manifest.display()))?;

    Ok(source)
}

#[allow(clippy::too_many_arguments)]
fn reeval_cross_abi_with_source(
    retained: &crate::types::CrossAbiReEvalInputs,
    running_base_lib: &Path,
    source: materialize::ConfigManifest,
    store_view: &store_view::StoreViewLocator,
    eval_root: PathBuf,
    out: PathBuf,
    verbose: u8,
    expected_current_generation: Option<u32>,
) -> Result<()> {
    remove_if_present(&out)?;
    let graph_out = out.with_file_name("graph.json");
    remove_if_present(&graph_out)?;
    validate_retained_manifest_inputs(&source, retained)?;
    validate_cross_abi_inputs(retained, running_base_lib, &source, store_view)?;

    let working_set = retained_cross_abi_working_set(&source, retained, store_view)?;
    let runtime_modules = retained_runtime_modules_in_store_view(&source, store_view)?;
    let host_nix =
        EvaluatorInput::in_store_view(PathBuf::from(&retained.host_nix_ref), store_view)?;
    let facts_json = store_view.read_path(Path::new(&retained.facts_ref))?;
    let running_base_lib =
        EvaluatorInput::in_store_view(running_base_lib.to_path_buf(), store_view)?;
    let evaluator = stock::StockNixEvaluator::in_store_view(eval_root, verbose, store_view.clone());
    let attempt = EvalAttempt {
        host_nix: &host_nix,
        runtime_modules: &runtime_modules,
        base_lib: &running_base_lib,
        facts_json: Some(&facts_json),
        working_set: &working_set,
        iteration: 0,
    };
    let evaluated = match evaluator.evaluate(&attempt)? {
        EvalClass::Manifest(manifest) => manifest,
        other => anyhow::bail!(
            "retained configuration is incompatible with module ABI {}: {other:?}",
            retained.to_module_abi
        ),
    };
    let mut raw: serde_json::Value =
        serde_json::from_str(&evaluated).context("parsing cross-ABI evaluator manifest")?;
    let object = raw
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("cross-ABI evaluator manifest is not an object"))?;

    // Package resolution is an authenticated input of the old intent, not a
    // mutable registry lookup. Re-project those exact pins into the newly
    // evaluated aggregate artifacts so configuration and ownership are rebuilt
    // against the running image's base library.
    let runtime = runtime::RuntimeResolution {
        packages: source.package_outputs.clone(),
        edges: source.graph.edges.clone(),
    };
    enrich_runtime_projection(object, &runtime)?;
    object.insert(
        "module_abi".into(),
        serde_json::json!(retained.to_module_abi),
    );

    let evaluator_path = std::env::current_exe().context("resolving evaluator executable")?;
    let evaluator_store_path = evaluator_store_root(&evaluator_path)?;
    let mut inputs = source.inputs.clone();
    inputs.store_view = store_view.clone();
    inputs.base_lib.store_path = running_base_lib.identity.to_string_lossy().into_owned();
    inputs.base_lib.module_abi = retained.to_module_abi;
    inputs.base_lib.abi_hash =
        read_base_lib_abi_hash(&running_base_lib.read_path, retained.to_module_abi)?;
    inputs.evaluator.store_path = evaluator_store_path.to_string_lossy().into_owned();
    inputs.evaluator.store_hash = evaluator_store_hash(&evaluator_path)?;
    if inputs.runtime_modules.is_some() || inputs.ability_activation.is_some() {
        inputs.expected_current_generation = Some(
            expected_current_generation
                .context("transactional re-evaluation requires the active generation snapshot")?,
        );
    }
    object.insert("inputs".into(), serde_json::to_value(inputs)?);

    let manifest: materialize::ConfigManifest =
        serde_json::from_value(raw).context("validating cross-ABI manifest structure")?;
    manifest.validate()?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating rollback output {}", parent.display()))?;
    }
    std::fs::write(&out, serde_json::to_vec(&manifest)?)
        .with_context(|| format!("writing cross-ABI manifest {}", out.display()))?;
    std::fs::write(&graph_out, serde_json::to_vec(&manifest.graph)?)
        .with_context(|| format!("writing cross-ABI graph {}", graph_out.display()))?;
    Ok(())
}

pub(crate) fn retained_runtime_modules(
    manifest: &materialize::ConfigManifest,
) -> Result<Vec<EvaluatorInput>> {
    let store_view = manifest.inputs.store_view.clone();
    retained_runtime_modules_in_store_view(manifest, &store_view)
}

fn retained_runtime_modules_in_store_view(
    manifest: &materialize::ConfigManifest,
    store_view: &store_view::StoreViewLocator,
) -> Result<Vec<EvaluatorInput>> {
    let Some(runtime) = &manifest.inputs.runtime_modules else {
        return Ok(Vec::new());
    };
    let identity_root = Path::new(&runtime.store_path);
    let actual = retained_store_path_nar_hash(identity_root).with_context(|| {
        format!(
            "hashing retained runtime module set {}",
            identity_root.display()
        )
    })?;
    anyhow::ensure!(
        crate::verify::sha256_hashes_equal(&actual, &runtime.nar_hash)?,
        "retained runtime module set {} does not match manifest NAR hash",
        identity_root.display()
    );

    runtime
        .entrypoints
        .iter()
        .map(|entry| {
            let identity = identity_root.join(entry);
            let input = EvaluatorInput::in_store_view(identity, store_view)?;
            anyhow::ensure!(
                input.read_path.is_file(),
                "retained runtime module entrypoint is absent: {}",
                input.read_path.display()
            );
            Ok(input)
        })
        .collect()
}

/// Resolves the descriptor's exact entrypoint list with an injectable NAR
/// hasher so replay invariants remain testable without mutating `/nix/store`.
#[cfg(test)]
fn retained_runtime_modules_with<F>(
    manifest: &materialize::ConfigManifest,
    nar_hash: F,
) -> Result<Vec<PathBuf>>
where
    F: FnOnce(&Path) -> Result<String>,
{
    let Some(runtime) = &manifest.inputs.runtime_modules else {
        return Ok(Vec::new());
    };
    let root = Path::new(&runtime.store_path);
    let actual = nar_hash(root)
        .with_context(|| format!("hashing retained runtime module set {}", root.display()))?;
    anyhow::ensure!(
        crate::verify::sha256_hashes_equal(&actual, &runtime.nar_hash)?,
        "retained runtime module set {} does not match manifest NAR hash",
        root.display()
    );
    runtime
        .entrypoints
        .iter()
        .map(|entry| {
            let path = root.join(entry);
            anyhow::ensure!(
                path.is_file(),
                "retained runtime module entrypoint is absent: {}",
                path.display()
            );
            Ok(path)
        })
        .collect()
}

fn retained_cross_abi_working_set(
    source: &materialize::ConfigManifest,
    retained: &crate::types::CrossAbiReEvalInputs,
    store_view: &store_view::StoreViewLocator,
) -> Result<Vec<WorkingSetMember>> {
    retained
        .package_modules
        .iter()
        .map(|module| {
            let pin = source
                .package_outputs
                .get(&module.package)
                .with_context(|| {
                    format!(
                        "retained package module {} has no runtime pin",
                        module.package
                    )
                })?;
            let contract = pin.contract.as_ref().with_context(|| {
                format!(
                    "retained package module {} has no package contract",
                    module.package
                )
            })?;
            let resolved = static_packages::resolve(
                &module.package,
                &pin.version,
                &pin.platform,
                &pin.store_path,
                &pin.nar_hash,
                contract,
                store_view,
            )?;
            anyhow::ensure!(
                resolved.document.content_digest()?.to_string() == module.document_digest,
                "retained package document digest disagrees with its manifest identity"
            );
            Ok(WorkingSetMember {
                registry: None,
                release_trust: None,
                config_realization: None,
                package: module.package.clone(),
                version: Some(pin.version.clone()),
                contract: Some(ResolvedPackageContract {
                    document: resolved.document,
                    interfaces: resolved.interfaces,
                }),
                outputs: PackageOutputs {
                    self_output: Some(pin.store_path.clone()),
                    dependencies: source
                        .graph
                        .edges
                        .get(&module.package)
                        .into_iter()
                        .flatten()
                        .filter_map(|dependency| {
                            source
                                .package_outputs
                                .get(dependency)
                                .map(|pin| (dependency.clone(), pin.store_path.clone()))
                        })
                        .collect(),
                },
            })
        })
        .collect()
}

fn validate_retained_manifest_inputs(
    source: &materialize::ConfigManifest,
    retained: &crate::types::CrossAbiReEvalInputs,
) -> Result<()> {
    if source.inputs.package_modules.modules != retained.package_modules
        || source.inputs.host_nix.store_path != retained.host_nix_ref
        || source.inputs.instance_facts.facts_hash != retained.facts_hash
        || source.inputs.instance_facts.store_path != retained.facts_ref
    {
        anyhow::bail!(
            "retained generation inputs disagree with its manifest; cross-ABI rollback refused"
        );
    }
    Ok(())
}

fn validate_cross_abi_inputs(
    retained: &crate::types::CrossAbiReEvalInputs,
    running_base_lib: &Path,
    source: &materialize::ConfigManifest,
    store_view: &store_view::StoreViewLocator,
) -> Result<()> {
    for (kind, canonical_path) in std::iter::once(("running base library", running_base_lib))
        .chain(std::iter::once((
            "host.nix",
            Path::new(&retained.host_nix_ref),
        )))
        .chain(std::iter::once((
            "instance facts",
            Path::new(&retained.facts_ref),
        )))
        .chain(
            retained
                .package_modules
                .iter()
                .map(|module| ("package module", Path::new(&module.store_path))),
        )
    {
        let path = store_view.read_path(canonical_path)?;
        if !path.exists() {
            anyhow::bail!(
                "required retained {kind} input is unavailable: {}",
                path.display()
            );
        }
    }
    let facts_path = store_view.read_path(Path::new(&retained.facts_ref))?;
    let facts_bytes = std::fs::read(&facts_path)
        .with_context(|| format!("reading retained facts {}", facts_path.display()))?;
    let facts: aos_metadata::fetcher::Facts = serde_json::from_slice(&facts_bytes)
        .with_context(|| format!("parsing retained facts {}", retained.facts_ref))?;
    let normalized = aos_metadata::facts_render::normalize_host_facts(&facts);
    let normalized_bytes = serde_json::to_vec(&normalized)?;
    if sha256_identity(&normalized_bytes) != retained.facts_hash {
        anyhow::bail!("retained facts bytes do not match the recorded facts_hash");
    }
    validate_retained_content_identities_in_store_view(source, retained, store_view)?;
    Ok(())
}

fn validate_retained_content_identities_in_store_view(
    source: &materialize::ConfigManifest,
    retained: &crate::types::CrossAbiReEvalInputs,
    store_view: &store_view::StoreViewLocator,
) -> Result<()> {
    let mut mapped = retained.clone();
    mapped.host_nix_ref = store_view
        .read_path(Path::new(&retained.host_nix_ref))?
        .to_string_lossy()
        .into_owned();

    validate_retained_content_identities(source, &mapped, retained_store_path_nar_hash)
}

/// Verifies the exact retained host and package-module bytes before evaluation.
///
/// The source manifest is already authenticated by the generation record. Its
/// hashes therefore remain the authority; a fresh image must prove that every
/// retained input still matches those identities rather than carrying the old
/// claims into a newly evaluated generation.
fn validate_retained_content_identities<F>(
    source: &materialize::ConfigManifest,
    retained: &crate::types::CrossAbiReEvalInputs,
    mut nar_hash: F,
) -> Result<()>
where
    F: FnMut(&Path) -> Result<String>,
{
    let host_bytes = std::fs::read(&retained.host_nix_ref)
        .with_context(|| format!("reading retained host.nix {}", retained.host_nix_ref))?;
    let actual_host_hash = sha256_identity(&host_bytes);
    if !crate::verify::sha256_hashes_equal(&actual_host_hash, &source.inputs.host_nix.content_hash)?
    {
        anyhow::bail!(
            "retained host.nix bytes do not match recorded content hash: expected {}, got {}",
            source.inputs.host_nix.content_hash,
            actual_host_hash,
        );
    }

    for module in &retained.package_modules {
        let actual = nar_hash(Path::new(&module.store_path)).with_context(|| {
            format!(
                "hashing retained package module {} at {}",
                module.package, module.store_path
            )
        })?;
        if !crate::verify::sha256_hashes_equal(&actual, &module.nar_hash)? {
            anyhow::bail!(
                "retained package module {} at {} does not match authenticated NAR hash: expected {}, got {actual}",
                module.package,
                module.store_path,
                module.nar_hash,
            );
        }
    }
    Ok(())
}

/// Recomputes a store path's NAR hash from its current bytes.
fn retained_store_path_nar_hash(path: &Path) -> Result<String> {
    let eval_store = selected_eval_store_uri()?;
    retained_store_path_nar_hash_in(path, eval_store.as_deref())
}

fn selected_eval_store_uri() -> Result<Option<std::ffi::OsString>> {
    let explicit_store = std::env::var_os("AOS_NIX_EVAL_STORE");
    let rooted_nix_environment = std::env::var_os("AOS_ROOT").map(|_| aos_core::nix::aos_nix_env());
    retained_eval_store_uri(explicit_store.as_deref(), rooted_nix_environment.as_deref())
}

/// Selects an explicit evaluator store or reconstructs the exact rooted store.
fn retained_eval_store_uri(
    explicit_store: Option<&std::ffi::OsStr>,
    rooted_nix_environment: Option<&[(&'static str, String)]>,
) -> Result<Option<std::ffi::OsString>> {
    if let Some(explicit_store) = explicit_store {
        anyhow::ensure!(
            !explicit_store.is_empty(),
            "AOS_NIX_EVAL_STORE must not be empty"
        );
        return Ok(Some(explicit_store.to_os_string()));
    }
    let Some(rooted_nix_environment) = rooted_nix_environment else {
        return Ok(None);
    };
    let setting = |name| {
        rooted_nix_environment
            .iter()
            .find_map(|(candidate, value)| (*candidate == name).then_some(value.as_str()))
            .with_context(|| format!("AOS_ROOT did not produce the required {name} binding"))
    };
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("store", setting("NIX_STORE_DIR")?);
    query.append_pair("state", setting("NIX_STATE_DIR")?);
    query.append_pair("log", setting("NIX_LOG_DIR")?);
    Ok(Some(format!("local?{}", query.finish()).into()))
}

/// Recomputes a store path's NAR hash through one exact evaluator store.
fn retained_store_path_nar_hash_in(
    path: &Path,
    eval_store: Option<&std::ffi::OsStr>,
) -> Result<String> {
    let mut command = std::process::Command::new("nix");
    command
        .args(["--extra-experimental-features", "nix-command"])
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("NIX_REMOTE")
        .env_remove("NIX_STORE_DIR")
        .env_remove("NIX_STATE_DIR")
        .env_remove("NIX_LOG_DIR");
    if let Some(eval_store) = eval_store {
        command.arg("--store").arg(eval_store);
    }
    let mut child = command
        .args(["store", "dump-path"])
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running nix store dump-path {}", path.display()))?;
    let stdout = child
        .stdout
        .take()
        .context("nix store dump-path did not provide stdout")?;
    let hash = crate::verify::sha256_stream(stdout);
    let output = child
        .wait_with_output()
        .with_context(|| format!("waiting for nix store dump-path {}", path.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "nix store dump-path failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    hash
}

/// Evaluates the closed host package-selection projection before resolution.
///
/// This is the bootstrap half of the fixpoint: package names must be known
/// before their registry package modules can be fetched, while the complete
/// runtime evaluation needs those modules. Only `aos.apm.desiredPackages` is
/// declared, so unrelated host definitions remain lazy.
fn load_host_selection(
    cmd: &EvalCommand,
    prepared: &PreparedEvaluatorInputs,
) -> Result<Vec<WorkingSetMember>> {
    let eval_store = selected_eval_store_uri()?;
    load_host_selection_in(cmd, prepared, eval_store.as_deref())
}

fn load_host_selection_in(
    cmd: &EvalCommand,
    prepared: &PreparedEvaluatorInputs,
    eval_store: Option<&std::ffi::OsStr>,
) -> Result<Vec<WorkingSetMember>> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HostSelection {
        packages: Vec<String>,
    }

    anyhow::ensure!(
        prepared.host_nix.identity.starts_with("/nix/store"),
        "host package-selection input must be pinned in /nix/store"
    );

    let source_root = cmd.eval_root.join("host-selection-source");
    std::fs::create_dir_all(&source_root)
        .with_context(|| format!("creating host-selection source {}", source_root.display()))?;
    let staged_entry = source_root.join("entry.nix");
    let lock = |input: &EvaluatorInput| -> Result<String> {
        stock::locked_evaluator_input_in(input, None, eval_store)
    };
    let base =
        lock(&prepared.base_lib).context("locking the base library for host package selection")?;
    let host = lock(&prepared.host_nix).context("locking host.nix for host package selection")?;
    let runtime_modules = prepared
        .runtime_modules
        .iter()
        .map(|input| lock(input).map(|locked| format!("(import {locked})")))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    let expression = format!(
        "# Generated by aos config eval; do not edit.\n\
         let\n\
        \x20 baseLib = import {base};\n\
        \x20 system = baseLib.evalHostSelection {{\n\
        \x20   operatorModules = [ (import {host}) ];\n\
        \x20   runtimeModules = [ {runtime_modules} ];\n\
        \x20 }};\n\
         in {{ packages = system.config.aos.apm.desiredPackages; }}\n",
        base = base,
        host = host,
        runtime_modules = runtime_modules,
    );
    std::fs::write(&staged_entry, &expression)
        .with_context(|| format!("writing {}", staged_entry.display()))?;
    let mut evaluator = stock::pure_eval_command_in(
        eval_store,
        Some(cmd.store_view.read_root.as_path()),
        &cmd.eval_root,
    )
    .context("resolving the AOS stock evaluator for host package selection")?;
    evaluator.arg("-");
    let output = stock::output_with_expression(&mut evaluator, &expression)
        .context("spawning restricted host package-selection evaluation")?;
    if !output.status.success() {
        anyhow::bail!(
            "host package-selection evaluation failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let selection: HostSelection =
        serde_json::from_slice(&output.stdout).context("parsing host package selection")?;
    let mut seen = BTreeSet::new();
    Ok(selection
        .packages
        .into_iter()
        .filter(|package| seen.insert(package.clone()))
        .map(WorkingSetMember::seed)
        .collect())
}

/// Load seed package names from a `desired.toml`, as bare working-set members.
///
/// Only the top-level `packages` array is read; seed config-module metadata
/// (package module artifacts, ABI bands) is discovered by the loop, so seeds carry no
/// package module artifact here.
fn load_seed_set(desired: Option<&Path>) -> Result<Vec<WorkingSetMember>> {
    let Some(path) = desired else {
        return Ok(Vec::new());
    };
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading desired packages {}", path.display()))?;
    let doc: toml::Value =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let names = doc
        .as_table()
        .and_then(|table| table.get("packages"))
        .and_then(|packages| packages.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| entry.as_str())
                .map(WorkingSetMember::seed)
                .collect()
        })
        .unwrap_or_default();
    Ok(names)
}

#[cfg(test)]
mod tests;
