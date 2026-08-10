//! The on-host resolve/evaluate fixpoint driver.
//!
//! Stock Nix gives no read-access instrumentation, so the set of config
//! providers a host needs cannot be statically closed: it is *discovered* by
//! evaluating the module set, observing what is missing, fetching the named
//! provider's `config` output, and re-evaluating until the eval succeeds or a
//! terminal state is reached. [`run_fixpoint`] is that deterministic state
//! machine; it is the driver *around* the existing closure resolver
//! ([`crate::resolve`]).
//!
//! # Module map
//!
//! - [`classify`] — the fragile string parse of stock-Nix throw strings into
//!   the [`EvalClass`] seam (build-spec §2). P2 aos-nix replaces exactly this.
//! - [`stock`] — the production [`NixEvaluator`] that renders `entry.nix`,
//!   shells out to `nix-instantiate --store dummy:// --eval --strict --json
//!   --pure-eval
//!   --option restrict-eval true
//!   --option allow-import-from-derivation false` with an empty environment,
//!   and classifies the result, plus the registry-backed
//!   [`ConfigOutputFetcher`]. Builder-gated:
//!   it requires a real
//!   stock-nix and registry, so it is unit-tested only for `entry.nix`
//!   rendering.
//!
//! # The seam
//!
//! Everything the P2 evaluator must keep stable is `eval(working_set, host_nix,
//! base_lib) -> Result<EvalClass>`. The resolver, the registry index, the fetch
//! order (config output first), the `module_abi` gate, and the manifest
//! contract are identical on both evaluators; swapping P1↔P2 changes only how
//! [`EvalClass`] is produced.
//!
//! # Failure-safe
//!
//! The fixpoint produces *only* a manifest and never activates. Every terminal
//! state — a [`FixpointError`] or non-convergence at the iteration cap — is a
//! clean no-op on the live system: no generation exists until a downstream
//! service consumes a returned manifest.

pub mod activation;
pub mod classify;
pub mod diagnostics;
pub mod dry_run;
pub mod materialize;
pub mod native;
pub mod runtime;
pub mod stock;
pub mod system_roots;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

pub use classify::{ConflictDef, EvalClass, KillReason, MissingOption, MissingOptionKind};
pub use system_roots::{
    CapabilitySetter, ConfigModuleResolver, ResolvedConfigModule, RootOwner, SystemRoots,
    SystemRootsError,
};

use crate::resolve::{GatedConfigModule, enforce_module_abi_compat};
use crate::types::{ConfigModuleMeta, ModuleAbiCompat, option_path_root};

/// Absolute ceiling on re-evals, so a pathological registry cannot make the
/// loop unbounded (build-spec §5).
pub const ITER_CAP_CEILING: u32 = 64;

/// Slack added to the reachable-provider count when deriving the iteration cap.
const ITER_CAP_SLACK: u32 = 8;

// ---------------------------------------------------------------------------
// Working set
// ---------------------------------------------------------------------------

/// One package in the fixpoint working set.
///
/// The seed set is supplied by the caller from the host's desired packages;
/// fetched providers are appended as the loop discovers missing options. A
/// member that carries config-module metadata is gated against the running
/// image's `module_abi` before it can enter `entry.nix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkingSetMember {
    /// Registry that authenticated this member's config output.
    pub registry: Option<String>,
    /// Signed release identity for the extracted registry tree.
    pub release_trust: Option<crate::registry::ReleaseTrustReceipt>,
    /// Hash of the signed store subgraph rooted at this config output.
    pub config_realization: Option<String>,
    /// Package name.
    pub package: String,
    /// Package version, when known.
    pub version: Option<String>,
    /// Store path of the package's `config` output (its config-only module),
    /// when it ships one. This is the only thing the eval reads.
    pub config_output: Option<String>,
    /// Authenticated NAR hash of [`Self::config_output`].
    pub config_output_nar_hash: Option<String>,
    /// The member's declared base-lib ABI band, when it ships a config module.
    pub module_abi_compat: Option<ModuleAbiCompat>,
    /// Resolver-controlled roots and foreign contribution paths authenticated
    /// by this package's config-module metadata.
    pub authorization: PackageAuthorization,
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

/// Exact write authorization passed beside one authenticated package module.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageAuthorization {
    /// Shared roots this package owns. Its private package-name root is always
    /// implicit and need not appear here.
    pub owns: Vec<String>,
    /// Allowed foreign writes, keyed by root and expressed as relative paths.
    pub contributes: BTreeMap<String, Vec<String>>,
}

impl PackageAuthorization {
    /// Derives authorization solely from authenticated config-module metadata.
    fn from_module(module: &ConfigModuleMeta) -> Self {
        let mut owns: Vec<String> = module
            .owns_roots
            .iter()
            .map(|owned| owned.root.clone())
            .collect();
        owns.sort();
        owns.dedup();
        let mut contributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for contribution in &module.contributes {
            contributes
                .entry(contribution.root.clone())
                .or_default()
                .extend(contribution.paths.iter().cloned());
        }
        for paths in contributes.values_mut() {
            paths.sort();
            paths.dedup();
        }
        Self { owns, contributes }
    }
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
            config_output: None,
            config_output_nar_hash: None,
            module_abi_compat: None,
            authorization: PackageAuthorization::default(),
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
    pub host_nix: PathBuf,
    /// The in-image, ABI-pinned module library.
    pub base_lib: PathBuf,
    /// Optional normalized metadata facts consumed as a typed Nix module.
    pub facts_json: Option<PathBuf>,
    /// Packages explicitly installed (`desired.toml`): the starting working set.
    pub seed_set: Vec<WorkingSetMember>,
    /// The running image's base-lib ABI (`K`).
    pub module_abi: u32,
    /// Optional override for the iteration cap; otherwise derived from the index.
    pub iter_cap: Option<u32>,
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
    /// First-class native option access graph for the converged evaluation.
    pub option_graph: aos_core::nix::native::OptionGraph,
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
    /// A missing option whose providers all exclude the running `module_abi`.
    AbiMismatch {
        /// The unresolved option path or root.
        path: String,
        /// The running image ABI the providers failed to admit.
        want: u32,
    },
    /// A seed config module excludes the running `module_abi` (pre-eval gate).
    SeedAbiMismatch(String),
    /// Two installed packages own the same shared root (a per-system owned-root
    /// exclusivity violation, caught while building [`SystemRoots`]).
    AmbiguousProvider {
        /// The contested shared root.
        root: String,
        /// The first owner, as `package@version`.
        owner_a: String,
        /// The second owner, as `package@version`.
        owner_b: String,
    },
    /// An installed package's owned root collides with a *different* installed
    /// package's name, which would silently shadow that package's private root.
    ShadowedRoot {
        /// The owned root that collides with a package name.
        root: String,
        /// The package that owns the root, as `package@version`.
        owner: String,
    },
    /// A package's `contributes` declaration is not permitted: the foreign root
    /// has no owner, or a contributed sub-path is outside the owner's
    /// contributable set (F3-B, checked at resolve time).
    Contributable {
        /// The contributing package, as `package@version`.
        contributor: String,
        /// The foreign root being contributed into.
        root: String,
        /// The offending sub-path (empty when the root has no owner at all).
        path: String,
        /// Whether the root lacked an owner or the sub-path was out of scope.
        reason: system_roots::ContributableError,
    },
    /// A provider is already present yet the same option stays missing —
    /// fetching cannot help (a read cycle's terminal frame).
    Unsatisfiable {
        /// The still-missing option path or root.
        path: String,
        /// The provider already in the working set.
        provider: String,
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
            FixpointError::AbiMismatch { path, want } => write!(
                f,
                "every provider of '{path}' is incompatible with image module_abi {want}"
            ),
            FixpointError::SeedAbiMismatch(msg) => f.write_str(msg),
            FixpointError::AmbiguousProvider {
                root,
                owner_a,
                owner_b,
            } => write!(
                f,
                "root '{root}' is owned by both '{owner_a}' and '{owner_b}'; \
                 owned roots are exclusive per system"
            ),
            FixpointError::ShadowedRoot { root, owner } => write!(
                f,
                "owned root '{root}' (owned by '{owner}') collides with a different \
                 installed package named '{root}'; the package's private root would be shadowed"
            ),
            FixpointError::Contributable {
                contributor,
                root,
                path,
                reason,
            } => match reason {
                system_roots::ContributableError::NoOwner => write!(
                    f,
                    "package '{contributor}' contributes to root '{root}' but no installed \
                     package owns it"
                ),
                system_roots::ContributableError::NotContributable => write!(
                    f,
                    "package '{contributor}' contributes '{root}.{path}' but '{path}' is not in \
                     the owner's contributable set"
                ),
                system_roots::ContributableError::InterfaceAbiMismatch { expected, actual } => {
                    write!(
                        f,
                        "package '{contributor}' contributes to root '{root}' against interface ABI \
                     {expected}, but the installed owner exports interface ABI {actual}; republish \
                     the contributor against the installed owner's interface"
                    )
                }
            },
            FixpointError::Unsatisfiable { path, provider } => write!(
                f,
                "'{path}' is still missing after fetching '{provider}'; fetching cannot satisfy it (read cycle)"
            ),
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
                    "fetching config output for '{provider}' failed: {source}"
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

impl From<SystemRootsError> for FixpointError {
    /// Maps a [`SystemRoots`] build failure onto its terminal [`FixpointError`],
    /// so an integrity violation in the installed set aborts the fixpoint before
    /// any eval runs.
    fn from(err: SystemRootsError) -> Self {
        match err {
            SystemRootsError::OwnedRootConflict {
                root,
                owner_a,
                owner_b,
            } => FixpointError::AmbiguousProvider {
                root,
                owner_a,
                owner_b,
            },
            SystemRootsError::ShadowedRoot { root, owner } => {
                FixpointError::ShadowedRoot { root, owner }
            }
            SystemRootsError::Contributable {
                contributor,
                root,
                path,
                reason,
            } => FixpointError::Contributable {
                contributor,
                root,
                path,
                reason,
            },
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
    pub host_nix: &'a Path,
    /// The in-image module library.
    pub base_lib: &'a Path,
    /// Optional normalized metadata facts file.
    pub facts_json: Option<&'a Path>,
    /// The current working set rendered into `entry.nix`.
    pub working_set: &'a [WorkingSetMember],
    /// 0-based iteration counter.
    pub iteration: u32,
}

/// The evaluator seam: render the working set and classify the eval result.
///
/// The P1 implementation ([`stock::StockNixEvaluator`]) renders `entry.nix`,
/// runs a cold stock-Nix subprocess, and parses stderr via [`classify`]. The P2
/// [`native::NativeNixEvaluator`] evaluates the same entry expression in
/// process and fails closed on unsupported language features. Tests inject a
/// scripted mock.
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

/// A provider the driver selected from the index and is about to fetch.
#[derive(Debug, Clone, Copy)]
pub struct SelectedProvider<'a> {
    /// Provider package name.
    pub package: &'a str,
    /// Provider package version.
    pub version: &'a str,
    /// Target platform.
    pub platform: &'a str,
    /// Store path of the `config` output to fetch.
    pub config_output: &'a str,
    /// Authenticated NAR hash of the config output.
    pub nar_hash: &'a str,
    /// Authenticated uncompressed NAR size of the config output.
    pub nar_size: u64,
}

/// The fetch seam: download a selected provider's `config` output NAR.
///
/// The driver fetches the `config` output **before** any `out` closure
/// (build-spec §4): the next eval reads only the config-only module, and the
/// binary closure is needed solely if the provider survives into the converged
/// set. Tests inject a recording mock.
pub trait ConfigOutputFetcher {
    /// Fetch and verify `provider`'s `config` output into the local store.
    ///
    /// # Errors
    ///
    /// Returns an error on a terminal fetch failure (registry unreachable,
    /// unsigned, hash mismatch); the driver maps it to [`FixpointError::Fetch`].
    fn fetch_config_output(&self, provider: &SelectedProvider<'_>) -> Result<()>;
}

// ---------------------------------------------------------------------------
// The fixpoint
// ---------------------------------------------------------------------------

/// Drive `evalModules` to a complete configuration (build-spec §1).
///
/// The loop renders the current `working_set` into `entry.nix`, evaluates it,
/// and on a missing-option signal selects the owning provider — a shared-root
/// owner from the locally-derived [`SystemRoots`], else the package the root
/// structurally names, resolved by name through `resolver` (ABI-gated) — fetches
/// its `config` output, and re-evaluates. `working_set` is append-only over the
/// finite package universe, so the loop terminates at or before the iteration
/// cap.
///
/// [`SystemRoots`] is built once, up front, from the installed set: every seed
/// package's config module (resolved by name through `resolver`). A per-system
/// integrity violation (owned-root exclusivity, a shadowing collision, or an
/// out-of-scope contribution) is a terminal error before any eval runs.
///
/// Before iteration 0 every seed that carries config-module metadata is gated
/// against `inputs.module_abi`; an incompatible seed is a terminal
/// [`FixpointError::SeedAbiMismatch`] before any eval runs. Each fetched
/// provider is likewise gated before it enters `entry.nix`.
///
/// # Errors
///
/// Returns a [`FixpointError`] for every terminal state (no provider, ABI
/// mismatch, owned-root/ shadowing/ contributable integrity violation, conflict,
/// assertion, kill, opaque eval error, fetch failure) and
/// [`FixpointError::NonConvergence`] at the iteration cap. Every terminal state
/// is a clean no-op: no manifest is emitted, so nothing downstream activates.
pub fn run_fixpoint<R, E, F>(
    inputs: &FixpointInputs,
    resolver: &R,
    evaluator: &E,
    fetcher: &F,
) -> std::result::Result<FixpointOutcome, FixpointError>
where
    R: ConfigModuleResolver,
    E: NixEvaluator,
    F: ConfigOutputFetcher,
{
    // Pre-eval gate (build-spec §6): refuse an ABI-incompatible seed before any
    // eval. Wires CS3's `enforce_module_abi_compat` into the live path.
    gate_seeds(&inputs.seed_set, inputs.module_abi)?;

    // Build the per-system shared-root map from the installed set's config
    // modules. This is the authoritative place the owned-root exclusivity,
    // shadowing, and F3-B contributable invariants are enforced; a violation
    // aborts before any eval runs.
    let selected_names = inputs
        .seed_set
        .iter()
        .map(|member| member.package.as_str())
        .collect::<BTreeSet<_>>();
    let mut installed = resolver
        .installed_config_modules()
        .into_iter()
        .filter(|module| !selected_names.contains(module.package))
        .collect::<Vec<_>>();
    installed.extend(inputs.seed_set.iter().filter_map(|member| {
        if member.outputs.self_output.is_some() {
            resolver.config_module_exact(
                &member.package,
                member.version.as_deref(),
                member.outputs.self_output.as_deref(),
            )
        } else {
            resolver.config_module(&member.package)
        }
    }));
    let bundled_roots = load_bundled_roots(&inputs.base_lib)?;
    let system_roots =
        SystemRoots::build_with_context(installed, bundled_roots, resolver.known_shared_roots())?;

    let mut working_set = inputs.seed_set.clone();
    // The no-progress guard tracks packages whose CONFIG MODULE is actually
    // loaded (`config_output` present), NOT every seed name. A bare seed (a
    // desired package with no config module yet) must remain fetchable — if the
    // host references its root, the loop fetches its config output. Seeding the
    // guard with bare names would wedge such a package to `Unsatisfiable`.
    let mut fetched: BTreeSet<String> = working_set
        .iter()
        .filter(|m| m.config_output.is_some())
        .map(|m| m.package.clone())
        .collect();
    let mut trace: Vec<IterRecord> = Vec::new();
    let cap = inputs
        .iter_cap
        .unwrap_or_else(|| derive_iter_cap(inputs.seed_set.len(), &system_roots));

    let mut iter: u32 = 0;
    loop {
        if iter >= cap {
            return Err(FixpointError::NonConvergence {
                trace,
                iterations: iter,
            });
        }

        let attempt = EvalAttempt {
            host_nix: &inputs.host_nix,
            base_lib: &inputs.base_lib,
            facts_json: inputs.facts_json.as_deref(),
            working_set: &working_set,
            iteration: iter,
        };
        let class = evaluator
            .evaluate(&attempt)
            .map_err(|e| FixpointError::EvalError {
                stderr: format!("{e:#}"),
            })?;

        match class {
            EvalClass::Manifest(manifest) => {
                return Ok(FixpointOutcome {
                    manifest,
                    option_graph: aos_core::nix::native::OptionGraph::default(),
                    working_set,
                    trace,
                    iterations: iter,
                });
            }
            EvalClass::NativeManifest {
                manifest,
                option_graph,
            } => {
                return Ok(FixpointOutcome {
                    manifest,
                    option_graph,
                    working_set,
                    trace,
                    iterations: iter,
                });
            }
            EvalClass::Missing(missing) => {
                let selection =
                    select_first_resolvable(&missing, &system_roots, resolver, inputs.module_abi)?;

                // The provider's config module is already loaded yet the same
                // option is still missing — fetching cannot fix it (build-spec
                // §5 read cycle / bad config module). This is the real
                // no-progress condition.
                if fetched.contains(&selection.package) {
                    return Err(FixpointError::Unsatisfiable {
                        path: selection.missing_path.clone(),
                        provider: selection.package,
                    });
                }

                let authenticated_module =
                    resolver.config_module(&selection.package).ok_or_else(|| {
                        FixpointError::NoProvider {
                            path: selection.missing_path.clone(),
                            read_by: selection.read_by.clone(),
                        }
                    })?;
                system_roots.validate_discovered_module(authenticated_module.clone())?;
                let authorization = PackageAuthorization::from_module(authenticated_module.module);

                // Gate the newly-selected provider before it enters entry.nix.
                let gate = GatedConfigModule {
                    package: &selection.package,
                    version: &selection.version,
                    module_abi_compat: selection.module_abi_compat,
                };
                enforce_module_abi_compat(&[gate], inputs.module_abi).map_err(|_| {
                    FixpointError::AbiMismatch {
                        path: selection.missing_path.clone(),
                        want: inputs.module_abi,
                    }
                })?;

                // Config output FIRST (build-spec §4).
                let provider = SelectedProvider {
                    package: &selection.package,
                    version: &selection.version,
                    platform: &selection.platform,
                    config_output: &selection.config_output,
                    nar_hash: &selection.config_nar_hash,
                    nar_size: selection.config_nar_size,
                };
                fetcher
                    .fetch_config_output(&provider)
                    .map_err(|source| FixpointError::Fetch {
                        provider: selection.package.clone(),
                        source,
                    })?;

                fetched.insert(selection.package.clone());
                working_set.push(WorkingSetMember {
                    registry: (!authenticated_module.registry.is_empty())
                        .then(|| authenticated_module.registry.to_string()),
                    release_trust: authenticated_module.release_trust.cloned(),
                    config_realization: authenticated_module.config_realization.clone(),
                    package: selection.package.clone(),
                    version: Some(selection.version.clone()),
                    config_output: Some(selection.config_output.clone()),
                    config_output_nar_hash: Some(selection.config_nar_hash.clone()),
                    module_abi_compat: Some(selection.module_abi_compat),
                    authorization,
                    outputs: PackageOutputs {
                        self_output: Some(authenticated_module.runtime_output.to_string()),
                        dependencies: BTreeMap::new(),
                    },
                });
                trace.push(IterRecord {
                    iter,
                    missing_path: selection.missing_path,
                    kind: selection.kind,
                    provider_added: selection.package,
                    read_by: selection.read_by,
                });
                iter += 1;
            }
            EvalClass::UndefinedOption { path, file } => {
                return Err(FixpointError::UndefinedOption { path, file });
            }
            EvalClass::Conflict { defs } => return Err(FixpointError::Conflict { defs }),
            EvalClass::Assertion { msg, file } => {
                return Err(FixpointError::AssertionFailed { msg, file });
            }
            EvalClass::Killed(reason) => return Err(FixpointError::EvalKilled { reason }),
            EvalClass::Other { stderr } => return Err(FixpointError::EvalError { stderr }),
        }
    }
}

/// Resolves and fetches every selected seed's config-only module before the
/// first full evaluation.
///
/// Seed package modules may define defaults and assertions without first
/// triggering a missing-option error. Leaving those modules unloaded would
/// therefore produce a false fixpoint. This preflight pins their registry
/// identity, ABI-gates them, fetches the config output, and makes iteration
/// zero evaluate the complete selected module set.
fn hydrate_seed_config_modules<R, F>(
    seeds: &mut [WorkingSetMember],
    resolver: &R,
    fetcher: &F,
    module_abi: u32,
) -> std::result::Result<(), FixpointError>
where
    R: ConfigModuleResolver,
    F: ConfigOutputFetcher,
{
    for seed in seeds {
        let Some(resolved) = resolver.config_module(&seed.package) else {
            continue;
        };
        seed.registry = (!resolved.registry.is_empty()).then(|| resolved.registry.to_string());
        seed.release_trust = resolved.release_trust.cloned();
        seed.config_realization = resolved.config_realization.clone();
        seed.authorization = PackageAuthorization::from_module(resolved.module);
        seed.outputs.self_output = Some(resolved.runtime_output.to_string());
        if seed.config_output_nar_hash.is_none() {
            seed.config_output_nar_hash = Some(resolved.module.config_output.nar_hash.clone());
        }
        if seed.config_output.is_some() {
            continue;
        }
        enforce_module_abi_compat(
            &[GatedConfigModule {
                package: resolved.package,
                version: resolved.version,
                module_abi_compat: resolved.module.module_abi_compat,
            }],
            module_abi,
        )
        .map_err(|error| FixpointError::SeedAbiMismatch(format!("{error:#}")))?;
        fetcher
            .fetch_config_output(&SelectedProvider {
                package: resolved.package,
                version: resolved.version,
                platform: resolved.platform,
                config_output: &resolved.module.config_output.store_path,
                nar_hash: &resolved.module.config_output.nar_hash,
                nar_size: resolved.module.config_output.nar_size,
            })
            .map_err(|source| FixpointError::Fetch {
                provider: resolved.package.to_string(),
                source,
            })?;
        seed.version = Some(resolved.version.to_string());
        seed.config_output = Some(resolved.module.config_output.store_path.clone());
        seed.config_output_nar_hash = Some(resolved.module.config_output.nar_hash.clone());
        seed.module_abi_compat = Some(resolved.module.module_abi_compat);
    }
    Ok(())
}

/// Installs the exact runtime-output map authenticated by one resolution.
fn assign_runtime_outputs(members: &mut [WorkingSetMember], runtime: &runtime::RuntimeResolution) {
    for member in members {
        if let Some(package) = runtime.packages.get(&member.package) {
            member.outputs.self_output = Some(package.store_path.clone());
        }
        member.outputs.dependencies = runtime
            .edges
            .get(&member.package)
            .into_iter()
            .flatten()
            .filter_map(|dependency| {
                runtime
                    .packages
                    .get(dependency)
                    .map(|pin| (dependency.clone(), pin.store_path.clone()))
            })
            .collect();
    }
}

/// Adds structurally named providers discovered by the conservative
/// publish-time option-access scan before the first evaluation.
fn preclose_config_requires<R>(seeds: &mut Vec<WorkingSetMember>, resolver: &R)
where
    R: ConfigModuleResolver,
{
    loop {
        let installed_owners = seeds
            .iter()
            .filter_map(|seed| resolver.config_module(&seed.package))
            .flat_map(|resolved| resolved.module.owns_roots.iter())
            .map(|owned| owned.root.as_str())
            .collect::<BTreeSet<_>>();
        let existing = seeds
            .iter()
            .map(|seed| seed.package.as_str())
            .collect::<BTreeSet<_>>();
        let additions = seeds
            .iter()
            .filter_map(|seed| resolver.config_module(&seed.package))
            .flat_map(|resolved| resolved.module.requires.iter())
            .filter_map(|path| path.split('.').next())
            .filter(|root| {
                *root != "system"
                    && !existing.contains(root)
                    && !installed_owners.contains(root)
                    && resolver.config_module(root).is_some()
            })
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        if additions.is_empty() {
            return;
        }
        seeds.extend(additions.into_iter().map(WorkingSetMember::seed));
    }
}

/// Gate every seed that carries config-module metadata (build-spec §6).
fn gate_seeds(
    seeds: &[WorkingSetMember],
    image_abi: u32,
) -> std::result::Result<(), FixpointError> {
    let gates: Vec<GatedConfigModule<'_>> = seeds
        .iter()
        .filter_map(|m| {
            m.module_abi_compat.map(|compat| GatedConfigModule {
                package: m.package.as_str(),
                version: m.version.as_deref().unwrap_or(""),
                module_abi_compat: compat,
            })
        })
        .collect();
    enforce_module_abi_compat(&gates, image_abi)
        .map_err(|e| FixpointError::SeedAbiMismatch(format!("{e:#}")))
}

/// Derive the iteration cap from local state, capped at the ceiling.
///
/// With the registry-wide index gone there is no closed provider universe to
/// count, so the cap is derived from what is known locally: the seed set size
/// plus the number of owned shared roots, plus [`ITER_CAP_SLACK`] headroom for
/// providers discovered by absent-root reads. Each iteration fetches one new
/// distinct package, so this bounds the loop in the same spirit as the old
/// provider count. The result is clamped to [`ITER_CAP_CEILING`] so no local
/// state can push the loop unbounded.
fn derive_iter_cap(seed_len: usize, system_roots: &SystemRoots) -> u32 {
    let base = seed_len.saturating_add(system_roots.len());
    let count = u32::try_from(base).unwrap_or(ITER_CAP_CEILING);
    count.saturating_add(ITER_CAP_SLACK).min(ITER_CAP_CEILING)
}

/// Loads image/base-lib shared-root ownership metadata.
///
/// Older base libraries legitimately omit `system-roots.json`; that is the
/// only compatibility fallback. A present but malformed file is terminal so
/// ownership cannot silently disappear after image corruption.
fn load_bundled_roots(
    base_lib: &Path,
) -> std::result::Result<Vec<crate::types::OwnedRoot>, FixpointError> {
    let path = base_lib.join("system-roots.json");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(FixpointError::EvalError {
                stderr: format!("reading bundled root metadata {}: {error}", path.display()),
            });
        }
    };
    serde_json::from_slice(&bytes).map_err(|error| FixpointError::EvalError {
        stderr: format!("parsing bundled root metadata {}: {error}", path.display()),
    })
}

/// A concrete provider choice the driver resolved from a missing-option signal.
struct Selection {
    package: String,
    version: String,
    platform: String,
    config_output: String,
    config_nar_hash: String,
    config_nar_size: u64,
    module_abi_compat: ModuleAbiCompat,
    missing_path: String,
    kind: MissingOptionKind,
    read_by: Option<String>,
}

/// Pick the first missing option that resolves to a provider, recording the
/// terminal error if none do (build-spec §2: "picks the first whose lookup
/// resolves").
fn select_first_resolvable<R: ConfigModuleResolver>(
    missing: &[MissingOption],
    system_roots: &SystemRoots,
    resolver: &R,
    abi: u32,
) -> std::result::Result<Selection, FixpointError> {
    let mut deferred: Option<FixpointError> = None;
    for item in missing {
        match resolve_one(item, system_roots, resolver, abi) {
            Ok(selection) => return Ok(selection),
            Err(err) => {
                // Keep the most informative terminal error: an ABI mismatch
                // outranks a plain "no provider", which is the fallback when
                // nothing resolved.
                if deferred
                    .as_ref()
                    .map(|d| matches!(d, FixpointError::NoProvider { .. }))
                    .unwrap_or(true)
                {
                    deferred = Some(err);
                }
            }
        }
    }
    Err(deferred.unwrap_or_else(|| FixpointError::NoProvider {
        path: missing
            .first()
            .map(|m| option_path_root(&m.path).to_string())
            .unwrap_or_default(),
        read_by: missing.first().and_then(|m| m.read_by.clone()),
    }))
}

/// Resolve a single missing option to a provider by its root (build-spec §4).
///
/// Both Case A (an undeclared write, whose `path` is a full leaf) and Case B (an
/// absent-root read, whose `path` is the bare root) collapse to the same
/// root-based dispatch; the full Case-A path is retained only for error text.
/// The root is dispatched in order:
///
/// 1. **Shared root** — a [`SystemRoots`] hit selects the single owning package,
///    ABI-gated by the owner's pinned `module_abi_compat`.
/// 2. **Private root** — the structural fallback treats the root as a package
///    name and resolves its config module by name through `resolver`, ABI-gated.
/// 3. Neither — a terminal [`FixpointError::NoProvider`].
///
/// # Errors
///
/// Returns [`FixpointError::AbiMismatch`] when the owning/named package exists
/// but its ABI band excludes `abi`, and [`FixpointError::NoProvider`] when no
/// installed package owns the root and no package named the root exists in the
/// registry.
fn resolve_one<R: ConfigModuleResolver>(
    item: &MissingOption,
    system_roots: &SystemRoots,
    resolver: &R,
    abi: u32,
) -> std::result::Result<Selection, FixpointError> {
    let root = option_path_root(&item.path);

    // 1. Shared root owned by an installed package (per-system ownership).
    if let Some(owner) = system_roots.owner(root) {
        if system_roots.is_bundled_root(root) {
            return Err(FixpointError::NoProvider {
                path: item.path.clone(),
                read_by: item.read_by.clone(),
            });
        }
        if !owner.module_abi_compat.admits(abi) {
            return Err(FixpointError::AbiMismatch {
                path: item.path.clone(),
                want: abi,
            });
        }
        return Ok(Selection {
            package: owner.package.clone(),
            version: owner.version.clone(),
            platform: owner.platform.clone(),
            config_output: owner.config_output.clone(),
            config_nar_hash: owner.config_nar_hash.clone(),
            config_nar_size: owner.config_nar_size,
            module_abi_compat: owner.module_abi_compat,
            missing_path: item.path.clone(),
            kind: item.kind,
            read_by: item.read_by.clone(),
        });
    }

    if system_roots.is_known_shared_root(root) {
        return Err(FixpointError::NoProvider {
            path: item.path.clone(),
            read_by: item.read_by.clone(),
        });
    }

    // 2. Private root: the root segment IS the package name. Resolve it by name
    //    from registry metadata and ABI-gate its config module.
    if let Some(resolved) = resolver.config_module(root) {
        if !resolved.module.module_abi_compat.admits(abi) {
            return Err(FixpointError::AbiMismatch {
                path: item.path.clone(),
                want: abi,
            });
        }
        return Ok(Selection {
            package: resolved.package.to_string(),
            version: resolved.version.to_string(),
            platform: resolved.platform.to_string(),
            config_output: resolved.module.config_output.store_path.clone(),
            config_nar_hash: resolved.module.config_output.nar_hash.clone(),
            config_nar_size: resolved.module.config_output.nar_size,
            module_abi_compat: resolved.module.module_abi_compat,
            missing_path: item.path.clone(),
            kind: item.kind,
            read_by: item.read_by.clone(),
        });
    }

    // 3. Terminal: no owner and no package named the root.
    Err(FixpointError::NoProvider {
        path: root.to_string(),
        read_by: item.read_by.clone(),
    })
}

// ---------------------------------------------------------------------------
// CLI driver (`apm __eval` / `aos config eval`)
// ---------------------------------------------------------------------------

/// Parameters for the on-host config-eval command.
#[derive(Debug, Clone)]
pub struct EvalCommand {
    /// The delivered leaf `host.nix` path.
    pub host_nix: PathBuf,
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

    /// Treats `host_nix` as the image-authored empty fallback module.
    ///
    /// This is used only by the boot service when neither current metadata nor
    /// the durable last-known-good input supplies an operator module. It keeps
    /// a no-input first boot and image transition on the normal transactional
    /// config-generation path without mislabelling the empty module as
    /// platform-authored input.
    pub image_default_host: bool,

    /// Require the delivered `host.nix` to carry a valid detached signature.
    /// The default trusts the deployment platform that supplied instance
    /// metadata. Signed mode is fail-closed when anchors or signatures are
    /// missing or invalid.
    pub require_signed_host_nix: bool,
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

/// Run the on-host fixpoint with the production native evaluator and fetcher.
///
/// Loads the on-host registries (as the by-name [`ConfigModuleResolver`]) and
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
/// The caller (the hidden `apm __eval` subcommand) maps this to a non-zero exit;
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
    // A failed re-evaluation must never leave an older manifest looking like
    // fresh output to ConditionPathExists or the graph compiler.
    remove_if_present(&cmd.out)?;
    let graph_out = cmd.out.with_file_name("graph.json");
    remove_if_present(&graph_out)?;

    // The default path trusts configuration delivered by the deployment
    // platform's metadata channel. Signed mode adds an independent trust root
    // for environments where that transport is not trusted. Authentication
    // runs before the fixpoint so failures cannot emit a manifest.
    enforce_host_nix_trust_policy(cmd)?;

    // The by-name config-module resolver is the on-host registry set: it reads
    // each package's `config_module` block from `registry.toml`. This replaces
    // the removed registry-wide provides index. When apm config is
    // unavailable or corrupt, fail closed before selecting or fetching any
    // package. Off-host callers inject an explicit resolver instead.
    let resolver = stock::RegistryConfigModules::load_system()
        .context("loading authenticated system registry snapshot for config evaluation")?;

    let mut seed_set = load_host_selection(cmd)?;
    for legacy_seed in load_seed_set(cmd.desired.as_deref())? {
        if !seed_set
            .iter()
            .any(|member| member.package == legacy_seed.package)
        {
            seed_set.push(legacy_seed);
        }
    }

    let evaluator = native::NativeNixEvaluator::new(cmd.eval_root.clone(), cmd.verbose);
    let fetcher = stock::SubstituterFetcher::new(
        cmd.verbose,
        resolver.registries(),
        crate::types::ProfileScope::System,
    );

    // Resolve the selected names before evaluation. This both pins the exact
    // runtime outputs and adds signed package-level dependencies (`requires`
    // and capability providers) to the module working set.
    preclose_config_requires(&mut seed_set, &resolver);
    let initially_selected: Vec<String> = seed_set
        .iter()
        .map(|member| member.package.clone())
        .collect();
    let mut runtime = runtime::resolve_runtime_with_local(
        resolver.registries(),
        resolver.image_packages(),
        &initially_selected,
    )
    .context("resolving selected runtime package closures")?;
    for package in runtime.packages.keys() {
        if !seed_set.iter().any(|member| &member.package == package) {
            seed_set.push(WorkingSetMember::seed(package.clone()));
        }
    }
    preclose_config_requires(&mut seed_set, &resolver);
    hydrate_seed_config_modules(&mut seed_set, &resolver, &fetcher, cmd.module_abi)
        .map_err(eval_command_failure)?;
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
            host_nix: cmd.host_nix.clone(),
            base_lib: cmd.base_lib.clone(),
            facts_json: cmd.facts_json.clone().filter(|path| path.is_file()),
            seed_set,
            module_abi: cmd.module_abi,
            iter_cap: None,
        };
        let candidate =
            run_fixpoint(&inputs, &resolver, &evaluator, &fetcher).map_err(eval_command_failure)?;
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
        preclose_config_requires(&mut next, &resolver);
        hydrate_seed_config_modules(&mut next, &resolver, &fetcher, cmd.module_abi)
            .map_err(eval_command_failure)?;
        seed_set = next;
        outer_iterations += 1;
    };

    merge_option_graph_edges(&mut runtime.edges, &outcome.option_graph);
    let manifest = enrich_manifest(cmd, &outcome, &runtime)?;
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

/// Merges cross-package native option reads into the runtime ordering graph.
fn merge_option_graph_edges(
    edges: &mut BTreeMap<String, Vec<String>>,
    graph: &aos_core::nix::native::OptionGraph,
) {
    use aos_core::nix::native::OptionAccessKind;

    for access in &graph.accesses {
        if access.kind != OptionAccessKind::Read {
            continue;
        }
        let Some(provider) = access.provider.as_ref() else {
            continue;
        };
        let dependencies = edges.entry(access.package.clone()).or_default();
        if !dependencies.contains(provider) {
            dependencies.push(provider.clone());
            dependencies.sort();
        }
    }
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
    let expected_hash = crate::graph_compile::reproject::hash_cjson(&serde_json::json!({
        "abi": recorded_abi,
        "schema": schema,
    }));
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

/// Hashes the authenticated config-output set independently of evaluator order.
fn config_module_closure_hash(store_paths: &[String], nar_hashes: &[String]) -> Result<String> {
    if store_paths.len() != nar_hashes.len() {
        anyhow::bail!("config module store-path and NAR-hash counts differ");
    }
    let mut members = store_paths
        .iter()
        .zip(nar_hashes)
        .map(|(path, nar_hash)| serde_json::json!([path, nar_hash]))
        .collect::<Vec<_>>();
    members.sort_by(|left, right| {
        left[0]
            .as_str()
            .unwrap_or_default()
            .cmp(right[0].as_str().unwrap_or_default())
    });
    Ok(crate::graph_compile::reproject::hash_cjson(
        &serde_json::Value::Array(members),
    ))
}

fn config_module_inputs(
    working_set: &[WorkingSetMember],
) -> Result<(
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<ModuleAbiCompat>,
    Vec<PackageAuthorization>,
    Vec<String>,
)> {
    let mut seen = BTreeMap::<String, String>::new();
    let mut paths = Vec::new();
    let mut nar_hashes = Vec::new();
    let mut packages = Vec::new();
    let mut abi_compat = Vec::new();
    let mut authorizations = Vec::new();
    let mut origins = Vec::new();
    for member in working_set {
        let Some(path) = member.config_output.as_deref() else {
            continue;
        };
        if let Some(existing_package) = seen.get(path) {
            if existing_package != &member.package {
                anyhow::bail!(
                    "config output {path} is authenticated for both package identities {} and {}; shared config-output identity is forbidden",
                    existing_package,
                    member.package
                );
            }
            continue;
        }
        seen.insert(path.to_string(), member.package.clone());
        let compat = member.module_abi_compat.with_context(|| {
            format!(
                "config module {} at {path} has no authenticated module_abi_compat",
                member.package
            )
        })?;
        let nar_hash = member.config_output_nar_hash.as_deref().with_context(|| {
            format!(
                "config module {} at {path} has no authenticated NAR hash",
                member.package
            )
        })?;
        let canonical_nar_hash =
            crate::registry::store::NarBytes::from_hash(nar_hash, 0)?.nar_hash();
        paths.push(path.to_string());
        nar_hashes.push(canonical_nar_hash);
        packages.push(member.package.clone());
        abi_compat.push(compat);
        authorizations.push(member.authorization.clone());
        origins.push(if member.registry.is_some() {
            "registry".to_string()
        } else {
            "image".to_string()
        });
    }
    Ok((
        paths,
        nar_hashes,
        packages,
        abi_compat,
        authorizations,
        origins,
    ))
}

fn config_module_release_identity(
    working_set: &[WorkingSetMember],
) -> Result<(
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
)> {
    let modules = working_set
        .iter()
        .filter(|member| member.config_output.is_some() && member.registry.is_some())
        .collect::<Vec<_>>();
    if modules.is_empty() {
        return Ok((None, None, None, None));
    }
    let first = modules[0];
    let registry = first
        .registry
        .as_deref()
        .context("config module has no authenticated source registry")?;
    let receipt = first
        .release_trust
        .as_ref()
        .context("config module registry has no verified signed-release receipt")?;
    if receipt.registry != registry {
        anyhow::bail!("config module registry disagrees with its signed-release receipt");
    }
    let mut realization_members = Vec::with_capacity(modules.len());
    for member in modules {
        let member_registry = member
            .registry
            .as_deref()
            .context("config module has no authenticated source registry")?;
        let member_receipt = member
            .release_trust
            .as_ref()
            .context("config module registry has no verified signed-release receipt")?;
        if member_registry != registry || member_receipt != receipt {
            anyhow::bail!("one configuration generation cannot mix signed registry releases");
        }
        realization_members.push(serde_json::json!([
            member
                .config_output
                .as_deref()
                .context("config module output disappeared")?,
            member
                .config_realization
                .as_deref()
                .context("config module has no authenticated store realization")?,
        ]));
    }
    realization_members.sort_by(|left, right| {
        left[0]
            .as_str()
            .unwrap_or_default()
            .cmp(right[0].as_str().unwrap_or_default())
    });
    let realization =
        crate::graph_compile::reproject::hash_cjson(&serde_json::Value::Array(realization_members));
    Ok((
        Some(registry.to_string()),
        Some(receipt.release_tag.clone()),
        Some(receipt.tag_signer_key.clone()),
        Some(realization),
    ))
}

fn enrich_manifest(
    cmd: &EvalCommand,
    outcome: &FixpointOutcome,
    runtime: &runtime::RuntimeResolution,
) -> Result<materialize::ConfigManifest> {
    let mut raw: serde_json::Value =
        serde_json::from_str(&outcome.manifest).context("parsing evaluated config manifest")?;
    let object = raw
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("evaluated config manifest is not an object"))?;

    enrich_runtime_projection(object, runtime)?;

    let host_bytes = std::fs::read(&cmd.host_nix)
        .with_context(|| format!("reading host input {}", cmd.host_nix.display()))?;
    let evaluator = std::env::current_exe().context("resolving evaluator executable")?;
    let evaluator_store_path = evaluator_store_root(&evaluator)?;
    let (
        config_outputs,
        config_nar_hashes,
        config_packages,
        config_abi_compat,
        config_authorizations,
        config_origins,
    ) = config_module_inputs(&outcome.working_set)?;

    let (facts, retained_facts_bytes, facts_input_path) =
        match cmd.facts_json.as_deref().filter(|path| path.is_file()) {
            Some(path) => {
                let bytes = std::fs::read(path)
                    .with_context(|| format!("reading facts {}", path.display()))?;
                let facts = serde_json::from_slice::<crate::metadata::fetcher::Facts>(&bytes)
                    .with_context(|| format!("parsing facts {}", path.display()))?;
                (facts, bytes, Some(path))
            }
            None => {
                let facts = crate::metadata::fetcher::Facts::default();
                let bytes =
                    serde_json::to_vec(&facts).context("serializing default instance facts")?;
                (facts, bytes, None)
            }
        };

    let normalized_facts = crate::metadata::facts_render::normalize_host_facts(&facts);
    let facts_identity = serde_json::to_vec(&normalized_facts)?;
    let retained_facts = cmd.eval_root.join("instance-facts.json");
    std::fs::create_dir_all(&cmd.eval_root)
        .with_context(|| format!("creating eval root {}", cmd.eval_root.display()))?;
    std::fs::write(&retained_facts, &retained_facts_bytes)
        .with_context(|| format!("writing retained facts {}", retained_facts.display()))?;
    // Reuse an already immutable facts input instead of asking Nix to import an
    // identical copy. Besides avoiding needless store traffic on-host, this
    // keeps hermetic preflight checks independent of a writable Nix state dir.
    let facts_store_source = facts_input_path
        .filter(|path| path.starts_with("/nix/store"))
        .unwrap_or(&retained_facts);
    let facts_store_path = add_fixed_input_to_store(facts_store_source)?;

    let provisioning = cmd
        .facts_json
        .as_deref()
        .and_then(Path::parent)
        .map(|parent| parent.join(".provisioning-result.json"))
        .filter(|path| path.is_file())
        .map(|path| {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading provisioning result {}", path.display()))?;
            serde_json::from_slice::<crate::metadata::provisioning::ProvisioningResult>(&bytes)
                .with_context(|| format!("parsing provisioning result {}", path.display()))
        })
        .transpose()?;
    let (platform, trust_mode, signer_key) = if cmd.image_default_host {
        ("image".to_string(), "image".to_string(), None)
    } else {
        let platform = provisioning.as_ref().map_or_else(
            || "unknown".to_string(),
            |record| record.platform_id.clone(),
        );
        let trust_mode = provisioning.as_ref().map_or_else(
            || {
                if cmd.require_signed_host_nix {
                    "signed".to_string()
                } else {
                    "platform".to_string()
                }
            },
            |record| record.trust_mode.as_str().to_string(),
        );
        let signer_key = provisioning.and_then(|record| record.signer);
        (platform, trust_mode, signer_key)
    };
    let base_abi_hash = read_base_lib_abi_hash(&cmd.base_lib, cmd.module_abi)?;
    let evaluator_store_hash = evaluator_store_hash(&evaluator)?;
    let config_closure_hash = config_module_closure_hash(&config_outputs, &config_nar_hashes)?;
    let (config_registry, config_release_tag, config_tag_signer_key, config_realization) =
        config_module_release_identity(&outcome.working_set)?;
    let host_store_path = add_fixed_input_to_store(&cmd.host_nix)?;

    object.insert(
        "inputs".into(),
        serde_json::json!({
            "base_lib": {
                "store_path": cmd.base_lib,
                "abi_hash": base_abi_hash,
                "module_abi": cmd.module_abi,
            },
            "evaluator": {
                "store_path": evaluator_store_path,
                "store_hash": evaluator_store_hash,
            },
            "config_modules": {
                "registry": config_registry,
                "release_tag": config_release_tag,
                "tag_signer_key": config_tag_signer_key,
                "realization": config_realization,
                "closure_hash": config_closure_hash,
                "count": config_outputs.len(),
                "store_paths": config_outputs,
                "nar_hashes": config_nar_hashes,
                "package_names": config_packages,
                "origins": config_origins,
                "module_abi_compat": config_abi_compat,
                "authorizations": config_authorizations,
            },
            "host_nix": {
                "content_hash": sha256_identity(&host_bytes),
                "trust_mode": trust_mode,
                "platform": platform,
                "signer_key": signer_key,
                "store_path": host_store_path,
            },
            "instance_facts": {
                "facts_hash": sha256_identity(&facts_identity),
                "platform": platform,
                "store_path": facts_store_path,
            },
        }),
    );
    let manifest: materialize::ConfigManifest =
        serde_json::from_value(raw).context("validating config manifest structure")?;
    manifest.validate()?;
    Ok(manifest)
}

/// Adds exact runtime pins and their ownership to an evaluated manifest value.
fn enrich_runtime_projection(
    object: &mut serde_json::Map<String, serde_json::Value>,
    runtime: &runtime::RuntimeResolution,
) -> Result<()> {
    object
        .entry("config")
        .or_insert_with(|| serde_json::json!({}));
    object
        .entry("credentials")
        .or_insert_with(|| serde_json::json!({}));
    enrich_expose_config_projections(object, runtime)?;
    enrich_exposed_units(object, runtime)?;
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
    store_paths.extend(runtime.packages.values().filter_map(|package| {
        package
            .expose_artifact
            .as_ref()
            .map(|artifact| artifact.store_path.clone())
    }));
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
        let package_paths = std::iter::once(package.store_path.as_str()).chain(
            package
                .expose_artifact
                .as_ref()
                .map(|artifact| artifact.store_path.as_str()),
        );
        for package_path in package_paths {
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
            // A bundled expose artifact can remain image-owned. Its unit links
            // are immutable and the package-owned enablement edge below is
            // what makes selecting or removing the package operational.
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

/// Projects authenticated package units and their atomic enablement edge.
fn enrich_exposed_units(
    object: &mut serde_json::Map<String, serde_json::Value>,
    runtime: &runtime::RuntimeResolution,
) -> Result<()> {
    let existing_store_owners = object
        .get("ownership")
        .and_then(serde_json::Value::as_object)
        .and_then(|ownership| ownership.get("storePaths"))
        .and_then(serde_json::Value::as_object)
        .context("manifest ownership.storePaths must be an object")?;
    let existing_etc_owners = object
        .get("ownership")
        .and_then(serde_json::Value::as_object)
        .and_then(|ownership| ownership.get("etc"))
        .and_then(serde_json::Value::as_object)
        .context("manifest ownership.etc must be an object")?
        .clone();
    let mut entries = Vec::new();
    let mut package_presets = Vec::new();
    for (package, pin) in &runtime.packages {
        match (&pin.expose, &pin.expose_artifact) {
            (None, None) => continue,
            (Some(expose), Some(artifact)) => {
                crate::types::validate_expose_meta_for_package(package, expose)
                    .with_context(|| format!("validating runtime expose metadata for {package}"))?;
                crate::types::validate_expose_artifact_meta(artifact)
                    .with_context(|| format!("validating runtime expose artifact for {package}"))?;
                let unit_owner = existing_store_owners
                    .get(&artifact.store_path)
                    .and_then(serde_json::Value::as_str)
                    .filter(|owner| *owner == "@base")
                    .unwrap_or(package);
                for unit in &expose.units {
                    entries.push((
                        format!("systemd/system/{unit}"),
                        serde_json::json!({
                            "kind": "store-symlink",
                            "target": format!("{}/units/{unit}", artifact.store_path),
                        }),
                        unit_owner.to_string(),
                        package.clone(),
                    ));
                }
                entries.push((
                    format!("systemd/system/multi-user.target.wants/{}", expose.target),
                    serde_json::json!({"kind": "symlink", "target": format!("../{}", expose.target)}),
                    package.clone(),
                    package.clone(),
                ));
                entries.push((
                    format!("systemd/system-preset/30-aos-config-{package}.preset"),
                    serde_json::json!({
                        "kind": "text",
                        "text": format!("enable {}\n", expose.target),
                        "mode": "0644",
                    }),
                    package.clone(),
                    package.clone(),
                ));
                package_presets.push((expose.target.clone(), package.clone()));
            }
            _ => anyhow::bail!(
                "runtime package {package:?} must carry expose metadata and its artifact together"
            ),
        }
    }

    let etc = object
        .get_mut("etc")
        .and_then(serde_json::Value::as_object_mut)
        .context("manifest etc must be an object")?;
    let mut newly_owned = Vec::new();
    for (path, entry, owner, package) in entries {
        if let Some(existing) = etc.get(&path) {
            if existing == &entry {
                continue;
            }
            if existing_etc_owners
                .get(&path)
                .and_then(serde_json::Value::as_str)
                == Some("@base")
            {
                etc.insert(path.clone(), entry);
                newly_owned.push((path, owner));
            } else {
                anyhow::bail!(
                    "runtime package {package:?} unit projection conflicts with existing /etc/{path}"
                );
            }
        } else {
            etc.insert(path.clone(), entry);
            newly_owned.push((path, owner));
        }
    }
    let owned = object
        .get_mut("ownership")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|ownership| ownership.get_mut("etc"))
        .and_then(serde_json::Value::as_object_mut)
        .context("manifest ownership.etc must be an object")?;
    for (path, package) in newly_owned {
        owned.insert(path, serde_json::Value::String(package));
    }

    let presets = object
        .get_mut("presets")
        .and_then(serde_json::Value::as_array_mut)
        .context("manifest presets must be an array")?;
    for (target, package) in &package_presets {
        let record = serde_json::json!({
            "unit": target,
            "policy": "enable",
            "source": package,
        });
        if presets.contains(&record) {
            anyhow::bail!("manifest already contains runtime preset for package {package:?}");
        }
        presets.push(record);
    }
    let preset_owners = object
        .get_mut("ownership")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|ownership| ownership.get_mut("presets"))
        .and_then(serde_json::Value::as_object_mut)
        .context("manifest ownership.presets must be an object")?;
    for (target, package) in package_presets {
        let key = format!("{target}:{package}");
        if preset_owners
            .insert(key, serde_json::Value::String(package.clone()))
            .is_some()
        {
            anyhow::bail!("manifest preset ownership collides for package {package:?}");
        }
    }
    Ok(())
}

fn enrich_expose_config_projections(
    object: &mut serde_json::Map<String, serde_json::Value>,
    runtime: &runtime::RuntimeResolution,
) -> Result<()> {
    let bindings = object
        .remove("configProjectionBindings")
        .unwrap_or_else(|| serde_json::json!({}));
    let bindings = bindings
        .as_object()
        .context("evaluated configProjectionBindings must be an object")?;
    let expected = runtime
        .packages
        .iter()
        .filter_map(|(package, pin)| pin.config_projection.as_ref().map(|_| package.as_str()))
        .collect::<BTreeSet<_>>();
    let actual = bindings.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if expected != actual {
        anyhow::bail!(
            "evaluated expose config bindings do not exactly cover authenticated migrated packages"
        );
    }

    let desired = object
        .get("config")
        .and_then(serde_json::Value::as_object)
        .context("evaluated manifest config must be an object")?;
    let mut projections = BTreeMap::new();
    for package in expected {
        let pin = runtime.packages[package]
            .config_projection
            .as_ref()
            .context("migrated package lost projection metadata")?;
        let expected_schema_hash = materialize::expose_config_schema_hash(&pin.config)?;
        let binding = bindings[package].as_object().with_context(|| {
            format!("config projection binding for {package:?} is not an object")
        })?;
        let binding_fields = binding.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if binding_fields != BTreeSet::from(["schema", "schema_hash"]) {
            anyhow::bail!("config projection binding for {package:?} contains unexpected fields");
        }
        if binding.get("schema").and_then(serde_json::Value::as_str)
            != Some("aos.expose-config-binding/v1")
            || binding
                .get("schema_hash")
                .and_then(serde_json::Value::as_str)
                != Some(expected_schema_hash.as_str())
        {
            anyhow::bail!("config projection binding for {package:?} is missing or tampered");
        }
        let desired_package = desired
            .get(package)
            .map(json_desired_package)
            .transpose()?
            .unwrap_or_default();
        let rendered =
            crate::render_package_config(package, &pin.config.artifacts, Some(&desired_package))?;
        let artifacts = rendered
            .into_iter()
            .map(|(artifact, bytes)| {
                let text = String::from_utf8(bytes).with_context(|| {
                    format!("rendered config artifact {} is not UTF-8", artifact.path)
                })?;
                Ok(materialize::ProjectedConfigArtifact {
                    path: artifact.path.clone(),
                    sha256: format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes()))),
                    mode: "0644".to_string(),
                    text,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        projections.insert(
            package.to_string(),
            materialize::ProjectedPackageConfig {
                schema: materialize::ProjectedPackageConfig::SCHEMA.to_string(),
                schema_hash: expected_schema_hash,
                artifacts,
                units: materialize::projected_unit_actions(&pin.config.artifacts),
            },
        );
    }
    object.insert(
        "configProjections".into(),
        serde_json::to_value(projections).context("serializing rendered config projections")?,
    );
    Ok(())
}

fn json_desired_package(
    value: &serde_json::Value,
) -> Result<BTreeMap<String, BTreeMap<String, toml::Value>>> {
    let artifacts = value
        .as_object()
        .context("desired package config must be an object")?;
    artifacts
        .iter()
        .map(|(artifact, fields)| {
            let fields = fields.as_object().with_context(|| {
                format!("desired config artifact {artifact:?} must be an object")
            })?;
            let fields = fields
                .iter()
                .map(|(field, value)| {
                    let value = serde_json::from_value::<toml::Value>(value.clone())
                        .with_context(|| format!("converting desired config field {field:?}"))?;
                    Ok((field.clone(), value))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            Ok((artifact.clone(), fields))
        })
        .collect()
}

fn add_fixed_input_to_store(path: &Path) -> Result<PathBuf> {
    if path.starts_with("/nix/store") {
        return Ok(path.to_path_buf());
    }
    let output = std::process::Command::new("nix-store")
        .args(["--add-fixed", "sha256"])
        .arg(path)
        .output()
        .with_context(|| format!("adding fixed host input {} to the store", path.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "adding fixed host input to the store failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let store_path = String::from_utf8(output.stdout)
        .context("nix-store returned a non-UTF-8 host input path")?;
    let store_path = PathBuf::from(store_path.trim());
    if !store_path.starts_with("/nix/store") {
        anyhow::bail!("nix-store returned invalid path {}", store_path.display());
    }
    Ok(store_path)
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
) -> Result<()> {
    remove_if_present(&out)?;
    let graph_out = out.with_file_name("graph.json");
    remove_if_present(&graph_out)?;
    validate_cross_abi_inputs(retained, running_base_lib)?;

    let source_bytes = std::fs::read(source_manifest)
        .with_context(|| format!("reading retained manifest {}", source_manifest.display()))?;
    let source: materialize::ConfigManifest = serde_json::from_slice(&source_bytes)
        .with_context(|| format!("parsing retained manifest {}", source_manifest.display()))?;
    source
        .validate()
        .with_context(|| format!("validating retained manifest {}", source_manifest.display()))?;
    validate_retained_manifest_inputs(&source, retained)?;

    let working_set = retained_cross_abi_working_set(&source, retained)?;
    let evaluator = native::NativeNixEvaluator::new(eval_root, verbose);
    let attempt = EvalAttempt {
        host_nix: Path::new(&retained.host_nix_ref),
        base_lib: running_base_lib,
        facts_json: Some(Path::new(&retained.facts_ref)),
        working_set: &working_set,
        iteration: 0,
    };
    let evaluated = match evaluator.evaluate(&attempt)? {
        EvalClass::Manifest(manifest) | EvalClass::NativeManifest { manifest, .. } => manifest,
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
    // evaluated aggregate artifacts so config, units, presets, and ownership
    // are rebuilt against the running image's base library.
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
    inputs.base_lib.store_path = running_base_lib.to_string_lossy().into_owned();
    inputs.base_lib.module_abi = retained.to_module_abi;
    inputs.base_lib.abi_hash = read_base_lib_abi_hash(running_base_lib, retained.to_module_abi)?;
    inputs.evaluator.store_path = evaluator_store_path.to_string_lossy().into_owned();
    inputs.evaluator.store_hash = evaluator_store_hash(&evaluator_path)?;
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

fn retained_cross_abi_working_set(
    source: &materialize::ConfigManifest,
    retained: &crate::types::CrossAbiReEvalInputs,
) -> Result<Vec<WorkingSetMember>> {
    let modules = &source.inputs.config_modules;
    if modules.authorizations.len() != retained.config_module_paths.len() {
        anyhow::bail!(
            "retained generation has no complete authenticated config-module authorization set"
        );
    }
    Ok(retained
        .config_module_paths
        .iter()
        .zip(&modules.nar_hashes)
        .zip(&retained.config_module_packages)
        .zip(&modules.module_abi_compat)
        .zip(&modules.authorizations)
        .map(
            |((((path, nar_hash), package), compat), authorization)| WorkingSetMember {
                registry: None,
                release_trust: None,
                config_realization: None,
                package: package.clone(),
                version: source
                    .package_outputs
                    .get(package)
                    .map(|pin| pin.version.clone()),
                config_output: Some(path.clone()),
                config_output_nar_hash: Some(nar_hash.clone()),
                module_abi_compat: Some(*compat),
                authorization: authorization.clone(),
                outputs: PackageOutputs {
                    self_output: source
                        .package_outputs
                        .get(package)
                        .map(|pin| pin.store_path.clone()),
                    dependencies: source
                        .graph
                        .edges
                        .get(package)
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
            },
        )
        .collect())
}

fn validate_retained_manifest_inputs(
    source: &materialize::ConfigManifest,
    retained: &crate::types::CrossAbiReEvalInputs,
) -> Result<()> {
    if source.inputs.config_modules.store_paths != retained.config_module_paths
        || source.inputs.config_modules.package_names != retained.config_module_packages
        || source.inputs.host_nix.store_path != retained.host_nix_ref
        || source.inputs.instance_facts.facts_hash != retained.facts_hash
        || source.inputs.instance_facts.store_path != retained.facts_ref
    {
        anyhow::bail!(
            "retained generation inputs disagree with its manifest; cross-ABI rollback refused"
        );
    }
    if source
        .inputs
        .config_modules
        .module_abi_compat
        .iter()
        .any(|compat| retained.to_module_abi < compat.min || retained.to_module_abi > compat.max)
    {
        anyhow::bail!(
            "a retained config module does not admit running module ABI {}; cross-ABI rollback refused",
            retained.to_module_abi
        );
    }
    Ok(())
}

fn validate_cross_abi_inputs(
    retained: &crate::types::CrossAbiReEvalInputs,
    running_base_lib: &Path,
) -> Result<()> {
    for (kind, path) in std::iter::once(("running base library", running_base_lib))
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
                .config_module_paths
                .iter()
                .map(|path| ("config module", Path::new(path))),
        )
    {
        if !path.starts_with("/nix/store/") || !path.exists() {
            anyhow::bail!(
                "required retained {kind} input is unavailable: {}",
                path.display()
            );
        }
    }
    let facts_bytes = std::fs::read(&retained.facts_ref)
        .with_context(|| format!("reading retained facts {}", retained.facts_ref))?;
    let facts: crate::metadata::fetcher::Facts = serde_json::from_slice(&facts_bytes)
        .with_context(|| format!("parsing retained facts {}", retained.facts_ref))?;
    let normalized = crate::metadata::facts_render::normalize_host_facts(&facts);
    let normalized_bytes = serde_json::to_vec(&normalized)?;
    if sha256_identity(&normalized_bytes) != retained.facts_hash {
        anyhow::bail!("retained facts bytes do not match the recorded facts_hash");
    }
    Ok(())
}

/// Evaluates the closed host package-selection projection before resolution.
///
/// This is the bootstrap half of the fixpoint: package names must be known
/// before their registry config modules can be fetched, while the complete
/// runtime evaluation needs those modules. Only `aos.apm.desiredPackages` is
/// declared, so unrelated host definitions remain lazy.
fn load_host_selection(cmd: &EvalCommand) -> Result<Vec<WorkingSetMember>> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HostSelection {
        packages: Vec<String>,
    }

    std::fs::create_dir_all(&cmd.eval_root)
        .with_context(|| format!("creating eval root {}", cmd.eval_root.display()))?;
    let entry = cmd.eval_root.join("host-selection-entry.nix");
    let nix_path = |path: &Path| path.to_string_lossy().replace(' ', "\\ ");
    let expression = format!(
        "# Generated by aos config eval; do not edit.\n\
         let\n\
        \x20 baseLib = import {base};\n\
        \x20 system = baseLib.evalHostSelection {{\n\
        \x20   operatorModules = [ (import {host}) ];\n\
        \x20 }};\n\
         in {{ packages = system.config.aos.apm.desiredPackages; }}\n",
        base = nix_path(&cmd.base_lib),
        host = nix_path(&cmd.host_nix),
    );
    std::fs::write(&entry, expression).with_context(|| format!("writing {}", entry.display()))?;

    let evaluator = native::NativeNixEvaluator::new(&cmd.eval_root, cmd.verbose);
    let expression = format!("import {}", stock::nix_path(&entry));
    let output = evaluator
        .eval_strict_json(
            &expression,
            [
                entry.as_path(),
                cmd.base_lib.as_path(),
                cmd.host_nix.as_path(),
            ],
        )
        .context("evaluating host package selection with the native evaluator")?;
    let selection: HostSelection =
        serde_json::from_str(&output).context("parsing host package selection")?;
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
/// (config outputs, ABI bands) is discovered by the loop, so seeds carry no
/// config output here.
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
